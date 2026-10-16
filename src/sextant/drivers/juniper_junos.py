"""Juniper Junos driver (EX/QFX switches, MX/SRX basics).

parse() works on `show configuration | display set`. An imported config file in the
hierarchical (curly-brace) format is converted to set-lines first, so both export
formats work offline. Interface ranges and VLAN names are resolved before ports are
mapped to the model.
"""

from __future__ import annotations

import re
import shlex
from collections import defaultdict

from sextant import model as m
from sextant.drivers import register
from sextant.drivers._ssh import run_commands
from sextant.drivers._util import compress_vlans, first, fixed_columns, scrub_after
from sextant.drivers.base import Credentials, Driver, RawCollection, Target
from sextant.drivers.cisco_ios import IPV4, community_label, is_ip, output
from sextant.redact import redact_text

JUNOS_COMMANDS = [
    "show configuration | display set",
    "show version",
    "show chassis hardware",
    "show interfaces terse",
    "show lldp neighbors",
    "show route",
    "show virtual-chassis",
    "show system uptime",
]

_SECRET_PREFIXES = [r"\bprivacy-key", r"\bauthentication-password", r"\bprivacy-password", r"\bplain-text-password-value"]
_MGMT_IFS = ("vme", "me0", "em0", "fxp0", "re0:mgmt-0")


def braces_to_set(text: str) -> str:
    """Convert hierarchical Junos config to `set` lines (best effort, tolerant)."""
    out: list[str] = []
    stack: list[str] = []
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith("##"):
            continue
        line = re.sub(r"\s*##.*$", "", line)
        inactive = line.startswith("inactive: ")
        line = line.removeprefix("inactive: ").removeprefix("protect: ")
        if line.endswith("{"):
            stack.append(line[:-1].strip())
        elif line == "}":
            if stack:
                stack.pop()
        elif line.endswith(";"):
            stmt = " ".join([*stack, line[:-1].strip()])
            out.append(("deactivate " if inactive else "set ") + stmt)
    return "\n".join(out)


def tokens(line: str) -> list[list[str]]:
    """'set a b [ x y ]' -> [['a','b','x'], ['a','b','y']] (without 'set')."""
    try:
        toks = shlex.split(line, posix=True)
    except ValueError:
        toks = line.split()
    if toks and toks[0] == "set":
        toks = toks[1:]
    if "[" in toks and "]" in toks:
        i, j = toks.index("["), toks.index("]")
        return [toks[:i] + [v] + toks[j + 1:] for v in toks[i + 1:j]] or [toks[:i] + toks[j + 1:]]
    return [toks]


def _range(a: str, b: str) -> list[str]:
    ma, mb = re.match(r"^(.*?)(\d+)$", a), re.match(r"^(.*?)(\d+)$", b)
    if not ma or not mb or ma.group(1) != mb.group(1):
        return [a, b]
    return [f"{ma.group(1)}{i}" for i in range(int(ma.group(2)), int(mb.group(2)) + 1)]


class JunosParser:
    def __init__(self, raw: RawCollection, platform: str):
        self.raw = raw
        text = output(raw, "show configuration | display set", "show configuration", "config").replace("\r", "")
        if text and not re.search(r"^set ", text, re.M) and "{" in text:
            text = braces_to_set(text)
        self.cfg = text
        self.sets: list[list[str]] = []
        for ln in text.splitlines():
            if ln.startswith("set "):
                self.sets.extend(t for t in tokens(ln) if t)
        self.dev = m.Device(hostname=raw.target or "unknown", vendor="Juniper", platform=platform, os_name="Junos",
                            collection_method=raw.method, source=raw.target)
        self.dev.collection_warnings.extend(raw.warnings)
        self.ifs: dict[str, m.Interface] = {}
        self.members: dict[str, list[str]] = defaultdict(list)  # interface -> vlan member names
        self.ranges: dict[str, list[str]] = defaultdict(list)
        self.filters_applied: dict[str, list[str]] = defaultdict(list)
        self.vlan_ids: dict[str, int] = {}

    def sel(self, *prefix: str) -> list[list[str]]:
        """Remaining tokens of all set-lines that start with `prefix`."""
        n = len(prefix)
        return [t[n:] for t in self.sets if t[:n] == list(prefix)]

    def val(self, *prefix: str) -> str | None:
        hits = self.sel(*prefix)
        return hits[0][0] if hits and hits[0] else None

    def parse(self) -> m.Device:
        d = self.dev
        if not self.sets:
            d.collection_warnings.append("No configuration (display set) in collection: configuration sections are empty.")
        for step in (self.parse_version, self.parse_hardware, self.parse_interfaces, self.parse_vlans, self.parse_status,
                     self.parse_routes, self.parse_protocols, self.parse_neighbors, self.parse_stp, self.parse_filters,
                     self.parse_management, self.parse_vc):
            try:
                step()
            except Exception as exc:  # noqa: BLE001
                d.collection_warnings.append(f"{step.__name__} failed: {exc.__class__.__name__}: {exc}")
        d.interfaces = list(self.ifs.values())
        d.mgmt_ip = self.find_mgmt_ip()
        model = (d.model or "").lower()
        d.role = (m.DeviceRole.firewall if model.startswith("srx") else
                  m.DeviceRole.router if model.startswith(("mx", "ptx", "acx", "vmx")) else
                  m.DeviceRole.switch if model.startswith(("ex", "qfx")) or d.vlans else m.DeviceRole.router)
        d.raw_config = scrub_after(redact_text(self.cfg), _SECRET_PREFIXES) if self.cfg else None
        return d

    def iface(self, name: str) -> m.Interface:
        itf = self.ifs.get(name)
        if itf is None:
            base = name.split(".")[0]
            kind = ("vlan" if base in ("irb", "vlan") else "loopback" if base == "lo0" else
                    "mgmt" if base in _MGMT_IFS else "lag" if re.match(r"^(ae|reth)\d+$", base) else
                    "tunnel" if re.match(r"^(gr|ip|st0|lt)-?", base) and "." in name else
                    "virtual" if "." in name else "physical")
            itf = m.Interface(name=name, kind=kind)
            self.ifs[name] = itf
        return itf

    # ------------------------------------------------------------------ identity / hardware
    def parse_version(self) -> None:
        d, ver = self.dev, output(self.raw, "show version")
        d.hostname = self.val("system", "host-name") or first(r"^Hostname:\s*(\S+)", ver) or d.hostname
        if not ver:
            d.collection_warnings.append("show version not collected: model and exact Junos version may be missing.")
        d.model = first(r"^Model:\s*(\S+)", ver)
        d.uptime = first(r"System booted:.*\((.+?) ago\)", output(self.raw, "show system uptime"))
        d.os_version = (first(r"^Junos:\s*(\S+)", ver) or first(r"JUNOS (?:Base OS|Software Release|EX\s+Software Suite)"
                                                                 r"[^\[]*\[(\S+)\]", ver) or self.val("version"))

    def parse_hardware(self) -> None:
        d = self.dev
        rows = fixed_columns(output(self.raw, "show chassis hardware"), r"^Item\s+Version\s+Part number")
        table = []
        for r in rows:
            item = r.get("Item", "")
            if not item:
                continue
            table.append([item, r.get("Version", ""), r.get("Part number", ""), r.get("Serial number", ""),
                          r.get("Description", "")])
            if item == "Chassis":
                d.serial = r.get("Serial number") or d.serial
                d.hardware.append(m.Fact(key="Chassis", value=f"{r.get('Description', '')} SN {r.get('Serial number', '')}"))
            elif re.match(r"^(FPC \d+|Power Supply \d+|Routing Engine \d+)$", item):
                d.hardware.append(m.Fact(key=item, value=f"{r.get('Description', '')} ({r.get('Part number', '')}) "
                                                         f"SN {r.get('Serial number', '')}".strip()))
        if table:
            d.sections.append(m.Section(id="chassis-hardware", title="Chassis hardware", tables=[m.Table(
                columns=["Item", "Version", "Part number", "Serial", "Description"], rows=table)]))
        if not d.model:
            fpc = next((r[4] for r in table if r[0].startswith("FPC")), None)
            d.model = fpc.lower() if fpc else None

    # ------------------------------------------------------------------ interfaces
    def parse_interfaces(self) -> None:
        for t in self.sel("interfaces", "interface-range"):
            if len(t) >= 3 and t[1] == "member":
                self.ranges[t[0]].append(t[2])
            elif len(t) >= 5 and t[1] == "member-range" and t[3] == "to":
                self.ranges[t[0]] += _range(t[2], t[4])
        for t in self.sel("interfaces"):
            if not t or t[0] == "interface-range" and len(t) > 2 and t[2] in ("member", "member-range"):
                continue
            if t[0] == "interface-range":
                for member in self.ranges.get(t[1], []):
                    self._if_stmt(member, t[2:])
            else:
                self._if_stmt(t[0], t[1:])
        for itf in self.ifs.values():
            if itf.lag and itf.kind == "physical":
                parent = self.iface(itf.lag)
                if itf.name not in parent.lag_members:
                    parent.lag_members.append(itf.name)
                itf.lag_protocol = parent.lag_protocol
        for t in self.sel("switch-options", "voip", "interface"):
            if len(t) >= 3 and t[1] == "vlan":
                targets = self.ranges.get(t[0]) or ([i.name for i in self.ifs.values() if i.mode == m.PortMode.access]
                                                    if t[0] == "access-ports" else [t[0].split(".")[0]])
                for name in targets:
                    self.iface(name).extra["voice vlan name"] = t[2]

    def _if_stmt(self, name: str, t: list[str]) -> None:  # noqa: C901
        if not t:
            self.iface(name)
            return
        if t[0] == "unit" and len(t) > 1:
            unit, rest = t[1], t[2:]
            logical = name in ("irb", "vlan", "lo0", *_MGMT_IFS) or unit != "0"
            itf = self.iface(f"{name}.{unit}" if logical else name)
            if logical and name not in ("irb", "vlan") and not itf.lag:
                itf.extra.setdefault("parent", name)
        else:
            itf, rest = self.iface(name), t
        if not rest:
            return
        k = rest[0]
        if k == "description" and len(rest) > 1:
            itf.description = itf.description or rest[1]
        elif k == "disable":
            itf.enabled = False
        elif k in ("ether-options", "gigether-options") and len(rest) > 2 and rest[1] == "802.3ad":
            itf.lag = rest[2]
        elif k == "aggregated-ether-options" and len(rest) > 2 and rest[1] == "lacp":
            itf.lag_protocol = "lacp"
            if rest[2] in ("active", "passive"):
                itf.extra["lacp mode"] = rest[2]
            elif len(rest) > 3:
                itf.extra[f"lacp {rest[2]}"] = rest[3]
        elif k == "native-vlan-id" and len(rest) > 1 and rest[1].isdigit():
            itf.native_vlan = int(rest[1])
        elif k == "mtu" and len(rest) > 1 and rest[1].isdigit():
            itf.mtu = int(rest[1])
        elif k == "speed" and len(rest) > 1:
            itf.speed = rest[1]
        elif k == "family" and len(rest) > 1:
            fam, r2 = rest[1], rest[2:]
            if fam == "ethernet-switching":
                itf.extra.setdefault("family", "ethernet-switching")
                if r2[:1] in (["interface-mode"], ["port-mode"]) and len(r2) > 1:
                    itf.extra["interface-mode"] = r2[1]
                elif r2[:2] == ["vlan", "members"] and len(r2) > 2:
                    self.members[itf.name].append(r2[2])
                elif r2[:1] == ["storm-control"]:
                    itf.extra["storm-control"] = " ".join(r2[1:])
            elif fam == "inet":
                if r2[:1] == ["address"] and len(r2) > 1:
                    itf.ipv4.append(m.IPAddress(address=r2[1]))
                    if "virtual-gateway-address" in r2:
                        itf.ipv4[-1].vrrp_vip = r2[r2.index("virtual-gateway-address") + 1]
                elif r2[:1] == ["dhcp"]:
                    itf.ipv4.append(m.IPAddress(address="dhcp"))
                elif r2[:1] == ["filter"] and len(r2) > 2:
                    self.filters_applied[r2[2]].append(f"{itf.name}{'.0' if '.' not in itf.name else ''} "
                                                       f"{'in' if r2[1] == 'input' else 'out'}")
            elif fam == "inet6" and r2[:1] == ["address"] and len(r2) > 1:
                itf.ipv6.append(r2[1])

    def parse_vlans(self) -> None:
        vlans: dict[str, m.Vlan] = {}
        l3: dict[str, str] = {}
        for t in self.sel("vlans"):
            if len(t) < 2:
                continue
            name = t[0]
            if t[1] == "vlan-id" and len(t) > 2 and t[2].isdigit():
                vlans[name] = m.Vlan(id=int(t[2]), name=name)
                self.vlan_ids[name] = int(t[2])
            elif t[1] == "l3-interface" and len(t) > 2:
                l3[name] = t[2]
        helpers: dict[str, list[str]] = defaultdict(list)
        groups: dict[str, list[str]] = defaultdict(list)
        for base in (("forwarding-options", "dhcp-relay"), ("forwarding-options", "helpers", "bootp")):
            for t in self.sel(*base):
                if len(t) >= 3 and t[0] == "server-group":
                    groups[t[1]].append(t[2])
                elif len(t) >= 4 and t[0] == "group" and t[2] == "interface":
                    helpers[t[3]].append(t[1])
                elif len(t) >= 3 and t[0] == "interface" and t[2] == "server":
                    helpers[t[1]].append(t[3] if len(t) > 3 else "")

        def vid_of(member: str) -> int | None:
            if member.isdigit():
                return int(member)
            return self.vlan_ids.get(member)

        for ifname, mems in self.members.items():
            itf = self.iface(ifname)
            ids = [v for v in (vid_of(x) for x in mems) if v is not None]
            mode = itf.extra.pop("interface-mode", "access")
            if itf.lag and itf.kind == "physical":
                itf.mode = m.PortMode.lag_member
            elif mode == "trunk":
                itf.mode = m.PortMode.trunk
                itf.trunk_vlans = "all" if "all" in mems else compress_vlans(ids)
            else:
                itf.mode = m.PortMode.access
                itf.access_vlan = ids[0] if ids else None
            if itf.mode == m.PortMode.access:
                for v in vlans.values():
                    if itf.access_vlan == v.id:
                        v.ports.append(ifname)
        for itf in self.ifs.values():
            if itf.mode == m.PortMode.unknown:
                fam = itf.extra.pop("family", None)
                mode = itf.extra.pop("interface-mode", None)
                if fam == "ethernet-switching":
                    itf.mode = m.PortMode.trunk if mode == "trunk" else m.PortMode.access
                elif itf.ipv4 or itf.kind in ("vlan", "loopback", "mgmt"):
                    itf.mode = m.PortMode.routed if itf.ipv4 or itf.kind == "vlan" else m.PortMode.unknown
                if itf.lag and itf.kind == "physical":
                    itf.mode = m.PortMode.lag_member
            else:
                itf.extra.pop("family", None)
            vname = itf.extra.pop("voice vlan name", None)
            if vname:
                itf.voice_vlan = vid_of(vname)
        for name, irb in l3.items():
            if name in vlans:
                itf = self.ifs.get(irb)
                if itf:
                    vlans[name].svi_ipv4 = [ip.address for ip in itf.ipv4]
                    itf.description = itf.description or name
                vlans[name].dhcp_helpers = [s for g in helpers.get(irb, []) for s in groups.get(g, [g]) if is_ip(s)]
        self.dev.vlans = sorted(vlans.values(), key=lambda v: v.id)

    def parse_status(self) -> None:
        for name, admin, link in re.findall(r"^(\S+)\s+(up|down)\s+(up|down)\b", output(self.raw, "show interfaces terse"),
                                            re.M):
            itf = self.ifs.get(name) or (self.ifs.get(name[:-2]) if name.endswith(".0") else None)
            if itf is None:
                if re.match(r"^(ge|xe|et|mge|ae)-?\d", name) and "." not in name:
                    itf = self.iface(name)
                else:
                    continue
            if itf.oper_up is None or "." not in name:
                itf.oper_up = link == "up"
                if not self.sets:
                    itf.enabled = admin == "up"

    # ------------------------------------------------------------------ routing
    def parse_routes(self) -> None:
        d = self.dev
        for t in self.sel("routing-instances"):
            if len(t) >= 3 and t[1] == "instance-type" and t[0] not in d.vrfs:
                d.vrfs.append(t[0])
        statics: list[tuple[str | None, list[str]]] = [(None, t) for t in self.sel("routing-options", "static", "route")]
        for t in self.sel("routing-instances"):
            if t[1:4] == ["routing-options", "static", "route"]:
                statics.append((t[0], t[4:]))
        routes: dict[tuple[str, str | None], m.Route] = {}
        for vrf, t in statics:
            if not t:
                continue
            key = (t[0], vrf)
            r = routes.setdefault(key, m.Route(prefix=t[0], protocol="static", vrf=vrf, distance=5))
            if len(t) > 2 and t[1] in ("next-hop", "qualified-next-hop"):
                if r.next_hop and r.next_hop != t[2]:
                    r2 = r.model_copy(update={"next_hop": t[2]})
                    routes[(t[0] + "#" + t[2], vrf)] = r2
                    r = r2
                r.next_hop = t[2] if is_ip(t[2]) else None
                r.interface = None if is_ip(t[2]) else t[2]
                if "preference" in t:
                    r.distance = int(t[t.index("preference") + 1])
            elif t[1:2] == ["preference"] and len(t) > 2:
                r.distance = int(t[2])
            elif t[1:2] in (["discard"], ["reject"]):
                r.interface = t[1]
        d.routes = list(routes.values())
        keys = {(r.prefix, r.next_hop, r.vrf) for r in d.routes}
        table, vrf, cur = output(self.raw, "show route"), None, None
        for ln in table.splitlines():
            mt = re.match(r"^(\S+?)\.inet\.0:|^inet\.0:", ln)
            if mt:
                vrf = mt.group(1)
                continue
            if re.match(r"^\S+:\s+\d+ destinations", ln):
                vrf = "skip"
                continue
            mt = re.match(rf"^({IPV4}/\d+)\s+[*+-]*\[(\w+(?:-\w+)?)/(\d+)\]", ln)
            if mt and vrf != "skip":
                proto = {"Static": "static", "Direct": "connected", "OSPF": "ospf", "BGP": "bgp", "RIP": "rip",
                         "IS-IS": "isis", "Aggregate": "aggregate"}.get(mt.group(2))
                cur = m.Route(prefix=mt.group(1), protocol=proto, distance=int(mt.group(3)), vrf=vrf) if proto else None
                continue
            mt = re.match(rf"^\s+>?\s*(?:to ({IPV4}) )?via (\S+)", ln)
            if mt and cur is not None:
                r = cur.model_copy(update={"next_hop": mt.group(1), "interface": mt.group(2)})
                if not (r.protocol == "static" and (r.prefix, r.next_hop, r.vrf) in keys):
                    d.routes.append(r)

    def parse_protocols(self) -> None:
        d = self.dev
        rid = self.val("routing-options", "router-id")
        asn = self.val("routing-options", "autonomous-system")
        ospf = self.sel("protocols", "ospf")
        if ospf:
            rp = m.RoutingProtocol(protocol="ospf", router_id=rid)
            for t in ospf:
                if len(t) >= 4 and t[0] == "area" and t[2] == "interface":
                    entry = f"{t[3]} area {t[1]}"
                    if entry not in rp.networks:
                        rp.networks.append(entry)
                    if "passive" in t:
                        rp.details["passive interfaces"] = ", ".join(
                            x for x in (rp.details.get("passive interfaces"), t[3]) if x)
                elif t[:1] in (["export"], ["reference-bandwidth"]):
                    rp.details[t[0]] = " ".join(t[1:])
            d.routing_protocols.append(rp)
        bgp = self.sel("protocols", "bgp")
        if bgp:
            rp = m.RoutingProtocol(protocol="bgp", router_id=rid, asn=asn)
            peers: dict[str, str] = {}
            group_as: dict[str, str] = {}
            for t in bgp:
                if len(t) >= 3 and t[0] == "group" and t[2] == "peer-as":
                    group_as[t[1]] = t[3]
                elif len(t) >= 4 and t[0] == "group" and t[2] == "neighbor":
                    peers.setdefault(t[3], group_as.get(t[1], ""))
                    if len(t) >= 6 and t[4] == "peer-as":
                        peers[t[3]] = t[5]
            rp.neighbors = [f"{ip} (AS {peer or '?'})" for ip, peer in peers.items()]
            d.routing_protocols.append(rp)

    def parse_neighbors(self) -> None:
        rows = fixed_columns(output(self.raw, "show lldp neighbors"), r"^Local Interface\s+")
        for r in rows:
            local = r.get("Local Interface", "")
            if not local or local.startswith("{"):
                continue
            self.dev.neighbors.append(m.Neighbor(
                local_port=local, remote_device=r.get("System Name") or r.get("Chassis Id") or "?",
                remote_port=r.get("Port info") or r.get("Port ID") or None, protocol="lldp"))

    def parse_stp(self) -> None:
        if not self.sets:
            return
        proto = next((p for p in ("rstp", "mstp", "vstp", "stp") if self.sel("protocols", p)), None)
        st = m.SpanningTree(mode=proto or "disabled")
        lines = self.sel("protocols", proto) if proto else []
        edges: set[str] = set()
        for t in lines:
            if t[:1] == ["bridge-priority"] and len(t) > 1:
                st.priority = t[1]
            elif t[:1] == ["bpdu-block-on-edge"]:
                st.bpdu_guard_default = True
            elif t[:1] == ["interface"] and len(t) > 2 and t[2] == "edge":
                edges.update(self.ranges.get(t[1]) or ([n for n, i in self.ifs.items() if i.kind == "physical"]
                                                      if t[1] == "all" else [t[1]]))
            elif t[:1] == ["interface"] and len(t) > 2 and t[2] == "disable":
                st.details["disabled on"] = ", ".join(x for x in (st.details.get("disabled on"), t[1]) if x)
        blocked = self.sel("protocols", "layer2-control", "bpdu-block", "interface")
        if blocked:
            st.details["bpdu-block interfaces"] = ", ".join(t[0] for t in blocked if t)
        if st.bpdu_guard_default is None:
            st.bpdu_guard_default = False
        for name in edges:
            self.iface(name).stp_edge = True
        st.details["edge ports"] = str(len(edges))
        self.dev.spanning_tree = st

    def parse_filters(self) -> None:
        acls: dict[str, m.Acl] = {}
        terms: dict[tuple[str, str], dict[str, list[str]]] = {}
        for t in self.sets:
            if t[:1] != ["firewall"]:
                continue
            if t[1:2] == ["family"] and len(t) > 4 and t[3] == "filter":
                fam, rest = t[2], t[4:]
            elif t[1:2] == ["filter"]:
                fam, rest = "inet", t[2:]
            else:
                continue
            if len(rest) < 4 or rest[1] != "term":
                continue
            name, term, part = rest[0], rest[2], rest[3:]
            acls.setdefault(name, m.Acl(name=name, kind={"inet": "extended", "inet6": "ipv6"}.get(fam, fam)))
            tdict = terms.setdefault((name, term), {"from": [], "then": []})
            if part[0] in ("from", "then"):
                tdict[part[0]].append(" ".join(part[1:]))
        for (name, term), td in terms.items():
            then = " ".join(td["then"])
            action = "permit" if "accept" in then else "deny" if re.search(r"discard|reject", then) else "other"
            text = f"term {term}: {'; '.join(td['from']) or 'any'} -> {then or '(next term)'}"
            acls[name].entries.append(m.AclEntry(seq=term, action=action, text=text))
        for name, acl in acls.items():
            acl.applied_to = self.filters_applied.get(name, [])
        self.dev.acls = list(acls.values())
        self._terms = terms

    # ------------------------------------------------------------------ management
    def parse_management(self) -> None:  # noqa: C901
        mg, d = self.dev.management, self.dev
        if not self.sets:
            return
        svc = self.sel("system", "services")
        mg.ssh = any(t[:1] == ["ssh"] for t in svc)
        mg.ssh_version = "2" if mg.ssh else None
        mg.telnet = any(t[:1] == ["telnet"] for t in svc)
        mg.http = any(t[:2] == ["web-management", "http"] for t in svc)
        mg.https = any(t[:2] == ["web-management", "https"] for t in svc)
        other = sorted({t[0] for t in svc if t and t[0] not in ("ssh", "telnet", "web-management")})
        mg.banner = (self.val("system", "login", "message") or "").replace("\\n", "\n").strip() or None
        mg.ntp_servers = [t[0] for t in self.sel("system", "ntp", "server") if t]
        mg.dns_servers = [t[0] for t in self.sel("system", "name-server") if t]
        mg.domain = self.val("system", "domain-name")
        mg.timezone = self.val("system", "time-zone")
        mg.syslog_servers = list(dict.fromkeys(t[0] for t in self.sel("system", "syslog", "host") if t))
        mg.mgmt_vrf = "mgmt_junos" if self.sel("system", "management-instance") else None
        mg.password_encryption = True  # Junos stores local passwords hashed ($6$/$5$/$1$)
        lo_filter = next((f for f, where in self.filters_applied.items() if any(w.startswith("lo0") and w.endswith(" in")
                                                                                for w in where)), None)
        mg.vty_acl = lo_filter
        for (name, _term), td in getattr(self, "_terms", {}).items():
            if name == lo_filter and any("accept" in x for x in td["then"]):
                for f in td["from"]:
                    if f.startswith(("source-address ", "address ")):
                        addr = f.split()[1]
                        if addr not in mg.allowed_mgmt_hosts and addr != "0.0.0.0/0":
                            mg.allowed_mgmt_hosts.append(addr)
        users: dict[str, m.LocalUser] = {}
        for t in self.sel("system", "login", "user"):
            if len(t) < 2:
                continue
            u = users.setdefault(t[0], m.LocalUser(name=t[0]))
            if t[1] == "class" and len(t) > 2:
                u.privilege = t[2]
            elif t[1] == "authentication" and len(t) > 2:
                kind = "encrypted-password (hashed)" if t[2] == "encrypted-password" else \
                    f"ssh-key ({t[2].removeprefix('ssh-')})" if t[2].startswith("ssh-") else t[2]
                if not u.auth:
                    u.auth = kind
                elif kind not in u.auth:
                    u.auth += f" + {kind}"
        root = self.sel("system", "root-authentication")
        if root:
            kinds = sorted({"encrypted-password (hashed)" if t[0] == "encrypted-password" else
                            f"ssh-key ({t[0].removeprefix('ssh-')})" for t in root if t})
            users = {"root": m.LocalUser(name="root", privilege="super-user", auth=" + ".join(kinds)), **users}
        mg.users = list(users.values())
        aaa = mg.aaa
        aaa.radius_servers = list(dict.fromkeys(t[0] for t in self.sel("system", "radius-server") if t))
        aaa.tacacs_servers = list(dict.fromkeys(t[0] for t in self.sel("system", "tacplus-server") if t))
        order = [t[0] for t in self.sel("system", "authentication-order") if t]
        if order:
            aaa.login_methods.append(f"authentication-order: {' '.join(order)}")
        aaa.accounting = bool(self.sel("system", "accounting"))
        sn = mg.snmp
        comms: dict[str, dict[str, str]] = {}
        for t in self.sel("snmp", "community"):
            c = comms.setdefault(t[0], {})
            if len(t) > 2 and t[1] == "authorization":
                c["auth"] = t[2]
            elif len(t) > 2 and t[1] == "clients":
                c["clients"] = ", ".join(x for x in (c.get("clients"), t[2]) if x)
        sn.communities = [community_label(name, c.get("auth", "read-only"),
                                          f"clients {c['clients']}" if c.get("clients") else None)
                          for name, c in comms.items()]
        if comms:
            sn.versions.append("v2c")
            sn.acl = next((f"clients {c['clients']}" for c in comms.values() if c.get("clients")), None)
        v3: dict[str, list[str]] = defaultdict(list)
        for t in self.sel("snmp", "v3", "usm", "local-engine", "user"):
            if len(t) > 1:
                v3[t[0]].append(t[1])
        for user, opts in v3.items():
            auth = next((o.removeprefix("authentication-").upper() for o in opts if o.startswith("authentication-")
                         and o != "authentication-none"), "-")
            priv = next((o.removeprefix("privacy-").upper() for o in opts if o.startswith("privacy-")
                         and o != "privacy-none"), "-")
            sn.v3_users.append(f"{user} ({'authPriv' if priv != '-' else 'authNoPriv'}, {auth}/{priv})")
        if v3:
            sn.versions.append("v3")
        sn.trap_hosts = list(dict.fromkeys(t[2] for t in self.sel("snmp", "trap-group") if len(t) > 2 and t[1] == "targets"))
        sn.trap_hosts += [t[3] for t in self.sel("snmp", "v3", "target-address") if len(t) > 3 and t[1] == "address"]
        sn.location = self.val("snmp", "location")
        sn.contact = self.val("snmp", "contact")
        sn.enabled = bool(comms or v3)
        d.location, d.contact = d.location or sn.location, d.contact or sn.contact
        if other:
            d.sections.append(m.Section(id="junos-services", title="System services",
                                        facts=[m.Fact(key="Other enabled services", value=", ".join(other))]))

    def parse_vc(self) -> None:
        vc = output(self.raw, "show virtual-chassis", "show virtual-chassis status")
        cfg_members = {t[0]: t for t in self.sel("virtual-chassis", "member") if t}
        rows = re.findall(r"^(\d+) \(FPC\s+\d+\)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\d+)\s+(\S+)", vc, re.M)
        if not rows and len(cfg_members) < 2:
            return
        members = [f"member {n} ({model}, {role.rstrip('*')}, {status}, SN {sn})" for n, status, sn, model, _p, role in rows] \
            or [f"member {n} ({' '.join(t[1:])})" for n, t in cfg_members.items()]
        state = None
        if rows:
            state = "ok" if all(r[1] == "Prsnt" for r in rows) else "degraded"
        details = {}
        vcid = first(r"Virtual Chassis ID:\s*(\S+)", vc)
        if vcid:
            details["virtual-chassis id"] = vcid
        if self.sel("virtual-chassis", "preprovisioned"):
            details["mode"] = "preprovisioned"
        self.dev.ha = m.HighAvailability(mode="virtual-chassis", group=vcid, members=members, state=state, details=details)
        for _n, _st, sn, model, _p, role in rows:
            self.dev.hardware.append(m.Fact(key=f"VC member ({role.rstrip('*')})", value=f"{model} SN {sn}"))

    def find_mgmt_ip(self) -> str | None:
        groups = [[i for i in self.ifs.values() if i.kind == "mgmt"],
                  [i for i in self.ifs.values() if i.kind == "vlan" and re.search(r"mgmt|manage", i.description or "", re.I)],
                  [i for i in self.ifs.values() if i.kind == "loopback"],
                  [i for i in self.ifs.values() if i.kind == "vlan"]]
        for group in groups:
            for itf in group:
                for ip in itf.ipv4:
                    if is_ip(ip.address) and not ip.address.startswith("127."):
                        return ip.address.split("/")[0]
        return self.raw.target if is_ip(self.raw.target) else None


class JuniperJunosDriver(Driver):
    id = "juniper_junos"
    label = "Juniper Junos (EX/QFX/MX/SRX)"
    methods = ("ssh", "file")
    netmiko_type = "juniper_junos"
    commands = tuple(JUNOS_COMMANDS)

    def collect(self, target: Target, creds: Credentials) -> RawCollection:
        return run_commands(target, creds, self.netmiko_type, list(JUNOS_COMMANDS), self.id)

    def parse(self, raw: RawCollection) -> m.Device:
        return JunosParser(raw, self.id).parse()


register(JuniperJunosDriver())
