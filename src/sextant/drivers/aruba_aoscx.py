"""Aruba AOS-CX driver (6xxx/8xxx/10000 CX switches), CLI over SSH or config-file import.

parse() reads `show running-config` (AOS-CX block syntax with 4-space indents) and
enriches it with show system / version / interface brief / vlan / lldp / ip route /
vsx status when present.
"""

from __future__ import annotations

import re
from collections import defaultdict

from sextant import model as m
from sextant.drivers import register
from sextant.drivers._ssh import run_commands
from sextant.drivers._stp import parse_aoscx as parse_stp_aoscx
from sextant.drivers._util import blocks, expand_vlans, first, fixed_columns, scrub_after
from sextant.drivers.base import Credentials, Driver, RawCollection, Target
from sextant.drivers.cisco_ios import IPV4, community_label, is_ip, kv_lines, network_cidr, output, parse_banner
from sextant.redact import redact_text

AOSCX_COMMANDS = [
    "show running-config",
    "show system",
    "show version",
    "show interface brief",
    "show vlan",
    "show lldp neighbor-info",
    "show ip route all-vrfs",
    "show vsx status",
    "show spanning-tree",
]

_SECRET_PREFIXES = [r"\bciphertext", r"\bplaintext", r"\bauth-pass(?:\s+(?:ciphertext|plaintext))?",
                    r"\bpriv-pass(?:\s+(?:ciphertext|plaintext))?"]


def norm_name(name: str) -> str:
    """'lag 1' -> 'lag1', 'vlan 10' -> 'vlan10', 'loopback 0' -> 'loopback0'; physical names unchanged."""
    name = re.sub(r"\s+multi-chassis.*$", "", name.strip())
    return re.sub(r"^(lag|vlan|loopback|tunnel)\s+(\d+)$", r"\1\2", name, flags=re.I)


def expand_ports(text: str) -> list[str]:
    """'1/1/1-1/1/3,lag1-lag2,1/1/48' -> individual port names."""
    out: list[str] = []
    for part in re.split(r"[,\s]+", text or ""):
        mt = re.match(r"^(\d+/\d+/)(\d+)-\1?(\d+)$", part) or re.match(r"^(\d+/\d+/)(\d+)-\d+/\d+/(\d+)$", part)
        ml = re.match(r"^(lag)(\d+)-(?:lag)?(\d+)$", part)
        mm = mt or ml
        if mm:
            out += [f"{mm.group(1)}{i}" for i in range(int(mm.group(2)), int(mm.group(3)) + 1)]
        elif part and part != "--":
            out.append(part)
    return out


class AosCxParser:
    def __init__(self, raw: RawCollection, platform: str):
        self.raw = raw
        self.cfg = output(raw, "show running-config", "show run", "config").replace("\r", "")
        self.dev = m.Device(hostname=raw.target or "unknown", vendor="Aruba (HPE)", platform=platform,
                            os_name="AOS-CX", role=m.DeviceRole.switch, collection_method=raw.method,
                            source=raw.target)
        self.dev.collection_warnings.extend(raw.warnings)
        self.ifs: dict[str, m.Interface] = {}
        self.helpers: dict[str, list[str]] = defaultdict(list)
        self.acl_apply: dict[str, list[str]] = defaultdict(list)
        self.ospf_if: list[tuple[str, str, str]] = []
        self.vips: dict[str, str] = {}

    def parse(self) -> m.Device:
        d = self.dev
        if not self.cfg:
            d.collection_warnings.append("No running configuration in collection: configuration sections are empty.")
        for step in (self.parse_system, self.parse_interfaces, self.parse_status, self.parse_vlans, self.parse_routes,
                     self.parse_ospf, self.parse_neighbors, self.parse_stp, self.parse_acls, self.parse_management,
                     self.parse_vsx):
            try:
                step()
            except Exception as exc:  # noqa: BLE001
                d.collection_warnings.append(f"{step.__name__} failed: {exc.__class__.__name__}: {exc}")
        d.interfaces = list(self.ifs.values())
        d.mgmt_ip = self.find_mgmt_ip()
        d.raw_config = scrub_after(redact_text(self.cfg), _SECRET_PREFIXES) if self.cfg else None
        return d

    def iface(self, name: str, create: bool = True) -> m.Interface | None:
        name = norm_name(name)
        itf = self.ifs.get(name.lower())
        if itf is None and create:
            n = name.lower()
            kind = ("lag" if n.startswith("lag") else "vlan" if n.startswith("vlan") else
                    "loopback" if n.startswith("loopback") else "mgmt" if n == "mgmt" else
                    "tunnel" if n.startswith("tunnel") else "physical")
            itf = m.Interface(name=name, kind=kind)
            self.ifs[n] = itf
        return itf

    # ------------------------------------------------------------------ identity
    def parse_system(self) -> None:
        d = self.dev
        d.hostname = first(r"^hostname\s+(\S+)", self.cfg) or d.hostname
        sysout = kv_lines(output(self.raw, "show system"))
        ver = kv_lines(output(self.raw, "show version"))
        if not sysout and not ver:
            d.collection_warnings.append("show system / show version not collected: model, serial and uptime missing.")
        if not first(r"^hostname\s+(\S+)", self.cfg) and sysout.get("Hostname"):
            d.hostname = sysout["Hostname"]
        d.os_version = (ver.get("Version") or sysout.get("ArubaOS-CX Version")
                        or first(r"^!Version ArubaOS-CX (\S+)", self.cfg))
        product = sysout.get("Product Name")
        if product:
            parts = product.split()
            d.model = f"{parts[1]} ({parts[0]})" if len(parts) > 1 and re.match(r"^[A-Z]{2}\d{3}[A-Z]$", parts[0]) else product
            d.hardware.append(m.Fact(key="Product", value=product))
        d.serial = sysout.get("Chassis Serial Nbr") or sysout.get("Serial Number")
        d.uptime = sysout.get("Up Time")
        d.location = sysout.get("System Location") or None
        d.contact = sysout.get("System Contact") or None
        for key in ("Base MAC Address", "CPU Util (%)", "Memory Usage (%)"):
            if sysout.get(key):
                d.hardware.append(m.Fact(key=key, value=sysout[key]))
        for key in ("Active Image", "Service OS Version", "BIOS Version", "Build Date"):
            if ver.get(key):
                d.hardware.append(m.Fact(key=key, value=ver[key]))
        for vid in re.findall(r"^vrf (\S+)\s*$", self.cfg, re.M):
            if vid not in d.vrfs:
                d.vrfs.append(vid)

    # ------------------------------------------------------------------ interfaces
    def parse_interfaces(self) -> None:
        for header, lines in blocks(self.cfg, r"^interface\s+\S+"):
            raw_name = header.split(None, 1)[1]
            itf = self.iface(raw_name)
            if "multi-chassis" in raw_name:
                itf.extra["multi-chassis"] = "yes (VSX)"
            st: dict = {"admin": None, "routing": None, "smode": None, "bpdu": False}
            for ln in lines:
                self._line(itf, ln, st)
            if st["admin"] is None:
                itf.enabled = itf.kind not in ("physical", "lag")
            if itf.kind in ("vlan", "loopback", "mgmt", "tunnel"):
                itf.mode = m.PortMode.routed if itf.ipv4 or itf.kind == "vlan" else m.PortMode.unknown
            elif st["smode"] == "trunk":
                itf.mode = m.PortMode.trunk
                itf.native_vlan = itf.native_vlan or 1
                itf.trunk_vlans = itf.trunk_vlans or "all"
            elif st["smode"] == "access" or st["routing"] is False:
                itf.mode, itf.access_vlan = m.PortMode.access, itf.access_vlan or 1
            elif itf.ipv4 or st["routing"] is True:
                itf.mode = m.PortMode.routed
            if itf.lag and itf.kind == "physical":
                itf.mode = m.PortMode.lag_member
        members = [i for i in self.ifs.values() if i.lag]
        for itf in members:
            parent = self.iface(itf.lag)
            if itf.name not in parent.lag_members:
                parent.lag_members.append(itf.name)
        for itf in self.ifs.values():
            if itf.kind == "lag" and itf.lag_members and not itf.lag_protocol:
                itf.lag_protocol = "static"  # 'interface lag N' without 'lacp mode'
        for itf in members:
            itf.lag_protocol = self.iface(itf.lag).lag_protocol

    def _line(self, itf: m.Interface, ln: str, st: dict) -> None:  # noqa: C901
        if ln.startswith("description "):
            itf.description = ln[12:].strip()
        elif ln == "shutdown":
            itf.enabled, st["admin"] = False, "down"
        elif ln == "no shutdown":
            itf.enabled, st["admin"] = True, "up"
        elif ln == "no routing":
            st["routing"] = False
        elif ln == "routing":
            st["routing"] = True
        elif mt := re.match(r"vlan access (\d+)", ln):
            itf.access_vlan, st["smode"] = int(mt.group(1)), "access"
        elif mt := re.match(r"vlan trunk native (\d+)( tag)?", ln):
            itf.native_vlan, st["smode"] = int(mt.group(1)), "trunk"
            if mt.group(2):
                itf.extra["native vlan tagged"] = "yes"
        elif mt := re.match(r"vlan trunk allowed (\S+)", ln):
            st["smode"] = "trunk"
            itf.trunk_vlans = mt.group(1) if not itf.trunk_vlans or itf.trunk_vlans == "all" else \
                f"{itf.trunk_vlans},{mt.group(1)}"
        elif mt := re.match(r"lag (\d+)$", ln):
            itf.lag = f"lag{mt.group(1)}"
        elif mt := re.match(r"lacp mode (\S+)", ln):
            itf.lag_protocol = "lacp"
            itf.extra["lacp mode"] = mt.group(1)
        elif mt := re.match(r"ip (?:address|static) (\S+/\d+)( secondary)?", ln):
            itf.ipv4.append(m.IPAddress(address=mt.group(1), secondary=bool(mt.group(2))))
        elif ln.startswith("ip dhcp"):
            itf.ipv4.append(m.IPAddress(address="dhcp"))
        elif mt := re.match(r"ipv6 address (\S+)", ln):
            itf.ipv6.append(mt.group(1))
        elif mt := re.match(rf"active-gateway ip ({IPV4})", ln):
            self.vips[itf.name] = mt.group(1)
        elif mt := re.match(rf"vrrp \d+ address-family ipv4|address ({IPV4}) primary", ln):
            if mt.group(1):
                self.vips[itf.name] = mt.group(1)
        elif mt := re.match(rf"ip helper-address ({IPV4})", ln):
            self.helpers[itf.name].append(mt.group(1))
        elif mt := re.match(r"vrf attach (\S+)", ln):
            itf.vrf = mt.group(1)
        elif mt := re.match(r"(?:ip )?mtu (\d+)", ln):
            itf.mtu = itf.mtu or int(mt.group(1))
        elif mt := re.match(r"speed (\S+)", ln):
            itf.speed = mt.group(1)
        elif ln.startswith("spanning-tree port-type admin-edge"):
            itf.stp_edge = True
        elif ln == "spanning-tree bpdu-guard":
            itf.extra["bpduguard"] = "enabled"
        elif mt := re.match(r"spanning-tree (root-guard|loop-guard|tcn-guard|bpdu-filter)", ln):
            itf.extra[mt.group(1)] = "enabled"
        elif ln == "loop-protect":
            itf.extra["loop-protect"] = "enabled"
        elif mt := re.match(r"apply access-list (ip|ipv6|mac) (\S+) (in|out|routed-in|routed-out)", ln):
            self.acl_apply[mt.group(2)].append(f"{itf.name} {mt.group(3)}")
        elif mt := re.match(r"ip ospf (\d+) area (\S+)", ln):
            self.ospf_if.append((mt.group(1), itf.name, mt.group(2)))
        elif mt := re.match(rf"default-gateway ({IPV4})", ln):
            self.dev.routes.append(m.Route(prefix="0.0.0.0/0", next_hop=mt.group(1), interface=itf.name,
                                           vrf="mgmt", protocol="static", distance=1,
                                           description="mgmt default-gateway"))
        elif ln.startswith("port-access") or ln.startswith("aaa authentication port-access"):
            itf.extra["port-access"] = ln
        elif mt := re.match(r"port-security(.*)", ln):
            itf.port_security = True

    def parse_status(self) -> None:
        rows = fixed_columns(output(self.raw, "show interface brief"), r"^Port\s+Native\s+Mode", multiword=False)
        for r in rows:
            port = r.get("Port", "")
            if not port or not re.match(r"^(\d+/\d+/\d+|lag\d+|vlan\d+|loopback\d+|mgmt)$", port):
                continue
            itf = self.iface(port)
            if r.get("Enabled") in ("yes", "no"):
                itf.enabled = r["Enabled"] == "yes"
            if r.get("Status") in ("up", "down"):
                itf.oper_up = r["Status"] == "up"
            speed = r.get("Speed", "")
            if itf.oper_up and speed.isdigit() and not itf.speed:
                # same form as Cisco/AOS-S: Mbps below 10G ('1000', '2500'), then '10G', '25G', '100G'
                itf.speed = f"{int(speed) // 1000}G" if int(speed) >= 10000 and int(speed) % 1000 == 0 else speed
            if r.get("Type") not in (None, "", "--") and itf.kind == "physical":
                itf.extra.setdefault("media", r["Type"])
            if r.get("Reason") and itf.oper_up is False:
                itf.extra.setdefault("down reason", r["Reason"])
            if not itf.description and r.get("Description") not in (None, "", "--"):
                itf.description = r["Description"]

    # ------------------------------------------------------------------ L2/L3
    def parse_vlans(self) -> None:
        vlans: dict[int, m.Vlan] = {}
        for header, lines in blocks(self.cfg, r"^vlan\s+[\d,\-]+\s*$"):
            ids = expand_vlans(header.split(None, 1)[1])
            name = next((ln.split(None, 1)[1].strip('"') for ln in lines if ln.startswith("name ")), None)
            for vid in ids:
                v = vlans.setdefault(vid, m.Vlan(id=vid))
                if name and len(ids) == 1:
                    v.name = name
                if "voice" in lines:
                    v.name = v.name or "voice"
        for r in fixed_columns(output(self.raw, "show vlan"), r"^VLAN\s+Name\s+Status", multiword=False):
            if not r.get("VLAN", "").isdigit():
                continue
            v = vlans.setdefault(int(r["VLAN"]), m.Vlan(id=int(r["VLAN"])))
            v.name = v.name or r.get("Name") or None
            v.ports = expand_ports(r.get("Interfaces", ""))
        have_table = any(v.ports for v in vlans.values())
        for itf in self.ifs.values():
            if itf.kind == "vlan":
                vid = int(re.sub(r"\D", "", itf.name))
                v = vlans.setdefault(vid, m.Vlan(id=vid))
                v.svi_ipv4 = [ip.address for ip in itf.ipv4]
                v.dhcp_helpers = self.helpers.get(itf.name, [])
                vip = self.vips.get(itf.name)
                if vip and itf.ipv4:
                    itf.ipv4[0].vrrp_vip = vip
            elif not have_table and itf.mode == m.PortMode.access and itf.access_vlan:
                vlans.setdefault(itf.access_vlan, m.Vlan(id=itf.access_vlan)).ports.append(itf.name)
        self.dev.vlans = [vlans[k] for k in sorted(vlans)]

    def parse_routes(self) -> None:
        d = self.dev
        for prefix, nh, rest in re.findall(r"^ip route (\S+/\d+) (\S+)(.*)$", self.cfg, re.M):
            r = m.Route(prefix=prefix, protocol="static", vrf=first(r"\bvrf (\S+)", rest),
                        distance=int(first(r"distance (\d+)", rest) or 1), description=first(r"\bname (\S+)", rest))
            if is_ip(nh):
                r.next_hop = nh
            elif nh in ("blackhole", "reject", "nullroute"):
                r.interface = nh
            else:
                r.interface = nh
            d.routes.append(r)
        table = output(self.raw, "show ip route all-vrfs", "show ip route")
        keys = {(r.prefix, r.next_hop, r.vrf) for r in d.routes}
        vrf, last = None, None
        for ln in table.splitlines():
            mt = re.match(r"^VRF:\s*(\S+)", ln)
            if mt:
                vrf = None if mt.group(1) == "default" else mt.group(1)
                continue
            ecmp = re.match(rf"^\s{{10,}}({IPV4})\s+(\S+)\s+\S+\s+\[(\d+)/\d+\]", ln)
            if ecmp and last is not None:
                d.routes.append(last.model_copy(update={"next_hop": ecmp.group(1), "interface": ecmp.group(2),
                                                        "distance": int(ecmp.group(3))}))
                continue
            mt = re.match(rf"^({IPV4}/\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+\[(\d+)/\d+\]", ln)
            last = None
            if not mt:
                continue
            code = mt.group(5).split("/")[0]
            proto = {"C": "connected", "S": "static", "O": "ospf", "B": "bgp", "R": "rip", "D": "dhcp"}.get(code, code)
            if code == "L":
                continue
            nh = mt.group(2) if is_ip(mt.group(2)) else None
            if proto == "static" and (mt.group(1), nh, vrf) in keys:
                continue
            last = m.Route(prefix=mt.group(1), next_hop=nh, interface=mt.group(3) if mt.group(3) != "-" else None,
                           protocol=proto, distance=int(mt.group(6)), vrf=vrf)
            d.routes.append(last)

    def parse_ospf(self) -> None:
        for header, lines in blocks(self.cfg, r"^router (ospf|ospfv3|bgp)\b"):
            parts = header.split()
            rp = m.RoutingProtocol(protocol=parts[1], process_id=parts[2] if len(parts) > 2 else None)
            if parts[1] == "bgp":
                rp.asn, rp.process_id = rp.process_id, None
            if "vrf" in parts:
                rp.details["vrf"] = parts[parts.index("vrf") + 1]
            for ln in lines:
                if mt := re.match(rf"(?:bgp )?router-id ({IPV4})", ln):
                    rp.router_id = mt.group(1)
                elif mt := re.match(r"area (\S+)(.*)$", ln):
                    rp.details[f"area {mt.group(1)}"] = mt.group(2).strip() or "normal"
                elif mt := re.match(rf"neighbor ({IPV4}) remote-as (\S+)", ln):
                    rp.neighbors.append(f"{mt.group(1)} (AS {mt.group(2)})")
                elif ln.startswith(("redistribute ", "passive-interface ", "default-information ")):
                    key = ln.split()[0]
                    rp.details[key] = ", ".join(x for x in (rp.details.get(key), ln) if x)
            for pid, ifname, area in self.ospf_if:
                if parts[1] == "ospf" and pid == rp.process_id:
                    rp.networks.append(f"{ifname} area {area}")
            self.dev.routing_protocols.append(rp)

    def parse_neighbors(self) -> None:
        rows = fixed_columns(output(self.raw, "show lldp neighbor-info", "show lldp neighbor-info detail"),
                             r"^LOCAL-PORT\s+CHASSIS-ID")
        for r in rows:
            local = r.get("LOCAL-PORT", "")
            if not re.match(r"^(\d+/\d+/\d+|mgmt)$", local):
                continue
            self.dev.neighbors.append(m.Neighbor(
                local_port=local, remote_device=r.get("SYS-NAME") or r.get("CHASSIS-ID") or "?",
                remote_port=r.get("PORT-ID") or None, protocol="lldp", remote_chassis=r.get("CHASSIS-ID") or None))

    def parse_stp(self) -> None:
        cfg = self.cfg
        if not cfg:
            return
        enabled = re.search(r"^spanning-tree\s*$", cfg, re.M)
        mode = first(r"^spanning-tree mode (\S+)", cfg)
        st = m.SpanningTree(mode=("rapid-pvst" if mode == "rpvst" else mode or "mstp") if enabled else "disabled")
        prio = first(r"^spanning-tree priority (\d+)", cfg)
        if prio:
            st.priority = f"{int(prio) * 4096} (multiplier {prio})"
        for vl, p in re.findall(r"^spanning-tree vlan (\S+) priority (\d+)", cfg, re.M):  # RPVST: before the global
            st.configured_priority[vl] = int(p) * 4096
        st.configured_priority["default" if st.configured_priority else "1-4094"] = int(prio) * 4096 if prio else 32768
        for inst, p in re.findall(r"^spanning-tree instance (\d+) priority (\d+)", cfg, re.M):
            st.configured_priority[f"mst {inst}"] = int(p) * 4096
        st.instances, st.bridge_mac = parse_stp_aoscx(output(self.raw, "show spanning-tree"))
        if st.instances:
            st.root_bridge = any(i.is_root for i in st.instances)
        edges = [i for i in self.ifs.values() if i.stp_edge]
        st.bpdu_guard_default = bool(edges) and all(i.extra.get("bpduguard") for i in edges)
        st.details["admin-edge ports"] = str(len(edges))
        st.details["edge ports with bpdu-guard"] = str(sum(1 for i in edges if i.extra.get("bpduguard")))
        for key, pat in (("config-name", r"^spanning-tree config-name (\S+)"),
                         ("config-revision", r"^spanning-tree config-revision (\S+)")):
            val = first(pat, cfg)
            if val:
                st.details[key] = val
        loop = [i.name for i in self.ifs.values() if i.extra.get("loop-protect")]
        if loop:
            st.details["loop-protect"] = ", ".join(loop)
        self.dev.spanning_tree = st

    def parse_acls(self) -> None:
        acls = []
        for name, where in re.findall(r"^apply access-list (?:ip|ipv6|mac) (\S+) (control-plane.*|\S+.*)$", self.cfg, re.M):
            self.acl_apply[name].append(where.strip())
        for header, lines in blocks(self.cfg, r"^access-list (ip|ipv6|mac) \S+"):
            kind, name = header.split()[1], header.split()[2]
            acl = m.Acl(name=name, kind={"ip": "extended"}.get(kind, kind), applied_to=self.acl_apply.get(name, []))
            for ln in lines:
                mt = re.match(r"^(\d+)\s+(permit|deny)\s+(.*)$", ln)
                if mt:
                    acl.entries.append(m.AclEntry(seq=mt.group(1), action=mt.group(2), text=mt.group(3)))
            acls.append(acl)
        self.dev.acls = acls

    # ------------------------------------------------------------------ management
    def parse_management(self) -> None:  # noqa: C901
        cfg, mg = self.cfg, self.dev.management
        if not cfg:
            return
        mg.ssh = bool(re.search(r"^ssh server vrf \S+", cfg, re.M))
        mg.ssh_version = "2" if mg.ssh else None
        mg.https = bool(re.search(r"^https-server vrf \S+", cfg, re.M))
        mg.http = False  # AOS-CX has no clear-text web/REST server
        mg.telnet = False  # AOS-CX has no telnet server
        mg.mgmt_vrf = "mgmt" if re.search(r"vrf mgmt", cfg) else None
        mg.banner = parse_banner(cfg, ("motd", "exec"))
        mg.ntp_servers = re.findall(r"^ntp server (\S+)", cfg, re.M)
        mg.dns_servers = re.findall(r"^ip dns server-address (\S+)", cfg, re.M)
        mg.domain = first(r"^ip dns domain-name (\S+)", cfg)
        mg.timezone = first(r"^clock timezone (\S+)", cfg) or kv_lines(output(self.raw, "show system")).get("Time Zone")
        mg.syslog_servers = re.findall(rf"^logging ({IPV4}|\S+\.\S+)\b", cfg, re.M)
        timeout = first(r"^\s*(?:cli-session\s*\n\s*)?timeout (\d+)", cfg)
        mg.console_timeout_min = int(timeout) if timeout else None
        sn = mg.snmp
        for header, lines in blocks(cfg, r"^snmp-server community \S+"):
            value = header.split()[2]
            access = next((ln.split()[-1].upper() for ln in lines if ln.startswith("access-level")), "RO")
            acl = next((ln.split()[-1] for ln in lines if ln.startswith("access-list")), None)
            sn.communities.append(community_label(value, access, f"acl {acl}" if acl else None))
        if sn.communities:
            sn.versions.append("v2c")
        for name, rest in re.findall(r"^snmpv3 user (\S+)(.*)$", cfg, re.M):
            auth = (first(r"\bauth (\S+)", rest) or "-").upper()
            priv = (first(r"\bpriv (\S+)", rest) or "-").upper()
            lvl = "authPriv" if priv != "-" else "authNoPriv" if auth != "-" else "noAuthNoPriv"
            sn.v3_users.append(f"{name} ({lvl}, {auth}/{priv})")
        if sn.v3_users:
            sn.versions.append("v3")
        sn.trap_hosts = list(dict.fromkeys(re.findall(r"^snmp-server host (\S+)", cfg, re.M)))
        sn.location = first(r"^snmp-server system-location (.+)$", cfg)
        sn.contact = first(r"^snmp-server system-contact (.+)$", cfg)
        sn.enabled = bool(re.search(r"^snmp-server vrf", cfg, re.M)) or bool(sn.communities or sn.v3_users)
        aaa = mg.aaa
        aaa.radius_servers = re.findall(r"^radius-server host (\S+)", cfg, re.M)
        aaa.tacacs_servers = re.findall(r"^tacacs-server host (\S+)", cfg, re.M)
        aaa.login_methods = [f"{t} {svc} {lst}: {meth}" for t, svc, lst, meth in
                             re.findall(r"^aaa (authentication|authorization) (\S+) (\S+) (.+)$", cfg, re.M)]
        aaa.accounting = bool(re.search(r"^aaa accounting ", cfg, re.M))
        for name, rest in re.findall(r"^user (\S+)(.*)$", cfg, re.M):
            u = next((x for x in mg.users if x.name == name), None)
            if u is None:
                u = m.LocalUser(name=name)
                mg.users.append(u)
            grp = first(r"\bgroup (\S+)", rest)
            if grp:
                u.privilege = grp
            if re.search(r"\bpassword\b", rest):
                kind = "plaintext" if " plaintext " in f"{rest} " else "ciphertext"
                u.auth = f"password {kind} (encrypted)" if kind == "ciphertext" else "password plaintext"
            if "authorized-key" in rest:
                u.auth = f"{u.auth} + ssh-key" if u.auth else "ssh-key"
        mg.password_encryption = not any(u.auth == "password plaintext" for u in mg.users)
        ctl = next((n for n, w in self.acl_apply.items() if any("control-plane" in x for x in w)), None)
        mg.vty_acl = ctl
        acl = next((a for a in self.dev.acls if a.name == ctl), None)
        for e in acl.entries if acl else []:
            mt = re.match(rf"^\S+\s+({IPV4}(?:/{IPV4}|/\d+)?|any)\s", e.text)
            if e.action == "permit" and mt and mt.group(1) != "any" and _cidr(mt.group(1)) not in mg.allowed_mgmt_hosts:
                mg.allowed_mgmt_hosts.append(_cidr(mt.group(1)))

    # ------------------------------------------------------------------ HA
    def parse_vsx(self) -> None:
        cfg_block = next(((h, ls) for h, ls in blocks(self.cfg, r"^vsx\s*$")), None)
        status = output(self.raw, "show vsx status")
        if not cfg_block and not status:
            return
        details: dict[str, str] = {}
        if cfg_block:
            for ln in cfg_block[1]:
                for key in ("system-mac", "inter-switch-link", "role", "keepalive", "linkup-delay-timer"):
                    if ln.startswith(key + " "):
                        details[key] = ln[len(key) + 1:].strip()
        kv = kv_lines(status)
        for key in ("ISL channel", "ISL mgmt channel", "Config Sync Status", "NAE", "HTTPS Server"):
            if key in kv:
                details[key] = kv[key]
        attr_rows = []
        for ln in status.splitlines():
            mt = re.match(r"^(ISL link|ISL version|System MAC|Platform|Software Version|Device Role)\s{2,}(\S+)\s+(\S+)", ln)
            if mt:
                attr_rows.append([mt.group(1), mt.group(2), mt.group(3)])
                if mt.group(1) == "Device Role":
                    details["role"] = mt.group(2)
        isl = re.sub(r"\s+", "", details.get("inter-switch-link", ""))
        isl_members = {p.lower() for i in self.ifs.values() if i.name.lower() == isl for p in i.lag_members}
        peers = sorted({n.remote_device for n in self.dev.neighbors if n.local_port.lower() in isl_members})
        in_sync = kv.get("ISL channel", "").lower() == "in-sync" and "in-sync" in kv.get("Config Sync Status", "in-sync").lower()
        self.dev.ha = m.HighAvailability(mode="vsx", group=details.get("system-mac"), members=[self.dev.hostname, *peers],
                                         state=("in-sync" if in_sync else "out-of-sync") if status else None,
                                         details=details)
        self.dev.sections.append(m.Section(
            id="vsx", title="VSX", summary_relevant=True, facts=[m.Fact(key=k, value=v) for k, v in details.items()],
            tables=[m.Table(columns=["Attribute", "Local", "Peer"], rows=attr_rows)] if attr_rows else []))

    def find_mgmt_ip(self) -> str | None:
        order = [i for i in self.ifs.values() if i.kind == "mgmt"] + \
                [i for i in self.ifs.values() if i.kind == "vlan" and re.search(r"mgmt|manage", i.description or "", re.I)] + \
                [i for i in self.ifs.values() if i.kind == "loopback"] + \
                [i for i in self.ifs.values() if i.kind == "vlan"]
        for itf in order:
            for ip in itf.ipv4:
                if is_ip(ip.address):
                    return ip.address.split("/")[0]
        return self.raw.target if is_ip(self.raw.target) else None


def _cidr(text: str) -> str:
    """'10.10.98.0/255.255.255.0' -> '10.10.98.0/24'."""
    if "/" in text and is_ip(text.split("/")[1]):
        return network_cidr(*text.split("/"))
    return text


class ArubaAosCxDriver(Driver):
    id = "aruba_aoscx"
    label = "Aruba AOS-CX"
    methods = ("ssh", "file")
    netmiko_type = "aruba_aoscx"
    commands = tuple(AOSCX_COMMANDS)

    def collect(self, target: Target, creds: Credentials) -> RawCollection:
        return run_commands(target, creds, self.netmiko_type, list(AOSCX_COMMANDS), self.id)

    def parse(self, raw: RawCollection) -> m.Device:
        return AosCxParser(raw, self.id).parse()


register(ArubaAosCxDriver())
