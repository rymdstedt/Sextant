"""HPE Aruba AOS-S / ProCurve driver (2530/2540/2930/3810/5400R...).

AOS-S keeps VLAN membership in `vlan` blocks (untagged/tagged port lists) rather
than per interface, and LAGs as `trunk <ports> trkN lacp` lines, so port modes are
derived from VLAN membership after the whole config has been read.
"""

from __future__ import annotations

import re
from collections import defaultdict

from sextant import model as m
from sextant.drivers import register
from sextant.drivers._ssh import run_commands
from sextant.drivers._util import blocks, compress_vlans, first, fixed_columns, mask_to_prefix, scrub_after
from sextant.drivers.base import Credentials, Driver, RawCollection, Target
from sextant.drivers.cisco_ios import IPV4, community_label, is_ip, network_cidr, output
from sextant.redact import redact_text

PROCURVE_COMMANDS = [
    "show running-config",
    "show system",
    "show version",
    "show interfaces brief",
    "show lldp info remote-device",
    "show trunks",
    "show vlans",
]

_MODELS = {"JL256A": "Aruba 2930F-48G-PoE+-4SFP+", "JL259A": "Aruba 2930F-24G-4SFP", "JL261A": "Aruba 2930F-24G-PoE+-4SFP",
           "JL262A": "Aruba 2930F-48G-PoE+-4SFP", "JL253A": "Aruba 2930F-24G-4SFP+", "JL254A": "Aruba 2930F-48G-4SFP+",
           "JL322A": "Aruba 2930M-48G-PoE+", "J9772A": "HP 2530-48G-PoE+", "J9773A": "HP 2530-24G-PoE+",
           "J9853A": "HP 2530-48G-PoE+-2SFP+", "J9850A": "HP 5406R zl2", "J9851A": "HP 5412R zl2",
           "JL075A": "Aruba 3810M-16SFP+-2-slot", "J9727A": "HP 2920-24G-PoE+", "J9729A": "HP 2920-48G-PoE+"}

_SECRET_PREFIXES = [r"\b(?:sha1|sha256|plaintext)", r"\bsnmpv3 user \"?[^\"\s]+\"? auth (?:md5|sha)",
                    r"\bpriv (?:des|aes)", r"\bkey"]


def port_name(p: str) -> str:
    return re.sub(r"^trk(\d+)$", r"Trk\1", p.strip(), flags=re.I)


def expand_ports(text: str) -> list[str]:
    """'1-4,A1-A3,1/1-1/2,Trk1' -> ['1','2','3','4','A1','A2','A3','1/1','1/2','Trk1']."""
    out: list[str] = []
    for part in re.split(r"[,\s]+", (text or "").strip()):
        mt = re.match(r"^([A-Za-z]?|\d+/)(\d+)-\1(\d+)$", part)
        if mt:
            out += [f"{mt.group(1)}{i}" for i in range(int(mt.group(2)), int(mt.group(3)) + 1)]
        elif part:
            out.append(port_name(part))
    return out


def _sort_key(name: str) -> tuple:
    nums = [int(x) for x in re.findall(r"\d+", name)]
    return (name.lower().startswith("trk"), re.sub(r"[\d/]+", "", name), nums)


class ProcurveParser:
    def __init__(self, raw: RawCollection, platform: str):
        self.raw = raw
        self.cfg = output(raw, "show running-config", "show run", "config").replace("\r", "")
        self.dev = m.Device(hostname=raw.target or "unknown", vendor="Aruba (HPE)", platform=platform,
                            os_name="ArubaOS-Switch", role=m.DeviceRole.switch, collection_method=raw.method,
                            source=raw.target)
        self.dev.collection_warnings.extend(raw.warnings)
        self.ifs: dict[str, m.Interface] = {}
        self.untagged: dict[str, set[int]] = defaultdict(set)
        self.tagged: dict[str, set[int]] = defaultdict(set)
        self.voice_vlans: set[int] = set()

    def parse(self) -> m.Device:
        d = self.dev
        if not self.cfg:
            d.collection_warnings.append("No running configuration in collection: configuration sections are empty.")
        for step in (self.parse_system, self.parse_interfaces, self.parse_trunks, self.parse_vlans, self.apply_modes,
                     self.parse_status, self.parse_routes, self.parse_neighbors, self.parse_stp, self.parse_management,
                     self.parse_ha):
            try:
                step()
            except Exception as exc:  # noqa: BLE001
                d.collection_warnings.append(f"{step.__name__} failed: {exc.__class__.__name__}: {exc}")
        d.interfaces = sorted(self.ifs.values(), key=lambda i: _sort_key(i.name))
        d.mgmt_ip = self.find_mgmt_ip()
        d.raw_config = scrub_after(redact_text(self.cfg), _SECRET_PREFIXES) if self.cfg else None
        return d

    def iface(self, name: str) -> m.Interface:
        name = port_name(name)
        itf = self.ifs.get(name.lower())
        if itf is None:
            itf = m.Interface(name=name, kind="lag" if name.lower().startswith("trk") else "physical")
            self.ifs[name.lower()] = itf
        return itf

    # ------------------------------------------------------------------ identity
    def parse_system(self) -> None:
        d, cfg, sysout = self.dev, self.cfg, output(self.raw, "show system", "show system information")
        if not sysout:
            d.collection_warnings.append("show system not collected: serial number and uptime missing.")
        d.hostname = first(r'^hostname "?([^"\n]+?)"?\s*$', cfg) or first(r"System Name\s*:\s*(\S+)", sysout) or d.hostname
        sku = first(r"^; (\S+) Configuration Editor", cfg)
        d.os_version = (first(r"Software revision\s*:\s*(\S+)", sysout) or first(r"^\s*([A-Z]{2}\.\d+\.\d+\.\d+)\s*$", output(
            self.raw, "show version")) or first(r"Created on release #(\S+)", cfg))
        if sku:
            d.model = f"{_MODELS.get(sku.upper(), sku.upper())} ({sku.upper()})" if sku.upper() in _MODELS else sku.upper()
        d.serial = first(r"Serial Number\s*:\s*(\S+)", sysout)
        d.uptime = first(r"Up Time\s*:\s*(.+?)(?:\s{2,}|$)", sysout)
        d.location = first(r"System Location\s*:\s*(.+?)\s*$", sysout) or first(r'^snmp-server location "([^"]*)"', cfg)
        d.contact = first(r"System Contact\s*:\s*(.+?)\s*$", sysout) or first(r'^snmp-server contact "([^"]*)"', cfg)
        for key, pat in (("ROM version", r"ROM Version\s*:\s*(\S+)"), ("Base MAC", r"Base MAC Addr\s*:\s*(\S+)"),
                         ("Memory total", r"Memory\s+- Total\s*:\s*(\S+)"), ("CPU util (%)", r"CPU Util \(%\)\s*:\s*(\S+)")):
            val = first(pat, sysout)
            if val:
                d.hardware.append(m.Fact(key=key, value=val))
        for num, typ in re.findall(r"^module (\S+) type (\S+)", cfg, re.M):
            d.hardware.append(m.Fact(key=f"Module {num}", value=typ.upper()))
        boot = first(r"Boot Image:\s*(\S+)", output(self.raw, "show version"))
        if boot:
            d.hardware.append(m.Fact(key="Boot image", value=boot))

    # ------------------------------------------------------------------ ports
    def parse_interfaces(self) -> None:
        for header, lines in blocks(self.cfg, r"^interface\s+\S+"):
            itf = self.iface(header.split()[1])
            for ln in lines:
                if mt := re.match(r'^name "?([^"]*)"?', ln):
                    itf.description = mt.group(1)
                elif ln == "disable":
                    itf.enabled = False
                elif ln == "enable":
                    itf.enabled = True
                elif mt := re.match(r"^speed-duplex (\S+)", ln):
                    itf.speed = mt.group(1)
                elif ln.startswith("no power-over-ethernet"):
                    itf.poe = False
                elif ln.startswith("spanning-tree admin-edge-port"):
                    itf.stp_edge = True
                elif ln.startswith("spanning-tree bpdu-protection"):
                    itf.extra["bpduguard"] = "enabled"
                elif ln.startswith("dhcp-snooping trust"):
                    itf.extra["dhcp snooping"] = "trusted"
                elif mt := re.match(r"^(?:ip )?access-group \"?([^\"\s]+)\"? (in|out)", ln):
                    itf.extra[f"acl {mt.group(2)}"] = mt.group(1)
                elif ln.startswith("port-security"):
                    itf.port_security = True

    def parse_trunks(self) -> None:
        for ports, trk, typ in re.findall(r"^trunk (\S+) (trk\d+)(?: (\S+))?", self.cfg, re.M | re.I):
            lag = self.iface(trk)
            lag.lag_protocol = "lacp" if "lacp" in (typ or "").lower() else "static"
            if typ:
                lag.extra["trunk type"] = typ
            for p in expand_ports(ports):
                mem = self.iface(p)
                mem.lag, mem.lag_protocol = lag.name, lag.lag_protocol
                if mem.name not in lag.lag_members:
                    lag.lag_members.append(mem.name)
        for ln in output(self.raw, "show trunks").splitlines():
            mt = re.match(r"^\s*(\S+)\s*\|.*\|\s*(Trk\d+)\s+(\S+)", ln)
            if mt:
                lag, mem = self.iface(mt.group(2)), self.iface(mt.group(1))
                lag.lag_protocol = lag.lag_protocol or ("lacp" if "lacp" in mt.group(3).lower() else "static")
                if not mem.lag:
                    mem.lag = lag.name
                    lag.lag_members.append(mem.name)

    def parse_vlans(self) -> None:
        vlans: list[m.Vlan] = []
        rows: list[list[str]] = []
        self.vlan_ips: dict[int, list[str]] = {}
        for header, lines in blocks(self.cfg, r"^vlan \d+\s*$"):
            vid = int(header.split()[1])
            v = m.Vlan(id=vid)
            unt: list[str] = []
            tag: list[str] = []
            for ln in lines:
                if mt := re.match(r'^name "?([^"]*)"?', ln):
                    v.name = mt.group(1)
                elif mt := re.match(r"^untagged (\S+)", ln):
                    unt += expand_ports(mt.group(1))
                elif mt := re.match(r"^tagged (\S+)", ln):
                    tag += expand_ports(mt.group(1))
                elif mt := re.match(rf"^ip address ({IPV4}) ({IPV4})", ln):
                    v.svi_ipv4.append(mask_to_prefix(mt.group(1), mt.group(2)))
                elif mt := re.match(rf"^ip address ({IPV4}/\d+)", ln):
                    v.svi_ipv4.append(mt.group(1))
                elif ln.startswith("ip address dhcp"):
                    v.svi_ipv4.append("dhcp")
                elif mt := re.match(rf"^ip helper-address ({IPV4})", ln):
                    v.dhcp_helpers.append(mt.group(1))
                elif ln == "voice":
                    self.voice_vlans.add(vid)
            for p in unt:
                self.untagged[p].add(vid)
                self.iface(p)
            for p in tag:
                self.tagged[p].add(vid)
                self.iface(p)
            v.ports = unt
            rows.append([str(vid), v.name or "", _compact(unt), _compact(tag), "yes" if vid in self.voice_vlans else ""])
            vlans.append(v)
        self.dev.vlans = sorted(vlans, key=lambda x: x.id)
        if rows:
            self.dev.sections.append(m.Section(id="vlan-membership", title="VLAN port membership", tables=[m.Table(
                columns=["VLAN", "Name", "Untagged", "Tagged", "Voice"], rows=rows)]))

    def apply_modes(self) -> None:
        for itf in self.ifs.values():
            key = itf.name
            unt, tag = sorted(self.untagged.get(key, set())), sorted(self.tagged.get(key, set()))
            if itf.lag and itf.kind == "physical":
                itf.mode = m.PortMode.lag_member
                continue
            if tag and set(tag) <= self.voice_vlans and unt:
                itf.mode, itf.access_vlan, itf.voice_vlan = m.PortMode.access, unt[0], tag[0]
            elif tag:
                itf.mode, itf.trunk_vlans = m.PortMode.trunk, compress_vlans(tag)
                itf.native_vlan = unt[0] if unt else None
                if not unt:
                    itf.extra["native vlan"] = "none (all tagged)"
            elif unt:
                itf.mode, itf.access_vlan = m.PortMode.access, unt[0]

    def parse_status(self) -> None:
        for ln in output(self.raw, "show interfaces brief").splitlines():
            mt = re.match(r"^\s*(\S+?)(?:-(Trk\d+))?\s+(\S*)\s*\|\s+(\S+)\s+(Yes|No)\s+(Up|Down)\s+(\S+)", ln)
            if not mt:
                continue
            itf = self.iface(mt.group(1))
            itf.enabled = mt.group(5) == "Yes"
            itf.oper_up = mt.group(6) == "Up"
            if mt.group(3) not in ("", "|"):
                itf.extra.setdefault("media", mt.group(3))
            if itf.oper_up:
                itf.speed, itf.duplex = _speed(mt.group(7))
            if mt.group(2) and not itf.lag:
                itf.lag = mt.group(2)
        for lag in [i for i in self.ifs.values() if i.kind == "lag" and i.oper_up is None]:
            states = [self.ifs[x.lower()].oper_up for x in lag.lag_members if x.lower() in self.ifs]
            if any(st is not None for st in states):
                lag.oper_up = any(states)

    # ------------------------------------------------------------------ L3 / neighbors / stp
    def parse_routes(self) -> None:
        d = self.dev
        gw = first(r"^ip default-gateway (\S+)", self.cfg)
        if gw:
            d.routes.append(m.Route(prefix="0.0.0.0/0", next_hop=gw, protocol="static", distance=1,
                                    description="ip default-gateway"))
        for net, mask, nh, rest in re.findall(rf"^ip route ({IPV4}) ({IPV4}) (\S+)(.*)$", self.cfg, re.M):
            d.routes.append(m.Route(prefix=network_cidr(net, mask), next_hop=nh if is_ip(nh) else None,
                                    interface=None if is_ip(nh) else nh, protocol="static",
                                    distance=int(first(r"distance (\d+)", rest) or 1), description=first(r'name "?([^"]+)"?', rest)))

    def parse_neighbors(self) -> None:
        text = output(self.raw, "show lldp info remote-device")
        for r in fixed_columns(text, r"LocalPort\s+\|\s+ChassisId", multiword=False):
            local = r.get("LocalPort", "")
            if not local or local == "|":
                continue
            self.dev.neighbors.append(m.Neighbor(local_port=port_name(local),
                                                 remote_device=r.get("SysName") or r.get("ChassisId") or "?",
                                                 remote_port=r.get("PortId") or None, protocol="lldp"))

    def parse_stp(self) -> None:
        cfg = self.cfg
        if not cfg:
            return
        on = re.search(r"^spanning-tree\s*$", cfg, re.M)
        ver = first(r"^spanning-tree force-version (\S+)", cfg)
        mode = {"rstp-operation": "rstp", "stp-compatible": "stp", "mstp-operation": "mstp"}.get(ver or "", "mstp")
        st = m.SpanningTree(mode=mode if on else "disabled")
        prio = first(r"^spanning-tree priority (\d+)", cfg)
        if prio:
            st.priority = f"{int(prio) * 4096} (multiplier {prio})"
        for ports in re.findall(r"^spanning-tree (\S+) admin-edge-port", cfg, re.M):
            for p in expand_ports(ports):
                self.iface(p).stp_edge = True
        for ports in re.findall(r"^spanning-tree (\S+) bpdu-protection", cfg, re.M):
            for p in expand_ports(ports):
                self.iface(p).extra["bpduguard"] = "enabled"
        edges = [i for i in self.ifs.values() if i.stp_edge]
        st.bpdu_guard_default = bool(edges) and all(i.extra.get("bpduguard") for i in edges)
        st.details["admin-edge ports"] = str(len(edges))
        loop = first(r"^loop-protect (\S+)", cfg)
        if loop:
            st.details["loop-protect ports"] = loop
        self.dev.spanning_tree = st

    # ------------------------------------------------------------------ management
    def parse_management(self) -> None:  # noqa: C901
        cfg, mg = self.cfg, self.dev.management
        if not cfg:
            return
        mg.telnet = not re.search(r"^no telnet-server", cfg, re.M)  # enabled by default on AOS-S
        mg.ssh = not re.search(r"^no ip ssh\s*$", cfg, re.M)
        mg.ssh_version = "2" if mg.ssh else None
        no_web = re.search(r"^no web-management\s*$", cfg, re.M)
        mg.http = not no_web and not re.search(r"^no web-management plaintext", cfg, re.M)
        mg.https = not no_web and bool(re.search(r"^web-management ssl", cfg, re.M))
        mt = re.search(r'^banner (?:motd|exec) "(.*?)"\s*$', cfg, re.M | re.S)
        mg.banner = mt.group(1).replace("\\n", "\n").strip() if mt else None
        mg.ntp_servers = re.findall(r"^(?:sntp|ntp) server (?:priority \d+ )?(\S+)", cfg, re.M)
        mg.dns_servers = re.findall(r"^ip dns server-address (?:priority \d+ )?(\S+)", cfg, re.M)
        mg.domain = first(r'^ip dns domain-name "?([^"\s]+)', cfg)
        tz = first(r"^time timezone (-?\d+)", cfg)
        if tz:
            mins = int(tz)
            mg.timezone = f"UTC{'+' if mins >= 0 else '-'}{abs(mins) // 60:02d}:{abs(mins) % 60:02d}"
            dst = first(r"^time daylight-time-rule (\S+)", cfg)
            mg.timezone += f" (DST {dst})" if dst else ""
        mg.syslog_servers = re.findall(rf"^logging ({IPV4})", cfg, re.M)
        to = first(r"^console inactivity-timer (\d+)", cfg)
        mg.console_timeout_min = int(to) if to else None
        mgrs = re.findall(rf"^ip authorized-managers ({IPV4})(?: ({IPV4}))?", cfg, re.M)
        if mgrs:
            mg.vty_acl = "ip authorized-managers"
            mg.allowed_mgmt_hosts = [network_cidr(a, mk) if mk else a for a, mk in mgrs]
        sn = mg.snmp
        for name, rest in re.findall(r'^snmp-server community "?([^"\s]+)"?(.*)$', cfg, re.M):
            sn.communities.append(community_label(name, " ".join(rest.split()) or "manager unrestricted"))
        if sn.communities:
            sn.versions.append("v2c")
        if re.search(r"^snmpv3 enable", cfg, re.M):
            sn.versions.append("v3")
            for name, rest in re.findall(r'^snmpv3 user "?([^"\s]+)"?(.*)$', cfg, re.M):
                auth = (first(r"\bauth (md5|sha)", rest) or "-").upper()
                priv = (first(r"\bpriv (des|aes)", rest) or "-").upper()
                sn.v3_users.append(f"{name} ({'authPriv' if priv != '-' else 'authNoPriv'}, {auth}/{priv})")
        if re.search(r"^snmpv3 only", cfg, re.M) and "v2c" in sn.versions:
            sn.versions.remove("v2c")
        sn.trap_hosts = list(dict.fromkeys(re.findall(r"^snmp-server host (\S+)", cfg, re.M)))
        sn.location = first(r'^snmp-server location "([^"]*)"', cfg)
        sn.contact = first(r'^snmp-server contact "([^"]*)"', cfg)
        sn.enabled = bool(sn.communities or sn.v3_users) and not re.search(r"^no snmp-server enable", cfg, re.M)
        aaa = mg.aaa
        aaa.radius_servers = re.findall(r"^radius-server host (\S+)", cfg, re.M)
        aaa.tacacs_servers = re.findall(r"^tacacs-server host (\S+)", cfg, re.M)
        aaa.login_methods = [f"{svc} {kind}: {meth.strip()}" for svc, kind, meth in
                             re.findall(r"^aaa authentication (\S+) (login|enable) (.+)$", cfg, re.M)]
        aaa.accounting = bool(re.search(r"^aaa accounting ", cfg, re.M))
        for level, user, rest in re.findall(r'^password (manager|operator|<redacted>)(?: user-name "?([^"\s]+)"?)?(.*)$',
                                            cfg, re.M):
            algo = first(r"\b(sha1|sha256|plaintext)\b", rest)
            priv = None if level == "<redacted>" else level
            mg.users.append(m.LocalUser(name=user or level, privilege=priv,
                                        auth=f"password {algo}" if algo else "password (hash not shown)"))
        for user, grp, rest in re.findall(r'^aaa authentication local-user "?([^"\s]+)"? group "?([^"\s]+)"?(.*)$', cfg, re.M):
            algo = first(r"password (sha1|sha256|plaintext)", rest)
            mg.users.append(m.LocalUser(name=user, privilege=grp, auth=f"password {algo}" if algo else None))
        if re.search(r"^encrypt-credentials", cfg, re.M):
            mg.password_encryption = True
        elif any(u.auth == "password plaintext" for u in mg.users):
            mg.password_encryption = False

    def parse_ha(self) -> None:
        members = re.findall(r'^\s+member (\d+)(?: type "?(\S+?)"?)?(?: mac-address \S+)?\s*$', self.cfg, re.M)
        mode = "stack" if re.search(r"^(?:vsf|stacking)\s*$", self.cfg, re.M) else None
        if mode and len(members) > 1:
            self.dev.ha = m.HighAvailability(mode=mode, members=[f"member {n} ({t or '?'})" for n, t in members],
                                             details={"technology": "VSF" if "vsf" in self.cfg else "backplane stacking"})

    def find_mgmt_ip(self) -> str | None:
        mgmt = first(r"^management-vlan (\d+)", self.cfg)
        order = sorted(self.dev.vlans, key=lambda v: (
            str(v.id) != mgmt, not re.search(r"mgmt|manage", v.name or "", re.I), v.id))
        for v in order:
            for ip in v.svi_ipv4:
                if is_ip(ip):
                    return ip.split("/")[0]
        oobm = first(rf"^oobm\s*\n(?:\s+.*\n)*?\s+ip address ({IPV4})", self.cfg)
        return oobm or (self.raw.target if is_ip(self.raw.target) else None)


def _compact(ports: list[str]) -> str:
    nums = [int(p) for p in ports if p.isdigit()]
    rest = [p for p in ports if not p.isdigit()]
    return ",".join(x for x in (compress_vlans(nums) if nums else "", *rest) if x)


def _speed(mode: str) -> tuple[str | None, str | None]:
    """'1000FDx' -> ('1000', 'full'), '10GigFD' -> ('10G', 'full')."""
    mt = re.match(r"^(\d+)(Gig)?(FDx|HDx|FD|HD)", mode)
    if not mt:
        return None, None
    return (mt.group(1) + ("G" if mt.group(2) else "")), ("full" if mt.group(3).startswith("F") else "half")


class HpProcurveDriver(Driver):
    id = "hp_procurve"
    label = "HPE Aruba AOS-S / ProCurve"
    methods = ("ssh", "file")
    netmiko_type = "hp_procurve"

    def collect(self, target: Target, creds: Credentials) -> RawCollection:
        return run_commands(target, creds, self.netmiko_type, list(PROCURVE_COMMANDS), self.id)

    def parse(self, raw: RawCollection) -> m.Device:
        return ProcurveParser(raw, self.id).parse()


register(HpProcurveDriver())
