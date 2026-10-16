"""Cisco IOS / IOS-XE driver (Catalyst switches, ISR/ASR routers).

parse() works from `show running-config` (or an imported config file) and enriches
the result with whatever show commands are present. The Cisco-style parsing lives in
`CiscoParser`; the NX-OS driver subclasses it and only overrides what differs.
"""

from __future__ import annotations

import ipaddress
import re
from collections import defaultdict

from sextant import model as m
from sextant.drivers import register
from sextant.drivers._ssh import run_commands
from sextant.drivers._util import (
    all_matches,
    blocks,
    compress_vlans,
    expand_vlans,
    first,
    mask_to_prefix,
    mask_value,
    scrub_after,
    short_ifname,
)
from sextant.drivers.base import Credentials, Driver, RawCollection, Target
from sextant.redact import redact_text

IPV4 = r"\d{1,3}(?:\.\d{1,3}){3}"

IOS_COMMANDS = [
    "show running-config",
    "show version",
    "show inventory",
    "show interfaces status",
    "show ip interface brief",
    "show vlan brief",
    "show cdp neighbors detail",
    "show lldp neighbors detail",
    "show ip route",
    "show ip ospf neighbor",
    "show spanning-tree summary",
    "show etherchannel summary",
    "show switch detail",
]

_LONG = {
    "gi": "GigabitEthernet", "te": "TenGigabitEthernet", "tw": "TwoGigabitEthernet",
    "twe": "TwentyFiveGigE", "fi": "FiveGigabitEthernet", "fo": "FortyGigabitEthernet",
    "hu": "HundredGigE", "fa": "FastEthernet", "po": "Port-channel", "eth": "Ethernet",
    "vl": "Vlan", "lo": "Loopback", "tu": "Tunnel", "ap": "AppGigabitEthernet",
}

_SNMP_USER_KEYS = [r"\bauth\s+(?:md5|sha\S*)", r"\bpriv(?:\s+(?:aes[\s-]?\d+|aes|3des|des))?"]

_CISCO_HASH_TYPES = {"0": "plain text", "4": "SHA-256 (weak)", "5": "MD5", "7": "reversible",
                     "8": "PBKDF2-SHA256", "9": "scrypt"}


# --------------------------------------------------------------------------- small helpers


def output(raw: RawCollection, *names: str) -> str:
    """First non-empty string output among `names`, else ''."""
    for n in names:
        v = raw.outputs.get(n)
        if isinstance(v, str) and v.strip():
            return v
    return ""


def is_ip(s: str | None) -> bool:
    try:
        ipaddress.IPv4Address((s or "").split("/")[0])
        return True
    except ValueError:
        return False


def long_ifname(name: str) -> str:
    """'Gi1/0/1' -> 'GigabitEthernet1/0/1'; already-long or unknown names are returned unchanged."""
    mt = re.match(r"^([A-Za-z][A-Za-z-]*?)(\d.*)$", name.strip())
    if not mt:
        return name.strip()
    return _LONG.get(mt.group(1).lower(), mt.group(1)) + mt.group(2)


def wildcard_to_cidr(addr: str, wildcard: str) -> str:
    try:
        mask = str(ipaddress.IPv4Address(int(ipaddress.IPv4Address(wildcard)) ^ 0xFFFFFFFF))
    except ValueError:
        return f"{addr} {wildcard}"
    return network_cidr(addr, mask)


def network_cidr(addr: str, mask: str) -> str:
    """'10.1.0.0', '255.255.0.0' -> '10.1.0.0/16' (network form)."""
    try:
        return str(ipaddress.IPv4Network(mask_to_prefix(addr, mask), strict=False))
    except ValueError:
        return f"{addr} {mask}"


def community_label(value: str, *attrs: str | None) -> str:
    extra = ", ".join(a for a in attrs if a)
    masked = mask_value(value) or ""
    return f"{masked} ({extra})" if extra else masked


def cisco_auth(text: str, types: dict[str, str] = _CISCO_HASH_TYPES) -> str | None:
    """Auth *type* from a username/enable line, never the value: 'secret type 9 (scrypt)'."""
    if re.search(r"\bnopassword\b", text):
        return "none (nopassword)"
    algo = first(r"algorithm-type\s+(\w+)", text)
    if algo:
        return {"scrypt": "secret type 9 (scrypt)", "sha256": "secret type 8 (PBKDF2-SHA256)",
                "md5": "secret type 5 (MD5)"}.get(algo.lower(), f"secret ({algo})")
    mt = re.search(r"\b(secret|password)\s+(?:(\d)\s+)?\S+", text)
    if mt:
        kind, typ = mt.group(1), mt.group(2) or "0"
        return f"{kind} type {typ} ({types.get(typ, 'unknown')})"
    if re.search(r"\bsshkey\b", text):
        return "ssh-key"
    return None


def first_ipv4(itf: m.Interface) -> str | None:
    for ip in itf.ipv4:
        if not ip.secondary and is_ip(ip.address):
            return ip.address.split("/")[0]
    return None


def split_records(text: str, start_regex: str | None = None) -> list[str]:
    """Split CDP/LLDP 'detail' output into one chunk per neighbor."""
    if re.search(r"^-{10,}\s*$", text, re.M):
        parts = re.split(r"^-{10,}\s*$", text, flags=re.M)
    elif start_regex:
        parts = re.split(f"(?m)^(?={start_regex})", text)
    else:
        parts = [text]
    return [p for p in parts if p.strip()]


def kv_lines(text: str) -> dict[str, str]:
    """'Key   : value' lines -> dict (first occurrence wins)."""
    out: dict[str, str] = {}
    for mt in re.finditer(r"^\s*([A-Za-z][^:\n]{1,60}?)\s*:\s*(\S[^\n]*?)\s*$", text or "", re.M):
        out.setdefault(mt.group(1).strip(), mt.group(2).strip())
    return out


def parse_cdp(text: str) -> list[m.Neighbor]:
    out = []
    for rec in split_records(text, r"Device ID"):
        dev_id = first(r"Device ID:\s*(\S+)", rec)
        local = first(r"^Interface:\s*([^,\n]+)", rec)
        if not dev_id or not local:
            continue
        platform = first(r"Platform:\s*([^,\n]+)", rec)
        if platform:
            platform = re.sub(r"^cisco\s+", "", platform.strip(), flags=re.I)
        out.append(m.Neighbor(
            local_port=long_ifname(local), remote_device=re.sub(r"\(.*\)$", "", dev_id),
            remote_port=first(r"Port ID \(outgoing port\):\s*(.+)$", rec), remote_platform=platform,
            remote_ip=first(rf"(?:IP address|IPv4 Address):\s*({IPV4})", rec), protocol="cdp"))
    return out


def parse_lldp_detail(text: str) -> list[m.Neighbor]:
    out = []
    for rec in split_records(text, r"Chassis id:"):
        local = first(r"^Local (?:Intf|Port id|Interface):\s*(\S+)", rec)
        name = first(r"^System Name:\s*(.+)$", rec)
        chassis = first(r"^Chassis id:\s*(\S+)", rec)
        if not local or not (name or chassis):
            continue
        descr = first(r"System Description:\s*(\S[^\n]*)", rec)
        if descr and descr.lower().startswith(("not advertised", "time remaining")):
            descr = None
        out.append(m.Neighbor(
            local_port=long_ifname(local), remote_device=(name or chassis or "").strip(),
            remote_port=first(r"^Port id:\s*(.+)$", rec), remote_platform=descr[:80] if descr else None,
            remote_ip=first(rf"Management Address[^\n:]*:\s*(?:IP:\s*)?({IPV4})", rec), protocol="lldp"))
    return out


def merge_neighbors(primary: list[m.Neighbor], extra: list[m.Neighbor]) -> list[m.Neighbor]:
    """Add LLDP entries unless CDP already reported the same peer on the same port."""
    def key(n: m.Neighbor) -> tuple[str, str]:
        return n.local_port.lower(), n.remote_device.lower().split(".")[0]

    seen = {key(n) for n in primary}
    return primary + [n for n in extra if key(n) not in seen]


_ROUTE_PROTO = {"C": "connected", "S": "static", "O": "ospf", "B": "bgp", "D": "eigrp", "R": "rip",
                "i": "isis", "E": "egp", "M": "mobile", "U": "static", "o": "odr", "l": "lisp", "H": "nhrp"}


def parse_ip_route(text: str) -> list[m.Route]:
    """`show ip route` for IOS (classic layout) and NX-OS (', ubest/mbest' layout)."""
    routes: list[m.Route] = []
    if "ubest/mbest" in text:  # NX-OS
        vrf, prefix = None, None
        for ln in text.splitlines():
            mt = re.match(r'^IP Route Table for VRF "(\S+)"', ln)
            if mt:
                vrf = None if mt.group(1) == "default" else mt.group(1)
                continue
            mt = re.match(rf"^({IPV4}/\d+), ubest", ln)
            if mt:
                prefix = mt.group(1)
                continue
            mt = re.match(rf"^\s+\*?via ({IPV4})?,?\s*(?:([A-Za-z][\w/.-]*\d),\s*)?\[(\d+)/(\d+)\],\s*[^,]+,\s*([\w-]+)", ln)
            if mt and prefix:
                proto = mt.group(5).split("-")[0]
                if proto in ("local", "hsrp", "vrrp"):
                    continue
                proto = {"direct": "connected", "am": "connected"}.get(proto, proto)
                routes.append(m.Route(prefix=prefix, next_hop=None if proto == "connected" else mt.group(1),
                                      interface=long_ifname(mt.group(2)) if mt.group(2) else None,
                                      protocol=proto, distance=int(mt.group(3)), vrf=vrf))
        return routes
    default_len: dict[str, str] = {}
    last: m.Route | None = None
    for ln in text.splitlines():
        mt = re.match(rf"^\s+({IPV4})/(\d+) is subnetted", ln)
        if mt:
            default_len[".".join(mt.group(1).split(".")[:1])] = mt.group(2)
            continue
        mt = re.match(rf"^([A-Za-z][a-z]?\*?(?:\s?(?:IA|E1|E2|N1|N2|EX|L1|L2|ia|su))?)\s+({IPV4})(/\d+)?\s*(.*)$", ln)
        if mt:
            code = mt.group(1).replace("*", "").split()[0][0]
            if code == "L":
                last = None
                continue
            plen = mt.group(3) or "/" + default_len.get(mt.group(2).split(".")[0], "32")
            rest = mt.group(4)
            r = m.Route(prefix=mt.group(2) + plen, protocol=_ROUTE_PROTO.get(code, code))
            _route_rest(r, rest)
            routes.append(r)
            last = r
            continue
        mt = re.match(rf"^\s+\[(\d+)/\d+\] via ({IPV4})(.*)$", ln)
        if mt and last is not None:
            r = m.Route(prefix=last.prefix, protocol=last.protocol, distance=int(mt.group(1)),
                        next_hop=mt.group(2))
            iface = re.findall(r",\s*([A-Za-z][\w/.-]*\d)\s*$", mt.group(3))
            r.interface = iface[0] if iface else None
            routes.append(r)
    return routes


def _route_rest(r: m.Route, rest: str) -> None:
    mt = re.search(rf"\[(\d+)/\d+\]\s+via\s+({IPV4})", rest)
    if mt:
        r.distance, r.next_hop = int(mt.group(1)), mt.group(2)
    elif "directly connected" in rest:
        r.distance = 0
    iface = re.findall(r",\s*([A-Za-z][\w/.-]*\d)\s*$", rest)
    if iface:
        r.interface = iface[0]
    elif re.search(r"is directly connected,\s*(\S+)", rest):
        r.interface = first(r"is directly connected,\s*(\S+)", rest)


def parse_banner(cfg: str, kinds: tuple[str, ...] = ("login", "motd", "exec")) -> str | None:
    found: dict[str, str] = {}
    lines = cfg.splitlines()
    for i, ln in enumerate(lines):
        mt = re.match(r"^banner (motd|login|exec|incoming) (\^C|\S)(.*)$", ln)
        if not mt:
            continue
        delim, rest, body = mt.group(2), mt.group(3), []
        if delim in rest:
            body.append(rest.split(delim)[0])
        else:
            body.append(rest)
            for nxt in lines[i + 1:]:
                if delim in nxt:
                    body.append(nxt.split(delim)[0])
                    break
                body.append(nxt)
        found.setdefault(mt.group(1), "\n".join(b.rstrip() for b in body).strip())
    for k in kinds:
        if found.get(k):
            return found[k]
    return None


# --------------------------------------------------------------------------- parser


class CiscoParser:
    """Cisco-style CLI config parser. Subclass hooks: class attributes and the `parse_*` methods."""

    vendor = "Cisco"
    os_name_default = "IOS"
    lag_prefix = "Port-channel"
    default_trunk_vlans = "all"
    config_cmds = ("show running-config", "show run", "config")
    version_cmds = ("show version",)
    status_cmds = ("show interfaces status",)
    brief_cmds = ("show ip interface brief",)
    lag_cmds = ("show etherchannel summary",)
    vlan_cmds = ("show vlan brief", "show vlan")
    route_cmds = ("show ip route",)
    stp_cmds = ("show spanning-tree summary",)

    def __init__(self, raw: RawCollection, platform: str):
        self.raw = raw
        self.cfg = output(raw, *self.config_cmds).replace("\r", "")
        self.dev = m.Device(hostname=raw.target or "unknown", vendor=self.vendor, platform=platform,
                            collection_method=raw.method, source=raw.target, os_name=self.os_name_default)
        self.dev.collection_warnings.extend(raw.warnings)
        self.ifs: dict[str, m.Interface] = {}
        self.acl_apply: dict[str, list[str]] = defaultdict(list)
        self.helpers: dict[str, list[str]] = defaultdict(list)
        self.ospf_if: list[tuple[str, str, str]] = []  # (process, interface, area)
        self.fhrp: list[tuple[str, str, str, str]] = []  # (interface, proto, group, vip)
        self.inventory: list[tuple[str, str, str, str]] = []
        self.lag_rows: list[list[str]] = []
        self.is_switch = bool(re.search(r"^\s*switchport\b|^vlan \d|^spanning-tree mode", self.cfg, re.M))
        self.edge_default = bool(re.search(r"^spanning-tree (?:portfast (?:edge )?default|port type edge default)",
                                           self.cfg, re.M))
        self.default_l2 = self.is_switch

    # ----------------------------------------------------------------- driver entry
    def parse(self) -> m.Device:
        d = self.dev
        if not self.cfg:
            d.collection_warnings.append("No running configuration in collection: configuration sections are empty.")
        steps = [self.parse_identity, self.parse_version, self.parse_inventory, self.parse_interfaces,
                 self.parse_status, self.parse_lags, self.parse_vlans, self.parse_vrfs, self.parse_routes,
                 self.parse_routing_protocols, self.parse_neighbors, self.parse_stp, self.parse_acls,
                 self.parse_management, self.parse_ha, self.parse_extras]
        for step in steps:
            try:
                step()
            except Exception as exc:  # noqa: BLE001 - a parser bug must never kill a whole run
                d.collection_warnings.append(f"{step.__name__} failed: {exc.__class__.__name__}: {exc}")
        d.interfaces = list(self.ifs.values())
        d.mgmt_ip = self.find_mgmt_ip()
        d.role = m.DeviceRole.switch if self.is_switch else m.DeviceRole.router
        d.raw_config = self.scrub(self.cfg) if self.cfg else None
        return d

    @staticmethod
    def scrub(text: str) -> str:
        """sextant.redact plus SNMPv3 user keys (`auth sha <key> priv aes-128 <key>`), which it does not cover."""
        lines = (redact_text(text) or "").splitlines()
        return "\n".join(scrub_after(ln, _SNMP_USER_KEYS) or "" if re.match(r"\s*snmp-server user ", ln) else ln
                         for ln in lines)

    # ----------------------------------------------------------------- helpers
    def iface(self, name: str, create: bool = True) -> m.Interface | None:
        key = long_ifname(name).lower()
        itf = self.ifs.get(key)
        if itf is None and create:
            itf = m.Interface(name=name if not re.match(r"^[A-Za-z]{2,3}\d", name) else long_ifname(name))
            itf.kind = self.if_kind(itf.name)
            self.ifs[key] = itf
        return itf

    def if_kind(self, name: str) -> str:
        n = name.lower()
        for prefix, kind in (("port-channel", "lag"), ("vlan", "vlan"), ("loopback", "loopback"),
                             ("tunnel", "tunnel"), ("mgmt", "mgmt"), ("nve", "virtual"), ("bdi", "virtual"),
                             ("appgigabitethernet", "virtual"), ("null", "virtual")):
            if n.startswith(prefix):
                return kind
        return "physical"

    # ----------------------------------------------------------------- identity / hardware
    def parse_identity(self) -> None:
        name = first(r"^(?:hostname|switchname)\s+(\S+)", self.cfg)
        if name:
            self.dev.hostname = name.strip('"')

    def parse_version(self) -> None:
        d, ver = self.dev, output(self.raw, *self.version_cmds)
        if not ver:
            d.collection_warnings.append("show version not collected: OS version, model and serial may be missing.")
            d.os_version = first(r"^version\s+(\S+)", self.cfg)
            return
        if re.search(r"IOS[ -]XE", ver):
            d.os_name = "IOS-XE"
        d.os_version = (first(r"Cisco IOS XE Software, Version\s+(\S+)", ver)
                        or first(r"Cisco IOS Software.*?Version\s+([^,\s]+)", ver))
        mt = re.search(r"^(\S+) uptime is (.+)$", ver, re.M)
        if mt:
            d.uptime = mt.group(2).strip()
            if d.hostname == self.raw.target and not first(r"^hostname\s+(\S+)", self.cfg):
                d.hostname = mt.group(1)
        d.model = first(r"^Model [Nn]umber\s*:\s*(\S+)", ver) or first(r"^cisco (\S+) \(.*?\) processor", ver)
        d.serial = first(r"^System [Ss]erial [Nn]umber\s*:\s*(\S+)", ver) or first(r"Processor board ID (\S+)", ver)
        for label, pat in (("Memory", r"with (\S+) bytes of memory"), ("Last reload reason", r"Last reload reason:\s*(.+)$"),
                           ("Configuration register", r"Configuration register is (\S+)"),
                           ("System image", r'System image file is "([^"]+)"')):
            val = first(pat, ver)
            if val:
                d.hardware.append(m.Fact(key=label, value=val))
        for mt in re.finditer(r"^\*?\s*(\d+)\s+(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(INSTALL|BUNDLE)\s*$", ver, re.M):
            d.hardware.append(m.Fact(key=f"Switch {mt.group(1)}",
                                     value=f"{mt.group(3)}, {mt.group(2)} ports, {mt.group(4)} ({mt.group(6)} mode)"))
        for mt in re.finditer(r"^((?:network|dna)-\w+)\s+(\S.*?)\s{2,}\S", ver, re.M):
            lic = f"{mt.group(1)} ({mt.group(2)})"
            if lic not in d.licenses:
                d.licenses.append(lic)

    def parse_inventory(self) -> None:
        inv = output(self.raw, "show inventory")
        for mt in re.finditer(r'NAME:\s*"([^"]*)",\s*DESCR:\s*"([^"]*)"\s*\n\s*PID:\s*([^,\s]*)\s*,\s*VID:\s*([^,]*?)\s*,'
                              r"\s*SN:\s*(\S*)", inv):
            name, descr, pid, _vid, sn = (g.strip() for g in mt.groups())
            self.inventory.append((name, descr, pid, sn))
            if re.match(r"^(Switch \d+|Chassis|Stack|\d+)$|Power Supply|Fan Tray|PSU", name, re.I) or \
                    name.lower() == descr.lower():
                value = " ".join(x for x in (pid, f"SN {sn}" if sn else "") if x)
                fact = next((f for f in self.dev.hardware if f.key == name), None)
                if fact is None:
                    self.dev.hardware.append(m.Fact(key=name, value=value))
                elif sn and sn not in fact.value:
                    fact.value += f", SN {sn}"
        if not self.dev.os_version:  # config-only import: "version 17.9" (major.minor only)
            ver = first(r"^version (\S+)", self.cfg)
            if ver:
                self.dev.os_version = ver
                self.dev.os_name = "IOS-XE" if re.search(r"^1[6-9]\.", ver) else (self.dev.os_name or "IOS")
        if self.dev.os_name == "IOS" and re.match(r"^1[6-9]\.", self.dev.os_version or ""):
            self.dev.os_name = "IOS-XE"  # 16.x and later are IOS-XE
        if not self.dev.model:  # config-only import: IOS-XE stacks keep "switch 1 provision c9300-48p"
            prov = all_matches(r"^switch (\d+) provision (\S+)", self.cfg, 2)
            if prov:
                self.dev.model = prov[0].upper() + (f" (stack of {len(prov)})" if len(prov) > 1 else "")
        if self.inventory:
            if not self.dev.model:
                self.dev.model = self.inventory[0][2] or None
            if not self.dev.serial:
                self.dev.serial = self.inventory[0][3] or None
            self.dev.sections.append(m.Section(id="inventory", title="Hardware inventory", tables=[m.Table(
                columns=["Name", "Description", "PID", "Serial"], rows=[list(r) for r in self.inventory])]))

    # ----------------------------------------------------------------- interfaces
    def parse_interfaces(self) -> None:
        for header, lines in blocks(self.cfg, r"^interface\s+\S+"):
            itf = self.iface(header.split(None, 1)[1].strip())
            st: dict = {"l2": None, "smode": None, "edge": None, "hsrp": None, "vrrp": None}
            for ln in lines:
                try:
                    self._iface_line(itf, ln, st)
                except (ValueError, IndexError):
                    continue
            self._finish_iface(itf, st)

    def _iface_line(self, itf: m.Interface, ln: str, st: dict) -> None:  # noqa: C901 - flat dispatch
        name = itf.name
        if ln.startswith("description "):
            itf.description = ln[12:].strip()
        elif ln == "shutdown":
            itf.enabled, st["admin"] = False, "down"
        elif ln == "no shutdown":
            itf.enabled, st["admin"] = True, "up"
        elif ln == "no switchport":
            st["l2"] = False
        elif ln == "switchport":
            st["l2"] = True
        elif mt := re.match(r"switchport mode (\S+)", ln):
            st["smode"], st["l2"] = mt.group(1), True
        elif mt := re.match(r"switchport access vlan (\d+)", ln):
            itf.access_vlan, st["l2"] = int(mt.group(1)), True
        elif mt := re.match(r"switchport voice vlan (\d+)", ln):
            itf.voice_vlan = int(mt.group(1))
        elif mt := re.match(r"switchport trunk native vlan (\d+)", ln):
            itf.native_vlan = int(mt.group(1))
        elif mt := re.match(r"switchport trunk allowed vlan (add |remove |except )?(\S+)", ln):
            op, val = (mt.group(1) or "").strip(), mt.group(2)
            if op == "add" and itf.trunk_vlans and itf.trunk_vlans not in ("all", "none"):
                itf.trunk_vlans = compress_vlans(expand_vlans(itf.trunk_vlans) + expand_vlans(val))
            elif op == "remove" and itf.trunk_vlans and itf.trunk_vlans not in ("all", "none"):
                rm = set(expand_vlans(val))
                itf.trunk_vlans = compress_vlans([v for v in expand_vlans(itf.trunk_vlans) if v not in rm])
            elif op == "except":
                itf.trunk_vlans = f"all except {val}"
            else:
                itf.trunk_vlans = val
        elif mt := re.match(rf"ip address ({IPV4})(?:\s+({IPV4})|/(\d+))?(\s+secondary)?", ln):
            addr = mask_to_prefix(mt.group(1), mt.group(2)) if mt.group(2) else (
                f"{mt.group(1)}/{mt.group(3)}" if mt.group(3) else mt.group(1))
            itf.ipv4.append(m.IPAddress(address=addr, secondary=bool(mt.group(4))))
        elif ln.startswith("ip address dhcp"):
            itf.ipv4.append(m.IPAddress(address="dhcp"))
        elif mt := re.match(r"ipv6 address (\S+)", ln):
            itf.ipv6.append(mt.group(1))
        elif mt := re.match(r"(?:ip )?vrf (?:forwarding|member) (\S+)", ln):
            itf.vrf = mt.group(1)
        elif mt := re.match(r"channel-group (\d+)(?: mode (\S+))?", ln):
            itf.lag = f"{self.lag_prefix}{mt.group(1)}"
            md = (mt.group(2) or "on").lower()
            itf.lag_protocol = "lacp" if md in ("active", "passive") else "pagp" if md in ("auto", "desirable") else "static"
            itf.extra["channel-group mode"] = md
        elif re.match(r"spanning-tree portfast disable|spanning-tree port type network", ln):
            st["edge"] = False
        elif re.match(r"spanning-tree portfast(?: edge)?(?: trunk)?$|spanning-tree port type edge", ln):
            st["edge"] = True
        elif mt := re.match(r"spanning-tree (bpduguard|bpdufilter) (enable|disable)", ln):
            itf.extra[mt.group(1)] = mt.group(2) + "d"
        elif mt := re.match(r"spanning-tree guard (\S+)", ln):
            itf.extra["stp guard"] = mt.group(1)
        elif mt := re.match(r"speed (\S+)", ln):
            itf.speed = mt.group(1)
        elif mt := re.match(r"duplex (\S+)", ln):
            itf.duplex = mt.group(1)
        elif mt := re.match(r"mtu (\d+)", ln):
            itf.mtu = int(mt.group(1))
        elif ln == "switchport port-security":
            itf.port_security = True
        elif mt := re.match(r"switchport port-security (maximum \d+|violation \S+|mac-address sticky$)", ln):
            itf.extra["port-security " + mt.group(1).split()[0]] = mt.group(1).split(None, 1)[-1]
        elif mt := re.match(rf"ip (?:helper-address|dhcp relay address)(?: global)? ({IPV4})", ln):
            self.helpers[name].append(mt.group(1))
        elif mt := re.match(r"ip(?:v6)? (?:port )?(?:access-group|traffic-filter) (\S+) (in|out)", ln):
            self.acl_apply[mt.group(1)].append(f"{short_ifname(name)} {mt.group(2)}")
        elif mt := re.match(rf"standby (?:(\d+) )?ip ({IPV4})", ln):
            self._fhrp(itf, "hsrp", mt.group(1) or "0", mt.group(2))
        elif mt := re.match(r"(hsrp|vrrp) (\d+)$", ln):  # NX-OS sub-mode
            st["fhrp"] = (mt.group(1), mt.group(2))
        elif (mt := re.match(rf"(?:ip|address) ({IPV4})", ln)) and st.get("fhrp"):
            self._fhrp(itf, st["fhrp"][0], st["fhrp"][1], mt.group(1))
        elif mt := re.match(rf"vrrp (\d+) (?:ip|address) ({IPV4})", ln):
            self._fhrp(itf, "vrrp", mt.group(1), mt.group(2))
        elif ln == "power inline never":
            itf.poe = False
        elif ln == "ip dhcp snooping trust":
            itf.extra["dhcp snooping"] = "trusted"
        elif mt := re.match(r"ip (?:router )?ospf (\S+) area (\S+)", ln):
            self.ospf_if.append((mt.group(1), name, mt.group(2)))
        elif ln == "vpc peer-link":
            itf.extra["vpc"] = "peer-link"
        elif mt := re.match(r"vpc (\d+)$", ln):
            itf.extra["vpc"] = mt.group(1)
        elif mt := re.match(r"authentication port-control (\S+)|dot1x pae (\S+)", ln):
            itf.extra["802.1X"] = mt.group(1) or mt.group(2)
        elif mt := re.match(r"storm-control (\S+) level (\S+)", ln):
            itf.extra[f"storm-control {mt.group(1)}"] = mt.group(2)

    def _fhrp(self, itf: m.Interface, proto: str, group: str, vip: str) -> None:
        self.fhrp.append((itf.name, proto, group, vip))
        for ip in itf.ipv4:
            if not ip.secondary:
                ip.vrrp_vip = vip
                break

    def _finish_iface(self, itf: m.Interface, st: dict) -> None:
        if itf.kind == "physical" and itf.vrf and itf.vrf.lower() in ("mgmt-vrf", "management"):
            itf.kind = "mgmt"
        l2, smode = st["l2"], st["smode"]
        if itf.kind in ("vlan", "loopback", "tunnel", "mgmt", "virtual"):
            itf.mode = m.PortMode.routed if itf.ipv4 or itf.kind == "vlan" else m.PortMode.unknown
        elif l2 is False or (itf.ipv4 and not l2):
            itf.mode = m.PortMode.routed
        elif smode == "trunk":
            itf.mode = m.PortMode.trunk
        elif smode in ("access", "private-vlan") or itf.access_vlan or l2 or self.default_l2:
            itf.mode = m.PortMode.access
        if itf.mode == m.PortMode.access and itf.access_vlan is None:
            itf.access_vlan = 1
        if itf.mode == m.PortMode.trunk:
            itf.native_vlan = itf.native_vlan or 1
            itf.trunk_vlans = itf.trunk_vlans or self.default_trunk_vlans
        if itf.lag and itf.kind == "physical":
            if itf.mode == m.PortMode.trunk:
                itf.extra["member mode"] = "trunk"
            itf.mode = m.PortMode.lag_member
        edge = st["edge"]
        if edge is None and self.edge_default and itf.mode == m.PortMode.access and itf.kind == "physical":
            edge = True
        itf.stp_edge = edge

    def parse_status(self) -> None:
        text = output(self.raw, *self.status_cmds)
        lines = text.splitlines()
        hdr = next((i for i, ln in enumerate(lines) if re.match(r"^\s*Port\s+Name\s+Status\s+Vlan", ln)), None)
        if hdr is not None:
            name_col, status_col = lines[hdr].index("Name"), lines[hdr].index("Status")
            for ln in lines[hdr + 1:]:
                if not ln.strip() or ln.startswith("-") or ln[:1] == " ":
                    continue
                rest = ln[status_col:].split()
                if len(rest) < 4:
                    continue
                itf = self.iface(ln.split()[0])
                status, vlan, duplex, speed = rest[:4]
                desc = ln[name_col:status_col].strip()
                if desc and desc != "--" and not itf.description:
                    itf.description = desc
                itf.oper_up = status == "connected"
                if itf.oper_up:
                    itf.enabled = True
                elif status == "disabled":
                    itf.enabled = False
                elif status.startswith("err-dis"):
                    itf.extra["status"] = "err-disabled"
                if itf.oper_up and itf.kind in ("physical", "lag", "mgmt"):
                    itf.speed = itf.speed if itf.speed and itf.speed != "auto" else speed.removeprefix("a-")
                    itf.duplex = itf.duplex if itf.duplex and itf.duplex != "auto" else duplex.removeprefix("a-")
                if len(rest) > 4 and rest[4] not in ("--", "N/A") and itf.kind == "physical":
                    itf.extra.setdefault("media", " ".join(rest[4:]))
                if itf.mode == m.PortMode.unknown and itf.kind in ("physical", "lag"):
                    if vlan.isdigit():
                        itf.mode, itf.access_vlan = m.PortMode.access, int(vlan)
                    elif vlan in ("trunk", "routed"):
                        itf.mode = m.PortMode(vlan)
        brief = output(self.raw, *self.brief_cmds)
        for mt in re.finditer(rf"^(\S+)\s+({IPV4}|unassigned)\s+(?:YES|NO)\s+\S+\s+(administratively down|up|down|deleted)"
                              r"\s+(up|down)", brief, re.M):
            self._brief(mt.group(1), mt.group(2), mt.group(3) != "administratively down", mt.group(4) == "up")
        for mt in re.finditer(rf"^(\S+)\s+({IPV4})\s+protocol-(up|down)/link-(up|down)/admin-(up|down)", brief, re.M):
            self._brief(mt.group(1), mt.group(2), mt.group(5) == "up", mt.group(3) == "up")

    def _brief(self, name: str, ip: str, admin_up: bool, oper_up: bool) -> None:
        itf = self.iface(name, create=bool(self.cfg) is False or is_ip(ip))
        if itf is None:
            return
        if itf.oper_up is None:
            itf.oper_up = oper_up
        if not self.cfg:
            itf.enabled = admin_up
        if is_ip(ip) and not itf.ipv4:
            itf.ipv4.append(m.IPAddress(address=ip))

    def parse_lags(self) -> None:
        for itf in list(self.ifs.values()):
            if itf.lag:
                parent = self.iface(itf.lag)
                parent.kind = "lag"
                if itf.name not in parent.lag_members:
                    parent.lag_members.append(itf.name)
                parent.lag_protocol = parent.lag_protocol or itf.lag_protocol
        text = output(self.raw, *self.lag_cmds)
        cur: list[str] | None = None
        for ln in text.splitlines():
            mt = re.match(r"^\s*(\d+)\s+(Po\d+)\((\w+)\)\s+(.*)$", ln)
            members_re = r"(\S+?)\((\w+)\)"
            if mt:
                toks = mt.group(4).split()
                proto = next((t for t in reversed(toks) if "(" not in t), "-")
                members = re.findall(members_re, mt.group(4))
                cur = [mt.group(2), mt.group(3), proto, " ".join(f"{a}({b})" for a, b in members)]
                self.lag_rows.append(cur)
                po = self.iface(mt.group(2))
                po.kind = "lag"
                po.oper_up = "U" in mt.group(3)
                po.lag_protocol = po.lag_protocol or {"lacp": "lacp", "pagp": "pagp"}.get(proto.lower(), "static")
                for a, _flag in members:
                    self._lag_member(po, a)
            elif cur is not None and re.match(rf"^\s+{members_re}", ln):
                members = re.findall(members_re, ln)
                cur[3] = (cur[3] + " " + " ".join(f"{a}({b})" for a, b in members)).strip()
                for a, _flag in members:
                    self._lag_member(self.iface(cur[0]), a)
        if self.lag_rows:
            self.dev.sections.append(m.Section(id="port-channels", title="Port-channel status", tables=[m.Table(
                columns=["Port-channel", "Flags", "Protocol", "Members (flags)"], rows=self.lag_rows,
                note="Flags: U in use, S layer 2, R layer 3, D down; member P bundled, s/I suspended/individual.")]))

    def _lag_member(self, po: m.Interface, member: str) -> None:
        mem = self.iface(member)
        if mem.name not in po.lag_members:
            po.lag_members.append(mem.name)
        if not mem.lag:
            mem.lag, mem.mode = po.name, m.PortMode.lag_member

    # ----------------------------------------------------------------- vlans / vrfs / routing
    def parse_vlans(self) -> None:
        vlans: dict[int, m.Vlan] = {}
        for header, lines in blocks(self.cfg, r"^vlan\s+[\d,\-]+\s*$"):
            ids = expand_vlans(header.split(None, 1)[1])
            name = next((ln.split(None, 1)[1].strip('"') for ln in lines if ln.startswith("name ")), None)
            for vid in ids:
                vlans.setdefault(vid, m.Vlan(id=vid))
                if name and len(ids) == 1:
                    vlans[vid].name = name
        brief = output(self.raw, *self.vlan_cmds)
        have_brief, cur = False, None
        for ln in brief.splitlines():
            mt = re.match(r"^(\d+)\s+(\S+)\s+(active|act/\w+|suspended|sus/\w+)\s*(.*)$", ln)
            if mt:
                vid, have_brief = int(mt.group(1)), True
                if 1002 <= vid <= 1005 and "unsup" in mt.group(3):
                    cur = None
                    continue
                cur = vlans.setdefault(vid, m.Vlan(id=vid))
                cur.name = cur.name or mt.group(2)
                cur.ports = [p.strip() for p in mt.group(4).split(",") if p.strip()]
            elif cur is not None and re.match(r"^\s{20,}\S", ln):
                cur.ports.extend(p.strip() for p in ln.split(",") if p.strip())
            elif ln.strip() and not ln.startswith(("-", " ", "VLAN")):
                cur = None
        for itf in self.ifs.values():
            if itf.kind == "vlan" and (vid := first(r"(\d+)$", itf.name)):
                v = vlans.setdefault(int(vid), m.Vlan(id=int(vid)))
                v.svi_ipv4 = [ip.address for ip in itf.ipv4]
                v.dhcp_helpers = list(dict.fromkeys(self.helpers.get(itf.name, [])))
            elif itf.mode in (m.PortMode.access,) and itf.access_vlan is not None:
                v = vlans.setdefault(itf.access_vlan, m.Vlan(id=itf.access_vlan, name="default" if itf.access_vlan == 1 else None))
                if not have_brief and itf.kind == "physical":
                    v.ports.append(short_ifname(itf.name))
        self.dev.vlans = [vlans[k] for k in sorted(vlans)]

    def parse_vrfs(self) -> None:
        for name in re.findall(r"^(?:vrf definition|ip vrf|vrf context)\s+(\S+)", self.cfg, re.M):
            if name not in self.dev.vrfs:
                self.dev.vrfs.append(name)

    def parse_routes(self) -> None:
        routes: list[m.Route] = []
        gw = first(r"^ip default-gateway (\S+)", self.cfg)  # L2 switches: management default gateway
        if gw:
            routes.append(m.Route(prefix="0.0.0.0/0", next_hop=gw, protocol="default-gateway",
                                  description="ip default-gateway (management)"))
        for vrf, rest in re.findall(r"^ip route (?:vrf (\S+) )?(.+)$", self.cfg, re.M):
            r = self._static(rest, vrf or None)
            if r:
                routes.append(r)
        for header, lines in blocks(self.cfg, r"^vrf context \S+"):
            vrf = header.split()[-1]
            for ln in lines:
                if ln.startswith("ip route "):
                    r = self._static(ln[9:], vrf)
                    if r:
                        routes.append(r)
        table = output(self.raw, *self.route_cmds)
        if table:
            keys = {(r.prefix, r.next_hop, r.vrf) for r in routes}
            for r in parse_ip_route(table):
                if r.protocol == "static" and (r.prefix, r.next_hop, r.vrf) in keys:
                    continue
                routes.append(r)
        self.dev.routes = routes

    def _static(self, rest: str, vrf: str | None) -> m.Route | None:
        toks = rest.split()
        if not toks:
            return None
        if "/" in toks[0]:
            prefix, toks = toks[0], toks[1:]
        elif len(toks) >= 2 and is_ip(toks[1]):
            prefix, toks = network_cidr(toks[0], toks[1]), toks[2:]
        else:
            return None
        r = m.Route(prefix=prefix, protocol="static", vrf=vrf, distance=1)
        it = iter(toks)
        for t in it:
            if t in ("name", "tag", "track", "description"):
                val = next(it, "")
                if t in ("name", "description"):
                    r.description = val
            elif t == "vrf":
                next(it, None)
            elif is_ip(t) and r.next_hop is None:
                r.next_hop = t.split("/")[0]
            elif t.isdigit():
                r.distance = int(t)
            elif re.match(r"^[A-Za-z][\w-]*\d[\d/.:]*$", t) and r.interface is None:
                r.interface = t
        return r

    def parse_routing_protocols(self) -> None:
        for header, lines in blocks(self.cfg, r"^router (ospf|ospfv3|bgp|eigrp|rip|isis)\b"):
            parts = header.split()
            proto, pid = parts[1], (parts[2] if len(parts) > 2 else None)
            rp = m.RoutingProtocol(protocol=proto, process_id=pid)
            if proto == "bgp":
                rp.asn, rp.process_id = pid, None
            nbr = None
            for ln in lines:
                if mt := re.match(rf"(?:bgp |eigrp )?router-id ({IPV4})", ln):
                    rp.router_id = mt.group(1)
                elif mt := re.match(rf"network ({IPV4}) ({IPV4}) area (\S+)", ln):
                    rp.networks.append(f"{wildcard_to_cidr(mt.group(1), mt.group(2))} area {mt.group(3)}")
                elif mt := re.match(rf"network ({IPV4}) mask ({IPV4})", ln):
                    rp.networks.append(network_cidr(mt.group(1), mt.group(2)))
                elif mt := re.match(rf"network ({IPV4})(?: ({IPV4}))?$", ln):
                    rp.networks.append(wildcard_to_cidr(mt.group(1), mt.group(2)) if mt.group(2) else mt.group(1))
                elif mt := re.match(rf"network ({IPV4}/\d+)", ln):
                    rp.networks.append(mt.group(1))
                elif mt := re.match(rf"neighbor ({IPV4}) remote-as (\S+)", ln):
                    rp.neighbors.append(f"{mt.group(1)} (AS {mt.group(2)})")
                elif mt := re.match(rf"neighbor ({IPV4})$", ln):
                    nbr = mt.group(1)
                elif (mt := re.match(r"remote-as (\S+)", ln)) and nbr:
                    rp.neighbors.append(f"{nbr} (AS {mt.group(1)})")
                    nbr = None
                elif ln == "passive-interface default":
                    rp.details["passive-interface"] = "default (all)"
                elif mt := re.match(r"no passive-interface (\S+)", ln):
                    rp.details["active interfaces"] = ", ".join(
                        x for x in (rp.details.get("active interfaces"), short_ifname(mt.group(1))) if x)
                elif mt := re.match(r"passive-interface (\S+)", ln):
                    rp.details["passive interfaces"] = ", ".join(
                        x for x in (rp.details.get("passive interfaces"), short_ifname(mt.group(1))) if x)
                elif mt := re.match(r"(default-information originate.*|redistribute .+|area \S+ (?:authentication.*|nssa.*|stub.*))", ln):
                    key = mt.group(1).split()[0] if not mt.group(1).startswith("area") else "area"
                    rp.details[key] = ", ".join(x for x in (rp.details.get(key), mt.group(1)) if x)
                elif mt := re.match(r"autonomous-system (\d+)", ln):
                    rp.asn = mt.group(1)
            for p, ifname, area in self.ospf_if:
                if proto == "ospf" and p == pid:
                    rp.networks.append(f"{short_ifname(ifname)} area {area}")
            self.dev.routing_protocols.append(rp)
        nbrs = output(self.raw, "show ip ospf neighbor", "show ip ospf neighbors")
        ospf = next((r for r in self.dev.routing_protocols if r.protocol == "ospf"), None)
        if ospf is not None:
            for mt in re.finditer(rf"^\s*({IPV4})\s+\d+\s+(\w+/\s*[\w-]+|\w+)\s+\S+\s+({IPV4})\s+(\S+)", nbrs, re.M):
                state = re.sub(r"\s+", "", mt.group(2))
                ospf.neighbors.append(f"{mt.group(1)} via {mt.group(3)} on {short_ifname(mt.group(4))} ({state})")

    # ----------------------------------------------------------------- neighbors / stp / acl
    def parse_neighbors(self) -> None:
        cdp = parse_cdp(output(self.raw, "show cdp neighbors detail", "show cdp neighbor detail"))
        lldp = parse_lldp_detail(output(self.raw, "show lldp neighbors detail", "show lldp neighbor detail"))
        for n in cdp + lldp:
            itf = self.iface(n.local_port, create=False)
            if itf is not None:
                n.local_port = itf.name
        self.dev.neighbors = merge_neighbors(cdp, lldp)

    def parse_stp(self) -> None:
        if not self.is_switch:
            return
        cfg, summ = self.cfg, output(self.raw, *self.stp_cmds)
        st = m.SpanningTree(mode=first(r"^spanning-tree mode (\S+)", cfg) or first(r"Switch is in (\S+) mode", summ))
        if not st.mode and cfg:
            st.mode = "pvst (default)"
        st.bpdu_guard_default = bool(re.search(
            r"^spanning-tree (?:portfast (?:edge )?bpduguard default|port type edge bpduguard default)", cfg, re.M))
        prios = [f"{p} (vlan {v})" for v, p in re.findall(r"^spanning-tree vlan (\S+) priority (\d+)", cfg, re.M)]
        prios += [f"{p} (mst {v})" for v, p in re.findall(r"^spanning-tree mst (\S+) priority (\d+)", cfg, re.M)]
        st.priority = "; ".join(prios) or None
        root = first(r"Root bridge for:\s*(.+)$", summ)
        if root is not None:
            st.root_bridge = root.lower() not in ("none", "")
            if st.root_bridge:
                st.details["root bridge for"] = root
        st.details["edge (portfast) default"] = "yes" if self.edge_default else "no"
        for key, pat in (("loopguard default", r"^spanning-tree loopguard default"),
                         ("bpdufilter default", r"^spanning-tree (?:portfast (?:edge )?bpdufilter|port type edge bpdufilter) default"),
                         ("extend system-id", r"^spanning-tree extend system-id"),
                         ("pathcost method", r"^spanning-tree pathcost method (\S+)")):
            mt = re.search(pat, cfg, re.M)
            if mt:
                st.details[key] = mt.group(1) if mt.groups() else "yes"
        disabled = re.findall(r"^no spanning-tree vlan (\S+)", cfg, re.M)
        if disabled:
            st.details["disabled on vlans"] = ",".join(disabled)
        self.dev.spanning_tree = st

    def parse_acls(self) -> None:
        acls: dict[str, m.Acl] = {}
        for header, lines in blocks(self.cfg, r"^(?:ip|ipv6|mac) access-list "):
            mt = re.match(r"^(ip|ipv6|mac) access-list (?:(standard|extended|role-based) )?(\S+)", header)
            if not mt:
                continue
            kind = {"ipv6": "ipv6", "mac": "mac"}.get(mt.group(1), mt.group(2) or "extended")
            acl = acls.setdefault(mt.group(3), m.Acl(name=mt.group(3), kind=kind))
            for ln in lines:
                em = re.match(r"^(?:(\d+)\s+)?(permit|deny)\s+(.*)$", ln)
                if em:
                    acl.entries.append(m.AclEntry(seq=em.group(1), action=em.group(2), text=em.group(3).strip()))
        for num, action, text in re.findall(r"^access-list (\d+) (permit|deny) (.+)$", self.cfg, re.M):
            n = int(num)
            kind = "standard" if n < 100 or 1300 <= n < 2000 else "extended"
            acls.setdefault(num, m.Acl(name=num, kind=kind)).entries.append(m.AclEntry(action=action, text=text.strip()))
        for header, lines in blocks(self.cfg, r"^line (vty|con)"):
            for ln in lines:
                mt = re.match(r"access-class (\S+) (in|out)", ln)
                if mt:
                    self.acl_apply[mt.group(1)].append(f"{header.removeprefix('line ')} {mt.group(2)}")
        for name in re.findall(r"^snmp-server community \S+.*?(?:\s(?:RO|RW|ro|rw))?\s+(?:ipv4 )?(\S+)\s*$", self.cfg, re.M):
            if name in acls:
                self.acl_apply[name].append("snmp")
        for name in re.findall(r"^snmp-server community \S+ use-(?:ipv4)?acl (\S+)", self.cfg, re.M):
            self.acl_apply[name].append("snmp")
        for name in re.findall(r"^ntp access-group \S+ (\S+)", self.cfg, re.M):
            self.acl_apply[name].append("ntp")
        for name, acl in acls.items():
            acl.applied_to = list(dict.fromkeys(self.acl_apply.get(name, [])))
        self.dev.acls = list(acls.values())

    # ----------------------------------------------------------------- management plane
    def parse_management(self) -> None:  # noqa: C901
        cfg, mg = self.cfg, self.dev.management
        if not cfg:
            return
        transports: list[str | None] = []
        for header, lines in blocks(cfg, r"^line "):
            if header.startswith("line vty"):
                t = next((ln.split(None, 2)[2] for ln in lines if ln.startswith("transport input ")), None)
                transports.append(t)
                acl = next((ln.split()[1] for ln in lines if re.match(r"access-class \S+ in\b", ln)), None)
                mg.vty_acl = mg.vty_acl or acl
            elif header.startswith(("line con", "line console")):
                to = next((ln.split()[1] for ln in lines if ln.startswith("exec-timeout ")), None)
                mg.console_timeout_min = int(to) if to and to.isdigit() else mg.console_timeout_min
        if transports:
            if any(t and ("telnet" in t or t == "all") for t in transports):
                mg.telnet = True
            elif all(t for t in transports):
                mg.telnet = False
            mg.ssh = any(t and ("ssh" in t or t == "all") for t in transports) or None
        if re.search(r"^ip ssh version 2", cfg, re.M):
            mg.ssh, mg.ssh_version = True, "2"
        mg.http = bool(re.search(r"^ip http server\s*$", cfg, re.M))
        mg.https = bool(re.search(r"^ip http secure-server\s*$", cfg, re.M))
        mg.banner = parse_banner(cfg)
        mg.ntp_servers = re.findall(r"^ntp server (?:vrf \S+ )?(?:ip )?(\S+)", cfg, re.M)
        for line in re.findall(r"^ip name-server (.+)$", cfg, re.M):
            mg.dns_servers += [t for t in line.split() if is_ip(t) or ":" in t]
        mg.domain = first(r"^ip domain[ -]name (?:vrf \S+ )?(\S+)", cfg)
        tz = first(r"^clock timezone (.+)$", cfg)
        summer = first(r"^clock summer-time (\S+)", cfg)
        mg.timezone = f"{tz} (summer-time {summer})" if tz and summer else tz
        mg.syslog_servers = (re.findall(r"^logging (?:host |server )?(?:vrf \S+ )?(?:ipv6 )?(\d[\d.]+\d|[0-9a-f:]+:[0-9a-f]+)\b",
                                        cfg, re.M))
        self._snmp()
        self._aaa()
        for name, rest in re.findall(r"^username (\S+)(.*)$", cfg, re.M):
            existing = next((u for u in mg.users if u.name == name), None)
            priv = first(r"privilege (\d+)", rest) or first(r"\brole (\S+)", rest)
            auth = cisco_auth(rest)
            if existing:
                existing.privilege = existing.privilege or priv
                existing.auth = existing.auth or auth
            else:
                mg.users.append(m.LocalUser(name=name, privilege=priv or ("1" if self.os_name_default == "IOS" else None),
                                            auth=auth))
        mt = re.search(r"^enable (secret|password)(?: level (\d+))?(.*)$", cfg, re.M)
        if mt:
            mg.users.append(m.LocalUser(name="enable", privilege=mt.group(2) or "15", auth=cisco_auth(mt.group(0))))
        mg.password_encryption = bool(re.search(r"^service password-encryption", cfg, re.M))
        for itf in self.ifs.values():
            if itf.kind == "mgmt" and itf.vrf:
                mg.mgmt_vrf = itf.vrf
        acl = next((a for a in self.dev.acls if a.name == mg.vty_acl), None)
        for e in acl.entries if acl else []:
            if e.action != "permit":
                continue
            mt = re.match(rf"^(?:(?:ip|tcp|udp)\s+)?(host\s+{IPV4}|{IPV4}/\d+|{IPV4}(?:\s+{IPV4})?|any)", e.text)
            if mt:
                src = mt.group(1).split()
                mg.allowed_mgmt_hosts.append(
                    src[1] if src[0] == "host" else wildcard_to_cidr(src[0], src[1]) if len(src) == 2 else src[0])
        for _h, lines in blocks(cfg, r"^archive$"):
            mg.backup_target = next((ln.split(None, 1)[1] for ln in lines if ln.startswith("path ")), None)

    def _snmp(self) -> None:
        cfg, sn = self.cfg, self.dev.management.snmp
        for mt in re.finditer(r"^snmp-server community (\S+)(.*)$", cfg, re.M):
            value, rest = mt.group(1), mt.group(2).split()
            if rest[:1] == ["use-acl"] or rest[:1] == ["use-ipv4acl"]:
                continue
            access = next((t.upper() for t in rest if t.lower() in ("ro", "rw")), None)
            group = rest[rest.index("group") + 1] if "group" in rest and rest.index("group") + 1 < len(rest) else None
            acl = None
            tail = [t for t in rest if t.lower() not in ("ro", "rw", "view", "group", "ipv4", "ipv6") and t != group]
            if tail and access:
                acl = tail[-1]
            if not acl:
                acl = first(rf"^snmp-server community {re.escape(value)} use-(?:ipv4)?acl (\S+)", cfg)
            sn.communities.append(community_label(value, access or group or "RO", f"acl {acl}" if acl else None))
            sn.acl = sn.acl or acl
            if "v2c" not in sn.versions:
                sn.versions.append("v2c")
        for name, ver, level in re.findall(r"^snmp-server group (\S+) (v1|v2c|v3)(?: (auth|noauth|priv))?", cfg, re.M):
            if ver not in sn.versions:
                sn.versions.append(ver)
            if ver == "v3":
                lvl = {"priv": "authPriv", "auth": "authNoPriv", "noauth": "noAuthNoPriv"}.get(level, level)
                sn.v3_users.append(f"group {name} ({lvl})")
        for name, rest in re.findall(r"^snmp-server user (\S+) (.*)$", cfg, re.M):
            auth = (first(r"\bauth (md5|sha\S*)", rest) or "").upper()
            pm = re.search(r"\bpriv\s+(aes[\s-]*\d*|des|3des)\b", rest)
            priv = (pm.group(1) if pm else ("DES" if " priv " in f" {rest} " else "")).upper().replace(" ", "")
            lvl = "authPriv" if " priv " in f" {rest} " else "authNoPriv" if auth else "noAuthNoPriv"
            sn.v3_users = [u for u in sn.v3_users if not u.startswith("group ")] if sn.v3_users else []
            sn.v3_users.append(f"{name} ({lvl}, {auth or '-'}/{priv or '-'})")
            if "v3" not in sn.versions:
                sn.versions.append("v3")
        sn.trap_hosts = list(dict.fromkeys(re.findall(r"^snmp-server host (\S+)", cfg, re.M)))
        sn.location = first(r"^snmp-server location (.+)$", cfg)
        sn.contact = first(r"^snmp-server contact (.+)$", cfg)
        sn.enabled = bool(sn.communities or sn.v3_users or sn.versions)

    def _aaa(self) -> None:
        cfg, aaa = self.cfg, self.dev.management.aaa
        for kind, attr in (("tacacs", "tacacs_servers"), ("radius", "radius_servers")):
            servers: list[str] = getattr(aaa, attr)
            for header, lines in blocks(cfg, rf"^{kind} server \S+"):
                addr = next((first(r"address ipv[46] (\S+)", ln) for ln in lines if ln.startswith("address ipv")), None)
                if addr:
                    servers.append(f"{addr} ({header.split()[-1]})")
            servers += re.findall(rf"^{kind}-server host (\S+)", cfg, re.M)
        for _header, lines in blocks(cfg, r"^ldap server \S+"):
            addr = next((first(r"ipv4 (\S+)", ln) for ln in lines if ln.startswith("ipv4 ")), None)
            if addr:
                aaa.ldap_servers.append(addr)
        for typ, svc, lst, methods in re.findall(r"^aaa (authentication|authorization) (\S+) (\S+) (.+)$", cfg, re.M):
            aaa.login_methods.append(f"{typ} {svc} {lst}: {methods.strip()}")
        aaa.accounting = bool(re.search(r"^aaa accounting ", cfg, re.M))

    # ----------------------------------------------------------------- HA / extras
    def parse_ha(self) -> None:
        sw = output(self.raw, "show switch detail", "show switch")
        members = re.findall(r"^\s*\*?(\d+)\s+(Active|Standby|Member)\s+(\S+)\s+(\d+)\s+\S+\s+(\S+)", sw, re.M)
        if len(members) > 1:
            states = {mm[4] for mm in members}
            self.dev.ha = m.HighAvailability(
                mode="stack", group=first(r"Switch/Stack Mac Address\s*:\s*(\S+)", sw),
                members=[f"Switch {n} ({role}, priority {prio}, {state})" for n, role, _mac, prio, state in members],
                state="ready" if states == {"Ready"} else ", ".join(sorted(states)),
                details={"members": str(len(members))})
            ring = re.findall(r"^\s+(\d+)\s+(OK|DOWN|Down)\s+(OK|DOWN|Down)\s", sw, re.M)
            if ring:
                ok = all(a == "OK" and b == "OK" for _n, a, b in ring)
                self.dev.ha.details["stack ring"] = "full ring (all stack ports OK)" if ok else "degraded: stack port down"
        if self.fhrp:
            rows = [[short_ifname(i), p.upper(), g, v] for i, p, g, v in self.fhrp]
            self.dev.sections.append(m.Section(id="fhrp", title="First-hop redundancy (HSRP/VRRP)",
                                               tables=[m.Table(columns=["Interface", "Protocol", "Group", "Virtual IP"],
                                                               rows=rows)]))
            if self.dev.ha is None:
                proto = self.fhrp[0][1]
                self.dev.ha = m.HighAvailability(mode=proto, group=", ".join(sorted({g for _i, _p, g, _v in self.fhrp})),
                                                 members=[self.dev.hostname],
                                                 details={short_ifname(i): v for i, _p, _g, v in self.fhrp})

    def parse_extras(self) -> None:
        cfg = self.cfg
        facts = []
        for label, pat in (("VTP mode", r"^vtp mode (\S+)"), ("VTP domain", r"^vtp domain (\S+)"),
                           ("IP routing", r"^(ip routing)$"), ("UDLD", r"^udld (\S+)"),
                           ("Errdisable recovery", r"^errdisable recovery cause (\S+)"),
                           ("Device tracking", r"^(device-tracking) policy"),
                           ("802.1X system auth control", r"^(dot1x system-auth-control)")):
            vals = re.findall(pat, cfg, re.M)
            if vals:
                facts.append(m.Fact(key=label, value=", ".join(dict.fromkeys(vals))))
        if facts:
            self.dev.sections.append(m.Section(id="switching-features", title="Switching features", facts=facts))
        snoop_vlans = first(r"^ip dhcp snooping vlan (\S+)", cfg)
        if re.search(r"^ip dhcp snooping\s*$", cfg, re.M) or snoop_vlans:
            trusted = [short_ifname(i.name) for i in self.ifs.values() if i.extra.get("dhcp snooping") == "trusted"]
            self.dev.sections.append(m.Section(id="dhcp-snooping", title="DHCP snooping", facts=[
                m.Fact(key="Enabled", value="yes" if re.search(r"^ip dhcp snooping\s*$", cfg, re.M) else "no (vlans only)"),
                m.Fact(key="VLANs", value=snoop_vlans or "-"),
                m.Fact(key="Option 82 insertion",
                       value="disabled" if re.search(r"^no ip dhcp snooping information option", cfg, re.M) else "enabled"),
                m.Fact(key="Trusted ports", value=", ".join(trusted) or "-")]))
        ps = [i for i in self.ifs.values() if i.port_security]
        if ps:
            rows = [[short_ifname(i.name), i.extra.get("port-security maximum", "1"),
                     i.extra.get("port-security violation", "shutdown"),
                     "yes" if "port-security mac-address" in i.extra else "no"] for i in ps]
            self.dev.sections.append(m.Section(id="port-security", title="Port security", tables=[m.Table(
                columns=["Interface", "Max MACs", "Violation", "Sticky"], rows=rows)]))

    # ----------------------------------------------------------------- mgmt ip
    def find_mgmt_ip(self) -> str | None:
        ifs = list(self.ifs.values())
        for itf in ifs:
            if itf.kind == "mgmt" and itf.enabled and first_ipv4(itf):
                return first_ipv4(itf)
        for src in re.findall(r"^(?:ip ssh|logging|ip tacacs|ip radius|snmp-server trap-source|ntp)\s*"
                              r"(?:source-interface|source)?\s+(\S+)\s*$", self.cfg, re.M):
            itf = self.iface(src, create=False)
            if itf is not None and first_ipv4(itf):
                return first_ipv4(itf)
        names = {v.id: (v.name or "") for v in self.dev.vlans}
        for itf in ifs:
            vid = first(r"(\d+)$", itf.name) if itf.kind == "vlan" else None
            if vid and re.search(r"mgmt|manage|oam", names.get(int(vid), "") + (itf.description or ""), re.I) \
                    and first_ipv4(itf):
                return first_ipv4(itf)
        for kind in ("loopback", "vlan", "physical", "lag"):
            for itf in ifs:
                if itf.kind == kind and first_ipv4(itf):
                    return first_ipv4(itf)
        return self.raw.target if is_ip(self.raw.target) else None


class CiscoIosDriver(Driver):
    id = "cisco_ios"
    label = "Cisco IOS / IOS-XE"
    methods = ("ssh", "file")
    netmiko_type = "cisco_ios"
    commands: tuple[str, ...] = tuple(IOS_COMMANDS)
    parser_cls: type[CiscoParser] = CiscoParser

    def collect(self, target: Target, creds: Credentials) -> RawCollection:
        return run_commands(target, creds, self.netmiko_type, list(self.commands), self.id)

    def parse(self, raw: RawCollection) -> m.Device:
        return self.parser_cls(raw, self.id).parse()


register(CiscoIosDriver())
