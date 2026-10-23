"""Cisco ASA driver (SSH, netmiko device_type "cisco_asa", or offline running-config import).

Read-only commands: show running-config, show version, show failover, show nat,
show access-list (hit counts), show interface ip brief, show route.
Interface-bound ACLs (access-group) become firewall rules (src zone = nameif); all ACLs
are also documented as plain ACLs. Object and twice NAT become NAT rules. Crypto maps +
IKE policies + tunnel-groups become IPsec tunnels.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from sextant import model as m
from sextant.drivers import register
from sextant.drivers._util import blocks, first, mask_to_prefix, mask_value, network_of, norm_action
from sextant.drivers.base import Credentials, Driver, RawCollection, Target
from sextant.redact import redact_text

CMD_RUN = "show running-config"
CMD_VER = "show version"
CMD_FAILOVER = "show failover"
CMD_NAT = "show nat"
CMD_ACL = "show access-list"
CMD_IPBRIEF = "show interface ip brief"
CMD_ROUTE = "show route"
COMMANDS = [CMD_RUN, CMD_VER, CMD_FAILOVER, CMD_NAT, CMD_ACL, CMD_IPBRIEF, CMD_ROUTE]

_IP = r"\d+\.\d+\.\d+\.\d+"


@dataclass
class _Cfg:
    text: str
    lines: list[str]
    objects: dict[str, tuple[str, str]] = field(default_factory=dict)  # name -> (kind, value)
    net_groups: dict[str, list[str]] = field(default_factory=dict)
    svc_groups: dict[str, list[str]] = field(default_factory=dict)
    svc_objects: dict[str, str] = field(default_factory=dict)
    nameif: dict[str, str] = field(default_factory=dict)  # physical -> nameif

    def resolve(self, name: str) -> str:
        return ", ".join(self.resolve_list(name))

    def resolve_list(self, name: str, depth: int = 0) -> list[str]:
        if name in self.objects:
            return [self.objects[name][1]]
        if name in self.net_groups and depth < 8:
            return [v for x in self.net_groups[name] for v in self.resolve_list(x, depth + 1)]
        return [name]


def _text(v: object) -> str:
    return v if isinstance(v, str) else ("" if v is None else str(v))


# --------------------------------------------------------------------------- ACE parsing

_ADDR_ANY = {"any", "any4", "any6"}
_PORT_OPS = {"eq", "neq", "lt", "gt"}


def _addr(tok: list[str], i: int) -> tuple[str | None, int]:
    if i >= len(tok):
        return None, i
    t = tok[i]
    if t in _ADDR_ANY:
        return "any", i + 1
    if t in ("host", "object", "object-group") and i + 1 < len(tok):
        return tok[i + 1], i + 2
    if t == "interface" and i + 1 < len(tok):
        return f"interface {tok[i + 1]}", i + 2
    if re.fullmatch(_IP, t) and i + 1 < len(tok) and re.fullmatch(_IP, tok[i + 1]):
        cidr = mask_to_prefix(t, tok[i + 1])
        return cidr.removesuffix("/32"), i + 2
    if ":" in t and "/" in t:
        return t, i + 1
    return None, i


def _port(tok: list[str], i: int, cfg: _Cfg) -> tuple[str | None, int]:
    if i >= len(tok):
        return None, i
    t = tok[i]
    if t in _PORT_OPS and i + 1 < len(tok):
        return (tok[i + 1] if t == "eq" else f"{t} {tok[i + 1]}"), i + 2
    if t == "range" and i + 2 < len(tok):
        return f"{tok[i + 1]}-{tok[i + 2]}", i + 3
    if t == "object-group" and i + 1 < len(tok) and tok[i + 1] in cfg.svc_groups:
        return tok[i + 1], i + 2
    return None, i


def parse_ace(rest: str, cfg: _Cfg) -> dict | None:
    """'extended permit tcp any object WEB eq https log' -> dict. None for remarks/unknown."""
    tok = rest.split()
    if len(tok) < 3 or tok[0] not in ("extended", "standard"):
        return None
    res: dict = {"kind": tok[0], "action": tok[1], "users": [], "log": None, "inactive": False, "time_range": None}
    i = 2
    if tok[0] == "standard":
        src, i = _addr(tok, i)
        if src is None and i < len(tok) and re.fullmatch(_IP, tok[i]):
            src, i = tok[i], i + 1
        res.update(proto="ip", src="any", dst=src or "any", sport=None, dport=None)
        return res
    if tok[i] in ("object-group", "object") and i + 1 < len(tok):
        res["proto"] = tok[i + 1]
        res["proto_is_obj"] = True
        i += 2
    else:
        res["proto"] = tok[i]
        i += 1
    while i < len(tok) and tok[i] in ("user", "user-group", "object-group-user", "security-group",
                                      "object-group-security"):
        if i + 1 < len(tok):
            res["users"].append(tok[i + 1] if tok[i] == "user" else f"{tok[i]}:{tok[i + 1]}")
        i += 2
    src, i = _addr(tok, i)
    sport, i = _port(tok, i, cfg)
    while i < len(tok) and tok[i] in ("security-group", "object-group-security"):
        i += 2
    dst, i = _addr(tok, i)
    dport, i = _port(tok, i, cfg)
    res.update(src=src or "any", dst=dst or "any", sport=sport, dport=dport)
    while i < len(tok):
        t = tok[i]
        if t == "log":
            if i + 1 < len(tok) and tok[i + 1] == "disable":
                res["log"] = False
                i += 2
                continue
            res["log"] = True
        elif t == "inactive":
            res["inactive"] = True
        elif t == "time-range" and i + 1 < len(tok):
            res["time_range"] = tok[i + 1]
            i += 1
        i += 1
    return res


def _service(ace: dict) -> str:
    proto, dport = ace.get("proto") or "ip", ace.get("dport")
    if ace.get("proto_is_obj"):
        return proto
    if proto in ("ip", "ipv4") and not dport:
        return "any"
    if dport:
        return f"{proto}/{dport}"
    return proto


# --------------------------------------------------------------------------- crypto helpers

_ENC = {"esp-aes": "aes128", "esp-aes-192": "aes192", "esp-aes-256": "aes256", "esp-3des": "3des", "esp-des": "des",
        "esp-aes-gcm": "aes128gcm", "esp-aes-gcm-192": "aes192gcm", "esp-aes-gcm-256": "aes256gcm",
        "esp-null": "null", "aes": "aes128", "aes-192": "aes192", "aes-256": "aes256", "3des": "3des", "des": "des",
        "aes-gcm": "aes128gcm", "aes-gcm-192": "aes192gcm", "aes-gcm-256": "aes256gcm", "null": "null"}
_HASH = {"esp-sha-hmac": "sha1", "esp-md5-hmac": "md5", "esp-sha256-hmac": "sha256", "esp-sha384-hmac": "sha384",
         "esp-sha512-hmac": "sha512", "esp-none": "none", "sha": "sha1", "sha-1": "sha1", "sha1": "sha1",
         "md5": "md5", "sha256": "sha256", "sha-256": "sha256", "sha384": "sha384", "sha-384": "sha384",
         "sha512": "sha512", "sha-512": "sha512", "null": "none"}


def _enc(x: str) -> str:
    return _ENC.get(x.lower(), x.lower())


def _hash(x: str) -> str:
    return _HASH.get(x.lower(), x.lower())


# --------------------------------------------------------------------------- driver


class CiscoAsaDriver(Driver):
    id = "cisco_asa"
    label = "Cisco ASA"
    methods = ("ssh", "file")
    commands = tuple(COMMANDS)

    def collect(self, target: Target, creds: Credentials) -> RawCollection:
        if target.method == "file" and target.file:
            from pathlib import Path

            return self.from_file(Path(target.file))
        from sextant.drivers._ssh import run_commands

        return run_commands(target, creds, "cisco_asa", COMMANDS, self.id, timeout=180)

    def parse(self, raw: RawCollection) -> m.Device:
        out = raw.outputs or {}
        warnings = list(raw.warnings)
        text = _text(out.get("config") or out.get(CMD_RUN) or out.get("show run"))
        ver = _text(out.get(CMD_VER))
        if not text.strip():
            warnings.append("no running-config in collection")
        if raw.method != "file":
            for c in (CMD_VER, CMD_FAILOVER, CMD_ACL, CMD_IPBRIEF):
                if not _text(out.get(c)).strip():
                    warnings.append(f"no output for '{c}'")
        dev = m.Device(hostname=raw.target, role=m.DeviceRole.firewall, vendor="Cisco", platform=self.id,
                       os_name="ASA", collection_method=raw.method, source=raw.target)
        cfg = _Cfg(text=text, lines=text.splitlines())
        for step in (_identity, _objects, _interfaces, _management, _routing, _acls, _nat, _vpn, _ha, _dhcp,
                     _extras):
            try:
                step(dev, cfg, out, ver)
            except Exception as exc:  # noqa: BLE001 - never lose the device for one bad block
                warnings.append(f"{step.__name__.lstrip('_')}: {exc.__class__.__name__}: {exc}")
        dev.collection_warnings = warnings
        try:
            dev.raw_config = redact_text(text) if text.strip() else None
        except Exception:  # noqa: BLE001
            dev.raw_config = None
        return dev


# --------------------------------------------------------------------------- steps


def _identity(dev: m.Device, cfg: _Cfg, out: dict, ver: str) -> None:
    t = cfg.text
    dev.hostname = first(r"^hostname\s+(\S+)", t) or first(r"^(\S+)\s+up\s+\d+", ver) or dev.hostname
    dev.os_version = first(r"Adaptive Security Appliance Software Version\s+(\S+)", ver) or \
        first(r"^ASA Version\s+(\S+)", t)
    dev.model = first(r"^:?\s*Hardware:\s+([\w-]+),", ver) or first(r"^:\s*Hardware:\s+([\w-]+),", t)
    dev.serial = first(r"^:?\s*Serial Number:\s+(\S+)", ver) or first(r"^:\s*Serial Number:\s+(\S+)", t)
    dev.uptime = first(rf"^{re.escape(dev.hostname)}\s+up\s+(.+)$", ver) or first(r"^\S+\s+up\s+(.+)$", ver)
    lic = first(r"^This platform has an? (.+?) license", ver)
    if lic:
        dev.licenses.append(lic)
    for key, pat in (("Firepower Extensible Operating System", r"Firepower Extensible Operating System Version\s+(\S+)"),
                     ("ASDM", r"Device Manager Version\s+(\S+)"), ("System image", r'System image file is "([^"]+)"'),
                     ("Hardware", r"^Hardware:\s+(.+)$"), ("Failover license", r"^Failover\s+:\s+(.+?)\s{2,}"),
                     ("Encryption-3DES-AES", r"^Encryption-3DES-AES\s+:\s+(\S+)"),
                     ("Config last modified", r"^Configuration last modified by (.+)$")):
        v = first(pat, ver)
        if v:
            dev.hardware.append(m.Fact(key=key, value=v))
    dev.location = first(r"^snmp-server location\s+(.+)$", t)
    dev.contact = first(r"^snmp-server contact\s+(.+)$", t)


def _objects(dev: m.Device, cfg: _Cfg, out: dict, ver: str) -> None:
    for header, kids in blocks(cfg.text, r"^object network "):
        name = header.split()[2]
        desc = next((k.split(" ", 1)[1] for k in kids if k.startswith("description ")), None)
        kind, value = "host", ""
        for k in kids:
            p = k.split()
            if p[0] == "host" and len(p) > 1:
                kind, value = "host", p[1]
            elif p[0] == "subnet" and len(p) > 2:
                kind, value = "subnet", mask_to_prefix(p[1], p[2]) if "." in p[2] else f"{p[1]}/{p[2]}"
            elif p[0] == "range" and len(p) > 2:
                kind, value = "range", f"{p[1]}-{p[2]}"
            elif p[0] == "fqdn" and len(p) > 1:
                kind, value = "fqdn", p[-1]
        if value:
            cfg.objects[name] = (kind, value)
            dev.address_objects.append(m.AddressObject(name=name, kind=kind, value=value, comment=desc))
    for header, kids in blocks(cfg.text, r"^object service "):
        name = header.split()[2]
        cfg.svc_objects[name] = next((k.removeprefix("service ") for k in kids if k.startswith("service ")), "")
    for header, kids in blocks(cfg.text, r"^object-group "):
        p = header.split()
        if len(p) < 3:
            continue
        typ, name = p[1], p[2]
        members: list[str] = []
        desc = None
        for k in kids:
            q = k.split()
            if q[0] == "description":
                desc = k.split(" ", 1)[1] if " " in k else None
            elif q[0] == "network-object" and len(q) > 1:
                if q[1] in ("host", "object") and len(q) > 2:
                    members.append(q[2])
                elif len(q) > 2 and re.fullmatch(_IP, q[2]):
                    members.append(mask_to_prefix(q[1], q[2]))
                else:
                    members.append(q[1])
            elif q[0] == "group-object" and len(q) > 1:
                members.append(q[1])
            elif q[0] in ("port-object", "service-object", "protocol-object", "icmp-object"):
                members.append(" ".join(q[1:]))
        if typ == "network":
            cfg.net_groups[name] = members
            dev.address_objects.append(m.AddressObject(name=name, kind="group", value=", ".join(members),
                                                       comment=desc))
        elif typ in ("service", "protocol", "icmp-type"):
            proto = p[3] if len(p) > 3 else ""
            cfg.svc_groups[name] = [f"{proto} {x}".strip() for x in members]


def _interfaces(dev: m.Device, cfg: _Cfg, out: dict, ver: str) -> None:
    oper: dict[str, bool] = {}
    for line in _text(out.get(CMD_IPBRIEF)).splitlines():
        p = line.split()
        if len(p) >= 6 and p[0][0].isupper() and p[0] != "Interface":
            oper[p[0]] = p[-1].lower() == "up"
    mtu = {mm.group(1): int(mm.group(2)) for mm in re.finditer(r"^mtu\s+(\S+)\s+(\d+)", cfg.text, re.MULTILINE)}
    lags: dict[str, list[str]] = {}
    for header, kids in blocks(cfg.text, r"^interface "):
        name = header.split()[1]
        intf = m.Interface(name=name, mode=m.PortMode.routed)
        if "." in name:
            intf.kind = "vlan"
        elif name.lower().startswith("port-channel"):
            intf.kind = "lag"
        elif name.lower().startswith(("management", "mgmt")):
            intf.kind = "mgmt"
        elif name.lower().startswith(("bvi", "redundant", "vlan", "tunnel")):
            intf.kind = "tunnel" if name.lower().startswith("tunnel") else "virtual"
        nameif = None
        for k in kids:
            p = k.split()
            if p[0] == "description":
                intf.description = k.split(" ", 1)[1] if " " in k else None
            elif p[0] == "nameif" and len(p) > 1:
                nameif = p[1]
            elif p[0] == "security-level" and len(p) > 1:
                intf.extra["security-level"] = p[1]
            elif k == "shutdown":
                intf.enabled = False
            elif p[0] == "vlan" and len(p) > 1 and p[1].isdigit():
                intf.access_vlan = int(p[1])
            elif p[0] == "channel-group" and len(p) > 1:
                intf.lag = f"Port-channel{p[1]}"
                intf.mode = m.PortMode.lag_member
                lags.setdefault(intf.lag, []).append(name)
            elif k == "management-only":
                intf.extra["management-only"] = "yes"
            elif p[:2] == ["ip", "address"] and len(p) > 2:
                if p[2] == "dhcp":
                    intf.extra["addressing"] = "dhcp"
                elif len(p) > 3:
                    intf.ipv4.append(m.IPAddress(address=mask_to_prefix(p[2], p[3])))
                    if "standby" in p and p.index("standby") + 1 < len(p):
                        intf.extra["standby-ip"] = p[p.index("standby") + 1]
            elif p[:2] == ["ipv6", "address"] and len(p) > 2:
                intf.ipv6.append(p[2])
            elif p[0] == "speed" and len(p) > 1:
                intf.speed = p[1]
            elif p[0] == "duplex" and len(p) > 1:
                intf.duplex = p[1]
            elif p[0] == "member-interface" and len(p) > 1:
                intf.lag_members.append(p[1])
        if nameif:
            intf.zone = nameif
            cfg.nameif[name] = nameif
            if nameif in mtu:
                intf.mtu = mtu[nameif]
        if name in oper:
            intf.oper_up = oper[name]
        dev.interfaces.append(intf)
        if intf.kind == "vlan" and intf.access_vlan is not None:
            dev.vlans.append(m.Vlan(id=intf.access_vlan, name=nameif, svi_ipv4=[a.address for a in intf.ipv4],
                                    ports=[name.split(".")[0]]))
    for intf in dev.interfaces:
        if intf.name in lags:
            intf.lag_members = lags[intf.name]
            intf.lag_protocol = "lacp"
    dev.vlans.sort(key=lambda v: v.id)
    mg = next((i for i in dev.interfaces if i.kind == "mgmt" and i.ipv4), None) or \
        next((i for i in dev.interfaces if i.zone and "manage" in i.zone and i.ipv4), None)
    if mg:
        dev.mgmt_ip = mg.ipv4[0].address.split("/")[0]


def _management(dev: m.Device, cfg: _Cfg, out: dict, ver: str) -> None:
    t, mg = cfg.text, dev.management
    ssh_hosts = re.findall(rf"^ssh\s+({_IP})\s+({_IP})\s+(\S+)", t, re.MULTILINE)
    telnet_hosts = re.findall(rf"^telnet\s+({_IP})\s+({_IP})\s+(\S+)", t, re.MULTILINE)
    http_hosts = re.findall(rf"^http\s+({_IP})\s+({_IP})\s+(\S+)", t, re.MULTILINE)
    http_on = bool(re.search(r"^http server enable", t, re.MULTILINE))
    mg.ssh = bool(ssh_hosts)
    mg.telnet = bool(telnet_hosts)
    mg.https = http_on and bool(http_hosts)
    mg.http = False  # ASDM is served over HTTPS only ("http redirect" just redirects to HTTPS)
    mg.ssh_version = first(r"^ssh version\s+(\d)", t) or ("2" if mg.ssh else None)
    for proto, lst in (("ssh", ssh_hosts), ("https", http_hosts), ("telnet", telnet_hosts)):
        for a, msk, ifc in lst:
            entry = f"{mask_to_prefix(a, msk)} ({ifc}, {proto})"
            mg.allowed_mgmt_hosts.append(entry)
    ct = first(r"^console timeout\s+(\d+)", t)
    mg.console_timeout_min = int(ct) if ct else None
    banners = [mm.group(2) for mm in re.finditer(r"^banner\s+(motd|login|exec|asdm)\s+(.*)$", t, re.MULTILINE)]
    mg.banner = "\n".join(banners) or None
    mg.ntp_servers = re.findall(r"^ntp server\s+(\S+)", t, re.MULTILINE)
    dns: list[str] = []
    for _h, kids in blocks(t, r"^dns server-group "):
        for k in kids:
            if k.startswith("name-server "):
                dns += k.split()[1:]
            elif k.startswith("domain-name ") and not mg.domain:
                mg.domain = k.split()[1]
    for line in re.findall(r"^dns name-server\s+(.+)$", t, re.MULTILINE):
        dns += line.split()
    mg.dns_servers = [d for d in dict.fromkeys(dns) if re.fullmatch(_IP, d) or ":" in d]
    mg.domain = first(r"^domain-name\s+(\S+)", t) or mg.domain
    tz = first(r"^clock timezone\s+(.+)$", t)
    mg.timezone = tz
    mg.syslog_servers = [f"{mm.group(2)} ({mm.group(1)}{', ' + mm.group(3) if mm.group(3) else ''})"
                         for mm in re.finditer(r"^logging host[ \t]+(\S+)[ \t]+(\S+)(?:[ \t]+(\S+))?", t,
                                               re.MULTILINE)]
    # SNMP
    sn = mg.snmp
    for c in re.findall(r"^snmp-server community\s+(\S+)", t, re.MULTILINE):
        sn.communities.append(f"{mask_value(c)} (RO)")
        if "v2c" not in sn.versions:
            sn.versions.append("v2c")
    for mm in re.finditer(r"^snmp-server host\s+(\S+)\s+(\S+)(.*)$", t, re.MULTILINE):
        rest = mm.group(3)
        v = first(r"version\s+(\S+)", rest) or "1"
        vlabel = {"1": "v1", "2c": "v2c", "3": "v3"}.get(v, v)
        sn.trap_hosts.append(f"{mm.group(2)} ({mm.group(1)}, {vlabel}"
                             + (", poll" if " poll" in rest else "") + (", trap" if " trap" in rest else "") + ")")
        if vlabel not in sn.versions:
            sn.versions.append(vlabel)
        com = first(r"community\s+(\S+)", rest)
        if com:
            sn.communities.append(f"{mask_value(com)} (host {mm.group(2)})")
    for mm in re.finditer(r"^snmp-server user\s+(\S+)\s+(\S+)\s+v3(.*)$", t, re.MULTILINE):
        rest = mm.group(3)
        auth = (first(r"auth\s+(\S+)", rest) or "").upper()
        priv = " ".join((first(r"priv\s+(\S+(?:\s+\d+)?)", rest) or "").upper().split())
        lvl = "authPriv" if priv else ("authNoPriv" if auth else "noAuthNoPriv")
        sn.v3_users.append(f"{mm.group(1)} ({lvl}, {auth or '-'}/{priv or '-'}, group {mm.group(2)})")
        if "v3" not in sn.versions:
            sn.versions.append("v3")
    sn.versions.sort()
    sn.enabled = bool(sn.communities or sn.v3_users) and not re.search(r"^no snmp-server enable\s*$", t,
                                                                         re.MULTILINE)
    sn.location, sn.contact = dev.location, dev.contact
    # AAA
    aaa = mg.aaa
    proto_of = dict(re.findall(r"^aaa-server\s+(\S+)\s+protocol\s+(\S+)", t, re.MULTILINE))
    for mm in re.finditer(r"^aaa-server\s+(\S+)\s+\((\S+)\)\s+host\s+(\S+)", t, re.MULTILINE):
        grp, ifc, host = mm.groups()
        proto = proto_of.get(grp, "")
        entry = f"{host} ({grp}, {ifc})"
        if proto == "radius":
            aaa.radius_servers.append(entry)
        elif proto.startswith("tacacs"):
            aaa.tacacs_servers.append(entry)
        elif proto in ("ldap", "kerberos", "nt"):
            aaa.ldap_servers.append(entry)
    aaa.login_methods = [ln.removeprefix("aaa ") for ln in re.findall(r"^aaa (?:authentication|authorization)\s.+$",
                                                                       t, re.MULTILINE)]
    aaa.accounting = bool(re.search(r"^aaa accounting\s", t, re.MULTILINE))
    # users
    key_users = {h.split()[1] for h, kids in blocks(t, r"^username \S+ attributes")
                 if any(k.startswith("ssh authentication publickey") for k in kids)}
    for mm in re.finditer(r"^username\s+(\S+)\s+(.*)$", t, re.MULTILINE):
        name, rest = mm.group(1), mm.group(2)
        if rest.startswith("attributes"):
            continue
        priv = first(r"privilege\s+(\d+)", rest) or "2"
        auth = []
        if rest.startswith(("password", "secret")):
            kind = "pbkdf2" if "pbkdf2" in rest else ("encrypted" if "encrypted" in rest else "hash")
            auth.append(f"password ({kind})")
        elif "nopassword" in rest:
            auth.append("no password")
        if name in key_users:
            auth.append("ssh-key")
        mg.users.append(m.LocalUser(name=name, privilege=priv, auth=", ".join(auth) or None))
    mg.password_encryption = bool(re.search(r"^password encryption aes", t, re.MULTILINE))


def _routing(dev: m.Device, cfg: _Cfg, out: dict, ver: str) -> None:
    t = cfg.text
    for mm in re.finditer(rf"^route\s+(\S+)\s+({_IP})\s+({_IP})\s+(\S+)\s*(\d+)?(.*)$", t, re.MULTILINE):
        ifc, net, msk, gw, dist, rest = mm.groups()
        prefix = mask_to_prefix(net, msk)
        if prefix.startswith("0.0.0.0/0") or (net == "0.0.0.0" and msk == "0.0.0.0"):
            prefix = "0.0.0.0/0"
        else:
            prefix = network_of(prefix)
        dev.routes.append(m.Route(prefix=prefix, next_hop=gw, interface=ifc, protocol="static",
                                  distance=int(dist) if dist else 1,
                                  description=rest.strip() or None))
    for mm in re.finditer(r"^ipv6 route\s+(\S+)\s+(\S+)\s+(\S+)", t, re.MULTILINE):
        dev.routes.append(m.Route(prefix=mm.group(2), next_hop=mm.group(3), interface=mm.group(1)))
    for header, kids in blocks(t, r"^router (ospf|bgp|eigrp) "):
        p = header.split()
        proto, pid = p[1], p[2]
        rp = m.RoutingProtocol(protocol=proto, process_id=pid if proto != "bgp" else None,
                               asn=pid if proto in ("bgp", "eigrp") else None)
        for k in kids:
            q = k.split()
            if q[0] in ("router-id", "bgp") and "router-id" in q:
                rp.router_id = q[q.index("router-id") + 1] if q.index("router-id") + 1 < len(q) else None
            elif q[0] == "network" and len(q) > 2:
                net = mask_to_prefix(q[1], q[2]) if re.fullmatch(_IP, q[2]) else q[1]
                if proto == "bgp" and len(q) > 3 and q[2] == "mask":
                    net = mask_to_prefix(q[1], q[3])
                rp.networks.append(net + (f" area {q[-1]}" if "area" in q else ""))
            elif q[0] == "network" and len(q) == 2:
                rp.networks.append(q[1])
            elif q[0] == "neighbor" and "remote-as" in q:
                rp.neighbors.append(f"{q[1]} (AS {q[q.index('remote-as') + 1]})")
            elif q[0] == "redistribute":
                rp.details["redistribute"] = ", ".join(filter(None, [rp.details.get("redistribute"), " ".join(q[1:])]))
            elif q[0] == "default-information":
                rp.details["default-information"] = " ".join(q[1:])
        dev.routing_protocols.append(rp)


def _acls(dev: m.Device, cfg: _Cfg, out: dict, ver: str) -> None:
    t = cfg.text
    hits: dict[tuple[str, int], int] = {}
    for mm in re.finditer(r"^access-list\s+(\S+)\s+line\s+(\d+)\s+.*\(hitcnt=(\d+)\)", _text(out.get(CMD_ACL)),
                          re.MULTILINE):
        hits[(mm.group(1), int(mm.group(2)))] = int(mm.group(3))
    bound: dict[str, list[str]] = {}
    for mm in re.finditer(r"^access-group\s+(\S+)\s+(?:(in|out)\s+interface\s+(\S+)|(global))", t, re.MULTILINE):
        name, direction, ifc, glob = mm.groups()
        bound.setdefault(name, []).append("global" if glob else f"{ifc} {direction}")
    acls: dict[str, m.Acl] = {}
    counters: dict[str, int] = {}
    pending_remark: dict[str, list[str]] = {}
    for mm in re.finditer(r"^access-list\s+(\S+)\s+(.*)$", t, re.MULTILINE):
        name, rest = mm.group(1), mm.group(2)
        lm = re.match(r"line\s+\d+\s+(.*)$", rest)
        if lm:
            rest = lm.group(1)
        counters[name] = counters.get(name, 0) + 1
        line_no = counters[name]
        acl = acls.setdefault(name, m.Acl(name=name, kind="extended", applied_to=bound.get(name, [])))
        if rest.startswith("remark"):
            pending_remark.setdefault(name, []).append(rest.removeprefix("remark").strip())
            continue
        ace = parse_ace(rest, cfg)
        if ace is None:
            continue
        acl.kind = ace["kind"]
        acl.entries.append(m.AclEntry(seq=str(line_no), action=ace["action"], text=" ".join(rest.split()[2:])))
        remark = " / ".join(pending_remark.pop(name, [])) or None
        for where in bound.get(name, []):
            if where == "global":
                src_zones, dst_zones = ["any"], ["any"]
            else:
                ifc, direction = where.split()
                src_zones, dst_zones = ([ifc], []) if direction == "in" else ([], [ifc])
            dev.firewall_rules.append(m.FirewallRule(
                id=f"{name}:{line_no}", name=name, enabled=not ace["inactive"],
                action=norm_action(ace["action"]), src_zones=src_zones, dst_zones=dst_zones,
                src_addresses=[ace["src"]], dst_addresses=[ace["dst"]], services=[_service(ace)],
                users=ace["users"], log=ace["log"], schedule=ace["time_range"],
                comment=remark, hit_count=hits.get((name, line_no))))
    dev.acls = list(acls.values())


def _nat(dev: m.Device, cfg: _Cfg, out: dict, ver: str) -> None:
    t = cfg.text
    n = 0
    for mm in re.finditer(r"^nat\s+\(([^,]+),([^)]+)\)\s+(.*)$", t, re.MULTILINE):
        n += 1
        real_if, mapped_if, rest = mm.groups()
        tok = rest.split()
        desc = first(r"description\s+(.+)$", rest)
        if "source" not in tok:
            continue
        i = tok.index("source")
        typ = tok[i + 1] if i + 1 < len(tok) else "static"
        real = tok[i + 2] if i + 2 < len(tok) else "?"
        mapped = tok[i + 3] if i + 3 < len(tok) else "?"
        dst = ""
        if "destination" in tok:
            j = tok.index("destination")
            if j + 3 < len(tok):
                dst = f" -> {tok[j + 3]}" + (f" (as {tok[j + 2]})" if tok[j + 2] != tok[j + 3] else "")
        svc = ""
        if "service" in tok:
            k = tok.index("service")
            svc = " service " + " ".join(tok[k + 1:k + 3])
        if typ == "static" and real == mapped:
            kind = "no-nat"
        elif typ == "static":
            kind = "static"
        elif mapped == "interface" or "pat-pool" in tok:
            kind = "pat"
        else:
            kind = "snat"
        dev.nat_rules.append(m.NatRule(
            id=f"twice:{n}" + (" (after-auto)" if "after-auto" in tok else ""), kind=kind,
            original=f"{real}{dst}{svc}", translated=(f"{mapped_if} interface" if mapped == "interface" else mapped),
            interface=f"{real_if} -> {mapped_if}", comment=desc, enabled="inactive" not in tok))
    for header, kids in blocks(t, r"^object network "):
        name = header.split()[2]
        for k in kids:
            mm = re.match(r"nat\s+\(([^,]+),([^)]+)\)\s+(static|dynamic)\s+(\S+)(.*)$", k)
            if not mm:
                continue
            real_if, mapped_if, typ, mapped, rest = mm.groups()
            svc = first(r"service\s+(\S+\s+\S+\s+\S+)", rest)
            orig = cfg.resolve(name)
            if svc:
                proto, rport, mport = svc.split()
                orig, mapped = f"{orig}:{rport}/{proto}", f"{mapped}:{mport}"
            kind = "static" if typ == "static" else ("pat" if mapped.startswith("interface") else "snat")
            dev.nat_rules.append(m.NatRule(
                id=f"object:{name}", kind=kind, original=f"{name} ({orig})" if name != orig else orig,
                translated=f"{mapped_if} interface" if mapped == "interface" else mapped,
                interface=f"{real_if} -> {mapped_if}", enabled="inactive" not in rest))


def _vpn(dev: m.Device, cfg: _Cfg, out: dict, ver: str) -> None:
    t = cfg.text
    # IKE policies
    p1: dict[str, list[str]] = {"ikev1": [], "ikev2": []}
    for ike in ("ikev1", "ikev2"):
        for _header, kids in blocks(t, rf"^crypto {ike} policy \d+"):
            enc, integ, grp, life = [], [], [], "86400"
            for k in kids:
                q = k.split()
                if q[0] == "encryption":
                    enc += [_enc(x) for x in q[1:]]
                elif q[0] in ("integrity", "hash"):
                    integ += [_hash(x) for x in q[1:]]
                elif q[0] == "group":
                    grp += q[1:]
                elif q[0] == "lifetime":
                    life = q[-1]
            if ike == "ikev1":
                enc = enc or ["3des"]
                integ = integ or ["sha1"]
                grp = grp or ["2"]
            p1[ike].append(f"{'/'.join(enc)}-{'/'.join(integ)}, dh{'/dh'.join(grp or ['?'])}, {life}s")
    # phase 2 building blocks
    # "transform-set TS mode transport" is a separate line that must not overwrite the crypto of TS
    tsets = {mm.group(1): f"{_enc(mm.group(2))}-{_hash(mm.group(3)) if mm.group(3) else 'none'}"
             for mm in re.finditer(r"^crypto ipsec ikev1 transform-set\s+(\S+)\s+(\S+)\s*(\S+)?", t, re.MULTILINE)
             if mm.group(2) != "mode"}
    props: dict[str, str] = {}
    for header, kids in blocks(t, r"^crypto ipsec ikev2 ipsec-proposal "):
        enc = next((k.split()[3:] for k in kids if k.startswith("protocol esp encryption")), [])
        integ = next((k.split()[3:] for k in kids if k.startswith("protocol esp integrity")), [])
        props[header.split()[-1]] = f"{'/'.join(_enc(x) for x in enc)}-{'/'.join(_hash(x) for x in integ) or 'none'}"
    psk_peers: set[str] = set()
    for header, kids in blocks(t, r"^tunnel-group \S+ ipsec-attributes"):
        if any("pre-shared-key" in k for k in kids):
            psk_peers.add(header.split()[1])
    maps_iface = dict(re.findall(r"^crypto map\s+(\S+)\s+interface\s+(\S+)", t, re.MULTILINE))
    entries: dict[tuple[str, str], dict[str, str]] = {}
    for mm in re.finditer(r"^crypto map\s+(\S+)\s+(\d+)\s+(.+)$", t, re.MULTILINE):
        entries.setdefault((mm.group(1), mm.group(2)), {})
        e = entries[(mm.group(1), mm.group(2))]
        rest = mm.group(3)
        for key, pat in (("acl", r"^match address\s+(\S+)"), ("peer", r"^set peer\s+(.+)$"),
                         ("ikev1", r"^set ikev1 transform-set\s+(.+)$"), ("ikev2", r"^set ikev2 ipsec-proposal\s+(.+)$"),
                         ("pfs", r"^set pfs\s*(\S*)"), ("life", r"^set security-association lifetime seconds\s+(\d+)")):
            mt = re.match(pat, rest)
            if mt:
                e[key] = mt.group(1).strip() or "group2"
    acl_by_name = {a.name: a for a in dev.acls}
    for (cmap, seq), e in entries.items():
        ike = "ikev2" if "ikev2" in e else "ikev1"
        p2names = e.get(ike, "").split()
        p2 = "/".join((props if ike == "ikev2" else tsets).get(x, x) for x in p2names) or "?"
        pfs = e.get("pfs")
        dh2 = f"dh{pfs.removeprefix('group')}" if pfs else "no-pfs"
        peer = (e.get("peer") or "").split()
        tun = m.VpnTunnel(name=f"{cmap} {seq}" + (f" ({peer[0]})" if peer else ""), kind="ipsec",
                          peer=", ".join(peer) or None, ike_version="IKEv2" if ike == "ikev2" else "IKEv1",
                          phase1="; ".join(p1[ike]) or None, phase2=f"{p2}, {dh2}, {e.get('life', '28800')}s",
                          psk_set=any(p in psk_peers for p in peer) if peer else None)
        acl = acl_by_name.get(e.get("acl", ""))
        if acl:
            for entry in acl.entries:
                ace = parse_ace(f"{acl.kind} {entry.action} {entry.text}", cfg)
                if ace:
                    for side, lst in (("src", tun.local_subnets), ("dst", tun.remote_subnets)):
                        for v in cfg.resolve_list(ace[side]):
                            if v not in lst:
                                lst.append(v)
        if cmap in maps_iface:
            tun.status = f"crypto map on {maps_iface[cmap]}"
        else:
            tun.status = "crypto map not applied"
        dev.vpn_tunnels.append(tun)
    # AnyConnect / remote access
    for _h, kids in blocks(t, r"^webvpn$"):
        en = [k.split()[1] for k in kids if k.startswith("enable ")]
        if en and any(k.startswith("anyconnect enable") for k in kids):
            pools = re.findall(r"^ip local pool\s+(\S+)\s+(\S+)", t, re.MULTILINE)
            dev.vpn_tunnels.append(m.VpnTunnel(name="AnyConnect", kind="ssl", peer="remote users",
                                               local_subnets=[f"{n} {r}" for n, r in pools],
                                               phase1=f"TLS/DTLS on {', '.join(en)}"))


def _ha(dev: m.Device, cfg: _Cfg, out: dict, ver: str) -> None:
    t = cfg.text
    fo = _text(out.get(CMD_FAILOVER))
    if not re.search(r"^failover\s*$", t, re.MULTILINE) and not re.search(r"^Failover On", fo, re.MULTILINE):
        return
    mode = "active-active" if re.search(r"^failover group \d", t, re.MULTILINE) else "active-passive"
    unit = first(r"^failover lan unit\s+(\S+)", t)
    d: dict[str, str] = {}
    lan = first(r"^failover lan interface\s+(.+)$", t)
    if lan:
        d["failover-link"] = lan
    st = first(r"^failover link\s+(.+)$", t)
    if st:
        d["state-link"] = st
    d["failover-key"] = "set" if re.search(r"^failover (?:ipsec pre-shared-)?key", t, re.MULTILINE) else "not set"
    h = m.HighAvailability(mode=mode, group=None)
    if fo:
        this = first(r"This host:\s*(\S+)\s*-\s*(.+?)\s*$", fo, group=2)
        this_role = first(r"This host:\s*(\S+)", fo)
        other = first(r"Other host:\s*(\S+)\s*-\s*(.+?)\s*$", fo, group=2)
        other_role = first(r"Other host:\s*(\S+)", fo)
        h.state = this.lower() if this else None
        h.members = [f"{dev.hostname} ({this_role}, {this})"] if this else []
        if other:
            h.members.append(f"mate ({other_role}, {other})")
            d["mate-state"] = other
        vers = re.search(r"^Version:\s*Ours\s+(\S+),\s*Mate\s+(\S+)", fo, re.MULTILINE)
        if vers:
            d["version"] = f"ours {vers.group(1)}, mate {vers.group(2)}"
        serial = re.search(r"^Serial Number:\s*Ours\s+(\S+),\s*Mate\s+(\S+)", fo, re.MULTILINE)
        if serial:
            d["mate-serial"] = serial.group(2)
        last = first(r"^Last Failover at:\s*(.+)$", fo)
        if last:
            d["last-failover"] = last
        mon = first(r"^Monitored Interfaces\s+(.+)$", fo)
        if mon:
            d["monitored-interfaces"] = mon
        # in sync when one unit is Active and the other Standby Ready, seen from either unit
        states = {(this or "").lower(), (other or "").lower()}
        ready = "active" in states and "standby ready" in states
        mismatch = vers is not None and vers.group(1) != vers.group(2)
        d["sync"] = "in-sync" if ready and not mismatch else "out-of-sync"
        failed = re.findall(r"Interface\s+(\S+)\s+\([^)]*\):\s+(Failed|No Link|Unknown)", fo)
        if failed:
            d["failed-interfaces"] = ", ".join(f"{a} {b}" for a, b in failed)
    else:
        h.members = [f"{dev.hostname} ({unit or 'unit ?'})"]
    if unit:
        d["configured-unit"] = unit
    h.details = d
    dev.ha = h


def _dhcp(dev: m.Device, cfg: _Cfg, out: dict, ver: str) -> None:
    t = cfg.text
    pools = re.findall(r"^dhcpd address\s+(\S+)\s+(\S+)", t, re.MULTILINE)
    enabled = set(re.findall(r"^dhcpd enable\s+(\S+)", t, re.MULTILINE))
    dns = " ".join(re.findall(r"^dhcpd dns\s+(.+)$", t, re.MULTILINE)).split()
    lease = first(r"^dhcpd lease\s+(\d+)", t) or "3600"
    rows = []
    by_zone = {i.zone: i for i in dev.interfaces if i.zone}
    for rng, ifc in pools:
        intf = by_zone.get(ifc)
        net = ""
        if intf and intf.ipv4:
            net = network_of(intf.ipv4[0].address)
        rows.append([ifc, net, rng, intf.ipv4[0].address.split("/")[0] if intf and intf.ipv4 else "",
                     ", ".join(dns), f"{lease}s", "", "enabled" if ifc in enabled else "disabled"])
    for mm in re.finditer(r"^dhcprelay server\s+(\S+)\s+(\S+)", t, re.MULTILINE):
        rows.append([mm.group(2), "", f"relay -> {mm.group(1)}", "", "", "", "", "relay"])
    if rows:
        dev.dhcp_scopes.append(m.Table(title="DHCP server scopes", columns=[
            "Interface", "Network", "Range", "Gateway", "DNS", "Lease", "Reservations", "Status"], rows=rows))


def _extras(dev: m.Device, cfg: _Cfg, out: dict, ver: str) -> None:
    t = cfg.text
    # interfaces/security levels
    rows = [[i.name, i.zone or "", i.extra.get("security-level", ""), ", ".join(a.address for a in i.ipv4),
             i.extra.get("standby-ip", "")] for i in dev.interfaces if i.zone]
    if rows:
        dev.sections.append(m.Section(id="asa-nameif", title="Interfaces, nameif and security levels", tables=[
            m.Table(columns=["Interface", "nameif", "Security level", "IP", "Standby IP"], rows=rows)]))
    srows = [[n, "object", v] for n, v in cfg.svc_objects.items()]
    srows += [[n, "object-group", ", ".join(v)] for n, v in cfg.svc_groups.items()]
    if srows:
        dev.sections.append(m.Section(id="asa-services", title="Service objects", tables=[
            m.Table(columns=["Name", "Type", "Definition"], rows=srows)]))
    insp = []
    for header, kids in blocks(t, r"^policy-map "):
        insp += [f"{header.split()[1]}: {k}" for k in kids if k.startswith("inspect ")]
    if insp:
        sp = re.findall(r"^service-policy\s+(.+)$", t, re.MULTILINE)
        dev.sections.append(m.Section(id="asa-mpf", title="Modular policy framework (inspections)",
                                      facts=[m.Fact(key="service-policy", value="; ".join(sp))],
                                      tables=[m.Table(columns=["Inspection"], rows=[[x] for x in insp])]))
    facts = []
    for key, pat in (("Threat detection", r"^(threat-detection basic-threat)"),
                     ("ICMP unreachable rate-limit", r"^icmp unreachable (.+)$"),
                     ("Logging enabled", r"^(logging enable)"), ("Logging trap level", r"^logging trap\s+(\S+)"),
                     ("Logging buffered level", r"^logging buffered\s+(\S+)"),
                     ("SSH key exchange", r"^ssh key-exchange\s+(.+)$"), ("SSL cipher", r"^ssl cipher\s+(.+)$"),
                     ("Same-security traffic", r"^same-security-traffic permit\s+(.+)$"),
                     ("ASDM image", r"^asdm image\s+(\S+)"), ("Boot image", r"^boot system\s+(\S+)")):
        vals = re.findall(pat, t, re.MULTILINE)
        if vals:
            facts.append(m.Fact(key=key, value="; ".join(vals)))
    if facts:
        dev.sections.append(m.Section(id="asa-system", title="ASA platform settings", facts=facts))
    nat_txt = _text(out.get(CMD_NAT))
    if nat_txt.strip():
        dev.sections.append(m.Section(id="asa-show-nat", title="NAT table with hit counts (show nat)",
                                      code=redact_text(nat_txt)))


register(CiscoAsaDriver())
