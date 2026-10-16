"""Fortinet FortiGate (FortiOS) driver.

Collection (strictly read-only):
- ssh: `show` (configuration), `get system status`, `get system ha status`,
  `get system interface physical` (netmiko device_type "fortinet").
- api: REST GET with a Bearer token: config backup, system status, HA peers, HA checksums.
- file: an exported configuration (`.conf`).

The FortiOS configuration is parsed into a small tree (`FNode`) that understands
`config <path>` / `edit "<name>"` / `set <key> <values...>` / `next` / `end`,
nested to any depth, quoted strings (also multi-line) and VDOM mode.
"""

from __future__ import annotations

import ipaddress
import json
import re
from collections.abc import Iterator
from typing import Any

from sextant import model as m
from sextant.drivers import register
from sextant.drivers._util import first, mask_to_prefix, mask_value, norm_action
from sextant.drivers.base import Credentials, Driver, RawCollection, Target
from sextant.redact import redact_text

CMD_CONFIG = "show"
CMD_STATUS = "get system status"
CMD_HA = "get system ha status"
CMD_PHYS = "get system interface physical"
SSH_COMMANDS = [CMD_CONFIG, CMD_STATUS, CMD_HA, CMD_PHYS]

API_BACKUP = "/api/v2/monitor/system/config/backup?scope=global"
API_STATUS = "/api/v2/monitor/system/status"
API_HA_PEER = "/api/v2/monitor/system/ha-peer"
API_HA_CHECKSUMS = "/api/v2/monitor/system/ha-checksums"
API_ENDPOINTS = [API_BACKUP, API_STATUS, API_HA_PEER, API_HA_CHECKSUMS]


# --------------------------------------------------------------------------- config tree


class FNode:
    """One `config` block or one `edit` entry of a FortiOS configuration."""

    __slots__ = ("configs", "entries", "settings")

    def __init__(self) -> None:
        self.settings: dict[str, list[str]] = {}
        self.entries: dict[str, FNode] = {}
        self.configs: dict[str, FNode] = {}

    def get(self, key: str, default: str | None = None) -> str | None:
        vals = self.settings.get(key)
        return " ".join(vals) if vals else default

    def vals(self, key: str) -> list[str]:
        return list(self.settings.get(key) or [])

    def on(self, key: str, default: bool = False) -> bool:
        v = self.get(key)
        return default if v is None else v.lower() == "enable"

    def sub(self, path: str) -> FNode:
        return self.configs.get(path) or FNode()

    def __bool__(self) -> bool:
        return bool(self.settings or self.entries or self.configs)


def _statements(text: str) -> Iterator[list[str]]:
    """Split FortiOS config into token lists, one per statement. Quoted strings may span lines."""
    tokens: list[str] = []
    buf: list[str] = []
    in_q = esc = quoted = False

    def flush() -> None:
        nonlocal buf, quoted
        if buf or quoted:
            tokens.append("".join(buf))
        buf, quoted = [], False

    for line in (text or "").splitlines():
        if not in_q and '"' not in line and "\\" not in line:
            if line.split():
                yield line.split()
            continue
        for ch in line:
            if in_q:
                if esc:
                    buf.append(ch)
                    esc = False
                elif ch == "\\":
                    esc = True
                elif ch == '"':
                    in_q = False
                else:
                    buf.append(ch)
            elif ch == '"':
                in_q = quoted = True
            elif ch in " \t\r":
                flush()
            else:
                buf.append(ch)
        if in_q:
            buf.append("\n")
            continue
        flush()
        if tokens:
            yield tokens
        tokens = []
    flush()
    if tokens:
        yield tokens


def parse_fortios(text: str) -> FNode:
    """Parse a FortiOS configuration into an FNode tree. Never raises on odd input."""
    root = FNode()
    stack: list[tuple[str, FNode]] = [("config", root)]
    for tok in _statements(text):
        kw = tok[0]
        if kw.startswith("#"):
            continue
        kind, cur = stack[-1]
        if kw == "config" and len(tok) > 1:
            node = cur.configs.setdefault(" ".join(tok[1:]), FNode())
            stack.append(("config", node))
        elif kw == "edit" and len(tok) > 1:
            if kind == "edit":  # tolerate a missing "next"
                stack.pop()
                cur = stack[-1][1]
            node = cur.entries.setdefault(tok[1], FNode())
            stack.append(("edit", node))
        elif kw == "next":
            if kind == "edit":
                stack.pop()
        elif kw == "end":
            while len(stack) > 1:
                k, _ = stack.pop()
                if k == "config":
                    break
        elif kw == "set" and len(tok) > 1:
            cur.settings[tok[1]] = tok[2:]
        elif kw == "append" and len(tok) > 2:
            cur.settings.setdefault(tok[1], []).extend(tok[2:])
    return root


class FortiConfig:
    """Lookup helper that hides VDOM mode (config global / config vdom)."""

    def __init__(self, root: FNode) -> None:
        self.root = root
        self.scopes: list[tuple[str | None, FNode]] = [(None, root)]
        if "global" in root.configs:
            self.scopes.append((None, root.configs["global"]))
        for name, vd in root.sub("vdom").entries.items():
            self.scopes.append((name, vd))
        self.multi_vdom = len(root.sub("vdom").entries) > 1

    def find(self, path: str) -> FNode:
        hits = [(vd, s.configs[path]) for vd, s in self.scopes if path in s.configs]
        if not hits:
            return FNode()
        if len(hits) == 1:
            return hits[0][1]
        merged = FNode()
        for vd, node in hits:
            merged.settings.update(node.settings)
            merged.configs.update(node.configs)
            for k, v in node.entries.items():
                key = k if k not in merged.entries else f"{k} ({vd})"
                merged.entries[key] = v
        return merged


# --------------------------------------------------------------------------- helpers


def _cidr(value: str | list[str] | None, host_ok: bool = True) -> str | None:
    """'10.0.0.1 255.255.255.0' or ['10.0.0.1','255.255.255.0'] or '10.0.0.0/24' -> CIDR."""
    if value is None:
        return None
    parts = value if isinstance(value, list) else value.split()
    if not parts:
        return None
    if len(parts) >= 2 and re.match(r"^\d+\.\d+\.\d+\.\d+$", parts[1]):
        return mask_to_prefix(parts[0], parts[1])
    return parts[0]


def _net(value: str | list[str] | None) -> str | None:
    c = _cidr(value)
    if not c:
        return None
    try:
        return str(ipaddress.IPv4Interface(c).network)
    except ValueError:
        return c


def _anyize(names: list[str]) -> list[str]:
    return ["any" if n.lower() in ("all", "any") else n for n in names]


def _svc(names: list[str]) -> list[str]:
    return ["any" if n.upper() in ("ALL",) else n for n in names]


def _text(raw: Any) -> str:
    if raw is None:
        return ""
    if isinstance(raw, (dict, list)):
        return json.dumps(raw)
    return str(raw)


def _json(raw: Any) -> dict[str, Any]:
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str) and raw.strip().startswith("{"):
        try:
            data = json.loads(raw)
            return data if isinstance(data, dict) else {}
        except ValueError:
            return {}
    return {}


# --------------------------------------------------------------------------- driver


class FortiGateDriver(Driver):
    id = "fortigate"
    label = "Fortinet FortiGate (FortiOS)"
    methods = ("ssh", "api", "file")

    # ---------------------------------------------------------------- collect
    def collect(self, target: Target, creds: Credentials) -> RawCollection:
        if target.method == "file" and target.file:
            from pathlib import Path

            return self.from_file(Path(target.file))
        if target.method == "api":
            return self._collect_api(target, creds)
        from sextant.drivers._ssh import run_commands

        return run_commands(target, creds, "fortinet", SSH_COMMANDS, self.id, timeout=180)

    def _collect_api(self, target: Target, creds: Credentials) -> RawCollection:
        import requests  # lazy

        raw = RawCollection(driver=self.id, target=target.name, method="api")
        host = target.host or target.name
        base = f"https://{host}:{target.port}" if target.port else f"https://{host}"
        headers = {"Authorization": f"Bearer {creds.api_token}", "Accept": "application/json"}
        with requests.Session() as s:
            for ep in API_ENDPOINTS:
                try:
                    r = s.get(base + ep, headers=headers, verify=target.verify_tls, timeout=60)  # GET only
                    r.raise_for_status()
                    if ep == API_BACKUP:
                        raw.outputs[ep] = r.text
                    else:
                        try:
                            raw.outputs[ep] = r.json()
                        except ValueError:
                            raw.outputs[ep] = r.text
                except Exception as exc:  # noqa: BLE001
                    raw.warnings.append(f"GET {ep}: {exc.__class__.__name__}: {exc}")
        return raw

    # ---------------------------------------------------------------- parse
    def parse(self, raw: RawCollection) -> m.Device:
        out = raw.outputs or {}
        warnings = list(raw.warnings)
        conf_text = _text(out.get("config") or out.get(CMD_CONFIG) or out.get(API_BACKUP)
                          or out.get("show full-configuration"))
        status_txt = _text(out.get(CMD_STATUS)) if not isinstance(out.get(CMD_STATUS), dict) else ""
        api_status = _json(out.get(API_STATUS))
        if not conf_text.strip():
            warnings.append("no FortiOS configuration in collection")
        if raw.method != "file" and not (status_txt or api_status):
            warnings.append("no system status output")

        try:
            root = parse_fortios(conf_text)
        except Exception as exc:  # noqa: BLE001 - parser must never raise
            warnings.append(f"config parse error: {exc}")
            root = FNode()
        cfg = FortiConfig(root)

        dev = m.Device(hostname=raw.target, role=m.DeviceRole.firewall, vendor="Fortinet",
                       platform=self.id, os_name="FortiOS", collection_method=raw.method, source=raw.target)
        steps = [self._identity, self._management, self._interfaces, self._routing, self._objects,
                 self._policies, self._vpn, self._ha, self._dhcp, self._extras]
        for step in steps:
            try:
                step(dev, cfg, conf_text, out, status_txt, api_status)
            except Exception as exc:  # noqa: BLE001 - one bad block must not lose the device
                warnings.append(f"{step.__name__.lstrip('_')}: {exc.__class__.__name__}: {exc}")
        dev.collection_warnings = warnings
        try:
            dev.raw_config = redact_text(_redact_communities(conf_text)) if conf_text.strip() else None
        except Exception:  # noqa: BLE001
            dev.raw_config = None
        return dev

    # ---------------------------------------------------------------- identity
    def _identity(self, dev: m.Device, cfg: FortiConfig, conf: str, out: dict, status: str,
                  api: dict) -> None:
        g = cfg.find("system global")
        hdr = first(r"^#config-version=([^:\s]+)", conf)  # FG100F-7.4.4-FW-build2662-240514
        hostname = g.get("hostname") or first(r"^Hostname:\s*(\S+)", status) \
            or (api.get("results") or {}).get("hostname")
        if hostname:
            dev.hostname = hostname
        ver = first(r"^Version:\s*\S+\s+v?([\d.]+),build(\d+)", status)
        build = first(r"^Version:\s*\S+\s+v?[\d.]+,build(\d+)", status)
        if not ver and api.get("version"):
            ver, build = str(api["version"]).lstrip("v"), str(api.get("build") or "") or None
        if not ver and hdr:
            mm = re.match(r"^\w+-([\d.]+)-FW-build(\d+)", hdr)
            if mm:
                ver, build = mm.group(1), mm.group(2)
        if ver:
            dev.os_version = f"{ver} build {build}" if build else ver
        model = first(r"^Version:\s*(FortiGate-[\w-]+|FortiWiFi-[\w-]+|FortiGate-VM\w*)", status)
        if not model and api.get("results"):
            r = api["results"]
            if r.get("model_name") and r.get("model_number"):
                model = f"{r['model_name']}-{r['model_number']}"
        if not model and hdr:
            mm = re.match(r"^F([GW])(\w+?)-", hdr)
            if mm:
                model = ("FortiGate-" if mm.group(1) == "G" else "FortiWiFi-") + mm.group(2)
        dev.model = model
        dev.serial = first(r"^Serial-Number:\s*(\S+)", status) or api.get("serial")
        up = first(r"^Cluster uptime:\s*(.+)$", status)
        if up:
            dev.uptime = up
        if status:
            for key in ("Virus-DB", "IPS-DB", "Operation Mode", "Virtual domain configuration",
                        "Current HA mode", "Branch point", "BIOS version", "Log hard disk",
                        "Firmware Signature", "FIPS-CC mode"):
                v = first(rf"^{re.escape(key)}:\s*(.+)$", status)
                if v:
                    dev.hardware.append(m.Fact(key=key, value=v))
        snmp = cfg.find("system snmp sysinfo")
        dev.location = snmp.get("location")
        dev.contact = snmp.get("contact-info")

    # ---------------------------------------------------------------- management
    def _management(self, dev: m.Device, cfg: FortiConfig, conf: str, out: dict, status: str,
                    api: dict) -> None:
        mg = dev.management
        g = cfg.find("system global")
        access: set[str] = set()
        for intf in cfg.find("system interface").entries.values():
            access.update(a.lower() for a in intf.vals("allowaccess"))
        mg.ssh = "ssh" in access
        mg.telnet = "telnet" in access
        mg.http = "http" in access
        mg.https = "https" in access
        mg.ssh_version = "2" if mg.ssh else None
        t = g.get("admintimeout")
        if t and t.isdigit():
            mg.console_timeout_min = int(t)
        mg.timezone = g.get("timezone")
        if g.on("pre-login-banner") or g.on("post-login-banner"):
            msg = cfg.find("system replacemsg admin pre_admin-disclaimer-text")
            mg.banner = msg.get("buffer") or "pre-login disclaimer enabled"
        # NTP
        ntp = cfg.find("system ntp")
        if ntp.get("ntpsync", "enable") == "enable":
            if (ntp.get("type") or "fortiguard") == "custom":
                mg.ntp_servers = [e.get("server") for e in ntp.sub("ntpserver").entries.values() if e.get("server")]
            elif ntp:
                mg.ntp_servers = ["FortiGuard NTP"]
        # DNS
        dns = cfg.find("system dns")
        mg.dns_servers = [x for x in (dns.get("primary"), dns.get("secondary")) if x and x != "0.0.0.0"]
        mg.domain = dns.get("domain") or next(
            (e.get("domain") for e in dns.sub("domain").entries.values() if e.get("domain")), None)
        # syslog / FortiAnalyzer
        for path in ("log syslogd setting", "log syslogd2 setting", "log syslogd3 setting", "log syslogd4 setting"):
            s = cfg.find(path)
            if s.get("status") == "enable" and s.get("server"):
                port = s.get("port")
                mg.syslog_servers.append(s.get("server") + (f":{port}" if port else ""))
        for path in ("log fortianalyzer setting", "log fortianalyzer2 setting"):
            s = cfg.find(path)
            if s.get("status") == "enable" and s.get("server"):
                mg.syslog_servers.append(f"{s.get('server')} (FortiAnalyzer)")
        if cfg.find("log fortiguard setting").get("status") == "enable":
            mg.syslog_servers.append("FortiCloud / FortiAnalyzer Cloud")
        # SNMP
        sn = mg.snmp
        sysinfo = cfg.find("system snmp sysinfo")
        sn.location, sn.contact = sysinfo.get("location"), sysinfo.get("contact-info")
        versions: set[str] = set()
        for c in cfg.find("system snmp community").entries.values():
            if c.get("status") == "disable":
                continue
            name = mask_value(c.get("name") or "")
            sn.communities.append(f"{name} (RO)")
            if c.get("query-v1-status", "enable") == "enable":
                versions.add("v1")
            if c.get("query-v2c-status", "enable") == "enable":
                versions.add("v2c")
            for h in c.sub("hosts").entries.values():
                ip = _cidr(h.vals("ip"))
                if ip and ip.removesuffix("/32") not in sn.trap_hosts:
                    sn.trap_hosts.append(ip.removesuffix("/32"))
        for name, u in cfg.find("system snmp user").entries.items():
            if u.get("status") == "disable":
                continue
            versions.add("v3")
            lvl = u.get("security-level") or "no-auth-no-priv"
            sn.v3_users.append(f"{name} ({lvl}, {(u.get('auth-proto') or 'sha').upper()}/"
                               f"{(u.get('priv-proto') or 'aes').upper()})")
            for ip in u.vals("notify-hosts"):
                if ip not in sn.trap_hosts:
                    sn.trap_hosts.append(ip)
        sn.versions = sorted(versions)
        sn.enabled = bool(sn.communities or sn.v3_users) and sysinfo.get("status", "disable") == "enable"
        # AAA
        aaa = mg.aaa
        for e in cfg.find("user radius").entries.values():
            aaa.radius_servers += [e.get(k) for k in ("server", "secondary-server") if e.get(k)]
        for e in cfg.find("user tacacs+").entries.values():
            aaa.tacacs_servers += [e.get(k) for k in ("server", "secondary-server") if e.get(k)]
        for e in cfg.find("user ldap").entries.values():
            aaa.ldap_servers += [e.get(k) for k in ("server", "secondary-server") if e.get(k)]
        # admins
        hosts: list[str] = []
        for name, a in cfg.find("system admin").entries.items():
            auth: list[str] = []
            if a.get("remote-auth") == "enable":
                auth.append(f"remote ({a.get('remote-group') or 'any group'})")
            elif a.get("wildcard") == "enable":
                auth.append("remote (wildcard)")
            elif a.get("password") or a.get("peer-auth") != "enable":
                auth.append("password")
            if a.get("ssh-public-key1") or a.get("ssh-public-key2"):
                auth.append("ssh-key")
            if a.get("two-factor") and a.get("two-factor") != "disable":
                auth.append(f"2FA {a.get('two-factor')}")
            mg.users.append(m.LocalUser(name=name, privilege=a.get("accprofile"), auth=", ".join(auth) or None))
            for i in range(1, 11):
                th = _cidr(a.vals(f"trusthost{i}"))
                if th and th not in ("0.0.0.0/0",) and th not in hosts:
                    hosts.append(th)
        for name, a in cfg.find("system api-user").entries.items():
            mg.users.append(m.LocalUser(name=name, privilege=a.get("accprofile"), auth="api-token"))
            for th in a.sub("trusthost").entries.values():
                c = _cidr(th.vals("ipv4-trusthost"))
                if c and c != "0.0.0.0/0" and c not in hosts:
                    hosts.append(c)
        mg.allowed_mgmt_hosts = hosts
        mg.password_encryption = True  # FortiOS always stores admin passwords hashed (ENC)
        mg.backup_target = "FortiManager " + cfg.find("system central-management").get("fmg", "") \
            if cfg.find("system central-management").get("type") == "fortimanager" else None

    # ---------------------------------------------------------------- interfaces
    def _interfaces(self, dev: m.Device, cfg: FortiConfig, conf: str, out: dict, status: str,
                    api: dict) -> None:
        zones: dict[str, str] = {}
        for zname, z in cfg.find("system zone").entries.items():
            for i in z.vals("interface"):
                zones[i] = zname
        phys = _parse_physical(_text(out.get(CMD_PHYS)))
        lag_of: dict[str, str] = {}
        intfs = cfg.find("system interface").entries
        for name, e in intfs.items():
            if e.get("type") in ("aggregate", "redundant"):
                for mbr in e.vals("member"):
                    lag_of[mbr] = name
        mgmt_ip: str | None = None
        for name, e in intfs.items():
            typ = e.get("type") or ("vlan" if e.get("vlanid") else "physical")  # `show` omits default "vlan"
            kind = {"physical": "physical", "aggregate": "lag", "redundant": "lag", "vlan": "vlan",
                    "tunnel": "tunnel", "loopback": "loopback"}.get(typ, "virtual")
            if typ == "physical" and name.startswith(("mgmt", "ha")):
                kind = "mgmt"
            intf = m.Interface(name=name, kind=kind, description=e.get("description") or e.get("alias"),
                               enabled=e.get("status") != "down", zone=zones.get(name),
                               mode=m.PortMode.routed)
            ip = e.vals("ip")
            mode = e.get("mode") or "static"
            if ip and ip[0] != "0.0.0.0":
                intf.ipv4.append(m.IPAddress(address=_cidr(ip) or ip[0]))
            for sec in e.sub("secondaryip").entries.values():
                c = _cidr(sec.vals("ip"))
                if c:
                    intf.ipv4.append(m.IPAddress(address=c, secondary=True))
            v6 = e.sub("ipv6").get("ip6-address")
            if v6 and not v6.startswith("::/"):
                intf.ipv6.append(v6)
            if e.get("vlanid"):
                try:
                    intf.access_vlan = int(e.get("vlanid") or "")
                except ValueError:
                    pass
            if kind == "lag":
                intf.lag_members = e.vals("member")
                intf.lag_protocol = "lacp" if (e.get("lacp-mode") or "active") != "static" else "static"
            if name in lag_of:
                intf.lag = lag_of[name]
                intf.mode = m.PortMode.lag_member
            if e.get("mtu-override") == "enable" and (e.get("mtu") or "").isdigit():
                intf.mtu = int(e.get("mtu") or 0)
            intf.speed = e.get("speed")
            intf.mac = e.get("macaddr")
            extra = {"vdom": e.get("vdom"), "role": e.get("role"), "addressing": mode,
                     "allowaccess": " ".join(e.vals("allowaccess")) or None, "parent": e.get("interface"),
                     "alias": e.get("alias")}
            if e.get("remote-ip"):
                extra["remote-ip"] = e.get("remote-ip")
            if e.get("dhcp-relay-service") == "enable":
                extra["dhcp-relay"] = " ".join(e.vals("dhcp-relay-ip"))
            intf.extra = {k: v for k, v in extra.items() if v}
            p = phys.get(name)
            if p:
                intf.oper_up = p.get("status") == "up"
                if p.get("speed"):
                    intf.speed = p["speed"]
                if mode != "static" and p.get("ip") and not intf.ipv4:
                    intf.ipv4.append(m.IPAddress(address=_cidr(p["ip"]) or p["ip"]))
            dev.interfaces.append(intf)
            if typ == "vlan" and intf.access_vlan is not None:
                dev.vlans.append(m.Vlan(id=intf.access_vlan, name=name,
                                        svi_ipv4=[a.address for a in intf.ipv4],
                                        dhcp_helpers=e.vals("dhcp-relay-ip"),
                                        ports=[e.get("interface")] if e.get("interface") else []))
            acc = {a.lower() for a in e.vals("allowaccess")}
            dedicated = kind == "mgmt" and name.startswith("mgmt")
            admin_on = bool({"https", "ssh"} & acc) and e.get("role") != "wan"
            if intf.ipv4 and not mgmt_ip and (dedicated or admin_on):
                mgmt_ip = intf.ipv4[0].address.split("/")[0]
        dev.mgmt_ip = mgmt_ip
        dev.vlans.sort(key=lambda v: v.id)

    # ---------------------------------------------------------------- routing
    def _routing(self, dev: m.Device, cfg: FortiConfig, conf: str, out: dict, status: str,
                 api: dict) -> None:
        addr = cfg.find("firewall address").entries
        groups = cfg.find("firewall addrgrp").entries

        def resolve(name: str, depth: int = 0) -> list[str]:
            if name in addr:
                net = _net(addr[name].vals("subnet"))
                return [net] if net else [name]
            if name in groups and depth < 4:
                return [x for mem in groups[name].vals("member") for x in resolve(mem, depth + 1)]
            return [name]

        for r in cfg.find("router static").entries.values():
            if r.get("status") == "disable":
                continue
            prefix = _net(r.vals("dst"))
            if not prefix and r.get("dstaddr"):
                nets = resolve(r.get("dstaddr"))
                prefix = f"{', '.join(nets)} ({r.get('dstaddr')})" if nets != [r.get("dstaddr")] else r.get("dstaddr")
            prefix = prefix or "0.0.0.0/0"
            nh = r.get("gateway")
            dev.routes.append(m.Route(
                prefix=prefix, next_hop=None if nh in (None, "0.0.0.0") else nh,
                interface="Null (blackhole)" if r.get("blackhole") == "enable" else r.get("device"),
                protocol="static", distance=int(r.get("distance") or 10),
                description=r.get("comment") or (f"SD-WAN zone {r.get('sdwan-zone')}" if r.get("sdwan-zone") else None),
            ))
        # WAN ports in DHCP/PPPoE mode install a default route from the provider (defaultgw enable by default)
        for name, e in cfg.find("system interface").entries.items():
            if e.get("mode") in ("dhcp", "pppoe") and e.get("defaultgw") != "disable" and e.get("status") != "down":
                dev.routes.append(m.Route(
                    prefix="0.0.0.0/0", next_hop=f"from {e.get('mode').upper()}", interface=name, protocol=e.get("mode"),
                    distance=int(e.get("distance") or 5),
                    description=f"Default gateway learned via {e.get('mode').upper()} on {name}"))
        ospf = cfg.find("router ospf")
        if ospf and (ospf.get("router-id") or ospf.sub("network").entries or ospf.sub("area").entries):
            nets = [f"{_net(n.vals('prefix'))} area {n.get('area') or '0.0.0.0'}"
                    for n in ospf.sub("network").entries.values() if n.vals("prefix")]
            dev.routing_protocols.append(m.RoutingProtocol(
                protocol="ospf", router_id=ospf.get("router-id"), networks=nets,
                details={k: v for k, v in {
                    "areas": ", ".join(ospf.sub("area").entries),
                    "interfaces": ", ".join(i.get("interface") or k for k, i in ospf.sub("ospf-interface").entries.items()),
                    "default-information-originate": ospf.get("default-information-originate"),
                    "redistribute": ", ".join(k for k, rd in ospf.configs.items()
                                              if k.startswith("redistribute") and rd.get("status") == "enable"),
                }.items() if v}))
        bgp = cfg.find("router bgp")
        if bgp and (bgp.get("as") or bgp.sub("neighbor").entries):
            neigh = [f"{ip} (AS {n.get('remote-as') or '?'})" + (f" {n.get('description')}" if n.get("description") else "")
                     for ip, n in bgp.sub("neighbor").entries.items()]
            nets = [_net(n.vals("prefix")) or "" for n in bgp.sub("network").entries.values()]
            dev.routing_protocols.append(m.RoutingProtocol(
                protocol="bgp", asn=bgp.get("as"), router_id=bgp.get("router-id"), networks=[n for n in nets if n],
                neighbors=neigh,
                details={k: v for k, v in {
                    "neighbor-groups": ", ".join(bgp.sub("neighbor-group").entries),
                    "redistribute": ", ".join(k.split(" ", 1)[1].strip('"') for k, rd in bgp.configs.items()
                                              if k.startswith("redistribute") and rd.get("status") == "enable"),
                }.items() if v}))

    # ---------------------------------------------------------------- objects
    def _objects(self, dev: m.Device, cfg: FortiConfig, conf: str, out: dict, status: str,
                 api: dict) -> None:
        for name, a in cfg.find("firewall address").entries.items():
            typ = a.get("type") or "ipmask"
            if typ == "ipmask":
                c = _cidr(a.vals("subnet")) or "0.0.0.0/0"
                kind = "host" if c.endswith("/32") else "subnet"
                value = c.removesuffix("/32") if kind == "host" else (_net(c) or c)
            elif typ == "iprange":
                kind, value = "range", f"{a.get('start-ip')}-{a.get('end-ip')}"
            elif typ in ("fqdn", "wildcard-fqdn"):
                kind, value = "fqdn", a.get("fqdn") or a.get("wildcard-fqdn") or ""
            elif typ == "geography":
                kind, value = "geo", a.get("country") or ""
            elif typ == "interface-subnet":
                kind, value = "subnet", f"{_cidr(a.vals('subnet'))} (interface {a.get('interface')})"
            else:
                kind, value = typ, a.get("subnet") or a.get("wildcard") or a.get("macaddr") or typ
            dev.address_objects.append(m.AddressObject(name=name, kind=kind, value=value, comment=a.get("comment")))
        for name, a in cfg.find("firewall address6").entries.items():
            dev.address_objects.append(m.AddressObject(name=name, kind="subnet" if a.get("ip6") else (a.get("type") or "ipv6"),
                                                       value=a.get("ip6") or a.get("fqdn") or "", comment=a.get("comment")))
        for path in ("firewall addrgrp", "firewall addrgrp6"):
            for name, g in cfg.find(path).entries.items():
                dev.address_objects.append(m.AddressObject(name=name, kind="group", value=", ".join(g.vals("member")),
                                                           comment=g.get("comment")))
        # VIPs -> NAT (dnat/static) + address objects
        for name, v in cfg.find("firewall vip").entries.items():
            mapped = " ".join(v.vals("mappedip")) or (v.get("mapped-addr") or "")
            ext = v.get("extip") or (v.get("extaddr") or "")
            if v.get("portforward") == "enable":
                proto = v.get("protocol") or "tcp"
                orig = f"{ext}:{v.get('extport')}/{proto}"
                trans = f"{mapped}:{v.get('mappedport') or v.get('extport')}"
                kind = "dnat"
            else:
                orig, trans, kind = ext, mapped, "static"
            dev.nat_rules.append(m.NatRule(id=f"vip:{name}", kind="vip" if kind == "dnat" else "static",
                                           original=orig, translated=trans, interface=v.get("extintf"),
                                           comment=v.get("comment"), enabled=v.get("status") != "disable"))
            dev.address_objects.append(m.AddressObject(name=name, kind="vip", value=f"{orig} -> {trans}",
                                                       comment=v.get("comment")))
        for name, g in cfg.find("firewall vipgrp").entries.items():
            dev.address_objects.append(m.AddressObject(name=name, kind="group", value=", ".join(g.vals("member")),
                                                       comment=g.get("comments")))
        # central SNAT (when central-nat is enabled)
        for sid, s in cfg.find("firewall central-snat-map").entries.items():
            pool = " ".join(s.vals("nat-ippool"))
            dev.nat_rules.append(m.NatRule(
                id=f"central-snat:{sid}", kind="snat",
                original=f"{', '.join(_anyize(s.vals('orig-addr')))} -> {', '.join(_anyize(s.vals('dst-addr')))}",
                translated=pool if s.get("nat") != "disable" and pool else
                ("egress interface address" if s.get("nat") != "disable" else "no NAT"),
                interface=" ".join(s.vals("dstintf")) or None, comment=s.get("comments"),
                enabled=s.get("status") != "disable"))

    # ---------------------------------------------------------------- policies
    def _policies(self, dev: m.Device, cfg: FortiConfig, conf: str, out: dict, status: str,
                  api: dict) -> None:
        central_nat = cfg.find("system settings").get("central-nat") == "enable"
        for pid, p in cfg.find("firewall policy").entries.items():
            utm = p.get("utm-status") == "enable"
            profiles: list[str] = []
            if p.get("profile-type") == "group" and p.get("profile-group"):
                profiles.append(f"group:{p.get('profile-group')}")
            for key, label in (("av-profile", "av"), ("webfilter-profile", "webfilter"), ("ips-sensor", "ips"),
                               ("application-list", "app"), ("dnsfilter-profile", "dns"),
                               ("file-filter-profile", "file"), ("emailfilter-profile", "email"),
                               ("dlp-profile", "dlp"), ("waf-profile", "waf"), ("ssl-ssh-profile", "ssl")):
                if p.get(key) and (utm or key == "ssl-ssh-profile"):
                    profiles.append(f"{label}:{p.get(key)}")
            if profiles == [f"ssl:{p.get('ssl-ssh-profile')}"] and not utm:
                profiles = []  # inspection profile without UTM has no effect
            dst = _anyize(p.vals("dstaddr") + p.vals("dstaddr6"))
            if p.get("internet-service") == "enable":
                dst = [f"ISDB:{x}" for x in p.vals("internet-service-name") + p.vals("internet-service-id")]
            src = _anyize(p.vals("srcaddr") + p.vals("srcaddr6"))
            if p.get("internet-service-src") == "enable":
                src = [f"ISDB:{x}" for x in p.vals("internet-service-src-name")]
            # FortiOS default is "utm": only security events are logged, so a rule without profiles logs nothing
            log = p.get("logtraffic") or "utm"
            logged = True if log == "all" else False if log == "disable" else (True if profiles else False)
            action = norm_action(p.get("action") or "deny")
            nat = p.get("nat") == "enable"
            rule = m.FirewallRule(
                id=pid, name=p.get("name"), enabled=p.get("status") != "disable", action=action,
                src_zones=p.vals("srcintf"), dst_zones=p.vals("dstintf"),
                src_addresses=src, dst_addresses=dst,
                services=_svc(p.vals("service")) or (["application-default"] if p.vals("application") else []),
                applications=p.vals("application"),
                users=p.vals("users") + [f"group:{g}" for g in p.vals("groups")] + p.vals("fsso-groups"),
                nat=None if central_nat else nat, log=logged, security_profiles=profiles,
                schedule=p.get("schedule") or "always", comment=p.get("comments"))
            dev.firewall_rules.append(rule)
            if nat and action == "allow" and not central_nat:
                pool = " ".join(p.vals("poolname")) if p.get("ippool") == "enable" else None
                dev.nat_rules.append(m.NatRule(
                    id=f"policy:{pid}", kind="snat" if pool else "pat",
                    original=f"{', '.join(src)} -> {', '.join(dst)} ({', '.join(rule.src_zones)} -> "
                             f"{', '.join(rule.dst_zones)})",
                    translated=f"IP pool {pool}" if pool else "egress interface address",
                    interface=", ".join(rule.dst_zones) or None, comment=p.get("name"),
                    enabled=rule.enabled))

    # ---------------------------------------------------------------- vpn
    def _vpn(self, dev: m.Device, cfg: FortiConfig, conf: str, out: dict, status: str,
             api: dict) -> None:
        p2_by_p1: dict[str, list[tuple[str, FNode]]] = {}
        for path in ("vpn ipsec phase2-interface", "vpn ipsec phase2"):
            for name, p2 in cfg.find(path).entries.items():
                p2_by_p1.setdefault(p2.get("phase1name") or "", []).append((name, p2))
        addr = {a.name: a.value for a in dev.address_objects}

        def subnet(p2: FNode, side: str) -> str | None:
            t = p2.get(f"{side}-addr-type") or "subnet"
            if t == "name":
                n = p2.get(f"{side}-name") or ""
                return f"{n} ({addr[n]})" if n in addr else n
            if t == "range":
                return f"{p2.get(f'{side}-start-ip')}-{p2.get(f'{side}-end-ip')}"
            if t == "ip":
                return p2.get(f"{side}-start-ip")
            return _net(p2.vals(f"{side}-subnet")) or "0.0.0.0/0"

        for path in ("vpn ipsec phase1-interface", "vpn ipsec phase1"):
            for name, p1 in cfg.find(path).entries.items():
                prop = p1.vals("proposal") or ["default"]
                dh = p1.vals("dhgrp") or ["14", "5"]
                phase1 = f"{'/'.join(prop)}, dh{'/dh'.join(dh)}, {p1.get('keylife') or '86400'}s"
                t = m.VpnTunnel(name=name, kind="ipsec", ike_version=f"IKEv{p1.get('ike-version') or '1'}",
                                phase1=phase1)
                if (p1.get("type") or "static") == "dynamic":
                    t.peer = "dial-up (dynamic)"
                elif p1.get("type") == "ddns":
                    t.peer = p1.get("remotegw-ddns")
                else:
                    t.peer = p1.get("remote-gw")
                auth = p1.get("authmethod") or "psk"
                t.psk_set = bool(p1.get("psksecret")) if auth == "psk" else False
                p2s: list[str] = []
                for _n2, p2 in p2_by_p1.get(name, []):
                    pp = p2.vals("proposal") or ["default"]
                    pfs = p2.get("pfs") or "enable"
                    dh2 = "dh" + "/dh".join(p2.vals("dhgrp") or ["14", "5"]) if pfs == "enable" else "no-pfs"
                    s = f"{'/'.join(pp)}, {dh2}, {p2.get('keylifeseconds') or '43200'}s"
                    if s not in p2s:
                        p2s.append(s)
                    for side, lst in (("src", t.local_subnets), ("dst", t.remote_subnets)):
                        sn = subnet(p2, side)
                        if sn and sn not in lst:
                            lst.append(sn)
                t.phase2 = "; ".join(p2s) or None
                dev.vpn_tunnels.append(t)
        ssl = cfg.find("vpn ssl settings")
        if ssl.get("source-interface") and ssl.get("status", "enable") != "disable":
            dev.vpn_tunnels.append(m.VpnTunnel(
                name="SSL VPN", kind="ssl", peer="remote users",
                local_subnets=ssl.vals("tunnel-ip-pools"),
                phase1=f"TLS on {', '.join(ssl.vals('source-interface'))}:{ssl.get('port') or '443'}"))

    # ---------------------------------------------------------------- HA
    def _ha(self, dev: m.Device, cfg: FortiConfig, conf: str, out: dict, status: str,
            api: dict) -> None:
        ha = cfg.find("system ha")
        hatxt = _text(out.get(CMD_HA))
        mode = ha.get("mode") or "standalone"
        peers = out.get(API_HA_PEER)
        if mode == "standalone" and "Mode: HA" not in hatxt:
            return
        h = m.HighAvailability(mode={"a-p": "active-passive", "a-a": "active-active"}.get(mode, mode),
                               group=ha.get("group-name"))
        d: dict[str, str] = {}
        for k in ("group-id", "priority", "override", "session-pickup", "monitor", "hbdev", "ha-mgmt-status"):
            if ha.get(k):
                d[k] = ha.get(k) or ""
        cur = first(r"^Current HA mode:\s*\S+,\s*(\S+)", status)
        if hatxt:
            d["health"] = first(r"^HA Health Status:\s*(.+)$", hatxt) or ""
            members = re.findall(r"^(Primary|Secondary|Master|Slave)\s*:\s*([^,]+?)\s*,\s*(\S+?),", hatxt, re.MULTILINE)
            for role, name, serial in members:
                role = {"Master": "Primary", "Slave": "Secondary"}.get(role, role)
                h.members.append(f"{name} ({serial}, {role.lower()})")
                if name == dev.hostname or serial == dev.serial:
                    cur = cur or role.lower()
            sync = re.findall(r"^\s*(\S+)\(updated [^)]*\):\s*(in-sync|out-of-sync)", hatxt, re.MULTILINE)
            if sync:
                d["sync"] = "in-sync" if all(s == "in-sync" for _, s in sync) else "out-of-sync"
                for serial, s in sync:
                    d[f"sync {serial}"] = s
            up = first(r"^Cluster Uptime:\s*(.+)$", hatxt)
            if up:
                d["cluster-uptime"] = up
        if isinstance(peers, dict):
            for p in peers.get("results") or []:
                label = f"{p.get('hostname')} ({p.get('serial_no')}, {'primary' if p.get('primary') else 'secondary'})"
                if label not in h.members:
                    h.members.append(label)
        cks = out.get(API_HA_CHECKSUMS)
        if isinstance(cks, dict) and "sync" not in d:
            sums = [(r.get("serial_no"), (r.get("checksum") or {}).get("all")) for r in cks.get("results") or []]
            if len(sums) > 1:
                d["sync"] = "in-sync" if len({s for _, s in sums}) == 1 else "out-of-sync"
        h.state = {"master": "primary", "slave": "secondary"}.get(cur or "", cur) or None
        h.details = {k: v for k, v in d.items() if v}
        dev.ha = h

    # ---------------------------------------------------------------- DHCP
    def _dhcp(self, dev: m.Device, cfg: FortiConfig, conf: str, out: dict, status: str,
              api: dict) -> None:
        rows: list[list[str]] = []
        for sid, s in cfg.find("system dhcp server").entries.items():
            ranges = [f"{r.get('start-ip')}-{r.get('end-ip')}" for r in s.sub("ip-range").entries.values()]
            gw = s.get("default-gateway") or ""
            net = _net([gw, s.get("netmask") or ""]) if gw and s.get("netmask") else ""
            dns = ", ".join(x for x in (s.get("dns-server1"), s.get("dns-server2")) if x) or \
                (s.get("dns-service") or "default")
            lease = s.get("lease-time") or "604800"
            rows.append([s.get("interface") or sid, net, ", ".join(ranges), gw, dns, f"{lease}s",
                         str(len(s.sub("reserved-address").entries)),
                         "disabled" if s.get("status") == "disable" else "enabled"])
        if rows:
            dev.dhcp_scopes.append(m.Table(title="DHCP server scopes",
                                           columns=["Interface", "Network", "Range", "Gateway", "DNS", "Lease",
                                                    "Reservations", "Status"], rows=rows))

    # ---------------------------------------------------------------- vendor extras
    def _extras(self, dev: m.Device, cfg: FortiConfig, conf: str, out: dict, status: str,
                api: dict) -> None:
        g = cfg.find("system global")
        facts = [m.Fact(key=k, value=g.get(k) or "") for k in (
            "admin-sport", "admin-ssh-port", "admintimeout", "admin-https-redirect", "admin-lockout-threshold",
            "strong-crypto", "ssl-min-proto-version", "admin-https-ssl-versions", "gui-theme", "fgd-alert-subscription")
            if g.get(k)]
        st = cfg.find("system settings")
        for k in ("opmode", "central-nat", "inspection-mode", "gui-multiple-interface-policy"):
            if st.get(k):
                facts.append(m.Fact(key=f"settings {k}", value=st.get(k) or ""))
        if cfg.multi_vdom:
            facts.append(m.Fact(key="VDOMs", value=", ".join(cfg.root.sub("vdom").entries)))
        if facts:
            dev.sections.append(m.Section(id="fortigate-system", title="FortiOS system settings", facts=facts))
        # zones
        zrows = [[n, ", ".join(z.vals("interface")), z.get("intrazone") or "deny", z.get("description") or ""]
                 for n, z in cfg.find("system zone").entries.items()]
        if zrows:
            dev.sections.append(m.Section(id="fortigate-zones", title="Zones", tables=[
                m.Table(columns=["Zone", "Interfaces", "Intra-zone traffic", "Description"], rows=zrows)]))
        # VIPs
        vrows = []
        for n, v in cfg.find("firewall vip").entries.items():
            vrows.append([n, v.get("extintf") or "any", v.get("extip") or "", " ".join(v.vals("mappedip")),
                          (v.get("protocol") or "tcp") if v.get("portforward") == "enable" else "all",
                          v.get("extport") or "", v.get("mappedport") or "", v.get("comment") or ""])
        if vrows:
            dev.sections.append(m.Section(id="fortigate-vips", title="Virtual IPs (destination NAT)",
                                          summary_relevant=True, tables=[m.Table(
                                              columns=["Name", "Ext. interface", "External IP", "Mapped IP",
                                                       "Protocol", "Ext. port", "Mapped port", "Comment"],
                                              rows=vrows)]))
        # IP pools
        prow = [[n, p.get("type") or "overload", p.get("startip") or "", p.get("endip") or "",
                 p.get("comments") or ""] for n, p in cfg.find("firewall ippool").entries.items()]
        if prow:
            dev.sections.append(m.Section(id="fortigate-ippools", title="IP pools (source NAT)", tables=[
                m.Table(columns=["Name", "Type", "Start", "End", "Comment"], rows=prow)]))
        # services
        srows = []
        for n, s in cfg.find("firewall service custom").entries.items():
            ports = []
            for k, label in (("tcp-portrange", "tcp"), ("udp-portrange", "udp"), ("sctp-portrange", "sctp")):
                if s.vals(k):
                    ports.append(f"{label}/{' '.join(s.vals(k))}")
            if not ports:
                proto = s.get("protocol") or "TCP/UDP/SCTP"
                ports.append(proto + (f" {s.get('icmptype')}" if s.get("icmptype") else "")
                             + (f" {s.get('protocol-number')}" if s.get("protocol-number") else ""))
            srows.append([n, s.get("category") or "", ", ".join(ports), s.get("comment") or ""])
        for n, s in cfg.find("firewall service group").entries.items():
            srows.append([n, "group", ", ".join(s.vals("member")), s.get("comment") or ""])
        if srows:
            dev.sections.append(m.Section(id="fortigate-services", title="Service objects", tables=[
                m.Table(columns=["Name", "Category / type", "Protocol / ports / members", "Comment"], rows=srows)]))
        # security profiles
        used: dict[str, int] = {}
        for r in dev.firewall_rules:
            for sp in r.security_profiles:
                used[sp] = used.get(sp, 0) + 1
        prof_rows = []
        for path, label in (("antivirus profile", "av"), ("webfilter profile", "webfilter"), ("ips sensor", "ips"),
                            ("application list", "app"), ("dnsfilter profile", "dns"),
                            ("file-filter profile", "file"), ("firewall ssl-ssh-profile", "ssl"),
                            ("emailfilter profile", "email"), ("firewall profile-group", "group")):
            for n, p in cfg.find(path).entries.items():
                prof_rows.append([label, n, p.get("comment") or "", str(used.get(f"{label}:{n}", 0))])
        if prof_rows:
            dev.sections.append(m.Section(id="fortigate-security-profiles", title="Security profiles", tables=[
                m.Table(columns=["Type", "Name", "Comment", "Used by policies"], rows=prof_rows)]))
        # SSL VPN
        ssl = cfg.find("vpn ssl settings")
        if ssl:
            facts = [m.Fact(key=k, value=" ".join(ssl.vals(k))) for k in (
                "status", "servercert", "port", "source-interface", "source-address", "tunnel-ip-pools",
                "default-portal", "ssl-min-proto-ver", "idle-timeout", "auth-timeout") if ssl.vals(k)]
            rules = [[rid, ", ".join(r.vals("groups") + r.vals("users")), r.get("portal") or "",
                      ", ".join(r.vals("source-interface"))] for rid, r in ssl.sub("authentication-rule").entries.items()]
            portals = [[n, p.get("tunnel-mode") or "disable", p.get("web-mode") or "disable",
                        p.get("split-tunneling") or "enable", " ".join(p.vals("split-tunneling-routing-address")),
                        " ".join(p.vals("ip-pools"))] for n, p in cfg.find("vpn ssl web portal").entries.items()]
            tables = []
            if rules:
                tables.append(m.Table(title="Authentication rules", columns=["#", "Users / groups", "Portal",
                                                                             "Source interface"], rows=rules))
            if portals:
                tables.append(m.Table(title="Portals", columns=["Portal", "Tunnel mode", "Web mode", "Split tunnel",
                                                                "Split networks", "IP pools"], rows=portals))
            dev.sections.append(m.Section(id="fortigate-sslvpn", title="SSL VPN", facts=facts, tables=tables))


_COMMUNITY_BLOCK = re.compile(r"^(\s*)config system snmp community\s*$.*?^\1end\s*$", re.MULTILINE | re.DOTALL)


def _redact_communities(text: str) -> str:
    """FortiOS stores SNMP communities as `set name "x"`, which generic redaction cannot know."""

    def block(mt: re.Match[str]) -> str:
        return re.sub(r'(\bset name\s+)("?)(?!(?:public|private)"?\s*$)[^"\n]+("?)', r"\1\2<redacted>\3",
                      mt.group(0), flags=re.IGNORECASE | re.MULTILINE)

    return _COMMUNITY_BLOCK.sub(block, text)


def _parse_physical(text: str) -> dict[str, dict[str, str]]:
    """`get system interface physical` -> {name: {status, ip, speed, mode}}."""
    res: dict[str, dict[str, str]] = {}
    cur: dict[str, str] | None = None
    for line in (text or "").splitlines():
        mm = re.match(r"^\s*==\[([^\]]+)\]\s*$", line)
        if mm:
            cur = res.setdefault(mm.group(1), {})
            continue
        if cur is None:
            continue
        kv = re.match(r"^\s*(mode|ip|status|speed):\s*(.+?)\s*$", line)
        if kv:
            key, val = kv.group(1), kv.group(2)
            if key == "speed":
                val = val.split(" (")[0]
            cur[key] = val
    return res


register(FortiGateDriver())
