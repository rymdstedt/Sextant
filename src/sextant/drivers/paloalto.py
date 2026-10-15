"""Palo Alto Networks PAN-OS driver (XML API or offline running-config.xml import).

Collection is strictly read-only: XML API GET `type=config&action=show` (running config)
and `type=op` with `show system info` / `show high-availability state`. The API key is
sent in the X-PAN-KEY header so it never ends up in URLs or proxy logs.
"""

from __future__ import annotations

from typing import Any
from xml.etree.ElementTree import Element

from sextant import model as m
from sextant.drivers import register
from sextant.drivers._util import mask_value, norm_action, parse_xml_safe, redact_xml
from sextant.drivers.base import Credentials, Driver, RawCollection, Target

OP_SYSTEM_INFO = "<show><system><info></info></system></show>"
OP_HA_STATE = "<show><high-availability><state></state></high-availability></show>"
OUT_CONFIG = "config"


# --------------------------------------------------------------------------- xml helpers


def _t(el: Element | None, path: str | None = None, default: str | None = None) -> str | None:
    if el is None:
        return default
    node = el.find(path) if path else el
    if node is None or node.text is None:
        return default
    return node.text.strip() or default


def _members(el: Element | None, path: str) -> list[str]:
    """<x><member>a</member><member>b</member></x> or <x>a</x> -> ['a', 'b']."""
    if el is None:
        return []
    node = el.find(path)
    if node is None:
        return []
    mem = [(x.text or "").strip() for x in node.findall("member")]
    if mem:
        return [x for x in mem if x]
    return [node.text.strip()] if node.text and node.text.strip() else []


def _entries(el: Element | None, path: str) -> list[Element]:
    if el is None:
        return []
    node = el.find(path)
    return [] if node is None else node.findall("entry")


def _yes(el: Element | None, path: str, default: bool = False) -> bool:
    v = _t(el, path)
    return default if v is None else v.lower() == "yes"


def _root(text: Any) -> Element | None:
    if text is None:
        return None
    if isinstance(text, bytes):
        text = text.decode("utf-8", "replace")
    s = str(text).strip()
    if not s:
        return None
    return parse_xml_safe(s)


def _result(el: Element | None) -> Element | None:
    """Unwrap <response><result>...</result></response>."""
    if el is None:
        return None
    if el.tag == "response":
        r = el.find("result")
        return r if r is not None else el
    return el


def _anyize(xs: list[str]) -> list[str]:
    return ["any" if x.lower() == "any" else x for x in xs]


# --------------------------------------------------------------------------- driver


class PaloAltoDriver(Driver):
    id = "paloalto"
    label = "Palo Alto Networks (PAN-OS)"
    methods = ("api", "file")

    def collect(self, target: Target, creds: Credentials) -> RawCollection:
        if target.method == "file" and target.file:
            from pathlib import Path

            return self.from_file(Path(target.file))
        import requests  # lazy

        raw = RawCollection(driver=self.id, target=target.name, method="api")
        host = target.host or target.name
        url = f"https://{host}:{target.port}/api/" if target.port else f"https://{host}/api/"
        headers = {"X-PAN-KEY": creds.api_token or ""}
        calls = [(OUT_CONFIG, {"type": "config", "action": "show"}),
                 (OP_SYSTEM_INFO, {"type": "op", "cmd": OP_SYSTEM_INFO}),
                 (OP_HA_STATE, {"type": "op", "cmd": OP_HA_STATE})]
        with requests.Session() as s:
            for key, params in calls:
                try:
                    r = s.get(url, params=params, headers=headers, verify=target.verify_tls, timeout=120)  # GET only
                    r.raise_for_status()
                    if 'status="error"' in r.text[:300]:
                        raw.warnings.append(f"{key}: API error: {r.text[:200]}")
                    raw.outputs[key] = r.text
                except Exception as exc:  # noqa: BLE001
                    raw.warnings.append(f"{key}: {exc.__class__.__name__}: {exc}")
        return raw

    # ---------------------------------------------------------------- parse
    def parse(self, raw: RawCollection) -> m.Device:
        out = raw.outputs or {}
        warnings = list(raw.warnings)
        dev = m.Device(hostname=raw.target, role=m.DeviceRole.firewall, vendor="Palo Alto Networks",
                       platform=self.id, os_name="PAN-OS", collection_method=raw.method, source=raw.target)
        cfg_text = out.get(OUT_CONFIG) or out.get("running-config") or ""
        config: Element | None = None
        try:
            r = _result(_root(cfg_text))
            if r is not None:
                config = r if r.tag == "config" else r.find(".//config")
        except ValueError as exc:
            warnings.append(f"config: {exc}")
        if config is None:
            warnings.append("no PAN-OS configuration in collection")
        sysinfo = ha_state = None
        for key, label in ((OP_SYSTEM_INFO, "system info"), (OP_HA_STATE, "HA state")):
            if not out.get(key):
                if raw.method != "file":
                    warnings.append(f"no {label} output")
                continue
            try:
                res = _result(_root(out.get(key)))
                if key == OP_SYSTEM_INFO:
                    sysinfo = res.find("system") if res is not None and res.find("system") is not None else res
                else:
                    ha_state = res
            except ValueError as exc:
                warnings.append(f"{label}: {exc}")

        ctx = _Ctx(config)
        for step in (_identity, _management, _interfaces, _routing, _objects, _rules, _vpn, _ha, _dhcp, _extras):
            try:
                step(dev, ctx, sysinfo, ha_state)
            except Exception as exc:  # noqa: BLE001 - one bad block must not lose the device
                warnings.append(f"{step.__name__.lstrip('_')}: {exc.__class__.__name__}: {exc}")
        dev.collection_warnings = warnings
        try:
            dev.raw_config = redact_xml(str(cfg_text)) if cfg_text else None
        except Exception:  # noqa: BLE001
            dev.raw_config = None
        return dev


class _Ctx:
    """Shortcuts into the PAN-OS config tree (firewall, single device entry)."""

    def __init__(self, config: Element | None) -> None:
        self.config = config
        empty = Element("empty")
        dev = config.find("devices/entry") if config is not None else None
        self.device = dev if dev is not None else empty
        self.network = self.device.find("network") if self.device.find("network") is not None else empty
        self.system = self.device.find("deviceconfig/system")
        if self.system is None:
            self.system = empty
        self.shared = config.find("shared") if config is not None and config.find("shared") is not None else empty
        self.mgt = config.find("mgt-config") if config is not None and config.find("mgt-config") is not None else empty
        self.vsys = _entries(self.device, "vsys")

    def objects(self, path: str) -> list[tuple[str | None, Element]]:
        """Shared + per-vsys objects as (vsys-or-None, entry)."""
        res: list[tuple[str | None, Element]] = [(None, e) for e in _entries(self.shared, path)]
        for v in self.vsys:
            res += [(v.get("name"), e) for e in _entries(v, path)]
        return res


# --------------------------------------------------------------------------- steps


def _identity(dev: m.Device, ctx: _Ctx, si: Element | None, ha: Element | None) -> None:
    dev.hostname = _t(si, "hostname") or _t(ctx.system, "hostname") or dev.hostname
    dev.model = _t(si, "model")
    dev.serial = _t(si, "serial")
    dev.os_version = _t(si, "sw-version") or (ctx.config.get("detail-version") if ctx.config is not None else None)
    dev.uptime = _t(si, "uptime")
    dev.mgmt_ip = _t(si, "ip-address") or _t(ctx.system, "ip-address")
    for key in ("family", "app-version", "threat-version", "av-version", "wildfire-version", "url-filtering-version",
                "global-protect-client-package-version", "multi-vsys", "operational-mode", "vm-license",
                "device-certificate-status", "mac-address"):
        v = _t(si, key)
        if v:
            dev.hardware.append(m.Fact(key=key, value=v))
    dev.location = _t(ctx.system, "snmp-setting/snmp-system/location")
    dev.contact = _t(ctx.system, "snmp-setting/snmp-system/contact")


def _mgmt_profiles(ctx: _Ctx) -> dict[str, Element]:
    return {e.get("name") or "": e for e in _entries(ctx.network, "profiles/interface-management-profile")}


def _management(dev: m.Device, ctx: _Ctx, si: Element | None, ha: Element | None) -> None:
    mg, sysel = dev.management, ctx.system
    svc = sysel.find("service")
    # management port defaults: HTTPS + SSH on, HTTP + Telnet off
    mg.https = not _yes(svc, "disable-https")
    mg.ssh = not _yes(svc, "disable-ssh")
    mg.http = _t(svc, "disable-http") == "no"
    mg.telnet = _t(svc, "disable-telnet") == "no"
    # data-plane interface management profiles that are actually bound to an interface
    profiles = _mgmt_profiles(ctx)
    used = {_t(x) for x in ctx.network.iter("interface-management-profile") if x.text}
    for name in used:
        p = profiles.get(name or "")
        if p is None:
            continue
        mg.http = mg.http or _yes(p, "http")
        mg.https = mg.https or _yes(p, "https")
        mg.ssh = mg.ssh or _yes(p, "ssh")
        mg.telnet = mg.telnet or _yes(p, "telnet")
    mg.ssh_version = "2" if mg.ssh else None
    mg.allowed_mgmt_hosts = [e.get("name") or "" for e in _entries(sysel, "permitted-ip")]
    mg.banner = _t(sysel, "login-banner")
    mg.timezone = _t(sysel, "timezone")
    mg.domain = _t(sysel, "domain")
    mg.dns_servers = [x for x in (_t(sysel, "dns-setting/servers/primary"), _t(sysel, "dns-setting/servers/secondary"))
                      if x]
    mg.ntp_servers = [x for x in (_t(sysel, "ntp-servers/primary-ntp-server/ntp-server-address"),
                                  _t(sysel, "ntp-servers/secondary-ntp-server/ntp-server-address")) if x]
    to = _t(ctx.device, "deviceconfig/setting/management/idle-timeout")
    if to and to.isdigit():
        mg.console_timeout_min = int(to)
    # syslog server profiles (shared + vsys)
    for _vs, prof in ctx.objects("log-settings/syslog"):
        for srv in _entries(prof, "server"):
            host = _t(srv, "server")
            if host:
                port = _t(srv, "port") or "514"
                mg.syslog_servers.append(f"{host}:{port}/{(_t(srv, 'transport') or 'UDP').lower()} "
                                         f"({prof.get('name')})")
    # SNMP
    sn = mg.snmp
    snmp = sysel.find("snmp-setting")
    sn.location = _t(snmp, "snmp-system/location")
    sn.contact = _t(snmp, "snmp-system/contact")
    ver = snmp.find("access-setting/version") if snmp is not None else None
    if ver is not None:
        if ver.find("v2c") is not None:
            sn.versions.append("v2c")
            c = _t(ver, "v2c/snmp-community-string")
            if c:
                sn.communities.append(f"{mask_value(c)} (RO)")
        if ver.find("v3") is not None:
            sn.versions.append("v3")
            for u in _entries(ver, "v3/users"):
                sn.v3_users.append(f"{u.get('name')} (authPriv, view {_t(u, 'view') or '-'})")
    sn.enabled = bool(sn.versions)
    for _vs, prof in ctx.objects("log-settings/snmptrap"):
        for v in ("v2c", "v3"):
            for srv in _entries(prof, f"version/{v}/server"):
                mgr = _t(srv, "manager")
                if mgr:
                    sn.trap_hosts.append(f"{mgr} ({v})")
                    if v == "v2c" and _t(srv, "community"):
                        sn.communities.append(f"{mask_value(_t(srv, 'community'))} (trap)")
    # AAA server profiles
    aaa = mg.aaa
    for kind, lst, field in (("radius", aaa.radius_servers, "ip-address"), ("tacplus", aaa.tacacs_servers, "address"),
                             ("ldap", aaa.ldap_servers, "address")):
        for _vs, prof in ctx.objects(f"server-profile/{kind}"):
            for srv in _entries(prof, "server"):
                addr = _t(srv, field) or _t(srv, "address") or _t(srv, "ip-address")
                if addr:
                    lst.append(f"{addr} ({prof.get('name')})")
    auth = _t(ctx.mgt, "authentication-profile") or _t(sysel, "authentication-profile")
    if auth:
        aaa.login_methods.append(f"admin authentication profile: {auth}")
    # admins
    for u in _entries(ctx.mgt, "users"):
        rb = u.find("permissions/role-based")
        priv = None
        if rb is not None:
            for child in rb:
                if child.tag == "custom":
                    priv = f"custom: {_t(child, 'profile')}"
                elif child.tag in ("vsysadmin", "vsysreader"):
                    priv = f"{child.tag}: {', '.join(e.get('name') or '' for e in child.findall('entry'))}"
                elif (child.text or "").strip().lower() == "yes" or len(child) == 0:
                    priv = child.tag
        methods = []
        if _t(u, "authentication-profile"):
            methods.append(f"auth-profile {_t(u, 'authentication-profile')}")
        if u.find("phash") is not None or u.find("password") is not None:
            methods.append("password")
        if u.find("public-key") is not None:
            methods.append("ssh-key")
        if u.find("client-certificate-only") is not None and _yes(u, "client-certificate-only"):
            methods.append("client-certificate")
        mg.users.append(m.LocalUser(name=u.get("name") or "?", privilege=priv, auth=", ".join(methods) or None))
    mg.password_encryption = True  # PAN-OS stores admin passwords as hashes (phash)
    panorama = _t(sysel, "panorama/local-panorama/panorama-server") or _t(sysel, "panorama-server")
    if panorama:
        mg.backup_target = f"Panorama {panorama}"


def _zones(ctx: _Ctx) -> dict[str, str]:
    z: dict[str, str] = {}
    for v in ctx.vsys:
        for e in _entries(v, "zone"):
            net = e.find("network")
            if net is None:
                continue
            for child in net:
                for mem in child.findall("member"):
                    if mem.text:
                        z[mem.text.strip()] = e.get("name") or ""
    return z


def _l3(intf: m.Interface, el: Element | None, profiles: dict[str, Element]) -> None:
    if el is None:
        return
    for e in _entries(el, "ip"):
        intf.ipv4.append(m.IPAddress(address=e.get("name") or "", secondary=bool(intf.ipv4)))
    if el.find("dhcp-client") is not None:
        intf.extra["addressing"] = "dhcp"
    for e in _entries(el, "ipv6/address"):
        intf.ipv6.append(e.get("name") or "")
    mp = _t(el, "interface-management-profile")
    if mp:
        intf.extra["mgmt-profile"] = mp
        p = profiles.get(mp)
        if p is not None:
            svcs = [s for s in ("https", "http", "ssh", "telnet", "ping", "snmp", "response-pages") if _yes(p, s)]
            intf.extra["allowaccess"] = " ".join(svcs)
    mtu = _t(el, "mtu")
    if mtu and mtu.isdigit():
        intf.mtu = int(mtu)
    if _t(el, "comment"):
        intf.description = _t(el, "comment")


def _interfaces(dev: m.Device, ctx: _Ctx, si: Element | None, ha: Element | None) -> None:
    zones = _zones(ctx)
    profiles = _mgmt_profiles(ctx)
    vr_of: dict[str, str] = {}
    for vr in _entries(ctx.network, "virtual-router"):
        for i in _members(vr, "interface"):
            vr_of[i] = vr.get("name") or ""
    result: list[m.Interface] = []
    lags: dict[str, list[str]] = {}

    def add(name: str, kind: str, el: Element | None, l3: Element | None = None, **kw: Any) -> m.Interface:
        intf = m.Interface(name=name, kind=kind, zone=zones.get(name), vrf=vr_of.get(name),
                           description=_t(el, "comment"), **kw)
        _l3(intf, l3, profiles)
        if _t(el, "link-state") == "down":
            intf.enabled = False
        if _t(el, "link-speed") and _t(el, "link-speed") != "auto":
            intf.speed = _t(el, "link-speed")
        result.append(intf)
        return intf

    def add_units(parent: str, l3: Element | None, kind: str = "vlan") -> None:
        for u in _entries(l3, "units"):
            intf = add(u.get("name") or "", kind, u, u)
            tag = _t(u, "tag")
            if tag and tag.isdigit():
                intf.access_vlan = int(tag)
                intf.mode = m.PortMode.routed
                dev.vlans.append(m.Vlan(id=int(tag), name=u.get("name"), svi_ipv4=[a.address for a in intf.ipv4],
                                        ports=[parent]))
            intf.extra["parent"] = parent

    for e in _entries(ctx.network, "interface/ethernet"):
        name = e.get("name") or ""
        if e.find("layer3") is not None:
            intf = add(name, "physical", e, e.find("layer3"), mode=m.PortMode.routed)
            add_units(name, e.find("layer3"))
        elif e.find("layer2") is not None:
            intf = add(name, "physical", e, None, mode=m.PortMode.access)
            add_units(name, e.find("layer2"))
        elif e.find("virtual-wire") is not None:
            intf = add(name, "physical", e, None)
            intf.extra["mode"] = "virtual-wire"
        elif _t(e, "aggregate-group"):
            intf = add(name, "physical", e, None, mode=m.PortMode.lag_member, lag=_t(e, "aggregate-group"))
            lags.setdefault(_t(e, "aggregate-group") or "", []).append(name)
        elif e.find("ha") is not None:
            intf = add(name, "physical", e, None)
            intf.extra["mode"] = "ha"
        elif e.find("tap") is not None:
            intf = add(name, "physical", e, None)
            intf.extra["mode"] = "tap"
        else:
            add(name, "physical", e, None)
    for e in _entries(ctx.network, "interface/aggregate-ethernet"):
        name = e.get("name") or ""
        l3 = e.find("layer3")
        intf = add(name, "lag", e, l3, mode=m.PortMode.routed if l3 is not None else m.PortMode.unknown)
        intf.lag_members = lags.get(name, [])
        if l3 is not None and l3.find("lacp") is not None:
            intf.lag_protocol = "lacp" if _yes(l3, "lacp/enable") else "static"
        add_units(name, l3 if l3 is not None else e.find("layer2"))
    for kind, path in (("vlan", "interface/vlan"), ("loopback", "interface/loopback"), ("tunnel", "interface/tunnel")):
        base = ctx.network.find(path)
        if base is None:
            continue
        for u in _entries(base, "units"):
            intf = add(u.get("name") or "", kind, u, u, mode=m.PortMode.routed)
            if kind == "vlan" and _t(u, "tag"):
                intf.access_vlan = int(_t(u, "tag") or 0)
    dev.interfaces = result
    dev.vlans.sort(key=lambda v: v.id)
    dev.vrfs = [vr.get("name") or "" for vr in _entries(ctx.network, "virtual-router")]


def _routing(dev: m.Device, ctx: _Ctx, si: Element | None, ha: Element | None) -> None:
    for vr in _entries(ctx.network, "virtual-router"):
        vname = vr.get("name") or "default"
        for r in _entries(vr, "routing-table/ip/static-route"):
            nh = r.find("nexthop")
            hop = None
            if nh is not None:
                hop = _t(nh, "ip-address") or _t(nh, "next-vr") or _t(nh, "fqdn")
                if nh.find("discard") is not None:
                    hop = "discard"
            metric = _t(r, "admin-dist") or _t(r, "metric")
            dev.routes.append(m.Route(prefix=_t(r, "destination") or "?", next_hop=hop, interface=_t(r, "interface"),
                                      protocol="static", distance=int(metric) if metric and metric.isdigit() else None,
                                      vrf=vname, description=r.get("name")))
        proto = vr.find("protocol")
        if proto is None:
            continue
        ospf = proto.find("ospf")
        if ospf is not None and _yes(ospf, "enable"):
            nets, ifs = [], []
            for a in _entries(ospf, "area"):
                nets.append(f"area {a.get('name')}")
                ifs += [f"{i.get('name')} (area {a.get('name')})" for i in _entries(a, "interface")]
            dev.routing_protocols.append(m.RoutingProtocol(protocol="ospf", process_id=vname,
                                                           router_id=_t(ospf, "router-id"), networks=nets,
                                                           details={"interfaces": ", ".join(ifs)} if ifs else {}))
        bgp = proto.find("bgp")
        if bgp is not None and _yes(bgp, "enable"):
            neigh = []
            for g in _entries(bgp, "peer-group"):
                for p in _entries(g, "peer"):
                    neigh.append(f"{_t(p, 'peer-address/ip') or p.get('name')} (AS {_t(p, 'peer-as') or '?'}, "
                                 f"{p.get('name')})")
            dev.routing_protocols.append(m.RoutingProtocol(protocol="bgp", process_id=vname, asn=_t(bgp, "local-as"),
                                                           router_id=_t(bgp, "router-id"), neighbors=neigh))


def _objects(dev: m.Device, ctx: _Ctx, si: Element | None, ha: Element | None) -> None:
    for _vs, e in ctx.objects("address"):
        name = e.get("name") or ""
        if _t(e, "ip-netmask"):
            v = _t(e, "ip-netmask") or ""
            kind = "host" if "/" not in v or v.endswith("/32") else "subnet"
            value = v.removesuffix("/32")
        elif _t(e, "ip-range"):
            kind, value = "range", _t(e, "ip-range") or ""
        elif _t(e, "fqdn"):
            kind, value = "fqdn", _t(e, "fqdn") or ""
        elif _t(e, "ip-wildcard"):
            kind, value = "wildcard", _t(e, "ip-wildcard") or ""
        else:
            kind, value = "other", ""
        dev.address_objects.append(m.AddressObject(name=name, kind=kind, value=value, comment=_t(e, "description")))
    for _vs, e in ctx.objects("address-group"):
        if e.find("dynamic") is not None:
            value = f"dynamic: {_t(e, 'dynamic/filter')}"
        else:
            value = ", ".join(_members(e, "static"))
        dev.address_objects.append(m.AddressObject(name=e.get("name") or "", kind="group", value=value,
                                                   comment=_t(e, "description")))
    for _vs, e in ctx.objects("region"):
        dev.address_objects.append(m.AddressObject(name=e.get("name") or "", kind="geo",
                                                   value=", ".join(x.get("name") or "" for x in _entries(e, "address"))))


def _rule_profiles(e: Element) -> list[str]:
    ps = e.find("profile-setting")
    if ps is None:
        return []
    out = [f"group:{g}" for g in _members(ps, "group")]
    prof = ps.find("profiles")
    if prof is not None:
        for child in prof:
            out += [f"{child.tag}:{x}" for x in _members(prof, child.tag)]
    return out


def _rules(dev: m.Device, ctx: _Ctx, si: Element | None, ha: Element | None) -> None:
    multi = len(ctx.vsys) > 1
    nat_rules_present = False
    for v in ctx.vsys:
        prefix = f"{v.get('name')}/" if multi else ""
        for idx, e in enumerate(_entries(v, "rulebase/security/rules"), 1):
            log_end = _t(e, "log-end")
            log = (log_end or "yes") == "yes" or _yes(e, "log-start")
            target = e.find("target")
            comment = _t(e, "description")
            dev.firewall_rules.append(m.FirewallRule(
                id=f"{prefix}{idx}", name=e.get("name"), enabled=not _yes(e, "disabled"),
                action=norm_action(_t(e, "action") or "allow"),
                src_zones=_anyize(_members(e, "from")), dst_zones=_anyize(_members(e, "to")),
                src_addresses=(["!"] if _yes(e, "negate-source") else []) + _anyize(_members(e, "source")),
                dst_addresses=(["!"] if _yes(e, "negate-destination") else []) + _anyize(_members(e, "destination")),
                services=_anyize(_members(e, "service")), applications=_anyize(_members(e, "application")),
                users=[u for u in _members(e, "source-user") if u.lower() != "any"],
                log=log, security_profiles=_rule_profiles(e), schedule=_t(e, "schedule"),
                comment=comment if target is None else (comment or "") + " [device target set]"))
        for idx, e in enumerate(_entries(v, "rulebase/nat/rules"), 1):
            nat_rules_present = True
            src = ", ".join(_anyize(_members(e, "source")))
            dst = ", ".join(_anyize(_members(e, "destination")))
            svc = _t(e, "service") or "any"
            st, dt = e.find("source-translation"), e.find("destination-translation")
            parts, kind = [], "snat"
            if st is not None:
                dip = st.find("dynamic-ip-and-port")
                if dip is not None:
                    kind = "pat"
                    ia = _t(dip, "interface-address/interface")
                    parts.append(f"src -> {ia} interface address" if ia else
                                 f"src -> {', '.join(_members(dip, 'translated-address'))}")
                elif st.find("static-ip") is not None:
                    kind = "static"
                    parts.append(f"src -> {_t(st, 'static-ip/translated-address')}"
                                 + (" (bi-directional)" if _yes(st, "static-ip/bi-directional") else ""))
                elif st.find("dynamic-ip") is not None:
                    parts.append(f"src -> {', '.join(_members(st.find('dynamic-ip'), 'translated-address'))}")
            if dt is not None:
                kind = "dnat" if st is None else kind
                port = _t(dt, "translated-port")
                parts.append(f"dst -> {_t(dt, 'translated-address')}" + (f":{port}" if port else ""))
            dyn = e.find("dynamic-destination-translation")
            if dyn is not None:
                kind = "dnat"
                parts.append(f"dst -> {_t(dyn, 'translated-address')} (dynamic)")
            orig = (f"{', '.join(_members(e, 'from'))} -> {', '.join(_members(e, 'to'))}: {src} -> {dst}"
                    + (f" svc {svc}" if svc != "any" else ""))
            if not parts:
                kind = "no-nat"
            dev.nat_rules.append(m.NatRule(id=f"{prefix}{idx}", kind=kind, original=orig,
                                           translated="; ".join(parts) or "no translation",
                                           interface=_t(e, "to-interface"),
                                           comment=f"{e.get('name')}" + (f": {_t(e, 'description')}"
                                                                         if _t(e, "description") else ""),
                                           enabled=not _yes(e, "disabled")))
    if not nat_rules_present:
        for r in dev.firewall_rules:
            r.nat = False  # no NAT rulebase at all; otherwise NAT is a separate rulebase (nat stays None)


def _fmt_lifetime(el: Element | None) -> str:
    if el is None:
        return "?"
    for unit, mul in (("seconds", 1), ("minutes", 60), ("hours", 3600), ("days", 86400)):
        v = _t(el, unit)
        if v and v.isdigit():
            return f"{int(v) * mul}s"
    return "?"


def _vpn(dev: m.Device, ctx: _Ctx, si: Element | None, ha: Element | None) -> None:
    ike_prof = {e.get("name"): e for e in _entries(ctx.network, "ike/crypto-profiles/ike-crypto-profiles")}
    ips_prof = {e.get("name"): e for e in _entries(ctx.network, "ike/crypto-profiles/ipsec-crypto-profiles")}

    def p1(name: str | None) -> str | None:
        e = ike_prof.get(name)
        if e is None:
            return f"profile {name}" if name else None
        dh = "/".join(x.replace("group", "dh") for x in _members(e, "dh-group"))
        return f"{'/'.join(_members(e, 'encryption'))}-{'/'.join(_members(e, 'hash'))}, {dh}, " \
               f"{_fmt_lifetime(e.find('lifetime'))}"

    def p2(name: str | None) -> str | None:
        e = ips_prof.get(name)
        if e is None:
            return f"profile {name}" if name else None
        proto = "esp" if e.find("esp") is not None else "ah"
        enc = "/".join(_members(e, f"{proto}/encryption"))
        auth = "/".join(_members(e, f"{proto}/authentication"))
        dh = (_t(e, "dh-group") or "no-pfs").replace("group", "dh")
        return f"{enc}-{auth}, {dh}, {_fmt_lifetime(e.find('lifetime'))}"

    gws = {e.get("name"): e for e in _entries(ctx.network, "ike/gateway")}
    used_gws: set[str] = set()
    for t in _entries(ctx.network, "tunnel/ipsec"):
        ak = t.find("auto-key")
        gw_names = [x.get("name") for x in _entries(ak, "ike-gateway")] if ak is not None else []
        gw = gws.get(gw_names[0]) if gw_names else None
        used_gws.update(n for n in gw_names if n)
        tun = m.VpnTunnel(name=t.get("name") or "?", kind="ipsec")
        if gw is not None:
            ver = _t(gw, "protocol/version") or "ikev1"
            tun.ike_version = {"ikev1": "IKEv1", "ikev2": "IKEv2", "ikev2-preferred": "IKEv2 (preferred)"}.get(ver, ver)
            prof = _t(gw, "protocol/ikev2/ike-crypto-profile") if "ikev2" in ver else \
                _t(gw, "protocol/ikev1/ike-crypto-profile")
            tun.phase1 = p1(prof or "default")
            tun.peer = _t(gw, "peer-address/ip") or _t(gw, "peer-address/fqdn") or \
                ("dynamic" if gw.find("peer-address/dynamic") is not None else None)
            tun.psk_set = gw.find("authentication/pre-shared-key") is not None
        if ak is not None:
            tun.phase2 = p2(_t(ak, "ipsec-crypto-profile") or "default")
            for pid in _entries(ak, "proxy-id"):
                if _t(pid, "local") and _t(pid, "local") not in tun.local_subnets:
                    tun.local_subnets.append(_t(pid, "local") or "")
                if _t(pid, "remote") and _t(pid, "remote") not in tun.remote_subnets:
                    tun.remote_subnets.append(_t(pid, "remote") or "")
        if _yes(t, "disabled"):
            tun.status = "disabled"
        dev.vpn_tunnels.append(tun)
    for name, gw in gws.items():
        if name not in used_gws:  # gateway without a tunnel (e.g. GlobalProtect / unused)
            dev.vpn_tunnels.append(m.VpnTunnel(name=name or "?", kind="ipsec", peer=_t(gw, "peer-address/ip"),
                                               status="no tunnel bound",
                                               psk_set=gw.find("authentication/pre-shared-key") is not None))
    # GlobalProtect gateways (configured in vsys)
    for v in ctx.vsys:
        for gp in _entries(v, "global-protect/global-protect-gateway"):
            pools: list[str] = []
            for cfg in _entries(gp, "remote-user-tunnel-configs"):
                pools += _members(cfg, "ip-pool")
            dev.vpn_tunnels.append(m.VpnTunnel(name=gp.get("name") or "GlobalProtect", kind="ssl",
                                               peer="remote users", local_subnets=pools,
                                               phase1=f"GlobalProtect on {_t(gp, 'local-address/interface') or '?'}"))


def _ha(dev: m.Device, ctx: _Ctx, si: Element | None, ha: Element | None) -> None:
    hac = ctx.device.find("deviceconfig/high-availability")
    enabled = _yes(hac, "enabled")
    op_enabled = _t(ha, "enabled") == "yes"
    if not enabled and not op_enabled:
        return
    mode_el = hac.find("group/mode") if hac is not None else None
    mode = "active-passive"
    if mode_el is not None and mode_el.find("active-active") is not None:
        mode = "active-active"
    g = ha.find("group") if ha is not None else None
    if _t(g, "mode"):
        mode = (_t(g, "mode") or mode).lower()
    h = m.HighAvailability(mode=mode, group=_t(hac, "group/group-id"))
    d: dict[str, str] = {}
    for k, path in (("peer-ip", "group/peer-ip"), ("priority", "group/election-option/device-priority"),
                    ("preemptive", "group/election-option/preemptive"),
                    ("state-sync", "group/state-synchronization/enabled"), ("ha1", "interface/ha1/port"),
                    ("ha2", "interface/ha2/port")):
        v = _t(hac, path)
        if v:
            d[k] = v
    if g is not None:
        local, peer = g.find("local-info"), g.find("peer-info")
        h.state = _t(local, "state")
        h.members = [f"{dev.hostname} (local, {_t(local, 'state') or '?'})"]
        if peer is not None:
            h.members.append(f"peer {(_t(peer, 'mgmt-ip') or '?').split('/')[0]} ({_t(peer, 'state') or '?'}, "
                             f"link {_t(peer, 'conn-status') or '?'})")
        rs = (_t(g, "running-sync") or "").lower()
        if rs:
            d["running-sync"] = rs
            d["sync"] = "in-sync" if rs == "synchronized" else "out-of-sync"
        for k, el, path in (("state-sync-status", local, "state-sync"), ("build-compat", local, "build-compat"),
                            ("app-compat", local, "app-compat"), ("peer-version", peer, "build-rel")):
            if _t(el, path):
                d[k] = _t(el, path) or ""
    h.details = d
    dev.ha = h


def _dhcp(dev: m.Device, ctx: _Ctx, si: Element | None, ha: Element | None) -> None:
    import ipaddress

    rows = []
    for e in _entries(ctx.network, "dhcp/interface"):
        srv = e.find("server")
        if srv is not None:
            opt = srv.find("option")
            lease = _t(opt, "lease/timeout")
            dns = ", ".join(x for x in (_t(opt, "dns/primary"), _t(opt, "dns/secondary")) if x)
            gw, mask = _t(opt, "gateway") or "", _t(opt, "subnet-mask") or ""
            try:
                net = str(ipaddress.IPv4Interface(f"{gw}/{mask}").network) if gw and mask else ""
            except ValueError:
                net = ""
            rows.append([e.get("name") or "", net, ", ".join(_members(srv, "ip-pool")), gw, dns,
                         f"{int(lease) * 60}s" if lease and lease.isdigit() else "default",
                         str(len(_entries(srv, "reserved"))), _t(srv, "mode") or "auto"])
        elif e.find("relay") is not None:
            rows.append([e.get("name") or "", "", "relay -> " + ", ".join(_members(e, "relay/ip/server")), "", "",
                         "", "", "relay"])
    if rows:
        dev.dhcp_scopes.append(m.Table(title="DHCP server scopes", columns=[
            "Interface", "Network", "Range", "Gateway", "DNS", "Lease", "Reservations", "Status"], rows=rows))


def _extras(dev: m.Device, ctx: _Ctx, si: Element | None, ha: Element | None) -> None:
    # zones incl. zone protection
    zrows = []
    for v in ctx.vsys:
        for z in _entries(v, "zone"):
            net = z.find("network")
            mode, members = "", []
            if net is not None:
                for child in net:
                    if child.tag in ("layer3", "layer2", "virtual-wire", "tap", "tunnel", "external"):
                        mode = child.tag
                        members += _members(net, child.tag)
            zp = _t(net, "zone-protection-profile") if net is not None else None
            zrows.append([z.get("name") or "", mode, ", ".join(members), zp or "none",
                          "yes" if _yes(z, "enable-user-identification") else "no",
                          _t(net, "log-setting") if net is not None and _t(net, "log-setting") else ""])
    if zrows:
        dev.sections.append(m.Section(id="paloalto-zones", title="Zones and zone protection", summary_relevant=True,
                                      tables=[m.Table(columns=["Zone", "Type", "Interfaces", "Zone protection",
                                                               "User-ID", "Log setting"], rows=zrows)]))
    zpp = []
    for e in _entries(ctx.network, "profiles/zone-protection-profile"):
        flood = e.find("flood")
        floods = [c.tag for c in flood if _yes(c, "enable")] if flood is not None else []
        zpp.append([e.get("name") or "", ", ".join(floods) or "none",
                    "yes" if e.find("scan") is not None else "no", _t(e, "description") or ""])
    if zpp:
        dev.sections.append(m.Section(id="paloalto-zone-protection", title="Zone protection profiles", tables=[
            m.Table(columns=["Profile", "Flood protection", "Recon protection", "Description"], rows=zpp)]))
    # services
    srows = []
    for _vs, e in ctx.objects("service"):
        proto = e.find("protocol")
        if proto is not None:
            for p in proto:
                srows.append([e.get("name") or "", p.tag, _t(p, "port") or "", _t(p, "source-port") or "",
                              _t(e, "description") or ""])
    for _vs, e in ctx.objects("service-group"):
        srows.append([e.get("name") or "", "group", ", ".join(_members(e, "members")), "", ""])
    if srows:
        dev.sections.append(m.Section(id="paloalto-services", title="Service objects", tables=[
            m.Table(columns=["Name", "Protocol", "Destination port", "Source port", "Description"], rows=srows)]))
    # security profiles & groups
    prows = []
    for v in ctx.vsys:
        profs = v.find("profiles")
        if profs is not None:
            for kind in profs:
                for e in kind.findall("entry"):
                    prows.append([kind.tag, e.get("name") or "", _t(e, "description") or ""])
        for g in _entries(v, "profile-group"):
            prows.append(["profile-group", g.get("name") or "",
                          ", ".join(f"{c.tag}={'/'.join(_members(g, c.tag))}" for c in g)])
    if prows:
        dev.sections.append(m.Section(id="paloalto-security-profiles", title="Security profiles", tables=[
            m.Table(columns=["Type", "Name", "Description / members"], rows=prows)]))
    # interface management profiles
    mrows = []
    for name, p in _mgmt_profiles(ctx).items():
        svcs = [s for s in ("https", "http", "ssh", "telnet", "ping", "snmp", "response-pages", "userid-service")
                if _yes(p, s)]
        mrows.append([name, " ".join(svcs), ", ".join(e.get("name") or "" for e in _entries(p, "permitted-ip"))
                      or "any"])
    if mrows:
        dev.sections.append(m.Section(id="paloalto-mgmt-profiles", title="Interface management profiles", tables=[
            m.Table(columns=["Profile", "Services", "Permitted IPs"], rows=mrows)]))
    # system facts
    facts = []
    if ctx.config is not None:
        for k in ("version", "detail-version"):
            if ctx.config.get(k):
                facts.append(m.Fact(key=f"config {k}", value=ctx.config.get(k) or ""))
    for k, path in (("Update server", "update-server"), ("Panorama", "panorama/local-panorama/panorama-server"),
                    ("Default gateway (mgmt)", "default-gateway"), ("Mgmt netmask", "netmask"),
                    ("Login banner", "login-banner")):
        v = _t(ctx.system, path)
        if v:
            facts.append(m.Fact(key=k, value=v))
    if facts:
        dev.sections.append(m.Section(id="paloalto-system", title="PAN-OS system settings", facts=facts))


register(PaloAltoDriver())
