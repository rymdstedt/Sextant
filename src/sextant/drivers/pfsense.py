"""pfSense and OPNsense drivers (config.xml).

Both products keep their whole configuration in /conf/config.xml. Collection is either
an offline import of that file or a read-only SSH `cat /conf/config.xml` (netmiko
device_type "linux"; the account needs a shell, e.g. pfSense "admin" lands in the console
menu, so use a dedicated shell user). The two formats share the legacy layout
(<system>, <interfaces>, <filter>, <nat>, <ipsec>, <openvpn>, <dhcpd>...); OPNsense adds
MVC models under <OPNsense> (Swanctl, WireGuard, Kea, Syslog, aliases, new-style rules)
which are parsed too when present.
"""

from __future__ import annotations

import ipaddress
import json
import re
from xml.etree.ElementTree import Element

from sextant import model as m
from sextant.drivers import register
from sextant.drivers._util import mask_value, norm_action, parse_xml_safe, redact_xml
from sextant.drivers.base import Credentials, Driver, RawCollection, Target

CMD_CONFIG = "cat /conf/config.xml"


# --------------------------------------------------------------------------- xml helpers


def _t(el: Element | None, path: str | None = None, default: str | None = None) -> str | None:
    if el is None:
        return default
    node = el.find(path) if path else el
    if node is None or node.text is None:
        return default
    return node.text.strip() or default


def _has(el: Element | None, path: str) -> bool:
    """Presence flags (<disabled/>, <log/>); '0'/'no'/'off' count as absent."""
    if el is None:
        return False
    node = el.find(path)
    if node is None:
        return False
    return (node.text or "").strip().lower() not in ("0", "no", "off", "false", "disabled")


def _on(el: Element | None, path: str) -> bool:
    """MVC style booleans: <enabled>1</enabled>."""
    return (_t(el, path) or "").lower() in ("1", "yes", "on", "true", "enabled")


def _split(v: str | None, sep: str = ",") -> list[str]:
    return [x.strip() for x in re.split(rf"[{re.escape(sep)}\n]+", v or "") if x.strip()]


def _cidr(addr: str | None, bits: str | None) -> str | None:
    if not addr:
        return None
    return f"{addr}/{bits}" if bits else addr


def _network(cidr: str | None) -> str | None:
    try:
        return str(ipaddress.ip_interface(cidr or "").network)
    except ValueError:
        return None


def _extract_xml(text: str) -> str:
    """Strip SSH noise (prompt, echoed command) around the XML document."""
    i = text.find("<?xml")
    if i < 0:
        mt = re.search(r"<(pfsense|opnsense)[\s>]", text)
        i = mt.start() if mt else 0
    j = max(text.rfind("</pfsense>"), text.rfind("</opnsense>"))
    if j > 0:
        j = text.find(">", j) + 1
        return text[i:j]
    return text[i:]


# --------------------------------------------------------------------------- driver


class _ConfigXmlDriver(Driver):
    methods = ("file", "ssh")
    product = ""
    vendor = ""
    version_cmd = ""

    def collect(self, target: Target, creds: Credentials) -> RawCollection:
        if target.method == "file" and target.file:
            from pathlib import Path

            return self.from_file(Path(target.file))
        from sextant.drivers._ssh import run_commands

        return run_commands(target, creds, "linux", [CMD_CONFIG, self.version_cmd], self.id, timeout=120)

    def _version(self, text: str) -> str | None:
        return None

    def parse(self, raw: RawCollection) -> m.Device:
        out = raw.outputs or {}
        warnings = list(raw.warnings)
        dev = m.Device(hostname=raw.target, role=m.DeviceRole.firewall, vendor=self.vendor, platform=self.id,
                       os_name=self.product, collection_method=raw.method, source=raw.target)
        text = str(out.get("config") or out.get(CMD_CONFIG) or "")
        root: Element | None = None
        if not text.strip():
            warnings.append("no config.xml in collection")
        else:
            try:
                root = parse_xml_safe(_extract_xml(text))
            except ValueError as exc:
                warnings.append(f"config.xml: {exc}")
        if root is not None and root.tag not in ("pfsense", "opnsense"):
            warnings.append(f"unexpected root element <{root.tag}>")
        if root is not None and root.tag in ("pfsense", "opnsense") and root.tag != self.id:
            warnings.append(f"config.xml looks like {root.tag}, parsed with the {self.id} driver")
        ver_out = out.get(self.version_cmd)
        if ver_out:
            dev.os_version = self._version(str(ver_out))
        elif raw.method == "ssh":
            warnings.append(f"no output for {self.version_cmd}")
        if root is not None:
            ctx = _Ctx(root)
            for step in (_system, _interfaces, _routing, _aliases, _filter, _nat, _vpn_ipsec, _vpn_openvpn,
                         _vpn_wireguard, _ha, _dhcp, _services, _extras):
                try:
                    step(dev, ctx)
                except Exception as exc:  # noqa: BLE001 - one bad block must not lose the device
                    warnings.append(f"{step.__name__.lstrip('_')}: {exc.__class__.__name__}: {exc}")
        dev.collection_warnings = warnings
        try:
            dev.raw_config = redact_xml(_extract_xml(text)) if text.strip() else None
        except Exception:  # noqa: BLE001
            dev.raw_config = None
        return dev


class PfSenseDriver(_ConfigXmlDriver):
    id = "pfsense"
    label = "Netgate pfSense"
    product = "pfSense"
    vendor = "Netgate"
    version_cmd = "cat /etc/version"

    def _version(self, text: str) -> str | None:
        mt = re.search(r"^\s*(\d+\.\d+(?:\.\d+)?[-\w.]*)\s*$", text, re.MULTILINE)
        return mt.group(1) if mt else None


class OPNsenseDriver(_ConfigXmlDriver):
    id = "opnsense"
    label = "Deciso OPNsense"
    product = "OPNsense"
    vendor = "Deciso"
    version_cmd = "cat /usr/local/opnsense/version/core"

    def _version(self, text: str) -> str | None:
        mt = re.search(r"\{.*\}", text, re.DOTALL)
        if mt:
            try:
                data = json.loads(mt.group(0))
                return data.get("product_version") or data.get("CORE_VERSION")
            except ValueError:
                pass
        mt2 = re.search(r'"product_version"\s*:\s*"([^"]+)"', text)
        return mt2.group(1) if mt2 else None


# --------------------------------------------------------------------------- context


class _Ctx:
    def __init__(self, root: Element) -> None:
        self.root = root
        self.mvc = root.find("OPNsense")
        self.system = root.find("system")
        self.ifaces: dict[str, Element] = {}
        ifs = root.find("interfaces")
        if ifs is not None:
            for child in ifs:
                self.ifaces[child.tag] = child
        self.gateways: dict[str, Element] = {}
        for g in root.findall("gateways/gateway_item"):
            if _t(g, "name"):
                self.gateways[_t(g, "name") or ""] = g
        if self.mvc is not None:
            for g in self.mvc.findall("Gateways/gateway_item"):
                if _t(g, "name"):
                    self.gateways[_t(g, "name") or ""] = g

    def friendly(self, key: str | None) -> str:
        """'lan' -> 'LAN', 'opt1' -> its description."""
        if not key:
            return "any"
        el = self.ifaces.get(key)
        if el is not None and _t(el, "descr"):
            return _t(el, "descr") or key
        return {"openvpn": "OpenVPN", "enc0": "IPsec", "ipsec": "IPsec", "wireguard": "WireGuard",
                "lo0": "Loopback"}.get(key, key.upper() if key in ("wan", "lan") else key)

    def iface_cidr(self, key: str) -> str | None:
        el = self.ifaces.get(key)
        ip = _t(el, "ipaddr")
        if ip and re.match(r"^\d+\.\d+\.\d+\.\d+$", ip):
            return _cidr(ip, _t(el, "subnet"))
        return None

    def mvc_find(self, path: str) -> list[Element]:
        return self.mvc.findall(path) if self.mvc is not None else []


# --------------------------------------------------------------------------- steps


def _system(dev: m.Device, ctx: _Ctx) -> None:
    s = ctx.system
    mg = dev.management
    if s is None:
        return
    host, dom = _t(s, "hostname"), _t(s, "domain")
    if host:
        dev.hostname = host
    mg.domain = dom
    mg.dns_servers = [x.text.strip() for x in s.findall("dnsserver") if x.text and x.text.strip()]
    mg.ntp_servers = (_t(s, "timeservers") or "").split()
    mg.timezone = _t(s, "timezone")
    proto = (_t(s, "webgui/protocol") or "https").lower()
    mg.https = proto == "https"
    mg.http = proto == "http"
    mg.telnet = False
    ssh = s.find("ssh")
    if ctx.root.tag == "opnsense":
        mg.ssh = _t(ssh, "enabled") == "enabled" or _on(ssh, "enabled")
    else:
        mg.ssh = _t(ssh, "enable") == "enabled" or _t(s, "enablesshd") == "enabled"
    mg.ssh_version = "2" if mg.ssh else None
    banner = _t(s, "webgui/loginmessage") or _t(s, "loginbanner")
    mg.banner = banner
    # users and groups
    gid_of_user: dict[str, list[str]] = {}
    privs_of_group: dict[str, list[str]] = {}
    for g in s.findall("group"):
        name = _t(g, "name") or "?"
        privs_of_group[name] = [p.text.strip() for p in g.findall("priv") if p.text]
        for mem in g.findall("member"):
            for uid in _split(mem.text):
                gid_of_user.setdefault(uid, []).append(name)
    for u in s.findall("user"):
        name = _t(u, "name") or "?"
        groups = [g for g in gid_of_user.get(_t(u, "uid") or "", []) if g != "all"] or \
            ([_t(u, "groupname") or ""] if _t(u, "groupname") else [])
        privs = [p.text.strip() for p in u.findall("priv") if p.text]
        if any(p == "page-all" for g in groups for p in privs_of_group.get(g, [])) or "page-all" in privs:
            priv = f"admin ({', '.join(groups)})" if groups else "admin"
        else:
            priv = ", ".join(groups + privs) or None
        auth = []
        for tag, label in (("bcrypt-hash", "password (bcrypt)"), ("sha512-hash", "password (sha512)"),
                           ("md5-hash", "password (md5)"), ("password", "password")):
            if u.find(tag) is not None and (u.find(tag).text or "").strip():
                if tag == "password" and (u.find(tag).text or "").startswith("$2"):
                    label = "password (bcrypt)"
                auth.append(label)
                break
        if (_t(u, "authorizedkeys") or "").strip():
            auth.append("ssh-key")
        if (_t(u, "otp_seed") or "").strip():
            auth.append("TOTP")
        if _has(u, "disabled"):
            auth.append("disabled")
        mg.users.append(m.LocalUser(name=name, privilege=priv, auth=", ".join(auth) or None))
    for a in s.findall("authserver"):
        typ, host = (_t(a, "type") or "").lower(), _t(a, "host")
        label = f"{host} ({_t(a, 'name')})"
        if host and typ == "radius":
            mg.aaa.radius_servers.append(label)
        elif host and typ.startswith("ldap"):
            mg.aaa.ldap_servers.append(label)
    authmode = _t(s, "webgui/authmode")
    if authmode:
        mg.aaa.login_methods.append(f"webgui: {authmode}")
    mg.password_encryption = True


def _interfaces(dev: m.Device, ctx: _Ctx) -> None:
    vlan_of: dict[str, tuple[int, str, str]] = {}
    for v in ctx.root.findall("vlans/vlan"):
        ifname = _t(v, "vlanif") or f"{_t(v, 'if')}.{_t(v, 'tag')}"
        tag = _t(v, "tag")
        if tag and tag.isdigit():
            vlan_of[ifname] = (int(tag), _t(v, "if") or "", _t(v, "descr") or "")
    lagg: dict[str, tuple[list[str], str]] = {}
    for lg in ctx.root.findall("laggs/lagg"):
        lagg[_t(lg, "laggif") or "?"] = (_split(_t(lg, "members")), _t(lg, "proto") or "")
    member_of = {mbr: name for name, (mbrs, _p) in lagg.items() for mbr in mbrs}
    seen: set[str] = set()
    for key, el in ctx.ifaces.items():
        phys = _t(el, "if") or key
        seen.add(phys)
        kind = "physical"
        if phys in vlan_of or re.search(r"\.\d+$", phys) or phys.startswith("vlan"):
            kind = "vlan"
        elif phys.startswith(("lagg", "bond")):
            kind = "lag"
        elif phys.startswith(("ovpn", "wg", "tun_wg", "ipsec", "gif", "gre", "tun")):
            kind = "tunnel"
        elif phys.startswith("lo"):
            kind = "loopback"
        friendly = ctx.friendly(key)
        intf = m.Interface(name=phys, description=friendly, kind=kind, enabled=_has(el, "enable"), zone=friendly,
                           mode=m.PortMode.routed)
        ip = _t(el, "ipaddr")
        extra = {"if-key": key}
        if ip and re.match(r"^\d+\.\d+\.\d+\.\d+$", ip):
            intf.ipv4.append(m.IPAddress(address=_cidr(ip, _t(el, "subnet")) or ip))
        elif ip:
            extra["addressing"] = ip
        ip6 = _t(el, "ipaddrv6")
        if ip6 and ":" in ip6:
            intf.ipv6.append(_cidr(ip6, _t(el, "subnetv6")) or ip6)
        elif ip6:
            extra["addressing-v6"] = ip6
        if _t(el, "mtu", "").isdigit():
            intf.mtu = int(_t(el, "mtu") or 0)
        if _t(el, "spoofmac"):
            intf.mac = _t(el, "spoofmac")
        if phys in vlan_of:
            intf.access_vlan = vlan_of[phys][0]
            extra["parent"] = vlan_of[phys][1]
        if phys in lagg:
            intf.lag_members, intf.lag_protocol = lagg[phys][0], lagg[phys][1] or None
        if phys in member_of:
            intf.lag = member_of[phys]
        for flag in ("blockpriv", "blockbogons"):
            if _has(el, flag):
                extra[flag] = "yes"
        if _t(el, "gateway"):
            extra["gateway"] = _t(el, "gateway") or ""
        intf.extra = extra
        dev.interfaces.append(intf)
    # assigned-or-not VLANs / LAG members not assigned as interfaces
    for name, (mbrs, _p) in lagg.items():
        for mbr in mbrs:
            if mbr not in seen:
                dev.interfaces.append(m.Interface(name=mbr, kind="physical", lag=name, mode=m.PortMode.lag_member))
                seen.add(mbr)
    by_name = {i.name: i for i in dev.interfaces}
    for ifname, (tag, parent, descr) in vlan_of.items():
        intf = by_name.get(ifname)
        dev.vlans.append(m.Vlan(id=tag, name=descr or (intf.description if intf else None),
                                svi_ipv4=[a.address for a in intf.ipv4] if intf else [], ports=[parent]))
    dev.vlans.sort(key=lambda v: v.id)
    lan = ctx.iface_cidr("lan")
    dev.mgmt_ip = lan.split("/")[0] if lan else None


def _routing(dev: m.Device, ctx: _Ctx) -> None:
    default4 = _t(ctx.root, "gateways/defaultgw4")
    for name, g in ctx.gateways.items():
        ip = _t(g, "gateway")
        if (_t(g, "ipprotocol") or "inet") != "inet":
            continue
        is_default = name == default4 or _on(g, "defaultgw") or g.find("defaultgw") is not None
        if is_default and ip and ip != "dynamic":
            dev.routes.append(m.Route(prefix="0.0.0.0/0", next_hop=ip, interface=ctx.friendly(_t(g, "interface")),
                                      protocol="static", description=f"default gateway {name}"))
    for r in ctx.root.findall("staticroutes/route"):
        gw = ctx.gateways.get(_t(r, "gateway") or "")
        dev.routes.append(m.Route(prefix=_t(r, "network") or "?",
                                  next_hop=_t(gw, "gateway") if gw is not None else _t(r, "gateway"),
                                  interface=ctx.friendly(_t(gw, "interface")) if gw is not None else None,
                                  protocol="static",
                                  description=(_t(r, "descr") or "") + (" (disabled)" if _has(r, "disabled") else "")
                                  or None))
    for r in ctx.mvc_find("routes/route"):
        if not _on(r, "disabled"):
            gw = ctx.gateways.get(_t(r, "gateway") or "")
            dev.routes.append(m.Route(prefix=_t(r, "network") or "?",
                                      next_hop=_t(gw, "gateway") if gw is not None else _t(r, "gateway"),
                                      protocol="static", description=_t(r, "descr")))
    # FRR (OPNsense os-frr / pfSense frr package): only a summary
    for bgp in ctx.mvc_find("quagga/bgp"):
        if _on(bgp, "enabled"):
            neigh = [f"{_t(n, 'address')} (AS {_t(n, 'remoteas')})" for n in ctx.mvc_find("quagga/bgp/neighbors/neighbor")]
            dev.routing_protocols.append(m.RoutingProtocol(protocol="bgp", asn=_t(bgp, "asnumber"),
                                                           router_id=_t(bgp, "routerid"), neighbors=neigh,
                                                           networks=_split(_t(bgp, "networks"))))
    for ospf in ctx.mvc_find("quagga/ospf"):
        if _on(ospf, "enabled"):
            nets = [f"{_t(n, 'ipaddr')}/{_t(n, 'netmask')} area {_t(n, 'area')}"
                    for n in ctx.mvc_find("quagga/ospf/networks/network")]
            dev.routing_protocols.append(m.RoutingProtocol(protocol="ospf", router_id=_t(ospf, "routerid"),
                                                           networks=nets))


def _aliases(dev: m.Device, ctx: _Ctx) -> None:
    rows: list[list[str]] = []
    items: list[tuple[str, str, list[str], str | None]] = []
    for a in ctx.root.findall("aliases/alias"):
        items.append((_t(a, "name") or "?", (_t(a, "type") or "host").lower(), (_t(a, "address") or "").split(),
                      _t(a, "descr")))
    for a in ctx.mvc_find("Firewall/Alias/aliases/alias"):
        if a.find("enabled") is not None and not _on(a, "enabled"):
            continue
        items.append((_t(a, "name") or "?", (_t(a, "type") or "host").lower(), _split(_t(a, "content"), "\n,"),
                      _t(a, "description")))
    for name, typ, vals, descr in items:
        if typ.startswith("port"):
            rows.append([name, " ".join(vals), descr or ""])
            continue
        if typ in ("url", "urltable", "url_ports", "urltable_ports"):
            kind = "url"
        elif typ == "geoip":
            kind = "geo"
        elif len(vals) > 1:
            kind = "group"
        elif typ == "network" or any("/" in v for v in vals):
            kind = "subnet"
        elif vals and re.match(r"^\d+\.\d+\.\d+\.\d+-\d+\.\d+\.\d+\.\d+$", vals[0]):
            kind = "range"
        elif vals and not re.match(r"^[\d.:]+$", vals[0]):
            kind = "fqdn"
        else:
            kind = "host"
        dev.address_objects.append(m.AddressObject(name=name, kind=kind, value=", ".join(vals), comment=descr))
    if rows:
        dev.sections.append(m.Section(id=f"{dev.platform}-port-aliases", title="Port aliases", tables=[
            m.Table(columns=["Alias", "Ports", "Description"], rows=rows)]))


def _endpoint(ctx: _Ctx, el: Element | None) -> tuple[str, str | None]:
    """<source>/<destination> -> ('LAN net' | '10.0.0.0/24' | 'any', port)."""
    if el is None:
        return "any", None
    neg = "!" if el.find("not") is not None else ""
    port = _t(el, "port")
    if el.find("any") is not None:
        return neg + "any", port
    net = _t(el, "network")
    if net:
        if net == "(self)":
            return neg + "This Firewall", port
        if net.endswith("ip") and net[:-2] in ctx.ifaces:
            return neg + f"{ctx.friendly(net[:-2])} address", port
        if net in ctx.ifaces:
            return neg + f"{ctx.friendly(net)} net", port
        return neg + net, port
    addr = _t(el, "address")
    return neg + (addr or "any"), port


def _svc(proto: str | None, port: str | None) -> list[str]:
    proto = (proto or "").lower()
    if not proto or proto == "any":
        return [f"any/{port}"] if port else ["any"]
    if not port:
        return [proto]
    return [f"{proto} {port}" if "/" in proto else f"{proto}/{port}"]


def _filter(dev: m.Device, ctx: _Ctx) -> None:
    for idx, r in enumerate(ctx.root.findall("filter/rule"), 1):
        src, sport = _endpoint(ctx, r.find("source"))
        dst, dport = _endpoint(ctx, r.find("destination"))
        ifs = _split(_t(r, "interface"))
        floating = _has(r, "floating")
        comment = _t(r, "descr")
        extras = []
        if floating:
            extras.append(f"floating, direction {_t(r, 'direction') or 'any'}, quick={'yes' if _has(r, 'quick') else 'no'}")
        if _t(r, "gateway"):
            extras.append(f"gateway {_t(r, 'gateway')}")
        if sport:
            extras.append(f"source port {sport}")
        if extras:
            comment = (comment + " " if comment else "") + f"[{'; '.join(extras)}]"
        dev.firewall_rules.append(m.FirewallRule(
            id=_t(r, "tracker") or r.get("uuid") or str(idx), name=None, enabled=not _has(r, "disabled"),
            action=norm_action(_t(r, "type") or "pass"),
            src_zones=[ctx.friendly(i) for i in ifs] or ["any"], dst_zones=[],
            src_addresses=[src], dst_addresses=[dst], services=_svc(_t(r, "protocol"), dport),
            log=_has(r, "log"), schedule=_t(r, "sched"), comment=comment,
            users=[], nat=True if (_t(r, "associated-rule-id") or "").startswith("nat_") else None))
    # OPNsense MVC rules (Firewall > Rules [new])
    for idx, r in enumerate(ctx.mvc_find("Firewall/Filter/rules/rule"), 1):
        def ep(prefix: str, r: Element = r) -> str:
            net = _t(r, f"{prefix}_net") or "any"
            if net in ctx.ifaces:
                net = f"{ctx.friendly(net)} net"
            elif net.endswith("ip") and net[:-2] in ctx.ifaces:
                net = f"{ctx.friendly(net[:-2])} address"
            return ("!" if _on(r, f"{prefix}_not") else "") + net
        dev.firewall_rules.append(m.FirewallRule(
            id=r.get("uuid") or f"mvc-{idx}", enabled=_on(r, "enabled"), action=norm_action(_t(r, "action") or "pass"),
            src_zones=[ctx.friendly(i) for i in _split(_t(r, "interface"))] or ["any"],
            src_addresses=[ep("source")], dst_addresses=[ep("destination")],
            services=_svc(_t(r, "protocol"), _t(r, "destination_port")), log=_on(r, "log"),
            comment=_t(r, "description")))


def _nat(dev: m.Device, ctx: _Ctx) -> None:
    nat = ctx.root.find("nat")
    if nat is None:
        return
    for idx, r in enumerate(nat.findall("rule"), 1):  # port forwards
        src, _sp = _endpoint(ctx, r.find("source"))
        dst, dport = _endpoint(ctx, r.find("destination"))
        proto = _t(r, "protocol") or "any"
        target = _t(r, "target") or "?"
        lport = _t(r, "local-port")
        dev.nat_rules.append(m.NatRule(
            id=f"rdr:{idx}", kind="dnat", original=f"{src} -> {dst}" + (f":{dport}" if dport else "") + f" ({proto})",
            translated=target + (f":{lport}" if lport else ""), interface=ctx.friendly(_t(r, "interface")),
            comment=_t(r, "descr"), enabled=not _has(r, "disabled")))
    mode = _t(nat, "outbound/mode") or "automatic"
    for idx, r in enumerate(nat.findall("outbound/rule"), 1):
        src, _sp = _endpoint(ctx, r.find("source"))
        dst, _dp = _endpoint(ctx, r.find("destination"))
        target = _t(r, "target") or ""
        if _has(r, "nonat"):
            trans = "no NAT"
        elif not target or target in ctx.ifaces or target.endswith("ip"):
            trans = f"{ctx.friendly(target[:-2] if target.endswith('ip') else _t(r, 'interface'))} address"
        else:
            trans = target
        dev.nat_rules.append(m.NatRule(
            id=f"outbound:{idx}", kind="snat" if not _has(r, "nonat") else "no-nat",
            original=f"{src} -> {dst}", translated=trans, interface=ctx.friendly(_t(r, "interface")),
            comment=_t(r, "descr"), enabled=not _has(r, "disabled")))
    if mode in ("automatic", "hybrid"):
        dev.nat_rules.append(m.NatRule(id="outbound:auto", kind="pat", original="all internal networks -> any",
                                       translated="WAN address (automatic outbound NAT)", interface="WAN",
                                       comment=f"outbound NAT mode: {mode}"))
    for idx, r in enumerate(nat.findall("onetoone"), 1):
        src, _sp = _endpoint(ctx, r.find("source"))
        dev.nat_rules.append(m.NatRule(id=f"1to1:{idx}", kind="static", original=_t(r, "external") or "?",
                                       translated=src, interface=ctx.friendly(_t(r, "interface")),
                                       comment=_t(r, "descr"), enabled=not _has(r, "disabled")))
    dev.sections.append(m.Section(id=f"{dev.platform}-nat", title="NAT settings",
                                  facts=[m.Fact(key="Outbound NAT mode", value=mode)]))


def _enc(el: Element | None) -> str:
    """<encryption-algorithm><name>aes</name><keylen>256</keylen></...> -> 'aes256'."""
    if el is None:
        return "?"
    name, kl = _t(el, "name") or "?", _t(el, "keylen")
    if kl and kl != "auto":
        return f"{name}{kl}" if not name.endswith(("gcm", "ccm")) else f"{name.replace('gcm', '')}{kl}gcm"
    return name


_HASH = {"hmac_sha1": "sha1", "hmac_sha256": "sha256", "hmac_sha384": "sha384", "hmac_sha512": "sha512",
         "hmac_md5": "md5", "aesxcbc": "aesxcbc"}


def _vpn_ipsec(dev: m.Device, ctx: _Ctx) -> None:
    ipsec = ctx.root.find("ipsec")
    p2_by: dict[str, list[Element]] = {}
    if ipsec is not None:
        for p2 in ipsec.findall("phase2"):
            p2_by.setdefault(_t(p2, "ikeid") or "", []).append(p2)

        def side(el: Element | None) -> str:
            if el is None:
                return "?"
            typ = _t(el, "type") or "network"
            if typ == "network":
                return _cidr(_t(el, "address"), _t(el, "netbits")) or "?"
            if typ == "address":
                return _t(el, "address") or "?"
            return f"{ctx.friendly(typ)} subnet" if typ in ctx.ifaces else typ

        for p1 in ipsec.findall("phase1"):
            props = []
            items = p1.findall("encryption/item")
            if items:
                for it in items:
                    props.append((_enc(it.find("encryption-algorithm")), _t(it, "hash-algorithm") or "?",
                                  _t(it, "dhgroup") or "?"))
            else:
                hashes = _split(_t(p1, "hash-algorithm"))
                for dh in _split(_t(p1, "dhgroup")) or ["?"]:
                    props.append((_enc(p1.find("encryption-algorithm")), "/".join(hashes) or "?", dh))
            encs = "/".join(dict.fromkeys(f"{e}-{h}" for e, h, _ in props))
            dhs = "/".join(dict.fromkeys(f"dh{d}" for _e, _h, d in props))
            phase1 = f"{encs}, {dhs}, {_t(p1, 'lifetime') or '28800'}s"
            ver = (_t(p1, "iketype") or "ikev1").lower()
            t = m.VpnTunnel(name=_t(p1, "descr") or f"phase1 {_t(p1, 'ikeid')}", kind="ipsec",
                            peer=_t(p1, "remote-gateway"),
                            ike_version={"ikev1": "IKEv1", "ikev2": "IKEv2", "auto": "auto"}.get(ver, ver),
                            phase1=phase1,
                            psk_set=bool(_t(p1, "pre-shared-key")) if "pre_shared_key" in
                            (_t(p1, "authentication_method") or "pre_shared_key") else False,
                            status="disabled" if _has(p1, "disabled") else None)
            p2s: list[str] = []
            for p2 in p2_by.get(_t(p1, "ikeid") or "", []):
                if _has(p2, "disabled"):
                    continue
                encs2 = "/".join(_enc(e) for e in p2.findall("encryption-algorithm-option")) or "?"
                hashes2 = "/".join(_HASH.get(h.text or "", h.text or "") for h in p2.findall("hash-algorithm-option")
                                   if h.text) or "?"
                pfs = _t(p2, "pfsgroup") or "0"
                s = f"{encs2}-{hashes2}, {'no-pfs' if pfs in ('0', 'off') else 'dh' + pfs}, " \
                    f"{_t(p2, 'lifetime') or '3600'}s"
                if s not in p2s:
                    p2s.append(s)
                if (_t(p2, "mode") or "tunnel").startswith("tunnel"):
                    loc, rem = side(p2.find("localid")), side(p2.find("remoteid"))
                    if loc not in t.local_subnets:
                        t.local_subnets.append(loc)
                    if rem not in t.remote_subnets:
                        t.remote_subnets.append(rem)
                else:
                    t.local_subnets.append(f"route-based ({_t(p2, 'mode')})")
            t.phase2 = "; ".join(p2s) or None
            dev.vpn_tunnels.append(t)
    # OPNsense swanctl (VPN > IPsec > Connections)
    children = ctx.mvc_find("Swanctl/children/child")
    locals_ = ctx.mvc_find("Swanctl/locals/local")
    for c in ctx.mvc_find("Swanctl/Connections/Connection"):
        uid = c.get("uuid") or ""
        mine = [ch for ch in children if _t(ch, "connection") == uid]
        auths = [_t(lo, "auth") for lo in locals_ if _t(lo, "connection") == uid]
        dev.vpn_tunnels.append(m.VpnTunnel(
            name=_t(c, "description") or uid, kind="ipsec", peer=_t(c, "remote_addrs"),
            ike_version=f"IKEv{_t(c, 'version')}" if (_t(c, "version") or "0") != "0" else "auto",
            phase1=_swan(_t(c, "proposals"), _t(c, "rekey_time")),
            phase2="; ".join(dict.fromkeys(_swan(_t(ch, "esp_proposals"), _t(ch, "rekey_time")) for ch in mine))
            or None,
            local_subnets=[x for ch in mine for x in _split(_t(ch, "local_ts"))],
            remote_subnets=[x for ch in mine for x in _split(_t(ch, "remote_ts"))],
            psk_set=True if "psk" in auths else None, status=None if _on(c, "enabled") else "disabled"))


_MODP = {"modp768": "1", "modp1024": "2", "modp1536": "5", "modp2048": "14", "modp3072": "15", "modp4096": "16",
         "modp6144": "17", "modp8192": "18", "ecp256": "19", "ecp384": "20", "ecp521": "21", "ecp224": "26",
         "x25519": "31", "curve25519": "31", "x448": "32", "curve448": "32"}


def _swan(proposals: str | None, lifetime: str | None) -> str:
    """strongSwan 'aes256-sha256-modp2048,aes128-sha1-modp1024' -> 'aes256-sha256/aes128-sha1, dh14/dh2, 14400s'."""
    if not proposals or proposals == "default":
        return "default" + (f", {lifetime}s" if lifetime else "")
    algs: list[str] = []
    dhs: list[str] = []
    for prop in _split(proposals):
        parts = prop.split("-")
        dh = [f"dh{_MODP[x]}" for x in parts if x in _MODP]
        rest = "-".join(x for x in parts if x not in _MODP)
        if rest and rest not in algs:
            algs.append(rest)
        for d in dh or ["no-pfs"]:
            if d not in dhs:
                dhs.append(d)
    return f"{'/'.join(algs)}, {'/'.join(dhs)}" + (f", {lifetime}s" if lifetime else "")


def _vpn_openvpn(dev: m.Device, ctx: _Ctx) -> None:
    for role in ("openvpn-server", "openvpn-client"):
        for o in ctx.root.findall(f"openvpn/{role}"):
            server = role.endswith("server")
            ciphers = _t(o, "data_ciphers") or _t(o, "crypto") or "default"
            mode = _t(o, "mode") or ""
            dev.vpn_tunnels.append(m.VpnTunnel(
                name=_t(o, "description") or f"{role} {_t(o, 'vpnid')}", kind="openvpn",
                peer="remote clients" if server and "p2p" not in mode else
                (f"{_t(o, 'server_addr')}:{_t(o, 'server_port')}" if not server else _t(o, "remote_network")),
                local_subnets=_split(_t(o, "local_network")),
                remote_subnets=_split(_t(o, "remote_network")) or ([_t(o, "tunnel_network") or ""]
                                                                   if _t(o, "tunnel_network") else []),
                phase1=f"{_t(o, 'protocol') or 'UDP'}/{_t(o, 'local_port') or _t(o, 'server_port') or '1194'}, "
                       f"{ciphers.replace(',', '/')}, auth {_t(o, 'digest') or 'SHA256'}, {mode}"
                       + (f", authmode {_t(o, 'authmode')}" if _t(o, "authmode") else ""),
                psk_set=bool(_t(o, "shared_key")) if "shared_key" in mode else None,
                status="disabled" if _has(o, "disable") else None))
    for o in ctx.mvc_find("OpenVPN/Instances/Instance"):
        server = (_t(o, "role") or "server") == "server"
        dev.vpn_tunnels.append(m.VpnTunnel(
            name=_t(o, "description") or o.get("uuid") or "openvpn", kind="openvpn",
            peer="remote clients" if server else _t(o, "remote"),
            local_subnets=_split(_t(o, "push_route")), remote_subnets=_split(_t(o, "server")),
            phase1=f"{_t(o, 'proto') or 'udp'}/{_t(o, 'port') or '1194'}, "
                   f"{(_t(o, 'data-ciphers') or 'default').replace(',', '/')}, auth {_t(o, 'auth') or 'default'}",
            status=None if _on(o, "enabled") else "disabled"))


def _vpn_wireguard(dev: m.Device, ctx: _Ctx) -> None:
    # pfSense WireGuard package
    wg = ctx.root.find("installedpackages/wireguard")
    if wg is not None:
        peers = wg.findall("peers/item")
        for t in wg.findall("tunnels/item"):
            name = _t(t, "name") or "wg"
            mine = [p for p in peers if _t(p, "tun") == name]
            dev.vpn_tunnels.append(m.VpnTunnel(
                name=f"{name}" + (f" ({_t(t, 'descr')})" if _t(t, "descr") else ""), kind="wireguard",
                peer=", ".join(f"{_t(p, 'descr') or 'peer'} {_t(p, 'endpoint') or 'dynamic'}"
                               + (f":{_t(p, 'port')}" if _t(p, "port") else "") for p in mine) or None,
                local_subnets=[_cidr(_t(r, "address"), _t(r, "mask")) or "" for r in t.findall("addresses/row")],
                remote_subnets=[_cidr(_t(r, "address"), _t(r, "mask")) or "" for p in mine
                                for r in p.findall("allowedips/row")],
                phase1=f"Curve25519/ChaCha20-Poly1305, listen {_t(t, 'listenport') or '51820'}/udp",
                psk_set=any(bool(_t(p, "presharedkey")) for p in mine),
                status=None if (_t(t, "enabled") or "yes") == "yes" else "disabled"))
    # OPNsense
    clients = {c.get("uuid"): c for c in ctx.mvc_find("wireguard/client/clients/client")}
    for s in ctx.mvc_find("wireguard/server/servers/server"):
        mine = [clients[u] for u in _split(_t(s, "peers")) if u in clients]
        dev.vpn_tunnels.append(m.VpnTunnel(
            name=_t(s, "name") or "wg", kind="wireguard",
            peer=", ".join(f"{_t(c, 'name')} {_t(c, 'serveraddress') or 'dynamic'}" for c in mine) or None,
            local_subnets=_split(_t(s, "tunneladdress")),
            remote_subnets=[x for c in mine for x in _split(_t(c, "tunneladdress"))],
            phase1=f"Curve25519/ChaCha20-Poly1305, listen {_t(s, 'port') or '51820'}/udp",
            psk_set=any(bool(_t(c, "psk")) for c in mine),
            status=None if _on(s, "enabled") else "disabled"))


def _ha(dev: m.Device, ctx: _Ctx) -> None:
    carp = [v for v in ctx.root.findall("virtualip/vip") if (_t(v, "mode") or "") == "carp"]
    hasync = ctx.root.find("hasync")
    if not carp and (hasync is None or not (_t(hasync, "synchronizetoip") or _t(hasync, "pfsyncpeerip"))):
        return
    d = {}
    if hasync is not None:
        for k in ("pfsyncenabled", "pfsyncinterface", "pfsyncpeerip", "synchronizetoip", "username"):
            if _t(hasync, k):
                d[k] = _t(hasync, k) or ""
        synced = [c.tag.removeprefix("synchronize") for c in hasync if c.tag.startswith("synchronize")
                  and c.tag != "synchronizetoip" and (c.text or "").strip() == "on"]
        if synced:
            d["xmlrpc-sync"] = ", ".join(synced)
    d["carp-vips"] = ", ".join(f"{_t(v, 'subnet')}/{_t(v, 'subnet_bits')} vhid {_t(v, 'vhid')} "
                               f"on {ctx.friendly(_t(v, 'interface'))} (skew {_t(v, 'advskew') or '0'})"
                               for v in carp)
    skews = {_t(v, "advskew") or "0" for v in carp}
    state = "primary (advskew 0)" if skews == {"0"} else ("secondary (advskew > 0)" if "0" not in skews else None)
    members = [dev.hostname]
    if hasync is not None and _t(hasync, "synchronizetoip"):
        members.append(f"peer {_t(hasync, 'synchronizetoip')}")
    by_key = {i.extra.get("if-key"): i for i in dev.interfaces}
    for v in carp:
        intf = by_key.get(_t(v, "interface"))
        if intf is not None and intf.ipv4 and not intf.ipv4[0].vrrp_vip:
            intf.ipv4[0].vrrp_vip = _t(v, "subnet")
    dev.ha = m.HighAvailability(mode="carp", members=members, state=state,
                                details={k: v for k, v in d.items() if v})


def _dhcp(dev: m.Device, ctx: _Ctx) -> None:
    rows = []
    dhcpd = ctx.root.find("dhcpd")
    if dhcpd is not None:
        for scope in dhcpd:
            cidr = ctx.iface_cidr(scope.tag)
            rng = f"{_t(scope, 'range/from')}-{_t(scope, 'range/to')}" if _t(scope, "range/from") else ""
            dns = ", ".join(x.text.strip() for x in scope.findall("dnsserver") if x.text and x.text.strip())
            gw = _t(scope, "gateway") or (cidr.split("/")[0] if cidr else "")
            lease = _t(scope, "defaultleasetime") or "7200"
            rows.append([ctx.friendly(scope.tag), _network(cidr) or "", rng, gw, dns or "interface IP / resolver",
                         f"{lease}s", str(len(scope.findall("staticmap"))),
                         "enabled" if _has(scope, "enable") else "disabled"])
    for sn in ctx.mvc_find("Kea/dhcp4/subnets/subnet4"):
        rows.append([_t(sn, "description") or "", _t(sn, "subnet") or "", ", ".join(_split(_t(sn, "pools"))),
                     _t(sn, "option_data/routers") or "", _t(sn, "option_data/domain_name_servers") or "", "", "",
                     "enabled (Kea)" if _on(ctx.mvc.find("Kea/dhcp4/general") if ctx.mvc is not None else None,
                                            "enabled") else "configured (Kea)"])
    if rows:
        dev.dhcp_scopes.append(m.Table(title="DHCP server scopes", columns=[
            "Interface", "Network", "Range", "Gateway", "DNS", "Lease", "Reservations", "Status"], rows=rows))


def _services(dev: m.Device, ctx: _Ctx) -> None:
    mg = dev.management
    sl = ctx.root.find("syslog")
    if sl is not None and _has(sl, "enable"):
        for k in ("remoteserver", "remoteserver2", "remoteserver3"):
            if _t(sl, k):
                mg.syslog_servers.append(_t(sl, k) or "")
    for d in ctx.mvc_find("Syslog/destinations/destination"):
        if _on(d, "enabled") and _t(d, "hostname"):
            mg.syslog_servers.append(f"{_t(d, 'hostname')}:{_t(d, 'port') or '514'}/{_t(d, 'transport') or 'udp4'}")
    sn = mg.snmp
    sd = ctx.root.find("snmpd")
    if sd is not None and _has(sd, "enable"):
        sn.enabled = True
        sn.versions = ["v1", "v2c"]
        if _t(sd, "rocommunity"):
            sn.communities.append(f"{mask_value(_t(sd, 'rocommunity'))} (RO)")
        if _has(sd, "trapenable") and _t(sd, "trapserver"):
            sn.trap_hosts.append(_t(sd, "trapserver") or "")
        sn.location, sn.contact = _t(sd, "syslocation"), _t(sd, "syscontact")
        dev.location = dev.location or sn.location
    for g in ctx.mvc_find("netsnmp/general"):
        if _on(g, "enabled"):
            sn.enabled = True
            sn.versions = ["v1", "v2c"]
            if _t(g, "community"):
                sn.communities.append(f"{mask_value(_t(g, 'community'))} (RO)")
            sn.location, sn.contact = _t(g, "syslocation"), _t(g, "syscontact")
            dev.location = dev.location or sn.location
    for u in ctx.mvc_find("netsnmp/user/users/user"):
        if _on(u, "enabled"):
            sn.versions = sorted(set(sn.versions) | {"v3"})
            sn.v3_users.append(f"{_t(u, 'username')} (authPriv)")


def _extras(dev: m.Device, ctx: _Ctx) -> None:
    s = ctx.system
    facts = []
    if _t(ctx.root, "version"):
        facts.append(m.Fact(key="config.xml version", value=_t(ctx.root, "version") or ""))
    if s is not None:
        for key, path in (("Web GUI protocol", "webgui/protocol"), ("Web GUI port", "webgui/port"),
                          ("SSH port", "ssh/port"), ("Optimization", "optimization"),
                          ("Disable anti-lockout", "webgui/noantilockout")):
            v = _t(s, path)
            if v is not None or (path.endswith("noantilockout") and s.find(path) is not None):
                facts.append(m.Fact(key=key, value=v or "yes"))
        if _t(s, "ssh/sshdkeyonly") == "enabled" or _t(s, "ssh/passwordauth") == "0":
            facts.append(m.Fact(key="SSH authentication", value="public key only"))
        elif dev.management.ssh:
            facts.append(m.Fact(key="SSH authentication", value="password or key"))
    for key, el in ctx.ifaces.items():
        flags = [f for f in ("blockpriv", "blockbogons") if _has(el, f)]
        if key == "wan":
            facts.append(m.Fact(key="WAN block private / bogon networks", value=", ".join(flags) or "no"))
    if facts:
        dev.sections.append(m.Section(id=f"{dev.platform}-system", title=f"{dev.os_name} system settings",
                                      facts=facts))
    pkgs = [_t(p, "name") or "" for p in ctx.root.findall("installedpackages/package")]
    if pkgs:
        dev.sections.append(m.Section(id=f"{dev.platform}-packages", title="Installed packages",
                                      facts=[m.Fact(key="Packages", value=", ".join(pkgs))]))
    rows = []
    for o in ctx.root.findall("openvpn/openvpn-server") + ctx.root.findall("openvpn/openvpn-client"):
        rows.append([_t(o, "description") or "", _t(o, "mode") or "", f"{_t(o, 'protocol')}/{_t(o, 'local_port')}",
                     ctx.friendly(_t(o, "interface")), _t(o, "tunnel_network") or "",
                     (_t(o, "data_ciphers") or _t(o, "crypto") or "").replace(",", ", "), _t(o, "digest") or "",
                     _t(o, "dh_length") or "", _t(o, "tls_type") or ("tls" if _t(o, "tls") else "")])
    if rows:
        dev.sections.append(m.Section(id=f"{dev.platform}-openvpn", title="OpenVPN instances", tables=[
            m.Table(columns=["Description", "Mode", "Protocol/port", "Interface", "Tunnel network", "Ciphers",
                             "Digest", "DH", "TLS key"], rows=rows)]))
    vips = [[_t(v, "mode") or "", ctx.friendly(_t(v, "interface")), f"{_t(v, 'subnet')}/{_t(v, 'subnet_bits')}",
             _t(v, "vhid") or "", _t(v, "descr") or ""] for v in ctx.root.findall("virtualip/vip")]
    if vips:
        dev.sections.append(m.Section(id=f"{dev.platform}-vips", title="Virtual IPs", tables=[
            m.Table(columns=["Type", "Interface", "Address", "VHID", "Description"], rows=vips)]))


register(PfSenseDriver())
register(OPNsenseDriver())
