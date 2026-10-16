"""Site topology: devices + links + layers, built from every device in a snapshot.

Links come from (strongest first):
  1. CDP/LLDP neighbors,
  2. interface descriptions that name another documented device ("UPLINK kis-dist-sw01 Te1/0/5"),
  3. point-to-point routed subnets (/30, /31) shared by two devices.
so a folder of plain running-configs still produces a topology.

Layers: an explicit `Device.layer` (inventory `layer:`) wins, then the device role
(firewall/router -> edge, hypervisor/server -> compute), then hostname hints
(core/dist/agg/acc...), then graph distance from the edge (core -> distribution -> access).
"""

from __future__ import annotations

import ipaddress
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field

from sextant.drivers._util import short_ifname
from sextant.model import Device, DeviceRole, PortMode, Snapshot

LAYERS = ["edge", "core", "distribution", "access", "compute", "other"]
LAYER_LABEL = {"edge": "Edge / firewall", "core": "Core", "distribution": "Distribution", "access": "Access",
               "compute": "Compute", "other": "Other"}
SOURCE_LABEL = {"cdp": "CDP", "lldp": "LLDP", "description": "Description",
                "description-partial": "Description (partial name)", "subnet": "Routed /30"}

_NAME_HINTS = [
    ("core", re.compile(r"(^|[-_.])(core|cor|cr|cs|bb|backbone|spine)\d*($|[-_.])", re.I)),
    ("distribution", re.compile(r"(^|[-_.])(dist|distr|distribution|ds|agg|aggr|aggregation|dis)\d*($|[-_.])", re.I)),
    ("access", re.compile(r"(^|[-_.])(acc|access|as|asw|edge|leaf|floor|fl)\d*($|[-_.])", re.I)),
]
_NET_PLATFORM = re.compile(r"(WS-C|C9[2-6]\d\d(?!AX)|N[3579]K|Nexus|Catalyst|ArubaOS-CX|Aruba \d{4}|JL\d{3}|"
                           r"EX\d{4}|QFX|ProCurve|cisco IOS|switch)", re.I)
_AP = re.compile(r"(AIR-|C91\d\d|AP\d|Aruba AP|-ap-|^ap[-\d]|access point|MR\d\d|UAP)", re.I)
_PHONE = re.compile(r"(IP Phone|SEP[0-9A-F]{6}|Polycom|Yealink|phone)", re.I)
_HOST = re.compile(r"(VMware ESX|ESXi|vmnic|Linux|Windows|Proxmox|Hyper-V)", re.I)
_LAGNAME = re.compile(r"^(po|port-channel|trk|lag|ae|bond)\d+$", re.I)
_TUNNEL = re.compile(r"^(tunnel|tun|vti|ipsec|gre|st\d|wg|ovpn)", re.I)
_IFNAME = re.compile(r"\b((?:[A-Za-z][A-Za-z-]*)?\d+(?:/\d+){1,3}(?:\.\d+)?|(?:Po|port-channel|Trk|lag|ae)\d+)\b", re.I)


def key(name: str | None) -> str:
    """Normalized node key: 'STO-CORE-SW01.corp.example(FDO123)' -> 'sto-core-sw01'."""
    return re.split(r"[.(\s]", (name or "").strip())[0].lower()


def _ifkey(name: str | None) -> str:
    return short_ifname(name or "").lower().replace(" ", "")


@dataclass
class Node:
    key: str
    name: str
    layer: str
    device: Device | None = None
    kind: str = "device"  # device | ghost (network device seen but not documented) | host (hypervisor host)
    model: str | None = None
    mgmt_ip: str | None = None
    parent: str | None = None  # hosts: the vCenter/cluster device they belong to
    endpoints: Counter = field(default_factory=Counter)  # APs, phones, other on this switch
    layer_reason: str = ""

    @property
    def documented(self) -> bool:
        return self.device is not None


@dataclass
class Link:
    a: str
    b: str
    ports: list[tuple[str, str | None]] = field(default_factory=list)  # (port on a, port on b)
    sources: set[str] = field(default_factory=set)
    lag_a: str | None = None
    lag_b: str | None = None

    @property
    def inferred(self) -> bool:
        return not (self.sources & {"cdp", "lldp"})

    def label(self) -> str:
        n = len(self.ports)
        lag = self.lag_a or self.lag_b
        return (f"{n}× " if n > 1 else "") + (lag or "")


@dataclass
class Topology:
    nodes: dict[str, Node] = field(default_factory=dict)
    links: dict[tuple[str, str], Link] = field(default_factory=dict)

    def neighbors(self, k: str) -> set[str]:
        out = set()
        for a, b in self.links:
            if a == k:
                out.add(b)
            elif b == k:
                out.add(a)
        return out

    def components(self) -> list[list[str]]:
        """Connected groups of nodes (largest first); single unconnected devices are their own group."""
        seen: set[str] = set()
        groups = []
        for k in sorted(self.nodes):
            if k in seen:
                continue
            stack, comp = [k], []
            while stack:
                cur = stack.pop()
                if cur in seen:
                    continue
                seen.add(cur)
                comp.append(cur)
                stack.extend(self.neighbors(cur) - seen)
            groups.append(sorted(comp))
        return sorted(groups, key=lambda g: (-len(g), g[0]))

    def by_layer(self, keys: list[str] | None = None) -> dict[str, list[Node]]:
        out: dict[str, list[Node]] = defaultdict(list)
        for k in keys or list(self.nodes):
            n = self.nodes[k]
            out[n.layer].append(n)
        return {lay: sorted(out[lay], key=lambda n: n.name.lower()) for lay in LAYERS if out.get(lay)}

    def link(self, a: str, b: str) -> Link | None:
        return self.links.get(tuple(sorted((a, b))))  # type: ignore[arg-type]

    def uplinks(self, k: str) -> list[str]:
        """Neighbors in a layer above this node's layer."""
        me = LAYERS.index(self.nodes[k].layer)
        return sorted(n for n in self.neighbors(k) if LAYERS.index(self.nodes[n].layer) < me)


def _role_layer(d: Device) -> str | None:
    if d.role in (DeviceRole.firewall, DeviceRole.router):
        return "edge"
    if d.role in (DeviceRole.hypervisor, DeviceRole.server, DeviceRole.storage):
        return "compute"
    if d.role == DeviceRole.wireless:
        return "access"
    if d.role == DeviceRole.other:
        return "other"
    return None


def _name_layer(name: str) -> str | None:
    for layer, pat in _NAME_HINTS:
        if pat.search(name):
            return layer
    return None


def build_topology(snap: Snapshot) -> Topology:
    topo = Topology()
    devices = {key(d.hostname): d for d in snap.devices}

    for k, d in devices.items():
        layer = d.layer or _role_layer(d)
        reason = "set in inventory" if d.layer else ("role" if layer else "")
        topo.nodes[k] = Node(k, d.hostname, layer or "", d, model=d.model, mgmt_ip=d.mgmt_ip, layer_reason=reason)
    # hypervisor hosts as compute nodes, so a switch's "vmnic0 -> esx01" lands on a known host
    for d in snap.devices:
        if d.virtualization:
            for h in d.virtualization.hosts:
                hk = key(h.name)
                if hk not in topo.nodes:
                    topo.nodes[hk] = Node(hk, h.name.split(".")[0], "compute", kind="host", model=h.vendor_model,
                                          mgmt_ip=h.mgmt_ip, parent=d.hostname, layer_reason="hypervisor host")

    def add(a: str, a_port: str | None, b: str, b_port: str | None, source: str) -> None:
        if a == b:
            return
        pair = tuple(sorted((a, b)))
        ln = topo.links.setdefault(pair, Link(pair[0], pair[1]))  # type: ignore[arg-type]
        pa, pb = (a_port, b_port) if pair[0] == a else (b_port, a_port)
        pa_k, pb_k = _ifkey(pa), _ifkey(pb)
        if _LAGNAME.match(pa_k):  # "PO1" in a member's description names the bundle, not one cable
            pa_k = ""
        if _LAGNAME.match(pb_k):
            pb_k = ""
        for i, (x, y) in enumerate(ln.ports):
            if (pa_k and _ifkey(x) == pa_k) or (pb_k and y and _ifkey(y) == pb_k):
                ln.ports[i] = (x or pa or "", y or pb)  # same physical link seen from the other side
                break
        else:
            ln.ports.append((pa or "", pb))
        ln.sources.add(source)

    # 1. CDP / LLDP
    for k, d in devices.items():
        for n in d.neighbors:
            rk = key(n.remote_device)
            if not rk:
                continue
            if rk not in topo.nodes:
                text = f"{n.remote_device} {n.remote_platform or ''}"
                if _AP.search(text):
                    topo.nodes[k].endpoints["AP"] += 1
                    continue
                if _PHONE.search(text):
                    topo.nodes[k].endpoints["phone"] += 1
                    continue
                if _NET_PLATFORM.search(n.remote_platform or "") or _name_layer(n.remote_device):
                    topo.nodes[rk] = Node(rk, n.remote_device.split(".")[0].split("(")[0], "", kind="ghost",
                                          model=n.remote_platform, mgmt_ip=n.remote_ip)
                elif _HOST.search(text):
                    topo.nodes[rk] = Node(rk, n.remote_device.split(".")[0], "compute", kind="host",
                                          model=n.remote_platform, mgmt_ip=n.remote_ip, layer_reason="LLDP/CDP")
                else:
                    topo.nodes[k].endpoints["other"] += 1
                    continue
            add(k, n.local_port, rk, n.remote_port, (n.protocol or "lldp").lower())

    # 2. interface descriptions naming another documented device
    names = sorted(devices, key=len, reverse=True)
    own_tokens = {k: set(_name_tokens(k)) for k in devices}
    owners: dict[str, set[str]] = defaultdict(set)
    for k, toks in own_tokens.items():
        for t in toks:
            owners[t].add(k)
    partial = {t: next(iter(ks)) for t, ks in sorted(owners.items(), key=lambda x: -len(x[0])) if len(ks) == 1}
    for k, d in devices.items():
        covered = set()
        for (a, b), ln in topo.links.items():
            for pa, pb in ln.ports:
                covered.add(_ifkey(pa) if a == k else _ifkey(pb) if b == k else "")
        # physical ports first; a LAG's own description only counts when its members said nothing
        for i in sorted(d.interfaces, key=lambda x: x.kind == "lag"):
            if not i.description or _ifkey(i.name) in covered or i.kind in ("vlan", "loopback", "tunnel"):
                continue
            if _TUNNEL.match(i.name):
                continue  # VPN tunnels are not cabling and would merge separate sites
            desc = i.description.lower()
            hit = None
            for other in names:
                if other == k:
                    continue
                pos = re.search(rf"(?<![\w-]){re.escape(other)}(?![\w-])", desc)
                if pos:
                    hit = (other, pos, "description")
                    break
            if not hit:  # "C3560", "3560XC .5", "Rymdstedt-2530": a part of a hostname that only one device has
                for token, other in partial.items():
                    if other == k or token in own_tokens[k]:
                        continue
                    pat = rf"(?<!\d){token}(?!\d)" if token.isdigit() else rf"(?<![a-z0-9]){re.escape(token)}(?![a-z0-9])"
                    pos = re.search(pat, desc)
                    if pos:
                        hit = (other, pos, "description-partial")
                        break
            if hit:
                other, pos, source = hit
                if i.kind == "lag" and topo.link(k, other):
                    continue
                mt = _IFNAME.search(i.description[pos.end():])
                remote = mt.group(1) if mt else None
                if remote and i.lag and _ifkey(remote) == _ifkey(i.lag):
                    remote = None  # "PA01 - PO2" on a member of our own Po2
                add(k, i.name, other, remote, source)

    # 3. routed point-to-point subnets
    p2p: dict[str, list[tuple[str, str]]] = defaultdict(list)
    for k, d in devices.items():
        for i in d.interfaces:
            for ip in i.ipv4:
                try:
                    net = ipaddress.IPv4Interface(ip.address).network
                except ValueError:
                    continue
                if net.prefixlen >= 30:
                    p2p[str(net)].append((k, i.name))
    for members in p2p.values():
        if len(members) == 2 and members[0][0] != members[1][0]:
            (a, pa), (b, pb) = members
            if not topo.link(a, b):
                add(a, pa, b, pb, "subnet")

    _pair_one_sided(topo)
    _attach_lags(topo)
    _assign_layers(topo)
    return topo


_GENERIC = {"switch", "core", "dist", "access", "acc", "agg", "edge", "firewall", "gw", "router", "rtr", "stack",
            "lab", "test", "host", "server", "srv", "prod", "mgmt", "uplink", "link", "port", "trunk", "vlan"}


def _name_tokens(k: str) -> list[str]:
    """Distinctive parts of a hostname: 'kattvind-3560' -> ['kattvind', '3560']."""
    out = []
    for t in re.split(r"[-_.\s]+", k.lower()):
        if t in _GENERIC or len(t) < 3 or (t.isdigit() and len(t) < 4):
            continue
        out.append(t)
    return out


def _lag_of(topo: Topology, node: str, port: str | None) -> str | None:
    d = topo.nodes[node].device
    if not d or not port:
        return None
    want = _ifkey(port)
    iface = next((i for i in d.interfaces if _ifkey(i.name) == want), None)
    return short_ifname(iface.lag) if iface and iface.lag else None


def _pair_one_sided(topo: Topology) -> None:
    """Both ends described the link but not the remote port: join ('Gi1/0/13', 'PO1') with ('', '9').

    LAG members pair with LAG members, single ports with single ports; the order inside a LAG is a guess
    (descriptions rarely say), which the Via column marks as inferred.
    """
    for ln in topo.links.values():
        a_side = [p for p in ln.ports if p[0] and (not p[1] or _LAGNAME.match(_ifkey(p[1])))]
        b_side = [p for p in ln.ports if not p[0] and p[1]]
        if not (a_side and b_side):
            continue
        rest = [p for p in ln.ports if p not in a_side and p not in b_side]
        pairs: list[tuple[str, str | None]] = []
        for want_lag in (True, False):
            aa = [p for p in a_side if bool(_lag_of(topo, ln.a, p[0])) == want_lag]
            bb = [p for p in b_side if bool(_lag_of(topo, ln.b, p[1])) == want_lag]
            for x, y in zip(aa, bb, strict=False):
                pairs.append((x[0], y[1]))
                a_side.remove(x)
                b_side.remove(y)
        ln.ports = rest + pairs + [(p[0], None) for p in a_side] + b_side


def _attach_lags(topo: Topology) -> None:
    for ln in topo.links.values():
        for side in ("a", "b"):
            node = topo.nodes[getattr(ln, side)]
            if not node.device:
                continue
            by_name = {_ifkey(i.name): i for i in node.device.interfaces}
            lags = set()
            for pa, pb in ln.ports:
                port = pa if side == "a" else pb
                iface = by_name.get(_ifkey(port))
                if iface and iface.lag:
                    lags.add(short_ifname(iface.lag))
                elif iface and iface.kind == "lag":
                    lags.add(short_ifname(iface.name))
            if len(lags) == 1:
                setattr(ln, f"lag_{side}", lags.pop())


def _assign_layers(topo: Topology) -> None:
    for n in topo.nodes.values():
        if not n.layer:
            hint = _name_layer(n.name)
            if hint:
                n.layer, n.layer_reason = hint, "hostname"
    switches = [k for k, n in topo.nodes.items() if not n.layer]
    if not switches:
        return
    # BFS over switch-like nodes from those adjacent to the edge (or the best-connected switch)
    fabric = set(switches) | {k for k, n in topo.nodes.items() if n.layer in ("core", "distribution", "access")}
    edge = {k for k, n in topo.nodes.items() if n.layer == "edge"}
    depth: dict[str, int] = {}
    for k, n in topo.nodes.items():  # anchor on already-known layers
        if n.layer in ("core", "distribution", "access") and k in fabric:
            depth[k] = ("core", "distribution", "access").index(n.layer)
    frontier = [k for k in fabric if topo.neighbors(k) & edge and k not in depth]
    if not depth and not frontier:
        frontier = _centre(topo, fabric)
    for k in frontier:
        depth.setdefault(k, 0)
    queue = sorted(depth, key=lambda k: depth[k])
    while queue:
        cur = queue.pop(0)
        for nb in sorted(topo.neighbors(cur) & fabric):
            if nb not in depth:
                depth[nb] = depth[cur] + 1
                queue.append(nb)
    max_depth = max(depth.values(), default=0)
    for k in switches:
        dpt = depth.get(k)
        n = topo.nodes[k]
        if dpt is None:
            n.layer, n.layer_reason = "access", "unconnected switch"
        elif max_depth <= 1:  # collapsed core: core + access
            n.layer, n.layer_reason = ("core" if dpt == 0 else "access"), "topology (two-tier)"
        else:
            n.layer = ("core", "distribution", "access")[min(dpt, 2)]
            n.layer_reason = "topology"
    # leaf switches with only one fabric neighbor and many access ports are access, whatever their depth
    for k in switches:
        n = topo.nodes[k]
        d = n.device
        if d and n.layer != "access" and len(topo.neighbors(k) & fabric) == 1:
            access_ports = sum(1 for i in d.interfaces if i.mode == PortMode.access and i.enabled)
            if access_ports >= 8:
                n.layer, n.layer_reason = "access", "topology (leaf)"


def _centre(topo: Topology, fabric: set[str]) -> list[str]:
    """Switches with the smallest eccentricity (max hops to any other switch) in each connected group.

    In a core/distribution/access tree that is the core, without needing hostnames or a firewall.
    """
    def hops(start: str) -> dict[str, int]:
        dist, queue = {start: 0}, [start]
        while queue:
            cur = queue.pop(0)
            for nb in topo.neighbors(cur) & fabric:
                if nb not in dist:
                    dist[nb] = dist[cur] + 1
                    queue.append(nb)
        return dist

    centres: list[str] = []
    seen: set[str] = set()
    for k in sorted(fabric):
        if k in seen:
            continue
        group = hops(k)
        seen |= set(group)
        ecc = {n: max(hops(n).values()) for n in group}
        best = min(ecc.values())
        centres += [n for n, e in ecc.items() if e == best]
    return centres


def site_name(topo: Topology, keys: list[str]) -> str:
    """A readable name for a group of nodes: the common site, else the common hostname prefix."""
    sites = Counter(topo.nodes[k].device.site for k in keys if topo.nodes[k].device and topo.nodes[k].device.site)
    if sites:
        return sites.most_common(1)[0][0]
    prefixes = Counter(re.split(r"[-_.]", topo.nodes[k].name)[0].upper() for k in keys)
    return prefixes.most_common(1)[0][0] if prefixes else "Site"
