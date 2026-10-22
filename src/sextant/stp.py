"""Spanning-tree view of a site: which bridge is root for which VLANs, and which links forward or block.

Built from each switch's runtime `show spanning-tree` output (StpInstance) mapped onto the
physical topology. VLANs that share the same root and the same forwarding/blocked links are
grouped into one tree, so a site with 40 VLANs on one MST instance shows one tree, and a
rapid-PVST site shows one tree per distinct root.

Without runtime output the configured bridge priorities give a prediction of the root.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from sextant.drivers._util import compress_vlans, short_ifname
from sextant.model import Device, StpInstance, StpPort
from sextant.topology import Link, Topology, _ifkey, key

DEFAULT_PRIORITY = 32768
PVST_MODES = ("pvst", "rapid-pvst", "rpvst")


@dataclass
class LinkState:
    state: str  # forwarding | blocked | absent | unknown
    blocked_at: str | None = None  # node key whose port blocks
    blocked_port: str | None = None


@dataclass
class Tree:
    vlans: list[int]
    root_mac: str | None
    root_priority: int | None
    root_node: str | None = None  # topology node key when the root is a documented device
    root_inferred: bool = False  # root_node guessed from configured priority (no runtime output from it)
    links: dict[tuple[str, str], LinkState] = field(default_factory=dict)
    parent: dict[str, str] = field(default_factory=dict)  # node -> next hop towards the root (from root ports)
    root_ports: dict[str, str] = field(default_factory=dict)  # node -> root port name
    reporters: list[str] = field(default_factory=list)  # nodes with runtime data for these VLANs
    disagreement: dict[str, str] = field(default_factory=dict)  # node -> root MAC it sees, when it differs

    @property
    def trivial(self) -> bool:
        """One switch alone (the VLAN is not carried to any neighbour): nothing to draw."""
        return len(self.reporters) <= 1 and not any(st.state in ("forwarding", "blocked")
                                                    for st in self.links.values())

    @property
    def vlan_text(self) -> str:
        return compress_vlans(self.vlans) if self.vlans else "all"

    @property
    def base_priority(self) -> int | None:
        """Root priority without the VLAN id PVST adds (extended system ID): 4106 for VLAN 10 -> 4096."""
        p = self.root_priority
        if p is not None and self.vlans and (p - self.vlans[0]) >= 0 and (p - self.vlans[0]) % 4096 == 0:
            return p - self.vlans[0]
        return p

    @property
    def vlan_label(self) -> str:
        """'VLAN 1', 'VLANs 5,10,15' or 'all VLANs'."""
        if not self.vlans:
            return "all VLANs"
        return f"VLAN{'s' if len(self.vlans) > 1 else ''} {self.vlan_text}"

    def default_priority(self) -> bool:
        if self.root_priority is None:
            return False
        return self.root_priority == DEFAULT_PRIORITY or (
            len(self.vlans) >= 1 and all(self.root_priority - v == DEFAULT_PRIORITY for v in self.vlans[:1]))


@dataclass
class Site:
    keys: list[str]
    trees: list[Tree]
    modes: dict[str, str]  # node -> stp mode (from config)
    prediction: str | None = None  # config-only root prediction text
    predicted_root: str | None = None


# --------------------------------------------------------------------------- helpers


def _instance_for(st_instances: list[StpInstance], vlan: int) -> StpInstance | None:
    for inst in st_instances:
        if inst.vlans and vlan in inst.vlans:
            return inst
    for inst in st_instances:  # MST0 / CIST / single RSTP tree without an explicit list: carries everything
        if not inst.vlans or inst.name in ("IST", "MST0", "CIST", "RSTP"):
            return inst
    return None


def _port(inst: StpInstance, d: Device, names: list[str | None]) -> StpPort | None:
    """STP port for a link side: the port itself, or the LAG it belongs to (STP runs on the bundle)."""
    wanted: list[str] = []
    for n in names:
        if not n:
            continue
        wanted.append(_ifkey(n))
        iface = next((i for i in d.interfaces if _ifkey(i.name) == _ifkey(n)), None)
        if iface and iface.lag:
            wanted.append(_ifkey(iface.lag))
    for p in inst.ports:
        if _ifkey(p.interface) in wanted:
            return p
    return None


def _side_ports(ln: Link, side: str) -> list[str | None]:
    ports = [pa if side == "a" else pb for pa, pb in ln.ports]
    lag = ln.lag_a if side == "a" else ln.lag_b
    return ports + ([lag] if lag else [])


def _link_state(topo: Topology, ln: Link, inst_of: dict[str, StpInstance]) -> LinkState:
    seen_any = False
    present = False
    for side in ("a", "b"):
        node = getattr(ln, side)
        inst = inst_of.get(node)
        d = topo.nodes[node].device
        if not inst or not d:
            continue
        seen_any = True
        p = _port(inst, d, _side_ports(ln, side))
        if p is None:
            continue
        present = True
        if p.role in ("alternate", "backup") or p.state in ("blocking", "discarding", "broken"):
            if p.role != "disabled":
                return LinkState("blocked", node, short_ifname(p.interface))
    if not seen_any:
        return LinkState("unknown")
    return LinkState("forwarding" if present else "absent")


def _bridge_owner(snap_devices: list[Device], mac: str | None) -> str | None:
    if not mac:
        return None
    for d in snap_devices:
        st = d.spanning_tree
        if st and (st.bridge_mac == mac or any(i.bridge_mac == mac for i in st.instances)):
            return key(d.hostname)
    return None


def _configured(d: Device, vlan: int) -> int | None:
    st = d.spanning_tree
    if not st or not st.configured_priority:
        return None
    from sextant.drivers._util import expand_vlans

    for k, v in st.configured_priority.items():
        if k.startswith("mst"):
            continue
        if k == "default" or vlan in expand_vlans(k):
            return v
    return DEFAULT_PRIORITY


def _effective(d: Device, vlan: int) -> int | None:
    """Bridge priority this switch advertises for the VLAN (PVST adds the VLAN id, extend system-id)."""
    base = _configured(d, vlan)
    if base is None:
        return None
    mode = (d.spanning_tree.mode or "") if d.spanning_tree else ""
    return base + vlan if any(mode.startswith(x) for x in PVST_MODES) else base


def _guess_root(topo: Topology, keys: list[str], tree: Tree) -> str | None:
    """Root not among switches with runtime data: the one documented switch whose configured priority matches."""
    if tree.root_priority is None or not tree.vlans:
        return None
    vlan = tree.vlans[0]
    cands = []
    for k in keys:
        d = topo.nodes[k].device
        if not d or not d.spanning_tree or d.spanning_tree.instances:
            continue  # switches with runtime data already told us their own bridge MAC
        if d.spanning_tree.mode in (None, "disabled"):
            continue
        if not any(vlan == v.id for v in d.vlans) and d.vlans:
            continue
        if _effective(d, vlan) == tree.root_priority:
            cands.append(k)
    return cands[0] if len(cands) == 1 else None


# --------------------------------------------------------------------------- build


def _routed_link(topo: Topology, ln: Link) -> bool:
    from sextant.model import PortMode

    for side in ("a", "b"):
        d = topo.nodes[getattr(ln, side)].device
        if not d:
            continue
        names = {_ifkey(p) for p in _side_ports(ln, side) if p}
        by_name = {_ifkey(i.name): i for i in d.interfaces}
        modes = set()
        for n in names:
            i = by_name.get(n)
            if i is None:
                continue
            if i.lag and _ifkey(i.lag) in by_name:  # a bundle member takes the bundle's mode
                i = by_name[_ifkey(i.lag)]
            modes.add(i.mode)
        if modes and modes <= {PortMode.routed}:
            return True
    return False


def l2_domains(topo: Topology) -> list[list[str]]:
    """Connected groups over layer-2 links only: routed (L3) links separate spanning-tree domains."""
    adj: dict[str, set[str]] = {k: set() for k in topo.nodes}
    for (a, b), ln in topo.links.items():
        if not _routed_link(topo, ln):
            adj[a].add(b)
            adj[b].add(a)
    seen: set[str] = set()
    out = []
    for k in sorted(topo.nodes):
        if k in seen:
            continue
        stack, comp = [k], []
        while stack:
            cur = stack.pop()
            if cur in seen:
                continue
            seen.add(cur)
            comp.append(cur)
            stack.extend(adj[cur] - seen)
        out.append(sorted(comp))
    return sorted(out, key=lambda g: (-len(g), g[0]))


def build_stp(snap, topo: Topology) -> list[Site]:
    sites = []
    for comp in l2_domains(topo):
        switches = [k for k in comp if topo.nodes[k].device and topo.nodes[k].device.spanning_tree
                    and topo.nodes[k].device.spanning_tree.mode not in (None,)]
        if not switches:
            continue
        modes = {k: topo.nodes[k].device.spanning_tree.mode for k in switches}
        with_data = [k for k in switches if topo.nodes[k].device.spanning_tree.instances]
        site = Site(keys=comp, trees=[], modes=modes)
        if with_data:
            site.trees = _trees(snap, topo, comp, with_data)
        if len(switches) > 1:
            site.prediction, site.predicted_root = _predict(topo, switches)
        if site.trees or site.prediction:
            sites.append(site)
    return sites


def _parent_of(topo: Topology, k: str, inst: StpInstance, comp_links) -> str | None:
    """Neighbour on the other end of this switch's root port."""
    if not inst.root_port or inst.is_root:
        return None
    d = topo.nodes[k].device
    want = _ifkey(inst.root_port)
    for pair, ln in comp_links:
        if k not in pair:
            continue
        side = "a" if pair[0] == k else "b"
        names = {_ifkey(p) for p in _side_ports(ln, side) if p}
        names |= {_ifkey(i.lag) for i in d.interfaces if i.lag and _ifkey(i.name) in names}
        if want in names:
            return pair[1] if side == "a" else pair[0]
    return None


def _trees(snap, topo: Topology, comp: list[str], with_data: list[str]) -> list[Tree]:
    vlans: set[int] = set()
    for k in with_data:
        st = topo.nodes[k].device.spanning_tree
        for inst in st.instances:
            vlans.update(inst.vlans)
        if any(not i.vlans for i in st.instances):
            vlans.update(v.id for v in topo.nodes[k].device.vlans)
    comp_links = [(pair, ln) for pair, ln in topo.links.items()
                  if pair[0] in comp and pair[1] in comp and not _routed_link(topo, ln)]
    groups: dict[tuple, Tree] = {}
    for vlan in sorted(vlans):
        inst_of = {}
        for k in with_data:
            inst = _instance_for(topo.nodes[k].device.spanning_tree.instances, vlan)
            if inst:
                inst_of[k] = inst
        if not inst_of:
            continue
        # a VLAN that is not carried between two switches forms separate trees: split by the root each one sees
        by_root: dict[tuple, dict[str, StpInstance]] = {}
        for k, inst in inst_of.items():
            by_root.setdefault((inst.root_mac, inst.root_priority), {})[k] = inst
        for (root_mac, root_prio), members in by_root.items():
            links = [(pair, ln) for pair, ln in comp_links if pair[0] in members or pair[1] in members]
            states = {pair: _link_state(topo, ln, members) for pair, ln in links}
            sig = (root_mac, tuple(sorted((p, st.state, st.blocked_at or "") for p, st in states.items())),
                   tuple(sorted((k, i.root_port or "") for k, i in members.items())))
            tree = groups.get(sig)
            if tree is None:
                tree = Tree(vlans=[], root_mac=root_mac, root_priority=root_prio, links=states,
                            reporters=sorted(members))
                for k, inst in members.items():
                    if inst.root_port and not inst.is_root:
                        tree.root_ports[k] = short_ifname(inst.root_port)
                        par = _parent_of(topo, k, inst, comp_links)
                        if par:
                            tree.parent[k] = par
                groups[sig] = tree
            tree.vlans.append(vlan)
        # conflict: two linked switches both forward this VLAN on the link but see different roots
        if len(by_root) > 1:
            for pair, ln in comp_links:
                a, b = pair
                if a in inst_of and b in inst_of and inst_of[a].root_mac != inst_of[b].root_mac:
                    pa = _port(inst_of[a], topo.nodes[a].device, _side_ports(ln, "a"))
                    pb = _port(inst_of[b], topo.nodes[b].device, _side_ports(ln, "b"))
                    if pa and pb and pa.state == "forwarding" and pb.state == "forwarding":
                        for t in groups.values():
                            if vlan in t.vlans and (a in t.reporters or b in t.reporters):
                                other = b if a in t.reporters else a
                                t.disagreement[other] = inst_of[other].root_mac or "?"
    trees = list(groups.values())
    for t in trees:
        t.root_node = _bridge_owner(snap.devices, t.root_mac)
        if t.root_node is None:  # also look at switches outside this group: an uplink nobody described
            t.root_node = _guess_root(topo, comp, t) or _guess_root(topo, [k for k in topo.nodes if k not in comp], t)
            t.root_inferred = t.root_node is not None
    trees.sort(key=lambda t: (t.vlans[0] if t.vlans else 0, t.root_mac or ""))
    return trees


def _predict(topo: Topology, switches: list[str]) -> tuple[str | None, str | None]:
    """Config-only: lowest configured priority wins; ties are decided by MAC address (not in the config)."""
    prios = {}
    for k in switches:
        d = topo.nodes[k].device
        p = _configured(d, 1)
        if p is not None and d.spanning_tree.mode != "disabled":
            prios[k] = p
    if not prios:
        return None, None
    best = min(prios.values())
    winners = sorted(k for k, p in prios.items() if p == best)
    names = [topo.nodes[k].name for k in winners]
    if len(winners) == 1:
        return f"{names[0]} has the lowest configured bridge priority ({best}) and should be root.", winners[0]
    return (f"{len(winners)} switches share the lowest priority ({best}): the root is decided by the lowest "
            f"MAC address, which is not in the configuration ({', '.join(names)}).", None)
