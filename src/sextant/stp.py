"""Spanning-tree view of a site: which bridge is root for which VLANs, and which links forward or block.

Built from each switch's runtime `show spanning-tree` output (StpInstance) mapped onto the
physical topology. VLANs that share the same root and the same forwarding/blocked links are
grouped into one tree, so a site with 40 VLANs on one MST instance shows one tree, and a
rapid-PVST site shows one tree per distinct root. VLANs whose trees only differ because a trunk
does not carry some of them (pruning) are merged; those links are marked as partial.

VLAN 1, the default VLAN that normally carries no user traffic, always gets a tree of its own.

Ports in a ring protocol (MRP, REP, ERPS) run no spanning tree: those links are drawn as ring links,
and a ring switch that only sees itself as root because no BPDUs cross the ring is not a root of
anything the rest of the network uses.

Without runtime output the configured bridge priorities give a prediction of the root.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from functools import lru_cache

from sextant.drivers._util import compress_vlans, short_ifname
from sextant.model import Device, StpInstance, StpPort
from sextant.topology import Link, Topology, ifkey, key

DEFAULT_PRIORITY = 32768
PVST_MODES = ("pvst", "rapid-pvst", "rpvst")


@dataclass
class LinkState:
    state: str  # forwarding | blocked | absent | unknown | ring (ring protocol port, no STP)
    blocked_at: str | None = None  # node key whose port blocks
    blocked_port: str | None = None
    vlans: list[int] | None = None  # set when the link carries only some of the tree's VLANs
    ring: str | None = None  # "MRP ring 1"


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
    root_entry: tuple[str, str] | None = None  # (switch, port) an outside root is reached through
    root_label: str | None = None  # an outside root's name, when a neighbour table knows its MAC
    root_documented: bool = False  # the root is an imported device (it may still lack a documented link)
    pvst: bool = False  # per-VLAN instances: a bridge advertises its priority plus the VLAN id
    ring: str | None = None  # root only of itself because its links are ring links ("MRP ring 1")

    @property
    def default_vlan(self) -> bool:
        """VLAN 1 alone: documented apart from the trees that carry traffic."""
        return self.vlans == [1]

    @property
    def trivial(self) -> bool:
        """One switch alone (the VLAN is not carried to any neighbour) and root itself: nothing to draw.
        A switch that reaches its root through a port is not alone, even if that root was not imported."""
        return len(self.reporters) <= 1 and not self.root_entry and not any(
            st.state in ("forwarding", "blocked") for st in self.links.values())

    @property
    def outside_root(self) -> bool:
        """The root is not one of the imported switches (nor inferred to be one)."""
        return self.root_entry is not None and not self.root_inferred and not self.root_documented

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
        """The root advertises the default priority, so the lowest MAC address made it root. On PVST VLANs
        that is 32768 + VLAN id; a bridge advertising a plain 32768 there won on priority, not on MAC."""
        if self.root_priority is None:
            return False
        if self.pvst and self.vlans:
            return self.root_priority == DEFAULT_PRIORITY + self.vlans[0]
        return self.root_priority == DEFAULT_PRIORITY


@dataclass
class Site:
    keys: list[str]
    trees: list[Tree]
    modes: dict[str, str]  # node -> stp mode (from config)
    prediction: str | None = None  # config-only root prediction text
    predicted_root: str | None = None
    vlan_notes: dict[int, str] = field(default_factory=dict)  # VLANs without a drawn tree: why


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
        wanted.append(ifkey(n))
        iface = next((i for i in d.interfaces if ifkey(i.name) == ifkey(n)), None)
        if iface and iface.lag:
            wanted.append(ifkey(iface.lag))
    for p in inst.ports:
        if ifkey(p.interface) in wanted:
            return p
    return None


def _side_ports(ln: Link, side: str) -> list[str | None]:
    ports = [pa if side == "a" else pb for pa, pb in ln.ports]
    lag = ln.lag_a if side == "a" else ln.lag_b
    return ports + ([lag] if lag else [])


def _iface_carries(i, vlan: int) -> bool | None:
    """Whether the configuration puts this VLAN on the port; None when the config does not say."""
    from sextant.model import PortMode

    if i.mode == PortMode.access:
        return vlan == (i.access_vlan or 1)
    if i.mode == PortMode.trunk:
        if vlan == i.native():
            return True
        tv = (i.trunk_vlans or "").strip().lower()
        if not tv or tv in ("all", "1-4094", "1-4095"):
            return True
        return vlan in _vlan_set(tv)
    return None


def _carries(d: Device, names: list[str | None], vlan: int, ifmap: dict[str, dict]) -> bool | None:
    """Config check for one side of a link (the port, or the LAG it is bundled in)."""
    by_name = ifmap.setdefault(d.hostname, {ifkey(i.name): i for i in d.interfaces})
    verdict = None
    for n in names:
        i = by_name.get(ifkey(n)) if n else None
        if i is None:
            continue
        if i.lag and ifkey(i.lag) in by_name:
            i = by_name[ifkey(i.lag)]
        c = _iface_carries(i, vlan)
        if c:
            return True
        if c is False:
            verdict = False
    return verdict


def _link_state(topo: Topology, ln: Link, inst_of: dict[str, StpInstance], carried: bool = True) -> LinkState:
    """State of a link for one VLAN. `carried` False: one end's config does not put the VLAN on the
    link (an MST/RSTP instance still lists the port, since it covers every VLAN)."""
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
        if p is None or p.role == "disabled" or p.state == "disabled":
            continue  # not in this instance, or listed but down (AOS-S lists every port)
        present = True
        if carried and (p.role in ("alternate", "backup") or p.state in ("blocking", "discarding", "broken")):
            return LinkState("blocked", node, short_ifname(p.interface))
    if not seen_any:
        return LinkState("unknown")
    return LinkState("forwarding" if present and carried else "absent")


def _mac_int(mac: str | None) -> int | None:
    from sextant.drivers._stp import norm_mac

    m = norm_mac(mac)
    return int(m.replace(".", ""), 16) if m else None


def _neighbour_with_mac(devices: list[Device], mac: str | None):
    """The CDP/LLDP neighbour whose chassis ID is this bridge MAC (or within a few addresses of it:
    switches take the bridge MAC from their base MAC range)."""
    want = _mac_int(mac)
    if want is None:
        return None
    best = None
    for d in devices:
        for n in d.neighbors:
            got = _mac_int(n.remote_chassis)
            if got is not None and abs(got - want) <= 64 and (best is None or abs(got - want) < best[0]):
                best = (abs(got - want), n)
    return best[1] if best else None


def _root_entry(topo: Topology, t: Tree, ifmap: dict) -> tuple[str, str] | None:
    """Where the documented switches meet a root they do not include: the reporting switch whose root
    port leads to no other reporting switch, provided the port carries these VLANs (an MST instance
    names a root port for VLANs the port does not carry). Any of the tree's VLANs will do: an MST switch
    whose root port is an access port in VLAN 200 takes every VLAN's root from there."""
    ends = [(k, t.root_ports[k]) for k in t.reporters if t.root_ports.get(k) and t.parent.get(k) not in t.reporters]
    for k, port in ends:
        d = topo.nodes[k].device
        if d and any(_carries(d, [port], v, ifmap) is not False for v in t.vlans or [1]):
            return k, port
    for k, port in ends:  # MST/RSTP: the CIST root port is every VLAN's, carried on it or not
        st = topo.nodes[k].device.spanning_tree if topo.nodes[k].device else None
        if st and not any((st.mode or "").startswith(m) for m in PVST_MODES + ("pvst",)):
            return k, port
    return None


def _bridge_owner(snap_devices: list[Device], mac: str | None) -> str | None:
    if not mac:
        return None
    for d in snap_devices:
        st = d.spanning_tree
        if st and (st.bridge_mac == mac or any(i.bridge_mac == mac for i in st.instances)):
            return key(d.hostname)
    return None


@lru_cache(maxsize=1024)
def _vlan_set(spec: str) -> frozenset[int]:
    from sextant.drivers._util import expand_vlans

    return frozenset(expand_vlans(spec))


def _configured(d: Device, vlan: int) -> int | None:
    st = d.spanning_tree
    if not st or not st.configured_priority:
        return None
    for k, v in st.configured_priority.items():  # a VLAN-specific setting beats the default
        if k != "default" and not k.startswith("mst") and vlan in _vlan_set(k):
            return v
    if (st.mode or "").startswith("mst"):  # MST: the CIST (instance 0) priority, "mst 0" or "mst 0-1"
        for k, v in st.configured_priority.items():
            if k.startswith("mst ") and 0 in _vlan_set(k[4:].strip()):
                return v
    return st.configured_priority.get("default", DEFAULT_PRIORITY)


def bridge_priority(d: Device | None, vlan: int) -> tuple[int, bool] | None:
    """(priority, from_runtime) this switch uses for the VLAN, without the system-id extension
    PVST/MST add (32778 for VLAN 10 -> 32768). Runtime output wins over the configuration."""
    st = d.spanning_tree if d else None
    if not st:
        return None
    inst = _instance_for(st.instances, vlan) if st.instances else None
    if inst and inst.bridge_priority is not None:
        return inst.bridge_priority - inst.bridge_priority % 4096, True
    p = _configured(d, vlan)
    return (p, False) if p is not None else None


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
        names = {ifkey(p) for p in _side_ports(ln, side) if p}
        by_name = {ifkey(i.name): i for i in d.interfaces}
        modes = set()
        for n in names:
            i = by_name.get(n)
            if i is None:
                continue
            if i.lag and ifkey(i.lag) in by_name:  # a bundle member takes the bundle's mode
                i = by_name[ifkey(i.lag)]
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
        site.vlan_notes = _vlan_notes(topo, site, switches, with_data)
        if site.trees or site.prediction:
            sites.append(site)
    return sites


def _vlan_notes(topo: Topology, site: Site, switches: list[str], with_data: list[str]) -> dict[int, str]:
    """Every VLAN of the domain that is in no drawn tree, with the reason: nothing goes missing silently."""
    name = {k: topo.nodes[k].name for k in site.keys}
    on: dict[int, list[str]] = {}
    for k in switches:
        for v in topo.nodes[k].device.vlans:
            on.setdefault(v.id, []).append(k)
    for t in site.trees:
        for v in t.vlans:
            on.setdefault(v, [])
    drawn = {v for t in site.trees if not t.trivial for v in t.vlans}
    notes: dict[int, str] = {}
    for vlan in sorted(on):
        if vlan in drawn:
            continue
        rings = sorted({t.ring for t in site.trees if t.ring and vlan in t.vlans})
        local = [k for t in site.trees if vlan in t.vlans and t.trivial and not t.ring for k in t.reporters]
        has = on[vlan]
        off = [k for k in has if topo.nodes[k].device.spanning_tree.mode == "disabled"
               or vlan in topo.nodes[k].device.spanning_tree.disabled_vlans]
        if rings:
            notes[vlan] = (f"{', '.join(rings)}: spanning tree does not run on the ring ports, each ring switch "
                           "is only its own root" + (f"; local to {', '.join(name[k] for k in local)}" if local else ""))
        elif local:
            notes[vlan] = f"Local to {', '.join(sorted(name[k] for k in local))} (not on a link between switches)"
        elif has and len(off) == len(has):
            notes[vlan] = f"Spanning tree disabled on {', '.join(sorted(name[k] for k in off))}"
        elif has and not set(has) & set(with_data):
            notes[vlan] = f"No 'show spanning-tree' output from {', '.join(sorted(name[k] for k in has))}"
        else:
            notes[vlan] = "No switch reports a spanning-tree instance for this VLAN" + (
                f" (disabled on {', '.join(sorted(name[k] for k in off))})" if off else "")
    return notes


def _parent_of(topo: Topology, k: str, inst: StpInstance, comp_links) -> str | None:
    """Neighbour on the other end of this switch's root port."""
    if not inst.root_port or inst.is_root:
        return None
    d = topo.nodes[k].device
    want = ifkey(inst.root_port)
    for pair, ln in comp_links:
        if k not in pair:
            continue
        side = "a" if pair[0] == k else "b"
        names = {ifkey(p) for p in _side_ports(ln, side) if p}
        names |= {ifkey(i.lag) for i in d.interfaces if i.lag and ifkey(i.name) in names}
        if want in names:
            return pair[1] if side == "a" else pair[0]
    return None


def _domain_vlans(topo: Topology, comp: list[str], with_data: list[str]) -> list[int]:
    """VLANs to evaluate: every PVST instance, plus the configured VLANs an MST/RSTP instance covers.
    An MST instance mapped to 1-4094 is not 4094 VLANs worth documenting; the VLANs that exist are."""
    configured = {v.id for k in comp if topo.nodes[k].device for v in topo.nodes[k].device.vlans}
    out: set[int] = set()
    for k in with_data:
        for inst in topo.nodes[k].device.spanning_tree.instances:
            if inst.name.upper().startswith("VLAN"):
                out.update(inst.vlans)
            elif inst.vlans:
                out.update(set(inst.vlans) & configured if configured else inst.vlans)
            else:
                out.update(configured or {1})
    return sorted(out)


def _trees(snap, topo: Topology, comp: list[str], with_data: list[str]) -> list[Tree]:
    from sextant.rings import link_ring

    comp_links = [(pair, ln) for pair, ln in topo.links.items()
                  if pair[0] in comp and pair[1] in comp and not _routed_link(topo, ln)]
    ring_of = {pair: r.label for pair, ln in comp_links if (r := link_ring(topo, ln))}
    ring_adj: dict[str, set[str]] = {}
    for a, b in ring_of:
        ring_adj.setdefault(a, set()).add(b)
        ring_adj.setdefault(b, set()).add(a)

    def with_rings(members) -> set[str]:
        """Members plus every switch on a ring they are on: the whole ring is drawn, not just its first hop."""
        out, stack = set(members), list(members)
        while stack:
            for nb in ring_adj.get(stack.pop(), ()):
                if nb not in out:
                    out.add(nb)
                    stack.append(nb)
        return out
    groups: dict[tuple, Tree] = {}
    done: dict[tuple, list[tuple]] = {}  # same instances and VLAN carriage -> same result, computed once
    ifmap: dict[str, dict] = {}
    has_vlans = {k: {v.id for v in topo.nodes[k].device.vlans} for k in comp if topo.nodes[k].device}
    for vlan in _domain_vlans(topo, comp, with_data):
        inst_of = {}
        for k in with_data:
            inst = _instance_for(topo.nodes[k].device.spanning_tree.instances, vlan)
            if not inst:
                continue
            if not inst.name.upper().startswith("VLAN") and has_vlans.get(k) and vlan not in has_vlans[k]:
                continue  # an MST/RSTP instance covers every VLAN, but this switch does not have this one
            if vlan in topo.nodes[k].device.spanning_tree.disabled_vlans:
                continue
            inst_of[k] = inst
        if not inst_of:
            continue
        carry = {}
        for pair, ln in comp_links:
            sides = [_carries(topo.nodes[n].device, _side_ports(ln, sd), vlan, ifmap)
                     for n, sd in ((pair[0], "a"), (pair[1], "b")) if topo.nodes[n].device]
            carry[pair] = False not in sides
        ident = (vlan == 1, tuple(sorted((k, id(i)) for k, i in inst_of.items())), tuple(sorted(carry.items())))
        if ident in done:
            for sig in done[ident]:
                groups[sig].vlans.append(vlan)
            continue
        done[ident] = sigs = []
        # a VLAN that is not carried between two switches forms separate trees: split by the root each one sees
        # grouped by the root's MAC: an MST region reports a PVST root with its VLAN 1 priority,
        # the PVST switches with the VLAN's own, and it is still the same bridge
        by_root: dict[str, dict[str, StpInstance]] = {}
        for k, inst in inst_of.items():
            by_root.setdefault(inst.root_mac or f"priority {inst.root_priority}", {})[k] = inst
        for members in by_root.values():
            own = next((i for i in members.values() if i.is_root), next(iter(members.values())))
            root_mac, root_prio = own.root_mac, own.root_priority
            ringed = with_rings(members)
            links = [(pair, ln) for pair, ln in comp_links if pair[0] in members or pair[1] in members
                     or (pair in ring_of and pair[0] in ringed)]
            states = {pair: LinkState("ring", ring=ring_of[pair]) if pair in ring_of
                      else _link_state(topo, ln, members, carry[pair]) for pair, ln in links}
            sig = (vlan == 1, root_mac,
                   tuple(sorted((p, st.state, st.blocked_at or "") for p, st in states.items())),
                   tuple(sorted((k, i.root_port or "") for k, i in members.items())))
            tree = groups.get(sig)
            if tree is None:
                tree = Tree(vlans=[], root_mac=root_mac, root_priority=root_prio, links=states,
                            reporters=sorted(members), pvst=any(i.name.upper().startswith("VLAN")
                                                                 for i in members.values()))
                for k, inst in members.items():
                    if inst.root_port and not inst.is_root:
                        tree.root_ports[k] = short_ifname(inst.root_port)
                        par = _parent_of(topo, k, inst, comp_links)
                        if par:
                            tree.parent[k] = par
                groups[sig] = tree
            tree.vlans.append(vlan)
            sigs.append(sig)
        # conflict: two linked switches both forward this VLAN on the link but see different roots
        if len(by_root) > 1:
            for pair, ln in comp_links:
                a, b = pair
                if a in inst_of and b in inst_of and inst_of[a].root_mac != inst_of[b].root_mac and carry[pair] \
                        and pair not in ring_of:
                    pa = _port(inst_of[a], topo.nodes[a].device, _side_ports(ln, "a"))
                    pb = _port(inst_of[b], topo.nodes[b].device, _side_ports(ln, "b"))
                    if pa and pb and pa.state == "forwarding" and pb.state == "forwarding":
                        for sig in sigs:
                            t = groups[sig]
                            if a in t.reporters or b in t.reporters:
                                other = b if a in t.reporters else a
                                t.disagreement[other] = inst_of[other].root_mac or "?"
    trees = _merge_pruned(list(groups.values()))
    for t in trees:
        t.root_node = _bridge_owner(snap.devices, t.root_mac)
        if t.root_node is None:  # a neighbour that was not imported, known by its LLDP chassis ID
            seen = _neighbour_with_mac(snap.devices, t.root_mac)
            if seen:
                t.root_label = seen.remote_device
                t.root_node = key(seen.remote_device) if key(seen.remote_device) in topo.nodes else None
        if t.root_node is None:  # also look at switches outside this group: an uplink nobody described
            t.root_node = _guess_root(topo, comp, t) or _guess_root(topo, [k for k in topo.nodes if k not in comp], t)
            t.root_inferred = t.root_node is not None
        t.root_documented = bool(t.root_node and t.root_node in topo.nodes and topo.nodes[t.root_node].device)
        if t.root_node not in t.reporters:
            t.root_entry = _root_entry(topo, t, ifmap)
        elif not any(st.state in _CARRIED for st in t.links.values()):
            # root of itself only: every link it has towards other switches is a ring link
            own = sorted({st.ring for pair, st in t.links.items() if st.ring and t.root_node in pair})
            t.ring = ", ".join(own) or None
    trees.sort(key=lambda t: (t.vlans[0] if t.vlans else 0, t.root_mac or ""))
    return trees


_CARRIED = ("forwarding", "blocked")


def same_tree(a: Tree, b: Tree) -> bool:
    """Same root, and wherever both trees carry a link it is in the same state with the same root ports."""
    if a.root_mac != b.root_mac or a.base_priority != b.base_priority:
        return False
    for pair in a.links.keys() & b.links.keys():
        sa, sb = a.links[pair], b.links[pair]
        if sa.state in _CARRIED and sb.state in _CARRIED and (sa.state, sa.blocked_at) != (sb.state, sb.blocked_at):
            return False
    return all(a.root_ports[k] == b.root_ports[k] for k in a.root_ports.keys() & b.root_ports.keys())


def _compatible(a: Tree, b: Tree) -> bool:
    return a.default_vlan == b.default_vlan and 1 not in a.vlans + b.vlans and same_tree(a, b)


def _merge_pruned(trees: list[Tree]) -> list[Tree]:
    """Merge trees that only differ in which trunks carry which VLANs (pruned or per-switch VLANs)."""
    carried: dict[int, dict[tuple, set[int]]] = {}
    merged: list[Tree] = []
    for t in sorted(trees, key=lambda x: -len(x.vlans)):
        own = {pair for pair, st in t.links.items() if st.state in _CARRIED}
        target = next((m for m in merged if _compatible(m, t) and not m.trivial and not t.trivial), None)
        if target is None:
            merged.append(t)
            carried[id(t)] = {pair: set(t.vlans) for pair in own}
            continue
        c = carried[id(target)]
        for pair in own:
            c.setdefault(pair, set()).update(t.vlans)
        for pair, st in t.links.items():
            cur = target.links.get(pair)
            if cur is None or (cur.state not in _CARRIED and st.state in _CARRIED) or cur.state == "unknown":
                target.links[pair] = LinkState(st.state, st.blocked_at, st.blocked_port, ring=st.ring)
        base = target.base_priority  # equal for both (compatible), and kept: vlans[0] may change below
        target.vlans = sorted(set(target.vlans) | set(t.vlans))
        if base is not None and target.root_priority != base:  # PVST: re-derive for the new first VLAN
            target.root_priority = base + target.vlans[0]
        target.reporters = sorted(set(target.reporters) | set(t.reporters))
        for k, v in t.root_ports.items():
            target.root_ports.setdefault(k, v)
        for k, v in t.parent.items():
            target.parent.setdefault(k, v)
        target.disagreement.update(t.disagreement)
    for m in merged:
        allv = set(m.vlans)
        for pair, vl in carried[id(m)].items():
            if m.links[pair].state in _CARRIED and vl != allv:
                m.links[pair].vlans = sorted(vl)
        m.vlans.sort()
    return merged


def _predict(topo: Topology, switches: list[str]) -> tuple[str | None, str | None]:
    """Config-only: lowest configured priority wins; ties are decided by MAC address (not in the config).
    Evaluated per configured VLAN, so per-VLAN load balancing (odd/even roots) is reported as such."""
    live = [k for k in switches if topo.nodes[k].device.spanning_tree.mode != "disabled"
            and topo.nodes[k].device.spanning_tree.configured_priority]
    if not live:
        return None, None
    vlans = sorted({v.id for k in live for v in topo.nodes[k].device.vlans}) or [1]
    by_winner: dict[tuple[tuple[str, ...], int], list[int]] = {}
    for vlan in vlans:
        prios = {k: _configured(topo.nodes[k].device, vlan) for k in live}
        prios = {k: p for k, p in prios.items() if p is not None}
        if not prios:
            continue
        best = min(prios.values())
        winners = tuple(sorted(k for k, p in prios.items() if p == best))
        by_winner.setdefault((winners, best), []).append(vlan)
    if not by_winner:
        return None, None

    def phrase(winners: tuple[str, ...], best: int) -> str:
        names = [topo.nodes[k].name for k in winners]
        if len(winners) == 1:
            return f"{names[0]} has the lowest configured bridge priority ({best})"
        shown = ", ".join(names[:6]) + (f" and {len(names) - 6} more" if len(names) > 6 else "")
        return (f"{len(winners)} switches share the lowest priority ({best}), so the lowest MAC address decides, "
                f"which is not in the configuration ({shown})")

    if len(by_winner) == 1:
        (winners, best), = by_winner
        root = winners[0] if len(winners) == 1 else None
        return phrase(winners, best) + (" and should be root." if root else "."), root
    parts = [f"VLAN{'s' if len(v) > 1 else ''} {compress_vlans(v)}: {phrase(w, b)}"
             for (w, b), v in sorted(by_winner.items(), key=lambda x: x[1][0])]
    return "Per VLAN: " + "; ".join(parts) + ".", None
