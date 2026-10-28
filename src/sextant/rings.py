"""Ring redundancy (MRP, REP, ERPS) across the topology: which links are ring links and which switches
form each ring. Spanning tree does not run on ring ports, so these links are neither forwarding nor
blocked in a spanning tree, and switches only joined by a ring are separate spanning trees."""

from __future__ import annotations

from dataclasses import dataclass, field

from sextant.model import Device, Ring
from sextant.topology import Link, Topology, ifkey


def ring_ports(d: Device | None) -> dict[str, Ring]:
    """Interface key -> ring, also for the LAG a ring port belongs to."""
    out: dict[str, Ring] = {}
    if not d:
        return out
    for r in d.rings:
        for p in r.ports:
            out[ifkey(p)] = r
    return out


def link_ring(topo: Topology, ln: Link) -> Ring | None:
    """The ring a link belongs to: either end's port is a ring port."""
    for side in ("a", "b"):
        d = topo.nodes[getattr(ln, side)].device
        rp = ring_ports(d)
        if not rp:
            continue
        names = [pa if side == "a" else pb for pa, pb in ln.ports] + [ln.lag_a if side == "a" else ln.lag_b]
        for n in names:
            if n and ifkey(n) in rp:
                return rp[ifkey(n)]
    return None


@dataclass
class RingGroup:
    protocol: str
    ring_id: str
    members: list[str] = field(default_factory=list)  # node keys
    links: list[tuple[str, str]] = field(default_factory=list)
    roles: dict[str, str] = field(default_factory=dict)  # node -> manager / client / edge ...
    states: dict[str, str] = field(default_factory=dict)  # node -> closed / open ... (runtime, where reported)

    @property
    def label(self) -> str:
        return f"{self.protocol} {'segment' if self.protocol == 'REP' else 'ring'} {self.ring_id}"


def ring_groups(topo: Topology) -> list[RingGroup]:
    """One group per physical ring: switches configured with the same ring id and joined by its links."""
    adj: dict[tuple[str, str, str], set[str]] = {}
    pairs: dict[tuple[str, str], list[tuple[str, str]]] = {}
    for k, n in topo.nodes.items():
        for r in n.device.rings if n.device else []:
            adj.setdefault((r.protocol, r.ring_id, k), set())
    for pair, ln in topo.links.items():
        r = link_ring(topo, ln)
        if r is None:
            continue
        a, b = pair
        for x, y in ((a, b), (b, a)):
            adj.setdefault((r.protocol, r.ring_id, x), set()).add(y)
        pairs.setdefault((r.protocol, r.ring_id), []).append(pair)
    out: list[RingGroup] = []
    seen: set[tuple[str, str, str]] = set()
    for start in sorted(adj):
        if start in seen:
            continue
        proto, rid, _ = start
        g = RingGroup(proto, rid)
        stack = [start]
        while stack:
            cur = stack.pop()
            if cur in seen:
                continue
            seen.add(cur)
            g.members.append(cur[2])
            stack += [(proto, rid, y) for y in adj.get(cur, ()) if (proto, rid, y) not in seen]
        g.members.sort(key=lambda k: topo.nodes[k].name)
        g.links = [p for p in pairs.get((proto, rid), []) if p[0] in g.members and p[1] in g.members]
        for k in g.members:
            d = topo.nodes[k].device
            r = next((r for r in d.rings if (r.protocol, r.ring_id) == (proto, rid)), None) if d else None
            if r and r.role:
                g.roles[k] = r.role
            if r and r.state:
                g.states[k] = r.state
        out.append(g)
    return out
