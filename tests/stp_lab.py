"""A small spanning-tree simulator for tests: describe any switched network, get the Devices a
collection would produce (config interfaces, LLDP neighbours, `show spanning-tree` instances in the
vendor's own interface naming) plus the correct answer (root, root ports, blocked ports per VLAN).

    net = Lab()
    net.switch("d1", "cisco", prio=4096)
    net.switch("a1", "procurve")
    net.link("d1", "a1", vlans=[1, 10])
    devices = net.devices()
    truth = net.truth(10)   # {"root": "d1", "root_ports": {...}, "blocked": {("a1", "7"), ...}}

Election follows 802.1D/w: lowest (priority, MAC) is root; each other bridge picks the port with the
lowest (root path cost, sender bridge id, sender port id); on every link the side with the better
(root path cost, bridge id, port id) is designated and the other side, unless it is the root port,
is alternate (discarding).
"""

from __future__ import annotations

import heapq
from dataclasses import dataclass, field

from sextant.model import (
    Device,
    DeviceRole,
    Interface,
    Neighbor,
    PortMode,
    SpanningTree,
    StpInstance,
    StpPort,
    Vlan,
)

# vendor -> (config name, LLDP name, STP name) for port n, LAG name, STP mode, MST?
STYLES = {
    "cisco": (lambda n: f"TenGigabitEthernet1/1/{n}", lambda n: f"TenGigabitEthernet1/1/{n}",
              lambda n: f"Te1/1/{n}", lambda n: (f"Port-channel{n}", f"Po{n}"), "rapid-pvst"),
    "nxos": (lambda n: f"Ethernet1/{n}", lambda n: f"Ethernet1/{n}", lambda n: f"Eth1/{n}",
             lambda n: (f"port-channel{n}", f"Po{n}"), "rapid-pvst"),
    "procurve": (lambda n: str(n), lambda n: str(n), lambda n: str(n), lambda n: (f"Trk{n}", f"Trk{n}"), "mstp"),
    "aoscx": (lambda n: f"1/1/{n}", lambda n: f"1/1/{n}", lambda n: f"1/1/{n}", lambda n: (f"lag{n}", f"lag{n}"),
              "mstp"),
    "junos": (lambda n: f"ge-0/0/{n}", lambda n: f"ge-0/0/{n}.0", lambda n: f"ge-0/0/{n}",
              lambda n: (f"ae{n}", f"ae{n}"), "rstp"),
    "cisco-mst": (lambda n: f"GigabitEthernet1/0/{n}", lambda n: f"Gi1/0/{n}", lambda n: f"Gi1/0/{n}",
                  lambda n: (f"Port-channel{n}", f"Po{n}"), "mst"),
}
PVST = ("rapid-pvst", "pvst")


@dataclass
class Sw:
    name: str
    style: str
    prio: dict[int, int] | int = 32768  # base priority, or per VLAN {vlan: prio} (others 32768)
    mac: str = ""
    vlans: set[int] = field(default_factory=set)
    next_port: int = 1
    next_lag: int = 1

    @property
    def mode(self) -> str:
        return STYLES[self.style][4]

    def base(self, vlan: int) -> int:
        return self.prio.get(vlan, 32768) if isinstance(self.prio, dict) else self.prio

    def bid(self, vlan: int) -> tuple[int, str]:
        """Advertised bridge id: PVST adds the VLAN id (extended system ID)."""
        return (self.base(vlan) + (vlan if self.mode in PVST else 0), self.mac)


@dataclass
class End:
    sw: str
    phys: list[str]  # config names
    lldp: list[str]
    stp: str  # STP port name (the LAG when bundled)
    lag: str | None
    port_id: int


@dataclass
class Ln:
    a: End
    b: End
    vlans: set[int]
    cost: int
    up: bool = True


class Lab:
    def __init__(self) -> None:
        self.sws: dict[str, Sw] = {}
        self.links: list[Ln] = []

    def switch(self, name: str, style: str = "cisco", prio: dict[int, int] | int = 32768,
               vlans: list[int] | None = None) -> Sw:
        n = len(self.sws) + 1
        sw = Sw(name, style, prio, mac=f"02aa.{n // 256:02x}{n % 256:02x}.0000", vlans=set(vlans or [1]))
        self.sws[name] = sw
        return sw

    def _end(self, sw: Sw, members: int) -> End:
        cfg, lldp, stp, lagname, _ = STYLES[sw.style]
        ports = list(range(sw.next_port, sw.next_port + members))
        sw.next_port += members
        lag = None
        stp_name = stp(ports[0])
        if members > 1:
            lag, stp_name = lagname(sw.next_lag)
            sw.next_lag += 1
        return End(sw.name, [cfg(p) for p in ports], [lldp(p) for p in ports], stp_name, lag, ports[0])

    def link(self, a: str, b: str, vlans: list[int] | None = None, members: int = 1, cost: int = 2000,
             up: bool = True) -> Ln:
        sa, sb = self.sws[a], self.sws[b]
        carried = set(vlans or [1])
        sa.vlans |= carried
        sb.vlans |= carried
        ln = Ln(self._end(sa, members), self._end(sb, members), carried, cost, up)
        self.links.append(ln)
        return ln

    # ------------------------------------------------------------------ election

    def _instances(self) -> list[tuple[str, list[int]]]:
        """(instance key, VLANs) as the network runs them: one per VLAN for PVST, one CIST otherwise."""
        modes = {s.mode for s in self.sws.values()}
        allv = sorted({v for s in self.sws.values() for v in s.vlans})
        if modes <= set(PVST):
            return [(f"VLAN{v:04d}", [v]) for v in allv]
        assert not modes & set(PVST), "the lab does not model PVST/MST boundaries"
        return [("CIST", allv)]

    def _carries(self, ln: Ln, key: str, vlan: int) -> bool:
        if not ln.up:
            return False
        return vlan in ln.vlans if key.startswith("VLAN") else True

    def _elect(self, key: str, vlan: int) -> dict:
        members = {n for n, s in self.sws.items() if key == "CIST" or vlan in s.vlans}
        links = [ln for ln in self.links if self._carries(ln, key, vlan)
                 and ln.a.sw in members and ln.b.sw in members]
        adj: dict[str, list[tuple[Ln, End, End]]] = {n: [] for n in members}
        for ln in links:
            adj[ln.a.sw].append((ln, ln.a, ln.b))
            adj[ln.b.sw].append((ln, ln.b, ln.a))
        result = {"root": {}, "cost": {}, "root_port": {}, "role": {}}
        seen: set[str] = set()
        for start in sorted(members):
            if start in seen:
                continue
            comp, stack = set(), [start]
            while stack:
                cur = stack.pop()
                if cur not in comp:
                    comp.add(cur)
                    stack += [o.sw for _, _, o in adj[cur]]
            seen |= comp
            root = min(comp, key=lambda n: self.sws[n].bid(vlan))
            cost = {root: 0}
            heap = [(0, root)]
            while heap:
                c, cur = heapq.heappop(heap)
                if c > cost[cur]:
                    continue
                for ln, _me, other in adj[cur]:
                    if c + ln.cost < cost.get(other.sw, 1 << 30):
                        cost[other.sw] = c + ln.cost
                        heapq.heappush(heap, (c + ln.cost, other.sw))
            for n in comp:
                result["root"][n] = root
                result["cost"][n] = cost[n]
                if n == root:
                    continue
                best = min(adj[n], key=lambda t: (cost[t[2].sw] + t[0].cost, self.sws[t[2].sw].bid(vlan),
                                                  t[2].port_id, t[1].port_id))
                result["root_port"][n] = best[1].stp
            for ln in links:
                if ln.a.sw not in comp:
                    continue

                va, vb = ((cost[e.sw], self.sws[e.sw].bid(vlan), e.port_id) for e in (ln.a, ln.b))
                des, other = (ln.a, ln.b) if va < vb else (ln.b, ln.a)
                result["role"][(des.sw, des.stp)] = "designated"
                result["role"][(other.sw, other.stp)] = ("root" if result["root_port"].get(other.sw) == other.stp
                                                         else "alternate")
        return result

    def truth(self, vlan: int) -> dict:
        key = next(k for k, vl in self._instances() if vlan in vl)
        r = self._elect(key, vlan)
        return {"root": {n: r["root"][n] for n in r["root"]},
                "root_ports": r["root_port"],
                "blocked": {(sw, port) for (sw, port), role in r["role"].items() if role == "alternate"}}

    # ------------------------------------------------------------------ devices

    def devices(self) -> list[Device]:
        out = {}
        for s in self.sws.values():
            st = SpanningTree(mode="mst" if s.mode == "mst" else s.mode, bridge_mac=s.mac)
            if isinstance(s.prio, dict):
                st.configured_priority = {"default": 32768} | {str(v): p for v, p in s.prio.items()}
            else:
                st.configured_priority = {"1-4094": s.prio}
            out[s.name] = Device(hostname=s.name, role=DeviceRole.switch, platform=s.style, model=f"{s.style}-sw",
                                 vlans=[Vlan(id=v) for v in sorted(s.vlans)], spanning_tree=st)
        for ln in self.links:
            for me, other in ((ln.a, ln.b), (ln.b, ln.a)):
                d = out[me.sw]
                trunk = ",".join(map(str, sorted(ln.vlans)))
                for i, p in enumerate(me.phys):
                    d.interfaces.append(Interface(name=p, mode=PortMode.trunk, trunk_vlans=trunk, lag=me.lag,
                                                  enabled=True, oper_up=ln.up))
                    if ln.up:
                        d.neighbors.append(Neighbor(local_port=p, remote_device=other.sw, remote_port=other.lldp[i]))
                if me.lag:
                    d.interfaces.append(Interface(name=me.lag, kind="lag", mode=PortMode.trunk, trunk_vlans=trunk,
                                                  lag_members=me.phys))
        for key, vlans in self._instances():
            for vlan in vlans if key.startswith("VLAN") else vlans[:1]:
                r = self._elect(key, vlan)
                for n, s in self.sws.items():
                    if n not in r["root"]:
                        continue
                    root = self.sws[r["root"][n]]
                    inst = StpInstance(name=key if key.startswith("VLAN") else {"mst": "MST0", "mstp": "IST",
                                                                              "rstp": "CIST"}[s.mode],
                                       vlans=[vlan] if key.startswith("VLAN") else
                                       ([] if s.mode == "rstp" else list(range(1, 4095))),
                                       protocol=s.mode, root_priority=root.bid(vlan)[0], root_mac=root.mac,
                                       root_cost=r["cost"][n], root_port=r["root_port"].get(n),
                                       is_root=root.name == n, bridge_priority=s.bid(vlan)[0], bridge_mac=s.mac)
                    for (sw, port), role in sorted(r["role"].items()):
                        if sw == n:
                            inst.ports.append(StpPort(interface=port, role=role,
                                                      state="blocking" if role == "alternate" else "forwarding"))
                    if s.style == "procurve":  # AOS-S lists every port, also the down ones
                        for ln in self.links:
                            for e in (ln.a, ln.b):
                                if e.sw == n and not ln.up:
                                    inst.ports.append(StpPort(interface=e.stp, role="disabled", state="disabled"))
                    out[n].spanning_tree.instances.append(inst)
        return list(out.values())
