"""Spanning tree on networks of different shapes, vendors and sizes, checked against a simulated
election (tests/stp_lab.py): the root, every root port and every blocked port must match."""

import time

import pytest

from sextant.analysis import analyze
from sextant.builders.asbuilt import build_asbuilt
from sextant.doc import Cell
from sextant.drivers._util import short_ifname
from sextant.model import Snapshot
from sextant.render.stp_diagram import stp_svg
from sextant.stp import build_stp
from sextant.theme import load_theme
from sextant.topology import build_topology
from tests.stp_lab import Lab


def _run(lab: Lab):
    snap = analyze(Snapshot(devices=lab.devices()))
    topo = build_topology(snap)
    return snap, topo, build_stp(snap, topo)


def _live(site):
    """Drawn trees, VLAN 1 (always a tree of its own) last."""
    return sorted((t for t in site.trees if not t.trivial), key=lambda t: t.default_vlan)


def _tree_for(sites, vlan, member):
    for site in sites:
        for t in site.trees:
            if vlan in t.vlans and member in t.reporters:
                return site, t
    raise AssertionError(f"no tree for VLAN {vlan} containing {member}")


def _check(lab: Lab, sites, vlans):
    """Sextant's tree for each VLAN equals the simulated election."""
    for vlan in vlans:
        truth = lab.truth(vlan)
        for member in sorted(truth["root"]):
            _, t = _tree_for(sites, vlan, member)
            assert t.root_node == truth["root"][member], (vlan, member)
            carried = {p: st for p, st in t.links.items() if st.vlans is None or vlan in st.vlans}
            got = {(st.blocked_at, st.blocked_port) for st in carried.values() if st.state == "blocked"}
            comp = {n for n, r in truth["root"].items() if r == truth["root"][member]}
            want = {(sw, short_ifname(p)) for sw, p in truth["blocked"] if sw in comp}
            assert got == want, (vlan, member)
            for sw, port in truth["root_ports"].items():
                if sw in comp:
                    assert t.root_ports.get(sw) == short_ifname(port), (vlan, sw)


def _render_all(snap, topo, sites):
    theme = load_theme(None)
    for site in sites:
        for t in site.trees:
            svg, ratio = stp_svg(topo, site.keys, t, theme, t.vlan_label)
            assert svg.startswith("<svg") and svg.endswith("</svg>") and ratio > 0.1
    build_asbuilt(snap)


def test_ring_of_access_switches():
    """Access switches daisy-chained between two distribution switches: one port blocks in the ring."""
    lab = Lab()
    lab.switch("d1", prio=4096)
    lab.switch("d2", prio=8192)
    lab.link("d1", "d2", vlans=[1, 10], members=2)
    chain = ["d1"] + [f"a{i}" for i in range(1, 7)] + ["d2"]
    for i in range(1, 7):
        lab.switch(f"a{i}")
    for x, y in zip(chain, chain[1:], strict=False):
        lab.link(x, y, vlans=[1, 10])
    snap, topo, sites = _run(lab)
    assert len(sites) == 1 and [t.vlans for t in _live(sites[0])] == [[10], [1]]
    _check(lab, sites, [1, 10])
    _render_all(snap, topo, sites)


def test_per_vlan_load_balancing_nxos():
    """Odd VLANs rooted on one core, even on the other; NX-OS naming (port-channel / Eth vs Ethernet)."""
    lab = Lab()
    vlans = [10, 11, 12, 13]
    lab.switch("core1", "nxos", prio={v: 4096 if v % 2 else 8192 for v in vlans})
    lab.switch("core2", "nxos", prio={v: 8192 if v % 2 else 4096 for v in vlans})
    lab.link("core1", "core2", vlans=vlans, members=2)
    for i in range(1, 5):
        lab.switch(f"leaf{i}", "nxos")
        lab.link(f"leaf{i}", "core1", vlans=vlans)
        lab.link(f"leaf{i}", "core2", vlans=vlans)
    snap, topo, sites = _run(lab)
    live = [t for t in sites[0].trees if not t.trivial]
    assert sorted(t.vlans for t in live) == [[10, 12], [11, 13]]
    _check(lab, sites, vlans)
    assert "Per VLAN" in sites[0].prediction and "core1" in sites[0].prediction
    _render_all(snap, topo, sites)


def test_pruned_trunks_give_one_tree():
    """Each access switch only carries its own VLAN plus management: one tree, partial links marked."""
    lab = Lab()
    lab.switch("d1", prio=4096)
    lab.switch("d2", prio=8192)
    lab.link("d1", "d2", vlans=[10] + [100 + i for i in range(1, 11)], members=2)
    for i in range(1, 11):
        lab.switch(f"a{i:02d}")
        lab.link(f"a{i:02d}", "d1", vlans=[10, 100 + i])
        lab.link(f"a{i:02d}", "d2", vlans=[10, 100 + i])
    snap, topo, sites = _run(lab)
    live = [t for t in sites[0].trees if not t.trivial]
    assert len(live) == 1 and live[0].vlans == [10] + [100 + i for i in range(1, 11)]
    partial = [st for st in live[0].links.values() if st.vlans]
    assert len(partial) == 20 and all(10 in st.vlans for st in partial)  # every access link is partial
    _check(lab, sites, [10, 101, 105, 110])
    _render_all(snap, topo, sites)


def test_mixed_vendor_mstp():
    """AOS-CX core pair, AOS-S and Junos access, one CIST: VLANs come from the config, not 1-4094."""
    lab = Lab()
    lab.switch("cx-core1", "aoscx", prio=4096, vlans=[1, 10, 20])
    lab.switch("cx-core2", "aoscx", prio=8192, vlans=[1, 10, 20])
    lab.link("cx-core1", "cx-core2", vlans=[1, 10, 20], members=2)
    for i, style in enumerate(["procurve"] * 4 + ["junos"] * 2, start=1):
        lab.switch(f"acc{i}", style, vlans=[1, 10, 20])
        lab.link(f"acc{i}", "cx-core1", vlans=[1, 10, 20], members=2 if style == "procurve" else 1)
        lab.link(f"acc{i}", "cx-core2", vlans=[1, 10, 20])
    snap, topo, sites = _run(lab)
    live = _live(sites[0])
    assert [t.vlans for t in live] == [[10, 20], [1]] and live[0].root_node == live[1].root_node == "cx-core1"
    _check(lab, sites, [1])
    _render_all(snap, topo, sites)


def test_down_port_listed_as_disabled_is_not_forwarding():
    lab = Lab()
    lab.switch("d1", "aoscx", prio=4096)
    lab.switch("d2", "aoscx", prio=8192)
    lab.link("d1", "d2")
    lab.switch("acc", "procurve")
    lab.link("acc", "d1")
    down = lab.link("acc", "d2", up=False)
    lab.devices()  # LLDP is gone on the down link: describe it so the topology still knows the cable
    devices = lab.devices()
    acc = next(d for d in devices if d.hostname == "acc")
    acc.interfaces[-1].description = f"uplink d2 port {down.b.phys[0]}"
    snap = analyze(Snapshot(devices=devices))
    topo = build_topology(snap)
    sites = build_stp(snap, topo)
    _, t = _tree_for(sites, 1, "acc")
    states = {frozenset(p): st.state for p, st in t.links.items()}
    assert states[frozenset({"acc", "d2"})] == "absent"
    _check(lab, sites, [1])


def test_root_outside_the_documented_switches():
    """The root sends no output (not collected): the tree still forms, the root is inferred from config."""
    lab = Lab()
    lab.switch("core", prio=4096)
    for i in range(1, 4):
        lab.switch(f"a{i}")
        lab.link(f"a{i}", "core", vlans=[1, 20])
    lab.link("a1", "a2", vlans=[1, 20])
    devices = lab.devices()
    core = next(d for d in devices if d.hostname == "core")
    core.spanning_tree.instances, core.spanning_tree.bridge_mac = [], None  # config only
    snap = analyze(Snapshot(devices=devices))
    topo = build_topology(snap)
    sites = build_stp(snap, topo)
    live = _live(sites[0])
    assert len(live) == 2 and all(t.root_node == "core" and t.root_inferred for t in live)
    _render_all(snap, topo, sites)


def test_large_flat_network_is_fast():
    lab = Lab()
    vlans = list(range(1, 41))
    lab.switch("d1", prio=4096)
    lab.switch("d2", prio=8192)
    lab.link("d1", "d2", vlans=vlans, members=2)
    for i in range(1, 61):
        lab.switch(f"acc{i:02d}")
        lab.link(f"acc{i:02d}", "d1", vlans=vlans)
        lab.link(f"acc{i:02d}", "d2", vlans=vlans)
    devices = lab.devices()
    start = time.perf_counter()
    snap = analyze(Snapshot(devices=devices))
    topo = build_topology(snap)
    sites = build_stp(snap, topo)
    t = _live(sites[0])
    svg, _ = stp_svg(topo, sites[0].keys, t[0], load_theme(None))
    elapsed = time.perf_counter() - start
    assert [len(x.vlans) for x in t] == [39, 1]
    # hubs without a name hint above switches named as access are not access themselves
    assert topo.nodes["d1"].layer == topo.nodes["d2"].layer == "core"
    assert "acc01–60" in svg and "60 switches" in svg  # identical access switches drawn as one group
    assert "prio 32768 · 60 switches" in svg
    assert sum(1 for st in t[0].links.values() if st.state == "blocked") == 60
    assert elapsed < 10, elapsed


@pytest.mark.parametrize("style", ["cisco", "nxos", "procurve", "aoscx", "junos", "cisco-mst"])
def test_triangle_per_vendor(style):
    lab = Lab()
    lab.switch("s1", style, prio=4096)
    lab.switch("s2", style, prio=8192)
    lab.switch("s3", style)
    lab.link("s1", "s2", vlans=[1, 10], members=2)
    lab.link("s3", "s1", vlans=[1, 10])
    lab.link("s3", "s2", vlans=[1, 10])
    snap, topo, sites = _run(lab)
    _check(lab, sites, [1, 10])
    _, t = _tree_for(sites, 1, "s3")
    assert sum(1 for st in t.links.values() if st.state == "blocked") == 1
    _render_all(snap, topo, sites)


def test_default_priority_survives_pruned_merge():
    """All switches at the default priority, VLAN 10 pruned from one trunk: the merged tree still knows
    its root won on MAC address (the root priority follows the tree's first VLAN)."""
    lab = Lab()
    for n in ("s1", "s2", "s3"):
        lab.switch(n)
    lab.link("s1", "s2", vlans=[10, 20, 30])
    lab.link("s2", "s3", vlans=[20, 30])
    lab.link("s1", "s3", vlans=[10, 20, 30])
    snap, topo, sites = _run(lab)
    live = [t for t in sites[0].trees if not t.trivial]
    assert len(live) == 1 and live[0].vlans == [10, 20, 30] and live[0].base_priority == 32768
    assert live[0].default_priority()
    assert any(f.check_id == "stp.default-priority-root" for d in snap.devices for f in d.findings)


def test_documented_root_without_documented_link_is_not_outside():
    lab = Lab()
    lab.switch("c", prio=4096)
    lab.switch("a")
    lab.switch("b")
    lab.link("c", "a", vlans=[10])
    lab.link("a", "b", vlans=[10])
    devices = lab.devices()
    for d in devices:  # nobody documented the c-a cable
        d.neighbors = [n for n in d.neighbors if {d.hostname, n.remote_device} != {"a", "c"}]
    snap = analyze(Snapshot(devices=devices))
    topo = build_topology(snap)
    t = next(t for s in build_stp(snap, topo) for t in s.trees if 10 in t.vlans and "a" in t.reporters)
    assert t.root_node == "c" and t.root_documented and not t.outside_root
    assert not any(f.check_id == "stp.root-outside" for d in snap.devices for f in d.findings)


def test_mst_priority_predicts_root():
    lab = Lab()
    lab.switch("core1", "cisco-mst")
    lab.switch("core2", "cisco-mst")
    lab.link("core1", "core2")
    devices = lab.devices()
    devices[0].spanning_tree.configured_priority = {"mst 0-1": 4096}
    devices[1].spanning_tree.configured_priority = {"default": 32768}
    for d in devices:
        d.spanning_tree.instances = []
    snap = analyze(Snapshot(devices=devices))
    topo = build_topology(snap)
    (site,) = build_stp(snap, topo)
    assert site.predicted_root == "core1" and "4096" in site.prediction


# --------------------------------------------------------------------------- MRP rings (Cisco IE3x00)


def _ring_lab(listed: bool, manager: str | None = "ie1") -> Lab:
    """Two distribution switches, an access switch, and a ring of five IE switches hanging off dist1 through
    an ordinary (spanning-tree) uplink from ie1. The ring links run MRP: no BPDUs cross them."""
    lab = Lab(ring_ports_in_stp=listed)
    vlans = [1, 50, 60]
    lab.switch("dist1", prio=4096)
    lab.switch("dist2", prio=8192)
    lab.link("dist1", "dist2", vlans=vlans, members=2)
    lab.switch("acc1")
    lab.link("acc1", "dist1", vlans=vlans)
    lab.link("acc1", "dist2", vlans=vlans)
    ring = [f"ie{i}" for i in range(1, 6)]
    for n in ring:
        lab.switch(n, "ie").ring_role = "manager" if n == manager else "client"
    lab.link("ie1", "dist1", vlans=[1, 50])
    for x, y in zip(ring, ring[1:] + ring[:1], strict=True):
        lab.link(x, y, vlans=[1, 50], ring="1")
    return lab


@pytest.mark.parametrize("listed", [False, True])
def test_mrp_ring_switches_are_not_roots(listed):
    lab = _ring_lab(listed)
    snap, topo, sites = _run(lab)
    (site,) = sites
    _check(lab, sites, [1, 50, 60])  # the election, including each ring switch being its own root
    main = [t for t in _live(site) if 50 in t.vlans]
    assert len(main) == 1 and main[0].root_node == "dist1" and main[0].root_ports["ie1"] == "Gi1/1"
    states = {frozenset(p): st for p, st in main[0].links.items()}
    assert states[frozenset({"ie1", "ie2"})].state == "ring" and states[frozenset({"ie1", "ie2"})].ring == "MRP ring 1"
    islands = [t for t in site.trees if t.ring]
    assert {t.root_node for t in islands} == {"ie2", "ie3", "ie4", "ie5"} and all(t.trivial for t in islands)
    assert all(t.root_node in ("dist1",) for t in _live(site))  # no ring switch is drawn as a root
    ids = {f.check_id for d in snap.devices for f in d.findings}
    assert not ids & {"stp.root-disagreement", "ring.no-manager", "ring.many-managers"}
    assert not any(f.check_id == "stp.default-priority-root" and d.hostname.startswith("ie")
                   for d in snap.devices for f in d.findings)
    doc = build_asbuilt(snap)
    from sextant.doc import Callout, Table

    (overview,) = [b for b in doc.blocks if isinstance(b, Table) and "Root for" in b.columns]
    rows = {r[0]: r for r in overview.rows}
    assert rows["ie3"][4] == "– (only of itself behind the ring)" and "MRP ring 1 client" in rows["ie3"][1]
    assert rows["dist1"][4].startswith("VLANs 50,60")
    assert any(isinstance(b, Callout) and b.title == "Ring redundancy instead of spanning tree" for b in doc.blocks)
    (index,) = [b for b in doc.blocks if isinstance(b, Table) and b.title == "Spanning tree per VLAN"]
    assert [r[0] for r in index.rows] == ["1", "50,60"] and "VLAN 1 section" in index.rows[0][1]
    (rings,) = [b for b in doc.blocks if isinstance(b, Table) and "Ring links" in b.columns]
    assert rings.rows == [["MRP ring 1", "ie1–5", "ie1 manager", Cell("closed", "success"), "5"]]
    from sextant.doc import Heading, Paragraph

    v1 = next(i for i, b in enumerate(doc.blocks) if isinstance(b, Heading) and b.text == "VLAN 1 (default VLAN)")
    assert any(isinstance(b, Paragraph) and b.text.startswith("Root dist1, with the same forwarding and blocked "
                                                               "links as VLANs 50,60") for b in doc.blocks[v1:v1 + 3])
    from sextant.builders.summary import build_summary

    (glance,) = [b for b in build_summary(snap).blocks if isinstance(b, Table) and b.title == "Spanning tree"]
    assert [(r[1], r[4]) for r in glance.rows] == [("VLANs 50,60", "–"), ("VLAN 1", "default VLAN")]
    svg, _ = stp_svg(topo, site.keys, main[0], load_theme(None))
    assert "MRP ring 1" in svg and "Ring protocol (MRP/REP), no STP" in svg
    assert ">ie3<" in svg and ">ie4<" in svg and svg.count(">MRP ring 1<") == 5  # the whole ring, every link
    _render_all(snap, topo, sites)


def test_mrp_ring_without_a_manager_is_a_loop():
    snap, _, _ = _run(_ring_lab(False, manager=None))
    (f,) = {f.title: f for d in snap.devices for f in d.findings if f.check_id == "ring.no-manager"}.values()
    assert f.severity.value == "high" and "MRP ring 1" in f.title


def test_vlan_index_lists_every_vlan():
    """A VLAN only on one switch, one with STP disabled, and the trees: each VLAN is accounted for."""
    lab = Lab()
    lab.switch("s1", prio=4096)
    lab.switch("s2")
    lab.link("s1", "s2", vlans=[1, 10])
    devices = lab.devices()
    s2 = next(d for d in devices if d.hostname == "s2")
    from sextant.model import Vlan

    s2.vlans += [Vlan(id=30), Vlan(id=40)]
    s2.spanning_tree.disabled_vlans = [40]
    from sextant.model import StpInstance

    s2.spanning_tree.instances.append(StpInstance(name="VLAN0030", vlans=[30], root_mac=s2.spanning_tree.bridge_mac,
                                                  root_priority=32798, is_root=True))
    snap = analyze(Snapshot(devices=devices))
    topo = build_topology(snap)
    (site,) = build_stp(snap, topo)
    assert site.vlan_notes == {30: "Local to s2 (not on a link between switches)",
                               40: "Spanning tree disabled on s2"}
    from sextant.doc import Table

    (index,) = [b for b in build_asbuilt(snap).blocks if isinstance(b, Table) and b.title == "Spanning tree per VLAN"]
    assert [r[0] for r in index.rows] == ["1", "10", "30", "40"]
