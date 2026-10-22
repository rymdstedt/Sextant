"""Spanning tree on networks of different shapes, vendors and sizes, checked against a simulated
election (tests/stp_lab.py): the root, every root port and every blocked port must match."""

import time

import pytest

from sextant.analysis import analyze
from sextant.builders.asbuilt import build_asbuilt
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
    assert len(sites) == 1 and len([t for t in sites[0].trees if not t.trivial]) == 1
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
    live = [t for t in sites[0].trees if not t.trivial]
    assert len(live) == 1 and live[0].vlans == [1, 10, 20]
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
    live = [t for t in sites[0].trees if not t.trivial]
    assert len(live) == 1 and live[0].root_node == "core" and live[0].root_inferred
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
    t = [t for t in sites[0].trees if not t.trivial]
    svg, _ = stp_svg(topo, sites[0].keys, t[0], load_theme(None))
    elapsed = time.perf_counter() - start
    assert len(t) == 1 and len(t[0].vlans) == 40
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
