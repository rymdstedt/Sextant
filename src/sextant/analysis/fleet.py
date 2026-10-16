"""Cross-device checks over the site topology: both ends of a link, VLAN naming, uplink redundancy.

These need more than one device, so they run from analysis.analyze(snapshot), after the
per-device checks, and add findings to every device involved.
"""

from __future__ import annotations

from collections import Counter, defaultdict

from sextant.drivers._util import expand_vlans, short_ifname
from sextant.model import Device, Finding, Interface, PortMode, Severity, Snapshot
from sextant.topology import Topology, build_topology


def _iface(d: Device, port: str | None) -> Interface | None:
    if not port:
        return None
    want = short_ifname(port).lower()
    return next((i for i in d.interfaces if short_ifname(i.name).lower() == want), None)


def _allowed(i: Interface) -> set[int]:
    text = (i.trunk_vlans or "all").strip().lower()
    return set(range(1, 4095)) if text in ("all", "1-4094", "") else set(expand_vlans(text))


def _add(d: Device, f: Finding) -> None:
    if not any(x.check_id == f.check_id and x.title == f.title for x in d.findings):
        d.findings.append(f)


def link_checks(topo: Topology) -> None:
    for ln in topo.links.values():
        da, db = topo.nodes[ln.a].device, topo.nodes[ln.b].device
        if not (da and db):
            continue
        for pa, pb in ln.ports:
            ia, ib = _iface(da, pa), _iface(db, pb)
            if not (ia and ib) or not (ia.enabled and ib.enabled):
                continue
            where = f"{da.hostname} {short_ifname(ia.name)} ↔ {db.hostname} {short_ifname(ib.name)}"
            modes = {ia.mode, ib.mode}
            if PortMode.trunk in modes and PortMode.access in modes:
                for d in (da, db):
                    _add(d, Finding(check_id="link.mode-mismatch", severity=Severity.high,
                                    title=f"Trunk/access mismatch: {where}",
                                    detail="One end is a trunk, the other an access port: VLANs leak or drop.",
                                    recommendation="Configure both ends the same way.", evidence=[where]))
            elif modes == {PortMode.trunk}:
                na, nb = ia.native_vlan or 1, ib.native_vlan or 1
                if na != nb:
                    for d in (da, db):
                        _add(d, Finding(check_id="link.native-mismatch", severity=Severity.medium,
                                        title=f"Native VLAN mismatch ({na} vs {nb}): {where}",
                                        detail="Untagged traffic is bridged between two different VLANs.",
                                        recommendation="Use the same native VLAN on both ends of the trunk.",
                                        evidence=[where]))
                aa, ab = _allowed(ia), _allowed(ib)
                if aa != ab:
                    diff = sorted(aa ^ ab)
                    shown = ",".join(map(str, diff[:12])) + ("…" if len(diff) > 12 else "")
                    for d in (da, db):
                        _add(d, Finding(check_id="link.allowed-mismatch", severity=Severity.low,
                                        title=f"Trunk VLAN lists differ: {where}",
                                        detail=f"VLANs allowed on only one end: {shown}.",
                                        recommendation="Align the allowed VLAN lists on both ends.",
                                        evidence=[where]))


def uplink_checks(topo: Topology) -> None:
    for k, n in topo.nodes.items():
        d = n.device
        if not d or n.layer not in ("access", "distribution"):
            continue
        ups = topo.uplinks(k)
        if not ups:
            continue
        active, live = 0, []
        for up in ups:
            ln = topo.link(k, up)
            assert ln is not None
            n_up = 0
            for pa, pb in ln.ports:
                port = pa if ln.a == k else pb
                iface = _iface(d, port)
                n_up += 1 if (iface is None or iface.enabled) else 0
            active += n_up
            if n_up:
                live.append(up)
        if active < 2:
            down = [u for u in ups if u not in live]
            _add(d, Finding(check_id="topology.single-uplink", severity=Severity.medium,
                            title=f"Single active uplink ({', '.join(live) or 'none'})",
                            detail="A single link or upstream switch failure isolates this switch."
                            + (f" Configured but shut down towards: {', '.join(down)}." if down else ""),
                            recommendation="Add a second uplink, ideally to a different upstream switch.",
                            evidence=ups))


def vlan_name_checks(topo: Topology) -> None:
    for comp in topo.components():
        names: dict[int, Counter] = defaultdict(Counter)
        holders: dict[tuple[int, str], list[Device]] = defaultdict(list)
        for k in comp:
            d = topo.nodes[k].device
            if not d:
                continue
            for v in d.vlans:
                if v.name and v.id != 1:
                    names[v.id][v.name] += 1
                    holders[(v.id, v.name)].append(d)
        for vid, cnt in names.items():
            if len(cnt) < 2:
                continue
            common = cnt.most_common(1)[0][0]
            for name, _ in cnt.items():
                if name == common:
                    continue
                for d in holders[(vid, name)]:
                    _add(d, Finding(check_id="vlan.name-mismatch", severity=Severity.low,
                                    title=f"VLAN {vid} named '{name}' (elsewhere '{common}')",
                                    recommendation=f"Rename VLAN {vid} to '{common}' for consistent documentation.",
                                    evidence=[f"{h.hostname}: {name}" for h in holders[(vid, name)]]))


def analyze_fleet(snap: Snapshot, topo: Topology | None = None) -> Topology:
    topo = topo or build_topology(snap)
    link_checks(topo)
    uplink_checks(topo)
    vlan_name_checks(topo)
    for d in snap.devices:
        d.findings.sort(key=lambda f: -f.severity.rank)
    return topo
