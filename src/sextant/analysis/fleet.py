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


def _bundle(d: Device, i):
    """The LAG an interface belongs to (where its switchport settings live), else the interface."""
    if i is not None and i.lag:
        lag = _iface(d, i.lag)
        if lag is not None:
            return lag
    return i


def link_checks(topo: Topology) -> None:
    for ln in topo.links.values():
        da, db = topo.nodes[ln.a].device, topo.nodes[ln.b].device
        if not (da and db):
            continue
        seen: set[tuple[str, str]] = set()
        for pa, pb in ln.ports:
            # CDP/LLDP name the member ports; a bundle's mode and VLANs are configured on the LAG
            ia, ib = _bundle(da, _iface(da, pa)), _bundle(db, _iface(db, pb))
            if not (ia and ib) or not (ia.enabled and ib.enabled) or (ia.name, ib.name) in seen:
                continue
            seen.add((ia.name, ib.name))
            where = f"{da.hostname} {short_ifname(ia.name)} ↔ {db.hostname} {short_ifname(ib.name)}"
            modes = {ia.mode, ib.mode}
            if PortMode.trunk in modes and PortMode.access in modes:
                for d in (da, db):
                    _add(d, Finding(check_id="link.mode-mismatch", severity=Severity.high,
                                    title=f"Trunk/access mismatch: {where}",
                                    detail="One end is a trunk, the other an access port: VLANs leak or drop.",
                                    recommendation="Configure both ends the same way.", evidence=[where]))
            elif modes == {PortMode.trunk}:
                na, nb = ia.native(), ib.native()  # None: all tagged, untagged frames are dropped
                if na != nb:
                    for d in (da, db):
                        _add(d, Finding(check_id="link.native-mismatch", severity=Severity.medium,
                                        title=f"Native VLAN mismatch ({na or 'none'} vs {nb or 'none'}): {where}",
                                        detail="Untagged traffic is bridged between two different VLANs"
                                               + (", or dropped by the end that tags every VLAN." if None in (na, nb)
                                                  else "."),
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


# modes that only meet at a region boundary (CST). PVST and rapid-PVST run the same per-VLAN trees and
# interoperate port by port, so they are one family here; legacy PVST is its own (per-switch) finding
_MODE_FAMILY = {"mstp": "MSTP", "mst": "MSTP", "rstp": "RSTP/STP", "stp": "RSTP/STP", "rapid-pvst": "PVST",
                "pvst": "PVST", "rpvst": "PVST", "pvst (default)": "PVST", "rapid-pvst (default)": "PVST"}


def stp_checks(snap: Snapshot, topo: Topology) -> None:
    from sextant.stp import build_stp, same_tree

    for site in build_stp(snap, topo):
        devs = {k: topo.nodes[k].device for k in site.modes}
        families = defaultdict(list)
        for k, mode in site.modes.items():
            if mode and mode != "disabled":
                families[_MODE_FAMILY.get(mode, mode)].append(topo.nodes[k].name)
        if len(families) > 1:
            text = "; ".join(f"{fam}: {', '.join(sorted(names))}" for fam, names in sorted(families.items()))
            for d in devs.values():
                _add(d, Finding(check_id="stp.mixed-modes", severity=Severity.medium,
                                title="Mixed spanning-tree modes in the site",
                                detail=f"{text}. Different modes only interoperate through the common spanning "
                                       "tree (PVST simulation on the MST boundary), which limits root placement "
                                       "and makes failures harder to predict.",
                                recommendation="Run one mode site-wide (MSTP on mixed-vendor networks), or make "
                                               "the MST region's CIST root also the root for every PVST VLAN.",
                                evidence=[text]))
        main = [t for t in site.trees if not t.trivial and not t.default_vlan]
        for tree in site.trees:
            if tree.trivial or (tree.default_vlan and any(same_tree(tree, t) for t in main)):
                continue  # VLAN 1 on the same tree as other VLANs: their findings cover it
            # VLAN 1 normally carries no traffic: where its root sits is hygiene, not design
            placement = Severity.low if tree.default_vlan else Severity.medium
            root = topo.nodes.get(tree.root_node) if tree.root_node else None
            who = (f"{root.name}{' (inferred)' if tree.root_inferred else ''}" if root
                   else f"bridge {tree.root_mac}")
            involved = [topo.nodes[k].device for k in tree.reporters] + ([root.device] if root and root.device else [])
            if tree.default_priority():
                for d in filter(None, involved):
                    _add(d, Finding(check_id="stp.default-priority-root", severity=placement,
                                    title=f"STP root for {tree.vlan_label} chosen by MAC address ({who})",
                                    detail=f"No switch has a lower bridge priority than the default, so the bridge "
                                           f"with the lowest MAC address ({tree.root_mac}) became root. Root "
                                           "placement then depends on hardware, not design.",
                                    recommendation="Give the intended core/distribution switch the lowest "
                                                   "bridge priority (e.g. 4096) and its peer the next (8192): "
                                                   f"'spanning-tree vlan {tree.vlan_text} root primary' on Cisco "
                                                   "PVST, 'spanning-tree priority 1' on Aruba/HPE MSTP.",
                                    evidence=[f"root priority {tree.root_priority}, MAC {tree.root_mac}"]))
            if root and root.layer == "access" and root.device and root.layer_reason != "unconnected switch":
                tie = _pvst_tie(topo, tree, list(site.modes))
                _add(root.device, Finding(check_id="stp.root-on-access", severity=placement,
                                          title=f"STP root for {tree.vlan_label} is an access switch",
                                          detail=f"{root.name} is in the access layer; traffic between other "
                                                 "switches is pulled through it." + tie,
                                          recommendation="Make a core or distribution switch the root bridge"
                                                         + (" with a priority below the access switch's (e.g. "
                                                            "'spanning-tree vlan 1-4094 priority 4096'), or raise the "
                                                            "MST priority on the access switch."
                                                            if tie else ".")))
            if tree.outside_root:
                _outside_root(topo, tree, list(site.modes))
            if tree.disagreement:
                text = ", ".join(f"{topo.nodes[k].name} sees {mac}" for k, mac in tree.disagreement.items())
                for k in tree.disagreement:
                    _add(topo.nodes[k].device, Finding(
                        check_id="stp.root-disagreement", severity=Severity.high,
                        title=f"Switches disagree on the STP root for {tree.vlan_label}",
                        detail=f"Most switches see {tree.root_mac}; {text}. The tree is partitioned or a "
                               "mode boundary is inconsistent.",
                        recommendation="Check STP mode, VLAN membership and BPDU filtering between these switches."))


def _pvst_tie(topo: Topology, tree, switches: list[str]) -> str:
    """Why an MST/RSTP bridge wins against PVST switches with the same configured priority: PVST adds the
    VLAN id to it (extended system ID), MST and 802.1D bridges do not. Empty when that is not the reason."""
    from sextant.stp import PVST_MODES, _configured

    vlan = tree.vlans[0] if tree.vlans else 1
    root = topo.nodes[tree.root_node].device if tree.root_node in topo.nodes else None
    if root and root.spanning_tree and any((root.spanning_tree.mode or "").startswith(m) for m in PVST_MODES):
        return ""  # a PVST root: plain priority/MAC, nothing hidden
    pvst = [n for n in switches if n != tree.root_node and topo.nodes[n].device and topo.nodes[n].device.spanning_tree
            and any((topo.nodes[n].device.spanning_tree.mode or "").startswith(m) for m in PVST_MODES)]
    bases = [p for p in (_configured(topo.nodes[n].device, vlan) for n in pvst) if p is not None]
    if not bases or tree.base_priority is None or tree.base_priority != min(bases):
        return ""
    best = min(bases)
    who = next(topo.nodes[n].name for n in pvst if _configured(topo.nodes[n].device, vlan) == best)
    return (f" Its priority {tree.base_priority} is not higher than the {best} configured on {who}: PVST "
            f"advertises {best} plus the VLAN id ({best + vlan} for VLAN {vlan}), MST and 802.1D bridges "
            "advertise the priority alone.")


def _outside_root(topo: Topology, tree, switches: list[str]) -> None:
    """The root bridge is not an imported switch: say where it is reached and why it may have won."""
    from sextant.drivers._util import short_ifname
    from sextant.model import PortMode
    from sextant.topology import ifkey

    k, port = tree.root_entry
    d = topo.nodes[k].device
    iface = next((i for i in d.interfaces if ifkey(i.name) == ifkey(port)), None)
    access = iface is not None and iface.mode == PortMode.access
    who = tree.root_label or (topo.nodes[tree.root_node].name if tree.root_node in topo.nodes else None)
    prio = f", priority {tree.base_priority}" if tree.base_priority is not None else ""
    detail = (f"Root bridge {tree.root_mac}{f' ({who})' if who else ''}{prio}, is not one "
              f"of the imported switches. It is reached through {short_ifname(port)} on {d.hostname}"
              + (f", an access port in VLAN {iface.access_vlan or 1}" if access else "") + ".")
    if access:
        detail += (" A switch treats BPDUs arriving on an access port as that VLAN's own, so a device behind it "
                   "(for example one running MST, with the same subnet on another VLAN) can win the election.")
    detail += _pvst_tie(topo, tree, switches)
    title = f"STP root for {tree.vlan_label} is outside the documented switches" + (f" ({who})" if who else "")
    _add(d, Finding(check_id="stp.root-outside", severity=Severity.high, title=title, detail=detail,
                    recommendation=f"If that device should not be root: 'spanning-tree guard root' on "
                                   f"{short_ifname(port)}" + (" (or BPDU guard if only end devices belong there)"
                                                               if access else "")
                                   + ", and a lower priority on the intended root (0, or 'root primary').",
                    evidence=[f"{d.hostname} {short_ifname(port)}: root port towards {tree.root_mac}"]))


_MANAGER = ("manager", "mrm")
_AUTO = ("auto-manager", "auto-mgr")
_RING_DOWN = ("open", "failed", "fail", "broken")


def ring_checks(topo: Topology) -> None:
    """MRP/REP/ERPS rings: broken rings, and MRP rings with no manager (nothing blocks: a loop) or two."""
    from sextant.rings import ring_groups

    for g in ring_groups(topo):
        devs = {k: topo.nodes[k].device for k in g.members if topo.nodes[k].device}
        names = ", ".join(topo.nodes[k].name for k in g.members)
        down = {k: st for k, st in g.states.items() if st in _RING_DOWN}
        if down:
            for k in down:
                _add(devs[k], Finding(check_id="ring.open", severity=Severity.high, title=f"{g.label} is {down[k]}",
                                      detail=f"The ring ({names}) has lost a link or a switch; it still forwards, "
                                             "but without redundancy.",
                                      recommendation="Find the failed ring port ('show mrp ring' / 'show rep "
                                                     "topology') and restore the link.",
                                      evidence=[f"{topo.nodes[k].name}: {down[k]}"]))
        if g.protocol != "MRP" or len(devs) != len(g.members) or len(g.roles) != len(g.members) \
                or len(g.links) < len(g.members):
            continue  # a ring member was not imported (its role is unknown) or the ring is not closed on paper
        roles = list(g.roles.values())
        managers = [topo.nodes[k].name for k, r in g.roles.items() if r in _MANAGER]
        if not managers and not any(r in _AUTO for r in roles):
            for d in devs.values():
                _add(d, Finding(check_id="ring.no-manager", severity=Severity.high,
                                title=f"{g.label} has no MRP manager",
                                detail=f"Every ring switch ({names}) is a client. Only the manager blocks a ring port, "
                                       "so a closed ring with no manager is a loop.",
                                recommendation="Make exactly one switch the manager ('mode manager' under the ring)."))
        elif len(managers) > 1:
            for d in devs.values():
                _add(d, Finding(check_id="ring.many-managers", severity=Severity.medium,
                                title=f"{g.label} has {len(managers)} MRP managers",
                                detail=f"Managers: {', '.join(managers)}. A ring needs exactly one; with several, "
                                       "failover depends on which one wins.",
                                recommendation="Keep one manager and make the others clients (or all auto-manager)."))


def analyze_fleet(snap: Snapshot, topo: Topology | None = None) -> Topology:
    topo = topo or build_topology(snap)
    link_checks(topo)
    uplink_checks(topo)
    vlan_name_checks(topo)
    stp_checks(snap, topo)
    ring_checks(topo)
    for d in snap.devices:
        d.findings.sort(key=lambda f: -f.severity.rank)
    return topo
