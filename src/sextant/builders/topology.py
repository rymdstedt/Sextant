"""Topology chapter (As-Built) and topology page (Summary)."""

from __future__ import annotations

import re
from collections import defaultdict

from sextant.builders.common import dash, device_status, join
from sextant.doc import Callout, Cell, Diagram, Document, Heading, Paragraph, Table, slug
from sextant.drivers._util import compress_vlans, short_ifname
from sextant.model import DeviceRole, Snapshot
from sextant.topology import LAYER_LABEL, LAYERS, SOURCE_LABEL, Topology, site_name

MIN_DIAGRAM = 3  # nodes; smaller groups are listed, not drawn


def compress_names(names: list[str]) -> str:
    """['kis-acc-sw01', 'kis-acc-sw02', 'kis-acc-sw03', 'kis-acc-sw09'] -> 'kis-acc-sw01–03, 09'."""
    groups: dict[str, list[tuple[int, str]]] = defaultdict(list)
    loose = []
    for n in sorted(set(names)):
        mt = re.match(r"^(.*?)(\d+)$", n)
        if mt:
            groups[mt.group(1)].append((int(mt.group(2)), mt.group(2)))
        else:
            loose.append(n)
    parts = []
    for prefix, nums in sorted(groups.items()):
        nums.sort()
        runs, start = [], 0
        for i in range(1, len(nums) + 1):
            if i == len(nums) or nums[i][0] != nums[i - 1][0] + 1:
                a, b = nums[start][1], nums[i - 1][1]
                runs.append(a if start == i - 1 else f"{a}–{b}")
                start = i
        parts.append(prefix + ", ".join(runs) if len(runs) > 0 else prefix)
    return ", ".join(parts + loose)


def _groups(topo: Topology) -> list[list[str]]:
    return [g for g in topo.components() if len(g) >= MIN_DIAGRAM]


def topology_chapter(doc: Document, snap: Snapshot, topo: Topology) -> None:
    groups = _groups(topo)
    if not groups and not topo.links:
        return
    doc.add(Heading("Topology", 1, "topology"))
    sources = sorted({SOURCE_LABEL[s] for ln in topo.links.values() for s in ln.sources})
    doc.add(Paragraph(
        f"{len([n for n in topo.nodes.values() if n.device])} documented devices and "
        f"{len(topo.links)} device-to-device connections, discovered via {join(sources, ', ')}. "
        "Layers are taken from the inventory where set, otherwise from device role, hostname and position "
        "in the topology.", "ingress"))
    if any(ln.inferred for ln in topo.links.values()):
        doc.add(Callout("Some links are inferred from interface descriptions or shared point-to-point subnets "
                        "(no CDP/LLDP data). They are marked in the Via column; verify them on site.", "info"))
    for n, g in enumerate(groups, 1):
        name = site_name(topo, g)
        doc.add(Heading(f"Site {name}", 2, f"topo-{slug(name)}-{n}"))
        doc.add(Diagram(g, title=None, topology=topo,
                        caption="Devices grouped by layer. Framed groups share the same uplinks; the number on a "
                                "link is the count of physical links it represents."))

    # layers
    rows = []
    for g in groups or [list(topo.nodes)]:
        for lay, nodes in topo.by_layer(g).items():
            for n in nodes:
                if n.kind == "host" and not n.device:
                    continue
                if n.device:
                    status, label = device_status(n.device)
                    st = Cell(label, status)
                else:
                    st = Cell("Not documented", "neutral")
                ups = topo.uplinks(n.key)
                rows.append([LAYER_LABEL[lay], n.name, dash(n.model), dash(n.mgmt_ip),
                             compress_names([topo.nodes[u].name for u in ups]) or "–", n.layer_reason or "–", st])
    doc.add(Heading("Layers", 2, "topo-layers"))
    doc.add(Table(["Layer", "Device", "Model", "Mgmt IP", "Uplinks to", "Layer from", "Status"], rows,
                  widths=[1.3, 1.8, 1.7, 1.3, 2.4, 1.4, 1.4], compact=True))

    # links, port level
    rows = []
    order = {k: (LAYERS.index(n.layer), n.name) for k, n in topo.nodes.items()}
    for ln in sorted(topo.links.values(), key=lambda x: (min(order[x.a], order[x.b]), max(order[x.a], order[x.b]))):
        a, b = (ln.a, ln.b) if order[ln.a] <= order[ln.b] else (ln.b, ln.a)
        flip = a != ln.a
        via = join(sorted(SOURCE_LABEL[s] for s in ln.sources), ", ")
        lag_a, lag_b = (ln.lag_b, ln.lag_a) if flip else (ln.lag_a, ln.lag_b)
        for pa, pb in ln.ports:
            pa, pb = (pb, pa) if flip else (pa, pb)
            rows.append([topo.nodes[a].name, short_ifname(pa) if pa else "–", topo.nodes[b].name,
                         short_ifname(pb) if pb else "–", join([x for x in (lag_a, lag_b) if x], " / "), via])
    if rows:
        doc.add(Heading("Links", 2, "topo-links"))
        doc.add(Table(["Device", "Port", "Neighbor", "Neighbor port", "LAG", "Via"], rows,
                      widths=[2.2, 1.3, 2.2, 1.4, 1.6, 1.6], compact=True))
    _rings_table(doc, topo)

    # VLAN distribution over switches
    vl: dict[int, dict] = {}
    for d in snap.devices:
        if d.role not in (DeviceRole.switch, DeviceRole.router):
            continue
        for v in d.vlans:
            e = vl.setdefault(v.id, {"names": set(), "switches": [], "gw": []})
            if v.name:
                e["names"].add(v.name)
            e["switches"].append(d.hostname)
            e["gw"] += [f"{ip} ({d.hostname})" for ip in v.svi_ipv4]
    if len({h for e in vl.values() for h in e["switches"]}) > 1:
        rows = []
        for vid in sorted(vl):
            e = vl[vid]
            names = sorted(e["names"])
            name_cell = Cell(" / ".join(names), "warning") if len(names) > 1 else (names[0] if names else "–")
            rows.append([str(vid), name_cell, str(len(e["switches"])), compress_names(e["switches"]),
                         join(e["gw"][:3], "; ") + (f" (+{len(e['gw']) - 3})" if len(e["gw"]) > 3 else "")])
        doc.add(Heading("VLAN distribution", 2, "topo-vlans"))
        doc.add(Paragraph("Which switches carry each VLAN. Differing names for the same VLAN are highlighted.",
                          "muted"))
        doc.add(Table(["VLAN", "Name", "Switches", "Present on", "Gateway (SVI)"], rows, numeric={0, 2},
                      widths=[0.7, 1.6, 0.9, 3.6, 3.2], compact=True))
    stp_chapter(doc, snap, topo)


RING_STATUS = {"closed": "success", "complete": "success", "open": "error", "failed": "error", "fail": "error"}


def _rings_table(doc: Document, topo: Topology) -> None:
    from sextant.rings import ring_groups

    rows = []
    for g in ring_groups(topo):
        roles = [f"{topo.nodes[k].name} {r}" for k, r in g.roles.items() if r not in ("client", "mrc", "transit")]
        # clients report "unknown": only the manager knows whether the ring is closed
        states = sorted(set(g.states.values()), key=lambda st: st == "unknown")
        known = [st for st in states if st != "unknown"]
        worst = next((RING_STATUS[st] for st in known if RING_STATUS.get(st) == "error"),
                     RING_STATUS.get(known[0], "neutral") if known else "neutral")
        rows.append([g.label, compress_names([topo.nodes[k].name for k in g.members]), join(roles) or "–",
                     Cell(join(known) if known else "unknown (only the manager reports it)", worst)
                     if states else "–", str(len(g.links))])
    if rows:
        doc.add(Heading("Ring redundancy", 2, "topo-rings"))
        doc.add(Paragraph("Rings protected by a ring protocol instead of spanning tree. State is from 'show mrp ring' "
                          "/ 'show rep topology' where captured.", "muted"))
        doc.add(Table(["Ring", "Switches", "Manager / edge", "State", "Ring links"], rows, numeric={4},
                      widths=[1.4, 3.4, 2.2, 1, 0.9], compact=True))


# --------------------------------------------------------------------------- spanning tree

_BLOCKING = ("alternate", "backup")
MAX_STP_DIAGRAMS = 6  # per layer-2 domain


def _priority_text(prio: dict[str, int]) -> str:
    if not prio:
        return "–"
    if len(prio) == 1:
        return str(next(iter(prio.values())))
    default = prio.get("default")
    rest = [f"{k if k.startswith('mst') else 'VLAN ' + k}: {v}" for k, v in prio.items() if k != "default"]
    return "; ".join(rest + ([f"others {default}"] if default is not None else []))


def _blocking_ports(d) -> list[str]:
    out = []
    for inst in d.spanning_tree.instances:
        for p in inst.ports:
            if (p.role in _BLOCKING or p.state in ("blocking", "broken")) and p.interface not in out:
                out.append(p.interface)
    return out


def _root_name(topo: Topology, tree) -> str:
    outside = " (not imported)" if tree.outside_root else ""
    if tree.root_node and tree.root_node in topo.nodes:
        return topo.nodes[tree.root_node].name + (" (inferred)" if tree.root_inferred else outside)
    if tree.root_label:
        return f"{tree.root_label}{outside}"
    return f"bridge {tree.root_mac or 'unknown'}{outside}"


def stp_chapter(doc: Document, snap: Snapshot, topo: Topology) -> None:
    """As-Built: per layer-2 domain an overview table, then one diagram per distinct spanning tree."""
    from sextant.stp import build_stp, same_tree

    sites = build_stp(snap, topo)
    if not sites:
        return
    doc.add(Heading("Spanning tree", 2, "topo-stp"))
    doc.add(Paragraph("The active spanning tree per group of VLANs that share a root bridge and the same "
                      "forwarding paths, built from 'show spanning-tree' output. Blocked links are the redundant "
                      "paths STP keeps in standby; a root marked inferred did not report data itself and was "
                      "matched on its configured priority.", "muted"))
    lvl = 3
    names = [site_name(topo, site.keys) for site in sites]
    for site, name in zip(sites, names, strict=True):
        if names.count(name) > 1:  # same site, several layer-2 domains: name them by their top switches
            top = min(LAYERS.index(topo.nodes[k].layer) for k in site.modes)
            name = f"{name}, {compress_names([topo.nodes[k].name for k in site.modes if LAYERS.index(topo.nodes[k].layer) == top])}"
        if len(sites) > 1:
            doc.add(Heading(f"{name} (layer-2 domain)", 3, f"stp-{slug(name)}"))
            lvl = 4
        rows = []
        live = [t for t in site.trees if not t.trivial]
        main = [t for t in live if not t.default_vlan]
        default = [t for t in live if t.default_vlan]
        ring_of = _ring_roles(topo, site.keys)
        # a root found outside the domain (its uplink is not documented) is listed too
        keys = set(site.modes) | {t.root_node for t in live if t.root_node and topo.nodes[t.root_node].device
                                  and topo.nodes[t.root_node].device.spanning_tree}
        for k in sorted(keys, key=lambda x: (LAYERS.index(topo.nodes[x].layer), topo.nodes[x].name)):
            d = topo.nodes[k].device
            st = d.spanning_tree
            root_for = [t.vlan_label + (" (inferred)" if t.root_inferred else "") for t in main + default
                        if t.root_node == k]
            rps = sorted({t.root_ports[k] for t in live if k in t.root_ports})
            blk = _blocking_ports(d)
            if not root_for and any(t.ring for t in site.trees if k in t.reporters):
                root_for = ["– (only of itself behind the ring)"]
            rows.append([d.hostname, join([st.mode, ring_of.get(k)], " · ") or "–",
                         _priority_text(st.configured_priority), dash(st.bridge_mac),
                         join(root_for, "; ") or "–", join(rps) or "–",
                         Cell(join(blk), "warning") if blk else "–"])
        doc.add(Table(["Switch", "Mode", "Configured priority", "Bridge MAC", "Root for", "Root port", "Blocking"],
                      rows, widths=[1.7, 1.0, 1.6, 1.4, 2.6, 1.0, 1.3], compact=True))
        if site.prediction:
            doc.add(Paragraph(f"From the configuration alone: {site.prediction}", "muted"))
        if not site.trees:
            doc.add(Callout("No runtime spanning-tree output was collected for this domain, so the active tree "
                            "cannot be drawn. Add 'show spanning-tree' to the capture (it is in the default "
                            "command set when collecting over SSH).", "info"))
            _vlan_index(doc, site, topo)
            continue
        # per-VLAN root placement can give many trees: draw the largest, list the rest
        drawn = sorted(sorted(main, key=lambda t: -len(t.vlans))[:MAX_STP_DIAGRAMS],
                       key=lambda t: t.vlans[0] if t.vlans else 0)
        for t in drawn:
            _tree_section(doc, topo, site, t, lvl)
        rest = [t for t in main if t not in drawn]
        if rest:
            doc.add(Table(["VLANs", "Root bridge", "Blocked links"],
                          [[t.vlan_label, _root_name(topo, t),
                            str(sum(1 for st in t.links.values() if st.state == "blocked"))] for t in rest],
                          title=f"Other trees ({len(rest)}, not drawn)", numeric={2}, widths=[3.5, 3, 1.2],
                          compact=True))
        if default:
            doc.add(Heading("VLAN 1 (default VLAN)", lvl, None, toc=False))
            doc.add(Paragraph("VLAN 1 normally carries no user traffic, so it is shown apart from the trees above. "
                              "Switches still send CDP, VTP, DTP and PAgP on it, and it is every untagged port's "
                              "VLAN until configured otherwise.", "muted"))
            for t in default:
                twin = next((m for m in main if same_tree(t, m)), None)
                if twin:  # nothing new to draw
                    on = (f"As seen by {compress_names([topo.nodes[k].name for k in t.reporters])}: root"
                          if len(default) > 1 else "Root")
                    doc.add(Paragraph(f"{on.strip()} {_root_name(topo, t)}, with the same forwarding and blocked "
                                      f"links as {twin.vlan_label}" + (" (drawn above)." if twin in drawn else "."),
                                      "body"))
                else:
                    _tree_section(doc, topo, site, t, lvl, heading=len(default) > 1)
        _ring_text(doc, topo, site)
        _vlan_index(doc, site, topo)


def _ring_roles(topo: Topology, keys: list[str]) -> dict[str, str]:
    """node -> 'MRP ring 1 client' for the overview table."""
    out: dict[str, str] = {}
    for k in keys:
        d = topo.nodes[k].device
        if d and d.rings:
            out[k] = ", ".join(f"{r.label}{f' {r.role}' if r.role else ''}" for r in d.rings)
    return out


def _ring_text(doc: Document, topo: Topology, site) -> None:
    """Switches joined only by a ring protocol: no spanning tree between them, each is its own root."""
    islands: dict[str, list] = {}
    for t in site.trees:
        if t.ring:
            islands.setdefault(t.ring, []).append(t)
    for ring, trees in sorted(islands.items()):
        names = sorted({topo.nodes[k].name for t in trees for k in t.reporters})
        vlans = sorted({v for t in trees for v in t.vlans})
        doc.add(Callout(f"{ring} ({compress_names(names)}) protects the loop itself: spanning tree does not run on "
                        f"the ring ports and no BPDUs cross them, so each ring switch reports itself as root for "
                        f"VLAN{'s' if len(vlans) > 1 else ''} {compress_vlans(vlans)}. That is expected and is not "
                        "a root other switches use.", "info", "Ring redundancy instead of spanning tree"))


def _tree_section(doc: Document, topo: Topology, site, t, lvl: int, heading: bool = True) -> None:
    root = _root_name(topo, t)
    if heading:
        doc.add(Heading(f"{t.vlan_label}: root {root}", lvl, None, toc=False))
    else:
        doc.add(Paragraph(f"Root {root}.", "body"))
    blocked = [(st, a, b) for (a, b), st in t.links.items() if st.state == "blocked"]
    absent = sum(1 for st in t.links.values() if st.state == "absent")
    partial = [(st, a, b) for (a, b), st in t.links.items() if st.vlans]
    facts = [f"Root priority {t.base_priority}" if t.root_priority is not None else None,
             f"MAC {t.root_mac}" if t.root_mac else None,
             f"{len(blocked)} blocked link{'s' if len(blocked) != 1 else ''}",
             f"{len(partial)} carrying only some of these VLANs" if partial else None,
             f"{absent} link{'s' if absent != 1 else ''} not carrying these VLANs" if absent else None]
    rings = sorted({st.ring for st in t.links.values() if st.state == "ring" and st.ring})
    facts.append(f"{', '.join(rings)}: ring links, no spanning tree" if rings else None)
    doc.add(Diagram(site.keys, title=None, topology=topo, stp=t,
                    caption=" · ".join(f for f in facts if f)))
    if blocked:
        brows = []
        for st, a, b in sorted(blocked, key=lambda x: topo.nodes[x[0].blocked_at or x[1]].name):
            at = st.blocked_at or a
            other = b if at == a else a
            brows.append([topo.nodes[at].name, dash(st.blocked_port), topo.nodes[other].name])
        doc.add(Table(["Blocking switch", "Port", "Link to"], brows, widths=[2.5, 1.5, 2.5], compact=True))
    if partial:
        prow = sorted([sorted([topo.nodes[a].name, topo.nodes[b].name]) + [compress_vlans(st.vlans)]
                       for st, a, b in partial])
        doc.add(Table(["Switch", "Neighbor", "Carries VLANs"], prow, title="Trunks carrying some of these VLANs",
                      widths=[2.2, 2.2, 3.6], compact=True))
    if t.disagreement:
        text = "; ".join(f"{topo.nodes[k].name} sees root {mac}" for k, mac in t.disagreement.items())
        doc.add(Callout(f"Not every switch agrees on the root: {text}.", "error", "Root disagreement"))


def _vlan_index(doc: Document, site, topo: Topology) -> None:
    """Every VLAN of the domain: its tree, or why it has none. Neighbouring VLANs with the same answer share a row."""
    per_vlan: dict[int, list] = {}
    for t in site.trees:
        if not t.trivial:
            for v in t.vlans:
                per_vlan.setdefault(v, []).append(t)
    where: dict[int, str] = {}
    for v, trees in per_vlan.items():
        texts = []
        for t in trees:
            via = (f", reached through {topo.nodes[t.root_entry[0]].name} {t.root_entry[1]}"
                   if t.root_entry and t.outside_root else "")
            # several trees for one VLAN (a partitioned VLAN): say which switches each one covers
            on = f" (seen by {compress_names([topo.nodes[k].name for k in t.reporters])})" if len(trees) > 1 else ""
            texts.append(f"Root {_root_name(topo, t)}{via}{on}")
        where[v] = "; ".join(texts) + (" (VLAN 1 section)" if v == 1 else "")
    where.update({v: n for v, n in site.vlan_notes.items() if v not in where})
    if not where:
        return
    rows: list[list] = []
    run: list[int] = []
    for v in sorted(where):
        if run and where[run[-1]] == where[v]:
            run.append(v)
            continue
        if run:
            rows.append([compress_vlans(run), where[run[0]]])
        run = [v]
    rows.append([compress_vlans(run), where[run[0]]])
    doc.add(Table(["VLANs", "Spanning tree"], rows, title="Spanning tree per VLAN", widths=[1.6, 6.4], compact=True))


def stp_glance(doc: Document, snap: Snapshot, topo: Topology) -> None:
    """Summary: one line per spanning tree."""
    from sextant.stp import build_stp

    rows = []
    for site in build_stp(snap, topo):
        top = min(LAYERS.index(topo.nodes[k].layer) for k in site.modes)
        domain = compress_names([topo.nodes[k].name for k in site.modes if LAYERS.index(topo.nodes[k].layer) == top])
        for t in sorted((t for t in site.trees if not t.trivial), key=lambda t: t.default_vlan):
            blocked = sum(1 for st in t.links.values() if st.state == "blocked")
            rows.append([domain, t.vlan_label, _root_name(topo, t), str(blocked),
                         Cell("disagreement", "error") if t.disagreement else
                         "default VLAN" if t.default_vlan else
                         Cell("default priority", "warning") if t.default_priority() else "–"])
    if rows:
        doc.add(Table(["Layer-2 domain", "VLANs", "Root bridge", "Blocked links", "Note"], rows, numeric={3},
                      title="Spanning tree", widths=[1.4, 2.6, 2.6, 1.1, 1.6], compact=True))


def topology_page(doc: Document, topo: Topology, snap: Snapshot | None = None) -> None:
    """Summary: one diagram per site, nothing else (it is a glance page)."""
    groups = _groups(topo)
    if not groups:
        return
    from sextant.doc import PageBreak

    doc.add(PageBreak(), Heading("Site topology", 1, "sum-topology", toc=False))
    for g in groups:
        doc.add(Diagram(g, title=f"Site {site_name(topo, g)}", topology=topo))
    if snap is not None:
        stp_glance(doc, snap, topo)


def position_facts(topo: Topology, hostname: str) -> list[tuple[str, str]]:
    from sextant.topology import key

    n = topo.nodes.get(key(hostname))
    if not n or not (topo.neighbors(n.key) or n.layer in ("core", "distribution", "access")):
        return []
    ups = topo.uplinks(n.key)
    downs = sorted(k for k in topo.neighbors(n.key) if LAYERS.index(topo.nodes[k].layer) > LAYERS.index(n.layer))
    peers = sorted(k for k in topo.neighbors(n.key) if topo.nodes[k].layer == n.layer)
    return [("Layer", f"{LAYER_LABEL[n.layer]} ({n.layer_reason})" if n.layer_reason else LAYER_LABEL[n.layer]),
            ("Uplinks to", compress_names([topo.nodes[k].name for k in ups]) or "–"),
            ("Peers", compress_names([topo.nodes[k].name for k in peers]) or "–"),
            ("Downlinks to", compress_names([topo.nodes[k].name for k in downs]) or "–")]
