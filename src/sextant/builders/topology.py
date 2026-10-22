"""Topology chapter (As-Built) and topology page (Summary)."""

from __future__ import annotations

import re
from collections import defaultdict

from sextant.builders.common import dash, device_status, join
from sextant.doc import Callout, Cell, Diagram, Document, Heading, Paragraph, Table
from sextant.drivers._util import short_ifname
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
    for g in groups:
        name = site_name(topo, g)
        doc.add(Heading(f"Site {name}", 2, f"topo-{name.lower()}"))
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


# --------------------------------------------------------------------------- spanning tree

_BLOCKING = ("alternate", "backup")


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
    if tree.root_node and tree.root_node in topo.nodes:
        return topo.nodes[tree.root_node].name + (" (inferred)" if tree.root_inferred else "")
    return f"bridge {tree.root_mac or 'unknown'}"


def stp_chapter(doc: Document, snap: Snapshot, topo: Topology) -> None:
    """As-Built: per layer-2 domain an overview table, then one diagram per distinct spanning tree."""
    from sextant.stp import build_stp

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
            doc.add(Heading(f"{name} (layer-2 domain)", 3, f"stp-{name.lower()}"))
            lvl = 4
        rows = []
        live = [t for t in site.trees if not t.trivial]
        # a root found outside the domain (its uplink is not documented) is listed too
        keys = set(site.modes) | {t.root_node for t in live if t.root_node and topo.nodes[t.root_node].device
                                  and topo.nodes[t.root_node].device.spanning_tree}
        for k in sorted(keys, key=lambda x: (LAYERS.index(topo.nodes[x].layer), topo.nodes[x].name)):
            d = topo.nodes[k].device
            st = d.spanning_tree
            root_for = [t.vlan_label + (" (inferred)" if t.root_inferred else "") for t in live if t.root_node == k]
            rps = sorted({t.root_ports[k] for t in live if k in t.root_ports})
            blk = _blocking_ports(d)
            rows.append([d.hostname, dash(st.mode), _priority_text(st.configured_priority), dash(st.bridge_mac),
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
            continue
        local = [t for t in site.trees if t.trivial]
        for t in live:
            root = _root_name(topo, t)
            doc.add(Heading(f"{t.vlan_label}: root {root}", lvl, None, toc=False))
            blocked = [(st, a, b) for (a, b), st in t.links.items() if st.state == "blocked"]
            absent = sum(1 for st in t.links.values() if st.state == "absent")
            facts = [f"Root priority {t.base_priority}" if t.root_priority is not None else None,
                     f"MAC {t.root_mac}" if t.root_mac else None,
                     f"{len(blocked)} blocked link{'s' if len(blocked) != 1 else ''}",
                     f"{absent} link{'s' if absent != 1 else ''} not carrying these VLANs" if absent else None]
            doc.add(Diagram(site.keys, title=None, topology=topo, stp=t,
                            caption=" · ".join(f for f in facts if f)))
            if blocked:
                brows = []
                for st, a, b in sorted(blocked, key=lambda x: topo.nodes[x[0].blocked_at or x[1]].name):
                    at = st.blocked_at or a
                    other = b if at == a else a
                    brows.append([topo.nodes[at].name, dash(st.blocked_port), topo.nodes[other].name])
                doc.add(Table(["Blocking switch", "Port", "Link to"], brows, widths=[2.5, 1.5, 2.5], compact=True))
            if t.disagreement:
                text = "; ".join(f"{topo.nodes[k].name} sees root {mac}" for k, mac in t.disagreement.items())
                doc.add(Callout(f"Not every switch agrees on the root: {text}.", "error", "Root disagreement"))
        if local:
            text = "; ".join(f"{t.vlan_label} on {join([topo.nodes[k].name for k in t.reporters])}"
                             for t in local)
            doc.add(Paragraph(f"Local to one switch (not carried on an inter-switch link): {text}.", "muted"))


def stp_glance(doc: Document, snap: Snapshot, topo: Topology) -> None:
    """Summary: one line per spanning tree."""
    from sextant.stp import build_stp

    rows = []
    for site in build_stp(snap, topo):
        top = min(LAYERS.index(topo.nodes[k].layer) for k in site.modes)
        domain = compress_names([topo.nodes[k].name for k in site.modes if LAYERS.index(topo.nodes[k].layer) == top])
        for t in site.trees:
            if t.trivial:
                continue
            blocked = sum(1 for st in t.links.values() if st.state == "blocked")
            rows.append([domain, t.vlan_label, _root_name(topo, t), str(blocked),
                         Cell("default priority", "warning") if t.default_priority() else
                         (Cell("disagreement", "error") if t.disagreement else "–")])
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
