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


def topology_page(doc: Document, topo: Topology) -> None:
    """Summary: one diagram per site, nothing else (it is a glance page)."""
    groups = _groups(topo)
    if not groups:
        return
    from sextant.doc import PageBreak

    doc.add(PageBreak(), Heading("Site topology", 1, "sum-topology", toc=False))
    for g in groups:
        doc.add(Diagram(g, title=f"Site {site_name(topo, g)}", topology=topo))


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
