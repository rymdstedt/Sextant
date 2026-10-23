"""Spanning-tree diagram: the root bridge on top, then switches by hop count from the root.

Forwarding links are solid (thin long dashes when the trunk carries only some of the tree's
VLANs), blocked links dashed in the error colour with the blocking port named, links that do not
carry these VLANs are faint. The root port of each switch is labelled
at its end of the link. A root that is not connected in the documented topology (for example
an uplink without a usable description) is drawn with a dashed "path not documented" link.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import replace
from xml.sax.saxutils import escape

from sextant.builders.common import device_status
from sextant.builders.topology import compress_names
from sextant.drivers._util import compress_vlans
from sextant.model import DeviceRole
from sextant.render.diagram import MARGIN, NODE_H, _status_colors
from sextant.render.diagram import W as BASE_W
from sextant.stp import LinkState, Tree, bridge_priority
from sextant.theme import Theme
from sextant.topology import LAYERS, Topology

GAP = 14
MIN_BOX = 112.0
MAX_W = 1800  # widest canvas before rows wrap
PEER_GAP = 120
BAND_GAP = 62
BAND_LABEL = 22
ROOT = "__root__"


def _nodes(topo: Topology, keys: list[str]) -> list[str]:
    """The switches. Hypervisors, servers and endpoints are left out, and so are routers and
    firewalls unless they run spanning tree: their ports are routed, so a path through them is
    not a layer-2 path and would make the tree look wrong."""
    out = []
    l3 = (DeviceRole.router, DeviceRole.firewall)
    for k in keys:
        n = topo.nodes[k]
        if n.kind == "host":
            continue
        if n.device and n.device.role in (DeviceRole.hypervisor, DeviceRole.server, DeviceRole.storage):
            continue
        if n.device and n.device.role in l3 and not (n.device.spanning_tree and n.device.spanning_tree.instances):
            continue
        out.append(k)
    return out


def _top_of_chain(tree: Tree, drawn: set[str]) -> str | None:
    """Follow root ports upwards from the switches that reported data to the highest node we know."""
    if tree.root_entry and tree.root_entry[0] in drawn:
        return tree.root_entry[0]  # the switch whose root port leads out of the documented network
    for start in tree.reporters:
        cur, seen = start, set()
        while cur in tree.parent and cur not in seen:
            seen.add(cur)
            cur = tree.parent[cur]
        if cur in drawn and cur != tree.root_node:
            return cur
    return None


GROUP_FROM = 12  # drawn switches; above this, leaf switches with the same STP pattern share one box
GROUP_MIN = 3


def _group_leaves(topo: Topology, tree: Tree, drawn: set[str], links: dict, root: str) -> dict[str, list[str]]:
    """Leaf switches (nothing hangs below them) with the same parent and the same link pattern: the
    typical access layer, 'root port to dist A, blocked to dist B'. Port names may differ."""
    if len(drawn) <= GROUP_FROM:
        return {}
    parents = set(tree.parent.values())
    pattern: dict[tuple, list[str]] = defaultdict(list)
    for k in sorted(drawn):
        if k == root or k in parents or k not in tree.parent:
            continue
        mine = []
        for (a, b), st in links.items():
            if k in (a, b):
                other = b if a == k else a
                side = None if st.state != "blocked" else ("self" if st.blocked_at == k else "other")
                mine.append((other, st.state, side, bool(st.vlans)))
        pattern[(tree.parent[k], tuple(sorted(mine)))].append(k)
    return {f"__group{i}__": members for i, members in enumerate(m for m in pattern.values() if len(m) >= GROUP_MIN)}


def _collapse(tree: Tree, links: dict, drawn: set[str], groups: dict[str, list[str]]) -> tuple[Tree, dict, set[str]]:
    """The tree and links with each group's members replaced by the group key."""
    of = {m: g for g, members in groups.items() for m in members}

    def common(values: list) -> str | None:
        return values[0] if values and all(v == values[0] for v in values) else None

    new_links: dict[tuple[str, str], LinkState] = {}
    gathered: dict[tuple[str, str], list[LinkState]] = defaultdict(list)
    for (a, b), st in links.items():
        pair = tuple(sorted((of.get(a, a), of.get(b, b))))
        gathered[pair].append(st)
    for pair, sts in gathered.items():
        st = sts[0]
        vlans = sorted({v for x in sts for v in (x.vlans or [])}) or None  # what the group's links carry
        new_links[pair] = LinkState(st.state, of.get(st.blocked_at, st.blocked_at),
                                    common([x.blocked_port for x in sts]), vlans)
    view = replace(tree, links=new_links,
                   parent={of.get(k, k): of.get(v, v) for k, v in tree.parent.items()},
                   root_ports={},
                   reporters=sorted({of.get(k, k) for k in tree.reporters}))
    for g, members in groups.items():
        rp = common([tree.root_ports.get(m) for m in members])
        if rp:
            view.root_ports[g] = rp
    for k, v in tree.root_ports.items():
        if k not in of:
            view.root_ports[k] = v
    return view, new_links, (drawn - set(of)) | set(groups)


def stp_svg(topo: Topology, keys: list[str], tree: Tree, theme: Theme, title: str | None = None) -> tuple[str, float]:
    c = theme.colors
    status_col = _status_colors(theme)
    drawn = set(_nodes(topo, keys))
    root = tree.root_node
    if root and root not in drawn:
        drawn.add(root)  # root found elsewhere (e.g. a switch whose uplink is undocumented)
    ghost_root = root is None
    if ghost_root:
        root = ROOT
    links = {pair: st for pair, st in tree.links.items() if pair[0] in drawn and pair[1] in drawn}
    degree: dict[str, int] = defaultdict(int)  # links per switch, before grouping
    for a, b in links:
        degree[a] += 1
        degree[b] += 1
    groups = _group_leaves(topo, tree, drawn, links, root)
    if groups:
        tree, links, drawn = _collapse(tree, links, drawn, groups)

    # depth: BFS from the root over links that forward these VLANs (a link that does not carry them is
    # no path); disconnected root -> hang the chain under it
    adj: dict[str, set[str]] = defaultdict(set)
    for (a, b), st in links.items():
        if st.state not in ("blocked", "absent"):
            adj[a].add(b)
            adj[b].add(a)
    chain_top = None
    if root == ROOT or not adj.get(root):
        chain_top = _top_of_chain(tree, drawn)
        if chain_top:
            adj[root].add(chain_top)
            adj[chain_top].add(root)
    depth = {root: 0}
    queue = [root]
    while queue:
        cur = queue.pop(0)
        for nb in sorted(adj[cur], key=lambda k: (0 if tree.parent.get(k) == cur else 1, k)):
            if nb not in depth:
                depth[nb] = depth[cur] + 1
                queue.append(nb)
    rest = sorted(drawn - set(depth))  # not reachable over forwarding links: below the tree
    max_d = max(depth.values(), default=0)
    for k in rest:
        depth[k] = max_d + 1

    # one band per hop count; a band that mixes layers (a peer distribution switch next to the
    # access switches) is split into one row per layer so blocked links run upwards, not sideways
    def rank(k: str) -> int:
        n = topo.nodes.get(groups[k][0] if k in groups else k)
        return LAYERS.index(n.layer) if n and n.layer in LAYERS else len(LAYERS)

    # a switch one hop away in the root's own (non-access) layer, e.g. the second distribution
    # switch, is drawn beside the root: the classic picture with the access layer below both
    peers = {k for k, d in depth.items() if d == 1 and k != ROOT and rank(k) == rank(root)
             and rank(root) < LAYERS.index("access") and degree[k] >= 3}
    row_of = {k: 0 for k in {root} | peers}
    queue = sorted(row_of)
    while queue:
        cur = queue.pop(0)
        for nb in sorted(adj[cur]):
            if nb not in row_of:
                row_of[nb] = row_of[cur] + 1
                queue.append(nb)
    last = max(row_of.values(), default=0) + 1
    for k in depth:
        row_of.setdefault(k, last)
    bands: dict[tuple[int, int], list[str]] = defaultdict(list)
    for k, d in row_of.items():
        bands[(d, rank(k) if d else 0)].append(k)
    # widen the canvas rather than wrap a row (it is scaled to the page); wrap only beyond MAX_W
    widest = max(len(r) for r in bands.values())
    W = min(MAX_W, max(BASE_W, 2 * MARGIN + widest * (MIN_BOX + GAP) - GAP))
    usable = W - 2 * MARGIN
    pos: dict[str, tuple[float, float, float]] = {}
    y = MARGIN + (28 if title else 0)
    band_rows = []
    for d, sub in sorted(bands):
        row = bands[(d, sub)]
        # order under the parent (barycenter of already placed neighbours)
        def bary(k: str) -> float:
            xs = [pos[n][0] + pos[n][2] / 2 for n in adj[k] | {tree.parent.get(k, "")} if n in pos]
            return sum(xs) / len(xs) if xs else W / 2

        row.sort(key=lambda k: (k != root, bary(k), topo.nodes[k].name.lower() if k in topo.nodes else ""))
        gap = PEER_GAP if d == 0 else GAP
        w = 200.0 if len(row) <= 3 else 160.0
        per_line = max(1, int((usable + gap) // (w + gap)))
        if len(row) > per_line:
            w = max(MIN_BOX, (usable + gap) / len(row) - gap)
            per_line = max(1, int((usable + gap) // (w + gap)))
        top = y
        first = not band_rows or band_rows[-1][0] != d
        y += BAND_LABEL if first else 0
        for i in range(0, len(row), per_line):
            line = row[i:i + per_line]
            total = len(line) * w + (len(line) - 1) * gap
            x0 = MARGIN + (usable - total) / 2
            for j, k in enumerate(line):
                pos[k] = (x0 + j * (w + gap), y, w)
            y += NODE_H + 18
        band_rows.append((d, top, y - 18, first))
        y += BAND_GAP - 18
    height = y - BAND_GAP + 18 + 46

    font = escape(theme.fonts.stack, {'"': ""})
    out = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {height:.0f}" width="{W}" height="{height:.0f}" '
           f'font-family="{font}" role="img" aria-label="{escape(title or "Spanning tree")}">',
           f'<rect width="{W}" height="{height:.0f}" fill="#ffffff"/>']
    if title:
        out.append(f'<text x="{MARGIN}" y="{MARGIN + 15}" font-size="16" font-weight="700" fill="{c.primary}">'
                   f'{escape(title)}</text>')
    taken = [(x - 2, yy - 2, x + w + 2, yy + NODE_H + 2) for x, yy, w in pos.values()]
    spans: dict[int, list[float]] = {}
    for d, top, bot, _first in band_rows:
        span = spans.setdefault(d, [top, bot])
        span[0], span[1] = min(span[0], top), max(span[1], bot)
    for d, (top, bot) in spans.items():
        if d % 2 == 0:
            out.append(f'<rect x="0" y="{top - 10:.1f}" width="{W}" height="{bot - top + 22:.1f}" fill="{c.gray_50}"/>')
    band_labels = []
    for d, top, _bot, first in band_rows:
        if not first:
            continue
        hops = sorted({depth[k] for k, r in row_of.items() if r == d and k not in rest})
        if d == 0:
            label = "ROOT BRIDGE AND PEERS" if peers else "ROOT BRIDGE"
        elif not hops:
            label = "NOT IN TREE / NO DATA"
        else:
            span_txt = str(hops[0]) if len(hops) == 1 else f"{hops[0]}–{hops[-1]}"
            label = f"{span_txt} HOP{'S' if hops[-1] > 1 else ''} FROM ROOT"
        taken.append((MARGIN, top - 2, MARGIN + 7.2 * len(label), top + 12))
        halo = c.gray_50 if d % 2 == 0 else "#ffffff"  # drawn over the links, so keep it legible
        txt = f'<text x="{MARGIN}" y="{top + 8:.1f}" font-size="10" font-weight="700" letter-spacing="1.2" '
        band_labels.append(f'{txt}fill="{halo}" stroke="{halo}" stroke-width="5">{label}</text>'
                           f'{txt}fill="{c.gray_600}">{label}</text>')

    def mid(k: str) -> tuple[float, float, float, float]:
        x, yy, w = pos[k]
        return x, yy, w, NODE_H

    # links; labels sit near the end they describe (the blocking port, the root port) and are
    # nudged along the link until they clear the boxes and the labels already placed
    parts, pending = [], []

    def cx(k: str) -> float:
        return pos[k][0] + pos[k][2] / 2

    def adjacent(a: str, b: str) -> bool:
        lo, hi = sorted((cx(a), cx(b)))
        return not any(abs(pos[k][1] - pos[a][1]) < 1 and lo < cx(k) < hi for k in pos if k not in (a, b))

    edges: list[tuple[str, str, str, str | None, str | None]] = []
    for (a, b), st in links.items():
        if a not in pos or b not in pos:
            continue
        note, near = None, None
        if st.state == "blocked":
            note, near = (f"BLK {st.blocked_port}" if st.blocked_port else "BLK"), st.blocked_at
        else:
            child = a if tree.parent.get(a) == b else b if tree.parent.get(b) == a else None
            if child and child in tree.root_ports:
                note, near = f"RP {tree.root_ports[child]}", child
        kind = st.state
        if st.vlans and st.state == "forwarding":  # carries only some of the tree's VLANs (pruned trunk)
            kind = "partial"
            if note is None:
                only = compress_vlans(st.vlans)
                note = f"VLAN{'s' if len(st.vlans) > 1 else ''} {only if len(only) <= 18 else only[:17] + '…'} only"
        edges.append((a, b, kind, note, near))
    if chain_top and chain_top in pos and root in pos and not any(root in p for p in links):
        rp = tree.root_ports.get(chain_top)
        edges.append((root, chain_top, "undocumented", "path not documented" + (f" · RP {rp}" if rp else ""), None))

    # spread the links leaving a box edge so parallel links do not draw on top of each other
    ends: dict[tuple[str, str], list[tuple[float, int]]] = defaultdict(list)
    def straight(a: str, b: str, note: str | None) -> bool:
        return adjacent(a, b) and note is None

    for i, (a, b, _kind, note, _near) in enumerate(edges):
        if abs(pos[a][1] - pos[b][1]) < 1:
            if not straight(a, b, note):
                ends[(a, "top")].append((cx(b), i))
                ends[(b, "top")].append((cx(a), i))
        else:
            up, lo = (a, b) if pos[a][1] < pos[b][1] else (b, a)
            ends[(up, "bottom")].append((cx(lo), i))
            ends[(lo, "top")].append((cx(up), i))
    anchor: dict[tuple[str, int], float] = {}
    for (k, _side), lst in ends.items():
        lst.sort()
        span = min(pos[k][2] * 0.7, (len(lst) - 1) * 14)
        for j, (_x, i) in enumerate(lst):
            anchor[(k, i)] = cx(k) - span / 2 + (span * j / (len(lst) - 1) if len(lst) > 1 else 0)

    def draw(i: int, a: str, b: str, kind: str, note: str | None = None, near: str | None = None) -> None:
        ax, ay, aw = pos[a]
        bx, by, bw = pos[b]
        if abs(ay - by) < 1:  # same row
            left, right = (a, b) if ax < bx else (b, a)
            if straight(a, b, note):
                x1, x2, yy = pos[left][0] + pos[left][2], pos[right][0], ay + NODE_H / 2
                p0, p1, p2, p3 = (x1, yy), (x1, yy), (x2, yy), (x2, yy)
            else:
                sx, ex, cy = anchor[(left, i)], anchor[(right, i)], ay - 30
                p0, p1, p2, p3 = (sx, ay), (sx, cy), (ex, cy), (ex, ay)
            first = left
        else:
            up, lo = (a, b) if ay < by else (b, a)
            x1, y1, x2, y2 = anchor[(up, i)], pos[up][1] + NODE_H, anchor[(lo, i)], pos[lo][1]
            m = (y1 + y2) / 2
            p0, p1, p2, p3 = (x1, y1), (x1, m), (x2, m), (x2, y2)
            first = up
        style = {
            "forwarding": f'stroke="{c.gray_700}" stroke-width="2.6"',
            "partial": f'stroke="{c.gray_700}" stroke-width="1.6" stroke-dasharray="12 3"',
            "blocked": f'stroke="{c.error}" stroke-width="2.2" stroke-dasharray="7 5"',
            "absent": f'stroke="{c.gray_200}" stroke-width="1.4" stroke-dasharray="2 4"',
            "unknown": f'stroke="{c.gray_500}" stroke-width="1.4"',
            "undocumented": f'stroke="{c.gray_500}" stroke-width="1.6" stroke-dasharray="3 4"',
        }[kind]
        parts.append(f'<path d="M{p0[0]:.1f},{p0[1]:.1f} C{p1[0]:.1f},{p1[1]:.1f} {p2[0]:.1f},{p2[1]:.1f} '
                     f'{p3[0]:.1f},{p3[1]:.1f}" fill="none" {style}/>')
        if note:
            pref = 0.5 if near is None else (0.22 if near == first else 0.78)
            pending.append((note, kind, (p0, p1, p2, p3), pref))

    def point(ctrl: tuple, t: float) -> tuple[float, float]:
        (x0, y0), (x1, y1), (x2, y2), (x3, y3) = ctrl
        u = 1 - t
        return (u ** 3 * x0 + 3 * u * u * t * x1 + 3 * u * t * t * x2 + t ** 3 * x3,
                u ** 3 * y0 + 3 * u * u * t * y1 + 3 * u * t * t * y2 + t ** 3 * y3)

    def place(note: str, kind: str, ctrl: tuple, pref: float) -> str:
        tw = 8 + 5.4 * len(note)
        cands = [pref] + [pref + s * d for d in (0.08, 0.16, 0.24, 0.32, 0.4) for s in (-1, 1)]
        best = None
        for t, dy in [(t, dy) for dy in (0, -11, 11) for t in cands if 0.05 <= t <= 0.95]:
            lx, ly = point(ctrl, t)
            ly += dy
            box = (lx - tw / 2, ly - 9, lx + tw / 2, ly + 4)
            hits = sum(1 for r in taken if box[0] < r[2] and r[0] < box[2] and box[1] < r[3] and r[1] < box[3])
            if best is None or hits < best[0]:
                best = (hits, lx, ly, box)
            if hits == 0:
                break
        _h, lx, ly, box = best
        taken.append(box)
        col = c.error if kind == "blocked" else c.gray_700
        return (f'<rect x="{lx - tw / 2:.1f}" y="{ly - 9:.1f}" width="{tw:.1f}" height="13" rx="3" '
                f'fill="#ffffff" stroke="{col if kind == "blocked" else c.gray_200}" stroke-width="0.8"/>'
                f'<text x="{lx:.1f}" y="{ly + 1:.1f}" font-size="8.5" text-anchor="middle" '
                f'font-weight="{700 if kind == "blocked" else 400}" fill="{col}">{escape(note)}</text>')

    for i, e in enumerate(edges):
        draw(i, *e)
    out += parts + band_labels
    labels = [place(*p) for p in sorted(pending, key=lambda p: p[1] != "blocked")]

    # boxes; the bridge priority is on every box, since it is what decides the election
    vlan = tree.vlans[0] if tree.vlans else 1

    def prio_text(devices: list) -> str:
        found = {bridge_priority(d, vlan) for d in devices}
        found.discard(None)
        values = {p for p, _rt in found}
        if len(values) != 1:
            return "prio varies" if values else ""
        return f"prio {values.pop()}"

    for k, (x, yy, w) in pos.items():
        is_root = k == root
        if k == ROOT:
            base = tree.base_priority
            name, stripe, ghost = "Root bridge", c.gray_200, True
            sub = tree.root_mac or "unknown"
            third = " · ".join(t for t in (f"prio {base}" if base is not None else "", "not documented") if t)
        elif k in groups:
            nodes = [topo.nodes[m] for m in groups[k]]
            name, ghost = compress_names([n.name for n in nodes]), False
            models = sorted({n.model for n in nodes if n.model})
            sub = " · ".join(t for t in (prio_text([n.device for n in nodes]), f"{len(nodes)} switches") if t)
            third = "same STP role" + (f" · {models[0]}" if len(models) == 1 else "")
            order = ("success", "info", "warning", "error")
            worst = max((device_status(n.device)[0] for n in nodes if n.device),
                        key=lambda st: order.index(st) if st in order else 0, default="success")
            stripe = status_col.get(worst, c.gray_500)
        else:
            node = topo.nodes[k]
            ghost = node.kind == "ghost" or node.device is None
            name = node.name
            mode = node.device.spanning_tree.mode if node.device and node.device.spanning_tree else None
            # STP facts first (they survive narrow boxes), identity on the last line
            sub = " · ".join(x2 for x2 in (prio_text([node.device]), mode) if x2) or ("not documented" if ghost else "")
            third = " · ".join(t for t in (node.model, node.mgmt_ip) if t)
            stripe = status_col.get(device_status(node.device)[0], c.gray_500) if node.device else c.gray_200
        border = c.primary if is_root else (c.gray_500 if ghost else c.gray_200)
        dash = ' stroke-dasharray="4 3"' if ghost else ""
        out.append(f'<rect x="{x:.1f}" y="{yy:.1f}" width="{w:.1f}" height="{NODE_H}" rx="6" '
                   f'fill="{c.gray_50 if ghost else "#ffffff"}" stroke="{border}" '
                   f'stroke-width="{2.2 if is_root else 1}"{dash}/>'
                   f'<rect x="{x:.1f}" y="{yy:.1f}" width="{w:.1f}" height="4" rx="2" fill="{stripe}"/>')
        maxc = int(w / 6.6)
        nm = name if len(name) <= maxc else name[:maxc - 1] + "…"
        maxs = int(w / 5.3)
        sub = sub if len(sub) <= maxs else sub[:maxs - 1] + "…"
        third = third if len(third) <= maxs else third[:maxs - 1] + "…"
        out.append(f'<text x="{x + 8:.1f}" y="{yy + 19:.1f}" font-size="11.5" font-weight="700" '
                   f'fill="{c.primary}">{escape(nm)}</text>'
                   f'<text x="{x + 8:.1f}" y="{yy + 32:.1f}" font-size="9.5" fill="{c.gray_600}">{escape(sub)}</text>'
                   f'<text x="{x + 8:.1f}" y="{yy + 45:.1f}" font-size="9.5" fill="{c.gray_600}">{escape(third)}</text>')
        if is_root:
            badge = "ROOT" + (" · inferred" if tree.root_inferred else " · not imported" if tree.outside_root else "")
            bw = 10 + 5.6 * len(badge)
            out.append(f'<rect x="{x + w - bw - 5:.1f}" y="{yy - 8:.1f}" width="{bw:.1f}" height="15" rx="7" '
                       f'fill="{c.primary}"/><text x="{x + w - bw / 2 - 5:.1f}" y="{yy + 3:.1f}" font-size="8.5" '
                       f'font-weight="700" text-anchor="middle" fill="{c.on_primary}">{badge}</text>')
    out += labels

    # legend
    ly = height - MARGIN
    x = MARGIN
    used = {e[2] for e in edges} | {"forwarding", "blocked"}
    legend = [("forwarding", "Forwarding", 2.6, c.gray_700, ""),
              ("partial", "Forwarding some of these VLANs", 1.6, c.gray_700, "12 3"),
              ("blocked", "Blocked", 2.2, c.error, "7 5"),
              ("absent", "VLANs not on link", 1.4, c.gray_200, "2 4"), ("unknown", "No STP data", 1.4, c.gray_500, ""),
              ("undocumented", "Path not documented", 1.6, c.gray_500, "3 4")]
    legend = [item for item in legend if item[0] in used]
    out.append(f'<text x="{W - MARGIN}" y="{ly - 3}" font-size="9" text-anchor="end" fill="{c.gray_600}">'
               f'RP = root port · BLK = blocking port, labelled at its own end</text>')
    for _k, label, sw, col, da in legend:
        dash = f' stroke-dasharray="{da}"' if da else ""
        out.append(f'<line x1="{x}" y1="{ly - 6}" x2="{x + 24}" y2="{ly - 6}" stroke="{col}" stroke-width="{sw}"{dash}/>'
                   f'<text x="{x + 29}" y="{ly - 3}" font-size="9" fill="{c.gray_600}">{label}</text>')
        x += 40 + len(label) * 5.4
    out.append("</svg>")
    return "".join(out), height / W


def block_svg(b, theme: Theme) -> tuple[str, float]:
    """SVG for a doc.Diagram block: the spanning tree when it carries one, else the layered topology."""
    from sextant.render.diagram import topology_svg

    if b.stp is not None:
        return stp_svg(b.topology, b.keys, b.stp, theme, b.title)
    return topology_svg(b.topology, b.keys, theme, b.title)
