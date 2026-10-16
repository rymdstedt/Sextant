"""Layered topology diagram as SVG (embedded in PDF/HTML; converted to PNG for Word).

One horizontal band per layer (edge, core, distribution, access, compute). Within a band:
  * nodes that share the same set of upstream devices (e.g. the 7 access switches of a
    building, all dual-homed to the same distribution pair) form a framed cluster with a grid
    of boxes and ONE link per upstream device, labelled with the number of links;
  * items are placed under the devices they connect to (barycenter x), then spread so they
    do not overlap; a band that is still too wide becomes a grid.
Per-port detail lives in the link tables; the diagram shows structure. Colours/font: theme.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from xml.sax.saxutils import escape

from sextant.builders.common import device_status
from sextant.drivers._util import short_ifname
from sextant.model import PortMode
from sextant.theme import Theme
from sextant.topology import LAYER_LABEL, LAYERS, Link, Topology

W = 1000  # viewBox width; scaled to the page
MARGIN = 16
GAP = 12  # between boxes
ITEM_GAP = 22  # between items (clusters / single boxes) in a band
NODE_H = 54
PAD = 10  # cluster padding
BAND_LABEL = 22
BAND_GAP = 56  # vertical room for links between bands
MIN_CLUSTER = 3


@dataclass
class Item:
    keys: list[str]
    cluster: bool = False
    cols: int = 1
    box_w: float = 150
    x: float = 0
    y: float = 0
    want: float | None = None  # desired centre x

    @property
    def rows(self) -> int:
        return -(-len(self.keys) // self.cols)

    @property
    def width(self) -> float:
        inner = self.cols * self.box_w + (self.cols - 1) * GAP
        return inner + (2 * PAD if self.cluster else 0)

    @property
    def height(self) -> float:
        inner = self.rows * NODE_H + (self.rows - 1) * GAP
        return inner + (2 * PAD + 14 if self.cluster else 0)

    def box_xy(self, i: int) -> tuple[float, float]:
        r, c = divmod(i, self.cols)
        ox = self.x + (PAD if self.cluster else 0)
        oy = self.y + (PAD + 14 if self.cluster else 0)
        return ox + c * (self.box_w + GAP), oy + r * (NODE_H + GAP)


def _total(items: list[Item]) -> float:
    return sum(it.width for it in items) + ITEM_GAP * (len(items) - 1)


def _status_colors(theme: Theme) -> dict[str, str]:
    c = theme.colors
    return {"error": c.error, "warning": c.warning_border, "success": c.success, "info": c.info,
            "neutral": c.gray_500}


def _active(topo: Topology, ln: Link) -> bool:
    for side in ("a", "b"):
        d = topo.nodes[getattr(ln, side)].device
        if not d:
            continue
        names = {short_ifname((pa if side == "a" else pb) or "").lower() for pa, pb in ln.ports}
        ifs = [i for i in d.interfaces if short_ifname(i.name).lower() in names]
        if ifs and not any(i.enabled for i in ifs):
            return False
    return True


def _routed(topo: Topology, ln: Link) -> bool:
    d = topo.nodes[ln.a].device
    if not d:
        return False
    names = {short_ifname(pa).lower() for pa, _ in ln.ports if pa}
    modes = {i.mode for i in d.interfaces if short_ifname(i.name).lower() in names}
    return modes == {PortMode.routed}


def _layout(topo: Topology, keys: list[str], y0: float) -> tuple[list[tuple[str, list[Item], float, float]], float]:
    by_layer = topo.by_layer(keys)
    layers = [lay for lay in LAYERS if lay in by_layer]
    usable = W - 2 * MARGIN
    rank = {n.key: LAYERS.index(lay) for lay, ns in by_layer.items() for n in ns}

    def is_leaf(k: str) -> bool:  # nothing below it: safe to fold into a cluster
        return not any(rank.get(n, -1) > rank[k] for n in topo.neighbors(k))
    centers: dict[str, float] = {}  # node key -> x centre once placed
    bands = []
    y = y0
    for lay in layers:
        row = [n.key for n in by_layer[lay]]
        placed_above = set(centers)

        def ups(k: str, placed: set[str] = placed_above) -> frozenset[str]:
            return frozenset(topo.neighbors(k) & placed)

        groups: dict[frozenset[str], list[str]] = defaultdict(list)
        for k in row:
            groups[ups(k)].append(k)
        items: list[Item] = []
        for up, members in groups.items():
            members.sort(key=lambda k: topo.nodes[k].name.lower())
            leaves = [k for k in members if is_leaf(k)]
            if up and len(leaves) >= MIN_CLUSTER:
                items.append(Item(leaves, cluster=True, cols=len(leaves)))
                items += [Item([k]) for k in members if k not in leaves]
            else:
                items += [Item([k]) for k in members]
        # box width, then shrink clusters (fewer columns) until the band fits
        n_boxes = len(row)
        box_w = 150.0 if n_boxes * (150 + GAP) <= usable else 118.0
        for it in items:
            it.box_w = box_w

        while _total(items) > usable and any(it.cluster and it.cols > 1 for it in items):
            widest = max((it for it in items if it.cluster and it.cols > 1), key=lambda it: it.width)
            widest.cols -= 1
        if _total(items) > usable:  # many unrelated boxes: one plain grid
            cols = max(1, int((usable + GAP) // (box_w + GAP)))
            items = [Item(row, cluster=False, cols=cols, box_w=box_w)]
        # desired x: under the upstream devices
        for it in items:
            xs = [centers[u] for k in it.keys for u in ups(k)]
            it.want = sum(xs) / len(xs) if xs else None
        if all(it.want is None for it in items):  # top band: pack centred
            items.sort(key=lambda it: topo.nodes[it.keys[0]].name.lower())
            x = MARGIN + max(0.0, (usable - _total(items)) / 2)
            for it in items:
                it.want = x + it.width / 2
                x += it.width + ITEM_GAP
        else:
            fallback = sum(it.want for it in items if it.want is not None) / sum(1 for it in items if it.want)
            for it in items:
                if it.want is None:
                    it.want = fallback
            items.sort(key=lambda it: (it.want, topo.nodes[it.keys[0]].name.lower()))
        # sweep: no overlaps, then pull back inside the margins
        x = MARGIN
        for it in items:
            it.x = max(it.want - it.width / 2, x)  # type: ignore[operator]
            x = it.x + it.width + ITEM_GAP
        overflow = items[-1].x + items[-1].width - (W - MARGIN)
        if overflow > 0:
            limit = W - MARGIN
            for it in reversed(items):
                it.x = min(it.x, limit - it.width)
                limit = it.x - ITEM_GAP
            shift = MARGIN - items[0].x
            if shift > 0:
                for it in items:
                    it.x += shift
        top = y
        y += BAND_LABEL
        for it in items:
            it.y = y
            for i, k in enumerate(it.keys):
                bx, _ = it.box_xy(i)
                centers[k] = bx + it.box_w / 2
        y += max(it.height for it in items)
        bands.append((lay, items, top, y))
        y += BAND_GAP
    return bands, y - BAND_GAP


def topology_svg(topo: Topology, keys: list[str], theme: Theme, title: str | None = None) -> tuple[str, float]:
    """Return (svg markup, aspect ratio height/width)."""
    c = theme.colors
    status_col = _status_colors(theme)
    bands, bottom = _layout(topo, keys, MARGIN + (28 if title else 0))
    height = bottom + 44

    box_of: dict[str, tuple[float, float, float]] = {}  # node -> x, y, w
    owner: dict[str, Item] = {}
    for _lay, items, _t, _b in bands:
        for it in items:
            for i, k in enumerate(it.keys):
                bx, by = it.box_xy(i)
                box_of[k] = (bx, by, it.box_w)
                owner[k] = it

    font = escape(theme.fonts.stack, {'"': ""})
    out = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {height:.0f}" width="{W}" '
           f'height="{height:.0f}" font-family="{font}" role="img" aria-label="{escape(title or "Topology")}">',
           f'<rect width="{W}" height="{height:.0f}" fill="#ffffff"/>']
    if title:
        out.append(f'<text x="{MARGIN}" y="{MARGIN + 15}" font-size="16" font-weight="700" fill="{c.primary}">'
                   f'{escape(title)}</text>')
    by_layer = topo.by_layer(keys)
    for i, (lay, _items, top, bot) in enumerate(bands):
        if i % 2 == 0:
            out.append(f'<rect x="0" y="{top - 10:.1f}" width="{W}" height="{bot - top + 22:.1f}" fill="{c.gray_50}"/>')
        out.append(f'<text x="{MARGIN}" y="{top + 8:.1f}" font-size="10" font-weight="700" letter-spacing="1.2" '
                   f'fill="{c.gray_600}">{escape(LAYER_LABEL[lay].upper())} · {len(by_layer[lay])}</text>')

    # ---- links, aggregated to cluster frames where a cluster member links outside its band
    def anchor_rect(k: str, other: str) -> tuple[str, float, float, float, float]:
        it = owner[k]
        if it.cluster and owner.get(other) is not it and abs(owner[other].y - it.y) > 1:
            return f"c{id(it)}", it.x, it.y, it.width, it.height
        x, y, w = box_of[k]
        return k, x, y, w, NODE_H

    edges: dict[tuple[str, str], dict] = {}
    for (a, b), ln in topo.links.items():
        if a not in box_of or b not in box_of:
            continue
        ea, eb = anchor_rect(a, b), anchor_rect(b, a)
        if ea[0] == eb[0]:
            continue  # inside one cluster
        key2 = tuple(sorted((ea[0], eb[0])))
        e = edges.setdefault(key2, {"ends": {ea[0]: ea, eb[0]: eb}, "links": 0, "active": 0, "lag": False,
                                    "routed": True, "members": 0})
        e["links"] += len(ln.ports) or 1
        e["members"] += 1
        e["active"] += 1 if _active(topo, ln) else 0
        e["lag"] |= len(ln.ports) > 1 or bool(ln.lag_a or ln.lag_b)
        e["routed"] &= _routed(topo, ln)

    fan: dict[tuple[str, str], list[float]] = defaultdict(list)
    for e in edges.values():
        (ka, ra), (kb, rb) = e["ends"].items()
        if abs(ra[2] - rb[2]) < 1:
            continue
        upper, lower = (ra, rb) if ra[2] < rb[2] else (rb, ra)
        fan[(upper[0], "down")].append(lower[1] + lower[3] / 2)
        fan[(lower[0], "up")].append(upper[1] + upper[3] / 2)

    def attach(r: tuple, direction: str, other_x: float) -> float:
        xs = sorted(fan[(r[0], direction)])
        i = xs.index(other_x) if other_x in xs else 0
        return r[1] + r[3] * (i + 1) / (len(xs) + 1)

    # band pairs whose links are all routed get one "Routed (L3)" note instead of a label per link
    band_of_y = {round(it.y): i for i, (_l, items, _t, _b) in enumerate(bands) for it in items}
    gap_routed: dict[tuple[int, int], list[bool]] = defaultdict(list)
    for e in edges.values():
        (_ka, ra), (_kb, rb) = e["ends"].items()
        ia, ib = band_of_y.get(round(ra[2])), band_of_y.get(round(rb[2]))
        if ia is not None and ib is not None and ia != ib:
            gap_routed[(min(ia, ib), max(ia, ib))].append(e["routed"])
    all_routed = {g for g, flags in gap_routed.items() if all(flags) and g[1] == g[0] + 1}

    parts, labels = [], []
    for g in sorted(all_routed):
        gy = (bands[g[0]][3] + bands[g[1]][2]) / 2 + 4
        labels.append(f'<text x="{MARGIN}" y="{gy:.1f}" font-size="9" font-style="italic" fill="{c.gray_600}">'
                      f'Routed (L3)</text>')
    for e in edges.values():
        (ka, ra), (kb, rb) = e["ends"].items()
        active = e["active"] > 0
        stroke = c.gray_500 if active else c.gray_200
        dash = "" if active else ' stroke-dasharray="5 4"'
        width = 3.2 if (e["lag"] or e["links"] > 1) else 1.6
        if abs(ra[2] - rb[2]) < 1:  # same band: peer link
            left, right = (ra, rb) if ra[1] < rb[1] else (rb, ra)
            yy = left[2] + NODE_H / 2
            if right[1] - (left[1] + left[3]) <= ITEM_GAP + GAP + 1:
                parts.append(f'<line x1="{left[1] + left[3]:.1f}" y1="{yy:.1f}" x2="{right[1]:.1f}" y2="{yy:.1f}" '
                             f'stroke="{stroke}" stroke-width="{width}"{dash}/>')
            else:
                x1, x2 = left[1] + left[3] / 2, right[1] + right[3] / 2
                parts.append(f'<path d="M{x1:.1f},{left[2]:.1f} Q{(x1 + x2) / 2:.1f},{left[2] - 30:.1f} '
                             f'{x2:.1f},{right[2]:.1f}" fill="none" stroke="{stroke}" stroke-width="{width}"{dash}/>')
            continue
        upper, lower = (ra, rb) if ra[2] < rb[2] else (rb, ra)
        x1 = attach(upper, "down", lower[1] + lower[3] / 2)
        x2 = attach(lower, "up", upper[1] + upper[3] / 2)
        y1, y2 = upper[2] + upper[4], lower[2]
        my = y1 + (y2 - y1) * 0.5
        skips = y2 - y1 > BAND_GAP + BAND_LABEL + 40  # passes another band: draw lighter
        opacity = ' stroke-opacity="0.45"' if skips else ""
        parts.append(f'<path d="M{x1:.1f},{y1:.1f} C{x1:.1f},{my:.1f} {x2:.1f},{my:.1f} {x2:.1f},{y2:.1f}" '
                     f'fill="none" stroke="{stroke}" stroke-width="{width}"{dash}{opacity}/>')
        ia, ib = band_of_y.get(round(upper[2])), band_of_y.get(round(lower[2]))
        per_link_l3 = e["routed"] and (ia, ib) not in all_routed
        text = " ".join(t for t in (f"{e['links']}×" if e["links"] > 1 else "", "L3" if per_link_l3 else "") if t)
        if text:
            tx, ty = (x1 + x2) / 2, my + 3
            tw = 7 + 5.6 * len(text)
            labels.append(f'<rect x="{tx - tw / 2:.1f}" y="{ty - 9:.1f}" width="{tw:.1f}" height="12" rx="3" '
                          f'fill="#ffffff" stroke="{c.gray_200}" stroke-width="0.6"/><text x="{tx:.1f}" y="{ty:.1f}" '
                          f'font-size="8.5" text-anchor="middle" fill="{c.gray_700}">{escape(text)}</text>')

    # ---- cluster frames
    frames = []
    for _lay, items, _t, _b in bands:
        for it in items:
            if it.cluster:
                ups = sorted({u for k in it.keys for u in topo.neighbors(k)
                              if u in owner and owner[u].y < it.y - 1})
                cap = f"Uplinks: {', '.join(topo.nodes[u].name for u in ups)}" if ups else ""
                frames.append(f'<rect x="{it.x:.1f}" y="{it.y:.1f}" width="{it.width:.1f}" height="{it.height:.1f}" '
                              f'rx="10" fill="#ffffff" fill-opacity="0.6" stroke="{c.gray_200}" stroke-width="1.2"/>'
                              f'<text x="{it.x + PAD:.1f}" y="{it.y + 15:.1f}" font-size="9" fill="{c.gray_600}">'
                              f'{escape(cap)}</text>')
    out += frames + parts + labels

    # ---- node boxes
    for k, (bx, by, bw) in box_of.items():
        node = topo.nodes[k]
        ghost = node.kind == "ghost"
        if node.device:
            st, _ = device_status(node.device)
            stripe = status_col.get(st, c.gray_500)
        else:
            stripe = c.gray_200 if ghost else c.gray_500
        fill = c.gray_50 if ghost else "#ffffff"
        dash = ' stroke-dasharray="4 3"' if ghost else ""
        out.append(f'<rect x="{bx:.1f}" y="{by:.1f}" width="{bw:.1f}" height="{NODE_H}" rx="6" fill="{fill}" '
                   f'stroke="{c.gray_500 if ghost else c.gray_200}" stroke-width="1"{dash}/>'
                   f'<rect x="{bx:.1f}" y="{by:.1f}" width="{bw:.1f}" height="4" rx="2" fill="{stripe}"/>')
        maxc = int(bw / 6.6)
        name = node.name if len(node.name) <= maxc else node.name[:maxc - 1] + "…"
        sub = node.model or ("not documented" if ghost else ("host of " + node.parent if node.parent else node.kind))
        maxs = int(bw / 5.3)
        sub = sub if len(sub) <= maxs else sub[:maxs - 1] + "…"
        tx = bx + 8
        out.append(f'<text x="{tx:.1f}" y="{by + 19:.1f}" font-size="11.5" font-weight="700" '
                   f'fill="{c.primary if node.device else c.gray_700}">{escape(name)}</text>'
                   f'<text x="{tx:.1f}" y="{by + 32:.1f}" font-size="9.5" fill="{c.gray_600}">{escape(sub)}</text>')
        third = node.mgmt_ip or ("not documented" if ghost and node.model else "")
        if third:
            out.append(f'<text x="{tx:.1f}" y="{by + 45:.1f}" font-size="9.5" fill="{c.gray_600}">{escape(third)}</text>')
        if node.endpoints:
            ep = " ".join(f"{v} {k2 if k2 != 'other' else 'dev'}" for k2, v in node.endpoints.most_common(2))
            ew = 6 + 5.2 * len(ep)
            out.append(f'<rect x="{bx + bw - ew - 5:.1f}" y="{by + 37:.1f}" width="{ew:.1f}" height="12" rx="6" '
                       f'fill="{c.gray_100}"/><text x="{bx + bw - ew / 2 - 5:.1f}" y="{by + 46:.1f}" font-size="8" '
                       f'text-anchor="middle" fill="{c.gray_700}">{escape(ep)}</text>')

    # ---- legend
    ly = height - MARGIN
    x = MARGIN
    for st, label in (("error", "Action needed"), ("warning", "Review"), ("info", "Minor"), ("success", "OK")):
        out.append(f'<rect x="{x}" y="{ly - 8}" width="14" height="4" rx="2" fill="{status_col[st]}"/>'
                   f'<text x="{x + 19}" y="{ly - 3}" font-size="9" fill="{c.gray_600}">{label}</text>')
        x += 30 + len(label) * 5.4
    legend = [
        f'<rect x="{{x}}" y="{ly - 12}" width="20" height="11" rx="3" fill="{c.gray_50}" stroke="{c.gray_500}" '
        f'stroke-dasharray="3 2"/>', "Not documented", 115,
        f'<line x1="{{x}}" y1="{ly - 6}" x2="{{x2}}" y2="{ly - 6}" stroke="{c.gray_500}" stroke-width="3.2"/>',
        "Several links / LAG", 135,
        f'<line x1="{{x}}" y1="{ly - 6}" x2="{{x2}}" y2="{ly - 6}" stroke="{c.gray_200}" stroke-width="1.6" '
        f'stroke-dasharray="5 4"/>', "Shut down", 80,
    ]
    for i in range(0, len(legend), 3):
        shape, label, step = legend[i], legend[i + 1], legend[i + 2]
        out.append(shape.format(x=x, x2=x + 22) + f'<text x="{x + 27}" y="{ly - 3}" font-size="9" '
                   f'fill="{c.gray_600}">{label}</text>')
        x += step
    out.append("</svg>")
    return "".join(out), height / W


def svg_to_png(svg: str, width_px: int = 2400) -> bytes | None:
    """PNG for Word. Returns None when cairosvg/cairo is unavailable."""
    try:
        import cairosvg
    except (ImportError, OSError):
        return None
    return cairosvg.svg2png(bytestring=svg.encode(), output_width=width_px)
