"""Summary document: fleet overview + one page per device, readable in 10-30 seconds."""

from __future__ import annotations

from sextant.builders.common import (
    ROLE_LABEL,
    device_kpis,
    device_status,
    finding_items,
    fleet_totals,
    glance_facts,
    identity_line,
    sorted_devices,
    vlan_subnets,
)
from sextant.builders.topology import position_facts, topology_page
from sextant.doc import (
    Callout,
    Cell,
    Cover,
    DeviceHeader,
    Document,
    Facts,
    FindingItem,
    Findings,
    Heading,
    Kpi,
    KpiRow,
    PageBreak,
    Paragraph,
    Table,
    slug,
)
from sextant.model import Snapshot
from sextant.topology import build_topology

TOP_N = 5

# One device page, in mm of the A4 PDF layout (measured from the rendered page): what the header, KPI tiles,
# findings and glance facts use, so the VLAN table gets the rest and the page never spills over.
_TOP, _BOTTOM = 92.0, 276.0
_LINE, _FINDING, _GLANCE_ROW, _VLAN_ROW = 4.8, 15.5, 7.6, 5.8
_HEADING, _CALLOUT, _TABLE_HEAD, _NOTE = 10.0, 12.7, 12.7, 6.4


def _lines(text: str, width: int) -> int:
    return max(1, -(-len(text) // width))


def _vlan_rows(d_line: str, items: list[FindingItem], more: bool, glance: list[tuple[str, str]],
               vlans: list[list[str]]) -> int:
    """How many VLAN rows still fit on the device page."""
    used = _TOP + (_lines(d_line, 80) - 1) * _LINE + _HEADING
    if not items:
        used += _HEADING
    for f in items:
        used += _FINDING + (_lines(f.title, 95) + _lines(f"Fix: {f.fix}", 100) - 2) * _LINE
    used += _CALLOUT if more else 0
    used += _HEADING
    for i in range(0, len(glance), 2):
        used += _GLANCE_ROW + (max(_lines(v, 28) for _, v in glance[i:i + 2]) - 1) * _LINE
    room = _BOTTOM - used - _TABLE_HEAD
    n = 0
    for row in vlans:
        h = _VLAN_ROW + (max(_lines(row[1], 40), _lines(row[2], 48)) - 1) * _LINE
        if room < h + (_NOTE if n + 1 < len(vlans) else 0):
            break
        room -= h
        n += 1
    return n


def build_summary(snap: Snapshot) -> Document:
    info = snap.info
    date = snap.created_at.strftime("%Y-%m-%d")
    doc = Document(title="Infrastructure Summary", kind="summary",
                   header_text=f"{info.customer} · Infrastructure Summary · {date}", footer_text=info.classification)
    doc.add(Cover(title="Infrastructure Summary", subtitle=info.project, customer=info.customer, site=info.site,
                  version=info.version, date=date, classification=info.classification))

    t = fleet_totals(snap)
    high = t["critical"] + t["high"]
    doc.add(Heading("Fleet overview", 1, "fleet", toc=False))
    doc.add(KpiRow([
        Kpi("Devices", str(t["devices"]), f"{len(snap.errors)} not collected" if snap.errors else "all collected",
            "warning" if snap.errors else None),
        Kpi("High / critical", str(high), "findings", "error" if high else "success"),
        Kpi("Medium", str(t["medium"]), "findings", "warning" if t["medium"] else "success"),
        Kpi("Virtual machines", str(t["vms"])),
        Kpi("VLANs", str(t["vlans"])),
    ]))

    fleet_items: list[FindingItem] = []
    for d in sorted_devices(snap):
        fleet_items += finding_items(d.findings, device=d.hostname)
    sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    fleet_items.sort(key=lambda f: -sev_rank[f.severity])
    doc.add(Findings(fleet_items[:TOP_N], title="Needs attention", compact=True,
                     empty_text="Nothing needs attention."))

    rows = []
    for d in sorted_devices(snap):
        status, label = device_status(d)
        top = d.findings[0].title if d.findings else "–"
        rows.append([d.hostname, ROLE_LABEL[d.role], d.mgmt_ip or "–", Cell(label, status), top])
    doc.add(Table(["Device", "Role", "Mgmt IP", "Status", "Top issue"], rows, title="Devices",
                  widths=[2, 1.3, 1.4, 1.4, 4.5], compact=True))
    if snap.errors:
        doc.add(Callout("; ".join(snap.errors), "warning", "Not collected"))
    topo = build_topology(snap)
    topology_page(doc, topo, snap)

    for d in sorted_devices(snap, topo):
        status, label = device_status(d)
        doc.add(PageBreak())
        doc.add(Heading(d.hostname, 1, f"sum-{slug(d.hostname)}", toc=False))
        doc.add(DeviceHeader(name=d.hostname, line=identity_line(d), role=ROLE_LABEL[d.role], status=status,
                             status_label=label))
        doc.add(KpiRow(device_kpis(d)))
        items = finding_items(d.findings[:TOP_N])
        doc.add(Findings(items, title="Needs attention", compact=True, empty_text="Nothing needs attention."))
        if len(d.findings) > TOP_N:
            doc.add(Callout(f"{len(d.findings) - TOP_N} more finding(s) in the As-Built document.", "neutral"))
        pos = dict(position_facts(topo, d.hostname))
        glance = glance_facts(d)
        if pos:
            glance = [("Layer", pos["Layer"].split(" (")[0]), ("Uplinks to", pos["Uplinks to"])] + glance
        doc.add(Facts(glance, title="At a glance", columns=2))
        vl = vlan_subnets(d)
        if vl:
            limit = _vlan_rows(identity_line(d), items, len(d.findings) > TOP_N, glance, vl)
            if limit:
                doc.add(Table(["VLAN", "Name", "Subnet / gateway"], vl[:limit], numeric={0}, widths=[0.8, 2.5, 3],
                              note=f"+{len(vl) - limit} more in the As-Built" if len(vl) > limit else None,
                              compact=True))
            else:
                doc.add(Paragraph(f"{len(vl)} VLANs: see the As-Built.", "muted"))
        elif d.virtualization and d.virtualization.datastores:
            rows = []
            for ds in sorted(d.virtualization.datastores, key=lambda x: -(x.used_pct or 0))[:6]:
                pct = ds.used_pct
                rows.append([ds.name, ds.kind or "–", f"{ds.capacity_gb or 0:.0f} GB",
                             Cell(f"{pct:.0f}%" if pct is not None else "–",
                                  "error" if (pct or 0) >= 90 else "warning" if (pct or 0) >= 80 else "success")])
            doc.add(Table(["Datastore", "Type", "Capacity", "Used"], rows, numeric={2}, compact=True))
    return doc
