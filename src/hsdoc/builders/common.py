"""Shared helpers for the builders: device KPIs, status and short labels."""

from __future__ import annotations

from collections import Counter

from hsdoc.doc import SEVERITY_STATUS, Cell, FindingItem, Kpi, Status
from hsdoc.model import Device, DeviceRole, Finding, PortMode, Snapshot

ROLE_LABEL = {
    DeviceRole.switch: "Switch", DeviceRole.router: "Router", DeviceRole.firewall: "Firewall",
    DeviceRole.hypervisor: "Virtualization", DeviceRole.server: "Server", DeviceRole.storage: "Storage",
    DeviceRole.wireless: "Wireless", DeviceRole.other: "Other",
}
ROLE_ORDER = [DeviceRole.firewall, DeviceRole.router, DeviceRole.switch, DeviceRole.wireless,
              DeviceRole.hypervisor, DeviceRole.storage, DeviceRole.server, DeviceRole.other]


def sorted_devices(snap: Snapshot) -> list[Device]:
    return sorted(snap.devices, key=lambda d: (ROLE_ORDER.index(d.role), d.hostname.lower()))


def yn(value: bool | None, yes: str = "Yes", no: str = "No") -> str:
    return "–" if value is None else (yes if value else no)


def join(values, sep: str = ", ", empty: str = "–") -> str:
    vals = [str(v) for v in (values or []) if v not in (None, "")]
    return sep.join(vals) if vals else empty


def dash(value) -> str:
    return "–" if value in (None, "", []) else str(value)


def device_status(d: Device) -> tuple[Status, str]:
    if not d.findings:
        return "success", "OK"
    worst = max(d.findings, key=lambda f: f.severity.rank).severity.value
    status = SEVERITY_STATUS[worst]
    label = {"error": "Action needed", "warning": "Review", "info": "Minor", "neutral": "OK"}[status]
    return ("success" if status == "neutral" else status), label


def severity_counts(findings: list[Finding]) -> Counter:
    return Counter(f.severity.value for f in findings)


def finding_items(findings: list[Finding], device: str | None = None) -> list[FindingItem]:
    return [FindingItem(severity=f.severity.value, title=f.title, detail=f.detail, fix=f.recommendation,
                        device=device) for f in findings]


def severity_cell(sev: str) -> Cell:
    return Cell(sev.capitalize(), SEVERITY_STATUS.get(sev, "neutral"))


def identity_line(d: Device) -> str:
    hw = " ".join(filter(None, [d.vendor, d.model])) or None
    sw = " ".join(filter(None, [d.os_name, d.os_version])) or None
    if hw and sw and (sw.startswith(hw) or hw in sw):  # "VMware vCenter Server" + "VMware vCenter Server 8.0.3"
        hw = None
    parts = [hw, sw, d.mgmt_ip, d.site]
    return "  ·  ".join(p for p in parts if p)


def physical_ports(d: Device):
    return [i for i in d.interfaces if i.kind == "physical"]


def device_kpis(d: Device) -> list[Kpi]:
    """4–6 tiles, chosen by role."""
    kpis: list[Kpi] = []
    c = severity_counts(d.findings)
    crit = c["critical"] + c["high"]
    kpis.append(Kpi("Findings", str(len(d.findings)),
                    f"{crit} high/critical · {c['medium']} medium",
                    "error" if crit else ("warning" if c["medium"] else "success")))
    ports = physical_ports(d)
    if ports and d.role in (DeviceRole.switch, DeviceRole.router, DeviceRole.firewall, DeviceRole.server):
        up = sum(1 for i in ports if i.oper_up)
        known = any(i.oper_up is not None for i in ports)
        enabled = sum(1 for i in ports if i.enabled)
        kpis.append(Kpi("Ports up" if known else "Ports enabled",
                        f"{up}/{len(ports)}" if known else f"{enabled}/{len(ports)}"))
    if d.vlans:
        kpis.append(Kpi("VLANs", str(len(d.vlans))))
    if d.firewall_rules:
        disabled = sum(1 for r in d.firewall_rules if not r.enabled)
        kpis.append(Kpi("Policies", str(len(d.firewall_rules)), f"{disabled} disabled" if disabled else None))
    if d.vpn_tunnels:
        kpis.append(Kpi("VPN tunnels", str(len(d.vpn_tunnels))))
    lags = [i for i in d.interfaces if i.kind == "lag"]
    if lags and d.role == DeviceRole.switch:
        kpis.append(Kpi("LAGs", str(len(lags))))
    v = d.virtualization
    if v:
        on = sum(1 for vm in v.vms if (vm.power_state or "").lower() in ("on", "poweredon", "running"))
        kpis.append(Kpi("VMs", str(len(v.vms)), f"{on} running"))
        kpis.append(Kpi("Hosts", str(len(v.hosts)),
                        f"{sum(1 for h in v.hosts if 'maint' in (h.state or '').lower())} in maintenance"
                        if any('maint' in (h.state or '').lower() for h in v.hosts) else None))
        cap = sum(ds.capacity_gb or 0 for ds in v.datastores)
        free = sum(ds.free_gb or 0 for ds in v.datastores)
        if cap:
            pct = 100 * (cap - free) / cap
            worst = max((ds.used_pct or 0) for ds in v.datastores)
            kpis.append(Kpi("Storage used", f"{pct:.0f}%", f"{_tb(cap - free)} of {_tb(cap)} · max {worst:.0f}%",
                            "error" if worst >= 90 else "warning" if worst >= 80 else "success"))
    if d.ha:
        kpis.append(Kpi("HA", d.ha.mode, d.ha.state))
    if d.routes and len(kpis) < 6:
        kpis.append(Kpi("Routes", str(len(d.routes))))
    return kpis[:6]


def _tb(gb: float) -> str:
    return f"{gb / 1024:.1f} TB" if gb >= 1024 else f"{gb:.0f} GB"


def default_route(d: Device) -> str:
    gws = [r.next_hop or r.interface for r in d.routes if r.prefix in ("0.0.0.0/0", "0.0.0.0 0.0.0.0", "default")]
    return join(dict.fromkeys(filter(None, gws)))


def uplinks(d: Device) -> str:
    lags = [f"{i.name} ({len(i.lag_members)}× {i.lag_protocol or 'lag'})" for i in d.interfaces if i.kind == "lag"]
    if lags:
        return join(lags[:4])
    trunks = [i.name for i in d.interfaces if i.mode == PortMode.trunk and i.kind == "physical" and i.enabled]
    return join(trunks[:4])


def glance_facts(d: Device) -> list[tuple[str, str]]:
    m = d.management
    aaa = m.aaa.tacacs_servers and "TACACS+" or m.aaa.radius_servers and "RADIUS" or m.aaa.ldap_servers and "LDAP"
    items = [("Management IP", dash(d.mgmt_ip)), ("Default gateway", default_route(d))]
    if d.role in (DeviceRole.switch, DeviceRole.router):
        items.append(("Uplinks / LAGs", uplinks(d)))
    if d.ha:
        items.append(("HA", f"{d.ha.mode}: {d.ha.state or '–'}"))
    items += [
        ("NTP", f"Yes ({len(m.ntp_servers)})" if m.ntp_servers else "No"),
        ("Syslog", f"Yes ({len(m.syslog_servers)})" if m.syslog_servers else "No"),
        ("Central AAA", aaa or "No"),
        ("SNMP", join(m.snmp.versions, "/") if m.snmp.enabled or m.snmp.versions else "No"),
        ("OS", " ".join(filter(None, [d.os_name, d.os_version])) or "–"),
        ("Serial", dash(d.serial)),
    ]
    if d.virtualization:
        v = d.virtualization
        items.insert(1, ("Manager", dash(v.manager)))
        clusters = [f"{c.name} (HA {yn(c.ha_enabled, 'on', 'off')}"
                    + (f", DRS {yn(c.drs_enabled, 'on', 'off')})" if v.platform == "vmware" else ")")
                    for c in v.clusters]
        items.insert(2, ("Clusters", join(clusters)))
    if d.uptime:
        items.append(("Uptime", d.uptime))
    return items


def vlan_subnets(d: Device) -> list[list[str]]:
    rows = []
    for v in sorted(d.vlans, key=lambda x: x.id):
        rows.append([str(v.id), dash(v.name), join(v.svi_ipv4)])
    if not rows:  # firewalls: subinterfaces with vlan ids
        for i in d.interfaces:
            if i.access_vlan and i.ipv4 and i.kind in ("vlan", "virtual"):
                rows.append([str(i.access_vlan), dash(i.description or i.name), join(a.address for a in i.ipv4)])
    return rows


def fleet_totals(snap: Snapshot) -> dict[str, int]:
    vms = sum(len(d.virtualization.vms) for d in snap.devices if d.virtualization)
    vlan_ids = {v.id for d in snap.devices for v in d.vlans}
    rules = sum(len(d.firewall_rules) for d in snap.devices)
    findings = [f for d in snap.devices for f in d.findings]
    c = severity_counts(findings)
    return {"devices": len(snap.devices), "vms": vms, "vlans": len(vlan_ids), "rules": rules,
            "findings": len(findings), "critical": c["critical"], "high": c["high"], "medium": c["medium"],
            "low": c["low"], "info": c["info"]}
