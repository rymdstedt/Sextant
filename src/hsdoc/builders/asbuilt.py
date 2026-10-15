"""As-Built document: exhaustive per-device documentation."""

from __future__ import annotations

from hsdoc import __version__
from hsdoc.builders.common import (
    ROLE_LABEL,
    dash,
    device_status,
    finding_items,
    fleet_totals,
    identity_line,
    join,
    severity_cell,
    sorted_devices,
    yn,
)
from hsdoc.doc import (
    Callout,
    Cell,
    Code,
    Cover,
    Document,
    Facts,
    Findings,
    Heading,
    Kpi,
    KpiRow,
    PageBreak,
    Paragraph,
    Table,
    Toc,
    slug,
)
from hsdoc.model import Device, Section, Snapshot


def build_asbuilt(snap: Snapshot, include_raw: bool = False, number_headings: bool = True) -> Document:
    info = snap.info
    date = snap.created_at.strftime("%Y-%m-%d")
    doc = Document(title="As-Built Documentation", kind="asbuilt",
                   header_text=f"{info.customer} · As-Built Documentation", footer_text=info.classification)
    doc.add(Cover(title="As-Built Documentation", subtitle=info.project, customer=info.customer,
                  site=info.site, version=info.version, date=date, classification=info.classification))

    doc.add(Heading("Document control", 1, "document-control", toc=False))
    doc.add(Table(["Version", "Date", "Author", "Reviewer", "Change"],
                  [[info.version, date, dash(info.author), dash(info.reviewer),
                    "Generated from collected configuration"]], widths=[1, 1.3, 2, 2, 3.5]))
    doc.add(Facts([("Customer", info.customer), ("Project", info.project), ("Site", dash(info.site)),
                   ("Classification", info.classification), ("Devices documented", str(len(snap.devices))),
                   ("Data collected", date), ("Generator", f"Hybrid As-Built {__version__}")], title="Scope"))
    if info.notes:
        doc.add(Paragraph(info.notes))
    doc.add(Callout("This document is generated from configuration collected from the devices. Secrets "
                    "(passwords, keys, SNMP communities) are redacted. Verify changes made after the "
                    "collection date.", "info"))
    doc.add(PageBreak(), Toc())

    _overview(doc, snap)
    _topology(doc, snap)
    for d in sorted_devices(snap):
        _device(doc, d)
    _appendix_findings(doc, snap)
    if include_raw:
        doc.add(Heading("Appendix B: Redacted configurations", 1, "appendix-raw"))
        for d in sorted_devices(snap):
            if d.raw_config:
                doc.add(Heading(d.hostname, 2, f"raw-{slug(d.hostname)}"), Code(d.raw_config))
    if number_headings:
        _number(doc)
    return doc


def _number(doc: Document) -> None:
    """Number chapters 1, 1.1, 1.1.1 (TOC headings only; appendices keep their letters)."""
    counters = [0, 0, 0]
    in_appendix = False
    for b in doc.blocks:
        if not isinstance(b, Heading) or not b.toc or b.level > 3:
            continue
        if b.level == 1:
            in_appendix = b.text.startswith("Appendix")
        if in_appendix:
            continue
        counters[b.level - 1] += 1
        for i in range(b.level, 3):
            counters[i] = 0
        b.text = f"{'.'.join(str(c) for c in counters[:b.level])} {b.text}"


# --------------------------------------------------------------------------- overview


def _overview(doc: Document, snap: Snapshot) -> None:
    t = fleet_totals(snap)
    doc.add(Heading("Executive overview", 1, "overview"))
    doc.add(Paragraph(f"This document describes the configuration of {t['devices']} device(s)"
                      + (f" at {snap.info.site}" if snap.info.site else "")
                      + f" as collected on {snap.created_at:%Y-%m-%d}.", "ingress"))
    doc.add(KpiRow([
        Kpi("Devices", str(t["devices"])),
        Kpi("High/critical findings", str(t["critical"] + t["high"]),
            status="error" if t["critical"] + t["high"] else "success"),
        Kpi("Medium findings", str(t["medium"]), status="warning" if t["medium"] else "success"),
        Kpi("Virtual machines", str(t["vms"])),
        Kpi("VLANs", str(t["vlans"])),
    ]))
    rows = []
    for d in sorted_devices(snap):
        status, label = device_status(d)
        rows.append([d.hostname, ROLE_LABEL[d.role], join([d.vendor, d.model], " "),
                     join([d.os_name, d.os_version], " "), dash(d.mgmt_ip), dash(d.site),
                     Cell(f"{label} ({len(d.findings)})", status)])
    doc.add(Heading("Device inventory", 2, "inventory"))
    doc.add(Table(["Hostname", "Role", "Vendor / model", "Software", "Mgmt IP", "Site", "Status"], rows,
                  widths=[2.2, 1.4, 2.4, 2, 1.6, 1.2, 1.8]))
    if snap.errors:
        doc.add(Callout("Not collected: " + "; ".join(snap.errors), "warning", "Collection errors"))


def _topology(doc: Document, snap: Snapshot) -> None:
    rows = []
    seen = set()
    for d in sorted_devices(snap):
        for n in d.neighbors:
            key = tuple(sorted([(d.hostname.lower(), n.local_port), (n.remote_device.split(".")[0].lower(),
                                                                     n.remote_port or "")]))
            if key in seen:
                continue
            seen.add(key)
            rows.append([d.hostname, n.local_port, n.remote_device, dash(n.remote_port), dash(n.remote_platform),
                         dash(n.remote_ip), n.protocol.upper()])
    if not rows:
        return
    doc.add(Heading("Topology and cabling", 1, "topology"))
    doc.add(Paragraph("Links discovered with CDP/LLDP. Each physical link is listed once.", "muted"))
    doc.add(Table(["Device", "Port", "Neighbor", "Neighbor port", "Platform", "Neighbor IP", "Via"], rows,
                  widths=[2, 1.4, 2.4, 1.6, 2, 1.5, 0.8], compact=True))


# --------------------------------------------------------------------------- device chapters


def _device(doc: Document, d: Device) -> None:
    a = slug(d.hostname)
    status, label = device_status(d)
    doc.add(Heading(d.hostname, 1, f"dev-{a}"))
    doc.add(Paragraph(f"{ROLE_LABEL[d.role]} · {identity_line(d)}", "ingress"))

    hw = [("Hostname", d.hostname), ("Role", ROLE_LABEL[d.role]), ("Vendor", dash(d.vendor)),
          ("Model", dash(d.model)), ("Software", join([d.os_name, d.os_version], " ")), ("Serial", dash(d.serial)),
          ("Uptime", dash(d.uptime)), ("Management IP", dash(d.mgmt_ip)), ("Location", dash(d.location)),
          ("Contact", dash(d.contact)), ("Collected", f"{d.collected_at:%Y-%m-%d %H:%M} UTC via "
                                                     f"{dash(d.collection_method)} ({dash(d.source)})"),
          ("Status", f"{label}, {len(d.findings)} finding(s)")]
    doc.add(Heading("Identity and hardware", 2, f"{a}-identity"), Facts(hw, columns=2))
    if d.hardware:
        doc.add(Table(["Component", "Details"], [[f.key, f.value] for f in d.hardware], title="Hardware",
                      widths=[1, 3], compact=True))
    if d.licenses:
        doc.add(Facts([("Licenses", join(d.licenses, "; "))]))
    if d.collection_warnings:
        doc.add(Callout("; ".join(d.collection_warnings[:8]), "warning", "Collection warnings"))

    _management(doc, d, a)
    _interfaces(doc, d, a)
    _l2(doc, d, a)
    _routing(doc, d, a)
    _security(doc, d, a)
    if d.virtualization:
        _virtualization(doc, d, a)
    for s in d.sections:
        _section(doc, s, 2, a)
    doc.add(Heading("Findings", 2, f"{a}-findings"))
    doc.add(Findings(finding_items(d.findings), empty_text="No findings for this device."))


def _management(doc: Document, d: Device, a: str) -> None:
    m = d.management
    s = m.snmp
    aaa = m.aaa
    facts = [
        ("SSH", yn(m.ssh) + (f" (v{m.ssh_version})" if m.ssh_version else "")), ("Telnet", yn(m.telnet)),
        ("HTTP", yn(m.http)), ("HTTPS", yn(m.https)), ("VTY ACL", dash(m.vty_acl)),
        ("Allowed mgmt hosts", join(m.allowed_mgmt_hosts)), ("Mgmt VRF", dash(m.mgmt_vrf)),
        ("Console/exec timeout", f"{m.console_timeout_min} min" if m.console_timeout_min is not None else "–"),
        ("NTP servers", join(m.ntp_servers)), ("Time zone", dash(m.timezone)),
        ("DNS servers", join(m.dns_servers)), ("Domain", dash(m.domain)),
        ("Syslog servers", join(m.syslog_servers)), ("Password encryption", yn(m.password_encryption)),
        ("Banner", "Configured" if m.banner else "–"), ("Config backup", dash(m.backup_target)),
    ]
    doc.add(Heading("Management plane", 2, f"{a}-mgmt"), Facts(facts, columns=2))
    if s.enabled or s.communities or s.v3_users:
        doc.add(Facts([("SNMP versions", join(s.versions)), ("Communities", join(s.communities)),
                       ("SNMPv3 users", join(s.v3_users)), ("Trap hosts", join(s.trap_hosts)),
                       ("SNMP ACL", dash(s.acl)), ("Location", dash(s.location)), ("Contact", dash(s.contact))],
                      title="SNMP", columns=2))
    if aaa.radius_servers or aaa.tacacs_servers or aaa.ldap_servers or aaa.login_methods:
        doc.add(Facts([("TACACS+", join(aaa.tacacs_servers)), ("RADIUS", join(aaa.radius_servers)),
                       ("LDAP", join(aaa.ldap_servers)), ("Login methods", join(aaa.login_methods, "; ")),
                       ("Accounting", yn(aaa.accounting))], title="AAA", columns=2))
    if m.users:
        doc.add(Table(["User", "Privilege / profile", "Authentication"],
                      [[u.name, dash(u.privilege), dash(u.auth)] for u in m.users], title="Local accounts",
                      widths=[2, 2, 3], compact=True))


def _interfaces(doc: Document, d: Device, a: str) -> None:
    if not d.interfaces:
        return
    rows = []
    for i in d.interfaces:
        state = "admin down" if not i.enabled else ("up" if i.oper_up else "down" if i.oper_up is False else "enabled")
        st = Cell(state, "success" if state == "up" else "neutral" if state != "down" else "warning")
        if i.mode.value == "access":
            vlan = str(i.access_vlan or "1") + (f" +voice {i.voice_vlan}" if i.voice_vlan else "")
        elif i.mode.value == "trunk":
            vlan = f"{i.trunk_vlans or 'all'} (native {i.native_vlan or 1})"
        else:
            vlan = str(i.access_vlan) if i.access_vlan else "–"
        rows.append([i.name, dash(i.description), st, i.mode.value if i.mode.value != "unknown" else i.kind,
                     vlan, join(x.address for x in i.ipv4), dash(i.zone or i.vrf), dash(i.lag),
                     join([i.speed, i.duplex], "/")])
    doc.add(Heading("Interfaces", 2, f"{a}-interfaces"))
    doc.add(Table(["Interface", "Description", "State", "Mode", "VLAN(s)", "IPv4", "Zone/VRF", "LAG", "Speed"],
                  rows, widths=[1.6, 2.4, 1.1, 1, 1.8, 1.7, 1.1, 0.8, 1], compact=True))
    lags = [i for i in d.interfaces if i.kind == "lag"]
    if lags:
        doc.add(Table(["LAG", "Description", "Protocol", "Members", "Mode", "VLANs"],
                      [[i.name, dash(i.description), dash(i.lag_protocol), join(i.lag_members), i.mode.value,
                        dash(i.trunk_vlans or i.access_vlan)] for i in lags], title="Link aggregation",
                      widths=[1, 2, 1, 3, 1, 2], compact=True))


def _l2(doc: Document, d: Device, a: str) -> None:
    if d.vlans:
        doc.add(Heading("VLANs", 2, f"{a}-vlans"))
        doc.add(Table(["ID", "Name", "SVI / gateway", "DHCP relay", "Ports"],
                      [[str(v.id), dash(v.name), join(v.svi_ipv4), join(v.dhcp_helpers),
                        _short_list(v.ports)] for v in sorted(d.vlans, key=lambda x: x.id)],
                      numeric={0}, widths=[0.6, 2, 2, 1.8, 4], compact=True))
    st = d.spanning_tree
    if st:
        facts = [("Mode", dash(st.mode)), ("Priority", dash(st.priority)), ("Root bridge", yn(st.root_bridge)),
                 ("BPDU guard default", yn(st.bpdu_guard_default)), *st.details.items()]
        doc.add(Heading("Spanning tree", 2, f"{a}-stp"), Facts(facts, columns=2))
    if d.ha:
        doc.add(Heading("High availability", 2, f"{a}-ha"))
        doc.add(Facts([("Mode", d.ha.mode), ("Group", dash(d.ha.group)), ("Members", join(d.ha.members)),
                       ("State", dash(d.ha.state)), *d.ha.details.items()], columns=2))


def _short_list(values: list[str], limit: int = 14) -> str:
    if not values:
        return "–"
    extra = len(values) - limit
    return ", ".join(values[:limit]) + (f" (+{extra} more)" if extra > 0 else "")


def _routing(doc: Document, d: Device, a: str) -> None:
    if not (d.routes or d.routing_protocols or d.vrfs):
        return
    doc.add(Heading("Routing", 2, f"{a}-routing"))
    if d.vrfs:
        doc.add(Facts([("VRFs", join(d.vrfs))]))
    if d.routes:
        doc.add(Table(["Prefix", "Next hop", "Interface", "Protocol", "AD", "VRF", "Description"],
                      [[r.prefix, dash(r.next_hop), dash(r.interface), r.protocol, dash(r.distance), dash(r.vrf),
                        dash(r.description)] for r in d.routes[:300]],
                      note=f"{len(d.routes) - 300} more routes not shown" if len(d.routes) > 300 else None,
                      numeric={4}, widths=[1.8, 1.6, 1.6, 1, 0.6, 1, 2.4], compact=True))
    for p in d.routing_protocols:
        facts = [("Process / AS", dash(p.process_id or p.asn)), ("Router ID", dash(p.router_id)),
                 ("Networks", join(p.networks)), ("Neighbors", join(p.neighbors)), *p.details.items()]
        doc.add(Facts(facts, title=p.protocol.upper(), columns=2))


def _security(doc: Document, d: Device, a: str) -> None:
    if d.acls:
        doc.add(Heading("Access lists", 2, f"{a}-acls"))
        for acl in d.acls:
            doc.add(Table(["Seq", "Action", "Rule"],
                          [[dash(e.seq), Cell(e.action, "success" if e.action == "permit" else "error"), e.text]
                           for e in acl.entries],
                          title=f"{acl.name} ({acl.kind})" + (f", applied: {join(acl.applied_to)}"
                                                              if acl.applied_to else ""),
                          widths=[0.6, 0.9, 7], compact=True))
    if d.firewall_rules:
        doc.add(Heading("Firewall policy", 2, f"{a}-policy"))
        rows = []
        for r in d.firewall_rules:
            act = Cell(r.action, "success" if r.action == "allow" else "error")
            rows.append([r.id + (f" {r.name}" if r.name else "") + ("" if r.enabled else " (disabled)"),
                         join(r.src_zones) + " → " + join(r.dst_zones), join(r.src_addresses),
                         join(r.dst_addresses), join(r.services + r.applications), act,
                         yn(r.log), join(r.security_profiles)])
        doc.add(Table(["Rule", "Zones", "Source", "Destination", "Service / app", "Action", "Log", "Profiles"],
                      rows, widths=[2, 1.8, 1.8, 1.8, 1.7, 0.9, 0.6, 1.4], compact=True))
    if d.nat_rules:
        doc.add(Heading("NAT", 2, f"{a}-nat"))
        doc.add(Table(["ID", "Type", "Original", "Translated", "Interface", "Comment"],
                      [[n.id + ("" if n.enabled else " (disabled)"), n.kind, n.original, n.translated,
                        dash(n.interface), dash(n.comment)] for n in d.nat_rules],
                      widths=[0.8, 0.8, 2.6, 2.6, 1.2, 2], compact=True))
    if d.address_objects:
        doc.add(Heading("Address objects", 2, f"{a}-objects"))
        doc.add(Table(["Name", "Type", "Value", "Comment"],
                      [[o.name, o.kind, o.value, dash(o.comment)] for o in d.address_objects],
                      widths=[2, 0.8, 4, 2], compact=True))
    if d.vpn_tunnels:
        doc.add(Heading("VPN", 2, f"{a}-vpn"))
        doc.add(Table(["Name", "Type", "Peer", "Local / remote networks", "IKE", "Phase 1", "Phase 2", "Status"],
                      [[t.name, t.kind, dash(t.peer), join(t.local_subnets) + " ⇄ " + join(t.remote_subnets),
                        dash(t.ike_version), dash(t.phase1), dash(t.phase2), dash(t.status)]
                       for t in d.vpn_tunnels], widths=[1.4, 0.8, 1.4, 2.6, 0.5, 2, 2, 0.9], compact=True))
    for t in d.dhcp_scopes:
        doc.add(Table(t.columns, t.rows, title=t.title or "DHCP", note=t.note, compact=True))


def _virtualization(doc: Document, d: Device, a: str) -> None:
    v = d.virtualization
    assert v
    doc.add(Heading("Virtualization", 2, f"{a}-virt"))
    doc.add(Facts([("Platform", v.platform), ("Manager", dash(v.manager)), ("Clusters", str(len(v.clusters))),
                   ("Hosts", str(len(v.hosts))), ("VMs", str(len(v.vms))),
                   ("Datastores", str(len(v.datastores))), ("Licenses", join(v.licenses, "; "))], columns=2))
    if v.clusters:
        doc.add(Table(["Cluster", "Hosts", "HA", "DRS", "EVC", "Quorum"],
                      [[c.name, str(len(c.hosts)), yn(c.ha_enabled, "On", "Off"),
                        yn(c.drs_enabled, "On", "Off") + (f" ({c.drs_level})" if c.drs_level else ""),
                        dash(c.evc_mode), dash(c.quorum)] for c in v.clusters], title="Clusters",
                      numeric={1}, compact=True))
        for c in v.clusters:
            if c.details:
                doc.add(Facts(list(c.details.items()), title=f"{c.name} settings", columns=2))
    if v.hosts:
        rows = []
        for h in v.hosts:
            st = (h.state or "").lower()
            cell = Cell(dash(h.state), "success" if st in ("connected", "online", "up", "running")
                        else "warning" if "maint" in st else "error" if st else "neutral")
            rows.append([h.name, dash(h.product) + (f" ({h.build})" if h.build else ""), dash(h.vendor_model),
                         f"{h.cpu_sockets or '–'}×{h.cpu_cores or '–'} cores", _gb(h.memory_gb),
                         _pct(h.cpu_usage_pct), cell, dash(h.mgmt_ip)])
        doc.add(Heading("Hosts", 3, f"{a}-hosts"))
        doc.add(Table(["Host", "Version", "Hardware", "CPU", "RAM", "CPU %", "State", "Mgmt IP"], rows,
                      numeric={4, 5}, widths=[2, 2.2, 1.8, 1.2, 0.8, 0.7, 1.2, 1.3], compact=True))
        for h in v.hosts:
            facts = [("Serial", dash(h.serial)), ("CPU model", dash(h.cpu_model)), ("Cluster", dash(h.cluster)),
                     ("NTP", join(h.ntp_servers)), ("Uptime", f"{h.uptime_days:.0f} days" if h.uptime_days else "–"),
                     ("NICs", join(h.nics, "; ")), *((k, v2) for k, v2 in h.services.items())]
            doc.add(Facts(facts, title=h.name, columns=2))
    if v.datastores:
        rows = []
        for ds in v.datastores:
            pct = ds.used_pct
            cell = Cell(_pct(pct), "error" if (pct or 0) >= 90 else "warning" if (pct or 0) >= 80 else "success") \
                if pct is not None else "–"
            rows.append([ds.name, dash(ds.kind), _gb(ds.capacity_gb), _gb(ds.free_gb), cell, yn(ds.shared),
                         dash(ds.backing)])
        doc.add(Heading("Storage", 3, f"{a}-storage"))
        doc.add(Table(["Datastore", "Type", "Capacity", "Free", "Used", "Shared", "Backing"], rows,
                      numeric={2, 3}, widths=[2, 0.9, 1, 1, 1, 0.7, 3], compact=True))
    if v.networks:
        doc.add(Heading("Virtual networking", 3, f"{a}-vnet"))
        doc.add(Table(["Switch / bridge", "Type", "Host", "Uplinks", "MTU", "Teaming"],
                      [[n.name, dash(n.kind), dash(n.host), join(n.uplinks), dash(n.mtu), dash(n.teaming)]
                       for n in v.networks], numeric={4}, compact=True))
        pg_rows = [[n.name, pg.get("name", "–"), pg.get("vlan", "–"), pg.get("active", "–"), pg.get("standby", "–")]
                   for n in v.networks for pg in n.port_groups]
        if pg_rows:
            doc.add(Table(["Switch", "Port group", "VLAN", "Active uplinks", "Standby"], pg_rows,
                          title="Port groups", compact=True))
    if v.vms:
        rows = []
        for vm in sorted(v.vms, key=lambda x: x.name.lower()):
            on = (vm.power_state or "").lower() in ("on", "poweredon", "running")
            snaps = f"{len(vm.snapshots)} ({vm.oldest_snapshot_days} d)" if vm.snapshots else "–"
            rows.append([vm.name, Cell(dash(vm.power_state), "success" if on else "neutral"), dash(vm.guest_os),
                         dash(vm.vcpus), _gb(vm.memory_mb / 1024 if vm.memory_mb else None),
                         _gb(sum(vm.disks_gb)) if vm.disks_gb else "–", join(vm.ip_addresses[:2]),
                         dash(vm.host), dash(vm.tools_status), snaps])
        doc.add(Heading("Virtual machines", 3, f"{a}-vms"))
        doc.add(Table(["VM", "Power", "Guest OS", "vCPU", "RAM", "Disk", "IP", "Host", "Tools", "Snapshots"],
                      rows, numeric={3, 4, 5}, widths=[1.8, 0.8, 2, 0.5, 0.7, 0.8, 1.4, 1.4, 1.1, 0.9],
                      compact=True))


def _gb(value: float | None) -> str:
    if value is None:
        return "–"
    return f"{value / 1024:.1f} TB" if value >= 1024 else f"{value:.0f} GB"


def _pct(value: float | None) -> str:
    return "–" if value is None else f"{value:.0f}%"


def _section(doc: Document, s: Section, level: int, a: str) -> None:
    doc.add(Heading(s.title, min(level, 4), f"{a}-{slug(s.id)}", toc=level <= 2))
    if s.intro:
        doc.add(Paragraph(s.intro))
    if s.facts:
        doc.add(Facts([(f.key, f.value) for f in s.facts], columns=2 if len(s.facts) > 4 else 1))
    for t in s.tables:
        doc.add(Table(t.columns, t.rows, title=t.title, note=t.note, compact=True))
    if s.code:
        doc.add(Code(s.code))
    for sub in s.subsections:
        _section(doc, sub, level + 1, a)


def _appendix_findings(doc: Document, snap: Snapshot) -> None:
    doc.add(Heading("Appendix A: All findings", 1, "appendix-findings"))
    rows = []
    for d in sorted_devices(snap):
        for f in d.findings:
            rows.append((f.severity.rank, d.hostname, f))
    rows.sort(key=lambda r: (-r[0], r[1]))
    if not rows:
        doc.add(Paragraph("No findings."))
        return
    doc.add(Table(["Severity", "Device", "Finding", "Recommendation"],
                  [[severity_cell(f.severity.value), host, f.title, f.recommendation] for _, host, f in rows],
                  widths=[1, 1.8, 3.5, 4], compact=True))
