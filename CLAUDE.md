# Sextant (`sextant`)

Named after the navigation instrument (fits the Ocean palette). The documents it
produces keep the industry-standard title "As-Built".

Generates infrastructure documentation from live devices (switches, routers,
firewalls, hypervisors, servers) or exported config files. Two outputs per run,
each as **Word (.docx), PDF and standalone HTML**:

1. **As-Built**: exhaustive documentation of how every system is configured.
2. **Summary**: a 1-page-per-device brief a sysadmin can read in 10–30 seconds.

Owner: Andreas Lindstedt, Hybrid Solutions AB. UI and docs language: English.

## Architecture

```
inventory.yaml ─► collectors (ssh/snmp/api/file) ─► RawCollection ─► parsers ─► model.Device
                                                                                    │
                                                         analysis (checks) ─► Device.findings
                                                                                    │
                           Snapshot (JSON, redacted) ◄──────────────────────────────┘
                                   │
                 builders (asbuilt.py, summary.py) ─► doc.Document (neutral blocks)
                                   │
                     render/html.py ─► PDF (WeasyPrint)      render/docx.py ─► .docx (python-docx)
```

- `src/sextant/model.py`: **the contract.** Vendor-neutral pydantic models. Drivers
  fill it, renderers and checks only read it. Vendor extras go in
  `Device.sections` (generic `Section` with facts/tables/code).
- `src/sextant/drivers/`: one module per platform, each a `Driver` subclass
  registered in `drivers/__init__.py`:
  - `collect(target, creds) -> RawCollection` (command outputs / API JSON / files)
  - `parse(raw) -> Device` (pure, offline, unit-tested against fixtures)
  - `from_file(path)` for config-file import (no device access needed).
- `src/sextant/redact.py`: strips secrets from raw config (passwords, secrets,
  keys, PSKs, communities except "public"/"private"). Runs before anything is
  saved. Never write secrets to the snapshot, documents or logs.
- `src/sextant/analysis/`: checks over the model producing `Finding`s
  (severity info→critical). These drive the Summary's "Attention" list.
  `analysis/fleet.py` adds cross-device checks over the topology.
- `src/sextant/topology.py`: site graph from CDP/LLDP, interface descriptions and
  routed /30s; layer inference (inventory `layer:` > role > hostname > graph
  centre). `render/diagram.py` draws it as SVG; `builders/topology.py` adds the
  topology chapter/page. `pipeline.import_many` handles folders/zips/session logs
  (captures for the same hostname are merged).
- `src/sextant/stp.py`: spanning trees per layer-2 domain (routed links split domains) and per
  group of VLANs with the same root and link states, from runtime `StpInstance`s parsed in
  `drivers/_stp.py`; config-only root prediction. `render/stp_diagram.py` draws a tree (root on
  top, blocked links dashed), `builders/topology.stp_chapter` adds it to the As-Built,
  `analysis/fleet.stp_checks` adds the STP findings. VLAN 1 is always its own tree.
- `src/sextant/rings.py`: ring protocols (MRP/REP/ERPS, `Device.rings`, parsed in `drivers/_ring.py`):
  ring links carry no STP (`LinkState("ring")`), ring switches that are only their own root are
  `Tree.ring` islands, not roots; `analysis/fleet.ring_checks` adds ring findings.
- `src/sextant/doc.py`: neutral document blocks (Heading, Paragraph, Facts,
  Table, KpiRow, Findings, Code, PageBreak, Toc). Both renderers consume it so
  Word and PDF always match.
- `src/sextant/builders/`: `asbuilt.py`, `summary.py` turn a `Snapshot` into a `Document`.
- `src/sextant/render/`: `html.py` (+ Jinja templates + CSS → WeasyPrint PDF),
  `docx.py` (python-docx with Hybrid Solutions styles).
- `src/sextant/cli.py`: Typer CLI `sextant`.
- `src/sextant/web/`: FastAPI + Jinja web UI.

## Drivers to build

| Driver id | Platform | Method | Key commands / endpoints |
| --- | --- | --- | --- |
| `cisco_ios` | IOS / IOS-XE (incl. Catalyst) | SSH (netmiko) | show running-config, version, inventory, interfaces status, ip int brief, vlan brief, cdp/lldp neighbors detail, ip route, spanning-tree (summary + full), etherchannel summary, switch detail |
| `cisco_nxos` | Nexus | SSH | as above + show vpc, show feature |
| `cisco_asa` | ASA | SSH | show run, show version, show failover, show nat, show access-list |
| `aruba_aoscx` | Aruba CX | SSH or REST v10.x | show running-config, show system, show lldp neighbor-info, show vsx status |
| `hp_procurve` | Aruba AOS-S / ProCurve | SSH | show running-config, show system, show interfaces brief, show lldp info remote-device, show trunks |
| `juniper_junos` | Junos (EX/SRX/MX) | SSH | show configuration \| display set, show version, show chassis hardware, show lldp neighbors |
| `fortigate` | FortiOS | SSH (`show full-configuration`) or REST API (`/api/v2/monitor/system/config/backup`, `/api/v2/cmdb/...`) | policies, addresses, VIPs, IPsec, HA, interfaces, zones, admins |
| `paloalto` | PAN-OS | XML API (`type=config&action=show`, `op` for system info) | rules, NAT, zones, interfaces, HA, objects |
| `pfsense` / `opnsense` | pfSense / OPNsense | file (config.xml) or SSH `cat /conf/config.xml` | interfaces, VLANs, rules, NAT, OpenVPN/IPsec/WireGuard, users |
| `vmware` | vCenter / ESXi | API (pyVmomi) | clusters (HA/DRS/EVC), hosts, VMs (snapshots, tools), datastores, vSwitch/dvSwitch/portgroups, licenses |
| `proxmox` | Proxmox VE | REST API (token) | nodes, cluster/quorum, VMs + LXC, storage, network bridges/bonds, backup jobs, HA |
| `hyperv` | Hyper-V / Failover Cluster | WinRM (PowerShell → JSON) | Get-VMHost, Get-VM, Get-VMSwitch, Get-ClusterSharedVolume, Get-Cluster |
| `linux` | Linux servers | SSH | hostnamectl, ip -j addr/route, lsblk -J, df, systemctl, ss -tlnp |
| `snmp` | Anything with SNMP | SNMP v2c/v3 (pysnmp) | SNMPv2-MIB system, IF-MIB, ENTITY-MIB, LLDP-MIB, IP-MIB |

Each driver ships with redacted sample fixtures in `examples/` and parser tests
in `tests/`. Parsers must be tolerant: unknown lines are ignored, never fatal.

## Analysis checks (initial set)

Telnet or HTTP management enabled; SNMP v1/v2c or community "public"/"private";
no NTP / no syslog / no AAA; local admin accounts without central auth; weak
password storage (type 7 / plain text); no VTY ACL; no login banner; STP
disabled or no BPDU guard on edge ports; admin-down ports still configured,
unused ports in access VLAN 1; native VLAN 1 on trunks; firewall rules
any→any allow, disabled rules, rules without logging, shadowed rules (best effort);
IPsec with weak crypto (DES/3DES/MD5/SHA1/DH<14); HA not in sync; VM snapshots
older than 7 days; VMware Tools not running; datastores > 80 % (medium) / 90 % (high);
host in maintenance/disconnected; cluster HA/DRS disabled; end-of-support OS versions (table).

## Documents

**As-Built** (PDF + Word): cover (Hybrid Solutions logo, customer, site, version,
date), document control table (version, author, reviewer, date), table of
contents, executive overview (device inventory table, totals), topology/cabling
table from CDP/LLDP, then one chapter per device: identity & hardware,
management plane (users, AAA, SNMP, NTP, DNS, syslog), interfaces (full table),
LAGs, VLANs, routing, STP, ACLs, firewall policies/NAT/objects/VPN, HA,
virtualization (clusters/hosts/VMs/datastores/networks), vendor sections,
findings. Appendices: all findings, redacted raw configs (optional flag).

**Summary** (PDF + Word): fleet overview page (KPI tiles: devices, findings by
severity, VMs, VLANs) then per device ONE page: identity line, 4–6 KPI tiles
(ports up/total, VLANs, rules, VMs, storage used), "Needs attention" (top 5
findings by severity, each one line + fix), "At a glance" (mgmt IP, default
route/gateway, uplinks/LAGs, VLAN→subnet table, HA state, NTP/syslog/AAA yes/no).
Scannable: no prose paragraphs longer than two lines.

## Design: themes (default: Hybrid Solutions Internal Apps)

All branding lives in `src/sextant/themes/<id>/theme.yaml` (+ logos, fonts in
`themes/_fonts`), loaded by `src/sextant/theme.py`. Renderers, CSS and the web UI
read colours by role (primary/accent/highlight/text, grays, status) and never
hard-code brand values; `tests/test_theme.py` enforces this. The values below are
the default `hybrid` theme.

Design system from the artifact "Hybrid Solutions Internal Apps"
(https://claude.ai/artifact/WiCv7t9nZENVKsJ4m2SjKK). Tokens copied to
`src/sextant/themes/hybrid/tokens.json`; logos in `src/sextant/themes/hybrid/`.

- Colours: `ocean` #1d2542 (main: headings, cover, table caption, top bar),
  `electric` #0099d4 (accents, focus ring; white text on it only 24px+),
  `poppy` #eb5e1d (accents only, e.g. active-nav underline, cover bands; never
  text fill), `merlot` #952f47 (supporting), `charcoal` #2c2d2d (body text).
  Greys gray-50 #f5f6f9 (table header / subtle surface), gray-100 #eceef3,
  gray-200 #dcdfe7 (dividers), gray-500 #6b7387 (control borders), gray-600
  #4e566a (muted text), gray-700 #363d50.
- Status: success #1e7a46 / #e6f4ec, warning #8f5e00 / #fdf3dc, error #b42318 /
  #fdecea, info #00709c / #e5f4fb. Always pair with an icon or text label,
  never colour alone. Map severities: critical/high → error, medium → warning,
  low → info, info → gray.
- Type: Open Sans. h1 32px Bold, h2 24px Bold, h3 18.67px Bold, h4 16px Bold,
  ingress 16px Semibold, body 13.33px (Light 300 in brand; use 400 in dense
  tables for legibility), footnote 10.67px. In Word: H1 24pt, H2 18pt, H3 14pt,
  H4 12pt, body 10pt, footnote 8pt (the manual's Word scale).
- Spacing 4px base (4, 8, 12, 16, 24, 32, 48); radius 4/8/12px.
- Gradients: `linear-gradient(180deg, #1d2542, #0099d4)` and
  `linear-gradient(180deg, #952f47, #eb5e1d)` for large brand surfaces (cover).
- Logo: colour logo on white, white logo on Ocean/gradients. Never modify,
  rotate or add effects; keep clear space.
- Web UI uses the components: TopBar (Ocean, white logo, poppy underline on
  current link), Button (primary Ocean), Table (gray-50 header, right-aligned
  numbers), Alert, Tabs, TextField, Select, Dialog.
- Note: the design system is scoped to internal apps. Customer-facing as-built
  docs may need the print rules from the brand manual (Futura PT / Tisa Pro);
  flagged to Andreas, not decided.

## Credentials and security

- Inventory references credentials by name; values come from env vars
  (`${VAR}`), a git-ignored `credentials.yaml`, or are entered per run in the
  web UI (kept in memory only, never persisted).
- Read-only accounts recommended; drivers only run show/get commands. No
  config changes, ever.
- Web UI requires login (`SEXTANT_ADMIN_USER` / `SEXTANT_ADMIN_PASSWORD`, or an
  OIDC reverse proxy). Snapshots are redacted before saving.

## Deployment

- `Dockerfile` (python:3.12-slim + pango for WeasyPrint), `docker-compose.yml`
  with a `/data` volume.
- Cloud-hosted UI cannot reach on-prem gear directly: run the container on-prem,
  or run `sextant collect` on-prem and upload the snapshot JSON to the UI.
- GitHub Actions: lint + tests, build and push image to GHCR.

## Dev

```bash
python3.12 -m venv .venv && .venv/bin/pip install -e ".[dev]"
.venv/bin/pytest
.venv/bin/sextant render examples/snapshot.json --out out/
.venv/bin/sextant web  # http://localhost:8080
```

macOS PDF rendering needs `brew install pango`.
