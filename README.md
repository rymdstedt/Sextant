# Sextant

*Know exactly where your infrastructure stands.*

Generates infrastructure documentation from switches, routers, firewalls, hypervisors and servers,
in Hybrid Solutions styling. Every run produces two documents, each as **PDF, Word and standalone HTML**:

| Document | For | Contents |
| --- | --- | --- |
| **As-Built** | Handover, audits, change planning | Cover, document control, contents, executive overview, CDP/LLDP cabling, one chapter per device (identity, management plane, interfaces, LAGs, VLANs, routing, STP, ACLs, firewall policy/NAT/objects/VPN, HA, virtualization), findings, appendices |
| **Summary** | The sysadmin's daily 10–30 second check | Fleet KPI tiles and top-5 "Needs attention", then **one page per device**: KPI tiles, top-5 findings with fixes, "At a glance" (mgmt IP, gateway, uplinks, HA, NTP/syslog/AAA, VLAN → subnet) |

The HTML version is a single self-contained file (fonts and logos embedded) with a section sidebar,
search, filterable tables and print styles: open it offline, mail it, or attach it to a ticket.
As-Built chapters are numbered (1, 1.1, 1.1.1) for easy reference in reviews.

Collection is **read-only**: drivers only send `show`/`get` commands or HTTP GET requests.
Secrets are redacted before anything is parsed, saved or rendered.

## Supported platforms

| Driver | Platform | Methods |
| --- | --- | --- |
| `cisco_ios` | Cisco IOS / IOS-XE (Catalyst) | SSH, file |
| `cisco_nxos` | Cisco Nexus | SSH, file |
| `cisco_asa` | Cisco ASA | SSH, file |
| `aruba_aoscx` | Aruba CX | SSH, file |
| `hp_procurve` | Aruba AOS-S / HPE ProCurve | SSH, file |
| `juniper_junos` | Juniper EX/SRX/MX (`display set`) | SSH, file |
| `fortigate` | Fortinet FortiGate | REST API, SSH, file |
| `paloalto` | Palo Alto PAN-OS | XML API, file |
| `pfsense`, `opnsense` | pfSense / OPNsense `config.xml` | file, SSH |
| `vmware` | vCenter / ESXi (pyVmomi) | API, JSON file |
| `proxmox` | Proxmox VE | REST API (token), JSON file |
| `hyperv` | Hyper-V / Failover Cluster | WinRM, JSON file from `examples/hyperv/collect-hyperv.ps1` |
| `linux` | Linux servers | SSH |
| `snmp` | Anything with SNMP (v2c/v3) | SNMP |

`sextant drivers` lists what is installed.

## Quick start

```bash
python3.12 -m venv .venv && .venv/bin/pip install -e ".[dev]"
# Linux: apt install libpango-1.0-0 libpangoft2-1.0-0   macOS: brew install pango

# Render the bundled example site (all four documents):
.venv/bin/sextant render examples/snapshot.json --out out/
```

### Import config files (no device access)

```bash
sextant import sto-core-sw01.txt --driver cisco_ios --customer "Example AB" --site Stockholm -o snap.json
sextant import config.xml --driver pfsense --append -o snap.json
sextant render snap.json -o out/
```

### Collect live from devices

Create an inventory (see [`examples/inventory.yaml`](examples/inventory.yaml)):

```yaml
info:
  customer: Example AB
  site: Stockholm
  author: Andreas Lindstedt
credentials:
  network-ro: { username: "${SEXTANT_NET_USER}", password: "${SEXTANT_NET_PASSWORD}" }
  fortigate-api: { api_token: "${SEXTANT_FGT_TOKEN}" }
targets:
  - { name: sto-core-sw01, host: 10.0.0.2, driver: cisco_ios, credentials: network-ro }
  - { name: sto-fw01, host: 10.0.0.1, driver: fortigate, method: api, credentials: fortigate-api }
  - { name: mlm-fw01, driver: pfsense, method: file, file: pfsense/config.xml }
```

Credential values come from environment variables (`${VAR}`) or a git-ignored `credentials.yaml`
next to the inventory ([example](examples/credentials.example.yaml)). Use read-only accounts.

```bash
sextant collect -i inventory.yaml -o snapshot.json --render out/
```

`snapshot.json` is redacted and self-contained: re-render it any time, merge several
(`sextant render a.json b.json`), or upload it to the web UI.

## Web UI

```bash
SEXTANT_ADMIN_PASSWORD=... SEXTANT_SECRET_KEY=$(openssl rand -hex 32) sextant web   # http://localhost:8080
```

Log in, then **New documentation** to upload config files or a snapshot (platform auto-detected), or
collect live with credentials typed into the form (kept in memory for that run only, never saved).
Each snapshot has tabs for devices, findings, an in-browser preview and document generation
(PDF + Word downloads).

| Variable | Purpose |
| --- | --- |
| `SEXTANT_ADMIN_USER` / `SEXTANT_ADMIN_PASSWORD` | Login. Without a password a one-time one is printed at start-up. |
| `SEXTANT_SECRET_KEY` | Signs the session cookie; set it so sessions survive restarts. |
| `SEXTANT_TRUSTED_USER_HEADER` | Behind an authenticating proxy (e.g. oauth2-proxy for Entra ID), the header that carries the user. Only set this when the app is reachable exclusively through that proxy. |
| `SEXTANT_HTTPS_ONLY=1` | Mark the session cookie Secure (when served over HTTPS). |
| `SEXTANT_DATA_DIR` | Where snapshots and documents are stored (`/data` in the container). |

### Docker

```bash
cp .env.example .env   # set SEXTANT_ADMIN_PASSWORD and SEXTANT_SECRET_KEY
docker compose up -d
docker compose run --rm sextant collect -i /data/inventory.yaml -o /data/snapshot.json
```

The image is built and pushed to `ghcr.io/rymdstedt/sextant` by GitHub Actions on every push to
`main` (after lint and tests pass).

> **Where to run it.** A cloud-hosted instance cannot reach devices on a customer's internal network.
> Either run the container on-prem (a management VM with access to the devices), or run
> `sextant collect` on-prem and upload the redacted `snapshot.json` to a hosted UI.

## Findings

Checks run automatically and feed the Summary's "Needs attention" list: Telnet/HTTP management,
SNMP v1/v2c and default communities, missing NTP/syslog/AAA, weak password storage (type 7/5/plain),
no VTY ACL or banner, STP disabled / no BPDU guard, native VLAN 1, ports in VLAN 1, leftover config on
shut ports, any→any and broad firewall rules, disabled/unlogged/shadowed rules, weak IPsec crypto
(DES/3DES/MD5/SHA1/DH < 14), HA out of sync, VM snapshots > 7 days, guest tools not running,
datastores ≥ 80/90 %, hosts in maintenance/disconnected, cluster HA/DRS off, end-of-support software
(table in `src/sextant/analysis/lifecycle.py`, review it regularly).

## Development

```bash
.venv/bin/pytest
.venv/bin/ruff check src tests
```

Architecture, driver contract and design rules: see [`CLAUDE.md`](CLAUDE.md). Adding a platform =
one module in `src/sextant/drivers/` (a `Driver` with `collect()` and a pure `parse()`), a redacted
fixture in `examples/<driver>/` and a parser test in `tests/drivers/`.

### Branding and themes

Nothing brand-specific is hard-coded: colours, fonts, logos, company and product name come from a
**theme** folder. `hybrid` (Hybrid Solutions, default) and `neutral` (unbranded) are built in.

```bash
sextant themes                                 # list themes
sextant theme-init acme --dir themes           # copy the default theme to themes/acme
#   edit themes/acme/theme.yaml (company, colours, fonts) and replace logo-color.png / logo-white.png
sextant render snapshot.json --theme themes/acme
```

| Where | How to pick the theme |
| --- | --- |
| CLI | `--theme <name or folder>` |
| Per customer snapshot | Web UI → Generate documents → *Branding theme* (stored in the snapshot) |
| Server default | `SEXTANT_THEME=acme`; extra theme folders in `SEXTANT_THEMES_DIR` (`/data/themes` in Docker) |

The web UI uses the server default theme; each document can use its own. A theme needs only
`theme.yaml`: logos and font files are optional (without a logo the company name is printed; without
font files the font family is used if installed, else the fallback). Fonts are embedded in PDF and
HTML; Word uses the font by name. A test fails if a brand colour or name is ever hard-coded outside
`src/sextant/themes/`.

The default theme follows the *Hybrid Solutions Internal Apps* design system. Open question: that
system is scoped to internal apps; customer-facing as-builts may need the brand manual's print fonts
(Futura PT / Tisa Pro), which is now only a `theme.yaml` change.
