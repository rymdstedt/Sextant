# Hybrid As-Built

Generates infrastructure documentation for Hybrid Solutions from switches, routers,
firewalls, hypervisors and servers, over SSH, SNMP, vendor APIs or exported config files.

Every run produces two documents, as Word and PDF, in the Hybrid Solutions design:

- **As-Built**: complete documentation of how each system is configured.
- **Summary**: one page per device that a sysadmin can read in 10–30 seconds,
  with the items that need attention listed first.

> Status: early development. See [CLAUDE.md](CLAUDE.md) for the architecture and the build plan.

## Supported platforms (planned)

Cisco IOS/IOS-XE, NX-OS, ASA · Aruba CX, Aruba AOS-S/ProCurve · Juniper Junos ·
Fortinet FortiGate · Palo Alto PAN-OS · pfSense/OPNsense · VMware vCenter/ESXi ·
Proxmox VE · Hyper-V · Linux · anything with SNMP.

## Security

Drivers only run read-only commands. Secrets are redacted before anything is saved.
Credentials are never written to snapshots or documents.
