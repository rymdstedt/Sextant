"""Virtualization checks: snapshots, tools, datastores, host state, cluster features."""

from __future__ import annotations

import re

from sextant.analysis import check
from sextant.model import Device, Finding, Severity

# Platforms whose driver reads NTP per host. HypervisorHost.ntp_servers cannot say "not collected", so the
# per-host check only runs where an empty list really means "none": Proxmox never reads it, Hyper-V only for
# the node the script ran on (that value is also Device.management.ntp_servers, checked below).
_HOST_NTP_PLATFORMS = {"vmware"}
_NO_QUORUM = re.compile(r"\bnot quorate\b|\bno quorum\b|\bquorum lost\b|\blost\b|^\s*0\s*$", re.I)


@check
def vm_snapshots(d: Device):
    v = d.virtualization
    if not v:
        return
    old = [vm for vm in v.vms if (vm.oldest_snapshot_days or 0) > 7]
    if old:
        worst = max(vm.oldest_snapshot_days or 0 for vm in old)
        yield Finding(check_id="virt.old-snapshots", severity=Severity.high if worst > 30 else Severity.medium,
                      title=f"{len(old)} VM(s) with snapshots older than 7 days",
                      detail=f"Oldest snapshot is {worst} days. Snapshots grow and hurt performance and backups.",
                      recommendation="Consolidate/delete old snapshots; snapshots are not backups.",
                      evidence=[f"{vm.name}: {vm.oldest_snapshot_days} d" for vm in old])


@check
def vm_tools(d: Device):
    v = d.virtualization
    if not v:
        return
    bad = [vm.name for vm in v.vms if (vm.power_state or "").lower() in ("on", "poweredon", "running")
           and vm.tools_status and any(x in vm.tools_status.lower() for x in ("notrunning", "not running",
                                                                              "not installed", "notinstalled"))]
    if bad:
        yield Finding(check_id="virt.tools", severity=Severity.medium,
                      title=f"Guest tools not running on {len(bad)} powered-on VM(s)",
                      detail="No graceful shutdown, guest IP visibility or quiesced backups.",
                      recommendation="Install/start VMware Tools / qemu-guest-agent / integration services.",
                      evidence=bad)


@check
def datastores(d: Device):
    v = d.virtualization
    if not v:
        return
    for ds in v.datastores:
        pct = ds.used_pct
        if pct is None:
            continue
        if pct >= 90:
            yield Finding(check_id="virt.datastore-full", severity=Severity.high,
                          title=f"Datastore {ds.name} {pct:.0f}% full",
                          detail=f"{ds.free_gb:.0f} GB free of {ds.capacity_gb:.0f} GB.",
                          recommendation="Free space or extend now: full datastores stop VMs with thin disks/snapshots.")
        elif pct >= 80:
            yield Finding(check_id="virt.datastore-high", severity=Severity.medium,
                          title=f"Datastore {ds.name} {pct:.0f}% full",
                          detail=f"{ds.free_gb:.0f} GB free of {ds.capacity_gb:.0f} GB.",
                          recommendation="Plan capacity; keep at least 20% free.")


@check
def hosts(d: Device):
    v = d.virtualization
    if not v:
        return
    for h in v.hosts:
        state = (h.state or "").lower()
        if "maint" in state:
            yield Finding(check_id="virt.host-maintenance", severity=Severity.medium,
                          title=f"Host {h.name} in maintenance mode",
                          detail="Cluster runs with reduced capacity and redundancy.",
                          recommendation="Finish the maintenance and exit maintenance mode.")
        elif any(x in state for x in ("disconnected", "notresponding", "not responding", "offline", "down")):
            yield Finding(check_id="virt.host-down", severity=Severity.critical,
                          title=f"Host {h.name} {h.state}",
                          recommendation="Restore host connectivity; check HA restarted its VMs.")
        if v.platform in _HOST_NTP_PLATFORMS and not h.ntp_servers and h.state and "maint" not in state:
            yield Finding(check_id="virt.host-ntp", severity=Severity.low, title=f"Host {h.name} has no NTP",
                          recommendation="Configure NTP on every hypervisor host.")
    if v.platform == "hyperv" and not d.management.ntp_servers:
        node = next((f.value for f in d.hardware if f.key == "Data collected from node"), d.hostname)
        yield Finding(check_id="virt.host-ntp", severity=Severity.low, title=f"Host {node} has no NTP",
                      recommendation="Configure NTP on every hypervisor host.")


@check
def clusters(d: Device):
    v = d.virtualization
    if not v:
        return
    for c in v.clusters:
        if c.ha_enabled is False:
            yield Finding(check_id="virt.cluster-ha", severity=Severity.high, title=f"Cluster {c.name}: HA disabled",
                          recommendation="Enable HA so VMs restart after a host failure.")
        if c.drs_enabled is False and v.platform == "vmware":
            yield Finding(check_id="virt.cluster-drs", severity=Severity.low, title=f"Cluster {c.name}: DRS disabled",
                          recommendation="Enable DRS (at least partially automated) to balance load.")
        if c.quorum and _NO_QUORUM.search(c.quorum):
            yield Finding(check_id="virt.quorum", severity=Severity.critical, title=f"Cluster {c.name}: quorum issue",
                          detail=c.quorum, recommendation="Restore cluster quorum.")
