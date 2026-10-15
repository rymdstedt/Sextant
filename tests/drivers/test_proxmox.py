import json
from pathlib import Path

import pytest

from hsdoc.drivers import REGISTRY
from hsdoc.drivers.base import RawCollection
from hsdoc.drivers.proxmox import ProxmoxDriver
from hsdoc.model import DeviceRole

FIXTURE = Path(__file__).resolve().parents[2] / "examples" / "proxmox" / "raw.json"


@pytest.fixture(scope="module")
def dev():
    return ProxmoxDriver().parse(RawCollection(**json.loads(FIXTURE.read_text())))


def test_registered():
    assert REGISTRY["proxmox"].methods == ("api", "file")


def test_identity_and_cluster(dev):
    assert dev.hostname == "gbg-pve" and dev.role == DeviceRole.hypervisor and dev.platform == "proxmox"
    assert dev.os_version == "8.4.1" and dev.mgmt_ip == "10.30.1.11"
    assert dev.collection_warnings == []
    (c,) = dev.virtualization.clusters
    assert c.hosts == ["gbg-pve01", "gbg-pve02", "gbg-pve03"]
    assert c.quorum == "quorate" and c.ha_enabled is True
    assert dev.ha.mode == "cluster" and dev.ha.state == "OK"


def test_nodes(dev):
    hosts = {h.name: h for h in dev.virtualization.hosts}
    assert len(hosts) == 3
    h = hosts["gbg-pve01"]
    assert h.product == "Proxmox VE 8.4.1" and h.cpu_cores == 32 and h.memory_gb == 512.0
    assert h.cpu_usage_pct == 18.0 and h.state == "connected" and h.uptime_days == 45.0


def test_guests(dev):
    vms = {v.name: v for v in dev.virtualization.vms}
    assert len(vms) == 13
    assert sum(1 for v in vms.values() if v.hw_version == "lxc") == 3
    gl = vms["gbg-gitlab01"]
    assert gl.oldest_snapshot_days == 13 and gl.snapshots == ["pre_upgrade_17_11 (2026-09-30)"]
    assert gl.ha_protected is True and gl.networks == ["vmbr0 VLAN 20"] and gl.ip_addresses == ["10.30.20.40/24"]
    fs = vms["gbg-fs01"]
    assert fs.disks_gb == [100.0, 1536.0] and fs.datastores == ["ceph-vm"]  # efidisk/cdrom ignored
    assert vms["gbg-dns01"].ip_addresses == ["10.30.10.53/24"] and vms["gbg-dns01"].tools_status is None
    assert vms["gbg-test01"].power_state == "off" and vms["gbg-test01"].backup is None
    assert "backup-daily-pbs" in vms["gbg-dc01"].backup and "backup-weekly-nfs" in vms["gbg-dc01"].backup


def test_storage(dev):
    ds = {d.name: d for d in dev.virtualization.datastores}
    assert ds["ceph-vm"].kind == "Ceph RBD" and ds["ceph-vm"].shared and len(ds["ceph-vm"].hosts) == 3
    assert ds["ceph-vm"].used_pct == 60.0
    assert ds["local-zfs (gbg-pve01)"].kind == "ZFS" and ds["local-zfs (gbg-pve01)"].shared is False
    assert ds["nfs-iso"].kind == "NFS" and ds["pbs-gbg"].kind == "PBS"


def test_networks(dev):
    nets = [n for n in dev.virtualization.networks if n.host == "gbg-pve01"]
    vmbr0 = next(n for n in nets if n.name == "vmbr0")
    bond0 = next(n for n in nets if n.name == "bond0")
    assert vmbr0.kind == "bridge" and vmbr0.uplinks == ["bond0"] and "VLAN-aware" in vmbr0.teaming
    assert {pg["vlan"] for pg in vmbr0.port_groups} >= {"10", "20", "30"}
    assert "10.30.1.11/24" in vmbr0.teaming
    assert bond0.kind == "bond" and bond0.uplinks == ["eno1", "eno2"] and bond0.teaming.startswith("802.3ad")


def test_sections(dev):
    secs = {s.id: s for s in dev.sections}
    backup = secs["proxmox-backup"].tables[0]
    assert len(backup.rows) == 3 and backup.rows[0][4] == "all except 150" and backup.rows[2][1] == "no"
    assert len(secs["proxmox-ha"].tables[0].rows) == 6


def test_tolerant():
    d = ProxmoxDriver().parse(RawCollection(driver="proxmox", target="pve", method="api", outputs={}))
    assert d.hostname == "pve" and d.virtualization.vms == [] and d.collection_warnings
    d = ProxmoxDriver().parse(RawCollection(driver="proxmox", target="pve", method="api", outputs={
        "/nodes": [{"node": "n1"}], "/nodes/n1/qemu": [{"vmid": 100, "name": "a"}, "junk"],
        "/nodes/n1/qemu/100/config": {"scsi0": "garbage", "net0": "nonsense"}, "/cluster/backup": [None]}))
    assert d.hostname == "n1" and [v.name for v in d.virtualization.vms] == ["a"]
