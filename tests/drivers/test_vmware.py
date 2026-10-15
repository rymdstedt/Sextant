import json
from pathlib import Path

import pytest

from hsdoc.drivers import REGISTRY
from hsdoc.drivers.base import RawCollection
from hsdoc.drivers.vmware import VMwareDriver
from hsdoc.model import DeviceRole

FIXTURE = Path(__file__).resolve().parents[2] / "examples" / "vmware" / "raw.json"


@pytest.fixture(scope="module")
def dev():
    return VMwareDriver().parse(RawCollection(**json.loads(FIXTURE.read_text())))


def test_registered():
    assert REGISTRY["vmware"].methods == ("api", "file")


def test_identity(dev):
    assert dev.hostname == "sto-vc01"
    assert dev.role == DeviceRole.hypervisor and dev.vendor == "VMware" and dev.platform == "vmware"
    assert dev.os_version == "8.0.3"
    assert dev.collection_method == "api" and dev.source == "sto-vc01"
    assert dev.collection_warnings == []
    assert "vCenter Server 8.0.3" in dev.virtualization.manager


def test_cluster(dev):
    (c,) = dev.virtualization.clusters
    assert c.name == "STO-PROD" and len(c.hosts) == 3
    assert c.ha_enabled is True and c.drs_enabled is True
    assert c.drs_level == "fully automated" and c.evc_mode == "intel-sapphirerapids"


def test_hosts(dev):
    hosts = {h.name.split(".")[0]: h for h in dev.virtualization.hosts}
    assert len(hosts) == 3
    assert hosts["sto-esx03"].state == "maintenance"
    assert hosts["sto-esx01"].state == "connected"
    h = hosts["sto-esx01"]
    assert h.vendor_model == "Dell Inc. PowerEdge R660" and h.product.startswith("VMware ESXi 8.0.3")
    assert h.memory_gb == 1024.0 and h.cpu_cores == 64 and h.mgmt_ip == "10.10.1.11"
    assert "vmnic2 25000 Mb up" in h.nics and h.ntp_servers == ["10.10.10.11", "10.10.10.12"]
    assert h.services["SSH"].startswith("stopped")


def test_vms(dev):
    vms = {v.name: v for v in dev.virtualization.vms}
    assert len(vms) == 18
    assert vms["sto-sql01"].oldest_snapshot_days == 40
    assert vms["sto-sql01"].snapshots == ["pre-CU14 upgrade (2026-09-04)"]
    assert vms["sto-app01"].snapshots[1] == "after-patch (2026-10-12)"  # nested snapshot tree flattened
    assert vms["sto-print01"].tools_status == "not running"
    assert vms["sto-app01"].power_state == "off" and vms["sto-app01"].tools_status is None
    assert vms["sto-dc01"].tools_status == "running" and vms["sto-dc01"].ip_addresses == ["10.10.10.11"]
    assert vms["sto-sql01"].disks_gb == [100.0, 500.0, 200.0] and vms["sto-sql01"].vcpus == 8
    assert vms["sto-veeam01"].networks == ["VL10-Servers", "VL40-Backup"]


def test_datastores(dev):
    ds = {d.name: d for d in dev.virtualization.datastores}
    assert len(ds) == 3
    assert ds["STO-VMFS-01"].used_pct == 86.0 and ds["STO-VMFS-01"].kind == "VMFS"
    assert ds["STO-VMFS-02"].used_pct == 93.0
    assert ds["STO-NFS-ISO"].kind == "NFS" and ds["STO-NFS-ISO"].backing == "10.10.40.20:/mnt/pool1/iso"
    assert all(d.shared for d in ds.values())


def test_networks(dev):
    nets = dev.virtualization.networks
    dvs = [n for n in nets if n.kind == "distributed"]
    std = [n for n in nets if n.kind == "standard"]
    assert len(dvs) == 1 and len(std) == 3
    assert {pg["vlan"] for pg in dvs[0].port_groups} == {"10", "20", "30", "40", "100"}
    assert dvs[0].mtu == 9000
    assert std[0].name == "vSwitch0" and std[0].uplinks == ["vmnic0", "vmnic1"]
    assert std[0].port_groups[0]["name"] == "Management Network"


def test_licenses_and_sections(dev):
    assert any("vSphere Foundation" in lic for lic in dev.virtualization.licenses)
    ids = [s.id for s in dev.sections]
    assert ids[0] == "vmware-overview" and "vmware-licenses" in ids and "vmware-vmkernel" in ids


def test_snapshot_age_falls_back_to_now():
    raw = RawCollection(driver="vmware", target="x", method="file", outputs={
        "vms": [{"name": "a", "power_state": "poweredOn",
                 "snapshots": [{"name": "s", "create_time": "2000-01-01T00:00:00+00:00"}]}]})
    vm = VMwareDriver().parse(raw).virtualization.vms[0]
    assert vm.oldest_snapshot_days > 9000


def test_tolerant_on_empty_and_garbage():
    d = VMwareDriver().parse(RawCollection(driver="vmware", target="vc", method="api", outputs={}))
    assert d.hostname == "vc" and d.virtualization.vms == []
    assert any("missing" in w for w in d.collection_warnings)
    d = VMwareDriver().parse(RawCollection(driver="vmware", target="vc", method="api", outputs={
        "about": "x", "hosts": [None, 1, {"name": "h", "memory_bytes": "junk"}], "vms": {"name": "single"},
        "datastores": [{"name": "d", "capacity": None}], "networks": [], "clusters": [{}]}))
    assert [h.name for h in d.virtualization.hosts] == ["h"]
    assert [v.name for v in d.virtualization.vms] == ["single"]


def test_from_file_json(tmp_path):
    data = json.loads(FIXTURE.read_text())
    p = tmp_path / "export.json"
    p.write_text(json.dumps(data["outputs"]))
    raw = VMwareDriver().from_file(p)
    assert raw.method == "file" and raw.outputs["about"]["name"] == "sto-vc01"
    assert len(VMwareDriver().parse(raw).virtualization.vms) == 18
