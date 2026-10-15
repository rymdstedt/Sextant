import json
import re
from pathlib import Path

import pytest

from sextant.drivers import REGISTRY
from sextant.drivers.base import RawCollection
from sextant.drivers.hyperv import COLLECT_SCRIPT, HyperVDriver, _command_line, assert_script_read_only
from sextant.model import DeviceRole

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "examples" / "hyperv" / "raw.json"


@pytest.fixture(scope="module")
def dev():
    return HyperVDriver().parse(RawCollection(**json.loads(FIXTURE.read_text())))


def test_registered():
    assert REGISTRY["hyperv"].methods == ("winrm", "file")


def test_script_is_read_only_and_shipped():
    assert_script_read_only(COLLECT_SCRIPT)
    assert not re.search(r"\b(Set|New|Remove|Start|Stop)-\w", COLLECT_SCRIPT)
    shipped = (ROOT / "examples" / "hyperv" / "collect-hyperv.ps1").read_text()
    assert shipped.replace("\r\n", "\n") == COLLECT_SCRIPT
    with pytest.raises(ValueError):
        assert_script_read_only("Get-VM | Stop-VM")
    assert len(_command_line(COLLECT_SCRIPT)) < 8000  # cmd.exe limit is 8191


def test_identity_and_cluster(dev):
    assert dev.hostname == "mlm-hvc01" and dev.role == DeviceRole.hypervisor and dev.vendor == "Microsoft"
    assert dev.os_name == "Microsoft Windows Server 2022 Datacenter" and dev.mgmt_ip == "10.40.1.11"
    assert dev.collection_warnings == []
    assert dev.ha.state == "all nodes up" and dev.ha.members == ["MLM-HV01", "MLM-HV02"]
    assert dev.virtualization.manager == "Failover Cluster mlm-hvc01.ad.example.internal"
    hosts = {h.name: h for h in dev.virtualization.hosts}
    assert set(hosts) == {"MLM-HV01", "MLM-HV02"}
    assert hosts["MLM-HV01"].vendor_model == "HPE ProLiant DL380 Gen11" and hosts["MLM-HV01"].state == "connected"
    assert hosts["MLM-HV01"].ntp_servers == ["domain hierarchy (NT5DS)"]


def test_vms(dev):
    vms = {v.name: v for v in dev.virtualization.vms}
    assert len(vms) == 8
    assert vms["mlm-app01"].oldest_snapshot_days == 20
    assert vms["mlm-print01"].tools_status == "not running"
    assert vms["mlm-test01"].power_state == "off" and vms["mlm-test01"].tools_status is None
    sql = vms["mlm-sql01"]
    assert sql.host == "MLM-HV02" and sql.datastores == ["CSV-VM02"] and sql.disks_gb == [100.0, 400.0, 150.0]
    assert sql.networks == ["SET-vSwitch VLAN 20"] and sql.ip_addresses == ["10.40.20.31"]  # fe80 dropped
    assert sql.ha_protected is True and sql.cluster == "mlm-hvc01"


def test_storage_and_networks(dev):
    ds = {d.name: d for d in dev.virtualization.datastores}
    assert ds["CSV-VM01"].kind == "CSV" and ds["CSV-VM01"].used_pct == 71.0
    assert ds["CSV-VM02"].used_pct == 82.0 and ds["CSV-VM02"].shared
    sw = [n for n in dev.virtualization.networks if n.host == "MLM-HV01"][0]
    assert sw.name == "SET-vSwitch" and sw.kind == "external" and sw.teaming.startswith("SET")
    assert {pg["vlan"] for pg in sw.port_groups} == {"41", "42", "43", "10", "20"}
    assert dev.routes[0].next_hop == "10.40.1.1"
    assert dev.management.dns_servers == ["10.40.10.11", "10.40.10.12"]
    mgmt = next(i for i in dev.interfaces if i.name == "vEthernet (Management)")
    assert mgmt.access_vlan == 41 and mgmt.ipv4[0].address == "10.40.1.11/24"


def test_from_file_utf16_and_single_items(tmp_path):
    inv = json.loads(FIXTURE.read_text())["outputs"]["inventory"]
    inv = dict(inv, VMs=inv["VMs"][0], ClusterNodes=None, Cluster=None, ClusterGroups=[])  # PS collapses 1-arrays
    p = tmp_path / "hyperv-inventory.json"
    p.write_bytes(("﻿" + json.dumps(inv)).encode("utf-16-le"))
    raw = HyperVDriver().from_file(p)
    d = HyperVDriver().parse(raw)
    assert d.hostname == "MLM-HV01" and len(d.virtualization.vms) == 1 and d.ha is None


def test_tolerant():
    d = HyperVDriver().parse(RawCollection(driver="hyperv", target="hv", method="winrm", outputs={}))
    assert d.hostname == "hv" and d.collection_warnings
    d = HyperVDriver().parse(RawCollection(driver="hyperv", target="hv", method="winrm", outputs={"inventory": {
        "VMs": [None, {"Name": "x", "HardDrives": "junk", "Snapshots": [{"CreationTime": "bad"}]}],
        "Volumes": [{"DriveLetter": "C"}], "VMSwitches": [{}]}}))
    assert [v.name for v in d.virtualization.vms] == ["x"]
