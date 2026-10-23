"""Regression tests for the server / hypervisor driver review (VMware, Proxmox, Hyper-V, Linux, SNMP,
the SSH read-only guard, end-of-support and virtualization checks, As-Built virtualization tables)."""

import importlib
import json
from datetime import date
from pathlib import Path

import pytest

from sextant.analysis import analyze_device
from sextant.analysis.lifecycle import end_of_support
from sextant.builders.asbuilt import _gb, _virtualization
from sextant.doc import Document, Table
from sextant.drivers._ssh import assert_read_only
from sextant.drivers.base import RawCollection
from sextant.drivers.hyperv import COLLECT_SCRIPT, HyperVDriver, assert_script_read_only
from sextant.drivers.linux import C_DF, C_OS, C_RSYSLOG, C_RSYSLOG_D, C_SSHD, C_SSHD_D, LinuxDriver
from sextant.drivers.proxmox import ProxmoxDriver
from sextant.drivers.snmp import _os_name, _value
from sextant.drivers.vmware import VMwareDriver, _short_name
from sextant.model import (
    Cluster,
    Device,
    HypervisorHost,
    Management,
    Virtualization,
    VirtualMachine,
)

ROOT = Path(__file__).resolve().parents[1]
TODAY = date(2026, 10, 23)


def linux(outputs):
    return LinuxDriver().parse(RawCollection(driver="linux", target="srv", method="file", outputs=outputs))


def hyperv(inv):
    return HyperVDriver().parse(RawCollection(driver="hyperv", target="hv", method="file", outputs={"inventory": inv}))


def proxmox(outputs):
    return ProxmoxDriver().parse(RawCollection(driver="proxmox", target="pve", method="file", outputs=outputs))


def titles(findings):
    return [f.title for f in findings]


# --------------------------------------------------------------------------- 1. end of support


def test_eos_esxi_hosts_by_version_not_build():
    v = Virtualization(platform="vmware", hosts=[
        HypervisorHost(name="esx-a1.lab.test", product="VMware ESXi 7.0.3 build-21930508"),
        HypervisorHost(name="esx-a2.lab.test", product="VMware ESXi 8.0.3 build-24022510")])
    d = Device(hostname="vc-lab", platform="vmware", os_version="8.0.3", virtualization=v)
    f = list(end_of_support(d, TODAY))
    assert titles(f) == ["vSphere 7.x is end of support"]
    assert f[0].evidence == ["esx-a1.lab.test: 7.0.3"]


def test_eos_vcenter_version():
    d = Device(hostname="vc-lab", platform="vmware", os_version="7.0.3", virtualization=Virtualization(
        platform="vmware", hosts=[HypervisorHost(name="esx-b1", product="VMware ESXi 8.0.2 build-1")]))
    assert [f.check_id for f in end_of_support(d, TODAY)] == ["lifecycle.eos"]


@pytest.mark.parametrize("os_release,expected", [
    ('NAME="Ubuntu"\nVERSION="20.04.6 LTS (Focal Fossa)"\nVERSION_ID="20.04"\n', ["Ubuntu 20.04 is end of support"]),
    ('NAME="Ubuntu"\nVERSION_ID="22.04"\n', []),
    ('NAME="Debian GNU/Linux"\nVERSION_ID="10"\nVERSION="10 (buster)"\n', ["Debian 10 is end of support"]),
    ('NAME="Debian GNU/Linux"\nVERSION_ID="12"\nVERSION="12 (bookworm)"\n', []),
    ('NAME="CentOS Stream"\nVERSION="9"\nVERSION_ID="9"\nPRETTY_NAME="CentOS Stream 9"\n', []),
    ('NAME="CentOS Stream"\nVERSION="8"\nVERSION_ID="8"\n', ["CentOS Stream 8 is end of support"]),
    ('NAME="CentOS Linux"\nVERSION="7 (Core)"\nVERSION_ID="7"\n', ["CentOS Linux 7 is end of support"]),
    ('PRETTY_NAME="Ubuntu 18.04.6 LTS"\n', ["Ubuntu 18.04 is end of support"]),  # PRETTY_NAME only
])
def test_eos_linux_os_release(os_release, expected):
    assert titles(end_of_support(linux({C_OS: os_release}), TODAY)) == expected


def test_eos_hyperv_host_os():
    d = hyperv({"ComputerName": "HVX01", "ComputerInfo": {"OsName": "Microsoft Windows Server 2012 R2 Standard"}})
    assert titles(end_of_support(d, TODAY)) == ["Windows Server 2012 is end of support"]


# --------------------------------------------------------------------------- 2. quorum


def test_proxmox_lost_quorum_is_reported():
    d = proxmox({"/cluster/status": [{"type": "cluster", "name": "pvx", "quorate": 0, "nodes": 3},
                                     {"type": "node", "name": "pvx1", "online": 1}],
                 "/cluster/ha/status/current": [{"id": "quorum", "type": "quorum", "status": "OK"}]})
    assert d.virtualization.clusters[0].quorum == "not quorate" and d.ha.state == "not quorate"
    assert "virt.quorum" in {f.check_id for f in analyze_device(d)}
    d = proxmox({"/cluster/status": [{"type": "cluster", "name": "pvx", "quorate": 1}]})
    assert "virt.quorum" not in {f.check_id for f in analyze_device(d)}


@pytest.mark.parametrize("quorum,bad", [("quorate", False), ("NOT quorate", True), ("No quorum on node 'pvx1'!", True),
                                        ("NodeMajority (Cluster Disk 10)", False), ("0", True)])
def test_quorum_check_strings(quorum, bad):
    d = Device(hostname="c", role="hypervisor", virtualization=Virtualization(
        platform="proxmox", clusters=[Cluster(name="c", quorum=quorum)]))
    assert ("virt.quorum" in {f.check_id for f in analyze_device(d)}) is bad


# --------------------------------------------------------------------------- 3. sshd


def test_sshd_match_in_dropin_does_not_hide_main_config():
    d = linux({C_SSHD_D: "Match Group sftponly\n  ForceCommand internal-sftp\n",
               C_SSHD: "Include /etc/ssh/sshd_config.d/*.conf\nPermitRootLogin yes\nPasswordAuthentication yes\n"
                       "Match User backup\n  PermitRootLogin no\n"})
    assert d.management.users[0].auth == "ssh PermitRootLogin yes"
    facts = {f.key: f.value for s in d.sections if s.id == "linux-sshd" for f in s.facts}
    assert facts["PasswordAuthentication"] == "yes"


def test_sshd_tab_and_equals_separators():
    d = linux({C_SSHD: "PermitRootLogin\tyes\nPasswordAuthentication=no\nPort = 2222\n"})
    facts = {f.key: f.value for s in d.sections if s.id == "linux-sshd" for f in s.facts}
    assert facts["PermitRootLogin"] == "yes" and facts["PasswordAuthentication"] == "no" and facts["Port"] == "2222"


# --------------------------------------------------------------------------- 4. read-only guard


@pytest.mark.parametrize("cmd", [
    "ip link set eth0 down", "ip route flush all", "cat x | tee y", "more x | sh", "show version\nreload",
    "show run | redirect flash:x", "show run | append flash:x", "show run | tee flash:x",
    "show configuration | save /var/tmp/x", "catastrophic-cmd", "config system console", "cat", "show run > x",
    "cat /etc/hosts; reboot", "uname -r && reboot", "cat $(id)", "cat `id`", "show run || reload",
    "hostnamectl set-hostname evil", "timedatectl set-ntp false", "ss -K", "systemctl restart sshd",
])
def test_guard_rejects(cmd):
    with pytest.raises(ValueError):
        assert_read_only(cmd)


@pytest.mark.parametrize("cmd", ["show", "show running-config | include ntp", "show configuration | display set",
                                 "show interfaces | no-more", "show run | i snmp | e community",
                                 "ip -j addr", "cat /etc/ssh/sshd_config.d/*.conf", "terminal length 0",
                                 "get system status", "more flash:vlan.dat"])
def test_guard_allows(cmd):
    assert_read_only(cmd)


def test_guard_allows_every_driver_command():
    lists = {"aruba_aoscx": "AOSCX_COMMANDS", "juniper_junos": "JUNOS_COMMANDS", "cisco_ios": "IOS_COMMANDS",
             "cisco_nxos": "NXOS_COMMANDS", "cisco_asa": "COMMANDS", "hp_procurve": "PROCURVE_COMMANDS",
             "fortigate": "SSH_COMMANDS", "linux": "COMMANDS"}
    for mod, attr in lists.items():
        for cmd in getattr(importlib.import_module(f"sextant.drivers.{mod}"), attr):
            assert_read_only(cmd)
    pf = importlib.import_module("sextant.drivers.pfsense")
    for cmd in (pf.CMD_CONFIG, pf.PfSenseDriver.version_cmd, pf.OPNsenseDriver.version_cmd):
        assert_read_only(cmd)


# --------------------------------------------------------------------------- 5. Proxmox cores, 14. backups


def test_proxmox_cores_not_multiplied_by_sockets():
    d = proxmox({"/nodes": [{"node": "pvx1", "status": "online"}],
                 "/nodes/pvx1/status": {"cpuinfo": {"model": "Xeon", "sockets": 2, "cores": 64, "cpus": 128}}})
    h = d.virtualization.hosts[0]
    assert (h.cpu_sockets, h.cpu_cores) == (2, 64)


def test_proxmox_backup_job_pool_and_node_selection():
    d = proxmox({
        "/nodes": [{"node": "pvx1"}, {"node": "pvx2"}],
        "/cluster/backup": [{"id": "pool-job", "pool": "prod", "schedule": "02:00", "storage": "pbs"},
                            {"id": "node-job", "all": 1, "node": "pvx2", "schedule": "03:00", "storage": "nfs"}],
        "/cluster/resources": [{"type": "qemu", "vmid": 201, "node": "pvx1", "pool": "prod"},
                               {"type": "qemu", "vmid": 202, "node": "pvx1"},
                               {"type": "qemu", "vmid": 203, "node": "pvx2"}],
        "/nodes/pvx1/qemu": [{"vmid": 201, "name": "alpha"}, {"vmid": 202, "name": "bravo"}],
        "/nodes/pvx2/qemu": [{"vmid": 203, "name": "charlie"}]})
    backup = {v.name: v.backup for v in d.virtualization.vms}
    assert backup == {"alpha": "pool-job: 02:00 -> pbs", "bravo": None, "charlie": "node-job: 03:00 -> nfs"}


# --------------------------------------------------------------------------- 6/7/9/15. Hyper-V

CLUSTER_INV = {
    "ComputerName": "HVX01",
    "ComputerInfo": {"CsName": "HVX01", "OsName": "Microsoft Windows Server 2022 Datacenter", "OsBuildNumber": "20348",
                     "Sockets": 2, "Cores": 32, "LogicalProcessors": 64, "Processor": "Xeon Gold"},
    "Cluster": {"Name": "hvxc", "QuorumType": "NodeAndFileShareMajority", "QuorumResource": "File Share Witness"},
    "ClusterNodes": [{"Name": "HVX01", "State": "Up"}, {"Name": "HVX02", "State": "Up"},
                     {"Name": "HVX03", "State": "Up"}],
    "NodeInfo": [{"ComputerName": "HVX02", "OsName": "Microsoft Windows Server 2019 Standard",
                  "OsBuildNumber": "17763", "Sockets": 2, "Cores": 24, "LogicalProcessors": 48}],
    "VMHosts": [{"ComputerName": "HVX02", "LogicalProcessorCount": 48, "MemoryCapacityGB": 512},
                {"ComputerName": "HVX03", "LogicalProcessorCount": 40, "MemoryCapacityGB": 384}],
    "Volumes": [{"DriveLetter": "D", "FileSystemLabel": "VMs", "FileSystem": "ReFS", "SizeGB": 2000, "FreeGB": 500}],
    "VMs": [{"Name": "vm-local", "ComputerName": "HVX01", "HardDrives": [{"Path": "D:\\Hyper-V\\vm-local.vhdx"}]},
            {"Name": "vm-remote", "ComputerName": "HVX02", "HardDrives": [{"Path": "D:\\Hyper-V\\vm-remote.vhdx"}]}],
    "Ntp": {"Type": "NTP", "NtpServer": "ntp1.lab.test,0x9 ntp2.lab.test,0x9"},
}


def test_hyperv_remote_nodes_do_not_borrow_local_values():
    hosts = {h.name: h for h in hyperv(CLUSTER_INV).virtualization.hosts}
    assert (hosts["HVX01"].cpu_sockets, hosts["HVX01"].cpu_cores) == (2, 32)
    assert (hosts["HVX02"].cpu_sockets, hosts["HVX02"].cpu_cores) == (2, 24)  # CIM cores, not 48 threads
    assert hosts["HVX02"].product == "Hyper-V (Windows Server 2019 Standard)" and hosts["HVX02"].build == "build 17763"
    assert hosts["HVX03"].cpu_cores is None and hosts["HVX03"].product == "Hyper-V" and hosts["HVX03"].build is None
    assert hosts["HVX03"].memory_gb == 384


def test_hyperv_volume_datastores_match_vm_references():
    v = hyperv(CLUSTER_INV).virtualization
    assert [ds.name for ds in v.datastores] == ["D: (HVX01)"] and v.datastores[0].backing == "label VMs"
    vms = {vm.name: vm for vm in v.vms}
    assert vms["vm-local"].datastores == ["D: (HVX01)"]
    assert vms["vm-remote"].datastores == ["D: (HVX02)"]  # not HVX01's drive


def test_hyperv_failover_cluster_is_a_cluster():
    d = hyperv(CLUSTER_INV)
    (c,) = d.virtualization.clusters
    assert c.name == "hvxc" and c.hosts == ["HVX01", "HVX02", "HVX03"] and c.ha_enabled is True
    assert c.quorum == "NodeAndFileShareMajority (File Share Witness)"
    assert "virt.quorum" not in {f.check_id for f in analyze_device(d)}


def test_hyperv_ps51_array_wrapper():
    inv = {"ComputerName": "HVX09",
           "VMs": {"value": [{"Name": "vm-a", "NetworkAdapters": {"value": [{"SwitchName": "ext", "VlanId": 30,
                                                                            "IPAddresses": ["10.9.9.9"]}],
                                                                  "Count": 1}},
                             {"Name": "vm-b"}], "Count": 2}}
    vms = {v.name: v for v in hyperv(inv).virtualization.vms}
    assert set(vms) == {"vm-a", "vm-b"}
    assert vms["vm-a"].networks == ["ext VLAN 30"] and vms["vm-a"].ip_addresses == ["10.9.9.9"]


def test_hyperv_script_forbidden_cmdlets_and_shipped_copy():
    assert_script_read_only(COLLECT_SCRIPT)
    for bad in ("Checkpoint-VM x", "Rename-VM x", "Save-VM x", "Merge-VHD x", "Resize-VHD x", "Mount-VHD x",
                "Export-VM x", "Restore-VMSnapshot x", "Grant-VMConnectAccess x"):
        with pytest.raises(ValueError):
            assert_script_read_only(bad)
    shipped = (ROOT / "examples" / "hyperv" / "collect-hyperv.ps1").read_text()
    assert shipped.replace("\r\n", "\n") == COLLECT_SCRIPT and "NodeInfo = $nodeInfo" in COLLECT_SCRIPT


# --------------------------------------------------------------------------- 8. host NTP only where collected


def _ntp_findings(d):
    return [f.title for f in analyze_device(d) if f.check_id == "virt.host-ntp"]


def test_no_false_host_ntp_findings():
    d = proxmox({"/nodes": [{"node": "pvx1", "status": "online"}]})
    assert _ntp_findings(d) == []
    assert _ntp_findings(hyperv(CLUSTER_INV)) == []  # remote nodes: NTP not collected


def test_host_ntp_still_reported_where_collected():
    v = Virtualization(platform="vmware", hosts=[HypervisorHost(name="esx-c1", state="connected")])
    assert _ntp_findings(Device(hostname="vc", role="hypervisor", platform="vmware", virtualization=v)) == [
        "Host esx-c1 has no NTP"]
    assert _ntp_findings(hyperv(dict(CLUSTER_INV, Ntp={"Type": "NTP", "NtpServer": ""}))) == ["Host HVX01 has no NTP"]


# --------------------------------------------------------------------------- 10. rsyslog


def test_rsyslog_omfwd_case_insensitive_and_multiline():
    d = linux({C_RSYSLOG: '*.* action(Type="omfwd" Target="10.0.0.5" Port="10514" Protocol="TCP")\n',
               C_RSYSLOG_D: 'authpriv.* action(type="omfwd"\n    target="logs.lab.test"\n    port="514"\n'
                            '    template="Fmt(x)")\nkern.* @10.0.0.7\n'})
    assert d.management.syslog_servers == ["10.0.0.5:10514/tcp", "logs.lab.test:514/udp", "10.0.0.7:514/udp"]


# --------------------------------------------------------------------------- 11. vCenter name


def test_vcenter_name_from_ip_target():
    assert _short_name(None, "10.20.30.40") == "10.20.30.40"
    assert _short_name("vc01.lab.test", "10.20.30.40") == "vc01"
    assert _short_name(None, "vc02.lab.test") == "vc02"
    d = VMwareDriver().parse(RawCollection(driver="vmware", target="10.20.30.40", method="file", outputs={}))
    assert d.hostname == "10.20.30.40"


# --------------------------------------------------------------------------- 12. As-Built tables


def _tables(d):
    doc = Document(title="t", kind="asbuilt")
    _virtualization(doc, d, "x")
    return [b for b in doc.blocks if isinstance(b, Table)]


def test_asbuilt_virtualization_cells():
    v = Virtualization(platform="proxmox",
                       hosts=[HypervisorHost(name="pvx1", cpu_sockets=2, cpu_cores=64, memory_gb=512)],
                       vms=[VirtualMachine(name="tiny", memory_mb=512, snapshots=["pre-upgrade"]),
                            VirtualMachine(name="mid", memory_mb=1536, snapshots=["a (2026-10-01)"],
                                           oldest_snapshot_days=22)])
    tables = _tables(Device(hostname="pvx", virtualization=v))
    host_row = next(t for t in tables if t.columns[0] == "Host").rows[0]
    assert host_row[3] == "64 cores (2 sockets)"
    vm_rows = {r[0]: r for r in next(t for t in tables if t.columns[0] == "VM").rows}
    assert vm_rows["tiny"][4] == "512 MB" and vm_rows["tiny"][9] == "1"
    assert vm_rows["mid"][4] == "1.5 GB" and vm_rows["mid"][9] == "1 (22 d)"
    assert (_gb(None), _gb(0.5), _gb(8), _gb(120), _gb(2048)) == ("–", "512 MB", "8 GB", "120 GB", "2.0 TB")


# --------------------------------------------------------------------------- 13. SNMP


class OctetString(bytes):  # _value dispatches on the pysnmp class name; bytes(v) gives the raw octets
    pass


def test_snmp_trailing_nul_is_text():
    assert _value(OctetString(b"core-sw-lab\x00")) == "core-sw-lab"
    assert _value(OctetString(b"\x00\x1a\x2b\x3c\x4d\x5e\x6f\x70")) == "00:1a:2b:3c:4d:5e:6f:70"


def test_snmp_cat9k_is_ios_xe():
    descr = ("Cisco IOS Software [Cupertino], Catalyst L3 Switch Software (CAT9K_IOSXE), Version 17.9.4a, "
             "RELEASE SOFTWARE (fc5)")
    assert _os_name(descr, "Cisco") == "IOS-XE"
    assert _os_name("Cisco IOS Software, C2960X Software (C2960X-UNIVERSALK9-M), Version 15.2(7)E8", "Cisco") == "IOS"


# --------------------------------------------------------------------------- 14. filesystem thresholds


@pytest.mark.parametrize("pct,status", [(79, "ok"), (80, "warning"), (89, "warning"), (90, "critical")])
def test_linux_filesystem_thresholds_match_datastores(pct, status):
    df = f"Filesystem Type Size Used Avail Use% Mounted on\n/dev/sdb1 xfs 100G {pct}G 1G {pct}% /data\n"
    rows = next(s for s in linux({C_DF: df}).sections if s.id == "linux-filesystems").tables[0].rows
    assert rows[0][7].startswith(status)


def test_unknown_still_not_a_finding():
    d = Device(hostname="srv", role="server", management=Management(ntp_servers=["a", "b"], syslog_servers=["s"]))
    assert json.loads(d.model_dump_json())["hostname"] == "srv" and analyze_device(d) == []
