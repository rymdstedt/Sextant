import json
from pathlib import Path

import pytest

from hsdoc.drivers import REGISTRY
from hsdoc.drivers._ssh import assert_read_only
from hsdoc.drivers.base import RawCollection
from hsdoc.drivers.linux import COMMANDS, LinuxDriver
from hsdoc.model import DeviceRole

FIXTURE = Path(__file__).resolve().parents[2] / "examples" / "linux" / "raw.json"


@pytest.fixture(scope="module")
def dev():
    return LinuxDriver().parse(RawCollection(**json.loads(FIXTURE.read_text())))


def test_commands_read_only():
    assert REGISTRY["linux"].methods == ("ssh", "file")
    for c in COMMANDS:
        assert_read_only(c)


def test_identity(dev):
    assert dev.hostname == "sto-mon01" and dev.role == DeviceRole.server and dev.platform == "linux"
    assert dev.os_name == "Ubuntu" and dev.os_version.startswith("24.04.1")
    assert dev.model == "Virtual machine (vmware)" and dev.mgmt_ip == "10.10.10.90"
    assert dev.uptime.startswith("3 weeks") and dev.collection_warnings == []
    assert any(f.key == "Kernel" and f.value == "6.8.0-45-generic" for f in dev.hardware)


def test_interfaces_and_routes(dev):
    itf = {i.name: i for i in dev.interfaces}
    assert itf["lo"].kind == "loopback" and itf["docker0"].kind == "virtual"
    assert itf["ens192"].ipv4[0].address == "10.10.10.90/24" and itf["ens192"].oper_up is True
    assert itf["ens192"].mac == "00:50:56:9a:3c:21" and itf["ens192"].mtu == 1500
    assert itf["veth3f2a1c9"].extra["bridge"] == "docker0"
    default = next(r for r in dev.routes if r.prefix == "0.0.0.0/0")
    assert default.next_hop == "10.10.10.1" and default.interface == "ens192"
    assert any(r.protocol == "connected" for r in dev.routes)


def test_management(dev):
    m = dev.management
    assert m.ntp_servers == ["10.10.10.11", "10.10.10.12"]
    assert m.dns_servers == ["10.10.10.11", "10.10.10.12"]  # upstream, not the 127.0.0.53 stub
    assert m.domain == "ad.example.internal" and m.timezone == "Europe/Stockholm"
    assert m.syslog_servers == ["10.10.10.95:514/tcp", "10.10.10.96:6514/tcp"]
    assert m.ssh is True and m.telnet is False
    assert m.users[0].name == "root" and m.users[0].auth == "ssh PermitRootLogin no"  # drop-in wins


def test_sections(dev):
    secs = {s.id: s for s in dev.sections}
    fs = secs["linux-filesystems"].tables[0]
    mounts = [r[0] for r in fs.rows]
    assert "/" in mounts and "/var/lib/docker" in mounts and "/run" not in mounts  # tmpfs/overlay skipped
    full = secs["linux-filesystems-full"]
    assert full.summary_relevant and [r[0] for r in full.tables[0].rows] == ["/var/lib/docker"]
    assert full.tables[0].rows[0][6] == "85%"
    disks = secs["linux-disks"].tables[0].rows
    assert disks[0][0] == "sda" and any(r[0].strip() == "ubuntu--vg-ubuntu--lv" for r in disks)
    assert not any(r[0].startswith("loop") for r in disks)
    ports = {r[1] for r in secs["linux-listening"].tables[0].rows}
    assert {"22", "80", "443", "10051"} <= ports
    svcs = [r[0] for r in secs["linux-services"].tables[0].rows]
    assert "docker" in svcs and "nginx" in svcs and "chrony" in svcs and len(svcs) == 19
    sshd = {f.key: f.value for f in secs["linux-sshd"].facts}
    assert sshd["PasswordAuthentication"] == "no"


def test_tolerant():
    d = LinuxDriver().parse(RawCollection(driver="linux", target="srv", method="ssh", outputs={}))
    assert d.hostname == "srv" and d.collection_warnings
    assert d.management.users[0].auth == "ssh PermitRootLogin prohibit-password (default)"
    d = LinuxDriver().parse(RawCollection(driver="linux", target="srv", method="ssh", outputs={
        "ip -j addr": "not json", "ip -j route": "[{}]", "df -hPT": "garbage line\n", "lsblk -J -o NAME,SIZE,TYPE,"
        "MOUNTPOINT,FSTYPE": "{}"}))
    assert d.interfaces == [] and any("JSON" in w for w in d.collection_warnings)


def test_from_file_text_bundle(tmp_path):
    p = tmp_path / "srv.txt"
    p.write_text("### hostnamectl\n Static hostname: web01\n### df -hPT\n"
                 "Filesystem Type Size Used Avail Use% Mounted on\n/dev/sda1 ext4 10G 9.5G 0.5G 95% /\n")
    d = LinuxDriver().parse(LinuxDriver().from_file(p))
    assert d.hostname == "web01"
    full = next(s for s in d.sections if s.id == "linux-filesystems-full")
    assert full.tables[0].rows[0][7].startswith("critical")
