import json
from pathlib import Path

import pytest

from sextant.drivers import get_driver
from sextant.drivers.base import RawCollection
from sextant.drivers.cisco_asa import CiscoAsaDriver, _Cfg, parse_ace

EX = Path(__file__).resolve().parents[2] / "examples" / "cisco_asa"


@pytest.fixture(scope="module")
def dev():
    return CiscoAsaDriver().parse(RawCollection(**json.loads((EX / "raw.json").read_text())))


def test_registered():
    assert get_driver("cisco_asa").label == "Cisco ASA"


def test_identity(dev):
    assert dev.hostname == "dc-asa01" and dev.model == "ASA5516" and dev.os_version == "9.16(4)57"
    assert dev.serial == "JAD21430ABC" and dev.uptime == "212 days 4 hours"
    assert dev.licenses == ["ASA5516 Security Plus"] and dev.mgmt_ip == "10.20.99.10"
    assert dev.role.value == "firewall" and dev.vendor == "Cisco" and dev.collection_warnings == []


def test_management(dev):
    mg = dev.management
    assert mg.ssh and mg.https and not mg.http and not mg.telnet and mg.ssh_version == "2"
    assert "10.20.99.0/24 (management, ssh)" in mg.allowed_mgmt_hosts
    assert mg.ntp_servers == ["10.20.20.10", "10.20.20.11"] and mg.dns_servers == ["10.20.20.10", "10.20.20.11"]
    assert mg.syslog_servers == ["10.20.20.50 (servers)", "10.20.20.51 (servers, 6/1470)"]
    assert mg.snmp.versions == ["v2c", "v3"] and mg.snmp.communities[0] == "<redacted> (RO)"
    assert mg.snmp.v3_users[0].startswith("librenms (authPriv, SHA256/AES 256")
    assert mg.aaa.radius_servers[0] == "10.20.20.10 (RADIUS-NPS, servers)" and mg.aaa.accounting is True
    users = {u.name: u for u in mg.users}
    assert users["admin"].privilege == "15" and users["netops"].auth == "password (pbkdf2), ssh-key"
    assert users["readonly"].privilege == "5"
    assert mg.console_timeout_min == 15 and mg.banner.startswith("Authorized access only")


def test_interfaces(dev):
    by = {i.name: i for i in dev.interfaces}
    out = by["GigabitEthernet1/1"]
    assert out.zone == "outside" and out.ipv4[0].address == "203.0.113.2/29"
    assert out.extra["security-level"] == "0" and out.extra["standby-ip"] == "203.0.113.3"
    sub = by["Port-channel1.20"]
    assert sub.kind == "vlan" and sub.access_vlan == 20 and sub.zone == "servers" and sub.mtu == 9000
    assert by["Port-channel1"].lag_members == ["GigabitEthernet1/2", "GigabitEthernet1/3"]
    assert by["GigabitEthernet1/5"].enabled is False and by["GigabitEthernet1/5"].oper_up is False
    assert [v.id for v in dev.vlans] == [10, 20, 99]


def test_rules(dev):
    rules = dev.firewall_rules
    assert len(rules) == 14
    r = rules[0]
    assert (r.id, r.action, r.src_zones, r.dst_addresses, r.services, r.log, r.hit_count) == (
        "outside_access_in:2", "allow", ["outside"], ["OBJ-WEB01"], ["tcp/WEB-PORTS"], True, 1882231)
    assert r.comment == "Published web server"
    by = {x.id: x for x in rules}
    assert by["outside_access_in:5"].enabled is False  # inactive
    anyany = by["inside_access_in:6"]
    assert (anyany.action, anyany.src_addresses, anyany.dst_addresses, anyany.services) == (
        "allow", ["any"], ["any"], ["any"])
    assert by["servers_access_in:3"].log is False  # log disable
    assert by["servers_access_in:1"].services == ["MGMT-SVC"]
    assert by["dmz_access_in:2"].action == "deny"
    assert {a.name for a in dev.acls} >= {"VPN-STO", "VPN-SUPPLIER"}


def test_nat(dev):
    nat = {n.id: n for n in dev.nat_rules}
    assert nat["twice:1"].kind == "no-nat" and nat["twice:1"].original == "GRP-DC-INTERNAL -> NET-STO"
    assert nat["object:NET-INSIDE"].kind == "pat" and nat["object:NET-INSIDE"].translated == "outside interface"
    sftp = nat["object:H-SFTP01"]
    assert sftp.kind == "static" and sftp.translated == "203.0.113.6:ssh" and sftp.interface == "dmz -> outside"


def test_vpn(dev):
    sto, sup, ac = dev.vpn_tunnels
    assert sto.peer == "203.0.113.10" and sto.ike_version == "IKEv2" and sto.psk_set
    assert sto.phase1 == "aes256-sha256, dh14, 28800s" and sto.phase2 == "aes256-sha256, dh14, 3600s"
    assert sto.local_subnets == ["10.20.10.0/24", "10.20.20.0/24", "10.20.50.0/24"]
    assert sto.remote_subnets == ["10.10.0.0/16"]
    assert sup.ike_version == "IKEv1" and sup.phase1 == "aes256-sha1, dh5, 86400s"
    assert sup.phase2 == "aes256-sha1, no-pfs, 28800s"
    assert ac.kind == "ssl"


def test_ha_routes(dev):
    ha = dev.ha
    assert ha.mode == "active-passive" and ha.state == "active" and ha.details["sync"] == "in-sync"
    assert ha.members == ["dc-asa01 (Primary, Active)", "mate (Secondary, Standby Ready)"]
    assert dev.routes[0].prefix == "0.0.0.0/0" and dev.routes[0].next_hop == "203.0.113.1"
    assert dev.routes[2].distance == 10
    ospf = dev.routing_protocols[0]
    assert ospf.protocol == "ospf" and ospf.router_id == "10.20.99.1" and len(ospf.networks) == 2


def test_parse_ace():
    cfg = _Cfg(text="", lines=[], svc_groups={"WEB": []})
    a = parse_ace("extended permit tcp host 10.1.1.1 10.2.0.0 255.255.0.0 range 1000 2000 log 6 interval 300", cfg)
    assert (a["src"], a["dst"], a["dport"], a["log"]) == ("10.1.1.1", "10.2.0.0/16", "1000-2000", True)
    b = parse_ace("extended deny ip any4 any4 time-range WORK inactive", cfg)
    assert b["inactive"] and b["time_range"] == "WORK" and b["log"] is None
    assert parse_ace("remark hello", cfg) is None


def test_file_import_and_secrets(tmp_path):
    conf = (EX / "running-config.txt").read_text().replace(
        "snmp-server community <redacted>", "snmp-server community Sn0wFlake99").replace(
        "ikev1 pre-shared-key <redacted>", "ikev1 pre-shared-key TopSecretKey1")
    f = tmp_path / "dc-asa01.txt"
    f.write_text(conf)
    drv = CiscoAsaDriver()
    dev = drv.parse(drv.from_file(f))
    assert dev.collection_method == "file" and dev.collection_warnings == [] and dev.ha.state is None
    assert dev.management.snmp.communities[0] == "S****9 (RO)"
    dump = dev.model_dump_json()
    assert "Sn0wFlake99" not in dump and "TopSecretKey1" not in dump


def test_tolerant():
    dev = CiscoAsaDriver().parse(RawCollection(driver="cisco_asa", target="x", method="ssh",
                                               outputs={"show running-config": "garbage\naccess-list X extended"}))
    assert dev.hostname == "x" and dev.collection_warnings
