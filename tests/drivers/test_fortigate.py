import json
from pathlib import Path

import pytest

from sextant.drivers import get_driver
from sextant.drivers.base import RawCollection
from sextant.drivers.fortigate import FortiGateDriver, parse_fortios

EX = Path(__file__).resolve().parents[2] / "examples" / "fortigate"


@pytest.fixture(scope="module")
def dev():
    raw = RawCollection(**json.loads((EX / "raw.json").read_text()))
    return FortiGateDriver().parse(raw)


def test_registered():
    assert get_driver("fortigate").methods == ("ssh", "api", "file")


def test_identity(dev):
    assert dev.hostname == "sto-fw01"
    assert dev.role.value == "firewall" and dev.vendor == "Fortinet" and dev.platform == "fortigate"
    assert dev.model == "FortiGate-100F"
    assert dev.os_name == "FortiOS" and dev.os_version == "7.4.4 build 2662"
    assert dev.serial == "FG100FTK21000001"
    assert dev.mgmt_ip == "10.10.99.2"
    assert dev.collection_method == "ssh" and dev.collection_warnings == []


def test_management(dev):
    mg = dev.management
    assert mg.ssh and mg.https and mg.http and not mg.telnet  # http only on LAN-SERVERS
    assert mg.ntp_servers == ["10.10.20.10", "se.pool.ntp.org"]
    assert mg.dns_servers == ["10.10.20.10", "10.10.20.11"] and mg.domain == "corp.example"
    assert mg.timezone == "Europe/Stockholm"
    assert "10.10.99.30:6514" in mg.syslog_servers
    assert mg.snmp.communities == ["public (RO)"] and "v2c" in mg.snmp.versions
    assert mg.snmp.v3_users == ["monitor (auth-priv, SHA256/AES256)"]
    assert mg.banner.startswith("Authorized access only")
    users = {u.name: u for u in mg.users}
    assert users["admin"].privilege == "super_admin" and users["admin"].auth == "password"
    assert users["netops"].auth == "remote (FW-Admins)"
    assert "ssh-key" in users["backup-ro"].auth
    assert mg.aaa.radius_servers == ["10.10.20.10", "10.10.20.11"]


def test_interfaces_and_vlans(dev):
    by = {i.name: i for i in dev.interfaces}
    assert by["wan1"].zone == "WAN" and by["wan1"].ipv4[0].address == "203.0.113.10/29"
    assert by["LAN-SERVERS"].kind == "vlan" and by["LAN-SERVERS"].access_vlan == 20
    assert by["port1"].lag == "lag-core" and by["lag-core"].lag_members == ["port1", "port2"]
    assert by["port16"].enabled is False and by["port16"].oper_up is False
    assert [v.id for v in dev.vlans] == [10, 20, 30, 99]


def test_policies(dev):
    rules = dev.firewall_rules
    assert len(rules) == 25
    r1 = rules[0]
    assert (r1.id, r1.name, r1.action, r1.nat, r1.log) == ("1", "Users-Internet", "allow", True, True)
    assert r1.src_zones == ["LAN"] and r1.dst_zones == ["WAN"] and r1.dst_addresses == ["any"]
    assert "webfilter:wf-corp" in r1.security_profiles and r1.schedule == "always"
    by = {r.name: r for r in rules}
    assert by["Temp-Vendor-RDP"].enabled is False
    assert by["VPN-Partner-In"].log is False
    anyany = by["Legacy-Any-Any"]
    assert anyany.src_addresses == ["any"] and anyany.dst_addresses == ["any"] and anyany.services == ["any"]
    assert by["Cleanup-Deny"].action == "deny"  # implicit default action
    assert by["SSLVPN-Servers"].users == ["group:VPN-Users"]
    assert by["Patch-Window"].schedule == "maint-window"


def test_nat_and_objects(dev):
    vip = next(n for n in dev.nat_rules if n.id == "vip:VIP-WEB01-HTTPS")
    assert vip.original == "203.0.113.11:443/tcp" and vip.translated == "10.10.50.10:443" and vip.interface == "wan1"
    snat = next(n for n in dev.nat_rules if n.id == "policy:1")
    assert snat.translated == "IP pool POOL-USERS"
    objs = {o.name: o for o in dev.address_objects}
    assert objs["H-DC01"].kind == "host" and objs["H-DC01"].value == "10.10.20.10"
    assert objs["NET-USERS"].value == "10.10.10.0/24"
    assert objs["SSLVPN-POOL"].kind == "range"
    assert objs["GRP-FILESERVERS"].kind == "group" and objs["GRP-FILESERVERS"].value == "H-FILE01, H-FILE02"
    assert objs["FQDN-BACKUP-CLOUD"].kind == "fqdn"


def test_vpn(dev):
    t = {v.name: v for v in dev.vpn_tunnels}
    assert t["to-gbg"].phase1 == "aes256-sha256/aes256gcm-prfsha384, dh14, 28800s"
    assert t["to-gbg"].phase2 == "aes256-sha256, dh14, 3600s" and t["to-gbg"].ike_version == "IKEv2"
    assert t["to-gbg"].remote_subnets == ["10.30.0.0/16"] and t["to-gbg"].psk_set is True
    assert t["to-partner"].phase1 == "3des-sha1, dh2, 86400s" and t["to-partner"].ike_version == "IKEv1"
    assert t["to-partner"].peer == "198.51.100.150"
    assert t["SSL VPN"].kind == "ssl"


def test_ha_routes_dhcp(dev):
    assert dev.ha.mode == "active-passive" and dev.ha.state == "primary" and dev.ha.group == "STO-HA"
    assert dev.ha.details["sync"] == "out-of-sync" and len(dev.ha.members) == 2
    default = [r for r in dev.routes if r.prefix == "0.0.0.0/0"]
    assert default[0].next_hop == "203.0.113.9" and default[1].distance == 20
    bgp = dev.routing_protocols[0]
    assert bgp.protocol == "bgp" and bgp.asn == "65010"
    assert dev.dhcp_scopes[0].rows[0][2] == "10.10.10.100-10.10.10.239"
    assert {"fortigate-vips", "fortigate-sslvpn", "fortigate-security-profiles"} <= {s.id for s in dev.sections}


def test_no_secrets_and_file_import(tmp_path):
    conf = (EX / "sto-fw01.conf").read_text().replace(
        'set name "public"', 'set name "Sup3rS3cretComm"').replace(
        "set psksecret ENC <redacted>", "set psksecret ENC Zm9vYmFyMTIzNDU2Nzg5MGFiY2Q=")
    f = tmp_path / "x.conf"
    f.write_text(conf)
    drv = FortiGateDriver()
    dev = drv.parse(drv.from_file(f))
    assert dev.hostname == "sto-fw01" and dev.collection_method == "file"
    assert dev.management.snmp.communities == ["S****m (RO)"]
    dump = dev.model_dump_json()
    assert "Sup3rS3cretComm" not in dump and "Zm9vYmFyMTIz" not in dump


def test_api_collection_shape():
    conf = (EX / "sto-fw01.conf").read_text()
    raw = RawCollection(driver="fortigate", target="10.10.99.2", method="api", outputs={
        "/api/v2/monitor/system/config/backup?scope=global": conf,
        "/api/v2/monitor/system/status": {"results": {"model_name": "FortiGate", "model_number": "100F",
                                                      "hostname": "sto-fw01"},
                                          "serial": "FG100FTK21000001", "version": "v7.4.4", "build": 2662},
        "/api/v2/monitor/system/ha-checksums": {"results": [
            {"serial_no": "FG100FTK21000001", "checksum": {"all": "aa"}},
            {"serial_no": "FG100FTK21000002", "checksum": {"all": "aa"}}]},
    })
    dev = FortiGateDriver().parse(raw)
    assert dev.os_version == "7.4.4 build 2662" and dev.model == "FortiGate-100F"
    assert dev.ha.details["sync"] == "in-sync"


def test_parser_tolerant():
    root = parse_fortios('config system global\n  set hostname "a b"\n  set x "multi\nline"\nend\nedit stray\nnext\n')
    assert root.sub("system global").get("hostname") == "a b"
    dev = FortiGateDriver().parse(RawCollection(driver="fortigate", target="t", method="ssh", outputs={}))
    assert dev.hostname == "t" and dev.collection_warnings
