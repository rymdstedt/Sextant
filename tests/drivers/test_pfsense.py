import json
from pathlib import Path

import pytest

from sextant.drivers import get_driver
from sextant.drivers.base import RawCollection
from sextant.drivers.pfsense import PfSenseDriver

EX = Path(__file__).resolve().parents[2] / "examples" / "pfsense"


@pytest.fixture(scope="module")
def dev():
    return PfSenseDriver().parse(RawCollection(**json.loads((EX / "raw.json").read_text())))


def test_registered():
    drv = get_driver("pfsense")
    assert drv.methods == ("file", "ssh") and drv.label == "Netgate pfSense"


def test_identity_and_management(dev):
    assert dev.hostname == "mlm-fw01" and dev.os_name == "pfSense" and dev.os_version == "2.7.2-RELEASE"
    assert dev.vendor == "Netgate" and dev.platform == "pfsense" and dev.role.value == "firewall"
    assert dev.mgmt_ip == "10.40.0.1" and dev.collection_warnings == []
    mg = dev.management
    assert mg.https and not mg.http and mg.ssh and not mg.telnet
    assert mg.ntp_servers == ["0.se.pool.ntp.org", "1.se.pool.ntp.org"]
    assert mg.dns_servers == ["10.40.20.10", "9.9.9.9"] and mg.domain == "corp.example"
    assert mg.syslog_servers == ["10.40.20.50:514"]
    assert mg.snmp.enabled and mg.snmp.communities == ["public (RO)"] and "v2c" in mg.snmp.versions
    assert mg.aaa.radius_servers == ["10.40.20.10 (NPS-RADIUS)"]
    users = {u.name: u for u in mg.users}
    assert users["admin"].privilege == "admin (admins)" and users["admin"].auth == "password (bcrypt)"
    assert users["netops"].auth == "password (bcrypt), ssh-key"
    assert users["monitor"].privilege == "readonly"


def test_interfaces_vlans_routes(dev):
    by = {i.name: i for i in dev.interfaces}
    assert by["igb0"].zone == "WAN" and by["igb0"].ipv4[0].address == "198.51.100.10/29"
    assert by["igb1.20"].kind == "vlan" and by["igb1.20"].access_vlan == 20 and by["igb1.20"].zone == "SERVERS"
    assert by["igb2"].enabled is False
    assert [(v.id, v.name) for v in dev.vlans] == [(20, "Servers"), (30, "Guest WiFi")]
    assert dev.routes[0].prefix == "0.0.0.0/0" and dev.routes[0].next_hop == "198.51.100.9"
    assert dev.routes[1].prefix == "10.41.0.0/16" and dev.routes[1].next_hop == "10.40.0.254"


def test_rules(dev):
    rules = dev.firewall_rules
    assert len(rules) == 14
    by = {r.id: r for r in rules}
    r = by["1700000101"]
    assert (r.action, r.src_zones, r.dst_addresses, r.services, r.log, r.nat) == (
        "allow", ["WAN"], ["H_WEB01"], ["tcp/443"], True, True)
    assert by["1700000104"].enabled is False
    lan = by["0100000101"]
    assert lan.src_addresses == ["LAN net"] and lan.dst_addresses == ["any"] and lan.log is False
    anyany = by["1700000203"]
    assert anyany.src_addresses == ["any"] and anyany.dst_addresses == ["any"] and anyany.services == ["any"]
    assert by["1700000202"].dst_addresses == ["!RFC1918"]
    assert by["1700000301"].action == "drop" and by["1700000303"].action == "reject"
    assert by["1700000303"].dst_addresses == ["This Firewall"]
    assert by["1700000601"].src_zones == ["IPsec"]


def test_nat(dev):
    nat = {n.id: n for n in dev.nat_rules}
    assert nat["rdr:1"].kind == "dnat" and nat["rdr:1"].translated == "H_WEB01:443"
    assert nat["rdr:1"].original == "any -> WAN address:443 (tcp)"
    assert nat["outbound:1"].translated == "198.51.100.11" and nat["outbound:2"].kind == "no-nat"
    assert "outbound:auto" in nat  # hybrid keeps automatic rules


def test_vpn(dev):
    t = {v.name: v for v in dev.vpn_tunnels}
    lund = t["Warehouse Lund"]
    assert lund.phase1 == "aes256-sha256, dh14, 28800s" and lund.phase2 == "aes256-sha256, dh14, 3600s"
    assert lund.ike_version == "IKEv2" and lund.peer == "203.0.113.50" and lund.psk_set
    assert lund.local_subnets == ["10.40.20.0/24"] and lund.remote_subnets == ["10.41.0.0/16"]
    legacy = t["Logistics partner (legacy)"]
    assert legacy.phase1 == "aes128-sha1, dh2, 86400s" and legacy.phase2 == "aes128-sha1, no-pfs, 28800s"
    ovpn = t["Remote access users"]
    assert ovpn.kind == "openvpn" and "AES-256-GCM" in ovpn.phase1
    wg = t["tun_wg0 (Admin access)"]
    assert wg.kind == "wireguard" and wg.remote_subnets == ["10.40.250.10/32"] and wg.psk_set


def test_objects_dhcp_sections(dev):
    objs = {o.name: o for o in dev.address_objects}
    assert objs["H_WEB01"].kind == "host" and objs["RFC1918"].kind == "group"
    assert objs["NET_WAREHOUSE"].kind == "subnet"
    scopes = dev.dhcp_scopes[0].rows
    assert scopes[0][:4] == ["LAN", "10.40.0.0/24", "10.40.0.100-10.40.0.199", "10.40.0.1"]
    assert dev.ha is None
    assert {"pfsense-port-aliases", "pfsense-openvpn", "pfsense-packages"} <= {s.id for s in dev.sections}


def test_file_import_secrets(tmp_path):
    xml = (EX / "config.xml").read_text()
    xml = xml.replace("<rocommunity>public</rocommunity>", "<rocommunity>Xyzzy-Comm-42</rocommunity>")
    xml = xml.replace("<bcrypt-hash>&lt;redacted&gt;</bcrypt-hash>",
                      "<bcrypt-hash>$2y$10$abcdefghijABCDEFGHIJ0123456789abcdefghijABCDEFGHIJ01</bcrypt-hash>", 1)
    xml = xml.replace("<pre-shared-key>&lt;redacted&gt;</pre-shared-key>",
                      "<pre-shared-key>VerySecretPSK123</pre-shared-key>")
    f = tmp_path / "config.xml"
    f.write_text(xml)
    drv = PfSenseDriver()
    dev = drv.parse(drv.from_file(f))
    assert dev.collection_method == "file" and dev.os_version is None and dev.collection_warnings == []
    assert dev.management.snmp.communities == ["X****2 (RO)"]
    dump = dev.model_dump_json()
    for secret in ("Xyzzy-Comm-42", "$2y$10$abcdefghij", "VerySecretPSK123"):
        assert secret not in dump
    assert "&lt;redacted&gt;" in dev.raw_config


def test_tolerant():
    drv = PfSenseDriver()
    dev = drv.parse(RawCollection(driver="pfsense", target="x", method="ssh", outputs={}))
    assert dev.hostname == "x" and dev.collection_warnings
    dev = drv.parse(RawCollection(driver="pfsense", target="y", method="file",
                                  outputs={"config": "<pfsense><system><hostname>h</hostname></system>"
                                                     "<filter><rule><bogus/></rule></filter></pfsense>"}))
    assert dev.hostname == "h" and len(dev.firewall_rules) == 1 and dev.firewall_rules[0].action == "allow"
