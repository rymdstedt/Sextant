import json
from pathlib import Path

import pytest

from hsdoc.drivers import get_driver
from hsdoc.drivers.base import RawCollection
from hsdoc.drivers.pfsense import OPNsenseDriver

EX = Path(__file__).resolve().parents[2] / "examples" / "opnsense"


@pytest.fixture(scope="module")
def dev():
    return OPNsenseDriver().parse(RawCollection(**json.loads((EX / "raw.json").read_text())))


def test_registered():
    assert get_driver("opnsense").methods == ("file", "ssh")


def test_identity_and_management(dev):
    assert dev.hostname == "lab-fw01" and dev.os_name == "OPNsense" and dev.os_version == "24.7.6"
    assert dev.platform == "opnsense" and dev.vendor == "Deciso" and dev.collection_warnings == []
    mg = dev.management
    assert mg.http is True and mg.https is False and mg.ssh is True  # HTTP-only web GUI
    assert mg.syslog_servers == ["10.60.0.60:514/udp4"]
    assert mg.snmp.enabled and mg.snmp.communities == ["<redacted> (RO)"]
    assert mg.snmp.v3_users == ["librenms (authPriv)"] and "v3" in mg.snmp.versions
    users = {u.name: u for u in mg.users}
    assert users["labadmin"].auth == "password, ssh-key, TOTP" and users["labadmin"].privilege == "admin (admins)"
    assert "disabled" in users["olduser"].auth


def test_interfaces(dev):
    by = {i.name: i for i in dev.interfaces}
    assert by["vtnet0"].extra["addressing"] == "dhcp" and by["vtnet0"].zone == "WAN"
    lan = by["vtnet1"]
    assert lan.ipv4[0].address == "10.60.0.2/24" and lan.ipv4[0].vrrp_vip == "10.60.0.1"
    assert by["vtnet1_vlan40"].access_vlan == 40 and by["vtnet1_vlan40"].zone == "IOT"
    assert [v.id for v in dev.vlans] == [40]


def test_rules_and_nat(dev):
    assert len(dev.firewall_rules) == 7
    by = {r.comment: r for r in dev.firewall_rules}
    assert by["IoT to MQTT brokers"].enabled is False
    assert by["IoT may not reach LAN"].action == "drop" and by["IoT may not reach LAN"].log is True
    mvc = by["Lab to HQ jump hosts (automation rule)"]
    assert mvc.dst_addresses == ["HQ_NETS"] and mvc.services == ["tcp/22"] and mvc.src_addresses == ["LAN net"]
    rdr = next(n for n in dev.nat_rules if n.kind == "dnat")
    assert rdr.original == "any -> WAN address:8443 (tcp)" and rdr.translated == "10.60.50.20:443"


def test_vpn_ha_dhcp(dev):
    t = {v.name: v for v in dev.vpn_tunnels}
    s = t["lab-to-sto"]
    assert s.phase1 == "aes256-sha256, dh14, 14400s" and s.phase2 == "aes256gcm16, dh14, 3600s"
    assert s.ike_version == "IKEv2" and s.peer == "203.0.113.10" and s.psk_set
    assert s.local_subnets == ["10.60.0.0/16"] and s.remote_subnets == ["10.10.0.0/16"]
    assert t["wg-lab"].kind == "wireguard" and t["wg-lab"].remote_subnets == ["10.60.251.10/32"]
    assert dev.ha.mode == "carp" and dev.ha.state == "primary (advskew 0)"
    assert "10.60.255.2" in dev.ha.details["synchronizetoip"]
    assert dev.dhcp_scopes[0].rows[1][0] == "IOT"
    objs = {o.name: o for o in dev.address_objects}
    assert objs["MQTT_BROKERS"].value == "10.60.50.30, 10.60.50.31"


def test_no_secrets(dev):
    assert "&lt;redacted&gt;" in dev.raw_config
    xml = (EX / "config.xml").read_text().replace("<community>&lt;redacted&gt;</community>",
                                                  "<community>labComm99x</community>")
    raw = RawCollection(driver="opnsense", target="lab", method="file", outputs={"config": xml})
    d = OPNsenseDriver().parse(raw)
    assert d.management.snmp.communities == ["l****x (RO)"]
    assert "labComm99x" not in d.model_dump_json()
