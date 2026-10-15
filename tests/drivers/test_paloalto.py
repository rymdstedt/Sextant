import json
from pathlib import Path

import pytest

from sextant.drivers import get_driver
from sextant.drivers.base import RawCollection
from sextant.drivers.paloalto import PaloAltoDriver

EX = Path(__file__).resolve().parents[2] / "examples" / "paloalto"


@pytest.fixture(scope="module")
def dev():
    return PaloAltoDriver().parse(RawCollection(**json.loads((EX / "raw.json").read_text())))


def test_registered():
    assert get_driver("paloalto").methods == ("api", "file")


def test_identity(dev):
    assert dev.hostname == "gbg-fw01" and dev.model == "PA-440"
    assert dev.os_name == "PAN-OS" and dev.os_version == "11.1.2-h3"
    assert dev.serial == "024101012345" and dev.mgmt_ip == "10.30.0.2"
    assert dev.role.value == "firewall" and dev.platform == "paloalto" and dev.collection_method == "api"
    assert dev.collection_warnings == []


def test_management(dev):
    mg = dev.management
    assert mg.https and mg.ssh and not mg.http and not mg.telnet
    assert mg.ntp_servers == ["10.30.10.10", "se.pool.ntp.org"]
    assert mg.dns_servers == ["10.30.10.10", "10.10.20.10"] and mg.timezone == "Europe/Stockholm"
    assert mg.banner.startswith("Authorized access only")
    assert mg.syslog_servers == ["10.30.10.50:514/udp (SIEM)"]
    assert mg.snmp.versions == ["v2c"] and "public (RO)" in mg.snmp.communities
    assert mg.aaa.radius_servers == ["10.10.20.10 (NPS)"]
    users = {u.name: u for u in mg.users}
    assert users["admin"].privilege == "superuser" and users["admin"].auth == "password"
    assert users["netops"].auth == "auth-profile AP-RADIUS"
    assert users["ansible"].privilege == "custom: automation-ro" and users["ansible"].auth == "ssh-key"


def test_interfaces(dev):
    by = {i.name: i for i in dev.interfaces}
    assert by["ethernet1/1"].zone == "untrust" and by["ethernet1/1"].ipv4[0].address == "198.51.100.20/29"
    sub = by["ethernet1/2.20"]
    assert sub.kind == "vlan" and sub.access_vlan == 20 and sub.zone == "trust"
    assert by["ae1"].kind == "lag" and by["ae1"].lag_members == ["ethernet1/4", "ethernet1/5"]
    assert by["ethernet1/4"].lag == "ae1"
    assert by["ethernet1/8"].enabled is False
    assert by["tunnel.1"].zone == "vpn-sto"
    assert [v.id for v in dev.vlans] == [10, 20, 30]


def test_rules(dev):
    rules = dev.firewall_rules
    assert len(rules) == 10
    r = rules[0]
    assert (r.name, r.action, r.log) == ("users-internet", "allow", True)
    assert r.src_zones == ["trust"] and r.dst_zones == ["untrust"]
    assert r.applications == ["web-browsing", "ssl", "dns"] and r.services == ["application-default"]
    assert r.security_profiles == ["group:PG-STRICT"]
    by = {x.name: x for x in rules}
    assert by["vpn-sto"].log is False
    assert by["temp-allow-all"].enabled is False and by["temp-allow-all"].src_addresses == ["any"]
    assert by["block-quarantine"].action == "drop"
    assert by["guest-to-internal-deny"].action == "reject"
    assert by["users-servers"].users == ["corp\\gbg-staff"]
    assert by["nas-backup"].schedule == "nightly-backup"


def test_nat(dev):
    nat = {n.comment.split(":")[0]: n for n in dev.nat_rules}
    assert nat["outbound-pat"].kind == "pat" and nat["outbound-pat"].interface == "ethernet1/1"
    assert nat["intranet-dnat"].kind == "dnat" and nat["intranet-dnat"].translated == "dst -> H-GBG-WEB01:443"
    assert nat["no-nat-vpn"].kind == "no-nat"


def test_objects_vpn_routes(dev):
    objs = {o.name: o for o in dev.address_objects}
    assert objs["H-GBG-WEB01"].kind == "host" and objs["H-GBG-WEB01"].value == "10.30.50.10"
    assert objs["R-PRINTERS"].kind == "range" and objs["GRP-INTERNAL"].kind == "group"
    t = dev.vpn_tunnels[0]
    assert t.name == "IPSEC-STO" and t.peer == "203.0.113.10" and t.ike_version == "IKEv2"
    assert t.phase1 == "aes-256-cbc-sha256, dh14, 28800s" and t.phase2 == "aes-256-cbc-sha256, dh14, 3600s"
    assert t.local_subnets == ["10.30.0.0/16"] and t.remote_subnets == ["10.10.0.0/16"] and t.psk_set
    assert dev.routes[0].prefix == "0.0.0.0/0" and dev.routes[0].next_hop == "198.51.100.17"
    assert dev.routing_protocols[0].asn == "65030"
    assert dev.dhcp_scopes[0].rows[0][1:4] == ["10.30.20.0/24", "10.30.20.100-10.30.20.240", "10.30.20.1"]


def test_ha(dev):
    ha = dev.ha
    assert ha.mode == "active-passive" and ha.state == "active" and ha.group == "3"
    assert ha.details["sync"] == "in-sync" and len(ha.members) == 2


def test_sections(dev):
    ids = {s.id for s in dev.sections}
    assert {"paloalto-zones", "paloalto-zone-protection", "paloalto-security-profiles"} <= ids
    zones = next(s for s in dev.sections if s.id == "paloalto-zones").tables[0].rows
    assert ["untrust", "layer3", "ethernet1/1", "zp-internet", "no", ""] in zones


def test_file_import_masks_secrets(tmp_path):
    xml = (EX / "running-config.xml").read_text().replace(
        "<snmp-community-string>public</snmp-community-string>",
        "<snmp-community-string>N0tPubl1cComm</snmp-community-string>").replace(
        "<key>&lt;redacted&gt;</key>", "<key>-AQ==S3cr3tPskValue==</key>")
    f = tmp_path / "running-config.xml"
    f.write_text(xml)
    drv = PaloAltoDriver()
    dev = drv.parse(drv.from_file(f))
    assert dev.hostname == "gbg-fw01" and dev.os_version == "11.1.2" and dev.collection_warnings == []
    assert dev.management.snmp.communities[0] == "N****m (RO)"
    dump = dev.model_dump_json()
    assert "N0tPubl1cComm" not in dump and "S3cr3tPsk" not in dump


def test_tolerant_and_dtd_refused():
    bomb = '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "aaaa">]><config>&a;</config>'
    dev = PaloAltoDriver().parse(RawCollection(driver="paloalto", target="x", method="file",
                                               outputs={"config": bomb}))
    assert dev.hostname == "x" and any("DTD" in w for w in dev.collection_warnings)
    dev = PaloAltoDriver().parse(RawCollection(driver="paloalto", target="y", method="api", outputs={}))
    assert dev.hostname == "y" and dev.collection_warnings
