from hsdoc.drivers.cisco_ios import cisco_auth
from hsdoc.model import DeviceRole
from tests.drivers._switch import assert_no_secrets, finding_ids, iface, load, load_file


def test_identity():
    d = load("cisco_ios")
    assert (d.hostname, d.model, d.os_version, d.serial) == ("sto-dist-sw01", "C9300-24P", "17.09.04a", "FOC2418L0AB")
    assert d.role == DeviceRole.switch and d.mgmt_ip == "10.10.99.4"
    assert d.ha.mode == "stack" and d.ha.state == "ready"


def test_layer2():
    d = load("cisco_ios")
    assert len(d.interfaces) == 76 and len(d.vlans) == 9 and len(d.neighbors) == 9
    po = iface(d, "Port-channel1")
    assert po.trunk_vlans == "10,20,30,40,50,60,99,100" and po.native_vlan == 999
    assert po.lag_members == ["TenGigabitEthernet1/1/1", "TenGigabitEthernet2/1/1"] and po.lag_protocol == "lacp"
    gi = iface(d, "GigabitEthernet1/0/1")
    assert gi.access_vlan == 10 and gi.stp_edge is True
    assert next(v for v in d.vlans if v.id == 10).svi_ipv4 == ["10.10.10.1/24"]
    assert d.spanning_tree.mode == "rapid-pvst"


def test_management_and_routing():
    d = load("cisco_ios")
    users = {u.name: u.auth for u in d.management.users}
    assert users["netadmin"] == "secret type 9 (scrypt)" and users["netops"] == "password type 7 (reversible)"
    assert d.management.ntp_servers == ["10.10.100.5", "10.10.100.6"]
    assert d.management.snmp.communities[0].startswith("<redacted>")
    assert [p.protocol for p in d.routing_protocols] == ["ospf"] and len(d.routes) == 22 and len(d.acls) == 3


def test_findings():
    assert {"mgmt.weak-password-hash", "mgmt.http", "snmp.v2c", "l2.native-vlan1"} <= finding_ids(load("cisco_ios"))


def test_file_import_matches():
    d = load_file("cisco_ios")
    assert d.hostname == "sto-dist-sw01" and len(d.interfaces) == 76 and len(d.vlans) == 9


def test_auth_type_survives_double_redaction():
    assert cisco_auth("username a secret 9 <redacted>") == "secret type 9 (scrypt)"


def test_no_plaintext_secrets():
    from hsdoc.drivers import RawCollection
    from hsdoc.pipeline import parse_raw

    raw = RawCollection(driver="cisco_ios", target="t", method="file", outputs={"config": (
        "hostname t\nenable secret 9 $9$LeakMe\nusername x privilege 15 password 7 0822455D0A16\n"
        "snmp-server community Sup3rS3cret RO\n")})
    assert_no_secrets(parse_raw(raw), "$9$LeakMe", "0822455D0A16", "Sup3rS3cret")
