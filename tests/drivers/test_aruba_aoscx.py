from tests.drivers._switch import finding_ids, iface, load, load_file


def test_identity_and_vsx():
    d = load("aruba_aoscx")
    assert d.hostname == "sto-agg-sw01" and d.os_version == "GL.10.13.1005" and d.serial == "SG9ZKM4012"
    assert d.ha.mode == "vsx" and d.ha.state == "in-sync"
    assert d.spanning_tree.mode == "mstp"


def test_l2():
    d = load("aruba_aoscx")
    assert len(d.interfaces) == 66 and len(d.vlans) == 6 and len(d.neighbors) == 7
    assert iface(d, "lag1").trunk_vlans == "10,20,30,40,99"
    assert iface(d, "1/1/47").access_vlan == 30
    assert next(v for v in d.vlans if v.id == 10).svi_ipv4 == ["10.20.10.2/24"]


def test_findings_and_file():
    assert {"mgmt.no-syslog", "snmp.v2c"} <= finding_ids(load("aruba_aoscx"))
    assert load_file("aruba_aoscx").hostname == "sto-agg-sw01"
