from tests.drivers._switch import finding_ids, iface, load, load_file


def test_identity():
    d = load("hp_procurve")
    assert d.hostname == "sto-acc-sw02" and d.os_version == "WC.16.11.0012" and d.mgmt_ip == "10.20.99.12"


def test_vlan_port_lists():
    d = load("hp_procurve")
    assert len(d.interfaces) == 53 and len(d.vlans) == 6 and len(d.neighbors) == 6
    assert iface(d, "1").access_vlan == 10
    assert iface(d, "41").native_vlan == 99 and iface(d, "41").trunk_vlans == "40"
    assert iface(d, "Trk1").lag_members == ["49", "50"]


def test_insecure_defaults_flagged():
    found = finding_ids(load("hp_procurve"))
    assert {"mgmt.telnet", "snmp.default-community", "mgmt.http"} <= found
    assert load_file("hp_procurve").hostname == "sto-acc-sw02"
