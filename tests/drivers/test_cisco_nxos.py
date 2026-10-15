from tests.drivers._switch import finding_ids, iface, load, load_file


def test_identity_and_vpc():
    d = load("cisco_nxos")
    assert (d.hostname, d.model, d.os_version) == ("sto-core-sw01", "N9K-C93180YC-FX", "10.3(4a)")
    assert d.ha.mode == "vpc" and d.ha.state == "ok"


def test_interfaces_and_vlans():
    d = load("cisco_nxos")
    assert len(d.interfaces) == 63 and len(d.vlans) == 11 and len(d.neighbors) == 9
    po = iface(d, "port-channel1")
    assert po.trunk_vlans == "1-4094" and po.lag_members == ["Ethernet1/52", "Ethernet1/54"]
    assert iface(d, "Ethernet1/3").access_vlan == 100


def test_users_not_flagged_weak():
    d = load("cisco_nxos")
    assert all("SHA-256" in u.auth for u in d.management.users)
    assert "mgmt.weak-password-hash" not in finding_ids(d)
    assert "l2.native-vlan1" in finding_ids(d)


def test_file_import():
    d = load_file("cisco_nxos")
    assert d.hostname == "sto-core-sw01" and len(d.interfaces) == 63
