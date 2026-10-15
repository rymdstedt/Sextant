from tests.drivers._switch import finding_ids, iface, load, load_file


def test_identity_and_vc():
    d = load("juniper_junos")
    assert (d.hostname, d.model, d.os_version) == ("sto-acc-sw03", "ex3400-24p", "21.4R3-S5.4")
    assert d.ha.mode == "virtual-chassis"


def test_display_set_parsing():
    d = load("juniper_junos")
    assert len(d.vlans) == 6 and len(d.neighbors) == 5
    assert iface(d, "ge-0/0/0").access_vlan == 10
    assert iface(d, "ge-0/0/22").native_vlan == 99
    assert iface(d, "ae0").lag_members == ["xe-0/2/0", "xe-1/2/0"]
    users = {u.name: u.auth for u in d.management.users}
    assert users["automation"] == "ssh-key (ed25519)" and "hashed" in users["root"]


def test_findings_and_file():
    assert "mgmt.no-syslog" in finding_ids(load("juniper_junos"))
    assert load_file("juniper_junos").hostname == "sto-acc-sw03"
