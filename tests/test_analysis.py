from datetime import date

from sextant.analysis import analyze_device
from sextant.analysis.lifecycle import end_of_support
from sextant.model import (
    Datastore,
    Device,
    FirewallRule,
    HighAvailability,
    Interface,
    LocalUser,
    Management,
    SnmpConfig,
    Virtualization,
    VirtualMachine,
    VpnTunnel,
)


def ids(device):
    return {f.check_id for f in analyze_device(device)}


def test_management_checks():
    d = Device(hostname="sw", role="switch", management=Management(
        telnet=True, ssh=True, snmp=SnmpConfig(enabled=True, versions=["v2c"], communities=["public (RO)"]),
        users=[LocalUser(name="old", auth="password type 7")]))
    found = ids(d)
    assert {"mgmt.telnet", "snmp.default-community", "mgmt.no-ntp", "mgmt.no-syslog", "aaa.none",
            "mgmt.weak-password-hash", "mgmt.no-vty-acl"} <= found


def test_unknown_is_not_a_finding():
    d = Device(hostname="srv", role="server", management=Management(ntp_servers=["a", "b"], syslog_servers=["s"]))
    assert ids(d) == set()


def test_native_vlan1():
    d = Device(hostname="sw", role="switch", interfaces=[Interface(name="Te1/1/1", mode="trunk", native_vlan=1)])
    assert "l2.native-vlan1" in ids(d)


def test_firewall_checks():
    rules = [
        FirewallRule(id="1", action="allow", src_addresses=["all"], dst_addresses=["all"], services=["ALL"], log=True),
        FirewallRule(id="2", action="allow", src_addresses=["10.0.0.0/24"], dst_addresses=["any"],
                     services=["HTTPS"], log=False),
        FirewallRule(id="3", action="deny", enabled=False),
    ]
    d = Device(hostname="fw", role="firewall", firewall_rules=rules,
               vpn_tunnels=[VpnTunnel(name="branch", phase1="3des-sha1, dh2", phase2="aes128-sha1")],
               ha=HighAvailability(mode="active-passive", state="out-of-sync"))
    found = ids(d)
    assert {"fw.any-any", "fw.no-logging", "fw.disabled-rules", "fw.shadowed", "vpn.weak-crypto",
            "ha.not-in-sync"} <= found


def test_virtualization_checks():
    v = Virtualization(platform="vmware",
                       vms=[VirtualMachine(name="a", power_state="on", oldest_snapshot_days=40,
                                           tools_status="toolsNotRunning")],
                       datastores=[Datastore(name="ds", capacity_gb=1000, free_gb=50)])
    found = ids(Device(hostname="vc", role="hypervisor", virtualization=v))
    assert {"virt.old-snapshots", "virt.tools", "virt.datastore-full"} <= found


def test_end_of_support():
    d = Device(hostname="fw", platform="fortigate", os_version="6.4.15")
    assert [f.check_id for f in end_of_support(d, today=date(2026, 10, 15))] == ["lifecycle.eos"]
    d.os_version = "7.4.5"
    assert list(end_of_support(d, today=date(2026, 10, 15))) == []


def test_end_of_support_zero_padded_ios_xe():
    """IOS-XE 'show version' pads: 17.06.05 is the 17.6 train."""
    d = Device(hostname="ie", platform="cisco_ios", os_version="17.06.05")
    assert [f.check_id for f in end_of_support(d, today=date(2026, 12, 1))] == ["lifecycle.eos"]
    d.os_version = "17.09.05"
    assert list(end_of_support(d, today=date(2026, 12, 1))) == []


def test_legacy_pvst():
    from sextant.model import SpanningTree

    d = Device(hostname="old", role="switch", spanning_tree=SpanningTree(mode="pvst"))
    assert "stp.legacy" in ids(d)
    d.spanning_tree.mode = "rapid-pvst"
    assert "stp.legacy" not in ids(d)


def test_merge_keeps_collection_date():
    from datetime import UTC, datetime

    from sextant.model import Snapshot
    from sextant.pipeline import merge

    a = Snapshot(created_at=datetime(2026, 1, 1, tzinfo=UTC))
    b = Snapshot(created_at=datetime(2026, 2, 1, tzinfo=UTC))
    assert merge([a, b]).created_at == datetime(2026, 2, 1, tzinfo=UTC)


def test_link_checks_on_lag_links():
    """CDP names the member ports; the trunk settings sit on the port-channel."""
    from sextant.analysis import analyze
    from sextant.model import Neighbor, PortMode, Snapshot

    def sw(name, peer, native):
        return Device(hostname=name, role="switch", interfaces=[
            Interface(name="Port-channel1", kind="lag", mode=PortMode.trunk, native_vlan=native, trunk_vlans="all"),
            Interface(name="GigabitEthernet1/0/1", mode=PortMode.lag_member, lag="Port-channel1"),
            Interface(name="GigabitEthernet1/0/2", mode=PortMode.lag_member, lag="Port-channel1")],
            neighbors=[Neighbor(local_port=f"GigabitEthernet1/0/{i}", remote_device=peer,
                                remote_port=f"GigabitEthernet1/0/{i}", protocol="cdp") for i in (1, 2)])

    snap = analyze(Snapshot(devices=[sw("a", "b", 1), sw("b", "a", 999)]))
    found = [f for d in snap.devices for f in d.findings if f.check_id == "link.native-mismatch"]
    assert len(found) == 2 and "Po1" in found[0].title  # one per end, reported on the bundle


def test_per_port_bpdu_guard_counts():
    from sextant.model import PortMode, SpanningTree

    ports = [Interface(name=f"GigabitEthernet1/0/{i}", mode=PortMode.access, access_vlan=10, stp_edge=True,
                       extra={"bpduguard": "enabled"}) for i in range(1, 9)]
    d = Device(hostname="sw", role="switch", interfaces=ports,
               spanning_tree=SpanningTree(mode="rapid-pvst", bpdu_guard_default=False))
    assert "stp.no-bpduguard" not in ids(d)
    ports[0].extra = {}
    assert "stp.no-bpduguard" in ids(d)


def test_snmp_collected_device_has_no_ntp_findings():
    d = Device(hostname="ups", role="other", collection_method="snmp")
    assert not {"mgmt.no-ntp", "mgmt.no-syslog"} & ids(d)


def test_all_tagged_trunk_is_not_native_vlan_1():
    """AOS-S/Junos trunks without an untagged VLAN: no native VLAN, so a Cisco end with native 1 mismatches,
    and two all-tagged ends agree."""
    from sextant.analysis import analyze
    from sextant.model import Neighbor, PortMode, Snapshot
    from sextant.stp import _iface_carries

    def sw(name, peer, native):
        return Device(hostname=name, role="switch", interfaces=[
            Interface(name="GigabitEthernet1/0/1", mode=PortMode.trunk, native_vlan=native, trunk_vlans="10,20")],
            neighbors=[Neighbor(local_port="GigabitEthernet1/0/1", remote_device=peer, remote_port="Gi1/0/1")])

    tagged = Interface(name="x", mode=PortMode.trunk, native_vlan=0, trunk_vlans="10,20")
    assert tagged.native() is None and not _iface_carries(tagged, 1) and _iface_carries(tagged, 10)
    snap = analyze(Snapshot(devices=[sw("a", "b", 0), sw("b", "a", None)]))
    (f,) = [f for f in snap.devices[0].findings if f.check_id == "link.native-mismatch"]
    assert "(none vs 1)" in f.title
    snap = analyze(Snapshot(devices=[sw("a", "b", 0), sw("b", "a", 0)]))
    assert not any(f.check_id == "link.native-mismatch" for d in snap.devices for f in d.findings)
