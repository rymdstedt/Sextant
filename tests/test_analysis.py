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
