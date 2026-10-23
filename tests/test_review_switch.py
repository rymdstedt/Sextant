"""Regression tests for the switch-driver review findings (invented hostnames, IPs and MACs)."""

from sextant.drivers import RawCollection, get_driver
from sextant.drivers._stp import parse_cisco, parse_junos
from sextant.drivers.base import expand_command
from sextant.drivers.cisco_ios import IOS_COMMANDS, cisco_auth
from sextant.drivers.hp_procurve import expand_ports
from sextant.drivers.juniper_junos import JUNOS_COMMANDS, braces_to_set
from sextant.model import PortMode


def parse(driver: str, **outputs: str):
    raw = RawCollection(driver=driver, target="lab", method="file", outputs=outputs)
    return get_driver(driver).parse(raw)


def iface(d, name):
    return next(i for i in d.interfaces if i.name == name)


# ---------------------------------------------------------------- 1. session-log modifiers


def test_no_more_and_junos_config_mode_show():
    junos = tuple(JUNOS_COMMANDS)
    assert expand_command("show configuration | display set | no-more", junos) == "show configuration | display set"
    assert expand_command("sh conf | disp set | no-more", junos) == "show configuration | display set"
    assert expand_command("show | display set", junos) == "show configuration | display set"
    assert expand_command("show | display set | no-more", junos) == "show configuration | display set"
    assert expand_command("show running-config | no-more", ("show running-config",)) == "show running-config"
    assert expand_command("show configuration | no-more | display set", junos) == "show configuration | display set"


def test_junos_session_log_with_no_more(tmp_path):
    log = tmp_path / "lab-ex.log"
    log.write_text("ops@lab-ex01> show configuration | display set | no-more\n"
                   "set system host-name lab-ex01\nset vlans V10 vlan-id 10\n"
                   "ops@lab-ex01> show version | no-more\nHostname: lab-ex01\nModel: ex2300-24t\nJunos: 22.4R1.10\n"
                   "ops@lab-ex01> ")
    drv = get_driver("juniper_junos")
    d = drv.parse(drv.from_file(log))
    assert d.hostname == "lab-ex01" and d.model == "ex2300-24t" and [v.id for v in d.vlans] == [10]


def test_nxos_session_log_with_no_more(tmp_path):
    log = tmp_path / "lab-nx.log"
    log.write_text("lab-nx01# show running-config | no-more\nhostname lab-nx01\nvlan 20\n  name SRV\n"
                   "lab-nx01# ")
    drv = get_driver("cisco_nxos")
    d = drv.parse(drv.from_file(log))
    assert d.hostname == "lab-nx01" and 20 in [v.id for v in d.vlans]


# ---------------------------------------------------------------- 2./10. ProCurve


def test_procurve_port_ranges():
    assert expand_ports("Trk1-Trk3") == ["Trk1", "Trk2", "Trk3"]
    assert expand_ports("trk1-trk2") == ["Trk1", "Trk2"]
    assert expand_ports("1/A1-1/A3,2/1-2/2") == ["1/A1", "1/A2", "1/A3", "2/1", "2/2"]
    assert expand_ports("1-3,A1-A2") == ["1", "2", "3", "A1", "A2"]


def test_procurve_rpvst_mode_and_vlan_priorities():
    cfg = ("hostname \"lab-2930\"\nspanning-tree\nspanning-tree mode rapid-pvst\nspanning-tree priority 2\n"
           "spanning-tree vlan 10 priority 4\nspanning-tree vlan 20,30 priority 1\n"
           "vlan 10\n   name \"TEN\"\n   untagged 1-2\n   exit\n")
    st = parse("hp_procurve", config=cfg).spanning_tree
    assert st.mode == "rapid-pvst"
    assert st.configured_priority == {"10": 16384, "20,30": 4096, "default": 8192}
    assert list(st.configured_priority)[-1] == "default"  # VLAN keys first (stp._configured takes the first hit)
    mst = parse("hp_procurve", config="spanning-tree\nspanning-tree priority 1\n").spanning_tree
    assert mst.mode == "mstp" and mst.configured_priority == {"1-4094": 4096}


# ---------------------------------------------------------------- 3./8./9./11./12./14. IOS


def test_ios_inventory_empty_serial():
    inv = ('NAME: "1", DESCR: "WS-C2960X-48FPD-L"\nPID: WS-C2960X-48FPD-L , VID: V05  , SN: FOC0000X1AB\n\n'
           'NAME: "GigabitEthernet1/0/49", DESCR: "1000BaseSX SFP"\nPID: GLC-SX-MMD          , VID: V01  , SN: \n\n'
           'NAME: "Power Supply 1", DESCR: "FRU Power Supply"\nPID: PWR-C1-350WAC , VID: V02  , SN: DCB0000Y2CD\n')
    d = parse("cisco_ios", **{"show inventory": inv, "config": "hostname lab-sw01\n"})
    rows = next(s for s in d.sections if s.id == "inventory").tables[0].rows
    assert [r[0] for r in rows] == ["1", "GigabitEthernet1/0/49", "Power Supply 1"]
    assert rows[1][3] == "" and rows[2][3] == "DCB0000Y2CD"


_SW_DETAIL_15 = """Switch/Stack Mac Address : 0200.0000.1100
                                           H/W   Current
Switch#  Role   Mac Address     Priority Version  State
----------------------------------------------------------
*1       Master 0200.0000.1100     15     4       Ready
 2       Member 0200.0000.1180     14     4       Ready

         Stack Port Status             Neighbors
Switch#  Port 1     Port 2           Port 1   Port 2
--------------------------------------------------------
  1        Ok         Ok                2        2
  2        Ok         Ok                1        1
"""

_VER_2960X = """Cisco IOS Software, C2960X Software (C2960X-UNIVERSALK9-M), Version 15.2(7)E4, RELEASE SOFTWARE (fc2)
lab-sw01 uptime is 10 weeks, 2 days
Switch Ports Model                     SW Version            SW Image
------ ----- -----                     ----------            ----------
*    1 52    WS-C2960X-48FPD-L         15.2(7)E4             C2960X-UNIVERSALK9-M
     2 52    WS-C2960X-48FPD-L         15.2(7)E4             C2960X-UNIVERSALK9-M
"""


def test_ios_classic_stack():
    d = parse("cisco_ios", **{"show switch detail": _SW_DETAIL_15, "show version": _VER_2960X,
                              "config": "hostname lab-sw01\n"})
    assert d.ha.mode == "stack" and d.ha.state == "ready" and len(d.ha.members) == 2
    assert "Master" in d.ha.members[0]
    assert d.ha.details["stack ring"].startswith("full ring")
    hw = {f.key: f.value for f in d.hardware}
    assert hw["Switch 1"] == "WS-C2960X-48FPD-L, 52 ports, 15.2(7)E4" and "Switch 2" in hw
    down = parse("cisco_ios", **{"show switch detail": _SW_DETAIL_15.replace("  2        Ok         Ok ",
                                                                              "  2        Down       Ok "),
                                 "config": "hostname lab-sw01\n"})
    assert down.ha.details["stack ring"].startswith("degraded")


def test_ios_old_banner_version():
    ver = ("Cisco Internetwork Operating System Software \n"
           "IOS (tm) C2950 Software (C2950-I6Q4L2-M), Version 12.1(22)EA14, RELEASE SOFTWARE (fc1)\n"
           "lab-old01 uptime is 3 years, 2 weeks\ncisco WS-C2950T-24 (RC32300) processor (revision R0)\n")
    d = parse("cisco_ios", **{"show version": ver, "config": "hostname lab-old01\n"})
    assert d.os_version == "12.1(22)EA14" and d.model == "WS-C2950T-24"


def test_ios_enable_secret_levels():
    assert cisco_auth("enable secret level 5 5 $1$abcd$EXAMPLEHASHxx") == "secret type 5 (MD5)"
    cfg = ("hostname lab-sw01\nenable secret 9 $9$EXAMPLE$EXAMPLEHASH\n"
           "enable secret level 5 5 $1$abcd$EXAMPLEHASHxx\n")
    users = {u.name: u for u in parse("cisco_ios", config=cfg).management.users}
    assert users["enable"].auth == "secret type 9 (scrypt)" and users["enable"].privilege == "15"
    assert users["enable level 5"].auth == "secret type 5 (MD5)" and users["enable level 5"].privilege == "5"
    assert not any("type 0" in (u.auth or "") for u in users.values())


def test_ios_mst0_priority_sets_default():
    cfg = "hostname lab-sw01\nspanning-tree mode mst\nspanning-tree mst 0-1 priority 4096\n"
    st = parse("cisco_ios", config=cfg).spanning_tree
    assert st.configured_priority == {"mst 0-1": 4096, "default": 4096}
    st2 = parse("cisco_ios", config="hostname x\nspanning-tree mode mst\nspanning-tree mst 2 priority 8192\n").spanning_tree
    assert "default" not in st2.configured_priority


def test_ios_xe_vrrpv3():
    cfg = ("hostname lab-sw01\ninterface Vlan10\n ip address 10.0.10.2 255.255.255.0\n"
           " vrrp 10 address-family ipv4\n  address 10.0.10.1 primary\n  priority 110\n"
           " vrrp 11 address-family ipv6\n  address FE80::1 primary\n")
    d = parse("cisco_ios", config=cfg)
    rows = next(s for s in d.sections if s.id == "fhrp").tables[0].rows
    assert rows == [["Vlan10", "VRRP", "10", "10.0.10.1"]]
    assert iface(d, "Vlan10").ipv4[0].vrrp_vip == "10.0.10.1"


def test_ios_archive_path_credentials_stripped():
    cfg = "hostname lab-sw01\narchive\n path scp://backup:S3cr3tPw@192.0.2.50/configs/$h-$t\n write-memory\n"
    mg = parse("cisco_ios", config=cfg).management
    assert mg.backup_target == "scp://192.0.2.50/configs/$h-$t"


# ---------------------------------------------------------------- 4. NX-OS vPC


_VPC = """vPC domain id                     : 10
Peer status                       : peer adjacency formed ok
vPC keep-alive status             : peer is alive
Configuration consistency status  : success

vPC Peer-link status
---------------------------------------------------------------------
id    Port   Status Active vlans
--    ----   ------ -------------------------------------------------
1     Po1    up     1,10,20

vPC status
----------------------------------------------------------------------------
Id    Port          Status Consistency Reason                Active vlans
--    ------------  ------ ----------- ------                ---------------
10    Po10          up     success     success               10,20
20    Po20          down*  failed      Consistency Check Not -
                                       Performed
"""


def test_nxos_vpc_down_row():
    d = parse("cisco_nxos", **{"show vpc": _VPC, "config": "hostname lab-nx01\nfeature vpc\nvpc domain 10\n"})
    assert d.ha.mode == "vpc" and d.ha.state == "degraded" and d.ha.details["vPCs down"] == "Po20"
    rows = next(s for s in d.sections if s.id == "vpc").tables[0].rows
    assert rows == [["10", "Po10", "up", "success", "success", "10,20"],
                    ["20", "Po20", "down*", "failed", "Consistency Check Not Performed", "-"]]
    ok = parse("cisco_nxos", **{"show vpc": _VPC.split("20    Po20")[0], "config": "hostname lab-nx01\n"})
    assert ok.ha.state == "ok"


# ---------------------------------------------------------------- 5./6./7. Junos


_JUNOS = """set system host-name lab-ex01
set vlans V10 vlan-id 10
set vlans V99 vlan-id 99
set interfaces ge-0/0/1 unit 0 family ethernet-switching interface-mode trunk
set interfaces ge-0/0/1 unit 0 family ethernet-switching vlan members 100-102
set interfaces ge-0/0/1 unit 0 family ethernet-switching vlan members V10
set interfaces ge-0/0/2 unit 0 family ethernet-switching port-mode trunk
set interfaces ge-0/0/2 unit 0 family ethernet-switching vlan members V10
set interfaces ge-0/0/2 unit 0 family ethernet-switching native-vlan-id 99
set interfaces ge-0/0/3 unit 0 family ethernet-switching port-mode trunk
set interfaces ge-0/0/3 unit 0 family ethernet-switching vlan members V10
set interfaces ge-0/0/3 unit 0 family ethernet-switching native-vlan-id V99
set interfaces interface-range EDGE member "ge-0/0/[10-12]"
set interfaces interface-range EDGE unit 0 family ethernet-switching vlan members V10
set interfaces ge-0/0/5 description "spare"
set interfaces ge-0/0/5 unit 0 family ethernet-switching vlan members V10
deactivate interfaces ge-0/0/5
set interfaces ge-0/0/20 ether-options 802.3ad ae1
set interfaces ge-0/0/21 ether-options 802.3ad ae1
set interfaces ae1 unit 0 family ethernet-switching interface-mode trunk
set interfaces ae1 unit 0 family ethernet-switching vlan members V10
set protocols rstp interface all edge
deactivate protocols rstp
set protocols lldp interface all
"""


def test_junos_vlan_ranges_native_and_wildcards():
    d = parse("juniper_junos", **{"show configuration | display set": _JUNOS})
    assert iface(d, "ge-0/0/1").trunk_vlans == "10,100-102"
    assert iface(d, "ge-0/0/1").extra["native vlan"] == "none (all tagged)"
    assert iface(d, "ge-0/0/2").native_vlan == 99 and iface(d, "ge-0/0/3").native_vlan == 99
    assert "native vlan" not in iface(d, "ge-0/0/2").extra
    for n in ("ge-0/0/10", "ge-0/0/11", "ge-0/0/12"):
        assert iface(d, n).access_vlan == 10
    assert not any("[" in i.name for i in d.interfaces)


def test_junos_deactivate_and_static_lag():
    d = parse("juniper_junos", **{"show configuration | display set": _JUNOS})
    sp = iface(d, "ge-0/0/5")
    assert sp.enabled is False and sp.description is None and sp.extra["config"] == "deactivated (inactive)"
    assert d.spanning_tree.mode == "disabled"
    assert any(s.id == "junos-inactive" for s in d.sections)
    ae = iface(d, "ae1")
    assert ae.lag_protocol == "static" and iface(d, "ge-0/0/20").lag_protocol == "static"
    braces = "interfaces {\n    inactive: ge-0/0/7 {\n        description x;\n    }\n}\n"
    assert "deactivate interfaces ge-0/0/7" in braces_to_set(braces)


def test_junos_member_range_wildcard():
    cfg = 'set interfaces interface-range R member "ge-[0-1]/0/[1,3]"\nset interfaces interface-range R disable\n'
    d = parse("juniper_junos", **{"show configuration | display set": cfg})
    assert sorted(i.name for i in d.interfaces) == ["ge-0/0/1", "ge-0/0/3", "ge-1/0/1", "ge-1/0/3"]


def test_junos_route_table_reset():
    table = """inet.0: 2 destinations, 2 routes (2 active, 0 holddown, 0 hidden)
+ = Active Route, - = Last Active, * = Both

10.0.10.0/24       *[Direct/0] 1w0d 01:00:00
                    >  via irb.10

inet6.0: 1 destinations, 1 routes (1 active, 0 holddown, 0 hidden)
+ = Active Route, - = Last Active, * = Both

2001:db8:10::/64   *[Direct/0] 1w0d 01:00:00
                    >  via irb.10
"""
    d = parse("juniper_junos", **{"show route": table, "show configuration | display set": "set system host-name x\n"})
    assert [(r.prefix, r.interface) for r in d.routes] == [("10.0.10.0/24", "irb.10")]


def test_junos_lldp_wide_port():
    text = """Local Interface    Parent Interface    Chassis Id          Port info          System Name
ge-0/0/47          -                   02:00:00:aa:bb:01   GigabitEthernet1/0/49 lab-core-01
ge-0/0/46          -                   02:00:00:aa:bb:02   eth0               lab-ap-01
"""
    d = parse("juniper_junos", **{"show lldp neighbors": text})
    nb = {n.local_port: n for n in d.neighbors}
    assert (nb["ge-0/0/47"].remote_device, nb["ge-0/0/47"].remote_port) == ("lab-core-01", "GigabitEthernet1/0/49")
    assert nb["ge-0/0/47"].remote_chassis == "02:00:00:aa:bb:01"
    assert (nb["ge-0/0/46"].remote_device, nb["ge-0/0/46"].remote_port) == ("lab-ap-01", "eth0")


# ---------------------------------------------------------------- 13. consistency


def test_aoscx_speed_and_static_lag():
    cfg = ("hostname lab-cx01\ninterface lag 1\n    no shutdown\n    vlan trunk allowed 10\n"
           "interface 1/1/1\n    no shutdown\n    lag 1\ninterface 1/1/2\n    no shutdown\n    lag 1\n"
           "interface lag 2\n    no shutdown\n    lacp mode active\ninterface 1/1/3\n    lag 2\n"
           "interface 1/1/10\n    no shutdown\n    vlan access 10\n")
    brief = """Port      Native  Mode   Type           Enabled Status  Reason                  Speed   Description
          VLAN                                                                  (Mb/s)
1/1/10    10      access 1GbT           yes     up                              1000    --
1/1/1     --      --     SFP+DAC3       yes     up                              10000   --
"""
    d = parse("aruba_aoscx", **{"show running-config": cfg, "show interface brief": brief})
    assert iface(d, "1/1/10").speed == "1000" and iface(d, "1/1/1").speed == "10G"
    assert iface(d, "lag1").lag_protocol == "static" and iface(d, "1/1/1").lag_protocol == "static"
    assert iface(d, "lag2").lag_protocol == "lacp" and iface(d, "1/1/3").lag_protocol == "lacp"
    assert iface(d, "1/1/10").mode == PortMode.access


def test_aoscx_rpvst_vlan_priority_beats_global():
    cfg = "hostname lab-cx01\nspanning-tree\nspanning-tree mode rpvst\nspanning-tree vlan 10 priority 1\n"
    st = parse("aruba_aoscx", **{"show running-config": cfg}).spanning_tree
    assert st.configured_priority == {"10": 4096, "default": 32768}


def test_stp_role_mappings():
    junos_if = ("Spanning tree interface parameters for instance 0\n\n"
                "Interface    Port ID    Designated      Designated         Port    State  Role\n"
                "                         port ID        bridge ID          Cost\n"
                "ge-0/0/1     128:513      128:513  32768.020000000001     20000  DIS    DIS\n")
    inst, _ = parse_junos("", junos_if)
    assert inst[0].ports[0].role == "disabled"
    cisco = ("MST0\n  Spanning tree enabled protocol mstp\n"
             "Interface           Role Sts Cost      Prio.Nbr Type\n"
             "------------------- ---- --- --------- -------- --------------------------------\n"
             "Gi1/0/1             Bound FWD 20000     128.1    P2p Bound(RSTP)\n")
    inst, _ = parse_cisco(cisco)
    assert inst[0].ports[0].role == "boundary"


def test_ios_commands_still_expand():
    assert expand_command("sh run", tuple(IOS_COMMANDS)) == "show running-config"
