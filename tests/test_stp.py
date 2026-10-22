"""Spanning tree: runtime parsers per vendor, trees per VLAN group, findings and the diagram."""

import re
import shutil
from pathlib import Path

import pytest

from sextant.analysis import analyze
from sextant.builders.asbuilt import build_asbuilt
from sextant.drivers._stp import norm_mac, parse_aoscx, parse_cisco, parse_junos, parse_procurve
from sextant.model import Snapshot
from sextant.pipeline import import_many
from sextant.render.stp_diagram import stp_svg
from sextant.stp import build_stp
from sextant.theme import load_theme
from sextant.topology import build_topology

CAMPUS = Path(__file__).resolve().parent.parent / "examples" / "campus"

# Same layout as a Catalyst 3560-CX running rapid-PVST (addresses invented)
CISCO = """\
sw1#show spanning-tree

VLAN0001
  Spanning tree enabled protocol rstp
  Root ID    Priority    4096
             Address     0011.2233.4401
             Cost        3
             Port        456 (Port-channel1)
             Hello Time   2 sec  Max Age 20 sec  Forward Delay 15 sec

  Bridge ID  Priority    32769  (priority 32768 sys-id-ext 1)
             Address     0011.2233.4499
             Hello Time   2 sec  Max Age 20 sec  Forward Delay 15 sec
             Aging Time  300 sec

Interface           Role Sts Cost      Prio.Nbr Type
------------------- ---- --- --------- -------- --------------------------------
Po1                 Root FWD 3         128.456  P2p
Po2                 Altn BLK 3         128.464  P2p
Gi1/0/3             Desg BKN*4         128.3    P2p *PVID_Inc


VLAN0035
  Spanning tree enabled protocol rstp
  Root ID    Priority    32803
             Address     0011.2233.4499
             This bridge is the root
             Hello Time   2 sec  Max Age 20 sec  Forward Delay 15 sec

  Bridge ID  Priority    32803  (priority 32768 sys-id-ext 35)
             Address     0011.2233.4499
             Hello Time   2 sec  Max Age 20 sec  Forward Delay 15 sec
             Aging Time  300 sec

Interface           Role Sts Cost      Prio.Nbr Type
------------------- ---- --- --------- -------- --------------------------------
Po1                 Desg FWD 3         128.456  P2p
Gi1/0/2             Desg FWD 4         128.2    P2p Edge
"""

CISCO_MST = """\
MST0
  Spanning tree enabled protocol mstp
  Root ID    Priority    4096
             Address     0011.2233.4401
             Cost        0
             Port        25 (TenGigabitEthernet1/1/1)

  Bridge ID  Priority    32768  (priority 32768 sys-id-ext 0)
             Address     0011.2233.44aa
Vlans mapped:   1-4094

Interface           Role Sts Cost      Prio.Nbr Type
------------------- ---- --- --------- -------- --------------------------------
Te1/1/1             Root FWD 2000      128.25   P2p
Te1/1/2             Altn BLK 2000      128.26   P2p
"""

PROCURVE = """\
 Multiple Spanning Trees (MST) Information

  STP Enabled   : Yes
  Force Version : MSTP-operation
  IST Mapped VLANs : 1-4094
  Switch MAC Address : 001122-3344bb
  Switch Priority    : 32768

  CST Root MAC Address : 001122-334401
  CST Root Priority    : 4096
  CST Root Path Cost   : 20000
  CST Root Port        : Trk1

  Port  Type      | Cost      Prio Role       State      Designated Bridge
                  |           rity
  ----- --------- + --------- ---- ---------- ---------- -----------------
  1     100/1000T | Auto      128  Disabled   Disabled
  7     100/1000T | 20000     128  Alternate  Blocking   001122-334402
  Trk1            | 20000     64   Root       Forwarding 001122-334401
"""

AOSCX = """\
Spanning tree status              : Enabled Protocol: MSTP
MST0
  Root ID    Priority   : 4096
             MAC-Address: 00:11:22:33:44:01
             Hello time(in seconds):2  Max Age(in seconds):20

  Bridge ID  Priority   : 32768
             MAC-Address: 00:11:22:33:44:cc

Port         Role           State      Cost    Priority   Type
------------ -------------- ---------- ------- ---------- ----------
1/1/1        Designated     Forwarding 20000   128        P2P Edge
lag1         Root           Forwarding 2000    64         P2P
lag2         Alternate      Blocking   2000    64         P2P
"""

JUNOS_BRIDGE = """\
STP bridge parameters
Routing instance name               : GLOBAL
Enabled protocol                    : RSTP
  Root ID                           : 4096.00:11:22:33:44:01
  Root cost                         : 20000
  Root port                         : ge-0/0/47
  Local parameters
    Bridge ID                       : 32768.00:11:22:33:44:dd
"""

JUNOS_IF = """\
Spanning tree interface parameters for instance 0

Interface    Port ID    Designated      Designated         Port    State  Role
                         port ID        bridge ID          Cost
ge-0/0/0     128:1      128:1   32768.001122334400     20000   FWD    DESG
ge-0/0/47    128:48     128:12  4096.001122334401      20000   FWD    ROOT
ge-0/0/46    128:47     128:11  8192.001122334402      20000   BLK    ALT
"""


def test_norm_mac():
    assert norm_mac("00:11:22:33:44:AA") == norm_mac("001122-3344aa") == "0011.2233.44aa"
    assert norm_mac("garbage") is None


def test_parse_cisco_pvst():
    insts, mac = parse_cisco(CISCO)
    assert mac == "0011.2233.4499" and [i.name for i in insts] == ["VLAN0001", "VLAN0035"]
    v1, v35 = insts
    assert v1.vlans == [1] and v1.root_mac == "0011.2233.4401" and v1.root_priority == 4096
    assert v1.root_port == "Port-channel1" and v1.root_cost == 3 and not v1.is_root
    ports = {p.interface: (p.role, p.state) for p in v1.ports}
    assert ports == {"Po1": ("root", "forwarding"), "Po2": ("alternate", "blocking"),
                     "Gi1/0/3": ("designated", "broken")}
    assert v35.is_root and v35.root_port is None and v35.bridge_priority == 32803


def test_parse_cisco_mst():
    (inst,), mac = parse_cisco(CISCO_MST)
    assert inst.name == "MST0" and inst.vlans[:2] == [1, 2] and len(inst.vlans) == 4094
    assert inst.root_port == "TenGigabitEthernet1/1/1" and mac == "0011.2233.44aa"


def test_parse_procurve():
    (inst,), mac = parse_procurve(PROCURVE)
    assert mac == "0011.2233.44bb" and inst.protocol == "mstp" and len(inst.vlans) == 4094
    assert inst.root_mac == "0011.2233.4401" and inst.root_priority == 4096 and inst.root_port == "Trk1"
    ports = {p.interface: (p.role, p.state) for p in inst.ports}
    assert ports["7"] == ("alternate", "blocking") and ports["Trk1"] == ("root", "forwarding")
    assert parse_procurve("") == ([], None)


def test_parse_aoscx():
    (inst,), mac = parse_aoscx(AOSCX)
    assert inst.protocol == "mstp" and mac == "0011.2233.44cc" and inst.root_mac == "0011.2233.4401"
    assert inst.root_port == "lag1" and not inst.is_root
    assert [(p.interface, p.role) for p in inst.ports if p.state == "blocking"] == [("lag2", "alternate")]


def test_parse_junos():
    (inst,), mac = parse_junos(JUNOS_BRIDGE, JUNOS_IF)
    assert inst.protocol == "rstp" and mac == "0011.2233.44dd" and inst.root_priority == 4096
    assert inst.root_port == "ge-0/0/47" and inst.root_cost == 20000
    assert {p.interface: p.role for p in inst.ports} == {"ge-0/0/0": "designated", "ge-0/0/47": "root",
                                                         "ge-0/0/46": "alternate"}


# --------------------------------------------------------------------------- campus: two buildings


def _load(path: Path):
    devices, errors = import_many([path])
    assert errors == []
    snap = analyze(Snapshot(devices=devices))
    topo = build_topology(snap)
    return snap, topo, build_stp(snap, topo)


@pytest.fixture(scope="module")
def campus():
    return _load(CAMPUS)


def _tree(sites, topo, root, vlan):
    for site in sites:
        for t in site.trees:
            if t.root_node == root and vlan in t.vlans:
                return site, t
    raise AssertionError(f"no tree rooted at {root} for VLAN {vlan}")


def test_session_logs_merge_into_the_config(campus):
    snap, _, _ = campus
    sw = next(d for d in snap.devices if d.hostname == "kis-acc-sw01")
    assert sw.spanning_tree.mode == "rapid-pvst" and len(sw.spanning_tree.instances) == 5
    assert sw.spanning_tree.instances[0].root_port == "TenGigabitEthernet1/1/1"


def test_one_layer2_domain_per_building(campus):
    _, topo, sites = campus
    assert len(sites) == 2  # the cores route between the buildings, so they do not join the domains
    assert all(not any("core" in k for k in s.keys) for s in sites)


def test_building_a_tree(campus):
    _, topo, sites = campus
    site, t = _tree(sites, topo, "kis-dist-sw01", 10)
    assert t.vlans == [10, 20, 30, 40, 99] and not t.root_inferred
    blocked = {(st.blocked_at, st.blocked_port) for st in t.links.values() if st.state == "blocked"}
    assert blocked == {(f"kis-acc-sw{i:02d}", "Te1/1/2") for i in range(1, 8)}
    assert t.parent["kis-dist-sw02"] == "kis-dist-sw01" and t.root_ports["kis-dist-sw02"] == "Po1"
    assert "kis-dist-sw01" in site.prediction


def test_building_b_planted_faults(campus):
    _, topo, sites = campus
    _, t = _tree(sites, topo, "kis-dist-sw03", 10)
    assert t.vlans == [10, 20, 30, 40, 99]  # VLAN 40 is pruned from one trunk: same tree, partial link
    states = {frozenset(k): st for k, st in t.links.items()}
    sw12 = states[frozenset({"kis-acc-sw12", "kis-dist-sw03"})]
    assert sw12.state == "blocked" and sw12.blocked_port == "Te1/1/1"  # PVID inconsistent
    assert t.root_ports["kis-acc-sw12"] == "Te1/1/2"
    assert states[frozenset({"kis-acc-sw09", "kis-dist-sw04"})].state == "absent"  # shut uplink
    assert states[frozenset({"kis-acc-sw14", "kis-dist-sw04"})].vlans == [10, 20, 30, 99]
    assert [p for p, st in states.items() if st.vlans] == [frozenset({"kis-acc-sw14", "kis-dist-sw04"})]


def test_no_stp_findings_on_a_designed_campus(campus):
    snap, _, _ = campus
    ids = {f.check_id for d in snap.devices for f in d.findings}
    assert not ids & {"stp.mixed-modes", "stp.default-priority-root", "stp.root-on-access", "stp.root-disagreement"}


def test_stp_findings(tmp_path):
    """Building A without root priorities, one MST switch and one switch that sees another root."""
    for f in CAMPUS.iterdir():
        shutil.copy(f, tmp_path / f.name)
    building_a = [f"kis-acc-sw{i:02d}" for i in range(1, 8)] + ["kis-dist-sw01", "kis-dist-sw02"]
    for host in building_a:
        log = tmp_path / f"{host}-stp.log"
        text = re.sub(r"(Root ID    Priority    )(\d+)", lambda m: m.group(1) + str(int(m.group(2)) + 28672),
                      log.read_text())
        if host == "kis-acc-sw05":
            text = text.replace("Address     70b3.17aa.0100", "Address     70b3.17aa.0f00")
        log.write_text(text)
    cfg = tmp_path / "kis-acc-sw03.cfg"
    cfg.write_text(cfg.read_text().replace("spanning-tree mode rapid-pvst", "spanning-tree mode mst"))
    snap, _, _ = _load(tmp_path)
    by = {d.hostname: {f.check_id for f in d.findings} for d in snap.devices}
    assert "stp.default-priority-root" in by["kis-acc-sw01"] and "stp.default-priority-root" in by["kis-dist-sw01"]
    assert "stp.mixed-modes" in by["kis-acc-sw03"] and "stp.mixed-modes" in by["kis-dist-sw02"]
    assert "stp.mixed-modes" not in by["kis-acc-sw10"]  # other building, one mode
    assert "stp.root-disagreement" in by["kis-acc-sw05"]


def test_diagram_and_document(campus):
    snap, topo, sites = campus
    site, t = _tree(sites, topo, "kis-dist-sw03", 10)
    svg, ratio = stp_svg(topo, site.keys, t, load_theme(None), "Building B")
    assert svg.startswith("<svg") and 0.2 < ratio < 1.5
    assert "ROOT BRIDGE AND PEERS" in svg and "BLK Te1/1/1" in svg and "RP Po1" in svg
    assert "prio 4096 · rapid-pvst" in svg and "prio 8192" in svg and "prio 32768" in svg  # per box
    assert svg.count('stroke-dasharray="7 5"') == 6 + 1  # six blocked links + the legend
    doc = build_asbuilt(snap)
    from sextant.doc import Diagram, Heading
    titles = [re.sub(r"^[\d.]+ ", "", b.text) for b in doc.blocks if isinstance(b, Heading)]
    assert "Spanning tree" in titles and "VLANs 10,20,30,40,99: root kis-dist-sw03" in titles
    assert sum(1 for b in doc.blocks if isinstance(b, Diagram) and b.stp is not None) == 2
    from sextant.doc import Table
    partial = [b for b in doc.blocks if isinstance(b, Table) and b.title == "Trunks carrying some of these VLANs"]
    assert [r for b in partial for r in b.rows] == [["kis-acc-sw14", "kis-dist-sw04", "10,20,30,99"]]


# --------------------------------------------------------------------------- AOS-S 16.x and MST/PVST boundaries

PROCURVE_16 = """\
 Multiple Spanning Tree (MST) Information

  STP Enabled   : Yes
  Force Version : MSTP-operation
  IST Mapped VLANs : 1-4094
  Switch MAC Address : 0011aa-000002
  Switch Priority    : 4096

  CST Root MAC Address : 0011aa-000001
  CST Root Priority    : 1
  CST Root Path Cost   : 20000
  CST Root Port        : Trk1

                   |           Prio              | Designated    Hello
  Port  Type       | Cost      rity State        | Bridge        Time PtP Edge
  ----- ---------- + --------- ---- ------------ + ------------- ---- --- ----
  1     100/1000T  | 200000    128  Forwarding   | 0011aa-000002 2    Yes Yes
  2     100/1000T  | Auto      128  Disabled     |               2    Yes No
  5     100/1000T  | 20000     128  Forwarding   | 0011aa-000002 2    Yes No
  6     100/1000T  | 20000     128  Blocking     | 0011aa-000009 2    Yes No
  Trk1             | 20000     64   Forwarding   | 0011aa-000001 2    Yes No
"""

PROCURVE_LLDP = """\
 LLDP Remote Devices Information

  LocalPort | ChassisId          PortId             PortDescr SysName
  --------- + ------------------ ------------------ --------- ------------------
  5         | lab-acc-3560.ex... GigabitEthernet...           cisco WS-C3560C...
  5         | 00 11 aa 00 00 05  Gi1/0/14           Uplink... lab-acc-3560...
  6         | lab-garage-2960... GigabitEthernet0/8           cisco WS-C2960C...
  7         | 00 11 aa 00 00 07  00 11 aa 00 00 07  bond0     ap-hall
"""


def test_procurve_16_stp_without_role_column():
    (inst,), mac = parse_procurve(PROCURVE_16)
    assert mac == "0011.aa00.0002" and inst.root_mac == "0011.aa00.0001" and inst.root_port == "Trk1"
    roles = {p.interface: (p.role, p.state) for p in inst.ports}
    assert roles == {"1": ("designated", "forwarding"), "2": ("disabled", "disabled"),
                     "5": ("designated", "forwarding"), "6": ("alternate", "blocking"),
                     "Trk1": ("root", "forwarding")}


def test_procurve_lldp_table_with_cdp_rows():
    """AOS-S shows CDP neighbours in the LLDP table: device ID under ChassisId, platform under SysName."""
    from sextant.drivers import RawCollection
    from sextant.pipeline import parse_raw

    cfg = 'hostname "lab-core-2530"\nvlan 1\n   name "DEFAULT_VLAN"\n   exit\n'
    d = parse_raw(RawCollection(driver="hp_procurve", target="x", method="file",
                                outputs={"show running-config": cfg, "show lldp info remote-device": PROCURVE_LLDP}))
    got = [(n.local_port, n.remote_device, n.remote_port, n.remote_platform) for n in d.neighbors]
    assert got == [("5", "lab-acc-3560.ex", "Gi1/0/14", "cisco WS-C3560C"),  # LLDP + CDP rows merged
                   ("6", "lab-garage-2960", "GigabitEthernet0/8", "cisco WS-C2960C"),  # CDP only
                   ("7", "ap-hall", "00 11 aa 00 00 07", None)]


def test_mst_region_between_pvst_switches():
    """A PVST root seen through an MST switch: same bridge, different priority (the region reports the
    root with its VLAN 1 priority). One tree; VLANs the MST switch does not tag on a port are not on it."""
    from sextant.model import (
        Device,
        DeviceRole,
        Interface,
        Neighbor,
        PortMode,
        SpanningTree,
        StpInstance,
        StpPort,
        Vlan,
    )

    def pvst(vlan, root, me, rp=None, ports=()):
        return StpInstance(name=f"VLAN{vlan:04d}", vlans=[vlan], root_mac=root, root_priority=vlan,
                           is_root=root == me, root_port=rp, bridge_mac=me, bridge_priority=32768 + vlan,
                           ports=[StpPort(interface=p, role=r, state="forwarding") for p, r in ports])

    core_mac, mst_mac, acc_mac = "0011.aa00.0001", "0011.aa00.0002", "0011.aa00.0003"
    core = Device(hostname="core", role=DeviceRole.switch, vlans=[Vlan(id=1), Vlan(id=10), Vlan(id=20)],
                  interfaces=[Interface(name="Port-channel1", kind="lag", mode=PortMode.trunk, trunk_vlans="all"),
                              Interface(name="GigabitEthernet1/0/13", mode=PortMode.trunk, lag="Port-channel1")],
                  neighbors=[Neighbor(local_port="GigabitEthernet1/0/13", remote_device="mst", remote_port="9")],
                  spanning_tree=SpanningTree(mode="rapid-pvst", bridge_mac=core_mac, configured_priority={"1-4094": 0},
                                             instances=[pvst(v, core_mac, core_mac, ports=[("Po1", "designated")])
                                                        for v in (1, 10, 20)]))
    mst = Device(hostname="mst", role=DeviceRole.switch, vlans=[Vlan(id=1), Vlan(id=10), Vlan(id=20)],
                 interfaces=[Interface(name="Trk1", kind="lag", mode=PortMode.trunk, native_vlan=5, trunk_vlans="10,20"),
                             Interface(name="9", mode=PortMode.unknown, lag="Trk1"),
                             Interface(name="5", mode=PortMode.trunk, native_vlan=5, trunk_vlans="1,10")],
                 neighbors=[Neighbor(local_port="9", remote_device="core", remote_port="Gi1/0/13"),
                            Neighbor(local_port="5", remote_device="acc", remote_port="Gi1/0/1")],
                 spanning_tree=SpanningTree(mode="mstp", bridge_mac=mst_mac, configured_priority={"1-4094": 4096},
                                            instances=[StpInstance(
                                                name="IST", vlans=list(range(1, 4095)), root_mac=core_mac,
                                                root_priority=1, root_port="Trk1", bridge_mac=mst_mac,
                                                ports=[StpPort(interface="Trk1", role="root", state="forwarding"),
                                                       StpPort(interface="5", role="designated", state="forwarding")])]))
    acc = Device(hostname="acc", role=DeviceRole.switch, vlans=[Vlan(id=1), Vlan(id=10), Vlan(id=20)],
                 interfaces=[Interface(name="GigabitEthernet1/0/1", mode=PortMode.trunk, trunk_vlans="all")],
                 neighbors=[Neighbor(local_port="GigabitEthernet1/0/1", remote_device="mst", remote_port="5")],
                 spanning_tree=SpanningTree(mode="rapid-pvst", bridge_mac=acc_mac,
                                            instances=[pvst(1, core_mac, acc_mac, "GigabitEthernet1/0/1",
                                                            [("Gi1/0/1", "root")]),
                                                       pvst(10, core_mac, acc_mac, "GigabitEthernet1/0/1",
                                                            [("Gi1/0/1", "root")]),
                                                       pvst(20, acc_mac, acc_mac, None, [("Gi1/0/1", "designated")])]))
    snap = analyze(Snapshot(devices=[core, mst, acc]))
    topo = build_topology(snap)
    (site,) = build_stp(snap, topo)
    live = [t for t in site.trees if not t.trivial]
    assert len(live) == 1 and live[0].root_node == "core" and live[0].vlans == [1, 10, 20]
    assert set(live[0].reporters) == {"core", "mst", "acc"}
    states = {frozenset(p): st for p, st in live[0].links.items()}
    assert states[frozenset({"core", "mst"})].vlans == [10, 20]  # VLAN 1 is not on Trk1
    assert states[frozenset({"mst", "acc"})].vlans == [1, 10]  # VLAN 20 is not on port 5
    local = [t for t in site.trees if t.trivial]
    assert [(t.vlans, t.root_node) for t in local] == [([20], "acc")]  # isolated on acc: its own root
    ids = {f.check_id for d in snap.devices for f in d.findings}
    assert "stp.root-disagreement" not in ids and "stp.mixed-modes" in ids
