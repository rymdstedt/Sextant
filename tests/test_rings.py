"""Ring protocols on Cisco Industrial Ethernet switches (MRP, REP), and switches with spanning tree off."""

from sextant.analysis import analyze, analyze_device
from sextant.doc import Cell
from sextant.drivers._ring import parse_cisco_rings
from sextant.drivers.base import RawCollection
from sextant.drivers.cisco_ios import CiscoIosDriver
from sextant.model import Snapshot

IE_CONFIG = """\
hostname ie-03
spanning-tree mode rapid-pvst
vlan 50
 name CELL-A
mrp ring 1
 mode client
 profile 200
 port 1 interface GigabitEthernet1/1
 port 2 interface GigabitEthernet1/2
!
interface GigabitEthernet1/1
 switchport mode trunk
!
interface GigabitEthernet1/2
 switchport mode trunk
!
interface GigabitEthernet1/3
 switchport access vlan 50
 switchport mode access
!
end
"""

SHOW_MRP = """\
MRP ring 1

Profile     : 200 ms
Mode        : Client
Priority    : 0xA000
Operational Mode: Client
From        : CLI
License     : Active

Network Topology: Ring
Network Status  : OPEN

Port1:                                Port2:
 MAC Address  :70:1F:53:00:00:03       MAC Address  :70:1F:53:00:00:04
 Interface    :GigabitEthernet1/1     Interface    :GigabitEthernet1/2
 Status       :Forwarding             Status       :Not Connected
VLAN ID     : 1
"""


def test_mrp_block_form_and_runtime():
    (r,) = parse_cisco_rings(IE_CONFIG, SHOW_MRP)
    assert (r.label, r.role, r.vlan, r.state) == ("MRP ring 1", "client", 1, "open")
    assert r.ports == ["GigabitEthernet1/1", "GigabitEthernet1/2"] and r.details["profile"] == "200 ms"
    assert r.port_states == {"GigabitEthernet1/1": "forwarding", "GigabitEthernet1/2": "not connected"}


def test_interface_forms_mrp_rep():
    cfg = ("mrp ring 2 manager\n"
           "interface GigabitEthernet1/1\n mrp ring 2\ninterface GigabitEthernet1/2\n mrp ring 2\n"
           "interface GigabitEthernet1/5\n rep segment 10 edge primary\n"
           "interface GigabitEthernet1/6\n rep segment 10\n")
    rep_show = ("REP Segment 10\nBridgeName       PortName   Edge Role\n---------------- ---------- ---- ----\n"
                "ie-01            Gi1/5      Pri  Alt\nie-02            Gi1/1           Open\n")
    mrp, rep = parse_cisco_rings(cfg, "", rep_show)
    assert (mrp.label, mrp.role, mrp.ports) == ("MRP ring 2", "manager", ["GigabitEthernet1/1", "GigabitEthernet1/2"])
    assert (rep.label, rep.role, rep.state) == ("REP segment 10", "edge (primary)", "complete")
    assert rep.ports == ["GigabitEthernet1/5", "GigabitEthernet1/6"]


def _parse(outputs):
    return CiscoIosDriver().parse(RawCollection(driver="cisco_ios", target="ie-03", method="file", outputs=outputs))


def test_driver_reads_rings_and_ignores_errors():
    d = _parse({"show running-config": IE_CONFIG, "show mrp ring": SHOW_MRP,
                "show rep topology": "% Invalid input detected at '^' marker."})
    (r,) = d.rings
    assert r.state == "open" and r.role == "client"
    (dev,) = analyze(Snapshot(devices=[d])).devices
    assert any(f.check_id == "ring.open" and f.title == "MRP ring 1 is open" for f in dev.findings)


def test_spanning_tree_off():
    off = IE_CONFIG.replace("spanning-tree mode rapid-pvst\n", "spanning-tree mode rapid-pvst\nno spanning-tree vlan 1-4094\n")
    d = _parse({"show running-config": off})
    st = d.spanning_tree
    assert st.mode == "disabled" and st.details["configured mode"] == "rapid-pvst" and 50 in st.disabled_vlans
    d = _parse({"show running-config": IE_CONFIG, "show spanning-tree": "No spanning tree instance exists.\n"})
    assert d.spanning_tree.mode == "disabled"
    (f,) = [f for f in analyze_device(d) if f.check_id == "stp.disabled"]
    assert f.severity.value == "medium" and "MRP ring 1" in f.title


# --------------------------------------------------------------------------- real IE3100 output (KS506 site)

N006_MRP = """\
MRP ring 1

Mode            : Client
From            : CLI
License         : Not Applicable
Gateway         :
 Status         : Disabled
Best Manager    :
 MAC Address    : Unknown
 Priority       : Unknown

Network Topology: Ring
Network Status  : Unknown
Port1:                                  Port2:
 MAC Address    :08:F4:F0:0B:3B:42       MAC Address    :08:F4:F0:0B:3B:41
 Interface      :Gi1/2                   Interface      :Gi1/1
 Status         :Forwarding              Status         :Forwarding

VLAN ID     : 554
Domain Name : Cisco MRP Ring 1
Domain ID   : FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF

Link Down Timer Interval        : 20 ms
Link Up Timer Interval          : 20 ms
Link Change (Up or Down) count  :  4 ms
MRP ring 2 not configured
MRP ring 3 not configured
"""

N006_STP = """\

MST0
  Spanning tree enabled protocol mstp
  Root ID    Priority    32768
             Address     08f4.f00b.3b40
             This bridge is the root
             Hello Time   2 sec  Max Age 20 sec  Forward Delay 15 sec

  Bridge ID  Priority    32768  (priority 32768 sys-id-ext 0)
             Address     08f4.f00b.3b40
             Hello Time   2 sec  Max Age 20 sec  Forward Delay 15 sec

Interface           Role Sts Cost      Prio.Nbr Type
------------------- ---- --- --------- -------- --------------------------------
Gi1/1               Desg FWD 20000     128.1    P2p Edge
Gi1/2               Desg FWD 20000     128.2    P2p Edge
Ap1/1               Desg FWD 20000     128.7    P2p Edge
Po1                 Desg FWD 10000     128.32   P2p Bound(PVST)

"""

N002_STP = """\

MST0
  Spanning tree enabled protocol mstp
  Root ID    Priority    32768
             Address     a033.4f5e.fc80
             This bridge is the root
             Hello Time   2 sec  Max Age 20 sec  Forward Delay 15 sec

  Bridge ID  Priority    32768  (priority 32768 sys-id-ext 0)
             Address     a033.4f5e.fc80
             Hello Time   2 sec  Max Age 20 sec  Forward Delay 15 sec

Interface           Role Sts Cost      Prio.Nbr Type
------------------- ---- --- --------- -------- --------------------------------
Gi1/1               Desg FWD 20000     128.1    P2p Edge
Gi1/2               Desg FWD 20000     128.2    P2p Edge
Gi1/5               Desg FWD 20000     128.5    P2p Edge
Ap1/1               Desg FWD 20000     128.13   P2p Edge

"""


N001_MRP = """\
MRP ring 1

Profile         : 200 ms
Mode            : Auto-Manager
Priority        : 36864
Operational Mode: Manager
From            : CLI
License         : Not Applicable
Gateway         :
 Status         : Disabled
Best Manager    :
 MAC Address    : A0:33:4F:88:4B:A3
 Priority       : 36864

Network Topology: Ring
Network Status  : CLOSED
Port1:                                  Port2:
 MAC Address    :A0:33:4F:88:4B:A3       MAC Address    :A0:33:4F:88:4B:A4
 Interface      :GigabitEthernet1/3     Interface      :GigabitEthernet1/4
 Status         :Forwarding             Status         :Blocked

VLAN ID     : 554
Domain Name : Cisco MRP Ring 1
Domain ID   : FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF

Topology Change Request Interval        : 10ms
Topology Change Repeat Count            : 3
Short Test Frame Interval               : 10ms
Default Test Frame Interval             : 20ms
Operational Test Frame Interval         : 20ms
Test Monitoring Interval Count          : 3
Test Monitoring Extended Interval Count : N/A
MRP ring 2 not configured
MRP ring 3 not configured
"""

N001_STP = """\

MST0
  Spanning tree enabled protocol mstp
  Root ID    Priority    32768
             Address     a033.4f88.4ba0
             This bridge is the root
             Hello Time   2 sec  Max Age 20 sec  Forward Delay 15 sec

  Bridge ID  Priority    32768  (priority 32768 sys-id-ext 0)
             Address     a033.4f88.4ba0
             Hello Time   2 sec  Max Age 20 sec  Forward Delay 15 sec

Interface           Role Sts Cost      Prio.Nbr Type
------------------- ---- --- --------- -------- --------------------------------
Gi1/3               Desg FWD 20000     128.3    P2p Edge
Gi1/4               Desg FWD 20000     128.4    P2p Edge
Gi1/5               Desg FWD 200000    128.5    P2p Edge
Gi1/6               Desg FWD 200000    128.6    P2p Edge
Gi1/7               Desg FWD 200000    128.7    P2p Edge
Gi1/8               Desg FWD 200000    128.8    P2p Edge
Gi1/9               Desg FWD 200000    128.9    P2p Edge
Gi1/12              Desg FWD 20000     128.12   P2p Edge
Ap1/1               Desg FWD 20000     128.13   P2p Edge

"""


def test_mrp_auto_manager_operating_as_manager():
    """Auto-Manager configured, Manager in operation; the Gateway and Best Manager blocks are not the ports."""
    (r,) = parse_cisco_rings("", N001_MRP)
    assert (r.role, r.state, r.vlan) == ("manager", "closed", 1 + 553)
    assert r.details == {"configured mode": "auto-manager", "priority": "36864", "profile": "200 ms"}
    assert r.port_states == {"GigabitEthernet1/3": "forwarding", "GigabitEthernet1/4": "blocking"}


def _cdp(entries):
    return "".join(f"-------------------------\nDevice ID: {dev}\nEntry address(es):\n  IP address: 10.55.4.{i}\n"
                   f"Platform: cisco IE-3100-8T2C,  Capabilities: Switch IGMP\n"
                   f"Interface: {mine},  Port ID (outgoing port): {theirs}\nHoldtime : 150 sec\n\n"
                   for i, (mine, dev, theirs) in enumerate(entries, start=1))


def _ie_config(host, extra=""):
    return (f"hostname {host}\nspanning-tree mode mst\nvlan 554\n name MRP\nvlan 600\n name CELL\n"
            "interface GigabitEthernet1/1\n switchport mode trunk\ninterface GigabitEthernet1/2\n switchport mode trunk\n"
            "interface GigabitEthernet1/5\n switchport access vlan 600\n switchport mode access\n" + extra + "end\n")


def test_ie3100_ring_from_session_logs(tmp_path):
    """Two IE3100s in MRP ring 1 (clients; the manager was not captured), both reporting themselves as MST
    root because no BPDUs cross the ring. N006 also has Po1 to a rapid-PVST distribution switch."""
    from sextant.builders.asbuilt import build_asbuilt
    from sextant.doc import Callout, Table
    from sextant.pipeline import import_many
    from sextant.stp import build_stp
    from sextant.topology import build_topology

    n006_cfg = _ie_config("KS506-NV03-N006", "interface GigabitEthernet1/3\n channel-group 1 mode active\n"
                                             "interface Port-channel1\n switchport mode trunk\n")
    # the ring: N001 Gi1/3 - N002 Gi1/1, N002 Gi1/2 - N006 Gi1/1, N006 Gi1/2 - N001 Gi1/4 (N001 is the manager)
    logs = {
        "KS506-NV03-N001": [("show running-config", _ie_config("KS506-NV03-N001")), ("show mrp ring", N001_MRP),
                            ("show spann", N001_STP),
                            ("sh cdp nei det", _cdp([("GigabitEthernet1/3", "KS506-NV03-N002", "GigabitEthernet1/1"),
                                                     ("GigabitEthernet1/4", "KS506-NV03-N006", "GigabitEthernet1/2")]))],
        "KS506-NV03-N006": [("show running-config", n006_cfg), ("show mrp ring", N006_MRP), ("show spann", N006_STP),
                            ("sh cdp nei det", _cdp([("GigabitEthernet1/1", "KS506-NV03-N002", "GigabitEthernet1/2"),
                                                     ("GigabitEthernet1/3", "KS506-DIST", "GigabitEthernet1/0/1")]))],
        "KS506-NV03-N002": [("show running-config", _ie_config("KS506-NV03-N002")),
                            ("show mrp ring", N006_MRP.replace("Gi1/2 ", "Gi1/1 ", 1).replace(":Gi1/1\n", ":Gi1/2\n")),
                            ("show spann", N002_STP)],
        "KS506-DIST": [("show running-config", "hostname KS506-DIST\nspanning-tree mode rapid-pvst\nvlan 554\nvlan 600\n"
                                               "interface GigabitEthernet1/0/1\n channel-group 1 mode active\n"
                                               "interface Port-channel1\n switchport mode trunk\nend\n"),
                       ("show spanning-tree", "".join(
                           f"\nVLAN{v:04d}\n  Spanning tree enabled protocol rstp\n  Root ID    Priority    32768\n"
                           f"             Address     08f4.f00b.3b40\n             Cost        3\n"
                           f"             Port        65 (Port-channel1)\n\n  Bridge ID  Priority    {32768 + v}\n"
                           f"             Address     0011.2200.0001\n\nInterface           Role Sts Cost      "
                           f"Prio.Nbr Type\n------------------- ---- --- --------- -------- -----\n"
                           f"Po1                 Root FWD 3         128.65   P2p Bound(STP)\n"
                           for v in (1, 554, 600)))],
    }
    for host, cmds in logs.items():
        (tmp_path / f"{host}.log").write_text("".join(f"{host}#{cmd}\n{out}\n" for cmd, out in cmds) + f"{host}#\n")
    devices, errors = import_many([tmp_path])
    assert not errors
    snap = analyze(Snapshot(devices=devices))
    by = {d.hostname: d for d in snap.devices}
    (r,) = by["KS506-NV03-N002"].rings
    assert (r.label, r.role, r.vlan, r.state) == ("MRP ring 1", "client", 554, "unknown")
    assert r.ports == ["Gi1/1", "Gi1/2"] and r.port_states == {"Gi1/1": "forwarding", "Gi1/2": "forwarding"}
    topo = build_topology(snap)
    (site,) = build_stp(snap, topo)
    live = [t for t in site.trees if not t.trivial]
    # N006 really is root for the PVST side (it wins over 32768 + VLAN id); N002 is only its own root
    assert {t.root_node for t in live} == {"ks506-nv03-n006"}
    assert {t.root_node for t in site.trees if t.ring} == {"ks506-nv03-n001", "ks506-nv03-n002"}
    ids = {f.check_id for d in snap.devices for f in d.findings}
    assert not ids & {"stp.root-disagreement", "ring.no-manager", "ring.many-managers", "ring.open"}
    (f,) = [f for f in by["KS506-NV03-N006"].findings if f.check_id == "stp.root-on-access" and "554" in f.title]
    assert "PVST advertises 32768 plus the VLAN id (33322 for VLAN 554)" in f.detail  # MST 32768 beats it
    doc = build_asbuilt(snap)
    (overview,) = [b for b in doc.blocks if isinstance(b, Table) and "Root for" in b.columns]
    rows = {r[0]: r for r in overview.rows}
    assert rows["KS506-NV03-N002"][4] == rows["KS506-NV03-N001"][4] == "– (only of itself behind the ring)"
    assert rows["KS506-NV03-N006"][4].startswith("VLAN")
    assert any(isinstance(b, Callout) and b.title == "Ring redundancy instead of spanning tree" for b in doc.blocks)
    (rings,) = [b for b in doc.blocks if isinstance(b, Table) and "Ring links" in b.columns]
    # the manager reports CLOSED; the clients' "unknown" does not hide it
    assert rings.rows == [["MRP ring 1", "KS506-NV03-N001–002, 006",
                           "KS506-NV03-N001 manager", Cell("closed", "success"), "3"]]
