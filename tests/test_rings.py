"""Ring protocols on Cisco Industrial Ethernet switches (MRP, REP), and switches with spanning tree off."""

from sextant.analysis import analyze, analyze_device
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
