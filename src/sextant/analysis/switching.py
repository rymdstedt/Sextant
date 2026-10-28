"""Layer 2 checks: STP, edge ports, VLAN 1 use, unused ports."""

from __future__ import annotations

from sextant.analysis import check
from sextant.model import Device, DeviceRole, Finding, PortMode, Severity


@check
def stp(d: Device):
    if d.role != DeviceRole.switch or d.spanning_tree is None:
        return
    st = d.spanning_tree
    if st.mode and st.mode.lower() in ("disabled", "none", "off"):
        if d.rings:  # the ring protocol protects the ring ports; the other ports have no loop protection
            yield Finding(check_id="stp.disabled", severity=Severity.medium,
                          title=f"Spanning tree disabled (ring ports protected by {d.rings[0].label})",
                          detail="The ring protocol breaks the ring loop, but a loop through any other port "
                                 "(a patch cable between two edge ports, an unmanaged switch) is not stopped.",
                          recommendation="Run rapid-pvst/MST on the switch (ring ports are left to the ring "
                                         "protocol), or BPDU guard / storm control on the edge ports.")
            return
        yield Finding(check_id="stp.disabled", severity=Severity.high, title="Spanning tree disabled",
                      detail="A single patching mistake can cause a broadcast storm.",
                      recommendation="Enable RSTP/MST (or rapid-pvst) on all switches.")
        return
    if st.mode and st.mode.lower() in ("pvst", "stp", "ieee"):
        yield Finding(check_id="stp.legacy", severity=Severity.low, title=f"Legacy spanning tree ({st.mode})",
                      detail="802.1D timers: a topology change takes 30-50 seconds to converge, against about "
                             "one second with rapid spanning tree.",
                      recommendation="spanning-tree mode rapid-pvst (it interoperates with PVST neighbours, so "
                                     "switches can be moved one at a time).")
    access = [i for i in d.interfaces if i.kind == "physical" and i.mode == PortMode.access and i.enabled]
    if st.bpdu_guard_default is False or st.bpdu_guard_default is None:
        unguarded = [i.name for i in access if i.stp_edge is not True]
        # edge ports without BPDU guard, globally or on the port (Cisco 'spanning-tree bpduguard enable',
        # AOS-S/AOS-CX 'bpdu-protection' / 'bpdu-guard')
        guarded_edges = [i for i in access if i.stp_edge and i.extra.get("bpduguard") != "enabled"]
        if guarded_edges and st.bpdu_guard_default is False:
            yield Finding(check_id="stp.no-bpduguard", severity=Severity.medium,
                          title="Edge ports without BPDU guard",
                          detail=f"{len(guarded_edges)} portfast/edge port(s) without BPDU guard, globally or on "
                                 "the port.",
                          recommendation="spanning-tree portfast bpduguard default (or per edge port).")
        elif len(unguarded) > 4 and st.bpdu_guard_default is False:
            yield Finding(check_id="stp.no-edge", severity=Severity.low,
                          title=f"{len(unguarded)} access ports not configured as edge",
                          recommendation="Enable portfast/admin-edge on host-facing access ports.")


@check
def vlan1(d: Device):
    if d.role != DeviceRole.switch:
        return
    native1 = [i.name for i in d.interfaces if i.mode == PortMode.trunk and (i.native_vlan in (None, 1))
               and i.kind in ("physical", "lag") and i.native_vlan == 1]
    if native1:
        yield Finding(check_id="l2.native-vlan1", severity=Severity.low,
                      title=f"Native VLAN 1 on {len(native1)} trunk(s)",
                      detail="Untagged traffic on trunks lands in the default VLAN (VLAN hopping risk).",
                      recommendation="Set an unused, dedicated native VLAN on trunks.", evidence=native1[:10])
    active_v1 = [i.name for i in d.interfaces if i.kind == "physical" and i.mode == PortMode.access
                 and i.access_vlan in (1, None) and i.enabled and i.access_vlan == 1]
    if active_v1:
        yield Finding(check_id="l2.access-vlan1", severity=Severity.low,
                      title=f"{len(active_v1)} enabled access port(s) in VLAN 1",
                      recommendation="Move unused ports to a parking VLAN and shut them down.",
                      evidence=active_v1[:10])


@check
def unused_ports(d: Device):
    if d.role != DeviceRole.switch:
        return
    shut = [i for i in d.interfaces if i.kind == "physical" and not i.enabled]
    configured = [i.name for i in shut if i.description or (i.access_vlan not in (None, 1)) or i.mode == PortMode.trunk]
    if configured:
        yield Finding(check_id="l2.shut-configured", severity=Severity.info,
                      title=f"{len(configured)} admin-down port(s) still carry configuration",
                      detail="Disabled ports with descriptions or VLANs are often leftovers.",
                      recommendation="Verify and default the configuration of decommissioned ports.",
                      evidence=configured[:10])
