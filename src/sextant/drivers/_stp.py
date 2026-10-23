"""Parsers for spanning-tree runtime output, shared by the switch drivers.

Each returns (instances, bridge_mac). Instances carry the root bridge, this bridge, the root
port and every port's role/state, which is what the STP diagrams and checks need.
"""

from __future__ import annotations

import re

from sextant.drivers._util import expand_vlans
from sextant.model import StpInstance, StpPort

_ROLES = {
    "root": "root", "desg": "designated", "designated": "designated", "altn": "alternate", "alternate": "alternate",
    "alt": "alternate", "back": "backup", "backup": "backup", "mstr": "master", "master": "master",
    "disa": "disabled", "disabled": "disabled", "desig": "designated", "bkup": "backup", "boundary": "boundary",
    "dis": "disabled", "bound": "boundary",  # Junos DIS, Cisco Bound (MST region boundary)
}
_STATES = {
    "fwd": "forwarding", "forwarding": "forwarding", "blk": "blocking", "blocking": "blocking",
    "lrn": "learning", "learning": "learning", "lis": "listening", "listening": "listening",
    "dis": "disabled", "disabled": "disabled", "bkn": "broken", "broken": "broken",
    "discarding": "discarding", "dsc": "discarding",
}


def norm_mac(text: str | None) -> str | None:
    """Any MAC notation -> '0011.2233.44aa'."""
    if not text:
        return None
    hexes = re.sub(r"[^0-9a-fA-F]", "", text)
    if len(hexes) != 12:
        return None
    h = hexes.lower()
    return f"{h[0:4]}.{h[4:8]}.{h[8:12]}"


def compress_instances(names: list[str]) -> str:
    """['VLAN0035', 'VLAN0040', 'MST0'] -> 'VLAN 35, 40; MST0'."""
    vlans = sorted(int(n[4:]) for n in names if n.startswith("VLAN") and n[4:].isdigit())
    other = [n for n in names if not (n.startswith("VLAN") and n[4:].isdigit())]
    parts = [("VLAN " + ", ".join(map(str, vlans)))] if vlans else []
    return "; ".join(parts + other)


def _int(v: str | None) -> int | None:
    try:
        return int(v) if v is not None else None
    except ValueError:
        return None


# --------------------------------------------------------------------------- Cisco IOS / IOS-XE / NX-OS


def parse_cisco(text: str) -> tuple[list[StpInstance], str | None]:
    """`show spanning-tree` on IOS/IOS-XE (PVST/rapid-PVST/MST) and NX-OS."""
    out: list[StpInstance] = []
    bridge_mac = None
    parts = re.split(r"^(VLAN\d{4}|MST\d+)\s*$", text or "", flags=re.M)
    for name, body in zip(parts[1::2], parts[2::2], strict=False):
        inst = StpInstance(name=name)
        if name.startswith("VLAN"):
            inst.vlans = [int(name[4:])]
        inst.protocol = (re.search(r"Spanning tree enabled protocol (\S+)", body) or [None, None])[1]
        root = re.search(r"Root ID\s+Priority\s+(\d+)\s*\n\s*Address\s+(\S+)(.*?)(?=Bridge ID|\Z)", body, re.S)
        if root:
            inst.root_priority, inst.root_mac = int(root.group(1)), norm_mac(root.group(2))
            rest = root.group(3)
            inst.is_root = "This bridge is the root" in rest
            inst.root_cost = _int((re.search(r"Cost\s+(\d+)", rest) or [None, None])[1])
            rp = re.search(r"Port\s+\d+\s+\(([^)]+)\)", rest)
            inst.root_port = rp.group(1) if rp else None
        br = re.search(r"Bridge ID\s+Priority\s+(\d+).*?\n\s*Address\s+(\S+)", body, re.S)
        if br:
            inst.bridge_priority, inst.bridge_mac = int(br.group(1)), norm_mac(br.group(2))
            bridge_mac = bridge_mac or inst.bridge_mac
        mv = re.search(r"Vlans mapped:\s*(\S+)", body)
        if mv:
            inst.vlans = expand_vlans(mv.group(1))
        for mt in re.finditer(r"^(\S+)\s+(Root|Desg|Altn|Back|Mstr|Disa|Bound|Master)\s+(\w{3})\*?\s*(\d+)\s+(\S+)\s*(.*)$",
                              body, re.M):
            inst.ports.append(StpPort(interface=mt.group(1), role=_ROLES.get(mt.group(2).lower(), mt.group(2).lower()),
                                      state=_STATES.get(mt.group(3).lower(), mt.group(3).lower()),
                                      cost=_int(mt.group(4)), priority=mt.group(5),
                                      link_type=mt.group(6).strip() or None))
        if inst.root_mac or inst.ports:
            out.append(inst)
    return out, bridge_mac


# --------------------------------------------------------------------------- HPE ProCurve / Aruba AOS-S


def parse_procurve(text: str) -> tuple[list[StpInstance], str | None]:
    """`show spanning-tree` on AOS-S (MSTP or RPVST)."""
    if not text or not re.search(r"Spanning Tree|STP Enabled", text, re.I):
        return [], None

    def val(label: str) -> str | None:
        mt = re.search(rf"^\s*{label}\s*:\s*(.*?)\s*$", text, re.M | re.I)
        return mt.group(1) if mt else None

    bridge_mac = norm_mac(val("Switch MAC Address"))
    inst = StpInstance(name="IST" if "MST" in (val("Force Version") or "MST") else "RSTP",
                       protocol=(val("Force Version") or "").replace("-operation", "").lower() or None)
    mapped = val("IST Mapped VLANs")
    inst.vlans = expand_vlans(mapped) if mapped else []
    inst.bridge_priority = _int(val("Switch Priority"))
    inst.bridge_mac = bridge_mac
    inst.root_mac = norm_mac(val("CST Root MAC Address") or val("Root MAC Address"))
    inst.root_priority = _int(val("CST Root Priority") or val("Root Priority"))
    inst.root_cost = _int(val("CST Root Path Cost") or val("Root Path Cost"))
    rp = val("CST Root Port") or val("Root Port")
    inst.is_root = bool(rp and "this switch" in rp.lower()) or (inst.root_mac is not None and inst.root_mac == bridge_mac)
    inst.root_port = None if inst.is_root else rp
    # Port  Type      | Cost      Prio Role       State      Designated Bridge
    row = re.compile(r"^\s*(\S+)\s+(?:[\w/+-]+\s+)?\|\s*(\d+|Auto)\s+(?:(\d+)\s+)?"
                     r"(Root|Designated|Alternate|Backup|Disabled|Master)\s+"
                     r"(Forwarding|Blocking|Disabled|Learning|Listening|Discarding)\b", re.M | re.I)
    for mt in row.finditer(text):
        inst.ports.append(StpPort(interface=mt.group(1), cost=_int(mt.group(2)), priority=mt.group(3),
                                  role=_ROLES.get(mt.group(4).lower()), state=_STATES.get(mt.group(5).lower())))
    if not inst.ports:
        # 16.x without a Role column: "Port Type | Cost Prio State | Designated Bridge Hello PtP Edge"
        bare = re.compile(r"^\s*(\S+)\s+(?:[\w/+-]+\s+)?\|\s*(\d+|Auto)\s+(\d+)\s+"
                          r"(Forwarding|Blocking|Disabled|Learning|Listening|Discarding)\b", re.M | re.I)
        for mt in bare.finditer(text):
            state = _STATES.get(mt.group(4).lower())
            role = ("root" if inst.root_port and mt.group(1).lower() == inst.root_port.lower() else
                    "disabled" if state == "disabled" else
                    "alternate" if state in ("blocking", "discarding") else "designated")
            inst.ports.append(StpPort(interface=mt.group(1), cost=_int(mt.group(2)), priority=mt.group(3),
                                      role=role, state=state))
    return ([inst] if inst.root_mac or inst.ports else []), bridge_mac


# --------------------------------------------------------------------------- Aruba AOS-CX


def parse_aoscx(text: str) -> tuple[list[StpInstance], str | None]:
    """`show spanning-tree` on AOS-CX (MSTP/RPVST)."""
    out: list[StpInstance] = []
    bridge_mac = None
    parts = re.split(r"^(MST\d+|VLAN\s*\d+)\s*$", text or "", flags=re.M)
    proto = (re.search(r"Protocol:\s*(\S+)", text or "") or [None, None])[1]
    for name, body in zip(parts[1::2], parts[2::2], strict=False):
        name = name.replace(" ", "")
        inst = StpInstance(name=name, protocol=proto.lower() if proto else None)
        if name.upper().startswith("VLAN"):
            inst.vlans = [int(re.sub(r"\D", "", name))]
        mapped = re.search(r"Vlans? mapped\s*:?\s*(\S+)", body, re.I)
        if mapped:
            inst.vlans = expand_vlans(mapped.group(1))
        root = re.search(r"Root ID\s+Priority\s*:\s*(\d+)\s*\n\s*MAC-Address\s*:\s*(\S+)(.*?)(?=Bridge ID|\Z)", body, re.S)
        if root:
            inst.root_priority, inst.root_mac = int(root.group(1)), norm_mac(root.group(2))
            inst.is_root = "This bridge is the root" in root.group(3)
        br = re.search(r"Bridge ID\s+Priority\s*:\s*(\d+)\s*\n\s*MAC-Address\s*:\s*(\S+)", body)
        if br:
            inst.bridge_priority, inst.bridge_mac = int(br.group(1)), norm_mac(br.group(2))
            bridge_mac = bridge_mac or inst.bridge_mac
            inst.is_root = inst.is_root or inst.bridge_mac == inst.root_mac
        for mt in re.finditer(r"^(\S+)\s+(Root|Designated|Alternate|Backup|Disabled|Master)\s+"
                              r"(Forwarding|Blocking|Discarding|Learning|Disabled)\s+(\d+)\s+(\d+)\s*(.*)$", body, re.M | re.I):
            port = StpPort(interface=mt.group(1), role=_ROLES.get(mt.group(2).lower()),
                           state=_STATES.get(mt.group(3).lower()), cost=_int(mt.group(4)), priority=mt.group(5),
                           link_type=mt.group(6).strip() or None)
            inst.ports.append(port)
            if port.role == "root":
                inst.root_port = port.interface
        if inst.root_mac or inst.ports:
            out.append(inst)
    return out, bridge_mac


# --------------------------------------------------------------------------- Junos


def parse_junos(bridge: str, interfaces: str) -> tuple[list[StpInstance], str | None]:
    """`show spanning-tree bridge` + `show spanning-tree interface` (RSTP/MSTP/VSTP, instance 0)."""
    if not (bridge or interfaces):
        return [], None
    inst = StpInstance(name="CIST", protocol=((re.search(r"Enabled protocol\s*:\s*(\S+)", bridge or "") or
                                               [None, None])[1] or "").lower() or None)
    root = re.search(r"Root ID\s*:\s*(\d+)\.(\S+)", bridge or "")
    if root:
        inst.root_priority, inst.root_mac = int(root.group(1)), norm_mac(root.group(2))
    inst.root_cost = _int((re.search(r"Root cost\s*:\s*(\d+)", bridge or "") or [None, None])[1])
    rp = (re.search(r"Root port\s*:\s*(\S+)", bridge or "") or [None, None])[1]
    local = re.search(r"Local parameters.*?Bridge ID\s*:\s*(\d+)\.(\S+)", bridge or "", re.S)
    if local:
        inst.bridge_priority, inst.bridge_mac = int(local.group(1)), norm_mac(local.group(2))
    inst.is_root = inst.root_mac is not None and inst.root_mac == inst.bridge_mac
    inst.root_port = None if inst.is_root else rp
    for mt in re.finditer(r"^(\S+)\s+\d+:\d+\s+\d+:\d+\s+\S+\s+(\d+)\s+(FWD|BLK|DIS|LRN)\s+(ROOT|DESG|ALT|BKUP|DIS)\s*$",
                          interfaces or "", re.M):
        inst.ports.append(StpPort(interface=mt.group(1), cost=_int(mt.group(2)),
                                  state=_STATES.get(mt.group(3).lower()), role=_ROLES.get(mt.group(4).lower())))
    return ([inst] if inst.root_mac or inst.ports else []), inst.bridge_mac
