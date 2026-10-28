"""Ring redundancy protocols on Cisco IOS / IOS-XE (Industrial Ethernet: IE3x00, IE4000, IE9300...).

MRP (IEC 62439-2), REP (Cisco Resilient Ethernet Protocol) and ERPS (ITU-T G.8032) break the ring loop
themselves; spanning tree does not run on the ring ports and no BPDUs cross them. Parsed from the
configuration in both forms Cisco uses, plus `show mrp ring` / `show rep topology` for the runtime state:

    mrp ring 1                          interface GigabitEthernet1/1
     mode manager                        mrp ring 1
     profile 200                         rep segment 10 edge primary
     port 1 interface GigabitEthernet1/1
     port 2 interface GigabitEthernet1/2
"""

from __future__ import annotations

import re

from sextant.drivers._util import blocks, short_ifname
from sextant.model import Ring

_MRP_ROLE = re.compile(r"^(?:mode\s+)?(manager|client|auto-manager|auto-mgr|mrm|mrc)\b", re.I)


def parse_cisco_rings(cfg: str, mrp_show: str = "", rep_show: str = "") -> list[Ring]:
    rings: dict[tuple[str, str], Ring] = {}

    def ring(proto: str, rid: str) -> Ring:
        return rings.setdefault((proto, rid), Ring(protocol=proto, ring_id=rid))

    def add_port(r: Ring, port: str) -> str:
        """Add once ('GigabitEthernet1/2' in the config is 'Gi1/2' in show output); returns the stored name."""
        for have in r.ports:
            if _same(have, port):
                return have
        r.ports.append(port)
        return port

    for header, lines in blocks(cfg or "", r"^mrp ring \d+"):
        parts = header.split()
        r = ring("MRP", parts[2])
        if len(parts) > 3 and (mt := _MRP_ROLE.match(parts[3])):
            r.role = mt.group(1).lower()
        for ln in lines:
            if mt := _MRP_ROLE.match(ln):
                r.role = mt.group(1).lower()
            elif mt := re.match(r"^port\s+\d\s+interface\s+(\S+)", ln, re.I):
                add_port(r, mt.group(1))
            elif mt := re.match(r"^(profile)\s+(\S+)", ln, re.I):
                r.details["profile"] = f"{mt.group(2)} ms" if mt.group(2).isdigit() else mt.group(2)
            elif mt := re.match(r"^vlan(?:-id)?\s+(\d+)", ln, re.I):
                r.vlan = int(mt.group(1))
            elif mt := re.match(r"^(name|domain-name|domain-id|priority)\s+(.+)$", ln, re.I):
                r.details[mt.group(1).lower()] = mt.group(2).strip('"')
    for header, lines in blocks(cfg or "", r"^ethernet ring g8032 \S+"):
        r = ring("ERPS", header.split()[3])
        for ln in lines:
            if mt := re.match(r"^port[01]\s+(?:interface\s+)?(\S+)", ln, re.I):
                add_port(r, mt.group(1))
    for header, lines in blocks(cfg or "", r"^interface\s+\S+"):
        name = header.split(None, 1)[1]
        for ln in lines:
            if mt := re.match(r"^mrp ring (\d+)(?:\s+(\S+))?", ln, re.I):
                r = ring("MRP", mt.group(1))
                add_port(r, name)
                if mt.group(2) and (rm := _MRP_ROLE.match(mt.group(2))):
                    r.role = rm.group(1).lower()
            elif mt := re.match(r"^rep segment (\d+)\s*(.*)$", ln, re.I):
                r = ring("REP", mt.group(1))
                add_port(r, name)
                extra = mt.group(2).lower()
                if "edge" in extra:
                    r.role = "edge (primary)" if "primary" in extra else "edge"
                    r.details[name] = extra
                elif r.role is None:
                    r.role = "transit"
            elif mt := re.match(r"^(?:ethernet ring g8032|erps ring)\s+(\S+)", ln, re.I):
                add_port(ring("ERPS", mt.group(1)), name)
    _mrp_runtime(mrp_show, ring, add_port)
    _rep_runtime(rep_show, rings)
    return [rings[k] for k in sorted(rings, key=lambda k: (k[0], int(k[1]) if k[1].isdigit() else 0, k[1]))]


def _same(a: str, b: str) -> bool:
    return short_ifname(a.strip()).lower() == short_ifname(b.strip()).lower()


def _mrp_runtime(text: str, ring, add_port) -> None:
    """`show mrp ring`: one section per ring; ports shown side by side under 'Port1: Port2:'
    ('Interface :Gi1/2   Interface :Gi1/1'). Clients report 'Network Status : Unknown' (only the manager
    knows); the Gateway block has a ' Status' line of its own, which is not a port's."""
    parts = re.split(r"^\s*MRP ring\s+(\d+)\s*$", text or "", flags=re.M | re.I)
    for rid, body in zip(parts[1::2], parts[2::2], strict=False):
        r = ring("MRP", rid)
        # Auto-Manager is configured; the operational mode says whether it won (Manager) or not (Client)
        configured = re.search(r"^\s*Mode\s*:\s*(\S+)", body, re.M | re.I)
        operational = re.search(r"^\s*Operational Mode\s*:\s*(\S+)", body, re.M | re.I)
        for mt in (configured, operational):
            if mt and (rm := _MRP_ROLE.match(mt.group(1))):
                r.role = rm.group(1).lower()
        if configured and operational and configured.group(1).lower() != operational.group(1).lower():
            r.details["configured mode"] = configured.group(1).lower()
        prio = re.search(r"^Priority\s*:\s*(\d+)", body, re.M | re.I)
        if prio:
            r.details.setdefault("priority", prio.group(1))
        state = re.search(r"^\s*(?:Network Status|Ring State|Ring Status)\s*:\s*(\S+)", body, re.M | re.I)
        if state:
            r.state = state.group(1).lower()
        vlan = re.search(r"^\s*VLAN(?: ID)?\s*:\s*(\d+)", body, re.M | re.I)
        if vlan:
            r.vlan = int(vlan.group(1))
        prof = re.search(r"^\s*Profile\s*:\s*(.+?)\s*$", body, re.M | re.I)
        if prof:
            r.details.setdefault("profile", prof.group(1))
        ifaces, states = [], []
        ports = re.search(r"^\s*Port1\s*:.*?(?=^\s*$|^\s*VLAN|\Z)", body, re.M | re.S | re.I)
        for ln in (ports.group(0) if ports else "").splitlines():
            ifaces += re.findall(r"Interface\s*:\s*(\S+)", ln, re.I)
            states += [x.strip() for x in re.findall(r"Status\s*:\s*([A-Za-z][A-Za-z ]*?)(?=\s{2,}|\s*$)", ln, re.I)]
        for i, name in enumerate(ifaces):
            stored = add_port(r, name)
            if i < len(states):
                r.port_states[stored] = states[i].lower().replace("blocked", "blocking")


def _rep_runtime(text: str, rings: dict) -> None:
    """`show rep topology`: a segment with a failed port is broken; one alternate (blocking) port means complete."""
    parts = re.split(r"^\s*REP Segment\s+(\d+)\s*$", text or "", flags=re.M | re.I)
    for sid, body in zip(parts[1::2], parts[2::2], strict=False):
        r = rings.get(("REP", sid))
        if r is None:
            continue
        rows = [ln for ln in body.splitlines() if ln.strip() and not ln.startswith(("-", "BridgeName"))]
        if any(re.search(r"\bFail\b", ln) for ln in rows):
            r.state = "failed"
        elif any(re.search(r"\bAlt\b", ln) for ln in rows):
            r.state = "complete"
