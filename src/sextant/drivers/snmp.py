"""Generic SNMP driver (v2c or v3, pysnmp 7 asyncio API, GETBULK walks only).

Works for anything with an SNMP agent: switches without a dedicated driver,
UPSes, PDUs, printers, appliances. ``raw.outputs`` maps an object name to
``{index: value}`` (all strings), e.g. ``outputs["ifName"]["3"] = "Gi1/0/3"``,
plus ``_meta`` (version / v3 user / masked community hint) and ``collected_at``.

Target options: ``version`` ("2c" | "3"; default 3 when a v3 user is set),
``auth_protocol`` (SHA | SHA256 | SHA384 | SHA512 | MD5; default SHA),
``priv_protocol`` (AES | AES192 | AES256 | DES | 3DES; default AES),
``timeout`` (s, default 3), ``retries`` (default 2), ``max_repetitions`` (default 25).
"""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sextant.drivers import register
from sextant.drivers._util import parse_dt, to_int
from sextant.drivers.base import Credentials, Driver, RawCollection, Target
from sextant.model import (
    Device,
    DeviceRole,
    Fact,
    Interface,
    IPAddress,
    Neighbor,
    PortMode,
    Section,
    SnmpConfig,
    Table,
    mask_secret,
)
from sextant.redact import redact_obj

# name -> numeric OID (column / scalar group). Numeric so no MIB files are needed.
OIDS: dict[str, str] = {
    # SNMPv2-MIB system
    "sysDescr": "1.3.6.1.2.1.1.1", "sysObjectID": "1.3.6.1.2.1.1.2", "sysUpTime": "1.3.6.1.2.1.1.3",
    "sysContact": "1.3.6.1.2.1.1.4", "sysName": "1.3.6.1.2.1.1.5", "sysLocation": "1.3.6.1.2.1.1.6",
    # IF-MIB ifTable / ifXTable
    "ifDescr": "1.3.6.1.2.1.2.2.1.2", "ifType": "1.3.6.1.2.1.2.2.1.3", "ifMtu": "1.3.6.1.2.1.2.2.1.4",
    "ifSpeed": "1.3.6.1.2.1.2.2.1.5", "ifPhysAddress": "1.3.6.1.2.1.2.2.1.6",
    "ifAdminStatus": "1.3.6.1.2.1.2.2.1.7", "ifOperStatus": "1.3.6.1.2.1.2.2.1.8",
    "ifName": "1.3.6.1.2.1.31.1.1.1.1", "ifHighSpeed": "1.3.6.1.2.1.31.1.1.1.15", "ifAlias": "1.3.6.1.2.1.31.1.1.1.18",
    # IP-MIB ipAddrTable
    "ipAdEntAddr": "1.3.6.1.2.1.4.20.1.1", "ipAdEntIfIndex": "1.3.6.1.2.1.4.20.1.2",
    "ipAdEntNetMask": "1.3.6.1.2.1.4.20.1.3",
    # ENTITY-MIB entPhysicalTable
    "entPhysicalDescr": "1.3.6.1.2.1.47.1.1.1.1.2", "entPhysicalClass": "1.3.6.1.2.1.47.1.1.1.1.5",
    "entPhysicalName": "1.3.6.1.2.1.47.1.1.1.1.7", "entPhysicalHardwareRev": "1.3.6.1.2.1.47.1.1.1.1.8",
    "entPhysicalFirmwareRev": "1.3.6.1.2.1.47.1.1.1.1.9", "entPhysicalSoftwareRev": "1.3.6.1.2.1.47.1.1.1.1.10",
    "entPhysicalSerialNum": "1.3.6.1.2.1.47.1.1.1.1.11", "entPhysicalMfgName": "1.3.6.1.2.1.47.1.1.1.1.12",
    "entPhysicalModelName": "1.3.6.1.2.1.47.1.1.1.1.13",
    # LLDP-MIB local ports + remote table
    "lldpLocPortId": "1.0.8802.1.1.2.1.3.7.1.3", "lldpLocPortDesc": "1.0.8802.1.1.2.1.3.7.1.4",
    "lldpRemChassisId": "1.0.8802.1.1.2.1.4.1.1.5", "lldpRemPortId": "1.0.8802.1.1.2.1.4.1.1.7",
    "lldpRemPortDesc": "1.0.8802.1.1.2.1.4.1.1.8", "lldpRemSysName": "1.0.8802.1.1.2.1.4.1.1.9",
    "lldpRemSysDesc": "1.0.8802.1.1.2.1.4.1.1.10",
}
# Walked only when sysObjectID is under APC/Schneider (enterprise 318): PowerNet-MIB UPS status.
APC_OIDS: dict[str, str] = {
    "upsBasicIdentModel": "1.3.6.1.4.1.318.1.1.1.1.1.1", "upsAdvIdentFirmwareRevision": "1.3.6.1.4.1.318.1.1.1.1.2.1",
    "upsAdvIdentDateOfManufacture": "1.3.6.1.4.1.318.1.1.1.1.2.2",
    "upsAdvIdentSerialNumber": "1.3.6.1.4.1.318.1.1.1.1.2.3",
    "upsBasicBatteryStatus": "1.3.6.1.4.1.318.1.1.1.2.1.1",
    "upsBasicBatteryLastReplaceDate": "1.3.6.1.4.1.318.1.1.1.2.1.3",
    "upsAdvBatteryCapacity": "1.3.6.1.4.1.318.1.1.1.2.2.1", "upsAdvBatteryTemperature": "1.3.6.1.4.1.318.1.1.1.2.2.2",
    "upsAdvBatteryRunTimeRemaining": "1.3.6.1.4.1.318.1.1.1.2.2.3",
    "upsAdvBatteryReplaceIndicator": "1.3.6.1.4.1.318.1.1.1.2.2.4",
    "upsAdvInputLineVoltage": "1.3.6.1.4.1.318.1.1.1.3.2.1", "upsBasicOutputStatus": "1.3.6.1.4.1.318.1.1.1.4.1.1",
    "upsAdvOutputLoad": "1.3.6.1.4.1.318.1.1.1.4.2.3",
    "upsAdvTestDiagnosticsResults": "1.3.6.1.4.1.318.1.1.1.7.2.3",
    "upsAdvTestLastDiagnosticsDate": "1.3.6.1.4.1.318.1.1.1.7.2.4",
}

ENTERPRISES: dict[int, str] = {
    2: "IBM", 9: "Cisco", 11: "HPE", 43: "3Com", 171: "D-Link", 207: "Allied Telesis", 253: "Xerox", 311: "Microsoft",
    318: "APC (Schneider Electric)", 367: "Ricoh", 476: "Vertiv (Liebert)", 534: "Eaton", 674: "Dell",
    789: "NetApp", 1347: "Kyocera", 1588: "Brocade", 1602: "Canon", 1916: "Extreme Networks", 1991: "Brocade (Foundry)",
    2011: "Huawei", 2435: "Brother", 2620: "Check Point", 2636: "Juniper", 3375: "F5", 4413: "Ubiquiti (EdgeSwitch)",
    4526: "Netgear", 5528: "APC NetBotz", 5951: "Citrix", 6027: "Dell (Force10)", 6574: "Synology", 6876: "VMware",
    8072: "Net-SNMP", 8741: "SonicWall", 9148: "Oracle (Acme Packet)", 10418: "Vertiv (Avocent)", 11863: "TP-Link",
    12356: "Fortinet", 13742: "Raritan", 14179: "Cisco (Airespace)", 14823: "Aruba (HPE)", 14988: "MikroTik",
    18334: "Konica Minolta", 24681: "QNAP", 25461: "Palo Alto Networks", 25506: "HPE (H3C/Comware)",
    30065: "Arista", 41112: "Ubiquiti", 47196: "HPE Aruba (AOS-CX)",
}
_MAC_COLUMNS = {"ifPhysAddress"}  # LLDP ids may be 6-char names like "Gi0/24": rely on printability
_IF_KIND = {"24": "loopback", "6": "physical", "117": "physical", "62": "physical", "161": "lag", "53": "vlan",
            "135": "vlan", "136": "vlan", "131": "tunnel", "1": "virtual"}
_ENT_CLASS = {"3": "Chassis", "6": "Power supply", "7": "Fan", "8": "Sensor", "9": "Module", "11": "Stack",
              "12": "CPU"}


# =========================================================================== collection


def _value(v: Any, mac: bool = False) -> str:
    """pysnmp value -> string. Printable OCTET STRINGs as text, others (MACs) as colon hex."""
    cls = type(v).__name__
    if cls == "OctetString":
        b = bytes(v)
        if mac and len(b) == 6:
            return ":".join(f"{x:02x}" for x in b)
        try:
            text = b.rstrip(b"\x00").decode("utf-8")  # C-style strings: "sw01\x00" is still text
            if all(c.isprintable() or c in "\r\n\t" for c in text):
                return text.strip()
        except UnicodeDecodeError:
            pass
        return ":".join(f"{x:02x}" for x in b)
    if cls in ("ObjectIdentifier", "ObjectName"):
        return ".".join(str(x) for x in tuple(v))
    if cls == "IpAddress":
        return v.prettyPrint()
    try:
        return str(int(v))
    except (TypeError, ValueError):
        return v.prettyPrint() if hasattr(v, "prettyPrint") else str(v)


async def _walk(target: Target, creds: Credentials, raw: RawCollection) -> None:  # pragma: no cover - live only
    import pysnmp.hlapi.v3arch.asyncio as a
    from pysnmp.hlapi.v3arch.asyncio import (
        CommunityData,
        ContextData,
        ObjectIdentity,
        ObjectType,
        SnmpEngine,
        UdpTransportTarget,
        UsmUserData,
        bulk_walk_cmd,
    )

    opts = target.options
    version = str(opts.get("version") or ("3" if creds.snmp_v3_user else "2c")).lstrip("v")
    if version == "3":
        auth_p = {"SHA": a.USM_AUTH_HMAC96_SHA, "SHA224": a.USM_AUTH_HMAC128_SHA224,
                  "SHA256": a.USM_AUTH_HMAC192_SHA256, "SHA384": a.USM_AUTH_HMAC256_SHA384,
                  "SHA512": a.USM_AUTH_HMAC384_SHA512, "MD5": a.USM_AUTH_HMAC96_MD5}
        priv_p = {"AES": a.USM_PRIV_CFB128_AES, "AES128": a.USM_PRIV_CFB128_AES, "AES192": a.USM_PRIV_CFB192_AES,
                  "AES256": a.USM_PRIV_CFB256_AES, "DES": a.USM_PRIV_CBC56_DES, "3DES": a.USM_PRIV_CBC168_3DES}
        ap = str(opts.get("auth_protocol", "SHA")).upper()
        pp = str(opts.get("priv_protocol", "AES")).upper()
        level = "authPriv" if creds.snmp_v3_priv else ("authNoPriv" if creds.snmp_v3_auth else "noAuthNoPriv")
        auth_data = UsmUserData(
            creds.snmp_v3_user, authKey=creds.snmp_v3_auth, privKey=creds.snmp_v3_priv,
            authProtocol=auth_p[ap] if creds.snmp_v3_auth else a.USM_AUTH_NONE,
            privProtocol=priv_p[pp] if creds.snmp_v3_priv else a.USM_PRIV_NONE)
        raw.outputs["_meta"] = {"version": "v3", "user": creds.snmp_v3_user, "level": level,
                                "auth_protocol": ap if creds.snmp_v3_auth else None,
                                "priv_protocol": pp if creds.snmp_v3_priv else None}
    else:
        auth_data = CommunityData(creds.snmp_community or "public", mpModel=1)
        raw.outputs["_meta"] = {"version": "v2c", "community_hint": mask_secret(creds.snmp_community or "public")}

    engine = SnmpEngine()
    transport = await UdpTransportTarget.create((target.host or target.name, target.port or 161),
                                                timeout=float(opts.get("timeout", 3)), retries=int(opts.get("retries", 2)))
    reps = int(opts.get("max_repetitions", 25))

    async def walk(name: str, oid: str) -> None:
        col: dict[str, str] = {}
        async for err_ind, err_stat, _err_idx, var_binds in bulk_walk_cmd(
                engine, auth_data, transport, ContextData(), 0, reps, ObjectType(ObjectIdentity(oid)),
                lexicographicMode=False):
            if err_ind or err_stat:
                raw.warnings.append(f"{name}: {err_ind or err_stat.prettyPrint()}")
                break
            for vb in var_binds:
                o = vb[0].getOid() if hasattr(vb[0], "getOid") else vb[0]
                full = ".".join(str(x) for x in tuple(o))
                if full.startswith(oid + "."):
                    col[full[len(oid) + 1:]] = _value(vb[1], mac=name in _MAC_COLUMNS)
        raw.outputs[name] = col

    try:
        for name, oid in OIDS.items():
            await walk(name, oid)
        if raw.outputs.get("sysObjectID", {}).get("0", "").startswith("1.3.6.1.4.1.318."):
            for name, oid in APC_OIDS.items():
                await walk(name, oid)
    finally:
        engine.close_dispatcher()


class SnmpDriver(Driver):
    id = "snmp"
    label = "Generic SNMP (v2c/v3)"
    methods = ("snmp",)

    def collect(self, target: Target, creds: Credentials) -> RawCollection:  # pragma: no cover - live only
        import asyncio

        raw = RawCollection(driver=self.id, target=target.name, method="snmp")
        raw.outputs["collected_at"] = datetime.now(UTC).isoformat()
        asyncio.run(_walk(target, creds, raw))
        if not raw.outputs.get("sysDescr"):
            raw.warnings.append("no response to SNMPv2-MIB::system (wrong credentials, ACL or version?)")
        raw.outputs = redact_obj(raw.outputs)
        return raw

    def from_file(self, path: Path) -> RawCollection:
        """Load a saved walk (this driver's JSON format, bare outputs or a RawCollection dump)."""
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, dict) and "outputs" in data and "driver" in data:
            data = data["outputs"]
        return RawCollection(driver=self.id, target=path.name, method="file",
                             outputs=redact_obj(data if isinstance(data, dict) else {}))

    # ----------------------------------------------------------------------- parse

    def parse(self, raw: RawCollection) -> Device:
        out = raw.outputs or {}
        warnings = list(raw.warnings)

        def col(name: str) -> dict[str, str]:
            v = out.get(name)
            return {str(k): str(x) for k, x in v.items()} if isinstance(v, dict) else {}

        def scalar(name: str) -> str | None:
            c = col(name)
            return c.get("0") or (next(iter(c.values())) if c else None) or None

        collected = parse_dt(out.get("collected_at"))
        descr = scalar("sysDescr") or ""
        if not descr:
            warnings.append("snmp: sysDescr missing")
        oid = scalar("sysObjectID") or ""
        ent_no = to_int(oid.split(".")[6]) if oid.startswith("1.3.6.1.4.1.") and len(oid.split(".")) > 6 else None
        vendor = ENTERPRISES.get(ent_no) if ent_no is not None else None
        ticks = to_int(scalar("sysUpTime"))

        # ENTITY-MIB
        ent_rows, hardware = [], []
        chassis: dict[str, str] = {}
        classes = col("entPhysicalClass")
        for idx in sorted(classes, key=lambda x: to_int(x) or 0):
            cls = classes[idx]
            row = {k: col(f"entPhysical{k}").get(idx, "") for k in
                   ("Name", "Descr", "ModelName", "SerialNum", "HardwareRev", "FirmwareRev", "SoftwareRev", "MfgName")}
            if cls == "3" and not chassis:
                chassis = row
            if cls in _ENT_CLASS and (row["SerialNum"] or row["ModelName"] or cls == "3"):
                ent_rows.append([_ENT_CLASS[cls], row["Name"] or row["Descr"], row["ModelName"], row["SerialNum"],
                                 row["HardwareRev"], row["FirmwareRev"] or row["SoftwareRev"]])
                if cls != "3" and row["SerialNum"]:
                    hardware.append(Fact(key=f"{_ENT_CLASS[cls]} {row['Name'] or idx}",
                                         value=f"{row['ModelName'] or row['Descr']} SN {row['SerialNum']}".strip()))

        apc = {k: scalar(k) for k in APC_OIDS if scalar(k)}
        model = chassis.get("ModelName") or apc.get("upsBasicIdentModel") or chassis.get("Descr") or None
        serial = chassis.get("SerialNum") or apc.get("upsAdvIdentSerialNumber") or None
        os_version = chassis.get("SoftwareRev") or chassis.get("FirmwareRev") or apc.get("upsAdvIdentFirmwareRevision") \
            or _version_from_descr(descr)

        # interfaces
        names, descrs, aliases = col("ifName"), col("ifDescr"), col("ifAlias")
        ip_by_if: dict[str, list[IPAddress]] = {}
        masks = col("ipAdEntNetMask")
        for key, ifidx in col("ipAdEntIfIndex").items():
            addr = col("ipAdEntAddr").get(key, key)
            prefix = _prefix(masks.get(key))
            ip_by_if.setdefault(ifidx, []).append(IPAddress(address=f"{addr}/{prefix}" if prefix is not None else addr))
        interfaces = []
        for idx in sorted(set(descrs) | set(names), key=lambda x: to_int(x) or 0):
            hs = to_int(col("ifHighSpeed").get(idx))
            sp = to_int(col("ifSpeed").get(idx))
            mbps = hs if hs else (sp // 1_000_000 if sp else None)
            interfaces.append(Interface(
                name=names.get(idx) or descrs.get(idx) or f"ifIndex {idx}",
                description=aliases.get(idx) or None, kind=_IF_KIND.get(col("ifType").get(idx, ""), "physical"),
                enabled=col("ifAdminStatus").get(idx, "1") == "1",
                oper_up={"1": True, "2": False}.get(col("ifOperStatus").get(idx, "")),
                speed=f"{mbps} Mb" if mbps else None, mtu=to_int(col("ifMtu").get(idx)),
                mac=col("ifPhysAddress").get(idx) or None, ipv4=ip_by_if.get(idx, []),
                mode=PortMode.routed if ip_by_if.get(idx) else PortMode.unknown,
                extra={"ifIndex": idx, **({"ifDescr": descrs[idx]} if names.get(idx) and descrs.get(idx)
                                          and descrs[idx] != names[idx] else {})}))
        mgmt_ip = next((a.address.split("/")[0] for i in interfaces if i.kind != "loopback" for a in i.ipv4
                        if not a.address.startswith("127.")), None)

        # LLDP
        neighbors = []
        loc_desc, loc_id = col("lldpLocPortDesc"), col("lldpLocPortId")
        for key, sysname in col("lldpRemSysName").items() or {k: "" for k in col("lldpRemChassisId")}.items():
            parts = key.split(".")
            lport = parts[1] if len(parts) >= 3 else parts[0]
            local = loc_desc.get(lport) or loc_id.get(lport) or names.get(lport) or descrs.get(lport) or lport
            neighbors.append(Neighbor(
                local_port=local, remote_device=sysname or col("lldpRemChassisId").get(key, "?"),
                remote_port=col("lldpRemPortDesc").get(key) or col("lldpRemPortId").get(key) or None,
                remote_platform=((col("lldpRemSysDesc").get(key) or "").splitlines() or [""])[0][:80] or None, protocol="lldp",
                remote_chassis=col("lldpRemChassisId").get(key) or None))

        # management (what we can know from the agent itself)
        meta = out.get("_meta") if isinstance(out.get("_meta"), dict) else {}
        snmp = SnmpConfig(enabled=True, location=scalar("sysLocation"), contact=scalar("sysContact"))
        if meta.get("version"):
            snmp.versions = [str(meta["version"])]
        if meta.get("community_hint"):
            snmp.communities = [f"{meta['community_hint']} (RO)"]
        if meta.get("user"):
            snmp.v3_users = [f"{meta['user']} ({meta.get('level', '?')}, "
                             f"{meta.get('auth_protocol') or '-'}/{meta.get('priv_protocol') or '-'})"]

        sections: list[Section] = []
        sections.append(Section(id="snmp-system", title="SNMP system group", facts=[
            Fact(key=k, value=v) for k, v in (
                ("sysDescr", descr), ("sysObjectID", oid + (f" ({vendor})" if vendor else "")),
                ("sysUpTime", _uptime(ticks) or ""), ("sysContact", scalar("sysContact") or ""),
                ("sysLocation", scalar("sysLocation") or "")) if v]))
        if ent_rows:
            sections.append(Section(id="snmp-entity", title="Physical inventory (ENTITY-MIB)", tables=[
                Table(columns=["Class", "Name", "Model", "Serial", "HW rev", "FW/SW rev"], rows=ent_rows)]))
        if apc:
            sections.append(_apc_section(apc))

        dev = Device(
            hostname=scalar("sysName") or raw.target, role=_role(descr, vendor, ent_no, bool(apc)), vendor=vendor,
            platform=self.id, model=model, os_name=_os_name(descr, vendor), os_version=os_version, serial=serial,
            uptime=_uptime(ticks), mgmt_ip=mgmt_ip, location=scalar("sysLocation"), contact=scalar("sysContact"),
            hardware=hardware, collected_at=collected or datetime.now(UTC), collection_method=raw.method,
            source=raw.target, collection_warnings=warnings, interfaces=interfaces, neighbors=neighbors,
            sections=sections)
        dev.management.snmp = snmp
        return dev


# =========================================================================== helpers


def _prefix(mask: str | None) -> int | None:
    try:
        return sum(bin(int(x)).count("1") for x in str(mask).split(".")) if mask and mask.count(".") == 3 else None
    except ValueError:
        return None


def _uptime(ticks: int | None) -> str | None:
    if ticks is None:
        return None
    s = ticks // 100
    return f"{s // 86400} days, {s % 86400 // 3600:02d}:{s % 3600 // 60:02d}"


def _version_from_descr(descr: str) -> str | None:
    m = re.search(r"\bVersion\s+([\w.()\-]+)", descr, re.I) or re.search(r"\bv(\d+\.\d+[\w.\-]*)", descr)
    return m.group(1).rstrip(",") if m else None


def _os_name(descr: str, vendor: str | None) -> str | None:
    for pat, name in ((r"IOS[ -]?XE", "IOS-XE"), (r"NX-OS", "NX-OS"), (r"\bIOS\b", "IOS"), (r"JUNOS", "Junos"),
                      (r"ArubaOS-CX|AOS-CX", "AOS-CX"), (r"FortiOS|FortiGate", "FortiOS"), (r"PAN-OS", "PAN-OS"),
                      (r"RouterOS", "RouterOS"), (r"VMware ESXi", "ESXi"), (r"Windows", "Windows"),
                      (r"Linux", "Linux"), (r"Network Management Card|AOS", "APC NMC AOS")):
        if re.search(pat, descr, re.I):
            return name
    return vendor


def _role(descr: str, vendor: str | None, ent_no: int | None, ups: bool) -> DeviceRole:
    d = descr.lower()
    if ups or ent_no in (318, 534, 476, 13742, 10418) or re.search(r"\bups\b|\bpdu\b", d):
        return DeviceRole.other  # power: UPS / PDU / KVM
    if ent_no in (12356, 25461, 2620, 8741) or re.search(r"firewall|fortigate|\basa\b|pan-os", d):
        return DeviceRole.firewall
    if ent_no in (6574, 24681, 789) or re.search(r"\bnas\b|storage|diskstation", d):
        return DeviceRole.storage
    if re.search(r"printer|laserjet|imagerunner|bizhub|ecosys|mfp", d) or ent_no in (367, 1602, 2435, 253, 1347, 18334):
        return DeviceRole.other
    if re.search(r"access point|wireless|\bwlc\b|\bap\d", d) or ent_no == 14179:
        return DeviceRole.wireless
    if "esxi" in d:
        return DeviceRole.hypervisor
    if re.search(r"switch|catalyst|cat\d|c9[2-5]00|ws-c|c[23]9[56]0|c3[68]50|nexus|procurve|aruba|ex\d{4}|"
                 r"comware|icx|cbs\d|sg\d{3}|aos-cx|edgeswitch", d):
        return DeviceRole.switch
    if re.search(r"router|isr\d|asr\d|routeros|ios xr|\bmx\d|c8[23]00", d) or (ent_no == 9 and "ios" in d):
        return DeviceRole.router
    if re.search(r"linux|windows|freebsd|sunos", d) or ent_no in (8072, 311):
        return DeviceRole.server
    return DeviceRole.other


def _apc_section(apc: dict[str, str]) -> Section:
    batt = {"1": "unknown", "2": "normal", "3": "low", "4": "in fault"}.get(apc.get("upsBasicBatteryStatus", ""), "")
    outp = {"2": "on line", "3": "on battery", "4": "on smart boost", "6": "software bypass", "7": "off",
            "9": "switched bypass", "12": "on smart trim", "14": "eco mode"}.get(apc.get("upsBasicOutputStatus", ""), "")
    replace = {"1": "no", "2": "YES - replace battery"}.get(apc.get("upsAdvBatteryReplaceIndicator", ""), "")
    test = {"1": "ok", "2": "failed", "3": "invalid test", "4": "in progress"}.get(
        apc.get("upsAdvTestDiagnosticsResults", ""), "")
    runtime = to_int(apc.get("upsAdvBatteryRunTimeRemaining"))
    facts = [Fact(key=k, value=v) for k, v in (
        ("Model", apc.get("upsBasicIdentModel", "")), ("Serial", apc.get("upsAdvIdentSerialNumber", "")),
        ("Firmware", apc.get("upsAdvIdentFirmwareRevision", "")),
        ("Manufactured", apc.get("upsAdvIdentDateOfManufacture", "")),
        ("Output status", outp), ("Output load", f"{apc['upsAdvOutputLoad']} %" if apc.get("upsAdvOutputLoad") else ""),
        ("Input voltage", f"{apc['upsAdvInputLineVoltage']} V" if apc.get("upsAdvInputLineVoltage") else ""),
        ("Battery status", batt),
        ("Battery capacity", f"{apc['upsAdvBatteryCapacity']} %" if apc.get("upsAdvBatteryCapacity") else ""),
        ("Runtime remaining", f"{runtime // 6000} min" if runtime is not None else ""),
        ("Battery temperature", f"{apc['upsAdvBatteryTemperature']} °C" if apc.get("upsAdvBatteryTemperature") else ""),
        ("Battery replacement needed", replace),
        ("Battery last replaced", apc.get("upsBasicBatteryLastReplaceDate", "")),
        ("Last self-test", f"{test} ({apc.get('upsAdvTestLastDiagnosticsDate', '?')})" if test else "")) if v]
    return Section(id="snmp-ups", title="UPS status (APC PowerNet-MIB)", facts=facts, summary_relevant=True)


register(SnmpDriver())
