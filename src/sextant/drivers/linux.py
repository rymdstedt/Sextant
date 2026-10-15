"""Generic Linux server driver (SSH via netmiko, read-only commands only).

Every command in ``COMMANDS`` passes ``sextant.drivers._ssh.assert_read_only``.
Shell operators (``||``, ``2>/dev/null``) are not allowed, so alternative
config file locations are read with one multi-file ``cat``; the resulting
``cat: ...: No such file or directory`` lines are ignored by the parser.
"""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sextant.drivers import register
from sextant.drivers._ssh import assert_read_only, run_commands
from sextant.drivers._util import parse_dt, to_int
from sextant.drivers.base import Credentials, Driver, RawCollection, Target
from sextant.model import (
    Device,
    DeviceRole,
    Fact,
    Interface,
    IPAddress,
    LocalUser,
    PortMode,
    Route,
    Section,
    Table,
)
from sextant.redact import redact_text

C_HOSTNAMECTL = "hostnamectl"
C_OS = "cat /etc/os-release"
C_KERNEL = "uname -r"
C_UPTIME = "uptime -p"
C_LSCPU = "lscpu"
C_FREE = "free -m"
C_ADDR = "ip -j addr"
C_ROUTE = "ip -j route"
C_LSBLK = "lsblk -J -o NAME,SIZE,TYPE,MOUNTPOINT,FSTYPE"
C_DF = "df -hPT"
C_SERVICES = "systemctl list-units --type=service --state=running --no-pager --plain"
C_LISTEN = "ss -tlnpH"
C_TIME = "timedatectl show"
C_RESOLV = "cat /etc/resolv.conf"
C_RESOLV_UP = "cat /run/systemd/resolve/resolv.conf"  # upstream servers behind the 127.0.0.53 stub
C_NTP = "cat /etc/chrony/chrony.conf /etc/chrony.conf /etc/ntp.conf /etc/systemd/timesyncd.conf"
C_SSHD = "cat /etc/ssh/sshd_config"
C_SSHD_D = "cat /etc/ssh/sshd_config.d/*.conf"
C_RSYSLOG = "cat /etc/rsyslog.conf"
C_RSYSLOG_D = "cat /etc/rsyslog.d/*.conf"

COMMANDS = [C_HOSTNAMECTL, C_OS, C_KERNEL, C_UPTIME, C_LSCPU, C_FREE, C_ADDR, C_ROUTE, C_LSBLK, C_DF, C_SERVICES,
            C_LISTEN, C_TIME, C_RESOLV, C_RESOLV_UP, C_NTP, C_SSHD, C_SSHD_D, C_RSYSLOG, C_RSYSLOG_D]
for _c in COMMANDS:  # fail at import time rather than on a customer's server
    assert_read_only(_c)

FS_WARN_PCT = 80
_SKIP_FS = {"tmpfs", "devtmpfs", "efivarfs", "overlay", "squashfs", "proc", "sysfs", "devpts", "cgroup2", "nsfs"}


def _text(out: dict[str, Any], cmd: str) -> str:
    """Command output without 'cat: x: No such file' noise."""
    v = out.get(cmd)
    if not isinstance(v, str):
        return ""
    return "\n".join(ln for ln in v.splitlines() if not re.match(r"^cat: .*: (No such file|Permission denied)", ln))


def _json(out: dict[str, Any], cmd: str, warnings: list[str]) -> Any:
    text = _text(out, cmd).strip()
    if not text:
        return None
    try:
        return json.loads(text[min((i for i in (text.find("["), text.find("{")) if i >= 0), default=0):])
    except ValueError:
        warnings.append(f"linux: could not parse JSON from '{cmd}'")
        return None


def _kv(text: str, sep: str = ":") -> dict[str, str]:
    out: dict[str, str] = {}
    for ln in text.splitlines():
        if sep in ln:
            k, _, v = ln.partition(sep)
            out.setdefault(k.strip(), v.strip().strip('"'))
    return out


def _conf_lines(text: str) -> list[str]:
    return [ln.strip() for ln in text.splitlines() if ln.strip() and not ln.strip().startswith(("#", ";"))]


class LinuxDriver(Driver):
    id = "linux"
    label = "Linux server"
    methods = ("ssh", "file")

    def collect(self, target: Target, creds: Credentials) -> RawCollection:  # pragma: no cover - live only
        raw = run_commands(target, creds, "linux", COMMANDS, self.id)
        raw.outputs = {k: redact_text(v) if isinstance(v, str) else v for k, v in raw.outputs.items()}
        raw.outputs["collected_at"] = datetime.now(UTC).isoformat()
        return raw

    def from_file(self, path: Path) -> RawCollection:
        """Import saved command outputs: a JSON object {command: output} or a RawCollection dump, or a text
        file with sections headed '### <command>' (e.g. produced by running COMMANDS by hand)."""
        text = path.read_text(encoding="utf-8", errors="replace")
        outputs: dict[str, Any] = {}
        try:
            data = json.loads(text)
            if isinstance(data, dict):
                outputs = data.get("outputs", data) if "driver" in data else data
        except ValueError:
            cmd = None
            for ln in text.splitlines():
                if ln.startswith("### "):
                    cmd = ln[4:].strip()
                    outputs[cmd] = ""
                elif cmd is not None:
                    outputs[cmd] += ln + "\n"
        outputs = {k: redact_text(v) if isinstance(v, str) else v for k, v in outputs.items()}
        return RawCollection(driver=self.id, target=path.name, method="file", outputs=outputs)

    # ----------------------------------------------------------------------- parse

    def parse(self, raw: RawCollection) -> Device:
        out = raw.outputs or {}
        warnings = list(raw.warnings)
        for cmd in (C_HOSTNAMECTL, C_ADDR, C_DF):
            if not _text(out, cmd):
                warnings.append(f"linux: no output for '{cmd}'")
        collected = parse_dt(out.get("collected_at"))
        hn = _kv(_text(out, C_HOSTNAMECTL))
        osr = _kv(_text(out, C_OS), "=")
        cpu = _kv(_text(out, C_LSCPU))
        tdc = _kv(_text(out, C_TIME), "=")
        virt_kind = hn.get("Virtualization")
        hostname = hn.get("Static hostname") or hn.get("Transient hostname") or raw.target

        hardware: list[Fact] = []
        for key, label in (("Hardware Vendor", "Hardware vendor"), ("Hardware Model", "Hardware model"),
                           ("Virtualization", "Virtualization"), ("Chassis", "Chassis"),
                           ("Architecture", "Architecture"), ("Firmware Version", "Firmware")):
            if hn.get(key):
                hardware.append(Fact(key=label, value=re.sub(r"[^\x20-\x7e]", "", hn[key]).strip()))
        if cpu.get("Model name"):
            sockets = to_int(cpu.get("Socket(s)")) or 1
            cores = (to_int(cpu.get("Core(s) per socket")) or 0) * sockets
            hardware.append(Fact(key="CPU", value=f"{cpu['Model name']} ({cpu.get('CPU(s)', '?')} vCPU, "
                                                  f"{sockets} socket(s), {cores or '?'} cores)"))
        mem = re.search(r"^Mem:\s+(\d+)\s+(\d+)\s+\d+\s+\d+\s+\d+\s+(\d+)", _text(out, C_FREE), re.M)
        if mem:
            hardware.append(Fact(key="Memory", value=f"{int(mem.group(1)) / 1024:.1f} GB total, "
                                                     f"{int(mem.group(3)) / 1024:.1f} GB available"))
        kernel = _text(out, C_KERNEL).strip() or hn.get("Kernel", "").replace("Linux ", "") or None
        if kernel:
            hardware.append(Fact(key="Kernel", value=kernel))

        # interfaces
        interfaces = []
        for itf in _json(out, C_ADDR, warnings) or []:
            if not isinstance(itf, dict) or not itf.get("ifname"):
                continue
            name = str(itf["ifname"])
            flags = itf.get("flags") or []
            kind = _if_kind(name, itf)
            i = Interface(name=name, kind=kind, enabled="UP" in flags,
                          oper_up=(itf.get("operstate") == "UP") or (kind == "loopback" and "UP" in flags)
                          if itf.get("operstate") else None,
                          mtu=to_int(itf.get("mtu")), mac=itf.get("address") if kind != "loopback" else None,
                          mode=PortMode.routed if itf.get("addr_info") else PortMode.unknown,
                          lag=itf.get("master") if str(itf.get("master", "")).startswith("bond") else None)
            if itf.get("master") and not i.lag:
                i.extra["bridge"] = str(itf["master"])
            for a in itf.get("addr_info") or []:
                if a.get("family") == "inet":
                    i.ipv4.append(IPAddress(address=f"{a.get('local')}/{a.get('prefixlen')}",
                                            secondary=bool(a.get("secondary"))))
                elif a.get("family") == "inet6" and a.get("scope") != "link":
                    i.ipv6.append(f"{a.get('local')}/{a.get('prefixlen')}")
            interfaces.append(i)

        # routes
        routes = []
        for r in _json(out, C_ROUTE, warnings) or []:
            if not isinstance(r, dict) or not r.get("dst"):
                continue
            routes.append(Route(prefix="0.0.0.0/0" if r["dst"] == "default" else str(r["dst"]),
                                next_hop=r.get("gateway"), interface=r.get("dev"),
                                protocol={"kernel": "connected", "boot": "static"}.get(r.get("protocol"),
                                                                                       r.get("protocol") or "static"),
                                distance=to_int(r.get("metric"))))
        default = next((r for r in _json(out, C_ROUTE, []) or []
                        if isinstance(r, dict) and r.get("dst") == "default"), {})
        mgmt_ip = default.get("prefsrc")
        if not mgmt_ip:
            dev = next((i for i in interfaces if i.name == default.get("dev") and i.ipv4), None) or \
                  next((i for i in interfaces if i.kind == "physical" and i.ipv4), None)
            mgmt_ip = dev.ipv4[0].address.split("/")[0] if dev else None

        dev = Device(
            hostname=hostname, role=DeviceRole.server, platform=self.id,
            vendor=osr.get("NAME") if virt_kind else (hn.get("Hardware Vendor") or osr.get("NAME")),
            model=f"Virtual machine ({virt_kind})" if virt_kind else hn.get("Hardware Model"),
            os_name=osr.get("NAME") or (hn.get("Operating System") or "").split(" ")[0] or None,
            os_version=osr.get("VERSION") or osr.get("VERSION_ID"),
            uptime=_text(out, C_UPTIME).strip().removeprefix("up ") or None, mgmt_ip=mgmt_ip,
            hardware=hardware, collected_at=collected or datetime.now(UTC),
            collection_method=raw.method, source=raw.target, collection_warnings=warnings,
            interfaces=interfaces, routes=routes)

        self._management(dev, out)
        dev.sections = [s for s in (
            self._system_section(osr, hn, tdc, out),
            self._disks_section(_json(out, C_LSBLK, warnings)),
            *self._fs_sections(_text(out, C_DF)),
            self._listen_section(_text(out, C_LISTEN)),
            self._services_section(_text(out, C_SERVICES)),
        ) if s is not None]
        sshd = self._sshd_section(out)
        if sshd:
            dev.sections.append(sshd)
        return dev

    # ----------------------------------------------------------------------- pieces

    @staticmethod
    def _management(dev: Device, out: dict[str, Any]) -> None:
        m = dev.management
        tdc = _kv(_text(out, C_TIME), "=")
        m.timezone = tdc.get("Timezone")
        for ln in _conf_lines(_text(out, C_NTP)):
            parts = ln.split()
            if parts[0] in ("server", "pool", "peer") and len(parts) > 1 and parts[1] not in m.ntp_servers:
                m.ntp_servers.append(parts[1])
            elif ln.startswith(("NTP=", "FallbackNTP=")) and not ln.startswith("FallbackNTP"):
                m.ntp_servers += [s for s in ln.split("=", 1)[1].split() if s not in m.ntp_servers]
        upstream = _text(out, C_RESOLV_UP)
        resolv = upstream if re.search(r"^nameserver", upstream, re.M) else _text(out, C_RESOLV)
        for ln in _conf_lines(resolv):
            parts = ln.split()
            if parts[0] == "nameserver" and len(parts) > 1:
                m.dns_servers.append(parts[1])
            elif parts[0] in ("search", "domain") and len(parts) > 1 and not m.domain:
                m.domain = parts[1]
        for ln in _conf_lines(_text(out, C_RSYSLOG) + "\n" + _text(out, C_RSYSLOG_D)):
            tok = ln.split()[-1] if len(ln.split()) > 1 else ""
            if tok.startswith("@"):  # legacy: *.* @host:514 (udp) / @@host:514 (tcp), optional @@(o)host
                proto = "tcp" if tok.startswith("@@") else "udp"
                dest = re.sub(r"^@@?(\([^)]*\))?", "", tok).split(";")[0]
                hm = re.match(r"^\[?([^\]]+?)\]?(?::(\d+))?$", dest) if dest.count(":") <= 1 or dest.startswith("[") \
                    else re.match(r"^(.+)()$", dest)
                if hm:
                    m.syslog_servers.append(f"{hm.group(1)}:{hm.group(2) or 514}/{proto}")
                continue
            if "omfwd" in ln:
                tgt = re.search(r'target="([^"]+)"', ln)
                if tgt:
                    port = re.search(r'port="(\d+)"', ln)
                    proto = re.search(r'protocol="(\w+)"', ln)
                    m.syslog_servers.append(f"{tgt.group(1)}:{port.group(1) if port else 514}/"
                                            f"{proto.group(1).lower() if proto else 'udp'}")
        sshd = _sshd_settings(out)
        listening = _listeners(_text(out, C_LISTEN))
        m.ssh = any(p == "22" or proc == "sshd" for _, p, proc in listening) or bool(sshd) or None
        m.ssh_version = "2" if m.ssh else None
        m.telnet = any(p == "23" for _, p, _ in listening)
        root = sshd.get("permitrootlogin", "prohibit-password (default)")
        m.users.append(LocalUser(name="root", privilege="root", auth=f"ssh PermitRootLogin {root}"))

    @staticmethod
    def _system_section(osr: dict[str, str], hn: dict[str, str], tdc: dict[str, str],
                        out: dict[str, Any]) -> Section | None:
        facts = []
        for k, v in (("OS", osr.get("PRETTY_NAME") or hn.get("Operating System")),
                     ("OS support URL", osr.get("SUPPORT_URL")),
                     ("Timezone", tdc.get("Timezone")), ("NTP enabled", tdc.get("NTP")),
                     ("Clock synchronized", tdc.get("NTPSynchronized")),
                     ("Machine ID", hn.get("Machine ID"))):
            if v:
                facts.append(Fact(key=k, value=v))
        return Section(id="linux-system", title="Operating system", facts=facts) if facts else None

    @staticmethod
    def _disks_section(data: Any) -> Section | None:
        rows: list[list[str]] = []

        def walk(nodes: Any, depth: int) -> None:
            for n in nodes or []:
                if not isinstance(n, dict) or n.get("type") in ("loop", "rom"):
                    continue
                mp = n.get("mountpoint") or ",".join(x for x in (n.get("mountpoints") or []) if x)
                rows.append([("  " * depth) + str(n.get("name", "")), str(n.get("type") or ""),
                             str(n.get("size") or ""), str(n.get("fstype") or ""), str(mp or "")])
                walk(n.get("children"), depth + 1)

        walk((data or {}).get("blockdevices") if isinstance(data, dict) else None, 0)
        if not rows:
            return None
        return Section(id="linux-disks", title="Block devices", tables=[
            Table(columns=["Device", "Type", "Size", "Filesystem", "Mount point"], rows=rows)])

    @staticmethod
    def _fs_sections(text: str) -> list[Section]:
        rows, full = [], []
        for ln in text.splitlines():
            p = ln.split()
            if len(p) < 7 or p[0] == "Filesystem" or not p[5].endswith("%"):
                continue
            fs, typ, size, used, avail, pct, mount = p[0], p[1], p[2], p[3], p[4], p[5], " ".join(p[6:])
            if typ in _SKIP_FS:
                continue
            usep = to_int(pct.rstrip("%")) or 0
            status = "critical (> 90 %)" if usep > 90 else (f"warning (> {FS_WARN_PCT} %)" if usep > FS_WARN_PCT else "ok")
            row = [mount, fs, typ, size, used, avail, pct, status]
            rows.append(row)
            if usep > FS_WARN_PCT:
                full.append(row)
        if not rows:
            return []
        cols = ["Mount point", "Device", "Type", "Size", "Used", "Available", "Use %", "Status"]
        secs = [Section(id="linux-filesystems", title="Filesystems",
                        tables=[Table(columns=cols, rows=rows, note=f"Status flags usage above {FS_WARN_PCT} %.")])]
        if full:
            secs.append(Section(id="linux-filesystems-full", title=f"Filesystems above {FS_WARN_PCT} % used",
                                summary_relevant=True, tables=[Table(columns=cols, rows=full)]))
        return secs

    @staticmethod
    def _listen_section(text: str) -> Section | None:
        rows = [[addr, port, proc or ""] for addr, port, proc in _listeners(text)]
        if not rows:
            return None
        return Section(id="linux-listening", title="Listening TCP services", tables=[
            Table(columns=["Address", "Port", "Process"], rows=sorted(rows, key=lambda r: (to_int(r[1]) or 0, r[0])))])

    @staticmethod
    def _services_section(text: str) -> Section | None:
        rows = []
        for ln in text.splitlines():
            p = ln.split(None, 4)
            if len(p) >= 4 and p[0].endswith(".service"):
                rows.append([p[0].removesuffix(".service"), p[2], p[3], p[4] if len(p) > 4 else ""])
        if not rows:
            return None
        return Section(id="linux-services", title="Running services", tables=[
            Table(columns=["Service", "Active", "State", "Description"], rows=rows)])

    @staticmethod
    def _sshd_section(out: dict[str, Any]) -> Section | None:
        s = _sshd_settings(out)
        if not s:
            return None
        labels = {"port": "Port", "listenaddress": "ListenAddress", "permitrootlogin": "PermitRootLogin",
                  "passwordauthentication": "PasswordAuthentication", "pubkeyauthentication": "PubkeyAuthentication",
                  "kbdinteractiveauthentication": "KbdInteractiveAuthentication", "allowusers": "AllowUsers",
                  "allowgroups": "AllowGroups", "x11forwarding": "X11Forwarding", "maxauthtries": "MaxAuthTries",
                  "usepam": "UsePAM", "clientaliveinterval": "ClientAliveInterval", "banner": "Banner"}
        facts = [Fact(key=label, value=s[k]) for k, label in labels.items() if k in s]
        if "permitrootlogin" not in s:
            facts.append(Fact(key="PermitRootLogin", value="prohibit-password (default)"))
        return Section(id="linux-sshd", title="SSH daemon", facts=facts)


# =========================================================================== helpers


def _if_kind(name: str, itf: dict[str, Any]) -> str:
    if itf.get("link_type") == "loopback" or name == "lo":
        return "loopback"
    if name.startswith("bond"):
        return "lag"
    if "." in name or name.startswith("vlan"):
        return "vlan"
    if name.startswith(("docker", "br-", "veth", "virbr", "vmbr", "cni", "flannel", "tun", "tap", "wg", "lxc")):
        return "virtual"
    return "physical"


def _sshd_settings(out: dict[str, Any]) -> dict[str, str]:
    """Effective sshd settings: first value wins; drop-ins (Include at top on Debian/Ubuntu) come first."""
    s: dict[str, str] = {}
    for ln in _conf_lines(_text(out, C_SSHD_D) + "\n" + _text(out, C_SSHD)):
        if ln.lower().startswith("match "):
            break  # Match blocks are conditional; keep only global settings
        k, _, v = ln.partition(" ")
        if k.lower() != "include" and v.strip():
            s.setdefault(k.lower(), v.strip())
    return s


def _listeners(text: str) -> list[tuple[str, str, str | None]]:
    rows: list[tuple[str, str, str | None]] = []
    for ln in text.splitlines():
        p = ln.split()
        if len(p) < 4:
            continue
        local = p[3] if p[0] in ("LISTEN", "UNCONN") else p[2] if len(p) > 2 else ""
        m = re.match(r"^(.*):(\d+|\*)$", local)
        if not m:
            continue
        addr = m.group(1).split("%")[0]
        proc = re.search(r'users:\(\("([^"]+)"', ln)
        row = (addr, m.group(2), proc.group(1) if proc else None)
        if row not in rows:
            rows.append(row)
    return rows


register(LinuxDriver())
