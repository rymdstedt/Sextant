"""Cisco NX-OS driver (Nexus 3k/5k/7k/9k).

Reuses the Cisco-style parser from cisco_ios and overrides what differs on NX-OS:
version/inventory layout, feature-driven management services, role-based users,
default port state, vPC and the `feature` list.
"""

from __future__ import annotations

import re

from sextant import model as m
from sextant.drivers import register
from sextant.drivers._util import blocks, first, short_ifname
from sextant.drivers.cisco_ios import CiscoIosDriver, CiscoParser, cisco_auth, kv_lines, output

NXOS_COMMANDS = [
    "show running-config",
    "show version",
    "show inventory",
    "show interface status",
    "show ip interface brief vrf all",
    "show vlan brief",
    "show cdp neighbors detail",
    "show lldp neighbors detail",
    "show ip route vrf all",
    "show ip ospf neighbors",
    "show spanning-tree summary",
    "show port-channel summary",
    "show vpc",
    "show feature",
]

# NX-OS: 5 = SHA-256 crypt ($5$), 7 = reversible (only on some features), 0 = clear text
_NXOS_HASH_TYPES = {"0": "plain text", "5": "SHA-256 crypt", "7": "reversible", "8": "PBKDF2-SHA256",
                    "9": "scrypt"}


class NxosParser(CiscoParser):
    os_name_default = "NX-OS"
    lag_prefix = "port-channel"
    default_trunk_vlans = "1-4094"
    status_cmds = ("show interface status", "show interfaces status")
    brief_cmds = ("show ip interface brief vrf all", "show ip interface brief")
    lag_cmds = ("show port-channel summary", "show etherchannel summary")
    route_cmds = ("show ip route vrf all", "show ip route")

    def __init__(self, raw, platform):
        super().__init__(raw, platform)
        self.is_switch = True
        self.default_l2 = bool(re.search(r"^system default switchport\s*$", self.cfg, re.M))
        self.features = re.findall(r"^feature (\S+)", self.cfg, re.M)

    def _finish_iface(self, itf: m.Interface, st: dict) -> None:
        # NX-OS prints "no shutdown" for enabled ports; physical ports without it are admin-down by default.
        if itf.kind == "physical" and st.get("admin") is None and self.cfg:
            itf.enabled = False
        super()._finish_iface(itf, st)

    def parse_version(self) -> None:
        d, ver = self.dev, output(self.raw, *self.version_cmds)
        if not ver:
            d.collection_warnings.append("show version not collected: OS version, model and serial may be missing.")
            d.os_version = first(r"^version\s+(\S+)", self.cfg)
            return
        d.os_version = first(r"NXOS: version\s+(\S+)", ver) or first(r"system:\s+version\s+(\S+)", ver)
        chassis = first(r"cisco Nexus\s*\S*\s+(\S+)\s+[Cc]hassis", ver)
        if chassis and not output(self.raw, "show inventory"):
            d.model = chassis
        d.serial = first(r"Processor [Bb]oard ID (\S+)", ver)
        d.uptime = first(r"Kernel uptime is (.+)$", ver)
        if not first(r"^(?:hostname|switchname)\s+(\S+)", self.cfg):
            d.hostname = first(r"Device name:\s*(\S+)", ver) or d.hostname
        for label, pat in (("Chassis", r"(cisco Nexus.*[Cc]hassis.*)$"), ("CPU / memory", r"^\s*(.*CPU.*with \d+ kB of memory)"),
                           ("NX-OS image", r"NXOS image file is:\s*(\S+)"), ("BIOS", r"BIOS: version\s+(\S+)"),
                           ("Last reset reason", r"Reason:\s*(.+)$")):
            val = first(pat, ver)
            if val:
                d.hardware.append(m.Fact(key=label, value=val.strip()))

    def parse_stp(self) -> None:
        super().parse_stp()
        st = self.dev.spanning_tree
        if st and st.mode == "pvst (default)":
            st.mode = "rapid-pvst (default)"

    def parse_management(self) -> None:
        super().parse_management()
        mg, cfg = self.dev.management, self.cfg
        if not cfg:
            return
        mg.ssh = not re.search(r"^no feature ssh", cfg, re.M)
        mg.ssh_version = "2" if mg.ssh else None
        mg.telnet = "telnet" in self.features
        nxapi = "nxapi" in self.features
        mg.https = nxapi and not re.search(r"^no nxapi https", cfg, re.M)
        mg.http = nxapi and bool(re.search(r"^nxapi http port", cfg, re.M))
        mg.password_encryption = True  # NX-OS always stores local passwords hashed
        users: list[m.LocalUser] = []
        for name, rest in re.findall(r"^username (\S+)(.*)$", cfg, re.M):
            u = next((x for x in users if x.name == name), None)
            if u is None:
                u = m.LocalUser(name=name)
                users.append(u)
            roles = re.findall(r"\brole (\S+)", rest)
            if roles:
                u.privilege = ", ".join(x for x in (u.privilege, *roles) if x)
            auth = cisco_auth(rest, _NXOS_HASH_TYPES)
            if auth and auth.startswith("password type 5"):  # NX-OS type 5 is SHA-256 crypt, not IOS MD5
                auth = "password hashed (SHA-256 crypt)"
            if auth and auth != "ssh-key":
                u.auth = auth if not u.auth else f"{u.auth} + {auth}" if "ssh-key" in u.auth else u.auth
            elif auth == "ssh-key":
                u.auth = f"{u.auth} + ssh-key" if u.auth else "ssh-key"
        mg.users = users
        if not mg.mgmt_vrf and re.search(r"^vrf context management", cfg, re.M):
            mg.mgmt_vrf = "management"

    def parse_ha(self) -> None:
        super().parse_ha()
        vpc = output(self.raw, "show vpc", "show vpc brief")
        dom_cfg = next(((h, ls) for h, ls in blocks(self.cfg, r"^vpc domain \d+")), None)
        if not vpc and not dom_cfg:
            return
        kv = kv_lines(vpc)
        details: dict[str, str] = {}
        for key in ("Peer status", "vPC keep-alive status", "Configuration consistency status",
                    "Per-vlan consistency status", "Type-2 consistency status", "vPC role", "Number of vPCs configured",
                    "Peer Gateway", "Auto-recovery status"):
            if key in kv:
                details[key] = kv[key]
        domain = kv.get("vPC domain id")
        if dom_cfg:
            domain = domain or dom_cfg[0].split()[-1]
            for ln in dom_cfg[1]:
                if ln.startswith("peer-keepalive"):
                    details["peer-keepalive"] = ln.removeprefix("peer-keepalive ").strip()
                elif ln.startswith(("role priority", "system-priority")):
                    details[ln.rsplit(None, 1)[0]] = ln.rsplit(None, 1)[1]
                elif ln in ("peer-gateway", "auto-recovery", "ip arp synchronize", "layer3 peer-router"):
                    details.setdefault(ln, "enabled")
        peer_links = [i.name for i in self.ifs.values() if i.extra.get("vpc") == "peer-link"]
        peer_ports = {p.lower() for i in self.ifs.values() if i.name in peer_links for p in i.lag_members}
        peers = sorted({n.remote_device for n in self.dev.neighbors if n.local_port.lower() in peer_ports})
        peer_ok = "formed ok" in kv.get("Peer status", "")
        cons_ok = kv.get("Configuration consistency status", "success") == "success"
        state = None
        if vpc:
            state = "ok" if peer_ok and cons_ok else "degraded"
        stack = self.dev.ha
        self.dev.ha = m.HighAvailability(mode="vpc", group=f"domain {domain}" if domain else None,
                                         members=[self.dev.hostname, *peers], state=state, details=details)
        if stack and stack.mode != "vpc":  # keep HSRP info as a detail
            self.dev.ha.details[f"{stack.mode} groups"] = stack.group or ""
        rows = []
        for ln in vpc.splitlines():
            mt = re.match(r"^(\d+)\s+(Po\d+)\s+(up|down)\s+(\S+)\s+(\S+)\s+(\S*)\s*$", ln)
            if mt:
                rows.append([mt.group(1), mt.group(2), mt.group(3), mt.group(4), mt.group(6)])
        if rows or peer_links:
            peer_line = first(r"^\d+\s+(Po\d+\s+\S+\s+\S+)\s*$", vpc)
            self.dev.sections.append(m.Section(
                id="vpc", title="vPC", summary_relevant=True,
                facts=[m.Fact(key=k, value=v) for k, v in details.items()] +
                      ([m.Fact(key="Peer-link", value=", ".join(short_ifname(p) for p in peer_links)
                               + (f" ({peer_line.split()[1]})" if peer_line else ""))] if peer_links else []),
                tables=[m.Table(title="vPC port-channels", columns=["vPC id", "Port", "Status", "Consistency",
                                                                    "Active VLANs"], rows=rows)] if rows else []))

    def parse_extras(self) -> None:
        super().parse_extras()
        rows: list[list[str]] = []
        for mt in re.finditer(r"^(\S+)\s+(\d+)\s+(enabled|disabled)\S*\s*$", output(self.raw, "show feature"), re.M):
            if mt.group(3) == "enabled" and mt.group(2) == "1":
                rows.append([mt.group(1), "enabled"])
        if not rows:
            rows = [[f, "enabled (config)"] for f in self.features]
        if rows:
            self.dev.sections.append(m.Section(
                id="nxos-features", title="NX-OS features",
                facts=[m.Fact(key="Enabled features", value=", ".join(r[0] for r in rows))]))


class CiscoNxosDriver(CiscoIosDriver):
    id = "cisco_nxos"
    label = "Cisco NX-OS (Nexus)"
    methods = ("ssh", "file")
    netmiko_type = "cisco_nxos"
    commands = tuple(NXOS_COMMANDS)
    parser_cls = NxosParser


register(CiscoNxosDriver())
