"""Management-plane hygiene: protocols, SNMP, NTP, syslog, AAA, passwords, banners."""

from __future__ import annotations

import re

from sextant.analysis import check
from sextant.model import Device, DeviceRole, Finding, Severity

_NET_ROLES = {DeviceRole.switch, DeviceRole.router, DeviceRole.firewall, DeviceRole.wireless}


def _is_net(d: Device) -> bool:
    return d.role in _NET_ROLES


@check
def insecure_mgmt_protocols(d: Device):
    m = d.management
    if m.telnet:
        yield Finding(check_id="mgmt.telnet", severity=Severity.high, title="Telnet management enabled",
                      detail="Telnet sends credentials and session data in clear text.",
                      recommendation="Disable Telnet (transport input ssh) and use SSHv2 only.")
    if m.http:
        yield Finding(check_id="mgmt.http", severity=Severity.medium, title="HTTP management enabled",
                      detail="The web management interface accepts unencrypted HTTP.",
                      recommendation="Disable HTTP admin access; allow HTTPS from management networks only.")
    if m.ssh and m.ssh_version and m.ssh_version.strip().startswith("1"):
        yield Finding(check_id="mgmt.sshv1", severity=Severity.high, title="SSH version 1 allowed",
                      recommendation="Set ip ssh version 2.")


@check
def snmp_weak(d: Device):
    s = d.management.snmp
    if not s.enabled and not s.communities:
        return
    defaults = [c for c in s.communities if c.split()[0].lower() in {"public", "private"}]
    if defaults:
        yield Finding(check_id="snmp.default-community", severity=Severity.high,
                      title="Default SNMP community in use",
                      detail=f"Communities: {', '.join(defaults)}.",
                      recommendation="Remove default communities; move to SNMPv3 authPriv.",
                      evidence=defaults)
    rw = [c for c in s.communities if re.search(r"\bRW\b|read-write|write", c, re.I)]
    if rw:
        yield Finding(check_id="snmp.rw-community", severity=Severity.high,
                      title="SNMP read-write community configured",
                      detail="Anyone with the community string can change the configuration over SNMP "
                             "(v1/v2c sends it in clear text).",
                      recommendation="Remove the RW community; use read-only SNMPv3 for monitoring.",
                      evidence=rw)
    legacy = [v for v in s.versions if v.lower() in {"v1", "v2c", "1", "2c"}]
    if legacy and not defaults:
        yield Finding(check_id="snmp.v2c", severity=Severity.low, title=f"SNMP {'/'.join(legacy)} enabled",
                      detail="SNMP v1/v2c has no encryption and community-only authentication.",
                      recommendation="Use SNMPv3 with authPriv (SHA/AES), restrict with an ACL.")
    if (s.communities and not s.acl) and _is_net(d):
        yield Finding(check_id="snmp.no-acl", severity=Severity.low, title="SNMP not restricted by ACL",
                      recommendation="Bind SNMP communities to an ACL of polling stations.")


@check
def time_and_logging(d: Device):
    if d.role == DeviceRole.hypervisor:
        return  # host-level NTP is checked per host in virtualization
    m = d.management
    if not m.ntp_servers:
        yield Finding(check_id="mgmt.no-ntp", severity=Severity.medium, title="No NTP server configured",
                      detail="Clock drift breaks log correlation, certificates and Kerberos.",
                      recommendation="Configure at least two NTP servers.")
    elif len(m.ntp_servers) == 1:
        yield Finding(check_id="mgmt.single-ntp", severity=Severity.low, title="Only one NTP server",
                      recommendation="Configure at least two NTP sources for redundancy.")
    if not m.syslog_servers:
        yield Finding(check_id="mgmt.no-syslog", severity=Severity.medium, title="No remote syslog",
                      detail="Logs are only kept locally and are lost on reboot or compromise.",
                      recommendation="Forward logs to a central syslog/SIEM.")


@check
def aaa(d: Device):
    if not _is_net(d):
        return
    a = d.management.aaa
    central = a.radius_servers or a.tacacs_servers or a.ldap_servers
    if not central:
        yield Finding(check_id="aaa.none", severity=Severity.medium, title="No central authentication (AAA)",
                      detail=f"{len(d.management.users)} local account(s); no RADIUS/TACACS+/LDAP.",
                      recommendation="Authenticate admins against TACACS+/RADIUS with local fallback only.")
    elif len(d.management.users) > 2:
        yield Finding(check_id="aaa.many-local", severity=Severity.low,
                      title=f"{len(d.management.users)} local admin accounts",
                      detail="Central AAA is configured but several local accounts remain.",
                      recommendation="Keep a single break-glass local account.",
                      evidence=[u.name for u in d.management.users])


@check
def weak_passwords(d: Device):
    weak = [u for u in d.management.users
            if u.auth and any(x in u.auth.lower() for x in ("type 7", "type 0", "plain", "clear", "type 5"))]
    if weak:
        sev = Severity.high if any("type 7" in u.auth.lower() or "type 0" in u.auth.lower() or "plain"
                                   in u.auth.lower() for u in weak) else Severity.low
        yield Finding(check_id="mgmt.weak-password-hash", severity=sev,
                      title="Weak password storage",
                      detail="Accounts use reversible or legacy password hashing.",
                      recommendation="Use 'secret' type 8/9 (scrypt/PBKDF2) for all accounts.",
                      evidence=[f"{u.name}: {u.auth}" for u in weak])
    if d.management.password_encryption is False and d.platform in ("cisco_ios", "cisco_nxos", "cisco_asa"):
        yield Finding(check_id="mgmt.no-password-encryption", severity=Severity.low,
                      title="service password-encryption disabled",
                      recommendation="Enable service password-encryption (obfuscation baseline).")


@check
def vty_and_banner(d: Device):
    if d.role not in (DeviceRole.switch, DeviceRole.router):
        return
    m = d.management
    if (m.ssh or m.telnet) and not m.vty_acl and not m.allowed_mgmt_hosts:
        yield Finding(check_id="mgmt.no-vty-acl", severity=Severity.medium, title="No ACL on VTY lines",
                      detail="SSH is reachable from every network that can route to the device.",
                      recommendation="Apply an access-class limiting management to admin subnets.")
    if m.banner is None and d.raw_config:
        yield Finding(check_id="mgmt.no-banner", severity=Severity.info, title="No login banner",
                      recommendation="Add a legal/authorized-use login banner.")
