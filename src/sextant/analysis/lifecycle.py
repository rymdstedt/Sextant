"""End-of-support software versions. Extend the table as vendors publish EoS dates.

Matching is prefix based on (platform, version) at a version boundary: os_version for network
gear, the ESXi / Proxmox VE / Windows Server version of every hypervisor host, and os-release
NAME + VERSION (or PRETTY_NAME) for Linux. Dates are end of
vendor support / security fixes as published by the vendor; keep the
`source` column honest and update this table during each review.
"""

from __future__ import annotations

import re
from datetime import date

from sextant.analysis import check
from sextant.model import Device, Finding, Severity

# platform, version prefix, end-of-support date, label
EOS_TABLE: list[tuple[str, str, date, str]] = [
    ("cisco_ios", "15.0", date(2020, 7, 31), "IOS 15.0"),
    ("cisco_ios", "15.2", date(2023, 3, 31), "IOS 15.2"),
    ("cisco_ios", "16.", date(2024, 1, 31), "IOS-XE 16.x"),
    ("cisco_ios", "17.3", date(2025, 3, 31), "IOS-XE 17.3"),
    ("cisco_ios", "17.6", date(2026, 10, 31), "IOS-XE 17.6"),
    ("cisco_asa", "9.8", date(2023, 9, 30), "ASA 9.8"),
    ("cisco_asa", "9.12", date(2024, 9, 30), "ASA 9.12"),
    ("cisco_asa", "9.14", date(2025, 9, 30), "ASA 9.14"),
    ("fortigate", "6.", date(2024, 9, 29), "FortiOS 6.x"),
    ("fortigate", "7.0", date(2026, 3, 30), "FortiOS 7.0"),
    ("paloalto", "9.", date(2023, 12, 31), "PAN-OS 9.x"),
    ("paloalto", "10.1", date(2025, 8, 31), "PAN-OS 10.1"),
    ("vmware", "6.", date(2022, 10, 15), "vSphere 6.x"),  # vCenter and ESXi 6.5 / 6.7: end of general support
    ("vmware", "7.", date(2025, 10, 2), "vSphere 7.x"),
    ("proxmox", "7.", date(2024, 7, 31), "Proxmox VE 7"),
    ("hyperv", "2008", date(2020, 1, 14), "Windows Server 2008"),
    ("hyperv", "2012", date(2023, 10, 10), "Windows Server 2012"),  # incl. 2012 R2
    ("hyperv", "2016", date(2027, 1, 12), "Windows Server 2016"),
    # linux: matched against "<os-release NAME> <VERSION or VERSION_ID>" and PRETTY_NAME
    ("linux", "Ubuntu 18.04", date(2023, 5, 31), "Ubuntu 18.04"),
    ("linux", "Ubuntu 20.04", date(2025, 5, 31), "Ubuntu 20.04"),
    ("linux", "CentOS Linux 7", date(2024, 6, 30), "CentOS Linux 7"),
    ("linux", "CentOS Linux 8", date(2021, 12, 31), "CentOS Linux 8"),
    ("linux", "CentOS Stream 8", date(2024, 5, 31), "CentOS Stream 8"),  # Stream 9 is still supported
    ("linux", "Red Hat Enterprise Linux Server 7", date(2024, 6, 30), "RHEL 7 (maintenance support)"),
    ("linux", "Debian GNU/Linux 10", date(2024, 6, 30), "Debian 10"),
    ("linux", "Debian GNU/Linux 11", date(2026, 8, 31), "Debian 11"),
]


def _versions(d: Device) -> list[tuple[str, str | None]]:
    """(version text, where) pairs to look up: the device's own OS plus, for hypervisors, every host."""
    hosts = d.virtualization.hosts if d.virtualization else []
    if d.platform == "linux":
        pretty = next((f.value for s in d.sections if s.id == "linux-system" for f in s.facts if f.key == "OS"), None)
        return [(v, None) for v in (" ".join(x for x in (d.os_name, d.os_version) if x), pretty) if v]
    if d.platform == "vmware":  # vCenter (or a standalone ESXi) version + each host's ESXi version
        out = [(d.os_version, None)] if d.os_version else []
        return out + [(m.group(1), h.name) for h in hosts if (m := re.search(r"ESXi\s+(\d+(?:\.\d+)*)", h.product or ""))]
    if d.platform == "proxmox":
        out = [(d.os_version, None)] if d.os_version else []
        return out + [(m.group(1), h.name) for h in hosts if (m := re.search(r"(\d+(?:\.\d+)+)", h.product or ""))]
    if d.platform == "hyperv":  # "Microsoft Windows Server 2016 Datacenter" / "Hyper-V (Windows Server 2012 R2 ...)"
        out = [(m.group(1), None)] if (m := re.search(r"\b(20\d\d)\b", d.os_name or "")) else []
        return out + [(m.group(1), h.name) for h in hosts if (m := re.search(r"Server (20\d\d)\b", h.product or ""))]
    if d.platform == "cisco_ios" and d.os_version:  # IOS-XE pads: "17.06.05" -> "17.6.5", so it matches "17.6"
        return [(re.sub(r"(?<=\.)0+(?=\d)", "", d.os_version), None)]
    return [(d.os_version, None)] if d.os_version else []


def _matches(version: str, prefix: str) -> bool:
    """Prefix match on a version boundary: "Debian GNU/Linux 1" must not match "Debian GNU/Linux 10"."""
    if not version.startswith(prefix):
        return False
    rest = version[len(prefix):]
    return not (prefix[-1:].isdigit() and rest[:1].isdigit())


@check
def end_of_support(d: Device, today: date | None = None):
    today = today or date.today()
    versions = _versions(d)
    if not versions:
        return
    for platform, prefix, eos, label in EOS_TABLE:
        if d.platform != platform:
            continue
        hits = [(v, where) for v, where in versions if _matches(v, prefix)]
        if not hits:
            continue
        evidence = [f"{where}: {v}" for v, where in hits if where]
        days = (eos - today).days
        if days < 0:
            yield Finding(check_id="lifecycle.eos", severity=Severity.high,
                          title=f"{label} is end of support",
                          detail=f"Support ended {eos.isoformat()}; no security fixes.",
                          recommendation="Plan an upgrade to a supported release.", evidence=evidence)
        elif days < 180:
            yield Finding(check_id="lifecycle.eos-soon", severity=Severity.medium,
                          title=f"{label} reaches end of support in {days} days",
                          detail=f"End of support {eos.isoformat()}.",
                          recommendation="Schedule the upgrade.", evidence=evidence)
