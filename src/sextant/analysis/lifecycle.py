"""End-of-support software versions. Extend the table as vendors publish EoS dates.

Matching is prefix based on (platform, os_version). Dates are end of
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
    ("vmware", "6.", date(2022, 10, 15), "vSphere 6.x"),
    ("vmware", "7.", date(2025, 10, 2), "vSphere 7.x"),
    ("proxmox", "7.", date(2024, 7, 31), "Proxmox VE 7"),
    ("hyperv", "2012", date(2023, 10, 10), "Windows Server 2012"),
    ("hyperv", "2016", date(2027, 1, 12), "Windows Server 2016"),
    ("linux", "Ubuntu 18.04", date(2023, 5, 31), "Ubuntu 18.04"),
    ("linux", "Ubuntu 20.04", date(2025, 5, 31), "Ubuntu 20.04"),
    ("linux", "CentOS", date(2024, 6, 30), "CentOS"),
    ("linux", "Debian GNU/Linux 10", date(2024, 6, 30), "Debian 10"),
    ("linux", "Debian GNU/Linux 11", date(2026, 8, 31), "Debian 11"),
]


def _version_of(d: Device) -> str:
    if d.platform == "linux":
        return d.os_name or ""
    if d.platform in ("vmware", "proxmox", "hyperv") and d.virtualization and d.virtualization.hosts:
        return d.virtualization.hosts[0].product or d.os_version or ""
    return d.os_version or ""


@check
def end_of_support(d: Device, today: date | None = None):
    today = today or date.today()
    version = _version_of(d)
    if not version:
        return
    if d.platform == "cisco_ios":  # IOS-XE pads: "17.06.05" -> "17.6.5", so it matches "17.6"
        version = re.sub(r"(?<=\.)0+(?=\d)", "", version)
    for platform, prefix, eos, label in EOS_TABLE:
        hay = version if platform == "linux" else version.split()[-1] if platform in ("vmware", "proxmox") else version
        if d.platform == platform and (hay.startswith(prefix) or (platform == "hyperv" and prefix in version)):
            days = (eos - today).days
            if days < 0:
                yield Finding(check_id="lifecycle.eos", severity=Severity.high,
                              title=f"{label} is end of support",
                              detail=f"Support ended {eos.isoformat()}; no security fixes.",
                              recommendation="Plan an upgrade to a supported release.")
            elif days < 180:
                yield Finding(check_id="lifecycle.eos-soon", severity=Severity.medium,
                              title=f"{label} reaches end of support in {days} days",
                              detail=f"End of support {eos.isoformat()}.",
                              recommendation="Schedule the upgrade.")
            return
