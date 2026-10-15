"""Analysis checks: read a model.Device, return Findings.

A check is a function `(Device) -> Iterable[Finding]` registered with @check.
Checks must be defensive: data from offline imports is often partial, so a
missing value (None) means "unknown", never "disabled".
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterable

from sextant.model import Device, Finding, Snapshot

log = logging.getLogger(__name__)

CheckFn = Callable[[Device], Iterable[Finding]]
CHECKS: list[CheckFn] = []


def check(fn: CheckFn) -> CheckFn:
    CHECKS.append(fn)
    return fn


def analyze_device(device: Device) -> list[Finding]:
    from sextant.analysis import firewall, lifecycle, management, switching, virtualization  # noqa: F401

    findings: list[Finding] = []
    for fn in CHECKS:
        try:
            findings.extend(fn(device))
        except Exception as exc:  # noqa: BLE001 - one broken check must not break the document
            log.warning("check %s failed on %s: %s", fn.__name__, device.hostname, exc)
    findings.sort(key=lambda f: -f.severity.rank)
    return findings


def analyze(snapshot: Snapshot) -> Snapshot:
    """Recompute findings for every device (idempotent)."""
    for device in snapshot.devices:
        device.findings = analyze_device(device)
    return snapshot
