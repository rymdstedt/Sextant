"""Firewall policy, VPN crypto and HA checks."""

from __future__ import annotations

import re

from sextant.analysis import check
from sextant.model import Device, Finding, FirewallRule, Severity

_ANY = {"any", "all", "0.0.0.0/0", "*", "any4", "any6", "::/0"}


def _is_any(values: list[str]) -> bool:
    return not values or any(v.strip().lower().strip('"') in _ANY for v in values)


def _label(r: FirewallRule) -> str:
    return f"{r.id}" + (f" ({r.name})" if r.name else "")


@check
def any_any(d: Device):
    hits = [r for r in d.firewall_rules if r.enabled and r.action == "allow"
            and _is_any(r.src_addresses) and _is_any(r.dst_addresses) and _is_any(r.services)
            and not r.applications]
    if hits:
        yield Finding(check_id="fw.any-any", severity=Severity.critical,
                      title=f"{len(hits)} allow rule(s) any → any, all services",
                      detail="Rules permitting every source, destination and service defeat segmentation.",
                      recommendation="Replace with explicit sources, destinations and services.",
                      evidence=[_label(r) for r in hits])
    broad = [r for r in d.firewall_rules if r.enabled and r.action == "allow" and r not in hits
             and _is_any(r.services) and not r.applications and (_is_any(r.src_addresses) or _is_any(r.dst_addresses))]
    if broad:
        yield Finding(check_id="fw.broad", severity=Severity.medium,
                      title=f"{len(broad)} broad allow rule(s) (any service)",
                      recommendation="Restrict services/applications on these rules.",
                      evidence=[_label(r) for r in broad[:10]])


@check
def disabled_and_unlogged(d: Device):
    disabled = [r for r in d.firewall_rules if not r.enabled]
    if disabled:
        yield Finding(check_id="fw.disabled-rules", severity=Severity.low,
                      title=f"{len(disabled)} disabled rule(s)",
                      recommendation="Remove rules that are no longer needed to keep the policy readable.",
                      evidence=[_label(r) for r in disabled[:10]])
    unlogged = [r for r in d.firewall_rules if r.enabled and r.log is False and r.action == "allow"]
    if unlogged:
        yield Finding(check_id="fw.no-logging", severity=Severity.medium,
                      title=f"{len(unlogged)} allow rule(s) without logging",
                      detail="Traffic matching these rules leaves no trace for incident response.",
                      recommendation="Enable traffic logging on allow rules.",
                      evidence=[_label(r) for r in unlogged[:10]])
    unused = [r for r in d.firewall_rules if r.enabled and r.hit_count == 0]
    if unused:
        yield Finding(check_id="fw.zero-hits", severity=Severity.info,
                      title=f"{len(unused)} rule(s) with zero hits",
                      recommendation="Review and remove unused rules.", evidence=[_label(r) for r in unused[:10]])


def _key(values: list[str]) -> frozenset[str]:
    return frozenset(v.lower() for v in values) if not _is_any(values) else frozenset({"*"})


def _covers(a: frozenset[str], b: frozenset[str]) -> bool:
    return "*" in a or b <= a


@check
def shadowed(d: Device):
    """Best effort: a later rule whose match set is a subset of an earlier enabled rule's."""
    rules = [r for r in d.firewall_rules if r.enabled]
    out: list[str] = []
    for i, later in enumerate(rules):
        for earlier in rules[:i]:
            fields = ("src_zones", "dst_zones", "src_addresses", "dst_addresses", "services", "applications")
            if all(_covers(_key(getattr(earlier, f)), _key(getattr(later, f))) for f in fields) \
                    and not earlier.users and not earlier.schedule:
                out.append(f"{_label(later)} shadowed by {_label(earlier)}")
                break
    if out:
        yield Finding(check_id="fw.shadowed", severity=Severity.low,
                      title=f"{len(out)} rule(s) possibly shadowed",
                      detail="An earlier rule matches the same or wider traffic, so these never match.",
                      recommendation="Verify order; remove or move the shadowed rules.", evidence=out[:10])


_WEAK = [(r"\b3?des\b|des-|\bdes\b|3des", "DES/3DES"), (r"\bmd5\b", "MD5"), (r"\bsha-?1\b|\bsha\b(?!-?\d)", "SHA1"),
         (r"\bdh-?(?:group)?\s*(?:1|2|5)\b|\bmodp(?:768|1024|1536)\b|dhgroup\s*(?:1|2|5)\b", "DH group < 14")]


@check
def weak_vpn(d: Device):
    for t in d.vpn_tunnels:
        text = " ".join(filter(None, [t.phase1, t.phase2])).lower()
        weak = sorted({label for pat, label in _WEAK if re.search(pat, text)})
        if weak:
            yield Finding(check_id="vpn.weak-crypto", severity=Severity.high,
                          title=f"VPN '{t.name}' uses weak crypto ({', '.join(weak)})",
                          detail=f"Phase 1: {t.phase1 or '-'}; Phase 2: {t.phase2 or '-'}.",
                          recommendation="Use IKEv2 with AES-256-GCM/SHA-256+ and DH group 19/20/21 (min 14).")
        if t.ike_version and t.ike_version.strip().lower() in ("1", "v1", "ikev1"):
            yield Finding(check_id="vpn.ikev1", severity=Severity.low, title=f"VPN '{t.name}' uses IKEv1",
                          recommendation="Migrate to IKEv2 where the peer supports it.")


@check
def ha_sync(d: Device):
    if not d.ha:
        return
    text = " ".join([d.ha.state or "", *d.ha.details.values()]).lower()
    if any(x in text for x in ("out-of-sync", "out of sync", "not synchronized", "not-synchronized", "unsync",
                               "failed", "degraded", "split")):
        yield Finding(check_id="ha.not-in-sync", severity=Severity.high,
                      title=f"HA ({d.ha.mode}) not in sync / degraded",
                      detail=f"State: {d.ha.state or '-'}; {'; '.join(f'{k}: {v}' for k, v in d.ha.details.items())}",
                      recommendation="Investigate the HA pair and resynchronize configuration before changes.")
