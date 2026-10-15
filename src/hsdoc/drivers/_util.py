"""Small helpers shared by the parsers. Keep them pure and forgiving."""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterator


def blocks(config: str, top: str | re.Pattern[str]) -> Iterator[tuple[str, list[str]]]:
    """Yield (header, child_lines) for indented IOS-style config blocks whose header matches `top`.

    Child lines are returned stripped. Works for IOS, NX-OS, ASA, AOS-CX and ProCurve
    (ProCurve closes blocks with 'exit', which is dropped).
    """
    pat = re.compile(top) if isinstance(top, str) else top
    header: str | None = None
    children: list[str] = []
    for line in config.splitlines():
        if not line.strip() or line.strip() == "!":
            if header is not None and not line.strip():
                continue
        if line[:1] not in (" ", "\t") and line.strip():
            if header is not None:
                yield header, children
            header, children = (line.strip(), []) if pat.match(line.strip()) else (None, [])
        elif header is not None and line.strip() and line.strip() not in ("!", "exit"):
            children.append(line.strip())
    if header is not None:
        yield header, children


def first(pattern: str, text: str, group: int = 1, flags: int = re.M) -> str | None:
    m = re.search(pattern, text or "", flags)
    return m.group(group).strip() if m else None


def all_matches(pattern: str, text: str, group: int = 1, flags: int = re.M) -> list[str]:
    return [m.group(group).strip() for m in re.finditer(pattern, text or "", flags)]


def mask_to_prefix(addr: str, mask: str) -> str:
    """'10.0.0.1', '255.255.255.0' -> '10.0.0.1/24'. Returns addr unchanged on bad input."""
    try:
        return f"{addr}/{ipaddress.IPv4Network(f'0.0.0.0/{mask}').prefixlen}"
    except ValueError:
        return addr


def network_of(cidr: str) -> str:
    """'10.0.0.1/24' -> '10.0.0.0/24' (strict=False). Returns input on bad input."""
    try:
        return str(ipaddress.IPv4Interface(cidr).network)
    except ValueError:
        return cidr


def compress_vlans(ids: list[int]) -> str:
    """[1,2,3,5,10,11] -> '1-3,5,10-11'."""
    ids = sorted(set(ids))
    out: list[str] = []
    i = 0
    while i < len(ids):
        j = i
        while j + 1 < len(ids) and ids[j + 1] == ids[j] + 1:
            j += 1
        out.append(str(ids[i]) if i == j else f"{ids[i]}-{ids[j]}")
        i = j + 1
    return ",".join(out)


def expand_vlans(text: str) -> list[int]:
    """'1-3,5' -> [1,2,3,5]. Ignores junk."""
    out: list[int] = []
    for part in re.split(r"[,\s]+", text or ""):
        if "-" in part:
            a, _, b = part.partition("-")
            if a.isdigit() and b.isdigit():
                out.extend(range(int(a), int(b) + 1))
        elif part.isdigit():
            out.append(int(part))
    return out


_IF_ABBREV = [
    ("TwentyFiveGigE", "Twe"), ("HundredGigE", "Hu"), ("FortyGigabitEthernet", "Fo"),
    ("TenGigabitEthernet", "Te"), ("GigabitEthernet", "Gi"), ("FastEthernet", "Fa"),
    ("Port-channel", "Po"), ("Ethernet", "Eth"),
]


def short_ifname(name: str) -> str:
    for long, short in _IF_ABBREV:
        if name.startswith(long):
            return short + name[len(long):]
    return name


def table_rows(text: str, header_regex: str) -> list[str]:
    """Return the lines after the header line matching header_regex (skips dashes)."""
    lines = (text or "").splitlines()
    for i, line in enumerate(lines):
        if re.search(header_regex, line):
            return [ln for ln in lines[i + 1:] if ln.strip() and not set(ln.strip()) <= {"-", " ", "="}]
    return []


# --------------------------------------------------------------------------- generic helpers (API/JSON drivers)


def as_list(value: object) -> list:
    """None -> [], a single dict/scalar -> [value], list/tuple -> list. PowerShell's
    ConvertTo-Json collapses one-element arrays, so JSON consumers need this."""
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return list(value)
    return [value]


def parse_dt(value: object):  # -> datetime | None
    """Parse ISO 8601 (with 'Z'), PowerShell '/Date(ms)/' or epoch seconds into an aware UTC datetime."""
    from datetime import UTC, datetime

    if value is None or value == "":
        return None
    try:
        if isinstance(value, (int, float)):
            return datetime.fromtimestamp(float(value), tz=UTC)
        text = str(value).strip()
        m = re.match(r"^/Date\((-?\d+)(?:[+-]\d+)?\)/$", text)
        if m:
            return datetime.fromtimestamp(int(m.group(1)) / 1000, tz=UTC)
        if re.fullmatch(r"\d{9,11}(\.\d+)?", text):
            return datetime.fromtimestamp(float(text), tz=UTC)
        text = re.sub(r"(\.\d{6})\d+", r"\1", text.replace("Z", "+00:00"))  # .NET 'o' has 7 digits
        dt = datetime.fromisoformat(text)
        return dt if dt.tzinfo else dt.replace(tzinfo=UTC)
    except (ValueError, OverflowError, OSError):
        return None


def to_int(value: object) -> int | None:
    try:
        return int(float(value))  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None


def to_float(value: object) -> float | None:
    try:
        return float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None


def bytes_to_gb(value: object, ndigits: int = 1) -> float | None:
    """Bytes -> GiB rounded (labelled GB in documents, as hypervisor UIs do)."""
    f = to_float(value)
    return None if f is None else round(f / 1024**3, ndigits)


# --------------------------------------------------------------------------- XML / firewall helpers

def parse_xml_safe(text: str):  # -> xml.etree.ElementTree.Element
    """Parse untrusted XML. Uses defusedxml when installed; otherwise refuses DTDs/entities
    (no billion-laughs / XXE) and parses with xml.etree. Raises ValueError on bad input."""
    import xml.etree.ElementTree as ET  # noqa: N817

    text = (text or "").lstrip("﻿")
    if re.search(r"<!(DOCTYPE|ENTITY)", text, re.I):
        raise ValueError("XML with DTD/entity declarations refused")
    try:
        from defusedxml.ElementTree import fromstring  # type: ignore[import-not-found]
    except ImportError:
        fromstring = ET.fromstring
    try:
        return fromstring(text.encode("utf-8") if text.startswith("<?xml") else text)
    except ET.ParseError as exc:
        raise ValueError(f"invalid XML: {exc}") from exc


_XML_SECRET_TAG = re.compile(
    r"<((?:[\w.-]*(?:password|passwd|secret|community|community-string|trapstring|psk|presharedkey|"
    r"pre-shared-key|privkey|privatekey|private-key|apikey|api_key|authkey|enckey|seed|authpwd|privpwd|phash))|"
    r"(?:[\w.-]*[-_])?(?:hash|key|prv|tls))(\s[^>]*)?>([^<]+)</\1>", re.I)


def redact_xml(text: str | None) -> str | None:
    """hsdoc.redact.redact_text for XML exports, keeping the result well-formed:
    additionally masks any secret-looking element text (communities other than public/private
    included) and writes the mask as an escaped entity so the XML still parses."""
    from hsdoc.redact import MASK, redact_text

    if not text:
        return text

    def _sub(mt: re.Match[str]) -> str:
        val = mt.group(3).strip()
        if val.lower() in {"public", "private", "", "&lt;redacted&gt;"}:
            return mt.group(0)
        return f"<{mt.group(1)}{mt.group(2) or ''}>{MASK}</{mt.group(1)}>"

    text = _XML_SECRET_TAG.sub(_sub, text)
    out = redact_text(text) or ""
    return out.replace(f">{MASK}<", ">&lt;redacted&gt;<")


def mask_value(value: str | None) -> str | None:
    """model.mask_secret, but leaves an already-redacted placeholder readable."""
    from hsdoc.model import mask_secret

    if value is None or value.strip() in ("", "<redacted>", "&lt;redacted&gt;", "*****"):
        return value if value is None else "<redacted>"
    return mask_secret(value)


def norm_action(action: str | None, default: str = "deny") -> str:
    """Vendor rule action -> allow | deny | drop | reject."""
    a = (action or "").strip().lower()
    if a in ("accept", "allow", "permit", "pass", "ipsec"):
        return "allow"
    if a in ("drop", "block"):
        return "drop"
    if a.startswith("reset") or a == "reject":
        return "reject"
    if a in ("deny",):
        return "deny"
    return default if not a else a


# --------------------------------------------------------------------------- fixed-width CLI tables


def fixed_columns(text: str, header_regex: str, multiword: bool = True) -> list[dict[str, str]]:
    """Parse a left-aligned fixed-width CLI table into dicts keyed by header names.

    Column boundaries are the start offsets of the header words in the line matching
    `header_regex`. With multiword=True, words separated by ONE space form one column
    name ("Part number"); otherwise every word is its own column. Separator lines
    (dashes, '=', '+', '|') and blank lines are skipped. The last column takes the rest.
    """
    lines = (text or "").splitlines()
    for i, line in enumerate(lines):  # noqa: B007 - i is used after the loop
        if re.search(header_regex, line):
            word = r"\S+(?: \S+)*" if multiword else r"\S+"
            cols = [(mt.group(0), mt.start()) for mt in re.finditer(word, line)]
            break
    else:
        return []
    rows: list[dict[str, str]] = []
    for ln in lines[i + 1:]:
        if not ln.strip() or set(ln.strip()) <= set("-=+| "):
            continue
        row: dict[str, str] = {}
        for j, (name, start) in enumerate(cols):
            end = cols[j + 1][1] if j + 1 < len(cols) else len(ln)
            row[name] = ln[start:end].strip()
        rows.append(row)
    return rows


def scrub_after(text: str | None, prefixes: list[str]) -> str | None:
    """Defensive second redaction pass for vendor syntaxes the generic redactor misses.

    Each prefix is a regex (no capture groups) for the part that is kept; the token that
    follows it (quoted or bare) is replaced by <redacted> unless it already is.
    """
    if not text:
        return text
    for prefix in prefixes:
        pat = re.compile(rf"((?:{prefix})\s+)(?!\"?<redacted>)(\"[^\"\n]*\"|\S+)", re.I)
        text = pat.sub(lambda mt: mt.group(1) + ('"<redacted>"' if mt.group(2).startswith('"') else "<redacted>"),
                       text)
    return text
