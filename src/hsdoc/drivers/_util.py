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
