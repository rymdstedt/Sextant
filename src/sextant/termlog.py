"""Turn a raw terminal session log into the text the operator saw.

Logs from SecureCRT, PuTTY, MobaXterm, iTerm or `script` record the byte stream: paging prompts
(`--More--` and friends) followed by the backspaces and spaces that erase them, `\\r` overwrites,
ANSI colour and cursor codes, sometimes UTF-16. Left in, a config line reads
`\\b\\b\\b\\b\\b\\b\\b\\b\\b        \\b\\b\\b\\b\\b\\b\\b\\b\\binterface Gi1/0/2` and neither platform detection nor
the parsers see it. Output that already is clean passes through unchanged.
"""

from __future__ import annotations

import re

_ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b[()][0-9A-Za-z]|\x1b[=>78DEHMNOZc]")
# paging prompts: IOS/IOS-XE/NX-OS/AOS-CX/ASA "--More--" / "<--- More --->", AOS-S "-- MORE --, next page: Space,
# next line: Enter, quit: Control-C", Junos "---(more)---" / "---(more 42%)---"
_PAGER = re.compile(r"(?i) ?(?:<-+ ?more ?-+>|-{2,3} ?\(?more(?: \d+%)?\)?(?:,[^\n\x08\r]*?control-c)? ?-{2,3}) ?")
_ERASE = re.compile(r"[\x08 ]*\x08")  # what a client sends to wipe the pager prompt
_ANYKEY = re.compile(r"^\s*Press any key to continue\s*$", re.M | re.I)
# per-line timestamps some clients add: "[09:40:49] ", "09:40:49.123 ", "[2026-10-23 09:40:49] ", "2026-10-23T09:40:49Z "
_STAMP = re.compile(r"^(?:\[[^\]\n]{0,40}\d{1,2}:\d{2}:\d{2}[^\]\n]{0,12}\]|"
                    r"(?:\d{4}[-/.]\d{2}[-/.]\d{2}[ T])?\d{1,2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?)[ \t]?")


def decode(data: bytes) -> str:
    """Bytes of a log or config file -> text (UTF-8, UTF-16 with or without BOM, else Windows-1252)."""
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        return data.decode("utf-16", errors="replace")
    if data.startswith(b"\xef\xbb\xbf"):
        return data[3:].decode("utf-8", errors="replace")
    sample = data[:4096]
    if sample and sample.count(b"\x00") > len(sample) // 4:  # UTF-16 without a BOM
        return data.decode("utf-16-le" if sample[1:2] == b"\x00" else "utf-16-be", errors="replace")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("cp1252", errors="replace")


def _backspaces(line: str) -> str:
    out: list[str] = []
    for ch in line:
        if ch == "\x08":
            if out:
                out.pop()
        else:
            out.append(ch)
    return "".join(out)


def _overwrite(line: str) -> str:
    """'\\r' returns the cursor to column 0: later text overwrites earlier text."""
    if "\r" not in line:
        return line
    buf: list[str] = []
    for part in line.split("\r"):
        for i, ch in enumerate(part):
            if i < len(buf):
                buf[i] = ch
            else:
                buf.append(ch)
    return "".join(buf).rstrip()  # what a blanking run of spaces leaves behind is invisible


def _drop_pager(line: str) -> str:
    if not _PAGER.search(line):
        return line
    out, pos = [], 0
    for mt in _PAGER.finditer(line):
        out.append(line[pos:mt.start()])
        pos = mt.end()
        erase = _ERASE.match(line, pos)
        if erase:
            pos = erase.end()  # the erase sequence, not the indent of the line that follows
        else:
            spaces = re.match(r" {4,}", line[pos:])  # a client that logs the screen: pager blanked with spaces
            if spaces:
                pos += spaces.end()
    out.append(line[pos:])
    return "".join(out)


def _strip_stamps(lines: list[str]) -> list[str]:
    """Remove a timestamp prefix when (nearly) every line carries one; a config never does."""
    filled = [ln for ln in lines if ln.strip()]
    if not filled or sum(1 for ln in filled if _STAMP.match(ln)) < 0.9 * len(filled):
        return lines
    return [_STAMP.sub("", ln, count=1) for ln in lines]


def clean(text: str) -> str:
    if not text:
        return text
    text = text.replace("\x00", "")
    lines = text.replace("\r\n", "\n").split("\n")
    lines = _strip_stamps(lines)
    if not re.search(r"[\x08\x1b\r]|more|any key", text, re.I):
        return "\n".join(lines)
    text = _ANSI.sub("", "\n".join(lines))
    lines = []
    for line in text.split("\n"):
        line = _drop_pager(line)
        if "\x08" in line:
            line = _backspaces(line)
        if "\r" in line:
            line = _overwrite(line)
        lines.append(line)
    return _ANYKEY.sub("", "\n".join(lines))
