"""Neutral document blocks.

Builders produce a `Document` (a flat list of blocks); the HTML/PDF and Word
renderers both consume it, so the two output formats always contain the same
content in the same order.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

Status = Literal["error", "warning", "info", "success", "neutral"]


@dataclass
class Heading:
    text: str
    level: int = 1  # 1 = chapter (new page in As-Built), 2..4 = sub levels
    anchor: str | None = None
    toc: bool = True


@dataclass
class Paragraph:
    text: str
    style: Literal["body", "ingress", "muted", "footnote"] = "body"


@dataclass
class Facts:
    """Key/value list, rendered as a two-column table without header."""

    items: list[tuple[str, str]]
    title: str | None = None
    columns: int = 1  # 2 = render as two side-by-side key/value pairs per row


@dataclass
class Cell:
    text: str
    status: Status | None = None  # renders a coloured pill with the text as label


@dataclass
class Table:
    columns: list[str]
    rows: list[list[str | Cell]]
    title: str | None = None
    note: str | None = None
    numeric: set[int] = field(default_factory=set)  # right-aligned column indexes
    widths: list[float] | None = None  # relative widths
    compact: bool = False


@dataclass
class Kpi:
    label: str
    value: str
    sub: str | None = None
    status: Status | None = None


@dataclass
class KpiRow:
    items: list[Kpi]


@dataclass
class FindingItem:
    severity: str  # info | low | medium | high | critical
    title: str
    detail: str = ""
    fix: str = ""
    device: str | None = None


@dataclass
class Findings:
    items: list[FindingItem]
    title: str | None = None
    compact: bool = False  # one line + fix (Summary) vs full detail (As-Built)
    empty_text: str = "No findings."


@dataclass
class Code:
    text: str
    title: str | None = None


@dataclass
class Callout:
    text: str
    status: Status = "info"
    title: str | None = None


@dataclass
class PageBreak:
    pass


@dataclass
class Toc:
    title: str = "Contents"


@dataclass
class Cover:
    title: str
    subtitle: str | None = None
    customer: str | None = None
    site: str | None = None
    version: str | None = None
    date: str | None = None
    classification: str | None = None


@dataclass
class DeviceHeader:
    """Identity strip at the top of a Summary device page."""

    name: str
    line: str  # "Cisco C9300-48P · IOS-XE 17.9.4a · 10.0.0.2"
    role: str
    status: Status
    status_label: str


Block = (Heading | Paragraph | Facts | Table | KpiRow | Findings | Code | Callout | PageBreak | Toc | Cover
         | DeviceHeader)


@dataclass
class Document:
    title: str
    kind: Literal["asbuilt", "summary"]
    blocks: list[Block] = field(default_factory=list)
    header_text: str = ""  # running header, e.g. customer + document title
    footer_text: str = ""  # classification
    landscape: bool = False

    def add(self, *blocks: Block | None) -> Document:
        self.blocks.extend(b for b in blocks if b is not None)
        return self

    def headings(self) -> list[Heading]:
        return [b for b in self.blocks if isinstance(b, Heading) and b.toc]


SEVERITY_STATUS: dict[str, Status] = {
    "critical": "error", "high": "error", "medium": "warning", "low": "info", "info": "neutral",
}
SEVERITY_LABEL = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low", "info": "Info"}


def slug(text: str) -> str:
    import re

    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-") or "s"
