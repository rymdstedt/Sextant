"""Renderers: doc.Document -> PDF (via HTML/WeasyPrint) and Word."""

from __future__ import annotations

from pathlib import Path

from hsdoc.builders.asbuilt import build_asbuilt
from hsdoc.builders.summary import build_summary
from hsdoc.model import Snapshot


def render_all(snap: Snapshot, out_dir: Path, formats: tuple[str, ...] = ("pdf", "docx"),
               kinds: tuple[str, ...] = ("asbuilt", "summary"), include_raw: bool = False,
               basename: str | None = None) -> list[Path]:
    """Render the requested documents; returns the written paths."""
    from hsdoc.render.docx import render_docx
    from hsdoc.render.html import render_pdf

    base = basename or _basename(snap)
    out: list[Path] = []
    for kind in kinds:
        doc = build_asbuilt(snap, include_raw=include_raw) if kind == "asbuilt" else build_summary(snap)
        name = f"{base}-{'As-Built' if kind == 'asbuilt' else 'Summary'}"
        if "pdf" in formats:
            out.append(render_pdf(doc, out_dir / f"{name}.pdf"))
        if "docx" in formats:
            out.append(render_docx(doc, out_dir / f"{name}.docx"))
    return out


def _basename(snap: Snapshot) -> str:
    import re

    parts = [snap.info.customer, snap.info.site, snap.created_at.strftime("%Y-%m-%d")]
    return re.sub(r"[^A-Za-z0-9._-]+", "-", "-".join(p for p in parts if p)).strip("-")
