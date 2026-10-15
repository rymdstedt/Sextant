"""Renderers: doc.Document -> PDF (via HTML/WeasyPrint), Word and standalone HTML."""

from __future__ import annotations

from pathlib import Path

from sextant.builders.asbuilt import build_asbuilt
from sextant.builders.summary import build_summary
from sextant.model import Snapshot


def render_all(snap: Snapshot, out_dir: Path, formats: tuple[str, ...] = ("pdf", "docx", "html"),
               kinds: tuple[str, ...] = ("asbuilt", "summary"), include_raw: bool = False,
               basename: str | None = None, theme: str | Path | None = None) -> list[Path]:
    """Render the requested documents; returns the written paths.

    theme: name or folder; defaults to the snapshot's theme, then $SEXTANT_THEME, then 'hybrid'.
    """
    from sextant.render.docx import render_docx
    from sextant.render.html import render_html_file, render_pdf
    from sextant.theme import load_theme

    th = load_theme(theme or snap.info.theme)

    base = basename or _basename(snap)
    out: list[Path] = []
    for kind in kinds:
        doc = build_asbuilt(snap, include_raw=include_raw) if kind == "asbuilt" else build_summary(snap)
        name = f"{base}-{'As-Built' if kind == 'asbuilt' else 'Summary'}"
        if "pdf" in formats:
            out.append(render_pdf(doc, out_dir / f"{name}.pdf", th))
        if "docx" in formats:
            out.append(render_docx(doc, out_dir / f"{name}.docx", th))
        if "html" in formats:
            out.append(render_html_file(doc, out_dir / f"{name}.html", th))
    return out


def _basename(snap: Snapshot) -> str:
    import re

    parts = [snap.info.customer, snap.info.site, snap.created_at.strftime("%Y-%m-%d")]
    return re.sub(r"[^A-Za-z0-9._-]+", "-", "-".join(p for p in parts if p)).strip("-")
