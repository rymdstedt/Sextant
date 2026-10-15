"""Render a doc.Document to HTML: paged HTML for PDF (WeasyPrint), or a standalone interactive HTML file."""

from __future__ import annotations

import base64
import mimetypes
from functools import cache
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from sextant.doc import SEVERITY_LABEL, SEVERITY_STATUS, Document

TEMPLATES = Path(__file__).parent / "templates"
ASSETS = Path(__file__).resolve().parent.parent / "assets"

_env = Environment(loader=FileSystemLoader(TEMPLATES), autoescape=select_autoescape(["html", "j2"]),
                   trim_blocks=False, lstrip_blocks=False)


def _css_string(text: str) -> str:
    return text.replace("\\", "\\\\").replace('"', '\\"')


@cache
def _data_uri(name: str) -> str:
    path = ASSETS / name
    mime = mimetypes.guess_type(path.name)[0] or ("font/ttf" if path.suffix == ".ttf" else "application/octet-stream")
    return f"data:{mime};base64,{base64.b64encode(path.read_bytes()).decode()}"


def render_html(doc: Document, assets_url: str | None = None, standalone: bool = False) -> str:
    """standalone=True embeds fonts/logos as data URIs and adds the screen layout (navigation, table filter)."""
    if standalone:
        asset = _data_uri
    else:
        base = assets_url or ASSETS.as_uri()

        def asset(name: str) -> str:
            return f"{base}/{name}"

    css_env = Environment(autoescape=False)
    css = css_env.from_string((TEMPLATES / "style.css").read_text()).render(
        asset=asset, landscape=doc.landscape,
        header_text=_css_string(doc.header_text), footer_text=_css_string(doc.footer_text))
    screen_css = (TEMPLATES / "screen.css").read_text() if standalone else ""
    screen_js = (TEMPLATES / "screen.js").read_text() if standalone else ""
    return _env.get_template("document.html.j2").render(
        doc=doc, css=css, screen_css=screen_css, screen_js=screen_js, standalone=standalone, asset=asset,
        sev_status=SEVERITY_STATUS, sev_label=SEVERITY_LABEL)


def render_html_file(doc: Document, out: Path) -> Path:
    """A single self-contained .html file: opens offline, can be mailed or attached to a ticket."""
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(render_html(doc, standalone=True), encoding="utf-8")
    return out


def render_pdf(doc: Document, out: Path) -> Path:
    from weasyprint import HTML  # lazy: needs pango system libraries

    out.parent.mkdir(parents=True, exist_ok=True)
    HTML(string=render_html(doc), base_url=str(ASSETS)).write_pdf(out)
    return out
