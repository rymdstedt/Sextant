"""Render a doc.Document to HTML: paged HTML for PDF (WeasyPrint), or a standalone interactive HTML file."""

from __future__ import annotations

import base64
import mimetypes
from functools import cache
from html import escape
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from sextant.doc import SEVERITY_LABEL, SEVERITY_STATUS, Document
from sextant.theme import Theme, load_theme

TEMPLATES = Path(__file__).parent / "templates"

_env = Environment(loader=FileSystemLoader(TEMPLATES), autoescape=select_autoescape(["html", "j2"]),
                   trim_blocks=False, lstrip_blocks=False)


def _css_string(text: str) -> str:
    """Text for a CSS string literal inside <style>: every character that could end the string, the rule or
    the style element is written as a CSS escape (customer names come from user input)."""
    out = []
    for ch in text or "":
        out.append(f"\\{ord(ch):x} " if ch in '"\'\\<>&{}\n\r;' or ord(ch) < 32 else ch)
    return "".join(out)


@cache
def _data_uri(path: Path) -> str:
    mime = mimetypes.guess_type(path.name)[0] or ("font/ttf" if path.suffix == ".ttf" else "application/octet-stream")
    return f"data:{mime};base64,{base64.b64encode(path.read_bytes()).decode()}"


def render_html(doc: Document, theme: Theme | None = None, standalone: bool = False) -> str:
    """standalone=True embeds fonts/logos as data URIs and adds the screen layout (navigation, table filter)."""
    theme = theme or load_theme()

    def asset(rel: str | None) -> str:
        path = theme.asset(rel)
        if path is None:
            return ""
        return _data_uri(path) if standalone else path.as_uri()

    css_env = Environment(autoescape=False)
    css = css_env.from_string((TEMPLATES / "style.css").read_text()).render(
        asset=asset, theme=theme, landscape=doc.landscape, company=_css_string(theme.company),
        header_text=_css_string(doc.header_text), footer_text=_css_string(doc.footer_text))
    def diagram(b) -> str:
        from markupsafe import Markup

        from sextant.render.stp_diagram import block_svg

        svg, _ = block_svg(b, theme)
        if standalone:
            return Markup(svg)
        return Markup(f'<img alt="{escape(b.title or "Topology")}" '
                      f'src="data:image/svg+xml;base64,{base64.b64encode(svg.encode()).decode()}">')

    screen_css = (TEMPLATES / "screen.css").read_text() if standalone else ""
    screen_js = (TEMPLATES / "screen.js").read_text() if standalone else ""
    return _env.get_template("document.html.j2").render(
        doc=doc, css=css, screen_css=screen_css, screen_js=screen_js, standalone=standalone, asset=asset,
        theme=theme, diagram=diagram, sev_status=SEVERITY_STATUS, sev_label=SEVERITY_LABEL)


def render_html_file(doc: Document, out: Path, theme: Theme | None = None) -> Path:
    """A single self-contained .html file: opens offline, can be mailed or attached to a ticket."""
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(render_html(doc, theme, standalone=True), encoding="utf-8")
    return out


def render_pdf(doc: Document, out: Path, theme: Theme | None = None) -> Path:
    from weasyprint import HTML  # lazy: needs pango system libraries

    out.parent.mkdir(parents=True, exist_ok=True)
    HTML(string=render_html(doc, theme)).write_pdf(out)
    return out
