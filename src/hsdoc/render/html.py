"""Render a doc.Document to HTML and PDF (WeasyPrint)."""

from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from hsdoc.doc import SEVERITY_LABEL, SEVERITY_STATUS, Document

TEMPLATES = Path(__file__).parent / "templates"
ASSETS = Path(__file__).resolve().parent.parent / "assets"

_env = Environment(loader=FileSystemLoader(TEMPLATES), autoescape=select_autoescape(["html", "j2"]),
                   trim_blocks=False, lstrip_blocks=False)


def _css_string(text: str) -> str:
    return text.replace("\\", "\\\\").replace('"', '\\"')


def render_html(doc: Document, assets_url: str | None = None) -> str:
    assets = assets_url or ASSETS.as_uri()
    css_env = Environment(autoescape=False)
    css = css_env.from_string((TEMPLATES / "style.css").read_text()).render(
        fonts=f"{assets}/fonts", assets=assets, landscape=doc.landscape,
        header_text=_css_string(doc.header_text), footer_text=_css_string(doc.footer_text))
    return _env.get_template("document.html.j2").render(
        doc=doc, css=css, assets=assets, sev_status=SEVERITY_STATUS, sev_label=SEVERITY_LABEL)


def render_pdf(doc: Document, out: Path) -> Path:
    from weasyprint import HTML  # lazy: needs pango system libraries

    out.parent.mkdir(parents=True, exist_ok=True)
    HTML(string=render_html(doc), base_url=str(ASSETS)).write_pdf(out)
    return out
