import re
from pathlib import Path

import pytest

from sextant.theme import BUILTIN, available, init_theme, load_theme

SRC = Path(__file__).resolve().parent.parent / "src" / "sextant"


def test_builtin_themes():
    assert {"hybrid", "neutral"} <= set(available())
    hy = load_theme("hybrid")
    assert hy.colors.primary == "#1d2542" and hy.asset(hy.logos.color).is_file()
    assert [w for w, _, _ in hy.font_faces()] == ["300", "400", "400", "600", "700"]
    assert load_theme("neutral").logos.color is None


def test_unknown_theme():
    with pytest.raises(FileNotFoundError):
        load_theme("does-not-exist")


def test_env_default(monkeypatch):
    monkeypatch.setenv("SEXTANT_THEME", "neutral")
    assert load_theme().id == "neutral"


def test_init_theme_is_self_contained(tmp_path, monkeypatch):
    dest = init_theme("acme", tmp_path)
    (dest / "theme.yaml").write_text((dest / "theme.yaml").read_text()
                                     .replace("Hybrid Solutions AB", "ACME Corp").replace("#1d2542", "#123456"))
    th = load_theme(dest)
    assert th.id == "acme" and th.company == "ACME Corp" and th.colors.primary == "#123456"
    assert all(th.path in th.asset(rel).parents for _, _, rel in th.font_faces())  # fonts copied in
    monkeypatch.setenv("SEXTANT_THEMES_DIR", str(tmp_path))
    assert "acme" in available() and load_theme("acme").company == "ACME Corp"


def test_asset_cannot_escape_theme_folder():
    hy = load_theme("hybrid")
    assert hy.asset("../../theme.py") is None and hy.asset("/etc/passwd") is None


def test_no_brand_values_hard_coded():
    """Brand colours, fonts and names must only live in themes/."""
    brand = re.compile(r"#1d2542|#0099d4|#eb5e1d|1D2542|0099D4|EB5E1D|Open Sans|Hybrid Solutions|logo-color|logo-white",
                       re.I)
    offenders = []
    for f in SRC.rglob("*"):
        if f.suffix in {".py", ".css", ".j2", ".html", ".js"} and BUILTIN not in f.parents and f.name != "theme.py":
            offenders += [f"{f.relative_to(SRC)}: {m}" for m in brand.findall(f.read_text())]
    assert offenders == []


def test_render_with_neutral_theme(tmp_path):
    from docx import Document as Docx

    from sextant.builders.summary import build_summary
    from sextant.model import Device, DocumentInfo, Snapshot
    from sextant.render import render_all
    from sextant.render.html import render_html

    snap = Snapshot(info=DocumentInfo(customer="ACME", theme="neutral"), devices=[Device(hostname="sw1", role="switch")])
    html = render_html(build_summary(snap), load_theme("neutral"), standalone=True)
    assert "#1f2937" in html and "#1d2542" not in html and "image/png" not in html
    paths = render_all(snap, tmp_path, formats=("docx", "pdf"), kinds=("summary",))
    doc = Docx(next(p for p in paths if p.suffix == ".docx"))
    assert not doc.inline_shapes  # no logo pictures in an unbranded theme
    assert doc.core_properties.author == "Sextant"
