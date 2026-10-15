"""End-to-end: example snapshot -> As-Built + Summary as PDF and Word."""

from pathlib import Path

import pytest

from sextant.builders.asbuilt import build_asbuilt
from sextant.builders.summary import build_summary
from sextant.doc import DeviceHeader, KpiRow, PageBreak
from sextant.pipeline import load_snapshot

EXAMPLE = Path(__file__).resolve().parent.parent / "examples" / "snapshot.json"
pytestmark = pytest.mark.skipif(not EXAMPLE.exists(), reason="examples/snapshot.json not built")


@pytest.fixture(scope="module")
def snap():
    return load_snapshot(EXAMPLE)


def test_summary_one_page_per_device(snap):
    doc = build_summary(snap)
    assert sum(isinstance(b, DeviceHeader) for b in doc.blocks) == len(snap.devices)
    assert sum(isinstance(b, PageBreak) for b in doc.blocks) == len(snap.devices)
    for b in doc.blocks:
        if isinstance(b, KpiRow):
            assert 1 <= len(b.items) <= 6


def test_render_all_formats(snap, tmp_path):
    from docx import Document

    from sextant.render import render_all

    paths = render_all(snap, tmp_path, include_raw=True)
    assert len(paths) == 6 and all(p.stat().st_size > 10_000 for p in paths)
    asbuilt_docx = next(p for p in paths if p.name.endswith("As-Built.docx"))
    text = "\n".join(p.text for p in Document(asbuilt_docx).paragraphs)
    assert "Executive overview" in text
    for d in snap.devices:
        assert d.hostname in text


def test_no_secrets_leak(snap):
    from sextant.render.html import render_html

    html = render_html(build_asbuilt(snap, include_raw=True))
    for needle in ("$9$", "$1$", "ENC SH2", "BEGIN RSA PRIVATE KEY-----\nMII"):
        assert needle not in html
