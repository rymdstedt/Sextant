"""Rebuild examples/snapshot.json from the per-driver fixtures (examples/<driver>/raw.json).

    python scripts/build_example_snapshot.py
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from sextant.analysis import analyze
from sextant.drivers import RawCollection
from sextant.model import DocumentInfo, Snapshot
from sextant.pipeline import parse_raw, save_snapshot

ROOT = Path(__file__).resolve().parent.parent / "examples"


def main() -> None:
    snap = Snapshot(
        info=DocumentInfo(customer="Example AB", project="Infrastructure documentation", site="Stockholm",
                          author="Andreas Lindstedt", reviewer="", version="1.0", classification="Internal",
                          notes="Example site built from the redacted sample fixtures in examples/."),
        created_at=datetime(2026, 10, 15, 6, 0, tzinfo=UTC),
    )
    for raw_file in sorted(ROOT.glob("*/raw*.json")):
        raw = RawCollection.model_validate_json(raw_file.read_text())
        dev = parse_raw(raw)
        dev.collected_at = snap.created_at
        snap.devices.append(dev)
        print(f"{raw_file.relative_to(ROOT)} -> {dev.hostname} ({len(dev.findings)} findings)")
    save_snapshot(analyze(snap), ROOT / "snapshot.json")
    print(f"{len(snap.devices)} devices -> examples/snapshot.json")


if __name__ == "__main__":
    main()
