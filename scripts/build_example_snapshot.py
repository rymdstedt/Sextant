"""Rebuild examples/snapshot.json (per-driver fixtures) and examples/campus.json (20 campus configs).

    python scripts/build_example_snapshot.py
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from sextant.analysis import analyze
from sextant.drivers import RawCollection
from sextant.model import DocumentInfo, Snapshot
from sextant.pipeline import import_many, parse_raw, save_snapshot

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

    # campus: 20 plain running-configs (no CDP/LLDP), topology inferred from descriptions and /30s
    devices, errors = import_many([ROOT / "campus"], site="Kista")
    campus = Snapshot(
        info=DocumentInfo(customer="Example AB", project="Campus network", site="Kista",
                          author="Andreas Lindstedt", version="1.0", classification="Internal",
                          notes="20 switch running-configs imported from a config backup, no device access."),
        created_at=datetime(2026, 10, 15, 6, 0, tzinfo=UTC), devices=devices, errors=errors)
    for d in campus.devices:
        d.collected_at = campus.created_at
    save_snapshot(analyze(campus), ROOT / "campus.json")
    print(f"{len(campus.devices)} devices -> examples/campus.json")


if __name__ == "__main__":
    main()
