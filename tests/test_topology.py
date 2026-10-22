import re
import zipfile
from pathlib import Path

import pytest

from sextant.analysis import analyze
from sextant.builders.topology import compress_names
from sextant.drivers.base import split_session_log
from sextant.drivers.cisco_ios import IOS_COMMANDS
from sextant.model import Snapshot
from sextant.pipeline import import_many
from sextant.topology import build_topology

CAMPUS = Path(__file__).resolve().parent.parent / "examples" / "campus"


@pytest.fixture(scope="module")
def campus():
    devices, errors = import_many([CAMPUS])
    assert errors == [] and len(devices) == 20
    snap = analyze(Snapshot(devices=devices))
    return snap, build_topology(snap)


def test_layers_and_links_from_config_files_only(campus):
    _, topo = campus
    layers = {lay: [n.name for n in nodes] for lay, nodes in topo.by_layer().items()}
    assert len(layers["core"]) == 2 and len(layers["distribution"]) == 4 and len(layers["access"]) == 14
    # 1 core peer + 8 core-dist + 2 dist peers + 28 dist-access
    assert len(topo.links) == 39
    assert all(ln.sources <= {"description", "subnet"} for ln in topo.links.values())
    assert topo.uplinks("kis-acc-sw01") == ["kis-dist-sw01", "kis-dist-sw02"]
    assert topo.uplinks("kis-acc-sw08") == ["kis-dist-sw03", "kis-dist-sw04"]


def test_layers_without_name_hints(tmp_path):
    """Neutral hostnames: layers come from position (distance from the core / leaf-ness)."""
    for f in CAMPUS.glob("*.cfg"):
        text = f.read_text()
        text = re.sub(r"kis-(core|dist|acc)-sw(\d+)", lambda m: f"sw{ {'core': 0, 'dist': 10, 'acc': 20}[m.group(1)] + int(m.group(2)):02d}", text)
        (tmp_path / f.name).write_text(text)
    devices, _ = import_many([tmp_path])
    topo = build_topology(Snapshot(devices=devices))
    got = {n.name: n.layer for n in topo.nodes.values()}
    assert got["sw01"] == got["sw02"] == "core"
    assert all(got[f"sw{10 + i:02d}"] == "distribution" for i in range(1, 5))
    assert all(got[f"sw{20 + i:02d}"] == "access" for i in range(1, 15))
    assert all(n.layer_reason == "topology" for n in topo.nodes.values())


def test_cross_device_findings(campus):
    snap, _ = campus
    by = {d.hostname: {f.check_id for f in d.findings} for d in snap.devices}
    assert "vlan.name-mismatch" in by["kis-acc-sw05"]
    assert "topology.single-uplink" in by["kis-acc-sw09"]
    assert "link.native-mismatch" in by["kis-acc-sw12"] and "link.native-mismatch" in by["kis-dist-sw03"]
    assert "link.allowed-mismatch" in by["kis-acc-sw14"]
    assert "mgmt.telnet" in by["kis-acc-sw07"]
    clean = [h for h, ids in by.items() if not ids & {"vlan.name-mismatch", "topology.single-uplink",
                                                      "link.native-mismatch", "link.allowed-mismatch"}]
    assert len(clean) == 14  # no false positives on the healthy switches


def test_zip_import_and_session_log(tmp_path):
    z = tmp_path / "backup.zip"
    with zipfile.ZipFile(z, "w") as zf:
        for f in sorted(CAMPUS.glob("*.cfg"))[:3]:
            zf.write(f, f"backup/{f.name}")
        zf.writestr("../../evil.cfg", (CAMPUS / "kis-acc-sw04.cfg").read_text())  # name is never used as a path
        zf.writestr("__MACOSX/._x.cfg", "junk")
    devices, errors = import_many([z])
    assert {d.hostname for d in devices} >= {"kis-acc-sw01", "kis-acc-sw04"} and errors == []
    assert not (tmp_path.parent / "evil.cfg").exists()

    log = "kis-acc-sw01#sh run\nhostname x\nkis-acc-sw01#sh cdp nei det\nDevice ID: y\nkis-acc-sw01#show ver\nV\n"
    parts = split_session_log(log, tuple(IOS_COMMANDS))
    assert list(parts) == ["_prompt", "show running-config", "show cdp neighbors detail", "show version"]
    assert parts["_prompt"] == "kis-acc-sw01"


def test_tunnels_do_not_merge_sites():
    from sextant.pipeline import load_snapshot

    topo = build_topology(load_snapshot(Path(__file__).resolve().parent.parent / "examples" / "snapshot.json"))
    biggest = topo.components()[0]
    assert "gbg-fw01" not in biggest and "sto-core-sw01" in biggest


def test_compress_names():
    assert compress_names(["kis-acc-sw01", "kis-acc-sw02", "kis-acc-sw03", "kis-acc-sw09", "fw"]) == \
        "kis-acc-sw01–03, 09, fw"
