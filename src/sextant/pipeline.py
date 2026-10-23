"""Inventory loading and the collect -> redact -> parse -> analyze pipeline."""

from __future__ import annotations

import json
import logging
import os
import re
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field

from sextant import termlog
from sextant.analysis import analyze, analyze_device
from sextant.drivers import Credentials, RawCollection, Target, get_driver
from sextant.drivers.base import _RUNNING
from sextant.model import Device, DocumentInfo, Snapshot
from sextant.redact import redact_obj, redact_text

log = logging.getLogger(__name__)

_ENV = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")


class Inventory(BaseModel):
    info: DocumentInfo = Field(default_factory=DocumentInfo)
    credentials: dict[str, Credentials] = Field(default_factory=dict)
    targets: list[Target] = Field(default_factory=list)


def _expand_env(value: Any) -> Any:
    if isinstance(value, str):
        return _ENV.sub(lambda m: os.environ.get(m.group(1), ""), value)
    if isinstance(value, dict):
        return {k: _expand_env(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_expand_env(v) for v in value]
    return value


def load_inventory(path: Path, credentials_file: Path | None = None) -> Inventory:
    """Load inventory.yaml. `${VAR}` is expanded from the environment. Credentials may also live in a
    separate, git-ignored credentials.yaml (same `credentials:` structure) next to the inventory."""
    data = yaml.safe_load(path.read_text()) or {}
    creds = data.get("credentials") or {}
    cred_path = credentials_file or path.with_name("credentials.yaml")
    if cred_path.exists():
        creds.update((yaml.safe_load(cred_path.read_text()) or {}).get("credentials") or {})
    data["credentials"] = creds
    base = path.parent
    for t in data.get("targets") or []:
        if t.get("file") and not Path(t["file"]).is_absolute():
            t["file"] = str(base / t["file"])
    return Inventory.model_validate(_expand_env(data))


def sanitize_raw(raw: RawCollection) -> RawCollection:
    """Redact every output before it is parsed or stored."""
    outputs = {k: (redact_text(v) if isinstance(v, str) else redact_obj(v)) for k, v in raw.outputs.items()}
    return raw.model_copy(update={"outputs": outputs})


def parse_raw(raw: RawCollection, site: str | None = None, keep_raw: bool = False) -> Device:
    raw = sanitize_raw(raw)
    device = get_driver(raw.driver).parse(raw)
    prompt = raw.outputs.get("_prompt")
    if isinstance(prompt, str) and prompt and device.hostname in (raw.target, "", None):
        device.hostname = prompt  # e.g. a 'show spanning-tree' capture without the running-config
    device.raw_config = redact_text(device.raw_config)
    device.collection_warnings = list(dict.fromkeys([*raw.warnings, *device.collection_warnings]))
    if site and not device.site:
        device.site = site
    if keep_raw:  # the running-config once: file imports also carry it as "config"
        dup = raw.outputs.get("config")
        same = dup is not None and any(raw.outputs.get(c) == dup for c in _RUNNING if c != "config")
        device.raw = {k: v for k, v in raw.outputs.items() if not (same and k == "config")}
    else:
        device.raw = {}
    device.findings = analyze_device(device)
    return device


def collect_target(target: Target, creds: Credentials | None, keep_raw: bool = False) -> Device:
    driver = get_driver(target.driver)
    if target.method == "file" or target.file:
        if not target.file:
            raise ValueError(f"{target.name}: method 'file' needs 'file:'")
        raw = driver.from_file(Path(target.file))
        raw.target = target.name
    else:
        raw = driver.collect(target, creds or Credentials())
    device = parse_raw(raw, site=target.site, keep_raw=keep_raw)
    device.layer = target.layer or device.layer
    return device


def collect_inventory(inv: Inventory, workers: int = 8, only: list[str] | None = None,
                      extra_creds: dict[str, Credentials] | None = None, keep_raw: bool = False,
                      progress: Any = None) -> Snapshot:
    creds = {**inv.credentials, **(extra_creds or {})}
    targets = [t for t in inv.targets if not only or t.name in only]
    snap = Snapshot(info=inv.info)

    def run(t: Target) -> Device | str:
        try:
            dev = collect_target(t, creds.get(t.credentials or "") if t.credentials else None, keep_raw)
            if progress:
                progress(t.name, "ok")
            return dev
        except Exception as exc:  # noqa: BLE001 - report per target, keep going
            log.exception("collection failed for %s", t.name)
            if progress:
                progress(t.name, f"failed: {exc.__class__.__name__}")
            return f"{t.name}: {exc.__class__.__name__}: {redact_text(str(exc))}"

    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        for result in pool.map(run, targets):
            if isinstance(result, Device):
                snap.devices.append(result)
            else:
                snap.errors.append(result)
    return analyze(snap)


def import_file(path: Path, driver_id: str, name: str | None = None, site: str | None = None) -> Device:
    """Import an exported config / JSON file. A RawCollection JSON (with 'driver' and 'outputs') is accepted too."""
    return parse_raw(load_raw(path, driver_id, name), site=site)


def load_raw(path: Path, driver_id: str, name: str | None = None) -> RawCollection:
    driver = get_driver(driver_id)
    raw: RawCollection | None = None
    if path.suffix.lower() == ".json":
        try:
            data = json.loads(path.read_text())
            if isinstance(data, dict) and "outputs" in data and "driver" in data:
                raw = RawCollection.model_validate(data)
        except (json.JSONDecodeError, ValueError):
            raw = None
    if raw is None:
        raw = driver.from_file(path)
    if name:
        raw.target = name
    return raw


def load_snapshot(path: Path) -> Snapshot:
    return Snapshot.model_validate_json(path.read_text())


def save_snapshot(snap: Snapshot, path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(snap.model_dump_json(indent=2))
    return path


def merge(snapshots: list[Snapshot], info: DocumentInfo | None = None) -> Snapshot:
    out = Snapshot(info=info or (snapshots[0].info if snapshots else DocumentInfo()))
    if snapshots:  # keep the collection date (documents print it), not the render time
        out.created_at = max(s.created_at for s in snapshots)
    for s in snapshots:
        out.devices.extend(s.devices)
        out.errors.extend(s.errors)
    return analyze(out)


_DETECT: list[tuple[str, re.Pattern[str]]] = [
    ("fortigate", re.compile(r"^#config-version=FG|^config system global", re.M)),
    ("paloalto", re.compile(r"<config [^>]*version=|<devices>\s*<entry name=\"localhost.localdomain\"", re.S)),
    ("opnsense", re.compile(r"<opnsense>")),
    ("pfsense", re.compile(r"<pfsense>")),
    ("cisco_asa", re.compile(r"^ASA Version |^: Saved\s*$\n?.*ASA", re.M)),
    ("cisco_nxos", re.compile(r"^feature \S+|^!Command: show running-config|NX-OS", re.M)),
    ("juniper_junos", re.compile(r"^set (system|interfaces|vlans|protocols) ", re.M)),
    ("aruba_aoscx", re.compile(r"^!Version ArubaOS-CX|^!Version AOS-CX", re.M)),
    ("hp_procurve", re.compile(r"^; \S+ Configuration Editor|^hostname \".*\"\s*$", re.M)),
    ("cisco_ios", re.compile(r"^version 1[5-7]\.|^Building configuration|^interface (Gigabit|TenGigabit|FastEthernet)",
                             re.M)),
    # command output without a config (e.g. a 'show spanning-tree' capture)
    ("hp_procurve", re.compile(r"Multiple Spanning Trees \(MST\) Information|^\s*CST Root MAC Address", re.M)),
    ("aruba_aoscx", re.compile(r"^Spanning tree status\s*:|MAC-Address\s*:\s*[0-9a-f]{2}:", re.M)),
    ("juniper_junos", re.compile(r"^STP bridge parameters|Spanning tree interface parameters", re.M)),
    ("cisco_ios", re.compile(r"Spanning tree enabled protocol (rstp|ieee|mstp)", re.M)),
    # 'show version' (a log without the running-config, or with a config the patterns above miss)
    ("cisco_nxos", re.compile(r"Cisco Nexus Operating System|^\s*NXOS: version", re.M)),
    ("cisco_asa", re.compile(r"Cisco Adaptive Security Appliance Software Version", re.M)),
    ("cisco_ios", re.compile(r"Cisco IOS[ -]XE Software|^Cisco IOS Software|^cisco \S+ \(.*\) processor", re.M)),
    ("juniper_junos", re.compile(r"^JUNOS .*\[|^Junos: \d", re.M)),
    ("aruba_aoscx", re.compile(r"ArubaOS-CX|^\s*Product Name\s*:.*\bCX\b", re.M)),
    ("hp_procurve", re.compile(r"^Image stamp:|^\s*Boot ROM Version:|Status and Counters - General System", re.M)),
]


def why_unrecognised(text: str) -> str:
    """A hint for the 'platform not recognised' error: what the file looks like instead."""
    if not text.strip():
        return "the file is empty"
    if "\ufffd" in text[:4096] and text[:4096].count("\ufffd") > 20:
        return "the file is not text (binary or an unknown encoding)"
    prompt = re.search(r"^[\w.@()/:-]+[#>$]\s*\S", text, re.M)
    if not prompt:
        first = next((ln.strip() for ln in text.splitlines() if ln.strip()), "")[:60]
        return f"no CLI prompt or config found (first line: {redact_text(first)!r})"
    return "a session log without a running-config or 'show version' Sextant knows"


def guess_driver(text: str, filename: str = "") -> str | None:
    """Best-effort driver detection for uploaded files."""
    if filename.lower().endswith(".json"):
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return None
        if isinstance(data, dict):
            if data.get("driver"):
                return str(data["driver"])
            keys = set(data)
            if {"VMHost", "VMs"} & keys or "Host" in keys and "VM" in str(keys):
                return "hyperv"
            if {"vms", "hosts", "datastores"} <= keys:
                return "vmware"
        return None
    head = text[:200_000]
    for driver_id, pattern in _DETECT:
        if pattern.search(head):
            return driver_id
    return None


SKIP_SUFFIXES = {".png", ".jpg", ".jpeg", ".gif", ".pdf", ".docx", ".xlsx", ".zip", ".gz", ".exe", ".msi", ".bin"}
MAX_FILE = 50 * 1024 * 1024


def iter_inputs(paths: list[Path]):
    """Yield (name, text) for files, folders (recursive) and .zip archives (read in memory, never extracted)."""
    import zipfile

    for p in paths:
        if p.is_dir():
            yield from iter_inputs(sorted(x for x in p.rglob("*") if x.is_file() and not x.name.startswith(".")))
        elif p.suffix.lower() == ".zip":
            with zipfile.ZipFile(p) as zf:
                for info in sorted(zf.infolist(), key=lambda i: i.filename):
                    name = Path(info.filename).name
                    if info.is_dir() or not name or name.startswith(".") or "__MACOSX" in info.filename:
                        continue
                    if Path(name).suffix.lower() in SKIP_SUFFIXES or info.file_size > MAX_FILE:
                        continue
                    yield name, termlog.clean(termlog.decode(zf.read(info)))
        elif p.is_file() and p.suffix.lower() not in SKIP_SUFFIXES and p.stat().st_size <= MAX_FILE:
            yield p.name, termlog.clean(termlog.decode(p.read_bytes()))


def add_to_snapshot(snap: Snapshot, devices: list[Device], errors: list[str],
                    imported_files: set[str] | None = None) -> list[str]:
    """Add newly imported devices to an existing snapshot, any vendor mix.

    A device that is already there (same hostname, same platform) is merged when both kept their
    redacted command outputs, e.g. a switch's config imported first and its `show spanning-tree`
    later; otherwise the new import replaces it. Errors from earlier attempts at files that imported
    now are dropped. Returns one note per merged or replaced device. Run analyze() afterwards.
    """
    notes: list[str] = []
    index = {d.hostname.lower(): i for i, d in enumerate(snap.devices)}
    for dev in devices:
        i = index.get(dev.hostname.lower())
        if i is None:
            index[dev.hostname.lower()] = len(snap.devices)
            snap.devices.append(dev)
            continue
        old = snap.devices[i]
        if old.raw and dev.raw and old.platform == dev.platform and dev.platform:
            outputs = {**old.raw, **{c: o for c, o in dev.raw.items()
                                     if c not in old.raw or len(str(o)) > len(str(old.raw[c]))}}
            run = next((outputs[c] for c in _RUNNING if c in outputs), None)
            if run is not None and "config" not in outputs:
                outputs["config"] = run
            dev = parse_raw(RawCollection(driver=dev.platform, target=dev.hostname, method="file", outputs=outputs),
                            site=old.site, keep_raw=True)
            notes.append(f"{dev.hostname}: added to the earlier import")
        else:
            notes.append(f"{dev.hostname}: replaced the earlier import")
        snap.devices[i] = dev
    done = imported_files or set()
    snap.errors = [e for e in snap.errors if e.split(": ", 1)[0] not in done] + errors
    return notes


def import_many(paths: list[Path], driver: str | None = None, site: str | None = None,
                progress: Any = None, keep_raw: bool = True) -> tuple[list[Device], list[str]]:
    """Import many config files at once (e.g. 20 switch configs or a backup-tool zip).

    The driver is detected per file unless given, so one batch can mix vendors. Returns (devices,
    errors). Several captures of one switch are combined. Devices keep their redacted command
    outputs (keep_raw) so a later import can be added to them (add_to_snapshot).
    """
    import tempfile

    devices: dict[str, Device] = {}
    raws: dict[str, RawCollection] = {}
    errors: list[str] = []
    with tempfile.TemporaryDirectory(prefix="sextant-import-") as tmp:
        for i, (name, text) in enumerate(iter_inputs(paths)):
            drv = driver or guess_driver(text, name)
            if not drv:  # a bare command capture of a switch we already have: use that switch's platform
                prompt = re.search(r"^(?:[\w.@()/:-]+[#>]\s*)*([\w.@()/:-]+?)[#>]", text, re.M)
                host = prompt.group(1).split("@")[-1].lower() if prompt else ""
                drv = raws[host].driver if host in raws else None
            if not drv:
                errors.append(f"{name}: platform not recognised: {why_unrecognised(text)} (or use --driver)")
                continue
            f = Path(tmp) / f"{i:05d}-{Path(name).name}"
            f.write_text(text)
            try:
                raw = load_raw(f, drv, name=Path(name).stem)
                dev = parse_raw(raw, site=site, keep_raw=keep_raw)
                k = dev.hostname.lower()
                if k in raws and raws[k].driver == drv:
                    # several captures of one switch (e.g. 'show run' and 'show spanning-tree'): combine them
                    prev = raws[k]
                    merged = {**prev.outputs, **{c: o for c, o in raw.outputs.items()
                                                 if c not in prev.outputs or len(str(o)) > len(str(prev.outputs[c]))}}
                    if "config" in prev.outputs and "config" not in raw.outputs:
                        merged["config"] = prev.outputs["config"]
                    raw = prev.model_copy(update={"outputs": merged})
                    dev = parse_raw(raw, site=site, keep_raw=keep_raw)
                    k = dev.hostname.lower()
                elif k in devices:
                    dev.collection_warnings.append(f"Several files for {dev.hostname}; using {name}.")
                raws[k] = raw
            except Exception as exc:  # noqa: BLE001 - one bad file must not stop the batch
                errors.append(f"{name}: {exc.__class__.__name__}: {exc}")
                continue
            devices[k] = dev
            if progress:
                progress(name, drv, dev.hostname)
    return list(devices.values()), errors
