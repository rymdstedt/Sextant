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
    device.collection_warnings = list(dict.fromkeys(redact_text(w) or "" for w in [*raw.warnings,
                                                                                    *device.collection_warnings]))
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
    for s in snapshots:  # a device in several snapshots appears once (completed or replaced, newest last)
        add_to_snapshot(out, list(s.devices), list(s.errors))
    return analyze(out)


_DETECT: list[tuple[str, re.Pattern[str]] | None] = [
    ("fortigate", re.compile(r"^#config-version=FG|^config system global", re.M)),
    ("paloalto", re.compile(r"<config [^>]*version=|<devices>\s*<entry name=\"localhost.localdomain\"", re.S)),
    ("opnsense", re.compile(r"<opnsense>")),
    ("pfsense", re.compile(r"<pfsense>")),
    ("cisco_asa", re.compile(r"^ASA Version |^: Saved\s*$\n?.*ASA", re.M)),
    ("cisco_nxos", re.compile(r"^feature \S+|^!Command: show running-config", re.M)),
    ("juniper_junos", re.compile(r"^set (system|interfaces|vlans|protocols) ", re.M)),
    ("aruba_aoscx", re.compile(r"^!Version ArubaOS-CX|^!Version AOS-CX", re.M)),
    ("hp_procurve", re.compile(r"^; \S+ Configuration Editor|^hostname \".*\"\s*$", re.M)),
    ("cisco_ios", re.compile(r"^version 1[2-7]\.|^Building configuration|^interface (Gigabit|TenGigabit|FastEthernet)",
                             re.M)),
    None,  # --- below: command output, used when no configuration identifies the platform
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
    prompt = re.search(r"^[\w.@()/:-]+[#>$][ \t]*\S.*$", text, re.M)
    if not prompt:
        first = next((ln.strip() for ln in text.splitlines() if ln.strip()), "")[:60]
        return f"no CLI prompt or config found (first line: {redact_text(first)!r})"
    from sextant.drivers.base import split_session_log

    lines = len(text.splitlines())
    parts = split_session_log(text) or {}
    cmds = [c for c in parts if not c.startswith("_")]
    seen = f"{lines} lines, first prompt {redact_text(prompt.group(0).strip()[:50])!r}"
    if not cmds:
        return f"a session log with no show commands ({seen}); the session may have ended early"
    shown = ", ".join(repr(c) for c in cmds[:5]) + (f" and {len(cmds) - 5} more" if len(cmds) > 5 else "")
    return (f"a session log with {shown} but no running-config or 'show version' Sextant knows ({seen}); "
            "an output that was cut off is the usual reason")


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
    head = text  # the whole file: a long capture can reach its 'show running-config' late
    # per tier, the marker that appears first wins: a session log starts with its own config/version,
    # and mentions other platforms only later (CDP neighbours, descriptions, banners)
    best: tuple[int, str] | None = None
    for entry in _DETECT:
        if entry is None:
            if best:
                return best[1]
            continue
        driver_id, pattern = entry
        mt = pattern.search(head)
        if mt and (best is None or mt.start() < best[0]):
            best = (mt.start(), driver_id)
    return best[1] if best else None


SKIP_SUFFIXES = {".png", ".jpg", ".jpeg", ".gif", ".pdf", ".docx", ".xlsx", ".zip", ".gz", ".exe", ".msi", ".bin"}
MAX_FILE = 50 * 1024 * 1024
MAX_ZIP_TOTAL = 500 * 1024 * 1024  # uncompressed bytes read from one archive (a zip bomb stops here)
MAX_ZIP_MEMBERS = 5000


def iter_inputs(paths: list[Path], errors: list[str] | None = None):
    """Yield (name, text) for files, folders (recursive) and .zip archives (read in memory, never extracted).
    An archive over MAX_ZIP_TOTAL / MAX_ZIP_MEMBERS is read up to the limit and reported in `errors`."""
    import zipfile

    for p in paths:
        if p.is_dir():
            yield from iter_inputs(sorted(x for x in p.rglob("*") if x.is_file() and not x.name.startswith(".")),
                                   errors)
        elif p.suffix.lower() == ".zip":
            total = count = 0
            with zipfile.ZipFile(p) as zf:
                for info in sorted(zf.infolist(), key=lambda i: i.filename):
                    name = Path(info.filename).name
                    if info.is_dir() or not name or name.startswith(".") or "__MACOSX" in info.filename:
                        continue
                    if Path(name).suffix.lower() in SKIP_SUFFIXES or info.file_size > MAX_FILE:
                        continue
                    count += 1
                    total += info.file_size
                    if count > MAX_ZIP_MEMBERS or total > MAX_ZIP_TOTAL:
                        if errors is not None:
                            errors.append(f"{p.name}: archive larger than {MAX_ZIP_TOTAL // 2**20} MB or "
                                          f"{MAX_ZIP_MEMBERS} files unpacked; the rest was not read")
                        break
                    data = zf.read(info)  # file_size is what the archive claims; trust what was read
                    if len(data) > MAX_FILE:
                        continue
                    yield name, termlog.clean(termlog.decode(data))
        elif p.is_file() and p.suffix.lower() not in SKIP_SUFFIXES:
            if p.stat().st_size > MAX_FILE:
                if errors is not None:
                    errors.append(f"{p.name}: larger than {MAX_FILE // 2**20} MB, not read")
                continue
            yield p.name, termlog.clean(termlog.decode(p.read_bytes()))


def split_hosts(name: str, text: str) -> list[tuple[str, str]]:
    """A session log that visits several devices (ssh from one switch to the next in the same log) as one
    capture per device, by the hostname in the prompt. A log of one device comes back unchanged."""
    from sextant.drivers.base import _PROMPT

    marks = list(_PROMPT.finditer(text))
    hosts = [mt.group(1).split("@")[-1].lower() for mt in marks]
    if len(set(hosts)) <= 1:
        return [(name, text)]
    parts: dict[str, list[str]] = {}
    shown: dict[str, str] = {}
    for i, (mt, host) in enumerate(zip(marks, hosts, strict=True)):
        start = 0 if i == 0 else mt.start()  # the banner before the first prompt belongs to the first device
        end = marks[i + 1].start() if i + 1 < len(marks) else len(text)
        parts.setdefault(host, []).append(text[start:end])
        shown.setdefault(host, mt.group(1).split("@")[-1])
    return [(f"{name} [{shown[h]}]", "".join(chunks)) for h, chunks in parts.items()]


def redact_device(device: Device) -> Device:
    """Redact what a snapshot from elsewhere may carry in clear (an uploaded snapshot.json is not trusted
    to have been made by this version, or by Sextant at all)."""
    device.raw_config = redact_text(device.raw_config)
    device.raw = redact_obj(device.raw) if device.raw else {}
    device.collection_warnings = [redact_text(w) or "" for w in device.collection_warnings]
    if device.virtualization:
        for vm in device.virtualization.vms:
            vm.notes = redact_text(vm.notes)
    return device


def same_device(a: Device, b: Device) -> bool:
    """Two captures of one device: same hostname and platform, and no serial numbers that disagree
    (a 'show spanning-tree' capture has no serial, so it joins the config of that switch)."""
    return (a.hostname.lower() == b.hostname.lower() and a.platform == b.platform
            and not (a.serial and b.serial and a.serial != b.serial))


def _distinct_name(dev: Device, taken: dict[str, Device] | list[Device]) -> Device:
    """A second device with a name already used (a FortiGate and a switch both 'core01', two unconfigured
    'Switch'): keep both, the new one under a name the topology can tell apart."""
    names = {d.hostname.lower() for d in (taken.values() if isinstance(taken, dict) else taken)}
    base = dev.hostname
    tag = dev.serial or dev.mgmt_ip or dev.platform or "2"
    new, n = f"{base} ({tag})", 2
    while new.lower() in names:
        n += 1
        new = f"{base} ({tag} {n})"
    dev.collection_warnings.append(f"Another device is also named {base}; this one is listed as {new}.")
    dev.hostname = new
    return dev


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
        if not same_device(old, dev):  # another device that happens to have the same name
            dev = _distinct_name(dev, snap.devices)
            index[dev.hostname.lower()] = len(snap.devices)
            snap.devices.append(dev)
            notes.append(f"{dev.hostname}: added next to the other {old.hostname}")
            continue
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
    failed = {e.split(": ", 1)[0] for e in errors}  # a file that failed again replaces its earlier error
    kept = [e for e in snap.errors if e.split(": ", 1)[0] not in done | failed]
    snap.errors = list(dict.fromkeys(kept + errors))
    return notes


def import_many(paths: list[Path], driver: str | None = None, site: str | None = None,
                progress: Any = None, keep_raw: bool = True,
                notes: list[str] | None = None) -> tuple[list[Device], list[str]]:
    """Import many config files at once (e.g. 20 switch configs or a backup-tool zip).

    The driver is detected per file unless given, so one batch can mix vendors. Returns (devices,
    errors). Several captures of one switch are combined; a log that visits several switches is
    split per switch. What was combined or split is added to `notes`, so files and devices add up.
    Devices keep their redacted command outputs (keep_raw) so a later import can be added to them.
    """
    import tempfile

    devices: dict[str, Device] = {}  # by (unique) hostname
    raws: dict[str, RawCollection] = {}
    first_file: dict[str, str] = {}  # hostname -> the file it came from first
    errors: list[str] = []
    notes = notes if notes is not None else []

    def host_of(text: str) -> str:
        prompt = re.search(r"^(?:[\w.@()/:-]+[#>]\s*)*([\w.@()/:-]+?)[#>]", text, re.M)
        return prompt.group(1).split("@")[-1].lower() if prompt else ""

    def inputs():
        for name, text in iter_inputs(paths, errors):
            parts = split_hosts(name, text)
            if len(parts) > 1:
                notes.append(f"{name} visits {len(parts)} devices ({', '.join(n.rsplit('[', 1)[1][:-1] for n, _ in parts)}): "
                             "imported as one capture each")
            yield from parts

    with tempfile.TemporaryDirectory(prefix="sextant-import-") as tmp:
        pending: list[tuple[str, str]] = []  # bare command captures: matched to their device after the rest
        queue = list(inputs())
        retry = False
        i = 0
        while queue:
            name, text = queue.pop(0)
            i += 1
            drv = driver or guess_driver(text, name)
            if not drv:  # a bare command capture of a switch we have: use that switch's platform
                host = host_of(text)
                drv = raws[host].driver if host in raws else None
            if not drv:
                if not retry:
                    pending.append((name, text))
                else:
                    errors.append(f"{name}: platform not recognised: {why_unrecognised(text)} (or use --driver)")
                if not queue and pending and not retry:
                    queue, pending, retry = pending, [], True
                continue
            f = Path(tmp) / f"{i:05d}-{Path(name).name}"
            f.write_text(text)
            try:
                raw = load_raw(f, drv, name=Path(name).stem)
                dev = parse_raw(raw, site=site, keep_raw=keep_raw)
                k = dev.hostname.lower()
                if k in raws and same_device(devices[k], dev):
                    # several captures of one switch (e.g. 'show run' and 'show spanning-tree'): combine them
                    prev = raws[k]
                    merged = {**prev.outputs, **{c: o for c, o in raw.outputs.items()
                                                 if c not in prev.outputs or len(str(o)) > len(str(prev.outputs[c]))}}
                    if "config" in prev.outputs and "config" not in raw.outputs:
                        merged["config"] = prev.outputs["config"]
                    raw = prev.model_copy(update={"outputs": merged})
                    dev = parse_raw(raw, site=site, keep_raw=keep_raw)
                    k = dev.hostname.lower()
                    notes.append(f"{name}: another capture of {dev.hostname} (first in {first_file.get(k, '?')}): "
                                 "combined into one device")
                elif k in devices:
                    dev = _distinct_name(dev, devices)
                    k = dev.hostname.lower()
                raws[k] = raw
                first_file.setdefault(k, name)
            except Exception as exc:  # noqa: BLE001 - one bad file must not stop the batch
                errors.append(f"{name}: {exc.__class__.__name__}: {redact_text(str(exc))}")
            else:
                devices[k] = dev
                if progress:
                    progress(name, drv, dev.hostname)
            if not queue and pending and not retry:
                queue, pending, retry = pending, [], True
    return list(devices.values()), errors
