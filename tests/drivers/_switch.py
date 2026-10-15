"""Shared helpers for the switch driver tests."""

from pathlib import Path

from sextant.drivers import RawCollection
from sextant.pipeline import import_file, parse_raw

EXAMPLES = Path(__file__).resolve().parents[2] / "examples"


def load(driver: str):
    return parse_raw(RawCollection.model_validate_json((EXAMPLES / driver / "raw.json").read_text()))


def load_file(driver: str):
    return import_file(EXAMPLES / driver / "running-config.txt", driver)


def iface(device, name):
    return next(i for i in device.interfaces if i.name == name)


def finding_ids(device):
    return {f.check_id for f in device.findings}


def assert_no_secrets(device, *plaintexts):
    dump = device.model_dump_json()
    for p in plaintexts:
        assert p not in dump
