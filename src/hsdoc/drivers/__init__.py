"""Driver registry. Each driver module calls register() at import time."""

from __future__ import annotations

import importlib
import logging

from hsdoc.drivers.base import Credentials, Driver, RawCollection, Target

REGISTRY: dict[str, Driver] = {}

DRIVER_MODULES = [
    "cisco_ios", "cisco_nxos", "cisco_asa", "aruba_aoscx", "hp_procurve", "juniper_junos",
    "fortigate", "paloalto", "pfsense",
    "vmware", "proxmox", "hyperv", "linux", "snmp",
]
_loaded = False


def register(driver: Driver) -> Driver:
    REGISTRY[driver.id] = driver
    return driver


def load_all() -> dict[str, Driver]:
    global _loaded
    if not _loaded:
        for name in DRIVER_MODULES:
            try:
                importlib.import_module(f"hsdoc.drivers.{name}")
            except ModuleNotFoundError as exc:
                if exc.name != f"hsdoc.drivers.{name}":
                    raise
                logging.getLogger(__name__).debug("driver module %s not present", name)
        _loaded = True
    return REGISTRY


def get_driver(driver_id: str) -> Driver:
    load_all()
    try:
        return REGISTRY[driver_id]
    except KeyError:
        raise KeyError(f"Unknown driver '{driver_id}'. Known: {', '.join(sorted(REGISTRY))}") from None


__all__ = ["REGISTRY", "Credentials", "Driver", "RawCollection", "Target", "get_driver", "load_all", "register"]
