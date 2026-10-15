"""Driver registry. Each driver module calls register() at import time."""

from __future__ import annotations

from hsdoc.drivers.base import Credentials, Driver, RawCollection, Target

REGISTRY: dict[str, Driver] = {}


def register(driver: Driver) -> Driver:
    REGISTRY[driver.id] = driver
    return driver


def get_driver(driver_id: str) -> Driver:
    try:
        return REGISTRY[driver_id]
    except KeyError:
        raise KeyError(f"Unknown driver '{driver_id}'. Known: {', '.join(sorted(REGISTRY))}") from None


__all__ = ["REGISTRY", "Credentials", "Driver", "RawCollection", "Target", "get_driver", "register"]
