"""Driver contract: collect raw data from a device, parse it into a model.Device."""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from hsdoc.model import Device


class Credentials(BaseModel):
    username: str | None = None
    password: str | None = None
    api_token: str | None = None
    ssh_key_file: str | None = None
    enable_secret: str | None = None
    snmp_community: str | None = None
    snmp_v3_user: str | None = None
    snmp_v3_auth: str | None = None
    snmp_v3_priv: str | None = None

    def __repr__(self) -> str:  # never leak secrets into logs or tracebacks
        return f"Credentials(username={self.username!r}, ...)"

    __str__ = __repr__


class Target(BaseModel):
    """One entry of inventory.yaml."""

    name: str
    host: str | None = None
    driver: str  # registry id, e.g. "cisco_ios"
    method: str = "ssh"  # ssh | snmp | api | file
    port: int | None = None
    credentials: str | None = None  # name of a credential set
    file: str | None = None  # for method=file
    verify_tls: bool = True
    site: str | None = None
    options: dict[str, Any] = Field(default_factory=dict)


class RawCollection(BaseModel):
    """Unparsed data as retrieved: command -> output, endpoint -> JSON, file -> text."""

    driver: str
    target: str
    method: str
    outputs: dict[str, Any] = Field(default_factory=dict)
    warnings: list[str] = Field(default_factory=list)


class Driver(ABC):
    id: str = ""
    label: str = ""
    methods: tuple[str, ...] = ("ssh",)

    @abstractmethod
    def collect(self, target: Target, creds: Credentials) -> RawCollection:
        """Connect read-only and gather everything parse() needs."""

    @abstractmethod
    def parse(self, raw: RawCollection) -> Device:
        """Pure function: raw data -> Device. Must tolerate missing outputs."""

    def from_file(self, path: Path) -> RawCollection:
        """Offline import of an exported config file."""
        return RawCollection(
            driver=self.id, target=path.name, method="file",
            outputs={"config": path.read_text(errors="replace")},
        )
