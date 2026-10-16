"""Driver contract: collect raw data from a device, parse it into a model.Device."""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from sextant.model import Device


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
    layer: str | None = None  # override topology layer: core | distribution | access | edge | compute
    options: dict[str, Any] = Field(default_factory=dict)


class RawCollection(BaseModel):
    """Unparsed data as retrieved: command -> output, endpoint -> JSON, file -> text."""

    driver: str
    target: str
    method: str
    outputs: dict[str, Any] = Field(default_factory=dict)
    warnings: list[str] = Field(default_factory=list)


# A CLI prompt followed by a command: "sto-sw01#show run", "sw01> sh ver", "user@ex3400> show lldp neighbors"
_PROMPT = re.compile(r"^(?:[\w.@()/:-]+)(?:\(config[^)]*\))?[#>$]\s*((?:show|sh|display|dis|get|more|cat)\b.*?)\s*$",
                     re.M | re.I)
_RUNNING = ("show running-config", "show configuration | display set", "show configuration", "show run",
            "show full-configuration", "show")


def split_session_log(text: str, known: tuple[str, ...] = ()) -> dict[str, str] | None:
    """Split a terminal capture ('host#show run' ... 'host#show cdp nei det' ...) into {command: output}.

    Abbreviated commands are expanded against the driver's known commands the way the CLI does it:
    each typed word must be a prefix of the corresponding command word ('sh cdp nei det').
    Returns None when the text is not a session log.
    """
    marks = list(_PROMPT.finditer(text))
    if not marks:
        return None
    out: dict[str, str] = {}
    preamble = text[:marks[0].start()].strip()
    if preamble:
        out["_preamble"] = preamble  # login banner: model / software revision on some platforms
    for i, mt in enumerate(marks):
        body = text[mt.end():marks[i + 1].start() if i + 1 < len(marks) else len(text)].strip("\r\n")
        out[expand_command(mt.group(1), known)] = body
    return out


def expand_command(typed: str, known: tuple[str, ...]) -> str:
    words = typed.split()
    if words and words[0].lower() in ("sh", "sho"):
        words[0] = "show"
    for cmd in known:
        cw = cmd.split()
        if len(cw) == len(words) and all(c.lower().startswith(w.lower()) for w, c in zip(words, cw, strict=True)):
            return cmd
    return " ".join(words)


class Driver(ABC):
    id: str = ""
    label: str = ""
    methods: tuple[str, ...] = ("ssh",)
    commands: tuple[str, ...] = ()  # read-only commands collect() runs; also used to expand session logs

    @abstractmethod
    def collect(self, target: Target, creds: Credentials) -> RawCollection:
        """Connect read-only and gather everything parse() needs."""

    @abstractmethod
    def parse(self, raw: RawCollection) -> Device:
        """Pure function: raw data -> Device. Must tolerate missing outputs."""

    def from_file(self, path: Path) -> RawCollection:
        """Offline import of an exported config file or a terminal session log with several commands."""
        text = path.read_text(errors="replace")
        outputs: dict[str, Any] = {"config": text}
        parts = split_session_log(text, self.commands)
        if parts:
            outputs = dict(parts)
            run = next((parts[c] for c in _RUNNING if c in parts), None)
            if run is not None:
                outputs["config"] = run
        return RawCollection(driver=self.id, target=path.name, method="file", outputs=outputs)
