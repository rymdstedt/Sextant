"""Read-only SSH command runner shared by the CLI-based drivers (netmiko)."""

from __future__ import annotations

import logging

from sextant.drivers.base import Credentials, RawCollection, Target

log = logging.getLogger(__name__)

# Only these command prefixes may ever be sent. Collection is strictly read-only.
READ_ONLY_PREFIXES = ("show ", "display ", "get ", "cat ", "hostnamectl", "ip ", "lsblk", "df ", "systemctl list",
                      "ss ", "uname", "uptime", "free ", "lscpu", "cat", "timedatectl", "dmidecode", "findmnt",
                      "lspci", "lsb_release", "journalctl --list-boots", "dir ", "more ", "terminal length",
                      "terminal pager", "no page", "set cli screen-length", "config system console")


def assert_read_only(command: str) -> None:
    c = command.strip()
    if not c.startswith(READ_ONLY_PREFIXES) or any(x in c for x in (";", "&&", "|| ", "`", "$(", ">")):
        if not (c.startswith(("show ", "display ")) and "| " in c):  # allow output filters on show
            raise ValueError(f"Refusing non read-only command: {command!r}")


def run_commands(target: Target, creds: Credentials, device_type: str, commands: list[str],
                 driver_id: str, timeout: int = 60) -> RawCollection:
    """Connect with netmiko, run each command, return outputs. Failures become warnings."""
    from netmiko import ConnectHandler  # imported lazily: heavy, and not needed for offline parsing

    raw = RawCollection(driver=driver_id, target=target.name, method="ssh")
    params = {
        "device_type": device_type, "host": target.host or target.name, "username": creds.username,
        "password": creds.password, "port": target.port or 22, "timeout": timeout,
        "conn_timeout": 20, "fast_cli": False,
    }
    if creds.ssh_key_file:
        params.update(use_keys=True, key_file=creds.ssh_key_file)
    if creds.enable_secret:
        params["secret"] = creds.enable_secret
    with ConnectHandler(**params) as conn:
        if creds.enable_secret:
            try:
                conn.enable()
            except Exception as exc:  # noqa: BLE001
                raw.warnings.append(f"enable failed: {exc.__class__.__name__}")
        for cmd in commands:
            assert_read_only(cmd)
            try:
                raw.outputs[cmd] = conn.send_command(cmd, read_timeout=timeout)
            except Exception as exc:  # noqa: BLE001
                raw.warnings.append(f"{cmd}: {exc.__class__.__name__}: {exc}")
                log.warning("%s on %s failed: %s", cmd, target.name, exc)
    return raw
