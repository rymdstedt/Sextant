"""Read-only SSH command runner shared by the CLI-based drivers (netmiko)."""

from __future__ import annotations

import logging
import re

from sextant.drivers.base import Credentials, RawCollection, Target

log = logging.getLogger(__name__)

# Only these commands may ever be sent. Collection is strictly read-only: network OS "show"/"display"/"get"
# commands (with output filters only) and a fixed set of read-only Linux forms.
READ_ONLY_PREFIXES = ("show ", "display ", "get ", "dir ", "terminal length", "terminal pager", "no page",
                      "set cli screen-length")
READ_ONLY_EXACT = frozenset({"show", "lscpu", "hostnamectl", "timedatectl", "uname", "uptime"})
_PATH_ARGS = r"(?:\s+[\w./*@:+,~-]+)+"  # plain file names / globs, no shell syntax
_LINUX_READ_ONLY = re.compile(r"""^(?:
    cat{p} | more{p}
  | hostnamectl\s+(?:status|show)
  | timedatectl\s+(?:status|show|show-timesync|timesync-status)
  | ip(?:\s+-[a-z0-9]+)*\s+(?:addr|address|route|link|neigh|rule)(?:\s+(?:show|list))?
  | (?:uname|uptime|free|df|lspci|lsb_release)(?:\s+-[A-Za-z0-9]+)+
  | ss(?:\s+-[A-JL-Za-z0-9]+)+
  | lsblk(?:\s+-[A-Za-z]+|\s+[A-Z][A-Z,:-]*)*
  | findmnt(?:\s+-[A-Za-z]+|\s+[\w,/-]+)*
  | dmidecode(?:\s+-[A-Za-z]+|\s+[\w-]+)*
  | systemctl\s+list-[a-z-]+(?:\s+--?[\w=,-]+)*
  | journalctl\s+--list-boots
)$""".replace("{p}", _PATH_ARGS), re.X)
# "show ... | <filter>" output modifiers (IOS/NX-OS/ASA/AOS-CX/ProCurve/Junos). No redirect/tee/append/save.
OUTPUT_FILTERS = frozenset({"include", "exclude", "begin", "section", "count", "match", "except", "no-more",
                            "display", "find", "last", "trim", "i", "in", "inc", "incl", "e", "ex", "exc", "excl",
                            "b", "be", "beg", "s", "se", "sec", "sect", "c", "co", "cou"})
_SHELL_META = re.compile(r"[;`<>&]|\$\(|\$\{|[\x00-\x1f\x7f]")


def _is_read_only(command: str) -> bool:
    if _SHELL_META.search(command):  # newlines (a second command), ; && || ` $( > redirection, &
        return False
    c = command.strip()
    head, *filters = (p.strip() for p in c.split("|"))
    if filters:  # pipes only as show/display output filters
        if not head.startswith(("show ", "display ")):
            return False
        for f in filters:
            word = f.split()[0].lower() if f.split() else ""
            if word not in OUTPUT_FILTERS:
                return False
    return head in READ_ONLY_EXACT or head.startswith(READ_ONLY_PREFIXES) or bool(_LINUX_READ_ONLY.match(head))


def assert_read_only(command: str) -> None:
    if not _is_read_only(command):
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
