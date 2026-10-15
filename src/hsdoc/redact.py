"""Strip secrets from raw configs and command output before anything is saved.

Redaction is line based and conservative: when in doubt, mask. The replacement
keeps the keyword and type so a reviewer can still see *that* a secret is set
and how it is stored (type 7 vs type 9 matters for the analysis), just not the
value. SNMP communities "public" and "private" are kept on purpose: they are
findings in themselves.
"""

from __future__ import annotations

import re
from typing import Any

MASK = "<redacted>"
_KEEP_COMMUNITIES = {"public", "private"}

# (pattern, replacement). Group 1 is always the part that is kept.
_RULES: list[tuple[re.Pattern[str], str]] = [
    # Junos: secret "$9$..."; encrypted-password "$6$..."
    (re.compile(r'((?:encrypted-password|secret|pre-shared-key\s+ascii-text|authentication-key)\s+)"[^"]*"', re.I),
     rf'\g<1>"{MASK}"'),
    # FortiOS: set password ENC xxx / set psksecret ENC xxx / set passwd ENC...
    (re.compile(r'(\bset\s+(?:password|passwd|psksecret|secret|key|private-key|passphrase|auth-pwd|priv-pwd|'
                r'pre-shared-key|ldap-password|community|token|auth-password|sso-password)\s+)(?:ENC\s+)?(?:"[^"]*"|\S+)',
                re.I), rf"\g<1>{MASK}"),
    # Cisco IOS/NX-OS/ASA: "enable secret 9 $9$...", "username x secret 5 $1$..", "password 7 0822..."
    (re.compile(r'((?:enable\s+)?(?:secret|password)\s+(?:sha512\s+|\d+\s+)?)(?!"?<redacted>)\S+(.*)$', re.I), rf"\g<1>{MASK}\2"),
    # "key 7 xxxx", "key-string xxx", "authentication-key ...", "md5 ... key"
    (re.compile(r"(\b(?:key-string|authentication-key|message-digest-key\s+\d+\s+md5)\s+(?:\d+\s+)?)\S+", re.I),
     rf"\g<1>{MASK}"),
    (re.compile(r"(\bkey\s+[0-7]\s+)\S+", re.I), rf"\g<1>{MASK}"),
    (re.compile(r"(\bcrypto\s+isakmp\s+key\s+)\S+", re.I), rf"\g<1>{MASK}"),
    # pre-shared keys (IOS crypto isakmp key / tunnel-group ipsec-attributes)
    (re.compile(r"((?:pre-shared-key|ikev\d\s+(?:local|remote)-authentication\s+pre-shared-key)\s+(?:\d+\s+)?)\S+", re.I),
     rf"\g<1>{MASK}"),
    # tacacs/radius "server-key", "key 7 ..."
    (re.compile(r"(\bserver-key\s+(?:\d+\s+)?)\S+", re.I), rf"\g<1>{MASK}"),
    # XML (pfSense/OPNsense/PAN-OS): <password>..</password>, <bcrypt-hash>, <pre-shared-key>, <phash>
    (re.compile(r"(<(password|bcrypt-hash|sha512-hash|pre-shared-key|presharedkey|phash|md5-hash|secret|key|"
                r"privatekey|private-key|tls|shared_key|community|apikey|api_key|authkey|privkey|prv)>)"
                r"[^<]*(</\2>)", re.I), rf"\g<1>{MASK}\3"),
    # generic "password: x", "password=x", JSON "password": "x"
    (re.compile(r'(["\']?(?:password|passwd|secret|token|api[_-]?key|psk|private[_-]?key)["\']?\s*[:=]\s*)'
                r'(?:"[^"]*"|\'[^\']*\'|\S+)', re.I), rf'\g<1>"{MASK}"'),
    # PEM blocks handled separately below
]

_SNMP_COMMUNITY = re.compile(
    r"(snmp-server\s+community\s+|snmp-server\s+host\s+\S+\s+(?:version\s+\S+\s+)?|"
    r"snmp\s+community\s+|community\s+(?:name\s+)?|rocommunity6?\s+|rwcommunity6?\s+)"
    r'("?)([^\s"]+)("?)', re.I)
_PEM = re.compile(r"-----BEGIN ([A-Z ]*PRIVATE KEY|CERTIFICATE)-----.*?-----END \1-----", re.S)
_ASA_CERT = re.compile(r"(certificate (?:ca )?[0-9a-f]+\n)(?:\s+[0-9a-f ]+\n)+\s+quit", re.I)


def _community(m: re.Match[str]) -> str:
    value = m.group(3)
    keep = value.lower() in _KEEP_COMMUNITIES or value.lower() in {"ro", "rw", "view", "version", "2c", "1", "3",
                                                                      "informs", "traps"}
    return m.group(0) if keep else f"{m.group(1)}{m.group(2)}{MASK}{m.group(4)}"


def redact_line(line: str) -> str:
    if "snmp" in line.lower() or "community" in line.lower():
        line = _SNMP_COMMUNITY.sub(_community, line)
    for pattern, repl in _RULES:
        if pattern.search(line):
            line = pattern.sub(repl, line)
    return line


def redact_text(text: str | None) -> str | None:
    """Redact a whole config / command output."""
    if not text:
        return text
    text = _PEM.sub(lambda m: f"-----BEGIN {m.group(1)}-----\n{MASK}\n-----END {m.group(1)}-----", text)
    text = _ASA_CERT.sub(lambda m: f"{m.group(1)}  {MASK}\n  quit", text)
    return "\n".join(redact_line(line) for line in text.splitlines())


_SECRET_KEYS = re.compile(r"(pass(word|wd|phrase)?|secret|token|psk|private.?key|api.?key|community|"
                          r"pre.?shared|bcrypt|hash|key.?string)$", re.I)


def redact_obj(obj: Any) -> Any:
    """Redact nested API JSON: values under secret-looking keys, and all strings as text."""
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if isinstance(k, str) and _SECRET_KEYS.search(k) and isinstance(v, (str, int)) and v not in ("", None):
                out[k] = v if str(v).lower() in _KEEP_COMMUNITIES else MASK
            else:
                out[k] = redact_obj(v)
        return out
    if isinstance(obj, list):
        return [redact_obj(v) for v in obj]
    if isinstance(obj, str) and "\n" in obj:
        return redact_text(obj)
    return obj


# Back-compat name referenced from model.py's docstring.
redact_config = redact_text
