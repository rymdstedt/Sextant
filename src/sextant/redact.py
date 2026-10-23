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

# A secret value: quoted or one word, and not one an earlier rule already masked.
_V = r'(?!"?<redacted>)(?:"[^"]*"|\S+)'
_TYPE = r"(?:[0-9]\s+)?(?:(?:ciphertext|plaintext)\s+)?"  # Cisco type digit, AOS-CX ciphertext/plaintext

# (pattern, replacement). Group 1 is always the part that is kept: the keyword and how the secret is
# stored (type 7 vs 9 matters to the analysis), never the value.
_RULES: list[tuple[re.Pattern[str], str]] = [
    # Junos and others, quoted: secret "$9$...", encrypted-password "$6$...", key "$9$...", value "$9$..."
    (re.compile(r'((?:encrypted-password|secret|pre-shared-key\s+ascii-text|authentication-key(?:\s+\d+\s+type\s+\S+'
                r'\s+value)?|(?<![\w-])key|plain-text-password-value)\s+)"(?!<redacted>)[^"]*"', re.I), rf'\g<1>"{MASK}"'),
    # FortiOS: any "set <name> [ENC] value" whose name says secret (password, passwd, psksecret, sae-password,
    # ppk-secret, api-key, md5-key, wifi-passphrase, ...), except names that only contain the word
    (re.compile(r"(\bset\s+(?!keylife|key-?chain|keyword|keepalive)[\w-]*(?:passw|secret|psk|pwd|passphrase|token|"
                r"key|community)[\w-]*\s+)(?:ENC\s+)?" + _V, re.I), rf"\g<1>{MASK}"),
    # ProCurve / AOS-S: password manager user-name "admin" sha1 "<hash>"  ("password manager" alone = set, no value)
    (re.compile(r'(\bpassword\s+(?:manager|operator)\b.*?\b(?:sha1|sha256|plaintext)\s+)("[^"]*"|\S+)', re.I),
     rf'\g<1>"{MASK}"'),
    # Cisco IOS/NX-OS/ASA "enable secret 9 $9$...", "username x secret 5 ..", "password 7 0822...", AOS-CX
    # "password ciphertext AQB..."
    (re.compile(r'((?:enable\s+)?(?:secret|password)\s+(?:sha512\s+|\d+\s+)?(?:(?:ciphertext|plaintext)\s+)?)'
                r'(?!\d+\s|"?<redacted>|(?:manager|operator|all|port-access|encryption|minimum-length|complexity|'
                r'history|configuration-control|aging)\b)\S+(.*)$', re.I), rf"\g<1>{MASK}\2"),
    (re.compile(r"(\bpasswd\s+)" + _V, re.I), rf"\g<1>{MASK}"),  # ASA "passwd x encrypted"
    # NTP/OSPF/IS-IS keys: "ntp authentication-key 1 md5 <key> 7", "ip ospf authentication-key 7 <key>",
    # Junos "authentication-key 1 type md5 value <key>", AOS-CX "authentication-key 1 sha1 ciphertext <key>"
    (re.compile(r"(\bauthentication-key\s+(?:\d+\s+)?(?:(?:md5|sha\d*|hmac-\S+|cmac-\S+|type\s+\S+|value|ciphertext|"
                r"plaintext)\s+)*)" + _V, re.I), rf"\g<1>{MASK}"),
    (re.compile(r"(\b(?:key-string|message-digest-key\s+\d+\s+md5)\s+(?:\d+\s+)?)" + _V, re.I), rf"\g<1>{MASK}"),
    (re.compile(r"((?<![\w-])key\s+[0-7]\s+)" + _V, re.I), rf"\g<1>{MASK}"),
    (re.compile(r"(\bplain-text-password-value\s+)" + _V, re.I), rf"\g<1>{MASK}"),
    # RADIUS/TACACS+ keys on one line, and the bare " key x" of a server sub-mode (not "key 1" of a key chain)
    (re.compile(r"(\b(?:radius-server|tacacs-server|aaa-server|tacacs\+?|radius)\b.*?(?<![\w-])key\s+" + _TYPE + ")" + _V,
                re.I), rf"\g<1>{MASK}"),
    (re.compile(r"^(\s*key\s+" + _TYPE + r")(?!chain\b|config-key\b|\d+\s*$)" + _V, re.I), rf"\g<1>{MASK}"),
    (re.compile(r"(\b(?:pac|failover)\s+key\s+(?:hex\s+)?(?:[0-7]\s+)?)" + _V, re.I), rf"\g<1>{MASK}"),
    (re.compile(r"(\bconfig-key\s+password-encrypt\s+)" + _V, re.I), rf"\g<1>{MASK}"),
    # HSRP/VRRP/GLBP/NHRP: "standby 1 authentication <key>", "vrrp 1 authentication text <key>" (md5 key-chain
    # names a key chain, md5 key-string is masked above)
    (re.compile(r"(\b(?:standby\s+(?:\d+\s+)?|vrrp\s+\d+\s+|glbp\s+\d+\s+|nhrp\s+)authentication\s+(?:text\s+)?)"
                r"(?!md5\b|key-chain\b)" + _V, re.I), rf"\g<1>{MASK}"),
    (re.compile(r"(\bwpa-psk\s+(?:ascii|hex)\s+(?:\d\s+)?)" + _V, re.I), rf"\g<1>{MASK}"),
    (re.compile(r"(\bcrypto\s+isakmp\s+key\s+(?:\d\s+)?)" + _V, re.I), rf"\g<1>{MASK}"),
    # pre-shared keys: IOS keyring "pre-shared-key address <ip> key <key>", IKEv2 "pre-shared-key [local|remote]
    # <key>", ASA "ikev1 pre-shared-key <key>", Junos "pre-shared-key ascii-text <key>"
    (re.compile(r"(\bpre-shared-key\b.*?(?<![\w-])key\s+(?:[0-7]\s+)?)" + _V, re.I), rf"\g<1>{MASK}"),
    (re.compile(r"(\b(?:ikev\d\s+(?:local|remote)-authentication\s+)?pre-shared-key\s+(?:(?:local|remote)\s+)?"
                r"(?:(?:ascii-text|hexadecimal)\s+)?(?:\d\s+)?)(?!address\b|hostname\b)" + _V, re.I), rf"\g<1>{MASK}"),
    (re.compile(r"(\bserver-key\s+(?:\d+\s+)?)" + _V, re.I), rf"\g<1>{MASK}"),
    # XML (pfSense/OPNsense/PAN-OS): <password>..</password>, <bcrypt-hash>, <pre-shared-key>, <phash>
    (re.compile(r"(<(password|bcrypt-hash|sha512-hash|pre-shared-key|presharedkey|phash|md5-hash|secret|key|"
                r"privatekey|private-key|tls|shared_key|apikey|api_key|authkey|privkey|prv|otp_seed)>)"
                r"[^<]*(</\2>)", re.I), rf"\g<1>{MASK}\3"),
    # generic "password: x", "password=x", JSON "password": "x"
    (re.compile(r'(["\']?(?:password|passwd|secret|token|api[_-]?key|psk|private[_-]?key)["\']?\s*[:=]\s*)'
                r'(?!"?<redacted>)(?:"[^"]*"|\'[^\']*\'|\S+)', re.I), rf'\g<1>"{MASK}"'),
    # HTTP: "Authorization: Bearer x", "X-PAN-KEY: x", "?key=x" in a URL
    (re.compile(r"(\bAuthorization\s*:\s*(?:Bearer|Basic|Token|Digest|PVEAPIToken=?)\s*)\S+", re.I), rf"\g<1>{MASK}"),
    (re.compile(r"(\bX-PAN-KEY\s*:\s*)\S+", re.I), rf"\g<1>{MASK}"),
    (re.compile(r"([?&](?:key|apikey|api_key|access_token|token|password|passwd|secret)=)[^&\s\"']+", re.I),
     rf"\g<1>{MASK}"),
    # credentials in a URL: "scp://backup:<password>@192.0.2.50/", "https://user:<password>@host"
    (re.compile(r"(\b[a-z][a-z0-9+.-]*://[^/\s:@]+:)[^@\s/]+(@)", re.I), rf"\g<1>{MASK}\2"),
    # PEM blocks handled separately below
]

# Lines that carry human text: descriptions, remarks, comments, aliases, banners
_FREE_TEXT = re.compile(r"^\s*(?:description|remark|banner|alias|(?:set|edit)\s+(?:comments?|description|alias))\b"
                        r"|\s(?:description|comments?|remark)\s+\"", re.I)
_PASSWORD_RULE = _RULES[3][0]

_XML_COMMUNITY = re.compile(r"(<(community|rocommunity|rwcommunity)>)([^<]*)(</\2>)", re.I)
_SNMP_COMMUNITY = re.compile(
    r"(snmp-server\s+community\s+|snmp\s+community\s+|community\s+(?:name\s+)?|rocommunity6?\s+|rwcommunity6?\s+)"
    r'("?)([^\s"]+)("?)', re.I)
_SNMP_HOST = re.compile(r"^(\s*snmp-server\s+host\s+)(.*)$", re.I)
_HOST_WORDS = {"traps", "informs", "version", "1", "2c", "3", "auth", "noauth", "priv", "trap", "inform"}
_NO_COMMUNITY = {"use-vrf", "filter-vrf", "source-interface", "poll", "udp-port"}


def _snmp_host(line: str) -> str:
    """'snmp-server host <host> [traps|informs] [version 1|2c|3 [auth|noauth|priv]] <community|v3 user> ...',
    ASA '<interface> <ip> ...', AOS-S '<ip> community "<community>"'. NX-OS 'use-vrf' lines carry none."""
    mt = _SNMP_HOST.match(line)
    if not mt:
        return line
    tokens = mt.group(2).split()
    i = 1  # the host
    if len(tokens) > 1 and re.fullmatch(r"[\d.]+|[0-9a-f:]*:[0-9a-f:]*", tokens[1], re.I):
        i = 2  # ASA: interface name, then the address
    v3 = False
    while i < len(tokens):
        t = tokens[i].lower()
        if t in _NO_COMMUNITY:
            return line
        if t == "community" and i + 1 < len(tokens):
            i += 1
            break
        if t in _HOST_WORDS:
            v3 = v3 or (t == "3" and tokens[i - 1].lower() == "version")
            i += 1
            continue
        break
    if i >= len(tokens) or v3 or tokens[i].strip('"').lower() in _KEEP_COMMUNITIES or MASK in tokens[i]:
        return line
    tokens[i] = f'"{MASK}"' if tokens[i].startswith('"') else MASK
    return mt.group(1) + " ".join(tokens)
# SNMPv3 user keys: IOS/ASA/NX-OS "auth sha <key> priv aes 128 <key>", AOS-S 'auth sha "<key>" priv aes "<key>"',
# AOS-CX "auth sha auth-pass ciphertext <key> priv aes priv-pass ciphertext <key>"
_SNMPV3 = re.compile(r'(\b(?:auth\s+(?:md5|sha\S*)|priv(?:\s+(?:des\S*|3des|aes\S*)(?:\s+\d{3})?)?)\s+'
                     r'(?:(?:auth|priv)-pass\s+)?(?:(?:plaintext|ciphertext)\s+)?)'
                     r'(?!(?:read|write|notify|access|context|match|v\d)\b)("[^"]*"|\S+)', re.I)
_PEM = re.compile(r"-----BEGIN ([A-Z ]*PRIVATE KEY|CERTIFICATE)-----.*?-----END \1-----", re.S)
_ASA_CERT = re.compile(r"(certificate (?:ca )?[0-9a-f]+\n)(?:\s+[0-9a-f ]+\n)+\s+quit", re.I)


def _community(m: re.Match[str]) -> str:
    value = m.group(3)
    keep = value.lower() in _KEEP_COMMUNITIES or value.lower() in {"ro", "rw", "view", "version", "2c", "1", "3",
                                                                      "informs", "traps", "auth", "noauth", "priv"}
    # ASA "snmp-server host inside 10.0.0.50 community x": the interface took the host's place, keep the address
    keep = keep or bool(re.fullmatch(r"[\d.]+|[0-9a-f:]+:[0-9a-f:]*", value, re.I))
    return m.group(0) if keep else f"{m.group(1)}{m.group(2)}{MASK}{m.group(4)}"


def redact_line(line: str) -> str:
    if "<" in line and "community>" in line.lower():
        line = _XML_COMMUNITY.sub(lambda m: m.group(0) if m.group(3).strip().lower() in _KEEP_COMMUNITIES
                                  else f"{m.group(1)}{MASK}{m.group(4)}", line)
    elif "snmp" in line.lower() or "community" in line.lower():
        if _SNMP_HOST.match(line):
            line = _snmp_host(line)
        else:
            line = _SNMP_COMMUNITY.sub(_community, line)
    if "snmp" in line.lower():
        line = _SNMPV3.sub(lambda m: m.group(0) if m.group(2).strip('"') == MASK else f"{m.group(1)}{MASK}", line)
    free_text = bool(_FREE_TEXT.match(line))
    for pattern, repl in _RULES:
        if free_text and pattern is _PASSWORD_RULE:
            continue  # "description reset password via portal" is a sentence, not a secret
        if pattern.search(line):
            line = pattern.sub(repl, line)
    return line


# XML configs (PAN-OS, pfSense, OPNsense): secrets are elements, matched on the element name.
_XML_SECRET_TAG = re.compile(
    r"(?:^|[-_])(pass(?:word|wd|phrase)?|phash|secret|key|private-?key|privkey|prv|psk|pre-?shared-?key|"
    r"presharedkey|shared-?key|api-?key|apikey|authkey|token|bindpw|authpwd|privpwd|auth-?pwd|priv-?pwd|hash|"
    r"radius_secret|ldap_bindpw|tls|tls_?key|static_?key|otp_?seed|seed|enckey|trapstring|ipsecpsk|[a-z]*psk)$",
    re.I)
_XML_COMMUNITY_TAG = re.compile(r"(?:^|[-_])community(?:-string)?$|^(?:ro|rw)community$", re.I)
_PRIVATE_PEM = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----|-----BEGIN ENCRYPTED PRIVATE KEY-----")
# Values that are secrets whatever the element is called: PAN-OS encrypted blobs ("-AQ==..."), FortiOS "ENC ..."
_ENCRYPTED_VALUE = re.compile(r"^(-AQ==|ENC\s+\S{8,})")


def redact_xml(text: str) -> str | None:
    """Parse XML and mask secret element text. Returns None if the text is not well-formed XML.

    Public certificates stay (they are documentation, not secrets); private keys anywhere are masked.
    Entities/DTDs are refused before parsing (no external entities, no billion laughs).
    """
    import xml.etree.ElementTree as ET

    if re.search(r"<!DOCTYPE|<!ENTITY", text[:5000], re.I):
        return None
    head = ""
    body = text
    mt = re.match(r"\s*(<\?xml[^>]*\?>)\s*", text)
    if mt:
        head, body = mt.group(1) + "\n", text[mt.end():]
    try:
        root = ET.fromstring(body)
    except ET.ParseError:
        return None
    for el in root.iter():
        tag = el.tag.rsplit("}", 1)[-1] if isinstance(el.tag, str) else ""
        txt = (el.text or "").strip()
        if not txt or len(el):
            continue
        if _XML_COMMUNITY_TAG.search(tag):
            if txt.lower() not in _KEEP_COMMUNITIES:
                el.text = MASK
        elif (_XML_SECRET_TAG.search(tag) and not tag.lower().startswith("public")) or _PRIVATE_PEM.search(txt) \
                or _ENCRYPTED_VALUE.match(txt):
            el.text = MASK
        for k, v in list(el.attrib.items()):
            if _XML_SECRET_TAG.search(k) and v:
                el.attrib[k] = MASK
    return head + ET.tostring(root, encoding="unicode")


# FortiOS names an SNMP community with `set name "x"` inside `config system snmp community`
_FORTI_COMMUNITY_BLOCK = re.compile(r"^(\s*)config system snmp community\s*$.*?^\1end\s*$", re.M | re.S)


def _forti_community(mt: re.Match[str]) -> str:
    return re.sub(r'(\bset name\s+)("?)(?!(?:public|private)"?\s*$)[^"\n]+("?)', rf"\1\2{MASK}\3", mt.group(0),
                  flags=re.I | re.M)


def redact_text(text: str | None) -> str | None:
    """Redact a whole config / command output."""
    if not text:
        return text
    if text.lstrip().startswith("<"):
        xml = redact_xml(text)
        if xml is not None:
            return xml
    text = _PEM.sub(lambda m: f"-----BEGIN {m.group(1)}-----\n{MASK}\n-----END {m.group(1)}-----", text)
    if "config system snmp community" in text:
        text = _FORTI_COMMUNITY_BLOCK.sub(_forti_community, text)
    text = _ASA_CERT.sub(lambda m: f"{m.group(1)}  {MASK}\n  quit", text)
    out = "\n".join(redact_line(line) for line in text.splitlines())
    if text.lstrip().startswith("<"):  # malformed XML fell through: never emit a raw tag-like mask
        out = out.replace(MASK, "&lt;redacted&gt;")
    return out


# JSON key names (camelCase, snake_case, kebab-case) that hold secrets: preSharedKey, secret_key, authKey,
# privKey, pwd, community_string, Proxmox "ticket"; a plain "key" holds a secret only as a string (vSphere
# device keys are numbers)
_SECRET_KEYS = re.compile(r"(pass(word|wd|phrase)?s?|pwd|secret|token|ticket|psk|private.?key|priv.?key|api.?key|"
                          r"auth.?key|shared.?key|secret.?key|community(.?string)?|pre.?shared(.?key)?|bcrypt|hash|"
                          r"key.?string)$", re.I)


def _mask_all(v: Any) -> Any:
    if isinstance(v, dict):
        return {k: _mask_all(x) for k, x in v.items()}
    if isinstance(v, list):
        return [_mask_all(x) for x in v]
    if v in ("", None) or isinstance(v, bool):
        return v
    return v if str(v).lower() in _KEEP_COMMUNITIES else MASK


def redact_obj(obj: Any) -> Any:
    """Redact nested API JSON: everything under secret-looking keys, and all strings as text."""
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if isinstance(k, str) and (_SECRET_KEYS.search(k) or (k.lower() == "key" and isinstance(v, str))):
                out[k] = _mask_all(v)
            else:
                out[k] = redact_obj(v)
        return out
    if isinstance(obj, list):
        return [redact_obj(v) for v in obj]
    if isinstance(obj, str) and obj:
        return redact_text(obj)
    return obj


# Back-compat name referenced from model.py's docstring.
redact_config = redact_text
