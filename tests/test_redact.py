from sextant.redact import MASK, redact_obj, redact_text


def test_cisco_secrets_masked_type_kept():
    out = redact_text("enable secret 9 $9$abc\nusername bob privilege 15 password 7 0822455D0A16\n"
                      "snmp-server community S3cret RO 10\nsnmp-server community public RO\n"
                      "crypto isakmp key MyPsk address 203.0.113.1\n tacacs-server key 7 1234")
    assert "$9$abc" not in out and "0822455D0A16" not in out and "S3cret" not in out and "MyPsk" not in out
    assert "secret 9 " + MASK in out and "password 7 " + MASK in out
    assert "community public RO" in out


def test_vendor_formats():
    out = redact_text(' set password ENC SH2xyz\n set psksecret ENC abc==\n'
                      'set system root-authentication encrypted-password "$6$x";\n<password>hunter2</password>\n'
                      '-----BEGIN RSA PRIVATE KEY-----\nMIIabc\n-----END RSA PRIVATE KEY-----')
    for leaked in ("SH2xyz", "abc==", "$6$x", "hunter2", "MIIabc"):
        assert leaked not in out
    assert "service password-encryption" == redact_text("service password-encryption")


def test_redact_json():
    out = redact_obj({"user": "a", "password": "x", "nested": [{"api_key": "k", "community": "public"}]})
    assert out == {"user": "a", "password": MASK, "nested": [{"api_key": MASK, "community": "public"}]}


def test_xml_community_keeps_defaults_only():
    out = redact_text("<community>public</community>\n<rocommunity>S3cret</rocommunity>")
    assert "<community>public</community>" in out and "S3cret" not in out


def test_xml_stays_well_formed():
    import xml.etree.ElementTree as ET

    out = redact_text('<?xml version="1.0"?>\n<system><user><password>hunter2</password></user>'
                      '<snmpd><rocommunity>S3cret</rocommunity></snmpd></system>')
    root = ET.fromstring(out.split("\n", 1)[1])
    assert root.find("user/password").text == "<redacted>" and "hunter2" not in out and "S3cret" not in out


def test_xml_driver_file_import():
    from pathlib import Path

    from sextant.pipeline import import_file

    ex = Path(__file__).resolve().parent.parent / "examples"
    for path, driver in [("pfsense/config.xml", "pfsense"), ("opnsense/config.xml", "opnsense"),
                         ("paloalto/running-config.xml", "paloalto")]:
        dev = import_file(ex / path, driver)
        assert dev.firewall_rules, (driver, dev.collection_warnings)


def test_redaction_is_idempotent():
    text = ("enable secret 9 $9$abc\nusername a privilege 15 secret 9 $9$x\nusername b password 7 0822\n"
            "username c password 5 $5$y role network-admin\n set password ENC SH2\n"
            'encrypted-password "$6$z";\n<password>p</password>')
    once = redact_text(text)
    assert redact_text(once) == once
    assert "secret 9 <redacted>" in once and "password 7 <redacted>" in once and "password 5 <redacted>" in once


def test_snmpv3_user_keys_every_vendor():
    from sextant.redact import redact_text

    text = ("snmp-server user mon grp v3 auth sha AuthKey123 priv aes 128 PrivKey456\n"
            "snmp-server user admin network-admin auth sha 0x1234abcd priv aes-128 0x5678ef localizedkey\n"
            'snmpv3 user "ops" auth sha "AuthKey123" priv aes "PrivKey456"\n'
            "snmpv3 user ops auth sha auth-pass ciphertext AQBapXYZ== priv aes priv-pass ciphertext AQBapABC==\n"
            "snmp-server group grp v3 priv read v1default\n")
    out = redact_text(text)
    for secret in ("AuthKey123", "PrivKey456", "0x1234abcd", "0x5678ef", "AQBapXYZ", "AQBapABC"):
        assert secret not in out
    assert "snmp-server group grp v3 priv read v1default" in out  # no key there, nothing masked


# every line holds the secret value "S3cretVal" (or a variant); none may survive
LEAKS = """\
radius-server host 10.1.1.2 auth-port 1812 acct-port 1813 key S3cretVal
tacacs-server key S3cretVal
radius server ISE
 address ipv4 10.1.1.3 auth-port 1812
 key 7 S3cretVal
aaa-server ISE (inside) host 10.1.1.4
 key S3cretVal
 standby 1 authentication S3cretVal
 standby 2 authentication text S3cretVal
 vrrp 1 authentication text S3cretVal
 glbp 1 authentication text S3cretVal
 ip nhrp authentication S3cretVal
 ip ospf authentication-key 7 S3cretVal
 wpa-psk ascii 0 S3cretVal
 pac key 7 S3cretVal
ntp authentication-key 1 md5 S3cretVal 7
 pre-shared-key address 192.0.2.1 key S3cretVal
 pre-shared-key local S3cretVal
 pre-shared-key remote S3cretVal
 pre-shared-key S3cretVal
passwd S3cretVal encrypted
failover key S3cretVal
snmp-server user nx network-admin auth md5 0xS3cretVal priv 0xS3cretVal localizedkey
user admin group administrators password ciphertext S3cretVal
radius-server host 10.1.1.5 key ciphertext S3cretVal
radius-server host 10.1.1.6 key plaintext S3cretVal
tacacs-server host 10.1.1.7 key "S3cretVal"
ntp authentication-key 1 sha1 ciphertext S3cretVal
set protocols ospf area 0 interface ge-0/0/0 authentication md5 1 key "S3cretVal"
set system ntp authentication-key 1 type md5 value "S3cretVal"
set system login user x authentication plain-text-password-value S3cretVal
    set sslvpn-passwd S3cretVal
    set wifi-passphrase "S3cretVal"
    set api-key S3cretVal
    set authpasswd ENC S3cretVal
    set password2 ENC S3cretVal
    set md5-key S3cretVal
    set tacacs-key ENC S3cretVal
    set psk S3cretVal
    set sae-password ENC S3cretVal
    set ppk-secret ENC S3cretVal
    set ha-password ENC S3cretVal
    set group-password ENC S3cretVal
    set radius-secret ENC S3cretVal
    set secondary-secret ENC S3cretVal
    set server-key ENC S3cretVal
Authorization: Bearer S3cretVal
GET https://10.0.0.1/api/?type=op&key=S3cretVal&cmd=x
"""

KEEP = """\
key chain OSPF
 key 1
  key-string 7 S3cretVal
crypto key generate rsa modulus 2048
    set keylife 28800
    set keepalive 10
 standby 1 authentication md5 key-chain HSRP
 ip rip authentication key-chain RIP
snmp-server group grp v3 priv read v1default
"""


def test_redaction_covers_vendor_secret_syntaxes():
    from sextant.redact import redact_text

    out = redact_text(LEAKS)
    leaked = [ln for ln in out.splitlines() if "S3cretVal" in ln]
    assert leaked == []


def test_redaction_keeps_what_is_not_secret():
    from sextant.redact import redact_text

    out = redact_text(KEEP)
    assert "S3cretVal" not in out  # the key-string is a secret
    for kept in (" key 1", "crypto key generate rsa", "set keylife 28800", "set keepalive 10",
                 "authentication md5 key-chain HSRP", "authentication key-chain RIP", "v3 priv read v1default"):
        assert kept in out, kept
    assert "ntp authentication-key 1 md5 <redacted> 7" in redact_text("ntp authentication-key 1 md5 Ab12cd 7")
    assert redact_text(" description reset password via portal") == " description reset password via portal"
    assert "reset password via portal" in redact_text("    set comments \"reset password via portal\"")


def test_redact_json_key_names():
    from sextant.redact import MASK, redact_obj

    data = {"preSharedKey": "S3cretVal", "pre_shared_key": "S3cretVal", "secretKey": "S3cretVal", "sharedKey": "x1",
            "authKey": "x2", "privKey": "x3", "pwd": "x4", "community_string": "x5", "ticket": "PVE:x6",
            "password": {"value": "x7"}, "passwords": ["x8"], "key": "x9", "device": {"key": 4000, "label": "NIC 1"}}
    out = redact_obj(data)
    for k in ("preSharedKey", "pre_shared_key", "secretKey", "sharedKey", "authKey", "privKey", "pwd",
              "community_string", "ticket", "key"):
        assert out[k] == MASK, k
    assert out["password"] == {"value": MASK} and out["passwords"] == [MASK]
    assert out["device"] == {"key": 4000, "label": "NIC 1"}  # vSphere device keys are ids, not secrets


def test_redact_xml_static_keys():
    from sextant.redact import redact_text

    xml = "<opnsense><openvpn><tls>-----BEGIN OpenVPN Static key V1-----\nabcd\n</tls><otp_seed>JBSWY3DP</otp_seed>" \
          "</openvpn></opnsense>"
    out = redact_text(xml)
    assert "abcd" not in out and "JBSWY3DP" not in out


def test_redact_firewall_formats():
    from sextant.redact import redact_text

    asa = "snmp-server host inside 10.0.0.50 community Zebra7Comm version 2c\n"
    assert redact_text(asa) == "snmp-server host inside 10.0.0.50 community <redacted> version 2c"
    forti = ("config system snmp community\n    edit 1\n        set name \"Zebra7Comm\"\n    next\nend\n"
             "config system interface\n    edit \"port1\"\n        set name \"keepme\"\n    next\nend\n")
    out = redact_text(forti)
    assert "Zebra7Comm" not in out and 'set name "keepme"' in out
    xml = ("<config><snmp-community-string>Zebra7Comm</snmp-community-string><ipsecpsk>Psk123</ipsecpsk>"
           "<trapstring>Trap77</trapstring><community>public</community></config>")
    out = redact_text(xml)
    assert not any(x in out for x in ("Zebra7Comm", "Psk123", "Trap77")) and "public" in out


def test_snmp_host_forms_and_url_credentials():
    from sextant.redact import redact_text

    cases = {
        "snmp-server host 10.0.0.9 traps version 2c Comm2Secret": "snmp-server host 10.0.0.9 traps version 2c <redacted>",
        "snmp-server host 10.0.0.9 informs version 2c Comm2Secret udp-port 162":
            "snmp-server host 10.0.0.9 informs version 2c <redacted> udp-port 162",
        "snmp-server host 10.0.0.9 Comm2Secret": "snmp-server host 10.0.0.9 <redacted>",
        'snmp-server host 10.0.0.9 community "PcComm16" trap-level all':
            'snmp-server host 10.0.0.9 community "<redacted>" trap-level all',
        "snmp-server host inside 10.0.0.50 community Comm2Secret version 2c":
            "snmp-server host inside 10.0.0.50 community <redacted> version 2c",
        "snmp-server host 10.0.0.9 version 3 auth monuser": "snmp-server host 10.0.0.9 version 3 auth monuser",
        "snmp-server host 10.0.0.9 use-vrf management": "snmp-server host 10.0.0.9 use-vrf management",
        "snmp-server host 10.0.0.9 version 2c public": "snmp-server host 10.0.0.9 version 2c public",
        " path scp://backup:Bkp$ecret1@192.0.2.50/cfg/": " path scp://backup:<redacted>@192.0.2.50/cfg/",
    }
    for line, want in cases.items():
        assert redact_text(line) == want, line


def test_aoscx_snmp_host_version_words():
    v3 = "snmp-server host 10.1.1.1 trap version v3 user nmsuser vrf mgmt"
    assert redact_text(v3) == v3  # no community on a v3 host line
    assert redact_text("snmp-server host 10.1.1.1 trap version v2c community s3cr3tc vrf mgmt") == \
        "snmp-server host 10.1.1.1 trap version v2c community <redacted> vrf mgmt"
