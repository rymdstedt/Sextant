from hsdoc.redact import MASK, redact_obj, redact_text


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

    from hsdoc.pipeline import import_file

    ex = Path(__file__).resolve().parent.parent / "examples"
    for path, driver in [("pfsense/config.xml", "pfsense"), ("opnsense/config.xml", "opnsense"),
                         ("paloalto/running-config.xml", "paloalto")]:
        dev = import_file(ex / path, driver)
        assert dev.firewall_rules, (driver, dev.collection_warnings)
