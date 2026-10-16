"""Regression tests for structures seen in real exports (values invented, structure from the field)."""

from pathlib import Path

from sextant.model import Snapshot
from sextant.pipeline import import_file, import_many
from sextant.topology import build_topology

EX = Path(__file__).resolve().parent.parent / "examples"


def test_panos_real_export_quirks(tmp_path):
    base = (EX / "paloalto" / "running-config.xml").read_text()
    baseline = import_file(EX / "paloalto" / "running-config.xml", "paloalto")
    text = base.replace("<description>", "<description>Allow password reset portal, secret 5 key 7 ", 1)
    text = text.replace("</shared>", """<certificate><entry name="root-ca">
<public-key>-----BEGIN CERTIFICATE-----
MIIFbDCCA1SgAwIBAgIUVDE1h
-----END CERTIFICATE-----</public-key>
<private-key>-AQ==Zm9vYmFyYmF6cXV4</private-key></entry></certificate>
<tag><entry name="ddns-secret-token"><value>-AQ==c2VjcmV0dmFsdWU=</value></entry></tag></shared>""", 1)
    f = tmp_path / "running-config.xml"
    f.write_text(text)
    dev = import_file(f, "paloalto")
    assert dev.collection_warnings == [] and len(dev.firewall_rules) == len(baseline.firewall_rules) > 0
    assert len(dev.interfaces) == len(baseline.interfaces)
    dump = dev.model_dump_json()
    assert "Zm9vYmFyYmF6cXV4" not in dump and "c2VjcmV0dmFsdWU" not in dump
    from sextant.redact import redact_text

    red = redact_text(text)
    assert "MIIFbDCCA1SgAwIBAgIUVDE1h" in red  # public certificates are documentation, not secrets
    assert "Zm9vYmFyYmF6cXV4" not in red and "c2VjcmV0dmFsdWU" not in red


def test_panos_interface_ip_as_address_object(tmp_path):
    text = (EX / "paloalto" / "running-config.xml").read_text()
    import re

    mt = re.search(r'<ip>\s*<entry name="(\d+\.\d+\.\d+\.\d+/\d+)"/>', text)
    assert mt, "fixture needs an interface IP"
    cidr = mt.group(1)
    text = text.replace(mt.group(0), '<ip><entry name="gw-object"/>', 1)
    text = text.replace("<address>", f'<address><entry name="gw-object"><ip-netmask>{cidr}</ip-netmask></entry>', 1)
    f = tmp_path / "pa.xml"
    f.write_text(text)
    dev = import_file(f, "paloalto")
    assert any(a.address == cidr for i in dev.interfaces for a in i.ipv4)


PROCURVE_LOG = """HP J9774A 2530-8G-PoEP Switch
Software revision YA.16.11.0018

sw-office# show run

Running configuration:

; J9774A Configuration Editor; Created on release #YA.16.11.0018
hostname "sw-office"
trunk 9-10 trk1 lacp
interface 9
   name "corecat .5"
   exit
interface 10
   name "corecat .5"
   exit
snmpv3 enable
snmpv3 user "monitor"
vlan 5
   name "MGMT"
   untagged 1-8,Trk1
   ip address 10.0.5.2 255.255.255.0
   exit
password manager
password operator user-name "ops" sha1 "0123456789abcdef0123456789abcdef01234567"

sw-office#
"""

CISCO_LOG = """corecat-3560#show run
Building configuration...
version 15.2
hostname corecat-3560
switch 1 provision ws-c3560cx-12pd-s
snmp-server community s3cretRW RW
interface Port-channel1
 description sw-office uplink
 switchport mode trunk
interface GigabitEthernet1/0/13
 description "office .2 PO1"
 switchport mode trunk
 channel-group 1 mode active
interface GigabitEthernet1/0/14
 description "office .2 PO1"
 switchport mode trunk
 channel-group 1 mode active
interface Vlan5
 ip address 10.0.5.5 255.255.255.0
end
corecat-3560#
"""


def test_procurve_session_log(tmp_path):
    f = tmp_path / "aruba.txt"
    f.write_text(PROCURVE_LOG)
    d = import_file(f, "hp_procurve")
    assert d.model == "HP 2530-8G-PoEP (J9774A)" and d.os_version == "YA.16.11.0018"
    users = {u.name: u.auth for u in d.management.users}
    assert set(users) == {"manager", "ops"} and users["ops"] == "password sha1"
    assert "0123456789abcdef" not in d.model_dump_json()
    assert d.management.snmp.v3_users == ["monitor"]  # no invented auth/priv levels


def test_cisco_rw_community_and_quotes(tmp_path):
    f = tmp_path / "cisco.txt"
    f.write_text(CISCO_LOG)
    d = import_file(f, "cisco_ios")
    assert "snmp.rw-community" in {x.check_id for x in d.findings}
    assert "s3cretRW" not in d.model_dump_json()
    assert next(i for i in d.interfaces if i.name.endswith("1/0/13")).description == "office .2 PO1"


def test_partial_names_and_lag_pairing(tmp_path):
    (tmp_path / "aruba.txt").write_text(PROCURVE_LOG)
    (tmp_path / "cisco.txt").write_text(CISCO_LOG)
    devices, errors = import_many([tmp_path])
    assert errors == []
    topo = build_topology(Snapshot(devices=devices))
    ln = topo.link("corecat-3560", "sw-office")
    assert ln is not None and ln.sources & {"description", "description-partial"}
    ports = sorted(ln.ports)
    assert ports == [("GigabitEthernet1/0/13", "9"), ("GigabitEthernet1/0/14", "10")], ports
