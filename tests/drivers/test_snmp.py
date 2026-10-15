import json
from pathlib import Path

import pytest

from sextant.drivers import REGISTRY
from sextant.drivers.base import RawCollection
from sextant.drivers.snmp import SnmpDriver, _role, _value
from sextant.model import DeviceRole

FIXTURE = Path(__file__).resolve().parents[2] / "examples" / "snmp" / "raw.json"


@pytest.fixture(scope="module")
def dev():
    return SnmpDriver().parse(RawCollection(**json.loads(FIXTURE.read_text())))


def test_registered():
    assert REGISTRY["snmp"].methods == ("snmp",)


def test_identity(dev):
    assert dev.hostname == "sto-ups01" and dev.platform == "snmp" and dev.role == DeviceRole.other
    assert dev.vendor.startswith("APC") and dev.model == "SRT3000RMXLI" and dev.serial == "AS2104123456"
    assert dev.uptime == "46 days, 03:40" and dev.mgmt_ip == "10.10.1.50"
    assert dev.location.startswith("Stockholm DC1") and dev.collection_warnings == []


def test_interfaces_neighbors(dev):
    itf = {i.name: i for i in dev.interfaces}
    assert itf["eth0"].ipv4[0].address == "10.10.1.50/24" and itf["eth0"].speed == "1000 Mb"
    assert itf["eth0"].oper_up is True and itf["eth0"].mac == "28:29:86:4a:0c:31"
    assert itf["eth0"].description == "Management" and itf["lo"].kind == "loopback"
    (n,) = dev.neighbors
    assert n.local_port == "eth0" and n.remote_device == "sto-sw-mgmt01"
    assert n.remote_port == "GigabitEthernet1/0/24"


def test_management_and_sections(dev):
    s = dev.management.snmp
    assert s.enabled and s.versions == ["v3"] and s.v3_users == ["sextant-ro (authPriv, SHA/AES)"]
    secs = {x.id: x for x in dev.sections}
    ups = {f.key: f.value for f in secs["snmp-ups"].facts}
    assert ups["Battery replacement needed"].startswith("YES") and ups["Runtime remaining"] == "29 min"
    assert len(secs["snmp-entity"].tables[0].rows) == 2


def test_role_heuristics():
    assert _role("Cisco IOS Software, C9300 Software (CAT9K_IOSXE), Version 17.9.4", "Cisco", 9, False) == \
        DeviceRole.switch
    assert _role("FortiGate-100F v7.4.4", "Fortinet", 12356, False) == DeviceRole.firewall
    assert _role("HP ETHERNET MULTI-ENVIRONMENT,ROM none,JETDIRECT,JD153, LaserJet", "HPE", 11, False) == \
        DeviceRole.other
    assert _role("Linux nas01 4.4.302+ #72806 SMP x86_64", "Synology", 6574, False) == DeviceRole.storage
    assert _role("Linux mon01 6.8.0-45-generic", "Net-SNMP", 8072, False) == DeviceRole.server


def test_value_conversion():
    from pysnmp.hlapi.v3arch.asyncio import IpAddress, ObjectIdentifier, OctetString

    assert _value(OctetString(hexValue="0050569a3c21")) == "00:50:56:9a:3c:21"
    assert _value(OctetString("Gi0/24"), mac=False) == "Gi0/24"
    assert _value(OctetString("Gi0/24"), mac=True) == "47:69:30:2f:32:34"
    assert _value(IpAddress("10.1.2.3")) == "10.1.2.3"
    assert _value(ObjectIdentifier("1.3.6.1.4.1.9.1.1")) == "1.3.6.1.4.1.9.1.1"


def test_tolerant():
    d = SnmpDriver().parse(RawCollection(driver="snmp", target="10.0.0.9", method="snmp", outputs={}))
    assert d.hostname == "10.0.0.9" and d.collection_warnings and d.role == DeviceRole.other
    d = SnmpDriver().parse(RawCollection(driver="snmp", target="x", method="snmp", outputs={
        "sysDescr": "notadict", "ifDescr": {"1": "eth0"}, "ipAdEntIfIndex": {"10.0.0.1": "1"},
        "ipAdEntNetMask": {"10.0.0.1": "junk"}, "lldpRemSysName": {"weird": "peer"}}))
    assert d.interfaces[0].ipv4[0].address == "10.0.0.1" and d.neighbors[0].remote_device == "peer"
