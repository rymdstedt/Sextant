"""Terminal session logs as clients write them: timestamps, UTF-16, pager prompts, ANSI codes."""

from sextant import termlog
from sextant.pipeline import guess_driver, import_many

LOG = """\
lab-c9300-01#terminal length 0
lab-c9300-01#show running-config
Building configuration...

Current configuration : 900 bytes
!
version 17.15
hostname lab-c9300-01
!
interface GigabitEthernet1/0/1
 description UPLINK lab-core Gi1/0/1
 switchport mode trunk
!
end

lab-c9300-01#show version
Cisco IOS XE Software, Version 17.15.05
Cisco IOS Software [IOSXE], Catalyst L3 Switch Software (CAT9K_IOSXE), Version 17.15.5, RELEASE SOFTWARE (fc3)
lab-c9300-01 uptime is 15 weeks, 19 hours, 44 minutes
cisco C9300-24S (X86) processor with 1331521K/6147K bytes of memory.
Processor board ID FOC0000X0AA
Model Number                       : C9300-24S
System Serial Number               : FOC0000X0AA
lab-c9300-01#
"""


def test_clean_text_passes_through():
    assert termlog.clean(LOG) == LOG


def test_timestamps_on_every_line():
    stamped = "\n".join(f"[09:40:{i % 60:02d}] {ln}" for i, ln in enumerate(LOG.splitlines()))
    assert termlog.clean(stamped) == LOG.rstrip("\n")
    iso = "\n".join(f"2026-10-23 09:40:49.123 {ln}" for ln in LOG.splitlines())
    assert termlog.clean(iso) == LOG.rstrip("\n")


def test_compact_timestamps():
    """SecureCRT 'custom log data' %h%m%s.%t: on each line, also on the empty ones; the banner is not stamped."""
    lines = LOG.splitlines()
    stamped = ["%@%%@@@%%@@@+**===++*%*:+=#*=*+="] + [f"092524.{i % 1000:03d}: {ln}".rstrip() for i, ln in
                                                         enumerate(lines)]
    assert termlog.clean("\n".join(stamped)).splitlines()[1:] == [ln.rstrip() for ln in lines]
    tight = [f"092524.956:{ln}" for ln in lines]  # no space after the colon
    assert termlog.clean("\n".join(tight)).splitlines() == lines
    # a numbered list or a config with numeric lines is left alone
    assert termlog.clean("100000 packets input\n vlan 10\n") == "100000 packets input\n vlan 10\n"


def test_utf16_and_crlf():
    data = LOG.replace("\n", "\r\n").encode("utf-16")  # with BOM
    assert termlog.clean(termlog.decode(data)) == LOG
    bare = LOG.encode("utf-16-le")  # without BOM
    assert termlog.clean(termlog.decode(bare)) == LOG
    assert termlog.decode("hostname sw-åäö\n".encode("cp1252")) == "hostname sw-åäö\n"


def test_pager_prompts_and_ansi():
    erase = "\x08" * 9 + " " * 9 + "\x08" * 9
    raw = ("interface GigabitEthernet1/0/1\n --More-- " + erase + " switchport mode trunk\n"
           "\x1b[32mvlan 10\x1b[0m\n"
           "-- MORE --, next page: Space, next line: Enter, quit: Control-C" + "\r" + " " * 70 + "\r" + "vlan 20\n"
           "---(more 42%)---" + erase + "set system host-name lab\n"
           "sw01#sh\x08\x08show ver\n")
    assert termlog.clean(raw).splitlines() == [
        "interface GigabitEthernet1/0/1", " switchport mode trunk", "vlan 10", "vlan 20",
        "set system host-name lab", "sw01#show ver"]


def test_detect_from_show_version_only():
    ver = LOG[LOG.index("lab-c9300-01#show version"):]
    assert guess_driver(ver) == "cisco_ios"
    assert guess_driver("Cisco Nexus Operating System (NX-OS) Software\n") == "cisco_nxos"
    assert guess_driver("Cisco Adaptive Security Appliance Software Version 9.18(4)\n") == "cisco_asa"


def test_import_stamped_utf16_log(tmp_path):
    stamped = "\n".join(f"[09:40:49] {ln}" for ln in LOG.splitlines())
    (tmp_path / "192.0.2.4-20261023-094049_896.log").write_bytes(stamped.replace("\n", "\r\n").encode("utf-16"))
    (tmp_path / "junk.log").write_text("nothing here\n")
    devices, errors = import_many([tmp_path])
    (d,) = devices
    assert (d.hostname, d.model, d.os_version, d.serial) == ("lab-c9300-01", "C9300-24S", "17.15.05", "FOC0000X0AA")
    assert [i.name for i in d.interfaces][:1] == ["GigabitEthernet1/0/1"]
    assert errors == ["junk.log: platform not recognised: no CLI prompt or config found (first line: 'nothing here') "
                      "(or use --driver)"]


def test_detection_prefers_the_first_marker():
    ios_log = ("sw1#show running-config\nBuilding configuration...\nversion 17.9\nhostname sw1\n"
               "interface GigabitEthernet1/0/1\n description uplink to NX-OS core\n!\nend\n"
               "sw1#show cdp neighbors detail\nDevice ID: n9k\nVersion :\nCisco Nexus Operating System (NX-OS) Software\n"
               "Device ID: fw\nVersion :\nCisco Adaptive Security Appliance Software Version 9.18\n")
    assert guess_driver(ios_log) == "cisco_ios"
    banner = ("version 15.2\nhostname sw2\nbanner motd ^C\nconfig system global\n^C\ninterface FastEthernet0/1\n")
    assert guess_driver(banner) == "cisco_ios"
    assert guess_driver("version 12.2\nhostname old\n!\nline vty 0 4\n") == "cisco_ios"


def test_cr_only_files_and_pager_lookalikes():
    assert termlog.clean("hostname sw1\r!\rinterface Gi1/0/1\r description more ports\r") == \
        "hostname sw1\n!\ninterface Gi1/0/1\n description more ports\n"
    assert termlog.clean(" description --- more ---  spare\n") == " description --- more ---  spare\n"
