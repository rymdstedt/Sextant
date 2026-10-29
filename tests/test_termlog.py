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


# --------------------------------------------------------------------------- IE3100 logs (KS506 site)

N009_VER = """\
Cisco IOS XE Software, Version 17.15.05
Cisco IOS Software [IOSXE], IE31xx Switch Software (IE31xx-UNIVERSALK9-M), Version 17.15.5, RELEASE SOFTWARE (fc3)
Technical Support: http://www.cisco.com/techsupport
Copyright (c) 1986-2026 by Cisco Systems, Inc.
Compiled Fri 20-Feb-26 07:33 by mcpre


ROM: IOS-XE ROMMON
BOOTLDR: Version 1.1.11 [RELEASE SOFTWARE]
KS506-NV03-N009 uptime is 15 weeks, 6 days, 22 hours, 4 minutes
Uptime for this control processor is 15 weeks, 6 days, 22 hours, 6 minutes
System returned to ROM by Image Install
System image file is "flash:packages.conf"
Last reload reason: Image Install

Technology-package                                     Technology-package
Current                        Type                       Next reboot
------------------------------------------------------------------------------
network-essentials      Smart License                    None

cisco IE-3100-4T2S (ARM) processor (revision V03) with 658511K/6147K bytes of memory.
Processor board ID FDO2922J8TK
3 Virtual Ethernet interfaces
6 Gigabit Ethernet interfaces
4096K bytes of non-volatile configuration memory.
"""


def _stamped(lines):
    return "\n".join(f"115627.212: {ln}" for ln in lines)


def test_show_version_late_in_a_long_log(tmp_path):
    """The only identifying output comes after 200 kB of other commands (stamped like SecureCRT)."""
    filler = [f"GigabitEthernet1/{i % 6 + 1} is up, line protocol is up (connected) {i}" for i in range(4000)]
    log = ["KS506-NV03-N009#show interfaces", *filler, "KS506-NV03-N009#show ver", *N009_VER.splitlines(),
           "KS506-NV03-N009#"]
    text = _stamped(log)
    assert len(text) > 200_000
    (tmp_path / "192.168.137.89-20261023-095749_273.log").write_text(text)
    (d,), errors = import_many([tmp_path])
    assert not errors and (d.hostname, d.model, d.serial) == ("KS506-NV03-N009", "IE-3100-4T2S", "FDO2922J8TK")


def test_log_that_visits_several_switches(tmp_path):
    """ssh from N001 to N009 in the same session log: two devices, and the import says so."""
    log = ["KS506-NV03-N001#show ver", *N009_VER.replace("N009", "N001").replace("FDO2922J8TK", "FDO0000AAAA")
           .splitlines(), "KS506-NV03-N001#ssh -l admin 10.55.4.9", "Password:", "",
           "KS506-NV03-N009#show ver", *N009_VER.splitlines(), "KS506-NV03-N009#exit",
           "[Connection to 10.55.4.9 closed by foreign host]", "KS506-NV03-N001#"]
    (tmp_path / "hop.log").write_text(_stamped(log))
    notes: list[str] = []
    devices, errors = import_many([tmp_path], notes=notes)
    assert not errors
    assert sorted((d.hostname, d.serial) for d in devices) == [("KS506-NV03-N001", "FDO0000AAAA"),
                                                              ("KS506-NV03-N009", "FDO2922J8TK")]
    assert notes == ["hop.log visits 2 devices (KS506-NV03-N001, KS506-NV03-N009): imported as one capture each"]


def test_bare_capture_before_its_config_and_repeat_captures(tmp_path):
    """Files are read in name order: a 'show cdp neighbors' capture sorted before the switch's own log
    still joins it, and a second capture of the same switch is reported as combined."""
    cdp = ("-------------------------\nDevice ID: KS506-NV03-N001\nEntry address(es):\n  IP address: 10.55.4.1\n"
           "Platform: cisco IE-3100-8T2C,  Capabilities: Switch IGMP\n"
           "Interface: GigabitEthernet1/1,  Port ID (outgoing port): GigabitEthernet1/2\nHoldtime : 150 sec\n")
    (tmp_path / "a-cdp.log").write_text(f"KS506-NV03-N009#show cdp neighbors detail\n{cdp}\nKS506-NV03-N009#\n")
    ver = "KS506-NV03-N009#show ver\n" + N009_VER + "KS506-NV03-N009#\n"
    (tmp_path / "b-ver.log").write_text(ver)
    (tmp_path / "c-ver-again.log").write_text(ver)
    notes: list[str] = []
    (d,), errors = import_many([tmp_path], notes=notes)
    assert not errors and d.serial == "FDO2922J8TK" and [n.remote_device for n in d.neighbors] == ["KS506-NV03-N001"]
    assert notes == ["c-ver-again.log: another capture of KS506-NV03-N009 (first in b-ver.log): combined into one device",
                     "a-cdp.log: another capture of KS506-NV03-N009 (first in b-ver.log): combined into one device"]


def test_unrecognised_log_says_what_it_saw(tmp_path):
    (tmp_path / "cut.log").write_text("KS506-NV03-N009#show ver\nCisco IOS XE Sof\n")  # the session dropped
    (tmp_path / "idle.log").write_text("login as: admin\nKS506-NV03-N009#\nKS506-NV03-N009#exit\n")
    _, errors = import_many([tmp_path])
    assert errors == [
        "cut.log: platform not recognised: a session log with 'show ver' but no running-config or "
        "'show version' Sextant knows (2 lines, first prompt 'KS506-NV03-N009#show ver'); an output that was "
        "cut off is the usual reason (or use --driver)",
        "idle.log: platform not recognised: a session log with no show commands (3 lines, first prompt "
        "'KS506-NV03-N009#exit'); the session may have ended early (or use --driver)"]
