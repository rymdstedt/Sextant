"""Generate examples/campus/: 20 Cisco IOS-XE running-configs for a two-building campus.

Config files only (no CDP/LLDP), the way they come out of a config backup tool, to exercise
topology inference from interface descriptions and routed /30s. Includes deliberate mistakes:
kis-acc-sw09 single uplink, kis-acc-sw12 native VLAN mismatch, kis-acc-sw05 VLAN name typo,
kis-acc-sw14 trunk VLAN list mismatch, kis-acc-sw07 Telnet enabled.

    python scripts/make_campus_example.py
"""

from __future__ import annotations

from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "examples" / "campus"
VLANS = {10: "USERS", 20: "VOICE", 30: "PRINTERS", 40: "WLAN-AP", 99: "MGMT", 998: "PARKING", 999: "NATIVE"}
TRUNK = "10,20,30,40,99"

COMMON = """!
version 17.9
service timestamps debug datetime msec localtime show-timezone
service timestamps log datetime msec localtime show-timezone
service password-encryption
!
hostname {host}
!
boot-start-marker
boot-end-marker
!
logging buffered 64000 informational
enable secret 9 <redacted>
!
aaa new-model
aaa group server tacacs+ ISE
 server name ise01
 server name ise02
aaa authentication login default group ISE local
aaa authorization exec default group ISE local
aaa accounting exec default start-stop group ISE
!
clock timezone CET 1 0
clock summer-time CEST recurring last Sun Mar 2:00 last Sun Oct 3:00
ip domain name corp.example
ip name-server 10.40.100.10 10.40.100.11
!
{provision}
username netadmin privilege 15 secret 9 <redacted>
!
spanning-tree mode rapid-pvst
spanning-tree portfast bpduguard default
spanning-tree extend system-id
{stp_prio}
!
{vlans}
"""

TAIL = """!
ip access-list standard MGMT
 10 permit 10.40.100.0 0.0.0.255
 20 deny   any log
ip access-list standard SNMP-RO
 10 permit 10.40.100.25
!
logging host 10.40.100.20
snmp-server community <redacted> RO SNMP-RO
snmp-server location Kista campus, {location}
snmp-server contact noc@example.se
!
tacacs server ise01
 address ipv4 10.40.100.31
 key 7 <redacted>
tacacs server ise02
 address ipv4 10.40.100.32
 key 7 <redacted>
!
banner login ^C
Authorized access only. Activity is logged.
^C
!
line con 0
 exec-timeout 15 0
line vty 0 15
 access-class MGMT in
 exec-timeout 15 0
 transport input {transport}
!
ntp server 10.40.100.5
ntp server 10.40.100.6
!
end
"""


def vlan_block(names: dict[int, str]) -> str:
    return "\n".join(f"vlan {v}\n name {n}\n!" for v, n in names.items())


def access(n: int) -> tuple[str, str]:
    host = f"kis-acc-sw{n:02d}"
    building = "A" if n <= 7 else "B"
    d1, d2 = (1, 2) if building == "A" else (3, 4)
    dist_port = 4 + (n if n <= 7 else n - 7)  # Te1/0/5..Te1/0/11 on the distribution pair
    model = "c9200l-48p-4x" if n in (6, 7, 13, 14) else "c9300-48p"
    names = dict(VLANS)
    if n == 5:
        names[30] = "PRINTER"  # typo: inconsistent VLAN name
    lines = [COMMON.format(host=host, provision=f"switch 1 provision {model}", stp_prio="", vlans=vlan_block(names))]
    for p in range(1, 49):
        if p <= 40:
            lines.append(f"interface GigabitEthernet1/0/{p}\n description User port\n switchport access vlan 10\n"
                         f" switchport mode access\n switchport voice vlan 20\n spanning-tree portfast\n!")
        elif p <= 44:
            lines.append(f"interface GigabitEthernet1/0/{p}\n description Printer\n switchport access vlan 30\n"
                         f" switchport mode access\n spanning-tree portfast\n!")
        elif p <= 46:
            lines.append(f"interface GigabitEthernet1/0/{p}\n description WLAN AP\n switchport access vlan 40\n"
                         f" switchport mode access\n spanning-tree portfast\n!")
        else:
            lines.append(f"interface GigabitEthernet1/0/{p}\n description UNUSED\n switchport access vlan 998\n"
                         f" switchport mode access\n shutdown\n!")
    for idx, dist in ((1, d1), (2, d2)):
        native = 1 if (n == 12 and idx == 1) else 999
        allowed = "10,20,30,99" if (n == 14 and idx == 2) else TRUNK
        shut = "\n shutdown" if (n == 9 and idx == 2) else ""
        lines.append(f"interface TenGigabitEthernet1/1/{idx}\n description UPLINK kis-dist-sw{dist:02d} "
                     f"Te1/0/{dist_port}\n switchport trunk native vlan {native}\n switchport trunk allowed vlan "
                     f"{allowed}\n switchport mode trunk\n ip dhcp snooping trust{shut}\n!")
    for idx in (3, 4):
        lines.append(f"interface TenGigabitEthernet1/1/{idx}\n shutdown\n!")
    third = 10 + n
    lines.append(f"interface Vlan1\n no ip address\n shutdown\n!\ninterface Vlan99\n description MGMT\n"
                 f" ip address 10.40.99.{third} 255.255.255.0\n!\nip default-gateway 10.40.99.1\n")
    transport = "telnet ssh" if n == 7 else "ssh"
    lines.append(TAIL.format(location=f"building {building}, floor {(n - 1) % 7 + 1}", transport=transport))
    return host, "\n".join(lines)


def distribution(n: int) -> tuple[str, str]:
    host = f"kis-dist-sw{n:02d}"
    building = "A" if n <= 2 else "B"
    peer = n + 1 if n % 2 else n - 1
    accs = range(1, 8) if building == "A" else range(8, 15)
    prio = "spanning-tree vlan 1-4094 priority 4096" if n % 2 else "spanning-tree vlan 1-4094 priority 8192"
    lines = [COMMON.format(host=host, provision="switch 1 provision c9500-16x", stp_prio=prio,
                           vlans=vlan_block(VLANS))]
    lines.append(f"interface Port-channel1\n description PEER kis-dist-sw{peer:02d} Po1\n"
                 f" switchport trunk native vlan 999\n switchport trunk allowed vlan {TRUNK}\n switchport mode trunk\n!")
    for idx in (1, 2):  # routed uplinks to both cores
        core = idx
        net = 40 + (n - 1) * 2 + (idx - 1)  # unique /30 per core-dist link
        lines.append(f"interface TenGigabitEthernet1/0/{idx}\n description P2P kis-core-sw{core:02d} Te1/0/{n}\n"
                     f" no switchport\n ip address 10.40.{net}.2 255.255.255.252\n ip ospf network point-to-point\n!")
    for idx in (3, 4):
        lines.append(f"interface TenGigabitEthernet1/0/{idx}\n description PEER kis-dist-sw{peer:02d} "
                     f"Te1/0/{idx}\n switchport trunk native vlan 999\n switchport trunk allowed vlan {TRUNK}\n"
                     f" switchport mode trunk\n channel-group 1 mode active\n!")
    side = 1 if n % 2 else 2
    for i, a in enumerate(accs):
        port = 5 + i
        allowed = TRUNK
        lines.append(f"interface TenGigabitEthernet1/0/{port}\n description DOWNLINK kis-acc-sw{a:02d} "
                     f"Te1/1/{side}\n switchport trunk native vlan 999\n switchport trunk allowed vlan {allowed}\n"
                     f" switchport mode trunk\n!")
    for port in range(5 + len(accs), 17):
        lines.append(f"interface TenGigabitEthernet1/0/{port}\n shutdown\n!")
    base = 0 if building == "A" else 128
    for vid, vname in VLANS.items():
        if vid in (998, 999):
            continue
        third = vid if building == "A" else vid + 100
        prio = "\n standby 1 priority 110\n standby 1 preempt" if n % 2 else ""
        lines.append(f"interface Vlan{vid}\n description {vname}\n ip address 10.41.{third}.{2 if n % 2 else 3} "
                     f"255.255.255.0\n standby version 2\n standby 1 ip 10.41.{third}.1{prio}\n"
                     f" ip helper-address 10.40.100.15\n!")
    _ = base
    lines.append(f"interface Loopback0\n ip address 10.40.255.{10 + n} 255.255.255.255\n!\n"
                 f"router ospf 1\n router-id 10.40.255.{10 + n}\n passive-interface default\n"
                 f" no passive-interface TenGigabitEthernet1/0/1\n no passive-interface TenGigabitEthernet1/0/2\n"
                 f" network 10.40.0.0 0.0.255.255 area 0\n network 10.41.0.0 0.0.255.255 area 0\n!")
    lines.append(TAIL.format(location=f"building {building}, MDF", transport="ssh"))
    return host, "\n".join(lines)


def core(n: int) -> tuple[str, str]:
    host = f"kis-core-sw{n:02d}"
    peer = 2 if n == 1 else 1
    lines = [COMMON.format(host=host, provision="switch 1 provision c9500-24y4c", stp_prio="",
                           vlans=vlan_block({99: "MGMT", 999: "NATIVE"}))]
    lines.append(f"interface Port-channel1\n description PEER kis-core-sw{peer:02d} Po1\n no switchport\n"
                 f" ip address 10.40.30.{1 if n == 1 else 2} 255.255.255.252\n!")
    for d in range(1, 5):
        net = 40 + (d - 1) * 2 + (n - 1)
        lines.append(f"interface TenGigabitEthernet1/0/{d}\n description P2P kis-dist-sw{d:02d} Te1/0/{n}\n"
                     f" no switchport\n ip address 10.40.{net}.1 255.255.255.252\n ip ospf network point-to-point\n!")
    for d in range(5, 25):
        lines.append(f"interface TenGigabitEthernet1/0/{d}\n shutdown\n!")
    for h in (25, 26):
        lines.append(f"interface HundredGigE1/0/{h}\n description PEER kis-core-sw{peer:02d} Hu1/0/{h}\n no switchport\n"
                     f" channel-group 1 mode active\n!")
    lines.append(f"interface TenGigabitEthernet1/0/24\n description WAN kis-fw01 port1\n no switchport\n"
                 f" ip address 10.40.20.{1 + n * 4} 255.255.255.252\n!")
    lines.append(f"interface Loopback0\n ip address 10.40.255.{n} 255.255.255.255\n!\n"
                 f"router ospf 1\n router-id 10.40.255.{n}\n network 10.40.0.0 0.0.255.255 area 0\n"
                 f" default-information originate\n!\nip route 0.0.0.0 0.0.0.0 10.40.20.{2 + n * 4} name INTERNET\n")
    lines.append(TAIL.format(location="datacenter", transport="ssh"))
    return host, "\n".join(lines)


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    configs = [core(1), core(2)] + [distribution(i) for i in range(1, 5)] + [access(i) for i in range(1, 15)]
    for host, text in configs:
        (OUT / f"{host}.cfg").write_text(text)
    print(f"{len(configs)} configs -> {OUT}")


if __name__ == "__main__":
    main()
