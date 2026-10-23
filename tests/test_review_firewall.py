"""Regression tests for the firewall driver / firewall check review findings."""

from sextant.analysis import analyze_device
from sextant.drivers.base import RawCollection
from sextant.drivers.cisco_asa import CMD_FAILOVER, CMD_RUN, CiscoAsaDriver
from sextant.drivers.fortigate import FortiGateDriver
from sextant.drivers.paloalto import PaloAltoDriver
from sextant.drivers.pfsense import OPNsenseDriver, PfSenseDriver
from sextant.model import Device, FirewallRule, VpnTunnel


def findings(dev):
    return {f.check_id: f for f in analyze_device(dev)}


def fw(rules=(), tunnels=()):
    return Device(hostname="fw-test", role="firewall", firewall_rules=list(rules), vpn_tunnels=list(tunnels))


def fortigate(conf: str):
    return FortiGateDriver().parse(RawCollection(driver="fortigate", target="fg-test", method="file",
                                                 outputs={"config": conf}))


def paloalto(xml: str):
    return PaloAltoDriver().parse(RawCollection(driver="paloalto", target="pa-test", method="file",
                                                outputs={"config": xml}))


def pfsense(xml: str, driver=PfSenseDriver):
    return driver().parse(RawCollection(driver=driver.id, target="pf-test", method="file", outputs={"config": xml}))


def asa(run: str, failover: str = ""):
    return CiscoAsaDriver().parse(RawCollection(driver="cisco_asa", target="asa-test", method="file",
                                                outputs={CMD_RUN: run, CMD_FAILOVER: failover}))


def _pa_config(rules: str, network: str = "", extra: str = "") -> str:
    return f"""<config version="10.2.0"><shared>{extra}</shared><devices><entry name="localhost.localdomain">
      <deviceconfig><system><hostname>pa-test</hostname></system></deviceconfig>
      <network>{network}</network>
      <vsys><entry name="vsys1">
        <address><entry name="QUARANTINE"><ip-netmask>10.99.0.0/16</ip-netmask></entry></address>
        <rulebase><security><rules>{rules}</rules></security></rulebase>
      </entry></vsys></entry></devices></config>"""


_PA_ANY = ("<entry name='open'><from><member>any</member></from><to><member>any</member></to>"
           "<source><member>any</member></source><destination><member>any</member></destination>"
           "<application><member>any</member></application><service><member>any</member></service>"
           "<action>allow</action></entry>")


# 1 --------------------------------------------------------------- any/any with application "any"


def test_paloalto_any_any_rule_with_application_any_is_flagged():
    dev = paloalto(_pa_config(_PA_ANY))
    assert dev.firewall_rules[0].applications == ["any"]
    f = findings(dev)
    assert "fw.any-any" in f and f["fw.any-any"].evidence == ["1 (open)"]


def test_specific_application_is_not_any_any():
    rule = FirewallRule(id="1", action="allow", src_addresses=["any"], dst_addresses=["any"], services=["any"],
                        applications=["web-browsing"])
    assert "fw.any-any" not in findings(fw([rule])) and "fw.broad" not in findings(fw([rule]))


# 2 / 3 ------------------------------------------------------------ ASA failover and transform sets

_ASA_RUN = """: Saved
ASA Version 9.16(4)
hostname asa-test
interface GigabitEthernet0/0
 nameif outside
 security-level 0
 ip address 192.0.2.2 255.255.255.248 standby 192.0.2.3
object network LOCAL-NET
 subnet 10.30.0.0 255.255.255.0
object network PEER-NET
 subnet 10.40.0.0 255.255.255.0
access-list S2S extended permit ip object LOCAL-NET object PEER-NET
crypto ipsec ikev1 transform-set TS-L2TP esp-aes-256 esp-sha-hmac
crypto ipsec ikev1 transform-set TS-L2TP mode transport
crypto map OUTSIDE-MAP 10 match address S2S
crypto map OUTSIDE-MAP 10 set peer 198.51.100.20
crypto map OUTSIDE-MAP 10 set ikev1 transform-set TS-L2TP
crypto map OUTSIDE-MAP interface outside
failover
failover lan unit secondary
failover lan interface FOLINK GigabitEthernet0/3
failover link FOLINK GigabitEthernet0/3
"""

_FO = """Failover On
Failover unit {unit}
Failover LAN Interface: FOLINK GigabitEthernet0/3 (up)
Version: Ours 9.16(4), Mate 9.16(4)
        This host: {this}
                Active time: 0 (sec)
        Other host: {other}
                Active time: 1000 (sec)
"""


def test_asa_standby_unit_is_in_sync():
    dev = asa(_ASA_RUN, _FO.format(unit="Secondary", this="Secondary - Standby Ready", other="Primary - Active"))
    assert dev.ha.state == "standby ready" and dev.ha.details["sync"] == "in-sync"
    assert "ha.not-in-sync" not in findings(dev)


def test_asa_active_unit_is_in_sync_and_failed_mate_is_not():
    ok = asa(_ASA_RUN, _FO.format(unit="Primary", this="Primary - Active", other="Secondary - Standby Ready"))
    assert ok.ha.details["sync"] == "in-sync"
    bad = asa(_ASA_RUN, _FO.format(unit="Primary", this="Primary - Active", other="Secondary - Failed"))
    assert bad.ha.details["sync"] == "out-of-sync" and "ha.not-in-sync" in findings(bad)


def test_asa_transform_set_mode_line_keeps_crypto():
    dev = asa(_ASA_RUN)
    (tun,) = [t for t in dev.vpn_tunnels if t.kind == "ipsec"]
    assert tun.phase2.startswith("aes256-sha1,") and "mode" not in tun.phase2
    assert "SHA1" in findings(dev)["vpn.weak-crypto"].title


# 4 / 5 / 6 / 13 ---------------------------------------------------- FortiGate

_FG_SHADOW = """config firewall address
    edit "LAN-NET"
        set subnet 10.50.0.0 255.255.255.0
    next
end
config firewall policy
    edit 1
        set name "lan-out"
        set srcintf "lan"
        set dstintf "wan1"
        set action accept
        set srcaddr "LAN-NET"
        set dstaddr "all"
        set schedule "always"
        set service "ALL"
    next
    edit 2
        set name "lan-https"
        set srcintf "lan"
        set dstintf "wan1"
        set action accept
        set srcaddr "LAN-NET"
        set dstaddr "all"
        set schedule "always"
        set service "HTTPS"
    next
end
"""


def test_fortigate_schedule_always_does_not_hide_shadowed_rules():
    dev = fortigate(_FG_SHADOW)
    assert {r.schedule for r in dev.firewall_rules} == {"always"}
    assert findings(dev)["fw.shadowed"].evidence == ["2 (lan-https) shadowed by 1 (lan-out)"]


def test_shadowed_respects_real_schedules():
    wide = FirewallRule(id="1", action="allow", services=["any"], schedule="office-hours")
    narrow = FirewallRule(id="2", action="allow", services=["HTTPS"], schedule="always")
    same = FirewallRule(id="3", action="allow", services=["SSH"], schedule="office-hours")
    f = findings(fw([wide, narrow, same]))
    assert f["fw.shadowed"].evidence == ["3 shadowed by 1"]


def test_fortigate_negate_is_recorded_and_not_a_superset():
    conf = _FG_SHADOW.replace('set name "lan-out"', 'set name "not-lan"\n        set srcaddr-negate enable')
    conf = conf.replace('set service "HTTPS"', 'set service "HTTPS"\n        set service-negate enable')
    dev = fortigate(conf)
    r1, r2 = dev.firewall_rules
    assert r1.src_addresses == ["!LAN-NET"] and r2.services == ["!HTTPS"]
    assert "fw.shadowed" not in findings(dev)


def test_paloalto_negate_source_is_not_a_superset():
    rules = ("<entry name='not-quarantine'><from><member>trust</member></from><to><member>untrust</member></to>"
             "<source><member>QUARANTINE</member></source><negate-source>yes</negate-source>"
             "<destination><member>any</member></destination><application><member>web-browsing</member>"
             "</application><service><member>application-default</member></service><action>allow</action></entry>"
             "<entry name='block-quarantine'><from><member>trust</member></from><to><member>untrust</member></to>"
             "<source><member>QUARANTINE</member></source><destination><member>any</member></destination>"
             "<application><member>web-browsing</member></application><service><member>application-default"
             "</member></service><action>deny</action></entry>")
    dev = paloalto(_pa_config(rules))
    assert dev.firewall_rules[0].src_addresses == ["!QUARANTINE"]
    assert "fw.shadowed" not in findings(dev)


def test_negated_any_is_not_any():
    rule = FirewallRule(id="1", action="allow", src_addresses=["!any"], dst_addresses=["any"], services=["any"])
    assert "fw.any-any" not in findings(fw([rule]))


_FG_VDOMS = """#config-version=FG100F-7.4.4-FW-build2662-240514:opmode=0:vdom=1:user=ro
config vdom
edit root
next
edit TENANT
next
end
config global
config system global
    set hostname "fg-vdom"
end
end
config vdom
edit root
config system settings
    set central-nat enable
end
config firewall policy
    edit 1
        set srcintf "port1"
        set dstintf "wan1"
        set action accept
        set srcaddr "all"
        set dstaddr "all"
        set schedule "always"
        set service "HTTPS"
        set nat enable
    next
end
next
edit TENANT
config system settings
    set opmode nat
end
config firewall policy
    edit 1
        set srcintf "port2"
        set dstintf "wan2"
        set action accept
        set srcaddr "all"
        set dstaddr "all"
        set schedule "always"
        set service "HTTPS"
        set nat enable
    next
end
next
end
"""


def test_fortigate_system_settings_per_vdom():
    dev = fortigate(_FG_VDOMS)
    rules = {r.id: r for r in dev.firewall_rules}
    assert set(rules) == {"1 (root)", "1 (TENANT)"}
    assert rules["1 (root)"].nat is None  # central NAT in root: NAT is decided by the central SNAT map
    assert rules["1 (TENANT)"].nat is True
    assert [n.id for n in dev.nat_rules] == ["policy:1 (TENANT)"]
    facts = {f.key: f.value for s in dev.sections if s.id == "fortigate-system" for f in s.facts}
    assert facts["settings central-nat (root)"] == "enable" and "settings central-nat (TENANT)" not in facts


_FG_HTTP = """config system global
    set hostname "fg-http"
{redirect}end
config system interface
    edit "lan"
        set ip 10.60.0.1 255.255.255.0
        set allowaccess ping https ssh http
    next
end
"""


def test_fortigate_http_redirect_is_not_http_management():
    assert fortigate(_FG_HTTP.format(redirect="")).management.http is False  # redirect defaults to enable
    assert fortigate(_FG_HTTP.format(redirect="    set admin-https-redirect enable\n")).management.http is False
    dev = fortigate(_FG_HTTP.format(redirect="    set admin-https-redirect disable\n"))
    assert dev.management.http is True and dev.management.https is True


# 7 / 8 / 9 -------------------------------------------------------- pfSense / OPNsense


def test_opnsense_mvc_gateways_defaultgw_zero_and_disabled():
    dev = pfsense("""<?xml version="1.0"?><opnsense><system><hostname>opn-test</hostname></system>
      <interfaces>
        <wan><enable>1</enable><if>vtnet0</if><ipaddr>192.0.2.10</ipaddr><subnet>29</subnet></wan>
        <opt1><enable>1</enable><if>vtnet2</if><ipaddr>198.51.100.2</ipaddr><subnet>30</subnet><descr>MPLS</descr></opt1>
      </interfaces>
      <OPNsense><Gateways>
        <gateway_item uuid="g1"><disabled>0</disabled><name>WAN_GW</name><interface>wan</interface>
          <ipprotocol>inet</ipprotocol><gateway>192.0.2.9</gateway><defaultgw>1</defaultgw></gateway_item>
        <gateway_item uuid="g2"><disabled>0</disabled><name>MPLS_GW</name><interface>opt1</interface>
          <ipprotocol>inet</ipprotocol><gateway>198.51.100.1</gateway><defaultgw>0</defaultgw></gateway_item>
        <gateway_item uuid="g3"><disabled>1</disabled><name>OLD_GW</name><interface>wan</interface>
          <ipprotocol>inet</ipprotocol><gateway>192.0.2.14</gateway><defaultgw>1</defaultgw></gateway_item>
      </Gateways></OPNsense></opnsense>""", OPNsenseDriver)
    defaults = [r for r in dev.routes if r.prefix == "0.0.0.0/0"]
    assert [(r.next_hop, r.interface) for r in defaults] == [("192.0.2.9", "WAN")]


_PF_DHCP = """<?xml version="1.0"?><pfsense><system><hostname>pf-test</hostname></system>
  <interfaces>
    <wan><enable/><if>igb0</if><ipaddr>{mode}</ipaddr><descr>WAN</descr></wan>
    <lan><enable/><if>igb1</if><ipaddr>10.70.0.1</ipaddr><subnet>24</subnet></lan>
  </interfaces>{gateways}</pfsense>"""


def test_pfsense_dhcp_and_pppoe_wan_get_a_default_route():
    for mode, label in (("dhcp", "DHCP"), ("pppoe", "PPPoE")):
        dev = pfsense(_PF_DHCP.format(mode=mode, gateways=""))
        (r,) = [r for r in dev.routes if r.prefix == "0.0.0.0/0"]
        assert (r.interface, r.protocol, r.next_hop) == ("WAN", mode, f"from {label}")


def test_pfsense_dhcp_wan_with_static_default_elsewhere():
    gws = ("<gateways><gateway_item><interface>lan</interface><gateway>10.70.0.254</gateway><name>LAN_GW</name>"
           "<ipprotocol>inet</ipprotocol></gateway_item><defaultgw4>LAN_GW</defaultgw4></gateways>")
    dev = pfsense(_PF_DHCP.format(mode="dhcp", gateways=gws))
    assert [(r.next_hop, r.protocol) for r in dev.routes if r.prefix == "0.0.0.0/0"] == [("10.70.0.254", "static")]
    gws = "<gateways><defaultgw4>WAN_DHCP</defaultgw4></gateways>"
    dev = pfsense(_PF_DHCP.format(mode="dhcp", gateways=gws))
    assert [r.protocol for r in dev.routes if r.prefix == "0.0.0.0/0"] == ["dhcp"]


def test_pfsense_gcm_names():
    dev = pfsense("""<?xml version="1.0"?><pfsense><system><hostname>pf-test</hostname></system>
      <interfaces><lan><enable/><if>igb1</if><ipaddr>10.70.0.1</ipaddr><subnet>24</subnet></lan></interfaces>
      <ipsec>
        <phase1><ikeid>1</ikeid><iketype>ikev2</iketype><remote-gateway>203.0.113.40</remote-gateway><descr>s2s</descr>
          <encryption><item><encryption-algorithm><name>aes256gcm</name><keylen>128</keylen></encryption-algorithm>
          <hash-algorithm>sha256</hash-algorithm><dhgroup>19</dhgroup></item></encryption></phase1>
        <phase2><ikeid>1</ikeid><mode>tunnel</mode>
          <localid><type>lan</type></localid><remoteid><type>network</type><address>10.80.0.0</address>
          <netbits>24</netbits></remoteid>
          <encryption-algorithm-option><name>aes128gcm</name><keylen>96</keylen></encryption-algorithm-option>
          <encryption-algorithm-option><name>aes</name><keylen>256</keylen></encryption-algorithm-option>
          <hash-algorithm-option>hmac_sha256</hash-algorithm-option><pfsgroup>19</pfsgroup></phase2>
      </ipsec></pfsense>""")
    (t,) = dev.vpn_tunnels
    assert t.phase1.startswith("aes256gcm16-sha256,")
    assert t.phase2.startswith("aes128gcm12/aes256-sha256,")


# 10 / 11 ---------------------------------------------------------- weak crypto check


def test_weak_prf_is_flagged():
    for p1 in ("aes128gcm-prfsha1, dh19, 28800s", "aes256gcm16-prfsha1, dh20", "aes256gcm16-prfmd5, dh20"):
        f = findings(fw(tunnels=[VpnTunnel(name="t", ike_version="IKEv2", phase1=p1)]))
        assert "vpn.weak-crypto" in f, p1
    ok = findings(fw(tunnels=[VpnTunnel(name="t", ike_version="IKEv2", phase1="aes256gcm16-prfsha384, dh20")]))
    assert "vpn.weak-crypto" not in ok


def test_disabled_tunnel_weak_crypto_is_downgraded():
    t = VpnTunnel(name="old", ike_version="IKEv1", phase1="3des-sha1, dh2", status="disabled")
    f = findings(fw(tunnels=[t]))
    assert f["vpn.weak-crypto"].severity.value == "low" and "disabled" in f["vpn.weak-crypto"].title
    assert "vpn.ikev1" not in f


# 12 / 14 ---------------------------------------------------------- PAN-OS objects, Panorama, Advanced Routing


def test_paloalto_ipv6_object_is_not_a_host():
    extra = ("<address><entry name='V6-NET'><ip-netmask>2001:db8::/32</ip-netmask></entry>"
             "<entry name='V6-HOST'><ip-netmask>2001:db8::10/128</ip-netmask></entry>"
             "<entry name='V4-HOST'><ip-netmask>10.99.1.1/32</ip-netmask></entry></address>")
    objs = {a.name: (a.kind, a.value) for a in paloalto(_pa_config("", extra=extra)).address_objects}
    assert objs["V6-NET"] == ("subnet", "2001:db8::/32")
    assert objs["V6-HOST"] == ("host", "2001:db8::10")
    assert objs["V4-HOST"] == ("host", "10.99.1.1")


def test_paloalto_advanced_routing_logical_router():
    network = """<interface><ethernet><entry name="ethernet1/1"><layer3><ip><entry name="192.0.2.34/29"/></ip>
      </layer3></entry></ethernet></interface>
      <logical-router><entry name="lr-main"><vrf><entry name="default">
        <interface><member>ethernet1/1</member></interface>
        <routing-table><ip><static-route><entry name="internet">
          <destination>0.0.0.0/0</destination><interface>ethernet1/1</interface>
          <nexthop><ip-address>192.0.2.33</ip-address></nexthop><admin-dist>10</admin-dist>
        </entry></static-route></ip></routing-table>
        <bgp><enable>yes</enable><router-id>192.0.2.34</router-id><local-as>64512</local-as>
          <peer-group><entry name="isp"><peer><entry name="isp1"><peer-as>64513</peer-as>
          <peer-address><ip>192.0.2.33</ip></peer-address></entry></peer></entry></peer-group></bgp>
      </entry></vrf></entry></logical-router>"""
    dev = paloalto(_pa_config("", network=network))
    (r,) = dev.routes
    assert (r.prefix, r.next_hop, r.vrf, r.distance) == ("0.0.0.0/0", "192.0.2.33", "lr-main/default", 10)
    assert dev.vrfs == ["lr-main/default"]
    assert dev.interfaces[0].vrf == "lr-main/default"
    (bgp,) = dev.routing_protocols
    assert bgp.asn == "64512" and bgp.neighbors == ["192.0.2.33 (AS 64513, isp1)"]


def test_paloalto_panorama_rulebases_and_device_group_objects():
    def rule(name, action="allow"):
        return (f"<entry name='{name}'><from><member>any</member></from><to><member>any</member></to>"
                "<source><member>any</member></source><destination><member>BRANCH-SRV</member></destination>"
                "<application><member>ssl</member></application><service><member>application-default</member>"
                f"</service><action>{action}</action></entry>")

    xml = f"""<config version="10.2.0">
      <shared><pre-rulebase><security><rules>{rule("shared-pre", "deny")}</rules></security></pre-rulebase>
        <post-rulebase><security><rules>{rule("shared-post", "deny")}</rules></security></post-rulebase></shared>
      <devices><entry name="localhost.localdomain">
        <deviceconfig><system><hostname>panorama-test</hostname></system></deviceconfig>
        <device-group><entry name="DG-BRANCH">
          <address><entry name="BRANCH-SRV"><ip-netmask>10.90.0.10</ip-netmask></entry></address>
          <pre-rulebase><security><rules>{rule("dg-pre")}</rules></security></pre-rulebase>
          <post-rulebase><security><rules>{rule("dg-post")}</rules></security></post-rulebase>
        </entry></device-group>
        <template><entry name="T-BRANCH"/></template>
      </entry></devices></config>"""
    dev = paloalto(xml)
    assert [(r.id, r.name) for r in dev.firewall_rules] == [
        ("shared/pre/1", "shared-pre"), ("DG-BRANCH/pre/1", "dg-pre"), ("DG-BRANCH/post/1", "dg-post"),
        ("shared/post/1", "shared-post")]
    assert ("BRANCH-SRV", "host", "10.90.0.10") in {(a.name, a.kind, a.value) for a in dev.address_objects}
    assert any("Panorama templates" in w for w in dev.collection_warnings)


def test_shadowing_stays_within_a_vdom_or_device_group():
    from sextant.analysis.firewall import shadowed
    from sextant.model import Device, FirewallRule

    def rule(rid, scope, src):
        return FirewallRule(id=rid, action="allow", src_addresses=src, dst_addresses=["all"], services=["ALL"],
                            src_zones=["port1"], dst_zones=["wan1"], scope=scope)

    d = Device(hostname="fw", role="firewall", firewall_rules=[rule("1 (root)", "root", ["all"]),
                                                                 rule("1 (CUST)", "CUST", ["LAN"])])
    assert list(shadowed(d)) == []
    d.firewall_rules.append(rule("2 (CUST)", "CUST", ["LAN"]))
    assert "2 (CUST) shadowed by 1 (CUST)" in next(iter(shadowed(d))).evidence
    shared = FirewallRule(id="shared/pre/1", action="allow", src_addresses=["any"], dst_addresses=["any"],
                          services=["any"], src_zones=["any"], dst_zones=["any"])  # Panorama shared: everywhere
    d2 = Device(hostname="pa", role="firewall", firewall_rules=[shared, rule("DG1/pre/1", "DG1", ["LAN"])])
    assert next(iter(shadowed(d2))).evidence == ["DG1/pre/1 shadowed by shared/pre/1"]
