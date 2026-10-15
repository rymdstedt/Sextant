"""Normalized, vendor-neutral data model.

Every driver (collector + parser) produces a `Device`. Renderers and analysis
checks only ever read this model, never vendor-specific data. Anything that does
not fit the typed fields goes into `Device.sections` as generic `Section`s, so a
renderer can document it without knowing the vendor.

Secrets (passwords, keys, SNMP communities, PSKs) must never be stored in clear
text: drivers call `mask_secret()` before putting them in the model, and strip
them from `raw_config` with `redact_config()` (see sextant.redact).
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


def utcnow() -> datetime:
    return datetime.now(UTC)


def mask_secret(value: str | None) -> str | None:
    """Keep only a hint of a secret so reviewers can tell 'set' from 'default'."""
    if value is None:
        return None
    if value.lower() in {"public", "private"}:
        return value  # default communities are themselves a finding; keep them visible
    return "****" if len(value) <= 4 else value[:1] + "****" + value[-1:]


# --------------------------------------------------------------------------- enums


class DeviceRole(StrEnum):
    switch = "switch"
    router = "router"
    firewall = "firewall"
    hypervisor = "hypervisor"
    server = "server"
    storage = "storage"
    wireless = "wireless"
    other = "other"


class Severity(StrEnum):
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"

    @property
    def rank(self) -> int:
        return ["info", "low", "medium", "high", "critical"].index(self.value)


class PortMode(StrEnum):
    access = "access"
    trunk = "trunk"
    routed = "routed"
    lag_member = "lag-member"
    unknown = "unknown"


# --------------------------------------------------------------------------- generic blocks


class Fact(BaseModel):
    key: str
    value: str


class Table(BaseModel):
    title: str | None = None
    columns: list[str]
    rows: list[list[str]] = Field(default_factory=list)
    note: str | None = None


class Section(BaseModel):
    """Vendor-specific or extra documentation that has no typed field."""

    id: str
    title: str
    intro: str | None = None
    facts: list[Fact] = Field(default_factory=list)
    tables: list[Table] = Field(default_factory=list)
    code: str | None = None  # verbatim (already redacted) config excerpt
    subsections: list[Section] = Field(default_factory=list)
    summary_relevant: bool = False  # True = also show in the quick summary


class Finding(BaseModel):
    """A risk, misconfiguration or notable fact, produced by sextant.analysis."""

    check_id: str
    severity: Severity
    title: str
    detail: str = ""
    recommendation: str = ""
    evidence: list[str] = Field(default_factory=list)


# --------------------------------------------------------------------------- network


class IPAddress(BaseModel):
    address: str  # "10.0.10.1/24" (CIDR) or "10.0.10.1"
    secondary: bool = False
    vrrp_vip: str | None = None


class Interface(BaseModel):
    name: str
    description: str | None = None
    kind: str = "physical"  # physical | lag | vlan | loopback | tunnel | mgmt | virtual
    enabled: bool = True  # admin state
    oper_up: bool | None = None  # None = unknown (offline config import)
    mode: PortMode = PortMode.unknown
    access_vlan: int | None = None
    native_vlan: int | None = None
    trunk_vlans: str | None = None  # keep compact text form: "10,20,100-110" or "all"
    voice_vlan: int | None = None
    ipv4: list[IPAddress] = Field(default_factory=list)
    ipv6: list[str] = Field(default_factory=list)
    vrf: str | None = None
    lag: str | None = None  # name of the parent LAG for members
    lag_members: list[str] = Field(default_factory=list)
    lag_protocol: str | None = None  # lacp | static
    speed: str | None = None
    duplex: str | None = None
    mtu: int | None = None
    mac: str | None = None
    poe: bool | None = None
    stp_edge: bool | None = None
    port_security: bool | None = None
    zone: str | None = None  # firewall zone / security level
    extra: dict[str, str] = Field(default_factory=dict)


class Vlan(BaseModel):
    id: int
    name: str | None = None
    svi_ipv4: list[str] = Field(default_factory=list)
    dhcp_helpers: list[str] = Field(default_factory=list)
    ports: list[str] = Field(default_factory=list)


class Route(BaseModel):
    prefix: str  # "0.0.0.0/0"
    next_hop: str | None = None
    interface: str | None = None
    protocol: str = "static"
    distance: int | None = None
    vrf: str | None = None
    description: str | None = None


class RoutingProtocol(BaseModel):
    protocol: str  # ospf | bgp | eigrp | rip | isis
    process_id: str | None = None
    router_id: str | None = None
    asn: str | None = None
    networks: list[str] = Field(default_factory=list)
    neighbors: list[str] = Field(default_factory=list)
    details: dict[str, str] = Field(default_factory=dict)


class Neighbor(BaseModel):
    """CDP/LLDP neighbor, used to build the cabling/topology tables."""

    local_port: str
    remote_device: str
    remote_port: str | None = None
    remote_platform: str | None = None
    remote_ip: str | None = None
    protocol: str = "lldp"


class AclEntry(BaseModel):
    seq: str | None = None
    action: str  # permit | deny
    text: str  # compact human-readable rule


class Acl(BaseModel):
    name: str
    kind: str = "extended"  # standard | extended | ipv6 | mac
    entries: list[AclEntry] = Field(default_factory=list)
    applied_to: list[str] = Field(default_factory=list)  # "Gi1/0/1 in"


class FirewallRule(BaseModel):
    id: str
    name: str | None = None
    enabled: bool = True
    action: str  # allow | deny | drop | reject
    src_zones: list[str] = Field(default_factory=list)
    dst_zones: list[str] = Field(default_factory=list)
    src_addresses: list[str] = Field(default_factory=list)
    dst_addresses: list[str] = Field(default_factory=list)
    services: list[str] = Field(default_factory=list)
    applications: list[str] = Field(default_factory=list)
    users: list[str] = Field(default_factory=list)
    nat: bool | None = None
    log: bool | None = None
    security_profiles: list[str] = Field(default_factory=list)
    schedule: str | None = None
    comment: str | None = None
    hit_count: int | None = None


class NatRule(BaseModel):
    id: str
    kind: str  # snat | dnat | static | pat | vip
    original: str
    translated: str
    interface: str | None = None
    comment: str | None = None
    enabled: bool = True


class AddressObject(BaseModel):
    name: str
    kind: str = "host"  # host | subnet | range | fqdn | group | geo
    value: str
    comment: str | None = None


class VpnTunnel(BaseModel):
    name: str
    kind: str = "ipsec"  # ipsec | ssl | wireguard | openvpn | gre
    peer: str | None = None
    local_subnets: list[str] = Field(default_factory=list)
    remote_subnets: list[str] = Field(default_factory=list)
    ike_version: str | None = None
    phase1: str | None = None  # "aes256-sha256, dh14, 28800s"
    phase2: str | None = None
    status: str | None = None
    psk_set: bool | None = None


class HighAvailability(BaseModel):
    mode: str  # active-passive | active-active | vrrp | hsrp | stack | vpc | mlag | cluster
    group: str | None = None
    members: list[str] = Field(default_factory=list)
    state: str | None = None
    details: dict[str, str] = Field(default_factory=dict)


# --------------------------------------------------------------------------- management plane


class LocalUser(BaseModel):
    name: str
    privilege: str | None = None  # "15", "admin", "read-only"
    auth: str | None = None  # "secret type 9", "ssh-key", "password type 7" (never the value)


class SnmpConfig(BaseModel):
    enabled: bool = False
    versions: list[str] = Field(default_factory=list)  # v1 | v2c | v3
    communities: list[str] = Field(default_factory=list)  # masked, "public (RO)"
    v3_users: list[str] = Field(default_factory=list)  # "monitor (authPriv, SHA/AES)"
    trap_hosts: list[str] = Field(default_factory=list)
    location: str | None = None
    contact: str | None = None
    acl: str | None = None


class AaaConfig(BaseModel):
    radius_servers: list[str] = Field(default_factory=list)
    tacacs_servers: list[str] = Field(default_factory=list)
    ldap_servers: list[str] = Field(default_factory=list)
    login_methods: list[str] = Field(default_factory=list)  # "default: group tacacs+ local"
    accounting: bool | None = None


class Management(BaseModel):
    ssh: bool | None = None
    ssh_version: str | None = None
    telnet: bool | None = None
    http: bool | None = None
    https: bool | None = None
    console_timeout_min: int | None = None
    vty_acl: str | None = None
    allowed_mgmt_hosts: list[str] = Field(default_factory=list)
    banner: str | None = None
    mgmt_vrf: str | None = None
    ntp_servers: list[str] = Field(default_factory=list)
    dns_servers: list[str] = Field(default_factory=list)
    domain: str | None = None
    timezone: str | None = None
    syslog_servers: list[str] = Field(default_factory=list)
    snmp: SnmpConfig = Field(default_factory=SnmpConfig)
    aaa: AaaConfig = Field(default_factory=AaaConfig)
    users: list[LocalUser] = Field(default_factory=list)
    password_encryption: bool | None = None
    backup_target: str | None = None


class SpanningTree(BaseModel):
    mode: str | None = None  # rstp | mstp | rapid-pvst | pvst | disabled
    priority: str | None = None  # "4096 (vlan 1-4094)"
    root_bridge: bool | None = None
    bpdu_guard_default: bool | None = None
    details: dict[str, str] = Field(default_factory=dict)


# --------------------------------------------------------------------------- virtualization


class VirtualMachine(BaseModel):
    name: str
    power_state: str | None = None  # on | off | suspended
    host: str | None = None
    cluster: str | None = None
    guest_os: str | None = None
    vcpus: int | None = None
    memory_mb: int | None = None
    disks_gb: list[float] = Field(default_factory=list)
    datastores: list[str] = Field(default_factory=list)
    networks: list[str] = Field(default_factory=list)
    ip_addresses: list[str] = Field(default_factory=list)
    tools_status: str | None = None
    snapshots: list[str] = Field(default_factory=list)  # "pre-upgrade (2026-01-03)"
    oldest_snapshot_days: int | None = None
    hw_version: str | None = None
    ha_protected: bool | None = None
    backup: str | None = None
    notes: str | None = None
    tags: list[str] = Field(default_factory=list)


class HypervisorHost(BaseModel):
    name: str
    product: str | None = None  # "VMware ESXi 8.0.3", "Proxmox VE 8.2", "Hyper-V 2022"
    build: str | None = None
    vendor_model: str | None = None
    serial: str | None = None
    cpu_model: str | None = None
    cpu_sockets: int | None = None
    cpu_cores: int | None = None
    memory_gb: float | None = None
    memory_used_gb: float | None = None
    cpu_usage_pct: float | None = None
    state: str | None = None  # connected | maintenance | disconnected
    cluster: str | None = None
    mgmt_ip: str | None = None
    uptime_days: float | None = None
    nics: list[str] = Field(default_factory=list)  # "vmnic0 25000 Mb up"
    ntp_servers: list[str] = Field(default_factory=list)
    services: dict[str, str] = Field(default_factory=dict)  # "SSH": "running"


class Cluster(BaseModel):
    name: str
    hosts: list[str] = Field(default_factory=list)
    ha_enabled: bool | None = None
    drs_enabled: bool | None = None
    drs_level: str | None = None
    evc_mode: str | None = None
    quorum: str | None = None
    details: dict[str, str] = Field(default_factory=dict)


class Datastore(BaseModel):
    name: str
    kind: str | None = None  # VMFS | NFS | vSAN | ZFS | LVM-thin | CSV | Ceph
    capacity_gb: float | None = None
    free_gb: float | None = None
    hosts: list[str] = Field(default_factory=list)
    backing: str | None = None  # "naa.6000... on PureStorage", "10.0.0.5:/vol1"
    shared: bool | None = None

    @property
    def used_pct(self) -> float | None:
        if not self.capacity_gb or self.free_gb is None:
            return None
        return round(100 * (self.capacity_gb - self.free_gb) / self.capacity_gb, 1)


class VirtualNetwork(BaseModel):
    name: str  # vSwitch / dvSwitch / Linux bridge / Hyper-V vSwitch
    kind: str | None = None  # standard | distributed | bridge | external | internal
    host: str | None = None
    uplinks: list[str] = Field(default_factory=list)
    mtu: int | None = None
    portgroups: list[Table] = Field(default_factory=list)  # usually not needed; use port_groups
    port_groups: list[dict[str, str]] = Field(default_factory=list)  # {"name","vlan","active","standby"}
    teaming: str | None = None


class Virtualization(BaseModel):
    platform: str  # vmware | proxmox | hyperv
    manager: str | None = None  # "vCenter 8.0.3 (vc01.corp.local)"
    clusters: list[Cluster] = Field(default_factory=list)
    hosts: list[HypervisorHost] = Field(default_factory=list)
    vms: list[VirtualMachine] = Field(default_factory=list)
    datastores: list[Datastore] = Field(default_factory=list)
    networks: list[VirtualNetwork] = Field(default_factory=list)
    licenses: list[str] = Field(default_factory=list)


# --------------------------------------------------------------------------- device


class Device(BaseModel):
    # identity
    hostname: str
    role: DeviceRole = DeviceRole.other
    vendor: str | None = None  # "Cisco", "Fortinet", "VMware"
    platform: str | None = None  # driver id: "cisco_ios", "fortigate", "vmware"
    model: str | None = None
    os_name: str | None = None  # "IOS-XE", "FortiOS"
    os_version: str | None = None
    serial: str | None = None
    uptime: str | None = None
    mgmt_ip: str | None = None
    site: str | None = None
    location: str | None = None
    contact: str | None = None
    hardware: list[Fact] = Field(default_factory=list)  # modules, PSUs, stack members
    licenses: list[str] = Field(default_factory=list)

    # collection provenance
    collected_at: datetime = Field(default_factory=utcnow)
    collection_method: str | None = None  # ssh | snmp | api | file
    source: str | None = None  # host or file name the data came from
    collection_warnings: list[str] = Field(default_factory=list)

    # network / security config
    management: Management = Field(default_factory=Management)
    interfaces: list[Interface] = Field(default_factory=list)
    vlans: list[Vlan] = Field(default_factory=list)
    vrfs: list[str] = Field(default_factory=list)
    routes: list[Route] = Field(default_factory=list)
    routing_protocols: list[RoutingProtocol] = Field(default_factory=list)
    neighbors: list[Neighbor] = Field(default_factory=list)
    spanning_tree: SpanningTree | None = None
    acls: list[Acl] = Field(default_factory=list)
    firewall_rules: list[FirewallRule] = Field(default_factory=list)
    nat_rules: list[NatRule] = Field(default_factory=list)
    address_objects: list[AddressObject] = Field(default_factory=list)
    vpn_tunnels: list[VpnTunnel] = Field(default_factory=list)
    ha: HighAvailability | None = None
    dhcp_scopes: list[Table] = Field(default_factory=list)

    # hypervisors
    virtualization: Virtualization | None = None

    # extras
    sections: list[Section] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)  # filled by sextant.analysis
    raw_config: str | None = None  # redacted running config / export
    raw: dict[str, Any] = Field(default_factory=dict)  # redacted raw command outputs, for debugging


# --------------------------------------------------------------------------- project


class DocumentInfo(BaseModel):
    """Metadata printed on the cover and document-control page."""

    customer: str = "Internal"
    project: str = "Infrastructure documentation"
    site: str | None = None
    author: str | None = None
    reviewer: str | None = None
    version: str = "1.0"
    classification: str = "Internal"
    language: str = "en"
    notes: str | None = None
    theme: str | None = None  # branding theme name or folder (see sextant.theme); None = server default


class Snapshot(BaseModel):
    """Everything collected in one run. Saved as JSON so documents can be
    re-rendered offline, and uploaded to a cloud-hosted UI from an on-prem run."""

    schema_version: int = 1
    info: DocumentInfo = Field(default_factory=DocumentInfo)
    created_at: datetime = Field(default_factory=utcnow)
    devices: list[Device] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)  # targets that failed to collect
