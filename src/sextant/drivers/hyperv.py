"""Microsoft Hyper-V / Failover Cluster driver (WinRM + one read-only PowerShell script).

collect() runs ``COLLECT_SCRIPT`` (only Get-* cmdlets) over WinRM and stores the
single JSON object it prints in ``raw.outputs["inventory"]``. The same script is
shipped as ``examples/hyperv/collect-hyperv.ps1`` so customers can run it
themselves and upload the JSON file (``from_file``).

Target options: ``transport`` (ntlm | kerberos | credssp | basic; default ntlm),
``scheme`` (https | http; default https), ``port``.
On a cluster the script queries every node (``Get-VM -ComputerName``). With NTLM
that remote hop may be refused (double hop); use Kerberos/CredSSP, or run the
script on each node, or accept the per-node warnings (cluster roles still list
every clustered VM with its owner node).
"""

from __future__ import annotations

import base64
import gzip
import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sextant.drivers import register
from sextant.drivers._util import as_list, parse_dt, to_float, to_int
from sextant.drivers.base import Credentials, Driver, RawCollection, Target
from sextant.model import (
    Datastore,
    Device,
    DeviceRole,
    Fact,
    HighAvailability,
    HypervisorHost,
    Interface,
    IPAddress,
    Route,
    Section,
    Table,
    Virtualization,
    VirtualMachine,
    VirtualNetwork,
)
from sextant.redact import redact_obj

COLLECT_SCRIPT = r"""# collect-hyperv.ps1 - read-only Hyper-V / Failover Cluster inventory for sextant (Sextant).
# Uses Get-* cmdlets only; changes nothing. Prints ONE JSON object on stdout.
# Run on a Hyper-V host or cluster node (Hyper-V Administrators or local admin, read access suffices):
#   powershell -NoProfile -ExecutionPolicy Bypass -File .\collect-hyperv.ps1 > hyperv-inventory.json
# then import the file with:  sextant import --driver hyperv hyperv-inventory.json
$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
$warn = [System.Collections.Generic.List[string]]::new()
function Iso($d) { if ($d) { ([datetime]$d).ToUniversalTime().ToString('o') } }
function GB($b) { if ($null -ne $b) { [math]::Round([double]$b / 1GB, 1) } }
function Try-Get([string]$what, [scriptblock]$sb) {
  try { & $sb } catch { $warn.Add("${what}: $($_.Exception.Message)"); $null }
}

$ci = Try-Get 'Get-ComputerInfo' {
  $c = Get-ComputerInfo -Property CsName, CsDomain, CsManufacturer, CsModel, BiosSeralNumber, OsName, OsVersion,
    OsBuildNumber, OsLastBootUpTime, CsNumberOfLogicalProcessors, CsNumberOfProcessors, CsTotalPhysicalMemory,
    CsProcessors, TimeZone
  [pscustomobject]@{ CsName = $c.CsName; CsDomain = $c.CsDomain; CsManufacturer = $c.CsManufacturer
    CsModel = $c.CsModel; BiosSerialNumber = $c.BiosSeralNumber; OsName = $c.OsName; OsVersion = $c.OsVersion
    OsBuildNumber = $c.OsBuildNumber; OsLastBootUpTime = (Iso $c.OsLastBootUpTime)
    LogicalProcessors = $c.CsNumberOfLogicalProcessors; Sockets = $c.CsNumberOfProcessors
    TotalPhysicalMemoryGB = (GB $c.CsTotalPhysicalMemory); Processor = (@($c.CsProcessors)[0].Name)
    Cores = (@($c.CsProcessors) | Measure-Object -Property NumberOfCores -Sum).Sum; TimeZone = $c.TimeZone }
}

$cluster = $null; $nodes = @($env:COMPUTERNAME); $clusterNodes = @(); $csv = @(); $cnet = @(); $groups = @()
if (Get-Command Get-Cluster -ErrorAction SilentlyContinue) {
  $cl = Try-Get 'Get-Cluster' { Get-Cluster -ErrorAction Stop }
  if ($cl) {
    $q = Try-Get 'Get-ClusterQuorum' { Get-ClusterQuorum -ErrorAction Stop }
    $cluster = [pscustomobject]@{ Name = $cl.Name; Domain = $cl.Domain; QuorumType = "$($q.QuorumType)"
      QuorumResource = "$($q.QuorumResource)"; SameSubnetThreshold = $cl.SameSubnetThreshold
      DynamicQuorum = $cl.DynamicQuorum; S2DEnabled = $cl.S2DEnabled }
    $clusterNodes = @(Get-ClusterNode | ForEach-Object { [pscustomobject]@{ Name = $_.Name; State = "$($_.State)"
      NodeWeight = $_.NodeWeight; DynamicWeight = $_.DynamicWeight } })
    $nodes = @($clusterNodes | ForEach-Object { $_.Name })
    $csv = @(Try-Get 'Get-ClusterSharedVolume' { Get-ClusterSharedVolume -ErrorAction Stop | ForEach-Object {
      $i = @($_.SharedVolumeInfo)[0]
      [pscustomobject]@{ Name = $_.Name; OwnerNode = "$($_.OwnerNode)"; State = "$($_.State)"
        Path = $i.FriendlyVolumeName; FileSystem = "$($i.Partition.FileSystem)"; SizeGB = (GB $i.Partition.Size)
        FreeGB = (GB $i.Partition.FreeSpace); Maintenance = $i.MaintenanceMode; Redirected = "$($i.RedirectedAccess)" } } })
    $cnet = @(Get-ClusterNetwork | ForEach-Object { [pscustomobject]@{ Name = $_.Name; Role = "$($_.Role)"
      Address = $_.Address; AddressMask = $_.AddressMask; State = "$($_.State)"; Metric = $_.Metric } })
    $groups = @(Get-ClusterGroup | Where-Object { "$($_.GroupType)" -eq 'VirtualMachine' } | ForEach-Object {
      [pscustomobject]@{ Name = $_.Name; OwnerNode = "$($_.OwnerNode)"; State = "$($_.State)"; Priority = $_.Priority } })
  }
}

$vmHosts = @(foreach ($n in $nodes) { Try-Get "Get-VMHost $n" { Get-VMHost -ComputerName $n -ErrorAction Stop |
  Select-Object ComputerName, LogicalProcessorCount, @{ n = 'MemoryCapacityGB'; e = { GB $_.MemoryCapacity } },
    VirtualMachinePath, VirtualHardDiskPath, VirtualMachineMigrationEnabled, MaximumVirtualMachineMigrations,
    @{ n = 'MigrationAuth'; e = { "$($_.VirtualMachineMigrationAuthenticationType)" } }, NumaSpanningEnabled } })

$vms = @(foreach ($n in $nodes) { Try-Get "Get-VM $n" { Get-VM -ComputerName $n -ErrorAction Stop } })
$vmOut = @(foreach ($vm in $vms) {
  if (-not $vm) { continue }
  $cn = $vm.ComputerName
  $nics = @(Get-VMNetworkAdapter -VM $vm | ForEach-Object { [pscustomobject]@{ Name = $_.Name; SwitchName = $_.SwitchName
    MacAddress = $_.MacAddress; IPAddresses = @($_.IPAddresses); VlanMode = "$($_.VlanSetting.OperationMode)"
    VlanId = $_.VlanSetting.AccessVlanId } })
  $disks = @(Get-VMHardDiskDrive -VM $vm | ForEach-Object {
    $vhd = $null; try { $vhd = Get-VHD -Path $_.Path -ComputerName $cn -ErrorAction Stop } catch { }
    [pscustomobject]@{ Path = $_.Path; Controller = "$($_.ControllerType) $($_.ControllerNumber):$($_.ControllerLocation)"
      SizeGB = (GB $vhd.Size); FileSizeGB = (GB $vhd.FileSize); VhdType = "$($vhd.VhdType)" } })
  $snaps = @(Get-VMSnapshot -VM $vm | ForEach-Object { [pscustomobject]@{ Name = $_.Name
    CreationTime = (Iso $_.CreationTime); SnapshotType = "$($_.SnapshotType)"; Parent = $_.ParentSnapshotName } })
  $os = $null
  try {
    $kvp = Get-CimInstance -Namespace root\virtualization\v2 -ClassName Msvm_KvpExchangeComponent -ComputerName $cn `
      -Filter "SystemName='$($vm.Id)'" -ErrorAction Stop
    foreach ($x in @($kvp.GuestIntrinsicExchangeItems)) {
      $xml = [xml]$x
      if ($xml.SelectSingleNode("//PROPERTY[@NAME='Name']/VALUE").InnerText -eq 'OSName') {
        $os = $xml.SelectSingleNode("//PROPERTY[@NAME='Data']/VALUE").InnerText } }
  } catch { }
  [pscustomobject]@{ Name = $vm.Name; Id = "$($vm.Id)"; ComputerName = $cn; State = "$($vm.State)"; Status = $vm.Status
    GuestOS = $os; ProcessorCount = $vm.ProcessorCount; MemoryStartupMB = [int]($vm.MemoryStartup / 1MB)
    MemoryAssignedMB = [int]($vm.MemoryAssigned / 1MB); DynamicMemoryEnabled = $vm.DynamicMemoryEnabled
    Generation = $vm.Generation; Version = "$($vm.Version)"; UptimeHours = [math]::Round($vm.Uptime.TotalHours, 1)
    IsClustered = $vm.IsClustered; Path = $vm.Path; Notes = $vm.Notes; Heartbeat = "$($vm.Heartbeat)"
    IntegrationServicesState = "$($vm.IntegrationServicesState)"; ReplicationState = "$($vm.ReplicationState)"
    AutomaticStartAction = "$($vm.AutomaticStartAction)"; NetworkAdapters = $nics; HardDrives = $disks; Snapshots = $snaps }
})

$switches = @(foreach ($n in $nodes) { Try-Get "Get-VMSwitch $n" { Get-VMSwitch -ComputerName $n -ErrorAction Stop | ForEach-Object {
  $team = $null
  if ($_.EmbeddedTeamingEnabled) { $team = Get-VMSwitchTeam -Name $_.Name -ComputerName $n -ErrorAction SilentlyContinue }
  [pscustomobject]@{ ComputerName = $n; Name = $_.Name; SwitchType = "$($_.SwitchType)"
    NetAdapterInterfaceDescriptions = @($_.NetAdapterInterfaceDescriptions); AllowManagementOS = $_.AllowManagementOS
    EmbeddedTeamingEnabled = $_.EmbeddedTeamingEnabled; BandwidthReservationMode = "$($_.BandwidthReservationMode)"
    TeamingMode = "$($team.TeamingMode)"; LoadBalancingAlgorithm = "$($team.LoadBalancingAlgorithm)" } } } })
$mgmtNics = @(Try-Get 'Get-VMNetworkAdapter -ManagementOS' { Get-VMNetworkAdapter -ManagementOS -ErrorAction Stop |
  ForEach-Object { [pscustomobject]@{ Name = $_.Name; SwitchName = $_.SwitchName; MacAddress = $_.MacAddress
    VlanId = $_.VlanSetting.AccessVlanId; VlanMode = "$($_.VlanSetting.OperationMode)" } } })

$ips = @(Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -notlike 'Loopback*' } |
  ForEach-Object { [pscustomobject]@{ InterfaceAlias = $_.InterfaceAlias; IPAddress = $_.IPAddress
    PrefixLength = $_.PrefixLength; PrefixOrigin = "$($_.PrefixOrigin)" } })
$routes = @(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | ForEach-Object {
  [pscustomobject]@{ NextHop = $_.NextHop; InterfaceAlias = $_.InterfaceAlias; RouteMetric = $_.RouteMetric } })
$dns = @(Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object { $_.ServerAddresses } | ForEach-Object {
  [pscustomobject]@{ InterfaceAlias = $_.InterfaceAlias; ServerAddresses = @($_.ServerAddresses) } })
$ntp = Try-Get 'W32Time' { Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters' -ErrorAction Stop |
  Select-Object NtpServer, Type }
$vols = @(Get-Volume | Where-Object { $_.DriveLetter } | ForEach-Object { [pscustomobject]@{ DriveLetter = "$($_.DriveLetter)"
  FileSystemLabel = $_.FileSystemLabel; FileSystem = $_.FileSystem; SizeGB = (GB $_.Size)
  FreeGB = (GB $_.SizeRemaining); HealthStatus = "$($_.HealthStatus)" } })

[pscustomobject]@{
  SchemaVersion = 1; CollectedAt = (Get-Date).ToUniversalTime().ToString('o'); ComputerName = $env:COMPUTERNAME
  ComputerInfo = $ci; VMHosts = $vmHosts; Cluster = $cluster; ClusterNodes = $clusterNodes
  ClusterSharedVolumes = $csv; ClusterNetworks = $cnet; ClusterGroups = $groups; VMs = $vmOut
  VMSwitches = $switches; ManagementOSAdapters = $mgmtNics; NetIPAddresses = $ips; DefaultRoutes = $routes
  DnsServers = $dns; Ntp = $ntp; Volumes = $vols; Warnings = @($warn)
} | ConvertTo-Json -Depth 5 -Compress
"""

_FORBIDDEN = re.compile(r"\b(Set|New|Remove|Start|Stop|Restart|Suspend|Resume|Move|Enable|Disable|Invoke|Add|"
                        r"Clear|Update|Install|Uninstall)-[A-Za-z]", re.I)


def assert_script_read_only(script: str) -> None:
    hits = _FORBIDDEN.findall(script)
    if hits:
        raise ValueError(f"Refusing to run script with state-changing cmdlets: {sorted(set(hits))}")


def _minify(script: str) -> str:
    """Drop comment-only lines and indentation (the script has no here-strings, so this is safe)."""
    return "\n".join(ln.strip() for ln in script.splitlines() if ln.strip() and not ln.strip().startswith("#"))


def _command_line(script: str) -> str:
    """One cmd.exe-safe command line (< 8191 chars) that runs the script.

    The minified script is gzip+base64 encoded (alphabet [A-Za-z0-9+/=]) and passed in plain ASCII to
    ``powershell -Command``; ``-EncodedCommand`` would double the size (UTF-16) and exceed the limit.
    """
    blob = base64.b64encode(gzip.compress(_minify(script).encode("utf-8"))).decode("ascii")
    wrapper = ("$s=[IO.StreamReader]::new([IO.Compression.GZipStream]::new([IO.MemoryStream]::new("
               f"[Convert]::FromBase64String('{blob}')),[IO.Compression.CompressionMode]::Decompress)).ReadToEnd();"
               "& ([scriptblock]::Create($s))")
    cmd = f'powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "{wrapper}"'
    if len(cmd) > 8000:
        raise ValueError(f"collection command line too long ({len(cmd)} chars)")
    return cmd


def _extract_json(text: str) -> dict[str, Any]:
    start = text.find("{")
    if start < 0:
        raise ValueError("no JSON object in script output")
    return json.loads(text[start:text.rfind("}") + 1])


class HyperVDriver(Driver):
    id = "hyperv"
    label = "Microsoft Hyper-V / Failover Cluster"
    methods = ("winrm", "file")

    def collect(self, target: Target, creds: Credentials) -> RawCollection:  # pragma: no cover - live only
        import winrm  # lazy

        assert_script_read_only(COLLECT_SCRIPT)
        opts = target.options
        scheme = opts.get("scheme", "https")
        port = target.port or opts.get("port") or (5986 if scheme == "https" else 5985)
        sess = winrm.Session(
            f"{scheme}://{target.host or target.name}:{port}/wsman", auth=(creds.username, creds.password),
            transport=opts.get("transport", "ntlm"),
            server_cert_validation="validate" if target.verify_tls else "ignore")
        raw = RawCollection(driver=self.id, target=target.name, method="winrm")
        res = sess.run_cmd(_command_line(COLLECT_SCRIPT))
        if res.status_code != 0:
            raw.warnings.append(f"script exit code {res.status_code}: "
                                f"{res.std_err.decode(errors='replace')[:500]}")
        try:
            inv = _extract_json(res.std_out.decode("utf-8-sig", errors="replace"))
        except ValueError as exc:
            raw.warnings.append(f"could not parse script output: {exc}")
            inv = {}
        raw.outputs["inventory"] = redact_obj(inv)
        return raw

    def from_file(self, path: Path) -> RawCollection:
        text = path.read_bytes().decode("utf-8-sig", errors="replace")
        if text.startswith("﻿") or "\x00" in text:  # PowerShell 5.1 '>' writes UTF-16
            text = path.read_bytes().decode("utf-16", errors="replace")
        data = _extract_json(text)
        if "outputs" in data and "driver" in data:
            data = data["outputs"].get("inventory", {})
        return RawCollection(driver=self.id, target=path.name, method="file", outputs={"inventory": redact_obj(data)})

    # ----------------------------------------------------------------------- parse

    def parse(self, raw: RawCollection) -> Device:
        inv = raw.outputs.get("inventory") if isinstance(raw.outputs.get("inventory"), dict) else {}
        warnings = list(raw.warnings)
        if not inv:
            warnings.append("hyperv: 'inventory' missing or empty")
        warnings += [f"collector: {w}" for w in as_list(inv.get("Warnings")) if w]
        collected = parse_dt(inv.get("CollectedAt"))
        ref = collected or datetime.now(UTC)
        ci = inv.get("ComputerInfo") if isinstance(inv.get("ComputerInfo"), dict) else {}
        local = str(inv.get("ComputerName") or ci.get("CsName") or raw.target)
        cl = inv.get("Cluster") if isinstance(inv.get("Cluster"), dict) else None
        cluster_name = cl.get("Name") if cl else None
        nodes = [n for n in as_list(inv.get("ClusterNodes")) if isinstance(n, dict) and n.get("Name")]
        node_names = [n["Name"] for n in nodes] or [local]
        os_name = ci.get("OsName")
        product = f"Hyper-V ({os_name.replace('Microsoft ', '')})" if os_name else "Hyper-V"

        virt = Virtualization(platform="hyperv")
        if cluster_name:
            virt.manager = f"Failover Cluster {cluster_name}" + (f".{cl['Domain']}" if cl.get("Domain") else "")

        # hosts
        vmhosts = {str(h.get("ComputerName", "")).lower(): h for h in as_list(inv.get("VMHosts")) if isinstance(h, dict)}
        boot = parse_dt(ci.get("OsLastBootUpTime"))
        ips = [x for x in as_list(inv.get("NetIPAddresses")) if isinstance(x, dict)]
        for name in node_names:
            vh = vmhosts.get(name.lower(), {})
            nd = next((n for n in nodes if n["Name"] == name), {})
            is_local = name.lower() == local.lower()
            st = str(nd.get("State") or ("Up" if is_local else ""))
            mgmt = next((x.get("IPAddress") for x in ips if "manage" in str(x.get("InterfaceAlias", "")).lower()),
                        ips[0].get("IPAddress") if ips else None) if is_local else None
            virt.hosts.append(HypervisorHost(
                name=name, product=product, build=ci.get("OsBuildNumber") and f"build {ci['OsBuildNumber']}",
                vendor_model=" ".join(x for x in (ci.get("CsManufacturer"), ci.get("CsModel")) if x) or None
                if is_local else None,
                serial=ci.get("BiosSerialNumber") if is_local else None,
                cpu_model=ci.get("Processor") if is_local else None,
                cpu_sockets=to_int(ci.get("Sockets")) if is_local else None,
                cpu_cores=to_int(ci.get("Cores")) if is_local else to_int(vh.get("LogicalProcessorCount")),
                memory_gb=to_float(vh.get("MemoryCapacityGB")) or (to_float(ci.get("TotalPhysicalMemoryGB"))
                                                                    if is_local else None),
                state={"Up": "connected", "Paused": "maintenance", "Down": "disconnected", "Joining": "joining"}
                .get(st, st.lower() or None),
                cluster=cluster_name, mgmt_ip=mgmt,
                uptime_days=round((ref - boot).total_seconds() / 86400, 1) if boot and is_local else None))

        # datastores: CSVs (shared) + local volumes of the queried node
        csvs = [c for c in as_list(inv.get("ClusterSharedVolumes")) if isinstance(c, dict) and c.get("Name")]
        for c in csvs:
            virt.datastores.append(Datastore(
                name=c["Name"], kind="CSV", capacity_gb=to_float(c.get("SizeGB")), free_gb=to_float(c.get("FreeGB")),
                hosts=list(node_names), shared=True,
                backing=f"{c.get('Path', '')} ({c.get('FileSystem', '?')}, owner {c.get('OwnerNode', '?')})"))
        for v in as_list(inv.get("Volumes")):
            if isinstance(v, dict) and v.get("DriveLetter") and to_float(v.get("SizeGB")):
                virt.datastores.append(Datastore(
                    name=f"{v['DriveLetter']}: {v.get('FileSystemLabel') or ''} ({local})".replace("  ", " "),
                    kind=f"local {v.get('FileSystem') or ''}".strip(), capacity_gb=to_float(v.get("SizeGB")),
                    free_gb=to_float(v.get("FreeGB")), hosts=[local], shared=False))

        def store_of(path: str) -> str | None:
            for c in csvs:
                if c.get("Path") and path.lower().startswith(str(c["Path"]).lower().rstrip("\\") + "\\"):
                    return c["Name"]
            m = re.match(r"^([A-Za-z]):\\", path)
            return f"{m.group(1).upper()}: ({local})" if m else None

        # VMs (from Get-VM), then clustered roles not seen (node unreachable)
        seen = set()
        for vm in as_list(inv.get("VMs")):
            if not isinstance(vm, dict) or not vm.get("Name"):
                continue
            seen.add(str(vm["Name"]).lower())
            disks = [d for d in as_list(vm.get("HardDrives")) if isinstance(d, dict)]
            nics = [n for n in as_list(vm.get("NetworkAdapters")) if isinstance(n, dict)]
            snaps = [s for s in as_list(vm.get("Snapshots")) if isinstance(s, dict)]
            ages = [(ref - dt).days for s in snaps if (dt := parse_dt(s.get("CreationTime")))]
            power = _power(vm.get("State"))
            stores = []
            for d in disks:
                s = store_of(str(d.get("Path") or ""))
                if s and s not in stores:
                    stores.append(s)
            virt.vms.append(VirtualMachine(
                name=vm["Name"], power_state=power, host=vm.get("ComputerName"),
                cluster=cluster_name if vm.get("IsClustered") else None, guest_os=vm.get("GuestOS") or None,
                vcpus=to_int(vm.get("ProcessorCount")),
                memory_mb=to_int(vm.get("MemoryStartupMB")),
                disks_gb=[f for f in (to_float(d.get("SizeGB")) for d in disks) if f is not None],
                datastores=stores,
                networks=[f"{n.get('SwitchName') or 'not connected'}"
                          + (f" VLAN {n['VlanId']}" if to_int(n.get("VlanId")) else "") for n in nics],
                ip_addresses=[ip for n in nics for ip in as_list(n.get("IPAddresses"))
                              if isinstance(ip, str) and not ip.lower().startswith("fe80")],
                tools_status=_heartbeat(vm.get("Heartbeat")) if power == "on" else None,
                snapshots=[f"{s.get('Name')} ({dt.date().isoformat()})" if (dt := parse_dt(s.get("CreationTime")))
                           else str(s.get("Name")) for s in snaps],
                oldest_snapshot_days=max(ages) if ages else None,
                hw_version=f"Gen {vm.get('Generation', '?')}, config {vm.get('Version', '?')}",
                ha_protected=bool(vm.get("IsClustered")), notes=(vm.get("Notes") or "").strip() or None,
                tags=[t for t in (f"memory: {'dynamic' if vm.get('DynamicMemoryEnabled') else 'static'}",
                                  f"replication: {vm['ReplicationState']}"
                                  if vm.get("ReplicationState") not in (None, "", "Disabled") else None) if t]))
        groups = [g for g in as_list(inv.get("ClusterGroups")) if isinstance(g, dict) and g.get("Name")]
        for g in groups:
            if str(g["Name"]).lower() not in seen:
                virt.vms.append(VirtualMachine(
                    name=g["Name"], power_state="on" if g.get("State") == "Online" else "off",
                    host=g.get("OwnerNode"), cluster=cluster_name, ha_protected=True,
                    notes="Clustered role only; VM details not collected (node not reachable)"))
                warnings.append(f"VM {g['Name']}: only cluster role data (owner {g.get('OwnerNode')})")

        # virtual switches (+ management OS vNICs as "port groups")
        mgmt_nics = [m for m in as_list(inv.get("ManagementOSAdapters")) if isinstance(m, dict)]
        for sw in as_list(inv.get("VMSwitches")):
            if not isinstance(sw, dict) or not sw.get("Name"):
                continue
            team = None
            if sw.get("EmbeddedTeamingEnabled"):
                team = f"SET {sw.get('TeamingMode') or 'SwitchIndependent'}, {sw.get('LoadBalancingAlgorithm') or '?'}"
            pgs = [{"name": f"vEthernet ({m.get('Name')}) [host]",
                    "vlan": str(m.get("VlanId") or "untagged"), "active": "", "standby": ""}
                   for m in mgmt_nics if m.get("SwitchName") == sw["Name"]
                   and str(sw.get("ComputerName", local)).lower() == local.lower()]
            vlans = sorted({to_int(n.split(" VLAN ")[1]) for v in virt.vms for n in v.networks
                            if n.startswith(sw["Name"] + " VLAN ")} - {None})
            pgs += [{"name": f"VLAN {t} (VMs)", "vlan": str(t), "active": "", "standby": ""} for t in vlans]
            virt.networks.append(VirtualNetwork(
                name=sw["Name"], kind=str(sw.get("SwitchType") or "").lower() or None, host=sw.get("ComputerName"),
                uplinks=[str(x) for x in as_list(sw.get("NetAdapterInterfaceDescriptions"))],
                port_groups=pgs, teaming=team))

        # host OS networking
        interfaces: dict[str, Interface] = {}
        for x in ips:
            alias = str(x.get("InterfaceAlias") or "?")
            itf = interfaces.setdefault(alias, Interface(
                name=alias, kind="virtual" if alias.startswith("vEthernet") else "physical", oper_up=True))
            if x.get("IPAddress"):
                itf.ipv4.append(IPAddress(address=f"{x['IPAddress']}/{x.get('PrefixLength', 32)}"))
        for m in mgmt_nics:
            itf = interfaces.get(f"vEthernet ({m.get('Name')})")
            if itf and to_int(m.get("VlanId")):
                itf.access_vlan = to_int(m["VlanId"])
                itf.mac = m.get("MacAddress")
        routes = [Route(prefix="0.0.0.0/0", next_hop=r.get("NextHop"), interface=r.get("InterfaceAlias"),
                        protocol="static", distance=to_int(r.get("RouteMetric")))
                  for r in as_list(inv.get("DefaultRoutes")) if isinstance(r, dict)]
        dns = []
        for d in as_list(inv.get("DnsServers")):
            for s in as_list(d.get("ServerAddresses") if isinstance(d, dict) else None):
                if s not in dns:
                    dns.append(s)
        ntp = inv.get("Ntp") if isinstance(inv.get("Ntp"), dict) else {}
        # Type NT5DS = sync from the domain hierarchy; NtpServer is then ignored by W32Time
        ntp_servers = ["domain hierarchy (NT5DS)"] if ntp.get("Type") == "NT5DS" else \
            [s.split(",")[0] for s in str(ntp.get("NtpServer") or "").split() if s]
        for h in virt.hosts:
            if h.name.lower() == local.lower():
                h.ntp_servers = ntp_servers

        sections: list[Section] = []
        if cl:
            facts = [Fact(key="Cluster", value=f"{cluster_name}" + (f".{cl['Domain']}" if cl.get("Domain") else "")),
                     Fact(key="Quorum", value=f"{cl.get('QuorumType', '?')} ({cl.get('QuorumResource') or 'no witness'})"),
                     Fact(key="Dynamic quorum", value=str(bool(to_int(cl.get("DynamicQuorum"))))),
                     Fact(key="Storage Spaces Direct", value=str(bool(to_int(cl.get("S2DEnabled")))))]
            rows = [[n["Name"], str(n.get("State", "")), str(n.get("NodeWeight", "")), str(n.get("DynamicWeight", ""))]
                    for n in nodes]
            sec = Section(id="hyperv-cluster", title="Failover cluster", facts=facts, tables=[
                Table(title="Nodes", columns=["Node", "State", "Vote", "Dynamic vote"], rows=rows)])
            cnet = [c for c in as_list(inv.get("ClusterNetworks")) if isinstance(c, dict)]
            if cnet:
                sec.tables.append(Table(title="Cluster networks", columns=["Name", "Role", "Subnet", "State", "Metric"],
                                        rows=[[str(c.get("Name", "")), str(c.get("Role", "")),
                                               f"{c.get('Address', '')}/{c.get('AddressMask', '')}",
                                               str(c.get("State", "")), str(c.get("Metric", ""))] for c in cnet]))
            if csvs:
                sec.tables.append(Table(title="Cluster Shared Volumes", columns=[
                    "Name", "Path", "Owner", "State", "Size GB", "Free GB", "Redirected"], rows=[
                    [str(c["Name"]), str(c.get("Path", "")), str(c.get("OwnerNode", "")), str(c.get("State", "")),
                     str(c.get("SizeGB", "")), str(c.get("FreeGB", "")), str(c.get("Redirected", ""))] for c in csvs]))
            if groups:
                sec.tables.append(Table(title="Clustered VM roles", columns=["Role", "Owner node", "State", "Priority"],
                                        rows=[[str(g["Name"]), str(g.get("OwnerNode", "")), str(g.get("State", "")),
                                               str(g.get("Priority", ""))] for g in groups]))
            sections.append(sec)
        if vmhosts:
            sections.append(Section(id="hyperv-host-settings", title="Hyper-V host settings", tables=[Table(
                columns=["Host", "Logical CPUs", "Memory GB", "VM path", "VHD path", "Live migration", "Auth",
                         "NUMA spanning"],
                rows=[[str(h.get("ComputerName", "")), str(h.get("LogicalProcessorCount", "")),
                       str(h.get("MemoryCapacityGB", "")), str(h.get("VirtualMachinePath", "")),
                       str(h.get("VirtualHardDiskPath", "")),
                       f"{h.get('VirtualMachineMigrationEnabled')} (max {h.get('MaximumVirtualMachineMigrations')})",
                       str(h.get("MigrationAuth", "")), str(h.get("NumaSpanningEnabled", ""))]
                      for h in vmhosts.values()])]))

        ha = HighAvailability(mode="cluster", group=cluster_name, members=node_names,
                              state="all nodes up" if all(n.get("State") == "Up" for n in nodes) else
                              ", ".join(f"{n['Name']} {n.get('State')}" for n in nodes if n.get("State") != "Up"),
                              details={"Quorum": str(cl.get("QuorumType", ""))}) if cl else None
        dev = Device(
            hostname=cluster_name or local, role=DeviceRole.hypervisor, vendor="Microsoft", platform=self.id,
            model=" ".join(x for x in (ci.get("CsManufacturer"), ci.get("CsModel")) if x) or None,
            os_name=os_name, os_version=f"{ci.get('OsVersion', '')}".strip() or None,
            serial=None if cl else ci.get("BiosSerialNumber"), mgmt_ip=next((h.mgmt_ip for h in virt.hosts if h.mgmt_ip), None),
            uptime=f"{(ref - boot).days} days" if boot and not cl else None,
            collected_at=collected or datetime.now(UTC), collection_method=raw.method, source=raw.target,
            collection_warnings=warnings, virtualization=virt, ha=ha, interfaces=list(interfaces.values()),
            routes=routes, sections=sections,
            hardware=[Fact(key="Data collected from node", value=local)] if cl else [],
        )
        dev.management.dns_servers = dns
        dev.management.ntp_servers = ntp_servers
        dev.management.domain = ci.get("CsDomain")
        dev.management.timezone = ci.get("TimeZone")
        return dev


def _power(state: Any) -> str | None:
    s = str(state or "")
    if s.startswith("Running"):
        return "on"
    if s.startswith("Off"):
        return "off"
    if s.startswith(("Saved", "Paused")):
        return "suspended"
    return s.lower() or None


def _heartbeat(hb: Any) -> str | None:
    s = str(hb or "")
    if s.startswith("Ok"):
        return "running"
    if s in ("NoContact", "LostCommunication", "Error"):
        return "not running"
    return s or None


register(HyperVDriver())
