# collect-hyperv.ps1 - read-only Hyper-V / Failover Cluster inventory for hsdoc (Hybrid As-Built).
# Uses Get-* cmdlets only; changes nothing. Prints ONE JSON object on stdout.
# Run on a Hyper-V host or cluster node (Hyper-V Administrators or local admin, read access suffices):
#   powershell -NoProfile -ExecutionPolicy Bypass -File .\collect-hyperv.ps1 > hyperv-inventory.json
# then import the file with:  hsdoc import --driver hyperv hyperv-inventory.json
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
