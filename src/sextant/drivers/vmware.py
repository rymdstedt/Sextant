"""VMware vCenter / ESXi driver (pyVmomi, read-only).

collect() walks the inventory with one container view per object type and
serialises everything into plain JSON-able dicts (``raw.outputs``):

    collected_at  ISO timestamp of the collection (snapshot ages are relative to it)
    about         vCenter/ESXi product info
    clusters      HA / DRS / EVC configuration
    hosts         hardware, state, NICs, NTP, services, VMkernel adapters
    vms           hardware, guest, tools, snapshot tree, storage
    datastores    capacity / free / backing / mounted hosts
    networks      {"vswitches": [...per host...], "dvswitches": [...]}
    licenses      edition, usage (key reduced to a 5 character hint)

parse() works only from that structure, so a JSON export (``from_file``) is
documented exactly like a live collection.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sextant.drivers import register
from sextant.drivers._util import as_list, bytes_to_gb, parse_dt, to_float, to_int
from sextant.drivers.base import Credentials, Driver, RawCollection, Target
from sextant.model import (
    Cluster,
    Datastore,
    Device,
    DeviceRole,
    Fact,
    HypervisorHost,
    Section,
    Table,
    Virtualization,
    VirtualMachine,
    VirtualNetwork,
)
from sextant.redact import redact_obj

OUTPUT_KEYS = ("about", "clusters", "hosts", "vms", "datastores", "networks", "licenses")


# =========================================================================== collection


def _iso(dt: Any) -> str | None:
    return dt.isoformat() if isinstance(dt, datetime) else None


def _g(obj: Any, path: str, default: Any = None) -> Any:
    """Safe dotted getattr: _g(host, 'summary.runtime.inMaintenanceMode')."""
    for part in path.split("."):
        if obj is None:
            return default
        try:
            obj = getattr(obj, part)
        except Exception:  # noqa: BLE001  (pyVmomi raises on missing privileges)
            return default
    return default if obj is None else obj


def _snap_tree(nodes: Any) -> list[dict[str, Any]]:
    return [{"name": s.name, "description": s.description or "", "create_time": _iso(s.createTime),
             "state": str(s.state), "quiesced": bool(s.quiesced),
             "children": _snap_tree(s.childSnapshotList)} for s in (nodes or [])]


def _vlan_text(vlan: Any) -> str:
    vid = _g(vlan, "vlanId")
    if isinstance(vid, int):
        return str(vid)
    ranges = [f"{r.start}-{r.end}" if r.start != r.end else str(r.start) for r in (vid or [])]
    return "trunk " + ",".join(ranges) if ranges else ""


def _collect_vsphere(si: Any, raw: RawCollection) -> None:  # pragma: no cover - needs a live vCenter
    from pyVmomi import vim

    content = si.RetrieveContent()
    about = content.about

    def view(kind: Any) -> list[Any]:
        v = content.viewManager.CreateContainerView(content.rootFolder, [kind], True)
        try:
            return list(v.view)
        finally:
            v.Destroy()

    fqdn = None
    try:
        fqdn = content.setting.QueryView("VirtualCenter.FQDN")[0].value
    except Exception:  # noqa: BLE001  (ESXi direct / no privilege)
        pass
    out = raw.outputs
    out["about"] = {"name": (fqdn or raw.target).split(".")[0], "fqdn": fqdn, "full_name": about.fullName,
                    "product_name": about.name, "version": about.version, "build": about.build,
                    "api_type": about.apiType, "api_version": about.apiVersion, "instance_uuid": about.instanceUuid}

    clusters = []
    for c in view(vim.ClusterComputeResource):
        das, drs = _g(c, "configurationEx.dasConfig"), _g(c, "configurationEx.drsConfig")
        dc = c.parent
        while dc is not None and not isinstance(dc, vim.Datacenter):
            dc = dc.parent
        clusters.append({
            "name": c.name, "datacenter": _g(dc, "name"), "hosts": [h.name for h in c.host],
            "ha_enabled": _g(das, "enabled"), "ha_admission_control": _g(das, "admissionControlEnabled"),
            "ha_host_monitoring": _g(das, "hostMonitoring"), "drs_enabled": _g(drs, "enabled"),
            "drs_behavior": str(_g(drs, "defaultVmBehavior", "")), "evc_mode": _g(c, "summary.currentEVCModeKey"),
            "vsan_enabled": _g(c, "configurationEx.vsanConfigInfo.enabled"),
            "total_cpu_mhz": _g(c, "summary.totalCpu"), "total_memory_bytes": _g(c, "summary.totalMemory"),
        })
    out["clusters"] = clusters

    hosts, vswitches = [], []
    for h in view(vim.HostSystem):
        hw, s, cfg = h.hardware, h.summary, h.config
        pnic_name = {p.key: p.device for p in _g(cfg, "network.pnic", [])}
        hosts.append({
            "name": h.name,
            "cluster": h.parent.name if isinstance(h.parent, vim.ClusterComputeResource) else None,
            "vendor": _g(hw, "systemInfo.vendor"), "model": _g(hw, "systemInfo.model"),
            "serial": _g(hw, "systemInfo.serialNumber"), "cpu_model": _g(s, "hardware.cpuModel"),
            "cpu_sockets": _g(hw, "cpuInfo.numCpuPackages"), "cpu_cores": _g(hw, "cpuInfo.numCpuCores"),
            "cpu_threads": _g(hw, "cpuInfo.numCpuThreads"), "cpu_mhz": _g(s, "hardware.cpuMhz"),
            "memory_bytes": _g(hw, "memorySize"), "cpu_usage_mhz": _g(s, "quickStats.overallCpuUsage"),
            "memory_usage_mb": _g(s, "quickStats.overallMemoryUsage"),
            "connection_state": str(_g(s, "runtime.connectionState", "")),
            "power_state": str(_g(s, "runtime.powerState", "")),
            "in_maintenance_mode": _g(s, "runtime.inMaintenanceMode"),
            "product": _g(cfg, "product.fullName"), "version": _g(cfg, "product.version"),
            "build": _g(cfg, "product.build"), "boot_time": _iso(_g(s, "runtime.bootTime")),
            "pnics": [{"device": p.device, "mac": p.mac, "driver": p.driver,
                       "speed_mb": _g(p, "linkSpeed.speedMb", 0)} for p in _g(cfg, "network.pnic", [])],
            "vmknics": [{"device": v.device, "portgroup": v.portgroup or _g(v, "spec.distributedVirtualPort.portgroupKey"),
                         "ip": _g(v, "spec.ip.ipAddress"), "netmask": _g(v, "spec.ip.subnetMask"),
                         "mtu": _g(v, "spec.mtu")} for v in _g(cfg, "network.vnic", [])],
            "ntp_servers": list(_g(cfg, "dateTimeInfo.ntpConfig.server", [])),
            "services": [{"key": sv.key, "label": sv.label, "running": sv.running, "policy": sv.policy}
                         for sv in _g(cfg, "service.service", [])],
        })
        pgs_by_sw: dict[str, list[dict[str, Any]]] = {}
        for pg in _g(cfg, "network.portgroup", []):
            team = _g(pg, "computedPolicy.nicTeaming.nicOrder")
            pgs_by_sw.setdefault(pg.spec.vswitchName, []).append({
                "name": pg.spec.name, "vlan": str(pg.spec.vlanId),
                "active": ",".join(_g(team, "activeNic", [])), "standby": ",".join(_g(team, "standbyNic", []))})
        for sw in _g(cfg, "network.vswitch", []):
            order = _g(sw, "spec.policy.nicTeaming.nicOrder")
            vswitches.append({
                "host": h.name, "name": sw.name, "mtu": sw.mtu, "num_ports": sw.numPorts,
                "uplinks": [pnic_name.get(k, k.rsplit("-", 1)[-1]) for k in (sw.pnic or [])],
                "teaming": _g(sw, "spec.policy.nicTeaming.policy"),
                "active": list(_g(order, "activeNic", [])), "standby": list(_g(order, "standbyNic", [])),
                "portgroups": pgs_by_sw.get(sw.name, [])})
    out["hosts"] = hosts

    vms = []
    for vm in view(vim.VirtualMachine):
        cfg, rt, g = vm.config, vm.runtime, vm.guest
        if cfg is None:
            raw.warnings.append(f"VM {vm.name}: config not accessible")
            continue
        disks = []
        for d in cfg.hardware.device:
            if isinstance(d, vim.vm.device.VirtualDisk):
                disks.append({"label": d.deviceInfo.label, "capacity_gb": round(d.capacityInKB / 1048576, 1),
                              "datastore": _g(d, "backing.datastore.name"), "file": _g(d, "backing.fileName"),
                              "thin": _g(d, "backing.thinProvisioned")})
        host = _g(rt, "host")
        vms.append({
            "name": vm.name, "power_state": str(rt.powerState), "template": cfg.template,
            "host": _g(host, "name"),
            "cluster": host.parent.name if host is not None and isinstance(host.parent, vim.ClusterComputeResource)
            else None,
            "guest_os": _g(g, "guestFullName") or cfg.guestFullName, "num_cpu": cfg.hardware.numCPU,
            "memory_mb": cfg.hardware.memoryMB, "hw_version": cfg.version, "disks": disks,
            "datastores": [ds.name for ds in vm.datastore], "networks": [n.name for n in vm.network],
            "ip_addresses": sorted({ip for n in (_g(g, "net", [])) for ip in (n.ipAddress or [])}),
            "hostname": _g(g, "hostName"), "tools_running_status": _g(g, "toolsRunningStatus"),
            "tools_version_status": _g(g, "toolsVersionStatus2"),
            "snapshots": _snap_tree(_g(vm, "snapshot.rootSnapshotList")),
            "committed_bytes": _g(vm, "summary.storage.committed"),
            "uncommitted_bytes": _g(vm, "summary.storage.uncommitted"),
            "ha_protected": _g(rt, "dasVmProtection.dasProtected"), "annotation": cfg.annotation or "",
        })
    out["vms"] = vms

    datastores = []
    for ds in view(vim.Datastore):
        s, info = ds.summary, ds.info
        backing = None
        if hasattr(info, "nas"):
            backing = f"{info.nas.remoteHost}:{info.nas.remotePath}"
        elif hasattr(info, "vmfs"):
            backing = ", ".join(e.diskName for e in info.vmfs.extent)
        datastores.append({"name": s.name, "type": s.type, "capacity": s.capacity, "free_space": s.freeSpace,
                           "uncommitted": s.uncommitted, "url": s.url, "accessible": s.accessible,
                           "multiple_host_access": s.multipleHostAccess, "backing": backing,
                           "vmfs_version": _g(info, "vmfs.version"), "hosts": [m.key.name for m in ds.host]})
    out["datastores"] = datastores

    dvswitches = []
    for dvs in view(vim.DistributedVirtualSwitch):
        dcfg = dvs.config
        pgs = []
        for pg in dvs.portgroup:
            pc = pg.config
            if _g(pc, "uplink"):
                continue
            order = _g(pc, "defaultPortConfig.uplinkTeamingPolicy.uplinkPortOrder")
            pgs.append({"name": pg.name, "vlan": _vlan_text(_g(pc, "defaultPortConfig.vlan")),
                        "teaming": _g(pc, "defaultPortConfig.uplinkTeamingPolicy.policy.value"),
                        "active": ",".join(_g(order, "activeUplinkPort", [])),
                        "standby": ",".join(_g(order, "standbyUplinkPort", [])),
                        "ports": pc.numPorts, "binding": pc.type})
        dvswitches.append({"name": dvs.name, "version": _g(dvs, "summary.productInfo.version"),
                           "mtu": _g(dcfg, "maxMtu"), "uplinks": list(_g(dcfg, "uplinkPortPolicy.uplinkPortName", [])),
                           "hosts": [m.config.host.name for m in _g(dcfg, "host", [])],
                           "lacp": [{"name": lg.name, "mode": lg.mode, "uplinks": lg.uplinkNum}
                                    for lg in _g(dcfg, "lacpGroupConfig", [])],
                           "portgroups": pgs})
    out["networks"] = {"vswitches": vswitches, "dvswitches": dvswitches}

    licenses = []
    for lic in _g(content, "licenseManager.licenses", []):
        if lic.editionKey == "eval":
            continue
        licenses.append({"name": lic.name, "edition": lic.editionKey, "total": lic.total, "used": lic.used,
                         "cost_unit": lic.costUnit, "key_hint": (lic.licenseKey or "")[-5:]})
    out["licenses"] = licenses


class VMwareDriver(Driver):
    id = "vmware"
    label = "VMware vCenter / ESXi"
    methods = ("api", "file")

    def collect(self, target: Target, creds: Credentials) -> RawCollection:  # pragma: no cover - live only
        from pyVim.connect import Disconnect, SmartConnect  # lazy: heavy and not needed offline

        raw = RawCollection(driver=self.id, target=target.name, method="api")
        raw.outputs["collected_at"] = datetime.now(UTC).isoformat()
        kwargs: dict[str, Any] = {"host": target.host or target.name, "user": creds.username,
                                  "pwd": creds.password, "port": target.port or 443}
        if not target.verify_tls:
            kwargs["disableSslCertValidation"] = True
        si = SmartConnect(**kwargs)
        try:
            _collect_vsphere(si, raw)
        finally:
            Disconnect(si)
        raw.outputs = redact_obj(raw.outputs)
        return raw

    def from_file(self, path: Path) -> RawCollection:
        """Load a JSON export: either the bare outputs dict or a full RawCollection dump."""
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, dict) and "outputs" in data and "driver" in data:
            data = data["outputs"]
        return RawCollection(driver=self.id, target=path.name, method="file",
                             outputs=redact_obj(data if isinstance(data, dict) else {}))

    # ----------------------------------------------------------------------- parse

    def parse(self, raw: RawCollection) -> Device:
        out = raw.outputs or {}
        warnings = list(raw.warnings)
        for key in OUTPUT_KEYS:
            if key not in out:
                warnings.append(f"vmware: '{key}' missing from collection")
        collected = parse_dt(out.get("collected_at"))
        ref = collected or datetime.now(UTC)
        about = out.get("about") if isinstance(out.get("about"), dict) else {}

        virt = Virtualization(platform="vmware")
        is_vc = about.get("api_type", "VirtualCenter") == "VirtualCenter"
        product = "vCenter Server" if is_vc else "ESXi"
        name = about.get("name") or raw.target
        if about.get("version"):
            virt.manager = f"{product} {about['version']} build {about.get('build', '?')} ({about.get('fqdn') or name})"

        for c in as_list(out.get("clusters")):
            if not isinstance(c, dict) or not c.get("name"):
                continue
            details = {}
            for k, label in (("datacenter", "Datacenter"), ("ha_admission_control", "HA admission control"),
                             ("ha_host_monitoring", "HA host monitoring"), ("vsan_enabled", "vSAN")):
                if c.get(k) is not None:
                    details[label] = str(c[k])
            if c.get("total_memory_bytes"):
                details["Total memory"] = f"{bytes_to_gb(c['total_memory_bytes'], 0):.0f} GB"
            virt.clusters.append(Cluster(
                name=c["name"], hosts=[str(h) for h in as_list(c.get("hosts"))],
                ha_enabled=c.get("ha_enabled"), drs_enabled=c.get("drs_enabled"),
                drs_level=_drs_level(c.get("drs_behavior")) if c.get("drs_enabled") else None,
                evc_mode=c.get("evc_mode") or None, details=details))

        vmk_rows, svc_rows = [], []
        for h in as_list(out.get("hosts")):
            if not isinstance(h, dict) or not h.get("name"):
                continue
            boot = parse_dt(h.get("boot_time"))
            mem_gb = bytes_to_gb(h.get("memory_bytes"))
            cpu_total = (to_float(h.get("cpu_mhz")) or 0) * (to_float(h.get("cpu_cores")) or 0)
            vmks = [v for v in as_list(h.get("vmknics")) if isinstance(v, dict)]
            for v in vmks:
                vmk_rows.append([h["name"], str(v.get("device", "")), str(v.get("portgroup", "")),
                                 f"{v.get('ip', '')}/{v.get('netmask', '')}", str(v.get("mtu", ""))])
            services = {}
            for sv in as_list(h.get("services")):
                if isinstance(sv, dict) and sv.get("key"):
                    label = sv.get("label") or sv["key"]
                    services[label] = ("running" if sv.get("running") else "stopped") + f" ({sv.get('policy', '?')})"
                    svc_rows.append([h["name"], label, services[label]])
            virt.hosts.append(HypervisorHost(
                name=h["name"], product=h.get("product"), build=h.get("build"),
                vendor_model=" ".join(x for x in (h.get("vendor"), h.get("model")) if x) or None,
                serial=h.get("serial"), cpu_model=h.get("cpu_model"), cpu_sockets=to_int(h.get("cpu_sockets")),
                cpu_cores=to_int(h.get("cpu_cores")), memory_gb=mem_gb,
                memory_used_gb=round(to_float(h["memory_usage_mb"]) / 1024, 1)
                if to_float(h.get("memory_usage_mb")) is not None else None,
                cpu_usage_pct=round(100 * to_float(h["cpu_usage_mhz"]) / cpu_total, 1)
                if cpu_total and to_float(h.get("cpu_usage_mhz")) is not None else None,
                state=_host_state(h), cluster=h.get("cluster"),
                mgmt_ip=next((v.get("ip") for v in vmks if v.get("device") == "vmk0"), None),
                uptime_days=round((ref - boot).total_seconds() / 86400, 1) if boot else None,
                nics=[_pnic_text(p) for p in as_list(h.get("pnics")) if isinstance(p, dict)],
                ntp_servers=[str(s) for s in as_list(h.get("ntp_servers"))], services=services))

        for vm in as_list(out.get("vms")):
            if not isinstance(vm, dict) or not vm.get("name"):
                continue
            if vm.get("template"):
                continue
            snaps = list(_flatten_snaps(vm.get("snapshots")))
            ages = [(ref - dt).days for _, dt in snaps if dt]
            disks = [d for d in as_list(vm.get("disks")) if isinstance(d, dict)]
            notes = (vm.get("annotation") or "").strip() or None
            virt.vms.append(VirtualMachine(
                name=vm["name"], power_state=_power(vm.get("power_state")), host=vm.get("host"),
                cluster=vm.get("cluster"), guest_os=vm.get("guest_os"), vcpus=to_int(vm.get("num_cpu")),
                memory_mb=to_int(vm.get("memory_mb")),
                disks_gb=[f for f in (to_float(d.get("capacity_gb")) for d in disks) if f is not None],
                datastores=[str(x) for x in as_list(vm.get("datastores"))],
                networks=[str(x) for x in as_list(vm.get("networks"))],
                ip_addresses=[str(x) for x in as_list(vm.get("ip_addresses"))],
                tools_status=_tools(vm.get("tools_running_status"), vm.get("tools_version_status"))
                if _power(vm.get("power_state")) == "on" else None,
                snapshots=[f"{n} ({dt.date().isoformat()})" if dt else n for n, dt in snaps],
                oldest_snapshot_days=max(ages) if ages else None, hw_version=vm.get("hw_version"),
                ha_protected=vm.get("ha_protected"), notes=notes))

        for ds in as_list(out.get("datastores")):
            if not isinstance(ds, dict) or not ds.get("name"):
                continue
            hosts = [str(x) for x in as_list(ds.get("hosts"))]
            kind = str(ds.get("type") or "") or None
            if kind and kind.upper().startswith("NFS"):
                kind = "NFS"
            virt.datastores.append(Datastore(
                name=ds["name"], kind=kind, capacity_gb=bytes_to_gb(ds.get("capacity")),
                free_gb=bytes_to_gb(ds.get("free_space")), hosts=hosts, backing=ds.get("backing"),
                shared=ds.get("multiple_host_access") if ds.get("multiple_host_access") is not None
                else (len(hosts) > 1 if hosts else None)))

        nets = out.get("networks") if isinstance(out.get("networks"), dict) else {}
        for sw in as_list(nets.get("vswitches")):
            if not isinstance(sw, dict) or not sw.get("name"):
                continue
            teaming = sw.get("teaming")
            if sw.get("active") or sw.get("standby"):
                teaming = f"{teaming or '?'}; active {','.join(as_list(sw.get('active'))) or '-'}; " \
                          f"standby {','.join(as_list(sw.get('standby'))) or '-'}"
            virt.networks.append(VirtualNetwork(
                name=sw["name"], kind="standard", host=sw.get("host"),
                uplinks=[str(u) for u in as_list(sw.get("uplinks"))], mtu=to_int(sw.get("mtu")),
                port_groups=_pgs(sw.get("portgroups")), teaming=teaming))
        for dvs in as_list(nets.get("dvswitches")):
            if not isinstance(dvs, dict) or not dvs.get("name"):
                continue
            lacp = [f"{lg.get('name')} ({lg.get('mode')}, {lg.get('uplinks')} uplinks)"
                    for lg in as_list(dvs.get("lacp")) if isinstance(lg, dict)]
            virt.networks.append(VirtualNetwork(
                name=dvs["name"], kind="distributed",
                uplinks=[str(u) for u in as_list(dvs.get("uplinks"))], mtu=to_int(dvs.get("mtu")),
                port_groups=_pgs(dvs.get("portgroups")),
                teaming=("LACP " + "; ".join(lacp)) if lacp else None))

        lic_rows = []
        for lic in as_list(out.get("licenses")):
            if not isinstance(lic, dict) or not lic.get("name"):
                continue
            unit = str(lic.get("cost_unit") or "").replace("cpuPackage", "CPUs").replace("cpuCore", "cores")
            virt.licenses.append(f"{lic['name']} ({lic.get('used', '?')}/{lic.get('total', '?')} {unit})".strip())
            lic_rows.append([str(lic["name"]), str(lic.get("edition", "")), str(lic.get("used", "")),
                             str(lic.get("total", "")), unit, f"*****{lic.get('key_hint', '')}"])

        sections = []
        if lic_rows:
            sections.append(Section(id="vmware-licenses", title="vSphere licenses", tables=[
                Table(columns=["License", "Edition", "Used", "Total", "Unit", "Key"], rows=lic_rows)]))
        if vmk_rows:
            sections.append(Section(id="vmware-vmkernel", title="VMkernel adapters", tables=[
                Table(columns=["Host", "Adapter", "Port group", "IP / mask", "MTU"], rows=vmk_rows)]))
        if svc_rows:
            sections.append(Section(id="vmware-host-services", title="ESXi host services", tables=[
                Table(columns=["Host", "Service", "State (policy)"], rows=svc_rows)]))
        powered_on = sum(1 for v in virt.vms if v.power_state == "on")
        cap = sum(d.capacity_gb or 0 for d in virt.datastores)
        free = sum(d.free_gb or 0 for d in virt.datastores)
        sections.insert(0, Section(id="vmware-overview", title="vSphere overview", summary_relevant=True, facts=[
            Fact(key="Clusters", value=str(len(virt.clusters))),
            Fact(key="Hosts", value=f"{len(virt.hosts)} ({sum(1 for h in virt.hosts if h.state == 'maintenance')}"
                                    " in maintenance)"),
            Fact(key="VMs", value=f"{len(virt.vms)} ({powered_on} powered on)"),
            Fact(key="Datastore capacity", value=f"{cap:,.0f} GB ({cap - free:,.0f} GB used)"),
        ]))

        return Device(
            hostname=name, role=DeviceRole.hypervisor, vendor="VMware", platform=self.id,
            model=product, os_name=about.get("product_name") or f"VMware {product}",
            os_version=about.get("version"), licenses=list(virt.licenses),
            hardware=[Fact(key="Build", value=str(about["build"]))] if about.get("build") else [],
            collected_at=collected or datetime.now(UTC), collection_method=raw.method,
            source=raw.target, collection_warnings=warnings, virtualization=virt, sections=sections,
        )


# =========================================================================== parse helpers


def _drs_level(behavior: Any) -> str | None:
    return {"fullyAutomated": "fully automated", "partiallyAutomated": "partially automated",
            "manual": "manual"}.get(str(behavior), str(behavior) if behavior else None)


def _host_state(h: dict[str, Any]) -> str:
    if h.get("in_maintenance_mode"):
        return "maintenance"
    cs = str(h.get("connection_state") or "").lower()
    if cs in ("disconnected", "notresponding"):
        return "disconnected"
    if str(h.get("power_state") or "").lower() in ("poweredoff", "standby"):
        return "powered off"
    return "connected" if cs in ("connected", "") else cs


def _pnic_text(p: dict[str, Any]) -> str:
    speed = to_int(p.get("speed_mb")) or 0
    return f"{p.get('device', '?')} {speed} Mb up" if speed else f"{p.get('device', '?')} down"


def _power(state: Any) -> str | None:
    return {"poweredOn": "on", "poweredOff": "off", "suspended": "suspended"}.get(str(state), state or None)


def _tools(running: Any, version: Any) -> str | None:
    if not running:
        return None
    text = {"guestToolsRunning": "running", "guestToolsNotRunning": "not running",
            "guestToolsExecutingScripts": "starting"}.get(str(running), str(running))
    if version and version not in ("guestToolsCurrent", "guestToolsSupportedNew"):
        text += f" ({str(version).replace('guestTools', '').lower()})"
    return text


def _flatten_snaps(nodes: Any):
    for s in as_list(nodes):
        if isinstance(s, dict):
            yield str(s.get("name", "?")), parse_dt(s.get("create_time"))
            yield from _flatten_snaps(s.get("children"))


def _pgs(items: Any) -> list[dict[str, str]]:
    out = []
    for pg in as_list(items):
        if isinstance(pg, dict) and pg.get("name"):
            out.append({k: str(pg.get(k, "") if pg.get(k) is not None else "")
                        for k in ("name", "vlan", "active", "standby")})
    return out


register(VMwareDriver())
