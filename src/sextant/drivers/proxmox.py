"""Proxmox VE driver (REST API with an API token, GET only).

Credentials: ``username`` is the token id ``user@realm!tokenid`` (for example
``sextant@pve!asbuilt``) and ``api_token`` is the token secret (UUID). The token
needs only the ``PVEAuditor`` role on ``/``. Header sent:
``Authorization: PVEAPIToken=<user@realm!tokenid>=<secret>``.

``raw.outputs`` is keyed by API path (without ``/api2/json``), the value being
the response's ``data`` member, e.g. ``outputs["/nodes/pve01/qemu/101/config"]``.
"""

from __future__ import annotations

import json
import re
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
    HighAvailability,
    HypervisorHost,
    Section,
    Table,
    Virtualization,
    VirtualMachine,
    VirtualNetwork,
)
from sextant.redact import redact_obj

_OSTYPE = {"win11": "Windows 11 / Server 2022 / 2025", "win10": "Windows 10 / Server 2016 / 2019",
           "win8": "Windows 8 / Server 2012", "win7": "Windows 7 / Server 2008 R2", "l26": "Linux (kernel 2.6+)",
           "l24": "Linux (kernel 2.4)", "solaris": "Solaris", "other": "Other"}
_DISK_KEY = re.compile(r"^(scsi|virtio|sata|ide|efidisk|tpmstate)\d+$|^(rootfs|mp\d+)$")
_NET_KEY = re.compile(r"^net\d+$")


class ProxmoxDriver(Driver):
    id = "proxmox"
    label = "Proxmox VE"
    methods = ("api", "file")

    def collect(self, target: Target, creds: Credentials) -> RawCollection:  # pragma: no cover - live only
        import requests  # lazy

        raw = RawCollection(driver=self.id, target=target.name, method="api")
        base = f"https://{target.host or target.name}:{target.port or 8006}/api2/json"
        sess = requests.Session()
        sess.verify = target.verify_tls
        sess.headers["Authorization"] = f"PVEAPIToken={creds.username}={creds.api_token}"
        timeout = int(target.options.get("timeout", 30))

        def get(path: str) -> Any:
            try:
                r = sess.get(base + path, timeout=timeout)  # GET only: read-only by construction
                r.raise_for_status()
                data = r.json().get("data")
                raw.outputs[path] = data
                return data
            except Exception as exc:  # noqa: BLE001
                raw.warnings.append(f"GET {path}: {exc.__class__.__name__}: {exc}")
                return None

        raw.outputs["collected_at"] = datetime.now(UTC).isoformat()
        for path in ("/version", "/cluster/status", "/cluster/resources", "/cluster/backup",
                     "/cluster/ha/resources", "/cluster/ha/status/current"):
            get(path)
        for node in as_list(get("/nodes")):
            n = node.get("node") if isinstance(node, dict) else None
            if not n:
                continue
            if node.get("status") not in (None, "online"):
                raw.warnings.append(f"node {n} is {node.get('status')}: per-node data skipped")
                continue
            for sub in ("status", "network", "storage"):
                get(f"/nodes/{n}/{sub}")
            for vm in as_list(get(f"/nodes/{n}/qemu")):
                vmid = vm.get("vmid") if isinstance(vm, dict) else None
                if vmid is not None:
                    get(f"/nodes/{n}/qemu/{vmid}/config")
                    get(f"/nodes/{n}/qemu/{vmid}/snapshot")
            for ct in as_list(get(f"/nodes/{n}/lxc")):
                vmid = ct.get("vmid") if isinstance(ct, dict) else None
                if vmid is not None:
                    get(f"/nodes/{n}/lxc/{vmid}/config")
        raw.outputs = redact_obj(raw.outputs)
        return raw

    def from_file(self, path: Path) -> RawCollection:
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, dict) and "outputs" in data and "driver" in data:
            data = data["outputs"]
        return RawCollection(driver=self.id, target=path.name, method="file",
                             outputs=redact_obj(data if isinstance(data, dict) else {}))

    # ----------------------------------------------------------------------- parse

    def parse(self, raw: RawCollection) -> Device:
        out = raw.outputs or {}
        warnings = list(raw.warnings)
        collected = parse_dt(out.get("collected_at"))
        ref = collected or datetime.now(UTC)
        for key in ("/version", "/cluster/status", "/nodes"):
            if key not in out:
                warnings.append(f"proxmox: '{key}' missing from collection")

        version = out.get("/version") if isinstance(out.get("/version"), dict) else {}
        status = [x for x in as_list(out.get("/cluster/status")) if isinstance(x, dict)]
        cl = next((x for x in status if x.get("type") == "cluster"), None)
        node_status = {x.get("name"): x for x in status if x.get("type") == "node"}
        nodes = [x for x in as_list(out.get("/nodes")) if isinstance(x, dict) and x.get("node")]
        node_names = [x["node"] for x in nodes] or sorted(k for k in node_status if k)
        if not node_names:  # derive from per-node keys when /nodes is missing
            node_names = sorted({m.group(1) for k in out if (m := re.match(r"^/nodes/([^/]+)/", str(k)))})
        hostname = (cl or {}).get("name") or (node_names[0] if node_names else raw.target)
        cluster_name = (cl or {}).get("name")

        virt = Virtualization(platform="proxmox")
        pve_ver = version.get("version")
        virt.manager = f"Proxmox VE {pve_ver}" + (f" (cluster {cluster_name})" if cluster_name else "") \
            if pve_ver else None

        # HA
        ha_res = [x for x in as_list(out.get("/cluster/ha/resources")) if isinstance(x, dict)]
        ha_cur = [x for x in as_list(out.get("/cluster/ha/status/current")) if isinstance(x, dict)]
        ha_sids = {str(x.get("sid")) for x in ha_res}
        quorum = next((x for x in ha_cur if x.get("type") == "quorum" or x.get("id") == "quorum"), None)
        master = next((x for x in ha_cur if x.get("type") == "master" or x.get("id") == "master"), None)

        if cl:
            details = {"Config version": str(cl.get("version", "")), "Nodes": str(cl.get("nodes", ""))}
            if master:
                details["HA manager"] = f"{master.get('node', '?')} ({master.get('status', '?')})"
            details["HA resources"] = str(len(ha_res))
            virt.clusters.append(Cluster(
                name=cluster_name, hosts=node_names, ha_enabled=bool(ha_res), drs_enabled=None,
                quorum=("quorate" if to_int(cl.get("quorate")) else "NOT quorate")
                if cl.get("quorate") is not None else None, details=details))

        # resources (fallback/extra info: HA state, tags, lists for offline nodes)
        res = [x for x in as_list(out.get("/cluster/resources")) if isinstance(x, dict)]

        # nodes
        for name in node_names:
            st = out.get(f"/nodes/{name}/status") if isinstance(out.get(f"/nodes/{name}/status"), dict) else {}
            nd = next((x for x in nodes if x["node"] == name), {})
            cpu = st.get("cpuinfo") if isinstance(st.get("cpuinfo"), dict) else {}
            mem = st.get("memory") if isinstance(st.get("memory"), dict) else {}
            online = nd.get("status", "online" if to_int(node_status.get(name, {}).get("online")) else None)
            netcfg = [x for x in as_list(out.get(f"/nodes/{name}/network")) if isinstance(x, dict)]
            nics = [f"{x.get('iface')} {'up' if x.get('active') else 'down'}" for x in netcfg
                    if x.get("type") == "eth"]
            uptime = to_float(st.get("uptime") or nd.get("uptime"))
            cpu_pct = to_float(st.get("cpu") if st.get("cpu") is not None else nd.get("cpu"))
            virt.hosts.append(HypervisorHost(
                name=name, product=f"Proxmox VE {_pve_short(st.get('pveversion')) or pve_ver or ''}".strip(),
                build=_kernel(st),
                cpu_model=cpu.get("model"), cpu_sockets=to_int(cpu.get("sockets")),
                cpu_cores=(to_int(cpu.get("cores")) or 0) * (to_int(cpu.get("sockets")) or 1) or None,
                memory_gb=bytes_to_gb(mem.get("total") or nd.get("maxmem")),
                memory_used_gb=bytes_to_gb(mem.get("used") or nd.get("mem")),
                cpu_usage_pct=round(cpu_pct * 100, 1) if cpu_pct is not None else None,
                state="connected" if online == "online" else (online or None), cluster=cluster_name,
                mgmt_ip=node_status.get(name, {}).get("ip"),
                uptime_days=round(uptime / 86400, 1) if uptime else None, nics=nics))

            # networks: bridges + bonds
            for x in netcfg:
                kind = x.get("type")
                if kind not in ("bridge", "OVSBridge", "bond", "OVSBond"):
                    continue
                ports = str(x.get("bridge_ports") or x.get("slaves") or x.get("ovs_ports") or "").split()
                if kind in ("bridge", "OVSBridge"):
                    aware = bool(to_int(x.get("bridge_vlan_aware")))
                    pg = [{"name": "untagged" if not aware else "VLAN-aware",
                           "vlan": str(x.get("bridge_vids") or "2-4094") if aware else "none",
                           "active": " ".join(ports), "standby": ""}]
                    teaming = f"VLAN-aware (vids {x.get('bridge_vids') or '2-4094'})" if aware else "not VLAN-aware"
                    if x.get("cidr") or x.get("address"):
                        teaming += f"; IP {x.get('cidr') or x.get('address')}"
                    if x.get("gateway"):
                        teaming += f" gw {x['gateway']}"
                    virt.networks.append(VirtualNetwork(
                        name=x.get("iface", "?"), kind="bridge", host=name, uplinks=ports,
                        mtu=to_int(x.get("mtu")), port_groups=pg, teaming=teaming))
                else:
                    mode = x.get("bond_mode") or "?"
                    if x.get("bond_xmit_hash_policy"):
                        mode += f", hash {x['bond_xmit_hash_policy']}"
                    virt.networks.append(VirtualNetwork(
                        name=x.get("iface", "?"), kind="bond", host=name, uplinks=ports,
                        mtu=to_int(x.get("mtu")), teaming=mode))

        # storage: per storage id, merged across nodes
        stores: dict[str, Datastore] = {}
        for name in node_names:
            for s in as_list(out.get(f"/nodes/{name}/storage")):
                if not isinstance(s, dict) or not s.get("storage"):
                    continue
                sid = s["storage"]
                shared = bool(to_int(s.get("shared")))
                key = sid if shared else f"{sid}@{name}"
                ds = stores.get(key)
                if ds is None:
                    ds = stores[key] = Datastore(
                        name=sid if shared else f"{sid} ({name})", kind=_storage_kind(s.get("type")),
                        capacity_gb=bytes_to_gb(s.get("total")), free_gb=bytes_to_gb(s.get("avail")),
                        shared=shared, backing=f"{s.get('type', '?')}; content {s.get('content', '')}")
                ds.hosts.append(name)
        if not stores:  # fallback: /cluster/resources storage entries
            for s in res:
                if s.get("type") == "storage" and s.get("storage"):
                    shared = bool(to_int(s.get("shared")))
                    key = s["storage"] if shared else f"{s['storage']}@{s.get('node')}"
                    ds = stores.setdefault(key, Datastore(
                        name=s["storage"] if shared else f"{s['storage']} ({s.get('node')})",
                        kind=_storage_kind(s.get("plugintype")), capacity_gb=bytes_to_gb(s.get("maxdisk")),
                        free_gb=round(bytes_to_gb(s.get("maxdisk")) - bytes_to_gb(s.get("disk")), 1)
                        if s.get("maxdisk") and s.get("disk") is not None else None, shared=shared))
                    ds.hosts.append(str(s.get("node")))
        virt.datastores = list(stores.values())

        # backup jobs
        jobs = [x for x in as_list(out.get("/cluster/backup")) if isinstance(x, dict)]

        def backup_for(vmid: int) -> str | None:
            hits = []
            for j in jobs:
                if not _enabled(j):
                    continue
                ids = {to_int(v) for v in str(j.get("vmid") or "").split(",") if v.strip()}
                excluded = {to_int(v) for v in str(j.get("exclude") or "").split(",") if v.strip()}
                if (to_int(j.get("all")) and vmid not in excluded) or vmid in ids:
                    hits.append(f"{j.get('id', 'job')}: {j.get('schedule', '?')} -> {j.get('storage', '?')}")
            return "; ".join(hits) or None

        # guests
        res_by_id = {to_int(x.get("vmid")): x for x in res if x.get("type") in ("qemu", "lxc")}
        seen: set[int] = set()
        for name in node_names:
            for kind in ("qemu", "lxc"):
                for g in as_list(out.get(f"/nodes/{name}/{kind}")):
                    if not isinstance(g, dict) or to_int(g.get("vmid")) is None:
                        continue
                    vmid = to_int(g["vmid"])
                    if to_int(g.get("template")):
                        continue
                    seen.add(vmid)
                    cfg = out.get(f"/nodes/{name}/{kind}/{vmid}/config")
                    snaps = out.get(f"/nodes/{name}/{kind}/{vmid}/snapshot")
                    virt.vms.append(_guest(kind, vmid, name, cluster_name, g, cfg if isinstance(cfg, dict) else {},
                                           snaps, res_by_id.get(vmid, {}), ha_sids, backup_for(vmid), ref))
        for vmid, r in res_by_id.items():  # guests on nodes without per-node data
            if vmid is not None and vmid not in seen and not to_int(r.get("template")):
                virt.vms.append(_guest(r.get("type", "qemu"), vmid, r.get("node"), cluster_name, r, {}, None, r,
                                       ha_sids, backup_for(vmid), ref))

        virt.vms.sort(key=lambda v: (v.tags[0] if v.tags else "", v.name))
        _annotate_bridges(virt, out, node_names)

        # sections
        sections: list[Section] = []
        if jobs:
            rows = [[str(j.get("id", "")), "yes" if _enabled(j) else "no", str(j.get("schedule", "")),
                     str(j.get("storage", "")), "all" + (f" except {j['exclude']}" if j.get("exclude") else "")
                     if to_int(j.get("all")) else str(j.get("vmid") or j.get("pool") or ""),
                     str(j.get("mode", "")), str(j.get("compress", "")), _prune(j.get("prune-backups")),
                     str(j.get("notes-template", "") or j.get("comment", ""))] for j in jobs]
            sections.append(Section(id="proxmox-backup", title="Backup jobs", summary_relevant=True, tables=[
                Table(columns=["Job", "Enabled", "Schedule", "Storage", "Guests", "Mode", "Compress",
                               "Retention", "Notes"], rows=rows)]))
        if ha_res:
            state = {str(x.get("sid")): x for x in ha_cur if x.get("sid")}
            rows = [[str(r.get("sid", "")), str(r.get("state", "")), str(r.get("group", "")),
                     str(state.get(str(r.get("sid")), {}).get("node", "")),
                     str(state.get(str(r.get("sid")), {}).get("state", "")),
                     str(r.get("max_restart", "")), str(r.get("max_relocate", ""))] for r in ha_res]
            sections.append(Section(id="proxmox-ha", title="HA resources", tables=[
                Table(columns=["Resource", "Requested", "Group", "Node", "Current", "Max restart", "Max relocate"],
                      rows=rows)]))
        if ha_cur:
            sections.append(Section(id="proxmox-ha-status", title="HA manager status", facts=[
                Fact(key=str(x.get("id", "?")), value=f"{x.get('node', '')} {x.get('status', '')}".strip())
                for x in ha_cur if not x.get("sid")]))
        if status:
            rows = [[str(x.get("name", "")), str(x.get("nodeid", "")), str(x.get("ip", "")),
                     "online" if to_int(x.get("online")) else "offline", "yes" if to_int(x.get("local")) else ""]
                    for x in status if x.get("type") == "node"]
            if rows:
                sections.append(Section(id="proxmox-corosync", title="Cluster membership", tables=[
                    Table(columns=["Node", "Node ID", "Ring address", "State", "Queried"], rows=rows)]))

        ha = None
        if cl:
            ha = HighAvailability(mode="cluster", group=cluster_name, members=node_names,
                                  state=(quorum or {}).get("status") or
                                  ("quorate" if to_int(cl.get("quorate")) else "not quorate"),
                                  details={"HA resources": str(len(ha_res))})
        first = node_status.get(node_names[0], {}) if node_names else {}
        return Device(
            hostname=hostname, role=DeviceRole.hypervisor, vendor="Proxmox", platform=self.id,
            model="Proxmox VE cluster" if cl else "Proxmox VE", os_name="Proxmox VE", os_version=pve_ver,
            mgmt_ip=first.get("ip"), collected_at=collected or datetime.now(UTC),
            collection_method=raw.method, source=raw.target, collection_warnings=warnings,
            hardware=[Fact(key="Release", value=f"{version.get('release', '')} (repoid {version.get('repoid', '')})")]
            if version.get("release") else [],
            virtualization=virt, ha=ha, sections=sections,
        )


# =========================================================================== helpers


def _annotate_bridges(virt: Virtualization, out: dict[str, Any], node_names: list[str]) -> None:
    """Add the VLAN tags guests actually use (cluster wide) and host VLAN interfaces to each bridge."""
    used: dict[str, set[int]] = {}
    for vm in virt.vms:
        for net in vm.networks:
            br, _, tag = net.partition(" VLAN ")
            if tag.isdigit():
                used.setdefault(br, set()).add(int(tag))
    for name in node_names:
        for x in as_list(out.get(f"/nodes/{name}/network")):
            if isinstance(x, dict) and x.get("type") == "vlan" and (x.get("cidr") or x.get("address")):
                dev = x.get("vlan-raw-device") or str(x.get("iface", "")).split(".")[0]
                for n in virt.networks:
                    if n.host == name and n.name == dev:
                        n.teaming = f"{n.teaming}; host IP {x.get('cidr') or x.get('address')} on {x.get('iface')}" + \
                                    (f" gw {x['gateway']}" if x.get("gateway") else "")
    for n in virt.networks:
        if n.kind == "bridge":
            for tag in sorted(used.get(n.name, ())):
                n.port_groups.append({"name": f"VLAN {tag} (in use)", "vlan": str(tag),
                                      "active": " ".join(n.uplinks), "standby": ""})


def _enabled(job: dict[str, Any]) -> bool:
    return job.get("enabled") in (None, 1, "1", True)


def _pve_short(v: Any) -> str | None:
    m = re.search(r"pve-manager/(\S+?)/", str(v or ""))
    return m.group(1) if m else None


def _kernel(st: dict[str, Any]) -> str | None:
    ck = st.get("current-kernel")
    if isinstance(ck, dict) and ck.get("release"):
        return f"kernel {ck['release']}"
    parts = str(st.get("kversion") or "").split()
    return f"kernel {parts[1]}" if len(parts) > 1 else None


def _storage_kind(t: Any) -> str | None:
    return {"zfspool": "ZFS", "zfs": "ZFS", "rbd": "Ceph RBD", "cephfs": "CephFS", "nfs": "NFS", "cifs": "SMB",
            "lvmthin": "LVM-thin", "lvm": "LVM", "dir": "Directory", "pbs": "PBS", "iscsi": "iSCSI",
            "btrfs": "Btrfs", "esxi": "ESXi import"}.get(str(t), str(t) if t else None)


def _size_gb(text: str) -> float | None:
    m = re.search(r"(?:^|,)size=(\d+(?:\.\d+)?)([KMGT])?", text)
    if not m:
        return None
    return round(float(m.group(1)) * {"K": 1 / 1024**2, "M": 1 / 1024, "G": 1, "T": 1024, None: 1 / 1024**3}[m.group(2)], 1)


def _prune(p: Any) -> str:
    if isinstance(p, dict):
        return ", ".join(f"{k.replace('keep-', '')}={v}" for k, v in p.items())
    return str(p or "").replace("keep-", "")


def _guest(kind: str, vmid: int, node: Any, cluster: str | None, listing: dict[str, Any], cfg: dict[str, Any],
           snaps: Any, res: dict[str, Any], ha_sids: set[str], backup: str | None, ref: datetime) -> VirtualMachine:
    disks, stores = [], []
    for k, v in cfg.items():
        if _DISK_KEY.match(str(k)) and isinstance(v, str) and "media=cdrom" not in v:
            size = _size_gb(v)
            if size is not None and not k.startswith(("efidisk", "tpmstate")):
                disks.append(size)
            st = v.split(":", 1)[0] if ":" in v else None
            if st and st not in stores:
                stores.append(st)
    if not disks and (listing.get("maxdisk") or res.get("maxdisk")):
        disks.append(bytes_to_gb(listing.get("maxdisk") or res.get("maxdisk")) or 0.0)
    nets, ips = [], []
    for k, v in sorted(cfg.items()):
        if _NET_KEY.match(str(k)) and isinstance(v, str):
            opts = dict(p.split("=", 1) for p in v.split(",") if "=" in p)
            net = opts.get("bridge", "?") + (f" VLAN {opts['tag']}" if opts.get("tag") else "")
            nets.append(net)
            ip = opts.get("ip")
            if ip and ip not in ("dhcp", "manual"):
                ips.append(ip)
    for k, v in cfg.items():  # cloud-init ipconfigN
        if str(k).startswith("ipconfig") and isinstance(v, str):
            ip = dict(p.split("=", 1) for p in v.split(",") if "=" in p).get("ip")
            if ip and ip != "dhcp":
                ips.append(ip)
    snap_list, ages = [], []
    for s in as_list(snaps):
        if isinstance(s, dict) and s.get("name") and s.get("name") != "current":
            dt = parse_dt(s.get("snaptime"))
            snap_list.append(f"{s['name']} ({dt.date().isoformat()})" if dt else str(s["name"]))
            if dt:
                ages.append((ref - dt).days)
    cores = to_int(cfg.get("cores")) or 0
    vcpus = cores * (to_int(cfg.get("sockets")) or 1) if cores else to_int(listing.get("cpus") or res.get("maxcpu"))
    mem = to_int(cfg.get("memory"))
    if mem is None and (listing.get("maxmem") or res.get("maxmem")):
        mem = int((to_float(listing.get("maxmem") or res.get("maxmem")) or 0) / 1024**2)
    sid = f"{'vm' if kind == 'qemu' else 'ct'}:{vmid}"
    agent = str(cfg.get("agent", ""))
    tags = [t for t in re.split(r"[;, ]+", str(cfg.get("tags") or listing.get("tags") or res.get("tags") or "")) if t]
    status = listing.get("status") or res.get("status")
    name = cfg.get("name") or cfg.get("hostname") or listing.get("name") or res.get("name") or f"{kind}-{vmid}"
    return VirtualMachine(
        name=str(name), power_state={"running": "on", "stopped": "off", "paused": "suspended"}.get(
            str(status), str(status) if status else None),
        host=str(node) if node else None, cluster=cluster,
        guest_os=("LXC " + str(cfg.get("ostype") or "")).strip() if kind == "lxc"
        else (_OSTYPE.get(str(cfg.get("ostype")), cfg.get("ostype")) or None),
        vcpus=vcpus, memory_mb=mem, disks_gb=disks, datastores=stores, networks=nets, ip_addresses=ips,
        tools_status=None if kind == "lxc" else ("qemu-guest-agent enabled" if agent.startswith(("1", "enabled=1"))
                                                 else "qemu-guest-agent disabled"),
        snapshots=snap_list, oldest_snapshot_days=max(ages) if ages else None,
        hw_version=f"{kind} {cfg.get('machine', '')}".strip() if kind == "qemu" else "lxc",
        ha_protected=sid in ha_sids, backup=backup,
        notes=(str(cfg.get("description")).strip() or None) if cfg.get("description") else None,
        tags=[f"vmid:{vmid}", *tags])


register(ProxmoxDriver())
