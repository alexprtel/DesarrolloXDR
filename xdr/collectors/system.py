"""Sensores de sistema: cuentas de usuario, kernel/rootkits, dispositivos USB
y montajes, y consumo de recursos (criptominería)."""
from __future__ import annotations

import os
import time
from typing import Any

import psutil

from xdr.collectors.base import Collector
from xdr.events import Event
from xdr.utils import IS_LINUX, read_text

PRIV_GROUPS = {"sudo", "wheel", "admin", "root", "docker", "lxd", "adm", "shadow", "disk",
               "Administrators"}


# --------------------------------------------------------------------------- cuentas
class AccountCollector(Collector):
    name = "accounts"
    default_interval = 30.0

    def setup(self) -> None:
        self.ns = "accounts"
        self.baseline = self.storage.baseline_load(self.ns)
        self.initialized = self.storage.baseline_exists(self.ns)
        self.sessions: set[tuple] = {self._skey(u) for u in psutil.users()}

    @staticmethod
    def _skey(u: Any) -> tuple:
        return (u.name, u.terminal or "", u.host or "", round(u.started or 0))

    def _snapshot(self) -> dict[str, dict]:
        users: dict[str, dict] = {}
        passwd = read_text("/etc/passwd") or ""
        for line in passwd.splitlines():
            parts = line.split(":")
            if len(parts) < 7:
                continue
            users[f"user:{parts[0]}"] = {"name": parts[0], "uid": int(parts[2] or -1),
                                         "gid": int(parts[3] or -1), "home": parts[5],
                                         "shell": parts[6]}
        shadow = read_text("/etc/shadow") or ""
        for line in shadow.splitlines():
            parts = line.split(":")
            if len(parts) > 1 and f"user:{parts[0]}" in users:
                users[f"user:{parts[0]}"]["empty_password"] = parts[1] == ""
        group = read_text("/etc/group") or ""
        for line in group.splitlines():
            parts = line.split(":")
            if len(parts) < 4 or parts[0] not in PRIV_GROUPS:
                continue
            members = sorted(m for m in parts[3].split(",") if m)
            users[f"group:{parts[0]}"] = {"name": parts[0], "members": members}
        return users

    def collect(self) -> list[Event]:
        events: list[Event] = []
        # Sesiones interactivas
        now_sessions = {self._skey(u) for u in psutil.users()}
        for name, term, host, started in now_sessions - self.sessions:
            events.append(self.event("auth", "session_start", user=name, terminal=term,
                                     src_ip=host, started=started))
        for name, term, host, started in self.sessions - now_sessions:
            events.append(self.event("auth", "session_end", user=name, terminal=term, src_ip=host))
        self.sessions = now_sessions

        if not IS_LINUX:
            return events
        snap = self._snapshot()
        if not self.initialized:
            for key, item in snap.items():
                if key.startswith("user:") and item["uid"] == 0 and item["name"] != "root":
                    events.append(self.event("account", "uid0_user", initial=True, **item))
                if key.startswith("user:") and item.get("empty_password"):
                    events.append(self.event("account", "empty_password", initial=True, **item))
            self.storage.baseline_update(self.ns, snap)
            self.baseline, self.initialized = snap, True
            return events
        for key, item in snap.items():
            prev = self.baseline.get(key)
            if key.startswith("user:"):
                if prev is None:
                    events.append(self.event("account", "created", **item))
                    if item["uid"] == 0:
                        events.append(self.event("account", "uid0_user", **item))
                elif prev != item:
                    changes = {k: [prev.get(k), v] for k, v in item.items() if prev.get(k) != v}
                    events.append(self.event("account", "modified", changes=changes, **item))
                    if item["uid"] == 0 and prev.get("uid") != 0:
                        events.append(self.event("account", "uid0_user", **item))
                if item.get("empty_password") and not (prev or {}).get("empty_password"):
                    events.append(self.event("account", "empty_password", **item))
            else:
                old_members = set((prev or {}).get("members", []))
                for member in set(item["members"]) - old_members:
                    events.append(self.event("account", "group_member_added", user=member,
                                             group=item["name"], privileged=True))
        for key in set(self.baseline) - set(snap):
            if key.startswith("user:"):
                events.append(self.event("account", "deleted", **self.baseline[key]))
        if snap != self.baseline:
            self.storage.baseline_update(self.ns, snap, [k for k in self.baseline if k not in snap])
            self.baseline = snap
        return events


# --------------------------------------------------------------------------- kernel / rootkits
class KernelCollector(Collector):
    name = "kernel"
    default_interval = 30.0

    def supported(self) -> bool:
        return IS_LINUX

    def setup(self) -> None:
        self.ns = "kernel_modules"
        self.modules = set(self.storage.baseline_load(self.ns))
        self.initialized = self.storage.baseline_exists(self.ns)
        self.taint = self._taint()
        self.reported_hidden: set[int] = set()

    @staticmethod
    def _modules() -> dict[str, dict]:
        mods = {}
        for line in (read_text("/proc/modules") or "").splitlines():
            parts = line.split()
            if parts:
                mods[parts[0]] = {"size": parts[1] if len(parts) > 1 else "",
                                  "taint": parts[6].strip("()") if len(parts) > 6 else ""}
        return mods

    @staticmethod
    def _taint() -> int:
        try:
            return int((read_text("/proc/sys/kernel/tainted") or "0").strip())
        except ValueError:
            return 0

    def hidden_processes(self) -> list[int]:
        """Técnica 'unhide': PIDs accesibles por stat() pero ocultos en el
        listado de /proc (típico de rootkits LKM que enganchan getdents)."""
        try:
            listed = {int(p) for p in os.listdir("/proc") if p.isdigit()}
        except OSError:
            return []
        if not listed:
            return []
        tids: set[int] = set()
        for pid in listed:
            try:
                tids.update(int(t) for t in os.listdir(f"/proc/{pid}/task"))
            except OSError:
                continue
        visible = listed | tids
        limit = max(visible) + 512
        suspects = [pid for pid in range(1, limit) if pid not in visible
                    and os.path.exists(f"/proc/{pid}/status")]
        if not suspects:
            return []
        # verificación: descartar procesos/hilos creados durante el barrido
        relisted = {int(p) for p in os.listdir("/proc") if p.isdigit()}
        confirmed = []
        for pid in suspects:
            if pid in relisted:
                continue
            status = read_text(f"/proc/{pid}/status") or ""
            tgid = next((ln.split()[1] for ln in status.splitlines() if ln.startswith("Tgid:")), None)
            if tgid and int(tgid) != pid and int(tgid) in relisted:
                continue  # es un hilo de un proceso visible
            confirmed.append(pid)
        return confirmed

    def collect(self) -> list[Event]:
        events: list[Event] = []
        mods = self._modules()
        if not self.initialized:
            self.storage.baseline_update(self.ns, mods)
            self.initialized = True
            for name, info in mods.items():
                events.append(self.event("kernel", "module_loaded", module=name, initial=True, **info))
        else:
            for name in set(mods) - self.modules:
                events.append(self.event("kernel", "module_loaded", module=name, **mods[name]))
            for name in self.modules - set(mods):
                events.append(self.event("kernel", "module_unloaded", module=name))
            if set(mods) != self.modules:
                self.storage.baseline_update(self.ns, {n: mods[n] for n in set(mods) - self.modules},
                                             self.modules - set(mods))
        self.modules = set(mods)

        taint = self._taint()
        if taint != self.taint:
            events.append(self.event("kernel", "tainted", value=taint, previous=self.taint,
                                     unsigned_module=bool(taint & 8192),
                                     out_of_tree=bool(taint & 4096)))
            self.taint = taint

        for pid in self.hidden_processes():
            if pid in self.reported_hidden:
                continue
            self.reported_hidden.add(pid)
            status = read_text(f"/proc/{pid}/status") or ""
            name = next((ln.split(None, 1)[1] for ln in status.splitlines()
                         if ln.startswith("Name:")), "")
            events.append(self.event("kernel", "hidden_process", pid=pid, name=name.strip()))
        return events


# --------------------------------------------------------------------------- dispositivos
USB_CLASSES = {"03": "hid", "08": "mass_storage", "02": "communications", "e0": "wireless",
               "0e": "video", "01": "audio", "07": "printer", "09": "hub", "ff": "vendor_specific"}


class DeviceCollector(Collector):
    name = "devices"
    default_interval = 5.0

    def setup(self) -> None:
        self.usb = self._usb()
        self.mounts = self._mounts()

    @staticmethod
    def _usb() -> dict[str, dict]:
        devices: dict[str, dict] = {}
        base = "/sys/bus/usb/devices"
        if not os.path.isdir(base):
            return devices
        for dev in os.listdir(base):
            path = os.path.join(base, dev)
            vid = read_text(os.path.join(path, "idVendor"))
            if not vid:
                continue

            def rd(name: str) -> str:
                return (read_text(os.path.join(path, name)) or "").strip()

            classes = set()
            for sub in os.listdir(path):
                cls = read_text(os.path.join(path, sub, "bInterfaceClass"))
                if cls:
                    classes.add(USB_CLASSES.get(cls.strip().lower(), cls.strip()))
            key = f"{dev}:{vid.strip()}:{rd('idProduct')}:{rd('serial')}"
            devices[key] = {"bus_id": dev, "vendor_id": vid.strip(), "product_id": rd("idProduct"),
                            "manufacturer": rd("manufacturer"), "product": rd("product"),
                            "serial": rd("serial"), "interfaces": sorted(classes)}
        return devices

    @staticmethod
    def _mounts() -> dict[str, dict]:
        out = {}
        try:
            for p in psutil.disk_partitions(all=False):
                out[p.mountpoint] = {"device": p.device, "mountpoint": p.mountpoint,
                                     "fstype": p.fstype, "opts": p.opts}
        except OSError:
            pass
        return out

    def collect(self) -> list[Event]:
        events: list[Event] = []
        usb = self._usb()
        for key in set(usb) - set(self.usb):
            d = usb[key]
            events.append(self.event("device", "usb_connected", **d,
                                     mass_storage="mass_storage" in d["interfaces"],
                                     hid="hid" in d["interfaces"]))
        for key in set(self.usb) - set(usb):
            events.append(self.event("device", "usb_disconnected", **self.usb[key]))
        self.usb = usb
        mounts = self._mounts()
        for mp in set(mounts) - set(self.mounts):
            m = mounts[mp]
            removable = any(x in m["device"] for x in ("/dev/sd", "/dev/mmcblk", "/media",
                                                       "/run/media")) or mp.startswith(("/media",
                                                                                        "/run/media"))
            events.append(self.event("device", "mounted", removable=removable, **m))
        for mp in set(self.mounts) - set(mounts):
            events.append(self.event("device", "unmounted", **self.mounts[mp]))
        self.mounts = mounts
        return events


# --------------------------------------------------------------------------- recursos
class ResourceCollector(Collector):
    name = "resources"
    default_interval = 10.0

    def setup(self) -> None:
        self.threshold = float(self.settings.get("cpu_threshold", 85.0))
        self.needed = int(self.settings.get("sustained_samples", 6))
        self.hot: dict[int, int] = {}
        self.reported: set[tuple[int, float]] = set()
        self.procs: dict[int, psutil.Process] = {}
        self.disk_reported: set[str] = set()

    def collect(self) -> list[Event]:
        events: list[Event] = []
        alive = set()
        for proc in psutil.process_iter(["pid"]):
            pid = proc.pid
            alive.add(pid)
            p = self.procs.get(pid)
            if p is None:
                self.procs[pid] = proc
                try:
                    proc.cpu_percent(None)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
                continue
            try:
                cpu = p.cpu_percent(None)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
            if cpu >= self.threshold and pid != os.getpid():
                self.hot[pid] = self.hot.get(pid, 0) + 1
                if self.hot[pid] >= self.needed:
                    try:
                        key = (pid, p.create_time())
                        if key not in self.reported:
                            self.reported.add(key)
                            events.append(self.event(
                                "resource", "high_cpu", pid=pid, process=p.name(), exe=p.exe(),
                                cmdline=" ".join(p.cmdline()), username=p.username(), cpu=cpu,
                                duration=self.hot[pid] * self.interval,
                                connections=[f"{c.raddr.ip}:{c.raddr.port}" for c in
                                             p.net_connections() if c.raddr][:20]))
                    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                        pass
            else:
                self.hot.pop(pid, None)
        for pid in set(self.procs) - alive:
            self.procs.pop(pid, None)
            self.hot.pop(pid, None)
        try:
            for part in psutil.disk_partitions(all=False):
                usage = psutil.disk_usage(part.mountpoint)
                if usage.percent >= 97 and part.mountpoint not in self.disk_reported:
                    self.disk_reported.add(part.mountpoint)
                    events.append(self.event("resource", "disk_full", mountpoint=part.mountpoint,
                                             percent=usage.percent))
                elif usage.percent < 90:
                    self.disk_reported.discard(part.mountpoint)
        except OSError:
            pass
        events.append(self.event("metric", "system", cpu=psutil.cpu_percent(None),
                                 memory=psutil.virtual_memory().percent, ts=time.time()))
        return events
