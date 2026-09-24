"""Sensor de procesos: altas/bajas, línea de comandos, hash del binario,
binarios borrados (fileless) y LD_PRELOAD."""
from __future__ import annotations

import logging
import os
import socket
import struct
import threading
from typing import Any

import psutil

from xdr.collectors.base import Collector
from xdr.events import Event
from xdr.utils import IS_LINUX, sha256_file

log = logging.getLogger("xdr.collector.process")

ATTRS = ["pid", "ppid", "name", "exe", "cmdline", "username", "create_time", "cwd"]


def describe_process(proc: psutil.Process, info: dict | None = None, hash_exe: bool = True) -> dict:
    """Construye el diccionario de datos de un proceso (tolerante a errores)."""
    if info is None:
        try:
            info = proc.as_dict(attrs=ATTRS)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            info = {"pid": proc.pid}
    cmdline = info.get("cmdline") or []
    exe = info.get("exe") or ""
    data: dict[str, Any] = {
        "pid": info.get("pid"),
        "ppid": info.get("ppid"),
        "name": info.get("name") or "",
        "exe": exe,
        "cmdline": " ".join(cmdline) if isinstance(cmdline, list) else str(cmdline),
        "args": cmdline if isinstance(cmdline, list) else [],
        "username": info.get("username") or "",
        "cwd": info.get("cwd") or "",
        "create_time": info.get("create_time"),
    }
    if IS_LINUX and data["pid"]:
        try:
            link = os.readlink(f"/proc/{data['pid']}/exe")
            data["exe_deleted"] = link.endswith(" (deleted)")
            if data["exe_deleted"] and not exe:
                data["exe"] = link.replace(" (deleted)", "")
            data["memfd"] = link.startswith("/memfd:")
        except OSError:
            data["exe_deleted"] = False
        try:
            with open(f"/proc/{data['pid']}/environ", "rb") as fh:
                env = fh.read(65536).split(b"\0")
            for item in env:
                if item.startswith(b"LD_PRELOAD="):
                    data["ld_preload"] = item[11:].decode(errors="replace")
                    break
        except OSError:
            pass
    if hash_exe and data["exe"] and not data.get("exe_deleted"):
        data["exe_hash"] = sha256_file(data["exe"])
    elif hash_exe and data.get("exe_deleted") and IS_LINUX:
        # El binario ya no existe en disco: se puede hashear vía /proc/<pid>/exe
        data["exe_hash"] = sha256_file(f"/proc/{data['pid']}/exe")
    return data


class ExecListener:
    """Suscripción al 'proc connector' de Linux (netlink) para recibir cada
    exec() en tiempo real. Requiere root; si no está disponible se usa solo
    el sondeo periódico."""

    NETLINK_CONNECTOR = 11
    CN_IDX_PROC = 1
    CN_VAL_PROC = 1
    PROC_CN_MCAST_LISTEN = 1
    PROC_EVENT_EXEC = 0x00000002

    def __init__(self, callback):
        self.callback = callback
        self.sock: socket.socket | None = None
        self.running = False

    def start(self) -> bool:
        if not IS_LINUX or not hasattr(socket, "AF_NETLINK"):
            return False
        try:
            sock = socket.socket(socket.AF_NETLINK, socket.SOCK_DGRAM, self.NETLINK_CONNECTOR)
            sock.bind((0, self.CN_IDX_PROC))
            op = struct.pack("=I", self.PROC_CN_MCAST_LISTEN)
            cn = struct.pack("=IIIIHH", self.CN_IDX_PROC, self.CN_VAL_PROC, 0, 0, len(op), 0) + op
            sock.send(struct.pack("=IHHII", 16 + len(cn), 3, 0, 0, 0) + cn)
            sock.settimeout(1.0)
        except OSError as exc:
            log.info("proc connector no disponible (%s); se usará sondeo", exc)
            return False
        self.sock = sock
        self.running = True
        threading.Thread(target=self._loop, name="exec-listener", daemon=True).start()
        return True

    def _loop(self) -> None:
        while self.running and self.sock:
            try:
                data = self.sock.recv(4096)
            except socket.timeout:
                continue
            except OSError:
                break
            offset = 0
            while offset + 16 <= len(data):
                nl_len = struct.unpack_from("=I", data, offset)[0]
                if nl_len < 16:
                    break
                body = offset + 16 + 20  # nlmsghdr + cn_msg
                if body + 16 <= len(data):
                    what = struct.unpack_from("=I", data, body)[0]
                    if what == self.PROC_EVENT_EXEC and body + 24 <= len(data):
                        _pid, tgid = struct.unpack_from("=II", data, body + 16)
                        try:
                            self.callback(tgid)
                        except Exception:  # noqa: BLE001
                            log.debug("fallo procesando exec de %s", tgid, exc_info=True)
                offset += (nl_len + 3) & ~3

    def stop(self) -> None:
        self.running = False
        if self.sock:
            self.sock.close()


class ProcessCollector(Collector):
    name = "process"
    default_interval = 2.0

    def setup(self) -> None:
        self.known: dict[tuple[int, float], dict] = {}
        self.first = True
        self.hash_exe = bool(self.settings.get("hash_executables", True))
        self.lock = threading.Lock()
        self.ignore_own = bool(self.settings.get("ignore_own_children", True))
        self.listener = ExecListener(self._on_exec)
        self.realtime = bool(self.settings.get("realtime", True)) and self.listener.start()

    def teardown(self) -> None:
        self.listener.stop()

    def _parent(self, ppid: int | None) -> dict:
        try:
            pp = psutil.Process(ppid)
            return {"pid": ppid, "name": pp.name(), "exe": pp.exe(), "cmdline": " ".join(pp.cmdline())}
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, TypeError, ValueError):
            return {"pid": ppid, "name": "", "exe": "", "cmdline": ""}

    def _on_exec(self, pid: int) -> None:
        if pid == os.getpid():
            return
        try:
            proc = psutil.Process(pid)
            info = proc.as_dict(attrs=ATTRS)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            return
        if self.ignore_own and info.get("ppid") == os.getpid():
            return  # subprocesos del propio agente (iptables, last...)
        key = (info["pid"], info.get("create_time") or 0.0)
        data = describe_process(proc, info, self.hash_exe)
        data["parent"] = self._parent(info.get("ppid"))
        data["initial"] = False
        data["realtime"] = True
        with self.lock:
            # un exec() sin fork mantiene (pid, create_time): se registra igualmente
            prev = self.known.get(key)
            if prev and prev.get("exe") == info.get("exe") and prev.get("cmdline") == data["cmdline"]:
                return
            self.known[key] = {"pid": info["pid"], "name": info.get("name"), "exe": info.get("exe"),
                               "cmdline": data["cmdline"]}
        self.emit(self.event("process", "start", **data))

    def collect(self) -> list[Event]:
        events: list[Event] = []
        current: dict[tuple[int, float], dict] = {}
        infos: dict[int, dict] = {}
        for proc in psutil.process_iter(ATTRS):
            info = proc.info
            key = (info["pid"], info.get("create_time") or 0.0)
            current[key] = info
            infos[info["pid"]] = info
        own = os.getpid()
        for key, info in current.items():
            with self.lock:
                if key in self.known or info["pid"] == own:
                    continue
                if self.ignore_own and info.get("ppid") == own:
                    self.known[key] = {"pid": info["pid"], "name": info.get("name"),
                                       "exe": info.get("exe"), "cmdline": ""}
                    continue
            try:
                proc = psutil.Process(info["pid"])
            except psutil.NoSuchProcess:
                continue
            data = describe_process(proc, info, self.hash_exe)
            parent = infos.get(info.get("ppid") or -1)
            if parent:
                pcmd = parent.get("cmdline") or []
                data["parent"] = {"pid": parent["pid"], "name": parent.get("name") or "",
                                  "exe": parent.get("exe") or "",
                                  "cmdline": " ".join(pcmd) if isinstance(pcmd, list) else str(pcmd)}
            else:
                data["parent"] = {"pid": info.get("ppid"), "name": "", "exe": "", "cmdline": ""}
            data["initial"] = self.first
            with self.lock:
                if key in self.known:
                    continue
                self.known[key] = {"pid": info["pid"], "name": info.get("name"), "exe": info.get("exe"),
                                   "cmdline": data["cmdline"]}
            events.append(self.event("process", "start", **data))
        with self.lock:
            for key in list(self.known):
                if key not in current:
                    gone = self.known.pop(key)
                    if not self.first:
                        events.append(self.event("process", "stop", pid=gone["pid"],
                                                 name=gone.get("name"), exe=gone.get("exe")))
        self.first = False
        return events
