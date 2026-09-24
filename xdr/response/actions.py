"""Acciones de respuesta en el endpoint. Todas son idempotentes, registran su
resultado y respetan el modo simulación (dry_run) y las listas de protección."""
from __future__ import annotations

import json
import logging
import os
import shutil
import signal
import stat
import sys
import time
from pathlib import Path
from typing import Any, Callable

import psutil

from xdr.utils import IS_LINUX, IS_WINDOWS, ip_in_list, is_valid_ip, run_cmd, sha256_file

log = logging.getLogger("xdr.response")

CHAIN = "SENTINEL-XDR"
ISOLATION_CHAIN = "SENTINEL-XDR-ISOLATE"

# Rutas del sistema operativo que la respuesta automática nunca mueve ni borra.
# Aislar un binario del sistema (p.ej. /usr/bin/bash) deja el equipo inutilizable.
SYSTEM_PREFIXES = ("/usr/", "/bin/", "/sbin/", "/lib/", "/lib32/", "/lib64/", "/libx32/", "/boot/",
                   "/opt/", "/snap/", "/nix/", "/proc/", "/sys/", "/dev/",
                   "C:\\Windows\\", "C:\\Program Files")
SYSTEM_EXCEPTIONS = ("/usr/local/bin/", "/usr/local/sbin/")  # binarios instalados a mano: sí se aíslan
# Ficheros de configuración cuya ausencia rompe el arranque o el login: se alerta, no se mueven.
CRITICAL_FILES = {"/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow", "/etc/sudoers",
                  "/etc/fstab", "/etc/hosts", "/etc/resolv.conf", "/etc/nsswitch.conf",
                  "/etc/profile", "/etc/bash.bashrc", "/etc/environment", "/etc/login.defs",
                  "/etc/ssh/sshd_config", "/etc/crontab", "/etc/hostname", "/etc/os-release"}
CRITICAL_DIRS = ("/etc/pam.d/", "/etc/security/", "/etc/systemd/", "/etc/default/")


def is_system_path(path: str) -> bool:
    try:
        real = os.path.realpath(path)
    except (OSError, ValueError):
        real = path
    for p in {path, real}:
        if p in CRITICAL_FILES or p.startswith(CRITICAL_DIRS):
            return True
        if p.startswith(SYSTEM_EXCEPTIONS):
            continue
        if p.startswith(SYSTEM_PREFIXES):
            return True
    return False


class ActionResult(dict):
    def __init__(self, action: str, success: bool, message: str, **details: Any):
        super().__init__(action=action, success=success, message=message, ts=time.time(),
                         **details)


class ResponseActions:
    def __init__(self, settings: dict[str, Any], data_dir: str, server_host: str | None = None):
        self.settings = settings
        self.dry_run = bool(settings.get("dry_run", False))
        self.protected = set(settings.get("protected_processes", []))
        self.never_block = list(settings.get("never_block_ips", []))
        self.protected_paths = [os.path.realpath(p) for p in settings.get("protected_paths", [])]
        self.server_host = server_host
        self.quarantine_dir = Path(settings.get("quarantine_dir") or os.path.join(data_dir, "quarantine"))
        self.forensics_dir = Path(os.path.join(data_dir, "forensics"))
        self.actions: dict[str, Callable[..., ActionResult]] = {
            "kill_process": self.kill_process,
            "suspend_process": self.suspend_process,
            "resume_process": self.resume_process,
            "kill_top_writer": self.kill_top_writer,
            "quarantine_file": self.quarantine_file,
            "restore_file": self.restore_file,
            "delete_file": self.delete_file,
            "block_ip": self.block_ip,
            "unblock_ip": self.unblock_ip,
            "isolate_host": self.isolate_host,
            "release_host": self.release_host,
            "disable_user": self.disable_user,
            "enable_user": self.enable_user,
            "kill_user_sessions": self.kill_user_sessions,
            "collect_forensics": self.collect_forensics,
            "scan_path": self.scan_path,
            "list_quarantine": self.list_quarantine,
        }
        self.scanner = None  # inyectado por el agente para scan_path

    def execute(self, action: str, **params: Any) -> ActionResult:
        fn = self.actions.get(action)
        if not fn:
            return ActionResult(action, False, f"acción desconocida: {action}")
        try:
            result = fn(**params)
        except TypeError as exc:
            result = ActionResult(action, False, f"parámetros inválidos: {exc}")
        except Exception as exc:  # noqa: BLE001
            log.exception("acción %s falló", action)
            result = ActionResult(action, False, f"error: {exc}")
        log.warning("RESPUESTA %s %s -> %s", action, params, result.get("message"))
        return result

    # ------------------------------------------------------------- procesos
    def _is_protected(self, proc: psutil.Process) -> str | None:
        if proc.pid in (0, 1, os.getpid(), os.getppid()):
            return "proceso crítico o del propio agente"
        try:
            name = proc.name()
            if name in self.protected:
                return f"proceso protegido ({name})"
            if proc.pid in {p.pid for p in psutil.Process(os.getpid()).parents()}:
                return "proceso ancestro del agente"
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
        return None

    def kill_process(self, pid: int | None = None, create_time: float | None = None,
                     tree: bool = True, **_: Any) -> ActionResult:
        if not pid:
            return ActionResult("kill_process", False, "pid no indicado")
        try:
            proc = psutil.Process(int(pid))
        except psutil.NoSuchProcess:
            return ActionResult("kill_process", True, f"el proceso {pid} ya no existe", pid=pid)
        if create_time and abs(proc.create_time() - float(create_time)) > 1:
            return ActionResult("kill_process", False, "el PID fue reutilizado por otro proceso", pid=pid)
        reason = self._is_protected(proc)
        if reason:
            return ActionResult("kill_process", False, f"no se termina: {reason}", pid=pid)
        name = proc.name()
        targets = [proc]
        if tree:
            try:
                targets = proc.children(recursive=True) + [proc]
            except psutil.NoSuchProcess:
                pass
        if self.dry_run:
            return ActionResult("kill_process", True, f"[simulación] se terminaría {name} ({pid})",
                                pid=pid, dry_run=True)
        killed = []
        for p in targets:
            try:
                p.kill()
                killed.append(p.pid)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        psutil.wait_procs(targets, timeout=3)
        return ActionResult("kill_process", bool(killed), f"terminado {name} ({pid}) y {len(killed) - 1} hijos",
                            pid=pid, killed=killed, process=name)

    def suspend_process(self, pid: int | None = None, **_: Any) -> ActionResult:
        try:
            proc = psutil.Process(int(pid))
            reason = self._is_protected(proc)
            if reason:
                return ActionResult("suspend_process", False, f"no se suspende: {reason}")
            if not self.dry_run:
                proc.suspend()
            return ActionResult("suspend_process", True, f"proceso {pid} suspendido", pid=pid)
        except (psutil.NoSuchProcess, TypeError, ValueError) as exc:
            return ActionResult("suspend_process", False, str(exc))

    def resume_process(self, pid: int | None = None, **_: Any) -> ActionResult:
        try:
            psutil.Process(int(pid)).resume()
            return ActionResult("resume_process", True, f"proceso {pid} reanudado", pid=pid)
        except (psutil.NoSuchProcess, TypeError, ValueError) as exc:
            return ActionResult("resume_process", False, str(exc))

    def kill_top_writer(self, directories: list[str] | None = None, sample: float = 1.0,
                        **_: Any) -> ActionResult:
        """Contención de ransomware: entre los procesos que tienen ficheros
        abiertos (o su cwd) en los directorios afectados, termina el que más
        escribe a disco. Nunca actúa a ciegas sobre procesos no relacionados."""
        dirs = [d.rstrip("/") + "/" for d in (directories or []) if d]
        if not dirs:
            return ActionResult("kill_top_writer", False, "sin directorios afectados para acotar")

        def related(p: psutil.Process) -> bool:
            try:
                paths = [f.path for f in p.open_files()]
                paths.append(p.cwd() + "/")
            except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
                return False
            return any(path.startswith(d) or path + "/" == d for path in paths for d in dirs)

        before: dict[int, int] = {}
        for p in psutil.process_iter(["pid"]):
            try:
                if p.pid != os.getpid() and related(p):
                    before[p.pid] = p.io_counters().write_bytes
            except (psutil.NoSuchProcess, psutil.AccessDenied, AttributeError):
                continue
        if not before:
            return ActionResult("kill_top_writer", False,
                                "ningún proceso activo en los directorios afectados")
        time.sleep(sample)
        best, best_rate = None, -1
        for pid, wb in before.items():
            try:
                p = psutil.Process(pid)
                rate = p.io_counters().write_bytes - wb
            except (psutil.NoSuchProcess, psutil.AccessDenied, AttributeError):
                continue
            if rate > best_rate and not self._is_protected(p):
                best, best_rate = p, rate
        if not best:
            return ActionResult("kill_top_writer", False, "no se identificó proceso cifrador")
        res = self.kill_process(pid=best.pid)
        res["action"] = "kill_top_writer"
        res["write_rate"] = best_rate / sample
        return res

    # --------------------------------------------------------------- ficheros
    def _protected_file(self, real: str) -> str | None:
        """Motivo por el que un fichero no debe moverse/borrarse, o None."""
        if is_system_path(real):
            return "ruta del sistema operativo protegida"
        for prefix in self.protected_paths:
            if real == prefix or real.startswith(prefix.rstrip("/") + "/"):
                return "ruta protegida por configuración"
        if real == os.path.realpath(sys.executable):
            return "intérprete del propio agente"
        for p in psutil.process_iter(["exe", "name"]):
            if p.info.get("exe") == real and (p.info.get("name") in self.protected or p.pid == 1):
                return f"lo ejecuta un proceso protegido ({p.info.get('name')})"
        return None

    def quarantine_file(self, path: str | None = None, **_: Any) -> ActionResult:
        if not path or not os.path.isfile(path):
            if path and self.quarantine_dir.is_dir():
                for meta in self.quarantine_dir.glob("*.json"):
                    try:
                        if json.loads(meta.read_text()).get("original_path") == os.path.realpath(path):
                            return ActionResult("quarantine_file", True, "ya estaba en cuarentena",
                                                path=path, quarantine_id=meta.stem)
                    except (OSError, ValueError):
                        continue
            return ActionResult("quarantine_file", False, f"fichero no encontrado: {path}")
        real = os.path.realpath(path)
        if real.startswith(str(self.quarantine_dir)):
            return ActionResult("quarantine_file", True, "ya está en cuarentena", path=path)
        reason = self._protected_file(real)
        if reason:
            return ActionResult("quarantine_file", False, f"no se aísla {real}: {reason}", path=path)
        digest = sha256_file(real) or "unknown"
        st = os.stat(real)
        if self.dry_run:
            return ActionResult("quarantine_file", True, f"[simulación] cuarentena de {path}",
                                path=path, dry_run=True)
        self.quarantine_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        qid = f"{int(time.time())}_{digest[:16]}"
        dest = self.quarantine_dir / f"{qid}.bin"
        # Matar procesos que ejecutan el binario antes de moverlo
        for p in psutil.process_iter(["pid", "exe"]):
            if p.info.get("exe") == real and not self._is_protected(p):
                try:
                    p.kill()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
        shutil.move(real, dest)
        os.chmod(dest, 0o000)
        meta = {"id": qid, "original_path": real, "sha256": digest, "mode": stat.S_IMODE(st.st_mode),
                "uid": st.st_uid, "gid": st.st_gid, "size": st.st_size, "ts": time.time()}
        with open(self.quarantine_dir / f"{qid}.json", "w") as fh:
            json.dump(meta, fh, indent=1)
        return ActionResult("quarantine_file", True, f"{path} movido a cuarentena", path=path,
                            quarantine_id=qid, sha256=digest)

    def restore_file(self, quarantine_id: str | None = None, **_: Any) -> ActionResult:
        meta_path = self.quarantine_dir / f"{quarantine_id}.json"
        if not quarantine_id or not meta_path.is_file():
            return ActionResult("restore_file", False, "id de cuarentena no encontrado")
        meta = json.loads(meta_path.read_text())
        src = self.quarantine_dir / f"{quarantine_id}.bin"
        os.chmod(src, 0o600)
        shutil.move(str(src), meta["original_path"])
        os.chmod(meta["original_path"], meta["mode"])
        try:
            os.chown(meta["original_path"], meta["uid"], meta["gid"])
        except (OSError, AttributeError):
            pass
        meta_path.unlink()
        return ActionResult("restore_file", True, f"restaurado {meta['original_path']}")

    def delete_file(self, path: str | None = None, **_: Any) -> ActionResult:
        if not path or not os.path.isfile(path):
            return ActionResult("delete_file", False, "fichero no encontrado")
        reason = self._protected_file(os.path.realpath(path))
        if reason:
            return ActionResult("delete_file", False, f"no se borra {path}: {reason}")
        if self.dry_run:
            return ActionResult("delete_file", True, f"[simulación] se borraría {path}", dry_run=True)
        os.remove(path)
        return ActionResult("delete_file", True, f"{path} eliminado")

    def list_quarantine(self, **_: Any) -> ActionResult:
        items = []
        if self.quarantine_dir.is_dir():
            for meta in sorted(self.quarantine_dir.glob("*.json")):
                try:
                    items.append(json.loads(meta.read_text()))
                except (OSError, ValueError):
                    continue
        return ActionResult("list_quarantine", True, f"{len(items)} ficheros en cuarentena", items=items)

    # -------------------------------------------------------------------- red
    def _fw(self, args: list[str]) -> tuple[int, str]:
        return run_cmd(["iptables", "-w"] + args) if IS_LINUX else (1, "no soportado")

    def _ensure_chain(self, chain: str, hooks: tuple[str, ...] = ("INPUT", "OUTPUT", "FORWARD")) -> None:
        self._fw(["-N", chain])
        for hook in hooks:
            code, _ = self._fw(["-C", hook, "-j", chain])
            if code != 0:
                self._fw(["-I", hook, "1", "-j", chain])

    def block_ip(self, ip: str | None = None, **_: Any) -> ActionResult:
        if not ip or not is_valid_ip(ip):
            return ActionResult("block_ip", False, f"IP inválida: {ip}")
        if ip_in_list(ip, self.never_block) or ip == self.server_host:
            return ActionResult("block_ip", False, f"{ip} está en la lista de no bloqueo")
        if self.dry_run:
            return ActionResult("block_ip", True, f"[simulación] se bloquearía {ip}", ip=ip, dry_run=True)
        if IS_WINDOWS:  # pragma: no cover
            name = f"SentinelXDR block {ip}"
            c1, o1 = run_cmd(["netsh", "advfirewall", "firewall", "add", "rule", f"name={name}",
                              "dir=in", "action=block", f"remoteip={ip}"])
            run_cmd(["netsh", "advfirewall", "firewall", "add", "rule", f"name={name}",
                     "dir=out", "action=block", f"remoteip={ip}"])
            return ActionResult("block_ip", c1 == 0, o1 or f"{ip} bloqueada", ip=ip)
        if ":" in ip:
            cmd = "ip6tables"
            run_cmd([cmd, "-w", "-N", CHAIN])
            for hook in ("INPUT", "OUTPUT"):
                if run_cmd([cmd, "-w", "-C", hook, "-j", CHAIN])[0] != 0:
                    run_cmd([cmd, "-w", "-I", hook, "1", "-j", CHAIN])
            if run_cmd([cmd, "-w", "-C", CHAIN, "-s", ip, "-j", "DROP"])[0] != 0:
                code, out = run_cmd([cmd, "-w", "-A", CHAIN, "-s", ip, "-j", "DROP"])
                run_cmd([cmd, "-w", "-A", CHAIN, "-d", ip, "-j", "DROP"])
                if code != 0:
                    return ActionResult("block_ip", False, out, ip=ip)
            return ActionResult("block_ip", True, f"{ip} bloqueada", ip=ip)
        self._ensure_chain(CHAIN)
        if self._fw(["-C", CHAIN, "-s", ip, "-j", "DROP"])[0] == 0:
            return ActionResult("block_ip", True, f"{ip} ya estaba bloqueada", ip=ip)
        code, out = self._fw(["-A", CHAIN, "-s", ip, "-j", "DROP"])
        if code != 0:
            return ActionResult("block_ip", False, f"iptables falló: {out}", ip=ip)
        self._fw(["-A", CHAIN, "-d", ip, "-j", "DROP"])
        # Cortar conexiones ya establecidas
        run_cmd(["ss", "-K", "dst", ip])
        return ActionResult("block_ip", True, f"{ip} bloqueada (entrada y salida)", ip=ip)

    def unblock_ip(self, ip: str | None = None, **_: Any) -> ActionResult:
        if not ip or not is_valid_ip(ip):
            return ActionResult("unblock_ip", False, "IP inválida")
        if IS_WINDOWS:  # pragma: no cover
            code, out = run_cmd(["netsh", "advfirewall", "firewall", "delete", "rule",
                                 f"name=SentinelXDR block {ip}"])
            return ActionResult("unblock_ip", code == 0, out)
        cmd = "ip6tables" if ":" in ip else "iptables"
        for direction in ("-s", "-d"):
            while run_cmd([cmd, "-w", "-D", CHAIN, direction, ip, "-j", "DROP"])[0] == 0:
                pass
        return ActionResult("unblock_ip", True, f"{ip} desbloqueada", ip=ip)

    def isolate_host(self, allow: list[str] | None = None, **_: Any) -> ActionResult:
        """Aislamiento de red: solo se permite loopback, conexiones con el
        servidor XDR y las IPs indicadas."""
        if self.dry_run:
            return ActionResult("isolate_host", True, "[simulación] host aislado", dry_run=True)
        if IS_WINDOWS:  # pragma: no cover
            code, out = run_cmd(["netsh", "advfirewall", "set", "allprofiles", "firewallpolicy",
                                 "blockinbound,blockoutbound"])
            return ActionResult("isolate_host", code == 0, out or "host aislado")
        if not IS_LINUX:
            return ActionResult("isolate_host", False, "plataforma no soportada")
        allowed = list(allow or [])
        if self.server_host:
            allowed.append(self.server_host)
        self._fw(["-N", ISOLATION_CHAIN])
        self._fw(["-F", ISOLATION_CHAIN])
        rules = [["-A", ISOLATION_CHAIN, "-i", "lo", "-j", "RETURN"],
                 ["-A", ISOLATION_CHAIN, "-o", "lo", "-j", "RETURN"]]
        for ip in allowed:
            if is_valid_ip(ip) and ":" not in ip:
                rules += [["-A", ISOLATION_CHAIN, "-s", ip, "-j", "RETURN"],
                          ["-A", ISOLATION_CHAIN, "-d", ip, "-j", "RETURN"]]
        rules.append(["-A", ISOLATION_CHAIN, "-j", "DROP"])
        for r in rules:
            code, out = self._fw(r)
            if code != 0:
                return ActionResult("isolate_host", False, f"iptables falló: {out}")
        for hook in ("INPUT", "OUTPUT", "FORWARD"):
            if self._fw(["-C", hook, "-j", ISOLATION_CHAIN])[0] != 0:
                self._fw(["-I", hook, "1", "-j", ISOLATION_CHAIN])
        return ActionResult("isolate_host", True, "host aislado de la red (excepto servidor XDR)",
                            allowed=allowed)

    def release_host(self, **_: Any) -> ActionResult:
        if IS_WINDOWS:  # pragma: no cover
            code, out = run_cmd(["netsh", "advfirewall", "set", "allprofiles", "firewallpolicy",
                                 "blockinbound,allowoutbound"])
            return ActionResult("release_host", code == 0, out or "aislamiento retirado")
        for hook in ("INPUT", "OUTPUT", "FORWARD"):
            while self._fw(["-D", hook, "-j", ISOLATION_CHAIN])[0] == 0:
                pass
        self._fw(["-F", ISOLATION_CHAIN])
        self._fw(["-X", ISOLATION_CHAIN])
        return ActionResult("release_host", True, "aislamiento de red retirado")

    # --------------------------------------------------------------- usuarios
    def disable_user(self, user: str | None = None, **_: Any) -> ActionResult:
        if not user or user == "root":
            return ActionResult("disable_user", False, "usuario inválido o protegido (root)")
        if self.dry_run:
            return ActionResult("disable_user", True, f"[simulación] se bloquearía {user}", dry_run=True)
        if IS_WINDOWS:  # pragma: no cover
            code, out = run_cmd(["net", "user", user, "/active:no"])
            return ActionResult("disable_user", code == 0, out)
        code, out = run_cmd(["usermod", "-L", "-e", "1", user])
        if code != 0:
            return ActionResult("disable_user", False, out)
        self.kill_user_sessions(user=user)
        return ActionResult("disable_user", True, f"cuenta {user} bloqueada y sesiones cerradas", user=user)

    def enable_user(self, user: str | None = None, **_: Any) -> ActionResult:
        if not user:
            return ActionResult("enable_user", False, "usuario no indicado")
        code, out = run_cmd(["usermod", "-U", "-e", "", user])
        return ActionResult("enable_user", code == 0, out or f"cuenta {user} desbloqueada")

    def kill_user_sessions(self, user: str | None = None, **_: Any) -> ActionResult:
        if not user or user == "root":
            return ActionResult("kill_user_sessions", False, "usuario inválido o protegido")
        killed = []
        for p in psutil.process_iter(["pid", "username"]):
            if p.info.get("username") == user and not self._is_protected(p):
                if self.dry_run:
                    killed.append(p.pid)
                    continue
                try:
                    p.send_signal(signal.SIGKILL) if hasattr(signal, "SIGKILL") else p.kill()
                    killed.append(p.pid)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        return ActionResult("kill_user_sessions", True, f"{len(killed)} procesos de {user} terminados",
                            killed=killed)

    # --------------------------------------------------------------- forense
    def collect_forensics(self, reason: str = "", **_: Any) -> ActionResult:
        """Captura volátil: procesos, conexiones, sesiones, módulos, cron, etc."""
        snap: dict[str, Any] = {"ts": time.time(), "reason": reason, "hostname": os.uname().nodename
                                if hasattr(os, "uname") else ""}
        procs = []
        for p in psutil.process_iter(["pid", "ppid", "name", "exe", "cmdline", "username",
                                      "create_time"]):
            info = p.info
            info["cmdline"] = " ".join(info.get("cmdline") or [])
            procs.append(info)
        snap["processes"] = procs
        try:
            snap["connections"] = [
                {"pid": c.pid, "laddr": f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "",
                 "raddr": f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "", "status": c.status}
                for c in psutil.net_connections(kind="inet")]
        except (psutil.AccessDenied, OSError):
            snap["connections"] = []
        snap["users"] = [u._asdict() for u in psutil.users()]
        snap["boot_time"] = psutil.boot_time()
        if IS_LINUX:
            for name, path in (("modules", "/proc/modules"), ("crontab", "/etc/crontab"),
                               ("ld_so_preload", "/etc/ld.so.preload"), ("hosts", "/etc/hosts"),
                               ("passwd", "/etc/passwd")):
                try:
                    with open(path, "r", errors="replace") as fh:
                        snap[name] = fh.read(512 * 1024)
                except OSError:
                    snap[name] = None
            snap["iptables"] = run_cmd(["iptables", "-S"])[1]
            snap["last_logins"] = run_cmd(["last", "-n", "50"])[1]
        self.forensics_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        path = self.forensics_dir / f"forensics_{int(time.time())}.json"
        with open(path, "w") as fh:
            json.dump(snap, fh, default=str)
        return ActionResult("collect_forensics", True, f"paquete forense guardado en {path}",
                            path=str(path), processes=len(procs),
                            connections=len(snap["connections"]))

    def scan_path(self, path: str | None = None, **_: Any) -> ActionResult:
        if not self.scanner or not path:
            return ActionResult("scan_path", False, "escáner no disponible o ruta vacía")
        findings = self.scanner(path)
        return ActionResult("scan_path", True, f"{len(findings)} detecciones en {path}",
                            findings=findings)
