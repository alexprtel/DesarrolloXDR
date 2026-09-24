"""Evaluación de postura / hardening (gestión de vulnerabilidades de
configuración). Genera hallazgos con referencia CIS y remediación."""
from __future__ import annotations

import glob
import os
import re
import shutil
import stat
from typing import Any, Callable

import psutil

from xdr.collectors.base import Collector
from xdr.events import Event
from xdr.utils import IS_LINUX, read_text, run_cmd

RISKY_PORTS = {21: "FTP", 23: "Telnet", 69: "TFTP", 111: "rpcbind", 135: "MSRPC", 139: "NetBIOS",
               445: "SMB", 512: "rexec", 513: "rlogin", 514: "rsh", 1433: "MSSQL", 2375: "Docker API",
               3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
               9200: "Elasticsearch", 11211: "Memcached", 27017: "MongoDB"}

DANGEROUS_SUID = {"bash", "sh", "dash", "zsh", "python", "python3", "perl", "ruby", "php", "vim",
                  "vi", "nano", "find", "awk", "gawk", "nmap", "less", "more", "env", "tee", "cp",
                  "node", "lua", "tclsh", "socat", "nc", "netcat", "gdb", "busybox", "docker"}


def _sshd_option(name: str) -> str | None:
    texts = [read_text("/etc/ssh/sshd_config") or ""]
    texts += [read_text(p) or "" for p in sorted(glob.glob("/etc/ssh/sshd_config.d/*.conf"))]
    for text in texts[1:] + texts[:1]:  # los drop-in tienen prioridad (primera coincidencia)
        for line in text.splitlines():
            line = line.strip()
            if line.lower().startswith(name.lower() + " ") or line.lower().startswith(name.lower() + "\t"):
                return line.split(None, 1)[1].strip().lower()
    return None


def _sysctl(key: str) -> str | None:
    val = read_text("/proc/sys/" + key.replace(".", "/"))
    return val.strip() if val is not None else None


class PostureCollector(Collector):
    name = "posture"
    default_interval = 3600.0

    def supported(self) -> bool:
        return IS_LINUX

    def checks(self) -> list[tuple[str, str, str, str, Callable[[], tuple[str, str]]]]:
        """(id, título, severidad, remediación, función) -> función devuelve (status, detalle)."""
        return [
            ("SSH-001", "SSH permite login directo de root", "high",
             "Establecer 'PermitRootLogin no' (o prohibit-password) en sshd_config", self.c_ssh_root),
            ("SSH-002", "SSH permite autenticación por contraseña", "medium",
             "Usar claves: 'PasswordAuthentication no'", self.c_ssh_password),
            ("SSH-003", "SSH permite contraseñas vacías", "critical",
             "'PermitEmptyPasswords no'", self.c_ssh_empty),
            ("NET-001", "Cortafuegos del host inactivo", "medium",
             "Activar ufw/firewalld/nftables con política de denegación por defecto", self.c_firewall),
            ("NET-002", "Servicios de riesgo expuestos a la red", "high",
             "Restringir a localhost o filtrar con cortafuegos", self.c_risky_ports),
            ("NET-003", "Reenvío IP habilitado", "low",
             "net.ipv4.ip_forward=0 salvo que sea un router", self.c_ip_forward),
            ("NET-004", "SYN cookies deshabilitadas", "low",
             "net.ipv4.tcp_syncookies=1", self.c_syncookies),
            ("KRN-001", "ASLR no está completamente habilitado", "medium",
             "kernel.randomize_va_space=2", self.c_aslr),
            ("KRN-002", "Punteros del kernel expuestos (kptr_restrict)", "low",
             "kernel.kptr_restrict=1", self.c_kptr),
            ("KRN-003", "dmesg accesible a usuarios sin privilegios", "low",
             "kernel.dmesg_restrict=1", self.c_dmesg),
            ("KRN-004", "Volcados de memoria de procesos SUID permitidos", "low",
             "fs.suid_dumpable=0", self.c_suid_dump),
            ("ACC-001", "Cuentas con contraseña vacía", "critical",
             "Bloquear la cuenta: passwd -l <usuario>", self.c_empty_passwords),
            ("ACC-002", "Cuentas con UID 0 además de root", "critical",
             "Eliminar o reasignar UID de la cuenta", self.c_uid0),
            ("ACC-003", "Reglas sudo NOPASSWD globales", "medium",
             "Eliminar NOPASSWD: ALL de sudoers", self.c_sudo_nopasswd),
            ("ACC-004", "Caducidad de contraseñas excesiva", "low",
             "PASS_MAX_DAYS <= 365 en /etc/login.defs", self.c_pass_max_days),
            ("FS-001", "Permisos inseguros en /etc/shadow", "high",
             "chmod 640 /etc/shadow; chown root:shadow /etc/shadow", self.c_shadow_perms),
            ("FS-002", "/etc/passwd escribible por otros", "critical",
             "chmod 644 /etc/passwd", self.c_passwd_perms),
            ("FS-003", "Ficheros escribibles por cualquiera en rutas del sistema", "high",
             "chmod o-w sobre los ficheros listados", self.c_world_writable),
            ("FS-004", "Binarios SUID peligrosos (GTFOBins)", "high",
             "chmod u-s sobre los binarios listados", self.c_dangerous_suid),
            ("FS-005", "/tmp sin noexec", "low", "Montar /tmp con nodev,nosuid,noexec", self.c_tmp_noexec),
            ("FS-006", "Directorios home accesibles por otros", "medium",
             "chmod 750 sobre los homes listados", self.c_home_perms),
            ("SYS-001", "Actualizaciones automáticas de seguridad no configuradas", "low",
             "Instalar unattended-upgrades / dnf-automatic", self.c_auto_updates),
            ("SYS-002", "Socket de Docker accesible por cualquiera", "high",
             "chmod 660 /var/run/docker.sock", self.c_docker_sock),
            ("SYS-003", "PATH de root contiene directorios inseguros", "medium",
             "Eliminar '.' y rutas escribibles del PATH", self.c_root_path),
            ("SYS-004", "Auditoría del sistema (auditd) no activa", "low",
             "Instalar y habilitar auditd", self.c_auditd),
        ]

    # ---------------------------------------------------------------- checks
    def c_ssh_root(self):
        if not os.path.exists("/etc/ssh/sshd_config"):
            return "na", "sshd no instalado"
        v = _sshd_option("PermitRootLogin")
        return ("fail", f"PermitRootLogin={v}") if v == "yes" else ("pass", f"PermitRootLogin={v or 'default'}")

    def c_ssh_password(self):
        if not os.path.exists("/etc/ssh/sshd_config"):
            return "na", "sshd no instalado"
        v = _sshd_option("PasswordAuthentication")
        return ("pass", "PasswordAuthentication=no") if v == "no" else ("fail", f"PasswordAuthentication={v or 'yes (default)'}")

    def c_ssh_empty(self):
        if not os.path.exists("/etc/ssh/sshd_config"):
            return "na", "sshd no instalado"
        v = _sshd_option("PermitEmptyPasswords")
        return ("fail", "PermitEmptyPasswords=yes") if v == "yes" else ("pass", "")

    def c_firewall(self):
        code, out = run_cmd(["ufw", "status"])
        if code == 0 and "Status: active" in out:
            return "pass", "ufw activo"
        code, out = run_cmd(["firewall-cmd", "--state"])
        if code == 0 and "running" in out:
            return "pass", "firewalld activo"
        code, out = run_cmd(["nft", "list", "ruleset"])
        if code == 0 and ("drop" in out or "reject" in out):
            return "pass", "reglas nftables con filtrado"
        code, out = run_cmd(["iptables", "-S"])
        if code == 0 and ("-P INPUT DROP" in out or " -j DROP" in out or " -j REJECT" in out):
            return "pass", "reglas iptables con filtrado"
        return "fail", "No se detecta política de filtrado de entrada"

    def c_risky_ports(self):
        exposed = []
        try:
            for c in psutil.net_connections(kind="inet"):
                if c.status == psutil.CONN_LISTEN and c.laddr and c.laddr.port in RISKY_PORTS \
                        and c.laddr.ip not in ("127.0.0.1", "::1"):
                    exposed.append(f"{RISKY_PORTS[c.laddr.port]} ({c.laddr.ip}:{c.laddr.port})")
        except (psutil.AccessDenied, OSError):
            return "na", "sin permisos para listar sockets"
        return ("fail", ", ".join(sorted(set(exposed)))) if exposed else ("pass", "")

    def c_ip_forward(self):
        return ("fail", "ip_forward=1") if _sysctl("net.ipv4.ip_forward") == "1" else ("pass", "")

    def c_syncookies(self):
        v = _sysctl("net.ipv4.tcp_syncookies")
        return ("na", "") if v is None else (("pass", "") if v == "1" else ("fail", f"tcp_syncookies={v}"))

    def c_aslr(self):
        v = _sysctl("kernel.randomize_va_space")
        return ("pass", "") if v == "2" else ("fail", f"randomize_va_space={v}")

    def c_kptr(self):
        v = _sysctl("kernel.kptr_restrict")
        return ("fail", "kptr_restrict=0") if v == "0" else ("pass", "")

    def c_dmesg(self):
        v = _sysctl("kernel.dmesg_restrict")
        return ("fail", "dmesg_restrict=0") if v == "0" else ("pass", "")

    def c_suid_dump(self):
        v = _sysctl("fs.suid_dumpable")
        return ("fail", f"suid_dumpable={v}") if v not in (None, "0") else ("pass", "")

    def c_empty_passwords(self):
        shadow = read_text("/etc/shadow")
        if shadow is None:
            return "na", "sin acceso a /etc/shadow"
        users = [ln.split(":")[0] for ln in shadow.splitlines() if ln.count(":") > 1 and ln.split(":")[1] == ""]
        return ("fail", ", ".join(users)) if users else ("pass", "")

    def c_uid0(self):
        users = [ln.split(":")[0] for ln in (read_text("/etc/passwd") or "").splitlines()
                 if ln.count(":") >= 6 and ln.split(":")[2] == "0" and ln.split(":")[0] != "root"]
        return ("fail", ", ".join(users)) if users else ("pass", "")

    def c_sudo_nopasswd(self):
        hits = []
        for path in ["/etc/sudoers"] + glob.glob("/etc/sudoers.d/*"):
            for line in (read_text(path) or "").splitlines():
                s = line.strip()
                if not s.startswith("#") and re.search(r"NOPASSWD:\s*ALL", s):
                    hits.append(f"{path}: {s}")
        return ("fail", "; ".join(hits)[:500]) if hits else ("pass", "")

    def c_pass_max_days(self):
        text = read_text("/etc/login.defs")
        if text is None:
            return "na", ""
        m = re.search(r"^\s*PASS_MAX_DAYS\s+(\d+)", text, re.M)
        days = int(m.group(1)) if m else 99999
        return ("fail", f"PASS_MAX_DAYS={days}") if days > 365 else ("pass", f"PASS_MAX_DAYS={days}")

    def c_shadow_perms(self):
        try:
            mode = stat.S_IMODE(os.stat("/etc/shadow").st_mode)
        except OSError:
            return "na", ""
        return ("fail", f"modo {mode:04o}") if mode & 0o037 else ("pass", f"modo {mode:04o}")

    def c_passwd_perms(self):
        try:
            mode = stat.S_IMODE(os.stat("/etc/passwd").st_mode)
        except OSError:
            return "na", ""
        return ("fail", f"modo {mode:04o}") if mode & 0o022 else ("pass", "")

    def c_world_writable(self):
        found = []
        for root in ("/etc", "/usr/bin", "/usr/sbin", "/bin", "/sbin", "/usr/local/bin"):
            for dirpath, _, files in os.walk(root):
                for f in files:
                    p = os.path.join(dirpath, f)
                    try:
                        st = os.lstat(p)
                    except OSError:
                        continue
                    if stat.S_ISREG(st.st_mode) and st.st_mode & stat.S_IWOTH:
                        found.append(p)
                if len(found) > 50:
                    break
        return ("fail", ", ".join(found[:20])) if found else ("pass", "")

    def c_dangerous_suid(self):
        found = []
        for root in ("/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/local/bin", "/usr/local/sbin"):
            try:
                entries = os.scandir(root)
            except OSError:
                continue
            with entries:
                for e in entries:
                    try:
                        st = e.stat(follow_symlinks=False)
                    except OSError:
                        continue
                    name = re.sub(r"[\d.]+$", "", e.name)
                    if stat.S_ISREG(st.st_mode) and st.st_mode & stat.S_ISUID and name in DANGEROUS_SUID:
                        found.append(e.path)
        return ("fail", ", ".join(found)) if found else ("pass", "")

    def c_tmp_noexec(self):
        for p in psutil.disk_partitions(all=True):
            if p.mountpoint == "/tmp":
                return ("pass", p.opts) if "noexec" in p.opts else ("fail", p.opts)
        return "fail", "/tmp no es una partición separada"

    def c_home_perms(self):
        bad = []
        for home in glob.glob("/home/*"):
            try:
                mode = stat.S_IMODE(os.stat(home).st_mode)
            except OSError:
                continue
            if mode & 0o007:
                bad.append(f"{home} ({mode:04o})")
        return ("fail", ", ".join(bad)) if bad else ("pass", "")

    def c_auto_updates(self):
        if os.path.exists("/etc/apt/apt.conf.d/20auto-upgrades"):
            txt = read_text("/etc/apt/apt.conf.d/20auto-upgrades") or ""
            return ("pass", "unattended-upgrades") if '"1"' in txt else ("fail", "desactivado")
        if glob.glob("/etc/dnf/automatic.conf") or shutil.which("dnf-automatic"):
            return "pass", "dnf-automatic"
        return "fail", "no configurado"

    def c_docker_sock(self):
        try:
            mode = stat.S_IMODE(os.stat("/var/run/docker.sock").st_mode)
        except OSError:
            return "na", ""
        return ("fail", f"modo {mode:04o}") if mode & 0o006 else ("pass", "")

    def c_root_path(self):
        path = os.environ.get("PATH", "") if os.geteuid() == 0 else ""
        bad = []
        for d in path.split(":"):
            if d in ("", "."):
                bad.append(d or "(vacío)")
                continue
            try:
                if stat.S_IMODE(os.stat(d).st_mode) & 0o002:
                    bad.append(d)
            except OSError:
                continue
        return ("fail", ", ".join(bad)) if bad else ("pass", "")

    def c_auditd(self):
        running = any(p.info["name"] == "auditd" for p in psutil.process_iter(["name"]))
        return ("pass", "") if running else ("fail", "auditd no está en ejecución")

    # ---------------------------------------------------------------- collect
    def run_checks(self) -> list[dict[str, Any]]:
        findings = []
        for cid, title, sev, remediation, fn in self.checks():
            try:
                status, detail = fn()
            except Exception as exc:  # noqa: BLE001
                status, detail = "error", str(exc)
            findings.append({"check_id": cid, "title": title, "severity": sev, "status": status,
                             "detail": detail, "remediation": remediation})
        return findings

    def collect(self) -> list[Event]:
        findings = self.run_checks()
        return [self.event("posture", "assessment", findings=findings, score=posture_score(findings))]


SEV_WEIGHT = {"critical": 25, "high": 12, "medium": 6, "low": 2, "info": 0}


def posture_score(findings: list[dict]) -> int:
    penalty = sum(SEV_WEIGHT.get(f["severity"], 0) for f in findings if f["status"] == "fail")
    return max(0, 100 - penalty)
