"""Analítica de comportamiento con estado (UEBA ligera):
fuerza bruta, password spraying, ransomware, beaconing C2, escaneos,
exfiltración y anomalías sobre línea base aprendida."""
from __future__ import annotations

import math
import os
import re
import statistics
import time
from collections import defaultdict, deque
from typing import Any

from xdr.events import Alert, Event
from xdr.storage import Storage

COMPRESSED_EXT = {".zip", ".gz", ".tgz", ".bz2", ".xz", ".7z", ".rar", ".zst", ".jpg", ".jpeg",
                  ".png", ".gif", ".webp", ".mp3", ".mp4", ".mkv", ".avi", ".mov", ".ogg", ".flac",
                  ".pdf", ".docx", ".xlsx", ".pptx", ".odt", ".ods", ".odp", ".jar", ".apk", ".whl",
                  ".deb", ".rpm", ".iso", ".gpg", ".asc", ".pgp", ".enc", ".kdbx", ".woff", ".woff2",
                  ".sqlite", ".db", ".pack", ".idx", ".heic", ".m4a", ".aac", ".epub", ".pyc", ".so",
                  ".bin", ".dat", ".img", ".vmdk", ".qcow2", ".crx", ".xpi", ".cab", ".msi", ".dmg"}

RANSOM_EXT = {".locked", ".lock", ".encrypted", ".enc", ".crypt", ".crypted", ".cry", ".locky",
              ".wncry", ".wnry", ".wcry", ".cerber", ".zepto", ".odin", ".ryk", ".ryuk", ".conti",
              ".lockbit", ".abcd", ".djvu", ".akira", ".blackcat", ".royal", ".hive", ".babyk",
              ".phobos", ".dharma", ".makop", ".stop", ".rhysida", ".play", ".medusa", ".xdrsim"}

RANSOM_NOTE = re.compile(
    r"(readme|read_me|how[_-]?to[_-]?(decrypt|recover|restore)|decrypt|restore[_-]?(my|your)?[_-]?files|"
    r"recover[_-]?files|!!!|ransom|your[_-]?files|_help_|help_decrypt|unlock[_-]?files)",
    re.IGNORECASE)


class _Window:
    """Ventana deslizante de marcas temporales (con valores opcionales)."""

    def __init__(self, seconds: float):
        self.seconds = seconds
        self.items: deque[tuple[float, Any]] = deque()

    def add(self, ts: float, value: Any = None) -> None:
        self.items.append((ts, value))
        self.trim(ts)

    def trim(self, now: float) -> None:
        while self.items and now - self.items[0][0] > self.seconds:
            self.items.popleft()

    def __len__(self) -> int:
        return len(self.items)

    def values(self) -> list[Any]:
        return [v for _, v in self.items]


class BehaviorEngine:
    def __init__(self, cfg: dict[str, Any], storage: Storage | None = None):
        self.cfg = cfg
        self.storage = storage
        bf = cfg.get("bruteforce", {})
        self.bf_threshold = int(bf.get("threshold", 5))
        self.bf_window = float(bf.get("window", 120))
        sp = cfg.get("spray", {})
        self.spray_users = int(sp.get("distinct_users", 5))
        self.spray_window = float(sp.get("window", 300))
        rw = cfg.get("ransomware", {})
        self.rw_threshold = int(rw.get("threshold", 25))
        self.rw_window = float(rw.get("window", 30))
        self.rw_entropy = float(rw.get("entropy", 7.2))
        bc = cfg.get("beaconing", {})
        self.bc_samples = int(bc.get("min_samples", 6))
        self.bc_jitter = float(bc.get("max_jitter", 0.15))
        sc = cfg.get("scan", {})
        self.scan_targets = int(sc.get("distinct_targets", 25))
        self.scan_window = float(sc.get("window", 60))
        ex = cfg.get("exfiltration", {})
        self.ex_z = float(ex.get("zscore", 6.0))
        self.ex_min = float(ex.get("min_bytes", 50 * 1024 * 1024))
        self.learning_period = float(cfg.get("learning_period", 300))

        self.failed: dict[tuple, _Window] = defaultdict(lambda: _Window(self.bf_window))
        self.failed_total: dict[tuple, _Window] = defaultdict(lambda: _Window(3600))
        self.spray: dict[tuple, _Window] = defaultdict(lambda: _Window(self.spray_window))
        self.user_fail_ips: dict[tuple, _Window] = defaultdict(lambda: _Window(self.spray_window))
        self.rw: dict[str, _Window] = defaultdict(lambda: _Window(self.rw_window))
        self.rw_del: dict[str, _Window] = defaultdict(lambda: _Window(self.rw_window))
        self.beacons: dict[tuple, deque] = defaultdict(lambda: deque(maxlen=30))
        self.out_scan: dict[tuple, _Window] = defaultdict(lambda: _Window(self.scan_window))
        self.in_scan: dict[tuple, _Window] = defaultdict(lambda: _Window(self.scan_window))
        self.ex_mean: dict[str, float] = {}
        self.ex_var: dict[str, float] = {}
        self.ex_n: dict[str, int] = defaultdict(int)
        self.fired: dict[tuple, float] = {}

        started = storage.kv_get("learning_started") if storage else None
        if started is None:
            started = time.time()
            if storage:
                storage.kv_set("learning_started", started)
        self.learning_started = float(started)
        self.seen_exes: set[str] = set(storage.baseline_load("seen_exes")) if storage else set()
        self.seen_logins: set[str] = set(storage.baseline_load("seen_logins")) if storage else set()
        self._pending_exes: dict[str, int] = {}
        self._pending_logins: dict[str, int] = {}

    # ----------------------------------------------------------------- helpers
    @property
    def learning(self) -> bool:
        return time.time() - self.learning_started < self.learning_period

    def _once(self, key: tuple, cooldown: float = 600) -> bool:
        now = time.time()
        last = self.fired.get(key)
        if last and now - last < cooldown:
            return False
        self.fired[key] = now
        if len(self.fired) > 20000:
            self.fired = {k: v for k, v in self.fired.items() if now - v < 3600}
        return True

    @staticmethod
    def _alert(event: Event, rule_id: str, title: str, severity: str, description: str,
               mitre: list[str], tactic: str, context: dict, actions: list[str] | None = None) -> Alert:
        return Alert(rule_id=rule_id, title=title, severity=severity, description=description,
                     source="behavior", mitre=mitre, tactic=tactic, host=event.host,
                     event=event.to_dict(), context=context, recommended_actions=actions or [])

    def flush_baselines(self) -> None:
        if not self.storage:
            return
        if self._pending_exes:
            self.storage.baseline_update("seen_exes", self._pending_exes)
            self._pending_exes = {}
        if self._pending_logins:
            self.storage.baseline_update("seen_logins", self._pending_logins)
            self._pending_logins = {}

    # ----------------------------------------------------------------- analyze
    def analyze(self, event: Event) -> list[Alert]:
        handler = {
            ("auth", "login_failed"): self._login_failed,
            ("auth", "login_success"): self._login_success,
            ("file", "modify"): self._file_change,
            ("file", "create"): self._file_change,
            ("file", "rename"): self._file_change,
            ("file", "delete"): self._file_delete,
            ("network", "connection"): self._connection,
            ("metric", "net_io"): self._net_io,
            ("process", "start"): self._process_start,
        }.get((event.category, event.action))
        return handler(event) if handler else []

    # -- autenticación
    def _login_failed(self, ev: Event) -> list[Alert]:
        alerts = []
        ip = ev.get("src_ip") or "local"
        user = ev.get("user") or "?"
        now = ev.timestamp
        w = self.failed[(ev.host, ip)]
        w.add(now, user)
        self.failed_total[(ev.host, ip)].add(now, user)
        if len(w) >= self.bf_threshold and self._once(("bf", ev.host, ip), self.bf_window):
            alerts.append(self._alert(
                ev, "BEH-BRUTEFORCE", f"Fuerza bruta contra {ev.get('service') or 'servicio'} desde {ip}",
                "high", f"{len(w)} intentos fallidos en {int(self.bf_window)}s", ["T1110.001"],
                "credential-access", {"src_ip": ip, "attempts": len(w), "users": sorted(set(w.values()))[:20]},
                ["block_ip"] if ip != "local" else []))
        sp = self.spray[(ev.host, ip)]
        sp.add(now, user)
        users = set(sp.values())
        if len(users) >= self.spray_users and self._once(("spray", ev.host, ip), self.spray_window):
            alerts.append(self._alert(
                ev, "BEH-SPRAY", f"Password spraying desde {ip}", "high",
                f"{len(users)} usuarios distintos atacados", ["T1110.003"], "credential-access",
                {"src_ip": ip, "users": sorted(users)[:30]}, ["block_ip"] if ip != "local" else []))
        uf = self.user_fail_ips[(ev.host, user)]
        uf.add(now, ip)
        ips = set(uf.values())
        if len(ips) >= self.spray_users and self._once(("dbf", ev.host, user), self.spray_window):
            alerts.append(self._alert(
                ev, "BEH-DIST-BRUTEFORCE", f"Fuerza bruta distribuida contra el usuario {user}",
                "medium", f"{len(ips)} IPs de origen distintas", ["T1110"], "credential-access",
                {"user": user, "src_ips": sorted(ips)[:30]}))
        return alerts

    def _login_success(self, ev: Event) -> list[Alert]:
        alerts = []
        ip = ev.get("src_ip") or "local"
        user = ev.get("user") or "?"
        total = self.failed_total.get((ev.host, ip))
        if total is not None:
            total.trim(ev.timestamp)
        if total is not None and len(total) >= self.bf_threshold:
            alerts.append(self._alert(
                ev, "BEH-BRUTEFORCE-SUCCESS", f"Login exitoso tras fuerza bruta: {user} desde {ip}",
                "critical", f"{len(total)} fallos previos desde la misma IP en la última hora",
                ["T1110", "T1078"], "initial-access", {"src_ip": ip, "user": user,
                                                       "failures": len(total)},
                ["block_ip", "disable_user", "kill_user_sessions"]))
        key = f"{ev.host}|{user}|{ip}"
        if key not in self.seen_logins:
            self.seen_logins.add(key)
            self._pending_logins[key] = 1
            if not self.learning and ip != "local" and any(k.startswith(f"{ev.host}|{user}|")
                                                          for k in self.seen_logins if k != key):
                alerts.append(self._alert(
                    ev, "UEBA-NEW-LOGIN-SOURCE", f"Login de {user} desde un origen nunca visto ({ip})",
                    "medium", "Anomalía respecto a la línea base de accesos", ["T1078"],
                    "initial-access", {"src_ip": ip, "user": user}))
        return alerts

    # -- ransomware
    def _file_change(self, ev: Event) -> list[Alert]:
        if ev.get("zone") != "user":
            return []
        alerts = []
        ext = (ev.get("extension") or "").lower()
        fname = ev.get("filename") or ""
        entropy = ev.get("entropy") or 0.0
        suspicious = False
        reason = ""
        if ext in RANSOM_EXT:
            suspicious, reason = True, f"extensión de ransomware {ext}"
        elif ev.action == "rename" and ev.get("old_extension") != ext and ext and \
                ext not in COMPRESSED_EXT and len(ext) > 1:
            suspicious, reason = True, f"renombrado {ev.get('old_extension')} -> {ext}"
        elif entropy >= self.rw_entropy and ext not in COMPRESSED_EXT and (ev.get("size") or 0) > 256:
            suspicious, reason = True, f"entropía {entropy}"
        if suspicious:
            w = self.rw[ev.host]
            w.add(ev.timestamp, ev.get("path"))
            if len(w) >= self.rw_threshold and self._once(("rw", ev.host), 300):
                dirs = sorted({os.path.dirname(p) for p in w.values()})
                alerts.append(self._alert(
                    ev, "BEH-RANSOMWARE", "Actividad de cifrado masivo de ficheros (ransomware)",
                    "critical", f"{len(w)} ficheros sospechosos en {int(self.rw_window)}s ({reason})",
                    ["T1486"], "impact", {"files": w.values()[-20:], "directories": dirs[:20],
                                          "count": len(w)},
                    ["kill_top_writer", "isolate_host", "collect_forensics"]))
        if ev.action in ("create", "rename") and RANSOM_NOTE.search(fname) and \
                ext in (".txt", ".html", ".hta", ".htm", ".rtf", ".url", "") and \
                self._once(("note", ev.host, os.path.dirname(ev.get("path") or "")), 600):
            recent = len(self.rw[ev.host])
            alerts.append(self._alert(
                ev, "BEH-RANSOM-NOTE", f"Posible nota de rescate creada: {fname}",
                "critical" if recent else "medium", "Nombre típico de nota de rescate",
                ["T1486"], "impact", {"path": ev.get("path"), "recent_suspicious": recent},
                ["collect_forensics"]))
        return alerts

    def _file_delete(self, ev: Event) -> list[Alert]:
        if ev.get("zone") != "user":
            return []
        w = self.rw_del[ev.host]
        w.add(ev.timestamp, ev.get("path"))
        if len(w) >= self.rw_threshold * 4 and self._once(("wipe", ev.host), 300):
            return [self._alert(ev, "BEH-MASS-DELETE", "Borrado masivo de ficheros de usuario",
                                "high", f"{len(w)} ficheros eliminados en {int(self.rw_window)}s",
                                ["T1485", "T1070.004"], "impact", {"files": w.values()[-20:]},
                                ["kill_top_writer", "collect_forensics"])]
        return []

    # -- red
    def _connection(self, ev: Event) -> list[Alert]:
        alerts = []
        rip, rport = ev.get("remote_ip"), ev.get("remote_port")
        proc = ev.get("process") or str(ev.get("pid"))
        now = ev.timestamp
        if ev.get("direction") == "outbound" and not ev.get("initial"):
            # Beaconing: conexiones cortas repetidas a intervalos regulares
            if not ev.get("remote_private"):
                key = (ev.host, proc, rip, rport)
                times = self.beacons[key]
                times.append(now)
                if len(times) >= self.bc_samples:
                    intervals = [b - a for a, b in zip(times, list(times)[1:])]
                    mean = statistics.mean(intervals)
                    if mean >= 4:
                        cv = statistics.pstdev(intervals) / mean if mean else 1
                        if cv <= self.bc_jitter and self._once(("beacon",) + key, 3600):
                            alerts.append(self._alert(
                                ev, "BEH-BEACONING", f"Beaconing C2: {proc} -> {rip}:{rport}", "high",
                                f"{len(times)} conexiones cada ~{mean:.0f}s (jitter {cv:.2f})",
                                ["T1071", "T1573"], "command-and-control",
                                {"remote_ip": rip, "remote_port": rport, "interval": round(mean, 1),
                                 "jitter": round(cv, 3), "samples": len(times)},
                                ["kill_process", "block_ip"]))
            # Escaneo saliente / movimiento lateral
            sk = (ev.host, proc)
            w = self.out_scan[sk]
            w.add(now, (rip, rport))
            targets = set(w.values())
            if len(targets) >= self.scan_targets and self._once(("oscan",) + sk, 600):
                ports = {t[1] for t in targets}
                hosts = {t[0] for t in targets}
                lateral = ports <= {22, 445, 3389, 5985, 5986, 135} and len(hosts) >= 5
                alerts.append(self._alert(
                    ev, "BEH-LATERAL-SCAN" if lateral else "BEH-OUTBOUND-SCAN",
                    f"{'Movimiento lateral' if lateral else 'Escaneo de red'} desde el proceso {proc}",
                    "high" if lateral else "medium",
                    f"{len(hosts)} hosts / {len(ports)} puertos en {int(self.scan_window)}s",
                    ["T1021.004", "T1046"] if lateral else ["T1046"],
                    "lateral-movement" if lateral else "discovery",
                    {"hosts": sorted(hosts)[:30], "ports": sorted(ports)[:30]}, ["kill_process"]))
        elif ev.get("direction") == "inbound" and not ev.get("initial"):
            sk = (ev.host, rip)
            w = self.in_scan[sk]
            w.add(now, ev.get("local_port"))
            ports = set(w.values())
            if len(ports) >= max(5, self.scan_targets // 3) and self._once(("iscan",) + sk, 600):
                alerts.append(self._alert(
                    ev, "BEH-INBOUND-SCAN", f"Escaneo de puertos entrante desde {rip}", "medium",
                    f"{len(ports)} puertos locales contactados", ["T1595", "T1046"], "reconnaissance",
                    {"src_ip": rip, "ports": sorted(ports)}, ["block_ip"]))
        return alerts

    def _net_io(self, ev: Event) -> list[Alert]:
        sent = float(ev.get("bytes_sent") or 0)
        host = ev.host
        n = self.ex_n[host]
        mean = self.ex_mean.get(host, sent)
        var = self.ex_var.get(host, 0.0)
        alerts = []
        if n > 30 and not self.learning:
            std = math.sqrt(var) if var > 0 else 1.0
            z = (sent - mean) / max(std, 1024.0)
            if z >= self.ex_z and sent >= self.ex_min and self._once(("exfil", host), 900):
                alerts.append(self._alert(
                    ev, "BEH-EXFILTRATION", "Volumen de subida anómalo (posible exfiltración)",
                    "medium", f"{sent / 1048576:.1f} MB enviados en {ev.get('seconds', 0):.0f}s "
                              f"(z={z:.1f})", ["T1048"], "exfiltration",
                    {"bytes_sent": sent, "zscore": round(z, 1), "baseline_mean": mean},
                    ["collect_forensics"]))
        alpha = 0.05
        diff = sent - mean
        mean += alpha * diff
        var = (1 - alpha) * (var + alpha * diff * diff)
        self.ex_mean[host], self.ex_var[host] = mean, var
        self.ex_n[host] = n + 1
        return alerts

    # -- procesos (línea base de binarios)
    def _process_start(self, ev: Event) -> list[Alert]:
        exe = ev.get("exe")
        if not exe:
            return []
        key = f"{ev.host}|{exe}"
        if key in self.seen_exes:
            return []
        self.seen_exes.add(key)
        self._pending_exes[key] = 1
        if self.learning or ev.get("initial"):
            return []
        return [self._alert(ev, "UEBA-RARE-BINARY", f"Primera ejecución de {os.path.basename(exe)}",
                            "low", f"{exe} nunca se había ejecutado en este host", ["T1204"],
                            "execution", {"exe": exe, "sha256": ev.get("exe_hash")})]
