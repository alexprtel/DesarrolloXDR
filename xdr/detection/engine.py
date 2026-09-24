"""Orquestador de detección: reglas + IOCs + firmas + comportamiento, con
listas de permitidos y deduplicación de alertas."""
from __future__ import annotations

import logging
import threading
import time
from typing import Any

from xdr.config import PACKAGE_DIR, Config, rule_dirs
from xdr.detection.behavior import BehaviorEngine
from xdr.detection.intel import IntelStore
from xdr.detection.rules import RuleEngine
from xdr.detection.signatures import SignatureScanner
from xdr.events import Alert, Event
from xdr.storage import Storage
from xdr.utils import ip_in_list, matches_any

log = logging.getLogger("xdr.detection")

DEDUP_FIELDS = ("exe", "path", "cmdline", "src_ip", "remote_ip", "user", "module", "pid", "name",
                "sha256", "mechanism", "local_port", "interface", "serial")


class DetectionEngine:
    def __init__(self, config: Config, storage: Storage | None = None,
                 intel: IntelStore | None = None):
        det = config.path("detection", {})
        self.config = config
        self.rules = RuleEngine(rule_dirs(self.config))
        self.intel = intel or IntelStore(det.get("ioc_file"))
        self.signatures = SignatureScanner(det.get("signatures_file"),
                                           config.path("collectors.malware_scan.max_size",
                                                       20 * 1024 * 1024))
        self.behavior = BehaviorEngine(det, storage)
        allow = det.get("allowlist", {}) or {}
        self.allow_procs = set(allow.get("processes") or [])
        self.allow_ips = list(allow.get("ips") or [])
        self.allow_paths = list(allow.get("paths") or [])
        # Autoexclusión: los ficheros del propio XDR (BD, IOCs, cuarentena, forense,
        # reglas) contienen por diseño cadenas maliciosas y no deben analizarse.
        self.self_paths = [str(p).rstrip("/") + "/" for p in (
            config.path("agent.data_dir"), config.path("server.data_dir"),
            config.path("response.quarantine_dir"), PACKAGE_DIR) if p]
        self.dedup_window = float(det.get("dedup_window", 900))
        self._dedup: dict[tuple, float] = {}
        self._lock = threading.Lock()
        self.stats = {"events": 0, "alerts": 0, "suppressed": 0}

    def allowed(self, event: Event) -> bool:
        if event.category in ("file", "persistence"):
            p = event.get("path") or ""
            if any(p.startswith(sp) for sp in self.self_paths):
                return True
        if self.allow_procs:
            for f in ("name", "process"):
                if event.get(f) in self.allow_procs:
                    return True
            exe = event.get("exe")
            if exe and exe in self.allow_procs:
                return True
        if self.allow_paths:
            p = event.get("path") or event.get("exe")
            if p and matches_any(p, self.allow_paths):
                return True
        return False

    def _ip_allowed(self, alert: Alert) -> bool:
        ev = (alert.event or {}).get("data", {})
        for f in ("src_ip", "remote_ip"):
            ip = ev.get(f) or alert.context.get(f)
            if ip and self.allow_ips and ip_in_list(ip, self.allow_ips) and alert.source != "ioc":
                return True
        return False

    def _dedup_key(self, alert: Alert) -> tuple:
        data = (alert.event or {}).get("data", {})
        parts = tuple(str(data.get(f, "")) for f in DEDUP_FIELDS if f != "pid")
        return (alert.rule_id, alert.host) + parts

    def analyze(self, event: Event) -> list[Alert]:
        self.stats["events"] += 1
        if self.allowed(event):
            return []
        alerts: list[Alert] = []
        for source, fn in (("rules", self.rules.analyze), ("intel", self.intel.match_event),
                           ("signatures", self.signatures.match_event),
                           ("behavior", self.behavior.analyze)):
            try:
                alerts.extend(fn(event))
            except Exception:  # noqa: BLE001
                log.exception("fallo en detector %s", source)
        out = []
        now = time.time()
        with self._lock:
            for alert in alerts:
                if self._ip_allowed(alert):
                    continue
                key = self._dedup_key(alert)
                last = self._dedup.get(key)
                if last and now - last < self.dedup_window:
                    self.stats["suppressed"] += 1
                    continue
                self._dedup[key] = now
                out.append(alert)
            if len(self._dedup) > 50000:
                self._dedup = {k: v for k, v in self._dedup.items() if now - v < self.dedup_window}
        self.stats["alerts"] += len(out)
        return out

    def reload(self) -> None:
        det = self.config.path("detection", {})
        self.rules = RuleEngine(rule_dirs(self.config))

    def info(self) -> dict[str, Any]:
        return {"rules": len(self.rules.rules), "signatures": len(self.signatures.signatures),
                "iocs": self.intel.counts(), "learning": self.behavior.learning, **self.stats}
