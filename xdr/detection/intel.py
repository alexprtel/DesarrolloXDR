"""Inteligencia de amenazas: IOCs (hashes, IPs, dominios, nombres de fichero)
y actualización desde feeds públicos (abuse.ch)."""
from __future__ import annotations

import json
import logging
import re
import threading
import urllib.request
from pathlib import Path
from typing import Any

from xdr.events import Alert, Event
from xdr.utils import ip_in_list, is_valid_ip

log = logging.getLogger("xdr.intel")

DOMAIN_RE = re.compile(r"(?<![A-Za-z0-9_.-])((?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,24})(?![A-Za-z0-9-])")
HASH_FIELDS = ("exe_hash", "sha256")
IP_FIELDS = ("remote_ip", "src_ip")
TEXT_FIELDS = ("cmdline", "content", "added_lines", "raw", "command")

FEEDS = {
    # Botnets C2 (Feodo Tracker)
    "feodo_ips": ("ips", "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"),
    # Hashes de malware recientes (MalwareBazaar)
    "bazaar_sha256": ("sha256", "https://bazaar.abuse.ch/export/txt/sha256/recent/"),
    # URLs maliciosas (URLhaus) -> dominios
    "urlhaus_domains": ("domains", "https://urlhaus.abuse.ch/downloads/hostfile/"),
}


class IntelStore:
    KINDS = ("sha256", "md5", "ips", "cidrs", "domains", "filenames")

    def __init__(self, path: str | None = None):
        self.path = Path(path) if path else None
        self.lock = threading.RLock()
        self.data: dict[str, dict[str, str]] = {k: {} for k in self.KINDS}
        self.version = 0
        if self.path and self.path.is_file():
            self.load(self.path)

    def load(self, path: Path) -> None:
        with open(path, "r", encoding="utf-8") as fh:
            raw = json.load(fh)
        self.merge(raw)

    def merge(self, raw: dict[str, Any]) -> int:
        added = 0
        with self.lock:
            for kind in self.KINDS:
                for key, desc in (raw.get(kind) or {}).items():
                    key = key.strip().lower()
                    if key and key not in self.data[kind]:
                        added += 1
                    self.data[kind][key] = desc
            self.version += 1
        return added

    def add(self, kind: str, value: str, description: str = "") -> None:
        if kind not in self.KINDS:
            raise ValueError(f"tipo de IOC desconocido: {kind}")
        with self.lock:
            self.data[kind][value.strip().lower()] = description or "IOC manual"
            self.version += 1

    def remove(self, kind: str, value: str) -> bool:
        with self.lock:
            found = self.data.get(kind, {}).pop(value.strip().lower(), None) is not None
            self.version += 1
            return found

    def save(self) -> None:
        if not self.path:
            return
        with self.lock:
            tmp = self.path.with_suffix(".tmp")
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(self.data, fh, indent=1, sort_keys=True)
            tmp.replace(self.path)

    def export(self) -> dict[str, dict[str, str]]:
        with self.lock:
            return {k: dict(v) for k, v in self.data.items()}

    def counts(self) -> dict[str, int]:
        with self.lock:
            return {k: len(v) for k, v in self.data.items()}

    # ---------------------------------------------------------------- lookup
    def lookup_hash(self, digest: str | None) -> str | None:
        if not digest:
            return None
        d = digest.lower()
        return self.data["sha256"].get(d) or self.data["md5"].get(d)

    def lookup_ip(self, ip: str | None) -> str | None:
        if not ip or not is_valid_ip(ip):
            return None
        hit = self.data["ips"].get(ip.lower())
        if hit:
            return hit
        for cidr, desc in self.data["cidrs"].items():
            if ip_in_list(ip, [cidr]):
                return desc
        return None

    def lookup_domain(self, domain: str) -> str | None:
        domain = domain.lower().rstrip(".")
        parts = domain.split(".")
        for i in range(len(parts) - 1):
            hit = self.data["domains"].get(".".join(parts[i:]))
            if hit:
                return hit
        return None

    def match_event(self, event: Event) -> list[Alert]:
        alerts: list[Alert] = []
        with self.lock:
            for f in HASH_FIELDS:
                desc = self.lookup_hash(event.get(f))
                if desc:
                    alerts.append(self._alert(event, "IOC-HASH", f"Hash malicioso conocido: {desc}",
                                              "critical", {"ioc_type": "hash", "ioc": event.get(f),
                                                           "field": f, "intel": desc},
                                              ["kill_process", "quarantine_file"], ["T1204"],
                                              "execution"))
            for f in IP_FIELDS:
                ip = event.get(f)
                desc = self.lookup_ip(ip)
                if desc:
                    alerts.append(self._alert(event, "IOC-IP", f"Comunicación con IP maliciosa: {ip}",
                                              "high", {"ioc_type": "ip", "ioc": ip, "field": f,
                                                       "intel": desc},
                                              ["block_ip", "kill_process"], ["T1071"],
                                              "command-and-control"))
            seen: set[str] = set()
            for f in TEXT_FIELDS:
                text = event.get(f)
                if not isinstance(text, str) or not text:
                    continue
                for m in DOMAIN_RE.finditer(text[:20000]):
                    dom = m.group(1).lower()
                    if dom in seen:
                        continue
                    seen.add(dom)
                    desc = self.lookup_domain(dom)
                    if desc:
                        alerts.append(self._alert(event, "IOC-DOMAIN",
                                                  f"Referencia a dominio malicioso: {dom}", "high",
                                                  {"ioc_type": "domain", "ioc": dom, "field": f,
                                                   "intel": desc}, ["kill_process"], ["T1071"],
                                                  "command-and-control"))
            fname = event.get("filename")
            if fname and fname.lower() in self.data["filenames"]:
                desc = self.data["filenames"][fname.lower()]
                alerts.append(self._alert(event, "IOC-FILENAME", f"Nombre de fichero malicioso: {fname}",
                                          "medium", {"ioc_type": "filename", "ioc": fname,
                                                     "intel": desc}, ["quarantine_file"], ["T1204"],
                                          "execution"))
        return alerts

    @staticmethod
    def _alert(event: Event, rule_id: str, title: str, sev: str, ctx: dict, actions: list[str],
               mitre: list[str], tactic: str) -> Alert:
        return Alert(rule_id=rule_id, title=title, severity=sev, source="ioc", host=event.host,
                     description="Coincidencia con inteligencia de amenazas", event=event.to_dict(),
                     context=ctx, recommended_actions=actions, mitre=mitre, tactic=tactic)

    # ----------------------------------------------------------------- feeds
    def update_from_feeds(self, feeds: list[str] | None = None, timeout: int = 30) -> dict[str, Any]:
        results: dict[str, Any] = {}
        for name in feeds or list(FEEDS):
            kind, url = FEEDS[name]
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "SentinelXDR/1.0"})
                with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
                    text = resp.read(50 * 1024 * 1024).decode("utf-8", "replace")
            except Exception as exc:  # noqa: BLE001
                results[name] = f"error: {exc}"
                continue
            entries: dict[str, str] = {}
            for line in text.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if kind == "domains":
                    parts = line.split()
                    value = parts[-1] if parts else ""
                else:
                    value = line.split(",")[0].strip('" ')
                if kind == "ips" and not is_valid_ip(value):
                    continue
                if kind == "sha256" and not re.fullmatch(r"[0-9a-fA-F]{64}", value):
                    continue
                if kind == "domains" and ("." not in value or value in ("localhost",)):
                    continue
                entries[value.lower()] = f"feed:{name}"
            results[name] = self.merge({kind: entries})
        self.save()
        return results
