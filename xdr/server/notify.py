"""Integraciones salientes: webhooks (Slack/Teams/genérico) y syslog CEF (SIEM)."""
from __future__ import annotations

import json
import logging
import queue
import socket
import threading
import urllib.request
from typing import Any

from xdr.events import severity_at_least

log = logging.getLogger("xdr.notify")

CEF_SEV = {"info": 1, "low": 3, "medium": 5, "high": 8, "critical": 10}


def _cef_escape(v: Any) -> str:
    return str(v).replace("\\", "\\\\").replace("=", "\\=").replace("\n", " ")


def to_cef(alert: dict) -> str:
    data = (alert.get("event") or {}).get("data") or {}
    ext = {
        "rt": int(alert.get("timestamp", 0) * 1000), "dhost": alert.get("host"),
        "cs1Label": "mitre", "cs1": ",".join(alert.get("mitre") or []),
        "cs2Label": "tactic", "cs2": alert.get("tactic", ""),
        "msg": alert.get("description", ""), "externalId": alert.get("id"),
    }
    for src, dst in (("src_ip", "src"), ("remote_ip", "dst"), ("user", "suser"), ("pid", "spid"),
                     ("exe", "filePath"), ("path", "filePath"), ("cmdline", "cs3")):
        if data.get(src):
            ext[dst] = data[src]
    if "cs3" in ext:
        ext["cs3Label"] = "cmdline"
    header = "|".join(["CEF:0", "SentinelXDR", "XDR", "1.0", str(alert.get("rule_id")),
                       str(alert.get("title", "")).replace("|", "/"),
                       str(CEF_SEV.get(alert.get("severity"), 5))])
    return header + "|" + " ".join(f"{k}={_cef_escape(v)}" for k, v in ext.items())


class Notifier:
    def __init__(self, settings: dict[str, Any]):
        self.webhook = settings.get("webhook_url")
        self.webhook_min = settings.get("webhook_min_severity", "high")
        self.syslog = settings.get("syslog")
        self.syslog_min = settings.get("syslog_min_severity", "low")
        self.q: queue.Queue[dict] = queue.Queue(maxsize=10000)
        self.sent = 0
        self.errors = 0
        if self.webhook or self.syslog:
            threading.Thread(target=self._worker, name="notifier", daemon=True).start()

    def notify(self, alert: dict) -> None:
        if not (self.webhook or self.syslog):
            return
        try:
            self.q.put_nowait(alert)
        except queue.Full:
            self.errors += 1

    def _worker(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) if self.syslog else None
        target = None
        if self.syslog:
            host, _, port = self.syslog.partition(":")
            target = (host, int(port or 514))
        while True:
            alert = self.q.get()
            sev = alert.get("severity", "info")
            try:
                if sock and target and severity_at_least(sev, self.syslog_min):
                    sock.sendto(f"<{8 * 13 + 4}>{to_cef(alert)}".encode(), target)
                    self.sent += 1
                if self.webhook and severity_at_least(sev, self.webhook_min):
                    text = (f"[SentinelXDR] {sev.upper()} en {alert.get('host')}: {alert.get('title')}"
                            f" ({alert.get('rule_id')})")
                    body = json.dumps({"text": text, "alert": alert}, default=str).encode()
                    req = urllib.request.Request(self.webhook, data=body, method="POST",
                                                 headers={"Content-Type": "application/json"})
                    urllib.request.urlopen(req, timeout=10).close()  # noqa: S310
                    self.sent += 1
            except Exception as exc:  # noqa: BLE001
                self.errors += 1
                log.warning("fallo notificando alerta: %s", exc)
