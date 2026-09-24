"""Agente de endpoint: ejecuta los sensores, analiza la telemetría localmente,
aplica respuesta automática y sincroniza con el servidor XDR."""
from __future__ import annotations

import logging
import os
import platform
import queue
import socket
import threading
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import psutil

from xdr import __version__
from xdr.collectors import REGISTRY
from xdr.config import Config
from xdr.detection.engine import DetectionEngine
from xdr.detection.intel import IntelStore
from xdr.events import HOSTNAME, Alert, Event
from xdr.response.actions import ResponseActions
from xdr.response.playbooks import Playbook
from xdr.storage import Storage
from xdr.transport import TransportError

log = logging.getLogger("xdr.agent")

NOT_STORED = {"metric"}


def primary_ip() -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("10.255.255.255", 1))
            return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"


class Agent:
    def __init__(self, config: Config, transport: Any = None, collectors: list[str] | None = None):
        self.config = config
        acfg = config.path("agent", {})
        self.data_dir = Path(acfg.get("data_dir"))
        self.data_dir.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.data_dir, 0o700)
        except OSError:
            pass
        self.storage = Storage(self.data_dir / "agent.db")
        self.intel = IntelStore(config.path("detection.ioc_file"))
        self.engine = DetectionEngine(config, self.storage, self.intel)
        server_url = acfg.get("server_url")
        server_host = urlparse(server_url).hostname if server_url else None
        self.actions = ResponseActions(config.path("response", {}), str(self.data_dir), server_host)
        self.actions.scanner = self.scan_path
        self.playbook = Playbook(config.path("response", {}))
        self.transport = transport
        self.queue: queue.Queue[Event] = queue.Queue(maxsize=200000)
        self.dropped = 0
        self._stop = threading.Event()
        self._buf_lock = threading.Lock()
        self._events: list[dict] = []
        self._alerts: list[dict] = []
        self.threads: list[threading.Thread] = []
        self.started = time.time()
        self.intel_version = 0
        self.connected = False
        self.hostname = acfg.get("name") or HOSTNAME
        self.collectors = []
        wanted = collectors
        for name, cls in REGISTRY.items():
            settings = config.path(f"collectors.{name}", {}) or {}
            if wanted is not None and name not in wanted:
                continue
            if wanted is None and not settings.get("enabled", True):
                continue
            c = cls(settings, self.storage, self.emit, config)
            if c.supported():
                self.collectors.append(c)
            else:
                log.info("sensor %s no soportado en esta plataforma", name)

    # ------------------------------------------------------------- pipeline
    def emit(self, event: Event) -> None:
        event.host = self.hostname
        try:
            self.queue.put_nowait(event)
        except queue.Full:
            self.dropped += 1

    def process(self, event: Event) -> list[Alert]:
        """Procesa un evento: detección, respuesta y encolado para envío."""
        alerts = self.engine.analyze(event)
        for alert in alerts:
            for action, params in self.playbook.plan(alert):
                result = self.actions.execute(action, **params)
                result["automatic"] = True
                alert.response.append(dict(result))
            log.warning("ALERTA [%s] %s %s", alert.severity.upper(), alert.rule_id, alert.title)
        with self._buf_lock:
            if event.category not in NOT_STORED:
                self._events.append(event.to_dict())
            self._alerts.extend(a.to_dict() for a in alerts)
        return alerts

    def _pipeline(self) -> None:
        while not self._stop.is_set() or not self.queue.empty():
            try:
                ev = self.queue.get(timeout=0.5)
            except queue.Empty:
                continue
            try:
                self.process(ev)
            except Exception:  # noqa: BLE001
                log.exception("error procesando evento %s/%s", ev.category, ev.action)

    # ------------------------------------------------------------- shipping
    def _register(self) -> None:
        if not self.transport:
            return
        info = self.info()
        res = self.transport.register(info)
        self.connected = True
        log.info("agente registrado en el servidor (id=%s)", res.get("agent_id"))

    def flush(self) -> None:
        with self._buf_lock:
            events, alerts = self._events, self._alerts
            self._events, self._alerts = [], []
        if not self.transport:
            return
        backlog = self.storage.outbox_peek(20)
        try:
            if not self.connected:
                self._register()
            for seq, _kind, payload in backlog:
                self.transport.send(payload.get("events", []), payload.get("alerts", []))
                self.storage.outbox_ack(seq)
            for i in range(0, max(len(events), 1), 2000):
                chunk = events[i:i + 2000]
                self.transport.send(chunk, alerts if i == 0 else [])
            self.connected = True
        except TransportError as exc:
            self.connected = False
            log.warning("servidor no disponible (%s); datos guardados en cola local", exc)
            if events or alerts:
                if self.storage.outbox_size() < 5000:
                    self.storage.outbox_put("batch", {"events": events[-5000:], "alerts": alerts})
                else:
                    self.storage.outbox_put("batch", {"events": [], "alerts": alerts})

    def heartbeat(self) -> None:
        if not self.transport:
            return
        try:
            if not self.connected:
                self._register()
            res = self.transport.heartbeat({"info": self.info(), "intel_version": self.intel_version})
        except TransportError as exc:
            self.connected = False
            log.debug("heartbeat fallido: %s", exc)
            return
        intel = res.get("intel")
        if intel:
            self.intel.merge(intel)
            self.intel_version = res.get("intel_version", self.intel_version)
            log.info("IOCs actualizados desde el servidor (versión %s)", self.intel_version)
        for cmd in res.get("commands", []):
            self.run_command(cmd)

    def run_command(self, cmd: dict) -> dict:
        action, params = cmd.get("action"), cmd.get("params") or {}
        if action == "run_posture":
            posture = next((c for c in self.collectors if c.name == "posture"), None)
            if posture:
                posture.run_once()
                result = {"action": action, "success": True, "message": "evaluación de postura lanzada"}
            else:
                result = {"action": action, "success": False, "message": "sensor de postura no activo"}
        else:
            result = dict(self.actions.execute(action, **params))
        result["manual"] = True
        try:
            self.transport.command_result(cmd["id"], result)
        except TransportError:
            log.warning("no se pudo enviar el resultado del comando %s", cmd.get("id"))
        return result

    def _periodic(self, interval: float, fn: Any) -> None:
        while not self._stop.wait(interval):
            try:
                fn()
            except Exception:  # noqa: BLE001
                log.exception("tarea periódica falló")

    # ------------------------------------------------------------- lifecycle
    def info(self) -> dict[str, Any]:
        return {
            "hostname": self.hostname, "os": platform.system(), "os_release": platform.release(),
            "platform": platform.platform(), "ip": primary_ip(), "version": __version__,
            "started": self.started, "boot_time": psutil.boot_time(),
            "cpu_count": psutil.cpu_count(), "memory": psutil.virtual_memory().total,
            "collectors": [c.status() for c in self.collectors],
            "detection": self.engine.info(), "queue": self.queue.qsize(), "dropped": self.dropped,
            "outbox": self.storage.outbox_size(),
        }

    def start(self) -> None:
        log.info("iniciando agente en %s con sensores: %s", self.hostname,
                 ", ".join(c.name for c in self.collectors))
        try:
            self._register()
        except TransportError as exc:
            log.warning("no se pudo registrar el agente todavía: %s", exc)
        for fn, name in ((self._pipeline, "pipeline"),):
            t = threading.Thread(target=fn, name=name, daemon=True)
            t.start()
            self.threads.append(t)
        acfg = self.config.path("agent", {})
        for interval, fn, name in ((float(acfg.get("ship_interval", 5)), self.flush, "shipper"),
                                   (float(acfg.get("heartbeat_interval", 10)), self.heartbeat, "heartbeat"),
                                   (60.0, self.engine.behavior.flush_baselines, "baselines")):
            t = threading.Thread(target=self._periodic, args=(interval, fn), name=name, daemon=True)
            t.start()
            self.threads.append(t)
        for c in self.collectors:
            c.start()

    def stop(self) -> None:
        for c in self.collectors:
            c.stop()
        self._stop.set()
        for c in self.collectors:
            c.join(timeout=5)
        for t in self.threads:
            t.join(timeout=5)
        self.engine.behavior.flush_baselines()
        self.flush()

    def run_forever(self) -> None:
        self.start()
        try:
            while not self._stop.is_set():
                time.sleep(1)
        except KeyboardInterrupt:
            pass
        finally:
            self.stop()

    # ------------------------------------------------------------- escaneo
    def scan_path(self, path: str) -> list[dict]:
        return scan_path(self.engine, path)


def scan_path(engine: DetectionEngine, path: str, max_files: int = 200000) -> list[dict]:
    """Escaneo bajo demanda de un fichero o directorio (firmas + IOCs)."""
    findings: list[dict] = []
    files: list[str] = []
    if os.path.isfile(path):
        files = [path]
    else:
        for root, dirs, names in os.walk(path):
            dirs[:] = [d for d in dirs if not os.path.islink(os.path.join(root, d))]
            for n in names:
                files.append(os.path.join(root, n))
                if len(files) >= max_files:
                    break
    from xdr.utils import sha256_file
    for f in files:
        digest = sha256_file(f, engine.signatures.max_size)
        ioc = engine.intel.lookup_hash(digest)
        if ioc:
            findings.append({"path": f, "type": "ioc", "name": ioc, "severity": "critical",
                             "sha256": digest})
        for res in engine.signatures.scan_file(f):
            sig = res["signature"]
            findings.append({"path": f, "type": "signature", "name": sig.name, "id": sig.id,
                             "severity": sig.severity, "matches": res["hits"], "sha256": digest})
    return findings
