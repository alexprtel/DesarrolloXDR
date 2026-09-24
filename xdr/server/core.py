"""Núcleo del servidor XDR: registro de agentes, ingesta, correlación
multi-host, cola de comandos de respuesta, inteligencia y consultas."""
from __future__ import annotations

import hmac
import logging
import secrets
import shutil
import threading
import time
from pathlib import Path
from typing import Any

from xdr.config import Config, rule_dirs
from xdr.detection.correlation import CorrelationEngine, incident_summary
from xdr.detection.intel import IntelStore
from xdr.detection.mitre import TACTICS, TECHNIQUES
from xdr.detection.rules import RuleEngine
from xdr.events import Alert, Event, new_id
from xdr.response.playbooks import build_params
from xdr.server.notify import Notifier
from xdr.storage import Storage

log = logging.getLogger("xdr.server")

VALID_ACTIONS = {"kill_process", "suspend_process", "resume_process", "kill_top_writer",
                 "quarantine_file", "restore_file", "delete_file", "block_ip", "unblock_ip",
                 "isolate_host", "release_host", "disable_user", "enable_user",
                 "kill_user_sessions", "collect_forensics", "scan_path", "list_quarantine",
                 "run_posture"}
ALERT_STATUSES = {"open", "investigating", "closed", "false_positive"}


class AuthError(Exception):
    pass


class ServerCore:
    def __init__(self, config: Config):
        self.config = config
        scfg = config.path("server", {})
        self.data_dir = Path(scfg.get("data_dir"))
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.storage = Storage(self.data_dir / "server.db")
        ioc_path = self.data_dir / "iocs.json"
        if not ioc_path.exists() and config.path("detection.ioc_file"):
            try:
                shutil.copy(config.path("detection.ioc_file"), ioc_path)
            except OSError:
                pass
        self.intel = IntelStore(str(ioc_path))
        self.intel.version = int(self.storage.kv_get("intel_version", 1))
        self.correlation = CorrelationEngine(self.storage)
        self.notifier = Notifier(config.path("integrations", {}) or {})
        self.enroll_key = scfg.get("enroll_key", "")
        self.admin_token = scfg.get("admin_token", "")
        self.retention_days = float(scfg.get("retention_days", 30))
        self.max_events = int(scfg.get("max_events", 500000))
        self.started = time.time()
        self._lock = threading.Lock()
        self._last_prune = 0.0

    # ------------------------------------------------------------ seguridad
    def check_admin(self, token: str | None) -> None:
        if not token or not hmac.compare_digest(token, self.admin_token):
            raise AuthError("token de administrador inválido")

    def agent_for_token(self, token: str | None) -> dict:
        if not token:
            raise AuthError("token de agente ausente")
        agent = self.storage.get_agent_by_token(token)
        if not agent:
            raise AuthError("token de agente inválido")
        return agent

    # --------------------------------------------------------------- agentes
    def register(self, info: dict, enroll_key: str, token: str | None = None) -> dict:
        if not hmac.compare_digest(str(enroll_key or ""), str(self.enroll_key)):
            raise AuthError("clave de enrolamiento inválida")
        hostname = str(info.get("hostname") or "desconocido")[:200]
        existing = self.storage.get_agent_by_token(token) if token else None
        if existing:
            agent_id, tok = existing["id"], existing["token"]
        else:
            same = [a for a in self.storage.list_agents() if a["hostname"] == hostname]
            agent_id = same[0]["id"] if same else new_id()
            tok = secrets.token_urlsafe(32)
        self.storage.upsert_agent(agent_id, hostname, tok, info)
        return {"agent_id": agent_id, "token": tok}

    def heartbeat(self, agent_id: str, status: dict) -> dict:
        self.storage.touch_agent(agent_id, status.get("info"))
        out: dict[str, Any] = {"commands": self.storage.pending_commands(agent_id),
                               "intel_version": self.intel.version}
        if int(status.get("intel_version") or 0) < self.intel.version:
            out["intel"] = self.intel.export()
        return out

    def command_result(self, agent_id: str, cmd_id: str, result: dict) -> dict:
        cmd = self.storage.complete_command(cmd_id, bool(result.get("success")), result)
        if cmd and result.get("success"):
            if cmd["action"] == "isolate_host":
                self.storage.set_agent_isolated(agent_id, True)
            elif cmd["action"] == "release_host":
                self.storage.set_agent_isolated(agent_id, False)
        return {"ok": True}

    # ---------------------------------------------------------------- ingesta
    def ingest(self, agent_id: str, events: list[dict], alerts: list[dict]) -> dict:
        agent = self.storage.get_agent(agent_id)
        hostname = agent["hostname"] if agent else "desconocido"
        evs = []
        for d in events:
            try:
                ev = Event.from_dict(d)
            except (KeyError, TypeError):
                continue
            ev.host = hostname
            if ev.category == "posture" and ev.action == "assessment":
                for f in ev.data.get("findings", []):
                    self.storage.set_posture(hostname, f)
                self.storage.kv_set(f"posture_score:{hostname}", ev.data.get("score"))
            evs.append(ev)
        self.storage.add_events(evs)
        stored = 0
        for d in alerts:
            try:
                alert = Alert.from_dict(d)
            except TypeError:
                continue
            alert.host = hostname
            self.add_alert(alert, agent_id)
            stored += 1
        self.storage.touch_agent(agent_id)
        self._maybe_prune()
        return {"ok": True, "events": len(evs), "alerts": stored}

    def add_alert(self, alert: Alert, agent_id: str | None = None) -> None:
        with self._lock:
            incident, extra = self.correlation.process(alert)
            self.storage.add_alert(alert, incident["id"] if incident else None)
            self.notifier.notify(alert.to_dict())
            for x in extra:
                self.storage.add_alert(x, incident["id"] if incident else None)
                self.notifier.notify(x.to_dict())
                log.warning("CORRELACIÓN [%s] %s", x.severity.upper(), x.title)
                if agent_id and "isolate_host" in x.recommended_actions and \
                        self.config.path("response.auto_isolate", False):
                    self.queue_command(agent_id, "isolate_host", {}, "auto-correlación")

    def _maybe_prune(self) -> None:
        if time.time() - self._last_prune > 600:
            self._last_prune = time.time()
            self.storage.prune(self.retention_days, self.max_events)

    # ------------------------------------------------------------- respuesta
    def queue_command(self, agent_id: str, action: str, params: dict, requested_by: str = "admin") -> dict:
        if action not in VALID_ACTIONS:
            raise ValueError(f"acción no válida: {action}")
        if not self.storage.get_agent(agent_id):
            raise ValueError("agente desconocido")
        cmd = {"id": new_id(), "agent_id": agent_id, "ts": time.time(), "action": action,
               "params": params or {}, "status": "pending", "requested_by": requested_by}
        self.storage.add_command(cmd)
        return cmd

    def respond_to_alert(self, alert_id: str, action: str, requested_by: str = "admin") -> dict:
        alert = self.storage.get_alert(alert_id)
        if not alert:
            raise ValueError("alerta no encontrada")
        agent = next((a for a in self.storage.list_agents() if a["hostname"] == alert["host"]), None)
        if not agent:
            raise ValueError("no hay agente para el host de la alerta")
        params = build_params(action, alert)
        if params is None:
            raise ValueError(f"la alerta no tiene datos para ejecutar {action}")
        if alert.get("status") == "open":
            self.storage.set_alert_status(alert_id, "investigating")
        return self.queue_command(agent["id"], action, params, requested_by)

    # ----------------------------------------------------------- inteligencia
    def add_ioc(self, kind: str, value: str, description: str) -> dict:
        self.intel.add(kind, value, description)
        self._bump_intel()
        return {"ok": True, "counts": self.intel.counts()}

    def remove_ioc(self, kind: str, value: str) -> dict:
        found = self.intel.remove(kind, value)
        self._bump_intel()
        return {"ok": found}

    def update_feeds(self) -> dict:
        res = self.intel.update_from_feeds()
        self._bump_intel()
        return res

    def _bump_intel(self) -> None:
        self.intel.version += 1
        self.storage.kv_set("intel_version", self.intel.version)
        self.intel.save()

    # -------------------------------------------------------------- consultas
    def agents(self) -> list[dict]:
        now = time.time()
        out = []
        for a in self.storage.list_agents():
            a = dict(a)
            a.pop("token", None)
            a["online"] = now - (a["last_seen"] or 0) < 60
            a["posture_score"] = self.storage.kv_get(f"posture_score:{a['hostname']}")
            a["open_alerts"] = len(self.storage.query_alerts(host=a["hostname"], status="open",
                                                             limit=1000))
            out.append(a)
        return out

    def overview(self, hours: float = 24) -> dict:
        since = time.time() - hours * 3600
        stats = self.storage.alert_stats(since)
        agents = self.agents()
        incidents = [incident_summary(i) for i in self.storage.query_incidents(limit=200)]
        open_inc = [i for i in incidents if i["status"] != "closed"]
        scores = [a["posture_score"] for a in agents if a["posture_score"] is not None]
        sev = stats["by_severity"]
        risk = min(100, sev.get("critical", 0) * 25 + sev.get("high", 0) * 10 +
                   sev.get("medium", 0) * 3 + sev.get("low", 0))
        bucket = 3600 if hours > 6 else 600
        return {
            "generated": time.time(), "hours": hours,
            "agents": {"total": len(agents), "online": sum(a["online"] for a in agents),
                       "isolated": sum(a["isolated"] for a in agents)},
            "alerts": stats, "events": self.storage.event_counts(since),
            "incidents": {"open": len(open_inc), "critical": sum(1 for i in open_inc
                                                                   if i["severity"] == "critical"),
                          "recent": open_inc[:8]},
            "posture": {"average": round(sum(scores) / len(scores)) if scores else None},
            "risk_score": risk,
            "timeline": self.storage.alert_timeline(since, bucket), "bucket": bucket,
            "tactics": {k: {"id": v[0], "name": v[1]} for k, v in TACTICS.items()},
            "intel": self.intel.counts(), "notifier": {"sent": self.notifier.sent,
                                                        "errors": self.notifier.errors},
        }

    def incidents(self, status: str | None = None) -> list[dict]:
        return [incident_summary(i) for i in self.storage.query_incidents(status=status)]

    def incident(self, inc_id: str) -> dict | None:
        inc = self.storage.get_incident(inc_id)
        if not inc:
            return None
        inc["alerts"] = self.storage.query_alerts(incident_id=inc_id, limit=500)
        inc["mitre_names"] = {t: TECHNIQUES.get(t, "") for t in inc.get("mitre", [])}
        return inc

    def set_incident_status(self, inc_id: str, status: str) -> bool:
        if status not in ALERT_STATUSES:
            raise ValueError("estado inválido")
        ok = self.storage.set_incident_status(inc_id, status)
        if ok and status in ("closed", "false_positive"):
            for a in self.storage.query_alerts(incident_id=inc_id, limit=1000):
                self.storage.set_alert_status(a["id"], status)
        return ok

    def set_alert_status(self, alert_id: str, status: str) -> bool:
        if status not in ALERT_STATUSES:
            raise ValueError("estado inválido")
        return self.storage.set_alert_status(alert_id, status)

    def rules(self) -> list[dict]:
        try:
            engine = RuleEngine(rule_dirs(self.config))
        except Exception as exc:  # noqa: BLE001
            return [{"error": str(exc)}]
        return [r.summary() for r in engine.rules]

    def mitre_matrix(self, hours: float = 24 * 7) -> dict:
        since = time.time() - hours * 3600
        alerts = self.storage.query_alerts(since=since, limit=5000)
        matrix: dict[str, dict[str, int]] = {t: {} for t in TACTICS}
        for a in alerts:
            tac = a.get("tactic") or ""
            for tech in a.get("mitre") or []:
                matrix.setdefault(tac, {})
                matrix[tac][tech] = matrix[tac].get(tech, 0) + 1
        return {"tactics": {k: {"id": v[0], "name": v[1]} for k, v in TACTICS.items()},
                "matrix": matrix, "techniques": TECHNIQUES}
