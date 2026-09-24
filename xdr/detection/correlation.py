"""Correlación de alertas en incidentes (por host y entre hosts) con
valoración de la progresión en la cadena de ataque MITRE ATT&CK."""
from __future__ import annotations

import threading
import time
from typing import Any

from xdr.detection.mitre import KILL_CHAIN, TACTICS
from xdr.events import Alert, SEVERITY_SCORE, max_severity, new_id
from xdr.storage import Storage

SEV_POINTS = {"info": 0, "low": 5, "medium": 15, "high": 35, "critical": 60}
ENTITY_FIELDS = ("src_ip", "remote_ip", "sha256", "exe_hash", "user")
IGNORED_ENTITIES = {"", None, "127.0.0.1", "::1", "local", "?", "root"}


def alert_entities(alert: dict) -> set[str]:
    ents: set[str] = set()
    ev = (alert.get("event") or {}).get("data") or {}
    ctx = alert.get("context") or {}
    for f in ENTITY_FIELDS:
        for src in (ev, ctx):
            v = src.get(f)
            if isinstance(v, str) and v not in IGNORED_ENTITIES:
                ents.add(f"{'hash' if 'sha' in f or 'hash' in f else f}:{v}")
    if ctx.get("ioc"):
        ents.add(f"ioc:{ctx['ioc']}")
    return ents


class CorrelationEngine:
    def __init__(self, storage: Storage, window: float = 3600):
        self.storage = storage
        self.window = window
        self.lock = threading.Lock()

    def _open_incidents(self) -> list[dict]:
        now = time.time()
        return [i for i in self.storage.query_incidents(limit=500)
                if i.get("status") != "closed" and now - i["ts_update"] <= self.window]

    def process(self, alert: Alert) -> tuple[dict | None, list[Alert]]:
        """Asigna la alerta a un incidente. Devuelve (incidente, alertas de correlación)."""
        if alert.severity == "info":
            return None, []
        a = alert.to_dict()
        ents = alert_entities(a)
        extra: list[Alert] = []
        with self.lock:
            incidents = self._open_incidents()
            target = None
            for inc in incidents:
                if alert.host in inc["hosts"]:
                    target = inc
                    break
            cross = None
            for inc in incidents:
                shared = ents & set(inc.get("entities", []))
                if shared and alert.host not in inc["hosts"]:
                    cross = (inc, shared)
                    break
            if target is None and cross is not None:
                target = cross[0]
            if target is None:
                target = {"id": new_id(), "ts_start": alert.timestamp, "ts_update": alert.timestamp,
                          "title": "", "severity": alert.severity, "status": "open", "hosts": [],
                          "alert_ids": [], "tactics": [], "mitre": [], "entities": [], "score": 0,
                          "timeline": [], "rules": []}
            elif cross is not None and target is not cross[0]:
                # fusionar incidente de otro host que comparte entidades (campaña)
                other = cross[0]
                target["hosts"] = sorted(set(target["hosts"]) | set(other["hosts"]))
                target["alert_ids"] += other["alert_ids"]
                target["timeline"] = sorted(target["timeline"] + other["timeline"],
                                            key=lambda t: t["ts"])[-200:]
                target["tactics"] = sorted(set(target["tactics"]) | set(other["tactics"]),
                                           key=_tactic_order)
                target["entities"] = sorted(set(target["entities"]) | set(other["entities"]))
                target["score"] += other["score"]
                target["severity"] = max_severity(target["severity"], other["severity"])
                for aid in other["alert_ids"]:
                    self.storage.set_alert_incident(aid, target["id"])
                other["status"] = "closed"
                other["merged_into"] = target["id"]
                self.storage.upsert_incident(other)

            prev_tactics = set(target["tactics"])
            prev_hosts = set(target["hosts"])
            target["hosts"] = sorted(prev_hosts | {alert.host})
            target["alert_ids"].append(alert.id)
            if alert.tactic:
                target["tactics"] = sorted(prev_tactics | {alert.tactic}, key=_tactic_order)
            target["mitre"] = sorted(set(target["mitre"]) | set(alert.mitre))
            target["entities"] = sorted(set(target["entities"]) | ents)[:200]
            target["rules"] = sorted(set(target.get("rules", [])) | {alert.rule_id})
            target["ts_update"] = max(target["ts_update"], alert.timestamp)
            target["score"] += SEV_POINTS.get(alert.severity, 0)
            target["severity"] = max_severity(target["severity"], alert.severity)
            target["timeline"].append({"ts": alert.timestamp, "alert_id": alert.id,
                                       "title": alert.title, "severity": alert.severity,
                                       "host": alert.host, "tactic": alert.tactic})
            target["timeline"] = target["timeline"][-200:]

            n_tactics = len(target["tactics"])
            if n_tactics >= 3 and len(prev_tactics) < 3:
                target["severity"] = "critical"
                extra.append(Alert(
                    rule_id="CORR-KILLCHAIN", title="Ataque multi-etapa detectado", severity="critical",
                    source="correlation", host=alert.host, tactic=alert.tactic,
                    description="El incidente abarca varias tácticas: " + ", ".join(
                        TACTICS.get(t, ("", t))[1] for t in target["tactics"]),
                    context={"incident_id": target["id"], "tactics": target["tactics"]},
                    recommended_actions=["isolate_host", "collect_forensics"]))
            if len(target["hosts"]) > 1 and len(prev_hosts) <= 1 and prev_hosts:
                target["severity"] = max_severity(target["severity"], "high")
                extra.append(Alert(
                    rule_id="CORR-MULTIHOST", title="Actividad relacionada en varios equipos",
                    severity="high", source="correlation", host=alert.host, tactic="lateral-movement",
                    mitre=["T1021"], description="Entidades compartidas entre hosts: " +
                    ", ".join(sorted(ents & set(target["entities"]))[:5]),
                    context={"incident_id": target["id"], "hosts": target["hosts"]},
                    recommended_actions=["isolate_host"]))
            target["score"] += 20 * max(0, n_tactics - len(prev_tactics)) if n_tactics > 1 else 0
            target["title"] = self._title(target)
            self.storage.upsert_incident(target)
            for x in extra:
                target["alert_ids"].append(x.id)
            if extra:
                self.storage.upsert_incident(target)
        return target, extra

    @staticmethod
    def _title(inc: dict) -> str:
        hosts = inc["hosts"]
        where = hosts[0] if len(hosts) == 1 else f"{len(hosts)} equipos"
        if len(inc["tactics"]) >= 3:
            return f"Ataque multi-etapa en {where}"
        if inc["tactics"]:
            last = TACTICS.get(inc["tactics"][-1], ("", inc["tactics"][-1]))[1]
            return f"{last} en {where}"
        return f"Actividad sospechosa en {where}"


def _tactic_order(t: str) -> int:
    return KILL_CHAIN.index(t) if t in KILL_CHAIN else len(KILL_CHAIN)


def incident_summary(inc: dict[str, Any]) -> dict[str, Any]:
    return {k: inc.get(k) for k in ("id", "title", "severity", "status", "hosts", "tactics", "score",
                                    "ts_start", "ts_update", "mitre", "rules")} | {
        "alerts": len(inc.get("alert_ids", [])),
        "sev_score": SEVERITY_SCORE.get(inc.get("severity", "info"), 0)}
