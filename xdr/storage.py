"""Persistencia en SQLite (thread-safe) para agente y servidor."""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Iterable

from xdr.events import Alert, Event, SEVERITY_SCORE

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id TEXT PRIMARY KEY, ts REAL, host TEXT, category TEXT, action TEXT, data TEXT
);
CREATE INDEX IF NOT EXISTS ix_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS ix_events_cat ON events(category, action);
CREATE INDEX IF NOT EXISTS ix_events_host ON events(host);

CREATE TABLE IF NOT EXISTS alerts (
    id TEXT PRIMARY KEY, ts REAL, host TEXT, rule_id TEXT, title TEXT, severity TEXT,
    sev_score INTEGER, source TEXT, status TEXT, tactic TEXT, incident_id TEXT, body TEXT
);
CREATE INDEX IF NOT EXISTS ix_alerts_ts ON alerts(ts);
CREATE INDEX IF NOT EXISTS ix_alerts_host ON alerts(host);

CREATE TABLE IF NOT EXISTS incidents (
    id TEXT PRIMARY KEY, ts_start REAL, ts_update REAL, title TEXT, severity TEXT,
    status TEXT, score INTEGER, body TEXT
);

CREATE TABLE IF NOT EXISTS agents (
    id TEXT PRIMARY KEY, hostname TEXT, token TEXT, last_seen REAL, isolated INTEGER DEFAULT 0,
    info TEXT
);

CREATE TABLE IF NOT EXISTS commands (
    id TEXT PRIMARY KEY, agent_id TEXT, ts REAL, action TEXT, params TEXT, status TEXT,
    result TEXT, requested_by TEXT, updated REAL
);
CREATE INDEX IF NOT EXISTS ix_commands_agent ON commands(agent_id, status);

CREATE TABLE IF NOT EXISTS posture (
    host TEXT, check_id TEXT, status TEXT, severity TEXT, title TEXT, detail TEXT,
    remediation TEXT, ts REAL, PRIMARY KEY (host, check_id)
);

CREATE TABLE IF NOT EXISTS kv (key TEXT PRIMARY KEY, value TEXT);

CREATE TABLE IF NOT EXISTS baseline (
    ns TEXT, key TEXT, value TEXT, PRIMARY KEY (ns, key)
);

CREATE TABLE IF NOT EXISTS outbox (
    seq INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT, payload TEXT
);
"""


class Storage:
    def __init__(self, path: str | Path):
        self.path = str(path)
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(self.path, check_same_thread=False, timeout=30)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            if self.path != ":memory:":
                self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=NORMAL")
            self._conn.executescript(SCHEMA)
            self._conn.commit()

    # ------------------------------------------------------------------ util
    def execute(self, sql: str, params: Iterable[Any] = ()) -> list[sqlite3.Row]:
        with self._lock:
            cur = self._conn.execute(sql, tuple(params))
            rows = cur.fetchall()
            self._conn.commit()
            return rows

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # -------------------------------------------------------------------- kv
    def kv_get(self, key: str, default: Any = None) -> Any:
        rows = self.execute("SELECT value FROM kv WHERE key=?", (key,))
        return json.loads(rows[0]["value"]) if rows else default

    def kv_set(self, key: str, value: Any) -> None:
        self.execute("INSERT OR REPLACE INTO kv(key, value) VALUES (?, ?)", (key, json.dumps(value)))

    # -------------------------------------------------------------- baseline
    def baseline_load(self, ns: str) -> dict[str, Any]:
        return {r["key"]: json.loads(r["value"]) for r in self.execute(
            "SELECT key, value FROM baseline WHERE ns=?", (ns,))}

    def baseline_exists(self, ns: str) -> bool:
        return bool(self.execute("SELECT 1 FROM baseline WHERE ns=? LIMIT 1", (ns,))) or \
            self.kv_get(f"baseline_init:{ns}", False)

    def baseline_update(self, ns: str, upserts: dict[str, Any], deletes: Iterable[str] = ()) -> None:
        with self._lock:
            if upserts:
                self._conn.executemany(
                    "INSERT OR REPLACE INTO baseline(ns, key, value) VALUES (?,?,?)",
                    [(ns, k, json.dumps(v, default=str)) for k, v in upserts.items()])
            dels = [(ns, k) for k in deletes]
            if dels:
                self._conn.executemany("DELETE FROM baseline WHERE ns=? AND key=?", dels)
            self._conn.commit()
        self.kv_set(f"baseline_init:{ns}", True)

    # ---------------------------------------------------------------- events
    def add_events(self, events: Iterable[Event]) -> None:
        rows = [(e.id, e.timestamp, e.host, e.category, e.action, json.dumps(e.data, default=str))
                for e in events]
        if not rows:
            return
        with self._lock:
            self._conn.executemany(
                "INSERT OR IGNORE INTO events(id, ts, host, category, action, data) VALUES (?,?,?,?,?,?)",
                rows)
            self._conn.commit()

    def query_events(self, *, host: str | None = None, category: str | None = None,
                     action: str | None = None, text: str | None = None,
                     since: float | None = None, limit: int = 200) -> list[dict]:
        sql = "SELECT * FROM events WHERE 1=1"
        params: list[Any] = []
        if host:
            sql += " AND host=?"; params.append(host)
        if category:
            sql += " AND category=?"; params.append(category)
        if action:
            sql += " AND action=?"; params.append(action)
        if since:
            sql += " AND ts>=?"; params.append(since)
        if text:
            sql += " AND data LIKE ?"; params.append(f"%{text}%")
        sql += " ORDER BY ts DESC LIMIT ?"
        params.append(int(limit))
        return [{"id": r["id"], "timestamp": r["ts"], "host": r["host"], "category": r["category"],
                 "action": r["action"], "data": json.loads(r["data"])}
                for r in self.execute(sql, params)]

    def event_counts(self, since: float) -> dict[str, int]:
        rows = self.execute(
            "SELECT category, COUNT(*) c FROM events WHERE ts>=? GROUP BY category", (since,))
        return {r["category"]: r["c"] for r in rows}

    def prune(self, retention_days: float, max_events: int) -> None:
        cutoff = time.time() - retention_days * 86400
        self.execute("DELETE FROM events WHERE ts<?", (cutoff,))
        rows = self.execute("SELECT COUNT(*) c FROM events")
        excess = rows[0]["c"] - max_events
        if excess > 0:
            self.execute(
                "DELETE FROM events WHERE id IN (SELECT id FROM events ORDER BY ts ASC LIMIT ?)",
                (excess,))

    # ---------------------------------------------------------------- alerts
    def add_alert(self, alert: Alert, incident_id: str | None = None) -> None:
        self.execute(
            "INSERT OR REPLACE INTO alerts(id, ts, host, rule_id, title, severity, sev_score, source,"
            " status, tactic, incident_id, body) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (alert.id, alert.timestamp, alert.host, alert.rule_id, alert.title, alert.severity,
             SEVERITY_SCORE.get(alert.severity, 0), alert.source, alert.status, alert.tactic,
             incident_id, json.dumps(alert.to_dict(), default=str)))

    def _row_to_alert(self, r: sqlite3.Row) -> dict:
        body = json.loads(r["body"])
        body["status"] = r["status"]
        body["incident_id"] = r["incident_id"]
        return body

    def get_alert(self, alert_id: str) -> dict | None:
        rows = self.execute("SELECT * FROM alerts WHERE id=?", (alert_id,))
        return self._row_to_alert(rows[0]) if rows else None

    def query_alerts(self, *, host: str | None = None, status: str | None = None,
                     min_severity: str | None = None, since: float | None = None,
                     rule_id: str | None = None, incident_id: str | None = None,
                     limit: int = 200) -> list[dict]:
        sql = "SELECT * FROM alerts WHERE 1=1"
        params: list[Any] = []
        if host:
            sql += " AND host=?"; params.append(host)
        if status:
            sql += " AND status=?"; params.append(status)
        if min_severity:
            sql += " AND sev_score>=?"; params.append(SEVERITY_SCORE.get(min_severity, 0))
        if since:
            sql += " AND ts>=?"; params.append(since)
        if rule_id:
            sql += " AND rule_id=?"; params.append(rule_id)
        if incident_id:
            sql += " AND incident_id=?"; params.append(incident_id)
        sql += " ORDER BY ts DESC LIMIT ?"
        params.append(int(limit))
        return [self._row_to_alert(r) for r in self.execute(sql, params)]

    def set_alert_status(self, alert_id: str, status: str) -> bool:
        rows = self.execute("SELECT id FROM alerts WHERE id=?", (alert_id,))
        if not rows:
            return False
        self.execute("UPDATE alerts SET status=? WHERE id=?", (status, alert_id))
        return True

    def set_alert_incident(self, alert_id: str, incident_id: str) -> None:
        self.execute("UPDATE alerts SET incident_id=? WHERE id=?", (incident_id, alert_id))

    def alert_stats(self, since: float) -> dict[str, Any]:
        sev = {r["severity"]: r["c"] for r in self.execute(
            "SELECT severity, COUNT(*) c FROM alerts WHERE ts>=? GROUP BY severity", (since,))}
        status = {r["status"]: r["c"] for r in self.execute(
            "SELECT status, COUNT(*) c FROM alerts GROUP BY status")}
        top = [{"rule_id": r["rule_id"], "title": r["title"], "count": r["c"]} for r in self.execute(
            "SELECT rule_id, title, COUNT(*) c FROM alerts WHERE ts>=? GROUP BY rule_id"
            " ORDER BY c DESC LIMIT 10", (since,))]
        tactics = {r["tactic"]: r["c"] for r in self.execute(
            "SELECT tactic, COUNT(*) c FROM alerts WHERE ts>=? AND tactic!='' GROUP BY tactic",
            (since,))}
        hosts = {r["host"]: r["c"] for r in self.execute(
            "SELECT host, COUNT(*) c FROM alerts WHERE ts>=? GROUP BY host", (since,))}
        return {"by_severity": sev, "by_status": status, "top_rules": top, "by_tactic": tactics,
                "by_host": hosts}

    def alert_timeline(self, since: float, bucket: int) -> list[dict]:
        rows = self.execute(
            "SELECT CAST(ts/? AS INTEGER)*? AS b, severity, COUNT(*) c FROM alerts WHERE ts>=?"
            " GROUP BY b, severity ORDER BY b", (bucket, bucket, since))
        return [{"bucket": r["b"], "severity": r["severity"], "count": r["c"]} for r in rows]

    # ------------------------------------------------------------- incidents
    def upsert_incident(self, inc: dict) -> None:
        self.execute(
            "INSERT OR REPLACE INTO incidents(id, ts_start, ts_update, title, severity, status, score,"
            " body) VALUES (?,?,?,?,?,?,?,?)",
            (inc["id"], inc["ts_start"], inc["ts_update"], inc["title"], inc["severity"],
             inc.get("status", "open"), inc.get("score", 0), json.dumps(inc, default=str)))

    def get_incident(self, inc_id: str) -> dict | None:
        rows = self.execute("SELECT * FROM incidents WHERE id=?", (inc_id,))
        if not rows:
            return None
        body = json.loads(rows[0]["body"])
        body["status"] = rows[0]["status"]
        return body

    def query_incidents(self, status: str | None = None, limit: int = 100) -> list[dict]:
        sql = "SELECT * FROM incidents"
        params: list[Any] = []
        if status:
            sql += " WHERE status=?"; params.append(status)
        sql += " ORDER BY ts_update DESC LIMIT ?"
        params.append(limit)
        out = []
        for r in self.execute(sql, params):
            body = json.loads(r["body"])
            body["status"] = r["status"]
            out.append(body)
        return out

    def set_incident_status(self, inc_id: str, status: str) -> bool:
        inc = self.get_incident(inc_id)
        if not inc:
            return False
        inc["status"] = status
        self.upsert_incident(inc)
        return True

    # ---------------------------------------------------------------- agents
    def upsert_agent(self, agent_id: str, hostname: str, token: str, info: dict) -> None:
        self.execute(
            "INSERT INTO agents(id, hostname, token, last_seen, info) VALUES (?,?,?,?,?)"
            " ON CONFLICT(id) DO UPDATE SET hostname=excluded.hostname, token=excluded.token,"
            " last_seen=excluded.last_seen, info=excluded.info",
            (agent_id, hostname, token, time.time(), json.dumps(info, default=str)))

    def touch_agent(self, agent_id: str, info: dict | None = None) -> None:
        if info is None:
            self.execute("UPDATE agents SET last_seen=? WHERE id=?", (time.time(), agent_id))
        else:
            self.execute("UPDATE agents SET last_seen=?, info=? WHERE id=?",
                         (time.time(), json.dumps(info, default=str), agent_id))

    def set_agent_isolated(self, agent_id: str, isolated: bool) -> None:
        self.execute("UPDATE agents SET isolated=? WHERE id=?", (1 if isolated else 0, agent_id))

    def get_agent(self, agent_id: str) -> dict | None:
        rows = self.execute("SELECT * FROM agents WHERE id=?", (agent_id,))
        return self._agent_row(rows[0]) if rows else None

    def get_agent_by_token(self, token: str) -> dict | None:
        rows = self.execute("SELECT * FROM agents WHERE token=?", (token,))
        return self._agent_row(rows[0]) if rows else None

    def list_agents(self) -> list[dict]:
        return [self._agent_row(r) for r in self.execute("SELECT * FROM agents ORDER BY hostname")]

    @staticmethod
    def _agent_row(r: sqlite3.Row) -> dict:
        return {"id": r["id"], "hostname": r["hostname"], "last_seen": r["last_seen"],
                "isolated": bool(r["isolated"]), "token": r["token"],
                "info": json.loads(r["info"] or "{}")}

    # -------------------------------------------------------------- commands
    def add_command(self, cmd: dict) -> None:
        self.execute(
            "INSERT INTO commands(id, agent_id, ts, action, params, status, result, requested_by,"
            " updated) VALUES (?,?,?,?,?,?,?,?,?)",
            (cmd["id"], cmd["agent_id"], cmd["ts"], cmd["action"], json.dumps(cmd.get("params", {})),
             cmd.get("status", "pending"), json.dumps(cmd.get("result")), cmd.get("requested_by", ""),
             time.time()))

    def pending_commands(self, agent_id: str) -> list[dict]:
        rows = self.execute(
            "SELECT * FROM commands WHERE agent_id=? AND status='pending' ORDER BY ts", (agent_id,))
        cmds = [self._cmd_row(r) for r in rows]
        for c in cmds:
            self.execute("UPDATE commands SET status='sent', updated=? WHERE id=?", (time.time(), c["id"]))
        return cmds

    def complete_command(self, cmd_id: str, success: bool, result: Any) -> dict | None:
        self.execute("UPDATE commands SET status=?, result=?, updated=? WHERE id=?",
                     ("done" if success else "failed", json.dumps(result, default=str), time.time(),
                      cmd_id))
        rows = self.execute("SELECT * FROM commands WHERE id=?", (cmd_id,))
        return self._cmd_row(rows[0]) if rows else None

    def list_commands(self, limit: int = 100) -> list[dict]:
        return [self._cmd_row(r) for r in self.execute(
            "SELECT * FROM commands ORDER BY ts DESC LIMIT ?", (limit,))]

    @staticmethod
    def _cmd_row(r: sqlite3.Row) -> dict:
        return {"id": r["id"], "agent_id": r["agent_id"], "ts": r["ts"], "action": r["action"],
                "params": json.loads(r["params"] or "{}"), "status": r["status"],
                "result": json.loads(r["result"]) if r["result"] else None,
                "requested_by": r["requested_by"], "updated": r["updated"]}

    # --------------------------------------------------------------- posture
    def set_posture(self, host: str, finding: dict) -> None:
        self.execute(
            "INSERT OR REPLACE INTO posture(host, check_id, status, severity, title, detail,"
            " remediation, ts) VALUES (?,?,?,?,?,?,?,?)",
            (host, finding["check_id"], finding["status"], finding.get("severity", "low"),
             finding.get("title", ""), finding.get("detail", ""), finding.get("remediation", ""),
             time.time()))

    def get_posture(self, host: str | None = None) -> list[dict]:
        sql, params = "SELECT * FROM posture", []
        if host:
            sql += " WHERE host=?"; params.append(host)
        sql += " ORDER BY host, status DESC, check_id"
        return [dict(r) for r in self.execute(sql, params)]

    # ---------------------------------------------------------------- outbox
    def outbox_put(self, kind: str, payload: dict) -> None:
        self.execute("INSERT INTO outbox(kind, payload) VALUES (?, ?)",
                     (kind, json.dumps(payload, default=str)))

    def outbox_peek(self, limit: int = 500) -> list[tuple[int, str, dict]]:
        rows = self.execute("SELECT * FROM outbox ORDER BY seq LIMIT ?", (limit,))
        return [(r["seq"], r["kind"], json.loads(r["payload"])) for r in rows]

    def outbox_ack(self, max_seq: int) -> None:
        self.execute("DELETE FROM outbox WHERE seq<=?", (max_seq,))

    def outbox_size(self) -> int:
        return self.execute("SELECT COUNT(*) c FROM outbox")[0]["c"]
