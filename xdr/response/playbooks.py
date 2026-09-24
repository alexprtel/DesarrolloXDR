"""Playbooks: traduce alertas en acciones de respuesta concretas con sus
parámetros, y decide si se ejecutan automáticamente."""
from __future__ import annotations

from typing import Any

from xdr.events import Alert, severity_at_least
from xdr.response.actions import is_system_path

AUTO_SAFE = {"kill_process", "quarantine_file", "block_ip", "collect_forensics", "kill_top_writer",
             "disable_user", "kill_user_sessions", "isolate_host"}


def build_params(action: str, alert: Alert | dict) -> dict[str, Any] | None:
    a = alert.to_dict() if isinstance(alert, Alert) else alert
    data = (a.get("event") or {}).get("data") or {}
    ctx = a.get("context") or {}
    if action in ("kill_process", "suspend_process"):
        pid = data.get("pid")
        if not pid:
            return None
        return {"pid": pid, "create_time": data.get("create_time")}
    if action == "quarantine_file":
        path = ctx.get("path") or data.get("path")
        exe = data.get("exe")
        # El ejecutable de un proceso solo se aísla si NO es un binario del sistema:
        # una línea de comandos maliciosa en bash no convierte a /usr/bin/bash en malware.
        if not path and exe and not is_system_path(exe):
            path = exe
        return {"path": path} if path else None
    if action == "block_ip":
        ip = ctx.get("src_ip") or data.get("src_ip") or ctx.get("remote_ip") or data.get("remote_ip")
        if not ip and ctx.get("ioc_type") == "ip":
            ip = ctx.get("ioc")
        return {"ip": ip} if ip else None
    if action in ("disable_user", "kill_user_sessions"):
        user = ctx.get("user") or data.get("user") or data.get("name")
        return {"user": user} if user else None
    if action == "collect_forensics":
        return {"reason": f"{a.get('rule_id')}: {a.get('title')}"}
    if action == "kill_top_writer":
        import os
        dirs = list(ctx.get("directories") or [])
        if data.get("path"):
            dirs.append(os.path.dirname(data["path"]))
        return {"directories": sorted(set(dirs))} if dirs else None
    if action in ("isolate_host", "release_host"):
        return {}
    return {}


class Playbook:
    def __init__(self, settings: dict[str, Any]):
        self.enabled = bool(settings.get("enabled", True))
        self.min_severity = settings.get("min_severity", "high")
        self.auto_isolate = bool(settings.get("auto_isolate", False))

    def plan(self, alert: Alert) -> list[tuple[str, dict[str, Any]]]:
        """Acciones a ejecutar automáticamente para esta alerta."""
        if not self.enabled or not severity_at_least(alert.severity, self.min_severity):
            return []
        if (alert.event or {}).get("data", {}).get("simulated"):
            return []
        plan = []
        for action in alert.recommended_actions:
            if action not in AUTO_SAFE:
                continue
            if action == "isolate_host" and not self.auto_isolate:
                continue
            params = build_params(action, alert)
            if params is not None:
                plan.append((action, params))
        return plan
