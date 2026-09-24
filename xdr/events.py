"""Modelo de datos común: eventos de telemetría y alertas."""
from __future__ import annotations

import socket
import time
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any

SEVERITIES = ["info", "low", "medium", "high", "critical"]
SEVERITY_SCORE = {s: i for i, s in enumerate(SEVERITIES)}

HOSTNAME = socket.gethostname()


def severity_at_least(severity: str, minimum: str) -> bool:
    return SEVERITY_SCORE.get(severity, 0) >= SEVERITY_SCORE.get(minimum, 0)


def max_severity(*severities: str) -> str:
    return max(severities, key=lambda s: SEVERITY_SCORE.get(s, 0))


def new_id() -> str:
    return uuid.uuid4().hex


@dataclass
class Event:
    """Evento de telemetría generado por un sensor."""

    category: str
    action: str
    data: dict[str, Any] = field(default_factory=dict)
    host: str = HOSTNAME
    timestamp: float = field(default_factory=time.time)
    id: str = field(default_factory=new_id)

    def get(self, path: str, default: Any = None) -> Any:
        """Resuelve un campo: 'category', 'action', 'host' o una ruta con
        puntos dentro de data (p.ej. 'parent.name')."""
        if path in ("category", "action", "host", "timestamp", "id"):
            return getattr(self, path)
        if path.startswith("data."):
            path = path[5:]
        cur: Any = self.data
        for part in path.split("."):
            if isinstance(cur, dict) and part in cur:
                cur = cur[part]
            else:
                return default
        return cur

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Event":
        return cls(
            category=d["category"],
            action=d["action"],
            data=d.get("data") or {},
            host=d.get("host", HOSTNAME),
            timestamp=d.get("timestamp", time.time()),
            id=d.get("id") or new_id(),
        )


@dataclass
class Alert:
    """Alerta producida por el motor de detección."""

    rule_id: str
    title: str
    severity: str
    description: str = ""
    source: str = "rule"  # rule | ioc | signature | behavior | correlation
    mitre: list[str] = field(default_factory=list)
    tactic: str = ""
    host: str = HOSTNAME
    event: dict[str, Any] | None = None
    context: dict[str, Any] = field(default_factory=dict)
    response: list[dict[str, Any]] = field(default_factory=list)
    recommended_actions: list[str] = field(default_factory=list)
    status: str = "open"  # open | investigating | closed
    timestamp: float = field(default_factory=time.time)
    id: str = field(default_factory=new_id)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Alert":
        known = {f for f in cls.__dataclass_fields__}
        return cls(**{k: v for k, v in d.items() if k in known})
