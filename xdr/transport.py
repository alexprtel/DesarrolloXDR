"""Transporte agente <-> servidor: local (mismo proceso) o HTTP(S)."""
from __future__ import annotations

import json
import logging
import ssl
import urllib.error
import urllib.request
from typing import Any

log = logging.getLogger("xdr.transport")


class TransportError(RuntimeError):
    pass


class LocalTransport:
    """Llama directamente al núcleo del servidor (modo todo-en-uno)."""

    def __init__(self, core: Any, enroll_key: str):
        self.core = core
        self.enroll_key = enroll_key
        self.agent_id: str | None = None

    def register(self, info: dict) -> dict:
        res = self.core.register(info, self.enroll_key)
        self.agent_id = res["agent_id"]
        return res

    def send(self, events: list[dict], alerts: list[dict]) -> dict:
        return self.core.ingest(self.agent_id, events, alerts)

    def heartbeat(self, status: dict) -> dict:
        return self.core.heartbeat(self.agent_id, status)

    def command_result(self, cmd_id: str, result: dict) -> dict:
        return self.core.command_result(self.agent_id, cmd_id, result)


class HttpTransport:
    def __init__(self, base_url: str, enroll_key: str, token: str | None = None,
                 verify_tls: bool = True, ca_file: str | None = None, timeout: float = 20):
        self.base = base_url.rstrip("/")
        self.enroll_key = enroll_key
        self.token = token
        self.agent_id: str | None = None
        self.timeout = timeout
        self.ctx = None
        if self.base.startswith("https"):
            self.ctx = ssl.create_default_context(cafile=ca_file) if verify_tls else \
                ssl._create_unverified_context()  # noqa: S323 - opción explícita del usuario

    def _post(self, path: str, body: dict, auth: str | None) -> dict:
        data = json.dumps(body, default=str).encode()
        req = urllib.request.Request(self.base + path, data=data, method="POST",
                                     headers={"Content-Type": "application/json"})
        if auth:
            req.add_header("Authorization", f"Bearer {auth}")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=self.ctx) as resp:  # noqa: S310
                return json.loads(resp.read() or b"{}")
        except urllib.error.HTTPError as exc:
            if exc.code == 401 and path != "/api/agent/register":
                self.token = None
            raise TransportError(f"HTTP {exc.code}: {exc.read()[:200]!r}") from exc
        except (urllib.error.URLError, OSError, ValueError) as exc:
            raise TransportError(str(exc)) from exc

    def register(self, info: dict) -> dict:
        res = self._post("/api/agent/register", {"info": info, "enroll_key": self.enroll_key,
                                                  "token": self.token}, None)
        self.agent_id, self.token = res["agent_id"], res["token"]
        return res

    def _ensure(self, info: dict | None = None) -> None:
        if not self.token:
            raise TransportError("agente no registrado")

    def send(self, events: list[dict], alerts: list[dict]) -> dict:
        self._ensure()
        return self._post("/api/agent/events", {"events": events, "alerts": alerts}, self.token)

    def heartbeat(self, status: dict) -> dict:
        self._ensure()
        return self._post("/api/agent/heartbeat", status, self.token)

    def command_result(self, cmd_id: str, result: dict) -> dict:
        self._ensure()
        return self._post("/api/agent/command_result", {"id": cmd_id, "result": result}, self.token)
