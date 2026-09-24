"""Servidor HTTP(S): API de agentes, API REST de administración y consola web."""
from __future__ import annotations

import json
import logging
import mimetypes
import re
import ssl
import threading
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable
from urllib.parse import parse_qs, urlparse

from xdr.server.core import AuthError, ServerCore

log = logging.getLogger("xdr.api")
STATIC_DIR = Path(__file__).parent / "static"
MAX_BODY = 32 * 1024 * 1024

Route = tuple[str, re.Pattern, Callable[..., Any], str]  # método, patrón, handler, auth(agent|admin|none)


class XDRRequestHandler(BaseHTTPRequestHandler):
    core: ServerCore
    routes: list[Route] = []
    server_version = "SentinelXDR"
    sys_version = ""

    def log_message(self, fmt: str, *args: Any) -> None:  # silenciar log por petición
        log.debug("%s - %s", self.address_string(), fmt % args)

    # ---------------------------------------------------------------- utils
    def _send(self, status: int, body: bytes, ctype: str = "application/json",
              extra: dict[str, str] | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Security-Policy",
                         "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, status: int, obj: Any) -> None:
        self._send(status, json.dumps(obj, default=str).encode())

    def _body(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        if length > MAX_BODY:
            raise ValueError("cuerpo demasiado grande")
        if not length:
            return {}
        data = json.loads(self.rfile.read(length))
        if not isinstance(data, dict):
            raise ValueError("se esperaba un objeto JSON")
        return data

    def _token(self) -> str | None:
        auth = self.headers.get("Authorization", "")
        return auth[7:].strip() if auth.startswith("Bearer ") else None

    # -------------------------------------------------------------- dispatch
    def _dispatch(self, method: str) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        query = {k: v[-1] for k, v in parse_qs(parsed.query).items()}
        if method == "GET" and not path.startswith("/api/"):
            return self._static(path)
        for m, pattern, handler, auth in self.routes:
            if m != method:
                continue
            match = pattern.fullmatch(path)
            if not match:
                continue
            try:
                ctx: dict[str, Any] = {"query": query, **match.groupdict()}
                if auth == "admin":
                    self.core.check_admin(self._token())
                elif auth == "agent":
                    ctx["agent"] = self.core.agent_for_token(self._token())
                if method == "POST":
                    ctx["body"] = self._body()
                result = handler(self.core, **ctx)
                if result is None:
                    return self._json(404, {"error": "no encontrado"})
                return self._json(200, result)
            except AuthError as exc:
                return self._json(401, {"error": str(exc)})
            except (ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
                return self._json(400, {"error": str(exc)})
            except Exception as exc:  # noqa: BLE001
                log.exception("error en %s %s", method, path)
                return self._json(500, {"error": f"error interno: {exc.__class__.__name__}"})
        self._json(404, {"error": "ruta no encontrada"})

    def _static(self, path: str) -> None:
        if path in ("", "/"):
            path = "/index.html"
        target = (STATIC_DIR / path.lstrip("/")).resolve()
        if not str(target).startswith(str(STATIC_DIR.resolve())) or not target.is_file():
            return self._send(404, b"not found", "text/plain")
        ctype = mimetypes.guess_type(str(target))[0] or "application/octet-stream"
        if ctype.startswith("text/") or ctype in ("application/javascript",):
            ctype += "; charset=utf-8"
        self._send(200, target.read_bytes(), ctype)

    def do_GET(self) -> None:  # noqa: N802
        self._dispatch("GET")

    def do_HEAD(self) -> None:  # noqa: N802
        self._dispatch("GET")

    def do_POST(self) -> None:  # noqa: N802
        self._dispatch("POST")

    def do_DELETE(self) -> None:  # noqa: N802
        self._dispatch("DELETE")


# ------------------------------------------------------------------ handlers
def _int(q: dict, key: str, default: int, maximum: int = 5000) -> int:
    try:
        return max(1, min(int(q.get(key, default)), maximum))
    except (TypeError, ValueError):
        return default


def _float(q: dict, key: str, default: float) -> float:
    try:
        return float(q.get(key, default))
    except (TypeError, ValueError):
        return default


def h_register(core: ServerCore, body: dict, **_: Any) -> dict:
    return core.register(body.get("info") or {}, body.get("enroll_key", ""), body.get("token"))


def h_events(core: ServerCore, agent: dict, body: dict, **_: Any) -> dict:
    return core.ingest(agent["id"], body.get("events") or [], body.get("alerts") or [])


def h_heartbeat(core: ServerCore, agent: dict, body: dict, **_: Any) -> dict:
    return core.heartbeat(agent["id"], body)


def h_cmd_result(core: ServerCore, agent: dict, body: dict, **_: Any) -> dict:
    return core.command_result(agent["id"], body["id"], body.get("result") or {})


def h_overview(core: ServerCore, query: dict, **_: Any) -> dict:
    return core.overview(_float(query, "hours", 24))


def h_alerts(core: ServerCore, query: dict, **_: Any) -> list:
    since = time.time() - _float(query, "hours", 24 * 30) * 3600
    return core.storage.query_alerts(host=query.get("host") or None, status=query.get("status") or None,
                                     min_severity=query.get("severity") or None, since=since,
                                     rule_id=query.get("rule_id") or None,
                                     limit=_int(query, "limit", 200))


def h_alert(core: ServerCore, alert_id: str, **_: Any) -> dict | None:
    return core.storage.get_alert(alert_id)


def h_alert_status(core: ServerCore, alert_id: str, body: dict, **_: Any) -> dict:
    if not core.set_alert_status(alert_id, body["status"]):
        raise ValueError("alerta no encontrada")
    return {"ok": True}


def h_alert_respond(core: ServerCore, alert_id: str, body: dict, **_: Any) -> dict:
    return core.respond_to_alert(alert_id, body["action"], body.get("by", "admin"))


def h_incidents(core: ServerCore, query: dict, **_: Any) -> list:
    return core.incidents(query.get("status") or None)


def h_incident(core: ServerCore, inc_id: str, **_: Any) -> dict | None:
    return core.incident(inc_id)


def h_incident_status(core: ServerCore, inc_id: str, body: dict, **_: Any) -> dict:
    if not core.set_incident_status(inc_id, body["status"]):
        raise ValueError("incidente no encontrado")
    return {"ok": True}


def h_events_search(core: ServerCore, query: dict, **_: Any) -> list:
    since = time.time() - _float(query, "hours", 24) * 3600
    return core.storage.query_events(host=query.get("host") or None,
                                     category=query.get("category") or None,
                                     action=query.get("action") or None, text=query.get("q") or None,
                                     since=since, limit=_int(query, "limit", 200))


def h_agents(core: ServerCore, **_: Any) -> list:
    return core.agents()


def h_command(core: ServerCore, body: dict, **_: Any) -> dict:
    return core.queue_command(body["agent_id"], body["action"], body.get("params") or {},
                              body.get("by", "admin"))


def h_commands(core: ServerCore, query: dict, **_: Any) -> list:
    return core.storage.list_commands(_int(query, "limit", 100))


def h_posture(core: ServerCore, query: dict, **_: Any) -> list:
    return core.storage.get_posture(query.get("host") or None)


def h_iocs(core: ServerCore, **_: Any) -> dict:
    return {"counts": core.intel.counts(), "version": core.intel.version,
            "iocs": {k: dict(list(v.items())[:500]) for k, v in core.intel.export().items()}}


def h_ioc_add(core: ServerCore, body: dict, **_: Any) -> dict:
    return core.add_ioc(body["type"], body["value"], body.get("description", ""))


def h_ioc_delete(core: ServerCore, body: dict, **_: Any) -> dict:
    return core.remove_ioc(body["type"], body["value"])


def h_feeds(core: ServerCore, **_: Any) -> dict:
    return core.update_feeds()


def h_rules(core: ServerCore, **_: Any) -> list:
    return core.rules()


def h_mitre(core: ServerCore, query: dict, **_: Any) -> dict:
    return core.mitre_matrix(_float(query, "hours", 24 * 7))


def h_health(core: ServerCore, **_: Any) -> dict:
    return {"status": "ok", "uptime": time.time() - core.started}


def build_routes() -> list[Route]:
    def r(method: str, pattern: str, handler: Callable, auth: str) -> Route:
        return (method, re.compile(pattern), handler, auth)

    ident = r"(?P<{}>[0-9a-f]{{32}})"
    return [
        r("GET", "/api/health", h_health, "none"),
        r("POST", "/api/agent/register", h_register, "none"),
        r("POST", "/api/agent/events", h_events, "agent"),
        r("POST", "/api/agent/heartbeat", h_heartbeat, "agent"),
        r("POST", "/api/agent/command_result", h_cmd_result, "agent"),
        r("GET", "/api/overview", h_overview, "admin"),
        r("GET", "/api/alerts", h_alerts, "admin"),
        r("GET", "/api/alerts/" + ident.format("alert_id"), h_alert, "admin"),
        r("POST", "/api/alerts/" + ident.format("alert_id") + "/status", h_alert_status, "admin"),
        r("POST", "/api/alerts/" + ident.format("alert_id") + "/respond", h_alert_respond, "admin"),
        r("GET", "/api/incidents", h_incidents, "admin"),
        r("GET", "/api/incidents/" + ident.format("inc_id"), h_incident, "admin"),
        r("POST", "/api/incidents/" + ident.format("inc_id") + "/status", h_incident_status, "admin"),
        r("GET", "/api/events", h_events_search, "admin"),
        r("GET", "/api/agents", h_agents, "admin"),
        r("POST", "/api/commands", h_command, "admin"),
        r("GET", "/api/commands", h_commands, "admin"),
        r("GET", "/api/posture", h_posture, "admin"),
        r("GET", "/api/iocs", h_iocs, "admin"),
        r("POST", "/api/iocs", h_ioc_add, "admin"),
        r("POST", "/api/iocs/delete", h_ioc_delete, "admin"),
        r("POST", "/api/iocs/feeds", h_feeds, "admin"),
        r("GET", "/api/rules", h_rules, "admin"),
        r("GET", "/api/mitre", h_mitre, "admin"),
    ]


class XDRServer:
    def __init__(self, core: ServerCore, host: str = "127.0.0.1", port: int = 8443,
                 tls_cert: str | None = None, tls_key: str | None = None):
        handler = type("Handler", (XDRRequestHandler,), {"core": core, "routes": build_routes()})
        self.httpd = ThreadingHTTPServer((host, port), handler)
        self.httpd.daemon_threads = True
        self.scheme = "http"
        if tls_cert and tls_key:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            ctx.load_cert_chain(tls_cert, tls_key)
            self.httpd.socket = ctx.wrap_socket(self.httpd.socket, server_side=True)
            self.scheme = "https"
        self.thread: threading.Thread | None = None

    @property
    def url(self) -> str:
        host, port = self.httpd.server_address[:2]
        return f"{self.scheme}://{host}:{port}"

    def start(self) -> None:
        self.thread = threading.Thread(target=self.httpd.serve_forever, name="http", daemon=True)
        self.thread.start()
        log.info("consola y API disponibles en %s", self.url)

    def stop(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
