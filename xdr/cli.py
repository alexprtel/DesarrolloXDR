"""Interfaz de línea de comandos de SentinelXDR."""
from __future__ import annotations

import argparse
import json
import logging
import os
import secrets
import signal
import sys
import time
from pathlib import Path

import yaml

from xdr import __version__
from xdr.config import DEFAULTS, load_config, rule_dirs

log = logging.getLogger("xdr")

BANNER = r"""
  ____             _   _            _  __  ______  ____
 / ___|  ___ _ __ | |_(_)_ __   ___| | \ \/ /  _ \|  _ \
 \___ \ / _ \ '_ \| __| | '_ \ / _ \ |  \  /| | | | |_) |
  ___) |  __/ | | | |_| | | | |  __/ |  /  \| |_| |  _ <
 |____/ \___|_| |_|\__|_|_| |_|\___|_| /_/\_\____/|_| \_\   v{}
"""

SEV_COLORS = {"critical": "\033[1;41;97m", "high": "\033[1;31m", "medium": "\033[33m",
              "low": "\033[36m", "info": "\033[37m"}


def setup_logging(verbose: bool, logfile: str | None = None) -> None:
    handlers: list[logging.Handler] = [logging.StreamHandler(sys.stderr)]
    if logfile:
        Path(logfile).parent.mkdir(parents=True, exist_ok=True)
        handlers.append(logging.FileHandler(logfile))
    logging.basicConfig(level=logging.DEBUG if verbose else logging.INFO, handlers=handlers,
                        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s")


def _writable_dir(path: str, fallback: str) -> str:
    try:
        Path(path).mkdir(parents=True, exist_ok=True)
        test = Path(path) / ".w"
        test.write_text("x")
        test.unlink()
        return path
    except OSError:
        fb = os.path.expanduser(fallback)
        Path(fb).mkdir(parents=True, exist_ok=True)
        return fb


def get_config(args: argparse.Namespace):
    cfg = load_config(getattr(args, "config", None))
    cfg["agent"]["data_dir"] = _writable_dir(cfg["agent"]["data_dir"], "~/.sentinel-xdr/agent")
    cfg["server"]["data_dir"] = _writable_dir(cfg["server"]["data_dir"], "~/.sentinel-xdr/server")
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        log.warning("ejecutando sin privilegios de root: visibilidad y respuesta limitadas")
    return cfg


def _warn_defaults(cfg) -> None:
    if cfg["server"]["admin_token"].startswith("change-me") or \
            cfg["server"]["enroll_key"].startswith("change-me"):
        log.warning("¡Se usan credenciales por defecto! Ejecute 'sentinel-xdr init' para generarlas.")


# --------------------------------------------------------------------- comandos
def cmd_init(args: argparse.Namespace) -> int:
    path = Path(args.output)
    if path.exists() and not args.force:
        print(f"{path} ya existe (use --force para sobrescribir)")
        return 1
    cfg = {
        "agent": {"server_url": None, "enroll_key": secrets.token_urlsafe(24),
                  "data_dir": DEFAULTS["agent"]["data_dir"]},
        "server": {"host": "127.0.0.1", "port": 8443, "admin_token": secrets.token_urlsafe(32),
                   "data_dir": DEFAULTS["server"]["data_dir"]},
        "response": {"enabled": True, "min_severity": "high", "dry_run": False, "auto_isolate": False},
        "integrations": {"webhook_url": None, "syslog": None},
        "detection": {"learning_period": 3600, "allowlist": {"processes": [], "ips": ["127.0.0.1", "::1"],
                                                             "paths": []}},
    }
    cfg["server"]["enroll_key"] = cfg["agent"]["enroll_key"]
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("# Configuración de SentinelXDR (valores por defecto en xdr/config.py)\n")
        yaml.safe_dump(cfg, fh, sort_keys=False, allow_unicode=True)
    os.chmod(path, 0o600)
    print(f"Configuración creada en {path}")
    print(f"  Token de administrador (consola web): {cfg['server']['admin_token']}")
    print(f"  Clave de enrolamiento de agentes:     {cfg['server']['enroll_key']}")
    return 0


def _wait_forever(stop_fns: list) -> None:
    stopping = {"flag": False}

    def handler(*_):
        stopping["flag"] = True

    signal.signal(signal.SIGTERM, handler)
    signal.signal(signal.SIGINT, handler)
    while not stopping["flag"]:
        time.sleep(0.5)
    log.info("deteniendo...")
    for fn in stop_fns:
        try:
            fn()
        except Exception:  # noqa: BLE001
            log.exception("error al detener")


def cmd_run(args: argparse.Namespace) -> int:
    """Modo todo-en-uno: servidor + agente local."""
    from xdr.agent import Agent
    from xdr.server.api import XDRServer
    from xdr.server.core import ServerCore
    from xdr.transport import LocalTransport

    cfg = get_config(args)
    if args.port:
        cfg["server"]["port"] = args.port
    if args.host:
        cfg["server"]["host"] = args.host
    if args.dry_run:
        cfg["response"]["dry_run"] = True
    print(BANNER.format(__version__))
    _warn_defaults(cfg)
    core = ServerCore(cfg)
    server = XDRServer(core, cfg["server"]["host"], int(cfg["server"]["port"]),
                       cfg["server"].get("tls_cert"), cfg["server"].get("tls_key"))
    server.start()
    agent = Agent(cfg, LocalTransport(core, cfg["server"]["enroll_key"]),
                  collectors=args.collectors.split(",") if args.collectors else None)
    agent.start()
    print(f"Consola web: {server.url}   (token: server.admin_token)")
    print("Ctrl+C para detener.\n")
    _wait_forever([agent.stop, server.stop])
    return 0


def cmd_server(args: argparse.Namespace) -> int:
    from xdr.server.api import XDRServer
    from xdr.server.core import ServerCore

    cfg = get_config(args)
    if args.port:
        cfg["server"]["port"] = args.port
    if args.host:
        cfg["server"]["host"] = args.host
    print(BANNER.format(__version__))
    _warn_defaults(cfg)
    if cfg["server"]["host"] not in ("127.0.0.1", "localhost", "::1") and \
            cfg["server"]["admin_token"].startswith("change-me"):
        log.error("Rechazo exponer el servidor a la red con credenciales por defecto.")
        return 2
    core = ServerCore(cfg)
    server = XDRServer(core, cfg["server"]["host"], int(cfg["server"]["port"]),
                       cfg["server"].get("tls_cert"), cfg["server"].get("tls_key"))
    server.start()
    print(f"Servidor XDR escuchando en {server.url}")
    _wait_forever([server.stop])
    return 0


def cmd_agent(args: argparse.Namespace) -> int:
    from xdr.agent import Agent
    from xdr.transport import HttpTransport

    cfg = get_config(args)
    url = args.server or cfg["agent"].get("server_url")
    key = args.enroll_key or cfg["agent"].get("enroll_key")
    if not url:
        print("Indique --server URL (o use 'sentinel-xdr run' para el modo todo-en-uno)")
        return 2
    cfg["agent"]["server_url"] = url
    if args.dry_run:
        cfg["response"]["dry_run"] = True
    transport = HttpTransport(url, key, verify_tls=cfg["agent"].get("verify_tls", True),
                              ca_file=cfg["agent"].get("ca_file"))
    agent = Agent(cfg, transport, collectors=args.collectors.split(",") if args.collectors else None)
    agent.start()
    print(f"Agente activo en {agent.hostname} -> {url}")
    _wait_forever([agent.stop])
    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    from xdr.agent import scan_path
    from xdr.detection.engine import DetectionEngine
    from xdr.response.actions import ResponseActions

    cfg = load_config(getattr(args, "config", None))
    engine = DetectionEngine(cfg)
    total = 0
    actions = ResponseActions(cfg["response"], _writable_dir(cfg["agent"]["data_dir"],
                                                             "~/.sentinel-xdr/agent"))
    for path in args.paths:
        findings = scan_path(engine, path)
        for f in findings:
            total += 1
            color = SEV_COLORS.get(f["severity"], "")
            print(f"{color}[{f['severity'].upper()}]\033[0m {f['path']}: {f['name']}"
                  + (f"  ({', '.join(f.get('matches', [])[:3])})" if f.get("matches") else ""))
            if args.quarantine and f["severity"] in ("high", "critical"):
                res = actions.quarantine_file(path=f["path"])
                print(f"    -> {res['message']}")
    print(f"\n{total} detecciones.")
    return 1 if total else 0


def cmd_posture(args: argparse.Namespace) -> int:
    from xdr.collectors.posture import PostureCollector, posture_score
    from xdr.storage import Storage

    pc = PostureCollector({}, Storage(":memory:"), lambda e: None)
    findings = pc.run_checks()
    if args.json:
        print(json.dumps({"score": posture_score(findings), "findings": findings}, indent=2,
                         ensure_ascii=False))
        return 0
    for f in sorted(findings, key=lambda x: (x["status"] != "fail", x["check_id"])):
        mark = {"fail": "\033[31m✗ FALLA\033[0m", "pass": "\033[32m✓ OK   \033[0m"}.get(
            f["status"], "- N/A  ")
        print(f"{mark} [{f['severity']:<8}] {f['check_id']} {f['title']}"
              + (f"\n           {f['detail']}" if f["status"] == "fail" and f["detail"] else "")
              + (f"\n           → {f['remediation']}" if f["status"] == "fail" else ""))
    print(f"\nPuntuación de postura: {posture_score(findings)}/100")
    return 0


def cmd_rules(args: argparse.Namespace) -> int:
    from xdr.detection.rules import load_rules

    cfg = load_config(getattr(args, "config", None))
    rules = load_rules(rule_dirs(cfg))
    for r in rules:
        print(f"{r.id:<12} {r.severity:<9} {r.tactic:<22} {r.title}")
    techniques = {t for r in rules for t in r.mitre}
    print(f"\n{len(rules)} reglas válidas · {len(techniques)} técnicas MITRE ATT&CK")
    return 0


def cmd_intel(args: argparse.Namespace) -> int:
    from xdr.detection.intel import IntelStore

    cfg = load_config(getattr(args, "config", None))
    path = args.file or cfg.path("detection.ioc_file")
    store = IntelStore(path)
    if args.intel_cmd == "update":
        print(json.dumps(store.update_from_feeds(), indent=2))
    elif args.intel_cmd == "add":
        store.add(args.type, args.value, args.description or "")
        store.save()
        print("IOC añadido")
    print(json.dumps(store.counts()))
    return 0


def cmd_simulate(args: argparse.Namespace) -> int:
    from xdr.simulate import cleanup, run_simulation

    if args.cleanup:
        cleanup()
        print("Artefactos de simulación eliminados.")
        return 0
    run_simulation(args.auth_log, args.ransomware_dir)
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    import urllib.request

    cfg = load_config(getattr(args, "config", None))
    url = args.url or f"http://{cfg['server']['host']}:{cfg['server']['port']}"
    req = urllib.request.Request(url + "/api/overview?hours=24",
                                 headers={"Authorization": f"Bearer {cfg['server']['admin_token']}"})
    with urllib.request.urlopen(req, timeout=10) as resp:  # noqa: S310
        o = json.load(resp)
    print(f"Agentes: {o['agents']['online']}/{o['agents']['total']} en línea "
          f"({o['agents']['isolated']} aislados)")
    print(f"Riesgo: {o['risk_score']}/100 · Incidentes abiertos: {o['incidents']['open']}")
    print("Alertas 24h por severidad:", o["alerts"]["by_severity"])
    for inc in o["incidents"]["recent"]:
        print(f"  - [{inc['severity']}] {inc['title']} ({inc['alerts']} alertas)")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="sentinel-xdr", description="SentinelXDR - Extended Detection & Response")
    p.add_argument("--version", action="version", version=__version__)
    p.add_argument("-c", "--config", help="fichero de configuración YAML")
    p.add_argument("-v", "--verbose", action="store_true")
    p.add_argument("--log-file")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("init", help="genera un fichero de configuración con credenciales aleatorias")
    s.add_argument("-o", "--output", default="config/xdr.yaml")
    s.add_argument("--force", action="store_true")
    s.set_defaults(func=cmd_init)

    s = sub.add_parser("run", help="modo todo-en-uno: servidor + consola + agente local")
    s.add_argument("--host")
    s.add_argument("--port", type=int)
    s.add_argument("--collectors", help="lista separada por comas de sensores a activar")
    s.add_argument("--dry-run", action="store_true", help="respuesta en modo simulación")
    s.set_defaults(func=cmd_run)

    s = sub.add_parser("server", help="servidor central (API + consola)")
    s.add_argument("--host")
    s.add_argument("--port", type=int)
    s.set_defaults(func=cmd_server)

    s = sub.add_parser("agent", help="agente de endpoint conectado a un servidor")
    s.add_argument("--server", help="URL del servidor, p.ej. https://xdr.local:8443")
    s.add_argument("--enroll-key")
    s.add_argument("--collectors")
    s.add_argument("--dry-run", action="store_true")
    s.set_defaults(func=cmd_agent)

    s = sub.add_parser("scan", help="escaneo antimalware bajo demanda")
    s.add_argument("paths", nargs="+")
    s.add_argument("--quarantine", action="store_true", help="poner en cuarentena detecciones altas/críticas")
    s.set_defaults(func=cmd_scan)

    s = sub.add_parser("posture", help="auditoría de hardening del equipo")
    s.add_argument("--json", action="store_true")
    s.set_defaults(func=cmd_posture)

    s = sub.add_parser("rules", help="valida y lista las reglas de detección")
    s.set_defaults(func=cmd_rules)

    s = sub.add_parser("intel", help="gestión de inteligencia de amenazas")
    s.add_argument("intel_cmd", choices=["show", "update", "add"])
    s.add_argument("--type", choices=["sha256", "md5", "ips", "cidrs", "domains", "filenames"])
    s.add_argument("--value")
    s.add_argument("--description")
    s.add_argument("--file")
    s.set_defaults(func=cmd_intel)

    s = sub.add_parser("simulate", help="simula técnicas de ataque inofensivas para validar la detección")
    s.add_argument("--cleanup", action="store_true")
    s.add_argument("--auth-log", help="fichero de log de auth vigilado donde inyectar fuerza bruta")
    s.add_argument("--ransomware-dir", help="directorio vigilado donde simular cifrado masivo")
    s.set_defaults(func=cmd_simulate)

    s = sub.add_parser("status", help="resumen del estado desde el servidor")
    s.add_argument("--url")
    s.set_defaults(func=cmd_status)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    setup_logging(args.verbose, args.log_file)
    return int(args.func(args) or 0)
