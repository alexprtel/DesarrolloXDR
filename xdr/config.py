"""Carga de configuración (YAML) con valores por defecto."""
from __future__ import annotations

import copy
import os
from pathlib import Path
from typing import Any

import yaml

PACKAGE_DIR = Path(__file__).resolve().parent
DATA_DIR = PACKAGE_DIR / "data"

DEFAULTS: dict[str, Any] = {
    "agent": {
        "name": None,  # por defecto el hostname
        "data_dir": "/var/lib/sentinel-xdr",
        "server_url": None,  # p.ej. http://10.0.0.5:8443 ; None = modo autónomo
        "enroll_key": "change-me-enroll-key",
        "ship_interval": 5,
        "verify_tls": True,
        "ca_file": None,
        "heartbeat_interval": 10,
    },
    "server": {
        "host": "127.0.0.1",
        "port": 8443,
        "data_dir": "/var/lib/sentinel-xdr/server",
        "enroll_key": "change-me-enroll-key",
        "admin_token": "change-me-admin-token",
        "retention_days": 30,
        "tls_cert": None,
        "tls_key": None,
        "max_events": 500000,
    },
    "collectors": {
        "process": {"enabled": True, "interval": 2, "hash_executables": True},
        "network": {"enabled": True, "interval": 3},
        "fim": {
            "enabled": True,
            "interval": 30,
            "paths": [
                "/etc", "/bin", "/sbin", "/usr/bin", "/usr/sbin",
                "/usr/local/bin", "/usr/local/sbin", "/boot", "/root/.ssh",
            ],
            "exclude": [
                "/etc/mtab", "/etc/adjtime", "/etc/ld.so.cache",
                "*.swp", "*~", "/etc/.pwd.lock",
            ],
            "max_files": 60000,
            "max_hash_size": 50 * 1024 * 1024,
        },
        "malware_scan": {
            "enabled": True,
            "interval": 15,
            # Directorios típicos de descarga/staging de malware
            "paths": ["/tmp", "/var/tmp", "/dev/shm", "/home/*/Downloads", "/root/Downloads",
                      "/var/www"],
            "max_depth": 4,
            "max_size": 20 * 1024 * 1024,
        },
        "ransomware": {
            "enabled": True,
            "interval": 5,
            "paths": ["/home", "/root", "/srv"],
            "canaries": True,
            "max_files": 30000,
        },
        "auth": {
            "enabled": True,
            "files": ["/var/log/auth.log", "/var/log/secure"],
            "from_start": False,
            "interval": 2,
        },
        "persistence": {"enabled": True, "interval": 20},
        "accounts": {"enabled": True, "interval": 30},
        "kernel": {"enabled": True, "interval": 30},
        "devices": {"enabled": True, "interval": 5},
        "resources": {
            "enabled": True,
            "interval": 10,
            "cpu_threshold": 85.0,
            "sustained_samples": 6,
        },
        "posture": {"enabled": True, "interval": 3600},
    },
    "detection": {
        "rules_dirs": [str(DATA_DIR / "rules")],
        "extra_rules_dirs": [],
        "ioc_file": str(DATA_DIR / "iocs.json"),
        "signatures_file": str(DATA_DIR / "signatures.yaml"),
        "learning_period": 300,  # segundos de aprendizaje de línea base
        "bruteforce": {"threshold": 5, "window": 120},
        "spray": {"distinct_users": 5, "window": 300},
        "ransomware": {"threshold": 25, "window": 30, "entropy": 7.2},
        "beaconing": {"min_samples": 6, "max_jitter": 0.15},
        "scan": {"distinct_targets": 25, "window": 60},
        "exfiltration": {"zscore": 6.0, "min_bytes": 50 * 1024 * 1024},
        "allowlist": {"processes": [], "ips": ["127.0.0.1", "::1"], "paths": []},
    },
    "integrations": {
        "webhook_url": None,  # Slack/Teams/genérico (POST JSON)
        "webhook_min_severity": "high",
        "syslog": None,  # "host:514" -> reenvío CEF por UDP a un SIEM
        "syslog_min_severity": "low",
    },
    "response": {
        "enabled": True,
        "min_severity": "high",  # respuesta automática a partir de esta severidad
        "auto_isolate": False,  # el aislamiento automático de red es disruptivo: opt-in
        "dry_run": False,
        "quarantine_dir": None,  # por defecto <data_dir>/quarantine
        "protected_processes": [
            "systemd", "init", "kthreadd", "sshd", "sentinel-xdr", "dockerd", "containerd",
        ],
        "never_block_ips": ["127.0.0.1", "::1"],
    },
}


def deep_merge(base: dict, override: dict) -> dict:
    out = copy.deepcopy(base)
    for k, v in (override or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = deep_merge(out[k], v)
        else:
            out[k] = copy.deepcopy(v)
    return out


def rule_dirs(cfg: dict) -> list[str]:
    det = cfg.get("detection", {})
    return list(det.get("rules_dirs") or []) + list(det.get("extra_rules_dirs") or [])


class Config(dict):
    """Diccionario de configuración con acceso por ruta 'a.b.c'."""

    def path(self, dotted: str, default: Any = None) -> Any:
        cur: Any = self
        for part in dotted.split("."):
            if not isinstance(cur, dict) or part not in cur:
                return default
            cur = cur[part]
        return cur


def load_config(path: str | os.PathLike | None = None, overrides: dict | None = None) -> Config:
    data: dict[str, Any] = {}
    candidates = [path] if path else [
        os.environ.get("XDR_CONFIG"),
        "/etc/sentinel-xdr/xdr.yaml",
        "config/xdr.yaml",
    ]
    for cand in candidates:
        if cand and Path(cand).is_file():
            with open(cand, "r", encoding="utf-8") as fh:
                data = yaml.safe_load(fh) or {}
            break
    else:
        if path:
            raise FileNotFoundError(path)
    merged = deep_merge(DEFAULTS, data)
    if overrides:
        merged = deep_merge(merged, overrides)
    return Config(merged)
