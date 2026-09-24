"""Escáner de firmas de malware (estilo YARA simplificado) + heurísticas de
empaquetado/ofuscación."""
from __future__ import annotations

import os
import re
from typing import Any

import yaml

from xdr.events import Alert, Event
from xdr.utils import shannon_entropy

SCANNABLE_ACTIONS = {"create", "modify", "rename", "existing"}


class Signature:
    def __init__(self, spec: dict[str, Any]):
        self.id = spec["id"]
        self.name = spec["name"]
        self.severity = spec.get("severity", "high")
        self.mitre = spec.get("mitre", [])
        self.tactic = spec.get("tactic", "execution")
        self.description = spec.get("description", "")
        self.response = spec.get("response", ["quarantine_file"])
        nocase = spec.get("nocase", True)
        self.strings = [s.encode("utf-8", "replace") for s in spec.get("strings", [])]
        if nocase:
            self.strings = [s.lower() for s in self.strings]
        self.nocase = nocase
        flags = re.IGNORECASE if nocase else 0
        self.regexes = [re.compile(r.encode(), flags | re.DOTALL) for r in spec.get("regex", [])]
        cond = spec.get("condition", "any")
        total = len(self.strings) + len(self.regexes)
        self.required = total if cond == "all" else (1 if cond == "any" else int(cond))
        self.filetypes = set(spec.get("filetypes", []))  # elf, pe, script, text

    def match(self, data: bytes, lowered: bytes, filetype: str) -> list[str]:
        if self.filetypes and filetype not in self.filetypes:
            return []
        hits: list[str] = []
        buf = lowered if self.nocase else data
        for s in self.strings:
            if s in buf:
                hits.append(s.decode("utf-8", "replace"))
        for r in self.regexes:
            if r.search(data):
                hits.append(r.pattern.decode("utf-8", "replace"))
        return hits if len(hits) >= self.required else []


def filetype_of(data: bytes) -> str:
    if data[:4] == b"\x7fELF":
        return "elf"
    if data[:2] == b"MZ":
        return "pe"
    if data[:2] == b"#!":
        return "script"
    return "text" if b"\x00" not in data[:4096] else "binary"


class SignatureScanner:
    def __init__(self, path: str | None, max_size: int = 20 * 1024 * 1024):
        self.max_size = max_size
        self.signatures: list[Signature] = []
        if path and os.path.isfile(path):
            with open(path, "r", encoding="utf-8") as fh:
                self.signatures = [Signature(s) for s in (yaml.safe_load(fh) or [])]

    def scan_bytes(self, data: bytes) -> list[dict[str, Any]]:
        lowered = data.lower()
        ftype = filetype_of(data)
        results = []
        for sig in self.signatures:
            hits = sig.match(data, lowered, ftype)
            if hits:
                results.append({"signature": sig, "hits": hits[:10]})
        # Heurística: ejecutable empaquetado / cifrado
        if ftype in ("elf", "pe") and len(data) > 4096:
            ent = shannon_entropy(data[: 2 * 1024 * 1024])
            if ent > 7.4:
                results.append({"signature": _PACKED, "hits": [f"entropía={ent:.2f}"]})
        return results

    def scan_file(self, path: str) -> list[dict[str, Any]]:
        try:
            if not os.path.isfile(path) or os.path.getsize(path) > self.max_size:
                return []
            with open(path, "rb") as fh:
                data = fh.read(self.max_size)
        except OSError:
            return []
        return self.scan_bytes(data)

    def match_event(self, event: Event) -> list[Alert]:
        if event.category != "file" or event.action not in SCANNABLE_ACTIONS:
            return []
        path = event.get("path")
        if not path:
            return []
        alerts = []
        for res in self.scan_file(path):
            sig: Signature = res["signature"]
            alerts.append(Alert(
                rule_id=sig.id, title=f"Malware detectado: {sig.name}", severity=sig.severity,
                description=sig.description or f"Firma {sig.id} en {path}", source="signature",
                mitre=list(sig.mitre), tactic=sig.tactic, host=event.host, event=event.to_dict(),
                context={"path": path, "matches": res["hits"], "signature": sig.id},
                recommended_actions=list(sig.response)))
        return alerts


_PACKED = Signature({"id": "SIG-HEUR-PACKED", "name": "Ejecutable empaquetado/cifrado (alta entropía)",
                     "severity": "medium", "mitre": ["T1027.002"], "tactic": "defense-evasion",
                     "strings": [], "condition": 0, "response": []})
