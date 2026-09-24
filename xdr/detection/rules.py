"""Motor de reglas declarativas (YAML) al estilo Sigma.

Formato de regla:
    - id: PROC-001
      title: ...
      severity: high
      tactic: execution
      mitre: [T1059.004]
      category: process            # o lista
      action: [start]              # o lista / omitido
      condition:                   # árbol all/any/not con comparaciones
        all:
          - field: cmdline
            regex: '\\bnc\\b.*\\s-e\\s'
          - not: {field: username, equals: root}
      threshold: {count: 5, window: 60, group_by: [src_ip]}   # opcional
      response: [kill_process]
      skip_initial: false
"""
from __future__ import annotations

import logging
import os
import re
import time
from collections import defaultdict, deque
from pathlib import Path
from typing import Any

import yaml

from xdr.events import Alert, Event, SEVERITIES

log = logging.getLogger("xdr.rules")

OPS = {"equals", "not_equals", "contains", "not_contains", "startswith", "endswith", "regex",
       "not_regex", "in", "not_in", "gt", "gte", "lt", "lte", "exists", "is_true", "is_false",
       "length_gt"}


class RuleError(ValueError):
    pass


def _as_list(v: Any) -> list:
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def _norm(v: Any, case: bool) -> Any:
    if isinstance(v, str) and not case:
        return v.lower()
    return v


class Condition:
    """Nodo compilado del árbol de condiciones."""

    def __init__(self, spec: Any):
        if not isinstance(spec, dict):
            raise RuleError(f"condición inválida: {spec!r}")
        self.kind: str
        if "all" in spec:
            self.kind, self.children = "all", [Condition(c) for c in _as_list(spec["all"])]
        elif "any" in spec:
            self.kind, self.children = "any", [Condition(c) for c in _as_list(spec["any"])]
        elif "not" in spec:
            self.kind, self.children = "not", [Condition(spec["not"])]
        elif "field" in spec:
            self.kind = "field"
            self.field = spec["field"]
            self.case = bool(spec.get("case_sensitive", False))
            self.ops: list[tuple[str, Any]] = []
            for op, val in spec.items():
                if op in ("field", "case_sensitive"):
                    continue
                if op not in OPS:
                    raise RuleError(f"operador desconocido '{op}'")
                if op in ("regex", "not_regex"):
                    flags = 0 if self.case else re.IGNORECASE
                    val = [re.compile(v, flags) for v in _as_list(val)]
                elif op in ("contains", "not_contains", "startswith", "endswith", "in", "not_in"):
                    val = [_norm(v, self.case) for v in _as_list(val)]
                elif op in ("equals", "not_equals"):
                    val = _norm(val, self.case)
                self.ops.append((op, val))
        else:
            raise RuleError(f"condición sin all/any/not/field: {spec!r}")

    def match(self, event: Event) -> bool:
        if self.kind == "all":
            return all(c.match(event) for c in self.children)
        if self.kind == "any":
            return any(c.match(event) for c in self.children)
        if self.kind == "not":
            return not self.children[0].match(event)
        raw = event.get(self.field)
        return all(self._op(op, val, raw) for op, val in self.ops)

    def _op(self, op: str, expected: Any, raw: Any) -> bool:
        if op == "exists":
            return (raw is not None and raw != "") == bool(expected)
        if op == "is_true":
            return bool(raw) is bool(expected)
        if op == "is_false":
            return (not raw) is bool(expected)
        if op == "length_gt":
            try:
                return len(raw) > float(expected)
            except TypeError:
                return False
        if isinstance(raw, list):
            # listas: la comparación se cumple si algún elemento la cumple
            if op.startswith("not_"):
                return all(self._op(op, expected, r) for r in raw) if raw else True
            return any(self._op(op, expected, r) for r in raw)
        if op in ("gt", "gte", "lt", "lte"):
            try:
                num, exp = float(raw), float(expected)
            except (TypeError, ValueError):
                return False
            return {"gt": num > exp, "gte": num >= exp, "lt": num < exp, "lte": num <= exp}[op]
        if raw is None:
            return op.startswith("not_")
        val = _norm(raw if isinstance(raw, (str, int, float, bool)) else str(raw), self.case)
        sval = val if isinstance(val, str) else str(val).lower()
        if op == "equals":
            return val == expected or sval == str(expected).lower()
        if op == "not_equals":
            return not (val == expected or sval == str(expected).lower())
        if op == "contains":
            return any(e in sval for e in expected)
        if op == "not_contains":
            return not any(e in sval for e in expected)
        if op == "startswith":
            return any(sval.startswith(e) for e in expected)
        if op == "endswith":
            return any(sval.endswith(e) for e in expected)
        if op == "in":
            return val in expected or sval in [str(e).lower() for e in expected]
        if op == "not_in":
            return not (val in expected or sval in [str(e).lower() for e in expected])
        if op == "regex":
            return any(r.search(str(raw)) for r in expected)
        if op == "not_regex":
            return not any(r.search(str(raw)) for r in expected)
        return False


class Rule:
    def __init__(self, spec: dict[str, Any], source: str = ""):
        for key in ("id", "title", "severity"):
            if key not in spec:
                raise RuleError(f"regla sin '{key}': {spec}")
        if spec["severity"] not in SEVERITIES:
            raise RuleError(f"severidad inválida en {spec['id']}")
        self.id: str = spec["id"]
        self.title: str = spec["title"]
        self.description: str = spec.get("description", "")
        self.severity: str = spec["severity"]
        self.tactic: str = spec.get("tactic", "")
        self.mitre: list[str] = _as_list(spec.get("mitre"))
        self.categories = set(_as_list(spec.get("category")))
        self.actions = set(_as_list(spec.get("action")))
        self.condition = Condition(spec["condition"]) if spec.get("condition") else None
        self.threshold = spec.get("threshold")
        self.response: list[str] = _as_list(spec.get("response"))
        self.skip_initial: bool = bool(spec.get("skip_initial", False))
        self.dedup: list[str] = _as_list(spec.get("dedup"))
        self.enabled: bool = spec.get("enabled", True)
        self.source = source
        self._windows: dict[tuple, deque] = defaultdict(deque)

    def applies(self, event: Event) -> bool:
        if self.categories and event.category not in self.categories:
            return False
        if self.actions and event.action not in self.actions:
            return False
        if self.skip_initial and event.data.get("initial"):
            return False
        return True

    def evaluate(self, event: Event) -> bool:
        if not self.enabled or not self.applies(event):
            return False
        if self.condition and not self.condition.match(event):
            return False
        if self.threshold:
            count = int(self.threshold.get("count", 1))
            window = float(self.threshold.get("window", 60))
            key = (event.host,) + tuple(str(event.get(f)) for f in _as_list(
                self.threshold.get("group_by")))
            dq = self._windows[key]
            now = event.timestamp
            dq.append(now)
            while dq and now - dq[0] > window:
                dq.popleft()
            if len(dq) < count:
                return False
            dq.clear()
        return True

    def to_alert(self, event: Event) -> Alert:
        return Alert(rule_id=self.id, title=self.title, severity=self.severity,
                     description=self.description, source="rule", mitre=list(self.mitre),
                     tactic=self.tactic, host=event.host, event=event.to_dict(),
                     recommended_actions=list(self.response))

    def summary(self) -> dict[str, Any]:
        return {"id": self.id, "title": self.title, "severity": self.severity, "tactic": self.tactic,
                "mitre": self.mitre, "categories": sorted(self.categories),
                "actions": sorted(self.actions), "response": self.response,
                "description": self.description, "enabled": self.enabled, "source": self.source}


def load_rules(dirs: list[str]) -> list[Rule]:
    rules: list[Rule] = []
    seen: set[str] = set()
    for d in dirs:
        path = Path(d)
        files = sorted(path.glob("*.y*ml")) if path.is_dir() else ([path] if path.is_file() else [])
        for f in files:
            with open(f, "r", encoding="utf-8") as fh:
                docs = yaml.safe_load(fh) or []
            for spec in docs:
                try:
                    rule = Rule(spec, source=os.path.basename(f))
                except (RuleError, re.error) as exc:
                    log.error("regla inválida en %s: %s", f, exc)
                    raise
                if rule.id in seen:
                    raise RuleError(f"id de regla duplicado: {rule.id}")
                seen.add(rule.id)
                rules.append(rule)
    return rules


class RuleEngine:
    def __init__(self, dirs: list[str]):
        self.dirs = dirs
        self.rules = load_rules(dirs)
        self.loaded_at = time.time()

    def analyze(self, event: Event) -> list[Alert]:
        return [r.to_alert(event) for r in self.rules if r.evaluate(event)]
