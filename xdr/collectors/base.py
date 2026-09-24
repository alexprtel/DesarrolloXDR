"""Clase base para sensores de telemetría."""
from __future__ import annotations

import logging
import threading
import time
from typing import Any, Callable

from xdr.events import Event
from xdr.storage import Storage

log = logging.getLogger("xdr.collector")


class Collector:
    name = "base"
    default_interval = 10.0

    def __init__(self, settings: dict[str, Any], storage: Storage, emit: Callable[[Event], None],
                 config: Any = None):
        self.settings = settings or {}
        self.storage = storage
        self.emit = emit
        self.config = config
        self.interval = float(self.settings.get("interval", self.default_interval))
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.errors = 0
        self.last_run = 0.0
        self.runs = 0

    # -- a implementar por cada sensor
    def supported(self) -> bool:
        return True

    def setup(self) -> None:
        """Inicialización (línea base)."""

    def collect(self) -> list[Event]:
        raise NotImplementedError

    def teardown(self) -> None:
        pass

    # -- ciclo de vida
    def run_once(self) -> list[Event]:
        events = self.collect()
        for ev in events:
            self.emit(ev)
        self.last_run = time.time()
        self.runs += 1
        return events

    def _loop(self) -> None:
        try:
            self.setup()
        except Exception:  # noqa: BLE001
            log.exception("setup del sensor %s falló", self.name)
            self.errors += 1
        while not self._stop.is_set():
            started = time.time()
            try:
                self.run_once()
            except Exception:  # noqa: BLE001
                self.errors += 1
                log.exception("sensor %s falló", self.name)
            elapsed = time.time() - started
            self._stop.wait(max(0.2, self.interval - elapsed))
        try:
            self.teardown()
        except Exception:  # noqa: BLE001
            log.exception("teardown del sensor %s falló", self.name)

    def start(self) -> None:
        self._thread = threading.Thread(target=self._loop, name=f"collector-{self.name}", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def join(self, timeout: float | None = None) -> None:
        if self._thread:
            self._thread.join(timeout)

    def status(self) -> dict[str, Any]:
        return {"name": self.name, "interval": self.interval, "runs": self.runs,
                "errors": self.errors, "last_run": self.last_run}

    def event(self, category: str, action: str, **data: Any) -> Event:
        return Event(category=category, action=action, data=data)
