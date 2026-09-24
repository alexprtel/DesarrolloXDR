"""Sensores de ficheros:
  * FileIntegrityCollector (FIM) - binarios y configuración del sistema.
  * MalwareScanCollector - zonas de staging (/tmp, descargas, webroot).
  * RansomwareCollector - datos de usuario, entropía, renombrados y canarios.
"""
from __future__ import annotations

import hashlib
import os
import stat
import time
from typing import Any

from xdr.collectors.base import Collector
from xdr.events import Event
from xdr.utils import (expand_paths, file_entropy, home_dirs, is_elf, matches_any, owner_name,
                       read_head, sha256_file)


class FileMonitor(Collector):
    name = "fim"
    zone = "system"
    default_interval = 30.0
    emit_initial = False  # emitir eventos para los ficheros existentes en la primera pasada
    hash_files = True
    compute_entropy = False
    skip_hidden = False
    default_max_depth = 12

    def setup(self) -> None:
        self.roots = expand_paths(self.settings.get("paths", []))
        self.exclude = list(self.settings.get("exclude", []))
        self.max_files = int(self.settings.get("max_files", 60000))
        self.max_depth = int(self.settings.get("max_depth", self.default_max_depth))
        self.max_hash = int(self.settings.get("max_hash_size", self.settings.get("max_size",
                                                                                  50 * 1024 * 1024)))
        self.ns = f"files:{self.name}"
        self.baseline: dict[str, list] = self.storage.baseline_load(self.ns)
        self.initialized = self.storage.baseline_exists(self.ns)

    # ------------------------------------------------------------------ walk
    def _walk(self) -> dict[str, list]:
        snap: dict[str, list] = {}
        stack: list[tuple[str, int]] = [(r, 0) for r in self.roots]
        while stack and len(snap) < self.max_files:
            path, depth = stack.pop()
            try:
                st = os.lstat(path)
            except OSError:
                continue
            if stat.S_ISDIR(st.st_mode):
                if depth > self.max_depth:
                    continue
                try:
                    with os.scandir(path) as it:
                        for entry in it:
                            if self.skip_hidden and entry.name.startswith("."):
                                continue
                            full = entry.path
                            if self.exclude and matches_any(full, self.exclude):
                                continue
                            try:
                                if entry.is_dir(follow_symlinks=False):
                                    stack.append((full, depth + 1))
                                elif entry.is_file(follow_symlinks=False):
                                    est = entry.stat(follow_symlinks=False)
                                    snap[full] = [est.st_mtime_ns, est.st_size, est.st_mode,
                                                  est.st_uid, est.st_gid, est.st_ino, None]
                            except OSError:
                                continue
                except OSError:
                    continue
            elif stat.S_ISREG(st.st_mode):
                snap[path] = [st.st_mtime_ns, st.st_size, st.st_mode, st.st_uid, st.st_gid,
                              st.st_ino, None]
        return snap

    def _hash(self, path: str, meta: list) -> str | None:
        if not self.hash_files or meta[1] > self.max_hash:
            return None
        return sha256_file(path, self.max_hash)

    def _describe(self, path: str, meta: list, **extra: Any) -> dict:
        mode = meta[2]
        head = read_head(path, 64)
        data = {
            "path": path,
            "zone": self.zone,
            "size": meta[1],
            "mode": f"{stat.S_IMODE(mode):04o}",
            "uid": meta[3],
            "owner": owner_name(meta[3]),
            "setuid": bool(mode & stat.S_ISUID),
            "setgid": bool(mode & stat.S_ISGID),
            "world_writable": bool(mode & stat.S_IWOTH),
            "executable": bool(mode & 0o111),
            "extension": os.path.splitext(path)[1].lower(),
            "filename": os.path.basename(path),
            "directory": os.path.dirname(path),
            "is_elf": is_elf(head),
            "is_script": head.startswith(b"#!"),
            "sha256": meta[6],
        }
        if self.compute_entropy:
            data["entropy"] = file_entropy(path)
        data.update(extra)
        return data

    # --------------------------------------------------------------- collect
    def collect(self) -> list[Event]:
        snap = self._walk()
        events: list[Event] = []
        upserts: dict[str, list] = {}
        if not self.initialized:
            for path, meta in snap.items():
                meta[6] = self._hash(path, meta)
                upserts[path] = meta
                if self.emit_initial:
                    events.append(self.event("file", "existing", **self._describe(path, meta,
                                                                                  initial=True)))
            self.baseline = snap
            self.storage.baseline_update(self.ns, upserts)
            self.initialized = True
            return events

        old = self.baseline
        created = [p for p in snap if p not in old]
        deleted = [p for p in old if p not in snap]
        deleted_by_inode = {old[p][5]: p for p in deleted}
        renamed_from: set[str] = set()

        for path in created:
            meta = snap[path]
            meta[6] = self._hash(path, meta)
            upserts[path] = meta
            src = deleted_by_inode.get(meta[5])
            if src:
                renamed_from.add(src)
                events.append(self.event("file", "rename", **self._describe(
                    path, meta, old_path=src,
                    old_extension=os.path.splitext(src)[1].lower())))
            else:
                events.append(self.event("file", "create", **self._describe(path, meta)))

        for path, meta in snap.items():
            if path in created:
                continue
            prev = old[path]
            content_changed = meta[0] != prev[0] or meta[1] != prev[1]
            attr_changed = meta[2] != prev[2] or meta[3] != prev[3] or meta[4] != prev[4]
            if not content_changed and not attr_changed:
                meta[6] = prev[6]
                continue
            meta[6] = self._hash(path, meta) if content_changed else prev[6]
            upserts[path] = meta
            if content_changed and (not self.hash_files or meta[6] != prev[6] or meta[6] is None):
                events.append(self.event("file", "modify", **self._describe(
                    path, meta, old_sha256=prev[6], old_size=prev[1])))
            if attr_changed:
                events.append(self.event("file", "attrib", **self._describe(
                    path, meta, old_mode=f"{stat.S_IMODE(prev[2]):04o}", old_uid=prev[3],
                    became_setuid=bool(meta[2] & stat.S_ISUID) and not bool(prev[2] & stat.S_ISUID))))

        really_deleted = [p for p in deleted if p not in renamed_from]
        for path in really_deleted:
            prev = old[path]
            events.append(self.event("file", "delete", path=path, zone=self.zone, sha256=prev[6],
                                     filename=os.path.basename(path),
                                     extension=os.path.splitext(path)[1].lower()))
        self.baseline = snap
        if upserts or deleted:
            self.storage.baseline_update(self.ns, upserts, deleted)
        return events


class FileIntegrityCollector(FileMonitor):
    name = "fim"
    zone = "system"


class MalwareScanCollector(FileMonitor):
    """Vigila directorios de staging; los ficheros nuevos se analizan con firmas
    e IOCs en el motor de detección."""
    name = "malware_scan"
    zone = "staging"
    default_interval = 15.0
    emit_initial = True
    default_max_depth = 4


CANARY_NAME = ".xdr_canary_{}.docx"
CANARY_BODY = (b"CONFIDENCIAL - Nominas y datos bancarios 2026\n"
               b"Este documento es un senuelo de SentinelXDR. No lo modifique.\n") * 40


class RansomwareCollector(FileMonitor):
    """Monitoriza datos de usuario sin hashear (solo metadatos + entropía) y
    despliega ficheros canario."""
    name = "ransomware"
    zone = "user"
    default_interval = 5.0
    hash_files = False
    compute_entropy = True
    skip_hidden = True
    default_max_depth = 8

    def setup(self) -> None:
        super().setup()
        self.canaries: dict[str, str] = self.storage.kv_get("canaries", {}) or {}
        self.tampered: set[str] = set()
        if self.settings.get("canaries", True):
            self._deploy_canaries()

    def _canary_dirs(self) -> list[str]:
        dirs = []
        for root in self.roots:
            if root in ("/home",):
                continue
            dirs.append(root)
        for home in home_dirs():
            if any(home == r or home.startswith(r.rstrip("/") + "/") for r in self.roots):
                dirs.append(home)
                for sub in ("Documents", "Documentos", "Desktop", "Escritorio"):
                    p = os.path.join(home, sub)
                    if os.path.isdir(p):
                        dirs.append(p)
        return sorted(set(dirs))

    def _deploy_canaries(self) -> None:
        changed = False
        for d in self._canary_dirs():
            if any(os.path.dirname(p) == d for p in self.canaries):
                continue
            tag = hashlib.sha1(d.encode()).hexdigest()[:6]
            path = os.path.join(d, CANARY_NAME.format(tag))
            try:
                with open(path, "wb") as fh:
                    fh.write(CANARY_BODY)
                os.chmod(path, 0o644)
            except OSError:
                continue
            self.canaries[path] = sha256_file(path) or ""
            changed = True
        if changed:
            self.storage.kv_set("canaries", self.canaries)

    def collect(self) -> list[Event]:
        events = super().collect()
        for path, digest in self.canaries.items():
            if path in self.tampered:
                continue
            current = sha256_file(path) if os.path.exists(path) else None
            if current != digest:
                self.tampered.add(path)
                events.append(self.event("file", "canary_tampered", path=path, zone="canary",
                                         deleted=current is None, expected_sha256=digest,
                                         sha256=current, entropy=file_entropy(path)
                                         if current else None, detected_at=time.time()))
        return events

    def teardown(self) -> None:
        pass
