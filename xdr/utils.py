"""Utilidades compartidas: hashing, entropía, IPs, rutas."""
from __future__ import annotations

import fnmatch
import glob
import hashlib
import ipaddress
import math
import os
import shutil
import subprocess
import sys
import threading
from collections import Counter
from typing import Iterable

IS_LINUX = sys.platform.startswith("linux")
IS_WINDOWS = sys.platform.startswith("win")
IS_MAC = sys.platform == "darwin"

_hash_cache: dict[str, tuple[int, int, str]] = {}
_hash_lock = threading.Lock()


def sha256_file(path: str, max_size: int = 100 * 1024 * 1024) -> str | None:
    """SHA-256 de un fichero con caché por (mtime, size)."""
    try:
        st = os.stat(path)
    except OSError:
        return None
    if st.st_size > max_size or not os.path.isfile(path):
        return None
    with _hash_lock:
        cached = _hash_cache.get(path)
        if cached and cached[0] == st.st_mtime_ns and cached[1] == st.st_size:
            return cached[2]
    h = hashlib.sha256()
    try:
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                h.update(chunk)
    except OSError:
        return None
    digest = h.hexdigest()
    with _hash_lock:
        if len(_hash_cache) > 50000:
            _hash_cache.clear()
        _hash_cache[path] = (st.st_mtime_ns, st.st_size, digest)
    return digest


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def file_entropy(path: str, sample: int = 65536) -> float | None:
    try:
        with open(path, "rb") as fh:
            return round(shannon_entropy(fh.read(sample)), 3)
    except OSError:
        return None


def read_text(path: str, limit: int = 1024 * 1024) -> str | None:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read(limit)
    except OSError:
        return None


def read_head(path: str, size: int = 4096) -> bytes:
    try:
        with open(path, "rb") as fh:
            return fh.read(size)
    except OSError:
        return b""


def is_private_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast \
        or addr.is_unspecified


def is_valid_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def ip_in_list(ip: str, entries: Iterable[str]) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for entry in entries:
        try:
            if addr in ipaddress.ip_network(entry, strict=False):
                return True
        except ValueError:
            continue
    return False


def matches_any(path: str, patterns: Iterable[str]) -> bool:
    base = os.path.basename(path)
    for pat in patterns:
        if path == pat or path.startswith(pat.rstrip("/") + "/") or fnmatch.fnmatch(path, pat) \
                or fnmatch.fnmatch(base, pat):
            return True
    return False


def expand_paths(patterns: Iterable[str]) -> list[str]:
    out: list[str] = []
    for pat in patterns:
        pat = os.path.expanduser(os.path.expandvars(pat))
        if any(ch in pat for ch in "*?["):
            out.extend(sorted(glob.glob(pat)))
        elif os.path.exists(pat):
            out.append(pat)
    seen: set[str] = set()
    return [p for p in out if not (p in seen or seen.add(p))]


def home_dirs() -> list[str]:
    homes: set[str] = set()
    try:
        import pwd  # noqa: WPS433 (solo Unix)
        for pw in pwd.getpwall():
            if pw.pw_dir and pw.pw_dir not in ("/", "/nonexistent") and os.path.isdir(pw.pw_dir) \
                    and (pw.pw_uid == 0 or pw.pw_uid >= 1000):
                homes.add(pw.pw_dir)
    except ImportError:
        profile = os.environ.get("USERPROFILE")
        if profile:
            homes.add(profile)
    return sorted(homes)


def run_cmd(args: list[str], timeout: int = 15) -> tuple[int, str]:
    """Ejecuta un comando sin shell. Devuelve (código, salida combinada)."""
    if not shutil.which(args[0]):
        return 127, f"{args[0]}: no encontrado"
    try:
        proc = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return proc.returncode, (proc.stdout + proc.stderr).strip()
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 1, str(exc)


def is_elf(head: bytes) -> bool:
    return head[:4] == b"\x7fELF"


def is_pe(head: bytes) -> bool:
    return head[:2] == b"MZ"


def owner_name(uid: int) -> str:
    try:
        import pwd
        return pwd.getpwuid(uid).pw_name
    except (ImportError, KeyError):
        return str(uid)
