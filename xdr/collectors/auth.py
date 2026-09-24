"""Sensor de autenticación: analiza auth.log/secure (o journald) para detectar
logins, fallos, sudo, su y cambios de cuentas."""
from __future__ import annotations

import os
import re
import select
import shutil
import subprocess
from typing import Any

from xdr.collectors.base import Collector
from xdr.events import Event
from xdr.utils import is_private_ip

PATTERNS: list[tuple[str, re.Pattern]] = [
    ("login_failed", re.compile(
        r"sshd\[\d+\]: Failed (?P<method>\S+) for (?:invalid user )?(?P<user>\S+) from "
        r"(?P<src_ip>[0-9a-fA-F:.]+) port (?P<port>\d+)")),
    ("login_failed", re.compile(
        r"sshd\[\d+\]: Invalid user (?P<user>\S*) from (?P<src_ip>[0-9a-fA-F:.]+)")),
    ("login_success", re.compile(
        r"sshd\[\d+\]: Accepted (?P<method>\S+) for (?P<user>\S+) from "
        r"(?P<src_ip>[0-9a-fA-F:.]+) port (?P<port>\d+)")),
    ("login_failed", re.compile(
        r"(?P<service>\S+)\(pam_unix\)\[\d+\]: authentication failure;.*?rhost=(?P<src_ip>\S*)"
        r"(?:\s+user=(?P<user>\S+))?")),
    ("login_failed", re.compile(
        r"pam_unix\((?P<service>[^:]+):auth\): authentication failure;.*?rhost=(?P<src_ip>\S*)"
        r"(?:\s+user=(?P<user>\S+))?")),
    ("sudo_failed", re.compile(
        r"sudo(?:\[\d+\])?: +(?P<user>\S+) : (?:\d+ )?incorrect password attempts?.*COMMAND=(?P<command>.*)$")),
    ("sudo_denied", re.compile(
        r"sudo(?:\[\d+\])?: +(?P<user>\S+) : (?:user NOT in sudoers|command not allowed).*COMMAND=(?P<command>.*)$")),
    ("sudo", re.compile(
        r"sudo(?:\[\d+\])?: +(?P<user>\S+) : .*?USER=(?P<target_user>\S+) ; COMMAND=(?P<command>.*)$")),
    ("su_failed", re.compile(r"su(?:\[\d+\])?: (?:FAILED su|pam_authenticate: Authentication failure).*?(?:for (?P<target_user>\S+))?(?: by (?P<user>\S+))?$")),
    ("su", re.compile(
        r"su(?:\[\d+\])?: .*session opened for user (?P<target_user>\S+?)(?:\(uid=\d+\))? by (?P<user>\S*?)(?:\(uid=\d+\))?$")),
    ("user_created", re.compile(r"useradd(?:\[\d+\])?: new user: name=(?P<user>[^,]+),\s*UID=(?P<uid>\d+)")),
    ("user_deleted", re.compile(r"userdel(?:\[\d+\])?: delete user '(?P<user>[^']+)'")),
    ("password_changed", re.compile(r"(?:passwd|chpasswd)(?:\[\d+\])?: .*password changed for (?P<user>\S+)")),
    ("group_member_added", re.compile(
        r"(?:usermod|gpasswd)(?:\[\d+\])?: (?:add|user) '?(?P<user>[^' ]+)'? (?:to|added by \S+ to) (?:group|shadow group)? ?'?(?P<group>[^' ]+)'?")),
]


PROGRAM = re.compile(r"\s([A-Za-z0-9_.()-]+?)(?:\[\d+\])?:\s")


def parse_auth_line(line: str) -> tuple[str, dict[str, Any]] | None:
    if "pam_unix(sshd:auth)" in line:
        return None  # sshd ya registra "Failed password" para el mismo intento
    for action, pattern in PATTERNS:
        m = pattern.search(line)
        if m:
            data = {k: v for k, v in m.groupdict().items() if v is not None}
            if data.get("src_ip"):
                data["src_private"] = is_private_ip(data["src_ip"])
            if "service" not in data:
                prog = PROGRAM.search(line)
                data["service"] = prog.group(1) if prog else ""
            data["raw"] = line.strip()[:500]
            return action, data
    return None


class AuthLogCollector(Collector):
    name = "auth"
    default_interval = 2.0

    def supported(self) -> bool:
        return os.name == "posix"

    def setup(self) -> None:
        self.files: dict[str, dict] = {}
        self.journal: subprocess.Popen | None = None
        from_start = bool(self.settings.get("from_start", False))
        for path in self.settings.get("files", []):
            if os.path.isfile(path):
                try:
                    st = os.stat(path)
                except OSError:
                    continue
                self.files[path] = {"ino": st.st_ino, "pos": 0 if from_start else st.st_size}
        if not self.files and shutil.which("journalctl") and self.settings.get("journald", True):
            try:
                self.journal = subprocess.Popen(
                    ["journalctl", "-f", "-n", "0", "-o", "short", "SYSLOG_FACILITY=4",
                     "SYSLOG_FACILITY=10"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                    text=True)
                os.set_blocking(self.journal.stdout.fileno(), False)
            except OSError:
                self.journal = None

    def _read_file(self, path: str, state: dict) -> list[str]:
        try:
            st = os.stat(path)
        except OSError:
            return []
        if st.st_ino != state["ino"] or st.st_size < state["pos"]:
            state["ino"], state["pos"] = st.st_ino, 0  # rotación
        if st.st_size == state["pos"]:
            return []
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            fh.seek(state["pos"])
            chunk = fh.read(4 * 1024 * 1024)
            state["pos"] = fh.tell()
        return chunk.splitlines()

    def _read_journal(self) -> list[str]:
        if not self.journal or self.journal.poll() is not None:
            return []
        lines = []
        try:
            ready, _, _ = select.select([self.journal.stdout], [], [], 0)
            while ready:
                line = self.journal.stdout.readline()
                if not line:
                    break
                lines.append(line)
                ready, _, _ = select.select([self.journal.stdout], [], [], 0)
        except (OSError, ValueError):
            pass
        return lines

    def collect(self) -> list[Event]:
        lines: list[str] = []
        for path, state in self.files.items():
            lines.extend(self._read_file(path, state))
        lines.extend(self._read_journal())
        events = []
        for line in lines:
            parsed = parse_auth_line(line)
            if parsed:
                action, data = parsed
                events.append(self.event("auth", action, **data))
        return events

    def teardown(self) -> None:
        if self.journal:
            self.journal.terminate()
