"""Sensor de mecanismos de persistencia (MITRE TA0003): cron, systemd, init,
perfiles de shell, authorized_keys, ld.so.preload, sudoers, PAM, autostart,
udev, hooks de APT, módulos de arranque y claves Run de Windows."""
from __future__ import annotations

import glob
import hashlib
import os
from typing import Any

from xdr.collectors.base import Collector
from xdr.events import Event
from xdr.utils import IS_WINDOWS, home_dirs, read_text

SYSTEM_LOCATIONS: list[tuple[str, str]] = [
    ("cron", "/etc/crontab"), ("cron", "/etc/cron.d/*"), ("cron", "/etc/cron.hourly/*"),
    ("cron", "/etc/cron.daily/*"), ("cron", "/etc/cron.weekly/*"), ("cron", "/etc/cron.monthly/*"),
    ("cron", "/var/spool/cron/*"), ("cron", "/var/spool/cron/crontabs/*"),
    ("at", "/var/spool/at/*"), ("at", "/var/spool/cron/atjobs/*"),
    ("systemd", "/etc/systemd/system/*.service"), ("systemd", "/etc/systemd/system/*.timer"),
    ("systemd", "/etc/systemd/system/*/*.service"), ("systemd", "/etc/systemd/system/*/*.timer"),
    ("systemd", "/run/systemd/system/*.service"), ("systemd", "/usr/lib/systemd/system-generators/*"),
    ("systemd", "/etc/systemd/system-generators/*"),
    ("init", "/etc/init.d/*"), ("init", "/etc/rc.local"), ("init", "/etc/rc.d/rc.local"),
    ("shell_profile", "/etc/profile"), ("shell_profile", "/etc/profile.d/*"),
    ("shell_profile", "/etc/bash.bashrc"), ("shell_profile", "/etc/bashrc"),
    ("shell_profile", "/etc/environment"), ("shell_profile", "/etc/zsh/zshrc"),
    ("ssh", "/etc/ssh/sshd_config"), ("ssh", "/etc/ssh/sshd_config.d/*"),
    ("preload", "/etc/ld.so.preload"), ("preload", "/etc/ld.so.conf.d/*"),
    ("sudoers", "/etc/sudoers"), ("sudoers", "/etc/sudoers.d/*"),
    ("pam", "/etc/pam.d/*"),
    ("autostart", "/etc/xdg/autostart/*"),
    ("udev", "/etc/udev/rules.d/*"),
    ("motd", "/etc/update-motd.d/*"),
    ("package_hook", "/etc/apt/apt.conf.d/*"), ("package_hook", "/etc/yum/pluginconf.d/*"),
    ("kernel_module", "/etc/modules"), ("kernel_module", "/etc/modules-load.d/*"),
    ("kernel_module", "/etc/modprobe.d/*"),
    ("accounts", "/etc/passwd"), ("accounts", "/etc/group"),
    ("hosts", "/etc/hosts"), ("dns", "/etc/resolv.conf"),
]

USER_LOCATIONS: list[tuple[str, str]] = [
    ("shell_profile", ".bashrc"), ("shell_profile", ".bash_profile"), ("shell_profile", ".profile"),
    ("shell_profile", ".zshrc"), ("shell_profile", ".bash_logout"), ("shell_profile", ".bash_login"),
    ("ssh", ".ssh/authorized_keys"), ("ssh", ".ssh/authorized_keys2"), ("ssh", ".ssh/rc"),
    ("autostart", ".config/autostart/*"), ("systemd", ".config/systemd/user/*.service"),
    ("systemd", ".config/systemd/user/*.timer"), ("systemd", ".config/systemd/user/*/*.service"),
    ("shell_profile", ".config/fish/config.fish"), ("x11", ".xinitrc"), ("x11", ".xsession"),
    ("vim", ".vimrc"),
]

WINDOWS_RUN_KEYS = [
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
    r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
]


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()


class PersistenceCollector(Collector):
    name = "persistence"
    default_interval = 20.0

    def setup(self) -> None:
        self.ns = "persistence"
        self.baseline: dict[str, dict] = self.storage.baseline_load(self.ns)
        self.initialized = self.storage.baseline_exists(self.ns)

    def _items(self) -> dict[str, dict[str, Any]]:
        items: dict[str, dict[str, Any]] = {}
        if IS_WINDOWS:
            items.update(self._windows_items())
            return items
        locations = list(SYSTEM_LOCATIONS)
        for home in home_dirs():
            for mech, rel in USER_LOCATIONS:
                locations.append((mech, os.path.join(home, rel)))
        for mech, pattern in locations:
            for path in glob.glob(pattern):
                if not os.path.isfile(path):
                    continue
                content = read_text(path, 256 * 1024)
                if content is None:
                    continue
                items[path] = {"mechanism": mech, "hash": _digest(content), "content": content}
        return items

    def _windows_items(self) -> dict[str, dict[str, Any]]:  # pragma: no cover - solo Windows
        items: dict[str, dict[str, Any]] = {}
        try:
            import winreg
        except ImportError:
            return items
        for hive_name, hive in (("HKLM", winreg.HKEY_LOCAL_MACHINE), ("HKCU", winreg.HKEY_CURRENT_USER)):
            for key_path in WINDOWS_RUN_KEYS:
                try:
                    with winreg.OpenKey(hive, key_path) as key:
                        i = 0
                        while True:
                            try:
                                name, value, _ = winreg.EnumValue(key, i)
                            except OSError:
                                break
                            ident = f"{hive_name}\\{key_path}\\{name}"
                            text = str(value)
                            items[ident] = {"mechanism": "registry_run", "hash": _digest(text),
                                            "content": text}
                            i += 1
                except OSError:
                    continue
        for folder in [os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"),
                       os.path.expandvars(r"%PROGRAMDATA%\Microsoft\Windows\Start Menu\Programs\StartUp"),
                       r"C:\Windows\System32\Tasks"]:
            for path in glob.glob(os.path.join(folder, "*")):
                if os.path.isfile(path):
                    text = read_text(path, 64 * 1024) or ""
                    items[path] = {"mechanism": "startup_folder" if "Start" in folder else
                                   "scheduled_task", "hash": _digest(text), "content": text}
        return items

    def collect(self) -> list[Event]:
        current = self._items()
        events: list[Event] = []
        if not self.initialized:
            for path, item in current.items():
                events.append(self._ev("existing", path, item, initial=True))
            self._save(current, [])
            self.initialized = True
            return events
        for path, item in current.items():
            prev = self.baseline.get(path)
            if prev is None:
                events.append(self._ev("created", path, item))
            elif prev.get("hash") != item["hash"]:
                events.append(self._ev("modified", path, item, previous=prev.get("content", "")))
        deleted = [p for p in self.baseline if p not in current]
        for path in deleted:
            events.append(self.event("persistence", "deleted", path=path,
                                     mechanism=self.baseline[path].get("mechanism", "")))
        if events or deleted:
            self._save(current, deleted)
        return events

    def _ev(self, action: str, path: str, item: dict, previous: str | None = None, **extra) -> Event:
        content = item["content"]
        data: dict[str, Any] = {"path": path, "mechanism": item["mechanism"],
                                "content": content[:4096], "sha256": item["hash"]}
        if previous is not None:
            old_lines = set(previous.splitlines())
            added = [ln for ln in content.splitlines() if ln not in old_lines]
            data["added_lines"] = "\n".join(added)[:4096]
        else:
            data["added_lines"] = content[:4096]
        data.update(extra)
        return self.event("persistence", action, **data)

    def _save(self, current: dict[str, dict], deleted: list[str]) -> None:
        changed = {p: {"mechanism": i["mechanism"], "hash": i["hash"], "content": i["content"][:65536]}
                   for p, i in current.items()
                   if self.baseline.get(p, {}).get("hash") != i["hash"]}
        self.storage.baseline_update(self.ns, changed, deleted)
        self.baseline = {p: {"mechanism": i["mechanism"], "hash": i["hash"],
                             "content": i["content"][:65536]} for p, i in current.items()}
