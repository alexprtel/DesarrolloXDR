import os
import subprocess
import time

from xdr.events import Alert
from xdr.response.actions import ResponseActions, is_system_path
from xdr.response.playbooks import Playbook, build_params


def make(tmp_path, **kw):
    settings = {"dry_run": False, "protected_processes": ["systemd"], "never_block_ips": ["127.0.0.1"]}
    settings.update(kw)
    return ResponseActions(settings, str(tmp_path))


def test_kill_process(tmp_path):
    ra = make(tmp_path)
    p = subprocess.Popen(["sleep", "30"])
    res = ra.execute("kill_process", pid=p.pid)
    assert res["success"], res
    p.wait(timeout=5)
    assert p.returncode is not None


def test_kill_refuses_protected(tmp_path):
    ra = make(tmp_path)
    assert not ra.kill_process(pid=1)["success"]
    assert not ra.kill_process(pid=os.getpid())["success"]


def test_kill_detects_pid_reuse(tmp_path):
    ra = make(tmp_path)
    p = subprocess.Popen(["sleep", "30"])
    try:
        assert not ra.kill_process(pid=p.pid, create_time=time.time() - 10000)["success"]
    finally:
        p.kill()


def test_quarantine_and_restore(tmp_path):
    ra = make(tmp_path)
    f = tmp_path / "malware.bin"
    f.write_bytes(b"MZ evil")
    os.chmod(f, 0o755)
    res = ra.quarantine_file(path=str(f))
    assert res["success"] and not f.exists()
    assert ra.quarantine_file(path=str(f))["message"] == "ya estaba en cuarentena"
    listing = ra.list_quarantine()
    assert listing["items"][0]["original_path"] == str(f)
    assert ra.restore_file(quarantine_id=res["quarantine_id"])["success"]
    assert f.read_bytes() == b"MZ evil" and oct(f.stat().st_mode & 0o777) == "0o755"


def test_dry_run_and_validation(tmp_path):
    ra = make(tmp_path, dry_run=True)
    f = tmp_path / "x"
    f.write_text("x")
    assert ra.quarantine_file(path=str(f))["dry_run"] and f.exists()
    assert not ra.block_ip(ip="no-es-ip")["success"]
    assert not ra.block_ip(ip="127.0.0.1")["success"]
    assert not ra.disable_user(user="root")["success"]
    assert not ra.execute("nope")["success"]


def test_forensics(tmp_path):
    res = make(tmp_path).collect_forensics(reason="test")
    assert res["success"] and os.path.exists(res["path"]) and res["processes"] > 0


def test_playbook():
    alert = Alert(rule_id="X", title="t", severity="critical",
                  event={"data": {"pid": 42, "path": "/tmp/x", "src_ip": "203.0.113.1"}},
                  recommended_actions=["kill_process", "quarantine_file", "block_ip", "isolate_host"])
    plan = dict(Playbook({"enabled": True, "min_severity": "high"}).plan(alert))
    assert plan["kill_process"]["pid"] == 42 and plan["block_ip"]["ip"] == "203.0.113.1"
    assert "isolate_host" not in plan  # opt-in
    assert Playbook({"enabled": True, "min_severity": "critical"}).plan(
        Alert(rule_id="Y", title="t", severity="high", recommended_actions=["kill_process"],
              event={"data": {"pid": 1}})) == []
    assert build_params("block_ip", {"context": {"ioc_type": "ip", "ioc": "1.2.3.4"}}) == {"ip": "1.2.3.4"}


def test_never_quarantines_system_binaries(tmp_path):
    """Regresión: una línea de comandos maliciosa ejecutada por bash no debe
    provocar la cuarentena de /usr/bin/bash (dejaba el equipo sin shell)."""
    shell_alert = {"event": {"data": {"pid": 7, "exe": "/usr/bin/bash", "name": "bash",
                                      "cmdline": "bash -c 'xmrig --donate-level 1'"}}}
    assert build_params("quarantine_file", shell_alert) is None
    dropped = {"event": {"data": {"pid": 7, "exe": "/tmp/.x/xmrig"}}}
    assert build_params("quarantine_file", dropped) == {"path": "/tmp/.x/xmrig"}
    ra = make(tmp_path)
    for path in ("/usr/bin/bash", "/bin/sh", "/etc/passwd", "/etc/pam.d/common-auth"):
        if os.path.exists(path):
            res = ra.quarantine_file(path=path)
            assert not res["success"] and "protegid" in res["message"], res
            assert os.path.exists(path)
            assert not ra.delete_file(path=path)["success"]
    assert is_system_path("/usr/lib/x86_64-linux-gnu/libc.so.6")
    assert not is_system_path("/usr/local/bin/implant")
    assert not is_system_path("/tmp/malware")
