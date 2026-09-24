import json
import time
import urllib.error
import urllib.request

import pytest

from conftest import ev, make_config
from xdr.agent import Agent
from xdr.server.api import XDRServer
from xdr.server.core import ServerCore
from xdr.transport import HttpTransport, LocalTransport, TransportError


@pytest.fixture
def server(tmp_path):
    cfg = make_config(tmp_path)
    core = ServerCore(cfg)
    srv = XDRServer(core, "127.0.0.1", 0)
    srv.start()
    yield srv, core, cfg
    srv.stop()


def call(url, path, token=None, body=None, method=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url + path, data=data, method=method or ("POST" if data else "GET"),
                                 headers={"Content-Type": "application/json"})
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, json.loads(r.read() or b"null")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"null")


def test_auth_required(server):
    srv, _, _ = server
    assert call(srv.url, "/api/overview")[0] == 401
    assert call(srv.url, "/api/overview", "wrong")[0] == 401
    assert call(srv.url, "/api/overview", "admin-test")[0] == 200
    assert call(srv.url, "/api/agent/events", "fake", {"events": []})[0] == 401
    assert call(srv.url, "/api/agent/register", None, {"info": {}, "enroll_key": "bad"})[0] == 401
    assert call(srv.url, "/api/health")[0] == 200


def test_static_and_traversal(server):
    srv, _, _ = server
    with urllib.request.urlopen(srv.url + "/") as r:
        body = r.read().decode()
        assert "SentinelXDR" in body and "default-src 'self'" in r.headers["Content-Security-Policy"]
    for bad in ("/../../etc/passwd", "/%2e%2e/%2e%2e/etc/passwd", "/..%2fserver.db"):
        with pytest.raises(urllib.error.HTTPError) as exc:
            urllib.request.urlopen(srv.url + bad)
        assert exc.value.code == 404


def test_agent_flow_over_http(server):
    srv, core, _ = server
    t = HttpTransport(srv.url, "enroll-test")
    reg = t.register({"hostname": "web-01", "os": "Linux"})
    alert = {"rule_id": "PROC-009", "title": "Criptominero", "severity": "critical", "tactic": "impact",
             "mitre": ["T1496"], "event": ev("process", "start", pid=99, name="xmrig").to_dict()}
    res = t.send([ev("process", "start", name="xmrig", pid=99).to_dict(),
                  ev("metric", "x").to_dict()], [alert])
    assert res["alerts"] == 1
    status, alerts = call(srv.url, "/api/alerts", "admin-test")
    assert alerts[0]["host"] == "web-01" and alerts[0]["incident_id"]
    # respuesta manual desde la consola -> cola -> agente -> resultado
    status, cmd = call(srv.url, f"/api/alerts/{alerts[0]['id']}/respond", "admin-test", {"action": "kill_process"})
    assert status == 200 and cmd["params"]["pid"] == 99
    hb = t.heartbeat({"intel_version": 0})
    assert hb["commands"][0]["id"] == cmd["id"] and "intel" in hb
    assert t.heartbeat({"intel_version": hb["intel_version"]})["commands"] == []
    t.command_result(cmd["id"], {"success": True, "message": "ok"})
    _, cmds = call(srv.url, "/api/commands", "admin-test")
    assert cmds[0]["status"] == "done"
    _, agents = call(srv.url, "/api/agents", "admin-test")
    assert agents[0]["hostname"] == "web-01" and agents[0]["online"] and "token" not in agents[0]
    # re-registro conserva la identidad
    assert t.register({"hostname": "web-01"})["agent_id"] == reg["agent_id"]
    # búsqueda de eventos (threat hunting)
    _, evs = call(srv.url, "/api/events?q=xmrig", "admin-test")
    assert len(evs) == 1 and evs[0]["category"] == "process"
    # estados y validación
    assert call(srv.url, f"/api/alerts/{alerts[0]['id']}/status", "admin-test", {"status": "closed"})[0] == 200
    assert call(srv.url, f"/api/alerts/{alerts[0]['id']}/status", "admin-test", {"status": "x"})[0] == 400
    assert call(srv.url, "/api/commands", "admin-test",
                {"agent_id": reg["agent_id"], "action": "rm_rf"})[0] == 400


def test_ioc_distribution(server):
    srv, core, _ = server
    t = HttpTransport(srv.url, "enroll-test")
    t.register({"hostname": "h"})
    v0 = t.heartbeat({"intel_version": 0})["intel_version"]
    assert call(srv.url, "/api/iocs", "admin-test", {"type": "ips", "value": "192.0.2.10"})[0] == 200
    hb = t.heartbeat({"intel_version": v0})
    assert "192.0.2.10" in hb["intel"]["ips"]


def test_transport_errors():
    t = HttpTransport("http://127.0.0.1:1", "k", timeout=1)
    with pytest.raises(TransportError):
        t.register({})


def test_agent_end_to_end(tmp_path):
    cfg = make_config(tmp_path)
    core = ServerCore(cfg)
    agent = Agent(cfg, LocalTransport(core, "enroll-test"), collectors=[])
    agent._register()
    alerts = agent.process(ev("process", "start", name="xmrig", pid=999999, cmdline="xmrig -o stratum+tcp://p:3333",
                              exe="/tmp/.x/xmrig"))
    assert {"PROC-009", "PROC-004"} <= {a.rule_id for a in alerts}
    miner = next(a for a in alerts if a.rule_id == "PROC-009")
    assert miner.response and miner.response[0]["action"] == "kill_process"
    agent.flush()
    stored = core.storage.query_alerts()
    assert {a["rule_id"] for a in stored} >= {"PROC-009", "PROC-004"}
    assert core.overview()["incidents"]["open"] == 1
    # servidor caído -> cola local persistente -> reenvío
    agent.transport = HttpTransport("http://127.0.0.1:1", "k", token="x", timeout=1)
    agent.connected = True
    agent.process(ev("kernel", "hidden_process", pid=4242, name="evil"))
    agent.flush()
    assert agent.storage.outbox_size() == 1
    agent.transport = LocalTransport(core, "enroll-test")
    agent.connected = False
    agent.flush()
    assert agent.storage.outbox_size() == 0
    assert core.storage.query_alerts(rule_id="KRN-003")
