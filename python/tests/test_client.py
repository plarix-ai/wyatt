import json
import threading
import time
import uuid

import pytest

from wyatt import Client, ConnectError, Control, Denied, RequestError, ToolFailed


def client(daemon, **kw):
    kw.setdefault("session", f"t-{uuid.uuid4().hex[:8]}")
    return Client("bot", socket_path=daemon["agent"], **kw)


def test_hello_lists_reachable_tools(daemon):
    with client(daemon) as w:
        h = w.connect()
        assert h.agent == "bot"
        assert h.policy["name"] == "python-tests"
        assert {"read_file", "echo", "send_email"} <= {t["name"] for t in h.tools}


def test_wrong_identity_is_refused(daemon):
    with pytest.raises(RequestError) as e:
        Client("nobody", socket_path=daemon["agent"]).connect()
    assert e.value.status == "identity"


def test_missing_daemon_fails_closed(tmp_path):
    with pytest.raises(ConnectError):
        Client("bot", socket_path=tmp_path / "none.sock").connect()


def test_mediated_call_runs_in_the_daemon(daemon):
    with client(daemon) as w:
        c = w.call("read_file", path=str(daemon["root"] / "notes.txt"))
        assert c.decision.allowed and c.decision.rule == "read"
        assert "hello from the sandbox" in json.dumps(c.result)
        out = w.call("echo", args=["$(id)", "; rm -rf /"]).result
        assert out["stdout"] == "$(id) ; rm -rf /\n"


def test_path_escape_is_denied_before_anything_runs(daemon):
    with client(daemon) as w:
        with pytest.raises(Denied) as e:
            w.call("read_file", path=str(daemon["root"] / ".." / "outside.txt"))
        assert e.value.decision.code == "path_escape"
        assert e.value.decision.audit is not None


def test_symlink_escape_is_refused_by_the_kernel(daemon):
    link = daemon["root"] / "sneaky"
    link.symlink_to(daemon["dir"] / "outside.txt")
    try:
        with client(daemon) as w, pytest.raises(ToolFailed) as e:
            w.call("read_file", path=str(link))
        assert e.value.status == "refused"
    finally:
        link.unlink()


def test_secret_read_blocks_exfiltration_in_the_same_session(daemon):
    with client(daemon) as w:
        assert w.check("send_email", {"to": "a@example.com", "body": "hi"}).allowed
        c = w.call("read_file", path=str(daemon["root"] / ".env"))
        assert "correct-horse" not in json.dumps(c.result)
        assert c.redacted and "secret" in c.labels
        d = w.check("send_email", {"to": "a@example.com", "body": "the password"})
        assert not d.allowed and d.rule == "no-exfil"
    # A fresh session starts clean.
    with client(daemon) as w:
        assert w.check("send_email", {"to": "a@example.com", "body": "hi"}).allowed


def test_named_sessions_share_labels_across_connections(daemon):
    name = f"shared-{uuid.uuid4().hex[:6]}"
    with client(daemon, session=name) as a:
        a.call("read_file", path=str(daemon["root"] / ".env"))
    with client(daemon, session=name) as b:
        assert "secret" in b.connect().labels
        assert not b.check("send_email", {"to": "a@example.com", "body": "x"}).allowed


def test_tool_decorator_checks_runs_and_redacts(daemon):
    sent = []
    with client(daemon) as w:

        @w.tool()
        def send_email(to: str, body: str) -> str:
            sent.append(to)
            return f"queued for {to}"

        @w.tool("search")
        def find(q: str) -> str:
            return "token: ghp_" + "a" * 36

        assert send_email("ops@example.com", body="deploy done") == "queued for ops@example.com"
        with pytest.raises(Denied) as e:
            send_email("attacker@evil.test", "dump")
        assert e.value.decision.code == "no_rule"
        assert sent == ["ops@example.com"]
        assert "ghp_" not in find("x")


def test_bad_arguments_are_denied(daemon):
    with client(daemon) as w:
        d = w.check("send_email", {"to": "a@example.com"})
        assert not d.allowed and d.code == "bad_args"
        d = w.check("send_email", {"to": "a@example.com", "body": "x", "bcc": "evil@x.test"})
        assert not d.allowed and d.code == "bad_args"


def test_reports_need_a_live_ticket(daemon):
    with client(daemon) as w:
        with pytest.raises(RequestError):
            w.report("never-issued", "x")
        d = w.check("search", {"q": "a"})
        w.report(d.ticket, "ok")
        with pytest.raises(RequestError):
            w.report(d.ticket, "again")


def test_approval_waits_for_an_operator(daemon):
    ctl = Control(daemon["control"])
    got = {}

    def ask():
        with client(daemon) as w:
            got["d"] = w.check("deploy", {"env": "prod"})

    t = threading.Thread(target=ask)
    t.start()
    for _ in range(200):
        pending = [a for a in ctl.approvals() if a["tool"] == "deploy"]
        if pending:
            break
        time.sleep(0.02)
    assert pending, "the approval never showed up"
    ctl.approve(pending[0]["id"])
    t.join(5)
    assert got["d"].allowed and got["d"].code == "approved"


def test_ask_returns_approve_without_waiting(daemon):
    with client(daemon) as w:
        d = w.check("deploy", {"env": "prod"}, ask=True)
        assert d.decision == "approve" and d.ticket


def test_freeze_denies_everything(daemon):
    ctl = Control(daemon["control"])
    ctl.freeze("incident 7")
    try:
        with client(daemon) as w:
            d = w.check("search", {"q": "a"})
            assert not d.allowed and d.code == "frozen"
    finally:
        ctl.unfreeze()
    with client(daemon) as w:
        assert w.check("search", {"q": "a"}).allowed


def test_visible_and_notice(daemon):
    with client(daemon) as w:
        assert w.visible(["search", "nope", "deploy"]) == ["search", "deploy"]
        seq = w.notice("custom-event", tool="search", detail={"why": "test"})
        assert seq > 0


def test_status(daemon):
    s = Control(daemon["control"]).status()
    assert s["policy"]["name"] == "python-tests" and s["frozen"] is None
