"""Enrolment rules, request-size and rate limits, notification and CLI."""
from __future__ import annotations

import http.server
import json
import threading

from softauthn import FLAG_AT, FLAG_UP, SoftAuthenticator

from perathos_gate import notify
from perathos_gate.app import admin_invite
from perathos_gate.cli import main as cli_main


def _enrol_path(gate, org_id, name="Bob"):
    url = admin_invite(gate.db, gate.settings, org_id, name)
    return url[len(gate.settings.origin):]


def test_enrol_link_single_use(gate):
    org_id, _ = gate.org()
    path = _enrol_path(gate, org_id)
    auth = SoftAuthenticator("localhost", "http://localhost:8787")
    opts = gate.client.post(path + "/options", json={}).json()
    assert opts["authenticatorSelection"]["userVerification"] == "required"
    assert opts["authenticatorSelection"]["residentKey"] == "preferred"
    assert opts["attestation"] == "none" and opts["rp"]["id"] == "localhost"
    assert gate.client.post(path + "/verify", json={"credential": auth.register(opts)}).status_code == 200
    # used: page, options and verify all refuse
    assert gate.client.get(path).status_code == 404
    assert gate.client.post(path + "/options", json={}).status_code == 404
    other = SoftAuthenticator("localhost", "http://localhost:8787")
    assert gate.client.post(path + "/verify", json={"credential": other.register(opts)}).status_code == 404


def test_enrol_requires_user_verification(gate):
    org_id, _ = gate.org()
    path = _enrol_path(gate, org_id)
    auth = SoftAuthenticator("localhost", "http://localhost:8787")
    opts = gate.client.post(path + "/options", json={}).json()
    r = gate.client.post(path + "/verify", json={"credential": auth.register(opts, flags=FLAG_UP | FLAG_AT)})
    assert r.status_code == 400
    # the link is not burned by a failed attempt
    opts = gate.client.post(path + "/options", json={}).json()
    assert gate.client.post(path + "/verify", json={"credential": auth.register(opts)}).status_code == 200


def test_enrol_wrong_challenge(gate):
    org_id, _ = gate.org()
    path = _enrol_path(gate, org_id)
    auth = SoftAuthenticator("localhost", "http://localhost:8787")
    opts = gate.client.post(path + "/options", json={}).json()
    gate.client.post(path + "/options", json={})  # a newer challenge replaces the first
    assert gate.client.post(path + "/verify", json={"credential": auth.register(opts)}).status_code == 400


def test_enrol_bad_token(gate):
    assert gate.client.get("/enroll/not-a-token").status_code == 404
    assert gate.client.post("/enroll/not-a-token/options", json={}).status_code == 404


def test_body_too_large(gate):
    _, key = gate.org()
    big = {"action": {"summary": "x" * (70 * 1024)}, "agent": {}, "args_hash": "0" * 64}
    r = gate.client.post("/v1/approvals", json=big, headers={"Authorization": f"Bearer {key}"})
    assert r.status_code == 413


def test_rate_limit(make_gate):
    gate = make_gate(rate_limit_per_min=5)
    codes = [gate.client.post("/a/apr_aaaaaaaaaaaaaaaaaaaaaaaaaa/options", json={"t": "x", "decision": "approve"})
             .status_code for _ in range(7)]
    assert codes[:5] == [404] * 5 and codes[5:] == [429, 429]


def test_no_cors(gate):
    r = gate.client.options("/v1/approvals", headers={"Origin": "https://evil.example",
                                                      "Access-Control-Request-Method": "POST"})
    assert "access-control-allow-origin" not in {k.lower() for k in r.headers}


def test_webhook_delivery_real_thread():
    received = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802
            received.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
            self.send_response(200)
            self.end_headers()

        def log_message(self, *a):
            pass

    srv = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=srv.handle_request, daemon=True).start()
    req = {"agent": {"name": "bot"}, "action": {"summary": "drop table users"}}
    t = notify.send_webhook(f"http://127.0.0.1:{srv.server_port}/hook", req, "https://g/a/apr_x?t=y")
    t.join(5)
    srv.server_close()
    assert received == [{"text": "bot wants to drop table users. Approve or deny: https://g/a/apr_x?t=y"}]
    # unreachable hooks fail quietly in the background
    t = notify.send_webhook("http://127.0.0.1:9/nothing", req, "u", timeout=1)
    t.join(5)
    assert notify.send_webhook("ftp://x", req, "u") is None


def test_cli_end_to_end(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{(tmp_path / 'd' / 'gate.db').as_posix()}")
    monkeypatch.setenv("GATE_KEY_FILE", str(tmp_path / "d" / "gate_signing.key"))
    monkeypatch.delenv("GATE_SIGNING_KEY", raising=False)
    assert cli_main(["init"]) == 0
    out = capsys.readouterr().out
    assert "Verify key:" in out and (tmp_path / "d" / "gate_signing.key").exists()
    assert cli_main(["create-org", "Acme", "--webhook", "https://example.com/hook"]) == 0
    out = capsys.readouterr().out
    org_id = out.split("Org id:")[1].split()[0]
    assert "API key: pgk_" in out
    assert cli_main(["invite", "--org", org_id, "--name", "Alice Moyo"]) == 0
    assert "/enroll/" in capsys.readouterr().out
    assert cli_main(["invite", "--org", "org_missing", "--name", "x"]) == 1
    assert cli_main(["list-approvals", "--org", org_id]) == 0
    assert "No approvals." in capsys.readouterr().out
