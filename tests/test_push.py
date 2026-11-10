"""Web Push: who may subscribe a device, who gets notified, and what happens when delivery fails."""
from __future__ import annotations

import http.server
import json
import os
import threading

import http_ece
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from softauthn import SoftAuthenticator, b64url, b64url_decode
from sqlalchemy import select

from perathos_gate import push
from perathos_gate.app import admin_invite
from perathos_gate.cli import main as cli_main
from perathos_gate.config import Settings
from perathos_gate.models import Approver, PushSubscription


def _device(n: int = 1, host: str = "push.example.net") -> dict:
    """What a browser's PushSubscription.toJSON() looks like."""
    key = ec.generate_private_key(ec.SECP256R1())
    point = key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    return {"endpoint": f"https://{host}/send/device-{n}", "expirationTime": None,
            "keys": {"p256dh": b64url(point), "auth": b64url(os.urandom(16))}}


def _enrol(gate, org_id: str, name: str = "Alice Moyo") -> tuple[SoftAuthenticator, dict]:
    """Enrol a passkey and return (authenticator, the enrol-verify response body)."""
    path = admin_invite(gate.db, gate.settings, org_id, name)[len(gate.settings.origin):]
    auth = SoftAuthenticator(gate.settings.rp_id, gate.settings.origin)
    opts = gate.client.post(path + "/options", json={}).json()
    r = gate.client.post(path + "/verify", json={"credential": auth.register(opts)})
    assert r.status_code == 200, r.text
    return auth, r.json()


def _subscribe(gate, token, device: dict):
    return gate.client.post("/push/subscribe", json={"token": token, "subscription": device})


def _rows(gate) -> list[PushSubscription]:
    with gate.db.session() as s:
        return list(s.scalars(select(PushSubscription).order_by(PushSubscription.id)).all())


def _approver_id(gate, name: str) -> int:
    with gate.db.session() as s:
        return s.scalars(select(Approver.id).where(Approver.name == name)).one()


def _secret(gate) -> bytes:
    return push.load_vapid(gate.settings).secret


# ----------------------------------------------------------------- disabled


def test_without_vapid_nothing_changes(gate):
    assert gate.client.app.state.pusher is None
    org_id, key = gate.org()
    path = admin_invite(gate.db, gate.settings, org_id, "Alice")[len(gate.settings.origin):]
    page = gate.client.get(path)
    assert page.status_code == 200
    assert "push-on" not in page.text and "manifest" not in page.text and "data-vapid-key" not in page.text
    auth, enrolled = _enrol(gate, org_id)
    assert "push_token" not in enrolled
    created = gate.create(key)
    approve_page = gate.client.get(created["approve_url"][len(gate.settings.origin):])
    assert approve_page.status_code == 200 and "push-on" not in approve_page.text
    decided = gate.decide(created, "approve", auth)
    assert decided.status_code == 200 and "push_token" not in decided.json()
    for path in ("/", "/sw.js", "/manifest.webmanifest"):
        assert gate.client.get(path).status_code == 404
    assert _subscribe(gate, "1.9999999999.x", _device()).status_code == 404
    assert gate.client.post("/push/unsubscribe", json={"endpoint": "https://push.example.net/x"}).status_code == 404
    assert gate.pushes == []


def test_bad_vapid_key_disables_push_but_not_the_server(make_gate, caplog):
    gate = make_gate(vapid_private_key="not-a-key", vapid_subject="mailto:ops@example.com")
    assert gate.client.app.state.pusher is None
    assert "push disabled" in caplog.text and "not-a-key" not in caplog.text
    _, key = gate.org()
    assert gate.create(key)["status"] == "pending"
    # a key without a usable subject is refused the same way (the test origin is plain http)
    s = Settings(origin="http://localhost:8787", vapid_private_key=push.generate_vapid_keys()[0])
    assert push.load_vapid(s) is None
    s.origin = "https://gate.example.com"
    assert push.load_vapid(s).subject == "https://gate.example.com"


# -------------------------------------------------------------------- pages


def test_pages_offer_the_button_and_serve_the_worker(push_gate):
    gate = push_gate
    org_id, key = gate.org()
    public = push.load_vapid(gate.settings).public_key
    assert len(b64url_decode(public)) == 65
    path = admin_invite(gate.db, gate.settings, org_id, "Alice")[len(gate.settings.origin):]
    page = gate.client.get(path)
    assert 'id="push-on"' in page.text and f'data-vapid-key="{public}"' in page.text
    assert 'rel="manifest"' in page.text
    assert "worker-src 'self'" in page.headers["content-security-policy"]
    assert "manifest-src 'self'" in page.headers["content-security-policy"]
    approve_page = gate.client.get(gate.create(key)["approve_url"][len(gate.settings.origin):])
    assert 'id="push-on"' in approve_page.text

    sw = gate.client.get("/sw.js")
    assert sw.status_code == 200 and sw.headers["content-type"].startswith("text/javascript")
    assert "notificationclick" in sw.text and "importScripts" not in sw.text
    manifest = gate.client.get("/manifest.webmanifest")
    assert manifest.headers["content-type"].startswith("application/manifest+json")
    assert manifest.json()["display"] == "standalone" and manifest.json()["start_url"] == "/"
    home = gate.client.get("/")
    assert home.status_code == 200 and 'id="push-signin"' in home.text


# ---------------------------------------------------------------- subscribe


def test_subscribe_requires_a_valid_token(push_gate):
    gate = push_gate
    org_id, _ = gate.org()
    _, enrolled = _enrol(gate, org_id)
    token = enrolled["push_token"]
    device = _device()
    assert gate.client.post("/push/subscribe", json={"subscription": device}).status_code == 422
    for bad in ("", "garbage", "1.2.3", token[:-2] + "AA", token + "x"):
        assert _subscribe(gate, bad, device).status_code == 403, bad
    assert _rows(gate) == []
    assert _subscribe(gate, token, device).status_code == 200
    row, = _rows(gate)
    assert row.endpoint == device["endpoint"] and row.org_id == org_id
    assert row.approver_id == _approver_id(gate, "Alice Moyo")
    assert row.p256dh == device["keys"]["p256dh"] and row.auth == device["keys"]["auth"]
    assert row.created_at is not None and row.last_success_at is None and row.last_failure_at is None
    # subscribing the same device again does not duplicate it
    assert _subscribe(gate, token, device).status_code == 200
    assert len(_rows(gate)) == 1


def test_token_of_one_approver_cannot_subscribe_for_another(push_gate):
    gate = push_gate
    org_a, _ = gate.org("A")
    org_b, _ = gate.org("B")
    _, alice = _enrol(gate, org_a, "Alice")
    _enrol(gate, org_b, "Bob")
    alice_id, bob_id = _approver_id(gate, "Alice"), _approver_id(gate, "Bob")
    # Alice's token, edited to name Bob: the signature no longer matches
    _, expires, mac = alice["push_token"].split(".")
    assert _subscribe(gate, f"{bob_id}.{expires}.{mac}", _device()).status_code == 403
    assert _rows(gate) == []
    # used as issued, it attaches the device to Alice and her org only
    assert _subscribe(gate, alice["push_token"], _device()).status_code == 200
    row, = _rows(gate)
    assert (row.approver_id, row.org_id) == (alice_id, org_a)
    # a token minted under another server key is worthless here
    other = push.issue_token(b"\x01" * 32, bob_id)
    assert _subscribe(gate, other, _device(2)).status_code == 403


def test_expired_token_rejected(push_gate):
    gate = push_gate
    org_id, _ = gate.org()
    _enrol(gate, org_id)
    approver_id = _approver_id(gate, "Alice Moyo")
    expired = push.issue_token(_secret(gate), approver_id, ttl=-1)
    assert _subscribe(gate, expired, _device()).status_code == 403
    assert _subscribe(gate, push.issue_token(_secret(gate), approver_id), _device()).status_code == 200
    # a valid token for an approver who was since deactivated is refused too
    with gate.db.session() as s:
        s.get(Approver, approver_id).active = False
    assert _subscribe(gate, push.issue_token(_secret(gate), approver_id), _device(2)).status_code == 403
    assert len(_rows(gate)) == 1


def test_decision_also_issues_a_token(push_gate):
    gate = push_gate
    org_id, key = gate.org()
    auth, _ = _enrol(gate, org_id)
    decided = gate.decide(gate.create(key), "deny", auth)
    assert decided.status_code == 200
    assert _subscribe(gate, decided.json()["push_token"], _device()).status_code == 200
    assert _rows(gate)[0].approver_id == _approver_id(gate, "Alice Moyo")


def test_subscription_must_look_like_a_push_subscription(push_gate):
    gate = push_gate
    org_id, _ = gate.org()
    _, enrolled = _enrol(gate, org_id)
    good = _device()
    bad_endpoints = ["http://push.example.net/x", "https://127.0.0.1/x", "https://[::1]/x", "https://localhost/x",
                     "https://db.internal/x", "ftp://push.example.net/x", "", "https://push.example.net/" + "a" * 3000]
    for endpoint in bad_endpoints:
        assert _subscribe(gate, enrolled["push_token"], {**good, "endpoint": endpoint}).status_code == 422, endpoint
    for keys in ({}, {"p256dh": good["keys"]["p256dh"]}, {"p256dh": "AAAA", "auth": good["keys"]["auth"]},
                 {"p256dh": good["keys"]["p256dh"], "auth": "AAAA"}):
        assert _subscribe(gate, enrolled["push_token"], {**good, "keys": keys}).status_code == 422
    assert _rows(gate) == []


def test_unsubscribe(push_gate):
    gate = push_gate
    org_id, key = gate.org()
    _, enrolled = _enrol(gate, org_id)
    device = _device()
    _subscribe(gate, enrolled["push_token"], device)
    r = gate.client.post("/push/unsubscribe", json={"endpoint": "https://push.example.net/send/unknown"})
    assert r.json() == {"ok": True, "removed": False} and len(_rows(gate)) == 1
    r = gate.client.post("/push/unsubscribe", json={"endpoint": device["endpoint"]})
    assert r.json() == {"ok": True, "removed": True} and _rows(gate) == []
    gate.create(key)
    gate.wait_push()
    assert gate.pushes == []


def test_confirm_with_passkey_on_the_home_page(push_gate):
    gate = push_gate
    org_id, _ = gate.org()
    auth, _ = _enrol(gate, org_id)
    opts = gate.client.post("/push/options", json={}).json()
    assert opts["allowCredentials"] == [] and opts["userVerification"] == "required"
    assert len(b64url_decode(opts["challenge"])) == 56  # never the size of a decision challenge
    r = gate.client.post("/push/verify", json={"credential": auth.assert_(opts)})
    assert r.status_code == 200 and r.json()["approver"] == "Alice Moyo"
    assert _subscribe(gate, r.json()["push_token"], _device()).status_code == 200
    # a challenge this server did not issue, or an expired one, is refused before any signature check
    forged = b64url(os.urandom(56))
    assert gate.client.post("/push/verify", json={"credential": auth.assert_(opts, challenge_override=forged)}) \
        .status_code == 400
    stale = b64url(push.new_challenge(_secret(gate), ttl=-1))
    assert gate.client.post("/push/verify", json={"credential": auth.assert_(opts, challenge_override=stale)}) \
        .status_code == 400
    # a passkey that was never enrolled gets nothing
    stranger = SoftAuthenticator(gate.settings.rp_id, gate.settings.origin)
    opts = gate.client.post("/push/options", json={}).json()
    assert gate.client.post("/push/verify", json={"credential": stranger.assert_(opts)}).status_code == 400
    assert gate.client.post("/push/verify", json={"credential": {"id": "x"}}).status_code == 400


# ------------------------------------------------------------------ sending


def test_approval_pushes_to_every_device_in_the_org_only(push_gate, caplog):
    gate = push_gate
    org_a, key_a = gate.org("A")
    org_b, key_b = gate.org("B")
    _, alice = _enrol(gate, org_a, "Alice")
    _, amara = _enrol(gate, org_a, "Amara")
    _, bob = _enrol(gate, org_b, "Bob")
    phone, laptop, tablet, bobs = _device(1), _device(2), _device(3), _device(4)
    for token, device in ((alice["push_token"], phone), (alice["push_token"], laptop),
                          (amara["push_token"], tablet), (bob["push_token"], bobs)):
        assert _subscribe(gate, token, device).status_code == 200

    with caplog.at_level("INFO"):
        created = gate.create(key_a, summary="railway volume delete pg-data --yes " + "x" * 400, ttl=600)
        gate.wait_push()
    assert sorted(p[0]["endpoint"] for p in gate.pushes) == sorted(d["endpoint"] for d in (phone, laptop, tablet))
    info, payload, ttl = gate.pushes[0]
    assert set(info["keys"]) == {"p256dh", "auth"} and 590 <= ttl <= 600
    message = json.loads(payload)
    assert message["url"] == created["approve_url"] and message["tag"] == created["id"]
    assert message["title"] == "claude-code is asking for approval"
    assert message["body"].startswith("railway volume delete pg-data --yes") and len(message["body"]) == 180
    by_endpoint = {r.endpoint: r for r in _rows(gate)}
    assert by_endpoint[phone["endpoint"]].last_success_at is not None
    assert by_endpoint[bobs["endpoint"]].last_success_at is None
    # logs name the push host only: never the endpoint path, never the approve token
    assert "push.example.net" in caplog.text
    assert "device-1" not in caplog.text and created["approve_url"].split("t=")[1] not in caplog.text

    gate.pushes.clear()
    gate.create(key_b)
    gate.wait_push()
    assert [p[0]["endpoint"] for p in gate.pushes] == [bobs["endpoint"]]


def test_gone_subscriptions_are_removed(push_gate):
    gate = push_gate
    org_id, key = gate.org()
    _, enrolled = _enrol(gate, org_id)
    gone, missing, busy, fine = _device(1), _device(2), _device(3), _device(4)
    for device in (gone, missing, busy, fine):
        _subscribe(gate, enrolled["push_token"], device)
    gate.push_answers.update({gone["endpoint"]: 410, missing["endpoint"]: 404, busy["endpoint"]: 503})
    gate.create(key)
    gate.wait_push()
    assert len(gate.pushes) == 4
    rows = {r.endpoint: r for r in _rows(gate)}
    assert set(rows) == {busy["endpoint"], fine["endpoint"]}
    assert rows[busy["endpoint"]].last_failure_at is not None and rows[busy["endpoint"]].last_success_at is None
    assert rows[fine["endpoint"]].last_success_at is not None and rows[fine["endpoint"]].last_failure_at is None
    # the next request no longer tries the removed devices
    gate.pushes.clear()
    gate.create(key)
    gate.wait_push()
    assert len(gate.pushes) == 2


def test_push_failure_never_breaks_approval_creation(push_gate, monkeypatch):
    gate = push_gate
    org_id, key = gate.org()
    _, enrolled = _enrol(gate, org_id)
    broken, fine = _device(1), _device(2)
    _subscribe(gate, enrolled["push_token"], broken)
    _subscribe(gate, enrolled["push_token"], fine)
    gate.push_answers[broken["endpoint"]] = OSError("connection reset")
    created = gate.create(key)  # asserts 201
    gate.wait_push()
    assert gate.status(key, created["id"]).json()["status"] == "pending"
    rows = {r.endpoint: r for r in _rows(gate)}
    assert rows[broken["endpoint"]].last_failure_at is not None
    assert rows[fine["endpoint"]].last_success_at is not None  # one bad device does not stop the others

    def explode(*args, **kwargs):
        raise RuntimeError("cannot start thread")

    monkeypatch.setattr(push, "notify_approval", explode)
    assert gate.create(key)["status"] == "pending"


def test_devices_of_deactivated_approvers_get_nothing(push_gate):
    gate = push_gate
    org_id, key = gate.org()
    _, enrolled = _enrol(gate, org_id)
    _subscribe(gate, enrolled["push_token"], _device())
    with gate.db.session() as s:
        s.get(Approver, _approver_id(gate, "Alice Moyo")).active = False
    gate.create(key)
    gate.wait_push()
    assert gate.pushes == []


def test_real_sender_encrypts_and_signs():
    """The pywebpush-backed sender against a local stand-in for a push service: the body decrypts
    with the device's keys (RFC 8291) and the request carries a VAPID header (RFC 8292)."""
    seen = []
    answers = [201, 410]

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802
            seen.append((dict(self.headers), self.rfile.read(int(self.headers["Content-Length"]))))
            self.send_response(answers[len(seen) - 1])
            self.end_headers()

        def log_message(self, *a):
            pass

    srv = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        private, public = push.generate_vapid_keys()
        vapid = push.load_vapid(Settings(vapid_private_key=private, vapid_subject="mailto:ops@example.com"))
        assert vapid.public_key == public
        device_key = ec.generate_private_key(ec.SECP256R1())
        point = device_key.public_key().public_bytes(serialization.Encoding.X962,
                                                     serialization.PublicFormat.UncompressedPoint)
        auth = os.urandom(16)
        info = {"endpoint": f"http://127.0.0.1:{srv.server_port}/send/abc",
                "keys": {"p256dh": b64url(point), "auth": b64url(auth)}}
        send = push.make_sender(vapid, timeout=5)
        data = push.payload({"id": "apr_x", "agent": {"name": "bot"}, "action": {"summary": "drop table users"}},
                            "https://g/a/apr_x?t=y")
        assert send(info, data, 120) == 201
        assert send(info, data, 120) == 410  # an HTTP error comes back as a status, not an exception
    finally:
        srv.shutdown()
        srv.server_close()
    headers, body = seen[0]
    headers = {k.lower(): v for k, v in headers.items()}
    assert headers["authorization"].startswith("vapid t=") and f"k={public}" in headers["authorization"]
    assert headers["content-encoding"] == "aes128gcm" and headers["ttl"] == "120" and headers["urgency"] == "high"
    assert b"apr_x" not in body
    plain = http_ece.decrypt(body, private_key=device_key, auth_secret=auth, version="aes128gcm")
    assert json.loads(plain) == {"title": "bot is asking for approval", "body": "drop table users",
                                 "url": "https://g/a/apr_x?t=y", "tag": "apr_x"}


def test_cli_vapid_keygen(capsys):
    assert cli_main(["vapid-keygen"]) == 0
    out = capsys.readouterr().out
    private = out.split("GATE_VAPID_PRIVATE_KEY=")[1].split()[0]
    vapid = push.load_vapid(Settings(vapid_private_key=private, vapid_subject="mailto:ops@example.com"))
    assert vapid is not None and vapid.public_key in out
