"""End-to-end flows through the real HTTP app with a software passkey (no network)."""
from __future__ import annotations

import copy
import threading
import time
from datetime import timedelta

from conftest import args_hash
from perathos.gate import b64url, b64url_decode, check_approval_for, decision_challenge, verify_receipt
from softauthn import FLAG_UP
from sqlalchemy import update

from perathos_gate.models import Approval, utcnow


def test_well_known(gate):
    r = gate.client.get("/.well-known/perathos-gate.json")
    assert r.status_code == 200
    body = r.json()
    assert body == {"gate": "gate.test", "verify_key": gate.verify_key, "rp_id": "localhost",
                    "origin": "http://localhost:8787", "version": "perathos.gate/v1"}


def test_full_approve_flow(gate):
    org_id, key = gate.org()
    alice = gate.enrol(org_id, "Alice Moyo")
    created = gate.create(key)
    assert created["status"] == "pending"
    assert created["id"].startswith("apr_") and created["approve_url"].startswith("http://localhost:8787/a/apr_")
    assert created["request"]["org"] == org_id and created["request"]["gate"] == "gate.test"
    assert created["expires_at"] == created["request"]["expires_at"]

    # approver page renders the action, with a CSP
    path, t = gate.page_parts(created)
    page = gate.client.get(f"{path}?t={t}")
    assert page.status_code == 200
    assert "railway volume delete pg-data --yes" in page.text and "Approve" in page.text and "Deny" in page.text
    assert "default-src 'none'" in page.headers["content-security-policy"]
    assert page.headers["referrer-policy"] == "no-referrer"

    # options carry exactly the decision challenge, UV required, the org's credential
    opts = gate.options(created, "approve").json()
    req_hash = gate.status(key, created["id"]).json()  # still pending
    assert req_hash["status"] == "pending" and "receipt" not in req_hash
    from perathos.gate import chash
    expected = decision_challenge(chash(created["request"]), "approve")
    assert b64url_decode(opts["challenge"]) == expected and len(expected) == 32
    assert opts["userVerification"] == "required" and opts["rpId"] == "localhost"
    assert [c["id"] for c in opts["allowCredentials"]] == [b64url(alice.credential_id)]

    r = gate.verify(created, "approve", alice.assert_(opts))
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "approved" and r.json()["approver"] == "Alice Moyo"

    st = gate.status(key, created["id"]).json()
    assert st["status"] == "approved"
    receipt = st["receipt"]
    assert receipt["decision"] == "approve" and receipt["approver"]["name"] == "Alice Moyo"
    assert receipt["approver"]["alg"] == -7
    assert receipt["rp"] == {"id": "localhost", "origin": "http://localhost:8787"}
    assert verify_receipt(receipt, gate_key=gate.verify_key)
    real_args = args_hash("railway volume delete pg-data --yes")
    assert check_approval_for(receipt, gate_key=gate.verify_key, args_hash=real_args)
    assert not check_approval_for(receipt, gate_key=gate.verify_key, args_hash=args_hash("something else"))
    assert not verify_receipt(receipt, gate_key="00" * 32)  # pinned to a different Gate

    # decided page shows the outcome and no buttons
    page = gate.client.get(f"{path}?t={t}")
    assert "Approved" in page.text and "data-decision" not in page.text

    # the same assertion cannot be replayed; the request cannot be decided twice
    assert gate.options(created, "deny").status_code == 409
    assert gate.verify(created, "approve", alice.assert_(opts)).status_code == 409
    assert gate.status(key, created["id"]).json()["receipt"] == receipt


def test_deny_flow(gate):
    org_id, key = gate.org()
    alice = gate.enrol(org_id)
    created = gate.create(key)
    r = gate.decide(created, "deny", alice)
    assert r.status_code == 200 and r.json()["status"] == "denied"
    st = gate.status(key, created["id"]).json()
    assert st["status"] == "denied"
    assert st["receipt"]["decision"] == "deny"
    assert verify_receipt(st["receipt"], gate_key=gate.verify_key)
    chk = check_approval_for(st["receipt"], gate_key=gate.verify_key,
                             args_hash=args_hash("railway volume delete pg-data --yes"))
    assert not chk and chk.error.startswith("ERR_GATE_DENIED")


def test_expired_request(gate):
    org_id, key = gate.org()
    alice = gate.enrol(org_id)
    created = gate.create(key, ttl=60)
    opts = gate.options(created, "approve").json()  # fetched while still pending
    with gate.db.session() as s:
        s.execute(update(Approval).where(Approval.id == created["id"])
                  .values(expires_at=utcnow() - timedelta(seconds=1)))
    assert gate.status(key, created["id"]).json() == {"id": created["id"], "status": "expired",
                                                      "opened_via": [], "decided_via": None}
    assert gate.options(created, "approve").status_code == 409
    assert gate.verify(created, "approve", alice.assert_(opts)).status_code == 409
    path, t = gate.page_parts(created)
    assert "Expired" in gate.client.get(f"{path}?t={t}").text


def test_ttl_bounds(gate):
    _, key = gate.org()
    r = gate.client.post("/v1/approvals", headers={"Authorization": f"Bearer {key}"},
                         json={"action": {"summary": "x"}, "agent": {}, "args_hash": "0" * 64, "ttl_seconds": 5})
    assert r.status_code == 422
    r = gate.client.post("/v1/approvals", headers={"Authorization": f"Bearer {key}"},
                         json={"action": {"tool": "Bash"}, "agent": {}, "args_hash": "0" * 64})
    assert r.status_code == 422  # summary required
    r = gate.client.post("/v1/approvals", headers={"Authorization": f"Bearer {key}"},
                         json={"action": {"summary": "x"}, "agent": {}, "args_hash": "XYZ"})
    assert r.status_code == 422


def test_wrong_api_key(gate):
    _, key = gate.org()
    body = {"action": {"summary": "x"}, "agent": {}, "args_hash": "0" * 64}
    assert gate.client.post("/v1/approvals", json=body).status_code == 401
    assert gate.client.post("/v1/approvals", json=body, headers={"Authorization": "Bearer nope"}).status_code == 401
    assert gate.client.post("/v1/approvals", json=body, headers={"Authorization": f"Basic {key}"}).status_code == 401
    created = gate.create(key)
    assert gate.status("pgk_wrong", created["id"]).status_code == 401


def test_other_org_cannot_read(gate):
    _, key_a = gate.org("A")
    _, key_b = gate.org("B")
    created = gate.create(key_a)
    assert gate.status(key_b, created["id"]).status_code == 404
    assert gate.status(key_a, created["id"]).status_code == 200


def test_other_orgs_approver_cannot_decide(gate):
    org_a, key_a = gate.org("A")
    org_b, _ = gate.org("B")
    gate.enrol(org_a, "Alice")
    mallory = gate.enrol(org_b, "Mallory")
    created = gate.create(key_a)
    opts = gate.options(created, "approve").json()
    forged = mallory.assert_({**opts, "allowCredentials": [{"id": b64url(mallory.credential_id)}]})
    r = gate.verify(created, "approve", forged)
    assert r.status_code == 400
    assert gate.status(key_a, created["id"]).json()["status"] == "pending"


def test_replay_for_different_request_fails(gate):
    org_id, key = gate.org()
    alice = gate.enrol(org_id)
    first = gate.create(key, summary="rm -rf /srv/a", args="a")
    second = gate.create(key, summary="rm -rf /srv/b", args="b")
    assertion_for_first = alice.assert_(gate.options(first, "approve").json())
    r = gate.verify(second, "approve", assertion_for_first)
    assert r.status_code == 400
    assert gate.status(key, second["id"]).json()["status"] == "pending"
    # the assertion is still good for the request it was made for
    assert gate.verify(first, "approve", assertion_for_first).status_code == 200


def test_tampered_decision_fails(gate):
    org_id, key = gate.org()
    alice = gate.enrol(org_id)
    created = gate.create(key)
    deny_assertion = alice.assert_(gate.options(created, "deny").json())
    r = gate.verify(created, "approve", deny_assertion)  # signed "deny", submitted as "approve"
    assert r.status_code == 400
    assert gate.status(key, created["id"]).json()["status"] == "pending"


def test_tampered_receipt_fails_offline(gate):
    org_id, key = gate.org()
    alice = gate.enrol(org_id)
    created = gate.create(key)
    gate.decide(created, "deny", alice)
    receipt = gate.status(key, created["id"]).json()["receipt"]
    flipped = copy.deepcopy(receipt)
    flipped["decision"] = "approve"
    assert not verify_receipt(flipped, gate_key=gate.verify_key)
    # even if an attacker re-signs the receipt with their own key, the passkey challenge does not match
    from perathos.gate import build_receipt
    forged = build_receipt(request=receipt["request"], decision="approve", approver=receipt["approver"],
                           rp=receipt["rp"], webauthn=receipt["webauthn"], server_signer="11" * 32)
    chk = verify_receipt(forged, gate_key=None)
    assert not chk and chk.error.startswith("ERR_GATE_CHALLENGE")


def test_user_verification_required(gate):
    org_id, key = gate.org()
    alice = gate.enrol(org_id)
    created = gate.create(key)
    opts = gate.options(created, "approve").json()
    r = gate.verify(created, "approve", alice.assert_(opts, flags=FLAG_UP))  # presence only, no UV
    assert r.status_code == 400


def test_wrong_origin_rejected(gate):
    org_id, key = gate.org()
    alice = gate.enrol(org_id)
    created = gate.create(key)
    opts = gate.options(created, "approve").json()
    r = gate.verify(created, "approve", alice.assert_(opts, origin="https://evil.example"))
    assert r.status_code == 400


def test_bad_view_token(gate):
    org_id, key = gate.org()
    gate.enrol(org_id)
    created = gate.create(key)
    path, _ = gate.page_parts(created)
    assert gate.client.get(f"{path}?t=wrong").status_code == 404
    assert gate.client.get(path).status_code == 404
    assert gate.client.post(path + "/options", json={"t": "wrong", "decision": "approve"}).status_code == 404


def test_no_approvers_enrolled(gate):
    _, key = gate.org()
    created = gate.create(key)
    assert gate.options(created, "approve").status_code == 409


def test_long_poll_returns_early(gate):
    org_id, key = gate.org()
    alice = gate.enrol(org_id)
    created = gate.create(key)
    result = {}

    def poll():
        t0 = time.monotonic()
        r = gate.status(key, created["id"], wait=20)
        result["elapsed"] = time.monotonic() - t0
        result["body"] = r.json()

    th = threading.Thread(target=poll)
    th.start()
    time.sleep(1.0)
    assert gate.decide(created, "approve", alice).status_code == 200
    th.join(timeout=25)
    assert result["body"]["status"] == "approved" and "receipt" in result["body"]
    assert result["elapsed"] < 5, result


def test_long_poll_times_out_pending(gate):
    _, key = gate.org()
    created = gate.create(key)
    t0 = time.monotonic()
    r = gate.status(key, created["id"], wait=1)
    assert r.json()["status"] == "pending" and 0.9 <= time.monotonic() - t0 < 5


def test_webhook_fired(gate):
    _, key = gate.org(webhook="https://hooks.slack.com/services/T/B/X")
    created = gate.create(key)
    assert len(gate.webhooks) == 1
    url, req, approve_url = gate.webhooks[0]
    assert url == "https://hooks.slack.com/services/T/B/X" and approve_url == created["approve_url"] + "&via=webhook"
    from perathos_gate.notify import message_text
    assert message_text(req, approve_url) == (
        f"claude-code wants to railway volume delete pg-data --yes. Approve or deny: {approve_url}")


def test_route_to_the_request_is_recorded(gate, caplog):
    """Notification, QR code, webhook or plain link: the server notes which one was used."""
    import logging

    from perathos_gate.app import approval_routes
    org_id, key = gate.org()
    alice = gate.enrol(org_id)
    created = gate.create(key)
    path, t = gate.page_parts(created)
    assert gate.status(key, created["id"]).json()["opened_via"] == []

    with caplog.at_level(logging.INFO, logger="perathos_gate"):
        assert 'data-via="link"' in gate.client.get(f"{path}?t={t}").text
        assert 'data-via="qr"' in gate.client.get(f"{path}?t={t}&via=qr").text
        gate.client.get(f"{path}?t={t}&via=qr")  # a reload is not listed twice
        # An unknown route is recorded as a plain link, and is never echoed into the page.
        page = gate.client.get(f"{path}?t={t}&via=%22%3E%3Cscript%3E")
        assert 'data-via="link"' in page.text and "<script>\"" not in page.text
    assert "opened via qr" in caplog.text and t not in caplog.text
    # A wrong token records nothing.
    assert gate.client.get(f"{path}?t=wrong&via=push").status_code == 404
    st = gate.status(key, created["id"]).json()
    assert st["opened_via"] == ["link", "qr"] and st["decided_via"] is None

    opts = gate.options(created, "approve").json()
    r = gate.client.post(path + "/verify", json={"t": t, "decision": "approve", "via": "qr",
                                                 "credential": alice.assert_(opts)})
    assert r.status_code == 200, r.text
    st = gate.status(key, created["id"]).json()
    assert st["status"] == "approved" and st["decided_via"] == "qr"
    # The route is a browser-reported hint: it is not in the signed receipt.
    assert "via" not in st["receipt"] and "opened_via" not in st["receipt"]
    assert approval_routes(gate.db, [created["id"]])[created["id"]]["decided_via"] == "qr"

    # A decision that sends no route, or a made-up one, counts as a plain link.
    second = gate.create(key)
    assert gate.decide(second, "deny", alice).status_code == 200
    assert gate.status(key, second["id"]).json()["decided_via"] == "link"
