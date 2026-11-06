"""Drive a RUNNING Perathos Gate over real HTTP with the software passkey from the tests.

Usage:
    python scripts/e2e_live.py --base http://localhost:8787 --org-key pgk_... --enroll-url http://.../enroll/...

Enrols the authenticator, creates an approval (agent API), approves it via the approver
endpoints, long-polls the decision, then verifies the receipt offline with perathos.gate
against the key pinned from /.well-known. Also runs a deny and a replay attempt.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tests"))

from perathos.gate import check_approval_for, verify_receipt  # noqa: E402
from softauthn import SoftAuthenticator  # noqa: E402


def call(method: str, url: str, body: dict | None = None, key: str | None = None, timeout: float = 90):
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    if key:
        headers["Authorization"] = f"Bearer {key}"
    req = urllib.request.Request(url, method=method, headers=headers,
                                 data=json.dumps(body).encode() if body is not None else None)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read() or b"{}")


def step(msg: str) -> None:
    print(f"--> {msg}", flush=True)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", required=True)
    ap.add_argument("--org-key", required=True)
    ap.add_argument("--enroll-url", required=True)
    a = ap.parse_args()
    base = a.base.rstrip("/")

    status, info = call("GET", f"{base}/.well-known/perathos-gate.json")
    step(f"GET /.well-known/perathos-gate.json -> {status} {info}")
    gate_key = info["verify_key"]

    auth = SoftAuthenticator(info["rp_id"], info["origin"])
    enroll_path = urlparse(a.enroll_url).path
    status, opts = call("POST", f"{base}{enroll_path}/options", {})
    step(f"POST /enroll/<token>/options -> {status} (challenge {opts['challenge'][:12]}..., "
         f"UV={opts['authenticatorSelection']['userVerification']})")
    status, res = call("POST", f"{base}{enroll_path}/verify", {"credential": auth.register(opts)})
    step(f"POST /enroll/<token>/verify -> {status} {res}")
    status, res = call("POST", f"{base}{enroll_path}/options", {})
    step(f"enrolment link reuse -> {status} {res}")

    def create(summary: str, args: str):
        body = {"action": {"tool": "Bash", "summary": summary, "rule": "paas.railway", "target": "pg-data"},
                "agent": {"name": "claude-code", "session_id": "live-1", "host": "laptop"},
                "args_hash": hashlib.sha256(args.encode()).hexdigest(), "ttl_seconds": 600}
        status, created = call("POST", f"{base}/v1/approvals", body, a.org_key)
        step(f"POST /v1/approvals -> {status} id={created['id']} status={created['status']}")
        return created

    def decide(created: dict, decision: str):
        url = urlparse(created["approve_url"])
        t = url.query.split("t=", 1)[1]
        status, o = call("POST", f"{base}{url.path}/options", {"t": t, "decision": decision})
        step(f"POST /a/{created['id']}/options ({decision}) -> {status}")
        assertion = auth.assert_(o)
        status, r = call("POST", f"{base}{url.path}/verify", {"t": t, "decision": decision, "credential": assertion})
        step(f"POST /a/{created['id']}/verify ({decision}) -> {status} {r}")
        return assertion

    args = "railway volume delete pg-data --yes"
    created = create(args, args)
    with urllib.request.urlopen(created["approve_url"], timeout=10) as resp:
        status, csp = resp.status, resp.headers.get("Content-Security-Policy")
    step(f"GET approve page -> {status}, CSP: {csp}")

    result: dict = {}

    def poll():
        t0 = time.monotonic()
        result["status"], result["body"] = call("GET", f"{base}/v1/approvals/{created['id']}?wait=30", key=a.org_key)
        result["elapsed"] = time.monotonic() - t0

    th = threading.Thread(target=poll)
    th.start()
    time.sleep(1.5)
    assertion = decide(created, "approve")
    th.join(40)
    receipt = result["body"]["receipt"]
    step(f"long-poll GET /v1/approvals/{created['id']}?wait=30 -> {result['status']} status="
         f"{result['body']['status']} after {result['elapsed']:.2f}s")
    chk = verify_receipt(receipt, gate_key=gate_key)
    step(f"perathos.gate.verify_receipt -> ok={chk.ok} {chk.error}")
    chk2 = check_approval_for(receipt, gate_key=gate_key, args_hash=hashlib.sha256(args.encode()).hexdigest())
    step(f"perathos.gate.check_approval_for(args) -> ok={chk2.ok} {chk2.error}")
    step(f"receipt: decision={receipt['decision']} approver={receipt['approver']['name']} "
         f"alg={receipt['approver']['alg']} receipt_hash={receipt['receipt_hash'][:16]}... "
         f"server key={receipt['server_signature']['verify_key'][:16]}...")

    other = create("rm -rf /var/lib/postgresql", "rm -rf /var/lib/postgresql")
    url = urlparse(other["approve_url"])
    status, r = call("POST", f"{base}{url.path}/verify",
                     {"t": url.query.split("t=", 1)[1], "decision": "approve", "credential": assertion})
    step(f"replay first approval's assertion against another request -> {status} {r}")
    decide(other, "deny")
    status, st = call("GET", f"{base}/v1/approvals/{other['id']}", key=a.org_key)
    chk3 = check_approval_for(st["receipt"], gate_key=gate_key, args_hash="0" * 64)
    step(f"GET denied -> {status} status={st['status']}; verify_receipt ok="
         f"{verify_receipt(st['receipt'], gate_key=gate_key).ok}; check_approval_for -> {chk3.error}")
    status, r = call("GET", f"{base}/v1/approvals/{created['id']}", key="pgk_wrong")
    step(f"wrong API key -> {status} {r}")

    ok = chk.ok and chk2.ok and result["body"]["status"] == "approved" and st["status"] == "denied"
    print("LIVE E2E:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
