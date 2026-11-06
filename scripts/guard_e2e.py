"""Integration: real Perathos guard hook <-> real Perathos Gate server <-> software passkey.

1. Start the Gate server (its own venv) on 127.0.0.1:8799 with a fresh database.
2. Create an org, invite an approver, enrol a software passkey through the real endpoints.
3. Configure Perathos (temp HOME) with `perathos gate login`; run the real `perathos-hook
   record --guard` with a Claude Code PreToolUse payload for `dropdb prod`: it blocks waiting.
4. While it waits, approve through the real approval endpoints with the passkey.
5. The hook must exit allowing the call; the session log binds the approval; an evidence pack
   verifies offline with the approval inside.
"""
# Usage: python scripts/guard_e2e.py <empty work dir>   (set PERATHOS_PY to use another venv)
import json
import os
import subprocess
import sys
import threading
import time
import urllib.request
from pathlib import Path
from urllib.parse import urlparse

GATE_REPO = Path(__file__).resolve().parent.parent
# Python with perathos >= 1.3.0 installed (the agent side); default: this interpreter.
PERATHOS_PY = Path(os.environ.get("PERATHOS_PY", sys.executable))
GATE_PY = Path(sys.executable)
WORK = Path(sys.argv[1])
PORT = 8799
BASE = f"http://127.0.0.1:{PORT}"

sys.path.insert(0, str(GATE_REPO / "tests"))
from softauthn import SoftAuthenticator  # noqa: E402


def say(msg):
    print(f"--> {msg}", flush=True)


def call(method, url, body=None, key=None, timeout=30):
    h = {"Content-Type": "application/json"}
    if key:
        h["Authorization"] = f"Bearer {key}"
    req = urllib.request.Request(url, method=method, headers=h, data=json.dumps(body).encode() if body is not None else None)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read() or b"{}")


server_dir = WORK / "server"
project = WORK / "project"
home = WORK / "home"
for d in (server_dir, project, home):
    d.mkdir(parents=True, exist_ok=True)
senv = {**os.environ, "GATE_RP_ID": "localhost", "GATE_ORIGIN": f"http://localhost:{PORT}", "GATE_ID": "gate.e2e"}
penv = {**os.environ, "HOME": str(home), "USERPROFILE": str(home)}

gate_cli = [str(GATE_PY), "-m", "perathos_gate.cli"]
subprocess.run(gate_cli + ["init"], cwd=server_dir, env=senv, check=True, capture_output=True)
org = subprocess.run(gate_cli + ["create-org", "Acme"], cwd=server_dir, env=senv, check=True, capture_output=True, text=True).stdout
api_key = next(w for w in org.split() if w.startswith("pgk_"))
inv = subprocess.run(gate_cli + ["invite", "--org", next(w for w in org.split() if w.startswith("org_")), "--name", "Alice Moyo"],
                     cwd=server_dir, env=senv, check=True, capture_output=True, text=True).stdout
enroll_url = next(w for w in inv.split() if "/enroll/" in w)
srv = subprocess.Popen(gate_cli + ["serve", "--host", "127.0.0.1", "--port", str(PORT)], cwd=server_dir, env=senv,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
try:
    for _ in range(100):
        try:
            info = call("GET", f"{BASE}/.well-known/perathos-gate.json")
            break
        except OSError:
            time.sleep(0.2)
    say(f"Gate server up: gate={info['gate']} key={info['verify_key'][:16]}...")

    auth = SoftAuthenticator(info["rp_id"], info["origin"])
    ep = urlparse(enroll_url).path
    opts = call("POST", f"{BASE}{ep}/options", {})
    call("POST", f"{BASE}{ep}/verify", {"credential": auth.register(opts)})
    say("approver Alice Moyo enrolled a passkey (software authenticator, user verification on)")

    r = subprocess.run([str(PERATHOS_PY), "-m", "perathos", "keygen"], env=penv, capture_output=True, text=True)
    r = subprocess.run([str(PERATHOS_PY), "-m", "perathos", "gate", "login", "--url", BASE, "--api-key", api_key,
                        "--wait", "30"], env=penv, capture_output=True, text=True)
    say("perathos gate login: " + r.stdout.splitlines()[1])

    payload = {"hook_event_name": "PreToolUse", "session_id": "e2e", "cwd": str(project), "tool_name": "Bash",
               "tool_use_id": "t1", "tool_input": {"command": "dropdb prod"}}
    hook_exe = PERATHOS_PY.parent / "perathos-hook.exe"
    result = {}

    def run_hook():
        t0 = time.monotonic()
        p = subprocess.run([str(hook_exe), "record", "--guard"], input=json.dumps(payload), env=penv,
                           capture_output=True, text=True, timeout=120)
        result.update(out=p.stdout, err=p.stderr, secs=time.monotonic() - t0)

    th = threading.Thread(target=run_hook)
    th.start()
    say("agent runs `dropdb prod`; the guard blocks it and asks Gate, waiting for a person...")
    pending = project / ".perathos" / "approvals" / "pending.json"
    for _ in range(200):
        if pending.exists() and json.loads(pending.read_text(encoding="utf-8")):
            break
        time.sleep(0.1)
    entry = next(iter(json.loads(pending.read_text(encoding="utf-8")).values()))
    u = urlparse(entry["approve_url"])
    with urllib.request.urlopen(entry["approve_url"].replace("localhost", "127.0.0.1"), timeout=10) as page:
        html = page.read().decode()
    say(f"approval page shows the real command: {'dropdb prod' in html}")
    time.sleep(1)
    t = u.query.split("t=", 1)[1]
    o = call("POST", f"{BASE}{u.path}/options", {"t": t, "decision": "approve"})
    res = call("POST", f"{BASE}{u.path}/verify", {"t": t, "decision": "approve", "credential": auth.assert_(o)})
    say(f"Alice approves on her phone with the passkey -> {res.get('status')}")
    th.join(130)
    say(f"hook finished after {result['secs']:.1f}s; stdout={result['out'].strip() or '(empty: call allowed)'}")

    log = project / ".perathos" / "sessions" / "e2e.jsonl"
    rec = json.loads(log.read_text(encoding="utf-8").splitlines()[0])
    say(f"action receipt guard field: {rec['guard']}")

    # second identical command: approval was single-use, so it must ask again
    p2 = subprocess.run([str(hook_exe), "record", "--guard"], input=json.dumps({**payload, "tool_use_id": "t2"}),
                        env={**penv}, capture_output=True, text=True, timeout=120)
    # (gate_wait=30 would block; the hook asks again and we let it time out quickly by denying)
    say("second identical call after approval was used: " +
        ("DENIED until a new approval" if "deny" in p2.stdout else "ALLOWED (unexpected)"))

    sk = (home / ".perathos" / "keys" / "signing.key").read_text(encoding="utf-8").strip()
    subprocess.run([str(hook_exe), "record"], input=json.dumps({"hook_event_name": "Stop", "session_id": "e2e",
                                                                 "cwd": str(project)}), env=penv, check=True, text=True)
    v = subprocess.run([str(PERATHOS_PY), "-m", "perathos", "session", "export", "e2e", "--out", str(WORK / "pack")],
                       cwd=project, env=penv, capture_output=True, text=True)
    say("evidence pack: " + v.stdout.splitlines()[0])
    vk = (home / ".perathos" / "keys" / "verify.key").read_text(encoding="utf-8").strip()
    ev = subprocess.run([str(PERATHOS_PY), "-m", "perathos", "evidence", "verify", str(WORK / "pack.zip"), "--verify-key", vk],
                        env=penv, capture_output=True, text=True)
    say("independent pack check: " + ev.stdout.splitlines()[0])
    rep = json.loads((WORK / "pack" / "verification.json").read_text(encoding="utf-8"))
    say(f"pack says approved by: {rep['approved_by_person']}")
    gv = subprocess.run([str(PERATHOS_PY), "-m", "perathos", "gate", "verify",
                         str(next((WORK / "pack" / "approvals").glob("*.json")))], env=penv, capture_output=True, text=True)
    say("gate verify receipt: " + gv.stdout.splitlines()[0])
finally:
    srv.terminate()
    srv.wait(10)
    say("server stopped")
