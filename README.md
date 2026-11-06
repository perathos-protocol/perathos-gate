# Perathos Gate server

A small web service that lets AI agents ask a person for approval before an irreversible
action (delete data, move money, deploy), and lets that person approve or deny **on their
phone with a passkey** (WebAuthn, user verification required: Face ID, fingerprint or PIN).

Every decision produces a **receipt** that anyone can verify offline with
`perathos.gate.verify_receipt`: the passkey signed a challenge derived from the exact request
and the decision, and the Gate server signed the whole receipt with its Ed25519 key.
Protocol: [`docs/specs/GATE_V1.md`](https://github.com/perathos-protocol/perathos/blob/feat/gate/docs/specs/GATE_V1.md).
Request building, the decision challenge, receipt construction and verification all come from
`perathos.gate`; this server does not reimplement them.

## 5-minute local run

```bash
python -m venv .venv && . .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -e ".[dev]"

perathos-gate init                                 # data dir, database, server key; prints the verify key
perathos-gate create-org "Acme" [--webhook https://hooks.slack.com/services/...]
#   Org id:  org_...
#   API key: pgk_...      <- shown once; the server stores only its SHA-256
perathos-gate invite --org org_... --name "Alice Moyo"
#   http://localhost:8787/enroll/<token>   <- single use, 24 h
perathos-gate serve --port 8787
```

Open the enrolment link and press **Create passkey**. Then ask for an approval:

```bash
curl -s -X POST http://localhost:8787/v1/approvals \
  -H "Authorization: Bearer pgk_..." -H "Content-Type: application/json" \
  -d '{"action":{"tool":"Bash","summary":"railway volume delete pg-data --yes","rule":"paas.railway","target":"pg-data"},
       "agent":{"name":"claude-code","host":"laptop"},
       "args_hash":"<64 hex>","ttl_seconds":600}'
# -> 201 {"id":"apr_...","status":"pending","approve_url":"http://localhost:8787/a/apr_...?t=...", ...}

curl -s "http://localhost:8787/v1/approvals/apr_...?wait=60" -H "Authorization: Bearer pgk_..."
# -> {"id":"apr_...","status":"approved","receipt":{...}}
```

**Passkeys need a secure context.** Browsers allow WebAuthn only over HTTPS, except on
`localhost`. A phone cannot reach your laptop's `localhost`, so to test on a real phone put the
server behind HTTPS (a deployed instance, or a tunnel such as `cloudflared` / `ngrok`) and set
`GATE_RP_ID` / `GATE_ORIGIN` to that host name. The RP id is baked into each passkey: passkeys
enrolled under one host name do not work under another.

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `GATE_ID` | `GATE_RP_ID` | Gate identity written into every request |
| `GATE_RP_ID` | `localhost` | WebAuthn relying-party id (bare host name) |
| `GATE_ORIGIN` | `http://localhost:8787` | Exact origin approvers' browsers use; also the base of approve/enrol links |
| `GATE_RP_NAME` | `Perathos Gate` | Name shown in the passkey prompt |
| `GATE_SIGNING_KEY` | (unset) | 64-hex Ed25519 seed; takes precedence over the key file |
| `GATE_KEY_FILE` | `./data/gate_signing.key` | Key file written by `init` (mode 0600) |
| `DATABASE_URL` | `sqlite:///./data/gate.db` | SQLite, or Postgres (`postgres://`/`postgresql://` URLs are accepted) |
| `GATE_TRUST_PROXY` | `0` | `1` behind a reverse proxy: use `X-Forwarded-For` for rate limiting |
| `GATE_RATE_LIMIT_PER_MIN` | `30` | Approver POSTs per IP per minute on `/a/*` and `/enroll/*` |
| `PORT` | `8787` | Default port for `serve` |

See `.env.example`.

## CLI

| Command | Does |
|---|---|
| `perathos-gate init` | Creates the data dir, tables and server key; prints the verify key to pin in clients |
| `perathos-gate create-org NAME [--webhook URL]` | Prints the org id and API key (once) |
| `perathos-gate invite --org ID --name "Alice Moyo" [--hours 24]` | Prints a single-use enrolment URL |
| `perathos-gate serve [--host 127.0.0.1] [--port 8787]` | Runs the server |
| `perathos-gate list-approvals --org ID [--limit 50]` | Recent approvals and their status |

## Deploy

The `Dockerfile` builds a `python:3.11-slim` image that runs as a non-root user and starts
`perathos-gate serve --host 0.0.0.0 --port $PORT`.

* **Railway / Render / Fly**: deploy the Dockerfile; set `GATE_ID`, `GATE_RP_ID` (your domain),
  `GATE_ORIGIN` (`https://your.domain`), `GATE_SIGNING_KEY` (generate with
  `python -c "import secrets; print(secrets.token_hex(32))"` and keep it as a secret), and
  `DATABASE_URL` pointing at a managed Postgres. `GATE_TRUST_PROXY=1` is the image default.
  Then run `perathos-gate create-org` / `invite` in a one-off shell on the service (same env).
* **SQLite** works for a single instance with a persistent volume mounted at `/data`.
* Long-polling reads the database every 0.5 s, so several instances behind a load balancer share
  state correctly with Postgres. The rate limiter is per process.
* Losing the signing key invalidates nothing already issued, but clients pinned to the old key
  will reject new receipts; rotate deliberately and republish the key.

## Security model

* **The server cannot approve on anyone's behalf.** An approval needs an enrolled approver's
  passkey signature over `decision_challenge(request_hash, decision)`, made with user
  verification. The server never holds approvers' private keys. A compromised server can delay or
  refuse requests, or sign garbage, but it cannot forge the WebAuthn signature, and verifiers
  check both signatures.
* **Binding**: the challenge covers the full request (action, agent, `args_hash`, expiry) and the
  decision, so an approval cannot be replayed for another request, or turned into a denial (and
  vice versa). The guard additionally checks `args_hash` against the arguments it is about to run.
* Before storing a decision the server re-verifies the receipt it just built
  (`verify_receipt` against its own key) and refuses to record it if that fails.
* Decisions are recorded with a conditional update (`status = pending` and not expired), so a
  request is decided at most once. Sign counters are tracked to detect cloned authenticators.
* Secrets at rest are hashed: API keys, approve-page tokens and enrolment tokens are stored as
  SHA-256 and compared in constant time. Tokens are `secrets.token_urlsafe(32)`.
* Approver pages send a strict CSP (no inline script), `X-Frame-Options: DENY`,
  `Referrer-Policy: no-referrer` and `Cache-Control: no-store`. CORS is not enabled.
* Request bodies over 64 KB are rejected (413). Approver POSTs are rate-limited per IP (429).
* The access log records method, path and status only: no query strings (approve tokens), no
  enrolment tokens, no API keys, and webhook failures log only the host.
* The approve link is a bearer capability for *viewing* a request and starting the ceremony;
  deciding still requires an enrolled passkey of the same organisation.
* Enrolment links are single-use and expire in 24 hours; deliver them out of band. Anyone who
  holds an unused link can enrol a passkey as that approver.

## Development

```bash
pip install -e ".[dev]"
pytest -q          # full flow with a software WebAuthn authenticator (tests/softauthn.py)
ruff check .
```

`scripts/e2e_live.py` drives a running server over real HTTP with the same software
authenticator: `python scripts/e2e_live.py --base http://127.0.0.1:8787 --org-key pgk_... --enroll-url <invite url>`.
