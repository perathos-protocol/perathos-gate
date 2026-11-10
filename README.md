# Perathos Gate server

A small web service that lets AI agents ask a person for approval before an irreversible
action (delete data, move money, deploy), and lets that person approve or deny **on their
phone with a passkey** (WebAuthn, user verification required: Face ID, fingerprint or PIN).

Every decision produces a **receipt** that anyone can verify offline with
`perathos.gate.verify_receipt`: the passkey signed a challenge derived from the exact request
and the decision, and the Gate server signed the whole receipt with its Ed25519 key.
Protocol: [`docs/specs/GATE_V1.md`](https://github.com/perathos-protocol/perathos/blob/main/docs/specs/GATE_V1.md).
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

## Notifications

An approver has to learn that a request is waiting. The Gate can tell them in two ways; both are
optional, both run in a background thread, and neither can delay or fail the agent's API call.
**The approve link (`approve_url` in the API response) always works**, so an agent or a person can
still pass it on, or show it as a QR code, when a notification does not arrive.

### Webhook

`create-org --webhook URL` stores a Slack-compatible incoming webhook. Each new request posts
`{"text": "<agent> wants to <summary>. Approve or deny: <approve_url>"}` to it. Anyone who can read
that channel can open the request; deciding still needs an enrolled passkey.

### Web Push (browser notifications)

With a VAPID key configured, approvers can turn on notifications for a browser or phone. A new
request then shows a system notification with the agent name and the action summary; tapping it
opens the approve page.

Set up (operator):

```bash
perathos-gate vapid-keygen
#   GATE_VAPID_PRIVATE_KEY=...    <- printed once, not stored; keep it secret
#   GATE_VAPID_SUBJECT=mailto:you@example.com
```

Put both variables in the server's environment and restart. `GATE_VAPID_SUBJECT` must be a
`mailto:` or `https:` contact for the push services; if it is unset the Gate uses `GATE_ORIGIN`
when that is https. Without `GATE_VAPID_PRIVATE_KEY` push is off: no button, no extra routes, and
everything else behaves as before. A malformed key logs an error and leaves push off; it does not
stop the server. Replacing the key invalidates every existing subscription (approvers enable
notifications again).

Turning it on (approver): after creating a passkey, or after approving or denying a request, the
page shows **Enable notifications on this device**. The same button is on the Gate's home page
(`/`) behind **Confirm with passkey**. **Turn off notifications on this device** removes the
subscription from the browser and the server.

What to expect, plainly:

* **iPhone and iPad: Web Push only works after the site is added to the Home Screen**, on iOS /
  iPadOS 16.4 or later. In Safari: Share, Add to Home Screen, open the Gate from that icon, press
  **Confirm with passkey**, then **Enable notifications on this device**. A Safari tab on iOS
  cannot receive push at all. The passkey prompt on the home page needs a passkey the device can
  find by itself (a discoverable credential); iCloud Keychain passkeys are.
* Android (Chrome, Firefox, Edge, Samsung Internet) and desktop browsers can enable it from a
  normal tab. Desktop browsers usually only show notifications while the browser is running.
* **Delivery is best effort.** Messages travel through the browser vendor's push service (Google
  FCM, Mozilla, Apple, Microsoft). The Gate hands the message over and learns only whether it was
  accepted, not whether or when the device showed it. Battery savers, focus modes, revoked
  permission or an offline device can delay or drop a notification. A message that is not
  delivered before the request expires is discarded by the push service.
* A notification is a pointer, not an approval. Nothing is approved until someone opens the page
  and signs with their passkey.
* A subscription the push service reports as gone (HTTP 404 or 410) is deleted. Other failures are
  recorded on the subscription (`last_failure_at`); a failed message is not retried.
* What has been tested: the send path is unit-tested against a local stand-in push service
  (encryption and VAPID header), and the whole flow (enable, receive, show, turn off) was run once
  by hand in headless Chrome on Windows against Google's push service. There is no automated
  browser test, and it has not been tried on iOS, Android, Firefox or Safari. Try it on your own
  devices before relying on it.

How a device is tied to an approver: a browser may subscribe only with a token that the server
issues in the response to a verified passkey ceremony (enrolment, a decision, or the home-page
confirmation). The token is an HMAC over the approver id and an expiry ten minutes ahead, keyed
with a secret derived from the VAPID private key. It can do one thing: attach a push subscription
to that approver. The message itself is encrypted to the browser (RFC 8291), so the push service
cannot read the summary or the approve link.

### Which route was used

The server notes how each request was reached. Notification links carry `&via=push`, webhook
messages `&via=webhook`, and a client adds `&via=qr` to the link it draws as a QR code; anything
else counts as a plain `link`. The route appears in the server log, in
`perathos-gate list-approvals`, and in `GET /v1/approvals/{id}` as `opened_via` and
`decided_via`. It is reported by the approver's browser and anyone holding the link can change
it, so treat it as a usage statistic. It is not part of the signed receipt.

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
| `GATE_VAPID_PRIVATE_KEY` | (unset) | Web Push key from `perathos-gate vapid-keygen`; unset means push is off |
| `GATE_VAPID_SUBJECT` | `GATE_ORIGIN` if https | `mailto:` or `https:` contact sent to push services |
| `PORT` | `8787` | Default port for `serve` |

See `.env.example`.

## CLI

| Command | Does |
|---|---|
| `perathos-gate init` | Creates the data dir, tables and server key; prints the verify key to pin in clients |
| `perathos-gate create-org NAME [--webhook URL]` | Prints the org id and API key (once) |
| `perathos-gate invite --org ID --name "Alice Moyo" [--hours 24]` | Prints a single-use enrolment URL |
| `perathos-gate vapid-keygen` | Prints a new VAPID key pair for Web Push (private key shown once) |
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
* Tables are created at startup with SQLAlchemy `create_all`, which only adds tables that do not
  exist yet and never alters existing ones. There is no migration tool.
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
* Web Push: a device can be attached to an approver only with a short-lived token issued after
  that approver's passkey was verified. Push endpoints must be https URLs on a host name (no IP
  literals, no `localhost`), redirects are not followed, and logs name the push host only. A
  notification carries the approve link, so whoever holds an approver's unlocked device can view
  the request, exactly as with the link itself. The server does POST to an endpoint URL chosen by
  the approver's browser; only enrolled approvers can register one.
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

## Licence

The Gate server is licensed under the GNU Affero General Public License v3.0 or later (see
LICENSE): run it, change it, self-host it; if you offer a modified version as a service, publish
your changes. The client library and verifier (`perathos` on PyPI) stay MIT, so receipts can be
verified anywhere without licence concerns. Commercial licences and hosted Gate are available
from hello@perathos.com.
