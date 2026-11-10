"""Web Push (RFC 8030 / 8291 / 8292, VAPID) to approvers' devices, sent in a background thread.

Push is optional: without GATE_VAPID_PRIVATE_KEY nothing here runs. Delivery goes through the
browser vendor's push service and is best effort; the approve link stays the fallback.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import json
import logging
import secrets
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from urllib.parse import urlparse

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from sqlalchemy import delete, select, update

from .config import Settings
from .db import Database
from .models import Approver, PushSubscription, utcnow

log = logging.getLogger("perathos_gate.push")

TOKEN_TTL = 600  # a subscribe token is good for ten minutes after the passkey was used
CHALLENGE_TTL = 300
MAX_ENDPOINT_LEN = 2048
MAX_PER_APPROVER = 10
BODY_MAX = 180
GONE = (404, 410)

# (subscription_info, payload, ttl_seconds) -> HTTP status from the push service. May raise.
Sender = Callable[[dict, str, int], int]


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


# --------------------------------------------------------------------------- #
# VAPID key pair
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Vapid:
    private_key: ec.EllipticCurvePrivateKey
    public_key: str  # base64url uncompressed P-256 point: the browser's applicationServerKey
    subject: str
    secret: bytes  # HMAC key for subscribe tokens and sign-in challenges, derived from the private key


def _public_b64(key: ec.EllipticCurvePrivateKey) -> str:
    return _b64url(key.public_key().public_bytes(serialization.Encoding.X962,
                                                 serialization.PublicFormat.UncompressedPoint))


def generate_vapid_keys() -> tuple[str, str]:
    """A new P-256 key pair as (private, public), both base64url (raw 32-byte scalar, 65-byte point)."""
    key = ec.generate_private_key(ec.SECP256R1())
    return _b64url(key.private_numbers().private_value.to_bytes(32, "big")), _public_b64(key)


def load_vapid(settings: Settings) -> Vapid | None:
    """The VAPID identity from settings, or None (push disabled). A bad value disables push, loudly,
    rather than stopping the server: approvals must keep working."""
    if not settings.vapid_private_key:
        return None
    try:
        raw = _b64url_decode(settings.vapid_private_key)
        if len(raw) != 32:
            raise ValueError("expected 32 bytes")
        key = ec.derive_private_key(int.from_bytes(raw, "big"), ec.SECP256R1())
    except ValueError:
        log.error("GATE_VAPID_PRIVATE_KEY is not a valid key (use `perathos-gate vapid-keygen`); push disabled")
        return None
    subject = settings.vapid_subject or (settings.origin if settings.origin.startswith("https://") else "")
    if not subject.startswith(("mailto:", "https://")):
        log.error("GATE_VAPID_SUBJECT must be a mailto: or https: URL; push disabled")
        return None
    secret = hmac.new(raw, b"perathos-gate/push/v1", hashlib.sha256).digest()
    return Vapid(private_key=key, public_key=_public_b64(key), subject=subject, secret=secret)


# --------------------------------------------------------------------------- #
# Subscribe tokens and sign-in challenges (stateless, HMAC-signed, short-lived)
# --------------------------------------------------------------------------- #


def _mac(secret: bytes, purpose: bytes, message: bytes) -> bytes:
    return hmac.new(secret, purpose + b"\x00" + message, hashlib.sha256).digest()


def issue_token(secret: bytes, approver_id: int, ttl: int = TOKEN_TTL) -> str:
    """A token that lets its holder attach a device to `approver_id`, and nothing else."""
    body = f"{approver_id}.{int(time.time()) + ttl}"
    return f"{body}.{_b64url(_mac(secret, b'subscribe', body.encode()))}"


def check_token(secret: bytes, token: str | None) -> int | None:
    """The approver id a valid, unexpired token was issued for; otherwise None."""
    try:
        approver_id, expires, mac = (token or "").split(".")
        body = f"{approver_id}.{expires}"
        if not hmac.compare_digest(_b64url(_mac(secret, b"subscribe", body.encode())), mac):
            return None
        if int(expires) <= time.time():
            return None
        return int(approver_id)
    except ValueError:
        return None


def new_challenge(secret: bytes, ttl: int = CHALLENGE_TTL) -> bytes:
    """A WebAuthn challenge for the 'confirm with passkey' step on the home page. It is 56 bytes, so
    a signature over it can never stand in for a 32-byte decision challenge."""
    body = secrets.token_bytes(16) + (int(time.time()) + ttl).to_bytes(8, "big")
    return body + _mac(secret, b"challenge", body)


def challenge_valid(secret: bytes, challenge: bytes) -> bool:
    if len(challenge) != 56:
        return False
    body, mac = challenge[:24], challenge[24:]
    return hmac.compare_digest(_mac(secret, b"challenge", body), mac) and \
        int.from_bytes(body[16:], "big") > time.time()


# --------------------------------------------------------------------------- #
# Subscriptions
# --------------------------------------------------------------------------- #


def endpoint_host(endpoint: str) -> str:
    """Push endpoints are capability URLs: log the host only."""
    return urlparse(endpoint).netloc


def is_valid_endpoint(endpoint: object) -> bool:
    """https on a public-looking host name: the server will POST to this URL."""
    if not isinstance(endpoint, str) or not 0 < len(endpoint) <= MAX_ENDPOINT_LEN:
        return False
    parsed = urlparse(endpoint)
    host = (parsed.hostname or "").lower()
    if parsed.scheme != "https" or "." not in host or host.endswith((".local", ".localhost", ".internal")):
        return False
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return True
    return False


def parse_subscription(subscription: dict) -> tuple[str, str, str]:
    """Validate a browser PushSubscription JSON; returns (endpoint, p256dh, auth). Raises ValueError."""
    endpoint = subscription.get("endpoint")
    if not is_valid_endpoint(endpoint):
        raise ValueError("bad endpoint")
    keys = subscription.get("keys")
    if not isinstance(keys, dict) or not isinstance(keys.get("p256dh"), str) or not isinstance(keys.get("auth"), str):
        raise ValueError("bad keys")
    p256dh, auth = _b64url_decode(keys["p256dh"]), _b64url_decode(keys["auth"])
    if len(p256dh) != 65 or p256dh[0] != 4 or len(auth) != 16:
        raise ValueError("bad keys")
    return endpoint, _b64url(p256dh), _b64url(auth)


def save_subscription(db: Database, approver: Approver, endpoint: str, p256dh: str, auth: str) -> None:
    """Attach a device to an approver. A device already known moves to this approver."""
    digest = hashlib.sha256(endpoint.encode("utf-8")).hexdigest()
    with db.session() as s:
        row = s.scalars(select(PushSubscription).where(PushSubscription.endpoint_hash == digest)).first()
        if row is None:
            s.add(PushSubscription(approver_id=approver.id, org_id=approver.org_id, endpoint=endpoint,
                                   endpoint_hash=digest, p256dh=p256dh, auth=auth, created_at=utcnow()))
        else:
            row.approver_id, row.org_id, row.p256dh, row.auth = approver.id, approver.org_id, p256dh, auth
        s.flush()
        old = s.scalars(select(PushSubscription.id).where(PushSubscription.approver_id == approver.id)
                        .order_by(PushSubscription.id.desc()).offset(MAX_PER_APPROVER)).all()
        if old:
            s.execute(delete(PushSubscription).where(PushSubscription.id.in_(old)))


def delete_subscription(db: Database, endpoint: str) -> bool:
    digest = hashlib.sha256(endpoint.encode("utf-8")).hexdigest()
    with db.session() as s:
        return s.execute(delete(PushSubscription).where(PushSubscription.endpoint_hash == digest)).rowcount > 0


# --------------------------------------------------------------------------- #
# Sending
# --------------------------------------------------------------------------- #


def payload(request: dict, approve_url: str) -> str:
    """What the service worker shows. Encrypted to the browser (RFC 8291), so the approve URL may ride in it."""
    agent = request.get("agent", {}).get("name") or "An agent"
    summary = str(request.get("action", {}).get("summary", ""))
    if len(summary) > BODY_MAX:
        summary = summary[:BODY_MAX - 1] + "…"
    return json.dumps({"title": f"{agent} is asking for approval"[:80], "body": summary, "url": approve_url,
                       "tag": request.get("id", "")}, separators=(",", ":"))


def make_sender(vapid: Vapid, *, timeout: float = 10.0) -> Sender:
    """The real sender: encrypts and POSTs one message with pywebpush."""
    import requests
    from py_vapid import Vapid02
    from pywebpush import WebPushException, webpush

    signer = Vapid02(private_key=vapid.private_key)

    def send(subscription: dict, data: str, ttl: int) -> int:
        session = requests.Session()
        session.max_redirects = 0  # a push service has no reason to redirect us anywhere
        try:
            resp = webpush(subscription, data=data, vapid_private_key=signer, vapid_claims={"sub": vapid.subject},
                           ttl=ttl, timeout=timeout, headers={"Urgency": "high"}, requests_session=session)
            return resp.status_code
        except WebPushException as exc:
            if exc.response is None:
                raise
            return exc.response.status_code
        finally:
            session.close()

    return send


def _deliver(db: Database, sender: Sender, org_id: str, data: str, ttl: int) -> None:
    try:
        with db.session() as s:
            subs = s.scalars(select(PushSubscription).join(Approver, Approver.id == PushSubscription.approver_id)
                             .where(PushSubscription.org_id == org_id, Approver.active.is_(True))).all()
        for sub in subs:
            host = endpoint_host(sub.endpoint)
            info = {"endpoint": sub.endpoint, "keys": {"p256dh": sub.p256dh, "auth": sub.auth}}
            try:
                status = sender(info, data, ttl)
            except Exception as exc:  # one bad device must not stop the others
                # Never log the endpoint or the payload: both are secrets.
                log.warning("push to %s failed: %s", host, type(exc).__name__)
                status = 0
            with db.session() as s:
                if status in GONE:
                    s.execute(delete(PushSubscription).where(PushSubscription.id == sub.id))
                    log.info("push subscription at %s is gone (HTTP %s); removed", host, status)
                elif 200 <= status < 300:
                    s.execute(update(PushSubscription).where(PushSubscription.id == sub.id)
                              .values(last_success_at=utcnow()))
                    log.info("push accepted by %s: HTTP %s", host, status)
                else:
                    s.execute(update(PushSubscription).where(PushSubscription.id == sub.id)
                              .values(last_failure_at=utcnow()))
                    if status:
                        log.warning("push to %s failed: HTTP %s", host, status)
    except Exception:  # pragma: no cover - a background thread must not die noisily
        log.exception("push delivery failed for org %s", org_id)


def notify_approval(db: Database, sender: Sender, org_id: str, request: dict, approve_url: str,
                    ttl: int) -> threading.Thread:
    """Fire-and-forget push to every device of every active approver in the org. Returns the thread."""
    t = threading.Thread(target=_deliver, args=(db, sender, org_id, payload(request, approve_url), max(0, ttl)),
                         name="gate-push", daemon=True)
    t.start()
    return t
