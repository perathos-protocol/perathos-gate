"""FastAPI application: the agent API, the approver pages and the passkey ceremonies (GATE_V1.md)."""
from __future__ import annotations

import asyncio
import json
import logging
import re
import secrets
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from perathos.gate import (
    DECISIONS,
    b64url,
    b64url_decode,
    build_receipt,
    build_request,
    chash,
    decision_challenge,
    parse_iso,
    verify_receipt,
)
from pydantic import BaseModel, Field
from sqlalchemy import select, update

from . import __version__, notify, push
from .config import SPEC_VERSION, Settings
from .db import Database
from .models import Approval, ApprovalEvent, Approver, EnrollToken, Org, utcnow
from .security import RateLimiter, SecurityMiddleware, new_token, sha256_hex, token_matches
from .webauthn_flow import (
    WebAuthnError,
    authentication_options,
    registration_options,
    verify_assertion,
    verify_registration,
)

log = logging.getLogger("perathos_gate")

HERE = Path(__file__).parent
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_APR_ID = re.compile(r"^apr_[a-z2-7]{26}$")
MAX_WAIT = 60
POLL_INTERVAL = 0.5
STATUS_FOR = {"approve": "approved", "deny": "denied"}


# --------------------------------------------------------------------------- #
# Request bodies
# --------------------------------------------------------------------------- #


class CreateApprovalBody(BaseModel):
    action: dict[str, Any]
    agent: dict[str, Any] = Field(default_factory=dict)
    args_hash: str
    ttl_seconds: int = 600


class DecisionBody(BaseModel):
    t: str = Field(max_length=200)
    decision: str
    credential: dict[str, Any] | None = None
    via: str | None = Field(default=None, max_length=16)


# Routes by which an approver can reach a request. Anything else counts as a plain link.
VIA = ("push", "qr", "webhook", "link")


def clean_via(via: str | None) -> str:
    return via if via in VIA else "link"


def record_event(db: Database, approval_id: str, kind: str, via: str | None) -> None:
    """Note how a request was opened or decided. Never allowed to break the approval itself."""
    try:
        with db.session() as s:
            s.add(ApprovalEvent(approval_id=approval_id, kind=kind, via=clean_via(via)))
    except Exception:
        log.exception("could not record %s event for %s", kind, approval_id)


def approval_routes(db: Database, approval_ids: list[str]) -> dict[str, dict]:
    """Per approval: the routes it was opened by (in order, no repeats) and the route it was decided by."""
    out: dict[str, dict] = {i: {"opened_via": [], "decided_via": None} for i in approval_ids}
    if not approval_ids:
        return out
    with db.session() as s:
        rows = s.scalars(select(ApprovalEvent).where(ApprovalEvent.approval_id.in_(approval_ids))
                         .order_by(ApprovalEvent.id)).all()
    for r in rows:
        entry = out[r.approval_id]
        if r.kind == "decided":
            entry["decided_via"] = r.via
        elif r.via not in entry["opened_via"]:
            entry["opened_via"].append(r.via)
    return out


class EnrollVerifyBody(BaseModel):
    credential: dict[str, Any]


class PushSubscribeBody(BaseModel):
    token: str = Field(max_length=200)
    subscription: dict[str, Any]


class PushUnsubscribeBody(BaseModel):
    endpoint: str = Field(max_length=push.MAX_ENDPOINT_LEN)


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _iso(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    return dt.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _norm_b64url(value: Any) -> str:
    """Re-encode a base64url (or padded base64url) string canonically, unpadded."""
    if not isinstance(value, str):
        raise ValueError("expected a base64url string")
    return b64url(b64url_decode(value))


def _expire_if_due(db: Database, approval: Approval) -> Approval:
    if approval.status == "pending" and utcnow() >= approval.expires_at:
        with db.session() as s:
            s.execute(update(Approval).where(Approval.id == approval.id, Approval.status == "pending")
                      .values(status="expired"))
            fresh = s.get(Approval, approval.id)
        return fresh
    return approval


def _status_payload(approval: Approval, routes: dict | None = None) -> dict:
    out: dict[str, Any] = {"id": approval.id, "status": approval.status}
    if approval.receipt is not None:
        out["receipt"] = approval.receipt
    if routes:
        out.update(routes)  # outside the receipt: reported by the browser, not signed
    return out


def create_app(settings: Settings | None = None, *, database: Database | None = None) -> FastAPI:
    settings = settings or Settings.from_env()
    db = database or Database(settings.database_url)
    db.create_all()
    signer = settings.load_signer()
    verify_key = signer.public_key_hex()

    app = FastAPI(title="Perathos Gate", version=__version__, docs_url=None, redoc_url=None, openapi_url=None)
    app.state.settings = settings
    app.state.db = db
    app.state.verify_key = verify_key
    app.state.notifier = notify.send_webhook
    # Web Push is optional: without a VAPID key there is no pusher, no push routes and no button.
    vapid = push.load_vapid(settings)
    app.state.pusher = push.make_sender(vapid) if vapid else None
    app.add_middleware(SecurityMiddleware, max_body_bytes=settings.max_body_bytes,
                       limiter=RateLimiter(settings.rate_limit_per_min), trust_proxy=settings.trust_proxy)
    app.mount("/static", StaticFiles(directory=str(HERE / "static")), name="static")
    templates = Jinja2Templates(directory=str(HERE / "templates"))

    def page(request: Request, template: str, status_code: int = 200, **ctx) -> HTMLResponse:
        base = {"origin": settings.origin, "vapid_public_key": vapid.public_key if vapid else None}
        return templates.TemplateResponse(request, template, {**base, **ctx}, status_code=status_code)

    def message_page(request: Request, title: str, text: str, status_code: int) -> HTMLResponse:
        return page(request, "message.html", status_code, title=title, text=text)

    # ------------------------------------------------------------------ auth

    def require_org(authorization: str | None = Header(default=None)) -> Org:
        scheme, _, key = (authorization or "").partition(" ")
        if scheme.lower() != "bearer" or not key.strip():
            raise HTTPException(401, "missing bearer API key", headers={"WWW-Authenticate": "Bearer"})
        key_hash = sha256_hex(key.strip())
        with db.session() as s:
            org = s.scalars(select(Org).where(Org.api_key_hash == key_hash)).first()
        if org is None or not secrets.compare_digest(org.api_key_hash, key_hash):
            raise HTTPException(401, "invalid API key", headers={"WWW-Authenticate": "Bearer"})
        return org

    def load_for_approver(approval_id: str, token: str | None) -> Approval:
        if not _APR_ID.match(approval_id):
            raise HTTPException(404, "not found")
        with db.session() as s:
            approval = s.get(Approval, approval_id)
        if approval is None or not token_matches(token, approval.view_token_hash):
            raise HTTPException(404, "not found")
        return _expire_if_due(db, approval)

    # ------------------------------------------------------------- discovery

    @app.get("/.well-known/perathos-gate.json")
    def well_known() -> dict:
        return {"gate": settings.gate_id, "verify_key": verify_key, "rp_id": settings.rp_id,
                "origin": settings.origin, "version": SPEC_VERSION}

    @app.get("/healthz")
    def healthz() -> dict:
        return {"ok": True}

    # ------------------------------------------------------------- agent API

    @app.post("/v1/approvals", status_code=201)
    def create_approval(body: CreateApprovalBody, org: Org = Depends(require_org)) -> dict:
        if not _HEX64.match(body.args_hash):
            raise HTTPException(422, "args_hash must be 64 lowercase hex characters")
        try:
            req = build_request(org=org.id, gate=settings.gate_id, action=body.action, agent=body.agent,
                                args_hash=body.args_hash, ttl_seconds=body.ttl_seconds)
        except (ValueError, TypeError) as exc:
            raise HTTPException(422, str(exc)) from exc
        token = new_token()
        approval = Approval(id=req["id"], org_id=org.id, request=req, request_hash=chash(req), status="pending",
                            view_token_hash=sha256_hex(token), created_at=parse_iso(req["created_at"]),
                            expires_at=parse_iso(req["expires_at"]))
        with db.session() as s:
            s.add(approval)
        approve_url = f"{settings.origin}/a/{approval.id}?t={token}"
        try:
            app.state.notifier(org.notify_webhook_url, req, approve_url + "&via=webhook")
        except Exception:  # never let notification break the API
            log.exception("notification failed for %s", approval.id)
        if vapid and app.state.pusher:
            try:
                push.notify_approval(db, app.state.pusher, org.id, req, approve_url + "&via=push",
                                     ttl=int((approval.expires_at - utcnow()).total_seconds()))
            except Exception:  # same rule as the webhook
                log.exception("push notification failed for %s", approval.id)
        return {"id": approval.id, "status": "pending", "request": req, "approve_url": approve_url,
                "expires_at": req["expires_at"]}

    def _read_status(org_id: str, approval_id: str) -> Approval | None:
        with db.session() as s:
            approval = s.get(Approval, approval_id)
        if approval is None or approval.org_id != org_id:
            return None
        return _expire_if_due(db, approval)

    @app.get("/v1/approvals/{approval_id}")
    async def get_approval(approval_id: str, wait: int = 0, org: Org = Depends(require_org)) -> dict:
        approval = await run_in_threadpool(_read_status, org.id, approval_id)
        if approval is None:
            raise HTTPException(404, "not found")
        deadline = time.monotonic() + max(0, min(int(wait), MAX_WAIT))
        while approval.status == "pending" and time.monotonic() < deadline:
            await asyncio.sleep(min(POLL_INTERVAL, max(0.0, deadline - time.monotonic())))
            approval = await run_in_threadpool(_read_status, org.id, approval_id)
            if approval is None:  # pragma: no cover - deleted underneath us
                raise HTTPException(404, "not found")
        routes = await run_in_threadpool(approval_routes, db, [approval.id])
        return _status_payload(approval, routes[approval.id])

    # -------------------------------------------------------- approver pages

    @app.get("/a/{approval_id}", response_class=HTMLResponse)
    def approver_page(request: Request, approval_id: str, t: str | None = None, via: str | None = None):
        try:
            approval = load_for_approver(approval_id, t)
        except HTTPException:
            return message_page(request, "Link not valid", "This approval link is not valid.", 404)
        via = clean_via(via)
        record_event(db, approval.id, "opened", via)
        log.info("approval %s opened via %s", approval.id, via)
        req = approval.request
        receipt = approval.receipt or {}
        return page(request, "approve.html", approval=approval, req=req, action=req.get("action", {}), via=via,
                    agent=req.get("agent", {}), expires_at=_iso(approval.expires_at),
                    approver_name=(receipt.get("approver") or {}).get("name"),
                    decided_at=receipt.get("decided_at"), receipt_hash=receipt.get("receipt_hash"))

    def push_offer(approver_id: int) -> dict:
        """Extra field for a response that follows a verified passkey ceremony: a short-lived token
        that lets this browser attach itself to that approver for notifications."""
        return {"push_token": push.issue_token(vapid.secret, approver_id)} if vapid else {}

    def _assert_decidable(approval: Approval, decision: str) -> None:
        if decision not in DECISIONS:
            raise HTTPException(422, "decision must be 'approve' or 'deny'")
        if approval.status != "pending":
            raise HTTPException(409, f"this request is already {approval.status}")

    @app.post("/a/{approval_id}/options")
    def approval_options(approval_id: str, body: DecisionBody) -> dict:
        approval = load_for_approver(approval_id, body.t)
        _assert_decidable(approval, body.decision)
        with db.session() as s:
            creds = s.scalars(select(Approver.credential_id).where(
                Approver.org_id == approval.org_id, Approver.active.is_(True))).all()
        if not creds:
            raise HTTPException(409, "no approvers are enrolled for this organisation")
        challenge = decision_challenge(approval.request_hash, body.decision)
        return authentication_options(settings, challenge=challenge, credential_ids=list(creds))

    @app.post("/a/{approval_id}/verify")
    def approval_verify(approval_id: str, body: DecisionBody) -> dict:
        approval = load_for_approver(approval_id, body.t)
        _assert_decidable(approval, body.decision)
        cred = body.credential
        if not isinstance(cred, dict):
            raise HTTPException(422, "credential is required")
        try:
            raw_id = b64url_decode(str(cred.get("rawId") or cred.get("id") or ""))
            response = cred["response"]
            wa = {"authenticator_data": _norm_b64url(response["authenticatorData"]),
                  "client_data_json": _norm_b64url(response["clientDataJSON"]),
                  "signature": _norm_b64url(response["signature"])}
        except (KeyError, TypeError, ValueError) as exc:
            raise HTTPException(400, "malformed credential") from exc

        with db.session() as s:
            approver = s.scalars(select(Approver).where(
                Approver.org_id == approval.org_id, Approver.credential_id == raw_id,
                Approver.active.is_(True))).first()
        if approver is None:
            raise HTTPException(400, "this passkey is not enrolled as an approver for this organisation")

        challenge = decision_challenge(approval.request_hash, body.decision)
        try:
            new_count = verify_assertion(settings, cred, challenge=challenge,
                                         public_key_cose=approver.public_key_cose, sign_count=approver.sign_count)
        except WebAuthnError as exc:
            log.info("assertion rejected for %s: %s", approval.id, exc)
            raise HTTPException(400, "passkey verification failed") from exc

        receipt = build_receipt(
            request=approval.request,
            decision=body.decision,
            approver={"name": approver.name, "credential_id": b64url(approver.credential_id),
                      "public_key": b64url(approver.public_key), "alg": approver.alg,
                      "enrolled_at": _iso(approver.enrolled_at)},
            rp={"id": settings.rp_id, "origin": settings.origin},
            webauthn=wa,
            server_signer=signer,
            valid_seconds=settings.receipt_valid_seconds,
        )
        check = verify_receipt(receipt, gate_key=verify_key)
        if not check or receipt["request_hash"] != approval.request_hash:
            log.error("receipt self-check failed for %s: %s", approval.id, check.error or "request hash mismatch")
            raise HTTPException(500, "receipt self-check failed; decision not recorded")

        status = STATUS_FOR[body.decision]
        with db.session() as s:
            result = s.execute(
                update(Approval)
                .where(Approval.id == approval.id, Approval.status == "pending", Approval.expires_at > utcnow())
                .values(status=status, receipt=receipt, decided_at=parse_iso(receipt["decided_at"])))
            if result.rowcount != 1:
                raise HTTPException(409, "this request is no longer pending")
            s.execute(update(Approver).where(Approver.id == approver.id).values(sign_count=new_count))
        record_event(db, approval.id, "decided", body.via)
        log.info("approval %s %s by approver #%s via %s", approval.id, status, approver.id, clean_via(body.via))
        return {"id": approval.id, "status": status, "decision": body.decision, "approver": approver.name,
                "receipt_hash": receipt["receipt_hash"], **push_offer(approver.id)}

    # ------------------------------------------------------- push notifications

    def register_push_routes() -> None:
        @app.get("/", response_class=HTMLResponse)
        def home(request: Request):
            # Where the Home Screen app opens (iOS only delivers Web Push to a Home Screen app).
            return page(request, "home.html")

        @app.get("/sw.js")
        def service_worker():
            # Served from the root so its scope is the whole origin.
            return FileResponse(HERE / "static" / "sw.js", media_type="text/javascript")

        @app.get("/manifest.webmanifest")
        def manifest():
            return JSONResponse({"name": settings.rp_name, "short_name": "Gate", "start_url": "/", "scope": "/",
                                 "display": "standalone", "background_color": "#f6f7f9", "theme_color": "#14181f"},
                                media_type="application/manifest+json")

        @app.post("/push/options")
        def push_options() -> dict:
            """Start the confirm-with-passkey step: any discoverable passkey of this Gate may answer."""
            return authentication_options(settings, challenge=push.new_challenge(vapid.secret), credential_ids=[])

        @app.post("/push/verify")
        def push_verify(body: EnrollVerifyBody) -> dict:
            cred = body.credential
            try:
                raw_id = b64url_decode(str(cred.get("rawId") or cred.get("id") or ""))
                client_data = json.loads(b64url_decode(cred["response"]["clientDataJSON"]))
                challenge = b64url_decode(client_data["challenge"])
            except (KeyError, TypeError, ValueError, AttributeError) as exc:
                raise HTTPException(400, "malformed credential") from exc
            if not push.challenge_valid(vapid.secret, challenge):
                raise HTTPException(400, "passkey verification failed")
            with db.session() as s:
                approver = s.scalars(select(Approver).where(Approver.credential_id == raw_id,
                                                            Approver.active.is_(True))).first()
            if approver is None:
                raise HTTPException(400, "this passkey is not enrolled as an approver")
            try:
                new_count = verify_assertion(settings, cred, challenge=challenge,
                                             public_key_cose=approver.public_key_cose,
                                             sign_count=approver.sign_count)
            except WebAuthnError as exc:
                log.info("push sign-in rejected: %s", exc)
                raise HTTPException(400, "passkey verification failed") from exc
            with db.session() as s:
                s.execute(update(Approver).where(Approver.id == approver.id).values(sign_count=new_count))
            return {"ok": True, "approver": approver.name, **push_offer(approver.id)}

        @app.post("/push/subscribe")
        def push_subscribe(body: PushSubscribeBody) -> dict:
            approver_id = push.check_token(vapid.secret, body.token)
            if approver_id is None:
                raise HTTPException(403, "confirm with your passkey again, then enable notifications")
            try:
                endpoint, p256dh, auth = push.parse_subscription(body.subscription)
            except ValueError as exc:
                raise HTTPException(422, "malformed push subscription") from exc
            with db.session() as s:
                approver = s.get(Approver, approver_id)
            if approver is None or not approver.active:
                raise HTTPException(403, "this approver is no longer active")
            push.save_subscription(db, approver, endpoint, p256dh, auth)
            log.info("push subscription saved for approver #%s at %s", approver.id, push.endpoint_host(endpoint))
            return {"ok": True}

        @app.post("/push/unsubscribe")
        def push_unsubscribe(body: PushUnsubscribeBody) -> dict:
            # The endpoint URL is known only to that browser and this server, so presenting it is enough.
            return {"ok": True, "removed": push.delete_subscription(db, body.endpoint)}

    # --------------------------------------------------------------- enrolment

    def load_enroll_token(token: str) -> EnrollToken:
        with db.session() as s:
            row = s.get(EnrollToken, sha256_hex(token))
        if row is None or row.used or utcnow() >= row.expires_at:
            raise HTTPException(404, "this enrolment link is not valid, already used, or expired")
        return row

    @app.get("/enroll/{token}", response_class=HTMLResponse)
    def enroll_page(request: Request, token: str):
        try:
            row = load_enroll_token(token)
        except HTTPException:
            return message_page(request, "Link not valid",
                                "This enrolment link is not valid, was already used, or has expired. "
                                "Ask your administrator for a new one.", 404)
        with db.session() as s:
            org = s.get(Org, row.org_id)
        return page(request, "enroll.html", name=row.approver_name, org_name=org.name if org else "",
                    expires_at=_iso(row.expires_at))

    @app.post("/enroll/{token}/options")
    def enroll_options(token: str) -> dict:
        row = load_enroll_token(token)
        challenge = secrets.token_bytes(32)
        user_handle = row.user_handle or secrets.token_bytes(16)
        with db.session() as s:
            s.execute(update(EnrollToken).where(EnrollToken.token_hash == row.token_hash)
                      .values(challenge=challenge, user_handle=user_handle))
            existing = s.scalars(select(Approver.credential_id).where(
                Approver.org_id == row.org_id, Approver.active.is_(True))).all()
        return registration_options(settings, user_name=row.approver_name, user_handle=user_handle,
                                    challenge=challenge, exclude=list(existing))

    @app.post("/enroll/{token}/verify")
    def enroll_verify(token: str, body: EnrollVerifyBody) -> dict:
        row = load_enroll_token(token)
        if not row.challenge:
            raise HTTPException(409, "request registration options first")
        try:
            reg = verify_registration(settings, body.credential, challenge=row.challenge)
        except WebAuthnError as exc:
            log.info("registration rejected: %s", exc)
            raise HTTPException(400, "passkey registration failed") from exc
        with db.session() as s:
            if s.scalars(select(Approver.id).where(Approver.credential_id == reg.credential_id)).first():
                raise HTTPException(409, "this passkey is already enrolled")
            used = s.execute(update(EnrollToken).where(EnrollToken.token_hash == row.token_hash,
                                                       EnrollToken.used.is_(False))
                             .values(used=True, challenge=None))
            if used.rowcount != 1:
                raise HTTPException(409, "this enrolment link was already used")
            approver = Approver(org_id=row.org_id, name=row.approver_name, credential_id=reg.credential_id,
                                public_key=reg.public_key_der, public_key_cose=reg.public_key_cose, alg=reg.alg,
                                sign_count=reg.sign_count, enrolled_at=utcnow(), active=True)
            s.add(approver)
        log.info("approver enrolled for org %s", row.org_id)
        return {"ok": True, "approver": row.approver_name, "credential_id": b64url(reg.credential_id),
                "alg": reg.alg, **push_offer(approver.id)}

    if vapid:
        register_push_routes()

    return app


# --------------------------------------------------------------------------- #
# Admin operations shared by the CLI and tests
# --------------------------------------------------------------------------- #


def admin_create_org(db: Database, name: str, webhook: str | None = None) -> tuple[str, str]:
    """Create an organisation; returns (org_id, api_key). The key is not stored, only its sha256."""
    from .security import new_api_key, new_org_id

    if webhook and not notify.is_valid_webhook_url(webhook):
        raise ValueError("webhook must be an http(s) URL")
    org_id, key = new_org_id(), new_api_key()
    with db.session() as s:
        s.add(Org(id=org_id, name=name, api_key_hash=sha256_hex(key), notify_webhook_url=webhook or None,
                  created_at=utcnow()))
    return org_id, key


def admin_rotate_key(db: Database, org_id: str) -> str:
    """Replace an organisation's API key; returns the new key once. The old key stops working at once."""
    from .security import new_api_key

    key = new_api_key()
    with db.session() as s:
        org = s.get(Org, org_id)
        if org is None:
            raise ValueError(f"unknown org {org_id}")
        org.api_key_hash = sha256_hex(key)
    return key


def admin_invite(db: Database, settings: Settings, org_id: str, name: str, *, hours: int = 24) -> str:
    """Create a single-use enrolment link valid for `hours`."""
    with db.session() as s:
        if s.get(Org, org_id) is None:
            raise ValueError(f"unknown org {org_id}")
        token = new_token()
        s.add(EnrollToken(token_hash=sha256_hex(token), org_id=org_id, approver_name=name,
                          expires_at=utcnow() + timedelta(hours=hours), used=False))
    return f"{settings.origin}/enroll/{token}"


def admin_list_approvals(db: Database, org_id: str, limit: int = 50) -> list[Approval]:
    with db.session() as s:
        rows = s.scalars(select(Approval).where(Approval.org_id == org_id)
                         .order_by(Approval.created_at.desc()).limit(limit)).all()
    return [_expire_if_due(db, r) for r in rows]


def app_factory() -> FastAPI:
    """Entry point for `uvicorn --factory perathos_gate.app:app_factory`."""
    return create_app()
