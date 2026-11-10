"""Tokens, hashing, rate limiting, body-size limit, security headers and redacted access logs."""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import re
import secrets
import threading
import time
from collections import deque

log = logging.getLogger("perathos_gate.access")

_B32 = "abcdefghijklmnopqrstuvwxyz234567"


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def new_token() -> str:
    return secrets.token_urlsafe(32)


def new_api_key() -> str:
    return "pgk_" + secrets.token_urlsafe(32)


def new_org_id() -> str:
    return "org_" + "".join(secrets.choice(_B32) for _ in range(16))


def token_matches(presented: str | None, stored_hash: str) -> bool:
    """Constant-time comparison of a presented secret against its stored sha256."""
    if not presented:
        return False
    return hmac.compare_digest(sha256_hex(presented), stored_hash)


# --------------------------------------------------------------------------- #
# Rate limiting (in-memory sliding window, per client IP)
# --------------------------------------------------------------------------- #


class RateLimiter:
    def __init__(self, limit: int, window_seconds: float = 60.0, max_keys: int = 100_000):
        self.limit = limit
        self.window = window_seconds
        self.max_keys = max_keys
        self._hits: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        with self._lock:
            if len(self._hits) > self.max_keys:
                self._hits.clear()
            q = self._hits.setdefault(key, deque())
            while q and now - q[0] > self.window:
                q.popleft()
            if len(q) >= self.limit:
                return False
            q.append(now)
            return True


# --------------------------------------------------------------------------- #
# ASGI middleware
# --------------------------------------------------------------------------- #

HTML_CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
            "connect-src 'self'; worker-src 'self'; manifest-src 'self'; form-action 'self'; base-uri 'none'; "
            "frame-ancestors 'none'")

_COMMON_HEADERS = [
    (b"x-content-type-options", b"nosniff"),
    (b"referrer-policy", b"no-referrer"),
    (b"x-frame-options", b"DENY"),
    (b"cache-control", b"no-store"),
]

_ENROLL_PATH = re.compile(r"^/enroll/[^/]+")


def redact_path(path: str) -> str:
    """Enrolment tokens live in the path; never log them."""
    return _ENROLL_PATH.sub("/enroll/<token>", path)


class SecurityMiddleware:
    """Pure-ASGI middleware: rejects bodies over the limit (413), rate-limits approver POSTs (429),
    adds security headers (CSP on HTML) and writes an access log line without query strings or tokens."""

    def __init__(self, app, *, max_body_bytes: int, limiter: RateLimiter, trust_proxy: bool = False):
        self.app = app
        self.max_body = max_body_bytes
        self.limiter = limiter
        self.trust_proxy = trust_proxy

    def _client_ip(self, scope) -> str:
        if self.trust_proxy:
            for name, value in scope.get("headers", []):
                if name == b"x-forwarded-for":
                    return value.decode("latin-1").split(",")[0].strip()
        client = scope.get("client")
        return client[0] if client else "unknown"

    async def _reply(self, send, status: int, message: str) -> None:
        body = json.dumps({"detail": message}).encode()
        await send({"type": "http.response.start", "status": status,
                    "headers": [(b"content-type", b"application/json"),
                                (b"content-length", str(len(body)).encode()), *_COMMON_HEADERS]})
        await send({"type": "http.response.body", "body": body})

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        method, path = scope["method"], scope["path"]
        started = time.monotonic()
        status_holder = {"status": 0}

        async def send_wrapper(message):
            if message["type"] == "http.response.start":
                status_holder["status"] = message["status"]
                headers = list(message.get("headers", []))
                names = {h[0].lower() for h in headers}
                for h in _COMMON_HEADERS:
                    if h[0] not in names:
                        headers.append(h)
                ctype = next((v for k, v in headers if k.lower() == b"content-type"), b"")
                if ctype.startswith(b"text/html"):
                    headers.append((b"content-security-policy", HTML_CSP.encode()))
                message = {**message, "headers": headers}
            await send(message)

        try:
            for name, value in scope.get("headers", []):
                if name == b"content-length":
                    try:
                        too_big = int(value) > self.max_body
                    except ValueError:
                        too_big = True
                    if too_big:
                        status_holder["status"] = 413
                        return await self._reply(send, 413, "request body too large")

            approver_post = method == "POST" and path.startswith(("/a/", "/enroll/", "/push/"))
            if approver_post and not self.limiter.allow(self._client_ip(scope)):
                status_holder["status"] = 429
                return await self._reply(send, 429, "too many requests")

            received = 0
            max_body = self.max_body

            async def limited_receive():
                nonlocal received
                message = await receive()
                if message["type"] == "http.request":
                    received += len(message.get("body", b""))
                    if received > max_body:
                        raise _BodyTooLarge()
                return message

            try:
                await self.app(scope, limited_receive, send_wrapper)
            except _BodyTooLarge:
                if status_holder["status"] == 0:
                    status_holder["status"] = 413
                    await self._reply(send, 413, "request body too large")
        finally:
            log.info("%s %s %s %.0fms", method, redact_path(path), status_holder["status"],
                     (time.monotonic() - started) * 1000)


class _BodyTooLarge(Exception):
    pass
