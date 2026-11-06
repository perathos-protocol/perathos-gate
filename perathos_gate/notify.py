"""Slack-compatible webhook notification, fired in a background thread (never blocks a request)."""
from __future__ import annotations

import json
import logging
import threading
import urllib.error
import urllib.request
from urllib.parse import urlparse

log = logging.getLogger("perathos_gate.notify")


def is_valid_webhook_url(url: str) -> bool:
    parsed = urlparse(url)
    return parsed.scheme in ("https", "http") and bool(parsed.netloc)


def message_text(request: dict, approve_url: str) -> str:
    agent = request.get("agent", {}).get("name") or "An agent"
    summary = request.get("action", {}).get("summary", "")
    return f"{agent} wants to {summary}. Approve or deny: {approve_url}"


def _post(url: str, payload: dict, timeout: float) -> None:
    host = urlparse(url).netloc
    if urlparse(url).scheme not in ("http", "https"):
        return
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST",  # noqa: S310 - scheme checked above
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - scheme checked above
            log.info("webhook delivered to %s: HTTP %s", host, resp.status)
    except urllib.error.HTTPError as exc:
        log.warning("webhook to %s failed: HTTP %s", host, exc.code)
    except (urllib.error.URLError, OSError, ValueError) as exc:
        # Never log the full URL: Slack webhook URLs are secrets.
        log.warning("webhook to %s failed: %s", host, type(exc).__name__)


def send_webhook(url: str | None, request: dict, approve_url: str, *, timeout: float = 5.0) -> threading.Thread | None:
    """Fire-and-forget POST of {"text": ...}. Returns the thread (tests may join it)."""
    if not url or not is_valid_webhook_url(url):
        return None
    t = threading.Thread(target=_post, args=(url, {"text": message_text(request, approve_url)}, timeout),
                         name="gate-webhook", daemon=True)
    t.start()
    return t
