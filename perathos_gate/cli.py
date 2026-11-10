"""`perathos-gate` command line: init, create-org, rotate-key, invite, serve, list-approvals."""
from __future__ import annotations

import argparse
import logging
import os
import sys

from .config import Settings, create_key_file
from .db import Database


def _settings() -> Settings:
    return Settings.from_env()


def _db(settings: Settings) -> Database:
    db = Database(settings.database_url)
    db.create_all()
    return db


def cmd_init(args) -> int:
    s = _settings()
    if s.signing_key_hex:
        vk = s.load_signer().public_key_hex()
        print("Using GATE_SIGNING_KEY from the environment (no key file written).")
    else:
        vk, created = create_key_file(s.key_file)
        print(("Created" if created else "Existing") + f" Gate signing key: {s.key_file}")
    _db(s)
    print(f"Database ready: {s.database_url.split('@')[-1]}")
    print(f"Gate id:    {s.gate_id}")
    print(f"RP id:      {s.rp_id}")
    print(f"Origin:     {s.origin}")
    print(f"Verify key: {vk}")
    print("Pin this verify key in clients (it is also served at /.well-known/perathos-gate.json).")
    return 0


def cmd_create_org(args) -> int:
    from .app import admin_create_org

    s = _settings()
    org_id, key = admin_create_org(_db(s), args.name, args.webhook)
    print(f"Org id:  {org_id}")
    print(f"API key: {key}")
    print("Store the API key now: it is shown only once (the server keeps only its SHA-256).")
    return 0


def cmd_rotate_key(args) -> int:
    from .app import admin_rotate_key

    s = _settings()
    try:
        key = admin_rotate_key(_db(s), args.org)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f"Org id:  {args.org}")
    print(f"API key: {key}")
    print("The previous key no longer works. Store this one now: it is shown only once.")
    return 0


def cmd_invite(args) -> int:
    from .app import admin_invite

    s = _settings()
    try:
        url = admin_invite(_db(s), s, args.org, args.name, hours=args.hours)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f"Enrolment link for {args.name} (single use, expires in {args.hours} h):")
    print(url)
    print("Send it out of band. Passkeys need HTTPS except on localhost.")
    return 0


def cmd_list_approvals(args) -> int:
    from .app import admin_list_approvals

    s = _settings()
    rows = admin_list_approvals(_db(s), args.org, args.limit)
    if not rows:
        print("No approvals.")
        return 0
    for r in rows:
        summary = r.request.get("action", {}).get("summary", "")
        approver = ((r.receipt or {}).get("approver") or {}).get("name", "")
        print(f"{r.id}  {r.status:<8}  {r.created_at:%Y-%m-%d %H:%M:%S}Z  {approver:<20}  {summary[:70]}")
    return 0


def cmd_serve(args) -> int:
    import uvicorn

    s = _settings()
    s.load_signer()  # fail fast with a clear message if there is no key
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    uvicorn.run(
        "perathos_gate.app:app_factory",
        factory=True,
        host=args.host,
        port=args.port,
        access_log=False,  # our middleware logs requests without query strings or tokens
        proxy_headers=s.trust_proxy,
        forwarded_allow_ips="*" if s.trust_proxy else None,
        log_level="info",
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="perathos-gate", description="Perathos Gate server")
    sub = p.add_subparsers(dest="command", required=True)

    sub.add_parser("init", help="create the data dir, database and server signing key").set_defaults(func=cmd_init)

    c = sub.add_parser("create-org", help="create an organisation and print its API key once")
    c.add_argument("name")
    c.add_argument("--webhook", help="Slack-compatible incoming webhook URL for notifications")
    c.set_defaults(func=cmd_create_org)

    rk = sub.add_parser("rotate-key", help="replace an organisation's API key and print the new one once")
    rk.add_argument("--org", required=True)
    rk.set_defaults(func=cmd_rotate_key)

    i = sub.add_parser("invite", help="print a single-use passkey enrolment link for an approver")
    i.add_argument("--org", required=True)
    i.add_argument("--name", required=True)
    i.add_argument("--hours", type=int, default=24)
    i.set_defaults(func=cmd_invite)

    sv = sub.add_parser("serve", help="run the HTTP server")
    sv.add_argument("--host", default="127.0.0.1")
    sv.add_argument("--port", type=int, default=int(os.environ.get("PORT", "8787")))
    sv.set_defaults(func=cmd_serve)

    la = sub.add_parser("list-approvals", help="list recent approvals for an organisation")
    la.add_argument("--org", required=True)
    la.add_argument("--limit", type=int, default=50)
    la.set_defaults(func=cmd_list_approvals)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
