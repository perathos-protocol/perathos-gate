from __future__ import annotations

import hashlib
import secrets
import sys
import threading
from dataclasses import dataclass, field
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).parent))

from softauthn import SoftAuthenticator  # noqa: E402

from perathos_gate.app import admin_create_org, admin_invite, create_app  # noqa: E402
from perathos_gate.config import Settings  # noqa: E402
from perathos_gate.db import Database  # noqa: E402
from perathos_gate.push import generate_vapid_keys  # noqa: E402

RP_ID = "localhost"
ORIGIN = "http://localhost:8787"


@dataclass
class Gate:
    client: TestClient
    settings: Settings
    db: Database
    verify_key: str
    webhooks: list = field(default_factory=list)
    # Web Push: every (subscription, payload, ttl) the fake sender saw, and what it answers per endpoint
    # (an HTTP status, or an exception to raise). Default 201.
    pushes: list = field(default_factory=list)
    push_answers: dict = field(default_factory=dict)

    def fake_push(self, subscription: dict, payload: str, ttl: int) -> int:
        self.pushes.append((subscription, payload, ttl))
        answer = self.push_answers.get(subscription["endpoint"], 201)
        if isinstance(answer, Exception):
            raise answer
        return answer

    @staticmethod
    def wait_push() -> None:
        for t in threading.enumerate():
            if t.name == "gate-push":
                t.join(5)

    # ------------------------------------------------------------ admin

    def org(self, name: str = "Acme", webhook: str | None = None) -> tuple[str, str]:
        return admin_create_org(self.db, name, webhook)

    def enrol(self, org_id: str, name: str = "Alice Moyo") -> SoftAuthenticator:
        url = admin_invite(self.db, self.settings, org_id, name)
        path = url[len(self.settings.origin):]
        auth = SoftAuthenticator(self.settings.rp_id, self.settings.origin)
        r = self.client.get(path)
        assert r.status_code == 200, r.text
        opts = self.client.post(path + "/options", json={})
        assert opts.status_code == 200, opts.text
        r = self.client.post(path + "/verify", json={"credential": auth.register(opts.json())})
        assert r.status_code == 200, r.text
        return auth

    # ------------------------------------------------------------ agent

    def create(self, api_key: str, *, summary: str = "railway volume delete pg-data --yes",
               args: str = "railway volume delete pg-data --yes", ttl: int = 600) -> dict:
        r = self.client.post("/v1/approvals", headers={"Authorization": f"Bearer {api_key}"}, json={
            "action": {"tool": "Bash", "summary": summary, "rule": "paas.railway", "target": "pg-data",
                       "detail": "Deletes the production Postgres volume."},
            "agent": {"name": "claude-code", "session_id": "sess-1", "host": "build-01"},
            "args_hash": args_hash(args), "ttl_seconds": ttl})
        assert r.status_code == 201, r.text
        return r.json()

    def status(self, api_key: str, approval_id: str, wait: int = 0):
        return self.client.get(f"/v1/approvals/{approval_id}?wait={wait}",
                               headers={"Authorization": f"Bearer {api_key}"})

    # ------------------------------------------------------------ approver

    @staticmethod
    def page_parts(created: dict) -> tuple[str, str]:
        url = created["approve_url"]
        path, _, query = url.partition("?")
        return "/a/" + path.rsplit("/a/", 1)[1], query.split("t=", 1)[1]

    def options(self, created: dict, decision: str):
        path, t = self.page_parts(created)
        return self.client.post(path + "/options", json={"t": t, "decision": decision})

    def verify(self, created: dict, decision: str, credential: dict):
        path, t = self.page_parts(created)
        return self.client.post(path + "/verify", json={"t": t, "decision": decision, "credential": credential})

    def decide(self, created: dict, decision: str, auth: SoftAuthenticator):
        opts = self.options(created, decision)
        assert opts.status_code == 200, opts.text
        return self.verify(created, decision, auth.assert_(opts.json()))


def args_hash(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


@pytest.fixture
def make_gate(tmp_path):
    clients = []

    def _make(**overrides) -> Gate:
        settings = Settings(gate_id="gate.test", rp_id=RP_ID, origin=ORIGIN,
                            database_url=f"sqlite:///{(tmp_path / 'gate.db').as_posix()}",
                            key_file=tmp_path / "gate.key", signing_key_hex=secrets.token_bytes(32).hex(),
                            rate_limit_per_min=1000)
        for k, v in overrides.items():
            setattr(settings, k, v)
        db = Database(settings.database_url)
        app = create_app(settings, database=db)
        gate = Gate(client=None, settings=settings, db=db, verify_key=app.state.verify_key)  # type: ignore[arg-type]
        app.state.notifier = lambda url, req, approve_url: gate.webhooks.append((url, req, approve_url))
        if app.state.pusher is not None:  # only when the test configured a VAPID key
            app.state.pusher = gate.fake_push
        client = TestClient(app)
        client.__enter__()
        clients.append(client)
        gate.client = client
        return gate

    yield _make
    for c in clients:
        c.__exit__(None, None, None)


@pytest.fixture
def gate(make_gate) -> Gate:
    return make_gate()


@pytest.fixture
def push_gate(make_gate) -> Gate:
    """A gate with Web Push configured and the sender replaced by Gate.fake_push."""
    return make_gate(vapid_private_key=generate_vapid_keys()[0], vapid_subject="mailto:ops@example.com")
