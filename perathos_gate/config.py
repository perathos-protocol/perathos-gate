"""Settings from environment variables, and the server's Ed25519 signing key."""
from __future__ import annotations

import contextlib
import os
import secrets
from dataclasses import dataclass, field
from pathlib import Path

from perathos.keytrust import LocalSigner

SPEC_VERSION = "perathos.gate/v1"


def _env(name: str, default: str) -> str:
    value = os.environ.get(name, "").strip()
    return value or default


def normalise_database_url(url: str) -> str:
    """Accept the `postgres://` URLs PaaS providers hand out."""
    if url.startswith("postgres://"):
        return "postgresql+psycopg://" + url[len("postgres://"):]
    if url.startswith("postgresql://"):
        return "postgresql+psycopg://" + url[len("postgresql://"):]
    return url


@dataclass
class Settings:
    gate_id: str = "localhost"
    rp_id: str = "localhost"
    origin: str = "http://localhost:8787"
    rp_name: str = "Perathos Gate"
    database_url: str = "sqlite:///./data/gate.db"
    key_file: Path = field(default_factory=lambda: Path("./data/gate_signing.key"))
    signing_key_hex: str | None = None
    trust_proxy: bool = False
    rate_limit_per_min: int = 30
    max_body_bytes: int = 64 * 1024
    receipt_valid_seconds: int = 600
    vapid_private_key: str | None = None
    vapid_subject: str | None = None

    @classmethod
    def from_env(cls) -> Settings:
        rp_id = _env("GATE_RP_ID", "localhost")
        return cls(
            gate_id=_env("GATE_ID", rp_id),
            rp_id=rp_id,
            origin=_env("GATE_ORIGIN", "http://localhost:8787").rstrip("/"),
            rp_name=_env("GATE_RP_NAME", "Perathos Gate"),
            database_url=normalise_database_url(_env("DATABASE_URL", "sqlite:///./data/gate.db")),
            key_file=Path(_env("GATE_KEY_FILE", "./data/gate_signing.key")),
            signing_key_hex=os.environ.get("GATE_SIGNING_KEY", "").strip().lower() or None,
            trust_proxy=_env("GATE_TRUST_PROXY", "0").lower() in ("1", "true", "yes"),
            rate_limit_per_min=int(_env("GATE_RATE_LIMIT_PER_MIN", "30")),
            vapid_private_key=os.environ.get("GATE_VAPID_PRIVATE_KEY", "").strip() or None,
            vapid_subject=os.environ.get("GATE_VAPID_SUBJECT", "").strip() or None,
        )

    def load_signer(self) -> LocalSigner:
        """The Gate's receipt-signing key, from GATE_SIGNING_KEY or GATE_KEY_FILE."""
        if self.signing_key_hex:
            return LocalSigner.from_hex(self.signing_key_hex)
        if not self.key_file.exists():
            raise RuntimeError(
                f"No Gate signing key: set GATE_SIGNING_KEY or run 'perathos-gate init' (expected {self.key_file})")
        return LocalSigner.from_hex(self.key_file.read_text(encoding="ascii").strip().lower())


def create_key_file(path: Path) -> tuple[str, bool]:
    """Create a new Ed25519 seed at `path` (mode 0600) unless one exists. Returns (verify_key_hex, created)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        return LocalSigner.from_hex(path.read_text(encoding="ascii").strip().lower()).public_key_hex(), False
    seed = secrets.token_bytes(32).hex()
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="ascii") as fh:
        fh.write(seed + "\n")
    with contextlib.suppress(OSError):  # best effort on filesystems without POSIX modes
        os.chmod(path, 0o600)
    return LocalSigner.from_hex(seed).public_key_hex(), True
