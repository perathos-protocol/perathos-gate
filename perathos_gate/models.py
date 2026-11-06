"""ORM models: organisations, approvers (passkeys), enrolment tokens and approval requests."""
from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Integer, LargeBinary, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy.types import TypeDecorator


def utcnow() -> datetime:
    return datetime.now(UTC).replace(microsecond=0)


class UTCDateTime(TypeDecorator):
    """Always timezone-aware UTC in Python, whatever the backend stores."""

    impl = DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is not None and value.tzinfo is None:
            value = value.replace(tzinfo=UTC)
        return value

    def process_result_value(self, value, dialect):
        if value is not None and value.tzinfo is None:
            value = value.replace(tzinfo=UTC)
        return value


class Base(DeclarativeBase):
    pass


class Org(Base):
    __tablename__ = "orgs"

    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    name: Mapped[str] = mapped_column(String(200))
    api_key_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    notify_webhook_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)


class Approver(Base):
    __tablename__ = "approvers"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    org_id: Mapped[str] = mapped_column(ForeignKey("orgs.id"), index=True)
    name: Mapped[str] = mapped_column(String(200))
    credential_id: Mapped[bytes] = mapped_column(LargeBinary(1024), unique=True, index=True)
    # DER SubjectPublicKeyInfo: what receipts carry and offline verifiers use.
    public_key: Mapped[bytes] = mapped_column(LargeBinary)
    # COSE_Key bytes as returned by the authenticator: what py_webauthn verifies assertions with.
    public_key_cose: Mapped[bytes] = mapped_column(LargeBinary)
    alg: Mapped[int] = mapped_column(Integer)
    sign_count: Mapped[int] = mapped_column(Integer, default=0)
    enrolled_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    active: Mapped[bool] = mapped_column(Boolean, default=True)


class EnrollToken(Base):
    __tablename__ = "enroll_tokens"

    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    org_id: Mapped[str] = mapped_column(ForeignKey("orgs.id"), index=True)
    approver_name: Mapped[str] = mapped_column(String(200))
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime)
    used: Mapped[bool] = mapped_column(Boolean, default=False)
    # Registration ceremony state (set by /options, consumed by /verify).
    user_handle: Mapped[bytes | None] = mapped_column(LargeBinary(64), nullable=True)
    challenge: Mapped[bytes | None] = mapped_column(LargeBinary(64), nullable=True)


class Approval(Base):
    __tablename__ = "approvals"

    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    org_id: Mapped[str] = mapped_column(ForeignKey("orgs.id"), index=True)
    request: Mapped[dict] = mapped_column(JSON)
    request_hash: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(16), default="pending", index=True)
    # sha256 of the approver-page token; the token itself only ever appears in approve_url.
    view_token_hash: Mapped[str] = mapped_column(String(64))
    receipt: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime)
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime)
    decided_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
