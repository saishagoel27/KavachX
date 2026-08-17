"""Append-only, hash-chained audit log."""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import BigInteger, ForeignKey, Index, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, JSONType, TimestampMixin, UUIDType


class AuditEvent(Base, TimestampMixin):
    """One audit record.

    ``hash = sha256(canonical(actor, action, subject, timestamp, evidence_hash, previous_hash))``

    ``seq`` is per-tenant and monotonic; combined with ``previous_hash`` it makes silent
    deletion or reordering detectable. There is deliberately no update or delete path.
    """

    __tablename__ = "audit_events"
    __table_args__ = (
        UniqueConstraint("tenant_id", "seq", name="uq_audit_seq"),
        Index("ix_audit_tenant_seq", "tenant_id", "seq"),
        Index("ix_audit_action", "action"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUIDType, primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUIDType, nullable=False, index=True)
    seq: Mapped[int] = mapped_column(BigInteger, nullable=False)

    actor_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUIDType, ForeignKey("users.id", ondelete="SET NULL")
    )
    actor_label: Mapped[str] = mapped_column(String(200), nullable=False, default="system")
    action: Mapped[str] = mapped_column(String(80), nullable=False)
    subject_type: Mapped[str] = mapped_column(String(60), nullable=False, default="")
    subject_id: Mapped[str] = mapped_column(String(120), nullable=False, default="")
    request_id: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    source_ip: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    detail: Mapped[dict[str, Any]] = mapped_column(JSONType, nullable=False, default=dict)

    #: The exact timestamp string that went into ``hash``.
    #:
    #: Stored explicitly rather than re-deriving it from ``created_at`` at verification time.
    #: ``created_at`` round-trips differently across dialects — SQLite drops the timezone, so
    #: ``created_at.isoformat()`` after a read is not the string that was hashed on write, and the
    #: chain would appear broken on a database that had never been touched.
    hashed_at: Mapped[str] = mapped_column(String(40), nullable=False, default="")
    evidence_hash: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    previous_hash: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    hash: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    note: Mapped[str] = mapped_column(Text, nullable=False, default="")


class AuditAction:
    """Canonical action names. Strings, so historical records stay readable."""

    LOGIN = "auth.login"
    LOGIN_FAILED = "auth.login_failed"
    LOGOUT = "auth.logout"
    TOKEN_REFRESH = "auth.token_refresh"
    USER_REGISTERED = "user.registered"
    ORG_CREATED = "org.created"
    MEMBER_INVITED = "member.invited"
    MEMBER_ROLE_CHANGED = "member.role_changed"
    PROJECT_CREATED = "project.created"
    REPOSITORY_INSTALLED = "repository.installed"
    REPOSITORY_AUTHORITY_VERIFIED = "repository.authority_verified"
    REPOSITORY_AUTHORITY_REJECTED = "repository.authority_rejected"
    RUN_STARTED = "run.started"
    RUN_COMPLETED = "run.completed"
    RUN_FAILED = "run.failed"
    RUN_ABORTED = "run.aborted"
    FINDING_ACCESSED = "finding.accessed"
    EXPLOIT_ACCESSED = "finding.exploit_accessed"
    SHIELD_DEPLOYED = "shield.deployed"
    SHIELD_REVERTED = "shield.reverted"
    PATCH_REVIEWED = "patch.reviewed"
    PATCH_APPROVED = "patch.approved"
    PATCH_REJECTED = "patch.rejected"
    POLICY_CHANGED = "policy.changed"
    CERTIFICATE_ISSUED = "certificate.issued"
    CERTIFICATE_DOWNLOADED = "certificate.downloaded"
    PR_PUBLISHED = "publisher.pr_published"
    PUBLISH_BLOCKED = "publisher.blocked"
    AUDIT_READ = "audit.read"
