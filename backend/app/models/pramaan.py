"""PRAMAAN: the evidence graph and the assurance certificate."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    DateTime,
    ForeignKey,
    Index,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, JSONType, TimestampMixin, UUIDPrimaryKeyMixin, UUIDType
from app.models.enums import AssuranceLevel


class EvidenceNode(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """A single addressable piece of evidence.

    ``content_hash`` is the sha256 of the canonical serialisation of whatever the node
    asserts. Certificates reference these hashes, so a certificate cannot silently drift
    from the evidence it claims.
    """

    __tablename__ = "evidence_nodes"
    __table_args__ = (
        UniqueConstraint("run_id", "ref", name="uq_evidence_ref"),
        Index("ix_evidence_nodes_run_type", "run_id", "type"),
    )

    tenant_id: Mapped[uuid.UUID] = mapped_column(UUIDType, nullable=False, index=True)
    run_id: Mapped[uuid.UUID] = mapped_column(
        UUIDType, ForeignKey("runs.id", ondelete="CASCADE"), nullable=False
    )
    #: Stable, human-readable reference used by every other table, e.g. ``ev:code:hdr.c:340``.
    ref: Mapped[str] = mapped_column(String(300), nullable=False)
    type: Mapped[str] = mapped_column(String(40), nullable=False)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False, default="")
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    meta_json: Mapped[dict[str, Any]] = mapped_column(JSONType, nullable=False, default=dict)
    #: Which subsystem produced it — never "llm" for anything decision-bearing.
    produced_by: Mapped[str] = mapped_column(String(80), nullable=False, default="")


class EvidenceEdge(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "evidence_edges"
    __table_args__ = (
        UniqueConstraint("run_id", "source_ref", "relation", "target_ref", name="uq_evidence_edge"),
        Index("ix_evidence_edges_run", "run_id"),
    )

    tenant_id: Mapped[uuid.UUID] = mapped_column(UUIDType, nullable=False, index=True)
    run_id: Mapped[uuid.UUID] = mapped_column(
        UUIDType, ForeignKey("runs.id", ondelete="CASCADE"), nullable=False
    )
    source_ref: Mapped[str] = mapped_column(String(300), nullable=False)
    relation: Mapped[str] = mapped_column(String(60), nullable=False)
    target_ref: Mapped[str] = mapped_column(String(300), nullable=False)
    meta_json: Mapped[dict[str, Any]] = mapped_column(JSONType, nullable=False, default=dict)


class Certificate(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """Certificate of *bounded empirical assurance*. Never a formal proof."""

    __tablename__ = "certificates"
    __table_args__ = (
        UniqueConstraint("run_id", "finding_id", name="uq_certificate_finding"),
        Index("ix_certificates_run", "run_id"),
    )

    tenant_id: Mapped[uuid.UUID] = mapped_column(UUIDType, nullable=False, index=True)
    run_id: Mapped[uuid.UUID] = mapped_column(
        UUIDType, ForeignKey("runs.id", ondelete="CASCADE"), nullable=False
    )
    finding_id: Mapped[uuid.UUID | None] = mapped_column(
        UUIDType, ForeignKey("findings.id", ondelete="SET NULL")
    )
    patch_id: Mapped[uuid.UUID | None] = mapped_column(
        UUIDType, ForeignKey("patches.id", ondelete="SET NULL")
    )
    serial: Mapped[str] = mapped_column(String(60), nullable=False, default="")
    assurance_level: Mapped[str] = mapped_column(
        String(2), nullable=False, default=AssuranceLevel.R.value
    )
    grading_rationale: Mapped[list[Any]] = mapped_column(JSONType, nullable=False, default=list)
    limitations: Mapped[list[Any]] = mapped_column(JSONType, nullable=False, default=list)
    document: Mapped[dict[str, Any]] = mapped_column(JSONType, nullable=False, default=dict)
    #: sha256 over the canonical JSON of ``document``.
    certificate_hash: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    #: HMAC-SHA256 of ``certificate_hash`` under the deployment signing key.
    signature: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    signature_algorithm: Mapped[str] = mapped_column(
        String(40), nullable=False, default="HMAC-SHA256"
    )
    evidence_node_count: Mapped[int] = mapped_column(nullable=False, default=0)
    evidence_edge_count: Mapped[int] = mapped_column(nullable=False, default=0)
    generation_ms: Mapped[int] = mapped_column(nullable=False, default=0)
    issued_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
