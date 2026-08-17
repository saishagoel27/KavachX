"""Runs, the persisted event log, orchestrator checkpoints, world models and artifacts."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, JSONType, TimestampMixin, UUIDPrimaryKeyMixin, UUIDType
from app.models.enums import AnalysisProfile, ExecutionProfile, Phase, RunStatus

if TYPE_CHECKING:
    from app.models.project import Project


class Run(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "runs"
    __table_args__ = (
        Index("ix_runs_tenant_created", "tenant_id", "created_at"),
        Index("ix_runs_status", "status"),
    )

    tenant_id: Mapped[uuid.UUID] = mapped_column(UUIDType, nullable=False, index=True)
    project_id: Mapped[uuid.UUID] = mapped_column(
        UUIDType, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False
    )
    repository_id: Mapped[uuid.UUID] = mapped_column(
        UUIDType, ForeignKey("repositories.id", ondelete="CASCADE"), nullable=False
    )
    #: Short human-facing handle shown in the console header, e.g. ``7F3A``.
    short_code: Mapped[str] = mapped_column(String(8), nullable=False, index=True)

    branch: Mapped[str] = mapped_column(String(300), nullable=False, default="main")
    commit_sha: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    #: Content hash of the pinned immutable source artifact handed to the sandbox.
    pinned_source_sha256: Mapped[str] = mapped_column(String(64), nullable=False, default="")

    analysis_profile: Mapped[str] = mapped_column(
        String(32), nullable=False, default=AnalysisProfile.STANDARD.value
    )
    execution_profile: Mapped[str] = mapped_column(
        String(32), nullable=False, default=ExecutionProfile.DEV_LOCAL.value
    )
    max_runtime_seconds: Mapped[int] = mapped_column(nullable=False, default=1800)
    resource_budget: Mapped[dict[str, Any]] = mapped_column(JSONType, nullable=False, default=dict)

    # Indexed via the explicit ix_runs_status entry in __table_args__; declaring index=True here
    # too would emit the same index twice and fail on create.
    status: Mapped[str] = mapped_column(String(32), nullable=False, default=RunStatus.QUEUED.value)
    phase: Mapped[str] = mapped_column(String(40), nullable=False, default=Phase.INGEST.value)
    phase_status: Mapped[dict[str, Any]] = mapped_column(JSONType, nullable=False, default=dict)

    #: "full" or "static_only". Persisted rather than left in the checkpoint because it changes how
    #: every downstream number must be read: a static-only run executed nothing, so zero findings
    #: means "nothing was proved", not "nothing is wrong". A reader who loads this run tomorrow needs
    #: that qualifier as much as the operator watching the live stream did.
    mode: Mapped[str] = mapped_column(String(20), nullable=False, default="full")
    #: Why the run degraded, in the operator's words. Empty for a full run.
    static_only_reason: Mapped[str] = mapped_column(Text, nullable=False, default="")

    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    #: Wall clock from run start to the first verified shield deployment.
    time_to_protection_ms: Mapped[int | None] = mapped_column(BigInteger)
    #: Wall clock from run start to the first gauntlet-verified patch.
    time_to_repair_ms: Mapped[int | None] = mapped_column(BigInteger)

    # live resource meter -------------------------------------------------
    tokens_used: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    model_calls: Mapped[int] = mapped_column(nullable=False, default=0)
    sandbox_executions: Mapped[int] = mapped_column(nullable=False, default=0)
    coverage_percent: Mapped[float] = mapped_column(nullable=False, default=0.0)
    peak_ram_mb: Mapped[int] = mapped_column(nullable=False, default=0)
    cpu_seconds: Mapped[float] = mapped_column(nullable=False, default=0.0)
    egress_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)

    iteration_counters: Mapped[dict[str, Any]] = mapped_column(
        JSONType, nullable=False, default=dict
    )
    error_code: Mapped[str] = mapped_column(String(80), nullable=False, default="")
    error_message: Mapped[str] = mapped_column(Text, nullable=False, default="")

    requested_by: Mapped[uuid.UUID | None] = mapped_column(
        UUIDType, ForeignKey("users.id", ondelete="SET NULL")
    )
    abort_requested: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    aborted_by: Mapped[uuid.UUID | None] = mapped_column(
        UUIDType, ForeignKey("users.id", ondelete="SET NULL")
    )
    publish_approved_by: Mapped[uuid.UUID | None] = mapped_column(
        UUIDType, ForeignKey("users.id", ondelete="SET NULL")
    )
    publish_approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    workspace_path: Mapped[str] = mapped_column(String(1000), nullable=False, default="")

    project: Mapped[Project] = relationship(back_populates="runs")


class RunEvent(Base, TimestampMixin):
    """Append-only structured event log.

    Persisted so a reconnecting SSE client can replay from ``Last-Event-ID`` and a page
    refresh loses nothing. ``seq`` is per-run and monotonic.
    """

    __tablename__ = "run_events"
    __table_args__ = (
        UniqueConstraint("run_id", "seq", name="uq_run_event_seq"),
        Index("ix_run_events_run_seq", "run_id", "seq"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUIDType, primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUIDType, nullable=False, index=True)
    run_id: Mapped[uuid.UUID] = mapped_column(
        UUIDType, ForeignKey("runs.id", ondelete="CASCADE"), nullable=False
    )
    seq: Mapped[int] = mapped_column(BigInteger, nullable=False)
    #: Event discriminator matching the frontend ``RunEvent["t"]`` union.
    t: Mapped[str] = mapped_column(String(32), nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JSONType, nullable=False, default=dict)


class RunCheckpoint(Base, TimestampMixin):
    """LangGraph state snapshot written after every node."""

    __tablename__ = "run_checkpoints"
    __table_args__ = (
        UniqueConstraint("run_id", "seq", name="uq_run_checkpoint_seq"),
        Index("ix_run_checkpoints_run", "run_id", "seq"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUIDType, primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUIDType, nullable=False, index=True)
    run_id: Mapped[uuid.UUID] = mapped_column(
        UUIDType, ForeignKey("runs.id", ondelete="CASCADE"), nullable=False
    )
    seq: Mapped[int] = mapped_column(nullable=False)
    node: Mapped[str] = mapped_column(String(64), nullable=False)
    state_json: Mapped[dict[str, Any]] = mapped_column(JSONType, nullable=False, default=dict)
    state_hash: Mapped[str] = mapped_column(String(64), nullable=False, default="")


class WorldModel(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """Structured repository model. The LLM receives *handles*, never the whole tree."""

    __tablename__ = "world_models"

    tenant_id: Mapped[uuid.UUID] = mapped_column(UUIDType, nullable=False, index=True)
    run_id: Mapped[uuid.UUID] = mapped_column(
        UUIDType, ForeignKey("runs.id", ondelete="CASCADE"), nullable=False, index=True
    )
    commit_sha: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    file_count: Mapped[int] = mapped_column(nullable=False, default=0)
    function_count: Mapped[int] = mapped_column(nullable=False, default=0)
    entrypoint_count: Mapped[int] = mapped_column(nullable=False, default=0)
    sink_count: Mapped[int] = mapped_column(nullable=False, default=0)
    indexer: Mapped[str] = mapped_column(String(64), nullable=False, default="tree-sitter")
    graph_json: Mapped[dict[str, Any]] = mapped_column(JSONType, nullable=False, default=dict)


class Artifact(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "artifacts"
    __table_args__ = (Index("ix_artifacts_run_kind", "run_id", "kind"),)

    tenant_id: Mapped[uuid.UUID] = mapped_column(UUIDType, nullable=False, index=True)
    run_id: Mapped[uuid.UUID] = mapped_column(
        UUIDType, ForeignKey("runs.id", ondelete="CASCADE"), nullable=False
    )
    kind: Mapped[str] = mapped_column(String(40), nullable=False)
    name: Mapped[str] = mapped_column(String(300), nullable=False)
    media_type: Mapped[str] = mapped_column(String(120), nullable=False, default="text/plain")
    content: Mapped[str] = mapped_column(Text, nullable=False, default="")
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    size_bytes: Mapped[int] = mapped_column(nullable=False, default=0)
    url: Mapped[str] = mapped_column(String(1000), nullable=False, default="")
    meta_json: Mapped[dict[str, Any]] = mapped_column(JSONType, nullable=False, default=dict)
