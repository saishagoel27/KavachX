"""Patches, gauntlet runs and gauntlet stage results."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, JSONType, TimestampMixin, UUIDPrimaryKeyMixin, UUIDType
from app.models.enums import PatchStatus, Verdict


class Patch(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "patches"
    __table_args__ = (
        UniqueConstraint("finding_id", "iteration", name="uq_patch_iteration"),
        Index("ix_patches_run_status", "run_id", "status"),
    )

    tenant_id: Mapped[uuid.UUID] = mapped_column(UUIDType, nullable=False, index=True)
    run_id: Mapped[uuid.UUID] = mapped_column(
        UUIDType, ForeignKey("runs.id", ondelete="CASCADE"), nullable=False
    )
    finding_id: Mapped[uuid.UUID] = mapped_column(
        UUIDType, ForeignKey("findings.id", ondelete="CASCADE"), nullable=False
    )
    iteration: Mapped[int] = mapped_column(nullable=False, default=1)
    status: Mapped[str] = mapped_column(
        String(24), nullable=False, default=PatchStatus.PROPOSED.value
    )
    reason: Mapped[str] = mapped_column(Text, nullable=False, default="")
    unified_diff: Mapped[str] = mapped_column(Text, nullable=False, default="")
    files: Mapped[list[Any]] = mapped_column(JSONType, nullable=False, default=list)
    #: ``{path: {"old": ..., "new": ...}}`` — the complete content of every changed file.
    #:
    #: Stored rather than reconstructed from the diff on purpose. The publisher writes whole
    #: files, and rebuilding them from hunks would yield only the changed regions — a truncated
    #: file pushed to a real repository. Storing the content also lets the publish-time policy
    #: gate re-run its AST checks against exactly what was verified.
    file_contents: Mapped[dict[str, Any]] = mapped_column(JSONType, nullable=False, default=dict)
    risk: Mapped[str] = mapped_column(String(400), nullable=False, default="")
    expected_effect: Mapped[str] = mapped_column(Text, nullable=False, default="")
    diff_hash: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    lines_added: Mapped[int] = mapped_column(nullable=False, default=0)
    lines_removed: Mapped[int] = mapped_column(nullable=False, default=0)

    # --- deterministic gates ---------------------------------------------
    applied: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    apply_error: Mapped[str] = mapped_column(Text, nullable=False, default="")
    policy_passed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    policy_violations: Mapped[list[Any]] = mapped_column(JSONType, nullable=False, default=list)
    within_blast_radius: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    blast_radius_json: Mapped[dict[str, Any]] = mapped_column(
        JSONType, nullable=False, default=dict
    )

    #: Constraints derived from earlier refutations. The synthesiser must honour these.
    constraints: Mapped[list[Any]] = mapped_column(JSONType, nullable=False, default=list)
    refutation_summary: Mapped[str] = mapped_column(Text, nullable=False, default="")
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    withdrawn_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    proposed_by_model: Mapped[str] = mapped_column(String(120), nullable=False, default="")
    evidence_refs: Mapped[list[Any]] = mapped_column(JSONType, nullable=False, default=list)


class GauntletRun(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """One full four-stage pass over a single patch iteration."""

    __tablename__ = "gauntlet_runs"
    __table_args__ = (Index("ix_gauntlet_runs_patch", "patch_id"),)

    tenant_id: Mapped[uuid.UUID] = mapped_column(UUIDType, nullable=False, index=True)
    run_id: Mapped[uuid.UUID] = mapped_column(
        UUIDType, ForeignKey("runs.id", ondelete="CASCADE"), nullable=False
    )
    finding_id: Mapped[uuid.UUID] = mapped_column(
        UUIDType, ForeignKey("findings.id", ondelete="CASCADE"), nullable=False
    )
    patch_id: Mapped[uuid.UUID] = mapped_column(
        UUIDType, ForeignKey("patches.id", ondelete="CASCADE"), nullable=False
    )
    iteration: Mapped[int] = mapped_column(nullable=False, default=1)
    verdict: Mapped[str] = mapped_column(String(8), nullable=False, default=Verdict.FAIL.value)
    stages_passed: Mapped[int] = mapped_column(nullable=False, default=0)
    stages_total: Mapped[int] = mapped_column(nullable=False, default=4)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    duration_ms: Mapped[int] = mapped_column(nullable=False, default=0)
    #: First stage that failed, if any — drives the failure UX headline.
    failing_stage: Mapped[str] = mapped_column(String(40), nullable=False, default="")
    summary: Mapped[str] = mapped_column(Text, nullable=False, default="")


class GauntletResult(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """The outcome of one stage. Verdicts come from executed evidence only."""

    __tablename__ = "gauntlet_results"
    __table_args__ = (
        UniqueConstraint("gauntlet_run_id", "stage", name="uq_gauntlet_stage"),
        Index("ix_gauntlet_results_run", "run_id"),
    )

    tenant_id: Mapped[uuid.UUID] = mapped_column(UUIDType, nullable=False, index=True)
    run_id: Mapped[uuid.UUID] = mapped_column(
        UUIDType, ForeignKey("runs.id", ondelete="CASCADE"), nullable=False
    )
    gauntlet_run_id: Mapped[uuid.UUID] = mapped_column(
        UUIDType, ForeignKey("gauntlet_runs.id", ondelete="CASCADE"), nullable=False
    )
    stage: Mapped[str] = mapped_column(String(40), nullable=False)
    verdict: Mapped[str] = mapped_column(String(8), nullable=False, default=Verdict.FAIL.value)
    detail: Mapped[str] = mapped_column(Text, nullable=False, default="")
    #: Concrete refuting evidence: the mutated payload, the diverging replay case, etc.
    refuting_evidence: Mapped[dict[str, Any]] = mapped_column(
        JSONType, nullable=False, default=dict
    )
    metrics: Mapped[dict[str, Any]] = mapped_column(JSONType, nullable=False, default=dict)
    duration_ms: Mapped[int] = mapped_column(nullable=False, default=0)
    cases_total: Mapped[int] = mapped_column(nullable=False, default=0)
    cases_passed: Mapped[int] = mapped_column(nullable=False, default=0)
    evidence_refs: Mapped[list[Any]] = mapped_column(JSONType, nullable=False, default=list)
