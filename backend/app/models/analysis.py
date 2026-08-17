"""SAMHITA clauses, the hypothesis queue, findings and shields."""

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
from app.models.enums import ClauseStatus, FindingState, HypothesisStatus, Severity


class SamhitaClause(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """One clause of the executable behavioural contract.

    A clause only reaches ``SURVIVING`` after its compiled predicate has been evaluated
    against held-out observations that the proposer never saw. Anything that fails there is
    ``FALSIFIED`` and can never be used as evidence.
    """

    __tablename__ = "samhita_clauses"
    __table_args__ = (
        UniqueConstraint("run_id", "clause_id", name="uq_clause_id_per_run"),
        Index("ix_clauses_run_status", "run_id", "status"),
    )

    tenant_id: Mapped[uuid.UUID] = mapped_column(UUIDType, nullable=False, index=True)
    run_id: Mapped[uuid.UUID] = mapped_column(
        UUIDType, ForeignKey("runs.id", ondelete="CASCADE"), nullable=False
    )
    clause_id: Mapped[str] = mapped_column(String(40), nullable=False)
    kind: Mapped[str] = mapped_column(String(60), nullable=False)
    description: Mapped[str] = mapped_column(String(800), nullable=False)
    #: Source form of the predicate, e.g. ``len(input) <= 64``.
    predicate: Mapped[str] = mapped_column(Text, nullable=False)
    #: Where the clause applies: ``module:function`` or ``module:*``.
    scope: Mapped[str] = mapped_column(String(300), nullable=False)
    observation_count: Mapped[int] = mapped_column(nullable=False, default=0)
    status: Mapped[str] = mapped_column(
        String(24), nullable=False, default=ClauseStatus.PROPOSED.value
    )
    evidence_refs: Mapped[list[Any]] = mapped_column(JSONType, nullable=False, default=list)
    #: Populated when the clause is FALSIFIED or UNCOMPILABLE.
    falsification_reason: Mapped[str] = mapped_column(Text, nullable=False, default="")
    counterexample: Mapped[dict[str, Any]] = mapped_column(JSONType, nullable=False, default=dict)
    holdout_pass_count: Mapped[int] = mapped_column(nullable=False, default=0)
    holdout_fail_count: Mapped[int] = mapped_column(nullable=False, default=0)
    proposed_by: Mapped[str] = mapped_column(String(80), nullable=False, default="llm")
    compiled_source: Mapped[str] = mapped_column(Text, nullable=False, default="")


class Hypothesis(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """A candidate weakness pushed by any discovery channel.

    Priority is ``reachability × confidence × blast_radius`` — persisted so the queue
    ordering is reproducible and auditable, not recomputed on the fly.
    """

    __tablename__ = "hypotheses"
    __table_args__ = (
        UniqueConstraint("run_id", "handle", name="uq_hypothesis_handle"),
        Index("ix_hypotheses_run_priority", "run_id", "priority"),
        Index("ix_hypotheses_run_status", "run_id", "status"),
    )

    tenant_id: Mapped[uuid.UUID] = mapped_column(UUIDType, nullable=False, index=True)
    run_id: Mapped[uuid.UUID] = mapped_column(
        UUIDType, ForeignKey("runs.id", ondelete="CASCADE"), nullable=False
    )
    handle: Mapped[str] = mapped_column(String(40), nullable=False)
    source_channel: Mapped[str] = mapped_column(String(40), nullable=False)
    description: Mapped[str] = mapped_column(String(1000), nullable=False)
    location: Mapped[str] = mapped_column(String(400), nullable=False, default="")
    severity: Mapped[str] = mapped_column(String(16), nullable=False, default=Severity.MEDIUM.value)
    reachability: Mapped[float] = mapped_column(nullable=False, default=0.0)
    confidence: Mapped[float] = mapped_column(nullable=False, default=0.0)
    blast_radius: Mapped[float] = mapped_column(nullable=False, default=0.0)
    priority: Mapped[float] = mapped_column(nullable=False, default=0.0, index=True)
    evidence_refs: Mapped[list[Any]] = mapped_column(JSONType, nullable=False, default=list)
    status: Mapped[str] = mapped_column(
        String(24), nullable=False, default=HypothesisStatus.QUEUED.value
    )
    #: Every state change is appended here — nothing silently disappears.
    transitions: Mapped[list[Any]] = mapped_column(JSONType, nullable=False, default=list)
    #: Candidate clause this hypothesis claims to violate (verified later).
    candidate_clause_id: Mapped[str] = mapped_column(String(40), nullable=False, default="")
    #: Machine-readable recipe the validator turns into a sandbox job.
    validation_plan: Mapped[dict[str, Any]] = mapped_column(JSONType, nullable=False, default=dict)
    #: Why it could not be validated — feeds REMAINING.md.
    unknown_reason: Mapped[str] = mapped_column(Text, nullable=False, default="")
    cwe: Mapped[str] = mapped_column(String(32), nullable=False, default="")


class Finding(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """A hypothesis that reached a terminal, deterministically-decided state."""

    __tablename__ = "findings"
    __table_args__ = (
        UniqueConstraint("run_id", "handle", name="uq_finding_handle"),
        Index("ix_findings_run_state", "run_id", "state"),
    )

    tenant_id: Mapped[uuid.UUID] = mapped_column(UUIDType, nullable=False, index=True)
    run_id: Mapped[uuid.UUID] = mapped_column(
        UUIDType, ForeignKey("runs.id", ondelete="CASCADE"), nullable=False
    )
    hypothesis_id: Mapped[uuid.UUID | None] = mapped_column(
        UUIDType, ForeignKey("hypotheses.id", ondelete="SET NULL")
    )
    #: Stable public handle, e.g. ``V17``.
    handle: Mapped[str] = mapped_column(String(40), nullable=False)
    title: Mapped[str] = mapped_column(String(400), nullable=False)
    state: Mapped[str] = mapped_column(
        String(24), nullable=False, default=FindingState.HYPOTHESIS.value
    )
    severity: Mapped[str] = mapped_column(String(16), nullable=False, default=Severity.MEDIUM.value)
    cwe: Mapped[str] = mapped_column(String(32), nullable=False, default="")
    source_channel: Mapped[str] = mapped_column(String(40), nullable=False, default="")
    violated_clause_id: Mapped[str] = mapped_column(String(40), nullable=False, default="")
    location: Mapped[str] = mapped_column(String(400), nullable=False, default="")
    reachable: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    reachability_score: Mapped[float] = mapped_column(nullable=False, default=0.0)

    # --- deterministic reproduction record -------------------------------
    reproduced: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    reproduction_count: Mapped[int] = mapped_column(nullable=False, default=0)
    exit_code: Mapped[int | None] = mapped_column()
    sanitizer_signal: Mapped[str] = mapped_column(String(200), nullable=False, default="")
    contract_violation: Mapped[str] = mapped_column(String(400), nullable=False, default="")
    input_hash: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    output_hash: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    trace_hash: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    coverage_percent: Mapped[float] = mapped_column(nullable=False, default=0.0)

    #: The working exploit. Access requires ``finding:read_pov`` and is always audited.
    pov_payload: Mapped[str] = mapped_column(Text, nullable=False, default="")
    pov_kind: Mapped[str] = mapped_column(String(60), nullable=False, default="")
    pov_hash: Mapped[str] = mapped_column(String(64), nullable=False, default="")

    # --- root cause -------------------------------------------------------
    root_cause_location: Mapped[str] = mapped_column(String(400), nullable=False, default="")
    root_cause_summary: Mapped[str] = mapped_column(Text, nullable=False, default="")
    root_cause_verified: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    root_cause_chain: Mapped[list[Any]] = mapped_column(JSONType, nullable=False, default=list)

    blast_radius_json: Mapped[dict[str, Any]] = mapped_column(
        JSONType, nullable=False, default=dict
    )
    evidence_refs: Mapped[list[Any]] = mapped_column(JSONType, nullable=False, default=list)
    validated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    #: Final per-finding disposition surfaced in the findings table.
    status_label: Mapped[str] = mapped_column(String(60), nullable=False, default="OPEN")


class Shield(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """A reversible mitigation deployed before the real repair exists."""

    __tablename__ = "shields"
    __table_args__ = (Index("ix_shields_run", "run_id"),)

    tenant_id: Mapped[uuid.UUID] = mapped_column(UUIDType, nullable=False, index=True)
    run_id: Mapped[uuid.UUID] = mapped_column(
        UUIDType, ForeignKey("runs.id", ondelete="CASCADE"), nullable=False
    )
    finding_id: Mapped[uuid.UUID] = mapped_column(
        UUIDType, ForeignKey("findings.id", ondelete="CASCADE"), nullable=False
    )
    handle: Mapped[str] = mapped_column(String(40), nullable=False, default="")
    mechanism: Mapped[str] = mapped_column(String(60), nullable=False, default="input_filter")
    rule: Mapped[str] = mapped_column(Text, nullable=False, default="")
    rule_json: Mapped[dict[str, Any]] = mapped_column(JSONType, nullable=False, default=dict)
    deploy_command: Mapped[str] = mapped_column(Text, nullable=False, default="")
    revert_command: Mapped[str] = mapped_column(Text, nullable=False, default="")
    verified_blocked: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    verified_benign: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    benign_pass_count: Mapped[int] = mapped_column(nullable=False, default=0)
    benign_total: Mapped[int] = mapped_column(nullable=False, default=0)
    deployed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    reverted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    evidence_refs: Mapped[list[Any]] = mapped_column(JSONType, nullable=False, default=list)

    @property
    def active(self) -> bool:
        return self.deployed_at is not None and self.reverted_at is None
