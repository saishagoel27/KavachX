"""Persisted code intelligence: the index, its graph, the security model and generated tests.

Added deliberately narrowly. The spec's guidance is to add entities only where appropriate and not
to duplicate what existing models already represent well, so:

* **Not added**: a row per symbol or per relationship. A mid-sized repository has tens of thousands
  of each, they are fully derivable from the pinned tree plus the recorded indexer versions, and
  storing them would multiply the database size for data nobody queries relationally. The graph is
  stored once, as a bounded JSON document, alongside the counts that *are* queried.
* **Not added**: a second findings table. Generated tests attach to the existing
  :class:`~app.models.analysis.Finding` and :class:`~app.models.analysis.Hypothesis` rows.

What is stored is what makes the analysis auditable and reproducible after the run: the index's
identity and health, the graph the reachability claims came from, the security flows, the
architecture model, and every generated test with its harness hash and execution record.
"""

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


class RepositoryIndex(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """One indexing run over one pinned tree.

    ``index_id`` is the reproducible identity: sha256 over the pinned source hash, the indexer and
    parser versions, and the indexing options. It is indexed (not unique) because the same index
    id legitimately recurs across runs of the same commit — that recurrence is the point, and it is
    what a future incremental path will match on to reuse work.
    """

    __tablename__ = "repository_indexes"
    __table_args__ = (
        UniqueConstraint("run_id", name="uq_index_per_run"),
        Index("ix_indexes_index_id", "index_id"),
        Index("ix_indexes_tenant_created", "tenant_id", "created_at"),
    )

    tenant_id: Mapped[uuid.UUID] = mapped_column(UUIDType, nullable=False, index=True)
    run_id: Mapped[uuid.UUID] = mapped_column(
        UUIDType, ForeignKey("runs.id", ondelete="CASCADE"), nullable=False
    )

    index_id: Mapped[str] = mapped_column(String(64), nullable=False)
    commit_sha: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    source_sha256: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    #: Structural digest of the produced graph.
    graph_hash: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    #: Derived from actual provider contribution — never asserted. See app.indexing.merge.
    graph_source: Mapped[str] = mapped_column(String(120), nullable=False, default="none")
    status: Mapped[str] = mapped_column(String(24), nullable=False, default="PENDING")

    #: Indexer, parser, grammar, GitNexus and semgrep versions. Part of the index identity.
    versions: Mapped[dict[str, Any]] = mapped_column(JSONType, nullable=False, default=dict)
    options: Mapped[dict[str, Any]] = mapped_column(JSONType, nullable=False, default=dict)
    providers: Mapped[list[Any]] = mapped_column(JSONType, nullable=False, default=list)

    # -- counters, denormalised because the console and dashboard query them -----
    files_discovered: Mapped[int] = mapped_column(nullable=False, default=0)
    files_indexed: Mapped[int] = mapped_column(nullable=False, default=0)
    files_skipped: Mapped[int] = mapped_column(nullable=False, default=0)
    symbols: Mapped[int] = mapped_column(nullable=False, default=0)
    functions: Mapped[int] = mapped_column(nullable=False, default=0)
    classes: Mapped[int] = mapped_column(nullable=False, default=0)
    relationships: Mapped[int] = mapped_column(nullable=False, default=0)
    call_relationships: Mapped[int] = mapped_column(nullable=False, default=0)
    import_relationships: Mapped[int] = mapped_column(nullable=False, default=0)
    #: Relationships a symbol-resolving provider confirmed, as opposed to name matches. The single
    #: most important qualifier on any reachability claim built from this index.
    resolved_relationships: Mapped[int] = mapped_column(nullable=False, default=0)
    entrypoints: Mapped[int] = mapped_column(nullable=False, default=0)
    tests_discovered: Mapped[int] = mapped_column(nullable=False, default=0)
    configs_discovered: Mapped[int] = mapped_column(nullable=False, default=0)
    dependencies_discovered: Mapped[int] = mapped_column(nullable=False, default=0)

    languages: Mapped[dict[str, Any]] = mapped_column(JSONType, nullable=False, default=dict)
    #: ``[{"path": ..., "reason": ...}]`` — named, not merely counted.
    skipped_files: Mapped[list[Any]] = mapped_column(JSONType, nullable=False, default=list)
    warnings: Mapped[list[Any]] = mapped_column(JSONType, nullable=False, default=list)
    errors: Mapped[list[Any]] = mapped_column(JSONType, nullable=False, default=list)

    # -- health -------------------------------------------------------------
    health_grade: Mapped[str] = mapped_column(String(2), nullable=False, default="F")
    health: Mapped[dict[str, Any]] = mapped_column(JSONType, nullable=False, default=dict)
    #: Claims this index cannot support. Carried into the certificate.
    claim_bounds: Mapped[list[Any]] = mapped_column(JSONType, nullable=False, default=list)

    # -- the graph itself ---------------------------------------------------
    #: The bounded code-graph document (nodes, edges, provenance, stats). One blob rather than
    #: normalised tables — see the module docstring for why.
    graph_json: Mapped[dict[str, Any]] = mapped_column(JSONType, nullable=False, default=dict)
    #: True when the stored graph was truncated against the node cap.
    graph_truncated: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    # -- incremental --------------------------------------------------------
    incremental: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    changed_files: Mapped[list[Any]] = mapped_column(JSONType, nullable=False, default=list)
    affected_symbols: Mapped[list[Any]] = mapped_column(JSONType, nullable=False, default=list)

    duration_ms: Mapped[int] = mapped_column(nullable=False, default=0)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    @property
    def resolved_ratio(self) -> float:
        if not self.relationships:
            return 0.0
        return round(self.resolved_relationships / self.relationships, 4)


class SecurityModelRow(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """The security graph derived over one index."""

    __tablename__ = "security_models"
    __table_args__ = (
        UniqueConstraint("run_id", name="uq_security_model_per_run"),
        Index("ix_security_models_run", "run_id"),
    )

    tenant_id: Mapped[uuid.UUID] = mapped_column(UUIDType, nullable=False, index=True)
    run_id: Mapped[uuid.UUID] = mapped_column(
        UUIDType, ForeignKey("runs.id", ondelete="CASCADE"), nullable=False
    )
    index_id: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False, default="")

    sources: Mapped[int] = mapped_column(nullable=False, default=0)
    sinks: Mapped[int] = mapped_column(nullable=False, default=0)
    sanitizers: Mapped[int] = mapped_column(nullable=False, default=0)
    validators: Mapped[int] = mapped_column(nullable=False, default=0)
    controls: Mapped[int] = mapped_column(nullable=False, default=0)
    flows: Mapped[int] = mapped_column(nullable=False, default=0)
    reachable_flows: Mapped[int] = mapped_column(nullable=False, default=0)
    sanitized_flows: Mapped[int] = mapped_column(nullable=False, default=0)
    trust_boundaries: Mapped[int] = mapped_column(nullable=False, default=0)

    #: Which taxonomy produced these facts, including any operator extension.
    taxonomy: Mapped[dict[str, Any]] = mapped_column(JSONType, nullable=False, default=dict)
    #: Nodes, flows and boundaries. Bounded by the builder's own caps.
    model_json: Mapped[dict[str, Any]] = mapped_column(JSONType, nullable=False, default=dict)
    #: Files the taint analyser could not parse, and why.
    parse_errors: Mapped[list[Any]] = mapped_column(JSONType, nullable=False, default=list)
    warnings: Mapped[list[Any]] = mapped_column(JSONType, nullable=False, default=list)


class ArchitectureModelRow(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """The structured application model and ranked attack surface."""

    __tablename__ = "architecture_models"
    __table_args__ = (
        UniqueConstraint("run_id", name="uq_architecture_per_run"),
        Index("ix_architecture_run", "run_id"),
    )

    tenant_id: Mapped[uuid.UUID] = mapped_column(UUIDType, nullable=False, index=True)
    run_id: Mapped[uuid.UUID] = mapped_column(
        UUIDType, ForeignKey("runs.id", ondelete="CASCADE"), nullable=False
    )
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    application_type: Mapped[str] = mapped_column(String(60), nullable=False, default="unknown")
    languages: Mapped[dict[str, Any]] = mapped_column(JSONType, nullable=False, default=dict)
    frameworks: Mapped[list[Any]] = mapped_column(JSONType, nullable=False, default=list)
    entrypoint_count: Mapped[int] = mapped_column(nullable=False, default=0)
    unauthenticated_entrypoints: Mapped[int] = mapped_column(nullable=False, default=0)
    #: False when no entrypoint existed, so the surface is unknown rather than empty.
    surface_measured: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    surface_items: Mapped[int] = mapped_column(nullable=False, default=0)
    externally_controllable: Mapped[int] = mapped_column(nullable=False, default=0)
    testable_items: Mapped[int] = mapped_column(nullable=False, default=0)

    model_json: Mapped[dict[str, Any]] = mapped_column(JSONType, nullable=False, default=dict)
    attack_surface_json: Mapped[dict[str, Any]] = mapped_column(
        JSONType, nullable=False, default=dict
    )
    #: What the model does not know, and why. Feeds REMAINING.md.
    gaps: Mapped[list[Any]] = mapped_column(JSONType, nullable=False, default=list)


class GeneratedTest(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """One generated test plan: the spec, the chosen engine, and the harness that was produced."""

    __tablename__ = "generated_tests"
    __table_args__ = (
        UniqueConstraint("run_id", "plan_id", name="uq_generated_test_plan"),
        Index("ix_generated_tests_run_status", "run_id", "status"),
    )

    tenant_id: Mapped[uuid.UUID] = mapped_column(UUIDType, nullable=False, index=True)
    run_id: Mapped[uuid.UUID] = mapped_column(
        UUIDType, ForeignKey("runs.id", ondelete="CASCADE"), nullable=False
    )
    finding_id: Mapped[uuid.UUID | None] = mapped_column(
        UUIDType, ForeignKey("findings.id", ondelete="SET NULL")
    )

    #: Reproducible: sha256 over the canonical spec plus the index id.
    plan_id: Mapped[str] = mapped_column(String(64), nullable=False)
    candidate_ref: Mapped[str] = mapped_column(String(400), nullable=False, default="")
    finding_handle: Mapped[str] = mapped_column(String(40), nullable=False, default="")
    status: Mapped[str] = mapped_column(String(24), nullable=False, default="PLANNED")

    strategy: Mapped[str] = mapped_column(String(24), nullable=False, default="")
    oracle_kind: Mapped[str] = mapped_column(String(48), nullable=False, default="")
    engine: Mapped[str] = mapped_column(String(48), nullable=False, default="")
    engine_available: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    engine_reason: Mapped[str] = mapped_column(Text, nullable=False, default="")
    language: Mapped[str] = mapped_column(String(24), nullable=False, default="")

    #: Whether the spec came from a model proposal or the deterministic fallback. Recorded because
    #: "the model wrote this test" and "KavachX derived this test" are different provenance.
    proposed_by: Mapped[str] = mapped_column(String(24), nullable=False, default="deterministic")

    harness_path: Mapped[str] = mapped_column(String(400), nullable=False, default="")
    harness_sha256: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    #: The argv the sandbox ran. Built by KavachX, never model-supplied.
    command: Mapped[list[Any]] = mapped_column(JSONType, nullable=False, default=list)
    security_property: Mapped[str] = mapped_column(Text, nullable=False, default="")

    spec_json: Mapped[dict[str, Any]] = mapped_column(JSONType, nullable=False, default=dict)
    provenance: Mapped[dict[str, Any]] = mapped_column(JSONType, nullable=False, default=dict)
    notes: Mapped[list[Any]] = mapped_column(JSONType, nullable=False, default=list)


class TestExecutionRow(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """The reproducible record of executing one generated test."""

    __tablename__ = "test_executions"
    __table_args__ = (Index("ix_test_executions_run_plan", "run_id", "plan_id"),)

    tenant_id: Mapped[uuid.UUID] = mapped_column(UUIDType, nullable=False, index=True)
    run_id: Mapped[uuid.UUID] = mapped_column(
        UUIDType, ForeignKey("runs.id", ondelete="CASCADE"), nullable=False
    )
    plan_id: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    candidate_ref: Mapped[str] = mapped_column(String(400), nullable=False, default="")
    finding_handle: Mapped[str] = mapped_column(String(40), nullable=False, default="")

    strategy: Mapped[str] = mapped_column(String(24), nullable=False, default="")
    engine: Mapped[str] = mapped_column(String(48), nullable=False, default="")
    harness_path: Mapped[str] = mapped_column(String(400), nullable=False, default="")
    harness_sha256: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    command: Mapped[list[Any]] = mapped_column(JSONType, nullable=False, default=list)
    commit_sha: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    index_id: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    input_hash: Mapped[str] = mapped_column(String(64), nullable=False, default="")

    #: Adapter, isolation model and the honest capability flags at execution time. A reproduction
    #: under the dev adapter and one under gVisor are not equally strong evidence.
    environment: Mapped[dict[str, Any]] = mapped_column(JSONType, nullable=False, default=dict)

    reproduced: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    reproduction_count: Mapped[int] = mapped_column(nullable=False, default=0)
    reproductions_required: Mapped[int] = mapped_column(nullable=False, default=0)
    verdict_detail: Mapped[str] = mapped_column(Text, nullable=False, default="")
    #: The observable that decided it, quoted.
    proving_evidence: Mapped[str] = mapped_column(Text, nullable=False, default="")

    #: Per-attempt exit codes, signals and output hashes.
    attempts: Mapped[list[Any]] = mapped_column(JSONType, nullable=False, default=list)
    coverage: Mapped[dict[str, Any]] = mapped_column(JSONType, nullable=False, default=dict)
    #: Populated for a coverage-guided campaign rather than a single execution.
    campaign: Mapped[dict[str, Any]] = mapped_column(JSONType, nullable=False, default=dict)
    error: Mapped[str] = mapped_column(Text, nullable=False, default="")
    duration_ms: Mapped[int] = mapped_column(nullable=False, default=0)


class ModelContextRow(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """Exactly what context a model received for one candidate.

    Stored so a hallucination can be debugged by looking at what the model was actually told, which
    is the first question and usually the answer. Deliberately stores the *selection and hashes*
    rather than the raw prompt: the code slices are recoverable from the pinned tree plus the
    recorded line ranges, and copying target source into a second place adds risk without adding
    information.
    """

    __tablename__ = "model_contexts"
    __table_args__ = (Index("ix_model_contexts_run_candidate", "run_id", "candidate_ref"),)

    tenant_id: Mapped[uuid.UUID] = mapped_column(UUIDType, nullable=False, index=True)
    run_id: Mapped[uuid.UUID] = mapped_column(
        UUIDType, ForeignKey("runs.id", ondelete="CASCADE"), nullable=False
    )
    candidate_ref: Mapped[str] = mapped_column(String(400), nullable=False, default="")
    task: Mapped[str] = mapped_column(String(60), nullable=False, default="")
    context_hash: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    context_version: Mapped[str] = mapped_column(String(60), nullable=False, default="")
    provider: Mapped[str] = mapped_column(String(40), nullable=False, default="")
    model: Mapped[str] = mapped_column(String(120), nullable=False, default="")
    size_chars: Mapped[int] = mapped_column(nullable=False, default=0)

    selected_files: Mapped[list[Any]] = mapped_column(JSONType, nullable=False, default=list)
    selected_functions: Mapped[list[Any]] = mapped_column(JSONType, nullable=False, default=list)
    code_slice_keys: Mapped[list[Any]] = mapped_column(JSONType, nullable=False, default=list)
    #: Every read-only graph query made while assembling the context.
    tool_calls: Mapped[list[Any]] = mapped_column(JSONType, nullable=False, default=list)
    budget: Mapped[dict[str, Any]] = mapped_column(JSONType, nullable=False, default=dict)
    used: Mapped[dict[str, Any]] = mapped_column(JSONType, nullable=False, default=dict)
    #: What did not fit. Never silent — a model reasoning over an elided path must be visible.
    dropped: Mapped[list[Any]] = mapped_column(JSONType, nullable=False, default=list)
