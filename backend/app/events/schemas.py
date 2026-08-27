"""Structured run events.

These mirror the frontend ``RunEvent`` discriminated union exactly. The backend emits
*structured state transitions* — never raw model tokens, and never hidden chain-of-thought.
A ``thought`` event carries only an application-authored summary plus evidence handles.
"""

from __future__ import annotations

from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class _Event(BaseModel):
    model_config = ConfigDict(extra="forbid")


class PhaseEvent(_Event):
    t: Literal["phase"] = "phase"
    phase: str
    status: Literal["start", "done", "failed", "blocked"]
    detail: str = ""


class ThoughtEvent(_Event):
    """A structured reasoning summary.

    ``hypothesis``/``decision`` are short application-composed statements, and ``evidence``
    holds evidence refs or ``file:line`` handles the UI can resolve. There is intentionally
    no field for free-form model deliberation.
    """

    t: Literal["thought"] = "thought"
    agent: str
    hypothesis: str
    evidence: list[str] = Field(default_factory=list)
    decision: str
    confidence: float = Field(ge=0.0, le=1.0)


class ToolEvent(_Event):
    t: Literal["tool"] = "tool"
    name: str
    target: str
    ms: int
    ok: bool
    detail: str = ""


class FindingEvent(_Event):
    t: Literal["finding"] = "finding"
    id: str
    state: Literal["hypothesis", "validated", "refuted"]
    clause: str | None = None
    severity: str
    reachable: bool
    title: str = ""


class DiffEvent(_Event):
    t: Literal["diff"] = "diff"
    finding: str
    file: str
    patch: str
    iter: int
    patch_id: str = ""


class GauntletEvent(_Event):
    t: Literal["gauntlet"] = "gauntlet"
    finding: str
    stage: str
    verdict: Literal["pass", "fail", "running"]
    detail: str
    iter: int = 1


class MetricEvent(_Event):
    t: Literal["metric"] = "metric"
    tokens: int
    coverage: float
    ram_mb: int
    egress: int = 0
    model_calls: int = 0
    sandbox_executions: int = 0
    cpu_seconds: float = 0.0
    elapsed_ms: int = 0


class ArtifactEvent(_Event):
    t: Literal["artifact"] = "artifact"
    kind: str
    url: str
    name: str = ""
    hash: str = ""


class ClauseEvent(_Event):
    """SAMHITA lifecycle. Surfaced in the contract panel."""

    t: Literal["clause"] = "clause"
    clause_id: str
    status: str
    description: str
    scope: str = ""
    kind: str = ""


class ShieldEvent(_Event):
    t: Literal["shield"] = "shield"
    finding: str
    shield_id: str
    mechanism: str
    verified_blocked: bool
    verified_benign: bool
    deployed: bool
    rule: str = ""


class CertificateEvent(_Event):
    t: Literal["certificate"] = "certificate"
    finding: str
    level: str
    certificate_hash: str
    certificate_id: str


class StatusEvent(_Event):
    t: Literal["status"] = "status"
    status: str
    detail: str = ""


class LogEvent(_Event):
    """Terminal-style operational line for the evidence console."""

    t: Literal["log"] = "log"
    stream: Literal["stdout", "stderr", "system"] = "system"
    line: str
    source: str = ""



class IndexEvent(_Event):
    """Index health, as the console's INDEX HEALTH panel renders it.

    Carries counts rather than a rendered string so the UI can lay it out and a client can compare
    two runs numerically.
    """

    t: Literal["index"] = "index"
    index_id: str
    status: str
    graph_source: str
    files_discovered: int = 0
    files_indexed: int = 0
    files_skipped: int = 0
    symbols: int = 0
    relationships: int = 0
    resolved_relationships: int = 0
    entrypoints: int = 0
    tests: int = 0
    configs: int = 0
    dependencies: int = 0
    health_grade: str = ""
    duration_ms: int = 0


class SecurityFlowEvent(_Event):
    """One evidenced data flow from an external input to a dangerous operation.

    ``basis`` and ``precision`` travel with every flow because they are what qualify it: a
    taint-proven flow and a name-matched call path are not the same claim.
    """

    t: Literal["security_flow"] = "security_flow"
    ref: str
    source_kind: str
    sink_kind: str
    severity: str
    cwe: str = ""
    basis: str = ""
    precision: str = ""
    confidence: float = 0.0
    reachable: bool = False
    sanitized: bool = False
    path: list[str] = Field(default_factory=list)
    boundaries: list[str] = Field(default_factory=list)


class ArchitectureEvent(_Event):
    """The structured application model, summarised for the console."""

    t: Literal["architecture"] = "architecture"
    application_type: str
    languages: dict[str, int] = Field(default_factory=dict)
    frameworks: list[str] = Field(default_factory=list)
    entrypoints: int = 0
    unauthenticated_entrypoints: int = 0
    data_stores: list[str] = Field(default_factory=list)
    authentication: list[str] = Field(default_factory=list)
    trust_boundaries: list[str] = Field(default_factory=list)
    surface_items: int = 0
    externally_controllable: int = 0
    testable: int = 0
    #: False when no entrypoint existed, so the surface is unknown rather than empty.
    measured: bool = True
    gaps: list[str] = Field(default_factory=list)


class TestSpecEvent(_Event):
    """A generated harness. ``proposed_by`` distinguishes model-assisted from deterministic."""

    t: Literal["testspec"] = "testspec"
    plan_id: str
    candidate: str
    strategy: str
    engine: str
    oracle: str
    harness_path: str = ""
    harness_hash: str = ""
    security_property: str = ""
    proposed_by: Literal["model", "deterministic"] = "deterministic"


class TestResultEvent(_Event):
    """The outcome of executing one harness, as the oracle decided it."""

    t: Literal["test_result"] = "test_result"
    plan_id: str
    candidate: str
    strategy: str
    engine: str
    reproduced: bool
    reproduction_count: int = 0
    required: int = 0
    oracle: str = ""
    evidence: str = ""
    coverage_percent: float = 0.0
    error: str = ""


class CoverageEvent(_Event):
    """A coverage-guided campaign's result.

    ``model_candidates_useful`` vs ``model_candidates`` is the honest score for the model's
    contribution: how many of its proposed inputs actually reached new coverage.
    """

    t: Literal["coverage"] = "coverage"
    candidate: str
    percent: float = 0.0
    corpus_size: int = 0
    executions: int = 0
    rounds: int = 0
    new_findings: int = 0
    uncovered_branches: int = 0
    model_candidates: int = 0
    model_candidates_useful: int = 0
    stopped_because: str = ""


RunEventPayload = Annotated[
    PhaseEvent
    | ThoughtEvent
    | ToolEvent
    | IndexEvent
    | SecurityFlowEvent
    | ArchitectureEvent
    | TestSpecEvent
    | TestResultEvent
    | CoverageEvent
    | FindingEvent
    | DiffEvent
    | GauntletEvent
    | MetricEvent
    | ArtifactEvent
    | ClauseEvent
    | ShieldEvent
    | CertificateEvent
    | StatusEvent
    | LogEvent,
    Field(discriminator="t"),
]


class EnvelopedEvent(BaseModel):
    """What an SSE consumer actually receives."""

    seq: int
    run_id: str
    ts: str
    event: dict[str, Any]
