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


RunEventPayload = Annotated[
    PhaseEvent
    | ThoughtEvent
    | ToolEvent
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
