"""Orchestrator state and run context.

Two objects, deliberately separated:

* :class:`KavachState` — a plain, JSON-serialisable TypedDict. This is what LangGraph passes
  between nodes and what gets checkpointed after every node. Because it holds only data, a
  checkpoint is a complete, inspectable record of what the run believed at that moment.
* :class:`RunContext` — the live resources (sandbox adapter, model provider, world model, event
  emitter). These cannot be serialised and must not be: a checkpoint that carried a live sandbox
  handle would be a checkpoint you cannot resume.

Iteration ceilings live in the state and are enforced by the nodes, so there is no path to an
unbounded autonomous loop: ``harness <= 3``, ``patch <= 3``, ``clause <= 2``.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, TypedDict

from app.analysis.probe import TargetDescriptor
from app.analysis.world_model import WorldModel
from app.config import settings
from app.core.hashing import sha256_json
from app.events.emitter import RunEmitter
from app.llm.base import LLMProvider, TokenBudget
from app.samhita.engine import SamhitaResult
from app.sandbox.base import SandboxAdapter
from app.sandbox.workspace import PinnedSource


class KavachState(TypedDict, total=False):
    run_id: str
    tenant_id: str
    phase: str
    status: str
    target: dict[str, Any]
    world: dict[str, Any]
    samhita: list[dict[str, Any]]
    benign_corpus_ref: str
    hypotheses: list[dict[str, Any]]
    validated: list[dict[str, Any]]
    downgraded: list[dict[str, Any]]
    attack_graph: dict[str, Any]
    priority: list[str]
    shields: list[dict[str, Any]]
    patches: list[dict[str, Any]]
    gauntlet: dict[str, Any]
    pramaan: dict[str, Any]
    certificates: list[dict[str, Any]]
    ledger: list[dict[str, Any]]
    budget: dict[str, Any]
    iter: dict[str, int]
    errors: list[dict[str, Any]]
    #: "full" or "static_only".
    mode: str
    static_only_reason: str
    #: Terminal flag so the graph can end without a node raising.
    aborted: bool


def initial_state(*, run_id: uuid.UUID, tenant_id: uuid.UUID) -> KavachState:
    return KavachState(
        run_id=str(run_id),
        tenant_id=str(tenant_id),
        phase="ingest",
        status="RUNNING",
        target={},
        world={},
        samhita=[],
        benign_corpus_ref="",
        hypotheses=[],
        validated=[],
        downgraded=[],
        attack_graph={},
        priority=[],
        shields=[],
        patches=[],
        gauntlet={},
        pramaan={},
        certificates=[],
        ledger=[],
        budget={
            "token_limit": settings.llm_run_token_budget,
            "tokens_used": 0,
            "model_calls": 0,
            "sandbox_executions": 0,
            "wall_clock_limit_seconds": settings.run_max_runtime_seconds,
        },
        iter={
            "harness": 0,
            "patch": 0,
            "clause": 0,
            "harness_limit": settings.max_harness_iterations,
            "patch_limit": settings.max_patch_iterations,
            "clause_limit": settings.max_clause_iterations,
        },
        errors=[],
        mode="full",
        static_only_reason="",
        aborted=False,
    )


def state_hash(state: KavachState) -> str:
    return sha256_json(state)


@dataclass
class RunContext:
    """Live resources for one run. Never serialised."""

    run_id: uuid.UUID
    tenant_id: uuid.UUID
    project_id: uuid.UUID
    repository_id: uuid.UUID
    short_code: str
    emitter: RunEmitter
    provider: LLMProvider
    budget: TokenBudget
    workspace_root: Path
    execution_profile: str
    analysis_profile: str
    requested_by: uuid.UUID | None = None

    sandbox: SandboxAdapter | None = None
    pinned: PinnedSource | None = None
    world_model: WorldModel | None = None
    descriptor: TargetDescriptor | None = None
    samhita: SamhitaResult | None = None
    benign_cases: list[dict[str, Any]] = field(default_factory=list)
    baseline: dict[str, Any] = field(default_factory=dict)
    channel_results: list[Any] = field(default_factory=list)
    #: finding handle -> live per-finding working data (validation outcome, root cause, etc.)
    findings: dict[str, Any] = field(default_factory=dict)
    started_monotonic: float = 0.0
    checkpoint_seq: int = 0
    abort_requested: bool = False
    #: True when the target cannot be executed or observed (no confirmed entrypoint, or no benign
    #: workload). The dynamic half of the pipeline is skipped and every surface says so, because a
    #: static-only run presented as a full one would be the central dishonesty this system avoids.
    static_only: bool = False
    #: True when the target is executed through the language-agnostic **black-box** harness
    #: (a non-Python request→output CLI, driven via its run command and observed from the outside)
    #: rather than the in-process Python tracer. Findings are still proven by execution; the value
    #: profiles / SAMHITA contract the Python path builds are not available, so those stages degrade.
    blackbox: bool = False
    #: Operator run configuration (root dir, install/build/start commands, target type, env vars,
    #: benign requests), loaded from the run row at index time. Empty for auto-detected runs.
    run_config: dict[str, Any] = field(default_factory=dict)
    #: For a black-box run: "cli" (request→output) or "http" (long-running server).
    blackbox_kind: str = "cli"
    #: CLI argv template with a ``{payload}`` placeholder, or the server start argv for http.
    blackbox_argv: list[str] = field(default_factory=list)
    #: Working directory (root_directory) the target runs from, workspace-relative.
    blackbox_cwd: str = "."
    #: Target environment variables injected when the target runs (operator-supplied).
    blackbox_env: dict[str, str] = field(default_factory=dict)
    #: HTTP request specs ({method, path}) for the http black-box benign workload.
    http_requests: list[dict[str, Any]] = field(default_factory=list)
    #: The port an http target listens on inside the sandbox (framework default or operator override).
    #: Used to publish the container port when the server runs under gVisor.
    blackbox_port: int = 0
    #: Aggregate metrics mirrored onto the Run row and the metric event stream.
    metrics: dict[str, Any] = field(
        default_factory=lambda: {
            "tokens": 0,
            "model_calls": 0,
            "sandbox_executions": 0,
            "coverage": 0.0,
            "peak_ram_mb": 0,
            "cpu_seconds": 0.0,
            "egress_bytes": 0,
        }
    )

    def elapsed_ms(self) -> int:
        return self.emitter.elapsed_ms

    def refresh_metrics(self) -> dict[str, Any]:
        self.metrics["tokens"] = self.budget.used
        self.metrics["model_calls"] = self.budget.calls
        if self.sandbox is not None:
            stats = self.sandbox.stats()
            self.metrics["sandbox_executions"] = stats["executions"]
            self.metrics["peak_ram_mb"] = stats["peak_ram_mb"]
            self.metrics["cpu_seconds"] = stats["cpu_seconds"]
            self.metrics["egress_bytes"] = stats["egress_bytes"]
        if self.samhita is not None:
            self.metrics["coverage"] = self.samhita.coverage_percent
        return self.metrics

    def provider_info(self) -> dict[str, Any]:
        return {
            "provider": self.provider.name,
            "models": settings.llm_models,
            "configured_provider": settings.llm_provider,
            "fell_back_to_mock": self.provider.name == "mock" and settings.llm_provider != "mock",
            "calls": self.budget.calls,
            "tokens": self.budget.used,
            "token_limit": self.budget.limit,
            "per_task_tokens": dict(self.budget.per_task),
            "note": (
                "The model proposes; deterministic components validate; the state machine "
                "decides. No verdict in this run was set by a model."
            ),
        }

    def sandbox_stats(self) -> dict[str, Any]:
        return self.sandbox.stats() if self.sandbox is not None else {}


@dataclass(slots=True)
class FindingWork:
    """Per-finding working set carried between repair nodes."""

    handle: str
    hypothesis_handle: str
    finding_id: uuid.UUID | None = None
    outcome: Any = None
    root_cause: Any = None
    blast: Any = None
    shield: Any = None
    patches: list[Any] = field(default_factory=list)
    gauntlets: list[Any] = field(default_factory=list)
    constraints: list[str] = field(default_factory=list)
    certificate: Any = None
    assurance: Any = None
    coverage_before: float = 0.0
    coverage_after: float = 0.0
    verified_patch: Any = None
    verified_synthesis: Any = None
    iteration: int = 0
    exploit_eliminated: bool = False
    channels: list[str] = field(default_factory=list)
    clause: dict[str, Any] | None = None
    plan: dict[str, Any] = field(default_factory=dict)
    #: Set when no repair could be synthesised at all — feeds the Level R certificate and
    #: REMAINING.md, and is distinct from "a patch was tried and refuted".
    repair_blocked_reason: str = ""


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
