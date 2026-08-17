"""SAMHITA engine.

::

    Benign Workload → Observation → Value Profiles → LLM Clause Proposal
        → Strict JSON Schema → Deterministic Clause Compiler
        → Held-out Trace Falsification → Surviving Clauses → SAMHITA

The engine owns the split and the iteration ceiling. Everything decision-bearing here is
deterministic: the model only ever supplies candidate predicate *strings*.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.analysis.probe import TargetDescriptor
from app.config import settings
from app.core.hashing import sha256_json
from app.core.logging import get_logger
from app.llm.base import LLMProvider, LLMRequest, LLMTask
from app.llm.contracts import ClauseProposal
from app.models.enums import ClauseStatus
from app.samhita.falsifier import falsify_proposal, summarise
from app.samhita.observation import (
    ObservationRecord,
    ObservationSet,
    ValueProfile,
    build_observe_spec,
    derive_value_profiles,
    load_benign_corpus,
    parse_observations,
    profiles_payload,
    split_cases,
    widen_profiles,
)
from app.sandbox.base import ExecRequest, SandboxAdapter

logger = get_logger(__name__)

OBSERVE_SPEC_NAME = "_kavachx/out/observe-spec.json"
OBSERVE_OUT_NAME = "_kavachx/out/observations.json"

CLAUSE_INSTRUCTION = (
    "You are proposing clauses for SAMHITA, an executable behavioural contract for the "
    "target under analysis.\n"
    "You are given aggregate VALUE PROFILES observed while running a benign workload. Each "
    "profile names a scope, a metric, the kind of metric, and the range or set of values seen.\n"
    "Propose clauses that a correct implementation should always satisfy.\n"
    "Each predicate must be a single boolean Python expression over metric names only — no "
    "function calls, no attribute access, no subscripts. Example: `arg_len_raw <= 64`.\n"
    "Your clauses will be tested against held-out observations you have not seen. A clause "
    "that is too tight will be discarded, so prefer bounds that plausibly generalise."
)


@dataclass(slots=True)
class ClauseRecord:
    clause_id: str
    kind: str
    description: str
    predicate: str
    scope: str
    status: str
    observation_count: int = 0
    holdout_pass_count: int = 0
    holdout_fail_count: int = 0
    falsification_reason: str = ""
    counterexample: dict[str, Any] = field(default_factory=dict)
    evidence_refs: list[str] = field(default_factory=list)
    proposed_by: str = "llm"
    iteration: int = 1
    compiled_source: str = ""
    confidence: float = 0.5

    def as_dict(self) -> dict[str, Any]:
        return {
            "clause_id": self.clause_id,
            "kind": self.kind,
            "description": self.description,
            "predicate": self.predicate,
            "scope": self.scope,
            "status": self.status,
            "observation_count": self.observation_count,
            "holdout_pass_count": self.holdout_pass_count,
            "holdout_fail_count": self.holdout_fail_count,
            "falsification_reason": self.falsification_reason,
            "counterexample": self.counterexample,
            "evidence_refs": self.evidence_refs,
            "proposed_by": self.proposed_by,
            "iteration": self.iteration,
            "confidence": self.confidence,
        }


@dataclass
class SamhitaResult:
    clauses: list[ClauseRecord] = field(default_factory=list)
    observation_set: ObservationSet | None = None
    holdout_set: ObservationSet | None = None
    profiles: list[ValueProfile] = field(default_factory=list)
    observation_cases: list[str] = field(default_factory=list)
    holdout_cases: list[str] = field(default_factory=list)
    coverage_percent: float = 0.0
    iterations: int = 0
    stats: dict[str, Any] = field(default_factory=dict)
    corpus_ref: str = ""
    tool_events: list[dict[str, Any]] = field(default_factory=list)
    model_calls: list[dict[str, Any]] = field(default_factory=list)

    @property
    def surviving(self) -> list[ClauseRecord]:
        return [c for c in self.clauses if c.status == ClauseStatus.SURVIVING.value]

    @property
    def falsified(self) -> list[ClauseRecord]:
        return [c for c in self.clauses if c.status == ClauseStatus.FALSIFIED.value]

    def clause_by_id(self, clause_id: str) -> ClauseRecord | None:
        return next((c for c in self.clauses if c.clause_id == clause_id), None)


class SamhitaEngine:
    def __init__(
        self,
        *,
        sandbox: SandboxAdapter,
        provider: LLMProvider,
        descriptor: TargetDescriptor,
        workspace: Path,
        max_iterations: int | None = None,
    ) -> None:
        self.sandbox = sandbox
        self.provider = provider
        self.descriptor = descriptor
        self.workspace = workspace
        self.max_iterations = max_iterations or settings.max_clause_iterations

    # ------------------------------------------------------------------
    async def observe(
        self, cases: list[dict[str, Any]], *, label: str, passes: int = 1
    ) -> tuple[ObservationSet, dict[str, Any]]:
        """Execute ``cases`` under the tracing harness inside the sandbox."""
        spec = build_observe_spec(
            project_root=".",
            source_root=self.descriptor.source_root,
            entry_module=self.descriptor.entry_module,
            entry_callable=self.descriptor.entry_callable,
            cases=[{"id": c["id"], "argv": c["argv"]} for c in cases],
            passes=passes,
        )
        spec_path = self.workspace / f"_kavachx/out/observe-spec-{label}.json"
        spec_path.parent.mkdir(parents=True, exist_ok=True)
        spec_path.write_text(json.dumps(spec, sort_keys=True), encoding="utf-8")

        out_rel = f"_kavachx/out/observations-{label}.json"
        containment_root = (
            str((self.workspace / self.descriptor.asset_dir).resolve())
            if self.descriptor.asset_dir
            else ""
        )

        result = await self.sandbox.execute(
            ExecRequest(
                argv=[
                    "python",
                    "-m",
                    "kx_observe",
                    "--spec",
                    str(spec_path.relative_to(self.workspace)).replace("\\", "/"),
                    "--out",
                    out_rel,
                ],
                cwd=".",
                env={"KAVACHX_CONTAINMENT_ROOT": containment_root} if containment_root else {},
                collect_artifacts=[out_rel],
                label=f"observe:{label}",
                timeout_seconds=min(180, self.sandbox.limits.wall_clock_seconds * 2),
            )
        )

        tool_event = {
            "name": "kx_observe",
            "target": f"{label} ({len(cases)} cases)",
            "ms": result.duration_ms,
            "ok": result.exit_code == 0,
            "detail": result.stderr[-400:] if result.exit_code != 0 else "",
        }

        raw = result.artifacts.get(out_rel, "")
        if not raw:
            logger.warning(
                "samhita.observation_missing",
                label=label,
                exit_code=result.exit_code,
                stderr=result.stderr[-400:],
            )
            return ObservationSet(), tool_event

        document = json.loads(raw)
        observations = parse_observations(document)
        observations.raw_hash = sha256_json(document)
        return observations, tool_event

    # ------------------------------------------------------------------
    async def run(self) -> SamhitaResult:
        result = SamhitaResult()

        corpus_dir = self.workspace / (self.descriptor.corpus_dir or "corpus/benign")
        cases = load_benign_corpus(corpus_dir)
        if not cases:
            result.stats = {
                "error": "no benign corpus",
                "detail": (
                    "SAMHITA needs a benign workload to observe. No JSON cases were found at "
                    f"{self.descriptor.corpus_dir or 'corpus/benign'}."
                ),
            }
            return result

        observation_cases, holdout_cases = split_cases(cases)
        result.observation_cases = [c["id"] for c in observation_cases]
        result.holdout_cases = [c["id"] for c in holdout_cases]
        result.corpus_ref = sha256_json([c["request"] for c in cases])

        # Two passes over the observation split so response determinism is observable.
        observation_set, tool_a = await self.observe(
            observation_cases, label="observation", passes=2
        )
        holdout_set, tool_b = await self.observe(holdout_cases, label="holdout", passes=1)
        result.tool_events.extend([tool_a, tool_b])
        result.observation_set = observation_set
        result.holdout_set = holdout_set
        result.coverage_percent = max(
            observation_set.coverage_percent, holdout_set.coverage_percent
        )

        if not observation_set.records:
            result.stats = {
                "error": "observation produced no records",
                "detail": (
                    "The tracing harness ran but recorded no project-level calls. The "
                    "entrypoint may be wrong."
                ),
            }
            return result

        profiles = derive_value_profiles(observation_set)
        result.profiles = profiles

        holdout_records = holdout_set.records
        counter = 0
        outcomes: list[tuple[str, Any]] = []
        pending_counterexamples: list[dict[str, Any]] = []

        for iteration in range(1, self.max_iterations + 1):
            result.iterations = iteration

            if iteration > 1:
                if not pending_counterexamples:
                    break
                # The one permitted retry: widen numeric bounds to the value that actually
                # falsified them, then re-falsify against the same held-out split.
                profiles = widen_profiles(profiles, pending_counterexamples)
                pending_counterexamples = []

            proposal = await self._propose(profiles, iteration=iteration)
            result.model_calls.append(proposal["evidence"])

            already = {(c.predicate, c.scope) for c in result.clauses}
            for proposed in proposal["clauses"]:
                key = (proposed.predicate, proposed.scope)
                if key in already:
                    continue
                already.add(key)
                counter += 1
                clause_id = f"C{counter:03d}"

                compiled, verdict = falsify_proposal(
                    predicate=proposed.predicate,
                    scope=proposed.scope,
                    holdout_records=holdout_records,
                )
                status = _status_for(verdict.verdict)
                record = ClauseRecord(
                    clause_id=clause_id,
                    kind=proposed.kind,
                    description=proposed.description,
                    predicate=proposed.predicate,
                    scope=proposed.scope,
                    status=status,
                    observation_count=_observation_support(
                        observation_set.records, proposed.scope, compiled
                    ),
                    holdout_pass_count=verdict.pass_count,
                    holdout_fail_count=verdict.fail_count,
                    falsification_reason=verdict.reason,
                    counterexample=verdict.counterexample,
                    iteration=iteration,
                    compiled_source=compiled.predicate if compiled else "",
                    confidence=proposed.confidence,
                    evidence_refs=[
                        f"ev:observation:{observation_set.raw_hash[:12]}",
                        f"ev:holdout:{holdout_set.raw_hash[:12]}",
                    ],
                )
                result.clauses.append(record)
                outcomes.append((clause_id, verdict))

                if verdict.verdict == "FALSIFIED" and verdict.counterexample:
                    pending_counterexamples.append(verdict.counterexample)

            if not pending_counterexamples:
                break

        result.stats = {
            **summarise(outcomes),
            "iterations": result.iterations,
            "observation_cases": len(observation_cases),
            "holdout_cases": len(holdout_cases),
            "observation_records": len(observation_set.records),
            "holdout_records": len(holdout_records),
            "coverage_percent": result.coverage_percent,
            "profiles": len(profiles),
        }
        logger.info("samhita.complete", **result.stats)
        return result

    # ------------------------------------------------------------------
    async def _propose(self, profiles: list[ValueProfile], *, iteration: int) -> dict[str, Any]:
        request: LLMRequest[ClauseProposal] = LLMRequest(
            task=LLMTask.SAMHITA_PROPOSE,
            instruction=CLAUSE_INSTRUCTION,
            payload={
                "value_profiles": profiles_payload(profiles),
                "iteration": iteration,
                "note": (
                    "Bounds from iteration 1 were falsified by held-out observations and have "
                    "been widened. Re-propose."
                )
                if iteration > 1
                else "",
            },
            schema=ClauseProposal,
            model_hint="workhorse",
        )
        response = await self.provider.generate(request)
        return {"clauses": response.parsed.clauses, "evidence": response.evidence_payload()}


def _status_for(verdict: str) -> str:
    return {
        "SURVIVING": ClauseStatus.SURVIVING.value,
        "FALSIFIED": ClauseStatus.FALSIFIED.value,
        "UNSUPPORTED": ClauseStatus.FALSIFIED.value,
        "UNCOMPILABLE": ClauseStatus.UNCOMPILABLE.value,
    }.get(verdict, ClauseStatus.PROPOSED.value)


def _observation_support(records: list[ObservationRecord], scope: str, compiled: Any) -> int:
    """How many observation-split records the predicate was applicable to."""
    if compiled is None:
        return 0
    from app.samhita.falsifier import scope_matches

    count = 0
    for record in records:
        if scope_matches(scope, record.scope) and compiled.evaluate(record.metrics) is not None:
            count += 1
    return count
