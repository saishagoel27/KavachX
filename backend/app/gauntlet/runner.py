"""The Refutation Gauntlet.

Four stages, run against the **patched** workspace copy. Every one of them tries to prove the
patch wrong:

1. **Exploit mutation** — mutate the validated proof of vulnerability and execute every variant.
   A patch that blocked one payload but not its cousins dies here.
2. **Sibling hunt** — look for the same weakness class in neighbouring code paths, and attempt
   the analogous exploit against each candidate.
3. **Differential replay** — replay the benign corpus before and after the patch and compare
   response hashes. Any behavioural divergence is a regression.
4. **SAMHITA re-check** — re-evaluate every surviving clause in the blast radius against traces
   from the patched build.

Stages 1, 3 and 4 run concurrently (they need no shared mutable state — each gets its own
workspace snapshot phase); the sibling hunt runs after the mutation stage because it reuses the
mutation engine's payload shapes.

**If any stage fails, the patch is REFUTED.** The refuting evidence becomes a constraint, the
patch is withdrawn, and the next iteration begins. After three iterations: honest failure, with
the shield left in place.
"""

from __future__ import annotations

import asyncio
import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.analysis.probe import TargetDescriptor
from app.analysis.world_model import WorldModel
from app.core.hashing import sha256_json
from app.core.logging import get_logger
from app.gauntlet import mutation, replay, samhita_recheck, sibling
from app.models.enums import GauntletStage, Verdict
from app.patching.blast_radius import BlastRadius
from app.patching.synthesis import SynthesisResult, constraints_from_refutation
from app.samhita.engine import SamhitaResult
from app.sandbox.base import SandboxAdapter
from app.sandbox.workspace import PinnedSource
from app.validator.service import ValidationOutcome

logger = get_logger(__name__)


@dataclass
class StageResult:
    stage: str
    verdict: str = Verdict.FAIL.value
    detail: str = ""
    refuting_evidence: dict[str, Any] = field(default_factory=dict)
    metrics: dict[str, Any] = field(default_factory=dict)
    duration_ms: int = 0
    cases_total: int = 0
    cases_passed: int = 0
    evidence_refs: list[str] = field(default_factory=list)
    error: str = ""

    @property
    def passed(self) -> bool:
        return self.verdict == Verdict.PASS.value

    def as_dict(self) -> dict[str, Any]:
        return {
            "stage": self.stage,
            "verdict": self.verdict,
            "detail": self.detail,
            "refuting_evidence": self.refuting_evidence,
            "metrics": self.metrics,
            "duration_ms": self.duration_ms,
            "cases_total": self.cases_total,
            "cases_passed": self.cases_passed,
            "error": self.error,
        }


@dataclass
class GauntletOutcome:
    verdict: str = Verdict.FAIL.value
    stages: list[StageResult] = field(default_factory=list)
    failing_stage: str = ""
    stages_passed: int = 0
    stages_total: int = 4
    duration_ms: int = 0
    summary: str = ""
    constraints: list[str] = field(default_factory=list)
    model_calls: list[dict[str, Any]] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return self.verdict == Verdict.PASS.value

    def stage(self, name: str) -> StageResult | None:
        return next((s for s in self.stages if s.stage == name), None)

    def as_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict,
            "failing_stage": self.failing_stage,
            "stages_passed": self.stages_passed,
            "stages_total": self.stages_total,
            "duration_ms": self.duration_ms,
            "summary": self.summary,
            "stages": [s.as_dict() for s in self.stages],
            "constraints": self.constraints,
        }


class GauntletRunner:
    def __init__(
        self,
        *,
        sandbox: SandboxAdapter,
        provider: Any,
        descriptor: TargetDescriptor,
        model: WorldModel,
        samhita: SamhitaResult,
        pinned: PinnedSource,
        workspace: Path,
        benign_cases: list[dict[str, Any]],
        baseline: dict[str, Any] | None = None,
    ) -> None:
        self.sandbox = sandbox
        self.provider = provider
        self.descriptor = descriptor
        self.model = model
        self.samhita = samhita
        self.pinned = pinned
        self.workspace = workspace
        self.benign_cases = benign_cases
        #: Pre-patch response hashes, captured once from the pinned build.
        self.baseline = baseline or {}

    # ------------------------------------------------------------------
    async def capture_baseline(self) -> dict[str, Any]:
        """Record pre-patch behaviour. Must be called on the unpatched workspace."""
        self.baseline = await replay.capture(
            sandbox=self.sandbox,
            descriptor=self.descriptor,
            workspace=self.workspace,
            cases=self.benign_cases,
            label="baseline",
        )
        logger.info(
            "gauntlet.baseline_captured",
            cases=len(self.baseline.get("by_case", {})),
        )
        return self.baseline

    # ------------------------------------------------------------------
    async def run(
        self,
        *,
        outcome: ValidationOutcome,
        synthesis: SynthesisResult,
        blast: BlastRadius,
        iteration: int,
        finding_handle: str,
        on_stage: Any = None,
    ) -> GauntletOutcome:
        started = time.perf_counter()
        result = GauntletOutcome()

        async def emit(stage: str, verdict: str, detail: str) -> None:
            if on_stage is not None:
                await on_stage(stage=stage, verdict=verdict, detail=detail, iteration=iteration)

        for stage_name in (
            GauntletStage.EXPLOIT_MUTATION.value,
            GauntletStage.SIBLING_HUNT.value,
            GauntletStage.DIFFERENTIAL_REPLAY.value,
            GauntletStage.SAMHITA_RECHECK.value,
        ):
            await emit(stage_name, "running", "stage started")

        # Stage 1 first: it produces the payload shapes stage 2 reuses, and a bypass here is the
        # most decisive refutation there is.
        stage_mutation = await mutation.run(
            sandbox=self.sandbox,
            provider=self.provider,
            descriptor=self.descriptor,
            workspace=self.workspace,
            outcome=outcome,
        )
        result.stages.append(stage_mutation)
        result.model_calls.extend(stage_mutation.metrics.pop("_model_calls", []))
        await emit(stage_mutation.stage, stage_mutation.verdict, stage_mutation.detail)

        stage_sibling, stage_replay, stage_contract = await asyncio.gather(
            sibling.run(
                sandbox=self.sandbox,
                provider=self.provider,
                descriptor=self.descriptor,
                workspace=self.workspace,
                model=self.model,
                outcome=outcome,
                synthesis=synthesis,
                mutation_payloads=list(stage_mutation.metrics.get("payloads", [])),
            ),
            replay.run(
                sandbox=self.sandbox,
                descriptor=self.descriptor,
                workspace=self.workspace,
                cases=self.benign_cases,
                baseline=self.baseline,
            ),
            samhita_recheck.run(
                sandbox=self.sandbox,
                descriptor=self.descriptor,
                workspace=self.workspace,
                samhita=self.samhita,
                blast=blast,
                cases=self.benign_cases,
            ),
        )
        for stage_result in (stage_sibling, stage_replay, stage_contract):
            result.stages.append(stage_result)
            result.model_calls.extend(stage_result.metrics.pop("_model_calls", []))
            await emit(stage_result.stage, stage_result.verdict, stage_result.detail)

        result.stages_total = len(result.stages)
        result.stages_passed = len([s for s in result.stages if s.passed])
        failing = [s for s in result.stages if not s.passed]

        if failing:
            first = failing[0]
            result.verdict = Verdict.FAIL.value
            result.failing_stage = first.stage
            result.summary = f"PATCH v{iteration} REFUTED at {first.stage}: {first.detail}"
            for stage_result in failing:
                result.constraints.extend(
                    constraints_from_refutation(
                        stage_result.stage, stage_result.detail, stage_result.refuting_evidence
                    )
                )
        else:
            result.verdict = Verdict.PASS.value
            result.summary = (
                f"PATCH v{iteration} VERIFIED: all {result.stages_total} refutation stages passed."
            )

        result.duration_ms = int((time.perf_counter() - started) * 1000)
        logger.info(
            "gauntlet.complete",
            finding=finding_handle,
            iteration=iteration,
            verdict=result.verdict,
            failing_stage=result.failing_stage,
            passed=result.stages_passed,
            total=result.stages_total,
        )
        return result


def outcome_hash(outcome: GauntletOutcome) -> str:
    return sha256_json(outcome.as_dict())


def write_stage_spec(workspace: Path, name: str, spec: dict[str, Any]) -> str:
    rel = f"_kavachx/out/{name}-spec.json"
    path = workspace / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(spec, sort_keys=True), encoding="utf-8")
    return rel
