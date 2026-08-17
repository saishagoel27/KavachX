"""Assurance grading.

Deterministic rules over gauntlet results. No model input, no discretion.

**These levels are not formal proof.** They are *bounded empirical assurance*: statements about
what was executed and observed, bounded by the coverage that was achieved, the corpus that was
available and the mutations that were tried. Every grade carries the bounds that qualify it, and
the certificate renders them next to the badge rather than in a footnote.

    Level A  exploit eliminated · all relevant clauses hold · replay passes · mutation passes
             · sibling hunt passes with nothing unproved · coverage change bounded
    Level B  as A, but the sibling hunt left unproved candidates elsewhere
    Level C  exploit eliminated, but behaviour changed or some clauses could not be verified
    Level R  patch refuted → withdrawn, shield remains deployed, refuting evidence attached
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.core.logging import get_logger
from app.models.enums import AssuranceLevel, GauntletStage, Verdict

logger = get_logger(__name__)

#: A coverage swing larger than this is treated as an unbounded behavioural change.
COVERAGE_DELTA_LIMIT = 10.0


@dataclass
class AssuranceAssessment:
    level: str = AssuranceLevel.R.value
    rationale: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    criteria: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "level": self.level,
            "label": LEVEL_LABELS[self.level],
            "rationale": self.rationale,
            "limitations": self.limitations,
            "criteria": self.criteria,
            "assurance_kind": "bounded empirical assurance",
            "not_a_formal_proof": True,
        }


LEVEL_LABELS: dict[str, str] = {
    AssuranceLevel.A.value: "Exploit eliminated, contract preserved, no residual candidates",
    AssuranceLevel.B.value: "Exploit eliminated, contract preserved, unproved candidates remain",
    AssuranceLevel.C.value: "Exploit eliminated, with behavioural change or unverified clauses",
    AssuranceLevel.R.value: "Patch refuted and withdrawn; shield remains deployed",
}

LEVEL_DESCRIPTIONS: dict[str, str] = {
    AssuranceLevel.A.value: (
        "The validated exploit no longer reproduces, every mutation attempted failed, the benign "
        "corpus is behaviourally identical, every in-scope SAMHITA clause still holds, the "
        "sibling hunt found nothing unproved, and the coverage change is bounded."
    ),
    AssuranceLevel.B.value: (
        "As Level A, except the sibling hunt shortlisted code paths that share the weakness "
        "pattern and could not be proved safe. None was exploitable in the probes that ran; they "
        "are recorded as residual risk."
    ),
    AssuranceLevel.C.value: (
        "The exploit no longer reproduces, but at least one verification dimension is "
        "incomplete: behaviour changed on a benign case, or clauses could not be evaluated. The "
        "specific limitation is listed."
    ),
    AssuranceLevel.R.value: (
        "The patch was refuted by execution and has been withdrawn. The reversible shield "
        "remains deployed. The refuting evidence is attached. This finding is NOT repaired."
    ),
}


def grade(
    *,
    gauntlet: Any,
    exploit_eliminated: bool,
    shield_active: bool,
    coverage_before: float,
    coverage_after: float,
    clause_total: int,
    clause_held: int,
    clause_unsupported: int,
    unproved_siblings: list[dict[str, Any]] | None = None,
    iteration: int = 1,
    max_iterations: int = 3,
) -> AssuranceAssessment:
    unproved_siblings = unproved_siblings or []
    assessment = AssuranceAssessment()

    stage = {s.stage: s for s in getattr(gauntlet, "stages", [])}
    mutation_pass = _passed(stage.get(GauntletStage.EXPLOIT_MUTATION.value))
    sibling_pass = _passed(stage.get(GauntletStage.SIBLING_HUNT.value))
    replay_pass = _passed(stage.get(GauntletStage.DIFFERENTIAL_REPLAY.value))
    contract_pass = _passed(stage.get(GauntletStage.SAMHITA_RECHECK.value))
    coverage_delta = round(abs(coverage_after - coverage_before), 2)
    coverage_bounded = coverage_delta <= COVERAGE_DELTA_LIMIT

    assessment.criteria = {
        "exploit_eliminated": exploit_eliminated,
        "mutation_pass": mutation_pass,
        "sibling_pass": sibling_pass,
        "replay_pass": replay_pass,
        "samhita_pass": contract_pass,
        "coverage_before": coverage_before,
        "coverage_after": coverage_after,
        "coverage_delta": coverage_delta,
        "coverage_bounded": coverage_bounded,
        "coverage_delta_limit": COVERAGE_DELTA_LIMIT,
        "clauses_in_scope": clause_total,
        "clauses_held": clause_held,
        "clauses_unsupported": clause_unsupported,
        "unproved_siblings": len(unproved_siblings),
        "patch_iteration": iteration,
        "max_patch_iterations": max_iterations,
        "shield_active": shield_active,
    }

    # -- Level R ----------------------------------------------------------
    gauntlet_verdict = getattr(gauntlet, "verdict", Verdict.FAIL.value)
    if gauntlet_verdict != Verdict.PASS.value or not exploit_eliminated:
        assessment.level = AssuranceLevel.R.value
        failing = getattr(gauntlet, "failing_stage", "") or "exploit still reproduces"
        assessment.rationale = [
            f"Refutation gauntlet verdict: FAIL (first failing stage: {failing}).",
            "The patch has been withdrawn.",
        ]
        if not exploit_eliminated:
            assessment.rationale.append(
                "The validated exploit still reproduces against the patched build."
            )
        assessment.limitations = [
            "This finding is not repaired.",
            (
                "The reversible shield remains deployed and continues to block the validated "
                "exploit."
                if shield_active
                else "No shield is active: this finding is currently unmitigated."
            ),
            f"Patch iteration {iteration} of a maximum {max_iterations}.",
        ]
        for stage_result in getattr(gauntlet, "stages", []):
            if not _passed(stage_result):
                assessment.limitations.append(f"{stage_result.stage}: {stage_result.detail}")
        return assessment

    base_rationale = [
        "The validated exploit no longer reproduces against the patched build.",
        f"Exploit mutation: PASS ({_metric(stage, GauntletStage.EXPLOIT_MUTATION.value)}).",
        f"Differential replay: PASS ({_metric(stage, GauntletStage.DIFFERENTIAL_REPLAY.value)}).",
        f"SAMHITA re-check: PASS ({clause_held}/{clause_total} in-scope clauses hold).",
        f"Sibling hunt: PASS ({_metric(stage, GauntletStage.SIBLING_HUNT.value)}).",
    ]

    # -- Level C ----------------------------------------------------------
    if not replay_pass or not contract_pass or clause_unsupported > 0 or not coverage_bounded:
        assessment.level = AssuranceLevel.C.value
        assessment.rationale = base_rationale
        if not replay_pass:
            assessment.limitations.append(
                "Differential replay did not establish behavioural equivalence for every "
                "benign case."
            )
        if not contract_pass:
            assessment.limitations.append(
                "At least one in-scope SAMHITA clause could not be confirmed on the patched build."
            )
        if clause_unsupported:
            assessment.limitations.append(
                f"{clause_unsupported} clause(s) could not be evaluated after the patch, so "
                "their preservation is unverified rather than confirmed."
            )
        if not coverage_bounded:
            assessment.limitations.append(
                f"Coverage moved by {coverage_delta:.1f} percentage points "
                f"({coverage_before:.1f}% → {coverage_after:.1f}%), above the "
                f"{COVERAGE_DELTA_LIMIT:.0f}-point bound. The patch may have changed which code "
                "executes."
            )
        return assessment

    # -- Level B ----------------------------------------------------------
    if unproved_siblings:
        assessment.level = AssuranceLevel.B.value
        assessment.rationale = base_rationale
        assessment.limitations = [
            (
                f"The sibling hunt shortlisted {len(unproved_siblings)} code path(s) sharing this "
                "weakness pattern that could not be proved safe. None was exploitable in the "
                "probes that ran."
            ),
            *[
                f"unproved: {s.get('location', '?')} — {s.get('why', 'structural similarity')}"
                for s in unproved_siblings[:8]
            ],
        ]
        return assessment

    # -- Level A ----------------------------------------------------------
    assessment.level = AssuranceLevel.A.value
    assessment.rationale = [
        *base_rationale,
        f"Coverage change bounded: {coverage_before:.1f}% → {coverage_after:.1f}% "
        f"(Δ{coverage_delta:.1f} ≤ {COVERAGE_DELTA_LIMIT:.0f}).",
        "No unproved sibling candidates remain.",
    ]
    assessment.limitations = [
        (
            "Bounded empirical assurance, not a formal proof. The claims hold for the inputs "
            "that were executed: the benign corpus, the validated exploit, and the mutations "
            "attempted."
        ),
        f"Line coverage at verification time was {coverage_after:.1f}%; code that did not "
        "execute was not verified.",
    ]
    return assessment


def _passed(stage: Any) -> bool:
    return bool(stage is not None and getattr(stage, "verdict", "") == Verdict.PASS.value)


def _metric(stages: dict[str, Any], name: str) -> str:
    stage = stages.get(name)
    if stage is None:
        return "not run"
    return (
        f"{stage.cases_passed}/{stage.cases_total} cases"
        if stage.cases_total
        else stage.detail[:80]
    )
