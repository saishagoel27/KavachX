"""Held-out trace falsification.

This is the component that makes SAMHITA trustworthy. A proposed clause is evaluated against
observation records the proposer never saw. Three outcomes:

* **SURVIVING** — the predicate held on every applicable held-out record, and there was at
  least one such record. Only these clauses enter SAMHITA.
* **FALSIFIED** — at least one held-out record made the predicate false. The counterexample is
  stored, and it is what feeds the single permitted widening retry.
* **UNSUPPORTED** — no held-out record carried the metrics the predicate needs, so the clause
  is untested. An untested clause is *not* admitted. A clause nobody could contradict is not
  the same as a clause nobody did contradict, and treating it as evidence would be exactly the
  kind of unfalsifiable claim this system exists to avoid.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.core.logging import get_logger
from app.samhita.compiler import CompiledClause, try_compile
from app.samhita.observation import ObservationRecord

logger = get_logger(__name__)


@dataclass(slots=True)
class FalsificationResult:
    verdict: str  # SURVIVING | FALSIFIED | UNSUPPORTED | UNCOMPILABLE
    pass_count: int = 0
    fail_count: int = 0
    applicable: int = 0
    reason: str = ""
    counterexample: dict[str, Any] = field(default_factory=dict)
    evidence_refs: list[str] = field(default_factory=list)

    @property
    def survived(self) -> bool:
        return self.verdict == "SURVIVING"


def scope_matches(clause_scope: str, record_scope: str) -> bool:
    """``module:function``, ``module:*``, ``*`` and bare-function scopes all resolve here."""
    if clause_scope in ("*", "", record_scope):
        return True
    if clause_scope.endswith(":*"):
        return record_scope.startswith(clause_scope[:-1])
    if clause_scope.endswith("*"):
        return record_scope.startswith(clause_scope[:-1])
    # A clause may name only the function; match the suffix after the file separator.
    if ":" not in clause_scope and ":" in record_scope:
        return record_scope.rsplit(":", 1)[1] == clause_scope
    return False


def evaluate_clause(
    compiled: CompiledClause,
    records: list[ObservationRecord],
    *,
    clause_scope: str,
    max_counterexamples: int = 1,
) -> FalsificationResult:
    applicable = 0
    passes = 0
    failures: list[ObservationRecord] = []

    for record in records:
        if not scope_matches(clause_scope, record.scope):
            continue
        outcome = compiled.evaluate(record.metrics)
        if outcome is None:
            continue
        applicable += 1
        if outcome:
            passes += 1
        else:
            failures.append(record)
            if len(failures) >= max_counterexamples:
                break

    if applicable == 0:
        return FalsificationResult(
            verdict="UNSUPPORTED",
            applicable=0,
            reason=(
                "No held-out observation carried the metrics this predicate needs "
                f"({', '.join(sorted(compiled.metrics))}), so the clause could not be tested."
            ),
        )

    if failures:
        failure = failures[0]
        offending_metric = ""
        offending_value: Any = None
        for metric in sorted(compiled.metrics):
            if metric in failure.metrics:
                offending_metric = metric
                offending_value = failure.metrics[metric]
                break
        return FalsificationResult(
            verdict="FALSIFIED",
            pass_count=passes,
            fail_count=len(failures),
            applicable=applicable,
            reason=(
                f"Held-out case {failure.case_id or '?'} in scope {failure.scope} contradicts "
                f"the predicate ({offending_metric}={offending_value!r})."
            ),
            counterexample={
                "case_id": failure.case_id,
                "scope": failure.scope,
                "metric": offending_metric,
                "value": offending_value,
                "metrics": {k: v for k, v in failure.metrics.items() if k in compiled.metrics},
            },
        )

    return FalsificationResult(
        verdict="SURVIVING",
        pass_count=passes,
        applicable=applicable,
        reason=f"Held on all {applicable} applicable held-out observations.",
    )


def falsify_proposal(
    *,
    predicate: str,
    scope: str,
    holdout_records: list[ObservationRecord],
) -> tuple[CompiledClause | None, FalsificationResult]:
    """Compile, then falsify. A predicate that will not compile never reaches evaluation."""
    compiled, error = try_compile(predicate)
    if compiled is None:
        return None, FalsificationResult(
            verdict="UNCOMPILABLE",
            reason=f"Predicate rejected by the clause compiler: {error}",
        )
    return compiled, evaluate_clause(compiled, holdout_records, clause_scope=scope)


def check_clause_against_records(
    *,
    predicate: str,
    scope: str,
    records: list[ObservationRecord],
) -> FalsificationResult:
    """Re-check a *surviving* clause against fresh records.

    Used by the SAMHITA re-check stage of the Refutation Gauntlet, and by the validator when it
    needs to know whether an exploit run violated a contract clause.
    """
    compiled, error = try_compile(predicate)
    if compiled is None:
        return FalsificationResult(verdict="UNCOMPILABLE", reason=error)
    return evaluate_clause(compiled, records, clause_scope=scope)


def summarise(results: list[tuple[str, FalsificationResult]]) -> dict[str, Any]:
    counts: dict[str, int] = {}
    for _, result in results:
        counts[result.verdict] = counts.get(result.verdict, 0) + 1
    return {
        "proposed": len(results),
        "surviving": counts.get("SURVIVING", 0),
        "falsified": counts.get("FALSIFIED", 0),
        "unsupported": counts.get("UNSUPPORTED", 0),
        "uncompilable": counts.get("UNCOMPILABLE", 0),
    }
