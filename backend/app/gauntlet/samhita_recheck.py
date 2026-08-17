"""Stage 4 — SAMHITA re-check.

Re-observe the patched build under tracing and re-evaluate every surviving clause that the blast
radius says could be affected. A patch that silently changes a contract — even one that fixes the
vulnerability — has changed behaviour someone else may depend on.

Two distinct failure modes, both refutations:

* a clause that held before the patch is now **falsified** — the patch broke a contract;
* a clause that held before is now **unsupported** on the patched build, because the code path it
  described no longer executes. That is a silent behavioural change, and treating it as a pass
  would let the patch delete functionality and call it a fix.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any

from app.analysis.probe import TargetDescriptor
from app.core.logging import get_logger
from app.models.enums import GauntletStage, Verdict
from app.patching.blast_radius import BlastRadius
from app.samhita.engine import SamhitaResult
from app.samhita.falsifier import check_clause_against_records
from app.samhita.observation import parse_observations
from app.sandbox.base import ExecRequest, SandboxAdapter

if TYPE_CHECKING:
    from app.gauntlet.runner import StageResult

logger = get_logger(__name__)


async def run(
    *,
    sandbox: SandboxAdapter,
    descriptor: TargetDescriptor,
    workspace: Path,
    samhita: SamhitaResult,
    blast: BlastRadius,
    cases: list[dict[str, Any]],
) -> StageResult:
    from app.gauntlet.runner import StageResult

    started = time.perf_counter()
    result = StageResult(stage=GauntletStage.SAMHITA_RECHECK.value)

    in_scope = [c for c in samhita.surviving if c.clause_id in set(blast.clause_ids)]
    if not in_scope:
        in_scope = samhita.surviving

    if not in_scope:
        result.verdict = Verdict.PASS.value
        result.detail = (
            "SAMHITA holds no surviving clauses, so there is no contract to re-check. Recorded "
            "as a coverage gap: this is not evidence that behaviour was preserved."
        )
        result.metrics = {"clauses_checked": 0, "coverage_gap": True}
        result.duration_ms = int((time.perf_counter() - started) * 1000)
        return result

    if not cases:
        result.verdict = Verdict.FAIL.value
        result.detail = "No benign workload is available to re-observe the patched build."
        result.refuting_evidence = {"reason": "no benign cases"}
        result.duration_ms = int((time.perf_counter() - started) * 1000)
        return result

    spec = {
        "project_root": ".",
        "source_root": descriptor.source_root,
        "entry_module": descriptor.entry_module,
        "entry_callable": descriptor.entry_callable,
        "cases": [{"id": c["id"], "argv": c["argv"]} for c in cases],
        "passes": 1,
    }
    spec_rel = "_kavachx/out/recheck-spec.json"
    out_rel = "_kavachx/out/recheck-observations.json"
    (workspace / spec_rel).parent.mkdir(parents=True, exist_ok=True)
    (workspace / spec_rel).write_text(json.dumps(spec, sort_keys=True), encoding="utf-8")

    containment_root = (
        str((workspace / descriptor.asset_dir).resolve()) if descriptor.asset_dir else ""
    )
    exec_result = await sandbox.execute(
        ExecRequest(
            argv=["python", "-m", "kx_observe", "--spec", spec_rel, "--out", out_rel],
            env={"KAVACHX_CONTAINMENT_ROOT": containment_root} if containment_root else {},
            collect_artifacts=[out_rel],
            label="gauntlet:samhita-recheck",
            timeout_seconds=max(150, sandbox.limits.wall_clock_seconds * 2),
        )
    )

    raw = exec_result.artifacts.get(out_rel, "")
    if not raw:
        result.verdict = Verdict.FAIL.value
        result.detail = (
            f"The patched build could not be re-observed (exit {exec_result.exit_code}); "
            "contract preservation is unverifiable."
        )
        result.refuting_evidence = {
            "reason": "re-observation failed",
            "exit_code": exec_result.exit_code,
            "stderr": exec_result.stderr[-400:],
        }
        result.duration_ms = int((time.perf_counter() - started) * 1000)
        return result

    observations = parse_observations(json.loads(raw))
    records = observations.records

    broken: list[dict[str, Any]] = []
    unsupported: list[dict[str, Any]] = []
    held = 0

    for clause in in_scope:
        verdict = check_clause_against_records(
            predicate=clause.predicate, scope=clause.scope, records=records
        )
        if verdict.verdict == "SURVIVING":
            held += 1
        elif verdict.verdict == "FALSIFIED":
            broken.append(
                {
                    "clause_id": clause.clause_id,
                    "predicate": clause.predicate,
                    "scope": clause.scope,
                    "description": clause.description,
                    "reason": verdict.reason,
                    "counterexample": verdict.counterexample,
                }
            )
        else:
            unsupported.append(
                {
                    "clause_id": clause.clause_id,
                    "predicate": clause.predicate,
                    "scope": clause.scope,
                    "reason": verdict.reason,
                }
            )

    result.cases_total = len(in_scope)
    result.cases_passed = held
    result.metrics = {
        "clauses_checked": len(in_scope),
        "clauses_held": held,
        "clauses_broken": len(broken),
        "clauses_unsupported": len(unsupported),
        "coverage_percent": observations.coverage_percent,
        "blast_radius_clauses": len(blast.clause_ids),
        "unsupported": unsupported[:10],
    }

    if broken:
        first = broken[0]
        result.verdict = Verdict.FAIL.value
        result.detail = (
            f"CONTRACT BROKEN — {len(broken)} clause(s) that held before the patch are now "
            f"false. First: {first['clause_id']} ({first['predicate']})."
        )
        result.refuting_evidence = first
    elif unsupported:
        first = unsupported[0]
        result.verdict = Verdict.FAIL.value
        result.detail = (
            f"CONTRACT COVERAGE LOST — {len(unsupported)} clause(s) can no longer be evaluated "
            f"on the patched build. First: {first['clause_id']} ({first['predicate']}). The code "
            "path it described no longer executes, which is a silent behavioural change."
        )
        result.refuting_evidence = first
    else:
        result.verdict = Verdict.PASS.value
        result.detail = (
            f"All {held} in-scope SAMHITA clauses still hold on the patched build "
            f"(blast radius: {len(blast.clause_ids)} clauses)."
        )

    result.duration_ms = int((time.perf_counter() - started) * 1000)
    logger.info(
        "gauntlet.recheck.complete",
        verdict=result.verdict,
        held=held,
        broken=len(broken),
        unsupported=len(unsupported),
    )
    return result
