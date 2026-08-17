"""Stage 3 — differential replay.

Replay the benign corpus against the pre-patch build and the post-patch build, then compare
response hashes case by case. Behavioural equivalence is required where applicable.

Two details matter for this to mean anything:

* **The baseline is captured before the patch is applied**, from the pinned tree, in the same
  sandbox with the same environment. Comparing against a remembered value from a different
  configuration would compare the configuration, not the patch.
* **Volatile fields are excluded explicitly, not silently.** The comparison normalises fields
  that legitimately vary between runs (absolute paths in echoed commands) and records exactly
  which keys were normalised, so a reader can see what "equivalent" was allowed to mean.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any

from app.analysis.probe import TargetDescriptor
from app.core.hashing import sha256_json
from app.core.logging import get_logger
from app.models.enums import GauntletStage, Verdict
from app.sandbox.base import ExecRequest, SandboxAdapter

if TYPE_CHECKING:
    from app.gauntlet.runner import StageResult

logger = get_logger(__name__)

#: Response fields excluded from equivalence, with the reason. Anything not listed here is
#: compared byte for byte.
VOLATILE_FIELDS: dict[str, str] = {
    "command": "contains the absolute interpreter path and the workspace-relative output path",
}


def normalise(response: Any) -> Any:
    """Strip declared volatile fields, recursively."""
    if isinstance(response, dict):
        return {
            key: normalise(value)
            for key, value in sorted(response.items())
            if key not in VOLATILE_FIELDS
        }
    if isinstance(response, list):
        return [normalise(item) for item in response]
    return response


async def capture(
    *,
    sandbox: SandboxAdapter,
    descriptor: TargetDescriptor,
    workspace: Path,
    cases: list[dict[str, Any]],
    label: str,
) -> dict[str, Any]:
    """Run the corpus and record a normalised hash per case."""
    if not cases:
        return {"by_case": {}, "label": label, "total": 0, "error": "no benign cases"}

    spec = {
        "project_root": ".",
        "source_root": descriptor.source_root,
        "entry_module": descriptor.entry_module,
        "entry_callable": descriptor.entry_callable,
        "cases": [{"id": c["id"], "argv": c["argv"]} for c in cases],
    }
    spec_rel = f"_kavachx/out/replay-{label}-spec.json"
    out_rel = f"_kavachx/out/replay-{label}-result.json"
    (workspace / spec_rel).parent.mkdir(parents=True, exist_ok=True)
    (workspace / spec_rel).write_text(json.dumps(spec, sort_keys=True), encoding="utf-8")

    exec_result = await sandbox.execute(
        ExecRequest(
            argv=["python", "-m", "kx_batch", "--spec", spec_rel, "--out", out_rel],
            collect_artifacts=[out_rel],
            label=f"replay:{label}",
            timeout_seconds=max(120, sandbox.limits.wall_clock_seconds * 2),
        )
    )

    raw = exec_result.artifacts.get(out_rel, "")
    if not raw:
        return {
            "by_case": {},
            "label": label,
            "total": 0,
            "error": f"replay did not produce a result (exit {exec_result.exit_code})",
        }

    document = json.loads(raw)
    by_case: dict[str, Any] = {}
    for record in document.get("cases", []):
        normalised = normalise(record.get("response"))
        by_case[record["id"]] = {
            "exit_code": record["exit_code"],
            "response_hash": sha256_json(normalised),
            "response": normalised,
            "error_type": record.get("error_type", ""),
            "shield_blocked": bool(record.get("shield_blocked")),
        }
    return {
        "by_case": by_case,
        "label": label,
        "total": len(by_case),
        "guard_total": document.get("guard_total", {}),
        "error": "",
    }


async def run(
    *,
    sandbox: SandboxAdapter,
    descriptor: TargetDescriptor,
    workspace: Path,
    cases: list[dict[str, Any]],
    baseline: dict[str, Any],
) -> StageResult:
    from app.gauntlet.runner import StageResult

    started = time.perf_counter()
    result = StageResult(stage=GauntletStage.DIFFERENTIAL_REPLAY.value)

    if not baseline or not baseline.get("by_case"):
        result.verdict = Verdict.FAIL.value
        result.detail = (
            "No pre-patch baseline is available, so behavioural equivalence cannot be "
            "established. An unverifiable patch is not a passing patch."
        )
        result.refuting_evidence = {
            "reason": "missing baseline",
            "error": baseline.get("error", ""),
        }
        result.duration_ms = int((time.perf_counter() - started) * 1000)
        return result

    after = await capture(
        sandbox=sandbox,
        descriptor=descriptor,
        workspace=workspace,
        cases=cases,
        label="patched",
    )
    if after.get("error"):
        result.verdict = Verdict.FAIL.value
        result.detail = f"Post-patch replay failed to run: {after['error']}"
        result.refuting_evidence = {"reason": "post-patch replay failed", "error": after["error"]}
        result.duration_ms = int((time.perf_counter() - started) * 1000)
        return result

    before_cases = baseline["by_case"]
    after_cases = after["by_case"]

    divergences: list[dict[str, Any]] = []
    matched = 0
    for case_id, before in sorted(before_cases.items()):
        current = after_cases.get(case_id)
        if current is None:
            divergences.append(
                {
                    "case_id": case_id,
                    "kind": "missing",
                    "detail": "the case did not execute after the patch",
                }
            )
            continue
        if current["exit_code"] != before["exit_code"]:
            divergences.append(
                {
                    "case_id": case_id,
                    "kind": "exit_code",
                    "before": before["exit_code"],
                    "after": current["exit_code"],
                    "detail": (
                        f"exit code changed from {before['exit_code']} to {current['exit_code']}"
                    ),
                }
            )
            continue
        if current["response_hash"] != before["response_hash"]:
            divergences.append(
                {
                    "case_id": case_id,
                    "kind": "response",
                    "before_hash": before["response_hash"][:16],
                    "after_hash": current["response_hash"][:16],
                    "before": _trim(before["response"]),
                    "after": _trim(current["response"]),
                    "detail": "the response differs from the pre-patch behaviour",
                }
            )
            continue
        matched += 1

    result.cases_total = len(before_cases)
    result.cases_passed = matched
    result.metrics = {
        "cases": len(before_cases),
        "matched": matched,
        "diverged": len(divergences),
        "normalised_fields": VOLATILE_FIELDS,
        "baseline_guard": baseline.get("guard_total", {}),
        "patched_guard": after.get("guard_total", {}),
    }

    if divergences:
        first = divergences[0]
        result.verdict = Verdict.FAIL.value
        result.detail = (
            f"BEHAVIOURAL REGRESSION — {len(divergences)} of {len(before_cases)} benign cases "
            f"changed. First: {first['case_id']} ({first['detail']})."
        )
        result.refuting_evidence = first
    else:
        result.verdict = Verdict.PASS.value
        result.detail = (
            f"All {matched} benign cases produced identical behaviour before and after the patch."
        )

    result.duration_ms = int((time.perf_counter() - started) * 1000)
    logger.info(
        "gauntlet.replay.complete",
        verdict=result.verdict,
        matched=matched,
        diverged=len(divergences),
    )
    return result


def _trim(value: Any, limit: int = 600) -> Any:
    rendered = json.dumps(value, sort_keys=True, default=str)
    return rendered[:limit]
