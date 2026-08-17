"""Stage 1 — exploit mutation.

Takes the validated proof of vulnerability and attacks the patch with variations of it. The model
proposes mutation *strategies*; every strategy is then **executed** against the patched build and
judged by the same deterministic signal that proved the original finding — the marker in stdout,
the canary content, a nonzero exit.

This is the stage that catches the classic incomplete fix. A patch that rejects ``;`` looks
correct against the reported payload and falls over the moment ``&`` is tried. The refutation is
not staged: if no mutation reproduced the effect, the stage passes.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any

from app.analysis.probe import TargetDescriptor
from app.core.logging import get_logger
from app.discovery.base import CANARY_CONTENT, CANARY_FILENAME, POV_MARKER
from app.llm.base import LLMProvider, LLMRequest, LLMTask
from app.llm.contracts import MutationProposal
from app.models.enums import GauntletStage, Verdict
from app.sandbox.base import ExecRequest, SandboxAdapter
from app.validator.service import ValidationOutcome

if TYPE_CHECKING:
    from app.gauntlet.runner import StageResult

logger = get_logger(__name__)

MUTATION_INSTRUCTION = (
    "Propose mutations of a proof-of-vulnerability payload that might bypass a patch.\n"
    "You are given the original payload, the kind of weakness, and the tokens the patch is "
    "known to reject.\n"
    "Propose payloads that reach the same effect by a different route: alternative separators, "
    "alternative encodings, different lengths, different traversal forms.\n"
    "You are proposing candidates only. Each one will be executed and judged by its observed "
    "effect — do not claim any of them works."
)

#: Deterministic baseline mutations, always executed regardless of what the model proposes.
#: A model that returns nothing must not silently weaken the stage.
_BASELINE_SEPARATORS = ["&", ";", "|", "&&", "||", "\n", "\r", "`", "$(", ">", "<"]
_BASELINE_TRAVERSALS = [
    f"../{CANARY_FILENAME}",
    f"..\\{CANARY_FILENAME}",
    f"a/../../{CANARY_FILENAME}",
    f"./../{CANARY_FILENAME}",
    f".../.././{CANARY_FILENAME}",
    f"..%2f{CANARY_FILENAME}",
]


async def run(
    *,
    sandbox: SandboxAdapter,
    provider: LLMProvider,
    descriptor: TargetDescriptor,
    workspace: Path,
    outcome: ValidationOutcome,
) -> StageResult:
    from app.gauntlet.runner import StageResult

    started = time.perf_counter()
    result = StageResult(stage=GauntletStage.EXPLOIT_MUTATION.value)
    model_calls: list[dict[str, Any]] = []

    if not outcome.pov_request:
        result.verdict = Verdict.PASS.value
        result.detail = (
            "No proof-of-vulnerability request is attached to this finding, so there is nothing "
            "to mutate. Recorded as a coverage gap rather than a pass on the merits."
        )
        result.metrics = {"payloads": [], "coverage_gap": True, "_model_calls": model_calls}
        result.duration_ms = int((time.perf_counter() - started) * 1000)
        return result

    payloads = _baseline_payloads(outcome)

    try:
        response = await provider.generate(
            LLMRequest(
                task=LLMTask.MUTATION_STRATEGIES,
                instruction=MUTATION_INSTRUCTION,
                payload={
                    "pov_payload": outcome.pov_payload,
                    "pov_kind": outcome.pov_kind,
                    "base_value": _base_value(outcome),
                    "base_count": _base_count(outcome),
                    "blocked_tokens": outcome.observed_tokens,
                    "marker": POV_MARKER,
                    "traversal_target": CANARY_FILENAME,
                },
                schema=MutationProposal,
                model_hint="security",
            )
        )
        model_calls.append(response.evidence_payload())
        for strategy in response.parsed.strategies:
            candidate = {"name": strategy.name, "payload": strategy.payload, "source": "model"}
            if not any(p["payload"] == strategy.payload for p in payloads):
                payloads.append(candidate)
    except Exception as exc:
        logger.warning("gauntlet.mutation.model_unavailable", error=str(exc)[:200])
        result.metrics["model_error"] = str(exc)[:200]

    # Always re-test the original payload: a patch that does not stop the reported exploit
    # cannot pass, whatever else it does.
    if not any(p["payload"] == outcome.pov_payload for p in payloads):
        payloads.insert(
            0,
            {"name": "verbatim-replay", "payload": outcome.pov_payload, "source": "validator"},
        )

    cases: list[dict[str, Any]] = []
    for index, candidate in enumerate(payloads[:40]):
        request = _request_for(outcome, candidate["payload"])
        cases.append(
            {
                "id": f"mut-{index:03d}",
                "argv": descriptor.argv_for(json.dumps(request, sort_keys=True)),
                "name": candidate["name"],
                "payload": candidate["payload"],
                "request": request,
                "source": candidate["source"],
            }
        )

    bypasses: list[dict[str, Any]] = []
    executed = 0
    containment_root = (
        str((workspace / descriptor.asset_dir).resolve()) if descriptor.asset_dir else ""
    )

    # Each mutation is an independent process: no shared interpreter state can mask a bypass.
    for case in cases:
        exec_result = await sandbox.execute(
            ExecRequest(
                argv=case["argv"],
                env={"KAVACHX_CONTAINMENT_ROOT": containment_root} if containment_root else {},
                label=f"mutation:{case['id']}",
                timeout_seconds=min(45, sandbox.limits.wall_clock_seconds),
            )
        )
        executed += 1
        effect = _effect_observed(outcome.pov_kind, exec_result.stdout, exec_result)
        if effect["observed"]:
            bypasses.append(
                {
                    "case_id": case["id"],
                    "name": case["name"],
                    "payload": case["payload"][:600],
                    "source": case["source"],
                    "signal": effect["signal"],
                    "exit_code": exec_result.exit_code,
                    "separator": _separator_of(case["payload"], outcome),
                    "output_hash": exec_result.output_hash(),
                }
            )
            # One live bypass is enough to refute; stop rather than burn budget.
            break

    result.cases_total = len(cases)
    result.cases_passed = executed - len(bypasses)
    result.metrics = {
        "payloads": [{"name": c["name"], "payload": c["payload"][:200]} for c in cases],
        "executed": executed,
        "candidates": len(cases),
        "model_proposed": len([c for c in cases if c["source"] == "model"]),
        "_model_calls": model_calls,
    }

    if bypasses:
        first = bypasses[0]
        result.verdict = Verdict.FAIL.value
        result.detail = (
            f"BYPASS FOUND — mutation {first['name']!r} still reproduced the vulnerability "
            f"({first['signal']}). The patch blocks the reported payload but not this variant."
        )
        result.refuting_evidence = first
    else:
        result.verdict = Verdict.PASS.value
        result.detail = f"{executed} mutated payloads executed; none reproduced the vulnerability."

    result.duration_ms = int((time.perf_counter() - started) * 1000)
    logger.info(
        "gauntlet.mutation.complete",
        verdict=result.verdict,
        executed=executed,
        bypasses=len(bypasses),
    )
    return result


# ---------------------------------------------------------------------------
def _baseline_payloads(outcome: ValidationOutcome) -> list[dict[str, Any]]:
    kind = outcome.pov_kind
    out: list[dict[str, Any]] = []

    if kind == "command_injection":
        base = _base_value(outcome)
        for separator in _BASELINE_SEPARATORS:
            out.append(
                {
                    "name": f"separator:{separator.strip() or 'newline'}",
                    "payload": f"{base}{separator}echo {POV_MARKER}",
                    "source": "baseline",
                }
            )
        out.extend(
            [
                {
                    "name": "quoted-separator",
                    "payload": f'{base}"&echo {POV_MARKER}',
                    "source": "baseline",
                },
                {
                    "name": "tab-padded",
                    "payload": f"{base}\t&\techo {POV_MARKER}",
                    "source": "baseline",
                },
                {
                    "name": "command-substitution",
                    "payload": f"{base}$(echo {POV_MARKER})",
                    "source": "baseline",
                },
                {
                    "name": "backtick-substitution",
                    "payload": f"{base}`echo {POV_MARKER}`",
                    "source": "baseline",
                },
            ]
        )
    elif kind == "length_boundary":
        base = _base_count(outcome)
        for count in (base, base + 1, base + 4, base * 2, 128, 1024):
            out.append(
                {
                    "name": f"lines:{count}",
                    "payload": "\n".join(f"h{i}:{i}" for i in range(int(count))),
                    "source": "baseline",
                }
            )
        out.append(
            {
                "name": "blank-padded",
                "payload": "\n\n".join(f"h{i}:{i}" for i in range(int(base))),
                "source": "baseline",
            }
        )
    elif kind == "path_traversal":
        for payload in _BASELINE_TRAVERSALS:
            out.append({"name": f"traversal:{payload}", "payload": payload, "source": "baseline"})
    elif outcome.pov_payload:
        out.append(
            {"name": "verbatim-replay", "payload": outcome.pov_payload, "source": "validator"}
        )
    return out


def _base_value(outcome: ValidationOutcome) -> str:
    payload = outcome.pov_payload or ""
    for separator in ("&", ";", "|", "\n"):
        if separator in payload:
            return payload.split(separator, 1)[0].strip() or "kavachx-probe"
    return "kavachx-probe"


def _base_count(outcome: ValidationOutcome) -> int:
    payload = outcome.pov_payload or ""
    if payload:
        count = len([ln for ln in payload.split("\n") if ln.strip()])
        if count:
            return count
    return 9


def _request_for(outcome: ValidationOutcome, payload: str) -> dict[str, Any]:
    request = dict(outcome.pov_request or {})
    kind = outcome.pov_kind
    if kind == "command_injection":
        request.setdefault("op", "export")
        request["name"] = payload
        request.setdefault("format", "txt")
    elif kind == "length_boundary":
        request.setdefault("op", "parse")
        request["headers"] = payload
    elif kind == "path_traversal":
        request.setdefault("op", "asset")
        request["path"] = payload
    return request


def _effect_observed(kind: str, stdout: str, exec_result: Any) -> dict[str, Any]:
    """Deterministic per-kind judgement. Identical criteria to the original validation."""
    if kind == "command_injection":
        observed = POV_MARKER in stdout
        return {"observed": observed, "signal": "injected command executed"}
    if kind == "path_traversal":
        observed = CANARY_CONTENT in stdout
        return {"observed": observed, "signal": "canary read outside the asset root"}
    # Crash-shaped findings: any nonzero exit or sanitizer signal is a reproduction.
    observed = exec_result.exit_code != 0 or bool(exec_result.signals)
    return {
        "observed": observed,
        "signal": f"exit {exec_result.exit_code}"
        + (f" / {','.join(exec_result.signals)}" if exec_result.signals else ""),
    }


def _separator_of(payload: str, outcome: ValidationOutcome) -> str:
    if outcome.pov_kind != "command_injection":
        return ""
    for separator in _BASELINE_SEPARATORS:
        if separator in payload:
            return separator
    return ""
