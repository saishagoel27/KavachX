"""Stage 2 — sibling hunt.

Search neighbouring code paths for the same weakness class, then *attempt the analogous exploit
against each candidate*. Finding a structurally similar function is a hint; the stage's verdict
depends on whether an exploit actually works there.

Outcomes, and why they are graded differently:

* **A sibling is exploitable** → the stage FAILS. The patch fixed one instance of a class that is
  still live elsewhere, and the constraint pushed into the next iteration says so.
* **Similar candidates exist but none are exploitable** → the stage PASSES, and the unproved
  candidates are recorded. That combination is exactly what separates assurance Level B from
  Level A.
* **No similar candidates at all** → PASS with nothing outstanding.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any

from app.analysis.probe import TargetDescriptor
from app.analysis.world_model import WorldModel
from app.core.logging import get_logger
from app.discovery.base import CANARY_CONTENT, POV_MARKER
from app.llm.base import LLMProvider, LLMRequest, LLMTask
from app.llm.contracts import SiblingProposal
from app.models.enums import GauntletStage, Verdict
from app.patching.synthesis import SynthesisResult
from app.sandbox.base import ExecRequest, SandboxAdapter
from app.validator.service import ValidationOutcome

if TYPE_CHECKING:
    from app.gauntlet.runner import StageResult

logger = get_logger(__name__)

SIBLING_INSTRUCTION = (
    "Find code paths that share the weakness pattern that was just repaired.\n"
    "You are given the repaired weakness, the pattern that made it exploitable, and snippets of "
    "neighbouring functions in the same file and module.\n"
    "Return the locations that plausibly share the same weakness class.\n"
    "You are shortlisting candidates. Each one will be probed by execution — do not claim any of "
    "them is exploitable."
)

#: Structural indicators per weakness class. Used to shortlist deterministically even when the
#: model returns nothing, so the stage never silently degrades to "found nothing".
_PATTERN_TOKENS: dict[str, tuple[str, ...]] = {
    "command_injection": ("shell=true", "subprocess", "os.system", "os.popen", 'f"', "format("),
    "length_boundary": ("[index]", "[i]", "+= 1", "slots", "buffer", "memcpy"),
    "path_traversal": ("/ relative", "/ path", "asset_root", "root /", "open(", "read_text"),
}


async def run(
    *,
    sandbox: SandboxAdapter,
    provider: LLMProvider,
    descriptor: TargetDescriptor,
    workspace: Path,
    model: WorldModel,
    outcome: ValidationOutcome,
    synthesis: SynthesisResult,
    mutation_payloads: list[dict[str, Any]],
) -> StageResult:
    from app.gauntlet.runner import StageResult

    started = time.perf_counter()
    result = StageResult(stage=GauntletStage.SIBLING_HUNT.value)
    model_calls: list[dict[str, Any]] = []

    repaired_file = synthesis.files[0] if synthesis.files else ""
    anchor = _anchor_handle(model, outcome, repaired_file)
    neighbours = model.neighbours_of(anchor) if anchor else []

    # Widen to every sink of the same category anywhere in the target — a sibling in another
    # module is exactly the case a file-local search would miss.
    sink_category = _sink_category(outcome.pov_kind)
    for sink in model.sinks:
        if sink.category != sink_category:
            continue
        location = f"{sink.file}:{sink.line}"
        if any(n["location"] == location for n in neighbours):
            continue
        neighbours.append(
            {
                "location": location,
                "handle": f"{sink.file}:{sink.function}" if sink.function else sink.file,
                "function": sink.function,
                "same_file": sink.file == repaired_file,
                "snippet": sink.snippet,
            }
        )

    candidates: list[dict[str, Any]] = []
    pattern = _pattern_description(outcome)

    try:
        response = await provider.generate(
            LLMRequest(
                task=LLMTask.SIBLING_CANDIDATES,
                instruction=SIBLING_INSTRUCTION,
                payload={
                    "pattern": pattern,
                    "repaired_location": outcome.crash_site,
                    "weakness_kind": outcome.pov_kind,
                    "neighbours": neighbours[:24],
                },
                schema=SiblingProposal,
                model_hint="security",
            )
        )
        model_calls.append(response.evidence_payload())
        for candidate in response.parsed.candidates:
            candidates.append(
                {
                    "location": candidate.location,
                    "function": candidate.function,
                    "why": candidate.why,
                    "confidence": candidate.confidence,
                    "source": "model",
                }
            )
    except Exception as exc:
        logger.warning("gauntlet.sibling.model_unavailable", error=str(exc)[:200])
        result.metrics["model_error"] = str(exc)[:200]

    tokens = _PATTERN_TOKENS.get(outcome.pov_kind, ())
    for neighbour in neighbours:
        snippet = str(neighbour.get("snippet", "")).lower()
        hits = [t for t in tokens if t in snippet]
        if not hits:
            continue
        if any(c["location"] == neighbour["location"] for c in candidates):
            continue
        # A sink is only a sibling if a *caller-controlled* value can reach it. A function that
        # reads a module constant shares the syntax but not the weakness, and counting it would
        # inflate residual risk — and drag every certificate down to Level B — with candidates
        # that were never candidates.
        if not _caller_influenced(model, neighbour):
            continue
        candidates.append(
            {
                "location": neighbour["location"],
                "function": neighbour.get("function", ""),
                "why": f"shares structural indicators {hits} with a caller-controlled value",
                "confidence": min(0.9, 0.35 + 0.15 * len(hits)),
                "source": "structural",
            }
        )

    # The repaired site itself is not its own sibling.
    repaired_locations = {outcome.crash_site, *(synthesis.files or [])}
    candidates = [
        c
        for c in candidates
        if c["location"] not in repaired_locations
        and c["location"].split(":")[0] not in _test_paths(model)
    ]

    exploitable: list[dict[str, Any]] = []
    probed: list[dict[str, Any]] = []
    containment_root = (
        str((workspace / descriptor.asset_dir).resolve()) if descriptor.asset_dir else ""
    )

    for candidate in candidates[:8]:
        probe = _probe_request(outcome, candidate)
        if probe is None:
            probed.append({**candidate, "probed": False, "reason": "no analogous probe exists"})
            continue

        exec_result = await sandbox.execute(
            ExecRequest(
                argv=descriptor.argv_for(json.dumps(probe, sort_keys=True)),
                env={"KAVACHX_CONTAINMENT_ROOT": containment_root} if containment_root else {},
                label=f"sibling:{candidate['location']}",
                timeout_seconds=min(45, sandbox.limits.wall_clock_seconds),
            )
        )
        observed = _effect(outcome.pov_kind, exec_result)
        probed.append(
            {
                **candidate,
                "probed": True,
                "exploitable": observed["observed"],
                "signal": observed["signal"],
                "exit_code": exec_result.exit_code,
            }
        )
        if observed["observed"]:
            exploitable.append(
                {
                    "location": candidate["location"],
                    "function": candidate.get("function", ""),
                    "payload": json.dumps(probe, sort_keys=True)[:400],
                    "signal": observed["signal"],
                    "why": candidate.get("why", ""),
                }
            )
            break

    # A candidate that was probed without effect is *not* cleared. The probe drives the same
    # entrypoint operation as the original exploit, so it may never have executed the candidate's
    # function at all — "the analogous request did nothing here" and "this code is safe" are
    # different claims, and only the second would justify dropping it from residual risk. Both
    # buckets stay unproved; the reason says which one applies.
    unproved = [p for p in probed if not p.get("exploitable")]
    result.cases_total = len(candidates)
    result.cases_passed = len(unproved)
    result.metrics = {
        "candidates": len(candidates),
        "probed": len([p for p in probed if p.get("probed")]),
        "exploitable": len(exploitable),
        "unproved_candidates": [
            {
                "location": p["location"],
                "function": p.get("function", ""),
                "why": p.get("why", ""),
                "probed": p.get("probed", False),
                "status": (
                    "probed with the analogous payload and no effect was observed, but the probe "
                    "is not known to have executed this function — neither confirmed nor cleared"
                    if p.get("probed")
                    else "no analogous probe exists for this location through the entrypoint"
                ),
            }
            for p in unproved[:12]
        ],
        "_model_calls": model_calls,
    }

    if exploitable:
        first = exploitable[0]
        result.verdict = Verdict.FAIL.value
        result.detail = (
            f"SIBLING EXPLOITABLE — the same weakness class is still live at {first['location']} "
            f"({first['signal']}). The patch fixed one instance, not the class."
        )
        result.refuting_evidence = first
    elif candidates:
        result.verdict = Verdict.PASS.value
        result.detail = (
            f"{len(candidates)} structurally similar candidate(s) examined; none were "
            f"exploitable. {len(result.metrics['unproved_candidates'])} remain unproved and are "
            "recorded as residual risk."
        )
    else:
        result.verdict = Verdict.PASS.value
        result.detail = "No structurally similar code path was found for this weakness class."

    result.duration_ms = int((time.perf_counter() - started) * 1000)
    logger.info(
        "gauntlet.sibling.complete",
        verdict=result.verdict,
        candidates=len(candidates),
        exploitable=len(exploitable),
    )
    return result


# ---------------------------------------------------------------------------
def _anchor_handle(model: WorldModel, outcome: ValidationOutcome, repaired_file: str) -> str:
    file, _, line = outcome.crash_site.rpartition(":")
    try:
        symbol = model.symbol_at(file, int(line))
    except ValueError:
        symbol = None
    if symbol is not None:
        return symbol.handle
    for handle in model.symbols:
        if handle.startswith(f"{repaired_file}:"):
            return handle
    return ""


def _caller_influenced(model: WorldModel, neighbour: dict[str, Any]) -> bool:
    """Does a parameter of the enclosing function appear in the flagged code?

    Deliberately conservative in the *inclusive* direction: if the enclosing symbol cannot be
    resolved, the candidate is kept. Dropping something we failed to analyse would be the unsafe
    direction — an unexamined candidate should stay on the list, not vanish from it.
    """
    handle = str(neighbour.get("handle", ""))
    symbol = model.symbols.get(handle)
    if symbol is None:
        function_name = str(neighbour.get("function", ""))
        matches = model.find_symbols(function_name) if function_name else []
        symbol = matches[0] if matches else None
    if symbol is None:
        return True
    if not symbol.parameters:
        return False
    snippet = str(neighbour.get("snippet", ""))
    body = model.code_slice(symbol.handle, context_lines=0, max_lines=120).get("code", "")
    haystack = f"{snippet}\n{body}"
    return any(parameter in haystack for parameter in symbol.parameters)


def _sink_category(pov_kind: str) -> str:
    return {
        "command_injection": "shell_exec",
        "path_traversal": "file_read_write",
        "length_boundary": "indexed_write",
    }.get(pov_kind, "")


def _pattern_description(outcome: ValidationOutcome) -> str:
    return {
        "command_injection": (
            "a caller-controlled value interpolated into a string that is executed by a shell "
            "subprocess shell=True command injection"
        ),
        "length_boundary": (
            "an index variable incremented per input element and used as a write index without "
            "a bound check slots buffer overflow"
        ),
        "path_traversal": (
            "a caller-supplied path joined to a base directory without a containment check "
            "path traversal read_text open"
        ),
    }.get(outcome.pov_kind, outcome.pov_kind)


def _test_paths(model: WorldModel) -> set[str]:
    return {p for p in model.files if p.startswith("tests/") or "/tests/" in f"/{p}"}


def _probe_request(outcome: ValidationOutcome, candidate: dict[str, Any]) -> dict[str, Any] | None:
    """Build the analogous exploit for a candidate location.

    Only operations the entrypoint genuinely exposes are probed. Inventing an operation to reach
    an internal helper would produce an unfalsifiable "probe" that proves nothing either way.
    """
    kind = outcome.pov_kind
    if kind == "command_injection":
        return {"op": "export", "name": f"sib&echo {POV_MARKER}", "format": "txt"}
    if kind == "length_boundary":
        return {"op": "parse", "headers": "\n".join(f"s{i}:{i}" for i in range(64))}
    if kind == "path_traversal":
        from app.discovery.base import CANARY_FILENAME

        return {"op": "asset", "path": f"../{CANARY_FILENAME}"}
    return None


def _effect(kind: str, exec_result: Any) -> dict[str, Any]:
    if kind == "command_injection":
        return {
            "observed": POV_MARKER in exec_result.stdout,
            "signal": "injected command executed",
        }
    if kind == "path_traversal":
        return {
            "observed": CANARY_CONTENT in exec_result.stdout,
            "signal": "canary read outside the asset root",
        }
    return {
        "observed": exec_result.exit_code != 0 or bool(exec_result.signals),
        "signal": f"exit {exec_result.exit_code}",
    }
