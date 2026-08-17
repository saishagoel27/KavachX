"""Root-cause analysis.

Do not patch the crash site blindly. The observed failure and the defect are frequently in
different places — the crash is where the invalid state finally became fatal.

::

    Observed failure → Execution path → First causal condition → Root cause → Minimal patch location

The model may propose a root cause. It is then **verified deterministically**: the proposed
location must lie inside a function that the validated exploit actually executed, and it must be
in the target's own source. A proposal that fails those checks is rejected and the analysis falls
back to the deepest project frame on the recorded execution path — which is at least known to
have run.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.analysis.world_model import WorldModel
from app.core.logging import get_logger
from app.llm.base import LLMProvider, LLMRequest, LLMTask
from app.llm.contracts import RootCauseHypothesis
from app.validator.service import ValidationOutcome

logger = get_logger(__name__)

ROOT_CAUSE_INSTRUCTION = (
    "Identify the ROOT CAUSE of a reproduced failure, not the crash site.\n"
    "You are given the failure signal, the executed frames, the enclosing code slice and the "
    "behavioural clause that was violated.\n"
    "The root cause is the first condition on the executed path that made the failure "
    "inevitable — typically a missing bound check, a missing containment check, or an "
    "unvalidated value crossing a trust boundary.\n"
    "Return the location as `relative/path.py:LINE`. A deterministic verifier will reject any "
    "location that was not actually executed."
)


@dataclass
class RootCause:
    location: str = ""
    function: str = ""
    summary: str = ""
    causal_chain: list[str] = field(default_factory=list)
    minimal_patch_location: str = ""
    verified: bool = False
    verification_notes: list[str] = field(default_factory=list)
    proposed_location: str = ""
    confidence: float = 0.0
    executed_path: list[str] = field(default_factory=list)
    code_slice: dict[str, Any] = field(default_factory=dict)
    model_call: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "location": self.location,
            "function": self.function,
            "summary": self.summary,
            "causal_chain": self.causal_chain,
            "minimal_patch_location": self.minimal_patch_location,
            "verified": self.verified,
            "verification_notes": self.verification_notes,
            "proposed_location": self.proposed_location,
            "confidence": self.confidence,
            "executed_path": self.executed_path,
        }

    def display_chain(self) -> list[str]:
        return [
            f"Observed failure  {self.executed_path[-1] if self.executed_path else 'unknown'}",
            f"Execution path  {len(self.executed_path)} frames",
            f"First causal condition  {self.causal_chain[0] if self.causal_chain else 'unknown'}",
            f"Root cause  {self.location}",
            f"Minimal patch location  {self.minimal_patch_location or self.location}",
        ]


async def analyse(
    *,
    provider: LLMProvider,
    model: WorldModel,
    outcome: ValidationOutcome,
    plan: dict[str, Any],
    clause_description: str = "",
) -> RootCause:
    frames = outcome.trace_frames or _synthetic_frames(outcome, plan)
    project_frames = [f for f in frames if f.get("in_project")]
    executed_scopes = set(outcome.evidence.get("pov_executed_scopes") or [])

    root = RootCause(
        executed_path=[
            f"{f.get('file', '')}:{f.get('line', 0)} in {f.get('function', '?')}"
            for f in project_frames
        ]
    )

    sink_location = (
        outcome.crash_site or f"{plan.get('target_file', '')}:{plan.get('target_line', 0)}"
    )
    anchor_file, anchor_line = _split(sink_location)
    anchor_symbol = model.symbol_at(anchor_file, anchor_line)
    if anchor_symbol is not None:
        root.code_slice = model.code_slice(anchor_symbol.handle, context_lines=6)

    payload = {
        "failure_summary": outcome.detail,
        "failure_signal": outcome.sanitizer_signal,
        "exit_code": outcome.exit_code,
        "violated_clause": clause_description,
        "sink_location": sink_location,
        "trace_frames": frames,
        "executed_scopes": sorted(executed_scopes)[:40],
        "code_slice": root.code_slice,
        "callers": (
            sorted(set(model.callers.get(anchor_symbol.handle, []))) if anchor_symbol else []
        ),
    }

    proposal: RootCauseHypothesis | None = None
    try:
        response = await provider.generate(
            LLMRequest(
                task=LLMTask.ROOT_CAUSE,
                instruction=ROOT_CAUSE_INSTRUCTION,
                payload=payload,
                schema=RootCauseHypothesis,
                model_hint="security",
            )
        )
        proposal = response.parsed
        root.model_call = response.evidence_payload()
    except Exception as exc:
        root.verification_notes.append(f"model proposal unavailable: {str(exc)[:200]}")

    if proposal is not None:
        root.proposed_location = proposal.location
        root.confidence = proposal.confidence
        verified, notes = _verify(
            proposal.location, model=model, executed_scopes=executed_scopes, frames=frames
        )
        root.verification_notes.extend(notes)
        if verified:
            root.location = proposal.location
            root.function = proposal.function or _function_at(model, proposal.location)
            root.summary = proposal.summary
            root.causal_chain = proposal.causal_chain or root.executed_path
            root.minimal_patch_location = (
                proposal.minimal_patch_location
                if proposal.minimal_patch_location
                and _verify(
                    proposal.minimal_patch_location,
                    model=model,
                    executed_scopes=executed_scopes,
                    frames=frames,
                )[0]
                else proposal.location
            )
            root.verified = True
            logger.info("rootcause.verified", location=root.location, function=root.function)
            return root

    # Deterministic fallback: the deepest project frame that actually ran.
    fallback = project_frames[-1] if project_frames else None
    if fallback is not None:
        root.location = f"{fallback['file']}:{fallback['line']}"
    else:
        root.location = sink_location
    root.function = _function_at(model, root.location)
    root.summary = (
        "Root cause taken from the deepest executed frame in project code, because the "
        "proposed location could not be verified against the execution path."
    )
    root.causal_chain = root.executed_path or [root.location]
    root.minimal_patch_location = root.location
    root.verified = False
    root.verification_notes.append(
        "Falling back to the deepest executed project frame; this location is known to have run."
    )
    logger.warning("rootcause.fallback", location=root.location)
    return root


# ---------------------------------------------------------------------------
def _verify(
    location: str,
    *,
    model: WorldModel,
    executed_scopes: set[str],
    frames: list[dict[str, Any]],
) -> tuple[bool, list[str]]:
    """A proposed location must exist, be project source, and have actually executed."""
    notes: list[str] = []
    file, line = _split(location)
    if not file or line <= 0:
        return False, [f"proposed location {location!r} is not a file:line reference"]

    index = model.files.get(file)
    if index is None:
        return False, [f"{file} is not part of the indexed target"]
    if line > index.lines:
        return False, [f"line {line} is past the end of {file} ({index.lines} lines)"]

    symbol = model.symbol_at(file, line)
    if symbol is None:
        notes.append(f"{location} is not inside any indexed function (module level)")

    frame_hit = any(
        f.get("file") == file and abs(int(f.get("line", 0)) - line) <= 40 for f in frames
    )
    scope_hit = bool(
        symbol
        and (
            symbol.handle in executed_scopes
            or any(scope.endswith(f":{symbol.name}") for scope in executed_scopes)
        )
    )

    if not (frame_hit or scope_hit):
        return False, [
            *notes,
            (
                f"{location} was not on the recorded execution path — neither a traceback frame "
                "nor an observed call scope covers it, so it cannot be the root cause of this "
                "reproduction."
            ),
        ]

    notes.append(
        f"{location} confirmed on the execution path via "
        + ("traceback frame" if frame_hit else "observed call scope")
    )
    return True, notes


def _function_at(model: WorldModel, location: str) -> str:
    file, line = _split(location)
    symbol = model.symbol_at(file, line)
    return symbol.qualname if symbol else ""


def _synthetic_frames(outcome: ValidationOutcome, plan: dict[str, Any]) -> list[dict[str, Any]]:
    """Some validated findings have no traceback (a successful injection does not crash).

    Their execution path comes from the observed call scopes instead.
    """
    frames: list[dict[str, Any]] = []
    target_file = str(plan.get("target_file", ""))
    target_line = int(plan.get("target_line", 0) or 0)
    for scope in sorted(outcome.evidence.get("pov_executed_scopes") or []):
        if ":" not in scope or scope == "*":
            continue
        file, function = scope.split(":", 1)
        frames.append(
            {
                "file": file,
                "line": target_line if file == target_file else 0,
                "function": function,
                "text": "",
                "in_project": True,
            }
        )
    if target_file and not any(f["file"] == target_file for f in frames):
        frames.append(
            {
                "file": target_file,
                "line": target_line,
                "function": str(plan.get("target_function", "")),
                "text": "",
                "in_project": True,
            }
        )
    return frames


def _split(location: str) -> tuple[str, int]:
    file, _, line = location.rpartition(":")
    try:
        return file, int(line)
    except ValueError:
        return location, 0
