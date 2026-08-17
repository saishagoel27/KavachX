"""Patch synthesis.

The synthesiser receives exactly what the spec requires:

* the verified root cause,
* the relevant code slice (bounded, not the file tree),
* the SAMHITA clauses touching the function,
* the reproduction evidence,
* the invariants that must be preserved,
* and, from iteration 2 onward, the **constraints derived from every refutation so far**.

It returns whole-file replacement content, from which KavachX generates the unified diff itself.
The patch is applied to a **copy** in the sandbox workspace — the user's repository is never
touched during analysis. Hard limit: three iterations, then honest failure.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.analysis.world_model import WorldModel
from app.core.hashing import sha256_text
from app.core.logging import get_logger
from app.llm.base import LLMProvider, LLMRequest, LLMTask
from app.llm.contracts import PatchProposal
from app.patching.diffing import (
    DiffStats,
    combine_diffs,
    diff_stats,
    make_unified_diff,
    summarise_change,
)
from app.patching.rootcause import RootCause
from app.samhita.engine import SamhitaResult
from app.sandbox.workspace import PinnedSource, read_pristine_file, write_work_file
from app.validator.service import ValidationOutcome

logger = get_logger(__name__)

PATCH_INSTRUCTION = (
    "Repair the ROOT CAUSE of a reproduced vulnerability.\n"
    "You are given the root cause, the current content of the file, the behavioural clauses "
    "that constrain the affected function, the reproduction evidence, and any constraints "
    "carried over from patches that were already refuted.\n"
    "Return the COMPLETE new content of each file you change. Change as little as possible.\n"
    "Do not add dependencies, network calls, or new process execution. Do not touch CI, "
    "container, git, lockfile or manifest files.\n"
    "Every constraint listed under `constraints` came from a patch that was refuted by "
    "execution. A patch that violates one of them will be refuted again."
)


@dataclass
class SynthesisResult:
    ok: bool = False
    reason: str = ""
    unified_diff: str = ""
    files: list[str] = field(default_factory=list)
    file_changes: dict[str, tuple[str, str]] = field(default_factory=dict)
    risk: str = "medium"
    expected_effect: str = ""
    invariants_preserved: list[str] = field(default_factory=list)
    stats: DiffStats = field(default_factory=DiffStats)
    diff_hash: str = ""
    change_summary: dict[str, Any] = field(default_factory=dict)
    error: str = ""
    model_call: dict[str, Any] = field(default_factory=dict)
    model_name: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "reason": self.reason,
            "files": self.files,
            "risk": self.risk,
            "expected_effect": self.expected_effect,
            "invariants_preserved": self.invariants_preserved,
            "stats": self.stats.as_dict(),
            "diff_hash": self.diff_hash,
            "error": self.error,
        }


def build_payload(
    *,
    model: WorldModel,
    samhita: SamhitaResult,
    root_cause: RootCause,
    outcome: ValidationOutcome,
    pinned: PinnedSource,
    iteration: int,
    constraints: list[str],
    cwe: str,
) -> dict[str, Any]:
    """Assemble the synthesiser's structured input.

    Only files the patch is allowed to touch are included, and only clauses that actually scope
    the affected function — the model gets what it needs to fix this, and nothing else.
    """
    target_file = root_cause.location.split(":")[0]
    contents: dict[str, str] = {}
    if target_file:
        try:
            contents[target_file] = read_pristine_file(pinned, target_file)
        except (OSError, ValueError) as exc:
            logger.warning("synthesis.read_failed", path=target_file, error=str(exc)[:200])

    function_name = root_cause.function.split(".")[-1] if root_cause.function else ""
    relevant_clauses = [
        {
            "clause_id": clause.clause_id,
            "kind": clause.kind,
            "description": clause.description,
            "predicate": clause.predicate,
            "scope": clause.scope,
        }
        for clause in samhita.surviving
        if clause.scope.split(":")[0] == target_file
        or (function_name and clause.scope.endswith(f":{function_name}"))
        or clause.clause_id == outcome.violated_clause_id
    ][:20]

    return {
        "cwe": cwe,
        "iteration": iteration,
        "root_cause": root_cause.as_dict(),
        "code_slice": root_cause.code_slice,
        "files": contents,
        "clauses": relevant_clauses,
        "violated_clause_id": outcome.violated_clause_id,
        "reproduction": {
            "kind": outcome.pov_kind,
            "exit_code": outcome.exit_code,
            "signal": outcome.sanitizer_signal,
            "detail": outcome.detail,
            "reproduction_count": outcome.reproduction_count,
        },
        "observed_tokens": outcome.observed_tokens,
        "constraints": constraints,
        "callers": [
            {"handle": handle, "function": handle.split(":")[-1]}
            for handle in sorted(set(model.callers.get(f"{target_file}:{root_cause.function}", [])))
        ][:20],
        "required_invariants": [
            "the benign corpus must behave identically",
            "no new dependency, network call, or process execution",
            "only the root-cause file may change",
        ],
    }


async def synthesise(
    *,
    provider: LLMProvider,
    payload: dict[str, Any],
    pinned: PinnedSource,
) -> SynthesisResult:
    result = SynthesisResult()

    try:
        response = await provider.generate(
            LLMRequest(
                task=LLMTask.PATCH_SYNTHESIS,
                instruction=PATCH_INSTRUCTION,
                payload=payload,
                schema=PatchProposal,
                model_hint="workhorse",
            )
        )
    except Exception as exc:
        result.error = f"patch synthesis failed: {exc}"
        logger.warning("synthesis.failed", error=str(exc)[:300])
        return result

    proposal: PatchProposal = response.parsed
    result.model_call = response.evidence_payload()
    result.model_name = response.model
    result.reason = proposal.reason
    result.risk = proposal.risk
    result.expected_effect = proposal.expected_effect
    result.invariants_preserved = list(proposal.invariants_preserved)

    diffs: list[str] = []
    for entry in proposal.files:
        path = entry.path.replace("\\", "/").lstrip("./")
        try:
            old = read_pristine_file(pinned, path)
        except (OSError, ValueError) as exc:
            result.error = f"cannot read {path} from the pinned tree: {exc}"
            return result

        new = entry.new_content
        if new == old:
            continue
        diff = make_unified_diff(path=path, old=old, new=new)
        if not diff:
            continue
        diffs.append(diff)
        result.files.append(path)
        result.file_changes[path] = (old, new)
        result.change_summary[path] = summarise_change(old, new)

    if not diffs:
        result.error = "the proposal produced no change against the pinned source"
        return result

    result.unified_diff = combine_diffs(diffs)
    result.stats = diff_stats(result.unified_diff)
    result.diff_hash = sha256_text(result.unified_diff)
    result.ok = True
    logger.info(
        "synthesis.ok",
        files=len(result.files),
        added=result.stats.lines_added,
        removed=result.stats.lines_removed,
        iteration=payload.get("iteration"),
    )
    return result


def apply_to_workspace(result: SynthesisResult, pinned: PinnedSource) -> tuple[bool, str]:
    """Write the patched content into ``work/``.

    ``work/`` is a copy; ``pristine/`` keeps the pinned tree and is what every diff is computed
    against, so an applied patch can always be reverted exactly by resetting the copy.
    """
    if not result.ok:
        return False, result.error or "no patch to apply"
    try:
        for path, (_old, new) in result.file_changes.items():
            write_work_file(pinned, path, new)
    except (OSError, ValueError) as exc:
        return False, f"failed to write {path}: {exc}"

    # Applying the patch must never disturb the pinned tree; verify rather than assume.
    from app.sandbox.workspace import verify_pristine

    if not verify_pristine(pinned):
        return False, (
            "the pinned source tree changed while applying the patch; refusing to continue"
        )
    return True, ""


def constraints_from_refutation(stage: str, detail: str, evidence: dict[str, Any]) -> list[str]:
    """Turn a gauntlet failure into hard constraints for the next iteration.

    This is the mechanism by which "failure becomes a constraint" is literal rather than
    rhetorical: the strings produced here go into the next synthesis payload, and the recipe /
    model must satisfy them.
    """
    constraints: list[str] = []
    if stage == "exploit_mutation":
        payload = str(evidence.get("payload", ""))
        separator = str(evidence.get("separator", ""))
        constraints.append(
            f"BYPASS FOUND: the previous patch was defeated by the mutated payload "
            f"{payload!r}. Filtering individual characters is insufficient — "
            f"{separator or 'another separator'} still reached the shell. Remove the unsafe "
            "construct entirely rather than blocking characters."
        )
    elif stage == "differential_replay":
        case = str(evidence.get("case_id", ""))
        constraints.append(
            f"BEHAVIOURAL REGRESSION: benign case {case or '?'} produced different output after "
            "the previous patch. The repair must not change the response for any benign input."
        )
    elif stage == "samhita_recheck":
        clause = str(evidence.get("clause_id", ""))
        constraints.append(
            f"CONTRACT BROKEN: the previous patch falsified SAMHITA clause {clause or '?'} "
            f"({evidence.get('predicate', '')}). The repair must keep every surviving clause true."
        )
    elif stage == "sibling_hunt":
        location = str(evidence.get("location", "")) or "a neighbouring code path"
        constraints.append(
            f"SIBLING WEAKNESS: an equivalent weakness remains at {location}. Prefer a fix "
            "that removes the unsafe pattern class, not one instance of it."
        )
    if not constraints:
        constraints.append(f"REFUTED at stage {stage}: {detail[:300]}")
    return constraints
