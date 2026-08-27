"""Security oracles — the deterministic judgement of whether a test proved something.

An oracle answers one question: *did the security property get violated?* It answers it from
observable facts only — an exit code, a signal string, a marker in stdout, a clause evaluating
false on a trace — and it is the reason a finding can be VALIDATED without any model being
consulted.

Every oracle here is a pure function of an :class:`~app.sandbox.base.ExecResult` (plus, for the
contract oracle, a parsed observation set). There is deliberately no oracle that takes a natural
language description and decides whether output "looks wrong": that is the judgement call this
whole architecture exists to avoid making.

Two properties worth stating explicitly:

* **A ``no_crash`` oracle is not the absence of an oracle.** It is used by the gauntlet's
  differential replay and by benign-corpus verification, where the property being asserted is
  "this behaves normally". Its verdict is as deterministic as any other.
* **An oracle that cannot be evaluated returns ``UNSUPPORTED``, never ``False``.** "The sanitizer
  output was not available" and "no sanitizer report was found" are different facts, and
  collapsing them into a negative is how a run reports a clean result it did not earn.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.core.logging import get_logger
from app.discovery.base import CANARY_CONTENT, POV_MARKER
from app.sandbox.base import ExecResult

logger = get_logger(__name__)


class Verdict:
    """An oracle's answer."""

    #: The security property was violated — the test proved the finding.
    FIRED = "FIRED"
    #: The property held for this input.
    HELD = "HELD"
    #: The oracle could not be evaluated. Distinct from HELD, always.
    UNSUPPORTED = "UNSUPPORTED"


@dataclass
class OracleResult:
    verdict: str = Verdict.UNSUPPORTED
    kind: str = ""
    #: The observable that decided it, quoted.
    evidence: str = ""
    detail: str = ""
    #: Everything the run should record about this execution.
    signals: list[str] = field(default_factory=list)
    exit_code: int | None = None
    output_hash: str = ""
    duration_ms: int = 0
    peak_ram_mb: int = 0

    @property
    def fired(self) -> bool:
        return self.verdict == Verdict.FIRED

    def as_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict,
            "kind": self.kind,
            "evidence": self.evidence[:600],
            "detail": self.detail[:600],
            "signals": self.signals,
            "exit_code": self.exit_code,
            "output_hash": self.output_hash,
            "duration_ms": self.duration_ms,
            "peak_ram_mb": self.peak_ram_mb,
        }


#: Signals that indicate a sanitizer (ASan/UBSan/etc.) rather than an ordinary failure.
_SANITIZER_SIGNALS = (
    "asan",
    "ubsan",
    "lsan",
    "tsan",
    "msan",
    "segv",
)

#: Resource-exhaustion evidence. A memory ceiling hit is a real security signal (a decompression
#: bomb, an unbounded allocation) and is distinguishable from an ordinary crash.
_EXHAUSTION_SIGNALS = ("python:MemoryError", "python:RecursionError")


def evaluate(
    oracle: Any,
    result: ExecResult,
    *,
    baseline: ExecResult | None = None,
    observations: Any = None,
    markers: dict[str, str] | None = None,
) -> OracleResult:
    """Judge one execution against one :class:`~app.testing.specs.OracleSpec`.

    ``markers`` carries the values KavachX injected for marker/canary oracles. They are read from
    here rather than from the spec because a model-chosen marker could collide with the target's
    own output and manufacture a reproduction that never happened.
    """
    markers = markers or {}
    kind = getattr(oracle, "kind", "")
    out = OracleResult(
        kind=kind,
        signals=list(result.signals),
        exit_code=result.exit_code,
        output_hash=result.output_hash(),
        duration_ms=result.duration_ms,
        peak_ram_mb=result.peak_ram_mb,
    )

    combined = f"{result.stdout}\n{result.stderr}"

    if kind == "exit_code_nonzero":
        if result.timed_out:
            out.verdict = Verdict.UNSUPPORTED
            out.detail = (
                "The process timed out, so its exit code is not meaningful. Use a 'timeout' "
                "oracle to assert on that instead."
            )
            return out
        out.verdict = Verdict.FIRED if result.exit_code != 0 else Verdict.HELD
        out.evidence = f"exit code {result.exit_code}"
        return out

    if kind == "exit_code_equals":
        expected = getattr(oracle, "expected_exit_code", None)
        if expected is None:
            out.verdict = Verdict.UNSUPPORTED
            out.detail = "No expected_exit_code was supplied."
            return out
        out.verdict = Verdict.FIRED if result.exit_code == expected else Verdict.HELD
        out.evidence = f"exit code {result.exit_code} (expected {expected})"
        return out

    if kind == "crash_signal":
        crash = [s for s in result.signals if not s.startswith("python:")]
        out.verdict = Verdict.FIRED if crash or result.exit_code not in (0, 1) else Verdict.HELD
        out.evidence = ",".join(crash) or f"exit code {result.exit_code}"
        return out

    if kind == "sanitizer_report":
        found = [s for s in result.signals if any(s.startswith(p) for p in _SANITIZER_SIGNALS)]
        if found:
            out.verdict = Verdict.FIRED
            out.evidence = ",".join(found)
            out.detail = _quote_sanitizer(combined)
            return out
        # No sanitizer signal. Whether that means "clean" depends on whether the build was
        # instrumented at all, which the caller knows and we do not — so this is HELD only when
        # the process actually ran.
        if result.exit_code is None:
            out.verdict = Verdict.UNSUPPORTED
            out.detail = "The process did not run, so no sanitizer output could exist."
            return out
        out.verdict = Verdict.HELD
        out.evidence = "no sanitizer report in output"
        out.detail = (
            "Absence of a sanitizer report only means something if the build was "
            "sanitizer-instrumented. The engine record states whether it was."
        )
        return out

    if kind == "exception_raised":
        expected = str(getattr(oracle, "exception_type", "") or "")
        raised = [s for s in result.signals if s.startswith("python:")]
        if expected:
            hit = expected in combined
            out.verdict = Verdict.FIRED if hit else Verdict.HELD
            out.evidence = f"{expected} {'present' if hit else 'absent'} in output"
        else:
            out.verdict = Verdict.FIRED if raised else Verdict.HELD
            out.evidence = ",".join(raised) or "no exception in output"
        return out

    if kind == "assertion_failure":
        hit = "AssertionError" in combined or "assertion failed" in combined.lower()
        out.verdict = Verdict.FIRED if hit else Verdict.HELD
        out.evidence = "AssertionError present" if hit else "no assertion failure"
        return out

    if kind == "marker_in_stdout":
        marker = markers.get("pov_marker") or POV_MARKER
        hit = marker in result.stdout
        out.verdict = Verdict.FIRED if hit else Verdict.HELD
        out.evidence = f"marker {'present' if hit else 'absent'} in stdout"
        out.detail = (
            "The marker appearing in stdout proves the injected command executed: nothing in the "
            "target's own output can produce it."
            if hit
            else "The injected command did not execute."
        )
        return out

    if kind == "canary_content_in_stdout":
        canary = markers.get("canary") or CANARY_CONTENT
        hit = canary in result.stdout
        out.verdict = Verdict.FIRED if hit else Verdict.HELD
        out.evidence = f"canary {'present' if hit else 'absent'} in stdout"
        out.detail = (
            "Canary content planted outside the declared root appeared in output, which proves a "
            "containment escape."
            if hit
            else "No content from outside the declared root appeared."
        )
        return out

    if kind == "contract_violation":
        if observations is None:
            out.verdict = Verdict.UNSUPPORTED
            out.detail = (
                "No observation trace was collected, so no SAMHITA clause could be evaluated. "
                "This is an absence of evidence, not a clause holding."
            )
            return out
        clause_id = str(getattr(oracle, "clause_id", "") or "")
        violated = list(getattr(observations, "violated_clause_ids", []) or [])
        if not clause_id:
            out.verdict = Verdict.FIRED if violated else Verdict.HELD
            out.evidence = f"violated clauses: {','.join(violated) or 'none'}"
            return out
        hit = clause_id in violated
        out.verdict = Verdict.FIRED if hit else Verdict.HELD
        out.evidence = f"clause {clause_id} {'falsified' if hit else 'held'} on this trace"
        return out

    if kind == "output_differs_from_baseline":
        if baseline is None:
            out.verdict = Verdict.UNSUPPORTED
            out.detail = "No baseline execution was supplied to compare against."
            return out
        differs = result.output_hash() != baseline.output_hash()
        out.verdict = Verdict.FIRED if differs else Verdict.HELD
        out.evidence = (
            f"output hash {result.output_hash()[:16]} vs baseline "
            f"{baseline.output_hash()[:16]}"
        )
        out.detail = (
            "Behaviour changed relative to the pre-patch baseline on this input."
            if differs
            else "Byte-identical to the baseline."
        )
        return out

    if kind == "timeout":
        out.verdict = Verdict.FIRED if result.timed_out else Verdict.HELD
        out.evidence = f"timed_out={result.timed_out} after {result.duration_ms}ms"
        return out

    if kind == "resource_exhaustion":
        hit = any(s in result.signals for s in _EXHAUSTION_SIGNALS) or result.timed_out
        out.verdict = Verdict.FIRED if hit else Verdict.HELD
        out.evidence = (
            f"signals={result.signals} timed_out={result.timed_out} "
            f"peak_ram_mb={result.peak_ram_mb}"
        )
        return out

    if kind == "no_crash":
        # Asserting normality. Used by differential replay and benign verification.
        crashed = result.crashed
        out.verdict = Verdict.HELD if not crashed else Verdict.FIRED
        out.evidence = (
            f"exit {result.exit_code}, signals {result.signals or 'none'}, "
            f"timed_out={result.timed_out}"
        )
        out.detail = (
            "The target behaved normally on this input."
            if not crashed
            else "The target crashed on an input that should be benign."
        )
        return out

    out.verdict = Verdict.UNSUPPORTED
    out.detail = f"No oracle implements kind {kind!r}."
    return out


def _quote_sanitizer(text: str) -> str:
    """The sanitizer's own report, trimmed. Quoted verbatim as evidence."""
    for anchor in ("ERROR: AddressSanitizer", "AddressSanitizer", "runtime error:", "SUMMARY:"):
        index = text.find(anchor)
        if index >= 0:
            return text[index : index + 800]
    return text[-800:]


def require_reproductions(
    results: list[OracleResult], *, required: int
) -> tuple[bool, str]:
    """Did the oracle fire the required number of times, in independent executions?

    This is what makes a reproduction claim mean something. One firing can be a flake, a race, or
    an artefact of a shared workspace; ``required`` independent firings in separate processes is
    the standard the existing validator already holds itself to, and this preserves it for
    generated tests.
    """
    fired = [r for r in results if r.fired]
    if len(fired) >= required:
        return True, (
            f"The oracle fired in {len(fired)} of {len(results)} independent executions "
            f"(required {required})."
        )
    unsupported = [r for r in results if r.verdict == Verdict.UNSUPPORTED]
    if unsupported and not fired:
        return False, (
            f"The oracle could not be evaluated in {len(unsupported)} of {len(results)} "
            "executions, so this is unresolved rather than refuted: "
            + (unsupported[0].detail or "no detail recorded")
        )
    return False, (
        f"The oracle fired in {len(fired)} of {len(results)} executions, below the {required} "
        "independent reproductions required."
    )
