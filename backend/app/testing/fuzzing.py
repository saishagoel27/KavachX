"""Coverage-guided fuzzing: LLM-guided, not LLM-implemented.

The loop the spec describes:

    seed corpus → execute → coverage → mutate → execute → new coverage?
                                                   ├── yes → keep the input
                                                   └── no  → discard it

Everything in that loop is deterministic. The model's role is bounded and specific: every so many
rounds it receives *coverage feedback* — newly reached lines, still-uncovered branches with their
conditions, crashes so far — and proposes candidate inputs and mutation families. Those candidates
are then executed, and **whether they were good is decided by whether coverage actually moved**,
not by the model's confidence in them.

That is the difference between LLM-guided and LLM-implemented fuzzing, and it is why a model that
proposes nonsense costs a round rather than corrupting the campaign: a candidate that reaches
nothing new is discarded by the same rule that discards a random mutation that reaches nothing new.

The corpus is a *set of inputs that each reached something new*, which is the property that makes a
coverage-guided corpus valuable and a blind one merely large.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.core.hashing import sha256_text
from app.core.logging import get_logger
from app.llm.base import LLMRequest, LLMTask
from app.testing.coverage import (
    CoverageObservation,
    UncoveredBranch,
    feedback_payload,
    uncovered_branches,
    unmeasured,
)
from app.testing.specs import FuzzStrategyProposal

logger = get_logger(__name__)

FUZZ_STRATEGY_INSTRUCTION = (
    "Propose inputs and mutation families for a coverage-guided fuzzing campaign.\n"
    "You are given the coverage measured so far, the branches that remain uncovered with their "
    "source conditions, and any crashes found.\n"
    "Propose concrete input values likely to reach the uncovered branches, and the mutation "
    "families worth prioritising.\n"
    "Your proposals are executed and then judged by whether coverage actually increased. Do not "
    "claim an input will work, and do not claim anything is exploitable."
)

#: Deterministic mutation operators. The model may select families; it never supplies an operator,
#: because an operator is code. Mirrors the table in the generated mutation harness.
_OPERATORS: dict[str, Any] = {
    "boundary_values": lambda v: ["", "0", "-1", "1", "2147483647", "-2147483648", "0.0"],
    "negative_numbers": lambda v: ["-1", "-2", "-2147483648"],
    "large_values": lambda v: ["9" * 32, "9" * 512, str(2**63), str(2**64 + 1)],
    "empty_and_null": lambda v: ["", " ", "\t", "null", "None", "undefined"],
    "type_confusion": lambda v: ["[]", "{}", "true", "0", f'"{v}"'],
    "encoding_variants": lambda v: [
        str(v).replace("/", "%2f"),
        str(v).upper(),
        "".join(f"%{ord(c):02x}" for c in str(v)[:24]),
    ],
    "separator_injection": lambda v: [
        f"{v}{sep}echo KAVACHX" for sep in ("&", ";", "|", "&&", "||", "`", "$(")
    ],
    "traversal_sequences": lambda v: [
        f"{prefix}{v}" for prefix in ("../", "..\\", "a/../../", "./../", "..%2f")
    ],
    "length_escalation": lambda v: [str(v) * n for n in (2, 8, 32, 128, 512)],
    # Written as escapes, never as raw characters. A literal NUL in a source file makes the
    # whole module unparseable ("source code string cannot contain null bytes"), which took
    # down the EXECUTE node at import time; a literal RTL override silently reorders the line
    # for anyone reviewing it.
    # Written as source-level escapes, never as raw characters. A literal NUL makes the whole
    # module unparseable ("source code string cannot contain null bytes") and took down the
    # EXECUTE node at import time; a literal U+202E right-to-left override silently reorders
    # the line for anyone reading the diff.
    "unicode_edge_cases": lambda v: ["\x00", "\uffff", "\u202e", "e\u0301", "\U0001f4a9"],
    "format_specifiers": lambda v: ["%s%s%s", "%n", "{0}", "${7*7}", "{{7*7}}"],
    "structural_nesting": lambda v: ["[" * 32 + "]" * 32, "{" * 32 + "}" * 32],
}


@dataclass
class CorpusEntry:
    """An input that reached something new."""

    value: str
    #: Why it was kept: seed | mutation:<family> | model-proposed.
    origin: str
    #: Lines this input reached that nothing before it had.
    new_lines: list[str] = field(default_factory=list)
    round_found: int = 0

    @property
    def digest(self) -> str:
        return sha256_text(self.value)

    def as_dict(self) -> dict[str, Any]:
        return {
            "digest": self.digest[:16],
            "value": self.value[:400],
            "origin": self.origin,
            "new_line_count": len(self.new_lines),
            "new_lines": self.new_lines[:20],
            "round_found": self.round_found,
        }


@dataclass
class FuzzCampaign:
    """The record of one coverage-guided campaign."""

    candidate_ref: str = ""
    rounds_run: int = 0
    executions: int = 0
    corpus: list[CorpusEntry] = field(default_factory=list)
    #: Inputs whose oracle fired. The whole point of the campaign.
    crashes: list[dict[str, Any]] = field(default_factory=list)
    coverage: dict[str, Any] = field(default_factory=dict)
    coverage_growth: list[dict[str, Any]] = field(default_factory=list)
    uncovered_branches: list[dict[str, Any]] = field(default_factory=list)
    model_rounds: int = 0
    model_candidates: int = 0
    #: Model-proposed inputs that actually reached something new. The honest score for the
    #: model's contribution — it is measured, not assumed.
    model_candidates_useful: int = 0
    model_errors: list[str] = field(default_factory=list)
    duration_ms: int = 0
    stopped_because: str = ""
    tool_events: list[dict[str, Any]] = field(default_factory=list)

    @property
    def found_signal(self) -> bool:
        return bool(self.crashes)

    def as_dict(self) -> dict[str, Any]:
        return {
            "candidate_ref": self.candidate_ref,
            "rounds_run": self.rounds_run,
            "executions": self.executions,
            "corpus_size": len(self.corpus),
            "corpus": [c.as_dict() for c in self.corpus[:60]],
            "crashes": self.crashes[:20],
            "found_signal": self.found_signal,
            "coverage": self.coverage,
            "coverage_growth": self.coverage_growth,
            "uncovered_branches": self.uncovered_branches[:20],
            "model": {
                "rounds": self.model_rounds,
                "candidates": self.model_candidates,
                "candidates_useful": self.model_candidates_useful,
                "errors": self.model_errors[:5],
            },
            "duration_ms": self.duration_ms,
            "stopped_because": self.stopped_because,
        }


class CoverageGuidedFuzzer:
    """The deterministic loop. The model advises; coverage decides."""

    def __init__(
        self,
        *,
        executor: Any,
        code_graph: Any,
        workspace: Path,
        provider: Any = None,
        model_every_rounds: int = 3,
    ) -> None:
        self.executor = executor
        self.code_graph = code_graph
        self.workspace = workspace
        self.provider = provider
        self.model_every_rounds = max(1, model_every_rounds)

    # ------------------------------------------------------------------
    async def run(
        self,
        plan: Any,
        *,
        seeds: list[str] | None = None,
        max_rounds: int = 6,
        max_executions: int = 60,
        focus_symbols: list[str] | None = None,
    ) -> FuzzCampaign:
        """Drive the campaign for one plan."""
        started = time.perf_counter()
        campaign = FuzzCampaign(candidate_ref=getattr(plan, "candidate_ref", ""))

        families = list(plan.spec.fuzz.mutations) if plan.spec.fuzz else ["boundary_values"]
        queue: list[tuple[str, str]] = [
            (value, "seed")
            for value in (seeds or (plan.spec.fuzz.seeds if plan.spec.fuzz else []) or plan.spec.payloads or [""])
        ]
        accumulated = unmeasured("The campaign has not executed yet.")
        seen_inputs: set[str] = set()

        for round_index in range(1, max_rounds + 1):
            if campaign.executions >= max_executions:
                campaign.stopped_because = (
                    f"execution budget of {max_executions} runs was reached; the campaign is "
                    "bounded, not exhaustive"
                )
                break
            if not queue:
                campaign.stopped_because = "no candidate inputs remained to try"
                break

            campaign.rounds_run = round_index
            round_coverage = accumulated
            batch, queue = queue[:12], queue[12:]

            for value, origin in batch:
                digest = sha256_text(value)
                if digest in seen_inputs or campaign.executions >= max_executions:
                    continue
                seen_inputs.add(digest)

                record = await self._execute_one(plan, value)
                campaign.executions += 1
                if record is None:
                    continue

                observation = _coverage_from(record)
                new_lines = observation.new_relative_to(round_coverage)
                if new_lines:
                    campaign.corpus.append(
                        CorpusEntry(
                            value=value,
                            origin=origin,
                            new_lines=sorted(new_lines),
                            round_found=round_index,
                        )
                    )
                    if origin == "model-proposed":
                        campaign.model_candidates_useful += 1
                    round_coverage = round_coverage.merge(observation)

                if record.reproduced:
                    campaign.crashes.append(
                        {
                            "input": value[:400],
                            "input_digest": digest[:16],
                            "origin": origin,
                            "evidence": record.proving_evidence[:400],
                            "reproduction_count": record.reproduction_count,
                            "round": round_index,
                        }
                    )
                    if plan.spec.fuzz is None or plan.spec.fuzz.stop_on_first_signal:
                        campaign.stopped_because = (
                            "the oracle fired and the spec asked to stop on the first signal"
                        )
                        accumulated = round_coverage
                        campaign.coverage_growth.append(
                            _growth(round_index, accumulated, len(campaign.corpus))
                        )
                        return self._finish(campaign, accumulated, focus_symbols, started)

            accumulated = round_coverage
            campaign.coverage_growth.append(
                _growth(round_index, accumulated, len(campaign.corpus))
            )

            # -- extend the queue: deterministic mutations of the corpus ---
            branches = uncovered_branches(
                code_graph=self.code_graph,
                coverage=accumulated,
                root=self.workspace,
                focus_symbols=focus_symbols,
                limit=20,
            )
            queue.extend(_mutate(campaign.corpus, families, branches))

            # -- ask the model, periodically -------------------------------
            if self.provider is not None and round_index % self.model_every_rounds == 0:
                proposed, error = await self._ask_model(accumulated, branches, campaign)
                campaign.model_rounds += 1
                if error:
                    campaign.model_errors.append(error)
                for value in proposed:
                    campaign.model_candidates += 1
                    queue.append((value, "model-proposed"))

        if not campaign.stopped_because:
            campaign.stopped_because = f"round limit of {max_rounds} was reached"
        return self._finish(campaign, accumulated, focus_symbols, started)

    # ------------------------------------------------------------------
    def _finish(
        self,
        campaign: FuzzCampaign,
        coverage: CoverageObservation,
        focus_symbols: list[str] | None,
        started: float,
    ) -> FuzzCampaign:
        campaign.coverage = coverage.as_dict()
        campaign.uncovered_branches = [
            b.as_dict()
            for b in uncovered_branches(
                code_graph=self.code_graph,
                coverage=coverage,
                root=self.workspace,
                focus_symbols=focus_symbols,
                limit=20,
            )
        ]
        campaign.duration_ms = int((time.perf_counter() - started) * 1000)
        campaign.tool_events.append(
            {
                "name": "fuzz:coverage-guided",
                "target": campaign.candidate_ref,
                "ms": campaign.duration_ms,
                "ok": True,
                "detail": (
                    f"{campaign.executions} execution(s), corpus {len(campaign.corpus)}, "
                    f"{len(campaign.crashes)} signal(s), coverage "
                    f"{coverage.percent:.1f}% — {campaign.stopped_because}"
                ),
            }
        )
        logger.info(
            "testing.fuzz_campaign",
            candidate=campaign.candidate_ref,
            rounds=campaign.rounds_run,
            executions=campaign.executions,
            corpus=len(campaign.corpus),
            crashes=len(campaign.crashes),
            model_useful=campaign.model_candidates_useful,
            model_candidates=campaign.model_candidates,
        )
        return campaign

    async def _execute_one(self, plan: Any, value: str) -> Any:
        """Run the plan once with ``value`` substituted as its payload."""
        import copy

        # A shallow copy with a replaced payload: the harness is regenerated per input by the
        # caller for engines that need it, and for the mutation harness the value rides in the
        # request template.
        candidate = copy.deepcopy(plan)
        candidate.spec.payloads = [value]
        try:
            from app.testing import harness as harness_mod

            generated = harness_mod.generate(
                candidate, workspace=self.workspace, descriptor=self.executor.descriptor
            )
            if not generated.ok:
                return None
            harness_mod.attach(candidate, generated)
            return await self.executor.execute(candidate, collect_coverage=True)
        except Exception as exc:  # pragma: no cover - one bad input must not end the campaign
            logger.warning("testing.fuzz_execution_failed", error=str(exc)[:200])
            return None

    async def _ask_model(
        self,
        coverage: CoverageObservation,
        branches: list[UncoveredBranch],
        campaign: FuzzCampaign,
    ) -> tuple[list[str], str]:
        previous = None
        if campaign.coverage_growth:
            previous = coverage  # growth is recorded per round; the delta is already reflected
        payload = feedback_payload(
            coverage=coverage,
            previous=previous,
            branches=branches,
            crashes=campaign.crashes,
        )
        try:
            response = await self.provider.generate(
                LLMRequest(
                    task=LLMTask.FUZZ_STRATEGY,
                    instruction=FUZZ_STRATEGY_INSTRUCTION,
                    payload=payload,
                    schema=FuzzStrategyProposal,
                    model_hint="workhorse",
                )
            )
        except Exception as exc:
            return [], f"{type(exc).__name__}: {str(exc)[:200]}"
        return list(response.parsed.candidate_inputs)[:24], ""


# ---------------------------------------------------------------------------
def _coverage_from(record: Any) -> CoverageObservation:
    """Rebuild a coverage observation from an execution record's serialised coverage."""
    payload = getattr(record, "coverage", {}) or {}
    if not payload.get("measured"):
        return unmeasured(str(payload.get("reason", "coverage was not measured")))
    return CoverageObservation(
        covered_lines=set(payload.get("covered_lines_sample") or []),
        covered_scopes=set(payload.get("covered_scopes") or []),
        total_statements=int(payload.get("total_statements", 0) or 0),
        covered_statements=int(payload.get("covered_statements", 0) or 0),
        source=str(payload.get("source", "kx_observe")),
        measured=True,
    )


def _mutate(
    corpus: list[CorpusEntry],
    families: list[str],
    branches: list[UncoveredBranch],
) -> list[tuple[str, str]]:
    """Next round's candidates: mutations of interesting inputs, plus branch-derived values.

    Branch-derived values come first. This is the code-aware part: a value taken from the literal
    an uncovered ``if`` compares against is far more likely to flip that branch than a random
    mutation, and trying it first is what makes the campaign converge rather than wander.
    """
    out: list[tuple[str, str]] = []

    for branch in branches:
        for value in branch.suggested_values[:6]:
            out.append((value, f"branch:{branch.location}"))

    bases = [entry.value for entry in corpus[-6:]] or [""]
    for base in bases:
        for family in families:
            operator = _OPERATORS.get(family)
            if operator is None:
                continue
            try:
                for value in operator(base)[:8]:
                    out.append((str(value), f"mutation:{family}"))
            except Exception:  # pragma: no cover - an operator must never end the round
                continue
    return out[:48]


def _growth(round_index: int, coverage: CoverageObservation, corpus_size: int) -> dict[str, Any]:
    return {
        "round": round_index,
        "coverage_percent": coverage.percent,
        "covered_lines": len(coverage.covered_lines),
        "corpus_size": corpus_size,
    }
