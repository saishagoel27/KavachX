"""Shared types for the four discovery channels.

Every channel produces :class:`HypothesisCandidate` objects and pushes them into the same
queue. No channel may mark anything validated, and no channel blocks another — they are run
concurrently and their results merged.

The ``validation_plan`` is the important field: it is a machine-readable recipe the validator
turns into an executable sandbox job. A candidate with no plan can never be validated, so it
goes straight to the unknown ledger with that as its stated reason. That is deliberate — it
keeps "we found something suspicious" and "we proved something" permanently separate.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.models.enums import DiscoveryChannel, Severity

#: Marker the validator looks for in sandbox output to prove command execution. Distinctive
#: enough that it cannot occur by accident in a target's own output.
POV_MARKER = "KAVACHX_POV_MARKER_7F3A"
#: File planted outside the asset root; reading it proves a containment escape.
CANARY_FILENAME = "KAVACHX_CANARY.txt"
CANARY_CONTENT = "KAVACHX_CANARY_CONTENT_D91C"

#: Stand-in for the reachability factor when the call graph cannot supply one. Only consulted when
#: ``HypothesisCandidate.reachability_measured`` is False.
_SEVERITY_WEIGHT: dict[str, float] = {
    Severity.CRITICAL.value: 1.0,
    Severity.HIGH.value: 0.8,
    Severity.MEDIUM.value: 0.5,
    Severity.LOW.value: 0.25,
    Severity.INFO.value: 0.1,
}


@dataclass(slots=True)
class HypothesisCandidate:
    handle: str
    source_channel: str
    description: str
    location: str
    severity: str = Severity.MEDIUM.value
    reachability: float = 0.0
    confidence: float = 0.0
    blast_radius: float = 0.0
    cwe: str = ""
    candidate_clause_id: str = ""
    evidence_refs: list[str] = field(default_factory=list)
    validation_plan: dict[str, Any] = field(default_factory=dict)
    #: Populated when the channel already knows the candidate cannot be validated.
    unknown_reason: str = ""
    rule_id: str = ""
    #: Structured reasoning summary surfaced in the console trace.
    hypothesis_statement: str = ""
    decision: str = ""
    #: False when no call graph path could be computed because the target has no entrypoint — a
    #: static-only run. See the ``priority`` property for why this changes the formula.
    reachability_measured: bool = True

    @property
    def priority(self) -> float:
        """``reachability × confidence × blast_radius`` — persisted, never recomputed ad hoc.

        **When reachability could not be measured**, severity stands in for it. Without an
        entrypoint there is no path to search, so ``reachability_score`` returns its floor for
        *everything* — and multiplying every code finding by that floor does not merely add noise,
        it inverts the ranking. Observed on a real repository: SQL injection, template injection and
        unsafe deserialisation all landed at 0.01, below a LOW "container may run as root" note at
        0.12, because the config channel legitimately knows its own findings are reachable (config is
        read at startup) while the graph could say nothing about the code.

        An operator reading that queue top-down would have seen the Dockerfile note first and the
        remote code execution last. Severity is the honest stand-in: it answers the same question
        the reachability factor was there to answer — *how much should I care?* — using the evidence
        that does exist. The substitution is recorded on the candidate and explained by the run's
        ``static_only`` mode, so the number is never presented as a measurement it isn't.

        **Blast radius is dropped in that case, not substituted.** It comes from the same call graph
        that could not find an entrypoint, so it floors uniformly for every code finding too —
        multiplying by a constant only rescales the ranking while implying a measurement that was
        never taken. Channels that *assert* their own blast radius from evidence other than the graph
        (configuration is read at startup, so the config channel knows its own reachability) keep all
        three factors, because for them all three mean something.
        """
        if not self.reachability_measured:
            return round(
                max(self._severity_weight(), 0.01) * max(self.confidence, 0.01),
                6,
            )
        return round(
            max(self.reachability, 0.01)
            * max(self.confidence, 0.01)
            * max(self.blast_radius, 0.01),
            6,
        )

    def _severity_weight(self) -> float:
        return _SEVERITY_WEIGHT.get(self.severity, 0.3)

    def as_dict(self) -> dict[str, Any]:
        return {
            "handle": self.handle,
            "source_channel": self.source_channel,
            "description": self.description,
            "location": self.location,
            "severity": self.severity,
            "reachability": self.reachability,
            "reachability_measured": self.reachability_measured,
            "confidence": self.confidence,
            "blast_radius": self.blast_radius,
            "priority": self.priority,
            "cwe": self.cwe,
            "candidate_clause_id": self.candidate_clause_id,
            "evidence_refs": self.evidence_refs,
            "validation_plan": self.validation_plan,
            "unknown_reason": self.unknown_reason,
            "rule_id": self.rule_id,
        }


@dataclass
class ChannelResult:
    channel: str
    candidates: list[HypothesisCandidate] = field(default_factory=list)
    tool_events: list[dict[str, Any]] = field(default_factory=list)
    thoughts: list[dict[str, Any]] = field(default_factory=list)
    model_calls: list[dict[str, Any]] = field(default_factory=list)
    error: str = ""
    duration_ms: int = 0
    #: What the channel actually covered, for REMAINING.md.
    coverage_notes: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "channel": self.channel,
            "candidates": len(self.candidates),
            "duration_ms": self.duration_ms,
            "error": self.error,
            "coverage_notes": self.coverage_notes,
        }


CHANNEL_LABELS = {
    DiscoveryChannel.GRAPH_STATIC.value: "GRAPH / STATIC",
    DiscoveryChannel.CONFIG_REACHABILITY.value: "CONFIG / REACHABILITY",
    DiscoveryChannel.FUZZING.value: "FUZZING",
    DiscoveryChannel.RUNTIME.value: "RUNTIME",
}
