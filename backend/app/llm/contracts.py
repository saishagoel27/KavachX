"""Strict schemas for every model response.

Nothing the model says is trusted until it validates against one of these. Note what is
*absent*: no field anywhere lets a model assert that something is verified, reproduced,
passing or safe. Those values are only ever written by deterministic components.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


# --------------------------------------------------------------------------
# SAMHITA clause proposal
# --------------------------------------------------------------------------
class ProposedClause(StrictModel):
    kind: str = Field(max_length=60)
    description: str = Field(min_length=8, max_length=500)
    #: A single boolean Python expression over the observation namespace. The deterministic
    #: compiler re-parses this with a restricted AST walker; anything else is rejected.
    predicate: str = Field(min_length=3, max_length=400)
    scope: str = Field(min_length=1, max_length=200)
    rationale: str = Field(default="", max_length=600)
    confidence: float = Field(ge=0.0, le=1.0, default=0.5)

    @field_validator("predicate")
    @classmethod
    def _no_statements(cls, v: str) -> str:
        if "\n" in v or ";" in v:
            raise ValueError("predicate must be a single expression")
        return v


class ClauseProposal(StrictModel):
    # A real contract for even a small service runs to dozens of clauses across scopes. A tight
    # cap here silently truncates whole modules out of SAMHITA — the clauses for the last
    # module alphabetically simply never get proposed.
    clauses: list[ProposedClause] = Field(default_factory=list, max_length=200)


# --------------------------------------------------------------------------
# Root cause hypothesis
# --------------------------------------------------------------------------
class RootCauseHypothesis(StrictModel):
    #: ``relative/path.py:LINE``
    location: str = Field(min_length=3, max_length=300)
    function: str = Field(default="", max_length=200)
    summary: str = Field(min_length=8, max_length=800)
    causal_chain: list[str] = Field(default_factory=list, max_length=12)
    minimal_patch_location: str = Field(default="", max_length=300)
    confidence: float = Field(ge=0.0, le=1.0, default=0.5)


# --------------------------------------------------------------------------
# Patch synthesis
# --------------------------------------------------------------------------
class PatchProposalFile(StrictModel):
    path: str = Field(min_length=1, max_length=400)
    #: Full replacement content for the file. The applier produces the unified diff itself,
    #: so a malformed model-authored diff cannot corrupt the workspace.
    new_content: str


class PatchProposal(StrictModel):
    reason: str = Field(min_length=8, max_length=2000)
    files: list[PatchProposalFile] = Field(min_length=1, max_length=8)
    risk: Literal["low", "medium", "high"] = "medium"
    expected_effect: str = Field(min_length=8, max_length=1200)
    invariants_preserved: list[str] = Field(default_factory=list, max_length=20)


# --------------------------------------------------------------------------
# Refutation strategy proposal (exploit mutation)
# --------------------------------------------------------------------------
class MutationStrategy(StrictModel):
    name: str = Field(min_length=2, max_length=80)
    payload: str = Field(max_length=4000)
    rationale: str = Field(default="", max_length=400)


class MutationProposal(StrictModel):
    strategies: list[MutationStrategy] = Field(default_factory=list, max_length=32)


# --------------------------------------------------------------------------
# Sibling-hunt candidate locations
# --------------------------------------------------------------------------
class SiblingCandidate(StrictModel):
    location: str = Field(min_length=3, max_length=300)
    function: str = Field(default="", max_length=200)
    why: str = Field(default="", max_length=400)
    confidence: float = Field(ge=0.0, le=1.0, default=0.5)


class SiblingProposal(StrictModel):
    candidates: list[SiblingCandidate] = Field(default_factory=list, max_length=24)


# --------------------------------------------------------------------------
# Interface / entrypoint hypothesis produced during probe
# --------------------------------------------------------------------------
class InterfaceHypothesis(StrictModel):
    entrypoint: str = Field(min_length=1, max_length=300)
    kind: Literal["cli", "http", "library", "worker", "unknown"] = "unknown"
    input_description: str = Field(default="", max_length=400)
    confidence: float = Field(ge=0.0, le=1.0, default=0.5)


class ProbeProposal(StrictModel):
    interfaces: list[InterfaceHypothesis] = Field(default_factory=list, max_length=20)
    build_command: str = Field(default="", max_length=400)
    test_command: str = Field(default="", max_length=400)


# --------------------------------------------------------------------------
# Static-analysis triage
# --------------------------------------------------------------------------
class TriagedCandidate(StrictModel):
    rule_id: str = Field(max_length=120)
    location: str = Field(max_length=300)
    description: str = Field(max_length=600)
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] = "MEDIUM"
    candidate_clause_kind: str = Field(default="", max_length=60)
    confidence: float = Field(ge=0.0, le=1.0, default=0.5)
    cwe: str = Field(default="", max_length=32)


class TriageProposal(StrictModel):
    candidates: list[TriagedCandidate] = Field(default_factory=list, max_length=40)
