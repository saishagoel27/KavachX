"""The security graph: sources, sinks, sanitizers, controls, trust boundaries and flows.

This is the layer the spec calls for over the general code graph. The code graph knows that
``handle`` calls ``export_report``; the security graph knows that an attacker-controlled request
field reaches a shell invocation through that call, that nothing sanitised it on the way, and that
the path crosses the CLI→application and application→shell trust boundaries.

The central object is :class:`SecurityFlow`. It exists so the reasoning layer receives a
*structured path* rather than being asked to infer one from a pile of source, and so every claim
about that path can be traced to the evidence that produced it:

* ``basis`` — how the flow was established (``taint`` from AST derivation, ``call-graph`` from
  stitching two functions' taint across a resolved call edge, ``proximity`` for the weakest
  same-function fallback in languages with no taint analyser).
* ``precision`` — whether the call path used only resolved edges or admitted name-matched ones.
* ``sanitizers`` / ``validators`` — controls found *on this value*, recorded as evidence and
  never as a clearance.
* ``confidence`` — deterministic, derived from all of the above.

A flow is never a finding. It is the best-evidenced hypothesis the static layer can produce, and
:mod:`app.validator` still has to reproduce it by execution before anything is called validated.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from app.core.hashing import sha256_json
from app.core.logging import get_logger
from app.security_model.taxonomy import (
    SOURCE_BOUNDARY,
    SecurityCategory,
    TrustBoundaryKind,
)

logger = get_logger(__name__)


@dataclass
class SecurityNode:
    """A code location with a security role."""

    #: Stable ref: ``sec:<category>:<file>:<line>``.
    ref: str
    category: str
    kind: str
    file: str
    line: int
    #: Owning callable's uid in the code graph, when one encloses this line.
    owner: str = ""
    rule_id: str = ""
    cwe: str = ""
    severity: str = "MEDIUM"
    snippet: str = ""
    why: str = ""
    confidence: float = 0.5

    def as_dict(self) -> dict[str, Any]:
        return {
            "ref": self.ref,
            "category": self.category,
            "kind": self.kind,
            "file": self.file,
            "line": self.line,
            # Serialised as well as available as a property: every consumer (tools, UI, evidence
            # graph) wants `file:line` as one string, and recomputing it in each of them is how
            # two of them end up formatting it differently.
            "location": self.location,
            "owner": self.owner,
            "rule_id": self.rule_id,
            "cwe": self.cwe,
            "severity": self.severity,
            "snippet": self.snippet,
            "why": self.why,
            "confidence": round(self.confidence, 3),
        }

    @property
    def location(self) -> str:
        return f"{self.file}:{self.line}"


@dataclass
class TrustBoundary:
    """A crossing between trust domains, and what crosses it."""

    kind: str
    #: Refs of the security nodes that sit on this boundary.
    members: list[str] = field(default_factory=list)
    description: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "description": self.description,
            "members": self.members[:60],
            "member_count": len(self.members),
        }


@dataclass
class FlowStep:
    """One hop of a security flow, at whatever granularity is known."""

    kind: str  # source | call | transform | sanitize | validate | sink
    location: str
    detail: str = ""
    symbol: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "location": self.location,
            "detail": self.detail,
            "symbol": self.symbol,
        }


@dataclass
class SecurityFlow:
    """An evidenced path from an external input to a dangerous operation."""

    #: ``flow:<source ref>-><sink ref>``.
    ref: str
    source_ref: str
    sink_ref: str
    source_kind: str
    sink_kind: str
    cwe: str = ""
    severity: str = "MEDIUM"
    #: Ordered, human-readable path. This is what the LLM receives instead of a repository dump.
    steps: list[FlowStep] = field(default_factory=list)
    #: Code-graph uids of the callables the value passes through, source-side first.
    call_path: list[str] = field(default_factory=list)
    sanitizers: list[str] = field(default_factory=list)
    validators: list[str] = field(default_factory=list)
    boundaries: list[str] = field(default_factory=list)
    #: taint | call-graph | proximity
    basis: str = "taint"
    #: resolved | union — which edges the call path was allowed to use.
    precision: str = "union"
    #: Entrypoint the source is reachable from, when one is.
    entrypoint: str = ""
    reachable_from_entrypoint: bool = False
    reachability_measured: bool = True
    #: True when the value is interpolated into a string before the sink (injection shape).
    interpolated: bool = False
    confidence: float = 0.0
    #: Tests that statically reference any symbol on the path.
    covering_tests: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def sanitized(self) -> bool:
        return bool(self.sanitizers)

    @property
    def crosses_trust_boundary(self) -> bool:
        return bool(self.boundaries)

    def explain(self) -> list[str]:
        """The flow as an ordered, readable path. Used in thoughts, docs and certificates."""
        return [f"{step.kind.upper():9} {step.location}  {step.detail}".rstrip() for step in self.steps]

    def as_dict(self) -> dict[str, Any]:
        return {
            "ref": self.ref,
            "source_ref": self.source_ref,
            "sink_ref": self.sink_ref,
            "source_kind": self.source_kind,
            "sink_kind": self.sink_kind,
            "cwe": self.cwe,
            "severity": self.severity,
            "steps": [s.as_dict() for s in self.steps],
            "call_path": self.call_path,
            "sanitizers": self.sanitizers,
            "validators": self.validators,
            "sanitized": self.sanitized,
            "boundaries": self.boundaries,
            "crosses_trust_boundary": self.crosses_trust_boundary,
            "basis": self.basis,
            "precision": self.precision,
            "entrypoint": self.entrypoint,
            "reachable_from_entrypoint": self.reachable_from_entrypoint,
            "reachability_measured": self.reachability_measured,
            "interpolated": self.interpolated,
            "confidence": round(self.confidence, 3),
            "covering_tests": self.covering_tests,
            "notes": self.notes,
        }


@dataclass
class SecurityGraph:
    """Every security-relevant fact derived over one code graph."""

    SCHEMA = "kavachx.security_graph.v1"

    nodes: dict[str, SecurityNode] = field(default_factory=dict)
    flows: list[SecurityFlow] = field(default_factory=list)
    boundaries: dict[str, TrustBoundary] = field(default_factory=dict)
    #: Taxonomy provenance, so a certificate can state which rule set produced these facts.
    taxonomy_summary: dict[str, Any] = field(default_factory=dict)
    #: Files the taint analyser could not parse, and why.
    parse_errors: list[dict[str, str]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    # -- construction ------------------------------------------------------
    def add_node(self, node: SecurityNode) -> SecurityNode:
        existing = self.nodes.get(node.ref)
        if existing is not None:
            # Same location matched by two rules: keep the higher-confidence classification but
            # remember that both fired, because a location that is both a sink and a sanitizer is
            # worth a human look.
            if node.confidence > existing.confidence:
                node.why = f"{node.why} (also matched {existing.rule_id})".strip()
                self.nodes[node.ref] = node
                return node
            existing.why = f"{existing.why} (also matched {node.rule_id})".strip()
            return existing
        self.nodes[node.ref] = node
        return node

    def add_flow(self, flow: SecurityFlow) -> SecurityFlow:
        existing = next((f for f in self.flows if f.ref == flow.ref), None)
        if existing is not None:
            if flow.confidence > existing.confidence:
                self.flows[self.flows.index(existing)] = flow
                return flow
            return existing
        self.flows.append(flow)
        return flow

    def add_boundary(self, kind: str, member_ref: str, description: str = "") -> None:
        boundary = self.boundaries.get(kind)
        if boundary is None:
            boundary = TrustBoundary(kind=kind, description=description or _boundary_text(kind))
            self.boundaries[kind] = boundary
        if member_ref not in boundary.members:
            boundary.members.append(member_ref)

    # -- queries -----------------------------------------------------------
    def of_category(self, category: str) -> list[SecurityNode]:
        return [n for n in self.nodes.values() if n.category == category]

    @property
    def sources(self) -> list[SecurityNode]:
        return self.of_category(SecurityCategory.SOURCE.value)

    @property
    def sinks(self) -> list[SecurityNode]:
        return self.of_category(SecurityCategory.SINK.value)

    @property
    def sanitizers(self) -> list[SecurityNode]:
        return self.of_category(SecurityCategory.SANITIZER.value)

    @property
    def validators(self) -> list[SecurityNode]:
        return self.of_category(SecurityCategory.VALIDATOR.value)

    @property
    def controls(self) -> list[SecurityNode]:
        return [
            n
            for n in self.nodes.values()
            if n.category
            in (
                SecurityCategory.AUTHENTICATION_CHECK.value,
                SecurityCategory.AUTHORIZATION_CHECK.value,
            )
        ]

    @property
    def reachable_flows(self) -> list[SecurityFlow]:
        """Flows whose source is reachable from a declared entrypoint.

        When reachability could not be measured (no entrypoints), this is empty — and callers must
        read that as "not measured", which is why :attr:`unmeasured_flows` exists separately.
        """
        return [f for f in self.flows if f.reachable_from_entrypoint]

    @property
    def unmeasured_flows(self) -> list[SecurityFlow]:
        return [f for f in self.flows if not f.reachability_measured]

    def flows_for_sink(self, location: str) -> list[SecurityFlow]:
        return [f for f in self.flows if self.nodes.get(f.sink_ref, None) and
                self.nodes[f.sink_ref].location == location]

    def flows_through(self, uid: str) -> list[SecurityFlow]:
        return [f for f in self.flows if uid in f.call_path]

    def nodes_in(self, file: str) -> list[SecurityNode]:
        return [n for n in self.nodes.values() if n.file == file]

    def sinks_owned_by(self, uid: str) -> list[SecurityNode]:
        return [n for n in self.sinks if n.owner == uid]

    def sources_owned_by(self, uid: str) -> list[SecurityNode]:
        return [n for n in self.sources if n.owner == uid]

    def top_flows(self, limit: int = 20) -> list[SecurityFlow]:
        """The flows most worth a reviewer's attention, in a deterministic order.

        Ordered by **reachability, then severity, then confidence**. Severity has to come before
        confidence: this ordering drives both the console display and which flows are selected
        into the model's context, and sorting on confidence alone put a MEDIUM path-traversal
        candidate above a CRITICAL shell injection on the seeded demo target purely because the
        traversal happened to be taint-proven within one function while the injection crossed
        three call boundaries. A reviewer reading top-down needs the remote-code-execution first.

        Confidence still decides *within* a severity band, so a well-evidenced CRITICAL outranks a
        speculative one, and the confidence number itself is never adjusted to achieve an
        ordering — it keeps meaning "how strong is the evidence".
        """
        return sorted(
            self.flows,
            key=lambda f: (
                not f.reachable_from_entrypoint,
                -_severity_rank(f.severity),
                -f.confidence,
                f.ref,
            ),
        )[:limit]

    # -- serialisation -----------------------------------------------------
    def stats(self) -> dict[str, Any]:
        by_source_kind: dict[str, int] = defaultdict(int)
        for node in self.sources:
            by_source_kind[node.kind] += 1
        by_sink_kind: dict[str, int] = defaultdict(int)
        for node in self.sinks:
            by_sink_kind[node.kind] += 1
        by_basis: dict[str, int] = defaultdict(int)
        for flow in self.flows:
            by_basis[flow.basis] += 1
        return {
            "sources": len(self.sources),
            "sinks": len(self.sinks),
            "sanitizers": len(self.sanitizers),
            "validators": len(self.validators),
            "controls": len(self.controls),
            "flows": len(self.flows),
            "reachable_flows": len(self.reachable_flows),
            "sanitized_flows": len([f for f in self.flows if f.sanitized]),
            "unmeasured_flows": len(self.unmeasured_flows),
            "trust_boundaries": len(self.boundaries),
            "by_source_kind": dict(sorted(by_source_kind.items())),
            "by_sink_kind": dict(sorted(by_sink_kind.items())),
            "by_flow_basis": dict(sorted(by_basis.items())),
            "parse_errors": len(self.parse_errors),
        }

    def as_dict(self, *, flow_limit: int = 400) -> dict[str, Any]:
        return {
            "schema": self.SCHEMA,
            "stats": self.stats(),
            "taxonomy": self.taxonomy_summary,
            "nodes": [n.as_dict() for n in sorted(self.nodes.values(), key=lambda n: n.ref)],
            "flows": [f.as_dict() for f in self.top_flows(flow_limit)],
            "trust_boundaries": [
                b.as_dict() for b in sorted(self.boundaries.values(), key=lambda b: b.kind)
            ],
            "parse_errors": self.parse_errors[:50],
            "warnings": self.warnings[:50],
        }

    def content_hash(self) -> str:
        return sha256_json(
            {
                "schema": self.SCHEMA,
                "nodes": sorted(
                    [n.ref, n.category, n.kind, n.rule_id] for n in self.nodes.values()
                ),
                "flows": sorted(
                    [f.ref, f.basis, f.precision, str(f.sanitized)] for f in self.flows
                ),
            }
        )

    def subgraph_for_flow(self, ref: str) -> dict[str, Any]:
        """SOURCE → TRANSFORMATION → SANITIZER → SINK for one flow, for the UI."""
        flow = next((f for f in self.flows if f.ref == ref), None)
        if flow is None:
            return {}
        refs = {flow.source_ref, flow.sink_ref}
        return {
            "flow": flow.as_dict(),
            "nodes": [n.as_dict() for n in self.nodes.values() if n.ref in refs],
            "call_path": flow.call_path,
            "boundaries": [
                self.boundaries[kind].as_dict()
                for kind in flow.boundaries
                if kind in self.boundaries
            ],
        }


# ---------------------------------------------------------------------------
def _severity_rank(severity: str) -> int:
    """Numeric severity, reusing the domain enum so the two can never disagree."""
    from app.models.enums import SEVERITY_RANK

    return SEVERITY_RANK.get(severity, 0)


def node_ref(category: str, file: str, line: int) -> str:
    return f"sec:{category.lower()}:{file}:{line}"


def flow_ref(source_ref: str, sink_ref: str) -> str:
    return f"flow:{source_ref}->{sink_ref}"


def _boundary_text(kind: str) -> str:
    return {
        TrustBoundaryKind.HTTP_TO_APP.value: "HTTP → application: request data enters the process.",
        TrustBoundaryKind.CLI_TO_APP.value: (
            "CLI → application: argv and stdin enter the process."
        ),
        TrustBoundaryKind.APP_TO_DATABASE.value: (
            "application → database: a query leaves the process as SQL."
        ),
        TrustBoundaryKind.APP_TO_SHELL.value: (
            "application → shell: a command line is handed to a shell or a new process."
        ),
        TrustBoundaryKind.APP_TO_FILESYSTEM.value: (
            "application → filesystem: a path is resolved and opened."
        ),
        TrustBoundaryKind.APP_TO_NETWORK.value: (
            "application → network: a request leaves for another host."
        ),
        TrustBoundaryKind.APP_TO_TEMPLATE.value: (
            "application → template engine: a string is compiled and evaluated."
        ),
        TrustBoundaryKind.APP_TO_DESERIALISER.value: (
            "application → deserialiser: bytes become objects."
        ),
        TrustBoundaryKind.ENV_TO_APP.value: (
            "environment → application: configuration set outside the process enters it."
        ),
        TrustBoundaryKind.FILE_TO_APP.value: (
            "file → application: stored bytes enter the process."
        ),
        TrustBoundaryKind.QUEUE_TO_APP.value: (
            "queue → application: a message from another producer enters the process."
        ),
    }.get(kind, kind.replace("_", " "))


def boundaries_for(source_kind: str, sink_kind: str) -> list[str]:
    """Trust boundaries a flow from ``source_kind`` to ``sink_kind`` crosses."""
    from app.security_model.taxonomy import SINK_BOUNDARY

    out: list[str] = []
    entry = SOURCE_BOUNDARY.get(source_kind)
    if entry:
        out.append(entry)
    exit_boundary = SINK_BOUNDARY.get(sink_kind)
    if exit_boundary and exit_boundary not in out:
        out.append(exit_boundary)
    return out
