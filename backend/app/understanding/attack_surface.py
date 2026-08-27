"""Attack-surface modelling: what an attacker can touch, and what it reaches.

The security graph knows every source, sink and flow. The attack surface answers the narrower
question a reviewer actually starts from: *which externally reachable entry points lead to
dangerous operations, and in what order should they be looked at?*

The ranking is deterministic and its factors are recorded per item, so a queue position is always
explainable. It reuses the priority factors the spec lists — reachability, external
controllability, sink severity, data-flow confidence, existing controls, testability, coverage —
and it never lets a model assign them.

One property is deliberately preserved from the existing hypothesis queue: when reachability could
not be measured, it is **not** silently treated as zero. A target with no entrypoints has an
unknown attack surface, not an empty one, and :attr:`AttackSurface.measured` says which.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.core.hashing import sha256_json
from app.core.logging import get_logger
from app.indexing.model import CodeGraph
from app.models.enums import SEVERITY_RANK
from app.security_model.graph import SecurityGraph
from app.security_model.taxonomy import SourceKind

logger = get_logger(__name__)

#: Source kinds an unauthenticated remote attacker controls directly. Anything reached from one of
#: these is externally controllable in the strongest sense.
_REMOTE_SOURCES: frozenset[str] = frozenset(
    {
        SourceKind.HTTP_PARAM.value,
        SourceKind.HTTP_BODY.value,
        SourceKind.HTTP_HEADER.value,
        SourceKind.HTTP_COOKIE.value,
        SourceKind.HTTP_PATH.value,
        SourceKind.UPLOADED_FILE.value,
    }
)

#: Source kinds controlled by whoever can invoke the process — a weaker but real position.
_LOCAL_SOURCES: frozenset[str] = frozenset(
    {SourceKind.CLI_ARG.value, SourceKind.STDIN.value, SourceKind.ENV_VAR.value}
)


@dataclass
class SurfaceItem:
    """One ranked attack-surface entry: a flow, with why it ranks where it does."""

    ref: str
    entrypoint: str
    entrypoint_kind: str
    route: str
    source_kind: str
    sink_kind: str
    sink_location: str
    cwe: str
    severity: str
    #: 0–1 factors. Every one is recorded so a rank is never a bare number.
    factors: dict[str, float] = field(default_factory=dict)
    priority: float = 0.0
    #: True when reachability was actually computed; see the module docstring.
    measured: bool = True
    controls: list[str] = field(default_factory=list)
    sanitizers: list[str] = field(default_factory=list)
    covering_tests: list[str] = field(default_factory=list)
    #: Whether a deterministic test/harness could plausibly drive this. Feeds test synthesis.
    testable: bool = False
    testability_reason: str = ""
    rationale: list[str] = field(default_factory=list)

    @property
    def externally_controllable(self) -> bool:
        return self.source_kind in _REMOTE_SOURCES

    def as_dict(self) -> dict[str, Any]:
        return {
            "ref": self.ref,
            "entrypoint": self.entrypoint,
            "entrypoint_kind": self.entrypoint_kind,
            "route": self.route,
            "source_kind": self.source_kind,
            "sink_kind": self.sink_kind,
            "sink_location": self.sink_location,
            "cwe": self.cwe,
            "severity": self.severity,
            "factors": {k: round(v, 3) for k, v in self.factors.items()},
            "priority": round(self.priority, 6),
            "measured": self.measured,
            "externally_controllable": self.externally_controllable,
            "controls": self.controls,
            "sanitizers": self.sanitizers,
            "covering_tests": self.covering_tests,
            "testable": self.testable,
            "testability_reason": self.testability_reason,
            "rationale": self.rationale,
        }


@dataclass
class AttackSurface:
    SCHEMA = "kavachx.attack_surface.v1"

    items: list[SurfaceItem] = field(default_factory=list)
    #: Entrypoints with no control on any path from them.
    unauthenticated_entrypoints: list[str] = field(default_factory=list)
    #: Sinks no entrypoint reaches. Not "safe" — unreached by *this* index.
    unreached_sinks: list[str] = field(default_factory=list)
    #: Security-sensitive paths with no covering test. The test-synthesis work list.
    untested_paths: list[str] = field(default_factory=list)
    #: False when the graph had no entrypoints, so nothing could be measured.
    measured: bool = True
    notes: list[str] = field(default_factory=list)

    @property
    def externally_controllable(self) -> list[SurfaceItem]:
        return [i for i in self.items if i.externally_controllable]

    @property
    def testable(self) -> list[SurfaceItem]:
        return [i for i in self.items if i.testable]

    def top(self, limit: int = 20) -> list[SurfaceItem]:
        return self.items[:limit]

    def as_dict(self, *, limit: int = 200) -> dict[str, Any]:
        return {
            "schema": self.SCHEMA,
            "measured": self.measured,
            "counts": {
                "items": len(self.items),
                "externally_controllable": len(self.externally_controllable),
                "testable": len(self.testable),
                "unauthenticated_entrypoints": len(self.unauthenticated_entrypoints),
                "unreached_sinks": len(self.unreached_sinks),
                "untested_paths": len(self.untested_paths),
            },
            "items": [i.as_dict() for i in self.items[:limit]],
            "unauthenticated_entrypoints": self.unauthenticated_entrypoints[:60],
            "unreached_sinks": self.unreached_sinks[:60],
            "untested_paths": self.untested_paths[:60],
            "notes": self.notes,
        }

    def content_hash(self) -> str:
        return sha256_json(
            {
                "schema": self.SCHEMA,
                "items": sorted([i.ref, i.severity, round(i.priority, 4)] for i in self.items),
            }
        )

    def render(self) -> str:
        lines = ["ATTACK SURFACE"]
        if not self.measured:
            lines.append("  NOT MEASURED — no entrypoint was identified for this target.")
        lines.append(
            f"  {len(self.items)} ranked path(s), {len(self.externally_controllable)} "
            f"remotely controllable, {len(self.testable)} testable"
        )
        lines.append("")
        for index, item in enumerate(self.top(15), start=1):
            guard = ", ".join(item.controls) or "no control on the path"
            lines.append(
                f"  {index:2}. [{item.severity:8}] {item.source_kind} → {item.sink_kind} "
                f"@ {item.sink_location}"
            )
            lines.append(
                f"      entry {item.route or item.entrypoint}  ({guard})  "
                f"priority {item.priority:.4f}"
            )
        if self.untested_paths:
            lines += ["", f"  {len(self.untested_paths)} security-sensitive path(s) have no test."]
        return "\n".join(lines)


# ---------------------------------------------------------------------------
def build_attack_surface(
    *,
    code_graph: CodeGraph,
    security_graph: SecurityGraph,
    application_model: Any = None,
) -> AttackSurface:
    """Rank every security flow as an attack-surface item. Deterministic."""
    surface = AttackSurface()
    entrypoints = code_graph.entrypoint_uids()
    surface.measured = bool(entrypoints)
    if not surface.measured:
        surface.notes.append(
            "No entrypoint was identified, so no flow could be shown to be externally "
            "triggerable. The items below are ranked by severity and data-flow confidence only; "
            "their position does not reflect proven exposure."
        )

    controls_by_entry: dict[str, list[str]] = {}
    routes_by_entry: dict[str, str] = {}
    kinds_by_entry: dict[str, str] = {}
    if application_model is not None:
        for entry in application_model.entrypoints:
            controls_by_entry[entry.uid] = list(entry.controls)
            routes_by_entry[entry.uid] = entry.route
            kinds_by_entry[entry.uid] = entry.kind

    reached_sinks: set[str] = set()

    for flow in security_graph.flows:
        sink_node = security_graph.nodes.get(flow.sink_ref)
        if sink_node is None:
            continue
        if flow.reachable_from_entrypoint:
            reached_sinks.add(sink_node.location)

        item = SurfaceItem(
            ref=flow.ref,
            entrypoint=flow.entrypoint,
            entrypoint_kind=kinds_by_entry.get(flow.entrypoint, ""),
            route=routes_by_entry.get(flow.entrypoint, ""),
            source_kind=flow.source_kind,
            sink_kind=flow.sink_kind,
            sink_location=sink_node.location,
            cwe=flow.cwe,
            severity=flow.severity,
            measured=flow.reachability_measured,
            controls=controls_by_entry.get(flow.entrypoint, []),
            sanitizers=list(flow.sanitizers),
            covering_tests=list(flow.covering_tests),
        )
        _score(item, flow, surface.measured)
        item.testable, item.testability_reason = _testability(flow, code_graph)
        surface.items.append(item)

    surface.items.sort(key=lambda i: (-i.priority, i.ref))

    # -- aggregates --------------------------------------------------------
    if application_model is not None:
        surface.unauthenticated_entrypoints = [
            entry.uid for entry in application_model.entrypoints if entry.unauthenticated
        ]
    surface.unreached_sinks = sorted(
        {n.location for n in security_graph.sinks} - reached_sinks
    )
    if surface.unreached_sinks:
        surface.notes.append(
            f"{len(surface.unreached_sinks)} sink(s) are not reached from any declared "
            "entrypoint by this index. That is not a clearance: an unresolved call edge, a "
            "framework-dispatched handler or a language without full call resolution all produce "
            "the same result."
        )
    surface.untested_paths = sorted(
        {item.ref for item in surface.items if not item.covering_tests}
    )

    logger.info(
        "understanding.attack_surface",
        items=len(surface.items),
        remote=len(surface.externally_controllable),
        testable=len(surface.testable),
        measured=surface.measured,
        untested=len(surface.untested_paths),
    )
    return surface


def _score(item: SurfaceItem, flow: Any, measured: bool) -> None:
    """Deterministic priority. Every factor is recorded on the item.

    The formula is a product of factors, each in (0, 1]. A product, not a sum, because these are
    conjunctive conditions: a CRITICAL sink that nothing can reach and a trivially reachable
    INFO-level log write should both rank low, and a sum lets one large factor carry an item that
    fails on every other axis.
    """
    severity = SEVERITY_RANK.get(item.severity, 3) / 5.0

    # External controllability: remote > local-invoker > indirect.
    if item.source_kind in _REMOTE_SOURCES:
        controllability = 1.0
    elif item.source_kind in _LOCAL_SOURCES:
        controllability = 0.7
    else:
        controllability = 0.4

    # Reachability. When it could not be measured, severity stands in for it rather than a floor
    # being applied uniformly — the same substitution the hypothesis queue already makes, and for
    # the same reason: a uniform floor inverts the ranking instead of merely flattening it.
    if not flow.reachability_measured:
        reachability = severity
        item.rationale.append(
            "Reachability was not measured (no entrypoint to search from), so severity stands in "
            "for it. This position does not reflect proven exposure."
        )
    elif flow.reachable_from_entrypoint:
        reachability = 1.0
    else:
        reachability = 0.25
        item.rationale.append(
            "No call path from a declared entrypoint reaches this flow, so it is ranked down but "
            "not discarded — an unresolved edge produces the same signal."
        )

    # Data-flow confidence, straight from the flow's own basis.
    dataflow = max(0.05, flow.confidence)

    # Existing controls reduce priority; they do not remove the item.
    control_factor = 1.0
    if item.controls:
        control_factor = 0.6
        item.rationale.append(
            f"{len(item.controls)} authentication/authorisation control(s) sit on the path, which "
            "lowers priority. Whether a control actually blocks this input is a runtime question."
        )
    if item.sanitizers:
        control_factor *= 0.7
        item.rationale.append(
            f"{len(item.sanitizers)} sanitizer(s) appear on the path. Priority is reduced; the "
            "flow is not cleared, because static presence is not proof of execution."
        )

    # An untested path is worth more attention, not less: nothing is watching it.
    coverage_factor = 1.0 if not item.covering_tests else 0.85
    if not item.covering_tests:
        item.rationale.append("No test covers any symbol on this path.")

    item.factors = {
        "severity": severity,
        "external_controllability": controllability,
        "reachability": reachability,
        "dataflow_confidence": dataflow,
        "controls": control_factor,
        "coverage": coverage_factor,
    }
    item.priority = round(
        severity * controllability * reachability * dataflow * control_factor * coverage_factor,
        6,
    )
    item.rationale.insert(
        0,
        f"priority = severity({severity:.2f}) × controllability({controllability:.2f}) × "
        f"reachability({reachability:.2f}) × dataflow({dataflow:.2f}) × "
        f"controls({control_factor:.2f}) × coverage({coverage_factor:.2f})",
    )


def _testability(flow: Any, code_graph: CodeGraph) -> tuple[bool, str]:
    """Could a deterministic harness plausibly drive this flow?

    This gates test synthesis, so being wrong in the optimistic direction wastes a sandbox
    execution while being wrong in the pessimistic direction silently drops a provable finding.
    The rule is therefore structural rather than clever: a flow is testable when it starts at a
    reachable entrypoint whose input KavachX can supply.
    """
    if not flow.entrypoint:
        return False, (
            "No entrypoint anchors this flow, so there is no interface to drive it through."
        )
    node = code_graph.node(flow.entrypoint)
    if node is None:
        return False, "The anchoring entrypoint is not in the index."
    kind = str(node.attrs.get("entrypoint_kind") or "")
    if kind in ("cli", "http"):
        return True, f"Reachable from a {kind} entrypoint, which KavachX can drive with input."
    if kind == "library":
        return True, (
            "Reachable from a library entrypoint; a generated unit or property harness can call "
            "it directly."
        )
    return False, f"Entrypoint kind {kind or 'unknown'!r} has no supported driving mechanism."
