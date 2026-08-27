"""Building the security graph over the code graph.

Three passes, each deterministic:

1. **Classify locations.** Every line of every indexed source file is matched against the
   taxonomy, producing SOURCE / SINK / SANITIZER / VALIDATOR / control nodes, each attributed to
   the callable that encloses it via the code graph.

2. **Establish flows.** In descending order of evidential strength:

   * *taint* — the AST analyser proved, inside one function, that the value reaching the sink is
     derived from the source.
   * *call-graph* — a source in function A and a sink in function B, with a call path A→…→B in the
     code graph. This is where GitNexus earns its place: the path is computed over resolved edges
     when they exist, and the flow records which precision it used.
   * *proximity* — source and sink in the same function, no taint analyser for that language. The
     weakest basis, labelled as such, kept because omitting it would silently blind the system to
     every non-Python target.

3. **Score and bound.** Reachability from a declared entrypoint, trust boundaries crossed,
   covering tests, and a deterministic confidence. Where reachability cannot be measured the flow
   says so rather than defaulting to "not reachable".

No model is involved anywhere in this module.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.core.logging import get_logger
from app.indexing.model import CodeGraph, EdgeKind, NodeKind, Precision
from app.security_model.graph import (
    FlowStep,
    SecurityFlow,
    SecurityGraph,
    SecurityNode,
    boundaries_for,
    flow_ref,
    node_ref,
)
from app.security_model.taint import TaintFinding, analyse_file
from app.security_model.taxonomy import (
    SecurityCategory,
    Taxonomy,
    load_taxonomy,
)

logger = get_logger(__name__)

#: Cap on (source, sink) pairs considered for cross-function stitching. The pair space is
#: quadratic, and on a large repository an uncapped sweep would dominate run time for
#: diminishing returns — the highest-confidence pairs are considered first.
_MAX_PAIRS = 20_000
#: Cap on flows retained. Ordered by confidence, so the cut removes the weakest.
_MAX_FLOWS = 2_000
_MAX_READ_BYTES = 800_000


@dataclass
class BuildReport:
    duration_ms: int = 0
    files_scanned: int = 0
    files_taint_analysed: int = 0
    pairs_considered: int = 0
    flows_before_cap: int = 0
    tool_events: list[dict[str, Any]] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "duration_ms": self.duration_ms,
            "files_scanned": self.files_scanned,
            "files_taint_analysed": self.files_taint_analysed,
            "pairs_considered": self.pairs_considered,
            "flows_before_cap": self.flows_before_cap,
        }


def build_security_graph(
    *,
    code_graph: CodeGraph,
    root: Path,
    taxonomy: Taxonomy | None = None,
) -> tuple[SecurityGraph, BuildReport]:
    """Derive the security graph for one indexed tree."""
    started = time.perf_counter()
    taxonomy = taxonomy or load_taxonomy()
    security = SecurityGraph(taxonomy_summary=taxonomy.summary())
    security.warnings.extend(taxonomy.errors)
    report = BuildReport()

    file_nodes = code_graph.nodes_of(NodeKind.FILE.value)
    taint_by_function: dict[str, list[TaintFinding]] = {}

    # -- pass 1: classify -------------------------------------------------
    for file_node in file_nodes:
        if file_node.attrs.get("skipped_reason"):
            # Build output was excluded from indexing; scanning it here would reintroduce exactly
            # the noise the indexer removed.
            continue
        path = root / file_node.uid
        if not path.is_file():
            continue
        try:
            if path.stat().st_size > _MAX_READ_BYTES:
                security.warnings.append(
                    f"{file_node.uid} exceeds the security-scan size limit and was not classified."
                )
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        language = file_node.language or ""
        report.files_scanned += 1
        _classify_file(
            security=security,
            code_graph=code_graph,
            file=file_node.uid,
            text=text,
            language=language,
            taxonomy=taxonomy,
        )

        if language == "python":
            findings, error = analyse_file(path=file_node.uid, text=text, taxonomy=taxonomy)
            report.files_taint_analysed += 1
            if error:
                security.parse_errors.append({"file": file_node.uid, "error": error})
            for finding in findings:
                key = f"{finding.file}:{finding.function}"
                taint_by_function.setdefault(key, []).append(finding)

    report.tool_events.append(
        {
            "name": "security-taxonomy",
            "target": f"{report.files_scanned} files",
            "ms": int((time.perf_counter() - started) * 1000),
            "ok": True,
            "detail": (
                f"{len(security.sources)} sources, {len(security.sinks)} sinks, "
                f"{len(security.sanitizers)} sanitizers, {len(security.controls)} controls"
            ),
        }
    )

    # -- pass 2: flows ----------------------------------------------------
    entrypoints = code_graph.entrypoint_uids()
    _flows_from_taint(security, code_graph, taint_by_function)
    _flows_from_call_graph(security, code_graph, report)
    report.flows_before_cap = len(security.flows)

    # -- pass 3: score and bound -----------------------------------------
    for flow in security.flows:
        _score_flow(flow, security, code_graph, entrypoints)

    if len(security.flows) > _MAX_FLOWS:
        security.flows = security.top_flows(_MAX_FLOWS)
        security.warnings.append(
            f"{report.flows_before_cap} flows were derived; the {_MAX_FLOWS} highest-confidence "
            "were retained. The remainder are lower-confidence and are not reported as absent."
        )

    report.duration_ms = int((time.perf_counter() - started) * 1000)
    report.tool_events.append(
        {
            "name": "security-flows",
            "target": f"{len(security.flows)} flows",
            "ms": report.duration_ms,
            "ok": True,
            "detail": (
                f"{len(security.reachable_flows)} reachable, "
                f"{len([f for f in security.flows if f.sanitized])} with a sanitizer on the path, "
                f"{len(security.boundaries)} trust boundaries"
            ),
        }
    )
    logger.info("security.graph_built", **security.stats())
    return security, report


# ---------------------------------------------------------------------------
def _classify_file(
    *,
    security: SecurityGraph,
    code_graph: CodeGraph,
    file: str,
    text: str,
    language: str,
    taxonomy: Taxonomy,
) -> None:
    """Match every line against the taxonomy and record the security nodes it produces."""
    active = taxonomy.for_language(language) if language else taxonomy
    families = (
        (active.sources, SecurityCategory.SOURCE.value),
        (active.sinks, SecurityCategory.SINK.value),
        (active.sanitizers, SecurityCategory.SANITIZER.value),
        (active.validators, SecurityCategory.VALIDATOR.value),
        (active.controls, ""),
    )

    for number, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped:
            continue
        # A comment cannot execute. Skipping it removes the single largest source of static-analysis
        # noise — a docstring that mentions `os.system` is not a shell sink.
        if stripped.startswith(("#", "//", "*", "/*")):
            continue

        for rules, default_category in families:
            for rule in rules:
                if not rule.compiled.search(line):
                    continue
                category = rule.category or default_category
                if not category:
                    continue
                owner = code_graph.symbol_at(file, number)
                security.add_node(
                    SecurityNode(
                        ref=node_ref(category, file, number),
                        category=category,
                        kind=rule.kind,
                        file=file,
                        line=number,
                        owner=owner.uid if owner else "",
                        rule_id=rule.id,
                        cwe=rule.cwe,
                        severity=rule.severity,
                        snippet=stripped[:220],
                        why=rule.why,
                        confidence=rule.confidence,
                    )
                )


def _flows_from_taint(
    security: SecurityGraph,
    code_graph: CodeGraph,
    taint_by_function: dict[str, list[TaintFinding]],
) -> None:
    """Promote AST-proven taint findings to flows. The strongest basis available."""
    for findings in taint_by_function.values():
        for finding in findings:
            source_ref = node_ref(SecurityCategory.SOURCE.value, finding.file, finding.source_line)
            sink_ref = node_ref(SecurityCategory.SINK.value, finding.file, finding.sink_line)

            # The taint analyser found a source the line scanner may have classified differently
            # (a call-target match vs a line match). Materialise any node the scanner missed so a
            # flow never references a node that does not exist — the same dangling-claim failure
            # the PRAMAAN graph refuses.
            if source_ref not in security.nodes:
                security.add_node(
                    SecurityNode(
                        ref=source_ref,
                        category=SecurityCategory.SOURCE.value,
                        kind=finding.source_kind,
                        file=finding.file,
                        line=finding.source_line,
                        owner=_owner_uid(code_graph, finding.file, finding.source_line),
                        rule_id=finding.source_rule,
                        why="External input identified by taint analysis.",
                        confidence=0.7,
                    )
                )
            if sink_ref not in security.nodes:
                security.add_node(
                    SecurityNode(
                        ref=sink_ref,
                        category=SecurityCategory.SINK.value,
                        kind=finding.sink_kind,
                        file=finding.file,
                        line=finding.sink_line,
                        owner=_owner_uid(code_graph, finding.file, finding.sink_line),
                        rule_id=finding.sink_rule,
                        cwe=finding.cwe,
                        severity=finding.severity,
                        why="Dangerous operation identified by taint analysis.",
                        confidence=0.7,
                    )
                )

            owner = _owner_uid(code_graph, finding.file, finding.sink_line)
            steps = [
                FlowStep(
                    kind=step.kind if step.kind in ("source", "sink", "sanitize", "validate")
                    else "transform",
                    location=f"{finding.file}:{step.line}",
                    detail=step.detail or step.name,
                    symbol=step.name,
                )
                for step in finding.chain
            ]
            security.add_flow(
                SecurityFlow(
                    ref=flow_ref(source_ref, sink_ref),
                    source_ref=source_ref,
                    sink_ref=sink_ref,
                    source_kind=finding.source_kind,
                    sink_kind=finding.sink_kind,
                    cwe=finding.cwe,
                    severity=finding.severity,
                    steps=steps,
                    call_path=[owner] if owner else [],
                    sanitizers=list(finding.sanitizers),
                    validators=list(finding.validators),
                    basis="taint",
                    interpolated=finding.interpolated,
                    confidence=finding.confidence,
                    notes=[
                        f"Data flow proven within {finding.function} by AST derivation "
                        f"({len(finding.chain)} hops)."
                    ],
                )
            )


def _flows_from_call_graph(
    security: SecurityGraph, code_graph: CodeGraph, report: BuildReport
) -> None:
    """Stitch a source in one function to a sink in another along call edges.

    This is the cross-function half that intra-procedural taint cannot see, and the place the
    resolved code graph pays for itself: the path is searched at RESOLVED precision first, so a
    flow backed by real symbol resolution is distinguishable from one backed by a name match.
    """
    sources = [n for n in security.sources if n.owner]
    sinks = [n for n in security.sinks if n.owner]
    if not sources or not sinks:
        return

    # Consider the most promising pairs first so the cap removes the weakest, not the newest.
    sources.sort(key=lambda n: -n.confidence)
    sinks.sort(key=lambda n: -n.confidence)

    for source in sources:
        for sink in sinks:
            if report.pairs_considered >= _MAX_PAIRS:
                security.warnings.append(
                    f"Cross-function flow search stopped after {_MAX_PAIRS} candidate pairs; "
                    "lower-confidence pairs were not searched and are not reported as absent."
                )
                return
            report.pairs_considered += 1

            if source.owner == sink.owner:
                # Same function. Python already has a taint verdict for this pair; only fall back
                # to proximity for languages with no taint analyser, and label it honestly.
                existing = flow_ref(source.ref, sink.ref)
                if any(f.ref == existing for f in security.flows):
                    continue
                if _language_of(code_graph, source.file) == "python":
                    # Python was taint-analysed and did NOT prove this pair. Recording a proximity
                    # flow here would manufacture a claim the stronger analysis already declined.
                    continue
                security.add_flow(
                    _proximity_flow(source, sink, code_graph)
                )
                continue

            path = code_graph.path_between(
                source.owner, sink.owner, precision=Precision.RESOLVED.value
            )
            precision = Precision.RESOLVED.value
            if not path:
                path = code_graph.path_between(
                    source.owner, sink.owner, precision=Precision.UNION.value
                )
                precision = Precision.UNION.value
            if not path:
                continue

            steps = [
                FlowStep(
                    kind="source",
                    location=source.location,
                    detail=source.why or source.kind,
                    symbol=source.owner,
                )
            ]
            for uid in path[1:]:
                node = code_graph.node(uid)
                steps.append(
                    FlowStep(
                        kind="call",
                        location=f"{node.file}:{node.start_line}" if node else uid,
                        detail=f"call into {node.qualname if node else uid}",
                        symbol=uid,
                    )
                )
            sanitizers_on_path = _sanitizers_on(security, path)
            for reference in sanitizers_on_path:
                node = security.nodes[reference]
                steps.append(
                    FlowStep(
                        kind="sanitize",
                        location=node.location,
                        detail=node.why or node.kind,
                        symbol=node.owner,
                    )
                )
            steps.append(
                FlowStep(
                    kind="sink",
                    location=sink.location,
                    detail=sink.why or sink.kind,
                    symbol=sink.owner,
                )
            )

            security.add_flow(
                SecurityFlow(
                    ref=flow_ref(source.ref, sink.ref),
                    source_ref=source.ref,
                    sink_ref=sink.ref,
                    source_kind=source.kind,
                    sink_kind=sink.kind,
                    cwe=sink.cwe,
                    severity=sink.severity,
                    steps=steps,
                    call_path=path,
                    sanitizers=[security.nodes[r].rule_id for r in sanitizers_on_path],
                    validators=[
                        security.nodes[r].rule_id
                        for r in _validators_on(security, path)
                    ],
                    basis="call-graph",
                    precision=precision,
                    confidence=_call_graph_confidence(
                        source, sink, path, precision, sanitizers_on_path
                    ),
                    notes=[
                        f"Call path of {len(path)} hop(s) from {source.owner} to {sink.owner} at "
                        f"{precision} precision. Whether the specific value reaching the sink "
                        "derives from this source was not proven by taint analysis across the "
                        "call boundary."
                    ],
                )
            )


def _proximity_flow(
    source: SecurityNode, sink: SecurityNode, code_graph: CodeGraph
) -> SecurityFlow:
    """Same-function fallback for languages with no taint analyser."""
    return SecurityFlow(
        ref=flow_ref(source.ref, sink.ref),
        source_ref=source.ref,
        sink_ref=sink.ref,
        source_kind=source.kind,
        sink_kind=sink.kind,
        cwe=sink.cwe,
        severity=sink.severity,
        steps=[
            FlowStep("source", source.location, source.why or source.kind, source.owner),
            FlowStep("sink", sink.location, sink.why or sink.kind, sink.owner),
        ],
        call_path=[source.owner],
        basis="proximity",
        confidence=round(min(source.confidence, sink.confidence) * 0.5, 3),
        notes=[
            "Source and sink are in the same function, but no taint analyser is available for "
            f"{_language_of(code_graph, source.file) or 'this language'}, so it is NOT established "
            "that the value reaching the sink comes from this source. Treat as a lead."
        ],
    )


def _score_flow(
    flow: SecurityFlow,
    security: SecurityGraph,
    code_graph: CodeGraph,
    entrypoints: set[str],
) -> None:
    """Reachability, trust boundaries, covering tests. Mutates ``flow`` in place."""
    flow.boundaries = boundaries_for(flow.source_kind, flow.sink_kind)
    for kind in flow.boundaries:
        security.add_boundary(kind, flow.source_ref)

    anchor = flow.call_path[0] if flow.call_path else ""
    if anchor:
        result = code_graph.reachability(
            anchor, precision=Precision.UNION.value, entrypoints=entrypoints
        )
        flow.reachable_from_entrypoint = result.reachable
        flow.reachability_measured = result.measured
        if result.reachable and result.path:
            flow.entrypoint = result.path[0]
            # Prepend the entrypoint hops so the flow reads from the outside in, which is the
            # order a reviewer thinks in: what can an attacker touch, and where does it end up.
            prefix = [
                FlowStep(
                    kind="call",
                    location=_location_of(code_graph, uid),
                    detail=f"entrypoint {uid}" if index == 0 else f"call into {uid}",
                    symbol=uid,
                )
                for index, uid in enumerate(result.path[:-1])
            ]
            flow.steps = [*prefix, *flow.steps]
        if not result.measured:
            flow.notes.append(result.note)
        # An unreachable flow is not deleted: an internal helper reached only by another module
        # KavachX could not resolve is still worth a human look. It is scored down instead.
        if result.measured and not result.reachable:
            flow.confidence = round(flow.confidence * 0.5, 3)
            flow.notes.append(
                "No call path from a declared entrypoint reaches this flow's source, so it is "
                "not shown to be externally triggerable."
            )

    tests: set[str] = set()
    for uid in flow.call_path:
        for edge in code_graph.out_edges(uid, EdgeKind.TESTED_BY.value):
            tests.add(edge.dst)
    flow.covering_tests = sorted(tests)
    if not flow.covering_tests:
        flow.notes.append(
            "No test statically references any symbol on this path — an untested "
            "security-sensitive flow."
        )


def _call_graph_confidence(
    source: SecurityNode,
    sink: SecurityNode,
    path: list[str],
    precision: str,
    sanitizers: list[str],
) -> float:
    """Deterministic confidence for a cross-function flow."""
    score = min(source.confidence, sink.confidence)
    # A resolved path is real; a name-matched one may not be a call at all.
    score *= 1.0 if precision == Precision.RESOLVED.value else 0.6
    # Each extra hop is another place the value could be replaced entirely.
    score *= max(0.4, 1.0 - 0.08 * max(0, len(path) - 2))
    if sanitizers:
        score *= 0.55
    return max(0.05, min(0.9, round(score, 3)))


def _sanitizers_on(security: SecurityGraph, path: list[str]) -> list[str]:
    owners = set(path)
    return [n.ref for n in security.sanitizers if n.owner in owners]


def _validators_on(security: SecurityGraph, path: list[str]) -> list[str]:
    owners = set(path)
    return [n.ref for n in security.validators if n.owner in owners]


def _owner_uid(code_graph: CodeGraph, file: str, line: int) -> str:
    owner = code_graph.symbol_at(file, line)
    return owner.uid if owner else ""


def _language_of(code_graph: CodeGraph, file: str) -> str:
    node = code_graph.node(file)
    return node.language if node else ""


def _location_of(code_graph: CodeGraph, uid: str) -> str:
    node = code_graph.node(uid)
    return f"{node.file}:{node.start_line}" if node else uid
