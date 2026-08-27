"""Merging provider graphs into one unified code graph.

The merge is where the two providers' complementary weaknesses are turned into a single graph that
is strictly better than either — and where the honesty properties are established.

Measured on the seeded demo target (26 files):

* GitNexus: 87 nodes, 99 edges, 8 of them ``CALLS``. It resolves imports and heritage, and every
  edge it emits is a resolved fact. It missed the cross-file call
  ``service.handle → parser.parse_header`` entirely.
* tree-sitter: finds that call, plus many more, by matching names — some of which are wrong.

So the merge must satisfy three properties:

1. **Union of nodes**, field-merged, so a symbol carries GitNexus's ``isExported`` *and*
   tree-sitter's decorators and parameters.
2. **Union of edges, provenance preserved.** An edge both providers found is corroborated and gets
   confidence 1.0. An edge only tree-sitter found stays sub-1.0 and stays unresolved, so a
   ``Precision.RESOLVED`` query cannot see it.
3. **A derived, never asserted, ``graph_source``.** The pre-existing code set
   ``graph_source = "gitnexus+tree-sitter"`` whenever a ``gitnexus`` binary merely *existed* on the
   host, without ever invoking it — a false provenance claim that travelled into certificates.
   :func:`describe_source` computes the label from what actually contributed edges.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.core.logging import get_logger
from app.indexing.model import CodeEdge, CodeGraph, CodeNode, EdgeKind, Provider

logger = get_logger(__name__)


@dataclass(slots=True)
class MergeReport:
    """What the merge did. Feeds the index health report and the certificate."""

    providers: list[str] = field(default_factory=list)
    nodes_total: int = 0
    edges_total: int = 0
    #: Nodes/edges reported by more than one provider — independent corroboration.
    nodes_corroborated: int = 0
    edges_corroborated: int = 0
    #: Edges only a resolving provider produced.
    edges_resolved_only: int = 0
    #: Edges only the name-matching provider produced. The over-approximated tail.
    edges_name_matched_only: int = 0
    per_provider: dict[str, dict[str, int]] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "providers": self.providers,
            "nodes_total": self.nodes_total,
            "edges_total": self.edges_total,
            "nodes_corroborated": self.nodes_corroborated,
            "edges_corroborated": self.edges_corroborated,
            "edges_resolved_only": self.edges_resolved_only,
            "edges_name_matched_only": self.edges_name_matched_only,
            "per_provider": self.per_provider,
            "warnings": self.warnings,
        }


def merge_graphs(*graphs: CodeGraph) -> tuple[CodeGraph, MergeReport]:
    """Fold provider graphs into one, in the order given.

    Order matters only for which provider's value wins a tie on a scalar field that is set in
    both; it does not affect edge provenance or confidence, which are unioned and maximised.
    Pass the more precise provider first so its line spans and export flags land first.
    """
    merged = CodeGraph()
    report = MergeReport()
    per_provider: dict[str, dict[str, int]] = {}

    for graph in graphs:
        for provider in graph.providers:
            if provider not in merged.providers:
                merged.providers.append(provider)
        merged.warnings.extend(graph.warnings)
        merged.metadata.update(graph.metadata)

        for node in graph.nodes:
            merged.add_node(
                CodeNode(
                    uid=node.uid,
                    kind=node.kind,
                    name=node.name,
                    qualname=node.qualname,
                    file=node.file,
                    start_line=node.start_line,
                    end_line=node.end_line,
                    language=node.language,
                    exported=node.exported,
                    signature=node.signature,
                    parameters=list(node.parameters),
                    decorators=list(node.decorators),
                    docline=node.docline,
                    provenance=set(node.provenance),
                    attrs=dict(node.attrs),
                )
            )
            for provider in node.provenance:
                per_provider.setdefault(provider, {"nodes": 0, "edges": 0})["nodes"] += 1

        for edge in graph.edges:
            merged.add_edge(
                CodeEdge(
                    src=edge.src,
                    dst=edge.dst,
                    kind=edge.kind,
                    provenance=set(edge.provenance),
                    confidence=edge.confidence,
                    attrs=dict(edge.attrs),
                )
            )
            for provider in edge.provenance:
                per_provider.setdefault(provider, {"nodes": 0, "edges": 0})["edges"] += 1

    # A relationship two independent providers agree on is corroborated: promote it to full
    # confidence. This is the one place a name-matched edge can become resolved, and only because
    # a resolving provider independently produced the same edge.
    for edge in merged.edges:
        if len(edge.provenance) > 1:
            report.edges_corroborated += 1
            edge.confidence = 1.0
        if edge.resolved:
            if len(edge.provenance) == 1:
                report.edges_resolved_only += 1
        else:
            report.edges_name_matched_only += 1

    report.nodes_corroborated = len([n for n in merged.nodes if len(n.provenance) > 1])
    report.providers = list(merged.providers)
    report.nodes_total = len(merged)
    report.edges_total = len(merged.edges)
    report.per_provider = per_provider

    _warn_on_disagreement(merged, report)

    logger.info(
        "indexing.merged",
        providers=report.providers,
        nodes=report.nodes_total,
        edges=report.edges_total,
        corroborated_edges=report.edges_corroborated,
    )
    return merged, report


def _warn_on_disagreement(graph: CodeGraph, report: MergeReport) -> None:
    """Surface provider disagreement as an index warning rather than hiding it in a ratio.

    A large gap between what one provider resolved and what the other guessed is exactly the
    signal an operator needs to interpret a reachability claim, so it is named explicitly.
    """
    calls = [e for e in graph.edges if e.kind == EdgeKind.CALLS.value]
    if not calls:
        report.warnings.append(
            "No call relationships were resolved by any provider. Reachability cannot be "
            "measured for this target, so candidate ranking falls back to severity."
        )
        return

    resolved = [e for e in calls if e.resolved]
    if Provider.GITNEXUS.value in report.providers and not resolved:
        report.warnings.append(
            "GitNexus contributed no call edges. Every reachability claim in this run rests on "
            "name-matched edges and is an over-approximation."
        )
    elif resolved and len(resolved) < len(calls) // 4:
        report.warnings.append(
            f"Only {len(resolved)} of {len(calls)} call edges were resolved by a "
            "symbol-resolving provider; the remainder are name matches. Reachability at "
            "'union' precision over-approximates on this target."
        )


def describe_source(report: MergeReport) -> str:
    """The ``graph_source`` label, derived from actual contribution.

    Never assert a provider that did not contribute. The previous implementation labelled a run
    ``gitnexus+tree-sitter`` on the strength of a binary existing on the host; the label then
    travelled into the certificate, where the fidelity of every reachability claim depends on it.
    """
    contributed = [
        provider
        for provider in (
            Provider.GITNEXUS.value,
            Provider.TREE_SITTER.value,
            Provider.REGEX.value,
        )
        if report.per_provider.get(provider, {}).get("nodes", 0) > 0
        or report.per_provider.get(provider, {}).get("edges", 0) > 0
    ]
    return "+".join(contributed) if contributed else "none"
