"""tree-sitter provider — adapts KavachX's existing indexer into the unified code graph.

This is deliberately an *adapter*, not a reimplementation. :mod:`app.analysis.indexer` already
parses Python, C and JavaScript/TypeScript with tree-sitter (falling back to a conservative regex
indexer per file), extracts symbols, imports, call sites, ``__main__`` guards and sink hits, and
identifies generated/minified build output. All of that is retained; this module only expresses
the result as :class:`~app.indexing.model.CodeGraph` nodes and edges.

What this provider contributes that GitNexus does not:

* **Recall.** Call resolution here is by *name*, preferring a definition in the same file, then the
  same module, then anywhere. That over-approximates — and on the seeded demo target it is the
  only provider that finds ``service.handle → parser.parse_header`` at all. Edges are therefore
  emitted with a confidence below 1.0 and are *not* marked resolved, so a caller asking for
  ``Precision.RESOLVED`` never sees them.
* **Per-file fidelity metadata** — which parser handled each file, and why a file was skipped.
  This is what the index health report is built from.
* **Sink hit lines**, consumed by the security model.

The confidence damping is not cosmetic. An ambiguous name match is genuinely weaker evidence than
a resolved symbol reference, and :meth:`CodeGraph.reachability` propagates the weakest hop along a
path, so a reachability claim that rests on three guesses reports lower confidence than one that
rests on three resolved calls.
"""

from __future__ import annotations

from collections import defaultdict
from pathlib import Path
from typing import Any

from app.analysis.indexer import (
    ENTRYPOINT_HINTS,
    FileIndex,
    SymbolRef,
    index_tree,
    indexer_summary,
)
from app.core.logging import get_logger
from app.indexing.model import (
    CodeEdge,
    CodeGraph,
    CodeNode,
    EdgeKind,
    NodeKind,
    Provider,
)

logger = get_logger(__name__)

#: Confidence for a call edge resolved by name within the same file. Highest of the three because
#: a same-file name collision is rare and the enclosing scope is known.
_CONF_SAME_FILE = 0.75
#: Same directory/module — plausible, but another module could define the same name.
_CONF_SAME_MODULE = 0.55
#: Anywhere in the tree. Kept deliberately low: this is the tier that produces false call edges.
_CONF_GLOBAL = 0.35

#: How many candidate definitions one call site may fan out to. Ambiguity is recorded as multiple
#: edges rather than guessed away, because an over-approximated caller set makes reachability
#: conservative — which is the safe direction for a security tool.
_MAX_CALL_FANOUT = 3


def _kind_for(symbol: SymbolRef) -> str:
    return {
        "class": NodeKind.CLASS.value,
        "method": NodeKind.METHOD.value,
        "function": NodeKind.FUNCTION.value,
    }.get(symbol.kind, NodeKind.SYMBOL.value)


def build_graph(root: Path, *, max_files: int = 4000) -> tuple[CodeGraph, list[FileIndex], dict[str, Any]]:
    """Index ``root`` with tree-sitter and return the graph, per-file indexes and a summary.

    The per-file indexes are returned alongside the graph because later stages need the raw
    detail the graph does not carry: sink hit lines for the security model, ``skipped_reason`` for
    the health report, and ``sha256`` per file for incremental indexing.
    """
    indexes = index_tree(root, max_files=max_files)
    summary = indexer_summary(indexes)

    graph = CodeGraph()
    graph.providers = [Provider.TREE_SITTER.value]

    # A file whose symbols came from the regex fallback is attributed to the regex provider, so
    # the certificate can distinguish "parsed" from "pattern-matched".
    for entry in indexes:
        provider = (
            Provider.REGEX.value if entry.indexer == "regex" else Provider.TREE_SITTER.value
        )
        file_uid = entry.path
        graph.add_node(
            CodeNode(
                uid=file_uid,
                kind=NodeKind.FILE.value,
                name=entry.path.rsplit("/", 1)[-1],
                qualname=entry.path,
                file=entry.path,
                language=entry.language,
                start_line=1,
                end_line=entry.lines,
                provenance={provider},
                attrs={
                    "indexer": entry.indexer,
                    "sha256": entry.sha256,
                    "lines": entry.lines,
                    "has_main_guard": entry.has_main_guard,
                    "skipped_reason": entry.skipped_reason,
                    "sink_hits": len(entry.sink_hits),
                },
            )
        )

        # Directory containment, so the graph can answer module-level questions.
        directory = entry.path.rsplit("/", 1)[0] if "/" in entry.path else "."
        graph.add_node(
            CodeNode(
                uid=directory,
                kind=NodeKind.DIRECTORY.value,
                name=directory.rsplit("/", 1)[-1] or ".",
                qualname=directory,
                provenance={provider},
            )
        )
        graph.add_edge(
            CodeEdge(
                src=directory,
                dst=file_uid,
                kind=EdgeKind.CONTAINS.value,
                provenance={provider},
                confidence=1.0,
            )
        )

        for symbol in entry.symbols:
            graph.add_node(
                CodeNode(
                    uid=symbol.handle,
                    kind=_kind_for(symbol),
                    name=symbol.name,
                    qualname=symbol.qualname,
                    file=symbol.file,
                    start_line=symbol.start_line,
                    end_line=symbol.end_line,
                    language=entry.language,
                    signature=f"{symbol.qualname}({', '.join(symbol.parameters)})",
                    parameters=list(symbol.parameters),
                    decorators=list(symbol.decorators),
                    docline=symbol.docline,
                    provenance={provider},
                    attrs={"raw_calls": sorted(set(symbol.calls))[:60]},
                )
            )
            # DEFINES from the file, and MEMBER_OF for a method's class.
            graph.add_edge(
                CodeEdge(
                    src=file_uid,
                    dst=symbol.handle,
                    kind=EdgeKind.DEFINES.value,
                    provenance={provider},
                    confidence=1.0,
                )
            )
            if symbol.kind == "method" and "." in symbol.qualname:
                class_qual = symbol.qualname.rsplit(".", 1)[0]
                class_uid = f"{symbol.file}:{class_qual}"
                graph.add_edge(
                    CodeEdge(
                        src=symbol.handle,
                        dst=class_uid,
                        kind=EdgeKind.MEMBER_OF.value,
                        provenance={provider},
                        confidence=1.0,
                    )
                )

        for statement in set(entry.imports):
            # An import statement is a node in its own right: the *target* of a Python
            # `from x import y` cannot be resolved to a file without doing GitNexus's job, so the
            # honest representation is the statement text, not a guessed file edge.
            import_uid = f"import:{entry.path}:{statement[:120]}"
            graph.add_node(
                CodeNode(
                    uid=import_uid,
                    kind=NodeKind.IMPORT.value,
                    name=statement[:120],
                    file=entry.path,
                    provenance={provider},
                    attrs={"statement": statement},
                )
            )
            graph.add_edge(
                CodeEdge(
                    src=file_uid,
                    dst=import_uid,
                    kind=EdgeKind.IMPORTS.value,
                    provenance={provider},
                    confidence=1.0,
                )
            )

    _link_calls(graph, indexes)
    _mark_entrypoints(graph, indexes)

    logger.info(
        "treesitter.graph_built",
        files=len(indexes),
        nodes=len(graph),
        edges=len(graph.edges),
    )
    return graph, indexes, summary


def _link_calls(graph: CodeGraph, indexes: list[FileIndex]) -> None:
    """Resolve textual call sites onto symbol uids by name.

    Preference order is same file → same module → anywhere, with confidence decreasing at each
    step. This is the recall half of the merged graph and it is explicitly an over-approximation;
    see the module docstring for why that is kept rather than tightened away.
    """
    by_name: dict[str, list[SymbolRef]] = defaultdict(list)
    for entry in indexes:
        for symbol in entry.symbols:
            by_name[symbol.name].append(symbol)

    for entry in indexes:
        for symbol in entry.symbols:
            module = symbol.file.rsplit("/", 1)[0] if "/" in symbol.file else "."
            for raw_call in set(symbol.calls):
                # `a.b.c(x)` -> `c`. The receiver is unknown without type resolution, which is
                # exactly the analysis GitNexus contributes and this provider does not attempt.
                target_name = raw_call.split("(")[0].strip().split(".")[-1]
                if not target_name or target_name == symbol.name:
                    continue
                candidates = by_name.get(target_name)
                if not candidates:
                    continue

                same_file = [c for c in candidates if c.file == symbol.file]
                same_module = [
                    c
                    for c in candidates
                    if (c.file.rsplit("/", 1)[0] if "/" in c.file else ".") == module
                ]
                if same_file:
                    chosen, confidence = same_file, _CONF_SAME_FILE
                elif same_module:
                    chosen, confidence = same_module, _CONF_SAME_MODULE
                else:
                    chosen, confidence = candidates, _CONF_GLOBAL

                # Fanning out to N candidates divides the evidence: if a name matches five
                # definitions, no single one of them is a 0.35-confidence call.
                damped = confidence / max(1, min(len(chosen), _MAX_CALL_FANOUT))
                for target in chosen[:_MAX_CALL_FANOUT]:
                    graph.add_edge(
                        CodeEdge(
                            src=symbol.handle,
                            dst=target.handle,
                            kind=EdgeKind.CALLS.value,
                            provenance={Provider.TREE_SITTER.value},
                            confidence=round(damped, 3),
                            attrs={"call_text": raw_call[:120], "resolution": "name-match"},
                        )
                    )


def _mark_entrypoints(graph: CodeGraph, indexes: list[FileIndex]) -> None:
    """Flag externally reachable symbols, reusing the existing entrypoint heuristics.

    The hint list is matched *exactly*, not by prefix — a loose match here is not a harmless
    heuristic. Treating an internal helper like ``parse_header`` as an entrypoint would make it
    trivially "reachable" and inflate every reachability score that depends on it, which is why
    :mod:`app.analysis.indexer` keeps the list tight and this preserves that.
    """
    hints = set(ENTRYPOINT_HINTS)
    for entry in indexes:
        for symbol in entry.symbols:
            if symbol.kind == "class":
                continue
            name = symbol.name.lower()
            kind = ""
            if (entry.has_main_guard and name == "main") or name in (
                "main",
                "lambda_handler",
                "llvmfuzzertestoneinput",
            ):
                kind = "cli"
            elif name in hints:
                kind = "library"
            elif any(
                decorator.lower().startswith(("@app.", "@router.", "@get", "@post", "@route"))
                for decorator in symbol.decorators
            ):
                kind = "http"
            if not kind:
                continue
            node = graph.node(symbol.handle)
            if node is None:
                continue
            # The node keeps its own kind (function/method) and gains an entrypoint marker, so a
            # symbol is not forced to choose between "is a function" and "is an entrypoint".
            node.attrs["entrypoint_kind"] = kind
