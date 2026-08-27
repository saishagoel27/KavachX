"""Code intelligence: repository indexing and the unified code knowledge graph.

``INGEST → INDEX → INDEX VALIDATION`` lives here. The package owns every indexer-specific detail
so that the rest of KavachX consumes one provider-neutral model:

* :mod:`app.indexing.model` — the internal :class:`~app.indexing.model.CodeGraph`.
* :mod:`app.indexing.gitnexus` — the GitNexus adapter (optional provider, precise/incomplete).
* :mod:`app.indexing.treesitter` — adapts KavachX's existing tree-sitter indexer
  (always available, complete/imprecise).
* :mod:`app.indexing.merge` — provenance-preserving merge, and the derived ``graph_source``.
* :mod:`app.indexing.job` / :mod:`app.indexing.health` — the index record and its validation.
* :mod:`app.indexing.incremental` — change sets and affected closures.
* :mod:`app.indexing.service` — :func:`~app.indexing.service.build_index`, the entry point.
"""

from app.indexing.model import (
    CALLABLE_KINDS,
    CodeEdge,
    CodeGraph,
    CodeNode,
    EdgeKind,
    NodeKind,
    Precision,
    Provider,
    ReachabilityResult,
)

__all__ = [
    "CALLABLE_KINDS",
    "CodeEdge",
    "CodeGraph",
    "CodeNode",
    "EdgeKind",
    "NodeKind",
    "Precision",
    "Provider",
    "ReachabilityResult",
]
