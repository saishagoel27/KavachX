"""The security-aware graph built over the general code graph.

GitNexus and tree-sitter answer "what code exists and how is it connected". This package answers
the security questions layered on top:

* :mod:`app.security_model.taxonomy` — an **extensible registry** of sources, sinks, sanitizers,
  validators and auth controls. Operator-supplied rules merge over the defaults, so a deployment
  can teach KavachX its own framework without forking it.
* :mod:`app.security_model.taint` — intra-procedural taint analysis for Python: does the value
  reaching the sink actually derive from the source, and was anything applied to it on the way?
* :mod:`app.security_model.graph` — SecurityNode / SecurityFlow / TrustBoundary, plus the queries
  the reasoning layer and the UI use.
* :mod:`app.security_model.builder` — :func:`~app.security_model.builder.build_security_graph`.

The invariant this package preserves: a flow is evidence, never a verdict. Every flow records how
it was established (``taint`` / ``call-graph`` / ``proximity``), at what precision, and what
sanitizers sat on the path — and a sanitizer lowers confidence without ever clearing the flow,
because whether it *executed* on the exploit input is a runtime question the sandbox answers.
"""

from app.security_model.graph import (
    SecurityFlow,
    SecurityGraph,
    SecurityNode,
    TrustBoundary,
)
from app.security_model.taxonomy import (
    SecurityCategory,
    SinkKind,
    SourceKind,
    Taxonomy,
    TrustBoundaryKind,
    load_taxonomy,
)

__all__ = [
    "SecurityCategory",
    "SecurityFlow",
    "SecurityGraph",
    "SecurityNode",
    "SinkKind",
    "SourceKind",
    "Taxonomy",
    "TrustBoundary",
    "TrustBoundaryKind",
    "load_taxonomy",
]
