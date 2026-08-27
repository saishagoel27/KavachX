"""The internal KavachX code graph.

This is the **provider-neutral** model every other subsystem consumes. GitNexus, tree-sitter and
any future indexer are adapted *into* it inside :mod:`app.indexing`; nothing outside this package
is allowed to know a GitNexus node id or a tree-sitter node type. That boundary is the reason a
second provider can be added, or GitNexus removed, without touching discovery, patching or PRAMAAN.

Two design decisions carry most of the weight.

**Node identity is KavachX's, not a provider's.** A uid is ``path`` for a file and
``path:qualname`` for a symbol — the same ``handle`` shape :mod:`app.analysis.indexer` has always
used. Adopting the existing shape rather than inventing a new one is what lets the World Model,
root-cause verification and blast radius keep working against a graph that is now assembled from
two providers.

**Every edge records who produced it, and edges are merged, not overwritten.** This is not
bookkeeping. Measured on the seeded demo target, GitNexus resolves 8 call edges and misses the
cross-file ``service.handle → parser.parse_header`` call entirely; the tree-sitter name-matched
graph finds it, by over-approximation. So:

* GitNexus edges are **precise but incomplete** — a resolved call really is a call.
* tree-sitter edges are **complete but imprecise** — a name match may be a different function.

Neither provider alone can answer "is this sink reachable?" honestly. Keeping both, tagged, means
reachability can be computed at a stated precision (:class:`Precision`) and the answer can say
which provider's edges supported it. A single untagged union would silently launder an
over-approximated guess into a "resolved" reachability claim, which is exactly the class of
dishonesty this system exists to avoid.
"""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from app.core.hashing import sha256_json


class _Str(str, Enum):
    """``StrEnum`` equivalent that also works on 3.10 hosts, matching app.models.enums."""

    def __str__(self) -> str:  # pragma: no cover - trivial
        return str(self.value)


class NodeKind(_Str):
    """What a graph node *is*.

    Deliberately wider than any single provider reports: the extra kinds are populated by later
    stages (tests by the test discoverer, entrypoints by the probe, configuration by config
    discovery) so that everything the spec's World Model calls for lives in one graph rather than
    in parallel side-tables that can drift out of sync with it.
    """

    REPOSITORY = "repository"
    DIRECTORY = "directory"
    FILE = "file"
    MODULE = "module"
    PACKAGE = "package"
    CLASS = "class"
    INTERFACE = "interface"
    FUNCTION = "function"
    METHOD = "method"
    VARIABLE = "variable"
    PARAMETER = "parameter"
    PROPERTY = "property"
    SYMBOL = "symbol"
    IMPORT = "import"
    EXPORT = "export"
    DEPENDENCY = "dependency"
    TEST = "test"
    CONFIGURATION = "configuration"
    ENTRYPOINT = "entrypoint"
    #: A provider-derived execution flow (GitNexus "Process"): an ordered walk from an entry point
    #: through a call chain. Distinct from a KavachX ExecutionPath, which is security-scoped.
    PROCESS = "process"
    #: A provider-derived module cluster / community.
    CLUSTER = "cluster"
    UNKNOWN = "unknown"


#: Node kinds that denote a callable. Reachability walks and sink ownership only ever consider
#: these, so a CALLS edge that lands on a File node (GitNexus emits those for module-level calls)
#: cannot masquerade as a function-to-function call.
CALLABLE_KINDS: frozenset[str] = frozenset(
    {NodeKind.FUNCTION.value, NodeKind.METHOD.value, NodeKind.ENTRYPOINT.value}
)


class EdgeKind(_Str):
    """How two nodes relate.

    The structural half (CONTAINS…STEP_IN_PROCESS) comes from the indexers. The semantic half
    (READS…CROSSES_TRUST_BOUNDARY) is written by :mod:`app.security_model` over the same graph, so
    a data-flow edge and a call edge are queryable through one interface.
    """

    # -- structural, from indexers ----------------------------------------
    CONTAINS = "CONTAINS"
    DEFINES = "DEFINES"
    IMPORTS = "IMPORTS"
    EXPORTS = "EXPORTS"
    CALLS = "CALLS"
    CALLED_BY = "CALLED_BY"
    INHERITS = "INHERITS"
    IMPLEMENTS = "IMPLEMENTS"
    MEMBER_OF = "MEMBER_OF"
    DEPENDS_ON = "DEPENDS_ON"
    STEP_IN_PROCESS = "STEP_IN_PROCESS"
    # -- semantic, from the security model --------------------------------
    READS = "READS"
    WRITES = "WRITES"
    PASSES_TO = "PASSES_TO"
    RETURNS_TO = "RETURNS_TO"
    REACHES = "REACHES"
    FLOWS_TO = "FLOWS_TO"
    TAINTS = "TAINTS"
    SANITIZES = "SANITIZES"
    VALIDATES = "VALIDATES"
    EXECUTES = "EXECUTES"
    TESTED_BY = "TESTED_BY"
    CONFIGURED_BY = "CONFIGURED_BY"
    CROSSES_TRUST_BOUNDARY = "CROSSES_TRUST_BOUNDARY"
    UNKNOWN = "UNKNOWN"


class Provider(_Str):
    """Who produced a node or edge. Travels into the certificate."""

    GITNEXUS = "gitnexus"
    TREE_SITTER = "tree-sitter"
    #: The regex fallback inside app.analysis.indexer, for files with no available grammar.
    REGEX = "regex"
    SEMGREP = "semgrep"
    #: KavachX's own AST rules / security taxonomy / config + test discovery.
    KAVACHX = "kavachx"
    RUNTIME = "runtime"


class Precision(_Str):
    """Which edges a graph query is allowed to traverse.

    ``RESOLVED`` restricts the walk to edges a provider actually resolved (GitNexus's symbol
    resolution, or a runtime observation). ``UNION`` also admits name-matched tree-sitter edges,
    which over-approximate. A caller must choose, and the answer records the choice — see
    :meth:`CodeGraph.reachability`.
    """

    RESOLVED = "resolved"
    UNION = "union"


#: Providers whose edges are treated as resolved rather than name-matched.
RESOLVED_PROVIDERS: frozenset[str] = frozenset(
    {Provider.GITNEXUS.value, Provider.RUNTIME.value, Provider.SEMGREP.value}
)


# ---------------------------------------------------------------------------
@dataclass
class CodeNode:
    uid: str
    kind: str
    name: str = ""
    qualname: str = ""
    file: str = ""
    start_line: int = 0
    end_line: int = 0
    language: str = ""
    exported: bool = False
    signature: str = ""
    parameters: list[str] = field(default_factory=list)
    decorators: list[str] = field(default_factory=list)
    docline: str = ""
    #: Providers that reported this node. A node seen by both is higher-confidence than either.
    provenance: set[str] = field(default_factory=set)
    #: Provider-specific extras, kept for debugging and never interpreted outside this package.
    attrs: dict[str, Any] = field(default_factory=dict)

    @property
    def is_callable(self) -> bool:
        return self.kind in CALLABLE_KINDS

    @property
    def module_dir(self) -> str:
        return self.file.rsplit("/", 1)[0] if "/" in self.file else "."

    def as_dict(self) -> dict[str, Any]:
        return {
            "uid": self.uid,
            "kind": self.kind,
            "name": self.name,
            "qualname": self.qualname,
            "file": self.file,
            "start_line": self.start_line,
            "end_line": self.end_line,
            "language": self.language,
            "exported": self.exported,
            "signature": self.signature,
            "parameters": self.parameters,
            "decorators": self.decorators,
            "docline": self.docline,
            "provenance": sorted(self.provenance),
        }


@dataclass
class CodeEdge:
    src: str
    dst: str
    kind: str
    provenance: set[str] = field(default_factory=set)
    #: Provider-reported or KavachX-assigned strength. Resolved edges default to 1.0; name-matched
    #: tree-sitter edges are damped, because an ambiguous name match is genuinely weaker evidence.
    confidence: float = 1.0
    attrs: dict[str, Any] = field(default_factory=dict)

    @property
    def key(self) -> tuple[str, str, str]:
        return (self.src, self.kind, self.dst)

    @property
    def resolved(self) -> bool:
        """True when at least one provider that actually resolves symbols produced this edge."""
        return bool(self.provenance & RESOLVED_PROVIDERS)

    def admits(self, precision: str) -> bool:
        return self.resolved if precision == Precision.RESOLVED.value else True

    def as_dict(self) -> dict[str, Any]:
        return {
            "src": self.src,
            "dst": self.dst,
            "kind": self.kind,
            "provenance": sorted(self.provenance),
            "confidence": round(self.confidence, 3),
            "resolved": self.resolved,
            **({"attrs": self.attrs} if self.attrs else {}),
        }


@dataclass
class ReachabilityResult:
    """The answer to "can an entrypoint reach this symbol?", with its own provenance.

    ``measured`` is the field that matters downstream. When a target has no entrypoints there is
    no path to search, so ``False`` here means *not measured* rather than *not reachable* — and
    :mod:`app.discovery.base` already relies on that distinction to avoid inverting the priority
    queue on static-only runs.
    """

    reachable: bool = False
    path: list[str] = field(default_factory=list)
    precision: str = Precision.UNION.value
    measured: bool = True
    #: Providers contributing at least one edge on the returned path.
    via_providers: list[str] = field(default_factory=list)
    #: Lowest edge confidence along the path — a path is only as strong as its weakest hop.
    confidence: float = 0.0
    note: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "reachable": self.reachable,
            "path": self.path,
            "precision": self.precision,
            "measured": self.measured,
            "via_providers": self.via_providers,
            "confidence": round(self.confidence, 3),
            "note": self.note,
        }


# ---------------------------------------------------------------------------
class CodeGraph:
    """An indexed repository as nodes plus provenance-tagged edges.

    Adjacency is maintained incrementally on insert so that reachability queries — which run once
    per static candidate, i.e. hundreds of times per run — do not rescan the edge list.
    """

    SCHEMA = "kavachx.code_graph.v1"

    def __init__(self) -> None:
        self._nodes: dict[str, CodeNode] = {}
        self._edges: dict[tuple[str, str, str], CodeEdge] = {}
        self._out: dict[str, list[CodeEdge]] = defaultdict(list)
        self._in: dict[str, list[CodeEdge]] = defaultdict(list)
        self._by_name: dict[str, list[str]] = defaultdict(list)
        #: Populated by the merge step; ordered by contribution for display.
        self.providers: list[str] = []
        #: Non-fatal problems found while adapting a provider's output. Feed the health report.
        self.warnings: list[str] = []
        #: Graph-level side data that is *about* the repository rather than a node in it — the
        #: dependency model, provider execution flows, the architecture model. Kept here rather
        #: than as synthetic nodes so it cannot contaminate node counts: a "dependency model"
        #: node would otherwise be counted as one more dependency.
        self.metadata: dict[str, Any] = {}

    # -- construction ------------------------------------------------------
    def add_node(self, node: CodeNode) -> CodeNode:
        """Insert or merge a node. Field-level merge keeps the more informative value.

        Providers disagree in detail: GitNexus knows ``isExported`` and gives a whole-symbol line
        range; tree-sitter knows decorators and parameters. Taking the union rather than
        last-writer-wins is what makes a merged node strictly better than either input.
        """
        existing = self._nodes.get(node.uid)
        if existing is None:
            self._nodes[node.uid] = node
            if node.name:
                self._by_name[node.name.lower()].append(node.uid)
            return node

        existing.provenance |= node.provenance
        # A more specific kind wins over UNKNOWN/SYMBOL; otherwise the first one stands.
        if existing.kind in (NodeKind.UNKNOWN.value, NodeKind.SYMBOL.value) and node.kind not in (
            NodeKind.UNKNOWN.value,
            NodeKind.SYMBOL.value,
        ):
            existing.kind = node.kind
        for attribute in ("name", "qualname", "file", "language", "signature", "docline"):
            if not getattr(existing, attribute) and getattr(node, attribute):
                setattr(existing, attribute, getattr(node, attribute))
        if not existing.start_line and node.start_line:
            existing.start_line = node.start_line
        # Prefer the wider span: a provider that only saw a declaration reports a narrower one,
        # and symbol_at() needs the true body extent to attribute a sink line to its function.
        if node.end_line > existing.end_line:
            existing.end_line = node.end_line
        existing.exported = existing.exported or node.exported
        if not existing.parameters and node.parameters:
            existing.parameters = node.parameters
        if not existing.decorators and node.decorators:
            existing.decorators = node.decorators
        existing.attrs.update(node.attrs)
        return existing

    def add_edge(self, edge: CodeEdge) -> CodeEdge:
        """Insert or merge an edge, unioning provenance and taking the strongest confidence."""
        existing = self._edges.get(edge.key)
        if existing is not None:
            existing.provenance |= edge.provenance
            existing.confidence = max(existing.confidence, edge.confidence)
            existing.attrs.update(edge.attrs)
            return existing
        self._edges[edge.key] = edge
        self._out[edge.src].append(edge)
        self._in[edge.dst].append(edge)
        return edge

    # -- access ------------------------------------------------------------
    def __len__(self) -> int:
        return len(self._nodes)

    def has(self, uid: str) -> bool:
        return uid in self._nodes

    def node(self, uid: str) -> CodeNode | None:
        return self._nodes.get(uid)

    @property
    def nodes(self) -> list[CodeNode]:
        return [self._nodes[uid] for uid in sorted(self._nodes)]

    @property
    def edges(self) -> list[CodeEdge]:
        return [self._edges[key] for key in sorted(self._edges)]

    def nodes_of(self, *kinds: str) -> list[CodeNode]:
        wanted = set(kinds)
        return [n for n in self.nodes if n.kind in wanted]

    def files(self) -> list[CodeNode]:
        return self.nodes_of(NodeKind.FILE.value)

    def callables(self) -> list[CodeNode]:
        return [n for n in self.nodes if n.is_callable]

    def find_by_name(self, name: str) -> list[CodeNode]:
        return [self._nodes[uid] for uid in self._by_name.get(name.lower(), []) if uid in self._nodes]

    def search_symbols(self, query: str, *, limit: int = 40) -> list[CodeNode]:
        """Substring search over names and qualnames. Deterministic ordering."""
        needle = query.lower().strip()
        if not needle:
            return []
        hits = [
            n
            for n in self.nodes
            if needle in n.name.lower() or needle in n.qualname.lower() or needle in n.uid.lower()
        ]
        # Exact name matches first, then shortest uid — stable and useful for a tool interface.
        hits.sort(key=lambda n: (n.name.lower() != needle, len(n.uid), n.uid))
        return hits[:limit]

    # -- edge queries ------------------------------------------------------
    def out_edges(
        self, uid: str, *kinds: str, precision: str = Precision.UNION.value
    ) -> list[CodeEdge]:
        wanted = set(kinds)
        return [
            e
            for e in self._out.get(uid, [])
            if (not wanted or e.kind in wanted) and e.admits(precision)
        ]

    def in_edges(
        self, uid: str, *kinds: str, precision: str = Precision.UNION.value
    ) -> list[CodeEdge]:
        wanted = set(kinds)
        return [
            e
            for e in self._in.get(uid, [])
            if (not wanted or e.kind in wanted) and e.admits(precision)
        ]

    def callees(self, uid: str, *, precision: str = Precision.UNION.value) -> list[str]:
        return sorted({e.dst for e in self.out_edges(uid, EdgeKind.CALLS.value, precision=precision)})

    def callers(self, uid: str, *, precision: str = Precision.UNION.value) -> list[str]:
        return sorted({e.src for e in self.in_edges(uid, EdgeKind.CALLS.value, precision=precision)})

    def caller_count(self, uid: str, *, precision: str = Precision.UNION.value) -> int:
        return len(self.callers(uid, precision=precision))

    def imports_of(self, file_uid: str) -> list[str]:
        return sorted({e.dst for e in self.out_edges(file_uid, EdgeKind.IMPORTS.value)})

    def members_of(self, uid: str) -> list[str]:
        """Symbols defined inside ``uid`` (a file's functions, a class's methods)."""
        return sorted(
            {
                e.dst
                for e in self.out_edges(uid, EdgeKind.DEFINES.value, EdgeKind.CONTAINS.value)
            }
        )

    def symbol_at(self, file: str, line: int) -> CodeNode | None:
        """Innermost callable containing ``file:line``.

        Innermost, not first: a method inside a class inside a module all span the line, and the
        one that owns a sink is the tightest enclosing callable.
        """
        best: CodeNode | None = None
        for node in self._nodes.values():
            if node.file != file or not node.is_callable:
                continue
            if node.start_line <= line <= (node.end_line or node.start_line):
                if best is None or node.start_line > best.start_line:
                    best = node
        return best

    def transitive_callers(
        self, uid: str, *, max_depth: int = 6, precision: str = Precision.UNION.value
    ) -> list[str]:
        seen: set[str] = set()
        frontier = [uid]
        for _ in range(max_depth):
            nxt: list[str] = []
            for current in frontier:
                for caller in self.callers(current, precision=precision):
                    if caller not in seen:
                        seen.add(caller)
                        nxt.append(caller)
            if not nxt:
                break
            frontier = nxt
        seen.discard(uid)
        return sorted(seen)

    def siblings_of(self, uid: str, *, limit: int = 40) -> list[str]:
        """Callables in the same file, then the same directory. The sibling-hunt search space."""
        node = self._nodes.get(uid)
        if node is None:
            return []
        same_file: list[str] = []
        same_dir: list[str] = []
        for other in self.callables():
            if other.uid == uid:
                continue
            if other.file == node.file:
                same_file.append(other.uid)
            elif other.module_dir == node.module_dir:
                same_dir.append(other.uid)
        return [*sorted(same_file), *sorted(same_dir)][:limit]

    # -- reachability ------------------------------------------------------
    def entrypoint_uids(self) -> set[str]:
        return {
            n.uid
            for n in self.nodes
            if n.kind == NodeKind.ENTRYPOINT.value or bool(n.attrs.get("entrypoint_kind"))
        }

    def reachability(
        self,
        uid: str,
        *,
        precision: str = Precision.UNION.value,
        entrypoints: set[str] | None = None,
        max_path: int = 12,
    ) -> ReachabilityResult:
        """Shortest reverse-BFS path from any entrypoint to ``uid`` at the given precision.

        Returns ``measured=False`` when the graph declares no entrypoints. That is not a
        pessimistic default dressed up as a result: with no entrypoint there is no path to search,
        and reporting ``reachable=False`` would let "we could not look" read as "we looked and
        found nothing".
        """
        entries = entrypoints if entrypoints is not None else self.entrypoint_uids()
        if not entries:
            return ReachabilityResult(
                reachable=False,
                precision=precision,
                measured=False,
                note=(
                    "No entrypoint is declared for this target, so no call path could be "
                    "searched. This is an absence of measurement, not evidence of "
                    "unreachability."
                ),
            )
        if uid in entries:
            node = self._nodes.get(uid)
            return ReachabilityResult(
                reachable=True,
                path=[uid],
                precision=precision,
                confidence=1.0,
                via_providers=sorted(node.provenance) if node else [],
                note="The symbol is itself a declared entrypoint.",
            )

        # (uid, path, weakest-confidence-so-far, providers-seen)
        queue: deque[tuple[str, list[str], float, frozenset[str]]] = deque(
            [(uid, [uid], 1.0, frozenset())]
        )
        seen = {uid}
        while queue:
            current, path, weakest, providers = queue.popleft()
            for edge in self.in_edges(current, EdgeKind.CALLS.value, precision=precision):
                caller = edge.src
                if caller in seen:
                    continue
                seen.add(caller)
                new_path = [caller, *path]
                new_weakest = min(weakest, edge.confidence)
                new_providers = providers | frozenset(edge.provenance)
                if caller in entries:
                    return ReachabilityResult(
                        reachable=True,
                        path=new_path,
                        precision=precision,
                        confidence=new_weakest,
                        via_providers=sorted(new_providers),
                        note=(
                            f"Path of {len(new_path)} hop(s) from entrypoint {caller} at "
                            f"{precision} precision."
                        ),
                    )
                if len(new_path) < max_path:
                    queue.append((caller, new_path, new_weakest, new_providers))

        return ReachabilityResult(
            reachable=False,
            precision=precision,
            measured=True,
            note=(
                f"No call path from any of {len(entries)} declared entrypoint(s) reaches this "
                f"symbol at {precision} precision."
            ),
        )

    def reachability_score(self, uid: str, *, precision: str = Precision.UNION.value) -> float:
        """A 0–1 exposure score. Shorter paths from an entrypoint score higher."""
        result = self.reachability(uid, precision=precision)
        if not result.measured:
            return 0.05
        if not result.reachable:
            return 0.15 if self.caller_count(uid) else 0.05
        hops = max(0, len(result.path) - 1)
        return round(max(0.4, 1.0 - 0.08 * hops) * max(result.confidence, 0.5), 3)

    def blast_radius_score(self, uid: str, *, precision: str = Precision.UNION.value) -> float:
        callers = self.transitive_callers(uid, precision=precision)
        modules = {self._nodes[c].module_dir for c in callers if c in self._nodes}
        return round(min(0.2 + 0.03 * len(callers) + 0.08 * len(modules), 1.0), 3)

    def path_between(
        self, src: str, dst: str, *, precision: str = Precision.UNION.value, max_depth: int = 10
    ) -> list[str]:
        """Shortest forward call path ``src → … → dst``, or ``[]``."""
        if src == dst:
            return [src]
        queue: deque[list[str]] = deque([[src]])
        seen = {src}
        while queue:
            path = queue.popleft()
            if len(path) > max_depth:
                continue
            for callee in self.callees(path[-1], precision=precision):
                if callee in seen:
                    continue
                seen.add(callee)
                if callee == dst:
                    return [*path, callee]
                queue.append([*path, callee])
        return []

    def subgraph(self, uid: str, *, depth: int = 2, limit: int = 120) -> dict[str, Any]:
        """A focused neighbourhood around one node — what the UI renders.

        Bounded on purpose: the whole repository graph is neither renderable nor useful, and
        every place the spec asks for visualisation asks for a subgraph around a finding, an
        entrypoint, a sink or a trust boundary.
        """
        seen = {uid}
        frontier = [uid]
        for _ in range(max(0, depth)):
            nxt: list[str] = []
            for current in frontier:
                for edge in [*self._out.get(current, []), *self._in.get(current, [])]:
                    for candidate in (edge.src, edge.dst):
                        if candidate not in seen and len(seen) < limit:
                            seen.add(candidate)
                            nxt.append(candidate)
            if not nxt:
                break
            frontier = nxt
        return {
            "root": uid,
            "nodes": [n.as_dict() for n in self.nodes if n.uid in seen],
            "edges": [
                e.as_dict() for e in self.edges if e.src in seen and e.dst in seen
            ],
        }

    # -- statistics / serialisation ---------------------------------------
    def stats(self) -> dict[str, Any]:
        by_kind: dict[str, int] = {}
        for node in self._nodes.values():
            by_kind[node.kind] = by_kind.get(node.kind, 0) + 1
        by_edge: dict[str, int] = {}
        resolved_edges = 0
        by_provider_edges: dict[str, int] = {}
        for edge in self._edges.values():
            by_edge[edge.kind] = by_edge.get(edge.kind, 0) + 1
            if edge.resolved:
                resolved_edges += 1
            for provider in edge.provenance:
                by_provider_edges[provider] = by_provider_edges.get(provider, 0) + 1
        by_provider_nodes: dict[str, int] = {}
        for node in self._nodes.values():
            for provider in node.provenance:
                by_provider_nodes[provider] = by_provider_nodes.get(provider, 0) + 1
        by_language: dict[str, int] = {}
        for node in self._nodes.values():
            if node.kind == NodeKind.FILE.value and node.language:
                by_language[node.language] = by_language.get(node.language, 0) + 1

        calls = by_edge.get(EdgeKind.CALLS.value, 0)
        return {
            "nodes": len(self._nodes),
            "edges": len(self._edges),
            "by_node_kind": by_kind,
            "by_edge_kind": by_edge,
            "by_provider_nodes": by_provider_nodes,
            "by_provider_edges": by_provider_edges,
            "by_language": by_language,
            "providers": list(self.providers),
            "files": by_kind.get(NodeKind.FILE.value, 0),
            "functions": by_kind.get(NodeKind.FUNCTION.value, 0)
            + by_kind.get(NodeKind.METHOD.value, 0),
            "classes": by_kind.get(NodeKind.CLASS.value, 0),
            "entrypoints": len(self.entrypoint_uids()),
            "tests": by_kind.get(NodeKind.TEST.value, 0),
            "configurations": by_kind.get(NodeKind.CONFIGURATION.value, 0),
            "dependencies": by_kind.get(NodeKind.DEPENDENCY.value, 0),
            "call_edges": calls,
            "import_edges": by_edge.get(EdgeKind.IMPORTS.value, 0),
            "resolved_edges": resolved_edges,
            #: The honest headline: what fraction of relationships a symbol-resolving provider
            #: actually confirmed, as opposed to a name match.
            "resolved_edge_ratio": round(resolved_edges / len(self._edges), 4)
            if self._edges
            else 0.0,
        }

    def as_dict(self, *, include_nodes: bool = True, node_limit: int = 20_000) -> dict[str, Any]:
        document: dict[str, Any] = {
            "schema": self.SCHEMA,
            "providers": list(self.providers),
            "stats": self.stats(),
            "warnings": self.warnings[:200],
        }
        if include_nodes:
            nodes = self.nodes
            edges = self.edges
            document["truncated"] = len(nodes) > node_limit
            document["nodes"] = [n.as_dict() for n in nodes[:node_limit]]
            document["edges"] = [e.as_dict() for e in edges[: node_limit * 4]]
        return document

    def content_hash(self) -> str:
        """Structural digest. Two indexes of the same tree by the same providers agree here.

        Hashes the *structure* — uids, kinds, edges, provenance — and deliberately not line
        numbers or timings, so the digest identifies the graph rather than the run that built it.
        """
        return sha256_json(
            {
                "schema": self.SCHEMA,
                "providers": sorted(self.providers),
                "nodes": [[n.uid, n.kind, sorted(n.provenance)] for n in self.nodes],
                "edges": [[e.src, e.kind, e.dst, sorted(e.provenance)] for e in self.edges],
            }
        )
