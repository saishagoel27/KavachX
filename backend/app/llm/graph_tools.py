"""Read-only graph tools — the structured interface the reasoning layer queries.

The spec asks for a tool-based interface so the model can *progressively inspect* what it needs
rather than receiving everything at once. This is that interface.

Three properties are structural, not conventions:

1. **Every tool is a read-only query.** There is no tool here that writes a file, runs a command,
   applies a patch or changes a verdict. A model driving this toolset can learn things; it cannot
   do anything. Execution authority lives in the sandbox and is reached only through a validated
   :class:`~app.testing.specs.TestSpec`, never through a tool call.

2. **Every result is bounded.** Each tool caps its own output, and :meth:`GraphToolset.get_file`
   returns a windowed slice rather than a file. The reason context cost stays flat as a repository
   grows is that no tool's output scales with repository size.

3. **Every call is recorded.** :attr:`GraphToolset.calls` is the audit trail behind the
   model-context inspection view: an operator can see exactly which queries were made, with what
   arguments, and how much each returned. Debugging a hallucination starts by looking at what the
   model was actually told.

Repository content returned by these tools is **untrusted data**. It is always delivered inside a
labelled envelope (see :mod:`app.llm.context`) and never concatenated into an instruction.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.core.hashing import canonical_json
from app.core.logging import get_logger
from app.indexing.model import CodeGraph, EdgeKind, NodeKind, Precision
from app.security_model.graph import SecurityGraph

logger = get_logger(__name__)

#: Default caps. Deliberately small: a tool that can return 5,000 rows is a tool that can blow the
#: context window in one call, and the model can always ask again with a narrower query.
_MAX_ROWS = 40
_MAX_SLICE_LINES = 160
_MAX_SEARCH_HITS = 30


@dataclass(slots=True)
class ToolCall:
    """One recorded query. Feeds the model-context inspection view."""

    name: str
    arguments: dict[str, Any]
    result_items: int
    result_bytes: int
    duration_ms: int
    truncated: bool = False
    error: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "arguments": self.arguments,
            "result_items": self.result_items,
            "result_bytes": self.result_bytes,
            "duration_ms": self.duration_ms,
            "truncated": self.truncated,
            "error": self.error,
        }


@dataclass
class GraphToolset:
    """The queryable view of one indexed target."""

    code_graph: CodeGraph
    security_graph: SecurityGraph
    root: Path
    application_model: Any = None
    attack_surface: Any = None
    #: Coverage by ``file:line`` or symbol uid, when a run has measured any.
    coverage: dict[str, Any] = field(default_factory=dict)
    #: Runtime observations keyed by symbol uid or scope.
    runtime: dict[str, Any] = field(default_factory=dict)
    calls: list[ToolCall] = field(default_factory=list)

    # -- recording ---------------------------------------------------------
    def _record(
        self,
        name: str,
        arguments: dict[str, Any],
        result: Any,
        started: float,
        *,
        truncated: bool = False,
        error: str = "",
    ) -> Any:
        items = len(result) if isinstance(result, (list, dict)) else 1
        self.calls.append(
            ToolCall(
                name=name,
                arguments=arguments,
                result_items=items,
                # Canonical JSON length, so the recorded size is the size the model would actually
                # be shown rather than a Python repr that differs from it.
                result_bytes=len(canonical_json(result)),
                duration_ms=int((time.perf_counter() - started) * 1000),
                truncated=truncated,
                error=error,
            )
        )
        return result

    def tool_log(self) -> list[dict[str, Any]]:
        return [c.as_dict() for c in self.calls]

    # -- code -------------------------------------------------------------
    def get_file(self, path: str, *, start: int = 1, end: int = 0) -> dict[str, Any]:
        """A bounded window of one file, with line numbers.

        This is the only path to raw source in the whole toolset, and it is windowed rather than
        whole-file: the repository is never poured into a prompt, so context cost does not grow
        with the target.
        """
        started = time.perf_counter()
        node = self.code_graph.node(path)
        file_path = self.root / path
        if not file_path.is_file():
            return self._record(
                "get_file", {"path": path}, {}, started, error=f"{path} is not in the index"
            )
        try:
            lines = file_path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError as exc:
            return self._record("get_file", {"path": path}, {}, started, error=str(exc)[:120])

        start = max(1, start)
        end = end or len(lines)
        end = min(len(lines), max(start, end), start + _MAX_SLICE_LINES - 1)
        result = {
            "path": path,
            "language": node.language if node else "",
            "total_lines": len(lines),
            "start_line": start,
            "end_line": end,
            "code": "\n".join(f"{n:>5}  {lines[n - 1]}" for n in range(start, end + 1)),
        }
        return self._record(
            "get_file",
            {"path": path, "start": start, "end": end},
            result,
            started,
            truncated=end < len(lines),
        )

    def get_function(self, symbol: str, *, context_lines: int = 4) -> dict[str, Any]:
        """A symbol's metadata plus a bounded slice of its body."""
        started = time.perf_counter()
        node = self.code_graph.node(symbol)
        if node is None:
            matches = self.code_graph.find_by_name(symbol)
            node = matches[0] if matches else None
        if node is None:
            return self._record(
                "get_function", {"symbol": symbol}, {}, started, error="unknown symbol"
            )
        window = self.get_file(
            node.file,
            start=max(1, node.start_line - context_lines),
            end=(node.end_line or node.start_line) + context_lines,
        )
        # get_file recorded its own call; drop it so the log reads as one get_function query.
        if self.calls and self.calls[-1].name == "get_file":
            self.calls.pop()
        result = {
            **node.as_dict(),
            "code": window.get("code", ""),
            "callers": self.code_graph.callers(node.uid)[:_MAX_ROWS],
            "callees": self.code_graph.callees(node.uid)[:_MAX_ROWS],
        }
        return self._record("get_function", {"symbol": symbol}, result, started)

    def get_class(self, symbol: str) -> dict[str, Any]:
        started = time.perf_counter()
        node = self.code_graph.node(symbol)
        if node is None or node.kind != NodeKind.CLASS.value:
            candidates = [
                n for n in self.code_graph.find_by_name(symbol) if n.kind == NodeKind.CLASS.value
            ]
            node = candidates[0] if candidates else None
        if node is None:
            return self._record("get_class", {"symbol": symbol}, {}, started, error="unknown class")
        methods = [
            uid
            for uid in self.code_graph.members_of(node.uid)
            if (m := self.code_graph.node(uid)) and m.kind == NodeKind.METHOD.value
        ]
        inherits = [e.dst for e in self.code_graph.out_edges(node.uid, EdgeKind.INHERITS.value)]
        implements = [
            e.dst for e in self.code_graph.out_edges(node.uid, EdgeKind.IMPLEMENTS.value)
        ]
        result = {
            **node.as_dict(),
            "methods": methods[:_MAX_ROWS],
            "inherits": inherits[:_MAX_ROWS],
            "implements": implements[:_MAX_ROWS],
        }
        return self._record("get_class", {"symbol": symbol}, result, started)

    def get_callers(self, symbol: str, *, precision: str = Precision.UNION.value) -> list[dict[str, Any]]:
        started = time.perf_counter()
        rows = [
            self._brief(uid, edge_confidence=self._edge_confidence(uid, symbol))
            for uid in self.code_graph.callers(symbol, precision=precision)[:_MAX_ROWS]
        ]
        return self._record("get_callers", {"symbol": symbol, "precision": precision}, rows, started)

    def get_callees(self, symbol: str, *, precision: str = Precision.UNION.value) -> list[dict[str, Any]]:
        started = time.perf_counter()
        rows = [
            self._brief(uid, edge_confidence=self._edge_confidence(symbol, uid))
            for uid in self.code_graph.callees(symbol, precision=precision)[:_MAX_ROWS]
        ]
        return self._record("get_callees", {"symbol": symbol, "precision": precision}, rows, started)

    def get_imports(self, file: str) -> list[str]:
        started = time.perf_counter()
        rows = [
            str((self.code_graph.node(uid) or _empty()).attrs.get("statement", uid))
            for uid in self.code_graph.imports_of(file)[:_MAX_ROWS]
        ]
        return self._record("get_imports", {"file": file}, rows, started)

    def get_dependents(self, symbol: str) -> list[dict[str, Any]]:
        """Transitive reverse dependencies — who breaks if this changes."""
        started = time.perf_counter()
        uids = self.code_graph.transitive_callers(symbol)
        rows = [self._brief(uid) for uid in uids[:_MAX_ROWS]]
        return self._record(
            "get_dependents", {"symbol": symbol}, rows, started, truncated=len(uids) > _MAX_ROWS
        )

    def get_siblings(self, symbol: str) -> list[dict[str, Any]]:
        """Callables in the same file/module — the sibling-hunt search space."""
        started = time.perf_counter()
        rows = [self._brief(uid) for uid in self.code_graph.siblings_of(symbol)[:_MAX_ROWS]]
        return self._record("get_siblings", {"symbol": symbol}, rows, started)

    # -- paths -------------------------------------------------------------
    def get_execution_path(self, entrypoint: str, *, target: str = "") -> dict[str, Any]:
        """The call path from an entrypoint, optionally to a specific target."""
        started = time.perf_counter()
        if target:
            resolved = self.code_graph.path_between(entrypoint, target, precision=Precision.RESOLVED.value)
            precision = Precision.RESOLVED.value
            if not resolved:
                resolved = self.code_graph.path_between(
                    entrypoint, target, precision=Precision.UNION.value
                )
                precision = Precision.UNION.value
            result = {
                "entrypoint": entrypoint,
                "target": target,
                "path": [self._brief(uid) for uid in resolved],
                "precision": precision,
                "found": bool(resolved),
            }
        else:
            result = {
                "entrypoint": entrypoint,
                "reachable": [
                    self._brief(uid)
                    for uid in self.code_graph.callees(entrypoint)[:_MAX_ROWS]
                ],
            }
        return self._record(
            "get_execution_path", {"entrypoint": entrypoint, "target": target}, result, started
        )

    def get_dataflow(self, source: str = "", sink: str = "") -> list[dict[str, Any]]:
        """Security flows, optionally filtered by source or sink location.

        This is the tool that replaces "here is the repository, find the data flow": the model
        receives the already-computed path with its basis and confidence attached.
        """
        started = time.perf_counter()
        flows = self.security_graph.flows
        if source:
            flows = [f for f in flows if source in f.source_ref]
        if sink:
            flows = [f for f in flows if sink in f.sink_ref]
        rows = [
            {
                "ref": f.ref,
                "source_kind": f.source_kind,
                "sink_kind": f.sink_kind,
                "cwe": f.cwe,
                "severity": f.severity,
                "basis": f.basis,
                "precision": f.precision,
                "confidence": f.confidence,
                "reachable": f.reachable_from_entrypoint,
                "reachability_measured": f.reachability_measured,
                "sanitizers": f.sanitizers,
                "validators": f.validators,
                "boundaries": f.boundaries,
                "path": f.explain(),
                "notes": f.notes,
            }
            for f in sorted(flows, key=lambda f: -f.confidence)[:_MAX_ROWS]
        ]
        return self._record("get_dataflow", {"source": source, "sink": sink}, rows, started)

    # -- security ----------------------------------------------------------
    def get_sources(self, function: str = "") -> list[dict[str, Any]]:
        started = time.perf_counter()
        nodes = (
            self.security_graph.sources_owned_by(function)
            if function
            else self.security_graph.sources
        )
        rows = [n.as_dict() for n in sorted(nodes, key=lambda n: n.ref)[:_MAX_ROWS]]
        return self._record("get_sources", {"function": function}, rows, started)

    def get_sinks(self, function: str = "") -> list[dict[str, Any]]:
        started = time.perf_counter()
        nodes = (
            self.security_graph.sinks_owned_by(function)
            if function
            else self.security_graph.sinks
        )
        rows = [n.as_dict() for n in sorted(nodes, key=lambda n: n.ref)[:_MAX_ROWS]]
        return self._record("get_sinks", {"function": function}, rows, started)

    def get_sanitizers(self, function: str = "") -> list[dict[str, Any]]:
        started = time.perf_counter()
        nodes = [
            n
            for n in [*self.security_graph.sanitizers, *self.security_graph.validators]
            if not function or n.owner == function
        ]
        rows = [n.as_dict() for n in sorted(nodes, key=lambda n: n.ref)[:_MAX_ROWS]]
        return self._record("get_sanitizers", {"function": function}, rows, started)

    def get_controls(self, function: str = "") -> list[dict[str, Any]]:
        started = time.perf_counter()
        nodes = [
            n for n in self.security_graph.controls if not function or n.owner == function
        ]
        rows = [n.as_dict() for n in sorted(nodes, key=lambda n: n.ref)[:_MAX_ROWS]]
        return self._record("get_controls", {"function": function}, rows, started)

    def get_trust_boundaries(self) -> list[dict[str, Any]]:
        started = time.perf_counter()
        rows = [b.as_dict() for b in self.security_graph.boundaries.values()]
        return self._record("get_trust_boundaries", {}, rows, started)

    def get_security_candidates(self, *, limit: int = 20) -> list[dict[str, Any]]:
        """The ranked attack surface. What to look at, in order, with the reasons."""
        started = time.perf_counter()
        if self.attack_surface is None:
            rows = [
                {"ref": f.ref, "severity": f.severity, "confidence": f.confidence}
                for f in self.security_graph.top_flows(limit)
            ]
        else:
            rows = [i.as_dict() for i in self.attack_surface.top(limit)]
        return self._record("get_security_candidates", {"limit": limit}, rows, started)

    # -- tests / coverage / runtime ----------------------------------------
    def get_related_tests(self, symbol: str) -> list[dict[str, Any]]:
        started = time.perf_counter()
        rows: list[dict[str, Any]] = []
        for edge in self.code_graph.out_edges(symbol, EdgeKind.TESTED_BY.value):
            node = self.code_graph.node(edge.dst)
            if node is None:
                continue
            rows.append(
                {
                    "test_file": node.qualname,
                    "framework": node.attrs.get("framework", ""),
                    "cases": (node.attrs.get("cases") or [])[:20],
                    "command": node.attrs.get("command") or [],
                    # Named explicitly so a static reference is never read as measured coverage.
                    "basis": edge.attrs.get("basis", "static name reference"),
                }
            )
        return self._record("get_related_tests", {"symbol": symbol}, rows[:_MAX_ROWS], started)

    def get_coverage(self, target: str = "") -> dict[str, Any]:
        started = time.perf_counter()
        if not self.coverage:
            result = {
                "available": False,
                "reason": (
                    "No coverage has been measured in this run. Nothing was executed, or the "
                    "target has no instrumented harness."
                ),
            }
        elif target:
            result = {"available": True, "target": target, "coverage": self.coverage.get(target)}
        else:
            result = {"available": True, **self.coverage}
        return self._record("get_coverage", {"target": target}, result, started)

    def get_runtime_observations(self, target: str = "") -> dict[str, Any]:
        started = time.perf_counter()
        if not self.runtime:
            result = {
                "available": False,
                "reason": "No runtime observation exists for this run (nothing was executed).",
            }
        else:
            result = {"available": True, **({target: self.runtime.get(target)} if target else self.runtime)}
        return self._record("get_runtime_observations", {"target": target}, result, started)

    # -- configuration / dependencies / architecture -----------------------
    def get_configuration(self, key: str = "") -> list[dict[str, Any]]:
        started = time.perf_counter()
        rows: list[dict[str, Any]] = []
        for node in self.code_graph.nodes_of(NodeKind.CONFIGURATION.value):
            settings_list = node.attrs.get("settings") or []
            if key and key not in str(node.qualname) and not any(
                key == s.get("id") for s in settings_list
            ):
                continue
            rows.append(
                {
                    "path": node.qualname,
                    "role": node.attrs.get("role", ""),
                    "settings": settings_list,
                    "ports": node.attrs.get("ports") or [],
                }
            )
        return self._record("get_configuration", {"key": key}, rows[:_MAX_ROWS], started)

    def get_dependencies(self, *, sensitive_only: bool = False) -> dict[str, Any]:
        started = time.perf_counter()
        from app.understanding.dependencies import model_from_graph

        model = model_from_graph(self.code_graph)
        if sensitive_only:
            model = {
                "sensitive": model.get("sensitive", []),
                "note": model.get("note", ""),
            }
        return self._record(
            "get_dependencies", {"sensitive_only": sensitive_only}, model, started
        )

    def get_architecture_summary(self) -> dict[str, Any]:
        started = time.perf_counter()
        if self.application_model is None:
            result = {"available": False, "reason": "No architecture model was built."}
        else:
            model = self.application_model
            # A summary, not the whole model: the module list and every entrypoint's reachable
            # sink set would be a large fraction of a context window on its own.
            result = {
                "available": True,
                "application_type": model.application_type,
                "type_evidence": model.type_evidence,
                "languages": model.languages,
                "frameworks": model.frameworks,
                "authentication": model.authentication,
                "authorization": model.authorization,
                "data_stores": model.data_stores,
                "external_services": model.external_services,
                "entrypoint_count": len(model.entrypoints),
                "entrypoints": [
                    {
                        "uid": e.uid,
                        "kind": e.kind,
                        "route": e.route,
                        "unauthenticated": e.unauthenticated,
                        "reachable_sink_count": len(e.reachable_sinks),
                    }
                    for e in model.entrypoints[:_MAX_ROWS]
                ],
                "sources": model.sources,
                "sinks": model.sinks,
                "trust_boundaries": [b.get("kind") for b in model.trust_boundaries],
                "tests": model.tests,
                "gaps": model.gaps,
            }
        return self._record("get_architecture_summary", {}, result, started)

    # -- search ------------------------------------------------------------
    def search_symbols(self, query: str) -> list[dict[str, Any]]:
        started = time.perf_counter()
        rows = [n.as_dict() for n in self.code_graph.search_symbols(query, limit=_MAX_SEARCH_HITS)]
        return self._record("search_symbols", {"query": query}, rows, started)

    def search_code(self, query: str, *, max_hits: int = _MAX_SEARCH_HITS) -> list[dict[str, Any]]:
        """Literal substring search across indexed source files.

        Deliberately a plain substring scan rather than a regex: a model-supplied regex is a
        denial-of-service surface (catastrophic backtracking) against KavachX's own process, and
        nothing this tool is for needs one.
        """
        started = time.perf_counter()
        needle = query.strip()
        rows: list[dict[str, Any]] = []
        if not needle:
            return self._record("search_code", {"query": query}, rows, started, error="empty query")
        lowered = needle.lower()
        for node in self.code_graph.nodes_of(NodeKind.FILE.value):
            if len(rows) >= max_hits:
                break
            if node.attrs.get("skipped_reason"):
                continue
            path = self.root / node.uid
            if not path.is_file():
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if lowered not in text.lower():
                continue
            for number, line in enumerate(text.splitlines(), start=1):
                if lowered in line.lower():
                    owner = self.code_graph.symbol_at(node.uid, number)
                    rows.append(
                        {
                            "file": node.uid,
                            "line": number,
                            "text": line.strip()[:220],
                            "owner": owner.uid if owner else "",
                        }
                    )
                    if len(rows) >= max_hits:
                        break
        return self._record(
            "search_code", {"query": query}, rows, started, truncated=len(rows) >= max_hits
        )

    # -- helpers -----------------------------------------------------------
    def _brief(self, uid: str, *, edge_confidence: float | None = None) -> dict[str, Any]:
        node = self.code_graph.node(uid)
        if node is None:
            return {"uid": uid, "unknown": True}
        out = {
            "uid": uid,
            "kind": node.kind,
            "qualname": node.qualname,
            "location": f"{node.file}:{node.start_line}",
            "provenance": sorted(node.provenance),
        }
        if edge_confidence is not None:
            # The edge's own confidence travels with the row, so a model reading a caller list
            # can tell a resolved reference from a name match.
            out["edge_confidence"] = round(edge_confidence, 3)
        return out

    def _edge_confidence(self, src: str, dst: str) -> float:
        for edge in self.code_graph.out_edges(src, EdgeKind.CALLS.value):
            if edge.dst == dst:
                return edge.confidence
        return 0.0


def _empty() -> Any:
    from app.indexing.model import CodeNode
    from app.indexing.model import NodeKind as _NK

    return CodeNode(uid="", kind=_NK.UNKNOWN.value)


#: The tool catalogue, for documentation and for a future function-calling transport. Names match
#: the method names exactly so a dispatcher needs no translation table.
TOOL_CATALOGUE: tuple[tuple[str, str], ...] = (
    ("get_file", "A bounded, line-numbered window of one indexed file."),
    ("get_function", "A symbol's metadata, body slice, callers and callees."),
    ("get_class", "A class's methods, inheritance and interfaces."),
    ("get_callers", "Who calls this symbol, with per-edge confidence."),
    ("get_callees", "What this symbol calls, with per-edge confidence."),
    ("get_imports", "Import statements of one file."),
    ("get_dependents", "Transitive reverse dependencies of a symbol."),
    ("get_siblings", "Callables in the same file or module."),
    ("get_execution_path", "Call path from an entrypoint, optionally to a target."),
    ("get_dataflow", "Computed security flows, filtered by source or sink."),
    ("get_sources", "External-input sources, optionally within one function."),
    ("get_sinks", "Dangerous operations, optionally within one function."),
    ("get_sanitizers", "Sanitizers and validators, optionally within one function."),
    ("get_controls", "Authentication and authorisation checks."),
    ("get_trust_boundaries", "Trust boundaries and their crossing points."),
    ("get_security_candidates", "The ranked attack surface, with priority factors."),
    ("get_related_tests", "Tests that statically reference a symbol."),
    ("get_coverage", "Measured coverage, or an explicit statement that there is none."),
    ("get_runtime_observations", "Runtime observations, or an explicit absence."),
    ("get_configuration", "Discovered configuration and security-relevant settings."),
    ("get_dependencies", "The dependency model (understanding, not advisories)."),
    ("get_architecture_summary", "The derived application model, summarised."),
    ("search_symbols", "Substring search over symbol names."),
    ("search_code", "Literal substring search over indexed source."),
)
