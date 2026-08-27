"""The World Model.

A structured, queryable model of the target: files, functions, classes, modules, callers,
callees, entrypoints, sinks, permissions, ports, processes, deployment units and dependencies.

The design constraint that matters: **the model holds handles, not content.** A symbol handle
is ``path:qualname``. When the reasoning layer needs source, it asks
:meth:`WorldModel.code_slice` for a bounded window around one handle. The repository is never
poured into a prompt, so context cost stays flat as the target grows and repository text can
never act as an instruction.

The call graph here is built from tree-sitter call sites, resolved **by name**. It
over-approximates, and that is deliberate: a conservative caller set makes reachability
pessimistic, which is the safe direction.

``graph_source`` is set by the orchestrator from the real index job (see
:mod:`app.indexing.merge`), which records which providers actually contributed nodes and edges.
It is never inferred from a binary being present on the host: an earlier version of this module
labelled every run ``gitnexus+tree-sitter`` whenever a ``gitnexus`` executable existed on PATH,
without ever invoking it — a false provenance claim that travelled into certificates, where the
fidelity of every reachability claim depends on exactly this field.

The resolved code knowledge graph lives in :mod:`app.indexing`; this model remains the structure
the static channel, root-cause verification, blast radius and the sibling hunt query.
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.analysis.indexer import (
    COMPILED_SINKS,
    ENTRYPOINT_HINTS,
    FileIndex,
    SymbolRef,
    index_tree,
    indexer_summary,
)
from app.core.hashing import sha256_json
from app.core.logging import get_logger

logger = get_logger(__name__)

DEPENDENCY_MANIFESTS = (
    "pyproject.toml",
    "requirements.txt",
    "package.json",
    "Cargo.toml",
    "go.mod",
    "Gemfile",
    "pom.xml",
)

DEPLOYMENT_FILES = (
    "Dockerfile",
    "docker-compose.yml",
    "docker-compose.yaml",
    "Procfile",
    "Makefile",
    "build.sh",
)

#: Config keys appear as ``port: 8099``, ``"bind_port": 8099`` and ``PORT=8099`` depending on
#: the file format, so the optional closing quote before the separator is load-bearing.
_PORT_PATTERN = re.compile(r"port[\"']?\s*[:=]\s*[\"']?(\d{2,5})", re.IGNORECASE)
_BIND_PATTERN = re.compile(r"[\"'](0\.0\.0\.0|::|\*)[\"']")
_DEBUG_PATTERN = re.compile(r"\bdebug[\"']?\s*[:=]\s*[\"']?(true|1|yes|on)\b", re.IGNORECASE)
_PERMISSION_PATTERN = re.compile(r"\b(chmod|0o?7\d\d|umask|setuid|setgid|sudo)\b")


@dataclass(slots=True)
class Sink:
    handle: str
    file: str
    line: int
    category: str
    snippet: str
    function: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "handle": self.handle,
            "file": self.file,
            "line": self.line,
            "category": self.category,
            "snippet": self.snippet,
            "function": self.function,
        }


@dataclass(slots=True)
class Entrypoint:
    handle: str
    file: str
    symbol: str
    kind: str
    line: int
    signature: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "handle": self.handle,
            "file": self.file,
            "symbol": self.symbol,
            "kind": self.kind,
            "line": self.line,
            "signature": self.signature,
        }


@dataclass
class WorldModel:
    root: Path
    files: dict[str, FileIndex] = field(default_factory=dict)
    symbols: dict[str, SymbolRef] = field(default_factory=dict)
    #: handle -> handles it calls
    callees: dict[str, list[str]] = field(default_factory=lambda: defaultdict(list))
    #: handle -> handles that call it
    callers: dict[str, list[str]] = field(default_factory=lambda: defaultdict(list))
    entrypoints: list[Entrypoint] = field(default_factory=list)
    sinks: list[Sink] = field(default_factory=list)
    modules: dict[str, list[str]] = field(default_factory=lambda: defaultdict(list))
    dependencies: dict[str, Any] = field(default_factory=dict)
    deployment_units: list[dict[str, Any]] = field(default_factory=list)
    ports: list[int] = field(default_factory=list)
    permissions: list[dict[str, Any]] = field(default_factory=list)
    processes: list[dict[str, Any]] = field(default_factory=list)
    config_findings: list[dict[str, Any]] = field(default_factory=list)
    graph_source: str = "tree-sitter"
    index_summary: dict[str, Any] = field(default_factory=dict)

    # -- queries -----------------------------------------------------------
    def symbol(self, handle: str) -> SymbolRef | None:
        return self.symbols.get(handle)

    def find_symbols(self, name: str) -> list[SymbolRef]:
        lowered = name.lower()
        return [
            s
            for s in self.symbols.values()
            if s.name.lower() == lowered or s.qualname.lower().endswith(lowered)
        ]

    def symbol_at(self, file: str, line: int) -> SymbolRef | None:
        """The innermost function/method containing ``file:line``."""
        best: SymbolRef | None = None
        for symbol in self.symbols.values():
            if symbol.file != file or symbol.kind == "class":
                continue
            if symbol.start_line <= line <= symbol.end_line:
                if best is None or symbol.start_line > best.start_line:
                    best = symbol
        return best

    def caller_count(self, handle: str) -> int:
        return len(set(self.callers.get(handle, [])))

    def transitive_callers(self, handle: str, *, max_depth: int = 6) -> list[str]:
        seen: set[str] = set()
        frontier = [handle]
        depth = 0
        while frontier and depth < max_depth:
            nxt: list[str] = []
            for current in frontier:
                for caller in self.callers.get(current, []):
                    if caller not in seen:
                        seen.add(caller)
                        nxt.append(caller)
            frontier = nxt
            depth += 1
        seen.discard(handle)
        return sorted(seen)

    def reachable_from_entrypoint(self, handle: str) -> tuple[bool, list[str]]:
        """Is ``handle`` reachable from a declared entrypoint, and by what path?"""
        entry_handles = {e.handle for e in self.entrypoints}
        if handle in entry_handles:
            return True, [handle]

        # Breadth-first over the reverse edges; the first entrypoint we touch gives the path.
        queue: list[tuple[str, list[str]]] = [(handle, [handle])]
        seen = {handle}
        while queue:
            current, path = queue.pop(0)
            for caller in self.callers.get(current, []):
                if caller in seen:
                    continue
                seen.add(caller)
                new_path = [caller, *path]
                if caller in entry_handles:
                    return True, new_path
                if len(new_path) < 12:
                    queue.append((caller, new_path))
        return False, []

    def reachability_score(self, handle: str) -> float:
        reachable, path = self.reachable_from_entrypoint(handle)
        if not reachable:
            return 0.15 if self.caller_count(handle) else 0.05
        # Shorter paths from an entrypoint mean more directly exposed.
        return round(max(0.4, 1.0 - 0.08 * max(0, len(path) - 1)), 3)

    def blast_radius_score(self, handle: str) -> float:
        callers = self.transitive_callers(handle)
        modules = {c.split(":")[0].rsplit("/", 1)[0] for c in callers}
        raw = 0.2 + 0.03 * len(callers) + 0.08 * len(modules)
        return round(min(raw, 1.0), 3)

    def code_slice(
        self, handle: str, *, context_lines: int = 4, max_lines: int = 160
    ) -> dict[str, Any]:
        """Bounded source window around a symbol. This is the only path to raw source."""
        symbol = self.symbols.get(handle)
        if symbol is None:
            return {}
        return self.file_slice(
            symbol.file,
            start=max(1, symbol.start_line - context_lines),
            end=symbol.end_line + context_lines,
            max_lines=max_lines,
        )

    def file_slice(
        self, file: str, *, start: int, end: int, max_lines: int = 200
    ) -> dict[str, Any]:
        path = self.root / file
        if not path.is_file():
            return {}
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        start = max(1, start)
        end = min(len(lines), max(start, end), start + max_lines - 1)
        return {
            "file": file,
            "start_line": start,
            "end_line": end,
            "code": "\n".join(f"{n:>5}  {lines[n - 1]}" for n in range(start, end + 1)),
        }

    def neighbours_of(self, handle: str, *, limit: int = 24) -> list[dict[str, Any]]:
        """Sibling functions in the same file/module — the sibling-hunt search space."""
        symbol = self.symbols.get(handle)
        if symbol is None:
            return []
        module_dir = symbol.file.rsplit("/", 1)[0]
        out: list[dict[str, Any]] = []
        for other in self.symbols.values():
            if other.handle == handle or other.kind == "class":
                continue
            same_file = other.file == symbol.file
            same_module = other.file.rsplit("/", 1)[0] == module_dir
            if not (same_file or same_module):
                continue
            body = self.code_slice(other.handle, context_lines=0, max_lines=80)
            out.append(
                {
                    "location": f"{other.file}:{other.start_line}",
                    "handle": other.handle,
                    "function": other.qualname,
                    "same_file": same_file,
                    "snippet": body.get("code", "")[:1500],
                }
            )
            if len(out) >= limit:
                break
        return out

    def sinks_in(self, file: str) -> list[Sink]:
        return [s for s in self.sinks if s.file == file]

    # -- serialisation -----------------------------------------------------
    def summary(self) -> dict[str, Any]:
        return {
            "files": len(self.files),
            "functions": len([s for s in self.symbols.values() if s.kind != "class"]),
            "classes": len([s for s in self.symbols.values() if s.kind == "class"]),
            "modules": len(self.modules),
            "entrypoints": len(self.entrypoints),
            "sinks": len(self.sinks),
            "call_edges": sum(len(v) for v in self.callees.values()),
            "dependencies": len(self.dependencies.get("declared", [])),
            "ports": self.ports,
            "deployment_units": len(self.deployment_units),
            "graph_source": self.graph_source,
            "index_summary": self.index_summary,
        }

    def as_graph_json(self) -> dict[str, Any]:
        return {
            "schema": "kavachx.world_model.v1",
            "graph_source": self.graph_source,
            "summary": self.summary(),
            "files": {path: index.as_dict() for path, index in sorted(self.files.items())},
            "symbols": {
                handle: symbol.as_dict() for handle, symbol in sorted(self.symbols.items())
            },
            "callers": {k: sorted(set(v)) for k, v in sorted(self.callers.items())},
            "callees": {k: sorted(set(v)) for k, v in sorted(self.callees.items())},
            "entrypoints": [e.as_dict() for e in self.entrypoints],
            "sinks": [s.as_dict() for s in self.sinks],
            "modules": {k: sorted(v) for k, v in sorted(self.modules.items())},
            "dependencies": self.dependencies,
            "deployment_units": self.deployment_units,
            "ports": self.ports,
            "permissions": self.permissions,
            "processes": self.processes,
            "config_findings": self.config_findings,
        }

    def content_hash(self) -> str:
        return sha256_json(self.as_graph_json())


# ---------------------------------------------------------------------------
def build_world_model(root: Path) -> WorldModel:
    indexes = index_tree(root)
    model = WorldModel(root=root)
    model.index_summary = indexer_summary(indexes)

    for entry in indexes:
        model.files[entry.path] = entry
        module = entry.path.rsplit("/", 1)[0] or "."
        for symbol in entry.symbols:
            model.symbols[symbol.handle] = symbol
            model.modules[module].append(symbol.handle)

    _build_call_graph(model)
    _detect_entrypoints(model)
    _detect_sinks(model)
    _collect_dependencies(model)
    _collect_deployment(model)
    _collect_config_signals(model)

    logger.info(
        "world_model.built", **{k: v for k, v in model.summary().items() if k != "index_summary"}
    )
    return model


def _build_call_graph(model: WorldModel) -> None:
    """Resolve textual call sites onto symbol handles.

    Resolution is by *name*, preferring a definition in the same file, then the same module,
    then anywhere. Ambiguity is recorded as multiple edges rather than guessed away — an
    over-approximated caller set makes reachability conservative, which is the safe direction.
    """
    by_name: dict[str, list[SymbolRef]] = defaultdict(list)
    for symbol in model.symbols.values():
        by_name[symbol.name].append(symbol)

    for symbol in model.symbols.values():
        for raw_call in set(symbol.calls):
            target_name = raw_call.split("(")[0].strip().split(".")[-1]
            if not target_name or target_name == symbol.name:
                continue
            candidates = by_name.get(target_name, [])
            if not candidates:
                continue
            same_file = [c for c in candidates if c.file == symbol.file]
            module = symbol.file.rsplit("/", 1)[0]
            same_module = [c for c in candidates if c.file.rsplit("/", 1)[0] == module]
            chosen = same_file or same_module or candidates
            for target in chosen[:3]:
                model.callees[symbol.handle].append(target.handle)
                model.callers[target.handle].append(symbol.handle)


def _detect_entrypoints(model: WorldModel) -> None:
    seen: set[str] = set()

    for path, entry in model.files.items():
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
            elif any(hint == name or name.startswith(hint) for hint in ENTRYPOINT_HINTS):
                kind = "library"
            elif any(
                dec.lower().startswith(("@app.", "@router.", "@get", "@post", "@route"))
                for dec in symbol.decorators
            ):
                kind = "http"
            if not kind or symbol.handle in seen:
                continue
            seen.add(symbol.handle)
            model.entrypoints.append(
                Entrypoint(
                    handle=symbol.handle,
                    file=path,
                    symbol=symbol.qualname,
                    kind=kind,
                    line=symbol.start_line,
                    signature=f"{symbol.qualname}({', '.join(symbol.parameters)})",
                )
            )

    # Deterministic ordering: CLI entrypoints first, then by location.
    model.entrypoints.sort(key=lambda e: (e.kind != "cli", e.file, e.line))


def _detect_sinks(model: WorldModel) -> None:
    for path, entry in model.files.items():
        if entry.language not in ("python", "c", "javascript"):
            continue
        for line_no, snippet in entry.sink_hits:
            category = ""
            for pattern, label in COMPILED_SINKS:
                if pattern.search(snippet):
                    category = label
                    break
            owner = model.symbol_at(path, line_no)
            model.sinks.append(
                Sink(
                    handle=f"{path}:{line_no}",
                    file=path,
                    line=line_no,
                    category=category or "unknown",
                    snippet=snippet[:300],
                    function=owner.qualname if owner else "",
                )
            )


def _collect_dependencies(model: WorldModel) -> None:
    declared: list[str] = []
    manifests: list[str] = []
    for manifest in DEPENDENCY_MANIFESTS:
        path = model.root / manifest
        if not path.is_file():
            continue
        manifests.append(manifest)
        text = path.read_text(encoding="utf-8", errors="replace")
        if manifest == "package.json":
            try:
                data = json.loads(text)
                for section in ("dependencies", "devDependencies"):
                    declared.extend(sorted((data.get(section) or {}).keys()))
            except ValueError:
                pass
        elif manifest == "requirements.txt":
            declared.extend(
                line.split("==")[0].split(">=")[0].strip()
                for line in text.splitlines()
                if line.strip() and not line.strip().startswith("#")
            )
        elif manifest == "pyproject.toml":
            for match in re.finditer(r'^\s*"([A-Za-z0-9_.\-\[\]]+)[><=~!]', text, re.MULTILINE):
                declared.append(match.group(1))
        elif manifest == "go.mod":
            declared.extend(
                line.split()[0]
                for line in text.splitlines()
                if line.startswith("\t") and line.strip()
            )
    model.dependencies = {
        "manifests": manifests,
        "declared": sorted({d for d in declared if d})[:200],
        "count": len({d for d in declared if d}),
    }


def _collect_deployment(model: WorldModel) -> None:
    for name in DEPLOYMENT_FILES:
        path = model.root / name
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        unit: dict[str, Any] = {"file": name, "kind": _deployment_kind(name), "signals": []}
        if "USER root" in text or ("USER" not in text and name.startswith("Dockerfile")):
            unit["signals"].append("container may run as root")
        for match in _PORT_PATTERN.finditer(text):
            port = int(match.group(1))
            if port not in model.ports:
                model.ports.append(port)
            unit["signals"].append(f"exposes port {port}")
        if _BIND_PATTERN.search(text):
            unit["signals"].append("binds all interfaces")
        model.deployment_units.append(unit)


def _deployment_kind(name: str) -> str:
    if name.startswith("Dockerfile"):
        return "container_image"
    if name.startswith("docker-compose"):
        return "compose_stack"
    if name == "Procfile":
        return "process_manifest"
    return "build_script"


def _collect_config_signals(model: WorldModel) -> None:
    """Configuration / reachability signals. Candidates, not findings."""
    for path, entry in model.files.items():
        if entry.language not in ("config", "python", "javascript", "other"):
            continue
        # Prose files mention configuration without *being* configuration; scanning them just
        # manufactures noise for the reachability channel to chase.
        if path.lower().endswith((".md", ".rst", ".txt", ".adoc")):
            continue
        # Same reasoning for build output. A minified bundle's single 40,000-character line will
        # contain "host" and a literal that looks like a bind address; neither is a configuration
        # decision anyone made. The indexer already identified these — honour its verdict here too,
        # or the noise the indexer removed from `sinks` simply reappears in this channel.
        if entry.skipped_reason:
            continue
        file_path = model.root / path
        if not file_path.is_file():
            continue
        try:
            text = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if len(text) > 400_000:
            continue

        for number, line in enumerate(text.splitlines(), start=1):
            if _DEBUG_PATTERN.search(line):
                model.config_findings.append(
                    {
                        "file": path,
                        "line": number,
                        "category": "debug_enabled",
                        "snippet": line.strip()[:200],
                        "message": "Debug mode is enabled by configuration.",
                    }
                )
            if _BIND_PATTERN.search(line) and (
                "host" in line.lower() or "bind" in line.lower() or "listen" in line.lower()
            ):
                model.config_findings.append(
                    {
                        "file": path,
                        "line": number,
                        "category": "bind_all_interfaces",
                        "snippet": line.strip()[:200],
                        "message": "Service binds every network interface.",
                    }
                )
            if _PERMISSION_PATTERN.search(line):
                model.permissions.append(
                    {"file": path, "line": number, "snippet": line.strip()[:200]}
                )
            match = _PORT_PATTERN.search(line)
            if match:
                port = int(match.group(1))
                if 0 < port < 65536 and port not in model.ports:
                    model.ports.append(port)

    for sink in model.sinks:
        if sink.category in ("process_exec", "shell_exec"):
            model.processes.append(
                {
                    "file": sink.file,
                    "line": sink.line,
                    "function": sink.function,
                    "category": sink.category,
                    "snippet": sink.snippet,
                }
            )
    model.ports.sort()
