"""GitNexus adapter — the only module in KavachX that knows what GitNexus is.

GitNexus (https://github.com/abhigyanpatwari/GitNexus, PolyForm Noncommercial 1.0.0) indexes a
repository into a LadybugDB knowledge graph and exposes it over a CLI. It resolves imports, class
heritage, field types and call targets across files, which is precisely the analysis KavachX's own
tree-sitter indexer does not attempt.

It is an **optional** dependency. Every method here reports unavailability as a first-class,
explainable outcome rather than raising, and :mod:`app.indexing.service` degrades to tree-sitter
alone and says so. That keeps two things true at once: KavachX gets a real resolved code graph
when GitNexus is installed, and KavachX remains a working system (and remains licence-clean for a
commercial deployment) when it is not.

Facts this adapter is built on, verified against 1.6.9 rather than assumed:

* ``analyze`` writes its index into a ``.gitnexus/`` directory **inside the analysed tree**. So it
  is pointed at the sandbox ``work/`` copy, never ``pristine/``, whose hash is the pinned-source
  identity.
* ``analyze`` also registers the repository in a **machine-global** registry at
  ``~/.gitnexus/registry.json``, keyed by directory basename. Every KavachX workspace is called
  ``work``, so a bare registration would collide across runs — and a query with no ``-r`` fails
  outright once any second repository exists on the host. Both problems are solved by registering
  a unique ``--name`` alias per index and passing ``-r <alias>`` on every single query.
* Query subcommands print JSON on stdout (``fs.writeSync(1, JSON.stringify(x, null, 2))``) while
  warnings go to stderr, so stdout is parsed and stderr is only ever logged.
* ``cypher`` returns ``{"markdown": "<pipe table>", "row_count": N}`` for tabular results. Whole
  nodes come back as JSON embedded in a table cell, so every query here returns **scalar columns
  only** and the pipe table is parsed deterministically.
* Its graph uses one relationship table, ``CodeRelation``, discriminated by ``r.type``
  (``DEFINES``, ``CONTAINS``, ``MEMBER_OF``, ``CALLS``, ``IMPORTS``, ``STEP_IN_PROCESS``, and
  heritage/export types on languages that support them).
"""

from __future__ import annotations

import asyncio
import json
import os
import platform
import re
import shutil
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.config import settings
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

#: GitNexus node label -> KavachX node kind. Unknown labels are kept as UNKNOWN with the original
#: label in ``attrs``, so a new GitNexus release adds nodes we can still see rather than silently
#: dropping them.
_LABEL_TO_KIND: dict[str, str] = {
    "File": NodeKind.FILE.value,
    "Folder": NodeKind.DIRECTORY.value,
    "Module": NodeKind.MODULE.value,
    "Package": NodeKind.PACKAGE.value,
    "Function": NodeKind.FUNCTION.value,
    "Method": NodeKind.METHOD.value,
    "Class": NodeKind.CLASS.value,
    "Interface": NodeKind.INTERFACE.value,
    "Variable": NodeKind.VARIABLE.value,
    "Property": NodeKind.PROPERTY.value,
    "Parameter": NodeKind.PARAMETER.value,
    "Process": NodeKind.PROCESS.value,
    "Community": NodeKind.CLUSTER.value,
    "Section": NodeKind.SYMBOL.value,
}

#: GitNexus ``CodeRelation.type`` -> KavachX edge kind.
_TYPE_TO_EDGE: dict[str, str] = {
    "CONTAINS": EdgeKind.CONTAINS.value,
    "DEFINES": EdgeKind.DEFINES.value,
    "IMPORTS": EdgeKind.IMPORTS.value,
    "EXPORTS": EdgeKind.EXPORTS.value,
    "CALLS": EdgeKind.CALLS.value,
    "MEMBER_OF": EdgeKind.MEMBER_OF.value,
    "STEP_IN_PROCESS": EdgeKind.STEP_IN_PROCESS.value,
    "INHERITS": EdgeKind.INHERITS.value,
    "EXTENDS": EdgeKind.INHERITS.value,
    "IMPLEMENTS": EdgeKind.IMPLEMENTS.value,
    "DEPENDS_ON": EdgeKind.DEPENDS_ON.value,
}


class GitNexusUnavailable(RuntimeError):
    """GitNexus is not installed or not runnable. Never fatal — callers degrade."""


@dataclass(slots=True)
class GitNexusInfo:
    available: bool = False
    version: str = ""
    #: How the binary was found: env | path | repo-local | npx | (empty when unavailable).
    resolution: str = ""
    command: list[str] = field(default_factory=list)
    node_version: str = ""
    reason: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "available": self.available,
            "version": self.version,
            "resolution": self.resolution,
            "command": self.command,
            "node_version": self.node_version,
            "reason": self.reason,
        }


@dataclass(slots=True)
class AnalyzeReport:
    """What one ``gitnexus analyze`` invocation actually did."""

    ok: bool = False
    alias: str = ""
    duration_ms: int = 0
    files: int = 0
    nodes: int = 0
    edges: int = 0
    communities: int = 0
    processes: int = 0
    indexed_at: str = ""
    #: Provider capability report from the index's own meta.json (graph / fts / vector).
    capabilities: dict[str, Any] = field(default_factory=dict)
    #: GitNexus's cache keys — part of the index's reproducible identity.
    cache_keys: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    error: str = ""
    stderr_tail: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "alias": self.alias,
            "duration_ms": self.duration_ms,
            "files": self.files,
            "nodes": self.nodes,
            "edges": self.edges,
            "communities": self.communities,
            "processes": self.processes,
            "indexed_at": self.indexed_at,
            "capabilities": self.capabilities,
            "cache_keys": self.cache_keys,
            "warnings": self.warnings,
            "error": self.error,
        }


# ---------------------------------------------------------------------------
def _windows_variants(path: Path) -> list[Path]:
    """Launchable spellings of an npm shim, most-launchable first.

    npm installs three shims per binary: an extensionless shell script (for Git Bash / WSL), a
    ``.cmd`` batch wrapper and a ``.ps1``. Only the ``.cmd`` is executable by ``CreateProcess``,
    so handing the extensionless one to ``subprocess`` on Windows fails with
    ``[WinError 193] %1 is not a valid Win32 application`` — which is exactly what a naive
    resolution does, and it looks like "GitNexus is broken" rather than "wrong spelling picked".
    """
    if platform.system() != "Windows":
        return [path]
    if path.suffix.lower() in (".cmd", ".bat", ".exe"):
        return [path]
    return [path.with_suffix(".cmd"), path.with_suffix(".exe"), path.with_suffix(".bat"), path]


def _first_launchable(path: Path) -> Path | None:
    for candidate in _windows_variants(path):
        if candidate.is_file():
            return candidate
    return None


def _repo_local_candidates() -> list[Path]:
    """Repo-local install locations, in the order ``make gitnexus`` produces them.

    GitNexus lives in its own ``gitnexus/`` directory rather than at the repository root: it is
    the only Node dependency the backend has, and keeping its manifest, lockfile and
    ``node_modules`` out of the root stops a PolyForm Noncommercial package from looking like a
    root-level dependency of KavachX itself. The pre-move root install is still accepted as a
    fallback so a checkout that ran ``make gitnexus`` before the move keeps its resolved graph
    instead of silently dropping to tree-sitter-only.
    """
    root = settings.repo_root
    return [
        root / "gitnexus" / "node_modules" / ".bin" / "gitnexus",
        root / "node_modules" / ".bin" / "gitnexus",
    ]


def resolve_command() -> GitNexusInfo:
    """Find a runnable GitNexus, in a documented order of authority.

    ``GITNEXUS_BIN`` → ``PATH`` → repo-local ``gitnexus/node_modules/.bin`` → ``npx`` (opt-in
    only).

    ``npx`` is last and off by default because it reaches the network on first use per machine
    and is slow; an indexer that silently downloads a package mid-run is not something a security
    tool should do without the operator having asked for it.
    """
    info = GitNexusInfo(node_version=_node_version())

    configured = (settings.gitnexus_bin or "").strip()
    if configured:
        launchable = _first_launchable(Path(configured))
        on_path = shutil.which(configured)
        if launchable is not None:
            info.command = [str(launchable)]
            info.resolution = "env"
        elif on_path:
            info.command = [str(on_path)]
            info.resolution = "env"
        else:
            info.reason = f"GITNEXUS_BIN={configured!r} is not an executable file or on PATH."
            return info

    if not info.command:
        found = shutil.which("gitnexus")
        if found:
            info.command = [found]
            info.resolution = "path"

    if not info.command:
        for candidate in _repo_local_candidates():
            launchable = _first_launchable(candidate)
            if launchable is not None:
                info.command = [str(launchable)]
                info.resolution = "repo-local"
                break

    if not info.command and settings.gitnexus_allow_npx:
        npx = shutil.which("npx")
        if npx:
            info.command = [npx, "-y", f"gitnexus@{settings.gitnexus_version}"]
            info.resolution = "npx"

    if not info.command:
        info.reason = (
            "GitNexus was not found. Install it repo-locally with `make gitnexus` (or "
            "`npm install` in the `gitnexus/` directory), install it globally with "
            "`npm install -g gitnexus`, or set GITNEXUS_BIN. Without it KavachX indexes with "
            "tree-sitter only and every reachability claim is name-matched rather than resolved."
        )
        return info

    version, probe_error = _probe_version(info.command)
    if not version:
        info.reason = (
            f"GitNexus was found at {info.command[0]!r} but did not report a version"
            + (f" ({probe_error})" if probe_error else "")
            + "; treating it as unavailable rather than trusting an index from a binary that "
            "will not run."
        )
        return info

    info.version = version
    info.available = True
    return info


def _node_version() -> str:
    node = shutil.which("node")
    if not node:
        return ""
    try:
        import subprocess

        out = subprocess.run(
            [node, "--version"], capture_output=True, text=True, timeout=20, check=False
        )
        return out.stdout.strip()
    except Exception:  # pragma: no cover - environment dependent
        return ""


def _probe_version(command: list[str]) -> tuple[str, str]:
    """``(version, error)``. The error is surfaced to the operator, not just logged.

    "GitNexus did not report a version" is useless on its own; ``WinError 193`` immediately tells
    an operator they have the wrong shim, so the reason string carries it.
    """
    try:
        import subprocess

        out = subprocess.run(
            [*command, "--version"],
            capture_output=True,
            text=True,
            timeout=settings.gitnexus_probe_timeout_seconds,
            check=False,
        )
    except Exception as exc:  # pragma: no cover - environment dependent
        logger.warning("gitnexus.version_probe_failed", error=str(exc)[:200])
        return "", f"{type(exc).__name__}: {str(exc)[:160]}"
    text = (out.stdout or out.stderr or "").strip()
    match = re.search(r"\d+\.\d+\.\d+(?:-[A-Za-z0-9.]+)?", text)
    if match:
        return match.group(0), ""
    return "", f"exit {out.returncode}, output {text[:160]!r}"


def _child_env() -> dict[str, str]:
    """Environment for the GitNexus child process.

    GitNexus runs on the **host**, outside the sandbox, over an already-pinned tree — it is an
    indexer, not an execution of the target. It still gets a reduced environment: the sandbox's
    forbidden-marker assertion is reused so a credential cannot reach a third-party process, and
    optional-extension installation is pinned to ``load-only`` so indexing never reaches the
    network on its own initiative.
    """
    from app.sandbox.base import FORBIDDEN_ENV_MARKERS

    env: dict[str, str] = {}
    for key, value in os.environ.items():
        upper = key.upper()
        if any(marker in upper for marker in FORBIDDEN_ENV_MARKERS):
            continue
        env[key] = value

    env["GITNEXUS_LBUG_EXTENSION_INSTALL"] = settings.gitnexus_extension_install
    env["GITNEXUS_SKIP_OPTIONAL_GRAMMARS"] = "1" if settings.gitnexus_skip_optional_grammars else "0"
    # Full-text/BM25 and embeddings are not used by KavachX — the graph is. Keeping them off makes
    # indexing faster and keeps the child offline.
    env.setdefault("GITNEXUS_DEBUG", "0")
    return env


# ---------------------------------------------------------------------------
class GitNexusAdapter:
    """One adapter instance owns one GitNexus index, identified by a unique alias.

    ``alias`` is what makes concurrent runs safe. GitNexus's registry is global and keyed by
    directory basename; since every KavachX workspace directory is named ``work``, two runs would
    otherwise fight over one registry entry and queries would resolve to the wrong tree.
    """

    provider = Provider.GITNEXUS.value

    def __init__(self, *, workspace: Path, alias: str, info: GitNexusInfo | None = None) -> None:
        self.workspace = workspace
        self.alias = alias
        self.info = info or resolve_command()
        self._analyzed = False

    # -- lifecycle ---------------------------------------------------------
    @property
    def available(self) -> bool:
        return self.info.available

    @property
    def index_dir(self) -> Path:
        return self.workspace / ".gitnexus"

    async def analyze(self, *, timeout_seconds: int | None = None) -> AnalyzeReport:
        """Build (or refresh) the index for this workspace.

        Flags, and why each one is not optional for KavachX:

        * ``--skip-git`` — the workspace lives *inside* the KavachX checkout. Without this,
          GitNexus walks up to the nearest ``.git`` and indexes KavachX itself instead of the
          target.
        * ``--index-only`` — suppresses every file-injection side effect (``AGENTS.md``,
          ``CLAUDE.md``, ``.claude/skills/``). Writing agent instructions into a tree under
          security analysis would both corrupt the pinned artifact and hand repository-adjacent
          text a channel into an agent's prompt.
        * ``--name <alias>`` — unique registry identity, per the class docstring.
        * ``--max-file-size`` — bounded parse cost on a hostile tree.
        """
        report = AnalyzeReport(alias=self.alias)
        if not self.available:
            report.error = self.info.reason or "GitNexus is unavailable."
            return report

        argv = [
            *self.info.command,
            "analyze",
            str(self.workspace),
            "--skip-git",
            "--index-only",
            "--name",
            self.alias,
            "--allow-duplicate-name",
            "--max-file-size",
            str(settings.gitnexus_max_file_size_kb),
        ]
        if settings.gitnexus_workers > 0:
            argv += ["--workers", str(settings.gitnexus_workers)]
        if settings.gitnexus_pdg:
            # Opt-in CFG/PDG substrate. Enables statement-level dependence queries; costs time.
            argv.append("--pdg")

        started = time.perf_counter()
        code, _stdout, stderr = await self._run(
            argv, timeout_seconds=timeout_seconds or settings.gitnexus_analyze_timeout_seconds
        )
        report.duration_ms = int((time.perf_counter() - started) * 1000)
        report.stderr_tail = stderr[-2000:]

        if code != 0:
            report.error = (
                f"gitnexus analyze exited {code}. Indexing continues with tree-sitter only. "
                f"stderr: {stderr[-400:]}"
            )
            logger.warning("gitnexus.analyze_failed", code=code, stderr=stderr[-400:])
            return report

        for line in stderr.splitlines():
            lowered = line.lower()
            if "warning" in lowered or "unavailable" in lowered:
                cleaned = _strip_ansi(line).strip()
                if cleaned and cleaned not in report.warnings:
                    report.warnings.append(cleaned[:300])

        meta = self._read_meta()
        if meta is None:
            report.error = (
                "gitnexus analyze reported success but wrote no readable "
                f"{self.index_dir.name}/meta.json, so the index cannot be trusted."
            )
            return report

        stats = meta.get("stats") or {}
        report.files = int(stats.get("files", 0) or 0)
        report.nodes = int(stats.get("nodes", 0) or 0)
        report.edges = int(stats.get("edges", 0) or 0)
        report.communities = int(stats.get("communities", 0) or 0)
        report.processes = int(stats.get("processes", 0) or 0)
        report.indexed_at = str(meta.get("indexedAt", ""))
        report.capabilities = dict(meta.get("capabilities") or {})
        report.cache_keys = [str(k) for k in (meta.get("cacheKeys") or [])]

        # A structurally empty index is a failure that reports success. Catch it here rather than
        # letting an empty graph read as "this repository has no code".
        if report.nodes == 0:
            report.error = (
                "gitnexus analyze produced an index with zero nodes. Treating the provider as "
                "unavailable for this run rather than reporting an empty graph as a result."
            )
            return report

        report.ok = True
        self._analyzed = True
        logger.info(
            "gitnexus.analyzed",
            alias=self.alias,
            files=report.files,
            nodes=report.nodes,
            edges=report.edges,
            processes=report.processes,
            ms=report.duration_ms,
        )
        return report

    def _read_meta(self) -> dict[str, Any] | None:
        for name in ("meta.json", "gitnexus.json"):
            path = self.index_dir / name
            if not path.is_file():
                continue
            try:
                return json.loads(path.read_text(encoding="utf-8", errors="replace"))
            except (OSError, ValueError):
                continue
        return None

    async def cleanup(self) -> None:
        """Deregister the alias so the machine-global registry does not accumulate dead runs.

        Best-effort by design: a failure here costs a stale registry row, and must never fail a
        run that has already produced its evidence.
        """
        if not self.available:
            return
        try:
            await self._run(
                [*self.info.command, "remove", self.alias, "--force"],
                timeout_seconds=settings.gitnexus_probe_timeout_seconds,
            )
        except Exception as exc:  # pragma: no cover - best effort
            logger.warning("gitnexus.cleanup_failed", alias=self.alias, error=str(exc)[:200])

    # -- queries -----------------------------------------------------------
    async def cypher(self, statement: str, *, limit: int | None = None) -> list[dict[str, Any]]:
        """Run a Cypher statement and return rows as dicts.

        Always ask for **scalar columns**. Returning a whole node makes GitNexus embed a JSON blob
        inside a markdown table cell, which is both fragile to parse and needlessly large.
        """
        if not self._analyzed:
            raise GitNexusUnavailable("No GitNexus index has been built for this workspace.")
        argv = [*self.info.command, "cypher", statement, "-r", self.alias]
        if limit is not None:
            argv += ["--limit", str(limit)]
        code, stdout, stderr = await self._run(
            argv, timeout_seconds=settings.gitnexus_query_timeout_seconds
        )
        if code != 0:
            raise GitNexusUnavailable(f"cypher exited {code}: {stderr[-300:]}")
        return _parse_cypher(stdout, statement=statement)

    async def tool_json(self, subcommand: str, *args: str) -> Any:
        """Run a query subcommand that emits structured JSON (``impact``, ``context``, ``trace``)."""
        if not self._analyzed:
            raise GitNexusUnavailable("No GitNexus index has been built for this workspace.")
        argv = [*self.info.command, subcommand, *args, "-r", self.alias]
        code, stdout, stderr = await self._run(
            argv, timeout_seconds=settings.gitnexus_query_timeout_seconds
        )
        if code != 0:
            raise GitNexusUnavailable(f"{subcommand} exited {code}: {stderr[-300:]}")
        try:
            return json.loads(stdout.strip() or "null")
        except ValueError as exc:
            raise GitNexusUnavailable(
                f"{subcommand} did not emit JSON: {stdout[:200]!r}"
            ) from exc

    async def impact(self, symbol: str, *, depth: int = 3) -> dict[str, Any]:
        """Provider-computed blast radius for one symbol.

        Used as *corroboration* for KavachX's own blast-radius computation, never as a
        replacement: KavachX's version is what the patch policy gate enforces, and that has to be
        computed from the graph KavachX itself can show its working for.
        """
        result = await self.tool_json(
            "impact", symbol, "--depth", str(depth), "--summary-only"
        )
        return result if isinstance(result, dict) else {}

    async def trace(self, source: str, target: str, *, depth: int = 10) -> dict[str, Any]:
        result = await self.tool_json("trace", source, target, "--depth", str(depth))
        return result if isinstance(result, dict) else {}

    # -- graph extraction --------------------------------------------------
    async def build_graph(self) -> tuple[CodeGraph, list[str]]:
        """Pull the whole index into a KavachX :class:`CodeGraph`.

        Two queries, not one per node: on a repository of any size the per-symbol round trip cost
        dominates (each invocation is a fresh Node process opening LadybugDB). One node query plus
        one edge query keeps indexing linear in process count regardless of repository size.
        """
        warnings: list[str] = []
        graph = CodeGraph()
        graph.providers = [self.provider]

        node_rows = await self.cypher(
            "MATCH (n) RETURN n.id AS id, n.name AS name, n.filePath AS file, "
            "n.startLine AS startLine, n.endLine AS endLine, n.isExported AS isExported, "
            "label(n) AS lbl",
            limit=settings.gitnexus_max_rows,
        )
        if not node_rows:
            warnings.append("GitNexus returned no nodes; its contribution to the graph is empty.")

        for row in node_rows:
            raw_id = str(row.get("id") or "").strip()
            label = str(row.get("lbl") or "").strip()
            if not raw_id:
                continue
            uid = canonical_uid(raw_id, label=label)
            if not uid:
                continue
            kind = _LABEL_TO_KIND.get(label, NodeKind.UNKNOWN.value)
            file_path = _posix(str(row.get("file") or ""))
            name = str(row.get("name") or "")
            node = CodeNode(
                uid=uid,
                kind=kind,
                name=name or uid.rsplit(":", 1)[-1],
                qualname=uid.split(":", 1)[1] if ":" in uid else name,
                file=file_path or (uid if kind == NodeKind.FILE.value else ""),
                start_line=_int(row.get("startLine")),
                end_line=_int(row.get("endLine")),
                exported=_bool(row.get("isExported")),
                provenance={self.provider},
                attrs={"gitnexus_id": raw_id, "gitnexus_label": label},
            )
            graph.add_node(node)

        edge_rows = await self.cypher(
            "MATCH (a)-[r:CodeRelation]->(b) "
            "RETURN a.id AS src, b.id AS dst, r.type AS rel, label(a) AS srcLbl, "
            "label(b) AS dstLbl",
            limit=settings.gitnexus_max_rows,
        )
        unknown_types: dict[str, int] = {}
        for row in edge_rows:
            raw_src = str(row.get("src") or "").strip()
            raw_dst = str(row.get("dst") or "").strip()
            rel = str(row.get("rel") or "").strip().upper()
            if not raw_src or not raw_dst or not rel:
                continue
            src = canonical_uid(raw_src, label=str(row.get("srcLbl") or ""))
            dst = canonical_uid(raw_dst, label=str(row.get("dstLbl") or ""))
            if not src or not dst:
                continue
            kind = _TYPE_TO_EDGE.get(rel)
            if kind is None:
                unknown_types[rel] = unknown_types.get(rel, 0) + 1
                kind = EdgeKind.UNKNOWN.value
            graph.add_edge(
                CodeEdge(
                    src=src,
                    dst=dst,
                    kind=kind,
                    provenance={self.provider},
                    # A resolved relationship is the strongest structural evidence available.
                    confidence=1.0,
                    attrs={"gitnexus_type": rel} if kind == EdgeKind.UNKNOWN.value else {},
                )
            )

        for rel, count in sorted(unknown_types.items()):
            warnings.append(
                f"GitNexus reported {count} '{rel}' relationship(s) that KavachX does not map to "
                "a known edge kind; they are recorded as UNKNOWN and excluded from reachability."
            )

        graph.warnings.extend(warnings)
        logger.info(
            "gitnexus.graph_built",
            alias=self.alias,
            nodes=len(graph),
            edges=len(graph.edges),
            warnings=len(warnings),
        )
        return graph, warnings

    # -- process / execution flows ----------------------------------------
    async def execution_flows(self) -> list[dict[str, Any]]:
        """GitNexus "Processes": provider-derived execution flows from an entry point.

        Returned as plain data for :mod:`app.understanding` to fold into the architecture model.
        Failure is non-fatal: flows enrich understanding, they do not gate any verdict.
        """
        try:
            rows = await self.cypher(
                "MATCH (a)-[r:CodeRelation]->(b) WHERE r.type='STEP_IN_PROCESS' "
                "RETURN a.id AS member, b.id AS process, label(a) AS memberLbl",
                limit=settings.gitnexus_max_rows,
            )
        except GitNexusUnavailable as exc:
            logger.warning("gitnexus.flows_failed", error=str(exc)[:200])
            return []

        grouped: dict[str, list[str]] = {}
        for row in rows:
            process = str(row.get("process") or "").strip()
            member = canonical_uid(
                str(row.get("member") or "").strip(), label=str(row.get("memberLbl") or "")
            )
            if not process or not member:
                continue
            grouped.setdefault(process, []).append(member)
        return [
            {"process": process, "members": sorted(set(members))}
            for process, members in sorted(grouped.items())
        ]

    # -- subprocess --------------------------------------------------------
    async def _run(
        self, argv: list[str], *, timeout_seconds: int
    ) -> tuple[int, str, str]:
        """Run GitNexus with a hard timeout, capturing stdout and stderr separately."""
        logger.debug("gitnexus.exec", argv=argv[:4], timeout=timeout_seconds)
        try:
            process = await asyncio.create_subprocess_exec(
                *argv,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=str(self.workspace),
                env=_child_env(),
            )
        except (OSError, ValueError) as exc:
            return 127, "", f"could not start gitnexus: {exc}"

        try:
            out, err = await asyncio.wait_for(process.communicate(), timeout=timeout_seconds)
        except TimeoutError:
            process.kill()
            with_suppress = getattr(process, "communicate", None)
            if with_suppress is not None:
                try:
                    await process.communicate()
                except Exception:  # pragma: no cover - process already dead
                    pass
            return 124, "", f"gitnexus timed out after {timeout_seconds}s"

        return (
            process.returncode or 0,
            out.decode("utf-8", errors="replace"),
            err.decode("utf-8", errors="replace"),
        )


# ---------------------------------------------------------------------------
# parsing helpers
# ---------------------------------------------------------------------------
_ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]|\x1b\[2K")


def _strip_ansi(text: str) -> str:
    return _ANSI.sub("", text)


def canonical_uid(raw_id: str, *, label: str = "") -> str:
    """Map a GitNexus node id onto a KavachX uid.

    GitNexus ids look like ``Function:src/main.py:main`` or ``File:src/main.py``. KavachX uids are
    ``src/main.py:main`` and ``src/main.py`` — the ``handle`` shape :mod:`app.analysis.indexer`
    already produces. Stripping the label prefix is what makes the two providers' nodes land on
    the same identity so they can merge, and it keeps every downstream consumer (root-cause
    verification, blast radius, the sibling hunt) working unchanged.

    Synthetic ids with no path component (GitNexus process ids such as ``proc_0_entrypoint``) are
    namespaced instead of stripped, so they cannot collide with a real file path.
    """
    text = raw_id.strip()
    if not text:
        return ""
    if ":" not in text:
        # A synthetic node (process, community). Namespace it explicitly.
        return f"gitnexus/{label.lower() or 'node'}:{text}" if label else f"gitnexus/node:{text}"
    prefix, remainder = text.split(":", 1)
    # Only strip a prefix that really is a label; a path-shaped prefix must survive intact.
    if prefix and prefix[:1].isupper() and "/" not in prefix and "." not in prefix:
        remainder = remainder.strip()
        return _posix(remainder)
    return _posix(text)


def _posix(path: str) -> str:
    return path.replace("\\", "/").strip()


def _int(value: Any) -> int:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return 0


def _bool(value: Any) -> bool:
    return str(value).strip().lower() in ("true", "1", "yes")


def _parse_cypher(stdout: str, *, statement: str) -> list[dict[str, Any]]:
    """Turn a ``cypher`` response into rows.

    Two response shapes exist, both handled: a tabular result
    ``{"markdown": "| a | b |\\n| --- | --- |\\n| 1 | 2 |", "row_count": 1}`` and a raw row array.
    An ``{"error": ...}`` body is raised rather than returned as zero rows, because "the query
    failed" and "the repository has none of these" must not collapse into the same answer.
    """
    text = stdout.strip()
    if not text:
        return []
    try:
        payload = json.loads(text)
    except ValueError as exc:
        raise GitNexusUnavailable(
            f"cypher returned non-JSON output for {statement[:80]!r}: {text[:200]!r}"
        ) from exc

    if isinstance(payload, dict) and payload.get("error"):
        raise GitNexusUnavailable(f"cypher error: {payload['error']}")

    if isinstance(payload, list):
        return [row for row in payload if isinstance(row, dict)]

    if isinstance(payload, dict) and isinstance(payload.get("markdown"), str):
        return _parse_markdown_table(payload["markdown"])

    if isinstance(payload, dict) and isinstance(payload.get("rows"), list):
        return [row for row in payload["rows"] if isinstance(row, dict)]

    return []


def _parse_markdown_table(markdown: str) -> list[dict[str, Any]]:
    """Parse GitNexus's pipe-table result format.

    The table is built as ``[header, separator, *rows].join("\\n")`` with ``|`` delimiters. Cell
    values are scalars for the queries this module issues. A ``\\|`` escape inside a value is
    honoured; anything else that fails to line up with the header is skipped rather than guessed
    at, so a malformed row never becomes a wrong fact.
    """
    lines = [line for line in markdown.splitlines() if line.strip()]
    if len(lines) < 2:
        return []

    def cells(line: str) -> list[str]:
        stripped = line.strip()
        if stripped.startswith("|"):
            stripped = stripped[1:]
        if stripped.endswith("|"):
            stripped = stripped[:-1]
        # Split on unescaped pipes only.
        parts = re.split(r"(?<!\\)\|", stripped)
        return [p.strip().replace("\\|", "|") for p in parts]

    header = cells(lines[0])
    rows: list[dict[str, Any]] = []
    for line in lines[2:]:  # line 1 is the --- separator
        values = cells(line)
        if len(values) != len(header):
            continue
        rows.append(
            {key: (None if value == "" else value) for key, value in zip(header, values, strict=True)}
        )
    return rows
