"""The indexing service — INGEST → INDEX → INDEX VALIDATION, as one auditable step.

This is the entry point the orchestrator calls. It runs every available provider, merges their
graphs, folds in the non-code discoveries (tests, configuration, dependencies), records the whole
thing as an :class:`~app.indexing.job.IndexJob`, and validates the result into an
:class:`~app.indexing.health.IndexHealthReport`.

Failure policy, which is the part that matters:

* **A provider failing is not the index failing.** GitNexus absent, broken, or timed out degrades
  the index to tree-sitter alone, records *why* in the job, and continues. The graph then reports
  ``graph_source: tree-sitter`` and the health report caps the grade — so the run proceeds with an
  honestly labelled, lower-fidelity index instead of dying.
* **The index failing is not silent.** A grade of ``F`` means the tree could not be understood at
  all; the caller is expected to treat that as a hard bound on what the run may claim, not as
  "nothing was found".
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.config import settings
from app.core.logging import get_logger
from app.indexing import health as health_mod
from app.indexing import treesitter
from app.indexing.gitnexus import GitNexusAdapter, resolve_command
from app.indexing.health import IndexHealthReport
from app.indexing.incremental import (
    AffectedClosure,
    ChangeSet,
    affected_closure,
    compute_change_set,
)
from app.indexing.job import IndexJob, IndexStatus
from app.indexing.merge import describe_source, merge_graphs
from app.indexing.model import CodeGraph
from app.indexing.versions import collect_versions, compute_index_id, index_options

logger = get_logger(__name__)


@dataclass
class IndexResult:
    """Everything one indexing run produced."""

    graph: CodeGraph
    job: IndexJob
    health: IndexHealthReport
    #: Per-file detail from the tree-sitter provider: sink hits, skip reasons, content hashes.
    file_indexes: list[Any] = field(default_factory=list)
    #: GitNexus execution flows ("Processes"), for the understanding stage. Empty when absent.
    execution_flows: list[dict[str, Any]] = field(default_factory=list)
    change_set: ChangeSet | None = None
    closure: AffectedClosure | None = None
    #: Tool events for the run event stream, in the shape the emitter expects.
    tool_events: list[dict[str, Any]] = field(default_factory=list)

    @property
    def usable(self) -> bool:
        return self.health.usable


def index_alias(*, run_short: str, index_id: str) -> str:
    """A registry alias unique to this run and index.

    GitNexus's registry is machine-global and keyed by directory basename; every KavachX workspace
    is named ``work``, so without a unique alias two concurrent runs would collide on one registry
    entry and a query could resolve against the wrong tree. The run code plus the index digest is
    both unique and reproducible.
    """
    safe = "".join(ch for ch in run_short.lower() if ch.isalnum()) or uuid.uuid4().hex[:4]
    return f"kavachx-{safe}-{index_id[:10]}"


async def build_index(
    root: Path,
    *,
    run_short: str = "adhoc",
    repository: str = "",
    commit_sha: str = "",
    source_sha256: str = "",
    previous_graph: CodeGraph | None = None,
    enable_gitnexus: bool | None = None,
) -> IndexResult:
    """Index ``root`` with every available provider and validate the result.

    ``root`` must be the **mutable** workspace copy, never the pinned ``pristine/`` tree: GitNexus
    writes its LadybugDB index into a ``.gitnexus/`` directory inside whatever it analyses, and
    writing into the pinned tree would invalidate the content hash that is the run's source
    identity.
    """
    job = IndexJob(
        repository=repository,
        commit_sha=commit_sha,
        source_sha256=source_sha256,
    ).start()

    use_gitnexus = settings.gitnexus_enabled if enable_gitnexus is None else enable_gitnexus
    info = resolve_command() if use_gitnexus else None

    job.versions = collect_versions(
        gitnexus_version=info.version if info else "",
        gitnexus_resolution=info.resolution if info else "",
        node_version=info.node_version if info else "",
    ).as_dict()
    job.options = index_options()
    job.index_id = compute_index_id(
        source_sha256=source_sha256 or "unpinned",
        versions=collect_versions(
            gitnexus_version=info.version if info else "",
            gitnexus_resolution=info.resolution if info else "",
            node_version=info.node_version if info else "",
        ),
        options=job.options,
    )
    if info is not None:
        job.provider_reports["gitnexus_info"] = info.as_dict()

    tool_events: list[dict[str, Any]] = []

    # -- provider 1: tree-sitter (always) ---------------------------------
    started = time.perf_counter()
    ts_graph, file_indexes, ts_summary = await _run_treesitter(root, job)
    tool_events.append(
        {
            "name": "tree-sitter",
            "target": f"{len(file_indexes)} files",
            "ms": int((time.perf_counter() - started) * 1000),
            "ok": len(ts_graph) > 0,
            "detail": (
                f"{ts_summary.get('symbols', 0)} symbols, "
                f"{ts_summary.get('by_indexer', {})}"
            ),
        }
    )
    job.provider_reports["tree_sitter"] = ts_summary

    # -- provider 2: GitNexus (optional) ----------------------------------
    gn_graph: CodeGraph | None = None
    execution_flows: list[dict[str, Any]] = []
    adapter: GitNexusAdapter | None = None

    if use_gitnexus and info is not None and info.available:
        adapter = GitNexusAdapter(
            workspace=root, alias=index_alias(run_short=run_short, index_id=job.index_id), info=info
        )
        started = time.perf_counter()
        gn_graph, execution_flows, report = await _run_gitnexus(adapter, job)
        tool_events.append(
            {
                "name": f"gitnexus:{info.version}",
                "target": f"{report.files} files",
                "ms": int((time.perf_counter() - started) * 1000),
                "ok": report.ok,
                "detail": (
                    f"{report.nodes} nodes, {report.edges} edges, {report.processes} flows"
                    if report.ok
                    else report.error[:300]
                ),
            }
        )
    elif use_gitnexus and info is not None:
        job.warn(info.reason or "GitNexus is unavailable.")
        tool_events.append(
            {
                "name": "gitnexus",
                "target": "unavailable",
                "ms": 0,
                "ok": False,
                "detail": info.reason[:300],
            }
        )
    else:
        job.warn(
            "GitNexus indexing is disabled (GITNEXUS_ENABLED=false). Relationships in this index "
            "are name matches, not resolved references."
        )

    # -- merge -------------------------------------------------------------
    # GitNexus first so its resolved line spans and export flags win scalar ties.
    graphs = [g for g in (gn_graph, ts_graph) if g is not None]
    graph, merge_report = merge_graphs(*graphs)
    job.merge_report = merge_report.as_dict()
    job.providers = merge_report.providers
    job.graph_source = describe_source(merge_report)
    for warning in merge_report.warnings:
        job.warn(warning)
    for warning in graph.warnings:
        job.warn(warning)

    # -- non-code discovery (tests, config, dependencies) ------------------
    # Folded into the same graph rather than kept in side-tables, so "what tests cover this
    # function" and "what configuration reaches this sink" are one query interface.
    from app.understanding import config_discovery, dependencies, tests_discovery

    try:
        test_count = tests_discovery.attach(graph, root)
    except Exception as exc:  # pragma: no cover - discovery must never fail the index
        test_count = 0
        job.warn(f"test discovery failed: {type(exc).__name__}: {str(exc)[:200]}")
    try:
        config_count = config_discovery.attach(graph, root)
    except Exception as exc:  # pragma: no cover
        config_count = 0
        job.warn(f"configuration discovery failed: {type(exc).__name__}: {str(exc)[:200]}")
    try:
        dependency_count = dependencies.attach(graph, root)
    except Exception as exc:  # pragma: no cover
        dependency_count = 0
        job.warn(f"dependency discovery failed: {type(exc).__name__}: {str(exc)[:200]}")

    # -- counters ----------------------------------------------------------
    stats = graph.stats()
    job.files_discovered = len(file_indexes)
    job.files_skipped = len([f for f in file_indexes if getattr(f, "skipped_reason", "")])
    job.files_indexed = job.files_discovered - job.files_skipped
    job.skipped_files = [
        {"path": f.path, "reason": f.skipped_reason}
        for f in file_indexes
        if getattr(f, "skipped_reason", "")
    ]
    job.languages = dict(ts_summary.get("by_language") or {})
    job.symbols_discovered = stats["functions"] + stats["classes"]
    job.functions = stats["functions"]
    job.classes = stats["classes"]
    job.relationships_discovered = stats["edges"]
    job.call_relationships = stats["call_edges"]
    job.import_relationships = stats["import_edges"]
    job.resolved_relationships = stats["resolved_edges"]
    job.entrypoints_discovered = stats["entrypoints"]
    job.tests_discovered = test_count
    job.configs_discovered = config_count
    job.dependencies_discovered = dependency_count
    job.graph_hash = graph.content_hash()

    # -- incremental bookkeeping ------------------------------------------
    change_set = compute_change_set(
        previous_graph=previous_graph, current_graph=graph, root=root
    )
    closure = affected_closure(graph, change_set) if not change_set.full else AffectedClosure()
    job.incremental = not change_set.full
    job.changed_files = change_set.changed_files[:200]
    job.affected_symbols = closure.all_symbols[:400]

    # -- validate ----------------------------------------------------------
    report = health_mod.validate(job, graph)
    if not report.usable:
        job.fail(report.summary)
        job.finish(IndexStatus.FAILED)
    elif report.grade in (health_mod.Grade.C,) or job.warnings:
        job.finish(IndexStatus.DEGRADED)
    else:
        job.finish(IndexStatus.COMPLETED)

    if adapter is not None:
        # Deregister the alias so the machine-global registry does not accumulate one dead entry
        # per run. The on-disk index stays inside the workspace and dies with it.
        await adapter.cleanup()

    logger.info(
        "indexing.complete",
        index_id=job.index_id[:16],
        status=job.status,
        grade=report.grade,
        source=job.graph_source,
        nodes=len(graph),
        edges=len(graph.edges),
        ms=job.duration_ms,
    )
    return IndexResult(
        graph=graph,
        job=job,
        health=report,
        file_indexes=file_indexes,
        execution_flows=execution_flows,
        change_set=change_set,
        closure=closure,
        tool_events=tool_events,
    )


# ---------------------------------------------------------------------------
async def _run_treesitter(root: Path, job: IndexJob) -> tuple[CodeGraph, list[Any], dict[str, Any]]:
    """Run the always-available provider off the event loop.

    Parsing a large tree is CPU-bound and synchronous; running it inline would block every other
    coroutine in the process, including the SSE stream the operator is watching.
    """
    import asyncio

    try:
        return await asyncio.to_thread(
            treesitter.build_graph, root, max_files=settings.index_max_files
        )
    except Exception as exc:
        job.fail(f"tree-sitter indexing failed: {type(exc).__name__}: {str(exc)[:300]}")
        logger.exception("indexing.treesitter_failed")
        empty = CodeGraph()
        empty.providers = []
        return empty, [], {}


async def _run_gitnexus(
    adapter: GitNexusAdapter, job: IndexJob
) -> tuple[CodeGraph | None, list[dict[str, Any]], Any]:
    """Run GitNexus, converting every failure mode into a recorded degradation."""
    report = await adapter.analyze()
    job.provider_reports["gitnexus"] = report.as_dict()
    for warning in report.warnings:
        job.warn(f"gitnexus: {warning}")

    if not report.ok:
        job.warn(
            report.error
            or "GitNexus produced no usable index; continuing with tree-sitter only."
        )
        return None, [], report

    try:
        graph, warnings = await adapter.build_graph()
    except Exception as exc:
        job.warn(
            f"GitNexus indexed successfully but its graph could not be read "
            f"({type(exc).__name__}: {str(exc)[:200]}); continuing with tree-sitter only."
        )
        logger.warning("indexing.gitnexus_read_failed", error=str(exc)[:300])
        return None, [], report

    for warning in warnings:
        job.warn(f"gitnexus: {warning}")

    try:
        flows = await adapter.execution_flows()
    except Exception as exc:  # pragma: no cover - enrichment only
        job.warn(f"GitNexus execution flows unavailable: {str(exc)[:200]}")
        flows = []

    return graph, flows, report


# ---------------------------------------------------------------------------
def graph_summary_for_state(result: IndexResult) -> dict[str, Any]:
    """The compact index/graph block written into orchestrator state and the certificate."""
    stats = result.graph.stats()
    return {
        "index_id": result.job.index_id,
        "graph_hash": result.job.graph_hash,
        "graph_source": result.job.graph_source,
        "status": result.job.status,
        "health_grade": result.health.grade,
        "claim_bounds": result.health.claim_bounds,
        "providers": result.job.providers,
        # File counts come from the job, not from graph stats, so the console and the index health
        # report never show two different "files" numbers. They legitimately differ: GitNexus's
        # walker and KavachX's `list_source_files` disagree about a couple of files (dotfiles,
        # size-capped ones), and `graph_file_nodes` records that rather than hiding it.
        "files": result.job.files_discovered,
        "files_indexed": result.job.files_indexed,
        "files_skipped": result.job.files_skipped,
        "graph_file_nodes": stats["files"],
        "functions": stats["functions"],
        "classes": stats["classes"],
        "call_edges": stats["call_edges"],
        "import_edges": stats["import_edges"],
        "resolved_edge_ratio": stats["resolved_edge_ratio"],
        "entrypoints": stats["entrypoints"],
        "tests": stats["tests"],
        "configurations": stats["configurations"],
        "dependencies": stats["dependencies"],
        "duration_ms": result.job.duration_ms,
        "warnings": result.job.warnings[:20],
    }
