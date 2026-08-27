"""Read endpoints for the code-intelligence layer.

Everything here is a projection of what a run already recorded — the index and its health, the code
graph, the security flows, the architecture model and attack surface, the generated tests and their
executions, and the model contexts. Nothing computes anything on request: a run's evidence is
whatever it wrote at the time, and recomputing it now against a different tree or a different
GitNexus version would produce a different answer while looking like the same one.

Tenant isolation is inherited, not reimplemented: every run-scoped route depends on the same
``load_run`` used by every other router, which returns 404 for a run in another tenant (a 403 would
confirm the id exists). Permissions are declared per route with ``RequirePermission``.

Two endpoints deserve a note:

* ``/graph`` returns a **bounded subgraph** by default. The whole repository graph is neither
  renderable nor useful; the spec asks for focused subgraphs around a finding, an entrypoint, a
  function, a sink or a trust boundary, and that is what the ``uid`` and ``depth`` parameters give.
* ``/context/{candidate}`` exposes what a model was actually told. It returns the *selection* —
  files, functions, tool calls, budget, what was dropped — and never a raw prompt, so it cannot
  become a channel for target source or for secrets.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db, load_run
from app.auth.deps import Principal, RequirePermission
from app.auth.rbac import Permission
from app.core.errors import NotFound
from app.core.logging import get_logger
from app.models.indexing import (
    ArchitectureModelRow,
    GeneratedTest,
    ModelContextRow,
    RepositoryIndex,
    SecurityModelRow,
    TestExecutionRow,
)
from app.models.run import Run

logger = get_logger(__name__)

router = APIRouter(tags=["intelligence"])


# ---------------------------------------------------------------------------
@router.get("/runs/{run_id}/index")
async def get_index(
    run: Run = Depends(load_run),
    db: AsyncSession = Depends(get_db),
    principal: Principal = Depends(RequirePermission(Permission.RUN_READ)),
) -> dict[str, Any]:
    """The index job record and its health report."""
    row = await db.scalar(select(RepositoryIndex).where(RepositoryIndex.run_id == run.id))
    if row is None:
        # An explicit absence, not an empty object: a run that predates the indexing stage, or one
        # that failed before it, must not look like a run with an empty index.
        return {
            "available": False,
            "reason": (
                "This run recorded no index. It either predates the code-intelligence stages or "
                "failed before indexing completed."
            ),
        }
    return {
        "available": True,
        "index": {
            "index_id": row.index_id,
            "commit_sha": row.commit_sha,
            "source_sha256": row.source_sha256,
            "graph_hash": row.graph_hash,
            "graph_source": row.graph_source,
            "status": row.status,
            "providers": row.providers,
            "versions": row.versions,
            "options": row.options,
            "languages": row.languages,
            "files": {
                "discovered": row.files_discovered,
                "indexed": row.files_indexed,
                "skipped": row.files_skipped,
                "skipped_detail": row.skipped_files,
            },
            "symbols": {
                "total": row.symbols,
                "functions": row.functions,
                "classes": row.classes,
            },
            "relationships": {
                "total": row.relationships,
                "calls": row.call_relationships,
                "imports": row.import_relationships,
                "resolved": row.resolved_relationships,
                "resolved_ratio": row.resolved_ratio,
            },
            "discovered": {
                "entrypoints": row.entrypoints,
                "tests": row.tests_discovered,
                "configs": row.configs_discovered,
                "dependencies": row.dependencies_discovered,
            },
            "incremental": {
                "enabled": row.incremental,
                "changed_files": row.changed_files,
                "affected_symbols": row.affected_symbols,
            },
            "warnings": row.warnings,
            "errors": row.errors,
            "duration_ms": row.duration_ms,
        },
        "health": row.health,
        "claim_bounds": row.claim_bounds,
    }


@router.get("/runs/{run_id}/graph")
async def get_graph(
    run: Run = Depends(load_run),
    uid: str = Query("", description="Centre the subgraph on this node uid."),
    depth: int = Query(2, ge=1, le=4, description="Hops from the centre node."),
    limit: int = Query(120, ge=10, le=600, description="Maximum nodes returned."),
    db: AsyncSession = Depends(get_db),
    principal: Principal = Depends(RequirePermission(Permission.RUN_READ)),
) -> dict[str, Any]:
    """A bounded subgraph of the code knowledge graph.

    With no ``uid`` this returns the graph's statistics plus its entrypoints, which is the useful
    default: it tells a caller what exists and where to start, without shipping a graph that could
    be tens of megabytes.
    """
    row = await db.scalar(select(RepositoryIndex).where(RepositoryIndex.run_id == run.id))
    if row is None:
        return {"available": False, "reason": "This run recorded no code graph."}

    document = dict(row.graph_json or {})
    stats = document.get("stats") or {}
    nodes = document.get("nodes") or []
    edges = document.get("edges") or []

    if not uid:
        entrypoints = [n for n in nodes if (n.get("provenance") or n.get("kind")) and n.get("kind") in ("function", "method", "entrypoint")]
        return {
            "available": True,
            "stats": stats,
            "providers": document.get("providers", []),
            "truncated": document.get("truncated", False),
            "warnings": document.get("warnings", []),
            # A starting set rather than the whole graph.
            "entrypoints": [
                n
                for n in nodes
                if n.get("kind") == "entrypoint"
                or n.get("uid") in set(_entrypoint_uids(document))
            ][:60],
            "sample_nodes": entrypoints[:40],
            "note": (
                "Pass ?uid=<node uid> to receive a bounded subgraph around one node. The whole "
                "graph is deliberately not returned."
            ),
        }

    # Bounded BFS over the stored document, so the projection matches what the run recorded rather
    # than a graph rebuilt now from a tree that may have changed.
    adjacency: dict[str, list[dict[str, Any]]] = {}
    for edge in edges:
        adjacency.setdefault(str(edge.get("src", "")), []).append(edge)
        adjacency.setdefault(str(edge.get("dst", "")), []).append(edge)

    seen = {uid}
    frontier = [uid]
    for _ in range(depth):
        nxt: list[str] = []
        for current in frontier:
            for edge in adjacency.get(current, []):
                for candidate in (str(edge.get("src", "")), str(edge.get("dst", ""))):
                    if candidate and candidate not in seen and len(seen) < limit:
                        seen.add(candidate)
                        nxt.append(candidate)
        if not nxt:
            break
        frontier = nxt

    return {
        "available": True,
        "root": uid,
        "depth": depth,
        "nodes": [n for n in nodes if n.get("uid") in seen],
        "edges": [
            e for e in edges if e.get("src") in seen and e.get("dst") in seen
        ],
        "truncated": len(seen) >= limit,
        "stats": stats,
    }


def _entrypoint_uids(document: dict[str, Any]) -> list[str]:
    return [
        str(n.get("uid", ""))
        for n in (document.get("nodes") or [])
        if n.get("kind") == "entrypoint"
    ]


@router.get("/runs/{run_id}/security")
async def get_security_model(
    run: Run = Depends(load_run),
    db: AsyncSession = Depends(get_db),
    principal: Principal = Depends(RequirePermission(Permission.RUN_READ)),
) -> dict[str, Any]:
    """Sources, sinks, sanitizers, controls, trust boundaries and the derived data flows."""
    row = await db.scalar(select(SecurityModelRow).where(SecurityModelRow.run_id == run.id))
    if row is None:
        return {
            "available": False,
            "reason": (
                "This run recorded no security model. Absence of derived flows is not evidence "
                "of safety."
            ),
        }
    document = dict(row.model_json or {})
    return {
        "available": True,
        "content_hash": row.content_hash,
        "index_id": row.index_id,
        "stats": document.get("stats") or {
            "sources": row.sources,
            "sinks": row.sinks,
            "sanitizers": row.sanitizers,
            "validators": row.validators,
            "controls": row.controls,
            "flows": row.flows,
            "reachable_flows": row.reachable_flows,
            "sanitized_flows": row.sanitized_flows,
            "trust_boundaries": row.trust_boundaries,
        },
        "taxonomy": row.taxonomy,
        "nodes": document.get("nodes", []),
        "flows": document.get("flows", []),
        "trust_boundaries": document.get("trust_boundaries", []),
        "parse_errors": row.parse_errors,
        "warnings": row.warnings,
    }


@router.get("/runs/{run_id}/architecture")
async def get_architecture(
    run: Run = Depends(load_run),
    db: AsyncSession = Depends(get_db),
    principal: Principal = Depends(RequirePermission(Permission.RUN_READ)),
) -> dict[str, Any]:
    """The structured application model and the ranked attack surface."""
    row = await db.scalar(
        select(ArchitectureModelRow).where(ArchitectureModelRow.run_id == run.id)
    )
    if row is None:
        return {"available": False, "reason": "This run recorded no architecture model."}
    return {
        "available": True,
        "content_hash": row.content_hash,
        "model": row.model_json,
        "attack_surface": row.attack_surface_json,
        "gaps": row.gaps,
    }


@router.get("/runs/{run_id}/tests")
async def get_tests(
    run: Run = Depends(load_run),
    db: AsyncSession = Depends(get_db),
    principal: Principal = Depends(RequirePermission(Permission.RUN_READ)),
) -> dict[str, Any]:
    """Generated test plans and their execution records."""
    plans = list(
        (
            await db.scalars(
                select(GeneratedTest)
                .where(GeneratedTest.run_id == run.id)
                .order_by(GeneratedTest.created_at.asc())
            )
        ).all()
    )
    executions = list(
        (
            await db.scalars(
                select(TestExecutionRow)
                .where(TestExecutionRow.run_id == run.id)
                .order_by(TestExecutionRow.created_at.asc())
            )
        ).all()
    )
    return {
        "plans": [
            {
                "plan_id": p.plan_id,
                "candidate_ref": p.candidate_ref,
                "finding_handle": p.finding_handle,
                "status": p.status,
                "strategy": p.strategy,
                "oracle_kind": p.oracle_kind,
                "engine": p.engine,
                "engine_available": p.engine_available,
                "engine_reason": p.engine_reason,
                "language": p.language,
                # Whether the spec came from a model or the deterministic fallback.
                "proposed_by": p.proposed_by,
                "harness_path": p.harness_path,
                "harness_sha256": p.harness_sha256,
                "command": p.command,
                "security_property": p.security_property,
                "spec": p.spec_json,
                "provenance": p.provenance,
                "notes": p.notes,
            }
            for p in plans
        ],
        "executions": [
            {
                "plan_id": e.plan_id,
                "candidate_ref": e.candidate_ref,
                "finding_handle": e.finding_handle,
                "strategy": e.strategy,
                "engine": e.engine,
                "harness_path": e.harness_path,
                "harness_sha256": e.harness_sha256,
                "command": e.command,
                "commit_sha": e.commit_sha,
                "index_id": e.index_id,
                "input_hash": e.input_hash,
                "environment": e.environment,
                "reproduced": e.reproduced,
                "reproduction_count": e.reproduction_count,
                "reproductions_required": e.reproductions_required,
                "verdict_detail": e.verdict_detail,
                "proving_evidence": e.proving_evidence,
                "attempts": e.attempts,
                "coverage": e.coverage,
                "campaign": e.campaign,
                "error": e.error,
                "duration_ms": e.duration_ms,
            }
            for e in executions
        ],
        "counts": {
            "plans": len(plans),
            "generated": len([p for p in plans if p.status == "GENERATED"]),
            "unsupported": len([p for p in plans if p.status == "UNSUPPORTED"]),
            "executions": len(executions),
            "reproduced": len([e for e in executions if e.reproduced]),
        },
    }


@router.get("/runs/{run_id}/contexts")
async def list_contexts(
    run: Run = Depends(load_run),
    db: AsyncSession = Depends(get_db),
    principal: Principal = Depends(RequirePermission(Permission.RUN_READ)),
) -> list[dict[str, Any]]:
    """Every model context this run assembled, newest first."""
    rows = list(
        (
            await db.scalars(
                select(ModelContextRow)
                .where(ModelContextRow.run_id == run.id)
                .order_by(ModelContextRow.created_at.desc())
            )
        ).all()
    )
    return [_context_payload(row) for row in rows]


@router.get("/runs/{run_id}/contexts/{context_hash}")
async def get_context(
    context_hash: str,
    run: Run = Depends(load_run),
    db: AsyncSession = Depends(get_db),
    principal: Principal = Depends(RequirePermission(Permission.RUN_READ)),
) -> dict[str, Any]:
    """One model context in full detail, including every graph query it made."""
    row = await db.scalar(
        select(ModelContextRow).where(
            ModelContextRow.run_id == run.id,
            ModelContextRow.context_hash == context_hash,
        )
    )
    if row is None:
        raise NotFound(
            f"No model context {context_hash} was recorded for this run.",
            code="CONTEXT_NOT_FOUND",
        )
    return _context_payload(row, full=True)


def _context_payload(row: ModelContextRow, *, full: bool = False) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "context_hash": row.context_hash,
        "candidate_ref": row.candidate_ref,
        "task": row.task,
        "version": row.context_version,
        "provider": row.provider,
        "model": row.model,
        "size_chars": row.size_chars,
        "selected_files": row.selected_files,
        "selected_functions": row.selected_functions,
        "code_slice_keys": row.code_slice_keys,
        "budget": row.budget,
        "used": row.used,
        "dropped": row.dropped,
        "tool_call_count": len(row.tool_calls or []),
        "note": (
            "This is the selection the model received, not a raw prompt. Repository content "
            "reached it only inside keys prefixed UNTRUSTED_, as JSON values. Code slices are "
            "recoverable from the pinned tree plus the recorded line ranges."
        ),
    }
    if full:
        payload["tool_calls"] = row.tool_calls
    return payload


@router.get("/system/engines")
async def system_engines(
    principal: Principal = Depends(RequirePermission(Permission.RUN_READ)),
) -> dict[str, Any]:
    """Which test and fuzz engines are usable on this host.

    Probed in the backend process, so it reports what the *host* has. A run probes the sandbox
    image instead, which is the interpreter that actually executes a harness, and records that
    result per run — the two can legitimately differ and the run's answer is the authoritative one.
    """
    from app.testing.engines import describe_available

    report = describe_available()
    report["probe_scope"] = "backend host process"
    report["caveat"] = (
        "A run re-probes the sandbox image, because that is the interpreter a generated harness "
        "runs in. Where they differ, the run's per-run record is authoritative."
    )
    return report


@router.get("/system/gitnexus")
async def system_gitnexus(
    principal: Principal = Depends(RequirePermission(Permission.RUN_READ)),
) -> dict[str, Any]:
    """GitNexus availability and how it was resolved."""
    from app.config import settings
    from app.indexing.gitnexus import resolve_command
    from app.indexing.versions import collect_versions

    info = resolve_command() if settings.gitnexus_enabled else None
    versions = collect_versions(
        gitnexus_version=info.version if info else "",
        gitnexus_resolution=info.resolution if info else "",
        node_version=info.node_version if info else "",
    )
    return {
        "enabled": settings.gitnexus_enabled,
        "resolution_order": [
            "GITNEXUS_BIN environment variable",
            "PATH",
            "<repo>/node_modules/.bin (make gitnexus)",
            "npx (opt-in via GITNEXUS_ALLOW_NPX)",
        ],
        "info": info.as_dict() if info else {"available": False, "reason": "disabled by config"},
        "versions": versions.as_dict(),
        "licence": {
            "package": "gitnexus",
            "licence": "PolyForm Noncommercial 1.0.0",
            "note": (
                "GitNexus is an optional provider. KavachX indexes with tree-sitter alone when it "
                "is absent, and the index health report records the resulting bound. See "
                "docs/CODE_GRAPH.md."
            ),
        },
        "degradation": (
            "Without GitNexus every relationship is a name match rather than a resolved "
            "reference, so reachability over-approximates and the index grade is capped."
        ),
    }
