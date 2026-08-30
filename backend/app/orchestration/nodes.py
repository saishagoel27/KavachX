"""LangGraph node implementations.

One node per pipeline phase. Each node:

1. emits ``phase start``,
2. does its work through the deterministic subsystems,
3. persists what it learned,
4. emits ``phase done`` / ``failed`` / ``blocked``,
5. returns a state delta.

The graph owns orchestration and state; the nodes own no control flow beyond their own step. Long
work (sandbox execution, fuzzing, replay) is awaited on the event loop through the sandbox
adapter, which runs it as an external process — so the graph process is never blocked on a
compute-bound child.
"""

from __future__ import annotations

import asyncio
import json
import shutil
import time
import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select

from app.analysis.probe import confirm_descriptor, probe_payload
from app.analysis.world_model import build_world_model
from app.config import settings
from app.core.hashing import sha256_json, sha256_text
from app.core.logging import get_logger
from app.db.session import session_scope
from app.discovery import config_channel, fuzz_channel, runtime_channel, static_channel
from app.discovery.queue import HypothesisQueue
from app.gauntlet.runner import GauntletRunner
from app.llm.base import LLMRequest, LLMTask
from app.llm.contracts import ProbeProposal
from app.models.analysis import Finding, Hypothesis, SamhitaClause, Shield
from app.models.enums import (
    PUBLISHABLE_PROVIDERS,
    AssuranceLevel,
    FindingState,
    GauntletStage,
    HypothesisStatus,
    PatchStatus,
    Phase,
    RepositoryProvider,
    RunStatus,
)
from app.models.pramaan import Certificate, EvidenceEdge, EvidenceNode
from app.models.project import Policy, Repository
from app.models.repair import GauntletResult, GauntletRun, Patch
from app.models.run import Artifact, Run, RunCheckpoint
from app.models.run import WorldModel as WorldModelRow
from app.orchestration.state import FindingWork, KavachState, RunContext, now_iso, state_hash
from app.patching import blast_radius, rootcause, synthesis
from app.patching.policy import PolicyConfig
from app.patching.policy import evaluate as evaluate_policy
from app.pramaan import assurance as assurance_mod
from app.pramaan import certificate as certificate_mod
from app.pramaan import docs as docs_mod
from app.pramaan import intel_evidence
from app.samhita.engine import SamhitaEngine
from app.samhita.observation import load_benign_corpus
from app.sandbox import create_sandbox, materialise
from app.sandbox.workspace import reset_work
from app.validator.service import Validator

logger = get_logger(__name__)

#: Providers whose source is fetched into a disposable staging directory at ingest, rather than
#: read from a path the operator already has on disk. Their staging copy is deleted once the tree
#: has been pinned; a ``local_seeded`` target is the operator's own tree and is never touched.
_FETCHED_PROVIDERS = frozenset(
    {RepositoryProvider.GITHUB_PUBLIC.value, RepositoryProvider.GITHUB.value}
)


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
async def _update_run(run_id: uuid.UUID, **fields: Any) -> None:
    async with session_scope() as db:
        run = await db.get(Run, run_id)
        if run is None:
            return
        for key, value in fields.items():
            setattr(run, key, value)


async def _run_row(run_id: uuid.UUID) -> dict[str, Any]:
    async with session_scope() as db:
        run = await db.get(Run, run_id)
        if run is None:
            return {}
        repository = await db.get(Repository, run.repository_id)
        return {
            "run": {
                "id": str(run.id),
                "short_code": run.short_code,
                "branch": run.branch,
                "commit_sha": run.commit_sha,
                "pinned_source_sha256": run.pinned_source_sha256,
                "analysis_profile": run.analysis_profile,
                "execution_profile": run.execution_profile,
                "started_at": run.started_at.isoformat() if run.started_at else None,
                "finished_at": run.finished_at.isoformat() if run.finished_at else None,
                "time_to_protection_ms": run.time_to_protection_ms,
                "time_to_repair_ms": run.time_to_repair_ms,
                "coverage_percent": run.coverage_percent,
                "tokens_used": run.tokens_used,
                "model_calls": run.model_calls,
                "sandbox_executions": run.sandbox_executions,
                "egress_bytes": run.egress_bytes,
                "run_config": dict(run.run_config or {}),
            },
            "repository": {
                "full_name": repository.full_name if repository else "",
                "provider": repository.provider if repository else "",
                "local_path": repository.local_path if repository else "",
                "default_branch": repository.default_branch if repository else "main",
                "installation_id": repository.installation_id if repository else None,
                "authority_verified_at": (
                    repository.authority_verified_at.isoformat()
                    if repository and repository.authority_verified_at
                    else None
                ),
            },
        }


async def _check_abort(ctx: RunContext) -> bool:
    async with session_scope() as db:
        run = await db.get(Run, ctx.run_id)
        if run is not None and run.abort_requested:
            ctx.abort_requested = True
    return ctx.abort_requested


async def _emit_metrics(ctx: RunContext) -> None:
    metrics = ctx.refresh_metrics()
    await ctx.emitter.metric(
        tokens=metrics["tokens"],
        coverage=metrics["coverage"],
        ram_mb=metrics["peak_ram_mb"],
        egress=metrics["egress_bytes"],
        model_calls=metrics["model_calls"],
        sandbox_executions=metrics["sandbox_executions"],
        cpu_seconds=metrics["cpu_seconds"],
    )
    await _update_run(
        ctx.run_id,
        tokens_used=metrics["tokens"],
        model_calls=metrics["model_calls"],
        sandbox_executions=metrics["sandbox_executions"],
        coverage_percent=metrics["coverage"],
        peak_ram_mb=metrics["peak_ram_mb"],
        cpu_seconds=metrics["cpu_seconds"],
        egress_bytes=metrics["egress_bytes"],
    )


async def _emit_tools(ctx: RunContext, events: list[dict[str, Any]]) -> None:
    for event in events:
        await ctx.emitter.tool(
            name=str(event.get("name", "")),
            target=str(event.get("target", "")),
            ms=int(event.get("ms", 0)),
            ok=bool(event.get("ok", False)),
            detail=str(event.get("detail", ""))[:400],
        )


async def _set_phase(ctx: RunContext, phase: str) -> None:
    async with session_scope() as db:
        run = await db.get(Run, ctx.run_id)
        if run is None:
            return
        run.phase = phase
        statuses = dict(run.phase_status or {})
        statuses[phase] = "running"
        run.phase_status = statuses


async def _mark_phase(ctx: RunContext, phase: str, status: str) -> None:
    async with session_scope() as db:
        run = await db.get(Run, ctx.run_id)
        if run is None:
            return
        statuses = dict(run.phase_status or {})
        statuses[phase] = status
        run.phase_status = statuses


async def checkpoint(ctx: RunContext, node: str, state: KavachState) -> None:
    """Persist state after a node. Called by the graph wrapper, not by nodes."""
    ctx.checkpoint_seq += 1
    async with session_scope() as db:
        db.add(
            RunCheckpoint(
                tenant_id=ctx.tenant_id,
                run_id=ctx.run_id,
                seq=ctx.checkpoint_seq,
                node=node,
                state_json=dict(state),
                state_hash=state_hash(state),
            )
        )


async def _store_artifact(
    ctx: RunContext,
    *,
    kind: str,
    name: str,
    content: str,
    media_type: str = "text/markdown",
    meta: dict[str, Any] | None = None,
) -> str:
    digest = sha256_text(content)
    async with session_scope() as db:
        artifact = Artifact(
            tenant_id=ctx.tenant_id,
            run_id=ctx.run_id,
            kind=kind,
            name=name,
            media_type=media_type,
            content=content,
            content_hash=digest,
            size_bytes=len(content.encode("utf-8")),
            url=f"{settings.api_prefix}/runs/{ctx.run_id}/artifacts/{name}",
            meta_json=meta or {},
        )
        db.add(artifact)
        await db.flush()
        url = artifact.url
    await ctx.emitter.artifact(kind=kind, url=url, name=name, digest=digest)
    return url


# ---------------------------------------------------------------------------
# 1. ingest
# ---------------------------------------------------------------------------
async def node_ingest(ctx: RunContext, state: KavachState) -> KavachState:
    phase = Phase.INGEST.value
    await _set_phase(ctx, phase)
    await ctx.emitter.phase_start(phase, "materialising the pinned source artifact")

    rows = await _run_row(ctx.run_id)
    repository = rows.get("repository", {})
    run = rows.get("run", {})

    from pathlib import Path

    provider = str(repository.get("provider", ""))
    source_path = repository.get("local_path") or ""
    fetch_evidence: dict[str, Any] = {}
    resolved_commit = run.get("commit_sha") or ""

    if provider == RepositoryProvider.GITHUB_PUBLIC.value:
        # Fetch happens here, outside the sandbox, and the tree is hashed before anything runs.
        # The sandbox never reaches the network, so it can never fetch its own source.
        from app.github import public_ingest

        staging = ctx.workspace_root / f"fetch-{ctx.short_code.lower()}-{ctx.run_id.hex[:6]}"
        await ctx.emitter.phase_start(
            phase, f"fetching public source for {repository.get('full_name', '')}"
        )
        started = time.perf_counter()
        try:
            fetch_evidence = await public_ingest.ingest(
                full_name=str(repository.get("full_name", "")),
                revision=resolved_commit or str(run.get("branch") or "") or "",
                destination=staging,
            )
        except Exception as exc:
            await ctx.emitter.phase_failed(phase, f"source fetch failed: {exc}")
            await _mark_phase(ctx, phase, "failed")
            state["errors"] = [
                *state.get("errors", []),
                {"phase": phase, "error": f"fetch failed: {exc}", "at": now_iso()},
            ]
            state["aborted"] = True
            return state

        resolved_commit = str(fetch_evidence["commit"]["sha"])
        source_path = str(staging)
        await ctx.emitter.tool(
            name="github:public-ingest",
            target=f"{repository.get('full_name', '')}@{resolved_commit[:12]}",
            ms=int((time.perf_counter() - started) * 1000),
            ok=True,
            detail=(
                f"{fetch_evidence['download']['members_extracted']} files, "
                f"{fetch_evidence['download']['archive_bytes']} archive bytes, "
                f"{len(fetch_evidence['download']['skipped'])} unsafe members skipped"
            ),
        )
        skipped = fetch_evidence["download"]["skipped"]
        if skipped:
            await ctx.emitter.log(
                f"skipped {len(skipped)} unsafe archive member(s): "
                + ", ".join(f"{s['name']} ({s['reason']})" for s in skipped[:5]),
                stream="stderr",
                source="ingest",
            )

    elif provider == RepositoryProvider.GITHUB.value:
        # A repository the configured fine-grained token has push access to — confirmed at attach
        # time, and the only kind KavachX can later open a pull request against. It is cloned
        # rather than downloaded: the publisher's base commit and the console's provenance both
        # refer to a real commit, and a clone is what produces one.
        #
        # This still happens outside the sandbox. The credential never enters the workspace: the
        # clone module strips .git before returning, so nothing downstream can reach a remote.
        from app.github import git_ingest

        staging = ctx.workspace_root / f"clone-{ctx.short_code.lower()}-{ctx.run_id.hex[:6]}"
        await ctx.emitter.phase_start(phase, f"cloning {repository.get('full_name', '')}")
        started = time.perf_counter()
        try:
            fetch_evidence = await git_ingest.clone_repository(
                full_name=str(repository.get("full_name", "")),
                revision=resolved_commit or str(run.get("branch") or "") or "",
                destination=staging,
            )
        except Exception as exc:
            await ctx.emitter.phase_failed(phase, f"clone failed: {exc}")
            await _mark_phase(ctx, phase, "failed")
            state["errors"] = [
                *state.get("errors", []),
                {"phase": phase, "error": f"clone failed: {exc}", "at": now_iso()},
            ]
            state["aborted"] = True
            return state

        resolved_commit = str(fetch_evidence["commit"]["sha"])
        source_path = str(staging)
        clone_record = fetch_evidence["clone"]
        await ctx.emitter.tool(
            name="git:clone",
            target=f"{repository.get('full_name', '')}@{resolved_commit[:12]}",
            ms=int((time.perf_counter() - started) * 1000),
            ok=True,
            detail=(
                f"{clone_record['files']} files, {clone_record['bytes']} bytes, "
                f"branch {clone_record['branch']}, depth {clone_record['depth']}, "
                f"submodules not followed"
            ),
        )
        removed = clone_record["symlinks_removed"]
        if removed:
            # Reported, not silently dropped: materialise() dereferences symlinks, so a link out
            # of the tree would otherwise copy the file it points at into the pinned artifact.
            await ctx.emitter.log(
                f"removed {len(removed)} symlink(s) from the checkout before pinning: "
                + ", ".join(f"{s['path']} -> {s['target']}" for s in removed[:5]),
                stream="stderr",
                source="ingest",
            )

    if not source_path:
        await ctx.emitter.phase_failed(phase, "the repository has no resolvable source location")
        await _mark_phase(ctx, phase, "failed")
        state["errors"] = [
            *state.get("errors", []),
            {"phase": phase, "error": "no source path", "at": now_iso()},
        ]
        state["aborted"] = True
        return state

    pinned = materialise(
        source=Path(source_path),
        workspace_root=ctx.workspace_root,
        run_short=ctx.short_code,
    )
    ctx.pinned = pinned

    # The fetched or cloned staging copy has served its purpose; pristine/ is now the pinned
    # artifact. A local target is left alone — it is the operator's own tree, not a copy.
    if provider in _FETCHED_PROVIDERS and fetch_evidence:
        shutil.rmtree(source_path, ignore_errors=True)

    # The sandbox image is the target's toolchain. Pick it now so a Node/Java/Go/Rust target gets an
    # image that actually has npm/mvn/go/cargo, instead of the Python default that produces
    # 'npm: not found'. The operator's chosen framework wins (it fixes the toolchain unambiguously);
    # otherwise a cheap manifest scan detects the language. Either way it happens before any
    # execution. The descriptor confirmed later only refines the run commands.
    from app.analysis.framework import detect_run_plan
    from app.sandbox.images import image_for_framework, image_for_language

    early_run = await _run_row(ctx.run_id)
    chosen_framework = str(
        (early_run.get("run", {}).get("run_config") or {}).get("framework") or ""
    ).strip()

    sandbox_image = image_for_framework(chosen_framework) if chosen_framework else None
    toolchain_note = f"framework {chosen_framework}" if sandbox_image else ""
    if not sandbox_image:
        detected_language = detect_run_plan(pinned.work).language
        sandbox_image = image_for_language(detected_language)
        toolchain_note = f"{detected_language or 'unknown'} target"

    ctx.sandbox = create_sandbox(
        workspace=pinned.work,
        execution_profile=ctx.execution_profile,
        image=sandbox_image,
    )
    await ctx.sandbox.start()

    capabilities = ctx.sandbox.capabilities()
    image_note = (
        f" · image {sandbox_image} ({toolchain_note})" if capabilities.adapter != "dev" else ""
    )
    await ctx.emitter.log(
        f"sandbox adapter '{capabilities.adapter}' — {capabilities.isolation_model}{image_note}",
        source="sandbox",
    )
    if not capabilities.suitable_for_untrusted_code:
        await ctx.emitter.log(f"WARNING: {capabilities.notes}", stream="stderr", source="sandbox")

    await _update_run(
        ctx.run_id,
        pinned_source_sha256=pinned.content_sha256,
        workspace_path=str(pinned.root),
        # A resolved commit SHA is what makes a public-repo run reproducible: `main` moves, a SHA
        # does not. Local targets have no commit, so they pin by content hash instead.
        commit_sha=resolved_commit or pinned.content_sha256[:40],
    )

    state["target"] = {
        "repository": repository.get("full_name", ""),
        "provider": repository.get("provider", ""),
        "publishable": provider in PUBLISHABLE_PROVIDERS,
        "branch": run.get("branch", ""),
        "commit_sha": resolved_commit or pinned.content_sha256[:40],
        "fetch": fetch_evidence.get("commit", {}),
        "pinned_source_sha256": pinned.content_sha256,
        "file_count": pinned.file_count,
        "total_bytes": pinned.total_bytes,
        "workspace": str(pinned.root),
        "sandbox": capabilities.as_dict(),
    }
    state["phase"] = phase

    await ctx.emitter.thought(
        agent="INGEST",
        hypothesis="The analysis target must be an immutable, content-addressed artifact.",
        evidence=[
            f"source: {source_path}",
            f"files: {pinned.file_count}",
            f"sha256: {pinned.content_sha256[:16]}",
        ],
        decision=(
            "Source pinned and copied into the sandbox workspace. The repository is never "
            "fetched from inside the sandbox."
        ),
        confidence=1.0,
    )
    await _emit_metrics(ctx)
    await ctx.emitter.phase_done(
        phase, f"{pinned.file_count} files pinned at sha256:{pinned.content_sha256[:12]}"
    )
    await _mark_phase(ctx, phase, "completed")
    return state


# ---------------------------------------------------------------------------
# 2. probe + 3. index + 4. world model
# ---------------------------------------------------------------------------
def _cli_argv_template(start_cmd: str, descriptor: Any) -> list[str]:
    """Build a CLI invocation template with a ``{payload}`` placeholder for the black-box probe.

    The operator's start command is authoritative. If it does not already mark where the request
    goes, ``--request {payload}`` is appended (the convention both demos follow). With no start
    command, fall back to ``<interpreter> <entry_file> --request {payload}`` from the descriptor.
    """
    if start_cmd:
        parts = start_cmd.split()
        if "{payload}" not in start_cmd:
            parts += ["--request", "{payload}"]
        return parts
    interpreter = {
        "javascript": "node",
        "typescript": "node",
        "python": "python",
        "go": "go",
    }.get(getattr(descriptor, "language", ""), getattr(descriptor, "interpreter", "") or "node")
    entry = getattr(descriptor, "entry_file", "") or ""
    return [interpreter, entry, "--request", "{payload}"]


async def _verify_cli_candidates(
    ctx: RunContext, candidates: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Run each candidate request and keep only the ones that execute cleanly (the honesty gate).

    A synthesised or guessed request that crashes or errors is never a valid benign baseline, so it
    is discarded rather than counted. What survives is a workload KavachX proved the target accepts.
    """
    import json as _json

    from app.sandbox.blackbox import observe

    verified: list[dict[str, Any]] = []
    for index, request in enumerate(candidates, start=1):
        if not isinstance(request, dict):
            continue
        payload = _json.dumps(request, sort_keys=True)
        argv = [arg.replace("{payload}", payload) for arg in ctx.blackbox_argv]
        try:
            obs = await observe(
                ctx.sandbox,
                argv=argv,
                case_id=f"verify-{index:03d}",
                cwd=ctx.blackbox_cwd,
                timeout_seconds=30,
            )
        except Exception:
            continue
        if not obs.crashed:
            verified.append({"id": f"gen-{index:03d}", "request": request})
    return verified


async def node_index_repo(ctx: RunContext, state: KavachState) -> KavachState:
    assert ctx.pinned is not None

    # -- world model -------------------------------------------------------
    # The INDEX phase is owned by app.orchestration.intel_nodes.node_index, which has already
    # built the merged code knowledge graph. The World Model is still built here because it is the
    # structure the static channel, root-cause verification, blast radius and the sibling hunt all
    # query, and replacing those call sites wholesale would be a rewrite rather than an upgrade.
    #
    # What *is* corrected: its `graph_source` now comes from the index job — which records what
    # actually contributed — instead of from a bare "is there a gitnexus binary on PATH" check
    # that labelled runs `gitnexus+tree-sitter` without ever invoking GitNexus.
    model = await asyncio.to_thread(build_world_model, ctx.pinned.work)
    ctx.world_model = model
    if ctx.index_job is not None:
        model.graph_source = ctx.index_job.graph_source
        model.index_summary = {
            **model.index_summary,
            "index_id": ctx.index_job.index_id,
            "index_status": ctx.index_job.status,
            "providers": ctx.index_job.providers,
            "resolved_relationship_ratio": ctx.index_job.resolved_ratio,
        }
    summary = model.summary()

    # -- probe -------------------------------------------------------------
    phase = Phase.PROBE.value
    await _set_phase(ctx, phase)
    await ctx.emitter.phase_start(phase, "identifying interfaces and entrypoints")

    proposal: dict[str, Any] = {}
    try:
        response = await ctx.provider.generate(
            LLMRequest(
                task=LLMTask.PROBE_INTERFACES,
                instruction=(
                    "Identify the externally reachable interfaces of this target and how to "
                    "build and test it. Every field you return is confirmed against the "
                    "filesystem before use."
                ),
                payload=probe_payload(model),
                schema=ProbeProposal,
                model_hint="router",
            )
        )
        proposal = response.parsed.model_dump()
    except Exception as exc:
        await ctx.emitter.log(
            f"interface proposal unavailable ({str(exc)[:160]}); falling back to graph-derived "
            "entrypoints",
            stream="stderr",
            source="probe",
        )

    descriptor = confirm_descriptor(ctx.pinned.work, model, proposal=proposal)
    ctx.descriptor = descriptor

    await ctx.emitter.thought(
        agent="PROBE",
        hypothesis="The target exposes a single CLI entrypoint taking one JSON request.",
        evidence=descriptor.confirmation_notes[:6],
        decision=(
            f"Entrypoint confirmed: {descriptor.entry_file}:{descriptor.entry_callable}"
            if descriptor.confirmed
            else "No entrypoint could be confirmed on disk."
        ),
        confidence=0.9 if descriptor.confirmed else 0.2,
    )

    # -- operator run configuration (Vercel/Render style) + provisioning ---
    run_row = await _run_row(ctx.run_id)
    ctx.run_config = dict(run_row.get("run", {}).get("run_config") or {})
    cfg = ctx.run_config
    cfg_root = (str(cfg.get("root_directory") or "").strip().strip("/\\")) or "."
    install_cmd = str(cfg.get("install_command") or "").strip()
    build_cmd = str(cfg.get("build_command") or "").strip()
    start_cmd = str(cfg.get("start_command") or "").strip()
    target_type = str(cfg.get("target_type") or "auto")
    # A chosen framework fixes whether the target is an HTTP server or a CLI, so honour its kind when
    # the operator left the target type on auto.
    if target_type == "auto" and cfg.get("framework"):
        from app.analysis.frameworks import kind_for_framework

        fw_kind = kind_for_framework(str(cfg.get("framework")))
        if fw_kind in ("http", "cli"):
            target_type = fw_kind
    cfg_env = {str(k): str(v) for k, v in (cfg.get("env_vars") or {}).items()}
    benign_requests = [r for r in (cfg.get("benign_requests") or []) if isinstance(r, dict)]

    if (install_cmd or build_cmd) and ctx.sandbox is not None:
        from app.sandbox.provision import provision

        await ctx.emitter.phase_start(phase, "provisioning dependencies in the sandbox")
        report = await provision(
            ctx.sandbox,
            commands=[("install", install_cmd), ("build", build_cmd)],
            cwd=cfg_root,
            env=cfg_env,
        )
        for step in report.steps:
            await ctx.emitter.tool(
                name=f"provision:{step.label}",
                target=step.command[:80],
                ms=step.duration_ms,
                ok=step.ok,
                detail=(step.output_tail[-200:] if step.output_tail else ""),
            )
        if not report.ok:
            await ctx.emitter.log("; ".join(report.notes), stream="stderr", source="provision")

    # -- decide execution mode: black-box (any language) vs the Python/C in-process path ---
    lang = descriptor.language
    kind = descriptor.project_kind
    is_http = target_type == "http" or (
        target_type == "auto" and kind == "web_service" and bool(start_cmd)
    )
    is_cli_bb = not is_http and (
        target_type == "cli"
        or (lang not in ("python", "c") and lang != "unknown" and bool(start_cmd or descriptor.run_command))
    )

    root_path = ctx.pinned.work / cfg_root if cfg_root != "." else ctx.pinned.work

    if is_http and start_cmd:
        from app.analysis.frameworks import framework_by_id
        from app.analysis.workload import discover_http_routes, synthesize_http_requests

        ctx.blackbox = True
        ctx.blackbox_kind = "http"
        ctx.blackbox_argv = start_cmd.split()
        ctx.blackbox_cwd = cfg_root
        ctx.blackbox_env = cfg_env
        # The port the server listens on inside the sandbox — an explicit operator override, else the
        # chosen framework's default, else 3000. Under gVisor this is the container port published to
        # loopback; the start command's own --port/bind should match it.
        fw = framework_by_id(str(cfg.get("framework") or ""))
        ctx.blackbox_port = int(cfg.get("port") or (fw.port if fw and fw.port else 3000))
        if benign_requests:
            ctx.http_requests = benign_requests
            source = "operator-supplied"
        else:
            # Fully automatic: derive the workload from the target's own routes.
            routes = discover_http_routes(root_path)
            ctx.http_requests = synthesize_http_requests(root_path, routes, descriptor.asset_dir)
            source = f"{len(routes)} route(s) auto-discovered from source"
        ctx.benign_cases = []
        state["benign_corpus_ref"] = sha256_json(ctx.http_requests)
        await ctx.emitter.thought(
            agent="WORKLOAD",
            hypothesis="A benign HTTP workload can be derived from the target's routes.",
            evidence=[source, f"{len(ctx.http_requests)} candidate request(s)"],
            decision="Generated the HTTP workload; each request is verified against the live server.",
            confidence=0.85,
        )
    elif is_cli_bb and start_cmd:
        from app.analysis.workload import synthesize_cli_candidates

        ctx.blackbox = True
        ctx.blackbox_kind = "cli"
        ctx.blackbox_argv = _cli_argv_template(start_cmd, descriptor)
        ctx.blackbox_cwd = cfg_root
        ctx.blackbox_env = cfg_env
        if benign_requests:
            candidates = benign_requests
            source = "operator-supplied"
        else:
            # Fully automatic: synthesise candidate requests from the CLI's dispatch ops and fields.
            candidates = synthesize_cli_candidates(
                root_path, descriptor.entry_file, descriptor.asset_dir
            )
            source = "auto-synthesised from the CLI's dispatch ops and request fields"
        # Verify by execution — only requests that actually run cleanly become the benign baseline.
        ctx.benign_cases = await _verify_cli_candidates(ctx, candidates)
        state["benign_corpus_ref"] = sha256_json([c["request"] for c in ctx.benign_cases])
        await ctx.emitter.thought(
            agent="WORKLOAD",
            hypothesis="A benign CLI workload can be generated and verified by execution.",
            evidence=[
                source,
                f"{len(candidates)} candidate(s)",
                f"{len(ctx.benign_cases)} verified benign by execution",
            ],
            decision="Only requests that executed cleanly are kept — a guessed input that errors "
            "is never treated as a valid baseline.",
            confidence=0.85,
        )
    else:
        # Python/C in-process path: benign corpus from the repo, or the config requests as a
        # fallback when the repo shipped none.
        ctx.benign_cases = (
            load_benign_corpus(ctx.pinned.work / descriptor.corpus_dir)
            if descriptor.corpus_dir
            else []
        )
        if not ctx.benign_cases and benign_requests:
            ctx.benign_cases = [
                {"id": f"cfg-{i:03d}", "request": r} for i, r in enumerate(benign_requests, start=1)
            ]
        state["benign_corpus_ref"] = sha256_json([c["request"] for c in ctx.benign_cases])

    # The *dynamic* half needs either an executable black-box target with a benign workload, or a
    # confirmed Python/C entrypoint with a benign corpus. Otherwise the run degrades to static-only
    # honestly — it must never present a static-only run as if it had executed anything.
    if ctx.blackbox and ctx.blackbox_kind == "http":
        ctx.static_only = not bool(ctx.blackbox_argv and ctx.http_requests)
    elif ctx.blackbox:
        ctx.static_only = not bool(ctx.blackbox_argv and ctx.benign_cases)
    else:
        ctx.static_only = not (descriptor.confirmed and ctx.benign_cases)
    state["mode"] = "static_only" if ctx.static_only else "full"

    if ctx.static_only:
        reasons: list[str] = []
        if target_type in ("cli", "http"):
            # The operator asked for a black-box run but the pieces to drive it are missing.
            if not start_cmd:
                reasons.append("no start command was configured for the target")
            if target_type == "http" and not benign_requests:
                reasons.append("no benign HTTP requests were provided to drive the server")
            if target_type == "cli" and not benign_requests:
                reasons.append("no benign requests were provided to drive the CLI")
            if not reasons:
                reasons.append("the configured black-box target could not be prepared")
        else:
            if not descriptor.confirmed:
                # The run-plan detector gives the honest "why" for a non-executable target (a web
                # service, a smart contract, a library, or a language with no tracing harness);
                # otherwise it is simply that no entrypoint could be confirmed on disk.
                if descriptor.project_kind in ("web_service", "smart_contract", "library") or (
                    descriptor.language not in ("python", "c") and descriptor.language != "unknown"
                ):
                    reasons.append(descriptor.dynamic_reason)
                else:
                    reasons.append("no entrypoint could be confirmed on disk")
                if descriptor.run_command:
                    reasons.append(f"detected run command: {' '.join(descriptor.run_command)}")
            if not ctx.benign_cases:
                reasons.append(
                    "no benign workload was found at "
                    f"{descriptor.corpus_dir or 'corpus/benign'} to observe (or configure a "
                    "target type + benign requests to run it black-box)"
                )
        detail = "; ".join(reasons)
        state["static_only_reason"] = detail
        # Persisted, not just streamed: whoever opens this run later must see the qualifier too.
        await _update_run(ctx.run_id, mode="static_only", static_only_reason=detail)

        await ctx.emitter.phase_blocked(phase, f"static-only analysis: {detail}")
        await _mark_phase(ctx, phase, "blocked")
        await ctx.emitter.thought(
            agent="PROBE",
            hypothesis="This target can be executed and observed.",
            evidence=[*descriptor.confirmation_notes[:4], detail],
            decision=(
                "STATIC-ONLY MODE. Nothing will be executed, so no finding in this run can be "
                "validated by reproduction, no SAMHITA contract can be built, and no patch will "
                "be attempted. Candidates are reported as unproven hypotheses."
            ),
            confidence=1.0,
        )
        await ctx.emitter.log(
            "Static-only analysis: "
            + detail
            + ". Findings will remain hypotheses — treat them as leads, not as proven "
            "vulnerabilities.",
            stream="stderr",
            source="probe",
        )
    else:
        await ctx.emitter.phase_done(
            phase,
            f"{descriptor.entry_file}:{descriptor.entry_callable} · "
            f"{len(ctx.benign_cases)} benign cases",
        )
        await _mark_phase(ctx, phase, "completed")

    # -- world model -------------------------------------------------------
    phase = Phase.WORLD_MODEL.value
    await _set_phase(ctx, phase)
    await ctx.emitter.phase_start(phase, "building the structured world model")

    graph_json = model.as_graph_json()
    content_hash = model.content_hash()
    async with session_scope() as db:
        db.add(
            WorldModelRow(
                tenant_id=ctx.tenant_id,
                run_id=ctx.run_id,
                commit_sha=str(state.get("target", {}).get("commit_sha", "")),
                content_hash=content_hash,
                file_count=summary["files"],
                function_count=summary["functions"],
                entrypoint_count=summary["entrypoints"],
                sink_count=summary["sinks"],
                indexer=model.graph_source,
                graph_json=graph_json,
            )
        )

    state["world"] = {
        **summary,
        "content_hash": content_hash,
        "descriptor": descriptor.as_dict(),
        "entrypoints": [e.as_dict() for e in model.entrypoints],
        "sinks": [s.as_dict() for s in model.sinks[:80]],
        "ports": model.ports,
        "dependencies": model.dependencies,
    }
    state["phase"] = phase

    await ctx.emitter.thought(
        agent="WORLD MODEL",
        hypothesis="Reasoning should query a graph of handles, not read the repository.",
        evidence=[
            f"{summary['functions']} functions indexed",
            f"{summary['entrypoints']} entrypoints",
            f"{summary['sinks']} candidate sinks",
            f"graph source: {model.graph_source}",
        ],
        decision="World model built; the model receives handles and bounded code slices only.",
        confidence=1.0,
    )
    await _emit_metrics(ctx)
    await ctx.emitter.phase_done(
        phase,
        f"{summary['functions']} functions · {summary['entrypoints']} entrypoints · "
        f"{summary['sinks']} sinks",
    )
    await _mark_phase(ctx, phase, "completed")
    return state


# ---------------------------------------------------------------------------
# 5. SAMHITA
# ---------------------------------------------------------------------------
async def node_contract_synthesis(ctx: RunContext, state: KavachState) -> KavachState:
    assert ctx.sandbox is not None and ctx.descriptor is not None and ctx.pinned is not None

    phase = Phase.SAMHITA.value
    await _set_phase(ctx, phase)

    if ctx.static_only:
        await ctx.emitter.phase_start(phase, "skipped — nothing to observe")
        await ctx.emitter.phase_blocked(
            phase,
            "no behavioural contract: "
            + str(state.get("static_only_reason", "the target cannot be observed")),
        )
        await _mark_phase(ctx, phase, "blocked")
        await ctx.emitter.thought(
            agent="SAMHITA",
            hypothesis="A behavioural contract can be reconstructed from observed behaviour.",
            evidence=[str(state.get("static_only_reason", ""))],
            decision=(
                "No contract was built. Findings in this run cannot be grounded in a violated "
                "clause, which is a real reduction in evidence quality — not a formality."
            ),
            confidence=1.0,
        )
        state["samhita"] = []
        return state

    if ctx.blackbox:
        # A black-box target is observed from the outside, so there are no per-function value
        # profiles to build a SAMHITA contract from. Findings are proven by observed effect
        # (a leaked canary, an echoed marker, a crash) rather than a violated clause.
        from app.samhita.engine import SamhitaResult

        await ctx.emitter.phase_start(phase, f"skipped — {ctx.blackbox_kind} black-box target")
        await ctx.emitter.thought(
            agent="SAMHITA",
            hypothesis="A behavioural contract can be reconstructed from in-process observation.",
            evidence=[f"{ctx.blackbox_kind} black-box target: observed from the outside only"],
            decision=(
                "No SAMHITA contract for a black-box target — value profiles need an in-process "
                "tracer. Findings are proven by an observed effect instead of a violated clause."
            ),
            confidence=1.0,
        )
        await ctx.emitter.phase_done(phase, "black-box mode: contract synthesis not applicable")
        await _mark_phase(ctx, phase, "completed")
        ctx.samhita = SamhitaResult()
        state["samhita"] = []
        return state

    await ctx.emitter.phase_start(phase, "observing the benign workload")

    engine = SamhitaEngine(
        sandbox=ctx.sandbox,
        provider=ctx.provider,
        descriptor=ctx.descriptor,
        workspace=ctx.pinned.work,
    )
    result = await engine.run()
    ctx.samhita = result

    await _emit_tools(ctx, result.tool_events)

    if result.stats.get("error"):
        await ctx.emitter.phase_failed(phase, str(result.stats.get("detail", "")))
        await _mark_phase(ctx, phase, "failed")
        state["errors"] = [
            *state.get("errors", []),
            {"phase": phase, "error": result.stats["error"], "at": now_iso()},
        ]
        # A run without a contract can still discover and validate; it just cannot ground
        # findings in clauses. Continue rather than abort, and say so.
        await ctx.emitter.log(
            "SAMHITA produced no contract; findings in this run will not be clause-grounded.",
            stream="stderr",
            source="samhita",
        )
        state["samhita"] = []
        return state

    async with session_scope() as db:
        for clause in result.clauses:
            db.add(
                SamhitaClause(
                    tenant_id=ctx.tenant_id,
                    run_id=ctx.run_id,
                    clause_id=clause.clause_id,
                    kind=clause.kind,
                    description=clause.description[:800],
                    predicate=clause.predicate,
                    scope=clause.scope[:300],
                    observation_count=clause.observation_count,
                    status=clause.status,
                    evidence_refs=clause.evidence_refs,
                    falsification_reason=clause.falsification_reason,
                    counterexample=clause.counterexample,
                    holdout_pass_count=clause.holdout_pass_count,
                    holdout_fail_count=clause.holdout_fail_count,
                    proposed_by=clause.proposed_by,
                    compiled_source=clause.compiled_source,
                )
            )

    for clause in result.clauses:
        await ctx.emitter.clause(
            clause_id=clause.clause_id,
            status=clause.status,
            description=clause.description,
            scope=clause.scope,
            kind=clause.kind,
        )

    surviving = result.surviving
    falsified = result.falsified
    await ctx.emitter.thought(
        agent="SAMHITA",
        hypothesis=(
            "A behavioural contract derived from benign observation can be used to detect "
            "violations."
        ),
        evidence=[
            f"observation cases: {result.stats.get('observation_cases', 0)}",
            f"held-out cases: {result.stats.get('holdout_cases', 0)}",
            f"value profiles: {result.stats.get('profiles', 0)}",
            f"proposed: {result.stats.get('proposed', 0)}",
            f"falsified by held-out traces: {len(falsified)}",
        ],
        decision=(
            f"{len(surviving)} clauses survived held-out falsification and form SAMHITA. "
            f"{len(falsified)} were rejected and cannot be used as evidence."
        ),
        confidence=0.9,
    )

    state["samhita"] = [c.as_dict() for c in result.clauses]
    state["iter"] = {**state.get("iter", {}), "clause": result.iterations}
    state["phase"] = phase
    await _emit_metrics(ctx)
    await ctx.emitter.phase_done(
        phase,
        f"{len(surviving)} surviving · {len(falsified)} falsified · "
        f"{result.iterations} iteration(s) · coverage {result.coverage_percent:.1f}%",
    )
    await _mark_phase(ctx, phase, "completed")
    return state


# ---------------------------------------------------------------------------
# 6. discovery fan-out
# ---------------------------------------------------------------------------
async def node_discovery_fanout(ctx: RunContext, state: KavachState) -> KavachState:
    assert ctx.world_model is not None and ctx.descriptor is not None and ctx.sandbox is not None
    samhita = ctx.samhita
    if samhita is None:
        from app.samhita.engine import SamhitaResult

        samhita = SamhitaResult()

    phase = Phase.DISCOVERY.value
    await _set_phase(ctx, phase)
    await ctx.emitter.phase_start(phase, "four channels, concurrently")

    seeds = [c["request"] for c in ctx.benign_cases]
    fuzz_budget = {"quick": 60, "standard": 160, "deep": 400}.get(ctx.analysis_profile, 160)

    # No channel blocks another. Fuzzing and runtime observation both use the Python/C in-process
    # harness, so in static-only mode they are not run at all — and in black-box mode the adaptive
    # black-box probe in the validation node does the executable discovery instead.
    channels = [
        static_channel.run(
            model=ctx.world_model,
            provider=ctx.provider,
            samhita=samhita,
            descriptor=ctx.descriptor,
        ),
        config_channel.run(model=ctx.world_model, descriptor=ctx.descriptor),
    ]
    if not ctx.static_only and not ctx.blackbox:
        channels.extend(
            [
                fuzz_channel.run(
                    sandbox=ctx.sandbox,
                    model=ctx.world_model,
                    descriptor=ctx.descriptor,
                    seeds=seeds,
                    budget=fuzz_budget,
                ),
                runtime_channel.run(
                    model=ctx.world_model, descriptor=ctx.descriptor, samhita=samhita
                ),
            ]
        )
    results = await asyncio.gather(*channels, return_exceptions=True)

    channel_results = []
    for outcome in results:
        if isinstance(outcome, BaseException):
            await ctx.emitter.log(
                f"a discovery channel failed: {outcome}", stream="stderr", source="discovery"
            )
            continue
        channel_results.append(outcome)
        await _emit_tools(ctx, outcome.tool_events)
        for thought in outcome.thoughts:
            await ctx.emitter.thought(
                agent=thought["agent"],
                hypothesis=thought["hypothesis"],
                evidence=thought["evidence"],
                decision=thought["decision"],
                confidence=thought["confidence"],
            )

    ctx.channel_results = channel_results
    candidates = [c for r in channel_results for c in r.candidates]

    state["attack_graph"] = {
        "channels": [r.as_dict() for r in channel_results],
        "candidates": len(candidates),
    }
    state["phase"] = phase
    await _emit_metrics(ctx)
    await ctx.emitter.phase_done(
        phase,
        f"{len(candidates)} candidates from {len(channel_results)} channels",
    )
    await _mark_phase(ctx, phase, "completed")

    # -- hypothesis queue --------------------------------------------------
    phase = Phase.HYPOTHESIS_QUEUE.value
    await _set_phase(ctx, phase)
    await ctx.emitter.phase_start(phase, "correlating and prioritising")

    async with session_scope() as db:
        queue = HypothesisQueue(db, run_id=ctx.run_id, tenant_id=ctx.tenant_id)
        stats = await queue.push_all(candidates)
        snapshot = await queue.snapshot()

    for entry in snapshot:
        await ctx.emitter.finding(
            handle=entry["handle"],
            state="hypothesis",
            severity=entry["severity"],
            reachable=entry["reachability"] > 0.3,
            clause=entry.get("candidate_clause_id") or None,
            title=entry["description"][:200],
        )

    state["hypotheses"] = snapshot
    state["priority"] = [e["handle"] for e in snapshot]
    state["phase"] = phase
    await ctx.emitter.thought(
        agent="HYPOTHESIS QUEUE",
        hypothesis="Correlated candidates should be validated in priority order.",
        evidence=[
            f"pushed: {stats.pushed}",
            f"merged by correlation: {stats.merged}",
            f"queued for validation: {stats.queued}",
            f"no executable plan (unknown ledger): {stats.unknown}",
            "priority = reachability x confidence x blast_radius",
        ],
        decision=f"{stats.queued} hypotheses queued; {stats.unknown} recorded as unknown.",
        confidence=1.0,
    )
    await ctx.emitter.phase_done(
        phase, f"{stats.queued} queued · {stats.merged} correlated · {stats.unknown} unknown"
    )
    await _mark_phase(ctx, phase, "completed")
    return state


# ---------------------------------------------------------------------------
# 7. validation
# ---------------------------------------------------------------------------
async def _node_validate_blackbox(ctx: RunContext, state: KavachState, phase: str) -> KavachState:
    """Validate a black-box target by adaptively fuzzing it and recording reproduced findings.

    Discovery and validation happen together here: the probe learns the interface from the benign
    workload, mutates it with exploit oracles, and confirms only on an observed effect. Each
    confirmed vulnerability becomes a VALIDATED finding, identical downstream to the Python path.
    """
    assert ctx.sandbox is not None
    await ctx.emitter.phase_start(phase, f"black-box validation — driving the {ctx.blackbox_kind} target")

    try:
        if ctx.blackbox_kind == "http":
            from app.sandbox.http_blackbox import probe_http

            findings = await probe_http(
                start_argv=ctx.blackbox_argv,
                workspace=ctx.pinned.work,
                http_requests=ctx.http_requests,
                cwd=ctx.blackbox_cwd,
                env=ctx.blackbox_env,
                # Under gVisor the server runs inside a runsc container; the adapter supplies the
                # docker argv. The dev adapter has no such method, so it falls back to a host process.
                service_adapter=ctx.sandbox,
                container_port=ctx.blackbox_port or None,
            )
        else:
            from app.analysis.blackbox_probe import probe as cli_probe

            findings = await cli_probe(
                ctx.sandbox,
                argv_template=ctx.blackbox_argv,
                benign_cases=ctx.benign_cases,
            )
    except Exception as exc:
        await ctx.emitter.phase_failed(phase, f"black-box validation error: {str(exc)[:200]}")
        await _mark_phase(ctx, phase, "failed")
        state["errors"] = [
            *state.get("errors", []),
            {"phase": phase, "error": f"blackbox: {type(exc).__name__}: {exc}", "at": now_iso()},
        ]
        return state

    validated: list[dict[str, Any]] = []
    for i, bf in enumerate(findings, start=1):
        handle = f"V{i:02d}"
        outcome = bf.outcome
        async with session_scope() as db:
            finding = Finding(
                tenant_id=ctx.tenant_id,
                run_id=ctx.run_id,
                hypothesis_id=None,
                handle=handle,
                title=bf.description[:400],
                state=FindingState.VALIDATED.value,
                severity=bf.severity,
                cwe=bf.cwe,
                source_channel="blackbox",
                violated_clause_id="",
                location=bf.location,
                reachable=True,
                reachability_score=1.0,
                reproduced=True,
                reproduction_count=outcome.reproduction_count,
                exit_code=outcome.exit_code,
                sanitizer_signal=outcome.sanitizer_signal[:200],
                contract_violation=outcome.contract_violation[:400],
                input_hash=outcome.input_hash,
                output_hash=outcome.output_hash,
                trace_hash=outcome.trace_hash,
                coverage_percent=0.0,
                pov_payload=outcome.pov_payload,
                pov_kind=outcome.pov_kind,
                pov_hash=sha256_text(outcome.pov_payload) if outcome.pov_payload else "",
                evidence_refs=[],
                validated_at=datetime.now(timezone.utc),
                status_label="VALIDATED",
            )
            db.add(finding)
            await db.flush()
            finding_id = finding.id

        ctx.findings[handle] = FindingWork(
            handle=handle,
            hypothesis_handle=handle,
            finding_id=finding_id,
            outcome=outcome,
            channels=["blackbox"],
            plan={},
            coverage_before=0.0,
        )
        await ctx.emitter.finding(
            handle=handle,
            state="validated",
            severity=bf.severity,
            reachable=True,
            title=bf.description[:200],
        )
        await ctx.emitter.thought(
            agent="RED TEAM (black-box)",
            hypothesis=bf.description[:300],
            evidence=[outcome.detail[:220], f"reproduced {outcome.reproduction_count}x", bf.cwe],
            decision=f"CONFIRMED by observed effect — {bf.cwe}",
            confidence=0.97,
        )
        validated.append({"handle": handle, "cwe": bf.cwe, "location": bf.location})

    state["validated"] = validated
    state["downgraded"] = []
    if findings:
        await ctx.emitter.phase_done(
            phase, f"{len(findings)} vulnerability(ies) reproduced black-box"
        )
    else:
        await ctx.emitter.phase_blocked(
            phase, "no reproducible vulnerability found by black-box fuzzing"
        )
    await _mark_phase(ctx, phase, "completed")
    await _emit_metrics(ctx)
    return state


async def node_validate(ctx: RunContext, state: KavachState) -> KavachState:
    assert ctx.sandbox is not None and ctx.descriptor is not None and ctx.pinned is not None
    samhita = ctx.samhita
    if samhita is None:
        from app.samhita.engine import SamhitaResult

        samhita = SamhitaResult()

    phase = Phase.VALIDATION.value
    await _set_phase(ctx, phase)

    if ctx.blackbox:
        return await _node_validate_blackbox(ctx, state, phase)

    if ctx.static_only:
        await ctx.emitter.phase_start(phase, "skipped — the target cannot be executed")
        async with session_scope() as db:
            queue = HypothesisQueue(db, run_id=ctx.run_id, tenant_id=ctx.tenant_id)
            reason = (
                "Static-only run: "
                + str(state.get("static_only_reason", "the target cannot be executed"))
                + ". This candidate was never executed, so it is neither confirmed nor refuted."
            )
            for row in await queue.all():
                if row.status == HypothesisStatus.QUEUED.value:
                    await queue.transition(row, HypothesisStatus.UNKNOWN.value, reason)
            ledger = await queue.ledger()

        state["validated"] = []
        state["downgraded"] = []
        state["ledger"] = ledger
        await ctx.emitter.thought(
            agent="VALIDATOR",
            hypothesis="Each candidate can be confirmed by executing it.",
            evidence=[str(state.get("static_only_reason", "")), f"{len(ledger)} candidates queued"],
            decision=(
                "No candidate was validated, because nothing was executed. Every candidate is "
                "reported as an unproven hypothesis in REMAINING.md."
            ),
            confidence=1.0,
        )
        await ctx.emitter.phase_blocked(
            phase, f"{len(ledger)} candidate(s) left unproven — no execution in static-only mode"
        )
        await _mark_phase(ctx, phase, "blocked")
        return state

    await ctx.emitter.phase_start(phase, "executing verification jobs in the sandbox")

    validator = Validator(
        sandbox=ctx.sandbox,
        descriptor=ctx.descriptor,
        samhita=samhita,
        workspace=ctx.pinned.work,
    )

    validated: list[dict[str, Any]] = []
    downgraded: list[dict[str, Any]] = []
    finding_counter = 0
    max_validations = {"quick": 3, "standard": 8, "deep": 20}.get(ctx.analysis_profile, 8)
    processed = 0

    while processed < max_validations:
        if await _check_abort(ctx):
            break

        async with session_scope() as db:
            queue = HypothesisQueue(db, run_id=ctx.run_id, tenant_id=ctx.tenant_id)
            hypothesis = await queue.next_queued()
            if hypothesis is None:
                break
            hypothesis_snapshot = {
                "id": hypothesis.id,
                "handle": hypothesis.handle,
                "description": hypothesis.description,
                "location": hypothesis.location,
                "severity": hypothesis.severity,
                "cwe": hypothesis.cwe,
                "source_channel": hypothesis.source_channel,
                "plan": dict(hypothesis.validation_plan or {}),
                "reachability": hypothesis.reachability,
                "evidence_refs": list(hypothesis.evidence_refs or []),
                "candidate_clause_id": hypothesis.candidate_clause_id,
            }

        processed += 1
        outcome = await validator.validate(
            hypothesis_snapshot["plan"], handle=hypothesis_snapshot["handle"]
        )
        await _emit_tools(ctx, outcome.tool_events)

        if not outcome.reproduced:
            async with session_scope() as db:
                queue = HypothesisQueue(db, run_id=ctx.run_id, tenant_id=ctx.tenant_id)
                row = await db.get(Hypothesis, hypothesis_snapshot["id"])
                if row is not None:
                    await queue.transition(
                        row,
                        HypothesisStatus.REFUTED.value,
                        outcome.refutation_reason
                        or "validation executed and did not reproduce the predicted behaviour",
                        detail={"attempts": outcome.attempts[:6]},
                    )
                    row.unknown_reason = outcome.refutation_reason
            await ctx.emitter.finding(
                handle=hypothesis_snapshot["handle"],
                state="refuted",
                severity=hypothesis_snapshot["severity"],
                reachable=hypothesis_snapshot["reachability"] > 0.3,
                title=hypothesis_snapshot["description"][:200],
            )
            await ctx.emitter.thought(
                agent="VALIDATOR",
                hypothesis=hypothesis_snapshot["description"][:300],
                evidence=[
                    hypothesis_snapshot["location"],
                    f"attempts: {len(outcome.attempts)}",
                    f"plan: {hypothesis_snapshot['plan'].get('kind', '')}",
                ],
                decision=f"REFUTED — {outcome.refutation_reason[:220]}",
                confidence=0.95,
            )
            downgraded.append(
                {
                    "handle": hypothesis_snapshot["handle"],
                    "reason": outcome.refutation_reason,
                    "location": hypothesis_snapshot["location"],
                }
            )
            await _emit_metrics(ctx)
            continue

        # -- validated -----------------------------------------------------
        finding_counter += 1
        handle = f"V{finding_counter:02d}"
        clause_record = (
            samhita.clause_by_id(outcome.violated_clause_id) if outcome.violated_clause_id else None
        )

        async with session_scope() as db:
            finding = Finding(
                tenant_id=ctx.tenant_id,
                run_id=ctx.run_id,
                hypothesis_id=hypothesis_snapshot["id"],
                handle=handle,
                title=hypothesis_snapshot["description"][:400],
                state=FindingState.VALIDATED.value,
                severity=outcome.severity or hypothesis_snapshot["severity"],
                cwe=hypothesis_snapshot["cwe"],
                source_channel=hypothesis_snapshot["source_channel"],
                violated_clause_id=outcome.violated_clause_id,
                location=outcome.crash_site or hypothesis_snapshot["location"],
                reachable=hypothesis_snapshot["reachability"] > 0.3,
                reachability_score=hypothesis_snapshot["reachability"],
                reproduced=True,
                reproduction_count=outcome.reproduction_count,
                exit_code=outcome.exit_code,
                sanitizer_signal=outcome.sanitizer_signal[:200],
                contract_violation=outcome.contract_violation[:400],
                input_hash=outcome.input_hash,
                output_hash=outcome.output_hash,
                trace_hash=outcome.trace_hash,
                coverage_percent=outcome.coverage_percent,
                pov_payload=outcome.pov_payload,
                pov_kind=outcome.pov_kind,
                pov_hash=sha256_text(outcome.pov_payload) if outcome.pov_payload else "",
                evidence_refs=hypothesis_snapshot["evidence_refs"],
                validated_at=datetime.now(timezone.utc),
                status_label="VALIDATED",
            )
            db.add(finding)
            await db.flush()
            finding_id = finding.id

            queue = HypothesisQueue(db, run_id=ctx.run_id, tenant_id=ctx.tenant_id)
            row = await db.get(Hypothesis, hypothesis_snapshot["id"])
            if row is not None:
                await queue.transition(
                    row,
                    HypothesisStatus.VALIDATED.value,
                    f"reproduced {outcome.reproduction_count}x in the sandbox; "
                    f"promoted to finding {handle}",
                    detail={"finding": handle, "signal": outcome.sanitizer_signal},
                )

        work = FindingWork(
            handle=handle,
            hypothesis_handle=hypothesis_snapshot["handle"],
            finding_id=finding_id,
            outcome=outcome,
            channels=[c.strip() for c in hypothesis_snapshot["source_channel"].split(",") if c],
            clause=clause_record.as_dict() if clause_record else None,
            plan=hypothesis_snapshot["plan"],
            coverage_before=outcome.coverage_percent,
        )
        ctx.findings[handle] = work

        await ctx.emitter.finding(
            handle=handle,
            state="validated",
            severity=finding_severity(outcome, hypothesis_snapshot),
            reachable=hypothesis_snapshot["reachability"] > 0.3,
            clause=outcome.violated_clause_id or None,
            title=hypothesis_snapshot["description"][:200],
        )
        await ctx.emitter.thought(
            agent="VALIDATOR",
            hypothesis=hypothesis_snapshot["description"][:300],
            evidence=[
                outcome.crash_site or hypothesis_snapshot["location"],
                f"reproduced {outcome.reproduction_count}x independently",
                f"signal: {outcome.sanitizer_signal or 'nonzero exit'}",
                f"violated clause: {outcome.violated_clause_id or 'none'}",
                f"input hash: {outcome.input_hash[:16]}",
            ],
            decision=f"VALIDATED as {handle} — {outcome.detail[:200]}",
            confidence=1.0,
        )
        validated.append(
            {
                "handle": handle,
                "hypothesis": hypothesis_snapshot["handle"],
                "location": outcome.crash_site or hypothesis_snapshot["location"],
                "severity": outcome.severity,
                "cwe": hypothesis_snapshot["cwe"],
                "clause": outcome.violated_clause_id,
                "pov_kind": outcome.pov_kind,
                "reproduction_count": outcome.reproduction_count,
            }
        )
        await _emit_metrics(ctx)

    # Anything still queued was never reached. Say exactly why — the analysis profile's validation
    # cap, an abort, or the wall clock — rather than leaving it QUEUED for the ledger to guess at.
    async with session_scope() as db:
        queue = HypothesisQueue(db, run_id=ctx.run_id, tenant_id=ctx.tenant_id)
        remaining = [
            row for row in await queue.all() if row.status == HypothesisStatus.QUEUED.value
        ]
        if remaining:
            if ctx.abort_requested:
                reason = "The run was aborted before this hypothesis was validated."
            elif processed >= max_validations:
                reason = (
                    f"The {ctx.analysis_profile!r} analysis profile validates at most "
                    f"{max_validations} hypotheses per run, and this one ranked below the cut. "
                    "Re-run with a deeper profile to reach it."
                )
            else:
                reason = (
                    "The run's time or resource budget was reached before this hypothesis was "
                    "validated."
                )
            for row in remaining:
                await queue.transition(row, HypothesisStatus.UNKNOWN.value, reason)

        ledger = await queue.ledger()
        counts = await queue.counts()

    state["validated"] = validated
    state["downgraded"] = downgraded
    state["ledger"] = ledger
    state["hypotheses"] = [
        *[
            h
            for h in state.get("hypotheses", [])
            if h["handle"] not in {d["handle"] for d in downgraded}
        ]
    ]
    state["phase"] = phase
    await ctx.emitter.phase_done(
        phase,
        f"{len(validated)} validated · {len(downgraded)} refuted · "
        f"{counts.get('UNKNOWN', 0)} unknown",
    )
    await ctx.emitter.log(
        f"Red Team: Validation complete. Promoting {len(validated)} validated vulnerability findings to Blue Team for patching.",
        source="red-team",
    )
    await _mark_phase(ctx, phase, "completed")
    return state


def finding_severity(outcome: Any, hypothesis: dict[str, Any]) -> str:
    return outcome.severity or hypothesis.get("severity", "MEDIUM")


# ---------------------------------------------------------------------------
# 8. shield
# ---------------------------------------------------------------------------
async def node_shield(ctx: RunContext, state: KavachState) -> KavachState:
    from app.shield.service import ShieldService

    assert ctx.sandbox is not None and ctx.descriptor is not None and ctx.pinned is not None

    phase = Phase.SHIELD.value
    await _set_phase(ctx, phase)

    if not ctx.findings:
        await ctx.emitter.phase_start(phase, "no validated findings to shield")
        await ctx.emitter.phase_done(phase, "skipped — nothing validated")
        await _mark_phase(ctx, phase, "completed")
        return state

    if ctx.blackbox:
        # Runtime shields are derived by the Python in-process harness; a black-box target is only
        # observed from the outside, so there is no shield-insertion point here.
        await ctx.emitter.phase_start(phase, "skipped — black-box target")
        await ctx.emitter.phase_done(
            phase, "runtime shielding is not available for a black-box target"
        )
        await _mark_phase(ctx, phase, "completed")
        return state

    await ctx.emitter.phase_start(phase, "synthesising reversible mitigations")
    service = ShieldService(
        sandbox=ctx.sandbox, descriptor=ctx.descriptor, workspace=ctx.pinned.work
    )

    shields: list[dict[str, Any]] = []
    first_protection_ms: int | None = None

    for index, (handle, work) in enumerate(sorted(ctx.findings.items()), start=1):
        result = await service.deploy(
            outcome=work.outcome,
            handle=f"S{index:02d}",
            benign_cases=ctx.benign_cases,
            elapsed_ms=ctx.elapsed_ms(),
        )
        await _emit_tools(ctx, result.tool_events)
        work.shield = result

        if result.ok:
            async with session_scope() as db:
                db.add(
                    Shield(
                        tenant_id=ctx.tenant_id,
                        run_id=ctx.run_id,
                        finding_id=work.finding_id,
                        handle=result.handle,
                        mechanism=result.mechanism,
                        rule=result.rule,
                        rule_json=result.rule_json,
                        deploy_command=result.deploy_command,
                        revert_command=result.revert_command,
                        verified_blocked=result.verified_blocked,
                        verified_benign=result.verified_benign,
                        benign_pass_count=result.benign_pass_count,
                        benign_total=result.benign_total,
                        deployed_at=datetime.now(timezone.utc),
                        evidence_refs=[f"ev:shield:{result.handle}"],
                    )
                )
            if first_protection_ms is None:
                first_protection_ms = result.time_to_protection_ms

        await ctx.emitter.shield(
            finding=handle,
            shield_id=result.handle,
            mechanism=result.mechanism,
            verified_blocked=result.verified_blocked,
            verified_benign=result.verified_benign,
            deployed=result.deployed,
            rule=result.rule,
        )
        await ctx.emitter.thought(
            agent="SHIELD",
            hypothesis=(
                "A reversible filter can block the proven exploit before the root cause is repaired."
            ),
            evidence=[
                f"rule: {result.rule[:160]}",
                f"exploit blocked: {result.verified_blocked}",
                f"benign corpus: {result.benign_pass_count}/{result.benign_total} pass",
            ],
            decision=result.detail[:240] or result.error[:240],
            confidence=0.95 if result.ok else 0.4,
        )
        shields.append({"finding": handle, **result.as_dict()})

    # The shield must not be active while the repair is verified, or the gauntlet would be
    # testing the shield instead of the patch.
    service.revert_all()
    await ctx.emitter.log(
        "Shields reverted in the verification workspace so the Refutation Gauntlet tests the "
        "patch itself, not the mitigation.",
        source="shield",
    )

    if first_protection_ms is not None:
        await _update_run(ctx.run_id, time_to_protection_ms=first_protection_ms)

    state["shields"] = shields
    state["phase"] = phase
    await _emit_metrics(ctx)
    deployed = len([s for s in shields if s["deployed"]])
    await ctx.emitter.phase_done(
        phase,
        f"{deployed}/{len(shields)} shields verified and deployed"
        + (
            f" · time to protection {first_protection_ms / 1000:.1f}s"
            if first_protection_ms
            else ""
        ),
    )
    await _mark_phase(ctx, phase, "completed")
    return state


# ---------------------------------------------------------------------------
# 9. root cause
# ---------------------------------------------------------------------------
async def node_root_cause(ctx: RunContext, state: KavachState) -> KavachState:
    assert ctx.world_model is not None

    phase = Phase.ROOT_CAUSE.value
    await _set_phase(ctx, phase)

    if not ctx.findings:
        await ctx.emitter.phase_start(phase, "nothing to analyse")
        await ctx.emitter.phase_done(phase, "skipped")
        await _mark_phase(ctx, phase, "completed")
        return state

    if ctx.blackbox:
        # A black-box target is observed only from the outside — the source location cannot be
        # traced. Record the observed request-interface location, unverified, and skip blast radius.
        from app.patching.rootcause import RootCause

        await ctx.emitter.phase_start(phase, "black-box target — recording the observed location")
        for _handle, work in sorted(ctx.findings.items()):
            oc = work.outcome
            location = getattr(oc, "crash_site", "") or ""
            summary = (
                "Observed black-box via the request interface; the exact source location was not "
                "traced (no in-process harness for this target). Confirmed by reproduced effect."
            )
            work.root_cause = RootCause(location=location, summary=summary, verified=False)
            async with session_scope() as db:
                finding = await db.get(Finding, work.finding_id)
                if finding is not None:
                    finding.root_cause_location = location[:400]
                    finding.root_cause_summary = summary
                    finding.root_cause_verified = False
                    finding.root_cause_chain = [oc.detail[:200]] if getattr(oc, "detail", "") else []
        await ctx.emitter.phase_done(phase, "recorded observed locations (source not traced)")
        await _mark_phase(ctx, phase, "completed")
        return state

    await ctx.emitter.phase_start(phase, "locating root causes on the executed path")
    samhita = ctx.samhita

    for handle, work in sorted(ctx.findings.items()):
        clause_description = ""
        if work.clause:
            clause_description = f"{work.clause['clause_id']}: {work.clause['description']}"

        root = await rootcause.analyse(
            provider=ctx.provider,
            model=ctx.world_model,
            outcome=work.outcome,
            plan=work.plan,
            clause_description=clause_description,
        )
        work.root_cause = root

        async with session_scope() as db:
            finding = await db.get(Finding, work.finding_id)
            if finding is not None:
                finding.root_cause_location = root.location[:400]
                finding.root_cause_summary = root.summary
                finding.root_cause_verified = root.verified
                finding.root_cause_chain = root.causal_chain

        await ctx.emitter.thought(
            agent="ROOT CAUSE",
            hypothesis=f"The defect is upstream of the crash site for {handle}.",
            evidence=[
                *root.display_chain(),
                *root.verification_notes[:3],
            ],
            decision=(
                f"Root cause {root.location} "
                + (
                    "verified on the execution path."
                    if root.verified
                    else "UNVERIFIED — using the deepest executed frame."
                )
            ),
            confidence=root.confidence if root.verified else 0.4,
        )

        # -- blast radius --------------------------------------------------
        radius = blast_radius.compute(
            model=ctx.world_model,
            samhita=samhita if samhita is not None else _empty_samhita(),
            root_cause_location=root.location,
            root_cause_function=root.function,
        )
        work.blast = radius

        async with session_scope() as db:
            finding = await db.get(Finding, work.finding_id)
            if finding is not None:
                finding.blast_radius_json = radius.as_dict()

        await ctx.emitter.thought(
            agent="BLAST RADIUS",
            hypothesis="The regression scope bounds what the patch may touch and what must be re-verified.",
            evidence=radius.chain(),
            decision=(
                f"Patch is confined to {', '.join(radius.allowed_paths) or 'no file'}; "
                f"{len(radius.clause_ids)} clauses will be re-checked."
            ),
            confidence=1.0,
        )

    state["phase"] = phase
    await _emit_metrics(ctx)
    verified = len([w for w in ctx.findings.values() if w.root_cause and w.root_cause.verified])
    await ctx.emitter.phase_done(
        phase, f"{verified}/{len(ctx.findings)} root causes verified on the execution path"
    )
    await _mark_phase(ctx, phase, "completed")

    phase = Phase.BLAST_RADIUS.value
    await _mark_phase(ctx, phase, "completed")
    await ctx.emitter.phase_start(phase, "computing regression scope")
    await ctx.emitter.phase_done(
        phase,
        " · ".join(
            f"{h}: {w.blast.regression_scope}" for h, w in sorted(ctx.findings.items()) if w.blast
        )
        or "no scope computed",
    )
    return state


def _empty_samhita() -> Any:
    from app.samhita.engine import SamhitaResult

    return SamhitaResult()


# ---------------------------------------------------------------------------
# 10. patch + gauntlet iteration loop
# ---------------------------------------------------------------------------
async def node_patch_and_gauntlet(ctx: RunContext, state: KavachState) -> KavachState:
    assert ctx.pinned is not None and ctx.sandbox is not None and ctx.descriptor is not None
    assert ctx.world_model is not None

    phase = Phase.PATCH.value
    await _set_phase(ctx, phase)

    if not ctx.findings:
        await ctx.emitter.phase_start(phase, "nothing to repair")
        await ctx.emitter.phase_done(phase, "skipped")
        await _mark_phase(ctx, phase, "completed")
        for skipped in (Phase.GAUNTLET.value,):
            await _mark_phase(ctx, skipped, "completed")
        return state

    if ctx.blackbox:
        # The vulnerabilities are confirmed by observed effect, but synthesising a source patch
        # needs source-level analysis the black-box path deliberately does not do. Mark each finding
        # for manual remediation (its reproduced exploit is the regression test) rather than
        # fabricating a patch that was never verified.
        await ctx.emitter.phase_start(phase, "black-box target — automated repair not available")
        for handle, work in sorted(ctx.findings.items()):
            work.repair_blocked_reason = (
                "Black-box target: confirmed by observed effect, but automated patch synthesis "
                "needs source-level analysis (an in-process harness). Remediate manually — the "
                "reproduced exploit is the regression test."
            )
            await ctx.emitter.thought(
                agent="BLUE TEAM",
                hypothesis=f"A minimal patch can be synthesised for {handle}.",
                evidence=[work.outcome.detail[:200] if work.outcome else ""],
                decision=(
                    "Repair not attempted for a black-box target — the finding is confirmed and "
                    "handed off for manual remediation."
                ),
                confidence=1.0,
            )
        await ctx.emitter.phase_done(phase, "black-box: findings confirmed; manual remediation")
        await _mark_phase(ctx, phase, "completed")
        await _mark_phase(ctx, Phase.GAUNTLET.value, "completed")
        state["patches"] = []
        state["gauntlet"] = {}
        return state

    samhita = ctx.samhita if ctx.samhita is not None else _empty_samhita()
    max_iterations = int(state.get("iter", {}).get("patch_limit", settings.max_patch_iterations))

    async with session_scope() as db:
        policy_row = await db.scalar(select(Policy).where(Policy.tenant_id == ctx.tenant_id))
        policy_config = PolicyConfig.from_model(policy_row)

    gauntlet = GauntletRunner(
        sandbox=ctx.sandbox,
        provider=ctx.provider,
        descriptor=ctx.descriptor,
        model=ctx.world_model,
        samhita=samhita,
        pinned=ctx.pinned,
        workspace=ctx.pinned.work,
        benign_cases=ctx.benign_cases,
    )

    # Baseline is captured from the unpatched tree, once.
    reset_work(ctx.pinned)
    ctx.baseline = await gauntlet.capture_baseline()

    patches_state: list[dict[str, Any]] = []
    gauntlet_state: dict[str, Any] = {}
    all_gauntlets: list[dict[str, Any]] = []
    first_repair_ms: int | None = None

    await ctx.emitter.log(
        f"Blue Team: Starting repair synthesis for {len(ctx.findings)} validated findings.",
        source="blue-team",
    )

    for handle, work in sorted(ctx.findings.items()):
        if await _check_abort(ctx):
            break
        if work.root_cause is None or work.blast is None:
            continue

        await ctx.emitter.phase_start(
            Phase.PATCH.value, f"{handle}: synthesising repair for {work.root_cause.location}"
        )

        for iteration in range(1, max_iterations + 1):
            work.iteration = iteration
            state["iter"] = {**state.get("iter", {}), "patch": iteration}

            await ctx.emitter.log(
                f"Blue Team: Synthesising patch candidate (iteration {iteration}/{max_iterations}) for finding {handle}...",
                source="blue-team",
            )

            reset_work(ctx.pinned)

            payload = synthesis.build_payload(
                model=ctx.world_model,
                samhita=samhita,
                root_cause=work.root_cause,
                outcome=work.outcome,
                pinned=ctx.pinned,
                iteration=iteration,
                constraints=work.constraints,
                cwe=_cwe_for(work),
            )
            result = await synthesis.synthesise(
                provider=ctx.provider, payload=payload, pinned=ctx.pinned
            )

            if not result.ok:
                # No patch was produced, so there is nothing to record as a patch. Writing an
                # empty PROPOSED/APPLY_FAILED row would put a zero-line "patch" in the history
                # and in the certificate, implying an attempt that never reached the workspace.
                # Record it on the finding as an unattempted repair instead.
                work.repair_blocked_reason = result.error
                async with session_scope() as db:
                    finding = await db.get(Finding, work.finding_id)
                    if finding is not None:
                        finding.status_label = "SHIELDED (no repair synthesised)"
                await ctx.emitter.log(
                    f"{handle}: no repair could be synthesised — {result.error}",
                    stream="stderr",
                    source="patch",
                )
                await ctx.emitter.thought(
                    agent="PATCH SYNTHESIS",
                    hypothesis=f"A minimal repair exists for {handle}.",
                    evidence=[
                        work.root_cause.location,
                        f"cwe: {_cwe_for(work) or 'unclassified'}",
                        result.error[:200],
                    ],
                    decision=(
                        "No repair was synthesised. The finding remains open with its shield as "
                        "the only mitigation, and is recorded in REMAINING.md."
                    ),
                    confidence=0.0,
                )
                break

            # -- policy gate (pre-application) -----------------------------
            decision = evaluate_policy(
                diff=result.unified_diff,
                file_changes=result.file_changes,
                config=policy_config,
                blast=work.blast,
                assurance_level=None,
                # The certificate does not exist yet; the certificate checks run again at publish.
                has_certificate=None,
            )
            certificate_codes = {
                "MISSING_CERTIFICATE",
                "ASSURANCE_LEVEL_R",
                "ASSURANCE_BELOW_FLOOR",
            }
            blocking = [v for v in decision.violations if v.code not in certificate_codes]

            within_radius = not any(v.code == "OUTSIDE_BLAST_RADIUS" for v in decision.violations)

            await ctx.emitter.thought(
                agent="POLICY GATE",
                hypothesis="A patch must be inside the verified scope and change nothing forbidden.",
                evidence=[
                    f"checks: {', '.join(decision.checks_run)}",
                    f"files: {', '.join(result.files)}",
                    f"diff: +{result.stats.lines_added}/-{result.stats.lines_removed}",
                    f"allowed paths: {', '.join(work.blast.allowed_paths)}",
                ],
                decision=(
                    "PASS" if not blocking else f"REJECTED — {'; '.join(v.code for v in blocking)}"
                ),
                confidence=1.0,
            )

            if blocking:
                patch_row = await _record_patch(
                    ctx,
                    work,
                    result,
                    iteration=iteration,
                    status=PatchStatus.POLICY_REJECTED.value,
                    policy_violations=[v.as_dict() for v in blocking],
                    within_radius=within_radius,
                    refutation_summary=decision.summary,
                )
                patches_state.append(patch_row)
                work.constraints.append(
                    f"POLICY REJECTED: {decision.summary}. The next patch must satisfy the "
                    "deterministic publish policy."
                )
                await ctx.emitter.phase_blocked(
                    Phase.PATCH.value, f"{handle} v{iteration}: {decision.summary[:200]}"
                )
                continue

            applied, apply_error = synthesis.apply_to_workspace(result, ctx.pinned)
            if not applied:
                await _record_patch(
                    ctx,
                    work,
                    result,
                    iteration=iteration,
                    status=PatchStatus.APPLY_FAILED.value,
                    policy_violations=[],
                    within_radius=within_radius,
                    refutation_summary=apply_error,
                )
                await ctx.emitter.log(
                    f"{handle}: patch v{iteration} could not be applied — {apply_error}",
                    stream="stderr",
                    source="patch",
                )
                break

            patch_row = await _record_patch(
                ctx,
                work,
                result,
                iteration=iteration,
                status=PatchStatus.APPLIED.value,
                policy_violations=[],
                within_radius=within_radius,
            )
            work.patches.append(result)
            await ctx.emitter.log(
                f"Blue Team: Synthesised patch candidate v{iteration} for finding {handle}. Handoff to Red Team for adversarial validation.",
                source="blue-team",
            )

            for path in result.files:
                await ctx.emitter.diff(
                    finding=handle,
                    file=path,
                    patch=result.unified_diff,
                    iteration=iteration,
                    patch_id=str(patch_row["id"]),
                )

            # -- gauntlet --------------------------------------------------
            await _set_phase(ctx, Phase.GAUNTLET.value)
            await ctx.emitter.phase_start(
                Phase.GAUNTLET.value, f"{handle}: attacking patch v{iteration}"
            )
            await ctx.emitter.log(
                f"Red Team: Launching adversarial gauntlet (4 stages of mutation & replay) against patch v{iteration} for finding {handle}.",
                source="red-team",
            )

            # `handle` is bound as a default rather than captured: the callback is defined inside
            # the per-finding loop, and a late-bound closure would attribute stage events to
            # whichever finding the loop happened to be on when the callback fired.
            async def on_stage(
                *,
                stage: str,
                verdict: str,
                detail: str,
                iteration: int,
                _finding: str = handle,
            ) -> None:
                await ctx.emitter.gauntlet(
                    finding=_finding,
                    stage=stage,
                    verdict=verdict,
                    detail=detail[:400],
                    iteration=iteration,
                )
                stage_label = {
                    "exploit_mutation": "Exploit Mutation",
                    "sibling_hunt": "Sibling Hunt",
                    "differential_replay": "Differential Replay",
                    "samhita_recheck": "SAMHITA Re-check",
                }.get(stage, stage)
                if verdict == "pass":
                    await ctx.emitter.log(
                        f"Red Team: Stage [{stage_label}] passed — patch successfully blocked/prevented the attack.",
                        source="red-team",
                    )
                elif verdict == "fail":
                    await ctx.emitter.log(
                        f"Red Team: Stage [{stage_label}] failed — exploit refuted the patch: {detail[:200]}",
                        stream="stderr",
                        source="red-team",
                    )

            outcome = await gauntlet.run(
                outcome=work.outcome,
                synthesis=result,
                blast=work.blast,
                iteration=iteration,
                finding_handle=handle,
                on_stage=on_stage,
            )
            work.gauntlets.append(outcome)

            gauntlet_dict = await _record_gauntlet(
                ctx, work, outcome, patch_id=patch_row["id"], iteration=iteration
            )
            all_gauntlets.append(gauntlet_dict)
            gauntlet_state[f"{handle}:v{iteration}"] = outcome.as_dict()

            recheck = outcome.stage(GauntletStage.SAMHITA_RECHECK.value)
            work.coverage_after = float(
                (recheck.metrics or {}).get("coverage_percent", work.coverage_before)
                if recheck
                else work.coverage_before
            )

            if outcome.passed:
                work.verified_patch = patch_row
                work.verified_synthesis = result
                work.exploit_eliminated = True
                async with session_scope() as db:
                    row = await db.get(Patch, uuid.UUID(str(patch_row["id"])))
                    if row is not None:
                        row.status = PatchStatus.VERIFIED.value
                        row.verified_at = datetime.now(timezone.utc)
                patch_row["status"] = PatchStatus.VERIFIED.value
                patches_state.append(patch_row)
                if first_repair_ms is None:
                    first_repair_ms = ctx.elapsed_ms()
                await ctx.emitter.log(
                    f"Blue Team: Verification successful. Patch v{iteration} for finding {handle} has passed all gauntlet refutations.",
                    source="blue-team",
                )
                await ctx.emitter.phase_done(
                    Phase.GAUNTLET.value, f"{handle} v{iteration}: {outcome.summary}"
                )
                break

            # -- refuted ---------------------------------------------------
            async with session_scope() as db:
                row = await db.get(Patch, uuid.UUID(str(patch_row["id"])))
                if row is not None:
                    row.status = PatchStatus.REFUTED.value
                    row.withdrawn_at = datetime.now(timezone.utc)
                    row.refutation_summary = outcome.summary
                    row.constraints = list(outcome.constraints)
            patch_row["status"] = PatchStatus.REFUTED.value
            patch_row["refutation_summary"] = outcome.summary
            patch_row["constraints"] = list(outcome.constraints)
            patches_state.append(patch_row)
            await ctx.emitter.log(
                f"Red Team: Patch v{iteration} for finding {handle} was refuted: {outcome.summary}",
                stream="stderr",
                source="red-team",
            )

            work.constraints.extend(outcome.constraints)
            await ctx.emitter.thought(
                agent="REFUTATION GAUNTLET",
                hypothesis=f"Patch v{iteration} for {handle} eliminates the vulnerability.",
                evidence=[
                    f"{s.stage}: {s.verdict.upper()} — {s.detail[:120]}" for s in outcome.stages
                ],
                decision=(
                    f"REFUTED at {outcome.failing_stage}. Patch withdrawn. "
                    f"{len(outcome.constraints)} constraint(s) added for iteration {iteration + 1}."
                    if iteration < max_iterations
                    else f"REFUTED at {outcome.failing_stage}. Iteration limit reached — honest failure."
                ),
                confidence=1.0,
            )
            await ctx.emitter.phase_failed(
                Phase.GAUNTLET.value, f"{handle} v{iteration}: {outcome.summary[:240]}"
            )

            if iteration >= max_iterations:
                await ctx.emitter.log(
                    f"{handle}: HONEST FAILURE — {max_iterations} patch iterations exhausted. "
                    "The shield remains the only mitigation.",
                    stream="stderr",
                    source="patch",
                )

        reset_work(ctx.pinned)

    if first_repair_ms is not None:
        await _update_run(ctx.run_id, time_to_repair_ms=first_repair_ms)

    state["patches"] = patches_state
    state["gauntlet"] = gauntlet_state
    state["phase"] = Phase.GAUNTLET.value
    await _emit_metrics(ctx)

    verified = len([w for w in ctx.findings.values() if w.verified_patch])
    await _mark_phase(ctx, Phase.PATCH.value, "completed")
    await _mark_phase(ctx, Phase.GAUNTLET.value, "completed" if verified else "failed")
    await ctx.emitter.phase_done(
        Phase.PATCH.value,
        f"{verified}/{len(ctx.findings)} findings repaired and verified",
    )
    return state


def _cwe_for(work: FindingWork) -> str:
    if work.plan.get("kind") == "command_injection":
        return "CWE-78"
    if work.plan.get("kind") == "length_boundary":
        return "CWE-1284"
    if work.plan.get("kind") == "path_traversal":
        return "CWE-22"
    outcome_kind = getattr(work.outcome, "pov_kind", "")
    return {
        "command_injection": "CWE-78",
        "length_boundary": "CWE-1284",
        "path_traversal": "CWE-22",
    }.get(outcome_kind, "")


async def _record_patch(
    ctx: RunContext,
    work: FindingWork,
    result: Any,
    *,
    iteration: int,
    status: str,
    policy_violations: list[dict[str, Any]],
    within_radius: bool,
    refutation_summary: str = "",
) -> dict[str, Any]:
    async with session_scope() as db:
        patch = Patch(
            tenant_id=ctx.tenant_id,
            run_id=ctx.run_id,
            finding_id=work.finding_id,
            iteration=iteration,
            status=status,
            reason=result.reason,
            unified_diff=result.unified_diff,
            files=result.files,
            file_contents={
                path: {"old": old, "new": new} for path, (old, new) in result.file_changes.items()
            },
            risk=result.risk,
            expected_effect=result.expected_effect,
            diff_hash=result.diff_hash,
            lines_added=result.stats.lines_added,
            lines_removed=result.stats.lines_removed,
            applied=status == PatchStatus.APPLIED.value,
            apply_error="" if status != PatchStatus.APPLY_FAILED.value else refutation_summary,
            policy_passed=not policy_violations,
            policy_violations=policy_violations,
            within_blast_radius=within_radius,
            blast_radius_json=work.blast.as_dict() if work.blast else {},
            constraints=list(work.constraints),
            refutation_summary=refutation_summary,
            proposed_by_model=result.model_name,
            evidence_refs=[f"ev:patch:{work.handle}:v{iteration}"],
        )
        db.add(patch)
        await db.flush()
        return {
            "id": str(patch.id),
            "finding_handle": work.handle,
            "iteration": iteration,
            "status": status,
            "reason": patch.reason,
            "unified_diff": patch.unified_diff,
            "files": patch.files,
            "risk": patch.risk,
            "expected_effect": patch.expected_effect,
            "diff_hash": patch.diff_hash,
            "lines_added": patch.lines_added,
            "lines_removed": patch.lines_removed,
            "policy_passed": patch.policy_passed,
            "policy_violations": policy_violations,
            "within_blast_radius": within_radius,
            "constraints": list(work.constraints),
            "refutation_summary": refutation_summary,
        }


async def _record_gauntlet(
    ctx: RunContext, work: FindingWork, outcome: Any, *, patch_id: str, iteration: int
) -> dict[str, Any]:
    async with session_scope() as db:
        row = GauntletRun(
            tenant_id=ctx.tenant_id,
            run_id=ctx.run_id,
            finding_id=work.finding_id,
            patch_id=uuid.UUID(str(patch_id)),
            iteration=iteration,
            verdict=outcome.verdict,
            stages_passed=outcome.stages_passed,
            stages_total=outcome.stages_total,
            started_at=datetime.now(timezone.utc),
            finished_at=datetime.now(timezone.utc),
            duration_ms=outcome.duration_ms,
            failing_stage=outcome.failing_stage,
            summary=outcome.summary,
        )
        db.add(row)
        await db.flush()
        for stage in outcome.stages:
            db.add(
                GauntletResult(
                    tenant_id=ctx.tenant_id,
                    run_id=ctx.run_id,
                    gauntlet_run_id=row.id,
                    stage=stage.stage,
                    verdict=stage.verdict,
                    detail=stage.detail,
                    refuting_evidence=stage.refuting_evidence,
                    metrics={
                        k: v for k, v in (stage.metrics or {}).items() if not k.startswith("_")
                    },
                    duration_ms=stage.duration_ms,
                    cases_total=stage.cases_total,
                    cases_passed=stage.cases_passed,
                    evidence_refs=[f"ev:gauntlet:{work.handle}:v{iteration}:{stage.stage}"],
                )
            )
    return {
        "finding_handle": work.handle,
        "iteration": iteration,
        "verdict": outcome.verdict,
        "failing_stage": outcome.failing_stage,
        "summary": outcome.summary,
        "stages": [s.as_dict() for s in outcome.stages],
    }


# ---------------------------------------------------------------------------
# 11. PRAMAAN
# ---------------------------------------------------------------------------
async def node_attest(ctx: RunContext, state: KavachState) -> KavachState:
    phase = Phase.PRAMAAN.value
    await _set_phase(ctx, phase)
    await ctx.emitter.phase_start(phase, "building evidence graphs and grading assurance")

    rows = await _run_row(ctx.run_id)
    run_info = rows.get("run", {})
    repository_info = rows.get("repository", {})
    samhita = ctx.samhita if ctx.samhita is not None else _empty_samhita()
    sandbox_stats = ctx.sandbox_stats()
    world_hash = ctx.world_model.content_hash() if ctx.world_model else ""

    certificates: list[dict[str, Any]] = []
    changes_entries: list[dict[str, Any]] = []

    for handle, work in sorted(ctx.findings.items()):
        latest_gauntlet = work.gauntlets[-1] if work.gauntlets else None
        sibling_stage = (
            latest_gauntlet.stage(GauntletStage.SIBLING_HUNT.value) if latest_gauntlet else None
        )
        recheck_stage = (
            latest_gauntlet.stage(GauntletStage.SAMHITA_RECHECK.value) if latest_gauntlet else None
        )
        unproved = (
            list((sibling_stage.metrics or {}).get("unproved_candidates", []))
            if sibling_stage
            else []
        )

        # Coverage before and after must be measured over the *same* workload, or the delta is
        # meaningless. The pre-patch figure is SAMHITA's observation coverage over the benign
        # corpus; the post-patch figure is the re-check over that same corpus. Using the
        # single-case proof-of-vulnerability observation as the baseline would compare one request
        # against twelve and report a large "behavioural change" that never happened.
        coverage_before = samhita.coverage_percent or work.coverage_before
        coverage_after = work.coverage_after or coverage_before

        assessment = assurance_mod.grade(
            gauntlet=latest_gauntlet or _null_gauntlet(),
            exploit_eliminated=work.exploit_eliminated,
            shield_active=bool(work.shield and work.shield.ok),
            coverage_before=coverage_before,
            coverage_after=coverage_after,
            clause_total=int((recheck_stage.metrics or {}).get("clauses_checked", 0))
            if recheck_stage
            else 0,
            clause_held=int((recheck_stage.metrics or {}).get("clauses_held", 0))
            if recheck_stage
            else 0,
            clause_unsupported=int((recheck_stage.metrics or {}).get("clauses_unsupported", 0))
            if recheck_stage
            else 0,
            unproved_siblings=unproved,
            iteration=work.iteration,
            max_iterations=int(state.get("iter", {}).get("patch_limit", 3)),
        )
        work.assurance = assessment

        finding_payload = await _finding_payload(work)
        patch_payloads = [p for p in state.get("patches", []) if p.get("finding_handle") == handle]
        gauntlet_payloads = [
            g.as_dict() | {"iteration": g_index + 1} for g_index, g in enumerate(work.gauntlets)
        ]

        graph = certificate_mod.build_graph(
            finding=finding_payload,
            channels=work.channels,
            clause=work.clause,
            shield=work.shield.as_dict() if work.shield else None,
            patches=patch_payloads,
            gauntlets=gauntlet_payloads,
            blast=work.blast.as_dict() if work.blast else {},
            world_model_hash=world_hash,
            sandbox_stats=sandbox_stats,
            runtime_digest=(
                work.outcome.evidence.get("pov_observation_hash", "") if work.outcome else ""
            ),
        )

        # -- code-intelligence evidence --------------------------------------
        # Added to the same graph, so the dangling-claim refusal covers it: a certificate that
        # cites an index, a flow or a harness must have a node for each.
        intel = intel_evidence.attach(
            graph,
            finding_handle=handle,
            index=state.get("index") or None,
            index_health=state.get("index_health") or None,
            graph_summary=state.get("graph") or None,
            architecture=state.get("architecture") or None,
            attack_surface=state.get("attack_surface") or None,
            security_flow=_flow_for_finding(ctx, work),
            test_plans=_plans_for_finding(ctx, work),
            test_executions=_executions_for_finding(ctx, work),
            coverage=(ctx.coverage.as_dict() if ctx.coverage is not None else None),
            model_context=_context_for_finding(ctx, work),
            regression=state.get("regression") or None,
        )
        intel["explains"] = intel_evidence.explains(intel, finding_payload)

        certificate = certificate_mod.build_certificate(
            run=run_info,
            repository=repository_info,
            finding=finding_payload,
            assurance=assessment,
            graph=graph,
            clause=work.clause,
            shield=work.shield.as_dict() if work.shield else None,
            patches=patch_payloads,
            gauntlets=gauntlet_payloads,
            blast=work.blast.as_dict() if work.blast else {},
            samhita_stats=samhita.stats,
            sandbox_stats=sandbox_stats,
            provider_info=ctx.provider_info(),
            intel=intel,
        )

        if not certificate.ok:
            await ctx.emitter.log(
                f"{handle}: certificate refused — {certificate.error}",
                stream="stderr",
                source="pramaan",
            )
            continue

        work.certificate = certificate

        async with session_scope() as db:
            row = Certificate(
                tenant_id=ctx.tenant_id,
                run_id=ctx.run_id,
                finding_id=work.finding_id,
                patch_id=uuid.UUID(str(work.verified_patch["id"])) if work.verified_patch else None,
                serial=certificate.serial,
                assurance_level=assessment.level,
                grading_rationale=assessment.rationale,
                limitations=assessment.limitations,
                document=certificate.document,
                certificate_hash=certificate.certificate_hash,
                signature=certificate.signature,
                evidence_node_count=len(graph.nodes),
                evidence_edge_count=len(graph.edges),
                generation_ms=certificate.generation_ms,
                issued_at=datetime.now(timezone.utc),
            )
            db.add(row)
            await db.flush()
            certificate_id = str(row.id)

            # Several nodes are legitimately shared between findings in the same run — the
            # discovery channels, the world model, the sandbox session. Their refs are stable by
            # design (that is what makes the graph a graph rather than N disjoint trees), so the
            # second finding's certificate must reuse them rather than re-insert them.
            existing_nodes = set(
                (
                    await db.scalars(
                        select(EvidenceNode.ref).where(EvidenceNode.run_id == ctx.run_id)
                    )
                ).all()
            )
            existing_edges = {
                (source, relation, target)
                for source, relation, target in (
                    await db.execute(
                        select(
                            EvidenceEdge.source_ref,
                            EvidenceEdge.relation,
                            EvidenceEdge.target_ref,
                        ).where(EvidenceEdge.run_id == ctx.run_id)
                    )
                ).all()
            }

            for node in graph.nodes:
                if node.ref in existing_nodes:
                    continue
                existing_nodes.add(node.ref)
                db.add(
                    EvidenceNode(
                        tenant_id=ctx.tenant_id,
                        run_id=ctx.run_id,
                        ref=node.ref,
                        type=node.type,
                        title=node.title,
                        content=node.content[:100000],
                        content_hash=node.content_hash,
                        meta_json=node.meta,
                        produced_by=node.produced_by,
                    )
                )
            for edge in graph.edges:
                key = (edge.source_ref, edge.relation, edge.target_ref)
                if key in existing_edges:
                    continue
                existing_edges.add(key)
                db.add(
                    EvidenceEdge(
                        tenant_id=ctx.tenant_id,
                        run_id=ctx.run_id,
                        source_ref=edge.source_ref,
                        relation=edge.relation,
                        target_ref=edge.target_ref,
                        meta_json=edge.meta,
                    )
                )

            finding = await db.get(Finding, work.finding_id)
            if finding is not None:
                finding.status_label = (
                    f"REPAIRED (Level {assessment.level})"
                    if assessment.level != AssuranceLevel.R.value
                    else "SHIELDED (patch refuted)"
                )

        await ctx.emitter.certificate(
            finding=handle,
            level=assessment.level,
            certificate_hash=certificate.certificate_hash,
            certificate_id=certificate_id,
        )
        await ctx.emitter.thought(
            agent="PRAMAAN",
            hypothesis="Every claim in a certificate must point at stored evidence.",
            evidence=[
                f"evidence nodes: {len(graph.nodes)}",
                f"evidence edges: {len(graph.edges)}",
                f"dangling claims: {len(graph.unsupported_claims())}",
                f"certificate hash: {certificate.certificate_hash[:16]}",
            ],
            decision=f"Level {assessment.level} — {assessment.rationale[0] if assessment.rationale else ''}",
            confidence=1.0,
        )

        certificate_json = json.dumps(certificate.document, indent=2, sort_keys=True, default=str)
        await _store_artifact(
            ctx,
            kind="certificate",
            name=f"certificate-{handle}.json",
            content=certificate_json,
            media_type="application/json",
            meta={
                "finding": handle,
                "level": assessment.level,
                "certificate_hash": certificate.certificate_hash,
                "certificate_id": certificate_id,
            },
        )

        certificates.append(
            {
                "id": certificate_id,
                "finding_handle": handle,
                "serial": certificate.serial,
                "assurance_level": assessment.level,
                "certificate_hash": certificate.certificate_hash,
                "limitations": assessment.limitations,
                "rationale": assessment.rationale,
            }
        )
        changes_entries.append(
            {
                "finding": finding_payload,
                "patch": work.verified_patch,
                "certificate": {
                    "assurance_level": assessment.level,
                    "certificate_hash": certificate.certificate_hash,
                },
                "clause": work.clause,
                "blast_radius": work.blast.as_dict() if work.blast else {},
                "gauntlet": {
                    "stages": certificate.document.get("verification", {}).get("stages", {})
                },
            }
        )

    # -- deliverable documents --------------------------------------------
    async with session_scope() as db:
        queue = HypothesisQueue(db, run_id=ctx.run_id, tenant_id=ctx.tenant_id)
        ledger = await queue.ledger()

    verified_entries = [
        e for e in changes_entries if e["certificate"]["assurance_level"] != AssuranceLevel.R.value
    ]
    changes_md = docs_mod.render_changes(
        run=run_info, repository=repository_info, entries=verified_entries
    )

    remaining_inputs = docs_mod.build_remaining_inputs(
        ledger=ledger,
        patches=state.get("patches", []),
        gauntlets=[
            {**g, "finding_handle": g.get("finding_handle", "")} for g in _all_gauntlet_dicts(ctx)
        ],
        clauses=state.get("samhita", []),
        channel_results=[
            *[r.as_dict() | {"coverage_notes": r.coverage_notes} for r in ctx.channel_results],
            *(
                [
                    {
                        "channel": "fuzzing + runtime",
                        "coverage_notes": [
                            "NOT RUN. "
                            + str(state.get("static_only_reason", "the target cannot be executed"))
                            + ". Both channels require an executable entrypoint, so this run has "
                            "zero dynamic coverage — no crash was searched for and no behaviour "
                            "was observed.",
                        ],
                    }
                ]
                if ctx.static_only
                else []
            ),
        ],
        coverage_percent=samhita.coverage_percent,
        covered_statements=(
            samhita.observation_set.covered_statements if samhita.observation_set else 0
        ),
        total_statements=(
            samhita.observation_set.total_statements if samhita.observation_set else 0
        ),
        certificates=certificates,
        world_model_summary=state.get("world", {}),
        sandbox_stats=sandbox_stats,
    )
    remaining_md = docs_mod.render_remaining(
        run=run_info, repository=repository_info, **remaining_inputs
    )

    await _store_artifact(ctx, kind="changes_md", name="CHANGES.md", content=changes_md)
    await _store_artifact(ctx, kind="remaining_md", name="REMAINING.md", content=remaining_md)

    state["certificates"] = certificates
    state["pramaan"] = {
        "certificates": len(certificates),
        "levels": {c["assurance_level"]: 1 for c in certificates},
        "changes_md_hash": sha256_text(changes_md),
        "remaining_md_hash": sha256_text(remaining_md),
    }
    state["ledger"] = ledger
    state["phase"] = phase
    await _emit_metrics(ctx)
    await ctx.emitter.phase_done(
        phase,
        f"{len(certificates)} certificate(s): "
        + (
            ", ".join(f"{c['finding_handle']}=Level {c['assurance_level']}" for c in certificates)
            or "none"
        ),
    )
    await _mark_phase(ctx, phase, "completed")
    return state


def _all_gauntlet_dicts(ctx: RunContext) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for handle, work in ctx.findings.items():
        for index, gauntlet in enumerate(work.gauntlets, start=1):
            out.append({**gauntlet.as_dict(), "iteration": index, "finding_handle": handle})
    return out


def _null_gauntlet() -> Any:
    from app.gauntlet.runner import GauntletOutcome

    return GauntletOutcome()


async def _finding_payload(work: FindingWork) -> dict[str, Any]:
    async with session_scope() as db:
        finding = await db.get(Finding, work.finding_id)
        if finding is None:
            return {"handle": work.handle, "title": "", "state": "", "severity": ""}
        return {
            "handle": finding.handle,
            "title": finding.title,
            "state": finding.state,
            "severity": finding.severity,
            "cwe": finding.cwe,
            "location": finding.location,
            "reachable": finding.reachable,
            "source_channel": finding.source_channel,
            "root_cause_location": finding.root_cause_location,
            "root_cause_summary": finding.root_cause_summary,
            "root_cause_verified": finding.root_cause_verified,
            "root_cause_chain": finding.root_cause_chain,
            "reproduced": finding.reproduced,
            "reproduction_count": finding.reproduction_count,
            "exit_code": finding.exit_code,
            "sanitizer_signal": finding.sanitizer_signal,
            "contract_violation": finding.contract_violation,
            "input_hash": finding.input_hash,
            "output_hash": finding.output_hash,
            "trace_hash": finding.trace_hash,
            "pov_hash": finding.pov_hash,
            "pov_kind": finding.pov_kind,
            "coverage_percent": finding.coverage_percent,
        }



# ---------------------------------------------------------------------------
# Mapping a finding back onto the code-intelligence evidence it came from.
#
# The link is by *location*: a finding's crash site or root cause is a `file:line`, and a security
# flow's sink is the same shape. Matching on location rather than carrying an id through every
# intermediate structure keeps the existing validator and queue untouched — they never had to know
# about flows — while still producing an auditable join.
# ---------------------------------------------------------------------------
def _finding_locations(work: FindingWork) -> set[str]:
    locations: set[str] = set()
    outcome = work.outcome
    if outcome is not None:
        site = str(getattr(outcome, "crash_site", "") or "")
        if site:
            locations.add(site)
    if work.root_cause is not None and work.root_cause.location:
        locations.add(work.root_cause.location)
    plan = work.plan or {}
    if plan.get("target_file"):
        locations.add(f"{plan['target_file']}:{plan.get('target_line', 0)}")
    return {loc for loc in locations if loc}


def _flow_for_finding(ctx: RunContext, work: FindingWork) -> dict[str, Any] | None:
    """The security flow whose sink matches this finding's location, if any."""
    if ctx.security_graph is None:
        return None
    locations = _finding_locations(work)
    files = {loc.split(":")[0] for loc in locations}
    best = None
    for flow in ctx.security_graph.flows:
        sink = ctx.security_graph.nodes.get(flow.sink_ref)
        if sink is None:
            continue
        if sink.location in locations:
            # Exact file:line match wins immediately.
            best = flow
            break
        if sink.file in files and best is None:
            # Same file is a weaker but useful match; keep looking for an exact one.
            best = flow
    if best is None:
        return None
    payload = best.as_dict()
    payload["steps"] = best.explain()
    return payload


def _plans_for_finding(ctx: RunContext, work: FindingWork) -> list[dict[str, Any]]:
    """Test plans generated for the flow this finding corresponds to."""
    flow = _flow_for_finding(ctx, work)
    if flow is None:
        return []
    result = ctx.synthesis.get(str(flow.get("ref", "")))
    if result is None:
        return []
    return [plan.as_dict() for plan in result.plans]


def _executions_for_finding(ctx: RunContext, work: FindingWork) -> list[dict[str, Any]]:
    """Execution records for this finding's plans."""
    plan_ids = {p.get("plan_id") for p in _plans_for_finding(ctx, work)}
    if not plan_ids:
        return []
    return [
        record.as_dict()
        for record in ctx.test_executions
        if record.plan_id in plan_ids
    ]


def _context_for_finding(ctx: RunContext, work: FindingWork) -> dict[str, Any] | None:
    """The model context assembled for this finding's candidate, if a model was consulted."""
    flow = _flow_for_finding(ctx, work)
    if flow is None:
        return None
    return ctx.model_contexts.get(str(flow.get("ref", "")))

# ---------------------------------------------------------------------------
# 12. publish gate
# ---------------------------------------------------------------------------
async def node_publish_gate(ctx: RunContext, state: KavachState) -> KavachState:
    phase = Phase.PUBLISH.value
    await _set_phase(ctx, phase)
    await ctx.emitter.phase_start(phase, "evaluating the publish gate")

    publishable = [
        c for c in state.get("certificates", []) if c["assurance_level"] != AssuranceLevel.R.value
    ]

    # Publishing needs a credential, and a credential only exists for a repository the configured
    # fine-grained token can push to. Blocking here — rather than when a reviewer clicks Approve —
    # means the console tells the truth about what this run can produce from the moment it finishes.
    provider_publishable = bool(state.get("target", {}).get("publishable", False))
    if publishable and not provider_publishable:
        await ctx.emitter.thought(
            agent="PUBLISH GATE",
            hypothesis="A verified patch is ready to become a pull request.",
            evidence=[
                f"{len(publishable)} certificate(s) above Level R",
                f"provider: {state.get('target', {}).get('provider', 'unknown')}",
                "no fine-grained token with push access is configured for this repository",
            ],
            decision=(
                "Publishing is unavailable for this repository. KavachX holds no credential for "
                "it, so the Publisher cannot act. The patch and its certificate are available as "
                "run artifacts for a human to apply."
            ),
            confidence=1.0,
        )
        await ctx.emitter.phase_blocked(
            phase,
            "this repository is analysis-only — publishing requires a fine-grained token with push access",
        )
        await _mark_phase(ctx, phase, "blocked")
        await ctx.emitter.status(
            RunStatus.COMPLETED.value,
            f"{len(publishable)} verified patch(es); publishing unavailable for a "
            f"{state.get('target', {}).get('provider', 'non-installed')} repository",
        )
        await _update_run(ctx.run_id, status=RunStatus.COMPLETED.value)
        state["status"] = RunStatus.COMPLETED.value
        return state

    if not publishable:
        await ctx.emitter.phase_blocked(
            phase,
            "no publishable certificate: nothing reached an assurance level above R",
        )
        await _mark_phase(ctx, phase, "blocked")
        await _update_run(ctx.run_id, status=RunStatus.COMPLETED.value)
        state["status"] = RunStatus.COMPLETED.value
        return state

    # Human approval is a policy decision, and the default is to require it. The run parks in
    # AWAITING_APPROVAL and the Publisher is invoked from the API once a human with
    # patch:publish approves.
    async with session_scope() as db:
        policy_row = await db.scalar(select(Policy).where(Policy.tenant_id == ctx.tenant_id))
        require_approval = policy_row.require_human_approval if policy_row else True

    if require_approval:
        await _update_run(ctx.run_id, status=RunStatus.AWAITING_APPROVAL.value)
        state["status"] = RunStatus.AWAITING_APPROVAL.value
        await ctx.emitter.thought(
            agent="PUBLISH GATE",
            hypothesis="A verified patch is ready to become a pull request.",
            evidence=[
                f"{len(publishable)} certificate(s) above Level R",
                *[f"{c['finding_handle']}: Level {c['assurance_level']}" for c in publishable],
                "policy: human approval required",
            ],
            decision=(
                "Held for human approval. The Publisher — the only component with GitHub "
                "credentials — is not invoked until a reviewer with patch:publish approves."
            ),
            confidence=1.0,
        )
        await ctx.emitter.status(
            RunStatus.AWAITING_APPROVAL.value,
            f"{len(publishable)} verified patch(es) awaiting human publish approval",
        )
        await ctx.emitter.phase_blocked(phase, "awaiting human approval")
        await _mark_phase(ctx, phase, "blocked")
        return state

    await _update_run(ctx.run_id, status=RunStatus.COMPLETED.value)
    state["status"] = RunStatus.COMPLETED.value
    await ctx.emitter.phase_done(phase, "publish permitted without human approval by policy")
    await _mark_phase(ctx, phase, "completed")
    return state
