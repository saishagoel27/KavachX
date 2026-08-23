"""Runs: creation, detail, SSE event stream, abort, dashboard."""

from __future__ import annotations

import asyncio
import json
import secrets
import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import StreamingResponse
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import client_ip, get_audit, load_run
from app.audit.service import AuditService
from app.auth.deps import Permission, Principal, RequirePermission, get_current_principal
from app.auth.security import decode_token
from app.core.errors import (
    AuthenticationError,
    BadRequest,
    RepositoryNotAuthorised,
    RunNotAbortable,
)
from app.core.logging import get_logger
from app.db.session import get_db
from app.events.bus import bus
from app.models.analysis import Finding, Hypothesis, SamhitaClause, Shield
from app.models.audit import AuditAction
from app.models.enums import FindingState, PatchStatus, RunStatus
from app.models.identity import OrganisationMember, User
from app.models.pramaan import Certificate
from app.models.project import Project, Repository
from app.models.repair import Patch
from app.models.run import Artifact, Run, RunEvent, WorldModel
from app.orchestration import runner
from app.sandbox import describe_available
from app.schemas.core import (
    AbortRequest,
    ArtifactOut,
    DashboardOut,
    RunCreate,
    RunDetail,
    RunOut,
)

logger = get_logger(__name__)
router = APIRouter(tags=["runs"])

#: SSE heartbeat, so proxies and browsers keep the connection open through quiet phases.
HEARTBEAT_SECONDS = 15.0


def _short_code() -> str:
    return secrets.token_hex(2).upper()


def _build_run_config(payload: RunCreate) -> dict[str, Any]:
    """Assemble the operator's Vercel/Render-style run configuration.

    A pasted ``.env`` blob is parsed here (with the shared parser) and merged under any individually
    supplied variables, so ``env_vars`` wins on a key present in both.
    """
    from app.core.dotenv import parse_dotenv

    env: dict[str, str] = {}
    if payload.env_text:
        env.update(parse_dotenv(payload.env_text))
    env.update(payload.env_vars or {})
    return {
        "root_directory": payload.root_directory.strip(),
        "install_command": payload.install_command.strip(),
        "build_command": payload.build_command.strip(),
        "start_command": payload.start_command.strip(),
        "target_type": payload.target_type or "auto",
        "env_vars": env,
        "benign_requests": [r for r in payload.benign_requests if isinstance(r, dict)],
    }


async def _run_out(db: AsyncSession, run: Run) -> RunOut:
    model = RunOut.model_validate(run)
    repository = await db.get(Repository, run.repository_id)
    project = await db.get(Project, run.project_id)
    model.repository_full_name = repository.full_name if repository else ""
    model.project_name = project.name if project else ""
    return model


# ---------------------------------------------------------------------------
@router.post("/runs", response_model=RunOut, status_code=202)
async def create_run(
    payload: RunCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    principal: Principal = Depends(RequirePermission(Permission.RUN_START)),
    audit: AuditService = Depends(get_audit),
) -> RunOut:
    repository = await db.get(Repository, payload.repository_id)
    if repository is None or repository.tenant_id != principal.tenant_id:
        raise RepositoryNotAuthorised(
            "That repository is not attached to this organisation.",
            code="REPOSITORY_NOT_FOUND",
        )

    # Authority is re-checked at run start, not trusted from attach time. A revoked installation
    # must stop new analysis even though the row still exists.
    if not repository.authority_verified:
        raise RepositoryNotAuthorised()

    if not payload.authorisation_confirmed:
        raise BadRequest(
            "You must confirm that you are authorised to analyse this repository.",
            code="AUTHORISATION_NOT_CONFIRMED",
        )

    run = Run(
        tenant_id=principal.tenant_id,
        project_id=repository.project_id,
        repository_id=repository.id,
        short_code=_short_code(),
        # Blank payload branch -> whatever the repository reported at attach time. The final
        # "main" is only reachable for a row attached before default_branch was recorded.
        branch=payload.branch or repository.default_branch or "main",
        commit_sha=payload.commit_sha,
        analysis_profile=payload.analysis_profile.value,
        execution_profile=payload.execution_profile.value,
        max_runtime_seconds=payload.max_runtime_seconds,
        resource_budget=payload.resource_budget,
        run_config=_build_run_config(payload),
        status=RunStatus.QUEUED.value,
        requested_by=principal.user_id,
    )
    db.add(run)
    await db.flush()

    await audit.record(
        tenant_id=principal.tenant_id,
        action=AuditAction.RUN_STARTED,
        actor_user_id=principal.user_id,
        actor_label=principal.label,
        subject_type="run",
        subject_id=str(run.id),
        source_ip=client_ip(request),
        detail={
            "repository": repository.full_name,
            "branch": run.branch,
            "commit_sha": run.commit_sha,
            "analysis_profile": run.analysis_profile,
            "execution_profile": run.execution_profile,
            "authorisation_confirmed": True,
            "authority_evidence": repository.authority_evidence,
        },
    )
    # Commit before scheduling: the background task opens its own session and must see the row.
    await db.commit()

    await runner.start_run(
        run_id=run.id,
        tenant_id=principal.tenant_id,
        project_id=run.project_id,
        repository_id=run.repository_id,
        short_code=run.short_code,
        execution_profile=run.execution_profile,
        analysis_profile=run.analysis_profile,
        max_runtime_seconds=run.max_runtime_seconds,
        requested_by=principal.user_id,
    )
    return await _run_out(db, run)


@router.get("/runs", response_model=list[RunOut])
async def list_runs(
    project_id: uuid.UUID | None = None,
    status: str | None = None,
    limit: int = Query(default=50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    principal: Principal = Depends(get_current_principal),
) -> list[RunOut]:
    stmt = select(Run).where(Run.tenant_id == principal.tenant_id)
    if project_id is not None:
        stmt = stmt.where(Run.project_id == project_id)
    if status:
        stmt = stmt.where(Run.status == status.upper())
    rows = list((await db.scalars(stmt.order_by(Run.created_at.desc()).limit(limit))).all())
    return [await _run_out(db, run) for run in rows]


@router.get("/runs/{run_id}", response_model=RunDetail)
async def get_run(
    run: Run = Depends(load_run),
    db: AsyncSession = Depends(get_db),
    principal: Principal = Depends(get_current_principal),
) -> RunDetail:
    base = await _run_out(db, run)
    detail = RunDetail(**base.model_dump())

    detail.findings_total = int(
        await db.scalar(select(func.count()).select_from(Finding).where(Finding.run_id == run.id))
        or 0
    )
    detail.findings_validated = int(
        await db.scalar(
            select(func.count())
            .select_from(Finding)
            .where(Finding.run_id == run.id, Finding.state == FindingState.VALIDATED.value)
        )
        or 0
    )
    detail.patches_verified = int(
        await db.scalar(
            select(func.count())
            .select_from(Patch)
            .where(Patch.run_id == run.id, Patch.status == PatchStatus.VERIFIED.value)
        )
        or 0
    )

    certificates = list(
        (await db.scalars(select(Certificate).where(Certificate.run_id == run.id))).all()
    )
    findings_by_id = {
        f.id: f for f in (await db.scalars(select(Finding).where(Finding.run_id == run.id))).all()
    }
    detail.certificates = [
        {
            "id": str(c.id),
            "serial": c.serial,
            "assurance_level": c.assurance_level,
            "certificate_hash": c.certificate_hash,
            "finding_handle": findings_by_id[c.finding_id].handle
            if c.finding_id in findings_by_id
            else "",
            "issued_at": c.issued_at.isoformat() if c.issued_at else None,
            "limitations": c.limitations,
        }
        for c in certificates
    ]

    shields = list((await db.scalars(select(Shield).where(Shield.run_id == run.id))).all())
    detail.shields = [
        {
            "id": str(s.id),
            "handle": s.handle,
            "mechanism": s.mechanism,
            "rule": s.rule,
            "verified_blocked": s.verified_blocked,
            "verified_benign": s.verified_benign,
            "benign_pass_count": s.benign_pass_count,
            "benign_total": s.benign_total,
            "active": s.active,
            "revert_command": s.revert_command,
            "finding_handle": findings_by_id[s.finding_id].handle
            if s.finding_id in findings_by_id
            else "",
        }
        for s in shields
    ]

    clause_rows = list(
        (await db.scalars(select(SamhitaClause).where(SamhitaClause.run_id == run.id))).all()
    )
    summary: dict[str, int] = {}
    for clause in clause_rows:
        summary[clause.status] = summary.get(clause.status, 0) + 1
    detail.clause_summary = summary

    hypothesis_rows = list(
        (await db.scalars(select(Hypothesis).where(Hypothesis.run_id == run.id))).all()
    )
    counts: dict[str, int] = {}
    for hypothesis in hypothesis_rows:
        counts[hypothesis.status] = counts.get(hypothesis.status, 0) + 1
    detail.hypothesis_counts = counts

    world = await db.scalar(select(WorldModel).where(WorldModel.run_id == run.id))
    if world is not None:
        detail.world_model = {
            "content_hash": world.content_hash,
            "file_count": world.file_count,
            "function_count": world.function_count,
            "entrypoint_count": world.entrypoint_count,
            "sink_count": world.sink_count,
            "indexer": world.indexer,
            "summary": (world.graph_json or {}).get("summary", {}),
            "entrypoints": (world.graph_json or {}).get("entrypoints", []),
            "sinks": (world.graph_json or {}).get("sinks", [])[:60],
        }

    detail.sandbox = describe_available()
    artifacts = list(
        (
            await db.scalars(
                select(Artifact)
                .where(Artifact.run_id == run.id)
                .order_by(Artifact.created_at.asc())
            )
        ).all()
    )
    detail.artifacts = [
        {
            "id": str(a.id),
            "kind": a.kind,
            "name": a.name,
            "media_type": a.media_type,
            "size_bytes": a.size_bytes,
            "content_hash": a.content_hash,
            "url": a.url,
        }
        for a in artifacts
    ]
    return detail


# ---------------------------------------------------------------------------
# SSE
# ---------------------------------------------------------------------------
async def _authenticate_stream(
    request: Request, db: AsyncSession, token_param: str | None
) -> Principal:
    """Resolve the principal for an SSE request.

    ``EventSource`` cannot set headers, so a token may arrive as a query parameter. It is
    validated identically to a header token — same signature check, same membership re-check.
    """
    from app.auth.rbac import permissions_for

    header = request.headers.get("authorization", "")
    token = ""
    if header.lower().startswith("bearer "):
        token = header.split(" ", 1)[1]
    elif token_param:
        token = token_param
    if not token:
        raise AuthenticationError()

    claims = decode_token(token, expected_type="access")
    user = await db.get(User, uuid.UUID(str(claims["sub"])))
    if user is None or not user.is_active:
        raise AuthenticationError()
    if int(claims.get("tv", 0)) != user.token_version:
        raise AuthenticationError("Token has been revoked. Sign in again.")

    tenant_raw = claims.get("tid")
    if not tenant_raw:
        raise AuthenticationError("Token is not scoped to an organisation.")
    tenant_id = uuid.UUID(str(tenant_raw))
    membership = await db.scalar(
        select(OrganisationMember).where(
            OrganisationMember.user_id == user.id,
            OrganisationMember.organisation_id == tenant_id,
        )
    )
    if membership is None:
        raise AuthenticationError("You are not a member of this organisation.")
    return Principal(
        user=user,
        tenant_id=tenant_id,
        role=membership.role,
        permissions=permissions_for(membership.role),
    )


@router.get("/runs/{run_id}/events")
async def stream_events(
    run_id: uuid.UUID,
    request: Request,
    token: str | None = Query(default=None, description="Access token for EventSource clients"),
    last_event_id: int | None = Query(default=None, alias="lastEventId"),
    db: AsyncSession = Depends(get_db),
) -> StreamingResponse:
    """Server-Sent Events stream.

    Replays from ``Last-Event-ID`` (header or query) out of PostgreSQL, then joins the live
    stream. A page refresh therefore loses nothing, and a reconnect produces no gap and no
    duplicate.
    """
    principal = await _authenticate_stream(request, db, token)
    run = await db.get(Run, run_id)
    if run is None or run.tenant_id != principal.tenant_id:
        from app.core.errors import RunNotFound

        raise RunNotFound()

    header_last = request.headers.get("last-event-id", "")
    after_seq = 0
    if header_last.isdigit():
        after_seq = int(header_last)
    elif last_event_id is not None:
        after_seq = int(last_event_id)

    tenant_id = principal.tenant_id
    terminal_statuses = {
        RunStatus.COMPLETED.value,
        RunStatus.FAILED.value,
        RunStatus.ABORTED.value,
        RunStatus.AWAITING_APPROVAL.value,
    }

    async def event_stream():
        queue = bus.subscribe(run_id)
        try:
            yield _sse(
                "hello",
                {
                    "run_id": str(run_id),
                    "replay_from": after_seq,
                    "server_time": datetime.now(timezone.utc).isoformat(),
                },
            )

            replay = await bus.replay(run_id=run_id, after_seq=after_seq)
            highest = after_seq
            for envelope in replay:
                highest = max(highest, int(envelope["seq"]))
                yield _sse("message", envelope, event_id=envelope["seq"])

            # A finished run needs no live tail.
            current_status = await _run_status(run_id, tenant_id)
            if current_status in terminal_statuses:
                yield _sse("end", {"run_id": str(run_id), "status": current_status})
                return

            while True:
                if await request.is_disconnected():
                    break
                try:
                    envelope = await asyncio.wait_for(queue.get(), timeout=HEARTBEAT_SECONDS)
                except TimeoutError:
                    status = await _run_status(run_id, tenant_id)
                    yield _sse(
                        "heartbeat",
                        {"ts": datetime.now(timezone.utc).isoformat(), "status": status},
                    )
                    if status in terminal_statuses:
                        yield _sse("end", {"run_id": str(run_id), "status": status})
                        break
                    continue

                if envelope.get("__terminal__"):
                    status = await _run_status(run_id, tenant_id)
                    yield _sse("end", {"run_id": str(run_id), "status": status})
                    break
                seq = int(envelope["seq"])
                if seq <= highest:
                    continue
                highest = seq
                yield _sse("message", envelope, event_id=seq)
        finally:
            bus.unsubscribe(run_id, queue)

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache, no-transform",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


def _sse(event: str, data: Any, *, event_id: int | None = None) -> str:
    lines = []
    if event_id is not None:
        lines.append(f"id: {event_id}")
    lines.append(f"event: {event}")
    lines.append(f"data: {json.dumps(data, default=str)}")
    return "\n".join(lines) + "\n\n"


async def _run_status(run_id: uuid.UUID, tenant_id: uuid.UUID) -> str:
    from app.db.session import session_scope

    async with session_scope() as db:
        run = await db.get(Run, run_id)
        if run is None or run.tenant_id != tenant_id:
            return "UNKNOWN"
        return run.status


@router.get("/runs/{run_id}/events/history")
async def event_history(
    run: Run = Depends(load_run),
    after_seq: int = Query(default=0, ge=0),
    limit: int = Query(default=1000, ge=1, le=5000),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    rows = list(
        (
            await db.scalars(
                select(RunEvent)
                .where(RunEvent.run_id == run.id, RunEvent.seq > after_seq)
                .order_by(RunEvent.seq.asc())
                .limit(limit)
            )
        ).all()
    )
    return {
        "run_id": str(run.id),
        "events": [
            {
                "seq": r.seq,
                "ts": r.created_at.isoformat(),
                "event": r.payload,
            }
            for r in rows
        ],
        "count": len(rows),
    }


# ---------------------------------------------------------------------------
@router.post("/runs/{run_id}/abort", response_model=RunOut)
async def abort_run(
    payload: AbortRequest,
    request: Request,
    run: Run = Depends(load_run),
    db: AsyncSession = Depends(get_db),
    principal: Principal = Depends(RequirePermission(Permission.RUN_ABORT)),
    audit: AuditService = Depends(get_audit),
) -> RunOut:
    if run.status not in (RunStatus.QUEUED.value, RunStatus.RUNNING.value):
        raise RunNotAbortable()

    run.abort_requested = True
    run.aborted_by = principal.user_id
    await audit.record(
        tenant_id=principal.tenant_id,
        action=AuditAction.RUN_ABORTED,
        actor_user_id=principal.user_id,
        actor_label=principal.label,
        subject_type="run",
        subject_id=str(run.id),
        source_ip=client_ip(request),
        detail={"reason": payload.reason},
    )
    await db.commit()
    await runner.request_abort(run.id)
    await db.refresh(run)
    return await _run_out(db, run)


@router.get("/runs/{run_id}/artifacts", response_model=list[ArtifactOut])
async def list_artifacts(
    run: Run = Depends(load_run),
    db: AsyncSession = Depends(get_db),
) -> list[ArtifactOut]:
    rows = list(
        (
            await db.scalars(
                select(Artifact)
                .where(Artifact.run_id == run.id)
                .order_by(Artifact.created_at.asc())
            )
        ).all()
    )
    return [ArtifactOut.model_validate(r) for r in rows]


@router.get("/runs/{run_id}/artifacts/{name}")
async def get_artifact(
    name: str,
    run: Run = Depends(load_run),
    db: AsyncSession = Depends(get_db),
) -> Any:
    from fastapi.responses import PlainTextResponse

    from app.core.errors import NotFound

    artifact = await db.scalar(
        select(Artifact).where(Artifact.run_id == run.id, Artifact.name == name)
    )
    if artifact is None:
        raise NotFound(f"No artifact named {name!r} for this run.", code="ARTIFACT_NOT_FOUND")
    return PlainTextResponse(
        artifact.content,
        media_type=artifact.media_type,
        headers={"X-Content-Sha256": artifact.content_hash},
    )


@router.get("/runs/{run_id}/checkpoints")
async def list_checkpoints(
    run: Run = Depends(load_run),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    from app.models.run import RunCheckpoint

    rows = list(
        (
            await db.scalars(
                select(RunCheckpoint)
                .where(RunCheckpoint.run_id == run.id)
                .order_by(RunCheckpoint.seq.asc())
            )
        ).all()
    )
    return {
        "run_id": str(run.id),
        "checkpoints": [
            {
                "seq": r.seq,
                "node": r.node,
                "state_hash": r.state_hash,
                "created_at": r.created_at.isoformat(),
                "phase": (r.state_json or {}).get("phase", ""),
                "status": (r.state_json or {}).get("status", ""),
            }
            for r in rows
        ],
    }


# ---------------------------------------------------------------------------
@router.get("/dashboard", response_model=DashboardOut)
async def dashboard(
    db: AsyncSession = Depends(get_db),
    principal: Principal = Depends(get_current_principal),
) -> DashboardOut:
    """Every number here is aggregated from run state. Nothing is hardcoded."""
    tenant = principal.tenant_id

    async def count(model: Any, *conditions: Any) -> int:
        stmt = select(func.count()).select_from(model).where(model.tenant_id == tenant)
        for condition in conditions:
            stmt = stmt.where(condition)
        return int(await db.scalar(stmt) or 0)

    runs = list(
        (
            await db.scalars(
                select(Run).where(Run.tenant_id == tenant).order_by(Run.created_at.desc()).limit(10)
            )
        ).all()
    )

    certificates = list(
        (await db.scalars(select(Certificate).where(Certificate.tenant_id == tenant))).all()
    )
    by_level: dict[str, int] = {}
    for certificate in certificates:
        by_level[certificate.assurance_level] = by_level.get(certificate.assurance_level, 0) + 1

    protection_values = [
        r.time_to_protection_ms
        for r in (await db.scalars(select(Run).where(Run.tenant_id == tenant))).all()
        if r.time_to_protection_ms
    ]
    repair_values = [
        r.time_to_repair_ms
        for r in (await db.scalars(select(Run).where(Run.tenant_id == tenant))).all()
        if r.time_to_repair_ms
    ]

    patches_verified = await count(Patch, Patch.status == PatchStatus.VERIFIED.value)
    patches_refuted = await count(Patch, Patch.status == PatchStatus.REFUTED.value)
    attempted = patches_verified + patches_refuted

    totals = (
        await db.execute(
            select(
                func.coalesce(func.sum(Run.tokens_used), 0),
                func.coalesce(func.sum(Run.sandbox_executions), 0),
                func.coalesce(func.sum(Run.egress_bytes), 0),
            ).where(Run.tenant_id == tenant)
        )
    ).one()

    residual = len(
        [c for c in certificates if c.assurance_level in ("B", "C", "R") or c.limitations]
    )

    return DashboardOut(
        projects=await count(Project),
        repositories=await count(Repository),
        repositories_verified=await count(Repository, Repository.authority_verified_at.isnot(None)),
        runs_total=await count(Run),
        runs_active=await count(
            Run, Run.status.in_([RunStatus.QUEUED.value, RunStatus.RUNNING.value])
        ),
        runs_completed=await count(Run, Run.status == RunStatus.COMPLETED.value),
        findings_total=await count(Finding),
        findings_validated=await count(Finding, Finding.state == FindingState.VALIDATED.value),
        findings_refuted=await count(Finding, Finding.state == FindingState.REFUTED.value),
        patches_verified=patches_verified,
        patches_refuted=patches_refuted,
        certificates_total=len(certificates),
        certificates_by_level=by_level,
        avg_time_to_protection_ms=(
            int(sum(protection_values) / len(protection_values)) if protection_values else None
        ),
        avg_time_to_repair_ms=(
            int(sum(repair_values) / len(repair_values)) if repair_values else None
        ),
        verification_success_rate=round(patches_verified / attempted, 4) if attempted else 0.0,
        open_pull_requests=await count(Artifact, Artifact.kind == "pr"),
        residual_risk_items=residual,
        total_tokens=int(totals[0] or 0),
        total_sandbox_executions=int(totals[1] or 0),
        egress_bytes=int(totals[2] or 0),
        recent_runs=[await _run_out(db, run) for run in runs],
    )
