"""
Dashboard API — the endpoints the React frontend consumes.

Mounted under `/api` by `app.py`:

    POST   /api/runs                                start a run
    GET    /api/runs                                list this tenant's runs
    GET    /api/runs/{run_id}                       run summary
    GET    /api/runs/{run_id}/stream                SSE trace (RunEvents)
    GET    /api/runs/{run_id}/findings              findings, PoV gated by role
    GET    /api/runs/{run_id}/certificate           PRAMAAN certificate
    GET    /api/runs/{run_id}/deliverables/{name}   CHANGES.md / REMAINING.md
    POST   /api/runs/{run_id}/abort                 cancel a running analysis
    POST   /api/publish                             policy gate → pull request
    GET    /api/audit                               hash-chained audit log
"""

import json
import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import PlainTextResponse, StreamingResponse
from pydantic import BaseModel, Field

from kavachx.api.deps import Identity, get_identity
from kavachx.core.audit import ledger
from kavachx.core.config import get_settings
from kavachx.core.run_engine import PublishRejected, publish_finding, registry

logger = logging.getLogger(__name__)

router = APIRouter(tags=["dashboard"])

DELIVERABLES = ("changes.md", "remaining.md")


# ── Request models ────────────────────────────────────────────────────────────

class StartRunRequest(BaseModel):
    repo_url: str = Field(min_length=1)
    role: Optional[str] = None
    branch: str = "main"


class PublishRequest(BaseModel):
    run_id: str
    finding_id: str
    role: Optional[str] = None


# ── Helpers ───────────────────────────────────────────────────────────────────

def _get_run(run_id: str, identity: Identity):
    run = registry.get(run_id)
    if not run:
        raise HTTPException(status_code=404, detail=f"Run {run_id} not found")
    if run.tenant_id != identity.tenant_id:
        # Same response as "missing" — never confirm another tenant's run exists.
        raise HTTPException(status_code=404, detail=f"Run {run_id} not found")
    return run


def _public_finding(finding: dict, can_read_pov: bool) -> dict:
    """Exploit payloads are redacted to a hash unless the role holds finding:read_pov."""
    view = {
        "finding_id": finding["finding_id"],
        "title": finding["title"],
        "description": finding.get("description", ""),
        "state": finding["state"],
        "severity": finding["severity"],
        "reachable": finding["reachable"],
        "clause": finding.get("clause"),
        "component": finding.get("component"),
        "remediation_path": finding.get("remediation_path"),
        "pov_hash": finding.get("pov_hash"),
    }
    if can_read_pov:
        view["pov_code"] = finding.get("pov_code")
    return view


# ── Runs ──────────────────────────────────────────────────────────────────────

@router.post("/runs", status_code=201)
async def start_run(
    payload: StartRunRequest,
    identity: Identity = Depends(get_identity),
) -> dict:
    identity = identity.with_role(payload.role)
    identity.require("run:start")

    settings = get_settings()
    if registry.active_count(identity.tenant_id) >= settings.max_concurrent_runs:
        raise HTTPException(
            status_code=429,
            detail=f"Concurrent run limit reached ({settings.max_concurrent_runs}). "
                   "Wait for a run to finish.",
        )

    run = registry.create(payload.repo_url, identity.role, identity.tenant_id)
    registry.start(run)

    logger.info("[API] Run %s started on %s by role=%s", run.run_id, run.channel, identity.role)
    return {
        "run_id": run.run_id,
        "status": "started",
        "repo_url": run.repo_url,
        "channel": run.channel,
    }


@router.get("/runs")
async def list_runs(identity: Identity = Depends(get_identity)) -> list[dict]:
    identity.require("finding:read")
    return [run.summary() for run in registry.list(identity.tenant_id)]


@router.get("/runs/{run_id}")
async def get_run(run_id: str, identity: Identity = Depends(get_identity)) -> dict:
    identity.require("finding:read")
    run = _get_run(run_id, identity)
    summary = run.summary()
    summary["gauntlet"] = dict(run.gauntlet)
    summary["error"] = run.error
    return summary


@router.post("/runs/{run_id}/abort")
async def abort_run(run_id: str, identity: Identity = Depends(get_identity)) -> dict:
    identity.require("run:abort")
    run = _get_run(run_id, identity)
    if run.task and not run.task.done():
        run.task.cancel()
    return {"run_id": run_id, "status": "aborted"}


# ── SSE stream ────────────────────────────────────────────────────────────────

@router.get("/runs/{run_id}/stream")
async def stream_run(
    run_id: str,
    request: Request,
    identity: Identity = Depends(get_identity),
):
    """
    Server-Sent Events. History is replayed first, so a client that connects
    after the run started still renders the full trace.
    """
    identity.require("finding:read")
    run = _get_run(run_id, identity)
    keepalive = get_settings().sse_keepalive_seconds

    async def event_source():
        try:
            async for event in run.stream.subscribe(keepalive=keepalive):
                if await request.is_disconnected():
                    break
                if event is None:
                    yield ": keepalive\n\n"
                    continue
                yield f"data: {json.dumps(event, default=str)}\n\n"
        except Exception:  # noqa: BLE001 — a broken pipe must not spam the log
            logger.debug("[API] SSE stream closed for %s", run_id, exc_info=True)

    return StreamingResponse(
        event_source(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache, no-transform",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",  # disable proxy buffering (nginx)
        },
    )


# ── Findings ──────────────────────────────────────────────────────────────────

@router.get("/runs/{run_id}/findings")
async def list_findings(run_id: str, identity: Identity = Depends(get_identity)) -> list[dict]:
    identity.require("finding:read")
    run = _get_run(run_id, identity)
    can_read_pov = identity.can("finding:read_pov")
    return [_public_finding(f, can_read_pov) for f in run.findings]


@router.get("/runs/{run_id}/findings/{finding_id}/pov")
async def get_finding_pov(
    run_id: str,
    finding_id: str,
    identity: Identity = Depends(get_identity),
) -> dict:
    identity.require("finding:read_pov")
    run = _get_run(run_id, identity)
    finding = run.finding(finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail=f"Finding {finding_id} not found")

    ledger.append(
        actor=identity.role,
        action="finding:pov_read",
        subject=finding_id,
        tenant_id=identity.tenant_id,
        run_id=run_id,
    )
    return {
        "finding_id": finding_id,
        "pov_code": finding.get("pov_code"),
        "pov_hash": finding.get("pov_hash"),
    }


# ── Patches ───────────────────────────────────────────────────────────────────

@router.get("/runs/{run_id}/patches")
async def list_patches(run_id: str, identity: Identity = Depends(get_identity)) -> list[dict]:
    identity.require("patch:review")
    run = _get_run(run_id, identity)
    return [{**diff, "gauntlet": dict(run.gauntlet)} for diff in run.diffs]


# ── Certificate ───────────────────────────────────────────────────────────────

@router.get("/runs/{run_id}/certificate")
async def get_certificate(run_id: str, identity: Identity = Depends(get_identity)) -> dict:
    identity.require("finding:read")
    run = _get_run(run_id, identity)
    if not run.certificate:
        raise HTTPException(status_code=404, detail="Certificate not issued yet")
    return run.certificate


# ── Deliverables ──────────────────────────────────────────────────────────────

@router.get("/runs/{run_id}/deliverables/{name}")
async def get_deliverable(
    run_id: str,
    name: str,
    identity: Identity = Depends(get_identity),
) -> PlainTextResponse:
    identity.require("finding:read")
    run = _get_run(run_id, identity)

    key = name.lower()
    if key not in DELIVERABLES:
        raise HTTPException(status_code=404, detail=f"Unknown deliverable '{name}'")
    content = run.deliverables.get(key)
    if content is None:
        raise HTTPException(status_code=404, detail=f"{name} is not available yet")

    return PlainTextResponse(
        content,
        media_type="text/markdown; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{key}"'},
    )


# ── Publish ───────────────────────────────────────────────────────────────────

@router.post("/publish")
async def publish(
    payload: PublishRequest,
    identity: Identity = Depends(get_identity),
) -> dict:
    identity = identity.with_role(payload.role)
    identity.require("patch:publish")
    run = _get_run(payload.run_id, identity)

    try:
        result = await publish_finding(run, payload.finding_id, identity.role)
    except PublishRejected as exc:
        ledger.append(
            actor=identity.role,
            action="publish:rejected",
            subject=f"{payload.finding_id} — {exc}",
            tenant_id=identity.tenant_id,
            run_id=run.run_id,
        )
        raise HTTPException(status_code=403, detail=str(exc)) from exc

    return {
        "run_id": run.run_id,
        "finding_id": payload.finding_id,
        "pr_url": result["pr_url"],
        "already_published": result["already_published"],
    }


# ── Audit ─────────────────────────────────────────────────────────────────────

@router.get("/audit")
async def get_audit(
    run_id: Optional[str] = None,
    limit: int = 200,
    identity: Identity = Depends(get_identity),
) -> list[dict]:
    identity.require("audit:read")
    entries = ledger.list(tenant_id=identity.tenant_id, run_id=run_id, limit=limit)
    return [
        {
            "log_id": e["log_id"],
            "timestamp": e["timestamp"],
            "actor": e["actor"],
            "action": e["action"],
            "subject": e["subject"],
            "evidence_hash": e["evidence_hash"],
            "prev_hash": e["prev_hash"],
            "run_id": e["run_id"],
        }
        for e in entries
    ]


@router.get("/audit/verify")
async def verify_audit(identity: Identity = Depends(get_identity)) -> dict:
    identity.require("audit:read")
    return {"intact": ledger.verify(), "anchor": ledger.anchor()}


__all__ = ["router"]
