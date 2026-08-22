"""Health, readiness, audit log, and system introspection."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import client_ip, get_audit
from app.audit.service import AuditService
from app.auth.deps import Permission, Principal, RequirePermission
from app.config import settings
from app.core.logging import get_logger
from app.db.session import get_db
from app.llm.registry import provider_health
from app.models.audit import AuditAction
from app.orchestration import runner
from app.sandbox import describe_available
from app.schemas.core import AuditEventOut, AuditPage, HealthOut, ReadyOut
from app.shield.service import describe_mechanisms

logger = get_logger(__name__)
router = APIRouter(tags=["system"])

VERSION = "1.0.0"


@router.get("/audit", response_model=AuditPage)
async def list_audit(
    request: Request,
    action: str | None = None,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    principal: Principal = Depends(RequirePermission(Permission.AUDIT_READ)),
    audit: AuditService = Depends(get_audit),
) -> AuditPage:
    items, total = await audit.list_events(
        tenant_id=principal.tenant_id, limit=limit, offset=offset, action=action
    )
    head = await audit.head_hash(tenant_id=principal.tenant_id)
    # Reading the audit log is itself an audited action.
    await audit.record(
        tenant_id=principal.tenant_id,
        action=AuditAction.AUDIT_READ,
        actor_user_id=principal.user_id,
        actor_label=principal.label,
        subject_type="audit",
        subject_id="page",
        source_ip=client_ip(request),
        detail={"limit": limit, "offset": offset, "filter_action": action or ""},
    )
    return AuditPage(
        items=[AuditEventOut.model_validate(e) for e in items],
        total=total,
        limit=limit,
        offset=offset,
        chain_head=head,
    )


@router.get("/audit/verify")
async def verify_audit_chain(
    principal: Principal = Depends(RequirePermission(Permission.AUDIT_READ)),
    audit: AuditService = Depends(get_audit),
) -> dict[str, Any]:
    """Recompute the whole hash chain for this tenant."""
    return await audit.verify_chain(tenant_id=principal.tenant_id)


# ---------------------------------------------------------------------------
@router.get("/system/sandbox")
async def sandbox_info() -> dict[str, Any]:
    """Adapter readiness and, crucially, what each one actually enforces."""
    info = describe_available()
    configured = info["adapters"].get(info["configured"], {})
    return {
        **info,
        "active_capabilities": configured,
        "honest_warning": (
            configured.get("notes", "")
            if not configured.get("suitable_for_untrusted_code", False)
            else ""
        ),
    }


@router.get("/system/llm")
async def llm_info() -> dict[str, Any]:
    health = await provider_health()
    return {
        **health,
        "configured_provider": settings.llm_provider,
        "fallback_to_mock": settings.llm_fallback_to_mock,
        "models": settings.llm_models,
        "token_budget_per_run": settings.llm_run_token_budget,
        "timeout_seconds": settings.llm_timeout_seconds,
        "max_retries": settings.llm_max_retries,
        "contract": (
            "The model proposes; deterministic components validate; the state machine decides. "
            "Every response is parsed through a strict Pydantic schema and a schema failure is a "
            "hard failure."
        ),
    }


@router.get("/system/shield")
async def shield_info() -> dict[str, Any]:
    return {"mechanisms": describe_mechanisms()}


@router.get("/system/limits")
async def limits_info() -> dict[str, Any]:
    return {
        "iteration_limits": {
            "harness": settings.max_harness_iterations,
            "patch": settings.max_patch_iterations,
            "clause": settings.max_clause_iterations,
        },
        "run_max_runtime_seconds": settings.run_max_runtime_seconds,
        "sandbox": {
            "cpu_limit": settings.sandbox_cpu_limit,
            "memory_mb": settings.sandbox_memory_mb,
            "pid_limit": settings.sandbox_pid_limit,
            "disk_mb": settings.sandbox_disk_mb,
            "wall_clock_seconds": settings.sandbox_wall_clock_seconds,
        },
        "token_budget_per_run": settings.llm_run_token_budget,
        "note": (
            "These ceilings exist so no run can loop autonomously without bound. Exceeding one "
            "aborts the run rather than degrading it silently."
        ),
    }


@router.get("/system/config")
async def config_info() -> dict[str, Any]:
    """Redacted settings snapshot. Every secret is replaced before serialisation."""
    return settings.safe_dump()


# ---------------------------------------------------------------------------
health_router = APIRouter(tags=["health"])


@health_router.get("/health", response_model=HealthOut)
async def health() -> HealthOut:
    return HealthOut(
        status="ok",
        version=VERSION,
        environment=settings.kavachx_env,
        dev_mode=settings.dev_mode,
    )


@health_router.get("/ready", response_model=ReadyOut)
async def ready(db: AsyncSession = Depends(get_db)) -> ReadyOut:
    database_ok = True
    details: dict[str, Any] = {}
    try:
        await db.execute(text("SELECT 1"))
    except Exception as exc:
        database_ok = False
        details["database_error"] = str(exc)[:300]

    sandbox = describe_available()
    configured = sandbox["adapters"].get(sandbox["configured"], {})

    return ReadyOut(
        status="ready" if database_ok else "degraded",
        database=database_ok,
        llm_provider=settings.llm_provider,
        llm_configured=settings.llm_configured,
        sandbox_adapter=sandbox["configured"],
        sandbox_suitable_for_untrusted_code=bool(
            configured.get("suitable_for_untrusted_code", False)
        ),
        github_configured=settings.github_configured,
        publisher_dry_run=settings.publisher_dry_run,
        active_runs=runner.active_run_ids(),
        details=details,
    )
