"""Shared API dependencies: audit service, tenant-scoped loaders."""

from __future__ import annotations

import uuid
from typing import Any

from fastapi import Depends, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit.service import AuditService
from app.auth.deps import Principal, get_current_principal
from app.core.errors import (
    CertificateNotFound,
    FindingNotFound,
    ProjectNotFound,
    RepositoryNotFound,
    RunNotFound,
)
from app.db.session import get_db
from app.models.analysis import Finding
from app.models.pramaan import Certificate
from app.models.project import Policy, Project, Repository
from app.models.run import Run


async def get_audit(db: AsyncSession = Depends(get_db)) -> AuditService:
    return AuditService(db)


def client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded:
        return forwarded.split(",")[0].strip()[:64]
    return (request.client.host if request.client else "")[:64]


async def load_run(
    run_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    principal: Principal = Depends(get_current_principal),
) -> Run:
    run = await db.get(Run, run_id)
    # A run in another tenant is reported as not-found rather than forbidden: a 403 would confirm
    # the id exists, which is itself a cross-tenant information leak.
    if run is None or run.tenant_id != principal.tenant_id:
        raise RunNotFound()
    return run


async def load_project(
    project_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    principal: Principal = Depends(get_current_principal),
) -> Project:
    project = await db.get(Project, project_id)
    if project is None or project.tenant_id != principal.tenant_id:
        raise ProjectNotFound()
    return project


async def load_repository(
    repository_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    principal: Principal = Depends(get_current_principal),
) -> Repository:
    repository = await db.get(Repository, repository_id)
    if repository is None or repository.tenant_id != principal.tenant_id:
        raise RepositoryNotFound()
    return repository


async def load_finding(
    finding_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    principal: Principal = Depends(get_current_principal),
) -> Finding:
    finding = await db.get(Finding, finding_id)
    if finding is None or finding.tenant_id != principal.tenant_id:
        raise FindingNotFound()
    return finding


async def load_certificate(
    certificate_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    principal: Principal = Depends(get_current_principal),
) -> Certificate:
    certificate = await db.get(Certificate, certificate_id)
    if certificate is None or certificate.tenant_id != principal.tenant_id:
        raise CertificateNotFound()
    return certificate


async def get_policy(db: AsyncSession, tenant_id: uuid.UUID) -> Policy | None:
    return await db.scalar(select(Policy).where(Policy.tenant_id == tenant_id))


async def ensure_policy(db: AsyncSession, tenant_id: uuid.UUID) -> Policy:
    from app.models.project import DEFAULT_FORBIDDEN_GLOBS

    policy = await get_policy(db, tenant_id)
    if policy is not None:
        return policy
    policy = Policy(
        tenant_id=tenant_id,
        name="default",
        forbidden_path_globs=list(DEFAULT_FORBIDDEN_GLOBS),
    )
    db.add(policy)
    await db.flush()
    return policy


def paginate(limit: int, offset: int, *, max_limit: int = 200) -> tuple[int, int]:
    return max(1, min(limit, max_limit)), max(0, offset)


def as_dict(model: Any, extra: dict[str, Any] | None = None) -> dict[str, Any]:
    out = {
        column.name: getattr(model, column.name)
        for column in model.__table__.columns  # type: ignore[attr-defined]
    }
    if extra:
        out.update(extra)
    return out
