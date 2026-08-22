"""Authentication and identity."""

from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Request
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import client_ip, ensure_policy, get_audit
from app.audit.service import AuditService
from app.auth.deps import (
    Principal,
    default_membership,
    get_current_principal,
    get_current_user_unscoped,
    resolve_membership,
)
from app.auth.rbac import permissions_for
from app.auth.security import (
    create_token,
    decode_token,
    hash_password,
    token_ttl_seconds,
    verify_password,
)
from app.config import settings
from app.core.errors import (
    EmailAlreadyRegistered,
    InvalidCredentials,
    TokenInvalid,
)
from app.db.session import get_db
from app.models.audit import AuditAction
from app.models.enums import Role
from app.models.identity import Organisation, OrganisationMember, User
from app.schemas.core import (
    LoginRequest,
    MembershipOut,
    MeOut,
    OrganisationCreate,
    OrganisationOut,
    RefreshRequest,
    RegisterRequest,
    SwitchOrgRequest,
    TokenPair,
    UserOut,
)

router = APIRouter(prefix="/auth", tags=["auth"])


def slugify(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return slug or f"org-{uuid.uuid4().hex[:8]}"


async def _unique_slug(db: AsyncSession, base: str) -> str:
    slug = slugify(base)
    for suffix in range(0, 50):
        candidate = slug if suffix == 0 else f"{slug}-{suffix}"
        exists = await db.scalar(select(Organisation.id).where(Organisation.slug == candidate))
        if exists is None:
            return candidate
    return f"{slug}-{uuid.uuid4().hex[:6]}"


def _token_pair(user: User, *, tenant_id: uuid.UUID | None, role: str | None) -> TokenPair:
    return TokenPair(
        access_token=create_token(
            subject=user.id,
            token_type="access",
            tenant_id=tenant_id,
            role=role,
            token_version=user.token_version,
        ),
        refresh_token=create_token(
            subject=user.id,
            token_type="refresh",
            tenant_id=tenant_id,
            role=role,
            token_version=user.token_version,
        ),
        expires_in=token_ttl_seconds("access"),
        organisation_id=tenant_id,
        role=role,
    )


# ---------------------------------------------------------------------------
@router.post("/register", response_model=TokenPair, status_code=201)
async def register(
    payload: RegisterRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    audit: AuditService = Depends(get_audit),
) -> TokenPair:
    existing = await db.scalar(select(User).where(func.lower(User.email) == payload.email.lower()))
    if existing is not None:
        raise EmailAlreadyRegistered()

    user = User(
        email=payload.email.lower(),
        full_name=payload.full_name,
        password_hash=hash_password(payload.password),
    )
    db.add(user)
    await db.flush()

    organisation_name = payload.organisation_name or f"{payload.email.split('@')[0]} workspace"
    organisation = Organisation(
        name=organisation_name,
        slug=await _unique_slug(db, organisation_name),
        created_by=user.id,
    )
    db.add(organisation)
    await db.flush()

    # The creator is the OWNER; ``tenant_id`` on the membership is the organisation itself.
    membership = OrganisationMember(
        tenant_id=organisation.id,
        organisation_id=organisation.id,
        user_id=user.id,
        role=Role.OWNER.value,
    )
    db.add(membership)
    await ensure_policy(db, organisation.id)
    await db.flush()

    await audit.record(
        tenant_id=organisation.id,
        action=AuditAction.USER_REGISTERED,
        actor_user_id=user.id,
        actor_label=user.email,
        subject_type="user",
        subject_id=str(user.id),
        source_ip=client_ip(request),
        detail={"organisation": organisation.slug},
    )
    await audit.record(
        tenant_id=organisation.id,
        action=AuditAction.ORG_CREATED,
        actor_user_id=user.id,
        actor_label=user.email,
        subject_type="organisation",
        subject_id=str(organisation.id),
        source_ip=client_ip(request),
        detail={"name": organisation.name},
    )
    return _token_pair(user, tenant_id=organisation.id, role=Role.OWNER.value)


@router.post("/login", response_model=TokenPair)
async def login(
    payload: LoginRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    audit: AuditService = Depends(get_audit),
) -> TokenPair:
    user = await db.scalar(select(User).where(func.lower(User.email) == payload.email.lower()))

    # Verify against a dummy hash when the account is absent so the response time does not
    # distinguish "no such user" from "wrong password".
    if user is None:
        verify_password(payload.password, hash_password("kavachx-timing-equaliser-value"))
        raise InvalidCredentials()
    if not user.is_active or not verify_password(payload.password, user.password_hash):
        membership = await default_membership(db, user.id)
        if membership is not None:
            await audit.record(
                tenant_id=membership[0].id,
                action=AuditAction.LOGIN_FAILED,
                actor_label=payload.email.lower(),
                subject_type="user",
                subject_id=str(user.id),
                source_ip=client_ip(request),
                detail={"reason": "invalid password" if user.is_active else "inactive account"},
            )
        raise InvalidCredentials()

    user.last_login_at = datetime.now(timezone.utc)
    membership = await default_membership(db, user.id)
    tenant_id = membership[0].id if membership else None
    role = membership[1].role if membership else None

    if tenant_id is not None:
        await audit.record(
            tenant_id=tenant_id,
            action=AuditAction.LOGIN,
            actor_user_id=user.id,
            actor_label=user.email,
            subject_type="user",
            subject_id=str(user.id),
            source_ip=client_ip(request),
            detail={"role": role},
        )
    return _token_pair(user, tenant_id=tenant_id, role=role)


@router.post("/refresh", response_model=TokenPair)
async def refresh(
    payload: RefreshRequest,
    db: AsyncSession = Depends(get_db),
) -> TokenPair:
    claims = decode_token(payload.refresh_token, expected_type="refresh")
    user = await db.get(User, uuid.UUID(str(claims["sub"])))
    if user is None or not user.is_active:
        raise TokenInvalid("The account is inactive or no longer exists.")
    if int(claims.get("tv", 0)) != user.token_version:
        raise TokenInvalid("Token has been revoked. Sign in again.")

    tenant_raw = claims.get("tid")
    tenant_id = uuid.UUID(str(tenant_raw)) if tenant_raw else None
    role = claims.get("role")
    if tenant_id is not None:
        # Re-check membership: a refresh must not resurrect access that was revoked.
        membership = await resolve_membership(db, user.id, tenant_id)
        role = membership.role
    return _token_pair(user, tenant_id=tenant_id, role=role)


@router.post("/switch-org", response_model=TokenPair)
async def switch_organisation(
    payload: SwitchOrgRequest,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user_unscoped),
) -> TokenPair:
    membership = await resolve_membership(db, user.id, payload.organisation_id)
    return _token_pair(user, tenant_id=payload.organisation_id, role=membership.role)


@router.get("/me", response_model=MeOut)
async def me(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user_unscoped),
    request: Request = None,  # type: ignore[assignment]
) -> MeOut:
    rows = (
        await db.execute(
            select(Organisation, OrganisationMember)
            .join(OrganisationMember, OrganisationMember.organisation_id == Organisation.id)
            .where(OrganisationMember.user_id == user.id)
            .order_by(OrganisationMember.created_at.asc())
        )
    ).all()

    memberships = [
        MembershipOut(
            organisation_id=org.id,
            organisation_name=org.name,
            organisation_slug=org.slug,
            role=member.role,
        )
        for org, member in rows
    ]

    active_id: uuid.UUID | None = None
    active_role: str | None = None
    header = request.headers.get("authorization", "") if request else ""
    if header.lower().startswith("bearer "):
        try:
            claims = decode_token(header.split(" ", 1)[1], expected_type="access")
            if claims.get("tid"):
                active_id = uuid.UUID(str(claims["tid"]))
                active_role = next(
                    (m.role for m in memberships if m.organisation_id == active_id), None
                )
        except Exception:
            active_id = None

    if active_id is None and memberships:
        active_id = memberships[0].organisation_id
        active_role = memberships[0].role

    return MeOut(
        user=UserOut.model_validate(user),
        memberships=memberships,
        active_organisation_id=active_id,
        active_role=active_role,
        permissions=sorted(permissions_for(active_role or "")),
    )


@router.post("/logout", status_code=204)
async def logout(
    request: Request,
    principal: Principal = Depends(get_current_principal),
    audit: AuditService = Depends(get_audit),
) -> None:
    await audit.record(
        tenant_id=principal.tenant_id,
        action=AuditAction.LOGOUT,
        actor_user_id=principal.user_id,
        actor_label=principal.label,
        subject_type="user",
        subject_id=str(principal.user_id),
        source_ip=client_ip(request),
    )


@router.post("/organisations", response_model=OrganisationOut, status_code=201)
async def create_organisation(
    payload: OrganisationCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user_unscoped),
    audit: AuditService = Depends(get_audit),
) -> OrganisationOut:
    organisation = Organisation(
        name=payload.name, slug=await _unique_slug(db, payload.name), created_by=user.id
    )
    db.add(organisation)
    await db.flush()
    db.add(
        OrganisationMember(
            tenant_id=organisation.id,
            organisation_id=organisation.id,
            user_id=user.id,
            role=Role.OWNER.value,
        )
    )
    await ensure_policy(db, organisation.id)
    await db.flush()
    await audit.record(
        tenant_id=organisation.id,
        action=AuditAction.ORG_CREATED,
        actor_user_id=user.id,
        actor_label=user.email,
        subject_type="organisation",
        subject_id=str(organisation.id),
        source_ip=client_ip(request),
        detail={"name": organisation.name},
    )
    return OrganisationOut.model_validate(organisation)


@router.get("/organisations", response_model=list[OrganisationOut])
async def list_organisations(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user_unscoped),
) -> list[OrganisationOut]:
    rows = (
        await db.scalars(
            select(Organisation)
            .join(OrganisationMember, OrganisationMember.organisation_id == Organisation.id)
            .where(OrganisationMember.user_id == user.id)
            .order_by(Organisation.created_at.asc())
        )
    ).all()
    return [OrganisationOut.model_validate(o) for o in rows]


@router.get("/config")
async def auth_config() -> dict[str, object]:
    """Non-secret facts the sign-in screen needs."""
    return {
        "password_min_length": settings.password_min_length,
        "access_token_ttl_seconds": settings.access_token_ttl_seconds,
        "dev_mode": settings.dev_mode,
        "github_app_configured": settings.github_app_configured,
        "github_app_slug": settings.github_app_slug,
    }
