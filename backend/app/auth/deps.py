"""Authentication / authorisation dependencies.

A request carries its tenant *inside the signed access token* (``tid`` + ``role``). The
client cannot pick a tenant by sending a header — switching organisations requires
re-minting a token through ``/api/auth/switch-org``, which re-checks membership. That
removes the entire class of "forgot to filter by tenant_id" bugs from the API layer.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field

from fastapi import Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.rbac import Permission, has_permission, permissions_for, require_permission
from app.auth.security import decode_token
from app.core.errors import AuthenticationError, PermissionDenied, TokenInvalid
from app.core.logging import tenant_id_var, user_id_var
from app.db.session import get_db
from app.models.identity import Organisation, OrganisationMember, User

bearer_scheme = HTTPBearer(auto_error=False, description="KavachX access token")


@dataclass(slots=True)
class Principal:
    """The authenticated actor, resolved once per request."""

    user: User
    tenant_id: uuid.UUID
    role: str
    permissions: frozenset[str] = field(default_factory=frozenset)

    @property
    def user_id(self) -> uuid.UUID:
        return self.user.id

    @property
    def label(self) -> str:
        return self.user.email

    def can(self, permission: str) -> bool:
        return permission in self.permissions

    def require(self, permission: str) -> None:
        require_permission(self.role, permission)

    def assert_tenant(self, tenant_id: uuid.UUID) -> None:
        from app.core.errors import TenantMismatch

        if tenant_id != self.tenant_id:
            raise TenantMismatch()


async def get_current_principal(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    db: AsyncSession = Depends(get_db),
) -> Principal:
    if credentials is None or not credentials.credentials:
        raise AuthenticationError()

    payload = decode_token(credentials.credentials, expected_type="access")

    try:
        user_id = uuid.UUID(str(payload["sub"]))
    except (KeyError, ValueError) as exc:
        raise TokenInvalid("Token subject is not a valid user id.") from exc

    user = await db.get(User, user_id)
    if user is None or not user.is_active:
        raise AuthenticationError("The account is inactive or no longer exists.")
    if int(payload.get("tv", 0)) != user.token_version:
        raise TokenInvalid("Token has been revoked. Sign in again.")

    tid_raw = payload.get("tid")
    if not tid_raw:
        raise TokenInvalid("Token is not scoped to an organisation.")
    tenant_id = uuid.UUID(str(tid_raw))

    # The role in the token is a cache; membership is re-verified against the database on
    # every request so a revoked or downgraded membership takes effect immediately.
    membership = await db.scalar(
        select(OrganisationMember).where(
            OrganisationMember.user_id == user.id,
            OrganisationMember.organisation_id == tenant_id,
        )
    )
    if membership is None:
        raise PermissionDenied("You are not a member of this organisation.")

    user_id_var.set(str(user.id))
    tenant_id_var.set(str(tenant_id))
    request.state.principal_email = user.email

    return Principal(
        user=user,
        tenant_id=tenant_id,
        role=membership.role,
        permissions=permissions_for(membership.role),
    )


async def get_current_user_unscoped(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    db: AsyncSession = Depends(get_db),
) -> User:
    """For endpoints that operate before an organisation is chosen (``/auth/me``)."""
    if credentials is None or not credentials.credentials:
        raise AuthenticationError()
    payload = decode_token(credentials.credentials, expected_type="access")
    user = await db.get(User, uuid.UUID(str(payload["sub"])))
    if user is None or not user.is_active:
        raise AuthenticationError()
    if int(payload.get("tv", 0)) != user.token_version:
        raise TokenInvalid("Token has been revoked. Sign in again.")
    return user


class RequirePermission:
    """Dependency factory: ``Depends(RequirePermission(Permission.RUN_START))``."""

    def __init__(self, permission: str) -> None:
        self.permission = permission

    async def __call__(self, principal: Principal = Depends(get_current_principal)) -> Principal:
        if not has_permission(principal.role, self.permission):
            raise PermissionDenied(
                f"Role {principal.role} lacks the {self.permission} permission.",
                details={"required_permission": self.permission, "role": principal.role},
            )
        return principal


async def resolve_membership(
    db: AsyncSession, user_id: uuid.UUID, organisation_id: uuid.UUID
) -> OrganisationMember:
    membership = await db.scalar(
        select(OrganisationMember).where(
            OrganisationMember.user_id == user_id,
            OrganisationMember.organisation_id == organisation_id,
        )
    )
    if membership is None:
        raise PermissionDenied("You are not a member of this organisation.")
    return membership


async def default_membership(
    db: AsyncSession, user_id: uuid.UUID
) -> tuple[Organisation, OrganisationMember] | None:
    row = (
        await db.execute(
            select(Organisation, OrganisationMember)
            .join(OrganisationMember, OrganisationMember.organisation_id == Organisation.id)
            .where(OrganisationMember.user_id == user_id)
            .order_by(OrganisationMember.created_at.asc())
            .limit(1)
        )
    ).first()
    if row is None:
        return None
    return row[0], row[1]


__all__ = [
    "Permission",
    "Principal",
    "RequirePermission",
    "default_membership",
    "get_current_principal",
    "get_current_user_unscoped",
    "resolve_membership",
]
