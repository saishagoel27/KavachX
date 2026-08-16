"""
Shared FastAPI dependencies: caller identity and permission checks.

Two identity sources, in order:

1. `Authorization: Bearer <session jwt>` — the real path (GitHub App login
   mints the token in `kavachx.api.routes.auth`).
2. A `role` query/body parameter — development only, and only while
   `AUTH_REQUIRED=false`. It lets the dashboard exercise the RBAC matrix
   before the login flow is wired into the frontend. `EventSource` cannot
   send headers, so the SSE stream depends on this path too.
"""

from dataclasses import dataclass, replace
from typing import Optional

from fastapi import Depends, HTTPException, Query, Request

from kavachx.api.middleware.rbac import has_permission, normalize_role
from kavachx.api.routes.auth import verify_session_token
from kavachx.core.config import get_settings


@dataclass(frozen=True)
class Identity:
    tenant_id: str
    role: str
    user_id: str
    source: str  # "session" | "role-param"

    @property
    def authenticated(self) -> bool:
        return self.source == "session"

    def with_role(self, role: Optional[str]) -> "Identity":
        """Apply a body-supplied role. A verified session always wins."""
        if self.authenticated or not role:
            return self
        return replace(self, role=normalize_role(role))

    def require(self, permission: str) -> None:
        if not has_permission(self.role, permission):
            raise HTTPException(
                status_code=403,
                detail=f"Role '{self.role}' lacks the '{permission}' permission",
            )

    def can(self, permission: str) -> bool:
        return has_permission(self.role, permission)


async def get_identity(
    request: Request,
    role: Optional[str] = Query(
        None, description="Dev-only role override; ignored when a session token is present"
    ),
) -> Identity:
    settings = get_settings()
    authorization = request.headers.get("Authorization", "")

    if authorization.startswith("Bearer "):
        claims = verify_session_token(authorization.removeprefix("Bearer ").strip())
        identity = Identity(
            tenant_id=claims.get("tenant_id", settings.demo_tenant_id),
            role=normalize_role(claims.get("role")),
            user_id=claims.get("sub", "unknown"),
            source="session",
        )
    elif settings.auth_required:
        raise HTTPException(status_code=401, detail="Authentication required")
    else:
        identity = Identity(
            tenant_id=settings.demo_tenant_id,
            role=normalize_role(role),
            user_id="dev-user",
            source="role-param",
        )

    request.state.tenant_id = identity.tenant_id
    request.state.role = identity.role
    request.state.user_id = identity.user_id
    return identity


def require_permission(permission: str):
    """Route dependency: 403 unless the caller's role holds `permission`."""

    async def _check(identity: Identity = Depends(get_identity)) -> Identity:
        identity.require(permission)
        return identity

    return _check


__all__ = ["Identity", "get_identity", "require_permission"]
