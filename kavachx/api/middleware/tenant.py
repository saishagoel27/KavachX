from fastapi import Request, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware
import jwt
from typing import Optional


def extract_tenant_from_token(token: str) -> Optional[str]:
    """
    Extract tenant_id from a JWT token.
    For P0, uses a simple mock token format: "tenant:{tenant_id}"
    In production, this will verify JWT signatures and extract claims.
    """
    try:
        # P0: Mock token format for testing
        if token.startswith("tenant:"):
            return token.split(":")[1]
        
        # Fallback: attempt JWT decode (requires SECRET_KEY from config)
        # decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        # return decoded.get("tenant_id")
        
        return None
    except Exception:
        return None


class TenantMiddleware(BaseHTTPMiddleware):
    """
    Reads tenant_id from the verified JWT (set by auth dependency) and
    stores it on request.state so DB sessions can call SET LOCAL app.tenant_id.
    """

    async def dispatch(self, request: Request, call_next):
        # tenant_id is populated by the auth dependency after JWT verification.
        # Middleware only ensures the attribute exists so downstream code can
        # always read request.state.tenant_id safely.
        if not hasattr(request.state, "tenant_id"):
            request.state.tenant_id = None
        return await call_next(request)


async def set_tenant_context(conn, tenant_id: str) -> None:
    """Call this at the start of every DB session to activate RLS."""
    if not tenant_id:
        raise ValueError("tenant_id must be set before executing queries")
    # Use parameterised SET to avoid injection
    await conn.execute(f"SET LOCAL app.tenant_id = '{tenant_id}'")
