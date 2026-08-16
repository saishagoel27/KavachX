from fastapi import HTTPException, Request

# Full permission matrix — all 6 roles defined now, enforced progressively
# P0 active roles: owner, sec_reviewer, viewer
ROLE_PERMISSIONS: dict[str, set[str]] = {
    "owner": {
        "run:start", "finding:read", "finding:read_pov",
        "patch:review", "patch:publish", "policy:manage",
        "member:manage", "audit:read", "run:abort",
    },
    "maintainer": {
        "run:start", "finding:read", "finding:read_pov",
        "patch:review", "patch:publish", "audit:read", "run:abort",
    },
    "sec_reviewer": {
        "finding:read", "finding:read_pov", "patch:review", "audit:read",
    },
    "developer": {
        "finding:read", "patch:review",
    },
    "viewer": {
        "finding:read",
    },
    "auditor": {
        "finding:read", "audit:read",
    },
}


def normalize_role(role: str | None) -> str:
    """
    Map a display role to a matrix key: "Sec Reviewer" → "sec_reviewer".

    Unknown or missing roles fall back to `viewer` (least privilege).
    """
    if not role:
        return "viewer"
    key = role.strip().lower().replace("-", "_").replace(" ", "_")
    return key if key in ROLE_PERMISSIONS else "viewer"


def has_permission(role: str, permission: str) -> bool:
    return permission in ROLE_PERMISSIONS.get(role, set())


def check_permission(role: str, permission: str) -> bool:
    """Check if a role has permission for an action."""
    return has_permission(role, permission)


def require(permission: str):
    """FastAPI dependency — raises 403 if the session role lacks the permission."""
    async def _check(request: Request):
        role = getattr(request.state, "role", None)
        if not role or not has_permission(role, permission):
            raise HTTPException(
                status_code=403,
                detail={
                    "error": "permission_denied",
                    "message": f"{permission} permission required",
                },
            )
    return _check
