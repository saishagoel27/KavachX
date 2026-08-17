"""Role-based access control.

Permissions are a closed set. A role's grant list is data, not code, so the whole
authorisation surface can be read in one screen and asserted in tests.

The important asymmetry: ``finding:read`` is broadly granted, but ``finding:read_pov`` —
the *working exploit* — is restricted to OWNER, MAINTAINER and SECURITY_REVIEWER. An
AUDITOR can read the audit log and the certificate but never the weapon.
"""

from __future__ import annotations

from app.core.errors import PermissionDenied
from app.models.enums import Role


class Permission:
    RUN_START = "run:start"
    RUN_READ = "run:read"
    RUN_ABORT = "run:abort"
    FINDING_READ = "finding:read"
    FINDING_READ_POV = "finding:read_pov"
    PATCH_READ = "patch:read"
    PATCH_REVIEW = "patch:review"
    PATCH_PUBLISH = "patch:publish"
    SHIELD_MANAGE = "shield:manage"
    POLICY_MANAGE = "policy:manage"
    MEMBER_MANAGE = "member:manage"
    PROJECT_MANAGE = "project:manage"
    REPOSITORY_MANAGE = "repository:manage"
    CERTIFICATE_READ = "certificate:read"
    AUDIT_READ = "audit:read"


ALL_PERMISSIONS: frozenset[str] = frozenset(
    value for key, value in vars(Permission).items() if not key.startswith("_")
)

_READ_ONLY = {
    Permission.RUN_READ,
    Permission.FINDING_READ,
    Permission.PATCH_READ,
    Permission.CERTIFICATE_READ,
}

ROLE_PERMISSIONS: dict[str, frozenset[str]] = {
    Role.OWNER: frozenset(ALL_PERMISSIONS),
    Role.MAINTAINER: frozenset(
        _READ_ONLY
        | {
            Permission.RUN_START,
            Permission.RUN_ABORT,
            Permission.FINDING_READ_POV,
            Permission.PATCH_REVIEW,
            Permission.PATCH_PUBLISH,
            Permission.SHIELD_MANAGE,
            Permission.PROJECT_MANAGE,
            Permission.REPOSITORY_MANAGE,
            Permission.AUDIT_READ,
        }
    ),
    Role.SECURITY_REVIEWER: frozenset(
        _READ_ONLY
        | {
            Permission.RUN_START,
            Permission.RUN_ABORT,
            Permission.FINDING_READ_POV,
            Permission.PATCH_REVIEW,
            Permission.SHIELD_MANAGE,
            Permission.AUDIT_READ,
        }
    ),
    # A developer can drive analysis and read patches, but never sees a working exploit
    # and cannot publish.
    Role.DEVELOPER: frozenset(_READ_ONLY | {Permission.RUN_START, Permission.RUN_ABORT}),
    Role.VIEWER: frozenset(_READ_ONLY),
    # An auditor reads the trail and the attestation. No exploits, no runs, no patches.
    Role.AUDITOR: frozenset(
        {
            Permission.RUN_READ,
            Permission.FINDING_READ,
            Permission.CERTIFICATE_READ,
            Permission.AUDIT_READ,
        }
    ),
}


def permissions_for(role: str) -> frozenset[str]:
    return ROLE_PERMISSIONS.get(role, frozenset())


def has_permission(role: str, permission: str) -> bool:
    return permission in permissions_for(role)


def require_permission(role: str, permission: str) -> None:
    if not has_permission(role, permission):
        raise PermissionDenied(
            f"Role {role} lacks the {permission} permission.",
            details={"required_permission": permission, "role": role},
        )


ROLE_DESCRIPTIONS: dict[str, str] = {
    Role.OWNER: "Full control of the organisation, including policy and membership.",
    Role.MAINTAINER: "Runs analysis, reviews and publishes patches, sees working exploits.",
    Role.SECURITY_REVIEWER: "Reviews findings and exploits; cannot publish to GitHub.",
    Role.DEVELOPER: "Starts runs and reads findings and patches; no exploit access.",
    Role.VIEWER: "Read-only access to runs, findings, patches and certificates.",
    Role.AUDITOR: "Read-only access to the audit trail and certificates. No exploit access.",
}
