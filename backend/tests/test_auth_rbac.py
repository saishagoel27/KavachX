"""Authentication, RBAC and tenant isolation."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import httpx
import jwt
import pytest

from app.auth.rbac import ROLE_PERMISSIONS, Permission, has_permission
from app.auth.security import create_token, hash_password, verify_password
from app.db.session import session_scope
from app.models.enums import Role
from app.models.identity import User
from tests.conftest import DEMO_PASSWORD, auth


# ---------------------------------------------------------------------------
# password hashing
# ---------------------------------------------------------------------------
def test_password_hash_round_trip():
    digest = hash_password("a-sufficiently-long-password")
    assert digest != "a-sufficiently-long-password"
    assert verify_password("a-sufficiently-long-password", digest)
    assert not verify_password("wrong-password-entirely", digest)


def test_short_password_rejected():
    from app.core.errors import ValidationError

    with pytest.raises(ValidationError):
        hash_password("short")


def test_overlong_password_rejected():
    """bcrypt truncates at 72 bytes; accepting a longer one would silently weaken it."""
    from app.core.errors import ValidationError

    with pytest.raises(ValidationError):
        hash_password("x" * 200)


# ---------------------------------------------------------------------------
# tokens
# ---------------------------------------------------------------------------
async def test_login_and_me(client: httpx.AsyncClient, tenant_a):
    response = await client.get("/api/auth/me", headers=auth(tenant_a["token"]))
    assert response.status_code == 200
    body = response.json()
    assert body["user"]["email"] == tenant_a["email"]
    assert body["active_role"] == Role.OWNER.value
    assert Permission.PATCH_PUBLISH in body["permissions"]


async def test_wrong_password_rejected(client: httpx.AsyncClient, tenant_a):
    response = await client.post(
        "/api/auth/login", json={"email": tenant_a["email"], "password": "not-the-password"}
    )
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "INVALID_CREDENTIALS"


async def test_unknown_email_gives_same_error(client: httpx.AsyncClient):
    """No user enumeration: an unknown address and a wrong password look identical."""
    response = await client.post(
        "/api/auth/login",
        json={"email": "nobody-at-all@kavachx.io", "password": "irrelevant-but-long"},
    )
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "INVALID_CREDENTIALS"


@pytest.mark.security
async def test_expired_jwt_rejected(client: httpx.AsyncClient, tenant_a):
    expired = create_token(
        subject=tenant_a["user_id"],
        token_type="access",
        tenant_id=tenant_a["organisation_id"],
        role=Role.OWNER.value,
        ttl_seconds=-60,
    )
    response = await client.get("/api/auth/me", headers=auth(expired))
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "TOKEN_EXPIRED"


@pytest.mark.security
async def test_token_signed_with_wrong_key_rejected(client: httpx.AsyncClient, tenant_a):
    forged = jwt.encode(
        {
            "sub": tenant_a["user_id"],
            "typ": "access",
            "tid": tenant_a["organisation_id"],
            "iss": "kavachx",
            "exp": int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp()),
        },
        "a-completely-different-signing-key",
        algorithm="HS256",
    )
    response = await client.get("/api/auth/me", headers=auth(forged))
    assert response.status_code == 401


@pytest.mark.security
async def test_refresh_token_cannot_be_used_as_access_token(client: httpx.AsyncClient, tenant_a):
    refresh = create_token(
        subject=tenant_a["user_id"],
        token_type="refresh",
        tenant_id=tenant_a["organisation_id"],
        role=Role.OWNER.value,
    )
    response = await client.get("/api/auth/me", headers=auth(refresh))
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "TOKEN_INVALID"


@pytest.mark.security
async def test_token_version_bump_revokes_tokens(client: httpx.AsyncClient, tenant_a):
    """A forced logout must invalidate tokens already in the wild."""
    before = await client.get("/api/auth/me", headers=auth(tenant_a["token"]))
    assert before.status_code == 200

    async with session_scope() as db:
        user = await db.get(User, uuid.UUID(tenant_a["user_id"]))
        user.token_version += 1

    after = await client.get("/api/auth/me", headers=auth(tenant_a["token"]))
    assert after.status_code == 401
    assert after.json()["error"]["code"] == "TOKEN_INVALID"


async def test_missing_token_rejected(client: httpx.AsyncClient):
    response = await client.get("/api/dashboard")
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "NOT_AUTHENTICATED"


async def test_refresh_issues_new_pair(client: httpx.AsyncClient, tenant_a):
    login = await client.post(
        "/api/auth/login", json={"email": tenant_a["email"], "password": DEMO_PASSWORD}
    )
    refresh_token = login.json()["refresh_token"]
    response = await client.post("/api/auth/refresh", json={"refresh_token": refresh_token})
    assert response.status_code == 200
    assert response.json()["access_token"]


# ---------------------------------------------------------------------------
# RBAC
# ---------------------------------------------------------------------------
def test_permission_matrix_shape():
    """The asymmetry that matters: who may see a working exploit, and who may publish."""
    assert has_permission(Role.OWNER, Permission.FINDING_READ_POV)
    assert has_permission(Role.MAINTAINER, Permission.FINDING_READ_POV)
    assert has_permission(Role.SECURITY_REVIEWER, Permission.FINDING_READ_POV)
    assert not has_permission(Role.DEVELOPER, Permission.FINDING_READ_POV)
    assert not has_permission(Role.VIEWER, Permission.FINDING_READ_POV)
    assert not has_permission(Role.AUDITOR, Permission.FINDING_READ_POV)

    assert has_permission(Role.OWNER, Permission.PATCH_PUBLISH)
    assert has_permission(Role.MAINTAINER, Permission.PATCH_PUBLISH)
    assert not has_permission(Role.SECURITY_REVIEWER, Permission.PATCH_PUBLISH)
    assert not has_permission(Role.DEVELOPER, Permission.PATCH_PUBLISH)

    assert has_permission(Role.AUDITOR, Permission.AUDIT_READ)
    assert not has_permission(Role.AUDITOR, Permission.RUN_START)
    assert not has_permission(Role.VIEWER, Permission.RUN_START)


def test_every_role_has_a_permission_set():
    for role in Role:
        assert role.value in ROLE_PERMISSIONS, f"{role} has no permission set"


@pytest.mark.security
async def test_viewer_cannot_start_run(client: httpx.AsyncClient, role_tokens):
    response = await client.post(
        "/api/runs",
        headers=auth(role_tokens[Role.VIEWER.value]),
        json={
            "repository_id": role_tokens["_repository_id"],
            "branch": "main",
            "analysis_profile": "quick",
            "execution_profile": "dev_local",
            "max_runtime_seconds": 300,
            "authorisation_confirmed": True,
        },
    )
    assert response.status_code == 403
    body = response.json()["error"]
    assert body["code"] == "PERMISSION_DENIED"
    assert body["details"]["required_permission"] == Permission.RUN_START


@pytest.mark.security
async def test_developer_cannot_manage_policy(client: httpx.AsyncClient, role_tokens):
    response = await client.patch(
        "/api/policy",
        headers=auth(role_tokens[Role.DEVELOPER.value]),
        json={"require_human_approval": False},
    )
    assert response.status_code == 403


async def test_owner_can_manage_policy(client: httpx.AsyncClient, role_tokens):
    response = await client.patch(
        "/api/policy",
        headers=auth(role_tokens[Role.OWNER.value]),
        json={"max_diff_lines": 150},
    )
    assert response.status_code == 200
    assert response.json()["max_diff_lines"] == 150


async def test_auditor_can_read_audit(client: httpx.AsyncClient, role_tokens):
    response = await client.get("/api/audit", headers=auth(role_tokens[Role.AUDITOR.value]))
    assert response.status_code == 200
    assert response.json()["chain_head"]


async def test_run_authorisation_must_be_confirmed(client: httpx.AsyncClient, tenant_a):
    response = await client.post(
        "/api/runs",
        headers=auth(tenant_a["token"]),
        json={
            "repository_id": tenant_a["repository_id"],
            "branch": "main",
            "analysis_profile": "quick",
            "execution_profile": "dev_local",
            "max_runtime_seconds": 300,
            "authorisation_confirmed": False,
        },
    )
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "AUTHORISATION_NOT_CONFIRMED"


@pytest.mark.security
async def test_unauthorised_repository_rejected(client: httpx.AsyncClient, tenant_a):
    """A repository whose authority was never verified cannot be analysed."""
    from app.models.project import Repository

    async with session_scope() as db:
        repository = Repository(
            tenant_id=uuid.UUID(tenant_a["organisation_id"]),
            project_id=uuid.UUID(tenant_a["project_id"]),
            provider="github_app",
            full_name="someone-else/private-repo",
            default_branch="main",
            authority_verified_at=None,
        )
        db.add(repository)
        await db.flush()
        unverified_id = str(repository.id)

    response = await client.post(
        "/api/runs",
        headers=auth(tenant_a["token"]),
        json={
            "repository_id": unverified_id,
            "branch": "main",
            "analysis_profile": "quick",
            "execution_profile": "dev_local",
            "max_runtime_seconds": 300,
            "authorisation_confirmed": True,
        },
    )
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "REPOSITORY_NOT_AUTHORISED"


@pytest.mark.security
async def test_local_target_outside_examples_rejected(
    client: httpx.AsyncClient, tenant_a, tmp_path
):
    """DEV_MODE does not mean "analyse any directory on this machine"."""
    from app.config import settings as live_settings

    original = live_settings.demo_repo_path
    live_settings.demo_repo_path = str(tmp_path)
    try:
        response = await client.post(
            f"/api/projects/{tenant_a['project_id']}/repositories",
            headers=auth(tenant_a["token"]),
            json={"full_name": "evil/elsewhere", "local_seeded": True, "default_branch": "main"},
        )
        assert response.status_code == 403
        assert response.json()["error"]["code"] == "REPOSITORY_NOT_AUTHORISED"
    finally:
        live_settings.demo_repo_path = original


# ---------------------------------------------------------------------------
# tenant isolation
# ---------------------------------------------------------------------------
@pytest.mark.security
async def test_tenant_a_cannot_read_tenant_b_project(client: httpx.AsyncClient, tenant_a, tenant_b):
    response = await client.get(
        f"/api/projects/{tenant_b['project_id']}", headers=auth(tenant_a["token"])
    )
    # 404 rather than 403: a 403 would confirm the id exists, which is itself a leak.
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "PROJECT_NOT_FOUND"


@pytest.mark.security
async def test_tenant_listings_are_disjoint(client: httpx.AsyncClient, tenant_a, tenant_b):
    a = await client.get("/api/projects", headers=auth(tenant_a["token"]))
    b = await client.get("/api/projects", headers=auth(tenant_b["token"]))
    a_ids = {p["id"] for p in a.json()}
    b_ids = {p["id"] for p in b.json()}
    assert a_ids and b_ids
    assert not (a_ids & b_ids)


@pytest.mark.security
async def test_tenant_a_cannot_read_tenant_b_run(client: httpx.AsyncClient, tenant_a, tenant_b):
    from app.models.run import Run

    async with session_scope() as db:
        run = Run(
            tenant_id=uuid.UUID(tenant_b["organisation_id"]),
            project_id=uuid.UUID(tenant_b["project_id"]),
            repository_id=uuid.UUID(tenant_b["repository_id"]),
            short_code="ZZZZ",
        )
        db.add(run)
        await db.flush()
        run_id = str(run.id)

    for path in (f"/api/runs/{run_id}", f"/api/runs/{run_id}/findings"):
        response = await client.get(path, headers=auth(tenant_a["token"]))
        assert response.status_code == 404, path


@pytest.mark.security
async def test_switch_org_requires_membership(client: httpx.AsyncClient, tenant_a, tenant_b):
    response = await client.post(
        "/api/auth/switch-org",
        headers=auth(tenant_a["token"]),
        json={"organisation_id": tenant_b["organisation_id"]},
    )
    assert response.status_code == 403


@pytest.mark.security
async def test_audit_log_is_tenant_scoped(client: httpx.AsyncClient, tenant_a, tenant_b):
    a = await client.get("/api/audit", headers=auth(tenant_a["token"]))
    b = await client.get("/api/audit", headers=auth(tenant_b["token"]))
    a_actors = {item["actor_label"] for item in a.json()["items"]}
    b_actors = {item["actor_label"] for item in b.json()["items"]}
    assert tenant_b["email"] not in a_actors
    assert tenant_a["email"] not in b_actors
