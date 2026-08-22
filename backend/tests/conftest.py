"""Test fixtures.

The suite runs against SQLite (aiosqlite) and the deterministic mock proposer, so it needs no
PostgreSQL, no network and no GPU — and it exercises the same code paths a hosted run does.
Environment is set before ``app`` is imported, because settings are read at import time.
"""

from __future__ import annotations

import asyncio
import os
import sys
import uuid
from collections.abc import AsyncIterator
from pathlib import Path

import pytest

BACKEND_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = BACKEND_ROOT.parent
sys.path.insert(0, str(BACKEND_ROOT))

_DB_PATH = BACKEND_ROOT / ".pytest-kavachx.db"

os.environ.update(
    {
        "KAVACHX_ENV": "test",
        "DEV_MODE": "true",
        "DATABASE_URL": f"sqlite+aiosqlite:///{_DB_PATH.as_posix()}",
        "LLM_PROVIDER": "mock",
        "SANDBOX_ADAPTER": "dev",
        "LOG_LEVEL": "WARNING",
        "LOG_FORMAT": "console",
        "JWT_SECRET": "test-secret-value-that-is-long-enough-for-hs256",
        "CERTIFICATE_SIGNING_KEY": "test-certificate-signing-key",
        "PUBLISHER_DRY_RUN": "true",
        "GITHUB_TOKEN": "",
        "GROQ_API_KEY": "",
        "MAX_PATCH_ITERATIONS": "3",
        "MAX_CLAUSE_ITERATIONS": "2",
        "SANDBOX_WALL_CLOCK_SECONDS": "90",
        "RUN_MAX_RUNTIME_SECONDS": "900",
    }
)

from datetime import timezone

import httpx

from app.auth.security import hash_password
from app.config import settings
from app.db.session import dispose_engine, get_engine, session_scope
from app.main import app
from app.models import Base
from app.models.enums import RepositoryProvider, Role
from app.models.identity import Organisation, OrganisationMember, User
from app.models.project import DEFAULT_FORBIDDEN_GLOBS, Policy, Project, Repository

DEMO_PASSWORD = "kavachx-test-password-1"


def pytest_sessionstart(session) -> None:
    """Create the schema once, synchronously, before any test runs.

    Deliberately not an async session-scoped fixture: pytest-asyncio binds its event loop per
    function, and a session-scoped async fixture would try to hold a loop across that boundary.
    """
    if _DB_PATH.exists():
        _DB_PATH.unlink()
    asyncio.run(_create_schema())


async def _create_schema() -> None:
    engine = get_engine()
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    await dispose_engine()


def pytest_sessionfinish(session, exitstatus) -> None:
    if _DB_PATH.exists():
        try:
            _DB_PATH.unlink()
        except OSError:
            pass


@pytest.fixture
async def client() -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as http:
        yield http


# ---------------------------------------------------------------------------
async def _make_tenant(
    slug: str, *, email: str, role: str = Role.OWNER.value, attach_repo: bool = True
) -> dict[str, str]:
    """Create an isolated organisation with one member and (optionally) the demo repository."""
    async with session_scope() as db:
        user = User(
            email=email,
            full_name=f"Test {role}",
            password_hash=hash_password(DEMO_PASSWORD),
        )
        db.add(user)
        await db.flush()

        organisation = Organisation(name=slug, slug=slug, created_by=user.id)
        db.add(organisation)
        await db.flush()

        db.add(
            OrganisationMember(
                tenant_id=organisation.id,
                organisation_id=organisation.id,
                user_id=user.id,
                role=role,
            )
        )
        db.add(
            Policy(
                tenant_id=organisation.id,
                name="default",
                forbidden_path_globs=list(DEFAULT_FORBIDDEN_GLOBS),
            )
        )

        project = Project(
            tenant_id=organisation.id,
            organisation_id=organisation.id,
            name=f"{slug} project",
            slug=f"{slug}-project",
            created_by=user.id,
        )
        db.add(project)
        await db.flush()

        repository_id = ""
        if attach_repo:
            from datetime import datetime

            repository = Repository(
                tenant_id=organisation.id,
                project_id=project.id,
                provider=RepositoryProvider.LOCAL_SEEDED.value,
                full_name="examples/vulnerable-demo",
                default_branch="main",
                local_path=str(settings.demo_repo_dir),
                authority_verified_at=datetime.now(timezone.utc),
                authority_evidence={"method": "local_seeded", "test": True},
            )
            db.add(repository)
            await db.flush()
            repository_id = str(repository.id)

        return {
            "user_id": str(user.id),
            "email": email,
            "organisation_id": str(organisation.id),
            "project_id": str(project.id),
            "repository_id": repository_id,
            "role": role,
        }


async def _login(client: httpx.AsyncClient, email: str) -> str:
    response = await client.post(
        "/api/auth/login", json={"email": email, "password": DEMO_PASSWORD}
    )
    assert response.status_code == 200, response.text
    return response.json()["access_token"]


@pytest.fixture
async def tenant_a(client: httpx.AsyncClient) -> dict[str, str]:
    suffix = uuid.uuid4().hex[:8]
    tenant = await _make_tenant(f"tenant-a-{suffix}", email=f"owner-a-{suffix}@kavachx.io")
    tenant["token"] = await _login(client, tenant["email"])
    return tenant


@pytest.fixture
async def tenant_b(client: httpx.AsyncClient) -> dict[str, str]:
    suffix = uuid.uuid4().hex[:8]
    tenant = await _make_tenant(f"tenant-b-{suffix}", email=f"owner-b-{suffix}@kavachx.io")
    tenant["token"] = await _login(client, tenant["email"])
    return tenant


@pytest.fixture
async def role_tokens(client: httpx.AsyncClient) -> dict[str, str]:
    """One authenticated token per role, all inside a single organisation."""
    suffix = uuid.uuid4().hex[:8]
    owner = await _make_tenant(f"roles-{suffix}", email=f"owner-{suffix}@kavachx.io")
    tokens = {Role.OWNER.value: await _login(client, owner["email"])}

    for role in (
        Role.MAINTAINER,
        Role.SECURITY_REVIEWER,
        Role.DEVELOPER,
        Role.VIEWER,
        Role.AUDITOR,
    ):
        email = f"{role.value.lower()}-{suffix}@kavachx.io"
        async with session_scope() as db:
            user = User(
                email=email, full_name=role.value, password_hash=hash_password(DEMO_PASSWORD)
            )
            db.add(user)
            await db.flush()
            db.add(
                OrganisationMember(
                    tenant_id=uuid.UUID(owner["organisation_id"]),
                    organisation_id=uuid.UUID(owner["organisation_id"]),
                    user_id=user.id,
                    role=role.value,
                )
            )
        tokens[role.value] = await _login(client, email)

    tokens["_organisation_id"] = owner["organisation_id"]
    tokens["_repository_id"] = owner["repository_id"]
    tokens["_project_id"] = owner["project_id"]
    return tokens


def auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def demo_repo_path() -> Path:
    path = settings.demo_repo_dir
    if not path.is_dir():
        pytest.skip(f"seeded demo target missing at {path}")
    return path
