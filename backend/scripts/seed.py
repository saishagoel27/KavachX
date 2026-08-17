"""Seed the demo tenant.

Creates (idempotently):

* the demo user, organisation and OWNER membership,
* the default publish policy,
* a project,
* the seeded local vulnerable repository with authority recorded,
* one member per role, so RBAC behaviour is demonstrable in the UI without extra setup.

Run with ``python -m scripts.seed`` from ``backend/``, or via ``scripts/dev.ps1``.
"""

from __future__ import annotations

import asyncio
import re
import sys
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import func, select

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.audit.service import AuditService
from app.config import settings
from app.core.logging import configure_logging, get_logger
from app.db.session import session_scope
from app.models.audit import AuditAction
from app.models.enums import RepositoryProvider, Role
from app.models.identity import Organisation, OrganisationMember, User
from app.models.project import DEFAULT_FORBIDDEN_GLOBS, Policy, Project, Repository

configure_logging()
logger = get_logger(__name__)

ROLE_USERS = [
    (Role.MAINTAINER, "maintainer@kavachx.io"),
    (Role.SECURITY_REVIEWER, "reviewer@kavachx.io"),
    (Role.DEVELOPER, "developer@kavachx.io"),
    (Role.VIEWER, "viewer@kavachx.io"),
    (Role.AUDITOR, "auditor@kavachx.io"),
]


def slugify(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-") or "workspace"


async def seed() -> dict[str, object]:
    from app.auth.security import hash_password

    async with session_scope() as db:
        email = settings.demo_user_email.lower()
        user = await db.scalar(select(User).where(func.lower(User.email) == email))
        created_user = user is None
        if user is None:
            user = User(
                email=email,
                full_name="KavachX Demo",
                password_hash=hash_password(settings.demo_user_password),
            )
            db.add(user)
            await db.flush()

        slug = slugify(settings.demo_org_name)
        organisation = await db.scalar(select(Organisation).where(Organisation.slug == slug))
        created_org = organisation is None
        if organisation is None:
            organisation = Organisation(name=settings.demo_org_name, slug=slug, created_by=user.id)
            db.add(organisation)
            await db.flush()

        membership = await db.scalar(
            select(OrganisationMember).where(
                OrganisationMember.organisation_id == organisation.id,
                OrganisationMember.user_id == user.id,
            )
        )
        if membership is None:
            db.add(
                OrganisationMember(
                    tenant_id=organisation.id,
                    organisation_id=organisation.id,
                    user_id=user.id,
                    role=Role.OWNER.value,
                )
            )

        policy = await db.scalar(select(Policy).where(Policy.tenant_id == organisation.id))
        if policy is None:
            db.add(
                Policy(
                    tenant_id=organisation.id,
                    name="default",
                    forbidden_path_globs=list(DEFAULT_FORBIDDEN_GLOBS),
                )
            )

        # One account per role, so the RBAC asymmetries (who may see a working exploit, who may
        # publish) are visible in the UI immediately.
        for role, role_email in ROLE_USERS:
            role_user = await db.scalar(select(User).where(func.lower(User.email) == role_email))
            if role_user is None:
                role_user = User(
                    email=role_email,
                    full_name=f"Demo {role.value.title().replace('_', ' ')}",
                    password_hash=hash_password(settings.demo_user_password),
                )
                db.add(role_user)
                await db.flush()
            exists = await db.scalar(
                select(OrganisationMember).where(
                    OrganisationMember.organisation_id == organisation.id,
                    OrganisationMember.user_id == role_user.id,
                )
            )
            if exists is None:
                db.add(
                    OrganisationMember(
                        tenant_id=organisation.id,
                        organisation_id=organisation.id,
                        user_id=role_user.id,
                        role=role.value,
                    )
                )

        project = await db.scalar(
            select(Project).where(
                Project.organisation_id == organisation.id, Project.slug == "demo-target"
            )
        )
        if project is None:
            project = Project(
                tenant_id=organisation.id,
                organisation_id=organisation.id,
                name="Demo Target",
                slug="demo-target",
                description=(
                    "The seeded vulnerable reportsvc target that ships with KavachX. Fully local."
                ),
                created_by=user.id,
            )
            db.add(project)
            await db.flush()

        demo_path = settings.demo_repo_dir
        repository = await db.scalar(
            select(Repository).where(
                Repository.project_id == project.id,
                Repository.full_name == "examples/vulnerable-demo",
            )
        )
        if repository is None:
            if not demo_path.is_dir():
                raise SystemExit(
                    f"The seeded demo target is missing at {demo_path}. "
                    "Check DEMO_REPO_PATH or restore examples/vulnerable-demo."
                )
            repository = Repository(
                tenant_id=organisation.id,
                project_id=project.id,
                provider=RepositoryProvider.LOCAL_SEEDED.value,
                full_name="examples/vulnerable-demo",
                default_branch="main",
                local_path=str(demo_path),
                private=True,
                authority_verified_at=datetime.now(UTC),
                authority_evidence={
                    "method": "local_seeded",
                    "path": str(demo_path),
                    "note": (
                        "DEV_MODE seeded target inside this repository's examples/ tree. This is "
                        "the only local path KavachX will analyse without a GitHub App "
                        "installation."
                    ),
                },
                language_summary={"python": True},
            )
            db.add(repository)
            await db.flush()

        audit = AuditService(db)
        await audit.record(
            tenant_id=organisation.id,
            action=AuditAction.ORG_CREATED if created_org else AuditAction.PROJECT_CREATED,
            actor_user_id=user.id,
            actor_label=user.email,
            subject_type="seed",
            subject_id=str(organisation.id),
            detail={
                "seeded": True,
                "created_user": created_user,
                "created_org": created_org,
                "repository": repository.full_name,
            },
            note="seed script",
        )

        return {
            "user_email": user.email,
            "password": settings.demo_user_password,
            "organisation_id": str(organisation.id),
            "organisation_slug": organisation.slug,
            "project_id": str(project.id),
            "repository_id": str(repository.id),
            "repository_path": repository.local_path,
            "role_accounts": [email for _role, email in ROLE_USERS],
        }


async def main() -> None:
    result = await seed()
    print("")
    print("  KavachX demo tenant ready")
    print("  " + "-" * 52)
    print(f"  email        {result['user_email']}")
    print(f"  password     {result['password']}")
    print(f"  organisation {result['organisation_slug']} ({result['organisation_id']})")
    print(f"  project      {result['project_id']}")
    print(f"  repository   {result['repository_id']}")
    print(f"  target path  {result['repository_path']}")
    print("")
    print("  Additional role accounts (same password):")
    for email in result["role_accounts"]:  # type: ignore[union-attr]
        print(f"    - {email}")
    print("")


if __name__ == "__main__":
    asyncio.run(main())
