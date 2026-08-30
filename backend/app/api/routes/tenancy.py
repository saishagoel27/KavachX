"""Projects, repositories, GitHub connection, members and policy."""

from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Request
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import client_ip, ensure_policy, get_audit, load_project
from app.audit.service import AuditService
from app.auth.deps import Permission, Principal, RequirePermission, get_current_principal
from app.auth.rbac import ROLE_DESCRIPTIONS
from app.auth.security import hash_password
from app.config import settings
from app.core.errors import (
    BadRequest,
    Conflict,
    GithubNotConfigured,
    NotFound,
    RepositoryNotAuthorised,
)
from app.db.session import get_db
from app.models.audit import AuditAction
from app.models.enums import RepositoryProvider, Role
from app.models.identity import OrganisationMember, User
from app.models.project import Project, Repository
from app.models.run import Run
from app.schemas.core import (
    MemberInvite,
    MemberOut,
    PolicyOut,
    PolicyUpdate,
    ProjectCreate,
    ProjectOut,
    PublicRepoPreview,
    RepositoryAttach,
    RepositoryOut,
    RoleUpdate,
)

router = APIRouter(tags=["workspace"])


def slugify(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return slug or f"project-{uuid.uuid4().hex[:6]}"


# ---------------------------------------------------------------------------
# projects
# ---------------------------------------------------------------------------
@router.post("/projects", response_model=ProjectOut, status_code=201)
async def create_project(
    payload: ProjectCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    principal: Principal = Depends(RequirePermission(Permission.PROJECT_MANAGE)),
    audit: AuditService = Depends(get_audit),
) -> ProjectOut:
    slug = slugify(payload.name)
    exists = await db.scalar(
        select(Project.id).where(
            Project.organisation_id == principal.tenant_id, Project.slug == slug
        )
    )
    if exists is not None:
        raise Conflict(f"A project with slug {slug!r} already exists.", code="PROJECT_EXISTS")

    project = Project(
        tenant_id=principal.tenant_id,
        organisation_id=principal.tenant_id,
        name=payload.name,
        slug=slug,
        description=payload.description,
        created_by=principal.user_id,
    )
    db.add(project)
    await db.flush()
    await audit.record(
        tenant_id=principal.tenant_id,
        action=AuditAction.PROJECT_CREATED,
        actor_user_id=principal.user_id,
        actor_label=principal.label,
        subject_type="project",
        subject_id=str(project.id),
        source_ip=client_ip(request),
        detail={"name": project.name, "slug": project.slug},
    )
    return ProjectOut.model_validate(project)


@router.get("/projects", response_model=list[ProjectOut])
async def list_projects(
    db: AsyncSession = Depends(get_db),
    principal: Principal = Depends(get_current_principal),
) -> list[ProjectOut]:
    projects = list(
        (
            await db.scalars(
                select(Project)
                .where(Project.tenant_id == principal.tenant_id)
                .order_by(Project.created_at.desc())
            )
        ).all()
    )
    out: list[ProjectOut] = []
    for project in projects:
        repository_count = int(
            await db.scalar(
                select(func.count())
                .select_from(Repository)
                .where(Repository.project_id == project.id)
            )
            or 0
        )
        run_count = int(
            await db.scalar(
                select(func.count()).select_from(Run).where(Run.project_id == project.id)
            )
            or 0
        )
        model = ProjectOut.model_validate(project)
        model.repository_count = repository_count
        model.run_count = run_count
        out.append(model)
    return out


@router.get("/projects/{project_id}", response_model=ProjectOut)
async def get_project(project: Project = Depends(load_project)) -> ProjectOut:
    return ProjectOut.model_validate(project)


# ---------------------------------------------------------------------------
# repositories
# ---------------------------------------------------------------------------
@router.post("/projects/{project_id}/repositories", response_model=RepositoryOut, status_code=201)
async def attach_repository(
    payload: RepositoryAttach,
    request: Request,
    project: Project = Depends(load_project),
    db: AsyncSession = Depends(get_db),
    principal: Principal = Depends(RequirePermission(Permission.REPOSITORY_MANAGE)),
    audit: AuditService = Depends(get_audit),
) -> RepositoryOut:
    """Attach a repository, verifying authority before it can ever be analysed.

    Three authority paths and no others, in descending capability:

    * **GitHub repository (fine-grained token)** — the configured token must actually have push
      access. The check calls GitHub; a repository the caller merely named, or one the token can
      only read, is rejected. This is the only path that can later publish a pull request.
    * **Public GitHub repository** — publicly readable source, ingested unauthenticated for
      analysis only. Deliberately not publishable: there is no write credential behind it, so the
      Publisher can never act on it.
    * **Local seeded target** (``DEV_MODE`` only) — the path must resolve inside this
      repository's own ``examples/`` tree. That is the whole allowlist: KavachX will not analyse
      an arbitrary local directory even in development.
    """
    if payload.public:
        # A public repository is ingested read-only. It is deliberately NOT publishable: there is
        # no write credential behind it, so the Publisher can never act on it. Reading published
        # source and executing it in a sandbox is ordinary security research; opening a pull
        # request against a repository you do not control is not.
        if not payload.authorisation_confirmed:
            raise BadRequest(
                "Confirm that you are authorised to analyse this repository before attaching it.",
                code="AUTHORISATION_NOT_CONFIRMED",
            )

        from app.github.public_ingest import (
            parse_repo_reference,
            resolve_commit,
            resolve_repository,
        )

        ref = parse_repo_reference(payload.full_name)
        info = await resolve_repository(ref)
        commit = await resolve_commit(ref, payload.default_branch or info.default_branch)

        existing = await db.scalar(
            select(Repository).where(
                Repository.project_id == project.id, Repository.full_name == info.full_name
            )
        )
        if existing is not None:
            return RepositoryOut.model_validate(existing)

        repository = Repository(
            tenant_id=principal.tenant_id,
            project_id=project.id,
            provider=RepositoryProvider.GITHUB_PUBLIC.value,
            full_name=info.full_name,
            default_branch=info.default_branch,
            clone_url=f"https://github.com/{info.full_name}.git",
            github_repo_id=info.repo_id,
            installation_id=None,
            private=False,
            authority_verified_at=datetime.now(timezone.utc),
            authority_evidence={
                **info.as_evidence(),
                "head_commit": commit,
                "attested_by": principal.label,
                "publishable": False,
                "publish_blocked_reason": (
                    "Public repositories are analysis-only. Publishing requires a fine-grained "
                    "token with push access to the repository."
                ),
            },
            language_summary={
                "primary": info.language,
                "languages": info.languages,
                "size_kb": info.size_kb,
            },
        )
        db.add(repository)
        await db.flush()
        await audit.record(
            tenant_id=principal.tenant_id,
            action=AuditAction.REPOSITORY_AUTHORITY_VERIFIED,
            actor_user_id=principal.user_id,
            actor_label=principal.label,
            subject_type="repository",
            subject_id=str(repository.id),
            source_ip=client_ip(request),
            detail={
                "full_name": repository.full_name,
                "provider": repository.provider,
                "authorisation_confirmed": True,
                "head_sha": commit.get("sha", ""),
                "publishable": False,
            },
        )
        return RepositoryOut.model_validate(repository)

    if payload.local_seeded:
        if not settings.dev_mode:
            raise BadRequest(
                "Local seeded targets are only permitted in DEV_MODE.",
                code="LOCAL_TARGET_FORBIDDEN",
            )
        examples_root = (settings.repo_root / "examples").resolve()
        # Resolve which example directory to attach from the requested name, defaulting to the seeded
        # demo. Any folder under examples/ is allowed — not just vulnerable-demo — so the web/node/
        # fuzz demos can be attached too. A bare name is treated as examples/<name>.
        requested = (payload.full_name or "examples/vulnerable-demo").strip().strip("/\\")
        if requested != "examples" and not requested.startswith("examples/"):
            requested = f"examples/{requested}"
        target = (settings.repo_root / requested).resolve()
        # The allowlist is the examples/ tree: a resolved path outside it (including via `..`) is
        # refused. This is the whole authority boundary for local targets.
        if examples_root != target and examples_root not in target.parents:
            raise RepositoryNotAuthorised(
                "A local target must live inside this repository's examples/ directory.",
            )
        if not target.is_dir():
            raise BadRequest(
                f"The local target does not exist at {target}.", code="DEMO_TARGET_MISSING"
            )
        # Attaching is idempotent, as it is for a public repository: the examples are attached
        # automatically at startup, so a second attach of the same folder must return the existing
        # row rather than adding a duplicate to the dropdown.
        existing = await db.scalar(
            select(Repository).where(
                Repository.project_id == project.id, Repository.full_name == requested
            )
        )
        if existing is not None:
            return RepositoryOut.model_validate(existing)
        evidence = {
            "method": "local_seeded",
            "path": str(target),
            "examples_root": str(examples_root),
            "note": (
                "DEV_MODE local target. Authority is granted only for targets inside examples/."
            ),
        }
        repository = Repository(
            tenant_id=principal.tenant_id,
            project_id=project.id,
            provider=RepositoryProvider.LOCAL_SEEDED.value,
            full_name=requested,
            default_branch=payload.default_branch or "main",
            local_path=str(target),
            private=True,
            authority_verified_at=datetime.now(timezone.utc),
            authority_evidence=evidence,
        )
    else:
        if not settings.github_configured:
            raise GithubNotConfigured()

        from app.github.app_client import GithubClient

        # Authority is confirmed against the API: the configured fine-grained token must actually
        # have push access to the repository. The user's claim is never taken at face value.
        verdict = await GithubClient().verify_repository_authority(payload.full_name)
        if not verdict["authorised"]:
            await audit.record(
                tenant_id=principal.tenant_id,
                action=AuditAction.REPOSITORY_AUTHORITY_REJECTED,
                actor_user_id=principal.user_id,
                actor_label=principal.label,
                subject_type="repository",
                subject_id=payload.full_name,
                source_ip=client_ip(request),
                detail={"reason": verdict["reason"]},
            )
            raise RepositoryNotAuthorised(verdict["reason"])

        info = verdict["repository"]
        repository = Repository(
            tenant_id=principal.tenant_id,
            project_id=project.id,
            provider=RepositoryProvider.GITHUB.value,
            full_name=str(info["full_name"]),
            default_branch=str(info.get("default_branch") or payload.default_branch or "main"),
            clone_url=f"https://github.com/{info['full_name']}.git",
            github_repo_id=info.get("id"),
            installation_id=None,
            private=bool(info.get("private", True)),
            authority_verified_at=datetime.now(timezone.utc),
            authority_evidence={
                "method": "github_fine_grained_token",
                "reason": verdict["reason"],
                "permissions": info.get("permissions", {}),
            },
        )

    db.add(repository)
    await db.flush()
    await audit.record(
        tenant_id=principal.tenant_id,
        action=AuditAction.REPOSITORY_AUTHORITY_VERIFIED,
        actor_user_id=principal.user_id,
        actor_label=principal.label,
        subject_type="repository",
        subject_id=str(repository.id),
        source_ip=client_ip(request),
        detail={
            "full_name": repository.full_name,
            "provider": repository.provider,
            "evidence": repository.authority_evidence,
        },
    )
    return RepositoryOut.model_validate(repository)


@router.get("/github/public/preview", response_model=PublicRepoPreview)
async def preview_public_repository(
    repo: str,
    revision: str = "",
    principal: Principal = Depends(RequirePermission(Permission.REPOSITORY_MANAGE)),
) -> PublicRepoPreview:
    """Resolve a public repository without attaching it.

    Lets the console show what it is about to ingest — language mix, size, licence, resolved HEAD —
    before anyone commits to a run. Unauthenticated; no credential is involved.
    """
    from app.github.public_ingest import (
        parse_repo_reference,
        resolve_commit,
        resolve_repository,
    )

    ref = parse_repo_reference(repo)
    info = await resolve_repository(ref)
    commit = await resolve_commit(ref, revision or info.default_branch)

    notes: list[str] = [
        "Analysis only — KavachX holds no credential for this repository and cannot publish to it.",
    ]
    if info.archived:
        notes.append("This repository is archived; a fix cannot be contributed upstream.")
    if info.fork:
        notes.append("This is a fork. Findings may already be fixed upstream.")
    if not info.languages:
        notes.append("GitHub reports no recognised language, so indexing may find little.")
    elif not any(
        language in info.languages
        for language in ("Python", "C", "C++", "JavaScript", "TypeScript")
    ):
        notes.append(
            "The static rule packs cover Python, C and JavaScript/TypeScript. Other languages are "
            "indexed but have thinner rule coverage."
        )

    return PublicRepoPreview(
        full_name=info.full_name,
        default_branch=info.default_branch,
        description=info.description,
        primary_language=info.language,
        languages=info.languages,
        size_kb=info.size_kb,
        stars=info.stars,
        archived=info.archived,
        fork=info.fork,
        html_url=info.html_url,
        head_commit=commit,
        publishable=False,
        notes=notes,
    )


@router.get("/repositories", response_model=list[RepositoryOut])
async def list_repositories(
    project_id: uuid.UUID | None = None,
    db: AsyncSession = Depends(get_db),
    principal: Principal = Depends(get_current_principal),
) -> list[RepositoryOut]:
    stmt = select(Repository).where(Repository.tenant_id == principal.tenant_id)
    if project_id is not None:
        stmt = stmt.where(Repository.project_id == project_id)
    rows = list((await db.scalars(stmt.order_by(Repository.created_at.desc()))).all())
    return [RepositoryOut.model_validate(r) for r in rows]


# ---------------------------------------------------------------------------
# GitHub connection
# ---------------------------------------------------------------------------
@router.get("/github/app")
async def github_info() -> dict[str, object]:
    return {
        "configured": settings.github_configured,
        "auth": "fine_grained_token",
        "publisher_dry_run": settings.publisher_dry_run,
        "dev_mode_local_target_available": settings.dev_mode and settings.demo_repo_dir.is_dir(),
        "notes": (
            "KavachX authenticates with a fine-grained personal access token (GITHUB_TOKEN) that "
            "needs Contents: read/write and Pull requests: read/write on the target repository. "
            "The token is never written to the database, and push authority is confirmed against "
            "the API before the repository is attached. The same token clones the source at "
            "ingest and opens the pull request at publish; neither is reachable from the sandbox."
        ),
    }


# ---------------------------------------------------------------------------
# members
# ---------------------------------------------------------------------------
@router.get("/members", response_model=list[MemberOut])
async def list_members(
    db: AsyncSession = Depends(get_db),
    principal: Principal = Depends(get_current_principal),
) -> list[MemberOut]:
    rows = (
        await db.execute(
            select(OrganisationMember, User)
            .join(User, User.id == OrganisationMember.user_id)
            .where(OrganisationMember.organisation_id == principal.tenant_id)
            .order_by(OrganisationMember.created_at.asc())
        )
    ).all()
    return [
        MemberOut(
            user_id=user.id,
            email=user.email,
            full_name=user.full_name,
            role=member.role,
            created_at=member.created_at,
        )
        for member, user in rows
    ]


@router.post("/members", response_model=MemberOut, status_code=201)
async def invite_member(
    payload: MemberInvite,
    request: Request,
    db: AsyncSession = Depends(get_db),
    principal: Principal = Depends(RequirePermission(Permission.MEMBER_MANAGE)),
    audit: AuditService = Depends(get_audit),
) -> MemberOut:
    user = await db.scalar(select(User).where(func.lower(User.email) == payload.email.lower()))
    if user is None:
        if not payload.password:
            raise BadRequest(
                "That email has no account yet. Supply an initial password to create one.",
                code="PASSWORD_REQUIRED",
            )
        user = User(
            email=payload.email.lower(),
            full_name="",
            password_hash=hash_password(payload.password),
        )
        db.add(user)
        await db.flush()

    existing = await db.scalar(
        select(OrganisationMember).where(
            OrganisationMember.organisation_id == principal.tenant_id,
            OrganisationMember.user_id == user.id,
        )
    )
    if existing is not None:
        raise Conflict("That user is already a member.", code="ALREADY_MEMBER")

    member = OrganisationMember(
        tenant_id=principal.tenant_id,
        organisation_id=principal.tenant_id,
        user_id=user.id,
        role=payload.role.value,
    )
    db.add(member)
    await db.flush()
    await audit.record(
        tenant_id=principal.tenant_id,
        action=AuditAction.MEMBER_INVITED,
        actor_user_id=principal.user_id,
        actor_label=principal.label,
        subject_type="user",
        subject_id=str(user.id),
        source_ip=client_ip(request),
        detail={"email": user.email, "role": member.role},
    )
    return MemberOut(
        user_id=user.id,
        email=user.email,
        full_name=user.full_name,
        role=member.role,
        created_at=member.created_at,
    )


@router.patch("/members/{user_id}", response_model=MemberOut)
async def update_member_role(
    user_id: uuid.UUID,
    payload: RoleUpdate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    principal: Principal = Depends(RequirePermission(Permission.MEMBER_MANAGE)),
    audit: AuditService = Depends(get_audit),
) -> MemberOut:
    member = await db.scalar(
        select(OrganisationMember).where(
            OrganisationMember.organisation_id == principal.tenant_id,
            OrganisationMember.user_id == user_id,
        )
    )
    if member is None:
        raise NotFound("That user is not a member of this organisation.")

    if member.role == Role.OWNER.value and payload.role != Role.OWNER:
        owners = int(
            await db.scalar(
                select(func.count())
                .select_from(OrganisationMember)
                .where(
                    OrganisationMember.organisation_id == principal.tenant_id,
                    OrganisationMember.role == Role.OWNER.value,
                )
            )
            or 0
        )
        if owners <= 1:
            raise Conflict("An organisation must retain at least one OWNER.", code="LAST_OWNER")

    previous = member.role
    member.role = payload.role.value
    user = await db.get(User, user_id)
    await audit.record(
        tenant_id=principal.tenant_id,
        action=AuditAction.MEMBER_ROLE_CHANGED,
        actor_user_id=principal.user_id,
        actor_label=principal.label,
        subject_type="user",
        subject_id=str(user_id),
        source_ip=client_ip(request),
        detail={"from": previous, "to": member.role},
    )
    return MemberOut(
        user_id=user_id,
        email=user.email if user else "",
        full_name=user.full_name if user else "",
        role=member.role,
        created_at=member.created_at,
    )


@router.get("/roles")
async def list_roles() -> dict[str, object]:
    from app.auth.rbac import ROLE_PERMISSIONS

    return {
        "roles": [
            {
                "role": role,
                "description": ROLE_DESCRIPTIONS.get(role, ""),
                "permissions": sorted(permissions),
            }
            for role, permissions in ROLE_PERMISSIONS.items()
        ]
    }


# ---------------------------------------------------------------------------
# policy
# ---------------------------------------------------------------------------
@router.get("/policy", response_model=PolicyOut)
async def get_policy_route(
    db: AsyncSession = Depends(get_db),
    principal: Principal = Depends(get_current_principal),
) -> PolicyOut:
    policy = await ensure_policy(db, principal.tenant_id)
    return PolicyOut.model_validate(policy)


@router.patch("/policy", response_model=PolicyOut)
async def update_policy(
    payload: PolicyUpdate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    principal: Principal = Depends(RequirePermission(Permission.POLICY_MANAGE)),
    audit: AuditService = Depends(get_audit),
) -> PolicyOut:
    policy = await ensure_policy(db, principal.tenant_id)
    changes: dict[str, object] = {}
    for field, value in payload.model_dump(exclude_unset=True).items():
        if value is None:
            continue
        previous = getattr(policy, field, None)
        if previous != value:
            changes[field] = {"from": previous, "to": value}
            setattr(policy, field, value)
    policy.updated_by = principal.user_id
    await db.flush()

    if changes:
        await audit.record(
            tenant_id=principal.tenant_id,
            action=AuditAction.POLICY_CHANGED,
            actor_user_id=principal.user_id,
            actor_label=principal.label,
            subject_type="policy",
            subject_id=str(policy.id),
            source_ip=client_ip(request),
            detail={"changes": changes},
        )
    return PolicyOut.model_validate(policy)
