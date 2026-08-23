"""The ``examples/`` tree, mirrored into the repository dropdown.

Why this exists. The run form lists *attached* repositories, and the seed only ever attached
``examples/vulnerable-demo`` — so every other demo target sat on disk, invisible, until someone
attached it by hand. Attachment now follows the filesystem instead: every project folder under
``examples/`` becomes a ``local_seeded`` repository on the demo project. Drop a new demo into
``examples/``, restart the API, and it is in the dropdown. No script, no curated list.

Where it runs. From the seed (fresh database) and from startup provisioning (an existing database
that has just pulled in new example folders — the seed itself is skipped there because the demo
tenant already exists). Both paths call the same function, so they cannot drift apart.

What it never does. It only ever *adds*. An example already attached is left exactly as it is, and
repositories attached by hand — a public GitHub repository, a token-verified private one — are
never touched or removed. The authority boundary is unchanged: a local target must live inside this
repository's ``examples/`` directory, and that is the whole allowlist.
"""

from __future__ import annotations

import uuid
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit.service import AuditService
from app.config import settings
from app.core.logging import get_logger
from app.db.session import session_scope
from app.models.audit import AuditAction
from app.models.enums import RepositoryProvider
from app.models.identity import Organisation
from app.models.project import Project, Repository

logger = get_logger(__name__)

#: Folder names under ``examples/`` that are build or tooling detritus rather than a demo target.
_SKIP_DIRS = frozenset(
    {"__pycache__", "node_modules", ".git", ".venv", "venv", "dist", "build", "target"}
)

#: Manifest → toolchain language, most specific first. Only a hint for display: the run pipeline
#: does its own detection (``app.analysis.framework.detect_run_plan``) against the pinned workspace.
_MANIFEST_LANGUAGES: tuple[tuple[str, str], ...] = (
    ("package.json", "node"),
    ("pyproject.toml", "python"),
    ("requirements.txt", "python"),
    ("go.mod", "go"),
    ("Cargo.toml", "rust"),
    ("pom.xml", "java"),
    ("build.gradle", "java"),
)

_EXTENSION_LANGUAGES = {
    ".py": "python",
    ".js": "node",
    ".mjs": "node",
    ".cjs": "node",
    ".ts": "node",
    ".c": "c",
    ".h": "c",
    ".go": "go",
    ".rs": "rust",
    ".java": "java",
    ".sol": "solidity",
}


def discover_example_dirs() -> list[Path]:
    """Every candidate target folder directly under ``examples/``, sorted by name.

    A folder qualifies when it is a non-hidden, non-cache directory with something in it. The test
    is deliberately permissive: what belongs in ``examples/`` is the repository's decision, not this
    function's, and a folder the operator can see on disk should be a folder they can select.
    """
    root = (settings.repo_root / "examples").resolve()
    if not root.is_dir():
        return []
    found: list[Path] = []
    for child in sorted(root.iterdir(), key=lambda p: p.name):
        if not child.is_dir() or child.name.startswith(".") or child.name in _SKIP_DIRS:
            continue
        if next(child.iterdir(), None) is None:
            continue  # an empty placeholder has nothing to analyse
        found.append(child)
    return found


def language_hint(path: Path) -> dict[str, object]:
    """Cheap top-of-tree language guess, for the repository card. Never walks the whole tree."""
    for manifest, language in _MANIFEST_LANGUAGES:
        if (path / manifest).is_file():
            return {"primary": language, "source": manifest}

    counts: Counter[str] = Counter()
    for folder in (path, path / "src"):
        if not folder.is_dir():
            continue
        for entry in folder.iterdir():
            language = _EXTENSION_LANGUAGES.get(entry.suffix.lower())
            if language and entry.is_file():
                counts[language] += 1
    if not counts:
        return {}
    return {"primary": counts.most_common(1)[0][0], "source": "file extensions"}


def _evidence(path: Path, examples_root: Path) -> dict[str, str]:
    return {
        "method": "local_seeded",
        "path": str(path),
        "examples_root": str(examples_root),
        "note": (
            "DEV_MODE local target discovered inside this repository's examples/ tree. Authority "
            "is granted only for targets inside examples/."
        ),
    }


async def attach_example_repositories(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    project_id: uuid.UUID,
    actor_user_id: uuid.UUID | None = None,
    actor_label: str = "system:provision",
) -> list[str]:
    """Attach every discovered example to ``project_id``. Returns the newly attached full names.

    Idempotent: an example whose ``examples/<name>`` is already on the project is skipped, so this
    is safe to call on every boot.
    """
    examples_root = (settings.repo_root / "examples").resolve()
    attached = set(
        (
            await db.scalars(
                select(Repository.full_name).where(Repository.project_id == project_id)
            )
        ).all()
    )

    audit = AuditService(db)
    added: list[str] = []
    for path in discover_example_dirs():
        full_name = f"examples/{path.name}"
        if full_name in attached:
            continue
        repository = Repository(
            tenant_id=tenant_id,
            project_id=project_id,
            provider=RepositoryProvider.LOCAL_SEEDED.value,
            full_name=full_name,
            default_branch="main",
            local_path=str(path),
            private=True,
            authority_verified_at=datetime.now(timezone.utc),
            authority_evidence=_evidence(path, examples_root),
            language_summary=language_hint(path),
        )
        db.add(repository)
        await db.flush()
        await audit.record(
            tenant_id=tenant_id,
            action=AuditAction.REPOSITORY_AUTHORITY_VERIFIED,
            actor_user_id=actor_user_id,
            actor_label=actor_label,
            subject_type="repository",
            subject_id=str(repository.id),
            detail={
                "full_name": full_name,
                "provider": repository.provider,
                "evidence": repository.authority_evidence,
            },
            note="discovered under examples/",
        )
        added.append(full_name)
    return added


async def _demo_project(db: AsyncSession) -> Project | None:
    """The project the example targets belong to.

    Preference order: the project that already holds a local target (so the examples stay together
    with the seeded demo, wherever the seed put it), then the seeded ``demo-target`` project, then
    the oldest project in the demo organisation. ``None`` means the database has not been seeded
    yet, in which case the seed itself does the attaching.
    """
    # Imported here, not at module scope: the seed imports this module, so a top-level import back
    # into it would be a cycle.
    from app.db.seed import slugify

    organisation_id = await db.scalar(
        select(Organisation.id).where(Organisation.slug == slugify(settings.demo_org_name))
    )
    if organisation_id is None:
        return None

    project_id = await db.scalar(
        select(Repository.project_id)
        .where(
            Repository.tenant_id == organisation_id,
            Repository.provider == RepositoryProvider.LOCAL_SEEDED.value,
        )
        .order_by(Repository.created_at.asc())
        .limit(1)
    )
    if project_id is not None:
        return await db.get(Project, project_id)

    seeded = select(Project).where(
        Project.organisation_id == organisation_id, Project.slug == "demo-target"
    )
    oldest = (
        select(Project)
        .where(Project.organisation_id == organisation_id)
        .order_by(Project.created_at.asc())
        .limit(1)
    )
    return await db.scalar(seeded) or await db.scalar(oldest)


async def ensure_example_repositories() -> list[str]:
    """Attach any ``examples/`` folder the demo project does not have yet. Returns what was added.

    This is the startup path: it runs on a database that was seeded long ago, which is exactly the
    case the seed cannot cover.
    """
    async with session_scope() as db:
        project = await _demo_project(db)
        if project is None:
            return []
        added = await attach_example_repositories(
            db, tenant_id=project.tenant_id, project_id=project.id
        )
    if added:
        logger.info("db.examples_attached", count=len(added), repositories=added)
    return added
