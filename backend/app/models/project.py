"""Projects, authorised repositories and publish policies."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import Boolean, DateTime, ForeignKey, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, JSONType, TimestampMixin, UUIDPrimaryKeyMixin, UUIDType
from app.models.enums import RepositoryProvider

if TYPE_CHECKING:
    from app.models.identity import Organisation
    from app.models.run import Run


class Project(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "projects"
    __table_args__ = (UniqueConstraint("organisation_id", "slug", name="uq_project_slug"),)

    tenant_id: Mapped[uuid.UUID] = mapped_column(UUIDType, nullable=False, index=True)
    organisation_id: Mapped[uuid.UUID] = mapped_column(
        UUIDType, ForeignKey("organisations.id", ondelete="CASCADE"), nullable=False
    )
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    slug: Mapped[str] = mapped_column(String(120), nullable=False)
    description: Mapped[str] = mapped_column(String(1000), nullable=False, default="")
    created_by: Mapped[uuid.UUID | None] = mapped_column(
        UUIDType, ForeignKey("users.id", ondelete="SET NULL")
    )

    organisation: Mapped[Organisation] = relationship(back_populates="projects")
    repositories: Mapped[list[Repository]] = relationship(
        back_populates="project", cascade="all, delete-orphan", lazy="selectin"
    )
    runs: Mapped[list[Run]] = relationship(back_populates="project", cascade="all, delete-orphan")


class Repository(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """A repository this tenant has proven authority over.

    ``authority_verified_at`` is set only after the configured fine-grained token is confirmed to
    have push access to this repository (or, in ``DEV_MODE``, after the local seeded path is
    confirmed to live inside the repository's own ``examples/`` tree). ``run:start`` refuses to
    touch a repository without it.
    """

    __tablename__ = "repositories"
    __table_args__ = (UniqueConstraint("project_id", "full_name", name="uq_repo_full_name"),)

    tenant_id: Mapped[uuid.UUID] = mapped_column(UUIDType, nullable=False, index=True)
    project_id: Mapped[uuid.UUID] = mapped_column(
        UUIDType, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False
    )
    provider: Mapped[str] = mapped_column(
        String(32), nullable=False, default=RepositoryProvider.LOCAL_SEEDED.value
    )
    full_name: Mapped[str] = mapped_column(String(400), nullable=False)
    default_branch: Mapped[str] = mapped_column(String(200), nullable=False, default="main")
    clone_url: Mapped[str] = mapped_column(String(600), nullable=False, default="")
    #: Only populated for ``local_seeded`` repositories in DEV_MODE.
    local_path: Mapped[str] = mapped_column(String(1000), nullable=False, default="")
    github_repo_id: Mapped[int | None] = mapped_column()
    installation_id: Mapped[int | None] = mapped_column(index=True)
    private: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    authority_verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    authority_evidence: Mapped[dict[str, Any]] = mapped_column(
        JSONType, nullable=False, default=dict
    )
    language_summary: Mapped[dict[str, Any]] = mapped_column(JSONType, nullable=False, default=dict)

    project: Mapped[Project] = relationship(back_populates="repositories")

    @property
    def authority_verified(self) -> bool:
        return self.authority_verified_at is not None


class Policy(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """Tenant-level publish policy. Deterministic gate input — never model-controlled."""

    __tablename__ = "policies"
    __table_args__ = (UniqueConstraint("tenant_id", "name", name="uq_policy_name"),)

    tenant_id: Mapped[uuid.UUID] = mapped_column(UUIDType, nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(120), nullable=False, default="default")
    forbidden_path_globs: Mapped[list[Any]] = mapped_column(JSONType, nullable=False, default=list)
    max_diff_lines: Mapped[int] = mapped_column(nullable=False, default=200)
    max_files_changed: Mapped[int] = mapped_column(nullable=False, default=5)
    allow_new_dependencies: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    allow_new_network_calls: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    allow_new_exec: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    allow_binary_changes: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    require_certificate: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    min_assurance_level: Mapped[str] = mapped_column(String(2), nullable=False, default="C")
    require_human_approval: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    enforce_blast_radius: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    updated_by: Mapped[uuid.UUID | None] = mapped_column(
        UUIDType, ForeignKey("users.id", ondelete="SET NULL")
    )


DEFAULT_FORBIDDEN_GLOBS: list[str] = [
    ".github/**",
    ".github/*",
    "**/Dockerfile",
    "Dockerfile*",
    "**/Dockerfile*",
    "**/*.yml",
    "**/*.yaml",
    ".git*",
    ".gitignore",
    ".gitattributes",
    "**/package-lock.json",
    "**/yarn.lock",
    "**/pnpm-lock.yaml",
    "**/poetry.lock",
    "**/uv.lock",
    "**/Cargo.lock",
    "**/requirements*.txt",
    "**/pyproject.toml",
    "**/package.json",
    "**/go.sum",
    "**/Gemfile.lock",
    "Makefile",
    "**/Makefile",
    "**/*.pem",
    "**/*.key",
]
