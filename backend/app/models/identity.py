"""Users, organisations, memberships and GitHub App installations."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, JSONType, TimestampMixin, UUIDPrimaryKeyMixin, UUIDType
from app.models.enums import Role

if TYPE_CHECKING:
    from app.models.project import Project


class User(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "users"

    email: Mapped[str] = mapped_column(String(320), unique=True, nullable=False, index=True)
    full_name: Mapped[str] = mapped_column(String(200), nullable=False, default="")
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    is_superuser: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    #: Monotonic counter bumped on password change / forced logout. Refresh tokens carry
    #: the value they were minted with, so a bump invalidates every outstanding token.
    token_version: Mapped[int] = mapped_column(nullable=False, default=0)

    memberships: Mapped[list[OrganisationMember]] = relationship(
        back_populates="user", cascade="all, delete-orphan", lazy="selectin"
    )


class Organisation(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """An organisation *is* a tenant. ``Organisation.id`` is the ``tenant_id`` everywhere."""

    __tablename__ = "organisations"

    name: Mapped[str] = mapped_column(String(200), nullable=False)
    slug: Mapped[str] = mapped_column(String(120), unique=True, nullable=False, index=True)
    created_by: Mapped[uuid.UUID | None] = mapped_column(
        UUIDType, ForeignKey("users.id", ondelete="SET NULL")
    )
    settings_json: Mapped[dict[str, Any]] = mapped_column(JSONType, nullable=False, default=dict)

    members: Mapped[list[OrganisationMember]] = relationship(
        back_populates="organisation", cascade="all, delete-orphan"
    )
    projects: Mapped[list[Project]] = relationship(
        back_populates="organisation", cascade="all, delete-orphan"
    )

    @property
    def tenant_id(self) -> uuid.UUID:
        return self.id


class OrganisationMember(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "organisation_members"
    __table_args__ = (
        UniqueConstraint("organisation_id", "user_id", name="uq_org_member"),
        Index("ix_org_members_tenant", "tenant_id"),
    )

    tenant_id: Mapped[uuid.UUID] = mapped_column(UUIDType, nullable=False, index=True)
    organisation_id: Mapped[uuid.UUID] = mapped_column(
        UUIDType, ForeignKey("organisations.id", ondelete="CASCADE"), nullable=False
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUIDType, ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    role: Mapped[str] = mapped_column(String(32), nullable=False, default=Role.VIEWER.value)

    organisation: Mapped[Organisation] = relationship(back_populates="members")
    user: Mapped[User] = relationship(back_populates="memberships")


class GithubInstallation(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """A verified GitHub App installation.

    Deliberately absent from this table: any installation access token. Tokens are minted
    on demand inside the publisher and discarded. Only the *installation id* — which is not
    a credential — is stored.
    """

    __tablename__ = "github_installations"
    __table_args__ = (
        UniqueConstraint("tenant_id", "installation_id", name="uq_gh_install_tenant"),
    )

    tenant_id: Mapped[uuid.UUID] = mapped_column(UUIDType, nullable=False, index=True)
    installation_id: Mapped[int] = mapped_column(nullable=False, index=True)
    account_login: Mapped[str] = mapped_column(String(200), nullable=False)
    account_type: Mapped[str] = mapped_column(String(40), nullable=False, default="Organization")
    target_id: Mapped[int | None] = mapped_column()
    permissions_json: Mapped[dict[str, Any]] = mapped_column(JSONType, nullable=False, default=dict)
    repository_selection: Mapped[str] = mapped_column(
        String(40), nullable=False, default="selected"
    )
    suspended: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    installed_by: Mapped[uuid.UUID | None] = mapped_column(
        UUIDType, ForeignKey("users.id", ondelete="SET NULL")
    )
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
