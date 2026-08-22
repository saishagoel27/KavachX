"""Declarative base, portable column types and shared mixins."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import DateTime, MetaData, String, Uuid, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy.types import JSON, Text

NAMING_CONVENTION = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}

#: JSONB on PostgreSQL, plain JSON elsewhere (the SQLite path used by the test suite).
JSONType = JSON().with_variant(JSONB(), "postgresql")

#: Portable UUID: native ``uuid`` on PostgreSQL, ``CHAR(32)`` on SQLite.
UUIDType = Uuid(as_uuid=True)


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def new_uuid() -> uuid.UUID:
    return uuid.uuid4()


class Base(DeclarativeBase):
    metadata = MetaData(naming_convention=NAMING_CONVENTION)

    type_annotation_map = {
        dict[str, Any]: JSONType,
        list[Any]: JSONType,
        str: String(255),
    }

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        pk = getattr(self, "id", None)
        return f"<{type(self).__name__} id={pk}>"


class UUIDPrimaryKeyMixin:
    id: Mapped[uuid.UUID] = mapped_column(
        UUIDType, primary_key=True, default=new_uuid, sort_order=-100
    )


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
        onupdate=utcnow,
        server_default=func.now(),
    )


class TenantMixin:
    """Every tenant-owned row carries ``tenant_id``.

    ``tenant_id`` is the owning organisation's id. It is duplicated onto child rows on
    purpose: it lets PostgreSQL row-level security policies and the repository layer filter
    without a join, so a missing join can never leak across tenants.
    """

    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUIDType, nullable=False, index=True, sort_order=-99
    )


LongText = Text
