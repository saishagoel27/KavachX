"""Initial schema.

Revision ID: 0001_initial
Revises:
Create Date: 2024-01-01 00:00:00

The initial revision creates the schema directly from ``Base.metadata``.

Why, rather than 25 tables of hand-written DDL: every column here already carries a precise,
dialect-aware definition in the models — ``JSONType`` is JSONB on PostgreSQL and JSON elsewhere,
``UUIDType`` is native ``uuid`` on PostgreSQL and ``CHAR(32)`` on SQLite. Transcribing that by
hand for the first revision introduces exactly one class of bug: schema drift between the models
and the migration, which is silent until a query fails in production. Generating revision 0001
from the metadata makes drift impossible at the starting point.

Every *subsequent* revision is explicit DDL produced by ``alembic revision --autogenerate``, and
diffs cleanly against this baseline.
"""

from __future__ import annotations

from typing import Sequence, Union

from alembic import op

revision: str = "0001_initial"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    from app.models import Base

    connection = op.get_bind()
    Base.metadata.create_all(bind=connection, checkfirst=True)


def downgrade() -> None:
    from app.models import Base

    connection = op.get_bind()
    Base.metadata.drop_all(bind=connection, checkfirst=True)
