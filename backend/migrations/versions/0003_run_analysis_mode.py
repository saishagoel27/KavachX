"""Record the analysis mode on the run row.

Revision ID: 0003_run_mode
Revises: 0002_rls
Create Date: 2024-01-01 00:00:02

``runs.mode`` and ``runs.static_only_reason`` were previously carried only in the LangGraph
checkpoint and the live event stream. That was enough for an operator watching a run and not enough
for anyone reading it afterwards: a static-only run executed nothing, so its zero validated findings
mean "nothing was proved", not "nothing is wrong". Without the qualifier on the row, a completed
static-only run is indistinguishable from a clean sweep in the runs table.

**Why the existence checks.** Revision 0001 builds the schema from ``Base.metadata``, so a database
created today already has these columns before this revision runs, while a database stamped at 0001
or 0002 earlier does not. Both must upgrade cleanly, so each column is added only if absent. This is
the one place where the metadata-generated baseline costs something, and an idempotent ALTER is a
cheaper price than hand-transcribing 25 tables of DDL.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0003_run_mode"
down_revision: Union[str, None] = "0002_rls"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


#: Built fresh per call: a Column instance binds to the table it is added to, so the same object
#: cannot be reused across two ``add_column`` calls (and ``Column.copy()`` is deprecated in 2.x).
def _columns() -> list[sa.Column]:
    return [
        sa.Column("mode", sa.String(length=20), nullable=False, server_default="full"),
        sa.Column("static_only_reason", sa.Text(), nullable=False, server_default=""),
    ]


def _existing_columns() -> set[str]:
    inspector = sa.inspect(op.get_bind())
    return {column["name"] for column in inspector.get_columns("runs")}


def upgrade() -> None:
    present = _existing_columns()
    for column in _columns():
        if column.name not in present:
            op.add_column("runs", column)


def downgrade() -> None:
    present = _existing_columns()
    for column in reversed(_columns()):
        if column.name in present:
            op.drop_column("runs", column.name)
