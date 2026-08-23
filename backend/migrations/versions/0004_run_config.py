"""Store operator-supplied run configuration on the run row.

Revision ID: 0004_run_config
Revises: 0003_run_mode
Create Date: 2024-01-01 00:00:03

Adds ``runs.run_config`` — the Vercel/Render-style configuration an operator provides when starting
a run (root directory, install/build/start commands, target type, and the target's own env vars).
It replaces run-plan guesswork: the detector only pre-fills the form. Added if absent, for the same
metadata-baseline reason documented in 0003.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0004_run_config"
down_revision: str | None = "0003_run_mode"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _existing_columns() -> set[str]:
    inspector = sa.inspect(op.get_bind())
    return {column["name"] for column in inspector.get_columns("runs")}


def upgrade() -> None:
    if "run_config" not in _existing_columns():
        op.add_column(
            "runs",
            sa.Column(
                "run_config",
                sa.JSON(),
                nullable=False,
                server_default=sa.text("'{}'"),
            ),
        )


def downgrade() -> None:
    if "run_config" in _existing_columns():
        op.drop_column("runs", "run_config")
