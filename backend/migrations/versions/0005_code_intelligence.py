"""Code intelligence: the index, its graph, the security model, and generated tests.

Revision ID: 0005_code_intel
Revises: 0004_run_config
Create Date: 2024-01-01 00:00:04

Adds six tables that make the code-intelligence stages auditable after the run:

* ``repository_indexes``   — the index's reproducible identity, provider provenance, counters,
                             health grade, claim bounds, and the code graph itself.
* ``security_models``      — sources, sinks, sanitizers, controls, flows and trust boundaries.
* ``architecture_models``  — the structured application model and ranked attack surface.
* ``generated_tests``      — each TestSpec, its chosen engine, and the harness hash.
* ``test_executions``      — the reproducible execution record: command, environment, attempts,
                             output hashes, reproduction count, coverage.
* ``model_contexts``       — exactly what context a model received, for hallucination debugging.

Created from ``Base.metadata`` with ``checkfirst=True`` rather than hand-written DDL, for the same
reason revision 0001 does it and 0003/0004 guard their column adds: every column here already
carries a precise, dialect-aware definition in the models (``JSONType`` is JSONB on PostgreSQL and
JSON elsewhere; ``UUIDType`` is native ``uuid`` on PostgreSQL and ``CHAR(32)`` on SQLite).
Transcribing that by hand introduces exactly one class of bug — silent schema drift between the
models and the migration — and these tables are new, so there is no existing data to migrate and
nothing an explicit DDL diff would protect.

``checkfirst=True`` also makes this revision idempotent against a database that was created by
``create_all`` during startup provisioning, which is how the SQLite demo path and the test suite
bring a schema up.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0005_code_intel"
down_revision: str | None = "0004_run_config"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

#: Tables this revision owns. Named explicitly so the up/down migration touches nothing else —
#: `Base.metadata.create_all()` would happily create every table in the model registry, which on a
#: partially-migrated database would silently paper over an unrelated missing table.
_TABLES: tuple[str, ...] = (
    "repository_indexes",
    "security_models",
    "architecture_models",
    "generated_tests",
    "test_executions",
    "model_contexts",
)


def _selected_tables() -> list[sa.Table]:
    from app.models import Base

    return [Base.metadata.tables[name] for name in _TABLES if name in Base.metadata.tables]


def upgrade() -> None:
    connection = op.get_bind()
    tables = _selected_tables()
    if not tables:
        return
    # checkfirst: idempotent against a schema already created by startup provisioning.
    for table in tables:
        table.create(bind=connection, checkfirst=True)


def downgrade() -> None:
    connection = op.get_bind()
    # Reverse order so a future foreign key between these tables drops cleanly.
    for table in reversed(_selected_tables()):
        table.drop(bind=connection, checkfirst=True)
