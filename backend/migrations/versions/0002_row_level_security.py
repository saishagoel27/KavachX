"""PostgreSQL row-level security on tenant-owned tables.

Revision ID: 0002_rls
Revises: 0001_initial
Create Date: 2024-01-01 00:00:01

**What this is and is not.**

The primary tenant control in KavachX is the application layer: the tenant comes from the signed
access token, every loader compares ``row.tenant_id`` against it, and a cross-tenant id is
reported as 404 rather than 403. That is what the tenant-isolation tests exercise.

RLS here is the *second* layer, for the case where something reaches the database outside that
path — an ad-hoc query, a reporting tool, a future service. Each tenant-owned table gets a policy
keyed on the ``kavachx.tenant_id`` session variable, plus a ``kavachx_reader`` role that is
subject to it.

Note the honest limitation: the application connects as the table owner, and a table owner is not
subject to RLS unless ``FORCE ROW LEVEL SECURITY`` is set. Forcing it would require the
application to ``SET kavachx.tenant_id`` on every pooled connection checkout, which this PoC does
not do — so for the application's own connection RLS is inert, and the application-level filter is
what is actually protecting tenants. The policies below are live for any non-owner role. See
docs/SECURITY.md.

Skipped entirely on non-PostgreSQL dialects (the test suite runs on SQLite).
"""

from __future__ import annotations

from typing import Sequence, Union

from alembic import op

revision: str = "0002_rls"
down_revision: Union[str, None] = "0001_initial"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

TENANT_TABLES = (
    "organisation_members",
    "github_installations",
    "projects",
    "repositories",
    "policies",
    "runs",
    "run_events",
    "run_checkpoints",
    "world_models",
    "artifacts",
    "samhita_clauses",
    "hypotheses",
    "findings",
    "shields",
    "patches",
    "gauntlet_runs",
    "gauntlet_results",
    "evidence_nodes",
    "evidence_edges",
    "certificates",
    "audit_events",
)


def upgrade() -> None:
    connection = op.get_bind()
    if connection.dialect.name != "postgresql":
        return

    op.execute(
        """
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'kavachx_reader') THEN
                CREATE ROLE kavachx_reader NOLOGIN;
            END IF;
        END
        $$;
        """
    )

    for table in TENANT_TABLES:
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY;")
        op.execute(
            f"""
            CREATE POLICY {table}_tenant_isolation ON {table}
            USING (
                tenant_id = NULLIF(current_setting('kavachx.tenant_id', true), '')::uuid
            );
            """
        )
        op.execute(f"GRANT SELECT ON {table} TO kavachx_reader;")

    # Append-only audit log: no UPDATE or DELETE for anyone but the owner, and a trigger that
    # refuses both outright. A tamper-evident chain is worth little if rows can be rewritten.
    op.execute(
        """
        CREATE OR REPLACE FUNCTION kavachx_audit_immutable() RETURNS trigger AS $$
        BEGIN
            RAISE EXCEPTION
                'audit_events is append-only: % is not permitted', TG_OP;
        END;
        $$ LANGUAGE plpgsql;
        """
    )
    op.execute(
        """
        CREATE TRIGGER audit_events_immutable
        BEFORE UPDATE OR DELETE ON audit_events
        FOR EACH ROW EXECUTE FUNCTION kavachx_audit_immutable();
        """
    )


def downgrade() -> None:
    connection = op.get_bind()
    if connection.dialect.name != "postgresql":
        return

    op.execute("DROP TRIGGER IF EXISTS audit_events_immutable ON audit_events;")
    op.execute("DROP FUNCTION IF EXISTS kavachx_audit_immutable();")
    for table in TENANT_TABLES:
        op.execute(f"DROP POLICY IF EXISTS {table}_tenant_isolation ON {table};")
        op.execute(f"ALTER TABLE {table} DISABLE ROW LEVEL SECURITY;")
