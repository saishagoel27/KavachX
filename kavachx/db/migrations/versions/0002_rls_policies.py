"""rls policies

Revision ID: 0002
Revises: 0001
Create Date: 2026-08-01
"""
from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None

# Tables that carry tenant_id and need RLS
_TENANT_TABLES = [
    "projects",
    "memberships",
    "runs",
    "findings",
    "shields",
    "patches",
    "certificates",
    "audit_events",
    "artifact_store",
]


def upgrade() -> None:
    for table in _TENANT_TABLES:
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
        op.execute(
            f"""
            CREATE POLICY tenant_isolation ON {table}
                USING (tenant_id = current_setting('app.tenant_id')::uuid)
            """
        )

    # audit_events is append-only — revoke UPDATE and DELETE from the app role
    # The role name matches what docker-compose creates: kavachx
    op.execute("REVOKE UPDATE, DELETE ON audit_events FROM kavachx")


def downgrade() -> None:
    op.execute("GRANT UPDATE, DELETE ON audit_events TO kavachx")
    for table in reversed(_TENANT_TABLES):
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation ON {table}")
        op.execute(f"ALTER TABLE {table} DISABLE ROW LEVEL SECURITY")
