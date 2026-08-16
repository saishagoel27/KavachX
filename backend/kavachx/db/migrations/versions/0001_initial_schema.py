"""initial schema

Revision ID: 0001
Revises:
Create Date: 2026-08-01
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "organisations",
        sa.Column("id", UUID(as_uuid=False), primary_key=True),
        sa.Column("name", sa.Text, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
    )

    op.create_table(
        "projects",
        sa.Column("id", UUID(as_uuid=False), primary_key=True),
        sa.Column("tenant_id", UUID(as_uuid=False),
                  sa.ForeignKey("organisations.id"), nullable=False),
        sa.Column("repo_url", sa.Text, nullable=False),
        sa.Column("github_app_installation_id", sa.BigInteger, nullable=False),
        sa.Column("auto_publish", sa.Boolean, nullable=False, server_default="false"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
    )

    op.create_table(
        "memberships",
        sa.Column("id", UUID(as_uuid=False), primary_key=True),
        sa.Column("tenant_id", UUID(as_uuid=False),
                  sa.ForeignKey("organisations.id"), nullable=False),
        sa.Column("user_id", UUID(as_uuid=False), nullable=False),
        sa.Column("project_id", UUID(as_uuid=False)),
        sa.Column("role", sa.Text, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
        sa.UniqueConstraint("tenant_id", "user_id", "project_id"),
    )

    op.create_table(
        "runs",
        sa.Column("id", UUID(as_uuid=False), primary_key=True),
        sa.Column("tenant_id", UUID(as_uuid=False),
                  sa.ForeignKey("organisations.id"), nullable=False),
        sa.Column("project_id", UUID(as_uuid=False),
                  sa.ForeignKey("projects.id"), nullable=False),
        sa.Column("commit_sha", sa.Text, nullable=False),
        sa.Column("phase", sa.Text, nullable=False, server_default="ingest"),
        sa.Column("status", sa.Text, nullable=False, server_default="running"),
        sa.Column("state_snapshot", JSONB),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
        sa.Column("budget_tokens", sa.Integer, nullable=False, server_default="0"),
        sa.Column("budget_seconds", sa.Float, nullable=False, server_default="0"),
    )
    op.create_index("idx_runs_project", "runs", ["project_id",
                    sa.text("started_at DESC")])

    op.create_table(
        "findings",
        sa.Column("id", UUID(as_uuid=False), primary_key=True),
        sa.Column("tenant_id", UUID(as_uuid=False),
                  sa.ForeignKey("organisations.id"), nullable=False),
        sa.Column("run_id", UUID(as_uuid=False),
                  sa.ForeignKey("runs.id"), nullable=False),
        sa.Column("channel", sa.Text, nullable=False),
        sa.Column("clause_id", sa.Text),
        sa.Column("location", sa.Text, nullable=False),
        sa.Column("severity", sa.Text, nullable=False),
        sa.Column("reachable", sa.Boolean, nullable=False),
        sa.Column("status", sa.Text, nullable=False, server_default="hypothesis"),
        sa.Column("exploit_ref", sa.Text),
        sa.Column("pov_hash", sa.Text),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
    )
    op.create_index("idx_findings_run", "findings", ["run_id", "status"])

    op.create_table(
        "shields",
        sa.Column("id", UUID(as_uuid=False), primary_key=True),
        sa.Column("tenant_id", UUID(as_uuid=False),
                  sa.ForeignKey("organisations.id"), nullable=False),
        sa.Column("run_id", UUID(as_uuid=False),
                  sa.ForeignKey("runs.id"), nullable=False),
        sa.Column("finding_id", UUID(as_uuid=False),
                  sa.ForeignKey("findings.id"), nullable=False),
        sa.Column("rule", sa.Text, nullable=False),
        sa.Column("revert_cmd", sa.Text, nullable=False),
        sa.Column("verified_blocked", sa.Boolean, nullable=False, server_default="false"),
        sa.Column("verified_benign", sa.Boolean, nullable=False, server_default="false"),
        sa.Column("deployed_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
    )

    op.create_table(
        "patches",
        sa.Column("id", UUID(as_uuid=False), primary_key=True),
        sa.Column("tenant_id", UUID(as_uuid=False),
                  sa.ForeignKey("organisations.id"), nullable=False),
        sa.Column("run_id", UUID(as_uuid=False),
                  sa.ForeignKey("runs.id"), nullable=False),
        sa.Column("finding_id", UUID(as_uuid=False),
                  sa.ForeignKey("findings.id"), nullable=False),
        sa.Column("diff_hash", sa.Text, nullable=False),
        sa.Column("diff_ref", sa.Text, nullable=False),
        sa.Column("root_cause", sa.Text, nullable=False),
        sa.Column("iteration", sa.Integer, nullable=False),
        sa.Column("status", sa.Text, nullable=False, server_default="pending"),
        sa.Column("refuting_input", sa.Text),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
    )

    op.create_table(
        "certificates",
        sa.Column("id", UUID(as_uuid=False), primary_key=True),
        sa.Column("tenant_id", UUID(as_uuid=False),
                  sa.ForeignKey("organisations.id"), nullable=False),
        sa.Column("run_id", UUID(as_uuid=False),
                  sa.ForeignKey("runs.id"), nullable=False),
        sa.Column("finding_id", UUID(as_uuid=False),
                  sa.ForeignKey("findings.id"), nullable=False),
        sa.Column("level", sa.String(1), nullable=False),
        sa.Column("evidence_hashes", ARRAY(sa.Text), nullable=False),
        sa.Column("signature", sa.Text, nullable=False),
        sa.Column("signed_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
    )

    op.create_table(
        "audit_events",
        sa.Column("id", sa.BigInteger, primary_key=True, autoincrement=True),
        sa.Column("tenant_id", UUID(as_uuid=False),
                  sa.ForeignKey("organisations.id"), nullable=False),
        sa.Column("run_id", UUID(as_uuid=False)),
        sa.Column("actor_id", UUID(as_uuid=False)),
        sa.Column("action", sa.Text, nullable=False),
        sa.Column("subject_type", sa.Text, nullable=False),
        sa.Column("subject_id", sa.Text, nullable=False),
        sa.Column("evidence_hash", sa.Text),
        sa.Column("metadata", JSONB),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
        sa.Column("prev_hash", sa.Text),
    )
    op.create_index("idx_audit_tenant", "audit_events",
                    ["tenant_id", sa.text("created_at DESC")])

    op.create_table(
        "artifact_store",
        sa.Column("sha256", sa.Text, primary_key=True),
        sa.Column("tenant_id", UUID(as_uuid=False),
                  sa.ForeignKey("organisations.id"), nullable=False),
        sa.Column("kind", sa.Text, nullable=False),
        sa.Column("size_bytes", sa.Integer, nullable=False),
        sa.Column("storage_path", sa.Text, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
    )


def downgrade() -> None:
    op.drop_table("artifact_store")
    op.drop_index("idx_audit_tenant", "audit_events")
    op.drop_table("audit_events")
    op.drop_table("certificates")
    op.drop_table("patches")
    op.drop_table("shields")
    op.drop_index("idx_findings_run", "findings")
    op.drop_table("findings")
    op.drop_index("idx_runs_project", "runs")
    op.drop_table("runs")
    op.drop_table("memberships")
    op.drop_table("projects")
    op.drop_table("organisations")
