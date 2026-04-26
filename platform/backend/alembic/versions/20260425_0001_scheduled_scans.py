"""Add scheduled_scans table

Revision ID: scheduled_scans
Revises: tool_permissions
Create Date: 2026-04-25
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy import text
from sqlalchemy.dialects import postgresql

revision = "scheduled_scans"
down_revision = "tool_permissions"
branch_labels = None
depends_on = None


def _table_exists(conn, name):
    return conn.execute(
        text("SELECT 1 FROM information_schema.tables WHERE table_name=:n"), {"n": name}
    ).scalar() is not None


def upgrade():
    conn = op.get_bind()
    if not _table_exists(conn, "scheduled_scans"):
        op.create_table(
            "scheduled_scans",
            sa.Column(
                "id",
                postgresql.UUID(as_uuid=True),
                primary_key=True,
                server_default=sa.text("gen_random_uuid()"),
            ),
            sa.Column(
                "org_id",
                postgresql.UUID(as_uuid=True),
                sa.ForeignKey("organizations.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column(
                "workspace_id",
                postgresql.UUID(as_uuid=True),
                sa.ForeignKey("workspaces.id", ondelete="SET NULL"),
                nullable=True,
            ),
            sa.Column(
                "created_by",
                postgresql.UUID(as_uuid=True),
                sa.ForeignKey("users.id", ondelete="SET NULL"),
                nullable=True,
            ),
            sa.Column("name", sa.String(255), nullable=False),
            sa.Column("target_domains", postgresql.ARRAY(sa.String()), nullable=False),
            sa.Column("company_name", sa.String(255), nullable=True),
            sa.Column(
                "scan_config",
                postgresql.JSONB(),
                nullable=False,
                server_default="{}",
            ),
            sa.Column("cron_expression", sa.String(100), nullable=False),
            sa.Column(
                "is_active",
                sa.Boolean(),
                nullable=False,
                server_default="true",
            ),
            sa.Column("last_run", sa.TIMESTAMP(timezone=True), nullable=True),
            sa.Column("next_run", sa.TIMESTAMP(timezone=True), nullable=True),
            sa.Column(
                "last_scan_job_id",
                postgresql.UUID(as_uuid=True),
                sa.ForeignKey("scan_jobs.id", ondelete="SET NULL"),
                nullable=True,
            ),
            sa.Column(
                "created_at",
                sa.TIMESTAMP(timezone=True),
                nullable=False,
                server_default=sa.text("now()"),
            ),
            sa.Column(
                "updated_at",
                sa.TIMESTAMP(timezone=True),
                nullable=False,
                server_default=sa.text("now()"),
            ),
        )
        op.create_index("ix_scheduled_scans_org_id", "scheduled_scans", ["org_id"])
        op.create_index("ix_scheduled_scans_next_run", "scheduled_scans", ["next_run"])


def downgrade():
    conn = op.get_bind()
    if _table_exists(conn, "scheduled_scans"):
        op.drop_table("scheduled_scans")
