"""Create scan_diffs table for asset change detection

Revision ID: scan_diffs
Revises: sla_compliance
Create Date: 2026-04-25 00:04:00.000000
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy import text
from sqlalchemy.dialects import postgresql

revision = "scan_diffs"
down_revision = "sla_compliance"
branch_labels = None
depends_on = None


def _table_exists(conn, table: str) -> bool:
    result = conn.execute(
        text(
            "SELECT 1 FROM information_schema.tables "
            "WHERE table_name=:t"
        ),
        {"t": table},
    )
    return result.scalar() is not None


def upgrade() -> None:
    conn = op.get_bind()

    if not _table_exists(conn, "scan_diffs"):
        op.create_table(
            "scan_diffs",
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
                "scan_id",
                postgresql.UUID(as_uuid=True),
                sa.ForeignKey("scan_jobs.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column(
                "previous_scan_id",
                postgresql.UUID(as_uuid=True),
                nullable=True,
            ),
            sa.Column("new_assets", postgresql.JSONB(), nullable=True),
            sa.Column("removed_assets", postgresql.JSONB(), nullable=True),
            sa.Column("new_findings", postgresql.JSONB(), nullable=True),
            sa.Column("resolved_findings", postgresql.JSONB(), nullable=True),
            sa.Column("diff_summary", postgresql.JSONB(), nullable=True),
            sa.Column(
                "created_at",
                sa.DateTime(timezone=True),
                server_default=sa.text("now()"),
                nullable=False,
            ),
        )
        op.create_index("ix_scan_diffs_org_id", "scan_diffs", ["org_id"])
        op.create_index("ix_scan_diffs_scan_id", "scan_diffs", ["scan_id"])


def downgrade() -> None:
    conn = op.get_bind()
    if _table_exists(conn, "scan_diffs"):
        op.drop_table("scan_diffs")
