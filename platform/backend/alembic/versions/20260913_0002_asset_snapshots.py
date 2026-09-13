"""Add asset_snapshots table for continuous EASM diffing

Revision ID: asset_snapshots_001
Revises: mfa_columns_001
Create Date: 2026-09-13

Changes:
- Add asset_snapshots: one row per org per periodic snapshot run, storing a
  point-in-time view of that org's assets (id -> {ports, metadata, risk_score})
  so a scheduled task can diff consecutive snapshots to detect new assets,
  newly opened ports, and other attack-surface changes independent of any
  particular scan run.
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "asset_snapshots_001"
down_revision = "mfa_columns_001"
branch_labels = None
depends_on = None


def _table_exists(conn, table: str) -> bool:
    result = conn.execute(
        sa.text("SELECT 1 FROM information_schema.tables WHERE table_name=:t"), {"t": table}
    )
    return result.scalar() is not None


def upgrade() -> None:
    conn = op.get_bind()
    if not _table_exists(conn, "asset_snapshots"):
        op.create_table(
            "asset_snapshots",
            sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
            sa.Column("org_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
            sa.Column("taken_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
            sa.Column("snapshot", postgresql.JSONB, nullable=False),
            sa.Column("asset_count", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        )
        op.create_index("ix_asset_snapshots_org_taken", "asset_snapshots", ["org_id", "taken_at"])


def downgrade() -> None:
    conn = op.get_bind()
    if _table_exists(conn, "asset_snapshots"):
        op.drop_table("asset_snapshots")
