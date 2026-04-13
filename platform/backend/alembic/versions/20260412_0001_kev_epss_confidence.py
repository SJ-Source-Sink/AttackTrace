"""kev epss confidence and suppression rules

Revision ID: kev_epss_confidence
Revises: cascade_assets_scan
Create Date: 2026-04-12 00:01:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "kev_epss_confidence"
down_revision = "cascade_assets_scan"
branch_labels = None
depends_on = None


def _col_exists(conn, table, col):
    result = conn.execute(sa.text(
        "SELECT 1 FROM information_schema.columns WHERE table_name=:t AND column_name=:c"
    ), {"t": table, "c": col})
    return result.scalar() is not None


def _idx_exists(conn, idx):
    result = conn.execute(sa.text(
        "SELECT 1 FROM pg_indexes WHERE indexname=:i"
    ), {"i": idx})
    return result.scalar() is not None


def _table_exists(conn, table):
    result = conn.execute(sa.text(
        "SELECT 1 FROM information_schema.tables WHERE table_name=:t"
    ), {"t": table})
    return result.scalar() is not None


def upgrade() -> None:
    conn = op.get_bind()

    # --- Add new columns to findings (idempotent) ---
    if not _col_exists(conn, "findings", "confidence"):
        op.add_column("findings", sa.Column("confidence", sa.String(16), nullable=True))
    if not _col_exists(conn, "findings", "kev_status"):
        op.add_column("findings", sa.Column("kev_status", sa.Boolean(), nullable=False, server_default=sa.text("false")))
    if not _col_exists(conn, "findings", "epss_score"):
        op.add_column("findings", sa.Column("epss_score", sa.Float(), nullable=True))
    if not _col_exists(conn, "findings", "priority_score"):
        op.add_column("findings", sa.Column("priority_score", sa.Float(), nullable=True))
    if not _col_exists(conn, "findings", "dedup_hash"):
        op.add_column("findings", sa.Column("dedup_hash", sa.String(64), nullable=True))

    if not _idx_exists(conn, "ix_findings_dedup_hash"):
        op.create_index("ix_findings_dedup_hash", "findings", ["dedup_hash"])

    # --- Create scan_suppression_rules table (idempotent) ---
    if _table_exists(conn, "scan_suppression_rules"):
        return

    op.create_table(
        "scan_suppression_rules",
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
        sa.Column("finding_title", sa.Text(), nullable=False),
        sa.Column("affected_asset_pattern", sa.Text(), nullable=False),
        sa.Column("action", sa.String(32), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_by",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("notes", sa.Text(), nullable=True),
    )
    op.create_index(
        "ix_scan_suppression_rules_org_id",
        "scan_suppression_rules",
        ["org_id"],
    )


def downgrade() -> None:
    op.drop_index("ix_scan_suppression_rules_org_id", table_name="scan_suppression_rules")
    op.drop_table("scan_suppression_rules")
    op.drop_index("ix_findings_dedup_hash", table_name="findings")
    op.drop_column("findings", "dedup_hash")
    op.drop_column("findings", "priority_score")
    op.drop_column("findings", "epss_score")
    op.drop_column("findings", "kev_status")
    op.drop_column("findings", "confidence")
