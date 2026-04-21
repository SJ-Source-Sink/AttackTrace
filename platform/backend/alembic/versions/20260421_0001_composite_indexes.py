"""composite indexes for findings and assets queries

Revision ID: composite_indexes
Revises: kev_epss_confidence
Create Date: 2026-04-21 00:01:00.000000

"""
from alembic import op
import sqlalchemy as sa

revision = "composite_indexes"
down_revision = "kev_epss_confidence"
branch_labels = None
depends_on = None


def _idx_exists(conn, idx: str) -> bool:
    result = conn.execute(
        sa.text("SELECT 1 FROM pg_indexes WHERE indexname = :i"),
        {"i": idx},
    )
    return result.scalar() is not None


def upgrade() -> None:
    conn = op.get_bind()

    # findings: common list query filter (org + status + severity)
    if not _idx_exists(conn, "ix_findings_org_status_severity"):
        op.create_index(
            "ix_findings_org_status_severity",
            "findings",
            ["org_id", "status", "severity"],
        )

    # findings: time-sorted listing (org + created_at DESC)
    if not _idx_exists(conn, "ix_findings_org_created_at"):
        op.create_index(
            "ix_findings_org_created_at",
            "findings",
            ["org_id", sa.text("created_at DESC")],
            postgresql_using="btree",
        )

    # findings: suppress/false-positive filter
    if not _idx_exists(conn, "ix_findings_org_fp_suppressed"):
        op.create_index(
            "ix_findings_org_fp_suppressed",
            "findings",
            ["org_id", "false_positive", "suppressed"],
        )

    # assets: common list query (org + asset_type)
    if not _idx_exists(conn, "ix_assets_org_asset_type"):
        op.create_index(
            "ix_assets_org_asset_type",
            "assets",
            ["org_id", "asset_type"],
        )

    # assets: active assets fast count
    if not _idx_exists(conn, "ix_assets_org_is_active"):
        op.create_index(
            "ix_assets_org_is_active",
            "assets",
            ["org_id", "is_active"],
        )

    # scans: listing by org + status
    if not _idx_exists(conn, "ix_scan_jobs_org_status"):
        op.create_index(
            "ix_scan_jobs_org_status",
            "scan_jobs",
            ["org_id", "status"],
        )

    # scans: time-sorted listing
    if not _idx_exists(conn, "ix_scan_jobs_org_created_at"):
        op.create_index(
            "ix_scan_jobs_org_created_at",
            "scan_jobs",
            ["org_id", sa.text("created_at DESC")],
            postgresql_using="btree",
        )


def downgrade() -> None:
    for idx, tbl in [
        ("ix_scan_jobs_org_created_at", "scan_jobs"),
        ("ix_scan_jobs_org_status", "scan_jobs"),
        ("ix_assets_org_is_active", "assets"),
        ("ix_assets_org_asset_type", "assets"),
        ("ix_findings_org_fp_suppressed", "findings"),
        ("ix_findings_org_created_at", "findings"),
        ("ix_findings_org_status_severity", "findings"),
    ]:
        op.drop_index(idx, table_name=tbl)
