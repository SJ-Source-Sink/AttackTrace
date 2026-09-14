"""Add (org_id, created_at) index to scan_jobs for monthly scan-quota counts

Revision ID: scan_jobs_org_created_001
Revises: finding_accept_risk_001
Create Date: 2026-09-13

Changes:
- scan_jobs.idx_scan_jobs_org_created (org_id, created_at): new monthly
  scan-quota enforcement (app/services/scan_service.py::enforce_scan_quota)
  runs `COUNT(*) FROM scan_jobs WHERE org_id = :org_id AND created_at >=
  :month_start` on every scan-creation request. The existing
  ix_scan_jobs_org_id (org_id only) and idx_scan_org_status_created
  (org_id, status, created_at) indexes don't let Postgres prune to just
  this month's rows for an org that isn't also filtering by status — a
  long-lived org would force a scan of every ScanJob row it has ever had.
  This index lets the range condition on created_at be applied directly
  in the index scan, keeping the quota check cheap regardless of how large
  scan_jobs grows over time.
"""

from alembic import op
import sqlalchemy as sa

revision = "scan_jobs_org_created_001"
down_revision = "finding_accept_risk_001"
branch_labels = None
depends_on = None

INDEX_NAME = "idx_scan_jobs_org_created"


def _index_exists(conn, index_name: str) -> bool:
    result = conn.execute(
        sa.text("SELECT 1 FROM pg_indexes WHERE indexname = :name"),
        {"name": index_name},
    )
    return result.scalar() is not None


def upgrade() -> None:
    conn = op.get_bind()
    if not _index_exists(conn, INDEX_NAME):
        op.create_index(
            INDEX_NAME,
            "scan_jobs",
            ["org_id", "created_at"],
        )


def downgrade() -> None:
    conn = op.get_bind()
    if _index_exists(conn, INDEX_NAME):
        op.drop_index(INDEX_NAME, table_name="scan_jobs")
