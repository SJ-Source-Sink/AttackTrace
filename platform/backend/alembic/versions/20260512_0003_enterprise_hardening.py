"""Enterprise hardening: unique dedup_hash constraint, missing indexes, scan version column

Revision ID: enterprise_hardening_001
Revises: mobile_scanner_001
Create Date: 2026-05-12

Changes:
- Add UNIQUE constraint on (org_id, dedup_hash) in findings — prevents duplicate findings
  across concurrent scans even under race conditions (enforced at DB level, not app level)
- Add partial index on findings for open critical/high findings — fast dashboard queries
- Add index on scans (org_id, status, created_at) — fast per-org scan list queries
- Add version column to scan_jobs for optimistic locking
- Add index on assets (org_id, scan_job_id) — fast per-scan asset lookups

Note: CONCURRENTLY indexes run outside Alembic's transaction block (transaction=False
in with_begin() calls) to avoid "cannot run inside a transaction block" error.
"""

from alembic import op
import sqlalchemy as sa


revision = "enterprise_hardening_001"
down_revision = "mobile_scanner_001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    conn = op.get_bind()

    # CREATE INDEX CONCURRENTLY cannot run inside a transaction — commit first
    conn.execute(sa.text("COMMIT"))

    # 1. Unique constraint on (org_id, dedup_hash) — atomic cross-scan deduplication
    conn.execute(sa.text("""
        CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS uq_finding_org_dedup_hash
        ON findings (org_id, dedup_hash)
        WHERE dedup_hash IS NOT NULL
    """))

    # 2. Partial index: open critical/high findings per org (dashboard KPI queries)
    conn.execute(sa.text("""
        CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_finding_org_open_critical_high
        ON findings (org_id, created_at DESC)
        WHERE status = 'OPEN' AND severity IN ('CRITICAL', 'HIGH')
    """))

    # 3. Composite index on scans for status-filtered list queries
    conn.execute(sa.text("""
        CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_scan_org_status_created
        ON scan_jobs (org_id, status, created_at DESC)
    """))

    # 4. Index on assets for per-scan asset lookups
    conn.execute(sa.text("""
        CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_asset_org_scan
        ON assets (org_id, scan_job_id)
        WHERE scan_job_id IS NOT NULL
    """))

    # Re-open a transaction for the non-concurrent DDL below
    conn.execute(sa.text("BEGIN"))

    # 5. Optimistic locking version column on scan_jobs
    conn.execute(sa.text("""
        ALTER TABLE scan_jobs
        ADD COLUMN IF NOT EXISTS row_version INTEGER NOT NULL DEFAULT 1
    """))


def downgrade() -> None:
    conn = op.get_bind()
    conn.execute(sa.text("COMMIT"))
    conn.execute(sa.text("DROP INDEX CONCURRENTLY IF EXISTS uq_finding_org_dedup_hash"))
    conn.execute(sa.text("DROP INDEX CONCURRENTLY IF EXISTS idx_finding_org_open_critical_high"))
    conn.execute(sa.text("DROP INDEX CONCURRENTLY IF EXISTS idx_scan_org_status_created"))
    conn.execute(sa.text("DROP INDEX CONCURRENTLY IF EXISTS idx_asset_org_scan"))
    conn.execute(sa.text("BEGIN"))
    conn.execute(sa.text("ALTER TABLE scan_jobs DROP COLUMN IF EXISTS row_version"))
