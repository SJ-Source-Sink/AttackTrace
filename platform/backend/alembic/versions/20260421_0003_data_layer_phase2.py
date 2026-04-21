"""Phase 2 data layer: dedup_hash unique constraint, missing indexes, scan_metrics matview

Revision ID: data_layer_phase2
Revises: anthropic_key_credential
Create Date: 2026-04-21 00:03:00.000000

Changes:
- Recompute all existing dedup_hash values to full sha256 (was truncated to 32 chars)
- Add unique constraint on (org_id, dedup_hash) after deduplication
- Add indexes: findings.kev_status, findings.suppressed, assets.created_at
- Create materialized view scan_metrics_mv for dashboard scan statistics
- Create index on scan_metrics_mv for fast lookup
"""
import hashlib

from alembic import op
import sqlalchemy as sa
from sqlalchemy import text

revision = "data_layer_phase2"
down_revision = "anthropic_key_credential"
branch_labels = None
depends_on = None


def _idx_exists(conn, name: str) -> bool:
    result = conn.execute(
        text("SELECT 1 FROM pg_indexes WHERE indexname = :n"),
        {"n": name},
    )
    return result.scalar() is not None


def _constraint_exists(conn, table: str, name: str) -> bool:
    result = conn.execute(
        text(
            "SELECT 1 FROM information_schema.table_constraints "
            "WHERE table_name=:t AND constraint_name=:n"
        ),
        {"t": table, "n": name},
    )
    return result.scalar() is not None


def _matview_exists(conn, name: str) -> bool:
    result = conn.execute(
        text("SELECT 1 FROM pg_matviews WHERE matviewname = :n"),
        {"n": name},
    )
    return result.scalar() is not None


def upgrade() -> None:
    conn = op.get_bind()

    # ------------------------------------------------------------------
    # 2b. Recompute dedup_hash to full 64-char sha256(org|title|asset|cves)
    # Fetch existing rows and recompute in Python so the hash algorithm
    # stays in sync with scan_worker._compute_dedup_hash.
    # ------------------------------------------------------------------
    rows = conn.execute(
        text(
            "SELECT id, org_id, title, affected_asset, cve "
            "FROM findings WHERE dedup_hash IS NOT NULL"
        )
    ).fetchall()

    for row in rows:
        finding_id, org_id, title, affected_asset, cve_list = row
        sorted_cves = "|".join(sorted(cve_list or []))
        key = f"{str(org_id)}|{title}|{affected_asset}|{sorted_cves}"
        new_hash = hashlib.sha256(key.encode()).hexdigest()
        conn.execute(
            text("UPDATE findings SET dedup_hash = :h WHERE id = :id"),
            {"h": new_hash, "id": finding_id},
        )

    # Extend column from String(64) — it's already TEXT-compatible but
    # the ORM maps it as String(64); 64 chars fits a sha256 hex digest exactly.
    # No column alteration needed since VARCHAR(64) holds 64 chars.

    # Deduplicate: if two findings have same (org_id, dedup_hash) keep the
    # oldest one (lowest created_at). Delete duplicates before adding constraint.
    conn.execute(text("""
        DELETE FROM findings f
        USING (
            SELECT org_id, dedup_hash, MIN(created_at) AS keep_at
            FROM findings
            WHERE dedup_hash IS NOT NULL
            GROUP BY org_id, dedup_hash
            HAVING COUNT(*) > 1
        ) dup
        WHERE f.org_id = dup.org_id
          AND f.dedup_hash = dup.dedup_hash
          AND f.created_at > dup.keep_at
    """))

    # Add unique constraint on (org_id, dedup_hash) — only on non-NULL rows,
    # achieved via a partial unique index (handles NULL = no dedup key).
    if not _idx_exists(conn, "uq_findings_org_dedup_hash"):
        op.create_index(
            "uq_findings_org_dedup_hash",
            "findings",
            ["org_id", "dedup_hash"],
            unique=True,
            postgresql_where=sa.text("dedup_hash IS NOT NULL"),
        )

    # ------------------------------------------------------------------
    # 2f. Missing indexes
    # ------------------------------------------------------------------

    # findings.kev_status — used by /findings?kev_status=true filters
    if not _idx_exists(conn, "ix_findings_kev_status"):
        op.create_index("ix_findings_kev_status", "findings", ["kev_status"])

    # findings.suppressed — used by suppression filters
    if not _idx_exists(conn, "ix_findings_suppressed"):
        op.create_index("ix_findings_suppressed", "findings", ["suppressed"])

    # assets.created_at — used for "newest assets" queries
    if not _idx_exists(conn, "ix_assets_created_at"):
        op.create_index(
            "ix_assets_created_at",
            "assets",
            [sa.text("created_at DESC")],
        )

    # ------------------------------------------------------------------
    # 2g. Materialized view for scan metrics (replaces GROUP BY on scan_jobs)
    # Refreshed on demand (after scan completes) — see scan_worker.py
    # ------------------------------------------------------------------
    if not _matview_exists(conn, "scan_metrics_mv"):
        conn.execute(text("""
            CREATE MATERIALIZED VIEW scan_metrics_mv AS
            SELECT
                org_id,
                COUNT(*)                                                                        AS total_scans,
                COUNT(*) FILTER (WHERE status::text = 'completed')                             AS completed_scans,
                COUNT(*) FILTER (WHERE status::text = 'failed')                                AS failed_scans,
                COUNT(*) FILTER (WHERE status::text IN ('pending', 'running'))                 AS active_scans,
                AVG(EXTRACT(EPOCH FROM (completed_at - started_at)))
                    FILTER (WHERE status::text = 'completed'
                            AND started_at IS NOT NULL
                            AND completed_at IS NOT NULL)                                       AS avg_duration_secs,
                MAX(completed_at)                                                               AS last_scan_at,
                SUM(COALESCE((findings_count->>'critical')::int, 0))                           AS total_critical,
                SUM(COALESCE((findings_count->>'high')::int, 0))                               AS total_high,
                SUM(COALESCE((findings_count->>'medium')::int, 0))                             AS total_medium,
                SUM(COALESCE((findings_count->>'low')::int, 0))                                AS total_low
            FROM scan_jobs
            GROUP BY org_id
            WITH DATA
        """))

        op.create_index(
            "ix_scan_metrics_mv_org_id",
            "scan_metrics_mv",
            ["org_id"],
            unique=True,
        )


def downgrade() -> None:
    conn = op.get_bind()
    if _matview_exists(conn, "scan_metrics_mv"):
        conn.execute(text("DROP MATERIALIZED VIEW IF EXISTS scan_metrics_mv"))
    op.drop_index("uq_findings_org_dedup_hash", table_name="findings", if_exists=True)
    op.drop_index("ix_findings_kev_status", table_name="findings", if_exists=True)
    op.drop_index("ix_findings_suppressed", table_name="findings", if_exists=True)
    op.drop_index("ix_assets_created_at", table_name="assets", if_exists=True)
