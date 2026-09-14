"""Add correlated_finding_ids column to findings (cross-scanner correlation engine)

Revision ID: finding_correlation_001
Revises: finding_accept_risk_001
Create Date: 2026-09-14

Changes:
- findings.correlated_finding_ids (text[], nullable): populated only on
  synthetic "compound finding" rows (source="correlation_engine") produced
  by app/services/correlation_engine.py — the UUIDs (as strings) of the real
  underlying findings a compound finding was derived from, so it's always
  traceable back to real evidence rather than an opaque new assertion.
"""

from alembic import op
import sqlalchemy as sa

revision = "finding_correlation_001"
down_revision = "scan_jobs_org_created_001"
branch_labels = None
depends_on = None


def _column_exists(conn, table: str, column: str) -> bool:
    result = conn.execute(
        sa.text(
            "SELECT 1 FROM information_schema.columns "
            "WHERE table_name=:t AND column_name=:c"
        ),
        {"t": table, "c": column},
    )
    return result.scalar() is not None


def upgrade() -> None:
    conn = op.get_bind()
    if not _column_exists(conn, "findings", "correlated_finding_ids"):
        op.add_column(
            "findings",
            sa.Column("correlated_finding_ids", sa.ARRAY(sa.String()), nullable=True),
        )


def downgrade() -> None:
    conn = op.get_bind()
    if _column_exists(conn, "findings", "correlated_finding_ids"):
        op.drop_column("findings", "correlated_finding_ids")
