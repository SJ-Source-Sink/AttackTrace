"""Add sla_breach_notified_at column to findings (SLA breach notification tracking)

Revision ID: sla_breach_notified_001
Revises: finding_correlation_001
Create Date: 2026-09-14

Changes:
- findings.sla_breach_notified_at (timestamptz, nullable): set the first time
  app/workers/sla_worker.py's periodic check_sla_breaches task fires an
  sla.breached notification for a finding, so the task never re-notifies the
  same finding on a subsequent run. NULL means "not yet notified" (or not
  currently breached).
"""

from alembic import op
import sqlalchemy as sa

revision = "sla_breach_notified_001"
down_revision = "finding_correlation_001"
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
    if not _column_exists(conn, "findings", "sla_breach_notified_at"):
        op.add_column(
            "findings",
            sa.Column("sla_breach_notified_at", sa.DateTime(timezone=True), nullable=True),
        )


def downgrade() -> None:
    conn = op.get_bind()
    if _column_exists(conn, "findings", "sla_breach_notified_at"):
        op.drop_column("findings", "sla_breach_notified_at")
