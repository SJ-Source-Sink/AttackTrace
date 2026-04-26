"""Add SLA, compliance, risk score columns and scan_diffs table

Revision ID: sla_compliance
Revises: notification_channels
Create Date: 2026-04-25 00:03:00.000000
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy import text
from sqlalchemy.dialects import postgresql

revision = "sla_compliance"
down_revision = "notification_channels"
branch_labels = None
depends_on = None


def _col_exists(conn, table: str, column: str) -> bool:
    result = conn.execute(
        text(
            "SELECT 1 FROM information_schema.columns "
            "WHERE table_name=:t AND column_name=:c"
        ),
        {"t": table, "c": column},
    )
    return result.scalar() is not None


def upgrade() -> None:
    conn = op.get_bind()

    # findings.sla_deadline
    if not _col_exists(conn, "findings", "sla_deadline"):
        op.add_column(
            "findings",
            sa.Column("sla_deadline", sa.DateTime(timezone=True), nullable=True),
        )

    # findings.compliance_tags
    if not _col_exists(conn, "findings", "compliance_tags"):
        op.add_column(
            "findings",
            sa.Column(
                "compliance_tags",
                postgresql.ARRAY(sa.String(50)),
                nullable=True,
            ),
        )

    # findings.risk_score
    if not _col_exists(conn, "findings", "risk_score"):
        op.add_column(
            "findings",
            sa.Column("risk_score", sa.Float(), nullable=True),
        )

    # findings.risk_explanation
    if not _col_exists(conn, "findings", "risk_explanation"):
        op.add_column(
            "findings",
            sa.Column("risk_explanation", sa.Text(), nullable=True),
        )

    # organizations.sla_config
    if not _col_exists(conn, "organizations", "sla_config"):
        op.add_column(
            "organizations",
            sa.Column("sla_config", postgresql.JSONB(), nullable=True),
        )

    # scan_jobs.waf_info
    if not _col_exists(conn, "scan_jobs", "waf_info"):
        op.add_column(
            "scan_jobs",
            sa.Column("waf_info", postgresql.JSONB(), nullable=True),
        )


def downgrade() -> None:
    conn = op.get_bind()

    if _col_exists(conn, "scan_jobs", "waf_info"):
        op.drop_column("scan_jobs", "waf_info")

    if _col_exists(conn, "organizations", "sla_config"):
        op.drop_column("organizations", "sla_config")

    if _col_exists(conn, "findings", "risk_explanation"):
        op.drop_column("findings", "risk_explanation")

    if _col_exists(conn, "findings", "risk_score"):
        op.drop_column("findings", "risk_score")

    if _col_exists(conn, "findings", "compliance_tags"):
        op.drop_column("findings", "compliance_tags")

    if _col_exists(conn, "findings", "sla_deadline"):
        op.drop_column("findings", "sla_deadline")
