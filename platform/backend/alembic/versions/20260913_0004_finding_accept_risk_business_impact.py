"""Add accept_risk_info and ai_business_impact columns to findings

Revision ID: finding_accept_risk_001
Revises: msra_scan_ownership_001
Create Date: 2026-09-13

Changes:
- findings.accept_risk_info (JSONB, nullable): the "Accept Risk" workflow
  (components/findings/status-workflow.tsx) built and sent a
  {reason, expires_at, approver} payload via PATCH /findings/{id} that had
  nowhere to land — FindingUpdate had no matching field, so Pydantic
  silently dropped it and FindingResponse.from_orm hardcoded
  accept_risk_info=None on every response. This column, populated in
  app/api/v1/findings.py::update_finding (server adds accepted_at/
  accepted_by), fixes that round-trip.
- findings.ai_business_impact (Text, nullable): AI Triage's "Business
  Impact" field was hardcoded to "" in FindingResponse.from_orm even though
  nothing ever generated or stored one. app/services/ai_service.py's
  triage_finding prompt now asks for a business_impact string in the same
  triage call, persisted here by app/api/v1/ai.py's triage endpoint and
  app/workers/scan_worker.py's bulk-triage path.
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "finding_accept_risk_001"
down_revision = "msra_scan_ownership_001"
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
    if not _column_exists(conn, "findings", "accept_risk_info"):
        op.add_column(
            "findings",
            sa.Column("accept_risk_info", postgresql.JSONB(), nullable=True),
        )
    if not _column_exists(conn, "findings", "ai_business_impact"):
        op.add_column(
            "findings",
            sa.Column("ai_business_impact", sa.Text(), nullable=True),
        )


def downgrade() -> None:
    conn = op.get_bind()
    if _column_exists(conn, "findings", "ai_business_impact"):
        op.drop_column("findings", "ai_business_impact")
    if _column_exists(conn, "findings", "accept_risk_info"):
        op.drop_column("findings", "accept_risk_info")
