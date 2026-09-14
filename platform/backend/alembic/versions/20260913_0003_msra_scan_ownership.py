"""Add msra_scan_ownership table for MSRA sidecar tenant isolation

Revision ID: msra_scan_ownership_001
Revises: qwen_provider_credentials
Create Date: 2026-09-13

Changes:
- Add msra_scan_ownership: maps an MSRA sidecar scan_id (MSRA has no org/
  tenant concept of its own — it's a single global Flask service, scan_ids
  are `uuid.uuid4().hex[:12]` with no namespacing) to the AttackTrace org_id
  that created it. Recorded once, at upload time, by
  app/api/v1/mobile.py::upload_file(). Every other proxied route that takes
  a scan_id checks ownership here before forwarding to MSRA, and the
  MSRA -> Finding sync only ingests scans present in this table for the
  calling org — closing a cross-org data leak/IDOR where any org could
  read, modify, delete, or silently absorb into its own Finding table any
  other org's mobile-pentest scan data.
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "msra_scan_ownership_001"
down_revision = "qwen_provider_credentials"
branch_labels = None
depends_on = None


def _table_exists(conn, table: str) -> bool:
    result = conn.execute(
        sa.text("SELECT 1 FROM information_schema.tables WHERE table_name=:t"), {"t": table}
    )
    return result.scalar() is not None


def upgrade() -> None:
    conn = op.get_bind()
    if not _table_exists(conn, "msra_scan_ownership"):
        op.create_table(
            "msra_scan_ownership",
            # MSRA's own scan_id (12 hex chars) — globally unique within MSRA,
            # so it's also our primary key: first org to create a given
            # scan_id claims it exactly once.
            sa.Column("msra_scan_id", sa.String(64), primary_key=True),
            sa.Column("org_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        )
        op.create_index("ix_msra_scan_ownership_org_id", "msra_scan_ownership", ["org_id"])


def downgrade() -> None:
    conn = op.get_bind()
    if _table_exists(conn, "msra_scan_ownership"):
        op.drop_table("msra_scan_ownership")
