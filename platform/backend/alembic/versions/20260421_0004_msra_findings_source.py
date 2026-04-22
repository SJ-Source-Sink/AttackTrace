"""Add source/source_scan_id to findings, make scan_job_id nullable for MSRA

Revision ID: msra_findings_source
Revises: data_layer_phase2
Create Date: 2026-04-21 00:04:00.000000

Changes:
- findings.scan_job_id: NOT NULL → nullable (MSRA findings have no AttackTrace scan job)
- findings.source VARCHAR(32) DEFAULT 'attacktrace' NOT NULL
- findings.source_scan_id VARCHAR(64) nullable (MSRA scan_id reference)
- Index on findings.source and findings.source_scan_id
"""

from alembic import op
import sqlalchemy as sa

revision = "msra_findings_source"
down_revision = "data_layer_phase2"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # 1. Drop the NOT NULL constraint on scan_job_id
    op.alter_column("findings", "scan_job_id", existing_type=sa.dialects.postgresql.UUID(as_uuid=True), nullable=True)

    # 2. Add source column (default attacktrace for all existing rows)
    op.add_column("findings", sa.Column("source", sa.String(32), nullable=False, server_default="attacktrace"))

    # 3. Add source_scan_id column
    op.add_column("findings", sa.Column("source_scan_id", sa.String(64), nullable=True))

    # 4. Indexes
    op.create_index("ix_findings_source", "findings", ["source"])
    op.create_index("ix_findings_source_scan_id", "findings", ["source_scan_id"])


def downgrade() -> None:
    op.drop_index("ix_findings_source_scan_id", table_name="findings")
    op.drop_index("ix_findings_source", table_name="findings")
    op.drop_column("findings", "source_scan_id")
    op.drop_column("findings", "source")
    op.alter_column("findings", "scan_job_id", existing_type=sa.dialects.postgresql.UUID(as_uuid=True), nullable=False)
