"""Add passive_due_diligence scan intensity

Revision ID: due_diligence
Revises: notification_channels
Create Date: 2026-04-25
"""
from alembic import op
from sqlalchemy import text

revision = "due_diligence"
down_revision = "scan_diffs"
branch_labels = None
depends_on = None


def upgrade():
    # PostgreSQL requires ALTER TYPE ... ADD VALUE to run outside a transaction
    conn = op.get_bind()
    conn.execute(
        text("ALTER TYPE scan_intensity ADD VALUE IF NOT EXISTS 'passive_due_diligence'")
    )


def downgrade():
    pass  # PostgreSQL does not support removing enum values
