"""Add endpoint asset type

Revision ID: endpoint_asset_type
Revises: due_diligence
Create Date: 2026-04-25
"""
from alembic import op
from sqlalchemy import text

revision = "endpoint_asset_type"
down_revision = "due_diligence"
branch_labels = None
depends_on = None


def upgrade():
    # PostgreSQL requires ALTER TYPE ... ADD VALUE to run outside a transaction
    conn = op.get_bind()
    conn.execute(
        text("ALTER TYPE asset_type ADD VALUE IF NOT EXISTS 'endpoint'")
    )


def downgrade():
    pass  # PostgreSQL does not support removing enum values
