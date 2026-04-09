"""add screenshot_url to assets

Revision ID: a3b4c5d6e7f8
Revises: 44ca25037a8b
Create Date: 2026-04-08 21:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

revision = "a3b4c5d6e7f8"
down_revision = "44ca25037a8b"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "assets",
        sa.Column("screenshot_url", sa.String(2048), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("assets", "screenshot_url")
