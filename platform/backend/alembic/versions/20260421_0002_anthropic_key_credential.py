"""add anthropic_key_enc to org_credentials

Revision ID: anthropic_key_credential
Revises: composite_indexes
Create Date: 2026-04-21 00:02:00.000000

"""
from alembic import op
import sqlalchemy as sa

revision = "anthropic_key_credential"
down_revision = "composite_indexes"
branch_labels = None
depends_on = None


def _col_exists(conn, table, col):
    result = conn.execute(
        sa.text(
            "SELECT 1 FROM information_schema.columns WHERE table_name=:t AND column_name=:c"
        ),
        {"t": table, "c": col},
    )
    return result.scalar() is not None


def upgrade() -> None:
    conn = op.get_bind()
    if not _col_exists(conn, "org_credentials", "anthropic_key_enc"):
        op.add_column(
            "org_credentials",
            sa.Column("anthropic_key_enc", sa.Text(), nullable=True),
        )


def downgrade() -> None:
    op.drop_column("org_credentials", "anthropic_key_enc")
