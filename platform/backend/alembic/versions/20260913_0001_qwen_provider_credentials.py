"""add ai_provider + qwen credential fields to org_credentials

Revision ID: qwen_provider_credentials
Revises: asset_snapshots_001
Create Date: 2026-09-13 00:01:00.000000

"""
from alembic import op
import sqlalchemy as sa

revision = "qwen_provider_credentials"
down_revision = "asset_snapshots_001"
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
    if not _col_exists(conn, "org_credentials", "ai_provider"):
        op.add_column(
            "org_credentials",
            sa.Column("ai_provider", sa.String(20), nullable=True),
        )
    if not _col_exists(conn, "org_credentials", "qwen_base_url_enc"):
        op.add_column(
            "org_credentials",
            sa.Column("qwen_base_url_enc", sa.Text(), nullable=True),
        )
    if not _col_exists(conn, "org_credentials", "qwen_api_key_enc"):
        op.add_column(
            "org_credentials",
            sa.Column("qwen_api_key_enc", sa.Text(), nullable=True),
        )
    if not _col_exists(conn, "org_credentials", "qwen_model_enc"):
        op.add_column(
            "org_credentials",
            sa.Column("qwen_model_enc", sa.Text(), nullable=True),
        )


def downgrade() -> None:
    op.drop_column("org_credentials", "qwen_model_enc")
    op.drop_column("org_credentials", "qwen_api_key_enc")
    op.drop_column("org_credentials", "qwen_base_url_enc")
    op.drop_column("org_credentials", "ai_provider")
