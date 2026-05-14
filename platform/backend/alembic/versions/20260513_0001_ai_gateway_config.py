"""Add AI gateway config columns to org_credentials

Revision ID: ai_gateway_config_001
Revises: enterprise_hardening_001
Create Date: 2026-05-13

Changes:
- Add ai_base_url_enc: encrypted custom API gateway URL (Bedrock proxy or any Anthropic-compatible gateway)
- Add ai_model_override_enc: encrypted optional model ID override
"""

from alembic import op
import sqlalchemy as sa

revision = "ai_gateway_config_001"
down_revision = "enterprise_hardening_001"
branch_labels = None
depends_on = None


def _col_exists(conn, table: str, col: str) -> bool:
    result = conn.execute(
        sa.text(
            "SELECT 1 FROM information_schema.columns "
            "WHERE table_name = :t AND column_name = :c"
        ),
        {"t": table, "c": col},
    )
    return result.fetchone() is not None


def upgrade() -> None:
    conn = op.get_bind()
    if not _col_exists(conn, "org_credentials", "ai_base_url_enc"):
        op.add_column("org_credentials", sa.Column("ai_base_url_enc", sa.Text(), nullable=True))
    if not _col_exists(conn, "org_credentials", "ai_model_override_enc"):
        op.add_column("org_credentials", sa.Column("ai_model_override_enc", sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column("org_credentials", "ai_base_url_enc")
    op.drop_column("org_credentials", "ai_model_override_enc")
