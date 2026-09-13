"""Add MFA (TOTP) columns to users

Revision ID: mfa_columns_001
Revises: ai_gateway_config_001
Create Date: 2026-09-13

Changes:
- Add totp_secret_enc: encrypted TOTP secret (Fernet, via app.core.security)
- Add mfa_enabled: whether the user has completed MFA enrollment
- Add mfa_backup_codes_enc: encrypted JSON array of one-time backup codes
"""

from alembic import op
import sqlalchemy as sa

revision = "mfa_columns_001"
down_revision = "ai_gateway_config_001"
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
    if not _col_exists(conn, "users", "totp_secret_enc"):
        op.add_column("users", sa.Column("totp_secret_enc", sa.String(512), nullable=True))
    if not _col_exists(conn, "users", "mfa_enabled"):
        op.add_column(
            "users",
            sa.Column("mfa_enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
        )
    if not _col_exists(conn, "users", "mfa_backup_codes_enc"):
        op.add_column("users", sa.Column("mfa_backup_codes_enc", sa.String(2048), nullable=True))


def downgrade() -> None:
    op.drop_column("users", "mfa_backup_codes_enc")
    op.drop_column("users", "mfa_enabled")
    op.drop_column("users", "totp_secret_enc")
