"""Add tool_permissions to org_members

Revision ID: tool_permissions
Revises: msra_findings_source
Create Date: 2026-04-24 00:01:00.000000
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy import text
from sqlalchemy.dialects import postgresql

revision = "tool_permissions"
down_revision = "msra_findings_source"
branch_labels = None
depends_on = None


def _col_exists(conn, table: str, column: str) -> bool:
    result = conn.execute(
        text(
            "SELECT 1 FROM information_schema.columns "
            "WHERE table_name=:t AND column_name=:c"
        ),
        {"t": table, "c": column},
    )
    return result.scalar() is not None


def upgrade() -> None:
    conn = op.get_bind()
    if not _col_exists(conn, "org_members", "tool_permissions"):
        op.add_column(
            "org_members",
            sa.Column(
                "tool_permissions",
                postgresql.ARRAY(sa.String(50)),
                nullable=True,
            ),
        )


def downgrade() -> None:
    conn = op.get_bind()
    if _col_exists(conn, "org_members", "tool_permissions"):
        op.drop_column("org_members", "tool_permissions")
