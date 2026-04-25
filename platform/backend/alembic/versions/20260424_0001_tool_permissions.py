"""Add tool_permissions to org_members

Revision ID: tool_permissions
Revises: msra_findings_source
Create Date: 2026-04-24 00:01:00.000000
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "tool_permissions"
down_revision = "msra_findings_source"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "org_members",
        sa.Column(
            "tool_permissions",
            postgresql.ARRAY(sa.String(50)),
            nullable=True,
        ),
    )


def downgrade() -> None:
    op.drop_column("org_members", "tool_permissions")
