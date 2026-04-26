"""Add notification_channels table

Revision ID: notification_channels
Revises: scheduled_scans
Create Date: 2026-04-25
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy import text
from sqlalchemy.dialects import postgresql

revision = "notification_channels"
down_revision = "scheduled_scans"
branch_labels = None
depends_on = None


def _table_exists(conn, name):
    return conn.execute(
        text("SELECT 1 FROM information_schema.tables WHERE table_name=:n"), {"n": name}
    ).scalar() is not None


def upgrade():
    conn = op.get_bind()
    if not _table_exists(conn, "notification_channels"):
        op.create_table(
            "notification_channels",
            sa.Column(
                "id",
                postgresql.UUID(as_uuid=True),
                primary_key=True,
                server_default=sa.text("gen_random_uuid()"),
            ),
            sa.Column(
                "org_id",
                postgresql.UUID(as_uuid=True),
                sa.ForeignKey("organizations.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column("name", sa.String(255), nullable=False),
            sa.Column("channel_type", sa.String(20), nullable=False),
            sa.Column("config_enc", sa.Text(), nullable=True),
            sa.Column(
                "is_active",
                sa.Boolean(),
                nullable=False,
                server_default="true",
            ),
            sa.Column(
                "events",
                postgresql.ARRAY(sa.String(50)),
                nullable=False,
                server_default="{}",
            ),
            sa.Column(
                "created_at",
                sa.TIMESTAMP(timezone=True),
                nullable=False,
                server_default=sa.text("now()"),
            ),
            sa.Column(
                "updated_at",
                sa.TIMESTAMP(timezone=True),
                nullable=False,
                server_default=sa.text("now()"),
            ),
        )
        op.create_index(
            "ix_notification_channels_org_id", "notification_channels", ["org_id"]
        )


def downgrade():
    conn = op.get_bind()
    if _table_exists(conn, "notification_channels"):
        op.drop_table("notification_channels")
