"""cascade delete assets when scan is deleted

Revision ID: cascade_assets_scan
Revises: a3b4c5d6e7f8
Create Date: 2026-04-09 00:00:00.000000

"""
from alembic import op

revision = "cascade_assets_scan"
down_revision = "a3b4c5d6e7f8"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Drop old SET NULL constraint, replace with CASCADE
    op.drop_constraint("assets_scan_job_id_fkey", "assets", type_="foreignkey")
    op.create_foreign_key(
        "assets_scan_job_id_fkey",
        "assets",
        "scan_jobs",
        ["scan_job_id"],
        ["id"],
        ondelete="CASCADE",
    )


def downgrade() -> None:
    op.drop_constraint("assets_scan_job_id_fkey", "assets", type_="foreignkey")
    op.create_foreign_key(
        "assets_scan_job_id_fkey",
        "assets",
        "scan_jobs",
        ["scan_job_id"],
        ["id"],
        ondelete="SET NULL",
    )
