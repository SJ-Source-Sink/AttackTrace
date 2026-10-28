"""widen findings.title / affected_asset to TEXT

The ORM models declare these as Text but the schema was created as VARCHAR(512), so a
finding with a long title or URL (common for scanner output) failed on insert. Widening
VARCHAR -> TEXT is lossless and needs no data rewrite beyond the type change.

Not included on purpose: the other differences `alembic revision --autogenerate` reports
(server defaults and indexes) are cases where the database is *ahead* of the models, so
applying them would remove defaults/indexes that are useful.

Revision ID: widen_finding_text_001
Revises: sla_breach_notified_001
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "widen_finding_text_001"
down_revision: Union[str, None] = "sla_breach_notified_001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    for col in ("title", "affected_asset"):
        op.alter_column(
            "findings", col,
            existing_type=sa.VARCHAR(length=512), type_=sa.Text(), existing_nullable=False,
        )


def downgrade() -> None:
    # Truncates anything over 512 chars, which is the pre-migration limit.
    for col in ("title", "affected_asset"):
        op.alter_column(
            "findings", col,
            existing_type=sa.Text(), type_=sa.VARCHAR(length=512), existing_nullable=False,
            postgresql_using=f"left({col}, 512)",
        )
