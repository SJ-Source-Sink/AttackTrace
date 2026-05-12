"""add assigned_to to findings

Revision ID: add_assigned_to_findings
Revises: 6707d00cd96d
Create Date: 2026-05-12 00:01:00.000000+00:00

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = 'add_assigned_to_findings'
down_revision: Union[str, None] = '6707d00cd96d'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        'findings',
        sa.Column('assigned_to', postgresql.UUID(as_uuid=True), nullable=True)
    )
    op.create_foreign_key(
        'fk_findings_assigned_to',
        'findings', 'users',
        ['assigned_to'], ['id'],
        ondelete='SET NULL',
    )
    op.create_index('idx_finding_assigned_to', 'findings', ['assigned_to'], unique=False)


def downgrade() -> None:
    op.drop_index('idx_finding_assigned_to', table_name='findings')
    op.drop_constraint('fk_findings_assigned_to', 'findings', type_='foreignkey')
    op.drop_column('findings', 'assigned_to')
