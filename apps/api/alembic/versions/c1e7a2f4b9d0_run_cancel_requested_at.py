"""run.cancel_requested_at

Durable cancellation flag so cancel works without Redis (embedded/desktop mode).

Revision ID: c1e7a2f4b9d0
Revises: d7570e0e6785
Create Date: 2026-06-07 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'c1e7a2f4b9d0'
down_revision: Union[str, Sequence[str], None] = 'd7570e0e6785'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table('run', schema=None) as batch_op:
        batch_op.add_column(sa.Column('cancel_requested_at', sa.DateTime(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table('run', schema=None) as batch_op:
        batch_op.drop_column('cancel_requested_at')
