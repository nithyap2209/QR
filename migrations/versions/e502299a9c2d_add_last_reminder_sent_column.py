"""add last reminder sent column

Revision ID: e502299a9c2d
Revises: 410e0d0ed473
Create Date: 2025-05-21 12:39:19.706650

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'e502299a9c2d'
down_revision = '410e0d0ed473'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('subscribed_users', schema=None) as batch_op:
        batch_op.add_column(sa.Column('last_reminder_sent', sa.DateTime(), nullable=True))

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('subscribed_users', schema=None) as batch_op:
        batch_op.drop_column('last_reminder_sent')

    # ### end Alembic commands ###
