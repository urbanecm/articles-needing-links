"""empty message

Revision ID: ccee79dfd336
Revises: 833224394c49
Create Date: 2020-04-03 18:51:40.607152

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'ccee79dfd336'
down_revision = '833224394c49'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('wiki', sa.Column('minimum_length', sa.Integer(), nullable=True))
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('wiki', 'minimum_length')
    # ### end Alembic commands ###