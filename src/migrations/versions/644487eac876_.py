"""empty message

Revision ID: 644487eac876
Revises: c4ccac140986
Create Date: 2020-04-03 20:33:39.549659

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '644487eac876'
down_revision = 'c4ccac140986'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('wiki', sa.Column('tolerance', sa.Integer(), nullable=True))
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('wiki', 'tolerance')
    # ### end Alembic commands ###
