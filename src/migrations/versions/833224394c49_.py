"""empty message

Revision ID: 833224394c49
Revises: 2da5cc2b5b18
Create Date: 2020-04-03 17:10:46.611249

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import mysql

# revision identifiers, used by Alembic.
revision = '833224394c49'
down_revision = '2da5cc2b5b18'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('wiki', sa.Column('url_', sa.String(length=255), nullable=True))
    op.drop_column('wiki', 'url')
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('wiki', sa.Column('url', mysql.VARCHAR(length=255), nullable=True))
    op.drop_column('wiki', 'url_')
    # ### end Alembic commands ###
