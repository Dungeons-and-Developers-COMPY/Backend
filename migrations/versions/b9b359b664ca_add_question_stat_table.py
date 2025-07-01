"""drop question_stat table

Revision ID: b9b359b664ca
Revises: 9554dff9b37f
Create Date: 2025-07-01 09:01:07.438053
"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'b9b359b664ca'
down_revision = '9554dff9b37f'
branch_labels = None
depends_on = None

def upgrade():
    op.drop_table('question_stat')

def downgrade():
    # You can leave this empty or re-add the table here if you want to restore it later
    pass
