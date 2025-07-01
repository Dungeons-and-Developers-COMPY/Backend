"""Recreate question_stat without encryption

Revision ID: 54211ca6dfaa
Revises: b9b359b664ca
Create Date: 2025-07-01 09:59:30.085306
"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '54211ca6dfaa'
down_revision = 'b9b359b664ca'
branch_labels = None
depends_on = None

def upgrade():
    # Drop the old encrypted table if it exists
    op.drop_table('question_stat')

    # Create the new table without encryption
    op.create_table(
        'question_stat',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('question_id', sa.Integer(), sa.ForeignKey('question.id', ondelete='CASCADE'), nullable=False),
        sa.Column('tag', sa.String(length=100), nullable=False),
        sa.Column('data', sa.JSON(), nullable=False),
        sa.UniqueConstraint('question_id', 'tag', name='uq_stat_qid_tag')
    )

def downgrade():
    # If you ever want to revert this, just drop it
    op.drop_table('question_stat')
