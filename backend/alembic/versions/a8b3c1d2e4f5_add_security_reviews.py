"""add security reviews and review agents tables

Revision ID: a8b3c1d2e4f5
Revises: f356fb45973c
Create Date: 2026-02-14 22:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'a8b3c1d2e4f5'
down_revision: Union[str, None] = 'f356fb45973c'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table('security_reviews',
        sa.Column('id', sa.Uuid(), server_default=sa.text('gen_random_uuid()'), nullable=False),
        sa.Column('project_id', sa.Uuid(), nullable=False),
        sa.Column('status', sa.String(length=20), server_default='pending', nullable=False),
        sa.Column('selected_categories', sa.ARRAY(sa.String()), nullable=False),
        sa.Column('started_at', sa.DateTime(), nullable=True),
        sa.Column('completed_at', sa.DateTime(), nullable=True),
        sa.Column('created_at', sa.DateTime(), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(), server_default=sa.text('now()'), nullable=False),
        sa.ForeignKeyConstraint(['project_id'], ['projects.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_security_reviews_project_id'), 'security_reviews', ['project_id'], unique=False)

    op.create_table('review_agents',
        sa.Column('id', sa.Uuid(), server_default=sa.text('gen_random_uuid()'), nullable=False),
        sa.Column('review_id', sa.Uuid(), nullable=False),
        sa.Column('category', sa.String(length=50), nullable=False),
        sa.Column('status', sa.String(length=20), server_default='pending', nullable=False),
        sa.Column('model', sa.String(length=100), nullable=False),
        sa.Column('conversation_id', sa.Uuid(), nullable=True),
        sa.Column('scratchpad', sa.Text(), nullable=True),
        sa.Column('findings_count', sa.Integer(), server_default='0', nullable=False),
        sa.Column('tool_calls_count', sa.Integer(), server_default='0', nullable=False),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('started_at', sa.DateTime(), nullable=True),
        sa.Column('completed_at', sa.DateTime(), nullable=True),
        sa.Column('created_at', sa.DateTime(), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(), server_default=sa.text('now()'), nullable=False),
        sa.ForeignKeyConstraint(['review_id'], ['security_reviews.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['conversation_id'], ['conversations.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_review_agents_review_id'), 'review_agents', ['review_id'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_review_agents_review_id'), table_name='review_agents')
    op.drop_table('review_agents')
    op.drop_index(op.f('ix_security_reviews_project_id'), table_name='security_reviews')
    op.drop_table('security_reviews')
