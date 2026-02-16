"""add emulation_sessions table

Revision ID: c2d3e4f5a6b7
Revises: b1c2d3e4f5a6
Create Date: 2026-02-15 14:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB


# revision identifiers, used by Alembic.
revision: str = 'c2d3e4f5a6b7'
down_revision: Union[str, None] = 'b1c2d3e4f5a6'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'emulation_sessions',
        sa.Column('id', sa.Uuid(), server_default=sa.text('gen_random_uuid()'), nullable=False),
        sa.Column('project_id', sa.Uuid(), nullable=False),
        sa.Column('firmware_id', sa.Uuid(), nullable=False),
        sa.Column('mode', sa.String(20), nullable=False),
        sa.Column('status', sa.String(20), server_default='created', nullable=False),
        sa.Column('binary_path', sa.String(512), nullable=True),
        sa.Column('arguments', sa.Text(), nullable=True),
        sa.Column('architecture', sa.String(50), nullable=True),
        sa.Column('port_forwards', JSONB, server_default=sa.text("'[]'::jsonb"), nullable=True),
        sa.Column('container_id', sa.String(100), nullable=True),
        sa.Column('pid', sa.Integer(), nullable=True),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('stopped_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(['project_id'], ['projects.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['firmware_id'], ['firmware.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('idx_emulation_project', 'emulation_sessions', ['project_id'])
    op.create_index('idx_emulation_status', 'emulation_sessions', ['status'])


def downgrade() -> None:
    op.drop_index('idx_emulation_status', table_name='emulation_sessions')
    op.drop_index('idx_emulation_project', table_name='emulation_sessions')
    op.drop_table('emulation_sessions')
