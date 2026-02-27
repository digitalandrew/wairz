"""Add uart_sessions table

Revision ID: e5f6a7b8c9d0
Revises: d4e5f6a7b8c9
Create Date: 2026-02-27 12:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "e5f6a7b8c9d0"
down_revision: Union[str, None] = "d4e5f6a7b8c9"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "uart_sessions",
        sa.Column("id", sa.Uuid(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("project_id", sa.Uuid(), nullable=False),
        sa.Column("firmware_id", sa.Uuid(), nullable=False),
        sa.Column("device_path", sa.String(255), nullable=False),
        sa.Column("baudrate", sa.Integer(), server_default="115200", nullable=False),
        sa.Column("status", sa.String(20), server_default="created", nullable=False),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("transcript_path", sa.String(512), nullable=True),
        sa.Column("connected_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("closed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["firmware_id"], ["firmware.id"], ondelete="CASCADE"),
    )
    op.create_index("ix_uart_sessions_project_id", "uart_sessions", ["project_id"])


def downgrade() -> None:
    op.drop_index("ix_uart_sessions_project_id", table_name="uart_sessions")
    op.drop_table("uart_sessions")
