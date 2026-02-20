"""add fuzzing tables

Revision ID: e4f5a6b7c8d9
Revises: d3e4f5a6b7c8
Create Date: 2026-02-19 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "e4f5a6b7c8d9"
down_revision: Union[str, None] = "d3e4f5a6b7c8"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "fuzzing_campaigns",
        sa.Column("id", sa.Uuid(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("project_id", sa.Uuid(), nullable=False),
        sa.Column("firmware_id", sa.Uuid(), nullable=False),
        sa.Column("binary_path", sa.String(512), nullable=False),
        sa.Column("status", sa.String(20), server_default="created", nullable=False),
        sa.Column("config", postgresql.JSONB(), server_default="'{}'", nullable=True),
        sa.Column("stats", postgresql.JSONB(), server_default="'{}'", nullable=True),
        sa.Column("crashes_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("container_id", sa.String(100), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("stopped_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["firmware_id"], ["firmware.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_fuzzing_campaigns_project_id", "fuzzing_campaigns", ["project_id"])

    op.create_table(
        "fuzzing_crashes",
        sa.Column("id", sa.Uuid(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("campaign_id", sa.Uuid(), nullable=False),
        sa.Column("crash_filename", sa.String(255), nullable=False),
        sa.Column("crash_input", sa.LargeBinary(), nullable=True),
        sa.Column("crash_size", sa.Integer(), nullable=True),
        sa.Column("signal", sa.String(20), nullable=True),
        sa.Column("stack_trace", sa.Text(), nullable=True),
        sa.Column("exploitability", sa.String(30), nullable=True),
        sa.Column("triage_output", sa.Text(), nullable=True),
        sa.Column("finding_id", sa.Uuid(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["campaign_id"], ["fuzzing_campaigns.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["finding_id"], ["findings.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_fuzzing_crashes_campaign_id", "fuzzing_crashes", ["campaign_id"])


def downgrade() -> None:
    op.drop_table("fuzzing_crashes")
    op.drop_table("fuzzing_campaigns")
