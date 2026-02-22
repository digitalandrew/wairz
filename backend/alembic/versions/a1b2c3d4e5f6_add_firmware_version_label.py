"""add firmware version_label and project_id index

Revision ID: a1b2c3d4e5f6
Revises: f5a6b7c8d9e0
Create Date: 2026-02-22 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "a1b2c3d4e5f6"
down_revision: Union[str, None] = "f5a6b7c8d9e0"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("firmware", sa.Column("version_label", sa.String(100), nullable=True))
    op.create_index("ix_firmware_project_id", "firmware", ["project_id"])


def downgrade() -> None:
    op.drop_index("ix_firmware_project_id", table_name="firmware")
    op.drop_column("firmware", "version_label")
