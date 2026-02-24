"""Add stub_profile to emulation_presets

Revision ID: c3d4e5f6a7b8
Revises: b2c3d4e5f6a7
Create Date: 2026-02-24 12:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "c3d4e5f6a7b8"
down_revision: Union[str, None] = "b2c3d4e5f6a7"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "emulation_presets",
        sa.Column(
            "stub_profile",
            sa.String(50),
            nullable=False,
            server_default="none",
        ),
    )


def downgrade() -> None:
    op.drop_column("emulation_presets", "stub_profile")
