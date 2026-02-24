"""Deduplicate analysis_cache and add unique index

Revision ID: b2c3d4e5f6a7
Revises: a1b2c3d4e5f6
Create Date: 2026-02-22 12:00:00.000000

"""
from typing import Sequence, Union

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "b2c3d4e5f6a7"
down_revision: Union[str, None] = "a1b2c3d4e5f6"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Deduplicate existing rows: keep the newest per (firmware_id, binary_sha256, operation)
    op.execute("""
        DELETE FROM analysis_cache
        WHERE id NOT IN (
            SELECT DISTINCT ON (firmware_id, binary_sha256, operation) id
            FROM analysis_cache
            ORDER BY firmware_id, binary_sha256, operation, created_at DESC
        )
    """)

    # 2. Drop the old non-unique index
    op.drop_index("idx_cache_lookup", table_name="analysis_cache")

    # 3. Create a unique index on the same columns
    op.create_index(
        "idx_cache_lookup",
        "analysis_cache",
        ["firmware_id", "binary_sha256", "operation"],
        unique=True,
    )


def downgrade() -> None:
    # Revert to non-unique index
    op.drop_index("idx_cache_lookup", table_name="analysis_cache")
    op.create_index(
        "idx_cache_lookup",
        "analysis_cache",
        ["firmware_id", "binary_sha256", "operation"],
        unique=False,
    )
