"""add vuln resolution and ai severity

Revision ID: f6a7b8c9d0e1
Revises: e5f6a7b8c9d0
Create Date: 2026-02-28 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "f6a7b8c9d0e1"
down_revision: Union[str, None] = "e5f6a7b8c9d0"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "sbom_vulnerabilities",
        sa.Column(
            "resolution_status",
            sa.String(20),
            server_default="open",
            nullable=False,
        ),
    )
    op.add_column(
        "sbom_vulnerabilities",
        sa.Column("resolution_justification", sa.Text(), nullable=True),
    )
    op.add_column(
        "sbom_vulnerabilities",
        sa.Column("resolved_by", sa.String(50), nullable=True),
    )
    op.add_column(
        "sbom_vulnerabilities",
        sa.Column("resolved_at", sa.DateTime(), nullable=True),
    )
    op.add_column(
        "sbom_vulnerabilities",
        sa.Column("adjusted_cvss_score", sa.Numeric(3, 1), nullable=True),
    )
    op.add_column(
        "sbom_vulnerabilities",
        sa.Column("adjusted_severity", sa.String(20), nullable=True),
    )
    op.add_column(
        "sbom_vulnerabilities",
        sa.Column("adjustment_rationale", sa.Text(), nullable=True),
    )
    op.create_index(
        "idx_sbom_vulns_resolution",
        "sbom_vulnerabilities",
        ["resolution_status"],
    )


def downgrade() -> None:
    op.drop_index("idx_sbom_vulns_resolution", table_name="sbom_vulnerabilities")
    op.drop_column("sbom_vulnerabilities", "adjustment_rationale")
    op.drop_column("sbom_vulnerabilities", "adjusted_severity")
    op.drop_column("sbom_vulnerabilities", "adjusted_cvss_score")
    op.drop_column("sbom_vulnerabilities", "resolved_at")
    op.drop_column("sbom_vulnerabilities", "resolved_by")
    op.drop_column("sbom_vulnerabilities", "resolution_justification")
    op.drop_column("sbom_vulnerabilities", "resolution_status")
