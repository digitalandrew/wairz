"""add sbom_components and sbom_vulnerabilities tables, add source/component_id to findings

Revision ID: b1c2d3e4f5a6
Revises: a8b3c1d2e4f5
Create Date: 2026-02-15 10:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB


# revision identifiers, used by Alembic.
revision: str = 'b1c2d3e4f5a6'
down_revision: Union[str, None] = 'a8b3c1d2e4f5'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # sbom_components table
    op.create_table(
        'sbom_components',
        sa.Column('id', sa.Uuid(), server_default=sa.text('gen_random_uuid()'), nullable=False),
        sa.Column('firmware_id', sa.Uuid(), nullable=False),
        sa.Column('name', sa.String(255), nullable=False),
        sa.Column('version', sa.String(100), nullable=True),
        sa.Column('type', sa.String(50), nullable=False),
        sa.Column('cpe', sa.String(255), nullable=True),
        sa.Column('purl', sa.String(512), nullable=True),
        sa.Column('supplier', sa.String(255), nullable=True),
        sa.Column('detection_source', sa.String(100), nullable=False),
        sa.Column('detection_confidence', sa.String(20), nullable=True),
        sa.Column('file_paths', sa.ARRAY(sa.Text()), nullable=True),
        sa.Column('metadata', JSONB, server_default=sa.text("'{}'"), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(['firmware_id'], ['firmware.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('idx_sbom_firmware', 'sbom_components', ['firmware_id'])

    # sbom_vulnerabilities table
    op.create_table(
        'sbom_vulnerabilities',
        sa.Column('id', sa.Uuid(), server_default=sa.text('gen_random_uuid()'), nullable=False),
        sa.Column('component_id', sa.Uuid(), nullable=False),
        sa.Column('firmware_id', sa.Uuid(), nullable=False),
        sa.Column('cve_id', sa.String(20), nullable=False),
        sa.Column('cvss_score', sa.Numeric(3, 1), nullable=True),
        sa.Column('cvss_vector', sa.String(255), nullable=True),
        sa.Column('severity', sa.String(20), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('published_date', sa.DateTime(timezone=True), nullable=True),
        sa.Column('finding_id', sa.Uuid(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(['component_id'], ['sbom_components.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['firmware_id'], ['firmware.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['finding_id'], ['findings.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('idx_sbom_vulns_component', 'sbom_vulnerabilities', ['component_id'])
    op.create_index('idx_sbom_vulns_firmware', 'sbom_vulnerabilities', ['firmware_id'])
    op.create_index('idx_sbom_vulns_cve', 'sbom_vulnerabilities', ['cve_id'])

    # Add source and component_id columns to findings
    op.add_column('findings', sa.Column('source', sa.String(50), server_default='manual', nullable=True))
    op.add_column('findings', sa.Column('component_id', sa.Uuid(), nullable=True))
    op.create_foreign_key(
        'fk_findings_component_id',
        'findings', 'sbom_components',
        ['component_id'], ['id'],
        ondelete='SET NULL',
    )
    op.create_index('idx_findings_source', 'findings', ['source'])


def downgrade() -> None:
    op.drop_index('idx_findings_source', table_name='findings')
    op.drop_constraint('fk_findings_component_id', 'findings', type_='foreignkey')
    op.drop_column('findings', 'component_id')
    op.drop_column('findings', 'source')
    op.drop_index('idx_sbom_vulns_cve', table_name='sbom_vulnerabilities')
    op.drop_index('idx_sbom_vulns_firmware', table_name='sbom_vulnerabilities')
    op.drop_index('idx_sbom_vulns_component', table_name='sbom_vulnerabilities')
    op.drop_table('sbom_vulnerabilities')
    op.drop_index('idx_sbom_firmware', table_name='sbom_components')
    op.drop_table('sbom_components')
