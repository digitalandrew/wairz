import uuid
from datetime import datetime

from sqlalchemy import ForeignKey, Index, Numeric, String, Text, func, text
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class SbomComponent(Base):
    __tablename__ = "sbom_components"

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True,
        default=uuid.uuid4,
        server_default=func.gen_random_uuid(),
    )
    firmware_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("firmware.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    version: Mapped[str | None] = mapped_column(String(100))
    type: Mapped[str] = mapped_column(String(50), nullable=False)
    cpe: Mapped[str | None] = mapped_column(String(255))
    purl: Mapped[str | None] = mapped_column(String(512))
    supplier: Mapped[str | None] = mapped_column(String(255))
    detection_source: Mapped[str] = mapped_column(String(100), nullable=False)
    detection_confidence: Mapped[str | None] = mapped_column(String(20))
    file_paths: Mapped[list[str] | None] = mapped_column(ARRAY(Text))
    metadata_: Mapped[dict] = mapped_column(
        "metadata", JSONB, server_default=text("'{}'")
    )
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())

    vulnerabilities: Mapped[list["SbomVulnerability"]] = relationship(
        back_populates="component", cascade="all, delete-orphan"
    )


class SbomVulnerability(Base):
    __tablename__ = "sbom_vulnerabilities"

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True,
        default=uuid.uuid4,
        server_default=func.gen_random_uuid(),
    )
    component_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("sbom_components.id", ondelete="CASCADE"),
        nullable=False,
    )
    firmware_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("firmware.id", ondelete="CASCADE"),
        nullable=False,
    )
    cve_id: Mapped[str] = mapped_column(String(20), nullable=False)
    cvss_score: Mapped[float | None] = mapped_column(Numeric(3, 1))
    cvss_vector: Mapped[str | None] = mapped_column(String(255))
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    published_date: Mapped[datetime | None] = mapped_column()
    finding_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("findings.id", ondelete="SET NULL"),
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())

    component: Mapped["SbomComponent"] = relationship(back_populates="vulnerabilities")

    __table_args__ = (
        Index("idx_sbom_vulns_component", "component_id"),
        Index("idx_sbom_vulns_firmware", "firmware_id"),
        Index("idx_sbom_vulns_cve", "cve_id"),
    )
