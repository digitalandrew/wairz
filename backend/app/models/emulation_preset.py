import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class EmulationPreset(Base):
    __tablename__ = "emulation_presets"

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True,
        default=uuid.uuid4,
        server_default=func.gen_random_uuid(),
    )
    project_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    mode: Mapped[str] = mapped_column(String(20), nullable=False)
    binary_path: Mapped[str | None] = mapped_column(String(512))
    arguments: Mapped[str | None] = mapped_column(Text)
    architecture: Mapped[str | None] = mapped_column(String(50))
    port_forwards: Mapped[dict | None] = mapped_column(JSONB, server_default="'[]'")
    kernel_name: Mapped[str | None] = mapped_column(String(255))
    init_path: Mapped[str | None] = mapped_column(String(512))
    pre_init_script: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
