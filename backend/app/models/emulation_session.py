import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class EmulationSession(Base):
    __tablename__ = "emulation_sessions"

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
    firmware_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("firmware.id", ondelete="CASCADE"),
        nullable=False,
    )
    mode: Mapped[str] = mapped_column(String(20), nullable=False)
    status: Mapped[str] = mapped_column(
        String(20), default="created", server_default="created"
    )
    binary_path: Mapped[str | None] = mapped_column(String(512))
    arguments: Mapped[str | None] = mapped_column(Text)
    architecture: Mapped[str | None] = mapped_column(String(50))
    port_forwards: Mapped[dict | None] = mapped_column(JSONB, server_default="'[]'")
    container_id: Mapped[str | None] = mapped_column(String(100))
    pid: Mapped[int | None] = mapped_column(Integer)
    error_message: Mapped[str | None] = mapped_column(Text)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    stopped_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
