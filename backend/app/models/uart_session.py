import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class UARTSession(Base):
    __tablename__ = "uart_sessions"

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
    device_path: Mapped[str] = mapped_column(String(255), nullable=False)
    baudrate: Mapped[int] = mapped_column(Integer, default=115200, server_default="115200")
    status: Mapped[str] = mapped_column(
        String(20), default="created", server_default="created"
    )
    error_message: Mapped[str | None] = mapped_column(Text)
    transcript_path: Mapped[str | None] = mapped_column(String(512))
    connected_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
