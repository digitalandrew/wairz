import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, LargeBinary, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class FuzzingCampaign(Base):
    __tablename__ = "fuzzing_campaigns"

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
    binary_path: Mapped[str] = mapped_column(String(512), nullable=False)
    status: Mapped[str] = mapped_column(
        String(20), default="created", server_default="created"
    )
    config: Mapped[dict | None] = mapped_column(JSONB, server_default="'{}'")
    stats: Mapped[dict | None] = mapped_column(JSONB, server_default="'{}'")
    crashes_count: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    container_id: Mapped[str | None] = mapped_column(String(100))
    error_message: Mapped[str | None] = mapped_column(Text)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    stopped_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class FuzzingCrash(Base):
    __tablename__ = "fuzzing_crashes"

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True,
        default=uuid.uuid4,
        server_default=func.gen_random_uuid(),
    )
    campaign_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("fuzzing_campaigns.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    crash_filename: Mapped[str] = mapped_column(String(255), nullable=False)
    crash_input: Mapped[bytes | None] = mapped_column(LargeBinary)
    crash_size: Mapped[int | None] = mapped_column(Integer)
    signal: Mapped[str | None] = mapped_column(String(20))
    stack_trace: Mapped[str | None] = mapped_column(Text)
    exploitability: Mapped[str | None] = mapped_column(
        String(30)
    )  # exploitable, probably_exploitable, probably_not, unknown
    triage_output: Mapped[str | None] = mapped_column(Text)
    finding_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("findings.id", ondelete="SET NULL"),
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
