import uuid
from datetime import datetime

from sqlalchemy import ForeignKey, Index, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class AnalysisCache(Base):
    __tablename__ = "analysis_cache"

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True,
        default=uuid.uuid4,
        server_default=func.gen_random_uuid(),
    )
    firmware_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("firmware.id", ondelete="CASCADE"),
        nullable=False,
    )
    binary_path: Mapped[str | None] = mapped_column(String(512))
    binary_sha256: Mapped[str | None] = mapped_column(String(64))
    operation: Mapped[str] = mapped_column(String(100), nullable=False)
    result: Mapped[dict | None] = mapped_column(JSONB)
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())

    __table_args__ = (
        Index(
            "idx_cache_lookup",
            "firmware_id",
            "binary_sha256",
            "operation",
        ),
    )
