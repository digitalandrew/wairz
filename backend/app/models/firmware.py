import uuid
from datetime import datetime

from sqlalchemy import BigInteger, ForeignKey, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class Firmware(Base):
    __tablename__ = "firmware"

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True,
        default=uuid.uuid4,
        server_default=func.gen_random_uuid(),
    )
    project_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"),
        nullable=False,
    )
    original_filename: Mapped[str | None] = mapped_column(String(255))
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    file_size: Mapped[int | None] = mapped_column(BigInteger)
    storage_path: Mapped[str | None] = mapped_column(String(512))
    extracted_path: Mapped[str | None] = mapped_column(String(512))
    architecture: Mapped[str | None] = mapped_column(String(50))
    endianness: Mapped[str | None] = mapped_column(String(10))
    os_info: Mapped[str | None] = mapped_column(Text)
    kernel_path: Mapped[str | None] = mapped_column(String(512))
    unpack_log: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())

    project: Mapped["Project"] = relationship(back_populates="firmware")  # noqa: F821
