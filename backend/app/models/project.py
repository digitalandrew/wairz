import uuid
from datetime import datetime

from sqlalchemy import String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class Project(Base):
    __tablename__ = "projects"

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True,
        default=uuid.uuid4,
        server_default=func.gen_random_uuid(),
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(50), default="created", server_default="created")
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(server_default=func.now(), onupdate=func.now())

    firmware: Mapped[list["Firmware"]] = relationship(  # noqa: F821
        back_populates="project",
        cascade="all, delete-orphan",
    )
    conversations: Mapped[list["Conversation"]] = relationship(  # noqa: F821
        back_populates="project",
        cascade="all, delete-orphan",
    )
    findings: Mapped[list["Finding"]] = relationship(  # noqa: F821
        back_populates="project",
        cascade="all, delete-orphan",
    )
    documents: Mapped[list["Document"]] = relationship(  # noqa: F821
        back_populates="project",
        cascade="all, delete-orphan",
    )
