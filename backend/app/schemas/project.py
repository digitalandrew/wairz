import uuid
from datetime import datetime

from pydantic import BaseModel


class ProjectCreate(BaseModel):
    name: str
    description: str | None = None


class ProjectUpdate(BaseModel):
    name: str | None = None
    description: str | None = None


class FirmwareResponse(BaseModel):
    model_config = {"from_attributes": True}

    id: uuid.UUID
    original_filename: str | None
    sha256: str
    file_size: int | None
    architecture: str | None
    endianness: str | None
    os_info: str | None
    version_label: str | None = None
    created_at: datetime


class ProjectResponse(BaseModel):
    model_config = {"from_attributes": True}

    id: uuid.UUID
    name: str
    description: str | None
    status: str
    created_at: datetime
    updated_at: datetime
    firmware: list[FirmwareResponse] = []


class ProjectListResponse(BaseModel):
    model_config = {"from_attributes": True}

    id: uuid.UUID
    name: str
    description: str | None
    status: str
    created_at: datetime
    updated_at: datetime
