import uuid
from datetime import datetime

from pydantic import BaseModel


class FirmwareUploadResponse(BaseModel):
    model_config = {"from_attributes": True}

    id: uuid.UUID
    original_filename: str | None
    sha256: str
    file_size: int | None
    created_at: datetime


class FirmwareDetailResponse(BaseModel):
    model_config = {"from_attributes": True}

    id: uuid.UUID
    project_id: uuid.UUID
    original_filename: str | None
    sha256: str
    file_size: int | None
    storage_path: str | None
    extracted_path: str | None
    architecture: str | None
    endianness: str | None
    os_info: str | None
    kernel_path: str | None
    unpack_log: str | None
    created_at: datetime
