import uuid
from datetime import datetime

from pydantic import BaseModel


ALLOWED_EXTENSIONS = {
    ".txt", ".md", ".pdf", ".doc", ".docx",
    ".csv", ".json", ".xml", ".html",
}

MAX_DOCUMENT_SIZE_MB = 10
MAX_DOCUMENTS_PER_PROJECT = 20


class DocumentResponse(BaseModel):
    model_config = {"from_attributes": True}

    id: uuid.UUID
    project_id: uuid.UUID
    original_filename: str
    description: str | None
    content_type: str
    file_size: int
    sha256: str
    storage_path: str
    created_at: datetime


class DocumentUpdate(BaseModel):
    description: str | None = None


class NoteCreate(BaseModel):
    title: str
    content: str = ""


class DocumentContentUpdate(BaseModel):
    content: str
