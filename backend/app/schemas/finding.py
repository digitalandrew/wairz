import uuid
from datetime import datetime
from enum import Enum

from pydantic import BaseModel, field_validator


class Severity(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"


class FindingStatus(str, Enum):
    open = "open"
    confirmed = "confirmed"
    false_positive = "false_positive"
    fixed = "fixed"


class FindingCreate(BaseModel):
    title: str
    severity: Severity
    description: str | None = None
    evidence: str | None = None
    file_path: str | None = None
    line_number: int | None = None
    cve_ids: list[str] | None = None
    cwe_ids: list[str] | None = None
    conversation_id: uuid.UUID | None = None
    source: str = "manual"
    component_id: uuid.UUID | None = None


class FindingUpdate(BaseModel):
    title: str | None = None
    severity: Severity | None = None
    description: str | None = None
    evidence: str | None = None
    file_path: str | None = None
    line_number: int | None = None
    cve_ids: list[str] | None = None
    cwe_ids: list[str] | None = None
    status: FindingStatus | None = None
    source: str | None = None


class FindingResponse(BaseModel):
    model_config = {"from_attributes": True}

    id: uuid.UUID
    project_id: uuid.UUID
    conversation_id: uuid.UUID | None
    title: str
    severity: str
    description: str | None
    evidence: str | None
    file_path: str | None
    line_number: int | None
    cve_ids: list[str] | None
    cwe_ids: list[str] | None
    status: str
    source: str
    component_id: uuid.UUID | None
    created_at: datetime
    updated_at: datetime
