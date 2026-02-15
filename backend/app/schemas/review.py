import uuid
from datetime import datetime
from enum import Enum

from pydantic import BaseModel


class ReviewStatus(str, Enum):
    pending = "pending"
    running = "running"
    completed = "completed"
    failed = "failed"
    cancelled = "cancelled"


class AgentStatus(str, Enum):
    pending = "pending"
    running = "running"
    completed = "completed"
    failed = "failed"
    cancelled = "cancelled"


class ReviewCategory(str, Enum):
    filesystem_survey = "filesystem_survey"
    credential_scan = "credential_scan"
    config_audit = "config_audit"
    binary_security = "binary_security"
    permissions_check = "permissions_check"
    deep_binary_analysis = "deep_binary_analysis"
    final_review = "final_review"


class ReviewCreate(BaseModel):
    categories: list[ReviewCategory]


class ReviewAgentResponse(BaseModel):
    model_config = {"from_attributes": True}

    id: uuid.UUID
    review_id: uuid.UUID
    category: str
    status: str
    model: str
    conversation_id: uuid.UUID | None
    scratchpad: str | None
    findings_count: int
    tool_calls_count: int
    error_message: str | None
    started_at: datetime | None
    completed_at: datetime | None
    created_at: datetime
    updated_at: datetime


class ReviewResponse(BaseModel):
    model_config = {"from_attributes": True}

    id: uuid.UUID
    project_id: uuid.UUID
    status: str
    selected_categories: list[str]
    started_at: datetime | None
    completed_at: datetime | None
    created_at: datetime
    updated_at: datetime
    agents: list[ReviewAgentResponse]
