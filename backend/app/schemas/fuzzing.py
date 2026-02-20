import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class FuzzingCampaignCreateRequest(BaseModel):
    binary_path: str
    timeout_per_exec: int = Field(default=1000, ge=100, le=30000)
    memory_limit: int = Field(default=256, ge=64, le=1024)
    dictionary: str | None = None
    seed_corpus: list[str] | None = None  # base64-encoded seed inputs


class FuzzingCampaignResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    project_id: uuid.UUID
    firmware_id: uuid.UUID
    binary_path: str
    status: str
    config: dict | None
    stats: dict | None
    crashes_count: int
    container_id: str | None
    error_message: str | None
    started_at: datetime | None
    stopped_at: datetime | None
    created_at: datetime


class FuzzingCrashResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    campaign_id: uuid.UUID
    crash_filename: str
    crash_size: int | None
    signal: str | None
    stack_trace: str | None
    exploitability: str | None
    triage_output: str | None
    finding_id: uuid.UUID | None
    created_at: datetime


class FuzzingCrashDetailResponse(FuzzingCrashResponse):
    crash_input_hex: str | None = None


class FuzzingTargetAnalysis(BaseModel):
    binary_path: str
    fuzzing_score: int
    input_sources: list[str] = []
    dangerous_functions: list[str] = []
    network_functions: list[str] = []
    protections: dict = {}
    recommended_strategy: str = "stdin"
    function_count: int = 0
    imports_of_interest: list[str] = []
    file_size: int = 0
    error: str | None = None
