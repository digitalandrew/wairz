import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class PortForward(BaseModel):
    host: int
    guest: int


class EmulationStartRequest(BaseModel):
    mode: Literal["user", "system"]
    binary_path: str | None = None
    arguments: str | None = None
    port_forwards: list[PortForward] = []
    kernel_name: str | None = None
    init_path: str | None = None  # Override /sbin/init (e.g., "/bin/sh" or "/bin/busybox")


class EmulationSessionResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    project_id: uuid.UUID
    firmware_id: uuid.UUID
    mode: str
    status: str
    architecture: str | None
    binary_path: str | None
    arguments: str | None
    port_forwards: list[dict] | None
    error_message: str | None
    started_at: datetime | None
    stopped_at: datetime | None
    created_at: datetime


class EmulationExecRequest(BaseModel):
    command: str
    timeout: int = Field(default=30, ge=1, le=120)
    environment: dict[str, str] | None = None


class EmulationExecResponse(BaseModel):
    stdout: str
    stderr: str
    exit_code: int
    timed_out: bool
