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
    pre_init_script: str | None = None  # Shell script to run before firmware init (e.g., start cfmd, set up LD_PRELOAD)
    stub_profile: Literal["none", "generic", "tenda"] | None = None  # Stub library profile for system-mode emulation


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


# ── Emulation Presets ──


class PortForwardItem(BaseModel):
    host: int
    guest: int


class EmulationPresetCreate(BaseModel):
    name: str = Field(..., max_length=255)
    description: str | None = None
    mode: Literal["user", "system"]
    binary_path: str | None = None
    arguments: str | None = None
    architecture: str | None = None
    port_forwards: list[PortForwardItem] = []
    kernel_name: str | None = None
    init_path: str | None = None
    pre_init_script: str | None = None
    stub_profile: Literal["none", "generic", "tenda"] = "none"


class EmulationPresetUpdate(BaseModel):
    name: str | None = Field(default=None, max_length=255)
    description: str | None = None
    mode: Literal["user", "system"] | None = None
    binary_path: str | None = None
    arguments: str | None = None
    architecture: str | None = None
    port_forwards: list[PortForwardItem] | None = None
    kernel_name: str | None = None
    init_path: str | None = None
    pre_init_script: str | None = None
    stub_profile: Literal["none", "generic", "tenda"] | None = None


class EmulationPresetResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    project_id: uuid.UUID
    name: str
    description: str | None
    mode: str
    binary_path: str | None
    arguments: str | None
    architecture: str | None
    port_forwards: list[dict] | None
    kernel_name: str | None
    init_path: str | None
    pre_init_script: str | None
    stub_profile: str
    created_at: datetime
    updated_at: datetime
