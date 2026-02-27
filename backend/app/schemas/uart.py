import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class UARTConnectRequest(BaseModel):
    device_path: str = Field(..., description="Serial device path (e.g., /dev/ttyUSB0)")
    baudrate: int = Field(default=115200, ge=300, le=4000000)
    data_bits: int = Field(default=8, ge=5, le=8)
    parity: str = Field(default="N", pattern="^[NEO]$")
    stop_bits: int = Field(default=1, ge=1, le=2)


class UARTSendCommandRequest(BaseModel):
    command: str = Field(..., min_length=1)
    timeout: int = Field(default=30, ge=1, le=300)
    prompt: str = Field(default="# ")


class UARTReadRequest(BaseModel):
    timeout: int = Field(default=2, ge=1, le=60)


class UARTSendRawRequest(BaseModel):
    data: str = Field(..., min_length=1)
    hex: bool = Field(default=False)


class UARTTranscriptRequest(BaseModel):
    tail_lines: int = Field(default=100, ge=1, le=10000)


class UARTSessionResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    project_id: uuid.UUID
    firmware_id: uuid.UUID
    device_path: str
    baudrate: int
    status: str
    error_message: str | None
    transcript_path: str | None
    connected_at: datetime | None
    closed_at: datetime | None
    created_at: datetime


class UARTCommandResponse(BaseModel):
    output: str


class UARTReadResponse(BaseModel):
    output: str
    bytes: int = 0


class UARTStatusResponse(BaseModel):
    connected: bool
    device: str | None
    baudrate: int
    buffer_bytes: int
    transcript_path: str | None
    session: UARTSessionResponse | None = None


class UARTTranscriptResponse(BaseModel):
    entries: list[dict]
    count: int
