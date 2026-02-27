"""REST endpoints for UART serial console access."""

import logging
import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.firmware import Firmware
from app.schemas.uart import (
    UARTCommandResponse,
    UARTConnectRequest,
    UARTReadRequest,
    UARTReadResponse,
    UARTSendCommandRequest,
    UARTSendRawRequest,
    UARTSessionResponse,
    UARTStatusResponse,
    UARTTranscriptRequest,
    UARTTranscriptResponse,
)
from app.services.firmware_service import FirmwareService
from app.services.uart_service import UARTService

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/projects/{project_id}/uart",
    tags=["uart"],
)


async def _resolve_firmware(
    project_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
) -> Firmware:
    """Resolve project -> firmware."""
    svc = FirmwareService(db)
    firmware = await svc.get_by_project(project_id)
    if not firmware:
        raise HTTPException(404, "No firmware uploaded for this project")
    return firmware


@router.post("/connect", response_model=UARTSessionResponse, status_code=201)
async def uart_connect(
    project_id: uuid.UUID,
    request: UARTConnectRequest,
    firmware: Firmware = Depends(_resolve_firmware),
    db: AsyncSession = Depends(get_db),
):
    """Connect to a UART serial device via the bridge."""
    svc = UARTService(db)
    try:
        session = await svc.connect(
            project_id=project_id,
            firmware_id=firmware.id,
            device_path=request.device_path,
            baudrate=request.baudrate,
            data_bits=request.data_bits,
            parity=request.parity,
            stop_bits=request.stop_bits,
        )
    except ConnectionError as exc:
        raise HTTPException(503, str(exc))
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    return session


@router.post("/send-command", response_model=UARTCommandResponse)
async def uart_send_command(
    project_id: uuid.UUID,
    request: UARTSendCommandRequest,
    db: AsyncSession = Depends(get_db),
):
    """Send a command and wait for the prompt."""
    svc = UARTService(db)
    try:
        result = await svc.send_command(
            project_id=project_id,
            command=request.command,
            timeout=request.timeout,
            prompt=request.prompt,
        )
    except ConnectionError as exc:
        raise HTTPException(503, str(exc))
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    return UARTCommandResponse(output=result.get("output", ""))


@router.post("/read", response_model=UARTReadResponse)
async def uart_read(
    project_id: uuid.UUID,
    request: UARTReadRequest,
    db: AsyncSession = Depends(get_db),
):
    """Read the current receive buffer contents."""
    svc = UARTService(db)
    try:
        result = await svc.read_buffer(
            project_id=project_id,
            timeout=request.timeout,
        )
    except ConnectionError as exc:
        raise HTTPException(503, str(exc))
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    return UARTReadResponse(
        output=result.get("output", ""),
        bytes=result.get("bytes", 0),
    )


@router.post("/send-break")
async def uart_send_break(
    project_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    """Send a serial BREAK signal."""
    svc = UARTService(db)
    try:
        result = await svc.send_break(project_id=project_id)
    except ConnectionError as exc:
        raise HTTPException(503, str(exc))
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    return result


@router.post("/send-raw")
async def uart_send_raw(
    project_id: uuid.UUID,
    request: UARTSendRawRequest,
    db: AsyncSession = Depends(get_db),
):
    """Send raw bytes to the serial port."""
    svc = UARTService(db)
    try:
        result = await svc.send_raw(
            project_id=project_id,
            data=request.data,
            hex_mode=request.hex,
        )
    except ConnectionError as exc:
        raise HTTPException(503, str(exc))
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    return result


@router.post("/disconnect", response_model=UARTSessionResponse)
async def uart_disconnect(
    project_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    """Disconnect the active UART session."""
    svc = UARTService(db)
    try:
        session = await svc.disconnect(project_id=project_id)
    except ConnectionError as exc:
        raise HTTPException(503, str(exc))
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    return session


@router.get("/status", response_model=UARTStatusResponse)
async def uart_status(
    project_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    """Get UART connection status."""
    svc = UARTService(db)
    result = await svc.get_status(project_id=project_id)
    return UARTStatusResponse(
        connected=result.get("connected", False),
        device=result.get("device"),
        baudrate=result.get("baudrate", 0),
        buffer_bytes=result.get("buffer_bytes", 0),
        transcript_path=result.get("transcript_path"),
    )


@router.post("/transcript", response_model=UARTTranscriptResponse)
async def uart_transcript(
    project_id: uuid.UUID,
    request: UARTTranscriptRequest,
    db: AsyncSession = Depends(get_db),
):
    """Get recent UART transcript entries."""
    svc = UARTService(db)
    try:
        result = await svc.get_transcript(
            project_id=project_id,
            tail_lines=request.tail_lines,
        )
    except ConnectionError as exc:
        raise HTTPException(503, str(exc))
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    return UARTTranscriptResponse(
        entries=result.get("entries", []),
        count=result.get("count", 0),
    )


@router.get("/sessions", response_model=list[UARTSessionResponse])
async def list_sessions(
    project_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    """List all UART sessions for this project."""
    svc = UARTService(db)
    return await svc.list_sessions(project_id=project_id)
