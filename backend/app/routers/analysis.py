"""REST endpoints for binary analysis: functions, disassembly, protections."""

import asyncio
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.services.analysis_service import (
    check_binary_protections,
    get_session_cache,
)
from app.services.firmware_service import FirmwareService
from app.utils.sandbox import validate_path

router = APIRouter(
    prefix="/api/v1/projects/{project_id}/analysis",
    tags=["analysis"],
)


async def _resolve_firmware(
    project_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    """Resolve project → firmware, return firmware record."""
    svc = FirmwareService(db)
    firmware = await svc.get_by_project(project_id)
    if not firmware:
        raise HTTPException(404, "No firmware uploaded for this project")
    if not firmware.extracted_path:
        raise HTTPException(400, "Firmware not yet unpacked")
    return firmware


@router.get("/functions")
async def list_functions(
    path: str = Query(..., description="Path to ELF binary in firmware filesystem"),
    firmware=Depends(_resolve_firmware),
):
    """List functions found in an ELF binary, sorted by size (largest first)."""
    try:
        full_path = validate_path(firmware.extracted_path, path)
    except Exception:
        raise HTTPException(403, "Invalid path")

    cache = get_session_cache()
    try:
        session = await cache.get_session(full_path)
    except asyncio.TimeoutError:
        raise HTTPException(504, "Binary analysis timed out")
    except Exception as e:
        raise HTTPException(400, f"Failed to analyze binary: {e}")

    functions = session.list_functions()
    return {
        "binary_path": path,
        "functions": [
            {
                "name": fn.get("name", "unknown"),
                "offset": fn.get("offset", 0),
                "size": fn.get("size", 0),
            }
            for fn in functions
        ],
    }


@router.get("/disasm")
async def disassemble_function(
    path: str = Query(..., description="Path to ELF binary"),
    function: str = Query(..., description="Function name to disassemble"),
    max_instructions: int = Query(100, ge=1, le=200),
    firmware=Depends(_resolve_firmware),
):
    """Disassemble a function from an ELF binary."""
    try:
        full_path = validate_path(firmware.extracted_path, path)
    except Exception:
        raise HTTPException(403, "Invalid path")

    cache = get_session_cache()
    try:
        session = await cache.get_session(full_path)
    except asyncio.TimeoutError:
        raise HTTPException(504, "Binary analysis timed out")
    except Exception as e:
        raise HTTPException(400, f"Failed to analyze binary: {e}")

    loop = asyncio.get_event_loop()
    disasm = await loop.run_in_executor(
        None, session.disassemble_function, function, max_instructions
    )

    return {
        "binary_path": path,
        "function": function,
        "disassembly": disasm,
    }


@router.get("/binary-info")
async def get_binary_info(
    path: str = Query(..., description="Path to ELF binary"),
    firmware=Depends(_resolve_firmware),
):
    """Get binary metadata and security protections."""
    try:
        full_path = validate_path(firmware.extracted_path, path)
    except Exception:
        raise HTTPException(403, "Invalid path")

    cache = get_session_cache()
    try:
        session = await cache.get_session(full_path)
    except asyncio.TimeoutError:
        raise HTTPException(504, "Binary analysis timed out")
    except Exception as e:
        raise HTTPException(400, f"Failed to analyze binary: {e}")

    info = session.get_binary_info()
    protections = check_binary_protections(full_path)

    return {
        "binary_path": path,
        "info": info,
        "protections": protections,
    }
