import dataclasses
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.services.file_service import FileService
from app.services.firmware_service import FirmwareService

router = APIRouter(prefix="/api/v1/projects/{project_id}/files", tags=["files"])


async def get_file_service(
    project_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
) -> FileService:
    """Resolve project → firmware → extracted_path, return a FileService."""
    firmware_svc = FirmwareService(db)
    firmware = await firmware_svc.get_by_project(project_id)
    if not firmware:
        raise HTTPException(404, "No firmware uploaded for this project")
    if not firmware.extracted_path:
        raise HTTPException(400, "Firmware not yet unpacked")
    return FileService(firmware.extracted_path)


@router.get("")
async def list_directory(
    path: str = Query("/", description="Directory path to list"),
    service: FileService = Depends(get_file_service),
):
    try:
        entries, truncated = service.list_directory(path)
    except FileNotFoundError as e:
        raise HTTPException(404, str(e))
    return {
        "path": path,
        "entries": [dataclasses.asdict(e) for e in entries],
        "truncated": truncated,
    }


@router.get("/read")
async def read_file(
    path: str = Query(..., description="File path to read"),
    offset: int = Query(0, ge=0, description="Byte offset to start reading from"),
    length: int | None = Query(None, ge=1, description="Number of bytes to read"),
    service: FileService = Depends(get_file_service),
):
    try:
        content = service.read_file(path, offset, length)
    except FileNotFoundError as e:
        raise HTTPException(404, str(e))
    return dataclasses.asdict(content)


@router.get("/info")
async def file_info(
    path: str = Query(..., description="File path to inspect"),
    service: FileService = Depends(get_file_service),
):
    try:
        info = service.file_info(path)
    except FileNotFoundError as e:
        raise HTTPException(404, str(e))
    return dataclasses.asdict(info)


@router.get("/search")
async def search_files(
    pattern: str = Query(..., description="Glob pattern to search for"),
    path: str = Query("/", description="Directory to search in"),
    service: FileService = Depends(get_file_service),
):
    matches, truncated = service.search_files(pattern, path)
    return {
        "pattern": pattern,
        "matches": matches,
        "truncated": truncated,
    }
