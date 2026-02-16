import os
import uuid

from fastapi import APIRouter, Depends, HTTPException, UploadFile
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.project import Project
from app.schemas.firmware import FirmwareDetailResponse, FirmwareUploadResponse
from app.services.firmware_service import FirmwareService
from app.workers.unpack import unpack_firmware

router = APIRouter(prefix="/api/v1/projects/{project_id}/firmware", tags=["firmware"])


def get_firmware_service(db: AsyncSession = Depends(get_db)) -> FirmwareService:
    return FirmwareService(db)


@router.post("", response_model=FirmwareUploadResponse, status_code=201)
async def upload_firmware(
    project_id: uuid.UUID,
    file: UploadFile,
    service: FirmwareService = Depends(get_firmware_service),
):
    try:
        firmware = await service.upload(project_id, file)
    except ValueError as e:
        raise HTTPException(409, str(e))
    return firmware


@router.get("", response_model=FirmwareDetailResponse)
async def get_firmware(
    project_id: uuid.UUID,
    service: FirmwareService = Depends(get_firmware_service),
):
    firmware = await service.get_by_project(project_id)
    if not firmware:
        raise HTTPException(404, "No firmware uploaded for this project")
    return firmware


@router.post("/unpack", response_model=FirmwareDetailResponse)
async def unpack(
    project_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    service: FirmwareService = Depends(get_firmware_service),
):
    # Get project and firmware
    proj_result = await db.execute(select(Project).where(Project.id == project_id))
    project = proj_result.scalar_one_or_none()
    if not project:
        raise HTTPException(404, "Project not found")

    firmware = await service.get_by_project(project_id)
    if not firmware:
        raise HTTPException(404, "No firmware uploaded for this project")

    if firmware.extracted_path:
        raise HTTPException(409, "Firmware already unpacked")

    # Update status to unpacking
    project.status = "unpacking"
    await db.flush()

    # Run unpacking
    output_base = os.path.dirname(firmware.storage_path)
    result = await unpack_firmware(firmware.storage_path, output_base)

    if result.success:
        firmware.extracted_path = result.extracted_path
        firmware.architecture = result.architecture
        firmware.endianness = result.endianness
        firmware.os_info = result.os_info
        firmware.kernel_path = result.kernel_path
        firmware.unpack_log = result.unpack_log
        project.status = "ready"
    else:
        firmware.unpack_log = result.unpack_log
        project.status = "error"

    await db.flush()
    return firmware
