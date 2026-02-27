import asyncio
import logging
import os
import uuid

from fastapi import APIRouter, Depends, Form, HTTPException, UploadFile
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import async_session_factory, get_db
from app.models.firmware import Firmware
from app.models.project import Project
from app.schemas.firmware import (
    FirmwareDetailResponse,
    FirmwareMetadataResponse,
    FirmwareUploadResponse,
)
from app.services.firmware_metadata_service import FirmwareMetadataService
from app.services.firmware_service import FirmwareService
from app.workers.unpack import detect_kernel, unpack_firmware

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/projects/{project_id}/firmware", tags=["firmware"])


def get_firmware_service(db: AsyncSession = Depends(get_db)) -> FirmwareService:
    return FirmwareService(db)


@router.post("", response_model=FirmwareUploadResponse, status_code=201)
async def upload_firmware(
    project_id: uuid.UUID,
    file: UploadFile,
    version_label: str | None = Form(None),
    service: FirmwareService = Depends(get_firmware_service),
):
    firmware = await service.upload(project_id, file, version_label=version_label)
    return firmware


@router.get("", response_model=list[FirmwareDetailResponse])
async def list_firmware(
    project_id: uuid.UUID,
    service: FirmwareService = Depends(get_firmware_service),
):
    return await service.list_by_project(project_id)


@router.get("/{firmware_id}", response_model=FirmwareDetailResponse)
async def get_single_firmware(
    project_id: uuid.UUID,
    firmware_id: uuid.UUID,
    service: FirmwareService = Depends(get_firmware_service),
):
    firmware = await service.get_by_id(firmware_id)
    if not firmware or firmware.project_id != project_id:
        raise HTTPException(404, "Firmware not found")
    return firmware


@router.delete("/{firmware_id}", status_code=204)
async def delete_firmware(
    project_id: uuid.UUID,
    firmware_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    service: FirmwareService = Depends(get_firmware_service),
):
    firmware = await service.get_by_id(firmware_id)
    if not firmware or firmware.project_id != project_id:
        raise HTTPException(404, "Firmware not found")
    await service.delete(firmware)


@router.post("/{firmware_id}/unpack", response_model=FirmwareDetailResponse, status_code=202)
async def unpack(
    project_id: uuid.UUID,
    firmware_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    service: FirmwareService = Depends(get_firmware_service),
):
    # Get project and firmware
    proj_result = await db.execute(select(Project).where(Project.id == project_id))
    project = proj_result.scalar_one_or_none()
    if not project:
        raise HTTPException(404, "Project not found")

    firmware = await service.get_by_id(firmware_id)
    if not firmware or firmware.project_id != project_id:
        raise HTTPException(404, "Firmware not found")

    if firmware.extracted_path:
        raise HTTPException(409, "Firmware already unpacked")

    if project.status == "unpacking":
        raise HTTPException(409, "Firmware is already being unpacked")

    # Update status to unpacking
    project.status = "unpacking"
    await db.flush()

    # Launch background task (uses its own DB session)
    asyncio.create_task(
        _run_unpack_background(project_id, firmware_id, firmware.storage_path)
    )

    return firmware


async def _run_unpack_background(
    project_id: uuid.UUID,
    firmware_id: uuid.UUID,
    storage_path: str,
) -> None:
    """Run firmware unpacking in the background with its own DB session."""
    try:
        output_base = os.path.dirname(storage_path)
        result = await unpack_firmware(storage_path, output_base)

        async with async_session_factory() as db:
            try:
                proj_result = await db.execute(
                    select(Project).where(Project.id == project_id)
                )
                project = proj_result.scalar_one_or_none()
                fw_result = await db.execute(
                    select(Firmware).where(Firmware.id == firmware_id)
                )
                firmware = fw_result.scalar_one_or_none()

                if not project or not firmware:
                    logger.error("Background unpack: project or firmware not found")
                    return

                if result.success:
                    firmware.extracted_path = result.extracted_path
                    firmware.extraction_dir = result.extraction_dir
                    firmware.architecture = result.architecture
                    firmware.endianness = result.endianness
                    firmware.os_info = result.os_info
                    firmware.kernel_path = result.kernel_path
                    firmware.unpack_log = result.unpack_log
                    project.status = "ready"
                else:
                    firmware.unpack_log = result.unpack_log
                    project.status = "error"

                await db.commit()
            except Exception:
                await db.rollback()
                raise
    except Exception:
        logger.exception("Background firmware unpack failed for firmware %s", firmware_id)
        # Try to set error status
        try:
            async with async_session_factory() as db:
                try:
                    proj_result = await db.execute(
                        select(Project).where(Project.id == project_id)
                    )
                    project = proj_result.scalar_one_or_none()
                    if project:
                        project.status = "error"
                    await db.commit()
                except Exception:
                    await db.rollback()
        except Exception:
            logger.exception("Failed to set error status for project %s", project_id)


@router.post("/{firmware_id}/redetect-kernel", response_model=FirmwareDetailResponse)
async def redetect_kernel(
    project_id: uuid.UUID,
    firmware_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    service: FirmwareService = Depends(get_firmware_service),
):
    """Re-run kernel detection on already-extracted firmware."""
    firmware = await service.get_by_id(firmware_id)
    if not firmware or firmware.project_id != project_id:
        raise HTTPException(404, "Firmware not found")

    if not firmware.extracted_path:
        raise HTTPException(400, "Firmware has not been unpacked yet")

    extraction_dir = os.path.dirname(firmware.extracted_path)
    firmware.kernel_path = detect_kernel(extraction_dir, firmware.extracted_path)
    await db.flush()

    return firmware


@router.get("/{firmware_id}/metadata", response_model=FirmwareMetadataResponse)
async def get_firmware_metadata(
    project_id: uuid.UUID,
    firmware_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    service: FirmwareService = Depends(get_firmware_service),
):
    """Get structural metadata for a firmware image (partitions, U-Boot, MTD)."""
    firmware = await service.get_by_id(firmware_id)
    if not firmware or firmware.project_id != project_id:
        raise HTTPException(404, "Firmware not found")
    if not firmware.storage_path:
        raise HTTPException(400, "Firmware file not available")

    metadata_service = FirmwareMetadataService()
    metadata = await metadata_service.scan_firmware_image(
        firmware.storage_path, firmware.id, db,
    )
    return metadata


# ── Backward-compatible endpoints (no firmware_id in path) ──
# These use the first/only firmware for the project, preserving existing behavior.


@router.post("/unpack", response_model=FirmwareDetailResponse, status_code=202, deprecated=True)
async def unpack_legacy(
    project_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    service: FirmwareService = Depends(get_firmware_service),
):
    """Legacy unpack endpoint — uses first firmware for the project."""
    firmware = await service.get_by_project(project_id)
    if not firmware:
        raise HTTPException(404, "No firmware uploaded for this project")

    return await unpack(project_id, firmware.id, db, service)


@router.post("/redetect-kernel", response_model=FirmwareDetailResponse, deprecated=True)
async def redetect_kernel_legacy(
    project_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    service: FirmwareService = Depends(get_firmware_service),
):
    """Legacy redetect-kernel endpoint — uses first firmware for the project."""
    firmware = await service.get_by_project(project_id)
    if not firmware:
        raise HTTPException(404, "No firmware uploaded for this project")

    return await redetect_kernel(project_id, firmware.id, db, service)
