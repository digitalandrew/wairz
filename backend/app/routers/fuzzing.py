"""REST endpoints for AFL++ fuzzing campaigns."""

import logging
import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.firmware import Firmware
from app.schemas.fuzzing import (
    FuzzingCampaignCreateRequest,
    FuzzingCampaignResponse,
    FuzzingCrashDetailResponse,
    FuzzingCrashResponse,
    FuzzingTargetAnalysis,
)
from app.services.firmware_service import FirmwareService
from app.services.fuzzing_service import FuzzingService

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/projects/{project_id}/fuzzing",
    tags=["fuzzing"],
)


async def _resolve_firmware(
    project_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
) -> Firmware:
    """Resolve project -> firmware, return firmware record."""
    svc = FirmwareService(db)
    firmware = await svc.get_by_project(project_id)
    if not firmware:
        raise HTTPException(404, "No firmware uploaded for this project")
    if not firmware.extracted_path:
        raise HTTPException(400, "Firmware not yet unpacked")
    return firmware


@router.get("/analyze", response_model=FuzzingTargetAnalysis)
async def analyze_target(
    project_id: uuid.UUID,
    path: str,
    firmware: Firmware = Depends(_resolve_firmware),
    db: AsyncSession = Depends(get_db),
):
    """Analyze a binary for fuzzing suitability."""
    svc = FuzzingService(db)
    try:
        analysis = await svc.analyze_target(firmware, path)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    return analysis


@router.post("/campaigns", response_model=FuzzingCampaignResponse, status_code=201)
async def create_campaign(
    project_id: uuid.UUID,
    request: FuzzingCampaignCreateRequest,
    firmware: Firmware = Depends(_resolve_firmware),
    db: AsyncSession = Depends(get_db),
):
    """Create a new fuzzing campaign."""
    svc = FuzzingService(db)
    config = {
        "timeout_per_exec": request.timeout_per_exec,
        "memory_limit": request.memory_limit,
        "dictionary": request.dictionary,
        "seed_corpus": request.seed_corpus,
    }
    try:
        campaign = await svc.create_campaign(firmware, request.binary_path, config)
        await db.commit()
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    return campaign


@router.post("/campaigns/{campaign_id}/start", response_model=FuzzingCampaignResponse)
async def start_campaign(
    project_id: uuid.UUID,
    campaign_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    """Start a fuzzing campaign."""
    svc = FuzzingService(db)
    try:
        campaign = await svc.start_campaign(campaign_id, project_id)
        await db.commit()
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    return campaign


@router.post("/campaigns/{campaign_id}/stop", response_model=FuzzingCampaignResponse)
async def stop_campaign(
    project_id: uuid.UUID,
    campaign_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    """Stop a running fuzzing campaign."""
    svc = FuzzingService(db)
    try:
        campaign = await svc.stop_campaign(campaign_id, project_id)
        await db.commit()
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    return campaign


@router.get("/campaigns", response_model=list[FuzzingCampaignResponse])
async def list_campaigns(
    project_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    """List all fuzzing campaigns for this project."""
    svc = FuzzingService(db)
    campaigns = await svc.list_campaigns(project_id)
    # Update status for running campaigns
    for campaign in campaigns:
        if campaign.status == "running":
            try:
                await svc.get_campaign_status(campaign.id)
            except Exception:
                pass
    return campaigns


@router.get("/campaigns/{campaign_id}", response_model=FuzzingCampaignResponse)
async def get_campaign(
    project_id: uuid.UUID,
    campaign_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    """Get campaign details with live stats."""
    svc = FuzzingService(db)
    try:
        campaign = await svc.get_campaign_status(campaign_id, project_id)
        await db.commit()
    except ValueError as exc:
        raise HTTPException(404, str(exc))
    return campaign


@router.get("/campaigns/{campaign_id}/crashes", response_model=list[FuzzingCrashResponse])
async def list_crashes(
    project_id: uuid.UUID,
    campaign_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    """List all crashes for a campaign."""
    svc = FuzzingService(db)
    crashes = await svc.get_crashes(campaign_id, project_id)
    return crashes


@router.get(
    "/campaigns/{campaign_id}/crashes/{crash_id}",
    response_model=FuzzingCrashDetailResponse,
)
async def get_crash_detail(
    project_id: uuid.UUID,
    campaign_id: uuid.UUID,
    crash_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    """Get detailed crash information including hex-encoded input."""
    svc = FuzzingService(db)
    try:
        crash = await svc.get_crash_detail(campaign_id, crash_id, project_id)
    except ValueError as exc:
        raise HTTPException(404, str(exc))

    # Build response with hex-encoded crash input
    resp = FuzzingCrashDetailResponse.model_validate(crash)
    if crash.crash_input:
        resp.crash_input_hex = crash.crash_input.hex()
    return resp


@router.post(
    "/campaigns/{campaign_id}/crashes/{crash_id}/triage",
    response_model=FuzzingCrashResponse,
)
async def triage_crash(
    project_id: uuid.UUID,
    campaign_id: uuid.UUID,
    crash_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    """Triage a crash: reproduce with GDB and classify exploitability."""
    svc = FuzzingService(db)
    try:
        crash = await svc.triage_crash(campaign_id, crash_id, project_id)
        await db.commit()
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    return crash
