import uuid

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.firmware import Firmware
from app.models.project import Project
from app.schemas.finding import FindingCreate, FindingResponse, FindingUpdate
from app.services.finding_service import FindingService
from app.services.report_service import generate_markdown_report

router = APIRouter(
    prefix="/api/v1/projects/{project_id}/findings",
    tags=["findings"],
)


async def _get_project_or_404(project_id: uuid.UUID, db: AsyncSession) -> Project:
    result = await db.execute(select(Project).where(Project.id == project_id))
    project = result.scalar_one_or_none()
    if not project:
        raise HTTPException(404, "Project not found")
    return project


@router.post("", response_model=FindingResponse, status_code=201)
async def create_finding(
    project_id: uuid.UUID,
    data: FindingCreate,
    db: AsyncSession = Depends(get_db),
):
    await _get_project_or_404(project_id, db)
    svc = FindingService(db)
    finding = await svc.create(project_id, data)
    return finding


@router.get("", response_model=list[FindingResponse])
async def list_findings(
    project_id: uuid.UUID,
    severity: str | None = Query(None),
    status: str | None = Query(None),
    db: AsyncSession = Depends(get_db),
):
    await _get_project_or_404(project_id, db)
    svc = FindingService(db)
    return await svc.list_by_project(project_id, severity=severity, status=status)


@router.get("/{finding_id}", response_model=FindingResponse)
async def get_finding(
    project_id: uuid.UUID,
    finding_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    await _get_project_or_404(project_id, db)
    svc = FindingService(db)
    finding = await svc.get(finding_id)
    if not finding or finding.project_id != project_id:
        raise HTTPException(404, "Finding not found")
    return finding


@router.patch("/{finding_id}", response_model=FindingResponse)
async def update_finding(
    project_id: uuid.UUID,
    finding_id: uuid.UUID,
    data: FindingUpdate,
    db: AsyncSession = Depends(get_db),
):
    await _get_project_or_404(project_id, db)
    svc = FindingService(db)
    # Verify finding belongs to this project
    existing = await svc.get(finding_id)
    if not existing or existing.project_id != project_id:
        raise HTTPException(404, "Finding not found")
    finding = await svc.update(finding_id, data)
    return finding


@router.delete("/{finding_id}", status_code=204)
async def delete_finding(
    project_id: uuid.UUID,
    finding_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    await _get_project_or_404(project_id, db)
    svc = FindingService(db)
    existing = await svc.get(finding_id)
    if not existing or existing.project_id != project_id:
        raise HTTPException(404, "Finding not found")
    await svc.delete(finding_id)


@router.post("/export")
async def export_findings(
    project_id: uuid.UUID,
    format: str = Query("markdown", pattern="^(markdown)$"),
    db: AsyncSession = Depends(get_db),
):
    project = await _get_project_or_404(project_id, db)

    # Load firmware
    fw_result = await db.execute(
        select(Firmware).where(Firmware.project_id == project_id)
    )
    firmware = fw_result.scalar_one_or_none()

    # Load findings
    svc = FindingService(db)
    findings = await svc.list_by_project(project_id)

    md = generate_markdown_report(project, firmware, findings)
    filename = f"{project.name.replace(' ', '_')}_security_report.md"

    return Response(
        content=md,
        media_type="text/markdown",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
