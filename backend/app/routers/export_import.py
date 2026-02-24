"""Project export and import endpoints."""

import uuid

from fastapi import APIRouter, Depends, HTTPException, UploadFile
from fastapi.responses import StreamingResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.database import get_db
from app.models.project import Project
from app.schemas.project import ProjectResponse
from app.services.export_service import ExportService
from app.services.import_service import ImportService

router = APIRouter(
    prefix="/api/v1/projects",
    tags=["export-import"],
)


async def _get_project_or_404(project_id: uuid.UUID, db: AsyncSession) -> Project:
    result = await db.execute(select(Project).where(Project.id == project_id))
    project = result.scalar_one_or_none()
    if not project:
        raise HTTPException(404, "Project not found")
    return project


@router.post("/{project_id}/export")
async def export_project(
    project_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    """Export a project as a .wairz archive."""
    project = await _get_project_or_404(project_id, db)
    svc = ExportService(db)

    try:
        buf = await svc.export_project(project_id)
    except ValueError as e:
        raise HTTPException(400, str(e))

    safe_name = project.name.replace(" ", "_").replace("/", "_")
    filename = f"{safe_name}.wairz"

    return StreamingResponse(
        buf,
        media_type="application/zip",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
        },
    )


@router.post("/import", response_model=ProjectResponse)
async def import_project(
    file: UploadFile,
    db: AsyncSession = Depends(get_db),
):
    """Import a .wairz archive as a new project."""
    if not file.filename or not (
        file.filename.endswith(".wairz") or file.filename.endswith(".zip")
    ):
        raise HTTPException(
            400,
            "Invalid file type. Please upload a .wairz archive.",
        )

    contents = await file.read()
    if not contents:
        raise HTTPException(400, "Empty file")

    svc = ImportService(db)
    try:
        project = await svc.import_project(contents)
    except ValueError as e:
        raise HTTPException(400, str(e))

    # Flush to ensure all records are written, then reload with firmware relationship
    await db.flush()
    result = await db.execute(
        select(Project)
        .where(Project.id == project.id)
        .options(selectinload(Project.firmware))
    )
    return result.scalar_one()
