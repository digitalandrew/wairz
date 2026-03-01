import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.database import get_db
from app.models.project import Project
from app.schemas.project import (
    ProjectCreate,
    ProjectListResponse,
    ProjectResponse,
    ProjectUpdate,
)
from app.services.document_service import DocumentService

router = APIRouter(prefix="/api/v1/projects", tags=["projects"])

SCRATCHPAD_MD_TEMPLATE = """\
# Agent Scratchpad

This document is used by AI agents to persist analysis notes, progress, and context across sessions.
Agents will read this at the start of each session and update it as they work.

---

*No notes yet.*
"""

WAIRZ_MD_TEMPLATE = """\
# WAIRZ.md — Project Instructions

Add custom instructions, notes, or context here for the AI assistant.
The AI will read this file automatically at the start of each conversation.

## Examples of what to put here

- Project-specific analysis focus areas
- Known components or versions to investigate
- Custom credentials or default passwords to check
- Architecture notes or device information
- Links to related documentation or datasheets
"""


@router.post("", response_model=ProjectResponse, status_code=201)
async def create_project(data: ProjectCreate, db: AsyncSession = Depends(get_db)):
    project = Project(name=data.name, description=data.description)
    db.add(project)
    await db.flush()

    # Create default WAIRZ.md note
    doc_svc = DocumentService(db)
    await doc_svc.create_note(
        project_id=project.id,
        title="WAIRZ",
        content=WAIRZ_MD_TEMPLATE,
    )

    # Create default SCRATCHPAD.md note
    await doc_svc.create_note(
        project_id=project.id,
        title="SCRATCHPAD",
        content=SCRATCHPAD_MD_TEMPLATE,
    )

    # Load firmware relationship (empty for new project)
    await db.refresh(project, ["firmware"])
    return project


@router.get("", response_model=list[ProjectListResponse])
async def list_projects(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Project).order_by(Project.created_at.desc()))
    return result.scalars().all()


@router.get("/{project_id}", response_model=ProjectResponse)
async def get_project(project_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(Project)
        .options(selectinload(Project.firmware))
        .where(Project.id == project_id)
    )
    project = result.scalar_one_or_none()
    if not project:
        raise HTTPException(404, "Project not found")
    return project


@router.patch("/{project_id}", response_model=ProjectResponse)
async def update_project(
    project_id: uuid.UUID, data: ProjectUpdate, db: AsyncSession = Depends(get_db)
):
    result = await db.execute(
        select(Project)
        .options(selectinload(Project.firmware))
        .where(Project.id == project_id)
    )
    project = result.scalar_one_or_none()
    if not project:
        raise HTTPException(404, "Project not found")

    update_data = data.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        setattr(project, key, value)
    await db.flush()
    return project


@router.delete("/{project_id}", status_code=204)
async def delete_project(project_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Project).where(Project.id == project_id))
    project = result.scalar_one_or_none()
    if not project:
        raise HTTPException(404, "Project not found")
    await db.delete(project)
