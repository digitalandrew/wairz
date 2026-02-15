import os
import uuid

from fastapi import APIRouter, Depends, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.project import Project
from app.schemas.document import (
    ALLOWED_EXTENSIONS,
    DocumentResponse,
    DocumentUpdate,
)
from app.services.document_service import DocumentService

router = APIRouter(
    prefix="/api/v1/projects/{project_id}/documents",
    tags=["documents"],
)


async def _get_project_or_404(project_id: uuid.UUID, db: AsyncSession) -> Project:
    result = await db.execute(select(Project).where(Project.id == project_id))
    project = result.scalar_one_or_none()
    if not project:
        raise HTTPException(404, "Project not found")
    return project


def _validate_extension(filename: str) -> None:
    ext = os.path.splitext(filename)[1].lower()
    if ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            400,
            f"File type '{ext}' not allowed. Allowed: {', '.join(sorted(ALLOWED_EXTENSIONS))}",
        )


@router.post("", response_model=DocumentResponse, status_code=201)
async def upload_document(
    project_id: uuid.UUID,
    file: UploadFile,
    description: str | None = Form(None),
    db: AsyncSession = Depends(get_db),
):
    await _get_project_or_404(project_id, db)
    _validate_extension(file.filename or "")
    svc = DocumentService(db)
    try:
        document = await svc.upload(project_id, file, description)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    return document


@router.get("", response_model=list[DocumentResponse])
async def list_documents(
    project_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    await _get_project_or_404(project_id, db)
    svc = DocumentService(db)
    return await svc.list_by_project(project_id)


@router.get("/{document_id}", response_model=DocumentResponse)
async def get_document(
    project_id: uuid.UUID,
    document_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    await _get_project_or_404(project_id, db)
    svc = DocumentService(db)
    document = await svc.get(document_id)
    if not document or document.project_id != project_id:
        raise HTTPException(404, "Document not found")
    return document


@router.get("/{document_id}/content")
async def read_document_content(
    project_id: uuid.UUID,
    document_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    """Return extracted text content suitable for viewing in the frontend."""
    await _get_project_or_404(project_id, db)
    svc = DocumentService(db)
    document = await svc.get(document_id)
    if not document or document.project_id != project_id:
        raise HTTPException(404, "Document not found")
    content = DocumentService.read_text_content(document)
    return {
        "content": content,
        "content_type": document.content_type,
        "filename": document.original_filename,
        "size": document.file_size,
    }


@router.get("/{document_id}/download")
async def download_document(
    project_id: uuid.UUID,
    document_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    await _get_project_or_404(project_id, db)
    svc = DocumentService(db)
    document = await svc.get(document_id)
    if not document or document.project_id != project_id:
        raise HTTPException(404, "Document not found")
    if not os.path.exists(document.storage_path):
        raise HTTPException(404, "Document file not found on disk")
    return FileResponse(
        path=document.storage_path,
        filename=document.original_filename,
        media_type=document.content_type,
    )


@router.patch("/{document_id}", response_model=DocumentResponse)
async def update_document(
    project_id: uuid.UUID,
    document_id: uuid.UUID,
    data: DocumentUpdate,
    db: AsyncSession = Depends(get_db),
):
    await _get_project_or_404(project_id, db)
    svc = DocumentService(db)
    existing = await svc.get(document_id)
    if not existing or existing.project_id != project_id:
        raise HTTPException(404, "Document not found")
    document = await svc.update_description(document_id, data.description)
    return document


@router.delete("/{document_id}", status_code=204)
async def delete_document(
    project_id: uuid.UUID,
    document_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    await _get_project_or_404(project_id, db)
    svc = DocumentService(db)
    existing = await svc.get(document_id)
    if not existing or existing.project_id != project_id:
        raise HTTPException(404, "Document not found")
    await svc.delete(document_id)
