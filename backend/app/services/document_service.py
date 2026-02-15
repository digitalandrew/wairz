import hashlib
import os
import uuid

from fastapi import UploadFile
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.models.document import Document
from app.schemas.document import MAX_DOCUMENT_SIZE_MB, MAX_DOCUMENTS_PER_PROJECT


class DocumentService:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def upload(
        self,
        project_id: uuid.UUID,
        file: UploadFile,
        description: str | None = None,
    ) -> Document:
        # Check document count limit
        count_result = await self.db.execute(
            select(func.count()).select_from(Document).where(
                Document.project_id == project_id,
            )
        )
        current_count = count_result.scalar_one()
        if current_count >= MAX_DOCUMENTS_PER_PROJECT:
            raise ValueError(
                f"Maximum of {MAX_DOCUMENTS_PER_PROJECT} documents per project reached"
            )

        # Read and hash the file, enforcing size limit
        max_bytes = MAX_DOCUMENT_SIZE_MB * 1024 * 1024
        hasher = hashlib.sha256()
        chunks: list[bytes] = []
        total_size = 0

        while True:
            chunk = await file.read(64 * 1024)
            if not chunk:
                break
            total_size += len(chunk)
            if total_size > max_bytes:
                raise ValueError(
                    f"File exceeds maximum size of {MAX_DOCUMENT_SIZE_MB}MB"
                )
            hasher.update(chunk)
            chunks.append(chunk)

        sha256 = hasher.hexdigest()
        content_type = file.content_type or "application/octet-stream"
        original_filename = file.filename or "document"

        # Build storage path
        settings = get_settings()
        doc_id = uuid.uuid4()
        safe_filename = original_filename.replace("/", "_").replace("\\", "_")
        storage_dir = os.path.join(
            settings.storage_root, "projects", str(project_id), "documents"
        )
        os.makedirs(storage_dir, exist_ok=True)
        storage_path = os.path.join(storage_dir, f"{doc_id}_{safe_filename}")

        # Write file to disk
        with open(storage_path, "wb") as f:
            for chunk in chunks:
                f.write(chunk)

        document = Document(
            id=doc_id,
            project_id=project_id,
            original_filename=original_filename,
            description=description,
            content_type=content_type,
            file_size=total_size,
            sha256=sha256,
            storage_path=storage_path,
        )
        self.db.add(document)
        await self.db.flush()
        return document

    async def list_by_project(self, project_id: uuid.UUID) -> list[Document]:
        result = await self.db.execute(
            select(Document)
            .where(Document.project_id == project_id)
            .order_by(Document.created_at.desc())
        )
        return list(result.scalars().all())

    async def get(self, document_id: uuid.UUID) -> Document | None:
        result = await self.db.execute(
            select(Document).where(Document.id == document_id)
        )
        return result.scalar_one_or_none()

    async def update_description(
        self, document_id: uuid.UUID, description: str | None
    ) -> Document | None:
        document = await self.get(document_id)
        if document is None:
            return None
        document.description = description
        await self.db.flush()
        return document

    async def delete(self, document_id: uuid.UUID) -> bool:
        document = await self.get(document_id)
        if document is None:
            return False
        # Remove file from disk
        if document.storage_path and os.path.exists(document.storage_path):
            os.remove(document.storage_path)
        await self.db.delete(document)
        await self.db.flush()
        return True

    async def create_note(
        self,
        project_id: uuid.UUID,
        title: str,
        content: str = "",
    ) -> Document:
        # Check document count limit
        count_result = await self.db.execute(
            select(func.count()).select_from(Document).where(
                Document.project_id == project_id,
            )
        )
        current_count = count_result.scalar_one()
        if current_count >= MAX_DOCUMENTS_PER_PROJECT:
            raise ValueError(
                f"Maximum of {MAX_DOCUMENTS_PER_PROJECT} documents per project reached"
            )

        # Sanitize title and build filename
        safe_title = title.strip().replace("/", "_").replace("\\", "_")
        if not safe_title:
            safe_title = "Untitled"
        filename = f"{safe_title}.md"

        content_bytes = content.encode("utf-8")
        sha256 = hashlib.sha256(content_bytes).hexdigest()
        file_size = len(content_bytes)

        settings = get_settings()
        doc_id = uuid.uuid4()
        storage_dir = os.path.join(
            settings.storage_root, "projects", str(project_id), "documents"
        )
        os.makedirs(storage_dir, exist_ok=True)
        storage_path = os.path.join(storage_dir, f"{doc_id}_{filename}")

        with open(storage_path, "w", encoding="utf-8") as f:
            f.write(content)

        document = Document(
            id=doc_id,
            project_id=project_id,
            original_filename=filename,
            description=None,
            content_type="text/markdown",
            file_size=file_size,
            sha256=sha256,
            storage_path=storage_path,
        )
        self.db.add(document)
        await self.db.flush()
        return document

    async def update_content(
        self,
        document_id: uuid.UUID,
        content: str,
    ) -> Document | None:
        document = await self.get(document_id)
        if document is None:
            return None

        content_bytes = content.encode("utf-8")
        document.sha256 = hashlib.sha256(content_bytes).hexdigest()
        document.file_size = len(content_bytes)

        with open(document.storage_path, "w", encoding="utf-8") as f:
            f.write(content)

        await self.db.flush()
        return document

    @staticmethod
    def read_text_content(document: Document) -> str:
        """Read document content as text. Uses pypdf for PDFs."""
        path = document.storage_path
        if not os.path.exists(path):
            return "[Error: file not found on disk]"

        lower = document.original_filename.lower()
        if lower.endswith(".pdf"):
            try:
                from pypdf import PdfReader

                reader = PdfReader(path)
                pages = []
                for page in reader.pages:
                    text = page.extract_text()
                    if text:
                        pages.append(text)
                return "\n\n".join(pages) if pages else "[No extractable text in PDF]"
            except Exception as exc:
                return f"[Error extracting PDF text: {exc}]"

        # Text-based formats: read directly
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                return f.read()
        except Exception as exc:
            return f"[Error reading file: {exc}]"
