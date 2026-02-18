import hashlib
import os
import re
import uuid

import aiofiles
from fastapi import UploadFile
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.models.firmware import Firmware


def _sanitize_filename(name: str) -> str:
    """Sanitize a user-supplied filename to prevent path traversal and OS issues.

    Strips directory components, replaces unsafe characters, and limits length.
    """
    # Take only the basename (strip any path components / traversal)
    name = os.path.basename(name)
    # Replace anything that isn't alphanumeric, dot, hyphen, or underscore
    name = re.sub(r"[^\w.\-]", "_", name)
    # Collapse consecutive underscores
    name = re.sub(r"__+", "_", name)
    # Strip leading dots (no hidden files / no "..") and leading underscores
    name = name.lstrip("._")
    # Limit to 200 chars to stay within filesystem limits
    name = name[:200]
    return name or "firmware.bin"


class FirmwareService:
    def __init__(self, db: AsyncSession):
        self.db = db
        self.settings = get_settings()

    async def upload(self, project_id: uuid.UUID, file: UploadFile) -> Firmware:
        # Check for existing firmware on this project
        result = await self.db.execute(
            select(Firmware).where(Firmware.project_id == project_id)
        )
        if result.scalar_one_or_none() is not None:
            raise ValueError("Firmware already uploaded for this project")

        # Create storage directory
        project_dir = os.path.join(self.settings.storage_root, "projects", str(project_id), "firmware")
        os.makedirs(project_dir, exist_ok=True)

        # Stream file to disk while computing SHA256
        raw_filename = file.filename or "firmware.bin"
        filename = _sanitize_filename(raw_filename)
        storage_path = os.path.join(project_dir, filename)
        sha256_hash = hashlib.sha256()
        file_size = 0

        async with aiofiles.open(storage_path, "wb") as out_file:
            while chunk := await file.read(8192):
                sha256_hash.update(chunk)
                await out_file.write(chunk)
                file_size += len(chunk)

        firmware = Firmware(
            project_id=project_id,
            original_filename=raw_filename,
            sha256=sha256_hash.hexdigest(),
            file_size=file_size,
            storage_path=storage_path,
        )
        self.db.add(firmware)
        await self.db.flush()
        return firmware

    async def get_by_project(self, project_id: uuid.UUID) -> Firmware | None:
        result = await self.db.execute(
            select(Firmware).where(Firmware.project_id == project_id)
        )
        return result.scalar_one_or_none()
