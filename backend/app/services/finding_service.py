import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.finding import Finding
from app.schemas.finding import FindingCreate, FindingUpdate


class FindingService:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def create(
        self,
        project_id: uuid.UUID,
        data: FindingCreate,
    ) -> Finding:
        finding = Finding(
            project_id=project_id,
            conversation_id=data.conversation_id,
            title=data.title,
            severity=data.severity.value,
            description=data.description,
            evidence=data.evidence,
            file_path=data.file_path,
            line_number=data.line_number,
            cve_ids=data.cve_ids,
            cwe_ids=data.cwe_ids,
        )
        self.db.add(finding)
        await self.db.flush()
        return finding

    async def list_by_project(
        self,
        project_id: uuid.UUID,
        severity: str | None = None,
        status: str | None = None,
    ) -> list[Finding]:
        stmt = select(Finding).where(Finding.project_id == project_id)
        if severity:
            stmt = stmt.where(Finding.severity == severity)
        if status:
            stmt = stmt.where(Finding.status == status)
        stmt = stmt.order_by(Finding.created_at.desc())
        result = await self.db.execute(stmt)
        return list(result.scalars().all())

    async def get(self, finding_id: uuid.UUID) -> Finding | None:
        result = await self.db.execute(
            select(Finding).where(Finding.id == finding_id)
        )
        return result.scalar_one_or_none()

    async def update(self, finding_id: uuid.UUID, data: FindingUpdate) -> Finding | None:
        finding = await self.get(finding_id)
        if finding is None:
            return None
        update_data = data.model_dump(exclude_unset=True)
        # Convert enum values to strings
        for key, value in update_data.items():
            if hasattr(value, "value"):
                value = value.value
            setattr(finding, key, value)
        await self.db.flush()
        await self.db.refresh(finding)
        return finding

    async def delete(self, finding_id: uuid.UUID) -> bool:
        finding = await self.get(finding_id)
        if finding is None:
            return False
        await self.db.delete(finding)
        await self.db.flush()
        return True
