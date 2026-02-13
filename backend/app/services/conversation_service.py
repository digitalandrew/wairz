import uuid

from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.conversation import Conversation


class ConversationService:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def create(self, project_id: uuid.UUID, title: str | None = None) -> Conversation:
        conversation = Conversation(project_id=project_id, title=title)
        self.db.add(conversation)
        await self.db.flush()
        return conversation

    async def list_by_project(self, project_id: uuid.UUID) -> list[Conversation]:
        result = await self.db.execute(
            select(Conversation)
            .where(Conversation.project_id == project_id)
            .order_by(Conversation.created_at.desc())
        )
        return list(result.scalars().all())

    async def get(self, conversation_id: uuid.UUID) -> Conversation | None:
        result = await self.db.execute(
            select(Conversation).where(Conversation.id == conversation_id)
        )
        return result.scalar_one_or_none()

    async def save_messages(self, conversation_id: uuid.UUID, messages: list[dict]) -> None:
        result = await self.db.execute(
            select(Conversation).where(Conversation.id == conversation_id)
        )
        conversation = result.scalar_one_or_none()
        if conversation is None:
            return
        conversation.messages = messages
        conversation.updated_at = func.now()
        await self.db.flush()
