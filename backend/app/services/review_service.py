import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models.security_review import ReviewAgent, SecurityReview


class ReviewService:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def create_review(
        self,
        project_id: uuid.UUID,
        categories: list[str],
    ) -> SecurityReview:
        review = SecurityReview(
            project_id=project_id,
            selected_categories=categories,
        )
        self.db.add(review)
        await self.db.flush()
        return review

    async def create_agent(
        self,
        review_id: uuid.UUID,
        category: str,
        model: str,
    ) -> ReviewAgent:
        agent = ReviewAgent(
            review_id=review_id,
            category=category,
            model=model,
        )
        self.db.add(agent)
        await self.db.flush()
        return agent

    async def get_review(self, review_id: uuid.UUID) -> SecurityReview | None:
        result = await self.db.execute(
            select(SecurityReview)
            .where(SecurityReview.id == review_id)
            .options(selectinload(SecurityReview.agents))
        )
        return result.scalar_one_or_none()

    async def list_reviews(self, project_id: uuid.UUID) -> list[SecurityReview]:
        result = await self.db.execute(
            select(SecurityReview)
            .where(SecurityReview.project_id == project_id)
            .options(selectinload(SecurityReview.agents))
            .order_by(SecurityReview.created_at.desc())
        )
        return list(result.scalars().all())

    async def update_review_status(
        self,
        review_id: uuid.UUID,
        status: str,
        **kwargs,
    ) -> SecurityReview | None:
        review = await self.get_review(review_id)
        if not review:
            return None
        review.status = status
        for key, value in kwargs.items():
            setattr(review, key, value)
        await self.db.flush()
        return review

    async def update_agent(
        self,
        agent_id: uuid.UUID,
        **kwargs,
    ) -> ReviewAgent | None:
        result = await self.db.execute(
            select(ReviewAgent).where(ReviewAgent.id == agent_id)
        )
        agent = result.scalar_one_or_none()
        if not agent:
            return None
        for key, value in kwargs.items():
            setattr(agent, key, value)
        await self.db.flush()
        return agent

    async def get_agents_for_review(self, review_id: uuid.UUID) -> list[ReviewAgent]:
        result = await self.db.execute(
            select(ReviewAgent)
            .where(ReviewAgent.review_id == review_id)
            .order_by(ReviewAgent.created_at)
        )
        return list(result.scalars().all())
