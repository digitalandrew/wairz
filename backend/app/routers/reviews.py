import asyncio
import json
import logging
import uuid

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.agent_config import AGENT_CONFIGS
from app.database import async_session_factory, get_db
from app.models.project import Project
from app.schemas.review import ReviewCreate, ReviewResponse
from app.services.review_runner import ReviewManager
from app.services.review_service import ReviewService

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/projects/{project_id}/reviews",
    tags=["reviews"],
)


async def _get_project_or_404(project_id: uuid.UUID, db: AsyncSession) -> Project:
    result = await db.execute(select(Project).where(Project.id == project_id))
    project = result.scalar_one_or_none()
    if not project:
        raise HTTPException(404, "Project not found")
    return project


@router.post("", response_model=ReviewResponse, status_code=201)
async def create_review(
    project_id: uuid.UUID,
    data: ReviewCreate,
    db: AsyncSession = Depends(get_db),
):
    project = await _get_project_or_404(project_id, db)

    if project.status != "ready":
        raise HTTPException(400, "Project firmware must be unpacked before running a review")

    # Validate categories
    categories = [c.value for c in data.categories]
    for cat in categories:
        if cat not in AGENT_CONFIGS:
            raise HTTPException(400, f"Unknown category: {cat}")

    svc = ReviewService(db)

    # Create review
    review = await svc.create_review(project_id, categories)

    # Create agent records for each category
    for cat in categories:
        config = AGENT_CONFIGS[cat]
        await svc.create_agent(
            review_id=review.id,
            category=cat,
            model=config["model"],
        )

    await db.commit()

    # Reload with agents
    review = await svc.get_review(review.id)

    # Launch the runner as a background task
    ReviewManager.start(review.id, project_id)

    return review


@router.get("", response_model=list[ReviewResponse])
async def list_reviews(
    project_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    await _get_project_or_404(project_id, db)
    svc = ReviewService(db)
    return await svc.list_reviews(project_id)


@router.get("/{review_id}", response_model=ReviewResponse)
async def get_review(
    project_id: uuid.UUID,
    review_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    await _get_project_or_404(project_id, db)
    svc = ReviewService(db)
    review = await svc.get_review(review_id)
    if not review or review.project_id != project_id:
        raise HTTPException(404, "Review not found")
    return review


@router.get("/{review_id}/stream")
async def stream_review(
    project_id: uuid.UUID,
    review_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    """SSE stream for real-time review progress updates."""
    await _get_project_or_404(project_id, db)
    svc = ReviewService(db)
    review = await svc.get_review(review_id)
    if not review or review.project_id != project_id:
        raise HTTPException(404, "Review not found")

    runner = ReviewManager.get(review_id)

    async def event_generator():
        # If review is already complete, send final status and close
        if review.status in ("completed", "failed", "cancelled"):
            yield _sse_format("review_complete", {
                "review_id": str(review_id),
                "status": review.status,
            })
            return

        # If no active runner and review is in a non-terminal state,
        # it's an orphan (runner crashed without updating status).
        # Mark it as failed and send terminal event so EventSource stops.
        if not runner:
            if review.status in ("pending", "running"):
                # Orphaned review — mark failed in DB
                try:
                    async with async_session_factory() as fail_db:
                        fail_svc = ReviewService(fail_db)
                        await fail_svc.update_review_status(review_id, "failed")
                        await fail_db.commit()
                except Exception:
                    logger.warning("Could not mark orphaned review %s as failed", review_id)
                yield _sse_format("review_complete", {
                    "review_id": str(review_id),
                    "status": "failed",
                    "error": "Review runner is no longer active. Please start a new review.",
                })
            else:
                yield _sse_format("review_complete", {
                    "review_id": str(review_id),
                    "status": review.status,
                })
            return

        queue = runner.subscribe()
        try:
            while True:
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=30)
                except asyncio.TimeoutError:
                    # Send heartbeat
                    yield _sse_format("heartbeat", {})
                    continue

                if event is None:
                    # Runner finished
                    break

                event_type = event.get("event", "message")
                event_data = event.get("data", {})
                yield _sse_format(event_type, event_data)

                if event_type == "review_complete":
                    break
        finally:
            runner.unsubscribe(queue)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@router.post("/{review_id}/cancel", status_code=200)
async def cancel_review(
    project_id: uuid.UUID,
    review_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    await _get_project_or_404(project_id, db)
    svc = ReviewService(db)
    review = await svc.get_review(review_id)
    if not review or review.project_id != project_id:
        raise HTTPException(404, "Review not found")

    if review.status not in ("pending", "running"):
        raise HTTPException(400, "Review is not running")

    cancelled = ReviewManager.cancel(review_id)
    if not cancelled:
        # Runner not active, update DB directly
        await svc.update_review_status(review_id, "cancelled")
        await db.commit()

    return {"status": "cancelled"}


def _sse_format(event: str, data: dict) -> str:
    """Format an SSE message."""
    return f"event: {event}\ndata: {json.dumps(data)}\n\n"
