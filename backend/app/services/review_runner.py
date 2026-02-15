"""Orchestrates concurrent agents for autonomous security reviews."""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai import create_tool_registry
from app.ai.agent_config import AGENT_CONFIGS
from app.ai.orchestrator import AIOrchestrator, ProjectContext
from app.ai.tools.review import register_review_tools
from app.database import async_session_factory
from app.models.conversation import Conversation
from app.models.firmware import Firmware
from app.models.project import Project
from app.models.security_review import ReviewAgent, SecurityReview
from app.services.review_service import ReviewService

logger = logging.getLogger(__name__)


class ReviewRunner:
    """Orchestrates all agents in a single security review."""

    def __init__(
        self,
        review_id: UUID,
        project_id: UUID,
    ) -> None:
        self.review_id = review_id
        self.project_id = project_id
        self._event_queues: list[asyncio.Queue] = []
        self._cancel = asyncio.Event()
        self._semaphore = asyncio.Semaphore(3)  # max 3 concurrent API calls
        self._task: asyncio.Task | None = None

    def subscribe(self) -> asyncio.Queue:
        """Add an SSE subscriber. Returns a queue to read events from."""
        q: asyncio.Queue = asyncio.Queue()
        self._event_queues.append(q)
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        """Remove an SSE subscriber."""
        try:
            self._event_queues.remove(q)
        except ValueError:
            pass

    def cancel(self) -> None:
        """Signal cancellation to all running agents."""
        self._cancel.set()

    @property
    def is_cancelled(self) -> bool:
        return self._cancel.is_set()

    async def _broadcast(self, event: dict) -> None:
        """Broadcast an event to all SSE subscribers."""
        for q in self._event_queues:
            try:
                q.put_nowait(event)
            except asyncio.QueueFull:
                pass  # drop event if subscriber is slow

    async def run(self) -> None:
        """Run the full review: phase 1 (category agents) then phase 2 (final review)."""
        async with async_session_factory() as db:
            try:
                # Load review and agents
                svc = ReviewService(db)
                review = await svc.get_review(self.review_id)
                if not review:
                    logger.error("Review %s not found", self.review_id)
                    return

                # Mark review as running
                now = datetime.now(timezone.utc)
                await svc.update_review_status(
                    self.review_id, "running", started_at=now,
                )
                await db.commit()

                await self._broadcast({
                    "event": "review_status_change",
                    "data": {"review_id": str(self.review_id), "status": "running"},
                })

                # Load project context
                project_context = await self._build_project_context(db)
                if not project_context:
                    await svc.update_review_status(self.review_id, "failed")
                    await db.commit()
                    return

                # Split agents into phases
                agents = await svc.get_agents_for_review(self.review_id)
                phase1 = [a for a in agents if a.category != "final_review"]
                final_agents = [a for a in agents if a.category == "final_review"]

            except Exception:
                logger.exception("Failed to initialize review %s", self.review_id)
                return

        # Phase 1: run category agents concurrently
        if phase1 and not self.is_cancelled:
            results = await asyncio.gather(
                *[self._run_agent(a.id, a.category, project_context) for a in phase1],
                return_exceptions=True,
            )
            for agent, result in zip(phase1, results):
                if isinstance(result, Exception):
                    logger.error("Agent %s failed: %s", agent.category, result)

        # Phase 2: run final review agent
        if final_agents and not self.is_cancelled:
            for agent in final_agents:
                await self._run_agent(agent.id, agent.category, project_context)

        # Mark review complete
        async with async_session_factory() as db:
            svc = ReviewService(db)
            final_status = "cancelled" if self.is_cancelled else "completed"
            now = datetime.now(timezone.utc)
            await svc.update_review_status(
                self.review_id, final_status, completed_at=now,
            )
            await db.commit()

        await self._broadcast({
            "event": "review_complete",
            "data": {
                "review_id": str(self.review_id),
                "status": final_status,
            },
        })

        # Signal end to all subscribers
        for q in self._event_queues:
            try:
                q.put_nowait(None)
            except asyncio.QueueFull:
                pass

    async def _run_agent(
        self,
        agent_id: UUID,
        category: str,
        project_context: ProjectContext,
    ) -> None:
        """Run a single agent with its own DB session and tool registry."""
        async with self._semaphore:
            if self.is_cancelled:
                return

            config = AGENT_CONFIGS.get(category)
            if not config:
                logger.error("No config for category %s", category)
                return

            async with async_session_factory() as db:
                try:
                    svc = ReviewService(db)

                    # Mark agent as running
                    now = datetime.now(timezone.utc)
                    await svc.update_agent(agent_id, status="running", started_at=now)
                    await db.commit()

                    await self._broadcast({
                        "event": "agent_status_change",
                        "data": {
                            "review_id": str(self.review_id),
                            "agent_id": str(agent_id),
                            "category": category,
                            "status": "running",
                        },
                    })

                    # Create conversation for this agent
                    conversation = Conversation(
                        project_id=self.project_id,
                        title=f"Security Review: {category.replace('_', ' ').title()}",
                        messages=[],
                    )
                    db.add(conversation)
                    await db.flush()

                    await svc.update_agent(agent_id, conversation_id=conversation.id)
                    await db.commit()

                    # Build filtered tool registry
                    full_registry = create_tool_registry()
                    register_review_tools(full_registry)
                    agent_registry = full_registry.subset(config["tools"])

                    # Build system prompt with firmware context
                    system_prompt = config["system_prompt"].format(
                        firmware_filename=project_context.firmware_filename,
                        architecture=project_context.architecture or "unknown",
                        endianness=project_context.endianness or "unknown",
                        extracted_path=project_context.extracted_path,
                    )

                    orchestrator = AIOrchestrator(
                        registry=agent_registry,
                        max_iterations=config["max_iterations"],
                    )

                    messages: list[dict] = [
                        {"role": "user", "content": config["initial_message"]},
                    ]

                    tool_calls_count = 0
                    findings_count = 0

                    async def on_event(event: dict) -> None:
                        nonlocal tool_calls_count, findings_count

                        if event.get("type") == "tool_call":
                            tool_calls_count += 1
                            await self._broadcast({
                                "event": "agent_tool_call",
                                "data": {
                                    "review_id": str(self.review_id),
                                    "agent_id": str(agent_id),
                                    "category": category,
                                    "tool": event.get("tool"),
                                    "tool_calls_count": tool_calls_count,
                                },
                            })
                            # Check if it's an add_finding call
                            if event.get("tool") == "add_finding":
                                findings_count += 1
                                await self._broadcast({
                                    "event": "agent_finding",
                                    "data": {
                                        "review_id": str(self.review_id),
                                        "agent_id": str(agent_id),
                                        "category": category,
                                        "findings_count": findings_count,
                                        "title": event.get("input", {}).get("title", ""),
                                        "severity": event.get("input", {}).get("severity", ""),
                                    },
                                })

                    def cancel_check() -> bool:
                        return self.is_cancelled

                    messages = await orchestrator.run_conversation(
                        messages=messages,
                        project_context=project_context,
                        db=db,
                        on_event=on_event,
                        model=config["model"],
                        system_prompt=system_prompt,
                        cancel_check=cancel_check,
                        tool_context_extras={
                            "review_id": self.review_id,
                            "review_agent_id": agent_id,
                        },
                    )

                    # Save conversation messages
                    conversation.messages = messages
                    await db.flush()

                    # Update agent status
                    final_status = "cancelled" if self.is_cancelled else "completed"
                    now = datetime.now(timezone.utc)
                    await svc.update_agent(
                        agent_id,
                        status=final_status,
                        completed_at=now,
                        tool_calls_count=tool_calls_count,
                        findings_count=findings_count,
                    )
                    await db.commit()

                    await self._broadcast({
                        "event": "agent_status_change",
                        "data": {
                            "review_id": str(self.review_id),
                            "agent_id": str(agent_id),
                            "category": category,
                            "status": final_status,
                            "tool_calls_count": tool_calls_count,
                            "findings_count": findings_count,
                        },
                    })

                except Exception as exc:
                    logger.exception("Agent %s failed", category)
                    now = datetime.now(timezone.utc)
                    try:
                        await svc.update_agent(
                            agent_id,
                            status="failed",
                            error_message=str(exc),
                            completed_at=now,
                            tool_calls_count=tool_calls_count,
                            findings_count=findings_count,
                        )
                        await db.commit()
                    except Exception:
                        logger.exception("Failed to update agent status")

                    await self._broadcast({
                        "event": "agent_status_change",
                        "data": {
                            "review_id": str(self.review_id),
                            "agent_id": str(agent_id),
                            "category": category,
                            "status": "failed",
                            "error": str(exc),
                        },
                    })

    async def _build_project_context(self, db: AsyncSession) -> ProjectContext | None:
        """Load project and firmware data to build ProjectContext."""
        result = await db.execute(
            select(Project).where(Project.id == self.project_id)
        )
        project = result.scalar_one_or_none()
        if not project:
            logger.error("Project %s not found", self.project_id)
            return None

        fw_result = await db.execute(
            select(Firmware).where(Firmware.project_id == self.project_id)
        )
        firmware = fw_result.scalar_one_or_none()
        if not firmware or not firmware.extracted_path:
            logger.error("No unpacked firmware for project %s", self.project_id)
            return None

        return ProjectContext(
            project_id=project.id,
            firmware_id=firmware.id,
            project_name=project.name,
            firmware_filename=firmware.original_filename or "firmware.bin",
            architecture=firmware.architecture,
            endianness=firmware.endianness,
            extracted_path=firmware.extracted_path,
        )


# Module-level manager: maps review_id -> ReviewRunner
_active_runners: dict[UUID, ReviewRunner] = {}


class ReviewManager:
    """Manages active review runners."""

    @staticmethod
    def start(review_id: UUID, project_id: UUID) -> ReviewRunner:
        """Create and launch a ReviewRunner as a background task."""
        runner = ReviewRunner(review_id, project_id)
        _active_runners[review_id] = runner
        task = asyncio.create_task(runner.run())
        runner._task = task

        # Clean up when done
        def _cleanup(t: asyncio.Task) -> None:
            _active_runners.pop(review_id, None)

        task.add_done_callback(_cleanup)
        return runner

    @staticmethod
    def get(review_id: UUID) -> ReviewRunner | None:
        """Get an active runner by review ID."""
        return _active_runners.get(review_id)

    @staticmethod
    def cancel(review_id: UUID) -> bool:
        """Cancel a running review."""
        runner = _active_runners.get(review_id)
        if runner:
            runner.cancel()
            return True
        return False
