import logging
import uuid

from fastapi import APIRouter, Depends, HTTPException, WebSocket, WebSocketDisconnect
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai import create_tool_registry
from app.ai.orchestrator import AIOrchestrator, ProjectContext
from app.database import async_session_factory, get_db
from app.models.firmware import Firmware
from app.models.project import Project
from app.schemas.chat import ConversationCreate, ConversationDetailResponse, ConversationResponse
from app.services.conversation_service import ConversationService

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/projects/{project_id}/conversations",
    tags=["conversations"],
)


async def _get_project_or_404(project_id: uuid.UUID, db: AsyncSession) -> Project:
    result = await db.execute(select(Project).where(Project.id == project_id))
    project = result.scalar_one_or_none()
    if not project:
        raise HTTPException(404, "Project not found")
    return project


@router.post("", response_model=ConversationResponse, status_code=201)
async def create_conversation(
    project_id: uuid.UUID,
    data: ConversationCreate,
    db: AsyncSession = Depends(get_db),
):
    await _get_project_or_404(project_id, db)
    svc = ConversationService(db)
    conversation = await svc.create(project_id, data.title)
    return conversation


@router.get("", response_model=list[ConversationResponse])
async def list_conversations(
    project_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    await _get_project_or_404(project_id, db)
    svc = ConversationService(db)
    return await svc.list_by_project(project_id)


@router.get("/{conversation_id}", response_model=ConversationDetailResponse)
async def get_conversation(
    project_id: uuid.UUID,
    conversation_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    await _get_project_or_404(project_id, db)
    svc = ConversationService(db)
    conversation = await svc.get(conversation_id)
    if not conversation or conversation.project_id != project_id:
        raise HTTPException(404, "Conversation not found")
    return conversation


@router.websocket("/{conversation_id}/ws")
async def websocket_chat(
    websocket: WebSocket,
    project_id: uuid.UUID,
    conversation_id: uuid.UUID,
):
    await websocket.accept()

    async with async_session_factory() as db:
        try:
            # Validate project
            result = await db.execute(select(Project).where(Project.id == project_id))
            project = result.scalar_one_or_none()
            if not project:
                await websocket.send_json({"type": "error", "content": "Project not found"})
                await websocket.close(code=4004)
                return

            # Validate conversation
            svc = ConversationService(db)
            conversation = await svc.get(conversation_id)
            if not conversation or conversation.project_id != project_id:
                await websocket.send_json({"type": "error", "content": "Conversation not found"})
                await websocket.close(code=4004)
                return

            # Load firmware metadata
            fw_result = await db.execute(
                select(Firmware).where(Firmware.project_id == project_id)
            )
            firmware = fw_result.scalar_one_or_none()
            if not firmware or not firmware.extracted_path:
                await websocket.send_json({"type": "error", "content": "No unpacked firmware found"})
                await websocket.close(code=4004)
                return

            # Set up orchestrator
            registry = create_tool_registry()
            orchestrator = AIOrchestrator(registry)

            project_context = ProjectContext(
                project_id=project.id,
                firmware_id=firmware.id,
                project_name=project.name,
                firmware_filename=firmware.original_filename or "firmware.bin",
                architecture=firmware.architecture,
                endianness=firmware.endianness,
                extracted_path=firmware.extracted_path,
            )

            messages = list(conversation.messages or [])

            # Message loop
            while True:
                data = await websocket.receive_json()

                if data.get("type") != "user_message" or not data.get("content"):
                    continue

                user_text = data["content"]
                messages.append({"role": "user", "content": user_text})

                async def on_event(event: dict) -> None:
                    await websocket.send_json(event)

                messages = await orchestrator.run_conversation(
                    messages, project_context, db, on_event,
                )

                await svc.save_messages(conversation_id, messages)
                await db.commit()

        except WebSocketDisconnect:
            logger.info("WebSocket disconnected: project=%s conversation=%s", project_id, conversation_id)
        except Exception:
            logger.exception("WebSocket error: project=%s conversation=%s", project_id, conversation_id)
            try:
                await websocket.close(code=1011)
            except Exception:
                pass
