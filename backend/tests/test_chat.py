"""Tests for conversations: service, REST endpoints, WebSocket, and registry factory."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from app.ai import create_tool_registry
from app.routers.chat import router
from app.services.conversation_service import ConversationService


# ---------------------------------------------------------------------------
# Helpers — use SimpleNamespace to avoid SQLAlchemy instrumentation issues
# ---------------------------------------------------------------------------

def _make_project(project_id: uuid.UUID | None = None) -> SimpleNamespace:
    return SimpleNamespace(
        id=project_id or uuid.uuid4(),
        name="Test Project",
        description=None,
        status="ready",
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )


def _make_firmware(project_id: uuid.UUID, firmware_id: uuid.UUID | None = None) -> SimpleNamespace:
    return SimpleNamespace(
        id=firmware_id or uuid.uuid4(),
        project_id=project_id,
        original_filename="openwrt.bin",
        sha256="a" * 64,
        file_size=1024,
        storage_path="/data/firmware/projects/test/firmware/openwrt.bin",
        extracted_path="/data/firmware/projects/test/extracted",
        architecture="mips",
        endianness="big",
        os_info=None,
        unpack_log=None,
        created_at=datetime.now(timezone.utc),
    )


def _make_conversation(
    project_id: uuid.UUID,
    conversation_id: uuid.UUID | None = None,
    title: str | None = None,
    messages: list | None = None,
) -> SimpleNamespace:
    return SimpleNamespace(
        id=conversation_id or uuid.uuid4(),
        project_id=project_id,
        title=title,
        messages=messages if messages is not None else [],
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )


# ---------------------------------------------------------------------------
# ConversationService tests
# ---------------------------------------------------------------------------

class TestConversationService:
    @pytest.mark.asyncio
    async def test_create(self):
        db = MagicMock()
        db.add = MagicMock()
        db.flush = AsyncMock()
        svc = ConversationService(db)
        conversation = await svc.create(uuid.uuid4(), "My Chat")

        db.add.assert_called_once()
        db.flush.assert_awaited_once()
        assert conversation.title == "My Chat"

    @pytest.mark.asyncio
    async def test_create_no_title(self):
        db = MagicMock()
        db.add = MagicMock()
        db.flush = AsyncMock()
        svc = ConversationService(db)
        conversation = await svc.create(uuid.uuid4())

        assert conversation.title is None

    @pytest.mark.asyncio
    async def test_list_by_project(self):
        project_id = uuid.uuid4()
        convos = [
            _make_conversation(project_id, title="First"),
            _make_conversation(project_id, title="Second"),
        ]

        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = convos

        db = AsyncMock()
        db.execute.return_value = mock_result

        svc = ConversationService(db)
        result = await svc.list_by_project(project_id)

        assert len(result) == 2
        db.execute.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_get_found(self):
        conv = _make_conversation(uuid.uuid4(), title="Found")

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = conv

        db = AsyncMock()
        db.execute.return_value = mock_result

        svc = ConversationService(db)
        result = await svc.get(conv.id)
        assert result is conv

    @pytest.mark.asyncio
    async def test_get_not_found(self):
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None

        db = AsyncMock()
        db.execute.return_value = mock_result

        svc = ConversationService(db)
        result = await svc.get(uuid.uuid4())
        assert result is None

    @pytest.mark.asyncio
    async def test_save_messages(self):
        conv = _make_conversation(uuid.uuid4())

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = conv

        db = AsyncMock()
        db.execute.return_value = mock_result

        svc = ConversationService(db)
        new_messages = [{"role": "user", "content": "hello"}]
        await svc.save_messages(conv.id, new_messages)

        assert conv.messages == new_messages
        db.flush.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_save_messages_not_found(self):
        """save_messages silently returns if conversation doesn't exist."""
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None

        db = AsyncMock()
        db.execute.return_value = mock_result

        svc = ConversationService(db)
        await svc.save_messages(uuid.uuid4(), [{"role": "user", "content": "hi"}])
        db.flush.assert_not_awaited()


# ---------------------------------------------------------------------------
# REST endpoint tests
# ---------------------------------------------------------------------------

def _create_test_app() -> FastAPI:
    app = FastAPI()
    app.include_router(router)
    return app


class TestConversationRESTEndpoints:
    @pytest.fixture
    def app(self):
        return _create_test_app()

    @pytest.fixture
    def project(self):
        return _make_project()

    @pytest.fixture
    def conversation(self, project):
        return _make_conversation(project.id, title="Test Chat")

    @pytest.mark.asyncio
    async def test_create_conversation(self, app, project, conversation):
        async def mock_get_db():
            db = AsyncMock()
            project_result = MagicMock()
            project_result.scalar_one_or_none.return_value = project
            db.execute.return_value = project_result
            db.commit = AsyncMock()
            yield db

        from app.database import get_db
        app.dependency_overrides[get_db] = mock_get_db

        with patch.object(ConversationService, "create", new_callable=AsyncMock) as mock_create:
            mock_create.return_value = conversation

            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test"
            ) as client:
                resp = await client.post(
                    f"/api/v1/projects/{project.id}/conversations",
                    json={"title": "Test Chat"},
                )

            assert resp.status_code == 201
            data = resp.json()
            assert data["title"] == "Test Chat"
            assert data["project_id"] == str(project.id)

        app.dependency_overrides.clear()

    @pytest.mark.asyncio
    async def test_list_conversations(self, app, project, conversation):
        conv2 = _make_conversation(project.id, title="Second")

        async def mock_get_db():
            db = AsyncMock()
            project_result = MagicMock()
            project_result.scalar_one_or_none.return_value = project
            db.execute.return_value = project_result
            db.commit = AsyncMock()
            yield db

        from app.database import get_db
        app.dependency_overrides[get_db] = mock_get_db

        with patch.object(
            ConversationService, "list_by_project", new_callable=AsyncMock
        ) as mock_list:
            mock_list.return_value = [conversation, conv2]

            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test"
            ) as client:
                resp = await client.get(
                    f"/api/v1/projects/{project.id}/conversations"
                )

            assert resp.status_code == 200
            data = resp.json()
            assert len(data) == 2

        app.dependency_overrides.clear()

    @pytest.mark.asyncio
    async def test_get_conversation_detail(self, app, project, conversation):
        conversation.messages = [{"role": "user", "content": "hello"}]

        async def mock_get_db():
            db = AsyncMock()
            project_result = MagicMock()
            project_result.scalar_one_or_none.return_value = project
            db.execute.return_value = project_result
            db.commit = AsyncMock()
            yield db

        from app.database import get_db
        app.dependency_overrides[get_db] = mock_get_db

        with patch.object(ConversationService, "get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = conversation

            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test"
            ) as client:
                resp = await client.get(
                    f"/api/v1/projects/{project.id}/conversations/{conversation.id}"
                )

            assert resp.status_code == 200
            data = resp.json()
            assert data["messages"] == [{"role": "user", "content": "hello"}]

        app.dependency_overrides.clear()

    @pytest.mark.asyncio
    async def test_get_conversation_not_found(self, app, project):
        async def mock_get_db():
            db = AsyncMock()
            project_result = MagicMock()
            project_result.scalar_one_or_none.return_value = project
            db.execute.return_value = project_result
            db.commit = AsyncMock()
            yield db

        from app.database import get_db
        app.dependency_overrides[get_db] = mock_get_db

        with patch.object(ConversationService, "get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = None

            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test"
            ) as client:
                resp = await client.get(
                    f"/api/v1/projects/{project.id}/conversations/{uuid.uuid4()}"
                )

            assert resp.status_code == 404

        app.dependency_overrides.clear()

    @pytest.mark.asyncio
    async def test_create_conversation_project_not_found(self, app):
        async def mock_get_db():
            db = AsyncMock()
            project_result = MagicMock()
            project_result.scalar_one_or_none.return_value = None
            db.execute.return_value = project_result
            db.commit = AsyncMock()
            yield db

        from app.database import get_db
        app.dependency_overrides[get_db] = mock_get_db

        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.post(
                f"/api/v1/projects/{uuid.uuid4()}/conversations",
                json={"title": "Orphan"},
            )

        assert resp.status_code == 404

        app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# WebSocket tests
# ---------------------------------------------------------------------------

def _mock_session_cm(mock_db):
    """Create a mock async context manager that yields mock_db."""
    cm = MagicMock()
    cm.__aenter__ = AsyncMock(return_value=mock_db)
    cm.__aexit__ = AsyncMock(return_value=False)
    return cm


def _setup_db_lookups(project, conversation, firmware):
    """Create a mock db with sequential execute results for WS setup."""
    mock_db = MagicMock()
    mock_db.commit = AsyncMock()
    mock_db.flush = AsyncMock()

    project_result = MagicMock()
    project_result.scalar_one_or_none.return_value = project

    conv_result = MagicMock()
    conv_result.scalar_one_or_none.return_value = conversation

    fw_result = MagicMock()
    fw_result.scalar_one_or_none.return_value = firmware

    call_count = 0

    async def mock_execute(stmt):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return project_result
        elif call_count == 2:
            return conv_result
        elif call_count == 3:
            return fw_result
        # Subsequent calls (e.g. save_messages) return conv_result
        return conv_result

    mock_db.execute = mock_execute
    return mock_db


class TestWebSocketChat:
    def test_websocket_send_and_receive(self):
        """Full WebSocket flow: connect, send message, receive streaming events."""
        app = _create_test_app()

        project = _make_project()
        firmware = _make_firmware(project.id)
        conversation = _make_conversation(project.id, messages=[])

        mock_db = _setup_db_lookups(project, conversation, firmware)

        async def mock_run_conversation(messages, context, db, on_event, **kwargs):
            await on_event({"type": "assistant_text", "content": "Hello!", "delta": True})
            await on_event({"type": "done"})
            messages.append({
                "role": "assistant",
                "content": [{"type": "text", "text": "Hello!"}],
            })
            return messages

        with (
            patch("app.routers.chat.async_session_factory", return_value=_mock_session_cm(mock_db)),
            patch("app.routers.chat.AIOrchestrator") as MockOrch,
        ):
            mock_orch_instance = MagicMock()
            mock_orch_instance.run_conversation = AsyncMock(side_effect=mock_run_conversation)
            MockOrch.return_value = mock_orch_instance

            from starlette.testclient import TestClient

            with TestClient(app) as client:
                with client.websocket_connect(
                    f"/api/v1/projects/{project.id}/conversations/{conversation.id}/ws"
                ) as ws:
                    ws.send_json({"type": "user_message", "content": "Hi there"})

                    events = []
                    while True:
                        event = ws.receive_json()
                        events.append(event)
                        if event.get("type") == "done":
                            break

                    assert len(events) == 2
                    assert events[0]["type"] == "assistant_text"
                    assert events[0]["content"] == "Hello!"
                    assert events[1]["type"] == "done"

    def test_websocket_project_not_found(self):
        """WebSocket sends error and closes if project not found."""
        app = _create_test_app()

        mock_db = MagicMock()
        project_result = MagicMock()
        project_result.scalar_one_or_none.return_value = None
        mock_db.execute = AsyncMock(return_value=project_result)

        with patch("app.routers.chat.async_session_factory", return_value=_mock_session_cm(mock_db)):
            from starlette.testclient import TestClient

            with TestClient(app) as client:
                with client.websocket_connect(
                    f"/api/v1/projects/{uuid.uuid4()}/conversations/{uuid.uuid4()}/ws"
                ) as ws:
                    # Server should send error then close
                    event = ws.receive_json()
                    assert event["type"] == "error"
                    assert "Project not found" in event["content"]

    def test_websocket_no_firmware(self):
        """WebSocket sends error if no unpacked firmware exists."""
        app = _create_test_app()

        project = _make_project()
        conversation = _make_conversation(project.id)

        mock_db = _setup_db_lookups(project, conversation, firmware=None)

        with patch("app.routers.chat.async_session_factory", return_value=_mock_session_cm(mock_db)):
            from starlette.testclient import TestClient

            with TestClient(app) as client:
                with client.websocket_connect(
                    f"/api/v1/projects/{project.id}/conversations/{conversation.id}/ws"
                ) as ws:
                    event = ws.receive_json()
                    assert event["type"] == "error"
                    assert "firmware" in event["content"].lower()

    def test_websocket_ignores_invalid_messages(self):
        """WebSocket ignores messages without proper type/content."""
        app = _create_test_app()

        project = _make_project()
        firmware = _make_firmware(project.id)
        conversation = _make_conversation(project.id, messages=[])

        mock_db = _setup_db_lookups(project, conversation, firmware)

        async def mock_run_conversation(messages, context, db, on_event, **kwargs):
            await on_event({"type": "assistant_text", "content": "Got it", "delta": True})
            await on_event({"type": "done"})
            messages.append({
                "role": "assistant",
                "content": [{"type": "text", "text": "Got it"}],
            })
            return messages

        with (
            patch("app.routers.chat.async_session_factory", return_value=_mock_session_cm(mock_db)),
            patch("app.routers.chat.AIOrchestrator") as MockOrch,
        ):
            mock_orch_instance = MagicMock()
            mock_orch_instance.run_conversation = AsyncMock(side_effect=mock_run_conversation)
            MockOrch.return_value = mock_orch_instance

            from starlette.testclient import TestClient

            with TestClient(app) as client:
                with client.websocket_connect(
                    f"/api/v1/projects/{project.id}/conversations/{conversation.id}/ws"
                ) as ws:
                    # Send invalid messages - should be ignored
                    ws.send_json({"content": "no type"})
                    ws.send_json({"type": "user_message", "content": ""})
                    # Send a valid message
                    ws.send_json({"type": "user_message", "content": "hello"})

                    events = []
                    while True:
                        event = ws.receive_json()
                        events.append(event)
                        if event.get("type") == "done":
                            break

                    assert events[-1]["type"] == "done"
                    assert mock_orch_instance.run_conversation.await_count == 1


# ---------------------------------------------------------------------------
# Registry factory tests
# ---------------------------------------------------------------------------

class TestRegistryFactory:
    def test_create_tool_registry_returns_registry_with_tools(self):
        registry = create_tool_registry()
        tools = registry.get_anthropic_tools()
        assert len(tools) >= 5
        tool_names = {t["name"] for t in tools}
        assert "list_directory" in tool_names
        assert "read_file" in tool_names
        assert "file_info" in tool_names
        assert "search_files" in tool_names
        assert "find_files_by_type" in tool_names

    def test_create_tool_registry_returns_new_instance(self):
        r1 = create_tool_registry()
        r2 = create_tool_registry()
        assert r1 is not r2
