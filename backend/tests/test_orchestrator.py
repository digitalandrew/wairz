"""Tests for the AI orchestrator and system prompt."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import anthropic.types as types
import pytest

from app.ai.orchestrator import AIOrchestrator, ProjectContext
from app.ai.system_prompt import build_system_prompt
from app.ai.tool_registry import ToolRegistry


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_message(
    content: list,
    stop_reason: str = "end_turn",
) -> types.Message:
    """Create a proper anthropic Message object."""
    return types.Message(
        id="msg_" + uuid4().hex[:8],
        content=content,
        model="claude-sonnet-4-20250514",
        role="assistant",
        stop_reason=stop_reason,
        stop_sequence=None,
        type="message",
        usage=types.Usage(input_tokens=10, output_tokens=20),
    )


def _text_block(text: str) -> types.TextBlock:
    return types.TextBlock(type="text", text=text, citations=None)


def _tool_use_block(
    name: str, input: dict, tool_id: str | None = None,
) -> types.ToolUseBlock:
    return types.ToolUseBlock(
        type="tool_use",
        id=tool_id or ("toolu_" + uuid4().hex[:8]),
        name=name,
        input=input,
    )


class MockStream:
    """Mock for the async stream context manager returned by client.messages.stream()."""

    def __init__(self, text_chunks: list[str], final_message: types.Message):
        self._text_chunks = text_chunks
        self._final_message = final_message

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        pass

    @property
    def text_stream(self):
        return self._iter_text()

    async def _iter_text(self):
        for chunk in self._text_chunks:
            yield chunk

    async def get_final_message(self):
        return self._final_message


def _make_project_context() -> ProjectContext:
    return ProjectContext(
        project_id=uuid4(),
        firmware_id=uuid4(),
        project_name="Test Project",
        firmware_filename="firmware.bin",
        architecture="arm",
        endianness="little",
        extracted_path="/tmp/fake_firmware",
    )


# ---------------------------------------------------------------------------
# System prompt tests
# ---------------------------------------------------------------------------

class TestSystemPrompt:
    def test_includes_project_name(self):
        prompt = build_system_prompt(
            "MyProject", "fw.bin", "mips", "big", "/extracted",
        )
        assert "MyProject" in prompt

    def test_includes_firmware_filename(self):
        prompt = build_system_prompt(
            "P", "openwrt-ramips.bin", "mips", "little", "/ex",
        )
        assert "openwrt-ramips.bin" in prompt

    def test_includes_architecture(self):
        prompt = build_system_prompt("P", "f.bin", "arm", "little", "/ex")
        assert "arm" in prompt

    def test_handles_none_architecture(self):
        prompt = build_system_prompt("P", "f.bin", None, None, "/ex")
        assert "unknown" in prompt

    def test_includes_methodology(self):
        prompt = build_system_prompt("P", "f.bin", "arm", "little", "/ex")
        assert "Hardcoded credentials" in prompt
        assert "security" in prompt.lower()

    def test_includes_extracted_path(self):
        prompt = build_system_prompt("P", "f.bin", "arm", "little", "/data/fw")
        assert "/data/fw" in prompt


# ---------------------------------------------------------------------------
# Orchestrator tests
# ---------------------------------------------------------------------------

class TestOrchestrator:
    @pytest.fixture
    def registry(self):
        reg = ToolRegistry()
        # Register a simple test tool
        async def echo_handler(input: dict, ctx):
            return f"echoed: {input.get('text', '')}"

        reg.register(
            name="echo",
            description="Echo tool",
            input_schema={
                "type": "object",
                "properties": {"text": {"type": "string"}},
                "required": ["text"],
            },
            handler=echo_handler,
        )
        return reg

    @pytest.fixture
    def orchestrator(self, registry):
        with patch("app.ai.orchestrator.get_settings") as mock_settings:
            mock_settings.return_value = MagicMock(
                anthropic_api_key="sk-test-key",
                max_tool_iterations=25,
            )
            orch = AIOrchestrator(registry, api_key="sk-test-key")
        return orch

    @pytest.fixture
    def context(self):
        return _make_project_context()

    @pytest.fixture
    def db(self):
        return MagicMock()

    @pytest.mark.asyncio
    async def test_simple_text_response(self, orchestrator, context, db):
        """Model returns text only with end_turn → text deltas + done."""
        events = []

        async def on_event(event):
            events.append(event)

        final_msg = _make_message(
            [_text_block("Hello, I can help analyze this firmware.")],
            stop_reason="end_turn",
        )

        mock_stream = MockStream(
            text_chunks=["Hello, ", "I can help ", "analyze this firmware."],
            final_message=final_msg,
        )

        orchestrator._client.messages.stream = MagicMock(return_value=mock_stream)

        messages = [{"role": "user", "content": "Hello"}]
        result = await orchestrator.run_conversation(messages, context, db, on_event)

        # Should have text delta events
        text_events = [e for e in events if e["type"] == "assistant_text"]
        assert len(text_events) == 3
        assert text_events[0]["content"] == "Hello, "
        assert text_events[0]["delta"] is True

        # Should end with done
        assert events[-1] == {"type": "done"}

        # Messages list should have the assistant response appended
        assert len(result) == 2
        assert result[1]["role"] == "assistant"
        assert result[1]["content"][0]["type"] == "text"

    @pytest.mark.asyncio
    async def test_single_tool_call(self, orchestrator, context, db):
        """Model calls a tool → execute → model responds with text."""
        events = []

        async def on_event(event):
            events.append(event)

        tool_block = _tool_use_block("echo", {"text": "hello"}, "toolu_abc123")

        # First response: tool_use
        msg1 = _make_message(
            [_text_block("Let me check. "), tool_block],
            stop_reason="tool_use",
        )
        stream1 = MockStream(["Let me check. "], msg1)

        # Second response: text after tool result
        msg2 = _make_message(
            [_text_block("The tool returned the echoed text.")],
            stop_reason="end_turn",
        )
        stream2 = MockStream(["The tool returned the echoed text."], msg2)

        call_count = 0

        def mock_stream_factory(**kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return stream1
            return stream2

        orchestrator._client.messages.stream = mock_stream_factory

        messages = [{"role": "user", "content": "Test tool"}]
        result = await orchestrator.run_conversation(messages, context, db, on_event)

        # Check event sequence
        event_types = [e["type"] for e in events]
        assert "assistant_text" in event_types
        assert "tool_call" in event_types
        assert "tool_result" in event_types
        assert event_types[-1] == "done"

        # Tool call event should have correct data
        tc = next(e for e in events if e["type"] == "tool_call")
        assert tc["tool"] == "echo"
        assert tc["input"] == {"text": "hello"}
        assert tc["tool_use_id"] == "toolu_abc123"

        # Tool result should contain the echoed text
        tr = next(e for e in events if e["type"] == "tool_result")
        assert "echoed: hello" in tr["output"]

        # Messages should include: user, assistant (tool_use), user (tool_result), assistant (text)
        assert len(result) == 4
        assert result[0]["role"] == "user"
        assert result[1]["role"] == "assistant"
        assert result[2]["role"] == "user"
        assert result[3]["role"] == "assistant"

    @pytest.mark.asyncio
    async def test_multi_step_tool_calls(self, orchestrator, context, db):
        """Model calls tools across multiple iterations."""
        events = []

        async def on_event(event):
            events.append(event)

        tool1 = _tool_use_block("echo", {"text": "step1"}, "toolu_1")
        tool2 = _tool_use_block("echo", {"text": "step2"}, "toolu_2")

        # Iteration 1: one tool call
        msg1 = _make_message([tool1], stop_reason="tool_use")
        stream1 = MockStream([], msg1)

        # Iteration 2: another tool call
        msg2 = _make_message([tool2], stop_reason="tool_use")
        stream2 = MockStream([], msg2)

        # Iteration 3: final text
        msg3 = _make_message(
            [_text_block("Done with both steps.")],
            stop_reason="end_turn",
        )
        stream3 = MockStream(["Done with both steps."], msg3)

        call_count = 0

        def mock_stream_factory(**kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return stream1
            elif call_count == 2:
                return stream2
            return stream3

        orchestrator._client.messages.stream = mock_stream_factory

        messages = [{"role": "user", "content": "Do two steps"}]
        result = await orchestrator.run_conversation(messages, context, db, on_event)

        # Should have 2 tool_call events and 2 tool_result events
        tool_calls = [e for e in events if e["type"] == "tool_call"]
        tool_results = [e for e in events if e["type"] == "tool_result"]
        assert len(tool_calls) == 2
        assert len(tool_results) == 2

        assert events[-1] == {"type": "done"}
        assert call_count == 3

    @pytest.mark.asyncio
    async def test_max_iterations_guard(self, orchestrator, context, db):
        """Loop stops when max iterations reached."""
        # Set low max iterations
        orchestrator._max_iterations = 2

        events = []

        async def on_event(event):
            events.append(event)

        tool = _tool_use_block("echo", {"text": "loop"})

        def mock_stream_factory(**kwargs):
            msg = _make_message([tool], stop_reason="tool_use")
            return MockStream([], msg)

        orchestrator._client.messages.stream = mock_stream_factory

        messages = [{"role": "user", "content": "Loop forever"}]
        result = await orchestrator.run_conversation(messages, context, db, on_event)

        # Should have emitted the limit warning
        text_events = [e for e in events if e["type"] == "assistant_text"]
        assert any("maximum tool call limit" in e["content"].lower() for e in text_events)

        # Should end with done
        assert events[-1] == {"type": "done"}

    @pytest.mark.asyncio
    async def test_api_error_handling(self, orchestrator, context, db):
        """API errors are caught and emitted as error events."""
        events = []

        async def on_event(event):
            events.append(event)

        def mock_stream_factory(**kwargs):
            raise anthropic.APIError(
                message="rate limit exceeded",
                request=MagicMock(),
                body=None,
            )

        orchestrator._client.messages.stream = mock_stream_factory

        messages = [{"role": "user", "content": "Hello"}]
        result = await orchestrator.run_conversation(messages, context, db, on_event)

        # Should have error event + done
        error_events = [e for e in events if e["type"] == "error"]
        assert len(error_events) == 1
        assert "error" in error_events[0]["content"].lower() or "rate limit" in error_events[0]["content"].lower()
        assert events[-1] == {"type": "done"}

    @pytest.mark.asyncio
    async def test_unexpected_error_handling(self, orchestrator, context, db):
        """Unexpected exceptions are caught and emitted as error events."""
        events = []

        async def on_event(event):
            events.append(event)

        def mock_stream_factory(**kwargs):
            raise RuntimeError("something broke")

        orchestrator._client.messages.stream = mock_stream_factory

        messages = [{"role": "user", "content": "Hello"}]
        result = await orchestrator.run_conversation(messages, context, db, on_event)

        error_events = [e for e in events if e["type"] == "error"]
        assert len(error_events) == 1
        assert "something broke" in error_events[0]["content"]
        assert events[-1] == {"type": "done"}

    @pytest.mark.asyncio
    async def test_tool_error_continues_loop(self, orchestrator, context, db):
        """When a tool returns an error string, it's sent as tool_result and loop continues."""
        events = []

        async def on_event(event):
            events.append(event)

        # Call a non-existent tool
        bad_tool = _tool_use_block("nonexistent_tool", {}, "toolu_bad")

        msg1 = _make_message([bad_tool], stop_reason="tool_use")
        stream1 = MockStream([], msg1)

        msg2 = _make_message(
            [_text_block("That tool doesn't exist, let me try something else.")],
            stop_reason="end_turn",
        )
        stream2 = MockStream(
            ["That tool doesn't exist, let me try something else."],
            msg2,
        )

        call_count = 0

        def mock_stream_factory(**kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return stream1
            return stream2

        orchestrator._client.messages.stream = mock_stream_factory

        messages = [{"role": "user", "content": "Use bad tool"}]
        result = await orchestrator.run_conversation(messages, context, db, on_event)

        # Tool result should contain error string
        tr = next(e for e in events if e["type"] == "tool_result")
        assert "Error" in tr["output"]
        assert "nonexistent_tool" in tr["output"]

        # Loop should have continued to get final text
        assert events[-1] == {"type": "done"}
        assert call_count == 2

    @pytest.mark.asyncio
    async def test_messages_serialized_correctly(self, orchestrator, context, db):
        """Content blocks are serialized as plain dicts in the messages list."""
        events = []

        async def on_event(event):
            events.append(event)

        tool = _tool_use_block("echo", {"text": "hi"}, "toolu_ser")

        msg1 = _make_message(
            [_text_block("Calling tool."), tool],
            stop_reason="tool_use",
        )
        stream1 = MockStream(["Calling tool."], msg1)

        msg2 = _make_message(
            [_text_block("Done.")],
            stop_reason="end_turn",
        )
        stream2 = MockStream(["Done."], msg2)

        call_count = 0

        def mock_stream_factory(**kwargs):
            nonlocal call_count
            call_count += 1
            return stream1 if call_count == 1 else stream2

        orchestrator._client.messages.stream = mock_stream_factory

        messages = [{"role": "user", "content": "Serialize test"}]
        result = await orchestrator.run_conversation(messages, context, db, on_event)

        # Assistant message with tool_use should be serialized as dicts
        assistant_msg = result[1]
        assert assistant_msg["role"] == "assistant"
        content = assistant_msg["content"]
        assert isinstance(content, list)
        # Should have text block and tool_use block as dicts
        text_block = next(b for b in content if b["type"] == "text")
        assert text_block["text"] == "Calling tool."
        tool_block = next(b for b in content if b["type"] == "tool_use")
        assert tool_block["name"] == "echo"
        assert tool_block["id"] == "toolu_ser"
        assert tool_block["input"] == {"text": "hi"}

        # Tool result message
        tool_result_msg = result[2]
        assert tool_result_msg["role"] == "user"
        assert tool_result_msg["content"][0]["type"] == "tool_result"
        assert tool_result_msg["content"][0]["tool_use_id"] == "toolu_ser"

    @pytest.mark.asyncio
    async def test_multiple_tool_calls_in_single_response(self, orchestrator, context, db):
        """Model returns multiple tool_use blocks in a single response."""
        events = []

        async def on_event(event):
            events.append(event)

        tool1 = _tool_use_block("echo", {"text": "a"}, "toolu_m1")
        tool2 = _tool_use_block("echo", {"text": "b"}, "toolu_m2")

        # Single response with two tool calls
        msg1 = _make_message([tool1, tool2], stop_reason="tool_use")
        stream1 = MockStream([], msg1)

        msg2 = _make_message(
            [_text_block("Both tools done.")],
            stop_reason="end_turn",
        )
        stream2 = MockStream(["Both tools done."], msg2)

        call_count = 0

        def mock_stream_factory(**kwargs):
            nonlocal call_count
            call_count += 1
            return stream1 if call_count == 1 else stream2

        orchestrator._client.messages.stream = mock_stream_factory

        messages = [{"role": "user", "content": "Use two tools"}]
        result = await orchestrator.run_conversation(messages, context, db, on_event)

        # Should have 2 tool_call and 2 tool_result events
        tool_calls = [e for e in events if e["type"] == "tool_call"]
        tool_results = [e for e in events if e["type"] == "tool_result"]
        assert len(tool_calls) == 2
        assert len(tool_results) == 2

        # Both tool results should be in a single user message
        tool_result_msg = result[2]
        assert len(tool_result_msg["content"]) == 2

        assert events[-1] == {"type": "done"}
