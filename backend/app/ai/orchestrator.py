from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from uuid import UUID

import anthropic
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.system_prompt import build_system_prompt
from app.ai.tool_registry import ToolContext, ToolRegistry
from app.config import get_settings

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Degeneration detection
# ---------------------------------------------------------------------------

class DegenerationError(Exception):
    """Raised when the AI model produces degenerate (repetitive/nonsensical) output."""


class DegenerationDetector:
    """Monitors streamed text for signs of model degeneration.

    Detection signals:
    1. Long runs of text without whitespace (>80 chars).
    2. Repeated 30-char n-grams appearing 5+ times in a rolling buffer.

    Each signal increments a strike counter. At 3 strikes the stream is
    considered degenerate.
    """

    MAX_SPACELESS_RUN = 80
    NGRAM_LENGTH = 30
    NGRAM_REPEAT_THRESHOLD = 5
    BUFFER_SIZE = 2000
    STRIKE_LIMIT = 3

    def __init__(self) -> None:
        self._buffer = ""
        self._spaceless_run = 0
        self._strikes = 0

    def feed(self, chunk: str) -> bool:
        """Feed a text chunk. Returns True if degeneration is confirmed."""
        for ch in chunk:
            if ch in (" ", "\t", "\n", "\r"):
                self._spaceless_run = 0
            else:
                self._spaceless_run += 1
                if self._spaceless_run == self.MAX_SPACELESS_RUN:
                    self._strikes += 1
                    logger.warning(
                        "Degeneration strike %d/%d: spaceless run of %d chars",
                        self._strikes, self.STRIKE_LIMIT, self._spaceless_run,
                    )
                    if self._strikes >= self.STRIKE_LIMIT:
                        return True

        # Update rolling buffer
        self._buffer += chunk
        if len(self._buffer) > self.BUFFER_SIZE:
            self._buffer = self._buffer[-self.BUFFER_SIZE:]

        # Check for repeated n-grams once we have enough text
        if len(self._buffer) >= self.NGRAM_LENGTH * self.NGRAM_REPEAT_THRESHOLD:
            if self._check_ngram_repetition():
                self._strikes += 1
                logger.warning(
                    "Degeneration strike %d/%d: repeated n-gram detected",
                    self._strikes, self.STRIKE_LIMIT,
                )
                if self._strikes >= self.STRIKE_LIMIT:
                    return True

        return False

    def _check_ngram_repetition(self) -> bool:
        """Check if any n-gram appears too many times in the buffer."""
        counts: dict[str, int] = {}
        text = self._buffer
        for i in range(len(text) - self.NGRAM_LENGTH + 1):
            ngram = text[i:i + self.NGRAM_LENGTH]
            counts[ngram] = counts.get(ngram, 0) + 1
            if counts[ngram] >= self.NGRAM_REPEAT_THRESHOLD:
                return True
        return False


DEFAULT_MODEL = "claude-sonnet-4-20250514"
ALLOWED_MODELS = {
    "claude-haiku-4-5-20251001",
    "claude-sonnet-4-20250514",
    "claude-opus-4-20250918",
}
MAX_TOKENS = 4096

# Chars-per-token estimate for rough token counting (conservative)
_CHARS_PER_TOKEN = 3.5


def _estimate_tokens(text: str) -> int:
    """Rough token count estimate based on character length."""
    return int(len(text) / _CHARS_PER_TOKEN)


def _estimate_message_tokens(message: dict) -> int:
    """Estimate token count for a single conversation message."""
    content = message.get("content", "")
    if isinstance(content, str):
        return _estimate_tokens(content)
    if isinstance(content, list):
        total = 0
        for block in content:
            if isinstance(block, dict):
                # Serialize the block to get a rough size
                total += _estimate_tokens(json.dumps(block, default=str))
            else:
                total += _estimate_tokens(str(block))
        return total
    return _estimate_tokens(str(content))


def trim_messages(messages: list[dict], max_tokens: int) -> list[dict]:
    """Trim conversation history to fit within a token budget.

    Strategy:
    - Always keep the first user message (original context)
    - Always keep the last 4 messages (current exchange)
    - If the first user message is the same as one of the kept tail messages,
      don't duplicate it
    - Remove oldest messages from the middle until under budget
    """
    if not messages:
        return messages

    # Estimate total tokens
    total = sum(_estimate_message_tokens(m) for m in messages)
    if total <= max_tokens:
        return messages

    logger.info(
        "Trimming conversation: ~%d tokens exceeds budget of %d",
        total, max_tokens,
    )

    # Always keep first message and last 4 messages
    keep_tail = min(4, len(messages))

    if len(messages) <= keep_tail + 1:
        # Too few messages to trim meaningfully
        return messages

    first_msg = messages[0]
    tail_msgs = messages[-keep_tail:]

    # Try progressively removing messages from the middle
    # Start from the oldest (after first) and remove until under budget
    middle = messages[1:-keep_tail]
    removed_count = 0

    # Calculate budget used by first + tail
    first_tokens = _estimate_message_tokens(first_msg)
    tail_tokens = sum(_estimate_message_tokens(m) for m in tail_msgs)
    remaining_budget = max_tokens - first_tokens - tail_tokens

    # Keep middle messages from the end (most recent) working backwards
    kept_middle: list[dict] = []
    budget_used = 0
    for msg in reversed(middle):
        msg_tokens = _estimate_message_tokens(msg)
        if budget_used + msg_tokens <= remaining_budget:
            kept_middle.insert(0, msg)
            budget_used += msg_tokens
        else:
            removed_count += 1

    result = [first_msg] + kept_middle + tail_msgs

    # Ensure valid message alternation: messages must alternate user/assistant.
    # The trimming may break this, so fix up by merging adjacent same-role messages.
    result = _fix_message_alternation(result)

    final_tokens = sum(_estimate_message_tokens(m) for m in result)
    logger.info(
        "Trimmed conversation from ~%d to ~%d tokens (%d messages removed)",
        total, final_tokens, removed_count,
    )
    return result


def _fix_message_alternation(messages: list[dict]) -> list[dict]:
    """Ensure messages alternate between user and assistant roles.

    If trimming produces adjacent messages with the same role, drop the older
    duplicate to maintain valid conversation structure.
    """
    if len(messages) <= 1:
        return messages

    fixed: list[dict] = [messages[0]]
    for msg in messages[1:]:
        if msg["role"] == fixed[-1]["role"]:
            # Same role in sequence - keep the newer one (replace)
            fixed[-1] = msg
        else:
            fixed.append(msg)
    return fixed


@dataclass
class ProjectContext:
    project_id: UUID
    firmware_id: UUID
    project_name: str
    firmware_filename: str
    architecture: str | None
    endianness: str | None
    extracted_path: str
    documents: list[dict] | None = None
    wairz_md_content: str | None = None


class AIOrchestrator:
    def __init__(
        self,
        registry: ToolRegistry,
        api_key: str | None = None,
        max_iterations: int | None = None,
    ) -> None:
        settings = get_settings()
        self._registry = registry
        self._max_iterations = max_iterations or settings.max_tool_iterations
        try:
            self._max_context_tokens = int(settings.ai_max_context_tokens)
        except (TypeError, ValueError, AttributeError):
            self._max_context_tokens = 100_000
        try:
            max_retries = int(settings.ai_max_retries)
        except (TypeError, ValueError, AttributeError):
            max_retries = 3
        self._client = anthropic.AsyncAnthropic(
            api_key=api_key or settings.anthropic_api_key,
            max_retries=max_retries,
        )

    async def _stream_with_retry(
        self,
        *,
        model: str,
        system: str,
        messages: list[dict],
        tools: list[dict],
        on_event: Callable[[dict], Awaitable[None]],
        max_retries: int = 3,
    ):
        """Stream an API call with retry logic for rate limit errors.

        The Anthropic SDK's built-in retry handles most transient errors,
        but for 429 specifically we add extra backoff with user notification.
        """
        detector = DegenerationDetector()

        for attempt in range(max_retries + 1):
            try:
                async with self._client.messages.stream(
                    model=model,
                    max_tokens=MAX_TOKENS,
                    system=system,
                    messages=messages,
                    tools=tools,
                ) as stream:
                    async for text in stream.text_stream:
                        if detector.feed(text):
                            raise DegenerationError(
                                "Model output degenerated into "
                                "repetitive/nonsensical text"
                            )
                        await on_event({
                            "type": "assistant_text",
                            "content": text,
                            "delta": True,
                        })
                    response = await stream.get_final_message()
                    return response

            except anthropic.RateLimitError as exc:
                if attempt >= max_retries:
                    raise

                # Extract retry-after hint if available
                retry_after = getattr(exc, "headers", {})
                wait_seconds = 30
                if hasattr(retry_after, "get"):
                    try:
                        wait_seconds = int(retry_after.get("retry-after", 30))
                    except (ValueError, TypeError):
                        pass
                # Minimum 10s, cap at 120s
                wait_seconds = max(10, min(wait_seconds, 120))

                logger.warning(
                    "Rate limited (attempt %d/%d), waiting %ds before retry",
                    attempt + 1, max_retries + 1, wait_seconds,
                )
                await on_event({
                    "type": "assistant_text",
                    "content": f"\n\n[Rate limited - waiting {wait_seconds}s before retry ({attempt + 1}/{max_retries + 1})...]\n\n",
                    "delta": False,
                })
                await asyncio.sleep(wait_seconds)

    async def run_conversation(
        self,
        messages: list[dict],
        project_context: ProjectContext,
        db: AsyncSession,
        on_event: Callable[[dict], Awaitable[None]],
        model: str | None = None,
        system_prompt: str | None = None,
        cancel_check: Callable[[], bool] | None = None,
        tool_context_extras: dict | None = None,
    ) -> list[dict]:
        """Run the AI tool-use loop, streaming events via on_event.

        Returns the updated messages list with all assistant/tool exchanges appended.
        """
        if system_prompt is None:
            system_prompt = build_system_prompt(
                project_name=project_context.project_name,
                firmware_filename=project_context.firmware_filename,
                architecture=project_context.architecture,
                endianness=project_context.endianness,
                extracted_path=project_context.extracted_path,
                documents=project_context.documents,
                wairz_md_content=project_context.wairz_md_content,
            )

        tool_context = ToolContext(
            project_id=project_context.project_id,
            firmware_id=project_context.firmware_id,
            extracted_path=project_context.extracted_path,
            db=db,
            **(tool_context_extras or {}),
        )

        resolved_model = model if model in ALLOWED_MODELS else DEFAULT_MODEL

        tools = self._registry.get_anthropic_tools()

        # Estimate fixed overhead (system prompt + tool definitions)
        tools_json = json.dumps(tools, default=str)
        overhead_tokens = _estimate_tokens(system_prompt) + _estimate_tokens(tools_json)
        # Budget for messages = total budget minus overhead, with margin for output
        message_budget = self._max_context_tokens - overhead_tokens - MAX_TOKENS

        # Trim conversation history to fit within budget
        messages = trim_messages(messages, max(message_budget, 10000))

        iteration = 0

        try:
            while iteration < self._max_iterations:
                if cancel_check and cancel_check():
                    await on_event({
                        "type": "assistant_text",
                        "content": "\n\n[Cancelled]",
                        "delta": False,
                    })
                    await on_event({"type": "done"})
                    return messages

                response = await self._stream_with_retry(
                    model=resolved_model,
                    system=system_prompt,
                    messages=messages,
                    tools=tools,
                    on_event=on_event,
                )

                # Append full assistant message to conversation
                messages.append({
                    "role": "assistant",
                    "content": _serialize_content(response.content),
                })

                # If the model stopped naturally, we're done
                if response.stop_reason == "end_turn":
                    await on_event({"type": "done"})
                    return messages

                # Process tool calls
                tool_use_blocks = [
                    block for block in response.content
                    if block.type == "tool_use"
                ]

                if not tool_use_blocks:
                    # No tool calls and not end_turn — unexpected, but treat as done
                    await on_event({"type": "done"})
                    return messages

                tool_results = []
                for block in tool_use_blocks:
                    iteration += 1

                    await on_event({
                        "type": "tool_call",
                        "tool": block.name,
                        "tool_use_id": block.id,
                        "input": block.input,
                    })

                    result = await self._registry.execute(
                        block.name, block.input, tool_context,
                    )

                    await on_event({
                        "type": "tool_result",
                        "tool": block.name,
                        "tool_use_id": block.id,
                        "output": result,
                    })

                    tool_results.append({
                        "type": "tool_result",
                        "tool_use_id": block.id,
                        "content": result,
                    })

                # Append tool results as a user message and continue the loop
                messages.append({"role": "user", "content": tool_results})

                # Re-trim if the conversation has grown during the tool loop
                messages = trim_messages(messages, max(message_budget, 10000))

            # Reached max iterations
            await on_event({
                "type": "assistant_text",
                "content": "\n\n[Reached maximum tool call limit]",
                "delta": False,
            })
            await on_event({"type": "done"})
            return messages

        except DegenerationError:
            logger.warning("Degenerate output detected — aborting response")
            # Don't append the degenerate response to history so it
            # doesn't poison future turns.  The partially streamed text
            # has already been sent to the client, so we just notify and
            # stop.
            await on_event({
                "type": "error",
                "content": (
                    "The AI model produced incoherent output. This sometimes "
                    "happens with complex queries. Please try rephrasing your "
                    "request or starting a new conversation."
                ),
            })
            await on_event({"type": "done"})
            return messages

        except anthropic.RateLimitError as exc:
            logger.warning("Rate limit exceeded after retries: %s", exc)
            await on_event({
                "type": "error",
                "content": "Rate limit exceeded. Please wait a minute and try again.",
            })
            await on_event({"type": "done"})
            return messages

        except anthropic.APIError as exc:
            logger.exception("Anthropic API error")
            await on_event({
                "type": "error",
                "content": f"API error: {exc}",
            })
            await on_event({"type": "done"})
            return messages

        except Exception as exc:
            logger.exception("Unexpected error in orchestrator")
            await on_event({
                "type": "error",
                "content": f"Unexpected error: {exc}",
            })
            await on_event({"type": "done"})
            return messages


def _serialize_content(content_blocks: list) -> list[dict]:
    """Convert SDK content block objects to plain dicts for JSON storage."""
    result = []
    for block in content_blocks:
        if block.type == "text":
            result.append({"type": "text", "text": block.text})
        elif block.type == "tool_use":
            result.append({
                "type": "tool_use",
                "id": block.id,
                "name": block.name,
                "input": block.input,
            })
    return result
