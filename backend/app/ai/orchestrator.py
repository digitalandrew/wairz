from __future__ import annotations

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

DEFAULT_MODEL = "claude-sonnet-4-20250514"
ALLOWED_MODELS = {
    "claude-haiku-4-5-20251001",
    "claude-sonnet-4-20250514",
    "claude-opus-4-20250918",
}
MAX_TOKENS = 4096


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
        self._client = anthropic.AsyncAnthropic(
            api_key=api_key or settings.anthropic_api_key,
        )

    async def run_conversation(
        self,
        messages: list[dict],
        project_context: ProjectContext,
        db: AsyncSession,
        on_event: Callable[[dict], Awaitable[None]],
        model: str | None = None,
    ) -> list[dict]:
        """Run the AI tool-use loop, streaming events via on_event.

        Returns the updated messages list with all assistant/tool exchanges appended.
        """
        system_prompt = build_system_prompt(
            project_name=project_context.project_name,
            firmware_filename=project_context.firmware_filename,
            architecture=project_context.architecture,
            endianness=project_context.endianness,
            extracted_path=project_context.extracted_path,
            documents=project_context.documents,
        )

        tool_context = ToolContext(
            project_id=project_context.project_id,
            firmware_id=project_context.firmware_id,
            extracted_path=project_context.extracted_path,
            db=db,
        )

        resolved_model = model if model in ALLOWED_MODELS else DEFAULT_MODEL

        tools = self._registry.get_anthropic_tools()
        iteration = 0

        try:
            while iteration < self._max_iterations:
                # Stream the API response
                async with self._client.messages.stream(
                    model=resolved_model,
                    max_tokens=MAX_TOKENS,
                    system=system_prompt,
                    messages=messages,
                    tools=tools,
                ) as stream:
                    # Emit text deltas as they arrive
                    async for text in stream.text_stream:
                        await on_event({
                            "type": "assistant_text",
                            "content": text,
                            "delta": True,
                        })

                    response = await stream.get_final_message()

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

            # Reached max iterations
            await on_event({
                "type": "assistant_text",
                "content": "\n\n[Reached maximum tool call limit]",
                "delta": False,
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
