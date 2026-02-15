import traceback
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from app.utils.truncation import truncate_output


@dataclass
class ToolContext:
    project_id: UUID
    firmware_id: UUID
    extracted_path: str
    db: AsyncSession
    review_id: UUID | None = None
    review_agent_id: UUID | None = None


@dataclass
class ToolDefinition:
    name: str
    description: str
    input_schema: dict
    handler: Callable[[dict, ToolContext], Awaitable[str]]


class ToolRegistry:
    def __init__(self) -> None:
        self._tools: dict[str, ToolDefinition] = {}

    def register(
        self,
        name: str,
        description: str,
        input_schema: dict,
        handler: Callable[[dict, ToolContext], Awaitable[str]],
    ) -> None:
        self._tools[name] = ToolDefinition(
            name=name,
            description=description,
            input_schema=input_schema,
            handler=handler,
        )

    def subset(self, tool_names: list[str]) -> "ToolRegistry":
        """Return a new ToolRegistry containing only the named tools."""
        new_registry = ToolRegistry()
        for name in tool_names:
            if name in self._tools:
                new_registry._tools[name] = self._tools[name]
        return new_registry

    def get_anthropic_tools(self) -> list[dict]:
        return [
            {
                "name": t.name,
                "description": t.description,
                "input_schema": t.input_schema,
            }
            for t in self._tools.values()
        ]

    async def execute(self, name: str, input: dict, context: ToolContext) -> str:
        tool = self._tools.get(name)
        if tool is None:
            return f"Error: unknown tool '{name}'"
        try:
            result = await tool.handler(input, context)
        except Exception as exc:
            return f"Error executing {name}: {exc}"
        return truncate_output(result)
