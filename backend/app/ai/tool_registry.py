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
    extraction_dir: str | None = None
    review_id: UUID | None = None
    review_agent_id: UUID | None = None

    def resolve_path(self, path: str) -> str:
        """Resolve a virtual firmware path to a real filesystem path.

        Handles virtual top-level paths like /rootfs/..., /jffs2-root/...,
        etc. when extraction_dir is set.  Falls back to simple validation
        against extracted_path for legacy (non-virtual) mode.
        """
        from app.services.file_service import FileService
        svc = FileService(self.extracted_path, extraction_dir=self.extraction_dir)
        return svc._resolve(path)

    def real_root_for(self, path: str) -> str:
        """Get the real filesystem root to use for relative path computation.

        When virtual paths are active, paths inside /rootfs/ use extracted_path
        as the base, while paths inside /jffs2-root/ etc. use the partition's
        real directory.  Returns the appropriate base so that:
            os.path.relpath(resolved_abs_path, real_root) → firmware-relative path
        """
        import os
        from app.services.file_service import FileService
        if not self.extraction_dir:
            return os.path.realpath(self.extracted_path)
        svc = FileService(self.extracted_path, extraction_dir=self.extraction_dir)
        clean = path.strip("/")
        # Paths inside rootfs
        if not clean or clean == svc.ROOTFS_VNAME or clean.startswith(svc.ROOTFS_VNAME + "/"):
            return os.path.realpath(self.extracted_path)
        # Paths inside a virtual partition — use the partition's real directory
        vmap = svc._build_virtual_map()
        top_name = clean.split("/", 1)[0]
        if top_name in vmap:
            return os.path.realpath(vmap[top_name])
        # Fallback: use extraction_dir
        return os.path.realpath(self.extraction_dir)


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
