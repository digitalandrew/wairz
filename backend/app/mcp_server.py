"""Wairz MCP Server — exposes firmware analysis tools via the Model Context Protocol.

Usage:
    wairz-mcp --project-id <uuid>

Connects to the Wairz database, loads the specified project and firmware,
then serves all registered analysis tools over stdio for MCP-compatible
clients (Claude Desktop, Claude Code, etc.).
"""

import argparse
import asyncio
import hashlib
import logging
import sys
import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import (
    GetPromptResult,
    Prompt,
    PromptMessage,
    Resource,
    ServerCapabilities,
    TextContent,
    Tool,
)

from app.ai import create_tool_registry
from app.ai.system_prompt import build_system_prompt
from app.ai.tool_registry import ToolContext, ToolRegistry
from app.config import get_settings
from app.models.analysis_cache import AnalysisCache
from app.models.firmware import Firmware
from app.models.project import Project
from app.utils.sandbox import validate_path

# All logging goes to stderr — stdout is the MCP protocol channel
logging.basicConfig(
    stream=sys.stderr,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("wairz.mcp")

# Tools that should NOT be exposed via MCP:
# - cleanup_decompiled_code: calls the Anthropic API internally; the MCP client IS the AI
# - write_scratchpad / read_agent_scratchpads: review-only (not in create_tool_registry anyway)
EXCLUDED_TOOLS = {"cleanup_decompiled_code"}


def _compute_sha256(file_path: str) -> str:
    """Compute SHA256 hash of a file."""
    sha = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha.update(chunk)
    return sha.hexdigest()


async def _handle_save_code_cleanup(
    input: dict, context: ToolContext
) -> str:
    """Save AI-cleaned decompiled code to the analysis cache.

    This lets the MCP client clean up Ghidra decompilation output and persist
    it so it appears in the Wairz web UI's "AI Cleaned" toggle.
    """
    binary_path_arg = input.get("binary_path", "")
    function_name = input.get("function_name", "")
    cleaned_code = input.get("cleaned_code", "")

    if not binary_path_arg or not function_name or not cleaned_code:
        return "Error: binary_path, function_name, and cleaned_code are all required."

    full_path = validate_path(context.extracted_path, binary_path_arg)

    binary_sha256 = await asyncio.get_event_loop().run_in_executor(
        None, _compute_sha256, full_path
    )

    operation = f"code_cleanup:{function_name}"

    # Check if an entry already exists and update it, or create a new one
    stmt = select(AnalysisCache).where(
        AnalysisCache.firmware_id == context.firmware_id,
        AnalysisCache.binary_sha256 == binary_sha256,
        AnalysisCache.operation == operation,
    )
    existing = (await context.db.execute(stmt)).scalar_one_or_none()

    if existing:
        existing.result = {"cleaned_code": cleaned_code}
    else:
        entry = AnalysisCache(
            firmware_id=context.firmware_id,
            binary_path=full_path,
            binary_sha256=binary_sha256,
            operation=operation,
            result={"cleaned_code": cleaned_code},
        )
        context.db.add(entry)

    await context.db.flush()
    return f"Saved cleaned code for {function_name} in {binary_path_arg}."


def _build_tool_registry() -> ToolRegistry:
    """Build the full tool registry, exclude MCP-inappropriate tools, add MCP-only tools."""
    registry = create_tool_registry()

    # Remove tools that shouldn't be in MCP
    for name in EXCLUDED_TOOLS:
        registry._tools.pop(name, None)

    # Add the MCP-only save_code_cleanup tool
    registry.register(
        name="save_code_cleanup",
        description=(
            "Save AI-cleaned decompiled code to the Wairz analysis cache. "
            "After you clean up Ghidra decompiled code (rename variables, add comments, etc.), "
            "call this tool to persist the result so it appears in the Wairz web UI's "
            '"AI Cleaned" toggle. Use the same binary_path and function_name from '
            "the decompile_function tool call."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "binary_path": {
                    "type": "string",
                    "description": "Path to the binary within the firmware filesystem.",
                },
                "function_name": {
                    "type": "string",
                    "description": "Name of the function that was decompiled and cleaned.",
                },
                "cleaned_code": {
                    "type": "string",
                    "description": "The cleaned-up pseudo-C code to save.",
                },
            },
            "required": ["binary_path", "function_name", "cleaned_code"],
        },
        handler=_handle_save_code_cleanup,
    )

    return registry


async def _load_project(
    session: AsyncSession, project_id: uuid.UUID
) -> tuple[Project, Firmware]:
    """Load and validate the project and its firmware."""
    project = await session.get(Project, project_id)
    if not project:
        logger.error("Project %s not found.", project_id)
        sys.exit(1)

    stmt = select(Firmware).where(Firmware.project_id == project_id)
    firmware = (await session.execute(stmt)).scalar_one_or_none()
    if not firmware:
        logger.error("No firmware found for project %s.", project_id)
        sys.exit(1)

    if not firmware.extracted_path:
        logger.error(
            "Firmware for project %s has not been unpacked (no extracted_path).",
            project_id,
        )
        sys.exit(1)

    return project, firmware


async def run_server(project_id: uuid.UUID) -> None:
    """Start the MCP server for a given project."""
    settings = get_settings()

    # Create a standalone async engine (not sharing the FastAPI module-level one)
    engine = create_async_engine(settings.database_url, echo=False)
    session_factory = async_sessionmaker(
        engine, class_=AsyncSession, expire_on_commit=False
    )

    # Validate project exists and firmware is unpacked
    async with session_factory() as session:
        project, firmware = await _load_project(session, project_id)
        # Capture values before session closes
        project_name = project.name
        project_desc = project.description or ""
        firmware_id = firmware.id
        firmware_filename = firmware.original_filename or "unknown"
        architecture = firmware.architecture
        endianness = firmware.endianness
        extracted_path = firmware.extracted_path

    logger.info(
        "Loaded project '%s' — firmware: %s (%s, %s)",
        project_name,
        firmware_filename,
        architecture or "unknown arch",
        endianness or "unknown endian",
    )

    # Build tool registry
    registry = _build_tool_registry()
    tool_count = len(registry._tools)
    logger.info("Registered %d tools.", tool_count)

    # Create MCP server
    server = Server("wairz")

    # --- Tool listing ---
    @server.list_tools()
    async def list_tools() -> list[Tool]:
        tools = []
        for tool_def in registry._tools.values():
            tools.append(
                Tool(
                    name=tool_def.name,
                    description=tool_def.description,
                    inputSchema=tool_def.input_schema,
                )
            )
        return tools

    # --- Tool dispatch ---
    @server.call_tool()
    async def call_tool(
        name: str, arguments: dict
    ) -> list[TextContent]:
        async with session_factory() as session:
            context = ToolContext(
                project_id=project_id,
                firmware_id=firmware_id,
                extracted_path=extracted_path,
                db=session,
            )
            try:
                result = await registry.execute(name, arguments, context)
                await session.commit()
            except Exception:
                await session.rollback()
                raise
        return [TextContent(type="text", text=result)]

    # --- Resources ---
    @server.list_resources()
    async def list_resources() -> list[Resource]:
        return [
            Resource(
                uri="wairz://project/info",
                name="Project Info",
                description="Project and firmware metadata for the current analysis session.",
                mimeType="text/plain",
            )
        ]

    @server.read_resource()
    async def read_resource(uri) -> str:
        if str(uri) == "wairz://project/info":
            lines = [
                f"Project: {project_name}",
                f"Description: {project_desc}",
                f"Project ID: {project_id}",
                f"Firmware: {firmware_filename}",
                f"Firmware ID: {firmware_id}",
                f"Architecture: {architecture or 'unknown'}",
                f"Endianness: {endianness or 'unknown'}",
                f"Extracted Path: {extracted_path}",
            ]
            return "\n".join(lines)
        raise ValueError(f"Unknown resource: {uri}")

    # --- Prompts ---
    @server.list_prompts()
    async def list_prompts() -> list[Prompt]:
        return [
            Prompt(
                name="firmware-analysis",
                description=(
                    "System prompt for firmware reverse engineering and security analysis. "
                    "Provides methodology guidance and firmware context."
                ),
            )
        ]

    @server.get_prompt()
    async def get_prompt(
        name: str, arguments: dict[str, str] | None
    ) -> GetPromptResult:
        if name == "firmware-analysis":
            prompt_text = build_system_prompt(
                project_name=project_name,
                firmware_filename=firmware_filename,
                architecture=architecture,
                endianness=endianness,
                extracted_path=extracted_path,
            )
            return GetPromptResult(
                description="Wairz firmware analysis system prompt",
                messages=[
                    PromptMessage(
                        role="user",
                        content=TextContent(type="text", text=prompt_text),
                    )
                ],
            )
        raise ValueError(f"Unknown prompt: {name}")

    # --- Run ---
    logger.info("Starting Wairz MCP server (stdio transport)...")
    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            server.create_initialization_options(),
        )


def main() -> None:
    """CLI entry point for the wairz-mcp command."""
    parser = argparse.ArgumentParser(
        description="Wairz MCP Server — firmware analysis tools over MCP",
    )
    parser.add_argument(
        "--project-id",
        required=True,
        type=str,
        help="UUID of the project to analyze.",
    )
    args = parser.parse_args()

    try:
        project_id = uuid.UUID(args.project_id)
    except ValueError:
        print(f"Error: '{args.project_id}' is not a valid UUID.", file=sys.stderr)
        sys.exit(1)

    asyncio.run(run_server(project_id))


if __name__ == "__main__":
    main()
