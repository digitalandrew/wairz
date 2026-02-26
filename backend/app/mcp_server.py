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
import os
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

# Docker volume path translation
# When the backend runs inside Docker it stores paths like /data/firmware/...
# but the MCP server runs on the host where that path doesn't exist.
# We detect this and resolve the Docker volume mountpoint automatically.
DOCKER_STORAGE_ROOT = "/data/firmware"

# All logging goes to stderr — stdout is the MCP protocol channel
logging.basicConfig(
    stream=sys.stderr,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("wairz.mcp")

# Tools that should NOT be exposed via MCP (currently none after orchestrator removal).
EXCLUDED_TOOLS: set[str] = set()


def _resolve_storage_root() -> str | None:
    """Find a host-accessible path for the firmware Docker volume.

    When the MCP server runs on the host (not inside Docker), DB paths
    like /data/firmware/... don't exist.  We attempt several strategies:

    1. If DOCKER_STORAGE_ROOT exists on this machine (we're inside
       Docker or have a bind mount), no translation needed.
    2. Check STORAGE_ROOT from settings — it may point to a local dev
       directory (e.g., ./data/firmware).
    3. Inspect the Docker volume's host mountpoint — requires the
       directory to be readable by the current user.

    Returns the host-side path or None if no translation is possible.
    """
    # Strategy 1: Docker-internal path exists (running inside Docker)
    if os.path.isdir(DOCKER_STORAGE_ROOT):
        return None

    # Strategy 2: Settings-based STORAGE_ROOT (local dev setup)
    settings = get_settings()
    if settings.storage_root != DOCKER_STORAGE_ROOT:
        resolved = os.path.realpath(settings.storage_root)
        if os.path.isdir(resolved):
            return resolved

    # Strategy 3: Docker volume mountpoint (requires read access)
    try:
        import docker as docker_sdk

        client = docker_sdk.from_env()
        for vol_name in ("wairz_firmware_data", "firmware_data"):
            try:
                vol = client.volumes.get(vol_name)
                mountpoint = vol.attrs.get("Mountpoint", "")
                if mountpoint and os.path.isdir(mountpoint):
                    return mountpoint
            except docker_sdk.errors.NotFound:
                continue
    except Exception as exc:
        logger.debug("Could not inspect Docker volumes: %s", exc)

    return None


def _translate_path(path: str, host_storage_root: str | None) -> str:
    """Rewrite a Docker-internal path to the host-side equivalent.

    If host_storage_root is None, returns path unchanged.
    """
    if not host_storage_root:
        return path
    if path.startswith(DOCKER_STORAGE_ROOT + "/"):
        return host_storage_root + path[len(DOCKER_STORAGE_ROOT):]
    if path == DOCKER_STORAGE_ROOT:
        return host_storage_root
    return path


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
        extraction_dir = firmware.extraction_dir

    # Translate Docker-internal paths to host paths when running outside Docker.
    # The DB stores paths like /data/firmware/... which only exist inside
    # the Docker container.  On the host we resolve via the Docker volume
    # or the local STORAGE_ROOT setting.
    host_storage_root = _resolve_storage_root()
    if host_storage_root:
        extracted_path = _translate_path(extracted_path, host_storage_root)
        if extraction_dir:
            extraction_dir = _translate_path(extraction_dir, host_storage_root)
        logger.info(
            "Path translation active: %s → %s",
            DOCKER_STORAGE_ROOT,
            host_storage_root,
        )

    if not os.path.isdir(extracted_path):
        logger.error(
            "Extracted firmware path does not exist: %s",
            extracted_path,
        )
        logger.error(
            "The database stores Docker-internal paths. To fix this, either:\n"
            "  1. Run the MCP server inside Docker:\n"
            "     docker exec -i wairz-backend-1 uv run wairz-mcp --project-id %s\n"
            "  2. Set STORAGE_ROOT in .env to point to a local copy of the firmware data",
            project_id,
        )
        sys.exit(1)

    logger.info(
        "Loaded project '%s' — firmware: %s (%s, %s)",
        project_name,
        firmware_filename,
        architecture or "unknown arch",
        endianness or "unknown endian",
    )
    logger.info("Firmware root: %s", extracted_path)

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
                extraction_dir=extraction_dir,
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
