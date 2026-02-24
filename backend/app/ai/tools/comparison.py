"""MCP tools for firmware version comparison."""

import difflib
import uuid

from sqlalchemy import select

from app.ai.tool_registry import ToolContext, ToolRegistry
from app.models.firmware import Firmware
from app.services.comparison_service import diff_binary, diff_filesystems
from app.services.ghidra_service import get_analysis_cache
from app.utils.sandbox import validate_path
from app.utils.truncation import truncate_output


async def _handle_list_firmware_versions(input: dict, context: ToolContext) -> str:
    """List all firmware versions for the current project."""
    stmt = (
        select(Firmware)
        .where(Firmware.project_id == context.project_id)
        .order_by(Firmware.created_at)
    )
    result = await context.db.execute(stmt)
    firmware_list = result.scalars().all()

    if not firmware_list:
        return "No firmware uploaded for this project."

    lines = [f"Firmware versions ({len(firmware_list)}):", ""]
    lines.append(f"  {'ID':<38} {'Filename':<30} {'Label':<15} {'Arch':<12} {'Size':>10} {'Unpacked'}")
    lines.append(f"  {'-' * 38} {'-' * 30} {'-' * 15} {'-' * 12} {'-' * 10} {'-' * 8}")

    for fw in firmware_list:
        fid = str(fw.id)
        fname = (fw.original_filename or "unknown")[:30]
        label = (fw.version_label or "")[:15]
        arch = (fw.architecture or "")[:12]
        size = f"{fw.file_size:,}" if fw.file_size else "?"
        unpacked = "Yes" if fw.extracted_path else "No"
        lines.append(f"  {fid:<38} {fname:<30} {label:<15} {arch:<12} {size:>10} {unpacked}")

    return "\n".join(lines)


async def _handle_diff_firmware(input: dict, context: ToolContext) -> str:
    """Compare two firmware versions' filesystems."""
    try:
        fw_a_id = uuid.UUID(input["firmware_a_id"])
        fw_b_id = uuid.UUID(input["firmware_b_id"])
    except (KeyError, ValueError) as e:
        return f"Error: invalid firmware IDs — {e}"

    # Look up both firmware
    fw_a = await _get_firmware(fw_a_id, context)
    if isinstance(fw_a, str):
        return fw_a
    fw_b = await _get_firmware(fw_b_id, context)
    if isinstance(fw_b, str):
        return fw_b

    result = diff_filesystems(fw_a.extracted_path, fw_b.extracted_path)

    lines: list[str] = []
    fw_a_label = fw_a.version_label or fw_a.original_filename or str(fw_a.id)
    fw_b_label = fw_b.version_label or fw_b.original_filename or str(fw_b.id)
    lines.append(f"Filesystem Diff: {fw_a_label} vs {fw_b_label}")
    lines.append(f"Files in A: {result.total_files_a}, Files in B: {result.total_files_b}")
    lines.append(f"Added: {len(result.added)}, Removed: {len(result.removed)}, "
                 f"Modified: {len(result.modified)}, Perms Changed: {len(result.permissions_changed)}")
    if result.truncated:
        lines.append("(Results truncated to 500 entries)")
    lines.append("")

    if result.added:
        lines.append(f"--- Added ({len(result.added)}) ---")
        for e in result.added[:50]:
            size = f" ({e.size_b:,} bytes)" if e.size_b else ""
            lines.append(f"  + {e.path}{size}")
        if len(result.added) > 50:
            lines.append(f"  ... and {len(result.added) - 50} more")
        lines.append("")

    if result.removed:
        lines.append(f"--- Removed ({len(result.removed)}) ---")
        for e in result.removed[:50]:
            size = f" ({e.size_a:,} bytes)" if e.size_a else ""
            lines.append(f"  - {e.path}{size}")
        if len(result.removed) > 50:
            lines.append(f"  ... and {len(result.removed) - 50} more")
        lines.append("")

    if result.modified:
        lines.append(f"--- Modified ({len(result.modified)}) ---")
        for e in result.modified[:50]:
            delta = ""
            if e.size_a is not None and e.size_b is not None:
                diff = e.size_b - e.size_a
                pct = (diff / e.size_a * 100) if e.size_a > 0 else 0
                delta = f" ({e.size_a:,} → {e.size_b:,}, {pct:+.1f}%)"
            lines.append(f"  ~ {e.path}{delta}")
        if len(result.modified) > 50:
            lines.append(f"  ... and {len(result.modified) - 50} more")
        lines.append("")

    if result.permissions_changed:
        lines.append(f"--- Permissions Changed ({len(result.permissions_changed)}) ---")
        for e in result.permissions_changed[:30]:
            lines.append(f"  {e.path}: {e.perms_a} → {e.perms_b}")
        if len(result.permissions_changed) > 30:
            lines.append(f"  ... and {len(result.permissions_changed) - 30} more")

    return truncate_output("\n".join(lines))


async def _handle_diff_binary(input: dict, context: ToolContext) -> str:
    """Compare a binary between two firmware versions at the function level."""
    try:
        fw_a_id = uuid.UUID(input["firmware_a_id"])
        fw_b_id = uuid.UUID(input["firmware_b_id"])
    except (KeyError, ValueError) as e:
        return f"Error: invalid firmware IDs — {e}"

    binary_path = input.get("binary_path", "")
    if not binary_path:
        return "Error: binary_path is required."

    fw_a = await _get_firmware(fw_a_id, context)
    if isinstance(fw_a, str):
        return fw_a
    fw_b = await _get_firmware(fw_b_id, context)
    if isinstance(fw_b, str):
        return fw_b

    try:
        path_a = validate_path(fw_a.extracted_path, binary_path)
    except Exception:
        return f"Error: binary not found in firmware A: {binary_path}"

    try:
        path_b = validate_path(fw_b.extracted_path, binary_path)
    except Exception:
        return f"Error: binary not found in firmware B: {binary_path}"

    result = diff_binary(path_a, path_b, binary_path)

    lines: list[str] = []
    fw_a_label = fw_a.version_label or fw_a.original_filename or str(fw_a.id)
    fw_b_label = fw_b.version_label or fw_b.original_filename or str(fw_b.id)
    lines.append(f"Binary Diff: {binary_path}")
    lines.append(f"  A: {fw_a_label} (size: {result.info_a.get('file_size', '?')})")
    lines.append(f"  B: {fw_b_label} (size: {result.info_b.get('file_size', '?')})")
    lines.append(f"Added: {len(result.functions_added)}, Removed: {len(result.functions_removed)}, "
                 f"Modified: {len(result.functions_modified)}")
    lines.append("")

    if result.functions_added:
        lines.append(f"--- Functions Added ({len(result.functions_added)}) ---")
        for f in result.functions_added[:30]:
            lines.append(f"  + {f.name} (size: {f.size_b})")
        if len(result.functions_added) > 30:
            lines.append(f"  ... and {len(result.functions_added) - 30} more")
        lines.append("")

    if result.functions_removed:
        lines.append(f"--- Functions Removed ({len(result.functions_removed)}) ---")
        for f in result.functions_removed[:30]:
            lines.append(f"  - {f.name} (size: {f.size_a})")
        if len(result.functions_removed) > 30:
            lines.append(f"  ... and {len(result.functions_removed) - 30} more")
        lines.append("")

    if result.functions_modified:
        lines.append(f"--- Functions Modified ({len(result.functions_modified)}) ---")
        for f in result.functions_modified[:30]:
            lines.append(f"  ~ {f.name} (size: {f.size_a} → {f.size_b})")
        if len(result.functions_modified) > 30:
            lines.append(f"  ... and {len(result.functions_modified) - 30} more")

    if not result.functions_added and not result.functions_removed and not result.functions_modified:
        lines.append("No function-level differences detected.")
        lines.append("(Note: only symbol table functions are compared; stripped binaries may show no differences)")

    return truncate_output("\n".join(lines))


async def _handle_diff_decompilation(input: dict, context: ToolContext) -> str:
    """Decompile a function from two firmware versions and produce a unified diff."""
    try:
        fw_a_id = uuid.UUID(input["firmware_a_id"])
        fw_b_id = uuid.UUID(input["firmware_b_id"])
    except (KeyError, ValueError) as e:
        return f"Error: invalid firmware IDs — {e}"

    binary_path = input.get("binary_path", "")
    function_name = input.get("function_name", "")
    if not binary_path or not function_name:
        return "Error: binary_path and function_name are required."

    context_lines = input.get("context_lines", 5)

    fw_a = await _get_firmware(fw_a_id, context)
    if isinstance(fw_a, str):
        return fw_a
    fw_b = await _get_firmware(fw_b_id, context)
    if isinstance(fw_b, str):
        return fw_b

    try:
        path_a = validate_path(fw_a.extracted_path, binary_path)
    except Exception:
        return f"Error: binary not found in firmware A: {binary_path}"

    try:
        path_b = validate_path(fw_b.extracted_path, binary_path)
    except Exception:
        return f"Error: binary not found in firmware B: {binary_path}"

    # Decompile from both versions
    cache = get_analysis_cache()
    try:
        code_a = await cache.decompile_function(
            path_a, function_name, fw_a.id, context.db,
        )
    except Exception as exc:
        return f"Error decompiling from firmware A: {exc}"

    try:
        code_b = await cache.decompile_function(
            path_b, function_name, fw_b.id, context.db,
        )
    except Exception as exc:
        return f"Error decompiling from firmware B: {exc}"

    # Generate unified diff
    label_a = fw_a.version_label or fw_a.original_filename or str(fw_a.id)
    label_b = fw_b.version_label or fw_b.original_filename or str(fw_b.id)

    lines_a = code_a.splitlines(keepends=True)
    lines_b = code_b.splitlines(keepends=True)

    diff = list(difflib.unified_diff(
        lines_a, lines_b,
        fromfile=f"{binary_path}:{function_name} ({label_a})",
        tofile=f"{binary_path}:{function_name} ({label_b})",
        n=context_lines,
    ))

    if not diff:
        return (
            f"No differences in {function_name} between firmware versions.\n"
            f"  A: {label_a}\n"
            f"  B: {label_b}"
        )

    header = [
        f"Decompilation Diff: {function_name}",
        f"  A: {label_a}",
        f"  B: {label_b}",
        "",
    ]
    diff_text = "".join(diff)
    return truncate_output("\n".join(header) + diff_text)


async def _get_firmware(firmware_id: uuid.UUID, context: ToolContext):
    """Look up firmware by ID and verify project ownership. Returns firmware or error string."""
    stmt = select(Firmware).where(Firmware.id == firmware_id)
    result = await context.db.execute(stmt)
    fw = result.scalar_one_or_none()
    if not fw:
        return f"Error: firmware {firmware_id} not found."
    if fw.project_id != context.project_id:
        return f"Error: firmware {firmware_id} does not belong to this project."
    if not fw.extracted_path:
        return f"Error: firmware {firmware_id} has not been unpacked yet."
    return fw


def register_comparison_tools(registry: ToolRegistry) -> None:
    """Register firmware comparison tools."""

    registry.register(
        name="list_firmware_versions",
        description=(
            "List all firmware versions uploaded to the current project. "
            "Shows firmware IDs, filenames, version labels, architecture, and unpack status. "
            "Use the firmware IDs from this list as parameters for diff_firmware and diff_binary."
        ),
        input_schema={
            "type": "object",
            "properties": {},
            "required": [],
        },
        handler=_handle_list_firmware_versions,
    )

    registry.register(
        name="diff_firmware",
        description=(
            "Compare two firmware versions' filesystems. Shows files added, removed, "
            "modified (by content hash), and permission changes. Use list_firmware_versions "
            "first to get the firmware IDs."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "firmware_a_id": {
                    "type": "string",
                    "description": "UUID of the first (older) firmware version",
                },
                "firmware_b_id": {
                    "type": "string",
                    "description": "UUID of the second (newer) firmware version",
                },
            },
            "required": ["firmware_a_id", "firmware_b_id"],
        },
        handler=_handle_diff_firmware,
    )

    registry.register(
        name="diff_binary",
        description=(
            "Compare a specific binary between two firmware versions at the function level. "
            "Shows functions added, removed, and modified (size changed). "
            "Useful for patch analysis: understanding what the vendor changed between versions."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "firmware_a_id": {
                    "type": "string",
                    "description": "UUID of the first (older) firmware version",
                },
                "firmware_b_id": {
                    "type": "string",
                    "description": "UUID of the second (newer) firmware version",
                },
                "binary_path": {
                    "type": "string",
                    "description": "Path to the binary within the firmware filesystem (e.g. '/usr/bin/httpd')",
                },
            },
            "required": ["firmware_a_id", "firmware_b_id", "binary_path"],
        },
        handler=_handle_diff_binary,
    )

    registry.register(
        name="diff_decompilation",
        description=(
            "Side-by-side decompilation diff: decompile the same function from "
            "two firmware versions and produce a unified diff. Shows exactly what "
            "changed in the pseudo-C code between versions. Useful for patch "
            "analysis — understanding what the vendor fixed or modified. "
            "Uses cached Ghidra decompilation (first call may take 1-3 minutes "
            "per firmware version)."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "firmware_a_id": {
                    "type": "string",
                    "description": "UUID of the first (older) firmware version",
                },
                "firmware_b_id": {
                    "type": "string",
                    "description": "UUID of the second (newer) firmware version",
                },
                "binary_path": {
                    "type": "string",
                    "description": "Path to the binary within the firmware filesystem (e.g. '/bin/httpd')",
                },
                "function_name": {
                    "type": "string",
                    "description": "Function name to decompile and diff (e.g. 'formSetSysToolChangePwd')",
                },
                "context_lines": {
                    "type": "integer",
                    "description": "Number of context lines around changes in the diff (default: 5)",
                },
            },
            "required": ["firmware_a_id", "firmware_b_id", "binary_path", "function_name"],
        },
        handler=_handle_diff_decompilation,
    )
