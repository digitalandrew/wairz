"""Binary analysis AI tools using radare2, pyelftools, and Ghidra."""

import logging

from app.ai.tool_registry import ToolContext, ToolRegistry
from app.services.analysis_service import (
    check_binary_protections,
    get_session_cache,
)
from app.services.code_cleanup_service import cleanup_decompiled_code
from app.services.ghidra_service import decompile_function
from app.utils.sandbox import validate_path

logger = logging.getLogger(__name__)


async def _handle_list_functions(input: dict, context: ToolContext) -> str:
    """List functions found in a binary, sorted by size (largest first)."""
    path = validate_path(context.extracted_path, input["binary_path"])

    cache = get_session_cache()
    session = await cache.get_session(path)
    functions = session.list_functions()

    if not functions:
        return "No functions found in binary."

    lines = [f"Found {len(functions)} function(s) (sorted by size, largest first):", ""]
    for fn in functions:
        name = fn.get("name", "unknown")
        size = fn.get("size", 0)
        offset = fn.get("offset", 0)
        lines.append(f"  0x{offset:08x}  {size:>6} bytes  {name}")

    return "\n".join(lines)


async def _handle_disassemble_function(input: dict, context: ToolContext) -> str:
    """Disassemble a function by name."""
    path = validate_path(context.extracted_path, input["binary_path"])
    function_name = input["function_name"]
    max_insn = input.get("num_instructions", 100)

    cache = get_session_cache()
    session = await cache.get_session(path)
    disasm = session.disassemble_function(function_name, max_insn)

    return f"Disassembly of {function_name}:\n\n{disasm}"


async def _handle_list_imports(input: dict, context: ToolContext) -> str:
    """List imported symbols, grouped by library."""
    path = validate_path(context.extracted_path, input["binary_path"])

    cache = get_session_cache()
    session = await cache.get_session(path)
    imports = session.get_imports()

    if not imports:
        return "No imports found."

    # Group by library
    by_lib: dict[str, list[str]] = {}
    for imp in imports:
        lib = imp.get("lib", "unknown")
        name = imp.get("name", "unknown")
        by_lib.setdefault(lib, []).append(name)

    lines = [f"Found {len(imports)} import(s):", ""]
    for lib, symbols in sorted(by_lib.items()):
        lines.append(f"  [{lib}]")
        for sym in sorted(symbols):
            lines.append(f"    {sym}")
        lines.append("")

    return "\n".join(lines)


async def _handle_list_exports(input: dict, context: ToolContext) -> str:
    """List exported symbols."""
    path = validate_path(context.extracted_path, input["binary_path"])

    cache = get_session_cache()
    session = await cache.get_session(path)
    exports = session.get_exports()

    if not exports:
        return "No exports found."

    lines = [f"Found {len(exports)} export(s):", ""]
    for exp in exports:
        name = exp.get("name", "unknown")
        vaddr = exp.get("vaddr", 0)
        size = exp.get("size", 0)
        lines.append(f"  0x{vaddr:08x}  {size:>6} bytes  {name}")

    return "\n".join(lines)


async def _handle_xrefs_to(input: dict, context: ToolContext) -> str:
    """Get cross-references to an address or symbol."""
    path = validate_path(context.extracted_path, input["binary_path"])
    target = input["address_or_symbol"]

    cache = get_session_cache()
    session = await cache.get_session(path)
    xrefs = session.get_xrefs_to(target)

    if not xrefs:
        return f"No cross-references to '{target}' found."

    lines = [f"Found {len(xrefs)} cross-reference(s) to '{target}':", ""]
    for xref in xrefs:
        from_addr = xref.get("from", 0)
        ref_type = xref.get("type", "unknown")
        opcode = xref.get("opcode", "")
        lines.append(f"  0x{from_addr:08x}  [{ref_type}]  {opcode}")

    return "\n".join(lines)


async def _handle_xrefs_from(input: dict, context: ToolContext) -> str:
    """Get cross-references from an address or symbol."""
    path = validate_path(context.extracted_path, input["binary_path"])
    target = input["address_or_symbol"]

    cache = get_session_cache()
    session = await cache.get_session(path)
    xrefs = session.get_xrefs_from(target)

    if not xrefs:
        return f"No cross-references from '{target}' found."

    lines = [f"Found {len(xrefs)} cross-reference(s) from '{target}':", ""]
    for xref in xrefs:
        to_addr = xref.get("to", 0)
        ref_type = xref.get("type", "unknown")
        opcode = xref.get("opcode", "")
        lines.append(f"  0x{to_addr:08x}  [{ref_type}]  {opcode}")

    return "\n".join(lines)


async def _handle_get_binary_info(input: dict, context: ToolContext) -> str:
    """Get binary metadata: architecture, format, entry point, etc."""
    path = validate_path(context.extracted_path, input["binary_path"])

    cache = get_session_cache()
    session = await cache.get_session(path)
    info = session.get_binary_info()

    if not info:
        return "Could not retrieve binary info."

    core = info.get("core", {})
    bin_info = info.get("bin", {})

    lines = [
        "Binary Information:",
        "",
        f"  File:         {bin_info.get('file', 'unknown')}",
        f"  Format:       {bin_info.get('bintype', 'unknown')}",
        f"  Architecture: {bin_info.get('arch', 'unknown')}",
        f"  Bits:         {bin_info.get('bits', 'unknown')}",
        f"  Endianness:   {bin_info.get('endian', 'unknown')}",
        f"  OS:           {bin_info.get('os', 'unknown')}",
        f"  Machine:      {bin_info.get('machine', 'unknown')}",
        f"  Class:        {bin_info.get('class', 'unknown')}",
        f"  Language:     {bin_info.get('lang', 'unknown')}",
        f"  Stripped:     {bin_info.get('stripped', 'unknown')}",
        f"  Static:       {bin_info.get('static', 'unknown')}",
        f"  Linked libs:  {', '.join(bin_info.get('libs', [])) or 'none'}",
    ]

    return "\n".join(lines)


async def _handle_check_binary_protections(
    input: dict, context: ToolContext
) -> str:
    """Check binary security protections (NX, RELRO, canary, PIE, Fortify)."""
    path = validate_path(context.extracted_path, input["binary_path"])

    protections = check_binary_protections(path)

    if "error" in protections:
        return f"Error: {protections['error']}"

    def _status(val: object) -> str:
        if isinstance(val, bool):
            return "enabled" if val else "disabled"
        return str(val)

    lines = [
        "Binary Protection Status:",
        "",
        f"  NX (No-Execute):    {_status(protections['nx'])}",
        f"  RELRO:              {protections['relro']}",
        f"  Stack Canary:       {_status(protections['canary'])}",
        f"  PIE:                {_status(protections['pie'])}",
        f"  Fortify Source:     {_status(protections['fortify'])}",
        f"  Stripped:           {_status(protections['stripped'])}",
    ]

    # Summary
    enabled = sum(
        1
        for k in ("nx", "canary", "pie", "fortify")
        if protections.get(k) is True
    )
    if protections.get("relro") == "full":
        enabled += 1
    elif protections.get("relro") == "partial":
        enabled += 0.5

    total = 5
    lines.append("")
    lines.append(f"  Protection score: {enabled}/{total}")

    return "\n".join(lines)


async def _handle_decompile_function(input: dict, context: ToolContext) -> str:
    """Decompile a function using Ghidra headless, returning pseudo-C output."""
    path = validate_path(context.extracted_path, input["binary_path"])
    function_name = input["function_name"]

    try:
        result = await decompile_function(
            binary_path=path,
            function_name=function_name,
            firmware_id=context.firmware_id,
            db=context.db,
        )
    except FileNotFoundError:
        return f"Error: Binary not found at '{input['binary_path']}'."
    except TimeoutError as exc:
        return f"Error: {exc}"
    except RuntimeError as exc:
        return f"Error: {exc}"

    return f"Decompiled output for {function_name}:\n\n{result}"


async def _handle_cleanup_decompiled_code(input: dict, context: ToolContext) -> str:
    """Clean up decompiled code using AI to rename variables and add comments."""
    path = validate_path(context.extracted_path, input["binary_path"])
    function_name = input["function_name"]

    # Get raw decompilation
    try:
        raw_code = await decompile_function(
            binary_path=path,
            function_name=function_name,
            firmware_id=context.firmware_id,
            db=context.db,
        )
    except FileNotFoundError:
        return f"Error: Binary not found at '{input['binary_path']}'."
    except TimeoutError as exc:
        return f"Error: {exc}"
    except RuntimeError as exc:
        return f"Error: {exc}"

    # Get R2 context (best-effort)
    binary_info = None
    imports = None
    try:
        cache = get_session_cache()
        session = await cache.get_session(path)
        binary_info = session.get_binary_info()
        imports = session.get_imports()
    except Exception:
        logger.debug("Could not get R2 context for cleanup tool, proceeding without it")

    # Run AI cleanup
    try:
        cleaned = await cleanup_decompiled_code(
            raw_code=raw_code,
            function_name=function_name,
            binary_path=path,
            binary_info=binary_info,
            imports=imports,
            firmware_id=context.firmware_id,
            db=context.db,
        )
    except RuntimeError as exc:
        return f"Error during AI cleanup: {exc}"

    return f"AI-cleaned decompilation of {function_name}:\n\n{cleaned}"


def register_binary_tools(registry: ToolRegistry) -> None:
    """Register all binary analysis tools with the given registry."""

    registry.register(
        name="list_functions",
        description=(
            "List all functions found in an ELF binary, sorted by size "
            "(largest first). Large custom functions are often the most "
            "interesting for security analysis. Max 500 functions. "
            "Requires radare2 analysis which may take 10-30s on first call."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "binary_path": {
                    "type": "string",
                    "description": "Path to the ELF binary in the firmware filesystem",
                },
            },
            "required": ["binary_path"],
        },
        handler=_handle_list_functions,
    )

    registry.register(
        name="disassemble_function",
        description=(
            "Disassemble a function from an ELF binary. Shows the assembly "
            "instructions with addresses and annotations. Use list_functions "
            "first to find function names."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "binary_path": {
                    "type": "string",
                    "description": "Path to the ELF binary",
                },
                "function_name": {
                    "type": "string",
                    "description": "Function name or address to disassemble (e.g. 'main', 'sym.auth_check')",
                },
                "num_instructions": {
                    "type": "integer",
                    "description": "Maximum number of instructions to show (default: 100, max: 200)",
                },
            },
            "required": ["binary_path", "function_name"],
        },
        handler=_handle_disassemble_function,
    )

    registry.register(
        name="decompile_function",
        description=(
            "Decompile a function from an ELF binary into pseudo-C code using "
            "Ghidra. This produces high-level C-like output that is much easier "
            "to read than assembly. Use list_functions first to find function "
            "names. Results are cached — first call for a binary may take 30-120s, "
            "subsequent calls for the same binary are instant. Best for "
            "understanding complex logic, finding vulnerabilities in source-like "
            "form, and analyzing authentication/crypto routines."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "binary_path": {
                    "type": "string",
                    "description": "Path to the ELF binary in the firmware filesystem",
                },
                "function_name": {
                    "type": "string",
                    "description": "Function name to decompile (e.g. 'main', 'auth_check'). Use list_functions to find available names.",
                },
            },
            "required": ["binary_path", "function_name"],
        },
        handler=_handle_decompile_function,
    )

    registry.register(
        name="list_imports",
        description=(
            "List imported symbols from an ELF binary, grouped by library. "
            "Useful for identifying dangerous functions (system, strcpy, "
            "gets) and external dependencies."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "binary_path": {
                    "type": "string",
                    "description": "Path to the ELF binary",
                },
            },
            "required": ["binary_path"],
        },
        handler=_handle_list_imports,
    )

    registry.register(
        name="list_exports",
        description=(
            "List exported symbols from an ELF binary. Shows symbol names, "
            "addresses, and sizes."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "binary_path": {
                    "type": "string",
                    "description": "Path to the ELF binary",
                },
            },
            "required": ["binary_path"],
        },
        handler=_handle_list_exports,
    )

    registry.register(
        name="xrefs_to",
        description=(
            "Find all cross-references TO a given address or symbol in a "
            "binary. Shows where in the code this function/address is called "
            "or referenced from."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "binary_path": {
                    "type": "string",
                    "description": "Path to the ELF binary",
                },
                "address_or_symbol": {
                    "type": "string",
                    "description": "Target address (0x...) or symbol name",
                },
            },
            "required": ["binary_path", "address_or_symbol"],
        },
        handler=_handle_xrefs_to,
    )

    registry.register(
        name="xrefs_from",
        description=(
            "Find all cross-references FROM a given address or symbol in a "
            "binary. Shows what functions/addresses are called or referenced "
            "by the target."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "binary_path": {
                    "type": "string",
                    "description": "Path to the ELF binary",
                },
                "address_or_symbol": {
                    "type": "string",
                    "description": "Source address (0x...) or symbol name",
                },
            },
            "required": ["binary_path", "address_or_symbol"],
        },
        handler=_handle_xrefs_from,
    )

    registry.register(
        name="get_binary_info",
        description=(
            "Get detailed metadata about an ELF binary: architecture, "
            "endianness, format, linked libraries, entry point, and more."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "binary_path": {
                    "type": "string",
                    "description": "Path to the ELF binary",
                },
            },
            "required": ["binary_path"],
        },
        handler=_handle_get_binary_info,
    )

    registry.register(
        name="check_binary_protections",
        description=(
            "Check security protections of an ELF binary: NX (no-execute), "
            "RELRO (read-only relocations), stack canaries, PIE (position-"
            "independent executable), Fortify Source, and whether the binary "
            "is stripped. Equivalent to checksec."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "binary_path": {
                    "type": "string",
                    "description": "Path to the ELF binary",
                },
            },
            "required": ["binary_path"],
        },
        handler=_handle_check_binary_protections,
    )

    registry.register(
        name="cleanup_decompiled_code",
        description=(
            "Clean up raw Ghidra decompiled code using AI. Renames auto-generated "
            "variables (uVar1, local_10) and functions (FUN_00401234) to meaningful "
            "names, adds inline comments explaining non-obvious logic, adds a "
            "function docstring, and annotates security-relevant patterns with "
            "[SECURITY] comments. Results are cached per binary+function. "
            "Use after decompile_function when you want more readable output."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "binary_path": {
                    "type": "string",
                    "description": "Path to the ELF binary in the firmware filesystem",
                },
                "function_name": {
                    "type": "string",
                    "description": "Function name to clean up (e.g. 'main', 'auth_check'). Use list_functions to find available names.",
                },
            },
            "required": ["binary_path", "function_name"],
        },
        handler=_handle_cleanup_decompiled_code,
    )
