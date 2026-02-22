"""Binary analysis AI tools using Ghidra and pyelftools."""

import hashlib
import json
import logging
import os

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection

from app.ai.tool_registry import ToolContext, ToolRegistry
from app.services.analysis_service import check_binary_protections
from app.services.ghidra_service import (
    decompile_function,
    get_analysis_cache,
    run_ghidra_subprocess,
)
from app.utils.sandbox import safe_walk, validate_path

logger = logging.getLogger(__name__)

# Standard library search paths in firmware filesystems
_STANDARD_LIB_PATHS = ["/lib", "/usr/lib", "/lib32", "/usr/lib32"]

# Markers for FindStringRefs.java output
_STRING_REFS_START = "===STRING_REFS_START==="
_STRING_REFS_END = "===STRING_REFS_END==="

# Markers for TaintAnalysis.java output
_TAINT_START = "===TAINT_START==="
_TAINT_END = "===TAINT_END==="

# Default source/sink functions for taint analysis
_DEFAULT_SOURCES = [
    "websGetVar", "httpGetEnv", "getenv", "recv", "read", "fgets",
    "nvram_get", "nvram_safe_get", "nvram_bufget", "gets",
    "scanf", "fscanf", "sscanf", "recvfrom", "recvmsg",
    "CGI_get_field", "get_cgi", "websGetFormString",
]

_DEFAULT_SINKS = [
    "system", "popen", "execve", "execl", "execlp", "execle",
    "execv", "execvp", "sprintf", "strcpy", "strcat", "strncpy",
    "doSystemCmd", "twsystem", "CsteSystem", "do_system",
    "vsprintf", "fprintf", "printf", "snprintf",
]


async def _handle_list_functions(input: dict, context: ToolContext) -> str:
    """List functions found in a binary, sorted by size (largest first)."""
    path = validate_path(context.extracted_path, input["binary_path"])

    cache = get_analysis_cache()
    functions = await cache.get_functions(path, context.firmware_id, context.db)

    if not functions:
        return "No functions found in binary."

    lines = [f"Found {len(functions)} function(s) (sorted by size, largest first):", ""]
    for fn in functions:
        name = fn.get("name", "unknown")
        size = fn.get("size", 0)
        address = fn.get("address", "0")
        lines.append(f"  {address}  {size:>6} bytes  {name}")

    return "\n".join(lines)


async def _handle_disassemble_function(input: dict, context: ToolContext) -> str:
    """Disassemble a function by name."""
    path = validate_path(context.extracted_path, input["binary_path"])
    function_name = input["function_name"]
    max_insn = input.get("num_instructions", 100)

    cache = get_analysis_cache()
    disasm = await cache.get_disassembly(
        path, function_name, context.firmware_id, context.db, max_insn,
    )

    return f"Disassembly of {function_name}:\n\n{disasm}"


async def _handle_list_imports(input: dict, context: ToolContext) -> str:
    """List imported symbols, grouped by library."""
    path = validate_path(context.extracted_path, input["binary_path"])

    cache = get_analysis_cache()
    imports = await cache.get_imports(path, context.firmware_id, context.db)

    if not imports:
        return "No imports found."

    # Group by library
    by_lib: dict[str, list[str]] = {}
    for imp in imports:
        lib = imp.get("library") or "unknown"
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

    cache = get_analysis_cache()
    exports = await cache.get_exports(path, context.firmware_id, context.db)

    if not exports:
        return "No exports found."

    lines = [f"Found {len(exports)} export(s):", ""]
    for exp in exports:
        name = exp.get("name", "unknown")
        address = exp.get("address", "0")
        lines.append(f"  {address}  {name}")

    return "\n".join(lines)


async def _handle_xrefs_to(input: dict, context: ToolContext) -> str:
    """Get cross-references to an address or symbol."""
    path = validate_path(context.extracted_path, input["binary_path"])
    target = input["address_or_symbol"]

    cache = get_analysis_cache()
    xrefs = await cache.get_xrefs_to(path, target, context.firmware_id, context.db)

    if not xrefs:
        return f"No cross-references to '{target}' found."

    lines = [f"Found {len(xrefs)} cross-reference(s) to '{target}':", ""]
    for xref in xrefs:
        from_addr = xref.get("from", "unknown")
        ref_type = xref.get("type", "unknown")
        from_func = xref.get("from_func", "")
        func_info = f"  ({from_func})" if from_func else ""
        lines.append(f"  {from_addr}  [{ref_type}]{func_info}")

    return "\n".join(lines)


async def _handle_xrefs_from(input: dict, context: ToolContext) -> str:
    """Get cross-references from an address or symbol."""
    path = validate_path(context.extracted_path, input["binary_path"])
    target = input["address_or_symbol"]

    cache = get_analysis_cache()
    xrefs = await cache.get_xrefs_from(path, target, context.firmware_id, context.db)

    if not xrefs:
        return f"No cross-references from '{target}' found."

    lines = [f"Found {len(xrefs)} cross-reference(s) from '{target}':", ""]
    for xref in xrefs:
        to_addr = xref.get("to", "unknown")
        ref_type = xref.get("type", "unknown")
        to_func = xref.get("to_func", "")
        func_info = f"  ({to_func})" if to_func else ""
        lines.append(f"  {to_addr}  [{ref_type}]{func_info}")

    return "\n".join(lines)


async def _handle_get_binary_info(input: dict, context: ToolContext) -> str:
    """Get binary metadata: architecture, format, entry point, etc."""
    path = validate_path(context.extracted_path, input["binary_path"])

    cache = get_analysis_cache()
    info = await cache.get_binary_info(path, context.firmware_id, context.db)

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


async def _handle_find_string_refs(input: dict, context: ToolContext) -> str:
    """Find functions referencing strings matching a pattern."""
    path = validate_path(context.extracted_path, input["binary_path"])
    pattern = input["pattern"]

    cache = get_analysis_cache()
    binary_sha256 = await cache.get_binary_sha256(path)
    cache_key = f"string_refs:{hashlib.md5(pattern.encode()).hexdigest()[:12]}"

    # Check cache
    cached = await cache.get_cached(
        context.firmware_id, binary_sha256, cache_key, context.db,
    )
    if cached:
        results = cached.get("results", [])
    else:
        # Run Ghidra FindStringRefs script
        try:
            raw_output = await run_ghidra_subprocess(
                path, "FindStringRefs.java", script_args=[pattern],
            )
        except (RuntimeError, TimeoutError) as exc:
            return f"Error: {exc}"

        # Parse output
        start = raw_output.find(_STRING_REFS_START)
        end = raw_output.find(_STRING_REFS_END)
        if start == -1 or end == -1:
            return "Ghidra FindStringRefs produced no parseable output."

        json_str = raw_output[start + len(_STRING_REFS_START):end].strip()
        # Extract JSON array
        json_start = json_str.find("[")
        json_end = json_str.rfind("]")
        if json_start == -1 or json_end == -1:
            return "No results found for pattern."

        try:
            results = json.loads(json_str[json_start:json_end + 1])
        except json.JSONDecodeError as exc:
            logger.error("Failed to parse FindStringRefs JSON: %s", exc)
            return "Error parsing Ghidra output."

        # Cache results
        await cache.store_cached(
            context.firmware_id, path, binary_sha256, cache_key,
            {"results": results}, context.db,
        )

    if not results:
        return f"No strings matching '{pattern}' with code references found."

    total_refs = sum(len(r.get("references", [])) for r in results)
    lines = [
        f"Found {len(results)} string(s) matching '{pattern}' "
        f"with {total_refs} code reference(s):",
        "",
    ]

    for entry in results:
        str_val = entry.get("string_value", "")
        str_addr = entry.get("string_address", "")
        refs = entry.get("references", [])
        # Truncate long strings for display
        display_str = str_val[:100] + "..." if len(str_val) > 100 else str_val
        lines.append(f"  \"{display_str}\" @ {str_addr}")
        for ref in refs:
            func = ref.get("function", "unknown")
            func_addr = ref.get("function_address", "")
            ref_addr = ref.get("ref_address", "")
            insn = ref.get("instruction", "")
            lines.append(f"    -> {func} @ {func_addr}  (ref {ref_addr}: {insn})")
        lines.append("")

    return "\n".join(lines)


async def _handle_resolve_import(input: dict, context: ToolContext) -> str:
    """Find the library implementing a function and decompile it."""
    path = validate_path(context.extracted_path, input["binary_path"])
    function_name = input["function_name"]
    real_root = os.path.realpath(context.extracted_path)

    # Step 1: Parse DT_NEEDED from the target binary
    try:
        with open(path, "rb") as f:
            elf = ELFFile(f)
            needed_libs: list[str] = []
            for seg in elf.iter_segments():
                if seg.header.p_type == "PT_DYNAMIC":
                    for tag in seg.iter_tags():
                        if tag.entry.d_tag == "DT_NEEDED":
                            needed_libs.append(tag.needed)
                    break
    except Exception as exc:
        return f"Error reading binary: {exc}"

    if not needed_libs:
        return f"Binary has no DT_NEEDED entries (statically linked?)."

    # Step 2: Search each library's exports for the function
    found_lib_path: str | None = None

    for lib_name in needed_libs:
        for lib_dir in _STANDARD_LIB_PATHS:
            candidate = os.path.join(real_root, lib_dir.lstrip("/"), lib_name)
            if not os.path.isfile(candidate):
                continue
            try:
                with open(candidate, "rb") as f:
                    lib_elf = ELFFile(f)
                    dynsym = lib_elf.get_section_by_name(".dynsym")
                    if dynsym and isinstance(dynsym, SymbolTableSection):
                        for sym in dynsym.iter_symbols():
                            if (sym.name == function_name
                                    and sym.entry.st_shndx != "SHN_UNDEF"
                                    and sym.entry.st_info.type in (
                                        "STT_FUNC", "STT_GNU_IFUNC")):
                                found_lib_path = candidate
                                break
                if found_lib_path:
                    break
            except Exception:
                continue
        if found_lib_path:
            break

    if not found_lib_path:
        return (
            f"Function '{function_name}' not found in any linked library.\n"
            f"Searched libraries: {', '.join(needed_libs)}\n"
            f"Search paths: {', '.join(_STANDARD_LIB_PATHS)}"
        )

    # Compute firmware-relative path for display
    rel_lib_path = "/" + os.path.relpath(found_lib_path, real_root)

    # Step 3: Decompile the function from the library
    try:
        decompiled = await decompile_function(
            binary_path=found_lib_path,
            function_name=function_name,
            firmware_id=context.firmware_id,
            db=context.db,
        )
    except (FileNotFoundError, TimeoutError, RuntimeError) as exc:
        return (
            f"Found '{function_name}' in {rel_lib_path}, "
            f"but decompilation failed: {exc}"
        )

    return (
        f"Resolved: '{function_name}' is implemented in {rel_lib_path}\n\n"
        f"{decompiled}"
    )


async def _handle_check_all_binary_protections(
    input: dict, context: ToolContext,
) -> str:
    """Scan all ELF binaries and report their security protections."""
    search_path = validate_path(context.extracted_path, input.get("path", "/"))
    real_root = os.path.realpath(context.extracted_path)

    ELF_MAGIC = b"\x7fELF"
    results: list[dict] = []

    for dirpath, _dirs, files in safe_walk(search_path):
        for name in files:
            abs_path = os.path.join(dirpath, name)

            # Skip symlinks to avoid duplicates
            if os.path.islink(abs_path):
                continue

            try:
                with open(abs_path, "rb") as f:
                    magic = f.read(4)
                if magic != ELF_MAGIC:
                    continue
            except (OSError, PermissionError):
                continue

            rel_path = "/" + os.path.relpath(abs_path, real_root)

            try:
                size = os.path.getsize(abs_path)
            except OSError:
                size = 0

            # Determine type (executable vs shared library)
            elf_type = "unknown"
            try:
                with open(abs_path, "rb") as f:
                    elf = ELFFile(f)
                    if elf.header.e_type == "ET_EXEC":
                        elf_type = "exe"
                    elif elf.header.e_type == "ET_DYN":
                        # Could be shared library or PIE executable
                        elf_type = "lib" if ".so" in name else "exe"
            except Exception:
                pass

            protections = check_binary_protections(abs_path)
            if "error" in protections:
                continue

            # Compute protection score
            score = 0.0
            if protections.get("nx") is True:
                score += 1
            if protections.get("canary") is True:
                score += 1
            if protections.get("pie") is True:
                score += 1
            if protections.get("fortify") is True:
                score += 1
            relro = protections.get("relro", "none")
            if relro == "full":
                score += 1
            elif relro == "partial":
                score += 0.5

            results.append({
                "path": rel_path,
                "type": elf_type,
                "size": size,
                "nx": protections.get("nx", False),
                "relro": relro,
                "canary": protections.get("canary", False),
                "pie": protections.get("pie", False),
                "fortify": protections.get("fortify", False),
                "score": score,
            })

    if not results:
        return "No ELF binaries found."

    # Sort by protection score ascending (least protected first)
    results.sort(key=lambda r: (r["score"], r["path"]))

    # Build output table
    def _yn(val: object) -> str:
        return "Y" if val is True else "N"

    lines = [
        f"Found {len(results)} ELF binary(ies), sorted by protection score "
        f"(least protected first):",
        "",
        f"  {'Path':<45} {'Type':<5} {'Size':>8} {'NX':>3} {'RELRO':>8} "
        f"{'Can':>4} {'PIE':>4} {'Fort':>5} {'Score':>6}",
        f"  {'─'*45} {'─'*5} {'─'*8} {'─'*3} {'─'*8} {'─'*4} {'─'*4} {'─'*5} {'─'*6}",
    ]

    for r in results:
        size_str = f"{r['size'] // 1024}K" if r['size'] >= 1024 else f"{r['size']}B"
        path_display = r["path"]
        if len(path_display) > 44:
            path_display = "..." + path_display[-41:]
        lines.append(
            f"  {path_display:<45} {r['type']:<5} {size_str:>8} "
            f"{_yn(r['nx']):>3} {r['relro']:>8} {_yn(r['canary']):>4} "
            f"{_yn(r['pie']):>4} {_yn(r['fortify']):>5} {r['score']:>5.1f}/5"
        )

    # Summary
    no_nx = sum(1 for r in results if not r["nx"])
    no_canary = sum(1 for r in results if not r["canary"])
    no_pie = sum(1 for r in results if not r["pie"])
    lines.append("")
    lines.append(
        f"Summary: {no_nx} without NX, {no_canary} without canary, "
        f"{no_pie} without PIE"
    )

    return "\n".join(lines)


async def _handle_trace_dataflow(input: dict, context: ToolContext) -> str:
    """Trace source-to-sink dataflow paths in a binary."""
    path = validate_path(context.extracted_path, input["binary_path"])
    sources = input.get("sources", _DEFAULT_SOURCES)
    sinks = input.get("sinks", _DEFAULT_SINKS)

    sources_csv = ",".join(sources)
    sinks_csv = ",".join(sinks)

    cache = get_analysis_cache()
    binary_sha256 = await cache.get_binary_sha256(path)
    cache_key = (
        f"taint_analysis:"
        f"{hashlib.md5((sources_csv + '|' + sinks_csv).encode()).hexdigest()[:12]}"
    )

    # Check cache
    cached = await cache.get_cached(
        context.firmware_id, binary_sha256, cache_key, context.db,
    )
    if cached:
        paths = cached.get("paths", [])
    else:
        # Run Ghidra TaintAnalysis script
        try:
            raw_output = await run_ghidra_subprocess(
                path, "TaintAnalysis.java",
                script_args=[sources_csv, sinks_csv],
            )
        except (RuntimeError, TimeoutError) as exc:
            return f"Error: {exc}"

        # Parse output
        start = raw_output.find(_TAINT_START)
        end = raw_output.find(_TAINT_END)
        if start == -1 or end == -1:
            return "Ghidra TaintAnalysis produced no parseable output."

        json_str = raw_output[start + len(_TAINT_START):end].strip()
        json_start = json_str.find("[")
        json_end = json_str.rfind("]")
        if json_start == -1 or json_end == -1:
            return "No dataflow paths found."

        try:
            paths = json.loads(json_str[json_start:json_end + 1])
        except json.JSONDecodeError as exc:
            logger.error("Failed to parse TaintAnalysis JSON: %s", exc)
            return "Error parsing Ghidra output."

        # Cache results
        await cache.store_cached(
            context.firmware_id, path, binary_sha256, cache_key,
            {"paths": paths}, context.db,
        )

    if not paths:
        return "No source-to-sink dataflow paths found."

    # Separate by confidence
    high_paths = [p for p in paths if not p.get("interprocedural", False)]
    medium_paths = [p for p in paths if p.get("interprocedural", False)]

    lines = [
        f"Found {len(paths)} potential dataflow path(s) "
        f"({len(high_paths)} high confidence, {len(medium_paths)} medium):",
        "",
    ]

    if high_paths:
        lines.append("## High Confidence (intraprocedural — same function)")
        lines.append("")
        for p in high_paths:
            func = p.get("function", "unknown")
            src = p.get("source_func", "?")
            sink = p.get("sink_func", "?")
            src_addr = p.get("source_call_site", "")
            sink_addr = p.get("sink_call_site", "")
            lines.append(f"  {func}:")
            lines.append(f"    {src}() @ {src_addr}  -->  {sink}() @ {sink_addr}")
        lines.append("")

    if medium_paths:
        lines.append("## Medium Confidence (interprocedural — across functions)")
        lines.append("")
        for p in medium_paths:
            func = p.get("function", "unknown")
            src = p.get("source_func", "?")
            sink = p.get("sink_func", "?")
            sink_func = p.get("sink_function", "?")
            lines.append(f"  {func}:")
            lines.append(f"    {src}()  -->  {sink_func}()  -->  {sink}()")
        lines.append("")

    lines.append(
        "Note: These are heuristic paths based on call ordering. "
        "Decompile the flagged functions to verify data actually flows "
        "from source to sink."
    )

    return "\n".join(lines)


def register_binary_tools(registry: ToolRegistry) -> None:
    """Register all binary analysis tools with the given registry."""

    registry.register(
        name="list_functions",
        description=(
            "List all functions found in an ELF binary, sorted by size "
            "(largest first). Large custom functions are often the most "
            "interesting for security analysis. Max 500 functions. "
            "First call for a binary triggers Ghidra analysis (1-3 minutes); "
            "subsequent calls are instant from cache."
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
            "instructions with addresses. Use list_functions first to find "
            "function names. Results come from Ghidra analysis cache."
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
                    "description": "Function name to disassemble (e.g. 'main', 'auth_check')",
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
            "names. Results are cached — first call for a binary may take 1-3 "
            "minutes, subsequent calls are instant. Best for understanding "
            "complex logic, finding vulnerabilities, and analyzing "
            "authentication/crypto routines."
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
            "gets) and external dependencies. Uses Ghidra analysis cache."
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
            "List exported symbols from an ELF binary. Shows symbol names "
            "and addresses. Uses Ghidra analysis cache."
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
            "Find all cross-references TO a given function or symbol in a "
            "binary. Shows where in the code this function is called or "
            "referenced from, including the caller function name."
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
                    "description": "Target function name or address (0x...)",
                },
            },
            "required": ["binary_path", "address_or_symbol"],
        },
        handler=_handle_xrefs_to,
    )

    registry.register(
        name="xrefs_from",
        description=(
            "Find all cross-references FROM a given function or symbol in a "
            "binary. Shows what functions are called or referenced by the "
            "target, including the callee function name."
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
                    "description": "Source function name or address (0x...)",
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
            "endianness, format, linked libraries, entry point, and more. "
            "Uses Ghidra analysis cache."
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

    # --- Phase 12 tools ---

    registry.register(
        name="find_string_refs",
        description=(
            "Find all functions that reference strings matching a regex pattern. "
            "Critical for tracing interesting strings (URLs like '/goform/telnet', "
            "format strings like 'password=%s', dangerous calls like 'doSystemCmd') "
            "back to the functions that use them. Uses Ghidra analysis — first call "
            "for a binary may take 1-3 minutes. Results are cached."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "binary_path": {
                    "type": "string",
                    "description": "Path to the ELF binary in the firmware filesystem",
                },
                "pattern": {
                    "type": "string",
                    "description": (
                        "Regex pattern to match against strings in the binary "
                        "(case-insensitive). Examples: 'password', 'goform', "
                        "'system.*cmd', '/cgi-bin/'"
                    ),
                },
            },
            "required": ["binary_path", "pattern"],
        },
        handler=_handle_find_string_refs,
    )

    registry.register(
        name="resolve_import",
        description=(
            "Find which shared library implements a given imported function and "
            "decompile it in one step. Eliminates the manual multi-step workflow: "
            "'find import -> guess which .so -> search exports -> decompile'. "
            "Parses DT_NEEDED from the target binary, searches each library's "
            "exports, and returns the decompiled pseudo-C source."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "binary_path": {
                    "type": "string",
                    "description": "Path to the ELF binary that imports the function",
                },
                "function_name": {
                    "type": "string",
                    "description": (
                        "Name of the imported function to resolve and decompile "
                        "(e.g. 'doSystemCmd', 'websGetVar', 'twsystem')"
                    ),
                },
            },
            "required": ["binary_path", "function_name"],
        },
        handler=_handle_resolve_import,
    )

    registry.register(
        name="check_all_binary_protections",
        description=(
            "Scan ALL ELF binaries in the firmware filesystem and report their "
            "security protections in a summary table. Sorted by protection score "
            "(least protected first) to quickly identify the most vulnerable "
            "targets. Shows NX, RELRO, canary, PIE, Fortify for each binary."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": (
                        "Directory to scan (default: entire firmware filesystem). "
                        "Use a subdirectory like '/usr/bin' to narrow scope."
                    ),
                },
            },
            "required": [],
        },
        handler=_handle_check_all_binary_protections,
    )

    registry.register(
        name="trace_dataflow",
        description=(
            "Trace dataflow from user-controlled sources to dangerous sinks in a "
            "binary. Identifies potential command injection and buffer overflow "
            "paths. Sources include: websGetVar, getenv, recv, read, nvram_get, "
            "fgets. Sinks include: system, popen, exec*, sprintf, strcpy. "
            "Uses Ghidra for intraprocedural analysis (same function) and "
            "interprocedural heuristics (across function calls). "
            "First call triggers Ghidra analysis (1-3 minutes); cached thereafter. "
            "HIGHEST-IMPACT tool for finding vulnerabilities in embedded web "
            "interfaces (e.g., router httpd binaries with goform handlers)."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "binary_path": {
                    "type": "string",
                    "description": "Path to the ELF binary to analyze",
                },
                "sources": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": (
                        "Custom source function names (user-controlled input). "
                        "Default: websGetVar, getenv, recv, read, fgets, nvram_get, etc."
                    ),
                },
                "sinks": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": (
                        "Custom sink function names (dangerous operations). "
                        "Default: system, popen, exec*, sprintf, strcpy, etc."
                    ),
                },
            },
            "required": ["binary_path"],
        },
        handler=_handle_trace_dataflow,
    )
