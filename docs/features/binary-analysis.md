# Binary Analysis

Wairz provides deep binary analysis using Ghidra headless for decompilation and custom analysis scripts for cross-references, dataflow tracing, and more.

## Functions

List all functions in an ELF binary, sorted by size (largest first). Large custom functions are typically the most interesting for security analysis.

!!! note
    The first analysis of a binary triggers Ghidra headless processing, which takes 1-3 minutes. Subsequent calls use cached results.

## Decompilation

View Ghidra pseudo-C decompilation of any function. The decompiled output is much easier to read than assembly and is the primary tool for understanding binary logic.

Claude can also clean up decompiled code — renaming variables, adding comments — and save the result for viewing in the web UI's "AI Cleaned" toggle.

## Disassembly

View raw assembly instructions for any function. Useful for verifying decompilation accuracy or analyzing low-level behavior.

## Cross-References

- **Xrefs To** — Find all locations that call or reference a given function
- **Xrefs From** — Find all functions called by a given function
- **Find Callers** — Find all call sites of a function across the binary, including aliases

## Dataflow Tracing

Trace data from user-controlled sources to dangerous sinks:

- **Sources:** `websGetVar`, `getenv`, `recv`, `read`, `nvram_get`, `fgets`
- **Sinks:** `system`, `popen`, `exec*`, `sprintf`, `strcpy`

This is the highest-impact tool for finding vulnerabilities in embedded web interfaces (e.g., router `httpd` binaries with `goform` handlers).

## Cross-Binary Dataflow

Trace data flows across multiple firmware binaries via IPC mechanisms:

- **nvram** — `nvram_get`/`nvram_set` pairs
- **config** — Config get/set operations
- **file** — File I/O between binaries

## String References

Find all functions that reference strings matching a pattern. Useful for tracing interesting strings (URLs, format strings, parameter names) back to the code that uses them.

## Stack & Global Layout

- **Stack Layout** — View local variables, offsets, sizes, and buffer-to-return-address distances for overflow analysis
- **Global Layout** — Map global variables around a target symbol to understand overflow impact

## Binary Protections

Check security protections (equivalent to `checksec`):

| Protection | Description |
|------------|-------------|
| NX | No-execute (DEP) |
| RELRO | Read-only relocations |
| Canary | Stack canaries |
| PIE | Position-independent executable |
| Fortify | Fortify Source |
| Stripped | Symbol table removed |

Use `check_all_binary_protections` to scan all binaries and sort by protection score (least protected first).

## MCP Tools

| Tool | Description |
|------|-------------|
| `list_functions` | List functions sorted by size |
| `decompile_function` | Ghidra pseudo-C decompilation |
| `disassemble_function` | Assembly instructions |
| `list_imports` / `list_exports` | Imported and exported symbols |
| `xrefs_to` / `xrefs_from` | Cross-references |
| `find_callers` | All call sites of a function |
| `find_string_refs` | Functions referencing matching strings |
| `trace_dataflow` | Source-to-sink dataflow analysis |
| `cross_binary_dataflow` | Cross-binary IPC tracing |
| `get_stack_layout` / `get_global_layout` | Memory layout analysis |
| `check_binary_protections` | Security protections check |
| `resolve_import` | Find and decompile imported functions |
| `search_binary_content` | Search for byte/string/disasm patterns |
| `get_binary_info` | ELF metadata and linked libraries |
