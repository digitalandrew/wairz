# CLAUDE.md — Wairz Codebase Guide

This file is for AI agents (Claude Code, etc.) working on the Wairz codebase. It describes the architecture, conventions, and patterns you need to follow when making changes.

**What is Wairz?** An open-source, browser-based firmware reverse engineering and security assessment platform. Users upload firmware, the tool unpacks it, and provides a unified interface for filesystem exploration, binary analysis, emulation, fuzzing, and security assessment — augmented by an AI assistant connected via MCP (Model Context Protocol). See `README.md` for user-facing documentation.

---

## Architecture Overview

```
Claude Code / Claude Desktop
        │
        │ MCP (stdio)
        ▼
┌─────────────────┐     ┌──────────────────────────────────┐
│   wairz-mcp     │────▶│         FastAPI Backend           │
│  (MCP server)   │     │                                    │
│  60+ tools      │     │  Services: firmware, file,         │
│                 │     │  analysis, emulation, fuzzing,     │
│  Entry point:   │     │  sbom, uart, finding, export...    │
│  wairz-mcp CLI  │     │                                    │
└─────────────────┘     │  Ghidra headless · QEMU · AFL++    │
                        └──────────┬───────────────────────┘
                                   │
┌──────────────┐    ┌──────────────┼──────────────┐
│   React SPA  │───▶│  PostgreSQL  │  Redis       │
│  (Frontend)  │    │              │              │
└──────────────┘    └──────────────┴──────────────┘

Host machine (optional):
  wairz-uart-bridge.py ←─ TCP:9999 ─→ Docker backend
```

- **Frontend:** React 19 + Vite + TypeScript, shadcn/ui + Tailwind, Monaco Editor, ReactFlow, xterm.js, Zustand
- **Backend:** Python 3.12 + FastAPI (async), SQLAlchemy 2.0 (async) + Alembic, pydantic-settings
- **MCP Server:** `wairz-mcp` CLI entry point (`app.mcp_server:main`), stdio transport, 60+ tools
- **Database:** PostgreSQL 16 (JSONB for analysis cache)
- **Containers:** Docker Compose — backend, postgres, redis, emulation (QEMU), fuzzing (AFL++)

---

## Directory Structure

```
wairz/
├── backend/
│   ├── pyproject.toml           # Entry point: wairz-mcp
│   ├── alembic/versions/        # Database migrations (auto-run on container start)
│   └── app/
│       ├── main.py              # FastAPI app + router registration
│       ├── config.py            # Settings via pydantic-settings
│       ├── database.py          # Async engine, session factory, get_db dependency
│       ├── mcp_server.py        # MCP server with dynamic project switching
│       ├── models/              # SQLAlchemy ORM models
│       ├── schemas/             # Pydantic request/response schemas
│       ├── routers/             # FastAPI REST endpoint routers
│       ├── services/            # Business logic layer
│       ├── workers/             # Background tasks (firmware unpacking)
│       ├── ai/
│       │   ├── __init__.py      # Tool registry factory — registers all tool categories
│       │   ├── tool_registry.py # ToolContext + ToolRegistry framework
│       │   ├── system_prompt.py # MCP system prompt for Claude
│       │   └── tools/           # Tool handlers by category
│       └── utils/
│           ├── sandbox.py       # Path traversal prevention (CRITICAL)
│           └── truncation.py    # Output truncation (30KB max)
├── frontend/
│   └── src/
│       ├── pages/               # Route pages, registered in App.tsx
│       ├── components/          # UI components organized by feature
│       ├── api/                 # Axios API client functions
│       ├── stores/              # Zustand state management
│       └── types/               # TypeScript type definitions
├── ghidra/
│   ├── Dockerfile
│   └── scripts/                 # Custom Java analysis scripts for headless Ghidra
├── emulation/
│   ├── Dockerfile               # QEMU + kernels (ARM, MIPS, MIPSel, AArch64)
│   └── scripts/                 # start-user-mode.sh, start-system-mode.sh, serial-exec.sh
├── fuzzing/
│   └── Dockerfile               # AFL++ with QEMU mode
└── scripts/
    └── wairz-uart-bridge.py     # Host-side serial bridge (standalone, pyserial only)
```

---

## How to Add Things

### Adding a New MCP Tool

1. Create or edit a handler in `backend/app/ai/tools/<category>.py`:
   ```python
   async def _handle_my_tool(input: dict, context: ToolContext) -> str:
       # Available on context: project_id, firmware_id, extracted_path, db
       path = context.resolve_path(input.get("path", "/"))  # validates against sandbox
       # ... do work ...
       return "result string (max 30KB, truncated automatically)"
   ```
2. Register in the same file's `register_<category>_tools(registry)` function:
   ```python
   registry.register(name="my_tool", description="...", input_schema={...}, handler=_handle_my_tool)
   ```
3. If it's a new category file, import and call `register_<category>_tools(registry)` in `backend/app/ai/__init__.py`.

### Adding a New REST Endpoint

1. Create router: `backend/app/routers/<name>.py`
   ```python
   router = APIRouter(prefix="/api/v1/projects/{project_id}/<name>", tags=["<name>"])
   ```
2. Register in `backend/app/main.py`: `app.include_router(<name>.router)`
3. Create Pydantic schemas in `backend/app/schemas/<name>.py` (use `from_attributes=True` for ORM compatibility)
4. Create service in `backend/app/services/<name>_service.py`

### Adding a Database Table

1. Create model in `backend/app/models/<name>.py`:
   - Use SQLAlchemy `Mapped`/`mapped_column` style
   - UUID primary key with dual defaults: `default=uuid.uuid4` + `server_default=func.gen_random_uuid()`
   - Foreign keys with `cascade="all, delete-orphan"` on relationships
2. Create Alembic migration: `alembic revision --autogenerate -m "description"`
3. Migrations run automatically on container startup

### Adding a Frontend Page

1. Create page component in `frontend/src/pages/<Name>Page.tsx`
2. Register route in `frontend/src/App.tsx`
3. Create API client functions in `frontend/src/api/<name>.ts`
4. Use Zustand stores (`frontend/src/stores/`) for shared state
5. UI components from shadcn/ui + Tailwind

---

## Critical Rules

### Security

1. **Path traversal prevention is mandatory.** Every file access must be validated via `app/utils/sandbox.py` (`os.path.realpath()` + prefix check against the extracted root). The MCP `ToolContext.resolve_path()` method handles this — always use it.
2. **Never execute firmware binaries on the host.** Emulation runs inside an isolated QEMU Docker container. Fuzzing runs inside an isolated AFL++ Docker container. Both have resource limits (memory, CPU).
3. **No API keys stored in the backend.** The Anthropic API key is user-provided via their Claude Code/Desktop configuration and never touches Wairz.

### Performance

1. **Cache Ghidra decompilations** — each run takes 30-120s. Cached by binary hash + function name in the `analysis_cache` table.
2. **Cache radare2 analysis** — `aaa` can take 10-30s. LRU session caching in the analysis service.
3. **Lazy-load the file tree** — firmware can have 10K+ files. Load children on expand, never the full tree at once.
4. **Truncate MCP tool outputs** — keep under 30KB (`app/utils/truncation.py`). Large outputs break MCP clients.
5. **Firmware unpacking is non-blocking** — the unpack endpoint returns 202 and runs `asyncio.create_task()`. The frontend polls every 2s until status changes from "unpacking".

### Conventions

- **Backend:** Async everywhere (SQLAlchemy async sessions, `asyncio.create_subprocess_exec` for subprocesses). Use `async_session_factory` from `database.py` for DB access outside request context (e.g., background tasks).
- **Frontend:** Zustand for state, API functions in `src/api/`, pages poll with `useEffect` + `setInterval` for long-running operations (see EmulationPage, FuzzingPage, ProjectDetailPage for the pattern).
- **Docker:** Backend has access to Docker socket for managing emulation/fuzzing containers. Emulation containers run on an internal `emulation_net` network.

---

## MCP Server

Entry point: `wairz-mcp = "app.mcp_server:main"` (defined in `pyproject.toml`)

The server uses a mutable `ProjectState` dataclass so all project context (project_id, firmware_id, extracted_path) can be switched dynamically via the `switch_project` tool without restarting the MCP process.

### Tool Categories (60+)

| Category | File | Tools |
|----------|------|-------|
| Project | `tools/filesystem.py` | `get_project_info`, `switch_project`, `list_projects` |
| Filesystem | `tools/filesystem.py` | `list_directory`, `read_file`, `search_files`, `file_info`, `find_files_by_type`, `get_component_map`, `get_firmware_metadata`, `extract_bootloader_env` |
| Strings | `tools/strings.py` | `extract_strings`, `search_strings`, `find_crypto_material`, `find_hardcoded_credentials` |
| Binary | `tools/binary.py` | `list_functions`, `disassemble_function`, `decompile_function`, `list_imports`, `list_exports`, `xrefs_to`, `xrefs_from`, `get_binary_info`, `check_binary_protections`, `check_all_binary_protections`, `find_string_refs`, `resolve_import`, `find_callers`, `search_binary_content`, `get_stack_layout`, `get_global_layout`, `trace_dataflow`, `cross_binary_dataflow` |
| Security | `tools/security.py` | `check_known_cves`, `analyze_config_security`, `check_setuid_binaries`, `analyze_init_scripts`, `check_filesystem_permissions`, `analyze_certificate` |
| SBOM | `tools/sbom.py` | `generate_sbom`, `get_sbom_components`, `check_component_cves`, `run_vulnerability_scan` |
| Emulation | `tools/emulation.py` | `start_emulation`, `run_command_in_emulation`, `stop_emulation`, `check_emulation_status`, `get_emulation_logs`, `enumerate_emulation_services`, `diagnose_emulation_environment`, `troubleshoot_emulation`, `get_crash_dump`, `run_gdb_command`, `save_emulation_preset`, `list_emulation_presets`, `start_emulation_from_preset` |
| Fuzzing | `tools/fuzzing.py` | `analyze_fuzzing_target`, `generate_fuzzing_dictionary`, `generate_seed_corpus`, `generate_fuzzing_harness`, `start_fuzzing_campaign`, `check_fuzzing_status`, `stop_fuzzing_campaign`, `triage_fuzzing_crash`, `diagnose_fuzzing_campaign` |
| Comparison | `tools/comparison.py` | `list_firmware_versions`, `diff_firmware`, `diff_binary`, `diff_decompilation` |
| UART | `tools/uart.py` | `uart_connect`, `uart_send_command`, `uart_read`, `uart_send_break`, `uart_send_raw`, `uart_disconnect`, `uart_status`, `uart_get_transcript` |
| Reporting | `tools/reporting.py` | `add_finding`, `list_findings`, `update_finding`, `read_project_instructions`, `list_project_documents`, `read_project_document` |
| Code | `tools/documents.py` | `save_code_cleanup` |

---

## UART Bridge Architecture

The bridge runs on the host (not in Docker) because USB serial adapters can't easily pass through to containers:

- **Host:** `scripts/wairz-uart-bridge.py` (standalone, only requires pyserial) listens on TCP 9999
- **Docker:** `uart_service.py` connects to bridge via `host.docker.internal`
- **Protocol:** Newline-delimited JSON, request/response matched by `id` field
- Must bind to `0.0.0.0` for Docker connectivity; may need iptables rule for Docker bridge traffic

---

## Environment Variables

See `.env.example` for defaults. Key variables:

| Variable | Description |
|----------|-------------|
| `DATABASE_URL` | PostgreSQL connection string (asyncpg) |
| `REDIS_URL` | Redis connection string |
| `STORAGE_ROOT` | Where firmware files are stored on disk |
| `MAX_UPLOAD_SIZE_MB` | Maximum firmware upload size (default 500) |
| `MAX_TOOL_OUTPUT_KB` | MCP tool output truncation limit (default 30) |
| `GHIDRA_PATH` / `GHIDRA_SCRIPTS_PATH` | Ghidra headless installation paths |
| `GHIDRA_TIMEOUT` | Decompilation timeout in seconds (default 120) |
| `EMULATION_IMAGE` / `EMULATION_NETWORK` | Docker image and network for QEMU containers |
| `FUZZING_IMAGE` / `FUZZING_TIMEOUT_MINUTES` | Docker image and timeout for AFL++ containers |
| `UART_BRIDGE_HOST` / `UART_BRIDGE_PORT` | Host-side UART bridge connection |
| `NVD_API_KEY` | Optional, for higher NVD rate limits during CVE scanning |

---

## Testing Firmware

Good images for development and testing:

- **OpenWrt** (MIPS, ARM) — well-structured embedded Linux with lots of components
- **DD-WRT** — similar to OpenWrt
- **DVRF** (Damn Vulnerable Router Firmware) — intentionally vulnerable, great for security tool testing
