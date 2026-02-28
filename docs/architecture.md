# Architecture

## System Overview

```
Claude Code / Claude Desktop
        |
        | MCP (stdio)
        v
+------------------+     +------------------------------------+
|   wairz-mcp      |---->|         FastAPI Backend             |
|  (MCP server)    |     |                                      |
|  60+ tools       |     |  Services: firmware, analysis,       |
+------------------+     |  emulation, fuzzing, sbom, uart      |
                         |                                      |
                         |  Ghidra headless - QEMU - AFL++      |
                         +-----------+--------------------------|
                                     |
+--------------+    +----------------+----------------+
|   React SPA  |--->|  PostgreSQL    |  Redis         |
|  (Frontend)  |    |                |                |
+--------------+    +----------------+----------------+

Optional:
  wairz-uart-bridge.py (host) <-- TCP:9999 --> Docker backend
```

## Tech Stack

| Layer | Technology |
|-------|------------|
| Frontend | React 19, Vite, TypeScript, Tailwind CSS, shadcn/ui |
| Code Viewer | Monaco Editor |
| Component Graph | ReactFlow + Dagre |
| Terminal | xterm.js |
| State Management | Zustand |
| Backend | Python 3.12, FastAPI, SQLAlchemy 2.0 (async), Alembic |
| Database | PostgreSQL 16 |
| Cache | Redis 7 |
| Firmware Extraction | binwalk, sasquatch, jefferson, ubi_reader, cramfs-tools |
| Binary Analysis | radare2 (r2pipe), pyelftools |
| Decompilation | Ghidra 11.3.1 (headless) with custom analysis scripts |
| Emulation | QEMU user-mode + system-mode (ARM, MIPS, MIPSel, AArch64) |
| Fuzzing | AFL++ with QEMU mode |
| SBOM | CycloneDX, NVD API (nvdlib) |
| UART | pyserial (host-side bridge) |
| AI Integration | MCP (Model Context Protocol) |
| Containers | Docker + Docker Compose |

## Project Structure

```
wairz/
├── backend/
│   ├── app/
│   │   ├── main.py              # FastAPI application
│   │   ├── config.py            # Settings (pydantic-settings)
│   │   ├── database.py          # Async SQLAlchemy engine/session
│   │   ├── mcp_server.py        # MCP server with dynamic project switching
│   │   ├── models/              # SQLAlchemy ORM models
│   │   ├── schemas/             # Pydantic request/response schemas
│   │   ├── routers/             # REST API endpoints
│   │   ├── services/            # Business logic
│   │   ├── ai/                  # MCP tool registry + 60+ tool implementations
│   │   │   └── tools/           # Organized by category
│   │   └── utils/               # Path sandboxing, output truncation
│   ├── alembic/                 # Database migrations
│   └── pyproject.toml
├── frontend/
│   ├── src/
│   │   ├── pages/               # Route pages
│   │   ├── components/          # UI components
│   │   ├── api/                 # API client functions
│   │   ├── stores/              # Zustand state management
│   │   └── types/               # TypeScript types
│   └── package.json
├── ghidra/
│   ├── Dockerfile               # Ghidra headless container
│   └── scripts/                 # Custom Java analysis scripts
├── emulation/
│   ├── Dockerfile               # QEMU container
│   └── scripts/                 # Emulation helper scripts
├── fuzzing/
│   └── Dockerfile               # AFL++ container with QEMU mode
├── scripts/
│   └── wairz-uart-bridge.py     # Host-side UART serial bridge
├── docker-compose.yml
├── launch.sh
├── .env.example
└── CLAUDE.md
```

## Key Design Decisions

### MCP as the AI Interface

Rather than embedding an LLM in the backend, Wairz exposes analysis tools through MCP. This means:

- Users bring their own Claude subscription (no API keys stored server-side)
- The AI assistant runs in the user's Claude Code or Claude Desktop
- Tools are composable — Claude can chain them together for complex analysis workflows

### Isolated Execution Environments

Firmware binaries are never executed on the host. All execution happens in isolated Docker containers:

- **Emulation** — QEMU runs inside a dedicated container with resource limits
- **Fuzzing** — AFL++ runs in a separate container
- Both are on an isolated Docker network

### Async Everything

The backend is fully async:

- SQLAlchemy async sessions with asyncpg
- `asyncio.create_subprocess_exec` for running Ghidra, binwalk, etc.
- Background tasks for long-running operations (firmware unpacking)
- Non-blocking API endpoints

### Caching Strategy

Analysis results are cached aggressively:

- **Ghidra decompilation** — Cached by binary hash + function name in PostgreSQL
- **SBOM data** — Cached after first generation
- **Firmware metadata** — Extracted once during unpacking

### Security Boundaries

- **Path traversal prevention** — All file access validated against the extracted firmware root via `sandbox.py`
- **Output truncation** — MCP tool outputs capped at 30KB to prevent client issues
- **Resource limits** — Emulation and fuzzing containers have memory and CPU limits
