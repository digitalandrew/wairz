# Wairz

AI-assisted firmware reverse engineering and security assessment platform. Upload firmware images, unpack them, explore the filesystem, analyze binaries, and conduct security assessments — all powered by AI analysis via [Model Context Protocol (MCP)](https://modelcontextprotocol.io/).

Connect Claude Code or Claude Desktop to Wairz's analysis tools through MCP and use your own Claude subscription for AI-driven firmware security research.

## Features

- **Firmware Unpacking** — Automatic extraction of SquashFS, JFFS2, UBIFS, CramFS, ext, and CPIO filesystems using binwalk
- **File Explorer** — Browse extracted filesystems with a virtual tree, view text/binary/hex content, and search for files
- **Binary Analysis** — List functions, disassemble, and decompile binaries using Ghidra headless
- **Component Map** — Interactive dependency graph showing binaries, libraries, scripts, and their relationships
- **Security Findings** — Record, categorize, and export security findings with severity ratings and evidence
- **SBOM & CVE Scanning** — Generate Software Bill of Materials and scan components against the NVD for known vulnerabilities
- **Firmware Emulation** — Boot firmware in QEMU (user-mode for single binaries, system-mode for full OS) in isolated containers
- **AI Analysis via MCP** — Connect Claude Code or Claude Desktop to 40+ analysis tools for AI-driven security assessment
- **Report Export** — Export findings as Markdown or PDF reports

## Architecture

```
Claude Code / Claude Desktop
        │
        │ MCP (stdio)
        ▼
┌─────────────────┐     ┌──────────────────────────────────┐
│   wairz-mcp     │────▶│         FastAPI Backend           │
│  (MCP server)   │     │  File explorer, binary analysis,  │
└─────────────────┘     │  SBOM, findings, emulation        │
                        └──────────┬───────────────────────┘
                                   │
┌──────────────┐    ┌──────────────┼──────────────┐
│   React SPA  │───▶│  PostgreSQL  │  QEMU        │
│  (Frontend)  │    │              │  (Emulation)  │
└──────────────┘    └──────────────┴──────────────┘
```

## Prerequisites

- [Docker](https://docs.docker.com/get-docker/) and Docker Compose
- [uv](https://docs.astral.sh/uv/getting-started/installation/) (for local development)

## Quick Start

### Docker deployment (recommended)

```bash
git clone https://github.com/digitalandrew/wairz.git
cd wairz
cp .env.example .env
docker compose up --build
```

The frontend is available at `http://localhost:3000` and the API at `http://localhost:8000/docs`.

### Local development

```bash
# Start PostgreSQL and Redis
docker compose up -d postgres redis

# Backend
cd backend
uv sync
uv run alembic upgrade head
uv run uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

# Frontend (in another terminal)
cd frontend
npm install
npm run dev
```

## Connecting AI via MCP

Wairz uses MCP to provide AI analysis tools to Claude Code or Claude Desktop. After starting the Wairz backend, add the MCP server to your client:

### Claude Code

```bash
claude mcp add wairz -- docker exec -i wairz-backend-1 uv run wairz-mcp --project-id <PROJECT_ID>
```

### Claude Desktop

Add to your Claude Desktop config:

```json
{
  "mcpServers": {
    "wairz": {
      "command": "docker",
      "args": [
        "exec", "-i", "wairz-backend-1",
        "uv", "run", "wairz-mcp",
        "--project-id", "<PROJECT_ID>"
      ]
    }
  }
}
```

### Available MCP Tools

The MCP server exposes 40+ tools for firmware analysis:

| Category | Tools |
|----------|-------|
| Filesystem | `list_directory`, `read_file`, `file_info`, `search_files`, `find_files_by_type` |
| Strings | `extract_strings`, `search_strings`, `find_crypto_material`, `find_hardcoded_credentials` |
| Binary Analysis | `list_functions`, `disassemble_function`, `decompile_function`, `list_imports`, `list_exports`, `xrefs_to`, `xrefs_from`, `get_binary_info`, `check_binary_protections` |
| Security | `analyze_config_security`, `check_setuid_binaries`, `analyze_init_scripts`, `check_filesystem_permissions` |
| SBOM & CVEs | `generate_sbom`, `get_sbom_components`, `check_component_cves`, `check_known_cves`, `run_vulnerability_scan` |
| Findings | `add_finding`, `list_findings`, `update_finding` |
| Emulation | `start_emulation`, `run_command_in_emulation`, `stop_emulation`, `check_emulation_status` |
| Component Map | `get_component_map` |
| Documents | `list_project_documents`, `read_project_document` |

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/projects` | Create project |
| `GET` | `/api/v1/projects` | List projects |
| `GET` | `/api/v1/projects/{id}` | Get project details |
| `PATCH` | `/api/v1/projects/{id}` | Update project |
| `DELETE` | `/api/v1/projects/{id}` | Delete project |
| `POST` | `/api/v1/projects/{id}/firmware` | Upload firmware |
| `POST` | `/api/v1/projects/{id}/firmware/unpack` | Unpack firmware |
| `GET` | `/api/v1/projects/{id}/files` | List directory |
| `GET` | `/api/v1/projects/{id}/files/read` | Read file contents |
| `GET` | `/api/v1/projects/{id}/files/info` | File metadata |
| `GET` | `/api/v1/projects/{id}/files/search` | Search files |
| `GET` | `/api/v1/projects/{id}/analysis/functions` | List binary functions |
| `GET` | `/api/v1/projects/{id}/analysis/disasm` | Disassemble function |
| `GET` | `/api/v1/projects/{id}/analysis/decompile` | Decompile function |
| `GET` | `/api/v1/projects/{id}/analysis/binary-info` | Binary info + protections |
| `GET` | `/api/v1/projects/{id}/component-map` | Component dependency graph |
| `POST` | `/api/v1/projects/{id}/findings` | Create finding |
| `GET` | `/api/v1/projects/{id}/findings` | List findings |
| `POST` | `/api/v1/projects/{id}/findings/export` | Export report |
| `POST` | `/api/v1/projects/{id}/sbom/generate` | Generate SBOM |
| `GET` | `/api/v1/projects/{id}/sbom` | Get SBOM components |
| `POST` | `/api/v1/projects/{id}/sbom/vulnerabilities/scan` | Scan for CVEs |
| `POST` | `/api/v1/projects/{id}/emulation/start` | Start emulation |
| `POST` | `/api/v1/projects/{id}/emulation/{sid}/exec` | Execute command |
| `POST` | `/api/v1/projects/{id}/emulation/{sid}/stop` | Stop emulation |

## Tech Stack

| Layer | Technology |
|-------|------------|
| Frontend | React 19, Vite, TypeScript, Tailwind CSS, shadcn/ui |
| Code Viewer | Monaco Editor |
| Component Graph | ReactFlow + Dagre |
| Terminal | xterm.js |
| Backend | Python 3.12, FastAPI, SQLAlchemy 2.0 (async) |
| Database | PostgreSQL 16 |
| Cache | Redis 7 |
| Firmware Extraction | binwalk, sasquatch, jefferson, ubi_reader |
| Binary Analysis | Ghidra 11.3.1 (headless) |
| Emulation | QEMU (user-mode + system-mode) |
| SBOM | CycloneDX, NVD API |
| AI Integration | MCP (Model Context Protocol) |

## Project Structure

```
wairz/
├── backend/
│   ├── app/
│   │   ├── main.py              # FastAPI application
│   │   ├── config.py            # Settings (pydantic-settings)
│   │   ├── database.py          # Async SQLAlchemy
│   │   ├── mcp_server.py        # MCP server for AI tools
│   │   ├── models/              # ORM models
│   │   ├── schemas/             # Pydantic schemas
│   │   ├── routers/             # API endpoints
│   │   ├── services/            # Business logic
│   │   ├── ai/                  # Tool registry + tool implementations
│   │   └── utils/               # Path validation, sandboxing
│   ├── alembic/                 # Database migrations
│   └── pyproject.toml
├── frontend/
│   ├── src/
│   │   ├── pages/               # Route pages
│   │   ├── components/          # UI components
│   │   ├── api/                 # API client
│   │   ├── stores/              # Zustand state stores
│   │   └── types/               # TypeScript types
│   └── package.json
├── emulation/
│   └── Dockerfile               # QEMU emulation container
├── docker-compose.yml
├── .env.example
└── CLAUDE.md                    # Full project specification
```

## Configuration

All settings are configured via environment variables or `.env` file:

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | `postgresql+asyncpg://wairz:wairz@localhost:5432/wairz` | PostgreSQL connection |
| `REDIS_URL` | `redis://localhost:6379/0` | Redis connection |
| `STORAGE_ROOT` | `/data/firmware` | Firmware storage directory |
| `MAX_UPLOAD_SIZE_MB` | `500` | Maximum firmware upload size |
| `MAX_TOOL_OUTPUT_KB` | `30` | Tool output truncation limit |
| `GHIDRA_PATH` | `/opt/ghidra` | Ghidra installation path |
| `GHIDRA_TIMEOUT` | `120` | Ghidra decompilation timeout (seconds) |
| `LOG_LEVEL` | `INFO` | Logging level |

## License

[AGPL-3.0](LICENSE)
