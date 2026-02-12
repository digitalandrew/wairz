# CLAUDE.md — Wairz: AI-Assisted Firmware Reverse Engineering & Security Assessment Tool

**Project Name:** Wairz
**Domain:** wairz.ai
**Repository:** [github.com/\[org\]/wairz](https://github.com/digitalandrew/wairz)

## Project Overview

Wairz is an open-source, browser-based firmware reverse engineering and security assessment platform. Users upload firmware images, the tool unpacks them, and provides a unified interface for exploring the filesystem, viewing/analyzing files, reverse engineering binaries, and conducting security assessments — all augmented by an AI assistant (Claude) that can autonomously run tools, inspect files, and generate findings.

**Target for v1:** Embedded Linux firmware (SquashFS, JFFS2, UBIFS, CramFS, ext, CPIO).
**Future:** RTOS and bare-metal firmware support.

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                   Browser Frontend                   │
│  (React + Vite + TypeScript)                        │
│                                                      │
│  ┌──────────┐ ┌──────────────┐ ┌──────────────────┐ │
│  │ Project  │ │ File Explorer│ │  AI Chat Panel   │ │
│  │ Dashboard│ │ + Hex/Code   │ │  (tool-use aware │ │
│  │ & Upload │ │   Viewer     │ │   streaming)     │ │
│  └──────────┘ └──────────────┘ └──────────────────┘ │
│                 ┌──────────────────┐                 │
│                 │ Findings & Report│                 │
│                 └──────────────────┘                 │
└──────────────────┬──────────────────────────────────┘
                   │ REST + WebSocket
                   ▼
┌─────────────────────────────────────────────────────┐
│              Backend API (Python / FastAPI)          │
│                                                      │
│  ┌────────────┐ ┌────────────┐ ┌──────────────────┐ │
│  │ Firmware   │ │ Analysis   │ │ AI Orchestrator  │ │
│  │ Service    │ │ Service    │ │ (tool-use loop)  │ │
│  │            │ │            │ │                  │ │
│  │ - upload   │ │ - strings  │ │ - Claude API     │ │
│  │ - unpack   │ │ - binwalk  │ │ - tool registry  │ │
│  │ - fs tree  │ │ - radare2  │ │ - result routing │ │
│  │ - file I/O │ │ - Ghidra   │ │ - WS streaming   │ │
│  │            │ │   headless │ │                  │ │
│  └────────────┘ └────────────┘ └──────────────────┘ │
│                                                      │
│  ┌──────────────────────────────────────────────┐   │
│  │           Tool Registry                       │   │
│  │  Maps tool names → handler functions          │   │
│  │  Validates inputs, truncates outputs           │   │
│  │  Enforces sandboxing & resource limits         │   │
│  └──────────────────────────────────────────────┘   │
└──────────┬──────────────┬───────────────────────────┘
           │              │
     ┌─────▼─────┐  ┌────▼──────┐
     │ PostgreSQL │  │  Volume / │
     │            │  │  MinIO    │
     │ - projects │  │  (blob    │
     │ - metadata │  │  storage) │
     │ - convos   │  │           │
     │ - findings │  └───────────┘
     │ - cache    │
     └───────────┘
     ┌───────────┐
     │   Redis   │
     │ - task    │
     │   queue   │
     │ - cache   │
     └───────────┘
```

---

## Tech Stack

| Layer | Technology | Notes |
|---|---|---|
| Frontend | React 18 + Vite + TypeScript | SPA, no SSR needed |
| UI Components | shadcn/ui + Tailwind CSS | Clean, accessible components |
| Code Viewer | Monaco Editor | Hex view, disassembly, config files |
| File Tree | react-arborist | Virtual tree for large filesystems |
| Backend | Python 3.12 + FastAPI | Async, WebSocket support |
| Task Queue | arq (Redis-backed) | Long-running analysis jobs |
| Database | PostgreSQL 16 | JSONB for conversations, standard relational for rest |
| Migrations | Alembic | Schema versioning |
| ORM | SQLAlchemy 2.0 (async) | Mapped classes, async sessions |
| RE: Unpacking | binwalk, sasquatch, jefferson, ubi_reader, cramfs-tools | Filesystem extraction |
| RE: Binary | radare2 (r2pipe), pyelftools | Disassembly, ELF parsing |
| RE: Decompile | Ghidra headless (via analyzeHeadless) | Pseudo-C decompilation |
| AI | Anthropic Claude API (tool use, streaming) | claude-sonnet-4-20250514 for tool use |
| Containers | Docker + Docker Compose | Local self-hosted deployment |
| Testing | pytest (backend), Vitest (frontend) | Unit + integration |

---

## Directory Structure

```
wairz/
├── CLAUDE.md                    # This file
├── README.md
├── LICENSE                      # MIT or Apache 2.0
├── docker-compose.yml
├── .env.example
│
├── frontend/
│   ├── package.json
│   ├── vite.config.ts
│   ├── tsconfig.json
│   ├── index.html
│   ├── src/
│   │   ├── main.tsx
│   │   ├── App.tsx
│   │   ├── api/                 # API client functions
│   │   │   ├── projects.ts
│   │   │   ├── files.ts
│   │   │   ├── analysis.ts
│   │   │   └── chat.ts          # WebSocket client
│   │   ├── components/
│   │   │   ├── layout/
│   │   │   │   ├── AppLayout.tsx
│   │   │   │   ├── Sidebar.tsx
│   │   │   │   └── Header.tsx
│   │   │   ├── projects/
│   │   │   │   ├── ProjectList.tsx
│   │   │   │   ├── ProjectCard.tsx
│   │   │   │   └── FirmwareUpload.tsx
│   │   │   ├── explorer/
│   │   │   │   ├── FileTree.tsx
│   │   │   │   ├── FileViewer.tsx
│   │   │   │   ├── HexViewer.tsx
│   │   │   │   └── BinaryInfo.tsx
│   │   │   ├── chat/
│   │   │   │   ├── ChatPanel.tsx
│   │   │   │   ├── ChatMessage.tsx
│   │   │   │   ├── ToolCallBlock.tsx
│   │   │   │   └── ChatInput.tsx
│   │   │   └── findings/
│   │   │       ├── FindingsList.tsx
│   │   │       ├── FindingDetail.tsx
│   │   │       └── ReportExport.tsx
│   │   ├── hooks/
│   │   │   ├── useWebSocket.ts
│   │   │   ├── useProject.ts
│   │   │   └── useFileTree.ts
│   │   ├── stores/              # Zustand stores
│   │   │   ├── projectStore.ts
│   │   │   ├── chatStore.ts
│   │   │   └── explorerStore.ts
│   │   ├── types/
│   │   │   └── index.ts
│   │   └── utils/
│   │       └── format.ts
│   └── Dockerfile
│
├── backend/
│   ├── pyproject.toml           # uv or poetry
│   ├── alembic.ini
│   ├── alembic/
│   │   └── versions/
│   ├── app/
│   │   ├── __init__.py
│   │   ├── main.py              # FastAPI app, mount routers
│   │   ├── config.py            # Settings via pydantic-settings
│   │   ├── database.py          # Async SQLAlchemy engine/session
│   │   ├── models/              # SQLAlchemy ORM models
│   │   │   ├── __init__.py
│   │   │   ├── project.py
│   │   │   ├── firmware.py
│   │   │   ├── conversation.py
│   │   │   ├── finding.py
│   │   │   └── analysis_cache.py
│   │   ├── schemas/             # Pydantic request/response schemas
│   │   │   ├── __init__.py
│   │   │   ├── project.py
│   │   │   ├── firmware.py
│   │   │   ├── chat.py
│   │   │   └── finding.py
│   │   ├── routers/             # FastAPI routers
│   │   │   ├── __init__.py
│   │   │   ├── projects.py
│   │   │   ├── files.py
│   │   │   ├── analysis.py
│   │   │   ├── chat.py          # WebSocket endpoint
│   │   │   └── findings.py
│   │   ├── services/            # Business logic
│   │   │   ├── __init__.py
│   │   │   ├── firmware_service.py
│   │   │   ├── file_service.py
│   │   │   ├── analysis_service.py
│   │   │   └── finding_service.py
│   │   ├── ai/                  # AI orchestration
│   │   │   ├── __init__.py
│   │   │   ├── orchestrator.py  # Main tool-use loop
│   │   │   ├── tool_registry.py # Tool name → handler mapping
│   │   │   ├── system_prompt.py # System prompt for Claude
│   │   │   └── tools/           # Individual tool implementations
│   │   │       ├── __init__.py
│   │   │       ├── filesystem.py
│   │   │       ├── strings.py
│   │   │       ├── binary.py
│   │   │       ├── security.py
│   │   │       └── reporting.py
│   │   ├── workers/             # Background task handlers
│   │   │   ├── __init__.py
│   │   │   ├── unpack.py
│   │   │   └── analysis.py
│   │   └── utils/
│   │       ├── __init__.py
│   │       ├── sandbox.py       # Subprocess sandboxing
│   │       └── truncation.py    # Output truncation for AI
│   ├── tests/
│   │   ├── conftest.py
│   │   ├── test_firmware_service.py
│   │   ├── test_file_service.py
│   │   ├── test_tools.py
│   │   └── test_orchestrator.py
│   └── Dockerfile
│
├── ghidra/
│   ├── Dockerfile               # Ghidra headless container
│   └── scripts/
│       └── DecompileFunction.java  # Ghidra script for decompilation
│
└── scripts/
    ├── setup.sh                 # First-time setup helper
    └── test-firmware/           # Sample firmware for testing
```

---

## Database Schema

```sql
-- Projects table
CREATE TABLE projects (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    description TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    status VARCHAR(50) DEFAULT 'created'  -- created, unpacking, ready, error
);

-- Firmware metadata
CREATE TABLE firmware (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id UUID REFERENCES projects(id) ON DELETE CASCADE,
    original_filename VARCHAR(255),
    sha256 VARCHAR(64) NOT NULL,
    file_size BIGINT,
    storage_path VARCHAR(512),        -- path to original firmware blob
    extracted_path VARCHAR(512),      -- path to unpacked filesystem root
    architecture VARCHAR(50),         -- arm, mips, mipsel, x86, etc.
    endianness VARCHAR(10),           -- little, big
    os_info TEXT,                      -- detected OS info
    unpack_log TEXT,                   -- binwalk/extraction output
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Conversations (AI chat history per project)
CREATE TABLE conversations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id UUID REFERENCES projects(id) ON DELETE CASCADE,
    title VARCHAR(255),
    messages JSONB DEFAULT '[]'::jsonb,  -- full message array for Claude API
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Security findings
CREATE TABLE findings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id UUID REFERENCES projects(id) ON DELETE CASCADE,
    conversation_id UUID REFERENCES conversations(id),
    title VARCHAR(255) NOT NULL,
    severity VARCHAR(20) NOT NULL,     -- critical, high, medium, low, info
    description TEXT,
    evidence TEXT,                      -- supporting evidence / output
    file_path VARCHAR(512),            -- affected file
    line_number INTEGER,
    cve_ids TEXT[],                     -- associated CVEs
    status VARCHAR(20) DEFAULT 'open', -- open, confirmed, false_positive, fixed
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Analysis cache (avoid re-running expensive operations)
CREATE TABLE analysis_cache (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    firmware_id UUID REFERENCES firmware(id) ON DELETE CASCADE,
    binary_path VARCHAR(512),
    binary_sha256 VARCHAR(64),
    operation VARCHAR(100),            -- e.g. "decompile:main", "disasm:auth_check"
    result JSONB,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_cache_lookup ON analysis_cache(firmware_id, binary_sha256, operation);
CREATE INDEX idx_findings_project ON findings(project_id);
CREATE INDEX idx_conversations_project ON conversations(project_id);
```

---

## AI Tool Definitions

These are the tools registered with the Claude API for the tool-use loop. Each tool maps to a handler function in `backend/app/ai/tools/`.

### Filesystem Tools (`tools/filesystem.py`)

| Tool | Parameters | Returns | Notes |
|---|---|---|---|
| `list_directory` | `path: str` | File listing with names, types, sizes, permissions | Returns max 200 entries, notes if truncated |
| `read_file` | `path: str, offset?: int, length?: int` | File contents (UTF-8 text or hex dump for binary) | Max 50KB per read. Auto-detects binary vs text |
| `search_files` | `pattern: str, path?: str` | List of matching file paths | Glob or regex. Max 100 results |
| `file_info` | `path: str` | Type (file/magic), size, permissions, hashes, ELF headers if applicable | Uses `python-magic` and `pyelftools` |
| `find_files_by_type` | `file_type: str, path?: str` | List of matching files | e.g., "elf", "shell_script", "config", "certificate" |

### String Analysis Tools (`tools/strings.py`)

| Tool | Parameters | Returns | Notes |
|---|---|---|---|
| `extract_strings` | `path: str, min_length?: int` | Interesting strings (URLs, IPs, paths, credentials patterns) | Pre-filtered and categorized. Max 200 strings |
| `search_strings` | `pattern: str, path?: str` | Grep results with file paths and line numbers | Regex. Max 100 results |
| `find_crypto_material` | `path?: str` | Detected private keys, certificates, key files | Scans for PEM headers, known key patterns |
| `find_hardcoded_credentials` | `path?: str` | Potential passwords, API keys, tokens | Pattern matching + entropy analysis |

### Binary Analysis Tools (`tools/binary.py`)

| Tool | Parameters | Returns | Notes |
|---|---|---|---|
| `list_functions` | `binary_path: str` | Function names, addresses, sizes | Via r2pipe. Max 500 functions |
| `disassemble_function` | `binary_path: str, function_name: str, num_instructions?: int` | Disassembly listing | Default 100 instructions max |
| `decompile_function` | `binary_path: str, function_name: str` | Pseudo-C decompilation | Via Ghidra headless. Cached per binary+function |
| `list_imports` | `binary_path: str` | Imported symbols and libraries | Via r2pipe |
| `list_exports` | `binary_path: str` | Exported symbols | Via r2pipe |
| `xrefs_to` | `binary_path: str, address_or_symbol: str` | Cross-references to the target | Via r2pipe |
| `xrefs_from` | `binary_path: str, address_or_symbol: str` | Cross-references from the target | Via r2pipe |
| `get_binary_info` | `binary_path: str` | Architecture, endianness, linked libs, sections, entry point | Combined r2 + pyelftools |

### Security Assessment Tools (`tools/security.py`)

| Tool | Parameters | Returns | Notes |
|---|---|---|---|
| `check_binary_protections` | `binary_path: str` | NX, ASLR, stack canaries, RELRO, PIE, Fortify | checksec equivalent via pyelftools |
| `check_known_cves` | `component: str, version: str` | Known CVEs with severity and description | Queries local CVE DB or NVD API |
| `analyze_config_security` | `path: str` | Security issues in config files | Checks for weak permissions, default creds, debug flags |
| `check_setuid_binaries` | `path?: str` | List of setuid/setgid binaries | Filesystem scan |
| `analyze_init_scripts` | `path?: str` | Services started at boot, exposed ports, running as root | Parses init.d, systemd, inittab |
| `check_filesystem_permissions` | `path?: str` | World-writable files, weak permissions on sensitive files | Recursive scan |

### Reporting Tools (`tools/reporting.py`)

| Tool | Parameters | Returns | Notes |
|---|---|---|---|
| `add_finding` | `title: str, severity: str, description: str, evidence?: str, file_path?: str` | Finding ID | Saves to database |
| `list_findings` | `severity?: str, status?: str` | Current findings for project | Filterable |
| `update_finding` | `finding_id: str, status?: str, description?: str` | Updated finding | For refining findings |

---

## AI System Prompt

Store in `backend/app/ai/system_prompt.py`. The system prompt should establish:

```
You are Wairz AI, an expert firmware reverse engineer and security analyst.
You are analyzing firmware for project: {project_name}
Firmware: {firmware_filename} ({architecture}, {endianness})
Extracted filesystem root: {extracted_path}

Your role:
- Help the user understand the firmware's structure, components, and security posture
- Proactively investigate interesting findings using your tools
- When you find security issues, use add_finding to formally record them
- Explain your reasoning and methodology as you work
- If you are unsure about something, say so rather than guessing

Methodology guidance:
1. Start by understanding the filesystem layout and identifying key components
2. Look at startup scripts to understand what services run
3. Identify interesting binaries (web servers, custom daemons, etc.)
4. Check for common embedded Linux vulnerabilities:
   - Hardcoded credentials
   - Insecure network services
   - Missing binary protections
   - Known vulnerable components (busybox version, openssl version, etc.)
   - Leftover debug interfaces
   - Weak file permissions
   - Unencrypted sensitive data
5. For custom binaries, analyze their security-relevant functions

Output format:
- Be concise but thorough
- When showing code or disassembly, highlight the relevant parts
- Always explain WHY something is a security concern, not just THAT it is
- Rate findings: critical, high, medium, low, info

You have access to the tools defined in this conversation. Use them freely
to investigate. You may make multiple tool calls in sequence to follow
a line of investigation.
```

---

## API Endpoints

### REST Endpoints

```
# Projects
POST   /api/v1/projects                    # Create project
GET    /api/v1/projects                    # List projects
GET    /api/v1/projects/{id}               # Get project details
DELETE /api/v1/projects/{id}               # Delete project

# Firmware
POST   /api/v1/projects/{id}/firmware      # Upload firmware (multipart)
GET    /api/v1/projects/{id}/firmware       # Get firmware metadata
POST   /api/v1/projects/{id}/firmware/unpack  # Trigger unpacking

# File Explorer
GET    /api/v1/projects/{id}/files?path=   # List directory
GET    /api/v1/projects/{id}/files/read?path=&offset=&length=  # Read file
GET    /api/v1/projects/{id}/files/info?path=  # File metadata
GET    /api/v1/projects/{id}/files/download?path=  # Download file

# Analysis
GET    /api/v1/projects/{id}/analysis/strings?path=  # Extract strings
GET    /api/v1/projects/{id}/analysis/binary-info?path=  # ELF info
GET    /api/v1/projects/{id}/analysis/functions?path=  # List functions
GET    /api/v1/projects/{id}/analysis/disasm?path=&function=  # Disassemble

# Findings
GET    /api/v1/projects/{id}/findings      # List findings
POST   /api/v1/projects/{id}/findings      # Create finding
PATCH  /api/v1/projects/{id}/findings/{fid}  # Update finding
DELETE /api/v1/projects/{id}/findings/{fid}  # Delete finding
POST   /api/v1/projects/{id}/findings/export  # Export report

# Conversations
GET    /api/v1/projects/{id}/conversations  # List conversations
POST   /api/v1/projects/{id}/conversations  # Create conversation
GET    /api/v1/projects/{id}/conversations/{cid}  # Get conversation
```

### WebSocket Endpoint

```
WS /api/v1/projects/{id}/conversations/{cid}/ws

# Client sends:
{ "type": "user_message", "content": "Analyze the main web server binary" }

# Server streams back:
{ "type": "assistant_text", "content": "I'll start by...", "delta": true }
{ "type": "tool_call", "tool": "list_directory", "input": {"path": "/usr/sbin"} }
{ "type": "tool_result", "tool": "list_directory", "output": "..." }
{ "type": "assistant_text", "content": "I found the httpd binary...", "delta": true }
{ "type": "done" }
```

---

## Development Phases & Session Guide

Each phase below is broken into discrete sessions suitable for a single Claude Code session. Each session has clear inputs, outputs, and a definition of done.

---

### Phase 1: Foundation — Backend Scaffold (Sessions 1–5)

**Goal:** Working backend with project CRUD, firmware upload, unpacking, and file browsing.

#### Session 1.1: Project Setup & Database

**Do:**
- Initialize the backend Python project with `pyproject.toml` (use `uv`)
- Dependencies: `fastapi`, `uvicorn`, `sqlalchemy[asyncio]`, `asyncpg`, `alembic`, `pydantic-settings`, `python-multipart`
- Set up FastAPI app in `app/main.py` with CORS middleware
- Create `app/config.py` with pydantic-settings (DB URL, storage paths, Anthropic API key)
- Create `app/database.py` with async SQLAlchemy engine and session factory
- Create SQLAlchemy models for `projects` and `firmware` tables
- Set up Alembic with async support, create initial migration
- Create `docker-compose.yml` with `postgres` and `redis` services (backend service can come later)

**Definition of Done:**
- `alembic upgrade head` creates the tables
- FastAPI app starts and serves `/docs`

#### Session 1.2: Project & Firmware CRUD

**Do:**
- Create Pydantic schemas for project and firmware (request/response)
- Create `app/services/firmware_service.py` — handles file storage
- Create `app/routers/projects.py` — full CRUD
- Create `app/routers/firmware.py` — upload endpoint (multipart), metadata retrieval
- Firmware upload saves the blob to `{STORAGE_ROOT}/projects/{id}/firmware/` and computes SHA256
- Add basic error handling (404 for missing projects, 409 for duplicate uploads)

**Definition of Done:**
- Can create a project, upload a firmware file, retrieve project with firmware metadata
- File is persisted on disk with correct hash
- Tests pass for happy path CRUD operations

#### Session 1.3: Firmware Unpacking Pipeline

**Do:**
- Install and configure `binwalk` in the backend Dockerfile
- Create `app/workers/unpack.py` — firmware extraction logic:
  1. Run `binwalk -e` on the firmware blob
  2. Find the extracted filesystem root (heuristic: largest directory, or look for `/etc`, `/usr`, etc.)
  3. Detect architecture by examining ELF binaries (`pyelftools`)
  4. Update firmware record with `extracted_path`, `architecture`, `endianness`
  5. Update project status to `ready`
- Create `POST /api/v1/projects/{id}/firmware/unpack` endpoint
- For v1, run synchronously (background tasks come in a later session)
- Handle extraction errors gracefully (update status to `error`, save log)

**Definition of Done:**
- Upload a real firmware image (e.g., OpenWrt), hit unpack, filesystem is extracted
- Architecture and endianness correctly detected
- Project status reflects the pipeline state

#### Session 1.4: File Explorer API

**Do:**
- Create `app/services/file_service.py`:
  - `list_directory(project_id, path)` — returns entries with name, type, size, permissions
  - `read_file(project_id, path, offset, length)` — returns content, auto-detect text vs binary
  - `file_info(project_id, path)` — file(1) magic, size, hashes, ELF headers if applicable
  - `search_files(project_id, pattern, path)` — glob search
- All paths MUST be validated against the extracted filesystem root (path traversal prevention!)
- Create `app/routers/files.py` with the REST endpoints
- Use `python-magic` for file type detection
- Use `pyelftools` for basic ELF header parsing

**Security Critical:**
```python
def validate_path(extracted_root: str, requested_path: str) -> str:
    """Resolve and validate that path stays within extracted_root."""
    full_path = os.path.realpath(os.path.join(extracted_root, requested_path.lstrip("/")))
    if not full_path.startswith(os.path.realpath(extracted_root)):
        raise HTTPException(403, "Path traversal detected")
    return full_path
```

**Definition of Done:**
- Can browse the unpacked filesystem via API
- Can read text files and get hex dumps of binary files
- Can get file info with magic type and ELF headers
- Path traversal is blocked

#### Session 1.5: Backend Dockerfile & Docker Compose

**Do:**
- Create `backend/Dockerfile`:
  - Base: `python:3.12-slim`
  - Install system deps: `binwalk`, `squashfs-tools`, `mtd-utils`, `e2fsprogs`, `cpio`, `p7zip-full`, `file`, `libmagic1`, `radare2`
  - Install sasquatch (non-standard SquashFS)
  - Install Python deps via uv
  - Run uvicorn
- Update `docker-compose.yml`:
  - `backend` service with volume mounts for firmware storage
  - `postgres` service with persistent volume
  - `redis` service
  - Shared network
  - Environment variables from `.env`
- Create `.env.example`
- Create `scripts/setup.sh` for first-time initialization

**Definition of Done:**
- `docker-compose up` starts all services
- Can hit API endpoints from host machine
- Firmware upload + unpack + browse works end-to-end in containers

---

### Phase 2: Frontend Foundation (Sessions 6–9)

**Goal:** Working React frontend with project management, file explorer, and file viewer.

#### Session 2.1: Frontend Scaffold

**Do:**
- Initialize React + Vite + TypeScript project in `frontend/`
- Install: `tailwindcss`, `@shadcn/ui`, `react-router-dom`, `zustand`, `axios`
- Set up Tailwind + shadcn/ui
- Create `AppLayout` with sidebar navigation and main content area
- Create routing: `/projects`, `/projects/:id`, `/projects/:id/explore`
- Create API client base in `src/api/` with axios instance (configurable base URL)
- Create `frontend/Dockerfile` (node:20-slim, build + serve with nginx or just vite preview for dev)

**Definition of Done:**
- Frontend builds and serves
- Layout renders with sidebar and routing works
- API client can hit the backend (CORS working)

#### Session 2.2: Project Dashboard

**Do:**
- Create `projectStore.ts` (Zustand) for project state
- Create `ProjectList.tsx` — grid of project cards
- Create `ProjectCard.tsx` — shows name, firmware info, status, created date
- Create project creation dialog/modal
- Create `FirmwareUpload.tsx` — drag-and-drop file upload with progress bar
- Wire up: create project → upload firmware → trigger unpack → show status
- Add loading states and error handling

**Definition of Done:**
- Can create projects, upload firmware, and see status update to "ready"
- Project list shows all projects with metadata
- Upload shows progress

#### Session 2.3: File Explorer

**Do:**
- Install `react-arborist` for the tree component
- Create `FileTree.tsx`:
  - Lazy-loads directory contents on expand
  - Icons for different file types (folder, binary, script, config, certificate, etc.)
  - Shows file size
  - Click to select and view file
- Create `explorerStore.ts` — selected path, tree state, current file content
- Create `FileViewer.tsx`:
  - Detects file type and renders appropriately
  - Text files: syntax-highlighted code view (Monaco)
  - Binary files: hex dump view
  - Images: inline preview (if applicable)
  - Config files: highlighted with warnings for insecure patterns
- Create `BinaryInfo.tsx` — shows ELF headers, architecture, protections for binaries

**Definition of Done:**
- Can browse the full unpacked filesystem
- Directories expand lazily
- Clicking a file shows its contents appropriately
- Binary files show hex view + ELF info

#### Session 2.4: Monaco Editor Integration

**Do:**
- Install `@monaco-editor/react`
- Configure Monaco for the file viewer:
  - Language detection based on file extension/magic
  - Read-only mode
  - Line numbers
  - Search functionality (Ctrl+F)
- Create `HexViewer.tsx`:
  - Classic hex view: offset | hex bytes | ASCII
  - Pagination for large files (load in 4KB chunks)
  - Highlight selection in both hex and ASCII panes
- Wire up file viewer to switch between text/hex based on file type
- Support viewing disassembly output (will be used later for binary analysis)

**Definition of Done:**
- Text files render with syntax highlighting in Monaco
- Binary files show proper hex view
- Can navigate large files
- Search works within files

---

### Phase 3: AI Chat Integration (Sessions 10–14)

**Goal:** Working AI chat panel with Claude tool-use loop, streaming, and first set of tools.

#### Session 3.1: Tool Registry & Handler Framework

**Do:**
- Create `app/ai/tool_registry.py`:
  ```python
  class ToolRegistry:
      def __init__(self):
          self._tools: dict[str, ToolDefinition] = {}

      def register(self, name: str, description: str, parameters: dict, handler: Callable):
          """Register a tool with its Anthropic API schema and handler function."""

      def get_anthropic_tools(self) -> list[dict]:
          """Return tool definitions in Anthropic API format."""

      async def execute(self, name: str, input: dict, context: ToolContext) -> str:
          """Execute a tool and return its string result."""
  ```
- Create `ToolContext` dataclass holding project_id, firmware_id, extracted_path, db_session
- Implement `app/ai/tools/filesystem.py`:
  - `list_directory` tool
  - `read_file` tool
  - `file_info` tool
  - `search_files` tool
  - `find_files_by_type` tool
- Each tool handler validates paths, calls the file_service, and formats output as a concise string
- Implement output truncation utility (`app/utils/truncation.py`):
  - Max output size per tool call: 30KB
  - Truncate with: `"... [truncated, showing {n} of {total} items]"`

**Definition of Done:**
- Tool registry can register and execute tools
- Filesystem tools work correctly against an unpacked firmware
- Output is properly truncated for large results
- Tool definitions serialize to valid Anthropic API format

#### Session 3.2: AI Orchestrator — Tool-Use Loop

**Do:**
- Create `app/ai/orchestrator.py`:
  ```python
  class AIOrchestrator:
      async def run_conversation(
          self,
          messages: list[dict],
          project_context: ProjectContext,
          on_event: Callable[[dict], Awaitable[None]]  # streaming callback
      ) -> list[dict]:  # returns updated messages array
  ```
- Implement the core loop:
  1. Call Anthropic API with messages + tools (streaming)
  2. Stream text blocks to callback as `assistant_text` events
  3. When `tool_use` block received, emit `tool_call` event
  4. Execute tool via registry
  5. Emit `tool_result` event
  6. Append tool result to messages, loop back to step 1
  7. When Claude returns `end_turn` with no tool use, emit `done` event
- Handle errors: tool execution failures become tool_result with error message
- Implement max iterations guard (default 25 tool calls per turn)
- Create `app/ai/system_prompt.py` with the system prompt template

**Definition of Done:**
- Orchestrator correctly loops through multi-step tool use
- Streaming events are emitted in order
- Errors in tool execution don't crash the loop
- Max iteration guard prevents infinite loops

#### Session 3.3: WebSocket Chat Endpoint

**Do:**
- Create `app/routers/chat.py`:
  - `WS /api/v1/projects/{id}/conversations/{cid}/ws`
  - On connect: load conversation messages from DB
  - On user message: append to messages, run orchestrator, stream events to WS
  - On orchestrator complete: save updated messages to DB
  - Handle disconnection gracefully (cancel in-progress API calls)
- Create conversation REST endpoints:
  - `POST /api/v1/projects/{id}/conversations` — create new
  - `GET /api/v1/projects/{id}/conversations` — list
  - `GET /api/v1/projects/{id}/conversations/{cid}` — get with messages
- Add conversations and their messages table/schema if not already done

**Definition of Done:**
- Can open WebSocket connection and send a message
- Receive streaming events: text deltas, tool calls, tool results, done
- Conversation persists in database between connections
- Reconnecting loads conversation history

#### Session 3.4: Chat Frontend Panel

**Do:**
- Create `chatStore.ts` (Zustand):
  - Current conversation state
  - Messages array (rendered format, not raw API format)
  - Connection status
  - Streaming state
- Create `useWebSocket.ts` hook:
  - Connect/disconnect lifecycle
  - Message parsing and dispatching to store
  - Reconnection logic
- Create `ChatPanel.tsx`:
  - Collapsible side panel (right side, resizable)
  - Message list with auto-scroll
  - Input field with send button and Shift+Enter for newlines
- Create `ChatMessage.tsx`:
  - User messages: simple bubble
  - Assistant messages: rendered markdown (use a lightweight md renderer)
  - Tool calls: collapsible blocks showing tool name, input (JSON), and output
- Create `ToolCallBlock.tsx`:
  - Collapsed: shows tool name and brief status (success/error)
  - Expanded: shows full input parameters and output
  - Color-coded: blue for tool call, green for success, red for error

**Definition of Done:**
- Chat panel opens and connects via WebSocket
- Can send messages and see streaming responses
- Tool calls render as collapsible blocks
- Conversation history loads on reconnect

#### Session 3.5: String & File Search Tools

**Do:**
- Implement `app/ai/tools/strings.py`:
  - `extract_strings` — run `strings` binary, then categorize (URLs, IPs, emails, file paths, potential credentials)
  - `search_strings` — grep/ripgrep across filesystem
  - `find_crypto_material` — scan for PEM headers, `.pem`/`.key`/`.crt` files, SSH keys
  - `find_hardcoded_credentials` — regex patterns for passwords, API keys, tokens; entropy analysis for high-entropy strings
- Register all new tools in the registry
- Test with real firmware: the AI should be able to find interesting strings and credentials

**Definition of Done:**
- AI can ask to extract strings from a binary and get categorized results
- AI can grep across the filesystem
- Crypto material detection finds certificates and keys
- Credential detection has reasonable signal-to-noise ratio

---

### Phase 4: Binary Analysis (Sessions 15–19)

**Goal:** Full binary analysis capability via radare2 and Ghidra.

#### Session 4.1: Radare2 Integration

**Do:**
- Install `r2pipe` Python package
- Create `app/services/analysis_service.py` with r2pipe wrapper:
  ```python
  class R2Session:
      """Manages a radare2 session for a binary."""
      def __init__(self, binary_path: str):
          self.r2 = r2pipe.open(binary_path)
          self.r2.cmd("aaa")  # full analysis

      def list_functions(self) -> list[dict]
      def disassemble_function(self, name: str, max_insn: int) -> str
      def get_imports(self) -> list[dict]
      def get_exports(self) -> list[dict]
      def get_xrefs_to(self, target: str) -> list[dict]
      def get_xrefs_from(self, target: str) -> list[dict]
      def get_binary_info(self) -> dict
  ```
- Implement session caching (keep r2 sessions open for recently analyzed binaries, with an LRU eviction)
- Handle r2 analysis timeout (some binaries take a long time — cap at 60s)

**Definition of Done:**
- Can analyze an ELF binary and list functions
- Disassembly output is clean and readable
- Import/export listing works
- Cross-references resolve correctly
- Session caching prevents re-analysis on repeated queries

#### Session 4.2: Binary Analysis AI Tools

**Do:**
- Implement `app/ai/tools/binary.py`:
  - `list_functions` — with sizes, sorted by size (large custom functions are often interesting)
  - `disassemble_function` — clean output with annotations
  - `list_imports` — grouped by library
  - `list_exports`
  - `xrefs_to` and `xrefs_from`
  - `get_binary_info` — architecture, linked libs, sections, entry point
- Register all tools
- Add `check_binary_protections` tool in `tools/security.py`:
  - Check NX (GNU_STACK segment)
  - Check RELRO (DYNAMIC segment)
  - Check stack canaries (imports `__stack_chk_fail`)
  - Check PIE (ELF type == DYN)
  - Check Fortify (`__*_chk` variants in imports)

**Definition of Done:**
- AI can fully investigate a binary: list functions, disassemble interesting ones, trace imports
- AI correctly identifies security-relevant functions (e.g., `system()`, `strcpy()`, network calls)
- Binary protection checks produce accurate results matching checksec

#### Session 4.3: Ghidra Headless Decompilation

**Do:**
- Create `ghidra/Dockerfile`:
  - Install OpenJDK 17
  - Download and extract Ghidra (latest stable)
  - Copy custom scripts to Ghidra's script directory
- Create `ghidra/scripts/DecompileFunction.java`:
  - Takes binary path and function name as arguments
  - Runs auto-analysis
  - Decompiles the function
  - Outputs pseudo-C to stdout
- Create decompilation service in backend:
  - Runs Ghidra headless via subprocess
  - Caches results in `analysis_cache` table (keyed by binary_sha256 + function_name)
  - Timeout: 120s per decompilation
- Add `decompile_function` tool to AI tools
- Update docker-compose to include Ghidra container (or run in backend container)

**Definition of Done:**
- Can decompile a function from an ELF binary and get readable pseudo-C
- Results are cached — second request is instant
- Ghidra container builds and runs headlessly
- AI can request decompilation and use the output in its analysis

#### Session 4.4: Security Assessment Tools

**Do:**
- Implement `app/ai/tools/security.py` (remaining tools):
  - `check_known_cves` — query a local CVE database or the NVD API by component name + version
  - `analyze_config_security` — parse common config files for insecure settings:
    - `/etc/shadow` — empty passwords, weak hashes
    - `/etc/passwd` — UID 0 accounts
    - `sshd_config` — root login, password auth
    - `httpd.conf` / `lighttpd.conf` — directory listing, default creds
    - `iptables` rules — overly permissive
  - `check_setuid_binaries` — find setuid/setgid files
  - `analyze_init_scripts` — parse init.d, inittab, systemd units for services
  - `check_filesystem_permissions` — world-writable files, sensitive files with bad perms
- Register all tools

**Definition of Done:**
- AI can run a comprehensive security assessment using all available tools
- Findings are accurate and actionable
- False positive rate is reasonable

#### Session 4.5: Frontend Binary Viewer Enhancements

**Do:**
- Update `BinaryInfo.tsx`:
  - Show full binary protection status with color coding
  - Show imports/exports in expandable sections
  - Show function list with search/filter
- Add disassembly view in `FileViewer.tsx`:
  - When viewing a binary, show a "Functions" panel
  - Click a function to see its disassembly in Monaco (assembly syntax highlighting)
  - Button to request decompilation → shows pseudo-C
- Add ability to right-click a file in the tree and "Ask AI about this file"

**Definition of Done:**
- Binary files show protection status, imports, exports, function list
- Can view disassembly and decompiled code inline
- Can trigger AI analysis from the file explorer

---

### Phase 5: Findings & Reporting (Sessions 20–22)

**Goal:** Structured findings management and report export.

#### Session 5.1: Findings Backend & Frontend

**Do:**
- Create `app/routers/findings.py` — full CRUD REST endpoints
- Create `FindingsList.tsx`:
  - Table view with columns: severity, title, file, status
  - Sortable and filterable
  - Color-coded severity badges
- Create `FindingDetail.tsx`:
  - Full finding view with description, evidence, affected file
  - Click file path to navigate to it in the explorer
  - Status management (confirm, false positive, etc.)
- AI-created findings (via `add_finding` tool) appear in real-time

**Definition of Done:**
- Findings from AI chat appear in the findings list immediately
- Can manually create, edit, and manage findings
- Filtering and sorting works

#### Session 5.2: Report Generation

**Do:**
- Create report export endpoint: `POST /api/v1/projects/{id}/findings/export`
- Support formats: Markdown and PDF (use `weasyprint` or `reportlab`)
- Report structure:
  1. Executive summary (auto-generated from findings)
  2. Firmware information (architecture, components, etc.)
  3. Findings by severity (critical → info)
  4. Each finding with description, evidence, remediation suggestion
  5. Appendix: file listing, binary protections matrix
- Create `ReportExport.tsx` — export button with format selection

**Definition of Done:**
- Can export a professional-looking security assessment report
- Report includes all findings with evidence
- Both Markdown and PDF formats work

---

### Phase 6: Polish & Release (Sessions 23–26)

#### Session 6.1: Background Tasks & Status

**Do:**
- Set up `arq` worker with Redis
- Move firmware unpacking to background worker
- Add real-time status updates via WebSocket or polling
- Add progress indicators for long-running operations (Ghidra analysis, full scan)

#### Session 6.2: Error Handling & Edge Cases

**Do:**
- Handle: corrupt firmware, unsupported formats, very large files, empty filesystems
- Add request validation everywhere
- Add rate limiting on API endpoints
- Add graceful shutdown handling
- Comprehensive error messages for users

#### Session 6.3: Documentation & Testing

**Do:**
- Write comprehensive `README.md`:
  - Quick start guide
  - Docker deployment instructions
  - Configuration reference
  - Screenshot gallery
  - Contributing guide
- Write API documentation (FastAPI auto-generates OpenAPI, but add descriptions)
- Add integration tests for critical paths:
  - Upload → unpack → browse → AI analysis → finding creation
- Add example firmware images for testing (OpenWrt, DD-WRT, etc.)

#### Session 6.4: Final Integration & Release

**Do:**
- End-to-end testing of full workflow
- Performance profiling and optimization
- Security review of the application itself (ironic but important)
- Create GitHub release with docker-compose one-liner for easy deployment
- Create demo video/screenshots for README

---

## Important Implementation Notes

### Security (of the tool itself)

1. **Path traversal prevention** is critical. Every file access must be validated against the extracted root.
2. **The worker container should be sandboxed.** Firmware may contain hostile files. Consider:
   - No network access for the worker
   - Resource limits (CPU, memory, disk)
   - Non-root execution
   - Read-only bind mounts where possible
3. **Never execute binaries from the firmware.** Analysis only, no running extracted code.
4. **Anthropic API key** should be user-provided or stored securely (not in the image).

### Performance

1. **Cache Ghidra decompilations** — they take 30-120s. Cache by binary hash + function name.
2. **Cache r2 analysis** — keep open sessions with LRU eviction (r2 `aaa` can take 10-30s).
3. **Lazy-load the file tree** — firmware can have 10K+ files. Load on expand, not all at once.
4. **Truncate AI tool outputs** — Claude's context window is valuable. Keep tool outputs under 30KB.
5. **Stream AI responses** — don't wait for the full response before showing text to the user.

### AI Prompt Engineering Tips

1. **Be specific in tool descriptions.** Tell Claude exactly what each tool returns and its limitations.
2. **Include firmware context** in the system prompt: architecture, OS version, known components.
3. **Encourage methodology.** The system prompt should guide Claude to be systematic rather than random.
4. **Handle "I don't know" gracefully.** Claude should say when it's unsure rather than hallucinating.
5. **Limit tool output verbosity.** Return pre-processed, relevant data — not raw dumps.

### Testing Firmware Sources

Good test firmware for development (all open source):
- **OpenWrt** images (MIPS, ARM) — well-structured, lots of components
- **DD-WRT** — similar to OpenWrt
- **Raspberry Pi OS** — ARM-based Linux
- Damn Vulnerable Router Firmware (DVRF) — intentionally vulnerable

---

## Environment Variables

```bash
# .env.example
DATABASE_URL=postgresql+asyncpg://wairz:wairz@postgres:5432/wairz
REDIS_URL=redis://redis:6379/0
ANTHROPIC_API_KEY=sk-ant-...
STORAGE_ROOT=/data/firmware
MAX_UPLOAD_SIZE_MB=500
MAX_TOOL_OUTPUT_KB=30
MAX_TOOL_ITERATIONS=25
GHIDRA_PATH=/opt/ghidra
LOG_LEVEL=INFO
```

---

## Claude Code Session Tips

- **Start each session by reading this file** to understand context.
- **One service or component per session** works best — don't try to build everything at once.
- **Test incrementally.** After each session, verify the new functionality works with the existing system.
- **Use the session definitions above** as your task scope — they're designed to be completable in a single session.
- **If a session is too large**, split it. It's better to commit working code for half a session than broken code for a full one.
- **Always validate file paths.** This is a security tool analyzing untrusted firmware — the tool itself must be secure.
