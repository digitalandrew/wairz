# CLAUDE.md — Wairz: AI-Assisted Firmware Reverse Engineering & Security Assessment Tool

**Project Name:** Wairz
**Domain:** wairz.ai
**Repository:** [github.com/digitalandrew/wairz](https://github.com/digitalandrew/wairz)

## Project Overview

Wairz is an open-source, browser-based firmware reverse engineering and security assessment platform. Users upload firmware images, the tool unpacks them, and provides a unified interface for exploring the filesystem, viewing/analyzing files, reverse engineering binaries, and conducting security assessments — all augmented by an AI assistant (Claude) that connects via MCP (Model Context Protocol) to autonomously run tools, inspect files, and generate findings.

**Target for v1:** Embedded Linux firmware (SquashFS, JFFS2, UBIFS, CramFS, ext, CPIO).
**Future:** RTOS and bare-metal firmware support.

---

## Architecture

```
Claude Code / Claude Desktop
        │
        │ MCP (stdio)
        ▼
┌─────────────────┐     ┌──────────────────────────────────┐
│   wairz-mcp     │────▶│         FastAPI Backend           │
│  (MCP server)   │     │                                    │
│                 │     │  ┌────────────┐ ┌──────────────┐  │
│  - 40+ tools   │     │  │ Firmware   │ │ Analysis     │  │
│  - resources   │     │  │ Service    │ │ Service      │  │
│  - prompts     │     │  │ - upload   │ │ - strings    │  │
│                 │     │  │ - unpack   │ │ - binwalk    │  │
│  Entry point:  │     │  │ - fs tree  │ │ - radare2    │  │
│  wairz-mcp CLI │     │  │ - file I/O │ │ - Ghidra     │  │
└─────────────────┘     │  └────────────┘ └──────────────┘  │
                        │                                    │
                        │  ┌──────────────────────────────┐  │
                        │  │ Tool Registry                 │  │
                        │  │ Maps tool names → handlers    │  │
                        │  │ Validates inputs, sandboxing  │  │
                        │  └──────────────────────────────┘  │
                        └──────────┬───────────────────────┘
                                   │
┌──────────────┐    ┌──────────────┼──────────────┐
│   React SPA  │───▶│  PostgreSQL  │  QEMU        │
│  (Frontend)  │    │  - projects  │  (Emulation   │
│  - Dashboard │    │  - metadata  │   Container)  │
│  - Explorer  │    │  - findings  │              │
│  - SBOM view │    │  - cache     │              │
│  - Emulation │    │  - SBOM      │              │
└──────────────┘    └──────────────┴──────────────┘
```

**How it works:**
1. Users upload firmware via the web UI (React SPA → FastAPI REST API)
2. Backend unpacks firmware, stores metadata in PostgreSQL, filesystem on disk
3. Users browse files, view findings, manage SBOM, and run emulation via the web UI
4. AI analysis is done via Claude Code or Claude Desktop connected through MCP:
   ```bash
   claude mcp add wairz -- docker exec -i wairz-backend-1 uv run wairz-mcp --project-id <PROJECT_ID>
   ```
5. Claude gets access to 40+ tools (filesystem, binary analysis, security checks, SBOM, emulation, findings) and can autonomously investigate the firmware

---

## Tech Stack

| Layer | Technology | Notes |
|---|---|---|
| Frontend | React 18 + Vite + TypeScript | SPA, no SSR needed |
| UI Components | shadcn/ui + Tailwind CSS | Clean, accessible components |
| Code Viewer | Monaco Editor | Hex view, disassembly, config files |
| File Tree | react-arborist | Virtual tree for large filesystems |
| Graph Viz | @xyflow/react (ReactFlow) | Component dependency map |
| Backend | Python 3.12 + FastAPI | Async, WebSocket support |
| AI Integration | MCP server (stdio) | `wairz-mcp` CLI entry point, `mcp[cli]>=1.2.0` |
| Database | PostgreSQL 16 | JSONB for analysis cache, standard relational for rest |
| Migrations | Alembic | Schema versioning |
| ORM | SQLAlchemy 2.0 (async) | Mapped classes, async sessions |
| RE: Unpacking | binwalk, sasquatch, jefferson, ubi_reader, cramfs-tools | Filesystem extraction |
| RE: Binary | radare2 (r2pipe), pyelftools | Disassembly, ELF parsing |
| RE: Decompile | Ghidra headless (via analyzeHeadless) | Pseudo-C decompilation |
| Emulation | QEMU (user-mode + system-mode) | ARM, MIPS, x86 in isolated container |
| SBOM | cyclonedx-python-lib, packageurl-python | CycloneDX SBOM generation, PURL identifiers |
| CVE Lookup | nvdlib | NVD API client for known vulnerability queries |
| Containers | Docker + Docker Compose | Local self-hosted deployment |
| Testing | pytest (backend), Vitest (frontend) | Unit + integration |

---

## Directory Structure

```
wairz/
├── CLAUDE.md                    # This file
├── README.md
├── LICENSE
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
│   │   │   └── emulation.ts
│   │   ├── components/
│   │   │   ├── layout/          # AppLayout, Sidebar, Header
│   │   │   ├── projects/        # ProjectList, ProjectCard, FirmwareUpload
│   │   │   ├── explorer/        # FileTree, FileViewer, HexViewer, BinaryInfo
│   │   │   ├── component-map/   # ComponentMap (ReactFlow), ComponentNode, MapControls
│   │   │   └── findings/        # FindingsList, FindingDetail, ReportExport
│   │   ├── hooks/               # useProject, useFileTree
│   │   ├── pages/               # EmulationPage, SbomPage, etc.
│   │   ├── stores/              # Zustand stores (project, explorer, emulation, componentMap)
│   │   ├── types/
│   │   │   └── index.ts
│   │   └── utils/
│   │       └── format.ts
│   └── Dockerfile
│
├── backend/
│   ├── pyproject.toml           # uv, entry point: wairz-mcp
│   ├── alembic.ini
│   ├── alembic/
│   │   └── versions/
│   ├── app/
│   │   ├── __init__.py
│   │   ├── main.py              # FastAPI app, mount routers
│   │   ├── config.py            # Settings via pydantic-settings
│   │   ├── database.py          # Async SQLAlchemy engine/session
│   │   ├── mcp_server.py        # MCP server — exposes tools/resources/prompts via stdio
│   │   ├── models/              # SQLAlchemy ORM models
│   │   │   ├── project.py
│   │   │   ├── firmware.py
│   │   │   ├── finding.py
│   │   │   ├── analysis_cache.py
│   │   │   ├── emulation_session.py
│   │   │   └── sbom.py          # SbomComponent, SbomVulnerability
│   │   ├── schemas/             # Pydantic request/response schemas
│   │   │   ├── project.py
│   │   │   ├── firmware.py
│   │   │   ├── finding.py
│   │   │   ├── emulation.py
│   │   │   └── sbom.py
│   │   ├── routers/             # FastAPI REST routers
│   │   │   ├── projects.py
│   │   │   ├── firmware.py      # Upload + unpack
│   │   │   ├── files.py         # File explorer
│   │   │   ├── analysis.py      # Binary analysis (strings, disasm, decompile)
│   │   │   ├── component_map.py # Dependency graph
│   │   │   ├── findings.py      # Finding CRUD + report export
│   │   │   ├── documents.py     # Project documents/notes
│   │   │   ├── sbom.py          # SBOM generation & vulnerability scan
│   │   │   ├── emulation.py     # Emulation start/stop/exec
│   │   │   ├── terminal.py      # WebSocket PTY to firmware filesystem
│   │   │   └── kernels.py       # Kernel management for emulation
│   │   ├── services/            # Business logic
│   │   │   ├── firmware_service.py
│   │   │   ├── file_service.py
│   │   │   ├── analysis_service.py
│   │   │   ├── component_map_service.py
│   │   │   ├── code_cleanup_service.py
│   │   │   ├── sbom_service.py
│   │   │   ├── vulnerability_service.py
│   │   │   ├── emulation_service.py
│   │   │   └── finding_service.py
│   │   ├── ai/                  # Tool registry + tool implementations (used by MCP server)
│   │   │   ├── __init__.py      # Creates tool registry with all tools
│   │   │   ├── tool_registry.py # Tool registration and execution framework
│   │   │   ├── system_prompt.py # Firmware analysis system prompt (exposed as MCP prompt)
│   │   │   └── tools/           # Individual tool handler modules
│   │   │       ├── filesystem.py
│   │   │       ├── strings.py
│   │   │       ├── binary.py
│   │   │       ├── security.py
│   │   │       ├── sbom.py
│   │   │       ├── emulation.py
│   │   │       ├── documents.py
│   │   │       └── reporting.py
│   │   └── utils/
│   │       ├── sandbox.py       # Path traversal prevention
│   │       └── truncation.py    # Output truncation
│   ├── tests/
│   └── Dockerfile
│
├── ghidra/
│   ├── Dockerfile               # Ghidra headless container
│   └── scripts/
│       └── DecompileFunction.java
│
├── emulation/
│   ├── Dockerfile               # QEMU emulation container
│   ├── kernels/                 # Pre-built Linux kernels (ARM, MIPS, MIPSel)
│   └── scripts/
│       ├── start-user-mode.sh   # chroot + qemu-user-static
│       ├── start-system-mode.sh # QEMU system-mode boot
│       └── serial-exec.sh       # Serial console command exec with marker-based output capture
│
└── scripts/
    ├── setup.sh
    └── test-firmware/
```

---

## MCP Server

The AI integration uses MCP (Model Context Protocol). The backend exposes a `wairz-mcp` CLI command that runs an MCP server over stdio.

**Entry point:** `wairz-mcp = "app.mcp_server:main"` (registered in pyproject.toml)

**Usage:**
```bash
# Register with Claude Code
claude mcp add wairz -- docker exec -i wairz-backend-1 uv run wairz-mcp --project-id <PROJECT_ID>

# Or run directly
uv run wairz-mcp --project-id <PROJECT_ID>
```

**Capabilities:**
- **Tools (40+):** All tools from `app/ai/tools/` are exposed as MCP tools — filesystem browsing, string analysis, binary analysis (r2pipe + Ghidra), security checks, SBOM generation, CVE lookup, emulation control, finding management
- **Resources:** Project and firmware metadata exposed as MCP resources
- **Prompts:** Firmware analysis system prompt with project context

**Tool categories:**
- Filesystem: `list_directory`, `read_file`, `search_files`, `file_info`, `find_files_by_type`
- Strings: `extract_strings`, `search_strings`, `find_crypto_material`, `find_hardcoded_credentials`
- Binary: `list_functions`, `disassemble_function`, `decompile_function`, `list_imports`, `list_exports`, `xrefs_to`, `xrefs_from`, `get_binary_info`
- Security: `check_binary_protections`, `check_known_cves`, `analyze_config_security`, `check_setuid_binaries`, `analyze_init_scripts`, `check_filesystem_permissions`
- SBOM: `generate_sbom`, `get_sbom_components`, `check_component_cves`, `run_vulnerability_scan`
- Emulation: `start_emulation`, `run_command_in_emulation`, `stop_emulation`, `check_emulation_status`
- Reporting: `add_finding`, `list_findings`, `update_finding`
- Code: `cleanup_decompiled_code`, `save_code_cleanup`
- UART: `uart_connect`, `uart_send_command`, `uart_read`, `uart_send_break`, `uart_send_raw`, `uart_disconnect`, `uart_status`, `uart_get_transcript`

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
    storage_path VARCHAR(512),
    extracted_path VARCHAR(512),
    architecture VARCHAR(50),
    endianness VARCHAR(10),
    os_info TEXT,
    unpack_log TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Security findings
CREATE TABLE findings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id UUID REFERENCES projects(id) ON DELETE CASCADE,
    conversation_id UUID REFERENCES conversations(id),
    title VARCHAR(255) NOT NULL,
    severity VARCHAR(20) NOT NULL,     -- critical, high, medium, low, info
    description TEXT,
    evidence TEXT,
    file_path VARCHAR(512),
    line_number INTEGER,
    cve_ids TEXT[],
    cwe_ids TEXT[],
    status VARCHAR(20) DEFAULT 'open', -- open, confirmed, false_positive, fixed
    source VARCHAR(50) DEFAULT 'manual', -- manual, ai_discovered, sbom_scan, fuzzing, security_review
    component_id UUID,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Analysis cache (avoid re-running expensive operations)
CREATE TABLE analysis_cache (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    firmware_id UUID REFERENCES firmware(id) ON DELETE CASCADE,
    binary_path VARCHAR(512),
    binary_sha256 VARCHAR(64),
    operation VARCHAR(100),
    result JSONB,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Emulation sessions (QEMU user-mode and system-mode)
CREATE TABLE emulation_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id UUID REFERENCES projects(id) ON DELETE CASCADE,
    firmware_id UUID REFERENCES firmware(id) ON DELETE CASCADE,
    mode VARCHAR(20) NOT NULL,            -- 'user' or 'system'
    status VARCHAR(20) DEFAULT 'created', -- created, starting, running, stopped, error
    binary_path VARCHAR(512),
    arguments TEXT,
    architecture VARCHAR(50),
    port_forwards JSONB DEFAULT '[]',
    container_id VARCHAR(100),
    pid INTEGER,
    error_message TEXT,
    started_at TIMESTAMPTZ,
    stopped_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- SBOM components identified from firmware filesystem
CREATE TABLE sbom_components (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    firmware_id UUID REFERENCES firmware(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    version VARCHAR(100),
    type VARCHAR(50) NOT NULL,               -- 'application', 'library', 'firmware', 'operating-system'
    cpe VARCHAR(255),
    purl VARCHAR(512),
    supplier VARCHAR(255),
    detection_source VARCHAR(100) NOT NULL,  -- 'package_manager', 'binary_strings', 'library_soname', 'kernel_modules', 'config_file'
    detection_confidence VARCHAR(20),
    file_paths TEXT[],
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Vulnerability matches from CVE lookup
CREATE TABLE sbom_vulnerabilities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    component_id UUID REFERENCES sbom_components(id) ON DELETE CASCADE,
    firmware_id UUID REFERENCES firmware(id) ON DELETE CASCADE,
    cve_id VARCHAR(20) NOT NULL,
    cvss_score DECIMAL(3,1),
    cvss_vector VARCHAR(255),
    severity VARCHAR(20) NOT NULL,
    description TEXT,
    published_date TIMESTAMPTZ,
    finding_id UUID REFERENCES findings(id),
    created_at TIMESTAMPTZ DEFAULT NOW()
);
```

---

## API Endpoints

### REST Endpoints

```
# Projects
POST   /api/v1/projects
GET    /api/v1/projects
GET    /api/v1/projects/{id}
DELETE /api/v1/projects/{id}

# Firmware
POST   /api/v1/projects/{id}/firmware        # Upload (multipart)
GET    /api/v1/projects/{id}/firmware
POST   /api/v1/projects/{id}/firmware/unpack

# File Explorer
GET    /api/v1/projects/{id}/files?path=
GET    /api/v1/projects/{id}/files/read?path=&offset=&length=
GET    /api/v1/projects/{id}/files/info?path=
GET    /api/v1/projects/{id}/files/download?path=

# Analysis
GET    /api/v1/projects/{id}/analysis/strings?path=
GET    /api/v1/projects/{id}/analysis/binary-info?path=
GET    /api/v1/projects/{id}/analysis/functions?path=
GET    /api/v1/projects/{id}/analysis/disasm?path=&function=
POST   /api/v1/projects/{id}/analysis/cleanup  # AI code cleanup

# Component Map
GET    /api/v1/projects/{id}/component-map

# SBOM & Vulnerability Scanning
POST   /api/v1/projects/{id}/sbom/generate
GET    /api/v1/projects/{id}/sbom
GET    /api/v1/projects/{id}/sbom/export?format=
POST   /api/v1/projects/{id}/sbom/vulnerabilities/scan
GET    /api/v1/projects/{id}/sbom/vulnerabilities
GET    /api/v1/projects/{id}/sbom/vulnerabilities/summary

# Emulation
POST   /api/v1/projects/{id}/emulation/start
POST   /api/v1/projects/{id}/emulation/{sid}/stop
POST   /api/v1/projects/{id}/emulation/{sid}/exec
GET    /api/v1/projects/{id}/emulation/sessions
GET    /api/v1/projects/{id}/emulation/{sid}/status

# Findings
GET    /api/v1/projects/{id}/findings
POST   /api/v1/projects/{id}/findings
PATCH  /api/v1/projects/{id}/findings/{fid}
DELETE /api/v1/projects/{id}/findings/{fid}
POST   /api/v1/projects/{id}/findings/export

# Documents
GET    /api/v1/projects/{id}/documents
POST   /api/v1/projects/{id}/documents
PATCH  /api/v1/projects/{id}/documents/{did}
DELETE /api/v1/projects/{id}/documents/{did}
```

### WebSocket Endpoints

```
WS /api/v1/projects/{id}/terminal              # PTY shell to firmware filesystem
WS /api/v1/projects/{id}/emulation/{sid}/terminal  # Interactive terminal to emulated system
```

---

## Completed Development Phases

### Phase 1: Foundation — Backend Scaffold (Sessions 1–5)

Working backend with project CRUD, firmware upload, unpacking, and file browsing. FastAPI + async SQLAlchemy + Alembic + docker-compose (postgres + redis). Firmware unpacking via binwalk with architecture/endianness detection. File explorer API with path traversal prevention. Backend Dockerfile.

### Phase 2: Frontend Foundation (Sessions 6–9)

React + Vite + TypeScript SPA with Tailwind + shadcn/ui. Project dashboard with Zustand state management. File explorer with react-arborist (lazy-load). Monaco editor with syntax highlighting and hex viewer.

### Phase 3: AI Chat Integration (Sessions 10–14)

Tool registry framework with filesystem and string analysis tools (list_directory, read_file, search_files, extract_strings, find_crypto_material, find_hardcoded_credentials). Output truncation (30KB max). Originally built with WebSocket chat + Anthropic API orchestrator; later migrated to MCP-only architecture.

### Phase 4: Binary Analysis (Sessions 15–19)

Radare2 integration via r2pipe with LRU session caching. Binary tools: list_functions, disassemble_function, list_imports/exports, xrefs, get_binary_info, check_binary_protections. Ghidra headless decompilation cached by binary_sha256 + function_name. Security tools: CVE checking, config analysis, setuid scanning, init script analysis, filesystem permissions. Frontend binary viewer with protections display, function list, and disassembly/decompile views.

### Phase 5: Findings & Reporting (Sessions 20–22)

Findings CRUD backend + frontend with sortable/filterable table, severity badges, evidence display, file navigation, status management. Report export in Markdown + PDF formats.

### Phase 6: Firmware Component Map (Sessions 23–25)

Component dependency graph: ELF DT_NEEDED parsing, imported functions per library, shell script calls, init script→service mapping, config→binary references. ReactFlow canvas with dagre layout, typed/colored nodes (binary=blue, library=purple, script=green, config=orange, init=yellow, kernel_module=red). Cluster collapsing for large graphs, PNG/SVG/JSON export.

### Phase 7: AI Decompiled Code Clean-up (Sessions 26–27)

Claude API-powered cleanup of Ghidra decompiled code: variable/function renaming, inline comments, security annotations. Cached in analysis_cache. Frontend toggle between raw/cleaned views in Monaco.

### Phase 8: Firmware Emulation (Sessions 28–31)

QEMU emulation in isolated Docker container. User-mode (qemu-user-static + chroot for single binary execution) and system-mode (full OS boot with bundled kernels for ARM/MIPS/MIPSel). Emulation service with Docker SDK container management, session tracking in DB, auto-stop timeout, concurrent session limits. REST API for start/stop/exec, WebSocket terminal via xterm.js. Serial console command execution via marker-based output capture script (serial-exec.sh). Frontend EmulationPage with session controls, terminal, and session history. MCP tools for AI-driven dynamic analysis.

### Phase 9: SBOM & Known Vulnerability Look-Up (Sessions 32–34)

SBOM generation with 5+ detection strategies: package manager DBs, kernel version, library SONAME, binary version strings, config file hints, firmware OS fingerprinting (DD-WRT, Buildroot, Yocto, Android), known service risk classification. CPE 2.3 + PURL identifiers. CycloneDX JSON export. Vulnerability lookup via NVD (nvdlib) with rate limiting. Auto-creates findings with `source='sbom_scan'`. Frontend SbomPage with component table, severity dashboard, CVE table, and finding links.

### Architecture Migration: MCP-Only (Post Phase 9)

Removed built-in AI orchestrator (Anthropic API client, WebSocket chat endpoint, conversation streaming). Replaced with `wairz-mcp` MCP server exposing all tools via stdio transport. All tool implementations preserved in `app/ai/tools/`. Claude Code/Desktop connects directly via MCP for AI analysis.

---

## Future Development Phases

### Phase 10: Automated Fuzzing (Sessions 35–38)

**Goal:** Integrate AFL++ fuzzing into the emulation environment with AI assistance for target selection, harness/shim generation, and crash triage, enabling automated vulnerability discovery in firmware binaries.

#### Session 10.1: Fuzzing Infrastructure — AFL++ Integration

**Do:**
- Update `emulation/Dockerfile` (or create a dedicated `fuzzing/Dockerfile`):
  - Install AFL++ with QEMU mode support: `afl-fuzz`, `afl-qemu-trace`, `afl-cmin`, `afl-tmin`
  - Install cross-architecture compilers for instrumented builds: `gcc-arm-linux-gnueabi`, `gcc-mipsel-linux-gnu` (if re-compilation is feasible)
  - Install crash analysis tools: `gdb-multiarch`, `exploitable` (GDB plugin)
  - Install `afl-utils` for crash deduplication and triage
- Create `app/services/fuzzing_service.py`:
  - `FuzzingService` class:
    - `analyze_target(project_id, binary_path)` — static analysis to identify fuzzing-relevant info:
      - Input sources: file parsing (argc/argv), stdin readers, network listeners (socket/accept)
      - Interesting functions: parse, decode, decompress, authenticate, handle_request
      - Recommended fuzzing strategy: file-based, stdin, network
      - Estimated complexity (binary size, number of basic blocks)
    - `create_campaign(project_id, binary_path, config)` — set up a fuzzing campaign:
      - Config: target binary, input corpus directory, dictionary, timeout, memory limit, QEMU mode arch
      - Generate or accept initial seed corpus
      - Set up AFL++ working directories (input, output, crashes, hangs)
    - `start_campaign(campaign_id)` — launch AFL++ with QEMU mode (`afl-fuzz -Q`)
    - `stop_campaign(campaign_id)` — stop the fuzzer
    - `get_campaign_status(campaign_id)` — parse AFL++ stats: executions/sec, paths found, crashes, hangs, coverage bitmap
    - `get_crashes(campaign_id)` — list crash inputs with deduplication
    - `triage_crash(campaign_id, crash_id)` — reproduce crash, get stack trace via GDB, classify exploitability
  - Campaign persistence: store campaigns in a DB table (`fuzzing_campaigns`)
  - Resource management: limit concurrent fuzzing campaigns per project (default: 1)

#### Session 10.2: Fuzzing API & Database

**Do:**
- Create Alembic migration for `fuzzing_campaigns` table
- Create Pydantic schemas in `app/schemas/fuzzing.py`
- Create `app/routers/fuzzing.py` with endpoints:
  - `POST /api/v1/projects/{id}/fuzzing/campaigns` — create campaign
  - `POST /api/v1/projects/{id}/fuzzing/campaigns/{cid}/start` — start fuzzing
  - `POST /api/v1/projects/{id}/fuzzing/campaigns/{cid}/stop` — stop fuzzing
  - `GET /api/v1/projects/{id}/fuzzing/campaigns` — list campaigns
  - `GET /api/v1/projects/{id}/fuzzing/campaigns/{cid}` — campaign details + stats
  - `GET /api/v1/projects/{id}/fuzzing/campaigns/{cid}/crashes` — list crash inputs
  - `POST /api/v1/projects/{id}/fuzzing/campaigns/{cid}/crashes/{crash_id}/triage` — triage a crash
  - `GET /api/v1/projects/{id}/fuzzing/analyze?path=` — analyze binary for fuzzing suitability

#### Session 10.3: Fuzzing Frontend

**Do:**
- Create `frontend/src/pages/FuzzingPage.tsx` with:
  - Campaign list with status, duration, crashes found
  - Campaign creation wizard (target selection, AI analysis, config, start)
  - Active campaign dashboard (real-time stats, coverage chart, crash list)
  - Crash detail view (hex dump, stack trace, exploitability, create finding button)
- Add route, navigation, API client, and types

#### Session 10.4: Fuzzing AI Integration — Smart Target Selection & Harness Generation

**Do:**
- Add fuzzing MCP tools: `analyze_fuzzing_target`, `generate_fuzzing_harness`, `generate_fuzzing_dictionary`, `generate_seed_corpus`, `start_fuzzing_campaign`, `check_fuzzing_status`, `triage_fuzzing_crash`
- Smart target selection heuristics: prioritize binaries that parse untrusted input, are network-facing, lack protections, use dangerous functions
- AI-guided but user-controllable workflow

---

### Phase 11: Polish & Bug Fixes (Sessions 39–42)

#### Session 11.1: Background Tasks & Status
- Set up `arq` worker with Redis
- Move firmware unpacking to background worker
- Real-time status updates via WebSocket or polling
- Progress indicators for long-running operations
- Add `list_services` MCP tool for emulation: after system-mode boot, auto-scan for listening ports and map them to binaries (e.g., `netstat -tlnp` or `/proc/net/tcp` parsing). Returns port/protocol/binary mappings for quick service enumeration

#### Session 11.2: Error Handling & Edge Cases
- Handle corrupt firmware, unsupported formats, large files, empty filesystems
- Request validation, rate limiting, graceful shutdown
- Emulation and fuzzing edge cases
- **Ghidra analysis error diagnostics:** When `list_functions`/`list_imports` fail, return actionable error info (timeout vs memory vs corrupt binary vs unsupported format) instead of generic "produced no parseable output." Add retry with adjusted settings (e.g., longer timeout, reduced analysis depth) for large binaries
- **Init script analysis coverage bug:** `analyze_init_scripts` only searches `/etc/init.d/` — must also search `/etc_ro/init.d/`, `/rom/etc/init.d/`, `/usr/etc/init.d/`, and follow symlinks. Many embedded devices use read-only `/etc_ro/` as the real init location with `/etc/` symlinked to tmpfs
- **Bulk binary protections check:** Add `check_all_binary_protections` MCP tool that scans every ELF binary in the extracted filesystem and returns a summary table (binary name, NX, RELRO, canaries, PIE, Fortify) instead of requiring one call per binary
- **Password hash identification:** Improve `analyze_config_security` and `find_hardcoded_credentials` to properly detect and classify password hashes in `/etc/passwd` and `/etc/shadow` — identify hash type (DES, MD5 `$1$`, SHA-256 `$5$`, SHA-512 `$6$`), flag weak algorithms (DES, MD5), and check against common embedded default passwords (admin, root, 1234, etc.)

#### Session 11.3: Documentation & Testing
- Comprehensive README with quick start, deployment, config reference
- Integration tests for critical paths
- Example firmware images for testing

#### Session 11.4: Final Integration & Release
- End-to-end testing, performance profiling, security review
- GitHub release with docker-compose one-liner

---

### Phase 12: Advanced Analysis & Security Tooling (Sessions 43–45)

**Goal:** Address high-impact gaps identified during real-world firmware assessments — better binary cross-referencing, automated import resolution, enhanced security scanning, and taint/dataflow analysis for finding command injection and buffer overflows.

#### Session 12.1: Binary Analysis Enhancements

**Do:**
- Add `xrefs_to_string` / `find_string_refs` MCP tool (`app/ai/tools/binary.py`):
  - Takes a binary path + string (or regex pattern) and returns all functions that reference matching strings
  - Implementation: use r2pipe to find string addresses (`iz~<pattern>`) then get xrefs to those addresses (`axt @<addr>`)
  - Critical for tracing interesting strings (URLs like `/goform/telnet`, format strings like `password=%s`, dangerous calls like `doSystemCmd`) back to the functions that use them
  - Return: list of `{function_name, address, instruction, string_value}` entries
- Add `resolve_import` MCP tool (`app/ai/tools/binary.py`):
  - Takes a binary path + imported function name, automatically finds the implementing shared library, and returns the library path + decompiled source in one call
  - Implementation: parse the binary's DT_NEEDED entries, search each library's exports for the function, then call `decompile_function` on the match
  - Eliminates the manual multi-step workflow: "find import → guess which .so → search exports → decompile"
  - Uses the component map service's existing ELF DT_NEEDED parsing logic
- Add `check_all_binary_protections` MCP tool (also listed in 11.2 for the bulk scan):
  - Scan all ELF binaries, return a summary table sorted by risk (fewest protections first)
  - Include binary size and type (executable vs shared library) for context
- Register all new tools in `app/ai/tools/__init__.py` and expose via MCP server

#### Session 12.2: Enhanced Security Scanning

**Do:**
- Add `analyze_certificate` MCP tool (`app/ai/tools/security.py`):
  - Parse X.509 certificates (PEM and DER format) and report: subject, issuer, validity dates, key size, signature algorithm, SANs, whether self-signed, key type (RSA/EC/DSA)
  - Flag security issues: expired, weak key size (<2048 RSA), weak signature (SHA-1, MD5), self-signed, wildcard, known default/shared certificates
  - Implementation: use Python `cryptography` library (`x509.load_pem_x509_certificate`)
  - Also scan for certificates across the filesystem: check `/etc/ssl/`, `/etc/pki/`, and find all `.pem`, `.crt`, `.cer`, `.der` files
- Improve `find_hardcoded_credentials` tool:
  - Add hash type identification for passwd/shadow entries (DES, MD5 `$1$`, Blowfish `$2a$`/`$2y$`, SHA-256 `$5$`, SHA-512 `$6$`)
  - Flag weak hash algorithms (DES, MD5) as findings
  - Check password hashes against a built-in list of common embedded defaults (admin, root, password, 1234, default, etc.) using `crypt` module to verify
  - Report accounts with empty passwords, uid=0 non-root accounts, and password-less login shells
- Add `enumerate_emulation_services` MCP tool (`app/ai/tools/emulation.py`):
  - For running system-mode emulation sessions, execute `netstat -tlnp` (or parse `/proc/net/tcp` + `/proc/*/cmdline` if netstat unavailable)
  - Return a table of listening ports with protocol, bound address, and binary path
  - Useful for validating which services are actually running after boot

#### Session 12.3: Taint & Dataflow Analysis

**Do:**
- Add `trace_dataflow` MCP tool (`app/ai/tools/binary.py`):
  - Trace data from user-controlled sources to dangerous sinks within a binary
  - Sources: HTTP parameter handlers (`websGetVar`, `httpGetEnv`, `getenv`, `recv`, `read`, `fgets` from stdin/sockets), CGI input (`QUERY_STRING`, `CONTENT_LENGTH`)
  - Sinks: `system()`, `popen()`, `exec*()`, `sprintf()` into stack buffers, `strcpy()`, `strcat()`, custom dangerous functions (e.g., `doSystemCmd()`, `twsystem()`)
  - Implementation approach: use Ghidra headless with a custom script (`TaintAnalysis.java`) that performs intraprocedural dataflow tracking:
    1. Identify all calls to source functions in the binary
    2. For each source, follow the return value through registers/stack slots
    3. Check if the tainted value reaches any sink function without sanitization
    4. Report: source function + call site → intermediate transforms → sink function + call site
  - Scope: intraprocedural first (within a single function), with heuristic interprocedural tracking for direct call chains
  - Cache results in `analysis_cache` keyed by `taint_analysis:{binary_sha256}`
  - Return: list of potential vulnerability paths with source, sink, and intermediate code snippets
- Create `ghidra/scripts/TaintAnalysis.java`:
  - Ghidra script that performs the dataflow analysis
  - Configurable source/sink function lists (passed as script arguments)
  - Outputs JSON with vulnerability paths
- This is the highest-impact tool for finding command injection and buffer overflows in embedded web interfaces (e.g., router httpd binaries with goform handlers)

---

### Phase 13: Firmware Metadata & Version Comparison (Sessions 46–47)

**Goal:** Provide deeper visibility into firmware image structure and enable comparative analysis across firmware versions for patch analysis and regression detection.

#### Session 13.1: Firmware Image Metadata & Partition Map

**Do:**
- Add `get_firmware_metadata` MCP tool (`app/ai/tools/filesystem.py`):
  - Parse the original firmware image to extract partition/section layout:
    - Use binwalk scan output to identify embedded filesystems, kernels, bootloaders, and their offsets/sizes
    - Identify compression types (LZMA, gzip, zlib, XZ) for each section
    - Extract bootloader info (U-Boot version, environment variables) if present
    - Parse MTD partition tables if embedded in the image
  - Return a structured partition map: `[{name, offset, size, type, compression, description}]`
  - Store parsed metadata in the firmware DB record or analysis_cache
- Add `extract_bootloader_env` helper:
  - Parse U-Boot environment variables (often at a fixed offset or in a named partition)
  - Extract: boot command, kernel load address, bootargs, MAC address source, console settings
  - Useful for understanding boot flow and finding hardcoded values
- Update the frontend firmware detail view to display the partition map visually (simple table or block diagram)

#### Session 13.2: Firmware Version Comparison & Binary Diffing

**Do:**
- Support multi-firmware projects: allow uploading multiple firmware versions to the same project
  - Update `firmware` DB model and API to support multiple firmware per project
  - Add firmware version label/tag field
  - Frontend firmware selector to switch between versions
- Add `diff_firmware` MCP tool:
  - Compare two extracted firmware filesystems:
    - Files added/removed/modified (by hash comparison)
    - Permission changes
    - Size changes with percentage delta
  - Return a structured diff report grouped by directory
- Add `diff_binary` MCP tool:
  - Compare two versions of the same binary using r2pipe `radiff2` or Ghidra's version tracking:
    - Functions added/removed/modified
    - For modified functions: show disassembly diff highlighting changed instructions
    - Basic block count changes (complexity delta)
  - Useful for patch analysis: "what did the vendor fix between v1.0 and v1.1?"
- Frontend: side-by-side comparison view with file diff and binary diff panels

---

### Phase 14: Project Export & Import (Sessions 48–50)

**Goal:** Enable users to export entire projects as portable `.wairz` archive files and import them on another instance. This phase is intentionally last so the archive format captures all features: findings, documents, analysis cache, SBOM data, emulation configs, fuzzing campaigns, and firmware comparison data.

#### Session 14.1: Export Backend — Project Archive Builder

**Do:**
- Create `app/services/export_service.py` — builds a self-contained ZIP archive containing:
  - `manifest.json`, `project.json`, `firmware.json`
  - `firmware/original/` and `firmware/extracted/` (with permissions manifest)
  - `findings/`, `documents/`, `analysis_cache/`, `sbom/`, `fuzzing_campaigns/`
- `POST /api/v1/projects/{id}/export` — streaming ZIP download with `.wairz` extension

#### Session 14.2: Import Backend — Project Archive Importer

**Do:**
- Validate archive, create new project with remapped UUIDs, restore all data
- `POST /api/v1/projects/import` — multipart upload of `.wairz` archive
- ZIP slip and path traversal prevention

#### Session 14.3: Export/Import Frontend

**Do:**
- Export button on project detail page with progress indicator
- Import button on projects page with file picker and upload progress
- Error handling for invalid archives

---

### Phase 15: Live Device UART Console (Sessions 51–53)

**Goal:** Enable Claude (via MCP) to interact with a live device's UART serial console for dynamic analysis, boot log capture, U-Boot interaction, and correlation with static firmware analysis — without requiring USB passthrough into Docker.

**Architecture:** A standalone host-side bridge (`wairz-uart-bridge`) wraps pyserial in a TCP JSON protocol. MCP tools inside Docker connect to the bridge via `host.docker.internal`. Single device at a time. No frontend terminal in v1 (MCP-only).

```
Host Machine                         Docker (backend container)
┌──────────────────────────┐         ┌───────────────────────────┐
│  /dev/ttyUSB0            │         │  wairz-mcp                │
│       │                  │         │       │                    │
│  wairz-uart-bridge       │◄──TCP──▶│  uart MCP tools            │
│  (pyserial + asyncio)    │  :9999  │  (JSON-over-TCP client)    │
│  - transcript logging    │         │                            │
│  - read ring buffer      │         │  uart_service.py           │
│  - prompt detection      │         │  (bridge client + DB)      │
│  - U-Boot break support  │         │                            │
└──────────────────────────┘         └───────────────────────────┘
```

**Usage:**
```bash
# 1. Start the bridge on the host (where the USB-UART adapter is plugged in)
python scripts/wairz-uart-bridge.py --port 9999 --transcript-dir ~/.wairz/uart-transcripts/

# 2. Claude connects via MCP tools (bridge host/port configured in .env)
```

#### Session 15.1: Host-Side UART Bridge

**Do:**
- Create `scripts/wairz-uart-bridge.py` — standalone asyncio TCP server (~300-400 lines), no dependency on wairz backend:
  - Dependencies: `pyserial`, `pyserial-asyncio` (or sync pyserial in thread executor)
  - CLI: `--port` (TCP listen port, default 9999), `--bind` (default 127.0.0.1), `--transcript-dir` (default `~/.wairz/uart-transcripts/`)
  - Manages **one serial connection at a time** — multiple TCP clients share the same serial session
  - Serializes access to serial port so concurrent tool calls don't interleave
- JSON-over-TCP protocol (newline-delimited JSON, request/response matched by `id` field):
  - `connect` — open serial device with baud rate, data bits, parity, stop bits config
  - `send_command` — send command string, wait for prompt (string or regex) or timeout, return captured output
  - `read` — drain and return whatever is in the receive ring buffer (for boot logs, async output)
  - `send_break` — send serial BREAK signal (pyserial `send_break()`) for U-Boot autoboot interrupt
  - `send_raw` — send arbitrary bytes (hex-encoded) for non-shell interaction, boot interrupt sequences
  - `get_transcript` — return last N lines of the transcript JSONL
  - `status` — return connection state, device path, baud rate, bytes buffered, transcript file path
  - `disconnect` — close serial connection, finalize transcript
- **Read ring buffer**: background task continuously reads from serial port, appends to bounded buffer (~1MB). `read` drains the buffer. `send_command` drains first, sends, then reads until prompt/timeout
- **Prompt detection**: `send_command` waits until output matches prompt string (e.g., `# `, `$ `, `=> ` for U-Boot) or regex, or timeout expires
- **U-Boot support**: `send_break` for BREAK signal; `send_raw` with timing for space/ESC key during boot window; prompt detection works with U-Boot prompt (`=> `)
- **Transcript logging**: every byte sent/received logged to JSONL file with timestamps:
  ```jsonl
  {"ts": "2026-02-24T14:30:22.123Z", "dir": "rx", "data": "U-Boot 2019.07\r\n"}
  {"ts": "2026-02-24T14:30:22.456Z", "dir": "tx", "data": "\x03"}
  {"ts": "2026-02-24T14:30:23.001Z", "dir": "cmd", "command": "printenv", "prompt": "=> "}
  ```
  New file per `connect` session. Filename: `YYYY-MM-DD_HHMMSS_{device}.jsonl`
- **Error protocol**: all responses include `"ok": true/false`, errors include `"error": "message"`
- **Testing**: use virtual serial pair (`socat -d -d pty,raw,echo=0 pty,raw,echo=0`) — no hardware needed for development

#### Session 15.2: Backend — Database, Service, Config

**Do:**
- Create Alembic migration for `uart_sessions` table:
  ```sql
  CREATE TABLE uart_sessions (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      project_id UUID REFERENCES projects(id) ON DELETE CASCADE,
      firmware_id UUID REFERENCES firmware(id) ON DELETE CASCADE,
      device_path VARCHAR(255) NOT NULL,     -- /dev/ttyUSB0
      baudrate INTEGER NOT NULL DEFAULT 115200,
      status VARCHAR(20) DEFAULT 'created',  -- created, connected, error, closed
      error_message TEXT,
      transcript_path VARCHAR(512),          -- bridge-side path to transcript JSONL
      connected_at TIMESTAMPTZ,
      closed_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ DEFAULT NOW()
  );
  ```
- Create `app/models/uart_session.py` — SQLAlchemy ORM model following existing patterns (Mapped/mapped_column, dual UUID defaults, FK cascade)
- Create `app/schemas/uart.py` — Pydantic schemas with `from_attributes=True`
- Update `app/config.py` — add UART bridge settings:
  - `uart_bridge_host: str = "host.docker.internal"`
  - `uart_bridge_port: int = 9999`
  - `uart_command_timeout: int = 30`
- Create `app/services/uart_service.py` — `UARTService` class:
  - `connect(project_id, firmware_id, device_path, baudrate, ...)` — create DB record, send `connect` to bridge, update status
  - `send_command(session_id, command, timeout, prompt)` — validate session connected, send `send_command` to bridge, return output
  - `read_buffer(session_id, timeout)` — send `read` to bridge, return buffered output
  - `send_break(session_id)` — send `send_break` to bridge
  - `send_raw(session_id, data_hex)` — send `send_raw` to bridge
  - `get_status(session_id)` — send `status` to bridge, return info
  - `disconnect(session_id)` — send `disconnect` to bridge, update DB
  - `get_transcript(session_id, tail_lines)` — send `get_transcript` to bridge, return recent entries
  - Internal helper: `_bridge_request(request_dict) -> dict` — open TCP connection, send JSON line, read JSON response line. Fresh TCP connection per call (simple, no pooling needed for v1)
- Update `docker-compose.yml` — add `extra_hosts: ["host.docker.internal:host-gateway"]` and `UART_BRIDGE_HOST`/`UART_BRIDGE_PORT` environment variables to backend service

#### Session 15.3: MCP Tools — UART Integration

**Do:**
- Create `app/ai/tools/uart.py` with `register_uart_tools(registry)`:
  - `uart_connect` — connect to UART device via bridge. Inputs: `device_path`, `baudrate` (default 115200), `data_bits` (default 8), `parity` (default "N"), `stop_bits` (default 1). No explicit session_id needed (single device — service tracks active session per project)
  - `uart_send_command` — send shell command, wait for prompt, return output. Inputs: `command`, `timeout` (default 30s), `prompt` (default "# ")
  - `uart_read` — read current receive buffer contents. Inputs: `timeout` (default 2s). For boot logs, async output, checking what's on the console
  - `uart_send_break` — send serial BREAK signal. No inputs. For U-Boot autoboot interrupt, debug console trigger
  - `uart_send_raw` — send raw bytes without waiting for response. Inputs: `data` (string or hex), `hex` (bool, default false). For U-Boot commands, boot interrupt sequences, binary protocols
  - `uart_disconnect` — close serial connection and session. No inputs
  - `uart_status` — check connection status, device info, transcript location. No inputs
  - `uart_get_transcript` — get recent UART transcript entries. Inputs: `tail_lines` (default 100)
- Update `app/ai/__init__.py` — import and call `register_uart_tools(registry)`
- Update `app/ai/tools/__init__.py` if needed for tool module discovery

**Key use cases enabled:**
- **Live device shell access** — Claude sends commands to a booted device, reads output, investigates running system
- **Boot log capture** — connect before power-on, capture full boot sequence, analyze for debug info/keys/errors
- **U-Boot interaction** — send break to interrupt boot, read/modify U-Boot env, dump flash partitions via `md`/`nand read`
- **Static ↔ dynamic correlation** — cross-reference extracted firmware analysis (existing tools) with live device state (UART tools): verify running services, test for discovered vulnerabilities, validate findings

---

## Important Implementation Notes

### Security (of the tool itself)

1. **Path traversal prevention** is critical. Every file access must be validated against the extracted root via `os.path.realpath()` + prefix check (`app/utils/sandbox.py`).
2. **The worker container should be sandboxed.** No network access, resource limits, non-root execution, read-only mounts.
3. **Never execute firmware binaries on the host.** The emulation subsystem runs firmware inside an isolated QEMU container with no host network access and resource limits.
4. **Anthropic API key** is user-provided (via Claude Code/Desktop config, not stored in the backend).

### Performance

1. **Cache Ghidra decompilations** — 30-120s per run. Cache by binary hash + function name in `analysis_cache`.
2. **Cache r2 analysis** — LRU session caching (r2 `aaa` can take 10-30s).
3. **Lazy-load the file tree** — firmware can have 10K+ files. Load on expand.
4. **Truncate tool outputs** — keep under 30KB for MCP tool responses.

### Testing Firmware Sources

Good test firmware for development (all open source):
- **OpenWrt** images (MIPS, ARM) — well-structured, lots of components
- **DD-WRT** — similar to OpenWrt
- **Raspberry Pi OS** — ARM-based Linux
- **DVRF** (Damn Vulnerable Router Firmware) — intentionally vulnerable

---

## Environment Variables

```bash
# .env.example
DATABASE_URL=postgresql+asyncpg://wairz:wairz@postgres:5432/wairz
REDIS_URL=redis://redis:6379/0
STORAGE_ROOT=/data/firmware
MAX_UPLOAD_SIZE_MB=500
MAX_TOOL_OUTPUT_KB=30
GHIDRA_PATH=/opt/ghidra
NVD_API_KEY=                         # Optional NVD API key for higher rate limits
SBOM_CVE_DB_CACHE_DIR=/data/cve-db
EMULATION_TIMEOUT_MINUTES=30
EMULATION_KERNEL_DIR=/opt/emulation/kernels
EMULATION_MAX_SESSIONS=3
EMULATION_MEMORY_LIMIT_MB=512
EMULATION_CPU_LIMIT=1.0
UART_BRIDGE_HOST=host.docker.internal   # Host where wairz-uart-bridge is running
UART_BRIDGE_PORT=9999                   # TCP port for UART bridge JSON protocol
UART_COMMAND_TIMEOUT=30                 # Default timeout (seconds) for uart_send_command
LOG_LEVEL=INFO
```

---

## Claude Code Session Tips

- **Start each session by reading this file** to understand context.
- **One service or component per session** works best.
- **Test incrementally** after each session.
- **Use the session definitions above** as your task scope.
- **Always validate file paths.** This is a security tool analyzing untrusted firmware.
