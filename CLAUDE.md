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
| Emulation | QEMU (user-mode + system-mode) | ARM, MIPS, x86 firmware emulation in isolated container |
| SBOM | cyclonedx-python-lib, packageurl-python | CycloneDX SBOM generation, PURL identifiers |
| CVE Lookup | nvdlib | NVD API client for known vulnerability queries |
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
│   │   │   ├── component-map/
│   │   │   │   ├── ComponentMap.tsx     # Main graph canvas (ReactFlow)
│   │   │   │   ├── ComponentNode.tsx    # Custom node renderer
│   │   │   │   ├── EdgeDetails.tsx      # Edge tooltip/popover (imported functions, etc.)
│   │   │   │   └── MapControls.tsx      # Filter, search, layout controls
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
│   │   │   ├── explorerStore.ts
│   │   │   └── componentMapStore.ts
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
│   │   │   ├── analysis_cache.py
│   │   │   └── sbom.py          # SbomComponent, SbomVulnerability models
│   │   ├── schemas/             # Pydantic request/response schemas
│   │   │   ├── __init__.py
│   │   │   ├── project.py
│   │   │   ├── firmware.py
│   │   │   ├── chat.py
│   │   │   ├── finding.py
│   │   │   └── sbom.py          # SBOM request/response schemas
│   │   ├── routers/             # FastAPI routers
│   │   │   ├── __init__.py
│   │   │   ├── projects.py
│   │   │   ├── files.py
│   │   │   ├── analysis.py
│   │   │   ├── chat.py          # WebSocket endpoint
│   │   │   ├── component_map.py # Component graph endpoint
│   │   │   ├── sbom.py          # SBOM generation & vulnerability scan
│   │   │   └── findings.py
│   │   ├── services/            # Business logic
│   │   │   ├── __init__.py
│   │   │   ├── firmware_service.py
│   │   │   ├── file_service.py
│   │   │   ├── analysis_service.py
│   │   │   ├── component_map_service.py # Graph builder: dependency analysis
│   │   │   ├── sbom_service.py          # SBOM generation from firmware FS
│   │   │   ├── vulnerability_service.py # CVE lookup via NVD
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
│   │   │       ├── sbom.py      # SBOM generation & CVE lookup tools
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
├── emulation/
│   ├── Dockerfile               # QEMU emulation container
│   ├── kernels/                 # Pre-built Linux kernels for emulation
│   │   ├── vmlinux-arm-versatile
│   │   ├── vmlinux-mips-malta
│   │   ├── vmlinux-mipsel-malta
│   │   └── vmlinux-x86
│   └── scripts/
│       ├── start-user-mode.sh   # chroot + qemu-user-static helper
│       └── start-system-mode.sh # QEMU system-mode boot helper
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
    cwe_ids TEXT[],                     -- associated CWEs
    status VARCHAR(20) DEFAULT 'open', -- open, confirmed, false_positive, fixed
    source VARCHAR(50) DEFAULT 'manual', -- manual, ai_discovered, sbom_scan, fuzzing, security_review
    component_id UUID,                  -- FK to sbom_components if source='sbom_scan'
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

-- Emulation sessions (QEMU user-mode and system-mode)
CREATE TABLE emulation_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id UUID REFERENCES projects(id) ON DELETE CASCADE,
    firmware_id UUID REFERENCES firmware(id) ON DELETE CASCADE,
    mode VARCHAR(20) NOT NULL,            -- 'user' or 'system'
    status VARCHAR(20) DEFAULT 'created', -- created, starting, running, stopped, error
    binary_path VARCHAR(512),             -- for user mode: which binary to run
    arguments TEXT,                        -- for user mode: command-line arguments
    architecture VARCHAR(50),             -- arm, mips, mipsel, x86
    port_forwards JSONB DEFAULT '[]',     -- [{host: 8080, guest: 80}, ...]
    container_id VARCHAR(100),            -- Docker container ID
    pid INTEGER,                          -- QEMU process ID inside container
    error_message TEXT,
    started_at TIMESTAMPTZ,
    stopped_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_emulation_project ON emulation_sessions(project_id);
CREATE INDEX idx_emulation_status ON emulation_sessions(status);

-- SBOM components identified from firmware filesystem
CREATE TABLE sbom_components (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    firmware_id UUID REFERENCES firmware(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,              -- e.g., "busybox", "openssl", "dropbear"
    version VARCHAR(100),                    -- e.g., "1.33.1", "1.1.1k"
    type VARCHAR(50) NOT NULL,               -- 'application', 'library', 'firmware', 'operating-system'
    cpe VARCHAR(255),                        -- CPE 2.3 URI, e.g., "cpe:2.3:a:busybox:busybox:1.33.1:*:*:*:*:*:*:*"
    purl VARCHAR(512),                       -- Package URL, e.g., "pkg:generic/busybox@1.33.1"
    supplier VARCHAR(255),                   -- Vendor/supplier name
    detection_source VARCHAR(100) NOT NULL,  -- 'package_manager', 'binary_strings', 'library_soname', 'kernel_modules', 'config_file'
    detection_confidence VARCHAR(20),        -- 'high', 'medium', 'low'
    file_paths TEXT[],                       -- Filesystem paths associated with this component
    metadata JSONB DEFAULT '{}',             -- Additional info: license, description, etc.
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Vulnerability matches from CVE lookup
CREATE TABLE sbom_vulnerabilities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    component_id UUID REFERENCES sbom_components(id) ON DELETE CASCADE,
    firmware_id UUID REFERENCES firmware(id) ON DELETE CASCADE,
    cve_id VARCHAR(20) NOT NULL,             -- e.g., "CVE-2021-42374"
    cvss_score DECIMAL(3,1),                 -- e.g., 9.8
    cvss_vector VARCHAR(255),                -- CVSS 3.1 vector string
    severity VARCHAR(20) NOT NULL,           -- critical, high, medium, low
    description TEXT,
    published_date TIMESTAMPTZ,
    finding_id UUID REFERENCES findings(id), -- Link to auto-generated finding
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_sbom_firmware ON sbom_components(firmware_id);
CREATE INDEX idx_sbom_vulns_component ON sbom_vulnerabilities(component_id);
CREATE INDEX idx_sbom_vulns_firmware ON sbom_vulnerabilities(firmware_id);
CREATE INDEX idx_sbom_vulns_cve ON sbom_vulnerabilities(cve_id);
CREATE INDEX idx_findings_source ON findings(source);
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

### SBOM & Vulnerability Tools (`tools/sbom.py`)

| Tool | Parameters | Returns | Notes |
|---|---|---|---|
| `generate_sbom` | `force_rescan?: bool` | SBOM summary: component count by type, notable components with versions | Triggers SBOM generation if not cached. Returns text summary for AI context |
| `get_sbom_components` | `type?: str, name_filter?: str` | List of identified components with versions and detection source | Filterable by type and name pattern. Max 100 results |
| `check_component_cves` | `component_name: str, version: str` | Known CVEs for the component with severity and CVSS scores | Queries NVD API. Returns formatted CVE list |
| `run_vulnerability_scan` | `force_rescan?: bool` | Vulnerability summary: counts by severity, top critical CVEs, findings created | Triggers full SBOM + CVE scan. Auto-creates findings with `source='sbom_scan'` |

### Emulation Tools (`tools/emulation.py`)

| Tool | Parameters | Returns | Notes |
|---|---|---|---|
| `start_emulation` | `mode: str, binary_path?: str, arguments?: str, port_forwards?: list` | Session ID and connection info | mode: "user" or "system". User mode requires binary_path |
| `run_command_in_emulation` | `session_id: str, command: str, timeout?: int` | Command stdout/stderr and exit code | Timeout default 30s, max 120s. For dynamic analysis |
| `stop_emulation` | `session_id: str` | Confirmation message | Gracefully stops QEMU and cleans up container |
| `check_emulation_status` | `session_id?: str` | Session status, uptime, resource usage | If no session_id, lists all active sessions for project |

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

# Component Map
GET    /api/v1/projects/{id}/component-map  # Build & return component dependency graph

# SBOM & Vulnerability Scanning
POST   /api/v1/projects/{id}/sbom/generate                # Generate/regenerate SBOM from firmware
GET    /api/v1/projects/{id}/sbom                          # Get SBOM components list
GET    /api/v1/projects/{id}/sbom/export?format=           # Export SBOM (cyclonedx-json, spdx-json)
POST   /api/v1/projects/{id}/sbom/vulnerabilities/scan     # Trigger vulnerability scan against NVD
GET    /api/v1/projects/{id}/sbom/vulnerabilities          # Get vulnerability results
GET    /api/v1/projects/{id}/sbom/vulnerabilities/summary  # Vulnerability stats summary

# Emulation
POST   /api/v1/projects/{id}/emulation/start              # Start emulation session
POST   /api/v1/projects/{id}/emulation/{sid}/stop          # Stop emulation session
POST   /api/v1/projects/{id}/emulation/{sid}/exec          # Execute command in session
GET    /api/v1/projects/{id}/emulation/sessions            # List active/recent sessions
GET    /api/v1/projects/{id}/emulation/{sid}/status        # Session status + resource usage

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

### WebSocket Endpoints

```
WS /api/v1/projects/{id}/conversations/{cid}/ws
WS /api/v1/projects/{id}/emulation/{sid}/terminal  # Interactive PTY to emulated system

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

### Phase 6: Firmware Component Map (Sessions 23–25)

**Goal:** Interactive graph visualization showing firmware components (binaries, libraries, scripts, config files) as nodes with relationship edges (library imports, script calls, service dependencies), enabling users to visually understand firmware architecture at a glance.

#### Session 6.1: Component Graph Backend — Dependency Analysis Engine

**Do:**
- Create `app/services/component_map_service.py` — builds a dependency graph from the unpacked firmware:
  - **ELF binary → shared library links:** Parse `DT_NEEDED` entries from the ELF dynamic section (via `pyelftools`) to find which `.so` libraries each binary links against. Resolve library paths using `DT_RPATH`/`DT_RUNPATH` and common search paths (`/lib`, `/usr/lib`, etc.)
  - **Binary → imported functions per library:** Parse the `.dynsym` and `.dynstr` sections to extract imported symbol names. Group by source library using version info and GOT/PLT entries. This powers the edge detail view showing which functions are imported from a given library
  - **Shell script → script/binary calls:** Parse shell scripts (files with `#!/bin/sh`, `#!/bin/bash`, etc. shebang or `.sh` extension) for:
    - `source`/`.` commands (script sourcing)
    - Direct binary invocations (e.g., `iptables`, `httpd`, `/usr/sbin/dropbear`)
    - Backtick/`$()` command substitution calls
  - **Init script → service mapping:** Parse `/etc/init.d/*`, `/etc/inittab`, and systemd units to determine which scripts start which binaries/services
  - **Config file → binary references:** Scan config files for paths to binaries or libraries they configure (e.g., `lighttpd.conf` referencing `/usr/lib/mod_*.so`)
- Define the graph data model:
  ```python
  @dataclass
  class ComponentNode:
      id: str              # filesystem path (unique)
      label: str           # filename
      type: str            # "binary", "library", "script", "config", "init_script"
      path: str            # full path in extracted FS
      size: int
      metadata: dict       # type-specific: architecture, protections, shebang, etc.

  @dataclass
  class ComponentEdge:
      source: str          # source node id
      target: str          # target node id
      type: str            # "links_library", "imports_functions", "sources_script",
                           # "executes", "starts_service", "configures"
      details: dict        # type-specific: {"functions": ["printf", "malloc", ...]}

  @dataclass
  class ComponentGraph:
      nodes: list[ComponentNode]
      edges: list[ComponentEdge]
  ```
- Create Pydantic response schemas in `app/schemas/component_map.py`
- Create `app/routers/component_map.py`:
  - `GET /api/v1/projects/{id}/component-map` — builds (or returns cached) graph
  - Should cache the result (graph building walks the entire filesystem and parses many ELF files — can take 10-30s)
  - Use `analysis_cache` table with operation `component_map` to cache per firmware
- Path validation: all paths must be validated against extracted root (reuse `validate_path` utility)
- Limit graph size: cap at 500 nodes. If firmware has more components, prioritize:
  1. ELF binaries and libraries
  2. Init scripts and startup scripts
  3. Config files referenced by services
  4. Other shell scripts
- Register router in `app/main.py`

**Definition of Done:**
- API endpoint returns a complete component graph for an unpacked firmware
- ELF binaries correctly show which libraries they link and which functions they import
- Shell scripts show call relationships to other scripts and binaries
- Init scripts show service startup relationships
- Graph is cached — second request is instant
- Result is < 1MB for typical firmware images

#### Session 6.2: Frontend — Interactive Graph Visualization

**Do:**
- Install `@xyflow/react` (ReactFlow v12) for the graph canvas
- Add route: `/projects/:id/map` accessible from the project sidebar/navigation
- Create `frontend/src/pages/ComponentMapPage.tsx`:
  - Fetches graph data from `/api/v1/projects/{id}/component-map`
  - Loading state while graph is being built (can take 10-30s on first load)
  - Error state if no firmware is unpacked
- Create `frontend/src/components/component-map/ComponentMap.tsx`:
  - ReactFlow canvas with pan, zoom, minimap
  - Automatic layout using `dagre` or `elkjs` (hierarchical left-to-right or top-to-bottom)
  - Nodes colored/shaped by type:
    - **Binary (executable):** Blue rounded rectangle with CPU icon
    - **Library (.so):** Purple rounded rectangle with package icon
    - **Shell script:** Green rounded rectangle with terminal icon
    - **Config file:** Orange rounded rectangle with settings icon
    - **Init script:** Yellow rounded rectangle with play icon
  - Edges styled by relationship type:
    - **links_library:** Solid line
    - **imports_functions:** Dashed line (detail available on hover)
    - **executes/sources_script:** Dotted line with arrow
    - **starts_service:** Bold line with arrow
    - **configures:** Thin gray line
- Create `frontend/src/components/component-map/ComponentNode.tsx`:
  - Custom ReactFlow node with icon, label, and file size badge
  - Click: navigate to file in the explorer view (`/projects/:id/explore` with the file selected)
  - Highlight on hover with connected edges
- Create `frontend/src/components/component-map/EdgeDetails.tsx`:
  - Hover/click an edge to see relationship details in a popover/tooltip
  - For library import edges: show list of imported function names (scrollable if many)
  - For script execution edges: show the command line used
  - For init script edges: show the service name and runlevel
- Create `frontend/src/components/component-map/MapControls.tsx`:
  - Filter by node type (checkboxes: binaries, libraries, scripts, configs)
  - Search/highlight: type a component name to find and center it
  - Layout toggle: hierarchical vs force-directed
  - Zoom-to-fit button
  - Show/hide edge labels
- Create `frontend/src/api/componentMap.ts` — API client function
- Add types to `frontend/src/types/index.ts`:
  ```typescript
  interface ComponentNode {
    id: string
    label: string
    type: 'binary' | 'library' | 'script' | 'config' | 'init_script'
    path: string
    size: number
    metadata: Record<string, unknown>
  }

  interface ComponentEdge {
    source: string
    target: string
    type: 'links_library' | 'imports_functions' | 'sources_script' |
          'executes' | 'starts_service' | 'configures'
    details: Record<string, unknown>
  }

  interface ComponentGraph {
    nodes: ComponentNode[]
    edges: ComponentEdge[]
  }
  ```
- Add "Map" navigation item to the project sidebar/layout

**Definition of Done:**
- Component map page loads and renders the firmware dependency graph
- Nodes are visually distinct by type with appropriate icons and colors
- Edges clearly show relationship types
- Hovering/clicking an edge shows details (e.g., imported function list)
- Clicking a node navigates to that file in the explorer
- Can filter by component type and search for specific components
- Layout is readable for firmware with 50-200 components
- Pan, zoom, and minimap work smoothly

#### Session 6.3: Component Map Polish & AI Integration

**Do:**
- Add AI tool `get_component_map` to `app/ai/tools/filesystem.py`:
  - Returns a text summary of the component graph (node count by type, key binaries, highly-connected components)
  - Useful for AI to understand firmware architecture before diving into specific files
- Add "Ask AI about this component" context option:
  - Right-click a node in the graph → opens chat with the file attached
  - Right-click an edge → opens chat with a prompt about the relationship (e.g., "What functions does httpd import from libcrypto?")
- Performance optimization:
  - Lazy render: only render nodes visible in the viewport (ReactFlow handles this natively)
  - Progressive loading: show the graph incrementally as nodes are processed
  - For large graphs (200+ nodes), default to collapsed clusters by directory (e.g., all `/usr/lib/*.so` as one "usr/lib libraries" group that expands on click)
- Add export options:
  - Export graph as PNG/SVG image
  - Export as JSON for external tools

**Definition of Done:**
- AI can query the component map and use it to understand firmware architecture
- Right-click context menus on nodes/edges integrate with AI chat
- Large firmware images render without lag
- Export to image works

---

### Phase 7: AI Decompiled Code Clean-up (Sessions 26–27)

**Goal:** Add an AI-powered code cleanup feature to the decompiled code viewer that transforms raw Ghidra output into human-readable pseudo-C by renaming variables/functions, adding comments, and improving structure — without changing functionality.

#### Session 7.1: Backend — AI Code Cleanup Service

**Do:**
- Create `app/services/code_cleanup_service.py`:
  - `cleanup_decompiled_code(project_id, binary_path, function_name, raw_code)` → cleaned code string
  - Calls Claude API with a specialized system prompt for code cleanup:
    - Rename auto-generated variables (`uVar1`, `local_10`, `param_1`) to meaningful names based on usage context
    - Rename auto-generated function names (`FUN_00401234`) to descriptive names based on behavior, or leave with a comment if unclear
    - Add inline comments explaining non-obvious operations (bit manipulation, magic numbers, protocol handling)
    - Add a function-level docstring summarizing purpose, parameters, and return value
    - Preserve the original structure and logic — no functional changes
    - Annotate security-relevant patterns (unchecked buffers, command injection, format strings)
  - Include ELF context in the prompt: binary name, architecture, linked libraries, imported functions used in the function
  - Cache results in `analysis_cache` with operation `code_cleanup:{function_name}` keyed by binary SHA256
  - Non-streaming: return the full cleaned code (AI response is typically < 5KB)
- Add endpoint to `app/routers/analysis.py`:
  - `POST /api/v1/projects/{id}/analysis/cleanup` — accepts `{ binary_path, function_name }`, returns `{ original_code, cleaned_code }`
  - First fetches the raw decompilation (from cache or Ghidra), then runs cleanup
  - Cache the cleaned result separately from the raw decompilation
- Add AI tool `cleanup_decompiled_code` to `app/ai/tools/binary.py`:
  - Allows the AI assistant to clean up code on behalf of the user during chat
  - Returns the cleaned code as a formatted text response

**Definition of Done:**
- API endpoint accepts a binary path and function name, returns AI-cleaned decompiled code
- Variables and functions are renamed to meaningful names
- Comments explain non-obvious logic
- Security-relevant patterns are annotated
- Results are cached per binary+function
- AI chat assistant can invoke code cleanup via tool use

#### Session 7.2: Frontend — Cleanup Code Viewer Integration

**Do:**
- Update the decompiled code viewer in `FileViewer.tsx` / binary analysis UI:
  - Add a "Clean Up with AI" button next to the decompile button
  - When clicked: show loading spinner, call the cleanup endpoint
  - Display the cleaned code in Monaco with a toggle to switch between raw and cleaned views
  - Use a split-view or tab UI: "Raw Decompilation" | "AI Cleaned"
  - Syntax highlighting for C/pseudo-C in both views
  - Diff highlighting: optionally show what the AI changed (renamed identifiers highlighted, added comments in a different color)
- Add visual indicators:
  - Badge showing "AI Cleaned" when viewing the cleaned version
  - Tooltip showing the original auto-generated name when hovering over a renamed identifier (if feasible with Monaco decorations)
- Add API client function in `src/api/analysis.ts`:
  - `cleanupCode(projectId, binaryPath, functionName)` → `{ original_code, cleaned_code }`
- Handle errors: show a message if cleanup fails (binary not found, Ghidra not available, API error)

**Definition of Done:**
- Button to trigger AI code cleanup appears in the decompiled code viewer
- Cleaned code displays with proper syntax highlighting
- Can toggle between raw and cleaned views
- Renamed identifiers and added comments are visible
- Loading and error states are handled

---

### Phase 8: Firmware Emulation (Sessions 28–31)

**Goal:** Add firmware emulation capability using QEMU in a separate Docker container, allowing users to boot and interact with the firmware's userland for dynamic analysis and finding validation.

#### Session 8.1: Emulation Infrastructure — Docker & QEMU Setup

**Do:**
- Create `emulation/Dockerfile`:
  - Base: `debian:bookworm-slim` or `ubuntu:24.04`
  - Install QEMU user-mode and system-mode: `qemu-system-arm`, `qemu-system-mips`, `qemu-system-mipsel`, `qemu-system-x86`, `qemu-user-static`
  - Install supporting tools: `bridge-utils`, `iproute2`, `busybox-static`, `socat`
  - Install filesystem tools for creating emulation images: `e2fsprogs`, `mount`, `kpartx`
  - Non-root user for emulation processes
  - Resource limits via Docker: CPU, memory, no host network access
- Create `app/services/emulation_service.py`:
  - `EmulationService` class managing emulation lifecycle:
    - `prepare(firmware_id)` — analyze the extracted filesystem to determine:
      - Architecture (ARM, MIPS, x86) and endianness from ELF binaries
      - Init system (sysvinit, systemd, busybox init)
      - Required kernel version (if `/lib/modules/` exists)
      - Network configuration from `/etc/network/interfaces`, `/etc/config/network`
    - `start(firmware_id, options)` — launch QEMU emulation:
      - Use QEMU user-mode (`qemu-{arch}-static` + chroot) for simple single-binary execution
      - Use QEMU system-mode for full OS boot (requires a matching kernel — bundle common embedded Linux kernels for ARM/MIPS)
      - Mount the extracted filesystem as the root
      - Set up virtual networking (TAP/bridge or user-mode networking with port forwarding)
      - Return emulation session ID and connection details
    - `stop(session_id)` — gracefully shut down QEMU, clean up resources
    - `status(session_id)` — return running/stopped/error, uptime, resource usage
    - `list_sessions(project_id)` — return all active/recent emulation sessions
  - Session management: track active emulation sessions in the `emulation_sessions` DB table (see Database Schema section)
  - Timeout: auto-stop emulations after `EMULATION_TIMEOUT_MINUTES` (default 30)
  - Limit concurrent sessions per project: `EMULATION_MAX_SESSIONS` (default 3)
  - Security: the emulation container runs on an isolated Docker network (`wairz_emulation_net`) with no internet access; firmware storage mounted read-only; resource-limited via `EMULATION_MEMORY_LIMIT_MB` and `EMULATION_CPU_LIMIT`
- Backend ↔ emulation container communication:
  - Use the **Docker SDK for Python** (`docker` package) to manage containers programmatically
  - Each emulation session spawns a new container from the emulation image
  - User-mode: `docker exec` into the container running `qemu-{arch}-static` + chroot
  - System-mode: container runs QEMU system-mode with serial console exposed via `socat` on a Unix socket
  - Terminal WebSocket connects to the container's PTY via `docker exec` attach or the `socat`-exposed serial console
  - Command execution (`run_command_in_emulation`) uses `docker exec` with timeout enforcement
- Create SQLAlchemy model `app/models/emulation_session.py`:
  ```python
  class EmulationSession(Base):
      __tablename__ = "emulation_sessions"
      id: Mapped[uuid.UUID]              # PK
      project_id: Mapped[uuid.UUID]      # FK → projects
      firmware_id: Mapped[uuid.UUID]     # FK → firmware
      mode: Mapped[str]                  # "user" or "system"
      status: Mapped[str]                # created, starting, running, stopped, error
      binary_path: Mapped[str | None]    # user mode: target binary
      arguments: Mapped[str | None]      # user mode: CLI arguments
      architecture: Mapped[str | None]   # arm, mips, mipsel, x86
      port_forwards: Mapped[dict | None] # JSONB: [{host, guest}]
      container_id: Mapped[str | None]   # Docker container ID
      pid: Mapped[int | None]            # QEMU PID inside container
      error_message: Mapped[str | None]
      started_at / stopped_at / created_at
  ```
- Create Alembic migration for the `emulation_sessions` table
- Bundle a set of pre-built Linux kernels for common architectures:
  - ARM (versatile-pb, vexpress-a9) — common for router firmware
  - MIPS/MIPSel (Malta) — common for router firmware
  - x86 — for x86-based embedded devices
  - Store in `emulation/kernels/` directory

**Definition of Done:**
- Emulation Docker container builds with QEMU for ARM, MIPS, x86
- Service can analyze firmware and determine emulation parameters
- Can start a QEMU user-mode chroot for running individual binaries
- Can start a QEMU system-mode boot for full OS emulation (with bundled kernel)
- Sessions are tracked and auto-stopped after timeout
- Emulation runs in an isolated, sandboxed container

#### Session 8.2: Emulation API & Terminal Integration

**Do:**
- Create Pydantic schemas in `app/schemas/emulation.py`:
  ```python
  class EmulationStartRequest(BaseModel):
      mode: Literal["user", "system"]
      binary_path: str | None = None       # required for user mode
      arguments: str | None = None          # optional CLI args for user mode
      port_forwards: list[PortForward] = [] # [{host: int, guest: int}]

  class PortForward(BaseModel):
      host: int  # port on the host/backend side
      guest: int # port inside the emulated system

  class EmulationSessionResponse(BaseModel):
      id: str
      project_id: str
      mode: str
      status: str
      architecture: str | None
      binary_path: str | None
      port_forwards: list[PortForward]
      started_at: str | None
      created_at: str

  class EmulationStatusResponse(EmulationSessionResponse):
      uptime_seconds: int | None
      container_id: str | None

  class EmulationExecRequest(BaseModel):
      command: str
      timeout: int = 30  # seconds, max 120

  class EmulationExecResponse(BaseModel):
      stdout: str
      stderr: str
      exit_code: int
      timed_out: bool
  ```
- Create `app/routers/emulation.py`:
  - `POST /api/v1/projects/{id}/emulation/start` — validates firmware exists and is unpacked, resolves architecture, creates DB record, starts container via `EmulationService.start()`, returns `EmulationSessionResponse`
    - User mode: validates `binary_path` against extracted root (path traversal prevention)
    - System mode: selects matching kernel from `EMULATION_KERNEL_DIR`
    - Enforces `EMULATION_MAX_SESSIONS` per project
  - `POST /api/v1/projects/{id}/emulation/{session_id}/stop` — calls `EmulationService.stop()`, updates DB status, returns updated session
  - `POST /api/v1/projects/{id}/emulation/{session_id}/exec` — accepts `EmulationExecRequest`, runs command in container, returns `EmulationExecResponse`
  - `GET /api/v1/projects/{id}/emulation/sessions` — list all sessions for project, ordered by `created_at` desc
  - `GET /api/v1/projects/{id}/emulation/{session_id}/status` — returns `EmulationStatusResponse` with live container info
  - `WS /api/v1/projects/{id}/emulation/{session_id}/terminal` — WebSocket for interactive terminal access:
    - On connect: attach to container PTY via Docker SDK `exec_start(socket=True)`
    - Bidirectional: WS text frames → container stdin, container stdout → WS text frames
    - Handle xterm.js resize events (`{ type: "resize", cols: int, rows: int }`)
    - On disconnect: detach but don't stop the session
- Register router in `app/main.py`
- Update `docker-compose.yml`:
  - Add `emulation` service with the emulation Dockerfile
  - Isolated network `wairz_emulation_net` (no internet access for emulated firmware)
  - Volume mount for firmware storage (read-only: `${STORAGE_ROOT}:/data/firmware:ro`)
  - Volume mount for kernels: `./emulation/kernels:/opt/kernels:ro`
  - Resource limits: `mem_limit: ${EMULATION_MEMORY_LIMIT_MB}m`, `cpus: ${EMULATION_CPU_LIMIT}`
  - Backend service gets access to Docker socket (`/var/run/docker.sock`) to manage emulation containers

**Definition of Done:**
- API endpoints for starting/stopping/monitoring emulation sessions work
- WebSocket terminal provides interactive shell access to the emulated firmware
- Port forwarding allows accessing emulated services from the host
- Command execution endpoint returns stdout/stderr with timeout enforcement
- Emulation container is properly isolated on its own Docker network
- Concurrent session limit is enforced

#### Session 8.3: Emulation Frontend

**Do:**
- Add types to `frontend/src/types/index.ts`:
  ```typescript
  type EmulationMode = 'user' | 'system'
  type EmulationStatus = 'created' | 'starting' | 'running' | 'stopped' | 'error'

  interface PortForward {
    host: number
    guest: number
  }

  interface EmulationSession {
    id: string
    project_id: string
    mode: EmulationMode
    status: EmulationStatus
    architecture: string | null
    binary_path: string | null
    arguments: string | null
    port_forwards: PortForward[]
    error_message: string | null
    started_at: string | null
    stopped_at: string | null
    created_at: string
  }

  interface EmulationStatusResponse extends EmulationSession {
    uptime_seconds: number | null
    container_id: string | null
  }

  interface EmulationExecResponse {
    stdout: string
    stderr: string
    exit_code: number
    timed_out: boolean
  }
  ```
- Create API client `frontend/src/api/emulation.ts`:
  - `startEmulation(projectId, request)` → `EmulationSession`
  - `stopEmulation(projectId, sessionId)` → `EmulationSession`
  - `execInEmulation(projectId, sessionId, command, timeout?)` → `EmulationExecResponse`
  - `listSessions(projectId)` → `EmulationSession[]`
  - `getSessionStatus(projectId, sessionId)` → `EmulationStatusResponse`
- Create `frontend/src/pages/EmulationPage.tsx` (or add to `ExplorePage.tsx` as a panel):
  - Emulation control panel:
    - "Start Emulation" button with mode selection (User mode / System mode)
    - For user mode: file picker to select which binary to run, with argument input
    - For system mode: optional port forwarding configuration (add/remove rows: host port ↔ guest port)
    - Architecture auto-detected from firmware metadata, shown as read-only badge
  - Active session display:
    - Status indicator with color coding (starting=yellow, running=green, stopped=gray, error=red)
    - Uptime counter and architecture badge
    - Stop button (with confirmation for system-mode sessions)
    - Terminal tab/panel for interactive access
  - Terminal integration:
    - Reuse or extend `TerminalPanel.tsx` for the emulation terminal
    - Connect via WebSocket to `/api/v1/projects/{id}/emulation/{sid}/terminal`
    - Full xterm.js terminal with proper key handling and resize events
    - Show connection status indicator in terminal header
  - Session history: table of past emulation sessions with mode, status, duration, start/stop times
    - Click a running session to reconnect terminal
    - Click a stopped session to see error message (if any)
- Add route: `/projects/:id/emulation` accessible from project sidebar
- Add "Emulation" navigation item to the project sidebar with a play-circle icon
- Create `frontend/src/stores/emulationStore.ts` (Zustand) if needed for session state tracking across components

**Definition of Done:**
- Can start/stop firmware emulation from the UI
- Interactive terminal connects to the emulated system
- Can run individual binaries in user mode
- Can boot the full firmware in system mode
- Port forwarding configuration UI works
- Session history is displayed with status indicators
- Terminal reconnects when navigating back to a running session

#### Session 8.4: Emulation AI Integration

**Do:**
- Create `app/ai/tools/emulation.py` with tool handlers:
  - `_handle_start_emulation(input, context)` — calls `EmulationService.start()`, returns session ID and status. Validates binary path for user mode. Limits to one active AI-initiated session per conversation to prevent resource exhaustion
  - `_handle_run_command_in_emulation(input, context)` — validates session exists and is running, executes command via `EmulationService.exec()`, returns stdout/stderr. Truncates output to `MAX_TOOL_OUTPUT_KB`. Default timeout 30s, max 120s
  - `_handle_stop_emulation(input, context)` — stops the session, returns confirmation
  - `_handle_check_emulation_status(input, context)` — returns session status, uptime, and whether the system has booted (for system mode). If no session_id given, lists all active sessions for the project
- Register all emulation tools via `register_emulation_tools(registry)`, called from `app/ai/tools/__init__.py`
- Update system prompt in `app/ai/system_prompt.py` to include emulation guidance:
  ```
  Emulation capabilities:
  - You can start QEMU-based emulation to dynamically test the firmware
  - User mode: run a single binary in a chroot (fast, good for testing specific programs)
  - System mode: boot the full firmware OS (slower, good for testing services and network behavior)
  - Use emulation to VALIDATE static findings: test if default credentials work, check if services are accessible, verify network behavior
  - Caveats: emulated firmware may behave differently than on real hardware (missing peripherals, different timing, no flash storage). Note these limitations when reporting findings
  - Always stop emulation sessions when done to free resources
  ```
- Add a context menu option in the file explorer: "Run in Emulation" for ELF binaries
  - In `FileTree.tsx`: detect ELF files from `fileInfo.elf_info`, add right-click menu item
  - Click navigates to the emulation page with `?binary=<path>` pre-filled, or opens a small dialog to configure and start user-mode emulation directly
- Add a context menu option in the chat: when AI mentions running a binary, show a quick-action button to "Open in Emulation"

**Definition of Done:**
- AI can start emulation, run commands, and stop sessions via tool use
- AI uses emulation to validate findings (e.g., "let me check if this service actually exposes the default credentials by starting system-mode emulation and connecting")
- Right-click → "Run in Emulation" works for ELF binaries in the file tree
- AI explains caveats about emulation vs. real hardware in its analysis
- Tool output is properly truncated for large command outputs
- AI cleans up sessions after analysis is complete

---

### Phase 9: SBOM & Known Vulnerability Look-Up (Sessions 32–34)

**Goal:** Generate a Software Bill of Materials (SBOM) from the extracted firmware filesystem and kernel, then check component versions against known vulnerability databases (NVD) to identify inherited vulnerabilities. Findings are automatically created with a distinct `source='sbom_scan'` tag to differentiate them from vulnerabilities discovered through manual analysis, AI investigation, or fuzzing. This gives users an immediate, automated overview of known risk before deeper manual analysis begins.

#### Session 9.1: SBOM Generation Backend — Component Identification Engine

**Do:**
- Install Python dependencies: `cyclonedx-python-lib`, `packageurl-python`
- Create SQLAlchemy models in `app/models/sbom.py`:
  ```python
  class SbomComponent(Base):
      __tablename__ = "sbom_components"
      id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4, server_default=func.gen_random_uuid())
      firmware_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("firmware.id", ondelete="CASCADE"))
      name: Mapped[str] = mapped_column(String(255))
      version: Mapped[str | None] = mapped_column(String(100))
      type: Mapped[str] = mapped_column(String(50))       # 'application', 'library', 'firmware', 'operating-system'
      cpe: Mapped[str | None] = mapped_column(String(255))
      purl: Mapped[str | None] = mapped_column(String(512))
      supplier: Mapped[str | None] = mapped_column(String(255))
      detection_source: Mapped[str] = mapped_column(String(100))  # 'package_manager', 'binary_strings', 'library_soname', 'kernel_modules', 'config_file'
      detection_confidence: Mapped[str | None] = mapped_column(String(20))
      file_paths: Mapped[list[str] | None] = mapped_column(ARRAY(Text))
      metadata: Mapped[dict] = mapped_column(JSONB, server_default=text("'{}'"))
      created_at: Mapped[datetime] = mapped_column(server_default=func.now())
      vulnerabilities: Mapped[list["SbomVulnerability"]] = relationship(back_populates="component", cascade="all, delete-orphan")

  class SbomVulnerability(Base):
      __tablename__ = "sbom_vulnerabilities"
      id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4, server_default=func.gen_random_uuid())
      component_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("sbom_components.id", ondelete="CASCADE"))
      firmware_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("firmware.id", ondelete="CASCADE"))
      cve_id: Mapped[str] = mapped_column(String(20))
      cvss_score: Mapped[float | None] = mapped_column(Numeric(3, 1))
      cvss_vector: Mapped[str | None] = mapped_column(String(255))
      severity: Mapped[str] = mapped_column(String(20))
      description: Mapped[str | None] = mapped_column(Text)
      published_date: Mapped[datetime | None]
      finding_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("findings.id"))
      created_at: Mapped[datetime] = mapped_column(server_default=func.now())
      component: Mapped["SbomComponent"] = relationship(back_populates="vulnerabilities")
  ```
- Create Alembic migration for `sbom_components` and `sbom_vulnerabilities` tables, plus `ALTER TABLE findings ADD COLUMN source VARCHAR(50) DEFAULT 'manual'` and `ADD COLUMN component_id UUID`
- Create `app/services/sbom_service.py` with `SbomService` class:
  - `generate_sbom(firmware_id, extracted_path, force_rescan=False)` → `list[SbomComponent]`
  - Component identification strategies (run in order, dedup by name+version):
    1. **Package manager databases:** Parse opkg status (`/usr/lib/opkg/status`, `/var/lib/opkg/status`), dpkg status (`/var/lib/dpkg/status`), RPM DB. Extract package name, version, architecture, description. Detection confidence: `high`
    2. **Kernel version:** Parse `/lib/modules/*/` directory names, search for version strings in `/proc/version` or kernel binaries. Build CPE for the Linux kernel. Detection confidence: `high`
    3. **Library SONAME parsing:** Scan `/lib/*.so*`, `/usr/lib/*.so*` for versioned shared libraries (e.g., `libssl.so.1.1.1k` → OpenSSL 1.1.1k). Parse ELF `SONAME` via `pyelftools`. Detection confidence: `high`
    4. **Binary version strings:** Run `strings` on key ELF binaries (`busybox`, `httpd`, `dropbear`, `dnsmasq`, etc.) and match against known version patterns (e.g., `BusyBox v1.33.1`, `OpenSSH_8.4`, `lighttpd/1.4.59`). Detection confidence: `medium`
    5. **Config file version hints:** Parse web interface HTML/JS for product version, check `/etc/*release`, `/etc/banner`, `/etc/openwrt_release`. Detection confidence: `low`
  - Build CPE 2.3 identifiers for each component using known vendor:product mappings (maintain a lookup dict for common embedded components: busybox, openssl, dropbear, dnsmasq, lighttpd, iptables, curl, etc.)
  - Build Package URLs (PURL) using `packageurl-python`
  - Cache SBOM in the database (check if `sbom_components` exist for this `firmware_id` before regenerating)
  - Generate CycloneDX JSON SBOM using `cyclonedx-python-lib` for export
- Create Pydantic schemas in `app/schemas/sbom.py`:
  ```python
  class SbomComponentResponse(BaseModel):
      id: uuid.UUID
      firmware_id: uuid.UUID
      name: str
      version: str | None
      type: str
      cpe: str | None
      purl: str | None
      supplier: str | None
      detection_source: str
      detection_confidence: str | None
      file_paths: list[str] | None
      metadata: dict
      vulnerability_count: int = 0
      created_at: datetime
      model_config = ConfigDict(from_attributes=True)

  class SbomSummaryResponse(BaseModel):
      total_components: int
      components_by_type: dict[str, int]
      components_with_vulns: int
      total_vulnerabilities: int
      vulns_by_severity: dict[str, int]
      scan_date: datetime | None
  ```

**Definition of Done:**
- SBOM service identifies packages from opkg/dpkg databases, library SONAMEs, binary version strings, and kernel modules
- Each component has a CPE identifier and detection confidence level
- SBOM is persisted to `sbom_components` table and cached per firmware
- CycloneDX JSON export produces a valid SBOM document
- Re-running on the same firmware returns cached results (unless `force_rescan=True`)

#### Session 9.2: Vulnerability Lookup & Findings Integration

**Do:**
- Install Python dependency: `nvdlib`
- Create `app/services/vulnerability_service.py`:
  - `VulnerabilityService` class:
    - `scan_components(firmware_id, components: list[SbomComponent], force_rescan=False)` → `VulnerabilityScanResult`
    - For each component with a CPE identifier:
      1. Query NVD API via `nvdlib.searchCVE(cpeName=cpe)` (or `keywordSearch` for components without exact CPE)
      2. Respect NVD rate limits: 0.6 req/s without API key, 6 req/s with key (use `asyncio.Semaphore` + `asyncio.sleep`)
      3. For each CVE match: extract CVSS score, vector, severity, description, published date
      4. Map CVSS to severity: ≥9.0 = critical, ≥7.0 = high, ≥4.0 = medium, <4.0 = low
      5. Store in `sbom_vulnerabilities` table
    - `_create_findings_from_vulns(firmware_id, project_id, vulns)`:
      - Group vulnerabilities by component to avoid one finding per CVE (noisy)
      - Strategy: create one finding per component with critical/high CVEs, list all CVEs in evidence
      - Finding fields:
        - `title`: "Known vulnerabilities in {component} {version}"
        - `severity`: highest severity among the component's CVEs
        - `description`: "SBOM scan identified {n} known CVEs in {component} {version}. This is an inherited vulnerability from a third-party component included in the firmware."
        - `evidence`: formatted list of CVEs with scores and descriptions
        - `source`: `'sbom_scan'`
        - `component_id`: reference to the `sbom_components` record
        - `cve_ids`: array of CVE IDs
        - `file_paths`: from the component's `file_paths`
      - For components with only medium/low CVEs, create a single grouped finding per severity tier to reduce noise
    - `get_vulnerability_summary(firmware_id)` → `SbomSummaryResponse`
  - Handle NVD API errors gracefully: timeout → skip component, rate limit → retry with backoff, API down → use cached results if available
- Create `app/routers/sbom.py`:
  - `POST /api/v1/projects/{id}/sbom/generate` — triggers SBOM generation, returns component list
    - Calls `_resolve_firmware()` (reuse from analysis.py), then `sbom_service.generate_sbom()`
    - Returns `list[SbomComponentResponse]`
  - `GET /api/v1/projects/{id}/sbom` — returns cached SBOM components with vulnerability counts
    - Query params: `type?: str`, `name?: str`, `has_vulns?: bool` for filtering
  - `GET /api/v1/projects/{id}/sbom/export?format=cyclonedx-json` — export SBOM document
    - Also support `format=spdx-json` (stretch goal, CycloneDX primary)
    - Returns file download with appropriate Content-Type
  - `POST /api/v1/projects/{id}/sbom/vulnerabilities/scan` — triggers CVE lookup for all SBOM components
    - Body: `{ force_rescan?: bool }`
    - Returns `VulnerabilityScanResponse` with summary stats
  - `GET /api/v1/projects/{id}/sbom/vulnerabilities` — returns all vulnerability matches
    - Query params: `severity?: str`, `component_id?: str`, `cve_id?: str`
    - Includes component name/version via join
  - `GET /api/v1/projects/{id}/sbom/vulnerabilities/summary` — aggregated stats
- Add Pydantic schemas for vulnerability responses:
  ```python
  class SbomVulnerabilityResponse(BaseModel):
      id: uuid.UUID
      component_id: uuid.UUID
      cve_id: str
      cvss_score: float | None
      cvss_vector: str | None
      severity: str
      description: str | None
      published_date: datetime | None
      finding_id: uuid.UUID | None
      component_name: str | None = None
      component_version: str | None = None
      model_config = ConfigDict(from_attributes=True)

  class VulnerabilityScanRequest(BaseModel):
      force_rescan: bool = False

  class VulnerabilityScanResponse(BaseModel):
      status: str
      total_components_scanned: int
      total_vulnerabilities_found: int
      findings_created: int
      vulns_by_severity: dict[str, int]
  ```
- Register router in `app/main.py`
- Add SBOM AI tools to `app/ai/tools/sbom.py`:
  - `generate_sbom` — triggers SBOM generation, returns text summary (component count by type, notable components with versions)
  - `get_sbom_components` — returns filtered component list as formatted text
  - `check_component_cves` — queries NVD for a specific component+version, returns CVE list
  - `run_vulnerability_scan` — triggers full scan, returns summary with auto-created finding count
- Register tools in tool registry
- Update `add_finding` tool to support optional `source` parameter (default `'ai_discovered'` when called from AI)

**Definition of Done:**
- Vulnerability scan queries NVD for all SBOM components with CPE identifiers
- CVE matches are stored in `sbom_vulnerabilities` with CVSS scores and severity
- Findings are auto-created with `source='sbom_scan'` and grouped by component (not one per CVE)
- Findings include CVE IDs, CVSS scores, and evidence text explaining the inherited nature
- NVD rate limiting is respected (graceful with/without API key)
- All REST endpoints return correct data
- AI tools allow the assistant to generate SBOMs and run vulnerability scans during chat
- Second scan returns cached results unless `force_rescan=True`

#### Session 9.3: Frontend — SBOM Viewer & Vulnerability Dashboard

**Do:**
- Add TypeScript types to `src/types/index.ts`:
  ```typescript
  export type DetectionSource = 'package_manager' | 'binary_strings' | 'library_soname' | 'kernel_modules' | 'config_file'
  export type DetectionConfidence = 'high' | 'medium' | 'low'
  export type FindingSource = 'manual' | 'ai_discovered' | 'sbom_scan' | 'fuzzing' | 'security_review'

  export interface SbomComponent {
    id: string
    firmware_id: string
    name: string
    version: string | null
    type: string
    cpe: string | null
    purl: string | null
    supplier: string | null
    detection_source: DetectionSource
    detection_confidence: DetectionConfidence
    file_paths: string[] | null
    metadata: Record<string, unknown>
    vulnerability_count: number
    created_at: string
  }

  export interface SbomVulnerability {
    id: string
    component_id: string
    cve_id: string
    cvss_score: number | null
    cvss_vector: string | null
    severity: Severity
    description: string | null
    published_date: string | null
    finding_id: string | null
    component_name: string | null
    component_version: string | null
  }

  export interface SbomSummary {
    total_components: int
    components_by_type: Record<string, number>
    components_with_vulns: number
    total_vulnerabilities: number
    vulns_by_severity: Record<string, number>
    scan_date: string | null
  }

  export interface VulnerabilityScanResult {
    status: string
    total_components_scanned: number
    total_vulnerabilities_found: number
    findings_created: number
    vulns_by_severity: Record<string, number>
  }
  ```
- Update `Finding` interface to include `source: FindingSource` and `component_id: string | null`
- Create API client in `src/api/sbom.ts`:
  - `generateSbom(projectId)` → `SbomComponent[]`
  - `getSbomComponents(projectId, filters?)` → `SbomComponent[]`
  - `exportSbom(projectId, format)` → blob download
  - `runVulnerabilityScan(projectId, forceRescan?)` → `VulnerabilityScanResult`
  - `getVulnerabilities(projectId, filters?)` → `SbomVulnerability[]`
  - `getVulnerabilitySummary(projectId)` → `SbomSummary`
- Create `frontend/src/pages/SbomPage.tsx`:
  - **SBOM tab:**
    - "Generate SBOM" button (shown if no SBOM exists yet, or "Regenerate" if one exists)
    - Component table with sortable columns: Name, Version, Type, Detection Source, Confidence, Vulns
    - Filter by component type (application, library, operating-system)
    - Search by component name
    - Click a component row to expand and show: file paths, CPE, PURL, associated vulnerabilities
    - Color-coded vulnerability count badge per component (red for critical/high, orange for medium, gray for low/none)
    - "Export SBOM" button (CycloneDX JSON download)
  - **Vulnerabilities tab:**
    - "Scan for Vulnerabilities" button with loading state (NVD queries can take 30-60s for large SBOMs)
    - Summary cards at the top: total vulns, critical, high, medium, low — styled like a dashboard
    - Vulnerability table: CVE ID (linked to NVD), Component, Version, CVSS Score, Severity, Published Date
    - Filter by severity, component
    - Click a CVE row to see full description and link to the auto-generated finding
  - **Both tabs** share a header showing: firmware name, total components identified, last scan date
- Update `FindingsList.tsx`:
  - Add a "Source" column or badge showing finding origin: "Manual", "AI Discovered", "SBOM Scan", "Fuzzing", "Security Review"
  - SBOM scan findings show a distinct visual treatment: a package icon and "Inherited Vulnerability" subtitle
  - Add filter by source to the findings filter controls
  - When clicking an SBOM-sourced finding, show a link to the associated component in the SBOM viewer
- Add route: `/projects/:id/sbom`
- Add "SBOM" navigation item to the project sidebar (between "Map" and "Emulation" or after "Findings")

**Definition of Done:**
- SBOM page displays all identified components in a sortable, filterable table
- Can generate and regenerate SBOM from the UI
- Can trigger vulnerability scan and see results with severity breakdown
- Vulnerability results link to auto-created findings
- Findings list distinguishes SBOM-sourced findings with "Inherited Vulnerability" badge and source filter
- CycloneDX JSON export downloads correctly
- Loading states for SBOM generation (fast) and vulnerability scanning (slower due to NVD queries)
- Empty states for projects with no SBOM generated yet

---

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

**Definition of Done:**
- AFL++ with QEMU mode can fuzz ARM/MIPS/x86 binaries from the extracted firmware
- Campaigns can be created, started, stopped, and monitored
- Crash inputs are collected and deduplicated
- Crash triage produces stack traces and exploitability classification

#### Session 10.2: Fuzzing API & Database

**Do:**
- Create Alembic migration for `fuzzing_campaigns` table:
  ```sql
  CREATE TABLE fuzzing_campaigns (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      project_id UUID REFERENCES projects(id) ON DELETE CASCADE,
      firmware_id UUID REFERENCES firmware(id) ON DELETE CASCADE,
      binary_path VARCHAR(512) NOT NULL,
      status VARCHAR(20) DEFAULT 'created',  -- created, running, stopped, completed, error
      config JSONB,                           -- AFL++ configuration
      stats JSONB,                            -- latest fuzzer statistics
      crashes_count INTEGER DEFAULT 0,
      started_at TIMESTAMPTZ,
      stopped_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ DEFAULT NOW()
  );
  ```
- Create Pydantic schemas in `app/schemas/fuzzing.py`
- Create `app/routers/fuzzing.py`:
  - `POST /api/v1/projects/{id}/fuzzing/campaigns` — create a new fuzzing campaign
  - `POST /api/v1/projects/{id}/fuzzing/campaigns/{cid}/start` — start fuzzing
  - `POST /api/v1/projects/{id}/fuzzing/campaigns/{cid}/stop` — stop fuzzing
  - `GET /api/v1/projects/{id}/fuzzing/campaigns` — list campaigns
  - `GET /api/v1/projects/{id}/fuzzing/campaigns/{cid}` — campaign details + stats
  - `GET /api/v1/projects/{id}/fuzzing/campaigns/{cid}/crashes` — list crash inputs
  - `POST /api/v1/projects/{id}/fuzzing/campaigns/{cid}/crashes/{crash_id}/triage` — triage a crash
  - `GET /api/v1/projects/{id}/fuzzing/analyze?path=` — analyze a binary for fuzzing suitability
- Register router in `app/main.py`

**Definition of Done:**
- All CRUD and lifecycle endpoints work for fuzzing campaigns
- Campaign stats update in real-time (or near-real-time via polling)
- Crash list and triage endpoints return useful data
- Binary analysis endpoint identifies good fuzzing targets

#### Session 10.3: Fuzzing Frontend

**Do:**
- Create `frontend/src/pages/FuzzingPage.tsx`:
  - Campaign list: shows all fuzzing campaigns with status, duration, crashes found
  - Campaign creation wizard:
    1. Select target binary (file picker from extracted filesystem)
    2. Show AI analysis of the binary (fuzzing suitability, recommended strategy)
    3. Configure options: timeout per execution, memory limit, custom dictionary, seed corpus upload
    4. Start fuzzing
  - Active campaign dashboard:
    - Real-time stats: executions/sec, total executions, paths discovered, crashes, hangs
    - Coverage progress chart (paths over time)
    - Crash list with severity indicators
    - Stop/restart controls
  - Crash detail view:
    - Crash input (hex dump)
    - Stack trace
    - Exploitability classification (exploitable, probably exploitable, probably not, unknown)
    - Button to create a finding from a crash
    - Button to reproduce in emulation
- Add route: `/projects/:id/fuzzing`
- Add "Fuzzing" navigation item to the project sidebar
- Add API client functions in `src/api/fuzzing.ts`
- Add types to `src/types/index.ts`: `FuzzingCampaign`, `FuzzingStats`, `FuzzingCrash`, etc.

**Definition of Done:**
- Can create, start, stop, and monitor fuzzing campaigns from the UI
- Real-time stats dashboard shows fuzzing progress
- Crash list displays with severity and triage info
- Can create security findings from discovered crashes
- Campaign wizard guides users through setup

#### Session 10.4: Fuzzing AI Integration — Smart Target Selection & Harness Generation

**Do:**
- Add fuzzing-related AI tools to `app/ai/tools/`:
  - `analyze_fuzzing_target` — analyze a binary and recommend fuzzing strategy, input format, and interesting functions to target
  - `generate_fuzzing_harness` — generate a C shim/harness for fuzzing a specific function:
    - Wraps the target function with AFL's `__AFL_LOOP` for persistent mode (if recompilation is possible)
    - Creates a standalone harness that reads from stdin/file and calls the target function
    - Handles library dependencies and initialization
  - `generate_fuzzing_dictionary` — analyze the binary's strings, protocol keywords, and magic bytes to generate an AFL dictionary file
  - `generate_seed_corpus` — create initial seed inputs based on the binary's expected input format (file headers, protocol messages, config syntax)
  - `start_fuzzing_campaign` — start a fuzzing campaign with AI-recommended settings
  - `check_fuzzing_status` — check campaign progress
  - `triage_fuzzing_crash` — analyze a crash and explain the vulnerability
- Update system prompt to include fuzzing workflow:
  - AI should proactively suggest fuzzing targets during security assessment
  - AI should explain its fuzzing strategy choices
  - AI should triage crashes and determine exploitability
  - AI should generate findings for confirmed crashes
- Smart target selection heuristics (used by both AI and binary analysis endpoint):
  - Prioritize binaries that: parse untrusted input (file formats, network protocols), are network-facing, lack binary protections (no canaries, no ASLR), have known dangerous function calls (strcpy, sprintf, system)
  - Score and rank targets by fuzzing value

**Definition of Done:**
- AI can recommend the best fuzzing targets and explain why
- AI can generate harnesses and dictionaries for selected targets
- AI can start fuzzing campaigns and monitor progress
- AI triages crashes and creates findings with vulnerability descriptions
- The fuzzing workflow is AI-guided but user-controllable

---

### Phase 11: Project Export & Import (Sessions 39–41)

**Goal:** Enable users to export entire projects as portable archive files and import them on another instance, supporting team collaboration, project sharing, and backup/restore workflows. This phase is intentionally last (before polish) so the archive format captures all features: findings, conversations, documents, analysis cache, SBOM data, emulation configs, and fuzzing campaigns.

#### Session 11.1: Export Backend — Project Archive Builder

**Do:**
- Create `app/services/export_service.py` — builds a self-contained project archive:
  - Archive format: ZIP file containing:
    - `manifest.json` — archive version, export timestamp, source instance info
    - `project.json` — project metadata (name, description, status, created_at, etc.)
    - `firmware.json` — firmware metadata (original_filename, sha256, architecture, endianness, os_info, unpack_log)
    - `firmware/original/` — the original uploaded firmware blob
    - `firmware/extracted/` — the full unpacked filesystem tree (preserve permissions via tar within the zip, or store a `permissions.json` manifest)
    - `conversations/` — one JSON file per conversation with full message history
    - `findings/` — all findings as JSON (title, severity, description, evidence, file_path, status, cve_ids)
    - `documents/` — project documents (notes) with metadata and content
    - `analysis_cache/` — cached analysis results (component map, Ghidra decompilations, code cleanups, etc.) as JSON keyed by operation
    - `sbom/` — SBOM components and vulnerability scan results as JSON
    - `fuzzing_campaigns/` — fuzzing campaign configs, stats, and crash inputs
    - `reviews/` — security review results and agent findings
  - Stream the ZIP to avoid loading everything into memory — use `zipfile.ZipFile` with a streaming response or write to a temp file
  - Include a progress callback for future real-time status updates
- Create `app/routers/export_import.py`:
  - `POST /api/v1/projects/{id}/export` — triggers archive creation, returns the ZIP as a streaming file download
  - Set `Content-Disposition: attachment; filename="{project_name}_{date}.wairz"` header
  - Use `.wairz` file extension (it's a ZIP internally) for branding
- Validate that the project exists and has firmware before allowing export
- Handle large projects: set a reasonable timeout (10 minutes), stream the response

**Definition of Done:**
- Can export a project with unpacked firmware to a `.wairz` archive
- Archive contains all project data: metadata, firmware, filesystem, conversations, findings, documents, cache, SBOM, fuzzing campaigns, reviews
- Download starts promptly even for large projects (streaming)
- Archive can be opened as a standard ZIP for inspection

#### Session 11.2: Import Backend — Project Archive Importer

**Do:**
- Add import logic to `app/services/export_service.py` (or create `app/services/import_service.py`):
  - Validate the uploaded archive:
    - Must be a valid ZIP
    - Must contain `manifest.json` with a recognized version
    - Must contain `project.json` and `firmware.json`
  - Create a new project from `project.json` (generate new UUID, preserve name/description)
  - Restore firmware metadata from `firmware.json` (generate new firmware UUID)
  - Extract `firmware/original/` to the storage root
  - Extract `firmware/extracted/` to the storage root (restore file permissions from manifest if available)
  - Restore conversations, findings, documents, analysis cache, SBOM data, fuzzing campaigns, and reviews into the database
  - Remap all UUIDs: project_id, firmware_id, conversation_ids, finding_ids, document_ids, component_ids, campaign_ids, review_ids — generate new ones while preserving internal references
  - Set project status to `ready` if extracted filesystem is present, otherwise `created`
- Add to `app/routers/export_import.py`:
  - `POST /api/v1/projects/import` — accepts a multipart file upload of a `.wairz` archive
  - Returns the newly created project metadata
  - Validate archive size (use `MAX_UPLOAD_SIZE_MB` setting or a separate limit)
- Security: validate all paths within the archive against path traversal (zip slip prevention)
- Register router in `app/main.py`

**Definition of Done:**
- Can import a `.wairz` archive and get a fully functional project
- All data is restored: firmware, filesystem, conversations, findings, documents, cache, SBOM, fuzzing campaigns, reviews
- Imported project works identically to the original (can browse files, view findings, chat with AI, see SBOM/vulnerability data, see fuzzing results)
- ZIP slip and path traversal attacks are prevented
- Duplicate imports create separate projects (no conflicts)

#### Session 11.3: Export/Import Frontend

**Do:**
- Add export button to `ProjectDetailPage.tsx`:
  - Button in the project header/actions area: "Export Project"
  - Shows a loading/progress indicator while the archive is being built
  - Triggers file download when complete
  - Disable during export to prevent double-clicks
- Add import functionality to `ProjectsPage.tsx`:
  - "Import Project" button alongside "Create Project"
  - File picker that accepts `.wairz` files
  - Upload progress bar (reuse `FirmwareUpload.tsx` pattern)
  - On success: redirect to the imported project's detail page
  - Error handling: show clear messages for invalid archives, corrupt files, etc.
- Add API client functions in `src/api/projects.ts`:
  - `exportProject(projectId)` — returns a download URL or triggers blob download
  - `importProject(file: File)` — uploads the archive, returns the new project
- Update `projectStore.ts` if needed for import state tracking

**Definition of Done:**
- Can export a project from the UI and download a `.wairz` file
- Can import a `.wairz` file from the UI and see the restored project
- Progress indicators show during both export and import
- Error messages are clear and actionable

---

### Phase 12: Polish & Release (Sessions 42–45)

#### Session 12.1: Background Tasks & Status

**Do:**
- Set up `arq` worker with Redis
- Move firmware unpacking to background worker
- Add real-time status updates via WebSocket or polling
- Add progress indicators for long-running operations (Ghidra analysis, full scan, emulation startup, fuzzing)

#### Session 12.2: Error Handling & Edge Cases

**Do:**
- Handle: corrupt firmware, unsupported formats, very large files, empty filesystems
- Add request validation everywhere
- Add rate limiting on API endpoints
- Add graceful shutdown handling
- Comprehensive error messages for users
- Handle emulation and fuzzing edge cases (unsupported architectures, missing kernels, insufficient resources)

#### Session 12.3: Documentation & Testing

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
  - SBOM generation → vulnerability scan → findings creation
  - Export → import round-trip
  - Emulation start → terminal → stop
  - Fuzzing campaign lifecycle
- Add example firmware images for testing (OpenWrt, DD-WRT, etc.)

#### Session 12.4: Final Integration & Release

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
3. **Never execute firmware binaries on the host.** All static analysis is read-only. The only exception is the emulation subsystem (Phase 8), which runs firmware inside an isolated QEMU container with no host network access, resource limits, and a non-root user. The emulation container must be treated as untrusted — it should never share volumes read-write with the backend or have access to credentials.
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
NVD_API_KEY=                         # Optional NVD API key for higher rate limits (6 req/s vs 0.6 req/s)
SBOM_CVE_DB_CACHE_DIR=/data/cve-db   # Local cache directory for NVD CVE data
EMULATION_TIMEOUT_MINUTES=30
EMULATION_KERNEL_DIR=/opt/emulation/kernels
EMULATION_MAX_SESSIONS=3
EMULATION_MEMORY_LIMIT_MB=512
EMULATION_CPU_LIMIT=1.0
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
