# Wairz

**AI-assisted firmware reverse engineering and security assessment platform.**

Upload firmware images, unpack them, explore the filesystem, analyze binaries, and conduct security assessments — all powered by AI analysis via [Model Context Protocol (MCP)](https://modelcontextprotocol.io/).

Connect [Claude Code](https://docs.anthropic.com/en/docs/claude-code) or [Claude Desktop](https://claude.ai/download) to Wairz's 60+ analysis tools through MCP, and use your own Claude subscription for AI-driven firmware security research.

---

## Key Features

<div class="grid cards" markdown>

- :material-folder-search: **File Explorer**

    Browse extracted filesystems with a virtual tree, view text/binary/hex content, and search across files.

- :material-code-braces: **Binary Analysis**

    Disassemble and decompile binaries using Ghidra headless, with cross-references, dataflow tracing, and stack layout analysis.

- :material-shield-alert: **Security Assessment**

    Detect hardcoded credentials, crypto material, setuid binaries, insecure configs, and weak permissions.

- :material-format-list-checks: **SBOM & CVE Scanning**

    Generate Software Bill of Materials and scan components against the NVD for known vulnerabilities.

- :material-play-box: **Emulation**

    Boot firmware in QEMU (user-mode or system-mode) in isolated containers, with GDB debugging support.

- :material-bug: **Fuzzing**

    AFL++ with QEMU mode for cross-architecture binary fuzzing, with automatic dictionary/corpus generation and crash triage.

- :material-compare: **Firmware Comparison**

    Diff filesystem trees, binaries, and decompiled functions across firmware versions for patch analysis.

- :material-console: **UART Console**

    Connect to physical devices via a host-side serial bridge for interactive console access.

- :material-robot: **AI Analysis via MCP**

    60+ analysis tools exposed to Claude for autonomous security research — from filesystem exploration to vulnerability discovery.

- :material-file-document: **Findings & Reports**

    Record security findings with severity ratings and evidence, export as Markdown or PDF.

</div>

---

## Quick Start

```bash
git clone https://github.com/digitalandrew/wairz.git
cd wairz
cp .env.example .env
docker compose up --build
```

Then open [http://localhost:3000](http://localhost:3000) to access the web interface.

See the [Installation Guide](getting-started/installation.md) for detailed setup instructions, or jump to [Connecting AI](getting-started/mcp-setup.md) to set up Claude with MCP.

---

## How It Works

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
```

1. **Upload** a firmware image through the web UI
2. **Wairz unpacks** the firmware automatically (SquashFS, JFFS2, UBIFS, CramFS, ext, CPIO)
3. **Explore** the extracted filesystem, analyze binaries, and assess security — through the browser or AI
4. **Connect Claude** via MCP to run autonomous analysis with 60+ specialized tools

---

## License

Wairz is open source under the [AGPL-3.0 License](https://github.com/digitalandrew/wairz/blob/main/LICENSE).
