# Quick Start

This guide walks you through uploading your first firmware image and running an initial analysis.

## 1. Create a Project

Open [http://localhost:3000](http://localhost:3000) and click **New Project**. Give it a name and optional description.

## 2. Upload Firmware

On the project page, click **Upload Firmware** and select a firmware image file. Wairz will automatically unpack it using binwalk, extracting supported filesystems:

- SquashFS, JFFS2, UBIFS, CramFS, ext, CPIO

The unpacking process runs in the background — the page will update automatically when it's done.

!!! tip "Test firmware"
    If you don't have a firmware image handy, try one of these:

    - **[OpenWrt](https://downloads.openwrt.org/)** — Well-structured embedded Linux (MIPS, ARM)
    - **[DD-WRT](https://dd-wrt.com/)** — Similar to OpenWrt
    - **[DVRF](https://github.com/praetorian-inc/DVRF)** (Damn Vulnerable Router Firmware) — Intentionally vulnerable, great for testing

## 3. Explore the Filesystem

Once unpacking completes, click **Explorer** to browse the extracted filesystem:

- Navigate the directory tree on the left
- View file contents (text, hex, or binary) on the right
- Use the search bar to find files by name or content

## 4. Analyze Binaries

Select any ELF binary in the file explorer to access analysis tools:

- **Functions** — List all functions, sorted by size
- **Decompile** — View Ghidra pseudo-C decompilation
- **Disassembly** — View assembly instructions
- **Imports/Exports** — See linked libraries and symbols
- **Protections** — Check NX, RELRO, canary, PIE, Fortify

## 5. Run Security Checks

Use the **Security** tab to run automated checks:

- Hardcoded credentials and crypto material
- Setuid/setgid binaries
- Configuration file analysis
- Filesystem permission issues

## 6. Connect AI for Deep Analysis

For the most powerful analysis, connect Claude via MCP. See [Connecting AI (MCP)](mcp-setup.md) for setup instructions. Once connected, Claude can autonomously:

- Explore the filesystem and identify interesting targets
- Decompile binaries and trace dataflows from user input to dangerous sinks
- Identify command injection, buffer overflow, and authentication bypass vulnerabilities
- Generate and run fuzzing campaigns
- Boot the firmware in emulation and test it dynamically
- Record findings with evidence and severity ratings
