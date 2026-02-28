# File Explorer

The File Explorer provides a browser-based interface for navigating extracted firmware filesystems.

## Filesystem Tree

The left panel shows a navigable directory tree of the extracted firmware. Directories are lazy-loaded on expand to handle firmware images with thousands of files.

- Click directories to expand/collapse
- Click files to view their contents
- File icons indicate type (binary, config, script, etc.)

## File Viewer

The right panel displays file contents with multiple view modes:

- **Text** — Syntax-highlighted source code and config files using Monaco Editor
- **Hex** — Hex dump view for binary files
- **Info** — File metadata including size, permissions, MIME type, and SHA256 hash

## Search

Search across the firmware filesystem:

- **File search** — Find files by glob pattern (e.g., `*.conf`, `passwd`)
- **Content search** — Search file contents with regex patterns
- **Type search** — Find files by type: ELF binaries, shell scripts, configs, certificates, Python, Lua, libraries, databases, web files

## Component Map

The Component Map provides an interactive dependency graph showing relationships between firmware components:

- **Binaries** linked to their shared libraries
- **Scripts** and their execution targets
- **Init scripts** and the services they start
- **Configuration files** associated with services

The graph uses ReactFlow with automatic Dagre layout for clear visualization of complex dependency chains.

## MCP Tools

When using Claude via MCP, these tools provide filesystem access:

| Tool | Description |
|------|-------------|
| `list_directory` | List contents of a directory |
| `read_file` | Read file contents (text or hex dump) |
| `search_files` | Search by glob pattern |
| `file_info` | Get file metadata, permissions, hash |
| `find_files_by_type` | Find files by type category |
| `get_component_map` | Get the component dependency graph |
| `get_firmware_metadata` | Get firmware image structure metadata |
| `extract_bootloader_env` | Extract U-Boot environment variables |
