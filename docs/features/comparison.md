# Firmware Comparison

Wairz can compare firmware versions to identify changes between releases — useful for patch analysis, understanding what a vendor fixed or modified.

## Filesystem Diff

Compare two firmware versions' filesystems to see:

- **Added files** — New files in the newer version
- **Removed files** — Files deleted in the newer version
- **Modified files** — Files with changed content (compared by hash)
- **Permission changes** — Files with changed permissions

## Binary Diff

Compare a specific binary between two firmware versions at the function level:

- **Added functions** — New functions in the newer version
- **Removed functions** — Functions deleted in the newer version
- **Modified functions** — Functions with size changes

## Decompilation Diff

Side-by-side decompilation comparison — decompile the same function from two firmware versions and produce a unified diff. Shows exactly what changed in the pseudo-C code.

This is the most detailed comparison level, useful for understanding precisely what a vendor patched.

## Usage

1. Upload multiple firmware versions to the same project
2. Use `list_firmware_versions` to see available versions and their IDs
3. Run comparison tools with the firmware IDs

## MCP Tools

| Tool | Description |
|------|-------------|
| `list_firmware_versions` | List uploaded firmware versions |
| `diff_firmware` | Compare filesystem trees |
| `diff_binary` | Compare binary functions |
| `diff_decompilation` | Side-by-side decompilation diff |
