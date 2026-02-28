# MCP Tools Reference

Wairz exposes 60+ tools to Claude via the Model Context Protocol. This page lists all available tools organized by category.

## Project

| Tool | Description |
|------|-------------|
| `get_project_info` | Get the currently active project details |
| `switch_project` | Switch to a different project without restarting |
| `list_projects` | List all available projects |

## Filesystem

| Tool | Description |
|------|-------------|
| `list_directory` | List contents of a directory (names, types, sizes, permissions) |
| `read_file` | Read file contents — text as UTF-8, binary as hex dump (max 50KB) |
| `search_files` | Search for files by glob pattern (max 100 results) |
| `file_info` | Get file metadata: type, MIME, size, permissions, SHA256, ELF headers |
| `find_files_by_type` | Find files by category: elf, shell_script, config, certificate, python, lua, library, database, web |
| `get_component_map` | Get the firmware component dependency graph |
| `get_firmware_metadata` | Get firmware image structure (partitions, U-Boot headers, MTD table) |
| `extract_bootloader_env` | Extract U-Boot environment variables |

## Strings

| Tool | Description |
|------|-------------|
| `extract_strings` | Extract and categorize strings from a file (URLs, IPs, emails, paths, credentials) |
| `search_strings` | Regex search across all text files in the firmware (like grep -rn) |
| `find_crypto_material` | Scan for private keys, certificates, SSH keys, PEM files |
| `find_hardcoded_credentials` | Find passwords, API keys, tokens with entropy ranking |

## Binary Analysis

| Tool | Description |
|------|-------------|
| `list_functions` | List functions sorted by size (largest first) |
| `decompile_function` | Ghidra pseudo-C decompilation |
| `disassemble_function` | Assembly instructions with addresses |
| `list_imports` | Imported symbols grouped by library |
| `list_exports` | Exported symbols with addresses |
| `xrefs_to` | Cross-references TO a function/symbol |
| `xrefs_from` | Cross-references FROM a function/symbol |
| `get_binary_info` | ELF metadata: architecture, endianness, linked libraries, entry point |
| `check_binary_protections` | Security protections: NX, RELRO, canary, PIE, Fortify, stripped |
| `check_all_binary_protections` | Scan all binaries, sorted by protection score |
| `find_string_refs` | Find functions referencing strings matching a pattern |
| `resolve_import` | Find which library implements an import and decompile it |
| `find_callers` | Find all call sites of a function (including aliases) |
| `search_binary_content` | Search for hex patterns, strings, or disassembly patterns |
| `get_stack_layout` | Stack frame layout with buffer-to-return-address distances |
| `get_global_layout` | Map global variables around a target symbol |
| `trace_dataflow` | Trace user input sources to dangerous sinks |
| `cross_binary_dataflow` | Trace data flows across binaries via IPC (nvram, config, file) |

## Security

| Tool | Description |
|------|-------------|
| `check_known_cves` | Look up CVEs for a component and version |
| `analyze_config_security` | Audit a configuration file for security issues |
| `check_setuid_binaries` | Find setuid/setgid binaries |
| `analyze_init_scripts` | Identify boot services and flag insecure ones |
| `check_filesystem_permissions` | Find world-writable and overly permissive files |
| `analyze_certificate` | Audit X.509 certificates for weaknesses |

## SBOM

| Tool | Description |
|------|-------------|
| `generate_sbom` | Generate Software Bill of Materials from firmware |
| `get_sbom_components` | List identified components (filter by type/name) |
| `check_component_cves` | Check one component against NVD |
| `run_vulnerability_scan` | Full CVE scan of all SBOM components |

## Emulation

| Tool | Description |
|------|-------------|
| `start_emulation` | Start QEMU emulation (user or system mode) |
| `run_command_in_emulation` | Execute a command in the emulated environment |
| `stop_emulation` | Stop a running session |
| `check_emulation_status` | Check session status or list all sessions |
| `get_emulation_logs` | Read QEMU boot logs and serial output |
| `enumerate_emulation_services` | List listening network services |
| `diagnose_emulation_environment` | Pre-flight check for common emulation issues |
| `troubleshoot_emulation` | Get troubleshooting advice for specific symptoms |
| `get_crash_dump` | Analyze core dumps from crashed binaries |
| `run_gdb_command` | Execute GDB commands via QEMU's GDB stub |
| `save_emulation_preset` | Save emulation config as a reusable preset |
| `list_emulation_presets` | List saved presets |
| `start_emulation_from_preset` | Start emulation from a saved preset |

## Fuzzing

| Tool | Description |
|------|-------------|
| `analyze_fuzzing_target` | Assess binary fuzzing suitability (score 0-100) |
| `generate_fuzzing_dictionary` | Extract strings for AFL++ dictionary |
| `generate_seed_corpus` | Generate minimal seed inputs |
| `generate_fuzzing_harness` | Get concrete fuzzing configuration |
| `start_fuzzing_campaign` | Launch AFL++ campaign |
| `check_fuzzing_status` | Monitor campaign statistics |
| `stop_fuzzing_campaign` | Stop a running campaign |
| `triage_fuzzing_crash` | Analyze crash exploitability |
| `diagnose_fuzzing_campaign` | Troubleshoot underperforming campaigns |

## Comparison

| Tool | Description |
|------|-------------|
| `list_firmware_versions` | List uploaded firmware versions |
| `diff_firmware` | Compare filesystem trees between versions |
| `diff_binary` | Compare binary functions between versions |
| `diff_decompilation` | Side-by-side decompilation diff |

## UART

| Tool | Description |
|------|-------------|
| `uart_connect` | Connect to a serial device via the host bridge |
| `uart_send_command` | Send command and wait for shell prompt |
| `uart_read` | Read from the receive buffer |
| `uart_send_break` | Send serial BREAK signal |
| `uart_send_raw` | Send raw bytes (text or hex) |
| `uart_disconnect` | Close the serial connection |
| `uart_status` | Check connection status |
| `uart_get_transcript` | Get session transcript with timestamps |

## Reporting

| Tool | Description |
|------|-------------|
| `add_finding` | Record a security finding with severity and evidence |
| `list_findings` | List findings (filter by severity/status) |
| `update_finding` | Update finding status or details |
| `read_project_instructions` | Read project-specific analysis instructions |
| `list_project_documents` | List supplementary project documents |
| `read_project_document` | Read a project document by ID |

## Code

| Tool | Description |
|------|-------------|
| `save_code_cleanup` | Save AI-cleaned decompiled code to the analysis cache |
