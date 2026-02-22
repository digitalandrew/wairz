"""Emulation AI tools for dynamic firmware analysis.

Tools for starting/stopping QEMU emulation sessions, executing commands
in running sessions, checking session status, listing available kernels,
reading boot logs, and diagnosing firmware emulation issues.
"""

import os

from app.ai.tool_registry import ToolContext, ToolRegistry
from app.config import get_settings
from app.models.emulation_preset import EmulationPreset
from app.models.emulation_session import EmulationSession
from app.models.firmware import Firmware
from app.services.emulation_service import EmulationService
from app.services.kernel_service import KernelService

from sqlalchemy import select


def register_emulation_tools(registry: ToolRegistry) -> None:
    """Register all emulation tools with the given registry."""

    registry.register(
        name="list_available_kernels",
        description=(
            "List pre-built Linux kernels available for system-mode emulation. "
            "System mode REQUIRES a kernel matching the firmware architecture. "
            "Use this tool to check what kernels are available before starting "
            "system-mode emulation. If no kernel matches, advise the user to "
            "upload one via the kernel management page."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "architecture": {
                    "type": "string",
                    "description": (
                        "Optional architecture filter (arm, aarch64, mips, mipsel, x86, x86_64). "
                        "If omitted, lists all kernels."
                    ),
                },
            },
        },
        handler=_handle_list_kernels,
    )

    registry.register(
        name="download_kernel",
        description=(
            "Download a pre-built Linux kernel from a URL and install it for "
            "system-mode emulation. Use this when no suitable kernel is available "
            "for the firmware's architecture. Before downloading, explain to the "
            "user which kernel you plan to download and why.\n\n"
            "Common trusted sources:\n"
            "- OpenWrt downloads (downloads.openwrt.org) — pre-built kernels for ARM, MIPS\n"
            "- kernel.org — official Linux kernel releases\n"
            "- GitHub releases — project-specific kernel builds\n\n"
            "The URL must be HTTPS (HTTP allowed but not recommended). "
            "Private/loopback IPs are blocked for security. "
            "The downloaded file is validated as a real kernel image before installation."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "Direct download URL for the kernel binary (must be https)",
                },
                "name": {
                    "type": "string",
                    "description": (
                        "Name for the kernel (alphanumeric, hyphens, underscores, dots). "
                        "Example: 'vmlinux-arm-openwrt-5.15'"
                    ),
                },
                "architecture": {
                    "type": "string",
                    "enum": ["arm", "aarch64", "mips", "mipsel", "x86", "x86_64"],
                    "description": "Target architecture for this kernel",
                },
                "description": {
                    "type": "string",
                    "description": "Optional description (e.g., 'OpenWrt 23.05 ARM kernel')",
                },
            },
            "required": ["url", "name", "architecture"],
        },
        handler=_handle_download_kernel,
    )

    registry.register(
        name="start_emulation",
        description=(
            "Start a QEMU-based emulation session for dynamic firmware analysis. "
            "User mode runs a single binary in a chroot (fast, good for testing "
            "specific programs). System mode boots the full firmware OS (slower, "
            "good for testing services and network behavior). "
            "For system mode, use list_available_kernels first to check that a "
            "matching kernel is available. You can specify kernel_name to select "
            "a specific kernel.\n\n"
            "SYSTEM MODE AUTO-SETUP: The emulator automatically mounts /proc, "
            "/sys, /dev, /tmp and configures networking (eth0 10.0.2.15/24, "
            "gateway 10.0.2.2) before starting the firmware init. You no longer "
            "need to do this manually.\n\n"
            "PRE-INIT SCRIPT: Use the pre_init_script parameter to run custom "
            "setup before the firmware's init starts. This is ideal for:\n"
            "- Setting LD_PRELOAD to inject stub libraries (e.g., fake MTD)\n"
            "- Starting dependent services (e.g., cfmd before httpd)\n"
            "- Creating config files or directories the firmware expects\n"
            "- Setting environment variables for the firmware's init\n\n"
            "Use emulation to VALIDATE static findings: test if default credentials "
            "work, check if services are accessible, verify network behavior. "
            "Always stop sessions when done to free resources."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "mode": {
                    "type": "string",
                    "enum": ["user", "system"],
                    "description": "Emulation mode: 'user' for single binary, 'system' for full OS boot",
                },
                "binary_path": {
                    "type": "string",
                    "description": "Path to binary within the firmware filesystem (required for user mode)",
                },
                "arguments": {
                    "type": "string",
                    "description": "Command-line arguments for the binary (user mode only)",
                },
                "port_forwards": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "host": {"type": "integer"},
                            "guest": {"type": "integer"},
                        },
                        "required": ["host", "guest"],
                    },
                    "description": "Port forwarding rules (system mode, e.g., [{host: 8080, guest: 80}])",
                },
                "kernel_name": {
                    "type": "string",
                    "description": (
                        "Name of a specific kernel to use (from list_available_kernels). "
                        "If omitted, auto-selects a kernel matching the firmware architecture."
                    ),
                },
                "init_path": {
                    "type": "string",
                    "description": (
                        "Override the init binary that runs AFTER the wairz init wrapper. "
                        "The wrapper always runs first (mounts filesystems, configures network, "
                        "runs pre_init_script), then execs this init. "
                        "If omitted, auto-detects from /sbin/init, /etc/preinit, etc. "
                        "Use '/bin/sh' for an interactive shell with all setup already done."
                    ),
                },
                "pre_init_script": {
                    "type": "string",
                    "description": (
                        "Shell script to run BEFORE the firmware's init starts but AFTER "
                        "the wairz init wrapper has mounted filesystems and configured "
                        "networking. The script runs inside the emulated system as PID 1's "
                        "child. Use this for firmware-specific setup like:\n"
                        "- export LD_PRELOAD=/path/to/fake_mtd.so\n"
                        "- mkdir -p /cfg && cp /webroot/default.cfg /cfg/mib.cfg\n"
                        "- /bin/cfmd &\n"
                        "- sleep 1 && /bin/httpd &\n"
                        "The script is sourced (not exec'd), so environment variables "
                        "set here are inherited by the firmware's init."
                    ),
                },
            },
            "required": ["mode"],
        },
        handler=_handle_start_emulation,
    )

    registry.register(
        name="run_command_in_emulation",
        description=(
            "Execute a command inside a running emulation session. "
            "Returns stdout, stderr, and exit code. "
            "Use this for dynamic analysis: check running services, test credentials, "
            "inspect network configuration, run binaries with different inputs. "
            "Default timeout is 30 seconds, max 120 seconds. "
            "IMPORTANT: This uses a serial console — keep commands simple and short. "
            "Run ONE command per call. Do NOT use pipes (|), chaining (&&, ;), "
            "backgrounding (&), or subshells — these are unreliable over serial "
            "and often return empty output. Run separate tool calls instead. "
            "If a previous command is stuck (e.g., a foreground daemon), set "
            "send_ctrl_c=true to send Ctrl-C before executing the new command."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "session_id": {
                    "type": "string",
                    "description": "The emulation session ID",
                },
                "command": {
                    "type": "string",
                    "description": "Shell command to execute",
                },
                "timeout": {
                    "type": "integer",
                    "description": "Command timeout in seconds (default 30, max 120)",
                },
                "environment": {
                    "type": "object",
                    "additionalProperties": {"type": "string"},
                    "description": (
                        "Environment variables to set for this command "
                        "(e.g., {\"LD_LIBRARY_PATH\": \"/lib\", \"DEBUG\": \"1\"})"
                    ),
                },
                "send_ctrl_c": {
                    "type": "boolean",
                    "description": (
                        "Send Ctrl-C to the serial console before executing the command. "
                        "Use this to recover from a stuck foreground process (e.g., a "
                        "daemon that didn't background itself). Only applies to system-mode sessions."
                    ),
                },
            },
            "required": ["session_id", "command"],
        },
        handler=_handle_run_command,
    )

    registry.register(
        name="stop_emulation",
        description=(
            "Stop a running emulation session and free its resources. "
            "Always stop sessions when you are done with dynamic analysis."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "session_id": {
                    "type": "string",
                    "description": "The emulation session ID to stop",
                },
            },
            "required": ["session_id"],
        },
        handler=_handle_stop_emulation,
    )

    registry.register(
        name="check_emulation_status",
        description=(
            "Check the status of an emulation session, or list all active sessions "
            "for the current project if no session_id is given. "
            "Returns session status, mode, architecture, and uptime."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "session_id": {
                    "type": "string",
                    "description": "Optional session ID. If omitted, lists all sessions for the project.",
                },
            },
        },
        handler=_handle_check_status,
    )

    registry.register(
        name="get_emulation_logs",
        description=(
            "Read QEMU boot logs and serial console output from an emulation session. "
            "Use this to diagnose WHY emulation failed or why the firmware isn't booting "
            "correctly. Works on both running and recently-stopped/errored sessions. "
            "The logs contain kernel boot messages, init script output, error messages, "
            "and any panic/crash information. Always check logs when emulation status "
            "is 'error' or when commands timeout."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "session_id": {
                    "type": "string",
                    "description": "The emulation session ID to read logs from",
                },
            },
            "required": ["session_id"],
        },
        handler=_handle_get_logs,
    )

    registry.register(
        name="diagnose_emulation_environment",
        description=(
            "Pre-flight check: inspect the firmware filesystem for known issues that "
            "cause emulation failures. Run this BEFORE starting system-mode emulation, "
            "or AFTER a failed boot to understand what went wrong. "
            "Checks for: broken symlinks (e.g., /etc -> /dev/null), missing init binary, "
            "missing /etc/passwd, architecture mismatches, missing shared libraries, "
            "and other common embedded firmware quirks. "
            "Returns a structured report with issues found and suggested fixes "
            "(e.g., use init_path=/bin/sh, or which commands to run to fix the environment)."
        ),
        input_schema={
            "type": "object",
            "properties": {},
        },
        handler=_handle_diagnose_environment,
    )

    registry.register(
        name="troubleshoot_emulation",
        description=(
            "Get a firmware-aware troubleshooting guide for system-mode emulation issues. "
            "Call this when emulation isn't working as expected — services not listening, "
            "boot hangs, kernel panics, MTD errors, network issues, etc. "
            "Returns structured advice tailored to the firmware's characteristics "
            "(detected from the filesystem). Optionally pass a symptom keyword to "
            "filter to the most relevant section."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "symptom": {
                    "type": "string",
                    "description": (
                        "Optional symptom to filter advice. Keywords: "
                        "'service_not_listening', 'boot_hang', 'kernel_panic', "
                        "'network', 'mtd', 'crash', 'httpd', or free text."
                    ),
                },
            },
        },
        handler=_handle_troubleshoot_emulation,
    )

    # ── Emulation Presets ──

    registry.register(
        name="save_emulation_preset",
        description=(
            "Save the current emulation configuration as a named preset for this project. "
            "Use this after iterating to a working emulation setup so you can re-use it "
            "without re-entering all the configuration. Presets are per-project."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "name": {
                    "type": "string",
                    "description": "Name for the preset (e.g., 'Tenda AC8 httpd')",
                },
                "description": {
                    "type": "string",
                    "description": "Optional description of what this preset does",
                },
                "mode": {
                    "type": "string",
                    "enum": ["user", "system"],
                    "description": "Emulation mode",
                },
                "binary_path": {
                    "type": "string",
                    "description": "Binary path (for user mode)",
                },
                "arguments": {
                    "type": "string",
                    "description": "Command-line arguments (for user mode)",
                },
                "port_forwards": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "host": {"type": "integer"},
                            "guest": {"type": "integer"},
                        },
                        "required": ["host", "guest"],
                    },
                    "description": "Port forwarding rules",
                },
                "kernel_name": {
                    "type": "string",
                    "description": "Kernel name (for system mode)",
                },
                "init_path": {
                    "type": "string",
                    "description": "Init override path (for system mode)",
                },
                "pre_init_script": {
                    "type": "string",
                    "description": "Pre-init shell script (for system mode)",
                },
            },
            "required": ["name", "mode"],
        },
        handler=_handle_save_preset,
    )

    registry.register(
        name="list_emulation_presets",
        description=(
            "List all saved emulation presets for the current project. "
            "Shows preset names, modes, and descriptions."
        ),
        input_schema={
            "type": "object",
            "properties": {},
        },
        handler=_handle_list_presets,
    )

    registry.register(
        name="start_emulation_from_preset",
        description=(
            "Start an emulation session using a saved preset's configuration. "
            "Loads the preset by name or ID and starts emulation with its settings."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "preset_name": {
                    "type": "string",
                    "description": "Name of the preset to use (case-insensitive match)",
                },
                "preset_id": {
                    "type": "string",
                    "description": "UUID of the preset (alternative to preset_name)",
                },
            },
        },
        handler=_handle_start_from_preset,
    )


# ---------------------------------------------------------------------------
# Tool handlers
# ---------------------------------------------------------------------------


async def _handle_list_kernels(input: dict, context: ToolContext) -> str:
    """List available kernels for system-mode emulation."""
    architecture = input.get("architecture")

    svc = KernelService()
    kernels = svc.list_kernels(architecture=architecture)

    if not kernels:
        arch_msg = f" for architecture '{architecture}'" if architecture else ""
        return (
            f"No kernels available{arch_msg}.\n\n"
            "System-mode emulation requires a pre-built Linux kernel matching the "
            "firmware's architecture. The user needs to upload a kernel via the "
            "Emulation page's kernel management section.\n\n"
            "Common kernel sources:\n"
            "- OpenWrt downloads (https://downloads.openwrt.org/) — pre-built kernels for ARM, MIPS\n"
            "- Buildroot — custom kernel builds for any architecture\n"
            "- Debian cross-compiled kernel packages (linux-image-*)\n"
            "- QEMU test kernels from various Linux distribution repos\n\n"
            "Advise the user to upload a kernel matching the firmware architecture, "
            "then retry system-mode emulation."
        )

    lines = [f"Available kernels ({len(kernels)}):\n"]
    for k in kernels:
        size_mb = k["file_size"] / (1024 * 1024)
        desc = f" — {k['description']}" if k.get("description") else ""
        lines.append(f"  {k['name']} [{k['architecture']}] ({size_mb:.1f} MB){desc}")

    return "\n".join(lines)


async def _handle_download_kernel(input: dict, context: ToolContext) -> str:
    """Download and install a kernel from a URL."""
    url = input.get("url", "")
    name = input.get("name", "")
    architecture = input.get("architecture", "")
    description = input.get("description", "")

    if not url or not name or not architecture:
        return "Error: url, name, and architecture are required."

    svc = KernelService()
    try:
        result = svc.list_kernels()
        existing = [k["name"] for k in result]
        if name in existing:
            return f"Error: a kernel named '{name}' already exists. Choose a different name."

        kernel_info = await svc.download_kernel(
            url=url,
            name=name,
            architecture=architecture,
            description=description,
        )
        size_mb = kernel_info["file_size"] / (1024 * 1024)
        return (
            f"Kernel downloaded and installed successfully.\n"
            f"  Name: {kernel_info['name']}\n"
            f"  Architecture: {kernel_info['architecture']}\n"
            f"  Size: {size_mb:.1f} MB\n"
            f"  Source: {url}\n\n"
            "The kernel is now available for system-mode emulation. "
            "You can use start_emulation with kernel_name='"
            f"{kernel_info['name']}' or it will be auto-selected for "
            f"{architecture} firmware."
        )
    except ValueError as exc:
        return f"Error downloading kernel: {exc}"
    except Exception as exc:
        return f"Error downloading kernel: {exc}"


async def _handle_start_emulation(input: dict, context: ToolContext) -> str:
    """Start an emulation session."""
    mode = input.get("mode", "user")
    binary_path = input.get("binary_path")
    arguments = input.get("arguments")
    port_forwards = input.get("port_forwards", [])
    kernel_name = input.get("kernel_name")
    init_path = input.get("init_path")
    pre_init_script = input.get("pre_init_script")

    if mode == "user" and not binary_path:
        return "Error: binary_path is required for user-mode emulation."

    # For system mode, auto-run diagnosis first to give immediate context
    diagnosis_summary = ""
    if mode == "system":
        try:
            diagnosis_summary = await _handle_diagnose_environment({}, context)
        except Exception:
            diagnosis_summary = "(diagnosis failed — continuing with emulation start)"

    # Get firmware record
    result = await context.db.execute(
        select(Firmware).where(Firmware.id == context.firmware_id)
    )
    firmware = result.scalar_one_or_none()
    if not firmware:
        return "Error: firmware not found."

    svc = EmulationService(context.db)
    try:
        session = await svc.start_session(
            firmware=firmware,
            mode=mode,
            binary_path=binary_path,
            arguments=arguments,
            port_forwards=port_forwards,
            kernel_name=kernel_name,
            init_path=init_path,
            pre_init_script=pre_init_script,
        )
        await context.db.commit()
    except ValueError as exc:
        return f"Error starting emulation: {exc}"
    except Exception as exc:
        return f"Error starting emulation: {exc}"

    lines = [
        f"Emulation session started successfully.",
        f"  Session ID: {session.id}",
        f"  Mode: {session.mode}",
        f"  Architecture: {session.architecture}",
        f"  Status: {session.status}",
    ]
    if session.binary_path:
        lines.append(f"  Binary: {session.binary_path}")
    if session.error_message:
        lines.append(f"  Error: {session.error_message}")
    if session.port_forwards:
        pf_strs = [f"{pf['host']}→{pf['guest']}" for pf in session.port_forwards]
        lines.append(f"  Port forwards: {', '.join(pf_strs)}")

    if session.mode == "system":
        lines.append("")
        lines.append(
            "Auto-setup: /proc, /sys, /dev, /tmp mounted; "
            "networking configured (eth0 10.0.2.15/24, gw 10.0.2.2)."
        )
        if pre_init_script:
            lines.append("Pre-init script: injected and will run before firmware init.")

    lines.append("")
    lines.append(
        "Note: emulated firmware may behave differently than on real hardware "
        "(missing peripherals, different timing). Note these limitations when "
        "reporting findings."
    )
    lines.append(
        "Use run_command_in_emulation with the session ID to execute commands, "
        "and stop_emulation when done."
    )

    # Append diagnosis for system-mode starts
    if diagnosis_summary:
        lines.append("")
        lines.append("--- Pre-flight Diagnosis ---")
        lines.append(diagnosis_summary)

    return "\n".join(lines)


async def _handle_run_command(input: dict, context: ToolContext) -> str:
    """Execute a command in a running emulation session."""
    session_id = input.get("session_id")
    command = input.get("command")
    timeout = min(input.get("timeout", 30), 120)
    environment = input.get("environment")
    send_ctrl_c = input.get("send_ctrl_c", False)

    if not session_id or not command:
        return "Error: session_id and command are required."

    svc = EmulationService(context.db)

    # Send Ctrl-C first if requested (to recover from stuck foreground process)
    if send_ctrl_c:
        try:
            from uuid import UUID as _UUID
            ctrl_c_result = await svc.send_ctrl_c(_UUID(session_id))
            if not ctrl_c_result.get("success"):
                return f"Error sending Ctrl-C: {ctrl_c_result.get('message', 'unknown error')}"
            # Brief pause to let the shell settle after Ctrl-C
            import asyncio
            await asyncio.sleep(0.5)
        except ValueError as exc:
            return f"Error sending Ctrl-C: {exc}"

    try:
        from uuid import UUID
        result = await svc.exec_command(
            session_id=UUID(session_id),
            command=command,
            timeout=timeout,
            environment=environment,
        )
    except ValueError as exc:
        return f"Error: {exc}"
    except Exception as exc:
        return f"Error executing command: {exc}"

    lines = []
    if result["timed_out"]:
        lines.append(f"[Command timed out after {timeout}s]")

    if result["stdout"]:
        lines.append(f"stdout:\n{result['stdout']}")
    if result["stderr"]:
        lines.append(f"stderr:\n{result['stderr']}")

    lines.append(f"exit_code: {result['exit_code']}")

    # Truncate output
    settings = get_settings()
    max_bytes = settings.max_tool_output_kb * 1024
    output = "\n".join(lines)
    if len(output) > max_bytes:
        output = output[:max_bytes] + f"\n... [output truncated at {settings.max_tool_output_kb}KB]"

    return output


async def _handle_stop_emulation(input: dict, context: ToolContext) -> str:
    """Stop an emulation session."""
    session_id = input.get("session_id")
    if not session_id:
        return "Error: session_id is required."

    svc = EmulationService(context.db)
    try:
        from uuid import UUID
        session = await svc.stop_session(UUID(session_id))
        await context.db.commit()
    except ValueError as exc:
        return f"Error: {exc}"
    except Exception as exc:
        return f"Error stopping session: {exc}"

    return f"Emulation session {session.id} stopped successfully."


async def _handle_check_status(input: dict, context: ToolContext) -> str:
    """Check emulation session status or list all sessions."""
    session_id = input.get("session_id")

    svc = EmulationService(context.db)

    if session_id:
        try:
            from uuid import UUID
            session = await svc.get_status(UUID(session_id))
        except ValueError as exc:
            return f"Error: {exc}"

        lines = [
            f"Session: {session.id}",
            f"  Mode: {session.mode}",
            f"  Status: {session.status}",
            f"  Architecture: {session.architecture}",
        ]
        if session.binary_path:
            lines.append(f"  Binary: {session.binary_path}")
        if session.started_at:
            from datetime import datetime, timezone
            uptime = datetime.now(timezone.utc) - session.started_at.replace(
                tzinfo=timezone.utc if session.started_at.tzinfo is None else session.started_at.tzinfo
            )
            lines.append(f"  Uptime: {int(uptime.total_seconds())}s")
        if session.error_message:
            lines.append(f"  Error: {session.error_message}")

        return "\n".join(lines)

    # List all sessions
    sessions = await svc.list_sessions(context.project_id)
    if not sessions:
        return "No emulation sessions found for this project."

    lines = [f"Emulation sessions ({len(sessions)}):\n"]
    for s in sessions[:10]:
        status_icon = {
            "running": "[RUNNING]",
            "starting": "[STARTING]",
            "stopped": "[STOPPED]",
            "error": "[ERROR]",
            "created": "[CREATED]",
        }.get(s.status, f"[{s.status}]")

        line = f"  {status_icon} {s.id} — {s.mode} mode"
        if s.binary_path:
            line += f" ({s.binary_path})"
        if s.architecture:
            line += f" [{s.architecture}]"
        lines.append(line)

    if len(sessions) > 10:
        lines.append(f"  ... and {len(sessions) - 10} more")

    return "\n".join(lines)


async def _handle_get_logs(input: dict, context: ToolContext) -> str:
    """Read QEMU boot logs from an emulation session."""
    session_id = input.get("session_id")
    if not session_id:
        return "Error: session_id is required."

    svc = EmulationService(context.db)
    try:
        from uuid import UUID
        logs = await svc.get_session_logs(UUID(session_id))
    except ValueError as exc:
        return f"Error: {exc}"
    except Exception as exc:
        return f"Error reading logs: {exc}"

    # Truncate if needed
    settings = get_settings()
    max_bytes = settings.max_tool_output_kb * 1024
    if len(logs) > max_bytes:
        logs = logs[-max_bytes:] + f"\n... [truncated to last {settings.max_tool_output_kb}KB]"

    return f"=== Emulation Boot Logs ===\n{logs}"


async def _handle_diagnose_environment(input: dict, context: ToolContext) -> str:
    """Pre-flight check of firmware filesystem for emulation compatibility."""
    # Get firmware record
    result = await context.db.execute(
        select(Firmware).where(Firmware.id == context.firmware_id)
    )
    firmware = result.scalar_one_or_none()
    if not firmware:
        return "Error: firmware not found."

    if not firmware.extracted_path:
        return "Error: firmware has not been unpacked yet."

    fs_root = firmware.extracted_path
    if not os.path.isdir(fs_root):
        return f"Error: extracted filesystem not found at {fs_root}"

    arch = firmware.architecture or "unknown"
    issues: list[str] = []
    info: list[str] = []
    suggestions: list[str] = []

    # --- 1. Check for broken /dev/null symlinks ---
    broken_symlinks = []
    for dirname in ["etc", "tmp", "home", "root", "var", "run",
                     "debug", "webroot", "media"]:
        path = os.path.join(fs_root, dirname)
        if os.path.islink(path):
            target = os.readlink(path)
            if target in ("/dev/null", "dev/null") or target.startswith("/dev/"):
                broken_symlinks.append(f"/{dirname} -> {target}")
    if broken_symlinks:
        issues.append(
            f"BROKEN SYMLINKS: {len(broken_symlinks)} directories are symlinked to "
            f"/dev/null or similar:\n"
            + "\n".join(f"    {s}" for s in broken_symlinks)
        )
        info.append(
            "The custom initramfs will automatically fix these broken symlinks "
            "before switch_root. This is handled for all architectures (ARM, "
            "aarch64, MIPSel)."
        )

    # --- 2. Check for /etc_ro (common in Tenda, TP-Link, etc.) ---
    etc_ro = os.path.join(fs_root, "etc_ro")
    has_etc_ro = os.path.isdir(etc_ro)
    if has_etc_ro:
        etc_path = os.path.join(fs_root, "etc")
        etc_is_link = os.path.islink(etc_path)
        etc_is_empty = (
            os.path.isdir(etc_path)
            and not os.path.islink(etc_path)
            and len(os.listdir(etc_path)) == 0
        )
        if etc_is_link or etc_is_empty:
            info.append(
                "FIRMWARE USES /etc_ro: Configuration files are in /etc_ro/ "
                "(read-only). The initramfs will populate /etc from /etc_ro "
                "automatically."
            )
        else:
            info.append(
                "Firmware has both /etc and /etc_ro directories. /etc appears "
                "to already have content."
            )

    # --- 3. Check init binary ---
    init_candidates = [
        "sbin/init", "bin/init", "init", "linuxrc",
        "sbin/procd", "usr/sbin/init",
    ]
    found_inits = []
    for candidate in init_candidates:
        path = os.path.join(fs_root, candidate)
        if os.path.exists(path) or os.path.islink(path):
            if os.path.islink(path):
                target = os.readlink(path)
                found_inits.append(f"/{candidate} -> {target}")
            else:
                found_inits.append(f"/{candidate}")

    if not found_inits:
        issues.append(
            "NO INIT BINARY: None of the standard init paths exist: "
            + ", ".join(f"/{c}" for c in init_candidates)
        )
        suggestions.append(
            "Try starting with init_path='/bin/sh' to get a shell, "
            "then manually investigate what init system the firmware uses."
        )
    else:
        info.append("Init binaries found: " + ", ".join(found_inits))

    # --- 4. Check for busybox (shell availability) ---
    bb_paths = ["bin/busybox", "usr/bin/busybox", "sbin/busybox"]
    found_bb = None
    for bp in bb_paths:
        full = os.path.join(fs_root, bp)
        if os.path.isfile(full) and not os.path.islink(full):
            try:
                size = os.path.getsize(full)
                if size > 1000:
                    found_bb = f"/{bp} ({size // 1024}KB)"
                    break
            except OSError:
                pass
    if found_bb:
        info.append(f"Busybox: {found_bb}")
    else:
        issues.append(
            "NO BUSYBOX: No busybox binary found. Shell commands may not "
            "work inside the emulated firmware."
        )

    # --- 5. Check /etc/passwd ---
    passwd_paths = ["etc/passwd"]
    if has_etc_ro:
        passwd_paths.append("etc_ro/passwd")
    found_passwd = False
    for pp in passwd_paths:
        full = os.path.join(fs_root, pp)
        if os.path.isfile(full):
            try:
                with open(full) as f:
                    content = f.read(512)
                content = content.replace("\x00", "").strip()
                if content and "root:" in content:
                    found_passwd = True
                    # Check if root has a password
                    for line in content.split("\n"):
                        if line.startswith("root:"):
                            parts = line.split(":")
                            if len(parts) >= 2:
                                pw = parts[1]
                                if pw in ("", "x"):
                                    info.append(
                                        f"/{pp}: root account found "
                                        f"(password in shadow or empty)"
                                    )
                                elif pw.startswith("$"):
                                    info.append(
                                        f"/{pp}: root account found (hashed password)"
                                    )
                                else:
                                    info.append(f"/{pp}: root account found")
                            break
            except OSError:
                pass
    if not found_passwd:
        if any("etc" in s for s in broken_symlinks):
            issues.append(
                "NO /etc/passwd: /etc is a broken symlink, so passwd is "
                "missing. The initramfs will fix this by populating /etc "
                "from /etc_ro (if available)."
            )
        else:
            issues.append(
                "NO /etc/passwd: No passwd file found. Login-based init "
                "systems (sulogin, getty) will fail."
            )
            suggestions.append(
                "Use init_path='/bin/sh' to bypass login, or create a "
                "minimal passwd file inside the emulated environment."
            )

    # --- 6. Check /etc/inittab or init scripts ---
    inittab = os.path.join(fs_root, "etc", "inittab")
    inittab_ro = os.path.join(fs_root, "etc_ro", "inittab")
    found_inittab = None
    for itab in [inittab, inittab_ro]:
        if os.path.isfile(itab):
            try:
                with open(itab) as f:
                    content = f.read(2048).replace("\x00", "").strip()
                if content:
                    found_inittab = itab.replace(fs_root, "")
                    # Check for sulogin/askfirst entries
                    if "sulogin" in content:
                        issues.append(
                            f"SULOGIN in {found_inittab}: inittab uses "
                            "sulogin which requires a root password. If "
                            "boot hangs at 'Give root password', the "
                            "initramfs has already fixed /etc from /etc_ro "
                            "so the password hash should be available."
                        )
                        suggestions.append(
                            "If sulogin still blocks boot, try "
                            "init_path='/bin/sh' to bypass it entirely."
                        )
                    if "askfirst" in content or "respawn" in content:
                        info.append(
                            f"{found_inittab}: uses BusyBox init "
                            "(askfirst/respawn entries found)"
                        )
                    break
            except OSError:
                pass

    # --- 7. Check init.d/rcS for startup scripts ---
    rcs_dirs = ["etc/init.d", "etc_ro/init.d"]
    for rcs_dir in rcs_dirs:
        full = os.path.join(fs_root, rcs_dir)
        if os.path.isdir(full):
            try:
                scripts = [f for f in os.listdir(full)
                           if not f.startswith(".")]
                info.append(
                    f"/{rcs_dir}/: {len(scripts)} init scripts"
                )
                # Check for rcS specifically
                rcs = os.path.join(full, "rcS")
                if os.path.isfile(rcs):
                    try:
                        with open(rcs) as f:
                            rcs_content = f.read(4096)
                        rcs_content = rcs_content.replace("\x00", "")
                        # Look for common patterns that fail in emulation
                        if "mount" in rcs_content and "mtd" in rcs_content:
                            issues.append(
                                f"/{rcs_dir}/rcS: references MTD flash "
                                "partitions. These don't exist in QEMU and "
                                "will cause mount errors (expected)."
                            )
                        if "insmod" in rcs_content or "modprobe" in rcs_content:
                            info.append(
                                f"/{rcs_dir}/rcS: loads kernel modules "
                                "(some will fail since QEMU uses a "
                                "different kernel — expected)."
                            )
                    except OSError:
                        pass
            except OSError:
                pass

    # --- 8. Check for MTD flash dependencies ---
    # Scan key binaries for get_mtd_size/get_mtd_num string references.
    # If found, the firmware likely needs the fake_mtd stub via LD_PRELOAD.
    mtd_binaries: list[str] = []
    mtd_scan_dirs = ["bin", "sbin", "usr/bin", "usr/sbin"]
    for scan_dir in mtd_scan_dirs:
        full_dir = os.path.join(fs_root, scan_dir)
        if not os.path.isdir(full_dir):
            continue
        try:
            for entry in os.scandir(full_dir):
                if not entry.is_file() or entry.is_symlink():
                    continue
                try:
                    size = entry.stat().st_size
                    if size < 1000 or size > 50_000_000:
                        continue
                    with open(entry.path, "rb") as bf:
                        data = bf.read(min(size, 2_000_000))
                    if b"get_mtd_size" in data or b"get_mtd_num" in data:
                        mtd_binaries.append(f"/{scan_dir}/{entry.name}")
                except OSError:
                    pass
        except OSError:
            pass

    if mtd_binaries:
        issues.append(
            f"MTD FLASH DEPENDENCY: {len(mtd_binaries)} binaries reference "
            f"MTD flash functions (get_mtd_size/get_mtd_num) that will fail "
            f"in QEMU (no MTD support):\n"
            + "\n".join(f"    {b}" for b in mtd_binaries[:10])
        )
        suggestions.append(
            "Use the fake MTD stub library via pre_init_script:\n"
            "    export LD_PRELOAD=/opt/stubs/fake_mtd.so\n"
            "This intercepts MTD functions (mtd_open, get_mtd_size, flash_read/write, "
            "etc.) with file-backed storage and also stubs wireless ioctls (0x8B00-0x8BFF) "
            "to prevent httpd InitConutryCode failures. The stub is automatically "
            "injected into the firmware rootfs at /opt/stubs/fake_mtd.so."
        )

    # --- 9. Check architecture of key binaries ---
    try:
        from elftools.elf.elffile import ELFFile
        elf_arch_map = {
            "EM_MIPS": "mips", "EM_ARM": "arm",
            "EM_AARCH64": "aarch64", "EM_386": "x86",
            "EM_X86_64": "x86_64",
        }
        for check_bin in ["bin/busybox", "sbin/init", "bin/sh"]:
            full = os.path.join(fs_root, check_bin)
            if os.path.isfile(full) and not os.path.islink(full):
                try:
                    with open(full, "rb") as f:
                        if f.read(4) == b"\x7fELF":
                            f.seek(0)
                            elf = ELFFile(f)
                            bin_arch = elf_arch_map.get(
                                elf.header.e_machine,
                                str(elf.header.e_machine),
                            )
                            endian = "LE" if elf.little_endian else "BE"
                            if bin_arch == "mips" and elf.little_endian:
                                bin_arch = "mipsel"
                            info.append(
                                f"/{check_bin}: {bin_arch} ({endian})"
                            )
                            # Check for architecture mismatch
                            if arch != "unknown" and bin_arch != arch:
                                issues.append(
                                    f"ARCH MISMATCH: /{check_bin} is "
                                    f"{bin_arch} but firmware detected as "
                                    f"{arch}. The kernel must match the "
                                    "binary architecture."
                                )
                except Exception:
                    pass
    except ImportError:
        pass

    # --- 10. Check shared library availability ---
    lib_dirs = ["lib", "usr/lib", "lib32"]
    total_libs = 0
    for ld in lib_dirs:
        full = os.path.join(fs_root, ld)
        if os.path.isdir(full):
            try:
                libs = [f for f in os.listdir(full)
                        if f.endswith(".so") or ".so." in f]
                total_libs += len(libs)
            except OSError:
                pass
    if total_libs > 0:
        info.append(f"Shared libraries: {total_libs} .so files found")
    else:
        issues.append(
            "NO SHARED LIBRARIES: No .so files found in /lib or /usr/lib. "
            "Dynamically linked binaries will fail to run."
        )

    # --- 11. Check kernel availability ---
    svc = KernelService()
    kernels = svc.list_kernels(architecture=arch)
    if kernels:
        k = kernels[0]
        initrd_note = " (with initramfs)" if k.get("has_initrd") else " (NO initramfs)"
        info.append(
            f"Kernel available: {k['name']} [{k['architecture']}]"
            f"{initrd_note}"
        )
        if not k.get("has_initrd") and broken_symlinks:
            issues.append(
                "KERNEL HAS NO INITRAMFS: The firmware has broken symlinks "
                "that need fixing at boot time, but the kernel has no "
                "companion initramfs to perform the fixes."
            )
            suggestions.append(
                "Upload a custom initramfs for this kernel, or use a "
                "different kernel that has one."
            )
    else:
        issues.append(
            f"NO KERNEL: No pre-built kernel available for architecture "
            f"'{arch}'. System-mode emulation cannot start."
        )
        suggestions.append(
            "Use download_kernel to fetch a kernel, or upload one via "
            "the kernel management page."
        )

    # --- Build report ---
    lines = [
        f"=== Emulation Pre-Flight Diagnosis ===",
        f"Firmware: {firmware.original_filename}",
        f"Architecture: {arch} ({firmware.endianness or 'unknown'} endian)",
        f"Filesystem root: {fs_root}",
        "",
    ]

    if issues:
        lines.append(f"ISSUES FOUND ({len(issues)}):")
        for i, issue in enumerate(issues, 1):
            lines.append(f"  {i}. {issue}")
        lines.append("")

    if info:
        lines.append("ENVIRONMENT INFO:")
        for item in info:
            lines.append(f"  - {item}")
        lines.append("")

    if suggestions:
        lines.append("SUGGESTED FIXES:")
        for i, sug in enumerate(suggestions, 1):
            lines.append(f"  {i}. {sug}")
        lines.append("")

    if not issues:
        lines.append(
            "No critical issues detected. The firmware should be compatible "
            "with system-mode emulation. Note that some runtime errors are "
            "expected (missing hardware, MTD flash, SoC-specific modules)."
        )

    return "\n".join(lines)


async def _handle_troubleshoot_emulation(input: dict, context: ToolContext) -> str:
    """Return a firmware-aware troubleshooting guide for emulation issues."""

    symptom = (input.get("symptom") or "").strip().lower()

    # ── Detect firmware characteristics ──
    has_etc_ro = False
    has_mtd_deps = False
    has_webroot = False
    arch = "unknown"

    result = await context.db.execute(
        select(Firmware).where(Firmware.id == context.firmware_id)
    )
    firmware = result.scalar_one_or_none()

    if firmware:
        arch = firmware.architecture or "unknown"
        fs_root = firmware.extracted_path or ""
        if fs_root and os.path.isdir(fs_root):
            has_etc_ro = os.path.isdir(os.path.join(fs_root, "etc_ro"))
            has_webroot = os.path.isdir(os.path.join(fs_root, "webroot"))

            # Quick MTD scan on a few key binaries
            for scan_dir in ["bin", "sbin", "usr/bin", "usr/sbin"]:
                full_dir = os.path.join(fs_root, scan_dir)
                if not os.path.isdir(full_dir):
                    continue
                try:
                    for entry in os.scandir(full_dir):
                        if has_mtd_deps:
                            break
                        if not entry.is_file() or entry.is_symlink():
                            continue
                        try:
                            size = entry.stat().st_size
                            if size < 1000 or size > 50_000_000:
                                continue
                            with open(entry.path, "rb") as bf:
                                data = bf.read(min(size, 500_000))
                            if b"get_mtd_size" in data or b"get_mtd_num" in data:
                                has_mtd_deps = True
                        except OSError:
                            pass
                except OSError:
                    pass

    # ── Build guide sections ──

    sections: dict[str, tuple[list[str], list[str]]] = {}
    # Each section: (keywords, lines)

    # 1. Service not listening
    service_lines = [
        "## Service Not Listening on Expected Port",
        "",
        "- **Interface mismatch**: Many firmware binaries bind to br0, not eth0.",
        "  Rename in pre-init: add `ip link set eth0 name br0` to pre_init_script.",
        "- **Check if running**: Use `ps` in emulation to verify the service started.",
        "  It may have crashed silently — run it in the foreground first to see errors.",
        "- **Config manager dependency**: Services like httpd often depend on a config",
        "  manager (cfmd, cfg_init) to populate runtime config before they can start.",
    ]
    if has_etc_ro:
        service_lines.append(
            "  This firmware has /etc_ro — try: `mkdir -p /cfg && cp /webroot/default.cfg /cfg/mib.cfg`"
        )
    service_lines += [
        "- **Don't start services directly in pre-init**: Pre-init runs before the",
        "  firmware's init. Services started there may be killed when init remounts",
        "  tmpfs or runs rcS. Instead, append startup commands to rcS:",
        '  `echo "/bin/httpd &" >> /etc_ro/init.d/rcS`',
        "- **Port forwarding**: Verify port_forwards param maps host→guest correctly.",
        "  QEMU SLiRP uses socat relay: host port → 127.0.0.1:guest_port+10000.",
    ]
    if has_webroot:
        service_lines += [
            "",
            "### Web Server (httpd) Specific",
            "- httpd may bind to a specific interface IP, not 0.0.0.0. Use",
            "  `extract_strings` on the httpd binary to find IP/interface references.",
            "- Check if httpd needs br0 specifically (common in Tenda/TP-Link firmware).",
            "- Config manager must seed /cfg before httpd will start properly.",
        ]
    sections["service_not_listening"] = (
        ["service", "listen", "port", "httpd", "web", "connect", "curl", "wget", "refused"],
        service_lines,
    )

    # 2. Boot hangs
    boot_lines = [
        "## Boot Hangs / No Shell Prompt",
        "",
        "- **sulogin blocking**: If boot stops at 'Give root password for maintenance',",
        "  the init wrapper should have already cleared the root password. However,",
        "  some busybox builds hardcode /etc_ro/inittab (not /etc/inittab).",
        "- **Use init_path=/bin/sh**: Bypass the firmware's init entirely to get a",
        "  shell with all wairz setup (mounts, networking, pre-init) already done.",
        "  Then manually run rcS or start services to debug what's failing.",
        "- **Check boot logs**: Use `get_emulation_logs` to see kernel messages and",
        "  init output. Look for mount failures, missing devices, or panic messages.",
        "- **Patience with ext4**: Filesystem creation for large firmware takes 60-90s.",
        "  Wait at least 2 minutes before assuming boot is hung.",
        "- **askfirst prompt**: BusyBox init with 'askfirst' entries prints",
        "  'Please press Enter to activate this console' — send an empty command",
        "  via run_command_in_emulation to proceed.",
    ]
    sections["boot_hang"] = (
        ["boot", "hang", "stuck", "prompt", "shell", "sulogin", "password", "freeze"],
        boot_lines,
    )

    # 3. Kernel panic / crash
    kernel_lines = [
        "## Kernel Panic / Crash",
        "",
        "- **Architecture must match exactly**: mips vs mipsel matters. A MIPS BE",
        "  kernel won't boot MIPS LE firmware and vice versa.",
    ]
    if "mips" in arch:
        kernel_lines.append(
            "- **MIPS FPU requirement**: QEMU MIPS needs CPU=34Kf (MIPS32r2 with FPU).",
            )
        kernel_lines.append(
            "  The default 24Kc/4Kc CPUs lack FPU and cause illegal instruction traps."
        )
    kernel_lines += [
        "- **Don't use firmware-extracted kernels**: Kernels extracted from firmware",
        "  images rarely work in QEMU (missing virtio drivers, wrong config).",
        "  Use pre-built kernels: Debian, OpenWrt, or Buildroot for QEMU.",
        "- **Check logs**: `get_emulation_logs` shows the panic message.",
        "  Common causes: missing root filesystem driver, wrong console= param,",
        "  incompatible kernel version for the firmware's userspace.",
        "- **Kernel/userspace ABI mismatch**: Very old firmware (kernel 2.6.x) may",
        "  not work with newer QEMU kernels. Check firmware's /lib/libc.so to",
        "  determine the expected kernel ABI version.",
    ]
    sections["kernel_panic"] = (
        ["kernel", "panic", "crash", "oops", "illegal", "instruction", "trap"],
        kernel_lines,
    )

    # 4. MTD / flash errors
    mtd_lines = [
        "## MTD / Flash Errors",
        "",
        "- **Auto-injected stub**: The init wrapper automatically sets",
        "  `LD_PRELOAD=/opt/stubs/fake_mtd.so` which intercepts common MTD functions:",
        "  mtd_open, get_mtd_size, get_mtd_num, flash_read, flash_write.",
        "- **File-backed storage**: The stub creates /tmp/fake_mtd_*.bin files that",
        "  simulate flash partitions. Read/write operations are backed by these files.",
        "- **Wireless ioctls**: The stub also intercepts wireless ioctls (0x8B00-0x8BFF)",
        "  to prevent httpd InitCountryCode failures.",
        "- **Missing functions**: If a binary imports custom MTD functions not covered",
        "  by the stub, use `extract_strings` on the binary to identify them, then",
        "  check `list_imports` to see which library provides them.",
    ]
    if has_mtd_deps:
        mtd_lines += [
            "",
            "**This firmware has MTD-dependent binaries.** The fake_mtd stub should",
            "handle most cases automatically. If you still see MTD errors, check which",
            "specific function is failing in the emulation logs.",
        ]
    mtd_lines += [
        "- **musl libc note**: musl does NOT support /etc/ld.so.preload.",
        "  LD_PRELOAD env var is the only way to inject shared libraries.",
    ]
    sections["mtd"] = (
        ["mtd", "flash", "nand", "nor", "partition", "ld_preload", "fake_mtd"],
        mtd_lines,
    )

    # 5. Network issues
    network_lines = [
        "## Network Issues",
        "",
        "- **QEMU user-mode networking**: guest=10.0.2.15/24, gateway=10.0.2.2,",
        "  DNS=10.0.2.3. The init wrapper configures eth0 automatically.",
        "- **Port forwarding**: Uses socat relay (host 0.0.0.0:PORT → guest",
        "  127.0.0.1:PORT+10000). Verify with `check_emulation_status`.",
        "- **Interface naming**: If firmware expects br0 (bridge), rename in pre-init:",
        "  `ip link set eth0 name br0 && ip addr add 10.0.2.15/24 dev br0 && ip link set br0 up`",
        "- **Binding to interface IP**: Some services bind to a specific interface's",
        "  IP rather than 0.0.0.0. Use `extract_strings` on the binary to find",
        "  hardcoded IPs or interface names.",
        "- **ICMP/ping won't work**: QEMU user-mode networking doesn't support ICMP.",
        "  Use TCP connections to test connectivity (wget, curl, nc).",
        "- **DNS**: The guest can resolve DNS via 10.0.2.3 (forwarded to host DNS).",
    ]
    sections["network"] = (
        ["network", "eth0", "br0", "interface", "ip", "route", "dns", "ping", "connect"],
        network_lines,
    )

    # 6. Pre-init best practices
    preinit_lines = [
        "## Pre-init Script Best Practices",
        "",
        "- Pre-init runs BEFORE the firmware's init — use it for environment setup only.",
        "- **Better pattern**: Set up interfaces, dirs, and config in pre-init. Append",
        "  service startup to rcS so it runs at the right point in the boot sequence.",
        "  Example:",
        "    ```",
        "    # pre-init: setup only",
        "    ip link set eth0 name br0",
        "    ip addr add 10.0.2.15/24 dev br0",
        "    ip link set br0 up",
        "    mkdir -p /cfg",
        "    cp /webroot/default.cfg /cfg/mib.cfg",
        '    echo "/bin/cfmd &" >> /etc_ro/init.d/rcS',
        '    echo "sleep 2 && /bin/httpd &" >> /etc_ro/init.d/rcS',
        "    ```",
        "- **LD_PRELOAD**: Auto-set by the init wrapper — don't duplicate in pre-init.",
        "- **musl libc**: No /etc/ld.so.preload support. Only LD_PRELOAD env var works.",
        "- Pre-init is sourced (not exec'd) — env vars are inherited by firmware init.",
    ]
    sections["preinit"] = (
        ["pre_init", "preinit", "pre-init", "script", "setup", "ld_preload", "environment"],
        preinit_lines,
    )

    # 7. Common firmware patterns
    pattern_lines = [
        "## Common Firmware Patterns",
        "",
    ]
    if has_etc_ro:
        pattern_lines += [
            "### Tenda / TP-Link Style (detected: /etc_ro present)",
            "- /etc is often a symlink to /dev/null in the squashfs image.",
            "  The init wrapper fixes this and populates /etc from /etc_ro.",
            "- cfmd (config manager) manages /cfg — seed with default.cfg before",
            "  starting services: `cp /webroot/default.cfg /cfg/mib.cfg`",
            "- httpd typically needs br0 interface, not eth0.",
            "- BusyBox may hardcode /etc_ro/inittab path (not /etc/inittab).",
            "- Boot sequence: rcS → cfmd → monitor → (httpd needs manual start)",
            "  Read rcS to understand the actual boot order.",
            "",
        ]
    pattern_lines += [
        "### General Embedded Linux",
        "- Read /etc/init.d/rcS (or /etc_ro/init.d/rcS) to understand boot sequence.",
        "- Look for cfg_init, cfmd, or similar config managers that seed runtime state.",
        "- Network services often start late in boot — wait for init to complete.",
        "- Many services depend on /proc, /sys, /dev being mounted (init wrapper does this).",
        "",
        "### OpenWrt",
        "- Uses procd init system, /etc/config for UCI configuration.",
        "- uhttpd is the default web server (port 80/443).",
        "- Procd reads /etc/inittab, runs /etc/init.d/* scripts.",
    ]
    sections["patterns"] = (
        ["pattern", "firmware", "tenda", "tp-link", "openwrt", "dd-wrt", "general", "common"],
        pattern_lines,
    )

    # ── Filter by symptom if provided ──

    selected_sections: list[list[str]] = []

    if symptom:
        for _section_name, (keywords, lines) in sections.items():
            if any(kw in symptom for kw in keywords):
                selected_sections.append(lines)

        # If no keyword matched, do a fuzzy match against all section content
        if not selected_sections:
            for _section_name, (_keywords, lines) in sections.items():
                joined = " ".join(lines).lower()
                # Check if any word from the symptom appears in the section
                symptom_words = [w for w in symptom.split() if len(w) > 2]
                if any(word in joined for word in symptom_words):
                    selected_sections.append(lines)

        if not selected_sections:
            # Still nothing — return everything with a note
            selected_sections = [lines for (_kw, lines) in sections.values()]
            header_note = (
                f"No specific section matched symptom '{symptom}'. "
                "Showing full troubleshooting guide.\n"
            )
        else:
            header_note = f"Filtered for symptom: {symptom}\n"
    else:
        selected_sections = [lines for (_kw, lines) in sections.values()]
        header_note = ""

    # ── Build output ──

    output_lines = [
        "=== Emulation Troubleshooting Guide ===",
        f"Architecture: {arch}",
    ]
    if has_etc_ro:
        output_lines.append("Detected: /etc_ro present (Tenda/TP-Link style firmware)")
    if has_mtd_deps:
        output_lines.append("Detected: MTD-dependent binaries (fake_mtd stub auto-injected)")
    if has_webroot:
        output_lines.append("Detected: /webroot present (web interface firmware)")
    output_lines.append("")
    if header_note:
        output_lines.append(header_note)

    for section_lines in selected_sections:
        output_lines.extend(section_lines)
        output_lines.append("")

    output_lines += [
        "---",
        "Tips:",
        "- Use `diagnose_emulation_environment` for pre-flight static checks.",
        "- Use `get_emulation_logs` to see boot output and error messages.",
        "- Use `init_path=/bin/sh` to bypass init and get a shell for manual debugging.",
        "- Use `check_emulation_status` to verify session state and port forwards.",
    ]

    return "\n".join(output_lines)


# ---------------------------------------------------------------------------
# Preset tool handlers
# ---------------------------------------------------------------------------


async def _handle_save_preset(input: dict, context: ToolContext) -> str:
    """Save an emulation configuration as a named preset."""
    name = input.get("name", "").strip()
    mode = input.get("mode", "")

    if not name:
        return "Error: name is required."
    if mode not in ("user", "system"):
        return "Error: mode must be 'user' or 'system'."

    svc = EmulationService(context.db)
    try:
        preset = await svc.create_preset(
            project_id=context.project_id,
            name=name,
            mode=mode,
            description=input.get("description"),
            binary_path=input.get("binary_path"),
            arguments=input.get("arguments"),
            port_forwards=input.get("port_forwards", []),
            kernel_name=input.get("kernel_name"),
            init_path=input.get("init_path"),
            pre_init_script=input.get("pre_init_script"),
        )
        await context.db.commit()
    except Exception as exc:
        return f"Error saving preset: {exc}"

    lines = [
        f"Preset saved successfully.",
        f"  Name: {preset.name}",
        f"  ID: {preset.id}",
        f"  Mode: {preset.mode}",
    ]
    if preset.description:
        lines.append(f"  Description: {preset.description}")
    if preset.pre_init_script:
        lines.append(f"  Pre-init script: {len(preset.pre_init_script)} chars")
    lines.append("")
    lines.append("Use start_emulation_from_preset to start a session with this preset.")

    return "\n".join(lines)


async def _handle_list_presets(input: dict, context: ToolContext) -> str:
    """List saved emulation presets for the current project."""
    svc = EmulationService(context.db)
    presets = await svc.list_presets(context.project_id)

    if not presets:
        return "No emulation presets saved for this project."

    lines = [f"Emulation presets ({len(presets)}):\n"]
    for p in presets:
        desc = f" — {p.description}" if p.description else ""
        lines.append(f"  [{p.mode}] {p.name}{desc}")
        lines.append(f"    ID: {p.id}")
        if p.binary_path:
            lines.append(f"    Binary: {p.binary_path}")
        if p.pre_init_script:
            lines.append(f"    Pre-init script: {len(p.pre_init_script)} chars")
        if p.port_forwards:
            pf_strs = [f"{pf['host']}:{pf['guest']}" for pf in p.port_forwards]
            lines.append(f"    Ports: {', '.join(pf_strs)}")

    return "\n".join(lines)


async def _handle_start_from_preset(input: dict, context: ToolContext) -> str:
    """Start an emulation session from a saved preset."""
    preset_name = input.get("preset_name", "").strip()
    preset_id = input.get("preset_id", "").strip()

    if not preset_name and not preset_id:
        return "Error: either preset_name or preset_id is required."

    svc = EmulationService(context.db)

    # Find the preset
    preset = None
    if preset_id:
        try:
            from uuid import UUID
            preset = await svc.get_preset(UUID(preset_id))
        except ValueError:
            return f"Error: preset with ID '{preset_id}' not found."
    else:
        # Search by name (case-insensitive)
        presets = await svc.list_presets(context.project_id)
        for p in presets:
            if p.name.lower() == preset_name.lower():
                preset = p
                break
        if not preset:
            return (
                f"Error: no preset named '{preset_name}' found. "
                "Use list_emulation_presets to see available presets."
            )

    # Start emulation using the preset's config
    start_input = {
        "mode": preset.mode,
        "binary_path": preset.binary_path,
        "arguments": preset.arguments,
        "port_forwards": preset.port_forwards or [],
        "kernel_name": preset.kernel_name,
        "init_path": preset.init_path,
        "pre_init_script": preset.pre_init_script,
    }

    result = await _handle_start_emulation(start_input, context)
    return f"Starting from preset '{preset.name}'...\n\n{result}"
