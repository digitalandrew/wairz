"""Emulation AI tools for dynamic firmware analysis.

Tools for starting/stopping QEMU emulation sessions, executing commands
in running sessions, checking session status, and listing available kernels.
"""

from app.ai.tool_registry import ToolContext, ToolRegistry
from app.config import get_settings
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
        name="start_emulation",
        description=(
            "Start a QEMU-based emulation session for dynamic firmware analysis. "
            "User mode runs a single binary in a chroot (fast, good for testing "
            "specific programs). System mode boots the full firmware OS (slower, "
            "good for testing services and network behavior). "
            "For system mode, use list_available_kernels first to check that a "
            "matching kernel is available. You can specify kernel_name to select "
            "a specific kernel. "
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
            "Default timeout is 30 seconds, max 120 seconds."
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


async def _handle_start_emulation(input: dict, context: ToolContext) -> str:
    """Start an emulation session."""
    mode = input.get("mode", "user")
    binary_path = input.get("binary_path")
    arguments = input.get("arguments")
    port_forwards = input.get("port_forwards", [])
    kernel_name = input.get("kernel_name")

    if mode == "user" and not binary_path:
        return "Error: binary_path is required for user-mode emulation."

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

    return "\n".join(lines)


async def _handle_run_command(input: dict, context: ToolContext) -> str:
    """Execute a command in a running emulation session."""
    session_id = input.get("session_id")
    command = input.get("command")
    timeout = min(input.get("timeout", 30), 120)

    if not session_id or not command:
        return "Error: session_id and command are required."

    svc = EmulationService(context.db)
    try:
        from uuid import UUID
        result = await svc.exec_command(
            session_id=UUID(session_id),
            command=command,
            timeout=timeout,
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
