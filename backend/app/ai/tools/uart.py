"""UART serial console MCP tools for live device interaction.

Tools for connecting to physical devices via UART serial console through
the host-side wairz-uart-bridge, sending commands, reading output,
U-Boot interaction, and transcript retrieval.
"""

from app.ai.tool_registry import ToolContext, ToolRegistry
from app.services.uart_service import UARTService


def register_uart_tools(registry: ToolRegistry) -> None:
    """Register all UART tools with the given registry."""

    registry.register(
        name="uart_connect",
        description=(
            "Connect to a live device's UART serial console via the host-side bridge. "
            "Requires the wairz-uart-bridge to be running on the host machine where "
            "the USB-UART adapter is plugged in. Only one connection per project at a time.\n\n"
            "Common baud rates: 115200 (most common), 9600, 57600, 38400.\n"
            "Common devices: /dev/ttyUSB0, /dev/ttyACM0, /dev/tty.usbserial-*"
        ),
        input_schema={
            "type": "object",
            "properties": {
                "device_path": {
                    "type": "string",
                    "description": "Serial device path (e.g., /dev/ttyUSB0)",
                },
                "baudrate": {
                    "type": "integer",
                    "description": "Baud rate (default: 115200)",
                    "default": 115200,
                },
                "data_bits": {
                    "type": "integer",
                    "description": "Data bits: 5, 6, 7, or 8 (default: 8)",
                    "default": 8,
                },
                "parity": {
                    "type": "string",
                    "enum": ["N", "E", "O"],
                    "description": "Parity: N=none, E=even, O=odd (default: N)",
                    "default": "N",
                },
                "stop_bits": {
                    "type": "integer",
                    "enum": [1, 2],
                    "description": "Stop bits: 1 or 2 (default: 1)",
                    "default": 1,
                },
            },
            "required": ["device_path"],
        },
        handler=_handle_uart_connect,
    )

    registry.register(
        name="uart_send_command",
        description=(
            "Send a command to the device's UART console and wait for the shell prompt. "
            "Returns the command output. The prompt parameter controls when to stop "
            "reading — set it to match your device's shell prompt (e.g., '# ' for root, "
            "'$ ' for user, '=> ' for U-Boot). If the prompt starts and ends with '/', "
            "it is treated as a regex pattern.\n\n"
            "Tips:\n"
            "- Use short timeout for quick commands, longer for slow operations\n"
            "- If output is truncated, the command may still be running\n"
            "- For commands that produce no output, the tool waits until timeout"
        ),
        input_schema={
            "type": "object",
            "properties": {
                "command": {
                    "type": "string",
                    "description": "The command to send (newline is appended automatically)",
                },
                "timeout": {
                    "type": "integer",
                    "description": "Max seconds to wait for prompt (default: 30)",
                    "default": 30,
                },
                "prompt": {
                    "type": "string",
                    "description": (
                        "Shell prompt to wait for (default: '# '). "
                        "Use '=> ' for U-Boot. Wrap in / for regex: '/\\w+@\\w+[#$] /'"
                    ),
                    "default": "# ",
                },
            },
            "required": ["command"],
        },
        handler=_handle_uart_send_command,
    )

    registry.register(
        name="uart_read",
        description=(
            "Read whatever is currently in the UART receive buffer. Use this for:\n"
            "- Capturing boot logs (connect before power-on, then read)\n"
            "- Reading async output that wasn't captured by send_command\n"
            "- Checking what's currently on the console\n"
            "- Reading continuous output from a device booting up\n\n"
            "The tool waits up to 'timeout' seconds for data to arrive, then returns "
            "everything in the buffer."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "timeout": {
                    "type": "integer",
                    "description": "Max seconds to wait for data (default: 2)",
                    "default": 2,
                },
            },
        },
        handler=_handle_uart_read,
    )

    registry.register(
        name="uart_send_break",
        description=(
            "Send a serial BREAK signal on the UART line. Common uses:\n"
            "- Interrupt U-Boot autoboot countdown to get U-Boot shell\n"
            "- Trigger debug console on some devices\n"
            "- Send attention signal to the device\n\n"
            "After sending break, use uart_read to check the device's response, "
            "then uart_send_command with prompt='=> ' for U-Boot interaction."
        ),
        input_schema={
            "type": "object",
            "properties": {},
        },
        handler=_handle_uart_send_break,
    )

    registry.register(
        name="uart_send_raw",
        description=(
            "Send raw bytes to the UART without waiting for a response. Use for:\n"
            "- Sending space/ESC key during U-Boot boot window to interrupt autoboot\n"
            "- Sending binary protocol data\n"
            "- Sending control characters (Ctrl+C = hex '03')\n"
            "- Non-shell interaction where you don't want a newline appended\n\n"
            "Set hex=true to send hex-encoded bytes (e.g., '03' for Ctrl+C, "
            "'1b' for ESC, '20' for space)."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "data": {
                    "type": "string",
                    "description": "Data to send (string or hex-encoded bytes)",
                },
                "hex": {
                    "type": "boolean",
                    "description": "If true, interpret data as hex bytes (default: false)",
                    "default": False,
                },
            },
            "required": ["data"],
        },
        handler=_handle_uart_send_raw,
    )

    registry.register(
        name="uart_disconnect",
        description=(
            "Close the UART serial connection and end the session. "
            "Always disconnect when done to release the serial port for other use."
        ),
        input_schema={
            "type": "object",
            "properties": {},
        },
        handler=_handle_uart_disconnect,
    )

    registry.register(
        name="uart_status",
        description=(
            "Check the current UART connection status. Returns whether connected, "
            "device path, baud rate, buffer size, and transcript file location."
        ),
        input_schema={
            "type": "object",
            "properties": {},
        },
        handler=_handle_uart_status,
    )

    registry.register(
        name="uart_get_transcript",
        description=(
            "Get recent UART transcript entries. The transcript logs all data sent "
            "and received with timestamps. Useful for:\n"
            "- Reviewing boot logs captured earlier in the session\n"
            "- Getting a record of all commands and responses\n"
            "- Debugging communication issues\n"
            "- Documenting device interaction for findings"
        ),
        input_schema={
            "type": "object",
            "properties": {
                "tail_lines": {
                    "type": "integer",
                    "description": "Number of recent transcript entries to return (default: 100)",
                    "default": 100,
                },
            },
        },
        handler=_handle_uart_get_transcript,
    )


# ---------------------------------------------------------------------------
# Tool handlers
# ---------------------------------------------------------------------------


async def _handle_uart_connect(input: dict, context: ToolContext) -> str:
    """Connect to a UART serial device."""
    device_path = input.get("device_path", "")
    if not device_path:
        return "Error: device_path is required."

    svc = UARTService(context.db)
    try:
        session = await svc.connect(
            project_id=context.project_id,
            firmware_id=context.firmware_id,
            device_path=device_path,
            baudrate=input.get("baudrate", 115200),
            data_bits=input.get("data_bits", 8),
            parity=input.get("parity", "N"),
            stop_bits=input.get("stop_bits", 1),
        )
        await context.db.commit()
    except ConnectionError as exc:
        return f"Error: {exc}"
    except ValueError as exc:
        return f"Error: {exc}"

    lines = [
        "UART connected successfully.",
        f"  Session ID: {session.id}",
        f"  Device: {session.device_path}",
        f"  Baud rate: {session.baudrate}",
        f"  Status: {session.status}",
        "",
        "Use uart_send_command to send commands (prompt defaults to '# ').",
        "Use uart_read to read the receive buffer (e.g., for boot logs).",
        "Use uart_send_break to interrupt U-Boot autoboot.",
        "Use uart_disconnect when done.",
    ]
    return "\n".join(lines)


async def _handle_uart_send_command(input: dict, context: ToolContext) -> str:
    """Send a command and return output."""
    command = input.get("command", "")
    if not command:
        return "Error: command is required."

    svc = UARTService(context.db)
    try:
        result = await svc.send_command(
            project_id=context.project_id,
            command=command,
            timeout=input.get("timeout", 30),
            prompt=input.get("prompt", "# "),
        )
    except ConnectionError as exc:
        return f"Error: Bridge unreachable — {exc}"
    except ValueError as exc:
        return f"Error: {exc}"

    output = result.get("output", "")
    if not output.strip():
        return "(no output — command may have produced no output or prompt was not detected before timeout)"
    return output


async def _handle_uart_read(input: dict, context: ToolContext) -> str:
    """Read receive buffer contents."""
    svc = UARTService(context.db)
    try:
        result = await svc.read_buffer(
            project_id=context.project_id,
            timeout=input.get("timeout", 2),
        )
    except ConnectionError as exc:
        return f"Error: Bridge unreachable — {exc}"
    except ValueError as exc:
        return f"Error: {exc}"

    output = result.get("output", "")
    byte_count = result.get("bytes", len(output))
    if not output.strip():
        return "(buffer empty — no data received)"
    return f"[{byte_count} bytes]\n{output}"


async def _handle_uart_send_break(input: dict, context: ToolContext) -> str:
    """Send serial BREAK signal."""
    svc = UARTService(context.db)
    try:
        await svc.send_break(project_id=context.project_id)
    except ConnectionError as exc:
        return f"Error: Bridge unreachable — {exc}"
    except ValueError as exc:
        return f"Error: {exc}"

    return (
        "BREAK signal sent.\n"
        "Use uart_read to check the device response.\n"
        "For U-Boot, set prompt to '=> ' when sending commands."
    )


async def _handle_uart_send_raw(input: dict, context: ToolContext) -> str:
    """Send raw bytes."""
    data = input.get("data", "")
    if not data:
        return "Error: data is required."

    hex_mode = input.get("hex", False)

    svc = UARTService(context.db)
    try:
        result = await svc.send_raw(
            project_id=context.project_id,
            data=data,
            hex_mode=hex_mode,
        )
    except ConnectionError as exc:
        return f"Error: Bridge unreachable — {exc}"
    except ValueError as exc:
        return f"Error: {exc}"

    bytes_sent = result.get("bytes_sent", 0)
    return f"Sent {bytes_sent} bytes. Use uart_read to check the response."


async def _handle_uart_disconnect(input: dict, context: ToolContext) -> str:
    """Disconnect UART session."""
    svc = UARTService(context.db)
    try:
        session = await svc.disconnect(project_id=context.project_id)
        await context.db.commit()
    except ConnectionError as exc:
        return f"Error: {exc}"
    except ValueError as exc:
        return f"Error: {exc}"

    return (
        f"UART disconnected.\n"
        f"  Session ID: {session.id}\n"
        f"  Device: {session.device_path}\n"
        f"  Duration: {session.connected_at} → {session.closed_at}"
    )


async def _handle_uart_status(input: dict, context: ToolContext) -> str:
    """Check UART connection status."""
    svc = UARTService(context.db)
    result = await svc.get_status(project_id=context.project_id)

    connected = result.get("connected", False)
    lines = [f"UART Status: {'Connected' if connected else 'Not connected'}"]

    if connected:
        lines.append(f"  Device: {result.get('device', 'unknown')}")
        lines.append(f"  Baud rate: {result.get('baudrate', 0)}")
        lines.append(f"  Buffer: {result.get('buffer_bytes', 0)} bytes")

    if result.get("transcript_path"):
        lines.append(f"  Transcript: {result['transcript_path']}")

    session_info = result.get("session")
    if session_info:
        lines.append(f"  Session ID: {session_info.get('id')}")
        lines.append(f"  DB status: {session_info.get('status')}")

    if result.get("bridge_error"):
        lines.append(f"  Bridge error: {result['bridge_error']}")

    return "\n".join(lines)


async def _handle_uart_get_transcript(input: dict, context: ToolContext) -> str:
    """Get recent transcript entries."""
    svc = UARTService(context.db)
    try:
        result = await svc.get_transcript(
            project_id=context.project_id,
            tail_lines=input.get("tail_lines", 100),
        )
    except ConnectionError as exc:
        return f"Error: Bridge unreachable — {exc}"
    except ValueError as exc:
        return f"Error: {exc}"

    entries = result.get("entries", [])
    count = result.get("count", len(entries))

    if not entries:
        return "No transcript entries found."

    lines = [f"UART Transcript ({count} entries):"]
    for entry in entries:
        ts = entry.get("ts", "")
        direction = entry.get("dir", "?")
        data = entry.get("data", "")

        # Format timestamp to just time for readability
        if "T" in ts:
            ts = ts.split("T")[1][:12]

        if direction == "cmd":
            cmd = entry.get("command", data)
            prompt = entry.get("prompt", "")
            lines.append(f"  [{ts}] CMD: {cmd} (prompt: {prompt!r})")
        elif direction == "tx":
            # Truncate long TX data
            display = data[:200] + "..." if len(data) > 200 else data
            lines.append(f"  [{ts}] TX: {display!r}")
        elif direction == "rx":
            display = data[:200] + "..." if len(data) > 200 else data
            lines.append(f"  [{ts}] RX: {display!r}")
        else:
            lines.append(f"  [{ts}] {direction}: {data}")

    return "\n".join(lines)
