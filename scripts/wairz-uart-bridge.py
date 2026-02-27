#!/usr/bin/env python3
"""Wairz UART Bridge — standalone TCP-to-serial bridge for MCP tool access.

Manages a single serial connection shared across multiple TCP clients.
JSON-over-TCP protocol (newline-delimited) with request/response matching by ID.

Usage:
    python wairz-uart-bridge.py --port 9999 --bind 127.0.0.1
    # Or with uv:
    uv run --with pyserial wairz-uart-bridge.py --port 9999

Dependencies: pyserial (pip install pyserial)

Test without hardware:
    socat -d -d pty,raw,echo=0 pty,raw,echo=0
    # Then connect to one of the created PTYs
"""

import argparse
import asyncio
import json
import logging
import os
import re
import sys
import time
from collections import deque
from datetime import datetime, timezone
from pathlib import Path

try:
    import serial
except ImportError:
    print("Error: pyserial is required. Install with: pip install pyserial", file=sys.stderr)
    sys.exit(1)

logger = logging.getLogger("wairz-uart-bridge")

RING_BUFFER_MAX_BYTES = 1 * 1024 * 1024  # 1 MB


class SerialManager:
    """Manages a single serial connection with background reading and transcript logging."""

    def __init__(self, transcript_dir: Path) -> None:
        self._serial: serial.Serial | None = None
        self._ring_buffer = bytearray()
        self._serial_lock = asyncio.Lock()
        self._reader_task: asyncio.Task | None = None
        self._transcript_file = None
        self._transcript_dir = transcript_dir
        self._transcript_path: str | None = None
        self._device_path: str | None = None
        self._baudrate: int = 115200
        self._connected = False
        self._data_event = asyncio.Event()

    @property
    def connected(self) -> bool:
        return self._connected and self._serial is not None and self._serial.is_open

    @property
    def device_path(self) -> str | None:
        return self._device_path

    @property
    def baudrate(self) -> int:
        return self._baudrate

    @property
    def buffer_bytes(self) -> int:
        return len(self._ring_buffer)

    @property
    def transcript_path(self) -> str | None:
        return self._transcript_path

    async def connect(
        self,
        device: str,
        baudrate: int = 115200,
        data_bits: int = 8,
        parity: str = "N",
        stop_bits: int = 1,
    ) -> None:
        """Open serial connection and start background reader."""
        if self.connected:
            raise ValueError(f"Already connected to {self._device_path}. Disconnect first.")

        bytesize_map = {5: serial.FIVEBITS, 6: serial.SIXBITS, 7: serial.SEVENBITS, 8: serial.EIGHTBITS}
        parity_map = {"N": serial.PARITY_NONE, "E": serial.PARITY_EVEN, "O": serial.PARITY_ODD}
        stopbits_map = {1: serial.STOPBITS_ONE, 2: serial.STOPBITS_TWO}

        loop = asyncio.get_event_loop()
        ser = serial.Serial()
        ser.port = device
        ser.baudrate = baudrate
        ser.bytesize = bytesize_map.get(data_bits, serial.EIGHTBITS)
        ser.parity = parity_map.get(parity.upper(), serial.PARITY_NONE)
        ser.stopbits = stopbits_map.get(stop_bits, serial.STOPBITS_ONE)
        ser.timeout = 0.1  # Read timeout for background reader

        await loop.run_in_executor(None, ser.open)

        self._serial = ser
        self._device_path = device
        self._baudrate = baudrate
        self._connected = True
        self._ring_buffer.clear()
        self._data_event.clear()

        # Set up transcript file
        self._transcript_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H%M%S")
        safe_device = device.replace("/", "_").strip("_")
        self._transcript_path = str(self._transcript_dir / f"{ts}_{safe_device}.jsonl")
        self._transcript_file = open(self._transcript_path, "a", encoding="utf-8")
        self._log_transcript("connect", data=f"device={device} baudrate={baudrate}")

        # Start background reader
        self._reader_task = asyncio.create_task(self._background_reader())
        logger.info("Connected to %s at %d baud", device, baudrate)

    async def disconnect(self) -> None:
        """Close serial connection and stop reader."""
        if self._reader_task and not self._reader_task.done():
            self._reader_task.cancel()
            try:
                await self._reader_task
            except asyncio.CancelledError:
                pass
            self._reader_task = None

        if self._serial and self._serial.is_open:
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, self._serial.close)

        self._connected = False
        self._serial = None
        self._device_path = None

        self._log_transcript("disconnect")
        if self._transcript_file:
            self._transcript_file.close()
            self._transcript_file = None

        self._ring_buffer.clear()
        logger.info("Disconnected")

    async def send_command(self, command: str, prompt: str = "# ", timeout: float = 30) -> str:
        """Send a command, wait for prompt in output, return captured output."""
        if not self.connected:
            raise ValueError("Not connected")

        async with self._serial_lock:
            # Drain existing buffer
            self._ring_buffer.clear()
            self._data_event.clear()

            # Write command
            cmd_bytes = (command + "\n").encode("utf-8")
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, self._serial.write, cmd_bytes)
            self._log_transcript("cmd", command=command, prompt=prompt)
            self._log_transcript("tx", data=command + "\n")

            # Wait for prompt or timeout
            collected = bytearray()
            is_regex = prompt.startswith("/") and prompt.endswith("/") and len(prompt) > 2
            if is_regex:
                prompt_pattern = re.compile(prompt[1:-1])
            else:
                prompt_pattern = None

            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break

                # Wait for new data with timeout
                try:
                    await asyncio.wait_for(self._data_event.wait(), timeout=min(remaining, 0.5))
                except asyncio.TimeoutError:
                    pass
                self._data_event.clear()

                # Grab whatever is in the buffer
                if self._ring_buffer:
                    collected.extend(self._ring_buffer)
                    self._ring_buffer.clear()

                # Check for prompt
                text = collected.decode("utf-8", errors="replace")
                if prompt_pattern:
                    if prompt_pattern.search(text):
                        break
                else:
                    if text.endswith(prompt) or prompt in text.split("\n")[-1]:
                        break

            output = collected.decode("utf-8", errors="replace")
            # Strip the echoed command from the start if present
            lines = output.split("\n")
            if lines and lines[0].strip() == command.strip():
                output = "\n".join(lines[1:])

            return output

    async def read_buffer(self, timeout: float = 2) -> str:
        """Wait up to timeout for data, then drain and return ring buffer contents."""
        if not self.connected:
            raise ValueError("Not connected")

        # Wait for some data to arrive
        try:
            await asyncio.wait_for(self._data_event.wait(), timeout=timeout)
        except asyncio.TimeoutError:
            pass
        self._data_event.clear()

        # Small additional delay to accumulate more data
        await asyncio.sleep(0.1)

        data = bytes(self._ring_buffer)
        self._ring_buffer.clear()
        return data.decode("utf-8", errors="replace")

    async def send_break(self, duration: float = 0.25) -> None:
        """Send serial BREAK signal."""
        if not self.connected:
            raise ValueError("Not connected")

        async with self._serial_lock:
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, self._serial.send_break, duration)
            self._log_transcript("tx", data="<BREAK>")

    async def send_raw(self, data: bytes) -> None:
        """Send raw bytes without waiting for response."""
        if not self.connected:
            raise ValueError("Not connected")

        async with self._serial_lock:
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, self._serial.write, data)
            self._log_transcript("tx", data=data.hex())

    def get_transcript(self, tail_lines: int = 100) -> list[dict]:
        """Read last N lines from transcript JSONL."""
        if not self._transcript_path or not os.path.exists(self._transcript_path):
            return []

        lines = []
        try:
            with open(self._transcript_path, "r", encoding="utf-8") as f:
                all_lines = f.readlines()
                for line in all_lines[-tail_lines:]:
                    line = line.strip()
                    if line:
                        try:
                            lines.append(json.loads(line))
                        except json.JSONDecodeError:
                            pass
        except OSError:
            pass
        return lines

    def status(self) -> dict:
        """Return connection status info."""
        return {
            "connected": self.connected,
            "device": self._device_path,
            "baudrate": self._baudrate,
            "buffer_bytes": self.buffer_bytes,
            "transcript_path": self._transcript_path,
        }

    async def _background_reader(self) -> None:
        """Continuously read from serial port into ring buffer."""
        loop = asyncio.get_event_loop()
        while True:
            try:
                data = await loop.run_in_executor(None, self._serial.read, 4096)
                if data:
                    self._ring_buffer.extend(data)
                    # Cap buffer size
                    if len(self._ring_buffer) > RING_BUFFER_MAX_BYTES:
                        excess = len(self._ring_buffer) - RING_BUFFER_MAX_BYTES
                        del self._ring_buffer[:excess]
                    self._log_transcript("rx", data=data.decode("utf-8", errors="replace"))
                    self._data_event.set()
            except serial.SerialException:
                logger.warning("Serial read error — device may have been disconnected")
                self._connected = False
                break
            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.error("Background reader error: %s", exc)
                await asyncio.sleep(0.1)

    def _log_transcript(self, direction: str, data: str | None = None, **extra) -> None:
        """Write a transcript entry to the JSONL file."""
        if not self._transcript_file:
            return
        entry = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "dir": direction,
        }
        if data is not None:
            entry["data"] = data
        entry.update(extra)
        try:
            self._transcript_file.write(json.dumps(entry) + "\n")
            self._transcript_file.flush()
        except OSError:
            pass


class BridgeServer:
    """Asyncio TCP server that handles JSON-over-TCP protocol for UART bridge."""

    def __init__(self, serial_mgr: SerialManager, bind: str, port: int) -> None:
        self._serial_mgr = serial_mgr
        self._bind = bind
        self._port = port
        self._server: asyncio.Server | None = None

    async def start(self) -> None:
        self._server = await asyncio.start_server(
            self._handle_client, self._bind, self._port
        )
        addrs = ", ".join(str(s.getsockname()) for s in self._server.sockets)
        logger.info("UART bridge listening on %s", addrs)
        async with self._server:
            await self._server.serve_forever()

    async def _handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        addr = writer.get_extra_info("peername")
        logger.debug("Client connected: %s", addr)
        try:
            while True:
                line = await reader.readline()
                if not line:
                    break
                try:
                    request = json.loads(line.decode("utf-8"))
                except json.JSONDecodeError:
                    response = {"ok": False, "error": "Invalid JSON"}
                    writer.write((json.dumps(response) + "\n").encode("utf-8"))
                    await writer.drain()
                    continue

                req_id = request.get("id")
                method = request.get("method", "")
                params = request.get("params", {})

                response = await self._dispatch(method, params)
                if req_id is not None:
                    response["id"] = req_id

                writer.write((json.dumps(response) + "\n").encode("utf-8"))
                await writer.drain()
        except (ConnectionResetError, asyncio.IncompleteReadError):
            pass
        except Exception as exc:
            logger.error("Client handler error: %s", exc)
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            logger.debug("Client disconnected: %s", addr)

    async def _dispatch(self, method: str, params: dict) -> dict:
        """Route a request to the appropriate handler."""
        try:
            if method == "connect":
                return await self._handle_connect(params)
            elif method == "send_command":
                return await self._handle_send_command(params)
            elif method == "read":
                return await self._handle_read(params)
            elif method == "send_break":
                return await self._handle_send_break(params)
            elif method == "send_raw":
                return await self._handle_send_raw(params)
            elif method == "get_transcript":
                return await self._handle_get_transcript(params)
            elif method == "status":
                return await self._handle_status(params)
            elif method == "disconnect":
                return await self._handle_disconnect(params)
            else:
                return {"ok": False, "error": f"Unknown method: {method}"}
        except ValueError as exc:
            return {"ok": False, "error": str(exc)}
        except Exception as exc:
            logger.error("Handler error for %s: %s", method, exc)
            return {"ok": False, "error": str(exc)}

    async def _handle_connect(self, params: dict) -> dict:
        device = params.get("device", "")
        if not device:
            return {"ok": False, "error": "device is required"}

        await self._serial_mgr.connect(
            device=device,
            baudrate=params.get("baudrate", 115200),
            data_bits=params.get("data_bits", 8),
            parity=params.get("parity", "N"),
            stop_bits=params.get("stop_bits", 1),
        )
        return {"ok": True, "result": self._serial_mgr.status()}

    async def _handle_send_command(self, params: dict) -> dict:
        command = params.get("command", "")
        if not command:
            return {"ok": False, "error": "command is required"}

        output = await self._serial_mgr.send_command(
            command=command,
            prompt=params.get("prompt", "# "),
            timeout=params.get("timeout", 30),
        )
        return {"ok": True, "result": {"output": output}}

    async def _handle_read(self, params: dict) -> dict:
        output = await self._serial_mgr.read_buffer(
            timeout=params.get("timeout", 2),
        )
        return {"ok": True, "result": {"output": output, "bytes": len(output)}}

    async def _handle_send_break(self, params: dict) -> dict:
        await self._serial_mgr.send_break(
            duration=params.get("duration", 0.25),
        )
        return {"ok": True, "result": {"sent": True}}

    async def _handle_send_raw(self, params: dict) -> dict:
        data_str = params.get("data", "")
        is_hex = params.get("hex", False)

        if not data_str:
            return {"ok": False, "error": "data is required"}

        if is_hex:
            try:
                data_bytes = bytes.fromhex(data_str)
            except ValueError:
                return {"ok": False, "error": "Invalid hex string"}
        else:
            data_bytes = data_str.encode("utf-8")

        await self._serial_mgr.send_raw(data_bytes)
        return {"ok": True, "result": {"bytes_sent": len(data_bytes)}}

    async def _handle_get_transcript(self, params: dict) -> dict:
        tail_lines = params.get("tail_lines", 100)
        entries = self._serial_mgr.get_transcript(tail_lines=tail_lines)
        return {"ok": True, "result": {"entries": entries, "count": len(entries)}}

    async def _handle_status(self, params: dict) -> dict:
        return {"ok": True, "result": self._serial_mgr.status()}

    async def _handle_disconnect(self, params: dict) -> dict:
        await self._serial_mgr.disconnect()
        return {"ok": True, "result": {"disconnected": True}}


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Wairz UART Bridge — TCP-to-serial bridge for MCP tools"
    )
    parser.add_argument(
        "--port", type=int, default=9999, help="TCP listen port (default: 9999)"
    )
    parser.add_argument(
        "--bind", default="127.0.0.1", help="Bind address (default: 127.0.0.1)"
    )
    parser.add_argument(
        "--transcript-dir",
        default=os.path.expanduser("~/.wairz/uart-transcripts/"),
        help="Directory for transcript JSONL files",
    )
    parser.add_argument(
        "--log-level", default="INFO", help="Log level (default: INFO)"
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log_level.upper(), logging.INFO),
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    )

    transcript_dir = Path(args.transcript_dir)
    serial_mgr = SerialManager(transcript_dir)
    server = BridgeServer(serial_mgr, bind=args.bind, port=args.port)

    try:
        asyncio.run(server.start())
    except KeyboardInterrupt:
        logger.info("Shutting down...")


if __name__ == "__main__":
    main()
