"""Service for UART serial console access via the wairz-uart-bridge.

Manages UART sessions in the database and proxies commands to the
host-side bridge process over TCP using a JSON-over-newline protocol.
"""

import asyncio
import json
import logging
from datetime import datetime, timezone
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.models.uart_session import UARTSession

logger = logging.getLogger(__name__)


class UARTService:
    """Manages UART sessions and communicates with the host-side bridge."""

    def __init__(self, db: AsyncSession) -> None:
        self._db = db

    # ── Public API ──

    async def connect(
        self,
        project_id: UUID,
        firmware_id: UUID,
        device_path: str,
        baudrate: int = 115200,
        data_bits: int = 8,
        parity: str = "N",
        stop_bits: int = 1,
    ) -> UARTSession:
        """Open a UART connection via the bridge and create a DB session record."""
        # Check for existing active session for this project
        active = await self._get_active_session(project_id)
        if active:
            raise ValueError(
                f"Project already has an active UART session ({active.id}) "
                f"to {active.device_path}. Disconnect first."
            )

        # Send connect to bridge
        result = await self._bridge_request({
            "method": "connect",
            "params": {
                "device": device_path,
                "baudrate": baudrate,
                "data_bits": data_bits,
                "parity": parity,
                "stop_bits": stop_bits,
            },
        })

        transcript_path = result.get("result", {}).get("transcript_path")

        # Create DB record
        session = UARTSession(
            project_id=project_id,
            firmware_id=firmware_id,
            device_path=device_path,
            baudrate=baudrate,
            status="connected",
            transcript_path=transcript_path,
            connected_at=datetime.now(timezone.utc),
        )
        self._db.add(session)
        await self._db.flush()
        return session

    async def send_command(
        self,
        project_id: UUID,
        command: str,
        timeout: int = 30,
        prompt: str = "# ",
    ) -> dict:
        """Send a command to the UART console and wait for the prompt."""
        session = await self._get_active_session(project_id)
        if not session:
            raise ValueError("No active UART session for this project. Connect first.")

        settings = get_settings()
        if timeout <= 0:
            timeout = settings.uart_command_timeout

        result = await self._bridge_request({
            "method": "send_command",
            "params": {
                "command": command,
                "prompt": prompt,
                "timeout": timeout,
            },
        })
        return result.get("result", {})

    async def read_buffer(self, project_id: UUID, timeout: int = 2) -> dict:
        """Read the current receive buffer contents."""
        session = await self._get_active_session(project_id)
        if not session:
            raise ValueError("No active UART session for this project. Connect first.")

        result = await self._bridge_request({
            "method": "read",
            "params": {"timeout": timeout},
        })
        return result.get("result", {})

    async def send_break(self, project_id: UUID) -> dict:
        """Send a serial BREAK signal."""
        session = await self._get_active_session(project_id)
        if not session:
            raise ValueError("No active UART session for this project. Connect first.")

        result = await self._bridge_request({"method": "send_break", "params": {}})
        return result.get("result", {})

    async def send_raw(self, project_id: UUID, data: str, hex_mode: bool = False) -> dict:
        """Send raw bytes to the serial port."""
        session = await self._get_active_session(project_id)
        if not session:
            raise ValueError("No active UART session for this project. Connect first.")

        result = await self._bridge_request({
            "method": "send_raw",
            "params": {"data": data, "hex": hex_mode},
        })
        return result.get("result", {})

    async def get_status(self, project_id: UUID) -> dict:
        """Get bridge connection status, handling unreachability gracefully."""
        session = await self._get_active_session(project_id)

        try:
            result = await self._bridge_request({"method": "status", "params": {}})
            bridge_status = result.get("result", {})
        except ConnectionError:
            bridge_status = {
                "connected": False,
                "device": None,
                "baudrate": 0,
                "buffer_bytes": 0,
                "transcript_path": None,
                "bridge_error": "Bridge unreachable",
            }

        if session:
            bridge_status["session"] = {
                "id": str(session.id),
                "status": session.status,
                "device_path": session.device_path,
                "baudrate": session.baudrate,
            }

        return bridge_status

    async def disconnect(self, project_id: UUID) -> UARTSession:
        """Disconnect the UART session and update DB."""
        session = await self._get_active_session(project_id)
        if not session:
            raise ValueError("No active UART session for this project.")

        # Try to tell the bridge to disconnect — but don't fail if bridge is unreachable
        try:
            await self._bridge_request({"method": "disconnect", "params": {}})
        except ConnectionError:
            logger.warning("Bridge unreachable during disconnect — marking session closed anyway")

        session.status = "closed"
        session.closed_at = datetime.now(timezone.utc)
        await self._db.flush()
        return session

    async def get_transcript(self, project_id: UUID, tail_lines: int = 100) -> dict:
        """Get recent transcript entries from the bridge."""
        session = await self._get_active_session(project_id)
        if not session:
            raise ValueError("No active UART session for this project. Connect first.")

        result = await self._bridge_request({
            "method": "get_transcript",
            "params": {"tail_lines": tail_lines},
        })
        return result.get("result", {})

    async def list_sessions(self, project_id: UUID) -> list[UARTSession]:
        """List all UART sessions for a project."""
        result = await self._db.execute(
            select(UARTSession)
            .where(UARTSession.project_id == project_id)
            .order_by(UARTSession.created_at.desc())
        )
        return list(result.scalars().all())

    # ── Internal helpers ──

    async def _get_active_session(self, project_id: UUID) -> UARTSession | None:
        """Find the active (connected) UART session for a project."""
        result = await self._db.execute(
            select(UARTSession).where(
                UARTSession.project_id == project_id,
                UARTSession.status == "connected",
            )
        )
        return result.scalar_one_or_none()

    async def _bridge_request(self, request: dict) -> dict:
        """Send a JSON request to the bridge and return the response.

        Opens a fresh TCP connection per call (simple, no pooling needed for v1).
        """
        settings = get_settings()
        host = settings.uart_bridge_host
        port = settings.uart_bridge_port

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=5,
            )
        except (OSError, asyncio.TimeoutError) as exc:
            raise ConnectionError(
                f"Cannot reach UART bridge at {host}:{port}. "
                f"Is wairz-uart-bridge running on the host? Error: {exc}"
            ) from exc

        try:
            # Send request
            payload = json.dumps(request) + "\n"
            writer.write(payload.encode("utf-8"))
            await writer.drain()

            # Read response (with timeout)
            line = await asyncio.wait_for(reader.readline(), timeout=60)
            if not line:
                raise ConnectionError("Bridge closed connection without response")

            response = json.loads(line.decode("utf-8"))
            if not response.get("ok"):
                raise ValueError(response.get("error", "Unknown bridge error"))

            return response
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
