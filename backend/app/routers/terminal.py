import asyncio
import fcntl
import logging
import os
import signal
import struct
import termios
import uuid

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from sqlalchemy import select

from app.database import async_session_factory
from app.models.firmware import Firmware
from app.models.project import Project

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/projects/{project_id}/terminal",
    tags=["terminal"],
)


@router.websocket("/ws")
async def websocket_terminal(
    websocket: WebSocket,
    project_id: uuid.UUID,
):
    await websocket.accept()

    # Look up project and firmware extracted_path
    async with async_session_factory() as db:
        result = await db.execute(select(Project).where(Project.id == project_id))
        project = result.scalar_one_or_none()
        if not project:
            await websocket.send_json({"type": "error", "data": "Project not found"})
            await websocket.close(code=4004)
            return

        fw_result = await db.execute(
            select(Firmware).where(Firmware.project_id == project_id)
        )
        firmware = fw_result.scalar_one_or_none()
        if not firmware or not firmware.extracted_path:
            await websocket.send_json(
                {"type": "error", "data": "No unpacked firmware found"}
            )
            await websocket.close(code=4004)
            return

        extracted_path = firmware.extracted_path

    if not os.path.isdir(extracted_path):
        await websocket.send_json(
            {"type": "error", "data": "Extracted firmware directory not found on disk"}
        )
        await websocket.close(code=4004)
        return

    # Spawn PTY
    master_fd, slave_fd = os.openpty()
    child_pid = os.fork()

    if child_pid == 0:
        # Child process
        os.close(master_fd)
        os.setsid()
        fcntl.ioctl(slave_fd, termios.TIOCSCTTY, 0)
        os.dup2(slave_fd, 0)
        os.dup2(slave_fd, 1)
        os.dup2(slave_fd, 2)
        if slave_fd > 2:
            os.close(slave_fd)

        real_root = os.path.realpath(extracted_path)

        env = {
            "TERM": "xterm-256color",
            "HOME": real_root,
            "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "PS1": r"wairz:\w\$ ",
            "LANG": "C.UTF-8",
        }

        os.chdir(real_root)
        os.execve("/bin/bash", ["/bin/bash", "--norc", "--noprofile"], env)
        # execve doesn't return

    # Parent process
    os.close(slave_fd)

    loop = asyncio.get_event_loop()

    # Send welcome banner
    banner = f"\r\n  Firmware root: {extracted_path}\r\n\r\n"
    await websocket.send_json({"type": "output", "data": banner})

    reader_task = None
    writer_task = None

    async def read_pty():
        """Read from PTY master and send to WebSocket."""
        try:
            while True:
                data = await loop.run_in_executor(None, os.read, master_fd, 4096)
                if not data:
                    break
                await websocket.send_json(
                    {"type": "output", "data": data.decode("utf-8", errors="replace")}
                )
        except OSError:
            # PTY closed
            pass
        except Exception:
            logger.debug("PTY reader stopped")

    async def write_pty():
        """Read from WebSocket and write to PTY master."""
        try:
            while True:
                msg = await websocket.receive_json()
                msg_type = msg.get("type")

                if msg_type == "input":
                    input_data = msg.get("data", "")
                    if input_data:
                        os.write(master_fd, input_data.encode("utf-8"))

                elif msg_type == "resize":
                    cols = msg.get("cols", 80)
                    rows = msg.get("rows", 24)
                    winsize = struct.pack("HHHH", rows, cols, 0, 0)
                    fcntl.ioctl(master_fd, termios.TIOCSWINSZ, winsize)
        except WebSocketDisconnect:
            pass
        except Exception:
            logger.debug("PTY writer stopped")

    try:
        reader_task = asyncio.create_task(read_pty())
        writer_task = asyncio.create_task(write_pty())
        # Wait for either task to finish (usually writer finishes on disconnect)
        done, pending = await asyncio.wait(
            [reader_task, writer_task], return_when=asyncio.FIRST_COMPLETED
        )
        for task in pending:
            task.cancel()
    finally:
        # Cleanup: kill child process and close FDs
        try:
            os.kill(child_pid, signal.SIGTERM)
        except OSError:
            pass

        try:
            os.close(master_fd)
        except OSError:
            pass

        # Reap child
        try:
            os.waitpid(child_pid, os.WNOHANG)
        except ChildProcessError:
            pass

        # Ensure kill if still running
        try:
            os.kill(child_pid, signal.SIGKILL)
        except OSError:
            pass
        try:
            os.waitpid(child_pid, os.WNOHANG)
        except ChildProcessError:
            pass

        logger.info("Terminal session ended: project=%s", project_id)
