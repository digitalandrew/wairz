"""REST and WebSocket endpoints for firmware emulation sessions."""

import asyncio
import logging
import uuid

from fastapi import APIRouter, Depends, HTTPException, WebSocket, WebSocketDisconnect
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import async_session_factory, get_db
from app.models.emulation_session import EmulationSession
from app.models.firmware import Firmware
from app.schemas.emulation import (
    EmulationExecRequest,
    EmulationExecResponse,
    EmulationPresetCreate,
    EmulationPresetResponse,
    EmulationPresetUpdate,
    EmulationSessionResponse,
    EmulationStartRequest,
)
from app.services.emulation_service import EmulationService
from app.services.firmware_service import FirmwareService

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/projects/{project_id}/emulation",
    tags=["emulation"],
)


async def _resolve_firmware(
    project_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
) -> Firmware:
    """Resolve project -> firmware, return firmware record."""
    svc = FirmwareService(db)
    firmware = await svc.get_by_project(project_id)
    if not firmware:
        raise HTTPException(404, "No firmware uploaded for this project")
    if not firmware.extracted_path:
        raise HTTPException(400, "Firmware not yet unpacked")
    return firmware


@router.post("/start", response_model=EmulationSessionResponse, status_code=201)
async def start_emulation(
    project_id: uuid.UUID,
    request: EmulationStartRequest,
    firmware: Firmware = Depends(_resolve_firmware),
    db: AsyncSession = Depends(get_db),
):
    """Start a new emulation session (user-mode or system-mode)."""
    svc = EmulationService(db)

    try:
        session = await svc.start_session(
            firmware=firmware,
            mode=request.mode,
            binary_path=request.binary_path,
            arguments=request.arguments,
            port_forwards=[pf.model_dump() for pf in request.port_forwards],
            kernel_name=request.kernel_name,
            init_path=request.init_path,
            pre_init_script=request.pre_init_script,
        )
    except ValueError as exc:
        raise HTTPException(400, str(exc))

    return session


@router.post(
    "/{session_id}/stop",
    response_model=EmulationSessionResponse,
)
async def stop_emulation(
    project_id: uuid.UUID,
    session_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    """Stop an emulation session."""
    svc = EmulationService(db)
    try:
        session = await svc.stop_session(session_id)
    except ValueError as exc:
        raise HTTPException(404, str(exc))
    return session


@router.post(
    "/{session_id}/exec",
    response_model=EmulationExecResponse,
)
async def exec_in_emulation(
    project_id: uuid.UUID,
    session_id: uuid.UUID,
    request: EmulationExecRequest,
    db: AsyncSession = Depends(get_db),
):
    """Execute a command inside a running emulation session."""
    svc = EmulationService(db)
    try:
        result = await svc.exec_command(
            session_id=session_id,
            command=request.command,
            timeout=request.timeout,
            environment=request.environment,
        )
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    return result


@router.get("/sessions", response_model=list[EmulationSessionResponse])
async def list_sessions(
    project_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    """List all emulation sessions for this project.

    Also updates status for any sessions that claim to be running —
    detects dead QEMU processes and captures error logs.
    """
    svc = EmulationService(db)
    sessions = await svc.list_sessions(project_id)
    # Update status for running sessions (detect dead QEMU)
    for session in sessions:
        if session.status in ("running", "starting"):
            try:
                await svc.get_status(session.id)
            except Exception:
                pass
    return sessions


@router.get("/{session_id}/status", response_model=EmulationSessionResponse)
async def get_session_status(
    project_id: uuid.UUID,
    session_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    """Get the current status of an emulation session."""
    svc = EmulationService(db)
    try:
        session = await svc.get_status(session_id)
    except ValueError as exc:
        raise HTTPException(404, str(exc))
    return session


@router.get("/{session_id}/logs")
async def get_session_logs(
    project_id: uuid.UUID,
    session_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    """Get QEMU startup/error logs for an emulation session."""
    svc = EmulationService(db)
    try:
        logs = await svc.get_session_logs(session_id)
    except ValueError as exc:
        raise HTTPException(404, str(exc))
    return {"logs": logs}


# ── Emulation Presets ──


@router.post("/presets", response_model=EmulationPresetResponse, status_code=201)
async def create_preset(
    project_id: uuid.UUID,
    request: EmulationPresetCreate,
    db: AsyncSession = Depends(get_db),
):
    """Create a new emulation preset."""
    svc = EmulationService(db)
    try:
        preset = await svc.create_preset(
            project_id=project_id,
            name=request.name,
            mode=request.mode,
            description=request.description,
            binary_path=request.binary_path,
            arguments=request.arguments,
            architecture=request.architecture,
            port_forwards=[pf.model_dump() for pf in request.port_forwards],
            kernel_name=request.kernel_name,
            init_path=request.init_path,
            pre_init_script=request.pre_init_script,
        )
        await db.commit()
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    return preset


@router.get("/presets", response_model=list[EmulationPresetResponse])
async def list_presets(
    project_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    """List all emulation presets for this project."""
    svc = EmulationService(db)
    return await svc.list_presets(project_id)


@router.get("/presets/{preset_id}", response_model=EmulationPresetResponse)
async def get_preset(
    project_id: uuid.UUID,
    preset_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    """Get a single emulation preset."""
    svc = EmulationService(db)
    try:
        return await svc.get_preset(preset_id)
    except ValueError as exc:
        raise HTTPException(404, str(exc))


@router.patch("/presets/{preset_id}", response_model=EmulationPresetResponse)
async def update_preset(
    project_id: uuid.UUID,
    preset_id: uuid.UUID,
    request: EmulationPresetUpdate,
    db: AsyncSession = Depends(get_db),
):
    """Update an emulation preset."""
    svc = EmulationService(db)
    try:
        updates = request.model_dump(exclude_unset=True)
        preset = await svc.update_preset(preset_id, updates)
        await db.commit()
    except ValueError as exc:
        raise HTTPException(404, str(exc))
    return preset


@router.delete("/presets/{preset_id}", status_code=204)
async def delete_preset(
    project_id: uuid.UUID,
    preset_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    """Delete an emulation preset."""
    svc = EmulationService(db)
    try:
        await svc.delete_preset(preset_id)
        await db.commit()
    except ValueError as exc:
        raise HTTPException(404, str(exc))


@router.websocket("/{session_id}/terminal")
async def websocket_emulation_terminal(
    websocket: WebSocket,
    project_id: uuid.UUID,
    session_id: uuid.UUID,
):
    """WebSocket terminal for interactive access to an emulation session.

    Connects to the Docker container's PTY, forwarding input/output
    using the same protocol as the firmware terminal:
      - Client sends: { "type": "input", "data": "<keystrokes>" }
      - Client sends: { "type": "resize", "cols": 80, "rows": 24 }
      - Server sends: { "type": "output", "data": "<text>" }
      - Server sends: { "type": "error", "data": "<message>" }
    """
    await websocket.accept()

    async with async_session_factory() as db:
        # Validate session
        result = await db.execute(
            select(EmulationSession).where(
                EmulationSession.id == session_id,
                EmulationSession.project_id == project_id,
            )
        )
        session = result.scalar_one_or_none()
        if not session:
            await websocket.send_json({"type": "error", "data": "Session not found"})
            await websocket.close(code=4004)
            return

        if session.status != "running" or not session.container_id:
            await websocket.send_json(
                {"type": "error", "data": f"Session is not running (status: {session.status})"}
            )
            await websocket.close(code=4004)
            return

    # Connect to the container's exec instance
    import docker

    try:
        client = docker.from_env()
        container = client.containers.get(session.container_id)
    except docker.errors.NotFound:
        await websocket.send_json({"type": "error", "data": "Container not found"})
        await websocket.close(code=4004)
        return
    except Exception as exc:
        await websocket.send_json({"type": "error", "data": f"Docker error: {exc}"})
        await websocket.close(code=4004)
        return

    # Build the shell command — for user mode, run through QEMU user-mode
    if session.mode == "user":
        shell_cmd = EmulationService.build_user_shell_cmd(session.architecture or "arm")
    else:
        # System mode: wait for QEMU serial socket, then connect via socat.
        # The start-system-mode.sh script creates an ext4 rootfs image and
        # launches QEMU with serial output on /tmp/qemu-serial.sock.
        # Ext4 creation + QEMU startup can take a while, and the socket file
        # may appear before QEMU is ready to accept connections, so we retry.
        shell_cmd = [
            "sh", "-c",
            # Wait for socket file to appear (up to 120s — ext4 creation can be slow)
            "echo 'Waiting for QEMU to start...'; "
            "for i in $(seq 1 120); do "
            "  [ -S /tmp/qemu-serial.sock ] && break; "
            "  if [ $((i % 10)) -eq 0 ]; then echo \"  still waiting... (${i}s)\"; fi; "
            "  sleep 1; "
            "done; "
            "if [ ! -S /tmp/qemu-serial.sock ]; then "
            "  echo ''; echo 'ERROR: QEMU serial socket not found after 120s.'; "
            "  echo ''; echo '--- QEMU startup log ---'; "
            "  cat /tmp/qemu-system.log 2>/dev/null || echo 'No log file found.'; "
            "  echo ''; echo 'The kernel may not be compatible with this QEMU machine type.'; "
            "  echo 'Try uploading a kernel built for QEMU (e.g., from OpenWrt or Buildroot).'; "
            "  sleep 30; exit 1; "
            "fi; "
            # Retry socat connection (socket file may exist before QEMU is listening)
            "for i in $(seq 1 15); do "
            "  socat -,raw,echo=0 UNIX-CONNECT:/tmp/qemu-serial.sock 2>/dev/null && exit 0; "
            "  sleep 2; "
            "done; "
            # All retries failed — show diagnostics
            "echo ''; echo 'Failed to connect to QEMU serial console.'; "
            "echo ''; echo '--- QEMU startup log ---'; "
            "cat /tmp/qemu-system.log 2>/dev/null || echo 'No log file found.'; "
            "echo ''; echo 'QEMU started but the kernel may have crashed immediately.'; "
            "echo 'Firmware kernels are often incompatible with generic QEMU machine types.'; "
            "echo 'Upload a kernel built for QEMU (e.g., from OpenWrt or Buildroot).'; "
            "sleep 30",
        ]

    # Create an interactive exec instance
    exec_id = client.api.exec_create(
        container.id,
        shell_cmd,
        stdin=True,
        tty=True,
        stdout=True,
        stderr=True,
    )

    sock = client.api.exec_start(exec_id, socket=True, tty=True)
    raw_sock = sock._sock  # Get underlying socket

    await websocket.send_json({
        "type": "output",
        "data": f"\r\n  Emulation terminal ({session.mode} mode, {session.architecture})\r\n\r\n",
    })

    loop = asyncio.get_event_loop()
    reader_task = None
    writer_task = None

    async def read_container():
        """Read from container socket and send to WebSocket."""
        try:
            while True:
                data = await loop.run_in_executor(None, raw_sock.recv, 4096)
                if not data:
                    break
                await websocket.send_json({
                    "type": "output",
                    "data": data.decode("utf-8", errors="replace"),
                })
        except OSError:
            pass
        except Exception:
            logger.debug("Container reader stopped")

    async def write_container():
        """Read from WebSocket and write to container socket."""
        try:
            while True:
                msg = await websocket.receive_json()
                msg_type = msg.get("type")

                if msg_type == "input":
                    input_data = msg.get("data", "")
                    if input_data:
                        await loop.run_in_executor(
                            None, raw_sock.sendall, input_data.encode("utf-8")
                        )

                elif msg_type == "resize":
                    # Resize is best-effort — may not work for all exec types
                    cols = msg.get("cols", 80)
                    rows = msg.get("rows", 24)
                    try:
                        client.api.exec_resize(exec_id, height=rows, width=cols)
                    except Exception:
                        pass
        except WebSocketDisconnect:
            pass
        except Exception:
            logger.debug("Container writer stopped")

    try:
        reader_task = asyncio.create_task(read_container())
        writer_task = asyncio.create_task(write_container())
        done, pending = await asyncio.wait(
            [reader_task, writer_task], return_when=asyncio.FIRST_COMPLETED
        )
        for task in pending:
            task.cancel()
    finally:
        try:
            raw_sock.close()
        except Exception:
            pass
        try:
            sock.close()
        except Exception:
            pass
        logger.info(
            "Emulation terminal ended: project=%s session=%s",
            project_id,
            session_id,
        )
