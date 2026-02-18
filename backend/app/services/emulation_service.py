"""Service for managing QEMU-based firmware emulation sessions.

Uses the Docker SDK to spawn isolated containers running QEMU in user-mode
(single binary chroot) or system-mode (full OS boot).
"""

import asyncio
import logging
import os
import shlex
from datetime import datetime, timezone
from uuid import UUID

import docker
import docker.errors
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.models.emulation_session import EmulationSession
from app.models.firmware import Firmware
from app.utils.sandbox import validate_path

logger = logging.getLogger(__name__)

# Map canonical architecture → QEMU user-mode binary
QEMU_USER_BIN_MAP: dict[str, str] = {
    "arm": "qemu-arm-static",
    "aarch64": "qemu-aarch64-static",
    "mips": "qemu-mips-static",
    "mipsel": "qemu-mipsel-static",
    "x86": "qemu-i386-static",
    "x86_64": "qemu-x86_64-static",
}

# Architecture aliases → canonical names used by QEMU
ARCH_ALIASES: dict[str, str] = {
    "arm": "arm",
    "armhf": "arm",
    "armel": "arm",
    "ARM": "arm",
    "aarch64": "aarch64",
    "arm64": "aarch64",
    "mips": "mips",
    "MIPS": "mips",
    "mipsbe": "mips",
    "mipsel": "mipsel",
    "MIPS-LE": "mipsel",
    "mipsle": "mipsel",
    "x86": "x86",
    "i386": "x86",
    "i686": "x86",
    "x86_64": "x86_64",
    "amd64": "x86_64",
}


def _validate_kernel_file(path: str) -> tuple[bool, str]:
    """Check whether a file looks like a valid kernel image by inspecting magic bytes.

    Returns (is_valid, reason) where reason describes what was detected or
    why the file was rejected.
    """
    try:
        size = os.path.getsize(path)
    except OSError:
        return False, "file not found or unreadable"

    if size < 500_000:
        return False, f"too small ({size} bytes) — kernels are typically >500KB"

    try:
        with open(path, "rb") as f:
            header = f.read(64)
    except OSError:
        return False, "unable to read file"

    if len(header) < 4:
        return False, "file too short to identify"

    # ELF — must be ET_EXEC (vmlinux), not ET_DYN (shared lib)
    if header[:4] == b"\x7fELF":
        # e_type is at offset 16 (2 bytes). ET_EXEC = 2
        if len(header) >= 18:
            # Check both endiannesses (EI_DATA at offset 5: 1=LE, 2=BE)
            ei_data = header[5]
            if ei_data == 1:  # little-endian
                e_type = int.from_bytes(header[16:18], "little")
            else:
                e_type = int.from_bytes(header[16:18], "big")
            if e_type == 2:
                return True, "ELF executable (vmlinux)"
            return False, f"ELF file but type={e_type} (not ET_EXEC=2) — likely a shared library or firmware image"
        return False, "ELF header too short"

    # U-Boot uImage
    if header[:4] == b"\x27\x05\x19\x56":
        return True, "U-Boot uImage"

    # ARM zImage — magic at offset 0x24: 0x016f2818 (little-endian)
    if len(header) >= 0x28:
        arm_magic = header[0x24:0x28]
        if arm_magic == b"\x18\x28\x6f\x01":
            return True, "ARM zImage"

    # gzip-compressed (common for compressed kernels)
    if header[:2] == b"\x1f\x8b" and size > 500_000:
        return True, "gzip-compressed (possibly vmlinuz)"

    # LZMA-compressed
    if header[:3] == b"\x5d\x00\x00" and size > 500_000:
        return True, "LZMA-compressed (possibly vmlinuz)"

    return False, "unrecognized format — not ELF/uImage/zImage/gzip/LZMA"


class EmulationService:
    """Manages QEMU emulation session lifecycle via Docker containers."""

    def __init__(self, db: AsyncSession):
        self.db = db
        self._settings = get_settings()

    def _get_docker_client(self) -> docker.DockerClient:
        """Create a Docker client (created per-call, not cached)."""
        return docker.from_env()

    def _normalize_arch(self, arch: str | None) -> str | None:
        if not arch:
            return None
        return ARCH_ALIASES.get(arch, arch.lower())

    async def _count_active_sessions(self, project_id: UUID) -> int:
        result = await self.db.scalar(
            select(func.count(EmulationSession.id)).where(
                EmulationSession.project_id == project_id,
                EmulationSession.status.in_(["created", "starting", "running"]),
            )
        )
        return result or 0

    async def start_session(
        self,
        firmware: Firmware,
        mode: str,
        binary_path: str | None = None,
        arguments: str | None = None,
        port_forwards: list[dict] | None = None,
        kernel_name: str | None = None,
    ) -> EmulationSession:
        """Start a new emulation session.

        Args:
            firmware: The firmware record (must have extracted_path).
            mode: "user" or "system".
            binary_path: For user mode — path to the binary within the extracted FS.
            arguments: Optional CLI arguments for user mode.
            port_forwards: List of {"host": int, "guest": int} dicts.
        """
        if mode not in ("user", "system"):
            raise ValueError("mode must be 'user' or 'system'")

        if not firmware.extracted_path:
            raise ValueError("Firmware has not been unpacked")

        if mode == "user" and not binary_path:
            raise ValueError("binary_path is required for user-mode emulation")

        # Validate binary_path against extracted root
        if binary_path:
            validate_path(firmware.extracted_path, binary_path)

        # Check concurrent session limit
        active = await self._count_active_sessions(firmware.project_id)
        if active >= self._settings.emulation_max_sessions:
            raise ValueError(
                f"Maximum concurrent sessions ({self._settings.emulation_max_sessions}) reached. "
                "Stop an existing session first."
            )

        arch = self._normalize_arch(firmware.architecture)
        if not arch:
            raise ValueError(
                "Cannot determine firmware architecture. "
                "Architecture detection must complete before emulation."
            )

        # Create DB record
        session = EmulationSession(
            project_id=firmware.project_id,
            firmware_id=firmware.id,
            mode=mode,
            status="starting",
            binary_path=binary_path,
            arguments=arguments,
            architecture=arch,
            port_forwards=port_forwards or [],
        )
        self.db.add(session)
        await self.db.flush()

        # Start Docker container
        try:
            container_id = await self._start_container(
                session=session,
                extracted_path=firmware.extracted_path,
                kernel_name=kernel_name,
                firmware_kernel_path=firmware.kernel_path,
            )
            session.container_id = container_id
            session.status = "running"
            session.started_at = datetime.now(timezone.utc)
        except Exception as exc:
            logger.exception("Failed to start emulation container")
            session.status = "error"
            session.error_message = str(exc)

        await self.db.flush()
        return session

    def _resolve_host_path(self, container_path: str) -> str | None:
        """Resolve a path inside this container to a host path for Docker mounts.

        When the backend runs inside Docker and uses the Docker socket, volume
        mounts reference HOST paths, not container paths. This method inspects
        our own container's mounts to translate paths.

        If not running in Docker, returns the path as-is.
        Returns None if the path is not on any mount (baked into image).
        """
        real_path = os.path.realpath(container_path)

        # Not running in Docker — path is already a host path
        if not os.path.exists("/.dockerenv"):
            return real_path

        client = self._get_docker_client()

        # Find our own container by hostname (Docker sets HOSTNAME to container ID)
        hostname = os.environ.get("HOSTNAME", "")
        if not hostname:
            return real_path

        try:
            our_container = client.containers.get(hostname)
            mounts = our_container.attrs.get("Mounts", [])

            for mount in mounts:
                dest = mount.get("Destination", "")
                source = mount.get("Source", "")
                if not dest or not source:
                    continue

                # Check if our path falls under this mount
                if real_path.startswith(dest + os.sep) or real_path == dest:
                    relative = os.path.relpath(real_path, dest)
                    host_path = os.path.join(source, relative)
                    logger.info(
                        "Path translation: %s -> %s (via mount %s -> %s)",
                        real_path, host_path, source, dest,
                    )
                    return host_path

        except Exception:
            logger.warning(
                "Could not inspect own container for path translation: %s",
                real_path,
            )

        # Path is not on any Docker mount — baked into the container image
        return None

    @staticmethod
    def _copy_dir_to_container(
        container: "docker.models.containers.Container",
        src_path: str,
        dst_path: str,
    ) -> None:
        """Copy a directory tree into a running container using put_archive.

        Creates a tar archive of src_path contents and streams it into
        dst_path inside the container.
        """
        import io
        import tarfile

        tar_stream = io.BytesIO()
        with tarfile.open(fileobj=tar_stream, mode="w") as tar:
            # Add all files from src_path, with arcname="" so they land
            # directly in dst_path (not in a subdirectory)
            for entry in os.scandir(src_path):
                tar.add(entry.path, arcname=entry.name)
        tar_stream.seek(0)

        container.put_archive(dst_path, tar_stream)

    @staticmethod
    def _copy_file_to_container(
        container: "docker.models.containers.Container",
        src_path: str,
        dst_path: str,
    ) -> None:
        """Copy a single file into a running container using put_archive."""
        import io
        import tarfile

        dst_dir = os.path.dirname(dst_path)
        dst_name = os.path.basename(dst_path)

        tar_stream = io.BytesIO()
        with tarfile.open(fileobj=tar_stream, mode="w") as tar:
            tar.add(src_path, arcname=dst_name)
        tar_stream.seek(0)

        container.put_archive(dst_dir, tar_stream)

    @staticmethod
    def _fix_firmware_permissions(
        container: "docker.models.containers.Container",
    ) -> None:
        """Fix execute permissions and broken symlinks in firmware.

        Binwalk extraction often loses execute bits and corrupts symlinks
        (replacing them with small files containing the original symlink
        target as text, or just null bytes). This method:
        1. Makes files in common binary/library directories executable.
        2. Restores corrupted symlinks across the entire firmware tree by
           reading small file contents to recover the original target path.
        3. Falls back to heuristics for .so versioned libraries and busybox.
        """
        bin_dirs = [
            "/firmware/bin", "/firmware/sbin",
            "/firmware/usr/bin", "/firmware/usr/sbin",
            "/firmware/lib", "/firmware/usr/lib",
            "/firmware/lib32", "/firmware/usr/lib32",
        ]
        for d in bin_dirs:
            container.exec_run(
                ["sh", "-c", f"[ -d {d} ] && chmod -R +x {d} 2>/dev/null || true"]
            )

        # Generic symlink restoration script.
        # Binwalk corruption patterns:
        #   a) Small file whose content IS the symlink target (as text, possibly null-padded)
        #   b) Small file of pure null bytes (target lost — need heuristics)
        #
        # Strategy:
        #   Pass 1: Scan entire tree for small files (<256 bytes). Read content.
        #           If content looks like a path, restore symlink.
        #   Pass 2: Fix remaining .so stubs using versioned-name matching.
        #   Pass 3: Fix remaining null stubs in bin/sbin using busybox (if present).
        fix_symlinks_script = r"""
FIXED=0
PASS1=0
PASS2=0
PASS3=0

# --- Pass 1: Content-based symlink recovery (most reliable) ---
# Scan the entire firmware tree for small regular files whose content
# looks like a symlink target path (e.g., "busybox", "../lib/libc.so.6",
# "/usr/bin/python3").
find /firmware -type f -size -256c 2>/dev/null | while read stub; do
    # Read file content, strip null bytes and whitespace
    target=$(tr -d '\000' < "$stub" 2>/dev/null | tr -d '\r\n' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')

    # Skip empty content
    [ -z "$target" ] && continue

    # Validate: target must look like a path (relative or absolute)
    # and contain only valid path characters
    case "$target" in
        /*|./*|../*)
            # Absolute or explicit relative path — good
            ;;
        *)
            # Bare name — only accept if it contains no spaces/specials
            # and is short (likely "busybox", "bash", etc.)
            case "$target" in
                *[[:space:]]*|*[^a-zA-Z0-9._-]*) continue ;;
            esac
            [ ${#target} -gt 64 ] && continue
            ;;
    esac

    # Don't create circular symlinks
    stubname=$(basename "$stub")
    targetname=$(basename "$target")
    [ "$stubname" = "$targetname" ] && [ "$target" = "$targetname" ] && continue

    # Replace the stub with a symlink
    rm -f "$stub"
    ln -s "$target" "$stub"
    PASS1=$((PASS1 + 1))
done

# --- Pass 2: Versioned .so heuristic for remaining stubs ---
# Some corrupted .so stubs may have been pure null (no readable target).
# Match libfoo.so -> libfoo.so.X.Y.Z by name pattern.
for dir in /firmware/lib /firmware/usr/lib /firmware/lib32 /firmware/usr/lib32; do
    [ -d "$dir" ] || continue
    for stub in $(find "$dir" -maxdepth 1 \( -name '*.so' -o -name '*.so.[0-9]*' \) 2>/dev/null); do
        # Skip if already a symlink (fixed in pass 1)
        [ -L "$stub" ] && continue
        [ -f "$stub" ] || continue
        size=$(stat -c%s "$stub" 2>/dev/null || echo 999999)
        [ "$size" -lt 256 ] || continue
        base=$(basename "$stub")
        best=""
        best_len=0
        for candidate in "$dir"/${base}*; do
            [ -f "$candidate" ] || [ -L "$candidate" ] || continue
            cand_name=$(basename "$candidate")
            [ "$cand_name" = "$base" ] && continue
            cand_size=$(stat -c%s "$candidate" 2>/dev/null || echo 0)
            [ "$cand_size" -gt 256 ] || [ -L "$candidate" ] || continue
            cand_len=${#cand_name}
            if [ "$cand_len" -gt "$best_len" ]; then
                best="$cand_name"
                best_len=$cand_len
            fi
        done
        if [ -n "$best" ]; then
            rm -f "$stub"
            ln -s "$best" "$stub"
            PASS2=$((PASS2 + 1))
        fi
    done
done

# --- Pass 3: Busybox fallback for remaining null stubs ---
# Only applies to files in bin/sbin dirs that are still tiny and not
# yet symlinks. This is the last resort for pure-null stubs.
bb=""
for candidate in /firmware/bin/busybox /firmware/usr/bin/busybox; do
    if [ -f "$candidate" ] && [ ! -L "$candidate" ]; then
        cand_size=$(stat -c%s "$candidate" 2>/dev/null || echo 0)
        if [ "$cand_size" -gt 1000 ]; then
            # Strip /firmware prefix so symlinks work as both chroot
            # and ext4 root paths
            bb="${candidate#/firmware}"
            break
        fi
    fi
done
if [ -n "$bb" ]; then
    for dir in /firmware/bin /firmware/sbin /firmware/usr/bin /firmware/usr/sbin; do
        [ -d "$dir" ] || continue
        for stub in "$dir"/*; do
            # Skip symlinks (already fixed) and directories
            [ -L "$stub" ] && continue
            [ -f "$stub" ] || continue
            size=$(stat -c%s "$stub" 2>/dev/null || echo 999999)
            [ "$size" -lt 64 ] || continue
            name=$(basename "$stub")
            [ "$name" = "busybox" ] && continue
            # Verify it's actually null/empty content (not a real tiny script)
            content=$(tr -d '\000' < "$stub" 2>/dev/null)
            [ -z "$content" ] || continue
            rm -f "$stub"
            ln -s "$bb" "$stub"
            PASS3=$((PASS3 + 1))
        done
    done
fi

echo "Symlink repair: pass1=$PASS1 pass2=$PASS2 pass3=$PASS3"
"""
        result = container.exec_run(["sh", "-c", fix_symlinks_script])
        output = result.output.decode("utf-8", errors="replace").strip()
        if output:
            logger.info("Firmware symlink repair: %s", output)

    def _find_initrd(
        self,
        kernel_path: str | None,
        kernel_name: str | None = None,
    ) -> str | None:
        """Find the initrd/initramfs companion for a kernel.

        Checks the kernel service sidecar metadata and convention-based
        naming (<kernel>.initrd).
        """
        from app.services.kernel_service import KernelService

        if not kernel_path:
            return None

        svc = KernelService()

        # If kernel_name was specified, check sidecar directly
        if kernel_name:
            initrd = svc._initrd_path(kernel_name)
            if initrd:
                return initrd

        # Try convention: look for <kernel_basename>.initrd in the kernel dir
        kernel_basename = os.path.basename(kernel_path)
        initrd = svc._initrd_path(kernel_basename)
        if initrd:
            return initrd

        return None

    async def _start_container(
        self,
        session: EmulationSession,
        extracted_path: str,
        kernel_name: str | None = None,
        firmware_kernel_path: str | None = None,
    ) -> str:
        """Spawn a Docker container for this emulation session."""
        client = self._get_docker_client()
        settings = self._settings

        # Resolve the extracted path to a host path for Docker volume mounts.
        # If None, the data is baked into the backend image (not on a volume),
        # so we'll use docker cp instead of a bind mount.
        real_path = os.path.realpath(extracted_path)
        host_path = self._resolve_host_path(real_path)
        use_docker_cp = host_path is None

        volumes = {}
        if not use_docker_cp:
            volumes[host_path] = {"bind": "/firmware", "mode": "rw"}

        # Build port bindings for system mode
        port_bindings = {}
        if session.port_forwards:
            for pf in session.port_forwards:
                guest = pf.get("guest", 0)
                host_ = pf.get("host", 0)
                if guest and host_:
                    port_bindings[f"{guest}/tcp"] = [{"HostPort": str(host_)}]

        # Resolve kernel path for system mode (backend-side path)
        kernel_backend_path = None
        initrd_backend_path = None
        if session.mode == "system":
            kernel_backend_path = self._find_kernel(
                session.architecture,
                kernel_name=kernel_name,
                firmware_kernel_path=firmware_kernel_path,
            )
            # Look for companion initrd
            initrd_backend_path = self._find_initrd(
                kernel_backend_path, kernel_name
            )
            if initrd_backend_path:
                logger.info("Found initrd: %s", initrd_backend_path)

        # Build the command for the container (kernel path will be updated below)
        if session.mode == "user":
            cmd = [
                "/opt/scripts/start-user-mode.sh",
                session.architecture or "arm",
                "/firmware",
                session.binary_path or "",
            ]
            if session.arguments:
                cmd.extend(session.arguments.split())

        # Container-internal path where the kernel will be placed
        CONTAINER_KERNEL_PATH = "/tmp/kernel"

        common_labels = {
            "wairz.session_id": str(session.id),
            "wairz.project_id": str(session.project_id),
            "wairz.mode": session.mode,
        }

        if use_docker_cp:
            # Create container with "sleep infinity" so we can copy files via SDK.
            container = client.containers.run(
                image=settings.emulation_image,
                command=["sleep", "infinity"],
                detach=True,
                ports=port_bindings or None,
                mem_limit=f"{settings.emulation_memory_limit_mb}m",
                nano_cpus=int(settings.emulation_cpu_limit * 1e9),
                privileged=False,
                network_mode="bridge",
                labels=common_labels,
            )

            # Create /firmware dir, then copy the extracted filesystem into it
            # using the Docker SDK's put_archive (accepts a tar stream).
            container.exec_run(["mkdir", "-p", "/firmware"])

            logger.info("Copying firmware to emulation container via tar stream: %s", real_path)
            try:
                self._copy_dir_to_container(container, real_path, "/firmware")
            except Exception as exc:
                container.remove(force=True)
                raise RuntimeError(f"Failed to copy firmware to emulation container: {exc}")

            # Fix permissions — binwalk extraction may lose execute bits.
            self._fix_firmware_permissions(container)

        else:
            # Standard bind mount — host path is available
            container = client.containers.run(
                image=settings.emulation_image,
                command=["sleep", "infinity"],
                detach=True,
                volumes=volumes or None,
                ports=port_bindings or None,
                mem_limit=f"{settings.emulation_memory_limit_mb}m",
                nano_cpus=int(settings.emulation_cpu_limit * 1e9),
                privileged=False,
                network_mode="bridge",
                labels=common_labels,
            )

            # Fix permissions — binwalk extraction may lose execute bits.
            self._fix_firmware_permissions(container)

        # For system mode, copy the kernel into the container and launch QEMU
        if session.mode == "system":
            if not kernel_backend_path:
                # No valid kernel available — clean up the container
                container.remove(force=True)
                raise ValueError(
                    "System-mode emulation requires a valid kernel, but none was found. "
                    "The firmware-extracted kernel (if any) failed validation and no "
                    "pre-built kernels are available. Upload a QEMU-compatible kernel "
                    "via the Kernel Manager."
                )

            self._copy_file_to_container(
                container, kernel_backend_path, CONTAINER_KERNEL_PATH,
            )

            # Copy initrd if available
            CONTAINER_INITRD_PATH = "/tmp/initrd"
            initrd_arg = ""
            if initrd_backend_path and os.path.isfile(initrd_backend_path):
                self._copy_file_to_container(
                    container, initrd_backend_path, CONTAINER_INITRD_PATH,
                )
                initrd_arg = CONTAINER_INITRD_PATH
                logger.info("Copied initrd to container: %s", initrd_backend_path)

            pf_str = ""
            if session.port_forwards:
                pf_str = ",".join(
                    f"{pf['host']}:{pf['guest']}" for pf in session.port_forwards
                )
            cmd = [
                "/opt/scripts/start-system-mode.sh",
                session.architecture or "arm",
                "/firmware",
                CONTAINER_KERNEL_PATH,
                pf_str,
                initrd_arg,
            ]
            container.exec_run(cmd, detach=True)

            # Health check: wait briefly to catch early QEMU failures
            await self._await_system_startup(container)

        return container.id

    async def _await_system_startup(
        self,
        container: "docker.models.containers.Container",
        timeout: int = 30,
    ) -> None:
        """Wait briefly after QEMU launch and check for early failures.

        The startup script creates an ext4 rootfs image (takes a few seconds),
        decompresses the kernel if needed, then exec's to QEMU. We need to
        account for this preparation phase where the QEMU process doesn't
        exist yet but the startup script is still running.

        Checks each second whether the startup script or QEMU is still alive.
        If both are gone, reads /tmp/qemu-system.log and raises with the log
        content so the caller can set error status.
        """
        qemu_was_seen = False

        for i in range(timeout):
            await asyncio.sleep(1)

            # Check if the container itself is still running
            try:
                container.reload()
                if container.status not in ("running", "created"):
                    log = self._read_container_qemu_log(container, quiet=True)
                    raise RuntimeError(
                        f"Emulation container exited during startup.\n\n"
                        f"--- QEMU log ---\n{log}"
                    )
            except docker.errors.NotFound:
                raise RuntimeError("Emulation container disappeared during startup")

            # Check if either the startup script or QEMU process is alive.
            # During ext4 creation, only the script runs. After exec, only
            # QEMU runs. If neither is found, something failed.
            try:
                result = container.exec_run(
                    ["sh", "-c",
                     "pgrep -f 'qemu-system' >/dev/null 2>&1 && echo qemu || "
                     "(pgrep -f 'start-system-mode' >/dev/null 2>&1 && echo script || echo none)"],
                )
                output = result.output.decode("utf-8", errors="replace").strip()

                if output == "qemu":
                    qemu_was_seen = True
                elif output == "none":
                    if qemu_was_seen:
                        # QEMU was running but now it's gone — it crashed
                        log = self._read_container_qemu_log(container)
                        raise RuntimeError(
                            f"QEMU process exited during startup.\n\n"
                            f"--- QEMU log ---\n{log}"
                        )
                    elif i > 15:
                        # Neither script nor QEMU found after 15s — something is wrong
                        log = self._read_container_qemu_log(container)
                        raise RuntimeError(
                            f"Neither startup script nor QEMU found after {i}s.\n\n"
                            f"--- QEMU log ---\n{log}"
                        )
                    # else: still early, script may not have started yet
            except docker.errors.APIError:
                pass  # Container may be in a transient state

            # Check if the serial socket appeared (means QEMU is up and listening)
            try:
                result = container.exec_run(["test", "-S", "/tmp/qemu-serial.sock"])
                if result.exit_code == 0:
                    logger.info("QEMU serial socket ready after %ds", i + 1)
                    return  # QEMU is healthy
            except docker.errors.APIError:
                pass

        # Timeout without socket, but QEMU is still running — that's OK,
        # it may just be slow (ext4 creation, kernel boot). Let it continue.
        logger.info(
            "QEMU still starting after %ds (no serial socket yet), "
            "continuing in background",
            timeout,
        )

    @staticmethod
    def _read_container_qemu_log(
        container: "docker.models.containers.Container",
        max_bytes: int = 4000,
        quiet: bool = False,
    ) -> str:
        """Read /tmp/qemu-system.log from inside a container.

        Returns the log content (truncated to max_bytes) or a fallback
        message if the log is not available.
        """
        try:
            result = container.exec_run(["cat", "/tmp/qemu-system.log"])
            log = result.output.decode("utf-8", errors="replace")
            if len(log) > max_bytes:
                log = log[-max_bytes:] + "\n... [truncated]"
            return log.strip() if log.strip() else "(log file is empty)"
        except Exception:
            if not quiet:
                logger.debug("Could not read QEMU log from container")
            # Fall back to container logs
            try:
                log = container.logs(tail=50).decode("utf-8", errors="replace")
                return log.strip() if log.strip() else "(no log available)"
            except Exception:
                return "(no log available)"

    def _find_kernel(
        self,
        arch: str | None,
        kernel_name: str | None = None,
        firmware_kernel_path: str | None = None,
    ) -> str:
        """Find a kernel for system-mode emulation.

        Priority order:
        1. Explicit kernel_name (user-specified from kernel management)
        2. Kernel extracted from the firmware during unpacking
        3. Pre-built kernels in emulation_kernel_dir (matching architecture)
        """
        from app.services.kernel_service import KernelService

        kernel_dir = self._settings.emulation_kernel_dir

        # 1) User-specified kernel from the kernel management system
        if kernel_name:
            if "/" in kernel_name or "\\" in kernel_name or ".." in kernel_name:
                raise ValueError(f"Invalid kernel name: {kernel_name}")
            kernel_path = os.path.join(kernel_dir, kernel_name)
            if not os.path.isfile(kernel_path):
                raise ValueError(
                    f"Kernel '{kernel_name}' not found in {kernel_dir}. "
                    "Upload a kernel via the kernel management API."
                )
            return kernel_path

        # 2) Kernel extracted from the firmware itself — validate before using
        if firmware_kernel_path and os.path.isfile(firmware_kernel_path):
            is_valid, reason = _validate_kernel_file(firmware_kernel_path)
            if is_valid:
                logger.info(
                    "Using kernel extracted from firmware: %s (%s)",
                    firmware_kernel_path, reason,
                )
                return firmware_kernel_path
            else:
                logger.warning(
                    "Firmware kernel candidate rejected: %s — %s. "
                    "Falling through to pre-built kernels.",
                    firmware_kernel_path, reason,
                )

        # 3) Pre-built kernel from the kernel management directory
        svc = KernelService()
        match = svc.find_kernel_for_arch(arch or "arm")
        if match:
            return os.path.join(kernel_dir, match["name"])

        raise ValueError(
            f"No kernel available for architecture '{arch or 'arm'}'. "
            "System-mode emulation requires a pre-built Linux kernel. "
            "A kernel was not found in the firmware image. "
            "Upload one via the kernel management page or API "
            "(GET/POST /api/v1/kernels)."
        )

    @staticmethod
    def build_user_shell_cmd(arch: str) -> list[str]:
        """Return the command list for an interactive QEMU user-mode shell."""
        qemu_bin = QEMU_USER_BIN_MAP.get(arch, "qemu-arm-static")
        return [qemu_bin, "-L", "/firmware", "/firmware/bin/sh"]

    async def stop_session(self, session_id: UUID) -> EmulationSession:
        """Stop an emulation session and remove its container."""
        result = await self.db.execute(
            select(EmulationSession).where(EmulationSession.id == session_id)
        )
        session = result.scalar_one_or_none()
        if not session:
            raise ValueError("Session not found")

        if session.status in ("stopped", "error"):
            return session

        # Stop the Docker container
        if session.container_id:
            try:
                client = self._get_docker_client()
                container = client.containers.get(session.container_id)
                container.stop(timeout=5)
                container.remove(force=True)
            except docker.errors.NotFound:
                logger.info("Container already removed: %s", session.container_id)
            except Exception:
                logger.exception("Error stopping container: %s", session.container_id)

        session.status = "stopped"
        session.stopped_at = datetime.now(timezone.utc)
        await self.db.flush()
        return session

    async def exec_command(
        self,
        session_id: UUID,
        command: str,
        timeout: int = 30,
    ) -> dict:
        """Execute a command inside a running emulation session."""
        result = await self.db.execute(
            select(EmulationSession).where(EmulationSession.id == session_id)
        )
        session = result.scalar_one_or_none()
        if not session:
            raise ValueError("Session not found")

        if session.status != "running":
            raise ValueError(f"Session is not running (status: {session.status})")

        if not session.container_id:
            raise ValueError("No container associated with this session")

        client = self._get_docker_client()
        try:
            container = client.containers.get(session.container_id)
        except docker.errors.NotFound:
            session.status = "error"
            session.error_message = "Container not found"
            await self.db.flush()
            raise ValueError("Container not found — session may have been terminated")

        # Build exec command — for user mode, use qemu-static with -L flag.
        # Wrap with `timeout` for enforcement (Docker SDK exec_run has no
        # timeout parameter).
        if session.mode == "user":
            arch = session.architecture or "arm"
            qemu_bin = QEMU_USER_BIN_MAP.get(arch, "qemu-arm-static")
            exec_cmd = [
                "timeout", str(timeout),
                qemu_bin,
                "-L", "/firmware",
                "/firmware/bin/sh", "-c", command,
            ]
        else:
            # System mode: send command through QEMU's serial console socket.
            # This is inherently messy (serial console mixes prompts/output),
            # but it executes inside the emulated firmware instead of the
            # host container.
            exec_cmd = [
                "sh", "-c",
                f"echo {shlex.quote(command)} | timeout {timeout} socat - UNIX-CONNECT:/tmp/qemu-serial.sock",
            ]

        try:
            exec_result = container.exec_run(exec_cmd, demux=True)

            stdout_bytes = exec_result.output[0] if exec_result.output[0] else b""
            stderr_bytes = exec_result.output[1] if exec_result.output[1] else b""
            exit_code = exec_result.exit_code

            # `timeout` returns exit code 124 when it kills the child
            timed_out = exit_code == 124

            return {
                "stdout": stdout_bytes.decode("utf-8", errors="replace"),
                "stderr": stderr_bytes.decode("utf-8", errors="replace"),
                "exit_code": exit_code if not timed_out else -1,
                "timed_out": timed_out,
            }

        except Exception as exc:
            raise ValueError(f"Command execution failed: {exc}")

    async def get_status(self, session_id: UUID) -> EmulationSession:
        """Get the status of an emulation session, updating from Docker if running."""
        result = await self.db.execute(
            select(EmulationSession).where(EmulationSession.id == session_id)
        )
        session = result.scalar_one_or_none()
        if not session:
            raise ValueError("Session not found")

        # If session claims to be running, verify with Docker
        if session.status == "running" and session.container_id:
            try:
                client = self._get_docker_client()
                container = client.containers.get(session.container_id)
                if container.status not in ("running", "created"):
                    # Container died — try to read QEMU log for diagnostics
                    log = self._read_container_qemu_log(container, quiet=True)
                    session.status = "error"
                    session.error_message = (
                        f"Emulation container exited unexpectedly.\n\n"
                        f"--- QEMU log ---\n{log}"
                    )
                    session.stopped_at = datetime.now(timezone.utc)
                    await self.db.flush()
                elif session.mode == "system":
                    # Container is running, but check if QEMU process inside is alive
                    try:
                        check = container.exec_run(
                            ["sh", "-c", "pgrep -f 'qemu-system' >/dev/null 2>&1; echo $?"],
                        )
                        output = check.output.decode("utf-8", errors="replace").strip()
                        if output != "0":
                            log = self._read_container_qemu_log(container)
                            session.status = "error"
                            session.error_message = (
                                f"QEMU process has exited.\n\n"
                                f"--- QEMU log ---\n{log}"
                            )
                            session.stopped_at = datetime.now(timezone.utc)
                            await self.db.flush()
                    except docker.errors.APIError:
                        pass  # transient Docker error, don't update status
            except docker.errors.NotFound:
                session.status = "stopped"
                session.error_message = "Container no longer exists"
                session.stopped_at = datetime.now(timezone.utc)
                await self.db.flush()
            except Exception:
                logger.exception("Error checking container status")

        return session

    async def list_sessions(self, project_id: UUID) -> list[EmulationSession]:
        """List all emulation sessions for a project."""
        result = await self.db.execute(
            select(EmulationSession)
            .where(EmulationSession.project_id == project_id)
            .order_by(EmulationSession.created_at.desc())
        )
        return list(result.scalars().all())

    async def get_session_logs(self, session_id: UUID) -> str:
        """Read QEMU startup logs from a session's container.

        Works for both running and recently-stopped containers.
        Returns the log text or an explanatory message.
        """
        result = await self.db.execute(
            select(EmulationSession).where(EmulationSession.id == session_id)
        )
        session = result.scalar_one_or_none()
        if not session:
            raise ValueError("Session not found")

        if not session.container_id:
            # No container — return stored error_message if available
            if session.error_message:
                return session.error_message
            return "No container associated with this session — no logs available."

        try:
            client = self._get_docker_client()
            container = client.containers.get(session.container_id)
            return self._read_container_qemu_log(container, max_bytes=8000)
        except docker.errors.NotFound:
            # Container removed — return stored error_message
            if session.error_message:
                return session.error_message
            return "Container has been removed — no logs available."
        except Exception as exc:
            return f"Failed to read logs: {exc}"

    async def cleanup_expired(self) -> int:
        """Stop sessions that have exceeded the timeout. Returns count stopped."""
        timeout_minutes = self._settings.emulation_timeout_minutes
        cutoff = datetime.now(timezone.utc).timestamp() - (timeout_minutes * 60)

        result = await self.db.execute(
            select(EmulationSession).where(
                EmulationSession.status == "running",
                EmulationSession.started_at.isnot(None),
            )
        )
        sessions = result.scalars().all()
        count = 0

        for session in sessions:
            if session.started_at and session.started_at.timestamp() < cutoff:
                try:
                    await self.stop_session(session.id)
                    count += 1
                except Exception:
                    logger.exception("Failed to stop expired session: %s", session.id)

        return count
