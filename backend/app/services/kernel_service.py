"""Service for managing pre-built Linux kernels for system-mode emulation.

Kernels are a global resource (not per-project). The filesystem is the source
of truth -- no database table needed. JSON sidecar files store metadata
alongside each kernel binary.
"""

import ipaddress
import json
import logging
import os
import re
import socket
import tempfile
from datetime import datetime, timezone
from urllib.parse import urlparse

import aiofiles
import httpx

from app.config import get_settings

logger = logging.getLogger(__name__)

SUPPORTED_ARCHITECTURES = {"arm", "aarch64", "mips", "mipsel", "x86", "x86_64"}

# Patterns for guessing architecture from filename (order matters: check
# more-specific names first to avoid "mips" matching "mipsel").
_ARCH_PATTERNS: list[tuple[str, str]] = [
    ("mipsel", "mipsel"),
    ("mips", "mips"),
    ("aarch64", "aarch64"),
    ("arm64", "aarch64"),
    ("arm", "arm"),
    ("x86_64", "x86_64"),
    ("x86", "x86"),
    ("i386", "x86"),
]


def _guess_arch(filename: str) -> str | None:
    """Heuristic: guess architecture from a kernel filename."""
    lower = filename.lower()
    for pattern, arch in _ARCH_PATTERNS:
        if pattern in lower:
            return arch
    return None


def _validate_kernel_name(name: str) -> None:
    """Raise ValueError if name contains disallowed characters."""
    if not name or not name.strip():
        raise ValueError("Kernel name must not be empty")
    if name.startswith("."):
        raise ValueError("Kernel name must not start with '.'")
    if "/" in name or "\\" in name or ".." in name:
        raise ValueError("Kernel name must not contain '/', '\\', or '..'")
    if not re.match(r"^[a-zA-Z0-9._-]+$", name):
        raise ValueError(
            "Kernel name may only contain alphanumeric characters, "
            "hyphens, underscores, and dots"
        )


def _validate_download_url(url: str) -> None:
    """Validate a URL for safe downloading (SSRF prevention).

    Rejects private/loopback/link-local IPs, non-HTTP(S) schemes,
    and malformed URLs.
    """
    if len(url) > 2048:
        raise ValueError("URL too long (max 2048 characters)")

    parsed = urlparse(url)

    if parsed.scheme not in ("http", "https"):
        raise ValueError(
            f"Unsupported URL scheme '{parsed.scheme}' — only http and https are allowed"
        )

    hostname = parsed.hostname
    if not hostname:
        raise ValueError("URL has no hostname")

    # Resolve hostname and check all returned IPs
    try:
        addr_infos = socket.getaddrinfo(hostname, parsed.port or 443, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise ValueError(f"Cannot resolve hostname '{hostname}': {exc}") from exc

    if not addr_infos:
        raise ValueError(f"Hostname '{hostname}' did not resolve to any address")

    for family, _, _, _, sockaddr in addr_infos:
        ip_str = sockaddr[0]
        ip = ipaddress.ip_address(ip_str)
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
            raise ValueError(
                f"URL resolves to non-public IP address ({ip_str}) — "
                "downloads from private/loopback/link-local networks are blocked"
            )


class KernelService:
    """Manages pre-built Linux kernels on the local filesystem."""

    def __init__(self) -> None:
        self._kernel_dir = get_settings().emulation_kernel_dir

    def _kernel_path(self, name: str) -> str:
        return os.path.join(self._kernel_dir, name)

    def _sidecar_path(self, name: str) -> str:
        return os.path.join(self._kernel_dir, f"{name}.json")

    def _read_sidecar(self, name: str) -> dict | None:
        path = self._sidecar_path(name)
        if not os.path.isfile(path):
            return None
        try:
            with open(path) as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            logger.warning("Failed to read sidecar for kernel %s", name)
            return None

    def _initrd_path(self, kernel_name: str) -> str | None:
        """Return the path to a kernel's companion initrd, if it exists.

        Checks the sidecar JSON for an explicit 'initrd' field, then
        falls back to the convention: <kernel_name>.initrd
        """
        sidecar = self._read_sidecar(kernel_name)
        if sidecar and sidecar.get("initrd"):
            initrd_name = sidecar["initrd"]
            path = os.path.join(self._kernel_dir, initrd_name)
            if os.path.isfile(path):
                return path

        # Convention fallback
        path = os.path.join(self._kernel_dir, f"{kernel_name}.initrd")
        if os.path.isfile(path):
            return path

        return None

    def _kernel_info(self, name: str) -> dict:
        """Build kernel info dict for a single kernel."""
        kernel_path = self._kernel_path(name)
        sidecar = self._read_sidecar(name)

        try:
            stat = os.stat(kernel_path)
            file_size = stat.st_size
            mtime = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat()
        except OSError:
            file_size = 0
            mtime = datetime.now(timezone.utc).isoformat()

        if sidecar:
            architecture = sidecar.get("architecture", _guess_arch(name) or "unknown")
            description = sidecar.get("description", "")
            uploaded_at = sidecar.get("uploaded_at", mtime)
        else:
            architecture = _guess_arch(name) or "unknown"
            description = ""
            uploaded_at = mtime

        # Check for companion initrd
        initrd_path = self._initrd_path(name)
        has_initrd = initrd_path is not None

        return {
            "name": name,
            "architecture": architecture,
            "description": description,
            "file_size": file_size,
            "uploaded_at": uploaded_at,
            "has_initrd": has_initrd,
        }

    def list_kernels(self, architecture: str | None = None) -> list[dict]:
        """List all available kernels, optionally filtered by architecture."""
        if not os.path.isdir(self._kernel_dir):
            return []

        kernels = []
        for entry in os.scandir(self._kernel_dir):
            # Skip sidecar JSON files, initrd companions, hidden files, directories
            if entry.name.startswith("."):
                continue
            if entry.name.endswith(".json"):
                continue
            if entry.name.endswith(".initrd"):
                continue
            if not entry.is_file():
                continue

            info = self._kernel_info(entry.name)

            if architecture and info["architecture"] != architecture:
                continue

            kernels.append(info)

        kernels.sort(key=lambda k: k["name"])
        return kernels

    def get_kernel(self, name: str) -> dict:
        """Get info for a single kernel by name."""
        _validate_kernel_name(name)
        kernel_path = self._kernel_path(name)
        if not os.path.isfile(kernel_path):
            raise ValueError(f"Kernel '{name}' not found")
        return self._kernel_info(name)

    async def upload_kernel(
        self,
        name: str,
        architecture: str,
        description: str,
        file_data: bytes,
    ) -> dict:
        """Write a kernel binary + sidecar JSON."""
        _validate_kernel_name(name)

        if architecture not in SUPPORTED_ARCHITECTURES:
            raise ValueError(
                f"Unsupported architecture '{architecture}'. "
                f"Supported: {', '.join(sorted(SUPPORTED_ARCHITECTURES))}"
            )

        kernel_path = self._kernel_path(name)
        if os.path.exists(kernel_path):
            raise ValueError(f"Kernel '{name}' already exists")

        os.makedirs(self._kernel_dir, exist_ok=True)

        # Write binary
        async with aiofiles.open(kernel_path, "wb") as f:
            await f.write(file_data)

        # Write sidecar metadata
        sidecar = {
            "architecture": architecture,
            "description": description,
            "uploaded_at": datetime.now(timezone.utc).isoformat(),
        }
        async with aiofiles.open(self._sidecar_path(name), "w") as f:
            await f.write(json.dumps(sidecar, indent=2))

        return self._kernel_info(name)

    def delete_kernel(self, name: str) -> None:
        """Delete a kernel binary and its sidecar."""
        _validate_kernel_name(name)
        kernel_path = self._kernel_path(name)
        if not os.path.isfile(kernel_path):
            raise ValueError(f"Kernel '{name}' not found")

        os.remove(kernel_path)

        sidecar_path = self._sidecar_path(name)
        if os.path.isfile(sidecar_path):
            os.remove(sidecar_path)

    def find_kernel_for_arch(self, architecture: str) -> dict | None:
        """Return the first kernel matching the given architecture, or None."""
        kernels = self.list_kernels(architecture=architecture)
        return kernels[0] if kernels else None

    async def upload_initrd(
        self,
        kernel_name: str,
        file_data: bytes,
    ) -> dict:
        """Upload an initrd/initramfs to pair with an existing kernel."""
        _validate_kernel_name(kernel_name)
        kernel_path = self._kernel_path(kernel_name)
        if not os.path.isfile(kernel_path):
            raise ValueError(f"Kernel '{kernel_name}' not found")

        initrd_name = f"{kernel_name}.initrd"
        initrd_path = os.path.join(self._kernel_dir, initrd_name)

        async with aiofiles.open(initrd_path, "wb") as f:
            await f.write(file_data)

        # Update sidecar to reference the initrd
        sidecar_path = self._sidecar_path(kernel_name)
        sidecar = {}
        if os.path.isfile(sidecar_path):
            try:
                with open(sidecar_path) as f:
                    sidecar = json.load(f)
            except (json.JSONDecodeError, OSError):
                pass
        sidecar["initrd"] = initrd_name
        async with aiofiles.open(sidecar_path, "w") as f:
            await f.write(json.dumps(sidecar, indent=2))

        logger.info("Uploaded initrd %s for kernel %s (%d bytes)",
                     initrd_name, kernel_name, len(file_data))
        return self._kernel_info(kernel_name)

    async def download_kernel(
        self,
        url: str,
        name: str,
        architecture: str,
        description: str = "",
        max_size_bytes: int = 100 * 1024 * 1024,
        timeout_seconds: int = 120,
    ) -> dict:
        """Download a kernel from a URL, validate it, and install it.

        Includes SSRF prevention (blocks private/loopback IPs) and kernel
        format validation before saving.

        Returns the kernel info dict on success, raises ValueError on failure.
        """
        # Import here to avoid circular dependency at module level
        from app.services.emulation_service import _validate_kernel_file

        # --- URL validation ---
        _validate_download_url(url)

        # --- Download with streaming ---
        tmp_fd, tmp_path = tempfile.mkstemp(prefix="kernel_dl_")
        os.close(tmp_fd)
        try:
            async with httpx.AsyncClient(
                follow_redirects=True,
                max_redirects=5,
                timeout=httpx.Timeout(timeout_seconds, connect=30.0),
            ) as client:
                async with client.stream("GET", url) as response:
                    response.raise_for_status()
                    downloaded = 0
                    async with aiofiles.open(tmp_path, "wb") as f:
                        async for chunk in response.aiter_bytes(chunk_size=65536):
                            downloaded += len(chunk)
                            if downloaded > max_size_bytes:
                                raise ValueError(
                                    f"Download exceeds maximum size "
                                    f"({max_size_bytes // (1024*1024)}MB)"
                                )
                            await f.write(chunk)

            if downloaded == 0:
                raise ValueError("Downloaded file is empty")

            # --- Validate kernel format ---
            is_valid, reason = _validate_kernel_file(tmp_path)
            if not is_valid:
                raise ValueError(f"Downloaded file is not a valid kernel: {reason}")

            # --- Read validated file and install via upload_kernel ---
            async with aiofiles.open(tmp_path, "rb") as f:
                file_data = await f.read()

            result = await self.upload_kernel(name, architecture, description, file_data)

            # Add download source to sidecar metadata
            sidecar_path = self._sidecar_path(name)
            if os.path.isfile(sidecar_path):
                with open(sidecar_path) as f:
                    sidecar = json.load(f)
                sidecar["source_url"] = url
                async with aiofiles.open(sidecar_path, "w") as f:
                    await f.write(json.dumps(sidecar, indent=2))

            return result

        except httpx.HTTPStatusError as exc:
            raise ValueError(
                f"HTTP {exc.response.status_code} downloading kernel from {url}"
            ) from exc
        except httpx.RequestError as exc:
            raise ValueError(f"Failed to download kernel: {exc}") from exc
        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
