"""Service for managing pre-built Linux kernels for system-mode emulation.

Kernels are a global resource (not per-project). The filesystem is the source
of truth -- no database table needed. JSON sidecar files store metadata
alongside each kernel binary.
"""

import json
import logging
import os
import re
from datetime import datetime, timezone

import aiofiles

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

        return {
            "name": name,
            "architecture": architecture,
            "description": description,
            "file_size": file_size,
            "uploaded_at": uploaded_at,
        }

    def list_kernels(self, architecture: str | None = None) -> list[dict]:
        """List all available kernels, optionally filtered by architecture."""
        if not os.path.isdir(self._kernel_dir):
            return []

        kernels = []
        for entry in os.scandir(self._kernel_dir):
            # Skip sidecar JSON files, hidden files, and directories
            if entry.name.startswith("."):
                continue
            if entry.name.endswith(".json"):
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
