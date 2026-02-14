"""Ghidra headless decompilation service with analysis_cache integration."""

import asyncio
import hashlib
import logging
import os
import tempfile
import uuid
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.models.analysis_cache import AnalysisCache

logger = logging.getLogger(__name__)

# Markers used by DecompileFunction.java to delimit output
_START_MARKER = "===DECOMPILE_START==="
_END_MARKER = "===DECOMPILE_END==="


def _compute_sha256(file_path: str) -> str:
    """Compute SHA256 hash of a file."""
    sha = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha.update(chunk)
    return sha.hexdigest()


def _parse_decompile_output(raw_output: str) -> str | None:
    """Extract decompiled code from Ghidra headless output.

    The DecompileFunction.java script wraps output between markers.
    """
    start = raw_output.find(_START_MARKER)
    end = raw_output.find(_END_MARKER)

    if start == -1 or end == -1:
        return None

    # Extract content between markers (skip the marker line itself)
    content = raw_output[start + len(_START_MARKER) : end].strip()
    return content if content else None


def _build_analyze_command(
    binary_path: str,
    function_name: str,
    project_dir: str,
) -> list[str]:
    """Build the Ghidra analyzeHeadless command."""
    settings = get_settings()
    ghidra_path = settings.ghidra_path
    scripts_path = settings.ghidra_scripts_path

    analyze_headless = os.path.join(ghidra_path, "support", "analyzeHeadless")

    # Use a unique project name to avoid conflicts
    project_name = f"wairz_{uuid.uuid4().hex[:8]}"

    cmd = [
        analyze_headless,
        project_dir,
        project_name,
        "-import",
        binary_path,
        "-scriptPath",
        scripts_path,
        "-postScript",
        "DecompileFunction.java",
        function_name,
        "-deleteProject",
    ]

    return cmd


async def _run_ghidra_subprocess(
    binary_path: str,
    function_name: str,
) -> str:
    """Run Ghidra headless analysis and return the raw output."""
    settings = get_settings()

    with tempfile.TemporaryDirectory(prefix="ghidra_") as project_dir:
        cmd = _build_analyze_command(binary_path, function_name, project_dir)

        logger.info(
            "Running Ghidra decompilation: %s in %s",
            function_name,
            os.path.basename(binary_path),
        )

        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=settings.ghidra_timeout,
            )
        except asyncio.TimeoutError:
            process.kill()
            await process.wait()
            raise TimeoutError(
                f"Ghidra decompilation timed out after {settings.ghidra_timeout}s"
            )

        stdout_text = stdout.decode("utf-8", errors="replace")
        stderr_text = stderr.decode("utf-8", errors="replace")

        if process.returncode != 0:
            # Ghidra often returns non-zero but still produces output
            # Only raise if we got no useful output
            parsed = _parse_decompile_output(stdout_text)
            if parsed is None:
                logger.error("Ghidra failed (rc=%d): %s", process.returncode, stderr_text[-500:])
                raise RuntimeError(
                    f"Ghidra decompilation failed (exit code {process.returncode})"
                )

        return stdout_text


async def _get_cached_result(
    db: AsyncSession,
    firmware_id: uuid.UUID,
    binary_sha256: str,
    operation: str,
) -> str | None:
    """Look up a cached decompilation result."""
    stmt = select(AnalysisCache.result).where(
        AnalysisCache.firmware_id == firmware_id,
        AnalysisCache.binary_sha256 == binary_sha256,
        AnalysisCache.operation == operation,
    )
    result = await db.execute(stmt)
    row = result.scalar_one_or_none()
    if row is not None and isinstance(row, dict):
        return row.get("decompiled_code")
    return None


async def _store_cached_result(
    db: AsyncSession,
    firmware_id: uuid.UUID,
    binary_path: str,
    binary_sha256: str,
    operation: str,
    decompiled_code: str,
) -> None:
    """Store a decompilation result in the cache."""
    cache_entry = AnalysisCache(
        firmware_id=firmware_id,
        binary_path=binary_path,
        binary_sha256=binary_sha256,
        operation=operation,
        result={"decompiled_code": decompiled_code},
    )
    db.add(cache_entry)
    await db.flush()


async def decompile_function(
    binary_path: str,
    function_name: str,
    firmware_id: uuid.UUID,
    db: AsyncSession,
) -> str:
    """Decompile a function using Ghidra headless, with caching.

    Args:
        binary_path: Absolute path to the ELF binary on disk.
        function_name: Name of the function to decompile.
        firmware_id: UUID of the firmware (for cache keying).
        db: Async database session.

    Returns:
        Pseudo-C decompilation output as a string.

    Raises:
        FileNotFoundError: If the binary doesn't exist.
        TimeoutError: If Ghidra takes too long.
        RuntimeError: If Ghidra fails.
    """
    if not os.path.isfile(binary_path):
        raise FileNotFoundError(f"Binary not found: {binary_path}")

    # Compute hash for cache key
    binary_sha256 = await asyncio.get_event_loop().run_in_executor(
        None, _compute_sha256, binary_path
    )

    operation = f"decompile:{function_name}"

    # Check cache first
    cached = await _get_cached_result(db, firmware_id, binary_sha256, operation)
    if cached is not None:
        logger.info("Cache hit for %s:%s", os.path.basename(binary_path), function_name)
        return cached

    # Run Ghidra
    raw_output = await _run_ghidra_subprocess(binary_path, function_name)

    # Parse the output
    decompiled = _parse_decompile_output(raw_output)
    if decompiled is None:
        # Check if the error message says function not found
        if "ERROR: Function" in raw_output and "not found" in raw_output:
            # Extract available functions from the output
            lines = raw_output.split("\n")
            func_lines = [
                l.strip()
                for l in lines
                if l.strip().startswith("  ") and "@" in l
            ]
            suggestion = ""
            if func_lines:
                suggestion = "\n\nAvailable functions:\n" + "\n".join(func_lines[:20])
            return f"Function '{function_name}' not found in binary.{suggestion}"
        return "Decompilation produced no output. The function may be too small or a thunk."

    # Store in cache
    # Use relative path for portability
    rel_path = binary_path  # Store the full path; it's within the extracted filesystem
    await _store_cached_result(
        db, firmware_id, rel_path, binary_sha256, operation, decompiled
    )

    return decompiled
