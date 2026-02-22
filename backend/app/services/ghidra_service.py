"""Ghidra-based binary analysis service with full-binary caching.

Runs Ghidra once per binary via AnalyzeBinary.java to extract all data
(functions, imports, exports, xrefs, disassembly, decompilation, binary_info),
stores everything in PostgreSQL analysis_cache, and serves subsequent queries
instantly from the DB.

Falls back to DecompileFunction.java for single-function decompilation requests
on functions not covered in the initial batch (top 200 by size).
"""

import asyncio
import hashlib
import json
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

# Markers used by both AnalyzeBinary.java and DecompileFunction.java
_START_MARKER = "===ANALYSIS_START==="
_END_MARKER = "===ANALYSIS_END==="
_DECOMPILE_START = "===DECOMPILE_START==="
_DECOMPILE_END = "===DECOMPILE_END==="

# Architecture mapping: Ghidra processor names → common short names
_ARCH_MAP = {
    "ARM": "arm",
    "AARCH64": "aarch64",
    "MIPS": "mips",
    "x86": "x86",
    "x86-64": "x86",
    "PowerPC": "ppc",
    "sparc": "sparc",
}


def _compute_sha256(file_path: str) -> str:
    """Compute SHA256 hash of a file."""
    sha = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha.update(chunk)
    return sha.hexdigest()


def _map_architecture(ghidra_arch: str) -> str:
    """Map Ghidra architecture string to common short name."""
    for key, val in _ARCH_MAP.items():
        if key.lower() in ghidra_arch.lower():
            return val
    return ghidra_arch.lower()


def _parse_analysis_output(raw_output: str) -> dict | None:
    """Extract JSON from Ghidra AnalyzeBinary.java output between markers.

    Ghidra wraps println() output with log prefixes like:
      INFO  AnalyzeBinary.java> {json...} (GhidraScript)
    So we extract the outermost { ... } between the markers.
    """
    start = raw_output.find(_START_MARKER)
    end = raw_output.find(_END_MARKER)

    if start == -1 or end == -1:
        return None

    content = raw_output[start + len(_START_MARKER):end].strip()
    if not content:
        return None

    # Find the outermost JSON object braces within the content
    json_start = content.find("{")
    json_end = content.rfind("}")
    if json_start == -1 or json_end == -1 or json_end <= json_start:
        logger.error("No JSON object found between analysis markers")
        return None

    json_str = content[json_start:json_end + 1]

    try:
        return json.loads(json_str)
    except json.JSONDecodeError as exc:
        logger.error("Failed to parse Ghidra analysis JSON: %s", exc)
        return None


def _parse_decompile_output(raw_output: str) -> str | None:
    """Extract decompiled code from DecompileFunction.java output between markers."""
    start = raw_output.find(_DECOMPILE_START)
    end = raw_output.find(_DECOMPILE_END)

    if start == -1 or end == -1:
        return None

    content = raw_output[start + len(_DECOMPILE_START):end].strip()
    return content if content else None


def _build_analyze_command(
    binary_path: str,
    script_name: str,
    project_dir: str,
    script_args: list[str] | None = None,
) -> list[str]:
    """Build a Ghidra analyzeHeadless command."""
    settings = get_settings()
    ghidra_path = settings.ghidra_path
    scripts_path = settings.ghidra_scripts_path

    analyze_headless = os.path.join(ghidra_path, "support", "analyzeHeadless")
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
        script_name,
    ]

    if script_args:
        cmd.extend(script_args)

    cmd.append("-deleteProject")
    return cmd


async def _run_ghidra_subprocess(
    binary_path: str,
    script_name: str,
    script_args: list[str] | None = None,
) -> str:
    """Run a Ghidra headless script and return the raw stdout."""
    settings = get_settings()

    with tempfile.TemporaryDirectory(prefix="ghidra_") as project_dir:
        cmd = _build_analyze_command(binary_path, script_name, project_dir, script_args)

        logger.info(
            "Running Ghidra %s on %s",
            script_name,
            os.path.basename(binary_path),
        )

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except FileNotFoundError:
            raise RuntimeError(
                f"Ghidra not found at {cmd[0]}. "
                "Install Ghidra or set GHIDRA_PATH in .env."
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
                f"Ghidra analysis timed out after {settings.ghidra_timeout}s"
            )

        stdout_text = stdout.decode("utf-8", errors="replace")
        stderr_text = stderr.decode("utf-8", errors="replace")

        if process.returncode != 0:
            # Ghidra often returns non-zero but still produces output
            if _START_MARKER not in stdout_text and _DECOMPILE_START not in stdout_text:
                logger.error(
                    "Ghidra failed (rc=%d): %s",
                    process.returncode,
                    stderr_text[-500:],
                )
                raise RuntimeError(
                    f"Ghidra analysis failed (exit code {process.returncode})"
                )

        return stdout_text


class GhidraAnalysisCache:
    """Cache for full-binary Ghidra analysis results.

    Runs Ghidra once per binary via AnalyzeBinary.java, stores all extracted
    data in the analysis_cache table, and serves subsequent queries from DB.

    Includes a concurrency guard: if two requests hit the same binary
    simultaneously, only one runs Ghidra and the other waits.
    """

    def __init__(self) -> None:
        # Concurrency guard: binary_sha256 → asyncio.Event
        self._analysis_locks: dict[str, asyncio.Event] = {}
        self._lock = asyncio.Lock()

    async def _get_binary_sha256(self, binary_path: str) -> str:
        """Compute SHA256 in a thread."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, _compute_sha256, binary_path)

    async def _is_analysis_complete(
        self,
        firmware_id: uuid.UUID,
        binary_sha256: str,
        db: AsyncSession,
    ) -> bool:
        """Check if full analysis has been completed for this binary."""
        stmt = select(AnalysisCache.id).where(
            AnalysisCache.firmware_id == firmware_id,
            AnalysisCache.binary_sha256 == binary_sha256,
            AnalysisCache.operation == "ghidra_full_analysis",
        )
        result = await db.execute(stmt)
        return result.scalar_one_or_none() is not None

    async def _get_cached(
        self,
        firmware_id: uuid.UUID,
        binary_sha256: str,
        operation: str,
        db: AsyncSession,
    ) -> dict | None:
        """Get a cached result by operation key."""
        stmt = select(AnalysisCache.result).where(
            AnalysisCache.firmware_id == firmware_id,
            AnalysisCache.binary_sha256 == binary_sha256,
            AnalysisCache.operation == operation,
        )
        result = await db.execute(stmt)
        row = result.scalar_one_or_none()
        if row is not None and isinstance(row, dict):
            return row
        return None

    async def _store_cached(
        self,
        firmware_id: uuid.UUID,
        binary_path: str,
        binary_sha256: str,
        operation: str,
        result_data: dict,
        db: AsyncSession,
    ) -> None:
        """Store a result in the cache."""
        cache_entry = AnalysisCache(
            firmware_id=firmware_id,
            binary_path=binary_path,
            binary_sha256=binary_sha256,
            operation=operation,
            result=result_data,
        )
        db.add(cache_entry)
        await db.flush()

    async def _run_full_analysis(
        self,
        binary_path: str,
        firmware_id: uuid.UUID,
        binary_sha256: str,
        db: AsyncSession,
    ) -> None:
        """Run AnalyzeBinary.java and store all results in DB."""
        raw_output = await _run_ghidra_subprocess(binary_path, "AnalyzeBinary.java")

        data = _parse_analysis_output(raw_output)
        if data is None:
            raise RuntimeError(
                "Ghidra full analysis produced no parseable output. "
                "Check Ghidra installation and binary compatibility."
            )

        # Store each section as a separate cache entry
        sections = [
            ("functions", "functions"),
            ("imports", "imports"),
            ("exports", "exports"),
            ("binary_info", "binary_info"),
            ("xrefs", "xrefs"),
            ("main_detection", "main_detection"),
        ]

        for key, operation in sections:
            if key in data:
                await self._store_cached(
                    firmware_id, binary_path, binary_sha256,
                    operation, {key: data[key]}, db,
                )

        # Store disassembly per function
        disassembly = data.get("disassembly", {})
        for func_name, disasm_text in disassembly.items():
            await self._store_cached(
                firmware_id, binary_path, binary_sha256,
                f"disasm:{func_name}",
                {"disassembly": disasm_text},
                db,
            )

        # Store decompilation per function
        decompilation = data.get("decompilation", {})
        for func_name, code in decompilation.items():
            await self._store_cached(
                firmware_id, binary_path, binary_sha256,
                f"decompile:{func_name}",
                {"decompiled_code": code},
                db,
            )

        # Store sentinel marking analysis as complete
        function_count = len(data.get("functions", []))
        decompile_count = len(decompilation)
        await self._store_cached(
            firmware_id, binary_path, binary_sha256,
            "ghidra_full_analysis",
            {
                "status": "complete",
                "function_count": function_count,
                "decompiled_count": decompile_count,
            },
            db,
        )

        logger.info(
            "Ghidra full analysis complete for %s: %d functions, %d decompiled",
            os.path.basename(binary_path),
            function_count,
            decompile_count,
        )

    async def ensure_analysis(
        self,
        binary_path: str,
        firmware_id: uuid.UUID,
        db: AsyncSession,
    ) -> str:
        """Ensure full analysis has been run for this binary. Returns binary_sha256.

        Uses a concurrency guard so only one Ghidra process runs per binary.
        """
        if not os.path.isfile(binary_path):
            raise FileNotFoundError(f"Binary not found: {binary_path}")

        binary_sha256 = await self._get_binary_sha256(binary_path)

        # Fast path: already analyzed
        if await self._is_analysis_complete(firmware_id, binary_sha256, db):
            return binary_sha256

        # Concurrency guard
        async with self._lock:
            if binary_sha256 in self._analysis_locks:
                # Another coroutine is already analyzing this binary
                event = self._analysis_locks[binary_sha256]
            else:
                event = asyncio.Event()
                self._analysis_locks[binary_sha256] = event
                event = None  # We're the one who will do the analysis

        if event is not None:
            # Wait for the other coroutine to finish
            await event.wait()
            return binary_sha256

        # We're responsible for running the analysis
        try:
            # Double-check after acquiring — might have been completed
            # between our first check and acquiring the lock
            if not await self._is_analysis_complete(firmware_id, binary_sha256, db):
                await self._run_full_analysis(
                    binary_path, firmware_id, binary_sha256, db,
                )
        finally:
            async with self._lock:
                ev = self._analysis_locks.pop(binary_sha256, None)
                if ev is not None:
                    ev.set()

        return binary_sha256

    async def get_functions(
        self,
        binary_path: str,
        firmware_id: uuid.UUID,
        db: AsyncSession,
    ) -> list[dict]:
        """Get function list for a binary (sorted by size desc)."""
        binary_sha256 = await self.ensure_analysis(binary_path, firmware_id, db)

        cached = await self._get_cached(firmware_id, binary_sha256, "functions", db)
        if cached:
            functions = cached.get("functions", [])
            # Apply main detection: if main was detected, update the list
            main_cached = await self._get_cached(
                firmware_id, binary_sha256, "main_detection", db,
            )
            if main_cached:
                main_info = main_cached.get("main_detection", {})
                if main_info.get("found") and main_info.get("method") == "libc_start_main_arg":
                    main_addr = main_info.get("address")
                    for func in functions:
                        if func.get("address") == main_addr and func["name"].startswith("FUN_"):
                            func["name"] = "main"
                            break
            return functions
        return []

    async def get_disassembly(
        self,
        binary_path: str,
        function_name: str,
        firmware_id: uuid.UUID,
        db: AsyncSession,
        max_instructions: int = 200,
    ) -> str:
        """Get disassembly for a function."""
        binary_sha256 = await self.ensure_analysis(binary_path, firmware_id, db)

        cached = await self._get_cached(
            firmware_id, binary_sha256, f"disasm:{function_name}", db,
        )
        if cached:
            disasm = cached.get("disassembly", "")
            # Apply max_instructions limit
            lines = disasm.split("\n")
            if len(lines) > max_instructions:
                lines = lines[:max_instructions]
                lines.append(f"... (truncated at {max_instructions} instructions)")
            return "\n".join(lines)

        return f"No disassembly found for function '{function_name}'. Use list_functions to see available function names."

    async def get_imports(
        self,
        binary_path: str,
        firmware_id: uuid.UUID,
        db: AsyncSession,
    ) -> list[dict]:
        """Get import list for a binary."""
        binary_sha256 = await self.ensure_analysis(binary_path, firmware_id, db)

        cached = await self._get_cached(firmware_id, binary_sha256, "imports", db)
        if cached:
            return cached.get("imports", [])
        return []

    async def get_exports(
        self,
        binary_path: str,
        firmware_id: uuid.UUID,
        db: AsyncSession,
    ) -> list[dict]:
        """Get export list for a binary."""
        binary_sha256 = await self.ensure_analysis(binary_path, firmware_id, db)

        cached = await self._get_cached(firmware_id, binary_sha256, "exports", db)
        if cached:
            return cached.get("exports", [])
        return []

    async def get_xrefs_to(
        self,
        binary_path: str,
        target: str,
        firmware_id: uuid.UUID,
        db: AsyncSession,
    ) -> list[dict]:
        """Get cross-references to a function/symbol."""
        binary_sha256 = await self.ensure_analysis(binary_path, firmware_id, db)

        cached = await self._get_cached(firmware_id, binary_sha256, "xrefs", db)
        if cached:
            xrefs = cached.get("xrefs", {})
            func_xrefs = xrefs.get(target, {})
            return func_xrefs.get("to", [])
        return []

    async def get_xrefs_from(
        self,
        binary_path: str,
        target: str,
        firmware_id: uuid.UUID,
        db: AsyncSession,
    ) -> list[dict]:
        """Get cross-references from a function/symbol."""
        binary_sha256 = await self.ensure_analysis(binary_path, firmware_id, db)

        cached = await self._get_cached(firmware_id, binary_sha256, "xrefs", db)
        if cached:
            xrefs = cached.get("xrefs", {})
            func_xrefs = xrefs.get(target, {})
            return func_xrefs.get("from", [])
        return []

    async def get_binary_info(
        self,
        binary_path: str,
        firmware_id: uuid.UUID,
        db: AsyncSession,
    ) -> dict:
        """Get binary metadata in r2-compatible shape for frontend compatibility.

        Returns a dict shaped like: {"core": {}, "bin": {"arch": ..., "libs": [...]}}
        """
        binary_sha256 = await self.ensure_analysis(binary_path, firmware_id, db)

        cached = await self._get_cached(firmware_id, binary_sha256, "binary_info", db)
        if not cached:
            return {}

        info = cached.get("binary_info", {})

        # Map to r2-compatible shape
        arch = _map_architecture(info.get("arch", "unknown"))
        bits = info.get("bits", 0)
        endian = info.get("endian", "unknown")
        fmt = info.get("format", "unknown")
        libs = info.get("libraries", [])
        entry = info.get("entry_point", "unknown")
        compiler = info.get("compiler", "unknown")
        image_base = info.get("image_base", "unknown")

        return {
            "core": {
                "format": fmt,
                "file": binary_path,
            },
            "bin": {
                "file": binary_path,
                "bintype": "elf" if "elf" in fmt.lower() else fmt.lower(),
                "arch": arch,
                "bits": bits,
                "endian": endian,
                "os": "linux",
                "machine": info.get("arch", "unknown"),
                "class": f"ELF{bits}" if "elf" in fmt.lower() else fmt,
                "lang": compiler if compiler != "unknown" else "c",
                "stripped": False,  # Ghidra doesn't report this directly; pyelftools handles it
                "static": len(libs) == 0,
                "libs": libs,
                "entry_point": entry,
                "image_base": image_base,
            },
        }

    async def decompile_function(
        self,
        binary_path: str,
        function_name: str,
        firmware_id: uuid.UUID,
        db: AsyncSession,
    ) -> str:
        """Decompile a function, using cached results or falling back to single-function Ghidra.

        First tries the full-analysis cache. If the function wasn't in the top 200
        decompiled, falls back to running DecompileFunction.java for that specific function.
        """
        if not os.path.isfile(binary_path):
            raise FileNotFoundError(f"Binary not found: {binary_path}")

        binary_sha256 = await self._get_binary_sha256(binary_path)
        operation = f"decompile:{function_name}"

        # Check cache (works for both full-analysis and single-function cache entries)
        cached = await self._get_cached(firmware_id, binary_sha256, operation, db)
        if cached:
            code = cached.get("decompiled_code")
            if code:
                logger.info(
                    "Cache hit for %s:%s",
                    os.path.basename(binary_path),
                    function_name,
                )
                return code

        # If full analysis was done but this function wasn't decompiled,
        # fall back to single-function decompilation
        raw_output = await _run_ghidra_subprocess(
            binary_path,
            "DecompileFunction.java",
            script_args=[function_name],
        )

        decompiled = _parse_decompile_output(raw_output)
        if decompiled is None:
            if "ERROR: Function" in raw_output and "not found" in raw_output:
                lines = raw_output.split("\n")
                func_lines = [
                    line.strip()
                    for line in lines
                    if line.strip().startswith("  ") and "@" in line
                ]
                suggestion = ""
                if func_lines:
                    suggestion = "\n\nAvailable functions:\n" + "\n".join(func_lines[:20])
                return f"Function '{function_name}' not found in binary.{suggestion}"
            return "Decompilation produced no output. The function may be too small or a thunk."

        # Store in cache for future use
        await self._store_cached(
            firmware_id, binary_path, binary_sha256, operation,
            {"decompiled_code": decompiled}, db,
        )

        return decompiled


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_analysis_cache = GhidraAnalysisCache()


def get_analysis_cache() -> GhidraAnalysisCache:
    """Get the module-level GhidraAnalysisCache singleton."""
    return _analysis_cache


# ---------------------------------------------------------------------------
# Legacy wrapper — maintains backward compatibility
# ---------------------------------------------------------------------------


async def decompile_function(
    binary_path: str,
    function_name: str,
    firmware_id: uuid.UUID,
    db: AsyncSession,
) -> str:
    """Decompile a function using Ghidra headless, with caching.

    This is a convenience wrapper around GhidraAnalysisCache.decompile_function().
    """
    cache = get_analysis_cache()
    return await cache.decompile_function(binary_path, function_name, firmware_id, db)
