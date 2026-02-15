"""AI-powered cleanup of Ghidra decompiled code.

Calls Claude with a specialized prompt to rename auto-generated variables/functions,
add comments, annotate security patterns, and produce human-readable pseudo-C.
"""

import asyncio
import logging
import os
import re
import uuid

import anthropic
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.models.analysis_cache import AnalysisCache
from app.services.ghidra_service import _compute_sha256

logger = logging.getLogger(__name__)

CLEANUP_MODEL = "claude-sonnet-4-20250514"
CLEANUP_MAX_TOKENS = 8192

_SYSTEM_PROMPT = """\
You are an expert reverse engineer specializing in embedded firmware analysis.
Your task is to clean up raw Ghidra decompiled C code to make it human-readable.

Rules:
1. Rename auto-generated variables (uVar1, local_10, param_1, etc.) to meaningful \
names based on how they are used in the code.
2. Rename auto-generated function names (FUN_00401234) to descriptive names when \
their behavior is inferable. If unclear, keep the original name but add a comment.
3. Add inline comments explaining non-obvious operations: bit manipulation, magic \
numbers, protocol handling, pointer arithmetic.
4. Add a function-level docstring summarizing the function's purpose, parameters, \
and return value.
5. Annotate security-relevant patterns with /* [SECURITY] ... */ comments: \
unchecked buffer operations, format string usage, command injection vectors, \
hardcoded credentials, missing bounds checks.
6. Preserve the original code structure and logic exactly. Do NOT refactor, \
reorder, add error handling, or change functionality.
7. Output ONLY the cleaned C code. No explanations, no markdown fences, no preamble."""

_MAX_IMPORTS_IN_PROMPT = 50


def _build_user_message(
    raw_code: str,
    function_name: str,
    binary_path: str,
    binary_info: dict | None,
    imports: list[dict] | None,
) -> str:
    """Build the user message with binary context and raw code."""
    parts: list[str] = []

    # Binary context
    parts.append(f"Binary: {os.path.basename(binary_path)}")
    if binary_info:
        bin_meta = binary_info.get("bin", {})
        if bin_meta.get("arch"):
            parts.append(f"Architecture: {bin_meta['arch']} ({bin_meta.get('bits', '?')}-bit, {bin_meta.get('endian', '?')})")
        libs = bin_meta.get("libs", [])
        if libs:
            parts.append(f"Linked libraries: {', '.join(libs)}")

    # Key imports (capped)
    if imports:
        by_lib: dict[str, list[str]] = {}
        for imp in imports[:_MAX_IMPORTS_IN_PROMPT]:
            lib = imp.get("lib", "unknown")
            name = imp.get("name", "unknown")
            by_lib.setdefault(lib, []).append(name)
        import_lines = []
        for lib, syms in sorted(by_lib.items()):
            import_lines.append(f"  {lib}: {', '.join(sorted(syms))}")
        if import_lines:
            parts.append("Key imports:\n" + "\n".join(import_lines))

    parts.append(f"\nFunction to clean up: {function_name}")
    parts.append(f"\nRaw Ghidra decompilation:\n```c\n{raw_code}\n```")

    return "\n".join(parts)


def _strip_markdown_fences(text: str) -> str:
    """Remove markdown code fences if the model wraps its output in them."""
    # Strip leading ```c or ``` and trailing ```
    stripped = text.strip()
    stripped = re.sub(r"^```[a-zA-Z]*\n?", "", stripped)
    stripped = re.sub(r"\n?```$", "", stripped)
    return stripped.strip()


async def cleanup_decompiled_code(
    raw_code: str,
    function_name: str,
    binary_path: str,
    binary_info: dict | None,
    imports: list[dict] | None,
    firmware_id: uuid.UUID,
    db: AsyncSession,
) -> str:
    """Clean up raw Ghidra decompilation using Claude.

    Args:
        raw_code: Raw decompiled C code from Ghidra.
        function_name: Name of the function being cleaned.
        binary_path: Absolute path to the binary on disk.
        binary_info: R2 binary info dict (optional, best-effort).
        imports: R2 imports list (optional, best-effort).
        firmware_id: UUID of the firmware for cache keying.
        db: Async database session.

    Returns:
        AI-cleaned pseudo-C code string.

    Raises:
        RuntimeError: If the Anthropic API call fails.
    """
    # Compute binary hash for cache key
    binary_sha256 = await asyncio.get_event_loop().run_in_executor(
        None, _compute_sha256, binary_path
    )

    operation = f"code_cleanup:{function_name}"

    # Check cache
    stmt = select(AnalysisCache.result).where(
        AnalysisCache.firmware_id == firmware_id,
        AnalysisCache.binary_sha256 == binary_sha256,
        AnalysisCache.operation == operation,
    )
    row = (await db.execute(stmt)).scalar_one_or_none()
    if row is not None and isinstance(row, dict):
        cached = row.get("cleaned_code")
        if cached:
            logger.info("Cache hit for code cleanup: %s:%s", os.path.basename(binary_path), function_name)
            return cached

    # Build prompt
    user_message = _build_user_message(raw_code, function_name, binary_path, binary_info, imports)

    # Call Claude API (non-streaming)
    settings = get_settings()
    client = anthropic.AsyncAnthropic(api_key=settings.anthropic_api_key)

    try:
        response = await client.messages.create(
            model=CLEANUP_MODEL,
            max_tokens=CLEANUP_MAX_TOKENS,
            system=_SYSTEM_PROMPT,
            messages=[{"role": "user", "content": user_message}],
        )
    except anthropic.APIError as exc:
        raise RuntimeError(f"Anthropic API error during code cleanup: {exc}") from exc

    # Extract text from response
    text_parts = [block.text for block in response.content if block.type == "text"]
    cleaned = "\n".join(text_parts).strip()

    if not cleaned:
        logger.warning("AI cleanup returned empty response for %s:%s", os.path.basename(binary_path), function_name)
        return raw_code + "\n\n/* AI cleanup failed — returning raw decompilation */"

    # Strip markdown fences if present
    cleaned = _strip_markdown_fences(cleaned)

    # Handle truncated response
    if response.stop_reason == "max_tokens":
        cleaned += "\n\n/* AI cleanup truncated — output exceeded token limit */"

    # Store in cache
    cache_entry = AnalysisCache(
        firmware_id=firmware_id,
        binary_path=binary_path,
        binary_sha256=binary_sha256,
        operation=operation,
        result={"cleaned_code": cleaned},
    )
    db.add(cache_entry)
    await db.flush()

    return cleaned
