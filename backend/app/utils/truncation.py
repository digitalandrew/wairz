from app.config import get_settings


def truncate_output(text: str, max_kb: int | None = None) -> str:
    """Truncate tool output to stay within size limits.

    Cuts at the last newline before the byte limit for clean line boundaries.
    """
    if max_kb is None:
        max_kb = get_settings().max_tool_output_kb

    max_bytes = max_kb * 1024
    encoded = text.encode("utf-8")

    if len(encoded) <= max_bytes:
        return text

    total_kb = len(encoded) / 1024

    # Truncate at byte level, then find last newline for clean boundary
    truncated = encoded[:max_bytes]
    last_newline = truncated.rfind(b"\n")
    if last_newline > 0:
        truncated = truncated[:last_newline]

    shown_kb = len(truncated) / 1024
    result = truncated.decode("utf-8", errors="replace")
    result += f"\n\n... [truncated: showing ~{shown_kb:.0f}KB of {total_kb:.0f}KB]"
    return result
