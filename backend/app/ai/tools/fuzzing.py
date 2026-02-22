"""Fuzzing AI tools for automated vulnerability discovery.

Tools for analyzing fuzzing targets, managing AFL++ campaigns, generating
dictionaries and seed corpora, and triaging crashes.
"""

import base64

from sqlalchemy import select

from app.ai.tool_registry import ToolContext, ToolRegistry
from app.config import get_settings
from app.models.firmware import Firmware
from app.models.fuzzing import FuzzingCampaign, FuzzingCrash
from app.services.fuzzing_service import FuzzingService


def register_fuzzing_tools(registry: ToolRegistry) -> None:
    """Register all fuzzing tools with the given registry."""

    registry.register(
        name="analyze_fuzzing_target",
        description=(
            "Analyze a firmware binary for fuzzing suitability. Returns a score "
            "(0-100), identified input-handling functions, dangerous sinks "
            "(strcpy, system, sprintf, etc.), binary protections, and a "
            "recommended fuzzing strategy (stdin, file, or network). "
            "Use this BEFORE starting a fuzzing campaign to identify the best "
            "targets — prioritize binaries with high scores."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "binary_path": {
                    "type": "string",
                    "description": "Path to the binary within the firmware filesystem (e.g., /usr/sbin/httpd)",
                },
            },
            "required": ["binary_path"],
        },
        handler=_handle_analyze_target,
    )

    registry.register(
        name="generate_fuzzing_dictionary",
        description=(
            "Generate an AFL++ dictionary from a firmware binary by extracting "
            "interesting strings (format specifiers, protocol keywords, magic "
            "values, parameter names). A good dictionary dramatically improves "
            "fuzzing effectiveness by guiding mutations toward meaningful values."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "binary_path": {
                    "type": "string",
                    "description": "Path to the binary within the firmware filesystem",
                },
            },
            "required": ["binary_path"],
        },
        handler=_handle_generate_dictionary,
    )

    registry.register(
        name="generate_seed_corpus",
        description=(
            "Generate minimal seed inputs for fuzzing based on the binary's "
            "input type. For stdin-based programs, generates short test strings. "
            "For file-based programs, generates minimal file headers. "
            "Returns base64-encoded seeds ready for the fuzzing campaign."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "binary_path": {
                    "type": "string",
                    "description": "Path to the binary within the firmware filesystem",
                },
                "input_type": {
                    "type": "string",
                    "enum": ["stdin", "file", "network"],
                    "description": "Type of input the binary processes (from analyze_fuzzing_target)",
                },
            },
            "required": ["binary_path"],
        },
        handler=_handle_generate_seed_corpus,
    )

    registry.register(
        name="start_fuzzing_campaign",
        description=(
            "Create and start an AFL++ fuzzing campaign for a firmware binary. "
            "The fuzzer runs in QEMU mode (-Q) inside an isolated Docker container. "
            "Returns the campaign ID for monitoring. Use analyze_fuzzing_target "
            "first to verify the binary is a good target, and optionally generate "
            "a dictionary and seed corpus for better results. "
            "Only one campaign can run at a time per project."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "binary_path": {
                    "type": "string",
                    "description": "Path to the binary within the firmware filesystem",
                },
                "timeout_per_exec": {
                    "type": "integer",
                    "description": "Timeout per execution in milliseconds (default 1000, max 30000)",
                },
                "memory_limit": {
                    "type": "integer",
                    "description": "Memory limit per execution in MB (default 256, max 1024)",
                },
                "dictionary": {
                    "type": "string",
                    "description": "AFL++ dictionary content (one entry per line, format: token=\"value\")",
                },
                "seed_corpus": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Base64-encoded seed input files",
                },
            },
            "required": ["binary_path"],
        },
        handler=_handle_start_campaign,
    )

    registry.register(
        name="check_fuzzing_status",
        description=(
            "Check the status of a fuzzing campaign or list all campaigns. "
            "Returns live statistics: executions/sec, total executions, corpus "
            "size, crash count, hang count, stability, and coverage. "
            "If no campaign_id is given, lists all campaigns for the project."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "campaign_id": {
                    "type": "string",
                    "description": "Optional campaign ID. If omitted, lists all campaigns.",
                },
            },
        },
        handler=_handle_check_status,
    )

    registry.register(
        name="stop_fuzzing_campaign",
        description=(
            "Stop a running fuzzing campaign. Syncs final crash data and "
            "statistics before stopping. Always stop campaigns when done to "
            "free resources."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "campaign_id": {
                    "type": "string",
                    "description": "The campaign ID to stop",
                },
            },
            "required": ["campaign_id"],
        },
        handler=_handle_stop_campaign,
    )

    registry.register(
        name="triage_fuzzing_crash",
        description=(
            "Triage a crash found by the fuzzer: reproduce it under GDB, "
            "capture the stack trace and register state, and classify "
            "exploitability (exploitable, probably_exploitable, probably_not, "
            "unknown). Use this on each crash to determine if it's a real "
            "vulnerability worth reporting as a finding."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "campaign_id": {
                    "type": "string",
                    "description": "The campaign ID",
                },
                "crash_id": {
                    "type": "string",
                    "description": "The crash ID to triage",
                },
            },
            "required": ["campaign_id", "crash_id"],
        },
        handler=_handle_triage_crash,
    )


# ---------------------------------------------------------------------------
# Tool handlers
# ---------------------------------------------------------------------------


async def _handle_analyze_target(input: dict, context: ToolContext) -> str:
    """Analyze a binary for fuzzing suitability."""
    binary_path = input.get("binary_path", "")
    if not binary_path:
        return "Error: binary_path is required."

    result = await context.db.execute(
        select(Firmware).where(Firmware.id == context.firmware_id)
    )
    firmware = result.scalar_one_or_none()
    if not firmware:
        return "Error: firmware not found."

    svc = FuzzingService(context.db)
    try:
        analysis = await svc.analyze_target(firmware, binary_path)
    except ValueError as exc:
        return f"Error: {exc}"

    if analysis.get("error"):
        return f"Error analyzing {binary_path}: {analysis['error']}"

    score = analysis["fuzzing_score"]
    lines = [
        f"Fuzzing Target Analysis: {binary_path}",
        f"  Score: {score}/100 ({'good target' if score >= 60 else 'moderate' if score >= 30 else 'poor target'})",
        f"  Recommended strategy: {analysis['recommended_strategy']}",
        f"  Functions: {analysis['function_count']}",
        f"  File size: {analysis['file_size']} bytes",
        "",
    ]

    if analysis["dangerous_functions"]:
        lines.append(f"  Dangerous sinks: {', '.join(analysis['dangerous_functions'])}")
    if analysis["input_sources"]:
        lines.append(f"  Input functions: {', '.join(analysis['input_sources'])}")
    if analysis["network_functions"]:
        lines.append(f"  Network functions: {', '.join(analysis['network_functions'])}")

    prot = analysis.get("protections", {})
    if prot:
        lines.append("")
        lines.append("  Binary protections:")
        lines.append(f"    NX: {'yes' if prot.get('nx') else 'NO'}")
        lines.append(f"    RELRO: {prot.get('relro', 'unknown')}")
        lines.append(f"    Canary: {'yes' if prot.get('canary') else 'NO'}")
        lines.append(f"    PIE: {'yes' if prot.get('pie') else 'NO'}")

    if score >= 60:
        lines.append("")
        lines.append("Recommendation: This binary is a good fuzzing target. "
                      "Proceed with start_fuzzing_campaign.")
    elif score >= 30:
        lines.append("")
        lines.append("Recommendation: Moderate fuzzing target. Consider generating "
                      "a dictionary and seed corpus for better results.")
    else:
        lines.append("")
        lines.append("Recommendation: This binary may not be a productive fuzzing target. "
                      "Consider analyzing other binaries first.")

    return "\n".join(lines)


async def _handle_generate_dictionary(input: dict, context: ToolContext) -> str:
    """Generate an AFL++ dictionary from binary strings."""
    binary_path = input.get("binary_path", "")
    if not binary_path:
        return "Error: binary_path is required."

    result = await context.db.execute(
        select(Firmware).where(Firmware.id == context.firmware_id)
    )
    firmware = result.scalar_one_or_none()
    if not firmware or not firmware.extracted_path:
        return "Error: firmware not found or not unpacked."

    from app.utils.sandbox import validate_path
    try:
        full_path = validate_path(firmware.extracted_path, binary_path)
    except Exception as exc:
        return f"Error: {exc}"

    # Extract strings and build dictionary entries
    import subprocess
    try:
        proc = subprocess.run(
            ["strings", "-n", "4", full_path],
            capture_output=True, timeout=30, text=True,
        )
        all_strings = proc.stdout.strip().split("\n") if proc.stdout else []
    except Exception as exc:
        return f"Error extracting strings: {exc}"

    # Filter for dictionary-worthy entries
    dict_entries = set()
    for s in all_strings:
        s = s.strip()
        if not s or len(s) > 64:
            continue
        # Format specifiers
        if "%" in s and any(c in s for c in "sdxXfn"):
            dict_entries.add(s)
        # Protocol keywords
        elif s.upper() in ("GET", "POST", "PUT", "DELETE", "HTTP", "HEAD",
                           "OPTIONS", "CONTENT-LENGTH", "CONTENT-TYPE",
                           "HOST", "USER-AGENT", "COOKIE", "SET-COOKIE"):
            dict_entries.add(s)
        # Delimiters and special chars
        elif s in ("=", "&", "?", ";", "|", "`", "$", "{", "}", "\\n", "\\r\\n",
                    "://", "/", "..", "../", "\\x00"):
            dict_entries.add(s)
        # Short interesting tokens (likely parameter names or keywords)
        elif 3 <= len(s) <= 16 and s.isalnum():
            # Keep if it looks like a keyword (not random hex)
            if s.isalpha() or (s[0].isalpha() and s.replace("_", "").isalnum()):
                dict_entries.add(s)

    # Limit to 200 entries
    entries = sorted(dict_entries)[:200]

    if not entries:
        return "No dictionary-worthy strings found in the binary."

    # Format as AFL++ dictionary
    dict_content = []
    for i, entry in enumerate(entries):
        # Escape for AFL++ dictionary format
        escaped = entry.replace("\\", "\\\\").replace('"', '\\"')
        dict_content.append(f'token_{i}="{escaped}"')

    output = "\n".join(dict_content)

    lines = [
        f"Generated AFL++ dictionary with {len(entries)} entries for {binary_path}.",
        "",
        "Dictionary content (pass to start_fuzzing_campaign as 'dictionary'):",
        "",
        output,
    ]

    return "\n".join(lines)


async def _handle_generate_seed_corpus(input: dict, context: ToolContext) -> str:
    """Generate minimal seed inputs for fuzzing."""
    input_type = input.get("input_type", "stdin")

    # Generate seeds based on input type
    seeds: list[bytes] = []

    if input_type == "network":
        seeds = [
            b"GET / HTTP/1.0\r\n\r\n",
            b"POST /login HTTP/1.1\r\nContent-Length: 10\r\n\r\nuser=admin",
            b"GET /admin HTTP/1.1\r\nHost: 192.168.1.1\r\nCookie: session=AAAA\r\n\r\n",
            b"\x00\x01\x00\x00\x00\x01\x00\x00",  # DNS-like
        ]
    elif input_type == "file":
        seeds = [
            b"test config\nkey=value\n",
            b'{"key": "value", "num": 123}\n',
            b"<?xml version=\"1.0\"?><root><item>test</item></root>",
            b"\x00" * 16,
        ]
    else:  # stdin
        seeds = [
            b"AAAA",
            b"admin\npassword\n",
            b"test input with spaces and $pecial chars!",
            b"\x00\x01\x02\x03\x04\x05\x06\x07",
            b"A" * 256,
        ]

    seed_b64 = [base64.b64encode(s).decode() for s in seeds]

    lines = [
        f"Generated {len(seeds)} seed inputs for {input_type}-based fuzzing.",
        "",
        "Seeds (base64-encoded, pass to start_fuzzing_campaign as 'seed_corpus'):",
    ]
    for i, (s, b) in enumerate(zip(seeds, seed_b64)):
        preview = s[:40].decode("utf-8", errors="replace")
        lines.append(f"  Seed {i}: {preview!r} ({len(s)} bytes)")

    lines.append("")
    lines.append("seed_corpus values:")
    for b in seed_b64:
        lines.append(f'  "{b}"')

    return "\n".join(lines)


async def _handle_start_campaign(input: dict, context: ToolContext) -> str:
    """Create and start a fuzzing campaign."""
    binary_path = input.get("binary_path", "")
    if not binary_path:
        return "Error: binary_path is required."

    result = await context.db.execute(
        select(Firmware).where(Firmware.id == context.firmware_id)
    )
    firmware = result.scalar_one_or_none()
    if not firmware:
        return "Error: firmware not found."

    config = {}
    if "timeout_per_exec" in input:
        config["timeout_per_exec"] = min(input["timeout_per_exec"], 30000)
    if "memory_limit" in input:
        config["memory_limit"] = min(input["memory_limit"], 1024)
    if "dictionary" in input:
        config["dictionary"] = input["dictionary"]
    if "seed_corpus" in input:
        config["seed_corpus"] = input["seed_corpus"]

    svc = FuzzingService(context.db)
    try:
        campaign = await svc.create_campaign(firmware, binary_path, config)
        campaign = await svc.start_campaign(campaign.id, context.project_id)
        await context.db.commit()
    except ValueError as exc:
        return f"Error: {exc}"
    except Exception as exc:
        return f"Error starting campaign: {exc}"

    lines = [
        f"Fuzzing campaign started successfully.",
        f"  Campaign ID: {campaign.id}",
        f"  Binary: {campaign.binary_path}",
        f"  Status: {campaign.status}",
    ]
    if campaign.error_message:
        lines.append(f"  Error: {campaign.error_message}")
    else:
        lines.append("")
        lines.append(
            "Use check_fuzzing_status with this campaign ID to monitor progress. "
            "AFL++ needs time to build coverage — check back after a few minutes."
        )
        lines.append(
            "Use stop_fuzzing_campaign when done. Use triage_fuzzing_crash to "
            "analyze any crashes found."
        )

    return "\n".join(lines)


async def _handle_check_status(input: dict, context: ToolContext) -> str:
    """Check fuzzing campaign status or list all campaigns."""
    campaign_id = input.get("campaign_id")

    svc = FuzzingService(context.db)

    if campaign_id:
        from uuid import UUID
        try:
            campaign = await svc.get_campaign_status(UUID(campaign_id), context.project_id)
        except ValueError as exc:
            return f"Error: {exc}"

        lines = [
            f"Campaign: {campaign.id}",
            f"  Binary: {campaign.binary_path}",
            f"  Status: {campaign.status}",
        ]

        stats = campaign.stats
        if stats:
            lines.append(f"  Execs/sec: {stats.get('execs_per_sec', 0)}")
            lines.append(f"  Total execs: {stats.get('total_execs', 0)}")
            lines.append(f"  Corpus: {stats.get('corpus_count', 0)}")
            lines.append(f"  Crashes: {stats.get('saved_crashes', 0)}")
            lines.append(f"  Hangs: {stats.get('saved_hangs', 0)}")
            lines.append(f"  Stability: {stats.get('stability', 'N/A')}")
            lines.append(f"  Coverage: {stats.get('bitmap_cvg', 'N/A')}")

        if campaign.crashes_count > 0:
            crashes = await svc.get_crashes(UUID(campaign_id), context.project_id)
            lines.append(f"\n  Crashes ({len(crashes)}):")
            for c in crashes[:10]:
                expl = f" [{c.exploitability}]" if c.exploitability else ""
                sig = f" ({c.signal})" if c.signal else ""
                lines.append(f"    {c.crash_filename}{sig}{expl} — ID: {c.id}")

        if campaign.error_message:
            lines.append(f"\n  Error: {campaign.error_message}")

        return "\n".join(lines)

    # List all campaigns
    campaigns = await svc.list_campaigns(context.project_id)
    if not campaigns:
        return "No fuzzing campaigns found for this project."

    lines = [f"Fuzzing campaigns ({len(campaigns)}):\n"]
    for c in campaigns[:10]:
        status_icon = {
            "running": "[RUNNING]",
            "created": "[CREATED]",
            "stopped": "[STOPPED]",
            "completed": "[COMPLETED]",
            "error": "[ERROR]",
        }.get(c.status, f"[{c.status}]")

        crashes_str = f" — {c.crashes_count} crashes" if c.crashes_count else ""
        lines.append(f"  {status_icon} {c.id} — {c.binary_path}{crashes_str}")

    return "\n".join(lines)


async def _handle_stop_campaign(input: dict, context: ToolContext) -> str:
    """Stop a fuzzing campaign."""
    campaign_id = input.get("campaign_id")
    if not campaign_id:
        return "Error: campaign_id is required."

    svc = FuzzingService(context.db)
    try:
        from uuid import UUID
        campaign = await svc.stop_campaign(UUID(campaign_id), context.project_id)
        await context.db.commit()
    except ValueError as exc:
        return f"Error: {exc}"

    lines = [f"Campaign {campaign.id} stopped."]
    if campaign.stats:
        lines.append(f"  Total execs: {campaign.stats.get('total_execs', 0)}")
        lines.append(f"  Crashes: {campaign.stats.get('saved_crashes', 0)}")
    lines.append(f"  Final crash count: {campaign.crashes_count}")

    return "\n".join(lines)


async def _handle_triage_crash(input: dict, context: ToolContext) -> str:
    """Triage a crash found by the fuzzer."""
    campaign_id = input.get("campaign_id")
    crash_id = input.get("crash_id")
    if not campaign_id or not crash_id:
        return "Error: campaign_id and crash_id are required."

    svc = FuzzingService(context.db)
    try:
        from uuid import UUID
        crash = await svc.triage_crash(UUID(campaign_id), UUID(crash_id), context.project_id)
        await context.db.commit()
    except ValueError as exc:
        return f"Error: {exc}"

    lines = [
        f"Crash triage: {crash.crash_filename}",
        f"  Signal: {crash.signal or 'unknown'}",
        f"  Exploitability: {crash.exploitability or 'unknown'}",
        f"  Size: {crash.crash_size or 0} bytes",
    ]

    if crash.stack_trace:
        lines.append(f"\nStack trace:\n{crash.stack_trace}")

    if crash.exploitability in ("exploitable", "probably_exploitable"):
        lines.append(
            "\nThis crash appears exploitable. Consider creating a finding "
            "with add_finding (source='fuzzing') to formally record it."
        )

    return "\n".join(lines)
