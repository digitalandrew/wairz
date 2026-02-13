import os

from app.ai.tool_registry import ToolContext, ToolRegistry
from app.services.file_service import FileService
from app.utils.sandbox import validate_path

MAX_FIND_RESULTS = 100

# Extension-based type mapping (fast first pass)
TYPE_EXTENSIONS: dict[str, set[str]] = {
    "config": {
        ".conf", ".cfg", ".ini", ".yaml", ".yml", ".json", ".xml", ".toml",
        ".properties", ".env", ".htaccess",
    },
    "certificate": {".pem", ".crt", ".cer", ".der", ".key", ".p12", ".pfx"},
    "python": {".py", ".pyc", ".pyo"},
    "lua": {".lua"},
    "web": {".html", ".htm", ".css", ".js", ".php", ".asp", ".jsp", ".cgi"},
    "database": {".db", ".sqlite", ".sqlite3"},
}

VALID_TYPES = {"elf", "shell_script", "config", "certificate", "python", "lua",
               "library", "database", "web"}


def _check_type_magic(filepath: str, file_type: str) -> bool:
    """Check file type using magic bytes for types that need it."""
    try:
        if file_type == "elf":
            with open(filepath, "rb") as f:
                return f.read(4) == b"\x7fELF"
        if file_type == "shell_script":
            with open(filepath, "rb") as f:
                header = f.read(2)
                return header == b"#!"
        if file_type == "database":
            with open(filepath, "rb") as f:
                return f.read(15) == b"SQLite format 3"
    except (OSError, PermissionError):
        pass
    return False


def _matches_type(filepath: str, name: str, file_type: str) -> bool:
    """Check if a file matches the requested type."""
    _, ext = os.path.splitext(name)
    ext = ext.lower()

    # Extension-based types
    if file_type in TYPE_EXTENSIONS:
        return ext in TYPE_EXTENSIONS[file_type]

    # Library: .so or .so.N patterns
    if file_type == "library":
        if ext == ".so" or ".so." in name or ext == ".a":
            return True
        return False

    # Types needing magic bytes
    if file_type == "elf":
        return _check_type_magic(filepath, "elf")

    if file_type == "shell_script":
        if ext in {".sh", ".bash"}:
            return True
        return _check_type_magic(filepath, "shell_script")

    return False


def _find_files_by_type(extracted_root: str, file_type: str, path: str | None) -> str:
    """Walk filesystem and find files matching the requested type."""
    if file_type not in VALID_TYPES:
        return f"Error: unknown file type '{file_type}'. Valid types: {', '.join(sorted(VALID_TYPES))}"

    search_root = validate_path(extracted_root, path or "/")
    real_root = os.path.realpath(extracted_root)
    matches: list[str] = []

    for dirpath, _dirs, files in os.walk(search_root):
        for name in files:
            abs_path = os.path.join(dirpath, name)
            if _matches_type(abs_path, name, file_type):
                rel_path = "/" + os.path.relpath(abs_path, real_root)
                matches.append(rel_path)
                if len(matches) >= MAX_FIND_RESULTS:
                    break
        if len(matches) >= MAX_FIND_RESULTS:
            break

    if not matches:
        return f"No files of type '{file_type}' found."

    header = f"Found {len(matches)} {file_type} file(s)"
    if len(matches) >= MAX_FIND_RESULTS:
        header += f" (showing first {MAX_FIND_RESULTS})"
    header += ":\n"
    return header + "\n".join(matches)


async def _handle_list_directory(input: dict, context: ToolContext) -> str:
    svc = FileService(context.extracted_path)
    entries, truncated = svc.list_directory(input["path"])

    if not entries:
        return "Empty directory."

    lines = []
    for e in entries:
        suffix = ""
        if e.type == "directory":
            suffix = "/"
        elif e.type == "symlink" and e.symlink_target:
            suffix = f" -> {e.symlink_target}"
        lines.append(f"{e.permissions}  {e.size:>8}  {e.name}{suffix}")

    result = "\n".join(lines)
    if truncated:
        result += f"\n\n... [truncated: showing first {len(entries)} entries]"
    return result


async def _handle_read_file(input: dict, context: ToolContext) -> str:
    svc = FileService(context.extracted_path)
    content = svc.read_file(
        path=input["path"],
        offset=input.get("offset", 0),
        length=input.get("length"),
    )

    header = f"File size: {content.size} bytes"
    if content.is_binary:
        header += " (binary, showing hex dump)"
    if content.truncated:
        header += " [truncated]"
    return f"{header}\n\n{content.content}"


async def _handle_file_info(input: dict, context: ToolContext) -> str:
    svc = FileService(context.extracted_path)
    info = svc.file_info(input["path"])

    lines = [
        f"Path: {info.path}",
        f"Type: {info.type}",
        f"MIME: {info.mime_type}",
        f"Size: {info.size} bytes",
        f"Permissions: {info.permissions}",
    ]
    if info.sha256:
        lines.append(f"SHA256: {info.sha256}")
    if info.elf_info:
        lines.append("ELF Info:")
        for k, v in info.elf_info.items():
            lines.append(f"  {k}: {v}")
    return "\n".join(lines)


async def _handle_search_files(input: dict, context: ToolContext) -> str:
    svc = FileService(context.extracted_path)
    matches, truncated = svc.search_files(
        pattern=input["pattern"],
        path=input.get("path", "/"),
    )

    if not matches:
        return f"No files matching '{input['pattern']}' found."

    header = f"Found {len(matches)} match(es)"
    if truncated:
        header += f" (showing first {len(matches)})"
    header += ":\n"
    return header + "\n".join(matches)


async def _handle_find_files_by_type(input: dict, context: ToolContext) -> str:
    return _find_files_by_type(
        extracted_root=context.extracted_path,
        file_type=input["file_type"],
        path=input.get("path"),
    )


def register_filesystem_tools(registry: ToolRegistry) -> None:
    """Register all filesystem tools with the given registry."""

    registry.register(
        name="list_directory",
        description=(
            "List contents of a directory in the firmware filesystem. "
            "Returns file names, types, sizes, and permissions. Max 200 entries."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Directory path to list (e.g. '/' or '/etc')",
                },
            },
            "required": ["path"],
        },
        handler=_handle_list_directory,
    )

    registry.register(
        name="read_file",
        description=(
            "Read contents of a file. Text files return UTF-8 content, "
            "binary files return a hex dump. Max 50KB per read. "
            "Use offset and length for partial reads of large files."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "File path to read",
                },
                "offset": {
                    "type": "integer",
                    "description": "Byte offset to start reading from (default: 0)",
                },
                "length": {
                    "type": "integer",
                    "description": "Number of bytes to read (default: up to 50KB)",
                },
            },
            "required": ["path"],
        },
        handler=_handle_read_file,
    )

    registry.register(
        name="file_info",
        description=(
            "Get detailed metadata for a file: type, MIME type, size, permissions, "
            "SHA256 hash, and ELF headers if applicable."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "File path to inspect",
                },
            },
            "required": ["path"],
        },
        handler=_handle_file_info,
    )

    registry.register(
        name="search_files",
        description=(
            "Search for files by glob pattern (e.g. '*.conf', 'passwd'). "
            "Returns matching file paths. Max 100 results."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "pattern": {
                    "type": "string",
                    "description": "Glob pattern to match file names against",
                },
                "path": {
                    "type": "string",
                    "description": "Directory to search in (default: '/')",
                },
            },
            "required": ["pattern"],
        },
        handler=_handle_search_files,
    )

    registry.register(
        name="find_files_by_type",
        description=(
            "Find files of a specific type in the firmware filesystem. "
            "Types: elf, shell_script, config, certificate, python, lua, "
            "library, database, web. Max 100 results."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "file_type": {
                    "type": "string",
                    "description": "Type of files to find",
                    "enum": sorted(VALID_TYPES),
                },
                "path": {
                    "type": "string",
                    "description": "Directory to search in (default: '/')",
                },
            },
            "required": ["file_type"],
        },
        handler=_handle_find_files_by_type,
    )
