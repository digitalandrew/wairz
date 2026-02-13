import base64
import fnmatch
import hashlib
import os
import stat
from dataclasses import dataclass, field

import magic
from elftools.elf.elffile import ELFFile

from app.utils.sandbox import validate_path

MAX_ENTRIES = 200
MAX_READ_SIZE = 50 * 1024  # 50KB
MAX_SEARCH_RESULTS = 100


@dataclass
class FileEntry:
    name: str
    type: str  # file, directory, symlink, other
    size: int
    permissions: str
    symlink_target: str | None = None


@dataclass
class FileContent:
    content: str
    is_binary: bool
    size: int
    truncated: bool = False
    encoding: str = "utf-8"


@dataclass
class FileInfo:
    path: str
    type: str
    mime_type: str
    size: int
    permissions: str
    sha256: str | None = None
    elf_info: dict | None = None


def _format_permissions(mode: int) -> str:
    """Format file mode as rwx string."""
    parts = []
    for who in range(2, -1, -1):
        for perm, char in [(4, "r"), (2, "w"), (1, "x")]:
            if mode & (perm << (who * 3)):
                parts.append(char)
            else:
                parts.append("-")
    return "".join(parts)


def _file_type_from_stat(st: os.stat_result) -> str:
    mode = st.st_mode
    if stat.S_ISDIR(mode):
        return "directory"
    if stat.S_ISLNK(mode):
        return "symlink"
    if stat.S_ISREG(mode):
        return "file"
    return "other"


def _is_binary(data: bytes) -> bool:
    """Check if data is binary by looking for null bytes."""
    return b"\x00" in data[:8192]


def _hex_dump(data: bytes, offset: int = 0) -> str:
    """Generate classic hex dump: offset | hex bytes | ASCII."""
    lines = []
    for i in range(0, len(data), 16):
        chunk = data[i : i + 16]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{offset + i:08x}  {hex_part:<48s}  |{ascii_part}|")
    return "\n".join(lines)


class FileService:
    def __init__(self, extracted_root: str):
        self.extracted_root = extracted_root

    def _validate(self, path: str) -> str:
        return validate_path(self.extracted_root, path)

    def list_directory(self, path: str = "/") -> tuple[list[FileEntry], bool]:
        """List directory contents. Returns (entries, truncated)."""
        full_path = self._validate(path)

        if not os.path.isdir(full_path):
            raise FileNotFoundError(f"Not a directory: {path}")

        entries = []
        items = sorted(os.listdir(full_path))
        truncated = len(items) > MAX_ENTRIES

        for name in items[:MAX_ENTRIES]:
            entry_path = os.path.join(full_path, name)
            try:
                # Use lstat to not follow symlinks
                st = os.lstat(entry_path)
                file_type = _file_type_from_stat(st)
                symlink_target = None
                if stat.S_ISLNK(st.st_mode):
                    try:
                        symlink_target = os.readlink(entry_path)
                    except OSError:
                        pass
                entries.append(
                    FileEntry(
                        name=name,
                        type=file_type,
                        size=st.st_size,
                        permissions=_format_permissions(st.st_mode),
                        symlink_target=symlink_target,
                    )
                )
            except OSError:
                continue

        return entries, truncated

    def read_file(
        self,
        path: str,
        offset: int = 0,
        length: int | None = None,
        format: str = "auto",
    ) -> FileContent:
        """Read file contents. Auto-detects binary vs text.

        format: "auto" (default) — hex dump for binary, utf-8 for text
                "base64" — raw bytes as base64 string
        """
        full_path = self._validate(path)

        if not os.path.isfile(full_path):
            raise FileNotFoundError(f"Not a file: {path}")

        file_size = os.path.getsize(full_path)
        read_length = min(length or MAX_READ_SIZE, MAX_READ_SIZE)

        with open(full_path, "rb") as f:
            f.seek(offset)
            data = f.read(read_length)

        truncated = (offset + len(data)) < file_size

        if format == "base64":
            return FileContent(
                content=base64.b64encode(data).decode("ascii"),
                is_binary=True,
                size=file_size,
                truncated=truncated,
                encoding="base64",
            )

        binary = _is_binary(data)

        if binary:
            content = _hex_dump(data, offset)
            encoding = "hex"
        else:
            content = data.decode("utf-8", errors="replace")
            encoding = "utf-8"

        return FileContent(
            content=content,
            is_binary=binary,
            size=file_size,
            truncated=truncated,
            encoding=encoding,
        )

    def file_info(self, path: str) -> FileInfo:
        """Get detailed file information including magic type and ELF headers."""
        full_path = self._validate(path)

        if not os.path.exists(full_path):
            raise FileNotFoundError(f"File not found: {path}")

        st = os.lstat(full_path)
        file_type = _file_type_from_stat(st)

        # MIME type detection
        try:
            mime_type = magic.from_file(full_path, mime=True)
        except Exception:
            mime_type = "application/octet-stream"

        # SHA256 for regular files
        sha256 = None
        if stat.S_ISREG(st.st_mode):
            h = hashlib.sha256()
            with open(full_path, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    h.update(chunk)
            sha256 = h.hexdigest()

        # ELF info if applicable
        elf_info = None
        if stat.S_ISREG(st.st_mode):
            try:
                with open(full_path, "rb") as f:
                    if f.read(4) == b"\x7fELF":
                        f.seek(0)
                        elf = ELFFile(f)
                        elf_info = {
                            "machine": elf.header.e_machine,
                            "type": elf.header.e_type,
                            "entry_point": hex(elf.header.e_entry),
                            "endianness": "little" if elf.little_endian else "big",
                            "bits": elf.elfclass,
                        }
            except Exception:
                pass

        return FileInfo(
            path=path,
            type=file_type,
            mime_type=mime_type,
            size=st.st_size,
            permissions=_format_permissions(st.st_mode),
            sha256=sha256,
            elf_info=elf_info,
        )

    def search_files(self, pattern: str, path: str = "/") -> tuple[list[str], bool]:
        """Search for files matching a glob pattern. Returns (matches, truncated)."""
        full_path = self._validate(path)
        real_root = os.path.realpath(self.extracted_root)

        matches = []
        truncated = False

        for root, dirs, files in os.walk(full_path):
            for name in files + dirs:
                if fnmatch.fnmatch(name, pattern):
                    abs_path = os.path.join(root, name)
                    # Return path relative to extracted root
                    rel_path = "/" + os.path.relpath(abs_path, real_root)
                    matches.append(rel_path)
                    if len(matches) >= MAX_SEARCH_RESULTS:
                        truncated = True
                        break
            if truncated:
                break

        return matches, truncated
