import base64
import fnmatch
import hashlib
import os
import re
import stat
from dataclasses import dataclass, field

import magic
from elftools.elf.elffile import ELFFile

from app.utils.sandbox import safe_walk, validate_path

MAX_ENTRIES = 200
MAX_READ_SIZE = 50 * 1024  # 50KB
MAX_SEARCH_RESULTS = 100

# Pattern matching binwalk-extracted filesystem root directories
# e.g. squashfs-root, jffs2-root, jffs2-root-0, ext-root-3
_ROOT_DIR_PATTERN = re.compile(r"^[a-z0-9]+-root(-\d+)?$")

# File extensions for raw filesystem images (not useful to browse directly)
_RAW_FS_EXTENSIONS = frozenset({
    ".jffs2", ".squashfs", ".sqfs", ".cramfs", ".ubifs", ".ubi",
    ".ext", ".ext2", ".ext3", ".ext4", ".yaffs", ".yaffs2", ".romfs", ".cpio",
})

# File extensions/patterns to skip at the virtual top level (already in rootfs)
_SKIP_EXTENSIONS = frozenset({".so", ".a", ".py"})

def _is_shared_lib(name: str) -> bool:
    """Check if a filename looks like a shared library (e.g., libfoo.so.1.2)."""
    return ".so." in name or name.endswith(".so")

# Minimum file size to show at the virtual top level (skip tiny files)
_MIN_RAW_FILE_SIZE = 100_000  # 100KB


@dataclass
class FileEntry:
    name: str
    type: str  # file, directory, symlink, other
    size: int
    permissions: str
    symlink_target: str | None = None
    broken: bool = False


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
    """Firmware filesystem browser with optional multi-partition virtual root.

    When *extraction_dir* is provided (the binwalk output directory that
    contains the rootfs **and** other extracted partitions), the service
    presents a virtual top-level at ``/`` that looks like::

        /
        ├── rootfs/              ← the primary Linux filesystem
        ├── jffs2-root/          ← extracted JFFS2 data partition
        ├── squashfs-root-0/     ← secondary squashfs
        └── 3A7BB               ← large raw file (kernel, etc.)

    Paths starting with ``/rootfs/`` resolve to the real rootfs directory.
    All other paths resolve against *extraction_dir*.

    When *extraction_dir* is ``None`` (legacy / simple firmware), everything
    works exactly as before — ``/`` lists the rootfs directly.
    """

    ROOTFS_VNAME = "rootfs"

    def __init__(self, extracted_root: str, extraction_dir: str | None = None):
        self.extracted_root = extracted_root
        # Only enable virtual top-level when extraction_dir differs from rootfs
        if extraction_dir and os.path.realpath(extraction_dir) != os.path.realpath(extracted_root):
            self.extraction_dir = extraction_dir
        else:
            self.extraction_dir = None
        # Lazily built mapping from virtual name → real path for nested roots
        self._virtual_map: dict[str, str] | None = None

    # ── path resolution ──────────────────────────────────────────────

    def _build_virtual_map(self) -> dict[str, str]:
        """Build mapping of virtual directory names to real paths.

        For nested binwalk -Me extractions, *-root directories can be inside
        subdirectories of extraction_dir. This map resolves virtual names like
        "ext-root" to their real paths regardless of nesting depth.
        """
        if self._virtual_map is not None:
            return self._virtual_map

        vmap: dict[str, str] = {}
        assert self.extraction_dir is not None
        rootfs_real = os.path.realpath(self.extracted_root)

        # Scan extraction_dir and one level of subdirectories for *-root dirs
        try:
            top_entries = list(os.scandir(self.extraction_dir))
        except OSError:
            self._virtual_map = vmap
            return vmap

        for entry in top_entries:
            if not entry.is_dir(follow_symlinks=False):
                continue
            real = os.path.realpath(entry.path)
            if real == rootfs_real:
                continue
            if _ROOT_DIR_PATTERN.match(entry.name):
                vmap[entry.name] = entry.path
            else:
                # Look one level deeper (for _*.extracted/ subdirs)
                try:
                    for child in os.scandir(entry.path):
                        if not child.is_dir(follow_symlinks=False):
                            continue
                        child_real = os.path.realpath(child.path)
                        if child_real == rootfs_real:
                            continue
                        if _ROOT_DIR_PATTERN.match(child.name):
                            # Use child.name as the virtual name (may collide;
                            # prefer the one with more content)
                            if child.name not in vmap:
                                vmap[child.name] = child.path
                except OSError:
                    continue

        self._virtual_map = vmap
        return vmap

    def _resolve(self, path: str) -> str:
        """Map a virtual path to a real filesystem path and validate it."""
        if self.extraction_dir is None:
            return validate_path(self.extracted_root, path)

        clean = path.strip("/")

        # Virtual /rootfs/... → extracted_root/...
        if clean == self.ROOTFS_VNAME or clean.startswith(self.ROOTFS_VNAME + "/"):
            sub = clean[len(self.ROOTFS_VNAME):]  # e.g. "" or "/etc/passwd"
            return validate_path(self.extracted_root, sub or "/")

        # Check virtual map for nested root dirs
        vmap = self._build_virtual_map()
        parts = clean.split("/", 1)
        top_name = parts[0]
        if top_name in vmap:
            base_path = vmap[top_name]
            sub = "/" + parts[1] if len(parts) > 1 else "/"
            return validate_path(base_path, sub)

        # Everything else → extraction_dir/...
        return validate_path(self.extraction_dir, path)

    # Back-compat alias used by some callers
    def _validate(self, path: str) -> str:
        return self._resolve(path)

    # ── virtual top-level listing ────────────────────────────────────

    def _list_virtual_root(self) -> tuple[list[FileEntry], bool]:
        """Build the virtual top-level listing from the extraction directory.

        Shows:
        - ``rootfs/`` — the primary Linux filesystem (always first)
        - Other extracted partition directories (``*-root``, ``*-root-N``)
          with deduplication: when both ``foo-root`` and ``foo-root-0..N``
          exist, only ``foo-root`` is shown
        - Large raw files (>100KB) that aren't filesystem images
        """
        assert self.extraction_dir is not None

        entries: list[FileEntry] = []

        # 1. "rootfs/" — always first
        try:
            st = os.lstat(self.extracted_root)
            entries.append(FileEntry(
                name=self.ROOTFS_VNAME,
                type="directory",
                size=st.st_size,
                permissions=_format_permissions(st.st_mode),
            ))
        except OSError:
            pass

        # 2. Collect root dirs from the virtual map (handles nested extraction)
        vmap = self._build_virtual_map()

        # Group by base name for deduplication
        # candidates[base] = [(name, real_path, file_count, is_numbered), ...]
        root_candidates: dict[str, list[tuple[str, str, int, bool]]] = {}
        for vname, real_path in vmap.items():
            try:
                file_count = sum(1 for _ in os.scandir(real_path))
            except OSError:
                file_count = 0
            if file_count == 0:
                continue

            base_m = re.match(r"^(.+-root)(-\d+)?$", vname)
            if not base_m:
                continue
            base = base_m.group(1)
            is_numbered = base_m.group(2) is not None
            root_candidates.setdefault(base, []).append(
                (vname, real_path, file_count, is_numbered)
            )

        # Pick the best representative for each base name
        for base, candidates in root_candidates.items():
            unnumbered = [c for c in candidates if not c[3]]
            if unnumbered:
                best_name, best_path = unnumbered[0][0], unnumbered[0][1]
            else:
                best = max(candidates, key=lambda c: c[2])
                best_name, best_path = best[0], best[1]

            try:
                st = os.lstat(best_path)
            except OSError:
                continue
            entries.append(FileEntry(
                name=best_name,
                type="directory",
                size=st.st_size,
                permissions=_format_permissions(st.st_mode),
            ))

        # 3. Large raw files (kernel images, compressed archives, etc.)
        try:
            dir_entries = sorted(os.scandir(self.extraction_dir), key=lambda e: e.name)
        except OSError:
            dir_entries = []

        for entry in dir_entries:
            if not entry.is_file(follow_symlinks=False):
                continue
            try:
                st = os.lstat(entry.path)
            except OSError:
                continue
            if st.st_size < _MIN_RAW_FILE_SIZE:
                continue
            name_lower = entry.name.lower()
            _, ext = os.path.splitext(name_lower)
            if ext in _RAW_FS_EXTENSIONS:
                continue
            if _is_shared_lib(name_lower):
                continue
            entries.append(FileEntry(
                name=entry.name,
                type="file",
                size=st.st_size,
                permissions=_format_permissions(st.st_mode),
            ))

        # Sort: rootfs first, then directories, then files alphabetically
        def sort_key(e: FileEntry) -> tuple[int, int, str]:
            is_rootfs = 0 if e.name == self.ROOTFS_VNAME else 1
            is_dir = 0 if e.type == "directory" else 1
            return (is_rootfs, is_dir, e.name)

        entries.sort(key=sort_key)
        return entries, False

    # ── public API ───────────────────────────────────────────────────

    def list_directory(self, path: str = "/") -> tuple[list[FileEntry], bool]:
        """List directory contents. Returns (entries, truncated)."""
        # Virtual top-level when extraction_dir is set
        if self.extraction_dir and path.strip("/") == "":
            return self._list_virtual_root()

        full_path = self._resolve(path)

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
                is_broken = False
                if stat.S_ISLNK(st.st_mode):
                    try:
                        symlink_target = os.readlink(entry_path)
                    except OSError:
                        pass
                    # Broken symlink: target does not exist
                    if not os.path.exists(entry_path):
                        is_broken = True
                entries.append(
                    FileEntry(
                        name=name,
                        type=file_type,
                        size=st.st_size,
                        permissions=_format_permissions(st.st_mode),
                        symlink_target=symlink_target,
                        broken=is_broken,
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

        try:
            file_size = os.path.getsize(full_path)
        except PermissionError:
            raise PermissionError(f"Permission denied: {path}")

        read_length = min(length or MAX_READ_SIZE, MAX_READ_SIZE)

        try:
            with open(full_path, "rb") as f:
                f.seek(offset)
                data = f.read(read_length)
        except PermissionError:
            raise PermissionError(f"Permission denied: {path}")

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
        except PermissionError:
            raise PermissionError(f"Permission denied: {path}")
        except Exception:
            mime_type = "application/octet-stream"

        # SHA256 for regular files
        sha256 = None
        if stat.S_ISREG(st.st_mode):
            try:
                h = hashlib.sha256()
                with open(full_path, "rb") as f:
                    for chunk in iter(lambda: f.read(8192), b""):
                        h.update(chunk)
                sha256 = h.hexdigest()
            except PermissionError:
                raise PermissionError(f"Permission denied: {path}")

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
        full_path = self._resolve(path)

        # Determine the prefix to use for relative paths
        if self.extraction_dir:
            clean = path.strip("/")
            if clean == "" or clean == self.ROOTFS_VNAME or clean.startswith(self.ROOTFS_VNAME + "/"):
                real_root = os.path.realpath(self.extracted_root)
                prefix = f"/{self.ROOTFS_VNAME}"
            else:
                real_root = os.path.realpath(self.extraction_dir)
                prefix = ""
        else:
            real_root = os.path.realpath(self.extracted_root)
            prefix = ""

        matches = []
        truncated = False

        for root, dirs, files in safe_walk(full_path):
            for name in files + dirs:
                if fnmatch.fnmatch(name, pattern):
                    abs_path = os.path.join(root, name)
                    # Return path relative to the appropriate root
                    rel_path = prefix + "/" + os.path.relpath(abs_path, real_root)
                    matches.append(rel_path)
                    if len(matches) >= MAX_SEARCH_RESULTS:
                        truncated = True
                        break
            if truncated:
                break

        return matches, truncated
