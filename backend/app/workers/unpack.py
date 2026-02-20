import asyncio
import glob
import os
from dataclasses import dataclass, field

from elftools.elf.elffile import ELFFile


@dataclass
class UnpackResult:
    extracted_path: str | None = None
    architecture: str | None = None
    endianness: str | None = None
    os_info: str | None = None
    kernel_path: str | None = None
    unpack_log: str = ""
    success: bool = False
    error: str | None = None


# Map ELF machine types to friendly names
_ELF_ARCH_MAP = {
    "EM_MIPS": "mips",
    "EM_ARM": "arm",
    "EM_AARCH64": "aarch64",
    "EM_386": "x86",
    "EM_X86_64": "x86_64",
    "EM_PPC": "ppc",
    "EM_PPC64": "ppc64",
    "EM_SH": "sh",
    "EM_SPARC": "sparc",
}


async def run_binwalk_extraction(firmware_path: str, output_dir: str, timeout: int = 600) -> str:
    """Run binwalk -e to extract firmware contents. Returns stdout+stderr."""
    proc = await asyncio.create_subprocess_exec(
        "binwalk", "-e", "-C", output_dir, firmware_path,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
    )
    try:
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        raise TimeoutError(f"binwalk extraction timed out after {timeout}s")

    return stdout.decode(errors="replace").replace("\x00", "")


def find_filesystem_root(extraction_dir: str) -> str | None:
    """Find the extracted filesystem root by looking for Linux directory markers."""
    # Walk all subdirectories looking for one that has /etc and (/usr or /bin)
    for root, dirs, _files in os.walk(extraction_dir):
        # os.walk() only lists real directories in `dirs`, not symlinks.
        # Firmware often has standard dirs as symlinks (e.g. /etc -> /dev/null,
        # /bin -> /usr/bin for merged-usr), so use listdir to see everything.
        all_entries = set(os.listdir(root))

        has_etc = "etc" in all_entries or "etc_ro" in all_entries
        has_usr_or_bin = "usr" in all_entries or "bin" in all_entries
        if has_etc and has_usr_or_bin:
            return root

    # Fallback: find largest directory by entry count
    best_dir = None
    best_count = 0
    for root, dirs, files in os.walk(extraction_dir):
        count = len(dirs) + len(files)
        if count > best_count:
            best_count = count
            best_dir = root

    return best_dir


def detect_architecture(fs_root: str) -> tuple[str | None, str | None]:
    """Detect architecture and endianness by examining ELF binaries.

    Uses majority voting across all ELF binaries found in common directories
    to handle mixed-architecture filesystems (e.g., ARM firmware with x86-64
    systemd from a host layer).
    """
    from collections import Counter

    # Look for ELF binaries in common dirs
    search_dirs = ["bin", "usr/bin", "sbin", "usr/sbin", "lib"]
    votes: Counter[tuple[str, str]] = Counter()
    max_scan = 50  # Cap scanning to avoid slowness on huge filesystems

    for search_dir in search_dirs:
        search_path = os.path.join(fs_root, search_dir)
        if not os.path.isdir(search_path):
            continue

        try:
            entries = os.listdir(search_path)
        except OSError:
            continue

        for entry in entries:
            if sum(votes.values()) >= max_scan:
                break

            full_path = os.path.join(search_path, entry)
            if not os.path.isfile(full_path):
                continue
            try:
                with open(full_path, "rb") as f:
                    magic = f.read(4)
                    if magic != b"\x7fELF":
                        continue
                    f.seek(0)
                    elf = ELFFile(f)
                    arch = _ELF_ARCH_MAP.get(elf.header.e_machine, elf.header.e_machine)
                    endianness = "little" if elf.little_endian else "big"

                    # For MIPS, distinguish mips vs mipsel
                    if arch == "mips" and endianness == "little":
                        arch = "mipsel"

                    votes[(arch, endianness)] += 1
            except Exception:
                continue

    if not votes:
        return None, None

    # Return the most common architecture
    (arch, endianness), _count = votes.most_common(1)[0]
    return arch, endianness


def detect_os_info(fs_root: str) -> str | None:
    """Read OS info from standard release files."""
    release_files = [
        "etc/os-release",
        "etc/openwrt_release",
        "etc/lsb-release",
        "etc/version",
        "etc/issue",
    ]
    for rel_file in release_files:
        full_path = os.path.join(fs_root, rel_file)
        if os.path.isfile(full_path):
            try:
                with open(full_path) as f:
                    content = f.read(1024)
                # Strip null bytes — firmware may have zeroed-out placeholder files
                content = content.replace("\x00", "").strip()
                if content:
                    return content
            except Exception:
                continue
    return None


def _read_magic(path: str, num_bytes: int = 4) -> bytes:
    """Read the first N bytes of a file for magic number detection."""
    try:
        with open(path, "rb") as f:
            return f.read(num_bytes)
    except OSError:
        return b""


# Known filesystem root directory names produced by binwalk extraction
_FS_ROOT_NAMES = frozenset({
    "ext-root", "squash-root", "squashfs-root", "ubifs-root",
    "cpio-root", "jffs2-root", "cramfs-root", "romfs-root",
})

# Filename patterns that strongly indicate a kernel image
_KERNEL_NAME_PATTERNS = ("vmlinux", "zimage", "uimage", "bzimage")

# File extensions for filesystem images — NOT kernels
_FS_IMAGE_EXTENSIONS = frozenset({
    ".ext", ".ext2", ".ext3", ".ext4",
    ".yaffs", ".yaffs2",
    ".jffs2",
    ".squashfs", ".sqfs",
    ".cramfs",
    ".ubifs", ".ubi",
    ".romfs",
    ".cpio",
})


def detect_kernel(extraction_dir: str, fs_root: str | None) -> str | None:
    """Scan the extraction directory for a kernel image.

    Kernels extracted by binwalk appear as siblings to the filesystem root
    in the .extracted/ directory — they are NOT inside the filesystem.

    Returns the absolute path to the best kernel candidate, or None.
    """
    # The parent of the filesystem root is the binwalk extraction output dir
    # (e.g., /data/.../extracted/_firmware.img.extracted/)
    if fs_root:
        scan_dir = os.path.dirname(fs_root)
    else:
        # No filesystem root found — scan all .extracted/ subdirectories
        scan_dir = extraction_dir

    if not os.path.isdir(scan_dir):
        return None

    candidates: list[tuple[str, int]] = []  # (path, priority)

    for entry in os.scandir(scan_dir):
        if not entry.is_file(follow_symlinks=False):
            continue

        name_lower = entry.name.lower()

        # Skip filesystem images and known roots
        if name_lower in _FS_ROOT_NAMES:
            continue
        # Skip JSON sidecar files and very small files
        if name_lower.endswith(".json") or name_lower.endswith(".txt"):
            continue
        # Skip filesystem image files (ext2, yaffs, jffs2, etc.)
        _, ext = os.path.splitext(name_lower)
        if ext in _FS_IMAGE_EXTENSIONS:
            continue

        try:
            file_size = entry.stat().st_size
        except OSError:
            continue

        # Kernels are typically > 500 KB
        if file_size < 500_000:
            continue

        # 1) Check filename patterns (highest priority)
        if any(p in name_lower for p in _KERNEL_NAME_PATTERNS):
            candidates.append((entry.path, 100))
            continue

        # 2) Check magic bytes
        magic = _read_magic(entry.path, 4)

        # ELF binary — could be an uncompressed vmlinux
        if magic == b"\x7fELF":
            # Verify it's an executable (not a shared library from extraction)
            try:
                with open(entry.path, "rb") as f:
                    elf = ELFFile(f)
                    # Kernel ELFs are ET_EXEC (type 2) and very large
                    if elf.header.e_type == "ET_EXEC" and file_size > 1_000_000:
                        candidates.append((entry.path, 95))
                        continue
            except Exception:
                pass

        # U-Boot uImage header
        if magic == b"\x27\x05\x19\x56":
            candidates.append((entry.path, 90))
            continue

        # ARM Linux zImage magic at offset 0x24: 0x016f2818
        if file_size > 1_000_000:
            try:
                with open(entry.path, "rb") as f:
                    f.seek(0x24)
                    arm_magic = f.read(4)
                    if arm_magic == b"\x18\x28\x6f\x01":
                        candidates.append((entry.path, 92))
                        continue
            except OSError:
                pass

        # gzip-compressed (possibly compressed kernel)
        if magic[:2] == b"\x1f\x8b" and file_size > 1_000_000:
            candidates.append((entry.path, 70))
            continue

        # LZMA-compressed
        if magic[:3] == b"\x5d\x00\x00" and file_size > 1_000_000:
            candidates.append((entry.path, 70))
            continue

    if not candidates:
        return None

    # Return highest-priority candidate
    candidates.sort(key=lambda x: x[1], reverse=True)
    return candidates[0][0]


async def unpack_firmware(firmware_path: str, output_base_dir: str) -> UnpackResult:
    """Orchestrate the full unpacking pipeline."""
    result = UnpackResult()

    # Step 1: Run binwalk extraction
    try:
        extraction_dir = os.path.join(output_base_dir, "extracted")
        os.makedirs(extraction_dir, exist_ok=True)
        result.unpack_log = await run_binwalk_extraction(firmware_path, extraction_dir)
    except TimeoutError as e:
        result.error = str(e)
        result.unpack_log = str(e)
        return result
    except Exception as e:
        result.error = f"Extraction failed: {e}"
        result.unpack_log = str(e)
        return result

    # Step 2: Find the filesystem root
    fs_root = find_filesystem_root(extraction_dir)
    if not fs_root:
        result.error = "Could not locate filesystem root in extracted contents"
        return result
    result.extracted_path = fs_root

    # Step 3: Detect architecture
    arch, endian = detect_architecture(fs_root)
    result.architecture = arch
    result.endianness = endian

    # Step 4: Detect OS info
    result.os_info = detect_os_info(fs_root)

    # Step 5: Detect kernel image
    result.kernel_path = detect_kernel(extraction_dir, fs_root)

    result.success = True
    return result
