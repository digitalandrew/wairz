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


async def run_binwalk_extraction(firmware_path: str, output_dir: str, timeout: int = 300) -> str:
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
        has_etc = "etc" in dirs
        has_usr_or_bin = "usr" in dirs or "bin" in dirs
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
    """Detect architecture and endianness by examining ELF binaries."""
    # Look for ELF binaries in common dirs
    search_dirs = ["bin", "usr/bin", "sbin", "usr/sbin", "lib"]
    for search_dir in search_dirs:
        search_path = os.path.join(fs_root, search_dir)
        if not os.path.isdir(search_path):
            continue

        for entry in os.listdir(search_path):
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

                    return arch, endianness
            except Exception:
                continue

    return None, None


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

    result.success = True
    return result
