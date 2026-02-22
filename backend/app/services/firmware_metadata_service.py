"""Service for extracting metadata from raw firmware images.

Parses partition layout (via binwalk scan), U-Boot headers and environment
variables, and MTD partition tables from firmware binary images.
"""

import asyncio
import csv
import io
import os
import re
import struct
import uuid
from dataclasses import asdict, dataclass, field

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.analysis_cache import AnalysisCache


@dataclass
class FirmwareSection:
    """A section/partition identified in the firmware image."""

    offset: int
    size: int | None  # None if unknown (last section or binwalk can't determine)
    type: str  # e.g. "SquashFS filesystem", "LZMA compressed data"
    description: str


@dataclass
class UBootHeader:
    """Parsed U-Boot uImage header (64 bytes)."""

    magic: str
    header_crc: str
    timestamp: int
    data_size: int
    load_address: str
    entry_point: str
    data_crc: str
    os_type: str
    architecture: str
    image_type: str
    compression: str
    name: str


@dataclass
class MTDPartition:
    """A partition from an MTD partition table string."""

    name: str
    offset: int | None
    size: int


@dataclass
class FirmwareImageMetadata:
    """Complete metadata extracted from a firmware image."""

    file_size: int
    sections: list[FirmwareSection] = field(default_factory=list)
    uboot_header: UBootHeader | None = None
    uboot_env: dict[str, str] = field(default_factory=dict)
    mtd_partitions: list[MTDPartition] = field(default_factory=list)


# U-Boot uImage magic number
UBOOT_MAGIC = 0x27051956

# U-Boot OS type mapping
UBOOT_OS_TYPES = {
    0: "Invalid", 1: "OpenBSD", 2: "NetBSD", 3: "FreeBSD",
    4: "4.4BSD", 5: "Linux", 6: "SVR4", 7: "Esix",
    8: "Solaris", 9: "Irix", 10: "SCO", 11: "Dell",
    12: "NCR", 13: "LynxOS", 14: "VxWorks", 15: "pSOS",
    16: "QNX", 17: "U-Boot", 18: "RTEMS", 19: "ARTOS",
    20: "Unity", 21: "INTEGRITY",
}

# U-Boot architecture mapping
UBOOT_ARCH_TYPES = {
    0: "Invalid", 1: "Alpha", 2: "ARM", 3: "x86",
    4: "IA64", 5: "MIPS", 6: "MIPS64", 7: "PowerPC",
    8: "S390", 9: "SuperH", 10: "SPARC", 11: "SPARC64",
    12: "M68K", 13: "MicroBlaze", 14: "Nios-II", 15: "Blackfin",
    16: "AVR32", 17: "ST200", 18: "Sandbox", 19: "NDS32",
    20: "OpenRISC", 21: "ARM64", 22: "ARC", 23: "x86_64",
    24: "Xtensa", 25: "RISC-V",
}

# U-Boot image type mapping
UBOOT_IMAGE_TYPES = {
    0: "Invalid", 1: "Standalone", 2: "Kernel", 3: "RAMDisk",
    4: "Multi-File", 5: "Firmware", 6: "Script", 7: "Filesystem",
    8: "Flat DT Blob",
}

# U-Boot compression type mapping
UBOOT_COMPRESSION_TYPES = {
    0: "none", 1: "gzip", 2: "bzip2", 3: "lzma",
    4: "lzo", 5: "lz4", 6: "zstd",
}

# Common U-Boot env variable prefixes for detection
UBOOT_ENV_PATTERNS = [
    b"bootcmd=", b"bootargs=", b"bootdelay=", b"baudrate=",
    b"ethaddr=", b"ipaddr=", b"serverip=", b"netmask=",
    b"gatewayip=", b"stdin=", b"stdout=", b"stderr=",
    b"mtdparts=", b"partition=", b"loadaddr=",
]


class FirmwareMetadataService:
    """Extracts structural metadata from raw firmware images."""

    async def scan_firmware_image(
        self,
        firmware_storage_path: str,
        firmware_id: uuid.UUID,
        db: AsyncSession,
    ) -> FirmwareImageMetadata:
        """Orchestrate all firmware metadata parsing.

        Checks cache first. If not cached, runs binwalk scan, U-Boot header/env
        parsing, and MTD partition detection. Caches the result.
        """
        # Check cache
        stmt = select(AnalysisCache).where(
            AnalysisCache.firmware_id == firmware_id,
            AnalysisCache.operation == "firmware_metadata",
        )
        result = await db.execute(stmt)
        cached = result.scalar_one_or_none()
        if cached and cached.result:
            return self._from_cache(cached.result)

        # Parse the firmware image
        file_size = os.path.getsize(firmware_storage_path)
        sections = await self._run_binwalk_scan(firmware_storage_path)
        uboot_header = self._detect_uboot_header(firmware_storage_path)
        uboot_env = self._extract_uboot_env(firmware_storage_path)
        mtd_partitions = self._parse_mtd_partitions(firmware_storage_path)

        metadata = FirmwareImageMetadata(
            file_size=file_size,
            sections=sections,
            uboot_header=uboot_header,
            uboot_env=uboot_env,
            mtd_partitions=mtd_partitions,
        )

        # Cache the result
        cache_entry = AnalysisCache(
            firmware_id=firmware_id,
            operation="firmware_metadata",
            result=self._to_cache(metadata),
        )
        db.add(cache_entry)
        await db.flush()

        return metadata

    async def _run_binwalk_scan(self, path: str) -> list[FirmwareSection]:
        """Run binwalk in scan-only CSV mode and parse the output."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "binwalk", "--csv", path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=120)
        except FileNotFoundError:
            return []
        except asyncio.TimeoutError:
            proc.kill()
            return []

        if proc.returncode != 0:
            return []

        output = stdout.decode("utf-8", errors="replace")
        sections: list[FirmwareSection] = []

        # binwalk --csv outputs lines like:
        # DECIMAL       HEXADECIMAL     DESCRIPTION
        # 0             0x0             uImage header...
        # Skip header lines and parse
        lines = output.strip().split("\n")
        csv_lines = []
        in_csv = False
        for line in lines:
            if line.startswith("DECIMAL"):
                in_csv = True
                continue
            if in_csv and line.strip():
                csv_lines.append(line)

        for line in csv_lines:
            # Parse: DECIMAL,HEXADECIMAL,DESCRIPTION
            parts = line.split(",", 2)
            if len(parts) < 3:
                # Fallback: try whitespace-separated
                parts = line.split(None, 2)
            if len(parts) < 3:
                continue
            try:
                offset = int(parts[0].strip())
            except ValueError:
                continue
            description = parts[2].strip() if len(parts) > 2 else parts[1].strip()

            # Extract type from description (first part before comma or details)
            section_type = description.split(",")[0].strip()

            sections.append(FirmwareSection(
                offset=offset,
                size=None,  # Will be computed below
                type=section_type,
                description=description,
            ))

        # Compute sizes from offsets (each section runs until the next one)
        file_size = os.path.getsize(path)
        for i, section in enumerate(sections):
            if i + 1 < len(sections):
                section.size = sections[i + 1].offset - section.offset
            else:
                section.size = file_size - section.offset

        return sections

    def _detect_uboot_header(self, path: str) -> UBootHeader | None:
        """Check for U-Boot uImage header at the start of the file."""
        try:
            with open(path, "rb") as f:
                header_bytes = f.read(64)
        except OSError:
            return None

        if len(header_bytes) < 64:
            return None

        # Check magic number (big-endian)
        magic = struct.unpack(">I", header_bytes[0:4])[0]
        if magic != UBOOT_MAGIC:
            # Also scan first 256KB for the magic (it might not be at offset 0)
            try:
                with open(path, "rb") as f:
                    data = f.read(256 * 1024)
                idx = data.find(struct.pack(">I", UBOOT_MAGIC))
                if idx < 0:
                    return None
                header_bytes = data[idx:idx + 64]
                if len(header_bytes) < 64:
                    return None
            except OSError:
                return None

        # Parse the 64-byte uImage header (all big-endian)
        (
            ih_magic, ih_hcrc, ih_time, ih_size,
            ih_load, ih_ep, ih_dcrc, ih_os,
            ih_arch, ih_type, ih_comp,
        ) = struct.unpack(">IIIIIIIBBBB", header_bytes[0:28])

        ih_name = header_bytes[32:64].split(b"\x00", 1)[0].decode("ascii", errors="replace")

        return UBootHeader(
            magic=f"0x{ih_magic:08X}",
            header_crc=f"0x{ih_hcrc:08X}",
            timestamp=ih_time,
            data_size=ih_size,
            load_address=f"0x{ih_load:08X}",
            entry_point=f"0x{ih_ep:08X}",
            data_crc=f"0x{ih_dcrc:08X}",
            os_type=UBOOT_OS_TYPES.get(ih_os, f"Unknown ({ih_os})"),
            architecture=UBOOT_ARCH_TYPES.get(ih_arch, f"Unknown ({ih_arch})"),
            image_type=UBOOT_IMAGE_TYPES.get(ih_type, f"Unknown ({ih_type})"),
            compression=UBOOT_COMPRESSION_TYPES.get(ih_comp, f"Unknown ({ih_comp})"),
            name=ih_name,
        )

    def _extract_uboot_env(self, path: str) -> dict[str, str]:
        """Scan firmware for U-Boot environment variable block.

        U-Boot env is typically a block of null-terminated key=value strings
        preceded by a 4-byte CRC and a 1-byte flags field (sometimes).
        """
        try:
            with open(path, "rb") as f:
                data = f.read()
        except OSError:
            return {}

        env_vars: dict[str, str] = {}

        # Search for common U-Boot env patterns to find the env block
        best_offset = -1
        best_count = 0
        for pattern in UBOOT_ENV_PATTERNS:
            idx = 0
            while True:
                idx = data.find(pattern, idx)
                if idx < 0:
                    break
                # Count how many env patterns are near this location (within 4KB)
                count = 0
                for p2 in UBOOT_ENV_PATTERNS:
                    pos = data.find(p2, max(0, idx - 512), idx + 4096)
                    if pos >= 0:
                        count += 1
                if count > best_count:
                    best_count = count
                    best_offset = idx
                idx += 1

        if best_offset < 0 or best_count < 3:
            return {}

        # Back up to find the start of the env block
        # U-Boot env starts with a 4-byte CRC (optionally + 1 byte flags)
        # then the key=value\0 pairs begin
        # Search backward for the CRC/start boundary (look for non-printable bytes)
        start = best_offset
        for offset in range(best_offset, max(0, best_offset - 256), -1):
            byte = data[offset]
            if byte == 0 or (byte < 0x20 and byte not in (0x0A, 0x0D)):
                start = offset + 1
                break

        # Parse null-terminated key=value pairs
        end = min(start + 65536, len(data))  # U-Boot env is typically ≤64KB
        pos = start
        while pos < end:
            # Find the end of this string (null terminator)
            null_pos = data.find(b"\x00", pos, end)
            if null_pos < 0:
                break
            if null_pos == pos:
                break  # Double null = end of env block

            entry = data[pos:null_pos]
            try:
                entry_str = entry.decode("ascii")
            except UnicodeDecodeError:
                pos = null_pos + 1
                continue

            if "=" in entry_str:
                key, _, value = entry_str.partition("=")
                # Basic validation: key should be alphanumeric/underscore
                if re.match(r"^[a-zA-Z_][a-zA-Z0-9_]*$", key):
                    env_vars[key] = value
            pos = null_pos + 1

        return env_vars

    def _parse_mtd_partitions(self, path: str) -> list[MTDPartition]:
        """Search firmware for mtdparts= string and parse partition definitions.

        Format: mtdparts=<mtddef>[;<mtddef>...]
        mtddef: <mtd-id>:<partdef>[,<partdef>...]
        partdef: <size>[@<offset>](<name>)[ro]
        """
        try:
            with open(path, "rb") as f:
                data = f.read()
        except OSError:
            return []

        # Search for mtdparts= string
        idx = data.find(b"mtdparts=")
        if idx < 0:
            return []

        # Extract the mtdparts string (up to null terminator or newline)
        end = idx + 9  # skip "mtdparts="
        while end < len(data) and end < idx + 2048:
            if data[end] in (0, 0x0A, 0x0D):
                break
            end += 1

        try:
            mtdparts_str = data[idx + 9:end].decode("ascii", errors="replace")
        except Exception:
            return []

        partitions: list[MTDPartition] = []

        # Split by ; for multiple MTD devices
        for mtddef in mtdparts_str.split(";"):
            # Remove mtd-id prefix (everything before first ':')
            if ":" in mtddef:
                _, _, partdefs = mtddef.partition(":")
            else:
                partdefs = mtddef

            # Parse each partition definition
            for partdef in partdefs.split(","):
                partdef = partdef.strip()
                if not partdef:
                    continue

                # Match: <size>[@<offset>](<name>)
                m = re.match(
                    r"([0-9a-fA-Fx]+[kKmMgG]?)(?:@([0-9a-fA-Fx]+[kKmMgG]?))?\(([^)]+)\)",
                    partdef,
                )
                if not m:
                    # Try: -(<name>) for "rest of device"
                    m2 = re.match(r"-\(([^)]+)\)", partdef)
                    if m2:
                        partitions.append(MTDPartition(
                            name=m2.group(1),
                            offset=None,
                            size=0,  # 0 means "rest of device"
                        ))
                    continue

                size_str = m.group(1)
                offset_str = m.group(2)
                name = m.group(3)

                size = self._parse_size(size_str)
                offset = self._parse_size(offset_str) if offset_str else None

                partitions.append(MTDPartition(
                    name=name,
                    offset=offset,
                    size=size,
                ))

        return partitions

    @staticmethod
    def _parse_size(s: str) -> int:
        """Parse a size string like '0x40000', '256k', '4m' into bytes."""
        s = s.strip()
        if not s:
            return 0

        multiplier = 1
        if s[-1].lower() == "k":
            multiplier = 1024
            s = s[:-1]
        elif s[-1].lower() == "m":
            multiplier = 1024 * 1024
            s = s[:-1]
        elif s[-1].lower() == "g":
            multiplier = 1024 * 1024 * 1024
            s = s[:-1]

        if s.startswith("0x") or s.startswith("0X"):
            return int(s, 16) * multiplier
        return int(s) * multiplier

    def _to_cache(self, metadata: FirmwareImageMetadata) -> dict:
        """Serialize metadata to JSON-compatible dict for caching."""
        return {
            "file_size": metadata.file_size,
            "sections": [asdict(s) for s in metadata.sections],
            "uboot_header": asdict(metadata.uboot_header) if metadata.uboot_header else None,
            "uboot_env": metadata.uboot_env,
            "mtd_partitions": [asdict(p) for p in metadata.mtd_partitions],
        }

    def _from_cache(self, data: dict) -> FirmwareImageMetadata:
        """Deserialize cached metadata."""
        return FirmwareImageMetadata(
            file_size=data["file_size"],
            sections=[FirmwareSection(**s) for s in data.get("sections", [])],
            uboot_header=UBootHeader(**data["uboot_header"]) if data.get("uboot_header") else None,
            uboot_env=data.get("uboot_env", {}),
            mtd_partitions=[MTDPartition(**p) for p in data.get("mtd_partitions", [])],
        )
