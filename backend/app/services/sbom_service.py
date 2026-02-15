"""SBOM service — identifies software components from unpacked firmware.

Walks the extracted filesystem, parses package databases, scans libraries
and binaries for version information, and returns a deduplicated list of
identified components with CPE and PURL identifiers.
"""

import os
import re
from dataclasses import dataclass, field

from elftools.elf.elffile import ELFFile

from app.utils.sandbox import validate_path

MAX_BINARIES_SCAN = 100
MAX_BINARY_READ = 64 * 1024  # 64KB for strings extraction

# Well-known vendor:product mappings for CPE construction
CPE_VENDOR_MAP: dict[str, tuple[str, str]] = {
    "busybox": ("busybox", "busybox"),
    "openssl": ("openssl", "openssl"),
    "libssl": ("openssl", "openssl"),
    "libcrypto": ("openssl", "openssl"),
    "dropbear": ("matt_johnston", "dropbear"),
    "dnsmasq": ("thekelleys", "dnsmasq"),
    "lighttpd": ("lighttpd", "lighttpd"),
    "curl": ("haxx", "curl"),
    "libcurl": ("haxx", "curl"),
    "wget": ("gnu", "wget"),
    "openssh": ("openbsd", "openssh"),
    "iptables": ("netfilter", "iptables"),
    "hostapd": ("w1.fi", "hostapd"),
    "wpa_supplicant": ("w1.fi", "wpa_supplicant"),
    "samba": ("samba", "samba"),
    "nginx": ("f5", "nginx"),
    "apache": ("apache", "http_server"),
    "httpd": ("apache", "http_server"),
    "mini_httpd": ("acme", "mini_httpd"),
    "uboot": ("denx", "u-boot"),
    "u-boot": ("denx", "u-boot"),
    "syslog-ng": ("balabit", "syslog-ng"),
    "zlib": ("zlib", "zlib"),
    "sqlite": ("sqlite", "sqlite"),
    "libjpeg": ("ijg", "libjpeg"),
    "libpng": ("libpng", "libpng"),
    "lua": ("lua", "lua"),
    "perl": ("perl", "perl"),
    "python": ("python", "python"),
    "bash": ("gnu", "bash"),
    "glibc": ("gnu", "glibc"),
    "libc": ("gnu", "glibc"),
    "uclibc": ("uclibc", "uclibc"),
    "musl": ("musl-libc", "musl"),
    "avahi": ("avahi", "avahi"),
    "miniupnpd": ("miniupnp_project", "miniupnpd"),
    "proftpd": ("proftpd", "proftpd"),
    "vsftpd": ("beasts", "vsftpd"),
    "ntpd": ("ntp", "ntp"),
    "netatalk": ("netatalk", "netatalk"),
    "mosquitto": ("eclipse", "mosquitto"),
}

# Regex patterns for binary version string extraction
VERSION_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("busybox", re.compile(rb"BusyBox v(\d+\.\d+(?:\.\d+)?)")),
    ("openssh", re.compile(rb"OpenSSH[_ ](\d+\.\d+(?:p\d+)?)")),
    ("dropbear", re.compile(rb"dropbear[_ ](\d+\.\d+(?:\.\d+)?)")),
    ("lighttpd", re.compile(rb"lighttpd/(\d+\.\d+\.\d+)")),
    ("dnsmasq", re.compile(rb"dnsmasq-(\d+\.\d+(?:\.\d+)?)")),
    ("curl", re.compile(rb"curl/(\d+\.\d+\.\d+)")),
    ("wget", re.compile(rb"GNU Wget (\d+\.\d+(?:\.\d+)?)")),
    ("nginx", re.compile(rb"nginx/(\d+\.\d+\.\d+)")),
    ("openssl", re.compile(rb"OpenSSL (\d+\.\d+\.\d+[a-z]*)")),
    ("samba", re.compile(rb"Samba (\d+\.\d+\.\d+)")),
    ("hostapd", re.compile(rb"hostapd v(\d+\.\d+(?:\.\d+)?)")),
    ("wpa_supplicant", re.compile(rb"wpa_supplicant v(\d+\.\d+(?:\.\d+)?)")),
    ("miniupnpd", re.compile(rb"miniupnpd[/ ](\d+\.\d+(?:\.\d+)?)")),
    ("proftpd", re.compile(rb"ProFTPD (\d+\.\d+\.\d+)")),
    ("vsftpd", re.compile(rb"vsftpd: version (\d+\.\d+\.\d+)")),
    ("avahi", re.compile(rb"avahi-daemon (\d+\.\d+\.\d+)")),
    ("ntpd", re.compile(rb"ntpd (\d+\.\d+\.\d+(?:p\d+)?)")),
    ("mini_httpd", re.compile(rb"mini_httpd/(\d+\.\d+(?:\.\d+)?)")),
    ("lua", re.compile(rb"Lua (\d+\.\d+\.\d+)")),
    ("sqlite", re.compile(rb"SQLite (\d+\.\d+\.\d+)")),
]

# Library SONAME -> component name mapping for well-known libraries
SONAME_COMPONENT_MAP: dict[str, str] = {
    "libssl": "openssl",
    "libcrypto": "openssl",
    "libcurl": "curl",
    "libz": "zlib",
    "libsqlite3": "sqlite",
    "libpng": "libpng",
    "libpng16": "libpng",
    "libjpeg": "libjpeg",
    "liblua": "lua",
    "libavahi-client": "avahi",
    "libavahi-common": "avahi",
    "libubus": "ubus",
    "libubox": "ubox",
    "libuci": "uci",
    "libpthread": "glibc",
    "libdl": "glibc",
    "librt": "glibc",
    "libm": "glibc",
    "libc": "glibc",
    "libgcc_s": "gcc",
    "libstdc++": "gcc",
}


@dataclass
class IdentifiedComponent:
    """A software component identified in the firmware."""
    name: str
    version: str | None
    type: str  # 'application', 'library', 'operating-system'
    cpe: str | None = None
    purl: str | None = None
    supplier: str | None = None
    detection_source: str = ""
    detection_confidence: str = "medium"
    file_paths: list[str] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)


class SbomService:
    """Identifies software components from an unpacked firmware filesystem."""

    def __init__(self, extracted_root: str):
        self.extracted_root = os.path.realpath(extracted_root)
        self._components: dict[tuple[str, str | None], IdentifiedComponent] = {}

    def _validate(self, path: str) -> str:
        return validate_path(self.extracted_root, path)

    def _abs_path(self, rel_path: str) -> str:
        return os.path.join(self.extracted_root, rel_path.lstrip("/"))

    def generate_sbom(self) -> list[dict]:
        """Run all identification strategies and return component list.

        Call from a thread executor (sync, CPU-bound).
        Returns list of dicts ready for DB insertion.
        """
        self._scan_package_managers()
        self._scan_kernel_version()
        self._scan_busybox()
        self._scan_library_sonames()
        self._scan_binary_version_strings()

        results = []
        for comp in self._components.values():
            results.append({
                "name": comp.name,
                "version": comp.version,
                "type": comp.type,
                "cpe": comp.cpe,
                "purl": comp.purl,
                "supplier": comp.supplier,
                "detection_source": comp.detection_source,
                "detection_confidence": comp.detection_confidence,
                "file_paths": comp.file_paths or None,
                "metadata": comp.metadata,
            })

        return results

    def _add_component(self, comp: IdentifiedComponent) -> None:
        """Add or merge a component, preferring higher-confidence detections."""
        key = (comp.name.lower(), comp.version)
        existing = self._components.get(key)

        if existing is None:
            self._components[key] = comp
            return

        confidence_rank = {"high": 3, "medium": 2, "low": 1}
        existing_rank = confidence_rank.get(existing.detection_confidence, 0)
        new_rank = confidence_rank.get(comp.detection_confidence, 0)

        # Merge file paths
        merged_paths = list(set(existing.file_paths + comp.file_paths))

        if new_rank > existing_rank:
            # Replace with higher-confidence data, keep merged paths
            comp.file_paths = merged_paths
            self._components[key] = comp
        else:
            existing.file_paths = merged_paths

    @staticmethod
    def _build_cpe(vendor: str, product: str, version: str | None) -> str | None:
        if not version:
            return None
        # Sanitize version for CPE
        ver = version.strip()
        return f"cpe:2.3:a:{vendor}:{product}:{ver}:*:*:*:*:*:*:*"

    @staticmethod
    def _build_purl(name: str, version: str | None, pkg_type: str = "generic") -> str | None:
        if not version:
            return None
        try:
            from packageurl import PackageURL
            purl = PackageURL(type=pkg_type, name=name, version=version)
            return str(purl)
        except Exception:
            # Fallback: construct manually
            return f"pkg:{pkg_type}/{name}@{version}"

    # ------------------------------------------------------------------
    # Strategy 1: Package manager databases
    # ------------------------------------------------------------------

    def _scan_package_managers(self) -> None:
        """Parse opkg and dpkg status databases."""
        opkg_paths = [
            "/usr/lib/opkg/status",
            "/var/lib/opkg/status",
            "/usr/lib/opkg/info",
        ]
        for rel_path in opkg_paths:
            abs_path = self._abs_path(rel_path)
            if os.path.isfile(abs_path):
                self._parse_opkg_status(abs_path)

        dpkg_path = self._abs_path("/var/lib/dpkg/status")
        if os.path.isfile(dpkg_path):
            self._parse_dpkg_status(dpkg_path)

    def _parse_opkg_status(self, abs_path: str) -> None:
        """Parse an opkg status file (key-value blocks separated by blank lines)."""
        try:
            with open(abs_path, "r", errors="replace") as f:
                content = f.read()
        except OSError:
            return

        blocks = content.split("\n\n")
        for block in blocks:
            if not block.strip():
                continue
            fields = self._parse_control_block(block)
            name = fields.get("package", "").strip()
            version = fields.get("version", "").strip() or None
            if not name:
                continue

            vendor_product = CPE_VENDOR_MAP.get(name.lower())
            cpe = None
            if vendor_product:
                cpe = self._build_cpe(vendor_product[0], vendor_product[1], version)

            comp = IdentifiedComponent(
                name=name,
                version=version,
                type="application",
                cpe=cpe,
                purl=self._build_purl(name, version, "opkg"),
                supplier=vendor_product[0] if vendor_product else None,
                detection_source="package_manager",
                detection_confidence="high",
                file_paths=[],
                metadata={
                    "arch": fields.get("architecture", ""),
                    "description": fields.get("description", ""),
                    "source": "opkg",
                },
            )
            self._add_component(comp)

    def _parse_dpkg_status(self, abs_path: str) -> None:
        """Parse a dpkg status file."""
        try:
            with open(abs_path, "r", errors="replace") as f:
                content = f.read()
        except OSError:
            return

        blocks = content.split("\n\n")
        for block in blocks:
            if not block.strip():
                continue
            fields = self._parse_control_block(block)
            name = fields.get("package", "").strip()
            version = fields.get("version", "").strip() or None
            status = fields.get("status", "")
            if not name:
                continue
            # Only include installed packages
            if "installed" not in status.lower():
                continue

            vendor_product = CPE_VENDOR_MAP.get(name.lower())
            cpe = None
            if vendor_product:
                cpe = self._build_cpe(vendor_product[0], vendor_product[1], version)

            comp = IdentifiedComponent(
                name=name,
                version=version,
                type="application",
                cpe=cpe,
                purl=self._build_purl(name, version, "deb"),
                supplier=vendor_product[0] if vendor_product else None,
                detection_source="package_manager",
                detection_confidence="high",
                file_paths=[],
                metadata={
                    "arch": fields.get("architecture", ""),
                    "description": fields.get("description", ""),
                    "source": "dpkg",
                },
            )
            self._add_component(comp)

    @staticmethod
    def _parse_control_block(block: str) -> dict[str, str]:
        """Parse a Debian-style control file block into a dict."""
        fields: dict[str, str] = {}
        current_key = ""
        current_val = ""
        for line in block.splitlines():
            if line.startswith((" ", "\t")):
                # Continuation line
                current_val += "\n" + line.strip()
            elif ":" in line:
                # Save previous field
                if current_key:
                    fields[current_key.lower()] = current_val
                key, _, val = line.partition(":")
                current_key = key.strip()
                current_val = val.strip()
        if current_key:
            fields[current_key.lower()] = current_val
        return fields

    # ------------------------------------------------------------------
    # Strategy 2: Kernel version
    # ------------------------------------------------------------------

    def _scan_kernel_version(self) -> None:
        """Detect Linux kernel version from modules directory and release files."""
        # Check /lib/modules/*/
        modules_dir = self._abs_path("/lib/modules")
        if os.path.isdir(modules_dir):
            try:
                for entry in os.listdir(modules_dir):
                    entry_path = os.path.join(modules_dir, entry)
                    if os.path.isdir(entry_path) and re.match(r"\d+\.\d+", entry):
                        # Extract base kernel version (strip local version suffix)
                        match = re.match(r"(\d+\.\d+\.\d+)", entry)
                        version = match.group(1) if match else entry
                        comp = IdentifiedComponent(
                            name="linux-kernel",
                            version=version,
                            type="operating-system",
                            cpe=f"cpe:2.3:o:linux:linux_kernel:{version}:*:*:*:*:*:*:*",
                            purl=self._build_purl("linux", version),
                            supplier="linux",
                            detection_source="kernel_modules",
                            detection_confidence="high",
                            file_paths=[f"/lib/modules/{entry}"],
                            metadata={"full_version": entry},
                        )
                        self._add_component(comp)
                        break  # Usually only one kernel version
            except OSError:
                pass

        # Check /etc/os-release, /etc/openwrt_release for distro info
        for rel_file in ["/etc/os-release", "/etc/openwrt_release"]:
            abs_path = self._abs_path(rel_file)
            if os.path.isfile(abs_path):
                self._parse_os_release(abs_path, rel_file)

    def _parse_os_release(self, abs_path: str, rel_path: str) -> None:
        """Parse os-release or openwrt_release for distro identification."""
        try:
            with open(abs_path, "r", errors="replace") as f:
                content = f.read(4096)
        except OSError:
            return

        fields: dict[str, str] = {}
        for line in content.splitlines():
            line = line.strip()
            if "=" in line and not line.startswith("#"):
                key, _, val = line.partition("=")
                fields[key.strip()] = val.strip().strip("'\"")

        distro_id = fields.get("ID", fields.get("DISTRIB_ID", "")).lower()
        distro_version = fields.get("VERSION_ID", fields.get("DISTRIB_RELEASE", ""))
        distro_name = fields.get("NAME", fields.get("DISTRIB_DESCRIPTION", distro_id))

        if distro_id and distro_version:
            comp = IdentifiedComponent(
                name=distro_id,
                version=distro_version,
                type="operating-system",
                cpe=self._build_cpe(distro_id, distro_id, distro_version),
                purl=self._build_purl(distro_id, distro_version),
                supplier=distro_id,
                detection_source="config_file",
                detection_confidence="high",
                file_paths=[rel_path],
                metadata={"display_name": distro_name},
            )
            self._add_component(comp)

    # ------------------------------------------------------------------
    # Dedicated BusyBox detection (critical for embedded Linux)
    # ------------------------------------------------------------------

    def _scan_busybox(self) -> None:
        """Explicitly search for BusyBox, which is present in most embedded
        Linux firmware.  BusyBox installs as a single binary with hundreds
        of symlinks, so the generic binary scanner (which skips symlinks)
        may miss it depending on layout.  We resolve symlinks here and read
        the actual binary to extract the version string."""

        # Common locations where the real busybox binary (or a symlink to
        # it) lives.  We also check /bin/sh since it's almost always a
        # symlink to busybox on embedded systems.
        candidates = [
            "/bin/busybox",
            "/bin/busybox.nosuid",
            "/bin/busybox.suid",
            "/usr/bin/busybox",
            "/sbin/busybox",
            "/bin/sh",
        ]

        checked_realpaths: set[str] = set()

        for candidate in candidates:
            abs_path = self._abs_path(candidate)

            # Resolve symlinks so we read the actual binary
            try:
                real_path = os.path.realpath(abs_path)
            except OSError:
                continue

            # Stay inside the extracted root
            if not real_path.startswith(self.extracted_root):
                continue
            if not os.path.isfile(real_path):
                continue
            # Don't scan the same underlying file twice
            if real_path in checked_realpaths:
                continue
            checked_realpaths.add(real_path)

            # Quick ELF check
            try:
                with open(real_path, "rb") as f:
                    if f.read(4) != b"\x7fELF":
                        continue
            except OSError:
                continue

            # Read and search for BusyBox version string
            try:
                with open(real_path, "rb") as f:
                    data = f.read(MAX_BINARY_READ)
            except OSError:
                continue

            match = re.search(rb"BusyBox v(\d+\.\d+(?:\.\d+)?)", data)
            if match:
                version = match.group(1).decode("ascii", errors="replace")
                rel_path = "/" + os.path.relpath(real_path, self.extracted_root)

                comp = IdentifiedComponent(
                    name="busybox",
                    version=version,
                    type="application",
                    cpe=self._build_cpe("busybox", "busybox", version),
                    purl=self._build_purl("busybox", version),
                    supplier="busybox",
                    detection_source="binary_strings",
                    detection_confidence="high",
                    file_paths=[rel_path],
                    metadata={"detection_note": "dedicated busybox scan"},
                )
                self._add_component(comp)
                return  # Found it, no need to check more candidates

    # ------------------------------------------------------------------
    # Strategy 3: Library SONAME parsing
    # ------------------------------------------------------------------

    def _scan_library_sonames(self) -> None:
        """Scan shared library files for version information."""
        lib_dirs = [
            "/lib", "/usr/lib", "/lib64", "/usr/lib64",
        ]
        seen_libs: set[str] = set()

        for lib_dir in lib_dirs:
            abs_dir = self._abs_path(lib_dir)
            if not os.path.isdir(abs_dir):
                continue
            try:
                entries = os.listdir(abs_dir)
            except OSError:
                continue

            for entry in entries:
                if ".so" not in entry:
                    continue
                abs_path = os.path.join(abs_dir, entry)
                if not os.path.isfile(abs_path):
                    continue
                # Skip symlinks to avoid double-counting
                if os.path.islink(abs_path):
                    continue

                lib_info = self._parse_library_file(abs_path, f"{lib_dir}/{entry}")
                if lib_info and lib_info["name"] not in seen_libs:
                    seen_libs.add(lib_info["name"])
                    vendor_product = CPE_VENDOR_MAP.get(lib_info["name"].lower())
                    cpe = None
                    if vendor_product:
                        cpe = self._build_cpe(vendor_product[0], vendor_product[1], lib_info["version"])

                    comp = IdentifiedComponent(
                        name=lib_info["name"],
                        version=lib_info["version"],
                        type="library",
                        cpe=cpe,
                        purl=self._build_purl(lib_info["name"], lib_info["version"]),
                        supplier=vendor_product[0] if vendor_product else None,
                        detection_source="library_soname",
                        detection_confidence="high",
                        file_paths=[f"{lib_dir}/{entry}"],
                        metadata={"soname": lib_info.get("soname", "")},
                    )
                    self._add_component(comp)

    def _parse_library_file(self, abs_path: str, rel_path: str) -> dict | None:
        """Extract component name and version from a shared library file."""
        basename = os.path.basename(abs_path)

        # Try to get SONAME from ELF
        soname = None
        try:
            with open(abs_path, "rb") as f:
                magic = f.read(4)
                if magic != b"\x7fELF":
                    return None
                f.seek(0)
                elf = ELFFile(f)
                for seg in elf.iter_segments():
                    if seg.header.p_type == "PT_DYNAMIC":
                        for tag in seg.iter_tags():
                            if tag.entry.d_tag == "DT_SONAME":
                                soname = tag.soname
                        break
        except Exception:
            return None

        # Parse version from filename: libfoo.so.1.2.3 -> name=libfoo, version=1.2.3
        name, version = self._parse_so_version(soname or basename)
        if not name:
            return None

        # Map library name to component name
        component_name = SONAME_COMPONENT_MAP.get(name, name)

        return {
            "name": component_name,
            "version": version,
            "soname": soname or basename,
        }

    @staticmethod
    def _parse_so_version(filename: str) -> tuple[str | None, str | None]:
        """Parse a .so filename into (name, version).

        Examples:
            libssl.so.1.1 -> (libssl, 1.1)
            libcrypto.so.1.1.1k -> (libcrypto, 1.1.1k)
            libc.so.6 -> (libc, 6)
            libfoo.so -> (libfoo, None)
        """
        # Match libXXX.so.VERSION
        match = re.match(r"^(lib[\w+-]+)\.so\.(.+)$", filename)
        if match:
            name = match.group(1)
            version = match.group(2)
            return name, version

        # Match libXXX.so (no version)
        match = re.match(r"^(lib[\w+-]+)\.so$", filename)
        if match:
            return match.group(1), None

        # Match libXXX-VERSION.so
        match = re.match(r"^(lib[\w+-]+)-(\d[\d.]+\w*)\.so$", filename)
        if match:
            return match.group(1), match.group(2)

        return None, None

    # ------------------------------------------------------------------
    # Strategy 4: Binary version strings
    # ------------------------------------------------------------------

    def _scan_binary_version_strings(self) -> None:
        """Scan ELF binaries in standard paths for version strings."""
        bin_dirs = ["/bin", "/sbin", "/usr/bin", "/usr/sbin"]
        scanned = 0

        for bin_dir in bin_dirs:
            abs_dir = self._abs_path(bin_dir)
            if not os.path.isdir(abs_dir):
                continue
            try:
                entries = os.listdir(abs_dir)
            except OSError:
                continue

            for entry in sorted(entries):
                if scanned >= MAX_BINARIES_SCAN:
                    return

                abs_path = os.path.join(abs_dir, entry)
                if not os.path.isfile(abs_path):
                    continue
                # Skip symlinks
                if os.path.islink(abs_path):
                    continue

                # Quick ELF check
                try:
                    with open(abs_path, "rb") as f:
                        if f.read(4) != b"\x7fELF":
                            continue
                except OSError:
                    continue

                scanned += 1
                self._scan_binary_strings(abs_path, f"{bin_dir}/{entry}")

    def _scan_binary_strings(self, abs_path: str, rel_path: str) -> None:
        """Extract printable strings from a binary and match version patterns."""
        try:
            with open(abs_path, "rb") as f:
                data = f.read(MAX_BINARY_READ)
        except OSError:
            return

        # Extract printable ASCII strings (min length 4)
        strings = self._extract_printable_strings(data, min_length=4)
        combined = b"\n".join(strings)

        for component_name, pattern in VERSION_PATTERNS:
            match = pattern.search(combined)
            if match:
                version = match.group(1).decode("ascii", errors="replace")

                # Skip if we already have this component from a higher-confidence source
                key = (component_name.lower(), version)
                existing = self._components.get(key)
                if existing and existing.detection_confidence == "high":
                    continue

                vendor_product = CPE_VENDOR_MAP.get(component_name.lower())
                cpe = None
                if vendor_product:
                    cpe = self._build_cpe(vendor_product[0], vendor_product[1], version)

                comp = IdentifiedComponent(
                    name=component_name,
                    version=version,
                    type="application",
                    cpe=cpe,
                    purl=self._build_purl(component_name, version),
                    supplier=vendor_product[0] if vendor_product else None,
                    detection_source="binary_strings",
                    detection_confidence="medium",
                    file_paths=[rel_path],
                    metadata={},
                )
                self._add_component(comp)

    @staticmethod
    def _extract_printable_strings(data: bytes, min_length: int = 4) -> list[bytes]:
        """Extract printable ASCII strings from binary data."""
        strings = []
        current = bytearray()
        for byte in data:
            if 0x20 <= byte < 0x7F:
                current.append(byte)
            else:
                if len(current) >= min_length:
                    strings.append(bytes(current))
                current = bytearray()
        if len(current) >= min_length:
            strings.append(bytes(current))
        return strings
