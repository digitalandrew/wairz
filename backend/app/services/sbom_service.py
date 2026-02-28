"""SBOM service — identifies software components from unpacked firmware.

Walks the extracted filesystem, parses package databases, scans libraries
and binaries for version information, and returns a deduplicated list of
identified components with CPE and PURL identifiers.
"""

import os
import re
from dataclasses import dataclass, field

from elftools.elf.elffile import ELFFile

from app.utils.sandbox import safe_walk, validate_path

MAX_BINARIES_SCAN = 200
MAX_BINARY_READ = 256 * 1024  # 256KB for strings extraction
MAX_LIBC_READ = 512 * 1024  # 512KB — C library binaries are large

# Well-known vendor:product mappings for CPE construction
CPE_VENDOR_MAP: dict[str, tuple[str, str]] = {
    # Core system
    "busybox": ("busybox", "busybox"),
    "glibc": ("gnu", "glibc"),
    "libc": ("gnu", "glibc"),
    "uclibc": ("uclibc", "uclibc"),
    "musl": ("musl-libc", "musl"),
    "bash": ("gnu", "bash"),
    # SSL/TLS & crypto
    "openssl": ("openssl", "openssl"),
    "libssl": ("openssl", "openssl"),
    "libcrypto": ("openssl", "openssl"),
    "wolfssl": ("wolfssl", "wolfssl"),
    "libwolfssl": ("wolfssl", "wolfssl"),
    "mbedtls": ("arm", "mbed_tls"),
    "libmbedtls": ("arm", "mbed_tls"),
    "libmbedcrypto": ("arm", "mbed_tls"),
    "gnutls": ("gnu", "gnutls"),
    "libgnutls": ("gnu", "gnutls"),
    "libsodium": ("libsodium_project", "libsodium"),
    "libgcrypt": ("gnupg", "libgcrypt"),
    "libnettle": ("gnu", "nettle"),
    # Web servers
    "nginx": ("f5", "nginx"),
    "lighttpd": ("lighttpd", "lighttpd"),
    "apache": ("apache", "http_server"),
    "httpd": ("apache", "http_server"),
    "mini_httpd": ("acme", "mini_httpd"),
    "uhttpd": ("openwrt", "uhttpd"),
    "goahead": ("embedthis", "goahead"),
    "boa": ("boa", "boa_web_server"),
    "thttpd": ("acme", "thttpd"),
    "mongoose": ("cesanta", "mongoose"),
    # SSH
    "dropbear": ("matt_johnston", "dropbear"),
    "openssh": ("openbsd", "openssh"),
    # DNS
    "dnsmasq": ("thekelleys", "dnsmasq"),
    "unbound": ("nlnetlabs", "unbound"),
    # Network services
    "curl": ("haxx", "curl"),
    "libcurl": ("haxx", "curl"),
    "wget": ("gnu", "wget"),
    "hostapd": ("w1.fi", "hostapd"),
    "wpa_supplicant": ("w1.fi", "wpa_supplicant"),
    "openvpn": ("openvpn", "openvpn"),
    "samba": ("samba", "samba"),
    "mosquitto": ("eclipse", "mosquitto"),
    "avahi": ("avahi", "avahi"),
    # Firewall / netfilter
    "iptables": ("netfilter", "iptables"),
    "ip6tables": ("netfilter", "iptables"),
    "nftables": ("netfilter", "nftables"),
    # FTP / SNMP / UPnP
    "proftpd": ("proftpd", "proftpd"),
    "vsftpd": ("beasts", "vsftpd"),
    "miniupnpd": ("miniupnp_project", "miniupnpd"),
    "ntpd": ("ntp", "ntp"),
    "netatalk": ("netatalk", "netatalk"),
    # Bootloader
    "uboot": ("denx", "u-boot"),
    "u-boot": ("denx", "u-boot"),
    # Utility libraries
    "zlib": ("zlib", "zlib"),
    "sqlite": ("sqlite", "sqlite"),
    "libjpeg": ("ijg", "libjpeg"),
    "libpng": ("libpng", "libpng"),
    "lua": ("lua", "lua"),
    "perl": ("perl", "perl"),
    "python": ("python", "python"),
    "json-c": ("json-c_project", "json-c"),
    "libxml2": ("xmlsoft", "libxml2"),
    "pcre": ("pcre", "pcre"),
    "expat": ("libexpat_project", "libexpat"),
    "dbus": ("freedesktop", "dbus"),
    "readline": ("gnu", "readline"),
    "ncurses": ("gnu", "ncurses"),
    # OpenWrt ecosystem
    "ubus": ("openwrt", "ubus"),
    "libubox": ("openwrt", "libubox"),
    "uci": ("openwrt", "uci"),
    # Compiler / toolchain
    "gcc": ("gnu", "gcc"),
    "uclibc-ng": ("uclibc", "uclibc"),
    # Network tools
    "net-snmp": ("net-snmp", "net-snmp"),
    "iproute2": ("iproute2_project", "iproute2"),
    "pppd": ("samba", "ppp"),
    "libnl": ("infradead", "libnl"),
    # Logging
    "syslog-ng": ("balabit", "syslog-ng"),
    # IoT protocols
    "libcoap": ("libcoap", "libcoap"),
    # TR-069/CWMP
    "cwmpd": ("cwmp", "cwmpd"),
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
    # C library
    ("glibc", re.compile(rb"GNU C Library[^\n]*version (\d+\.\d+(?:\.\d+)?)")),
    ("glibc", re.compile(rb"stable release version (\d+\.\d+(?:\.\d+)?)")),
    ("uclibc-ng", re.compile(rb"uClibc(?:-ng)? (\d+\.\d+\.\d+)")),
    ("musl", re.compile(rb"musl libc (\d+\.\d+\.\d+)")),
    # GCC / toolchain
    ("gcc", re.compile(rb"GCC: \([^)]*\) (\d+\.\d+\.\d+)")),
    # Bootloader
    ("u-boot", re.compile(rb"U-Boot (\d{4}\.\d{2}(?:-\S+)?)")),
    ("u-boot", re.compile(rb"U-Boot SPL (\d{4}\.\d{2}(?:-\S+)?)")),
    # Network tools
    ("iptables", re.compile(rb"iptables v(\d+\.\d+\.\d+)")),
    ("iproute2", re.compile(rb"iproute2[/-](\d+\.\d+(?:\.\d+)?)")),
    ("pppd", re.compile(rb"pppd (\d+\.\d+\.\d+)")),
    ("net-snmp", re.compile(rb"NET-SNMP (\d+\.\d+\.\d+)")),
    ("syslog-ng", re.compile(rb"syslog-ng (\d+\.\d+\.\d+)")),
    # Libraries (content-based extraction)
    ("zlib", re.compile(rb"(?:zlib |inflate )(\d+\.\d+\.\d+(?:\.\d+)?)")),
    ("libpng", re.compile(rb"libpng[- ](\d+\.\d+\.\d+)")),
    ("libxml2", re.compile(rb"libxml2[- ](\d+\.\d+\.\d+)")),
    ("pcre", re.compile(rb"PCRE (\d+\.\d+(?:\.\d+)?)")),
    ("expat", re.compile(rb"expat_(\d+\.\d+\.\d+)")),
    ("libjpeg", re.compile(rb"(?:libjpeg|JPEG[- ]library)[- ](\d+[a-z]?(?:\.\d+)*)")),
    ("json-c", re.compile(rb"json-c[/ ](\d+\.\d+(?:\.\d+)?)")),
    ("dbus", re.compile(rb"D-Bus (\d+\.\d+\.\d+)")),
    # Additional patterns
    ("apache", re.compile(rb"Apache/(\d+\.\d+\.\d+)")),
    ("uhttpd", re.compile(rb"uhttpd[/ ]v?(\d+\.\d+(?:\.\d+)?)")),
    ("goahead", re.compile(rb"GoAhead[/ -](\d+\.\d+\.\d+)")),
    ("openvpn", re.compile(rb"OpenVPN (\d+\.\d+\.\d+)")),
    ("wolfssl", re.compile(rb"wolfSSL (\d+\.\d+\.\d+)")),
    ("mbedtls", re.compile(rb"mbed TLS (\d+\.\d+\.\d+)")),
    ("unbound", re.compile(rb"unbound (\d+\.\d+\.\d+)")),
    ("mosquitto", re.compile(rb"mosquitto[/ ](\d+\.\d+\.\d+)")),
    ("boa", re.compile(rb"Boa/(\d+\.\d+\.\d+)")),
    ("thttpd", re.compile(rb"thttpd/(\d+\.\d+(?:\.\d+)?)")),
    ("mongoose", re.compile(rb"Mongoose[/ ](\d+\.\d+(?:\.\d+)?)")),
]

# Library SONAME -> component name mapping for well-known libraries
SONAME_COMPONENT_MAP: dict[str, str] = {
    # SSL/TLS & crypto
    "libssl": "openssl",
    "libcrypto": "openssl",
    "libwolfssl": "wolfssl",
    "libmbedtls": "mbedtls",
    "libmbedcrypto": "mbedtls",
    "libgnutls": "gnutls",
    "libsodium": "libsodium",
    "libgcrypt": "libgcrypt",
    "libnettle": "nettle",
    # Utility libraries
    "libcurl": "curl",
    "libz": "zlib",
    "libsqlite3": "sqlite",
    "libpng": "libpng",
    "libpng16": "libpng",
    "libjpeg": "libjpeg",
    "liblua": "lua",
    "libjson-c": "json-c",
    "libxml2": "libxml2",
    "libpcre": "pcre",
    "libexpat": "expat",
    "libdbus": "dbus",
    "libreadline": "readline",
    "libncurses": "ncurses",
    # Networking
    "libavahi-client": "avahi",
    "libavahi-common": "avahi",
    "libnl": "libnl",
    "libnl-3": "libnl",
    "libmosquitto": "mosquitto",
    # OpenWrt
    "libubus": "ubus",
    "libubox": "libubox",
    "libuci": "uci",
    "libiwinfo": "iwinfo",
    # Firewall / netfilter
    "libiptc": "iptables",
    "libnfnetlink": "netfilter",
    # System libraries (C runtime)
    "libpthread": "glibc",
    "libdl": "glibc",
    "librt": "glibc",
    "libm": "glibc",
    "libc": "glibc",
    "libgcc_s": "gcc",
    "libstdc++": "gcc",
}

# Firmware OS fingerprinting markers (additional to /etc/os-release)
FIRMWARE_MARKERS: dict[str, list[str]] = {
    "dd-wrt": ["/etc/dd-wrt_version"],
    "buildroot": ["/etc/buildroot_version", "/etc/br-version"],
    "yocto": ["/etc/version", "/etc/build"],
    "android": ["/system/build.prop"],
}

# Known services/daemons with risk classification for firmware security
# CRITICAL = should never be in production (plaintext, no auth)
# HIGH = common attack surface requiring review
KNOWN_SERVICE_RISKS: dict[str, str] = {
    # CRITICAL — plaintext protocols with no authentication
    "telnetd": "critical",
    "utelnetd": "critical",
    "rlogind": "critical",
    "rshd": "critical",
    "rexecd": "critical",
    "tftpd": "critical",
    # HIGH — common attack surface
    "ftpd": "high",
    "vsftpd": "high",
    "proftpd": "high",
    "httpd": "high",
    "uhttpd": "high",
    "lighttpd": "high",
    "goahead": "high",
    "miniupnpd": "high",
    "snmpd": "high",
    "smbd": "high",
    "cwmpd": "high",
    "mini_httpd": "high",
    "boa": "high",
    "mongoose": "high",
    # MEDIUM — expected but should be hardened
    "sshd": "medium",
    "dropbear": "medium",
    "dnsmasq": "medium",
    "hostapd": "medium",
    "openvpn": "medium",
    "mosquitto": "medium",
    # LOW — generally safe
    "ntpd": "low",
    "crond": "low",
    "syslogd": "low",
    "avahi-daemon": "low",
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
        self._scan_firmware_markers()
        self._scan_busybox()
        self._scan_c_library()
        self._scan_gcc_version()
        self._scan_library_sonames()
        self._scan_binary_version_strings()
        self._annotate_service_risks()

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
    # Strategy 2b: Firmware OS fingerprinting via marker files
    # ------------------------------------------------------------------

    def _scan_firmware_markers(self) -> None:
        """Check for firmware distro marker files beyond os-release."""
        for distro_id, marker_paths in FIRMWARE_MARKERS.items():
            for rel_path in marker_paths:
                abs_path = self._abs_path(rel_path)
                if not os.path.isfile(abs_path):
                    continue
                try:
                    with open(abs_path, "r", errors="replace") as f:
                        content = f.read(1024).strip()
                except OSError:
                    continue
                if not content:
                    continue

                # Try to extract a version number from the file content
                version_match = re.search(r"(\d+\.\d+(?:\.\d+)?)", content)
                version = version_match.group(1) if version_match else content[:50]

                comp = IdentifiedComponent(
                    name=distro_id,
                    version=version,
                    type="operating-system",
                    cpe=self._build_cpe(distro_id, distro_id, version),
                    purl=self._build_purl(distro_id, version),
                    supplier=distro_id,
                    detection_source="config_file",
                    detection_confidence="high",
                    file_paths=[rel_path],
                    metadata={"marker_file": rel_path, "raw_content": content[:200]},
                )
                self._add_component(comp)
                break  # Only need one marker per distro

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
    # Dedicated C library detection
    # ------------------------------------------------------------------

    def _scan_c_library(self) -> None:
        """Detect the C library (glibc, uClibc-ng, musl) and its version.

        Firmware has exactly one C library; we return after the first
        identification.  Reads up to MAX_LIBC_READ because libc binaries
        are large and the version string may be far into the file.
        """
        # Static candidate paths
        candidates: list[str] = [
            "/lib/libc.so.6",
            "/lib/libc.so.0",
        ]

        # Dynamic candidates from /lib directory listing
        lib_abs = self._abs_path("/lib")
        if os.path.isdir(lib_abs):
            try:
                for entry in os.listdir(lib_abs):
                    if entry.startswith(("ld-linux", "ld-musl-", "ld-uClibc")):
                        candidates.append(f"/lib/{entry}")
                    elif entry.startswith("libc.so."):
                        path = f"/lib/{entry}"
                        if path not in candidates:
                            candidates.append(path)
            except OSError:
                pass

        checked_realpaths: set[str] = set()

        for candidate in candidates:
            abs_path = self._abs_path(candidate)
            try:
                real_path = os.path.realpath(abs_path)
            except OSError:
                continue
            if not real_path.startswith(self.extracted_root):
                continue
            if not os.path.isfile(real_path):
                continue
            if real_path in checked_realpaths:
                continue
            checked_realpaths.add(real_path)

            try:
                with open(real_path, "rb") as f:
                    if f.read(4) != b"\x7fELF":
                        continue
                    f.seek(0)
                    data = f.read(MAX_LIBC_READ)
            except OSError:
                continue

            rel_path = "/" + os.path.relpath(real_path, self.extracted_root)

            # --- glibc detection ---
            # String match: "GNU C Library ... version 2.31"
            m = re.search(rb"GNU C Library[^\n]*version (\d+\.\d+(?:\.\d+)?)", data)
            if not m:
                m = re.search(rb"stable release version (\d+\.\d+(?:\.\d+)?)", data)
            if m:
                version = m.group(1).decode("ascii", errors="replace")
                self._add_component(IdentifiedComponent(
                    name="glibc",
                    version=version,
                    type="library",
                    cpe=self._build_cpe("gnu", "glibc", version),
                    purl=self._build_purl("glibc", version),
                    supplier="gnu",
                    detection_source="binary_strings",
                    detection_confidence="high",
                    file_paths=[rel_path],
                    metadata={"detection_note": "dedicated C library scan"},
                ))
                return

            # Fallback: pick highest GLIBC_X.Y symbol version
            glibc_versions = re.findall(rb"GLIBC_(\d+\.\d+(?:\.\d+)?)", data)
            if glibc_versions:
                parsed = []
                for v in set(glibc_versions):
                    try:
                        parts = tuple(int(x) for x in v.decode("ascii").split("."))
                        parsed.append((parts, v.decode("ascii")))
                    except (ValueError, UnicodeDecodeError):
                        continue
                if parsed:
                    parsed.sort(key=lambda x: x[0], reverse=True)
                    version = parsed[0][1]
                    self._add_component(IdentifiedComponent(
                        name="glibc",
                        version=version,
                        type="library",
                        cpe=self._build_cpe("gnu", "glibc", version),
                        purl=self._build_purl("glibc", version),
                        supplier="gnu",
                        detection_source="binary_strings",
                        detection_confidence="medium",
                        file_paths=[rel_path],
                        metadata={
                            "detection_note": "inferred from GLIBC symbol versions",
                        },
                    ))
                    return

            # --- uClibc-ng detection ---
            m = re.search(rb"uClibc(?:-ng)? (\d+\.\d+\.\d+)", data)
            if m:
                version = m.group(1).decode("ascii", errors="replace")
                self._add_component(IdentifiedComponent(
                    name="uclibc-ng",
                    version=version,
                    type="library",
                    cpe=self._build_cpe("uclibc", "uclibc", version),
                    purl=self._build_purl("uclibc-ng", version),
                    supplier="uclibc",
                    detection_source="binary_strings",
                    detection_confidence="high",
                    file_paths=[rel_path],
                    metadata={"detection_note": "dedicated C library scan"},
                ))
                return

            # --- musl detection ---
            m = re.search(rb"musl libc (\d+\.\d+\.\d+)", data)
            if m:
                version = m.group(1).decode("ascii", errors="replace")
                self._add_component(IdentifiedComponent(
                    name="musl",
                    version=version,
                    type="library",
                    cpe=self._build_cpe("musl-libc", "musl", version),
                    purl=self._build_purl("musl", version),
                    supplier="musl-libc",
                    detection_source="binary_strings",
                    detection_confidence="high",
                    file_paths=[rel_path],
                    metadata={"detection_note": "dedicated C library scan"},
                ))
                return

    # ------------------------------------------------------------------
    # Dedicated GCC version detection
    # ------------------------------------------------------------------

    def _scan_gcc_version(self) -> None:
        """Detect the GCC version used to compile the firmware.

        Probes a few common binaries for the ``GCC: (toolchain) X.Y.Z``
        string embedded by the compiler.  Returns after first match
        because the GCC version is consistent across a build.
        """
        probe_paths = [
            "/bin/busybox",
            "/sbin/init",
            "/lib/libc.so.6",
            "/lib/libc.so.0",
            "/usr/sbin/httpd",
            "/usr/bin/curl",
        ]

        checked_realpaths: set[str] = set()

        for probe in probe_paths:
            abs_path = self._abs_path(probe)
            try:
                real_path = os.path.realpath(abs_path)
            except OSError:
                continue
            if not real_path.startswith(self.extracted_root):
                continue
            if not os.path.isfile(real_path):
                continue
            if real_path in checked_realpaths:
                continue
            checked_realpaths.add(real_path)

            try:
                with open(real_path, "rb") as f:
                    if f.read(4) != b"\x7fELF":
                        continue
                    f.seek(0)
                    data = f.read(MAX_BINARY_READ)
            except OSError:
                continue

            m = re.search(rb"GCC: \(([^)]*)\) (\d+\.\d+\.\d+)", data)
            if m:
                toolchain = m.group(1).decode("ascii", errors="replace")
                version = m.group(2).decode("ascii", errors="replace")
                rel_path = "/" + os.path.relpath(real_path, self.extracted_root)

                metadata: dict = {"detection_note": "dedicated GCC scan"}
                if toolchain:
                    metadata["toolchain"] = toolchain

                self._add_component(IdentifiedComponent(
                    name="gcc",
                    version=version,
                    type="application",
                    cpe=self._build_cpe("gnu", "gcc", version),
                    purl=self._build_purl("gcc", version),
                    supplier="gnu",
                    detection_source="binary_strings",
                    detection_confidence="high",
                    file_paths=[rel_path],
                    metadata=metadata,
                ))
                return

    # ------------------------------------------------------------------
    # Strategy 3: Library SONAME parsing
    # ------------------------------------------------------------------

    def _scan_library_sonames(self) -> None:
        """Scan shared library files for version information.

        Uses safe_walk() for recursive scanning so libraries in
        subdirectories (e.g. /lib/ipsec/, /usr/lib/lua/) are found.
        When a library has a useless version (single digit like "6"),
        falls back to reading binary content for a real version string.
        """
        lib_dirs = [
            "/lib", "/usr/lib", "/lib64", "/usr/lib64",
        ]
        seen_libs: set[str] = set()

        for lib_dir in lib_dirs:
            abs_dir = self._abs_path(lib_dir)
            if not os.path.isdir(abs_dir):
                continue

            for dirpath, _dirs, files in safe_walk(abs_dir):
                # Stay inside the extracted root
                if not dirpath.startswith(self.extracted_root):
                    continue

                for entry in files:
                    if ".so" not in entry:
                        continue
                    abs_path = os.path.join(dirpath, entry)
                    if not os.path.isfile(abs_path):
                        continue
                    # Skip symlinks to avoid double-counting
                    if os.path.islink(abs_path):
                        continue

                    dir_rel = "/" + os.path.relpath(dirpath, self.extracted_root)
                    file_rel = f"{dir_rel}/{entry}"

                    lib_info = self._parse_library_file(abs_path, file_rel)
                    if not lib_info or lib_info["name"] in seen_libs:
                        continue

                    version = lib_info["version"]
                    component_name = lib_info["name"]

                    # If the version is useless, try to extract from binary content.
                    # If content extraction also fails, skip — a dedicated scanner
                    # or the binary string scanner will find the real version.
                    if self._is_useless_version(version):
                        content_version = self._extract_version_from_library_content(
                            abs_path, component_name
                        )
                        if content_version:
                            version = content_version
                        else:
                            continue

                    seen_libs.add(component_name)
                    vendor_product = CPE_VENDOR_MAP.get(component_name.lower())
                    cpe = None
                    if vendor_product:
                        cpe = self._build_cpe(vendor_product[0], vendor_product[1], version)

                    comp = IdentifiedComponent(
                        name=component_name,
                        version=version,
                        type="library",
                        cpe=cpe,
                        purl=self._build_purl(component_name, version),
                        supplier=vendor_product[0] if vendor_product else None,
                        detection_source="library_soname",
                        detection_confidence="high",
                        file_paths=[file_rel],
                        metadata={"soname": lib_info.get("soname", "")},
                    )
                    self._add_component(comp)

    @staticmethod
    def _is_useless_version(version: str | None) -> bool:
        """Return True if the version is missing or unlikely to be a real
        software version.

        SONAME versions like "6" (libc.so.6), "0" (libc.so.0), or "200"
        (libnl-3.so.200) are just ABI version numbers, not real
        upstream software versions.  Real versions have at least one dot
        (e.g. "1.2", "2.31", "1.0.2k").
        """
        if not version:
            return True
        # A bare integer (no dots) is almost always a SONAME ABI version
        return bool(re.fullmatch(r"\d+", version))

    def _extract_version_from_library_content(
        self, abs_path: str, component_name: str
    ) -> str | None:
        """Read a library binary and match VERSION_PATTERNS for its component.

        Returns the extracted version string, or None.
        """
        try:
            with open(abs_path, "rb") as f:
                data = f.read(MAX_BINARY_READ)
        except OSError:
            return None

        name_lower = component_name.lower()
        for pattern_name, pattern in VERSION_PATTERNS:
            if pattern_name.lower() != name_lower:
                continue
            m = pattern.search(data)
            if m:
                return m.group(1).decode("ascii", errors="replace")
        return None

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

    # ------------------------------------------------------------------
    # Post-processing: Annotate service risk levels
    # ------------------------------------------------------------------

    def _annotate_service_risks(self) -> None:
        """Tag identified components with service risk levels.

        Checks binary names in standard daemon paths and annotates
        components that match known services with their risk level.
        """
        # Check for known service binaries in the filesystem
        daemon_dirs = ["/usr/sbin", "/sbin", "/usr/bin", "/bin"]

        for daemon_dir in daemon_dirs:
            abs_dir = self._abs_path(daemon_dir)
            if not os.path.isdir(abs_dir):
                continue
            try:
                entries = os.listdir(abs_dir)
            except OSError:
                continue

            for entry in entries:
                risk = KNOWN_SERVICE_RISKS.get(entry)
                if not risk:
                    continue

                # Find and annotate the matching component
                for comp in self._components.values():
                    if comp.name.lower() == entry or entry in (
                        p.rsplit("/", 1)[-1] for p in comp.file_paths
                    ):
                        comp.metadata["service_risk"] = risk
                        break
                else:
                    # Service binary found but not yet identified as a component —
                    # add it as a low-confidence detection so it shows up in SBOM
                    rel_path = f"{daemon_dir}/{entry}"
                    vendor_product = CPE_VENDOR_MAP.get(entry.lower())

                    comp = IdentifiedComponent(
                        name=entry,
                        version=None,
                        type="application",
                        cpe=None,
                        purl=None,
                        supplier=vendor_product[0] if vendor_product else None,
                        detection_source="binary_strings",
                        detection_confidence="low",
                        file_paths=[rel_path],
                        metadata={"service_risk": risk},
                    )
                    self._add_component(comp)
