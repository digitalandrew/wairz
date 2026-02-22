"""Security assessment AI tools for firmware analysis.

Tools for evaluating the security posture of an extracted firmware filesystem:
config file auditing, setuid detection, init script analysis, filesystem
permissions, CVE lookups, and certificate analysis.
"""

import logging
import os
import re
import stat
from datetime import datetime, timezone

from app.ai.tool_registry import ToolContext, ToolRegistry
from app.utils.sandbox import safe_walk, validate_path

logger = logging.getLogger(__name__)

MAX_RESULTS = 100

# Certificate file extensions to scan for
_CERT_EXTENSIONS = {".pem", ".crt", ".cer", ".der", ".p12", ".pfx"}

# Directories commonly containing certificates in firmware
_CERT_SEARCH_DIRS = [
    "etc/ssl", "etc/ssl/certs", "etc/ssl/private",
    "etc/pki", "etc/pki/tls", "etc/pki/tls/certs",
    "etc/certificates", "etc/https", "etc/lighttpd",
    "usr/share/ca-certificates", "etc/ca-certificates",
]

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _walk_firmware(extracted_root: str, path: str | None) -> str:
    """Return the validated starting path for a filesystem walk."""
    return validate_path(extracted_root, path or "/")


def _rel(abs_path: str, extracted_root: str) -> str:
    """Return a firmware-relative path for display."""
    return "/" + os.path.relpath(abs_path, os.path.realpath(extracted_root))


# ---------------------------------------------------------------------------
# check_known_cves
# ---------------------------------------------------------------------------


async def _handle_check_known_cves(input: dict, context: ToolContext) -> str:
    """Look up known CVEs for a given component and version.

    Uses a local pattern database of commonly-vulnerable embedded Linux
    components.  This is intentionally offline — no external API calls — so
    results are best-effort.  The AI should cross-reference with its own
    knowledge for more complete coverage.
    """
    component = input["component"].strip().lower()
    version = input["version"].strip()

    # Lightweight offline CVE knowledge base for common embedded components.
    # Each entry: (component_pattern, version_check, cve_id, severity, summary)
    cve_db: list[tuple[str, str, str, str, str]] = [
        # BusyBox
        ("busybox", "<1.36.0", "CVE-2022-48174", "critical",
         "Stack overflow in BusyBox ash (awk applet) allows code execution"),
        ("busybox", "<1.35.0", "CVE-2022-28391", "high",
         "BusyBox DNS resolution use-after-free"),
        ("busybox", "<1.34.0", "CVE-2021-42386", "high",
         "BusyBox awk heap-use-after-free"),
        ("busybox", "<1.34.0", "CVE-2021-42385", "high",
         "BusyBox awk divide-by-zero"),
        ("busybox", "<1.34.0", "CVE-2021-42384", "high",
         "BusyBox awk use-after-free in evaluate"),
        # OpenSSL
        ("openssl", "<1.1.1w", "CVE-2023-5678", "medium",
         "OpenSSL DH key generation excessive time (DoS)"),
        ("openssl", "<3.0.12", "CVE-2023-5363", "medium",
         "OpenSSL incorrect cipher key/IV length processing"),
        ("openssl", "<1.1.1u", "CVE-2023-2650", "medium",
         "OpenSSL ASN1 object identifier DoS"),
        ("openssl", "<1.0.2", "CVE-2014-0160", "critical",
         "Heartbleed: TLS heartbeat buffer over-read"),
        # Dropbear SSH
        ("dropbear", "<2022.83", "CVE-2021-36369", "high",
         "Dropbear trivial authentication bypass via empty password"),
        ("dropbear", "<2020.81", "CVE-2020-36254", "high",
         "Dropbear MITM attack due to algorithm negotiation issue"),
        # dnsmasq
        ("dnsmasq", "<2.86", "CVE-2021-3448", "medium",
         "dnsmasq DNS rebinding protection bypass"),
        ("dnsmasq", "<2.83", "CVE-2020-25681", "critical",
         "dnsmasq DNSpooq heap buffer overflow in DNSSEC"),
        # lighttpd
        ("lighttpd", "<1.4.72", "CVE-2023-3447", "medium",
         "lighttpd use-after-free in h2 connection handling"),
        # curl
        ("curl", "<8.4.0", "CVE-2023-38545", "critical",
         "SOCKS5 heap buffer overflow in curl"),
        ("curl", "<7.87.0", "CVE-2022-43551", "high",
         "curl HSTS bypass via IDN encoding"),
        # uClibc / uClibc-ng
        ("uclibc", "<1.0.43", "CVE-2022-30295", "high",
         "uClibc-ng DNS transaction ID predictability"),
        # Linux kernel (common embedded versions)
        ("linux", "<5.15.0", "CVE-2022-0847", "critical",
         "DirtyPipe: arbitrary file overwrite via splice"),
        ("linux", "<5.4.0", "CVE-2021-22555", "high",
         "Netfilter heap-out-of-bounds write for privilege escalation"),
    ]

    def _version_tuple(v: str) -> tuple[int, ...]:
        """Parse a version string to a comparable tuple."""
        parts = re.findall(r"\d+", v)
        return tuple(int(p) for p in parts) if parts else (0,)

    ver = _version_tuple(version)
    matches: list[str] = []

    for comp_pat, ver_check, cve_id, severity, summary in cve_db:
        if comp_pat not in component:
            continue
        # Parse the version check (only supports "<X.Y.Z" for simplicity)
        m = re.match(r"<(.+)", ver_check)
        if m:
            threshold = _version_tuple(m.group(1))
            if ver < threshold:
                matches.append(
                    f"  [{severity.upper()}] {cve_id}\n"
                    f"    {summary}\n"
                    f"    Affected: {comp_pat} {ver_check}, your version: {version}"
                )

    if not matches:
        return (
            f"No known CVEs found for {component} {version} in the local database.\n"
            "Note: This database covers common embedded components only. "
            "Cross-reference with NVD or other sources for comprehensive results."
        )

    header = f"Found {len(matches)} potential CVE(s) for {component} {version}:\n"
    return header + "\n\n".join(matches)


# ---------------------------------------------------------------------------
# analyze_config_security
# ---------------------------------------------------------------------------

# Patterns for common insecure config settings
_CONFIG_CHECKS: list[tuple[str, str, re.Pattern, str, str]] = [
    # (filename_pattern, check_name, regex, severity, description)
    ("shadow", "empty_password",
     re.compile(r"^([^:]+)::"), "critical",
     "Account '{match}' has an empty password hash — no password required for login"),
    ("shadow", "weak_hash_des",
     re.compile(r"^([^:]+):[^$!*x]"), "high",
     "Account '{match}' uses DES password hash (trivially crackable)"),
    ("passwd", "uid0_extra",
     re.compile(r"^(?!root:)([^:]+):[^:]*:0:"), "high",
     "Non-root account '{match}' has UID 0 (root-equivalent)"),
    ("passwd", "no_password_field",
     re.compile(r"^([^:]+)::"), "medium",
     "Account '{match}' has empty password field in passwd"),
    ("sshd_config", "root_login",
     re.compile(r"^\s*PermitRootLogin\s+(yes|without-password)", re.IGNORECASE), "high",
     "SSH allows root login (PermitRootLogin {match})"),
    ("sshd_config", "password_auth",
     re.compile(r"^\s*PasswordAuthentication\s+yes", re.IGNORECASE), "medium",
     "SSH allows password authentication (prefer key-based auth)"),
    ("sshd_config", "empty_passwords",
     re.compile(r"^\s*PermitEmptyPasswords\s+yes", re.IGNORECASE), "critical",
     "SSH allows empty passwords"),
    ("httpd.conf", "dir_listing",
     re.compile(r"^\s*Options\s+.*Indexes", re.IGNORECASE), "medium",
     "Apache directory listing enabled (Options Indexes)"),
    ("lighttpd.conf", "dir_listing",
     re.compile(r'^\s*dir-listing\.activate\s*=\s*"enable"', re.IGNORECASE), "medium",
     "Lighttpd directory listing enabled"),
    ("telnetd", "telnet_enabled",
     re.compile(r"telnetd", re.IGNORECASE), "high",
     "Telnet daemon enabled — sends credentials in plaintext"),
]


async def _handle_analyze_config_security(input: dict, context: ToolContext) -> str:
    """Analyze a specific config file for common insecure settings."""
    path = input["path"]
    full_path = validate_path(context.extracted_path, path)

    if not os.path.isfile(full_path):
        return f"Error: '{path}' is not a file."

    try:
        with open(full_path, "r", errors="replace") as f:
            content = f.read(256_000)  # 256KB limit
    except PermissionError:
        return f"Error: Cannot read '{path}' — permission denied."

    basename = os.path.basename(full_path).lower()
    findings: list[str] = []

    for fname_pattern, check_name, regex, severity, desc_template in _CONFIG_CHECKS:
        if fname_pattern not in basename and fname_pattern not in path.lower():
            continue
        for line_num, line in enumerate(content.splitlines(), 1):
            m = regex.search(line)
            if m:
                match_val = m.group(1) if m.lastindex and m.lastindex >= 1 else m.group(0)
                desc = desc_template.format(match=match_val)
                findings.append(
                    f"  [{severity.upper()}] Line {line_num}: {desc}\n"
                    f"    {line.rstrip()}"
                )

    # Generic checks applicable to any config file
    for line_num, line in enumerate(content.splitlines(), 1):
        stripped = line.strip().lower()
        # Debug mode flags
        if re.search(r"\bdebug\s*[=:]\s*(true|1|on|yes)\b", stripped, re.IGNORECASE):
            findings.append(
                f"  [LOW] Line {line_num}: Debug mode appears to be enabled\n"
                f"    {line.rstrip()}"
            )
        # Default/common passwords in config values
        for pwd in ("admin", "password", "1234", "default", "root", "toor", "changeme"):
            if re.search(rf"\b(password|passwd|pass|pwd|secret)\s*[=:]\s*['\"]?{pwd}\b",
                         stripped, re.IGNORECASE):
                findings.append(
                    f"  [HIGH] Line {line_num}: Possible default/weak password\n"
                    f"    {line.rstrip()}"
                )
                break  # one match per line

    if not findings:
        return f"No obvious security issues found in '{path}'."

    header = f"Found {len(findings)} potential issue(s) in '{path}':\n\n"
    return header + "\n\n".join(findings[:MAX_RESULTS])


# ---------------------------------------------------------------------------
# check_setuid_binaries
# ---------------------------------------------------------------------------


async def _handle_check_setuid_binaries(input: dict, context: ToolContext) -> str:
    """Find all setuid/setgid files in the firmware filesystem."""
    search_root = _walk_firmware(context.extracted_path, input.get("path"))
    real_root = os.path.realpath(context.extracted_path)

    setuid_files: list[str] = []
    setgid_files: list[str] = []

    for dirpath, _dirs, files in safe_walk(search_root):
        for name in files:
            abs_path = os.path.join(dirpath, name)
            try:
                st = os.lstat(abs_path)
            except OSError:
                continue

            if not stat.S_ISREG(st.st_mode):
                continue

            rel = _rel(abs_path, real_root)
            mode = st.st_mode

            if mode & stat.S_ISUID:
                owner = f"uid={st.st_uid}"
                setuid_files.append(f"  SETUID  {oct(mode)[-4:]}  {owner}  {rel}")
            if mode & stat.S_ISGID:
                owner = f"gid={st.st_gid}"
                setgid_files.append(f"  SETGID  {oct(mode)[-4:]}  {owner}  {rel}")

            if len(setuid_files) + len(setgid_files) >= MAX_RESULTS:
                break
        if len(setuid_files) + len(setgid_files) >= MAX_RESULTS:
            break

    lines: list[str] = []

    if setuid_files:
        lines.append(f"Setuid binaries ({len(setuid_files)}):")
        lines.append("  These run with the file owner's privileges regardless of who executes them.")
        lines.append("")
        lines.extend(setuid_files)
        lines.append("")

    if setgid_files:
        lines.append(f"Setgid binaries ({len(setgid_files)}):")
        lines.append("  These run with the file group's privileges.")
        lines.append("")
        lines.extend(setgid_files)
        lines.append("")

    if not lines:
        return "No setuid or setgid binaries found."

    # Security note
    lines.append(
        "Note: Setuid-root binaries are common attack targets. "
        "Check each for known vulnerabilities and unnecessary permissions."
    )

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# analyze_init_scripts
# ---------------------------------------------------------------------------

# Known network-facing services that are security-relevant
_KNOWN_SERVICES = {
    "telnetd": ("high", "Telnet daemon — plaintext credential transmission"),
    "ftpd": ("high", "FTP daemon — plaintext credential transmission"),
    "vsftpd": ("medium", "FTP daemon (vsftpd)"),
    "tftpd": ("high", "TFTP daemon — unauthenticated file access"),
    "httpd": ("info", "HTTP server"),
    "lighttpd": ("info", "Lighttpd HTTP server"),
    "nginx": ("info", "Nginx HTTP/reverse proxy"),
    "uhttpd": ("info", "uHTTPd (OpenWrt web server)"),
    "sshd": ("info", "SSH daemon"),
    "dropbear": ("info", "Dropbear SSH daemon"),
    "dnsmasq": ("info", "DNS/DHCP server"),
    "miniupnpd": ("medium", "UPnP daemon — may expose internal services"),
    "snmpd": ("medium", "SNMP daemon — check community strings"),
    "mosquitto": ("info", "MQTT broker"),
    "upnpd": ("medium", "UPnP daemon"),
    "smbd": ("medium", "Samba file sharing"),
    "nmbd": ("medium", "NetBIOS name service"),
}


async def _handle_analyze_init_scripts(input: dict, context: ToolContext) -> str:
    """Parse init scripts and inittab to identify services started at boot."""
    real_root = os.path.realpath(context.extracted_path)
    search_root = _walk_firmware(context.extracted_path, input.get("path"))

    services: list[str] = []
    raw_entries: list[str] = []

    # 1. Check /etc/inittab
    inittab_path = os.path.join(real_root, "etc", "inittab")
    if os.path.isfile(inittab_path):
        try:
            with open(inittab_path, "r", errors="replace") as f:
                for line_num, line in enumerate(f.readlines()[:200], 1):
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    raw_entries.append(f"  inittab:{line_num}: {line}")
                    # Check for respawn entries and service names
                    for svc_name, (severity, desc) in _KNOWN_SERVICES.items():
                        if svc_name in line.lower():
                            services.append(f"  [{severity.upper()}] {svc_name}: {desc}")
                            services.append(f"    Source: /etc/inittab:{line_num}")
                            break
        except (PermissionError, OSError):
            pass

    # 2. Check /etc/init.d/ scripts
    initd_path = os.path.join(real_root, "etc", "init.d")
    if os.path.isdir(initd_path):
        for script_name in sorted(os.listdir(initd_path)):
            script_path = os.path.join(initd_path, script_name)
            if not os.path.isfile(script_path):
                continue
            raw_entries.append(f"  /etc/init.d/{script_name}")

            try:
                with open(script_path, "r", errors="replace") as f:
                    content = f.read(8192).lower()
            except (PermissionError, OSError):
                continue

            for svc_name, (severity, desc) in _KNOWN_SERVICES.items():
                if svc_name in content:
                    services.append(f"  [{severity.upper()}] {svc_name}: {desc}")
                    services.append(f"    Source: /etc/init.d/{script_name}")

    # 3. Check /etc/rc.d/ (common in OpenWrt)
    rcd_path = os.path.join(real_root, "etc", "rc.d")
    if os.path.isdir(rcd_path):
        for link_name in sorted(os.listdir(rcd_path)):
            raw_entries.append(f"  /etc/rc.d/{link_name}")

    # 4. Check systemd units
    for systemd_dir in ("etc/systemd/system", "lib/systemd/system", "usr/lib/systemd/system"):
        sd_path = os.path.join(real_root, systemd_dir)
        if not os.path.isdir(sd_path):
            continue
        for unit_name in sorted(os.listdir(sd_path)):
            if not unit_name.endswith(".service"):
                continue
            raw_entries.append(f"  {systemd_dir}/{unit_name}")
            unit_path = os.path.join(sd_path, unit_name)
            try:
                with open(unit_path, "r", errors="replace") as f:
                    content = f.read(4096).lower()
            except (PermissionError, OSError):
                continue

            for svc_name, (severity, desc) in _KNOWN_SERVICES.items():
                if svc_name in content:
                    services.append(f"  [{severity.upper()}] {svc_name}: {desc}")
                    services.append(f"    Source: {systemd_dir}/{unit_name}")

    lines: list[str] = []

    # Deduplicate services
    seen = set()
    unique_services: list[str] = []
    for s in services:
        if s not in seen:
            seen.add(s)
            unique_services.append(s)

    if unique_services:
        lines.append(f"Network/security-relevant services ({len(unique_services) // 2}):")
        lines.append("")
        lines.extend(unique_services)
        lines.append("")

    if raw_entries:
        lines.append(f"All init entries found ({len(raw_entries)}):")
        lines.append("")
        lines.extend(raw_entries[:MAX_RESULTS])
    else:
        lines.append("No init scripts, inittab, or systemd units found.")

    return "\n".join(lines) if lines else "No init system configuration found."


# ---------------------------------------------------------------------------
# check_filesystem_permissions
# ---------------------------------------------------------------------------

# Sensitive paths where weak permissions matter most
_SENSITIVE_PATHS = {
    "etc/shadow", "etc/shadow-", "etc/gshadow",
    "etc/passwd", "etc/group",
    "etc/ssh", "etc/dropbear",
}

_SENSITIVE_PATTERNS = re.compile(
    r"(\.pem|\.key|\.crt|id_rsa|id_dsa|id_ecdsa|id_ed25519|"
    r"authorized_keys|\.htpasswd|\.env|credentials|secrets)"
)


async def _handle_check_filesystem_permissions(input: dict, context: ToolContext) -> str:
    """Check for world-writable files and weak permissions on sensitive files."""
    search_root = _walk_firmware(context.extracted_path, input.get("path"))
    real_root = os.path.realpath(context.extracted_path)

    world_writable: list[str] = []
    sensitive_weak: list[str] = []
    world_exec: list[str] = []

    for dirpath, dirs, files in safe_walk(search_root):
        for name in files + dirs:
            abs_path = os.path.join(dirpath, name)
            try:
                st = os.lstat(abs_path)
            except OSError:
                continue

            mode = st.st_mode
            rel = _rel(abs_path, real_root)
            perm_str = oct(mode)[-4:]

            # World-writable files (not symlinks)
            if stat.S_ISREG(mode) and (mode & stat.S_IWOTH):
                world_writable.append(f"  {perm_str}  {rel}")

            # World-writable directories without sticky bit
            if stat.S_ISDIR(mode) and (mode & stat.S_IWOTH) and not (mode & stat.S_ISVTX):
                world_writable.append(f"  {perm_str}  {rel}/  (no sticky bit)")

            # Sensitive files with loose permissions
            rel_stripped = rel.lstrip("/")
            is_sensitive = (
                rel_stripped in _SENSITIVE_PATHS
                or _SENSITIVE_PATTERNS.search(name)
            )
            if is_sensitive and stat.S_ISREG(mode):
                # Sensitive files should not be world-readable
                if mode & stat.S_IROTH:
                    sensitive_weak.append(
                        f"  {perm_str}  {rel}  (world-readable sensitive file)"
                    )
                # Private keys should be owner-only
                if name.endswith((".key", ".pem")) or name.startswith("id_"):
                    if (mode & 0o077) != 0:
                        sensitive_weak.append(
                            f"  {perm_str}  {rel}  (private key accessible by group/others)"
                        )

            total = len(world_writable) + len(sensitive_weak)
            if total >= MAX_RESULTS:
                break
        if len(world_writable) + len(sensitive_weak) >= MAX_RESULTS:
            break

    lines: list[str] = []

    if world_writable:
        lines.append(f"World-writable files/directories ({len(world_writable)}):")
        lines.append("  These can be modified by any user on the system.")
        lines.append("")
        lines.extend(world_writable[:50])
        lines.append("")

    if sensitive_weak:
        lines.append(f"Sensitive files with weak permissions ({len(sensitive_weak)}):")
        lines.append("")
        lines.extend(sensitive_weak[:50])
        lines.append("")

    if not lines:
        return "No obvious filesystem permission issues found."

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# analyze_certificate
# ---------------------------------------------------------------------------


def _find_cert_files(extracted_root: str, search_path: str | None) -> list[str]:
    """Find certificate files in the firmware filesystem."""
    real_root = os.path.realpath(extracted_root)
    cert_files: list[str] = []

    if search_path:
        # Scan a specific file or directory
        full_path = os.path.join(real_root, search_path.lstrip("/"))
        if os.path.isfile(full_path):
            return [full_path]
        if os.path.isdir(full_path):
            for dirpath, _dirs, files in safe_walk(full_path):
                for name in files:
                    _, ext = os.path.splitext(name)
                    if ext.lower() in _CERT_EXTENSIONS:
                        cert_files.append(os.path.join(dirpath, name))
                    elif _is_pem_file(os.path.join(dirpath, name)):
                        cert_files.append(os.path.join(dirpath, name))
            return cert_files

    # Scan known certificate directories
    for cert_dir in _CERT_SEARCH_DIRS:
        full_dir = os.path.join(real_root, cert_dir)
        if not os.path.isdir(full_dir):
            continue
        for dirpath, _dirs, files in safe_walk(full_dir):
            for name in files:
                abs_path = os.path.join(dirpath, name)
                _, ext = os.path.splitext(name)
                if ext.lower() in _CERT_EXTENSIONS:
                    cert_files.append(abs_path)
                elif _is_pem_file(abs_path):
                    cert_files.append(abs_path)

    # Also scan entire filesystem for cert extensions if nothing found yet
    if not cert_files:
        for dirpath, _dirs, files in safe_walk(real_root):
            for name in files:
                _, ext = os.path.splitext(name)
                if ext.lower() in _CERT_EXTENSIONS:
                    cert_files.append(os.path.join(dirpath, name))
                if len(cert_files) >= MAX_RESULTS:
                    break
            if len(cert_files) >= MAX_RESULTS:
                break

    return cert_files


def _is_pem_file(path: str) -> bool:
    """Quick check if a file looks like PEM format."""
    try:
        with open(path, "rb") as f:
            header = f.read(64)
        return b"-----BEGIN" in header
    except (OSError, PermissionError):
        return False


def _audit_certificate(cert_data: bytes, file_path: str, real_root: str) -> dict:
    """Parse and audit a single certificate. Returns a dict with info and issues."""
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa
    except ImportError:
        return {"error": "cryptography library not installed"}

    cert = None
    parse_error = None

    # Try PEM first, then DER
    try:
        cert = x509.load_pem_x509_certificate(cert_data)
    except Exception:
        try:
            cert = x509.load_der_x509_certificate(cert_data)
        except Exception as exc:
            parse_error = str(exc)

    if cert is None:
        return {"error": f"Failed to parse certificate: {parse_error}"}

    rel_path = "/" + os.path.relpath(file_path, real_root)
    now = datetime.now(timezone.utc)

    # Extract info
    info: dict = {
        "path": rel_path,
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "not_before": cert.not_valid_before_utc.isoformat(),
        "not_after": cert.not_valid_after_utc.isoformat(),
        "serial": str(cert.serial_number),
    }

    # Key info
    pub_key = cert.public_key()
    if isinstance(pub_key, rsa.RSAPublicKey):
        info["key_type"] = "RSA"
        info["key_size"] = pub_key.key_size
    elif isinstance(pub_key, ec.EllipticCurvePublicKey):
        info["key_type"] = "EC"
        info["key_size"] = pub_key.key_size
    elif isinstance(pub_key, dsa.DSAPublicKey):
        info["key_type"] = "DSA"
        info["key_size"] = pub_key.key_size
    else:
        info["key_type"] = type(pub_key).__name__
        info["key_size"] = 0

    # Signature algorithm
    info["signature_algorithm"] = cert.signature_algorithm_oid._name

    # Self-signed check
    info["self_signed"] = cert.issuer == cert.subject

    # SANs
    try:
        san_ext = cert.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        )
        info["sans"] = [str(n) for n in san_ext.value]
    except x509.ExtensionNotFound:
        info["sans"] = []

    # Wildcard check
    cn_values = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
    info["wildcard"] = any("*" in attr.value for attr in cn_values)

    # Security issues
    issues: list[dict] = []

    # Expired
    if now > cert.not_valid_after_utc:
        issues.append({
            "severity": "HIGH",
            "issue": f"Certificate expired on {cert.not_valid_after_utc.date()}",
        })

    # Not yet valid
    if now < cert.not_valid_before_utc:
        issues.append({
            "severity": "MEDIUM",
            "issue": f"Certificate not valid until {cert.not_valid_before_utc.date()}",
        })

    # Weak key size
    if info["key_type"] == "RSA" and info["key_size"] < 2048:
        issues.append({
            "severity": "HIGH",
            "issue": f"Weak RSA key size: {info['key_size']} bits (minimum 2048)",
        })

    # Weak signature algorithm
    sig_algo = info["signature_algorithm"].lower()
    if "md5" in sig_algo:
        issues.append({
            "severity": "CRITICAL",
            "issue": "MD5 signature algorithm (broken, trivially forgeable)",
        })
    elif "sha1" in sig_algo:
        issues.append({
            "severity": "HIGH",
            "issue": "SHA-1 signature algorithm (deprecated, collision attacks exist)",
        })

    # Self-signed
    if info["self_signed"]:
        issues.append({
            "severity": "MEDIUM",
            "issue": "Self-signed certificate (no third-party trust chain)",
        })

    # Wildcard
    if info["wildcard"]:
        issues.append({
            "severity": "LOW",
            "issue": "Wildcard certificate",
        })

    info["issues"] = issues
    return info


async def _handle_analyze_certificate(input: dict, context: ToolContext) -> str:
    """Parse and audit X.509 certificates found in the firmware."""
    real_root = os.path.realpath(context.extracted_path)
    search_path = input.get("path")

    # Find certificate files
    cert_files = _find_cert_files(context.extracted_path, search_path)

    if not cert_files:
        return "No certificate files found in the firmware filesystem."

    results: list[dict] = []
    for cert_file in cert_files[:MAX_RESULTS]:
        try:
            with open(cert_file, "rb") as f:
                cert_data = f.read(100_000)  # 100KB limit per cert
        except (OSError, PermissionError):
            continue

        result = _audit_certificate(cert_data, cert_file, real_root)
        if "error" not in result:
            results.append(result)

    if not results:
        return (
            f"Found {len(cert_files)} certificate file(s) but none could be parsed. "
            "Files may be in an unsupported format or corrupted."
        )

    # Build output
    total_issues = sum(len(r.get("issues", [])) for r in results)
    lines = [
        f"Analyzed {len(results)} certificate(s), {total_issues} issue(s) found:",
        "",
    ]

    for r in results:
        issues = r.get("issues", [])
        issue_summary = f"  [{len(issues)} issue(s)]" if issues else "  [OK]"
        lines.append(f"## {r['path']}{issue_summary}")
        lines.append(f"  Subject:    {r['subject']}")
        lines.append(f"  Issuer:     {r['issuer']}")
        lines.append(f"  Valid:      {r['not_before'][:10]} to {r['not_after'][:10]}")
        lines.append(f"  Key:        {r['key_type']} {r['key_size']} bits")
        lines.append(f"  Signature:  {r['signature_algorithm']}")
        if r.get("self_signed"):
            lines.append(f"  Self-signed: yes")
        if r.get("sans"):
            lines.append(f"  SANs:       {', '.join(r['sans'][:10])}")

        for issue in issues:
            lines.append(f"  [{issue['severity']}] {issue['issue']}")
        lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------


def register_security_tools(registry: ToolRegistry) -> None:
    """Register all security assessment tools with the given registry."""

    registry.register(
        name="check_known_cves",
        description=(
            "Look up known CVEs for a given software component and version. "
            "Covers common embedded Linux components: BusyBox, OpenSSL, "
            "Dropbear, dnsmasq, lighttpd, curl, uClibc, Linux kernel. "
            "Uses a local database — results are best-effort. "
            "Cross-reference with your own knowledge for completeness."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "component": {
                    "type": "string",
                    "description": "Software component name (e.g. 'busybox', 'openssl', 'dropbear')",
                },
                "version": {
                    "type": "string",
                    "description": "Version string (e.g. '1.33.0', '1.1.1k')",
                },
            },
            "required": ["component", "version"],
        },
        handler=_handle_check_known_cves,
    )

    registry.register(
        name="analyze_config_security",
        description=(
            "Analyze a configuration file for security issues. Checks for: "
            "empty passwords in /etc/shadow, extra UID-0 accounts in /etc/passwd, "
            "insecure SSH settings (root login, password auth, empty passwords), "
            "web server directory listing, debug mode flags, and default/weak "
            "passwords in config values. Works on any text config file."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Path to the configuration file to analyze (e.g. '/etc/shadow', '/etc/ssh/sshd_config')",
                },
            },
            "required": ["path"],
        },
        handler=_handle_analyze_config_security,
    )

    registry.register(
        name="check_setuid_binaries",
        description=(
            "Find all setuid and setgid binaries in the firmware filesystem. "
            "Setuid-root binaries are common privilege escalation targets. "
            "Returns file permissions, owner info, and paths."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Directory to scan (default: entire filesystem)",
                },
            },
            "required": [],
        },
        handler=_handle_check_setuid_binaries,
    )

    registry.register(
        name="analyze_init_scripts",
        description=(
            "Analyze init scripts, inittab, and systemd units to identify "
            "services started at boot. Flags security-relevant services: "
            "telnet (plaintext), FTP, TFTP (unauthenticated), UPnP, SNMP. "
            "Covers /etc/inittab, /etc/init.d/, /etc/rc.d/, and systemd units."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Root directory to scan (default: entire filesystem)",
                },
            },
            "required": [],
        },
        handler=_handle_analyze_init_scripts,
    )

    registry.register(
        name="check_filesystem_permissions",
        description=(
            "Check for filesystem permission issues: world-writable files "
            "and directories (without sticky bit), sensitive files with "
            "overly permissive access (shadow, private keys, credentials, "
            "SSH configs). Helps identify privilege escalation opportunities."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Directory to scan (default: entire filesystem)",
                },
            },
            "required": [],
        },
        handler=_handle_check_filesystem_permissions,
    )

    registry.register(
        name="analyze_certificate",
        description=(
            "Parse and audit X.509 certificates (PEM and DER format) found in "
            "the firmware. Reports subject, issuer, validity dates, key type and "
            "size, signature algorithm, SANs, and self-signed status. Flags "
            "security issues: expired certs, weak keys (<2048 RSA), weak "
            "signatures (MD5, SHA-1), self-signed certs, and wildcards. "
            "If no path given, scans /etc/ssl/, /etc/pki/, and common cert "
            "directories. Pass a file path to analyze a specific certificate."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": (
                        "Path to a certificate file or directory to scan. "
                        "If omitted, scans common certificate directories "
                        "(/etc/ssl/, /etc/pki/, etc.) and falls back to "
                        "scanning the entire filesystem by extension."
                    ),
                },
            },
            "required": [],
        },
        handler=_handle_analyze_certificate,
    )
