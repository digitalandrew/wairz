# Security Assessment

Wairz provides automated security checks for common firmware vulnerabilities and misconfigurations.

## Hardcoded Credentials

Scan the firmware for hardcoded passwords, API keys, tokens, and other credentials:

- `/etc/shadow` and `/etc_ro/shadow` — Hash type identification (DES, MD5, SHA-256, SHA-512), weak hash flagging, and cracking against common default passwords (admin, root, password, 1234, etc.)
- `/etc/passwd` and `/etc_ro/passwd` — UID-0 non-root accounts, empty password fields with login shells
- Filesystem scan — Password/secret/token assignments in text files

Results are ranked by Shannon entropy to surface the most likely real credentials.

## Cryptographic Material

Scan for private keys, certificates, public keys, SSH keys, and files with crypto-related extensions (`.pem`, `.key`, `.crt`, etc.). Also checks file contents for PEM headers.

## Certificate Analysis

Parse and audit X.509 certificates (PEM and DER format):

- Subject, issuer, validity dates, key type and size, signature algorithm
- Flags: expired certs, weak keys (<2048 RSA), weak signatures (MD5, SHA-1), self-signed certs, wildcards

## Setuid/Setgid Binaries

Find all setuid and setgid binaries in the firmware. Setuid-root binaries are common privilege escalation targets.

## Configuration Security

Analyze configuration files for security issues:

- Empty passwords in `/etc/shadow`
- Extra UID-0 accounts in `/etc/passwd`
- Insecure SSH settings (root login, password auth, empty passwords)
- Web server directory listing
- Debug mode flags
- Default/weak passwords

## Init Script Analysis

Analyze init scripts, inittab, and systemd units to identify services started at boot. Flags security-relevant services:

- Telnet (plaintext credentials)
- FTP / TFTP (unauthenticated file transfer)
- UPnP (attack surface)
- SNMP (information disclosure)

## Filesystem Permissions

Check for permission issues:

- World-writable files and directories (without sticky bit)
- Sensitive files with overly permissive access (shadow, private keys, credentials, SSH configs)

## MCP Tools

| Tool | Description |
|------|-------------|
| `find_hardcoded_credentials` | Scan for passwords, keys, tokens |
| `find_crypto_material` | Find private keys and certificates |
| `analyze_certificate` | Audit X.509 certificates |
| `check_setuid_binaries` | Find setuid/setgid binaries |
| `analyze_config_security` | Audit configuration files |
| `analyze_init_scripts` | Analyze boot services |
| `check_filesystem_permissions` | Find permission issues |
| `check_known_cves` | Look up CVEs for a component |
