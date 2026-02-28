# SBOM & CVE Scanning

Wairz can generate a Software Bill of Materials (SBOM) from firmware and scan identified components against the National Vulnerability Database (NVD) for known CVEs.

## Generating an SBOM

The SBOM generator identifies installed packages, libraries, kernel version, and binary components with their versions by analyzing the firmware filesystem. The output follows the CycloneDX format.

Detection methods include:

- Package manager databases (opkg, dpkg)
- Binary version strings
- Library version patterns
- Kernel version from boot images

## Viewing Components

After generating an SBOM, browse identified components filtered by:

- **Type** — Application, library, or operating system
- **Name** — Search by component name

Each component shows its name, version, and how it was detected.

## CVE Scanning

### Individual Component Lookup

Check a specific component and version against the NVD:

```
Component: busybox
Version: 1.33.1
```

This queries the NVD API for matching CVEs and returns severity ratings, descriptions, and CVE IDs.

### Full Vulnerability Scan

Run a scan across all SBOM components with CPE identifiers. The scan:

1. Queries the NVD for each component
2. Matches against CPE entries
3. Auto-creates security findings for components with critical/high CVEs

!!! note
    Full scans may take 30-60+ seconds due to NVD API rate limits. An optional `NVD_API_KEY` environment variable enables higher rate limits.

## MCP Tools

| Tool | Description |
|------|-------------|
| `generate_sbom` | Generate SBOM from firmware filesystem |
| `get_sbom_components` | List identified components |
| `check_component_cves` | Check one component against NVD |
| `run_vulnerability_scan` | Full scan of all SBOM components |
