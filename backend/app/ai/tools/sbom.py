"""SBOM & vulnerability AI tools for firmware analysis.

Tools for generating Software Bill of Materials, listing identified
components, checking individual components for CVEs, and running
full vulnerability scans.
"""

import asyncio

from sqlalchemy import func, select

from app.ai.tool_registry import ToolContext, ToolRegistry
from app.models.sbom import SbomComponent, SbomVulnerability
from app.services.sbom_service import SbomService
from app.services.vulnerability_service import VulnerabilityService


def register_sbom_tools(registry: ToolRegistry) -> None:
    """Register all SBOM & vulnerability tools with the given registry."""

    registry.register(
        name="generate_sbom",
        description=(
            "Generate a Software Bill of Materials (SBOM) from the firmware "
            "filesystem. Identifies installed packages, libraries, kernel "
            "version, and binary components with their versions. Returns a "
            "text summary. Use this before running a vulnerability scan."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "force_rescan": {
                    "type": "boolean",
                    "description": "Force regeneration even if cached (default: false)",
                },
            },
        },
        handler=_handle_generate_sbom,
    )

    registry.register(
        name="get_sbom_components",
        description=(
            "List identified software components from the SBOM. "
            "Optionally filter by type (application, library, operating-system) "
            "or by name pattern. Returns component names, versions, and "
            "detection source. Requires generate_sbom to have been run first."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "type": {
                    "type": "string",
                    "enum": ["application", "library", "operating-system"],
                    "description": "Filter by component type",
                },
                "name_filter": {
                    "type": "string",
                    "description": "Filter by component name (partial match)",
                },
            },
        },
        handler=_handle_get_sbom_components,
    )

    registry.register(
        name="check_component_cves",
        description=(
            "Check a specific software component and version for known CVEs "
            "by querying the NVD (National Vulnerability Database). "
            "Use this for targeted CVE lookup on individual components. "
            "Requires internet access to NVD API. "
            "Note: rate-limited — use sparingly for specific components."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "component_name": {
                    "type": "string",
                    "description": "Component name (e.g. 'busybox', 'openssl', 'dropbear')",
                },
                "version": {
                    "type": "string",
                    "description": "Version string (e.g. '1.33.1', '1.1.1k')",
                },
            },
            "required": ["component_name", "version"],
        },
        handler=_handle_check_component_cves,
    )

    registry.register(
        name="run_vulnerability_scan",
        description=(
            "Run a full vulnerability scan on all SBOM components by "
            "querying the NVD for each component with a CPE identifier. "
            "Auto-creates security findings for components with critical/high "
            "CVEs. This can take 30-60+ seconds due to NVD rate limits. "
            "Requires generate_sbom to have been run first."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "force_rescan": {
                    "type": "boolean",
                    "description": "Force rescan even if results are cached (default: false)",
                },
            },
        },
        handler=_handle_run_vulnerability_scan,
    )


# ---------------------------------------------------------------------------
# Tool handlers
# ---------------------------------------------------------------------------


async def _handle_generate_sbom(input: dict, context: ToolContext) -> str:
    """Generate SBOM and return a text summary."""
    force_rescan = input.get("force_rescan", False)

    # Check for cached SBOM
    if not force_rescan:
        count = await context.db.scalar(
            select(func.count(SbomComponent.id)).where(
                SbomComponent.firmware_id == context.firmware_id
            )
        )
        if count and count > 0:
            return await _format_sbom_summary(context, cached=True)

    # Clear existing if rescan
    if force_rescan:
        existing = await context.db.execute(
            select(SbomComponent).where(
                SbomComponent.firmware_id == context.firmware_id
            )
        )
        for comp in existing.scalars().all():
            await context.db.delete(comp)
        await context.db.flush()

    # Run generation in executor (CPU-bound filesystem walk)
    service = SbomService(context.extracted_path)
    loop = asyncio.get_event_loop()
    try:
        component_dicts = await loop.run_in_executor(
            None, service.generate_sbom
        )
    except Exception as e:
        return f"Error generating SBOM: {e}"

    # Persist to database
    for comp_dict in component_dicts:
        db_comp = SbomComponent(
            firmware_id=context.firmware_id,
            name=comp_dict["name"],
            version=comp_dict["version"],
            type=comp_dict["type"],
            cpe=comp_dict["cpe"],
            purl=comp_dict["purl"],
            supplier=comp_dict["supplier"],
            detection_source=comp_dict["detection_source"],
            detection_confidence=comp_dict["detection_confidence"],
            file_paths=comp_dict["file_paths"],
            metadata_=comp_dict["metadata"],
        )
        context.db.add(db_comp)

    await context.db.commit()

    return await _format_sbom_summary(context, cached=False)


async def _format_sbom_summary(context: ToolContext, cached: bool) -> str:
    """Build a text summary of the SBOM."""
    # Count by type
    stmt = (
        select(SbomComponent.type, func.count(SbomComponent.id))
        .where(SbomComponent.firmware_id == context.firmware_id)
        .group_by(SbomComponent.type)
    )
    result = await context.db.execute(stmt)
    by_type = {row[0]: row[1] for row in result.all()}
    total = sum(by_type.values())

    lines = []
    cache_note = " (cached)" if cached else ""
    lines.append(f"SBOM generated{cache_note}: {total} components identified\n")

    lines.append("Components by type:")
    for comp_type, count in sorted(by_type.items()):
        lines.append(f"  {comp_type}: {count}")

    # List notable components (with versions and CPE)
    stmt = (
        select(SbomComponent)
        .where(
            SbomComponent.firmware_id == context.firmware_id,
            SbomComponent.version.isnot(None),
        )
        .order_by(SbomComponent.name)
        .limit(30)
    )
    result = await context.db.execute(stmt)
    notable = result.scalars().all()

    if notable:
        lines.append(f"\nNotable components with versions ({len(notable)}):")
        for comp in notable:
            cpe_tag = " [has CPE]" if comp.cpe else ""
            lines.append(
                f"  {comp.name} {comp.version} "
                f"({comp.detection_source}, {comp.detection_confidence}){cpe_tag}"
            )

    # Count components with CPE (scannable for CVEs)
    cpe_count = await context.db.scalar(
        select(func.count(SbomComponent.id)).where(
            SbomComponent.firmware_id == context.firmware_id,
            SbomComponent.cpe.isnot(None),
        )
    )
    lines.append(
        f"\n{cpe_count} component(s) have CPE identifiers and can be "
        f"scanned for known vulnerabilities using run_vulnerability_scan."
    )

    return "\n".join(lines)


async def _handle_get_sbom_components(
    input: dict, context: ToolContext
) -> str:
    """List SBOM components with optional filtering."""
    stmt = (
        select(SbomComponent)
        .where(SbomComponent.firmware_id == context.firmware_id)
        .order_by(SbomComponent.name)
    )

    type_filter = input.get("type")
    name_filter = input.get("name_filter")

    if type_filter:
        stmt = stmt.where(SbomComponent.type == type_filter)
    if name_filter:
        stmt = stmt.where(SbomComponent.name.ilike(f"%{name_filter}%"))

    stmt = stmt.limit(100)
    result = await context.db.execute(stmt)
    components = result.scalars().all()

    if not components:
        filters = []
        if type_filter:
            filters.append(f"type={type_filter}")
        if name_filter:
            filters.append(f"name contains '{name_filter}'")
        filter_str = f" (filters: {', '.join(filters)})" if filters else ""
        return f"No SBOM components found{filter_str}. Run generate_sbom first."

    lines = [f"Found {len(components)} component(s):\n"]
    for comp in components:
        version_str = f" {comp.version}" if comp.version else " (unknown version)"
        cpe_str = f"\n    CPE: {comp.cpe}" if comp.cpe else ""
        paths_str = ""
        if comp.file_paths:
            paths_str = f"\n    Files: {', '.join(comp.file_paths[:3])}"
            if len(comp.file_paths) > 3:
                paths_str += f" (+{len(comp.file_paths) - 3} more)"

        lines.append(
            f"- {comp.name}{version_str} [{comp.type}]"
            f"\n    Source: {comp.detection_source} ({comp.detection_confidence})"
            f"{cpe_str}{paths_str}"
        )

    return "\n".join(lines)


async def _handle_check_component_cves(
    input: dict, context: ToolContext
) -> str:
    """Check a specific component+version for CVEs via NVD."""
    component_name = input["component_name"].strip()
    version = input["version"].strip()

    # Try to find the component in the SBOM to get its CPE
    stmt = select(SbomComponent).where(
        SbomComponent.firmware_id == context.firmware_id,
        SbomComponent.name.ilike(f"%{component_name}%"),
    )
    result = await context.db.execute(stmt)
    comp = result.scalars().first()

    cpe = None
    if comp and comp.cpe:
        cpe = comp.cpe
    else:
        # Build a CPE from the component name
        from app.services.sbom_service import CPE_VENDOR_MAP

        vendor_product = CPE_VENDOR_MAP.get(component_name.lower())
        if vendor_product:
            cpe = f"cpe:2.3:a:{vendor_product[0]}:{vendor_product[1]}:{version}:*:*:*:*:*:*:*"

    if not cpe:
        return (
            f"Cannot look up CVEs for '{component_name}': no CPE identifier "
            f"available. Known components include: "
            + ", ".join(sorted(CPE_VENDOR_MAP.keys())[:20])
            + ". Use check_known_cves for offline local lookup instead."
        )

    # Query NVD
    try:
        from app.services.vulnerability_service import _search_nvd
        from app.config import get_settings

        settings = get_settings()
        api_key = settings.nvd_api_key or None

        loop = asyncio.get_event_loop()
        cves = await loop.run_in_executor(
            None,
            lambda: _search_nvd(cpe, api_key),
        )
    except Exception as e:
        return f"Error querying NVD for {component_name} {version}: {e}"

    if not cves:
        return (
            f"No known CVEs found for {component_name} {version} "
            f"(CPE: {cpe}) in the NVD."
        )

    lines = [
        f"Found {len(cves)} CVE(s) for {component_name} {version}:\n"
    ]

    for cve in cves[:25]:  # Cap display at 25
        cve_id = cve.id

        # Extract score
        score_str = ""
        if hasattr(cve, "score"):
            score_data = cve.score
            if isinstance(score_data, (list, tuple)) and len(score_data) >= 2:
                if score_data[1]:
                    score_str = f" (CVSS {score_data[1]})"

        # Extract description
        desc = ""
        if hasattr(cve, "descriptions"):
            for d in cve.descriptions:
                if hasattr(d, "lang") and d.lang == "en":
                    desc = d.value[:200]
                    break

        # Determine severity from score
        severity = "medium"
        if hasattr(cve, "score"):
            score_data = cve.score
            if isinstance(score_data, (list, tuple)) and len(score_data) >= 2 and score_data[1]:
                s = float(score_data[1])
                if s >= 9.0:
                    severity = "critical"
                elif s >= 7.0:
                    severity = "high"
                elif s >= 4.0:
                    severity = "medium"
                else:
                    severity = "low"

        lines.append(f"- [{severity.upper()}] {cve_id}{score_str}")
        if desc:
            lines.append(f"    {desc}")

    if len(cves) > 25:
        lines.append(f"\n... and {len(cves) - 25} more CVEs")

    return "\n".join(lines)


async def _handle_run_vulnerability_scan(
    input: dict, context: ToolContext
) -> str:
    """Run a full vulnerability scan on all SBOM components."""
    force_rescan = input.get("force_rescan", False)

    # Check SBOM exists
    comp_count = await context.db.scalar(
        select(func.count(SbomComponent.id)).where(
            SbomComponent.firmware_id == context.firmware_id
        )
    )
    if not comp_count:
        return (
            "No SBOM generated yet. Use generate_sbom first to identify "
            "firmware components."
        )

    vuln_svc = VulnerabilityService(context.db)
    try:
        summary = await vuln_svc.scan_components(
            firmware_id=context.firmware_id,
            project_id=context.project_id,
            force_rescan=force_rescan,
        )
    except Exception as e:
        return f"Vulnerability scan error: {e}"

    status = summary["status"]
    total_scanned = summary["total_components_scanned"]
    total_vulns = summary["total_vulnerabilities_found"]
    findings_created = summary["findings_created"]
    by_severity = summary["vulns_by_severity"]

    lines = []
    cache_note = " (cached results)" if status == "cached" else ""
    lines.append(
        f"Vulnerability scan complete{cache_note}\n"
    )
    lines.append(f"Components scanned (with CPE): {total_scanned}")
    lines.append(f"Total vulnerabilities found: {total_vulns}")

    if by_severity:
        lines.append("\nVulnerabilities by severity:")
        for sev in ("critical", "high", "medium", "low"):
            count = by_severity.get(sev, 0)
            if count:
                lines.append(f"  {sev.upper()}: {count}")

    if findings_created:
        lines.append(
            f"\n{findings_created} security finding(s) auto-created "
            f"for components with critical/high CVEs."
        )
    elif status != "cached":
        lines.append(
            "\nNo findings auto-created (no components with critical/high CVEs)."
        )

    if total_vulns > 0:
        lines.append(
            "\nUse get_sbom_components or list_findings to see details."
        )

    return "\n".join(lines)
