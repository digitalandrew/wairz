"""REST endpoints for SBOM generation, component listing, vulnerability scanning, and export."""

import asyncio
import json
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.sbom import SbomComponent, SbomVulnerability
from app.schemas.sbom import (
    SbomComponentResponse,
    SbomGenerateResponse,
    SbomSummaryResponse,
    SbomVulnerabilityResponse,
    VulnerabilityScanResponse,
)
from app.services.firmware_service import FirmwareService
from app.services.sbom_service import SbomService
from app.services.vulnerability_service import VulnerabilityService

router = APIRouter(
    prefix="/api/v1/projects/{project_id}/sbom",
    tags=["sbom"],
)


async def _resolve_firmware(
    project_id: uuid.UUID,
    firmware_id: uuid.UUID | None = Query(None, description="Specific firmware ID (defaults to first)"),
    db: AsyncSession = Depends(get_db),
):
    """Resolve project -> firmware, return firmware record."""
    svc = FirmwareService(db)
    if firmware_id:
        firmware = await svc.get_by_id(firmware_id)
        if not firmware or firmware.project_id != project_id:
            raise HTTPException(404, "Firmware not found")
    else:
        firmware = await svc.get_by_project(project_id)
        if not firmware:
            raise HTTPException(404, "No firmware uploaded for this project")
    if not firmware.extracted_path:
        raise HTTPException(400, "Firmware not yet unpacked")
    return firmware


async def _get_components_with_vuln_counts(
    db: AsyncSession,
    firmware_id: uuid.UUID,
    type_filter: str | None = None,
    name_filter: str | None = None,
) -> list[SbomComponentResponse]:
    """Load SBOM components with vulnerability counts."""
    # Subquery for vulnerability counts
    vuln_count_sq = (
        select(
            SbomVulnerability.component_id,
            func.count(SbomVulnerability.id).label("vuln_count"),
        )
        .group_by(SbomVulnerability.component_id)
        .subquery()
    )

    stmt = (
        select(SbomComponent, vuln_count_sq.c.vuln_count)
        .outerjoin(vuln_count_sq, SbomComponent.id == vuln_count_sq.c.component_id)
        .where(SbomComponent.firmware_id == firmware_id)
        .order_by(SbomComponent.name)
    )

    if type_filter:
        stmt = stmt.where(SbomComponent.type == type_filter)
    if name_filter:
        stmt = stmt.where(SbomComponent.name.ilike(f"%{name_filter}%"))

    result = await db.execute(stmt)
    rows = result.all()

    responses = []
    for row in rows:
        comp = row[0]
        vuln_count = row[1] or 0
        resp = SbomComponentResponse.model_validate(comp)
        resp.vulnerability_count = vuln_count
        responses.append(resp)
    return responses


@router.post("/generate", response_model=SbomGenerateResponse)
async def generate_sbom(
    force_rescan: bool = Query(False),
    firmware=Depends(_resolve_firmware),
    db: AsyncSession = Depends(get_db),
):
    """Generate SBOM from extracted firmware filesystem.

    Returns cached results unless force_rescan=True.
    """
    # Check if SBOM already exists
    if not force_rescan:
        stmt = select(func.count(SbomComponent.id)).where(
            SbomComponent.firmware_id == firmware.id
        )
        result = await db.execute(stmt)
        count = result.scalar()
        if count and count > 0:
            components = await _get_components_with_vuln_counts(db, firmware.id)
            return SbomGenerateResponse(
                components=components,
                total=len(components),
                cached=True,
            )

    # Clear existing components if force_rescan
    if force_rescan:
        stmt = select(SbomComponent).where(SbomComponent.firmware_id == firmware.id)
        result = await db.execute(stmt)
        existing = result.scalars().all()
        for comp in existing:
            await db.delete(comp)
        await db.flush()

    # Run SBOM generation (CPU-bound, run in thread)
    service = SbomService(firmware.extracted_path)
    loop = asyncio.get_event_loop()
    try:
        component_dicts = await loop.run_in_executor(None, service.generate_sbom)
    except Exception as e:
        raise HTTPException(500, f"Failed to generate SBOM: {e}")

    # Persist to database
    for comp_dict in component_dicts:
        db_comp = SbomComponent(
            firmware_id=firmware.id,
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
        db.add(db_comp)

    await db.commit()

    # Return with vuln counts
    components = await _get_components_with_vuln_counts(db, firmware.id)
    return SbomGenerateResponse(
        components=components,
        total=len(components),
        cached=False,
    )


@router.get("", response_model=list[SbomComponentResponse])
async def list_sbom_components(
    type: str | None = Query(None, description="Filter by component type"),
    name: str | None = Query(None, description="Filter by component name (partial match)"),
    firmware=Depends(_resolve_firmware),
    db: AsyncSession = Depends(get_db),
):
    """List SBOM components for a project's firmware."""
    return await _get_components_with_vuln_counts(
        db, firmware.id, type_filter=type, name_filter=name
    )


@router.get("/export")
async def export_sbom(
    format: str = Query("cyclonedx-json", pattern="^(cyclonedx-json)$"),
    firmware=Depends(_resolve_firmware),
    db: AsyncSession = Depends(get_db),
):
    """Export SBOM in CycloneDX JSON format."""
    stmt = select(SbomComponent).where(SbomComponent.firmware_id == firmware.id)
    result = await db.execute(stmt)
    components = result.scalars().all()

    if not components:
        raise HTTPException(404, "No SBOM generated yet. Run POST /generate first.")

    # Build CycloneDX 1.5 JSON manually
    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tools": [
                {
                    "vendor": "wairz",
                    "name": "wairz-sbom",
                    "version": "0.1.0",
                }
            ],
            "component": {
                "type": "firmware",
                "name": firmware.original_filename or "unknown",
                "version": "1.0",
            },
        },
        "components": [],
    }

    for comp in components:
        cdx_comp: dict = {
            "type": _map_type_to_cyclonedx(comp.type),
            "name": comp.name,
        }
        if comp.version:
            cdx_comp["version"] = comp.version
        if comp.purl:
            cdx_comp["purl"] = comp.purl
        if comp.cpe:
            cdx_comp["cpe"] = comp.cpe
        if comp.supplier:
            cdx_comp["supplier"] = {"name": comp.supplier}

        bom["components"].append(cdx_comp)

    content = json.dumps(bom, indent=2)
    return Response(
        content=content,
        media_type="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="sbom-{firmware.id}.cdx.json"'
        },
    )


# ---------------------------------------------------------------------------
# Vulnerability Scanning Endpoints
# ---------------------------------------------------------------------------


@router.post("/vulnerabilities/scan", response_model=VulnerabilityScanResponse)
async def scan_vulnerabilities(
    project_id: uuid.UUID,
    force_rescan: bool = Query(False),
    firmware=Depends(_resolve_firmware),
    db: AsyncSession = Depends(get_db),
):
    """Trigger a vulnerability scan against NVD for all SBOM components.

    Queries the NVD API for each component with a CPE identifier.
    Auto-creates findings with source='sbom_scan' for components with
    critical/high CVEs. Can take 30-60+ seconds for large SBOMs due to
    NVD rate limits.
    """
    # Ensure SBOM exists
    comp_count = await db.scalar(
        select(func.count(SbomComponent.id)).where(
            SbomComponent.firmware_id == firmware.id
        )
    )
    if not comp_count:
        raise HTTPException(
            400, "No SBOM generated yet. Run POST /generate first."
        )

    vuln_svc = VulnerabilityService(db)
    try:
        summary = await vuln_svc.scan_components(
            firmware_id=firmware.id,
            project_id=project_id,
            force_rescan=force_rescan,
        )
    except Exception as e:
        raise HTTPException(500, f"Vulnerability scan failed: {e}")

    return VulnerabilityScanResponse(**summary)


@router.get(
    "/vulnerabilities", response_model=list[SbomVulnerabilityResponse]
)
async def list_vulnerabilities(
    severity: str | None = Query(None, description="Filter by severity"),
    component_id: uuid.UUID | None = Query(
        None, description="Filter by component ID"
    ),
    cve_id: str | None = Query(None, description="Filter by CVE ID"),
    firmware=Depends(_resolve_firmware),
    db: AsyncSession = Depends(get_db),
):
    """List vulnerability matches for this firmware's SBOM."""
    stmt = (
        select(SbomVulnerability, SbomComponent.name, SbomComponent.version)
        .join(
            SbomComponent,
            SbomVulnerability.component_id == SbomComponent.id,
        )
        .where(SbomVulnerability.firmware_id == firmware.id)
        .order_by(SbomVulnerability.cvss_score.desc().nullslast())
    )

    if severity:
        stmt = stmt.where(SbomVulnerability.severity == severity)
    if component_id:
        stmt = stmt.where(SbomVulnerability.component_id == component_id)
    if cve_id:
        stmt = stmt.where(SbomVulnerability.cve_id == cve_id)

    result = await db.execute(stmt)
    rows = result.all()

    responses = []
    for vuln, comp_name, comp_version in rows:
        resp = SbomVulnerabilityResponse.model_validate(vuln)
        resp.component_name = comp_name
        resp.component_version = comp_version
        responses.append(resp)

    return responses


@router.get("/vulnerabilities/summary", response_model=SbomSummaryResponse)
async def vulnerability_summary(
    firmware=Depends(_resolve_firmware),
    db: AsyncSession = Depends(get_db),
):
    """Get aggregated vulnerability and SBOM statistics."""
    vuln_svc = VulnerabilityService(db)
    summary = await vuln_svc.get_vulnerability_summary(firmware.id)
    return SbomSummaryResponse(**summary)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _map_type_to_cyclonedx(comp_type: str) -> str:
    """Map our component type to CycloneDX component type."""
    mapping = {
        "application": "application",
        "library": "library",
        "operating-system": "operating-system",
        "firmware": "firmware",
    }
    return mapping.get(comp_type, "application")
