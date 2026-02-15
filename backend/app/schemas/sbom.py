import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class SbomComponentResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    firmware_id: uuid.UUID
    name: str
    version: str | None
    type: str
    cpe: str | None
    purl: str | None
    supplier: str | None
    detection_source: str
    detection_confidence: str | None
    file_paths: list[str] | None
    metadata: dict = Field(alias="metadata_", default={})
    vulnerability_count: int = 0
    created_at: datetime


class SbomGenerateResponse(BaseModel):
    components: list[SbomComponentResponse]
    total: int
    cached: bool


class SbomVulnerabilityResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    component_id: uuid.UUID
    cve_id: str
    cvss_score: float | None
    cvss_vector: str | None
    severity: str
    description: str | None
    published_date: datetime | None
    finding_id: uuid.UUID | None
    component_name: str | None = None
    component_version: str | None = None


class VulnerabilityScanRequest(BaseModel):
    force_rescan: bool = False


class VulnerabilityScanResponse(BaseModel):
    status: str
    total_components_scanned: int
    total_vulnerabilities_found: int
    findings_created: int
    vulns_by_severity: dict[str, int]


class SbomSummaryResponse(BaseModel):
    total_components: int
    components_by_type: dict[str, int]
    components_with_vulns: int
    total_vulnerabilities: int
    vulns_by_severity: dict[str, int]
    scan_date: datetime | None
