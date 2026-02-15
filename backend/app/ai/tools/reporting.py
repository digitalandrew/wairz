from app.ai.tool_registry import ToolContext, ToolRegistry
from app.models.finding import Finding
from app.schemas.finding import FindingCreate, FindingUpdate, Severity, FindingStatus
from app.services.finding_service import FindingService


def register_reporting_tools(registry: ToolRegistry) -> None:
    registry.register(
        name="add_finding",
        description=(
            "Record a security finding for the current firmware project. "
            "Use this whenever you identify a security issue, vulnerability, or notable concern. "
            "Severity levels: critical, high, medium, low, info."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "title": {
                    "type": "string",
                    "description": "Short descriptive title for the finding",
                },
                "severity": {
                    "type": "string",
                    "enum": ["critical", "high", "medium", "low", "info"],
                    "description": "Severity level of the finding",
                },
                "description": {
                    "type": "string",
                    "description": "Detailed description of the finding, including why it matters and potential impact",
                },
                "evidence": {
                    "type": "string",
                    "description": "Supporting evidence: command output, file contents, code snippets, etc.",
                },
                "file_path": {
                    "type": "string",
                    "description": "Filesystem path of the affected file (relative to firmware root)",
                },
                "line_number": {
                    "type": "integer",
                    "description": "Line number in the affected file, if applicable",
                },
                "cve_ids": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Associated CVE identifiers, e.g. ['CVE-2023-1234']",
                },
                "cwe_ids": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Associated CWE identifiers, e.g. ['CWE-798', 'CWE-259'] for hardcoded credentials",
                },
                "source": {
                    "type": "string",
                    "enum": ["ai_discovered", "manual", "sbom_scan", "fuzzing", "security_review"],
                    "description": "How this finding was discovered (default: ai_discovered)",
                },
            },
            "required": ["title", "severity", "description"],
        },
        handler=_handle_add_finding,
    )

    registry.register(
        name="list_findings",
        description=(
            "List all security findings recorded for the current project. "
            "Optionally filter by severity or status."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "severity": {
                    "type": "string",
                    "enum": ["critical", "high", "medium", "low", "info"],
                    "description": "Filter by severity level",
                },
                "status": {
                    "type": "string",
                    "enum": ["open", "confirmed", "false_positive", "fixed"],
                    "description": "Filter by finding status",
                },
            },
        },
        handler=_handle_list_findings,
    )

    registry.register(
        name="update_finding",
        description=(
            "Update an existing finding's status or details. "
            "Use this to mark findings as confirmed, false_positive, or fixed, "
            "or to refine the description/evidence."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "finding_id": {
                    "type": "string",
                    "description": "UUID of the finding to update",
                },
                "status": {
                    "type": "string",
                    "enum": ["open", "confirmed", "false_positive", "fixed"],
                    "description": "New status for the finding",
                },
                "description": {
                    "type": "string",
                    "description": "Updated description",
                },
                "evidence": {
                    "type": "string",
                    "description": "Updated or additional evidence",
                },
            },
            "required": ["finding_id"],
        },
        handler=_handle_update_finding,
    )


async def _handle_add_finding(input: dict, context: ToolContext) -> str:
    svc = FindingService(context.db)
    data = FindingCreate(
        title=input["title"],
        severity=Severity(input["severity"]),
        description=input.get("description"),
        evidence=input.get("evidence"),
        file_path=input.get("file_path"),
        line_number=input.get("line_number"),
        cve_ids=input.get("cve_ids"),
        cwe_ids=input.get("cwe_ids"),
        source=input.get("source", "ai_discovered"),
    )
    finding = await svc.create(context.project_id, data)
    await context.db.commit()
    return (
        f"Finding recorded: {finding.title} [{finding.severity}] "
        f"(ID: {finding.id})"
    )


async def _handle_list_findings(input: dict, context: ToolContext) -> str:
    svc = FindingService(context.db)
    findings = await svc.list_by_project(
        context.project_id,
        severity=input.get("severity"),
        status=input.get("status"),
    )
    if not findings:
        return "No findings recorded for this project."

    lines = [f"Found {len(findings)} finding(s):\n"]
    for f in findings:
        status_badge = f"[{f.status}]" if f.status != "open" else ""
        file_info = f" in {f.file_path}" if f.file_path else ""
        lines.append(
            f"- [{f.severity.upper()}] {f.title}{file_info} {status_badge} (ID: {f.id})"
        )
    return "\n".join(lines)


async def _handle_update_finding(input: dict, context: ToolContext) -> str:
    import uuid

    svc = FindingService(context.db)
    finding_id = uuid.UUID(input["finding_id"])
    finding = await svc.get(finding_id)
    if not finding or finding.project_id != context.project_id:
        return f"Error: Finding {input['finding_id']} not found in this project."

    update_fields = {}
    if "status" in input:
        update_fields["status"] = FindingStatus(input["status"])
    if "description" in input:
        update_fields["description"] = input["description"]
    if "evidence" in input:
        update_fields["evidence"] = input["evidence"]

    if not update_fields:
        return "No fields to update."

    data = FindingUpdate(**update_fields)
    updated = await svc.update(finding_id, data)
    await context.db.commit()
    return f"Finding updated: {updated.title} [{updated.severity}] — status: {updated.status}"
