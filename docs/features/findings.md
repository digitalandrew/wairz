# Findings & Reports

Wairz provides a structured system for recording security findings during firmware analysis and exporting them as reports.

## Recording Findings

Create findings with:

- **Title** — Short descriptive summary
- **Severity** — Critical, High, Medium, Low, or Info
- **Description** — Detailed explanation including why it matters and potential impact
- **Evidence** — Supporting data: command output, file contents, code snippets
- **File path** — The affected file in the firmware filesystem
- **Line number** — Specific line in the affected file
- **CWE IDs** — Associated Common Weakness Enumeration identifiers (e.g., CWE-798 for hardcoded credentials)
- **CVE IDs** — Associated Common Vulnerabilities and Exposures identifiers

## Finding Status

Findings progress through these states:

| Status | Description |
|--------|-------------|
| `open` | Newly created, not yet verified |
| `confirmed` | Verified as a real issue |
| `false_positive` | Determined to be a non-issue |
| `fixed` | Issue has been resolved |

## AI-Discovered Findings

When Claude analyzes firmware via MCP, it can automatically create findings as it discovers issues. Each finding includes:

- The source marked as `ai_discovered`
- Detailed evidence from the analysis tools
- Appropriate severity based on the vulnerability type
- Relevant CWE identifiers

## Export

Export findings as reports for documentation and sharing. Available formats include Markdown and PDF.

## MCP Tools

| Tool | Description |
|------|-------------|
| `add_finding` | Record a new security finding |
| `list_findings` | List all findings (filter by severity/status) |
| `update_finding` | Update status or details |
| `read_project_instructions` | Read project-specific analysis instructions |
| `list_project_documents` | List supplementary project documents |
| `read_project_document` | Read a project document by ID |
