import uuid

from sqlalchemy import select

from app.ai.tool_registry import ToolContext, ToolRegistry
from app.models.document import Document
from app.services.document_service import DocumentService


def register_document_tools(registry: ToolRegistry) -> None:
    registry.register(
        name="read_project_instructions",
        description=(
            "Read the WAIRZ.md project instructions file. "
            "This file contains project-specific instructions, context, and notes "
            "provided by the user to guide your analysis. "
            "You should call this tool at the start of each session to check for "
            "any special instructions before beginning work."
        ),
        input_schema={
            "type": "object",
            "properties": {},
        },
        handler=_handle_read_instructions,
    )

    registry.register(
        name="list_project_documents",
        description=(
            "List all supplementary documents uploaded to the current project. "
            "These may include scope documents, Rules of Engagement, prior reports, "
            "or other reference materials provided by the user."
        ),
        input_schema={
            "type": "object",
            "properties": {},
        },
        handler=_handle_list_documents,
    )

    registry.register(
        name="read_project_document",
        description=(
            "Read the text content of a project document by its ID. "
            "For PDF files, text is extracted automatically. "
            "Use list_project_documents first to see available documents and their IDs."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "document_id": {
                    "type": "string",
                    "description": "UUID of the document to read",
                },
            },
            "required": ["document_id"],
        },
        handler=_handle_read_document,
    )


async def _handle_read_instructions(input: dict, context: ToolContext) -> str:
    result = await context.db.execute(
        select(Document).where(
            Document.project_id == context.project_id,
            Document.original_filename == "WAIRZ.md",
        )
    )
    document = result.scalar_one_or_none()
    if document is None:
        return (
            "No WAIRZ.md instructions file found for this project. "
            "The user has not provided any project-specific instructions."
        )

    content = DocumentService.read_text_content(document)
    return (
        "=== Project Instructions (WAIRZ.md) ===\n\n"
        f"{content}\n\n"
        "=== End Project Instructions ===\n\n"
        "Follow these instructions as they apply to your analysis."
    )


async def _handle_list_documents(input: dict, context: ToolContext) -> str:
    svc = DocumentService(context.db)
    documents = await svc.list_by_project(context.project_id)
    if not documents:
        return "No documents have been uploaded to this project."

    lines = [f"Found {len(documents)} project document(s):\n"]
    for doc in documents:
        desc = f" — {doc.description}" if doc.description else ""
        size_kb = doc.file_size / 1024
        lines.append(
            f"- {doc.original_filename}{desc} "
            f"({size_kb:.1f} KB, {doc.content_type}) "
            f"(ID: {doc.id})"
        )
    return "\n".join(lines)


async def _handle_read_document(input: dict, context: ToolContext) -> str:
    doc_id_str = input.get("document_id", "")
    try:
        doc_id = uuid.UUID(doc_id_str)
    except (ValueError, AttributeError):
        return f"Error: Invalid document ID: {doc_id_str}"

    svc = DocumentService(context.db)
    document = await svc.get(doc_id)
    if not document or document.project_id != context.project_id:
        return f"Error: Document {doc_id_str} not found in this project."

    content = svc.read_text_content(document)

    header = (
        f"Document: {document.original_filename}\n"
        f"Type: {document.content_type}\n"
        f"Size: {document.file_size} bytes\n"
    )
    if document.description:
        header += f"Description: {document.description}\n"
    header += "---\n"

    return header + content
