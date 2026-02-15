from sqlalchemy import select

from app.ai.tool_registry import ToolContext, ToolRegistry
from app.models.security_review import ReviewAgent


def register_review_tools(registry: ToolRegistry) -> None:
    registry.register(
        name="write_scratchpad",
        description=(
            "Write or append to your scratchpad. Use this to record your analysis notes, "
            "summaries, and observations so other agents can reference them. "
            "Other agents can read your scratchpad via read_agent_scratchpads."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "content": {
                    "type": "string",
                    "description": "Content to write to the scratchpad. Replaces any existing content.",
                },
                "append": {
                    "type": "boolean",
                    "description": "If true, append to existing scratchpad content instead of replacing. Default: false.",
                },
            },
            "required": ["content"],
        },
        handler=_handle_write_scratchpad,
    )

    registry.register(
        name="read_agent_scratchpads",
        description=(
            "Read scratchpads from other agents in this security review. "
            "Use this to understand what other agents have found and which areas "
            "they've already analyzed. Returns scratchpad content from all agents "
            "that have written to theirs."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "category": {
                    "type": "string",
                    "description": "Optionally read only a specific agent's scratchpad by category name.",
                },
            },
        },
        handler=_handle_read_scratchpads,
    )


async def _handle_write_scratchpad(input: dict, context: ToolContext) -> str:
    if not context.review_agent_id:
        return "Error: write_scratchpad is only available during a security review."

    result = await context.db.execute(
        select(ReviewAgent).where(ReviewAgent.id == context.review_agent_id)
    )
    agent = result.scalar_one_or_none()
    if not agent:
        return "Error: agent not found."

    content = input["content"]
    if input.get("append") and agent.scratchpad:
        agent.scratchpad = agent.scratchpad + "\n\n" + content
    else:
        agent.scratchpad = content

    await context.db.flush()
    return f"Scratchpad updated ({len(agent.scratchpad)} chars)."


async def _handle_read_scratchpads(input: dict, context: ToolContext) -> str:
    if not context.review_id:
        return "Error: read_agent_scratchpads is only available during a security review."

    stmt = select(ReviewAgent).where(ReviewAgent.review_id == context.review_id)

    category = input.get("category")
    if category:
        stmt = stmt.where(ReviewAgent.category == category)

    result = await context.db.execute(stmt)
    agents = list(result.scalars().all())

    if not agents:
        return "No agents found."

    parts = []
    for agent in agents:
        if agent.id == context.review_agent_id:
            continue  # Skip self
        if not agent.scratchpad:
            parts.append(f"## {agent.category} ({agent.status})\n[No scratchpad content yet]")
        else:
            parts.append(f"## {agent.category} ({agent.status})\n{agent.scratchpad}")

    if not parts:
        return "No other agent scratchpads available yet."

    return "\n\n---\n\n".join(parts)
