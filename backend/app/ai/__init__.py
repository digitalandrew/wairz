from app.ai.tool_registry import ToolRegistry
from app.ai.tools.filesystem import register_filesystem_tools


def create_tool_registry() -> ToolRegistry:
    """Create a ToolRegistry with all available tools registered."""
    registry = ToolRegistry()
    register_filesystem_tools(registry)
    return registry
