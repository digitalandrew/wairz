from app.ai.tool_registry import ToolRegistry
from app.ai.tools.binary import register_binary_tools
from app.ai.tools.comparison import register_comparison_tools
from app.ai.tools.documents import register_document_tools
from app.ai.tools.emulation import register_emulation_tools
from app.ai.tools.fuzzing import register_fuzzing_tools
from app.ai.tools.filesystem import register_filesystem_tools
from app.ai.tools.reporting import register_reporting_tools
from app.ai.tools.sbom import register_sbom_tools
from app.ai.tools.security import register_security_tools
from app.ai.tools.strings import register_string_tools
from app.ai.tools.uart import register_uart_tools


def create_tool_registry() -> ToolRegistry:
    """Create a ToolRegistry with all available tools registered."""
    registry = ToolRegistry()
    register_filesystem_tools(registry)
    register_string_tools(registry)
    register_binary_tools(registry)
    register_security_tools(registry)
    register_reporting_tools(registry)
    register_document_tools(registry)
    register_sbom_tools(registry)
    register_emulation_tools(registry)
    register_fuzzing_tools(registry)
    register_comparison_tools(registry)
    register_uart_tools(registry)
    return registry
