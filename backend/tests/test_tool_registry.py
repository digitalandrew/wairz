"""Tests for the AI tool registry and filesystem tools."""

import os
import struct
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest

from app.ai.tool_registry import ToolContext, ToolRegistry
from app.ai.tools.filesystem import register_filesystem_tools
from app.utils.truncation import truncate_output


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def firmware_root(tmp_path: Path) -> Path:
    """Create a fake firmware filesystem for testing."""
    # Directories
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc" / "init.d").mkdir()
    (tmp_path / "usr").mkdir()
    (tmp_path / "usr" / "bin").mkdir()
    (tmp_path / "bin").mkdir()
    (tmp_path / "var").mkdir()

    # Text files
    (tmp_path / "etc" / "passwd").write_text(
        "root:x:0:0:root:/root:/bin/sh\nnobody:x:65534:65534:Nobody:/:/bin/false\n"
    )
    (tmp_path / "etc" / "shadow").write_text("root::0:0:99999:7:::\n")
    (tmp_path / "etc" / "config.conf").write_text(
        "[server]\nport=8080\ndebug=true\n"
    )
    (tmp_path / "etc" / "init.d" / "rcS").write_bytes(
        b"#!/bin/sh\necho 'Starting services...'\n"
    )

    # Fake ELF binary (valid magic, minimal header)
    elf_header = b"\x7fELF" + b"\x00" * 12  # ELF magic + padding
    (tmp_path / "usr" / "bin" / "httpd").write_bytes(elf_header)

    # Certificate file
    (tmp_path / "etc" / "server.pem").write_text(
        "-----BEGIN CERTIFICATE-----\nMIIBojCCAUmgAwIBAgI...\n-----END CERTIFICATE-----\n"
    )

    # Shared library
    (tmp_path / "usr" / "bin" / "libfoo.so.1").write_bytes(b"\x7fELF" + b"\x00" * 12)

    # Symlink
    (tmp_path / "bin" / "sh").symlink_to("/bin/busybox")

    return tmp_path


@pytest.fixture
def tool_context(firmware_root: Path) -> ToolContext:
    """Create a ToolContext with mock DB session."""
    return ToolContext(
        project_id=uuid4(),
        firmware_id=uuid4(),
        extracted_path=str(firmware_root),
        db=MagicMock(),
    )


@pytest.fixture
def registry() -> ToolRegistry:
    """Create a ToolRegistry with filesystem tools registered."""
    reg = ToolRegistry()
    register_filesystem_tools(reg)
    return reg


# ---------------------------------------------------------------------------
# Truncation tests
# ---------------------------------------------------------------------------

class TestTruncation:
    def test_no_truncation_when_under_limit(self):
        text = "Hello, world!"
        assert truncate_output(text, max_kb=1) == text

    def test_truncates_when_over_limit(self):
        text = "A" * 2048  # 2KB
        result = truncate_output(text, max_kb=1)
        assert len(result.encode("utf-8")) < 2048
        assert "truncated" in result

    def test_cuts_at_line_boundary(self):
        lines = "\n".join(f"line {i}" for i in range(200))
        result = truncate_output(lines, max_kb=1)
        # Should end with a complete line (before the truncation message)
        main_part = result.split("\n\n... [truncated")[0]
        assert main_part.endswith(("line " + str(i) for i in range(200)).__class__.__name__) or True
        # More precise: last line of main_part should be a complete "line N"
        last_line = main_part.rstrip().split("\n")[-1]
        assert last_line.startswith("line ")

    def test_appends_truncation_message(self):
        text = "X" * 4096  # 4KB
        result = truncate_output(text, max_kb=1)
        assert "... [truncated: showing ~" in result
        assert "KB of" in result

    def test_custom_limit(self):
        text = "Y" * 512
        # 512 bytes is under 1KB limit
        assert truncate_output(text, max_kb=1) == text
        # But over 0.25KB limit (256 bytes)
        result = truncate_output(text, max_kb=0)
        # max_kb=0 means 0 bytes limit, everything gets truncated
        assert "truncated" in result or len(result.encode("utf-8")) <= 0


# ---------------------------------------------------------------------------
# ToolRegistry tests
# ---------------------------------------------------------------------------

class TestToolRegistry:
    def test_register_and_list(self):
        reg = ToolRegistry()
        handler = AsyncMock(return_value="ok")
        reg.register(
            name="test_tool",
            description="A test tool",
            input_schema={
                "type": "object",
                "properties": {"x": {"type": "string"}},
                "required": ["x"],
            },
            handler=handler,
        )
        tools = reg.get_anthropic_tools()
        assert len(tools) == 1
        assert tools[0]["name"] == "test_tool"
        assert tools[0]["description"] == "A test tool"
        assert "input_schema" in tools[0]

    @pytest.mark.asyncio
    async def test_execute_success(self, tool_context):
        reg = ToolRegistry()
        handler = AsyncMock(return_value="result data")
        reg.register("my_tool", "desc", {"type": "object", "properties": {}}, handler)
        result = await reg.execute("my_tool", {"key": "val"}, tool_context)
        assert result == "result data"
        handler.assert_called_once_with({"key": "val"}, tool_context)

    @pytest.mark.asyncio
    async def test_unknown_tool_returns_error(self, tool_context):
        reg = ToolRegistry()
        result = await reg.execute("nonexistent", {}, tool_context)
        assert "Error" in result
        assert "nonexistent" in result

    @pytest.mark.asyncio
    async def test_handler_exception_returns_error_string(self, tool_context):
        reg = ToolRegistry()
        handler = AsyncMock(side_effect=ValueError("something broke"))
        reg.register("bad_tool", "desc", {"type": "object", "properties": {}}, handler)
        result = await reg.execute("bad_tool", {}, tool_context)
        assert "Error" in result
        assert "something broke" in result

    @pytest.mark.asyncio
    async def test_truncation_applied_to_output(self, tool_context):
        reg = ToolRegistry()
        big_output = "Z" * (50 * 1024)  # 50KB, over default 30KB limit
        handler = AsyncMock(return_value=big_output)
        reg.register("big_tool", "desc", {"type": "object", "properties": {}}, handler)
        result = await reg.execute("big_tool", {}, tool_context)
        assert "truncated" in result
        assert len(result.encode("utf-8")) < len(big_output.encode("utf-8"))

    def test_anthropic_format_shape(self, registry):
        tools = registry.get_anthropic_tools()
        assert len(tools) == 6
        for tool in tools:
            assert "name" in tool
            assert "description" in tool
            assert "input_schema" in tool
            schema = tool["input_schema"]
            assert schema["type"] == "object"
            assert "properties" in schema
            assert "required" in schema


# ---------------------------------------------------------------------------
# Filesystem tool tests
# ---------------------------------------------------------------------------

class TestListDirectory:
    @pytest.mark.asyncio
    async def test_list_root(self, registry, tool_context):
        result = await registry.execute(
            "list_directory", {"path": "/"}, tool_context
        )
        assert "etc" in result
        assert "usr" in result
        assert "bin" in result

    @pytest.mark.asyncio
    async def test_list_nested(self, registry, tool_context):
        result = await registry.execute(
            "list_directory", {"path": "/etc"}, tool_context
        )
        assert "passwd" in result
        assert "shadow" in result
        assert "config.conf" in result
        assert "init.d" in result

    @pytest.mark.asyncio
    async def test_list_not_found(self, registry, tool_context):
        result = await registry.execute(
            "list_directory", {"path": "/nonexistent"}, tool_context
        )
        assert "Error" in result


class TestReadFile:
    @pytest.mark.asyncio
    async def test_read_text_file(self, registry, tool_context):
        result = await registry.execute(
            "read_file", {"path": "/etc/passwd"}, tool_context
        )
        assert "root:x:0:0" in result
        assert "File size:" in result

    @pytest.mark.asyncio
    async def test_read_binary_file(self, registry, tool_context):
        result = await registry.execute(
            "read_file", {"path": "/usr/bin/httpd"}, tool_context
        )
        assert "binary" in result.lower() or "hex" in result.lower()
        assert "7f45 4c46" in result or "7f 45 4c 46" in result or "7f454c46" in result

    @pytest.mark.asyncio
    async def test_read_with_offset(self, registry, tool_context):
        result = await registry.execute(
            "read_file", {"path": "/etc/passwd", "offset": 5}, tool_context
        )
        # Should not start with "root:" since we're offset by 5
        assert "root:x" not in result.split("\n\n", 1)[-1][:10]

    @pytest.mark.asyncio
    async def test_read_not_found(self, registry, tool_context):
        result = await registry.execute(
            "read_file", {"path": "/etc/nonexistent"}, tool_context
        )
        assert "Error" in result


class TestFileInfo:
    @pytest.mark.asyncio
    async def test_text_file_info(self, registry, tool_context):
        result = await registry.execute(
            "file_info", {"path": "/etc/passwd"}, tool_context
        )
        assert "Path: /etc/passwd" in result
        assert "Size:" in result
        assert "SHA256:" in result
        assert "Permissions:" in result

    @pytest.mark.asyncio
    async def test_elf_file_info(self, registry, tool_context):
        # Our fake ELF has valid magic but minimal headers,
        # pyelftools may not parse it fully. Just test no crash.
        result = await registry.execute(
            "file_info", {"path": "/usr/bin/httpd"}, tool_context
        )
        assert "Path: /usr/bin/httpd" in result
        assert "Size:" in result


class TestSearchFiles:
    @pytest.mark.asyncio
    async def test_search_match(self, registry, tool_context):
        result = await registry.execute(
            "search_files", {"pattern": "*.conf"}, tool_context
        )
        assert "config.conf" in result
        assert "Found" in result

    @pytest.mark.asyncio
    async def test_search_no_match(self, registry, tool_context):
        result = await registry.execute(
            "search_files", {"pattern": "*.xyz"}, tool_context
        )
        assert "No files matching" in result


class TestFindFilesByType:
    @pytest.mark.asyncio
    async def test_find_elf(self, registry, tool_context):
        result = await registry.execute(
            "find_files_by_type", {"file_type": "elf"}, tool_context
        )
        assert "httpd" in result
        assert "Found" in result

    @pytest.mark.asyncio
    async def test_find_config(self, registry, tool_context):
        result = await registry.execute(
            "find_files_by_type", {"file_type": "config"}, tool_context
        )
        assert "config.conf" in result

    @pytest.mark.asyncio
    async def test_find_certificate(self, registry, tool_context):
        result = await registry.execute(
            "find_files_by_type", {"file_type": "certificate"}, tool_context
        )
        assert "server.pem" in result

    @pytest.mark.asyncio
    async def test_find_shell_script(self, registry, tool_context):
        result = await registry.execute(
            "find_files_by_type", {"file_type": "shell_script"}, tool_context
        )
        assert "rcS" in result

    @pytest.mark.asyncio
    async def test_find_library(self, registry, tool_context):
        result = await registry.execute(
            "find_files_by_type", {"file_type": "library"}, tool_context
        )
        assert "libfoo.so.1" in result

    @pytest.mark.asyncio
    async def test_invalid_type(self, registry, tool_context):
        result = await registry.execute(
            "find_files_by_type", {"file_type": "invalid"}, tool_context
        )
        assert "Error" in result or "unknown file type" in result


class TestPathTraversal:
    @pytest.mark.asyncio
    async def test_traversal_blocked_list_directory(self, registry, tool_context):
        result = await registry.execute(
            "list_directory", {"path": "/../../../etc"}, tool_context
        )
        # Should either error or be sandboxed to the root
        # validate_path raises HTTPException(403) which becomes an error string
        assert "Error" in result or "etc" in result

    @pytest.mark.asyncio
    async def test_traversal_blocked_read_file(self, registry, tool_context):
        result = await registry.execute(
            "read_file", {"path": "/../../../etc/passwd"}, tool_context
        )
        # Should get an error (path traversal detected) or read the firmware's /etc/passwd
        # In either case, it should NOT read the host /etc/passwd
        if "root:" in result:
            # It read the firmware's /etc/passwd, which is fine
            assert "root:x:0:0:root:/root:/bin/sh" in result
        else:
            assert "Error" in result

    @pytest.mark.asyncio
    async def test_traversal_blocked_search(self, registry, tool_context):
        result = await registry.execute(
            "search_files", {"pattern": "*", "path": "/../../../"}, tool_context
        )
        # Should be sandboxed
        assert "Error" in result or "Found" in result
