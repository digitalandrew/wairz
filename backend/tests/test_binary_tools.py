"""Tests for the binary analysis AI tools and analysis service."""

import struct
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest

from app.ai.tool_registry import ToolContext, ToolRegistry
from app.ai.tools.binary import register_binary_tools
from app.services.analysis_service import check_binary_protections


# ---------------------------------------------------------------------------
# Helpers: Build a minimal valid ELF binary in memory
# ---------------------------------------------------------------------------


def _build_minimal_elf(
    *,
    arch: str = "x86_64",
    pie: bool = False,
    nx: bool = True,
    has_relro: bool = False,
    has_bind_now: bool = False,
) -> bytes:
    """Build a minimal valid ELF binary for testing pyelftools-based checks.

    This produces a valid ELF header + program headers. Not executable,
    but enough for pyelftools to parse protections.
    """
    # ELF header constants
    EI_NIDENT = 16
    ET_EXEC = 2
    ET_DYN = 3
    EM_X86_64 = 62
    PT_LOAD = 1
    PT_GNU_STACK = 0x6474E551
    PT_GNU_RELRO = 0x6474E552
    PT_DYNAMIC = 2
    PF_R = 4
    PF_W = 2
    PF_X = 1
    DT_BIND_NOW = 24
    DT_NULL = 0

    e_type = ET_DYN if pie else ET_EXEC
    phentsize = 56  # 64-bit program header size
    ehsize = 64  # 64-bit ELF header size

    # Build program headers
    phdrs = []

    # PT_LOAD (text segment)
    phdrs.append(struct.pack(
        "<IIQQQQQQ",
        PT_LOAD, PF_R | PF_X, 0, 0, 0, 0, 0, 0,
    ))

    # PT_GNU_STACK
    stack_flags = PF_R | PF_W  # No PF_X = NX enabled
    if not nx:
        stack_flags |= PF_X
    phdrs.append(struct.pack(
        "<IIQQQQQQ",
        PT_GNU_STACK, stack_flags, 0, 0, 0, 0, 0, 0,
    ))

    if has_relro:
        phdrs.append(struct.pack(
            "<IIQQQQQQ",
            PT_GNU_RELRO, PF_R, 0, 0, 0, 0, 0, 0,
        ))

    if has_bind_now:
        # PT_DYNAMIC with DT_BIND_NOW entry
        # We'll place the dynamic section data after all headers
        dyn_offset = ehsize + len(phdrs) * phentsize + phentsize  # after this phdr
        dyn_data = struct.pack("<qQ", DT_BIND_NOW, 0)
        dyn_data += struct.pack("<qQ", DT_NULL, 0)
        dyn_size = len(dyn_data)

        phdrs.append(struct.pack(
            "<IIQQQQQQ",
            PT_DYNAMIC, PF_R | PF_W,
            dyn_offset, 0, 0,
            dyn_size, dyn_size, 0,
        ))
    else:
        dyn_data = b""

    phnum = len(phdrs)

    # ELF header (64-bit little-endian)
    e_ident = (
        b"\x7fELF"  # magic
        + b"\x02"    # EI_CLASS: ELFCLASS64
        + b"\x01"    # EI_DATA: ELFDATA2LSB
        + b"\x01"    # EI_VERSION: EV_CURRENT
        + b"\x00"    # EI_OSABI
        + b"\x00" * 8  # EI_ABIVERSION + padding
    )

    elf_header = struct.pack(
        "<HHIQQQIHHHHHH",
        e_type,       # e_type
        EM_X86_64,    # e_machine
        1,            # e_version
        0,            # e_entry
        ehsize,       # e_phoff (program headers right after ELF header)
        0,            # e_shoff (no section headers)
        0,            # e_flags
        ehsize,       # e_ehsize
        phentsize,    # e_phentsize
        phnum,        # e_phnum
        0,            # e_shentsize
        0,            # e_shnum
        0,            # e_shstrndx
    )

    binary = e_ident + elf_header
    for ph in phdrs:
        binary += ph
    binary += dyn_data

    return binary


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def firmware_root(tmp_path: Path) -> Path:
    """Create a fake firmware filesystem with ELF binaries."""
    (tmp_path / "usr" / "bin").mkdir(parents=True)
    (tmp_path / "usr" / "sbin").mkdir(parents=True)

    # Standard ELF with NX enabled, no PIE
    (tmp_path / "usr" / "bin" / "httpd").write_bytes(
        _build_minimal_elf(nx=True, pie=False)
    )

    # PIE binary with full RELRO
    (tmp_path / "usr" / "sbin" / "daemon").write_bytes(
        _build_minimal_elf(nx=True, pie=True, has_relro=True, has_bind_now=True)
    )

    # No NX (executable stack)
    (tmp_path / "usr" / "bin" / "legacy").write_bytes(
        _build_minimal_elf(nx=False, pie=False)
    )

    # Non-ELF file
    (tmp_path / "usr" / "bin" / "script.sh").write_text("#!/bin/sh\necho hello\n")

    return tmp_path


@pytest.fixture
def tool_context(firmware_root: Path) -> ToolContext:
    return ToolContext(
        project_id=uuid4(),
        firmware_id=uuid4(),
        extracted_path=str(firmware_root),
        db=MagicMock(),
    )


@pytest.fixture
def registry() -> ToolRegistry:
    reg = ToolRegistry()
    register_binary_tools(reg)
    return reg


# ---------------------------------------------------------------------------
# check_binary_protections tests (pyelftools, no external tools needed)
# ---------------------------------------------------------------------------


class TestCheckBinaryProtections:
    def test_nx_enabled(self, firmware_root):
        path = str(firmware_root / "usr" / "bin" / "httpd")
        result = check_binary_protections(path)
        assert result["nx"] is True

    def test_nx_disabled(self, firmware_root):
        path = str(firmware_root / "usr" / "bin" / "legacy")
        result = check_binary_protections(path)
        assert result["nx"] is False

    def test_pie_enabled(self, firmware_root):
        path = str(firmware_root / "usr" / "sbin" / "daemon")
        result = check_binary_protections(path)
        assert result["pie"] is True

    def test_pie_disabled(self, firmware_root):
        path = str(firmware_root / "usr" / "bin" / "httpd")
        result = check_binary_protections(path)
        assert result["pie"] is False

    def test_partial_relro(self, firmware_root):
        """Minimal ELF with PT_GNU_RELRO produces at least partial RELRO."""
        path = str(firmware_root / "usr" / "sbin" / "daemon")
        result = check_binary_protections(path)
        assert result["relro"] in ("partial", "full")

    def test_no_relro(self, firmware_root):
        path = str(firmware_root / "usr" / "bin" / "httpd")
        result = check_binary_protections(path)
        assert result["relro"] == "none"

    def test_not_elf(self, firmware_root):
        path = str(firmware_root / "usr" / "bin" / "script.sh")
        result = check_binary_protections(path)
        assert "error" in result

    def test_nonexistent_file(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            check_binary_protections(str(tmp_path / "nonexistent"))


# ---------------------------------------------------------------------------
# Tool registration tests
# ---------------------------------------------------------------------------


class TestRegistration:
    def test_all_tools_registered(self, registry):
        tools = registry.get_anthropic_tools()
        names = {t["name"] for t in tools}
        assert names == {
            "list_functions",
            "disassemble_function",
            "decompile_function",
            "list_imports",
            "list_exports",
            "xrefs_to",
            "xrefs_from",
            "get_binary_info",
            "check_binary_protections",
            "cleanup_decompiled_code",
        }

    def test_tool_schemas_valid(self, registry):
        for tool in registry.get_anthropic_tools():
            assert "name" in tool
            assert "description" in tool
            assert "input_schema" in tool
            assert tool["input_schema"]["type"] == "object"
            assert "properties" in tool["input_schema"]
            assert "required" in tool["input_schema"]

    def test_disassemble_has_optional_param(self, registry):
        tools = registry.get_anthropic_tools()
        disasm = next(t for t in tools if t["name"] == "disassemble_function")
        props = disasm["input_schema"]["properties"]
        assert "num_instructions" in props
        assert "num_instructions" not in disasm["input_schema"]["required"]

    def test_all_tools_require_binary_path(self, registry):
        for tool in registry.get_anthropic_tools():
            assert "binary_path" in tool["input_schema"]["properties"]
            assert "binary_path" in tool["input_schema"]["required"]


# ---------------------------------------------------------------------------
# check_binary_protections tool handler tests
# ---------------------------------------------------------------------------


class TestCheckBinaryProtectionsTool:
    @pytest.mark.asyncio
    async def test_returns_protection_info(self, registry, tool_context):
        result = await registry.execute(
            "check_binary_protections",
            {"binary_path": "/usr/bin/httpd"},
            tool_context,
        )
        assert "Binary Protection Status" in result
        assert "NX" in result
        assert "RELRO" in result
        assert "Stack Canary" in result
        assert "PIE" in result
        assert "Fortify" in result

    @pytest.mark.asyncio
    async def test_nx_enabled_in_output(self, registry, tool_context):
        result = await registry.execute(
            "check_binary_protections",
            {"binary_path": "/usr/bin/httpd"},
            tool_context,
        )
        assert "enabled" in result  # NX should be enabled

    @pytest.mark.asyncio
    async def test_not_elf_error(self, registry, tool_context):
        result = await registry.execute(
            "check_binary_protections",
            {"binary_path": "/usr/bin/script.sh"},
            tool_context,
        )
        assert "Error" in result

    @pytest.mark.asyncio
    async def test_protection_score(self, registry, tool_context):
        result = await registry.execute(
            "check_binary_protections",
            {"binary_path": "/usr/sbin/daemon"},
            tool_context,
        )
        assert "Protection score" in result


# ---------------------------------------------------------------------------
# Path traversal tests
# ---------------------------------------------------------------------------


class TestPathTraversal:
    @pytest.mark.asyncio
    async def test_list_functions_traversal(self, registry, tool_context):
        result = await registry.execute(
            "list_functions",
            {"binary_path": "/../../../etc/passwd"},
            tool_context,
        )
        assert "Error" in result

    @pytest.mark.asyncio
    async def test_disassemble_traversal(self, registry, tool_context):
        result = await registry.execute(
            "disassemble_function",
            {"binary_path": "/../../../etc/passwd", "function_name": "main"},
            tool_context,
        )
        assert "Error" in result

    @pytest.mark.asyncio
    async def test_check_protections_traversal(self, registry, tool_context):
        result = await registry.execute(
            "check_binary_protections",
            {"binary_path": "/../../../etc/passwd"},
            tool_context,
        )
        assert "Error" in result

    @pytest.mark.asyncio
    async def test_imports_traversal(self, registry, tool_context):
        result = await registry.execute(
            "list_imports",
            {"binary_path": "/../../../etc/passwd"},
            tool_context,
        )
        assert "Error" in result


# ---------------------------------------------------------------------------
# Handler formatting tests (mock GhidraAnalysisCache)
# ---------------------------------------------------------------------------


class TestHandlerFormatting:
    @pytest.mark.asyncio
    async def test_list_functions_format(self, registry, tool_context):
        mock_cache = MagicMock()
        mock_cache.get_functions = AsyncMock(return_value=[
            {"name": "main", "size": 200, "address": "00001000"},
            {"name": "auth_check", "size": 150, "address": "00002000"},
        ])

        with patch(
            "app.ai.tools.binary.get_analysis_cache",
            return_value=mock_cache,
        ):
            result = await registry.execute(
                "list_functions",
                {"binary_path": "/usr/bin/httpd"},
                tool_context,
            )

        assert "Found 2 function(s)" in result
        assert "main" in result
        assert "auth_check" in result
        assert "00001000" in result

    @pytest.mark.asyncio
    async def test_get_binary_info_format(self, registry, tool_context):
        mock_cache = MagicMock()
        mock_cache.get_binary_info = AsyncMock(return_value={
            "core": {},
            "bin": {
                "file": "/usr/bin/httpd",
                "bintype": "elf",
                "arch": "arm",
                "bits": 32,
                "endian": "little",
                "os": "linux",
                "machine": "ARM",
                "class": "ELF32",
                "lang": "c",
                "stripped": True,
                "static": False,
                "libs": ["libc.so.6", "libpthread.so.0"],
            },
        })

        with patch(
            "app.ai.tools.binary.get_analysis_cache",
            return_value=mock_cache,
        ):
            result = await registry.execute(
                "get_binary_info",
                {"binary_path": "/usr/bin/httpd"},
                tool_context,
            )

        assert "Binary Information" in result
        assert "arm" in result
        assert "little" in result
        assert "libc.so.6" in result

    @pytest.mark.asyncio
    async def test_list_imports_format(self, registry, tool_context):
        mock_cache = MagicMock()
        mock_cache.get_imports = AsyncMock(return_value=[
            {"name": "system", "library": "libc.so.6"},
            {"name": "printf", "library": "libc.so.6"},
            {"name": "pthread_create", "library": "libpthread.so.0"},
        ])

        with patch(
            "app.ai.tools.binary.get_analysis_cache",
            return_value=mock_cache,
        ):
            result = await registry.execute(
                "list_imports",
                {"binary_path": "/usr/bin/httpd"},
                tool_context,
            )

        assert "Found 3 import(s)" in result
        assert "[libc.so.6]" in result
        assert "system" in result
        assert "[libpthread.so.0]" in result

    @pytest.mark.asyncio
    async def test_list_exports_format(self, registry, tool_context):
        mock_cache = MagicMock()
        mock_cache.get_exports = AsyncMock(return_value=[
            {"name": "main", "address": "00001000"},
            {"name": "init", "address": "00002000"},
        ])

        with patch(
            "app.ai.tools.binary.get_analysis_cache",
            return_value=mock_cache,
        ):
            result = await registry.execute(
                "list_exports",
                {"binary_path": "/usr/bin/httpd"},
                tool_context,
            )

        assert "Found 2 export(s)" in result
        assert "main" in result
        assert "00001000" in result

    @pytest.mark.asyncio
    async def test_xrefs_to_format(self, registry, tool_context):
        mock_cache = MagicMock()
        mock_cache.get_xrefs_to = AsyncMock(return_value=[
            {"from": "00003000", "type": "UNCONDITIONAL_CALL", "from_func": "entry"},
        ])

        with patch(
            "app.ai.tools.binary.get_analysis_cache",
            return_value=mock_cache,
        ):
            result = await registry.execute(
                "xrefs_to",
                {"binary_path": "/usr/bin/httpd", "address_or_symbol": "main"},
                tool_context,
            )

        assert "Found 1 cross-reference(s) to 'main'" in result
        assert "00003000" in result
        assert "UNCONDITIONAL_CALL" in result

    @pytest.mark.asyncio
    async def test_no_functions_message(self, registry, tool_context):
        mock_cache = MagicMock()
        mock_cache.get_functions = AsyncMock(return_value=[])

        with patch(
            "app.ai.tools.binary.get_analysis_cache",
            return_value=mock_cache,
        ):
            result = await registry.execute(
                "list_functions",
                {"binary_path": "/usr/bin/httpd"},
                tool_context,
            )

        assert "No functions found" in result

    @pytest.mark.asyncio
    async def test_disassembly_format(self, registry, tool_context):
        mock_cache = MagicMock()
        mock_cache.get_disassembly = AsyncMock(
            return_value="00001000  push rbp\n00001001  mov rbp, rsp"
        )

        with patch(
            "app.ai.tools.binary.get_analysis_cache",
            return_value=mock_cache,
        ):
            result = await registry.execute(
                "disassemble_function",
                {"binary_path": "/usr/bin/httpd", "function_name": "main"},
                tool_context,
            )

        assert "Disassembly of main" in result
        assert "push rbp" in result


# ---------------------------------------------------------------------------
# Integration: full registry includes binary tools
# ---------------------------------------------------------------------------


class TestFullRegistration:
    def test_create_tool_registry_includes_binary(self):
        from app.ai import create_tool_registry

        registry = create_tool_registry()
        tools = registry.get_anthropic_tools()
        names = {t["name"] for t in tools}
        assert "list_functions" in names
        assert "check_binary_protections" in names
        assert "disassemble_function" in names
