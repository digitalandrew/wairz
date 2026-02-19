"""REST endpoints for binary analysis: functions, disassembly, decompilation, protections."""

import asyncio
import logging
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.services.analysis_service import check_binary_protections
from app.services.firmware_service import FirmwareService
from app.services.ghidra_service import (
    decompile_function as ghidra_decompile,
    get_analysis_cache,
)
from app.utils.sandbox import validate_path

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/projects/{project_id}/analysis",
    tags=["analysis"],
)


async def _resolve_firmware(
    project_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    """Resolve project -> firmware, return firmware record."""
    svc = FirmwareService(db)
    firmware = await svc.get_by_project(project_id)
    if not firmware:
        raise HTTPException(404, "No firmware uploaded for this project")
    if not firmware.extracted_path:
        raise HTTPException(400, "Firmware not yet unpacked")
    return firmware


@router.get("/functions")
async def list_functions(
    path: str = Query(..., description="Path to ELF binary in firmware filesystem"),
    firmware=Depends(_resolve_firmware),
    db: AsyncSession = Depends(get_db),
):
    """List functions found in an ELF binary, sorted by size (largest first)."""
    try:
        full_path = validate_path(firmware.extracted_path, path)
    except Exception:
        raise HTTPException(403, "Invalid path")

    cache = get_analysis_cache()
    try:
        functions = await cache.get_functions(full_path, firmware.id, db)
    except TimeoutError:
        raise HTTPException(504, "Binary analysis timed out")
    except Exception as e:
        raise HTTPException(400, f"Failed to analyze binary: {e}")

    return {
        "binary_path": path,
        "functions": [
            {
                "name": fn.get("name", "unknown"),
                "offset": fn.get("address", "0"),
                "size": fn.get("size", 0),
            }
            for fn in functions
        ],
    }


@router.get("/imports")
async def list_imports(
    path: str = Query(..., description="Path to ELF binary in firmware filesystem"),
    firmware=Depends(_resolve_firmware),
):
    """List imported symbols with their source library.

    Uses pyelftools to parse DT_NEEDED + .dynsym, then cross-references
    each undefined symbol against library exports to determine which
    function comes from which library.
    """
    try:
        full_path = validate_path(firmware.extracted_path, path)
    except Exception:
        raise HTTPException(403, "Invalid path")

    extracted_root = firmware.extracted_path
    loop = asyncio.get_event_loop()
    imports = await loop.run_in_executor(
        None, _resolve_elf_imports, full_path, extracted_root
    )

    return {
        "binary_path": path,
        "imports": imports,
    }


def _resolve_elf_imports(binary_path: str, extracted_root: str) -> list[dict]:
    """Parse ELF imports and resolve each to its source library.

    For each needed library, reads its exports and cross-references
    with the binary's undefined symbols.
    """
    import os
    from elftools.elf.elffile import ELFFile
    from elftools.elf.sections import SymbolTableSection

    STANDARD_LIB_PATHS = [
        "/lib", "/usr/lib", "/lib64", "/usr/lib64",
    ]

    try:
        with open(binary_path, "rb") as f:
            elf = ELFFile(f)

            # 1. Get DT_NEEDED libraries and rpath
            needed_libs: list[str] = []
            search_paths: list[str] = []
            for seg in elf.iter_segments():
                if seg.header.p_type == "PT_DYNAMIC":
                    for tag in seg.iter_tags():
                        if tag.entry.d_tag == "DT_NEEDED":
                            needed_libs.append(tag.needed)
                        elif tag.entry.d_tag in ("DT_RPATH", "DT_RUNPATH"):
                            rp = tag.runpath if hasattr(tag, "runpath") else tag.rpath
                            search_paths.extend(rp.split(":"))
                    break
            search_paths.extend(STANDARD_LIB_PATHS)

            # 2. Get undefined symbols (what this binary imports)
            undefined_syms: set[str] = set()
            dynsym = elf.get_section_by_name(".dynsym")
            if dynsym and isinstance(dynsym, SymbolTableSection):
                for sym in dynsym.iter_symbols():
                    if (sym.entry.st_shndx == "SHN_UNDEF"
                            and sym.name
                            and sym.entry.st_info.type in ("STT_FUNC", "STT_NOTYPE")):
                        undefined_syms.add(sym.name)

            if not undefined_syms or not needed_libs:
                return []

    except Exception as exc:
        logger.debug("Failed to parse ELF for imports: %s", exc)
        return []

    # 3. For each needed library, resolve its path and get its exports
    #    to determine which functions come from it
    func_to_lib: dict[str, str] = {}

    for lib_name in needed_libs:
        lib_abs = _find_library(extracted_root, lib_name, search_paths)
        if not lib_abs:
            continue

        try:
            lib_exports: set[str] = set()
            with open(lib_abs, "rb") as lf:
                lib_elf = ELFFile(lf)
                lib_dynsym = lib_elf.get_section_by_name(".dynsym")
                if lib_dynsym and isinstance(lib_dynsym, SymbolTableSection):
                    for sym in lib_dynsym.iter_symbols():
                        if (sym.entry.st_shndx != "SHN_UNDEF"
                                and sym.name
                                and sym.entry.st_info.type in ("STT_FUNC", "STT_GNU_IFUNC")):
                            lib_exports.add(sym.name)

            for sym_name in undefined_syms & lib_exports:
                if sym_name not in func_to_lib:
                    func_to_lib[sym_name] = lib_name
        except Exception:
            continue

    # 4. Build result
    results: list[dict] = []
    for sym_name, lib_name in func_to_lib.items():
        results.append({"name": sym_name, "libname": lib_name})

    # Also include unresolved imports (no library found)
    for sym_name in undefined_syms - func_to_lib.keys():
        results.append({"name": sym_name, "libname": None})

    return results


def _find_library(extracted_root: str, lib_name: str, search_paths: list[str]) -> str | None:
    """Resolve a library name to an absolute path within the extracted firmware."""
    import os

    for search_dir in search_paths:
        candidate = os.path.join(extracted_root, search_dir.lstrip("/"), lib_name)
        # Follow symlinks
        real = os.path.realpath(candidate)
        if os.path.isfile(real) and real.startswith(os.path.realpath(extracted_root)):
            return real

    return None


@router.get("/disasm")
async def disassemble_function(
    path: str = Query(..., description="Path to ELF binary"),
    function: str = Query(..., description="Function name to disassemble"),
    max_instructions: int = Query(100, ge=1, le=200),
    firmware=Depends(_resolve_firmware),
    db: AsyncSession = Depends(get_db),
):
    """Disassemble a function from an ELF binary."""
    try:
        full_path = validate_path(firmware.extracted_path, path)
    except Exception:
        raise HTTPException(403, "Invalid path")

    cache = get_analysis_cache()
    try:
        disasm = await cache.get_disassembly(
            full_path, function, firmware.id, db, max_instructions,
        )
    except TimeoutError:
        raise HTTPException(504, "Binary analysis timed out")
    except Exception as e:
        raise HTTPException(400, f"Failed to analyze binary: {e}")

    return {
        "binary_path": path,
        "function": function,
        "disassembly": disasm,
    }


@router.get("/binary-info")
async def get_binary_info(
    path: str = Query(..., description="Path to ELF binary"),
    firmware=Depends(_resolve_firmware),
    db: AsyncSession = Depends(get_db),
):
    """Get binary metadata and security protections."""
    try:
        full_path = validate_path(firmware.extracted_path, path)
    except Exception:
        raise HTTPException(403, "Invalid path")

    cache = get_analysis_cache()
    try:
        info = await cache.get_binary_info(full_path, firmware.id, db)
    except TimeoutError:
        raise HTTPException(504, "Binary analysis timed out")
    except Exception as e:
        raise HTTPException(400, f"Failed to analyze binary: {e}")

    protections = check_binary_protections(full_path)

    return {
        "binary_path": path,
        "info": info,
        "protections": protections,
    }


@router.get("/decompile")
async def decompile_function(
    path: str = Query(..., description="Path to ELF binary"),
    function: str = Query(..., description="Function name to decompile"),
    firmware=Depends(_resolve_firmware),
    db: AsyncSession = Depends(get_db),
):
    """Decompile a function from an ELF binary using Ghidra headless."""
    try:
        full_path = validate_path(firmware.extracted_path, path)
    except Exception:
        raise HTTPException(403, "Invalid path")

    try:
        decompiled = await ghidra_decompile(full_path, function, firmware.id, db)
    except FileNotFoundError:
        raise HTTPException(404, f"Binary not found: {path}")
    except TimeoutError as e:
        raise HTTPException(504, str(e))
    except RuntimeError as e:
        raise HTTPException(400, str(e))

    return {
        "binary_path": path,
        "function": function,
        "decompiled_code": decompiled,
    }
