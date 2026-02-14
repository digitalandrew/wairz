"""Binary analysis service using radare2 (r2pipe) and pyelftools."""

import asyncio
import os
from collections import OrderedDict

from elftools.elf.elffile import ELFFile
from elftools.elf.segments import Segment

from app.utils.sandbox import validate_path

MAX_SESSIONS = 5
R2_ANALYSIS_TIMEOUT = 60
MAX_FUNCTIONS = 500
MAX_INSTRUCTIONS = 200


class R2Session:
    """Manages a radare2 session for a single binary."""

    def __init__(self, binary_path: str) -> None:
        import r2pipe

        self.binary_path = binary_path
        self._r2 = r2pipe.open(binary_path, flags=["-2"])
        # Run full analysis (may take a while for large binaries)
        self._r2.cmd("aaa")

    def list_functions(self) -> list[dict]:
        """List all functions found by radare2 analysis."""
        result = self._r2.cmdj("aflj") or []
        # Sort by size descending — large custom functions are often interesting
        result.sort(key=lambda f: f.get("size", 0), reverse=True)
        return result[:MAX_FUNCTIONS]

    def disassemble_function(
        self, function_name: str, max_instructions: int = 100
    ) -> str:
        """Disassemble a function by name. Returns disassembly text."""
        max_instructions = min(max_instructions, MAX_INSTRUCTIONS)
        # Seek to function
        self._r2.cmd(f"s {function_name}")
        # Print disassembly (pdf = print disassembly function)
        result = self._r2.cmd(f"pdf")
        if not result or "Cannot find function" in result:
            # Fall back to linear disassembly at address
            result = self._r2.cmd(f"pd {max_instructions}")
        return result or f"Could not disassemble '{function_name}'."

    def get_imports(self) -> list[dict]:
        """List imported symbols."""
        return self._r2.cmdj("iij") or []

    def get_exports(self) -> list[dict]:
        """List exported symbols."""
        return self._r2.cmdj("iEj") or []

    def get_xrefs_to(self, target: str) -> list[dict]:
        """Get cross-references to an address or symbol."""
        self._r2.cmd(f"s {target}")
        return self._r2.cmdj("axtj") or []

    def get_xrefs_from(self, target: str) -> list[dict]:
        """Get cross-references from an address or symbol."""
        self._r2.cmd(f"s {target}")
        return self._r2.cmdj("axfj") or []

    def get_binary_info(self) -> dict:
        """Get binary metadata: architecture, format, sections, etc."""
        return self._r2.cmdj("ij") or {}

    def close(self) -> None:
        """Quit the r2 session."""
        try:
            self._r2.quit()
        except Exception:
            pass


class R2SessionCache:
    """LRU cache for R2Session instances.

    Keeps up to MAX_SESSIONS open r2 sessions. When the cache is full,
    the least-recently-used session is evicted and closed.
    """

    def __init__(self, max_size: int = MAX_SESSIONS) -> None:
        self._max_size = max_size
        self._cache: OrderedDict[str, R2Session] = OrderedDict()
        self._lock = asyncio.Lock()

    async def get_session(self, binary_path: str) -> R2Session:
        """Get or create an R2Session for the given binary path.

        Runs r2 analysis in a thread to avoid blocking the event loop.
        """
        real_path = os.path.realpath(binary_path)

        async with self._lock:
            if real_path in self._cache:
                # Move to end (most recently used)
                self._cache.move_to_end(real_path)
                return self._cache[real_path]

        # Create new session in a thread (r2 analysis blocks)
        loop = asyncio.get_event_loop()
        session = await asyncio.wait_for(
            loop.run_in_executor(None, R2Session, real_path),
            timeout=R2_ANALYSIS_TIMEOUT,
        )

        async with self._lock:
            # Evict oldest if at capacity
            while len(self._cache) >= self._max_size:
                _, evicted = self._cache.popitem(last=False)
                await loop.run_in_executor(None, evicted.close)

            self._cache[real_path] = session

        return session

    async def close_all(self) -> None:
        """Close all cached sessions."""
        async with self._lock:
            for session in self._cache.values():
                session.close()
            self._cache.clear()

    @property
    def size(self) -> int:
        return len(self._cache)


# Module-level singleton
_session_cache = R2SessionCache()


def get_session_cache() -> R2SessionCache:
    """Get the module-level R2 session cache singleton."""
    return _session_cache


def check_binary_protections(binary_path: str) -> dict[str, object]:
    """Check ELF binary security protections using pyelftools.

    Returns a dict with:
      - nx: bool (NX / DEP enabled)
      - relro: str ("full", "partial", "none")
      - canary: bool (stack canary / __stack_chk_fail present)
      - pie: bool (position-independent executable)
      - fortify: bool (fortified libc functions present)
      - stripped: bool (symbol table stripped)
    """
    result: dict[str, object] = {
        "nx": False,
        "relro": "none",
        "canary": False,
        "pie": False,
        "fortify": False,
        "stripped": True,
    }

    with open(binary_path, "rb") as f:
        try:
            elf = ELFFile(f)
        except Exception:
            return {"error": "Not a valid ELF file"}

        # NX: Check GNU_STACK segment for execute permission
        for seg in elf.iter_segments():
            if seg.header.p_type == "PT_GNU_STACK":
                # If PF_X (execute) flag is NOT set, NX is enabled
                result["nx"] = (seg.header.p_flags & 0x1) == 0
                break

        # RELRO: Check for PT_GNU_RELRO segment and BIND_NOW flag
        has_relro = False
        has_bind_now = False
        for seg in elf.iter_segments():
            if seg.header.p_type == "PT_GNU_RELRO":
                has_relro = True
            if seg.header.p_type == "PT_DYNAMIC":
                # Check for DT_BIND_NOW or DT_FLAGS with DF_BIND_NOW
                try:
                    for tag in seg.iter_tags():
                        if tag.entry.d_tag == "DT_BIND_NOW":
                            has_bind_now = True
                        if tag.entry.d_tag == "DT_FLAGS" and (
                            tag.entry.d_val & 0x8
                        ):  # DF_BIND_NOW
                            has_bind_now = True
                except Exception:
                    pass

        if has_relro and has_bind_now:
            result["relro"] = "full"
        elif has_relro:
            result["relro"] = "partial"

        # PIE: ELF type DYN means position-independent
        result["pie"] = elf.header.e_type == "ET_DYN"

        # Canary & Fortify: Check dynamic symbols for __stack_chk_fail and __*_chk
        try:
            dynsym = elf.get_section_by_name(".dynsym")
            if dynsym:
                for sym in dynsym.iter_symbols():
                    name = sym.name
                    if name == "__stack_chk_fail":
                        result["canary"] = True
                    if name.endswith("_chk") and name.startswith("__"):
                        result["fortify"] = True
        except Exception:
            pass

        # Stripped: Check for .symtab section
        symtab = elf.get_section_by_name(".symtab")
        result["stripped"] = symtab is None

    return result
