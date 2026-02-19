"""Binary analysis service — pyelftools-based ELF protection checks."""

from elftools.elf.elffile import ELFFile


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
