"""Component map service — builds a dependency graph from unpacked firmware.

Walks the extracted filesystem, classifies files, parses ELF dependencies
and shell script references, and returns a graph of components and their
relationships.
"""

import os
import re
import stat
from dataclasses import dataclass, field

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection

from app.utils.sandbox import validate_path

MAX_NODES = 500
MAX_FUNCTIONS_PER_EDGE = 50
MAX_FILE_READ = 64 * 1024  # 64KB for script/config parsing

# Extensions recognized as config files
CONFIG_EXTENSIONS = {
    ".conf", ".cfg", ".ini", ".json", ".yaml", ".yml", ".xml",
}

# Shell builtins to skip when matching bare command names
SHELL_BUILTINS = {
    "echo", "printf", "test", "true", "false", "exit", "return",
    "cd", "pwd", "export", "unset", "set", "shift", "wait",
    "read", "eval", "exec", "trap", "break", "continue",
    "case", "esac", "if", "then", "else", "elif", "fi",
    "for", "do", "done", "while", "until", "in",
    "local", "readonly", "alias", "unalias", "umask",
    "kill", "jobs", "fg", "bg", "type", "hash",
}

# Standard library search paths for resolving DT_NEEDED
STANDARD_LIB_PATHS = [
    "/lib", "/usr/lib", "/lib64", "/usr/lib64",
    "/lib/x86_64-linux-gnu", "/usr/lib/x86_64-linux-gnu",
    "/lib/arm-linux-gnueabihf", "/usr/lib/arm-linux-gnueabihf",
    "/lib/mips-linux-gnu", "/usr/lib/mips-linux-gnu",
    "/lib/mipsel-linux-gnu", "/usr/lib/mipsel-linux-gnu",
]

# Systemd unit directories
SYSTEMD_DIRS = {"/etc/systemd/system", "/lib/systemd/system", "/usr/lib/systemd/system"}

# Regex patterns for shell script analysis
RE_SOURCE_CMD = re.compile(r'(?:^|\s)(?:source|\.) +["\']?(/[^\s"\'#;]+)["\']?', re.MULTILINE)
RE_ABSOLUTE_PATH = re.compile(r'(?:^|\s|=|`|\$\()(/(?:usr/)?(?:s?bin|libexec)/[^\s"\'#;|&>]+)', re.MULTILINE)
RE_DAEMON_VAR = re.compile(
    r'(?:DAEMON|BIN|PROG|BINARY|SERVICE_PATH|EXEC)\s*=\s*["\']?(/[^\s"\'#;]+)["\']?',
    re.MULTILINE,
)
RE_EXEC_START = re.compile(r'^ExecStart\s*=\s*(-?)(.+)$', re.MULTILINE)
RE_INITTAB_LINE = re.compile(r'^([^#][^:]*):([^:]*):([^:]*):(.+)$', re.MULTILINE)


@dataclass
class ComponentNode:
    id: str        # relative path from firmware root (e.g. "/usr/sbin/httpd")
    label: str     # filename
    type: str      # binary, library, script, config, init_script
    path: str      # same as id
    size: int
    metadata: dict = field(default_factory=dict)


@dataclass
class ComponentEdge:
    source: str    # source node id
    target: str    # target node id
    type: str      # links_library, imports_functions, sources_script, executes, starts_service, configures
    details: dict = field(default_factory=dict)


@dataclass
class ComponentGraph:
    nodes: list[ComponentNode]
    edges: list[ComponentEdge]
    truncated: bool = False


class ComponentMapService:
    def __init__(self, extracted_root: str):
        self.extracted_root = os.path.realpath(extracted_root)
        # Lookup tables populated during walk
        self._nodes_by_id: dict[str, ComponentNode] = {}
        self._nodes_by_label: dict[str, list[str]] = {}  # label -> list of node ids
        self._edges: list[ComponentEdge] = []
        # Cache: library name -> resolved node id
        self._lib_resolve_cache: dict[str, str | None] = {}
        # Cache: library node id -> set of exported symbol names
        self._lib_exports_cache: dict[str, set[str]] = {}

    def _validate(self, path: str) -> str:
        return validate_path(self.extracted_root, path)

    def _rel_path(self, abs_path: str) -> str:
        """Get path relative to extracted root, prefixed with /."""
        return "/" + os.path.relpath(abs_path, self.extracted_root)

    def build_graph(self) -> ComponentGraph:
        """Build the full component dependency graph. Call from a thread executor."""
        self._walk_and_classify()
        self._analyze_elf_dependencies()
        self._analyze_shell_scripts()
        self._analyze_init_scripts()
        self._analyze_config_files()
        self._deduplicate_edges()
        truncated = self._prioritize_and_cap()

        return ComponentGraph(
            nodes=list(self._nodes_by_id.values()),
            edges=self._edges,
            truncated=truncated,
        )

    # ------------------------------------------------------------------
    # Step 1: Walk and classify files
    # ------------------------------------------------------------------

    def _walk_and_classify(self) -> None:
        """Walk the filesystem and classify each regular file."""
        for dirpath, _dirnames, filenames in os.walk(self.extracted_root):
            for fname in filenames:
                abs_path = os.path.join(dirpath, fname)

                # Skip symlinks and non-regular files
                try:
                    st = os.lstat(abs_path)
                except OSError:
                    continue
                if not stat.S_ISREG(st.st_mode):
                    continue

                rel = self._rel_path(abs_path)
                file_type = self._classify_file(abs_path, rel)
                if file_type is None:
                    continue

                metadata: dict = {}
                if file_type in ("binary", "library"):
                    metadata = self._elf_metadata(abs_path)

                node = ComponentNode(
                    id=rel,
                    label=fname,
                    type=file_type,
                    path=rel,
                    size=st.st_size,
                    metadata=metadata,
                )
                self._nodes_by_id[rel] = node
                self._nodes_by_label.setdefault(fname, []).append(rel)

    def _classify_file(self, abs_path: str, rel_path: str) -> str | None:
        """Classify a file. Returns type string or None to skip."""
        # Check ELF first (fast: read 4 bytes)
        try:
            with open(abs_path, "rb") as f:
                magic_bytes = f.read(4)
        except OSError:
            return None

        if magic_bytes == b"\x7fELF":
            return self._classify_elf(abs_path, rel_path)

        # Init script locations
        if self._is_init_script(rel_path):
            return "init_script"

        # Shell script: shebang or .sh extension
        if self._is_shell_script(abs_path, rel_path, magic_bytes):
            return "script"

        # Config file: under /etc with config extension
        if self._is_config_file(rel_path):
            return "config"

        return None

    def _classify_elf(self, abs_path: str, rel_path: str) -> str:
        """Classify an ELF as binary or library."""
        # .so in filename → library
        basename = os.path.basename(rel_path)
        if ".so" in basename:
            return "library"

        # Check ELF type: ET_DYN without being in a bin path is a library
        try:
            with open(abs_path, "rb") as f:
                elf = ELFFile(f)
                if elf.header.e_type == "ET_DYN":
                    # If it's in a lib directory, it's a library
                    parts = rel_path.split("/")
                    for part in parts:
                        if part.startswith("lib"):
                            return "library"
        except Exception:
            pass

        return "binary"

    def _is_init_script(self, rel_path: str) -> bool:
        """Check if path is an init script location."""
        parts = rel_path.split("/")
        # /etc/init.d/*, /etc/rc*.d/*
        if len(parts) >= 3 and parts[1] == "etc":
            if parts[2] == "init.d":
                return True
            if parts[2].startswith("rc") and parts[2].endswith(".d"):
                return True
        # /etc/inittab
        if rel_path == "/etc/inittab":
            return True
        # systemd unit files
        for sd_dir in SYSTEMD_DIRS:
            if rel_path.startswith(sd_dir + "/"):
                return True
        return False

    def _is_shell_script(self, abs_path: str, rel_path: str, magic_bytes: bytes) -> bool:
        """Check if file is a shell script by shebang or extension."""
        if rel_path.endswith(".sh"):
            return True
        # Check shebang
        if magic_bytes[:2] == b"#!":
            try:
                with open(abs_path, "rb") as f:
                    first_line = f.readline(256).decode("ascii", errors="replace")
                for shell in ("sh", "bash", "ash", "dash"):
                    if shell in first_line:
                        return True
            except OSError:
                pass
        return False

    def _is_config_file(self, rel_path: str) -> bool:
        """Check if file is a config file (under /etc with config extension)."""
        if not rel_path.startswith("/etc/"):
            return False
        _, ext = os.path.splitext(rel_path)
        return ext.lower() in CONFIG_EXTENSIONS

    def _elf_metadata(self, abs_path: str) -> dict:
        """Extract basic ELF metadata."""
        try:
            with open(abs_path, "rb") as f:
                elf = ELFFile(f)
                return {
                    "machine": elf.header.e_machine,
                    "type": elf.header.e_type,
                    "endianness": "little" if elf.little_endian else "big",
                    "bits": elf.elfclass,
                }
        except Exception:
            return {}

    # ------------------------------------------------------------------
    # Step 2: Analyze ELF dependencies
    # ------------------------------------------------------------------

    def _analyze_elf_dependencies(self) -> None:
        """Parse DT_NEEDED entries and cross-ref imported symbols for ELF nodes."""
        elf_nodes = [n for n in self._nodes_by_id.values() if n.type in ("binary", "library")]

        for node in elf_nodes:
            abs_path = os.path.join(self.extracted_root, node.id.lstrip("/"))
            try:
                with open(abs_path, "rb") as f:
                    elf = ELFFile(f)
                    needed_libs = self._get_dt_needed(elf)
                    rpath = self._get_rpath(elf)
                    undefined_syms = self._get_undefined_symbols(elf)

                    for lib_name in needed_libs:
                        lib_node_id = self._resolve_library(lib_name, rpath)
                        if lib_node_id is None:
                            continue

                        # links_library edge
                        self._edges.append(ComponentEdge(
                            source=node.id,
                            target=lib_node_id,
                            type="links_library",
                            details={"library": lib_name},
                        ))

                        # imports_functions edge: cross-ref undefined syms against lib exports
                        if undefined_syms:
                            lib_exports = self._get_library_exports(lib_node_id)
                            if lib_exports:
                                imported = sorted(undefined_syms & lib_exports)
                                if imported:
                                    self._edges.append(ComponentEdge(
                                        source=node.id,
                                        target=lib_node_id,
                                        type="imports_functions",
                                        details={"functions": imported[:MAX_FUNCTIONS_PER_EDGE]},
                                    ))
            except Exception:
                continue

    def _get_dt_needed(self, elf: ELFFile) -> list[str]:
        """Extract DT_NEEDED library names from the dynamic segment."""
        needed = []
        for seg in elf.iter_segments():
            if seg.header.p_type == "PT_DYNAMIC":
                for tag in seg.iter_tags():
                    if tag.entry.d_tag == "DT_NEEDED":
                        needed.append(tag.needed)
                break
        return needed

    def _get_rpath(self, elf: ELFFile) -> list[str]:
        """Extract DT_RPATH/DT_RUNPATH search paths."""
        paths: list[str] = []
        for seg in elf.iter_segments():
            if seg.header.p_type == "PT_DYNAMIC":
                for tag in seg.iter_tags():
                    if tag.entry.d_tag in ("DT_RPATH", "DT_RUNPATH"):
                        paths.extend(tag.runpath.split(":") if hasattr(tag, "runpath") else tag.rpath.split(":"))
                break
        return paths

    def _get_undefined_symbols(self, elf: ELFFile) -> set[str]:
        """Get undefined symbols from .dynsym (imported functions)."""
        syms: set[str] = set()
        dynsym = elf.get_section_by_name(".dynsym")
        if dynsym and isinstance(dynsym, SymbolTableSection):
            for sym in dynsym.iter_symbols():
                if (sym.entry.st_shndx == "SHN_UNDEF"
                        and sym.name
                        and sym.entry.st_info.type in ("STT_FUNC", "STT_NOTYPE")):
                    syms.add(sym.name)
        return syms

    def _resolve_library(self, lib_name: str, extra_paths: list[str] | None = None) -> str | None:
        """Resolve a library name (e.g. 'libc.so.6') to a node id in the graph."""
        cache_key = lib_name
        if cache_key in self._lib_resolve_cache:
            return self._lib_resolve_cache[cache_key]

        search_paths = list(extra_paths or []) + STANDARD_LIB_PATHS

        # Try exact path match first
        for search_dir in search_paths:
            candidate = search_dir.rstrip("/") + "/" + lib_name
            if candidate in self._nodes_by_id:
                self._lib_resolve_cache[cache_key] = candidate
                return candidate

        # Try matching by label (filename)
        if lib_name in self._nodes_by_label:
            node_id = self._nodes_by_label[lib_name][0]
            self._lib_resolve_cache[cache_key] = node_id
            return node_id

        # Try partial match for versioned libraries (e.g. libssl.so.1.1 -> libssl.so)
        base_name = lib_name.split(".so")[0] + ".so" if ".so" in lib_name else None
        if base_name and base_name in self._nodes_by_label:
            node_id = self._nodes_by_label[base_name][0]
            self._lib_resolve_cache[cache_key] = node_id
            return node_id

        self._lib_resolve_cache[cache_key] = None
        return None

    def _get_library_exports(self, lib_node_id: str) -> set[str]:
        """Get exported symbols from a library node."""
        if lib_node_id in self._lib_exports_cache:
            return self._lib_exports_cache[lib_node_id]

        exports: set[str] = set()
        abs_path = os.path.join(self.extracted_root, lib_node_id.lstrip("/"))

        try:
            with open(abs_path, "rb") as f:
                elf = ELFFile(f)
                dynsym = elf.get_section_by_name(".dynsym")
                if dynsym and isinstance(dynsym, SymbolTableSection):
                    for sym in dynsym.iter_symbols():
                        if (sym.entry.st_shndx != "SHN_UNDEF"
                                and sym.name
                                and sym.entry.st_info.type in ("STT_FUNC", "STT_GNU_IFUNC")):
                            exports.add(sym.name)
        except Exception:
            pass

        self._lib_exports_cache[lib_node_id] = exports
        return exports

    # ------------------------------------------------------------------
    # Step 3: Analyze shell scripts
    # ------------------------------------------------------------------

    def _analyze_shell_scripts(self) -> None:
        """Parse shell scripts for source commands and binary invocations."""
        script_nodes = [
            n for n in self._nodes_by_id.values()
            if n.type in ("script", "init_script")
        ]

        for node in script_nodes:
            abs_path = os.path.join(self.extracted_root, node.id.lstrip("/"))
            try:
                with open(abs_path, "r", errors="replace") as f:
                    content = f.read(MAX_FILE_READ)
            except OSError:
                continue

            # source/. commands
            for match in RE_SOURCE_CMD.finditer(content):
                target_path = match.group(1)
                if target_path in self._nodes_by_id:
                    self._edges.append(ComponentEdge(
                        source=node.id,
                        target=target_path,
                        type="sources_script",
                        details={},
                    ))

            # Absolute path invocations (/usr/bin/xxx, /usr/sbin/xxx, etc.)
            for match in RE_ABSOLUTE_PATH.finditer(content):
                target_path = match.group(1)
                if target_path in self._nodes_by_id:
                    self._edges.append(ComponentEdge(
                        source=node.id,
                        target=target_path,
                        type="executes",
                        details={"command": target_path},
                    ))

            # Bare command names matching binary node labels
            self._match_bare_commands(node.id, content)

    def _match_bare_commands(self, source_id: str, content: str) -> None:
        """Find bare command names in script content that match known binaries."""
        # Extract potential command tokens (first word on lines, after pipes, etc.)
        tokens = set(re.findall(r'(?:^|\||;|&&|\|\||`|\$\()\s*([a-zA-Z_][\w.-]*)', content, re.MULTILINE))

        for token in tokens:
            if token in SHELL_BUILTINS:
                continue
            if token not in self._nodes_by_label:
                continue

            for candidate_id in self._nodes_by_label[token]:
                candidate = self._nodes_by_id[candidate_id]
                if candidate.type == "binary":
                    self._edges.append(ComponentEdge(
                        source=source_id,
                        target=candidate_id,
                        type="executes",
                        details={"command": token},
                    ))
                    break  # take first matching binary

    # ------------------------------------------------------------------
    # Step 4: Analyze init scripts
    # ------------------------------------------------------------------

    def _analyze_init_scripts(self) -> None:
        """Parse init scripts for service startup relationships."""
        init_nodes = [n for n in self._nodes_by_id.values() if n.type == "init_script"]

        for node in init_nodes:
            abs_path = os.path.join(self.extracted_root, node.id.lstrip("/"))

            if node.id == "/etc/inittab":
                self._parse_inittab(node.id, abs_path)
            elif node.id.endswith(".service"):
                self._parse_systemd_unit(node.id, abs_path)
            else:
                self._parse_initd_script(node.id, abs_path)

    def _parse_inittab(self, source_id: str, abs_path: str) -> None:
        """Parse /etc/inittab for process entries."""
        try:
            with open(abs_path, "r", errors="replace") as f:
                content = f.read(MAX_FILE_READ)
        except OSError:
            return

        for match in RE_INITTAB_LINE.finditer(content):
            entry_id, runlevels, action, process = match.groups()
            # Extract binary path from process field
            binary = process.strip().split()[0] if process.strip() else ""
            if binary.startswith("/") and binary in self._nodes_by_id:
                self._edges.append(ComponentEdge(
                    source=source_id,
                    target=binary,
                    type="starts_service",
                    details={"action": action.strip(), "runlevels": runlevels.strip()},
                ))

    def _parse_systemd_unit(self, source_id: str, abs_path: str) -> None:
        """Parse a systemd unit file for ExecStart directives."""
        try:
            with open(abs_path, "r", errors="replace") as f:
                content = f.read(MAX_FILE_READ)
        except OSError:
            return

        for match in RE_EXEC_START.finditer(content):
            exec_line = match.group(2).strip()
            binary = exec_line.split()[0] if exec_line else ""
            # Strip prefix modifiers like -, +, !, !!
            binary = binary.lstrip("-+!@")
            if binary.startswith("/") and binary in self._nodes_by_id:
                self._edges.append(ComponentEdge(
                    source=source_id,
                    target=binary,
                    type="starts_service",
                    details={"exec_start": exec_line},
                ))

    def _parse_initd_script(self, source_id: str, abs_path: str) -> None:
        """Parse an init.d script for DAEMON=/BIN=/PROG= variables."""
        try:
            with open(abs_path, "r", errors="replace") as f:
                content = f.read(MAX_FILE_READ)
        except OSError:
            return

        for match in RE_DAEMON_VAR.finditer(content):
            binary_path = match.group(1)
            if binary_path in self._nodes_by_id:
                self._edges.append(ComponentEdge(
                    source=source_id,
                    target=binary_path,
                    type="starts_service",
                    details={"variable": match.group(0).split("=")[0].strip()},
                ))

    # ------------------------------------------------------------------
    # Step 5: Analyze config files
    # ------------------------------------------------------------------

    def _analyze_config_files(self) -> None:
        """Scan config files for absolute paths matching known nodes."""
        config_nodes = [n for n in self._nodes_by_id.values() if n.type == "config"]

        for node in config_nodes:
            abs_path = os.path.join(self.extracted_root, node.id.lstrip("/"))
            try:
                with open(abs_path, "r", errors="replace") as f:
                    content = f.read(MAX_FILE_READ)
            except OSError:
                continue

            # Find absolute paths in the content that match known nodes
            found_targets: set[str] = set()
            for match in re.finditer(r'(/(?:usr/)?(?:s?bin|lib(?:64|exec)?)/[\w./-]+)', content):
                target_path = match.group(1)
                if target_path in self._nodes_by_id and target_path != node.id:
                    found_targets.add(target_path)

            for target in found_targets:
                self._edges.append(ComponentEdge(
                    source=node.id,
                    target=target,
                    type="configures",
                    details={},
                ))

    # ------------------------------------------------------------------
    # Step 6: Deduplicate edges
    # ------------------------------------------------------------------

    def _deduplicate_edges(self) -> None:
        """Deduplicate edges by (source, target, type), merging function lists."""
        seen: dict[tuple[str, str, str], ComponentEdge] = {}

        for edge in self._edges:
            key = (edge.source, edge.target, edge.type)
            if key in seen:
                existing = seen[key]
                # Merge function lists for imports_functions edges
                if edge.type == "imports_functions":
                    existing_fns = set(existing.details.get("functions", []))
                    new_fns = set(edge.details.get("functions", []))
                    merged = sorted(existing_fns | new_fns)
                    existing.details["functions"] = merged[:MAX_FUNCTIONS_PER_EDGE]
            else:
                seen[key] = edge

        self._edges = list(seen.values())

    # ------------------------------------------------------------------
    # Step 7: Prioritize and cap nodes
    # ------------------------------------------------------------------

    def _prioritize_and_cap(self) -> bool:
        """If more than MAX_NODES, keep the highest-priority nodes. Returns True if truncated."""
        if len(self._nodes_by_id) <= MAX_NODES:
            return False

        # Score nodes by type priority + connectivity + size
        type_priority = {
            "binary": 5,
            "library": 4,
            "init_script": 3,
            "script": 2,
            "config": 1,
        }

        # Count edges per node
        edge_count: dict[str, int] = {}
        for edge in self._edges:
            edge_count[edge.source] = edge_count.get(edge.source, 0) + 1
            edge_count[edge.target] = edge_count.get(edge.target, 0) + 1

        def score(node: ComponentNode) -> float:
            tp = type_priority.get(node.type, 0)
            ec = edge_count.get(node.id, 0)
            # Normalize size (log scale, binaries tend to be larger)
            size_score = min(node.size / 1_000_000, 1.0)
            return tp * 10 + ec * 2 + size_score

        all_nodes = list(self._nodes_by_id.values())
        all_nodes.sort(key=score, reverse=True)

        keep_ids = {n.id for n in all_nodes[:MAX_NODES]}
        self._nodes_by_id = {nid: n for nid, n in self._nodes_by_id.items() if nid in keep_ids}

        # Prune edges referencing removed nodes
        self._edges = [
            e for e in self._edges
            if e.source in keep_ids and e.target in keep_ids
        ]

        return True
