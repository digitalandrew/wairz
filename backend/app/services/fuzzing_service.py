"""Service for managing AFL++ fuzzing campaigns.

Uses the Docker SDK to spawn isolated containers running AFL++ in QEMU mode
for cross-architecture firmware binary fuzzing.
"""

import base64
import io
import logging
import os
import tarfile
from datetime import datetime, timezone
from uuid import UUID

import docker
import docker.errors
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.models.firmware import Firmware
from app.models.fuzzing import FuzzingCampaign, FuzzingCrash
from app.services.analysis_service import check_binary_protections
from app.utils.sandbox import validate_path

logger = logging.getLogger(__name__)

# Architecture → AFL++ QEMU trace binary (instrumented QEMU for coverage)
QEMU_TRACE_MAP: dict[str, str] = {
    "arm": "afl-qemu-trace-arm",
    "aarch64": "afl-qemu-trace-aarch64",
    "mips": "afl-qemu-trace-mips",
    "mipsel": "afl-qemu-trace-mipsel",
    "x86": "afl-qemu-trace-i386",
    "x86_64": "afl-qemu-trace-x86_64",
}

# Architecture → stock QEMU user-mode static binary (for crash triage)
QEMU_USER_MAP: dict[str, str] = {
    "arm": "qemu-arm-static",
    "aarch64": "qemu-aarch64-static",
    "mips": "qemu-mips-static",
    "mipsel": "qemu-mipsel-static",
    "x86": "qemu-i386-static",
    "x86_64": "qemu-x86_64-static",
}

# Dangerous sink functions — indicate fuzzing value
DANGEROUS_SINKS = {
    "system", "popen", "execve", "execl", "execlp", "execle", "execv",
    "execvp", "execvpe", "sprintf", "vsprintf", "strcpy", "strcat",
    "gets", "scanf", "sscanf", "fscanf", "printf", "fprintf",
    "snprintf", "vsnprintf", "memcpy", "memmove", "strncpy",
    "strncat", "realpath", "wordexp",
}

# Input-handling functions — indicate the binary processes external input
INPUT_FUNCTIONS = {
    "read", "recv", "recvfrom", "recvmsg", "fread", "fgets", "getenv",
    "fopen", "open", "accept", "listen", "socket", "getline",
    "fgetc", "getc", "getchar", "gets", "scanf", "fscanf",
}

# Network-related functions — indicate network-facing binary
NETWORK_FUNCTIONS = {
    "socket", "bind", "listen", "accept", "connect",
    "recv", "recvfrom", "recvmsg", "send", "sendto", "sendmsg",
    "select", "poll", "epoll_wait",
}


class FuzzingService:
    """Manages AFL++ fuzzing campaign lifecycle via Docker containers."""

    def __init__(self, db: AsyncSession):
        self.db = db
        self._settings = get_settings()

    def _get_docker_client(self) -> docker.DockerClient:
        return docker.from_env()

    @staticmethod
    def _write_file_to_container(
        container: "docker.models.containers.Container",
        dest_path: str,
        data: bytes,
    ) -> None:
        """Write arbitrary bytes to a file inside a container using put_archive."""
        dest_dir = os.path.dirname(dest_path)
        dest_name = os.path.basename(dest_path)

        tar_stream = io.BytesIO()
        with tarfile.open(fileobj=tar_stream, mode="w") as tar:
            info = tarfile.TarInfo(name=dest_name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
        tar_stream.seek(0)

        container.put_archive(dest_dir, tar_stream)

    @staticmethod
    def _write_seeds_to_container(
        container: "docker.models.containers.Container",
        seeds_b64: list[str],
    ) -> None:
        """Write base64-encoded seed files to /opt/fuzzing/input/ using put_archive."""
        tar_stream = io.BytesIO()
        with tarfile.open(fileobj=tar_stream, mode="w") as tar:
            for i, seed_b64 in enumerate(seeds_b64):
                try:
                    seed_data = base64.b64decode(seed_b64)
                except Exception:
                    logger.warning("Failed to decode seed corpus entry %d", i)
                    continue
                info = tarfile.TarInfo(name=f"seed_{i}")
                info.size = len(seed_data)
                tar.addfile(info, io.BytesIO(seed_data))
        tar_stream.seek(0)

        container.put_archive("/opt/fuzzing/input", tar_stream)

    def _resolve_host_path(self, container_path: str) -> str | None:
        """Resolve a container path to a host path for Docker volume mounts."""
        real_path = os.path.realpath(container_path)

        if not os.path.exists("/.dockerenv"):
            return real_path

        client = self._get_docker_client()
        hostname = os.environ.get("HOSTNAME", "")
        if not hostname:
            return real_path

        try:
            our_container = client.containers.get(hostname)
            mounts = our_container.attrs.get("Mounts", [])

            for mount in mounts:
                dest = mount.get("Destination", "")
                source = mount.get("Source", "")
                if not dest or not source:
                    continue
                if real_path.startswith(dest + os.sep) or real_path == dest:
                    relative = os.path.relpath(real_path, dest)
                    return os.path.join(source, relative)
        except Exception:
            logger.warning("Could not inspect own container for path translation")

        return None

    async def analyze_target(
        self, firmware: Firmware, binary_path: str
    ) -> dict:
        """Analyze a binary for fuzzing suitability.

        Returns a dict with fuzzing_score (0-100), input_sources,
        dangerous_functions, protections, and recommended_strategy.
        """
        if not firmware.extracted_path:
            raise ValueError("Firmware has not been unpacked")

        full_path = validate_path(firmware.extracted_path, binary_path)

        if not os.path.isfile(full_path):
            raise ValueError(f"Binary not found: {binary_path}")

        # Parse ELF imports using pyelftools
        imports: list[str] = []
        function_count = 0
        try:
            from elftools.elf.elffile import ELFFile
            from elftools.elf.sections import SymbolTableSection

            with open(full_path, "rb") as f:
                elf = ELFFile(f)

                # Get dynamic imports
                dynsym = elf.get_section_by_name(".dynsym")
                if dynsym and isinstance(dynsym, SymbolTableSection):
                    for symbol in dynsym.iter_symbols():
                        if (
                            symbol.entry["st_info"]["type"] == "STT_FUNC"
                            and symbol.entry["st_shndx"] == "SHN_UNDEF"
                            and symbol.name
                        ):
                            imports.append(symbol.name)

                # Count defined functions
                symtab = elf.get_section_by_name(".symtab")
                if symtab and isinstance(symtab, SymbolTableSection):
                    for symbol in symtab.iter_symbols():
                        if symbol.entry["st_info"]["type"] == "STT_FUNC":
                            function_count += 1
                elif dynsym and isinstance(dynsym, SymbolTableSection):
                    for symbol in dynsym.iter_symbols():
                        if (
                            symbol.entry["st_info"]["type"] == "STT_FUNC"
                            and symbol.entry["st_shndx"] != "SHN_UNDEF"
                        ):
                            function_count += 1

        except Exception as exc:
            logger.warning("Failed to parse ELF %s: %s", binary_path, exc)
            return {
                "binary_path": binary_path,
                "error": f"Failed to parse ELF: {exc}",
                "fuzzing_score": 0,
            }

        # Categorize imports
        found_sinks = [i for i in imports if i in DANGEROUS_SINKS]
        found_input = [i for i in imports if i in INPUT_FUNCTIONS]
        found_network = [i for i in imports if i in NETWORK_FUNCTIONS]

        # Get binary protections
        protections = check_binary_protections(full_path)

        # Calculate fuzzing score (0-100)
        score = 0

        # Input handling (25 pts)
        if found_input:
            score += min(25, len(found_input) * 5)

        # Dangerous sinks (30 pts)
        if found_sinks:
            score += min(30, len(found_sinks) * 5)

        # Weak protections (25 pts)
        if not protections.get("nx"):
            score += 8
        if protections.get("relro") == "none":
            score += 6
        if not protections.get("canary"):
            score += 6
        if not protections.get("pie"):
            score += 5

        # Network-facing (10 pts)
        if found_network:
            score += min(10, len(found_network) * 3)

        # Binary size / complexity (10 pts)
        file_size = os.path.getsize(full_path)
        if file_size > 100_000:
            score += 5
        if function_count > 50:
            score += 5

        # Determine recommended strategy
        if found_network:
            strategy = "network"
        elif any(f in imports for f in ("fopen", "open", "fread")):
            strategy = "file"
        elif any(f in imports for f in ("read", "fgets", "getline", "scanf")):
            strategy = "stdin"
        else:
            strategy = "stdin"

        return {
            "binary_path": binary_path,
            "fuzzing_score": min(100, score),
            "input_sources": found_input,
            "dangerous_functions": found_sinks,
            "network_functions": found_network,
            "protections": protections,
            "recommended_strategy": strategy,
            "function_count": function_count,
            "imports_of_interest": found_sinks + found_input + found_network,
            "file_size": file_size,
        }

    async def _count_active_campaigns(self, project_id: UUID) -> int:
        result = await self.db.scalar(
            select(func.count(FuzzingCampaign.id)).where(
                FuzzingCampaign.project_id == project_id,
                FuzzingCampaign.status.in_(["created", "running"]),
            )
        )
        return result or 0

    async def create_campaign(
        self,
        firmware: Firmware,
        binary_path: str,
        config: dict | None = None,
    ) -> FuzzingCampaign:
        """Create a new fuzzing campaign."""
        if not firmware.extracted_path:
            raise ValueError("Firmware has not been unpacked")

        validate_path(firmware.extracted_path, binary_path)

        active = await self._count_active_campaigns(firmware.project_id)
        if active >= self._settings.fuzzing_max_campaigns:
            raise ValueError(
                f"Maximum concurrent campaigns ({self._settings.fuzzing_max_campaigns}) reached. "
                "Stop an existing campaign first."
            )

        campaign_config = {
            "timeout_per_exec": 1000,
            "memory_limit": 256,
            "dictionary": None,
            "seed_corpus": None,
        }
        if config:
            campaign_config.update(config)

        campaign = FuzzingCampaign(
            project_id=firmware.project_id,
            firmware_id=firmware.id,
            binary_path=binary_path,
            status="created",
            config=campaign_config,
        )
        self.db.add(campaign)
        await self.db.flush()

        return campaign

    async def start_campaign(self, campaign_id: UUID, project_id: UUID) -> FuzzingCampaign:
        """Start a fuzzing campaign by spawning an AFL++ container."""
        result = await self.db.execute(
            select(FuzzingCampaign).where(
                FuzzingCampaign.id == campaign_id,
                FuzzingCampaign.project_id == project_id,
            )
        )
        campaign = result.scalar_one_or_none()
        if not campaign:
            raise ValueError("Campaign not found")

        if campaign.status not in ("created", "stopped"):
            raise ValueError(f"Campaign cannot be started (status: {campaign.status})")

        # Get firmware for paths
        fw_result = await self.db.execute(
            select(Firmware).where(Firmware.id == campaign.firmware_id)
        )
        firmware = fw_result.scalar_one_or_none()
        if not firmware or not firmware.extracted_path:
            raise ValueError("Firmware not found or not unpacked")

        settings = self._settings
        client = self._get_docker_client()

        # Resolve host path for firmware volume mount
        real_path = os.path.realpath(firmware.extracted_path)
        host_path = self._resolve_host_path(real_path)

        volumes = {}
        if host_path:
            volumes[host_path] = {"bind": "/firmware", "mode": "ro"}

        arch = firmware.architecture or "arm"
        config = campaign.config or {}

        try:
            container = client.containers.run(
                image=settings.fuzzing_image,
                command=["sleep", "infinity"],
                detach=True,
                volumes=volumes or None,
                mem_limit=f"{settings.fuzzing_memory_limit_mb}m",
                nano_cpus=int(settings.fuzzing_cpu_limit * 1e9),
                privileged=False,
                network_mode="none",
                labels={
                    "wairz.campaign_id": str(campaign.id),
                    "wairz.project_id": str(campaign.project_id),
                    "wairz.type": "fuzzing",
                },
            )

            # If no host path, copy firmware via tar
            if not host_path:
                from app.services.emulation_service import EmulationService
                container.exec_run(["mkdir", "-p", "/firmware"])
                EmulationService._copy_dir_to_container(
                    container, real_path, "/firmware"
                )

            # Set up AFL++ working directories
            container.exec_run(["mkdir", "-p", "/opt/fuzzing/input", "/opt/fuzzing/output"])

            # Write seed corpus using put_archive for binary-safe transfer
            seed_corpus = config.get("seed_corpus")
            if seed_corpus:
                self._write_seeds_to_container(container, seed_corpus)
            else:
                # Create a minimal default seed
                self._write_seeds_to_container(
                    container, [base64.b64encode(b"AAAA").decode()]
                )

            # Write dictionary if provided
            dictionary = config.get("dictionary")
            if dictionary:
                self._write_file_to_container(
                    container,
                    "/opt/fuzzing/dictionary.dict",
                    dictionary.encode("utf-8"),
                )

            # Resolve the architecture-specific AFL++ QEMU trace binary
            qemu_trace = QEMU_TRACE_MAP.get(arch)
            if not qemu_trace:
                raise ValueError(
                    f"Unsupported architecture for fuzzing: {arch}. "
                    f"Supported: {', '.join(QEMU_TRACE_MAP.keys())}"
                )

            # Symlink the arch-specific trace binary so afl-fuzz -Q finds it
            container.exec_run([
                "ln", "-sf",
                f"/usr/local/bin/{qemu_trace}",
                "/usr/local/bin/afl-qemu-trace",
            ])

            # Build AFL++ command
            timeout_ms = config.get("timeout_per_exec", 1000)
            binary_in_firmware = campaign.binary_path.lstrip("/")

            # QEMU mode requires -m none: QEMU reserves a large virtual
            # address space for the guest (e.g. 2GB for MIPS) which is
            # not actual memory usage; a fixed -m limit causes mmap to
            # fail.  The Docker container's --memory limit handles real
            # memory enforcement.
            afl_cmd = (
                f"AFL_NO_UI=1 "
                f"AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 "
                f"AFL_SKIP_CPUFREQ=1 "
                f"QEMU_LD_PREFIX=/firmware "
                f"afl-fuzz -Q -i /opt/fuzzing/input -o /opt/fuzzing/output "
                f"-m none -t {timeout_ms} "
            )

            if dictionary:
                afl_cmd += "-x /opt/fuzzing/dictionary.dict "

            afl_cmd += f"-- /firmware/{binary_in_firmware}"

            # Launch AFL++ in background
            container.exec_run([
                "sh", "-c",
                f"nohup sh -c '{afl_cmd}' > /opt/fuzzing/afl.log 2>&1 & echo $! > /opt/fuzzing/afl.pid"
            ])

            campaign.container_id = container.id
            campaign.status = "running"
            campaign.started_at = datetime.now(timezone.utc)

        except Exception as exc:
            logger.exception("Failed to start fuzzing container")
            campaign.status = "error"
            campaign.error_message = str(exc)

        await self.db.flush()
        return campaign

    async def stop_campaign(self, campaign_id: UUID, project_id: UUID | None = None) -> FuzzingCampaign:
        """Stop a fuzzing campaign and clean up its container."""
        query = select(FuzzingCampaign).where(FuzzingCampaign.id == campaign_id)
        if project_id is not None:
            query = query.where(FuzzingCampaign.project_id == project_id)
        result = await self.db.execute(query)
        campaign = result.scalar_one_or_none()
        if not campaign:
            raise ValueError("Campaign not found")

        if campaign.status in ("stopped", "completed", "error"):
            return campaign

        # Sync crashes and stats before stopping
        if campaign.container_id:
            try:
                await self._sync_stats(campaign)
                await self._sync_crashes(campaign)
            except Exception:
                logger.warning("Failed to sync data before stopping campaign %s", campaign_id)

            try:
                client = self._get_docker_client()
                container = client.containers.get(campaign.container_id)
                container.stop(timeout=5)
                container.remove(force=True)
            except docker.errors.NotFound:
                logger.info("Container already removed: %s", campaign.container_id)
            except Exception:
                logger.exception("Error stopping container: %s", campaign.container_id)

        campaign.status = "stopped"
        campaign.stopped_at = datetime.now(timezone.utc)
        await self.db.flush()
        return campaign

    async def get_campaign_status(self, campaign_id: UUID, project_id: UUID | None = None) -> FuzzingCampaign:
        """Get live status of a fuzzing campaign, updating stats from container."""
        query = select(FuzzingCampaign).where(FuzzingCampaign.id == campaign_id)
        if project_id is not None:
            query = query.where(FuzzingCampaign.project_id == project_id)
        result = await self.db.execute(query)
        campaign = result.scalar_one_or_none()
        if not campaign:
            raise ValueError("Campaign not found")

        if campaign.status == "running" and campaign.container_id:
            try:
                client = self._get_docker_client()
                container = client.containers.get(campaign.container_id)

                if container.status != "running":
                    campaign.status = "error"
                    campaign.error_message = "Container exited unexpectedly"
                    campaign.stopped_at = datetime.now(timezone.utc)
                else:
                    await self._sync_stats(campaign)
                    await self._sync_crashes(campaign)

            except docker.errors.NotFound:
                campaign.status = "stopped"
                campaign.error_message = "Container no longer exists"
                campaign.stopped_at = datetime.now(timezone.utc)
            except Exception:
                logger.exception("Error checking campaign status")

            await self.db.flush()

        return campaign

    async def _sync_stats(self, campaign: FuzzingCampaign) -> None:
        """Read AFL++ fuzzer_stats from the container and update the campaign."""
        if not campaign.container_id:
            return

        client = self._get_docker_client()
        try:
            container = client.containers.get(campaign.container_id)
            result = container.exec_run([
                "cat", "/opt/fuzzing/output/default/fuzzer_stats"
            ])

            if result.exit_code != 0:
                return

            stats_text = result.output.decode("utf-8", errors="replace")
            stats = {}
            for line in stats_text.strip().split("\n"):
                if ":" in line:
                    key, _, value = line.partition(":")
                    key = key.strip()
                    value = value.strip()
                    # Parse numeric values
                    try:
                        if "." in value:
                            stats[key] = float(value)
                        else:
                            stats[key] = int(value)
                    except ValueError:
                        stats[key] = value

            campaign.stats = {
                "execs_per_sec": stats.get("execs_per_sec", 0),
                "total_execs": stats.get("execs_done", 0),
                "corpus_count": stats.get("corpus_count", stats.get("paths_total", 0)),
                "saved_crashes": stats.get("saved_crashes", stats.get("unique_crashes", 0)),
                "saved_hangs": stats.get("saved_hangs", stats.get("unique_hangs", 0)),
                "stability": stats.get("stability", "N/A"),
                "bitmap_cvg": stats.get("bitmap_cvg", "N/A"),
                "last_find": stats.get("last_find", 0),
                "run_time": stats.get("run_time", 0),
            }

        except docker.errors.NotFound:
            pass
        except Exception:
            logger.debug("Failed to sync stats for campaign %s", campaign.id)

    async def _sync_crashes(self, campaign: FuzzingCampaign) -> list[FuzzingCrash]:
        """Discover new crash files in the container and create DB records."""
        if not campaign.container_id:
            return []

        client = self._get_docker_client()
        new_crashes: list[FuzzingCrash] = []

        try:
            container = client.containers.get(campaign.container_id)

            # List crash files
            result = container.exec_run([
                "sh", "-c",
                "ls -1 /opt/fuzzing/output/default/crashes/ 2>/dev/null | grep -v README.txt"
            ])

            if result.exit_code != 0 or not result.output.strip():
                return []

            crash_files = result.output.decode("utf-8", errors="replace").strip().split("\n")

            # Get existing crash filenames for this campaign
            existing = await self.db.execute(
                select(FuzzingCrash.crash_filename).where(
                    FuzzingCrash.campaign_id == campaign.id
                )
            )
            existing_names = {row[0] for row in existing}

            for filename in crash_files:
                filename = filename.strip()
                if not filename or filename in existing_names:
                    continue

                # Read crash input bytes
                read_result = container.exec_run([
                    "cat", f"/opt/fuzzing/output/default/crashes/{filename}"
                ])
                crash_data = read_result.output if read_result.exit_code == 0 else None

                crash = FuzzingCrash(
                    campaign_id=campaign.id,
                    crash_filename=filename,
                    crash_input=crash_data,
                    crash_size=len(crash_data) if crash_data else 0,
                )
                self.db.add(crash)
                new_crashes.append(crash)

            if new_crashes:
                campaign.crashes_count = (campaign.crashes_count or 0) + len(new_crashes)
                await self.db.flush()

        except docker.errors.NotFound:
            pass
        except Exception:
            logger.debug("Failed to sync crashes for campaign %s", campaign.id)

        return new_crashes

    async def triage_crash(
        self, campaign_id: UUID, crash_id: UUID, project_id: UUID
    ) -> FuzzingCrash:
        """Reproduce a crash under QEMU user mode and classify exploitability.

        For cross-architecture firmware binaries, GDB alone cannot execute the
        binary on x86_64.  Instead we:
          1. Run the binary under qemu-{arch}-static with the crash input,
             capturing the exit signal.
          2. Optionally attach gdb-multiarch via QEMU's GDB server for a
             stack trace (best-effort).
        """
        result = await self.db.execute(
            select(FuzzingCrash)
            .join(FuzzingCampaign, FuzzingCrash.campaign_id == FuzzingCampaign.id)
            .where(
                FuzzingCrash.id == crash_id,
                FuzzingCrash.campaign_id == campaign_id,
                FuzzingCampaign.project_id == project_id,
            )
        )
        crash = result.scalar_one_or_none()
        if not crash:
            raise ValueError("Crash not found")

        # Get campaign and firmware
        camp_result = await self.db.execute(
            select(FuzzingCampaign).where(FuzzingCampaign.id == campaign_id)
        )
        campaign = camp_result.scalar_one_or_none()
        if not campaign or not campaign.container_id:
            raise ValueError("Campaign not found or container not available")

        fw_result = await self.db.execute(
            select(Firmware).where(Firmware.id == campaign.firmware_id)
        )
        firmware = fw_result.scalar_one_or_none()
        if not firmware:
            raise ValueError("Firmware not found")

        arch = firmware.architecture or "arm"
        qemu_bin = QEMU_USER_MAP.get(arch, "qemu-arm-static")

        client = self._get_docker_client()
        try:
            container = client.containers.get(campaign.container_id)
        except docker.errors.NotFound:
            raise ValueError("Campaign container not found — campaign may have been stopped")

        binary_in_firmware = campaign.binary_path.lstrip("/")
        crash_path = f"/opt/fuzzing/output/default/crashes/{crash.crash_filename}"

        triage_output = ""

        try:
            # Step 1: Reproduce the crash under QEMU user-mode to get the signal
            reproduce_cmd = (
                f"QEMU_LD_PREFIX=/firmware "
                f"timeout 30 {qemu_bin} /firmware/{binary_in_firmware} "
                f"< {crash_path} 2>&1; echo EXIT_CODE=$?"
            )
            reproduce_result = container.exec_run(
                ["sh", "-c", reproduce_cmd], demux=True
            )
            stdout = (reproduce_result.output[0] or b"").decode("utf-8", errors="replace")
            stderr = (reproduce_result.output[1] or b"").decode("utf-8", errors="replace")

            triage_output = f"=== QEMU reproduction ({qemu_bin}) ===\n{stdout}"
            if stderr:
                triage_output += f"\n--- stderr ---\n{stderr}"

            # Step 2: Try GDB remote debugging for a stack trace.
            # Launch QEMU with -g (GDB server) on a known port, then connect
            # gdb-multiarch to get a backtrace.
            gdb_port = 12345
            gdb_cmd = (
                f"timeout 30 sh -c '"
                f"QEMU_LD_PREFIX=/firmware "
                f"{qemu_bin} -g {gdb_port} /firmware/{binary_in_firmware} "
                f"< {crash_path} &"
                f" sleep 1 &&"
                f" gdb-multiarch -batch"
                f" -ex \"set confirm off\""
                f" -ex \"target remote :{gdb_port}\""
                f" -ex \"continue\""
                f" -ex \"bt\""
                f" -ex \"info registers\""
                f" /firmware/{binary_in_firmware}"
                f"'"
            )
            gdb_result = container.exec_run(["sh", "-c", gdb_cmd], demux=True)
            gdb_stdout = (gdb_result.output[0] or b"").decode("utf-8", errors="replace")
            gdb_stderr = (gdb_result.output[1] or b"").decode("utf-8", errors="replace")

            if gdb_stdout.strip():
                triage_output += f"\n\n=== GDB backtrace ===\n{gdb_stdout}"
            if gdb_stderr.strip():
                triage_output += f"\n--- gdb stderr ---\n{gdb_stderr}"

            # Classify based on signal
            signal = None
            exploitability = "unknown"

            # Check QEMU output and exit code for signal info
            combined = triage_output

            if "SIGSEGV" in combined or "Segmentation fault" in combined:
                signal = "SIGSEGV"
                exploitability = "probably_exploitable"
            elif "SIGABRT" in combined or "Aborted" in combined:
                signal = "SIGABRT"
                exploitability = "exploitable"
            elif "SIGBUS" in combined or "Bus error" in combined:
                signal = "SIGBUS"
                exploitability = "probably_exploitable"
            elif "SIGFPE" in combined:
                signal = "SIGFPE"
                exploitability = "probably_not"
            elif "SIGILL" in combined or "Illegal instruction" in combined:
                signal = "SIGILL"
                exploitability = "probably_exploitable"
            elif "SIGTRAP" in combined:
                signal = "SIGTRAP"
                exploitability = "probably_not"
            else:
                # Infer from QEMU exit code (128 + signal_number)
                exit_code = reproduce_result.exit_code or 0
                if exit_code > 128:
                    sig_num = exit_code - 128
                    sig_map = {11: "SIGSEGV", 6: "SIGABRT", 7: "SIGBUS",
                               8: "SIGFPE", 4: "SIGILL", 5: "SIGTRAP"}
                    signal = sig_map.get(sig_num, f"SIG{sig_num}")
                    if signal in ("SIGSEGV", "SIGBUS", "SIGILL"):
                        exploitability = "probably_exploitable"
                    elif signal == "SIGABRT":
                        exploitability = "exploitable"
                    else:
                        exploitability = "unknown"

            # Extract stack trace from GDB output
            stack_trace = ""
            in_bt = False
            for line in triage_output.split("\n"):
                if line.startswith("#"):
                    in_bt = True
                    stack_trace += line + "\n"
                elif in_bt and not line.strip():
                    break
                elif in_bt:
                    stack_trace += line + "\n"

            crash.signal = signal
            crash.exploitability = exploitability
            crash.stack_trace = stack_trace.strip() if stack_trace else None
            crash.triage_output = triage_output[:10000]  # cap at 10KB

        except Exception as exc:
            crash.triage_output = f"Triage failed: {exc}"
            crash.exploitability = "unknown"

        await self.db.flush()
        return crash

    async def list_campaigns(self, project_id: UUID) -> list[FuzzingCampaign]:
        """List all fuzzing campaigns for a project."""
        result = await self.db.execute(
            select(FuzzingCampaign)
            .where(FuzzingCampaign.project_id == project_id)
            .order_by(FuzzingCampaign.created_at.desc())
        )
        return list(result.scalars().all())

    async def get_crashes(self, campaign_id: UUID, project_id: UUID) -> list[FuzzingCrash]:
        """List all crashes for a campaign, verifying project ownership."""
        result = await self.db.execute(
            select(FuzzingCrash)
            .join(FuzzingCampaign, FuzzingCrash.campaign_id == FuzzingCampaign.id)
            .where(
                FuzzingCrash.campaign_id == campaign_id,
                FuzzingCampaign.project_id == project_id,
            )
            .order_by(FuzzingCrash.created_at.desc())
        )
        return list(result.scalars().all())

    async def get_crash_detail(
        self, campaign_id: UUID, crash_id: UUID, project_id: UUID
    ) -> FuzzingCrash:
        """Get a single crash with full details, verifying project ownership."""
        result = await self.db.execute(
            select(FuzzingCrash)
            .join(FuzzingCampaign, FuzzingCrash.campaign_id == FuzzingCampaign.id)
            .where(
                FuzzingCrash.id == crash_id,
                FuzzingCrash.campaign_id == campaign_id,
                FuzzingCampaign.project_id == project_id,
            )
        )
        crash = result.scalar_one_or_none()
        if not crash:
            raise ValueError("Crash not found")
        return crash

    async def cleanup_expired(self) -> int:
        """Stop campaigns that have exceeded the timeout. Returns count stopped."""
        timeout_minutes = self._settings.fuzzing_timeout_minutes
        cutoff = datetime.now(timezone.utc).timestamp() - (timeout_minutes * 60)

        result = await self.db.execute(
            select(FuzzingCampaign).where(
                FuzzingCampaign.status == "running",
                FuzzingCampaign.started_at.isnot(None),
            )
        )
        campaigns = result.scalars().all()
        count = 0

        for campaign in campaigns:
            if campaign.started_at and campaign.started_at.timestamp() < cutoff:
                try:
                    await self.stop_campaign(campaign.id)
                    count += 1
                except Exception:
                    logger.exception("Failed to stop expired campaign: %s", campaign.id)

        return count
