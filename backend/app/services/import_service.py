"""Project import service — restores a .wairz ZIP archive into a new project."""

import base64
import io
import json
import os
import stat
import uuid
import zipfile
from datetime import datetime

from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.models.analysis_cache import AnalysisCache
from app.models.document import Document
from app.models.emulation_preset import EmulationPreset
from app.models.finding import Finding
from app.models.firmware import Firmware
from app.models.fuzzing import FuzzingCampaign, FuzzingCrash
from app.models.project import Project
from app.models.sbom import SbomComponent, SbomVulnerability
from app.services.export_service import ARCHIVE_VERSION


def _parse_dt(val) -> datetime | None:
    """Parse an ISO datetime string or return None."""
    if val is None:
        return None
    if isinstance(val, datetime):
        return val
    try:
        return datetime.fromisoformat(val)
    except (TypeError, ValueError):
        return None


class ImportService:
    def __init__(self, db: AsyncSession):
        self.db = db
        self.settings = get_settings()

    async def import_project(self, archive_bytes: bytes) -> Project:
        """Import a .wairz archive, creating a new project with remapped UUIDs.

        Returns the newly created Project ORM object.
        """
        buf = io.BytesIO(archive_bytes)
        try:
            zf = zipfile.ZipFile(buf, "r")
        except zipfile.BadZipFile as exc:
            raise ValueError("Invalid archive: not a valid ZIP file") from exc

        # Validate: check for zip-slip paths
        for name in zf.namelist():
            if name.startswith("/") or ".." in name.split("/"):
                raise ValueError(f"Invalid archive: suspicious path '{name}'")

        # ── Read manifest ──────────────────────────────────────────
        try:
            manifest = json.loads(zf.read("manifest.json"))
        except KeyError as exc:
            raise ValueError("Invalid archive: missing manifest.json") from exc

        version = manifest.get("archive_version", 0)
        if version > ARCHIVE_VERSION:
            raise ValueError(
                f"Archive version {version} is newer than supported ({ARCHIVE_VERSION}). "
                "Please update your Wairz instance."
            )

        # ── Read project metadata ─────────────────────────────────
        try:
            project_data = json.loads(zf.read("project.json"))
        except KeyError as exc:
            raise ValueError("Invalid archive: missing project.json") from exc

        # ── Generate new IDs ───────────────────────────────────────
        new_project_id = uuid.uuid4()

        # Old ID → New ID mappings
        id_map: dict[str, uuid.UUID] = {
            project_data["id"]: new_project_id,
        }

        # ── Create project ─────────────────────────────────────────
        project = Project(
            id=new_project_id,
            name=project_data["name"],
            description=project_data.get("description"),
            status=project_data.get("status", "created"),
        )
        self.db.add(project)

        # ── Create project directory structure ─────────────────────
        project_dir = os.path.join(
            self.settings.storage_root, "projects", str(new_project_id)
        )
        os.makedirs(project_dir, exist_ok=True)

        # ── Import firmware ────────────────────────────────────────
        firmware_entries = self._list_firmware_dirs(zf)
        for old_fw_id_str in firmware_entries:
            await self._import_firmware(zf, old_fw_id_str, new_project_id, id_map)

        # ── Import findings ────────────────────────────────────────
        await self._import_findings(zf, new_project_id, id_map)

        # ── Import documents ───────────────────────────────────────
        await self._import_documents(zf, new_project_id, id_map)

        # ── Import emulation presets ───────────────────────────────
        await self._import_emulation_presets(zf, new_project_id, id_map)

        # ── Import per-firmware data ───────────────────────────────
        for old_fw_id_str in firmware_entries:
            new_fw_id = id_map.get(old_fw_id_str)
            if not new_fw_id:
                continue
            await self._import_analysis_cache(zf, old_fw_id_str, new_fw_id, id_map)
            await self._import_sbom(zf, old_fw_id_str, new_fw_id, id_map)
            await self._import_fuzzing(zf, old_fw_id_str, new_fw_id, new_project_id, id_map)

        await self.db.flush()
        return project

    # ── Firmware ───────────────────────────────────────────────────

    def _list_firmware_dirs(self, zf: zipfile.ZipFile) -> list[str]:
        """Find all firmware/{uuid}/ directories in the archive."""
        fw_ids = set()
        for name in zf.namelist():
            if name.startswith("firmware/") and name.count("/") >= 2:
                parts = name.split("/")
                if len(parts) >= 2 and parts[1]:
                    fw_ids.add(parts[1])
        return sorted(fw_ids)

    async def _import_firmware(
        self,
        zf: zipfile.ZipFile,
        old_fw_id_str: str,
        new_project_id: uuid.UUID,
        id_map: dict[str, uuid.UUID],
    ) -> None:
        prefix = f"firmware/{old_fw_id_str}"

        # Read metadata
        try:
            fw_data = json.loads(zf.read(f"{prefix}/metadata.json"))
        except KeyError:
            return

        new_fw_id = uuid.uuid4()
        id_map[old_fw_id_str] = new_fw_id

        # Create firmware directory on disk
        fw_dir = os.path.join(
            self.settings.storage_root,
            "projects",
            str(new_project_id),
            "firmware",
            str(new_fw_id),
        )
        os.makedirs(fw_dir, exist_ok=True)

        # Extract original firmware binary
        storage_path = None
        orig_prefix = f"{prefix}/original/"
        orig_files = [n for n in zf.namelist() if n.startswith(orig_prefix) and n != orig_prefix]
        if orig_files:
            orig_name = os.path.basename(orig_files[0])
            storage_path = os.path.join(fw_dir, orig_name)
            with zf.open(orig_files[0]) as src, open(storage_path, "wb") as dst:
                while chunk := src.read(65536):
                    dst.write(chunk)

        # Extract extracted filesystem
        extracted_path = None
        extracted_prefix = f"{prefix}/extracted/"
        extracted_files = [
            n for n in zf.namelist()
            if n.startswith(extracted_prefix) and n != extracted_prefix
        ]
        if extracted_files:
            extracted_path = os.path.join(fw_dir, "_extracted")
            os.makedirs(extracted_path, exist_ok=True)
            self._extract_filesystem(zf, extracted_prefix, extracted_path)

        firmware = Firmware(
            id=new_fw_id,
            project_id=new_project_id,
            original_filename=fw_data.get("original_filename"),
            sha256=fw_data.get("sha256", ""),
            file_size=fw_data.get("file_size"),
            storage_path=storage_path,
            extracted_path=extracted_path,
            architecture=fw_data.get("architecture"),
            endianness=fw_data.get("endianness"),
            os_info=fw_data.get("os_info"),
            kernel_path=fw_data.get("kernel_path"),
            version_label=fw_data.get("version_label"),
            unpack_log=fw_data.get("unpack_log"),
        )
        self.db.add(firmware)

    def _extract_filesystem(
        self, zf: zipfile.ZipFile, prefix: str, dest_root: str
    ) -> None:
        """Extract an archived filesystem to disk, restoring symlinks and permissions."""
        # First pass: extract all regular files
        symlinks: list[tuple[str, str]] = []
        permissions_data: list[dict] = []

        # Read permissions manifest if present
        perms_path = f"{prefix}permissions.json"
        if perms_path in zf.namelist():
            try:
                permissions_data = json.loads(zf.read(perms_path))
            except (json.JSONDecodeError, KeyError):
                pass

        # Build symlink map from permissions data
        symlink_map: dict[str, str] = {}
        for entry in permissions_data:
            if entry.get("type") == "symlink":
                symlink_map[entry["path"]] = entry["target"]

        # Extract files from the archive
        for name in sorted(zf.namelist()):
            if not name.startswith(prefix) or name == prefix:
                continue
            if name == perms_path:
                continue

            rel = name[len(prefix):]
            if not rel:
                continue

            # Handle .symlink marker files
            if rel.endswith(".symlink"):
                target = zf.read(name).decode("utf-8", errors="replace")
                real_rel = rel[:-8]  # strip .symlink suffix
                dest = os.path.join(dest_root, real_rel)
                os.makedirs(os.path.dirname(dest), exist_ok=True)
                if os.path.lexists(dest):
                    os.unlink(dest)
                try:
                    os.symlink(target, dest)
                except OSError:
                    pass
                continue

            dest = os.path.join(dest_root, rel)

            # Directory
            if name.endswith("/"):
                os.makedirs(dest, exist_ok=True)
                continue

            # Regular file
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            with zf.open(name) as src, open(dest, "wb") as dst:
                while chunk := src.read(65536):
                    dst.write(chunk)

        # Apply permissions from manifest
        for entry in permissions_data:
            if entry.get("type") in ("file", "directory"):
                path = os.path.join(dest_root, entry["path"])
                if os.path.exists(path):
                    try:
                        mode = int(entry.get("mode", "0o644"), 8)
                        os.chmod(path, mode)
                    except (OSError, ValueError):
                        pass

    # ── Findings ───────────────────────────────────────────────────

    async def _import_findings(
        self,
        zf: zipfile.ZipFile,
        new_project_id: uuid.UUID,
        id_map: dict[str, uuid.UUID],
    ) -> None:
        try:
            findings_data = json.loads(zf.read("findings.json"))
        except KeyError:
            return

        for f in findings_data:
            old_id = f.get("id", "")
            new_id = uuid.uuid4()
            id_map[old_id] = new_id

            finding = Finding(
                id=new_id,
                project_id=new_project_id,
                title=f["title"],
                severity=f["severity"],
                description=f.get("description"),
                evidence=f.get("evidence"),
                file_path=f.get("file_path"),
                line_number=f.get("line_number"),
                cve_ids=f.get("cve_ids"),
                cwe_ids=f.get("cwe_ids"),
                status=f.get("status", "open"),
                source=f.get("source", "manual"),
            )
            self.db.add(finding)

    # ── Documents ──────────────────────────────────────────────────

    async def _import_documents(
        self,
        zf: zipfile.ZipFile,
        new_project_id: uuid.UUID,
        id_map: dict[str, uuid.UUID],
    ) -> None:
        try:
            docs_data = json.loads(zf.read("documents/metadata.json"))
        except KeyError:
            return

        doc_dir = os.path.join(
            self.settings.storage_root,
            "projects",
            str(new_project_id),
            "documents",
        )
        os.makedirs(doc_dir, exist_ok=True)

        for d in docs_data:
            old_id = d.get("id", "")
            new_id = uuid.uuid4()
            id_map[old_id] = new_id

            # Look for the document file in the archive
            arc_name = f"documents/files/{old_id}_{d['original_filename']}"
            storage_path = os.path.join(
                doc_dir, f"{new_id}_{d['original_filename']}"
            )

            if arc_name in zf.namelist():
                with zf.open(arc_name) as src, open(storage_path, "wb") as dst:
                    while chunk := src.read(65536):
                        dst.write(chunk)
            else:
                storage_path = ""

            doc = Document(
                id=new_id,
                project_id=new_project_id,
                original_filename=d["original_filename"],
                description=d.get("description"),
                content_type=d.get("content_type", "application/octet-stream"),
                file_size=d.get("file_size", 0),
                sha256=d.get("sha256", ""),
                storage_path=storage_path,
            )
            self.db.add(doc)

    # ── Emulation Presets ──────────────────────────────────────────

    async def _import_emulation_presets(
        self,
        zf: zipfile.ZipFile,
        new_project_id: uuid.UUID,
        id_map: dict[str, uuid.UUID],
    ) -> None:
        try:
            presets_data = json.loads(zf.read("emulation_presets.json"))
        except KeyError:
            return

        for p in presets_data:
            old_id = p.get("id", "")
            new_id = uuid.uuid4()
            id_map[old_id] = new_id

            preset = EmulationPreset(
                id=new_id,
                project_id=new_project_id,
                name=p["name"],
                description=p.get("description"),
                mode=p["mode"],
                binary_path=p.get("binary_path"),
                arguments=p.get("arguments"),
                architecture=p.get("architecture"),
                port_forwards=p.get("port_forwards"),
                kernel_name=p.get("kernel_name"),
                init_path=p.get("init_path"),
                pre_init_script=p.get("pre_init_script"),
                stub_profile=p.get("stub_profile", "none"),
            )
            self.db.add(preset)

    # ── Analysis Cache ─────────────────────────────────────────────

    async def _import_analysis_cache(
        self,
        zf: zipfile.ZipFile,
        old_fw_id_str: str,
        new_fw_id: uuid.UUID,
        id_map: dict[str, uuid.UUID],
    ) -> None:
        try:
            cache_data = json.loads(
                zf.read(f"firmware/{old_fw_id_str}/analysis_cache.json")
            )
        except KeyError:
            return

        for c in cache_data:
            entry = AnalysisCache(
                id=uuid.uuid4(),
                firmware_id=new_fw_id,
                binary_path=c.get("binary_path"),
                binary_sha256=c.get("binary_sha256"),
                operation=c["operation"],
                result=c.get("result"),
            )
            self.db.add(entry)

    # ── SBOM ───────────────────────────────────────────────────────

    async def _import_sbom(
        self,
        zf: zipfile.ZipFile,
        old_fw_id_str: str,
        new_fw_id: uuid.UUID,
        id_map: dict[str, uuid.UUID],
    ) -> None:
        # Components
        try:
            components_data = json.loads(
                zf.read(f"firmware/{old_fw_id_str}/sbom_components.json")
            )
        except KeyError:
            components_data = []

        for c in components_data:
            old_id = c.get("id", "")
            new_id = uuid.uuid4()
            id_map[old_id] = new_id

            comp = SbomComponent(
                id=new_id,
                firmware_id=new_fw_id,
                name=c["name"],
                version=c.get("version"),
                type=c["type"],
                cpe=c.get("cpe"),
                purl=c.get("purl"),
                supplier=c.get("supplier"),
                detection_source=c["detection_source"],
                detection_confidence=c.get("detection_confidence"),
                file_paths=c.get("file_paths"),
                metadata_=c.get("metadata", {}),
            )
            self.db.add(comp)

        # Vulnerabilities
        try:
            vulns_data = json.loads(
                zf.read(f"firmware/{old_fw_id_str}/sbom_vulnerabilities.json")
            )
        except KeyError:
            vulns_data = []

        for v in vulns_data:
            old_comp_id = v.get("component_id", "")
            new_comp_id = id_map.get(old_comp_id)
            if not new_comp_id:
                continue

            # Resolve finding_id if it was mapped
            old_finding_id = v.get("finding_id")
            new_finding_id = id_map.get(old_finding_id) if old_finding_id else None

            vuln = SbomVulnerability(
                id=uuid.uuid4(),
                component_id=new_comp_id,
                firmware_id=new_fw_id,
                cve_id=v["cve_id"],
                cvss_score=v.get("cvss_score"),
                cvss_vector=v.get("cvss_vector"),
                severity=v["severity"],
                description=v.get("description"),
                published_date=_parse_dt(v.get("published_date")),
            )
            # Set finding_id after creation to avoid FK issues during flush
            if new_finding_id:
                vuln.finding_id = new_finding_id
            self.db.add(vuln)

    # ── Fuzzing ────────────────────────────────────────────────────

    async def _import_fuzzing(
        self,
        zf: zipfile.ZipFile,
        old_fw_id_str: str,
        new_fw_id: uuid.UUID,
        new_project_id: uuid.UUID,
        id_map: dict[str, uuid.UUID],
    ) -> None:
        try:
            campaigns_data = json.loads(
                zf.read(f"firmware/{old_fw_id_str}/fuzzing_campaigns.json")
            )
        except KeyError:
            return

        for c in campaigns_data:
            old_id = c.get("id", "")
            new_id = uuid.uuid4()
            id_map[old_id] = new_id

            # Imported campaigns are always in stopped state
            imported_status = "stopped" if c.get("status") == "running" else c.get("status", "created")

            campaign = FuzzingCampaign(
                id=new_id,
                project_id=new_project_id,
                firmware_id=new_fw_id,
                binary_path=c["binary_path"],
                status=imported_status,
                config=c.get("config"),
                stats=c.get("stats"),
                crashes_count=c.get("crashes_count", 0),
                error_message=c.get("error_message"),
                started_at=_parse_dt(c.get("started_at")),
                stopped_at=_parse_dt(c.get("stopped_at")),
            )
            self.db.add(campaign)

            # Import crashes
            crashes = c.get("_crashes", [])
            for cr in crashes:
                # Decode crash_input from base64
                crash_input = None
                raw = cr.get("crash_input")
                if raw and isinstance(raw, str):
                    try:
                        crash_input = base64.b64decode(raw)
                    except Exception:
                        pass
                elif isinstance(raw, bytes):
                    crash_input = raw

                crash = FuzzingCrash(
                    id=uuid.uuid4(),
                    campaign_id=new_id,
                    crash_filename=cr["crash_filename"],
                    crash_input=crash_input,
                    crash_size=cr.get("crash_size"),
                    signal=cr.get("signal"),
                    stack_trace=cr.get("stack_trace"),
                    exploitability=cr.get("exploitability"),
                    triage_output=cr.get("triage_output"),
                )
                # Resolve finding_id
                old_finding = cr.get("finding_id")
                if old_finding and old_finding in id_map:
                    crash.finding_id = id_map[old_finding]
                self.db.add(crash)
