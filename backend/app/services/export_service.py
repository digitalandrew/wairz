"""Project export service — builds a self-contained .wairz ZIP archive."""

import base64
import io
import json
import os
import stat
import uuid
import zipfile
from datetime import datetime, timezone

from sqlalchemy import select
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

ARCHIVE_VERSION = 1


def _json_serial(obj):
    """JSON serializer for objects not serializable by default."""
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, uuid.UUID):
        return str(obj)
    if isinstance(obj, bytes):
        return base64.b64encode(obj).decode("ascii")
    raise TypeError(f"Type {type(obj)} not serializable")


def _dumps(obj) -> str:
    return json.dumps(obj, default=_json_serial, indent=2)


class ExportService:
    def __init__(self, db: AsyncSession):
        self.db = db
        self.settings = get_settings()

    async def export_project(self, project_id: uuid.UUID) -> io.BytesIO:
        """Build a .wairz ZIP archive for the given project.

        Returns an in-memory BytesIO containing the ZIP file.
        """
        # ── Load all project data ──────────────────────────────────
        project = await self._load_project(project_id)
        firmware_list = await self._load_firmware(project_id)
        findings = await self._load_findings(project_id)
        documents = await self._load_documents(project_id)
        presets = await self._load_emulation_presets(project_id)

        # Per-firmware data
        firmware_data = {}
        for fw in firmware_list:
            fw_id = fw.id
            firmware_data[fw_id] = {
                "analysis_cache": await self._load_analysis_cache(fw_id),
                "sbom_components": await self._load_sbom_components(fw_id),
                "sbom_vulnerabilities": await self._load_sbom_vulnerabilities(fw_id),
                "fuzzing_campaigns": await self._load_fuzzing_campaigns(fw_id),
            }
            # Fuzzing crashes keyed by campaign
            for campaign in firmware_data[fw_id]["fuzzing_campaigns"]:
                campaign["_crashes"] = await self._load_fuzzing_crashes(campaign["id"])

        # ── Build ZIP ──────────────────────────────────────────────
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            # Manifest
            manifest = {
                "archive_version": ARCHIVE_VERSION,
                "exported_at": datetime.now(timezone.utc).isoformat(),
                "project_id": str(project_id),
                "project_name": project["name"],
            }
            zf.writestr("manifest.json", _dumps(manifest))

            # Project metadata
            zf.writestr("project.json", _dumps(project))

            # Findings
            zf.writestr("findings.json", _dumps(findings))

            # Documents metadata + files
            zf.writestr("documents/metadata.json", _dumps(documents))
            for doc in documents:
                doc_path = doc.get("storage_path")
                if doc_path and os.path.isfile(doc_path):
                    arcname = f"documents/files/{doc['id']}_{doc['original_filename']}"
                    zf.write(doc_path, arcname)

            # Emulation presets
            zf.writestr("emulation_presets.json", _dumps(presets))

            # Firmware (metadata + files)
            for fw in firmware_list:
                fw_id_str = str(fw.id)
                fw_prefix = f"firmware/{fw_id_str}"

                # Firmware metadata
                fw_dict = self._firmware_to_dict(fw)
                zf.writestr(f"{fw_prefix}/metadata.json", _dumps(fw_dict))

                # Original firmware binary
                if fw.storage_path and os.path.isfile(fw.storage_path):
                    orig_name = os.path.basename(fw.storage_path)
                    zf.write(fw.storage_path, f"{fw_prefix}/original/{orig_name}")

                # Extracted filesystem — walk and add each file
                extracted_root = self._get_extracted_root(fw)
                if extracted_root and os.path.isdir(extracted_root):
                    self._add_extracted_fs(zf, extracted_root, f"{fw_prefix}/extracted")

                # Per-firmware DB data
                fwd = firmware_data[fw.id]
                zf.writestr(f"{fw_prefix}/analysis_cache.json", _dumps(fwd["analysis_cache"]))
                zf.writestr(f"{fw_prefix}/sbom_components.json", _dumps(fwd["sbom_components"]))
                zf.writestr(f"{fw_prefix}/sbom_vulnerabilities.json", _dumps(fwd["sbom_vulnerabilities"]))

                # Fuzzing campaigns + crashes
                campaigns = fwd["fuzzing_campaigns"]
                zf.writestr(f"{fw_prefix}/fuzzing_campaigns.json", _dumps(campaigns))

        buf.seek(0)
        return buf

    # ── DB loaders ─────────────────────────────────────────────────

    async def _load_project(self, project_id: uuid.UUID) -> dict:
        result = await self.db.execute(
            select(Project).where(Project.id == project_id)
        )
        project = result.scalar_one_or_none()
        if not project:
            raise ValueError(f"Project {project_id} not found")
        return {
            "id": str(project.id),
            "name": project.name,
            "description": project.description,
            "status": project.status,
            "created_at": project.created_at,
            "updated_at": project.updated_at,
        }

    async def _load_firmware(self, project_id: uuid.UUID) -> list:
        result = await self.db.execute(
            select(Firmware)
            .where(Firmware.project_id == project_id)
            .order_by(Firmware.created_at)
        )
        return list(result.scalars().all())

    def _firmware_to_dict(self, fw: Firmware) -> dict:
        return {
            "id": str(fw.id),
            "project_id": str(fw.project_id),
            "original_filename": fw.original_filename,
            "sha256": fw.sha256,
            "file_size": fw.file_size,
            "architecture": fw.architecture,
            "endianness": fw.endianness,
            "os_info": fw.os_info,
            "kernel_path": fw.kernel_path,
            "version_label": fw.version_label,
            "unpack_log": fw.unpack_log,
            "created_at": fw.created_at,
        }

    async def _load_findings(self, project_id: uuid.UUID) -> list[dict]:
        result = await self.db.execute(
            select(Finding)
            .where(Finding.project_id == project_id)
            .order_by(Finding.created_at)
        )
        findings = result.scalars().all()
        return [
            {
                "id": str(f.id),
                "project_id": str(f.project_id),
                "title": f.title,
                "severity": f.severity,
                "description": f.description,
                "evidence": f.evidence,
                "file_path": f.file_path,
                "line_number": f.line_number,
                "cve_ids": f.cve_ids,
                "cwe_ids": f.cwe_ids,
                "status": f.status,
                "source": f.source,
                "created_at": f.created_at,
                "updated_at": f.updated_at,
            }
            for f in findings
        ]

    async def _load_documents(self, project_id: uuid.UUID) -> list[dict]:
        result = await self.db.execute(
            select(Document)
            .where(Document.project_id == project_id)
            .order_by(Document.created_at)
        )
        docs = result.scalars().all()
        return [
            {
                "id": str(d.id),
                "project_id": str(d.project_id),
                "original_filename": d.original_filename,
                "description": d.description,
                "content_type": d.content_type,
                "file_size": d.file_size,
                "sha256": d.sha256,
                "storage_path": d.storage_path,
                "created_at": d.created_at,
            }
            for d in docs
        ]

    async def _load_emulation_presets(self, project_id: uuid.UUID) -> list[dict]:
        result = await self.db.execute(
            select(EmulationPreset)
            .where(EmulationPreset.project_id == project_id)
            .order_by(EmulationPreset.created_at)
        )
        presets = result.scalars().all()
        return [
            {
                "id": str(p.id),
                "project_id": str(p.project_id),
                "name": p.name,
                "description": p.description,
                "mode": p.mode,
                "binary_path": p.binary_path,
                "arguments": p.arguments,
                "architecture": p.architecture,
                "port_forwards": p.port_forwards,
                "kernel_name": p.kernel_name,
                "init_path": p.init_path,
                "pre_init_script": p.pre_init_script,
                "stub_profile": p.stub_profile,
                "created_at": p.created_at,
                "updated_at": p.updated_at,
            }
            for p in presets
        ]

    async def _load_analysis_cache(self, firmware_id: uuid.UUID) -> list[dict]:
        result = await self.db.execute(
            select(AnalysisCache)
            .where(AnalysisCache.firmware_id == firmware_id)
            .order_by(AnalysisCache.created_at)
        )
        rows = result.scalars().all()
        return [
            {
                "id": str(r.id),
                "firmware_id": str(r.firmware_id),
                "binary_path": r.binary_path,
                "binary_sha256": r.binary_sha256,
                "operation": r.operation,
                "result": r.result,
                "created_at": r.created_at,
            }
            for r in rows
        ]

    async def _load_sbom_components(self, firmware_id: uuid.UUID) -> list[dict]:
        result = await self.db.execute(
            select(SbomComponent)
            .where(SbomComponent.firmware_id == firmware_id)
            .order_by(SbomComponent.created_at)
        )
        components = result.scalars().all()
        return [
            {
                "id": str(c.id),
                "firmware_id": str(c.firmware_id),
                "name": c.name,
                "version": c.version,
                "type": c.type,
                "cpe": c.cpe,
                "purl": c.purl,
                "supplier": c.supplier,
                "detection_source": c.detection_source,
                "detection_confidence": c.detection_confidence,
                "file_paths": c.file_paths,
                "metadata": c.metadata_,
                "created_at": c.created_at,
            }
            for c in components
        ]

    async def _load_sbom_vulnerabilities(self, firmware_id: uuid.UUID) -> list[dict]:
        result = await self.db.execute(
            select(SbomVulnerability)
            .where(SbomVulnerability.firmware_id == firmware_id)
            .order_by(SbomVulnerability.created_at)
        )
        vulns = result.scalars().all()
        return [
            {
                "id": str(v.id),
                "component_id": str(v.component_id),
                "firmware_id": str(v.firmware_id),
                "cve_id": v.cve_id,
                "cvss_score": float(v.cvss_score) if v.cvss_score is not None else None,
                "cvss_vector": v.cvss_vector,
                "severity": v.severity,
                "description": v.description,
                "published_date": v.published_date,
                "created_at": v.created_at,
            }
            for v in vulns
        ]

    async def _load_fuzzing_campaigns(self, firmware_id: uuid.UUID) -> list[dict]:
        result = await self.db.execute(
            select(FuzzingCampaign)
            .where(FuzzingCampaign.firmware_id == firmware_id)
            .order_by(FuzzingCampaign.created_at)
        )
        campaigns = result.scalars().all()
        return [
            {
                "id": str(c.id),
                "project_id": str(c.project_id),
                "firmware_id": str(c.firmware_id),
                "binary_path": c.binary_path,
                "status": c.status,
                "config": c.config,
                "stats": c.stats,
                "crashes_count": c.crashes_count,
                "error_message": c.error_message,
                "started_at": c.started_at,
                "stopped_at": c.stopped_at,
                "created_at": c.created_at,
            }
            for c in campaigns
        ]

    async def _load_fuzzing_crashes(self, campaign_id: str) -> list[dict]:
        result = await self.db.execute(
            select(FuzzingCrash)
            .where(FuzzingCrash.campaign_id == uuid.UUID(campaign_id))
            .order_by(FuzzingCrash.created_at)
        )
        crashes = result.scalars().all()
        return [
            {
                "id": str(c.id),
                "campaign_id": str(c.campaign_id),
                "crash_filename": c.crash_filename,
                "crash_input": c.crash_input,  # base64-encoded via _json_serial
                "crash_size": c.crash_size,
                "signal": c.signal,
                "stack_trace": c.stack_trace,
                "exploitability": c.exploitability,
                "triage_output": c.triage_output,
                "created_at": c.created_at,
            }
            for c in crashes
        ]

    # ── Filesystem helpers ─────────────────────────────────────────

    def _get_extracted_root(self, fw: Firmware) -> str | None:
        """Determine the extracted filesystem root directory for a firmware."""
        if fw.extracted_path and os.path.isdir(fw.extracted_path):
            return fw.extracted_path
        if fw.storage_path:
            candidate = os.path.join(os.path.dirname(fw.storage_path), "_extracted")
            if os.path.isdir(candidate):
                return candidate
        return None

    def _add_extracted_fs(
        self, zf: zipfile.ZipFile, root: str, arcprefix: str
    ) -> None:
        """Walk an extracted filesystem and add all files to the ZIP.

        Preserves file permissions in a sidecar permissions.json manifest
        and handles symlinks by storing their targets.
        """
        permissions: list[dict] = []

        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            rel_dir = os.path.relpath(dirpath, root)
            if rel_dir == ".":
                rel_dir = ""

            # Add directory entries
            for dirname in dirnames:
                full = os.path.join(dirpath, dirname)
                rel = os.path.join(rel_dir, dirname) if rel_dir else dirname
                arc = f"{arcprefix}/{rel}/"

                if os.path.islink(full):
                    target = os.readlink(full)
                    permissions.append({
                        "path": rel,
                        "type": "symlink",
                        "target": target,
                    })
                    # Store symlink as a small text file
                    zf.writestr(arc.rstrip("/") + ".symlink", target)
                else:
                    try:
                        st = os.lstat(full)
                        mode = stat.S_IMODE(st.st_mode)
                    except OSError:
                        mode = 0o755
                    permissions.append({
                        "path": rel,
                        "type": "directory",
                        "mode": oct(mode),
                        "uid": st.st_uid if st else 0,
                        "gid": st.st_gid if st else 0,
                    })

            for filename in filenames:
                full = os.path.join(dirpath, filename)
                rel = os.path.join(rel_dir, filename) if rel_dir else filename
                arc = f"{arcprefix}/{rel}"

                if os.path.islink(full):
                    target = os.readlink(full)
                    permissions.append({
                        "path": rel,
                        "type": "symlink",
                        "target": target,
                    })
                    zf.writestr(arc + ".symlink", target)
                else:
                    try:
                        st = os.lstat(full)
                        mode = stat.S_IMODE(st.st_mode)
                    except OSError:
                        mode = 0o644
                        st = None
                    permissions.append({
                        "path": rel,
                        "type": "file",
                        "mode": oct(mode),
                        "uid": st.st_uid if st else 0,
                        "gid": st.st_gid if st else 0,
                    })
                    try:
                        zf.write(full, arc)
                    except (OSError, PermissionError):
                        # Skip unreadable files, note in permissions
                        permissions.append({
                            "path": rel,
                            "type": "error",
                            "error": "unreadable",
                        })

        # Store permissions manifest
        zf.writestr(f"{arcprefix}/permissions.json", _dumps(permissions))
