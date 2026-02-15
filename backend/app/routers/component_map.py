"""REST endpoint for the firmware component dependency graph."""

import asyncio
import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.analysis_cache import AnalysisCache
from app.schemas.component_map import (
    ComponentEdgeResponse,
    ComponentGraphResponse,
    ComponentNodeResponse,
)
from app.services.component_map_service import ComponentMapService
from app.services.firmware_service import FirmwareService

router = APIRouter(
    prefix="/api/v1/projects/{project_id}/component-map",
    tags=["component-map"],
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


@router.get("", response_model=ComponentGraphResponse)
async def get_component_map(
    firmware=Depends(_resolve_firmware),
    db: AsyncSession = Depends(get_db),
):
    """Build and return the firmware component dependency graph.

    The result is cached per firmware — first call may take 10-25 seconds
    while subsequent calls return instantly.
    """
    # Check cache first
    stmt = select(AnalysisCache).where(
        AnalysisCache.firmware_id == firmware.id,
        AnalysisCache.operation == "component_map",
    )
    result = await db.execute(stmt)
    cached = result.scalar_one_or_none()

    if cached and cached.result:
        data = cached.result
        return ComponentGraphResponse(
            nodes=[ComponentNodeResponse(**n) for n in data["nodes"]],
            edges=[ComponentEdgeResponse(**e) for e in data["edges"]],
            node_count=len(data["nodes"]),
            edge_count=len(data["edges"]),
            truncated=data.get("truncated", False),
        )

    # Build graph (CPU-bound, run in thread)
    service = ComponentMapService(firmware.extracted_path)
    loop = asyncio.get_event_loop()
    try:
        graph = await loop.run_in_executor(None, service.build_graph)
    except Exception as e:
        raise HTTPException(500, f"Failed to build component map: {e}")

    # Serialize for cache and response
    nodes_data = [
        {"id": n.id, "label": n.label, "type": n.type, "path": n.path, "size": n.size, "metadata": n.metadata}
        for n in graph.nodes
    ]
    edges_data = [
        {"source": e.source, "target": e.target, "type": e.type, "details": e.details}
        for e in graph.edges
    ]

    # Store in cache
    cache_entry = AnalysisCache(
        firmware_id=firmware.id,
        operation="component_map",
        result={"nodes": nodes_data, "edges": edges_data, "truncated": graph.truncated},
    )
    db.add(cache_entry)
    await db.commit()

    return ComponentGraphResponse(
        nodes=[ComponentNodeResponse(**n) for n in nodes_data],
        edges=[ComponentEdgeResponse(**e) for e in edges_data],
        node_count=len(nodes_data),
        edge_count=len(edges_data),
        truncated=graph.truncated,
    )
