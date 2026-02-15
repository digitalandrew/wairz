from pydantic import BaseModel


class ComponentNodeResponse(BaseModel):
    id: str
    label: str
    type: str
    path: str
    size: int
    metadata: dict


class ComponentEdgeResponse(BaseModel):
    source: str
    target: str
    type: str
    details: dict


class ComponentGraphResponse(BaseModel):
    nodes: list[ComponentNodeResponse]
    edges: list[ComponentEdgeResponse]
    node_count: int
    edge_count: int
    truncated: bool
