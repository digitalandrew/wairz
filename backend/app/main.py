import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.requests import Request

from app.config import get_settings
from app.routers import analysis, comparison, component_map, documents, emulation, export_import, files, findings, firmware, fuzzing, kernels, projects, sbom, terminal
from app.utils.sandbox import PathTraversalError


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    os.makedirs(settings.storage_root, exist_ok=True)
    os.makedirs(settings.emulation_kernel_dir, exist_ok=True)
    yield


app = FastAPI(
    title="Wairz",
    description="AI-Assisted Firmware Reverse Engineering & Security Assessment",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(projects.router)
app.include_router(firmware.router)
app.include_router(files.router)
app.include_router(analysis.router)
app.include_router(component_map.router)
app.include_router(findings.router)
app.include_router(documents.router)
app.include_router(sbom.router)
app.include_router(terminal.router)
app.include_router(emulation.router)
app.include_router(fuzzing.router)
app.include_router(kernels.router)
app.include_router(comparison.router)
app.include_router(export_import.router)


@app.exception_handler(PathTraversalError)
async def path_traversal_handler(request: Request, exc: PathTraversalError):
    return JSONResponse(status_code=403, content={"detail": str(exc)})


@app.get("/health")
async def health():
    return {"status": "ok"}
