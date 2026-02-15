import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import get_settings
from app.routers import analysis, chat, documents, files, findings, firmware, projects, reviews


@asynccontextmanager
async def lifespan(app: FastAPI):
    os.makedirs(get_settings().storage_root, exist_ok=True)
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
app.include_router(chat.router)
app.include_router(analysis.router)
app.include_router(findings.router)
app.include_router(documents.router)
app.include_router(reviews.router)


@app.get("/health")
async def health():
    return {"status": "ok"}
