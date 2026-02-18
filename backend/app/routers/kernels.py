"""Global REST endpoints for managing pre-built emulation kernels."""

import logging

from fastapi import APIRouter, File, Form, HTTPException, UploadFile
from fastapi.responses import Response

from app.schemas.kernel import KernelListResponse, KernelResponse
from app.services.kernel_service import SUPPORTED_ARCHITECTURES, KernelService

logger = logging.getLogger(__name__)

MAX_KERNEL_SIZE = 100 * 1024 * 1024  # 100 MB

router = APIRouter(
    prefix="/api/v1/kernels",
    tags=["kernels"],
)


@router.get("", response_model=KernelListResponse)
async def list_kernels(architecture: str | None = None):
    """List available kernels, optionally filtered by architecture."""
    svc = KernelService()
    kernels = svc.list_kernels(architecture=architecture)
    return KernelListResponse(
        kernels=[KernelResponse(**k) for k in kernels],
        total=len(kernels),
    )


@router.post("", response_model=KernelResponse, status_code=201)
async def upload_kernel(
    file: UploadFile = File(...),
    name: str = Form(...),
    architecture: str = Form(...),
    description: str = Form(default=""),
):
    """Upload a pre-built Linux kernel for emulation."""
    if architecture not in SUPPORTED_ARCHITECTURES:
        raise HTTPException(
            400,
            f"Unsupported architecture '{architecture}'. "
            f"Supported: {', '.join(sorted(SUPPORTED_ARCHITECTURES))}",
        )

    file_data = await file.read()
    if len(file_data) > MAX_KERNEL_SIZE:
        raise HTTPException(400, f"Kernel file exceeds {MAX_KERNEL_SIZE // (1024 * 1024)}MB limit")
    if len(file_data) == 0:
        raise HTTPException(400, "Kernel file is empty")

    svc = KernelService()
    try:
        info = await svc.upload_kernel(
            name=name,
            architecture=architecture,
            description=description,
            file_data=file_data,
        )
    except ValueError as exc:
        raise HTTPException(400, str(exc))

    return KernelResponse(**info)


@router.post("/{kernel_name}/initrd", response_model=KernelResponse)
async def upload_initrd(
    kernel_name: str,
    file: UploadFile = File(...),
):
    """Upload an initrd/initramfs to pair with an existing kernel.

    Distribution kernels (e.g. Ubuntu vmlinuz) require an initramfs to
    load storage drivers before mounting root. Upload the matching initrd
    here so system-mode emulation can pass it to QEMU via -initrd.
    """
    file_data = await file.read()
    if len(file_data) > MAX_KERNEL_SIZE:
        raise HTTPException(400, f"Initrd file exceeds {MAX_KERNEL_SIZE // (1024 * 1024)}MB limit")
    if len(file_data) == 0:
        raise HTTPException(400, "Initrd file is empty")

    svc = KernelService()
    try:
        info = await svc.upload_initrd(
            kernel_name=kernel_name,
            file_data=file_data,
        )
    except ValueError as exc:
        raise HTTPException(400, str(exc))

    return KernelResponse(**info)


@router.delete("/{kernel_name}", status_code=204)
async def delete_kernel(kernel_name: str):
    """Delete a kernel."""
    svc = KernelService()
    try:
        svc.delete_kernel(kernel_name)
    except ValueError as exc:
        raise HTTPException(404, str(exc))
    return Response(status_code=204)
