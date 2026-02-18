"""Pydantic schemas for kernel management."""

from pydantic import BaseModel


class KernelResponse(BaseModel):
    name: str
    architecture: str
    description: str
    file_size: int
    uploaded_at: str
    has_initrd: bool = False


class KernelListResponse(BaseModel):
    kernels: list[KernelResponse]
    total: int
