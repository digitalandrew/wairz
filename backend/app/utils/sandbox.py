import os

from fastapi import HTTPException


def validate_path(extracted_root: str, requested_path: str) -> str:
    """Resolve and validate that path stays within extracted_root.

    Uses os.path.realpath() to resolve symlinks and canonicalize,
    then checks the result starts with the real root + os.sep (or is the root itself)
    to prevent path traversal and prefix collision attacks.
    """
    real_root = os.path.realpath(extracted_root)
    # Join and resolve the full path
    full_path = os.path.realpath(os.path.join(real_root, requested_path.lstrip("/")))

    # Must be the root itself or under root + separator
    if full_path != real_root and not full_path.startswith(real_root + os.sep):
        raise HTTPException(403, "Path traversal detected")

    return full_path
