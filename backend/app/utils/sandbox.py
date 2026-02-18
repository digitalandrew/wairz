import os
from collections.abc import Iterator

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


def safe_walk(
    top: str, *, followlinks: bool = True
) -> Iterator[tuple[str, list[str], list[str]]]:
    """Like os.walk() but follows symlinks safely with cycle detection.

    Firmware filesystems frequently use symlinks for standard directories
    (e.g. /bin -> /usr/bin, /lib -> /usr/lib). Plain os.walk() skips these
    entirely because followlinks defaults to False.  This wrapper enables
    followlinks and tracks visited real-directory inodes to break cycles.
    """
    visited: set[tuple[int, int]] = set()  # (dev, inode) pairs

    for dirpath, dirs, files in os.walk(top, followlinks=followlinks):
        # Check if we've already visited this real directory (cycle detection)
        try:
            st = os.stat(dirpath)
            key = (st.st_dev, st.st_ino)
            if key in visited:
                dirs.clear()  # prune — don't recurse further
                continue
            visited.add(key)
        except OSError:
            dirs.clear()
            continue

        yield dirpath, dirs, files
