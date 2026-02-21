"""
Atomic file writing with fsync to prevent corrupt PEM files.

Pattern:
  1. Write to temporary file in the same directory
  2. Call fsync to flush to disk
  3. Rename atomically (atomic on POSIX filesystems)

This ensures that partial writes are never visible, and crash during write
leaves the old file intact.
"""
from __future__ import annotations

import os
import tempfile
from pathlib import Path


def atomic_write_text(path: Path, content: str, encoding: str = "utf-8") -> None:
    """
    Atomically write text to a file with fsync.

    Writes to a temp file in the same directory, fsyncs, then renames atomically.
    Ensures corrupt files never overwrite valid ones.
    """
    path.parent.mkdir(parents=True, exist_ok=True)

    # Create temp file in the same directory (ensures same filesystem for atomic rename)
    fd, temp_path = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=str(path.parent),
        text=False,
    )

    try:
        # Write content
        with os.fdopen(fd, "w", encoding=encoding) as f:
            f.write(content)
            f.flush()
            # Ensure all data is written to disk
            os.fsync(f.fileno())

        # Atomic rename (on POSIX, overwrites destination)
        os.replace(temp_path, path)
    except Exception:
        # Clean up temp file on error
        try:
            os.unlink(temp_path)
        except OSError:
            pass
        raise


def atomic_write_bytes(path: Path, content: bytes) -> None:
    """
    Atomically write bytes to a file with fsync.

    Writes to a temp file in the same directory, fsyncs, then renames atomically.
    Ensures corrupt files never overwrite valid ones.
    """
    path.parent.mkdir(parents=True, exist_ok=True)

    # Create temp file in the same directory (ensures same filesystem for atomic rename)
    fd, temp_path = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=str(path.parent),
    )

    try:
        # Write content
        with os.fdopen(fd, "wb") as f:
            f.write(content)
            f.flush()
            # Ensure all data is written to disk
            os.fsync(f.fileno())

        # Atomic rename (on POSIX, overwrites destination)
        os.replace(temp_path, path)
    except Exception:
        # Clean up temp file on error
        try:
            os.unlink(temp_path)
        except OSError:
            pass
        raise
