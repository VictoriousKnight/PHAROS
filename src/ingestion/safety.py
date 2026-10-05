"""
Filesystem and resource safety checks for Pharos CDR.

This module prevents unsafe paths and obviously unsuitable files from
reaching the static analysis pipeline. It does not perform malware
detection or feature extraction.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from src.config.settings import settings


@dataclass(frozen=True)
class SafetyResult:
    """Result of a safety check."""

    safe: bool
    path: str
    reason: str = ""


def _resolve(path: Path) -> Path | None:
    try:
        return path.resolve(strict=True)
    except (OSError, RuntimeError):
        return None


def check_path(path: str | Path) -> SafetyResult:
    """
    Check whether a path is suitable for static processing.

    The check prevents:
    - missing paths
    - directories
    - symbolic links
    - files larger than the configured limit
    """
    path = Path(path)

    if not path.exists():
        return SafetyResult(
            safe=False,
            path=str(path),
            reason="file not found",
        )

    if path.is_symlink():
        return SafetyResult(
            safe=False,
            path=str(path),
            reason="symbolic links are not allowed",
        )

    if not path.is_file():
        return SafetyResult(
            safe=False,
            path=str(path),
            reason="path is not a regular file",
        )

    try:
        size = path.stat().st_size
    except OSError:
        return SafetyResult(
            safe=False,
            path=str(path),
            reason="file could not be accessed",
        )

    if size > settings.max_file_size:
        return SafetyResult(
            safe=False,
            path=str(path),
            reason="file exceeds size limit",
        )

    resolved = _resolve(path)

    if resolved is None:
        return SafetyResult(
            safe=False,
            path=str(path),
            reason="file path could not be resolved",
        )

    return SafetyResult(
        safe=True,
        path=str(resolved),
    )


def is_safe(path: str | Path) -> bool:
    """Return True when a file passes the safety checks."""
    return check_path(path).safe


def ensure_safe(path: str | Path) -> Path:
    """
    Validate a path and return its resolved path.

    Raises ValueError for an unsafe file.
    """
    result = check_path(path)

    if not result.safe:
        raise ValueError(f"unsafe file: {result.reason}")

    return Path(result.path)


def check_file_descriptor_limit() -> bool:
    """
    Perform a lightweight platform check for a usable process limit.

    On Windows this is not applicable, so the check simply succeeds.
    """
    if os.name == "nt":
        return True

    try:
        import resource

        soft, _ = resource.getrlimit(resource.RLIMIT_NOFILE)
        return soft > 0
    except (ImportError, OSError, ValueError):
        return True


__all__ = [
    "SafetyResult",
    "check_path",
    "is_safe",
    "ensure_safe",
    "check_file_descriptor_limit",
]
