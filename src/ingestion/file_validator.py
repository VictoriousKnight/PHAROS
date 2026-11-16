"""
PHAROS Ingestion - File Validation
----------------------------------
Lightweight, defensive file pre-validation.
Checks path accessibility, size bounds, and utilizes file_type identification.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from src.config.settings import settings
from src.ingestion.file_type import identify_file

HASH_CHUNK_SIZE = 1024 * 1024


@dataclass(frozen=True)
class ValidationResult:
    """Result of basic file validation."""

    valid: bool
    path: str
    size: int = 0
    sha256: str = ""
    file_type: str = ""
    mime_type: str = ""
    error: str = ""
    warnings: tuple[str, ...] = field(default_factory=tuple)


def _compute_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(HASH_CHUNK_SIZE):
            digest.update(chunk)
    return digest.hexdigest()


def validate_file(
    path: str | Path,
    *,
    max_size: Optional[int] = None,
) -> ValidationResult:
    """
    Validate a file before static processing.
    Ensures path exists, is a standard file, is within configured size limits,
    and identifies MIME/type without executing any content.
    """
    p = Path(path)

    if not p.exists():
        return ValidationResult(valid=False, path=str(p), error="file not found")

    if not p.is_file():
        return ValidationResult(valid=False, path=str(p), error="path is not a file")

    try:
        size = p.stat().st_size
    except OSError:
        return ValidationResult(valid=False, path=str(p), error="file could not be accessed")

    limit = max_size or getattr(settings, "max_file_size", 50 * 1024 * 1024)

    if size == 0:
        return ValidationResult(valid=False, path=str(p), size=0, error="empty file")

    if size > limit:
        return ValidationResult(valid=False, path=str(p), size=size, error="file exceeds size limit")

    warnings: list[str] = []

    # Accurate file identification using ingestion.file_type
    try:
        type_res = identify_file(p, include_hash=False)
        detected_type = type_res.name
        mime_type = type_res.mime_type
        if type_res.is_unknown:
            warnings.append("unknown file type")
        if type_res.extension_mismatch:
            warnings.append("file extension mismatch")
    except Exception:
        detected_type = "unknown"
        mime_type = "application/octet-stream"
        warnings.append("file identification error")

    try:
        sha256 = _compute_sha256(p)
    except OSError:
        return ValidationResult(
            valid=False,
            path=str(p),
            size=size,
            file_type=detected_type,
            error="file could not be read",
        )

    return ValidationResult(
        valid=True,
        path=str(p),
        size=size,
        sha256=sha256,
        file_type=detected_type,
        mime_type=mime_type,
        warnings=tuple(warnings),
    )


def is_valid_file(path: str | Path, *, max_size: Optional[int] = None) -> bool:
    """Return True when the file passes basic validation."""
    return validate_file(path, max_size=max_size).valid


def get_file_hash(path: str | Path) -> str:
    """Return the SHA-256 hash of a file."""
    return _compute_sha256(Path(path))


validate = validate_file

__all__ = [
    "ValidationResult",
    "validate_file",
    "validate",
    "is_valid_file",
    "get_file_hash",
]
