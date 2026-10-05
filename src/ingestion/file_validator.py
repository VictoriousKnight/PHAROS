"""
Basic file validation for Pharos CDR.

This module performs lightweight validation only. Feature extraction,
malware analysis, and detailed behavioral inspection belong elsewhere.
"""

from __future__ import annotations

import hashlib
import mimetypes
from dataclasses import dataclass, field
from pathlib import Path

from src.config.settings import settings

SUPPORTED_EXTENSIONS = {
    ".doc",
    ".docm",
    ".docx",
    ".dot",
    ".dotm",
    ".dotx",
    ".xls",
    ".xlsm",
    ".xlsx",
    ".xlt",
    ".xltm",
    ".xltx",
    ".ppt",
    ".pptm",
    ".pptx",
    ".pot",
    ".potm",
    ".potx",
    ".pps",
    ".ppsm",
    ".ppsx",
    ".pdf",
    ".txt",
    ".csv",
    ".rtf",
    ".js",
    ".jsx",
    ".vbs",
    ".vbe",
    ".ps1",
    ".bat",
    ".cmd",
    ".sh",
}

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


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()

    with path.open("rb") as file:
        for chunk in iter(
            lambda: file.read(HASH_CHUNK_SIZE),
            b"",
        ):
            digest.update(chunk)

    return digest.hexdigest()


def _detect_type(path: Path) -> str:
    extension = path.suffix.lower()

    if extension in SUPPORTED_EXTENSIONS:
        return extension[1:]

    mime_type = mimetypes.guess_type(path.name)[0]

    if mime_type:
        return mime_type

    return "unknown"


def _is_empty(path: Path) -> bool:
    return path.stat().st_size == 0


def validate_file(
    path: str | Path,
    *,
    max_size: int | None = None,
) -> ValidationResult:
    """
    Validate a file before processing.

    Validation is intentionally lightweight. A file being valid here does
    not mean it is safe or benign. It only means it is suitable for the
    static analysis pipeline.
    """
    path = Path(path)

    if not path.exists():
        return ValidationResult(
            valid=False,
            path=str(path),
            error="file not found",
        )

    if not path.is_file():
        return ValidationResult(
            valid=False,
            path=str(path),
            error="path is not a file",
        )

    try:
        stat = path.stat()
    except OSError:
        return ValidationResult(
            valid=False,
            path=str(path),
            error="file could not be accessed",
        )

    size = stat.st_size
    limit = max_size or settings.max_file_size

    if size == 0:
        return ValidationResult(
            valid=False,
            path=str(path),
            size=0,
            error="empty file",
        )

    if size > limit:
        return ValidationResult(
            valid=False,
            path=str(path),
            size=size,
            error="file exceeds size limit",
        )

    file_type = _detect_type(path)

    warnings: list[str] = []

    if file_type == "unknown":
        warnings.append("unknown file type")

    try:
        sha256 = _sha256(path)
    except OSError:
        return ValidationResult(
            valid=False,
            path=str(path),
            size=size,
            file_type=file_type,
            error="file could not be read",
        )

    return ValidationResult(
        valid=True,
        path=str(path),
        size=size,
        sha256=sha256,
        file_type=file_type,
        mime_type=mimetypes.guess_type(path.name)[0] or "",
        warnings=tuple(warnings),
    )


def is_valid_file(
    path: str | Path,
    *,
    max_size: int | None = None,
) -> bool:
    """Return True when the file passes basic validation."""
    return validate_file(
        path,
        max_size=max_size,
    ).valid


def get_file_hash(path: str | Path) -> str:
    """Return the SHA-256 hash of a file."""
    return _sha256(Path(path))


def validate(
    path: str | Path,
    *,
    max_size: int | None = None,
) -> ValidationResult:
    """Backward-compatible short name for validate_file()."""
    return validate_file(
        path,
        max_size=max_size,
    )


__all__ = [
    "ValidationResult",
    "validate_file",
    "validate",
    "is_valid_file",
    "get_file_hash",
]
