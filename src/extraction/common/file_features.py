"""
Lightweight generic file features for Pharos CDR.

File-type identification belongs to ingestion.file_type, while detailed
entropy analysis belongs to common.entropy.
"""

from __future__ import annotations

import hashlib
import math
import os
import re
from pathlib import Path
from typing import Any

from src.ingestion.file_type import identify_file

MAX_SAMPLE_SIZE = 64 * 1024
HASH_CHUNK_SIZE = 1024 * 1024
MAX_STRING_SAMPLE = 32 * 1024

_PRINTABLE = set(range(32, 127)) | {9, 10, 13}

CONTAINER_MARKERS = (
    b"PK\x03\x04",
    b"\x1f\x8b",
    b"BZh",
    b"\xfd7zXZ\x00",
    b"7z\xbc\xaf'\x1c",
    b"Rar!\x1a\x07",
)

URL_RE = re.compile(rb"""https?://[^\s"'<>]+""", re.IGNORECASE)


def _read_sample(path: Path, size: int = MAX_SAMPLE_SIZE) -> bytes:
    """Read a bounded sample without loading the whole file."""
    try:
        with path.open("rb") as file:
            return file.read(size)
    except OSError:
        return b""


def _sha256(path: Path) -> str:
    """Calculate the complete SHA-256 without loading the file into RAM."""
    digest = hashlib.sha256()
    try:
        with path.open("rb") as file:
            for chunk in iter(lambda: file.read(HASH_CHUNK_SIZE), b""):
                digest.update(chunk)
    except OSError:
        return ""
    return digest.hexdigest()


def _entropy(data: bytes) -> float:
    """Calculate Shannon entropy for a bounded sample."""
    if not data:
        return 0.0

    counts = [0] * 256
    for byte in data:
        counts[byte] += 1

    length = len(data)
    return -sum(
        (count / length) * math.log2(count / length)
        for count in counts
        if count
    )


def _printable_ratio(data: bytes) -> float:
    return sum(byte in _PRINTABLE for byte in data) / len(data) if data else 0.0


def _ascii_strings(data: bytes, minimum: int = 4) -> list[str]:
    """Extract a bounded set of printable ASCII strings."""
    strings = []
    current = bytearray()

    for byte in data[:MAX_STRING_SAMPLE]:
        if 32 <= byte <= 126:
            current.append(byte)
        elif len(current) >= minimum:
            strings.append(current.decode("ascii"))
            current.clear()
        else:
            current.clear()

    if len(current) >= minimum:
        strings.append(current.decode("ascii"))

    return strings


def _container_marker_count(data: bytes) -> int:
    return sum(marker in data for marker in CONTAINER_MARKERS)


def _url_count(data: bytes) -> int:
    return len(URL_RE.findall(data))


def _byte_features(data: bytes, name: str = "") -> dict[str, Any]:
    """Extract features that only require already-loaded bytes."""
    sample = data[:MAX_SAMPLE_SIZE]
    size = len(data)
    filename = Path(name).name if name else ""
    extension = Path(filename).suffix.lower() if filename else ""
    strings = _ascii_strings(sample)

    return {
        "file_size": size,
        "sample_size": len(sample),
        "sample_truncated": int(size > len(sample)),
        "filename_length": len(filename),
        "filename_stem_length": len(Path(filename).stem) if filename else 0,
        "extension_length": len(extension),
        "has_extension": int(bool(extension)),
        "filename_digit_count": sum(c.isdigit() for c in filename),
        "filename_uppercase_count": sum(c.isupper() for c in filename),
        "unique_byte_count": len(set(sample)),
        "printable_ratio": _printable_ratio(sample),
        "null_byte_count": sample.count(b"\x00"),
        "newline_count": sample.count(b"\n"),
        "carriage_return_count": sample.count(b"\r"),
        "sample_entropy": _entropy(sample),
        "ascii_string_count": len(strings),
        "ascii_string_bytes": sum(map(len, strings)),
        "url_count": _url_count(sample),
        "container_marker_count": _container_marker_count(sample),
    }


def extract_file_features(
    path: str | os.PathLike[str],
    *,
    include_hash: bool = True,
) -> dict[str, Any]:
    """
    Extract inexpensive generic features from a file.

    File-type identification and lightweight metadata are included when
    available. Reads remain bounded except for optional SHA-256 hashing.
    """
    file_path = Path(path)

    try:
        stat = file_path.stat()
    except OSError:
        return {"file_exists": 0, "file_readable": 0}

    if not file_path.is_file():
        return {"file_exists": 1, "file_readable": 0}

    sample = _read_sample(file_path)
    features = {
        "file_exists": 1,
        "file_readable": int(bool(sample) or stat.st_size == 0),
        **_byte_features(sample, file_path.name),
    }

    features["file_size"] = stat.st_size
    features["file_size_log2"] = math.log2(stat.st_size + 1)

    if include_hash:
        features["sha256"] = _sha256(file_path)

    try:
        file_type = identify_file(file_path, include_hash=False)
    except (OSError, ValueError, TypeError):
        file_type = None

    if file_type:
        features.update(
            {
                "file_type": file_type.name,
                "file_family": file_type.family,
                "file_mime": file_type.mime_type,
                "detected_extension": file_type.extension,
                "extension_mismatch": int(file_type.extension_mismatch),
                "is_document": int(file_type.is_document),
                "is_archive": int(file_type.family == "archive"),
                "is_executable": int(file_type.is_executable),
                "is_script": int(file_type.is_script),
                "is_text": int(file_type.is_text),
                "is_unknown_type": int(file_type.is_unknown),
            }
        )

    return features


def extract_from_bytes(
    data: bytes | bytearray | memoryview,
    *,
    filename: str = "",
) -> dict[str, Any]:
    """Extract generic features from already-loaded bytes."""
    data = bytes(data)
    features = _byte_features(data, filename)
    features["sha256"] = hashlib.sha256(data).hexdigest()
    return features


# Compatibility aliases for existing and specialized pipeline callers.
extract = extract_file_features
analyze = extract_file_features
extract_features = extract_file_features
analyze_features = extract_file_features
get_file_features = extract_file_features


__all__ = [
    "MAX_SAMPLE_SIZE",
    "extract_file_features",
    "extract_from_bytes",
    "extract",
    "analyze",
    "extract_features",
    "analyze_features",
    "get_file_features",
]
