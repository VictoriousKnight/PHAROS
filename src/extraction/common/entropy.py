"""
Lightweight entropy analysis for Pharos CDR.

Calculates Shannon entropy over a bounded sample and exposes a small set of
numeric features useful for static analysis. Detailed forensic byte
distribution analysis is intentionally excluded.
"""

from __future__ import annotations

import math
import os
from pathlib import Path
from typing import Any

MAX_READ_SIZE = 64 * 1024
DEFAULT_HIGH_ENTROPY = 7.0
DEFAULT_LOW_ENTROPY = 1.0


def _read_sample(
    path: str | os.PathLike[str],
    max_size: int,
) -> bytes:
    try:
        with Path(path).open("rb") as file:
            return file.read(max_size)
    except OSError:
        return b""


def shannon_entropy(data: bytes | bytearray | memoryview) -> float:
    """
    Calculate Shannon entropy in bits per byte.

    Returns a value from 0.0 to 8.0.
    """
    if not data:
        return 0.0

    if not isinstance(data, bytes):
        data = bytes(data)

    counts = [0] * 256

    for byte in data:
        counts[byte] += 1

    length = len(data)
    entropy = 0.0

    for count in counts:
        if count:
            probability = count / length
            entropy -= probability * math.log2(probability)

    return entropy


def byte_statistics(
    data: bytes | bytearray | memoryview,
) -> dict[str, int | float]:
    """Return compact byte-distribution statistics."""
    if not isinstance(data, bytes):
        data = bytes(data)

    if not data:
        return {
            "entropy": 0.0,
            "unique_bytes": 0,
            "zero_bytes": 0,
            "printable_ratio": 0.0,
            "high_entropy": 0,
            "low_entropy": 0,
        }

    entropy = shannon_entropy(data)

    printable = sum(byte in (9, 10, 13) or 32 <= byte <= 126 for byte in data)

    return {
        "entropy": entropy,
        "unique_bytes": len(set(data)),
        "zero_bytes": data.count(0),
        "printable_ratio": printable / len(data),
        "high_entropy": int(entropy >= DEFAULT_HIGH_ENTROPY),
        "low_entropy": int(entropy <= DEFAULT_LOW_ENTROPY),
    }


def analyze_bytes(
    data: bytes | bytearray | memoryview,
    *,
    high_threshold: float = DEFAULT_HIGH_ENTROPY,
    low_threshold: float = DEFAULT_LOW_ENTROPY,
) -> dict[str, Any]:
    """
    Analyze already-loaded bytes without reading the source again.
    """
    if not isinstance(data, bytes):
        data = bytes(data)

    if not data:
        return {
            "sample_size": 0,
            "entropy": 0.0,
            "unique_bytes": 0,
            "zero_bytes": 0,
            "printable_ratio": 0.0,
            "high_entropy": 0,
            "low_entropy": 0,
        }

    entropy = shannon_entropy(data)

    printable = sum(byte in (9, 10, 13) or 32 <= byte <= 126 for byte in data)

    return {
        "sample_size": len(data),
        "entropy": entropy,
        "unique_bytes": len(set(data)),
        "zero_bytes": data.count(0),
        "printable_ratio": printable / len(data),
        "high_entropy": int(entropy >= high_threshold),
        "low_entropy": int(entropy <= low_threshold),
    }


def analyze(
    source: str | os.PathLike[str] | bytes | bytearray | memoryview,
    *,
    max_read_size: int = MAX_READ_SIZE,
    high_threshold: float = DEFAULT_HIGH_ENTROPY,
    low_threshold: float = DEFAULT_LOW_ENTROPY,
) -> dict[str, Any]:
    """
    Analyze a file or already-loaded bytes.

    Files are read only up to ``max_read_size`` bytes.
    """
    if isinstance(source, (bytes, bytearray, memoryview)):
        data = bytes(source)
    else:
        data = _read_sample(source, max_read_size)

    return analyze_bytes(
        data,
        high_threshold=high_threshold,
        low_threshold=low_threshold,
    )


def entropy(
    source: str | os.PathLike[str] | bytes | bytearray | memoryview,
    *,
    max_read_size: int = MAX_READ_SIZE,
) -> float:
    """Return only Shannon entropy."""
    if isinstance(source, (bytes, bytearray, memoryview)):
        return shannon_entropy(source)

    return shannon_entropy(_read_sample(source, max_read_size))


def is_high_entropy(
    source: str | os.PathLike[str] | bytes | bytearray | memoryview,
    *,
    threshold: float = DEFAULT_HIGH_ENTROPY,
    max_read_size: int = MAX_READ_SIZE,
) -> bool:
    """Return whether the source has entropy above the supplied threshold."""
    return entropy(source, max_read_size=max_read_size) >= threshold


def is_low_entropy(
    source: str | os.PathLike[str] | bytes | bytearray | memoryview,
    *,
    threshold: float = DEFAULT_LOW_ENTROPY,
    max_read_size: int = MAX_READ_SIZE,
) -> bool:
    """Return whether the source has entropy below the supplied threshold."""
    return entropy(source, max_read_size=max_read_size) <= threshold


# Compatibility aliases.
calculate_entropy = entropy
extract = analyze


__all__ = [
    "MAX_READ_SIZE",
    "DEFAULT_HIGH_ENTROPY",
    "DEFAULT_LOW_ENTROPY",
    "shannon_entropy",
    "byte_statistics",
    "analyze_bytes",
    "analyze",
    "entropy",
    "calculate_entropy",
    "is_high_entropy",
    "is_low_entropy",
    "extract",
]
