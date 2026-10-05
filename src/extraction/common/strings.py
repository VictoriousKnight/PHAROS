"""
Lightweight string extraction for Pharos CDR.

Extracts bounded ASCII and UTF-16LE strings from files or already-loaded
bytes. This module does not perform URL analysis, malware scoring, or
behavior detection.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Iterable

MAX_READ_SIZE = 64 * 1024
MAX_STRING_LENGTH = 4096
DEFAULT_MIN_LENGTH = 4

# Avoid returning enormous string collections.
MAX_ASCII_STRINGS = 4096
MAX_UTF16_STRINGS = 2048


def _read_sample(
    path: str | os.PathLike[str],
    max_size: int,
) -> bytes:
    try:
        with Path(path).open("rb") as file:
            return file.read(max_size)
    except OSError:
        return b""


def _extract_ascii(
    data: bytes,
    minimum_length: int,
    maximum_length: int,
    limit: int,
) -> list[str]:
    strings: list[str] = []
    current = bytearray()

    for byte in data:
        if 32 <= byte <= 126:
            if len(current) < maximum_length:
                current.append(byte)
            continue

        if len(current) >= minimum_length:
            strings.append(current.decode("ascii"))
            if len(strings) >= limit:
                return strings

        current.clear()

    if len(current) >= minimum_length and len(strings) < limit:
        strings.append(current.decode("ascii"))

    return strings


def _extract_utf16le(
    data: bytes,
    minimum_length: int,
    maximum_length: int,
    limit: int,
) -> list[str]:
    strings: list[str] = []
    current: list[int] = []

    index = 0
    length = len(data)

    while index + 1 < length:
        codepoint = data[index] | (data[index + 1] << 8)

        if 32 <= codepoint <= 126:
            if len(current) < maximum_length:
                current.append(codepoint)
        else:
            if len(current) >= minimum_length:
                strings.append("".join(map(chr, current)))
                if len(strings) >= limit:
                    return strings

            current.clear()

        index += 2

    if len(current) >= minimum_length and len(strings) < limit:
        strings.append("".join(map(chr, current)))

    return strings


def extract_strings_from_bytes(
    data: bytes | bytearray | memoryview,
    *,
    min_length: int = DEFAULT_MIN_LENGTH,
    max_length: int = MAX_STRING_LENGTH,
    max_ascii: int = MAX_ASCII_STRINGS,
    max_utf16: int = MAX_UTF16_STRINGS,
) -> dict[str, list[str]]:
    """
    Extract bounded ASCII and UTF-16LE strings from bytes.

    Only printable strings are returned. The input is expected to already be
    bounded by the caller when working with large files.
    """
    if not isinstance(data, bytes):
        data = bytes(data)

    if not data:
        return {
            "ascii": [],
            "utf16": [],
        }

    min_length = max(1, min_length)
    max_length = max(min_length, max_length)

    return {
        "ascii": _extract_ascii(
            data,
            min_length,
            max_length,
            max(0, max_ascii),
        ),
        "utf16": _extract_utf16le(
            data,
            min_length,
            max_length,
            max(0, max_utf16),
        ),
    }


def extract_strings(
    source: str | os.PathLike[str] | bytes | bytearray | memoryview,
    *,
    min_length: int = DEFAULT_MIN_LENGTH,
    max_length: int = MAX_STRING_LENGTH,
    max_ascii: int = MAX_ASCII_STRINGS,
    max_utf16: int = MAX_UTF16_STRINGS,
    max_read_size: int = MAX_READ_SIZE,
) -> dict[str, list[str]]:
    """
    Extract strings from a file or already-loaded bytes.

    File input is bounded to ``max_read_size`` bytes. Bytes input is not
    copied or truncated beyond the conversion required for mutable buffers.
    """
    if isinstance(source, (bytes, bytearray, memoryview)):
        data = bytes(source)
    else:
        data = _read_sample(source, max_read_size)

    return extract_strings_from_bytes(
        data,
        min_length=min_length,
        max_length=max_length,
        max_ascii=max_ascii,
        max_utf16=max_utf16,
    )


def ascii_strings(
    source: str | os.PathLike[str] | bytes | bytearray | memoryview,
    *,
    min_length: int = DEFAULT_MIN_LENGTH,
    max_length: int = MAX_STRING_LENGTH,
    limit: int = MAX_ASCII_STRINGS,
    max_read_size: int = MAX_READ_SIZE,
) -> list[str]:
    """Return only ASCII strings."""
    if isinstance(source, (bytes, bytearray, memoryview)):
        data = bytes(source)
    else:
        data = _read_sample(source, max_read_size)

    return _extract_ascii(
        data,
        max(1, min_length),
        max(max(1, min_length), max_length),
        max(0, limit),
    )


def utf16_strings(
    source: str | os.PathLike[str] | bytes | bytearray | memoryview,
    *,
    min_length: int = DEFAULT_MIN_LENGTH,
    max_length: int = MAX_STRING_LENGTH,
    limit: int = MAX_UTF16_STRINGS,
    max_read_size: int = MAX_READ_SIZE,
) -> list[str]:
    """Return only UTF-16LE strings."""
    if isinstance(source, (bytes, bytearray, memoryview)):
        data = bytes(source)
    else:
        data = _read_sample(source, max_read_size)

    return _extract_utf16le(
        data,
        max(1, min_length),
        max(max(1, min_length), max_length),
        max(0, limit),
    )


def string_count(
    source: str | os.PathLike[str] | bytes | bytearray | memoryview,
    *,
    min_length: int = DEFAULT_MIN_LENGTH,
    max_read_size: int = MAX_READ_SIZE,
) -> dict[str, int]:
    """Return string counts without exposing the extracted strings."""
    strings = extract_strings(
        source,
        min_length=min_length,
        max_read_size=max_read_size,
    )

    return {
        "ascii_count": len(strings["ascii"]),
        "utf16_count": len(strings["utf16"]),
        "total_count": len(strings["ascii"]) + len(strings["utf16"]),
    }


def string_features(
    source: str | os.PathLike[str] | bytes | bytearray | memoryview,
    *,
    min_length: int = DEFAULT_MIN_LENGTH,
    max_read_size: int = MAX_READ_SIZE,
) -> dict[str, int | float]:
    """
    Return compact numeric string features.

    This is useful directly from FeaturePipeline when the actual strings
    are not needed.
    """
    strings = extract_strings(
        source,
        min_length=min_length,
        max_read_size=max_read_size,
    )

    ascii_values = strings["ascii"]
    utf16_values = strings["utf16"]

    ascii_bytes = sum(len(value) for value in ascii_values)
    utf16_bytes = sum(len(value) * 2 for value in utf16_values)

    return {
        "ascii_string_count": len(ascii_values),
        "utf16_string_count": len(utf16_values),
        "string_count": len(ascii_values) + len(utf16_values),
        "ascii_string_bytes": ascii_bytes,
        "utf16_string_bytes": utf16_bytes,
        "string_bytes": ascii_bytes + utf16_bytes,
        "long_ascii_string_count": sum(len(value) >= 32 for value in ascii_values),
        "long_utf16_string_count": sum(len(value) >= 32 for value in utf16_values),
    }


# Compatibility aliases.
extract = extract_strings
analyze = extract_strings


__all__ = [
    "MAX_READ_SIZE",
    "MAX_STRING_LENGTH",
    "DEFAULT_MIN_LENGTH",
    "MAX_ASCII_STRINGS",
    "MAX_UTF16_STRINGS",
    "extract_strings",
    "extract_strings_from_bytes",
    "ascii_strings",
    "utf16_strings",
    "string_count",
    "string_features",
    "extract",
    "analyze",
]
