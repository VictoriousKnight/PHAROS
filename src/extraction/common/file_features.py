"""
Generic file-level feature extraction.

This module extracts features that can be computed from a file without
understanding its application-specific format.

Responsibilities
----------------
- File size and basic filesystem metadata
- File extension / filename characteristics
- Header / magic-byte information
- Byte-level statistical characteristics
- Structural characteristics of the raw file
- Basic archive/container indicators
- Feature extraction in a deterministic, JSON-serializable format

Non-responsibilities
-------------------
- Office parsing
- VBA analysis
- Script analysis
- URL extraction
- Behavioral analysis
- Malware classification

The output of this module is intended to become part of the feature vector
consumed by src/extraction/feature_pipeline.py.
"""

from __future__ import annotations

import hashlib
import math
import mimetypes
import os
import re
import stat
import struct
import zipfile
from collections import Counter
from pathlib import Path
from typing import Any, BinaryIO

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_SAMPLE_SIZE = 1024 * 1024  # 1 MiB
DEFAULT_CHUNK_SIZE = 64 * 1024  # 64 KiB

# Common executable / script / document extensions.
# These are intentionally represented as sets so membership tests are O(1).
EXECUTABLE_EXTENSIONS = {
    ".exe",
    ".dll",
    ".sys",
    ".scr",
    ".com",
    ".cpl",
    ".ocx",
    ".drv",
    ".efi",
    ".msi",
    ".msp",
    ".appx",
    ".msix",
    ".jar",
    ".class",
}

SCRIPT_EXTENSIONS = {
    ".js",
    ".jse",
    ".vbs",
    ".vbe",
    ".wsf",
    ".wsh",
    ".ps1",
    ".psm1",
    ".psd1",
    ".bat",
    ".cmd",
    ".hta",
    ".py",
    ".pl",
    ".rb",
    ".sh",
}

OFFICE_EXTENSIONS = {
    ".doc",
    ".dot",
    ".docm",
    ".docx",
    ".dotm",
    ".xls",
    ".xlt",
    ".xlsm",
    ".xlsx",
    ".xltm",
    ".ppt",
    ".pot",
    ".pps",
    ".pptm",
    ".pptx",
    ".potm",
    ".ppsm",
    ".rtf",
}

ARCHIVE_EXTENSIONS = {
    ".zip",
    ".7z",
    ".rar",
    ".tar",
    ".gz",
    ".bz2",
    ".xz",
    ".cab",
    ".iso",
}

DOUBLE_EXTENSION_RE = re.compile(
    r"\.[a-z0-9]{1,10}\.[a-z0-9]{1,10}$",
    re.IGNORECASE,
)

SUSPICIOUS_FILENAME_RE = re.compile(
    r"(?:^|[\s._-])"
    r"(invoice|payment|document|scan|receipt|report|"
    r"update|install|setup|urgent|confidential|password|"
    r"resume|cv|statement|order|purchase)"
    r"(?:[\s._-]|$)",
    re.IGNORECASE,
)

UNICODE_CONTROL_RE = re.compile(r"[\u0000-\u001f\u007f-\u009f]")

# Selected magic signatures. Values are (human-readable type, category).
MAGIC_SIGNATURES: tuple[tuple[bytes, str, str], ...] = (
    (b"MZ", "pe", "windows_executable"),
    (b"\x7fELF", "elf", "unix_executable"),
    (b"%PDF-", "pdf", "pdf"),
    (b"PK\x03\x04", "zip", "zip_container"),
    (b"PK\x05\x06", "zip", "zip_container_empty"),
    (b"PK\x07\x08", "zip", "zip_container_spanned"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "ole", "ole_compound_file"),
    (b"Rar!\x1a\x07\x00", "rar", "rar_archive"),
    (b"7z\xbc\xaf\x27\x1c", "7z", "7z_archive"),
    (b"\x1f\x8b", "gzip", "gzip_archive"),
    (b"BZh", "bzip2", "bzip2_archive"),
    (b"\xfd7zXZ\x00", "xz", "xz_archive"),
    (b"ustar", "tar", "tar_archive"),
    (b"\x00asm", "wasm", "webassembly"),
)

# Useful byte sequences for identifying potentially executable content.
# These are indicators only; they are NOT verdicts.
SUSPICIOUS_BYTE_PATTERNS: tuple[tuple[str, bytes], ...] = (
    ("powershell_marker", b"powershell"),
    ("cmd_marker", b"cmd.exe"),
    ("wscript_marker", b"wscript"),
    ("cscript_marker", b"cscript"),
    ("rundll32_marker", b"rundll32"),
    ("regsvr32_marker", b"regsvr32"),
    ("mshta_marker", b"mshta"),
    ("certutil_marker", b"certutil"),
    ("bitsadmin_marker", b"bitsadmin"),
)

# Byte Order Marks.
BOMS = {
    b"\xef\xbb\xbf": "utf8",
    b"\xff\xfe": "utf16le",
    b"\xfe\xff": "utf16be",
    b"\xff\xfe\x00\x00": "utf32le",
    b"\x00\x00\xfe\xff": "utf32be",
}


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _safe_stat(path: Path) -> os.stat_result | None:
    """Return stat information without allowing filesystem errors to escape."""
    try:
        return path.stat()
    except (OSError, ValueError):
        return None


def _read_prefix(path: Path, size: int = 4096) -> bytes:
    """Read at most `size` bytes from the beginning of a file."""
    try:
        with path.open("rb") as handle:
            return handle.read(size)
    except (OSError, ValueError):
        return b""


def _normalize_extension(path: Path) -> str:
    """Return a lowercase extension including the leading dot."""
    return path.suffix.lower()


def _filename_without_extension(path: Path) -> str:
    """Return the filename without its final extension."""
    return path.stem


def _count_extensions(path: Path) -> int:
    """
    Count suffixes in a filename.

    Example:
        invoice.pdf.exe -> 2
        report.docx      -> 1
        README           -> 0
    """
    return max(0, len(path.name.split(".")) - 1)


def _has_double_extension(path: Path) -> bool:
    """Detect filenames containing two conventional extensions."""
    return bool(DOUBLE_EXTENSION_RE.search(path.name))


def _extension_chain(path: Path) -> list[str]:
    """Return all apparent filename extensions from left to right."""
    parts = path.name.split(".")
    if len(parts) <= 1:
        return []

    return [f".{part.lower()}" for part in parts[1:] if part]


def _detect_magic(prefix: bytes) -> tuple[str, str]:
    """Identify a file using its leading bytes."""
    for signature, file_type, category in MAGIC_SIGNATURES:
        if prefix.startswith(signature):
            return file_type, category

    # TAR commonly stores "ustar" at offset 257 rather than byte zero.
    if len(prefix) >= 262 and prefix[257:262] == b"ustar":
        return "tar", "tar_archive"

    return "unknown", "unknown"


def _entropy(data: bytes) -> float:
    """
    Calculate Shannon entropy in bits per byte.

    Range:
        0.0 -> all bytes identical
        8.0 -> maximally uniform byte distribution

    Empty data has entropy 0.0.
    """
    if not data:
        return 0.0

    counts = Counter(data)
    length = len(data)

    entropy = 0.0
    for count in counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return entropy


def _byte_diversity(data: bytes) -> float:
    """
    Ratio of unique byte values to all possible byte values.

    Range:
        0.0 -> no bytes
        1.0 -> all 256 byte values observed
    """
    if not data:
        return 0.0

    return len(set(data)) / 256.0


def _printable_ratio(data: bytes) -> float:
    """Return the proportion of bytes that are ASCII-printable or whitespace."""
    if not data:
        return 0.0

    printable = sum(1 for byte in data if byte in (9, 10, 13) or 32 <= byte <= 126)

    return printable / len(data)


def _null_byte_ratio(data: bytes) -> float:
    """Return the proportion of zero bytes."""
    if not data:
        return 0.0

    return data.count(b"\x00") / len(data)


def _high_byte_ratio(data: bytes) -> float:
    """Return the proportion of bytes >= 0x80."""
    if not data:
        return 0.0

    return sum(byte >= 0x80 for byte in data) / len(data)


def _ascii_string_lengths(data: bytes) -> list[int]:
    """
    Extract lengths of runs of printable ASCII characters.

    This is intentionally lightweight. Detailed string extraction belongs
    in common/strings.py.
    """
    lengths: list[int] = []
    current = 0

    for byte in data:
        if 32 <= byte <= 126:
            current += 1
        else:
            if current >= 4:
                lengths.append(current)
            current = 0

    if current >= 4:
        lengths.append(current)

    return lengths


def _count_ascii_strings(data: bytes, minimum_length: int = 4) -> int:
    """Count printable ASCII strings of at least `minimum_length` bytes."""
    count = 0
    current = 0

    for byte in data:
        if 32 <= byte <= 126:
            current += 1
        else:
            if current >= minimum_length:
                count += 1
            current = 0

    if current >= minimum_length:
        count += 1

    return count


def _contains_case_insensitive(data: bytes, needle: bytes) -> bool:
    """Case-insensitive byte substring search."""
    return needle.lower() in data.lower()


def _count_case_insensitive(data: bytes, needle: bytes) -> int:
    """Count non-overlapping case-insensitive byte occurrences."""
    if not data or not needle:
        return 0

    return data.lower().count(needle.lower())


def _sha256(path: Path, chunk_size: int = DEFAULT_CHUNK_SIZE) -> str:
    """Calculate SHA-256 without loading the whole file into memory."""
    digest = hashlib.sha256()

    try:
        with path.open("rb") as handle:
            while True:
                chunk = handle.read(chunk_size)
                if not chunk:
                    break
                digest.update(chunk)
    except (OSError, ValueError):
        return ""

    return digest.hexdigest()


def _md5(path: Path, chunk_size: int = DEFAULT_CHUNK_SIZE) -> str:
    """
    Calculate MD5 for file identity.

    MD5 is NOT used as a security/integrity primitive here. It can still be
    useful for compatibility with malware-analysis datasets and sample IDs.
    """
    digest = hashlib.md5(usedforsecurity=False)

    try:
        with path.open("rb") as handle:
            while True:
                chunk = handle.read(chunk_size)
                if not chunk:
                    break
                digest.update(chunk)
    except (OSError, ValueError):
        return ""

    return digest.hexdigest()


def _detect_bom(prefix: bytes) -> str:
    """Identify a Unicode BOM, if present."""
    # Check longest BOMs first.
    for bom, encoding in sorted(BOMS.items(), key=lambda item: -len(item[0])):
        if prefix.startswith(bom):
            return encoding

    return "none"


def _detect_mime_type(path: Path) -> str:
    """Best-effort MIME type based on filename."""
    mime_type, _ = mimetypes.guess_type(path.name)
    return mime_type or "application/octet-stream"


def _is_zip_container(path: Path, prefix: bytes) -> bool:
    """Determine whether a file is a valid ZIP container."""
    if not prefix.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")):
        return False

    try:
        return zipfile.is_zipfile(path)
    except (OSError, ValueError, zipfile.BadZipFile):
        return False


def _zip_features(path: Path) -> dict[str, Any]:
    """
    Extract conservative ZIP/container statistics.

    This is useful for OOXML files because DOCX/XLSX/PPTX are ZIP containers.
    Detailed OOXML analysis belongs in extraction/office/.
    """
    result: dict[str, Any] = {
        "is_valid_zip": False,
        "zip_entry_count": 0,
        "zip_compressed_bytes": 0,
        "zip_uncompressed_bytes": 0,
        "zip_compression_ratio": 0.0,
        "zip_max_entry_uncompressed_bytes": 0,
        "zip_directory_depth_max": 0,
        "zip_has_encrypted_entries": False,
    }

    try:
        with zipfile.ZipFile(path, "r") as archive:
            infos = archive.infolist()

            result["is_valid_zip"] = True
            result["zip_entry_count"] = len(infos)

            compressed_total = 0
            uncompressed_total = 0
            max_entry = 0
            max_depth = 0
            encrypted = False

            for info in infos:
                compressed_total += max(0, info.compress_size)
                uncompressed_total += max(0, info.file_size)
                max_entry = max(max_entry, max(0, info.file_size))

                # ZIP encryption flag is bit 0 of the general-purpose flag.
                if info.flag_bits & 0x0001:
                    encrypted = True

                name = info.filename.replace("\\", "/")
                depth = len([part for part in name.split("/") if part])
                max_depth = max(max_depth, depth)

            result["zip_compressed_bytes"] = compressed_total
            result["zip_uncompressed_bytes"] = uncompressed_total
            result["zip_max_entry_uncompressed_bytes"] = max_entry
            result["zip_directory_depth_max"] = max_depth
            result["zip_has_encrypted_entries"] = encrypted

            if compressed_total > 0:
                result["zip_compression_ratio"] = uncompressed_total / compressed_total

    except (OSError, ValueError, zipfile.BadZipFile):
        pass

    return result


def _read_sample(
    path: Path,
    sample_size: int = DEFAULT_SAMPLE_SIZE,
) -> bytes:
    """
    Read a bounded sample for statistical analysis.

    For small files the entire file is read.

    For larger files, this reads:
        - beginning
        - middle
        - end

    This gives more representative statistics than analyzing only the header
    while keeping memory usage bounded.
    """
    if sample_size <= 0:
        return b""

    try:
        file_size = path.stat().st_size
    except (OSError, ValueError):
        return b""

    if file_size <= sample_size:
        try:
            return path.read_bytes()
        except (OSError, ValueError):
            return b""

    # Divide the sample into three regions.
    first_size = sample_size // 2
    remaining = sample_size - first_size
    middle_size = remaining // 2
    last_size = remaining - middle_size

    try:
        with path.open("rb") as handle:
            first = handle.read(first_size)

            middle_offset = max(0, (file_size // 2) - (middle_size // 2))
            handle.seek(middle_offset)
            middle = handle.read(middle_size)

            end_offset = max(0, file_size - last_size)
            handle.seek(end_offset)
            last = handle.read(last_size)

        return first + middle + last

    except (OSError, ValueError):
        return b""


# ---------------------------------------------------------------------------
# Public feature extractor
# ---------------------------------------------------------------------------


class FileFeatureExtractor:
    """
    Extract generic features from a file.

    Parameters
    ----------
    sample_size:
        Maximum amount of data used for statistical byte-level features.

    calculate_hashes:
        Whether SHA-256 and MD5 should be calculated.

    include_filename_features:
        Whether filename-derived features should be included.

    include_content_indicators:
        Whether lightweight content indicators should be included.

    Notes
    -----
    The class deliberately does not raise an exception for a malformed or
    unreadable file during ordinary extraction. Instead, it records extraction
    status in the returned dictionary.

    This is important in batch dataset processing where one corrupt sample
    should not terminate extraction for thousands of files.
    """

    def __init__(
        self,
        *,
        sample_size: int = DEFAULT_SAMPLE_SIZE,
        calculate_hashes: bool = True,
        include_filename_features: bool = True,
        include_content_indicators: bool = True,
    ) -> None:
        if sample_size < 0:
            raise ValueError("sample_size must be >= 0")

        self.sample_size = sample_size
        self.calculate_hashes = calculate_hashes
        self.include_filename_features = include_filename_features
        self.include_content_indicators = include_content_indicators

    def extract(self, file_path: str | os.PathLike[str]) -> dict[str, Any]:
        """
        Extract generic features from `file_path`.

        Returns
        -------
        dict
            Flat JSON-serializable feature dictionary.

        Raises
        ------
        TypeError
            If `file_path` is not path-like.
        """
        path = Path(file_path)

        features: dict[str, Any] = {
            "file_extraction_version": 1,
            "file_path": str(path),
            "file_exists": False,
            "file_readable": False,
            "file_is_regular": False,
            "file_size_bytes": 0,
        }

        try:
            exists = path.exists()
        except (OSError, ValueError):
            exists = False

        features["file_exists"] = exists

        if not exists:
            features["extraction_error"] = "file_not_found"
            return features

        try:
            is_file = path.is_file()
        except (OSError, ValueError):
            is_file = False

        if not is_file:
            features["extraction_error"] = "not_a_regular_file"
            return features

        features["file_is_regular"] = True

        stat_result = _safe_stat(path)

        if stat_result is not None:
            features.update(
                {
                    "file_size_bytes": int(stat_result.st_size),
                    "file_mode": int(stat_result.st_mode),
                    "file_owner_readable": bool(stat_result.st_mode & stat.S_IRUSR),
                    "file_owner_writable": bool(stat_result.st_mode & stat.S_IWUSR),
                    "file_executable_bit": bool(
                        stat_result.st_mode
                        & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
                    ),
                }
            )

        prefix = _read_prefix(path)

        try:
            with path.open("rb"):
                features["file_readable"] = True
        except (OSError, ValueError):
            features["extraction_error"] = "file_not_readable"
            return features

        # ---------------------------------------------------------------
        # Filename and path-independent file identity
        # ---------------------------------------------------------------

        extension = _normalize_extension(path)
        magic_type, magic_category = _detect_magic(prefix)

        features.update(
            {
                "file_extension": extension,
                "file_extension_normalized": extension.lstrip("."),
                "file_mime_type": _detect_mime_type(path),
                "file_magic_type": magic_type,
                "file_magic_category": magic_category,
                "file_has_known_magic": magic_type != "unknown",
            }
        )

        if self.include_filename_features:
            filename = path.name
            filename_lower = filename.lower()

            extension_chain = _extension_chain(path)

            features.update(
                {
                    "filename_length": len(filename),
                    "filename_stem_length": len(_filename_without_extension(path)),
                    "filename_extension_count": _count_extensions(path),
                    "filename_has_double_extension": _has_double_extension(path),
                    "filename_extension_chain": extension_chain,
                    "filename_has_spaces": " " in filename,
                    "filename_has_unicode": any(ord(c) > 127 for c in filename),
                    "filename_has_control_chars": bool(
                        UNICODE_CONTROL_RE.search(filename)
                    ),
                    "filename_has_hidden_prefix": filename.startswith("."),
                    "filename_has_suspicious_keyword": bool(
                        SUSPICIOUS_FILENAME_RE.search(filename)
                    ),
                    "filename_lowercase_length": len(filename_lower),
                    "filename_is_executable_extension": (
                        extension in EXECUTABLE_EXTENSIONS
                    ),
                    "filename_is_script_extension": (extension in SCRIPT_EXTENSIONS),
                    "filename_is_office_extension": (extension in OFFICE_EXTENSIONS),
                    "filename_is_archive_extension": (extension in ARCHIVE_EXTENSIONS),
                }
            )

        # ---------------------------------------------------------------
        # Content sample statistics
        # ---------------------------------------------------------------

        sample = _read_sample(path, self.sample_size)

        features.update(
            {
                "content_sample_bytes": len(sample),
                "content_sample_entropy": round(_entropy(sample), 6),
                "content_sample_byte_diversity": round(_byte_diversity(sample), 6),
                "content_sample_printable_ratio": round(_printable_ratio(sample), 6),
                "content_sample_null_ratio": round(_null_byte_ratio(sample), 6),
                "content_sample_high_byte_ratio": round(_high_byte_ratio(sample), 6),
                "content_sample_unique_bytes": len(set(sample)),
                "content_sample_ascii_string_count": _count_ascii_strings(sample),
            }
        )

        ascii_lengths = _ascii_string_lengths(sample)

        features.update(
            {
                "content_sample_max_ascii_string_length": (
                    max(ascii_lengths) if ascii_lengths else 0
                ),
                "content_sample_avg_ascii_string_length": (
                    round(sum(ascii_lengths) / len(ascii_lengths), 6)
                    if ascii_lengths
                    else 0.0
                ),
            }
        )

        # ---------------------------------------------------------------
        # Header / encoding information
        # ---------------------------------------------------------------

        features.update(
            {
                "header_length": len(prefix),
                "header_entropy": round(_entropy(prefix), 6),
                "header_bom": _detect_bom(prefix),
                "header_starts_with_mz": prefix.startswith(b"MZ"),
                "header_starts_with_pk": prefix.startswith(b"PK"),
                "header_starts_with_ole": prefix.startswith(
                    b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
                ),
                "header_starts_with_pdf": prefix.startswith(b"%PDF-"),
                "header_starts_with_elf": prefix.startswith(b"\x7fELF"),
            }
        )

        # ---------------------------------------------------------------
        # Content indicators
        # ---------------------------------------------------------------

        if self.include_content_indicators:
            for name, marker in SUSPICIOUS_BYTE_PATTERNS:
                features[f"content_indicator_{name}"] = _contains_case_insensitive(
                    sample, marker
                )
                features[f"content_indicator_{name}_count"] = _count_case_insensitive(
                    sample, marker
                )

            features["content_indicator_suspicious_marker_count"] = sum(
                1
                for _, marker in SUSPICIOUS_BYTE_PATTERNS
                if _contains_case_insensitive(sample, marker)
            )

        # ---------------------------------------------------------------
        # Container information
        # ---------------------------------------------------------------

        is_zip = _is_zip_container(path, prefix)
        features["is_zip_container"] = is_zip

        if is_zip:
            features.update(_zip_features(path))
        else:
            features.update(
                {
                    "is_valid_zip": False,
                    "zip_entry_count": 0,
                    "zip_compressed_bytes": 0,
                    "zip_uncompressed_bytes": 0,
                    "zip_compression_ratio": 0.0,
                    "zip_max_entry_uncompressed_bytes": 0,
                    "zip_directory_depth_max": 0,
                    "zip_has_encrypted_entries": False,
                }
            )

        # ---------------------------------------------------------------
        # Size-derived features
        # ---------------------------------------------------------------

        size = int(features["file_size_bytes"])

        features.update(
            {
                "file_is_empty": size == 0,
                "file_size_log2": (round(math.log2(size), 6) if size > 0 else 0.0),
                "file_size_kb": round(size / 1024.0, 6),
                "file_size_mb": round(size / (1024.0 * 1024.0), 6),
            }
        )

        # ---------------------------------------------------------------
        # Hashes
        # ---------------------------------------------------------------

        if self.calculate_hashes:
            features["file_sha256"] = _sha256(path)
            features["file_md5"] = _md5(path)
        else:
            features["file_sha256"] = ""
            features["file_md5"] = ""

        # ---------------------------------------------------------------
        # Cross-feature indicators
        # ---------------------------------------------------------------

        features.update(
            {
                "extension_magic_mismatch": self._extension_magic_mismatch(
                    extension=extension,
                    magic_type=magic_type,
                ),
                "looks_like_office_container": self._looks_like_office_container(
                    extension=extension,
                    magic_type=magic_type,
                    is_zip=is_zip,
                ),
                "looks_like_executable": self._looks_like_executable(
                    extension=extension,
                    magic_type=magic_type,
                ),
                "looks_like_script": extension in SCRIPT_EXTENSIONS,
                "possible_extension_spoofing": self._possible_extension_spoofing(
                    extension=extension,
                    magic_type=magic_type,
                ),
            }
        )

        features["extraction_error"] = ""

        return features

    # -------------------------------------------------------------------
    # Cross-feature logic
    # -------------------------------------------------------------------

    @staticmethod
    def _extension_magic_mismatch(
        *,
        extension: str,
        magic_type: str,
    ) -> bool:
        """
        Detect obvious mismatches between extension and detected container.

        This is an indicator only. Many legitimate files have generic or
        misleading extensions, and some formats intentionally use containers.
        """
        if magic_type == "unknown" or not extension:
            return False

        if magic_type == "pe":
            return extension not in EXECUTABLE_EXTENSIONS

        if magic_type == "ole":
            # OLE is used by legacy Office formats and several other formats.
            return extension not in {
                ".doc",
                ".dot",
                ".xls",
                ".xlt",
                ".ppt",
                ".pot",
                ".pps",
                ".msg",
                ".vsd",
            }

        if magic_type == "pdf":
            return extension != ".pdf"

        if magic_type == "zip":
            return extension not in ARCHIVE_EXTENSIONS | OFFICE_EXTENSIONS

        if magic_type in {"rar", "7z", "gzip", "bzip2", "xz", "tar"}:
            return extension not in ARCHIVE_EXTENSIONS

        if magic_type == "elf":
            return extension not in EXECUTABLE_EXTENSIONS

        return False

    @staticmethod
    def _looks_like_office_container(
        *,
        extension: str,
        magic_type: str,
        is_zip: bool,
    ) -> bool:
        """
        Identify likely Office documents without deeply parsing them.

        OOXML formats are ZIP containers, while older Office formats generally
        use OLE compound storage.
        """
        if extension in OFFICE_EXTENSIONS:
            return True

        if magic_type == "ole":
            return True

        if is_zip and extension in OFFICE_EXTENSIONS:
            return True

        return False

    @staticmethod
    def _looks_like_executable(
        *,
        extension: str,
        magic_type: str,
    ) -> bool:
        """Identify obvious executable files from extension or magic bytes."""
        return extension in EXECUTABLE_EXTENSIONS or magic_type in {"pe", "elf", "wasm"}

    @staticmethod
    def _possible_extension_spoofing(
        *,
        extension: str,
        magic_type: str,
    ) -> bool:
        """
        Detect likely extension spoofing.

        This intentionally only flags strong mismatches rather than trying to
        determine whether a filename is malicious.
        """
        if magic_type == "pe":
            return extension not in EXECUTABLE_EXTENSIONS

        if magic_type == "elf":
            return extension not in EXECUTABLE_EXTENSIONS

        if magic_type == "pdf":
            return extension != ".pdf"

        if magic_type == "ole":
            return extension not in {
                ".doc",
                ".dot",
                ".xls",
                ".xlt",
                ".ppt",
                ".pot",
                ".pps",
                ".msg",
                ".vsd",
            }

        return False


# ---------------------------------------------------------------------------
# Convenience API
# ---------------------------------------------------------------------------

_DEFAULT_EXTRACTOR = FileFeatureExtractor()


def extract_file_features(
    file_path: str | os.PathLike[str],
    *,
    sample_size: int = DEFAULT_SAMPLE_SIZE,
    calculate_hashes: bool = True,
    include_filename_features: bool = True,
    include_content_indicators: bool = True,
) -> dict[str, Any]:
    """
    Convenience function for one-shot file feature extraction.

    Example
    -------
    >>> features = extract_file_features("sample.docm")
    >>> features["file_size_bytes"]
    12345
    """
    # Reuse the module-level extractor only for the default configuration.
    if (
        sample_size == DEFAULT_SAMPLE_SIZE
        and calculate_hashes
        and include_filename_features
        and include_content_indicators
    ):
        return _DEFAULT_EXTRACTOR.extract(file_path)

    extractor = FileFeatureExtractor(
        sample_size=sample_size,
        calculate_hashes=calculate_hashes,
        include_filename_features=include_filename_features,
        include_content_indicators=include_content_indicators,
    )

    return extractor.extract(file_path)


__all__ = [
    "FileFeatureExtractor",
    "extract_file_features",
    "EXECUTABLE_EXTENSIONS",
    "SCRIPT_EXTENSIONS",
    "OFFICE_EXTENSIONS",
    "ARCHIVE_EXTENSIONS",
]
