"""
pharos-cdr/src/ingestion/file_validator.py

Defensive static file validation for the Pharos CDR ingestion layer.

This module validates an input file before deeper extraction or CDR processing.
It does not execute the file, invoke external tools, decompress archives, parse
macros, resolve URLs, or modify the host filesystem.

Design goals
------------
- Deterministic validation results.
- Bounded resource consumption.
- Static/content-first inspection.
- Compatibility with ``src.ingestion.file_type``.
- Useful diagnostics for downstream pipeline/reporting.
- Stable scalar feature representation for ML and policy layers.
- Safe handling of malformed, truncated, oversized, or unreadable inputs.

Validation stages
-----------------
1. Input/path validation.
2. File metadata validation.
3. Size and readability checks.
4. Bounded content sampling.
5. Cryptographic hashing.
6. File-type identification.
7. Extension/content consistency checks.
8. Structural sanity checks.
9. Risk-oriented validation findings.
10. Stable feature-vector generation.

No validation finding means that a file is malicious. Validation is an
ingestion-quality and safety gate, not a malware verdict.
"""

from __future__ import annotations

import hashlib
import math
import os
import stat
from dataclasses import asdict, dataclass, field, is_dataclass
from pathlib import Path
from typing import (
    Any,
    Dict,
    Iterable,
    Iterator,
    List,
    Mapping,
    Optional,
    Sequence,
    Tuple,
)

# ---------------------------------------------------------------------------
# Resource limits
# ---------------------------------------------------------------------------

MAX_FILE_SIZE = 25 * 1024 * 1024
MAX_SAMPLE_SIZE = 64 * 1024
MAX_HASH_SIZE = 25 * 1024 * 1024
MAX_TEXT_PREVIEW = 4096
MAX_FINDINGS = 256
MAX_FEATURE_KEYS = 4096

SHA256_CHUNK_SIZE = 1024 * 1024
READ_CHUNK_SIZE = 64 * 1024


# ---------------------------------------------------------------------------
# Severity
# ---------------------------------------------------------------------------

SEVERITY_ORDER = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


# ---------------------------------------------------------------------------
# Validation finding
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ValidationFinding:
    """
    One deterministic validation finding.

    ``severity`` describes the ingestion concern, not malware certainty.
    """

    code: str
    message: str
    severity: str = "info"
    category: str = "validation"
    evidence: Optional[str] = None
    recoverable: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------------
# File hashes
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FileHashes:
    """Cryptographic hashes calculated during validation."""

    md5: str = ""
    sha1: str = ""
    sha256: str = ""
    size_hashed: int = 0
    complete: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------------
# File statistics
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FileStatistics:
    """Basic static properties of the supplied file."""

    size: int = 0
    sample_size: int = 0
    is_empty: bool = False
    is_regular_file: bool = False
    readable: bool = False
    seekable: bool = False

    ascii_ratio: float = 0.0
    printable_ratio: float = 0.0
    zero_ratio: float = 0.0
    entropy: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------------
# Validation result
# ---------------------------------------------------------------------------


@dataclass
class FileValidationResult:
    """
    Complete result of static file validation.

    ``valid`` means the input passed the ingestion gate. It does not mean the
    file is benign or safe to open.

    ``acceptable`` is retained as a semantic alias for pipeline consumers.
    """

    valid: bool
    acceptable: bool

    path: Optional[str] = None
    filename: str = ""
    extension: str = ""

    file_type: Optional[str] = None
    family: Optional[str] = None
    mime_type: Optional[str] = None

    type_confidence: float = 0.0
    extension_mismatch: bool = False

    hashes: FileHashes = field(default_factory=FileHashes)
    statistics: FileStatistics = field(default_factory=FileStatistics)

    findings: List[ValidationFinding] = field(default_factory=list)

    fatal_errors: int = 0
    warnings: int = 0
    informational_findings: int = 0

    feature_vector: Dict[str, float] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self._refresh_counts()
        self.feature_vector = build_feature_vector(self)

    def _refresh_counts(self) -> None:
        self.fatal_errors = sum(
            1 for finding in self.findings if not finding.recoverable
        )
        self.warnings = sum(
            1
            for finding in self.findings
            if finding.severity in {"medium", "high", "critical"}
        )
        self.informational_findings = sum(
            1 for finding in self.findings if finding.severity == "info"
        )

    @property
    def highest_severity(self) -> str:
        """Return the highest severity represented by the findings."""

        if not self.findings:
            return "info"

        return max(
            self.findings,
            key=lambda item: SEVERITY_ORDER.get(item.severity, 0),
        ).severity

    @property
    def has_errors(self) -> bool:
        """Whether validation encountered a non-recoverable error."""

        return self.fatal_errors > 0

    @property
    def has_warnings(self) -> bool:
        """Whether validation produced medium-or-higher findings."""

        return self.warnings > 0

    def to_dict(self) -> Dict[str, Any]:
        """Serialize the validation result to ordinary Python objects."""

        return {
            "valid": self.valid,
            "acceptable": self.acceptable,
            "path": self.path,
            "filename": self.filename,
            "extension": self.extension,
            "file_type": self.file_type,
            "family": self.family,
            "mime_type": self.mime_type,
            "type_confidence": self.type_confidence,
            "extension_mismatch": self.extension_mismatch,
            "hashes": self.hashes.to_dict(),
            "statistics": self.statistics.to_dict(),
            "findings": [item.to_dict() for item in self.findings],
            "fatal_errors": self.fatal_errors,
            "warnings": self.warnings,
            "informational_findings": self.informational_findings,
            "highest_severity": self.highest_severity,
            "feature_vector": dict(self.feature_vector),
        }


# ---------------------------------------------------------------------------
# Generic helpers
# ---------------------------------------------------------------------------


def _safe_text(value: Any, limit: int = MAX_TEXT_PREVIEW) -> str:
    """
    Convert arbitrary metadata into bounded display text.

    This function never evaluates arbitrary objects beyond ordinary string
    conversion and avoids exposing excessively large values in reports.
    """

    if value is None:
        return ""

    try:
        text = str(value)
    except Exception:
        return ""

    if len(text) <= limit:
        return text

    return text[:limit] + "..."


def _normalize_extension(extension: str) -> str:
    extension = _safe_text(extension, 64).strip().lower()

    if not extension:
        return ""

    if not extension.startswith("."):
        extension = "." + extension

    return extension


def _path_string(path: Any) -> Optional[str]:
    if path is None:
        return None

    try:
        return os.fspath(path)
    except TypeError:
        return _safe_text(path, 4096)


def _filename_from_path(path: Optional[str]) -> str:
    if not path:
        return ""

    try:
        return Path(path).name
    except Exception:
        return os.path.basename(path)


def _extension_from_path(path: Optional[str]) -> str:
    if not path:
        return ""

    try:
        return _normalize_extension(Path(path).suffix)
    except Exception:
        return ""


def _safe_stat(path: str) -> Optional[os.stat_result]:
    try:
        return os.stat(path, follow_symlinks=False)
    except (OSError, ValueError):
        return None


def _is_regular_file(path: str, metadata: Optional[os.stat_result] = None) -> bool:
    if metadata is None:
        metadata = _safe_stat(path)

    if metadata is None:
        return False

    try:
        return stat.S_ISREG(metadata.st_mode)
    except (AttributeError, TypeError):
        return False


def _is_probably_readable(path: str) -> bool:
    """
    Lightweight readability check.

    This is deliberately followed by an actual bounded read because access
    permissions alone are not sufficient to prove that a file can be read.
    """

    try:
        return os.access(path, os.R_OK)
    except OSError:
        return False


def _bounded_read(path: str, limit: int = MAX_SAMPLE_SIZE) -> Tuple[bytes, bool]:
    """
    Read at most ``limit`` bytes.

    Returns ``(data, complete)`` where ``complete`` indicates that EOF was
    reached before the limit.
    """

    limit = max(0, int(limit))

    if limit == 0:
        return b"", True

    chunks: List[bytes] = []
    total = 0

    try:
        with open(path, "rb") as handle:
            while total < limit:
                wanted = min(READ_CHUNK_SIZE, limit - total)
                chunk = handle.read(wanted)

                if not chunk:
                    return b"".join(chunks), True

                chunks.append(chunk)
                total += len(chunk)

                if len(chunk) < wanted:
                    return b"".join(chunks), True

    except (OSError, ValueError):
        return b"".join(chunks), False

    return b"".join(chunks), False


def _entropy(data: bytes) -> float:
    """Calculate Shannon entropy for a bounded byte sample."""

    if not data:
        return 0.0

    counts = [0] * 256

    for value in data:
        counts[value] += 1

    length = len(data)
    entropy = 0.0

    for count in counts:
        if count:
            probability = count / length
            entropy -= probability * math.log2(probability)

    return round(entropy, 6)


def _printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0

    printable = sum(1 for byte in data if byte in (9, 10, 13) or 32 <= byte <= 126)

    return round(printable / len(data), 6)


def _ascii_ratio(data: bytes) -> float:
    if not data:
        return 0.0

    ascii_bytes = sum(1 for byte in data if byte < 128)
    return round(ascii_bytes / len(data), 6)


def _zero_ratio(data: bytes) -> float:
    if not data:
        return 0.0

    return round(data.count(b"\x00") / len(data), 6)


def _hash_bytes(data: bytes) -> FileHashes:
    """
    Hash an in-memory byte sequence.

    Used primarily for byte-input validation.
    """

    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()

    md5.update(data)
    sha1.update(data)
    sha256.update(data)

    return FileHashes(
        md5=md5.hexdigest(),
        sha1=sha1.hexdigest(),
        sha256=sha256.hexdigest(),
        size_hashed=len(data),
        complete=True,
    )


def _hash_file(
    path: str,
    max_size: int = MAX_HASH_SIZE,
) -> FileHashes:
    """
    Calculate bounded MD5/SHA-1/SHA-256 hashes for a file.

    ``complete`` is false if the configured hash limit is reached before EOF.
    """

    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()

    total = 0
    complete = True

    try:
        with open(path, "rb") as handle:
            while total < max_size:
                wanted = min(SHA256_CHUNK_SIZE, max_size - total)
                chunk = handle.read(wanted)

                if not chunk:
                    break

                md5.update(chunk)
                sha1.update(chunk)
                sha256.update(chunk)
                total += len(chunk)

                if len(chunk) < wanted:
                    break
            else:
                # We consumed exactly the configured limit. Determine whether
                # additional content exists without reading it into memory.
                extra = handle.read(1)
                if extra:
                    complete = False

    except (OSError, ValueError):
        return FileHashes(
            md5="",
            sha1="",
            sha256="",
            size_hashed=total,
            complete=False,
        )

    return FileHashes(
        md5=md5.hexdigest(),
        sha1=sha1.hexdigest(),
        sha256=sha256.hexdigest(),
        size_hashed=total,
        complete=complete,
    )


def _hash_stream_bytes(data: bytes) -> FileHashes:
    return _hash_bytes(data)


# ---------------------------------------------------------------------------
# File-type integration
# ---------------------------------------------------------------------------


def _import_file_type_module() -> Any:
    """
    Import the sibling file-type detector.

    The fallback import supports direct execution/import arrangements without
    changing normal package behavior.
    """

    try:
        from . import file_type

        return file_type
    except ImportError:
        try:
            import file_type

            return file_type
        except ImportError:
            return None


def _identify_type(
    source: Any,
    filename: Optional[str] = None,
) -> Any:
    module = _import_file_type_module()

    if module is None:
        return None

    try:
        if isinstance(source, (bytes, bytearray, memoryview)):
            identifier = getattr(module, "identify_from_bytes", None)
            if callable(identifier):
                return identifier(bytes(source), filename=filename)
        else:
            identifier = getattr(module, "identify_file", None)
            if callable(identifier):
                return identifier(source)
    except Exception:
        return None

    return None


def _get_result_value(result: Any, *names: str) -> Any:
    if result is None:
        return None

    for name in names:
        if isinstance(result, Mapping) and name in result:
            return result[name]

        try:
            value = getattr(result, name)
        except AttributeError:
            continue

        if value is not None:
            return value

    return None


def _type_summary(type_result: Any) -> Tuple[
    Optional[str],
    Optional[str],
    Optional[str],
    float,
    bool,
]:
    """
    Normalize different versions of ``file_type.FileTypeResult``.

    Returns:
        file_type, family, mime_type, confidence, extension_mismatch
    """

    if type_result is None:
        return None, None, None, 0.0, False

    file_type = _get_result_value(
        type_result,
        "file_type",
        "type",
        "kind",
        "name",
    )

    family = _get_result_value(
        type_result,
        "family",
        "file_family",
    )

    mime_type = _get_result_value(
        type_result,
        "mime_type",
        "mime",
    )

    confidence = _get_result_value(
        type_result,
        "confidence",
        "type_confidence",
    )

    mismatch = _get_result_value(
        type_result,
        "extension_mismatch",
        "has_extension_mismatch",
    )

    try:
        confidence_value = float(confidence or 0.0)
    except (TypeError, ValueError):
        confidence_value = 0.0

    confidence_value = max(0.0, min(1.0, confidence_value))

    return (
        _safe_text(file_type, 128) or None,
        _safe_text(family, 128) or None,
        _safe_text(mime_type, 256) or None,
        confidence_value,
        bool(mismatch),
    )


# ---------------------------------------------------------------------------
# Finding construction
# ---------------------------------------------------------------------------


def _add_finding(
    findings: List[ValidationFinding],
    *,
    code: str,
    message: str,
    severity: str = "info",
    category: str = "validation",
    evidence: Optional[str] = None,
    recoverable: bool = True,
) -> None:
    if len(findings) >= MAX_FINDINGS:
        return

    normalized_severity = _safe_text(severity, 32).lower()

    if normalized_severity not in SEVERITY_ORDER:
        normalized_severity = "info"

    findings.append(
        ValidationFinding(
            code=_safe_text(code, 128),
            message=_safe_text(message, 2048),
            severity=normalized_severity,
            category=_safe_text(category, 128) or "validation",
            evidence=_safe_text(evidence, MAX_TEXT_PREVIEW) or None,
            recoverable=bool(recoverable),
        )
    )


# ---------------------------------------------------------------------------
# Structural checks
# ---------------------------------------------------------------------------


def _check_magic_consistency(
    data: bytes,
    family: Optional[str],
    file_type: Optional[str],
    findings: List[ValidationFinding],
) -> None:
    """
    Perform conservative sanity checks independent of the file-type module.

    These checks intentionally avoid declaring malware.
    """

    if not data:
        return

    upper_type = (file_type or "").lower()
    upper_family = (family or "").lower()

    if data.startswith(b"MZ"):
        if (
            upper_family
            and upper_family
            not in {
                "executable",
                "binary",
                "unknown",
            }
            and "pe" not in upper_type
            and "exe" not in upper_type
        ):
            _add_finding(
                findings,
                code="magic_type_inconsistency",
                message="The file begins with a Windows executable MZ signature but the detected family differs.",
                severity="medium",
                category="type_consistency",
            )

    if data.startswith(b"%PDF-"):
        if upper_family and upper_family not in {"document", "unknown"}:
            _add_finding(
                findings,
                code="magic_type_inconsistency",
                message="The file begins with a PDF signature but the detected family differs.",
                severity="medium",
                category="type_consistency",
            )

    if data.startswith(b"{\\rtf"):
        if upper_family and upper_family not in {"document", "unknown"}:
            _add_finding(
                findings,
                code="magic_type_inconsistency",
                message="The file begins with an RTF signature but the detected family differs.",
                severity="medium",
                category="type_consistency",
            )

    if data.startswith(b"PK\x03\x04"):
        if upper_family and upper_family not in {
            "archive",
            "document",
            "unknown",
        }:
            _add_finding(
                findings,
                code="zip_family_mismatch",
                message="The file has a ZIP container signature but the detected family differs.",
                severity="low",
                category="type_consistency",
            )


def _check_trailing_data(
    data: bytes,
    file_type: Optional[str],
    family: Optional[str],
    findings: List[ValidationFinding],
) -> None:
    """
    Identify a few common trailing-data conditions.

    This is deliberately conservative because many valid formats permit
    trailing data.
    """

    if len(data) < 16:
        return

    normalized_type = (file_type or "").lower()
    normalized_family = (family or "").lower()

    if normalized_type in {"pdf", "application/pdf"} or "pdf" in normalized_type:
        eof_marker = data.rfind(b"%%EOF")
        if eof_marker >= 0:
            trailing = data[eof_marker + len(b"%%EOF") :]
            if trailing.strip(b" \t\r\n\x00"):
                _add_finding(
                    findings,
                    code="pdf_trailing_data",
                    message="Non-whitespace data was found after the final PDF EOF marker in the bounded sample.",
                    severity="low",
                    category="structural_anomaly",
                )

    if normalized_family == "executable" or "pe" in normalized_type:
        # PE files commonly have overlay data, so this is intentionally not
        # reported as suspicious solely from the MZ/PE signatures.
        return


def _check_text_anomalies(
    data: bytes,
    findings: List[ValidationFinding],
) -> None:
    if not data:
        return

    text_ratio = _printable_ratio(data)

    # A very small sample that is mostly printable is not anomalous.
    if len(data) >= 1024 and text_ratio > 0.995:
        try:
            text = data.decode("utf-8", errors="ignore")
        except Exception:
            return

        null_count = text.count("\x00")

        if null_count:
            _add_finding(
                findings,
                code="mixed_text_nulls",
                message="The sample is predominantly printable but contains embedded NUL characters.",
                severity="low",
                category="structural_anomaly",
            )


def _check_entropy(
    statistics: FileStatistics,
    family: Optional[str],
    findings: List[ValidationFinding],
) -> None:
    """
    Flag unusually high sample entropy as a review signal.

    High entropy is not evidence of malware by itself; it can result from
    compression, encryption, media, archives, or legitimate packed data.
    """

    if statistics.sample_size < 4096:
        return

    if statistics.entropy < 7.75:
        return

    normalized_family = (family or "").lower()

    if normalized_family in {
        "archive",
        "audio",
        "video",
        "image",
        "binary",
        "executable",
    }:
        severity = "info"
    else:
        severity = "low"

    _add_finding(
        findings,
        code="high_entropy_sample",
        message="The bounded sample has high byte entropy; compression or encoding may be present.",
        severity=severity,
        category="content_characteristics",
        evidence=f"entropy={statistics.entropy:.4f}",
    )


# ---------------------------------------------------------------------------
# Extension validation
# ---------------------------------------------------------------------------


def _extension_declared_type(
    extension: str,
) -> Optional[str]:
    """
    Obtain a normalized declared type from ``file_type`` when available.
    """

    module = _import_file_type_module()

    if module is None:
        return None

    try:
        helper = getattr(module, "extension_metadata", None)

        if callable(helper):
            metadata = helper(extension)

            if isinstance(metadata, Mapping):
                for key in ("file_type", "type", "name", "family"):
                    value = metadata.get(key)
                    if value:
                        return _safe_text(value, 128)
    except Exception:
        pass

    return None


def _check_extension(
    extension: str,
    type_result: Any,
    findings: List[ValidationFinding],
) -> bool:
    """
    Check extension/content consistency.

    Returns whether a mismatch was identified.
    """

    if not extension or type_result is None:
        return False

    explicit = _get_result_value(
        type_result,
        "extension_mismatch",
        "has_extension_mismatch",
    )

    if explicit is not None:
        mismatch = bool(explicit)

        if mismatch:
            detected = _get_result_value(
                type_result,
                "file_type",
                "type",
                "kind",
            )

            _add_finding(
                findings,
                code="extension_content_mismatch",
                message=(
                    f"The declared extension '{extension}' does not match "
                    f"the detected content type."
                ),
                severity="medium",
                category="type_consistency",
                evidence=_safe_text(detected, 256),
            )

        return mismatch

    return False


# ---------------------------------------------------------------------------
# Core validators
# ---------------------------------------------------------------------------


def _statistics_from_sample(
    data: bytes,
    *,
    file_size: int,
    regular_file: bool,
    readable: bool,
    seekable: bool,
) -> FileStatistics:
    return FileStatistics(
        size=max(0, int(file_size)),
        sample_size=len(data),
        is_empty=file_size == 0,
        is_regular_file=regular_file,
        readable=readable,
        seekable=seekable,
        ascii_ratio=_ascii_ratio(data),
        printable_ratio=_printable_ratio(data),
        zero_ratio=_zero_ratio(data),
        entropy=_entropy(data),
    )


def validate_file(
    path: os.PathLike[str] | str,
    *,
    max_file_size: int = MAX_FILE_SIZE,
    max_sample_size: int = MAX_SAMPLE_SIZE,
    max_hash_size: int = MAX_HASH_SIZE,
    require_regular_file: bool = True,
    require_known_type: bool = False,
) -> FileValidationResult:
    """
    Validate a filesystem file using bounded static inspection.

    Parameters
    ----------
    path:
        Path to the file.
    max_file_size:
        Maximum accepted file size.
    max_sample_size:
        Maximum number of bytes used for content sampling.
    max_hash_size:
        Maximum number of bytes used for hashing.
    require_regular_file:
        Reject directories, FIFOs, sockets, and other non-regular objects.
    require_known_type:
        Reject files that cannot be identified by the file-type detector.

    Returns
    -------
    FileValidationResult
        Structured validation result.

    Security
    --------
    The function does not execute the target and does not follow symbolic
    links through ``stat``. Opening a symlink can still be affected by normal
    operating-system path semantics; callers operating in hostile shared
    directories should additionally enforce an appropriate filesystem
    isolation policy.
    """

    findings: List[ValidationFinding] = []

    normalized_path = _path_string(path)

    if not normalized_path:
        _add_finding(
            findings,
            code="missing_path",
            message="No file path was supplied.",
            severity="high",
            category="input",
            recoverable=False,
        )

        result = FileValidationResult(
            valid=False,
            acceptable=False,
            findings=findings,
        )
        return result

    filename = _filename_from_path(normalized_path)
    extension = _extension_from_path(normalized_path)

    if not os.path.exists(normalized_path):
        _add_finding(
            findings,
            code="file_not_found",
            message="The supplied file path does not exist.",
            severity="high",
            category="input",
            recoverable=False,
        )

        return FileValidationResult(
            valid=False,
            acceptable=False,
            path=normalized_path,
            filename=filename,
            extension=extension,
            findings=findings,
        )

    metadata = _safe_stat(normalized_path)

    if metadata is None:
        _add_finding(
            findings,
            code="stat_failed",
            message="The file metadata could not be read.",
            severity="high",
            category="input",
            recoverable=False,
        )

        return FileValidationResult(
            valid=False,
            acceptable=False,
            path=normalized_path,
            filename=filename,
            extension=extension,
            findings=findings,
        )

    regular_file = _is_regular_file(normalized_path, metadata)

    if require_regular_file and not regular_file:
        _add_finding(
            findings,
            code="not_regular_file",
            message="The input is not a regular filesystem file.",
            severity="high",
            category="input",
            recoverable=False,
        )

    file_size = int(getattr(metadata, "st_size", 0) or 0)

    if file_size < 0:
        _add_finding(
            findings,
            code="invalid_file_size",
            message="The filesystem reported an invalid negative file size.",
            severity="high",
            category="input",
            recoverable=False,
        )
        file_size = 0

    if file_size == 0:
        _add_finding(
            findings,
            code="empty_file",
            message="The input file is empty.",
            severity="medium",
            category="content",
        )

    if file_size > max_file_size:
        _add_finding(
            findings,
            code="file_too_large",
            message=(
                f"The file size ({file_size} bytes) exceeds the configured "
                f"ingestion limit ({max_file_size} bytes)."
            ),
            severity="high",
            category="resource_limit",
            recoverable=False,
        )

    readable_by_access = _is_probably_readable(normalized_path)

    if not readable_by_access:
        _add_finding(
            findings,
            code="read_access_denied",
            message="The process does not appear to have read access to the file.",
            severity="high",
            category="input",
            recoverable=False,
        )

    sample = b""
    sample_complete = False

    if regular_file and readable_by_access:
        sample, sample_complete = _bounded_read(
            normalized_path,
            min(max_sample_size, max(0, file_size)),
        )

        if file_size > 0 and not sample:
            _add_finding(
                findings,
                code="read_failed",
                message="The file could not be read for static validation.",
                severity="high",
                category="input",
                recoverable=False,
            )

        if sample and len(sample) < min(max_sample_size, file_size):
            _add_finding(
                findings,
                code="short_read",
                message="The file could not be completely read within the bounded sample operation.",
                severity="medium",
                category="input",
            )

    seekable = regular_file and readable_by_access

    statistics = _statistics_from_sample(
        sample,
        file_size=file_size,
        regular_file=regular_file,
        readable=bool(sample) or file_size == 0,
        seekable=seekable,
    )

    # Empty-file readability is meaningful even without a byte read.
    if file_size == 0 and regular_file and readable_by_access:
        statistics = _statistics_from_sample(
            b"",
            file_size=0,
            regular_file=True,
            readable=True,
            seekable=True,
        )

    hashes = FileHashes()

    if regular_file and readable_by_access:
        hashes = _hash_file(
            normalized_path,
            max_size=min(max_hash_size, max_file_size),
        )

        if not hashes.sha256:
            _add_finding(
                findings,
                code="hash_failed",
                message="Cryptographic hashing could not be completed.",
                severity="medium",
                category="integrity",
            )
        elif not hashes.complete:
            _add_finding(
                findings,
                code="partial_hash",
                message="Hashing stopped at the configured hash limit; the digest does not cover the complete file.",
                severity="medium",
                category="integrity",
            )

    type_result = None

    if sample and file_size <= max_file_size and regular_file and readable_by_access:
        type_result = _identify_type(
            normalized_path,
            filename=filename,
        )

    file_type, family, mime_type, confidence, _ = _type_summary(type_result)

    if type_result is None and sample:
        # The detector may legitimately be unavailable, but the ingestion
        # validator should make this visible.
        _add_finding(
            findings,
            code="type_detection_unavailable",
            message="File-type identification did not return a result.",
            severity="medium" if require_known_type else "low",
            category="type_detection",
            recoverable=not require_known_type,
        )

    if require_known_type and sample and not file_type:
        _add_finding(
            findings,
            code="unknown_file_type",
            message="The file could not be assigned a known content type.",
            severity="medium",
            category="type_detection",
            recoverable=False,
        )

    mismatch = _check_extension(
        extension,
        type_result,
        findings,
    )

    _check_magic_consistency(
        sample,
        family,
        file_type,
        findings,
    )

    _check_trailing_data(
        sample,
        file_type,
        family,
        findings,
    )

    _check_text_anomalies(
        sample,
        findings,
    )

    _check_entropy(
        statistics,
        family,
        findings,
    )

    if not extension and file_type:
        _add_finding(
            findings,
            code="missing_extension",
            message="The file has no conventional filename extension.",
            severity="info",
            category="metadata",
        )

    if sample and file_size > len(sample) and not sample_complete:
        _add_finding(
            findings,
            code="bounded_sample",
            message="Only a bounded prefix of the file was inspected.",
            severity="info",
            category="resource_limit",
        )

    # A file larger than the accepted limit is always invalid. Any other
    # non-recoverable finding also invalidates the ingestion result.
    fatal_count = sum(1 for finding in findings if not finding.recoverable)

    valid = fatal_count == 0

    # An empty file is not accepted even though its condition is technically
    # recoverable.
    if file_size == 0:
        valid = False

    result = FileValidationResult(
        valid=valid,
        acceptable=valid,
        path=normalized_path,
        filename=filename,
        extension=extension,
        file_type=file_type,
        family=family,
        mime_type=mime_type,
        type_confidence=confidence,
        extension_mismatch=mismatch,
        hashes=hashes,
        statistics=statistics,
        findings=findings,
    )

    return result


def validate_bytes(
    data: bytes | bytearray | memoryview,
    *,
    filename: Optional[str] = None,
    max_file_size: int = MAX_FILE_SIZE,
    max_sample_size: int = MAX_SAMPLE_SIZE,
    require_known_type: bool = False,
) -> FileValidationResult:
    """
    Validate an in-memory byte sequence without writing it to disk.

    This is useful for API uploads and pipeline tests.
    """

    findings: List[ValidationFinding] = []

    try:
        raw = bytes(data)
    except Exception:
        _add_finding(
            findings,
            code="invalid_bytes",
            message="The supplied input could not be converted to bytes.",
            severity="high",
            category="input",
            recoverable=False,
        )

        return FileValidationResult(
            valid=False,
            acceptable=False,
            filename=_safe_text(filename, 4096),
            findings=findings,
        )

    filename_value = _safe_text(filename, 4096)
    extension = _extension_from_path(filename_value)

    file_size = len(raw)

    if file_size == 0:
        _add_finding(
            findings,
            code="empty_file",
            message="The input byte sequence is empty.",
            severity="medium",
            category="content",
        )

    if file_size > max_file_size:
        _add_finding(
            findings,
            code="file_too_large",
            message=(
                f"The input size ({file_size} bytes) exceeds the configured "
                f"ingestion limit ({max_file_size} bytes)."
            ),
            severity="high",
            category="resource_limit",
            recoverable=False,
        )

    sample = raw[:max_sample_size]

    statistics = _statistics_from_sample(
        sample,
        file_size=file_size,
        regular_file=False,
        readable=True,
        seekable=False,
    )

    hashes = _hash_stream_bytes(raw)

    type_result = None

    if sample and file_size <= max_file_size:
        type_result = _identify_type(
            raw,
            filename=filename_value or None,
        )

    file_type, family, mime_type, confidence, _ = _type_summary(type_result)

    if type_result is None and sample:
        _add_finding(
            findings,
            code="type_detection_unavailable",
            message="File-type identification did not return a result.",
            severity="medium" if require_known_type else "low",
            category="type_detection",
            recoverable=not require_known_type,
        )

    if require_known_type and sample and not file_type:
        _add_finding(
            findings,
            code="unknown_file_type",
            message="The input could not be assigned a known content type.",
            severity="medium",
            category="type_detection",
            recoverable=False,
        )

    mismatch = _check_extension(
        extension,
        type_result,
        findings,
    )

    _check_magic_consistency(
        sample,
        family,
        file_type,
        findings,
    )

    _check_trailing_data(
        sample,
        file_type,
        family,
        findings,
    )

    _check_text_anomalies(
        sample,
        findings,
    )

    _check_entropy(
        statistics,
        family,
        findings,
    )

    if not extension and file_type:
        _add_finding(
            findings,
            code="missing_extension",
            message="No filename extension was supplied for the byte sequence.",
            severity="info",
            category="metadata",
        )

    if file_size > len(sample):
        _add_finding(
            findings,
            code="bounded_sample",
            message="Only a bounded prefix of the supplied byte sequence was analyzed for structural checks.",
            severity="info",
            category="resource_limit",
        )

    fatal_count = sum(1 for finding in findings if not finding.recoverable)

    valid = fatal_count == 0 and file_size > 0

    return FileValidationResult(
        valid=valid,
        acceptable=valid,
        path=None,
        filename=filename_value,
        extension=extension,
        file_type=file_type,
        family=family,
        mime_type=mime_type,
        type_confidence=confidence,
        extension_mismatch=mismatch,
        hashes=hashes,
        statistics=statistics,
        findings=findings,
    )


def validate(
    source: Any,
    *,
    filename: Optional[str] = None,
    max_file_size: int = MAX_FILE_SIZE,
    max_sample_size: int = MAX_SAMPLE_SIZE,
    max_hash_size: int = MAX_HASH_SIZE,
    require_regular_file: bool = True,
    require_known_type: bool = False,
) -> FileValidationResult:
    """
    Generic validation entry point.

    ``source`` may be:

    - a filesystem path;
    - ``bytes``;
    - ``bytearray``;
    - ``memoryview``.

    A string is interpreted as a filesystem path, not file content.
    """

    if isinstance(source, (bytes, bytearray, memoryview)):
        return validate_bytes(
            source,
            filename=filename,
            max_file_size=max_file_size,
            max_sample_size=max_sample_size,
            require_known_type=require_known_type,
        )

    if isinstance(source, (str, os.PathLike)):
        return validate_file(
            source,
            max_file_size=max_file_size,
            max_sample_size=max_sample_size,
            max_hash_size=max_hash_size,
            require_regular_file=require_regular_file,
            require_known_type=require_known_type,
        )

    findings = [
        ValidationFinding(
            code="unsupported_input",
            message=(
                "Validation expects a filesystem path or an in-memory byte sequence."
            ),
            severity="high",
            category="input",
            recoverable=False,
        )
    ]

    return FileValidationResult(
        valid=False,
        acceptable=False,
        filename=_safe_text(filename, 4096),
        findings=findings,
    )


# ---------------------------------------------------------------------------
# Convenience predicates
# ---------------------------------------------------------------------------


def is_valid(result: FileValidationResult) -> bool:
    """Return whether the result passed the ingestion gate."""

    return bool(result.valid)


def is_acceptable(result: FileValidationResult) -> bool:
    """Return whether the result is acceptable for downstream processing."""

    return bool(result.acceptable)


def has_finding(
    result: FileValidationResult,
    code: str,
) -> bool:
    """Check for a finding code."""

    target = _safe_text(code, 128).lower()

    return any(finding.code.lower() == target for finding in result.findings)


def has_category(
    result: FileValidationResult,
    category: str,
) -> bool:
    """Check whether a finding category is present."""

    target = _safe_text(category, 128).lower()

    return any(finding.category.lower() == target for finding in result.findings)


def findings_by_severity(
    result: FileValidationResult,
    severity: str,
) -> List[ValidationFinding]:
    """Return findings with the requested severity."""

    target = _safe_text(severity, 32).lower()

    return [
        finding for finding in result.findings if finding.severity.lower() == target
    ]


def findings_by_category(
    result: FileValidationResult,
    category: str,
) -> List[ValidationFinding]:
    """Return findings belonging to a category."""

    target = _safe_text(category, 128).lower()

    return [
        finding for finding in result.findings if finding.category.lower() == target
    ]


def highest_severity(
    result: FileValidationResult,
) -> str:
    """Return the highest severity present in a validation result."""

    return result.highest_severity


# ---------------------------------------------------------------------------
# Feature extraction
# ---------------------------------------------------------------------------


def build_feature_vector(
    result: FileValidationResult,
) -> Dict[str, float]:
    """
    Convert validation state into a deterministic scalar feature vector.

    Feature names are stable and contain no free-form values.
    """

    findings = result.findings

    vector: Dict[str, float] = {
        "valid": float(bool(result.valid)),
        "acceptable": float(bool(result.acceptable)),
        "has_file_type": float(bool(result.file_type)),
        "has_family": float(bool(result.family)),
        "has_mime_type": float(bool(result.mime_type)),
        "type_confidence": float(result.type_confidence),
        "extension_mismatch": float(bool(result.extension_mismatch)),
        "has_extension": float(bool(result.extension)),
        "has_path": float(bool(result.path)),
        "file_size": float(result.statistics.size),
        "sample_size": float(result.statistics.sample_size),
        "is_empty": float(result.statistics.is_empty),
        "is_regular_file": float(result.statistics.is_regular_file),
        "readable": float(result.statistics.readable),
        "seekable": float(result.statistics.seekable),
        "ascii_ratio": float(result.statistics.ascii_ratio),
        "printable_ratio": float(result.statistics.printable_ratio),
        "zero_ratio": float(result.statistics.zero_ratio),
        "entropy": float(result.statistics.entropy),
        "hash_available": float(bool(result.hashes.sha256)),
        "hash_complete": float(bool(result.hashes.complete)),
        "size_hashed": float(result.hashes.size_hashed),
        "finding_count": float(len(findings)),
        "fatal_error_count": float(result.fatal_errors),
        "warning_count": float(result.warnings),
        "info_finding_count": float(result.informational_findings),
        "highest_severity": float(SEVERITY_ORDER.get(result.highest_severity, 0)),
    }

    severity_counts = {severity: 0 for severity in SEVERITY_ORDER}

    category_counts: Dict[str, int] = {}
    code_counts: Dict[str, int] = {}

    for finding in findings:
        severity = finding.severity.lower()

        if severity in severity_counts:
            severity_counts[severity] += 1

        category = _feature_name(finding.category)

        if category:
            category_counts[category] = category_counts.get(category, 0) + 1

        code = _feature_name(finding.code)

        if code:
            code_counts[code] = code_counts.get(code, 0) + 1

    for severity, count in severity_counts.items():
        vector[f"severity_{severity}_count"] = float(count)

    for category, count in sorted(category_counts.items()):
        vector[f"category_{category}"] = float(count)

    for code, count in sorted(code_counts.items()):
        vector[f"finding_{code}"] = float(count)

    return dict(sorted(vector.items()))


def _feature_name(value: Any) -> str:
    """
    Convert arbitrary labels into stable feature-name fragments.
    """

    text = _safe_text(value, 128).strip().lower()

    if not text:
        return ""

    output: List[str] = []

    for character in text:
        if character.isalnum():
            output.append(character)
        elif character in {"_", "-", ".", " "}:
            output.append("_")

    normalized = "".join(output)

    while "__" in normalized:
        normalized = normalized.replace("__", "_")

    return normalized.strip("_")


def extract_feature_vector(
    result: FileValidationResult,
) -> Dict[str, float]:
    """Return the stable validation feature vector."""

    return dict(result.feature_vector)


def feature_names() -> List[str]:
    """
    Return the fixed core feature names.

    Dynamic finding/category features are intentionally not included here;
    consumers requiring a fixed ML schema should construct a union schema from
    training data or use the project's dataset module.
    """

    return [
        "valid",
        "acceptable",
        "has_file_type",
        "has_family",
        "has_mime_type",
        "type_confidence",
        "extension_mismatch",
        "has_extension",
        "has_path",
        "file_size",
        "sample_size",
        "is_empty",
        "is_regular_file",
        "readable",
        "seekable",
        "ascii_ratio",
        "printable_ratio",
        "zero_ratio",
        "entropy",
        "hash_available",
        "hash_complete",
        "size_hashed",
        "finding_count",
        "fatal_error_count",
        "warning_count",
        "info_finding_count",
        "highest_severity",
        "severity_info_count",
        "severity_low_count",
        "severity_medium_count",
        "severity_high_count",
        "severity_critical_count",
    ]


def build_feature_schema() -> Dict[str, Any]:
    """Return a serializable description of the core validation features."""

    return {
        "schema_version": "1.0",
        "module": "src.ingestion.file_validator",
        "feature_type": "scalar",
        "features": [
            {
                "name": name,
                "dtype": "float64",
            }
            for name in feature_names()
        ],
    }


def vectorize(
    result: FileValidationResult,
    names: Optional[Sequence[str]] = None,
) -> List[float]:
    """
    Convert a validation result into an ordered numeric vector.

    Missing feature names are represented by ``0.0``.
    """

    vector = result.feature_vector

    if names is None:
        names = feature_names()

    return [float(vector.get(name, 0.0)) for name in names]


# ---------------------------------------------------------------------------
# Serialization / summaries
# ---------------------------------------------------------------------------


def result_to_dict(
    result: FileValidationResult,
) -> Dict[str, Any]:
    """Serialize a validation result."""

    return result.to_dict()


def summarize(
    result: FileValidationResult,
) -> Dict[str, Any]:
    """
    Return a compact validation summary suitable for pipeline reports.
    """

    return {
        "valid": result.valid,
        "acceptable": result.acceptable,
        "filename": result.filename,
        "extension": result.extension,
        "file_type": result.file_type,
        "family": result.family,
        "mime_type": result.mime_type,
        "type_confidence": result.type_confidence,
        "extension_mismatch": result.extension_mismatch,
        "size": result.statistics.size,
        "sha256": result.hashes.sha256,
        "finding_count": len(result.findings),
        "fatal_errors": result.fatal_errors,
        "warnings": result.warnings,
        "highest_severity": result.highest_severity,
    }


def iter_findings(
    result: FileValidationResult,
) -> Iterator[ValidationFinding]:
    """Iterate over findings in deterministic insertion order."""

    yield from result.findings


def iter_high_risk_findings(
    result: FileValidationResult,
) -> Iterator[ValidationFinding]:
    """Iterate over medium/high/critical validation findings."""

    for finding in result.findings:
        if SEVERITY_ORDER.get(finding.severity, 0) >= SEVERITY_ORDER["medium"]:
            yield finding


# ---------------------------------------------------------------------------
# File validation policies
# ---------------------------------------------------------------------------


def passes_basic_ingestion_policy(
    result: FileValidationResult,
) -> bool:
    """
    Basic policy for allowing a file into downstream static analysis.

    This policy intentionally does not reject merely because the content type
    is unusual or the extension mismatches. Such findings are retained for the
    decision/CDR layer.
    """

    if not result.valid:
        return False

    if result.statistics.is_empty:
        return False

    if not result.statistics.readable:
        return False

    if result.statistics.size > MAX_FILE_SIZE:
        return False

    return True


def requires_review(
    result: FileValidationResult,
) -> bool:
    """
    Determine whether ingestion produced findings worth downstream review.

    This is not a malware verdict.
    """

    return any(
        finding.severity in {"medium", "high", "critical"}
        for finding in result.findings
    )


# ---------------------------------------------------------------------------
# Compatibility aliases
# ---------------------------------------------------------------------------


validate_file_input = validate_file
validate_path = validate_file
validate_content = validate_bytes
check_file = validate
check = validate
analyze = validate
analyze_file = validate_file
analyze_bytes = validate_bytes
extract_feature_vector_from_result = extract_feature_vector


# ---------------------------------------------------------------------------
# PUBLIC APIs
# ---------------------------------------------------------------------------


__all__ = [
    "ValidationFinding",
    "FileHashes",
    "FileStatistics",
    "FileValidationResult",
    "validate",
    "validate_file",
    "validate_bytes",
    "is_valid",
    "is_acceptable",
    "has_finding",
    "has_category",
    "findings_by_severity",
    "findings_by_category",
    "highest_severity",
    "passes_basic_ingestion_policy",
    "requires_review",
    "build_feature_vector",
    "extract_feature_vector",
    "extract_feature_vector_from_result",
    "feature_names",
    "build_feature_schema",
    "vectorize",
    "result_to_dict",
    "summarize",
    "iter_findings",
    "iter_high_risk_findings",
    "validate_file_input",
    "validate_path",
    "validate_content",
    "check_file",
    "check",
    "analyze",
    "analyze_file",
    "analyze_bytes",
]
