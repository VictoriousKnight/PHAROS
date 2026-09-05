"""
pharos-cdr.api.services
=======================

Application service layer for the Pharos CDR web/API layer.

This module intentionally keeps HTTP/Flask concerns out of the service layer.
It coordinates:

    upload bytes
        -> scanner
        -> scan result
        -> report generation
        -> sanitized-content retrieval

The service layer does not execute documents, macros, scripts, binaries, or
embedded payloads. It only passes bounded bytes/metadata to the existing
static-analysis and CDR pipeline.

Design goals
------------
- No Flask request/context dependency.
- No subprocesses.
- No network access.
- No macro/script execution.
- No direct filesystem writes except when an explicit caller asks to persist
  a generated report/sanitized artifact through a supplied destination.
- Deterministic service behavior for the same pipeline configuration/result.
- Strong input and output bounds.
- Compatible with dataclasses, mappings, and normal Python objects returned by
  the scanner/report layers.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
from dataclasses import asdict, dataclass, is_dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import (
    Any,
    BinaryIO,
    Iterable,
    Mapping,
    MutableMapping,
    Optional,
    Sequence,
)

try:
    from ..pipeline import report as report_pipeline
    from ..pipeline import scanner as scanner_pipeline
except ImportError:  # pragma: no cover - supports direct package execution
    from pipeline import report as report_pipeline  # type: ignore
    from pipeline import scanner as scanner_pipeline  # type: ignore


MODULE_NAME = "pharos_cdr.api.services"
SERVICES_VERSION = "1.0.0"

# ---------------------------------------------------------------------------
# Resource limits
# ---------------------------------------------------------------------------

MAX_INPUT_BYTES = 100 * 1024 * 1024
MAX_FILENAME_LENGTH = 255
MAX_CONTENT_TYPE_LENGTH = 160
MAX_METADATA_ITEMS = 128
MAX_METADATA_VALUE_LENGTH = 4_096

MAX_REPORT_BYTES = 25 * 1024 * 1024
MAX_SANITIZED_BYTES = 100 * 1024 * 1024
MAX_SCAN_ID_LENGTH = 128

DEFAULT_SCAN_MODE = "balanced"
DEFAULT_REPORT_FORMAT = "json"

ALLOWED_SCAN_MODES = frozenset(
    {
        "minimal",
        "analysis",
        "balanced",
        "strict",
    }
)

ALLOWED_REPORT_FORMATS = frozenset(
    {
        "json",
        "jsonl",
        "html",
        "text",
    }
)

SHA256_LENGTH = 64


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class ServiceError(RuntimeError):
    """Base exception for API service failures."""


class ServiceValidationError(ServiceError):
    """Raised when service input fails validation."""


class ServiceLimitError(ServiceError):
    """Raised when a service resource limit is exceeded."""


class ScanServiceError(ServiceError):
    """Raised when the scanner cannot complete a scan."""


class ReportServiceError(ServiceError):
    """Raised when report generation fails."""


class SanitizedContentError(ServiceError):
    """Raised when sanitized content is unavailable or invalid."""


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class UploadDescriptor:
    """
    Normalized metadata describing an uploaded document.
    """

    filename: str
    content_type: str = ""
    size: int = 0
    sha256: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "filename": self.filename,
            "content_type": self.content_type,
            "size": self.size,
            "sha256": self.sha256,
        }


@dataclass(frozen=True)
class ScanRequest:
    """
    Input to the scan service.
    """

    content: bytes
    filename: str
    content_type: str = ""
    mode: str = DEFAULT_SCAN_MODE
    metadata: Optional[Mapping[str, Any]] = None

    def to_descriptor(self) -> UploadDescriptor:
        digest = hashlib.sha256(self.content).hexdigest()

        return UploadDescriptor(
            filename=self.filename,
            content_type=self.content_type,
            size=len(self.content),
            sha256=digest,
        )


@dataclass(frozen=True)
class ScanServiceResult:
    """
    Stable service-level representation of a scan.

    ``raw_result`` intentionally remains available for internal integration
    with the pipeline while ``data`` contains a serialization-safe mapping.
    """

    scan_id: str
    descriptor: UploadDescriptor
    mode: str
    data: Mapping[str, Any]
    raw_result: Any = None
    created_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "mode": self.mode,
            "created_at": self.created_at,
            "file": self.descriptor.to_dict(),
            "result": _json_safe(self.data),
        }


@dataclass(frozen=True)
class ReportServiceResult:
    """
    Stable representation of a generated report.
    """

    scan_id: str
    format: str
    content: bytes
    media_type: str
    filename: str
    created_at: str

    @property
    def size(self) -> int:
        return len(self.content)

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.content).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "format": self.format,
            "media_type": self.media_type,
            "filename": self.filename,
            "size": self.size,
            "sha256": self.sha256,
            "created_at": self.created_at,
        }


@dataclass(frozen=True)
class SanitizedServiceResult:
    """
    Stable representation of sanitized output.
    """

    scan_id: str
    content: bytes
    filename: str
    media_type: str
    changed: bool
    original_sha256: str = ""
    sanitized_sha256: str = ""
    created_at: str = ""

    @property
    def size(self) -> int:
        return len(self.content)

    def to_dict(self) -> dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "filename": self.filename,
            "media_type": self.media_type,
            "size": self.size,
            "changed": self.changed,
            "original_sha256": self.original_sha256,
            "sanitized_sha256": self.sanitized_sha256,
            "created_at": self.created_at,
        }


# ---------------------------------------------------------------------------
# Generic helpers
# ---------------------------------------------------------------------------


def _safe_text(value: Any, maximum: int = MAX_METADATA_VALUE_LENGTH) -> str:
    """
    Convert arbitrary input to bounded text.
    """

    if value is None:
        return ""

    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")

    text = str(value).strip()

    if len(text) > maximum:
        return text[:maximum]

    return text


def _safe_filename(value: Any) -> str:
    """
    Normalize a user-supplied filename without creating filesystem paths.
    """

    name = _safe_text(value, MAX_FILENAME_LENGTH)

    if not name:
        return "document"

    name = name.replace("\\", "/")
    name = name.rsplit("/", 1)[-1]

    name = "".join(
        character
        for character in name
        if character.isprintable()
        and character not in {"\x00", "\r", "\n", "\t"}
    )

    if not name:
        return "document"

    return name[:MAX_FILENAME_LENGTH]


def _safe_content_type(value: Any) -> str:
    return _safe_text(value, MAX_CONTENT_TYPE_LENGTH).lower()


def _normalize_mode(value: Any) -> str:
    mode = _safe_text(value, 32).lower()

    if not mode:
        mode = DEFAULT_SCAN_MODE

    if mode not in ALLOWED_SCAN_MODES:
        raise ServiceValidationError(
            f"Unsupported scan mode: {mode!r}. "
            f"Expected one of: {', '.join(sorted(ALLOWED_SCAN_MODES))}."
        )

    return mode


def _normalize_report_format(value: Any) -> str:
    report_format = _safe_text(value, 16).lower()

    if not report_format:
        report_format = DEFAULT_REPORT_FORMAT

    if report_format not in ALLOWED_REPORT_FORMATS:
        raise ServiceValidationError(
            f"Unsupported report format: {report_format!r}. "
            f"Expected one of: {', '.join(sorted(ALLOWED_REPORT_FORMATS))}."
        )

    return report_format


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _validate_sha256(value: str) -> bool:
    if len(value) != SHA256_LENGTH:
        return False

    try:
        int(value, 16)
    except ValueError:
        return False

    return True


def _bounded_bytes(
    content: bytes | bytearray | memoryview,
    *,
    maximum: int = MAX_INPUT_BYTES,
) -> bytes:
    if isinstance(content, memoryview):
        content = content.tobytes()
    elif isinstance(content, bytearray):
        content = bytes(content)

    if not isinstance(content, bytes):
        raise ServiceValidationError("Content must be bytes-like.")

    if len(content) > maximum:
        raise ServiceLimitError(
            f"Input exceeds the service limit of {maximum} bytes."
        )

    return content


def _mapping(value: Any) -> Mapping[str, Any]:
    if isinstance(value, Mapping):
        return value

    if is_dataclass(value) and not isinstance(value, type):
        try:
            converted = asdict(value)
        except Exception:
            converted = {}

        if isinstance(converted, Mapping):
            return converted

    return {}


def _json_safe(
    value: Any,
    *,
    depth: int = 0,
    max_depth: int = 12,
) -> Any:
    """
    Convert arbitrary pipeline output into JSON-compatible bounded data.
    """

    if depth > max_depth:
        return "[max-depth]"

    if value is None or isinstance(value, (str, int, float, bool)):
        return value

    if isinstance(value, bytes):
        digest = hashlib.sha256(value).hexdigest()

        return {
            "type": "bytes",
            "size": len(value),
            "sha256": digest,
        }

    if isinstance(value, Path):
        return str(value)

    if isinstance(value, datetime):
        return value.isoformat()

    if is_dataclass(value) and not isinstance(value, type):
        try:
            return _json_safe(
                asdict(value),
                depth=depth + 1,
                max_depth=max_depth,
            )
        except Exception:
            return _safe_text(value)

    if isinstance(value, Mapping):
        output: dict[str, Any] = {}

        for index, (key, item) in enumerate(value.items()):
            if index >= MAX_METADATA_ITEMS * 10:
                break

            key_text = _safe_text(key, 256)

            output[key_text] = _json_safe(
                item,
                depth=depth + 1,
                max_depth=max_depth,
            )

        return output

    if isinstance(value, (list, tuple, set, frozenset)):
        output = []

        for index, item in enumerate(value):
            if index >= MAX_METADATA_ITEMS * 100:
                break

            output.append(
                _json_safe(
                    item,
                    depth=depth + 1,
                    max_depth=max_depth,
                )
            )

        return output

    return _safe_text(value)


def _result_to_mapping(result: Any) -> Mapping[str, Any]:
    """
    Convert a scanner result into a serialization-safe mapping.

    The scanner module is intentionally treated as the source of truth for
    its native serialization API.
    """

    serializer = getattr(scanner_pipeline, "result_to_dict", None)

    if callable(serializer):
        try:
            converted = serializer(result)
            if isinstance(converted, Mapping):
                return _json_safe(converted)
        except Exception:
            pass

    mapping = _mapping(result)

    if mapping:
        return _json_safe(mapping)

    return {
        "result": _json_safe(result),
    }


def _result_value(
    result: Any,
    *names: str,
    default: Any = None,
) -> Any:
    mapping = _mapping(result)

    for name in names:
        if name in mapping:
            return mapping[name]

    for name in names:
        try:
            value = getattr(result, name)
        except Exception:
            continue

        if value is not None:
            return value

    return default


def _scan_id_for_request(request: ScanRequest) -> str:
    """
    Produce a deterministic content-oriented identifier.

    The filename and scan mode are included so the same bytes can be analyzed
    under different policies without sharing an identifier.
    """

    identity = (
        request.mode,
        request.filename,
        request.content_type,
        _sha256(request.content),
    )

    payload = json.dumps(
        identity,
        ensure_ascii=True,
        separators=(",", ":"),
    ).encode("utf-8")

    return hashlib.sha256(payload).hexdigest()[:32]


def _sanitize_filename_extension(
    filename: str,
    *,
    suffix: str,
) -> str:
    """
    Preserve the original extension while adding a safe output suffix.
    """

    safe = _safe_filename(filename)

    path = Path(safe)

    if path.suffix:
        return f"{path.stem}{suffix}{path.suffix}"

    return f"{safe}{suffix}"


# ---------------------------------------------------------------------------
# Scanner configuration
# ---------------------------------------------------------------------------


def _scanner_config_for_mode(mode: str) -> Any:
    """
    Resolve a scanner configuration from the public scanner helpers.
    """

    mode = _normalize_mode(mode)

    if mode == "strict":
        factory = getattr(scanner_pipeline, "strict_config", None)
        if callable(factory):
            return factory()

    if mode == "analysis":
        factory = getattr(scanner_pipeline, "analysis_config", None)
        if callable(factory):
            return factory()

    if mode == "minimal":
        factory = getattr(scanner_pipeline, "minimal_config", None)
        if callable(factory):
            return factory()

    factory = getattr(scanner_pipeline, "default_config", None)

    if callable(factory):
        return factory()

    # A caller may be using an older scanner implementation. Passing None
    # allows scanner.scan_bytes() to select its own default.
    return None


def scanner_config_for_mode(mode: str = DEFAULT_SCAN_MODE) -> Any:
    """
    Public-friendly wrapper for resolving scanner configuration.
    """

    return _scanner_config_for_mode(_normalize_mode(mode))


# ---------------------------------------------------------------------------
# Scan service
# ---------------------------------------------------------------------------


def validate_scan_request(request: ScanRequest) -> ScanRequest:
    """
    Validate and normalize a scan request.
    """

    content = _bounded_bytes(request.content)

    filename = _safe_filename(request.filename)

    content_type = _safe_content_type(request.content_type)

    mode = _normalize_mode(request.mode)

    metadata: Optional[dict[str, Any]]

    if request.metadata is None:
        metadata = None
    else:
        if not isinstance(request.metadata, Mapping):
            raise ServiceValidationError("Metadata must be a mapping.")

        metadata = {}

        for index, (key, value) in enumerate(request.metadata.items()):
            if index >= MAX_METADATA_ITEMS:
                break

            key_text = _safe_text(key, 256)

            metadata[key_text] = _safe_text(
                value,
                MAX_METADATA_VALUE_LENGTH,
            )

    return ScanRequest(
        content=content,
        filename=filename,
        content_type=content_type,
        mode=mode,
        metadata=metadata,
    )


def scan_document(request: ScanRequest) -> ScanServiceResult:
    """
    Run the static scanner for a single document.
    """

    normalized = validate_scan_request(request)

    descriptor = normalized.to_descriptor()

    scan_id = _scan_id_for_request(normalized)

    config = _scanner_config_for_mode(normalized.mode)

    try:
        scan_function = getattr(scanner_pipeline, "scan_bytes", None)

        if not callable(scan_function):
            raise ScanServiceError(
                "scanner.scan_bytes() is not available."
            )

        kwargs: dict[str, Any] = {
            "filename": normalized.filename,
        }

        if normalized.content_type:
            kwargs["content_type"] = normalized.content_type

        if config is not None:
            kwargs["config"] = config

        try:
            raw_result = scan_function(
                normalized.content,
                **kwargs,
            )
        except TypeError:
            # Compatibility with scanner implementations that use a narrower
            # signature.
            kwargs.pop("content_type", None)

            try:
                raw_result = scan_function(
                    normalized.content,
                    **kwargs,
                )
            except TypeError:
                kwargs.pop("config", None)

                raw_result = scan_function(
                    normalized.content,
                    **kwargs,
                )

    except ServiceError:
        raise

    except Exception as exc:
        raise ScanServiceError(
            f"Static scan failed: {exc}"
        ) from exc

    data = _result_to_mapping(raw_result)

    # Keep the service identity outside the scanner's native result so the
    # API can rely on a stable contract even if the scanner evolves.
    if isinstance(data, MutableMapping):
        data = dict(data)
        data.setdefault("scan_id", scan_id)
        data.setdefault("service_version", SERVICES_VERSION)
        data.setdefault("file", descriptor.to_dict())
        data.setdefault("mode", normalized.mode)

        if normalized.metadata:
            data.setdefault("request_metadata", _json_safe(normalized.metadata))

    return ScanServiceResult(
        scan_id=scan_id,
        descriptor=descriptor,
        mode=normalized.mode,
        data=data,
        raw_result=raw_result,
        created_at=_utc_now(),
    )


def scan_bytes(
    content: bytes,
    *,
    filename: str = "document",
    content_type: str = "",
    mode: str = DEFAULT_SCAN_MODE,
    metadata: Optional[Mapping[str, Any]] = None,
) -> ScanServiceResult:
    """
    Convenience wrapper around :func:`scan_document`.
    """

    return scan_document(
        ScanRequest(
            content=content,
            filename=filename,
            content_type=content_type,
            mode=mode,
            metadata=metadata,
        )
    )


def scan_file(
    path: str | os.PathLike[str],
    *,
    filename: Optional[str] = None,
    content_type: str = "",
    mode: str = DEFAULT_SCAN_MODE,
    metadata: Optional[Mapping[str, Any]] = None,
) -> ScanServiceResult:
    """
    Read a local file and run the static scanner.

    This helper is intended for trusted server-side callers. The file is read
    as bytes and passed to the same bounded scan path; it is never executed.
    """

    try:
        source = Path(path)
    except Exception as exc:
        raise ServiceValidationError(
            "Invalid file path."
        ) from exc

    if not source.is_file():
        raise ServiceValidationError(
            f"Input file does not exist: {source}"
        )

    try:
        size = source.stat().st_size
    except OSError as exc:
        raise ServiceValidationError(
            f"Unable to inspect input file: {exc}"
        ) from exc

    if size > MAX_INPUT_BYTES:
        raise ServiceLimitError(
            f"Input file exceeds {MAX_INPUT_BYTES} bytes."
        )

    try:
        content = source.read_bytes()
    except OSError as exc:
        raise ServiceError(
            f"Unable to read input file: {exc}"
        ) from exc

    effective_filename = filename or source.name

    return scan_bytes(
        content,
        filename=effective_filename,
        content_type=content_type,
        mode=mode,
        metadata=metadata,
    )


def scan_stream(
    stream: BinaryIO,
    *,
    filename: str = "document",
    content_type: str = "",
    mode: str = DEFAULT_SCAN_MODE,
    metadata: Optional[Mapping[str, Any]] = None,
) -> ScanServiceResult:
    """
    Read a bounded binary stream and run the static scanner.
    """

    if not hasattr(stream, "read"):
        raise ServiceValidationError("stream must provide read().")

    chunks: list[bytes] = []
    total = 0
    chunk_size = 1024 * 1024

    while True:
        try:
            chunk = stream.read(chunk_size)
        except Exception as exc:
            raise ServiceError(
                f"Unable to read input stream: {exc}"
            ) from exc

        if not chunk:
            break

        if isinstance(chunk, str):
            raise ServiceValidationError(
                "Binary scan streams must return bytes."
            )

        chunk = bytes(chunk)

        total += len(chunk)

        if total > MAX_INPUT_BYTES:
            raise ServiceLimitError(
                f"Input stream exceeds {MAX_INPUT_BYTES} bytes."
            )

        chunks.append(chunk)

    return scan_bytes(
        b"".join(chunks),
        filename=filename,
        content_type=content_type,
        mode=mode,
        metadata=metadata,
    )


def scan_many(
    requests: Iterable[ScanRequest],
    *,
    fail_fast: bool = False,
) -> list[ScanServiceResult]:
    """
    Scan multiple documents sequentially.

    Sequential processing keeps resource use predictable and avoids creating
    an uncontrolled worker pool from an HTTP request.
    """

    results: list[ScanServiceResult] = []

    for item in requests:
        try:
            results.append(scan_document(item))
        except Exception:
            if fail_fast:
                raise

    return results


# ---------------------------------------------------------------------------
# Result helpers
# ---------------------------------------------------------------------------


def scan_result_to_dict(result: ScanServiceResult) -> dict[str, Any]:
    """
    Convert a service result into a JSON-compatible mapping.
    """

    return _json_safe(result.to_dict())


def scan_result_to_json(
    result: ScanServiceResult,
    *,
    indent: Optional[int] = 2,
) -> str:
    """
    Serialize a scan service result to JSON.
    """

    payload = json.dumps(
        scan_result_to_dict(result),
        ensure_ascii=False,
        indent=indent,
        sort_keys=True,
        separators=None if indent else (",", ":"),
    )

    if len(payload.encode("utf-8")) > MAX_REPORT_BYTES:
        raise ServiceLimitError(
            "Serialized scan result exceeds the service output limit."
        )

    return payload


def result_status(result: ScanServiceResult) -> str:
    """
    Return the scanner's normalized status when available.
    """

    value = _result_value(
        result.raw_result,
        "status",
        "scan_status",
        "verdict",
        "disposition",
        default=None,
    )

    if value is None:
        mapping = _mapping(result.data)
        value = (
            mapping.get("status")
            or mapping.get("scan_status")
            or mapping.get("verdict")
            or mapping.get("disposition")
        )

    return _safe_text(value, 64).lower()


def result_verdict(result: ScanServiceResult) -> str:
    """
    Return the scanner verdict when available.
    """

    value = _result_value(
        result.raw_result,
        "verdict",
        "status",
        "disposition",
        default=None,
    )

    if value is None:
        mapping = _mapping(result.data)
        value = (
            mapping.get("verdict")
            or mapping.get("status")
            or mapping.get("disposition")
        )

    return _safe_text(value, 64).lower()


def result_probability(result: ScanServiceResult) -> Optional[float]:
    """
    Extract the model probability from a scan result when available.
    """

    candidates = (
        "malicious_probability",
        "probability",
        "model_probability",
        "score",
    )

    value = _result_value(
        result.raw_result,
        *candidates,
        default=None,
    )

    if value is None:
        mapping = _mapping(result.data)

        for name in candidates:
            if name in mapping:
                value = mapping[name]
                break

        if value is None:
            model = mapping.get("model")
            model_mapping = _mapping(model)

            for name in candidates:
                if name in model_mapping:
                    value = model_mapping[name]
                    break

    if value is None:
        return None

    try:
        probability = float(value)
    except (TypeError, ValueError):
        return None

    if probability < 0.0 or probability > 1.0:
        return None

    return probability


def result_requires_review(result: ScanServiceResult) -> bool:
    """
    Determine whether the scan result requires analyst review.
    """

    raw = result.raw_result

    for name in (
        "requires_review",
        "review_required",
        "needs_review",
    ):
        value = _result_value(raw, name, default=None)

        if value is not None:
            return bool(value)

    mapping = _mapping(result.data)

    for name in (
        "requires_review",
        "review_required",
        "needs_review",
    ):
        if name in mapping:
            return bool(mapping[name])

    return False


def result_requires_sanitization(result: ScanServiceResult) -> bool:
    """
    Determine whether CDR sanitization is required.
    """

    raw = result.raw_result

    for name in (
        "requires_sanitization",
        "sanitization_required",
        "needs_sanitization",
    ):
        value = _result_value(raw, name, default=None)

        if value is not None:
            return bool(value)

    mapping = _mapping(result.data)

    for name in (
        "requires_sanitization",
        "sanitization_required",
        "needs_sanitization",
    ):
        if name in mapping:
            return bool(mapping[name])

    return False


def result_is_rejected(result: ScanServiceResult) -> bool:
    """
    Determine whether the scanner/policy rejected the document.
    """

    raw = result.raw_result

    checker = getattr(scanner_pipeline, "is_rejected", None)

    if callable(checker):
        try:
            return bool(checker(raw))
        except Exception:
            pass

    verdict = result_verdict(result)

    return verdict in {
        "reject",
        "rejected",
        "blocked",
        "malicious",
    }


def result_is_malicious(result: ScanServiceResult) -> bool:
    """
    Determine whether the scanner considers the input malicious.
    """

    checker = getattr(scanner_pipeline, "is_malicious", None)

    if callable(checker):
        try:
            return bool(checker(result.raw_result))
        except Exception:
            pass

    verdict = result_verdict(result)

    if verdict in {
        "malicious",
        "blocked",
        "reject",
        "rejected",
    }:
        return True

    probability = result_probability(result)

    return probability is not None and probability >= 0.80


# ---------------------------------------------------------------------------
# Report service
# ---------------------------------------------------------------------------


def _report_media_type(report_format: str) -> str:
    return {
        "json": "application/json; charset=utf-8",
        "jsonl": "application/x-ndjson; charset=utf-8",
        "html": "text/html; charset=utf-8",
        "text": "text/plain; charset=utf-8",
    }.get(
        report_format,
        "application/octet-stream",
    )


def _report_extension(report_format: str) -> str:
    return {
        "json": ".json",
        "jsonl": ".jsonl",
        "html": ".html",
        "text": ".txt",
    }[report_format]


def _render_report(
    result: ScanServiceResult,
    report_format: str,
) -> bytes:
    """
    Generate report bytes using the existing pipeline/report module.
    """

    report_format = _normalize_report_format(report_format)

    raw_result = result.raw_result

    try:
        if report_format == "json":
            renderer = getattr(report_pipeline, "report_to_json", None)

            if callable(renderer):
                rendered = renderer(raw_result)
            else:
                rendered = json.dumps(
                    _result_to_mapping(raw_result),
                    ensure_ascii=False,
                    indent=2,
                    sort_keys=True,
                )

        elif report_format == "jsonl":
            renderer = getattr(report_pipeline, "report_to_jsonl", None)

            if callable(renderer):
                rendered = renderer(raw_result)
            else:
                rendered = json.dumps(
                    _result_to_mapping(raw_result),
                    ensure_ascii=False,
                    sort_keys=True,
                )

        elif report_format == "html":
            renderer = getattr(report_pipeline, "report_to_html", None)

            if not callable(renderer):
                raise ReportServiceError(
                    "HTML report renderer is not available."
                )

            rendered = renderer(raw_result)

        else:
            renderer = getattr(report_pipeline, "report_to_text", None)

            if not callable(renderer):
                raise ReportServiceError(
                    "Text report renderer is not available."
                )

            rendered = renderer(raw_result)

    except ReportServiceError:
        raise

    except Exception as exc:
        raise ReportServiceError(
            f"Unable to render {report_format} report: {exc}"
        ) from exc

    if isinstance(rendered, str):
        content = rendered.encode("utf-8")

    elif isinstance(rendered, bytes):
        content = rendered

    else:
        content = _safe_text(rendered).encode("utf-8")

    if len(content) > MAX_REPORT_BYTES:
        raise ServiceLimitError(
            f"Generated report exceeds {MAX_REPORT_BYTES} bytes."
        )

    return content


def create_report(
    result: ScanServiceResult,
    *,
    report_format: str = DEFAULT_REPORT_FORMAT,
) -> ReportServiceResult:
    """
    Generate a report for a completed scan.
    """

    if not isinstance(result, ScanServiceResult):
        raise ServiceValidationError(
            "create_report() requires a ScanServiceResult."
        )

    report_format = _normalize_report_format(report_format)

    content = _render_report(
        result,
        report_format,
    )

    filename = _sanitize_filename_extension(
        result.descriptor.filename,
        suffix="-pharos-report",
    )

    path = Path(filename)

    filename = f"{path.stem}{_report_extension(report_format)}"

    return ReportServiceResult(
        scan_id=result.scan_id,
        format=report_format,
        content=content,
        media_type=_report_media_type(report_format),
        filename=filename,
        created_at=_utc_now(),
    )


def report_json(
    result: ScanServiceResult,
) -> ReportServiceResult:
    """
    Generate a JSON report.
    """

    return create_report(
        result,
        report_format="json",
    )


def report_html(
    result: ScanServiceResult,
) -> ReportServiceResult:
    """
    Generate a self-contained HTML report.
    """

    return create_report(
        result,
        report_format="html",
    )


def report_text(
    result: ScanServiceResult,
) -> ReportServiceResult:
    """
    Generate a text report.
    """

    return create_report(
        result,
        report_format="text",
    )


def save_report(
    report: ReportServiceResult,
    destination: str | os.PathLike[str],
) -> Path:
    """
    Persist a generated report.

    This function is intentionally explicit: report persistence only occurs
    when a caller invokes it.
    """

    if not isinstance(report, ReportServiceResult):
        raise ServiceValidationError(
            "save_report() requires a ReportServiceResult."
        )

    destination_path = Path(destination)

    if destination_path.exists() and destination_path.is_dir():
        raise ServiceValidationError(
            "Report destination must be a file, not a directory."
        )

    destination_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    try:
        destination_path.write_bytes(report.content)
    except OSError as exc:
        raise ServiceError(
            f"Unable to save report: {exc}"
        ) from exc

    return destination_path


# ---------------------------------------------------------------------------
# Sanitized-content service
# ---------------------------------------------------------------------------


def _extract_sanitized_bytes(raw_result: Any) -> Optional[bytes]:
    """
    Extract sanitized bytes from a scanner result.

    Supports common scanner result field names without requiring the scanner
    to expose one exact internal representation.
    """

    candidates = (
        "sanitized_content",
        "sanitized_bytes",
        "sanitized_document",
        "reconstructed_content",
        "reconstructed_bytes",
        "output_bytes",
    )

    for name in candidates:
        value = _result_value(
            raw_result,
            name,
            default=None,
        )

        if isinstance(value, bytes):
            return value

        if isinstance(value, bytearray):
            return bytes(value)

        if isinstance(value, memoryview):
            return value.tobytes()

    mapping = _mapping(raw_result)

    for container_name in (
        "sanitization",
        "sanitized",
        "cdr",
        "reconstruction",
    ):
        container = mapping.get(container_name)

        if container is None:
            continue

        for name in candidates:
            value = _result_value(
                container,
                name,
                default=None,
            )

            if isinstance(value, bytes):
                return value

            if isinstance(value, bytearray):
                return bytes(value)

            if isinstance(value, memoryview):
                return value.tobytes()

    return None


def sanitized_content(
    result: ScanServiceResult,
    *,
    original_content: Optional[bytes] = None,
) -> SanitizedServiceResult:
    """
    Retrieve sanitized bytes produced by the scan/CDR pipeline.

    The service never synthesizes a "sanitized" file if the pipeline did not
    actually produce one.
    """

    if not isinstance(result, ScanServiceResult):
        raise ServiceValidationError(
            "sanitized_content() requires a ScanServiceResult."
        )

    content = _extract_sanitized_bytes(result.raw_result)

    if content is None:
        raise SanitizedContentError(
            "No sanitized content is available for this scan."
        )

    content = _bounded_bytes(
        content,
        maximum=MAX_SANITIZED_BYTES,
    )

    original_sha256 = ""

    if original_content is not None:
        original = _bounded_bytes(
            original_content,
            maximum=MAX_INPUT_BYTES,
        )
        original_sha256 = _sha256(original)

    elif result.descriptor.sha256:
        original_sha256 = result.descriptor.sha256

    sanitized_sha256 = _sha256(content)

    changed = bool(
        original_sha256
        and _validate_sha256(original_sha256)
        and sanitized_sha256 != original_sha256
    )

    filename = _sanitize_filename_extension(
        result.descriptor.filename,
        suffix="-sanitized",
    )

    return SanitizedServiceResult(
        scan_id=result.scan_id,
        content=content,
        filename=filename,
        media_type=(
            result.descriptor.content_type
            or "application/octet-stream"
        ),
        changed=changed,
        original_sha256=original_sha256,
        sanitized_sha256=sanitized_sha256,
        created_at=_utc_now(),
    )


def save_sanitized_content(
    sanitized: SanitizedServiceResult,
    destination: str | os.PathLike[str],
) -> Path:
    """
    Explicitly persist sanitized content to a caller-selected path.
    """

    if not isinstance(sanitized, SanitizedServiceResult):
        raise ServiceValidationError(
            "save_sanitized_content() requires a SanitizedServiceResult."
        )

    destination_path = Path(destination)

    if destination_path.exists() and destination_path.is_dir():
        raise ServiceValidationError(
            "Sanitized destination must be a file, not a directory."
        )

    destination_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    try:
        destination_path.write_bytes(sanitized.content)
    except OSError as exc:
        raise ServiceError(
            f"Unable to save sanitized content: {exc}"
        ) from exc

    return destination_path


def sanitized_filename(result: ScanServiceResult) -> str:
    """
    Return the recommended sanitized download filename.
    """

    return _sanitize_filename_extension(
        result.descriptor.filename,
        suffix="-sanitized",
    )


# ---------------------------------------------------------------------------
# Report/sanitization orchestration
# ---------------------------------------------------------------------------


def scan_and_report(
    request: ScanRequest,
    *,
    report_format: str = DEFAULT_REPORT_FORMAT,
) -> tuple[ScanServiceResult, ReportServiceResult]:
    """
    Scan a document and immediately generate its requested report.
    """

    result = scan_document(request)

    report = create_report(
        result,
        report_format=report_format,
    )

    return result, report


def scan_and_sanitize(
    request: ScanRequest,
) -> tuple[ScanServiceResult, SanitizedServiceResult]:
    """
    Scan a document and return the sanitized artifact when available.

    The original input bytes are retained only in the caller's request object;
    the service does not persist them.
    """

    result = scan_document(request)

    sanitized = sanitized_content(
        result,
        original_content=request.content,
    )

    return result, sanitized


def scan_report_and_sanitize(
    request: ScanRequest,
    *,
    report_format: str = DEFAULT_REPORT_FORMAT,
) -> tuple[
    ScanServiceResult,
    ReportServiceResult,
    Optional[SanitizedServiceResult],
]:
    """
    Perform scan, report generation, and optional sanitized-content retrieval.

    A missing sanitized artifact is not considered a scan failure. This allows
    clean/rejected/non-sanitizable results to remain reportable.
    """

    result = scan_document(request)

    report = create_report(
        result,
        report_format=report_format,
    )

    sanitized: Optional[SanitizedServiceResult] = None

    try:
        sanitized = sanitized_content(
            result,
            original_content=request.content,
        )
    except SanitizedContentError:
        sanitized = None

    return result, report, sanitized


# ---------------------------------------------------------------------------
# API-oriented summaries
# ---------------------------------------------------------------------------


def service_summary(
    result: ScanServiceResult,
) -> dict[str, Any]:
    """
    Return a compact summary suitable for a web UI.
    """

    data = _mapping(result.data)

    summary: dict[str, Any] = {
        "scan_id": result.scan_id,
        "filename": result.descriptor.filename,
        "content_type": result.descriptor.content_type,
        "size": result.descriptor.size,
        "sha256": result.descriptor.sha256,
        "mode": result.mode,
        "created_at": result.created_at,
        "status": result_status(result),
        "verdict": result_verdict(result),
        "malicious": result_is_malicious(result),
        "rejected": result_is_rejected(result),
        "requires_review": result_requires_review(result),
        "requires_sanitization": result_requires_sanitization(result),
    }

    probability = result_probability(result)

    if probability is not None:
        summary["malicious_probability"] = probability

    for source_key, target_key in (
        ("risk_score", "risk_score"),
        ("confidence", "confidence"),
        ("feature_count", "feature_count"),
        ("finding_count", "finding_count"),
    ):
        if source_key in data:
            summary[target_key] = _json_safe(data[source_key])

    return summary


def service_metadata(
    result: ScanServiceResult,
) -> dict[str, Any]:
    """
    Return service-level metadata for API responses.
    """

    return {
        "service": MODULE_NAME,
        "service_version": SERVICES_VERSION,
        "scan_id": result.scan_id,
        "created_at": result.created_at,
        "file": result.descriptor.to_dict(),
        "mode": result.mode,
    }


def health_status() -> dict[str, Any]:
    """
    Return service dependency health information.

    This does not perform a document scan and does not execute external
    programs.
    """

    scanner_available = callable(
        getattr(scanner_pipeline, "scan_bytes", None)
    )

    report_available = all(
        callable(getattr(report_pipeline, name, None))
        for name in (
            "report_to_json",
            "report_to_html",
            "report_to_text",
        )
    )

    return {
        "service": MODULE_NAME,
        "version": SERVICES_VERSION,
        "status": (
            "ok"
            if scanner_available and report_available
            else "degraded"
        ),
        "dependencies": {
            "scanner": scanner_available,
            "report": report_available,
        },
        "limits": {
            "max_input_bytes": MAX_INPUT_BYTES,
            "max_report_bytes": MAX_REPORT_BYTES,
            "max_sanitized_bytes": MAX_SANITIZED_BYTES,
        },
        "timestamp": _utc_now(),
    }


# ---------------------------------------------------------------------------
# Stream/file compatibility helpers
# ---------------------------------------------------------------------------


def request_from_upload(
    stream: BinaryIO,
    *,
    filename: str,
    content_type: str = "",
    mode: str = DEFAULT_SCAN_MODE,
    metadata: Optional[Mapping[str, Any]] = None,
) -> ScanRequest:
    """
    Build a validated ScanRequest from a binary upload stream.
    """

    if not hasattr(stream, "read"):
        raise ServiceValidationError(
            "Upload stream must provide read()."
        )

    chunks: list[bytes] = []
    total = 0
    chunk_size = 1024 * 1024

    while True:
        chunk = stream.read(chunk_size)

        if not chunk:
            break

        if isinstance(chunk, str):
            raise ServiceValidationError(
                "Upload stream must be binary."
            )

        chunk = bytes(chunk)
        total += len(chunk)

        if total > MAX_INPUT_BYTES:
            raise ServiceLimitError(
                f"Upload exceeds {MAX_INPUT_BYTES} bytes."
            )

        chunks.append(chunk)

    return validate_scan_request(
        ScanRequest(
            content=b"".join(chunks),
            filename=filename,
            content_type=content_type,
            mode=mode,
            metadata=metadata,
        )
    )


def request_from_bytes(
    content: bytes,
    *,
    filename: str = "document",
    content_type: str = "",
    mode: str = DEFAULT_SCAN_MODE,
    metadata: Optional[Mapping[str, Any]] = None,
) -> ScanRequest:
    """
    Build a validated ScanRequest from bytes.
    """

    return validate_scan_request(
        ScanRequest(
            content=content,
            filename=filename,
            content_type=content_type,
            mode=mode,
            metadata=metadata,
        )
    )


def request_content_stream(
    request: ScanRequest,
) -> io.BytesIO:
    """
    Return an in-memory read-only-equivalent stream for a request.

    The returned stream contains only the request's bounded bytes.
    """

    normalized = validate_scan_request(request)

    return io.BytesIO(normalized.content)


# ---------------------------------------------------------------------------
# Aliases
# ---------------------------------------------------------------------------


scan = scan_document
create = scan_document
report = create_report
sanitize = sanitized_content
summary = service_summary
health = health_status


# ---------------------------------------------------------------------------
# PUBLIC APIs
# ---------------------------------------------------------------------------

__all__ = [
    "MODULE_NAME",
    "SERVICES_VERSION",
    "MAX_INPUT_BYTES",
    "MAX_REPORT_BYTES",
    "MAX_SANITIZED_BYTES",
    "DEFAULT_SCAN_MODE",
    "DEFAULT_REPORT_FORMAT",
    "ALLOWED_SCAN_MODES",
    "ALLOWED_REPORT_FORMATS",
    "ServiceError",
    "ServiceValidationError",
    "ServiceLimitError",
    "ScanServiceError",
    "ReportServiceError",
    "SanitizedContentError",
    "UploadDescriptor",
    "ScanRequest",
    "ScanServiceResult",
    "ReportServiceResult",
    "SanitizedServiceResult",
    "scanner_config_for_mode",
    "validate_scan_request",
    "request_from_upload",
    "request_from_bytes",
    "request_content_stream",
    "scan_document",
    "scan_bytes",
    "scan_file",
    "scan_stream",
    "scan_many",
    "scan_result_to_dict",
    "scan_result_to_json",
    "result_status",
    "result_verdict",
    "result_probability",
    "result_requires_review",
    "result_requires_sanitization",
    "result_is_rejected",
    "result_is_malicious",
    "create_report",
    "report_json",
    "report_html",
    "report_text",
    "save_report",
    "sanitized_content",
    "sanitized_filename",
    "save_sanitized_content",
    "scan_and_report",
    "scan_and_sanitize",
    "scan_report_and_sanitize",
    "service_summary",
    "service_metadata",
    "health_status",
    "scan",
    "create",
    "report",
    "sanitize",
    "summary",
    "health",
]