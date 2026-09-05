"""
pharos-cdr.api.schemas
======================

Request and response schemas for the Pharos CDR HTTP/API layer.

The project intentionally keeps this module dependency-light. The schemas
are implemented with dataclasses and explicit validation so the API can be
used with Flask without requiring a separate validation framework.

Security properties
-------------------
- Bounded request fields.
- No document execution.
- No URL fetching.
- No filesystem access.
- No macro/script execution.
- JSON-safe serialization.
- Explicit enum-like validation for modes, formats, and actions.
"""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import asdict, dataclass, field, is_dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Mapping, Optional, Sequence


MODULE_NAME = "pharos_cdr.api.schemas"
SCHEMAS_VERSION = "1.0.0"

# ---------------------------------------------------------------------------
# Limits
# ---------------------------------------------------------------------------

MAX_FILENAME_LENGTH = 255
MAX_CONTENT_TYPE_LENGTH = 160
MAX_SCAN_ID_LENGTH = 128
MAX_MODE_LENGTH = 32
MAX_REPORT_FORMAT_LENGTH = 16
MAX_REASON_LENGTH = 512
MAX_MESSAGE_LENGTH = 2_000
MAX_ERROR_LENGTH = 2_000
MAX_METADATA_ITEMS = 128
MAX_METADATA_KEY_LENGTH = 256
MAX_METADATA_VALUE_LENGTH = 4_096
MAX_FINDINGS = 20_000
MAX_SIGNALS = 20_000
MAX_STAGES = 10_000
MAX_ACTIONS = 10_000
MAX_FEATURES = 100_000
MAX_ITEMS = 20_000
MAX_JSON_DEPTH = 12

MAX_REQUEST_BYTES = 100 * 1024 * 1024

DEFAULT_SCAN_MODE = "balanced"
DEFAULT_REPORT_FORMAT = "json"

SCAN_MODES = frozenset(
    {
        "minimal",
        "analysis",
        "balanced",
        "strict",
    }
)

REPORT_FORMATS = frozenset(
    {
        "json",
        "jsonl",
        "html",
        "text",
    }
)

VERDICTS = frozenset(
    {
        "unknown",
        "clean",
        "benign",
        "suspicious",
        "malicious",
        "rejected",
        "blocked",
        "review",
    }
)

SEVERITIES = frozenset(
    {
        "info",
        "low",
        "medium",
        "high",
        "critical",
        "unknown",
    }
)

CDR_ACTIONS = frozenset(
    {
        "preserve",
        "sanitize",
        "remove",
        "reject",
        "review",
    }
)

SCAN_STATUSES = frozenset(
    {
        "queued",
        "running",
        "completed",
        "failed",
        "rejected",
        "error",
        "unknown",
    }
)


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class SchemaError(ValueError):
    """Base exception for schema validation errors."""


class SchemaValidationError(SchemaError):
    """Raised when a request or response violates the API schema."""


class SchemaSerializationError(SchemaError):
    """Raised when an object cannot be safely serialized."""


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class ScanMode(str, Enum):
    MINIMAL = "minimal"
    ANALYSIS = "analysis"
    BALANCED = "balanced"
    STRICT = "strict"


class ReportFormat(str, Enum):
    JSON = "json"
    JSONL = "jsonl"
    HTML = "html"
    TEXT = "text"


class ScanStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    REJECTED = "rejected"
    ERROR = "error"
    UNKNOWN = "unknown"


class Verdict(str, Enum):
    UNKNOWN = "unknown"
    CLEAN = "clean"
    BENIGN = "benign"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    REJECTED = "rejected"
    BLOCKED = "blocked"
    REVIEW = "review"


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    UNKNOWN = "unknown"


class CDRAction(str, Enum):
    PRESERVE = "preserve"
    SANITIZE = "sanitize"
    REMOVE = "remove"
    REJECT = "reject"
    REVIEW = "review"


# ---------------------------------------------------------------------------
# Primitive helpers
# ---------------------------------------------------------------------------


def _safe_text(
    value: Any,
    maximum: int,
    *,
    field_name: str,
    required: bool = False,
) -> str:
    if value is None:
        if required:
            raise SchemaValidationError(
                f"{field_name} is required."
            )
        return ""

    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")

    text = str(value).strip()

    if required and not text:
        raise SchemaValidationError(
            f"{field_name} cannot be empty."
        )

    if len(text) > maximum:
        raise SchemaValidationError(
            f"{field_name} exceeds the maximum length of {maximum}."
        )

    return text


def _safe_bool(value: Any, default: bool = False) -> bool:
    if value is None:
        return default

    if isinstance(value, bool):
        return value

    if isinstance(value, (int, float)):
        return bool(value)

    if isinstance(value, str):
        normalized = value.strip().lower()

        if normalized in {
            "1",
            "true",
            "yes",
            "on",
            "y",
        }:
            return True

        if normalized in {
            "0",
            "false",
            "no",
            "off",
            "n",
            "",
        }:
            return False

    return default


def _safe_int(
    value: Any,
    *,
    field_name: str,
    minimum: Optional[int] = None,
    maximum: Optional[int] = None,
    default: Optional[int] = None,
) -> Optional[int]:
    if value is None:
        return default

    if isinstance(value, bool):
        raise SchemaValidationError(
            f"{field_name} must be an integer."
        )

    try:
        result = int(value)
    except (TypeError, ValueError) as exc:
        raise SchemaValidationError(
            f"{field_name} must be an integer."
        ) from exc

    if minimum is not None and result < minimum:
        raise SchemaValidationError(
            f"{field_name} must be >= {minimum}."
        )

    if maximum is not None and result > maximum:
        raise SchemaValidationError(
            f"{field_name} must be <= {maximum}."
        )

    return result


def _safe_float(
    value: Any,
    *,
    field_name: str,
    minimum: Optional[float] = None,
    maximum: Optional[float] = None,
    default: Optional[float] = None,
) -> Optional[float]:
    if value is None:
        return default

    try:
        result = float(value)
    except (TypeError, ValueError) as exc:
        raise SchemaValidationError(
            f"{field_name} must be numeric."
        ) from exc

    if not math.isfinite(result):
        raise SchemaValidationError(
            f"{field_name} must be finite."
        )

    if minimum is not None and result < minimum:
        raise SchemaValidationError(
            f"{field_name} must be >= {minimum}."
        )

    if maximum is not None and result > maximum:
        raise SchemaValidationError(
            f"{field_name} must be <= {maximum}."
        )

    return result


def _safe_enum(
    value: Any,
    *,
    field_name: str,
    allowed: Sequence[str] | set[str] | frozenset[str],
    default: Optional[str] = None,
) -> str:
    text = _safe_text(
        value,
        maximum=MAX_MODE_LENGTH,
        field_name=field_name,
        required=default is None,
    ).lower()

    if not text and default is not None:
        text = default

    if text not in allowed:
        raise SchemaValidationError(
            f"Invalid {field_name}: {text!r}. "
            f"Expected one of: {', '.join(sorted(allowed))}."
        )

    return text


def _safe_mapping(
    value: Any,
    *,
    field_name: str,
    maximum_items: int = MAX_METADATA_ITEMS,
) -> dict[str, Any]:
    if value is None:
        return {}

    if not isinstance(value, Mapping):
        raise SchemaValidationError(
            f"{field_name} must be an object."
        )

    result: dict[str, Any] = {}

    for index, (key, item) in enumerate(value.items()):
        if index >= maximum_items:
            raise SchemaValidationError(
                f"{field_name} contains more than "
                f"{maximum_items} items."
            )

        key_text = _safe_text(
            key,
            MAX_METADATA_KEY_LENGTH,
            field_name=f"{field_name}.key",
            required=True,
        )

        result[key_text] = item

    return result


def _safe_sequence(
    value: Any,
    *,
    field_name: str,
    maximum_items: int,
) -> list[Any]:
    if value is None:
        return []

    if isinstance(value, (str, bytes, bytearray)):
        raise SchemaValidationError(
            f"{field_name} must be an array."
        )

    if not isinstance(value, Sequence):
        raise SchemaValidationError(
            f"{field_name} must be an array."
        )

    if len(value) > maximum_items:
        raise SchemaValidationError(
            f"{field_name} contains more than "
            f"{maximum_items} items."
        )

    return list(value)


def _json_safe(
    value: Any,
    *,
    depth: int = 0,
) -> Any:
    if depth > MAX_JSON_DEPTH:
        return "[max-depth]"

    if value is None or isinstance(
        value,
        (str, int, bool),
    ):
        return value

    if isinstance(value, float):
        return value if math.isfinite(value) else None

    if isinstance(value, bytes):
        return {
            "type": "bytes",
            "size": len(value),
            "sha256": hashlib.sha256(value).hexdigest(),
        }

    if isinstance(value, datetime):
        return value.isoformat()

    if isinstance(value, Enum):
        return value.value

    if is_dataclass(value) and not isinstance(value, type):
        try:
            return _json_safe(
                asdict(value),
                depth=depth + 1,
            )
        except Exception as exc:
            raise SchemaSerializationError(
                f"Unable to serialize dataclass: {exc}"
            ) from exc

    if isinstance(value, Mapping):
        result: dict[str, Any] = {}

        for index, (key, item) in enumerate(value.items()):
            if index >= MAX_ITEMS:
                break

            key_text = str(key)

            result[key_text] = _json_safe(
                item,
                depth=depth + 1,
            )

        return result

    if isinstance(value, (list, tuple, set, frozenset)):
        return [
            _json_safe(item, depth=depth + 1)
            for item in list(value)[:MAX_ITEMS]
        ]

    return str(value)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Request schemas
# ---------------------------------------------------------------------------


@dataclass
class ScanOptions:
    """
    Scanner options supplied by an API client.
    """

    mode: str = DEFAULT_SCAN_MODE
    include_report: bool = True
    report_format: str = DEFAULT_REPORT_FORMAT
    include_sanitized: bool = False
    include_features: bool = True
    include_evidence: bool = True
    include_explanations: bool = True

    def __post_init__(self) -> None:
        self.mode = _safe_enum(
            self.mode,
            field_name="mode",
            allowed=SCAN_MODES,
            default=DEFAULT_SCAN_MODE,
        )

        self.report_format = _safe_enum(
            self.report_format,
            field_name="report_format",
            allowed=REPORT_FORMATS,
            default=DEFAULT_REPORT_FORMAT,
        )

        self.include_report = _safe_bool(
            self.include_report,
            default=True,
        )

        self.include_sanitized = _safe_bool(
            self.include_sanitized,
            default=False,
        )

        self.include_features = _safe_bool(
            self.include_features,
            default=True,
        )

        self.include_evidence = _safe_bool(
            self.include_evidence,
            default=True,
        )

        self.include_explanations = _safe_bool(
            self.include_explanations,
            default=True,
        )

    @classmethod
    def from_mapping(
        cls,
        value: Optional[Mapping[str, Any]],
    ) -> "ScanOptions":
        if value is None:
            return cls()

        mapping = _safe_mapping(
            value,
            field_name="options",
        )

        return cls(
            mode=mapping.get("mode", DEFAULT_SCAN_MODE),
            include_report=mapping.get(
                "include_report",
                True,
            ),
            report_format=mapping.get(
                "report_format",
                DEFAULT_REPORT_FORMAT,
            ),
            include_sanitized=mapping.get(
                "include_sanitized",
                False,
            ),
            include_features=mapping.get(
                "include_features",
                True,
            ),
            include_evidence=mapping.get(
                "include_evidence",
                True,
            ),
            include_explanations=mapping.get(
                "include_explanations",
                True,
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "mode": self.mode,
            "include_report": self.include_report,
            "report_format": self.report_format,
            "include_sanitized": self.include_sanitized,
            "include_features": self.include_features,
            "include_evidence": self.include_evidence,
            "include_explanations": self.include_explanations,
        }


@dataclass
class ScanRequest:
    """
    JSON-compatible scan request.

    File bytes are intentionally not represented here. Multipart uploads are
    handled by the service layer/routes and converted into a bounded scan
    request before invoking the scanner.
    """

    filename: str
    content_type: str = ""
    options: ScanOptions = field(default_factory=ScanOptions)
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.filename = _safe_text(
            self.filename,
            MAX_FILENAME_LENGTH,
            field_name="filename",
            required=True,
        )

        self.filename = (
            self.filename.replace("\\", "/")
            .rsplit("/", 1)[-1]
        )

        if not self.filename:
            raise SchemaValidationError(
                "filename cannot be empty."
            )

        self.content_type = _safe_text(
            self.content_type,
            MAX_CONTENT_TYPE_LENGTH,
            field_name="content_type",
        ).lower()

        if not isinstance(self.options, ScanOptions):
            self.options = ScanOptions.from_mapping(
                self.options
            )

        self.metadata = _safe_mapping(
            self.metadata,
            field_name="metadata",
        )

    @classmethod
    def from_mapping(
        cls,
        value: Mapping[str, Any],
    ) -> "ScanRequest":
        mapping = _safe_mapping(
            value,
            field_name="request",
        )

        return cls(
            filename=mapping.get("filename", ""),
            content_type=mapping.get(
                "content_type",
                "",
            ),
            options=ScanOptions.from_mapping(
                mapping.get("options")
            ),
            metadata=mapping.get(
                "metadata",
                {},
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "filename": self.filename,
            "content_type": self.content_type,
            "options": self.options.to_dict(),
            "metadata": _json_safe(self.metadata),
        }


@dataclass
class ReportRequest:
    """
    Request to generate a report for a completed scan.
    """

    scan_id: str
    format: str = DEFAULT_REPORT_FORMAT
    inline: bool = False

    def __post_init__(self) -> None:
        self.scan_id = _safe_text(
            self.scan_id,
            MAX_SCAN_ID_LENGTH,
            field_name="scan_id",
            required=True,
        )

        self.format = _safe_enum(
            self.format,
            field_name="format",
            allowed=REPORT_FORMATS,
            default=DEFAULT_REPORT_FORMAT,
        )

        self.inline = _safe_bool(
            self.inline,
            default=False,
        )

    @classmethod
    def from_mapping(
        cls,
        value: Mapping[str, Any],
    ) -> "ReportRequest":
        mapping = _safe_mapping(
            value,
            field_name="report_request",
        )

        return cls(
            scan_id=mapping.get("scan_id", ""),
            format=mapping.get(
                "format",
                DEFAULT_REPORT_FORMAT,
            ),
            inline=mapping.get("inline", False),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "format": self.format,
            "inline": self.inline,
        }


@dataclass
class SanitizeRequest:
    """
    Request to retrieve sanitized content for a scan.
    """

    scan_id: str
    download: bool = True

    def __post_init__(self) -> None:
        self.scan_id = _safe_text(
            self.scan_id,
            MAX_SCAN_ID_LENGTH,
            field_name="scan_id",
            required=True,
        )

        self.download = _safe_bool(
            self.download,
            default=True,
        )

    @classmethod
    def from_mapping(
        cls,
        value: Mapping[str, Any],
    ) -> "SanitizeRequest":
        mapping = _safe_mapping(
            value,
            field_name="sanitize_request",
        )

        return cls(
            scan_id=mapping.get("scan_id", ""),
            download=mapping.get(
                "download",
                True,
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "download": self.download,
        }


# ---------------------------------------------------------------------------
# Response schemas
# ---------------------------------------------------------------------------


@dataclass
class FileInfo:
    """
    Normalized information about an analyzed document.
    """

    filename: str
    content_type: str = ""
    size: int = 0
    sha256: str = ""

    def __post_init__(self) -> None:
        self.filename = _safe_text(
            self.filename,
            MAX_FILENAME_LENGTH,
            field_name="filename",
            required=True,
        )

        self.content_type = _safe_text(
            self.content_type,
            MAX_CONTENT_TYPE_LENGTH,
            field_name="content_type",
        ).lower()

        self.size = _safe_int(
            self.size,
            field_name="size",
            minimum=0,
            maximum=MAX_REQUEST_BYTES,
            default=0,
        ) or 0

        self.sha256 = _safe_text(
            self.sha256,
            64,
            field_name="sha256",
        ).lower()

        if self.sha256 and (
            len(self.sha256) != 64
            or any(
                character not in "0123456789abcdef"
                for character in self.sha256
            )
        ):
            raise SchemaValidationError(
                "sha256 must be a 64-character hexadecimal digest."
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "filename": self.filename,
            "content_type": self.content_type,
            "size": self.size,
            "sha256": self.sha256,
        }


@dataclass
class Finding:
    """
    User-facing finding produced by static analysis/CDR.
    """

    category: str
    indicator: str = ""
    severity: str = "unknown"
    score: Optional[float] = None
    message: str = ""
    evidence: Optional[str] = None
    source: str = ""
    action: Optional[str] = None

    def __post_init__(self) -> None:
        self.category = _safe_text(
            self.category,
            128,
            field_name="category",
            required=True,
        ).lower()

        self.indicator = _safe_text(
            self.indicator,
            256,
            field_name="indicator",
        )

        self.severity = _safe_enum(
            self.severity,
            field_name="severity",
            allowed=SEVERITIES,
            default="unknown",
        )

        self.score = _safe_float(
            self.score,
            field_name="score",
            minimum=0.0,
            maximum=1.0,
        )

        self.message = _safe_text(
            self.message,
            MAX_MESSAGE_LENGTH,
            field_name="message",
        )

        if self.evidence is not None:
            self.evidence = _safe_text(
                self.evidence,
                MAX_MESSAGE_LENGTH,
                field_name="evidence",
            )

        self.source = _safe_text(
            self.source,
            256,
            field_name="source",
        )

        if self.action is not None:
            self.action = _safe_enum(
                self.action,
                field_name="action",
                allowed=CDR_ACTIONS,
            )

    @classmethod
    def from_mapping(
        cls,
        value: Mapping[str, Any],
    ) -> "Finding":
        mapping = _safe_mapping(
            value,
            field_name="finding",
        )

        return cls(
            category=mapping.get(
                "category",
                mapping.get("type", ""),
            ),
            indicator=mapping.get(
                "indicator",
                mapping.get("name", ""),
            ),
            severity=mapping.get(
                "severity",
                "unknown",
            ),
            score=mapping.get("score"),
            message=mapping.get(
                "message",
                mapping.get("description", ""),
            ),
            evidence=mapping.get(
                "evidence"
            ),
            source=mapping.get(
                "source",
                mapping.get("module", ""),
            ),
            action=mapping.get("action"),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "indicator": self.indicator,
            "severity": self.severity,
            "score": self.score,
            "message": self.message,
            "evidence": self.evidence,
            "source": self.source,
            "action": self.action,
        }


@dataclass
class Signal:
    """
    Normalized feature/capability signal for the web UI.
    """

    name: str
    value: Any = True
    category: str = ""
    source: str = ""
    severity: str = "unknown"

    def __post_init__(self) -> None:
        self.name = _safe_text(
            self.name,
            256,
            field_name="name",
            required=True,
        )

        self.category = _safe_text(
            self.category,
            128,
            field_name="category",
        ).lower()

        self.source = _safe_text(
            self.source,
            256,
            field_name="source",
        )

        self.severity = _safe_enum(
            self.severity,
            field_name="severity",
            allowed=SEVERITIES,
            default="unknown",
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "value": _json_safe(self.value),
            "category": self.category,
            "source": self.source,
            "severity": self.severity,
        }


@dataclass
class Stage:
    """
    Scanner pipeline stage status.
    """

    name: str
    status: str = "unknown"
    duration_ms: Optional[float] = None
    error: Optional[str] = None
    details: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.name = _safe_text(
            self.name,
            256,
            field_name="name",
            required=True,
        )

        self.status = _safe_text(
            self.status,
            64,
            field_name="status",
        ).lower() or "unknown"

        self.duration_ms = _safe_float(
            self.duration_ms,
            field_name="duration_ms",
            minimum=0.0,
        )

        if self.error is not None:
            self.error = _safe_text(
                self.error,
                MAX_ERROR_LENGTH,
                field_name="error",
            )

        self.details = _safe_mapping(
            self.details,
            field_name="details",
        )

    @classmethod
    def from_mapping(
        cls,
        value: Mapping[str, Any],
    ) -> "Stage":
        mapping = _safe_mapping(
            value,
            field_name="stage",
        )

        return cls(
            name=mapping.get("name", ""),
            status=mapping.get(
                "status",
                "unknown",
            ),
            duration_ms=mapping.get(
                "duration_ms",
                mapping.get("duration"),
            ),
            error=mapping.get("error"),
            details=mapping.get(
                "details",
                {},
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status,
            "duration_ms": self.duration_ms,
            "error": self.error,
            "details": _json_safe(self.details),
        }


@dataclass
class CDRDecision:
    """
    CDR policy decision presented to the API/UI.
    """

    action: str = "preserve"
    score: Optional[float] = None
    requires_sanitization: bool = False
    requires_review: bool = False
    rejected: bool = False
    reasons: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.action = _safe_enum(
            self.action,
            field_name="action",
            allowed=CDR_ACTIONS,
            default="preserve",
        )

        self.score = _safe_float(
            self.score,
            field_name="score",
            minimum=0.0,
            maximum=100.0,
        )

        self.requires_sanitization = _safe_bool(
            self.requires_sanitization
        )

        self.requires_review = _safe_bool(
            self.requires_review
        )

        self.rejected = _safe_bool(
            self.rejected
        )

        normalized: list[str] = []

        for reason in self.reasons[:MAX_ACTIONS]:
            text = _safe_text(
                reason,
                MAX_REASON_LENGTH,
                field_name="reason",
            )

            if text:
                normalized.append(text)

        self.reasons = normalized

    @classmethod
    def from_mapping(
        cls,
        value: Optional[Mapping[str, Any]],
    ) -> "CDRDecision":
        if value is None:
            return cls()

        mapping = _safe_mapping(
            value,
            field_name="cdr",
        )

        return cls(
            action=mapping.get(
                "action",
                mapping.get(
                    "final_action",
                    "preserve",
                ),
            ),
            score=mapping.get(
                "score",
                mapping.get("risk_score"),
            ),
            requires_sanitization=mapping.get(
                "requires_sanitization",
                False,
            ),
            requires_review=mapping.get(
                "requires_review",
                False,
            ),
            rejected=mapping.get(
                "rejected",
                mapping.get("is_rejected", False),
            ),
            reasons=_coerce_string_list(
                mapping.get(
                    "reasons",
                    [],
                ),
                "reasons",
                MAX_ACTIONS,
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "action": self.action,
            "score": self.score,
            "requires_sanitization": self.requires_sanitization,
            "requires_review": self.requires_review,
            "rejected": self.rejected,
            "reasons": list(self.reasons),
        }


@dataclass
class ModelInfo:
    """
    ML inference information exposed by the API.
    """

    available: bool = False
    probability: Optional[float] = None
    threshold: Optional[float] = None
    model_type: str = ""
    model_version: str = ""
    schema_version: str = ""

    def __post_init__(self) -> None:
        self.available = _safe_bool(
            self.available
        )

        self.probability = _safe_float(
            self.probability,
            field_name="probability",
            minimum=0.0,
            maximum=1.0,
        )

        self.threshold = _safe_float(
            self.threshold,
            field_name="threshold",
            minimum=0.0,
            maximum=1.0,
        )

        self.model_type = _safe_text(
            self.model_type,
            128,
            field_name="model_type",
        )

        self.model_version = _safe_text(
            self.model_version,
            128,
            field_name="model_version",
        )

        self.schema_version = _safe_text(
            self.schema_version,
            128,
            field_name="schema_version",
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "available": self.available,
            "probability": self.probability,
            "threshold": self.threshold,
            "model_type": self.model_type,
            "model_version": self.model_version,
            "schema_version": self.schema_version,
        }


@dataclass
class SanitizedInfo:
    """
    Metadata about CDR output without embedding the document bytes.
    """

    available: bool = False
    changed: bool = False
    size: Optional[int] = None
    sha256: str = ""
    filename: str = ""
    media_type: str = ""

    def __post_init__(self) -> None:
        self.available = _safe_bool(
            self.available
        )

        self.changed = _safe_bool(
            self.changed
        )

        self.size = _safe_int(
            self.size,
            field_name="size",
            minimum=0,
            maximum=MAX_REQUEST_BYTES,
        )

        self.sha256 = _safe_text(
            self.sha256,
            64,
            field_name="sha256",
        ).lower()

        self.filename = _safe_text(
            self.filename,
            MAX_FILENAME_LENGTH,
            field_name="filename",
        )

        self.media_type = _safe_text(
            self.media_type,
            MAX_CONTENT_TYPE_LENGTH,
            field_name="media_type",
        ).lower()

    def to_dict(self) -> dict[str, Any]:
        return {
            "available": self.available,
            "changed": self.changed,
            "size": self.size,
            "sha256": self.sha256,
            "filename": self.filename,
            "media_type": self.media_type,
        }


@dataclass
class ScanSummary:
    """
    Compact result summary for index/result pages.
    """

    scan_id: str
    status: str = "unknown"
    verdict: str = "unknown"
    malicious: bool = False
    rejected: bool = False
    requires_review: bool = False
    requires_sanitization: bool = False
    malicious_probability: Optional[float] = None
    risk_score: Optional[float] = None
    finding_count: int = 0
    feature_count: int = 0

    def __post_init__(self) -> None:
        self.scan_id = _safe_text(
            self.scan_id,
            MAX_SCAN_ID_LENGTH,
            field_name="scan_id",
            required=True,
        )

        self.status = _safe_text(
            self.status,
            64,
            field_name="status",
        ).lower() or "unknown"

        self.verdict = _safe_enum(
            self.verdict,
            field_name="verdict",
            allowed=VERDICTS,
            default="unknown",
        )

        self.malicious = _safe_bool(
            self.malicious
        )

        self.rejected = _safe_bool(
            self.rejected
        )

        self.requires_review = _safe_bool(
            self.requires_review
        )

        self.requires_sanitization = _safe_bool(
            self.requires_sanitization
        )

        self.malicious_probability = _safe_float(
            self.malicious_probability,
            field_name="malicious_probability",
            minimum=0.0,
            maximum=1.0,
        )

        self.risk_score = _safe_float(
            self.risk_score,
            field_name="risk_score",
            minimum=0.0,
            maximum=100.0,
        )

        self.finding_count = _safe_int(
            self.finding_count,
            field_name="finding_count",
            minimum=0,
            maximum=MAX_FINDINGS,
            default=0,
        ) or 0

        self.feature_count = _safe_int(
            self.feature_count,
            field_name="feature_count",
            minimum=0,
            maximum=MAX_FEATURES,
            default=0,
        ) or 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "status": self.status,
            "verdict": self.verdict,
            "malicious": self.malicious,
            "rejected": self.rejected,
            "requires_review": self.requires_review,
            "requires_sanitization": self.requires_sanitization,
            "malicious_probability": self.malicious_probability,
            "risk_score": self.risk_score,
            "finding_count": self.finding_count,
            "feature_count": self.feature_count,
        }


@dataclass
class ScanResponse:
    """
    Complete scan response returned by the API.
    """

    scan_id: str
    status: str
    verdict: str
    file: FileInfo
    summary: Optional[ScanSummary] = None
    model: Optional[ModelInfo] = None
    cdr: Optional[CDRDecision] = None
    findings: list[Finding] = field(default_factory=list)
    signals: list[Signal] = field(default_factory=list)
    stages: list[Stage] = field(default_factory=list)
    sanitized: Optional[SanitizedInfo] = None
    metadata: dict[str, Any] = field(default_factory=dict)
    created_at: str = ""

    def __post_init__(self) -> None:
        self.scan_id = _safe_text(
            self.scan_id,
            MAX_SCAN_ID_LENGTH,
            field_name="scan_id",
            required=True,
        )

        self.status = _safe_enum(
            self.status,
            field_name="status",
            allowed=SCAN_STATUSES,
            default="unknown",
        )

        self.verdict = _safe_enum(
            self.verdict,
            field_name="verdict",
            allowed=VERDICTS,
            default="unknown",
        )

        if not isinstance(self.file, FileInfo):
            if isinstance(self.file, Mapping):
                self.file = FileInfo(**dict(self.file))
            else:
                raise SchemaValidationError(
                    "file must be a FileInfo object."
                )

        if self.summary is not None and not isinstance(
            self.summary,
            ScanSummary,
        ):
            if isinstance(self.summary, Mapping):
                self.summary = ScanSummary(**dict(self.summary))
            else:
                raise SchemaValidationError(
                    "summary must be a ScanSummary object."
                )

        if self.model is not None and not isinstance(
            self.model,
            ModelInfo,
        ):
            if isinstance(self.model, Mapping):
                self.model = ModelInfo(**dict(self.model))
            else:
                raise SchemaValidationError(
                    "model must be a ModelInfo object."
                )

        if self.cdr is not None and not isinstance(
            self.cdr,
            CDRDecision,
        ):
            if isinstance(self.cdr, Mapping):
                self.cdr = CDRDecision.from_mapping(
                    self.cdr
                )
            else:
                raise SchemaValidationError(
                    "cdr must be a CDRDecision object."
                )

        self.findings = _coerce_findings(
            self.findings
        )

        self.signals = _coerce_signals(
            self.signals
        )

        self.stages = _coerce_stages(
            self.stages
        )

        if self.sanitized is not None and not isinstance(
            self.sanitized,
            SanitizedInfo,
        ):
            if isinstance(self.sanitized, Mapping):
                self.sanitized = SanitizedInfo(
                    **dict(self.sanitized)
                )
            else:
                raise SchemaValidationError(
                    "sanitized must be a SanitizedInfo object."
                )

        self.metadata = _safe_mapping(
            self.metadata,
            field_name="metadata",
        )

        self.created_at = _safe_text(
            self.created_at,
            128,
            field_name="created_at",
        ) or _utc_now()

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "scan_id": self.scan_id,
            "status": self.status,
            "verdict": self.verdict,
            "file": self.file.to_dict(),
            "findings": [
                item.to_dict()
                for item in self.findings
            ],
            "signals": [
                item.to_dict()
                for item in self.signals
            ],
            "stages": [
                item.to_dict()
                for item in self.stages
            ],
            "metadata": _json_safe(
                self.metadata
            ),
            "created_at": self.created_at,
        }

        if self.summary is not None:
            payload["summary"] = self.summary.to_dict()

        if self.model is not None:
            payload["model"] = self.model.to_dict()

        if self.cdr is not None:
            payload["cdr"] = self.cdr.to_dict()

        if self.sanitized is not None:
            payload["sanitized"] = (
                self.sanitized.to_dict()
            )

        return _json_safe(payload)


@dataclass
class ReportResponse:
    """
    Report metadata returned before binary/text download.
    """

    scan_id: str
    format: str
    filename: str
    media_type: str
    size: int
    sha256: str
    inline: bool = False
    created_at: str = ""

    def __post_init__(self) -> None:
        self.scan_id = _safe_text(
            self.scan_id,
            MAX_SCAN_ID_LENGTH,
            field_name="scan_id",
            required=True,
        )

        self.format = _safe_enum(
            self.format,
            field_name="format",
            allowed=REPORT_FORMATS,
        )

        self.filename = _safe_text(
            self.filename,
            MAX_FILENAME_LENGTH,
            field_name="filename",
            required=True,
        )

        self.media_type = _safe_text(
            self.media_type,
            MAX_CONTENT_TYPE_LENGTH,
            field_name="media_type",
        ).lower()

        self.size = _safe_int(
            self.size,
            field_name="size",
            minimum=0,
            maximum=MAX_REQUEST_BYTES,
            default=0,
        ) or 0

        self.sha256 = _safe_text(
            self.sha256,
            64,
            field_name="sha256",
        ).lower()

        if self.sha256 and len(self.sha256) != 64:
            raise SchemaValidationError(
                "sha256 must be a 64-character digest."
            )

        self.inline = _safe_bool(
            self.inline
        )

        self.created_at = _safe_text(
            self.created_at,
            128,
            field_name="created_at",
        ) or _utc_now()

    def to_dict(self) -> dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "format": self.format,
            "filename": self.filename,
            "media_type": self.media_type,
            "size": self.size,
            "sha256": self.sha256,
            "inline": self.inline,
            "created_at": self.created_at,
        }


@dataclass
class SanitizedResponse:
    """
    Metadata response for sanitized content.
    """

    scan_id: str
    filename: str
    media_type: str
    size: int
    changed: bool
    original_sha256: str
    sanitized_sha256: str
    download_available: bool = True
    created_at: str = ""

    def __post_init__(self) -> None:
        self.scan_id = _safe_text(
            self.scan_id,
            MAX_SCAN_ID_LENGTH,
            field_name="scan_id",
            required=True,
        )

        self.filename = _safe_text(
            self.filename,
            MAX_FILENAME_LENGTH,
            field_name="filename",
            required=True,
        )

        self.media_type = _safe_text(
            self.media_type,
            MAX_CONTENT_TYPE_LENGTH,
            field_name="media_type",
        ).lower()

        self.size = _safe_int(
            self.size,
            field_name="size",
            minimum=0,
            maximum=MAX_REQUEST_BYTES,
            default=0,
        ) or 0

        self.changed = _safe_bool(
            self.changed
        )

        self.original_sha256 = _safe_text(
            self.original_sha256,
            64,
            field_name="original_sha256",
        ).lower()

        self.sanitized_sha256 = _safe_text(
            self.sanitized_sha256,
            64,
            field_name="sanitized_sha256",
        ).lower()

        self.download_available = _safe_bool(
            self.download_available,
            default=True,
        )

        self.created_at = _safe_text(
            self.created_at,
            128,
            field_name="created_at",
        ) or _utc_now()

    def to_dict(self) -> dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "filename": self.filename,
            "media_type": self.media_type,
            "size": self.size,
            "changed": self.changed,
            "original_sha256": self.original_sha256,
            "sanitized_sha256": self.sanitized_sha256,
            "download_available": self.download_available,
            "created_at": self.created_at,
        }


@dataclass
class ErrorResponse:
    """
    Standard API error envelope.
    """

    error: str
    message: str
    status_code: int = 400
    request_id: Optional[str] = None
    details: Mapping[str, Any] = field(default_factory=dict)
    timestamp: str = ""

    def __post_init__(self) -> None:
        self.error = _safe_text(
            self.error,
            128,
            field_name="error",
            required=True,
        )

        self.message = _safe_text(
            self.message,
            MAX_ERROR_LENGTH,
            field_name="message",
            required=True,
        )

        self.status_code = _safe_int(
            self.status_code,
            field_name="status_code",
            minimum=400,
            maximum=599,
            default=400,
        ) or 400

        if self.request_id is not None:
            self.request_id = _safe_text(
                self.request_id,
                MAX_SCAN_ID_LENGTH,
                field_name="request_id",
            )

        self.details = _safe_mapping(
            self.details,
            field_name="details",
        )

        self.timestamp = _safe_text(
            self.timestamp,
            128,
            field_name="timestamp",
        ) or _utc_now()

    def to_dict(self) -> dict[str, Any]:
        return {
            "error": self.error,
            "message": self.message,
            "status_code": self.status_code,
            "request_id": self.request_id,
            "details": _json_safe(self.details),
            "timestamp": self.timestamp,
        }


@dataclass
class HealthResponse:
    """
    Service health/readiness response.
    """

    status: str
    service: str = MODULE_NAME
    version: str = SCHEMAS_VERSION
    dependencies: Mapping[str, Any] = field(
        default_factory=dict
    )
    timestamp: str = ""

    def __post_init__(self) -> None:
        self.status = _safe_text(
            self.status,
            64,
            field_name="status",
            required=True,
        ).lower()

        self.service = _safe_text(
            self.service,
            256,
            field_name="service",
        )

        self.version = _safe_text(
            self.version,
            128,
            field_name="version",
        )

        self.dependencies = _safe_mapping(
            self.dependencies,
            field_name="dependencies",
        )

        self.timestamp = _safe_text(
            self.timestamp,
            128,
            field_name="timestamp",
        ) or _utc_now()

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "service": self.service,
            "version": self.version,
            "dependencies": _json_safe(
                self.dependencies
            ),
            "timestamp": self.timestamp,
        }


# ---------------------------------------------------------------------------
# Coercion helpers
# ---------------------------------------------------------------------------


def _coerce_string_list(
    value: Any,
    field_name: str,
    maximum_items: int,
) -> list[str]:
    if value is None:
        return []

    if isinstance(value, str):
        return [
            _safe_text(
                value,
                MAX_REASON_LENGTH,
                field_name=field_name,
            )
        ]

    if not isinstance(
        value,
        (list, tuple, set, frozenset),
    ):
        raise SchemaValidationError(
            f"{field_name} must be an array of strings."
        )

    if len(value) > maximum_items:
        raise SchemaValidationError(
            f"{field_name} contains too many items."
        )

    result: list[str] = []

    for item in value:
        text = _safe_text(
            item,
            MAX_REASON_LENGTH,
            field_name=field_name,
        )

        if text:
            result.append(text)

    return result


def _coerce_findings(
    value: Any,
) -> list[Finding]:
    if value is None:
        return []

    if not isinstance(
        value,
        (list, tuple),
    ):
        raise SchemaValidationError(
            "findings must be an array."
        )

    if len(value) > MAX_FINDINGS:
        raise SchemaValidationError(
            f"findings exceeds {MAX_FINDINGS} items."
        )

    result: list[Finding] = []

    for item in value:
        if isinstance(item, Finding):
            result.append(item)
        elif isinstance(item, Mapping):
            result.append(
                Finding.from_mapping(item)
            )
        else:
            raise SchemaValidationError(
                "Each finding must be an object."
            )

    return result


def _coerce_signals(
    value: Any,
) -> list[Signal]:
    if value is None:
        return []

    if not isinstance(
        value,
        (list, tuple),
    ):
        raise SchemaValidationError(
            "signals must be an array."
        )

    if len(value) > MAX_SIGNALS:
        raise SchemaValidationError(
            f"signals exceeds {MAX_SIGNALS} items."
        )

    result: list[Signal] = []

    for item in value:
        if isinstance(item, Signal):
            result.append(item)
        elif isinstance(item, Mapping):
            result.append(
                Signal(
                    name=item.get(
                        "name",
                        item.get("indicator", ""),
                    ),
                    value=item.get(
                        "value",
                        True,
                    ),
                    category=item.get(
                        "category",
                        "",
                    ),
                    source=item.get(
                        "source",
                        "",
                    ),
                    severity=item.get(
                        "severity",
                        "unknown",
                    ),
                )
            )
        else:
            raise SchemaValidationError(
                "Each signal must be an object."
            )

    return result


def _coerce_stages(
    value: Any,
) -> list[Stage]:
    if value is None:
        return []

    if not isinstance(
        value,
        (list, tuple),
    ):
        raise SchemaValidationError(
            "stages must be an array."
        )

    if len(value) > MAX_STAGES:
        raise SchemaValidationError(
            f"stages exceeds {MAX_STAGES} items."
        )

    result: list[Stage] = []

    for item in value:
        if isinstance(item, Stage):
            result.append(item)
        elif isinstance(item, Mapping):
            result.append(
                Stage.from_mapping(item)
            )
        else:
            raise SchemaValidationError(
                "Each stage must be an object."
            )

    return result


# ---------------------------------------------------------------------------
# Factory helpers
# ---------------------------------------------------------------------------


def make_scan_request(
    *,
    filename: str,
    content_type: str = "",
    mode: str = DEFAULT_SCAN_MODE,
    include_report: bool = True,
    report_format: str = DEFAULT_REPORT_FORMAT,
    include_sanitized: bool = False,
    include_features: bool = True,
    include_evidence: bool = True,
    include_explanations: bool = True,
    metadata: Optional[Mapping[str, Any]] = None,
) -> ScanRequest:
    """
    Construct a validated scan request.
    """

    return ScanRequest(
        filename=filename,
        content_type=content_type,
        options=ScanOptions(
            mode=mode,
            include_report=include_report,
            report_format=report_format,
            include_sanitized=include_sanitized,
            include_features=include_features,
            include_evidence=include_evidence,
            include_explanations=include_explanations,
        ),
        metadata=dict(metadata or {}),
    )


def make_file_info(
    *,
    filename: str,
    content_type: str = "",
    size: int = 0,
    sha256: str = "",
) -> FileInfo:
    return FileInfo(
        filename=filename,
        content_type=content_type,
        size=size,
        sha256=sha256,
    )


def make_error(
    *,
    error: str,
    message: str,
    status_code: int = 400,
    request_id: Optional[str] = None,
    details: Optional[Mapping[str, Any]] = None,
) -> ErrorResponse:
    return ErrorResponse(
        error=error,
        message=message,
        status_code=status_code,
        request_id=request_id,
        details=dict(details or {}),
    )


# ---------------------------------------------------------------------------
# Scanner-result normalization
# ---------------------------------------------------------------------------


def _mapping(value: Any) -> Mapping[str, Any]:
    if isinstance(value, Mapping):
        return value

    if is_dataclass(value) and not isinstance(value, type):
        try:
            result = asdict(value)

            if isinstance(result, Mapping):
                return result
        except Exception:
            pass

    return {}


def _first(
    mapping: Mapping[str, Any],
    *keys: str,
    default: Any = None,
) -> Any:
    for key in keys:
        if key in mapping:
            value = mapping[key]

            if value is not None:
                return value

    return default


def _extract_file_info(
    result: Mapping[str, Any],
) -> FileInfo:
    file_mapping = _mapping(
        _first(
            result,
            "file",
            "document",
            "input",
            default={},
        )
    )

    filename = _first(
        file_mapping,
        "filename",
        "name",
        default=_first(
            result,
            "filename",
            "name",
            default="document",
        ),
    )

    content_type = _first(
        file_mapping,
        "content_type",
        "mime_type",
        "mimetype",
        default=_first(
            result,
            "content_type",
            "mime_type",
            default="",
        ),
    )

    size = _first(
        file_mapping,
        "size",
        "file_size",
        default=_first(
            result,
            "size",
            "file_size",
            default=0,
        ),
    )

    sha256 = _first(
        file_mapping,
        "sha256",
        "hash",
        "file_hash",
        default=_first(
            result,
            "sha256",
            "file_hash",
            default="",
        ),
    )

    return FileInfo(
        filename=filename,
        content_type=content_type,
        size=size,
        sha256=sha256,
    )


def _extract_model_info(
    result: Mapping[str, Any],
) -> Optional[ModelInfo]:
    mapping = _mapping(
        result.get("model")
    )

    if not mapping:
        mapping = result

    probability = _first(
        mapping,
        "probability",
        "malicious_probability",
        "model_probability",
        default=None,
    )

    available = _first(
        mapping,
        "available",
        default=probability is not None,
    )

    model_type = _first(
        mapping,
        "model_type",
        "type",
        default="",
    )

    model_version = _first(
        mapping,
        "model_version",
        "version",
        default="",
    )

    schema_version = _first(
        mapping,
        "schema_version",
        default="",
    )

    threshold = _first(
        mapping,
        "threshold",
        "decision_threshold",
        default=None,
    )

    if (
        probability is None
        and not available
        and not model_type
        and not model_version
        and threshold is None
    ):
        return None

    return ModelInfo(
        available=available,
        probability=probability,
        threshold=threshold,
        model_type=model_type,
        model_version=model_version,
        schema_version=schema_version,
    )


def _extract_cdr(
    result: Mapping[str, Any],
) -> Optional[CDRDecision]:
    mapping = _mapping(
        _first(
            result,
            "cdr",
            "policy",
            "decision",
            default=None,
        )
    )

    if not mapping:
        action = _first(
            result,
            "action",
            "cdr_action",
            "final_action",
            default=None,
        )

        if action is None:
            return None

        mapping = {
            "action": action,
            "score": _first(
                result,
                "risk_score",
                "score",
                default=None,
            ),
            "requires_sanitization": _first(
                result,
                "requires_sanitization",
                default=False,
            ),
            "requires_review": _first(
                result,
                "requires_review",
                default=False,
            ),
            "rejected": _first(
                result,
                "rejected",
                "is_rejected",
                default=False,
            ),
            "reasons": _first(
                result,
                "reasons",
                "decision_reasons",
                default=[],
            ),
        }

    return CDRDecision.from_mapping(mapping)


def _extract_findings(
    result: Mapping[str, Any],
) -> list[Finding]:
    raw = _first(
        result,
        "findings",
        "detections",
        "issues",
        "alerts",
        default=[],
    )

    if isinstance(raw, Mapping):
        raw = list(raw.values())

    return _coerce_findings(raw)


def _extract_signals(
    result: Mapping[str, Any],
) -> list[Signal]:
    raw = _first(
        result,
        "signals",
        "features",
        "indicators",
        default=[],
    )

    if isinstance(raw, Mapping):
        items: list[dict[str, Any]] = []

        for name, value in list(raw.items())[:MAX_SIGNALS]:
            items.append(
                {
                    "name": str(name),
                    "value": value,
                }
            )

        raw = items

    return _coerce_signals(raw)


def _extract_stages(
    result: Mapping[str, Any],
) -> list[Stage]:
    raw = _first(
        result,
        "stages",
        "pipeline",
        default=[],
    )

    if isinstance(raw, Mapping):
        items: list[dict[str, Any]] = []

        for name, value in list(raw.items())[:MAX_STAGES]:
            if isinstance(value, Mapping):
                item = dict(value)
                item.setdefault(
                    "name",
                    str(name),
                )
            else:
                item = {
                    "name": str(name),
                    "status": str(value),
                }

            items.append(item)

        raw = items

    return _coerce_stages(raw)


# ---------------------------------------------------------------------------
# Result factories
# ---------------------------------------------------------------------------


def scan_response_from_result(
    result: Any,
    *,
    scan_id: Optional[str] = None,
    mode: str = DEFAULT_SCAN_MODE,
) -> ScanResponse:
    """
    Convert a scanner/service result into the stable API response schema.
    """

    mapping = _mapping(result)

    if not mapping:
        raise SchemaValidationError(
            "Scanner result must be a mapping or dataclass."
        )

    effective_scan_id = scan_id or _first(
        mapping,
        "scan_id",
        "id",
        default="",
    )

    if not effective_scan_id:
        raise SchemaValidationError(
            "Scanner result does not contain a scan_id."
        )

    status = _safe_text(
        _first(
            mapping,
            "status",
            "scan_status",
            default="completed",
        ),
        64,
        field_name="status",
    ).lower()

    if status not in SCAN_STATUSES:
        status = "unknown"

    verdict = _safe_text(
        _first(
            mapping,
            "verdict",
            "disposition",
            "classification",
            default="unknown",
        ),
        64,
        field_name="verdict",
    ).lower()

    if verdict not in VERDICTS:
        verdict = "unknown"

    file_info = _extract_file_info(mapping)

    findings = _extract_findings(mapping)
    signals = _extract_signals(mapping)
    stages = _extract_stages(mapping)

    model = _extract_model_info(mapping)
    cdr = _extract_cdr(mapping)

    malicious_probability: Optional[float] = None

    if model is not None:
        malicious_probability = model.probability

    malicious = verdict in {
        "malicious",
        "blocked",
        "rejected",
    }

    rejected = verdict in {
        "rejected",
        "blocked",
    }

    requires_review = bool(
        _first(
            mapping,
            "requires_review",
            "review_required",
            "needs_review",
            default=(
                cdr.requires_review
                if cdr is not None
                else False
            ),
        )
    )

    requires_sanitization = bool(
        _first(
            mapping,
            "requires_sanitization",
            "sanitization_required",
            "needs_sanitization",
            default=(
                cdr.requires_sanitization
                if cdr is not None
                else False
            ),
        )
    )

    risk_score = _first(
        mapping,
        "risk_score",
        "score",
        default=(
            cdr.score
            if cdr is not None
            else None
        ),
    )

    summary = ScanSummary(
        scan_id=effective_scan_id,
        status=status,
        verdict=verdict,
        malicious=malicious,
        rejected=rejected,
        requires_review=requires_review,
        requires_sanitization=requires_sanitization,
        malicious_probability=malicious_probability,
        risk_score=risk_score,
        finding_count=len(findings),
        feature_count=len(signals),
    )

    sanitized_mapping = _mapping(
        _first(
            mapping,
            "sanitized",
            "sanitization",
            default=None,
        )
    )

    sanitized: Optional[SanitizedInfo] = None

    if sanitized_mapping:
        sanitized = SanitizedInfo(
            available=_first(
                sanitized_mapping,
                "available",
                default=True,
            ),
            changed=_first(
                sanitized_mapping,
                "changed",
                default=False,
            ),
            size=_first(
                sanitized_mapping,
                "size",
                default=None,
            ),
            sha256=_first(
                sanitized_mapping,
                "sha256",
                "sanitized_sha256",
                default="",
            ),
            filename=_first(
                sanitized_mapping,
                "filename",
                default="",
            ),
            media_type=_first(
                sanitized_mapping,
                "media_type",
                default="",
            ),
        )

    metadata = _safe_mapping(
        _first(
            mapping,
            "metadata",
            default={},
        ),
        field_name="metadata",
    )

    created_at = _safe_text(
        _first(
            mapping,
            "created_at",
            "timestamp",
            default="",
        ),
        128,
        field_name="created_at",
    )

    return ScanResponse(
        scan_id=effective_scan_id,
        status=status,
        verdict=verdict,
        file=file_info,
        summary=summary,
        model=model,
        cdr=cdr,
        findings=findings,
        signals=signals,
        stages=stages,
        sanitized=sanitized,
        metadata={
            **metadata,
            "mode": mode,
        },
        created_at=created_at,
    )


# ---------------------------------------------------------------------------
# JSON serialization
# ---------------------------------------------------------------------------


def to_dict(value: Any) -> Any:
    """
    Convert any supported schema object to JSON-safe data.
    """

    if hasattr(value, "to_dict") and callable(
        getattr(value, "to_dict")
    ):
        try:
            return _json_safe(
                value.to_dict()
            )
        except Exception as exc:
            raise SchemaSerializationError(
                f"Unable to serialize object: {exc}"
            ) from exc

    return _json_safe(value)


def to_json(
    value: Any,
    *,
    indent: Optional[int] = 2,
) -> str:
    """
    Serialize a schema object as JSON.
    """

    try:
        return json.dumps(
            to_dict(value),
            ensure_ascii=False,
            indent=indent,
            sort_keys=True,
            separators=None if indent else (",", ":"),
        )
    except (TypeError, ValueError) as exc:
        raise SchemaSerializationError(
            f"Unable to serialize schema: {exc}"
        ) from exc


def validate_json_object(
    value: Any,
    *,
    field_name: str = "object",
) -> dict[str, Any]:
    """
    Validate that a value is a JSON object.
    """

    if not isinstance(value, Mapping):
        raise SchemaValidationError(
            f"{field_name} must be a JSON object."
        )

    result = _json_safe(value)

    if not isinstance(result, dict):
        raise SchemaValidationError(
            f"{field_name} could not be normalized."
        )

    return result


# ---------------------------------------------------------------------------
# Convenience parsers
# ---------------------------------------------------------------------------


def parse_scan_request(
    payload: Mapping[str, Any],
) -> ScanRequest:
    return ScanRequest.from_mapping(payload)


def parse_report_request(
    payload: Mapping[str, Any],
) -> ReportRequest:
    return ReportRequest.from_mapping(payload)


def parse_sanitize_request(
    payload: Mapping[str, Any],
) -> SanitizeRequest:
    return SanitizeRequest.from_mapping(payload)


def parse_options(
    payload: Optional[Mapping[str, Any]],
) -> ScanOptions:
    return ScanOptions.from_mapping(payload)


# ---------------------------------------------------------------------------
# Schema metadata
# ---------------------------------------------------------------------------


def schema_metadata() -> dict[str, Any]:
    """
    Return machine-readable API schema metadata.
    """

    return {
        "module": MODULE_NAME,
        "version": SCHEMAS_VERSION,
        "request": {
            "scan_modes": sorted(SCAN_MODES),
            "report_formats": sorted(REPORT_FORMATS),
            "max_input_bytes": MAX_REQUEST_BYTES,
        },
        "response": {
            "statuses": sorted(SCAN_STATUSES),
            "verdicts": sorted(VERDICTS),
            "severities": sorted(SEVERITIES),
            "cdr_actions": sorted(CDR_ACTIONS),
        },
        "limits": {
            "max_filename_length": MAX_FILENAME_LENGTH,
            "max_findings": MAX_FINDINGS,
            "max_signals": MAX_SIGNALS,
            "max_stages": MAX_STAGES,
            "max_features": MAX_FEATURES,
        },
    }


def validate_scan_response(
    response: ScanResponse,
) -> ScanResponse:
    """
    Re-run response validation and return the normalized response.
    """

    if not isinstance(response, ScanResponse):
        raise SchemaValidationError(
            "response must be a ScanResponse."
        )

    return ScanResponse(
        scan_id=response.scan_id,
        status=response.status,
        verdict=response.verdict,
        file=response.file,
        summary=response.summary,
        model=response.model,
        cdr=response.cdr,
        findings=response.findings,
        signals=response.signals,
        stages=response.stages,
        sanitized=response.sanitized,
        metadata=response.metadata,
        created_at=response.created_at,
    )


# ---------------------------------------------------------------------------
# Aliases
# ---------------------------------------------------------------------------


parse_request = parse_scan_request
parse_report = parse_report_request
parse_sanitize = parse_sanitize_request
response_from_result = scan_response_from_result
serialize = to_dict
serialize_json = to_json
metadata = schema_metadata


# ---------------------------------------------------------------------------
# PUBLIC APIs
# ---------------------------------------------------------------------------

__all__ = [
    "MODULE_NAME",
    "SCHEMAS_VERSION",
    "MAX_FILENAME_LENGTH",
    "MAX_CONTENT_TYPE_LENGTH",
    "MAX_SCAN_ID_LENGTH",
    "MAX_REQUEST_BYTES",
    "DEFAULT_SCAN_MODE",
    "DEFAULT_REPORT_FORMAT",
    "SCAN_MODES",
    "REPORT_FORMATS",
    "VERDICTS",
    "SEVERITIES",
    "CDR_ACTIONS",
    "SCAN_STATUSES",
    "SchemaError",
    "SchemaValidationError",
    "SchemaSerializationError",
    "ScanMode",
    "ReportFormat",
    "ScanStatus",
    "Verdict",
    "Severity",
    "CDRAction",
    "ScanOptions",
    "ScanRequest",
    "ReportRequest",
    "SanitizeRequest",
    "FileInfo",
    "Finding",
    "Signal",
    "Stage",
    "CDRDecision",
    "ModelInfo",
    "SanitizedInfo",
    "ScanSummary",
    "ScanResponse",
    "ReportResponse",
    "SanitizedResponse",
    "ErrorResponse",
    "HealthResponse",
    "make_scan_request",
    "make_file_info",
    "make_error",
    "scan_response_from_result",
    "validate_scan_response",
    "to_dict",
    "to_json",
    "validate_json_object",
    "parse_scan_request",
    "parse_report_request",
    "parse_sanitize_request",
    "parse_options",
    "schema_metadata",
    "parse_request",
    "parse_report",
    "parse_sanitize",
    "response_from_result",
    "serialize",
    "serialize_json",
    "metadata",
]