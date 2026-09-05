"""
pharos-cdr - Static document scanning pipeline.

This module orchestrates the defensive analysis pipeline:

    input
      │
      ├── ingestion / file validation
      ├── file-type identification
      ├── feature extraction
      ├── ML prediction
      ├── CDR detection
      ├── policy evaluation
      └── optional sanitization + integrity verification
              │
              ▼
           ScanResult

Security model
--------------
- Static analysis only.
- Never executes VBA, XLM, JavaScript, VBScript, PowerShell, shell commands,
  embedded executables, DDE, or other active content.
- Never launches processes.
- Never resolves or contacts URLs.
- Never downloads remote resources.
- Never loads native libraries.
- Sanitization is performed only when explicitly requested.
- All byte processing is bounded.
- Results are deterministic except for model implementations that may
  intentionally provide probabilistic predictions.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import tempfile
from dataclasses import asdict, dataclass, field
from enum import Enum
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
    Union,
)
from zipfile import BadZipFile, ZipFile

MODULE_NAME = "pharos_cdr.pipeline.scanner"
SCANNER_VERSION = "1.0.0"

MAX_INPUT_BYTES = 100 * 1024 * 1024
MAX_ANALYSIS_TEXT = 25 * 1024 * 1024
MAX_FINDINGS = 20_000
MAX_FEATURES = 100_000
MAX_RESULT_JSON_BYTES = 25 * 1024 * 1024

DEFAULT_MODEL_THRESHOLD = 0.50

OOXML_EXTENSIONS = {
    ".docx",
    ".docm",
    ".dotx",
    ".dotm",
    ".xlsx",
    ".xlsm",
    ".xltx",
    ".xltm",
    ".pptx",
    ".pptm",
    ".potx",
    ".potm",
    ".ppsx",
    ".ppsm",
}

OLE_EXTENSIONS = {
    ".doc",
    ".dot",
    ".xls",
    ".xlt",
    ".ppt",
    ".pps",
    ".pot",
    ".pub",
}

SCRIPT_EXTENSIONS = {
    ".js",
    ".jse",
    ".vbs",
    ".vbe",
    ".ps1",
    ".psm1",
    ".bat",
    ".cmd",
    ".sh",
}

PDF_EXTENSIONS = {".pdf"}
RTF_EXTENSIONS = {".rtf"}
TEXT_EXTENSIONS = {
    ".txt",
    ".csv",
    ".log",
    ".xml",
    ".json",
    ".html",
    ".htm",
}


class ScanError(Exception):
    """Base scanner exception."""


class ScanInputError(ScanError):
    """Raised when scan input is invalid."""


class ScanLimitError(ScanError):
    """Raised when a configured scan limit is exceeded."""


class ScanStageError(ScanError):
    """Raised when an individual pipeline stage fails."""


class ScanStatus(str, Enum):
    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    SANITIZED = "sanitized"
    REJECTED = "rejected"
    ERROR = "error"


class ScanVerdict(str, Enum):
    ALLOW = "allow"
    REVIEW = "review"
    SANITIZE = "sanitize"
    REJECT = "reject"


class ScanStage(str, Enum):
    INGESTION = "ingestion"
    FILE_TYPE = "file_type"
    EXTRACTION = "extraction"
    ML = "ml"
    CDR_DETECTION = "cdr_detection"
    POLICY = "policy"
    SANITIZATION = "sanitization"
    INTEGRITY = "integrity"


@dataclass(frozen=True)
class StageResult:
    """Result of one pipeline stage."""

    stage: ScanStage
    success: bool
    duration_ms: Optional[float] = None
    summary: Dict[str, Any] = field(default_factory=dict)
    output: Optional[Dict[str, Any]] = None
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "stage": self.stage.value,
            "success": self.success,
            "duration_ms": self.duration_ms,
            "summary": dict(self.summary),
            "output": self.output,
            "error": self.error,
        }


@dataclass(frozen=True)
class ScanInput:
    """Normalized immutable representation of scan input."""

    source_name: str
    source_path: Optional[str]
    size: int
    sha256: str
    extension: str
    content: bytes

    def to_dict(self, *, include_content: bool = False) -> Dict[str, Any]:
        result = {
            "source_name": self.source_name,
            "source_path": self.source_path,
            "size": self.size,
            "sha256": self.sha256,
            "extension": self.extension,
        }

        if include_content:
            result["content"] = self.content

        return result


@dataclass
class ScanConfig:
    """
    Scanner configuration.

    The scanner is deliberately conservative by default. Static analysis
    remains enabled while potentially destructive CDR operations are opt-in.
    """

    run_extraction: bool = True
    run_ml: bool = True
    run_cdr_detection: bool = True
    run_policy: bool = True

    sanitize: bool = False
    verify_sanitized: bool = True
    strict_integrity: bool = True

    fail_closed: bool = True
    continue_on_stage_error: bool = False

    model_threshold: float = DEFAULT_MODEL_THRESHOLD

    include_raw_stage_outputs: bool = True
    include_feature_vector: bool = True
    include_member_metadata: bool = True

    max_input_bytes: int = MAX_INPUT_BYTES
    max_features: int = MAX_FEATURES
    max_findings: int = MAX_FINDINGS

    def normalized(self) -> "ScanConfig":
        threshold = float(self.model_threshold)

        if not 0.0 <= threshold <= 1.0:
            raise ScanInputError("model_threshold must be between 0 and 1.")

        if self.max_input_bytes <= 0:
            raise ScanInputError("max_input_bytes must be positive.")

        if self.max_features <= 0:
            raise ScanInputError("max_features must be positive.")

        if self.max_findings <= 0:
            raise ScanInputError("max_findings must be positive.")

        return ScanConfig(
            run_extraction=bool(self.run_extraction),
            run_ml=bool(self.run_ml),
            run_cdr_detection=bool(self.run_cdr_detection),
            run_policy=bool(self.run_policy),
            sanitize=bool(self.sanitize),
            verify_sanitized=bool(self.verify_sanitized),
            strict_integrity=bool(self.strict_integrity),
            fail_closed=bool(self.fail_closed),
            continue_on_stage_error=bool(self.continue_on_stage_error),
            model_threshold=threshold,
            include_raw_stage_outputs=bool(self.include_raw_stage_outputs),
            include_feature_vector=bool(self.include_feature_vector),
            include_member_metadata=bool(self.include_member_metadata),
            max_input_bytes=int(self.max_input_bytes),
            max_features=int(self.max_features),
            max_findings=int(self.max_findings),
        )


@dataclass
class ScanResult:
    """Complete result returned by the scanner."""

    scan_id: str
    scanner_version: str
    status: ScanStatus
    verdict: ScanVerdict

    input: ScanInput

    file_type: Optional[Dict[str, Any]] = None
    features: Dict[str, float] = field(default_factory=dict)
    prediction: Optional[Dict[str, Any]] = None

    cdr_detection: Optional[Dict[str, Any]] = None
    policy: Optional[Dict[str, Any]] = None

    sanitized_content: Optional[bytes] = None
    sanitized_sha256: Optional[str] = None
    integrity: Optional[Dict[str, Any]] = None

    findings: List[Dict[str, Any]] = field(default_factory=list)
    stages: List[StageResult] = field(default_factory=list)

    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(
        self,
        *,
        include_content: bool = False,
        include_features: bool = True,
    ) -> Dict[str, Any]:
        result = {
            "scan_id": self.scan_id,
            "scanner_version": self.scanner_version,
            "status": self.status.value,
            "verdict": self.verdict.value,
            "input": self.input.to_dict(include_content=include_content),
            "file_type": self.file_type,
            "features": (dict(self.features) if include_features else {}),
            "prediction": self.prediction,
            "cdr_detection": self.cdr_detection,
            "policy": self.policy,
            "sanitized_sha256": self.sanitized_sha256,
            "integrity": self.integrity,
            "findings": list(self.findings),
            "stages": [stage.to_dict() for stage in self.stages],
            "errors": list(self.errors),
            "warnings": list(self.warnings),
            "metadata": dict(self.metadata),
        }

        if include_content:
            result["sanitized_content"] = self.sanitized_content

        return result

    def to_json(
        self,
        *,
        indent: Optional[int] = 2,
        include_features: bool = True,
    ) -> str:
        return json.dumps(
            self.to_dict(
                include_content=False,
                include_features=include_features,
            ),
            indent=indent,
            sort_keys=True,
            ensure_ascii=False,
        )


@dataclass
class _StageContext:
    input: ScanInput
    config: ScanConfig

    file_type: Optional[Dict[str, Any]] = None
    extraction: Optional[Dict[str, Any]] = None
    features: Dict[str, float] = field(default_factory=dict)

    prediction: Optional[Dict[str, Any]] = None
    cdr_detection: Optional[Dict[str, Any]] = None
    policy: Optional[Dict[str, Any]] = None

    sanitized_content: Optional[bytes] = None
    integrity: Optional[Dict[str, Any]] = None

    stages: List[StageResult] = field(default_factory=list)
    findings: List[Dict[str, Any]] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


def _safe_text(value: Any, limit: int = 8192) -> str:
    if value is None:
        return ""

    try:
        text = str(value)
    except Exception:
        return ""

    return text[:limit]


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError, OverflowError):
        return default

    if number != number:
        return default

    if number in (float("inf"), float("-inf")):
        return default

    return number


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError, OverflowError):
        return default


def _json_safe(value: Any, depth: int = 0) -> Any:
    """
    Convert arbitrary stage output into bounded JSON-compatible data.
    """
    if depth > 12:
        return "<max-depth>"

    if value is None:
        return None

    if isinstance(value, (str, int, float, bool)):
        return value

    if isinstance(value, bytes):
        return {
            "type": "bytes",
            "size": len(value),
            "sha256": hashlib.sha256(value).hexdigest(),
        }

    if isinstance(value, bytearray):
        return {
            "type": "bytes",
            "size": len(value),
            "sha256": hashlib.sha256(bytes(value)).hexdigest(),
        }

    if isinstance(value, Mapping):
        result: Dict[str, Any] = {}

        for index, (key, item) in enumerate(value.items()):
            if index >= 10_000:
                break

            result[_safe_text(key, 512)] = _json_safe(
                item,
                depth + 1,
            )

        return result

    if isinstance(value, (list, tuple, set)):
        result = []

        for index, item in enumerate(value):
            if index >= 10_000:
                break

            result.append(
                _json_safe(
                    item,
                    depth + 1,
                )
            )

        return result

    if hasattr(value, "to_dict"):
        try:
            return _json_safe(
                value.to_dict(),
                depth + 1,
            )
        except Exception:
            pass

    if hasattr(value, "__dataclass_fields__"):
        try:
            return _json_safe(
                asdict(value),
                depth + 1,
            )
        except Exception:
            pass

    return _safe_text(value, 4096)


def _flatten_numeric_features(
    value: Any,
    *,
    prefix: str = "",
    output: Optional[Dict[str, float]] = None,
    max_features: int = MAX_FEATURES,
    depth: int = 0,
) -> Dict[str, float]:
    """
    Flatten a feature mapping while accepting output from different
    extraction implementations.
    """
    if output is None:
        output = {}

    if len(output) >= max_features:
        return output

    if depth > 12:
        return output

    if isinstance(value, Mapping):
        for key, item in value.items():
            if len(output) >= max_features:
                break

            name = _safe_text(key, 512).strip()

            if not name:
                continue

            child_prefix = f"{prefix}.{name}" if prefix else name

            if isinstance(
                item,
                Mapping,
            ):
                _flatten_numeric_features(
                    item,
                    prefix=child_prefix,
                    output=output,
                    max_features=max_features,
                    depth=depth + 1,
                )
                continue

            if isinstance(
                item,
                (list, tuple),
            ):
                for index, element in enumerate(item):
                    if len(output) >= max_features:
                        break

                    numeric = _safe_float(
                        element,
                        default=float("nan"),
                    )

                    if numeric != numeric:
                        continue

                    output[f"{child_prefix}.{index}"] = numeric

                continue

            numeric = _safe_float(
                item,
                default=float("nan"),
            )

            if numeric != numeric:
                continue

            output[child_prefix] = numeric

        return output

    if isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            if len(output) >= max_features:
                break

            _flatten_numeric_features(
                item,
                prefix=f"{prefix}.{index}" if prefix else str(index),
                output=output,
                max_features=max_features,
                depth=depth + 1,
            )

        return output

    numeric = _safe_float(
        value,
        default=float("nan"),
    )

    if numeric == numeric and prefix:
        output[prefix] = numeric

    return output


def _extract_feature_container(
    extraction: Any,
) -> Any:
    if not isinstance(extraction, Mapping):
        return extraction

    for key in (
        "feature_vector",
        "features",
        "feature_values",
        "vector",
    ):
        if key in extraction:
            return extraction[key]

    return extraction


def _extract_findings(
    value: Any,
    *,
    source: str,
    max_findings: int,
) -> List[Dict[str, Any]]:
    """
    Normalize findings from heterogeneous analyzers.
    """
    result: List[Dict[str, Any]] = []

    if value is None:
        return result

    if isinstance(value, Mapping):
        if any(
            key in value
            for key in (
                "severity",
                "category",
                "indicator",
                "message",
                "finding",
                "code",
            )
        ):
            item = _json_safe(value)

            if isinstance(item, Mapping):
                normalized = dict(item)
                normalized.setdefault(
                    "source",
                    source,
                )
                result.append(normalized)

            return result

        for key in (
            "findings",
            "evidence",
            "alerts",
            "detections",
            "indicators",
            "records",
            "results",
        ):
            if key in value:
                result.extend(
                    _extract_findings(
                        value[key],
                        source=source,
                        max_findings=max_findings,
                    )
                )

                if len(result) >= max_findings:
                    break

        return result[:max_findings]

    if isinstance(value, (list, tuple)):
        for item in value:
            result.extend(
                _extract_findings(
                    item,
                    source=source,
                    max_findings=max_findings,
                )
            )

            if len(result) >= max_findings:
                break

        return result[:max_findings]

    text = _safe_text(value)

    if text:
        result.append(
            {
                "source": source,
                "message": text,
            }
        )

    return result[:max_findings]


def _hash_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _make_scan_id(
    digest: str,
    *,
    scanner_version: str = SCANNER_VERSION,
) -> str:
    material = (f"{scanner_version}:{digest}").encode("utf-8")

    return hashlib.sha256(material).hexdigest()[:32]


def _read_input(
    source: Union[
        bytes,
        bytearray,
        memoryview,
        str,
        os.PathLike,
        ScanInput,
    ],
    *,
    max_input_bytes: int,
    source_name: Optional[str] = None,
) -> ScanInput:
    if isinstance(source, ScanInput):
        if source.size > max_input_bytes:
            raise ScanInputError("ScanInput exceeds configured input size.")

        return source

    content: bytes
    path: Optional[str] = None
    name = source_name or "input"

    if isinstance(source, bytes):
        content = source

    elif isinstance(source, bytearray):
        content = bytes(source)

    elif isinstance(source, memoryview):
        content = source.tobytes()

    elif isinstance(source, os.PathLike):
        path_obj = Path(source)

        try:
            stat = path_obj.stat()
        except OSError as exc:
            raise ScanInputError(f"Unable to inspect input file: {exc}") from exc

        if stat.st_size > max_input_bytes:
            raise ScanLimitError("Input file exceeds configured maximum size.")

        try:
            content = path_obj.read_bytes()
        except OSError as exc:
            raise ScanInputError(f"Unable to read input file: {exc}") from exc

        path = str(path_obj)
        name = source_name or path_obj.name

    elif isinstance(source, str):
        path_obj = Path(source)

        if not path_obj.exists():
            raise ScanInputError(f"Input file does not exist: {source}")

        if not path_obj.is_file():
            raise ScanInputError(f"Input path is not a regular file: {source}")

        return _read_input(
            path_obj,
            max_input_bytes=max_input_bytes,
            source_name=source_name,
        )

    else:
        raise ScanInputError(f"Unsupported scan input type: {type(source).__name__}")

    if len(content) > max_input_bytes:
        raise ScanLimitError("Input exceeds configured maximum size.")

    extension = Path(name).suffix.lower() if name else ""

    return ScanInput(
        source_name=name,
        source_path=path,
        size=len(content),
        sha256=_hash_bytes(content),
        extension=extension,
        content=content,
    )


def _detect_basic_file_type(
    scan_input: ScanInput,
) -> Dict[str, Any]:
    """
    Lightweight fallback type detector.

    If the project's dedicated ingestion.file_type module is available,
    the scanner uses it first and supplements the result with this detector.
    """
    data = scan_input.content
    extension = scan_input.extension

    detected = "unknown"
    confidence = 0.0
    mime = None

    if data.startswith(b"PK\x03\x04"):
        detected = "zip"
        confidence = 0.90
        mime = "application/zip"

        if extension in OOXML_EXTENSIONS:
            detected = "ooxml"
            confidence = 0.98
            mime = "application/" "vnd.openxmlformats-officedocument"

    elif data.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        detected = "ole"
        confidence = 0.99
        mime = "application/x-ole-storage"

    elif data.startswith(b"%PDF-"):
        detected = "pdf"
        confidence = 0.99
        mime = "application/pdf"

    elif data.startswith(b"{\\rtf"):
        detected = "rtf"
        confidence = 0.99
        mime = "application/rtf"

    elif data.startswith(b"MZ"):
        detected = "pe"
        confidence = 0.85
        mime = "application/vnd.microsoft.portable-executable"

    elif data.startswith(b"\x7fELF"):
        detected = "elf"
        confidence = 0.99
        mime = "application/x-elf"

    elif extension in SCRIPT_EXTENSIONS:
        detected = "script"
        confidence = 0.75
        mime = "text/plain"

    elif extension in TEXT_EXTENSIONS:
        detected = "text"
        confidence = 0.70
        mime = "text/plain"

    if extension in OLE_EXTENSIONS and detected == "unknown":
        detected = "ole"
        confidence = 0.70

    if extension in PDF_EXTENSIONS and detected == "unknown":
        detected = "pdf"
        confidence = 0.70

    if extension in RTF_EXTENSIONS and detected == "unknown":
        detected = "rtf"
        confidence = 0.70

    return {
        "detected_type": detected,
        "confidence": confidence,
        "mime_type": mime,
        "extension": extension,
        "size": scan_input.size,
        "sha256": scan_input.sha256,
    }


def _call_file_type_module(
    scan_input: ScanInput,
) -> Optional[Dict[str, Any]]:
    try:
        from ..ingestion import file_type
    except Exception:
        return None

    candidates = (
        "detect_file_type",
        "identify_file_type",
        "analyze_file_type",
        "classify_file_type",
        "detect",
        "analyze",
    )

    for name in candidates:
        function = getattr(
            file_type,
            name,
            None,
        )

        if not callable(function):
            continue

        for argument in (
            scan_input.content,
            io.BytesIO(scan_input.content),
        ):
            try:
                output = function(argument)

                return _json_safe(output)

            except (
                TypeError,
                AttributeError,
                ValueError,
            ):
                continue
            except Exception:
                return None

    return None


def _run_file_type(
    context: _StageContext,
) -> Dict[str, Any]:
    fallback = _detect_basic_file_type(context.input)

    dedicated = _call_file_type_module(context.input)

    if isinstance(dedicated, Mapping):
        result = dict(fallback)
        result.update({str(key): value for key, value in dedicated.items()})
        return result

    return fallback


def _call_feature_pipeline(
    scan_input: ScanInput,
) -> Optional[Any]:
    try:
        from ..extraction import feature_pipeline
    except Exception:
        return None

    candidates = (
        "extract_features",
        "analyze_file",
        "analyze",
        "extract",
        "run",
    )

    for name in candidates:
        function = getattr(
            feature_pipeline,
            name,
            None,
        )

        if not callable(function):
            continue

        attempts = (
            (scan_input.content,),
            (scan_input.content, scan_input.source_name),
        )

        for args in attempts:
            try:
                return function(*args)
            except (
                TypeError,
                AttributeError,
                ValueError,
            ):
                continue
            except Exception:
                return None

    return None


def _run_extraction(
    context: _StageContext,
) -> Dict[str, Any]:
    output = _call_feature_pipeline(context.input)

    if output is None:
        return {
            "feature_vector": {},
            "features": {},
            "fallback": True,
        }

    normalized = _json_safe(output)

    if isinstance(normalized, Mapping):
        return dict(normalized)

    return {
        "analysis": normalized,
    }


def _run_ml_prediction(
    context: _StageContext,
) -> Optional[Dict[str, Any]]:
    if not context.features:
        return None

    try:
        from ..ml import predict
    except Exception as exc:
        if context.config.fail_closed:
            raise ScanStageError(f"ML module unavailable: {exc}") from exc

        return None

    function = getattr(
        predict,
        "predict_record",
        None,
    )

    if not callable(function):
        function = getattr(
            predict,
            "predict",
            None,
        )

    if not callable(function):
        if context.config.fail_closed:
            raise ScanStageError("ML prediction API is unavailable.")

        return None

    record = {
        "sample_id": context.input.sha256,
        "sha256": context.input.sha256,
        "file_name": context.input.source_name,
        "features": context.features,
        "feature_vector": context.features,
    }

    attempts = (
        record,
        {
            "analysis": record,
            "features": context.features,
        },
    )

    for candidate in attempts:
        try:
            output = function(candidate)

            normalized = _json_safe(output)

            if isinstance(normalized, Mapping):
                result = dict(normalized)

                probability = _extract_probability(result)

                if probability is not None:
                    result.setdefault(
                        "probability",
                        probability,
                    )

                    result.setdefault(
                        "threshold",
                        context.config.model_threshold,
                    )

                    result.setdefault(
                        "predicted_malicious",
                        probability >= context.config.model_threshold,
                    )

                return result

            return {"prediction": normalized}

        except TypeError:
            continue
        except Exception as exc:
            if context.config.fail_closed:
                raise ScanStageError(f"ML prediction failed: {exc}") from exc

            return None

    return None


def _extract_probability(
    prediction: Mapping[str, Any],
) -> Optional[float]:
    for key in (
        "probability",
        "malicious_probability",
        "positive_probability",
        "score",
        "risk_score",
    ):
        if key not in prediction:
            continue

        value = _safe_float(
            prediction[key],
            default=float("nan"),
        )

        if value != value:
            continue

        if 0.0 <= value <= 1.0:
            return value

    probabilities = prediction.get("probabilities")

    if isinstance(probabilities, Mapping):
        for key in (
            "malicious",
            "malware",
            "positive",
            "1",
        ):
            if key in probabilities:
                value = _safe_float(
                    probabilities[key],
                    default=float("nan"),
                )

                if value == value and 0.0 <= value <= 1.0:
                    return value

    return None


def _call_cdr_detector(
    context: _StageContext,
) -> Optional[Any]:
    try:
        from ..cdr import detector
    except Exception:
        return None

    candidates = (
        "detect",
        "detect_content",
        "analyze",
        "scan",
        "inspect",
    )

    analysis = (
        context.extraction if context.extraction is not None else context.input.content
    )

    for name in candidates:
        function = getattr(
            detector,
            name,
            None,
        )

        if not callable(function):
            continue

        attempts = (
            (analysis,),
            (context.input.content,),
            (
                context.input.content,
                context.file_type,
            ),
        )

        for args in attempts:
            try:
                return function(*args)
            except (
                TypeError,
                AttributeError,
                ValueError,
            ):
                continue
            except Exception as exc:
                if context.config.fail_closed:
                    raise ScanStageError(f"CDR detector failed: {exc}") from exc

                return None

    return None


def _run_cdr_detection(
    context: _StageContext,
) -> Optional[Dict[str, Any]]:
    output = _call_cdr_detector(context)

    if output is None:
        return None

    normalized = _json_safe(output)

    if isinstance(normalized, Mapping):
        return dict(normalized)

    return {"detection": normalized}


def _call_policy(
    context: _StageContext,
) -> Optional[Any]:
    try:
        from ..cdr import policy
    except Exception:
        return None

    detector_output = (
        context.cdr_detection
        if context.cdr_detection is not None
        else context.extraction
    )

    candidates = (
        "evaluate_detector_output",
        "evaluate_policy",
        "evaluate",
    )

    for name in candidates:
        function = getattr(
            policy,
            name,
            None,
        )

        if not callable(function):
            continue

        attempts = (
            (detector_output,),
            (
                detector_output,
                None,
            ),
        )

        for args in attempts:
            try:
                return function(*args)
            except (
                TypeError,
                AttributeError,
                ValueError,
            ):
                continue
            except Exception as exc:
                if context.config.fail_closed:
                    raise ScanStageError(
                        f"CDR policy evaluation failed: {exc}"
                    ) from exc

                return None

    return None


def _run_policy(
    context: _StageContext,
) -> Optional[Dict[str, Any]]:
    output = _call_policy(context)

    if output is None:
        return None

    normalized = _json_safe(output)

    if isinstance(normalized, Mapping):
        return dict(normalized)

    return {"decision": normalized}


def _policy_action(
    policy_output: Optional[Mapping[str, Any]],
) -> Optional[str]:
    if not policy_output:
        return None

    for key in (
        "action",
        "final_action",
        "decision",
        "recommended_action",
    ):
        value = policy_output.get(key)

        if value is None:
            continue

        text = _safe_text(value).strip().lower()

        if text:
            return text

    decision = policy_output.get("policy_decision")

    if isinstance(decision, Mapping):
        return _policy_action(decision)

    return None


def _call_sanitizer(
    context: _StageContext,
) -> Optional[bytes]:
    try:
        from ..cdr import sanitizer
    except Exception as exc:
        raise ScanStageError(f"Sanitizer module unavailable: {exc}") from exc

    candidates = (
        "sanitize_content",
        "sanitize_document",
        "sanitize",
    )

    for name in candidates:
        function = getattr(
            sanitizer,
            name,
            None,
        )

        if not callable(function):
            continue

        attempts = (
            (context.input.content,),
            (
                context.input.content,
                None,
            ),
        )

        for args in attempts:
            try:
                output = function(*args)

                if isinstance(output, bytes):
                    return output

                if isinstance(
                    output,
                    bytearray,
                ):
                    return bytes(output)

                if isinstance(
                    output,
                    Mapping,
                ):
                    for key in (
                        "content",
                        "sanitized_content",
                        "data",
                        "output",
                    ):
                        value = output.get(key)

                        if isinstance(value, bytes):
                            return value

                        if isinstance(
                            value,
                            bytearray,
                        ):
                            return bytes(value)

                for attribute in (
                    "content",
                    "sanitized_content",
                    "data",
                    "output",
                ):
                    value = getattr(
                        output,
                        attribute,
                        None,
                    )

                    if isinstance(value, bytes):
                        return value

                    if isinstance(
                        value,
                        bytearray,
                    ):
                        return bytes(value)

            except TypeError:
                continue
            except Exception as exc:
                raise ScanStageError(f"Sanitization failed: {exc}") from exc

    raise ScanStageError("No compatible sanitizer API was found.")


def _run_sanitization(
    context: _StageContext,
) -> Optional[bytes]:
    if not context.config.sanitize:
        return None

    if context.input.extension not in OOXML_EXTENSIONS:
        raise ScanStageError(
            "Sanitization is currently supported only for OOXML " "packages."
        )

    sanitized = _call_sanitizer(context)

    if sanitized is None:
        raise ScanStageError("Sanitizer returned no output.")

    if len(sanitized) > MAX_INPUT_BYTES:
        raise ScanLimitError("Sanitized output exceeds configured scanner limits.")

    return sanitized


def _call_integrity(
    content: bytes,
    *,
    strict: bool,
) -> Optional[Dict[str, Any]]:
    try:
        from ..cdr import integrity
    except Exception as exc:
        raise ScanStageError(f"Integrity module unavailable: {exc}") from exc

    if strict:
        function = getattr(
            integrity,
            "verify_reconstructed_package",
            None,
        )

        if callable(function):
            try:
                output = function(
                    content,
                    strict=True,
                )

                return _json_safe(output)
            except TypeError:
                pass

    function = getattr(
        integrity,
        "verify_integrity",
        None,
    )

    if callable(function):
        try:
            output = function(content)

            return _json_safe(output)
        except Exception as exc:
            raise ScanStageError(f"Integrity verification failed: {exc}") from exc

    raise ScanStageError("No compatible integrity verification API was found.")


def _run_integrity(
    context: _StageContext,
) -> Optional[Dict[str, Any]]:
    if context.sanitized_content is None:
        return None

    if not context.config.verify_sanitized:
        return None

    output = _call_integrity(
        context.sanitized_content,
        strict=context.config.strict_integrity,
    )

    if output is None:
        return None

    if isinstance(output, Mapping):
        return dict(output)

    return {"integrity": output}


def _stage_success(
    context: _StageContext,
    stage: ScanStage,
    *,
    output: Any = None,
    summary: Optional[Dict[str, Any]] = None,
) -> None:
    context.stages.append(
        StageResult(
            stage=stage,
            success=True,
            summary=summary or {},
            output=(
                _json_safe(output) if context.config.include_raw_stage_outputs else None
            ),
        )
    )


def _stage_failure(
    context: _StageContext,
    stage: ScanStage,
    exc: Exception,
) -> None:
    message = f"{stage.value}: " f"{type(exc).__name__}: " f"{_safe_text(exc)}"

    context.errors.append(message)

    context.stages.append(
        StageResult(
            stage=stage,
            success=False,
            error=message,
        )
    )


def _summarize_extraction(
    extraction: Optional[Mapping[str, Any]],
    features: Mapping[str, float],
) -> Dict[str, Any]:
    return {
        "available": extraction is not None,
        "feature_count": len(features),
        "positive_feature_count": sum(1 for value in features.values() if value > 0),
    }


def _summarize_prediction(
    prediction: Optional[Mapping[str, Any]],
) -> Dict[str, Any]:
    if not prediction:
        return {"available": False}

    probability = _extract_probability(prediction)

    return {
        "available": True,
        "probability": probability,
        "predicted_malicious": (
            probability >= DEFAULT_MODEL_THRESHOLD if probability is not None else None
        ),
    }


def _summarize_policy(
    policy_output: Optional[Mapping[str, Any]],
) -> Dict[str, Any]:
    if not policy_output:
        return {"available": False}

    return {
        "available": True,
        "action": _policy_action(policy_output),
    }


def _append_findings(
    context: _StageContext,
    source: str,
    output: Any,
) -> None:
    remaining = context.config.max_findings - len(context.findings)

    if remaining <= 0:
        return

    findings = _extract_findings(
        output,
        source=source,
        max_findings=remaining,
    )

    context.findings.extend(findings)


def _derive_status(
    context: _StageContext,
) -> Tuple[ScanStatus, ScanVerdict]:
    if context.errors and context.config.fail_closed:
        return (
            ScanStatus.ERROR,
            ScanVerdict.REJECT,
        )

    integrity = context.integrity

    if isinstance(integrity, Mapping):
        valid = integrity.get("valid")

        if valid is False:
            return (
                ScanStatus.REJECTED,
                ScanVerdict.REJECT,
            )

    action = _policy_action(context.policy)

    if action:
        normalized = action.lower()

        if "reject" in normalized:
            return (
                ScanStatus.REJECTED,
                ScanVerdict.REJECT,
            )

        if "sanitize" in normalized:
            if context.sanitized_content is not None:
                return (
                    ScanStatus.SANITIZED,
                    ScanVerdict.SANITIZE,
                )

            return (
                ScanStatus.SUSPICIOUS,
                ScanVerdict.SANITIZE,
            )

        if "review" in normalized:
            return (
                ScanStatus.SUSPICIOUS,
                ScanVerdict.REVIEW,
            )

    probability = _extract_probability(context.prediction or {})

    if probability is not None:
        if probability >= 0.80:
            return (
                ScanStatus.MALICIOUS,
                ScanVerdict.REJECT,
            )

        if probability >= context.config.model_threshold:
            return (
                ScanStatus.SUSPICIOUS,
                ScanVerdict.REVIEW,
            )

    if context.findings:
        high_risk = 0

        for finding in context.findings:
            severity = _safe_text(
                finding.get("severity", "") if isinstance(finding, Mapping) else ""
            ).lower()

            if severity in {
                "critical",
                "high",
                "error",
            }:
                high_risk += 1

        if high_risk:
            return (
                ScanStatus.SUSPICIOUS,
                ScanVerdict.REVIEW,
            )

    return (
        ScanStatus.CLEAN,
        ScanVerdict.ALLOW,
    )


def _build_context_metadata(
    context: _StageContext,
) -> Dict[str, Any]:
    return {
        "module": MODULE_NAME,
        "scanner_version": SCANNER_VERSION,
        "input_extension": context.input.extension,
        "input_size": context.input.size,
        "input_sha256": context.input.sha256,
        "stage_count": len(context.stages),
        "successful_stage_count": sum(1 for stage in context.stages if stage.success),
        "failed_stage_count": sum(1 for stage in context.stages if not stage.success),
        "finding_count": len(context.findings),
        "error_count": len(context.errors),
        "warning_count": len(context.warnings),
    }


def scan(
    source: Union[
        bytes,
        bytearray,
        memoryview,
        str,
        os.PathLike,
        ScanInput,
    ],
    *,
    config: Optional[ScanConfig] = None,
    source_name: Optional[str] = None,
) -> ScanResult:
    """
    Run the complete static scanning pipeline.

    The input is read into memory and is never executed.
    """
    effective_config = (
        config.normalized() if config is not None else ScanConfig().normalized()
    )

    scan_input = _read_input(
        source,
        max_input_bytes=effective_config.max_input_bytes,
        source_name=source_name,
    )

    context = _StageContext(
        input=scan_input,
        config=effective_config,
    )

    # ---------------------------------------------------------------
    # Stage 1: ingestion
    # ---------------------------------------------------------------
    try:
        if scan_input.size > effective_config.max_input_bytes:
            raise ScanLimitError("Input exceeds configured maximum size.")

        _stage_success(
            context,
            ScanStage.INGESTION,
            summary={
                "size": scan_input.size,
                "sha256": scan_input.sha256,
            },
        )

    except Exception as exc:
        _stage_failure(
            context,
            ScanStage.INGESTION,
            exc,
        )

        if effective_config.fail_closed:
            return _finalize_result(context)

    # ---------------------------------------------------------------
    # Stage 2: file type
    # ---------------------------------------------------------------
    try:
        context.file_type = _run_file_type(context)

        _stage_success(
            context,
            ScanStage.FILE_TYPE,
            output=context.file_type,
            summary={
                "detected_type": (
                    context.file_type.get("detected_type")
                    if context.file_type
                    else None
                ),
            },
        )

    except Exception as exc:
        _stage_failure(
            context,
            ScanStage.FILE_TYPE,
            exc,
        )

        if effective_config.fail_closed:
            return _finalize_result(context)

    # ---------------------------------------------------------------
    # Stage 3: extraction
    # ---------------------------------------------------------------
    if effective_config.run_extraction:
        try:
            context.extraction = _run_extraction(context)

            feature_container = _extract_feature_container(context.extraction)

            context.features = _flatten_numeric_features(
                feature_container,
                max_features=effective_config.max_features,
            )

            _append_findings(
                context,
                "extraction",
                context.extraction,
            )

            _stage_success(
                context,
                ScanStage.EXTRACTION,
                output=context.extraction,
                summary=_summarize_extraction(
                    context.extraction,
                    context.features,
                ),
            )

        except Exception as exc:
            _stage_failure(
                context,
                ScanStage.EXTRACTION,
                exc,
            )

            if effective_config.fail_closed:
                return _finalize_result(context)

    # ---------------------------------------------------------------
    # Stage 4: ML prediction
    # ---------------------------------------------------------------
    if effective_config.run_ml:
        try:
            context.prediction = _run_ml_prediction(context)

            _append_findings(
                context,
                "ml",
                context.prediction,
            )

            _stage_success(
                context,
                ScanStage.ML,
                output=context.prediction,
                summary=_summarize_prediction(context.prediction),
            )

        except Exception as exc:
            _stage_failure(
                context,
                ScanStage.ML,
                exc,
            )

            if not effective_config.continue_on_stage_error:
                if effective_config.fail_closed:
                    return _finalize_result(context)

    # ---------------------------------------------------------------
    # Stage 5: CDR detection
    # ---------------------------------------------------------------
    if effective_config.run_cdr_detection:
        try:
            context.cdr_detection = _run_cdr_detection(context)

            _append_findings(
                context,
                "cdr_detection",
                context.cdr_detection,
            )

            _stage_success(
                context,
                ScanStage.CDR_DETECTION,
                output=context.cdr_detection,
                summary={
                    "available": (context.cdr_detection is not None),
                },
            )

        except Exception as exc:
            _stage_failure(
                context,
                ScanStage.CDR_DETECTION,
                exc,
            )

            if (
                effective_config.fail_closed
                and not effective_config.continue_on_stage_error
            ):
                return _finalize_result(context)

    # ---------------------------------------------------------------
    # Stage 6: policy
    # ---------------------------------------------------------------
    if effective_config.run_policy:
        try:
            context.policy = _run_policy(context)

            _append_findings(
                context,
                "policy",
                context.policy,
            )

            _stage_success(
                context,
                ScanStage.POLICY,
                output=context.policy,
                summary=_summarize_policy(context.policy),
            )

        except Exception as exc:
            _stage_failure(
                context,
                ScanStage.POLICY,
                exc,
            )

            if (
                effective_config.fail_closed
                and not effective_config.continue_on_stage_error
            ):
                return _finalize_result(context)

    # ---------------------------------------------------------------
    # Stage 7: sanitization
    # ---------------------------------------------------------------
    should_sanitize = effective_config.sanitize or _policy_requests_sanitization(
        context.policy
    )

    if should_sanitize:
        try:
            original_setting = context.config.sanitize

            context.config.sanitize = True

            context.sanitized_content = _run_sanitization(context)

            context.config.sanitize = original_setting

            _stage_success(
                context,
                ScanStage.SANITIZATION,
                summary={
                    "input_size": context.input.size,
                    "output_size": (
                        len(context.sanitized_content)
                        if context.sanitized_content
                        else 0
                    ),
                    "changed": (
                        context.sanitized_content != context.input.content
                        if context.sanitized_content is not None
                        else False
                    ),
                    "sha256": (
                        _hash_bytes(context.sanitized_content)
                        if context.sanitized_content is not None
                        else None
                    ),
                },
            )

        except Exception as exc:
            context.config.sanitize = effective_config.sanitize

            _stage_failure(
                context,
                ScanStage.SANITIZATION,
                exc,
            )

            if effective_config.fail_closed:
                return _finalize_result(context)

    # ---------------------------------------------------------------
    # Stage 8: integrity
    # ---------------------------------------------------------------
    if context.sanitized_content is not None and effective_config.verify_sanitized:
        try:
            context.integrity = _run_integrity(context)

            _append_findings(
                context,
                "integrity",
                context.integrity,
            )

            valid = None

            if isinstance(
                context.integrity,
                Mapping,
            ):
                valid = context.integrity.get("valid")

            _stage_success(
                context,
                ScanStage.INTEGRITY,
                output=context.integrity,
                summary={
                    "valid": valid,
                    "sha256": _hash_bytes(context.sanitized_content),
                },
            )

        except Exception as exc:
            _stage_failure(
                context,
                ScanStage.INTEGRITY,
                exc,
            )

            if effective_config.fail_closed:
                return _finalize_result(context)

    return _finalize_result(context)


def _policy_requests_sanitization(
    policy_output: Optional[Mapping[str, Any]],
) -> bool:
    if not policy_output:
        return False

    action = _policy_action(policy_output)

    if action is None:
        return False

    normalized = action.lower()

    return "sanitize" in normalized or "remove" in normalized


def _finalize_result(
    context: _StageContext,
) -> ScanResult:
    status, verdict = _derive_status(context)

    sanitized_sha256 = None

    if context.sanitized_content is not None:
        sanitized_sha256 = _hash_bytes(context.sanitized_content)

    metadata = _build_context_metadata(context)

    metadata["sanitized"] = context.sanitized_content is not None

    metadata["sanitized_changed"] = (
        context.sanitized_content != context.input.content
        if context.sanitized_content is not None
        else False
    )

    scan_id = _make_scan_id(context.input.sha256)

    return ScanResult(
        scan_id=scan_id,
        scanner_version=SCANNER_VERSION,
        status=status,
        verdict=verdict,
        input=context.input,
        file_type=context.file_type,
        features=(context.features if context.config.include_feature_vector else {}),
        prediction=context.prediction,
        cdr_detection=context.cdr_detection,
        policy=context.policy,
        sanitized_content=(
            context.sanitized_content
            if context.config.include_raw_stage_outputs
            else None
        ),
        sanitized_sha256=sanitized_sha256,
        integrity=context.integrity,
        findings=context.findings[: context.config.max_findings],
        stages=list(context.stages),
        errors=list(context.errors),
        warnings=list(context.warnings),
        metadata=metadata,
    )


def scan_bytes(
    content: Union[
        bytes,
        bytearray,
        memoryview,
    ],
    *,
    source_name: str = "input",
    config: Optional[ScanConfig] = None,
) -> ScanResult:
    """Scan an in-memory document."""
    return scan(
        content,
        config=config,
        source_name=source_name,
    )


def scan_file(
    path: Union[str, os.PathLike],
    *,
    config: Optional[ScanConfig] = None,
) -> ScanResult:
    """Scan a document from a filesystem path."""
    return scan(
        path,
        config=config,
    )


def scan_many(
    sources: Iterable[
        Union[
            bytes,
            bytearray,
            memoryview,
            str,
            os.PathLike,
            ScanInput,
        ]
    ],
    *,
    config: Optional[ScanConfig] = None,
) -> List[ScanResult]:
    """
    Scan multiple inputs sequentially.

    Sequential execution is intentional: it avoids creating uncontrolled
    concurrent memory pressure when scanning large documents.
    """
    results: List[ScanResult] = []

    for source in sources:
        try:
            results.append(
                scan(
                    source,
                    config=config,
                )
            )
        except Exception as exc:
            if config is not None and config.fail_closed:
                try:
                    fallback_input = _read_input(
                        source,
                        max_input_bytes=(config.max_input_bytes),
                    )
                except Exception:
                    fallback_input = ScanInput(
                        source_name="unreadable-input",
                        source_path=None,
                        size=0,
                        sha256="",
                        extension="",
                        content=b"",
                    )

                context = _StageContext(
                    input=fallback_input,
                    config=config.normalized(),
                )

                context.errors.append(
                    f"scan: " f"{type(exc).__name__}: " f"{_safe_text(exc)}"
                )

                results.append(_finalize_result(context))
            else:
                raise

    return results


def scan_stream(
    stream: Any,
    *,
    source_name: str = "stream",
    config: Optional[ScanConfig] = None,
) -> ScanResult:
    """
    Read a binary stream with a hard memory limit and scan its contents.

    The stream itself is never executed or otherwise interpreted.
    """
    effective_config = (
        config.normalized() if config is not None else ScanConfig().normalized()
    )

    buffer = io.BytesIO()
    total = 0

    while True:
        chunk = stream.read(
            min(
                1024 * 1024,
                effective_config.max_input_bytes - total + 1,
            )
        )

        if not chunk:
            break

        if not isinstance(
            chunk,
            (bytes, bytearray),
        ):
            raise ScanInputError("Binary stream must return bytes.")

        total += len(chunk)

        if total > effective_config.max_input_bytes:
            raise ScanLimitError("Stream exceeds configured maximum size.")

        buffer.write(chunk)

    return scan_bytes(
        buffer.getvalue(),
        source_name=source_name,
        config=effective_config,
    )


def is_ooxml_package(
    content: Union[
        bytes,
        bytearray,
        memoryview,
    ],
) -> bool:
    """Return True when content has the ZIP signature used by OOXML."""
    data = bytes(content)

    if not data.startswith(b"PK\x03\x04"):
        return False

    try:
        with ZipFile(
            io.BytesIO(data),
            "r",
        ) as archive:
            names = {name.replace("\\", "/") for name in archive.namelist()}

            return "[Content_Types].xml" in names

    except BadZipFile:
        return False


def scan_summary(
    result: ScanResult,
) -> Dict[str, Any]:
    """Return a compact scan summary suitable for dashboards/logs."""
    probability = _extract_probability(result.prediction or {})

    return {
        "scan_id": result.scan_id,
        "status": result.status.value,
        "verdict": result.verdict.value,
        "source_name": result.input.source_name,
        "size": result.input.size,
        "sha256": result.input.sha256,
        "file_type": (
            result.file_type.get("detected_type") if result.file_type else None
        ),
        "ml_probability": probability,
        "finding_count": len(result.findings),
        "error_count": len(result.errors),
        "warning_count": len(result.warnings),
        "sanitized": (result.sanitized_content is not None),
        "sanitized_sha256": (result.sanitized_sha256),
        "integrity_valid": (
            result.integrity.get("valid")
            if isinstance(
                result.integrity,
                Mapping,
            )
            else None
        ),
    }


def result_to_dict(
    result: ScanResult,
    *,
    include_features: bool = True,
) -> Dict[str, Any]:
    """Serialize a scan result to a dictionary."""
    return result.to_dict(
        include_content=False,
        include_features=include_features,
    )


def result_to_json(
    result: ScanResult,
    *,
    indent: Optional[int] = 2,
    include_features: bool = True,
) -> str:
    """Serialize a scan result to JSON."""
    return result.to_json(
        indent=indent,
        include_features=include_features,
    )


def save_report(
    result: ScanResult,
    output_path: Union[str, os.PathLike],
    *,
    overwrite: bool = False,
    include_features: bool = True,
    indent: int = 2,
) -> Path:
    """
    Explicitly persist a scan report.

    Reports never contain raw input bytes.
    """
    destination = Path(output_path)

    if destination.exists() and not overwrite:
        raise ScanInputError(f"Output report already exists: {destination}")

    payload = result_to_json(
        result,
        indent=indent,
        include_features=include_features,
    ).encode("utf-8")

    if len(payload) > MAX_RESULT_JSON_BYTES:
        raise ScanLimitError("Serialized report exceeds maximum size.")

    try:
        destination.parent.mkdir(
            parents=True,
            exist_ok=True,
        )
        destination.write_bytes(payload)
    except OSError as exc:
        raise ScanError(f"Unable to save scan report: {exc}") from exc

    return destination


def save_sanitized_content(
    result: ScanResult,
    output_path: Union[str, os.PathLike],
    *,
    overwrite: bool = False,
) -> Path:
    """Explicitly save scanner-produced sanitized content."""
    if result.sanitized_content is None:
        raise ScanInputError("Scan result does not contain sanitized content.")

    destination = Path(output_path)

    if destination.exists() and not overwrite:
        raise ScanInputError(f"Sanitized output already exists: {destination}")

    try:
        destination.parent.mkdir(
            parents=True,
            exist_ok=True,
        )
        destination.write_bytes(result.sanitized_content)
    except OSError as exc:
        raise ScanError(f"Unable to save sanitized content: {exc}") from exc

    return destination


def iter_findings(
    result: ScanResult,
) -> Iterator[Dict[str, Any]]:
    """Iterate normalized scan findings."""
    yield from result.findings


def high_risk_findings(
    result: ScanResult,
) -> List[Dict[str, Any]]:
    """Return high/critical/error findings."""
    high_risk = {
        "critical",
        "high",
        "error",
    }

    return [
        finding
        for finding in result.findings
        if isinstance(finding, Mapping)
        and _safe_text(finding.get("severity", "")).lower() in high_risk
    ]


def has_high_risk_findings(
    result: ScanResult,
) -> bool:
    """Return True when at least one high-risk finding exists."""
    return bool(high_risk_findings(result))


def model_probability(
    result: ScanResult,
) -> Optional[float]:
    """Return normalized ML malicious probability."""
    return _extract_probability(result.prediction or {})


def is_malicious(
    result: ScanResult,
    *,
    threshold: Optional[float] = None,
) -> bool:
    """Return True when the ML result exceeds the supplied threshold."""
    probability = model_probability(result)

    if probability is None:
        return result.status == ScanStatus.MALICIOUS

    effective_threshold = (
        DEFAULT_MODEL_THRESHOLD if threshold is None else float(threshold)
    )

    if not 0.0 <= effective_threshold <= 1.0:
        raise ScanInputError("threshold must be between 0 and 1.")

    return probability >= effective_threshold


def requires_review(
    result: ScanResult,
) -> bool:
    """Return True when the scanner verdict requires human review."""
    return result.verdict == ScanVerdict.REVIEW


def requires_sanitization(
    result: ScanResult,
) -> bool:
    """Return True when sanitization is recommended or was performed."""
    return (
        result.verdict == ScanVerdict.SANITIZE or result.sanitized_content is not None
    )


def is_rejected(
    result: ScanResult,
) -> bool:
    """Return True when the scanner rejected the input."""
    return (
        result.status
        in {
            ScanStatus.REJECTED,
            ScanStatus.ERROR,
        }
        or result.verdict == ScanVerdict.REJECT
    )


def sanitized_changed(
    result: ScanResult,
) -> bool:
    """Return True when sanitization produced different bytes."""
    if result.sanitized_content is None:
        return False

    return result.sanitized_content != result.input.content


def feature_count(
    result: ScanResult,
) -> int:
    """Return the number of numeric features in the result."""
    return len(result.features)


def successful_stages(
    result: ScanResult,
) -> List[ScanStage]:
    """Return successfully completed pipeline stages."""
    return [stage.stage for stage in result.stages if stage.success]


def failed_stages(
    result: ScanResult,
) -> List[ScanStage]:
    """Return failed pipeline stages."""
    return [stage.stage for stage in result.stages if not stage.success]


def default_config() -> ScanConfig:
    """Return the default scanner configuration."""
    return ScanConfig().normalized()


def strict_config() -> ScanConfig:
    """Return a fail-closed scanning configuration."""
    return ScanConfig(
        run_extraction=True,
        run_ml=True,
        run_cdr_detection=True,
        run_policy=True,
        sanitize=True,
        verify_sanitized=True,
        strict_integrity=True,
        fail_closed=True,
        continue_on_stage_error=False,
        model_threshold=0.50,
        include_raw_stage_outputs=True,
        include_feature_vector=True,
    ).normalized()


def analysis_config() -> ScanConfig:
    """
    Return an analysis-only configuration.

    No sanitization is performed.
    """
    return ScanConfig(
        run_extraction=True,
        run_ml=True,
        run_cdr_detection=True,
        run_policy=True,
        sanitize=False,
        verify_sanitized=False,
        strict_integrity=True,
        fail_closed=False,
        continue_on_stage_error=True,
        model_threshold=0.50,
        include_raw_stage_outputs=True,
        include_feature_vector=True,
    ).normalized()


def minimal_config() -> ScanConfig:
    """
    Return a lightweight static configuration.

    This still performs file-type detection and extraction but skips ML,
    CDR policy, sanitization, and integrity processing.
    """
    return ScanConfig(
        run_extraction=True,
        run_ml=False,
        run_cdr_detection=False,
        run_policy=False,
        sanitize=False,
        verify_sanitized=False,
        fail_closed=True,
        continue_on_stage_error=False,
        include_raw_stage_outputs=False,
        include_feature_vector=True,
    ).normalized()


def scan_and_save_report(
    source: Union[
        bytes,
        bytearray,
        memoryview,
        str,
        os.PathLike,
        ScanInput,
    ],
    report_path: Union[str, os.PathLike],
    *,
    config: Optional[ScanConfig] = None,
    overwrite: bool = False,
) -> ScanResult:
    """Scan an input and explicitly save its report."""
    result = scan(
        source,
        config=config,
    )

    save_report(
        result,
        report_path,
        overwrite=overwrite,
    )

    return result


# ---------------------------------------------------------------------------
# PUBLIC APIs
# ---------------------------------------------------------------------------

__all__ = [
    "MODULE_NAME",
    "SCANNER_VERSION",
    "MAX_INPUT_BYTES",
    "MAX_ANALYSIS_TEXT",
    "MAX_FINDINGS",
    "MAX_FEATURES",
    "MAX_RESULT_JSON_BYTES",
    "ScanError",
    "ScanInputError",
    "ScanLimitError",
    "ScanStageError",
    "ScanStatus",
    "ScanVerdict",
    "ScanStage",
    "StageResult",
    "ScanInput",
    "ScanConfig",
    "ScanResult",
    "scan",
    "scan_bytes",
    "scan_file",
    "scan_many",
    "scan_stream",
    "scan_and_save_report",
    "is_ooxml_package",
    "result_to_dict",
    "result_to_json",
    "save_report",
    "save_sanitized_content",
    "scan_summary",
    "iter_findings",
    "high_risk_findings",
    "has_high_risk_findings",
    "model_probability",
    "is_malicious",
    "requires_review",
    "requires_sanitization",
    "is_rejected",
    "sanitized_changed",
    "feature_count",
    "successful_stages",
    "failed_stages",
    "default_config",
    "strict_config",
    "analysis_config",
    "minimal_config",
]
