"""
pharos-cdr: static CDR threat detector.

This module provides a bounded, deterministic detector that converts document
analysis output into normalized CDR findings suitable for policy evaluation.

Security model
--------------
The detector is strictly static:

* It never executes macros, scripts, formulas, commands, or embedded files.
* It never launches processes or loads dynamic libraries.
* It never contacts URLs, DNS, network services, or external resources.
* It never writes extracted/untrusted document content to disk.
* It operates on bounded in-memory data.
* It treats detector output as evidence, not proof of malicious execution.

The detector is intentionally format-agnostic. It accepts:
* mappings/dictionaries,
* dataclass instances,
* sequences of analysis results,
* JSON-compatible structures,
* text or bytes,
* parser/extractor result objects exposing ``to_dict``/``as_dict``.

Typical flow
------------

    parsed = cdr.parser.parse_document(...)
    detected = detect_document(parsed)

    policy_result = evaluate_detector_output(detected)

The detector can also consume combined outputs from Office, VBA, script,
behavior, URL, payload, communication, and derived capability analyzers.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import math
import os
import re
import struct
import zipfile
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import (
    Any,
    Dict,
    Iterable,
    Iterator,
    List,
    Mapping,
    MutableMapping,
    Optional,
    Sequence,
    Set,
    Tuple,
)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MODULE_NAME = "cdr.detector"
DETECTOR_VERSION = "1.0.0"

MAX_INPUT_BYTES = 25 * 1024 * 1024
MAX_TEXT_LENGTH = 100_000
MAX_NESTING_DEPTH = 12
MAX_ITEMS = 30_000
MAX_EVIDENCE = 20_000
MAX_FINDINGS = 10_000
MAX_FEATURES = 100_000
MAX_PATH_LENGTH = 4_096
MAX_VALUE_LENGTH = 8_192
MAX_ZIP_ENTRIES = 10_000
MAX_ZIP_ENTRY_SIZE = 100 * 1024 * 1024
MAX_ZIP_TOTAL_UNCOMPRESSED = 250 * 1024 * 1024

DEFAULT_REVIEW_THRESHOLD = 35.0
DEFAULT_BLOCK_THRESHOLD = 75.0

MIN_SCORE = 0.0
MAX_SCORE = 100.0

# Risk levels intentionally map to numeric values for deterministic ordering.
RISK_ORDER = {
    "none": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

# Action suggestions are advisory. The policy engine remains authoritative.
ACTION_ORDER = {
    "preserve": 0,
    "sanitize": 1,
    "remove": 2,
    "review": 3,
    "reject": 4,
}


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class DetectorError(Exception):
    """Base exception for detector failures."""


class DetectorInputError(DetectorError):
    """Raised when detector input is invalid or exceeds safety limits."""


class DetectorConfigurationError(DetectorError):
    """Raised when detector configuration is invalid."""


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class DetectionSeverity(str, Enum):
    """Normalized severity assigned to detector findings."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class DetectionConfidence(str, Enum):
    """Confidence in the interpretation of a finding."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class SuggestedAction(str, Enum):
    """Advisory CDR action associated with a detection."""

    PRESERVE = "preserve"
    SANITIZE = "sanitize"
    REMOVE = "remove"
    REVIEW = "review"
    REJECT = "reject"


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DetectionEvidence:
    """
    Atomic evidence supporting a detector finding.
    """

    category: str
    indicator: str
    description: str = ""
    source: str = ""
    path: str = ""
    value: str = ""
    severity: DetectionSeverity = DetectionSeverity.LOW
    confidence: DetectionConfidence = DetectionConfidence.MEDIUM
    score: float = 0.0
    tags: Tuple[str, ...] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "category",
            _normalize_name(self.category),
        )
        object.__setattr__(
            self,
            "indicator",
            _normalize_name(self.indicator),
        )
        object.__setattr__(
            self,
            "description",
            _safe_text(self.description, MAX_TEXT_LENGTH),
        )
        object.__setattr__(
            self,
            "source",
            _safe_text(self.source, MAX_PATH_LENGTH),
        )
        object.__setattr__(
            self,
            "path",
            _safe_text(self.path, MAX_PATH_LENGTH),
        )
        object.__setattr__(
            self,
            "value",
            _safe_text(self.value, MAX_VALUE_LENGTH),
        )
        object.__setattr__(
            self,
            "score",
            _clamp_score(self.score),
        )
        object.__setattr__(
            self,
            "tags",
            tuple(
                sorted(
                    {
                        _normalize_name(tag)
                        for tag in self.tags
                        if _normalize_name(tag)
                    }
                )
            ),
        )


@dataclass(frozen=True)
class DetectionFinding:
    """
    Normalized detector finding.

    A finding is the primary object consumed by the CDR policy layer.
    """

    finding_id: str
    category: str
    indicator: str
    title: str
    description: str = ""
    severity: DetectionSeverity = DetectionSeverity.LOW
    confidence: DetectionConfidence = DetectionConfidence.MEDIUM
    score: float = 0.0
    suggested_action: SuggestedAction = SuggestedAction.PRESERVE
    path: str = ""
    source: str = ""
    evidence: Tuple[DetectionEvidence, ...] = ()
    tags: Tuple[str, ...] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "finding_id", _safe_text(self.finding_id, 512))
        object.__setattr__(self, "category", _normalize_name(self.category))
        object.__setattr__(self, "indicator", _normalize_name(self.indicator))
        object.__setattr__(
            self,
            "title",
            _safe_text(self.title, MAX_TEXT_LENGTH),
        )
        object.__setattr__(
            self,
            "description",
            _safe_text(self.description, MAX_TEXT_LENGTH),
        )
        object.__setattr__(
            self,
            "path",
            _safe_text(self.path, MAX_PATH_LENGTH),
        )
        object.__setattr__(
            self,
            "source",
            _safe_text(self.source, MAX_PATH_LENGTH),
        )
        object.__setattr__(self, "score", _clamp_score(self.score))
        object.__setattr__(
            self,
            "tags",
            tuple(
                sorted(
                    {
                        _normalize_name(tag)
                        for tag in self.tags
                        if _normalize_name(tag)
                    }
                )
            ),
        )

    @property
    def risk_level(self) -> str:
        """Return a normalized risk level derived from severity."""
        return self.severity.value

    @property
    def is_high_risk(self) -> bool:
        """Return True for high or critical findings."""
        return self.severity in {
            DetectionSeverity.HIGH,
            DetectionSeverity.CRITICAL,
        }


@dataclass(frozen=True)
class DetectionCombination:
    """
    Higher-order combination of indicators.

    Combinations are useful because isolated static indicators may be benign,
    while multiple related capabilities form a stronger signal.
    """

    name: str
    description: str
    indicators: Tuple[str, ...]
    categories: Tuple[str, ...] = ()
    severity: DetectionSeverity = DetectionSeverity.MEDIUM
    confidence: DetectionConfidence = DetectionConfidence.MEDIUM
    score: float = 0.0
    suggested_action: SuggestedAction = SuggestedAction.REVIEW
    evidence_ids: Tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "name", _normalize_name(self.name))
        object.__setattr__(
            self,
            "description",
            _safe_text(self.description, MAX_TEXT_LENGTH),
        )
        object.__setattr__(
            self,
            "indicators",
            tuple(sorted({_normalize_name(x) for x in self.indicators if x})),
        )
        object.__setattr__(
            self,
            "categories",
            tuple(sorted({_normalize_name(x) for x in self.categories if x})),
        )
        object.__setattr__(
            self,
            "evidence_ids",
            tuple(sorted(set(self.evidence_ids))),
        )
        object.__setattr__(self, "score", _clamp_score(self.score))


@dataclass(frozen=True)
class DetectorStatistics:
    """Aggregate detector statistics."""

    input_size: int
    finding_count: int
    evidence_count: int
    combination_count: int
    high_risk_count: int
    critical_count: int
    category_counts: Mapping[str, int]
    indicator_counts: Mapping[str, int]
    severity_counts: Mapping[str, int]
    action_counts: Mapping[str, int]
    source_counts: Mapping[str, int]
    maximum_score: float
    aggregate_score: float


@dataclass(frozen=True)
class DetectionResult:
    """
    Complete detector output.

    The object is intentionally serializable and suitable for passing into
    ``cdr.policy.evaluate_detector_output``.
    """

    detector: str
    version: str
    document_sha256: str
    findings: Tuple[DetectionFinding, ...]
    combinations: Tuple[DetectionCombination, ...]
    evidence: Tuple[DetectionEvidence, ...]
    feature_vector: Mapping[str, float]
    statistics: DetectorStatistics
    overall_score: float
    overall_severity: DetectionSeverity
    recommended_action: SuggestedAction
    metadata: Mapping[str, Any] = field(default_factory=dict)

    @property
    def is_suspicious(self) -> bool:
        """Return True when the result is medium-or-higher risk."""
        return self.overall_severity in {
            DetectionSeverity.MEDIUM,
            DetectionSeverity.HIGH,
            DetectionSeverity.CRITICAL,
        }

    @property
    def requires_review(self) -> bool:
        """Return True when manual review is advisable."""
        return self.recommended_action == SuggestedAction.REVIEW

    @property
    def should_reject(self) -> bool:
        """Return True when the detector recommends rejection."""
        return self.recommended_action == SuggestedAction.REJECT


@dataclass(frozen=True)
class DetectorConfig:
    """
    Configuration controlling detector behavior.
    """

    review_threshold: float = DEFAULT_REVIEW_THRESHOLD
    block_threshold: float = DEFAULT_BLOCK_THRESHOLD
    enable_content_signatures: bool = True
    enable_combinations: bool = True
    max_findings: int = MAX_FINDINGS
    max_evidence: int = MAX_EVIDENCE

    def __post_init__(self) -> None:
        if not math.isfinite(float(self.review_threshold)):
            raise DetectorConfigurationError("review_threshold must be finite")
        if not math.isfinite(float(self.block_threshold)):
            raise DetectorConfigurationError("block_threshold must be finite")

        if not 0.0 <= float(self.review_threshold) <= 100.0:
            raise DetectorConfigurationError(
                "review_threshold must be between 0 and 100"
            )

        if not 0.0 <= float(self.block_threshold) <= 100.0:
            raise DetectorConfigurationError(
                "block_threshold must be between 0 and 100"
            )

        if self.review_threshold > self.block_threshold:
            raise DetectorConfigurationError(
                "review_threshold cannot exceed block_threshold"
            )

        if self.max_findings <= 0 or self.max_findings > MAX_FINDINGS:
            raise DetectorConfigurationError(
                f"max_findings must be between 1 and {MAX_FINDINGS}"
            )

        if self.max_evidence <= 0 or self.max_evidence > MAX_EVIDENCE:
            raise DetectorConfigurationError(
                f"max_evidence must be between 1 and {MAX_EVIDENCE}"
            )


# ---------------------------------------------------------------------------
# Normalization helpers
# ---------------------------------------------------------------------------


def _safe_text(value: Any, limit: int = MAX_TEXT_LENGTH) -> str:
    """Convert a value to bounded text without invoking arbitrary code."""
    if value is None:
        return ""

    if isinstance(value, bytes):
        text = value[:limit].decode("utf-8", errors="replace")
    elif isinstance(value, str):
        text = value[:limit]
    else:
        try:
            text = str(value)
        except Exception:
            return ""

        text = text[:limit]

    return text.replace("\x00", "")


def _normalize_name(value: Any) -> str:
    """Normalize category/indicator names into stable identifiers."""
    text = _safe_text(value, 512).strip().lower()
    text = re.sub(r"[^a-z0-9]+", "_", text)
    text = re.sub(r"_+", "_", text)
    return text.strip("_")


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        result = float(value)
    except (TypeError, ValueError, OverflowError):
        return default

    if not math.isfinite(result):
        return default

    return result


def _clamp_score(value: Any) -> float:
    return round(
        max(MIN_SCORE, min(MAX_SCORE, _safe_float(value))),
        4,
    )


def _clamp_probability(value: Any) -> float:
    return max(0.0, min(1.0, _safe_float(value)))


def _normalize_enum(
    value: Any,
    enum_cls: type[Enum],
    default: Enum,
) -> Enum:
    if isinstance(value, enum_cls):
        return value

    text = _safe_text(value, 128).strip().lower()

    for member in enum_cls:
        if text == member.value.lower() or text == member.name.lower():
            return member

    return default


def _severity_from_score(score: float) -> DetectionSeverity:
    score = _clamp_score(score)

    if score >= 90:
        return DetectionSeverity.CRITICAL
    if score >= 65:
        return DetectionSeverity.HIGH
    if score >= 35:
        return DetectionSeverity.MEDIUM
    if score >= 15:
        return DetectionSeverity.LOW
    return DetectionSeverity.INFO


def _confidence_from_probability(
    probability: float,
) -> DetectionConfidence:
    probability = _clamp_probability(probability)

    if probability >= 0.85:
        return DetectionConfidence.HIGH
    if probability >= 0.60:
        return DetectionConfidence.MEDIUM
    return DetectionConfidence.LOW


def _severity_max(
    values: Iterable[DetectionSeverity],
) -> DetectionSeverity:
    best = DetectionSeverity.INFO
    best_rank = -1

    for value in values:
        rank = RISK_ORDER.get(value.value, 0)
        if rank > best_rank:
            best = value
            best_rank = rank

    return best


def _action_max(
    values: Iterable[SuggestedAction],
) -> SuggestedAction:
    best = SuggestedAction.PRESERVE
    best_rank = -1

    for value in values:
        rank = ACTION_ORDER.get(value.value, 0)
        if rank > best_rank:
            best = value
            best_rank = rank

    return best


def _hash_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _hash_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


# ---------------------------------------------------------------------------
# Input coercion
# ---------------------------------------------------------------------------


def _dataclass_to_mapping(value: Any) -> Any:
    """
    Convert dataclass instances to primitive structures.

    ``dataclasses.asdict`` recursively copies fields and therefore is only
    used after depth and input-size checks are applied by the caller.
    """
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        try:
            return dataclasses.asdict(value)
        except Exception:
            return repr(value)

    return value


def _object_to_mapping(value: Any) -> Any:
    """
    Convert common analysis objects into a mapping without executing methods
    other than explicitly supported serialization helpers.
    """
    if isinstance(value, Mapping):
        return value

    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return _dataclass_to_mapping(value)

    if hasattr(value, "to_dict"):
        method = getattr(value, "to_dict", None)
        if callable(method):
            try:
                result = method()
                if isinstance(result, Mapping):
                    return result
            except Exception:
                pass

    if hasattr(value, "as_dict"):
        method = getattr(value, "as_dict", None)
        if callable(method):
            try:
                result = method()
                if isinstance(result, Mapping):
                    return result
            except Exception:
                pass

    if hasattr(value, "__dict__"):
        try:
            return vars(value)
        except Exception:
            pass

    return value


def _estimate_input_size(value: Any, depth: int = 0) -> int:
    """
    Estimate input size without recursively traversing unbounded structures.
    """
    if depth > MAX_NESTING_DEPTH:
        return 0

    if value is None:
        return 0

    if isinstance(value, bytes):
        return min(len(value), MAX_INPUT_BYTES)

    if isinstance(value, str):
        return min(len(value.encode("utf-8", errors="replace")), MAX_INPUT_BYTES)

    value = _object_to_mapping(value)

    if isinstance(value, Mapping):
        total = 0
        for index, (key, item) in enumerate(value.items()):
            if index >= MAX_ITEMS:
                break
            total += _estimate_input_size(key, depth + 1)
            total += _estimate_input_size(item, depth + 1)
            if total >= MAX_INPUT_BYTES:
                return MAX_INPUT_BYTES
        return total

    if isinstance(value, Sequence) and not isinstance(
        value,
        (str, bytes, bytearray),
    ):
        total = 0
        for index, item in enumerate(value):
            if index >= MAX_ITEMS:
                break
            total += _estimate_input_size(item, depth + 1)
            if total >= MAX_INPUT_BYTES:
                return MAX_INPUT_BYTES
        return total

    return min(
        len(_safe_text(value, MAX_VALUE_LENGTH).encode("utf-8")),
        MAX_INPUT_BYTES,
    )


def _flatten_input(
    value: Any,
    *,
    path: str = "",
    depth: int = 0,
    output: Optional[List[Tuple[str, str, str]]] = None,
) -> List[Tuple[str, str, str]]:
    """
    Flatten heterogeneous analysis output into ``(path, key, text)`` tuples.

    The function deliberately does not interpret arbitrary scalar values as
    capabilities. Interpretation occurs in the detector rules below.
    """
    if output is None:
        output = []

    if len(output) >= MAX_ITEMS:
        return output

    if depth > MAX_NESTING_DEPTH:
        return output

    value = _object_to_mapping(value)

    if isinstance(value, Mapping):
        for key, item in list(value.items())[:MAX_ITEMS]:
            key_text = _safe_text(key, 512)
            child_path = (
                f"{path}.{key_text}"
                if path and key_text
                else key_text or path
            )

            if isinstance(
                item,
                (Mapping, Sequence),
            ) and not isinstance(item, (str, bytes, bytearray)):
                _flatten_input(
                    item,
                    path=child_path,
                    depth=depth + 1,
                    output=output,
                )
            else:
                output.append(
                    (
                        child_path,
                        _normalize_name(key_text),
                        _safe_text(item, MAX_VALUE_LENGTH),
                    )
                )

        return output

    if isinstance(value, Sequence) and not isinstance(
        value,
        (str, bytes, bytearray),
    ):
        for index, item in enumerate(value):
            if len(output) >= MAX_ITEMS:
                break

            child_path = f"{path}[{index}]"

            if isinstance(
                item,
                (Mapping, Sequence),
            ) and not isinstance(item, (str, bytes, bytearray)):
                _flatten_input(
                    item,
                    path=child_path,
                    depth=depth + 1,
                    output=output,
                )
            else:
                output.append(
                    (
                        child_path,
                        str(index),
                        _safe_text(item, MAX_VALUE_LENGTH),
                    )
                )

        return output

    output.append(
        (
            path,
            _normalize_name(path.rsplit(".", 1)[-1] if path else ""),
            _safe_text(value, MAX_VALUE_LENGTH),
        )
    )

    return output


def _read_input(
    value: Any,
) -> Tuple[Any, int, str]:
    """
    Normalize supported detector inputs.

    Returns:
        normalized value,
        approximate input size,
        SHA-256 identity.
    """
    if isinstance(value, os.PathLike):
        path = Path(value)

        try:
            stat = path.stat()
        except OSError as exc:
            raise DetectorInputError(
                f"Unable to inspect input path: {path}"
            ) from exc

        if not path.is_file():
            raise DetectorInputError(f"Input is not a regular file: {path}")

        if stat.st_size > MAX_INPUT_BYTES:
            raise DetectorInputError(
                f"Input exceeds maximum size of {MAX_INPUT_BYTES} bytes"
            )

        try:
            data = path.read_bytes()
        except OSError as exc:
            raise DetectorInputError(
                f"Unable to read input file: {path}"
            ) from exc

        return data, len(data), _hash_bytes(data)

    if isinstance(value, bytes):
        if len(value) > MAX_INPUT_BYTES:
            raise DetectorInputError(
                f"Input exceeds maximum size of {MAX_INPUT_BYTES} bytes"
            )
        return value, len(value), _hash_bytes(value)

    if isinstance(value, bytearray):
        data = bytes(value)
        if len(data) > MAX_INPUT_BYTES:
            raise DetectorInputError(
                f"Input exceeds maximum size of {MAX_INPUT_BYTES} bytes"
            )
        return data, len(data), _hash_bytes(data)

    if isinstance(value, str):
        data = value.encode("utf-8", errors="replace")
        if len(data) > MAX_INPUT_BYTES:
            raise DetectorInputError(
                f"Input exceeds maximum size of {MAX_INPUT_BYTES} bytes"
            )
        return value, len(data), _hash_bytes(data)

    normalized = _object_to_mapping(value)
    size = _estimate_input_size(normalized)

    if size > MAX_INPUT_BYTES:
        raise DetectorInputError(
            f"Input exceeds maximum estimated size of {MAX_INPUT_BYTES} bytes"
        )

    try:
        canonical = json.dumps(
            normalized,
            sort_keys=True,
            default=_json_default,
            separators=(",", ":"),
        )
    except Exception:
        canonical = repr(normalized)

    return normalized, size, _hash_text(canonical)


def _json_default(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value

    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return dataclasses.asdict(value)

    if isinstance(value, bytes):
        return value[:4096].hex()

    return _safe_text(value, MAX_VALUE_LENGTH)


# ---------------------------------------------------------------------------
# Indicator taxonomy
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _Rule:
    category: str
    indicator: str
    title: str
    description: str
    patterns: Tuple[str, ...]
    score: float
    severity: DetectionSeverity
    confidence: DetectionConfidence
    action: SuggestedAction
    tags: Tuple[str, ...] = ()
    exact_tokens: Tuple[str, ...] = ()
    negative_patterns: Tuple[str, ...] = ()


# Strong structural indicators. These names align with the extraction/CDR
# modules used elsewhere in pharos-cdr.
_RULES: Tuple[_Rule, ...] = (
    _Rule(
        "macro",
        "vba_macro",
        "VBA macro content",
        "The document contains VBA macro material.",
        (
            r"\bvba_project\b",
            r"\bvba_macro\b",
            r"\bvba\b",
            r"\bmacro\b",
            r"vba_project\.bin",
            r"vba_data\.xml",
        ),
        32,
        DetectionSeverity.MEDIUM,
        DetectionConfidence.HIGH,
        SuggestedAction.REMOVE,
        ("office", "active_content", "macro"),
    ),
    _Rule(
        "macro",
        "xlm_macro",
        "Excel 4 XLM macro content",
        "The document contains Excel 4 macro-sheet indicators.",
        (
            r"\bxlm\b",
            r"\bmacro_sheet\b",
            r"\bmacrosheet\b",
            r"get\.cell",
            r"get\.document",
            r"get\.workbook",
            r"\bexec\s*\(",
            r"\bcall\s*\(",
            r"\brun\s*\(",
        ),
        42,
        DetectionSeverity.HIGH,
        DetectionConfidence.HIGH,
        SuggestedAction.REMOVE,
        ("office", "active_content", "xlm"),
    ),
    _Rule(
        "office",
        "activex",
        "ActiveX control",
        "The document contains ActiveX/control content.",
        (
            r"\bactivex\b",
            r"active_x",
            r"control\d*\.xml",
            r"embeddings[/\\]oleobject",
        ),
        48,
        DetectionSeverity.HIGH,
        DetectionConfidence.HIGH,
        SuggestedAction.REMOVE,
        ("office", "active_content"),
    ),
    _Rule(
        "office",
        "dde",
        "Dynamic Data Exchange",
        "The document contains Dynamic Data Exchange indicators.",
        (
            r"\bdde\b",
            r"dynamic_data_exchange",
            r"\bddeauto\b",
            r"field.*dde",
        ),
        62,
        DetectionSeverity.HIGH,
        DetectionConfidence.HIGH,
        SuggestedAction.REMOVE,
        ("office", "execution", "external_content"),
    ),
    _Rule(
        "office",
        "remote_template",
        "Remote template reference",
        "The document references a remote or external template.",
        (
            r"attachedtemplate",
            r"remote_template",
            r"attached_template",
            r"template_url",
            r"globaltemplate",
            r"normaltemplate",
        ),
        50,
        DetectionSeverity.HIGH,
        DetectionConfidence.HIGH,
        SuggestedAction.REMOVE,
        ("office", "external_content"),
    ),
    _Rule(
        "office",
        "embedded_executable",
        "Embedded executable payload",
        "The document contains an embedded executable or executable signature.",
        (
            r"\bembedded_executable\b",
            r"\bexecutable_payload\b",
            r"\bpe_payload\b",
            r"\belf_payload\b",
            r"\bmacho_payload\b",
            r"\bexecutable\b",
            r"\bportable_executable\b",
        ),
        78,
        DetectionSeverity.CRITICAL,
        DetectionConfidence.HIGH,
        SuggestedAction.REJECT,
        ("payload", "embedded", "executable"),
    ),
    _Rule(
        "payload",
        "embedded_script",
        "Embedded script payload",
        "The document contains an embedded script or script-like payload.",
        (
            r"\bembedded_script\b",
            r"\bscript_payload\b",
            r"\bpowershell_payload\b",
            r"\bjavascript_payload\b",
            r"\bvbscript_payload\b",
            r"\bshell_payload\b",
            r"\bbatch_payload\b",
        ),
        54,
        DetectionSeverity.HIGH,
        DetectionConfidence.HIGH,
        SuggestedAction.REMOVE,
        ("payload", "embedded", "script"),
    ),
    _Rule(
        "payload",
        "embedded_object",
        "Embedded object",
        "The document contains an embedded object that requires CDR inspection.",
        (
            r"\bembedded_object\b",
            r"\bembedded_objects\b",
            r"\bole_object\b",
            r"\boleobject\b",
            r"\bpackage\b",
        ),
        25,
        DetectionSeverity.MEDIUM,
        DetectionConfidence.MEDIUM,
        SuggestedAction.SANITIZE,
        ("embedded", "office"),
    ),
    _Rule(
        "payload",
        "high_entropy_payload",
        "High-entropy payload",
        "A payload or document component exhibits unusually high entropy.",
        (
            r"\bhigh_entropy\b",
            r"\bhigh_entropy_payload\b",
            r"\bpacked\b",
            r"\bcompressed_payload\b",
            r"\bentropy_anomaly\b",
        ),
        30,
        DetectionSeverity.MEDIUM,
        DetectionConfidence.MEDIUM,
        SuggestedAction.REVIEW,
        ("payload", "obfuscation"),
    ),
    _Rule(
        "payload",
        "encoded_payload",
        "Encoded payload",
        "The analysis identifies encoded content that may conceal executable or script material.",
        (
            r"\bencoded_payload\b",
            r"\bbase64_payload\b",
            r"\bhex_payload\b",
            r"\bxor_payload\b",
            r"\bpayload_transform\b",
            r"\bencoding\b",
            r"\bencoded_command\b",
        ),
        35,
        DetectionSeverity.MEDIUM,
        DetectionConfidence.MEDIUM,
        SuggestedAction.SANITIZE,
        ("payload", "encoding"),
    ),
    _Rule(
        "payload",
        "payload_decoder",
        "Payload decoder",
        "The content contains static indicators of payload decoding or transformation.",
        (
            r"\bpayload_decoder\b",
            r"\bdecoder\b",
            r"frombase64string",
            r"certutil.*-decode",
            r"base64\s+-d",
            r"xxd\s+-r\s+-p",
            r"decode\s*\(",
        ),
        48,
        DetectionSeverity.HIGH,
        DetectionConfidence.HIGH,
        SuggestedAction.SANITIZE,
        ("payload", "decoder", "transform"),
    ),
    _Rule(
        "execution",
        "dynamic_execution",
        "Dynamic execution",
        "The analysis identifies dynamic code or command execution capability.",
        (
            r"\bdynamic_execution\b",
            r"\binvoke_expression\b",
            r"\binvokexpression\b",
            r"\beval\b",
            r"\bexecute\b",
            r"\bexecuteglobal\b",
            r"\bcreateprocess\b",
            r"\bshell_execute\b",
        ),
        60,
        DetectionSeverity.HIGH,
        DetectionConfidence.HIGH,
        SuggestedAction.REMOVE,
        ("execution", "dynamic"),
    ),
    _Rule(
        "execution",
        "process_execution",
        "Process execution",
        "The analysis identifies process or command interpreter execution.",
        (
            r"\bprocess_execution\b",
            r"\bprocess_creation\b",
            r"\bshell_execution\b",
            r"\bcommand_interpreter\b",
            r"\bscript_host\b",
            r"\bcreateprocess[a-z]*\b",
            r"\bwinexec\b",
            r"\bshellexecute[a-z]*\b",
            r"\bwscript\.shell\b",
        ),
        58,
        DetectionSeverity.HIGH,
        DetectionConfidence.HIGH,
        SuggestedAction.REMOVE,
        ("execution", "process"),
    ),
    _Rule(
        "execution",
        "command_shell",
        "Command shell execution",
        "The content contains command interpreter execution indicators.",
        (
            r"\bcmd\.exe\b",
            r"\bpowershell(?:\.exe)?\b",
            r"\bwscript\.exe\b",
            r"\bcscript\.exe\b",
            r"\bmshta\.exe\b",
            r"\brundll32\.exe\b",
            r"\bregsvr32\.exe\b",
            r"\bwmic\.exe\b",
        ),
        52,
        DetectionSeverity.HIGH,
        DetectionConfidence.HIGH,
        SuggestedAction.REMOVE,
        ("execution", "lolbin"),
    ),
    _Rule(
        "execution",
        "signed_binary_proxy",
        "Signed binary proxy execution",
        "The content references a commonly abused signed system binary proxy.",
        (
            r"\bmshta(?:\.exe)?\b",
            r"\brundll32(?:\.exe)?\b",
            r"\bregsvr32(?:\.exe)?\b",
            r"\binstallutil(?:\.exe)?\b",
            r"\bregasm(?:\.exe)?\b",
            r"\bmsbuild(?:\.exe)?\b",
            r"\bwmic(?:\.exe)?\b",
            r"\bcertutil(?:\.exe)?\b",
            r"\bbitsadmin(?:\.exe)?\b",
        ),
        45,
        DetectionSeverity.HIGH,
        DetectionConfidence.HIGH,
        SuggestedAction.REMOVE,
        ("execution", "living_off_the_land", "signed_binary_proxy"),
    ),
    _Rule(
        "network",
        "network_communication",
        "Network communication capability",
        "The analysis identifies network communication behavior or references.",
        (
            r"\bnetwork\b",
            r"\bnetwork_connection\b",
            r"\bcommunication\b",
            r"\bhttp\b",
            r"\bhttps\b",
            r"\bsocket\b",
            r"\bdns\b",
            r"\bwininet\b",
            r"\bwinhttp\b",
        ),
        20,
        DetectionSeverity.LOW,
        DetectionConfidence.MEDIUM,
        SuggestedAction.SANITIZE,
        ("network",),
    ),
    _Rule(
        "network",
        "network_download",
        "Network payload retrieval",
        "The content contains indicators of retrieving content from a network resource.",
        (
            r"\bnetwork_download\b",
            r"\bdownload\b",
            r"\burlmon\b",
            r"\burl_download\b",
            r"\bhttpclient\b",
            r"\bwinhttprequest\b",
            r"\bxmlhttp\b",
            r"\bdownloadfile\b",
            r"\bdownloadstring\b",
        ),
        48,
        DetectionSeverity.HIGH,
        DetectionConfidence.HIGH,
        SuggestedAction.SANITIZE,
        ("network", "download", "payload"),
    ),
    _Rule(
        "persistence",
        "persistence",
        "Persistence capability",
        "The analysis identifies a mechanism commonly associated with persistence.",
        (
            r"\bpersistence\b",
            r"\bregistry_persistence\b",
            r"\bservice_persistence\b",
            r"\bscheduled_task\b",
            r"\bstartup\b",
            r"\bautorun\b",
            r"\brun_key\b",
            r"\bstartup_folder\b",
        ),
        62,
        DetectionSeverity.HIGH,
        DetectionConfidence.HIGH,
        SuggestedAction.REMOVE,
        ("persistence",),
    ),
    _Rule(
        "credential",
        "credential_access",
        "Credential access capability",
        "The analysis identifies credential or token access indicators.",
        (
            r"\bcredential_access\b",
            r"\bcredential_collection\b",
            r"\bcredentials\b",
            r"\bpassword\b",
            r"\bpasswords\b",
            r"\btoken_manipulation\b",
            r"\bcredential_manager\b",
            r"\blsass\b",
        ),
        55,
        DetectionSeverity.HIGH,
        DetectionConfidence.MEDIUM,
        SuggestedAction.REMOVE,
        ("credential_access",),
    ),
    _Rule(
        "collection",
        "data_collection",
        "Data collection capability",
        "The analysis identifies collection of local or user data.",
        (
            r"\bcollection\b",
            r"\bdata_collection\b",
            r"\bdocument_collection\b",
            r"\bfile_collection\b",
            r"\bclipboard\b",
            r"\bkeylogging\b",
            r"\bbrowser_data\b",
        ),
        40,
        DetectionSeverity.HIGH,
        DetectionConfidence.MEDIUM,
        SuggestedAction.SANITIZE,
        ("collection",),
    ),
    _Rule(
        "exfiltration",
        "data_exfiltration",
        "Data exfiltration capability",
        "The analysis identifies transmission of collected data.",
        (
            r"\bexfiltration\b",
            r"\bdata_exfiltration\b",
            r"\bupload\b",
            r"\bhttp_post\b",
            r"\bftp\b",
            r"\bsend_data\b",
        ),
        58,
        DetectionSeverity.HIGH,
        DetectionConfidence.MEDIUM,
        SuggestedAction.REMOVE,
        ("exfiltration", "network"),
    ),
    _Rule(
        "evasion",
        "defense_evasion",
        "Defense evasion capability",
        "The analysis identifies anti-analysis or defense-evasion behavior.",
        (
            r"\bevasion\b",
            r"\bdefense_evasion\b",
            r"\banti_analysis\b",
            r"\banti_debugging\b",
            r"\banti_vm\b",
            r"\banti_sandbox\b",
            r"\bdebugger_artifacts\b",
            r"\bvirtualization_artifacts\b",
            r"\bsandbox_artifacts\b",
        ),
        52,
        DetectionSeverity.HIGH,
        DetectionConfidence.HIGH,
        SuggestedAction.REMOVE,
        ("evasion",),
    ),
    _Rule(
        "evasion",
        "security_impairment",
        "Security-control impairment",
        "The analysis identifies attempts to disable or impair security controls.",
        (
            r"\bsecurity_software_impairment\b",
            r"\blogging_impairment\b",
            r"\bav_impairment\b",
            r"\bfirewall_impairment\b",
            r"\buninstall_security\b",
            r"\bsecurity_impairment\b",
            r"\bdisable.*defender\b",
            r"\bstop.*security\b",
        ),
        78,
        DetectionSeverity.CRITICAL,
        DetectionConfidence.HIGH,
        SuggestedAction.REJECT,
        ("evasion", "security", "impairment"),
    ),
    _Rule(
        "evasion",
        "amsi_etw_bypass",
        "AMSI/ETW bypass indicator",
        "The analysis identifies static indicators associated with AMSI or ETW bypass.",
        (
            r"\bamsi_bypass\b",
            r"\betw_bypass\b",
            r"\bamsiutils\b",
            r"\bamsiinitfailed\b",
            r"\betweventwrite\b",
            r"\bamsiopen\b",
            r"\bamsiscanbuffer\b",
        ),
        82,
        DetectionSeverity.CRITICAL,
        DetectionConfidence.HIGH,
        SuggestedAction.REJECT,
        ("evasion", "security", "bypass"),
    ),
    _Rule(
        "memory",
        "process_injection",
        "Process injection capability",
        "The analysis identifies static indicators of process-memory injection.",
        (
            r"\bprocess_injection\b",
            r"\binjection\b",
            r"\bremote_thread\b",
            r"\bvirtualallocex\b",
            r"\bwriteprocessmemory\b",
            r"\bcreateremotethread\b",
            r"\bqueueuserapc\b",
        ),
        82,
        DetectionSeverity.CRITICAL,
        DetectionConfidence.HIGH,
        SuggestedAction.REJECT,
        ("memory", "injection", "execution"),
    ),
    _Rule(
        "memory",
        "in_memory_payload",
        "In-memory payload capability",
        "The analysis identifies indicators of loading or transforming payloads in memory.",
        (
            r"\bin_memory_payload\b",
            r"\breflective_payload\b",
            r"\breflective_loader\b",
            r"\bmemory_loader\b",
            r"\bvirtualalloc\b",
            r"\bvirtualprotect\b",
            r"\bloadlibrary\b",
            r"\bgetprocaddress\b",
        ),
        70,
        DetectionSeverity.HIGH,
        DetectionConfidence.HIGH,
        SuggestedAction.REJECT,
        ("memory", "payload"),
    ),
    _Rule(
        "dynamic",
        "dynamic_resolution",
        "Dynamic API or symbol resolution",
        "The analysis identifies dynamic resolution of functions or symbols.",
        (
            r"\bdynamic_resolution\b",
            r"\bgetprocaddress\b",
            r"\bloadlibrary\b",
            r"\breflection\b",
            r"\bcom_automation\b",
            r"\bcreateobject\b",
            r"\bgettype\b",
        ),
        48,
        DetectionSeverity.HIGH,
        DetectionConfidence.MEDIUM,
        SuggestedAction.SANITIZE,
        ("dynamic", "resolution"),
    ),
    _Rule(
        "obfuscation",
        "obfuscation",
        "Obfuscation indicator",
        "The analysis identifies static obfuscation or concealment indicators.",
        (
            r"\bobfuscation\b",
            r"\bobfuscated\b",
            r"\bencoded\b",
            r"\bpacking\b",
            r"\bpacked\b",
            r"\bstring_split\b",
            r"\bchr\s*\(",
            r"\basc\s*\(",
        ),
        32,
        DetectionSeverity.MEDIUM,
        DetectionConfidence.MEDIUM,
        SuggestedAction.SANITIZE,
        ("obfuscation",),
    ),
    _Rule(
        "artifact",
        "artifact_cleanup",
        "Artifact cleanup",
        "The analysis identifies deletion or cleanup intended to remove artifacts.",
        (
            r"\bartifact_removal\b",
            r"\bartifact_cleanup\b",
            r"\bfile_deletion\b",
            r"\blog_clearing\b",
            r"\bhistory_clearing\b",
            r"\btimestamp_manipulation\b",
            r"\bdelete.*log\b",
            r"\bclear.*history\b",
        ),
        48,
        DetectionSeverity.HIGH,
        DetectionConfidence.MEDIUM,
        SuggestedAction.REMOVE,
        ("evasion", "cleanup"),
    ),
    _Rule(
        "environment",
        "environment_aware_execution",
        "Environment-aware execution",
        "The analysis identifies execution conditioned on environment, locale, user, or sandbox state.",
        (
            r"\benvironment_aware_execution\b",
            r"\benvironment_checks\b",
            r"\buser_interaction_checks\b",
            r"\blocale_checks\b",
            r"\bdomain_checks\b",
            r"\bvm_sandbox_checks\b",
            r"\bsandbox_artifacts\b",
        ),
        42,
        DetectionSeverity.MEDIUM,
        DetectionConfidence.MEDIUM,
        SuggestedAction.REVIEW,
        ("evasion", "environment"),
    ),
    _Rule(
        "container",
        "nested_payload",
        "Nested payload",
        "The analysis identifies payloads nested inside containers or embedded objects.",
        (
            r"\bnested_payload\b",
            r"\bnested_objects\b",
            r"\bcontainer_payload\b",
            r"\barchive_payload\b",
            r"\bcompressed_payload\b",
        ),
        36,
        DetectionSeverity.MEDIUM,
        DetectionConfidence.MEDIUM,
        SuggestedAction.SANITIZE,
        ("payload", "container", "nested"),
    ),
)


# ---------------------------------------------------------------------------
# Content signatures
# ---------------------------------------------------------------------------

_MAGIC_SIGNATURES: Tuple[
    Tuple[str, bytes, str, DetectionSeverity, float],
    ...,
] = (
    ("pe", b"MZ", "executable_payload", DetectionSeverity.CRITICAL, 82.0),
    ("elf", b"\x7fELF", "elf_payload", DetectionSeverity.CRITICAL, 82.0),
    ("pdf", b"%PDF-", "pdf_payload", DetectionSeverity.MEDIUM, 15.0),
    ("rtf", b"{\\rtf", "rtf_payload", DetectionSeverity.MEDIUM, 18.0),
    ("ole", bytes.fromhex("D0CF11E0A1B11AE1"), "ole_payload", DetectionSeverity.HIGH, 38.0),
    ("zip", b"PK\x03\x04", "archive_payload", DetectionSeverity.LOW, 12.0),
    ("gzip", b"\x1f\x8b", "compressed_payload", DetectionSeverity.LOW, 12.0),
)


# ---------------------------------------------------------------------------
# Text extraction
# ---------------------------------------------------------------------------


def _decode_candidate_bytes(data: bytes) -> str:
    """
    Produce a bounded textual representation from arbitrary bytes.

    No executable interpretation is performed.
    """
    if not data:
        return ""

    sample = data[:MAX_INPUT_BYTES]

    candidates = [
        sample.decode("utf-8", errors="ignore"),
        sample.decode("utf-16le", errors="ignore"),
        sample.decode("utf-16be", errors="ignore"),
        sample.decode("latin-1", errors="ignore"),
    ]

    # Prefer the candidate containing the greatest number of printable chars.
    best = max(
        candidates,
        key=lambda text: sum(
            1 for char in text[:MAX_TEXT_LENGTH] if char.isprintable()
        ),
        default="",
    )

    return best[:MAX_TEXT_LENGTH]


def _extract_text_sources(value: Any) -> List[Tuple[str, str]]:
    """
    Extract bounded textual sources from raw detector input.
    """
    sources: List[Tuple[str, str]] = []

    if isinstance(value, bytes):
        text = _decode_candidate_bytes(value)
        if text:
            sources.append(("<bytes>", text))
        return sources

    if isinstance(value, str):
        if value:
            sources.append(("<text>", value[:MAX_TEXT_LENGTH]))
        return sources

    flattened = _flatten_input(value)

    for path, key, text in flattened:
        if not text:
            continue

        if len(sources) >= MAX_ITEMS:
            break

        sources.append(
            (
                path or key or "<analysis>",
                text[:MAX_TEXT_LENGTH],
            )
        )

    return sources


# ---------------------------------------------------------------------------
# Structural feature extraction
# ---------------------------------------------------------------------------


def _normalized_search_text(path: str, text: str) -> str:
    """
    Build searchable text from a field path and value.
    """
    return (
        f"{path}\n{text}"
    ).lower()[:MAX_TEXT_LENGTH + MAX_PATH_LENGTH]


def _is_feature_key(key: str) -> bool:
    """
    Return True for numeric feature-vector fields that should be interpreted
    as detector signals.
    """
    normalized = _normalize_name(key)

    prefixes = (
        "category_",
        "capability_",
        "indicator_",
        "combination_",
        "feature_",
        "signal_",
        "risk_",
        "payload_",
        "behavior_",
    )

    return normalized.startswith(prefixes)


def _collect_numeric_features(value: Any) -> Dict[str, float]:
    """
    Collect explicitly named numeric feature-vector values.

    Generic numeric values are ignored to avoid treating arbitrary metadata
    such as file size or page count as malicious indicators.
    """
    result: Dict[str, float] = {}

    flattened = _flatten_input(value)

    for path, key, text in flattened:
        candidate_key = _normalize_name(key or path)

        if not _is_feature_key(candidate_key):
            continue

        number = _safe_float(text, float("nan"))

        if not math.isfinite(number):
            continue

        result[candidate_key] = result.get(candidate_key, 0.0) + number

        if len(result) >= MAX_FEATURES:
            break

    return result


def _positive_feature_names(
    features: Mapping[str, float],
) -> Set[str]:
    """
    Return positive feature names from a numeric feature vector.
    """
    positive: Set[str] = set()

    for name, value in features.items():
        if _safe_float(value) <= 0:
            continue

        normalized = _normalize_name(name)

        if normalized.startswith(
            (
                "category_",
                "capability_",
                "indicator_",
                "combination_",
                "signal_",
                "behavior_",
                "payload_",
            )
        ):
            positive.add(normalized)

    return positive


# ---------------------------------------------------------------------------
# Finding generation
# ---------------------------------------------------------------------------


def _rule_matches(
    rule: _Rule,
    source_text: str,
) -> List[str]:
    """
    Return matched pattern strings for a rule.
    """
    if not source_text:
        return []

    matches: List[str] = []

    for pattern in rule.patterns:
        try:
            if re.search(
                pattern,
                source_text,
                flags=re.IGNORECASE,
            ):
                matches.append(pattern)
        except re.error:
            continue

        if len(matches) >= 32:
            break

    for negative in rule.negative_patterns:
        try:
            if re.search(
                negative,
                source_text,
                flags=re.IGNORECASE,
            ):
                return []
        except re.error:
            continue

    return matches


def _finding_id(
    category: str,
    indicator: str,
    path: str,
    source: str,
) -> str:
    canonical = "|".join(
        [
            _normalize_name(category),
            _normalize_name(indicator),
            _safe_text(path, MAX_PATH_LENGTH),
            _safe_text(source, MAX_PATH_LENGTH),
        ]
    )

    digest = hashlib.sha256(
        canonical.encode("utf-8", errors="replace")
    ).hexdigest()[:20]

    return f"det-{digest}"


def _evidence_id(evidence: DetectionEvidence) -> str:
    canonical = json.dumps(
        {
            "category": evidence.category,
            "indicator": evidence.indicator,
            "source": evidence.source,
            "path": evidence.path,
            "value": evidence.value[:512],
        },
        sort_keys=True,
        separators=(",", ":"),
    )

    return hashlib.sha256(
        canonical.encode("utf-8", errors="replace")
    ).hexdigest()[:20]


def _make_evidence(
    rule: _Rule,
    *,
    source: str,
    path: str,
    matched_patterns: Sequence[str],
    value: str,
    score: Optional[float] = None,
) -> DetectionEvidence:
    pattern_text = ", ".join(
        _safe_text(pattern, 256)
        for pattern in matched_patterns[:8]
    )

    description = rule.description

    if pattern_text:
        description = f"{description} Matched indicators: {pattern_text}."

    return DetectionEvidence(
        category=rule.category,
        indicator=rule.indicator,
        description=description,
        source=source,
        path=path,
        value=value[:MAX_VALUE_LENGTH],
        severity=rule.severity,
        confidence=rule.confidence,
        score=rule.score if score is None else score,
        tags=rule.tags,
        metadata={
            "rule_score": rule.score,
            "matched_pattern_count": len(matched_patterns),
        },
    )


def _merge_finding_evidence(
    findings: MutableMapping[str, DetectionFinding],
    evidence: DetectionEvidence,
    rule: _Rule,
) -> None:
    """
    Add evidence to a finding, deduplicating deterministically.
    """
    finding_id = _finding_id(
        rule.category,
        rule.indicator,
        evidence.path,
        evidence.source,
    )

    existing = findings.get(finding_id)

    if existing is None:
        findings[finding_id] = DetectionFinding(
            finding_id=finding_id,
            category=rule.category,
            indicator=rule.indicator,
            title=rule.title,
            description=rule.description,
            severity=rule.severity,
            confidence=rule.confidence,
            score=rule.score,
            suggested_action=rule.action,
            path=evidence.path,
            source=evidence.source,
            evidence=(evidence,),
            tags=rule.tags,
            metadata={
                "rule": rule.indicator,
            },
        )
        return

    evidence_keys = {
        (
            item.category,
            item.indicator,
            item.source,
            item.path,
            item.value,
        )
        for item in existing.evidence
    }

    key = (
        evidence.category,
        evidence.indicator,
        evidence.source,
        evidence.path,
        evidence.value,
    )

    if key in evidence_keys:
        return

    combined_evidence = tuple(
        list(existing.evidence) + [evidence]
    )[:MAX_EVIDENCE]

    best_score = max(existing.score, evidence.score)
    best_severity = _severity_max(
        [existing.severity, evidence.severity]
    )

    findings[finding_id] = DetectionFinding(
        finding_id=existing.finding_id,
        category=existing.category,
        indicator=existing.indicator,
        title=existing.title,
        description=existing.description,
        severity=best_severity,
        confidence=existing.confidence,
        score=best_score,
        suggested_action=_action_max(
            [existing.suggested_action, rule.action]
        ),
        path=existing.path or evidence.path,
        source=existing.source or evidence.source,
        evidence=combined_evidence,
        tags=tuple(
            sorted(
                set(existing.tags).union(rule.tags)
            )
        ),
        metadata=existing.metadata,
    )


def _detect_rules(
    sources: Sequence[Tuple[str, str]],
    *,
    max_findings: int,
    max_evidence: int,
) -> Tuple[List[DetectionFinding], List[DetectionEvidence]]:
    findings: Dict[str, DetectionFinding] = {}

    evidence_count = 0

    for source, text in sources:
        if len(findings) >= max_findings:
            break

        searchable = _normalized_search_text(source, text)

        for rule in _RULES:
            if len(findings) >= max_findings:
                break

            if evidence_count >= max_evidence:
                break

            matches = _rule_matches(rule, searchable)

            if not matches:
                continue

            evidence = _make_evidence(
                rule,
                source=source,
                path=source,
                matched_patterns=matches,
                value=text[:MAX_VALUE_LENGTH],
            )

            before = len(findings)
            _merge_finding_evidence(
                findings,
                evidence,
                rule,
            )

            if len(findings) > before:
                evidence_count += 1

    ordered = sorted(
        findings.values(),
        key=lambda finding: (
            -RISK_ORDER.get(finding.severity.value, 0),
            -finding.score,
            finding.category,
            finding.indicator,
            finding.finding_id,
        ),
    )

    evidence: List[DetectionEvidence] = []

    for finding in ordered:
        evidence.extend(finding.evidence)

    return (
        ordered[:max_findings],
        evidence[:max_evidence],
    )


# ---------------------------------------------------------------------------
# Signature detection
# ---------------------------------------------------------------------------


def _detect_content_signatures(
    value: Any,
) -> List[DetectionFinding]:
    """
    Detect strong binary content signatures without parsing/executing them.
    """
    if not isinstance(value, (bytes, bytearray)):
        return []

    data = bytes(value)
    findings: List[DetectionFinding] = []

    for name, magic, indicator, severity, score in _MAGIC_SIGNATURES:
        if not data.startswith(magic):
            continue

        category = (
            "payload"
            if indicator.endswith("_payload") or "payload" in indicator
            else "container"
        )

        title = f"{name.upper()} content signature"

        evidence = DetectionEvidence(
            category=category,
            indicator=indicator,
            description=(
                f"Input begins with a known {name.upper()} content signature."
            ),
            source="<binary>",
            path="<binary>",
            value=magic.hex(),
            severity=severity,
            confidence=DetectionConfidence.HIGH,
            score=score,
            tags=("signature", name),
            metadata={
                "magic_length": len(magic),
            },
        )

        finding_id = _finding_id(
            category,
            indicator,
            "<binary>",
            "<binary>",
        )

        findings.append(
            DetectionFinding(
                finding_id=finding_id,
                category=category,
                indicator=indicator,
                title=title,
                description=evidence.description,
                severity=severity,
                confidence=DetectionConfidence.HIGH,
                score=score,
                suggested_action=(
                    SuggestedAction.REJECT
                    if severity == DetectionSeverity.CRITICAL
                    else SuggestedAction.SANITIZE
                ),
                path="<binary>",
                source="<binary>",
                evidence=(evidence,),
                tags=("signature", name),
                metadata={
                    "signature": name,
                    "magic": magic.hex(),
                },
            )
        )

    return findings


# ---------------------------------------------------------------------------
# OOXML structural inspection
# ---------------------------------------------------------------------------


def _safe_zip_signature_findings(
    data: bytes,
) -> List[DetectionFinding]:
    """
    Inspect ZIP/OOXML central-directory names without extracting entries.

    This is intentionally limited to metadata and filenames. No archive
    member is executed or materialized onto the host filesystem.
    """
    if not data.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")):
        return []

    findings: List[DetectionFinding] = []

    try:
        import io

        with zipfile.ZipFile(io.BytesIO(data), "r") as archive:
            infos = archive.infolist()

            if len(infos) > MAX_ZIP_ENTRIES:
                infos = infos[:MAX_ZIP_ENTRIES]

            names = [
                info.filename[:MAX_PATH_LENGTH]
                for info in infos
                if info.filename
            ]

            total_uncompressed = sum(
                min(
                    max(0, int(info.file_size)),
                    MAX_ZIP_ENTRY_SIZE,
                )
                for info in infos
            )

            lowered = "\n".join(names).lower()

            structural_rules = (
                (
                    "macro",
                    "vba_project",
                    "vba_project.bin",
                    65.0,
                    DetectionSeverity.HIGH,
                    SuggestedAction.REMOVE,
                ),
                (
                    "macro",
                    "xlm_macro",
                    "xl/macrosheets/",
                    65.0,
                    DetectionSeverity.HIGH,
                    SuggestedAction.REMOVE,
                ),
                (
                    "office",
                    "activex",
                    "activeX/",
                    55.0,
                    DetectionSeverity.HIGH,
                    SuggestedAction.REMOVE,
                ),
                (
                    "office",
                    "external_relationship",
                    "externalLinks/",
                    38.0,
                    DetectionSeverity.MEDIUM,
                    SuggestedAction.SANITIZE,
                ),
                (
                    "payload",
                    "embedded_object",
                    "embeddings/",
                    32.0,
                    DetectionSeverity.MEDIUM,
                    SuggestedAction.SANITIZE,
                ),
                (
                    "payload",
                    "embedded_package",
                    "embeddings/",
                    40.0,
                    DetectionSeverity.MEDIUM,
                    SuggestedAction.SANITIZE,
                ),
            )

            for (
                category,
                indicator,
                marker,
                score,
                severity,
                action,
            ) in structural_rules:
                if marker.lower() not in lowered:
                    continue

                evidence = DetectionEvidence(
                    category=category,
                    indicator=indicator,
                    description=(
                        f"OOXML ZIP structure contains the marker "
                        f"{marker!r}."
                    ),
                    source="zip_structure",
                    path=marker,
                    value=marker,
                    severity=severity,
                    confidence=DetectionConfidence.HIGH,
                    score=score,
                    tags=("ooxml", "structure"),
                    metadata={
                        "entry_count": len(names),
                    },
                )

                finding_id = _finding_id(
                    category,
                    indicator,
                    marker,
                    "zip_structure",
                )

                findings.append(
                    DetectionFinding(
                        finding_id=finding_id,
                        category=category,
                        indicator=indicator,
                        title=indicator.replace("_", " ").title(),
                        description=evidence.description,
                        severity=severity,
                        confidence=DetectionConfidence.HIGH,
                        score=score,
                        suggested_action=action,
                        path=marker,
                        source="zip_structure",
                        evidence=(evidence,),
                        tags=("ooxml", "structure"),
                        metadata={
                            "entry_count": len(names),
                        },
                    )
                )

            # A ZIP with an unusually large aggregate uncompressed size can
            # warrant review for decompression/resource abuse. This is not
            # automatically malicious.
            if total_uncompressed > MAX_ZIP_TOTAL_UNCOMPRESSED:
                score = 30.0

                evidence = DetectionEvidence(
                    category="container",
                    indicator="oversized_archive",
                    description=(
                        "The archive declares an unusually large aggregate "
                        "uncompressed size."
                    ),
                    source="zip_structure",
                    path="<archive>",
                    value=str(total_uncompressed),
                    severity=DetectionSeverity.MEDIUM,
                    confidence=DetectionConfidence.HIGH,
                    score=score,
                    tags=("ooxml", "resource_limit"),
                    metadata={
                        "total_uncompressed": total_uncompressed,
                    },
                )

                finding_id = _finding_id(
                    "container",
                    "oversized_archive",
                    "<archive>",
                    "zip_structure",
                )

                findings.append(
                    DetectionFinding(
                        finding_id=finding_id,
                        category="container",
                        indicator="oversized_archive",
                        title="Oversized archive",
                        description=evidence.description,
                        severity=DetectionSeverity.MEDIUM,
                        confidence=DetectionConfidence.HIGH,
                        score=score,
                        suggested_action=SuggestedAction.REVIEW,
                        path="<archive>",
                        source="zip_structure",
                        evidence=(evidence,),
                        tags=("ooxml", "resource_limit"),
                        metadata={
                            "total_uncompressed": total_uncompressed,
                            "entry_count": len(names),
                        },
                    )
                )

    except (
        OSError,
        ValueError,
        RuntimeError,
        zipfile.BadZipFile,
        zipfile.LargeZipFile,
    ):
        # Malformed ZIP structure is itself useful evidence, but it should
        # not crash the detector.
        evidence = DetectionEvidence(
            category="container",
            indicator="malformed_archive",
            description=(
                "Input resembles a ZIP container but could not be parsed "
                "safely as a ZIP archive."
            ),
            source="zip_structure",
            path="<archive>",
            value="malformed_zip",
            severity=DetectionSeverity.MEDIUM,
            confidence=DetectionConfidence.HIGH,
            score=28.0,
            tags=("container", "malformed"),
        )

        findings.append(
            DetectionFinding(
                finding_id=_finding_id(
                    "container",
                    "malformed_archive",
                    "<archive>",
                    "zip_structure",
                ),
                category="container",
                indicator="malformed_archive",
                title="Malformed archive",
                description=evidence.description,
                severity=DetectionSeverity.MEDIUM,
                confidence=DetectionConfidence.HIGH,
                score=28.0,
                suggested_action=SuggestedAction.REVIEW,
                path="<archive>",
                source="zip_structure",
                evidence=(evidence,),
                tags=("container", "malformed"),
            )
        )

    return findings


# ---------------------------------------------------------------------------
# Combination detection
# ---------------------------------------------------------------------------


_COMBINATIONS: Tuple[
    Tuple[
        str,
        str,
        Tuple[str, ...],
        Tuple[str, ...],
        DetectionSeverity,
        DetectionConfidence,
        float,
        SuggestedAction,
    ],
    ...,
] = (
    (
        "download_then_execute",
        "Network retrieval indicators occur together with execution capability.",
        ("network_download", "process_execution"),
        ("network", "execution"),
        DetectionSeverity.CRITICAL,
        DetectionConfidence.HIGH,
        88.0,
        SuggestedAction.REJECT,
    ),
    (
        "macro_network_execution",
        "Macro capability occurs together with network and execution indicators.",
        ("vba_macro", "network_communication", "process_execution"),
        ("macro", "network", "execution"),
        DetectionSeverity.CRITICAL,
        DetectionConfidence.HIGH,
        90.0,
        SuggestedAction.REJECT,
    ),
    (
        "macro_to_process_execution",
        "Macro content is associated with process execution capability.",
        ("vba_macro", "process_execution"),
        ("macro", "execution"),
        DetectionSeverity.CRITICAL,
        DetectionConfidence.HIGH,
        88.0,
        SuggestedAction.REJECT,
    ),
    (
        "encoded_payload_delivery",
        "Encoded payload indicators occur with network delivery indicators.",
        ("encoded_payload", "network_download"),
        ("payload", "network"),
        DetectionSeverity.HIGH,
        DetectionConfidence.HIGH,
        76.0,
        SuggestedAction.REJECT,
    ),
    (
        "decode_then_execute",
        "A payload decoder occurs with execution capability.",
        ("payload_decoder", "process_execution"),
        ("payload", "execution"),
        DetectionSeverity.CRITICAL,
        DetectionConfidence.HIGH,
        90.0,
        SuggestedAction.REJECT,
    ),
    (
        "in_memory_payload_execution",
        "In-memory payload indicators occur with execution capability.",
        ("in_memory_payload", "process_execution"),
        ("memory", "execution"),
        DetectionSeverity.CRITICAL,
        DetectionConfidence.HIGH,
        92.0,
        SuggestedAction.REJECT,
    ),
    (
        "process_injection_payload",
        "Process injection is associated with payload or memory-loading behavior.",
        ("process_injection", "in_memory_payload"),
        ("memory", "payload"),
        DetectionSeverity.CRITICAL,
        DetectionConfidence.HIGH,
        96.0,
        SuggestedAction.REJECT,
    ),
    (
        "credential_collection_exfiltration",
        "Credential collection is combined with outbound data transfer.",
        ("credential_access", "data_exfiltration"),
        ("credential", "exfiltration"),
        DetectionSeverity.CRITICAL,
        DetectionConfidence.HIGH,
        92.0,
        SuggestedAction.REJECT,
    ),
    (
        "collection_exfiltration",
        "Data collection occurs together with outbound transfer.",
        ("data_collection", "data_exfiltration"),
        ("collection", "exfiltration"),
        DetectionSeverity.HIGH,
        DetectionConfidence.MEDIUM,
        78.0,
        SuggestedAction.REJECT,
    ),
    (
        "persistence_execution",
        "Persistence capability is associated with execution.",
        ("persistence", "process_execution"),
        ("persistence", "execution"),
        DetectionSeverity.CRITICAL,
        DetectionConfidence.HIGH,
        86.0,
        SuggestedAction.REJECT,
    ),
    (
        "evasion_execution",
        "Defense evasion indicators occur with execution capability.",
        ("defense_evasion", "process_execution"),
        ("evasion", "execution"),
        DetectionSeverity.CRITICAL,
        DetectionConfidence.HIGH,
        90.0,
        SuggestedAction.REJECT,
    ),
    (
        "evasion_persistence",
        "Defense evasion indicators occur with persistence.",
        ("defense_evasion", "persistence"),
        ("evasion", "persistence"),
        DetectionSeverity.CRITICAL,
        DetectionConfidence.HIGH,
        90.0,
        SuggestedAction.REJECT,
    ),
    (
        "obfuscated_dynamic_execution",
        "Obfuscation occurs with dynamic execution.",
        ("obfuscation", "dynamic_execution"),
        ("obfuscation", "dynamic"),
        DetectionSeverity.HIGH,
        DetectionConfidence.HIGH,
        80.0,
        SuggestedAction.REJECT,
    ),
    (
        "dynamic_resolution_network",
        "Dynamic resolution is combined with network communication.",
        ("dynamic_resolution", "network_communication"),
        ("dynamic", "network"),
        DetectionSeverity.HIGH,
        DetectionConfidence.MEDIUM,
        70.0,
        SuggestedAction.REVIEW,
    ),
    (
        "embedded_executable_document",
        "An embedded executable occurs within document content.",
        ("embedded_executable", "embedded_object"),
        ("payload", "office"),
        DetectionSeverity.CRITICAL,
        DetectionConfidence.HIGH,
        95.0,
        SuggestedAction.REJECT,
    ),
    (
        "container_payload_chain",
        "A container/nested payload is associated with executable or script content.",
        ("nested_payload", "embedded_script"),
        ("container", "payload"),
        DetectionSeverity.HIGH,
        DetectionConfidence.MEDIUM,
        76.0,
        SuggestedAction.REJECT,
    ),
    (
        "signed_proxy_payload",
        "A signed proxy execution mechanism is associated with payload behavior.",
        ("signed_binary_proxy", "embedded_script"),
        ("execution", "payload"),
        DetectionSeverity.CRITICAL,
        DetectionConfidence.HIGH,
        88.0,
        SuggestedAction.REJECT,
    ),
    (
        "security_impairment_persistence",
        "Security-control impairment occurs with persistence capability.",
        ("security_impairment", "persistence"),
        ("evasion", "persistence"),
        DetectionSeverity.CRITICAL,
        DetectionConfidence.HIGH,
        98.0,
        SuggestedAction.REJECT,
    ),
    (
        "execution_with_persistence_and_evasion",
        "Execution, persistence, and evasion capabilities co-occur.",
        ("process_execution", "persistence", "defense_evasion"),
        ("execution", "persistence", "evasion"),
        DetectionSeverity.CRITICAL,
        DetectionConfidence.HIGH,
        99.0,
        SuggestedAction.REJECT,
    ),
)


def _present_indicators(
    findings: Sequence[DetectionFinding],
) -> Set[str]:
    return {
        finding.indicator
        for finding in findings
        if finding.indicator
    }


def _detect_combinations(
    findings: Sequence[DetectionFinding],
) -> List[DetectionCombination]:
    present = _present_indicators(findings)

    evidence_by_indicator: Dict[str, List[str]] = defaultdict(list)

    for finding in findings:
        for evidence in finding.evidence:
            evidence_by_indicator[finding.indicator].append(
                _evidence_id(evidence)
            )

    combinations: List[DetectionCombination] = []

    for (
        name,
        description,
        indicators,
        categories,
        severity,
        confidence,
        score,
        action,
    ) in _COMBINATIONS:
        if not all(indicator in present for indicator in indicators):
            continue

        evidence_ids: List[str] = []

        for indicator in indicators:
            evidence_ids.extend(
                evidence_by_indicator.get(indicator, [])
            )

        combinations.append(
            DetectionCombination(
                name=name,
                description=description,
                indicators=indicators,
                categories=categories,
                severity=severity,
                confidence=confidence,
                score=score,
                suggested_action=action,
                evidence_ids=tuple(sorted(set(evidence_ids))),
            )
        )

    combinations.sort(
        key=lambda item: (
            -RISK_ORDER.get(item.severity.value, 0),
            -item.score,
            item.name,
        )
    )

    return combinations


# ---------------------------------------------------------------------------
# Score calculation
# ---------------------------------------------------------------------------


def _finding_contribution(
    finding: DetectionFinding,
) -> float:
    """
    Calculate bounded contribution of a finding.

    Multiple evidence items do not linearly multiply risk; this prevents a
    verbose analyzer from overwhelming the score.
    """
    evidence_bonus = min(
        12.0,
        max(0.0, math.log1p(len(finding.evidence)) * 4.0),
    )

    severity_multiplier = {
        DetectionSeverity.INFO: 0.25,
        DetectionSeverity.LOW: 0.50,
        DetectionSeverity.MEDIUM: 0.75,
        DetectionSeverity.HIGH: 1.00,
        DetectionSeverity.CRITICAL: 1.15,
    }[finding.severity]

    confidence_multiplier = {
        DetectionConfidence.LOW: 0.80,
        DetectionConfidence.MEDIUM: 1.00,
        DetectionConfidence.HIGH: 1.10,
    }[finding.confidence]

    return min(
        100.0,
        finding.score * severity_multiplier * confidence_multiplier
        + evidence_bonus,
    )


def _aggregate_score(
    findings: Sequence[DetectionFinding],
    combinations: Sequence[DetectionCombination],
) -> float:
    """
    Aggregate risk using diminishing returns.

    The calculation remains deterministic and bounded to [0, 100].
    """
    if not findings and not combinations:
        return 0.0

    contributions = sorted(
        (
            _finding_contribution(finding)
            for finding in findings
        ),
        reverse=True,
    )

    total = 0.0
    weights = (1.0, 0.55, 0.35, 0.25, 0.20)

    for index, contribution in enumerate(contributions):
        weight = (
            weights[index]
            if index < len(weights)
            else 0.15
        )
        total += contribution * weight

    combination_contributions = sorted(
        (
            min(100.0, combination.score)
            for combination in combinations
        ),
        reverse=True,
    )

    if combination_contributions:
        total += combination_contributions[0] * 0.35

        for score in combination_contributions[1:4]:
            total += score * 0.12

    return round(
        max(0.0, min(100.0, total)),
        4,
    )


def _recommended_action(
    *,
    score: float,
    findings: Sequence[DetectionFinding],
    combinations: Sequence[DetectionCombination],
    config: DetectorConfig,
) -> SuggestedAction:
    """
    Determine advisory action.

    Explicit critical/reject indicators always outrank aggregate thresholds.
    """
    if any(
        finding.suggested_action == SuggestedAction.REJECT
        for finding in findings
        if finding.severity == DetectionSeverity.CRITICAL
    ):
        return SuggestedAction.REJECT

    if any(
        combo.suggested_action == SuggestedAction.REJECT
        for combo in combinations
        if combo.severity == DetectionSeverity.CRITICAL
    ):
        return SuggestedAction.REJECT

    if score >= config.block_threshold:
        return SuggestedAction.REJECT

    if score >= config.review_threshold:
        return SuggestedAction.REVIEW

    if any(
        finding.suggested_action == SuggestedAction.REMOVE
        for finding in findings
    ):
        return SuggestedAction.REMOVE

    if any(
        finding.suggested_action == SuggestedAction.SANITIZE
        for finding in findings
    ):
        return SuggestedAction.SANITIZE

    return SuggestedAction.PRESERVE


def _overall_severity(
    score: float,
    findings: Sequence[DetectionFinding],
    combinations: Sequence[DetectionCombination],
) -> DetectionSeverity:
    """
    Determine overall severity using both aggregate score and strongest
    explicit signal.
    """
    score_severity = _severity_from_score(score)

    strongest_finding = _severity_max(
        [finding.severity for finding in findings]
    ) if findings else DetectionSeverity.INFO

    strongest_combination = _severity_max(
        [combo.severity for combo in combinations]
    ) if combinations else DetectionSeverity.INFO

    return _severity_max(
        [
            score_severity,
            strongest_finding,
            strongest_combination,
        ]
    )


# ---------------------------------------------------------------------------
# Feature vector
# ---------------------------------------------------------------------------


def _build_feature_vector(
    findings: Sequence[DetectionFinding],
    combinations: Sequence[DetectionCombination],
    input_size: int,
) -> Dict[str, float]:
    """
    Build a stable scalar detector feature vector.

    All feature values are numeric and suitable for downstream ML alignment.
    """
    vector: Dict[str, float] = {
        "detector_input_size": float(input_size),
        "detector_finding_count": float(len(findings)),
        "detector_evidence_count": float(
            sum(len(finding.evidence) for finding in findings)
        ),
        "detector_combination_count": float(len(combinations)),
        "detector_high_risk_count": float(
            sum(
                1
                for finding in findings
                if finding.is_high_risk
            )
        ),
        "detector_critical_count": float(
            sum(
                1
                for finding in findings
                if finding.severity == DetectionSeverity.CRITICAL
            )
        ),
        "detector_max_score": float(
            max(
                (
                    finding.score
                    for finding in findings
                ),
                default=0.0,
            )
        ),
        "detector_overall_score": float(
            _aggregate_score(findings, combinations)
        ),
    }

    category_counts = Counter(
        finding.category
        for finding in findings
    )

    indicator_counts = Counter(
        finding.indicator
        for finding in findings
    )

    severity_counts = Counter(
        finding.severity.value
        for finding in findings
    )

    action_counts = Counter(
        finding.suggested_action.value
        for finding in findings
    )

    source_counts = Counter(
        finding.source
        for finding in findings
        if finding.source
    )

    for category, count in sorted(category_counts.items()):
        vector[f"category_{category}"] = float(count)

    for indicator, count in sorted(indicator_counts.items()):
        vector[f"indicator_{indicator}"] = float(count)

    for severity, count in sorted(severity_counts.items()):
        vector[f"severity_{severity}"] = float(count)

    for action, count in sorted(action_counts.items()):
        vector[f"action_{action}"] = float(count)

    for source, count in sorted(source_counts.items()):
        normalized = _normalize_name(source)

        if normalized:
            vector[f"source_{normalized}"] = float(count)

    for combination in combinations:
        vector[f"combination_{combination.name}"] = 1.0

    return dict(sorted(vector.items()))


# ---------------------------------------------------------------------------
# Public detection APIs
# ---------------------------------------------------------------------------


def detect(
    value: Any,
    *,
    config: Optional[DetectorConfig] = None,
) -> DetectionResult:
    """
    Detect static document threats and CDR-relevant active content.

    Args:
        value:
            Raw bytes/text/path or analysis output from another module.
        config:
            Optional detector configuration.

    Returns:
        A deterministic :class:`DetectionResult`.
    """
    return detect_document(value, config=config)


def detect_document(
    value: Any,
    *,
    config: Optional[DetectorConfig] = None,
) -> DetectionResult:
    """
    Primary document-level detector API.
    """
    if config is None:
        config = DetectorConfig()

    normalized, input_size, document_sha256 = _read_input(value)

    sources = _extract_text_sources(normalized)

    findings, evidence = _detect_rules(
        sources,
        max_findings=config.max_findings,
        max_evidence=config.max_evidence,
    )

    if config.enable_content_signatures:
        signature_findings = _detect_content_signatures(normalized)

        by_id = {
            finding.finding_id: finding
            for finding in findings
        }

        for finding in signature_findings:
            if finding.finding_id not in by_id:
                by_id[finding.finding_id] = finding

        findings = list(by_id.values())

    if isinstance(normalized, (bytes, bytearray)):
        structural_findings = _safe_zip_signature_findings(
            bytes(normalized)
        )

        by_id = {
            finding.finding_id: finding
            for finding in findings
        }

        for finding in structural_findings:
            if finding.finding_id not in by_id:
                by_id[finding.finding_id] = finding

        findings = list(by_id.values())

    findings.sort(
        key=lambda finding: (
            -RISK_ORDER.get(finding.severity.value, 0),
            -finding.score,
            finding.category,
            finding.indicator,
            finding.finding_id,
        )
    )

    findings = findings[:config.max_findings]

    # Add evidence introduced by structural/signature inspection.
    evidence_map: Dict[str, DetectionEvidence] = {}

    for item in evidence:
        evidence_map[_evidence_id(item)] = item

    for finding in findings:
        for item in finding.evidence:
            evidence_map[_evidence_id(item)] = item

    evidence = list(evidence_map.values())[:config.max_evidence]

    combinations: List[DetectionCombination] = []

    if config.enable_combinations:
        combinations = _detect_combinations(findings)

    overall_score = _aggregate_score(
        findings,
        combinations,
    )

    severity = _overall_severity(
        overall_score,
        findings,
        combinations,
    )

    action = _recommended_action(
        score=overall_score,
        findings=findings,
        combinations=combinations,
        config=config,
    )

    feature_vector = _build_feature_vector(
        findings,
        combinations,
        input_size,
    )

    category_counts = Counter(
        finding.category
        for finding in findings
    )

    indicator_counts = Counter(
        finding.indicator
        for finding in findings
    )

    severity_counts = Counter(
        finding.severity.value
        for finding in findings
    )

    action_counts = Counter(
        finding.suggested_action.value
        for finding in findings
    )

    source_counts = Counter(
        finding.source
        for finding in findings
        if finding.source
    )

    statistics = DetectorStatistics(
        input_size=input_size,
        finding_count=len(findings),
        evidence_count=len(evidence),
        combination_count=len(combinations),
        high_risk_count=sum(
            1
            for finding in findings
            if finding.is_high_risk
        ),
        critical_count=sum(
            1
            for finding in findings
            if finding.severity == DetectionSeverity.CRITICAL
        ),
        category_counts=dict(sorted(category_counts.items())),
        indicator_counts=dict(sorted(indicator_counts.items())),
        severity_counts=dict(sorted(severity_counts.items())),
        action_counts=dict(sorted(action_counts.items())),
        source_counts=dict(sorted(source_counts.items())),
        maximum_score=max(
            (
                finding.score
                for finding in findings
            ),
            default=0.0,
        ),
        aggregate_score=overall_score,
    )

    return DetectionResult(
        detector=MODULE_NAME,
        version=DETECTOR_VERSION,
        document_sha256=document_sha256,
        findings=tuple(findings),
        combinations=tuple(combinations),
        evidence=tuple(evidence),
        feature_vector=feature_vector,
        statistics=statistics,
        overall_score=overall_score,
        overall_severity=severity,
        recommended_action=action,
        metadata={
            "static_only": True,
            "rules": len(_RULES),
            "input_size_limit": MAX_INPUT_BYTES,
            "review_threshold": config.review_threshold,
            "block_threshold": config.block_threshold,
        },
    )


def detect_analysis(
    analysis: Any,
    *,
    config: Optional[DetectorConfig] = None,
) -> DetectionResult:
    """
    Analyze output from one or more extraction/analyzer modules.

    This is an alias-like semantic API intended for callers that already have
    a parsed analysis structure rather than raw document bytes.
    """
    return detect_document(analysis, config=config)


def detect_content(
    content: bytes | bytearray | str,
    *,
    config: Optional[DetectorConfig] = None,
) -> DetectionResult:
    """
    Analyze raw in-memory content.
    """
    return detect_document(content, config=config)


def detect_file(
    path: os.PathLike[str] | str,
    *,
    config: Optional[DetectorConfig] = None,
) -> DetectionResult:
    """
    Analyze a file path without executing or modifying it.
    """
    return detect_document(path, config=config)


# ---------------------------------------------------------------------------
# Result/query helpers
# ---------------------------------------------------------------------------


def findings_by_category(
    result: DetectionResult,
    category: str,
) -> Tuple[DetectionFinding, ...]:
    """
    Return findings belonging to a category.
    """
    normalized = _normalize_name(category)

    return tuple(
        finding
        for finding in result.findings
        if finding.category == normalized
    )


def findings_by_indicator(
    result: DetectionResult,
    indicator: str,
) -> Tuple[DetectionFinding, ...]:
    """
    Return findings matching an indicator.
    """
    normalized = _normalize_name(indicator)

    return tuple(
        finding
        for finding in result.findings
        if finding.indicator == normalized
    )


def high_risk_findings(
    result: DetectionResult,
) -> Tuple[DetectionFinding, ...]:
    """
    Return high and critical findings.
    """
    return tuple(
        finding
        for finding in result.findings
        if finding.is_high_risk
    )


def critical_findings(
    result: DetectionResult,
) -> Tuple[DetectionFinding, ...]:
    """
    Return critical findings.
    """
    return tuple(
        finding
        for finding in result.findings
        if finding.severity == DetectionSeverity.CRITICAL
    )


def present_indicators(
    result: DetectionResult,
) -> Tuple[str, ...]:
    """
    Return unique detected indicators.
    """
    return tuple(
        sorted(
            {
                finding.indicator
                for finding in result.findings
            }
        )
    )


def present_categories(
    result: DetectionResult,
) -> Tuple[str, ...]:
    """
    Return unique detected categories.
    """
    return tuple(
        sorted(
            {
                finding.category
                for finding in result.findings
            }
        )
    )


def present_combinations(
    result: DetectionResult,
) -> Tuple[str, ...]:
    """
    Return names of detected higher-order combinations.
    """
    return tuple(
        combination.name
        for combination in result.combinations
    )


def highest_severity(
    result: DetectionResult,
) -> DetectionSeverity:
    """
    Return the strongest severity represented in a result.
    """
    return result.overall_severity


def highest_score(
    result: DetectionResult,
) -> float:
    """
    Return the highest individual finding score.
    """
    return result.statistics.maximum_score


def feature_vector(
    result: DetectionResult,
) -> Dict[str, float]:
    """
    Return a copy of the stable detector feature vector.
    """
    return dict(result.feature_vector)


def feature_names(
    result: Optional[DetectionResult] = None,
) -> Tuple[str, ...]:
    """
    Return detector feature names.

    If a result is provided, names present in that result are returned.
    Otherwise the stable base feature names are returned.
    """
    if result is not None:
        return tuple(sorted(result.feature_vector.keys()))

    base = {
        "detector_input_size",
        "detector_finding_count",
        "detector_evidence_count",
        "detector_combination_count",
        "detector_high_risk_count",
        "detector_critical_count",
        "detector_max_score",
        "detector_overall_score",
    }

    return tuple(sorted(base))


def build_feature_schema(
    result: Optional[DetectionResult] = None,
) -> Dict[str, str]:
    """
    Return a machine-readable detector feature schema.

    All detector features are numeric scalar values.
    """
    return {
        name: "float"
        for name in feature_names(result)
    }


def summarize(
    result: DetectionResult,
) -> Dict[str, Any]:
    """
    Return a concise machine-readable summary.
    """
    return {
        "detector": result.detector,
        "version": result.version,
        "document_sha256": result.document_sha256,
        "overall_score": result.overall_score,
        "overall_severity": result.overall_severity.value,
        "recommended_action": result.recommended_action.value,
        "finding_count": len(result.findings),
        "evidence_count": len(result.evidence),
        "combination_count": len(result.combinations),
        "high_risk_count": result.statistics.high_risk_count,
        "critical_count": result.statistics.critical_count,
        "categories": list(present_categories(result)),
        "indicators": list(present_indicators(result)),
        "combinations": list(present_combinations(result)),
    }


# ---------------------------------------------------------------------------
# Serialization
# ---------------------------------------------------------------------------


def _evidence_to_dict(
    evidence: DetectionEvidence,
) -> Dict[str, Any]:
    return {
        "category": evidence.category,
        "indicator": evidence.indicator,
        "description": evidence.description,
        "source": evidence.source,
        "path": evidence.path,
        "value": evidence.value,
        "severity": evidence.severity.value,
        "confidence": evidence.confidence.value,
        "score": evidence.score,
        "tags": list(evidence.tags),
        "metadata": dict(evidence.metadata),
    }


def _finding_to_dict(
    finding: DetectionFinding,
) -> Dict[str, Any]:
    return {
        "finding_id": finding.finding_id,
        "category": finding.category,
        "indicator": finding.indicator,
        "title": finding.title,
        "description": finding.description,
        "severity": finding.severity.value,
        "confidence": finding.confidence.value,
        "score": finding.score,
        "suggested_action": finding.suggested_action.value,
        "path": finding.path,
        "source": finding.source,
        "evidence": [
            _evidence_to_dict(item)
            for item in finding.evidence
        ],
        "tags": list(finding.tags),
        "metadata": dict(finding.metadata),
    }


def _combination_to_dict(
    combination: DetectionCombination,
) -> Dict[str, Any]:
    return {
        "name": combination.name,
        "description": combination.description,
        "indicators": list(combination.indicators),
        "categories": list(combination.categories),
        "severity": combination.severity.value,
        "confidence": combination.confidence.value,
        "score": combination.score,
        "suggested_action": combination.suggested_action.value,
        "evidence_ids": list(combination.evidence_ids),
    }


def _statistics_to_dict(
    statistics: DetectorStatistics,
) -> Dict[str, Any]:
    return {
        "input_size": statistics.input_size,
        "finding_count": statistics.finding_count,
        "evidence_count": statistics.evidence_count,
        "combination_count": statistics.combination_count,
        "high_risk_count": statistics.high_risk_count,
        "critical_count": statistics.critical_count,
        "category_counts": dict(statistics.category_counts),
        "indicator_counts": dict(statistics.indicator_counts),
        "severity_counts": dict(statistics.severity_counts),
        "action_counts": dict(statistics.action_counts),
        "source_counts": dict(statistics.source_counts),
        "maximum_score": statistics.maximum_score,
        "aggregate_score": statistics.aggregate_score,
    }


def result_to_dict(
    result: DetectionResult,
) -> Dict[str, Any]:
    """
    Convert a detector result to a JSON-compatible dictionary.
    """
    return {
        "detector": result.detector,
        "version": result.version,
        "document_sha256": result.document_sha256,
        "overall_score": result.overall_score,
        "overall_severity": result.overall_severity.value,
        "recommended_action": result.recommended_action.value,
        "findings": [
            _finding_to_dict(finding)
            for finding in result.findings
        ],
        "combinations": [
            _combination_to_dict(combination)
            for combination in result.combinations
        ],
        "evidence": [
            _evidence_to_dict(item)
            for item in result.evidence
        ],
        "feature_vector": dict(result.feature_vector),
        "statistics": _statistics_to_dict(result.statistics),
        "metadata": dict(result.metadata),
    }


def to_dict(
    result: DetectionResult,
) -> Dict[str, Any]:
    """Alias for :func:`result_to_dict`."""
    return result_to_dict(result)


def result_to_json(
    result: DetectionResult,
    *,
    indent: Optional[int] = 2,
) -> str:
    """
    Serialize a detector result to JSON.
    """
    return json.dumps(
        result_to_dict(result),
        indent=indent,
        sort_keys=True,
        ensure_ascii=False,
    )


def save_result(
    result: DetectionResult,
    path: os.PathLike[str] | str,
    *,
    indent: int = 2,
) -> None:
    """
    Persist detector JSON output.

    Only detector metadata is written; no untrusted embedded object is
    extracted or reconstructed.
    """
    target = Path(path)

    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(
            result_to_json(result, indent=indent),
            encoding="utf-8",
        )
    except OSError as exc:
        raise DetectorError(
            f"Unable to write detector result: {target}"
        ) from exc


# ---------------------------------------------------------------------------
# Iterators
# ---------------------------------------------------------------------------


def iter_findings(
    result: DetectionResult,
) -> Iterator[DetectionFinding]:
    """Yield findings in deterministic order."""
    yield from result.findings


def iter_evidence(
    result: DetectionResult,
) -> Iterator[DetectionEvidence]:
    """Yield evidence in deterministic order."""
    yield from result.evidence


def iter_high_risk_findings(
    result: DetectionResult,
) -> Iterator[DetectionFinding]:
    """Yield high and critical findings."""
    for finding in result.findings:
        if finding.is_high_risk:
            yield finding


def iter_combinations(
    result: DetectionResult,
) -> Iterator[DetectionCombination]:
    """Yield detected higher-order combinations."""
    yield from result.combinations


def iter_detector_results(
    values: Iterable[Any],
    *,
    config: Optional[DetectorConfig] = None,
) -> Iterator[DetectionResult]:
    """
    Analyze multiple inputs lazily.

    Each item is analyzed independently; no cross-sample state is retained.
    """
    for value in values:
        yield detect_document(value, config=config)


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


def validate_result(
    result: DetectionResult,
) -> Tuple[str, ...]:
    """
    Validate structural invariants of a detector result.

    Returns:
        Tuple of validation errors. Empty means valid.
    """
    errors: List[str] = []

    if not isinstance(result, DetectionResult):
        return ("result is not a DetectionResult",)

    if not re.fullmatch(r"[0-9a-f]{64}", result.document_sha256):
        errors.append("document_sha256 must be a SHA-256 hexadecimal digest")

    if not 0.0 <= result.overall_score <= 100.0:
        errors.append("overall_score must be between 0 and 100")

    if len(result.findings) > MAX_FINDINGS:
        errors.append("finding count exceeds maximum")

    if len(result.evidence) > MAX_EVIDENCE:
        errors.append("evidence count exceeds maximum")

    ids = [
        finding.finding_id
        for finding in result.findings
    ]

    if len(ids) != len(set(ids)):
        errors.append("finding IDs are not unique")

    for finding in result.findings:
        if not finding.category:
            errors.append(
                f"{finding.finding_id}: missing category"
            )

        if not finding.indicator:
            errors.append(
                f"{finding.finding_id}: missing indicator"
            )

        if not 0.0 <= finding.score <= 100.0:
            errors.append(
                f"{finding.finding_id}: invalid score"
            )

    return tuple(errors)


# ---------------------------------------------------------------------------
# Convenience predicates
# ---------------------------------------------------------------------------


def is_suspicious(
    result: DetectionResult,
) -> bool:
    """Return True when result severity is medium or higher."""
    return result.is_suspicious


def requires_review(
    result: DetectionResult,
) -> bool:
    """Return True when review is recommended."""
    return result.requires_review


def should_reject(
    result: DetectionResult,
) -> bool:
    """Return True when rejection is recommended."""
    return result.should_reject


def has_indicator(
    result: DetectionResult,
    indicator: str,
) -> bool:
    """Return whether an indicator is present."""
    normalized = _normalize_name(indicator)

    return any(
        finding.indicator == normalized
        for finding in result.findings
    )


def has_category(
    result: DetectionResult,
    category: str,
) -> bool:
    """Return whether a category is present."""
    normalized = _normalize_name(category)

    return any(
        finding.category == normalized
        for finding in result.findings
    )


def indicator_count(
    result: DetectionResult,
    indicator: str,
) -> int:
    """Count findings for an indicator."""
    return len(findings_by_indicator(result, indicator))


def category_count(
    result: DetectionResult,
    category: str,
) -> int:
    """Count findings for a category."""
    return len(findings_by_category(result, category))


# ---------------------------------------------------------------------------
# Public APIs
# ---------------------------------------------------------------------------

__all__ = [
    # Constants
    "MODULE_NAME",
    "DETECTOR_VERSION",
    "MAX_INPUT_BYTES",
    "MAX_TEXT_LENGTH",
    "MAX_NESTING_DEPTH",
    "MAX_ITEMS",
    "MAX_EVIDENCE",
    "MAX_FINDINGS",
    "MAX_FEATURES",
    "MAX_PATH_LENGTH",
    "MAX_VALUE_LENGTH",
    "MAX_ZIP_ENTRIES",
    "MAX_ZIP_ENTRY_SIZE",
    "MAX_ZIP_TOTAL_UNCOMPRESSED",
    "DEFAULT_REVIEW_THRESHOLD",
    "DEFAULT_BLOCK_THRESHOLD",
    "DetectorError",
    "DetectorInputError",
    "DetectorConfigurationError",
    "DetectionSeverity",
    "DetectionConfidence",
    "SuggestedAction",
    "DetectionEvidence",
    "DetectionFinding",
    "DetectionCombination",
    "DetectorStatistics",
    "DetectionResult",
    "DetectorConfig",
    "detect",
    "detect_document",
    "detect_analysis",
    "detect_content",
    "detect_file",
    "findings_by_category",
    "findings_by_indicator",
    "high_risk_findings",
    "critical_findings",
    "present_indicators",
    "present_categories",
    "present_combinations",
    "highest_severity",
    "highest_score",
    "feature_vector",
    "feature_names",
    "build_feature_schema",
    "summarize",
    "result_to_dict",
    "to_dict",
    "result_to_json",
    "save_result",
    "iter_findings",
    "iter_evidence",
    "iter_high_risk_findings",
    "iter_combinations",
    "iter_detector_results",
    "validate_result",
    "is_suspicious",
    "requires_review",
    "should_reject",
    "has_indicator",
    "has_category",
    "indicator_count",
    "category_count",
]