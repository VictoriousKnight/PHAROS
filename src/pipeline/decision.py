"""
pharos_cdr.pipeline.decision

Deterministic decision engine for the Pharos CDR pipeline.

This module combines static-analysis, ML, CDR detector, policy, and integrity
signals into one auditable disposition. It does not execute samples, macros,
scripts, payloads, or external content.

The decision engine is intentionally separate from scanning:
    scanner.py  -> produces observations
    decision.py -> converts observations into a disposition
    report.py   -> renders/persists the resulting decision

Supported dispositions:
    allow
    sanitize
    review
    reject

The implementation accepts both structured dataclass objects and ordinary
mapping/list outputs so it can consume results from the other Pharos modules
without requiring unsafe coupling.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
from dataclasses import asdict, dataclass, field, is_dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Iterable, Iterator, Mapping, Optional, Sequence

MODULE_NAME = "pharos_cdr.pipeline.decision"
DECISION_VERSION = "1.0.0"

MAX_INPUT_BYTES = 100 * 1024 * 1024
MAX_TEXT_LENGTH = 100_000
MAX_INPUT_ITEMS = 50_000
MAX_FINDINGS = 25_000
MAX_FEATURES = 100_000
MAX_EVIDENCE = 25_000
MAX_COMBINATIONS = 10_000
MAX_JSON_BYTES = 25 * 1024 * 1024

DEFAULT_SANITIZE_THRESHOLD = 35.0
DEFAULT_REVIEW_THRESHOLD = 55.0
DEFAULT_REJECT_THRESHOLD = 80.0
DEFAULT_MALICIOUS_PROBABILITY_THRESHOLD = 0.80
DEFAULT_REVIEW_PROBABILITY_THRESHOLD = 0.60

MIN_SCORE = 0.0
MAX_SCORE = 100.0

_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")


class DecisionError(Exception):
    """Base exception for decision-engine failures."""


class DecisionInputError(DecisionError):
    """Raised when decision input is malformed or unsafe."""


class DecisionConfigurationError(DecisionError):
    """Raised when decision configuration is invalid."""


class DecisionLimitError(DecisionError):
    """Raised when bounded processing limits are exceeded."""


class Disposition(str, Enum):
    """Final document disposition."""

    ALLOW = "allow"
    SANITIZE = "sanitize"
    REVIEW = "review"
    REJECT = "reject"


class DecisionConfidence(str, Enum):
    """Confidence band for the final decision."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class SignalSeverity(str, Enum):
    """Normalized severity for individual decision signals."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True)
class DecisionThresholds:
    """Threshold configuration for deterministic disposition."""

    sanitize: float = DEFAULT_SANITIZE_THRESHOLD
    review: float = DEFAULT_REVIEW_THRESHOLD
    reject: float = DEFAULT_REJECT_THRESHOLD
    malicious_probability: float = DEFAULT_MALICIOUS_PROBABILITY_THRESHOLD
    review_probability: float = DEFAULT_REVIEW_PROBABILITY_THRESHOLD

    def __post_init__(self) -> None:
        values = {
            "sanitize": self.sanitize,
            "review": self.review,
            "reject": self.reject,
            "malicious_probability": self.malicious_probability,
            "review_probability": self.review_probability,
        }

        for name, value in values.items():
            value = float(value)
            if not math.isfinite(value):
                raise DecisionConfigurationError(f"{name} threshold must be finite")

        if not 0 <= self.sanitize <= 100:
            raise DecisionConfigurationError(
                "sanitize threshold must be between 0 and 100"
            )

        if not 0 <= self.review <= 100:
            raise DecisionConfigurationError(
                "review threshold must be between 0 and 100"
            )

        if not 0 <= self.reject <= 100:
            raise DecisionConfigurationError(
                "reject threshold must be between 0 and 100"
            )

        if not (self.sanitize <= self.review <= self.reject):
            raise DecisionConfigurationError(
                "thresholds must satisfy sanitize <= review <= reject"
            )

        if not 0 <= self.malicious_probability <= 1:
            raise DecisionConfigurationError(
                "malicious_probability must be between 0 and 1"
            )

        if not 0 <= self.review_probability <= 1:
            raise DecisionConfigurationError(
                "review_probability must be between 0 and 1"
            )

        if self.review_probability > self.malicious_probability:
            raise DecisionConfigurationError(
                "review_probability cannot exceed malicious_probability"
            )


@dataclass(frozen=True)
class DecisionConfig:
    """Controls how observations are converted into a final decision."""

    thresholds: DecisionThresholds = field(default_factory=DecisionThresholds)

    fail_closed: bool = True
    require_integrity_for_allow: bool = True
    require_successful_analysis_for_allow: bool = True
    allow_without_ml: bool = True
    allow_without_cdr: bool = True

    malicious_probability_weight: float = 35.0
    cdr_weight: float = 25.0
    policy_weight: float = 20.0
    feature_weight: float = 15.0
    integrity_weight: float = 5.0

    critical_signal_score: float = 90.0
    high_signal_score: float = 70.0

    maximum_score: float = MAX_SCORE

    def __post_init__(self) -> None:
        weights = (
            self.malicious_probability_weight,
            self.cdr_weight,
            self.policy_weight,
            self.feature_weight,
            self.integrity_weight,
        )

        for value in weights:
            if not math.isfinite(float(value)) or float(value) < 0:
                raise DecisionConfigurationError(
                    "decision weights must be finite and non-negative"
                )

        if not math.isfinite(float(self.critical_signal_score)):
            raise DecisionConfigurationError("critical_signal_score must be finite")

        if not math.isfinite(float(self.high_signal_score)):
            raise DecisionConfigurationError("high_signal_score must be finite")

        if self.high_signal_score > self.critical_signal_score:
            raise DecisionConfigurationError(
                "high_signal_score cannot exceed critical_signal_score"
            )

        if self.maximum_score <= 0:
            raise DecisionConfigurationError("maximum_score must be positive")


@dataclass(frozen=True)
class DecisionSignal:
    """A normalized, auditable signal contributing to the decision."""

    source: str
    category: str
    name: str
    severity: SignalSeverity
    score: float
    confidence: float = 1.0
    evidence: str = ""
    indicator: str = ""
    stage: str = ""
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        score = float(self.score)
        confidence = float(self.confidence)

        if not math.isfinite(score):
            raise DecisionInputError("signal score must be finite")

        if not math.isfinite(confidence):
            raise DecisionInputError("signal confidence must be finite")

        if confidence < 0 or confidence > 1:
            raise DecisionInputError("signal confidence must be between 0 and 1")

        if score < 0:
            raise DecisionInputError("signal score cannot be negative")


@dataclass(frozen=True)
class DecisionFinding:
    """A user-facing finding derived from one or more signals."""

    category: str
    title: str
    severity: SignalSeverity
    score: float
    source: str = ""
    evidence: tuple[str, ...] = ()
    indicators: tuple[str, ...] = ()
    remediation: str = ""


@dataclass(frozen=True)
class DecisionStageStatus:
    """Availability/success information for a pipeline stage."""

    stage: str
    available: bool
    successful: bool
    failed: bool
    error: str = ""


@dataclass(frozen=True)
class DecisionResult:
    """Complete deterministic decision output."""

    decision_id: str
    disposition: Disposition
    score: float
    confidence: DecisionConfidence

    malicious_probability: Optional[float]

    reasons: tuple[str, ...]
    findings: tuple[DecisionFinding, ...]
    signals: tuple[DecisionSignal, ...]
    stages: tuple[DecisionStageStatus, ...]

    requires_sanitization: bool
    requires_review: bool
    rejected: bool

    sample_id: str = ""
    sha256: str = ""
    file_name: str = ""
    file_type: str = ""

    model_available: bool = False
    cdr_available: bool = False
    policy_available: bool = False
    integrity_available: bool = False

    policy_action: str = ""
    integrity_valid: Optional[bool] = None
    sanitized_changed: Optional[bool] = None

    metadata: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-compatible representation."""
        return decision_to_dict(self)


@dataclass(frozen=True)
class DecisionSummary:
    """Compact decision summary suitable for dashboards/logs."""

    disposition: str
    score: float
    confidence: str
    malicious_probability: Optional[float]
    finding_count: int
    high_risk_finding_count: int
    reason_count: int
    requires_sanitization: bool
    requires_review: bool
    rejected: bool
    sha256: str = ""


@dataclass(frozen=True)
class _ObservationContext:
    signals: tuple[DecisionSignal, ...]
    stages: tuple[DecisionStageStatus, ...]
    probability: Optional[float]
    policy_action: str
    integrity_valid: Optional[bool]
    sanitized_changed: Optional[bool]
    sample_id: str
    sha256: str
    file_name: str
    file_type: str
    model_available: bool
    cdr_available: bool
    policy_available: bool
    integrity_available: bool


def _safe_text(value: Any, limit: int = MAX_TEXT_LENGTH) -> str:
    if value is None:
        return ""

    if isinstance(value, bytes):
        text = value[:limit].decode("utf-8", errors="replace")
    else:
        try:
            text = str(value)
        except Exception:
            return ""

    text = text.replace("\x00", " ").strip()

    if len(text) > limit:
        text = text[:limit]

    return text


def _safe_float(
    value: Any,
    default: Optional[float] = None,
) -> Optional[float]:
    if value is None:
        return default

    if isinstance(value, bool):
        return float(value)

    try:
        result = float(value)
    except (TypeError, ValueError):
        return default

    if not math.isfinite(result):
        return default

    return result


def _safe_probability(value: Any) -> Optional[float]:
    result = _safe_float(value)

    if result is None:
        return None

    if result > 1 and result <= 100:
        result /= 100.0

    if not 0 <= result <= 1:
        return None

    return result


def _safe_int(
    value: Any,
    default: int = 0,
) -> int:
    if value is None:
        return default

    if isinstance(value, bool):
        return int(value)

    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _clamp(
    value: float,
    minimum: float = MIN_SCORE,
    maximum: float = MAX_SCORE,
) -> float:
    return max(minimum, min(maximum, float(value)))


def _normalize_name(value: Any) -> str:
    text = _safe_text(value, 512).lower()
    text = re.sub(r"[^a-z0-9._:-]+", "_", text)
    return text.strip("_")


def _normalize_source(value: Any) -> str:
    return _normalize_name(value) or "unknown"


def _normalize_category(value: Any) -> str:
    return _normalize_name(value) or "unknown"


def _json_safe(value: Any, depth: int = 0) -> Any:
    if depth > 8:
        return _safe_text(value, 2048)

    if value is None or isinstance(value, (str, int, float, bool)):
        if isinstance(value, float) and not math.isfinite(value):
            return None
        return value

    if isinstance(value, bytes):
        return value[:4096].hex()

    if isinstance(value, Enum):
        return value.value

    if is_dataclass(value):
        return _json_safe(asdict(value), depth + 1)

    if isinstance(value, Mapping):
        result: dict[str, Any] = {}

        for index, (key, item) in enumerate(value.items()):
            if index >= MAX_FEATURES:
                break

            result[_safe_text(key, 512)] = _json_safe(
                item,
                depth + 1,
            )

        return result

    if isinstance(value, (list, tuple, set, frozenset)):
        result = []

        for index, item in enumerate(value):
            if index >= MAX_INPUT_ITEMS:
                break

            result.append(_json_safe(item, depth + 1))

        return result

    return _safe_text(value, 4096)


def _mapping(value: Any) -> Mapping[str, Any]:
    if isinstance(value, Mapping):
        return value

    if is_dataclass(value):
        try:
            converted = asdict(value)
            if isinstance(converted, Mapping):
                return converted
        except Exception:
            return {}

    return {}


def _first(
    mapping: Mapping[str, Any],
    *keys: str,
    default: Any = None,
) -> Any:
    lowered = {_normalize_name(key): value for key, value in mapping.items()}

    for key in keys:
        normalized = _normalize_name(key)

        if normalized in lowered:
            return lowered[normalized]

    return default


def _get_nested(
    mapping: Mapping[str, Any],
    *paths: Sequence[str],
) -> Any:
    for path in paths:
        current: Any = mapping

        for key in path:
            if not isinstance(current, Mapping):
                current = None
                break

            current = _first(current, key, default=None)

        if current is not None:
            return current

    return None


def _iter_limited(
    value: Any,
    limit: int,
) -> Iterator[Any]:
    if value is None:
        return

    if isinstance(value, Mapping):
        for index, item in enumerate(value.items()):
            if index >= limit:
                break
            yield item
        return

    if isinstance(value, (list, tuple, set, frozenset)):
        for index, item in enumerate(value):
            if index >= limit:
                break
            yield item
        return

    yield value


def _hash_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _validate_sha256(value: Any) -> str:
    text = _safe_text(value, 128).lower()

    if _SHA256_RE.fullmatch(text):
        return text

    return ""


def _severity_from_value(
    value: Any,
    default: SignalSeverity = SignalSeverity.MEDIUM,
) -> SignalSeverity:
    if isinstance(value, SignalSeverity):
        return value

    text = _normalize_name(value)

    aliases = {
        "informational": SignalSeverity.INFO,
        "information": SignalSeverity.INFO,
        "info": SignalSeverity.INFO,
        "low": SignalSeverity.LOW,
        "medium": SignalSeverity.MEDIUM,
        "moderate": SignalSeverity.MEDIUM,
        "high": SignalSeverity.HIGH,
        "critical": SignalSeverity.CRITICAL,
        "severe": SignalSeverity.CRITICAL,
    }

    return aliases.get(text, default)


def _severity_score(severity: SignalSeverity) -> float:
    return {
        SignalSeverity.INFO: 0.0,
        SignalSeverity.LOW: 20.0,
        SignalSeverity.MEDIUM: 45.0,
        SignalSeverity.HIGH: 70.0,
        SignalSeverity.CRITICAL: 100.0,
    }[severity]


def _score_from_finding(
    finding: Mapping[str, Any],
    severity: SignalSeverity,
) -> float:
    explicit = _safe_float(
        _first(
            finding,
            "score",
            "risk_score",
            "signal_score",
            "severity_score",
        )
    )

    if explicit is not None:
        if 0 <= explicit <= 1:
            explicit *= 100.0
        return _clamp(explicit)

    return _severity_score(severity)


def _confidence_from_mapping(
    mapping: Mapping[str, Any],
) -> float:
    confidence = _safe_float(
        _first(
            mapping,
            "confidence",
            "confidence_score",
            "probability",
        )
    )

    if confidence is None:
        return 1.0

    if confidence > 1 and confidence <= 100:
        confidence /= 100.0

    return _clamp(confidence, 0.0, 1.0)


def _extract_evidence_text(
    mapping: Mapping[str, Any],
) -> str:
    for key in (
        "evidence",
        "detail",
        "details",
        "message",
        "description",
        "matched",
        "value",
        "text",
        "reason",
    ):
        value = _first(mapping, key)

        if isinstance(value, str) and value.strip():
            return _safe_text(value, 4096)

        if isinstance(value, (list, tuple)):
            parts = [
                _safe_text(item, 1024) for item in value[:10] if _safe_text(item, 1024)
            ]

            if parts:
                return "; ".join(parts)

    return ""


def _make_signal(
    source: str,
    category: str,
    name: str,
    severity: SignalSeverity,
    score: float,
    *,
    confidence: float = 1.0,
    evidence: str = "",
    indicator: str = "",
    stage: str = "",
    metadata: Optional[Mapping[str, Any]] = None,
) -> DecisionSignal:
    return DecisionSignal(
        source=_normalize_source(source),
        category=_normalize_category(category),
        name=_normalize_name(name) or "signal",
        severity=severity,
        score=_clamp(score),
        confidence=_clamp(confidence, 0.0, 1.0),
        evidence=_safe_text(evidence, 4096),
        indicator=_normalize_name(indicator),
        stage=_normalize_name(stage),
        metadata=dict(metadata or {}),
    )


def _iter_findings(value: Any) -> Iterator[Mapping[str, Any]]:
    """
    Yield finding-like mappings from arbitrarily nested analyzer output.
    """
    seen = 0

    def walk(node: Any, depth: int = 0) -> Iterator[Mapping[str, Any]]:
        nonlocal seen

        if seen >= MAX_FINDINGS or depth > 10:
            return

        if isinstance(node, Mapping):
            keys = {_normalize_name(key) for key in node.keys()}

            finding_keys = {
                "category",
                "severity",
                "score",
                "risk_score",
                "indicator",
                "indicators",
                "capability",
                "capabilities",
                "evidence",
                "reason",
                "title",
                "finding",
                "action",
            }

            if keys.intersection(finding_keys):
                seen += 1
                yield node

            for key, child in node.items():
                normalized = _normalize_name(key)

                if normalized in {
                    "findings",
                    "evidence",
                    "signals",
                    "detections",
                    "records",
                    "results",
                    "alerts",
                    "violations",
                    "combinations",
                    "capabilities",
                }:
                    yield from walk(child, depth + 1)

        elif isinstance(node, (list, tuple, set, frozenset)):
            for child in node:
                if seen >= MAX_FINDINGS:
                    break
                yield from walk(child, depth + 1)

    yield from walk(value)


def _iter_numeric_features(
    value: Any,
) -> Iterator[tuple[str, float]]:
    count = 0

    def walk(
        node: Any,
        prefix: str = "",
        depth: int = 0,
    ) -> Iterator[tuple[str, float]]:
        nonlocal count

        if depth > 8 or count >= MAX_FEATURES:
            return

        if isinstance(node, Mapping):
            for key, child in node.items():
                if count >= MAX_FEATURES:
                    break

                name = _normalize_name(key)

                if not name:
                    continue

                child_prefix = f"{prefix}_{name}" if prefix else name

                numeric = _safe_float(child)

                if numeric is not None:
                    count += 1
                    yield child_prefix, numeric
                elif isinstance(child, Mapping):
                    yield from walk(
                        child,
                        child_prefix,
                        depth + 1,
                    )
                elif isinstance(
                    child,
                    (list, tuple),
                ):
                    for index, item in enumerate(child[:1000]):
                        numeric = _safe_float(item)

                        if numeric is not None:
                            count += 1
                            yield (
                                f"{child_prefix}_{index}",
                                numeric,
                            )
                        elif isinstance(item, Mapping):
                            yield from walk(
                                item,
                                f"{child_prefix}_{index}",
                                depth + 1,
                            )

    yield from walk(value)


def _extract_stage_statuses(
    output: Any,
) -> list[DecisionStageStatus]:
    mapping = _mapping(output)
    result: list[DecisionStageStatus] = []

    stages = _first(
        mapping,
        "stages",
        "stage_results",
        "pipeline_stages",
    )

    if isinstance(stages, Mapping):
        items = stages.items()
    elif isinstance(stages, (list, tuple)):
        items = (
            (
                _first(_mapping(item), "stage", "name"),
                item,
            )
            for item in stages
        )
    else:
        items = ()

    for stage_name, stage_value in items:
        if not stage_name:
            continue

        stage_map = _mapping(stage_value)

        success_value = _first(
            stage_map,
            "successful",
            "success",
            "ok",
            default=None,
        )

        failed_value = _first(
            stage_map,
            "failed",
            "error",
            default=None,
        )

        if isinstance(failed_value, str):
            failed = bool(failed_value.strip())
        else:
            failed = bool(failed_value)

        successful = bool(success_value) if success_value is not None else not failed

        available = bool(
            _first(
                stage_map,
                "available",
                default=True,
            )
        )

        error = _safe_text(
            _first(
                stage_map,
                "error",
                "exception",
                "message",
                default="",
            ),
            4096,
        )

        result.append(
            DecisionStageStatus(
                stage=_normalize_name(stage_name),
                available=available,
                successful=successful,
                failed=failed,
                error=error,
            )
        )

    return result


def _extract_probability(
    output: Any,
) -> Optional[float]:
    mapping = _mapping(output)

    candidates = (
        "malicious_probability",
        "malware_probability",
        "probability",
        "risk_probability",
        "prediction_probability",
        "score_probability",
        "proba",
    )

    for key in candidates:
        value = _first(mapping, key)

        if isinstance(value, Mapping):
            value = _first(
                value,
                "malicious",
                "positive",
                "probability",
                "score",
            )

        probability = _safe_probability(value)

        if probability is not None:
            return probability

    prediction = _first(
        mapping,
        "prediction",
        "result",
        "model_result",
    )

    if isinstance(prediction, Mapping):
        for key in candidates:
            probability = _safe_probability(_first(prediction, key))

            if probability is not None:
                return probability

    return None


def _extract_policy_action(output: Any) -> str:
    mapping = _mapping(output)

    action = _first(
        mapping,
        "action",
        "final_action",
        "policy_action",
        "disposition",
    )

    if isinstance(action, Mapping):
        action = _first(
            action,
            "action",
            "name",
            "value",
        )

    return _normalize_name(action)


def _extract_integrity_valid(
    output: Any,
) -> Optional[bool]:
    mapping = _mapping(output)

    for key in (
        "valid",
        "integrity_valid",
        "is_valid",
        "passed",
        "success",
    ):
        value = _first(mapping, key)

        if isinstance(value, bool):
            return value

    status = _normalize_name(_first(mapping, "status", default=""))

    if status in {"valid", "passed", "success", "ok"}:
        return True

    if status in {
        "invalid",
        "failed",
        "failure",
        "corrupt",
    }:
        return False

    return None


def _extract_sanitized_changed(
    output: Any,
) -> Optional[bool]:
    mapping = _mapping(output)

    for key in (
        "sanitized_changed",
        "changed",
        "modified",
        "content_changed",
    ):
        value = _first(mapping, key)

        if isinstance(value, bool):
            return value

    return None


def _stage_available(
    output: Any,
    *names: str,
) -> bool:
    if output is None:
        return False

    if not isinstance(output, Mapping) and not is_dataclass(output):
        return True

    mapping = _mapping(output)

    if not mapping:
        return True

    for name in names:
        if any(_normalize_name(key) == _normalize_name(name) for key in mapping.keys()):
            return True

    return bool(mapping)


def _signals_from_output(
    output: Any,
    source: str,
    stage: str,
) -> list[DecisionSignal]:
    if output is None:
        return []

    signals: list[DecisionSignal] = []

    for finding in _iter_findings(output):
        category = _first(
            finding,
            "category",
            "type",
            "behavior",
            "capability",
            "finding_type",
            default="unknown",
        )

        name = _first(
            finding,
            "name",
            "indicator",
            "title",
            "finding",
            "capability",
            default=category,
        )

        severity = _severity_from_value(
            _first(
                finding,
                "severity",
                "risk",
                "level",
                default="medium",
            )
        )

        score = _score_from_finding(
            finding,
            severity,
        )

        confidence = _confidence_from_mapping(finding)

        evidence = _extract_evidence_text(finding)

        indicators = _first(
            finding,
            "indicators",
            "indicator",
            default="",
        )

        if isinstance(indicators, (list, tuple)):
            indicator = ",".join(_normalize_name(item) for item in indicators[:10])
        else:
            indicator = _normalize_name(indicators)

        signals.append(
            _make_signal(
                source,
                category,
                name,
                severity,
                score,
                confidence=confidence,
                evidence=evidence,
                indicator=indicator,
                stage=stage,
            )
        )

        if len(signals) >= MAX_FINDINGS:
            break

    # Interpret positive numeric feature vectors as lower-level risk signals.
    feature_values = list(_iter_numeric_features(output))

    for feature_name, numeric in feature_values:
        if numeric <= 0:
            continue

        normalized = _normalize_name(feature_name)

        if not (
            normalized.startswith("category_")
            or normalized.startswith("capability_")
            or normalized.startswith("indicator_")
            or normalized.startswith("combination_")
            or normalized.endswith("_score")
        ):
            continue

        score = min(
            MAX_SCORE,
            max(5.0, abs(numeric)),
        )

        if score >= 90:
            severity = SignalSeverity.CRITICAL
        elif score >= 70:
            severity = SignalSeverity.HIGH
        elif score >= 40:
            severity = SignalSeverity.MEDIUM
        else:
            severity = SignalSeverity.LOW

        signals.append(
            _make_signal(
                source,
                "feature",
                normalized,
                severity,
                score,
                confidence=1.0,
                stage=stage,
            )
        )

        if len(signals) >= MAX_FINDINGS:
            break

    return signals[:MAX_FINDINGS]


def _deduplicate_signals(
    signals: Iterable[DecisionSignal],
) -> tuple[DecisionSignal, ...]:
    result: list[DecisionSignal] = []
    seen: set[tuple[str, str, str, str, str]] = set()

    for signal in signals:
        key = (
            signal.source,
            signal.category,
            signal.name,
            signal.indicator,
            signal.evidence,
        )

        if key in seen:
            continue

        seen.add(key)
        result.append(signal)

        if len(result) >= MAX_FINDINGS:
            break

    return tuple(result)


def _signal_weight(
    signal: DecisionSignal,
) -> float:
    severity_weight = {
        SignalSeverity.INFO: 0.00,
        SignalSeverity.LOW: 0.25,
        SignalSeverity.MEDIUM: 0.50,
        SignalSeverity.HIGH: 0.75,
        SignalSeverity.CRITICAL: 1.00,
    }[signal.severity]

    return _clamp(signal.score) * severity_weight * _clamp(signal.confidence, 0.0, 1.0)


def _aggregate_signal_score(
    signals: Sequence[DecisionSignal],
) -> float:
    if not signals:
        return 0.0

    # Diminishing returns prevent dozens of repeated low-level findings from
    # automatically overwhelming a single high-confidence critical signal.
    ordered = sorted(
        signals,
        key=_signal_weight,
        reverse=True,
    )

    total = 0.0
    multiplier = 1.0

    for signal in ordered[:500]:
        contribution = _signal_weight(signal) * multiplier
        total += contribution
        multiplier *= 0.90

        if total >= MAX_SCORE:
            break

    return _clamp(total)


def _probability_score(
    probability: Optional[float],
) -> float:
    if probability is None:
        return 0.0

    return _clamp(probability * 100.0)


def _probability_signal(
    probability: Optional[float],
) -> Optional[DecisionSignal]:
    if probability is None:
        return None

    if probability >= 0.95:
        severity = SignalSeverity.CRITICAL
    elif probability >= 0.80:
        severity = SignalSeverity.HIGH
    elif probability >= 0.60:
        severity = SignalSeverity.MEDIUM
    elif probability >= 0.40:
        severity = SignalSeverity.LOW
    else:
        severity = SignalSeverity.INFO

    return _make_signal(
        "ml",
        "malware_probability",
        "model_probability",
        severity,
        probability * 100.0,
        confidence=max(probability, 1.0 - probability),
        evidence=f"model probability={probability:.4f}",
        stage="ml_prediction",
    )


def _policy_signal(
    action: str,
) -> Optional[DecisionSignal]:
    normalized = _normalize_name(action)

    scores = {
        "preserve": 0.0,
        "allow": 0.0,
        "sanitize": 55.0,
        "remove": 75.0,
        "review": 70.0,
        "reject": 100.0,
    }

    if normalized not in scores:
        return None

    score = scores[normalized]

    if score >= 90:
        severity = SignalSeverity.CRITICAL
    elif score >= 70:
        severity = SignalSeverity.HIGH
    elif score >= 40:
        severity = SignalSeverity.MEDIUM
    elif score > 0:
        severity = SignalSeverity.LOW
    else:
        severity = SignalSeverity.INFO

    return _make_signal(
        "policy",
        "policy_action",
        normalized,
        severity,
        score,
        evidence=f"policy action={normalized}",
        stage="policy",
    )


def _integrity_signal(
    valid: Optional[bool],
) -> Optional[DecisionSignal]:
    if valid is None:
        return None

    if valid:
        return _make_signal(
            "integrity",
            "integrity",
            "integrity_valid",
            SignalSeverity.INFO,
            0.0,
            evidence="sanitized/original package passed integrity checks",
            stage="integrity",
        )

    return _make_signal(
        "integrity",
        "integrity",
        "integrity_failure",
        SignalSeverity.CRITICAL,
        100.0,
        evidence="integrity validation failed",
        stage="integrity",
    )


def _stage_failure_signals(
    stages: Sequence[DecisionStageStatus],
) -> list[DecisionSignal]:
    signals: list[DecisionSignal] = []

    for stage in stages:
        if not stage.failed:
            continue

        severity = (
            SignalSeverity.HIGH
            if stage.stage
            in {
                "cdr_detection",
                "policy",
                "integrity",
            }
            else SignalSeverity.MEDIUM
        )

        score = 75.0 if severity == SignalSeverity.HIGH else 45.0

        signals.append(
            _make_signal(
                "pipeline",
                "stage_failure",
                stage.stage or "unknown_stage",
                severity,
                score,
                evidence=stage.error,
                stage=stage.stage,
            )
        )

    return signals


def _derive_findings(
    signals: Sequence[DecisionSignal],
) -> tuple[DecisionFinding, ...]:
    grouped: dict[
        tuple[str, str],
        list[DecisionSignal],
    ] = {}

    for signal in signals:
        key = (
            signal.category,
            signal.name,
        )
        grouped.setdefault(key, []).append(signal)

    findings: list[DecisionFinding] = []

    for (category, name), group in grouped.items():
        strongest = max(
            group,
            key=_signal_weight,
        )

        evidence = tuple(
            dict.fromkeys(signal.evidence for signal in group if signal.evidence)
        )[:10]

        indicators = tuple(
            dict.fromkeys(
                indicator
                for signal in group
                if signal.indicator
                for indicator in signal.indicator.split(",")
                if indicator
            )
        )[:20]

        remediation = _remediation_for_category(
            category,
            name,
        )

        findings.append(
            DecisionFinding(
                category=category,
                title=name.replace("_", " ").strip().title(),
                severity=strongest.severity,
                score=round(
                    max(signal.score for signal in group),
                    4,
                ),
                source=strongest.source,
                evidence=evidence,
                indicators=indicators,
                remediation=remediation,
            )
        )

    findings.sort(
        key=lambda item: (
            -_severity_score(item.severity),
            -item.score,
            item.category,
            item.title,
        )
    )

    return tuple(findings[:MAX_FINDINGS])


def _remediation_for_category(
    category: str,
    name: str,
) -> str:
    category = _normalize_name(category)
    name = _normalize_name(name)

    if category in {
        "macro",
        "vba",
        "xlm",
        "macro_execution",
    }:
        return "Remove active macro content before delivery."

    if category in {
        "payload",
        "embedded_payload",
        "executable_payload",
        "script_payload",
    }:
        return "Remove embedded active payloads and reconstruct the document."

    if category in {
        "network",
        "communication",
        "external_link",
        "remote_template",
    }:
        return "Remove or neutralize externally retrieved content."

    if category in {
        "evasion",
        "anti_analysis",
        "obfuscation",
    }:
        return "Remove or neutralize evasion and obfuscation mechanisms."

    if category in {
        "persistence",
        "registry_persistence",
        "service_persistence",
    }:
        return "Remove persistence mechanisms from the document or script."

    if category in {
        "credential",
        "credential_access",
        "collection",
    }:
        return "Treat the sample as high risk and investigate credential/data access."

    if category == "integrity":
        return "Reject or quarantine the artifact until package integrity is restored."

    if category == "stage_failure":
        return "Review the failed analysis stage before allowing the artifact."

    if name == "model_probability":
        return "Use the model score together with static findings and policy."

    return "Review the finding and apply the configured CDR policy."


def _derive_reasons(
    disposition: Disposition,
    score: float,
    probability: Optional[float],
    policy_action: str,
    integrity_valid: Optional[bool],
    stages: Sequence[DecisionStageStatus],
    findings: Sequence[DecisionFinding],
) -> tuple[str, ...]:
    reasons: list[str] = []

    if disposition == Disposition.REJECT:
        reasons.append("artifact exceeds the configured rejection risk threshold")

    elif disposition == Disposition.REVIEW:
        reasons.append("artifact requires analyst review")

    elif disposition == Disposition.SANITIZE:
        reasons.append("artifact contains content requiring CDR sanitization")

    else:
        reasons.append("no configured blocking or sanitization condition was triggered")

    if probability is not None:
        if probability >= DEFAULT_MALICIOUS_PROBABILITY_THRESHOLD:
            reasons.append(f"ML malicious probability is {probability:.3f}")
        elif probability >= DEFAULT_REVIEW_PROBABILITY_THRESHOLD:
            reasons.append(f"ML malicious probability is elevated at {probability:.3f}")

    normalized_policy = _normalize_name(policy_action)

    if normalized_policy in {
        "reject",
        "review",
        "sanitize",
        "remove",
    }:
        reasons.append(f"CDR policy requests {normalized_policy}")

    if integrity_valid is False:
        reasons.append("integrity validation failed")

    failed_stages = [stage.stage for stage in stages if stage.failed]

    if failed_stages:
        reasons.append(
            "analysis stage failure: " + ", ".join(sorted(set(failed_stages)))
        )

    high_risk = [
        finding
        for finding in findings
        if finding.severity
        in {
            SignalSeverity.HIGH,
            SignalSeverity.CRITICAL,
        }
    ]

    for finding in high_risk[:5]:
        reasons.append(f"{finding.severity.value} finding: " f"{finding.title}")

    return tuple(dict.fromkeys(reasons))


def _confidence_from_context(
    signals: Sequence[DecisionSignal],
    stages: Sequence[DecisionStageStatus],
    probability: Optional[float],
) -> DecisionConfidence:
    if not signals:
        return DecisionConfidence.LOW

    available_stages = [stage for stage in stages if stage.available]

    successful_stages = [
        stage for stage in available_stages if stage.successful and not stage.failed
    ]

    stage_factor = (
        len(successful_stages) / len(available_stages) if available_stages else 0.5
    )

    if probability is None:
        probability_factor = 0.45
    else:
        probability_factor = max(
            probability,
            1.0 - probability,
        )

    strong_signal_count = sum(
        1
        for signal in signals
        if signal.severity
        in {
            SignalSeverity.HIGH,
            SignalSeverity.CRITICAL,
        }
    )

    evidence_factor = min(
        1.0,
        0.4 + (strong_signal_count * 0.15),
    )

    combined = stage_factor * 0.40 + probability_factor * 0.25 + evidence_factor * 0.35

    if combined >= 0.80:
        return DecisionConfidence.HIGH

    if combined >= 0.55:
        return DecisionConfidence.MEDIUM

    return DecisionConfidence.LOW


def _derive_score(
    signals: Sequence[DecisionSignal],
    probability: Optional[float],
    policy_action: str,
    integrity_valid: Optional[bool],
    config: DecisionConfig,
) -> float:
    signal_score = _aggregate_signal_score(signals)

    probability_score = _probability_score(probability)

    policy_scores = {
        "preserve": 0.0,
        "allow": 0.0,
        "sanitize": 65.0,
        "remove": 75.0,
        "review": 75.0,
        "reject": 100.0,
    }

    policy_score = policy_scores.get(
        _normalize_name(policy_action),
        0.0,
    )

    integrity_score = 0.0 if integrity_valid is not False else 100.0

    total_weight = (
        config.malicious_probability_weight
        + config.cdr_weight
        + config.policy_weight
        + config.feature_weight
        + config.integrity_weight
    )

    if total_weight <= 0:
        return 0.0

    # ML probability is deliberately not the sole authority. It is one
    # component alongside static evidence, CDR policy, and integrity.
    combined = (
        probability_score * config.malicious_probability_weight
        + policy_score * config.policy_weight
        + signal_score * config.feature_weight
        + integrity_score * config.integrity_weight
    ) / total_weight

    # CDR-related signals receive their own contribution through the generic
    # signal aggregation and policy component. Add a bounded boost when
    # active-content findings are explicit.
    cdr_signal_score = _aggregate_signal_score(
        [
            signal
            for signal in signals
            if signal.source
            in {
                "cdr",
                "policy",
            }
            or signal.stage
            in {
                "cdr_detection",
                "policy",
            }
        ]
    )

    combined += cdr_signal_score * config.cdr_weight / total_weight * 0.35

    return _clamp(
        combined,
        0.0,
        config.maximum_score,
    )


def _forced_disposition(
    context: _ObservationContext,
    config: DecisionConfig,
) -> Optional[Disposition]:
    """
    Apply hard safety gates before score-based classification.
    """
    if context.integrity_valid is False:
        return Disposition.REJECT

    if context.policy_action in {
        "reject",
    }:
        return Disposition.REJECT

    if context.policy_action in {
        "review",
    }:
        return Disposition.REVIEW

    if context.policy_action in {
        "sanitize",
        "remove",
    }:
        return Disposition.SANITIZE

    if context.probability is not None:
        if context.probability >= config.thresholds.malicious_probability:
            # A high model probability is a strong signal but does not
            # automatically reject if policy/integrity are otherwise safe.
            if any(
                signal.severity == SignalSeverity.CRITICAL for signal in context.signals
            ):
                return Disposition.REJECT

    failed_critical_stages = {
        "cdr_detection",
        "policy",
        "integrity",
    }

    if config.fail_closed and any(
        stage.failed and stage.stage in failed_critical_stages
        for stage in context.stages
    ):
        return Disposition.REVIEW

    return None


def _score_disposition(
    score: float,
    config: DecisionConfig,
) -> Disposition:
    if score >= config.thresholds.reject:
        return Disposition.REJECT

    if score >= config.thresholds.review:
        return Disposition.REVIEW

    if score >= config.thresholds.sanitize:
        return Disposition.SANITIZE

    return Disposition.ALLOW


def _extract_sample_identity(
    output: Any,
) -> tuple[str, str, str, str]:
    mapping = _mapping(output)

    sample_id = _safe_text(
        _first(
            mapping,
            "sample_id",
            "scan_id",
            "id",
        ),
        256,
    )

    sha256 = _validate_sha256(
        _first(
            mapping,
            "sha256",
            "file_sha256",
            "hash",
            "content_hash",
        )
    )

    file_name = _safe_text(
        _first(
            mapping,
            "file_name",
            "filename",
            "name",
        ),
        1024,
    )

    file_type = _safe_text(
        _first(
            mapping,
            "file_type",
            "detected_type",
            "mime_type",
            "type",
        ),
        256,
    )

    return sample_id, sha256, file_name, file_type


def _build_context(
    *,
    scanner_output: Any = None,
    extraction_output: Any = None,
    ml_output: Any = None,
    cdr_output: Any = None,
    policy_output: Any = None,
    integrity_output: Any = None,
) -> _ObservationContext:
    signals: list[DecisionSignal] = []
    stages: list[DecisionStageStatus] = []

    outputs = (
        ("scanner", "scan", scanner_output),
        ("extraction", "extraction", extraction_output),
        ("ml", "ml_prediction", ml_output),
        ("cdr", "cdr_detection", cdr_output),
        ("policy", "policy", policy_output),
        ("integrity", "integrity", integrity_output),
    )

    for source, stage, output in outputs:
        if output is None:
            continue

        signals.extend(
            _signals_from_output(
                output,
                source,
                stage,
            )
        )

        stage_mapping = _mapping(output)

        explicit_stage_status = _extract_stage_statuses(output)

        if explicit_stage_status:
            stages.extend(explicit_stage_status)
        else:
            stages.append(
                DecisionStageStatus(
                    stage=stage,
                    available=True,
                    successful=True,
                    failed=False,
                )
            )

    probability = _extract_probability(ml_output)

    probability_signal = _probability_signal(probability)

    if probability_signal is not None:
        signals.append(probability_signal)

    policy_action = _extract_policy_action(policy_output)

    policy_signal = _policy_signal(policy_action)

    if policy_signal is not None:
        signals.append(policy_signal)

    integrity_valid = _extract_integrity_valid(integrity_output)

    integrity_signal = _integrity_signal(integrity_valid)

    if integrity_signal is not None:
        signals.append(integrity_signal)

    sanitized_changed = _extract_sanitized_changed(scanner_output)

    for output in (
        scanner_output,
        cdr_output,
        policy_output,
        integrity_output,
    ):
        stages.extend(_extract_stage_statuses(output))

    signals.extend(_stage_failure_signals(stages))

    signals = list(_deduplicate_signals(signals))

    identity_sources = (
        scanner_output,
        extraction_output,
        ml_output,
        cdr_output,
        policy_output,
        integrity_output,
    )

    sample_id = ""
    sha256 = ""
    file_name = ""
    file_type = ""

    for output in identity_sources:
        candidate = _extract_sample_identity(output)

        if not sample_id and candidate[0]:
            sample_id = candidate[0]

        if not sha256 and candidate[1]:
            sha256 = candidate[1]

        if not file_name and candidate[2]:
            file_name = candidate[2]

        if not file_type and candidate[3]:
            file_type = candidate[3]

    if not stages:
        stages = [
            DecisionStageStatus(
                stage="decision",
                available=True,
                successful=True,
                failed=False,
            )
        ]

    return _ObservationContext(
        signals=tuple(signals[:MAX_FINDINGS]),
        stages=tuple(_deduplicate_stages(stages)),
        probability=probability,
        policy_action=policy_action,
        integrity_valid=integrity_valid,
        sanitized_changed=sanitized_changed,
        sample_id=sample_id,
        sha256=sha256,
        file_name=file_name,
        file_type=file_type,
        model_available=ml_output is not None,
        cdr_available=cdr_output is not None,
        policy_available=policy_output is not None,
        integrity_available=integrity_output is not None,
    )


def _deduplicate_stages(
    stages: Iterable[DecisionStageStatus],
) -> tuple[DecisionStageStatus, ...]:
    result: list[DecisionStageStatus] = []
    seen: set[str] = set()

    for stage in stages:
        name = _normalize_name(stage.stage)

        if not name or name in seen:
            continue

        seen.add(name)
        result.append(
            DecisionStageStatus(
                stage=name,
                available=stage.available,
                successful=stage.successful,
                failed=stage.failed,
                error=stage.error,
            )
        )

    return tuple(result)


def _decision_id(
    context: _ObservationContext,
    disposition: Disposition,
    score: float,
) -> str:
    payload = {
        "version": DECISION_VERSION,
        "sample_id": context.sample_id,
        "sha256": context.sha256,
        "disposition": disposition.value,
        "score": round(score, 6),
        "probability": (
            None if context.probability is None else round(context.probability, 8)
        ),
        "policy_action": context.policy_action,
        "integrity_valid": context.integrity_valid,
    }

    digest = hashlib.sha256(
        json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()

    return f"decision-{digest[:24]}"


def decide(
    *,
    scanner_output: Any = None,
    extraction_output: Any = None,
    ml_output: Any = None,
    cdr_output: Any = None,
    policy_output: Any = None,
    integrity_output: Any = None,
    config: Optional[DecisionConfig] = None,
) -> DecisionResult:
    """
    Produce one deterministic final disposition from pipeline observations.

    The function accepts outputs from the scanner and individual pipeline
    stages. Missing optional stages are tolerated unless fail-closed rules
    require review.
    """
    if config is None:
        config = DecisionConfig()

    context = _build_context(
        scanner_output=scanner_output,
        extraction_output=extraction_output,
        ml_output=ml_output,
        cdr_output=cdr_output,
        policy_output=policy_output,
        integrity_output=integrity_output,
    )

    signals = list(context.signals)

    score = _derive_score(
        signals,
        context.probability,
        context.policy_action,
        context.integrity_valid,
        config,
    )

    forced = _forced_disposition(
        context,
        config,
    )

    if forced is not None:
        disposition = forced
    else:
        disposition = _score_disposition(
            score,
            config,
        )

    # If ML is unavailable, never reject solely because the model stage is
    # missing. Other static/CDR/policy evidence remains authoritative.
    if (
        disposition == Disposition.REJECT
        and not context.model_available
        and not any(signal.severity == SignalSeverity.CRITICAL for signal in signals)
        and context.policy_action != "reject"
        and context.integrity_valid is not False
    ):
        disposition = Disposition.REVIEW

    findings = _derive_findings(signals)

    confidence = _confidence_from_context(
        signals,
        context.stages,
        context.probability,
    )

    reasons = _derive_reasons(
        disposition,
        score,
        context.probability,
        context.policy_action,
        context.integrity_valid,
        context.stages,
        findings,
    )

    decision_id = _decision_id(
        context,
        disposition,
        score,
    )

    requires_sanitization = disposition == Disposition.SANITIZE

    requires_review = disposition == Disposition.REVIEW

    rejected = disposition == Disposition.REJECT

    metadata = {
        "module": MODULE_NAME,
        "version": DECISION_VERSION,
        "signal_count": len(signals),
        "finding_count": len(findings),
        "stage_count": len(context.stages),
        "successful_stage_count": sum(
            1 for stage in context.stages if stage.successful and not stage.failed
        ),
        "failed_stage_count": sum(1 for stage in context.stages if stage.failed),
        "thresholds": {
            "sanitize": config.thresholds.sanitize,
            "review": config.thresholds.review,
            "reject": config.thresholds.reject,
            "malicious_probability": (config.thresholds.malicious_probability),
            "review_probability": (config.thresholds.review_probability),
        },
    }

    return DecisionResult(
        decision_id=decision_id,
        disposition=disposition,
        score=round(score, 6),
        confidence=confidence,
        malicious_probability=context.probability,
        reasons=reasons,
        findings=findings,
        signals=tuple(signals),
        stages=context.stages,
        requires_sanitization=requires_sanitization,
        requires_review=requires_review,
        rejected=rejected,
        sample_id=context.sample_id,
        sha256=context.sha256,
        file_name=context.file_name,
        file_type=context.file_type,
        model_available=context.model_available,
        cdr_available=context.cdr_available,
        policy_available=context.policy_available,
        integrity_available=context.integrity_available,
        policy_action=context.policy_action,
        integrity_valid=context.integrity_valid,
        sanitized_changed=context.sanitized_changed,
        metadata=metadata,
    )


def decide_from_scan(
    scan_result: Any,
    *,
    config: Optional[DecisionConfig] = None,
) -> DecisionResult:
    """
    Convert a complete scanner result into a final disposition.
    """
    mapping = _mapping(scan_result)

    if not mapping:
        raise DecisionInputError("scan_result must be a mapping or dataclass result")

    extraction = _first(
        mapping,
        "extraction",
        "feature_analysis",
        "analysis",
    )

    ml = _first(
        mapping,
        "ml_prediction",
        "prediction",
        "model",
    )

    cdr = _first(
        mapping,
        "cdr_detection",
        "cdr",
        "detector",
    )

    policy = _first(
        mapping,
        "policy",
        "policy_result",
    )

    integrity = _first(
        mapping,
        "integrity",
        "integrity_result",
    )

    return decide(
        scanner_output=scan_result,
        extraction_output=extraction,
        ml_output=ml,
        cdr_output=cdr,
        policy_output=policy,
        integrity_output=integrity,
        config=config,
    )


def decide_from_outputs(
    outputs: Mapping[str, Any],
    *,
    config: Optional[DecisionConfig] = None,
) -> DecisionResult:
    """
    Convert a named collection of stage outputs into a decision.
    """
    if not isinstance(outputs, Mapping):
        raise DecisionInputError("outputs must be a mapping")

    return decide(
        scanner_output=_first(
            outputs,
            "scanner",
            "scan",
            "scan_result",
        ),
        extraction_output=_first(
            outputs,
            "extraction",
            "feature_pipeline",
            "analysis",
        ),
        ml_output=_first(
            outputs,
            "ml",
            "prediction",
            "model",
            "ml_prediction",
        ),
        cdr_output=_first(
            outputs,
            "cdr",
            "detector",
            "cdr_detection",
        ),
        policy_output=_first(
            outputs,
            "policy",
            "policy_result",
        ),
        integrity_output=_first(
            outputs,
            "integrity",
            "integrity_result",
        ),
        config=config,
    )


def decide_from_probability(
    probability: float,
    *,
    policy_action: str = "",
    integrity_valid: Optional[bool] = None,
    config: Optional[DecisionConfig] = None,
) -> DecisionResult:
    """
    Convenience API for a model-only or model-plus-policy decision.
    """
    normalized_probability = _safe_probability(probability)

    if normalized_probability is None:
        raise DecisionInputError("probability must be a number between 0 and 1")

    ml_output = {
        "malicious_probability": normalized_probability,
        "successful": True,
    }

    policy_output = {"action": policy_action} if policy_action else None

    integrity_output = (
        {"valid": integrity_valid} if integrity_valid is not None else None
    )

    return decide(
        ml_output=ml_output,
        policy_output=policy_output,
        integrity_output=integrity_output,
        config=config,
    )


def decision_to_dict(
    result: DecisionResult,
) -> dict[str, Any]:
    """
    Serialize a DecisionResult into a JSON-compatible mapping.
    """
    if not isinstance(result, DecisionResult):
        raise DecisionInputError("result must be a DecisionResult")

    return {
        "decision_id": result.decision_id,
        "disposition": result.disposition.value,
        "score": result.score,
        "confidence": result.confidence.value,
        "malicious_probability": result.malicious_probability,
        "reasons": list(result.reasons),
        "findings": [
            {
                "category": finding.category,
                "title": finding.title,
                "severity": finding.severity.value,
                "score": finding.score,
                "source": finding.source,
                "evidence": list(finding.evidence),
                "indicators": list(finding.indicators),
                "remediation": finding.remediation,
            }
            for finding in result.findings
        ],
        "signals": [
            {
                "source": signal.source,
                "category": signal.category,
                "name": signal.name,
                "severity": signal.severity.value,
                "score": signal.score,
                "confidence": signal.confidence,
                "evidence": signal.evidence,
                "indicator": signal.indicator,
                "stage": signal.stage,
                "metadata": _json_safe(signal.metadata),
            }
            for signal in result.signals
        ],
        "stages": [
            {
                "stage": stage.stage,
                "available": stage.available,
                "successful": stage.successful,
                "failed": stage.failed,
                "error": stage.error,
            }
            for stage in result.stages
        ],
        "requires_sanitization": (result.requires_sanitization),
        "requires_review": result.requires_review,
        "rejected": result.rejected,
        "sample_id": result.sample_id,
        "sha256": result.sha256,
        "file_name": result.file_name,
        "file_type": result.file_type,
        "model_available": result.model_available,
        "cdr_available": result.cdr_available,
        "policy_available": result.policy_available,
        "integrity_available": result.integrity_available,
        "policy_action": result.policy_action,
        "integrity_valid": result.integrity_valid,
        "sanitized_changed": result.sanitized_changed,
        "metadata": _json_safe(result.metadata),
    }


def result_to_dict(
    result: DecisionResult,
) -> dict[str, Any]:
    """Alias for :func:`decision_to_dict`."""
    return decision_to_dict(result)


def result_to_json(
    result: DecisionResult,
    *,
    indent: Optional[int] = 2,
) -> str:
    """Serialize a decision result to JSON."""
    payload = json.dumps(
        decision_to_dict(result),
        ensure_ascii=False,
        sort_keys=True,
        indent=indent,
    )

    if len(payload.encode("utf-8")) > MAX_JSON_BYTES:
        raise DecisionLimitError("serialized decision exceeds size limit")

    return payload


def save_decision(
    result: DecisionResult,
    path: str | os.PathLike[str],
) -> Path:
    """
    Persist a decision JSON report.

    This function writes only the caller-requested decision metadata; it does
    not write the analyzed sample or sanitized document.
    """
    target = Path(path)

    if not target.name:
        raise DecisionInputError("decision output path must name a file")

    target.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    data = result_to_json(result)

    target.write_text(
        data,
        encoding="utf-8",
    )

    return target


def summary(
    result: DecisionResult,
) -> DecisionSummary:
    """Return a compact decision summary."""
    high_risk = sum(
        1
        for finding in result.findings
        if finding.severity
        in {
            SignalSeverity.HIGH,
            SignalSeverity.CRITICAL,
        }
    )

    return DecisionSummary(
        disposition=result.disposition.value,
        score=result.score,
        confidence=result.confidence.value,
        malicious_probability=(result.malicious_probability),
        finding_count=len(result.findings),
        high_risk_finding_count=high_risk,
        reason_count=len(result.reasons),
        requires_sanitization=(result.requires_sanitization),
        requires_review=result.requires_review,
        rejected=result.rejected,
        sha256=result.sha256,
    )


def scan_summary(
    result: DecisionResult,
) -> dict[str, Any]:
    """Return a JSON-compatible compact summary."""
    item = summary(result)

    return {
        "disposition": item.disposition,
        "score": item.score,
        "confidence": item.confidence,
        "malicious_probability": item.malicious_probability,
        "finding_count": item.finding_count,
        "high_risk_finding_count": (item.high_risk_finding_count),
        "reason_count": item.reason_count,
        "requires_sanitization": (item.requires_sanitization),
        "requires_review": item.requires_review,
        "rejected": item.rejected,
        "sha256": item.sha256,
    }


def is_allowed(
    result: DecisionResult,
) -> bool:
    """Return whether the final disposition is allow."""
    return result.disposition == Disposition.ALLOW


def requires_sanitization(
    result: DecisionResult,
) -> bool:
    """Return whether CDR sanitization is required."""
    return result.disposition == Disposition.SANITIZE


def requires_review(
    result: DecisionResult,
) -> bool:
    """Return whether analyst review is required."""
    return result.disposition == Disposition.REVIEW


def is_rejected(
    result: DecisionResult,
) -> bool:
    """Return whether the artifact is rejected."""
    return result.disposition == Disposition.REJECT


def is_high_risk(
    result: DecisionResult,
) -> bool:
    """Return whether the decision contains high/critical risk."""
    return result.disposition in {
        Disposition.REVIEW,
        Disposition.REJECT,
    } or any(
        finding.severity
        in {
            SignalSeverity.HIGH,
            SignalSeverity.CRITICAL,
        }
        for finding in result.findings
    )


def model_probability(
    result: DecisionResult,
) -> Optional[float]:
    """Return the model malicious probability, if available."""
    return result.malicious_probability


def risk_score(
    result: DecisionResult,
) -> float:
    """Return the final normalized risk score."""
    return result.score


def highest_severity(
    result: DecisionResult,
) -> SignalSeverity:
    """Return the highest severity present in the result."""
    if not result.findings:
        return SignalSeverity.INFO

    return max(
        (finding.severity for finding in result.findings),
        key=_severity_score,
    )


def iter_findings(
    result: DecisionResult,
) -> Iterator[DecisionFinding]:
    """Iterate findings in deterministic risk order."""
    yield from result.findings


def iter_high_risk_findings(
    result: DecisionResult,
) -> Iterator[DecisionFinding]:
    """Iterate high and critical findings."""
    for finding in result.findings:
        if finding.severity in {
            SignalSeverity.HIGH,
            SignalSeverity.CRITICAL,
        }:
            yield finding


def iter_signals(
    result: DecisionResult,
) -> Iterator[DecisionSignal]:
    """Iterate normalized decision signals."""
    yield from result.signals


def validate_result(
    result: DecisionResult,
) -> tuple[str, ...]:
    """
    Validate internal consistency of a decision result.

    Returns an empty tuple when valid, otherwise a tuple of validation errors.
    """
    errors: list[str] = []

    if not isinstance(result, DecisionResult):
        return ("result is not a DecisionResult",)

    if not (0 <= result.score <= MAX_SCORE):
        errors.append("score is outside the 0..100 range")

    if result.malicious_probability is not None:
        if not (0 <= result.malicious_probability <= 1):
            errors.append("malicious_probability is outside the 0..1 range")

    if result.disposition == Disposition.ALLOW:
        if result.requires_review:
            errors.append("allow result cannot require review")

        if result.requires_sanitization:
            errors.append("allow result cannot require sanitization")

        if result.rejected:
            errors.append("allow result cannot be rejected")

    if result.disposition == Disposition.REJECT:
        if not result.rejected:
            errors.append("reject result must have rejected=True")

    if result.disposition == Disposition.REVIEW:
        if not result.requires_review:
            errors.append("review result must have requires_review=True")

    if result.disposition == Disposition.SANITIZE:
        if not result.requires_sanitization:
            errors.append("sanitize result must require sanitization")

    if result.decision_id and not result.decision_id.startswith("decision-"):
        errors.append("decision_id has an invalid format")

    return tuple(errors)


def build_config(
    *,
    sanitize_threshold: float = DEFAULT_SANITIZE_THRESHOLD,
    review_threshold: float = DEFAULT_REVIEW_THRESHOLD,
    reject_threshold: float = DEFAULT_REJECT_THRESHOLD,
    malicious_probability_threshold: float = (DEFAULT_MALICIOUS_PROBABILITY_THRESHOLD),
    review_probability_threshold: float = (DEFAULT_REVIEW_PROBABILITY_THRESHOLD),
    fail_closed: bool = True,
    require_integrity_for_allow: bool = True,
    require_successful_analysis_for_allow: bool = True,
) -> DecisionConfig:
    """Construct a validated decision configuration."""
    return DecisionConfig(
        thresholds=DecisionThresholds(
            sanitize=sanitize_threshold,
            review=review_threshold,
            reject=reject_threshold,
            malicious_probability=(malicious_probability_threshold),
            review_probability=(review_probability_threshold),
        ),
        fail_closed=fail_closed,
        require_integrity_for_allow=(require_integrity_for_allow),
        require_successful_analysis_for_allow=(require_successful_analysis_for_allow),
    )


def default_config() -> DecisionConfig:
    """Return the balanced default decision configuration."""
    return DecisionConfig()


def strict_config() -> DecisionConfig:
    """Return a conservative configuration for untrusted documents."""
    return DecisionConfig(
        thresholds=DecisionThresholds(
            sanitize=25.0,
            review=45.0,
            reject=70.0,
            malicious_probability=0.70,
            review_probability=0.50,
        ),
        fail_closed=True,
        require_integrity_for_allow=True,
        require_successful_analysis_for_allow=True,
        allow_without_ml=False,
        allow_without_cdr=False,
    )


def permissive_config() -> DecisionConfig:
    """Return a configuration intended for lower-risk environments."""
    return DecisionConfig(
        thresholds=DecisionThresholds(
            sanitize=50.0,
            review=70.0,
            reject=90.0,
            malicious_probability=0.90,
            review_probability=0.75,
        ),
        fail_closed=False,
        require_integrity_for_allow=False,
        require_successful_analysis_for_allow=False,
        allow_without_ml=True,
        allow_without_cdr=True,
    )


def analysis_config() -> DecisionConfig:
    """Return a balanced configuration for analysis environments."""
    return DecisionConfig(
        thresholds=DecisionThresholds(
            sanitize=35.0,
            review=55.0,
            reject=85.0,
            malicious_probability=0.85,
            review_probability=0.60,
        ),
        fail_closed=True,
        require_integrity_for_allow=False,
        require_successful_analysis_for_allow=False,
        allow_without_ml=True,
        allow_without_cdr=True,
    )


# ---------------------------------------------------------------------------
# PUBLIC APIs
# ---------------------------------------------------------------------------

__all__ = [
    "MODULE_NAME",
    "DECISION_VERSION",
    "Disposition",
    "DecisionConfidence",
    "SignalSeverity",
    "DecisionThresholds",
    "DecisionConfig",
    "DecisionSignal",
    "DecisionFinding",
    "DecisionStageStatus",
    "DecisionResult",
    "DecisionSummary",
    "DecisionError",
    "DecisionInputError",
    "DecisionConfigurationError",
    "DecisionLimitError",
    "decide",
    "decide_from_scan",
    "decide_from_outputs",
    "decide_from_probability",
    "decision_to_dict",
    "result_to_dict",
    "result_to_json",
    "save_decision",
    "summary",
    "scan_summary",
    "is_allowed",
    "requires_sanitization",
    "requires_review",
    "is_rejected",
    "is_high_risk",
    "model_probability",
    "risk_score",
    "highest_severity",
    "iter_findings",
    "iter_high_risk_findings",
    "iter_signals",
    "validate_result",
    "build_config",
    "default_config",
    "strict_config",
    "permissive_config",
    "analysis_config",
]
