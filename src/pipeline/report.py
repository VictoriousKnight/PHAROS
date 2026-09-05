"""
pharos_cdr.pipeline.report

Reporting and serialization layer for the Pharos CDR pipeline.

This module converts scan/decision results into deterministic, auditable
reports suitable for analysts, API responses, dashboards, and persisted
artifacts.

Security properties:
    - Never executes analyzed content.
    - Never executes macros, scripts, payloads, or URLs.
    - Never downloads remote resources.
    - Never embeds executable document content into reports.
    - Report HTML contains no external JavaScript, CSS, fonts, or URLs.
    - User-controlled values are HTML-escaped before rendering.
    - Report size and collection sizes are bounded.
    - Output is deterministic for identical input.

Supported formats:
    - JSON
    - JSONL
    - HTML
    - plain text

The module intentionally keeps presentation separate from decision logic:
    scanner.py -> observations
    decision.py -> disposition
    report.py -> presentation/persistence
"""

from __future__ import annotations

import hashlib
import html
import json
import math
import os
import re
from dataclasses import asdict, dataclass, is_dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Iterable, Iterator, Mapping, Optional, Sequence

MODULE_NAME = "pharos_cdr.pipeline.report"
REPORT_VERSION = "1.0.0"

MAX_INPUT_BYTES = 100 * 1024 * 1024
MAX_TEXT_LENGTH = 100_000
MAX_REPORT_BYTES = 25 * 1024 * 1024
MAX_FINDINGS = 25_000
MAX_SIGNALS = 25_000
MAX_STAGES = 1_000
MAX_REASONS = 5_000
MAX_METADATA_ITEMS = 10_000
MAX_JSON_DEPTH = 10

DEFAULT_REPORT_DIRECTORY = Path("outputs/reports")

_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


class ReportError(Exception):
    """Base exception for report generation."""


class ReportInputError(ReportError):
    """Raised when report input is invalid."""


class ReportLimitError(ReportError):
    """Raised when report generation exceeds configured limits."""


class ReportSerializationError(ReportError):
    """Raised when report serialization fails."""


class ReportFormat(str, Enum):
    """Supported report formats."""

    JSON = "json"
    JSONL = "jsonl"
    HTML = "html"
    TEXT = "text"


@dataclass(frozen=True)
class ReportConfig:
    """Controls report content and output behavior."""

    include_signals: bool = True
    include_evidence: bool = True
    include_metadata: bool = True
    include_stage_status: bool = True
    include_recommendations: bool = True
    include_model_probability: bool = True

    pretty_json: bool = True
    html_title: str = "Pharos CDR Analysis Report"

    max_findings: int = MAX_FINDINGS
    max_signals: int = MAX_SIGNALS
    max_reasons: int = MAX_REASONS

    def __post_init__(self) -> None:
        if self.max_findings < 1:
            raise ReportInputError("max_findings must be positive")

        if self.max_signals < 1:
            raise ReportInputError("max_signals must be positive")

        if self.max_reasons < 1:
            raise ReportInputError("max_reasons must be positive")


@dataclass(frozen=True)
class ReportArtifact:
    """A generated report artifact."""

    report_id: str
    format: ReportFormat
    content: str
    sha256: str
    byte_size: int
    created_at: str
    decision_id: str = ""
    sample_id: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-compatible representation."""
        return {
            "report_id": self.report_id,
            "format": self.format.value,
            "content": self.content,
            "sha256": self.sha256,
            "byte_size": self.byte_size,
            "created_at": self.created_at,
            "decision_id": self.decision_id,
            "sample_id": self.sample_id,
        }


@dataclass(frozen=True)
class ReportSummary:
    """Compact report summary."""

    report_id: str
    disposition: str
    score: float
    confidence: str
    malicious_probability: Optional[float]
    finding_count: int
    high_risk_finding_count: int
    stage_count: int
    failed_stage_count: int
    requires_sanitization: bool
    requires_review: bool
    rejected: bool
    sha256: str = ""
    decision_id: str = ""


def _safe_text(
    value: Any,
    limit: int = MAX_TEXT_LENGTH,
) -> str:
    if value is None:
        return ""

    if isinstance(value, bytes):
        value = value[:limit].decode(
            "utf-8",
            errors="replace",
        )

    try:
        text = str(value)
    except Exception:
        return ""

    text = _CONTROL_RE.sub(" ", text)
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

    try:
        number = float(value)
    except (TypeError, ValueError):
        return default

    if not math.isfinite(number):
        return default

    return number


def _safe_probability(
    value: Any,
) -> Optional[float]:
    number = _safe_float(value)

    if number is None:
        return None

    if 1 < number <= 100:
        number /= 100.0

    if not 0 <= number <= 1:
        return None

    return number


def _normalize_name(value: Any) -> str:
    text = _safe_text(value, 512).lower()
    text = re.sub(
        r"[^a-z0-9._:-]+",
        "_",
        text,
    )
    return text.strip("_")


def _json_safe(
    value: Any,
    depth: int = 0,
) -> Any:
    if depth > MAX_JSON_DEPTH:
        return _safe_text(value, 4096)

    if value is None:
        return None

    if isinstance(value, (str, int, bool)):
        return value

    if isinstance(value, float):
        return value if math.isfinite(value) else None

    if isinstance(value, bytes):
        return value[:4096].hex()

    if isinstance(value, Enum):
        return _json_safe(
            value.value,
            depth + 1,
        )

    if is_dataclass(value):
        try:
            return _json_safe(
                asdict(value),
                depth + 1,
            )
        except Exception:
            return _safe_text(value, 4096)

    if isinstance(value, Mapping):
        result: dict[str, Any] = {}

        for index, (key, item) in enumerate(value.items()):
            if index >= MAX_METADATA_ITEMS:
                break

            result[_safe_text(key, 512)] = _json_safe(
                item,
                depth + 1,
            )

        return result

    if isinstance(
        value,
        (list, tuple, set, frozenset),
    ):
        result = []

        for index, item in enumerate(value):
            if index >= MAX_METADATA_ITEMS:
                break

            result.append(
                _json_safe(
                    item,
                    depth + 1,
                )
            )

        return result

    return _safe_text(value, 4096)


def _mapping(value: Any) -> Mapping[str, Any]:
    if isinstance(value, Mapping):
        return value

    if is_dataclass(value):
        try:
            result = asdict(value)

            if isinstance(result, Mapping):
                return result
        except Exception:
            return {}

    return {}


def _first(
    mapping: Mapping[str, Any],
    *keys: str,
    default: Any = None,
) -> Any:
    normalized = {_normalize_name(key): value for key, value in mapping.items()}

    for key in keys:
        name = _normalize_name(key)

        if name in normalized:
            return normalized[name]

    return default


def _enum_value(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value

    return value


def _extract_decision_mapping(
    decision: Any,
) -> dict[str, Any]:
    if decision is None:
        raise ReportInputError("decision result cannot be None")

    mapping = _mapping(decision)

    if not mapping:
        raise ReportInputError("decision must be a mapping or dataclass")

    return dict(mapping)


def _extract_findings(
    mapping: Mapping[str, Any],
    limit: int,
) -> list[Mapping[str, Any]]:
    raw = _first(
        mapping,
        "findings",
        "detections",
        "alerts",
        "violations",
        default=[],
    )

    if isinstance(raw, Mapping):
        raw = [raw]

    if not isinstance(
        raw,
        (list, tuple, set, frozenset),
    ):
        return []

    result: list[Mapping[str, Any]] = []

    for item in raw:
        if len(result) >= limit:
            break

        item_mapping = _mapping(item)

        if item_mapping:
            result.append(item_mapping)

    return result


def _extract_signals(
    mapping: Mapping[str, Any],
    limit: int,
) -> list[Mapping[str, Any]]:
    raw = _first(
        mapping,
        "signals",
        "decision_signals",
        default=[],
    )

    if isinstance(raw, Mapping):
        raw = [raw]

    if not isinstance(
        raw,
        (list, tuple, set, frozenset),
    ):
        return []

    result: list[Mapping[str, Any]] = []

    for item in raw:
        if len(result) >= limit:
            break

        item_mapping = _mapping(item)

        if item_mapping:
            result.append(item_mapping)

    return result


def _extract_stages(
    mapping: Mapping[str, Any],
) -> list[Mapping[str, Any]]:
    raw = _first(
        mapping,
        "stages",
        "stage_results",
        "pipeline_stages",
        default=[],
    )

    if isinstance(raw, Mapping):
        raw = [
            {
                "stage": key,
                **(
                    dict(value)
                    if isinstance(value, Mapping)
                    else {
                        "value": value,
                    }
                ),
            }
            for key, value in raw.items()
        ]

    if not isinstance(
        raw,
        (list, tuple, set, frozenset),
    ):
        return []

    result: list[Mapping[str, Any]] = []

    for item in raw:
        item_mapping = _mapping(item)

        if item_mapping:
            result.append(item_mapping)

        if len(result) >= MAX_STAGES:
            break

    return result


def _extract_reasons(
    mapping: Mapping[str, Any],
    limit: int,
) -> list[str]:
    raw = _first(
        mapping,
        "reasons",
        "reason",
        "decision_reasons",
        default=[],
    )

    if isinstance(raw, str):
        return [_safe_text(raw, 4096)] if raw.strip() else []

    if not isinstance(
        raw,
        (list, tuple, set, frozenset),
    ):
        return []

    result: list[str] = []

    for item in raw:
        text = _safe_text(
            item,
            4096,
        )

        if text:
            result.append(text)

        if len(result) >= limit:
            break

    return result


def _extract_metadata(
    mapping: Mapping[str, Any],
) -> Mapping[str, Any]:
    raw = _first(
        mapping,
        "metadata",
        "meta",
        default={},
    )

    if isinstance(raw, Mapping):
        return raw

    return {}


def _extract_sha256(
    mapping: Mapping[str, Any],
) -> str:
    value = _safe_text(
        _first(
            mapping,
            "sha256",
            "file_sha256",
            "content_hash",
            "hash",
            default="",
        ),
        128,
    ).lower()

    if _SHA256_RE.fullmatch(value):
        return value

    return ""


def _extract_probability(
    mapping: Mapping[str, Any],
) -> Optional[float]:
    value = _first(
        mapping,
        "malicious_probability",
        "malware_probability",
        "prediction_probability",
        "risk_probability",
        "probability",
        default=None,
    )

    if isinstance(value, Mapping):
        value = _first(
            value,
            "malicious",
            "positive",
            "probability",
            "score",
            default=None,
        )

    return _safe_probability(value)


def _extract_score(
    mapping: Mapping[str, Any],
) -> float:
    value = _safe_float(
        _first(
            mapping,
            "score",
            "risk_score",
            "decision_score",
            default=0.0,
        ),
        0.0,
    )

    if value is None:
        return 0.0

    return max(
        0.0,
        min(100.0, value),
    )


def _extract_disposition(
    mapping: Mapping[str, Any],
) -> str:
    value = _first(
        mapping,
        "disposition",
        "decision",
        "verdict",
        "action",
        default="unknown",
    )

    value = _enum_value(value)

    if isinstance(value, Mapping):
        value = _first(
            value,
            "disposition",
            "decision",
            "action",
            "value",
            default="unknown",
        )

    return _normalize_name(value) or "unknown"


def _extract_confidence(
    mapping: Mapping[str, Any],
) -> str:
    value = _first(
        mapping,
        "confidence",
        "confidence_level",
        default="unknown",
    )

    value = _enum_value(value)

    return _normalize_name(value) or "unknown"


def _severity_value(
    value: Any,
) -> str:
    value = _enum_value(value)

    return _normalize_name(value) or "unknown"


def _finding_score(
    finding: Mapping[str, Any],
) -> float:
    value = _safe_float(
        _first(
            finding,
            "score",
            "risk_score",
            "signal_score",
            "severity_score",
            default=None,
        )
    )

    if value is None:
        severity = _severity_value(
            _first(
                finding,
                "severity",
                "risk",
                "level",
                default="info",
            )
        )

        return {
            "critical": 100.0,
            "high": 70.0,
            "medium": 45.0,
            "low": 20.0,
            "info": 0.0,
        }.get(
            severity,
            0.0,
        )

    if 0 <= value <= 1:
        value *= 100.0

    return max(
        0.0,
        min(100.0, value),
    )


def _finding_severity(
    finding: Mapping[str, Any],
) -> str:
    severity = _severity_value(
        _first(
            finding,
            "severity",
            "risk",
            "level",
            default="info",
        )
    )

    if severity not in {
        "info",
        "low",
        "medium",
        "high",
        "critical",
    }:
        return "unknown"

    return severity


def _high_risk(
    severity: str,
) -> bool:
    return severity in {
        "high",
        "critical",
    }


def _escape(
    value: Any,
) -> str:
    return html.escape(
        _safe_text(value, MAX_TEXT_LENGTH),
        quote=True,
    )


def _format_probability(
    value: Optional[float],
) -> str:
    if value is None:
        return "N/A"

    return f"{value:.3f} ({value * 100:.1f}%)"


def _format_score(
    value: Any,
) -> str:
    score = _safe_float(value, 0.0)

    if score is None:
        score = 0.0

    return f"{score:.2f}/100"


def _format_bool(
    value: Any,
) -> str:
    if value is True:
        return "Yes"

    if value is False:
        return "No"

    return "Unknown"


def _format_timestamp() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _report_digest_input(
    payload: Mapping[str, Any],
) -> str:
    canonical = json.dumps(
        _json_safe(payload),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )

    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _make_report_id(
    mapping: Mapping[str, Any],
    report_format: ReportFormat,
) -> str:
    decision_id = _safe_text(
        _first(
            mapping,
            "decision_id",
            "id",
            default="",
        ),
        256,
    )

    sample_id = _safe_text(
        _first(
            mapping,
            "sample_id",
            "scan_id",
            default="",
        ),
        256,
    )

    digest = _report_digest_input(
        {
            "version": REPORT_VERSION,
            "format": report_format.value,
            "decision_id": decision_id,
            "sample_id": sample_id,
            "disposition": _extract_disposition(mapping),
            "score": _extract_score(mapping),
            "sha256": _extract_sha256(mapping),
        }
    )

    return f"report-{digest[:24]}"


def _canonical_report_payload(
    decision: Any,
    *,
    config: ReportConfig,
) -> dict[str, Any]:
    mapping = _extract_decision_mapping(decision)

    disposition = _extract_disposition(mapping)

    score = _extract_score(mapping)
    confidence = _extract_confidence(mapping)
    probability = _extract_probability(mapping)

    findings = _extract_findings(
        mapping,
        config.max_findings,
    )

    reasons = _extract_reasons(
        mapping,
        config.max_reasons,
    )

    stages = _extract_stages(mapping) if config.include_stage_status else []

    signals = (
        _extract_signals(
            mapping,
            config.max_signals,
        )
        if config.include_signals
        else []
    )

    result: dict[str, Any] = {
        "report": {
            "module": MODULE_NAME,
            "version": REPORT_VERSION,
            "report_id": _make_report_id(
                mapping,
                ReportFormat.JSON,
            ),
            "created_at": _format_timestamp(),
        },
        "decision": {
            "decision_id": _safe_text(
                _first(
                    mapping,
                    "decision_id",
                    "id",
                    default="",
                ),
                256,
            ),
            "disposition": disposition,
            "score": round(score, 6),
            "confidence": confidence,
            "requires_sanitization": bool(
                _first(
                    mapping,
                    "requires_sanitization",
                    default=(disposition == "sanitize"),
                )
            ),
            "requires_review": bool(
                _first(
                    mapping,
                    "requires_review",
                    default=(disposition == "review"),
                )
            ),
            "rejected": bool(
                _first(
                    mapping,
                    "rejected",
                    default=(disposition == "reject"),
                )
            ),
        },
        "artifact": {
            "sample_id": _safe_text(
                _first(
                    mapping,
                    "sample_id",
                    "scan_id",
                    default="",
                ),
                256,
            ),
            "sha256": _extract_sha256(mapping),
            "file_name": _safe_text(
                _first(
                    mapping,
                    "file_name",
                    "filename",
                    default="",
                ),
                1024,
            ),
            "file_type": _safe_text(
                _first(
                    mapping,
                    "file_type",
                    "detected_type",
                    "mime_type",
                    default="",
                ),
                256,
            ),
        },
        "model": {
            "available": bool(
                _first(
                    mapping,
                    "model_available",
                    default=(probability is not None),
                )
            ),
        },
        "cdr": {
            "available": bool(
                _first(
                    mapping,
                    "cdr_available",
                    default=False,
                )
            ),
            "policy_action": _normalize_name(
                _first(
                    mapping,
                    "policy_action",
                    "action",
                    default="",
                )
            ),
        },
        "integrity": {
            "available": bool(
                _first(
                    mapping,
                    "integrity_available",
                    default=False,
                )
            ),
            "valid": _first(
                mapping,
                "integrity_valid",
                default=None,
            ),
            "sanitized_changed": _first(
                mapping,
                "sanitized_changed",
                "changed",
                default=None,
            ),
        },
        "summary": {
            "finding_count": len(findings),
            "high_risk_finding_count": sum(
                1 for finding in findings if _high_risk(_finding_severity(finding))
            ),
            "signal_count": len(signals),
            "stage_count": len(stages),
            "failed_stage_count": sum(
                1
                for stage in stages
                if bool(
                    _first(
                        stage,
                        "failed",
                        "error",
                        default=False,
                    )
                )
            ),
        },
    }

    if config.include_model_probability:
        result["model"]["malicious_probability"] = probability

    result["reasons"] = reasons

    result["findings"] = [_json_safe(finding) for finding in findings]

    if config.include_signals:
        result["signals"] = [_json_safe(signal) for signal in signals]

    if config.include_stage_status:
        result["stages"] = [_json_safe(stage) for stage in stages]

    if config.include_recommendations:
        result["recommendations"] = _derive_recommendations(
            disposition,
            findings,
            mapping,
        )

    if config.include_metadata:
        result["metadata"] = _json_safe(_extract_metadata(mapping))

    return result


def _derive_recommendations(
    disposition: str,
    findings: Sequence[Mapping[str, Any]],
    mapping: Mapping[str, Any],
) -> list[str]:
    recommendations: list[str] = []

    if disposition == "reject":
        recommendations.append(
            "Reject or quarantine the artifact and prevent downstream delivery."
        )

    elif disposition == "review":
        recommendations.append(
            "Route the artifact to an analyst before delivery or opening."
        )

    elif disposition == "sanitize":
        recommendations.append(
            "Run the configured CDR sanitization policy before delivery."
        )

    elif disposition == "allow":
        recommendations.append("Artifact passed the configured decision criteria.")

    if bool(
        _first(
            mapping,
            "requires_sanitization",
            default=False,
        )
    ):
        recommendations.append(
            "Preserve the original artifact separately and deliver only the sanitized reconstruction."
        )

    if bool(
        _first(
            mapping,
            "requires_review",
            default=False,
        )
    ):
        recommendations.append("Retain analyst review status in the audit trail.")

    integrity_valid = _first(
        mapping,
        "integrity_valid",
        default=None,
    )

    if integrity_valid is False:
        recommendations.append(
            "Do not deliver the reconstructed artifact until integrity validation succeeds."
        )

    for finding in findings[:20]:
        severity = _finding_severity(finding)
        category = _normalize_name(
            _first(
                finding,
                "category",
                "type",
                default="",
            )
        )

        if severity not in {
            "high",
            "critical",
        }:
            continue

        if category in {
            "macro",
            "vba",
            "xlm",
            "macro_execution",
        }:
            recommendations.append("Remove active macro content.")

        elif category in {
            "payload",
            "embedded_payload",
            "executable_payload",
        }:
            recommendations.append("Remove embedded executable or payload content.")

        elif category in {
            "evasion",
            "anti_analysis",
            "obfuscation",
        }:
            recommendations.append(
                "Treat evasion or obfuscation findings as high-risk indicators."
            )

        elif category in {
            "credential",
            "credential_access",
            "collection",
        }:
            recommendations.append(
                "Investigate possible credential or sensitive-data access."
            )

    return list(dict.fromkeys(recommendations))[:100]


def build_report_data(
    decision: Any,
    *,
    config: Optional[ReportConfig] = None,
) -> dict[str, Any]:
    """
    Build the canonical report data structure.

    The returned object contains metadata, artifact identity, decision state,
    findings, signals, stages, recommendations, and optional analyzer metadata.
    """
    if config is None:
        config = ReportConfig()

    payload = _canonical_report_payload(
        decision,
        config=config,
    )

    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")

    if len(encoded) > MAX_REPORT_BYTES:
        raise ReportLimitError("report data exceeds maximum size")

    return payload


def report_to_json(
    decision: Any,
    *,
    config: Optional[ReportConfig] = None,
) -> str:
    """Serialize a decision result as JSON."""
    if config is None:
        config = ReportConfig()

    payload = build_report_data(
        decision,
        config=config,
    )

    try:
        if config.pretty_json:
            content = json.dumps(
                payload,
                ensure_ascii=False,
                sort_keys=True,
                indent=2,
            )
        else:
            content = json.dumps(
                payload,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
    except (TypeError, ValueError) as exc:
        raise ReportSerializationError("failed to serialize report as JSON") from exc

    _enforce_report_size(content)

    return content


def report_to_jsonl(
    decisions: Iterable[Any],
    *,
    config: Optional[ReportConfig] = None,
) -> str:
    """
    Serialize multiple decisions as JSON Lines.

    Each line is an independent report object.
    """
    if config is None:
        config = ReportConfig(pretty_json=False)

    lines: list[str] = []
    total_bytes = 0

    for decision in decisions:
        payload = build_report_data(
            decision,
            config=config,
        )

        line = json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )

        encoded_size = len(line.encode("utf-8")) + 1

        total_bytes += encoded_size

        if total_bytes > MAX_REPORT_BYTES:
            raise ReportLimitError("JSONL report exceeds maximum size")

        lines.append(line)

        if len(lines) >= MAX_FINDINGS:
            break

    return "\n".join(lines) + ("\n" if lines else "")


def _html_table_rows(
    values: Sequence[tuple[str, Any]],
) -> str:
    rows: list[str] = []

    for label, value in values:
        rows.append(
            "<tr>" f"<th>{_escape(label)}</th>" f"<td>{_escape(value)}</td>" "</tr>"
        )

    return "\n".join(rows)


def _finding_html(
    finding: Mapping[str, Any],
) -> str:
    category = _safe_text(
        _first(
            finding,
            "category",
            "type",
            default="unknown",
        ),
        256,
    )

    title = _safe_text(
        _first(
            finding,
            "title",
            "name",
            "finding",
            default=category,
        ),
        512,
    )

    severity = _finding_severity(finding)

    score = _finding_score(finding)

    source = _safe_text(
        _first(
            finding,
            "source",
            "analyzer",
            "module",
            default="",
        ),
        256,
    )

    evidence = _first(
        finding,
        "evidence",
        "details",
        "detail",
        default=[],
    )

    if isinstance(evidence, str):
        evidence_items = [evidence]
    elif isinstance(
        evidence,
        (list, tuple),
    ):
        evidence_items = [_safe_text(item, 4096) for item in evidence[:20]]
    else:
        evidence_items = []

    indicators = _first(
        finding,
        "indicators",
        "indicator",
        default=[],
    )

    if isinstance(indicators, str):
        indicator_items = [indicators]
    elif isinstance(
        indicators,
        (list, tuple),
    ):
        indicator_items = [_safe_text(item, 512) for item in indicators[:30]]
    else:
        indicator_items = []

    remediation = _safe_text(
        _first(
            finding,
            "remediation",
            "recommendation",
            default="",
        ),
        4096,
    )

    evidence_html = (
        "<ul>"
        + "".join(
            f"<li><code>{_escape(item)}</code></li>" for item in evidence_items if item
        )
        + "</ul>"
        if evidence_items
        else '<span class="muted">No evidence supplied.</span>'
    )

    indicators_html = (
        "<ul>"
        + "".join(
            f"<li><code>{_escape(item)}</code></li>" for item in indicator_items if item
        )
        + "</ul>"
        if indicator_items
        else '<span class="muted">None</span>'
    )

    return f"""
<section class="finding severity-{_escape(severity)}">
  <div class="finding-header">
    <div>
      <h3>{_escape(title)}</h3>
      <div class="muted">{_escape(category)}</div>
    </div>
    <div class="finding-score">
      <span class="badge">{_escape(severity.upper())}</span>
      <span>{_escape(_format_score(score))}</span>
    </div>
  </div>
  <table class="details">
    {_html_table_rows([
        ("Source", source or "N/A"),
        ("Severity", severity),
    ])}
  </table>
  <h4>Indicators</h4>
  {indicators_html}
  <h4>Evidence</h4>
  {evidence_html}
  <h4>Remediation</h4>
  <p>{_escape(remediation or "Review according to the configured CDR policy.")}</p>
</section>
"""


def _signal_html(
    signal: Mapping[str, Any],
) -> str:
    source = _safe_text(
        _first(
            signal,
            "source",
            default="unknown",
        ),
        256,
    )

    category = _safe_text(
        _first(
            signal,
            "category",
            default="unknown",
        ),
        256,
    )

    name = _safe_text(
        _first(
            signal,
            "name",
            "indicator",
            default=category,
        ),
        512,
    )

    severity = _severity_value(
        _first(
            signal,
            "severity",
            default="info",
        )
    )

    score = _finding_score(signal)

    confidence = _safe_float(
        _first(
            signal,
            "confidence",
            default=None,
        )
    )

    evidence = _safe_text(
        _first(
            signal,
            "evidence",
            default="",
        ),
        4096,
    )

    confidence_text = f"{confidence:.3f}" if confidence is not None else "N/A"

    return f"""
<tr>
  <td>{_escape(source)}</td>
  <td>{_escape(category)}</td>
  <td>{_escape(name)}</td>
  <td><span class="badge">{_escape(severity.upper())}</span></td>
  <td>{_escape(_format_score(score))}</td>
  <td>{_escape(confidence_text)}</td>
  <td>{_escape(evidence)}</td>
</tr>
"""


def _stage_html(
    stage: Mapping[str, Any],
) -> str:
    name = _safe_text(
        _first(
            stage,
            "stage",
            "name",
            default="unknown",
        ),
        256,
    )

    available = _first(
        stage,
        "available",
        default=None,
    )

    successful = _first(
        stage,
        "successful",
        "success",
        "ok",
        default=None,
    )

    failed = _first(
        stage,
        "failed",
        default=False,
    )

    error = _safe_text(
        _first(
            stage,
            "error",
            "exception",
            "message",
            default="",
        ),
        4096,
    )

    status = (
        "failed" if bool(failed) else ("success" if bool(successful) else "unavailable")
    )

    return f"""
<tr>
  <td>{_escape(name)}</td>
  <td>{_escape(_format_bool(available))}</td>
  <td><span class="badge">{_escape(status.upper())}</span></td>
  <td>{_escape(error)}</td>
</tr>
"""


def report_to_html(
    decision: Any,
    *,
    config: Optional[ReportConfig] = None,
) -> str:
    """
    Render a complete self-contained HTML report.

    No external resources or active browser content are included.
    """
    if config is None:
        config = ReportConfig()

    data = build_report_data(
        decision,
        config=config,
    )

    decision_data = data["decision"]
    artifact = data["artifact"]
    model = data["model"]
    cdr = data["cdr"]
    integrity = data["integrity"]
    summary_data = data["summary"]

    findings = data.get(
        "findings",
        [],
    )

    reasons = data.get(
        "reasons",
        [],
    )

    signals = data.get(
        "signals",
        [],
    )

    stages = data.get(
        "stages",
        [],
    )

    recommendations = data.get(
        "recommendations",
        [],
    )

    disposition = decision_data["disposition"]

    title = config.html_title.strip() or "Pharos CDR Analysis Report"

    finding_sections = "\n".join(
        _finding_html(finding) for finding in findings if isinstance(finding, Mapping)
    )

    if not finding_sections:
        finding_sections = '<p class="muted">No findings were recorded.</p>'

    reason_items = "".join(f"<li>{_escape(reason)}</li>" for reason in reasons)

    recommendation_items = "".join(
        f"<li>{_escape(item)}</li>" for item in recommendations
    )

    signal_rows = "".join(
        _signal_html(signal) for signal in signals if isinstance(signal, Mapping)
    )

    if not signal_rows:
        signal_rows = (
            '<tr><td colspan="7" class="muted">'
            "No decision signals were recorded."
            "</td></tr>"
        )

    stage_rows = "".join(
        _stage_html(stage) for stage in stages if isinstance(stage, Mapping)
    )

    if not stage_rows:
        stage_rows = (
            '<tr><td colspan="4" class="muted">'
            "No stage information was recorded."
            "</td></tr>"
        )

    probability = model.get("malicious_probability")

    html_document = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="generator" content="{_escape(MODULE_NAME)} {REPORT_VERSION}">
<title>{_escape(title)}</title>
<style>
:root {{
  color-scheme: light;
  font-family: system-ui, -apple-system, BlinkMacSystemFont,
               "Segoe UI", sans-serif;
  line-height: 1.5;
}}
body {{
  margin: 0;
  background: #f5f7fa;
  color: #1b1f24;
}}
main {{
  max-width: 1200px;
  margin: 0 auto;
  padding: 32px 20px 64px;
}}
header {{
  margin-bottom: 24px;
}}
h1, h2, h3, h4 {{
  line-height: 1.2;
}}
.card {{
  background: #fff;
  border: 1px solid #d8dde3;
  border-radius: 10px;
  padding: 20px;
  margin: 16px 0;
  overflow-wrap: anywhere;
}}
.grid {{
  display: grid;
  grid-template-columns: repeat(auto-fit,minmax(220px,1fr));
  gap: 12px;
}}
.metric {{
  background: #fff;
  border: 1px solid #d8dde3;
  border-radius: 8px;
  padding: 16px;
}}
.metric-label {{
  font-size: .8rem;
  text-transform: uppercase;
  letter-spacing: .04em;
  color: #59636e;
}}
.metric-value {{
  font-size: 1.35rem;
  font-weight: 700;
  margin-top: 4px;
}}
.badge {{
  display: inline-block;
  border: 1px solid #aab2bb;
  border-radius: 999px;
  padding: 2px 8px;
  font-size: .72rem;
  font-weight: 700;
  letter-spacing: .04em;
}}
.disposition {{
  font-size: 1.7rem;
  font-weight: 800;
  text-transform: uppercase;
}}
.details {{
  width: 100%;
  border-collapse: collapse;
}}
.details th,
.details td {{
  text-align: left;
  vertical-align: top;
  padding: 8px;
  border-bottom: 1px solid #e4e7eb;
}}
.details th {{
  width: 220px;
}}
table.report-table {{
  width: 100%;
  border-collapse: collapse;
  display: block;
  overflow-x: auto;
}}
.report-table th,
.report-table td {{
  padding: 9px;
  border-bottom: 1px solid #e1e5e9;
  text-align: left;
  vertical-align: top;
}}
.finding {{
  border: 1px solid #d8dde3;
  border-radius: 8px;
  padding: 16px;
  margin: 12px 0;
  background: #fff;
}}
.finding-header {{
  display: flex;
  justify-content: space-between;
  gap: 16px;
  align-items: flex-start;
}}
.finding-score {{
  text-align: right;
  white-space: nowrap;
}}
.severity-critical {{
  border-left: 6px solid #6b1b1b;
}}
.severity-high {{
  border-left: 6px solid #914d19;
}}
.severity-medium {{
  border-left: 6px solid #7a6717;
}}
.severity-low {{
  border-left: 6px solid #405a75;
}}
.muted {{
  color: #626c76;
}}
code {{
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  overflow-wrap: anywhere;
}}
footer {{
  margin-top: 32px;
  font-size: .8rem;
  color: #66707a;
}}
@media (max-width: 700px) {{
  main {{
    padding: 20px 12px 48px;
  }}
  .finding-header {{
    display: block;
  }}
  .finding-score {{
    text-align: left;
    margin-top: 8px;
  }}
}}
</style>
</head>
<body>
<main>
<header>
  <h1>{_escape(title)}</h1>
  <div class="muted">
    Generated by {_escape(MODULE_NAME)} {REPORT_VERSION}
  </div>
</header>

<section class="grid">
  <div class="metric">
    <div class="metric-label">Disposition</div>
    <div class="metric-value disposition">{_escape(disposition)}</div>
  </div>
  <div class="metric">
    <div class="metric-label">Risk Score</div>
    <div class="metric-value">{_escape(_format_score(decision_data["score"]))}</div>
  </div>
  <div class="metric">
    <div class="metric-label">Confidence</div>
    <div class="metric-value">{_escape(decision_data["confidence"])}</div>
  </div>
  <div class="metric">
    <div class="metric-label">ML Probability</div>
    <div class="metric-value">{_escape(_format_probability(probability))}</div>
  </div>
</section>

<section class="card">
  <h2>Artifact</h2>
  <table class="details">
    {_html_table_rows([
        ("Sample ID", artifact.get("sample_id", "")),
        ("SHA-256", artifact.get("sha256", "") or "N/A"),
        ("File name", artifact.get("file_name", "") or "N/A"),
        ("File type", artifact.get("file_type", "") or "N/A"),
        ("Decision ID", decision_data.get("decision_id", "") or "N/A"),
    ])}
  </table>
</section>

<section class="card">
  <h2>Decision State</h2>
  <table class="details">
    {_html_table_rows([
        ("Requires sanitization", _format_bool(
            decision_data.get("requires_sanitization")
        )),
        ("Requires review", _format_bool(
            decision_data.get("requires_review")
        )),
        ("Rejected", _format_bool(
            decision_data.get("rejected")
        )),
        ("CDR available", _format_bool(
            cdr.get("available")
        )),
        ("Policy action", cdr.get("policy_action") or "N/A"),
        ("Integrity available", _format_bool(
            integrity.get("available")
        )),
        ("Integrity valid", _format_bool(
            integrity.get("valid")
        )),
        ("Sanitized changed", _format_bool(
            integrity.get("sanitized_changed")
        )),
    ])}
  </table>
</section>

<section class="card">
  <h2>Summary</h2>
  <div class="grid">
    <div class="metric">
      <div class="metric-label">Findings</div>
      <div class="metric-value">{_escape(summary_data["finding_count"])}</div>
    </div>
    <div class="metric">
      <div class="metric-label">High-risk Findings</div>
      <div class="metric-value">{_escape(summary_data["high_risk_finding_count"])}</div>
    </div>
    <div class="metric">
      <div class="metric-label">Signals</div>
      <div class="metric-value">{_escape(summary_data["signal_count"])}</div>
    </div>
    <div class="metric">
      <div class="metric-label">Failed Stages</div>
      <div class="metric-value">{_escape(summary_data["failed_stage_count"])}</div>
    </div>
  </div>
</section>

<section class="card">
  <h2>Reasons</h2>
  <ul>
    {reason_items or '<li class="muted">No explicit reasons recorded.</li>'}
  </ul>
</section>

<section class="card">
  <h2>Recommendations</h2>
  <ul>
    {recommendation_items or '<li class="muted">No recommendations recorded.</li>'}
  </ul>
</section>

<section class="card">
  <h2>Findings</h2>
  {finding_sections}
</section>

<section class="card">
  <h2>Pipeline Stages</h2>
  <table class="report-table">
    <thead>
      <tr>
        <th>Stage</th>
        <th>Available</th>
        <th>Status</th>
        <th>Error</th>
      </tr>
    </thead>
    <tbody>
      {stage_rows}
    </tbody>
  </table>
</section>

<section class="card">
  <h2>Decision Signals</h2>
  <table class="report-table">
    <thead>
      <tr>
        <th>Source</th>
        <th>Category</th>
        <th>Name</th>
        <th>Severity</th>
        <th>Score</th>
        <th>Confidence</th>
        <th>Evidence</th>
      </tr>
    </thead>
    <tbody>
      {signal_rows}
    </tbody>
  </table>
</section>

<footer>
  Report ID:
  <code>{_escape(data["report"]["report_id"])}</code>
  <br>
  Generated:
  <code>{_escape(data["report"]["created_at"])}</code>
</footer>
</main>
</body>
</html>
"""

    _enforce_report_size(html_document)

    return html_document


def report_to_text(
    decision: Any,
    *,
    config: Optional[ReportConfig] = None,
) -> str:
    """Render a concise analyst-oriented plain-text report."""
    if config is None:
        config = ReportConfig()

    data = build_report_data(
        decision,
        config=config,
    )

    decision_data = data["decision"]
    artifact = data["artifact"]
    model = data["model"]
    cdr = data["cdr"]
    integrity = data["integrity"]
    summary_data = data["summary"]

    lines: list[str] = [
        "PHAROS CDR ANALYSIS REPORT",
        "=" * 80,
        "",
        f"Disposition: {decision_data['disposition'].upper()}",
        f"Risk score: {_format_score(decision_data['score'])}",
        f"Confidence: {decision_data['confidence']}",
        (
            "ML malicious probability: "
            + _format_probability(model.get("malicious_probability"))
        ),
        "",
        "ARTIFACT",
        "-" * 80,
        f"Sample ID: {artifact.get('sample_id') or 'N/A'}",
        f"SHA-256: {artifact.get('sha256') or 'N/A'}",
        f"File name: {artifact.get('file_name') or 'N/A'}",
        f"File type: {artifact.get('file_type') or 'N/A'}",
        f"Decision ID: {decision_data.get('decision_id') or 'N/A'}",
        "",
        "DECISION STATE",
        "-" * 80,
        (
            "Requires sanitization: "
            + _format_bool(decision_data.get("requires_sanitization"))
        ),
        ("Requires review: " + _format_bool(decision_data.get("requires_review"))),
        ("Rejected: " + _format_bool(decision_data.get("rejected"))),
        ("CDR available: " + _format_bool(cdr.get("available"))),
        ("Policy action: " + (cdr.get("policy_action") or "N/A")),
        ("Integrity available: " + _format_bool(integrity.get("available"))),
        ("Integrity valid: " + _format_bool(integrity.get("valid"))),
        ("Sanitized changed: " + _format_bool(integrity.get("sanitized_changed"))),
        "",
        "SUMMARY",
        "-" * 80,
        f"Findings: {summary_data['finding_count']}",
        ("High-risk findings: " f"{summary_data['high_risk_finding_count']}"),
        f"Signals: {summary_data['signal_count']}",
        f"Stages: {summary_data['stage_count']}",
        ("Failed stages: " f"{summary_data['failed_stage_count']}"),
        "",
        "REASONS",
        "-" * 80,
    ]

    reasons = data.get(
        "reasons",
        [],
    )

    if reasons:
        lines.extend(f"- {reason}" for reason in reasons)
    else:
        lines.append("- No explicit reasons recorded.")

    lines.extend(
        [
            "",
            "RECOMMENDATIONS",
            "-" * 80,
        ]
    )

    recommendations = data.get(
        "recommendations",
        [],
    )

    if recommendations:
        lines.extend(f"- {recommendation}" for recommendation in recommendations)
    else:
        lines.append("- No recommendations recorded.")

    lines.extend(
        [
            "",
            "FINDINGS",
            "-" * 80,
        ]
    )

    findings = data.get(
        "findings",
        [],
    )

    if findings:
        for index, finding in enumerate(
            findings,
            start=1,
        ):
            category = _safe_text(
                _first(
                    finding,
                    "category",
                    "type",
                    default="unknown",
                ),
                256,
            )

            title = _safe_text(
                _first(
                    finding,
                    "title",
                    "name",
                    "finding",
                    default=category,
                ),
                512,
            )

            severity = _finding_severity(finding)

            score = _finding_score(finding)

            source = _safe_text(
                _first(
                    finding,
                    "source",
                    "analyzer",
                    "module",
                    default="N/A",
                ),
                256,
            )

            lines.extend(
                [
                    "",
                    (
                        f"{index}. {title} "
                        f"[{severity.upper()}] "
                        f"{_format_score(score)}"
                    ),
                    f"   Category: {category}",
                    f"   Source: {source}",
                ]
            )

            evidence = _first(
                finding,
                "evidence",
                "details",
                "detail",
                default=[],
            )

            if isinstance(evidence, str):
                evidence = [evidence]

            if isinstance(
                evidence,
                (list, tuple),
            ):
                for item in evidence[:10]:
                    text = _safe_text(
                        item,
                        4096,
                    )

                    if text:
                        lines.append(f"   Evidence: {text}")

    else:
        lines.append("No findings recorded.")

    lines.extend(
        [
            "",
            "=" * 80,
            (f"Report ID: " f"{data['report']['report_id']}"),
            (f"Generated: " f"{data['report']['created_at']}"),
        ]
    )

    content = "\n".join(lines) + "\n"

    _enforce_report_size(content)

    return content


def _enforce_report_size(
    content: str,
) -> None:
    size = len(content.encode("utf-8"))

    if size > MAX_REPORT_BYTES:
        raise ReportLimitError(f"report exceeds {MAX_REPORT_BYTES} bytes")


def create_report(
    decision: Any,
    *,
    report_format: ReportFormat | str = ReportFormat.JSON,
    config: Optional[ReportConfig] = None,
) -> ReportArtifact:
    """
    Generate a report artifact in the requested format.
    """
    if config is None:
        config = ReportConfig()

    try:
        if not isinstance(
            report_format,
            ReportFormat,
        ):
            report_format = ReportFormat(_normalize_name(report_format))
    except ValueError as exc:
        raise ReportInputError(f"unsupported report format: {report_format!r}") from exc

    mapping = _extract_decision_mapping(decision)

    if report_format == ReportFormat.JSON:
        content = report_to_json(
            decision,
            config=config,
        )
    elif report_format == ReportFormat.JSONL:
        content = report_to_jsonl(
            [decision],
            config=config,
        )
    elif report_format == ReportFormat.HTML:
        content = report_to_html(
            decision,
            config=config,
        )
    elif report_format == ReportFormat.TEXT:
        content = report_to_text(
            decision,
            config=config,
        )
    else:
        raise ReportInputError(f"unsupported report format: {report_format!r}")

    digest = hashlib.sha256(content.encode("utf-8")).hexdigest()

    report_id = _make_report_id(
        mapping,
        report_format,
    )

    return ReportArtifact(
        report_id=report_id,
        format=report_format,
        content=content,
        sha256=digest,
        byte_size=len(content.encode("utf-8")),
        created_at=_format_timestamp(),
        decision_id=_safe_text(
            _first(
                mapping,
                "decision_id",
                "id",
                default="",
            ),
            256,
        ),
        sample_id=_safe_text(
            _first(
                mapping,
                "sample_id",
                "scan_id",
                default="",
            ),
            256,
        ),
    )


def save_report(
    decision: Any,
    path: str | os.PathLike[str],
    *,
    report_format: ReportFormat | str | None = None,
    config: Optional[ReportConfig] = None,
) -> ReportArtifact:
    """
    Generate and persist a report.

    The destination directory is created when necessary. Only the report
    itself is written; analyzed document content is never written here.
    """
    target = Path(path)

    if not target.name:
        raise ReportInputError("report path must name a file")

    if report_format is None:
        report_format = _format_from_suffix(target.suffix)

    artifact = create_report(
        decision,
        report_format=report_format,
        config=config,
    )

    target.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    target.write_text(
        artifact.content,
        encoding="utf-8",
    )

    return artifact


def save_json_report(
    decision: Any,
    path: str | os.PathLike[str],
    *,
    config: Optional[ReportConfig] = None,
) -> ReportArtifact:
    """Generate and save a JSON report."""
    return save_report(
        decision,
        path,
        report_format=ReportFormat.JSON,
        config=config,
    )


def save_html_report(
    decision: Any,
    path: str | os.PathLike[str],
    *,
    config: Optional[ReportConfig] = None,
) -> ReportArtifact:
    """Generate and save an HTML report."""
    return save_report(
        decision,
        path,
        report_format=ReportFormat.HTML,
        config=config,
    )


def save_text_report(
    decision: Any,
    path: str | os.PathLike[str],
    *,
    config: Optional[ReportConfig] = None,
) -> ReportArtifact:
    """Generate and save a plain-text report."""
    return save_report(
        decision,
        path,
        report_format=ReportFormat.TEXT,
        config=config,
    )


def _format_from_suffix(
    suffix: str,
) -> ReportFormat:
    suffix = _normalize_name(suffix.lstrip("."))

    mapping = {
        "json": ReportFormat.JSON,
        "jsonl": ReportFormat.JSONL,
        "ndjson": ReportFormat.JSONL,
        "html": ReportFormat.HTML,
        "htm": ReportFormat.HTML,
        "txt": ReportFormat.TEXT,
        "text": ReportFormat.TEXT,
    }

    if suffix not in mapping:
        raise ReportInputError(
            "cannot infer report format from file extension; "
            "use .json, .jsonl, .html, or .txt"
        )

    return mapping[suffix]


def report_summary(
    decision: Any,
) -> ReportSummary:
    """Return a compact report summary."""
    mapping = _extract_decision_mapping(decision)

    findings = _extract_findings(
        mapping,
        MAX_FINDINGS,
    )

    stages = _extract_stages(mapping)

    probability = _extract_probability(mapping)

    return ReportSummary(
        report_id=_make_report_id(
            mapping,
            ReportFormat.JSON,
        ),
        disposition=_extract_disposition(mapping),
        score=_extract_score(mapping),
        confidence=_extract_confidence(mapping),
        malicious_probability=probability,
        finding_count=len(findings),
        high_risk_finding_count=sum(
            1 for finding in findings if _high_risk(_finding_severity(finding))
        ),
        stage_count=len(stages),
        failed_stage_count=sum(
            1
            for stage in stages
            if bool(
                _first(
                    stage,
                    "failed",
                    default=False,
                )
            )
        ),
        requires_sanitization=bool(
            _first(
                mapping,
                "requires_sanitization",
                default=(_extract_disposition(mapping) == "sanitize"),
            )
        ),
        requires_review=bool(
            _first(
                mapping,
                "requires_review",
                default=(_extract_disposition(mapping) == "review"),
            )
        ),
        rejected=bool(
            _first(
                mapping,
                "rejected",
                default=(_extract_disposition(mapping) == "reject"),
            )
        ),
        sha256=_extract_sha256(mapping),
        decision_id=_safe_text(
            _first(
                mapping,
                "decision_id",
                "id",
                default="",
            ),
            256,
        ),
    )


def summary_to_dict(
    value: ReportSummary,
) -> dict[str, Any]:
    """Serialize a report summary."""
    if not isinstance(
        value,
        ReportSummary,
    ):
        raise ReportInputError("value must be a ReportSummary")

    return {
        "report_id": value.report_id,
        "disposition": value.disposition,
        "score": value.score,
        "confidence": value.confidence,
        "malicious_probability": (value.malicious_probability),
        "finding_count": value.finding_count,
        "high_risk_finding_count": (value.high_risk_finding_count),
        "stage_count": value.stage_count,
        "failed_stage_count": (value.failed_stage_count),
        "requires_sanitization": (value.requires_sanitization),
        "requires_review": value.requires_review,
        "rejected": value.rejected,
        "sha256": value.sha256,
        "decision_id": value.decision_id,
    }


def iter_findings(
    decision: Any,
) -> Iterator[Mapping[str, Any]]:
    """Iterate decision findings in their supplied order."""
    mapping = _extract_decision_mapping(decision)

    yield from _extract_findings(
        mapping,
        MAX_FINDINGS,
    )


def iter_high_risk_findings(
    decision: Any,
) -> Iterator[Mapping[str, Any]]:
    """Iterate high and critical findings."""
    for finding in iter_findings(decision):
        if _high_risk(_finding_severity(finding)):
            yield finding


def finding_count(
    decision: Any,
) -> int:
    """Return the number of reportable findings."""
    return sum(1 for _ in iter_findings(decision))


def high_risk_finding_count(
    decision: Any,
) -> int:
    """Return the number of high/critical findings."""
    return sum(1 for _ in iter_high_risk_findings(decision))


def report_hash(
    content: str | bytes,
) -> str:
    """Return the SHA-256 digest of report content."""
    if isinstance(content, str):
        content = content.encode("utf-8")

    if not isinstance(
        content,
        bytes,
    ):
        raise ReportInputError("content must be str or bytes")

    if len(content) > MAX_REPORT_BYTES:
        raise ReportLimitError("content exceeds maximum report size")

    return hashlib.sha256(content).hexdigest()


def validate_report(
    content: str | bytes,
) -> tuple[str, ...]:
    """
    Validate report size and basic serialization.

    Returns an empty tuple when valid.
    """
    errors: list[str] = []

    if isinstance(content, str):
        encoded = content.encode("utf-8")
        text = content
    elif isinstance(content, bytes):
        encoded = content

        try:
            text = content.decode("utf-8")
        except UnicodeDecodeError:
            errors.append("report is not valid UTF-8")
            return tuple(errors)
    else:
        return ("report must be str or bytes",)

    if len(encoded) > MAX_REPORT_BYTES:
        errors.append("report exceeds maximum size")

    stripped = text.lstrip()

    if stripped.startswith("<!doctype html") or stripped.startswith("<html"):
        if "</html>" not in text.lower():
            errors.append("HTML report is missing closing html element")

    elif stripped:
        try:
            json.loads(text)
        except json.JSONDecodeError:
            # JSONL is also valid report output; validate each non-empty line.
            for index, line in enumerate(
                text.splitlines(),
                start=1,
            ):
                if not line.strip():
                    continue

                try:
                    json.loads(line)
                except json.JSONDecodeError:
                    if index == 1:
                        errors.append("content is neither valid JSON nor valid JSONL")
                    break

    return tuple(errors)


def default_config() -> ReportConfig:
    """Return the standard report configuration."""
    return ReportConfig()


def analyst_config() -> ReportConfig:
    """
    Return a configuration optimized for analyst-facing reports.
    """
    return ReportConfig(
        include_signals=True,
        include_evidence=True,
        include_metadata=True,
        include_stage_status=True,
        include_recommendations=True,
        include_model_probability=True,
        pretty_json=True,
    )


def api_config() -> ReportConfig:
    """
    Return a compact configuration suitable for API responses.
    """
    return ReportConfig(
        include_signals=False,
        include_evidence=False,
        include_metadata=False,
        include_stage_status=False,
        include_recommendations=True,
        include_model_probability=True,
        pretty_json=False,
        max_findings=5_000,
        max_signals=1,
        max_reasons=100,
    )


def minimal_config() -> ReportConfig:
    """Return a minimal deterministic report configuration."""
    return ReportConfig(
        include_signals=False,
        include_evidence=False,
        include_metadata=False,
        include_stage_status=False,
        include_recommendations=False,
        include_model_probability=True,
        pretty_json=False,
        max_findings=1_000,
        max_signals=1,
        max_reasons=50,
    )


def generate_report(
    decision: Any,
    *,
    report_format: ReportFormat | str = ReportFormat.JSON,
    config: Optional[ReportConfig] = None,
) -> ReportArtifact:
    """Alias for :func:`create_report`."""
    return create_report(
        decision,
        report_format=report_format,
        config=config,
    )


def render_json(
    decision: Any,
    *,
    config: Optional[ReportConfig] = None,
) -> str:
    """Alias for :func:`report_to_json`."""
    return report_to_json(
        decision,
        config=config,
    )


def render_html(
    decision: Any,
    *,
    config: Optional[ReportConfig] = None,
) -> str:
    """Alias for :func:`report_to_html`."""
    return report_to_html(
        decision,
        config=config,
    )


def render_text(
    decision: Any,
    *,
    config: Optional[ReportConfig] = None,
) -> str:
    """Alias for :func:`report_to_text`."""
    return report_to_text(
        decision,
        config=config,
    )


# ---------------------------------------------------------------------------
# PUBLIC APIs
# ---------------------------------------------------------------------------

__all__ = [
    "MODULE_NAME",
    "REPORT_VERSION",
    "MAX_INPUT_BYTES",
    "MAX_REPORT_BYTES",
    "DEFAULT_REPORT_DIRECTORY",
    "ReportError",
    "ReportInputError",
    "ReportLimitError",
    "ReportSerializationError",
    "ReportFormat",
    "ReportConfig",
    "ReportArtifact",
    "ReportSummary",
    "build_report_data",
    "report_to_json",
    "report_to_jsonl",
    "report_to_html",
    "report_to_text",
    "create_report",
    "generate_report",
    "save_report",
    "save_json_report",
    "save_html_report",
    "save_text_report",
    "report_summary",
    "summary_to_dict",
    "iter_findings",
    "iter_high_risk_findings",
    "finding_count",
    "high_risk_finding_count",
    "report_hash",
    "validate_report",
    "default_config",
    "analyst_config",
    "api_config",
    "minimal_config",
    "render_json",
    "render_html",
    "render_text",
]
