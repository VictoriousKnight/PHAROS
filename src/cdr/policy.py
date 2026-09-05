"""
pharos-cdr - Content Disarm and Reconstruction policy engine.

This module defines deterministic policy rules for CDR decisions.

Security properties
-------------------
- Static analysis only.
- Never executes macros, scripts, embedded objects, or external links.
- Never downloads referenced resources.
- Never writes sanitized content.
- Bounded processing of untrusted parser/detector output.
- Deterministic rule evaluation.
- Explicit reason/evidence tracking for auditability.
- Fail-closed behavior for malformed or ambiguous high-risk findings.

The policy engine consumes normalized parser/detector findings rather than
attempting to rediscover document semantics itself.

Typical flow
------------
    parser.py
        |
        v
    detector.py
        |
        v
    policy.py
        |
        +--> sanitizer.py
        |
        +--> reconstruction.py
        |
        +--> integrity.py

The policy layer answers questions such as:

    * Is the document allowed?
    * Which components must be removed?
    * Which components may be retained?
    * Does the document require manual review?
    * Why was a particular action selected?

It intentionally does not modify the source document.

Public APIs are listed at the end of this module.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import asdict, dataclass, field, is_dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Iterable, Iterator, Mapping, Optional, Sequence


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MAX_INPUT_BYTES = 25 * 1024 * 1024
MAX_TEXT_LENGTH = 100_000
MAX_ITEMS = 20_000
MAX_EVIDENCE = 20_000
MAX_RULES = 2_000
MAX_ACTIONS = 10_000
MAX_DEPTH = 12
MAX_STRING_LENGTH = 10_000
MAX_JSON_LENGTH = 25 * 1024 * 1024

DEFAULT_POLICY_NAME = "balanced"
DEFAULT_POLICY_VERSION = "1.0"

DEFAULT_REVIEW_SCORE = 50.0
DEFAULT_BLOCK_SCORE = 80.0

SEVERITY_ORDER = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

ACTION_ORDER = {
    "preserve": 0,
    "sanitize": 1,
    "remove": 2,
    "reject": 3,
    "review": 4,
}

CATEGORY_ALIASES = {
    "macro": "macro",
    "macros": "macro",
    "vba": "macro",
    "vba_macro": "macro",
    "xlm": "xlm",
    "excel4": "xlm",
    "excel4_macro": "xlm",
    "activex": "activex",
    "active_x": "activex",
    "ole": "ole",
    "ole_object": "ole",
    "embedded_object": "embedded_object",
    "embedded_objects": "embedded_object",
    "embedding": "embedded_object",
    "external_link": "external_link",
    "external_links": "external_link",
    "relationship": "relationship",
    "relationships": "relationship",
    "template": "template",
    "remote_template": "template",
    "dde": "dde",
    "dynamic_data_exchange": "dde",
    "script": "script",
    "scripts": "script",
    "javascript": "script",
    "vbscript": "script",
    "powershell": "script",
    "payload": "payload",
    "executable": "executable",
    "executable_payload": "executable",
    "network": "network",
    "url": "network",
    "network_reference": "network",
    "credential": "credential",
    "credential_access": "credential",
    "persistence": "persistence",
    "evasion": "evasion",
    "obfuscation": "obfuscation",
    "encryption": "obfuscation",
    "encoding": "obfuscation",
    "unknown": "unknown",
}


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class PolicyError(Exception):
    """Base exception for policy processing."""


class PolicyInputError(PolicyError):
    """Raised when policy input is invalid."""


class PolicyConfigurationError(PolicyError):
    """Raised when a policy configuration is invalid."""


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class PolicyAction(str, Enum):
    """Action selected by the CDR policy engine."""

    PRESERVE = "preserve"
    SANITIZE = "sanitize"
    REMOVE = "remove"
    REJECT = "reject"
    REVIEW = "review"


class PolicyMode(str, Enum):
    """Overall policy operating mode."""

    PERMISSIVE = "permissive"
    BALANCED = "balanced"
    STRICT = "strict"


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PolicyFinding:
    """
    Normalized finding consumed by the policy engine.

    A finding may originate from parser.py, detector.py, or another static
    analyzer. The policy layer deliberately accepts generic findings so that
    upstream detector implementations can evolve independently.
    """

    category: str
    indicator: str = ""
    severity: str = "medium"
    confidence: float = 1.0
    message: str = ""
    path: str = ""
    object_type: str = ""
    action_hint: str = ""
    source: str = ""
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "category",
            normalize_category(self.category),
        )
        object.__setattr__(
            self,
            "indicator",
            _safe_string(self.indicator),
        )
        object.__setattr__(
            self,
            "severity",
            normalize_severity(self.severity),
        )
        object.__setattr__(
            self,
            "confidence",
            clamp_probability(self.confidence),
        )
        object.__setattr__(
            self,
            "message",
            _safe_string(self.message),
        )
        object.__setattr__(
            self,
            "path",
            _safe_string(self.path),
        )
        object.__setattr__(
            self,
            "object_type",
            _safe_string(self.object_type),
        )
        object.__setattr__(
            self,
            "action_hint",
            normalize_action(self.action_hint)
            if self.action_hint
            else "",
        )
        object.__setattr__(
            self,
            "source",
            _safe_string(self.source),
        )


@dataclass(frozen=True)
class PolicyRule:
    """One deterministic policy rule."""

    name: str
    category: str = ""
    indicator: str = ""
    severity_at_least: str = ""
    min_confidence: float = 0.0
    action: PolicyAction = PolicyAction.SANITIZE
    score: float = 0.0
    reason: str = ""
    enabled: bool = True
    priority: int = 100

    def __post_init__(self) -> None:
        object.__setattr__(self, "name", _safe_string(self.name))
        object.__setattr__(
            self,
            "category",
            normalize_category(self.category) if self.category else "",
        )
        object.__setattr__(
            self,
            "indicator",
            _safe_string(self.indicator).lower(),
        )
        object.__setattr__(
            self,
            "severity_at_least",
            normalize_severity(self.severity_at_least)
            if self.severity_at_least
            else "",
        )
        object.__setattr__(
            self,
            "min_confidence",
            clamp_probability(self.min_confidence),
        )
        object.__setattr__(
            self,
            "score",
            _safe_float(self.score),
        )
        object.__setattr__(
            self,
            "reason",
            _safe_string(self.reason),
        )
        object.__setattr__(
            self,
            "priority",
            int(self.priority),
        )


@dataclass(frozen=True)
class PolicyDecision:
    """Final policy decision for a document."""

    action: PolicyAction
    score: float
    severity: str
    confidence: float
    reasons: tuple[str, ...] = ()
    matched_rules: tuple[str, ...] = ()
    categories: tuple[str, ...] = ()
    indicators: tuple[str, ...] = ()
    findings_count: int = 0
    requires_sanitization: bool = False
    requires_review: bool = False
    reject: bool = False
    preserve_safe_content: bool = True

    @property
    def blocked(self) -> bool:
        """Return True when the document must be rejected."""
        return self.reject or self.action is PolicyAction.REJECT

    @property
    def sanitized(self) -> bool:
        """Return True when sanitization is required."""
        return self.requires_sanitization or self.action is PolicyAction.SANITIZE


@dataclass(frozen=True)
class PolicyActionPlan:
    """
    Component-level sanitization plan.

    This object does not perform modifications. It describes what a later
    sanitizer/reconstruction layer is permitted or required to do.
    """

    action: PolicyAction
    path: str = ""
    category: str = ""
    reason: str = ""
    finding_count: int = 0
    confidence: float = 0.0
    severity: str = "info"
    preserve_children: bool = False
    preserve_metadata: bool = True


@dataclass(frozen=True)
class PolicyResult:
    """Complete auditable result of policy evaluation."""

    policy_name: str
    policy_version: str
    mode: PolicyMode
    decision: PolicyDecision
    actions: tuple[PolicyActionPlan, ...] = ()
    findings: tuple[PolicyFinding, ...] = ()
    document_id: str = ""
    input_size: int = 0
    input_sha256: str = ""
    safe_content_preserved: bool = True
    deterministic: bool = True
    warnings: tuple[str, ...] = ()

    @property
    def allowed(self) -> bool:
        """Return True if the document is allowed through CDR."""
        return not self.decision.blocked

    @property
    def needs_review(self) -> bool:
        """Return True if human/manual review is required."""
        return self.decision.requires_review


@dataclass(frozen=True)
class Policy:
    """Named CDR policy configuration."""

    name: str
    version: str
    mode: PolicyMode
    review_score: float
    block_score: float
    rules: tuple[PolicyRule, ...]
    preserve_safe_content: bool = True
    remove_unknown_active_content: bool = True
    reject_malformed_active_content: bool = True

    def __post_init__(self) -> None:
        if self.review_score < 0:
            raise PolicyConfigurationError("review_score must be >= 0")
        if self.block_score < self.review_score:
            raise PolicyConfigurationError(
                "block_score must be >= review_score"
            )
        if len(self.rules) > MAX_RULES:
            raise PolicyConfigurationError(
                f"too many policy rules: {len(self.rules)}"
            )


@dataclass(frozen=True)
class PolicySummary:
    """Compact policy result suitable for API/reporting layers."""

    action: str
    score: float
    severity: str
    confidence: float
    finding_count: int
    matched_rule_count: int
    categories: tuple[str, ...]
    requires_sanitization: bool
    requires_review: bool
    blocked: bool
    safe_content_preserved: bool


# ---------------------------------------------------------------------------
# Normalization helpers
# ---------------------------------------------------------------------------


def _safe_string(value: Any, limit: int = MAX_STRING_LENGTH) -> str:
    if value is None:
        return ""

    if isinstance(value, bytes):
        value = value[:limit]
        return value.decode("utf-8", errors="replace")[:limit]

    try:
        text = str(value)
    except Exception:
        return ""

    return text[:limit]


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        result = float(value)
    except (TypeError, ValueError, OverflowError):
        return default

    if not math.isfinite(result):
        return default

    return result


def clamp_probability(value: Any) -> float:
    """Clamp a confidence/probability value to [0, 1]."""
    return max(0.0, min(1.0, _safe_float(value)))


def normalize_severity(value: Any) -> str:
    """Normalize severity to info/low/medium/high/critical."""
    text = _safe_string(value).strip().lower()

    aliases = {
        "none": "info",
        "informational": "info",
        "notice": "low",
        "warning": "medium",
        "moderate": "medium",
        "severe": "high",
        "very_high": "critical",
        "very-high": "critical",
        "urgent": "critical",
    }

    text = aliases.get(text, text)

    if text not in SEVERITY_ORDER:
        return "medium"

    return text


def normalize_category(value: Any) -> str:
    """Normalize a finding category to a stable canonical category."""
    text = _safe_string(value).strip().lower()
    text = re.sub(r"[\s\-./]+", "_", text)
    return CATEGORY_ALIASES.get(text, text or "unknown")


def normalize_action(value: Any) -> str:
    """Normalize an action name."""
    if isinstance(value, PolicyAction):
        return value.value

    text = _safe_string(value).strip().lower()

    aliases = {
        "allow": "preserve",
        "keep": "preserve",
        "clean": "sanitize",
        "strip": "remove",
        "delete": "remove",
        "deny": "reject",
        "block": "reject",
        "manual_review": "review",
        "needs_review": "review",
    }

    text = aliases.get(text, text)

    if text not in ACTION_ORDER:
        return ""

    return text


def severity_rank(value: Any) -> int:
    """Return the numeric rank of a severity."""
    return SEVERITY_ORDER.get(normalize_severity(value), 1)


def highest_severity(findings: Iterable[PolicyFinding]) -> str:
    """Return the highest severity represented by findings."""
    best = "info"

    for finding in findings:
        if severity_rank(finding.severity) > severity_rank(best):
            best = finding.severity

    return best


# ---------------------------------------------------------------------------
# Generic input normalization
# ---------------------------------------------------------------------------


def _bounded_text(value: Any) -> str:
    text = _safe_string(value, MAX_TEXT_LENGTH)
    return text


def _flatten_mapping(
    value: Any,
    *,
    prefix: str = "",
    depth: int = 0,
    output: Optional[list[tuple[str, Any]]] = None,
) -> list[tuple[str, Any]]:
    """
    Flatten detector/parser structures without recursively trusting
    arbitrary unbounded input.
    """
    if output is None:
        output = []

    if len(output) >= MAX_ITEMS:
        return output

    if depth > MAX_DEPTH:
        return output

    if is_dataclass(value):
        try:
            value = asdict(value)
        except Exception:
            value = {}

    if isinstance(value, Mapping):
        for key, item in value.items():
            if len(output) >= MAX_ITEMS:
                break

            key_text = _safe_string(key, 500)
            next_prefix = (
                f"{prefix}.{key_text}" if prefix else key_text
            )

            if isinstance(item, (Mapping, list, tuple, set)):
                _flatten_mapping(
                    item,
                    prefix=next_prefix,
                    depth=depth + 1,
                    output=output,
                )
            else:
                output.append((next_prefix, item))

        return output

    if isinstance(value, (list, tuple, set)):
        for index, item in enumerate(value):
            if len(output) >= MAX_ITEMS:
                break

            next_prefix = (
                f"{prefix}[{index}]" if prefix else f"[{index}]"
            )

            if isinstance(item, (Mapping, list, tuple, set)):
                _flatten_mapping(
                    item,
                    prefix=next_prefix,
                    depth=depth + 1,
                    output=output,
                )
            else:
                output.append((next_prefix, item))

        return output

    if prefix:
        output.append((prefix, value))

    return output


def _get_mapping_value(
    mapping: Mapping[str, Any],
    *names: str,
    default: Any = None,
) -> Any:
    normalized = {
        _safe_string(key).strip().lower(): value
        for key, value in mapping.items()
    }

    for name in names:
        key = _safe_string(name).strip().lower()
        if key in normalized:
            return normalized[key]

    return default


def _looks_like_finding(value: Mapping[str, Any]) -> bool:
    keys = {
        _safe_string(key).strip().lower()
        for key in value.keys()
    }

    finding_keys = {
        "category",
        "indicator",
        "severity",
        "confidence",
        "message",
        "finding",
        "path",
        "object_type",
        "action_hint",
    }

    return bool(keys.intersection(finding_keys))


def normalize_finding(value: Any) -> Optional[PolicyFinding]:
    """
    Convert a generic detector finding into PolicyFinding.

    Returns None when the input does not resemble a finding.
    """
    if isinstance(value, PolicyFinding):
        return value

    if is_dataclass(value):
        try:
            value = asdict(value)
        except Exception:
            return None

    if not isinstance(value, Mapping):
        return None

    if not _looks_like_finding(value):
        return None

    category = _get_mapping_value(
        value,
        "category",
        "type",
        "finding_category",
        default="unknown",
    )

    indicator = _get_mapping_value(
        value,
        "indicator",
        "name",
        "rule",
        "finding",
        default="",
    )

    severity = _get_mapping_value(
        value,
        "severity",
        "risk",
        "level",
        default="medium",
    )

    confidence = _get_mapping_value(
        value,
        "confidence",
        "probability",
        "score_confidence",
        default=1.0,
    )

    message = _get_mapping_value(
        value,
        "message",
        "description",
        "reason",
        default="",
    )

    path = _get_mapping_value(
        value,
        "path",
        "location",
        "object_path",
        default="",
    )

    object_type = _get_mapping_value(
        value,
        "object_type",
        "object",
        "content_type",
        default="",
    )

    action_hint = _get_mapping_value(
        value,
        "action_hint",
        "action",
        "recommended_action",
        default="",
    )

    source = _get_mapping_value(
        value,
        "source",
        "module",
        "analyzer",
        default="",
    )

    metadata = _get_mapping_value(
        value,
        "metadata",
        "details",
        "attributes",
        default={},
    )

    if not isinstance(metadata, Mapping):
        metadata = {}

    return PolicyFinding(
        category=normalize_category(category),
        indicator=_safe_string(indicator),
        severity=normalize_severity(severity),
        confidence=clamp_probability(confidence),
        message=_bounded_text(message),
        path=_safe_string(path),
        object_type=_safe_string(object_type),
        action_hint=normalize_action(action_hint),
        source=_safe_string(source),
        metadata=dict(metadata),
    )


def normalize_findings(value: Any) -> tuple[PolicyFinding, ...]:
    """
    Normalize detector/parser output into a deterministic finding sequence.
    """
    findings: list[PolicyFinding] = []

    if isinstance(value, PolicyFinding):
        return (value,)

    if is_dataclass(value):
        try:
            value = asdict(value)
        except Exception:
            return ()

    if isinstance(value, Mapping):
        direct = normalize_finding(value)

        if direct is not None:
            findings.append(direct)

        for key in (
            "findings",
            "evidence",
            "detections",
            "indicators",
            "alerts",
            "records",
            "results",
        ):
            nested = _get_mapping_value(value, key)

            if nested is None:
                continue

            for finding in normalize_findings(nested):
                if len(findings) >= MAX_FINDINGS:
                    break
                findings.append(finding)

            if len(findings) >= MAX_FINDINGS:
                break

    elif isinstance(value, (list, tuple, set)):
        for item in value:
            if len(findings) >= MAX_FINDINGS:
                break

            finding = normalize_finding(item)

            if finding is not None:
                findings.append(finding)
            else:
                findings.extend(normalize_findings(item))

    # Deduplicate exact findings while preserving deterministic order.
    unique: list[PolicyFinding] = []
    seen: set[tuple[Any, ...]] = set()

    for finding in findings:
        key = (
            finding.category,
            finding.indicator.lower(),
            finding.severity,
            round(finding.confidence, 6),
            finding.path,
            finding.message,
        )

        if key in seen:
            continue

        seen.add(key)
        unique.append(finding)

        if len(unique) >= MAX_FINDINGS:
            break

    return tuple(unique)


# Alias kept internal to avoid repeating the literal throughout code.
MAX_FINDINGS = MAX_EVIDENCE


# ---------------------------------------------------------------------------
# Default policy
# ---------------------------------------------------------------------------


def _default_rules() -> tuple[PolicyRule, ...]:
    """
    Construct the default balanced policy.

    The rules are deliberately explicit. A later sanitizer can map these
    categories to concrete OOXML/OLE/ZIP modifications.
    """
    rules = [
        PolicyRule(
            name="remove_vba_macros",
            category="macro",
            action=PolicyAction.REMOVE,
            score=65,
            reason="VBA macro content is active document content and is removed.",
            priority=10,
        ),
        PolicyRule(
            name="remove_xlm_macros",
            category="xlm",
            action=PolicyAction.REMOVE,
            score=70,
            reason="Excel 4.0/XLM macro content is removed.",
            priority=10,
        ),
        PolicyRule(
            name="remove_activex",
            category="activex",
            action=PolicyAction.REMOVE,
            score=70,
            reason="ActiveX controls are removed because they can provide active execution capability.",
            priority=10,
        ),
        PolicyRule(
            name="remove_dde",
            category="dde",
            action=PolicyAction.REMOVE,
            score=75,
            reason="DDE content is removed because it can trigger external application interaction.",
            priority=10,
        ),
        PolicyRule(
            name="remove_remote_templates",
            category="template",
            action=PolicyAction.REMOVE,
            score=65,
            reason="Remote template references are removed to prevent external content retrieval.",
            priority=20,
        ),
        PolicyRule(
            name="remove_embedded_executables",
            category="executable",
            action=PolicyAction.REMOVE,
            score=90,
            reason="Embedded executable content is removed from the reconstructed document.",
            priority=5,
        ),
        PolicyRule(
            name="remove_payloads",
            category="payload",
            action=PolicyAction.REMOVE,
            score=90,
            reason="Detected payload content is removed.",
            priority=5,
        ),
        PolicyRule(
            name="remove_script_content",
            category="script",
            action=PolicyAction.REMOVE,
            score=80,
            reason="Embedded script content is removed.",
            priority=10,
        ),
        PolicyRule(
            name="remove_suspicious_ole",
            category="ole",
            severity_at_least="high",
            action=PolicyAction.REMOVE,
            score=80,
            reason="High-risk OLE content is removed.",
            priority=20,
        ),
        PolicyRule(
            name="sanitize_external_links",
            category="external_link",
            action=PolicyAction.SANITIZE,
            score=35,
            reason="External links are removed or converted to inert content.",
            priority=30,
        ),
        PolicyRule(
            name="sanitize_network_content",
            category="network",
            severity_at_least="medium",
            action=PolicyAction.SANITIZE,
            score=25,
            reason="Network references are neutralized where supported.",
            priority=40,
        ),
        PolicyRule(
            name="review_critical_unknown",
            category="unknown",
            severity_at_least="critical",
            action=PolicyAction.REVIEW,
            score=70,
            reason="Critical unknown content requires manual review.",
            priority=5,
        ),
        PolicyRule(
            name="reject_critical_payload",
            category="payload",
            severity_at_least="critical",
            action=PolicyAction.REJECT,
            score=100,
            reason="Critical payload detection causes rejection.",
            priority=1,
        ),
        PolicyRule(
            name="reject_critical_executable",
            category="executable",
            severity_at_least="critical",
            action=PolicyAction.REJECT,
            score=100,
            reason="Critical embedded executable detection causes rejection.",
            priority=1,
        ),
        PolicyRule(
            name="sanitize_obfuscation",
            category="obfuscation",
            severity_at_least="medium",
            action=PolicyAction.SANITIZE,
            score=20,
            reason="Obfuscated active content contributes to sanitization risk.",
            priority=50,
        ),
        PolicyRule(
            name="sanitize_persistence",
            category="persistence",
            action=PolicyAction.REMOVE,
            score=70,
            reason="Persistence-related active content is removed.",
            priority=15,
        ),
        PolicyRule(
            name="sanitize_evasion",
            category="evasion",
            severity_at_least="medium",
            action=PolicyAction.REMOVE,
            score=60,
            reason="Evasion-related active content is removed.",
            priority=15,
        ),
    ]

    return tuple(rules)


def default_policy(
    *,
    mode: PolicyMode | str = PolicyMode.BALANCED,
    name: str = DEFAULT_POLICY_NAME,
    version: str = DEFAULT_POLICY_VERSION,
) -> Policy:
    """
    Build the default CDR policy.

    ``strict`` mode increases the effective risk contribution of findings
    and treats unknown active content more aggressively.
    """
    normalized_mode = (
        mode
        if isinstance(mode, PolicyMode)
        else PolicyMode(_safe_string(mode).lower())
    )

    if normalized_mode is PolicyMode.PERMISSIVE:
        review_score = 65.0
        block_score = 100.0
        remove_unknown = False
        reject_malformed = True

    elif normalized_mode is PolicyMode.STRICT:
        review_score = 35.0
        block_score = 65.0
        remove_unknown = True
        reject_malformed = True

    else:
        review_score = DEFAULT_REVIEW_SCORE
        block_score = DEFAULT_BLOCK_SCORE
        remove_unknown = True
        reject_malformed = True

    return Policy(
        name=_safe_string(name) or DEFAULT_POLICY_NAME,
        version=_safe_string(version) or DEFAULT_POLICY_VERSION,
        mode=normalized_mode,
        review_score=review_score,
        block_score=block_score,
        rules=_default_rules(),
        preserve_safe_content=True,
        remove_unknown_active_content=remove_unknown,
        reject_malformed_active_content=reject_malformed,
    )


# ---------------------------------------------------------------------------
# Policy configuration loading
# ---------------------------------------------------------------------------


def rule_from_mapping(value: Mapping[str, Any]) -> PolicyRule:
    """Create a PolicyRule from a mapping."""
    action = normalize_action(
        _get_mapping_value(
            value,
            "action",
            "policy_action",
            default="sanitize",
        )
    )

    if not action:
        raise PolicyConfigurationError("policy rule has invalid action")

    return PolicyRule(
        name=_get_mapping_value(value, "name", "id", default="unnamed_rule"),
        category=_get_mapping_value(
            value,
            "category",
            "finding_category",
            default="",
        ),
        indicator=_get_mapping_value(
            value,
            "indicator",
            "pattern",
            default="",
        ),
        severity_at_least=_get_mapping_value(
            value,
            "severity_at_least",
            "minimum_severity",
            "severity",
            default="",
        ),
        min_confidence=_get_mapping_value(
            value,
            "min_confidence",
            "minimum_confidence",
            "confidence",
            default=0.0,
        ),
        action=PolicyAction(action),
        score=_get_mapping_value(
            value,
            "score",
            "risk_score",
            default=0.0,
        ),
        reason=_get_mapping_value(
            value,
            "reason",
            "description",
            default="",
        ),
        enabled=bool(
            _get_mapping_value(
                value,
                "enabled",
                default=True,
            )
        ),
        priority=int(
            _safe_float(
                _get_mapping_value(
                    value,
                    "priority",
                    default=100,
                ),
                100,
            )
        ),
    )


def policy_from_mapping(
    value: Mapping[str, Any],
    *,
    base_policy: Optional[Policy] = None,
) -> Policy:
    """
    Build a policy from JSON-like configuration.

    Missing settings inherit from the supplied base policy, or from the
    default balanced policy.
    """
    if not isinstance(value, Mapping):
        raise PolicyConfigurationError("policy configuration must be a mapping")

    base = base_policy or default_policy()

    name = _get_mapping_value(
        value,
        "name",
        "policy_name",
        default=base.name,
    )

    version = _get_mapping_value(
        value,
        "version",
        "policy_version",
        default=base.version,
    )

    mode_value = _get_mapping_value(
        value,
        "mode",
        "policy_mode",
        default=base.mode.value,
    )

    try:
        mode = (
            mode_value
            if isinstance(mode_value, PolicyMode)
            else PolicyMode(_safe_string(mode_value).lower())
        )
    except ValueError as exc:
        raise PolicyConfigurationError(
            f"invalid policy mode: {mode_value!r}"
        ) from exc

    rules_value = _get_mapping_value(value, "rules", default=None)

    if rules_value is None:
        rules = base.rules
    else:
        if not isinstance(rules_value, (list, tuple)):
            raise PolicyConfigurationError("rules must be a sequence")

        if len(rules_value) > MAX_RULES:
            raise PolicyConfigurationError("too many policy rules")

        rules = tuple(
            rule_from_mapping(item)
            for item in rules_value
            if isinstance(item, Mapping)
        )

    review_score = _safe_float(
        _get_mapping_value(
            value,
            "review_score",
            "review_threshold",
            default=base.review_score,
        ),
        base.review_score,
    )

    block_score = _safe_float(
        _get_mapping_value(
            value,
            "block_score",
            "block_threshold",
            default=base.block_score,
        ),
        base.block_score,
    )

    preserve_safe_content = bool(
        _get_mapping_value(
            value,
            "preserve_safe_content",
            default=base.preserve_safe_content,
        )
    )

    remove_unknown_active_content = bool(
        _get_mapping_value(
            value,
            "remove_unknown_active_content",
            default=base.remove_unknown_active_content,
        )
    )

    reject_malformed_active_content = bool(
        _get_mapping_value(
            value,
            "reject_malformed_active_content",
            default=base.reject_malformed_active_content,
        )
    )

    return Policy(
        name=_safe_string(name),
        version=_safe_string(version),
        mode=mode,
        review_score=review_score,
        block_score=block_score,
        rules=rules,
        preserve_safe_content=preserve_safe_content,
        remove_unknown_active_content=remove_unknown_active_content,
        reject_malformed_active_content=reject_malformed_active_content,
    )


def load_policy(
    source: str | bytes | Path | Mapping[str, Any],
    *,
    base_policy: Optional[Policy] = None,
) -> Policy:
    """Load a policy from a mapping or JSON file."""
    if isinstance(source, Mapping):
        return policy_from_mapping(source, base_policy=base_policy)

    if isinstance(source, Path):
        path = source
    elif isinstance(source, str):
        path = Path(source)
    else:
        if isinstance(source, bytes):
            raw = source[:MAX_JSON_LENGTH]
            try:
                value = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise PolicyConfigurationError(
                    "invalid policy JSON"
                ) from exc

            if not isinstance(value, Mapping):
                raise PolicyConfigurationError(
                    "policy JSON root must be an object"
                )

            return policy_from_mapping(value, base_policy=base_policy)

        raise PolicyConfigurationError("unsupported policy source")

    try:
        if path.stat().st_size > MAX_JSON_LENGTH:
            raise PolicyConfigurationError("policy file is too large")

        raw = path.read_bytes()
    except OSError as exc:
        raise PolicyConfigurationError(
            f"unable to read policy file: {path}"
        ) from exc

    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PolicyConfigurationError("invalid policy JSON") from exc

    if not isinstance(value, Mapping):
        raise PolicyConfigurationError("policy JSON root must be an object")

    return policy_from_mapping(value, base_policy=base_policy)


# ---------------------------------------------------------------------------
# Rule matching
# ---------------------------------------------------------------------------


def _rule_matches(
    rule: PolicyRule,
    finding: PolicyFinding,
) -> bool:
    if not rule.enabled:
        return False

    if rule.category:
        if normalize_category(rule.category) != finding.category:
            return False

    if rule.indicator:
        indicator = finding.indicator.lower()
        wanted = rule.indicator.lower()

        if wanted not in indicator:
            return False

    if rule.severity_at_least:
        if severity_rank(finding.severity) < severity_rank(
            rule.severity_at_least
        ):
            return False

    if finding.confidence < rule.min_confidence:
        return False

    return True


def matched_rules(
    finding: PolicyFinding,
    policy: Policy,
) -> tuple[PolicyRule, ...]:
    """Return all rules matching a finding."""
    matches = [
        rule
        for rule in policy.rules
        if _rule_matches(rule, finding)
    ]

    matches.sort(
        key=lambda rule: (
            rule.priority,
            -rule.score,
            rule.name,
        )
    )

    return tuple(matches)


# ---------------------------------------------------------------------------
# Risk scoring
# ---------------------------------------------------------------------------


def _mode_multiplier(mode: PolicyMode) -> float:
    if mode is PolicyMode.PERMISSIVE:
        return 0.75

    if mode is PolicyMode.STRICT:
        return 1.25

    return 1.0


def _severity_multiplier(severity: str) -> float:
    return {
        "info": 0.0,
        "low": 0.5,
        "medium": 1.0,
        "high": 1.5,
        "critical": 2.0,
    }.get(normalize_severity(severity), 1.0)


def finding_risk_score(
    finding: PolicyFinding,
    policy: Policy,
) -> float:
    """
    Calculate the contribution of one finding to the policy risk score.
    """
    rules = matched_rules(finding, policy)

    if rules:
        base = max(rule.score for rule in rules)
    else:
        base = 0.0

    severity_factor = _severity_multiplier(finding.severity)

    if base <= 0.0:
        base = {
            "info": 0.0,
            "low": 5.0,
            "medium": 15.0,
            "high": 30.0,
            "critical": 50.0,
        }.get(finding.severity, 15.0)

    return (
        base
        * max(0.1, finding.confidence)
        * max(0.1, severity_factor)
        * _mode_multiplier(policy.mode)
    )


def calculate_risk_score(
    findings: Iterable[PolicyFinding],
    policy: Policy,
) -> float:
    """
    Calculate a bounded document-level risk score.

    Multiple findings are combined using diminishing returns so a document
    containing many copies of the same finding does not grow without bound.
    """
    score = 0.0
    category_seen: set[str] = set()

    for finding in findings:
        contribution = finding_risk_score(finding, policy)

        # Give independent categories more weight than duplicate evidence.
        if finding.category in category_seen:
            contribution *= 0.35
        else:
            category_seen.add(finding.category)

        score += contribution

    return min(100.0, max(0.0, score))


# ---------------------------------------------------------------------------
# Component action inference
# ---------------------------------------------------------------------------


def _preferred_action(actions: Iterable[PolicyAction]) -> PolicyAction:
    """
    Select the strongest action according to the CDR action ordering.
    """
    best = PolicyAction.PRESERVE
    best_rank = ACTION_ORDER[best.value]

    for action in actions:
        normalized = (
            action
            if isinstance(action, PolicyAction)
            else PolicyAction(normalize_action(action))
        )

        rank = ACTION_ORDER[normalized.value]

        if rank > best_rank:
            best = normalized
            best_rank = rank

    return best


def action_for_finding(
    finding: PolicyFinding,
    policy: Policy,
) -> PolicyAction:
    """Determine the strongest action requested by matching rules."""
    rules = matched_rules(finding, policy)

    if not rules:
        if finding.action_hint:
            try:
                return PolicyAction(finding.action_hint)
            except ValueError:
                pass

        return PolicyAction.PRESERVE

    return _preferred_action(rule.action for rule in rules)


def _finding_reason(
    finding: PolicyFinding,
    policy: Policy,
) -> str:
    rules = matched_rules(finding, policy)

    if rules:
        rule = rules[0]

        if rule.reason:
            return rule.reason

        return rule.name

    if finding.message:
        return finding.message

    if finding.indicator:
        return f"Detected {finding.indicator}"

    return f"Detected {finding.category} content"


def build_action_plan(
    findings: Iterable[PolicyFinding],
    policy: Policy,
) -> tuple[PolicyActionPlan, ...]:
    """
    Build deterministic component-level actions.

    Findings sharing the same path/category are consolidated into one plan.
    """
    grouped: dict[tuple[str, str], list[PolicyFinding]] = {}

    for finding in findings:
        key = (
            finding.path or "",
            finding.category,
        )

        grouped.setdefault(key, []).append(finding)

        if len(grouped) >= MAX_ACTIONS:
            break

    plans: list[PolicyActionPlan] = []

    for (path, category), group in sorted(
        grouped.items(),
        key=lambda item: (
            item[0][0],
            item[0][1],
        ),
    ):
        actions = [
            action_for_finding(finding, policy)
            for finding in group
        ]

        action = _preferred_action(actions)

        severity = highest_severity(group)
        confidence = max(
            (finding.confidence for finding in group),
            default=0.0,
        )

        reasons: list[str] = []

        for finding in group:
            reason = _finding_reason(finding, policy)

            if reason and reason not in reasons:
                reasons.append(reason)

        preserve_children = (
            action in {
                PolicyAction.PRESERVE,
                PolicyAction.SANITIZE,
            }
        )

        plans.append(
            PolicyActionPlan(
                action=action,
                path=path,
                category=category,
                reason="; ".join(reasons[:5]),
                finding_count=len(group),
                confidence=confidence,
                severity=severity,
                preserve_children=preserve_children,
                preserve_metadata=True,
            )
        )

        if len(plans) >= MAX_ACTIONS:
            break

    return tuple(plans)


# ---------------------------------------------------------------------------
# Final decision
# ---------------------------------------------------------------------------


def decide(
    findings: Iterable[PolicyFinding],
    policy: Optional[Policy] = None,
) -> PolicyDecision:
    """
    Produce the document-level CDR decision.
    """
    active_policy = policy or default_policy()
    finding_tuple = tuple(findings)

    score = calculate_risk_score(
        finding_tuple,
        active_policy,
    )

    categories = tuple(
        sorted(
            {
                finding.category
                for finding in finding_tuple
            }
        )
    )

    indicators = tuple(
        sorted(
            {
                finding.indicator
                for finding in finding_tuple
                if finding.indicator
            }
        )
    )

    reasons: list[str] = []
    rule_names: list[str] = []
    actions: list[PolicyAction] = []

    for finding in finding_tuple:
        finding_actions = matched_rules(finding, active_policy)

        for rule in finding_actions:
            actions.append(rule.action)

            if rule.name not in rule_names:
                rule_names.append(rule.name)

            if rule.reason and rule.reason not in reasons:
                reasons.append(rule.reason)

        if finding.action_hint:
            try:
                actions.append(PolicyAction(finding.action_hint))
            except ValueError:
                pass

        if not finding_actions and finding.message:
            if finding.message not in reasons:
                reasons.append(finding.message)

    highest = highest_severity(finding_tuple)

    if not finding_tuple:
        return PolicyDecision(
            action=PolicyAction.PRESERVE,
            score=0.0,
            severity="info",
            confidence=1.0,
            reasons=(),
            matched_rules=(),
            categories=(),
            indicators=(),
            findings_count=0,
            requires_sanitization=False,
            requires_review=False,
            reject=False,
            preserve_safe_content=active_policy.preserve_safe_content,
        )

    strongest_rule_action = _preferred_action(actions)

    critical_reject = any(
        action is PolicyAction.REJECT
        for action in actions
    )

    if critical_reject:
        final_action = PolicyAction.REJECT
        requires_review = False
        reject = True

    elif score >= active_policy.block_score:
        final_action = PolicyAction.REJECT
        requires_review = False
        reject = True

    elif strongest_rule_action is PolicyAction.REMOVE:
        final_action = PolicyAction.SANITIZE
        requires_review = False
        reject = False

    elif strongest_rule_action is PolicyAction.SANITIZE:
        final_action = PolicyAction.SANITIZE
        requires_review = False
        reject = False

    elif strongest_rule_action is PolicyAction.REVIEW:
        final_action = PolicyAction.REVIEW
        requires_review = True
        reject = False

    elif score >= active_policy.review_score:
        final_action = PolicyAction.REVIEW
        requires_review = True
        reject = False

    else:
        final_action = PolicyAction.PRESERVE
        requires_review = False
        reject = False

    # A critical active-content finding should not silently pass through.
    if (
        highest == "critical"
        and strongest_rule_action
        in {
            PolicyAction.PRESERVE,
            PolicyAction.SANITIZE,
        }
        and active_policy.mode is PolicyMode.STRICT
    ):
        final_action = PolicyAction.REVIEW
        requires_review = True
        reject = False

    confidence = max(
        (finding.confidence for finding in finding_tuple),
        default=1.0,
    )

    return PolicyDecision(
        action=final_action,
        score=round(score, 6),
        severity=highest,
        confidence=round(confidence, 6),
        reasons=tuple(reasons[:50]),
        matched_rules=tuple(rule_names[:MAX_RULES]),
        categories=categories,
        indicators=indicators[:MAX_ITEMS],
        findings_count=len(finding_tuple),
        requires_sanitization=final_action is PolicyAction.SANITIZE,
        requires_review=requires_review,
        reject=reject,
        preserve_safe_content=active_policy.preserve_safe_content,
    )


# ---------------------------------------------------------------------------
# High-level policy evaluation
# ---------------------------------------------------------------------------


def evaluate_policy(
    findings: Any,
    *,
    policy: Optional[Policy] = None,
    document: Any = None,
    document_id: str = "",
) -> PolicyResult:
    """
    Evaluate parser/detector findings against a CDR policy.
    """
    active_policy = policy or default_policy()
    normalized = normalize_findings(findings)

    warnings: list[str] = []

    if len(normalized) >= MAX_FINDINGS:
        warnings.append("finding limit reached; input was bounded")

    decision = decide(
        normalized,
        active_policy,
    )

    actions = build_action_plan(
        normalized,
        active_policy,
    )

    input_size = 0
    input_sha256 = ""

    if document is not None:
        try:
            if isinstance(document, bytes):
                raw = document[:MAX_INPUT_BYTES]
            elif isinstance(document, str):
                raw = document.encode("utf-8")[:MAX_INPUT_BYTES]
            elif isinstance(document, Path):
                stat = document.stat()

                if stat.st_size > MAX_INPUT_BYTES:
                    warnings.append("document exceeds hashing size limit")
                    raw = b""
                else:
                    raw = document.read_bytes()
            else:
                raw = b""

            input_size = len(raw)

            if raw:
                input_sha256 = hashlib.sha256(raw).hexdigest()

        except (OSError, ValueError, TypeError):
            warnings.append("document identity could not be calculated")

    if not document_id:
        document_id = input_sha256

    return PolicyResult(
        policy_name=active_policy.name,
        policy_version=active_policy.version,
        mode=active_policy.mode,
        decision=decision,
        actions=actions,
        findings=normalized,
        document_id=_safe_string(document_id),
        input_size=input_size,
        input_sha256=input_sha256,
        safe_content_preserved=active_policy.preserve_safe_content,
        deterministic=True,
        warnings=tuple(warnings),
    )


# ---------------------------------------------------------------------------
# Policy predicates
# ---------------------------------------------------------------------------


def requires_sanitization(
    result: PolicyResult | PolicyDecision,
) -> bool:
    """Return True when active content should be sanitized/removed."""
    decision = (
        result.decision
        if isinstance(result, PolicyResult)
        else result
    )

    return decision.requires_sanitization or any(
        action in {
            PolicyAction.SANITIZE,
            PolicyAction.REMOVE,
        }
        for action in _decision_actions(decision)
    )


def requires_review(
    result: PolicyResult | PolicyDecision,
) -> bool:
    """Return True when manual review is required."""
    decision = (
        result.decision
        if isinstance(result, PolicyResult)
        else result
    )

    return decision.requires_review or (
        decision.action is PolicyAction.REVIEW
    )


def is_rejected(
    result: PolicyResult | PolicyDecision,
) -> bool:
    """Return True when the document should be rejected."""
    decision = (
        result.decision
        if isinstance(result, PolicyResult)
        else result
    )

    return decision.blocked


def _decision_actions(
    decision: PolicyDecision,
) -> tuple[PolicyAction, ...]:
    actions: list[PolicyAction] = []

    if decision.action:
        actions.append(decision.action)

    return tuple(actions)


def action_for_path(
    result: PolicyResult,
    path: str,
) -> PolicyAction:
    """
    Retrieve the action for a specific document component path.

    If no exact component action exists, the document-level decision is used
    as a conservative fallback.
    """
    normalized_path = _safe_string(path)

    matching: list[PolicyActionPlan] = [
        plan
        for plan in result.actions
        if plan.path == normalized_path
    ]

    if not matching:
        return result.decision.action

    return _preferred_action(
        plan.action
        for plan in matching
    )


def should_remove(
    result: PolicyResult,
    *,
    path: str = "",
    category: str = "",
) -> bool:
    """Determine whether a component should be removed."""
    normalized_category = (
        normalize_category(category)
        if category
        else ""
    )

    for plan in result.actions:
        if path and plan.path != path:
            continue

        if normalized_category and plan.category != normalized_category:
            continue

        if plan.action in {
            PolicyAction.REMOVE,
            PolicyAction.REJECT,
        }:
            return True

    return False


def should_preserve(
    result: PolicyResult,
    *,
    path: str = "",
    category: str = "",
) -> bool:
    """
    Determine whether a component may be preserved.

    Rejection and explicit removal always override preservation.
    """
    if should_remove(
        result,
        path=path,
        category=category,
    ):
        return False

    action = action_for_path(result, path)

    if action is PolicyAction.REJECT:
        return False

    if action is PolicyAction.REMOVE:
        return False

    return result.safe_content_preserved


def actions_for_category(
    result: PolicyResult,
    category: str,
) -> tuple[PolicyActionPlan, ...]:
    """Return all action plans for a normalized category."""
    normalized = normalize_category(category)

    return tuple(
        plan
        for plan in result.actions
        if plan.category == normalized
    )


# ---------------------------------------------------------------------------
# Parser/detector interoperability helpers
# ---------------------------------------------------------------------------


def findings_from_detector(
    detector_output: Any,
) -> tuple[PolicyFinding, ...]:
    """
    Normalize output from detector.py.

    This intentionally accepts generic mappings and dataclasses so policy.py
    does not become tightly coupled to a particular detector implementation.
    """
    return normalize_findings(detector_output)


def evaluate_detector_output(
    detector_output: Any,
    *,
    policy: Optional[Policy] = None,
    document: Any = None,
    document_id: str = "",
) -> PolicyResult:
    """Evaluate detector output directly."""
    return evaluate_policy(
        findings_from_detector(detector_output),
        policy=policy,
        document=document,
        document_id=document_id,
    )


# ---------------------------------------------------------------------------
# Serialization
# ---------------------------------------------------------------------------


def _json_safe(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value

    if is_dataclass(value):
        return _json_safe(asdict(value))

    if isinstance(value, Mapping):
        return {
            _safe_string(key): _json_safe(item)
            for key, item in value.items()
        }

    if isinstance(value, (list, tuple, set)):
        return [_json_safe(item) for item in value]

    if isinstance(value, float):
        if not math.isfinite(value):
            return 0.0

    if isinstance(value, (str, int, float, bool)) or value is None:
        return value

    return _safe_string(value)


def policy_to_dict(policy: Policy) -> dict[str, Any]:
    """Serialize a Policy to a JSON-compatible dictionary."""
    return _json_safe(policy)


def decision_to_dict(
    decision: PolicyDecision,
) -> dict[str, Any]:
    """Serialize a PolicyDecision."""
    return _json_safe(decision)


def result_to_dict(
    result: PolicyResult,
) -> dict[str, Any]:
    """Serialize a PolicyResult."""
    return _json_safe(result)


def result_to_json(
    result: PolicyResult,
    *,
    indent: Optional[int] = 2,
) -> str:
    """Serialize a PolicyResult to JSON."""
    return json.dumps(
        result_to_dict(result),
        indent=indent,
        sort_keys=True,
        ensure_ascii=False,
    )


def save_policy_result(
    result: PolicyResult,
    path: str | Path,
    *,
    indent: Optional[int] = 2,
) -> Path:
    """Persist a policy result as JSON."""
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)

    payload = result_to_json(
        result,
        indent=indent,
    )

    output.write_text(
        payload,
        encoding="utf-8",
    )

    return output


def save_policy(
    policy: Policy,
    path: str | Path,
    *,
    indent: Optional[int] = 2,
) -> Path:
    """Persist a policy configuration as JSON."""
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)

    payload = json.dumps(
        policy_to_dict(policy),
        indent=indent,
        sort_keys=True,
        ensure_ascii=False,
    )

    output.write_text(
        payload,
        encoding="utf-8",
    )

    return output


# ---------------------------------------------------------------------------
# Summary/report helpers
# ---------------------------------------------------------------------------


def summarize_policy(
    result: PolicyResult,
) -> PolicySummary:
    """Return a compact summary of a policy result."""
    return PolicySummary(
        action=result.decision.action.value,
        score=result.decision.score,
        severity=result.decision.severity,
        confidence=result.decision.confidence,
        finding_count=result.decision.findings_count,
        matched_rule_count=len(result.decision.matched_rules),
        categories=result.decision.categories,
        requires_sanitization=result.decision.requires_sanitization,
        requires_review=result.decision.requires_review,
        blocked=result.decision.blocked,
        safe_content_preserved=result.safe_content_preserved,
    )


def summarize(
    result: PolicyResult,
) -> dict[str, Any]:
    """Return a JSON-compatible compact summary."""
    return _json_safe(
        summarize_policy(result)
    )


def findings_by_category(
    findings: Iterable[PolicyFinding],
) -> dict[str, tuple[PolicyFinding, ...]]:
    """Group findings by canonical category."""
    grouped: dict[str, list[PolicyFinding]] = {}

    for finding in findings:
        grouped.setdefault(
            finding.category,
            [],
        ).append(finding)

    return {
        category: tuple(items)
        for category, items in sorted(grouped.items())
    }


def findings_by_severity(
    findings: Iterable[PolicyFinding],
) -> dict[str, tuple[PolicyFinding, ...]]:
    """Group findings by severity."""
    grouped: dict[str, list[PolicyFinding]] = {}

    for finding in findings:
        grouped.setdefault(
            finding.severity,
            [],
        ).append(finding)

    return {
        severity: tuple(grouped.get(severity, ()))
        for severity in (
            "info",
            "low",
            "medium",
            "high",
            "critical",
        )
        if grouped.get(severity)
    }


def iter_action_plans(
    result: PolicyResult,
) -> Iterator[PolicyActionPlan]:
    """Iterate deterministic component action plans."""
    yield from result.actions


def iter_findings(
    result: PolicyResult,
) -> Iterator[PolicyFinding]:
    """Iterate normalized policy findings."""
    yield from result.findings


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


def validate_policy(policy: Policy) -> tuple[str, ...]:
    """
    Validate policy configuration and return warnings/errors.

    An empty tuple means no validation problems were found.
    """
    problems: list[str] = []

    if not policy.name:
        problems.append("policy name is empty")

    if not policy.version:
        problems.append("policy version is empty")

    if policy.review_score < 0:
        problems.append("review score must be non-negative")

    if policy.block_score < policy.review_score:
        problems.append(
            "block score must be greater than or equal to review score"
        )

    names: set[str] = set()

    for rule in policy.rules:
        if not rule.name:
            problems.append("policy contains an unnamed rule")

        if rule.name in names:
            problems.append(
                f"duplicate policy rule: {rule.name}"
            )

        names.add(rule.name)

        if rule.score < 0:
            problems.append(
                f"negative rule score: {rule.name}"
            )

        if not 0.0 <= rule.min_confidence <= 1.0:
            problems.append(
                f"invalid confidence threshold: {rule.name}"
            )

        if rule.category:
            normalized = normalize_category(rule.category)

            if normalized == "unknown" and rule.category != "unknown":
                problems.append(
                    f"unknown rule category: {rule.category}"
                )

    return tuple(problems)


def validate_result(result: PolicyResult) -> tuple[str, ...]:
    """Validate internal consistency of a PolicyResult."""
    problems: list[str] = []

    problems.extend(
        f"policy: {item}"
        for item in validate_policy(
            Policy(
                name=result.policy_name,
                version=result.policy_version,
                mode=result.mode,
                review_score=DEFAULT_REVIEW_SCORE,
                block_score=DEFAULT_BLOCK_SCORE,
                rules=(),
            )
        )
    )

    if result.decision.findings_count != len(result.findings):
        problems.append(
            "decision finding count does not match findings"
        )

    if result.decision.blocked and not result.decision.reject:
        problems.append(
            "blocked decision must have reject=True"
        )

    if result.decision.score < 0 or result.decision.score > 100:
        problems.append(
            "decision score is outside [0, 100]"
        )

    return tuple(problems)


# ---------------------------------------------------------------------------
# Policy presets
# ---------------------------------------------------------------------------


def permissive_policy() -> Policy:
    """Return the permissive built-in policy."""
    return default_policy(mode=PolicyMode.PERMISSIVE)


def balanced_policy() -> Policy:
    """Return the balanced built-in policy."""
    return default_policy(mode=PolicyMode.BALANCED)


def strict_policy() -> Policy:
    """Return the strict built-in policy."""
    return default_policy(mode=PolicyMode.STRICT)


def policy_for_mode(
    mode: str | PolicyMode,
) -> Policy:
    """Return a built-in policy for the requested mode."""
    if isinstance(mode, PolicyMode):
        return default_policy(mode=mode)

    try:
        return default_policy(
            mode=PolicyMode(_safe_string(mode).lower())
        )
    except ValueError as exc:
        raise PolicyConfigurationError(
            f"unknown policy mode: {mode!r}"
        ) from exc


# ---------------------------------------------------------------------------
# Public APIs
# ---------------------------------------------------------------------------

__all__ = [
    "PolicyAction",
    "PolicyMode",
    "PolicyError",
    "PolicyInputError",
    "PolicyConfigurationError",
    "PolicyFinding",
    "PolicyRule",
    "PolicyDecision",
    "PolicyActionPlan",
    "PolicyResult",
    "Policy",
    "PolicySummary",
    "clamp_probability",
    "normalize_severity",
    "normalize_category",
    "normalize_action",
    "severity_rank",
    "highest_severity",
    "normalize_finding",
    "normalize_findings",
    "findings_from_detector",
    "default_policy",
    "permissive_policy",
    "balanced_policy",
    "strict_policy",
    "policy_for_mode",
    "rule_from_mapping",
    "policy_from_mapping",
    "load_policy",
    "validate_policy",
    "matched_rules",
    "finding_risk_score",
    "calculate_risk_score",
    "action_for_finding",
    "build_action_plan",
    "decide",
    "evaluate_policy",
    "evaluate_detector_output",
    "requires_sanitization",
    "requires_review",
    "is_rejected",
    "action_for_path",
    "should_remove",
    "should_preserve",
    "actions_for_category",
    "policy_to_dict",
    "decision_to_dict",
    "result_to_dict",
    "result_to_json",
    "save_policy_result",
    "save_policy",
    "summarize_policy",
    "summarize",
    "findings_by_category",
    "findings_by_severity",
    "iter_action_plans",
    "iter_findings",
    "validate_result",
]