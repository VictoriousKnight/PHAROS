"""
PHAROS Pipeline - Unified Decision Engine
-----------------------------------------
Synthesizes inputs across all inspection stages:
1. File validation / ingestion
2. Static feature extraction
3. ML threat prediction (probability and confidence)
4. CDR structural threat findings and policy

Produces final disposition: PASS, SANITIZE, REVIEW, or REJECT.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping, Optional

logger = logging.getLogger("pipeline.decision")


class Disposition(str, Enum):
    PASS = "pass"
    SANITIZE = "sanitize"
    REVIEW = "review"
    REJECT = "reject"


class DecisionConfidence(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass
class DecisionThresholds:
    sanitize_prob: float = 0.35
    review_prob: float = 0.60
    reject_prob: float = 0.85


@dataclass
class DecisionResult:
    disposition: Disposition
    confidence: DecisionConfidence
    score: float
    reasons: list[str] = field(default_factory=list)
    model_probability: Optional[float] = None
    model_available: bool = False
    requires_sanitization: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "disposition": self.disposition.value,
            "confidence": self.confidence.value,
            "score": round(self.score, 4),
            "reasons": self.reasons,
            "model_probability": round(self.model_probability, 4) if self.model_probability is not None else None,
            "model_available": self.model_available,
            "requires_sanitization": self.requires_sanitization,
            "metadata": self.metadata,
        }


def make_decision(
    *,
    features: Optional[Mapping[str, Any]] = None,
    ml_prediction: Optional[Mapping[str, Any]] = None,
    cdr_detection: Optional[Mapping[str, Any]] = None,
    cdr_policy: Optional[Mapping[str, Any]] = None,
    thresholds: Optional[DecisionThresholds] = None,
) -> DecisionResult:
    """
    Synthesize all stage outputs into a definitive security disposition.
    """
    th = thresholds or DecisionThresholds()
    reasons: list[str] = []
    
    # 1. Parse ML predictions
    ml_prob = None
    model_available = False
    if ml_prediction and isinstance(ml_prediction, Mapping):
        ml_prob = ml_prediction.get("probability")
        model_available = ml_prob is not None

    # 2. Parse CDR detection & policy
    cdr_action = None
    has_active_threats = False
    if cdr_policy and isinstance(cdr_policy, Mapping):
        cdr_action = cdr_policy.get("action")
    if cdr_detection and isinstance(cdr_detection, Mapping):
        has_active_threats = not cdr_detection.get("is_safe", True) or cdr_detection.get("requires_sanitization", False)

    # Calculate aggregate threat score (0.0 to 1.0)
    score = 0.0
    if ml_prob is not None:
        score += 0.60 * ml_prob
    if has_active_threats:
        score += 0.40

    # Determine disposition
    if score >= th.reject_prob or cdr_action == "block":
        disposition = Disposition.REJECT
        reasons.append("High-confidence malicious indicators or weaponized payload detected.")
    elif score >= th.review_prob or cdr_action == "review":
        disposition = Disposition.REVIEW
        reasons.append("Anomalous or suspicious characteristics warrant manual analyst review.")
    elif score >= th.sanitize_prob or has_active_threats or cdr_action == "sanitize":
        disposition = Disposition.SANITIZE
        disposition_reasons = (cdr_policy.get("reasons", []) if cdr_policy else [])
        if disposition_reasons:
            reasons.extend(disposition_reasons)
        else:
            reasons.append("Active macros or embedded components present; CDR sanitization required.")
    else:
        disposition = Disposition.PASS
        reasons.append("Document verified clean and safe.")

    # Confidence calculation
    conf = DecisionConfidence.HIGH if (score >= 0.80 or score <= 0.20) else DecisionConfidence.MEDIUM

    return DecisionResult(
        disposition=disposition,
        confidence=conf,
        score=score,
        reasons=reasons,
        model_probability=ml_prob,
        model_available=model_available,
        requires_sanitization=(disposition == Disposition.SANITIZE),
        metadata={"cdr_action": cdr_action, "has_active_threats": has_active_threats}
    )


# Short aliases
decide = make_decision

__all__ = [
    "Disposition",
    "DecisionConfidence",
    "DecisionThresholds",
    "DecisionResult",
    "make_decision",
    "decide",
]
