"""
PHAROS CDR - Policy Engine
--------------------------
Evaluates threat detections against organizational triage rules.
Maps risk findings into concrete CDR actions: PASS, SANITIZE, REVIEW, or BLOCK.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Mapping

logger = logging.getLogger("cdr.policy")

# Supported disposition actions
ACTION_PASS = "pass"
ACTION_SANITIZE = "sanitize"
ACTION_REVIEW = "review"
ACTION_BLOCK = "block"


@dataclass
class PolicyEvaluation:
    action: str
    reasons: list[str]
    allowed_dispositions: tuple[str, ...]
    policy_name: str = "default_cdr_policy"

    def to_dict(self) -> dict[str, Any]:
        return {
            "action": self.action,
            "policy_decision": self.action,
            "reasons": self.reasons,
            "allowed_dispositions": self.allowed_dispositions,
            "policy_name": self.policy_name,
        }


def evaluate_policy(detector_output: Mapping[str, Any] | Any, **kwargs) -> dict[str, Any]:
    """
    Evaluate detector findings against CDR operational rules.
    Outputs the final disposition recommendation (e.g. 'sanitize' vs 'pass').
    """
    if hasattr(detector_output, "to_dict"):
        data = detector_output.to_dict()
    elif isinstance(detector_output, Mapping):
        data = dict(detector_output)
    else:
        data = {}

    threat_level = data.get("threat_level", "low")
    threat_score = data.get("threat_score", 0.0)
    requires_sanitization = data.get("requires_sanitization", False)
    has_macros = data.get("has_macros", False)

    reasons: list[str] = []

    if threat_level == "critical" or threat_score >= 0.85:
        action = ACTION_BLOCK
        reasons.append("Critical risk score or malformed weaponized structure detected.")
    elif requires_sanitization or has_macros or threat_level in ["high", "medium"]:
        action = ACTION_SANITIZE
        if has_macros:
            reasons.append("Active macros must be purged via Content Disarm and Reconstruction.")
        if data.get("has_embedded_objects"):
            reasons.append("Embedded binary objects detected; disassembly required.")
        if data.get("has_external_targets"):
            reasons.append("Remote external targets present; sanitization recommended.")
    else:
        action = ACTION_PASS
        reasons.append("No actionable weaponization indicators found. Document passed clean.")

    allowed = (ACTION_PASS, ACTION_SANITIZE, ACTION_REVIEW, ACTION_BLOCK)
    eval_result = PolicyEvaluation(
        action=action,
        reasons=reasons,
        allowed_dispositions=allowed
    )
    return eval_result.to_dict()


# Short aliases
evaluate_detector_output = evaluate_policy
evaluate = evaluate_policy

__all__ = ["evaluate_policy", "evaluate_detector_output", "evaluate", "ACTION_PASS", "ACTION_SANITIZE", "ACTION_BLOCK"]
