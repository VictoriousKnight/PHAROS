"""
PHAROS ML - Explanation Engine
------------------------------
Generates structured threat explanations for model predictions.
Calculates feature contributions and formats technical signals and human-readable
rationales suitable for direct LLM summarization or end-user reporting.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping, Optional, Sequence

import numpy as np
import pandas as pd

from src.ml.predict import get_predictor

logger = logging.getLogger("ml.explain")

# Human-readable threat descriptions for key static indicators (useful for LLM prompting)
FEATURE_DESCRIPTIONS: dict[str, str] = {
    "vba_has_auto_exec": "Document contains automatic macro execution handlers (AutoOpen/Document_Open).",
    "vba_hex_strings_count": "Presence of hexadecimal-encoded strings typically used to obscure payloads.",
    "vba_base64_strings_count": "Presence of Base64 encoded payload blocks.",
    "vba_str_reverse_count": "Use of string reversal (StrReverse) obfuscation techniques.",
    "vba_calls_environ": "Accesses operating system environment variables (%TEMP%, %APPDATA%).",
    "vba_declares_api": "Invokes native Win32 API functions directly from VBA.",
    "vba_suspicious_keywords_count": "High density of suspicious keywords (CreateObject, Run, Shell).",
    "dynexec_calls_shell": "Executes external command-line shell utilities.",
    "dynexec_calls_wscript_shell": "Invokes WScript.Shell for background process execution.",
    "dynexec_creates_process": "Spawns child processes on the host machine.",
    "fs_drops_executable": "Attempts to drop or write executable binaries (.exe, .dll) to disk.",
    "fs_writes_temp": "Writes suspicious payload files to system temporary directories.",
    "net_has_ip_literal": "Hardcoded literal IP addresses found instead of standard domain names.",
    "net_downloads_file": "Initiates remote HTTP/network file downloads.",
    "entropy_stream_max": "Abnormally high Shannon entropy indicating packed, compressed, or encrypted payload streams.",
    "entropy_byte_level": "Elevated overall file byte entropy indicating obfuscation.",
    "ooxml_has_embedded_binaries": "Contains embedded binary objects within OpenXML package.",
    "ooxml_external_relationships_count": "External target relationships pointing outside the document container.",
    "ole_stream_count": "Unusually high number of embedded OLE storage streams.",
}


@dataclass(frozen=True)
class FeatureContribution:
    feature: str
    value: float
    importance: float
    description: str
    signal_type: str  # 'malicious_indicator' or 'benign_indicator'


@dataclass
class ExplanationResult:
    predicted_malicious: bool
    probability: float
    confidence: float
    summary_rationale: str
    top_contributions: list[FeatureContribution] = field(default_factory=list)
    llm_prompt_context: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "predicted_malicious": self.predicted_malicious,
            "probability": self.probability,
            "confidence": self.confidence,
            "summary_rationale": self.summary_rationale,
            "top_contributions": [
                {
                    "feature": c.feature,
                    "value": c.value,
                    "importance": c.importance,
                    "description": c.description,
                    "signal_type": c.signal_type,
                }
                for c in self.top_contributions
            ],
            "llm_prompt_context": self.llm_prompt_context,
        }


def explain_prediction(
    features: Mapping[str, Any],
    top_k: int = 5,
    threshold: Optional[float] = None
) -> ExplanationResult:
    """
    Explain why a sample was flagged as malicious or benign.
    Computes active feature contributions weighted by model importances,
    and returns formatted structured context ready to feed into an LLM.
    """
    predictor = get_predictor()
    pred_res = predictor.predict_features(features, threshold=threshold)

    prob = pred_res.get("probability", 0.0) or 0.0
    is_mal = pred_res.get("predicted_malicious", False)
    conf = pred_res.get("confidence", 0.0)

    # Extract tree-based feature importances from pipeline if available
    pipeline = predictor.pipeline
    model_rf = getattr(pipeline, "named_steps", {}).get("model", pipeline) if pipeline else None
    importances = getattr(model_rf, "feature_importances_", None)
    expected_cols = predictor.expected_features

    feature_weights = {}
    if importances is not None and len(importances) == len(expected_cols):
        feature_weights = dict(zip(expected_cols, importances))

    contributions: list[FeatureContribution] = []

    # Score activated or non-zero threat features
    for feat_name, val in features.items():
        try:
            num_val = float(val) if val is not None else 0.0
        except (ValueError, TypeError):
            continue

        if num_val > 0:
            imp = feature_weights.get(feat_name, 0.01)
            # High weight if feature has strong Gini importance and positive activation
            score = imp * (1.0 if num_val >= 1 else num_val)
            desc = FEATURE_DESCRIPTIONS.get(feat_name, f"Indicator {feat_name} observed with value {num_val}.")
            signal = "malicious_indicator" if is_mal else "benign_indicator"

            contributions.append(
                FeatureContribution(
                    feature=feat_name,
                    value=num_val,
                    importance=round(score, 4),
                    description=desc,
                    signal_type=signal,
                )
            )

    # Sort by importance
    contributions.sort(key=lambda c: c.importance, reverse=True)
    top_signals = contributions[:top_k]

    # Generate baseline human summary
    if is_mal:
        reasons = [c.description for c in top_signals if c.feature in FEATURE_DESCRIPTIONS]
        lead_reason = "; ".join(reasons[:2]) if reasons else "Multiple anomalous threat indicators observed."
        summary = f"Flagged MALICIOUS (Risk: {prob*100:.1f}%). Primary factors: {lead_reason}"
    else:
        summary = f"Flagged BENIGN (Clean Confidence: {conf*100:.1f}%). No high-risk macro execution or dynamic payloads detected."

    # Pre-structured payload specifically formatted for LLM generation
    llm_context = {
        "verdict": "MALICIOUS" if is_mal else "BENIGN",
        "threat_probability": prob,
        "confidence_score": conf,
        "key_observed_indicators": [
            {"indicator": c.feature, "value": c.value, "detail": c.description}
            for c in top_signals
        ],
        "system_prompt_recommendation": (
            "You are a cybersecurity analyst assistant. Explain to the user in concise, clear, non-technical language "
            "why this document was flagged, referencing the specific indicators provided."
        ),
    }

    return ExplanationResult(
        predicted_malicious=is_mal,
        probability=prob,
        confidence=conf,
        summary_rationale=summary,
        top_contributions=top_signals,
        llm_prompt_context=llm_context,
    )


# Short alias
explain = explain_prediction

__all__ = ["FeatureContribution", "ExplanationResult", "explain_prediction", "explain"]
