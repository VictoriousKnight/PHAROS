"""Utility helpers for the ML layer.

Provides a function to flatten the predictor output into the top‑level
structure expected by the web UI.
"""

from __future__ import annotations
from typing import Mapping, Any


def flatten_prediction(pred: Mapping[str, Any]) -> dict[str, Any]:
    """Return a flat dict with the fields the front‑end displays.

    The ``predict`` function returns a mapping like::

        {
            "probability": 0.84,
            "predicted_malicious": true,
            "confidence": 0.84,
            "threshold": 0.5,
            "model_name": "RandomForestClassifier",
            "features_evaluated": 127,
        }

    The UI expects ``model_probability`` (percentage), ``ml_confidence``
    and a few ancillary values. Missing keys are replaced with ``None``
    so the Jinja template can render gracefully.
    """
    if not pred:
        return {
            "model_probability": None,
            "predicted_malicious": None,
            "ml_confidence": None,
            "model_threshold": None,
            "model_name": None,
            "features_evaluated": None,
        }

    return {
        "model_probability": pred.get("probability"),
        "predicted_malicious": pred.get("predicted_malicious"),
        "ml_confidence": pred.get("confidence"),
        "model_threshold": pred.get("threshold"),
        "model_name": pred.get("model_name"),
        "features_evaluated": pred.get("features_evaluated"),
    }
