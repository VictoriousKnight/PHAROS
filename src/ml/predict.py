"""
PHAROS ML - Prediction Engine
-----------------------------
Lightweight, thread-safe inference module.
Loads the trained Random Forest pipeline and model metadata to produce
probabilities and threat classifications for extracted document feature vectors.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping, Optional, Sequence

import joblib
import numpy as np
import pandas as pd

logger = logging.getLogger("ml.predict")

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
DEFAULT_MODEL_PATH = PROJECT_ROOT / "models" / "trained" / "trained_model_pipeline.joblib"
DEFAULT_META_PATH = PROJECT_ROOT / "models" / "metadata" / "model_metadata.json"
DEFAULT_THRESHOLDS_PATH = PROJECT_ROOT / "models" / "metadata" / "thresholds.json"


@dataclass
class Predictor:
    """Singleton-style or reusable model wrapper for live inference."""

    model_path: Path = DEFAULT_MODEL_PATH
    meta_path: Path = DEFAULT_META_PATH
    pipeline: Any = None
    expected_features: list[str] = field(default_factory=list)
    default_threshold: float = 0.50

    def __post_init__(self):
        self._load()

    def _load(self):
        if not self.model_path.exists():
            # Fallback to standalone estimator if pipeline not found
            fallback = self.model_path.parent / "random_forest.joblib"
            if fallback.exists():
                self.model_path = fallback
            else:
                logger.warning("No model artifact found at %s", self.model_path)
                return

        try:
            self.pipeline = joblib.load(self.model_path)
        except Exception as exc:
            logger.error("Failed to load model from %s: %s", self.model_path, exc)
            return

        if self.meta_path.exists():
            try:
                with open(self.meta_path, "r", encoding="utf-8") as f:
                    meta = json.load(f)
                    self.expected_features = meta.get("features", [])
                    thresholds = meta.get("decision_thresholds", {})
                    self.default_threshold = thresholds.get("balanced", 0.50)
            except Exception as exc:
                logger.warning("Could not parse metadata from %s: %s", self.meta_path, exc)

    @property
    def is_available(self) -> bool:
        return self.pipeline is not None

    def predict_features(
        self,
        features: Mapping[str, Any],
        threshold: Optional[float] = None
    ) -> dict[str, Any]:
        """
        Run inference against a dictionary of extracted features.
        Missing features are automatically imputed via the pipeline.
        """
        if not self.is_available:
            return {
                "error": "model_unavailable",
                "probability": None,
                "predicted_malicious": False,
                "confidence": 0.0,
            }

        cutoff = threshold if threshold is not None else self.default_threshold
        cols = self.expected_features if self.expected_features else list(features.keys())

        # Construct single-row DataFrame aligned to expected features
        row = {c: features.get(c, np.nan) for c in cols}
        df_in = pd.DataFrame([row], columns=cols)

        try:
            probs = self.pipeline.predict_proba(df_in)[0]
            malicious_prob = float(probs[1]) if len(probs) > 1 else float(probs[0])
        except Exception as exc:
            logger.error("Inference execution failed: %s", exc)
            return {
                "error": f"inference_error: {exc}",
                "probability": None,
                "predicted_malicious": False,
                "confidence": 0.0,
            }

        is_mal = bool(malicious_prob >= cutoff)
        confidence = float(malicious_prob if is_mal else (1.0 - malicious_prob))

        return {
            "probability": round(malicious_prob, 4),
            "predicted_malicious": is_mal,
            "confidence": round(confidence, 4),
            "threshold": cutoff,
            "model_name": type(self.pipeline).__name__,
            "features_evaluated": len(cols),
        }

    # ------------------------------------------------------------------
    # Compatibility wrapper used by older code paths (e.g. diagnostics)
    # ------------------------------------------------------------------
    def predict(self, features: Mapping[str, Any], **kwargs) -> dict[str, Any]:
        """Legacy entry point that forwards to :meth:`predict_features`.

        The diagnostics utility historically called ``predictor.predict``.  The
        new API is ``predict_features``; this thin wrapper preserves backwards
        compatibility without altering the public contract of ``Predictor``.
        ``**kwargs`` is accepted for forward‑compatibility but ignored because
        the underlying implementation does not need it.
        """
        return self.predict_features(features, **kwargs)



# Global cached predictor instance
_PREDICTOR: Optional[Predictor] = None


def get_predictor() -> Predictor:
    global _PREDICTOR
    if _PREDICTOR is None:
        _PREDICTOR = Predictor()
    return _PREDICTOR


def predict(record_or_features: Mapping[str, Any], **kwargs) -> dict[str, Any]:
    """
    Main entry point for pipeline/scanner.py.
    Accepts raw feature mapping, a scan record, or nested candidate dicts.
    """
    predictor = get_predictor()

    # Extract feature vector from record if nested
    features = record_or_features
    if "feature_vector" in record_or_features and isinstance(record_or_features["feature_vector"], Mapping):
        features = record_or_features["feature_vector"]
    elif "features" in record_or_features and isinstance(record_or_features["features"], Mapping):
        features = record_or_features["features"]

    threshold = kwargs.get("threshold")
    return predictor.predict_features(features, threshold=threshold)


# Aliases for compatibility
predict_record = predict
classify = predict

__all__ = ["Predictor", "get_predictor", "predict", "predict_record", "classify"]
