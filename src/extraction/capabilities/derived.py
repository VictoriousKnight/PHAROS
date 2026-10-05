"""
Lightweight derived capabilities extraction for Pharos CDR.

Extracts scalar ML features directly from input text via heuristic static scanning.
"""

from __future__ import annotations

import re
from typing import Any, Union, Mapping

from src.extraction.capabilities.dynamic_execution import extract_dynamic_execution_feature_vector
from src.extraction.capabilities.payload import extract_payload_feature_vector
from src.extraction.capabilities.communication import extract_communication_feature_vector

def extract_derived_feature_vector(source: Union[str, bytes, bytearray], **kwargs: Any) -> list[float]:
    dyn = extract_dynamic_execution_feature_vector(source)
    pay = extract_payload_feature_vector(source)
    com = extract_communication_feature_vector(source)
    
    # Just merge and flatten them to keep it deterministic and simple.
    return dyn + pay + com

def extract_derived_features(source: Any, **kwargs: Any) -> dict[str, Any]:
    class AnalysisEmulator:
        def __init__(self, vec):
            self.feature_vector = vec
    return AnalysisEmulator(extract_derived_feature_vector(source))

def extract_feature_vector(source: Any, **kwargs: Any) -> list[float]:
    return extract_derived_feature_vector(source)

def vectorize_features(features: Mapping[str, object]) -> list[float]:
    keys = sorted(features.keys())
    return [float(features[k]) for k in keys]

__all__ = ["extract_derived_feature_vector", "extract_derived_features", "extract_feature_vector", "vectorize_features"]
