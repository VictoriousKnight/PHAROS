"""
Top-level script feature extractor for Pharos CDR.

Consolidates ML feature vectors from specialized script extraction modules.
"""

from __future__ import annotations

import re
from typing import Any, Union

from src.extraction.script.javascript import extract_javascript_feature_vector
from src.extraction.script.vbscript import extract_vbscript_feature_vector
from src.extraction.script.powershell import extract_powershell_feature_vector

def extract_script_feature_vector(
    source: Union[str, bytes, bytearray],
    family: str | None = None,
    filename: str | None = None,
    content_type: str | None = None,
) -> dict[str, float]:
    """Extract all Script features."""
    if isinstance(source, (bytes, bytearray)):
        text = source.decode("utf-8", errors="ignore")
    else:
        text = str(source)
        
    features = {
        "script_line_count": float(len(text.splitlines())),
        "script_source_size_bytes": float(len(text)),
    }
    
    # Generic heuristics
    strings = re.findall(r'"[^"\\]*(?:\\.[^"\\]*)*"|\'[^\'\\]*(?:\\.[^\'\\]*)*\'', text)
    features["script_string_count"] = float(len(strings))
    features["script_url_count"] = float(len(re.findall(r"(?i)https?://[^\s\"']+", text)))
    
    identifiers = set(re.findall(r"(?i)\b[A-Za-z_][A-Za-z0-9_]*\b", text))
    features["script_identifier_count"] = float(len(identifiers))

    # Guess family if not provided
    if not family:
        lower = text.lower()
        if filename and filename.endswith(".ps1") or "invoke-" in lower or "powershell" in lower:
            family = "powershell"
        elif filename and filename.endswith(".vbs") or "wscript" in lower or "createobject" in lower:
            family = "vbscript"
        elif filename and filename.endswith(".js") or "function" in lower or "var " in lower:
            family = "javascript"
        else:
            family = "generic"

    for f in ("javascript", "vbscript", "powershell", "generic"):
        features[f"script_family_{f}"] = 1.0 if family == f else 0.0

    if family == "javascript":
        features.update(extract_javascript_feature_vector(text))
    elif family == "vbscript":
        features.update(extract_vbscript_feature_vector(text))
    elif family == "powershell":
        features.update(extract_powershell_feature_vector(text))

    return features

def extract_script_features(
    source: Union[str, bytes, bytearray],
    family: str | None = None,
    filename: str | None = None,
    content_type: str | None = None,
) -> dict[str, Any]:
    return {"feature_vector": extract_script_feature_vector(source, family, filename, content_type)}

def extract_feature_vector(
    source: Union[str, bytes, bytearray],
    family: str | None = None,
    filename: str | None = None,
    content_type: str | None = None,
) -> dict[str, float]:
    return extract_script_feature_vector(source, family, filename, content_type)

__all__ = ["extract_script_feature_vector", "extract_script_features", "extract_feature_vector"]
