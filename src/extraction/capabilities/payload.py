"""
Lightweight payload extraction for Pharos CDR.

Extracts scalar ML features directly from input text via heuristic static scanning.
"""

from __future__ import annotations

import re
from typing import Any, Union, Mapping

MAX_CHARS = 1024 * 1024

PAYLOAD_INDICATORS = {
    "pe_file": re.compile(r"(?i)\b(?:MZ.{64,}?PE\0\0)\b"),
    "elf_file": re.compile(r"(?i)\b(?:\x7fELF)\b"),
    "script_file": re.compile(r"(?i)\b(?:Dim\s+|function\s+|Invoke-|Set-ExecutionPolicy)\b"),
    "archive_file": re.compile(r"(?i)\b(?:PK\x03\x04|Rar!\x1a\x07)\b"),
    "base64_blob": re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{100,}={0,2}(?![A-Za-z0-9+/=])"),
    "hex_blob": re.compile(r"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{2}){50,}(?![0-9A-Fa-f])"),
    "shellcode": re.compile(r"(?:\\x[0-9a-fA-F]{2}){16,}"),
    "url": re.compile(r"(?i)https?://[^\s\"']+"),
    "ip_address": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
}

PAYLOAD_CATEGORIES = {
    "binaries": ["pe_file", "elf_file"],
    "scripts": ["script_file"],
    "archives": ["archive_file"],
    "encoded": ["base64_blob", "hex_blob", "shellcode"],
    "network": ["url", "ip_address"],
}

def _vectorize(f: dict[str, float]) -> list[float]:
    keys = sorted(f.keys())
    return [f[k] for k in keys]

def extract_payload_feature_vector(source: Union[str, bytes, bytearray], **kwargs: Any) -> list[float]:
    if isinstance(source, (bytes, bytearray)):
        text = source.decode("utf-8", errors="ignore")
    else:
        text = str(source)
    
    text = text[:MAX_CHARS]
    
    f = {
        "source_size": float(len(text)),
        "record_count": 0.0,
        "evidence_count": 0.0,
        "indicator_count": 0.0,
        "category_count": 0.0,
    }
    
    indicator_counts = {}
    for ind, pattern in PAYLOAD_INDICATORS.items():
        count = float(len(pattern.findall(text)))
        indicator_counts[ind] = count
        f[f"indicator_present__{ind}"] = 1.0 if count > 0 else 0.0
        f[f"indicator_count__{ind}"] = count

    for cat, inds in PAYLOAD_CATEGORIES.items():
        count = sum(indicator_counts[ind] for ind in inds)
        f[f"category_present__{cat}"] = 1.0 if count > 0 else 0.0
        f[f"category_count__{cat}"] = count

    f["evidence_count"] = float(sum(indicator_counts.values()))
    f["indicator_count"] = float(sum(1 for v in indicator_counts.values() if v > 0))
    f["category_count"] = float(sum(1 for k, v in f.items() if k.startswith("category_present__") and v > 0))

    return _vectorize(f)

def extract_payload_features(source: Any, **kwargs: Any) -> dict[str, Any]:
    class AnalysisEmulator:
        def __init__(self, vec):
            self.feature_vector = vec
    return AnalysisEmulator(extract_payload_feature_vector(source))

def extract_feature_vector(source: Any, **kwargs: Any) -> list[float]:
    return extract_payload_feature_vector(source)

def vectorize_features(features: Mapping[str, object]) -> list[float]:
    return _vectorize({k: float(v) for k, v in features.items()})

__all__ = ["extract_payload_feature_vector", "extract_payload_features", "extract_feature_vector", "vectorize_features"]
