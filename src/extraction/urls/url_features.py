"""
Lightweight URL behavior feature extraction for Pharos CDR.

Extracts scalar ML features directly from input text via heuristic static scanning.
"""

from __future__ import annotations

import re
from typing import Any, Union, Mapping

MAX_CHARS = 1024 * 1024

URL_INDICATORS = {
    "http_scheme": re.compile(r"(?i)\bhttp://[^\s\"']+"),
    "https_scheme": re.compile(r"(?i)\bhttps://[^\s\"']+"),
    "ftp_scheme": re.compile(r"(?i)\bftp://[^\s\"']+"),
    "ip_host": re.compile(r"(?i)https?://(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?[/\"'\s]"),
    "suspicious_tld": re.compile(r"(?i)https?://[^/]+\.(?:xyz|top|pw|tk|ml|ga|cf|gq|su|ru|cn)[/\"'\s]"),
    "shortener": re.compile(r"(?i)https?://(?:bit\.ly|tinyurl\.com|goo\.gl|t\.co|ow\.ly|is\.gd|buff\.ly|adf\.ly)[/\"'\s]"),
    "port_override": re.compile(r"(?i)https?://[^/]+:\d{1,5}[/\"'\s]"),
    "credential_embedded": re.compile(r"(?i)https?://[^/]+:[^/]+@[^/]+[/\"'\s]"),
    "executable_path": re.compile(r"(?i)https?://[^\s\"']+\.(?:exe|dll|scr|bat|cmd|vbs|ps1|msi)"),
}

URL_CATEGORIES = {
    "schemes": ["http_scheme", "https_scheme", "ftp_scheme"],
    "suspicious_hosts": ["ip_host", "suspicious_tld", "shortener"],
    "obfuscation": ["port_override", "credential_embedded"],
    "payload_delivery": ["executable_path"],
}

def _vectorize(f: dict[str, float]) -> list[float]:
    keys = sorted(f.keys())
    return [f[k] for k in keys]

def extract_url_feature_vector(source: Union[str, bytes, bytearray], **kwargs: Any) -> list[float]:
    if isinstance(source, (bytes, bytearray)):
        text = source.decode("utf-8", errors="ignore")
    else:
        text = str(source)
    
    text = text[:MAX_CHARS]
    
    f = {
        "url_source_size": float(len(text)),
        "url_record_count": 0.0,
        "url_evidence_count": 0.0,
        "url_indicator_count": 0.0,
        "url_category_count": 0.0,
    }
    
    indicator_counts = {}
    for ind, pattern in URL_INDICATORS.items():
        count = float(len(pattern.findall(text)))
        indicator_counts[ind] = count
        f[f"url_indicator_present__{ind}"] = 1.0 if count > 0 else 0.0
        f[f"url_indicator_count__{ind}"] = count

    for cat, inds in URL_CATEGORIES.items():
        count = sum(indicator_counts[ind] for ind in inds)
        f[f"url_category_present__{cat}"] = 1.0 if count > 0 else 0.0
        f[f"url_category_count__{cat}"] = count

    f["url_evidence_count"] = float(sum(indicator_counts.values()))
    f["url_indicator_count"] = float(sum(1 for v in indicator_counts.values() if v > 0))
    f["url_category_count"] = float(sum(1 for k, v in f.items() if k.startswith("url_category_present__") and v > 0))
    f["url_record_count"] = float(len(re.findall(r"(?i)https?://[^\s\"']+", text)))

    return _vectorize(f)

def extract_url_features(source: Any, **kwargs: Any) -> dict[str, Any]:
    class AnalysisEmulator:
        def __init__(self, vec):
            self.feature_vector = vec
    return AnalysisEmulator(extract_url_feature_vector(source))

def extract_feature_vector(source: Any, **kwargs: Any) -> list[float]:
    return extract_url_feature_vector(source)

def vectorize_features(features: Mapping[str, object]) -> list[float]:
    return _vectorize({k: float(v) for k, v in features.items()})

__all__ = ["extract_url_feature_vector", "extract_url_features", "extract_feature_vector", "vectorize_features"]
