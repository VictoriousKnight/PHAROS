"""
Lightweight environment behavior feature extraction for Pharos CDR.

Extracts scalar ML features directly from input text via heuristic static scanning.
"""

from __future__ import annotations

import re
from typing import Any, Union

MAX_CHARS = 1024 * 1024

ENV_INDICATORS = {
    "env_vars": re.compile(r"(?i)\b(?:%APPDATA%|%LOCALAPPDATA%|%TEMP%|%TMP%|%USERPROFILE%|%WINDIR%|%SYSTEMROOT%)\b"),
    "env_api": re.compile(r"(?i)\b(?:GetEnvironmentVariable[A-Z]?|SetEnvironmentVariable[A-Z]?|ExpandEnvironmentStrings[A-Z]?)\b"),
    "system_info": re.compile(r"(?i)\b(?:GetSystemInfo|GetVersionEx|GetComputerName|GetUserName)\b"),
    "wmi_discovery": re.compile(r"(?i)\b(?:Win32_ComputerSystem|Win32_OperatingSystem|Win32_LogicalDisk)\b"),
    "language_locale": re.compile(r"(?i)\b(?:GetUserDefaultUILanguage|GetSystemDefaultUILanguage|GetLocaleInfo)\b"),
}

ENV_CATEGORIES = {
    "environment_variables": ["env_vars", "env_api"],
    "system_discovery": ["system_info", "wmi_discovery"],
    "locale_discovery": ["language_locale"],
}

def extract_environment_feature_vector(source: Union[str, bytes, bytearray]) -> dict[str, float]:
    if isinstance(source, (bytes, bytearray)):
        text = source.decode("utf-8", errors="ignore")
    else:
        text = str(source)
    
    text = text[:MAX_CHARS]
    
    f = {
        "environment_source_size": float(len(text)),
    }
    
    indicator_counts = {}
    for ind, pattern in ENV_INDICATORS.items():
        count = float(len(pattern.findall(text)))
        indicator_counts[ind] = count
        f[f"environment_indicator_{ind}"] = 1.0 if count > 0 else 0.0
        f[f"environment_indicator_{ind}_count"] = count

    for cat, inds in ENV_CATEGORIES.items():
        count = sum(indicator_counts[ind] for ind in inds)
        f[f"environment_category_{cat}"] = 1.0 if count > 0 else 0.0
        f[f"environment_category_{cat}_count"] = count

    f["environment_evidence_count"] = float(sum(indicator_counts.values()))
    f["environment_indicator_count"] = float(sum(1 for v in indicator_counts.values() if v > 0))
    f["environment_category_count"] = float(sum(1 for k, v in f.items() if k.startswith("environment_category_") and not k.endswith("_count") and v > 0))
    
    return f

def extract_environment_features(source: Any, **kwargs: Any) -> dict[str, Any]:
    return {"feature_vector": extract_environment_feature_vector(source)}

def extract_feature_vector(source: Any, **kwargs: Any) -> dict[str, float]:
    return extract_environment_feature_vector(source)

__all__ = ["extract_environment_feature_vector", "extract_environment_features", "extract_feature_vector"]
