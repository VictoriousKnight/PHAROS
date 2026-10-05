"""
Lightweight registry behavior feature extraction for Pharos CDR.

Extracts scalar ML features directly from input text via heuristic static scanning.
"""

from __future__ import annotations

import re
from typing import Any, Union

MAX_CHARS = 1024 * 1024

REG_INDICATORS = {
    "reg_open": re.compile(r"(?i)\b(?:RegOpenKey(?:Ex)?[A-Z]?|Get-ItemProperty)\b"),
    "reg_read": re.compile(r"(?i)\b(?:RegQueryValue(?:Ex)?[A-Z]?|RegRead|Get-ItemProperty)\b"),
    "reg_write": re.compile(r"(?i)\b(?:RegSetValue(?:Ex)?[A-Z]?|RegWrite|Set-ItemProperty|New-ItemProperty)\b"),
    "reg_create": re.compile(r"(?i)\b(?:RegCreateKey(?:Ex)?[A-Z]?|New-ItemProperty)\b"),
    "reg_delete": re.compile(r"(?i)\b(?:RegDeleteKey(?:Ex)?[A-Z]?|RegDeleteValue(?:Ex)?[A-Z]?|RegDelete|Remove-ItemProperty)\b"),
    "reg_hive_hklm": re.compile(r"(?i)\b(?:HKEY_LOCAL_MACHINE|HKLM)\b"),
    "reg_hive_hkcu": re.compile(r"(?i)\b(?:HKEY_CURRENT_USER|HKCU)\b"),
    "reg_hive_hkcr": re.compile(r"(?i)\b(?:HKEY_CLASSES_ROOT|HKCR)\b"),
    "reg_hive_hku": re.compile(r"(?i)\b(?:HKEY_USERS|HKU)\b"),
}

REG_CATEGORIES = {
    "registry_read": ["reg_open", "reg_read"],
    "registry_write": ["reg_write", "reg_create"],
    "registry_delete": ["reg_delete"],
    "registry_hives": ["reg_hive_hklm", "reg_hive_hkcu", "reg_hive_hkcr", "reg_hive_hku"],
}

def extract_registry_feature_vector(source: Union[str, bytes, bytearray]) -> dict[str, float]:
    if isinstance(source, (bytes, bytearray)):
        text = source.decode("utf-8", errors="ignore")
    else:
        text = str(source)
    
    text = text[:MAX_CHARS]
    
    f = {
        "registry_source_size": float(len(text)),
    }
    
    indicator_counts = {}
    for ind, pattern in REG_INDICATORS.items():
        count = float(len(pattern.findall(text)))
        indicator_counts[ind] = count
        f[f"registry_indicator_{ind}"] = 1.0 if count > 0 else 0.0
        f[f"registry_indicator_{ind}_count"] = count

    for cat, inds in REG_CATEGORIES.items():
        count = sum(indicator_counts[ind] for ind in inds)
        f[f"registry_category_{cat}"] = 1.0 if count > 0 else 0.0
        f[f"registry_category_{cat}_count"] = count

    f["registry_evidence_count"] = float(sum(indicator_counts.values()))
    f["registry_indicator_count"] = float(sum(1 for v in indicator_counts.values() if v > 0))
    f["registry_category_count"] = float(sum(1 for k, v in f.items() if k.startswith("registry_category_") and not k.endswith("_count") and v > 0))
    
    return f

def extract_registry_features(source: Any, **kwargs: Any) -> dict[str, Any]:
    return {"feature_vector": extract_registry_feature_vector(source)}

def extract_feature_vector(source: Any, **kwargs: Any) -> dict[str, float]:
    return extract_registry_feature_vector(source)

__all__ = ["extract_registry_feature_vector", "extract_registry_features", "extract_feature_vector"]
