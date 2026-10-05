"""
Lightweight VBA obfuscation extraction for Pharos CDR.

Extracts scalar ML features for VBA string manipulation and obfuscation.
"""

from __future__ import annotations

import re
from typing import Any, Union

MAX_CHARS = 1024 * 1024

OBFUSCATION_INDICATORS = {
    "base64_like_string": re.compile(r'"(?:[A-Za-z0-9+/]{4}){8,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?"'),
    "hex_like_string": re.compile(r'"(?:[0-9a-fA-F]{2}){16,}"'),
    "fragmented_string_construction": re.compile(r'"\s*&\s*"[^"]{1,3}"\s*&'),
    "excessive_line_continuations": re.compile(r"_\s*\n\s*_\s*\n"),
    "numeric_character_construction": re.compile(r"(?i)\b(?:Chr|ChrW)\s*\(\s*\d+\s*\)"),
    "repeated_numeric_character_sequence": re.compile(r"(?i)(?:ChrW?\s*\(\s*\d+\s*\)\s*&\s*){3,}"),
    "conditional_compilation": re.compile(r"(?i)#If\s+VBA7\b"),
}

TRANSFORM_CATEGORIES = {
    "string_manipulation": re.compile(r"(?i)\b(?:StrReverse|Replace|Mid|Left|Right|Split|Join|InStr|InStrRev|Len)\b"),
    "encoding": re.compile(r"(?i)\b(?:Chr|ChrW|ChrB|Asc|AscW|AscB|Hex|Oct)\b"),
    "environment": re.compile(r"(?i)\b(?:Environ|Environ\$)"),
}

def extract_obfuscation_feature_vector(source: Union[str, bytes, bytearray]) -> dict[str, float]:
    if isinstance(source, (bytes, bytearray)):
        text = source.decode("utf-8", errors="ignore")
    else:
        text = str(source)
    
    text = text[:MAX_CHARS]
    f = {}
    
    for ind, pattern in OBFUSCATION_INDICATORS.items():
        count = float(len(pattern.findall(text)))
        f[f"vba_obfuscation_indicator_{ind}"] = 1.0 if count > 0 else 0.0
        f[f"vba_obfuscation_indicator_{ind}_count"] = count

    for cat, pattern in TRANSFORM_CATEGORIES.items():
        count = float(len(pattern.findall(text)))
        f[f"vba_obfuscation_{cat}"] = 1.0 if count > 0 else 0.0
        f[f"vba_obfuscation_{cat}_count"] = count
        
    return f

def extract_obfuscation_features(source: Union[str, bytes, bytearray]) -> dict[str, Any]:
    return {"feature_vector": extract_obfuscation_feature_vector(source)}

def extract_feature_vector(source: Union[str, bytes, bytearray]) -> dict[str, float]:
    return extract_obfuscation_feature_vector(source)

__all__ = ["extract_obfuscation_feature_vector", "extract_obfuscation_features", "extract_feature_vector"]
