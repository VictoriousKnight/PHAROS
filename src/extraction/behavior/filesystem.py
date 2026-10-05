"""
Lightweight filesystem behavior feature extraction for Pharos CDR.

Extracts scalar ML features directly from input text via heuristic static scanning.
"""

from __future__ import annotations

import re
from typing import Any, Union

MAX_CHARS = 1024 * 1024

FS_INDICATORS = {
    "file_write": re.compile(r"(?i)\b(?:WriteFile|CreateFile[A-Z]?|CreateTextFile|OpenTextFile|Out-File|Set-Content)\b"),
    "file_read": re.compile(r"(?i)\b(?:ReadFile|Get-Content|ReadAllText|OpenTextFile)\b"),
    "file_delete": re.compile(r"(?i)\b(?:DeleteFile[A-Z]?|Remove-Item|Kill)\b"),
    "file_copy": re.compile(r"(?i)\b(?:CopyFile[A-Z]?|MoveFile[A-Z]?|Copy-Item|Move-Item|FileCopy)\b"),
    "directory_operations": re.compile(r"(?i)\b(?:CreateDirectory|RemoveDirectory|MkDir|RmDir|New-Item)\b"),
    "temp_file": re.compile(r"(?i)\b(?:GetTempPath[A-Z]?|GetTempFileName[A-Z]?|\[System\.IO\.Path\]::GetTempPath)\b"),
    "attributes": re.compile(r"(?i)\b(?:SetFileAttributes[A-Z]?|SetAttr)\b"),
}

FS_CATEGORIES = {
    "write_operations": ["file_write"],
    "read_operations": ["file_read"],
    "delete_operations": ["file_delete"],
    "move_operations": ["file_copy"],
    "directory_operations": ["directory_operations"],
    "temp_operations": ["temp_file"],
    "attribute_operations": ["attributes"],
}

def extract_filesystem_feature_vector(source: Union[str, bytes, bytearray]) -> dict[str, float]:
    if isinstance(source, (bytes, bytearray)):
        text = source.decode("utf-8", errors="ignore")
    else:
        text = str(source)
    
    text = text[:MAX_CHARS]
    
    f = {
        "filesystem_source_size": float(len(text)),
    }
    
    indicator_counts = {}
    for ind, pattern in FS_INDICATORS.items():
        count = float(len(pattern.findall(text)))
        indicator_counts[ind] = count
        f[f"filesystem_indicator_{ind}"] = 1.0 if count > 0 else 0.0
        f[f"filesystem_indicator_{ind}_count"] = count

    for cat, inds in FS_CATEGORIES.items():
        count = sum(indicator_counts[ind] for ind in inds)
        f[f"filesystem_category_{cat}"] = 1.0 if count > 0 else 0.0
        f[f"filesystem_category_{cat}_count"] = count

    f["filesystem_evidence_count"] = float(sum(indicator_counts.values()))
    f["filesystem_indicator_count"] = float(sum(1 for v in indicator_counts.values() if v > 0))
    f["filesystem_category_count"] = float(sum(1 for k, v in f.items() if k.startswith("filesystem_category_") and not k.endswith("_count") and v > 0))
    
    return f

def extract_filesystem_features(source: Any, **kwargs: Any) -> dict[str, Any]:
    return {"feature_vector": extract_filesystem_feature_vector(source)}

def extract_feature_vector(source: Any, **kwargs: Any) -> dict[str, float]:
    return extract_filesystem_feature_vector(source)

__all__ = ["extract_filesystem_feature_vector", "extract_filesystem_features", "extract_feature_vector"]