"""
Lightweight collection behavior feature extraction for Pharos CDR.

Extracts scalar ML features directly from input text via heuristic static scanning.
"""

from __future__ import annotations

import re
from typing import Any, Union

MAX_CHARS = 1024 * 1024

COLLECTION_INDICATORS = {
    "clipboard": re.compile(r"(?i)\b(?:OpenClipboard|GetClipboardData|SetClipboardData|clipboardData)\b"),
    "keylogging": re.compile(r"(?i)\b(?:GetAsyncKeyState|SetWindowsHookEx[A-Z]?|UnhookWindowsHookEx|CallNextHookEx)\b"),
    "screen_capture": re.compile(r"(?i)\b(?:GetDC|GetWindowDC|BitBlt|StretchBlt|PrintWindow|CreateCompatibleDC|CreateCompatibleBitmap)\b"),
    "audio_capture": re.compile(r"(?i)\b(?:mciSendString[A-Z]?|waveInOpen|waveInStart|waveInAddBuffer)\b"),
    "webcam_capture": re.compile(r"(?i)\b(?:capCreateCaptureWindow[A-Z]?|capGetDriverDescription)\b"),
    "window_text": re.compile(r"(?i)\b(?:GetWindowText[A-Z]?|GetForegroundWindow|EnumWindows)\b"),
    "file_search": re.compile(r"(?i)\b(?:FindFirstFile[A-Z]?|FindNextFile[A-Z]?)\b"),
}

COLLECTION_CATEGORIES = {
    "clipboard_access": ["clipboard"],
    "input_capture": ["keylogging"],
    "screen_capture": ["screen_capture", "window_text"],
    "media_capture": ["audio_capture", "webcam_capture"],
    "local_collection": ["file_search"],
}

def extract_collection_feature_vector(source: Union[str, bytes, bytearray]) -> dict[str, float]:
    if isinstance(source, (bytes, bytearray)):
        text = source.decode("utf-8", errors="ignore")
    else:
        text = str(source)
    
    text = text[:MAX_CHARS]
    
    f = {
        "collection_source_size": float(len(text)),
    }
    
    indicator_counts = {}
    for ind, pattern in COLLECTION_INDICATORS.items():
        count = float(len(pattern.findall(text)))
        indicator_counts[ind] = count
        f[f"collection_indicator_{ind}"] = 1.0 if count > 0 else 0.0
        f[f"collection_indicator_{ind}_count"] = count

    for cat, inds in COLLECTION_CATEGORIES.items():
        count = sum(indicator_counts[ind] for ind in inds)
        f[f"collection_category_{cat}"] = 1.0 if count > 0 else 0.0
        f[f"collection_category_{cat}_count"] = count

    f["collection_evidence_count"] = float(sum(indicator_counts.values()))
    f["collection_indicator_count"] = float(sum(1 for v in indicator_counts.values() if v > 0))
    f["collection_category_count"] = float(sum(1 for k, v in f.items() if k.startswith("collection_category_") and not k.endswith("_count") and v > 0))
    
    return f

def extract_collection_features(source: Any, **kwargs: Any) -> dict[str, Any]:
    return {"feature_vector": extract_collection_feature_vector(source)}

def extract_feature_vector(source: Any, **kwargs: Any) -> dict[str, float]:
    return extract_collection_feature_vector(source)

__all__ = ["extract_collection_feature_vector", "extract_collection_features", "extract_feature_vector"]
