"""
Lightweight OLE extraction for Pharos CDR.

Extracts scalar ML features from OLE/Compound files using lightweight structural 
heuristics and content scanning.
"""

from __future__ import annotations

import re
import struct
from typing import Any

MAX_SAMPLE_BYTES = 16 * 1024 * 1024

VBA_RE = re.compile(rb"(?i)Attribute\s+VB_Name|VBProject|VBA")
SUSPICIOUS_RE = re.compile(rb"(?i)shell|exec|autoopen|document_open|cmd\.exe|powershell")
URL_RE = re.compile(rb"(?i)https?://")
IPV4_RE = re.compile(rb"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")

def extract_ole_features(
    data: bytes,
    *,
    max_sample_bytes: int = MAX_SAMPLE_BYTES,
) -> dict[str, Any]:
    f = {
        "ole_version": 1.0,
        "ole_is_container": 0.0,
        "ole_valid_header": 0.0,
        "ole_parse_error": 0.0,
        "ole_sector_size": 0.0,
        "ole_directory_entry_count": 0.0,
        "ole_storage_count": 0.0,
        "ole_stream_count": 0.0,
        "ole_non_empty_stream_count": 0.0,
        "ole_mini_stream_count": 0.0,
        "ole_large_stream_count": 0.0,
        "ole_total_stream_bytes": 0.0,
        "ole_max_stream_size": 0.0,
        "ole_vba_stream_count": 0.0,
        "ole_macro_related_stream_count": 0.0,
        "ole_suspicious_name_count": 0.0,
        "ole_suspicious_content_count": 0.0,
        "ole_url_stream_count": 0.0,
        "ole_ipv4_stream_count": 0.0,
        "ole_windows_path_stream_count": 0.0,
        "ole_base64_like_stream_count": 0.0,
        "ole_shell_indicator_stream_count": 0.0,
        "ole_high_entropy_stream_count": 0.0,
        "ole_non_empty_clsid_count": 0.0,
        "ole_has_vba": 0.0,
        "ole_has_macros": 0.0,
        "ole_has_embedded_objects": 0.0,
        "ole_suspicious": 0.0,
        "ole_vba_stream_ratio": 0.0,
        "ole_suspicious_stream_ratio": 0.0,
        "ole_high_entropy_stream_ratio": 0.0,
        "ole_truncated": 0.0,
        "ole_parse_truncation_count": 0.0,
    }

    if not data or len(data) < 512:
        return f
        
    if not data.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        return f

    f["ole_is_container"] = 1.0
    f["ole_valid_header"] = 1.0

    try:
        # Parse basic OLE header
        sector_shift = struct.unpack_from("<H", data, 30)[0]
        if sector_shift == 9:
            f["ole_sector_size"] = 512.0
        elif sector_shift == 12:
            f["ole_sector_size"] = 4096.0
        else:
            f["ole_parse_error"] = 1.0
            return f
            
        dir_sectors = struct.unpack_from("<I", data, 40)[0]
        dir_entries = dir_sectors * (int(f["ole_sector_size"]) // 128)
        f["ole_directory_entry_count"] = float(dir_entries)
        f["ole_stream_count"] = float(dir_entries)  # approximate
        
        # Limit sample size for binary regex scanning
        sample = data[:max_sample_bytes]
        if len(data) > max_sample_bytes:
            f["ole_truncated"] = 1.0
            
        if VBA_RE.search(sample):
            f["ole_has_vba"] = 1.0
            f["ole_has_macros"] = 1.0
            f["ole_macro_related_stream_count"] = 1.0
            f["ole_vba_stream_count"] = 1.0
            
        if SUSPICIOUS_RE.search(sample):
            f["ole_suspicious"] = 1.0
            f["ole_suspicious_content_count"] = 1.0
            f["ole_shell_indicator_stream_count"] = 1.0
            
        if b"Ole10Native" in sample or b"Package" in sample:
            f["ole_has_embedded_objects"] = 1.0
            
        if URL_RE.search(sample):
            f["ole_url_stream_count"] = 1.0
            
        if IPV4_RE.search(sample):
            f["ole_ipv4_stream_count"] = 1.0
            
        if b":\\" in sample:
            f["ole_windows_path_stream_count"] = 1.0

    except struct.error:
        f["ole_parse_error"] = 1.0

    return f

__all__ = ["extract_ole_features"]
