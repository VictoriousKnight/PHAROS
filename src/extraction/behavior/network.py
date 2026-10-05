"""
Lightweight network behavior feature extraction for Pharos CDR.

Extracts scalar ML features directly from input text via heuristic static scanning.
"""

from __future__ import annotations

import re
from typing import Any, Union

MAX_CHARS = 1024 * 1024

NET_INDICATORS = {
    "wininet": re.compile(r"(?i)\b(?:InternetOpen[A-Z]?|InternetConnect[A-Z]?|HttpOpenRequest[A-Z]?|InternetReadFile)\b"),
    "winhttp": re.compile(r"(?i)\b(?:WinHttpOpen|WinHttpConnect|WinHttpSendRequest|WinHttpReceiveResponse)\b"),
    "urlmon": re.compile(r"(?i)\b(?:URLDownloadToFile[A-Z]?|URLDownloadToCacheFile[A-Z]?)\b"),
    "sockets": re.compile(r"(?i)\b(?:WSAStartup|socket|connect|send|recv|bind|listen|accept)\b"),
    "webclient": re.compile(r"(?i)\b(?:WebClient|DownloadString|DownloadFile|DownloadData)\b"),
    "powershell_web": re.compile(r"(?i)\b(?:Invoke-WebRequest|Invoke-RestMethod|iwr|irm|wget|curl)\b"),
    "xmlhttp": re.compile(r"(?i)\b(?:MSXML2\.XMLHTTP|Microsoft\.XMLHTTP|WinHttp\.WinHttpRequest|ServerXMLHTTP)\b"),
    "dns_resolution": re.compile(r"(?i)\b(?:gethostbyname|getaddrinfo|Resolve-DnsName)\b"),
    "bitsadmin": re.compile(r"(?i)\b(?:bitsadmin|Start-BitsTransfer)\b"),
}

NET_CATEGORIES = {
    "http_requests": ["wininet", "winhttp", "xmlhttp", "webclient", "powershell_web"],
    "raw_sockets": ["sockets"],
    "downloads": ["urlmon", "bitsadmin", "webclient", "powershell_web"],
    "dns": ["dns_resolution"],
}

def extract_network_feature_vector(source: Union[str, bytes, bytearray]) -> dict[str, float]:
    if isinstance(source, (bytes, bytearray)):
        text = source.decode("utf-8", errors="ignore")
    else:
        text = str(source)
    
    text = text[:MAX_CHARS]
    
    f = {
        "network_source_size": float(len(text)),
    }
    
    indicator_counts = {}
    for ind, pattern in NET_INDICATORS.items():
        count = float(len(pattern.findall(text)))
        indicator_counts[ind] = count
        f[f"network_indicator_{ind}"] = 1.0 if count > 0 else 0.0
        f[f"network_indicator_{ind}_count"] = count

    for cat, inds in NET_CATEGORIES.items():
        count = sum(indicator_counts[ind] for ind in inds)
        f[f"network_category_{cat}"] = 1.0 if count > 0 else 0.0
        f[f"network_category_{cat}_count"] = count

    f["network_evidence_count"] = float(sum(indicator_counts.values()))
    f["network_indicator_count"] = float(sum(1 for v in indicator_counts.values() if v > 0))
    f["network_category_count"] = float(sum(1 for k, v in f.items() if k.startswith("network_category_") and not k.endswith("_count") and v > 0))
    
    return f

def extract_network_features(source: Any, **kwargs: Any) -> dict[str, Any]:
    return {"feature_vector": extract_network_feature_vector(source)}

def extract_feature_vector(source: Any, **kwargs: Any) -> dict[str, float]:
    return extract_network_feature_vector(source)

__all__ = ["extract_network_feature_vector", "extract_network_features", "extract_feature_vector"]
