"""
Lightweight communication capabilities extraction for Pharos CDR.

Extracts scalar ML features directly from input text via heuristic static scanning.
"""

from __future__ import annotations

import re
from typing import Any, Union, Mapping

MAX_CHARS = 1024 * 1024

COMM_INDICATORS = {
    "http_client": re.compile(r"(?i)\b(?:MSXML2\.XMLHTTP|WinHttp\.WinHttpRequest|System\.Net\.WebClient|Invoke-WebRequest)\b"),
    "ftp_client": re.compile(r"(?i)\b(?:ftp\.exe|System\.Net\.FtpWebRequest)\b"),
    "smtp_client": re.compile(r"(?i)\b(?:System\.Net\.Mail\.SmtpClient|CDO\.Message)\b"),
    "raw_socket": re.compile(r"(?i)\b(?:System\.Net\.Sockets|WSAStartup|socket|connect|bind|listen)\b"),
    "pipe_comm": re.compile(r"(?i)\b(?:CreateNamedPipe|ConnectNamedPipe|CallNamedPipe)\b"),
    "rpc_comm": re.compile(r"(?i)\b(?:RpcBindingFromStringBinding|RpcStringBindingCompose)\b"),
    "dns_comm": re.compile(r"(?i)\b(?:Resolve-DnsName|nslookup|gethostbyname)\b"),
}

COMM_CATEGORIES = {
    "web_protocols": ["http_client", "ftp_client"],
    "mail_protocols": ["smtp_client"],
    "low_level_network": ["raw_socket", "dns_comm"],
    "ipc": ["pipe_comm", "rpc_comm"],
}

def _vectorize(f: dict[str, float]) -> list[float]:
    keys = sorted(f.keys())
    return [f[k] for k in keys]

def extract_communication_feature_vector(source: Union[str, bytes, bytearray], **kwargs: Any) -> list[float]:
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
    for ind, pattern in COMM_INDICATORS.items():
        count = float(len(pattern.findall(text)))
        indicator_counts[ind] = count
        f[f"indicator_present__{ind}"] = 1.0 if count > 0 else 0.0
        f[f"indicator_count__{ind}"] = count

    for cat, inds in COMM_CATEGORIES.items():
        count = sum(indicator_counts[ind] for ind in inds)
        f[f"category_present__{cat}"] = 1.0 if count > 0 else 0.0
        f[f"category_count__{cat}"] = count

    f["evidence_count"] = float(sum(indicator_counts.values()))
    f["indicator_count"] = float(sum(1 for v in indicator_counts.values() if v > 0))
    f["category_count"] = float(sum(1 for k, v in f.items() if k.startswith("category_present__") and v > 0))

    return _vectorize(f)

def extract_communication_features(source: Any, **kwargs: Any) -> dict[str, Any]:
    class AnalysisEmulator:
        def __init__(self, vec):
            self.feature_vector = vec
    return AnalysisEmulator(extract_communication_feature_vector(source))

def extract_feature_vector(source: Any, **kwargs: Any) -> list[float]:
    return extract_communication_feature_vector(source)

def vectorize_features(features: Mapping[str, object]) -> list[float]:
    return _vectorize({k: float(v) for k, v in features.items()})

__all__ = ["extract_communication_feature_vector", "extract_communication_features", "extract_feature_vector", "vectorize_features"]