"""
Lightweight evasion behavior feature extraction for Pharos CDR.

Extracts scalar ML features directly from input text via heuristic static scanning.
"""

from __future__ import annotations

import re
from typing import Any, Union

MAX_CHARS = 1024 * 1024

EVASION_INDICATORS = {
    "anti_debugging": re.compile(r"(?i)\b(?:IsDebuggerPresent|CheckRemoteDebuggerPresent|OutputDebugString|NtQueryInformationProcess)\b"),
    "anti_vm": re.compile(r"(?i)\b(?:vmtoolsd|vboxservice|vmware|virtualbox|hyper-v|qemu|cpuid)\b"),
    "anti_sandbox": re.compile(r"(?i)\b(?:sbiedll|dirwatch|api_log|cuckoo|sandboxie)\b"),
    "time_delay": re.compile(r"(?i)\b(?:Sleep|GetTickCount|QueryPerformanceCounter|Start-Sleep|WaitForSingleObject)\b"),
    "security_disable": re.compile(r"(?i)\b(?:DisableRealtimeMonitoring|DisableBehaviorMonitoring|DisableOnAccessProtection)\b"),
    "amsi_bypass": re.compile(r"(?i)\b(?:AmsiScanBuffer|AmsiInitialize|AmsiUtils|amsiInitFailed)\b"),
    "etw_bypass": re.compile(r"(?i)\b(?:EtwEventWrite|NtTraceEvent)\b"),
}

EVASION_CATEGORIES = {
    "anti_debugging": ["anti_debugging"],
    "anti_vm": ["anti_vm"],
    "anti_sandbox": ["anti_sandbox"],
    "timing": ["time_delay"],
    "defense_impairment": ["security_disable", "amsi_bypass", "etw_bypass"],
}

def extract_evasion_feature_vector(source: Union[str, bytes, bytearray]) -> dict[str, float]:
    if isinstance(source, (bytes, bytearray)):
        text = source.decode("utf-8", errors="ignore")
    else:
        text = str(source)
    
    text = text[:MAX_CHARS]
    
    f = {
        "evasion_source_size": float(len(text)),
    }
    
    indicator_counts = {}
    for ind, pattern in EVASION_INDICATORS.items():
        count = float(len(pattern.findall(text)))
        indicator_counts[ind] = count
        f[f"evasion_indicator_{ind}"] = 1.0 if count > 0 else 0.0
        f[f"evasion_indicator_{ind}_count"] = count

    for cat, inds in EVASION_CATEGORIES.items():
        count = sum(indicator_counts[ind] for ind in inds)
        f[f"evasion_category_{cat}"] = 1.0 if count > 0 else 0.0
        f[f"evasion_category_{cat}_count"] = count

    f["evasion_evidence_count"] = float(sum(indicator_counts.values()))
    f["evasion_indicator_count"] = float(sum(1 for v in indicator_counts.values() if v > 0))
    f["evasion_category_count"] = float(sum(1 for k, v in f.items() if k.startswith("evasion_category_") and not k.endswith("_count") and v > 0))
    
    return f

def extract_evasion_features(source: Any, **kwargs: Any) -> dict[str, Any]:
    return {"feature_vector": extract_evasion_feature_vector(source)}

def extract_feature_vector(source: Any, **kwargs: Any) -> dict[str, float]:
    return extract_evasion_feature_vector(source)

__all__ = ["extract_evasion_feature_vector", "extract_evasion_features", "extract_feature_vector"]
