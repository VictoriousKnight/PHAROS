"""
Lightweight process behavior feature extraction for Pharos CDR.

Extracts scalar ML features directly from input text via heuristic static scanning.
"""

from __future__ import annotations

import re
from typing import Any, Union

MAX_CHARS = 1024 * 1024

PROCESS_INDICATORS = {
    "create_process": re.compile(r"(?i)\b(?:CreateProcess[A-Z]?|WinExec|ShellExecute[A-Z]?|Start-Process)\b"),
    "wmi_process": re.compile(r"(?i)\b(?:Win32_Process|Win32_ProcessStartup)\b"),
    "process_injection": re.compile(r"(?i)\b(?:VirtualAllocEx|WriteProcessMemory|CreateRemoteThread|QueueUserAPC)\b"),
    "process_hollowing": re.compile(r"(?i)\b(?:ZwUnmapViewOfSection|NtUnmapViewOfSection|SetThreadContext)\b"),
    "process_enumeration": re.compile(r"(?i)\b(?:CreateToolhelp32Snapshot|Process32First|Process32Next|EnumProcesses)\b"),
    "terminate_process": re.compile(r"(?i)\b(?:TerminateProcess|ExitProcess|TaskKill|Stop-Process)\b"),
    "lolbin_execution": re.compile(r"(?i)\b(?:mshta|rundll32|regsvr32|certutil|bitsadmin|wmic|csc|installutil|msiexec)\.exe\b"),
    "script_host": re.compile(r"(?i)\b(?:cscript|wscript|powershell|pwsh|cmd)\.exe\b"),
    "process_token": re.compile(r"(?i)\b(?:OpenProcessToken|DuplicateToken|AdjustTokenPrivileges)\b"),
    "process_handle": re.compile(r"(?i)\b(?:OpenProcess|DuplicateHandle)\b"),
}

PROCESS_CATEGORIES = {
    "creation": ["create_process", "wmi_process", "lolbin_execution", "script_host"],
    "injection": ["process_injection", "process_hollowing"],
    "discovery": ["process_enumeration"],
    "termination": ["terminate_process"],
    "access": ["process_handle", "process_token"],
}

def extract_process_feature_vector(source: Union[str, bytes, bytearray]) -> dict[str, float]:
    if isinstance(source, (bytes, bytearray)):
        text = source.decode("utf-8", errors="ignore")
    else:
        text = str(source)
    
    text = text[:MAX_CHARS]
    
    f = {
        "process_source_size": float(len(text)),
    }
    
    indicator_counts = {}
    for ind, pattern in PROCESS_INDICATORS.items():
        count = float(len(pattern.findall(text)))
        indicator_counts[ind] = count
        f[f"process_indicator_{ind}"] = 1.0 if count > 0 else 0.0
        f[f"process_indicator_{ind}_count"] = count

    for cat, inds in PROCESS_CATEGORIES.items():
        count = sum(indicator_counts[ind] for ind in inds)
        f[f"process_category_{cat}"] = 1.0 if count > 0 else 0.0
        f[f"process_category_{cat}_count"] = count

    f["process_evidence_count"] = float(sum(indicator_counts.values()))
    f["process_indicator_count"] = float(sum(1 for v in indicator_counts.values() if v > 0))
    f["process_category_count"] = float(sum(1 for k, v in f.items() if k.startswith("process_category_") and not k.endswith("_count") and v > 0))
    f["process_shell_process_count"] = indicator_counts["script_host"]
    f["process_lolbin_count"] = indicator_counts["lolbin_execution"]
    
    return f

def extract_process_features(source: Any, **kwargs: Any) -> dict[str, Any]:
    return {"feature_vector": extract_process_feature_vector(source)}

def extract_feature_vector(source: Any, **kwargs: Any) -> dict[str, float]:
    return extract_process_feature_vector(source)

__all__ = ["extract_process_feature_vector", "extract_process_features", "extract_feature_vector"]
