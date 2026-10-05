"""
Lightweight VBA API extraction for Pharos CDR.

Extracts scalar ML features for VBA API declarations and invocations.
"""

from __future__ import annotations

import re
from typing import Any, Union

MAX_CHARS = 1024 * 1024

API_CATEGORIES = {
    "process_creation": re.compile(r"(?i)\b(?:CreateProcess|WinExec|ShellExecute|ShellExecuteEx)\b"),
    "memory_injection": re.compile(r"(?i)\b(?:VirtualAlloc|VirtualAllocEx|VirtualProtect|WriteProcessMemory|CreateRemoteThread)\b"),
    "download": re.compile(r"(?i)\b(?:URLDownloadToFile|InternetOpenUrl|InternetReadFile)\b"),
    "registry": re.compile(r"(?i)\b(?:RegOpenKey|RegCreateKey|RegSetValue)\b"),
    "evasion": re.compile(r"(?i)\b(?:IsDebuggerPresent|CheckRemoteDebuggerPresent|Sleep)\b"),
}

DLL_FAMILIES = {
    "kernel32": re.compile(r"(?i)\bkernel32\.dll\b"),
    "user32": re.compile(r"(?i)\buser32\.dll\b"),
    "advapi32": re.compile(r"(?i)\badvapi32\.dll\b"),
    "shell32": re.compile(r"(?i)\bshell32\.dll\b"),
    "urlmon": re.compile(r"(?i)\burlmon\.dll\b"),
    "wininet": re.compile(r"(?i)\bwininet\.dll\b"),
    "ntdll": re.compile(r"(?i)\bntdll\.dll\b"),
}

DECLARE_RE = re.compile(r"(?i)\bDeclare\s+(?:PtrSafe\s+)?(?:Function|Sub)\s+([A-Za-z0-9_]+)\b")
CALL_RE = re.compile(r"(?i)\bCall\s+([A-Za-z0-9_]+)\b")

def extract_api_feature_vector(source: Union[str, bytes, bytearray]) -> dict[str, float]:
    if isinstance(source, (bytes, bytearray)):
        text = source.decode("utf-8", errors="ignore")
    else:
        text = str(source)
    
    text = text[:MAX_CHARS]
    f = {}
    
    declares = DECLARE_RE.findall(text)
    f["vba_api_declaration_count"] = float(len(declares))
    f["vba_api_declared_unique_count"] = float(len(set(d.lower() for d in declares)))
    
    calls = CALL_RE.findall(text)
    f["vba_api_call_count"] = float(len(calls))
    f["vba_api_unique_count"] = float(len(set(c.lower() for c in calls)))
    
    for cat, pattern in API_CATEGORIES.items():
        count = float(len(pattern.findall(text)))
        f[f"vba_api_{cat}_count"] = count
        f[f"vba_api_has_{cat}"] = 1.0 if count > 0 else 0.0
        
    for dll, pattern in DLL_FAMILIES.items():
        count = float(len(pattern.findall(text)))
        f[f"vba_api_library_{dll}"] = 1.0 if count > 0 else 0.0

    return f

def extract_api_features(source: Union[str, bytes, bytearray]) -> dict[str, Any]:
    return {"feature_vector": extract_api_feature_vector(source)}

def extract_feature_vector(source: Union[str, bytes, bytearray]) -> dict[str, float]:
    return extract_api_feature_vector(source)

__all__ = ["extract_api_feature_vector", "extract_api_features", "extract_feature_vector"]
