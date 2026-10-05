"""
Lightweight PowerShell feature extraction for Pharos CDR.

Extracts scalar ML features directly from script source without heavy AST parsing.
"""

from __future__ import annotations

import re
from typing import Any, Union

MAX_CHARS = 1024 * 1024

PS_INDICATORS = {
    "invoke_expression": re.compile(r"(?i)\b(?:Invoke-Expression|IEX)\b"),
    "download_string": re.compile(r"(?i)\b(?:DownloadString|DownloadFile)\b"),
    "invoke_webrequest": re.compile(r"(?i)\b(?:Invoke-WebRequest|iwr|wget|curl)\b"),
    "webclient": re.compile(r"(?i)\b(?:Net\.WebClient|System\.Net\.WebClient)\b"),
    "encoded_command": re.compile(r"(?i)(?:-enc|-encodedcommand|-e)\s+[a-zA-Z0-9+/=]{10,}"),
    "execution_policy_bypass": re.compile(r"(?i)(?:-exec|-executionpolicy)\s+(?:bypass|unrestricted)"),
    "hidden_window": re.compile(r"(?i)(?:-w|-windowstyle)\s+hidden"),
    "non_interactive": re.compile(r"(?i)-noni(?:nteractive)?"),
    "no_profile": re.compile(r"(?i)-nop(?:rofile)?"),
    "start_process": re.compile(r"(?i)\b(?:Start-Process|saps)\b"),
    "reflection": re.compile(r"(?i)\b(?:Reflection\.Assembly|LoadWithPartialName|\[Reflection\.Assembly\]::Load)\b"),
    "wmi_object": re.compile(r"(?i)\b(?:Get-WmiObject|gwmi|Invoke-WmiMethod|iwmi)\b"),
    "amsi_bypass": re.compile(r"(?i)\b(?:AmsiUtils|amsiInitFailed|DisableRealtimeMonitoring)\b"),
    "registry_modification": re.compile(r"(?i)\b(?:Set-ItemProperty|New-ItemProperty|Remove-ItemProperty)\b"),
    "scheduled_task": re.compile(r"(?i)\b(?:Register-ScheduledTask|New-ScheduledTaskAction|schtasks)\b"),
    "format_string_obfuscation": re.compile(r"(?i)(?:-f\s+['\"]|['\"].*?\{[0-9]+\}.*?['\"]\s*-f)"),
    "char_obfuscation": re.compile(r"(?im)(?:\[\s*char\s*\]\s*|\b(?:char|charw)\s*\()\s*[0-9A-Fx]"),
    "secure_string": re.compile(r"(?i)\bConvertTo-SecureString\b"),
}

PS_CATEGORIES = {
    "dynamic_execution": ["invoke_expression", "reflection"],
    "download": ["download_string", "invoke_webrequest", "webclient"],
    "evasion": ["encoded_command", "execution_policy_bypass", "hidden_window", "amsi_bypass", "format_string_obfuscation", "char_obfuscation"],
    "process": ["start_process", "wmi_object"],
    "persistence": ["registry_modification", "scheduled_task"],
}

def extract_powershell_feature_vector(source: Union[str, bytes, bytearray]) -> dict[str, float]:
    if isinstance(source, (bytes, bytearray)):
        text = source.decode("utf-8", errors="ignore")
    else:
        text = str(source)
        
    text = text[:MAX_CHARS]
    
    f = {
        "powershell_source_size": float(len(text)),
        "powershell_line_count": float(len(text.splitlines())),
    }
    
    # Token extraction
    f["powershell_command_count"] = float(len(re.findall(r"(?i)\b(?:Invoke|Get|Set|New|Remove|Start|Stop|Add|Out|Write)-[a-z]+\b", text)))
    f["powershell_function_count"] = float(len(re.findall(r"(?im)^\s*(?:function|filter)\s+[a-z_][a-z0-9_.-]*", text)))
    f["powershell_alias_count"] = float(len(re.findall(r"(?i)\b(?:Set-Alias|New-Alias)\b", text)))
    f["powershell_parameter_count"] = float(len(re.findall(r"(?im)(?<![\w-])-[a-z][a-z0-9-]*", text)))
    f["powershell_variable_count"] = float(len(re.findall(r"(?<![\w])\$[a-z_][a-z0-9_]*", text)))
    
    urls = re.findall(r"(?i)https?://[^\s\"'`]+", text)
    f["powershell_url_count"] = float(len(urls))
    f["powershell_ipv4_count"] = float(len(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)))
    f["powershell_windows_path_count"] = float(len(re.findall(r"(?i)[a-z]:\\[^\s\"'`]+", text)))
    f["powershell_registry_path_count"] = float(len(re.findall(r"(?i)\b(?:HKLM|HKCU|HKCR|HKU|HKCC):[\\/]", text)))
    
    strings = re.findall(r"'(?:''|[^'])*'|\"(?:\"\"|`.|[^\"`])*\"", text)
    f["powershell_string_count"] = float(len(strings))
    lengths = [len(s) for s in strings]
    f["powershell_string_total_length"] = float(sum(lengths))
    f["powershell_string_max_length"] = float(max(lengths) if lengths else 0)
    f["powershell_string_mean_entropy"] = 0.0 # Skipping slow entropy
    
    f["powershell_base64_string_count"] = float(len([s for s in strings if len(s) > 40 and re.match(r"^[A-Za-z0-9+/]+={0,2}$", s.strip("'\""))]))
    f["powershell_hex_string_count"] = float(len([s for s in strings if len(s) > 32 and re.match(r"^[0-9A-Fa-f]+$", s.strip("'\""))]))
    
    f["powershell_base64_token_count"] = float(len(re.findall(r"(?<![a-zA-Z0-9+/=])[a-zA-Z0-9+/]{40,}={0,2}(?![a-zA-Z0-9+/=])", text)))
    f["powershell_hex_token_count"] = float(len(re.findall(r"(?i)(?<![0-9a-f])(?:[0-9a-f]{2}){16,}(?![0-9a-f])", text)))

    indicator_counts = {}
    for ind, pattern in PS_INDICATORS.items():
        count = float(len(pattern.findall(text)))
        indicator_counts[ind] = count
        f[f"powershell_indicator_{ind}"] = 1.0 if count > 0 else 0.0
        f[f"powershell_indicator_{ind}_count"] = count

    for cat, inds in PS_CATEGORIES.items():
        count = sum(indicator_counts[ind] for ind in inds)
        f[f"powershell_category_{cat}"] = 1.0 if count > 0 else 0.0
        f[f"powershell_category_{cat}_count"] = count
        
    f["powershell_indicator_count"] = float(sum(1 for v in indicator_counts.values() if v > 0))
    f["powershell_combination_count"] = 0.0
    f["powershell_present_combination_count"] = 0.0
    f["powershell_combination_download_execute"] = 1.0 if f.get("powershell_category_download") and f.get("powershell_category_dynamic_execution") else 0.0
    f["powershell_combination_encoded_hidden"] = 1.0 if indicator_counts.get("encoded_command") and indicator_counts.get("hidden_window") else 0.0
        
    return f

def extract_powershell_features(source: Union[str, bytes, bytearray]) -> dict[str, Any]:
    return {"feature_vector": extract_powershell_feature_vector(source)}

def extract_feature_vector(source: Union[str, bytes, bytearray]) -> dict[str, float]:
    return extract_powershell_feature_vector(source)

__all__ = ["extract_powershell_feature_vector", "extract_powershell_features", "extract_feature_vector"]
