"""
Lightweight Javascript extraction for Pharos CDR.

Extracts scalar ML features for JavaScript/JScript analysis.
"""

from __future__ import annotations

import re
from typing import Any, Union

MAX_CHARS = 1024 * 1024

JS_INDICATORS = {
    "eval_execution": re.compile(r"(?i)\beval\s*\("),
    "function_constructor": re.compile(r"(?i)\bFunction\s*\("),
    "timeout_execution": re.compile(r"(?i)\b(?:setTimeout|setInterval)\b"),
    "activex_creation": re.compile(r"(?i)\b(?:ActiveXObject|CreateObject|GetObject)\b"),
    "wscript_shell": re.compile(r"(?i)\bWScript\.Shell\b"),
    "wscript_network": re.compile(r"(?i)\bWScript\.Network\b"),
    "filesystem_object": re.compile(r"(?i)\bScripting\.FileSystemObject\b"),
    "shell_application": re.compile(r"(?i)\bShell\.Application\b"),
    "winmgmts": re.compile(r"(?i)winmgmts:"),
    "xmlhttp": re.compile(r"(?i)\b(?:MSXML2\.XMLHTTP|Microsoft\.XMLHTTP|WinHttp\.WinHttpRequest)\b"),
    "adodb_stream": re.compile(r"(?i)\bADODB\.Stream\b"),
    "document_write": re.compile(r"(?i)\bdocument\.write\b"),
    "string_fromCharCode": re.compile(r"(?i)\bString\.fromCharCode\b"),
    "unescape": re.compile(r"(?i)\b(?:unescape|decodeURI|decodeURIComponent)\b"),
    "base64_decode": re.compile(r"(?i)\b(?:atob|btoa)\b"),
    "array_manipulation": re.compile(r"(?i)\b(?:split|join|reverse|slice|splice)\b"),
    "math_random": re.compile(r"(?i)\bMath\.random\b"),
    "bitwise_operations": re.compile(r"(?:<<|>>|>>>|&|\||\^|~)"),
    "hex_encoding": re.compile(r"\\x[0-9a-fA-F]{2}"),
    "unicode_encoding": re.compile(r"\\u[0-9a-fA-F]{4}"),
    "long_string_concatenation": re.compile(r"(?:(?:'|\")[^\n\r'\"]*(?:'|\")\s*\+\s*){5,}"),
    "arguments_callee": re.compile(r"(?i)\barguments\.callee\b"),
    "try_catch": re.compile(r"(?i)\btry\b\s*\{.*?\bcatch\b"),
    "obfuscated_property_access": re.compile(r"(?i)\[\s*(?:'|\")\s*(?:[A-Za-z0-9_]+)\s*(?:'|\")\s*\]"),
}

JS_CATEGORIES = {
    "execution": ["eval_execution", "function_constructor", "timeout_execution", "document_write"],
    "com_automation": ["activex_creation", "wscript_shell", "wscript_network", "filesystem_object", "shell_application", "winmgmts", "xmlhttp", "adodb_stream"],
    "obfuscation": ["string_fromCharCode", "unescape", "base64_decode", "array_manipulation", "math_random", "bitwise_operations", "hex_encoding", "unicode_encoding", "long_string_concatenation", "arguments_callee", "obfuscated_property_access"],
    "evasion": ["try_catch"],
}

def extract_javascript_feature_vector(source: Union[str, bytes, bytearray]) -> dict[str, float]:
    if isinstance(source, (bytes, bytearray)):
        text = source.decode("utf-8", errors="ignore")
    else:
        text = str(source)
        
    text = text[:MAX_CHARS]
    f = {
        "javascript_schema_version": 1.0,
        "javascript_function_count": 0.0,
        "javascript_activex_object_count": 0.0,
        "javascript_url_count": 0.0,
        "javascript_identifier_count": 0.0,
    }
    
    # Text stats
    lines = text.splitlines()
    f["javascript_line_count"] = float(len(lines))
    f["javascript_source_size_bytes"] = float(len(text))
    
    # Strings
    strings = re.findall(r'"([^"\\]*(?:\\.[^"\\]*)*)"|\'([^\'\\]*(?:\\.[^\'\\]*)*)\'', text)
    str_vals = [s[0] or s[1] for s in strings]
    f["javascript_string_count"] = float(len(str_vals))
    lengths = [len(s) for s in str_vals]
    f["javascript_total_string_characters"] = float(sum(lengths))
    f["javascript_max_string_length"] = float(max(lengths) if lengths else 0)
    f["javascript_mean_string_length"] = float(sum(lengths) / len(lengths) if lengths else 0.0)
    
    f["javascript_base64_like_string_count"] = sum(1.0 for s in str_vals if len(s) > 16 and re.match(r"^[A-Za-z0-9+/]+={0,2}$", s))
    f["javascript_hex_like_string_count"] = sum(1.0 for s in str_vals if len(s) > 8 and re.match(r"^(?:[0-9A-Fa-f]{2})+$", s))
    
    # Identifiers
    identifiers = set(re.findall(r"\b[A-Za-z_$][A-Za-z0-9_$]*\b", text))
    f["javascript_identifier_count"] = float(len(identifiers))
    
    f["javascript_function_count"] = float(len(re.findall(r"(?i)\bfunction\s+(?:[A-Za-z_$][A-Za-z0-9_$]*)?\s*\(", text)))
    f["javascript_activex_object_count"] = float(len(JS_INDICATORS["activex_creation"].findall(text)))
    f["javascript_url_count"] = float(len(re.findall(r"(?i)https?://[^\s\"']+", text)))

    # Indicators & Categories
    indicator_counts = {}
    for ind, pattern in JS_INDICATORS.items():
        count = float(len(pattern.findall(text)))
        indicator_counts[ind] = count
        f[f"javascript_indicator_{ind}"] = 1.0 if count > 0 else 0.0
        f[f"javascript_indicator_{ind}_count"] = count

    for cat, inds in JS_CATEGORIES.items():
        count = sum(indicator_counts[ind] for ind in inds)
        f[f"javascript_category_{cat}"] = 1.0 if count > 0 else 0.0
        f[f"javascript_category_{cat}_count"] = count
        
    return f

def extract_javascript_features(source: Union[str, bytes, bytearray]) -> dict[str, Any]:
    return {"feature_vector": extract_javascript_feature_vector(source)}

def extract_feature_vector(source: Union[str, bytes, bytearray]) -> dict[str, float]:
    return extract_javascript_feature_vector(source)

__all__ = ["extract_javascript_feature_vector", "extract_javascript_features", "extract_feature_vector"]
