"""
Lightweight VBScript feature extraction for Pharos CDR.

Extracts scalar ML features directly from script source via fast regex scanning.
"""

from __future__ import annotations

import re
from typing import Any, Union

MAX_CHARS = 1024 * 1024

VBS_INDICATORS = {
    "eval_execution": re.compile(r"(?i)\b(?:Eval|Execute|ExecuteGlobal)\s*\("),
    "wscript_shell": re.compile(r"(?i)\bWScript\.Shell\b"),
    "wscript_network": re.compile(r"(?i)\bWScript\.Network\b"),
    "filesystem_object": re.compile(r"(?i)\bScripting\.FileSystemObject\b"),
    "shell_application": re.compile(r"(?i)\bShell\.Application\b"),
    "activex_creation": re.compile(r"(?i)\b(?:CreateObject|GetObject)\s*\("),
    "wmi_object": re.compile(r"(?i)\bwinmgmts:\b|\bWbemScripting\.SWbemLocator\b"),
    "xmlhttp_object": re.compile(r"(?i)\b(?:MSXML2\.XMLHTTP|Microsoft\.XMLHTTP|WinHttp\.WinHttpRequest|ServerXMLHTTP)\b"),
    "adodb_stream": re.compile(r"(?i)\bADODB\.Stream\b"),
    "document_write": re.compile(r"(?i)\bdocument\.write\b"),
    "char_encoding": re.compile(r"(?i)\b(?:Chr|ChrW|ChrB)\s*\("),
    "unescape": re.compile(r"(?i)\bunescape\s*\("),
    "array_manipulation": re.compile(r"(?i)\b(?:Split|Join|Filter|Replace)\b"),
    "string_reversal": re.compile(r"(?i)\bStrReverse\s*\("),
    "math_random": re.compile(r"(?i)\bRnd\s*\("),
    "bitwise_operations": re.compile(r"(?i)\b(?:And|Or|Xor|Not|Eqv|Imp)\b"),
    "hex_encoding": re.compile(r"(?i)\bHex\s*\("),
    "long_string_concatenation": re.compile(r"(?:(?:'|\")[^\n\r'\"]*(?:'|\")\s*&\s*){5,}"),
    "error_suppression": re.compile(r"(?i)\bOn\s+Error\s+Resume\s+Next\b"),
    "obfuscated_get_object": re.compile(r"(?i)\bGetObject\s*\(\s*(?:'|\")\s*(?!winmgmts).*?(?:'|\")\s*\)"),
    "registry_operations": re.compile(r"(?i)\b(?:RegRead|RegWrite|RegDelete)\b"),
}

VBS_CATEGORIES = {
    "execution": ["eval_execution"],
    "com_automation": ["wscript_shell", "wscript_network", "filesystem_object", "shell_application", "activex_creation", "wmi_object", "xmlhttp_object", "adodb_stream"],
    "obfuscation": ["char_encoding", "unescape", "array_manipulation", "string_reversal", "math_random", "bitwise_operations", "hex_encoding", "long_string_concatenation", "obfuscated_get_object"],
    "evasion": ["error_suppression"],
    "persistence": ["registry_operations"],
}

def extract_vbscript_feature_vector(source: Union[str, bytes, bytearray]) -> dict[str, float]:
    if isinstance(source, (bytes, bytearray)):
        text = source.decode("utf-8", errors="ignore")
    else:
        text = str(source)
        
    text = text[:MAX_CHARS]
    
    f = {
        "vbscript_schema_version": 1.0,
    }
    
    lines = text.splitlines()
    f["vbscript_line_count"] = float(len(lines))
    f["vbscript_source_size_bytes"] = float(len(text))
    
    strings = re.findall(r'"([^"\\]*(?:\\.[^"\\]*)*)"', text)
    f["vbscript_string_count"] = float(len(strings))
    lengths = [len(s) for s in strings]
    f["vbscript_total_string_characters"] = float(sum(lengths))
    f["vbscript_max_string_length"] = float(max(lengths) if lengths else 0)
    f["vbscript_mean_string_length"] = float(sum(lengths) / len(lengths) if lengths else 0.0)
    
    f["vbscript_base64_like_string_count"] = sum(1.0 for s in strings if len(s) > 16 and re.match(r"^[A-Za-z0-9+/]+={0,2}$", s))
    f["vbscript_hex_like_string_count"] = sum(1.0 for s in strings if len(s) > 8 and re.match(r"^(?:[0-9A-Fa-f]{2})+$", s))
    
    identifiers = set(re.findall(r"(?i)\b[A-Za-z_][A-Za-z0-9_]*\b", text))
    f["vbscript_identifier_count"] = float(len(identifiers))
    
    f["vbscript_function_count"] = float(len(re.findall(r"(?i)\b(?:Function|Sub)\s+[A-Za-z_]", text)))
    f["vbscript_activex_object_count"] = float(len(VBS_INDICATORS["activex_creation"].findall(text)))
    f["vbscript_url_count"] = float(len(re.findall(r"(?i)https?://[^\s\"']+", text)))

    indicator_counts = {}
    for ind, pattern in VBS_INDICATORS.items():
        count = float(len(pattern.findall(text)))
        indicator_counts[ind] = count
        f[f"vbscript_indicator_{ind}"] = 1.0 if count > 0 else 0.0
        f[f"vbscript_indicator_{ind}_count"] = count

    for cat, inds in VBS_CATEGORIES.items():
        count = sum(indicator_counts[ind] for ind in inds)
        f[f"vbscript_category_{cat}"] = 1.0 if count > 0 else 0.0
        f[f"vbscript_category_{cat}_count"] = count
        
    return f

def extract_vbscript_features(source: Union[str, bytes, bytearray]) -> dict[str, Any]:
    return {"feature_vector": extract_vbscript_feature_vector(source)}

def extract_feature_vector(source: Union[str, bytes, bytearray]) -> dict[str, float]:
    return extract_vbscript_feature_vector(source)

__all__ = ["extract_vbscript_feature_vector", "extract_vbscript_features", "extract_feature_vector"]
