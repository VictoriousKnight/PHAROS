"""
Lightweight VBA parser for Pharos CDR.

Extracts scalar ML features from VBA source code via regex-based static analysis.
"""

from __future__ import annotations

import re
from typing import Any, Union

MAX_CHARS = 1024 * 1024

# ---------------------------------------------------------------------------
# Regex patterns for structural counting
# ---------------------------------------------------------------------------

PROCEDURE_RE = re.compile(r"(?im)^\s*(?:Public\s+|Private\s+)?(?:Sub|Function|Property\s+(?:Get|Let|Set))\s+([A-Za-z_]\w*)")
API_DECLARE_RE = re.compile(r"(?i)\bDeclare\s+(?:PtrSafe\s+)?(?:Function|Sub)\s+(\w+).*?\bLib\s+\"([^\"]+)\"(?:.*?\bAlias\s+\"(\w+)\")?")
CALL_RE = re.compile(r"(?i)\b(?:Call\s+)?([A-Za-z_]\w*)\s*\(")
STRING_RE = re.compile(r'"([^"]*(?:""[^"]*)*)"')
COMMENT_RE = re.compile(r"(?m)^\s*'.*$|(?m)^\s*Rem\s.*$")
BLANK_RE = re.compile(r"(?m)^\s*$")
CONTINUATION_RE = re.compile(r"_\s*$", re.MULTILINE)
URL_RE = re.compile(r"(?i)https?://[^\s\"']+")
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
PATH_RE = re.compile(r'(?i)[A-Z]:\\[^\s"\']+')
OPTION_EXPLICIT_RE = re.compile(r"(?im)^\s*Option\s+Explicit\b")
OPTION_BASE_RE = re.compile(r"(?im)^\s*Option\s+Base\b")
GOTO_RE = re.compile(r"(?i)\bGoTo\b")
ERROR_HANDLER_RE = re.compile(r"(?i)\bOn\s+Error\b")
DIM_RE = re.compile(r"(?im)^\s*(?:Dim|Public|Private|Global|Static)\s+")

# Indicator patterns
COM_RE = re.compile(r"(?i)\bCreateObject\b")
SHELL_RE = re.compile(r"(?i)\bShell\b")
MACRO_EXEC_RE = re.compile(r"(?i)\bApplication\.Run\b")
ERROR_SUPPRESS_RE = re.compile(r"(?i)\bOn\s+Error\s+Resume\s+Next\b")
NETWORK_RE = re.compile(r"(?i)\b(?:XMLHTTP|WinHttp|InternetOpen|URLDownload|WebClient)\b")
REGISTRY_RE = re.compile(r"(?i)\b(?:RegOpenKey|RegCreateKey|RegSetValue|RegRead|RegWrite)\b")

# High-value API patterns (mapped to feature names)
HIGH_VALUE_APIS = {
    "process_creation": re.compile(r"(?i)\b(?:CreateProcess[AW]?|WinExec)\b"),
    "shell_execution": re.compile(r"(?i)\b(?:ShellExecute[AW]?|ShellExecuteEx[AW]?)\b"),
    "memory_allocation": re.compile(r"(?i)\bVirtualAlloc\b"),
    "remote_memory_allocation": re.compile(r"(?i)\bVirtualAllocEx\b"),
    "memory_protection": re.compile(r"(?i)\bVirtualProtect\b"),
    "remote_memory_protection": re.compile(r"(?i)\bVirtualProtectEx\b"),
    "remote_memory_write": re.compile(r"(?i)\bWriteProcessMemory\b"),
    "remote_thread": re.compile(r"(?i)\bCreateRemoteThread\b"),
    "process_access": re.compile(r"(?i)\bOpenProcess\b"),
    "dynamic_api_resolution": re.compile(r"(?i)\bGetProcAddress\b"),
    "dynamic_library_loading": re.compile(r"(?i)\bLoadLibrary[AW]?\b"),
    "registry_access": re.compile(r"(?i)\bRegOpenKey(?:Ex)?[AW]?\b"),
    "registry_modification": re.compile(r"(?i)\b(?:RegCreateKey|RegSetValue)(?:Ex)?[AW]?\b"),
    "download": re.compile(r"(?i)\bURLDownloadToFile[AW]?\b"),
    "network_download": re.compile(r"(?i)\bInternetOpenUrl[AW]?\b"),
    "network": re.compile(r"(?i)\b(?:WinHttpOpen|WinHttpConnect|WinHttpSendRequest)\b"),
    "clipboard": re.compile(r"(?i)\b(?:OpenClipboard|GetClipboardData)\b"),
    "token_access": re.compile(r"(?i)\bOpenProcessToken\b"),
    "token_privilege": re.compile(r"(?i)\bAdjustTokenPrivileges\b"),
}

# Library family patterns
LIBRARY_FAMILIES = {
    "kernel32": re.compile(r"(?i)\bkernel(?:32|base)(?:\.dll)?\b"),
    "user32": re.compile(r"(?i)\buser32(?:\.dll)?\b"),
    "advapi32": re.compile(r"(?i)\badvapi32(?:\.dll)?\b"),
    "ole32": re.compile(r"(?i)\bole32(?:\.dll)?\b"),
    "oleaut32": re.compile(r"(?i)\boleaut32(?:\.dll)?\b"),
    "wininet": re.compile(r"(?i)\bwininet(?:\.dll)?\b"),
    "winhttp": re.compile(r"(?i)\bwinhttp(?:\.dll)?\b"),
    "shell32": re.compile(r"(?i)\bshell32(?:\.dll)?\b"),
    "urlmon": re.compile(r"(?i)\burlmon(?:\.dll)?\b"),
    "crypt32": re.compile(r"(?i)\bcrypt32(?:\.dll)?\b"),
}


def extract_vba_features(source: str | bytes) -> dict[str, int | float]:
    """Extract all VBA parser features from source code."""
    if isinstance(source, bytes):
        text = source.decode("utf-8", errors="ignore")
    else:
        text = str(source)

    text = text[:MAX_CHARS]
    lines = text.splitlines()
    line_count = len(lines)

    # Structural counts
    procedures = PROCEDURE_RE.findall(text)
    api_declares = API_DECLARE_RE.findall(text)
    calls = CALL_RE.findall(text)
    strings = STRING_RE.findall(text)
    comments = COMMENT_RE.findall(text)
    blanks = BLANK_RE.findall(text)
    continuations = CONTINUATION_RE.findall(text)
    urls = URL_RE.findall(text)
    ips = IPV4_RE.findall(text)
    paths = PATH_RE.findall(text)
    declarations = DIM_RE.findall(text)

    unique_calls = set(c.lower() for c in calls)
    identifiers = set(re.findall(r"\b[A-Za-z_]\w*\b", text))
    api_names = set(d[0].lower() for d in api_declares)
    libraries = set(d[1].lower() for d in api_declares if d[1])
    long_strings = [s for s in strings if len(s) > 100]

    source_bytes = len(text.encode("utf-8", errors="ignore"))

    f: dict[str, int | float] = {
        "vba_source_size": source_bytes,
        "vba_line_count": line_count,
        "vba_module_count": 1,
        "vba_procedure_count": len(procedures),
        "vba_declaration_count": len(declarations),
        "vba_api_declaration_count": len(api_declares),
        "vba_statement_count": line_count - len(comments) - len(blanks),
        "vba_call_count": len(calls),
        "vba_unique_call_count": len(unique_calls),
        "vba_string_count": len(strings),
        "vba_identifier_count": len(identifiers),
        "vba_unique_identifier_count": len(identifiers),
        "vba_control_flow_count": len(GOTO_RE.findall(text)) + len(ERROR_HANDLER_RE.findall(text)),
        "vba_indicator_count": 0,
        "vba_comment_line_count": len(comments),
        "vba_blank_line_count": len(blanks),
        "vba_continuation_line_count": len(continuations),
        "vba_long_string_count": len(long_strings),
        "vba_url_count": len(urls),
        "vba_path_count": len(paths),
        "vba_ipv4_count": len(ips),
        "vba_api_unique_count": len(api_names),
        "vba_api_library_count": len(libraries),
        "vba_has_option_explicit": int(bool(OPTION_EXPLICIT_RE.search(text))),
        "vba_has_option_base": int(bool(OPTION_BASE_RE.search(text))),
        "vba_has_goto": int(bool(GOTO_RE.search(text))),
        "vba_has_error_handler": int(bool(ERROR_HANDLER_RE.search(text))),
        "vba_has_dynamic_code": 0,
        "vba_has_network_reference": int(bool(NETWORK_RE.search(text))),
        "vba_has_registry_reference": int(bool(REGISTRY_RE.search(text))),
        "vba_has_com_creation": int(bool(COM_RE.search(text))),
        "vba_has_shell_reference": int(bool(SHELL_RE.search(text))),
        "vba_has_macro_execution": int(bool(MACRO_EXEC_RE.search(text))),
        "vba_has_error_suppression": int(bool(ERROR_SUPPRESS_RE.search(text))),
        "vba_ptrsafe_api_count": len(re.findall(r"(?i)\bPtrSafe\b", text)),
        "vba_api_alias_count": sum(1 for d in api_declares if d[2]),
    }

    # Library family indicators
    for family, pattern in LIBRARY_FAMILIES.items():
        f[f"vba_api_library_{family}"] = int(bool(pattern.search(text)))

    # High-value API indicators
    for api_name, pattern in HIGH_VALUE_APIS.items():
        f[f"vba_api_{api_name}"] = int(bool(pattern.search(text)))

    # Derived chain signals
    f["vba_remote_memory_execution_chain"] = int(
        f.get("vba_api_remote_memory_allocation", 0)
        and f.get("vba_api_remote_memory_write", 0)
        and f.get("vba_api_remote_thread", 0)
    )
    f["vba_dynamic_api_loading_chain"] = int(
        f.get("vba_api_dynamic_api_resolution", 0)
        and f.get("vba_api_dynamic_library_loading", 0)
    )
    f["vba_download_execution_signal"] = int(
        f.get("vba_api_download", 0)
        and (f.get("vba_api_process_creation", 0) or f.get("vba_api_shell_execution", 0) or f.get("vba_has_shell_reference", 0))
    )
    f["vba_registry_persistence_signal"] = int(
        f.get("vba_api_registry_modification", 0)
        and (f.get("vba_has_macro_execution", 0) or f.get("vba_procedure_count", 0) > 0)
    )

    # Indicator count
    indicator_count = sum(1 for k, v in f.items() if k.startswith("vba_has_") and v)
    f["vba_indicator_count"] = indicator_count
    f["vba_suspicious_indicator_count"] = indicator_count
    f["vba_has_dynamic_code"] = int(
        f.get("vba_has_com_creation", 0) or f.get("vba_has_macro_execution", 0)
    )

    # Density measures
    safe_lines = max(line_count, 1)
    safe_bytes = max(source_bytes, 1)
    f["vba_calls_per_line"] = round(len(calls) / safe_lines, 6)
    f["vba_strings_per_line"] = round(len(strings) / safe_lines, 6)
    f["vba_indicators_per_kb"] = round(indicator_count / (safe_bytes / 1024.0), 6)

    return f


def extract_feature_vector(source: str | bytes) -> dict[str, int | float]:
    """Alias for extract_vba_features."""
    return extract_vba_features(source)


def looks_like_vba(source: str | bytes) -> bool:
    """Return whether source contains plausible VBA syntax."""
    if isinstance(source, bytes):
        text = source.decode("utf-8", errors="ignore")
    else:
        text = str(source)
    return bool(re.search(r"(?i)\b(?:Sub\s+\w+|Function\s+\w+|Dim\s+\w+|Attribute\s+VB_Name)\b", text[:4096]))


__all__ = ["extract_vba_features", "extract_feature_vector", "looks_like_vba"]
