"""
Lightweight VBA execution extraction for Pharos CDR.

Extracts scalar ML features related to VBA execution triggers and flow.
"""

from __future__ import annotations

import re
from typing import Any, Union

MAX_CHARS = 1024 * 1024

EXECUTION_INDICATORS = {
    "auto_open": re.compile(r"(?i)\b(?:AutoOpen|Auto_Open|Document_Open|Workbook_Open|AutoExec)\b"),
    "auto_close": re.compile(r"(?i)\b(?:AutoClose|Auto_Close|Document_Close|Workbook_BeforeClose)\b"),
    "shell_call": re.compile(r"(?i)\b(?:Shell|ShellExecute|WScript\.Shell|MacScript)\b"),
    "execute_call": re.compile(r"(?i)\bExecute\s*\("),
    "execute_global_call": re.compile(r"(?i)\bExecuteGlobal\b"),
    "eval_call": re.compile(r"(?i)\bEval\s*\("),
    "application_run": re.compile(r"(?i)\bApplication\.Run\b"),
    "application_evaluate": re.compile(r"(?i)\bApplication\.Evaluate\b"),
    "callbyname": re.compile(r"(?i)\bCallByName\b"),
    "wscript_shell_run": re.compile(r"(?i)\bRun\s*\("),
    "createobject": re.compile(r"(?i)\bCreateObject\b"),
    "getobject": re.compile(r"(?i)\bGetObject\b"),
    "ontime": re.compile(r"(?i)\bOnTime\b"),
    "sleep": re.compile(r"(?i)\b(?:Sleep|Application\.Wait)\b"),
    "app_activate": re.compile(r"(?i)\bAppActivate\b"),
    "sendkeys": re.compile(r"(?i)\bSendKeys\b"),
}

EXECUTION_CATEGORIES = {
    "auto_execution": ["auto_open", "auto_close"],
    "process_creation": ["shell_call", "wscript_shell_run"],
    "dynamic_execution": ["execute_call", "execute_global_call", "eval_call", "application_run", "application_evaluate", "callbyname"],
    "com_instantiation": ["createobject", "getobject"],
    "scheduling": ["ontime", "sleep"],
    "ui_interaction": ["app_activate", "sendkeys"],
}

def extract_execution_feature_vector(source: Union[str, bytes, bytearray]) -> dict[str, float]:
    """Return only the deterministic execution feature vector."""
    if isinstance(source, (bytes, bytearray)):
        text = source.decode("utf-8", errors="ignore")
    else:
        text = str(source)
        
    text = text[:MAX_CHARS]
    
    f = {}
    
    indicator_counts = {}
    for ind, pattern in EXECUTION_INDICATORS.items():
        count = float(len(pattern.findall(text)))
        indicator_counts[ind] = count
        f[f"vba_execution_indicator_{ind}"] = 1.0 if count > 0 else 0.0
        f[f"vba_execution_indicator_{ind}_count"] = count

    for cat, inds in EXECUTION_CATEGORIES.items():
        cat_count = sum(indicator_counts[ind] for ind in inds)
        f[f"vba_execution_{cat}"] = 1.0 if cat_count > 0 else 0.0
        f[f"vba_execution_{cat}_count"] = cat_count

    return f

def extract_execution_features(source: Union[str, bytes, bytearray]) -> dict[str, Any]:
    return {"feature_vector": extract_execution_feature_vector(source)}

def extract_feature_vector(source: Union[str, bytes, bytearray]) -> dict[str, float]:
    return extract_execution_feature_vector(source)

__all__ = ["extract_execution_feature_vector", "extract_execution_features", "extract_feature_vector"]
