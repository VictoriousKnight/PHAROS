"""
Lightweight dynamic execution extraction for Pharos CDR.

Extracts scalar ML features directly from input text via heuristic static scanning.
"""

from __future__ import annotations

import re
from typing import Any, Union, Mapping

MAX_CHARS = 1024 * 1024

DYN_INDICATORS = {
    "eval_exec": re.compile(r"(?i)\b(?:eval|exec|execute|executeglobal)\s*\("),
    "reflection_invoke": re.compile(r"(?i)\b(?:InvokeMember|GetMethod|GetProperty|CallByName)\b"),
    "com_instantiation": re.compile(r"(?i)\b(?:CreateObject|GetObject|CoCreateInstance)\b"),
    "shell_exec": re.compile(r"(?i)\b(?:ShellExecute|WinExec|CreateProcess|WScript\.Shell|Start-Process)\b"),
    "dynamic_assembly": re.compile(r"(?i)\b(?:Reflection\.Assembly|Assembly\.Load|LoadWithPartialName)\b"),
    "wmi_invoke": re.compile(r"(?i)\b(?:InvokeMethod|ExecMethod)\b"),
    "javascript_function": re.compile(r"(?i)\bFunction\s*\("),
    "powershell_iex": re.compile(r"(?i)\b(?:Invoke-Expression|IEX)\b"),
}

DYN_CATEGORIES = {
    "evaluation": ["eval_exec", "javascript_function", "powershell_iex"],
    "reflection": ["reflection_invoke", "dynamic_assembly"],
    "automation": ["com_instantiation", "wmi_invoke"],
    "process": ["shell_exec"],
}

def _vectorize(f: dict[str, float]) -> list[float]:
    # Preserve a deterministic order for list export
    keys = sorted(f.keys())
    return [f[k] for k in keys]

def extract_dynamic_execution_feature_vector(source: Union[str, bytes, bytearray], **kwargs: Any) -> list[float]:
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
        "combination_count": 0.0,
    }
    
    indicator_counts = {}
    for ind, pattern in DYN_INDICATORS.items():
        count = float(len(pattern.findall(text)))
        indicator_counts[ind] = count
        f[f"indicator_present__{ind}"] = 1.0 if count > 0 else 0.0
        f[f"indicator_count__{ind}"] = count

    for cat, inds in DYN_CATEGORIES.items():
        count = sum(indicator_counts[ind] for ind in inds)
        f[f"category_present__{cat}"] = 1.0 if count > 0 else 0.0
        f[f"category_count__{cat}"] = count

    f["evidence_count"] = float(sum(indicator_counts.values()))
    f["indicator_count"] = float(sum(1 for v in indicator_counts.values() if v > 0))
    f["category_count"] = float(sum(1 for k, v in f.items() if k.startswith("category_present__") and v > 0))
    
    # Combinations (legacy placeholders)
    combinations = ["dynamic_evaluation", "dynamic_invocation_chain", "script_host_execution", "com_to_execution", "reflection_to_execution"]
    for combo in combinations:
        f[f"combination_present__{combo}"] = 0.0

    return _vectorize(f)

def extract_dynamic_execution_features(source: Any, **kwargs: Any) -> dict[str, Any]:
    # Emulate the legacy analysis object
    class AnalysisEmulator:
        def __init__(self, vec):
            self.feature_vector = vec
    return AnalysisEmulator(extract_dynamic_execution_feature_vector(source))

def extract_feature_vector(source: Any, **kwargs: Any) -> list[float]:
    return extract_dynamic_execution_feature_vector(source)

def vectorize_features(features: Mapping[str, object]) -> list[float]:
    return _vectorize({k: float(v) for k, v in features.items()})

__all__ = ["extract_dynamic_execution_feature_vector", "extract_dynamic_execution_features", "extract_feature_vector", "vectorize_features"]
