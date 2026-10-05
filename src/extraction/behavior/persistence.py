"""
Lightweight persistence behavior feature extraction for Pharos CDR.

Extracts scalar ML features directly from input text via heuristic static scanning.
"""

from __future__ import annotations

import re
from typing import Any, Union

MAX_CHARS = 1024 * 1024

PERSIST_INDICATORS = {
    "registry_run_keys": re.compile(r"(?i)\b(?:CurrentVersion\\Run|CurrentVersion\\RunOnce)\b"),
    "startup_folder": re.compile(r"(?i)\b(?:\\Start\s+Menu\\Programs\\Startup|\\Startup\\)\b"),
    "scheduled_tasks": re.compile(r"(?i)\b(?:schtasks|Register-ScheduledTask|New-ScheduledTaskAction|Schedule\.Service)\b"),
    "services": re.compile(r"(?i)\b(?:CreateService[A-Z]?|OpenSCManager[A-Z]?|StartService[A-Z]?|sc\s+create|New-Service)\b"),
    "wmi_event_subscription": re.compile(r"(?i)\b(?:__EventFilter|__FilterToConsumerBinding|CommandLineEventConsumer)\b"),
    "com_hijacking": re.compile(r"(?i)\b(?:InprocServer32|TreatAs)\b"),
}

PERSIST_CATEGORIES = {
    "registry_persistence": ["registry_run_keys"],
    "file_persistence": ["startup_folder"],
    "task_persistence": ["scheduled_tasks"],
    "service_persistence": ["services"],
    "wmi_persistence": ["wmi_event_subscription"],
    "com_persistence": ["com_hijacking"],
}

def extract_persistence_feature_vector(source: Union[str, bytes, bytearray]) -> dict[str, float]:
    if isinstance(source, (bytes, bytearray)):
        text = source.decode("utf-8", errors="ignore")
    else:
        text = str(source)
    
    text = text[:MAX_CHARS]
    
    f = {
        "persistence_source_size": float(len(text)),
    }
    
    indicator_counts = {}
    for ind, pattern in PERSIST_INDICATORS.items():
        count = float(len(pattern.findall(text)))
        indicator_counts[ind] = count
        f[f"persistence_indicator_{ind}"] = 1.0 if count > 0 else 0.0
        f[f"persistence_indicator_{ind}_count"] = count

    for cat, inds in PERSIST_CATEGORIES.items():
        count = sum(indicator_counts[ind] for ind in inds)
        f[f"persistence_category_{cat}"] = 1.0 if count > 0 else 0.0
        f[f"persistence_category_{cat}_count"] = count

    f["persistence_evidence_count"] = float(sum(indicator_counts.values()))
    f["persistence_indicator_count"] = float(sum(1 for v in indicator_counts.values() if v > 0))
    f["persistence_category_count"] = float(sum(1 for k, v in f.items() if k.startswith("persistence_category_") and not k.endswith("_count") and v > 0))
    
    return f

def extract_persistence_features(source: Any, **kwargs: Any) -> dict[str, Any]:
    return {"feature_vector": extract_persistence_feature_vector(source)}

def extract_feature_vector(source: Any, **kwargs: Any) -> dict[str, float]:
    return extract_persistence_feature_vector(source)

__all__ = ["extract_persistence_feature_vector", "extract_persistence_features", "extract_feature_vector"]
