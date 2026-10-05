"""
Lightweight credentials behavior feature extraction for Pharos CDR.

Extracts scalar ML features directly from input text via heuristic static scanning.
"""

from __future__ import annotations

import re
from typing import Any, Union

MAX_CHARS = 1024 * 1024

CRED_INDICATORS = {
    "lsass_access": re.compile(r"(?i)\b(?:lsass\.exe|LsaEnumerateLogonSessions|LsaGetLogonSessionData|MiniDumpWriteDump)\b"),
    "sam_access": re.compile(r"(?i)\b(?:SAM\\SAM|SECURITY\\Policy|hklm\\sam)\b"),
    "credential_manager": re.compile(r"(?i)\b(?:CredEnumerate[A-Z]?|CredRead[A-Z]?|vaultcmd)\b"),
    "browser_credentials": re.compile(r"(?i)\b(?:Login\s+Data|Cookies|Web\s+Data|places\.sqlite|key3\.db|key4\.db)\b"),
    "mimikatz": re.compile(r"(?i)\b(?:mimikatz|sekurlsa|kerberos|wdigest|tspkg|livessp)\b"),
    "password_search": re.compile(r"(?i)\b(?:password|passwd|pwd|pass|credentials|creds)\b"),
    "token_manipulation": re.compile(r"(?i)\b(?:ImpersonateLoggedOnUser|DuplicateTokenEx|SetThreadToken|RevertToSelf)\b"),
}

CRED_CATEGORIES = {
    "os_credentials": ["lsass_access", "sam_access"],
    "manager_credentials": ["credential_manager"],
    "browser_credentials": ["browser_credentials"],
    "tool_indicators": ["mimikatz"],
    "generic_search": ["password_search"],
    "token_manipulation": ["token_manipulation"],
}

def extract_credential_feature_vector(source: Union[str, bytes, bytearray]) -> dict[str, float]:
    if isinstance(source, (bytes, bytearray)):
        text = source.decode("utf-8", errors="ignore")
    else:
        text = str(source)
    
    text = text[:MAX_CHARS]
    
    f = {
        "credential_source_size": float(len(text)),
    }
    
    indicator_counts = {}
    for ind, pattern in CRED_INDICATORS.items():
        count = float(len(pattern.findall(text)))
        indicator_counts[ind] = count
        f[f"credential_indicator_{ind}"] = 1.0 if count > 0 else 0.0
        f[f"credential_indicator_{ind}_count"] = count

    for cat, inds in CRED_CATEGORIES.items():
        count = sum(indicator_counts[ind] for ind in inds)
        f[f"credential_category_{cat}"] = 1.0 if count > 0 else 0.0
        f[f"credential_category_{cat}_count"] = count

    f["credential_evidence_count"] = float(sum(indicator_counts.values()))
    f["credential_indicator_count"] = float(sum(1 for v in indicator_counts.values() if v > 0))
    f["credential_category_count"] = float(sum(1 for k, v in f.items() if k.startswith("credential_category_") and not k.endswith("_count") and v > 0))
    
    return f

def extract_credential_features(source: Any, **kwargs: Any) -> dict[str, Any]:
    return {"feature_vector": extract_credential_feature_vector(source)}

def extract_feature_vector(source: Any, **kwargs: Any) -> dict[str, float]:
    return extract_credential_feature_vector(source)

__all__ = ["extract_credential_feature_vector", "extract_credential_features", "extract_feature_vector"]
