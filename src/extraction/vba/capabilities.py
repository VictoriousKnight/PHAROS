"""
Lightweight VBA capability derivation for Pharos CDR.

Extracts scalar ML features for high-level VBA capability categories.
"""

from __future__ import annotations

import re
from typing import Any, Union

MAX_CHARS = 1024 * 1024

CAPABILITY_CATEGORIES = (
    "execution",
    "process",
    "memory",
    "injection",
    "filesystem",
    "registry",
    "network",
    "download",
    "communication",
    "com_automation",
    "macro",
    "persistence",
    "credential_access",
    "discovery",
    "collection",
    "clipboard",
    "security_software",
    "evasion",
    "environment",
    "crypto",
    "encoding",
    "obfuscation",
    "reflection",
    "dynamic_resolution",
    "service",
    "token",
    "synchronization",
    "user_interface",
    "document_manipulation",
    "configuration",
)

CAPABILITY_PATTERNS = {
    "execution": re.compile(r"(?i)\b(?:Shell|WinExec|CreateProcess|ShellExecute|Application\.Run|MacScript)\b"),
    "process": re.compile(r"(?i)\b(?:CreateProcess|OpenProcess|TerminateProcess|Process32First|CreateToolhelp32Snapshot)\b"),
    "memory": re.compile(r"(?i)\b(?:VirtualAlloc|VirtualProtect|RtlMoveMemory|HeapAlloc)\b"),
    "injection": re.compile(r"(?i)\b(?:VirtualAllocEx|WriteProcessMemory|CreateRemoteThread|NtWriteVirtualMemory|QueueUserAPC)\b"),
    "filesystem": re.compile(r"(?i)\b(?:Kill|FileCopy|MkDir|RmDir|FileSystemObject|CreateTextFile|DeleteFile|CopyFile)\b"),
    "registry": re.compile(r"(?i)\b(?:RegOpenKey|RegCreateKey|RegSetValue|RegDelete|RegRead|RegWrite|SaveSetting|GetSetting)\b"),
    "network": re.compile(r"(?i)\b(?:XMLHTTP|WinHttp|InternetOpen|URLDownload|WinHttpOpen|socket|Winsock)\b"),
    "download": re.compile(r"(?i)\b(?:URLDownloadToFile|InternetReadFile|DownloadString|Invoke-WebRequest|WebClient)\b"),
    "communication": re.compile(r"(?i)\b(?:XMLHTTP|ServerXMLHTTP|WinHttpRequest|CDO\.Message|SMTP)\b"),
    "com_automation": re.compile(r"(?i)\b(?:CreateObject|GetObject|CoCreateInstance)\b"),
    "macro": re.compile(r"(?i)\b(?:AutoOpen|Auto_Open|Document_Open|Workbook_Open|AutoExec|AutoClose)\b"),
    "persistence": re.compile(r"(?i)\b(?:CurrentVersion\\\\Run|Startup|schtasks|Register-ScheduledTask|sc\s+create)\b"),
    "credential_access": re.compile(r"(?i)\b(?:password|credential|mimikatz|lsass|SAM|NTDS|sekurlsa)\b"),
    "discovery": re.compile(r"(?i)\b(?:GetComputerName|GetUserName|GetSystemInfo|GetVersionEx|Environ)\b"),
    "collection": re.compile(r"(?i)\b(?:screenshot|keylog|GetClipboardData|GetForegroundWindow|GetWindowText)\b"),
    "clipboard": re.compile(r"(?i)\b(?:OpenClipboard|GetClipboardData|SetClipboardData|EmptyClipboard)\b"),
    "security_software": re.compile(r"(?i)\b(?:DisableRealtimeMonitoring|Set-MpPreference|amsi|AmsiUtils)\b"),
    "evasion": re.compile(r"(?i)\b(?:IsDebuggerPresent|CheckRemoteDebuggerPresent|Sleep|GetTickCount|sandbox|vmware|virtualbox)\b"),
    "environment": re.compile(r"(?i)\b(?:Environ|GetEnvironmentVariable|ExpandEnvironmentStrings|%TEMP%|%APPDATA%)\b"),
    "crypto": re.compile(r"(?i)\b(?:CryptEncrypt|CryptDecrypt|CryptHashData|CryptDeriveKey|crypt32)\b"),
    "encoding": re.compile(r"(?i)\b(?:Base64|Chr\(|ChrW\(|Asc\(|StrReverse|frombase64string|xor)\b"),
    "obfuscation": re.compile(r"(?i)\b(?:Replace\(|Mid\(|StrReverse|Chr\(|ChrW\(|Environ\()\b"),
    "reflection": re.compile(r"(?i)\b(?:CallByName|GetType|InvokeMember)\b"),
    "dynamic_resolution": re.compile(r"(?i)\b(?:GetProcAddress|LoadLibrary|GetModuleHandle)\b"),
    "service": re.compile(r"(?i)\b(?:OpenSCManager|CreateService|StartService|sc\s+create|New-Service)\b"),
    "token": re.compile(r"(?i)\b(?:OpenProcessToken|AdjustTokenPrivileges|GetTokenInformation|ImpersonateLoggedOnUser)\b"),
    "synchronization": re.compile(r"(?i)\b(?:CreateMutex|OpenMutex|WaitForSingleObject|CreateEvent)\b"),
    "user_interface": re.compile(r"(?i)\b(?:MsgBox|InputBox|SendKeys|AppActivate)\b"),
    "document_manipulation": re.compile(r"(?i)\b(?:ActiveDocument|ActiveWorkbook|ActivePresentation|Selection\.TypeText)\b"),
    "configuration": re.compile(r"(?i)\b(?:SaveSetting|GetSetting|DeleteSetting|GetAllSettings)\b"),
}


def extract_capability_features(source: Union[str, bytes, bytearray]) -> dict[str, int | float]:
    """Extract ML-ready VBA capability features from source code."""
    if isinstance(source, (bytes, bytearray)):
        text = source.decode("utf-8", errors="ignore")
    else:
        text = str(source)

    text = text[:MAX_CHARS]
    f: dict[str, int | float] = {}

    for category in CAPABILITY_CATEGORIES:
        pattern = CAPABILITY_PATTERNS.get(category)
        if pattern:
            count = len(pattern.findall(text))
        else:
            count = 0
        f[f"vba_cap_{category}"] = int(count > 0)
        f[f"vba_cap_{category}_count"] = count

    # Chain signals
    has = lambda cat: f.get(f"vba_cap_{cat}", 0) > 0

    f["vba_cap_combo_download_then_execute"] = int(has("download") and has("execution"))
    f["vba_cap_combo_networked_com_automation"] = int(has("network") and has("com_automation"))
    f["vba_cap_combo_filesystem_execution"] = int(has("filesystem") and has("execution"))
    f["vba_cap_combo_registry_persistence"] = int(has("registry") and has("persistence"))
    f["vba_cap_combo_process_memory_injection"] = int(has("injection") and has("memory") and has("process"))
    f["vba_cap_combo_dynamic_execution"] = int(has("dynamic_resolution") and has("execution"))
    f["vba_cap_combo_obfuscated_execution"] = int(has("obfuscation") and has("execution"))
    f["vba_cap_combo_environment_aware_execution"] = int(has("environment") and has("execution"))
    f["vba_cap_combo_macro_network_execution"] = int(has("macro") and has("network") and has("execution"))
    f["vba_cap_combo_credential_collection"] = int(has("credential_access") and has("collection"))
    f["vba_cap_combo_service_persistence"] = int(has("service") and has("persistence"))

    # Aggregate signals
    f["vba_capability_count"] = sum(1 for cat in CAPABILITY_CATEGORIES if f.get(f"vba_cap_{cat}", 0))
    f["vba_capability_evidence_count"] = sum(f.get(f"vba_cap_{cat}_count", 0) for cat in CAPABILITY_CATEGORIES)
    f["vba_capability_high_severity_count"] = sum(1 for cat in ("injection", "credential_access", "evasion", "persistence") if has(cat))
    f["vba_capability_medium_severity_count"] = sum(1 for cat in ("execution", "process", "memory", "registry", "network", "download") if has(cat))
    f["vba_capability_high_confidence_count"] = f["vba_capability_count"]

    f["vba_cap_active_payload_chain"] = int(has("download") and has("execution"))
    f["vba_cap_persistence_chain"] = int(has("persistence") and (has("registry") or has("service")))
    f["vba_cap_injection_chain"] = int(has("injection") and has("memory") and has("process"))
    f["vba_cap_dynamic_execution_chain"] = int(has("dynamic_resolution") and has("execution"))

    return f


def extract_feature_vector(source: Union[str, bytes, bytearray]) -> dict[str, int | float]:
    """Alias for extract_capability_features."""
    return extract_capability_features(source)


__all__ = ["extract_capability_features", "extract_feature_vector", "CAPABILITY_CATEGORIES"]
