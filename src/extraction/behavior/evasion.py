"""
Static evasion-behavior extraction for Pharos CDR.

This module identifies static indicators associated with malware evasion,
anti-analysis, defense impairment, sandbox/VM awareness, hidden execution,
obfuscation, artifact cleanup, and related behaviors.

Security properties
-------------------
- Never executes commands, scripts, macros, or binaries.
- Never disables security software.
- Never modifies the registry, filesystem, services, or policies.
- Never performs environment discovery against the live host.
- Never launches processes or loads DLLs.
- Never contacts external systems.
- Only analyzes content supplied by the caller.

The extractor is intentionally conservative around generic terms such as
"hidden", "debug", and "virtual". Stronger API, command, registry, and
behavioral combinations receive higher confidence and severity.

Evidence chain
--------------
static text/path/API reference
    -> evasion indicator
    -> evasion category
    -> evasion behavior/combination
    -> feature vector
    -> ML/CDR policy
"""

from __future__ import annotations

import hashlib
import os
import re
from collections import Counter
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import (
    Any,
    Dict,
    Iterable,
    Iterator,
    List,
    Mapping,
    Optional,
    Sequence,
    Set,
    Tuple,
    Union,
)


# ---------------------------------------------------------------------------
# Limits
# ---------------------------------------------------------------------------

MAX_SOURCE_SIZE = 25 * 1024 * 1024
MAX_TEXT_CHARS = 25 * 1024 * 1024
MAX_EVIDENCE_ITEMS = 20_000
MAX_MATCHES_PER_RULE = 5_000
MAX_NESTING_DEPTH = 12
MAX_FIELD_TEXT = 100_000
MAX_EVASION_RECORDS = 10_000
MAX_LOCATIONS = 10_000
MAX_TOKENS = 250_000


# ---------------------------------------------------------------------------
# Taxonomy
# ---------------------------------------------------------------------------

EVASION_CATEGORIES: Tuple[str, ...] = (
    "evasion",
    "anti_analysis",
    "anti_debugging",
    "anti_vm",
    "anti_sandbox",
    "anti_emulation",
    "environment_awareness",
    "security_software_discovery",
    "security_software_impairment",
    "firewall_impairment",
    "logging_impairment",
    "event_log_impairment",
    "defender_impairment",
    "av_impairment",
    "amsi_impairment",
    "etw_impairment",
    "uac_bypass",
    "privilege_abuse",
    "hidden_execution",
    "hidden_window",
    "process_masquerading",
    "process_manipulation",
    "parent_process_manipulation",
    "process_injection",
    "process_hollowing",
    "memory_evasion",
    "code_injection",
    "module_unhooking",
    "api_unhooking",
    "api_resolution",
    "dynamic_resolution",
    "dynamic_loading",
    "obfuscation",
    "string_obfuscation",
    "encoding",
    "packing",
    "compression",
    "encryption",
    "macro_obfuscation",
    "script_obfuscation",
    "powershell_obfuscation",
    "javascript_obfuscation",
    "vba_obfuscation",
    "control_flow_obfuscation",
    "artifact_cleanup",
    "file_deletion",
    "log_cleanup",
    "history_cleanup",
    "registry_cleanup",
    "temporary_artifact_cleanup",
    "anti_forensics",
    "timestamp_manipulation",
    "file_metadata_manipulation",
    "network_evasion",
    "proxy_awareness",
    "connectivity_checks",
    "locale_awareness",
    "language_awareness",
    "username_awareness",
    "hostname_awareness",
    "domain_awareness",
    "sleep_delay",
    "timing_evasion",
    "sandbox_artifact_check",
    "virtualization_artifact_check",
    "debugger_artifact_check",
    "analysis_tool_check",
    "security_product_check",
)


SEVERITY_ORDER = {
    "low": 0,
    "medium": 1,
    "high": 2,
    "critical": 3,
}


SEVERITY_WEIGHTS = {
    "low": 1.0,
    "medium": 2.0,
    "high": 4.0,
    "critical": 7.0,
}


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class EvasionPattern:
    """A static evasion indicator rule."""

    name: str
    category: str
    regex: str
    severity: str = "medium"
    confidence: float = 0.8
    operation: str = "unknown"
    description: str = ""
    platform: str = "cross-platform"


@dataclass
class EvasionEvidence:
    """One bounded piece of static evasion evidence."""

    category: str
    indicator: str
    evidence: str
    source: str = "static"
    line_number: Optional[int] = None
    operation: str = "unknown"
    location: Optional[str] = None
    platform: str = "cross-platform"
    confidence: float = 1.0
    severity: str = "medium"


@dataclass
class EvasionRecord:
    """Normalized evasion behavior derived from evidence."""

    mechanism: str
    category: str
    location: Optional[str]
    operation: str
    platform: str
    indicator: str
    evidence: str
    severity: str
    confidence: float


@dataclass
class EvasionCombination:
    """Higher-level evasion behavior derived from multiple indicators."""

    name: str
    present: bool
    required_categories: Tuple[str, ...]
    explanation: str


@dataclass
class EvasionAnalysis:
    """Complete static evasion-behavior analysis."""

    source_hash: str
    source_size: int
    records: List[EvasionRecord] = field(default_factory=list)
    evidence: List[EvasionEvidence] = field(default_factory=list)
    indicators: List[str] = field(default_factory=list)
    categories: List[str] = field(default_factory=list)
    combinations: List[EvasionCombination] = field(default_factory=list)
    locations: List[str] = field(default_factory=list)
    platforms: List[str] = field(default_factory=list)
    feature_vector: Dict[str, float] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Input normalization
# ---------------------------------------------------------------------------


SourceLike = Union[
    str,
    bytes,
    bytearray,
    memoryview,
    os.PathLike,
    Mapping[str, Any],
    Sequence[Any],
    Any,
]


def _safe_scalar_text(value: Any) -> str:
    """Safely stringify a scalar within a strict size limit."""
    if value is None:
        return ""

    if isinstance(value, bytes):
        return value[:MAX_FIELD_TEXT].decode(
            "utf-8",
            errors="replace",
        )

    if isinstance(value, bytearray):
        return bytes(value[:MAX_FIELD_TEXT]).decode(
            "utf-8",
            errors="replace",
        )

    try:
        return str(value)[:MAX_FIELD_TEXT]
    except Exception:
        return ""


def _flatten_source(
    source: Any,
    *,
    depth: int = 0,
    seen: Optional[Set[int]] = None,
) -> str:
    """
    Recursively flatten nested mappings, sequences, and analysis objects.

    No arbitrary methods are invoked. The function only inspects mappings,
    sequences, and __dict__ values within bounded limits.
    """
    if depth > MAX_NESTING_DEPTH:
        return ""

    if seen is None:
        seen = set()

    if source is None:
        return ""

    if isinstance(
        source,
        (str, bytes, bytearray, memoryview, os.PathLike),
    ):
        if isinstance(source, memoryview):
            return _safe_scalar_text(source.tobytes())
        return _safe_scalar_text(source)

    object_id = id(source)

    if object_id in seen:
        return ""

    seen.add(object_id)

    parts: List[str] = []

    if isinstance(source, Mapping):
        for index, (key, value) in enumerate(source.items()):
            if index >= MAX_TOKENS:
                break

            key_text = _safe_scalar_text(key)
            value_text = _flatten_source(
                value,
                depth=depth + 1,
                seen=seen,
            )

            if key_text:
                parts.append(key_text)

            if value_text:
                parts.append(value_text)

        return "\n".join(parts)[:MAX_TEXT_CHARS]

    if isinstance(source, Sequence) and not isinstance(
        source,
        (str, bytes, bytearray, memoryview),
    ):
        for index, value in enumerate(source):
            if index >= MAX_TOKENS:
                break

            value_text = _flatten_source(
                value,
                depth=depth + 1,
                seen=seen,
            )

            if value_text:
                parts.append(value_text)

        return "\n".join(parts)[:MAX_TEXT_CHARS]

    if hasattr(source, "__dict__"):
        try:
            return _flatten_source(
                vars(source),
                depth=depth + 1,
                seen=seen,
            )
        except Exception:
            pass

    return _safe_scalar_text(source)


def _read_source(source: SourceLike) -> Tuple[str, int, str]:
    """
    Convert supplied material to bounded text.

    A caller-supplied path may be read, but the module never searches,
    enumerates, or discovers additional filesystem content.
    """
    if isinstance(source, bytes):
        raw = source[:MAX_SOURCE_SIZE]
        return (
            raw.decode("utf-8", errors="replace")[:MAX_TEXT_CHARS],
            len(raw),
            "bytes",
        )

    if isinstance(source, bytearray):
        raw = bytes(source[:MAX_SOURCE_SIZE])
        return (
            raw.decode("utf-8", errors="replace")[:MAX_TEXT_CHARS],
            len(raw),
            "bytes",
        )

    if isinstance(source, memoryview):
        raw = source.tobytes()[:MAX_SOURCE_SIZE]
        return (
            raw.decode("utf-8", errors="replace")[:MAX_TEXT_CHARS],
            len(raw),
            "bytes",
        )

    if isinstance(source, os.PathLike):
        path = Path(source)

        try:
            stat = path.stat()
            size = int(stat.st_size)
        except (OSError, ValueError):
            text = str(path)[:MAX_TEXT_CHARS]
            return text, len(text.encode("utf-8", errors="replace")), "path"

        if not path.is_file():
            text = str(path)[:MAX_TEXT_CHARS]
            return text, size, "path"

        read_size = min(size, MAX_SOURCE_SIZE)

        with path.open("rb") as handle:
            raw = handle.read(read_size)

        return (
            raw.decode("utf-8", errors="replace")[:MAX_TEXT_CHARS],
            size,
            "file",
        )

    if isinstance(source, str):
        return (
            source[:MAX_TEXT_CHARS],
            len(
                source.encode(
                    "utf-8",
                    errors="replace",
                )
            ),
            "text",
        )

    text = _flatten_source(source)
    return (
        text[:MAX_TEXT_CHARS],
        len(text.encode("utf-8", errors="replace")),
        "object",
    )


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def _normalize_space(value: str) -> str:
    return re.sub(r"\s+", " ", value).strip()


def _safe_excerpt(
    text: str,
    start: int,
    end: int,
    radius: int = 110,
) -> str:
    left = max(0, start - radius)
    right = min(len(text), end + radius)

    return _normalize_space(text[left:right])[:MAX_FIELD_TEXT]


def _line_number(
    text: str,
    position: int,
) -> int:
    return text.count("\n", 0, position) + 1


# ---------------------------------------------------------------------------
# Pattern construction
# ---------------------------------------------------------------------------


def _p(
    name: str,
    category: str,
    regex: str,
    *,
    severity: str = "medium",
    confidence: float = 0.8,
    operation: str = "unknown",
    description: str = "",
    platform: str = "cross-platform",
) -> EvasionPattern:
    return EvasionPattern(
        name=name,
        category=category,
        regex=regex,
        severity=severity,
        confidence=confidence,
        operation=operation,
        description=description,
        platform=platform,
    )


PATTERNS: Tuple[EvasionPattern, ...] = (
    # -----------------------------------------------------------------------
    # Debugger / analysis detection
    # -----------------------------------------------------------------------
    _p(
        "debugger_api",
        "anti_debugging",
        r"(?i)\b(?:IsDebuggerPresent|CheckRemoteDebuggerPresent|NtQueryInformationProcess|ZwQueryInformationProcess)\b",
        severity="high",
        confidence=0.94,
        operation="detect",
        description="Windows APIs commonly used for debugger detection.",
        platform="windows",
    ),
    _p(
        "debugger_exception_check",
        "anti_debugging",
        r"(?i)\b(?:OutputDebugString(?:A|W)?|DebugActiveProcess|DebugBreak|__debugbreak|BeingDebugged|NtGlobalFlag|PEB)\b",
        severity="high",
        confidence=0.88,
        operation="detect",
        description="Static references associated with debugger or debug-state checks.",
        platform="windows",
    ),
    _p(
        "debugger_process_check",
        "debugger_artifact_check",
        r"(?i)\b(?:x64dbg|x32dbg|WinDbg|windbg|OllyDbg|ImmunityDebugger|IDA(?:\s+Pro)?|Ghidra|dnSpy|ProcessHacker|Process Explorer)\b",
        severity="high",
        confidence=0.91,
        operation="detect",
        description="References to analysis/debugging tools.",
        platform="windows",
    ),
    _p(
        "analysis_tool_check",
        "analysis_tool_check",
        r"(?i)\b(?:wireshark|fiddler|procmon|processmon|procmon64|procexp|api\s*monitor|frida|radare2|cuckoo|any\.run|sandbox)\b",
        severity="high",
        confidence=0.90,
        operation="detect",
        description="References to analysis or sandbox tooling.",
    ),
    _p(
        "debugger_environment_variable",
        "debugger_artifact_check",
        r"(?i)(?:COR_ENABLE_PROFILING|COR_PROFILER|_NT_SYMBOL_PATH|DBGHELP|DEBUGGER|WINDBG)",
        severity="medium",
        confidence=0.76,
        operation="detect",
        description="Environment/configuration references associated with debugging.",
    ),
    # -----------------------------------------------------------------------
    # VM / sandbox / emulator detection
    # -----------------------------------------------------------------------
    _p(
        "virtual_machine_terms",
        "anti_vm",
        r"(?i)\b(?:VMware|VirtualBox|VBox|QEMU|KVM|Hyper-V|Parallels|Xen|Virtual Machine|virtualization)\b",
        severity="medium",
        confidence=0.72,
        operation="detect",
        description="Virtualization-related artifact references.",
    ),
    _p(
        "vm_artifact_paths",
        "virtualization_artifact_check",
        r"(?i)(?:\\Program Files\\VMware|\\VMware Tools\\|\\VirtualBox Guest Additions\\|vboxservice|vboxtray|vmtoolsd|vmwaretray|qemu-ga)",
        severity="high",
        confidence=0.91,
        operation="detect",
        description="Known virtualization artifact paths/processes.",
        platform="windows",
    ),
    _p(
        "sandbox_artifacts",
        "sandbox_artifact_check",
        r"(?i)\b(?:Cuckoo|Joe Sandbox|Any\.Run|Hybrid Analysis|Sandboxie|Comodo Sandbox|FireEye|detonation|sandbox artifact)\b",
        severity="high",
        confidence=0.89,
        operation="detect",
        description="Sandbox/detonation environment detection.",
    ),
    _p(
        "low_resource_check",
        "anti_sandbox",
        r"(?i)(?:GlobalMemoryStatusEx|GetSystemInfo|GetPhysicallyInstalledSystemMemory|NumberOfProcessors|Environment\.ProcessorCount|RAM\s*(?:<|<=)|CPU\s*(?:<|<=))",
        severity="medium",
        confidence=0.79,
        operation="detect",
        description="Resource checks that may be used to identify analysis environments.",
    ),
    _p(
        "virtual_hardware_check",
        "virtualization_artifact_check",
        r"(?i)(?:Win32_ComputerSystem|Win32_BIOS|Win32_VideoController|Win32_DiskDrive).{0,180}(?:VMware|VirtualBox|QEMU|Hyper-V|Virtual)",
        severity="high",
        confidence=0.91,
        operation="detect",
        description="WMI/hardware checks for virtualization artifacts.",
        platform="windows",
    ),
    # -----------------------------------------------------------------------
    # Security product discovery / impairment
    # -----------------------------------------------------------------------
    _p(
        "security_product_discovery",
        "security_software_discovery",
        r"(?i)\b(?:Get-MpComputerStatus|SecurityCenter2|Win32_QuickFixEngineering|Win32_Product|Win32_InstalledWin32Program|antivirus|anti.?virus|endpoint protection|EDR|EPP)\b",
        severity="medium",
        confidence=0.78,
        operation="discover",
        description="Security product or protection-state discovery.",
        platform="windows",
    ),
    _p(
        "defender_configuration",
        "defender_impairment",
        r"(?i)\b(?:Set-MpPreference|Add-MpPreference|Remove-MpPreference|DisableRealtimeMonitoring|DisableBehaviorMonitoring|DisableIOAVProtection|DisableScriptScanning|DisableArchiveScanning)\b",
        severity="critical",
        confidence=0.98,
        operation="impair",
        description="Windows Defender configuration or protection-disabling references.",
        platform="windows",
    ),
    _p(
        "defender_registry",
        "defender_impairment",
        r"(?i)(?:Windows Defender|Microsoft Defender).{0,180}(?:DisableAntiSpyware|DisableRealtimeMonitoring|DisableBehaviorMonitoring|DisableScriptScanning)",
        severity="critical",
        confidence=0.97,
        operation="impair",
        description="Static references to Defender impairment settings.",
        platform="windows",
    ),
    _p(
        "firewall_impairment",
        "firewall_impairment",
        r"(?i)\b(?:netsh\s+advfirewall\s+(?:set|firewall)|Set-NetFirewallProfile|Set-NetFirewallRule|Disable-NetFirewallRule|New-NetFirewallRule)\b",
        severity="high",
        confidence=0.93,
        operation="impair",
        description="Firewall configuration changes.",
        platform="windows",
    ),
    _p(
        "security_service_stop",
        "security_software_impairment",
        r"(?i)\b(?:sc(?:\.exe)?\s+(?:stop|config)|Stop-Service|Set-Service).{0,180}(?:Defender|WinDefend|Sense|Security|Firewall|MsMpEng|antivirus|EDR)",
        severity="critical",
        confidence=0.97,
        operation="impair",
        description="Attempts to stop or reconfigure security-related services.",
        platform="windows",
    ),
    _p(
        "security_process_termination",
        "security_software_impairment",
        r"(?i)\b(?:taskkill|Stop-Process|kill|pkill)\b.{0,150}(?:MsMpEng|MsSense|Sense|Defender|CrowdStrike|Sentinel|CarbonBlack|Sophos|ESET|Avast|Kaspersky|security)",
        severity="critical",
        confidence=0.96,
        operation="impair",
        description="Process termination references targeting security software.",
    ),
    # -----------------------------------------------------------------------
    # AMSI / ETW / logging impairment
    # -----------------------------------------------------------------------
    _p(
        "amsi_bypass",
        "amsi_impairment",
        r"(?i)\b(?:AmsiScanBuffer|AmsiInitialize|AmsiOpenSession|amsiInitFailed|amsiContext|AMSI\s*bypass|AmsiUtils)\b",
        severity="critical",
        confidence=0.98,
        operation="impair",
        description="AMSI bypass or manipulation references.",
        platform="windows",
    ),
    _p(
        "amsi_patch_terms",
        "amsi_impairment",
        r"(?i)(?:amsi\.dll|AmsiScanBuffer).{0,180}(?:patch|bypass|hook|unhook|memory|overwrite|VirtualProtect)",
        severity="critical",
        confidence=0.99,
        operation="impair",
        description="AMSI memory patching/unhooking references.",
        platform="windows",
    ),
    _p(
        "etw_bypass",
        "etw_impairment",
        r"(?i)\b(?:EtwEventWrite|EtwEventWriteFull|EtwEventRegister|ETW\s*bypass|ETW\s*patch|ntdll\.dll)\b.{0,180}(?:patch|bypass|hook|unhook|disable|overwrite)",
        severity="critical",
        confidence=0.98,
        operation="impair",
        description="ETW impairment or patching references.",
        platform="windows",
    ),
    _p(
        "event_log_clear",
        "event_log_impairment",
        r"(?i)\b(?:wevtutil(?:\.exe)?\s+cl|Clear-EventLog|Remove-EventLog|event\s+log.{0,30}(?:clear|delete|remove))\b",
        severity="high",
        confidence=0.96,
        operation="cleanup",
        description="Event-log clearing references.",
        platform="windows",
    ),
    _p(
        "logging_disable",
        "logging_impairment",
        r"(?i)\b(?:Disable-Logging|disable\s+(?:audit|logging|event\s+logging)|auditpol\s+/clear|auditpol\s+/remove)\b",
        severity="high",
        confidence=0.91,
        operation="impair",
        description="Logging/auditing impairment references.",
        platform="windows",
    ),
    # -----------------------------------------------------------------------
    # Hidden execution / process manipulation
    # -----------------------------------------------------------------------
    _p(
        "hidden_window",
        "hidden_window",
        r"(?i)(?:CreateNoWindow\s*=\s*true|WindowStyle\s*=\s*Hidden|SW_HIDE|CREATE_NO_WINDOW|vbHide|Run\s*,\s*0\b|WScript\.Shell\s*\.\s*Run\s*\([^)]*,\s*0\b)",
        severity="high",
        confidence=0.93,
        operation="hide",
        description="Hidden process/window execution configuration.",
    ),
    _p(
        "hidden_execution_terms",
        "hidden_execution",
        r"(?i)\b(?:hidden\s+window|invisible\s+window|background\s+execution|silent\s+execution|run\s+silently|no\s+window)\b",
        severity="medium",
        confidence=0.82,
        operation="hide",
        description="Explicit hidden/silent execution terminology.",
    ),
    _p(
        "process_masquerading",
        "process_masquerading",
        r"(?i)\b(?:masquerade|masquerading|process\s+name|fake\s+process|spoof(?:ed)?\s+process|svchost|explorer|rundll32|regsvr32)\b.{0,160}(?:rename|spoof|masquerade|impersonate|hidden)",
        severity="high",
        confidence=0.86,
        operation="masquerade",
        description="Process-name masquerading references.",
    ),
    _p(
        "parent_process_spoofing",
        "parent_process_manipulation",
        r"(?i)\b(?:PROC_THREAD_ATTRIBUTE_PARENT_PROCESS|STARTUPINFOEX|parent\s+process|PPID\s*spoof|parent\s+PID|ParentProcessId)\b",
        severity="high",
        confidence=0.93,
        operation="manipulate",
        description="Parent-process manipulation references.",
        platform="windows",
    ),
    _p(
        "process_hollowing",
        "process_hollowing",
        r"(?i)\b(?:process\s+hollowing|RunPE|NtUnmapViewOfSection|ZwUnmapViewOfSection|WriteProcessMemory).{0,220}(?:CreateProcess|VirtualAlloc|ResumeThread|entry.?point)",
        severity="critical",
        confidence=0.98,
        operation="inject",
        description="Process hollowing chain indicators.",
        platform="windows",
    ),
    _p(
        "remote_injection_chain",
        "process_injection",
        r"(?i)\b(?:OpenProcess|VirtualAllocEx|WriteProcessMemory|CreateRemoteThread|NtCreateThreadEx|QueueUserAPC)\b",
        severity="critical",
        confidence=0.96,
        operation="inject",
        description="Remote process injection APIs.",
        platform="windows",
    ),
    _p(
        "memory_protection_manipulation",
        "memory_evasion",
        r"(?i)\b(?:VirtualProtect|VirtualProtectEx|NtProtectVirtualMemory|ZwProtectVirtualMemory)\b",
        severity="high",
        confidence=0.87,
        operation="manipulate",
        description="Memory protection manipulation.",
        platform="windows",
    ),
    _p(
        "module_unhooking",
        "module_unhooking",
        r"(?i)\b(?:unhook|unhooking|restore\s+hooks|remove\s+hooks|ntdll.{0,80}(?:hook|clean|restore)|clean\s+ntdll)\b",
        severity="critical",
        confidence=0.97,
        operation="impair",
        description="API/module unhooking references.",
        platform="windows",
    ),
    # -----------------------------------------------------------------------
    # Dynamic resolution/loading
    # -----------------------------------------------------------------------
    _p(
        "dynamic_api_resolution",
        "api_resolution",
        r"(?i)\b(?:GetProcAddress|GetModuleHandle(?:A|W)?|LdrGetProcedureAddress|LoadLibrary(?:A|W)?|GetProcAddress\s*\()\b",
        severity="medium",
        confidence=0.76,
        operation="resolve",
        description="Dynamic Windows API/module resolution.",
        platform="windows",
    ),
    _p(
        "dynamic_module_loading",
        "dynamic_loading",
        r"(?i)\b(?:LoadLibrary(?:A|W)?|LoadLibraryEx(?:A|W)?|dlopen|dlsym|ctypes\.WinDLL|ctypes\.CDLL)\b",
        severity="medium",
        confidence=0.78,
        operation="load",
        description="Dynamic library loading references.",
    ),
    _p(
        "reflection_loading",
        "dynamic_resolution",
        r"(?i)\b(?:Assembly\.Load|Assembly\.LoadFile|Assembly\.LoadFrom|Reflection\.Assembly|GetType\s*\(|Activator\.CreateInstance)\b",
        severity="high",
        confidence=0.84,
        operation="resolve",
        description="Reflection-based dynamic resolution/loading.",
        platform="windows",
    ),
    # -----------------------------------------------------------------------
    # Obfuscation / encoding / packing
    # -----------------------------------------------------------------------
    _p(
        "powershell_encoded_command",
        "powershell_obfuscation",
        r"(?i)(?:-enc(?:odedcommand)?\b|-e(?:nc)?\s+[A-Za-z0-9+/=]{20,})",
        severity="high",
        confidence=0.95,
        operation="obfuscate",
        description="PowerShell encoded-command usage.",
        platform="windows",
    ),
    _p(
        "powershell_obfuscation",
        "powershell_obfuscation",
        r"(?i)\b(?:IEX|Invoke-Expression|FromBase64String|ToBase64String|Replace\s*\(|Substring\s*\(|char\s*\(|[char]\s*\d+)\b",
        severity="medium",
        confidence=0.74,
        operation="obfuscate",
        description="PowerShell constructs frequently used for obfuscation.",
        platform="windows",
    ),
    _p(
        "vba_obfuscation",
        "vba_obfuscation",
        r"(?i)\b(?:ChrW?\s*\(|AscW?\s*\(|StrReverse\s*\(|Replace\s*\(|Mid\s*\(|Split\s*\(|Join\s*\(|Environ\s*\()\b",
        severity="medium",
        confidence=0.72,
        operation="obfuscate",
        description="VBA string transformation constructs.",
        platform="windows",
    ),
    _p(
        "javascript_obfuscation",
        "javascript_obfuscation",
        r"(?i)\b(?:eval\s*\(|Function\s*\(|String\.fromCharCode|unescape\s*\(|decodeURIComponent\s*\(|atob\s*\(|fromCharCode)\b",
        severity="high",
        confidence=0.88,
        operation="obfuscate",
        description="JavaScript dynamic decoding/evaluation constructs.",
    ),
    _p(
        "vbscript_obfuscation",
        "script_obfuscation",
        r"(?i)\b(?:Execute\s*\(|ExecuteGlobal\s*\(|Eval\s*\(|Chr\s*\(|Replace\s*\(|Join\s*\(|Split\s*\()\b",
        severity="medium",
        confidence=0.78,
        operation="obfuscate",
        description="VBScript dynamic evaluation/string transformation constructs.",
    ),
    _p(
        "base64_transformation",
        "encoding",
        r"(?i)\b(?:FromBase64String|ToBase64String|Convert\.ToBase64String|base64(?:\s+|-)(?:encode|decode)|certutil\s+-decode|openssl\s+base64)\b",
        severity="medium",
        confidence=0.78,
        operation="encode",
        description="Base64 transformation references.",
    ),
    _p(
        "hex_transformation",
        "encoding",
        r"(?i)\b(?:Format-Hex|xxd|hexlify|unhexlify|ToHexString)\b",
        severity="low",
        confidence=0.65,
        operation="encode",
        description="Hexadecimal transformation references.",
    ),
    _p(
        "compressed_payload",
        "compression",
        r"(?i)\b(?:GZipStream|DeflateStream|CompressionStream|gzip|deflate|zlib|Brotli|ZipArchive)\b",
        severity="medium",
        confidence=0.73,
        operation="pack",
        description="Compression primitives that may support payload hiding.",
    ),
    _p(
        "packed_binary_terms",
        "packing",
        r"(?i)\b(?:UPX|Themida|VMProtect|Enigma Protector|packed\s+binary|packer|PE\s+packer)\b",
        severity="high",
        confidence=0.90,
        operation="pack",
        description="Executable packing/protection references.",
    ),
    _p(
        "encrypted_payload",
        "encryption",
        r"(?i)\b(?:AES|AesManaged|Rijndael|RC4|ChaCha20|CryptEncrypt|CryptDecrypt|System\.Security\.Cryptography)\b.{0,180}(?:payload|shellcode|command|script|blob|data)",
        severity="high",
        confidence=0.88,
        operation="obfuscate",
        description="Encryption associated with payload or command material.",
    ),
    _p(
        "long_encoded_blob",
        "string_obfuscation",
        r"(?i)\b[A-Za-z0-9+/]{120,}={0,2}\b",
        severity="medium",
        confidence=0.72,
        operation="obfuscate",
        description="Large base64-like static blob.",
    ),
    _p(
        "hex_encoded_blob",
        "string_obfuscation",
        r"(?i)\b(?:[0-9A-F]{2}){40,}\b",
        severity="medium",
        confidence=0.70,
        operation="obfuscate",
        description="Large hexadecimal-like static blob.",
    ),
    # -----------------------------------------------------------------------
    # Artifact cleanup / anti-forensics
    # -----------------------------------------------------------------------
    _p(
        "file_deletion",
        "file_deletion",
        r"(?i)\b(?:del|erase|rm|Remove-Item|DeleteFile(?:A|W)?|unlink|os\.remove|os\.unlink)\b.{0,180}(?:/q|/f|temp|log|history|artifact|trace|staged|payload)",
        severity="high",
        confidence=0.90,
        operation="cleanup",
        description="File deletion associated with cleanup or artifact removal.",
    ),
    _p(
        "self_delete",
        "artifact_cleanup",
        r"(?i)\b(?:self.?delete|delete\s+(?:itself|self)|delete\s+after\s+execution|cleanup\s+after\s+execution)\b",
        severity="high",
        confidence=0.94,
        operation="cleanup",
        description="Explicit self-deletion behavior.",
    ),
    _p(
        "history_cleanup",
        "history_cleanup",
        r"(?i)\b(?:Clear-History|history\s+(?:-c|clear)|Remove-Item).{0,150}(?:ConsoleHost_history|PSReadLine|history)",
        severity="high",
        confidence=0.92,
        operation="cleanup",
        description="Shell command-history cleanup.",
        platform="windows",
    ),
    _p(
        "browser_artifact_cleanup",
        "artifact_cleanup",
        r"(?i)\b(?:delete|remove|clear|wipe)\b.{0,150}(?:Cookies|History|Cache|browser\s+history|Chrome|Firefox|Edge)",
        severity="high",
        confidence=0.86,
        operation="cleanup",
        description="Browser artifact cleanup.",
    ),
    _p(
        "log_cleanup",
        "log_cleanup",
        r"(?i)\b(?:wevtutil\s+cl|Clear-EventLog|rm\s+-f|truncate\s+-s\s*0|clear\s+log|delete\s+logs?)\b",
        severity="high",
        confidence=0.93,
        operation="cleanup",
        description="Log deletion/clearing references.",
    ),
    _p(
        "timestamp_manipulation",
        "timestamp_manipulation",
        r"(?i)\b(?:SetFileTime|touch\s+-t|touch\s+-r|timestamp\s+(?:change|modify|spoof)|timestomp|MACB|creation\s+time)\b",
        severity="high",
        confidence=0.90,
        operation="modify",
        description="File timestamp manipulation references.",
    ),
    _p(
        "anti_forensics_terms",
        "anti_forensics",
        r"(?i)\b(?:anti.?forensics|cover\s+tracks|erase\s+traces|remove\s+artifacts|wipe\s+artifacts|destroy\s+evidence)\b",
        severity="high",
        confidence=0.94,
        operation="cleanup",
        description="Explicit anti-forensics terminology.",
    ),
    # -----------------------------------------------------------------------
    # Timing / connectivity / locale awareness
    # -----------------------------------------------------------------------
    _p(
        "sleep_delay",
        "sleep_delay",
        r"(?i)\b(?:Sleep|Thread\.Sleep|Start-Sleep|time\.sleep|sleep\s+\d{3,}|ping\s+-n\s+\d+)\b",
        severity="low",
        confidence=0.60,
        operation="delay",
        description="Delay/sleep constructs that may support timing evasion.",
    ),
    _p(
        "long_sleep",
        "timing_evasion",
        r"(?i)\b(?:Sleep|Start-Sleep|time\.sleep|sleep)\s*(?:\(|-Seconds\s+)?(?:[3-9]\d{2,}|[1-9]\d{3,})",
        severity="medium",
        confidence=0.78,
        operation="delay",
        description="Long static delay references.",
    ),
    _p(
        "connectivity_check",
        "connectivity_checks",
        r"(?i)\b(?:Test-Connection|ping|InternetGetConnectedState|NetworkInterface\.GetIsNetworkAvailable|requests\.get|curl|wget)\b.{0,150}(?:connect|internet|online|available|connectivity)",
        severity="medium",
        confidence=0.78,
        operation="detect",
        description="Connectivity checks that may gate execution.",
    ),
    _p(
        "locale_detection",
        "locale_awareness",
        r"(?i)\b(?:Get-Culture|CurrentCulture|CurrentUICulture|GetLocaleInfo|GetUserDefaultLocaleName|locale\.getdefaultlocale|LC_ALL|LANG=)\b",
        severity="medium",
        confidence=0.77,
        operation="detect",
        description="Locale/language awareness.",
    ),
    _p(
        "language_filter",
        "language_awareness",
        r"(?i)(?:language|locale|culture).{0,120}(?:exit|quit|terminate|abort|skip|if\s+not)",
        severity="high",
        confidence=0.86,
        operation="gate",
        description="Locale/language checks that condition execution.",
    ),
    _p(
        "hostname_awareness",
        "hostname_awareness",
        r"(?i)\b(?:GetComputerName(?:A|W)?|hostname|Environment\.MachineName|socket\.gethostname|uname\s+-n)\b",
        severity="low",
        confidence=0.64,
        operation="detect",
        description="Hostname/environment awareness.",
    ),
    _p(
        "username_awareness",
        "username_awareness",
        r"(?i)\b(?:whoami|Environment\.UserName|USERNAME|USER|GetUserName(?:A|W)?|$env:USERNAME)\b",
        severity="low",
        confidence=0.63,
        operation="detect",
        description="Username/environment awareness.",
    ),
    _p(
        "domain_awareness",
        "domain_awareness",
        r"(?i)\b(?:USERDOMAIN|GetComputerDomain|DomainName|LOGONSERVER|System\.DirectoryServices|ActiveDirectory)\b",
        severity="medium",
        confidence=0.72,
        operation="detect",
        description="Domain/environment awareness.",
        platform="windows",
    ),
    # -----------------------------------------------------------------------
    # UAC / privilege / policy bypass
    # -----------------------------------------------------------------------
    _p(
        "uac_bypass_terms",
        "uac_bypass",
        r"(?i)\b(?:UAC\s*bypass|fodhelper|eventvwr|computerdefaults|sdclt|cmstp|SilentCleanup|ms-settings)\b",
        severity="critical",
        confidence=0.96,
        operation="bypass",
        description="Known UAC bypass references.",
        platform="windows",
    ),
    _p(
        "token_manipulation",
        "privilege_abuse",
        r"(?i)\b(?:OpenProcessToken|DuplicateToken(?:Ex)?|ImpersonateLoggedOnUser|SetThreadToken|AdjustTokenPrivileges|SeDebugPrivilege|SeImpersonatePrivilege)\b",
        severity="high",
        confidence=0.91,
        operation="bypass",
        description="Token/privilege manipulation references.",
        platform="windows",
    ),
    # -----------------------------------------------------------------------
    # Network/proxy evasion
    # -----------------------------------------------------------------------
    _p(
        "proxy_detection",
        "proxy_awareness",
        r"(?i)\b(?:HTTP_PROXY|HTTPS_PROXY|ALL_PROXY|WinHttpGetIEProxyConfigForCurrentUser|InternetQueryOption|proxy(?:\s+|_)(?:server|config|settings))\b",
        severity="medium",
        confidence=0.76,
        operation="detect",
        description="Proxy configuration awareness.",
    ),
    _p(
        "network_environment_detection",
        "network_evasion",
        r"(?i)\b(?:GetAdaptersInfo|GetAdaptersAddresses|NetworkInterface\.GetAllNetworkInterfaces|ipconfig|ifconfig|netstat|route\s+print)\b.{0,120}(?:detect|check|avoid|block|allow|environment)",
        severity="medium",
        confidence=0.78,
        operation="detect",
        description="Network environment checks that may support execution gating.",
    ),
    # -----------------------------------------------------------------------
    # Generic explicit anti-analysis language
    # -----------------------------------------------------------------------
    _p(
        "anti_analysis_terms",
        "anti_analysis",
        r"(?i)\b(?:anti.?analysis|anti.?debug|anti.?debugging|anti.?sandbox|anti.?vm|anti.?emulation|analysis\s+detection|debugger\s+detection)\b",
        severity="high",
        confidence=0.95,
        operation="detect",
        description="Explicit anti-analysis terminology.",
    ),
    _p(
        "evasion_terms",
        "evasion",
        r"(?i)\b(?:evade|evasion|bypass\s+detection|avoid\s+detection|detection\s+evasion|stealth|cover\s+tracks)\b",
        severity="medium",
        confidence=0.82,
        operation="evade",
        description="Explicit evasion terminology.",
    ),
)


_COMPILED_PATTERNS: Tuple[Tuple[EvasionPattern, re.Pattern[str]]] = tuple(
    (pattern, re.compile(pattern.regex)) for pattern in PATTERNS
)


# ---------------------------------------------------------------------------
# Contextual helpers
# ---------------------------------------------------------------------------


_OPERATION_PATTERNS: Tuple[Tuple[str, re.Pattern[str]]] = (
    (
        "detect",
        re.compile(
            r"(?i)\b(?:detect|check|test|identify|determine|query|inspect|discover)\b"
        ),
    ),
    (
        "impair",
        re.compile(
            r"(?i)\b(?:disable|stop|kill|block|bypass|patch|hook|unhook|impair|turn\s+off)\b"
        ),
    ),
    (
        "cleanup",
        re.compile(
            r"(?i)\b(?:delete|remove|clear|wipe|erase|destroy|cleanup|clean\s+up)\b"
        ),
    ),
    (
        "obfuscate",
        re.compile(
            r"(?i)\b(?:obfuscat|encode|decode|encrypt|decrypt|pack|compress|hide)\w*\b"
        ),
    ),
    (
        "inject",
        re.compile(r"(?i)\b(?:inject|injection|hollow|hollowing|remote\s+thread)\w*\b"),
    ),
    (
        "bypass",
        re.compile(r"(?i)\b(?:bypass|circumvent|elevat|impersonat|spoof)\w*\b"),
    ),
    (
        "manipulate",
        re.compile(r"(?i)\b(?:manipulat|modify|overwrite|replace|restore|change)\w*\b"),
    ),
    (
        "hide",
        re.compile(r"(?i)\b(?:hide|hidden|invisible|silent|stealth)\w*\b"),
    ),
    (
        "delay",
        re.compile(r"(?i)\b(?:sleep|delay|wait|pause)\w*\b"),
    ),
    (
        "resolve",
        re.compile(r"(?i)\b(?:resolve|lookup|GetProcAddress|GetModuleHandle)\w*\b"),
    ),
    (
        "load",
        re.compile(r"(?i)\b(?:load|LoadLibrary|dlopen)\w*\b"),
    ),
)


_PLATFORM_PATTERNS: Tuple[Tuple[str, re.Pattern[str]]] = (
    (
        "windows",
        re.compile(
            r"(?i)(?:\bWindows\b|Win32|PowerShell|cmd\.exe|HKLM|HKCU|"
            r"C:\\|%APPDATA%|%TEMP%|ntdll\.dll|kernel32\.dll)"
        ),
    ),
    (
        "linux",
        re.compile(r"(?i)(?:\bLinux\b|/proc/|/sys/|/etc/|/var/log/|bash\b|systemd)"),
    ),
    (
        "macos",
        re.compile(r"(?i)(?:\bmacOS\b|/Users/|/Library/|osascript|launchctl)"),
    ),
    (
        "cloud",
        re.compile(r"(?i)(?:AWS|Azure|GCP|Google Cloud|Kubernetes)"),
    ),
)


_LOCATION_PATTERNS: Tuple[Tuple[str, re.Pattern[str]]] = (
    (
        "windows_security_paths",
        re.compile(
            r"(?i)(?:Windows\\System32\\(?:winevt|wbem)|"
            r"Windows Defender|Microsoft Defender|AMSI|ETW|ntdll\.dll)"
        ),
    ),
    (
        "windows_temp",
        re.compile(r"(?i)(?:%TEMP%|%TMP%|\\Temp\\|\\AppData\\Local\\Temp\\)"),
    ),
    (
        "windows_registry",
        re.compile(r"(?i)(?:HKLM\\|HKCU\\|HKEY_LOCAL_MACHINE\\|HKEY_CURRENT_USER\\)"),
    ),
    (
        "analysis_tools",
        re.compile(
            r"(?i)(?:x64dbg|x32dbg|WinDbg|OllyDbg|IDA(?:\s+Pro)?|Ghidra|"
            r"ProcessHacker|Procmon|Wireshark|Fiddler|Cuckoo|Any\.Run)"
        ),
    ),
    (
        "virtualization",
        re.compile(r"(?i)(?:VMware|VirtualBox|QEMU|Hyper-V|Parallels|Xen)"),
    ),
    (
        "browser_artifacts",
        re.compile(
            r"(?i)(?:Chrome\\User Data|Microsoft\\Edge\\User Data|"
            r"Mozilla\\Firefox\\Profiles)"
        ),
    ),
)


def _infer_operation(
    text: str,
    default: str = "unknown",
) -> str:
    """Infer the strongest operation represented by an evidence excerpt."""
    for operation, pattern in _OPERATION_PATTERNS:
        if pattern.search(text):
            return operation

    return default


def _infer_platform(
    text: str,
    default: str = "cross-platform",
) -> str:
    """Infer platform from static vocabulary."""
    matches = [
        platform for platform, pattern in _PLATFORM_PATTERNS if pattern.search(text)
    ]

    if not matches:
        return default

    if len(matches) == 1:
        return matches[0]

    if "cloud" in matches and len(matches) == 1:
        return "cloud"

    return "cross-platform"


def _find_location(
    text: str,
) -> Optional[str]:
    """Return the first recognizable static evasion-related location."""
    for _, pattern in _LOCATION_PATTERNS:
        match = pattern.search(text)

        if match:
            return match.group(0)[:MAX_FIELD_TEXT]

    return None


def _weak_pattern(
    pattern: EvasionPattern,
) -> bool:
    """Identify indicators that should receive conservative treatment."""
    return pattern.name in {
        "virtual_machine_terms",
        "sleep_delay",
        "hostname_awareness",
        "username_awareness",
        "system_information_commands",
        "dynamic_api_resolution",
        "dynamic_module_loading",
        "hex_transformation",
        "compressed_payload",
        "security_product_discovery",
        "document_extensions",
    }


def _contextual_confidence(
    pattern: EvasionPattern,
    excerpt: str,
) -> float:
    """Adjust static confidence using bounded contextual evidence."""
    confidence = pattern.confidence

    strong_terms = (
        r"\b(?:bypass|disable|evade|avoid|detect|debugger|sandbox|virtual)" r"\b",
        r"\b(?:cleanup|delete|clear|wipe|unhook|patch|impair)\w*\b",
        r"\b(?:hidden|silent|stealth|masquerad)\w*\b",
    )

    if any(re.search(term, excerpt, re.I) for term in strong_terms):
        confidence += 0.04

    if _weak_pattern(pattern):
        confidence -= 0.08

    return max(
        0.05,
        min(1.0, confidence),
    )


# ---------------------------------------------------------------------------
# Evidence extraction
# ---------------------------------------------------------------------------


def _extract_pattern_evidence(
    text: str,
) -> List[EvasionEvidence]:
    """Apply static evasion rules to supplied text."""
    evidence: List[EvasionEvidence] = []

    for pattern, compiled in _COMPILED_PATTERNS:
        matches = 0

        for match in compiled.finditer(text):
            if matches >= MAX_MATCHES_PER_RULE:
                break

            excerpt = _safe_excerpt(
                text,
                match.start(),
                match.end(),
            )

            evidence.append(
                EvasionEvidence(
                    category=pattern.category,
                    indicator=pattern.name,
                    evidence=excerpt,
                    source="static_pattern",
                    line_number=_line_number(
                        text,
                        match.start(),
                    ),
                    operation=_infer_operation(
                        excerpt,
                        default=pattern.operation,
                    ),
                    location=_find_location(excerpt),
                    platform=_infer_platform(
                        excerpt,
                        default=pattern.platform,
                    ),
                    confidence=_contextual_confidence(
                        pattern,
                        excerpt,
                    ),
                    severity=pattern.severity,
                )
            )

            matches += 1

            if len(evidence) >= MAX_EVIDENCE_ITEMS:
                return evidence

    return evidence


def _deduplicate_evidence(
    evidence: Iterable[EvasionEvidence],
) -> List[EvasionEvidence]:
    """Deduplicate evidence while preserving order."""
    result: List[EvasionEvidence] = []
    seen: Set[Tuple[Any, ...]] = set()

    for item in evidence:
        key = (
            item.category,
            item.indicator,
            item.evidence,
            item.line_number,
            item.location,
        )

        if key in seen:
            continue

        seen.add(key)
        result.append(item)

        if len(result) >= MAX_EVIDENCE_ITEMS:
            break

    return result


def _derive_records(
    evidence: Sequence[EvasionEvidence],
) -> List[EvasionRecord]:
    """Normalize evidence into bounded evasion records."""
    records: List[EvasionRecord] = []
    seen: Set[Tuple[Any, ...]] = set()

    for item in evidence:
        key = (
            item.indicator,
            item.category,
            item.location,
            item.operation,
            item.platform,
        )

        if key in seen:
            continue

        seen.add(key)

        records.append(
            EvasionRecord(
                mechanism=item.indicator,
                category=item.category,
                location=item.location,
                operation=item.operation,
                platform=item.platform,
                indicator=item.indicator,
                evidence=item.evidence,
                severity=item.severity,
                confidence=item.confidence,
            )
        )

        if len(records) >= MAX_EVASION_RECORDS:
            break

    return records


def _derive_locations(
    evidence: Sequence[EvasionEvidence],
) -> List[str]:
    """Return unique static locations."""
    locations: List[str] = []
    seen: Set[str] = set()

    for item in evidence:
        if not item.location:
            continue

        location = item.location[:MAX_FIELD_TEXT]

        if location in seen:
            continue

        seen.add(location)
        locations.append(location)

        if len(locations) >= MAX_LOCATIONS:
            break

    return locations


# ---------------------------------------------------------------------------
# Higher-level combinations
# ---------------------------------------------------------------------------


def _derive_combinations(
    categories: Set[str],
    evidence: Sequence[EvasionEvidence],
) -> List[EvasionCombination]:
    """Derive higher-confidence evasion behavior chains."""
    combinations: List[EvasionCombination] = []

    operations = {item.operation for item in evidence}

    def add(
        name: str,
        required: Tuple[str, ...],
        explanation: str,
        present: bool,
    ) -> None:
        combinations.append(
            EvasionCombination(
                name=name,
                present=present,
                required_categories=required,
                explanation=explanation,
            )
        )

    add(
        "anti_analysis_chain",
        (
            "anti_analysis",
            "anti_debugging",
        ),
        "Explicit anti-analysis terminology is combined with debugger detection.",
        "anti_analysis" in categories and "anti_debugging" in categories,
    )

    add(
        "sandbox_detection_chain",
        (
            "anti_sandbox",
            "sandbox_artifact_check",
        ),
        "Sandbox terminology and sandbox-artifact checks are both present.",
        "anti_sandbox" in categories and "sandbox_artifact_check" in categories,
    )

    add(
        "virtualization_detection_chain",
        (
            "anti_vm",
            "virtualization_artifact_check",
        ),
        "Virtualization terminology is combined with VM artifact checks.",
        "anti_vm" in categories and "virtualization_artifact_check" in categories,
    )

    add(
        "security_impairment",
        (
            "security_software_discovery",
            "security_software_impairment",
        ),
        "Security software is identified and impairment behavior is also present.",
        "security_software_discovery" in categories
        and "security_software_impairment" in categories,
    )

    add(
        "defender_impairment_chain",
        ("defender_impairment",),
        "Explicit Microsoft Defender protection impairment is present.",
        "defender_impairment" in categories,
    )

    add(
        "amsi_etw_impairment",
        (
            "amsi_impairment",
            "etw_impairment",
        ),
        "Both AMSI and ETW impairment indicators are present.",
        "amsi_impairment" in categories and "etw_impairment" in categories,
    )

    add(
        "logging_cleanup",
        (
            "logging_impairment",
            "log_cleanup",
        ),
        "Logging impairment and artifact cleanup indicators are combined.",
        "logging_impairment" in categories and "log_cleanup" in categories,
    )

    add(
        "hidden_process_execution",
        (
            "hidden_execution",
            "hidden_window",
        ),
        "Explicit hidden execution is combined with hidden-window configuration.",
        "hidden_execution" in categories and "hidden_window" in categories,
    )

    add(
        "process_injection_evasion",
        (
            "process_injection",
            "memory_evasion",
        ),
        "Process injection is combined with memory-protection manipulation.",
        "process_injection" in categories and "memory_evasion" in categories,
    )

    add(
        "process_hollowing_evasion",
        ("process_hollowing",),
        "Process hollowing indicators are present.",
        "process_hollowing" in categories,
    )

    add(
        "parent_process_evasion",
        ("parent_process_manipulation",),
        "Parent-process manipulation indicators are present.",
        "parent_process_manipulation" in categories,
    )

    add(
        "dynamic_resolution_evasion",
        (
            "api_resolution",
            "dynamic_resolution",
        ),
        "Dynamic API resolution is combined with broader dynamic-resolution behavior.",
        "api_resolution" in categories and "dynamic_resolution" in categories,
    )

    add(
        "obfuscated_execution",
        (
            "obfuscation",
            "dynamic_resolution",
        ),
        "Obfuscation and dynamic resolution are both represented.",
        "obfuscation" in categories and "dynamic_resolution" in categories,
    )

    add(
        "script_obfuscation_chain",
        (
            "script_obfuscation",
            "powershell_obfuscation",
        ),
        "Script obfuscation indicators include PowerShell-specific obfuscation.",
        "script_obfuscation" in categories and "powershell_obfuscation" in categories,
    )

    add(
        "encoded_payload_chain",
        (
            "encoding",
            "obfuscation",
        ),
        "Encoding is combined with an explicit obfuscation signal.",
        "encoding" in categories and "obfuscation" in categories,
    )

    add(
        "payload_packing_chain",
        (
            "packing",
            "compression",
        ),
        "Executable packing is combined with compression behavior.",
        "packing" in categories and "compression" in categories,
    )

    add(
        "cleanup_after_execution",
        (
            "artifact_cleanup",
            "file_deletion",
        ),
        "Artifact cleanup and file deletion are jointly represented.",
        "artifact_cleanup" in categories and "file_deletion" in categories,
    )

    add(
        "anti_forensics_chain",
        (
            "anti_forensics",
            "timestamp_manipulation",
        ),
        "Anti-forensics terminology is combined with timestamp manipulation.",
        "anti_forensics" in categories and "timestamp_manipulation" in categories,
    )

    add(
        "environment_gated_execution",
        (
            "environment_awareness",
            "locale_awareness",
        ),
        "Environment/locale awareness can be used to gate behavior.",
        "environment_awareness" in categories and "locale_awareness" in categories,
    )

    add(
        "timing_evasion_chain",
        (
            "sleep_delay",
            "timing_evasion",
        ),
        "Delay behavior is sufficiently strong to indicate timing-based evasion.",
        "sleep_delay" in categories and "timing_evasion" in categories,
    )

    add(
        "connectivity_gated_execution",
        ("connectivity_checks",),
        "Connectivity checks may condition subsequent behavior.",
        "connectivity_checks" in categories,
    )

    add(
        "uac_bypass_chain",
        (
            "uac_bypass",
            "privilege_abuse",
        ),
        "UAC bypass indicators are combined with token/privilege manipulation.",
        "uac_bypass" in categories and "privilege_abuse" in categories,
    )

    add(
        "security_and_cleanup_evasion",
        (
            "security_software_impairment",
            "artifact_cleanup",
        ),
        "Security impairment is combined with post-operation artifact cleanup.",
        "security_software_impairment" in categories
        and "artifact_cleanup" in categories,
    )

    add(
        "multi_layer_evasion",
        (
            "anti_debugging",
            "obfuscation",
            "artifact_cleanup",
        ),
        "Multiple independent evasion layers are represented.",
        sum(
            int(category in categories)
            for category in (
                "anti_debugging",
                "anti_vm",
                "anti_sandbox",
                "obfuscation",
                "artifact_cleanup",
                "security_software_impairment",
                "process_injection",
                "hidden_execution",
            )
        )
        >= 3,
    )

    add(
        "evasion_with_impairment",
        (
            "evasion",
            "security_software_impairment",
        ),
        "Generic evasion terminology is accompanied by security-control impairment.",
        "evasion" in categories and "security_software_impairment" in categories,
    )

    add(
        "detection_then_bypass",
        (
            "environment_awareness",
            "evasion",
        ),
        "Environment detection is combined with an explicit evasion operation.",
        (
            bool(
                categories
                & {
                    "anti_debugging",
                    "anti_vm",
                    "anti_sandbox",
                    "environment_awareness",
                    "security_software_discovery",
                    "connectivity_checks",
                    "locale_awareness",
                }
            )
            and (
                "bypass" in operations
                or "evade" in operations
                or "impair" in operations
            )
        ),
    )

    return combinations


# ---------------------------------------------------------------------------
# Signal scoring
# ---------------------------------------------------------------------------


def _derive_signal_score(
    evidence: Sequence[EvasionEvidence],
    combinations: Sequence[EvasionCombination],
) -> float:
    """Calculate a bounded heuristic evasion signal score."""
    score = 0.0

    for item in evidence:
        score += SEVERITY_WEIGHTS.get(
            item.severity,
            1.0,
        )

        if item.operation in {
            "impair",
            "bypass",
            "inject",
            "cleanup",
            "obfuscate",
        }:
            score += 1.0

        if item.operation in {
            "detect",
            "hide",
            "manipulate",
        }:
            score += 0.35

        score += (
            max(
                0.0,
                item.confidence - 0.5,
            )
            * 0.75
        )

        score *= 0.9995

    for combination in combinations:
        if combination.present:
            score += 4.5

    return round(
        min(100.0, max(0.0, score)),
        4,
    )


# ---------------------------------------------------------------------------
# Feature vector
# ---------------------------------------------------------------------------


def _build_feature_vector(
    source_size: int,
    records: Sequence[EvasionRecord],
    evidence: Sequence[EvasionEvidence],
    indicators: Sequence[str],
    categories: Sequence[str],
    combinations: Sequence[EvasionCombination],
    locations: Sequence[str],
    platforms: Sequence[str],
) -> Dict[str, float]:
    """Build a stable numeric feature vector."""
    vector: Dict[str, float] = {}

    vector["source_size"] = float(source_size)
    vector["record_count"] = float(len(records))
    vector["evidence_count"] = float(len(evidence))
    vector["location_count"] = float(len(locations))
    vector["platform_count"] = float(len(platforms))
    vector["indicator_count"] = float(len(indicators))
    vector["category_count"] = float(len(categories))
    vector["combination_count"] = float(sum(1 for item in combinations if item.present))

    severity_counts = Counter(item.severity for item in evidence)

    for severity in (
        "low",
        "medium",
        "high",
        "critical",
    ):
        vector[f"{severity}_count"] = float(severity_counts.get(severity, 0))

    operation_counts = Counter(item.operation for item in records)

    operations = (
        "detect",
        "impair",
        "cleanup",
        "obfuscate",
        "inject",
        "bypass",
        "manipulate",
        "hide",
        "delay",
        "resolve",
        "load",
        "pack",
        "encode",
        "unknown",
    )

    for operation in operations:
        vector[f"{operation}_count"] = float(
            operation_counts.get(
                operation,
                0,
            )
        )

    platform_counts = Counter(item.platform for item in records)

    for platform in (
        "windows",
        "linux",
        "macos",
        "cloud",
        "cross-platform",
    ):
        vector[f"{platform.replace('-', '_')}_count"] = float(
            platform_counts.get(
                platform,
                0,
            )
        )

    category_counts = Counter(item.category for item in evidence)

    for category in EVASION_CATEGORIES:
        vector[f"category_{category}_present"] = float(
            category_counts.get(
                category,
                0,
            )
            > 0
        )

        vector[f"category_{category}_count"] = float(
            category_counts.get(
                category,
                0,
            )
        )

    indicator_counts = Counter(item.indicator for item in evidence)

    all_indicators = sorted(
        {pattern.name for pattern in PATTERNS} | set(indicator_counts)
    )

    for indicator in all_indicators:
        vector[f"indicator_{indicator}_present"] = float(
            indicator_counts.get(
                indicator,
                0,
            )
            > 0
        )

        vector[f"indicator_{indicator}_count"] = float(
            indicator_counts.get(
                indicator,
                0,
            )
        )

    for combination in combinations:
        vector[f"combination_{combination.name}_present"] = float(combination.present)

    vector["evasion_signal_score"] = _derive_signal_score(
        evidence,
        combinations,
    )

    return vector


def evasion_feature_names() -> List[str]:
    """Return the stable feature names produced by this extractor."""
    empty_combinations = _derive_combinations(
        set(),
        [],
    )

    vector = _build_feature_vector(
        source_size=0,
        records=[],
        evidence=[],
        indicators=[],
        categories=[],
        combinations=empty_combinations,
        locations=[],
        platforms=[],
    )

    return list(vector.keys())


def build_feature_schema() -> Dict[str, Any]:
    """Return a machine-readable schema for ML integration."""
    return {
        "schema_version": "1.0",
        "feature_type": "static_evasion_behavior",
        "features": [
            {
                "name": name,
                "type": "float",
                "description": ("Stable static evasion-behavior feature."),
            }
            for name in evasion_feature_names()
        ],
    }


def vectorize_features(
    analysis: EvasionAnalysis,
    feature_names: Optional[Sequence[str]] = None,
) -> List[float]:
    """
    Convert an analysis into an ordered numeric vector.

    Missing externally requested features are represented as zero.
    """
    names = (
        list(feature_names) if feature_names is not None else evasion_feature_names()
    )

    return [
        float(
            analysis.feature_vector.get(
                name,
                0.0,
            )
        )
        for name in names
    ]


# ---------------------------------------------------------------------------
# Public analysis API
# ---------------------------------------------------------------------------


def analyze_evasion_behavior(
    source: SourceLike,
) -> EvasionAnalysis:
    """
    Perform static evasion-behavior analysis.

    No detected behavior is executed or reproduced.
    """
    text, source_size, source_kind = _read_source(source)

    if len(text) > MAX_TEXT_CHARS:
        text = text[:MAX_TEXT_CHARS]

    source_hash = _sha256_text(text)

    evidence = _extract_pattern_evidence(text)
    evidence = _deduplicate_evidence(evidence)

    records = _derive_records(evidence)

    indicators = sorted({item.indicator for item in evidence})

    categories = sorted({item.category for item in evidence})

    locations = _derive_locations(evidence)

    platforms = sorted({item.platform for item in evidence if item.platform})

    combinations = _derive_combinations(
        set(categories),
        evidence,
    )

    feature_vector = _build_feature_vector(
        source_size=source_size,
        records=records,
        evidence=evidence,
        indicators=indicators,
        categories=categories,
        combinations=combinations,
        locations=locations,
        platforms=platforms,
    )

    metadata = {
        "schema_version": "1.0",
        "analyzer": "pharos-cdr.static-evasion",
        "static_only": True,
        "source_kind": source_kind,
        "text_length": len(text),
        "truncated": len(text) >= MAX_TEXT_CHARS,
        "pattern_count": len(PATTERNS),
        "evidence_truncated": (len(evidence) >= MAX_EVIDENCE_ITEMS),
        "record_truncated": (len(records) >= MAX_EVASION_RECORDS),
        "location_truncated": (len(locations) >= MAX_LOCATIONS),
        "present_combination_count": sum(1 for item in combinations if item.present),
        "signal_score": feature_vector.get(
            "evasion_signal_score",
            0.0,
        ),
    }

    return EvasionAnalysis(
        source_hash=source_hash,
        source_size=source_size,
        records=records,
        evidence=evidence,
        indicators=indicators,
        categories=categories,
        combinations=combinations,
        locations=locations,
        platforms=platforms,
        feature_vector=feature_vector,
        metadata=metadata,
    )


def analyze_evasion(
    source: SourceLike,
) -> EvasionAnalysis:
    """Alias for analyze_evasion_behavior."""
    return analyze_evasion_behavior(source)


def analyze(
    source: SourceLike,
) -> EvasionAnalysis:
    """Short analysis alias."""
    return analyze_evasion_behavior(source)


def parse_evasion_behavior(
    source: SourceLike,
) -> EvasionAnalysis:
    """Compatibility parser alias."""
    return analyze_evasion_behavior(source)


def extract_evasion_features(
    source: SourceLike,
) -> EvasionAnalysis:
    """Return a complete static evasion analysis."""
    return analyze_evasion_behavior(source)


def extract_feature_vector(
    source: SourceLike,
) -> Dict[str, float]:
    """Return the ML-ready evasion feature mapping."""
    return analyze_evasion_behavior(source).feature_vector


def extract_evasion_feature_vector(
    source: SourceLike,
) -> Dict[str, float]:
    """Explicit evasion feature-vector alias."""
    return extract_feature_vector(source)


def extract_evasion_records(
    source: SourceLike,
) -> List[EvasionRecord]:
    """Return normalized evasion records."""
    return analyze_evasion_behavior(source).records


# ---------------------------------------------------------------------------
# Query helpers
# ---------------------------------------------------------------------------


def has_indicator(
    analysis: EvasionAnalysis,
    indicator: str,
) -> bool:
    """Return whether an indicator is present."""
    target = indicator.strip().lower()

    return any(value.lower() == target for value in analysis.indicators)


def has_category(
    analysis: EvasionAnalysis,
    category: str,
) -> bool:
    """Return whether a category is present."""
    target = category.strip().lower()

    return any(value.lower() == target for value in analysis.categories)


def indicator_count(
    analysis: EvasionAnalysis,
    indicator: str,
) -> int:
    """Count evidence items associated with an indicator."""
    target = indicator.strip().lower()

    return sum(1 for item in analysis.evidence if item.indicator.lower() == target)


def category_count(
    analysis: EvasionAnalysis,
    category: str,
) -> int:
    """Count evidence items associated with a category."""
    target = category.strip().lower()

    return sum(1 for item in analysis.evidence if item.category.lower() == target)


def evidence_by_category(
    analysis: EvasionAnalysis,
    category: str,
) -> List[EvasionEvidence]:
    """Return evidence belonging to a category."""
    target = category.strip().lower()

    return [item for item in analysis.evidence if item.category.lower() == target]


def evidence_by_indicator(
    analysis: EvasionAnalysis,
    indicator: str,
) -> List[EvasionEvidence]:
    """Return evidence belonging to an indicator."""
    target = indicator.strip().lower()

    return [item for item in analysis.evidence if item.indicator.lower() == target]


def high_risk_evidence(
    analysis: EvasionAnalysis,
) -> List[EvasionEvidence]:
    """Return high and critical evasion evidence."""
    return [
        item
        for item in analysis.evidence
        if SEVERITY_ORDER.get(
            item.severity,
            0,
        )
        >= 2
    ]


def present_combinations(
    analysis: EvasionAnalysis,
) -> List[EvasionCombination]:
    """Return only satisfied higher-level combinations."""
    return [item for item in analysis.combinations if item.present]


def highest_severity(
    analysis: EvasionAnalysis,
) -> str:
    """Return the highest observed evidence severity."""
    if not analysis.evidence:
        return "low"

    return max(
        (item.severity for item in analysis.evidence),
        key=lambda value: SEVERITY_ORDER.get(
            value,
            0,
        ),
    )


# ---------------------------------------------------------------------------
# Serialization and summaries
# ---------------------------------------------------------------------------


def analysis_to_dict(
    analysis: EvasionAnalysis,
) -> Dict[str, Any]:
    """Serialize an analysis into JSON-compatible structures."""
    return asdict(analysis)


def summarize_evasion_behavior(
    analysis: EvasionAnalysis,
) -> Dict[str, Any]:
    """Return a compact report-oriented summary."""
    severity_counts = Counter(item.severity for item in analysis.evidence)

    operation_counts = Counter(item.operation for item in analysis.records)

    return {
        "source_hash": analysis.source_hash,
        "source_size": analysis.source_size,
        "signal_score": analysis.feature_vector.get(
            "evasion_signal_score",
            0.0,
        ),
        "highest_severity": highest_severity(analysis),
        "record_count": len(analysis.records),
        "evidence_count": len(analysis.evidence),
        "indicator_count": len(analysis.indicators),
        "category_count": len(analysis.categories),
        "location_count": len(analysis.locations),
        "platforms": list(analysis.platforms),
        "categories": list(analysis.categories),
        "indicators": list(analysis.indicators),
        "present_combinations": [item.name for item in present_combinations(analysis)],
        "severity_counts": dict(severity_counts),
        "operation_counts": dict(operation_counts),
        "high_risk_evidence_count": len(high_risk_evidence(analysis)),
    }


# ---------------------------------------------------------------------------
# Iterators
# ---------------------------------------------------------------------------


def iter_evidence(
    analysis: EvasionAnalysis,
) -> Iterator[EvasionEvidence]:
    """Iterate over all evasion evidence."""
    yield from analysis.evidence


def iter_high_risk_evidence(
    analysis: EvasionAnalysis,
) -> Iterator[EvasionEvidence]:
    """Iterate over high/critical evidence."""
    yield from high_risk_evidence(analysis)


def iter_records(
    analysis: EvasionAnalysis,
) -> Iterator[EvasionRecord]:
    """Iterate over normalized evasion records."""
    yield from analysis.records


def iter_combinations(
    analysis: EvasionAnalysis,
    *,
    present_only: bool = False,
) -> Iterator[EvasionCombination]:
    """Iterate over derived evasion combinations."""
    for item in analysis.combinations:
        if present_only and not item.present:
            continue

        yield item


def iter_analyses(
    sources: Iterable[SourceLike],
) -> Iterator[EvasionAnalysis]:
    """Analyze supplied sources lazily."""
    for source in sources:
        yield analyze_evasion_behavior(source)


# ---------------------------------------------------------------------------
# Compatibility aliases
# ---------------------------------------------------------------------------


parse = parse_evasion_behavior
extract = extract_evasion_features


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


__all__ = [
    "EvasionPattern",
    "EvasionEvidence",
    "EvasionRecord",
    "EvasionCombination",
    "EvasionAnalysis",
    "analyze_evasion_behavior",
    "analyze_evasion",
    "analyze",
    "parse_evasion_behavior",
    "extract_evasion_features",
    "extract_feature_vector",
    "extract_evasion_feature_vector",
    "evasion_feature_names",
    "build_feature_schema",
    "vectorize_features",
    "extract_evasion_records",
    "has_indicator",
    "has_category",
    "indicator_count",
    "category_count",
    "evidence_by_category",
    "evidence_by_indicator",
    "high_risk_evidence",
    "present_combinations",
    "highest_severity",
    "analysis_to_dict",
    "summarize_evasion_behavior",
    "iter_evidence",
    "iter_high_risk_evidence",
    "iter_records",
    "iter_combinations",
    "iter_analyses",
    "parse",
    "extract",
]
