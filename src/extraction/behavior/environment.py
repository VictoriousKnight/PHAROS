"""
Static environment-behavior extraction.

This module identifies environment-awareness and environment-discovery
indicators from untrusted source material without executing it.

Supported inputs:
    - str
    - bytes / bytearray / memoryview
    - filesystem paths
    - mappings
    - nested lists / tuples / sets
    - arbitrary objects with bounded textual representations

The extractor is intentionally static. It never:
    - executes commands or scripts
    - launches processes
    - queries the live registry
    - reads environment variables from the host
    - contacts the network
    - opens sockets
    - loads DLLs/shared libraries
    - starts COM/WMI
    - modifies the filesystem or registry

The output is designed to integrate with:
    environment.py
        -> feature_pipeline.py
        -> ML / CDR / decision pipeline

Evidence chain:
    textual indicator
        -> environment behavior
        -> capability / anti-analysis interpretation
        -> stable feature vector
        -> downstream policy / ML
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
from collections import Counter
from dataclasses import asdict, dataclass, field, is_dataclass
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
)


# ---------------------------------------------------------------------------
# Safety and resource limits
# ---------------------------------------------------------------------------

MAX_SOURCE_SIZE = 25 * 1024 * 1024
MAX_TEXT_CHARS = 25 * 1024 * 1024
MAX_FIELD_TEXT = 100_000
MAX_EVIDENCE_ITEMS = 20_000
MAX_MATCHES_PER_RULE = 5_000
MAX_NESTING_DEPTH = 12
MAX_ENVIRONMENT_RECORDS = 10_000
MAX_LOCATIONS = 10_000
MAX_COMMAND_LINES = 20_000
MAX_TOKENS = 250_000
MAX_INDICATORS = 20_000
MAX_STRINGS = 20_000
MAX_SNIPPET_LENGTH = 500


# ---------------------------------------------------------------------------
# Taxonomy
# ---------------------------------------------------------------------------

ENVIRONMENT_CATEGORIES: Tuple[str, ...] = (
    "environment_discovery",
    "host_discovery",
    "user_discovery",
    "domain_discovery",
    "computer_name",
    "username",
    "system_identity",
    "os_version",
    "architecture",
    "locale",
    "language",
    "timezone",
    "regional_settings",
    "environment_variables",
    "path_discovery",
    "current_directory",
    "home_directory",
    "temporary_directory",
    "system_directory",
    "program_directory",
    "volume_information",
    "drive_discovery",
    "filesystem_discovery",
    "installed_software",
    "security_software",
    "security_product_discovery",
    "antivirus_discovery",
    "firewall_discovery",
    "virtualization",
    "virtual_machine",
    "hypervisor",
    "sandbox",
    "sandbox_detection",
    "analysis_environment",
    "debugger_detection",
    "debugger_awareness",
    "emulator_detection",
    "container_detection",
    "container_awareness",
    "domain_environment",
    "privilege_discovery",
    "integrity_level",
    "session_discovery",
    "interactive_session",
    "remote_session",
    "rdp_detection",
    "terminal_detection",
    "office_environment",
    "browser_environment",
    "security_policy",
    "execution_environment",
    "environment_gating",
    "anti_analysis",
)


# ---------------------------------------------------------------------------
# Severity ordering
# ---------------------------------------------------------------------------

SEVERITY_ORDER: Dict[str, int] = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class EnvironmentPattern:
    """A static rule describing an environment-related behavior."""

    name: str
    category: str
    regex: str
    severity: str = "medium"
    confidence: float = 0.90
    operation: str = "discover"
    platform: str = "generic"
    description: str = ""


@dataclass
class EnvironmentEvidence:
    """One bounded piece of static evidence."""

    category: str
    indicator: str
    evidence: str
    source: str = "text"
    line_number: Optional[int] = None
    operation: str = "discover"
    platform: str = "generic"
    location: Optional[str] = None
    confidence: float = 1.0
    severity: str = "medium"
    pattern: Optional[str] = None


@dataclass
class EnvironmentRecord:
    """Normalized environment behavior discovered in the input."""

    behavior: str
    category: str
    operation: str
    platform: str
    indicator: str
    evidence: str
    severity: str = "medium"
    confidence: float = 1.0
    location: Optional[str] = None
    line_number: Optional[int] = None


@dataclass
class EnvironmentCombination:
    """A higher-level environment-awareness combination."""

    name: str
    present: bool
    required_categories: Tuple[str, ...] = field(default_factory=tuple)
    explanation: str = ""


@dataclass
class EnvironmentAnalysis:
    """Complete static environment-behavior analysis."""

    source_hash: str
    source_size: int

    records: List[EnvironmentRecord] = field(default_factory=list)
    evidence: List[EnvironmentEvidence] = field(default_factory=list)

    indicators: List[str] = field(default_factory=list)
    categories: List[str] = field(default_factory=list)
    locations: List[str] = field(default_factory=list)
    platforms: List[str] = field(default_factory=list)

    combinations: List[EnvironmentCombination] = field(default_factory=list)

    feature_vector: Dict[str, float] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Pattern vocabulary
# ---------------------------------------------------------------------------

# The patterns deliberately focus on textual references rather than executing
# any of the commands/functions they identify.

ENVIRONMENT_PATTERNS: Tuple[EnvironmentPattern, ...] = (
    # Generic environment access.
    EnvironmentPattern(
        "environment_variable_access",
        "environment_variables",
        r"\b(?:getenvironmentvariable|getenv|environ|environment\.getenvironmentvariable|"
        r"process\.getenvironmentvariable|os\.environ|system\.getenv|"
        r"environment\.getenvironmentvariables)\b",
        severity="low",
        confidence=0.88,
        platform="generic",
        description="Reads or references process/environment variables.",
    ),
    EnvironmentPattern(
        "environment_variable_expansion",
        "environment_variables",
        r"(?:%[A-Za-z_][A-Za-z0-9_]{1,100}%|\$\{?[A-Za-z_][A-Za-z0-9_]{0,100}\}?|"
        r'"\b(?:env|set)\s+[A-Za-z_][A-Za-z0-9_]{0,100})',
        severity="low",
        confidence=0.78,
        platform="generic",
        description="References shell-style environment-variable expansion.",
    ),
    EnvironmentPattern(
        "path_environment_access",
        "path_discovery",
        r"\b(?:PATH|PATHEXT|Path|PSModulePath|LD_LIBRARY_PATH|DYLD_LIBRARY_PATH)\b",
        severity="low",
        confidence=0.82,
        platform="generic",
        description="References executable/module search paths.",
    ),
    # Host and identity discovery.
    EnvironmentPattern(
        "computer_name_api",
        "computer_name",
        r"\b(?:GetComputerName(?:Ex)?|ComputerName|COMPUTERNAME|hostname|"
        r"Environment\.MachineName|Dns\.GetHostName|InetAddress\.getLocalHost)\b",
        severity="low",
        confidence=0.92,
        platform="generic",
        description="Obtains or references the host/computer name.",
    ),
    EnvironmentPattern(
        "username_api",
        "username",
        r"\b(?:GetUserName(?:Ex)?|USERNAME|USER|LOGNAME|"
        r"Environment\.UserName|Environment\.UserDomainName|"
        r"whoami|[Ww]script\.Network\.UserName)\b",
        severity="low",
        confidence=0.92,
        platform="generic",
        description="Obtains or references the current user identity.",
    ),
    EnvironmentPattern(
        "domain_identity",
        "domain_discovery",
        r"\b(?:USERDOMAIN|USERDNSDOMAIN|LOGONSERVER|"
        r"GetComputerDomain|UserDomainName|DomainName|"
        r"NetWkstaUserGetInfo|Win32_ComputerSystem)\b",
        severity="low",
        confidence=0.88,
        platform="windows",
        description="References domain or workstation identity.",
    ),
    EnvironmentPattern(
        "whoami_domain",
        "domain_discovery",
        r"\bwhoami(?:\.exe)?\s+(?:/upn|/fqdn|/user|/groups|/priv|/all)\b",
        severity="medium",
        confidence=0.96,
        platform="windows",
        description="Uses whoami-style identity/group/privilege discovery.",
    ),
    # OS and architecture.
    EnvironmentPattern(
        "windows_version_api",
        "os_version",
        r"\b(?:GetVersionEx(?:A|W)?|RtlGetVersion|VerifyVersionInfo|"
        r"Win32_OperatingSystem|OperatingSystem|CurrentVersion|ProductName|"
        r"ReleaseId|DisplayVersion)\b",
        severity="low",
        confidence=0.91,
        platform="windows",
        description="References Windows version information.",
    ),
    EnvironmentPattern(
        "generic_os_version",
        "os_version",
        r"\b(?:platform\.release|platform\.version|platform\.system|"
        r"uname\s+-[aorvms]|/etc/os-release|lsb_release)\b",
        severity="low",
        confidence=0.90,
        platform="generic",
        description="Obtains or references operating-system information.",
    ),
    EnvironmentPattern(
        "architecture_detection",
        "architecture",
        r"\b(?:IsWow64Process(?:2)?|PROCESSOR_ARCHITECTURE|"
        r"PROCESSOR_IDENTIFIER|platform\.machine|platform\.architecture|"
        r"uname\s+-m|AMD64|x86_64|x86|arm64|aarch64|WOW64)\b",
        severity="low",
        confidence=0.89,
        platform="generic",
        description="Detects processor architecture or WOW64 state.",
    ),
    # Locale / language / timezone.
    EnvironmentPattern(
        "locale_detection",
        "locale",
        r"\b(?:GetLocaleInfo(?:A|W)?|GetUserDefaultLocaleName|"
        r"GetSystemDefaultLocaleName|LocaleName|LC_ALL|LC_CTYPE|LANG|LANGUAGE|"
        r"locale\.getdefaultlocale|CultureInfo|CurrentCulture)\b",
        severity="low",
        confidence=0.90,
        platform="generic",
        description="Detects or references locale settings.",
    ),
    EnvironmentPattern(
        "language_detection",
        "language",
        r"\b(?:GetSystemDefaultUILanguage|GetUserDefaultUILanguage|"
        r"GetKeyboardLayout|KeyboardLayout|SystemLanguage|UserLanguage|"
        r"UILanguage|CurrentUICulture)\b",
        severity="low",
        confidence=0.90,
        platform="generic",
        description="Detects system or user language settings.",
    ),
    EnvironmentPattern(
        "timezone_detection",
        "timezone",
        r"\b(?:GetTimeZoneInformation|GetDynamicTimeZoneInformation|"
        r"TimeZoneInfo|tzname|TZ|/etc/timezone|/etc/localtime)\b",
        severity="low",
        confidence=0.88,
        platform="generic",
        description="References system timezone information.",
    ),
    # Common filesystem/environment locations.
    EnvironmentPattern(
        "windows_directory",
        "system_directory",
        r"\b(?:%SystemRoot%|%WINDIR%|System32|SysWOW64|Windows\\System32|"
        r"Windows/System32)\b",
        severity="low",
        confidence=0.94,
        platform="windows",
        description="References standard Windows system directories.",
    ),
    EnvironmentPattern(
        "program_directory",
        "program_directory",
        r"\b(?:%ProgramFiles%|%ProgramFiles\(x86\)%|Program Files|"
        r"%ProgramData%|ProgramData)\b",
        severity="low",
        confidence=0.90,
        platform="windows",
        description="References standard Windows program-data locations.",
    ),
    EnvironmentPattern(
        "temporary_directory",
        "temporary_directory",
        r"\b(?:%TEMP%|%TMP%|TEMP|TMP|GetTempPath|GetTempFileName|"
        r"/tmp/|/var/tmp/)\b",
        severity="low",
        confidence=0.84,
        platform="generic",
        description="References temporary filesystem locations.",
    ),
    EnvironmentPattern(
        "home_directory",
        "home_directory",
        r"(?:%USERPROFILE%|%HOMEDRIVE%|%HOMEPATH%|%HOME%|"
        r"\$HOME\b|os\.path\.expanduser|Path\.home\(\)|/home/|/Users/)",
        severity="low",
        confidence=0.90,
        platform="generic",
        description="References the current user's home directory.",
    ),
    EnvironmentPattern(
        "current_directory",
        "current_directory",
        r"\b(?:GetCurrentDirectory|SetCurrentDirectory|"
        r"Environment\.CurrentDirectory|os\.getcwd|GetCurrentDirectoryA|"
        r"GetCurrentDirectoryW|pwd)\b",
        severity="low",
        confidence=0.90,
        platform="generic",
        description="References the process current working directory.",
    ),
    EnvironmentPattern(
        "drive_discovery",
        "drive_discovery",
        r"\b(?:GetLogicalDrives|GetLogicalDriveStrings|DriveInfo|"
        r"FileSystemObject|Drives|wmic\s+logicaldisk|Win32_LogicalDisk|"
        r"lsblk|df\s+-[hP])\b",
        severity="medium",
        confidence=0.91,
        platform="generic",
        description="Enumerates or references available drives/filesystems.",
    ),
    # Security product discovery.
    EnvironmentPattern(
        "security_product_wmi",
        "security_product_discovery",
        r"\b(?:AntiVirusProduct|AntiSpywareProduct|FirewallProduct|"
        r"SecurityCenter2?|root\\SecurityCenter2|"
        r"Win32_OperatingSystem.*Security)\b",
        severity="medium",
        confidence=0.96,
        platform="windows",
        description="References Windows security-product inventory classes.",
    ),
    EnvironmentPattern(
        "security_software_terms",
        "security_software",
        r"\b(?:Windows Defender|Microsoft Defender|MsMpEng(?:\.exe)?|"
        r"MsSense(?:\.exe)?|SecurityHealthService|SecurityHealthSystray|"
        r"avast|avg|bitdefender|kaspersky|eset|sophos|mcafee|"
        r"symantec|crowdstrike|falcon|sentinelone|carbonblack|"
        r"trend\s*micro|webroot|malwarebytes)\b",
        severity="medium",
        confidence=0.82,
        platform="generic",
        description="References security or endpoint-protection products.",
    ),
    EnvironmentPattern(
        "security_process_enumeration",
        "security_product_discovery",
        r"\b(?:tasklist|Get-Process|wmic\s+process|ps(?:\.exe)?\s+-|"
        r"pgrep|ps\s+aux)\b.{0,250}\b(?:defender|antivirus|"
        r"security|crowdstrike|sentinel|carbonblack|kaspersky|"
        r"symantec|sophos|mcafee)\b",
        severity="high",
        confidence=0.94,
        platform="generic",
        description="Combines process enumeration with security-product targeting.",
    ),
    # Virtualization / VM / hypervisor.
    EnvironmentPattern(
        "vm_vendor_terms",
        "virtual_machine",
        r"\b(?:VMware|VirtualBox|VBoxService|VBoxTray|QEMU|KVM|"
        r"Hyper-V|Microsoft Hv|Xen|Parallels|Virtual Machine|"
        r"VirtualBox Guest Additions|VMware Tools|vmmouse|vmtoolsd)\b",
        severity="medium",
        confidence=0.93,
        platform="generic",
        description="References known virtualization or hypervisor artifacts.",
    ),
    EnvironmentPattern(
        "vm_detection_wmi",
        "virtual_machine",
        r"\b(?:Win32_ComputerSystem|Win32_BIOS|Win32_BaseBoard|"
        r"Win32_DiskDrive|Win32_VideoController)\b.{0,500}\b(?:VMware|"
        r"VirtualBox|QEMU|KVM|Xen|Hyper-V|Parallels|virtual)\b",
        severity="high",
        confidence=0.95,
        platform="windows",
        description="Correlates hardware inventory with VM-specific values.",
    ),
    EnvironmentPattern(
        "hypervisor_detection",
        "hypervisor",
        r"\b(?:IsProcessorFeaturePresent|hypervisor|CPUID|VMX|SVM|"
        r"HypervisorPresent|VirtualizationBasedSecurity)\b",
        severity="medium",
        confidence=0.89,
        platform="generic",
        description="References hypervisor or virtualization state.",
    ),
    # Sandbox / analysis environment detection.
    EnvironmentPattern(
        "sandbox_terms",
        "sandbox_detection",
        r"\b(?:sandbox|analysis environment|malware analysis|detonation|"
        r"Joe Sandbox|Any\.Run|ANYRUN|Hybrid Analysis|Cuckoo|CAPEv2|"
        r"FLARE-VM|REMnux|INetSim)\b",
        severity="high",
        confidence=0.94,
        platform="generic",
        description="References sandbox or malware-analysis environments.",
    ),
    EnvironmentPattern(
        "analysis_process_terms",
        "analysis_environment",
        r"\b(?:procmon|procexp|process explorer|process monitor|"
        r"wireshark|fiddler|x64dbg|x32dbg|windbg|ollydbg|ida(?:64)?|"
        r"ghidra|dnspy|dnSpy|api monitor|regshot)\b",
        severity="high",
        confidence=0.92,
        platform="generic",
        description="References common analysis/debugging tools.",
    ),
    EnvironmentPattern(
        "sandbox_artifact_paths",
        "sandbox_detection",
        r"(?:C:\\\\(?:analysis|sandbox|sample|malware|tools)\\\\|"
        r"/(?:analysis|sandbox|samples|malware|tools)/)",
        severity="medium",
        confidence=0.82,
        platform="generic",
        description="References common analysis/sandbox filesystem paths.",
    ),
    # Debugger detection / anti-analysis.
    EnvironmentPattern(
        "debugger_api",
        "debugger_detection",
        r"\b(?:IsDebuggerPresent|CheckRemoteDebuggerPresent|"
        r"NtQueryInformationProcess|OutputDebugString(?:A|W)?|"
        r"DebuggerPresent|BeingDebugged|CheckForDebugger)\b",
        severity="high",
        confidence=0.98,
        platform="windows",
        description="References debugger-detection functionality.",
    ),
    EnvironmentPattern(
        "debugger_artifact",
        "debugger_awareness",
        r"\b(?:PEB\.BeingDebugged|NtGlobalFlag|DebugPort|DebugObjectHandle|"
        r"ProcessDebugFlags|ProcessDebugPort)\b",
        severity="high",
        confidence=0.96,
        platform="windows",
        description="References low-level debugger-detection artifacts.",
    ),
    EnvironmentPattern(
        "debugger_process_check",
        "debugger_detection",
        r"\b(?:tasklist|Get-Process|ps(?:\.exe)?|wmic\s+process)\b.{0,300}\b"
        r"(?:x64dbg|x32dbg|windbg|ollydbg|ida(?:64)?|dnspy|dbgview|"
        r"process\s+explorer)\b",
        severity="high",
        confidence=0.96,
        platform="generic",
        description="Combines process enumeration with debugger/tool detection.",
    ),
    # Container detection.
    EnvironmentPattern(
        "container_artifacts",
        "container_detection",
        r"\b(?:docker|containerd|kubepods|docker\.slice|"
        r"/\.dockerenv|/run/secrets/kubernetes\.io|"
        r"container=podman|lxc|lxd)\b",
        severity="medium",
        confidence=0.94,
        platform="generic",
        description="References common container artifacts.",
    ),
    EnvironmentPattern(
        "container_cgroup",
        "container_detection",
        r"\b(?:/proc/1/cgroup|/proc/self/cgroup|cgroup(?:v2)?|"
        r"docker\.slice|kubepods\.slice)\b",
        severity="medium",
        confidence=0.91,
        platform="linux",
        description="References Linux container/cgroup indicators.",
    ),
    # Privilege / integrity level.
    EnvironmentPattern(
        "privilege_discovery",
        "privilege_discovery",
        r"\b(?:whoami\s+/groups|whoami\s+/priv|GetTokenInformation|"
        r"TokenElevation|TokenElevationType|IsUserAnAdmin|"
        r"CheckTokenMembership|net\s+session|id\s+-u|id\s+-G|"
        r"groups(?:\.exe)?|SeDebugPrivilege)\b",
        severity="medium",
        confidence=0.93,
        platform="generic",
        description="Discovers current privilege or group membership.",
    ),
    EnvironmentPattern(
        "integrity_level",
        "integrity_level",
        r"\b(?:Mandatory Label|Medium Mandatory Level|High Mandatory Level|"
        r"System Mandatory Level|TokenIntegrityLevel|integrity level|"
        r"GetTokenInformation)\b",
        severity="medium",
        confidence=0.91,
        platform="windows",
        description="References Windows integrity-level information.",
    ),
    # Session / interactive state.
    EnvironmentPattern(
        "interactive_session",
        "interactive_session",
        r"\b(?:GetConsoleWindow|GetConsoleMode|Console\.IsInputRedirected|"
        r"Environment\.UserInteractive|SESSIONNAME|SessionName|"
        r"XDG_SESSION_TYPE|loginctl\s+show-session)\b",
        severity="low",
        confidence=0.89,
        platform="generic",
        description="Detects whether execution occurs in an interactive session.",
    ),
    EnvironmentPattern(
        "remote_session",
        "remote_session",
        r"\b(?:RDP-Tcp|Terminal Services|Remote Desktop|"
        r"CLIENTNAME|SESSIONNAME|REMOTEHOST|SSH_CONNECTION|"
        r"SSH_CLIENT|SSH_TTY|Win32_TerminalServiceSetting)\b",
        severity="medium",
        confidence=0.91,
        platform="generic",
        description="Detects or references remote/terminal sessions.",
    ),
    EnvironmentPattern(
        "rdp_detection",
        "rdp_detection",
        r"\b(?:mstsc(?:\.exe)?|RDP-Tcp|Remote Desktop Services|"
        r"TermService|Terminal Services)\b",
        severity="medium",
        confidence=0.89,
        platform="windows",
        description="References Windows Remote Desktop artifacts.",
    ),
    # Office environment.
    EnvironmentPattern(
        "office_environment",
        "office_environment",
        r"\b(?:Application\.Version|Application\.OperatingSystem|"
        r"Application\.Path|Application\.UserName|Application\.LanguageSettings|"
        r"Application\.Build|OfficeVersion|MSOffice|Microsoft Office)\b",
        severity="low",
        confidence=0.88,
        platform="windows",
        description="References Office host/environment properties.",
    ),
    # Browser environment.
    EnvironmentPattern(
        "browser_environment",
        "browser_environment",
        r"\b(?:Chrome|Chromium|Edge|Firefox|iexplore|Internet Explorer|"
        r"Opera|Brave|browser profile|User Data|Local State|"
        r"Cookies|Login Data|Firefox Profiles)\b",
        severity="medium",
        confidence=0.79,
        platform="generic",
        description="References browser installation/profile artifacts.",
    ),
    # Security policy / execution environment.
    EnvironmentPattern(
        "execution_policy",
        "security_policy",
        r"\b(?:ExecutionPolicy|Get-ExecutionPolicy|Set-ExecutionPolicy|"
        r"AppLocker|WDAC|Code Integrity|Device Guard|"
        r"Software Restriction Policies|SRP)\b",
        severity="medium",
        confidence=0.94,
        platform="windows",
        description="References Windows script/code execution policy.",
    ),
    EnvironmentPattern(
        "amsi_environment",
        "security_policy",
        r"\b(?:AMSI|AmsiScanBuffer|AmsiUtils|amsiInitFailed|"
        r"Antimalware Scan Interface)\b",
        severity="high",
        confidence=0.94,
        platform="windows",
        description="References the Windows antimalware scanning environment.",
    ),
    # Environment-gated execution.
    EnvironmentPattern(
        "environment_conditional_execution",
        "environment_gating",
        r"\b(?:if|elseif|switch|case|when)\b.{0,500}\b(?:VMware|VirtualBox|"
        r"sandbox|debugger|IsDebuggerPresent|USERNAME|COMPUTERNAME|"
        r"PROCESSOR_ARCHITECTURE|LANG|locale|timezone|antivirus|defender|"
        r"SecurityCenter2|domain)\b",
        severity="high",
        confidence=0.90,
        platform="generic",
        description="Conditionally branches on environment characteristics.",
    ),
    # Windows-specific discovery commands.
    EnvironmentPattern(
        "systeminfo_discovery",
        "host_discovery",
        r"\b(?:systeminfo(?:\.exe)?|ver(?:\.exe)?|wmic(?:\.exe)?\s+os)\b",
        severity="low",
        confidence=0.94,
        platform="windows",
        description="Uses standard commands to discover host/system information.",
    ),
    EnvironmentPattern(
        "set_command_discovery",
        "environment_variables",
        r"(?:^|[;&|]\s*)set(?:\.exe)?(?:\s+[A-Za-z_][A-Za-z0-9_]{0,100})?\s*$",
        severity="low",
        confidence=0.91,
        platform="windows",
        description="Enumerates shell environment variables.",
    ),
    EnvironmentPattern(
        "hostname_command",
        "computer_name",
        r"\bhostname(?:\.exe)?\b",
        severity="low",
        confidence=0.96,
        platform="generic",
        description="Queries the local host name.",
    ),
    # Linux/macOS environment.
    EnvironmentPattern(
        "uname_discovery",
        "os_version",
        r"\buname(?:\s+-[a-zA-Z]+)?\b",
        severity="low",
        confidence=0.97,
        platform="linux",
        description="Queries Unix kernel/system identity.",
    ),
    EnvironmentPattern(
        "id_discovery",
        "user_discovery",
        r"\bid(?:\.gnu)?(?:\s+-[a-zA-Z]+)?\b",
        severity="low",
        confidence=0.91,
        platform="linux",
        description="Queries Unix user/group identity.",
    ),
    EnvironmentPattern(
        "who_command",
        "session_discovery",
        r"\b(?:who|w|users)(?:\s|$)",
        severity="low",
        confidence=0.86,
        platform="linux",
        description="Queries logged-in or interactive users.",
    ),
    EnvironmentPattern(
        "sw_vers",
        "os_version",
        r"\bsw_vers(?:\s|$)",
        severity="low",
        confidence=0.98,
        platform="macos",
        description="Queries macOS version information.",
    ),
    EnvironmentPattern(
        "sysctl_environment",
        "system_identity",
        r"\bsysctl\b.{0,250}\b(?:hw\.|kern\.|machdep\.|sysctl)\b",
        severity="low",
        confidence=0.88,
        platform="macos",
        description="Queries macOS/BSD system properties.",
    ),
)


# ---------------------------------------------------------------------------
# Stable indicator list
# ---------------------------------------------------------------------------

STABLE_INDICATORS: Tuple[str, ...] = tuple(
    sorted({pattern.name for pattern in ENVIRONMENT_PATTERNS})
)


# ---------------------------------------------------------------------------
# Utility functions
# ---------------------------------------------------------------------------

def _safe_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _bounded_text(value: Any, limit: int = MAX_FIELD_TEXT) -> str:
    """Convert arbitrary values to bounded deterministic text."""
    if value is None:
        return ""

    if isinstance(value, bytes):
        raw = value[:limit]
        return raw.decode("utf-8", errors="replace")

    if isinstance(value, bytearray):
        raw = bytes(value[:limit])
        return raw.decode("utf-8", errors="replace")

    if isinstance(value, memoryview):
        raw = value.tobytes()[:limit]
        return raw.decode("utf-8", errors="replace")

    if isinstance(value, str):
        return value[:limit]

    try:
        if is_dataclass(value):
            return json.dumps(
                asdict(value),
                ensure_ascii=False,
                sort_keys=True,
                default=str,
            )[:limit]
    except Exception:
        pass

    if isinstance(value, Mapping):
        try:
            return json.dumps(
                value,
                ensure_ascii=False,
                sort_keys=True,
                default=str,
            )[:limit]
        except Exception:
            pass

    if isinstance(value, (list, tuple, set)):
        try:
            return json.dumps(
                list(value),
                ensure_ascii=False,
                sort_keys=False,
                default=str,
            )[:limit]
        except Exception:
            pass

    try:
        return str(value)[:limit]
    except Exception:
        return ""


def _read_path(path: Path) -> bytes:
    """
    Read a regular file with a strict size limit.

    The module never interprets or executes the file. It only reads bytes for
    static textual analysis.
    """
    try:
        if not path.is_file():
            return b""

        size = path.stat().st_size
        if size < 0 or size > MAX_SOURCE_SIZE:
            return b""

        with path.open("rb") as handle:
            return handle.read(MAX_SOURCE_SIZE + 1)
    except (OSError, ValueError):
        return b""


def _input_to_bytes(value: Any) -> bytes:
    if isinstance(value, bytes):
        return value[: MAX_SOURCE_SIZE + 1]

    if isinstance(value, bytearray):
        return bytes(value[: MAX_SOURCE_SIZE + 1])

    if isinstance(value, memoryview):
        return value.tobytes()[: MAX_SOURCE_SIZE + 1]

    if isinstance(value, Path):
        return _read_path(value)

    if isinstance(value, str):
        # A string is treated as content unless it unambiguously identifies
        # an existing regular file. No path is followed if it does not exist.
        try:
            candidate = Path(value)
            if len(value) <= 4096 and candidate.is_file():
                return _read_path(candidate)
        except (OSError, ValueError):
            pass

        return value.encode("utf-8", errors="replace")[: MAX_SOURCE_SIZE + 1]

    return _bounded_text(value, MAX_SOURCE_SIZE + 1).encode(
        "utf-8",
        errors="replace",
    )


def _flatten_input(
    value: Any,
    *,
    prefix: str = "root",
    depth: int = 0,
    seen: Optional[Set[int]] = None,
) -> List[Tuple[str, str]]:
    """
    Flatten nested structures into bounded textual fields.

    The traversal is deliberately bounded to avoid pathological recursive
    objects or attacker-controlled structures.
    """
    if seen is None:
        seen = set()

    if depth > MAX_NESTING_DEPTH:
        return []

    if len(seen) > MAX_ENVIRONMENT_RECORDS:
        return []

    if value is None:
        return []

    if isinstance(value, (str, bytes, bytearray, memoryview, Path)):
        text = _bounded_text(value)
        return [(prefix, text)] if text else []

    if isinstance(value, Mapping):
        object_id = id(value)
        if object_id in seen:
            return []

        seen.add(object_id)
        result: List[Tuple[str, str]] = []

        for index, (key, item) in enumerate(value.items()):
            if index >= MAX_ENVIRONMENT_RECORDS:
                break

            key_text = re.sub(
                r"[^A-Za-z0-9_.-]+",
                "_",
                _bounded_text(key, 200),
            ).strip("_")

            child_prefix = (
                f"{prefix}.{key_text}"
                if key_text
                else f"{prefix}.{index}"
            )

            result.extend(
                _flatten_input(
                    item,
                    prefix=child_prefix,
                    depth=depth + 1,
                    seen=seen,
                )
            )

            if len(result) >= MAX_ENVIRONMENT_RECORDS:
                break

        return result[:MAX_ENVIRONMENT_RECORDS]

    if isinstance(value, (list, tuple, set)):
        object_id = id(value)
        if object_id in seen:
            return []

        seen.add(object_id)
        result = []

        for index, item in enumerate(value):
            if index >= MAX_ENVIRONMENT_RECORDS:
                break

            result.extend(
                _flatten_input(
                    item,
                    prefix=f"{prefix}[{index}]",
                    depth=depth + 1,
                    seen=seen,
                )
            )

            if len(result) >= MAX_ENVIRONMENT_RECORDS:
                break

        return result[:MAX_ENVIRONMENT_RECORDS]

    object_id = id(value)
    if object_id in seen:
        return []

    seen.add(object_id)

    # Prefer explicit instance dictionaries.
    try:
        attributes = vars(value)
    except (TypeError, ValueError):
        attributes = None

    if isinstance(attributes, Mapping):
        return _flatten_input(
            attributes,
            prefix=prefix,
            depth=depth + 1,
            seen=seen,
        )

    text = _bounded_text(value)
    return [(prefix, text)] if text else []


def _normalize_source(
    source: Any,
) -> Tuple[str, int, str]:
    """
    Return:
        text,
        source_size,
        source_kind
    """
    if isinstance(source, (str, bytes, bytearray, memoryview, Path)):
        raw = _input_to_bytes(source)

        source_kind = "bytes"
        if isinstance(source, str):
            source_kind = "text_or_path"
        elif isinstance(source, Path):
            source_kind = "path"

        truncated = len(raw) > MAX_SOURCE_SIZE
        raw = raw[:MAX_SOURCE_SIZE]

        text = raw.decode("utf-8", errors="replace")
        if truncated:
            text = text[:MAX_TEXT_CHARS]

        return text, len(raw), source_kind

    fields = _flatten_input(source)

    if not fields:
        return "", 0, "structured"

    pieces: List[str] = []
    total = 0

    for name, value in fields:
        if not value:
            continue

        bounded = value[:MAX_FIELD_TEXT]
        piece = f"{name}: {bounded}"

        remaining = MAX_TEXT_CHARS - total
        if remaining <= 0:
            break

        piece = piece[:remaining]
        pieces.append(piece)
        total += len(piece) + 1

    text = "\n".join(pieces)
    raw = text.encode("utf-8", errors="replace")

    return text[:MAX_TEXT_CHARS], min(len(raw), MAX_SOURCE_SIZE), "structured"


def _line_number(text: str, position: int) -> int:
    if position <= 0:
        return 1
    return text.count("\n", 0, position) + 1


def _line_text(text: str, line_number: int) -> str:
    if line_number <= 0:
        return ""

    lines = text.splitlines()
    if line_number > len(lines):
        return ""

    return lines[line_number - 1][:MAX_SNIPPET_LENGTH]


def _normalize_indicator(value: str) -> str:
    return re.sub(r"\s+", " ", value.strip().lower())


def _normalize_platform(platform: str) -> str:
    value = platform.strip().lower()

    if value in {"win", "windows", "win32", "win64"}:
        return "windows"

    if value in {"linux", "unix", "gnu/linux"}:
        return "linux"

    if value in {"mac", "macos", "osx", "darwin"}:
        return "macos"

    if value in {"powershell", "vba", "vbscript", "javascript", "generic"}:
        return value

    return "generic"


def _infer_platform(text: str) -> str:
    lower = text.lower()

    windows_score = 0
    linux_score = 0
    macos_score = 0

    windows_terms = (
        r"\bwindows\b",
        r"\\system32\\",
        r"\bhklm\b",
        r"\bhkcu\b",
        r"\bwmic\b",
        r"\bpowershell\b",
        r"\bwscript\b",
        r"\bwin32_",
        r"\bregistry\b",
        r"\bdefender\b",
        r"\bmsmpeng\b",
        r"\brdp-tcp\b",
    )

    linux_terms = (
        r"/proc/",
        r"/etc/",
        r"\bsystemctl\b",
        r"\buname\b",
        r"\blinux\b",
        r"\bcron\b",
        r"\bld_library_path\b",
        r"\bkubepods\b",
        r"\bdockerenv\b",
    )

    macos_terms = (
        r"\bmacos\b",
        r"\bos x\b",
        r"\bdarwin\b",
        r"\bsw_vers\b",
        r"\blaunchagent",
        r"\blaunchdaemon",
        r"/users/",
    )

    for pattern in windows_terms:
        if re.search(pattern, lower):
            windows_score += 1

    for pattern in linux_terms:
        if re.search(pattern, lower):
            linux_score += 1

    for pattern in macos_terms:
        if re.search(pattern, lower):
            macos_score += 1

    scores = {
        "windows": windows_score,
        "linux": linux_score,
        "macos": macos_score,
    }

    platform, score = max(scores.items(), key=lambda item: item[1])

    return platform if score > 0 else "generic"


def _infer_operation(
    text: str,
    match_start: int,
    default: str,
) -> str:
    """
    Infer whether an indicator appears to represent discovery, comparison,
    enumeration, or environment-gated behavior.

    This does not execute or validate the referenced operation.
    """
    start = max(0, match_start - 350)
    context = text[start:match_start + 350].lower()

    if re.search(
        r"\b(?:if|elseif|switch|case|when|unless|while)\b",
        context,
    ):
        if re.search(
            r"\b(?:vm|virtual|sandbox|debugger|analysis|"
            r"defender|antivirus|locale|language|username|computername)\b",
            context,
        ):
            return "gate"

    if re.search(
        r"\b(?:check|test|verify|detect|is|compare|match|"
        r"query|get|read|enumerate|list|discover|inspect)\b",
        context,
    ):
        return "discover"

    return default


def _extract_location(text: str, match_start: int, match_end: int) -> Optional[str]:
    """
    Extract a nearby registry/path-like environment location.

    The result is evidence metadata only; it is never opened or resolved.
    """
    start = max(0, match_start - 300)
    end = min(len(text), match_end + 500)
    context = text[start:end]

    patterns = (
        r"(?i)\b(?:HKLM|HKCU|HKCR|HKU|HKEY_LOCAL_MACHINE|"
        r"HKEY_CURRENT_USER|HKEY_CLASSES_ROOT|HKEY_USERS)\\[A-Za-z0-9_.\\/\- ]{1,250}",
        r"(?i)(?:%SystemRoot%|%WINDIR%|%ProgramFiles%|%ProgramData%|"
        r"%TEMP%|%TMP%|%USERPROFILE%|%HOME%)[A-Za-z0-9_.\\/\- %]{0,250}",
        r"(?i)/(?:proc|etc|home|tmp|var|usr|opt|Users|Library)/"
        r"[A-Za-z0-9_.@%+\-=/]{1,250}",
        r"(?i)[A-Z]:\\[A-Za-z0-9_. %+\-\\]{1,250}",
    )

    for pattern in patterns:
        found = re.search(pattern, context)
        if found:
            value = re.sub(r"\s+", " ", found.group(0)).strip()
            return value[:300]

    return None


def _severity_max(current: str, candidate: str) -> str:
    if SEVERITY_ORDER.get(candidate, 0) > SEVERITY_ORDER.get(current, 0):
        return candidate
    return current


# ---------------------------------------------------------------------------
# Pattern compilation
# ---------------------------------------------------------------------------

_COMPILED_PATTERNS: Tuple[Tuple[EnvironmentPattern, re.Pattern[str]], ...] = tuple(
    (
        pattern,
        re.compile(pattern.regex, re.IGNORECASE | re.MULTILINE),
    )
    for pattern in ENVIRONMENT_PATTERNS
)


# ---------------------------------------------------------------------------
# Evidence extraction
# ---------------------------------------------------------------------------

def extract_environment_evidence(
    text: str,
    *,
    source_name: str = "text",
    max_items: int = MAX_EVIDENCE_ITEMS,
) -> List[EnvironmentEvidence]:
    """Extract bounded static environment evidence from text."""
    if not text:
        return []

    bounded_text = text[:MAX_TEXT_CHARS]
    evidence: List[EnvironmentEvidence] = []

    for pattern, compiled in _COMPILED_PATTERNS:
        if len(evidence) >= max_items:
            break

        match_count = 0

        try:
            iterator = compiled.finditer(bounded_text)
        except (re.error, ValueError):
            continue

        for match in iterator:
            if match_count >= MAX_MATCHES_PER_RULE:
                break
            if len(evidence) >= max_items:
                break

            match_count += 1

            start = match.start()
            end = match.end()

            line_number = _line_number(bounded_text, start)
            line = _line_text(bounded_text, line_number)

            indicator_text = match.group(0)
            indicator_text = re.sub(
                r"\s+",
                " ",
                indicator_text.strip(),
            )[:250]

            if not indicator_text:
                indicator_text = pattern.name

            platform = _normalize_platform(pattern.platform)

            if platform == "generic":
                platform = _infer_platform(
                    bounded_text[
                        max(0, start - 500): min(len(bounded_text), end + 500)
                    ]
                )

            operation = _infer_operation(
                bounded_text,
                start,
                pattern.operation,
            )

            location = _extract_location(
                bounded_text,
                start,
                end,
            )

            snippet = line or indicator_text
            snippet = snippet[:MAX_SNIPPET_LENGTH]

            evidence.append(
                EnvironmentEvidence(
                    category=pattern.category,
                    indicator=pattern.name,
                    evidence=snippet,
                    source=source_name,
                    line_number=line_number,
                    operation=operation,
                    platform=platform,
                    location=location,
                    confidence=max(0.0, min(1.0, pattern.confidence)),
                    severity=pattern.severity,
                    pattern=pattern.name,
                )
            )

    return evidence[:max_items]


def _deduplicate_evidence(
    evidence: Sequence[EnvironmentEvidence],
) -> List[EnvironmentEvidence]:
    seen: Set[Tuple[Any, ...]] = set()
    result: List[EnvironmentEvidence] = []

    for item in evidence:
        key = (
            item.category,
            item.indicator,
            item.line_number,
            item.evidence,
            item.operation,
            item.platform,
            item.location,
        )

        if key in seen:
            continue

        seen.add(key)
        result.append(item)

        if len(result) >= MAX_EVIDENCE_ITEMS:
            break

    return result


def _records_from_evidence(
    evidence: Sequence[EnvironmentEvidence],
) -> List[EnvironmentRecord]:
    records: List[EnvironmentRecord] = []
    seen: Set[Tuple[Any, ...]] = set()

    for item in evidence:
        key = (
            item.category,
            item.indicator,
            item.operation,
            item.platform,
            item.location,
            item.line_number,
        )

        if key in seen:
            continue

        seen.add(key)

        behavior = item.indicator.replace("_", " ")

        records.append(
            EnvironmentRecord(
                behavior=behavior,
                category=item.category,
                operation=item.operation,
                platform=item.platform,
                indicator=item.indicator,
                evidence=item.evidence,
                severity=item.severity,
                confidence=item.confidence,
                location=item.location,
                line_number=item.line_number,
            )
        )

        if len(records) >= MAX_ENVIRONMENT_RECORDS:
            break

    return records


# ---------------------------------------------------------------------------
# Combination derivation
# ---------------------------------------------------------------------------

COMBINATION_DEFINITIONS: Tuple[
    Tuple[str, Tuple[str, ...], str],
    ...
] = (
    (
        "virtualization_aware_execution",
        (
            "virtualization",
            "virtual_machine",
            "hypervisor",
            "sandbox_detection",
        ),
        "The source contains indicators for identifying virtualization or sandbox environments.",
    ),
    (
        "debugger_aware_execution",
        (
            "debugger_detection",
            "debugger_awareness",
            "analysis_environment",
        ),
        "The source contains indicators associated with debugger or analysis-tool detection.",
    ),
    (
        "security_software_discovery",
        (
            "security_software",
            "security_product_discovery",
            "antivirus_discovery",
        ),
        "The source references endpoint-security product discovery or identification.",
    ),
    (
        "host_identity_discovery",
        (
            "computer_name",
            "username",
            "domain_discovery",
        ),
        "The source combines host and user/domain identity discovery.",
    ),
    (
        "environment_fingerprinting",
        (
            "os_version",
            "architecture",
            "locale",
            "timezone",
        ),
        "The source gathers multiple host-environment properties.",
    ),
    (
        "privilege_environment_discovery",
        (
            "privilege_discovery",
            "integrity_level",
        ),
        "The source checks the execution user's privilege or integrity context.",
    ),
    (
        "remote_session_awareness",
        (
            "remote_session",
            "rdp_detection",
            "interactive_session",
        ),
        "The source checks whether execution occurs through a remote or interactive session.",
    ),
    (
        "container_awareness",
        (
            "container_detection",
            "container_awareness",
        ),
        "The source checks for container-specific execution artifacts.",
    ),
    (
        "environment_gated_execution",
        (
            "environment_gating",
            "execution_environment",
        ),
        "Execution behavior appears to depend on detected environment characteristics.",
    ),
    (
        "anti_analysis_environment_checks",
        (
            "sandbox_detection",
            "debugger_detection",
            "analysis_environment",
        ),
        "Multiple anti-analysis environment checks are present.",
    ),
)


def derive_combinations(
    records: Sequence[EnvironmentRecord],
    evidence: Sequence[EnvironmentEvidence],
    *,
    source_text: str = "",
) -> List[EnvironmentCombination]:
    categories = {item.category for item in records}
    indicators = {item.indicator for item in records}

    combinations: List[EnvironmentCombination] = []

    for name, required, explanation in COMBINATION_DEFINITIONS:
        present = False

        if name == "environment_gated_execution":
            present = (
                "environment_gating" in categories
                or (
                    "environment_variables" in categories
                    and bool(
                        re.search(
                            r"\b(?:if|elseif|switch|case|when)\b",
                            source_text,
                            re.IGNORECASE,
                        )
                    )
                    and bool(
                        re.search(
                            r"\b(?:execute|run|start|invoke|launch|shell|"
                            r"powershell|cmd|wscript|mshta|rundll32)\b",
                            source_text,
                            re.IGNORECASE,
                        )
                    )
                )
            )
        else:
            present = all(category in categories for category in required)

        combinations.append(
            EnvironmentCombination(
                name=name,
                present=present,
                required_categories=required,
                explanation=explanation,
            )
        )

    # A source can exhibit anti-analysis behavior through several distinct
    # indicators even if no single predefined category combination matches.
    anti_analysis_categories = {
        "sandbox_detection",
        "debugger_detection",
        "debugger_awareness",
        "virtual_machine",
        "hypervisor",
        "analysis_environment",
        "security_product_discovery",
    }

    if len(categories.intersection(anti_analysis_categories)) >= 2:
        already_present = any(
            item.name == "anti_analysis_environment_checks" and item.present
            for item in combinations
        )

        if not already_present:
            combinations.append(
                EnvironmentCombination(
                    name="multi_signal_anti_analysis",
                    present=True,
                    required_categories=tuple(
                        sorted(categories.intersection(anti_analysis_categories))
                    ),
                    explanation=(
                        "Multiple independent environment/analysis-awareness "
                        "signals occur in the same source."
                    ),
                )
            )

    # Host fingerprinting becomes stronger when several independent identity
    # dimensions occur together.
    fingerprint_categories = {
        "computer_name",
        "username",
        "domain_discovery",
        "os_version",
        "architecture",
        "locale",
        "timezone",
        "privilege_discovery",
        "environment_variables",
    }

    if len(categories.intersection(fingerprint_categories)) >= 4:
        combinations.append(
            EnvironmentCombination(
                name="broad_environment_fingerprinting",
                present=True,
                required_categories=tuple(
                    sorted(categories.intersection(fingerprint_categories))
                ),
                explanation=(
                    "The source gathers several independent properties of "
                    "the execution environment."
                ),
            )
        )

    return combinations


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------

_CATEGORY_WEIGHTS: Dict[str, float] = {
    "environment_discovery": 0.3,
    "host_discovery": 0.4,
    "user_discovery": 0.4,
    "domain_discovery": 0.6,
    "computer_name": 0.4,
    "username": 0.4,
    "system_identity": 0.4,
    "os_version": 0.3,
    "architecture": 0.4,
    "locale": 0.3,
    "language": 0.3,
    "timezone": 0.3,
    "regional_settings": 0.3,
    "environment_variables": 0.3,
    "path_discovery": 0.3,
    "current_directory": 0.2,
    "home_directory": 0.2,
    "temporary_directory": 0.2,
    "system_directory": 0.2,
    "program_directory": 0.2,
    "volume_information": 0.4,
    "drive_discovery": 0.6,
    "filesystem_discovery": 0.5,
    "installed_software": 0.5,
    "security_software": 1.0,
    "security_product_discovery": 1.4,
    "antivirus_discovery": 1.4,
    "firewall_discovery": 1.0,
    "virtualization": 1.0,
    "virtual_machine": 1.4,
    "hypervisor": 1.2,
    "sandbox": 1.5,
    "sandbox_detection": 2.0,
    "analysis_environment": 1.8,
    "debugger_detection": 2.2,
    "debugger_awareness": 2.2,
    "emulator_detection": 1.8,
    "container_detection": 1.0,
    "container_awareness": 1.0,
    "domain_environment": 0.5,
    "privilege_discovery": 0.8,
    "integrity_level": 1.0,
    "session_discovery": 0.4,
    "interactive_session": 0.4,
    "remote_session": 0.7,
    "rdp_detection": 0.8,
    "terminal_detection": 0.4,
    "office_environment": 0.3,
    "browser_environment": 0.5,
    "security_policy": 1.0,
    "execution_environment": 1.0,
    "environment_gating": 2.0,
    "anti_analysis": 1.5,
}


def _signal_score(
    records: Sequence[EnvironmentRecord],
    combinations: Sequence[EnvironmentCombination],
) -> float:
    score = 0.0

    for record in records:
        weight = _CATEGORY_WEIGHTS.get(record.category, 0.5)

        severity_multiplier = {
            "info": 0.25,
            "low": 0.50,
            "medium": 1.00,
            "high": 1.50,
            "critical": 2.00,
        }.get(record.severity, 1.0)

        confidence = max(0.0, min(1.0, record.confidence))

        score += weight * severity_multiplier * confidence

    for combination in combinations:
        if not combination.present:
            continue

        if combination.name in {
            "anti_analysis_environment_checks",
            "multi_signal_anti_analysis",
            "environment_gated_execution",
            "broad_environment_fingerprinting",
        }:
            score += 2.5
        else:
            score += 1.0

    return round(min(score, 100.0), 6)


# ---------------------------------------------------------------------------
# Feature-vector construction
# ---------------------------------------------------------------------------

def _count_by(
    records: Sequence[EnvironmentRecord],
    attribute: str,
) -> Counter:
    return Counter(
        getattr(record, attribute)
        for record in records
        if getattr(record, attribute, None)
    )


def build_feature_vector(
    records: Sequence[EnvironmentRecord],
    evidence: Sequence[EnvironmentEvidence],
    combinations: Sequence[EnvironmentCombination],
    *,
    source_size: int = 0,
) -> Dict[str, float]:
    """Build a deterministic, scalar feature vector."""
    vector: Dict[str, float] = {}

    category_counts = _count_by(records, "category")
    indicator_counts = _count_by(records, "indicator")
    platform_counts = _count_by(records, "platform")
    operation_counts = _count_by(records, "operation")

    severity_counts = _count_by(records, "severity")

    locations = {
        record.location
        for record in records
        if record.location
    }

    present_combinations = {
        combination.name
        for combination in combinations
        if combination.present
    }

    # Global features.
    vector["source_size"] = float(max(0, source_size))
    vector["record_count"] = float(len(records))
    vector["evidence_count"] = float(len(evidence))
    vector["indicator_count"] = float(len(indicator_counts))
    vector["category_count"] = float(len(category_counts))
    vector["location_count"] = float(len(locations))
    vector["platform_count"] = float(len(platform_counts))
    vector["combination_count"] = float(len(present_combinations))

    vector["info_count"] = float(severity_counts.get("info", 0))
    vector["low_count"] = float(severity_counts.get("low", 0))
    vector["medium_count"] = float(severity_counts.get("medium", 0))
    vector["high_count"] = float(severity_counts.get("high", 0))
    vector["critical_count"] = float(severity_counts.get("critical", 0))

    vector["discover_count"] = float(operation_counts.get("discover", 0))
    vector["gate_count"] = float(operation_counts.get("gate", 0))
    vector["unknown_operation_count"] = float(
        operation_counts.get("unknown", 0)
    )

    vector["windows_count"] = float(platform_counts.get("windows", 0))
    vector["linux_count"] = float(platform_counts.get("linux", 0))
    vector["macos_count"] = float(platform_counts.get("macos", 0))
    vector["generic_platform_count"] = float(
        platform_counts.get("generic", 0)
    )

    # High-value behavior counts.
    high_value_categories = {
        "security_product_discovery",
        "antivirus_discovery",
        "virtual_machine",
        "hypervisor",
        "sandbox_detection",
        "analysis_environment",
        "debugger_detection",
        "debugger_awareness",
        "container_detection",
        "environment_gating",
    }

    vector["high_value_environment_count"] = float(
        sum(
            count
            for category, count in category_counts.items()
            if category in high_value_categories
        )
    )

    vector["anti_analysis_record_count"] = float(
        sum(
            count
            for category, count in category_counts.items()
            if category in {
                "sandbox_detection",
                "analysis_environment",
                "debugger_detection",
                "debugger_awareness",
                "virtual_machine",
                "hypervisor",
                "security_product_discovery",
            }
        )
    )

    vector["identity_discovery_count"] = float(
        sum(
            count
            for category, count in category_counts.items()
            if category in {
                "computer_name",
                "username",
                "domain_discovery",
                "os_version",
                "architecture",
            }
        )
    )

    vector["environment_fingerprint_count"] = float(
        sum(
            count
            for category, count in category_counts.items()
            if category in {
                "computer_name",
                "username",
                "domain_discovery",
                "os_version",
                "architecture",
                "locale",
                "language",
                "timezone",
                "environment_variables",
            }
        )
    )

    # Stable category features.
    for category in ENVIRONMENT_CATEGORIES:
        count = category_counts.get(category, 0)
        vector[f"category_{category}_present"] = 1.0 if count else 0.0
        vector[f"category_{category}_count"] = float(count)

    # Stable indicator features.
    for indicator in STABLE_INDICATORS:
        count = indicator_counts.get(indicator, 0)
        vector[f"indicator_{indicator}_present"] = (
            1.0 if count else 0.0
        )
        vector[f"indicator_{indicator}_count"] = float(count)

    # Stable combination features.
    combination_names = {
        name
        for name, _, _ in COMBINATION_DEFINITIONS
    }
    combination_names.update(
        {
            "multi_signal_anti_analysis",
            "broad_environment_fingerprinting",
        }
    )

    for name in sorted(combination_names):
        vector[f"combination_{name}_present"] = (
            1.0 if name in present_combinations else 0.0
        )

    vector["environment_signal_score"] = _signal_score(
        records,
        combinations,
    )

    return vector


def feature_names() -> List[str]:
    """Return stable feature names in deterministic order."""
    names = {
        "source_size",
        "record_count",
        "evidence_count",
        "indicator_count",
        "category_count",
        "location_count",
        "platform_count",
        "combination_count",
        "info_count",
        "low_count",
        "medium_count",
        "high_count",
        "critical_count",
        "discover_count",
        "gate_count",
        "unknown_operation_count",
        "windows_count",
        "linux_count",
        "macos_count",
        "generic_platform_count",
        "high_value_environment_count",
        "anti_analysis_record_count",
        "identity_discovery_count",
        "environment_fingerprint_count",
        "environment_signal_score",
    }

    for category in ENVIRONMENT_CATEGORIES:
        names.add(f"category_{category}_present")
        names.add(f"category_{category}_count")

    for indicator in STABLE_INDICATORS:
        names.add(f"indicator_{indicator}_present")
        names.add(f"indicator_{indicator}_count")

    for name, _, _ in COMBINATION_DEFINITIONS:
        names.add(f"combination_{name}_present")

    names.update(
        {
            "combination_multi_signal_anti_analysis_present",
            "combination_broad_environment_fingerprinting_present",
        }
    )

    return sorted(names)


def persistence_feature_names() -> List[str]:
    """
    Compatibility-style alias.

    The actual feature namespace belongs to environment behavior, but keeping
    this helper avoids surprises in generic feature-discovery code that expects
    feature-name functions to be available across behavior modules.
    """
    return feature_names()


def environment_feature_names() -> List[str]:
    return feature_names()


def vectorize_features(
    feature_vector: Mapping[str, Any],
    names: Optional[Sequence[str]] = None,
) -> List[float]:
    """Convert a feature mapping into a deterministic numeric vector."""
    selected = list(names) if names is not None else feature_names()

    result: List[float] = []

    for name in selected:
        value = feature_vector.get(name, 0.0)

        if isinstance(value, bool):
            result.append(1.0 if value else 0.0)
            continue

        try:
            number = float(value)
        except (TypeError, ValueError):
            number = 0.0

        if not math.isfinite(number):
            number = 0.0

        result.append(number)

    return result


def extract_feature_vector(
    analysis: EnvironmentAnalysis,
    names: Optional[Sequence[str]] = None,
) -> List[float]:
    return vectorize_features(
        analysis.feature_vector,
        names=names,
    )


def extract_environment_feature_vector(
    analysis: EnvironmentAnalysis,
    names: Optional[Sequence[str]] = None,
) -> List[float]:
    return extract_feature_vector(analysis, names=names)


def build_feature_schema() -> Dict[str, Any]:
    """Return a JSON-serializable feature schema."""
    names = feature_names()

    return {
        "version": 1,
        "module": "extraction.behavior.environment",
        "feature_count": len(names),
        "features": [
            {
                "name": name,
                "type": "float",
            }
            for name in names
        ],
    }


# ---------------------------------------------------------------------------
# Main analysis API
# ---------------------------------------------------------------------------

def analyze_environment_behavior(
    source: Any,
    *,
    source_name: str = "text",
    max_evidence: int = MAX_EVIDENCE_ITEMS,
) -> EnvironmentAnalysis:
    """
    Analyze source material for environment-awareness behavior.

    This function is strictly static and side-effect free with respect to the
    analyzed environment.
    """
    text, source_size, source_kind = _normalize_source(source)

    source_hash = _safe_sha256(
        text.encode("utf-8", errors="replace")
    )

    if len(text) > MAX_TEXT_CHARS:
        text = text[:MAX_TEXT_CHARS]

    evidence = extract_environment_evidence(
        text,
        source_name=source_name,
        max_items=max_evidence,
    )

    evidence = _deduplicate_evidence(evidence)

    records = _records_from_evidence(evidence)

    indicators = sorted(
        {
            record.indicator
            for record in records
            if record.indicator
        }
    )

    categories = sorted(
        {
            record.category
            for record in records
            if record.category
        }
    )

    locations = sorted(
        {
            record.location
            for record in records
            if record.location
        }
    )[:MAX_LOCATIONS]

    platforms = sorted(
        {
            record.platform
            for record in records
            if record.platform
        }
    )

    combinations = derive_combinations(
        records,
        evidence,
        source_text=text,
    )

    feature_vector = build_feature_vector(
        records,
        evidence,
        combinations,
        source_size=source_size,
    )

    high_count = sum(
        1
        for record in records
        if SEVERITY_ORDER.get(record.severity, 0) >= 3
    )

    critical_count = sum(
        1
        for record in records
        if SEVERITY_ORDER.get(record.severity, 0) >= 4
    )

    anti_analysis_count = sum(
        1
        for record in records
        if record.category in {
            "sandbox_detection",
            "analysis_environment",
            "debugger_detection",
            "debugger_awareness",
            "virtual_machine",
            "hypervisor",
            "security_product_discovery",
        }
    )

    metadata: Dict[str, Any] = {
        "module": "extraction.behavior.environment",
        "version": 1,
        "static_only": True,
        "source_kind": source_kind,
        "source_name": source_name,
        "truncated": source_size >= MAX_SOURCE_SIZE
        or len(text) >= MAX_TEXT_CHARS,
        "pattern_count": len(ENVIRONMENT_PATTERNS),
        "feature_count": len(feature_names()),
        "high_severity_count": high_count,
        "critical_severity_count": critical_count,
        "anti_analysis_count": anti_analysis_count,
        "signal_score": feature_vector.get(
            "environment_signal_score",
            0.0,
        ),
    }

    return EnvironmentAnalysis(
        source_hash=source_hash,
        source_size=source_size,
        records=records,
        evidence=evidence,
        indicators=indicators[:MAX_INDICATORS],
        categories=categories,
        locations=locations,
        platforms=platforms,
        combinations=combinations,
        feature_vector=feature_vector,
        metadata=metadata,
    )


def analyze(
    source: Any,
    *,
    source_name: str = "text",
    max_evidence: int = MAX_EVIDENCE_ITEMS,
) -> EnvironmentAnalysis:
    """Short alias for analyze_environment_behavior."""
    return analyze_environment_behavior(
        source,
        source_name=source_name,
        max_evidence=max_evidence,
    )


def parse_environment_behavior(
    source: Any,
    *,
    source_name: str = "text",
    max_evidence: int = MAX_EVIDENCE_ITEMS,
) -> EnvironmentAnalysis:
    """Parser-style alias for compatibility with other behavior modules."""
    return analyze_environment_behavior(
        source,
        source_name=source_name,
        max_evidence=max_evidence,
    )


def extract_environment_features(
    source: Any,
    *,
    source_name: str = "text",
    max_evidence: int = MAX_EVIDENCE_ITEMS,
) -> Dict[str, Any]:
    """Return the complete JSON-friendly analysis dictionary."""
    return analysis_to_dict(
        analyze_environment_behavior(
            source,
            source_name=source_name,
            max_evidence=max_evidence,
        )
    )


def extract_environment_records(
    source: Any,
    *,
    source_name: str = "text",
    max_evidence: int = MAX_EVIDENCE_ITEMS,
) -> List[EnvironmentRecord]:
    """Return normalized environment behavior records."""
    return analyze_environment_behavior(
        source,
        source_name=source_name,
        max_evidence=max_evidence,
    ).records


# ---------------------------------------------------------------------------
# Query helpers
# ---------------------------------------------------------------------------

def has_indicator(
    analysis: EnvironmentAnalysis,
    indicator: str,
) -> bool:
    target = _normalize_indicator(indicator)

    return any(
        _normalize_indicator(item) == target
        for item in analysis.indicators
    )


def indicator_count(
    analysis: EnvironmentAnalysis,
    indicator: str,
) -> int:
    target = _normalize_indicator(indicator)

    return sum(
        1
        for record in analysis.records
        if _normalize_indicator(record.indicator) == target
    )


def has_category(
    analysis: EnvironmentAnalysis,
    category: str,
) -> bool:
    target = _normalize_indicator(category)

    return any(
        _normalize_indicator(item) == target
        for item in analysis.categories
    )


def category_count(
    analysis: EnvironmentAnalysis,
    category: str,
) -> int:
    target = _normalize_indicator(category)

    return sum(
        1
        for record in analysis.records
        if _normalize_indicator(record.category) == target
    )


def evidence_by_category(
    analysis: EnvironmentAnalysis,
    category: str,
) -> List[EnvironmentEvidence]:
    target = _normalize_indicator(category)

    return [
        item
        for item in analysis.evidence
        if _normalize_indicator(item.category) == target
    ]


def evidence_by_indicator(
    analysis: EnvironmentAnalysis,
    indicator: str,
) -> List[EnvironmentEvidence]:
    target = _normalize_indicator(indicator)

    return [
        item
        for item in analysis.evidence
        if _normalize_indicator(item.indicator) == target
    ]


def high_risk_evidence(
    analysis: EnvironmentAnalysis,
) -> List[EnvironmentEvidence]:
    return [
        item
        for item in analysis.evidence
        if SEVERITY_ORDER.get(item.severity, 0) >= 3
    ]


def present_combinations(
    analysis: EnvironmentAnalysis,
) -> List[EnvironmentCombination]:
    return [
        combination
        for combination in analysis.combinations
        if combination.present
    ]


def highest_severity(
    analysis: EnvironmentAnalysis,
) -> str:
    if not analysis.records:
        return "info"

    return max(
        (
            record.severity
            for record in analysis.records
        ),
        key=lambda value: SEVERITY_ORDER.get(value, 0),
    )


# ---------------------------------------------------------------------------
# Summaries and serialization
# ---------------------------------------------------------------------------

def summarize_environment_behavior(
    analysis: EnvironmentAnalysis,
) -> Dict[str, Any]:
    """Produce a compact summary suitable for pipeline reports."""
    category_counts = Counter(
        record.category
        for record in analysis.records
    )

    indicator_counts = Counter(
        record.indicator
        for record in analysis.records
    )

    operation_counts = Counter(
        record.operation
        for record in analysis.records
    )

    platform_counts = Counter(
        record.platform
        for record in analysis.records
    )

    severity_counts = Counter(
        record.severity
        for record in analysis.records
    )

    return {
        "source_hash": analysis.source_hash,
        "source_size": analysis.source_size,
        "record_count": len(analysis.records),
        "evidence_count": len(analysis.evidence),
        "category_count": len(analysis.categories),
        "indicator_count": len(analysis.indicators),
        "location_count": len(analysis.locations),
        "platform_count": len(analysis.platforms),
        "highest_severity": highest_severity(analysis),
        "signal_score": analysis.feature_vector.get(
            "environment_signal_score",
            0.0,
        ),
        "categories": dict(
            sorted(category_counts.items())
        ),
        "indicators": dict(
            sorted(indicator_counts.items())
        ),
        "operations": dict(
            sorted(operation_counts.items())
        ),
        "platforms": dict(
            sorted(platform_counts.items())
        ),
        "severities": dict(
            sorted(severity_counts.items())
        ),
        "present_combinations": [
            combination.name
            for combination in present_combinations(analysis)
        ],
        "anti_analysis": bool(
            analysis.feature_vector.get(
                "anti_analysis_record_count",
                0.0,
            )
        ),
        "environment_gating": bool(
            analysis.feature_vector.get(
                "combination_environment_gated_execution_present",
                0.0,
            )
        ),
    }


def _json_safe(value: Any) -> Any:
    if is_dataclass(value):
        return {
            key: _json_safe(item)
            for key, item in asdict(value).items()
        }

    if isinstance(value, Mapping):
        return {
            str(key): _json_safe(item)
            for key, item in value.items()
        }

    if isinstance(value, (list, tuple, set)):
        return [_json_safe(item) for item in value]

    if isinstance(value, Path):
        return str(value)

    if isinstance(value, float):
        if not math.isfinite(value):
            return 0.0

    return value


def analysis_to_dict(
    analysis: EnvironmentAnalysis,
) -> Dict[str, Any]:
    """Convert an EnvironmentAnalysis to a JSON-friendly dictionary."""
    return {
        "source_hash": analysis.source_hash,
        "source_size": analysis.source_size,
        "records": [
            _json_safe(record)
            for record in analysis.records
        ],
        "evidence": [
            _json_safe(item)
            for item in analysis.evidence
        ],
        "indicators": list(analysis.indicators),
        "categories": list(analysis.categories),
        "locations": list(analysis.locations),
        "platforms": list(analysis.platforms),
        "combinations": [
            _json_safe(item)
            for item in analysis.combinations
        ],
        "feature_vector": {
            key: float(value)
            for key, value in analysis.feature_vector.items()
        },
        "metadata": _json_safe(analysis.metadata),
        "summary": summarize_environment_behavior(analysis),
    }


# ---------------------------------------------------------------------------
# Iterators
# ---------------------------------------------------------------------------

def iter_evidence(
    analysis: EnvironmentAnalysis,
) -> Iterator[EnvironmentEvidence]:
    yield from analysis.evidence


def iter_high_risk_evidence(
    analysis: EnvironmentAnalysis,
) -> Iterator[EnvironmentEvidence]:
    for item in analysis.evidence:
        if SEVERITY_ORDER.get(item.severity, 0) >= 3:
            yield item


def iter_environment_records(
    analysis: EnvironmentAnalysis,
) -> Iterator[EnvironmentRecord]:
    yield from analysis.records


def iter_records(
    analysis: EnvironmentAnalysis,
) -> Iterator[EnvironmentRecord]:
    yield from analysis.records


def iter_combinations(
    analysis: EnvironmentAnalysis,
) -> Iterator[EnvironmentCombination]:
    yield from analysis.combinations


def iter_analyses(
    sources: Iterable[Any],
    *,
    source_name: str = "text",
) -> Iterator[EnvironmentAnalysis]:
    for source in sources:
        yield analyze_environment_behavior(
            source,
            source_name=source_name,
        )


# ---------------------------------------------------------------------------
# Compatibility aliases
# ---------------------------------------------------------------------------

parse = parse_environment_behavior
extract = extract_environment_features
environment_feature_schema = build_feature_schema
extract_environment_feature_vector = extract_environment_feature_vector


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

__all__ = [
    "MAX_SOURCE_SIZE",
    "MAX_TEXT_CHARS",
    "MAX_FIELD_TEXT",
    "MAX_EVIDENCE_ITEMS",
    "MAX_MATCHES_PER_RULE",
    "MAX_NESTING_DEPTH",
    "MAX_ENVIRONMENT_RECORDS",
    "MAX_LOCATIONS",
    "ENVIRONMENT_CATEGORIES",
    "SEVERITY_ORDER",
    "EnvironmentPattern",
    "EnvironmentEvidence",
    "EnvironmentRecord",
    "EnvironmentCombination",
    "EnvironmentAnalysis",
    "ENVIRONMENT_PATTERNS",
    "STABLE_INDICATORS",
    "COMBINATION_DEFINITIONS",
    "extract_environment_evidence",
    "derive_combinations",
    "build_feature_vector",
    "feature_names",
    "environment_feature_names",
    "persistence_feature_names",
    "vectorize_features",
    "extract_feature_vector",
    "extract_environment_feature_vector",
    "build_feature_schema",
    "analyze_environment_behavior",
    "analyze",
    "parse_environment_behavior",
    "extract_environment_features",
    "extract_environment_records",
    "has_indicator",
    "indicator_count",
    "has_category",
    "category_count",
    "evidence_by_category",
    "evidence_by_indicator",
    "high_risk_evidence",
    "present_combinations",
    "highest_severity",
    "summarize_environment_behavior",
    "analysis_to_dict",
    "iter_evidence",
    "iter_high_risk_evidence",
    "iter_environment_records",
    "iter_records",
    "iter_combinations",
    "iter_analyses",
    "parse",
    "extract",
    "environment_feature_schema",
]
