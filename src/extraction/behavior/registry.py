"""
Static Windows Registry behavior extraction for the Pharos CDR pipeline.

This module analyzes text, bytes, and structured static-analysis results for
Windows Registry-related behavior without executing anything.

Security properties
-------------------
- Never opens or modifies the host Windows Registry.
- Never invokes Windows Registry APIs.
- Never executes commands, macros, scripts, or extracted payloads.
- Registry paths found in input are treated strictly as data.
- All parsing and evidence collection are bounded.
- The module is suitable for document, VBA, script, and binary static
  analysis.

Pipeline position
-----------------
    static source/evidence
        -> registry behavior
        -> capabilities / behavior chains
        -> ML feature vector
        -> CDR policy / reporting

The feature vector is deterministic and intended for use alongside the other
behavior extractors in ``src/extraction/behavior``.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import asdict, dataclass, field
from typing import (
    Any,
    Dict,
    Iterable,
    Iterator,
    List,
    Mapping,
    Optional,
    Sequence,
    Tuple,
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
MAX_REGISTRY_PATHS = 20_000
MAX_REGISTRY_OPERATIONS = 20_000
MAX_UNIQUE_VALUES = 10_000


# ---------------------------------------------------------------------------
# Severity / confidence
# ---------------------------------------------------------------------------

SEVERITIES = ("low", "medium", "high", "critical")

SEVERITY_WEIGHT = {
    "low": 1.0,
    "medium": 2.0,
    "high": 4.0,
    "critical": 7.0,
}


def _clamp(value: float, lower: float, upper: float) -> float:
    return max(lower, min(upper, value))


def _severity_rank(value: str) -> int:
    try:
        return SEVERITIES.index(value)
    except ValueError:
        return 0


def _normalize_severity(value: Any, default: str = "medium") -> str:
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in SEVERITIES:
            return normalized
    return default


def _normalize_confidence(value: Any, default: float = 0.75) -> float:
    try:
        return _clamp(float(value), 0.0, 1.0)
    except (TypeError, ValueError):
        return default


def _max_severity(values: Iterable[str]) -> str:
    result = "low"
    for value in values:
        if _severity_rank(value) > _severity_rank(result):
            result = value
    return result


# ---------------------------------------------------------------------------
# Registry taxonomy
# ---------------------------------------------------------------------------

REGISTRY_CATEGORIES: Tuple[str, ...] = (
    "registry_read",
    "registry_write",
    "registry_delete",
    "registry_create_key",
    "registry_set_value",
    "registry_query_value",
    "registry_enumeration",
    "registry_key_exists",
    "registry_open_key",
    "registry_close_key",
    "registry_backup",
    "registry_restore",
    "registry_export",
    "registry_import",
    "registry_run_key",
    "registry_startup",
    "registry_services",
    "registry_winlogon",
    "registry_userinit",
    "registry_shell",
    "registry_appinit",
    "registry_ifeo",
    "registry_com",
    "registry_protocol_handler",
    "registry_file_association",
    "registry_bho",
    "registry_active_setup",
    "registry_scheduled_task",
    "registry_policy",
    "registry_security",
    "registry_firewall",
    "registry_network",
    "registry_proxy",
    "registry_rdp",
    "registry_uac",
    "registry_defender",
    "registry_amais",
    "registry_environment",
    "registry_credentials",
    "registry_discovery",
    "registry_evasion",
    "registry_persistence",
    "registry_execution",
    "registry_injection",
)


INDICATOR_NAMES: Tuple[str, ...] = (
    "reg_open_key",
    "reg_create_key",
    "reg_delete_key",
    "reg_set_value",
    "reg_delete_value",
    "reg_query_value",
    "reg_enum_key",
    "reg_enum_value",
    "reg_key_exists",
    "reg_close_key",
    "reg_read",
    "reg_write",
    "reg_delete",
    "reg_backup",
    "reg_restore",
    "reg_export",
    "reg_import",
    "run_key",
    "startup_registry",
    "winlogon_persistence",
    "userinit_persistence",
    "shell_persistence",
    "appinit_persistence",
    "ifeo_persistence",
    "com_hijacking",
    "protocol_handler_hijacking",
    "file_association_hijacking",
    "bho_persistence",
    "active_setup_persistence",
    "service_registry_change",
    "scheduled_task_registry_change",
    "policy_change",
    "security_product_change",
    "firewall_change",
    "proxy_change",
    "rdp_change",
    "uac_change",
    "defender_change",
    "amsi_change",
    "environment_change",
    "credential_registry_access",
    "registry_discovery",
    "registry_evasion",
    "registry_execution",
    "registry_injection",
    "registry_backup_restore",
    "registry_import_export",
)


# ---------------------------------------------------------------------------
# Registry hive vocabulary
# ---------------------------------------------------------------------------

HIVE_ALIASES: Dict[str, str] = {
    "hkcr": "HKEY_CLASSES_ROOT",
    "hkey_classes_root": "HKEY_CLASSES_ROOT",
    "hklm": "HKEY_LOCAL_MACHINE",
    "hkey_local_machine": "HKEY_LOCAL_MACHINE",
    "hkcu": "HKEY_CURRENT_USER",
    "hkey_current_user": "HKEY_CURRENT_USER",
    "hku": "HKEY_USERS",
    "hkey_users": "HKEY_USERS",
    "hkcc": "HKEY_CURRENT_CONFIG",
    "hkey_current_config": "HKEY_CURRENT_CONFIG",
}


KNOWN_HIVES: Tuple[str, ...] = tuple(sorted(HIVE_ALIASES, key=len, reverse=True))


# ---------------------------------------------------------------------------
# High-value registry paths
# ---------------------------------------------------------------------------

PERSISTENCE_PATHS: Tuple[Tuple[str, str, str, str], ...] = (
    (
        r"hkey_current_user\software\microsoft\windows\currentversion\run",
        "run_key",
        "registry_run_key",
        "User Run key persistence location.",
    ),
    (
        r"hkey_current_user\software\microsoft\windows\currentversion\runonce",
        "run_key",
        "registry_run_key",
        "User RunOnce persistence location.",
    ),
    (
        r"hkey_local_machine\software\microsoft\windows\currentversion\run",
        "run_key",
        "registry_run_key",
        "Machine Run key persistence location.",
    ),
    (
        r"hkey_local_machine\software\microsoft\windows\currentversion\runonce",
        "run_key",
        "registry_run_key",
        "Machine RunOnce persistence location.",
    ),
    (
        r"hkey_local_machine\software\wow6432node\microsoft\windows\currentversion\run",
        "run_key",
        "registry_run_key",
        "32-bit machine Run key persistence location.",
    ),
    (
        r"hkey_current_user\software\microsoft\windows\currentversion\explorer\user shell folders",
        "startup_registry",
        "registry_startup",
        "User shell-folder configuration.",
    ),
    (
        r"hkey_current_user\software\microsoft\windows\currentversion\explorer\shell folders",
        "startup_registry",
        "registry_startup",
        "User shell-folder configuration.",
    ),
    (
        r"hkey_local_machine\software\microsoft\windows\currentversion\explorer\user shell folders",
        "startup_registry",
        "registry_startup",
        "Machine shell-folder configuration.",
    ),
    (
        r"hkey_local_machine\software\microsoft\windows nt\currentversion\winlogon",
        "winlogon_persistence",
        "registry_winlogon",
        "Winlogon configuration.",
    ),
    (
        r"hkey_local_machine\software\microsoft\windows nt\currentversion\winlogon\userinit",
        "userinit_persistence",
        "registry_userinit",
        "Winlogon Userinit configuration.",
    ),
    (
        r"hkey_local_machine\software\microsoft\windows nt\currentversion\winlogon\shell",
        "shell_persistence",
        "registry_shell",
        "Winlogon shell configuration.",
    ),
    (
        r"hkey_local_machine\software\microsoft\windows nt\currentversion\windows",
        "appinit_persistence",
        "registry_appinit",
        "Legacy AppInit configuration.",
    ),
    (
        r"hkey_local_machine\software\microsoft\windows nt\currentversion\image file execution options",
        "ifeo_persistence",
        "registry_ifeo",
        "Image File Execution Options configuration.",
    ),
    (
        r"hkey_local_machine\software\classes\clsid",
        "com_hijacking",
        "registry_com",
        "COM class registration.",
    ),
    (
        r"hkey_current_user\software\classes\clsid",
        "com_hijacking",
        "registry_com",
        "Per-user COM class registration.",
    ),
    (
        r"hkey_local_machine\software\classes\protocols\handler",
        "protocol_handler_hijacking",
        "registry_protocol_handler",
        "Protocol-handler registration.",
    ),
    (
        r"hkey_current_user\software\classes\protocols\handler",
        "protocol_handler_hijacking",
        "registry_protocol_handler",
        "Per-user protocol-handler registration.",
    ),
    (
        r"hkey_local_machine\software\classes",
        "file_association_hijacking",
        "registry_file_association",
        "File/protocol association registration.",
    ),
    (
        r"hkey_current_user\software\classes",
        "file_association_hijacking",
        "registry_file_association",
        "Per-user file/protocol association registration.",
    ),
    (
        r"hkey_local_machine\software\microsoft\windows\currentversion\explorer\browser helper objects",
        "bho_persistence",
        "registry_bho",
        "Browser Helper Object registration.",
    ),
    (
        r"hkey_local_machine\software\microsoft\active setup\installed components",
        "active_setup_persistence",
        "registry_active_setup",
        "Active Setup persistence location.",
    ),
    (
        r"hkey_current_user\software\microsoft\windows\currentversion\policies\explorer\run",
        "run_key",
        "registry_run_key",
        "Explorer policy Run persistence location.",
    ),
)


# ---------------------------------------------------------------------------
# Security-sensitive registry paths
# ---------------------------------------------------------------------------

SECURITY_PATHS: Tuple[Tuple[str, str, str, str], ...] = (
    (
        r"system\currentcontrolset\services",
        "service_registry_change",
        "registry_services",
        "Windows service registry configuration.",
    ),
    (
        r"system\currentcontrolset\control\terminal server",
        "rdp_change",
        "registry_rdp",
        "Remote Desktop configuration.",
    ),
    (
        r"software\microsoft\windows\currentversion\policies\system",
        "uac_change",
        "registry_uac",
        "Windows policy/UAC configuration.",
    ),
    (
        r"software\microsoft\windows defender",
        "defender_change",
        "registry_defender",
        "Windows Defender configuration.",
    ),
    (
        r"software\microsoft\windows\currentversion\policies\system",
        "policy_change",
        "registry_policy",
        "Windows system policy configuration.",
    ),
    (
        r"system\currentcontrolset\services\sharedaccess\parameters\firewallpolicy",
        "firewall_change",
        "registry_firewall",
        "Windows Firewall configuration.",
    ),
    (
        r"software\microsoft\windows\currentversion\internet settings",
        "proxy_change",
        "registry_proxy",
        "Internet/proxy configuration.",
    ),
    (
        r"software\microsoft\windows\currentversion\internet settings\connections",
        "proxy_change",
        "registry_proxy",
        "Internet connection/proxy configuration.",
    ),
    (
        r"software\microsoft\windows\currentversion\run",
        "startup_registry",
        "registry_startup",
        "Startup-related registry location.",
    ),
)


# ---------------------------------------------------------------------------
# Regex helpers
# ---------------------------------------------------------------------------


def _compile(pattern: str, flags: int = re.IGNORECASE) -> re.Pattern[str]:
    return re.compile(pattern, flags)


# Registry path syntax is intentionally broad enough to cover:
#   HKCU\Software\...
#   HKEY_CURRENT_USER\Software\...
#   HKLM:\Software\...
#   HKEY_LOCAL_MACHINE/Software/...
REGISTRY_PATH_RE = _compile(
    r"""
    (?:
        \b(?:HKEY_[A-Z0-9_]+|HK(?:LM|CU|CR|U|CC))
        (?:
            [\\/:]
        )
        [A-Za-z0-9_$%~.\- ]+
        (?:
            [\\/][A-Za-z0-9_$%~.\- ]+
        ){0,64}
    )
    """,
    re.IGNORECASE | re.VERBOSE,
)

REGISTRY_KEY_VALUE_RE = _compile(
    r"""
    (?:
        \b(?:HKEY_[A-Z0-9_]+|HK(?:LM|CU|CR|U|CC))
        [\\/:]
        [A-Za-z0-9_$%~.\- ]+
        (?:
            [\\/][A-Za-z0-9_$%~.\- ]+
        ){0,64}
    )
    \s*(?:[=:]\s*)?
    (?:["']([^"']{1,1024})["'])?
    """,
    re.IGNORECASE | re.VERBOSE,
)

# Common command-line forms.
REG_EXE_RE = _compile(
    r"\breg(?:\.exe)?\s+"
    r"(?:add|delete|query|copy|save|restore|export|import|load|unload|compare)\b"
)

REG_QUERY_RE = _compile(
    r"\b(?:reg\s+(?:query|add|delete)|reg\.exe\s+(?:query|add|delete))\b"
)

REG_ADD_RE = _compile(r"\b(?:reg\s+add|reg\.exe\s+add)\b")

REG_DELETE_RE = _compile(r"\b(?:reg\s+delete|reg\.exe\s+delete)\b")

REG_EXPORT_RE = _compile(r"\b(?:reg\s+(?:export|save)|reg\.exe\s+(?:export|save))\b")

REG_IMPORT_RE = _compile(
    r"\b(?:reg\s+(?:import|restore)|reg\.exe\s+(?:import|restore))\b"
)

# Windows API names and common managed/runtime equivalents.
API_RULES: Tuple[Tuple[str, str, str, str, str, float], ...] = (
    (
        "reg_open_key",
        "registry_open_key",
        r"\b(?:RegOpenKey(?:Ex)?[AW]?|RegOpenUserClassesRoot)\b",
        "Registry key open operation.",
        "medium",
        0.96,
    ),
    (
        "reg_create_key",
        "registry_create_key",
        r"\b(?:RegCreateKey(?:Ex)?[AW]?|RegCreateKeyTransacted[AW]?)\b",
        "Registry key creation operation.",
        "high",
        0.96,
    ),
    (
        "reg_delete_key",
        "registry_delete",
        r"\b(?:RegDeleteKey(?:Ex)?[AW]?|RegDeleteTree[AW]?)\b",
        "Registry key deletion operation.",
        "high",
        0.96,
    ),
    (
        "reg_set_value",
        "registry_set_value",
        r"\b(?:RegSetValue(?:Ex)?[AW]?|RegistryKey\.SetValue|Set-ItemProperty|New-ItemProperty)\b",
        "Registry value modification operation.",
        "high",
        0.95,
    ),
    (
        "reg_delete_value",
        "registry_delete",
        r"\b(?:RegDeleteValue[AW]?|RegistryKey\.DeleteValue|Remove-ItemProperty)\b",
        "Registry value deletion operation.",
        "high",
        0.95,
    ),
    (
        "reg_query_value",
        "registry_query_value",
        r"\b(?:RegQueryValue(?:Ex)?[AW]?|RegistryKey\.GetValue|Get-ItemProperty)\b",
        "Registry value query operation.",
        "low",
        0.94,
    ),
    (
        "reg_enum_key",
        "registry_enumeration",
        r"\b(?:RegEnumKey(?:Ex)?[AW]?|RegistryKey\.GetSubKeyNames|Get-ChildItem)\b",
        "Registry key enumeration.",
        "low",
        0.90,
    ),
    (
        "reg_enum_value",
        "registry_enumeration",
        r"\b(?:RegEnumValue[AW]?|RegistryKey\.GetValueNames)\b",
        "Registry value enumeration.",
        "low",
        0.94,
    ),
    (
        "reg_key_exists",
        "registry_key_exists",
        r"\b(?:RegOpenKey(?:Ex)?[AW]?|RegistryKey\.OpenSubKey|Test-Path)\b",
        "Registry key existence/open check.",
        "low",
        0.82,
    ),
    (
        "reg_close_key",
        "registry_close_key",
        r"\b(?:RegCloseKey|RegistryKey\.Close)\b",
        "Registry key close operation.",
        "low",
        0.98,
    ),
    (
        "reg_backup",
        "registry_backup",
        r"\b(?:RegSaveKey(?:Ex)?[AW]?|RegSaveKeyEx|reg\s+(?:save|export))\b",
        "Registry backup/export operation.",
        "medium",
        0.94,
    ),
    (
        "reg_restore",
        "registry_restore",
        r"\b(?:RegRestoreKey[AW]?|reg\s+(?:restore|import))\b",
        "Registry restore/import operation.",
        "medium",
        0.94,
    ),
    (
        "registry_script_provider",
        "registry_write",
        r"\b(?:WScript\.Shell|Shell\.Reg(?:Read|Write|Delete)|StdRegProv)\b",
        "Script/COM registry provider usage.",
        "medium",
        0.91,
    ),
    (
        "registry_dotnet",
        "registry_write",
        r"\b(?:Microsoft\.Win32\.Registry(?:Key|Hive)|RegistryKey\.OpenBaseKey|RegistryKey\.CreateSubKey)\b",
        "Managed Windows Registry API usage.",
        "medium",
        0.93,
    ),
)


COMPILED_API_RULES = tuple(
    (
        name,
        category,
        _compile(pattern),
        description,
        severity,
        confidence,
    )
    for name, category, pattern, description, severity, confidence in API_RULES
)


# ---------------------------------------------------------------------------
# Semantic registry indicators
# ---------------------------------------------------------------------------

SEMANTIC_RULES: Tuple[Tuple[str, str, str, str, str, float], ...] = (
    (
        "run_key",
        "registry_run_key",
        r"(?:\\|/)(?:currentversion)(?:\\|/)(?:runonce|run)(?:\\|/|$)",
        "Registry Run/RunOnce persistence location.",
        "high",
        0.97,
    ),
    (
        "startup_registry",
        "registry_startup",
        r"(?:\\|/)(?:explorer)(?:\\|/)(?:user shell folders|shell folders)(?:\\|/|$)",
        "Registry shell-folder startup/configuration location.",
        "high",
        0.93,
    ),
    (
        "winlogon_persistence",
        "registry_winlogon",
        r"(?:\\|/)(?:winlogon)(?:\\|/)(?:shell|userinit|notify|taskman)(?:\\|/|$)",
        "Winlogon persistence-sensitive registry configuration.",
        "critical",
        0.97,
    ),
    (
        "userinit_persistence",
        "registry_userinit",
        r"(?:\\|/)(?:winlogon)(?:\\|/).*?\buserinit\b",
        "Winlogon Userinit configuration.",
        "critical",
        0.97,
    ),
    (
        "shell_persistence",
        "registry_shell",
        r"(?:\\|/)(?:winlogon)(?:\\|/).*?\bshell\b",
        "Winlogon shell configuration.",
        "critical",
        0.95,
    ),
    (
        "appinit_persistence",
        "registry_appinit",
        r"(?:\\|/)(?:windows nt)(?:\\|/)(?:currentversion)(?:\\|/)(?:windows)(?:\\|/|$)",
        "Legacy AppInit configuration.",
        "critical",
        0.92,
    ),
    (
        "ifeo_persistence",
        "registry_ifeo",
        r"(?:\\|/)(?:image file execution options)(?:\\|/)",
        "Image File Execution Options configuration.",
        "high",
        0.94,
    ),
    (
        "com_hijacking",
        "registry_com",
        r"(?:\\|/)(?:software)(?:\\|/)(?:classes)(?:\\|/)(?:clsid)(?:\\|/)",
        "COM class registration/hijacking-sensitive location.",
        "high",
        0.90,
    ),
    (
        "protocol_handler_hijacking",
        "registry_protocol_handler",
        r"(?:\\|/)(?:protocols)(?:\\|/)(?:handler)(?:\\|/)",
        "Protocol-handler registration location.",
        "high",
        0.92,
    ),
    (
        "file_association_hijacking",
        "registry_file_association",
        r"(?:\\|/)(?:software)(?:\\|/)(?:classes)(?:\\|/)[^\\/\r\n]{1,120}(?:\\|/)(?:shell|open|command)(?:\\|/)",
        "File-association execution configuration.",
        "high",
        0.88,
    ),
    (
        "bho_persistence",
        "registry_bho",
        r"(?:\\|/)(?:browser helper objects)(?:\\|/)",
        "Browser Helper Object registration.",
        "high",
        0.94,
    ),
    (
        "active_setup_persistence",
        "registry_active_setup",
        r"(?:\\|/)(?:active setup)(?:\\|/)(?:installed components)(?:\\|/)",
        "Active Setup persistence location.",
        "high",
        0.94,
    ),
    (
        "service_registry_change",
        "registry_services",
        r"(?:\\|/)(?:system)(?:\\|/)(?:currentcontrolset)(?:\\|/)(?:services)(?:\\|/)",
        "Windows service registry configuration.",
        "high",
        0.95,
    ),
    (
        "scheduled_task_registry_change",
        "registry_scheduled_task",
        r"(?:\\|/)(?:schedule)(?:\\|/)(?:tasks)(?:\\|/)",
        "Scheduled-task registry configuration reference.",
        "high",
        0.84,
    ),
    (
        "policy_change",
        "registry_policy",
        r"(?:\\|/)(?:policies)(?:\\|/)(?:system|explorer)(?:\\|/)",
        "Windows policy registry configuration.",
        "medium",
        0.87,
    ),
    (
        "security_product_change",
        "registry_security",
        r"(?:windows defender|security center|securityhealthservice|antivirus|antimalware)",
        "Security-product-related registry reference.",
        "high",
        0.76,
    ),
    (
        "firewall_change",
        "registry_firewall",
        r"(?:firewallpolicy|sharedaccess)(?:\\|/)",
        "Firewall-related registry configuration.",
        "high",
        0.90,
    ),
    (
        "proxy_change",
        "registry_proxy",
        r"(?:internet settings)(?:\\|/)(?:connections|proxyserver|proxyenable)",
        "Proxy/Internet Settings registry configuration.",
        "medium",
        0.90,
    ),
    (
        "rdp_change",
        "registry_rdp",
        r"(?:terminal server|fdenytsconnections|fusenrdp)",
        "Remote Desktop-related registry configuration.",
        "high",
        0.82,
    ),
    (
        "uac_change",
        "registry_uac",
        r"(?:enablelua|consentpromptbehavioradmin|promptonsecuredesktop|uac)",
        "UAC-related registry configuration.",
        "high",
        0.82,
    ),
    (
        "defender_change",
        "registry_defender",
        r"(?:windows defender|disableantispyware|disableantivirus|disablebehavior)",
        "Windows Defender-related registry configuration.",
        "high",
        0.82,
    ),
    (
        "amsi_change",
        "registry_amais",
        r"(?:amsi|amsiinitfailed|amsiutils|amsi\.dll)",
        "AMSI-related registry reference.",
        "high",
        0.74,
    ),
    (
        "environment_change",
        "registry_environment",
        r"(?:environment)(?:\\|/)(?:path|pathext|temp|tmp|comspec|windir)",
        "Environment-variable-related registry configuration.",
        "medium",
        0.85,
    ),
    (
        "credential_registry_access",
        "registry_credentials",
        r"(?:winlogon)(?:\\|/).*?(?:defaultusername|defaultpassword|password|credential)|"
        r"(?:lsa secrets|sam\\|security\\)",
        "Potential credential-related registry access.",
        "high",
        0.78,
    ),
    (
        "registry_execution",
        "registry_execution",
        r"(?:\\|/)(?:command|open|shell|run|runonce)(?:\\|/|$)",
        "Registry location associated with command execution.",
        "high",
        0.78,
    ),
)


COMPILED_SEMANTIC_RULES = tuple(
    (
        name,
        category,
        _compile(pattern),
        description,
        severity,
        confidence,
    )
    for name, category, pattern, description, severity, confidence in SEMANTIC_RULES
)


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RegistryPattern:
    """Static registry detection rule."""

    name: str
    category: str
    pattern: str
    description: str
    severity: str = "medium"
    confidence: float = 0.80


@dataclass
class RegistryEvidence:
    """One piece of static registry evidence."""

    category: str
    indicator: str
    evidence: str
    source: str = "static_text"
    line_number: Optional[int] = None
    hive: Optional[str] = None
    key_path: Optional[str] = None
    value_name: Optional[str] = None
    operation: Optional[str] = None
    severity: str = "medium"
    confidence: float = 0.75
    context: Optional[str] = None

    def __post_init__(self) -> None:
        self.category = str(self.category)
        self.indicator = str(self.indicator)
        self.severity = _normalize_severity(self.severity)
        self.confidence = _normalize_confidence(self.confidence)

        if self.evidence:
            self.evidence = self.evidence[:MAX_FIELD_TEXT]
        if self.context:
            self.context = self.context[:MAX_FIELD_TEXT]
        if self.key_path:
            self.key_path = self.key_path[:MAX_FIELD_TEXT]
        if self.value_name:
            self.value_name = self.value_name[:MAX_FIELD_TEXT]


@dataclass
class RegistryRecord:
    """Normalized registry operation discovered in static content."""

    operation: str
    key_path: Optional[str] = None
    value_name: Optional[str] = None
    value_data: Optional[str] = None
    hive: Optional[str] = None
    source: str = "static_text"
    category: Optional[str] = None
    indicator: Optional[str] = None
    line_number: Optional[int] = None
    severity: str = "medium"
    confidence: float = 0.75
    evidence: Optional[str] = None

    def __post_init__(self) -> None:
        self.operation = str(self.operation).strip().lower()
        self.severity = _normalize_severity(self.severity)
        self.confidence = _normalize_confidence(self.confidence)

        if self.key_path:
            self.key_path = self.key_path[:MAX_FIELD_TEXT]
        if self.value_name:
            self.value_name = self.value_name[:MAX_FIELD_TEXT]
        if self.value_data:
            self.value_data = self.value_data[:MAX_FIELD_TEXT]
        if self.evidence:
            self.evidence = self.evidence[:MAX_FIELD_TEXT]


@dataclass(frozen=True)
class RegistryCombination:
    """Higher-level registry behavior chain."""

    name: str
    present: bool
    required_indicators: Tuple[str, ...]
    explanation: str
    severity: str = "high"


@dataclass
class RegistryAnalysis:
    """Complete static registry behavior analysis."""

    source_hash: str
    source_size: int
    evidence: List[RegistryEvidence] = field(default_factory=list)
    records: List[RegistryRecord] = field(default_factory=list)
    indicators: List[str] = field(default_factory=list)
    categories: List[str] = field(default_factory=list)
    combinations: List[RegistryCombination] = field(default_factory=list)
    registry_paths: List[str] = field(default_factory=list)
    hives: List[str] = field(default_factory=list)
    persistence_paths: List[str] = field(default_factory=list)
    security_paths: List[str] = field(default_factory=list)
    suspicious_paths: List[str] = field(default_factory=list)
    write_paths: List[str] = field(default_factory=list)
    delete_paths: List[str] = field(default_factory=list)
    feature_vector: Dict[str, float] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Operation normalization
# ---------------------------------------------------------------------------

OPERATION_ALIASES: Dict[str, Tuple[str, str]] = {
    "read": ("registry_read", "reg_read"),
    "query": ("registry_query_value", "reg_query_value"),
    "queryvalue": ("registry_query_value", "reg_query_value"),
    "getvalue": ("registry_query_value", "reg_query_value"),
    "open": ("registry_open_key", "reg_open_key"),
    "openkey": ("registry_open_key", "reg_open_key"),
    "create": ("registry_create_key", "reg_create_key"),
    "createkey": ("registry_create_key", "reg_create_key"),
    "write": ("registry_write", "reg_write"),
    "set": ("registry_set_value", "reg_set_value"),
    "setvalue": ("registry_set_value", "reg_set_value"),
    "add": ("registry_set_value", "reg_set_value"),
    "delete": ("registry_delete", "reg_delete"),
    "deletekey": ("registry_delete", "reg_delete_key"),
    "deletevalue": ("registry_delete", "reg_delete_value"),
    "remove": ("registry_delete", "reg_delete"),
    "enumerate": ("registry_enumeration", "reg_enum_key"),
    "enum": ("registry_enumeration", "reg_enum_key"),
    "enumkey": ("registry_enumeration", "reg_enum_key"),
    "enumvalue": ("registry_enumeration", "reg_enum_value"),
    "backup": ("registry_backup", "reg_backup"),
    "save": ("registry_backup", "reg_backup"),
    "restore": ("registry_restore", "reg_restore"),
    "export": ("registry_export", "reg_export"),
    "import": ("registry_import", "reg_import"),
    "exists": ("registry_key_exists", "reg_key_exists"),
    "close": ("registry_close_key", "reg_close_key"),
}


def normalize_operation(operation: Any) -> Optional[Tuple[str, str]]:
    """Normalize a registry operation name into category and indicator."""
    if operation is None:
        return None

    value = str(operation).strip().lower()
    value = re.sub(r"[^a-z0-9]+", "", value)

    return OPERATION_ALIASES.get(value)


# ---------------------------------------------------------------------------
# Input normalization
# ---------------------------------------------------------------------------


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def _safe_value_to_text(value: Any, depth: int = 0) -> str:
    if depth > MAX_NESTING_DEPTH:
        return "<max-depth>"

    if value is None:
        return ""

    if isinstance(value, bytes):
        return value[:MAX_FIELD_TEXT].decode("utf-8", errors="replace")

    if isinstance(value, str):
        return value[:MAX_FIELD_TEXT]

    if isinstance(value, Mapping):
        parts: List[str] = []
        for key, item in list(value.items())[:MAX_UNIQUE_VALUES]:
            parts.append(
                f"{_safe_value_to_text(key, depth + 1)}="
                f"{_safe_value_to_text(item, depth + 1)}"
            )
        return "\n".join(parts)[:MAX_FIELD_TEXT]

    if isinstance(value, (list, tuple, set, frozenset)):
        return "\n".join(
            _safe_value_to_text(item, depth + 1)
            for item in list(value)[:MAX_UNIQUE_VALUES]
        )[:MAX_FIELD_TEXT]

    try:
        return str(value)[:MAX_FIELD_TEXT]
    except Exception:
        return ""


def _walk_mapping(
    mapping: Mapping[Any, Any],
    prefix: str = "",
    depth: int = 0,
) -> Iterator[Tuple[str, Any]]:
    if depth > MAX_NESTING_DEPTH:
        return

    for index, (key, value) in enumerate(list(mapping.items())[:MAX_UNIQUE_VALUES]):
        key_text = str(key)
        full_key = f"{prefix}.{key_text}" if prefix else key_text

        if isinstance(value, Mapping) and depth < MAX_NESTING_DEPTH:
            yield from _walk_mapping(value, full_key, depth + 1)
        else:
            yield full_key, value

        if index + 1 >= MAX_UNIQUE_VALUES:
            break


def _read_source(source: Any) -> Tuple[str, int, str]:
    """Convert supported static inputs to bounded text."""
    if source is None:
        return "", 0, "empty"

    if isinstance(source, bytes):
        original_size = len(source)
        bounded = source[:MAX_SOURCE_SIZE]
        return (
            bounded.decode("utf-8", errors="replace")[:MAX_TEXT_CHARS],
            original_size,
            "bytes",
        )

    if isinstance(source, str):
        original_size = len(source.encode("utf-8", errors="replace"))
        return source[:MAX_TEXT_CHARS], original_size, "text"

    if isinstance(source, Mapping):
        chunks: List[str] = []
        total = 0

        for key, value in _walk_mapping(source):
            fragment = (f"{key}={_safe_value_to_text(value)}")[:MAX_FIELD_TEXT]
            chunks.append(fragment)
            total += len(fragment.encode("utf-8", errors="replace"))

            if total >= MAX_SOURCE_SIZE:
                break

        return (
            "\n".join(chunks)[:MAX_TEXT_CHARS],
            total,
            "mapping",
        )

    if isinstance(source, (list, tuple, set, frozenset)):
        chunks = []
        total = 0

        for value in list(source)[:MAX_UNIQUE_VALUES]:
            fragment = _safe_value_to_text(value)
            chunks.append(fragment)
            total += len(fragment.encode("utf-8", errors="replace"))

            if total >= MAX_SOURCE_SIZE:
                break

        return (
            "\n".join(chunks)[:MAX_TEXT_CHARS],
            total,
            "sequence",
        )

    text = _safe_value_to_text(source)
    return (
        text[:MAX_TEXT_CHARS],
        len(text.encode("utf-8", errors="replace")),
        "object",
    )


# ---------------------------------------------------------------------------
# Registry path normalization
# ---------------------------------------------------------------------------


def normalize_hive(value: Any) -> Optional[str]:
    """Normalize a Registry hive alias."""
    if value is None:
        return None

    text = str(value).strip().strip("\"'`")
    text = text.rstrip("\\/:")
    return HIVE_ALIASES.get(text.casefold())


def split_registry_path(path: str) -> Tuple[Optional[str], str]:
    """
    Split a registry path into normalized hive and key path.

    Examples:
        HKCU\\Software\\Example
        HKEY_CURRENT_USER\\Software\\Example
        HKLM:\\Software\\Example
    """
    value = str(path).strip().strip("\"'`")
    value = value.replace("/", "\\")
    value = re.sub(r"\\+", r"\\", value)

    match = re.match(
        r"^\s*(HKEY_[A-Za-z0-9_]+|HK(?:LM|CU|CR|U|CC))" r"(?:\\|:)?(.*)$",
        value,
        re.IGNORECASE,
    )

    if not match:
        return None, value

    hive = normalize_hive(match.group(1))
    key_path = match.group(2).lstrip("\\/:").strip()

    return hive, key_path


def normalize_registry_path(path: str) -> str:
    """Normalize registry separators and hive aliases."""
    hive, key_path = split_registry_path(path)

    if hive:
        if key_path:
            return f"{hive}\\{key_path}"
        return hive

    value = str(path).strip().strip("\"'`")
    value = value.replace("/", "\\")
    value = re.sub(r"\\+", r"\\", value)
    return value[:MAX_FIELD_TEXT]


def extract_registry_paths(
    text: str,
    max_paths: int = MAX_REGISTRY_PATHS,
) -> List[str]:
    """Extract unique Registry paths from static text."""
    if not text:
        return []

    paths: List[str] = []
    seen = set()

    for match in REGISTRY_PATH_RE.finditer(text):
        value = normalize_registry_path(match.group(0))
        if not value:
            continue

        key = value.casefold()
        if key in seen:
            continue

        seen.add(key)
        paths.append(value)

        if len(paths) >= max_paths:
            break

    return paths


def extract_hives(paths: Iterable[str]) -> List[str]:
    """Return unique normalized Registry hives."""
    hives: List[str] = []
    seen = set()

    for path in paths:
        hive, _ = split_registry_path(path)
        if not hive:
            continue

        if hive not in seen:
            seen.add(hive)
            hives.append(hive)

    return hives


# ---------------------------------------------------------------------------
# Registry path classification
# ---------------------------------------------------------------------------


def _lower_path(path: str) -> str:
    return normalize_registry_path(path).casefold()


def classify_registry_path(path: str) -> Dict[str, Any]:
    """Classify a Registry path into defensive/model-friendly properties."""
    normalized = normalize_registry_path(path)
    lowered = normalized.casefold()
    hive, key_path = split_registry_path(normalized)

    persistence_matches = []
    security_matches = []

    for pattern, indicator, category, _ in PERSISTENCE_PATHS:
        if pattern in lowered:
            persistence_matches.append(
                {
                    "pattern": pattern,
                    "indicator": indicator,
                    "category": category,
                }
            )

    for pattern, indicator, category, _ in SECURITY_PATHS:
        if pattern in lowered:
            security_matches.append(
                {
                    "pattern": pattern,
                    "indicator": indicator,
                    "category": category,
                }
            )

    properties = {
        "normalized": normalized,
        "hive": hive,
        "key_path": key_path,
        "is_hklm": hive == "HKEY_LOCAL_MACHINE",
        "is_hkcu": hive == "HKEY_CURRENT_USER",
        "is_hkcr": hive == "HKEY_CLASSES_ROOT",
        "is_hku": hive == "HKEY_USERS",
        "is_hkcc": hive == "HKEY_CURRENT_CONFIG",
        "is_persistence": bool(persistence_matches),
        "is_security_sensitive": bool(security_matches),
        "is_services": "services" in lowered,
        "is_policy": "policies" in lowered,
        "is_classes": "\\software\\classes" in lowered,
        "is_current_version": "\\currentversion" in lowered,
        "is_current_control_set": "\\currentcontrolset" in lowered,
        "persistence_matches": persistence_matches,
        "security_matches": security_matches,
    }

    properties["is_suspicious"] = (
        properties["is_persistence"]
        or properties["is_security_sensitive"]
        or properties["is_services"]
        or properties["is_classes"]
    )

    return properties


def classify_registry_paths(
    paths: Iterable[str],
) -> Dict[str, List[str]]:
    """Group Registry paths into useful analysis categories."""
    groups: Dict[str, List[str]] = {
        "persistence": [],
        "security": [],
        "services": [],
        "classes": [],
        "policy": [],
        "hklm": [],
        "hkcu": [],
        "hkcr": [],
        "hku": [],
        "hkcc": [],
        "suspicious": [],
    }

    seen: Dict[str, set] = {key: set() for key in groups}

    for path in paths:
        info = classify_registry_path(path)
        normalized = info["normalized"]
        key = normalized.casefold()

        def add(group: str) -> None:
            if key not in seen[group]:
                seen[group].add(key)
                groups[group].append(normalized)

        if info["is_persistence"]:
            add("persistence")

        if info["is_security_sensitive"]:
            add("security")

        if info["is_services"]:
            add("services")

        if info["is_classes"]:
            add("classes")

        if info["is_policy"]:
            add("policy")

        if info["is_hklm"]:
            add("hklm")
        elif info["is_hkcu"]:
            add("hkcu")
        elif info["is_hkcr"]:
            add("hkcr")
        elif info["is_hku"]:
            add("hku")
        elif info["is_hkcc"]:
            add("hkcc")

        if info["is_suspicious"]:
            add("suspicious")

    return groups


# ---------------------------------------------------------------------------
# Line/context helpers
# ---------------------------------------------------------------------------


def _line_number(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _context(
    text: str,
    start: int,
    end: int,
    radius: int = 180,
) -> str:
    left = max(0, start - radius)
    right = min(len(text), end + radius)
    return text[left:right].replace("\x00", " ")[:MAX_FIELD_TEXT]


def _append_evidence(
    evidence: List[RegistryEvidence],
    seen: set,
    item: RegistryEvidence,
) -> None:
    if len(evidence) >= MAX_EVIDENCE_ITEMS:
        return

    key = (
        item.indicator,
        item.category,
        item.line_number,
        item.key_path,
        item.value_name,
        item.evidence[:256],
    )

    if key in seen:
        return

    seen.add(key)
    evidence.append(item)


def _append_record(
    records: List[RegistryRecord],
    seen: set,
    item: RegistryRecord,
) -> None:
    if len(records) >= MAX_REGISTRY_OPERATIONS:
        return

    key = (
        item.operation,
        (item.key_path or "").casefold(),
        (item.value_name or "").casefold(),
        item.line_number,
        item.indicator,
    )

    if key in seen:
        return

    seen.add(key)
    records.append(item)


# ---------------------------------------------------------------------------
# Structured operation extraction
# ---------------------------------------------------------------------------


def extract_registry_records(
    source: Any,
    max_records: int = MAX_REGISTRY_OPERATIONS,
) -> List[RegistryRecord]:
    """
    Normalize structured Registry operations from previous pipeline stages.

    This function never performs the represented operation.
    """
    records: List[RegistryRecord] = []
    seen = set()

    def consume(value: Any, depth: int = 0) -> None:
        if depth > MAX_NESTING_DEPTH:
            return

        if len(records) >= max_records:
            return

        if isinstance(value, RegistryRecord):
            _append_record(records, seen, value)
            return

        if isinstance(value, Mapping):
            operation_value = (
                value.get("operation")
                or value.get("action")
                or value.get("op")
                or value.get("registry_operation")
                or value.get("behavior")
            )

            normalized = normalize_operation(operation_value)

            if normalized:
                category, indicator = normalized

                raw_path = (
                    value.get("key_path")
                    or value.get("registry_path")
                    or value.get("path")
                    or value.get("key")
                )

                raw_hive = value.get("hive") or value.get("root")

                hive = normalize_hive(raw_hive)

                key_path = normalize_registry_path(str(raw_path)) if raw_path else None

                if key_path:
                    parsed_hive, parsed_key = split_registry_path(key_path)

                    if not hive and parsed_hive:
                        hive = parsed_hive

                    if parsed_hive:
                        key_path = (
                            f"{parsed_hive}\\{parsed_key}"
                            if parsed_key
                            else parsed_hive
                        )

                record = RegistryRecord(
                    operation=str(operation_value),
                    key_path=key_path,
                    value_name=(
                        str(value.get("value_name") or value.get("name"))[
                            :MAX_FIELD_TEXT
                        ]
                        if (
                            value.get("value_name") is not None
                            or value.get("name") is not None
                        )
                        else None
                    ),
                    value_data=(
                        _safe_value_to_text(
                            value.get("value_data")
                            if value.get("value_data") is not None
                            else value.get("data")
                        )[:MAX_FIELD_TEXT]
                        if (
                            value.get("value_data") is not None
                            or value.get("data") is not None
                        )
                        else None
                    ),
                    hive=hive,
                    source=str(value.get("source", "structured")),
                    category=category,
                    indicator=indicator,
                    line_number=_coerce_int(
                        value.get("line_number") or value.get("line")
                    ),
                    severity=_normalize_severity(
                        value.get("severity"),
                        "medium",
                    ),
                    confidence=_normalize_confidence(
                        value.get("confidence"),
                        0.85,
                    ),
                    evidence=(
                        _safe_value_to_text(value.get("evidence"))[:MAX_FIELD_TEXT]
                        if value.get("evidence") is not None
                        else None
                    ),
                )

                _append_record(records, seen, record)

            for key, nested in value.items():
                if key in {
                    "operation",
                    "action",
                    "op",
                    "registry_operation",
                    "behavior",
                    "key_path",
                    "registry_path",
                    "path",
                    "key",
                    "hive",
                    "root",
                    "value_name",
                    "name",
                    "value_data",
                    "data",
                }:
                    continue

                consume(nested, depth + 1)

            return

        if isinstance(value, (list, tuple, set, frozenset)):
            for item in list(value)[:MAX_UNIQUE_VALUES]:
                consume(item, depth + 1)
                if len(records) >= max_records:
                    break

    consume(source)
    return records


def _coerce_int(value: Any) -> Optional[int]:
    if value is None:
        return None

    try:
        number = int(value)
        return number if number >= 1 else None
    except (TypeError, ValueError):
        return None


# ---------------------------------------------------------------------------
# Command-line registry parsing
# ---------------------------------------------------------------------------


def _extract_reg_command_records(
    text: str,
    records: List[RegistryRecord],
    record_seen: set,
    evidence: List[RegistryEvidence],
    evidence_seen: set,
) -> None:
    """
    Parse common ``reg.exe`` command forms statically.

    No command is executed.
    """
    command_pattern = _compile(
        r"(?im)^[ \t]*(?:[\"']?[^ \t\"']*\\)?reg(?:\.exe)?"
        r"[ \t]+"
        r"(add|delete|query|copy|save|restore|export|import|load|unload|compare)"
        r"\b[^\r\n]*"
    )

    for match in command_pattern.finditer(text):
        command = match.group(0).strip()
        verb = match.group(1).casefold()
        line_number = _line_number(text, match.start())

        path_match = REGISTRY_PATH_RE.search(command)
        path = normalize_registry_path(path_match.group(0)) if path_match else None

        hive = None
        if path:
            hive, _ = split_registry_path(path)

        if verb in {"add"}:
            category, indicator = (
                "registry_set_value",
                "reg_set_value",
            )
            operation = "set"
            severity = "high"
            confidence = 0.98
        elif verb in {"delete"}:
            category, indicator = (
                "registry_delete",
                "reg_delete",
            )
            operation = "delete"
            severity = "high"
            confidence = 0.98
        elif verb in {"query"}:
            category, indicator = (
                "registry_query_value",
                "reg_query_value",
            )
            operation = "query"
            severity = "low"
            confidence = 0.98
        elif verb in {"save", "export"}:
            category, indicator = (
                "registry_export",
                "reg_export",
            )
            operation = "export"
            severity = "medium"
            confidence = 0.98
        elif verb in {"restore", "import"}:
            category, indicator = (
                "registry_import",
                "reg_import",
            )
            operation = "import"
            severity = "medium"
            confidence = 0.98
        else:
            category, indicator = (
                "registry_read",
                "reg_read",
            )
            operation = verb
            severity = "low"
            confidence = 0.90

        record = RegistryRecord(
            operation=operation,
            key_path=path,
            hive=hive,
            source="reg_command",
            category=category,
            indicator=indicator,
            line_number=line_number,
            severity=severity,
            confidence=confidence,
            evidence=command,
        )
        _append_record(records, record_seen, record)

        item = RegistryEvidence(
            category=category,
            indicator=indicator,
            evidence=command,
            source="reg_command",
            line_number=line_number,
            hive=hive,
            key_path=path,
            operation=operation,
            severity=severity,
            confidence=confidence,
            context=_context(
                text,
                match.start(),
                match.end(),
            ),
        )
        _append_evidence(evidence, evidence_seen, item)


# ---------------------------------------------------------------------------
# API evidence
# ---------------------------------------------------------------------------


def _extract_api_evidence(
    text: str,
    evidence: List[RegistryEvidence],
    evidence_seen: set,
    records: List[RegistryRecord],
    record_seen: set,
) -> None:
    for (
        name,
        category,
        regex,
        description,
        severity,
        confidence,
    ) in COMPILED_API_RULES:
        matches = 0

        for match in regex.finditer(text):
            raw = match.group(0).strip()
            if not raw:
                continue

            line_number = _line_number(text, match.start())
            context = _context(text, match.start(), match.end())
            path = _find_nearby_registry_path(
                text,
                match.start(),
                match.end(),
            )

            hive = None
            if path:
                hive, _ = split_registry_path(path)

            indicator = _indicator_for_category(category)

            item = RegistryEvidence(
                category=category,
                indicator=indicator,
                evidence=raw,
                source="registry_api",
                line_number=line_number,
                hive=hive,
                key_path=path,
                operation=_operation_from_category(category),
                severity=severity,
                confidence=confidence,
                context=context,
            )
            _append_evidence(evidence, evidence_seen, item)

            operation = _operation_from_category(category)
            if operation:
                record = RegistryRecord(
                    operation=operation,
                    key_path=path,
                    hive=hive,
                    source="registry_api",
                    category=category,
                    indicator=indicator,
                    line_number=line_number,
                    severity=severity,
                    confidence=confidence,
                    evidence=raw,
                )
                _append_record(records, record_seen, record)

            matches += 1
            if matches >= MAX_MATCHES_PER_RULE:
                break


def _indicator_for_category(category: str) -> str:
    mapping = {
        "registry_read": "reg_read",
        "registry_write": "reg_write",
        "registry_delete": "reg_delete",
        "registry_create_key": "reg_create_key",
        "registry_set_value": "reg_set_value",
        "registry_query_value": "reg_query_value",
        "registry_enumeration": "reg_enum_key",
        "registry_key_exists": "reg_key_exists",
        "registry_open_key": "reg_open_key",
        "registry_close_key": "reg_close_key",
        "registry_backup": "reg_backup",
        "registry_restore": "reg_restore",
        "registry_export": "reg_export",
        "registry_import": "reg_import",
        "registry_run_key": "run_key",
        "registry_startup": "startup_registry",
        "registry_services": "service_registry_change",
        "registry_winlogon": "winlogon_persistence",
        "registry_userinit": "userinit_persistence",
        "registry_shell": "shell_persistence",
        "registry_appinit": "appinit_persistence",
        "registry_ifeo": "ifeo_persistence",
        "registry_com": "com_hijacking",
        "registry_protocol_handler": "protocol_handler_hijacking",
        "registry_file_association": "file_association_hijacking",
        "registry_bho": "bho_persistence",
        "registry_active_setup": "active_setup_persistence",
        "registry_scheduled_task": "scheduled_task_registry_change",
        "registry_policy": "policy_change",
        "registry_security": "security_product_change",
        "registry_firewall": "firewall_change",
        "registry_proxy": "proxy_change",
        "registry_rdp": "rdp_change",
        "registry_uac": "uac_change",
        "registry_defender": "defender_change",
        "registry_amais": "amsi_change",
        "registry_environment": "environment_change",
        "registry_credentials": "credential_registry_access",
        "registry_discovery": "registry_discovery",
        "registry_evasion": "registry_evasion",
        "registry_persistence": "startup_registry",
        "registry_execution": "registry_execution",
        "registry_injection": "registry_injection",
    }
    return mapping.get(category, category)


def _operation_from_category(category: str) -> Optional[str]:
    mapping = {
        "registry_read": "read",
        "registry_write": "write",
        "registry_delete": "delete",
        "registry_create_key": "create",
        "registry_set_value": "set",
        "registry_query_value": "query",
        "registry_enumeration": "enumerate",
        "registry_key_exists": "exists",
        "registry_open_key": "open",
        "registry_close_key": "close",
        "registry_backup": "backup",
        "registry_restore": "restore",
        "registry_export": "export",
        "registry_import": "import",
    }
    return mapping.get(category)


def _find_nearby_registry_path(
    text: str,
    start: int,
    end: int,
    radius: int = 700,
) -> Optional[str]:
    left = max(0, start - radius)
    right = min(len(text), end + radius)
    context = text[left:right]

    paths = extract_registry_paths(context, max_paths=30)
    if not paths:
        return None

    relative_position = start - left
    best_path = None
    best_distance = float("inf")

    for path in paths:
        local_position = context.casefold().find(path.casefold())
        if local_position < 0:
            continue

        distance = abs(local_position - relative_position)
        if distance < best_distance:
            best_distance = distance
            best_path = path

    return best_path


# ---------------------------------------------------------------------------
# Registry path evidence
# ---------------------------------------------------------------------------


def _extract_path_evidence(
    text: str,
    paths: Sequence[str],
    evidence: List[RegistryEvidence],
    evidence_seen: set,
) -> None:
    for path in paths:
        info = classify_registry_path(path)

        position = text.casefold().find(path.casefold())
        line_number = _line_number(text, position) if position >= 0 else None

        context = (
            _context(
                text,
                position,
                position + len(path),
            )
            if position >= 0
            else path
        )

        hive = info["hive"]

        if info["is_persistence"]:
            for match in info["persistence_matches"]:
                item = RegistryEvidence(
                    category=match["category"],
                    indicator=match["indicator"],
                    evidence=path,
                    source="registry_path",
                    line_number=line_number,
                    hive=hive,
                    key_path=path,
                    severity=(
                        "critical"
                        if match["indicator"]
                        in {
                            "winlogon_persistence",
                            "userinit_persistence",
                            "shell_persistence",
                            "appinit_persistence",
                        }
                        else "high"
                    ),
                    confidence=0.94,
                    context=context,
                )
                _append_evidence(
                    evidence,
                    evidence_seen,
                    item,
                )

        if info["is_security_sensitive"]:
            for match in info["security_matches"]:
                item = RegistryEvidence(
                    category=match["category"],
                    indicator=match["indicator"],
                    evidence=path,
                    source="registry_path",
                    line_number=line_number,
                    hive=hive,
                    key_path=path,
                    severity="high",
                    confidence=0.90,
                    context=context,
                )
                _append_evidence(
                    evidence,
                    evidence_seen,
                    item,
                )

        # Generic path evidence is useful even when the path is not a
        # known persistence/security location.
        item = RegistryEvidence(
            category="registry_read",
            indicator="registry_discovery",
            evidence=path,
            source="registry_path",
            line_number=line_number,
            hive=hive,
            key_path=path,
            severity="low",
            confidence=0.86,
            context=context,
        )
        _append_evidence(
            evidence,
            evidence_seen,
            item,
        )


# ---------------------------------------------------------------------------
# Semantic rules
# ---------------------------------------------------------------------------


def _extract_semantic_evidence(
    text: str,
    evidence: List[RegistryEvidence],
    evidence_seen: set,
) -> None:
    for (
        name,
        category,
        regex,
        description,
        severity,
        confidence,
    ) in COMPILED_SEMANTIC_RULES:
        matches = 0

        for match in regex.finditer(text):
            raw = match.group(0).strip()
            if not raw:
                continue

            position = match.start()
            path = _find_nearby_registry_path(
                text,
                match.start(),
                match.end(),
            )

            hive = None
            if path:
                hive, _ = split_registry_path(path)

            item = RegistryEvidence(
                category=category,
                indicator=name,
                evidence=raw,
                source="semantic_pattern",
                line_number=_line_number(text, position),
                hive=hive,
                key_path=path,
                operation=None,
                severity=severity,
                confidence=confidence,
                context=_context(
                    text,
                    match.start(),
                    match.end(),
                ),
            )
            _append_evidence(
                evidence,
                evidence_seen,
                item,
            )

            matches += 1
            if matches >= MAX_MATCHES_PER_RULE:
                break


# ---------------------------------------------------------------------------
# Generic Registry API/source interpretation
# ---------------------------------------------------------------------------


def _extract_generic_registry_indicators(
    text: str,
    evidence: List[RegistryEvidence],
    evidence_seen: set,
) -> None:
    generic_rules = (
        (
            "registry_read",
            "reg_read",
            r"\b(?:registry|regkey|reg key)\b.{0,100}\b(?:read|query|get|open|enumerate)\b",
            "Generic Registry read/query language.",
            "low",
            0.65,
        ),
        (
            "registry_write",
            "reg_write",
            r"\b(?:registry|regkey|reg key)\b.{0,100}\b(?:write|set|create|add|modify)\b",
            "Generic Registry write language.",
            "medium",
            0.68,
        ),
        (
            "registry_delete",
            "reg_delete",
            r"\b(?:registry|regkey|reg key)\b.{0,100}\b(?:delete|remove)\b",
            "Generic Registry deletion language.",
            "high",
            0.72,
        ),
        (
            "registry_discovery",
            "registry_discovery",
            r"\b(?:registry|regkey|reg key)\b.{0,100}\b(?:enumerate|enumeration|discover|discovery|query)\b",
            "Generic Registry discovery language.",
            "low",
            0.68,
        ),
    )

    for (
        category,
        indicator,
        expression,
        description,
        severity,
        confidence,
    ) in generic_rules:
        regex = _compile(expression)

        for index, match in enumerate(regex.finditer(text)):
            if index >= MAX_MATCHES_PER_RULE:
                break

            item = RegistryEvidence(
                category=category,
                indicator=indicator,
                evidence=match.group(0)[:MAX_FIELD_TEXT],
                source="generic_semantics",
                line_number=_line_number(text, match.start()),
                severity=severity,
                confidence=confidence,
                context=_context(
                    text,
                    match.start(),
                    match.end(),
                ),
            )
            _append_evidence(
                evidence,
                evidence_seen,
                item,
            )


# ---------------------------------------------------------------------------
# Value-name extraction
# ---------------------------------------------------------------------------


def _extract_value_names(
    text: str,
    max_values: int = MAX_UNIQUE_VALUES,
) -> List[str]:
    """
    Extract likely Registry value names from common command/API syntax.

    This is intentionally conservative because arbitrary strings can look
    like value names.
    """
    values: List[str] = []
    seen = set()

    patterns = (
        _compile(
            r"(?:/v|-Name|[- ]Name|value(?:name)?)[ \t:=]+"
            r"['\"]?([A-Za-z0-9_$%~.\- ]{1,180})['\"]?",
        ),
        _compile(
            r"\b(?:RegSetValueEx|RegQueryValueEx|SetValue|GetValue)"
            r"\s*\([^,\r\n]{1,500},\s*['\"]([^'\"]{1,180})['\"]",
        ),
    )

    for regex in patterns:
        for match in regex.finditer(text):
            value = match.group(1).strip()

            if not value:
                continue

            key = value.casefold()
            if key in seen:
                continue

            seen.add(key)
            values.append(value)

            if len(values) >= max_values:
                return values

    return values


# ---------------------------------------------------------------------------
# Combination logic
# ---------------------------------------------------------------------------

COMBINATION_DEFINITIONS: Tuple[Tuple[str, Tuple[str, ...], str, str], ...] = (
    (
        "registry_persistence_write",
        ("run_key", "reg_set_value"),
        "A persistence-sensitive Run key is associated with a Registry write.",
        "critical",
    ),
    (
        "winlogon_persistence_write",
        ("winlogon_persistence", "reg_set_value"),
        "Winlogon persistence configuration is associated with a Registry write.",
        "critical",
    ),
    (
        "service_persistence_write",
        ("service_registry_change", "reg_set_value"),
        "A service registry location is associated with a Registry write.",
        "high",
    ),
    (
        "com_hijacking_write",
        ("com_hijacking", "reg_set_value"),
        "A COM registration location is associated with a Registry write.",
        "high",
    ),
    (
        "ifeo_write",
        ("ifeo_persistence", "reg_set_value"),
        "Image File Execution Options is associated with a Registry write.",
        "critical",
    ),
    (
        "registry_export_credentials",
        ("credential_registry_access", "reg_export"),
        "Credential-related Registry content is associated with export/backup behavior.",
        "critical",
    ),
    (
        "security_product_modification",
        ("security_product_change", "reg_set_value"),
        "Security-product-related Registry configuration is associated with a write.",
        "critical",
    ),
    (
        "firewall_modification",
        ("firewall_change", "reg_set_value"),
        "Firewall configuration is associated with a Registry write.",
        "high",
    ),
    (
        "uac_modification",
        ("uac_change", "reg_set_value"),
        "UAC-related configuration is associated with a Registry write.",
        "high",
    ),
    (
        "proxy_modification",
        ("proxy_change", "reg_set_value"),
        "Proxy/Internet configuration is associated with a Registry write.",
        "high",
    ),
    (
        "rdp_modification",
        ("rdp_change", "reg_set_value"),
        "Remote Desktop configuration is associated with a Registry write.",
        "high",
    ),
    (
        "registry_backup_restore",
        ("reg_backup", "reg_restore"),
        "Registry backup and restore operations are both present.",
        "medium",
    ),
    (
        "registry_import_export",
        ("reg_import", "reg_export"),
        "Registry import and export operations are both present.",
        "medium",
    ),
    (
        "registry_delete_after_write",
        ("reg_write", "reg_delete"),
        "Registry modification and deletion behavior are both present.",
        "high",
    ),
)


def _derive_combinations(
    indicators: set,
    evidence: Sequence[RegistryEvidence],
    records: Sequence[RegistryRecord],
) -> List[RegistryCombination]:
    combinations: List[RegistryCombination] = []

    for name, required, explanation, severity in COMBINATION_DEFINITIONS:
        present = all(
            required_indicator in indicators for required_indicator in required
        )

        combinations.append(
            RegistryCombination(
                name=name,
                present=present,
                required_indicators=required,
                explanation=explanation,
                severity=severity,
            )
        )

    # Record-aware refinement: distinguish a write specifically associated
    # with a persistence-sensitive path.
    persistence_write = any(
        record.operation in {"write", "set", "create"}
        and record.key_path
        and classify_registry_path(record.key_path)["is_persistence"]
        for record in records
    )

    if persistence_write:
        combinations.append(
            RegistryCombination(
                name="persistence_path_structured_write",
                present=True,
                required_indicators=(
                    "registry_persistence_path",
                    "reg_set_value",
                ),
                explanation=(
                    "Structured evidence associates a Registry write with "
                    "a persistence-sensitive path."
                ),
                severity="critical",
            )
        )

    return combinations


# ---------------------------------------------------------------------------
# Feature vector
# ---------------------------------------------------------------------------


def registry_feature_names() -> List[str]:
    """Return deterministic feature names."""
    names = [
        "registry_source_size",
        "registry_path_count",
        "registry_record_count",
        "registry_evidence_count",
        "registry_indicator_count",
        "registry_category_count",
        "registry_combination_count",
        "registry_present_combination_count",
        "registry_hive_count",
        "registry_persistence_path_count",
        "registry_security_path_count",
        "registry_suspicious_path_count",
        "registry_write_path_count",
        "registry_delete_path_count",
        "registry_hklm_path_count",
        "registry_hkcu_path_count",
        "registry_hkcr_path_count",
        "registry_hku_path_count",
        "registry_hkcc_path_count",
        "registry_high_severity_count",
        "registry_critical_severity_count",
        "registry_max_severity",
        "registry_signal_score",
        "registry_value_name_count",
    ]

    for category in REGISTRY_CATEGORIES:
        names.append(f"registry_category_{category}_present")
        names.append(f"registry_category_{category}_count")

    for indicator in INDICATOR_NAMES:
        names.append(f"registry_indicator_{indicator}_present")
        names.append(f"registry_indicator_{indicator}_count")

    for name, _, _, _ in COMBINATION_DEFINITIONS:
        names.append(f"registry_combination_{name}")

    names.append("registry_combination_persistence_path_structured_write")

    return names


def build_feature_schema() -> Dict[str, Any]:
    """Build a JSON-compatible Registry feature schema."""
    return {
        "name": "pharos.registry_behavior",
        "version": "1.0",
        "description": (
            "Static Windows Registry behavior features derived from "
            "documents, VBA, scripts, and binary-analysis evidence."
        ),
        "static_only": True,
        "feature_names": registry_feature_names(),
        "feature_count": len(registry_feature_names()),
        "categories": list(REGISTRY_CATEGORIES),
        "indicators": list(INDICATOR_NAMES),
        "combinations": [item[0] for item in COMBINATION_DEFINITIONS]
        + ["persistence_path_structured_write"],
    }


def _build_feature_vector(
    analysis: RegistryAnalysis,
    value_names: Optional[Sequence[str]] = None,
) -> Dict[str, float]:
    indicator_counts = {name: 0 for name in INDICATOR_NAMES}

    category_counts = {name: 0 for name in REGISTRY_CATEGORIES}

    for item in analysis.evidence:
        if item.indicator in indicator_counts:
            indicator_counts[item.indicator] += 1

        if item.category in category_counts:
            category_counts[item.category] += 1

    high_count = sum(1 for item in analysis.evidence if item.severity == "high")

    critical_count = sum(1 for item in analysis.evidence if item.severity == "critical")

    present_combinations = [item for item in analysis.combinations if item.present]

    score = 0.0

    for item in analysis.evidence:
        score += SEVERITY_WEIGHT.get(item.severity, 1.0) * _normalize_confidence(
            item.confidence
        )

    for combination in present_combinations:
        score += (
            SEVERITY_WEIGHT.get(
                combination.severity,
                1.0,
            )
            * 2.0
        )

    score = _clamp(score, 0.0, 100.0)

    groups = classify_registry_paths(analysis.registry_paths)

    feature_vector: Dict[str, float] = {
        "registry_source_size": float(analysis.source_size),
        "registry_path_count": float(len(analysis.registry_paths)),
        "registry_record_count": float(len(analysis.records)),
        "registry_evidence_count": float(len(analysis.evidence)),
        "registry_indicator_count": float(len(analysis.indicators)),
        "registry_category_count": float(len(analysis.categories)),
        "registry_combination_count": float(len(analysis.combinations)),
        "registry_present_combination_count": float(len(present_combinations)),
        "registry_hive_count": float(len(analysis.hives)),
        "registry_persistence_path_count": float(len(analysis.persistence_paths)),
        "registry_security_path_count": float(len(analysis.security_paths)),
        "registry_suspicious_path_count": float(len(analysis.suspicious_paths)),
        "registry_write_path_count": float(len(analysis.write_paths)),
        "registry_delete_path_count": float(len(analysis.delete_paths)),
        "registry_hklm_path_count": float(len(groups["hklm"])),
        "registry_hkcu_path_count": float(len(groups["hkcu"])),
        "registry_hkcr_path_count": float(len(groups["hkcr"])),
        "registry_hku_path_count": float(len(groups["hku"])),
        "registry_hkcc_path_count": float(len(groups["hkcc"])),
        "registry_high_severity_count": float(high_count),
        "registry_critical_severity_count": float(critical_count),
        "registry_max_severity": float(
            _severity_rank(
                _max_severity(item.severity for item in analysis.evidence)
                if analysis.evidence
                else "low"
            )
        ),
        "registry_signal_score": float(score),
        "registry_value_name_count": float(len(value_names or [])),
    }

    for category in REGISTRY_CATEGORIES:
        count = category_counts[category]
        feature_vector[f"registry_category_{category}_present"] = 1.0 if count else 0.0
        feature_vector[f"registry_category_{category}_count"] = float(count)

    for indicator in INDICATOR_NAMES:
        count = indicator_counts[indicator]
        feature_vector[f"registry_indicator_{indicator}_present"] = (
            1.0 if count else 0.0
        )
        feature_vector[f"registry_indicator_{indicator}_count"] = float(count)

    for name, _, _, _ in COMBINATION_DEFINITIONS:
        feature_vector[f"registry_combination_{name}"] = float(
            any(item.name == name and item.present for item in analysis.combinations)
        )

    feature_vector["registry_combination_persistence_path_structured_write"] = float(
        any(
            item.name == "persistence_path_structured_write" and item.present
            for item in analysis.combinations
        )
    )

    return feature_vector


def vectorize_features(
    analysis: RegistryAnalysis,
    feature_names: Optional[Sequence[str]] = None,
) -> List[float]:
    """Convert an analysis to an ordered numeric vector."""
    vector = analysis.feature_vector or _build_feature_vector(analysis)

    names = (
        list(feature_names) if feature_names is not None else registry_feature_names()
    )

    return [float(vector.get(name, 0.0)) for name in names]


# ---------------------------------------------------------------------------
# Main analysis
# ---------------------------------------------------------------------------


def analyze_registry_behavior(
    source: Any,
    *,
    include_paths: bool = True,
    include_records: bool = True,
    max_evidence: int = MAX_EVIDENCE_ITEMS,
    max_paths: int = MAX_REGISTRY_PATHS,
) -> RegistryAnalysis:
    """
    Perform bounded static Registry-behavior analysis.

    The function accepts raw source text, bytes, or structured analysis data.
    It never accesses the actual operating-system Registry.
    """
    text, source_size, source_kind = _read_source(source)
    source_hash = _sha256_text(text)

    evidence: List[RegistryEvidence] = []
    evidence_seen = set()

    records: List[RegistryRecord] = []
    record_seen = set()

    if include_records:
        structured_records = extract_registry_records(
            source,
            max_records=MAX_REGISTRY_OPERATIONS,
        )

        for record in structured_records:
            _append_record(
                records,
                record_seen,
                record,
            )

            category = record.category or "registry_read"

            indicator = record.indicator or _indicator_for_category(category)

            item = RegistryEvidence(
                category=category,
                indicator=indicator,
                evidence=(record.evidence or record.operation),
                source=record.source,
                line_number=record.line_number,
                hive=record.hive,
                key_path=record.key_path,
                value_name=record.value_name,
                operation=record.operation,
                severity=record.severity,
                confidence=record.confidence,
            )

            _append_evidence(
                evidence,
                evidence_seen,
                item,
            )

    _extract_reg_command_records(
        text,
        records,
        record_seen,
        evidence,
        evidence_seen,
    )

    _extract_api_evidence(
        text,
        evidence,
        evidence_seen,
        records,
        record_seen,
    )

    _extract_semantic_evidence(
        text,
        evidence,
        evidence_seen,
    )

    _extract_generic_registry_indicators(
        text,
        evidence,
        evidence_seen,
    )

    registry_paths = (
        extract_registry_paths(
            text,
            max_paths=max_paths,
        )
        if include_paths
        else []
    )

    if include_paths:
        _extract_path_evidence(
            text,
            registry_paths,
            evidence,
            evidence_seen,
        )

    if len(evidence) > max_evidence:
        evidence = evidence[:max_evidence]

    # Reconcile structured records with path context after all paths are known.
    if include_records and registry_paths:
        for record in records:
            if not record.key_path:
                continue

            normalized = normalize_registry_path(record.key_path)

            if normalized not in registry_paths:
                registry_paths.append(normalized)

            if len(registry_paths) >= max_paths:
                break

    groups = classify_registry_paths(registry_paths)

    # Determine path-associated operations.
    write_paths: List[str] = []
    delete_paths: List[str] = []

    for record in records:
        if not record.key_path:
            continue

        if record.operation in {
            "write",
            "set",
            "create",
        }:
            if record.key_path not in write_paths:
                write_paths.append(record.key_path)

        if record.operation in {
            "delete",
        }:
            if record.key_path not in delete_paths:
                delete_paths.append(record.key_path)

    # Also infer operation/path relationships from nearby evidence.
    for item in evidence:
        if not item.key_path:
            continue

        if item.indicator in {
            "reg_write",
            "reg_set_value",
            "reg_create_key",
            "reg_add",
        }:
            if item.key_path not in write_paths:
                write_paths.append(item.key_path)

        if item.indicator in {
            "reg_delete",
            "reg_delete_key",
            "reg_delete_value",
        }:
            if item.key_path not in delete_paths:
                delete_paths.append(item.key_path)

    indicators = {item.indicator for item in evidence if item.indicator}

    categories = {item.category for item in evidence if item.category}

    # Path groups add explicit semantic signals.
    if groups["persistence"]:
        indicators.add("startup_registry")
        categories.add("registry_persistence")

    if groups["security"]:
        indicators.add("security_product_change")
        categories.add("registry_security")

    if groups["services"]:
        indicators.add("service_registry_change")
        categories.add("registry_services")

    # Persistence-path structured-write condition.
    if any(
        record.key_path
        and record.operation in {"write", "set", "create"}
        and classify_registry_path(record.key_path)["is_persistence"]
        for record in records
    ):
        indicators.add("registry_persistence")
        categories.add("registry_persistence")

    combinations = _derive_combinations(
        indicators,
        evidence,
        records,
    )

    ordered_indicators = sorted(
        indicators,
        key=lambda item: (
            (
                INDICATOR_NAMES.index(item)
                if item in INDICATOR_NAMES
                else len(INDICATOR_NAMES)
            ),
            item,
        ),
    )

    ordered_categories = sorted(
        categories,
        key=lambda item: (
            (
                REGISTRY_CATEGORIES.index(item)
                if item in REGISTRY_CATEGORIES
                else len(REGISTRY_CATEGORIES)
            ),
            item,
        ),
    )

    hives = extract_hives(registry_paths)

    persistence_paths = groups["persistence"]
    security_paths = groups["security"]
    suspicious_paths = groups["suspicious"]

    value_names = _extract_value_names(text)

    analysis = RegistryAnalysis(
        source_hash=source_hash,
        source_size=source_size,
        evidence=evidence,
        records=records if include_records else [],
        indicators=ordered_indicators,
        categories=ordered_categories,
        combinations=combinations,
        registry_paths=registry_paths,
        hives=hives,
        persistence_paths=persistence_paths,
        security_paths=security_paths,
        suspicious_paths=suspicious_paths,
        write_paths=write_paths[:MAX_REGISTRY_PATHS],
        delete_paths=delete_paths[:MAX_REGISTRY_PATHS],
        metadata={
            "module": "pharos.extraction.behavior.registry",
            "version": "1.0",
            "static_only": True,
            "source_kind": source_kind,
            "limits": {
                "max_source_size": MAX_SOURCE_SIZE,
                "max_text_chars": MAX_TEXT_CHARS,
                "max_evidence_items": max_evidence,
                "max_registry_paths": max_paths,
                "max_registry_operations": MAX_REGISTRY_OPERATIONS,
            },
            "evidence_truncated": len(evidence) >= max_evidence,
            "paths_truncated": len(registry_paths) >= max_paths,
            "value_name_count": len(value_names),
        },
    )

    analysis.feature_vector = _build_feature_vector(
        analysis,
        value_names=value_names,
    )

    return analysis


# ---------------------------------------------------------------------------
# Public aliases
# ---------------------------------------------------------------------------


def analyze(
    source: Any,
    **kwargs: Any,
) -> RegistryAnalysis:
    """Alias for :func:`analyze_registry_behavior`."""
    return analyze_registry_behavior(
        source,
        **kwargs,
    )


def parse_registry_behavior(
    source: Any,
    **kwargs: Any,
) -> RegistryAnalysis:
    """Parser-style compatibility alias."""
    return analyze_registry_behavior(
        source,
        **kwargs,
    )


def extract_registry_features(
    source: Any,
    **kwargs: Any,
) -> Dict[str, float]:
    """Return the complete Registry feature mapping."""
    return analyze_registry_behavior(
        source,
        **kwargs,
    ).feature_vector


def extract_feature_vector(
    source: Any,
    feature_names: Optional[Sequence[str]] = None,
    **kwargs: Any,
) -> List[float]:
    """Return an ordered Registry feature vector."""
    analysis = analyze_registry_behavior(
        source,
        **kwargs,
    )

    return vectorize_features(
        analysis,
        feature_names=feature_names,
    )


def extract_registry_feature_vector(
    source: Any,
    feature_names: Optional[Sequence[str]] = None,
    **kwargs: Any,
) -> List[float]:
    """Explicit ML integration alias."""
    return extract_feature_vector(
        source,
        feature_names=feature_names,
        **kwargs,
    )


# ---------------------------------------------------------------------------
# Query helpers
# ---------------------------------------------------------------------------


def has_indicator(
    analysis: RegistryAnalysis,
    indicator: str,
) -> bool:
    """Return whether an indicator is present."""
    return indicator in set(analysis.indicators)


def has_category(
    analysis: RegistryAnalysis,
    category: str,
) -> bool:
    """Return whether a category is present."""
    return category in set(analysis.categories)


def indicator_count(
    analysis: RegistryAnalysis,
    indicator: str,
) -> int:
    """Return the evidence count for an indicator."""
    return sum(1 for item in analysis.evidence if item.indicator == indicator)


def category_count(
    analysis: RegistryAnalysis,
    category: str,
) -> int:
    """Return the evidence count for a category."""
    return sum(1 for item in analysis.evidence if item.category == category)


def evidence_by_category(
    analysis: RegistryAnalysis,
    category: str,
) -> List[RegistryEvidence]:
    """Return evidence belonging to a Registry category."""
    return [item for item in analysis.evidence if item.category == category]


def evidence_by_indicator(
    analysis: RegistryAnalysis,
    indicator: str,
) -> List[RegistryEvidence]:
    """Return evidence belonging to an indicator."""
    return [item for item in analysis.evidence if item.indicator == indicator]


def high_risk_evidence(
    analysis: RegistryAnalysis,
) -> List[RegistryEvidence]:
    """Return high/critical Registry evidence."""
    return [item for item in analysis.evidence if item.severity in {"high", "critical"}]


def present_combinations(
    analysis: RegistryAnalysis,
) -> List[RegistryCombination]:
    """Return only satisfied Registry behavior combinations."""
    return [item for item in analysis.combinations if item.present]


def highest_severity(
    analysis: RegistryAnalysis,
) -> str:
    """Return the highest evidence severity."""
    if not analysis.evidence:
        return "low"

    return _max_severity(item.severity for item in analysis.evidence)


# ---------------------------------------------------------------------------
# Serialization / summaries
# ---------------------------------------------------------------------------


def analysis_to_dict(
    analysis: RegistryAnalysis,
) -> Dict[str, Any]:
    """Convert RegistryAnalysis into a JSON-compatible dictionary."""
    return {
        "source_hash": analysis.source_hash,
        "source_size": analysis.source_size,
        "evidence": [asdict(item) for item in analysis.evidence],
        "records": [asdict(item) for item in analysis.records],
        "indicators": list(analysis.indicators),
        "categories": list(analysis.categories),
        "combinations": [asdict(item) for item in analysis.combinations],
        "registry_paths": list(analysis.registry_paths),
        "hives": list(analysis.hives),
        "persistence_paths": list(analysis.persistence_paths),
        "security_paths": list(analysis.security_paths),
        "suspicious_paths": list(analysis.suspicious_paths),
        "write_paths": list(analysis.write_paths),
        "delete_paths": list(analysis.delete_paths),
        "feature_vector": dict(analysis.feature_vector),
        "metadata": dict(analysis.metadata),
    }


def summarize_registry_behavior(
    analysis: RegistryAnalysis,
) -> Dict[str, Any]:
    """Return a compact report/API-friendly Registry summary."""
    present = present_combinations(analysis)

    return {
        "source_hash": analysis.source_hash,
        "source_size": analysis.source_size,
        "evidence_count": len(analysis.evidence),
        "record_count": len(analysis.records),
        "registry_path_count": len(analysis.registry_paths),
        "hive_count": len(analysis.hives),
        "indicator_count": len(analysis.indicators),
        "category_count": len(analysis.categories),
        "combination_count": len(present),
        "highest_severity": highest_severity(analysis),
        "signal_score": analysis.feature_vector.get(
            "registry_signal_score",
            0.0,
        ),
        "high_risk_evidence_count": len(high_risk_evidence(analysis)),
        "persistence_path_count": len(analysis.persistence_paths),
        "security_path_count": len(analysis.security_paths),
        "write_path_count": len(analysis.write_paths),
        "delete_path_count": len(analysis.delete_paths),
        "hives": list(analysis.hives),
        "present_combinations": [item.name for item in present],
    }


# ---------------------------------------------------------------------------
# Iterators
# ---------------------------------------------------------------------------


def iter_evidence(
    analysis: RegistryAnalysis,
) -> Iterator[RegistryEvidence]:
    """Yield Registry evidence."""
    yield from analysis.evidence


def iter_high_risk_evidence(
    analysis: RegistryAnalysis,
) -> Iterator[RegistryEvidence]:
    """Yield high/critical Registry evidence."""
    for item in analysis.evidence:
        if item.severity in {"high", "critical"}:
            yield item


def iter_records(
    analysis: RegistryAnalysis,
) -> Iterator[RegistryRecord]:
    """Yield normalized Registry records."""
    yield from analysis.records


def iter_paths(
    analysis: RegistryAnalysis,
) -> Iterator[str]:
    """Yield extracted Registry paths."""
    yield from analysis.registry_paths


def iter_combinations(
    analysis: RegistryAnalysis,
) -> Iterator[RegistryCombination]:
    """Yield Registry behavior combinations."""
    yield from analysis.combinations


def iter_analyses(
    sources: Iterable[Any],
    **kwargs: Any,
) -> Iterator[RegistryAnalysis]:
    """Lazily analyze multiple static sources."""
    for source in sources:
        yield analyze_registry_behavior(
            source,
            **kwargs,
        )


# ---------------------------------------------------------------------------
# Explicit exports
# ---------------------------------------------------------------------------

__all__ = [
    "MAX_SOURCE_SIZE",
    "MAX_TEXT_CHARS",
    "MAX_EVIDENCE_ITEMS",
    "MAX_REGISTRY_PATHS",
    "MAX_REGISTRY_OPERATIONS",
    "REGISTRY_CATEGORIES",
    "INDICATOR_NAMES",
    "HIVE_ALIASES",
    "KNOWN_HIVES",
    "RegistryPattern",
    "RegistryEvidence",
    "RegistryRecord",
    "RegistryCombination",
    "RegistryAnalysis",
    "PERSISTENCE_PATHS",
    "SECURITY_PATHS",
    "OPERATION_ALIASES",
    "normalize_hive",
    "split_registry_path",
    "normalize_registry_path",
    "extract_registry_paths",
    "extract_hives",
    "classify_registry_path",
    "classify_registry_paths",
    "normalize_operation",
    "extract_registry_records",
    "registry_feature_names",
    "build_feature_schema",
    "vectorize_features",
    "analyze_registry_behavior",
    "analyze",
    "parse_registry_behavior",
    "extract_registry_features",
    "extract_feature_vector",
    "extract_registry_feature_vector",
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
    "summarize_registry_behavior",
    "iter_evidence",
    "iter_high_risk_evidence",
    "iter_records",
    "iter_paths",
    "iter_combinations",
    "iter_analyses",
]
