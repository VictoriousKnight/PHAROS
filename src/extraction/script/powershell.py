"""
PowerShell / PowerShell-like script static analysis.

This module performs defensive, static-only analysis of PowerShell source.
It does not execute PowerShell, invoke cmdlets, load assemblies, resolve
remote resources, access the registry/filesystem through PowerShell, or spawn
child processes.

The analyzer is designed to complement ``src.extraction.script.parser`` and
produce stable, ML-friendly scalar features while retaining human-readable
evidence for CDR and malware-analysis decisions.

Supported inputs:
    * str containing PowerShell source
    * bytes containing PowerShell source
    * filesystem Path / path-like object

Primary APIs:
    analyze_powershell()
    parse_powershell()
    extract_powershell_features()
    extract_feature_vector()
    extract_powershell_feature_vector()
    powershell_feature_names()
    build_feature_schema()
    vectorize_features()
    has_indicator()
    has_category()
    high_risk_evidence()
    present_combinations()
    analysis_to_dict()
    summarize_powershell()
    iter_evidence()
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import math
import re
from collections import Counter, defaultdict
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
    Tuple,
    Union,
)

# ---------------------------------------------------------------------------
# Safety / resource limits
# ---------------------------------------------------------------------------

MAX_SOURCE_SIZE = 25 * 1024 * 1024
MAX_LINES = 250_000
MAX_EVIDENCE_ITEMS = 20_000
MAX_STRINGS = 50_000
MAX_URLS = 10_000
MAX_IDENTIFIERS = 100_000
MAX_TOKENS = 250_000
MAX_BASE64_DECODE_BYTES = 2 * 1024 * 1024
MAX_ENTROPY_BYTES = 1 * 1024 * 1024


# ---------------------------------------------------------------------------
# Severity and confidence
# ---------------------------------------------------------------------------

SEVERITIES = ("low", "medium", "high", "critical")
SEVERITY_RANK = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


# ---------------------------------------------------------------------------
# Indicator taxonomy
# ---------------------------------------------------------------------------

INDICATOR_CATEGORIES: Tuple[str, ...] = (
    "execution",
    "dynamic_execution",
    "download",
    "network",
    "encoded_command",
    "obfuscation",
    "reflection",
    "assembly",
    "process",
    "process_injection",
    "memory",
    "filesystem",
    "registry",
    "persistence",
    "credential_access",
    "discovery",
    "security_software",
    "evasion",
    "environment",
    "com_automation",
    "wmi",
    "archive",
    "encoding",
    "decoding",
    "logging",
    "amsi",
    "etw",
    "defender",
    "scheduled_task",
    "service",
    "bits",
    "certutil",
    "rundll32",
    "regsvr32",
    "mshta",
    "web_client",
    "powershell_hosting",
    "scripting",
)


@dataclass(frozen=True)
class PowerShellPattern:
    """A static PowerShell pattern definition."""

    name: str
    category: str
    regex: str
    severity: str
    confidence: float
    description: str
    weight: float


# ---------------------------------------------------------------------------
# PowerShell patterns
# ---------------------------------------------------------------------------

PATTERNS: Tuple[PowerShellPattern, ...] = (
    # Execution / dynamic execution
    PowerShellPattern(
        "invoke_expression",
        "dynamic_execution",
        r"(?im)(?:\bInvoke-Expression\b|\bIEX\b|\b&\s*\(?\s*(?:iex|invoke-expression)\b)",
        "high",
        0.98,
        "Invokes dynamically constructed PowerShell code.",
        18.0,
    ),
    PowerShellPattern(
        "invoke_command",
        "execution",
        r"(?im)\b(?:Invoke-Command|ICM)\b",
        "medium",
        0.90,
        "Uses PowerShell remoting or command invocation.",
        5.0,
    ),
    PowerShellPattern(
        "start_process",
        "process",
        r"(?im)\b(?:Start-Process|start-process)\b",
        "medium",
        0.96,
        "Starts a process through PowerShell.",
        7.0,
    ),
    PowerShellPattern(
        "call_operator",
        "dynamic_execution",
        r"(?m)(?:^|[\s;])&\s*(?:\$[A-Za-z_][\w:.-]*|\([^)]+\)|['\"])",
        "medium",
        0.84,
        "Uses the PowerShell call operator with a dynamic command expression.",
        7.0,
    ),
    PowerShellPattern(
        "scriptblock_create",
        "dynamic_execution",
        r"(?im)\[scriptblock\]::(?:Create|CreateAsModule)\s*\(",
        "high",
        0.98,
        "Creates executable PowerShell script blocks dynamically.",
        14.0,
    ),
    PowerShellPattern(
        "add_type",
        "assembly",
        r"(?im)\bAdd-Type\b",
        "medium",
        0.95,
        "Compiles or loads .NET type definitions from PowerShell.",
        7.0,
    ),
    PowerShellPattern(
        "reflection_load",
        "reflection",
        r"(?im)(?:\[[A-Za-z0-9_.+`]+\]\s*::(?:Load|LoadFile|LoadFrom|LoadWithPartialName)|Assembly\]::Load)",
        "high",
        0.97,
        "Loads .NET assemblies using reflection.",
        14.0,
    ),
    PowerShellPattern(
        "reflection_invoke",
        "reflection",
        r"(?im)(?:GetMethod|GetField|GetProperty|InvokeMember|\.Invoke\s*\()",
        "high",
        0.88,
        "Uses .NET reflection primitives capable of dynamic invocation.",
        11.0,
    ),
    # Encoded commands / decoding
    PowerShellPattern(
        "encoded_command",
        "encoded_command",
        r"(?im)(?:^|[\s/-])(?:-enc|-encodedcommand|/enc|/encodedcommand)(?:[\s:=]+|$)",
        "high",
        0.99,
        "Uses the PowerShell encoded-command option.",
        20.0,
    ),
    PowerShellPattern(
        "encoded_argument",
        "encoded_command",
        r"(?im)\b(?:-e|-ec|-enco|-encod|-encodedc|-encodedco|-encodedcom|-encodedcomm|-encodedcomma|-encodedcomman)\b",
        "high",
        0.96,
        "Uses an abbreviated PowerShell encoded-command parameter.",
        18.0,
    ),
    PowerShellPattern(
        "from_base64_string",
        "decoding",
        r"(?im)\[Convert\]::FromBase64String\s*\(",
        "high",
        0.98,
        "Decodes Base64 content in memory.",
        14.0,
    ),
    PowerShellPattern(
        "to_base64_string",
        "encoding",
        r"(?im)\[Convert\]::ToBase64String\s*\(",
        "low",
        0.88,
        "Encodes content as Base64.",
        3.0,
    ),
    PowerShellPattern(
        "base64_decode_transform",
        "decoding",
        r"(?im)(?:FromBase64String|FromBase64CharArray|Base64StringToByteArray)",
        "high",
        0.94,
        "Performs explicit Base64 decoding.",
        12.0,
    ),
    # Network / download
    PowerShellPattern(
        "invoke_web_request",
        "download",
        r"(?im)\b(?:Invoke-WebRequest|IWR)\b",
        "medium",
        0.97,
        "Uses PowerShell's web request functionality.",
        8.0,
    ),
    PowerShellPattern(
        "invoke_rest_method",
        "network",
        r"(?im)\b(?:Invoke-RestMethod|IRM)\b",
        "medium",
        0.97,
        "Uses PowerShell's REST/web request functionality.",
        7.0,
    ),
    PowerShellPattern(
        "web_client",
        "web_client",
        r"(?im)(?:New-Object\s+(?:Net\.)?WebClient|\[Net\.(?:WebClient|WebRequest)\]|\[System\.Net\.WebClient\])",
        "high",
        0.98,
        "Creates or references .NET web client functionality.",
        12.0,
    ),
    PowerShellPattern(
        "download_string",
        "download",
        r"(?im)\.(?:DownloadString|DownloadData|DownloadFile)\s*\(",
        "high",
        0.99,
        "Downloads remote content through a .NET web client.",
        14.0,
    ),
    PowerShellPattern(
        "http_request",
        "network",
        r"(?im)(?:HttpWebRequest|HttpClient|WebRequest|WebClient|WinHttpRequest|XMLHTTP|ServerXMLHTTP)",
        "medium",
        0.92,
        "References an HTTP/network client API.",
        6.0,
    ),
    PowerShellPattern(
        "uri_literal",
        "network",
        r"(?i)\b(?:https?|ftp)://[^\s'\"<>]+",
        "low",
        0.99,
        "Contains a network URI.",
        2.0,
    ),
    # Process execution / LOLBins
    PowerShellPattern(
        "cmd_execution",
        "execution",
        r"(?im)(?:\bcmd(?:\.exe)?\b\s*/[cC]\b|\bcmd\.exe\b)",
        "medium",
        0.94,
        "References Windows command interpreter execution.",
        7.0,
    ),
    PowerShellPattern(
        "powershell_execution",
        "powershell_hosting",
        r"(?im)\b(?:powershell|pwsh)(?:\.exe)?\b",
        "low",
        0.98,
        "References a PowerShell host executable.",
        3.0,
    ),
    PowerShellPattern(
        "mshta_execution",
        "mshta",
        r"(?im)\bmshta(?:\.exe)?\b",
        "high",
        0.99,
        "References mshta, a Windows signed binary commonly abused for execution.",
        12.0,
    ),
    PowerShellPattern(
        "rundll32_execution",
        "rundll32",
        r"(?im)\brundll32(?:\.exe)?\b",
        "high",
        0.99,
        "References rundll32 execution.",
        11.0,
    ),
    PowerShellPattern(
        "regsvr32_execution",
        "regsvr32",
        r"(?im)\bregsvr32(?:\.exe)?\b",
        "high",
        0.99,
        "References regsvr32 execution.",
        11.0,
    ),
    PowerShellPattern(
        "certutil_execution",
        "certutil",
        r"(?im)\bcertutil(?:\.exe)?\b",
        "high",
        0.99,
        "References certutil, which can be abused for transfer or decoding.",
        10.0,
    ),
    PowerShellPattern(
        "bitsadmin_execution",
        "bits",
        r"(?im)\b(?:bitsadmin(?:\.exe)?|Start-BitsTransfer)\b",
        "high",
        0.98,
        "References BITS transfer functionality.",
        10.0,
    ),
    # COM / WMI
    PowerShellPattern(
        "new_com_object",
        "com_automation",
        r"(?im)\bNew-Object\s+-ComObject\b",
        "medium",
        0.99,
        "Creates a COM automation object.",
        8.0,
    ),
    PowerShellPattern(
        "com_object_reference",
        "com_automation",
        r"(?im)\b(?:CreateObject|GetObject)\s*\(",
        "medium",
        0.88,
        "References generic COM-style object creation/access.",
        6.0,
    ),
    PowerShellPattern(
        "wmi",
        "wmi",
        r"(?im)\b(?:Get-WmiObject|gwmi|Get-CimInstance|New-CimSession|Invoke-CimMethod|winmgmts:|ManagementObject(?:Searcher)?|System\.Management)\b",
        "medium",
        0.96,
        "Uses WMI/CIM functionality.",
        8.0,
    ),
    PowerShellPattern(
        "wmi_process",
        "process",
        r"(?im)(?:Win32_Process|Win32_ProcessStartup|Create\s*\(\s*\$?CommandLine)",
        "high",
        0.96,
        "References WMI process creation or process-management classes.",
        12.0,
    ),
    # Process injection / memory
    PowerShellPattern(
        "virtual_alloc",
        "memory",
        r"(?im)\b(?:VirtualAlloc|VirtualAllocEx|VirtualProtect|VirtualProtectEx)\b",
        "critical",
        0.99,
        "References Windows virtual-memory APIs.",
        18.0,
    ),
    PowerShellPattern(
        "write_process_memory",
        "process_injection",
        r"(?im)\b(?:WriteProcessMemory|WriteProcessMemoryEx)\b",
        "critical",
        0.99,
        "References process-memory writing APIs.",
        22.0,
    ),
    PowerShellPattern(
        "create_remote_thread",
        "process_injection",
        r"(?im)\b(?:CreateRemoteThread|NtCreateThreadEx|RtlCreateUserThread)\b",
        "critical",
        0.99,
        "References APIs associated with remote-thread process injection.",
        22.0,
    ),
    PowerShellPattern(
        "open_process",
        "process",
        r"(?im)\b(?:OpenProcess|OpenProcessToken|GetCurrentProcess)\b",
        "medium",
        0.95,
        "References process handles or process-token APIs.",
        6.0,
    ),
    PowerShellPattern(
        "virtual_query",
        "memory",
        r"(?im)\b(?:VirtualQuery|VirtualQueryEx|ReadProcessMemory)\b",
        "high",
        0.98,
        "References process-memory inspection APIs.",
        13.0,
    ),
    # Filesystem
    PowerShellPattern(
        "filesystem_cmdlets",
        "filesystem",
        r"(?im)\b(?:Get-Content|Set-Content|Add-Content|Out-File|Clear-Content|Remove-Item|Copy-Item|Move-Item|New-Item|Get-Item|Get-ChildItem|Test-Path)\b",
        "low",
        0.96,
        "Uses PowerShell filesystem cmdlets.",
        2.0,
    ),
    PowerShellPattern(
        "file_stream",
        "filesystem",
        r"(?im)(?:FileStream|StreamReader|StreamWriter|ReadAllBytes|WriteAllBytes|ReadAllText|WriteAllText)",
        "medium",
        0.95,
        "Uses direct .NET file or stream APIs.",
        5.0,
    ),
    PowerShellPattern(
        "temp_directory",
        "filesystem",
        r"(?im)(?:\$env:TEMP|\$env:TMP|GetTempPath|IO\.Path]::GetTemp)",
        "medium",
        0.94,
        "References a temporary filesystem location.",
        5.0,
    ),
    # Registry / persistence
    PowerShellPattern(
        "registry_provider",
        "registry",
        r"(?im)(?:HKLM:|HKCU:|HKCR:|HKU:|HKCC:|Registry::|Get-ItemProperty|Set-ItemProperty|New-ItemProperty|Remove-ItemProperty)",
        "medium",
        0.95,
        "Accesses or modifies the Windows registry.",
        6.0,
    ),
    PowerShellPattern(
        "run_key",
        "persistence",
        r"(?im)(?:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run(?:Once)?\b|CurrentVersion['\"\\/:]+Run(?:Once)?)",
        "high",
        0.99,
        "References Windows startup Run/RunOnce persistence locations.",
        14.0,
    ),
    PowerShellPattern(
        "startup_folder",
        "persistence",
        r"(?im)(?:\\Start Menu\\Programs\\Startup\b|Shell(?:Application)?::SpecialFolders.*Startup|CommonStartup)",
        "high",
        0.97,
        "References a Windows startup folder.",
        12.0,
    ),
    PowerShellPattern(
        "scheduled_task",
        "scheduled_task",
        r"(?im)\b(?:Register-ScheduledTask|New-ScheduledTaskAction|schtasks(?:\.exe)?)\b",
        "high",
        0.99,
        "References Windows scheduled-task persistence or execution.",
        12.0,
    ),
    PowerShellPattern(
        "service_creation",
        "service",
        r"(?im)\b(?:New-Service|Set-Service|sc(?:\.exe)?\s+(?:create|config)|CreateService(?:W|A)?)\b",
        "high",
        0.98,
        "References Windows service creation or modification.",
        12.0,
    ),
    # Credentials / discovery
    PowerShellPattern(
        "credential_cmdlets",
        "credential_access",
        r"(?im)\b(?:Get-Credential|ConvertTo-SecureString|PSCredential|CredentialManager|Get-StoredCredential)\b",
        "medium",
        0.94,
        "References PowerShell credential handling or stored credentials.",
        6.0,
    ),
    PowerShellPattern(
        "sam_security_account_manager",
        "credential_access",
        r"(?im)(?:\\SAM\\|SecurityAccountsManager|Win32_UserAccount|Get-LocalUser)",
        "high",
        0.95,
        "References local-account or SAM-related data.",
        12.0,
    ),
    PowerShellPattern(
        "lsass",
        "credential_access",
        r"(?im)\b(?:lsass(?:\.exe)?|MiniDumpWriteDump|comsvcs\.dll)\b",
        "critical",
        0.98,
        "References LSASS or process-dump credential-access primitives.",
        20.0,
    ),
    PowerShellPattern(
        "system_discovery",
        "discovery",
        r"(?im)\b(?:Get-ComputerInfo|Get-CimInstance|Get-WmiObject|Get-Process|Get-Service|Get-NetIPConfiguration|Get-NetAdapter|Get-NetTCPConnection|ipconfig|systeminfo|whoami|hostname|tasklist)\b",
        "low",
        0.91,
        "Performs host, process, service, account, or network discovery.",
        3.0,
    ),
    PowerShellPattern(
        "security_product_discovery",
        "security_software",
        r"(?im)(?:Get-MpComputerStatus|Get-MpPreference|WinDefend|MsMpEng|Defender|AntiVirusProduct|SecurityCenter2)",
        "medium",
        0.96,
        "References endpoint security or Microsoft Defender state.",
        7.0,
    ),
    # AMSI / ETW / evasion
    PowerShellPattern(
        "amsi_reference",
        "amsi",
        r"(?im)\b(?:amsi|AmsiUtils|AmsiScanBuffer|AmsiScanString|amsiInitFailed)\b",
        "high",
        0.98,
        "References PowerShell AMSI internals or APIs.",
        13.0,
    ),
    PowerShellPattern(
        "amsi_bypass_field",
        "amsi",
        r"(?im)(?:AmsiUtils|amsiUtils|amsiInitFailed|amsiContext|amsiSession)",
        "critical",
        0.97,
        "References known AMSI bypass-oriented implementation details.",
        18.0,
    ),
    PowerShellPattern(
        "etw_reference",
        "etw",
        r"(?im)\b(?:EventWrite|EtwEventWrite|EtwEventWriteFull|EventProvider|PSEtwLogProvider)\b",
        "high",
        0.96,
        "References ETW telemetry functionality.",
        12.0,
    ),
    PowerShellPattern(
        "logging_control",
        "logging",
        r"(?im)(?:ScriptBlockLogging|ModuleLogging|Transcription|Set-PSDebug|LogPipelineExecutionDetails)",
        "medium",
        0.92,
        "References PowerShell logging or debugging controls.",
        6.0,
    ),
    PowerShellPattern(
        "error_suppression",
        "evasion",
        r"(?im)(?:-ErrorAction\s+SilentlyContinue|\$ErrorActionPreference\s*=\s*['\"]SilentlyContinue['\"])",
        "medium",
        0.93,
        "Suppresses PowerShell errors, potentially hiding execution failures.",
        5.0,
    ),
    PowerShellPattern(
        "execution_policy_bypass",
        "evasion",
        r"(?im)(?:-ExecutionPolicy\s+(?:Bypass|Unrestricted)|Set-ExecutionPolicy\s+(?:Bypass|Unrestricted))",
        "high",
        0.98,
        "References PowerShell execution-policy bypass or weakening.",
        12.0,
    ),
    PowerShellPattern(
        "no_profile",
        "evasion",
        r"(?im)(?:\s-(?:NoProfile|NonInteractive)\b)",
        "low",
        0.94,
        "Uses PowerShell host options that can reduce normal interactive behavior.",
        3.0,
    ),
    PowerShellPattern(
        "hidden_window",
        "evasion",
        r"(?im)(?:-WindowStyle\s+Hidden|\bHiddenWindow\b)",
        "medium",
        0.96,
        "Requests hidden PowerShell process/window execution.",
        8.0,
    ),
    PowerShellPattern(
        "bypass_encoded_combo",
        "evasion",
        r"(?im)(?=.*(?:-enc|-encodedcommand))(?=.*(?:-executionpolicy\s+bypass|powershell|pwsh))",
        "high",
        0.99,
        "Combines encoded command execution with PowerShell policy bypass.",
        18.0,
    ),
    # Environment / anti-analysis
    PowerShellPattern(
        "environment_variables",
        "environment",
        r"(?im)\$env:[A-Za-z_][A-Za-z0-9_]*",
        "low",
        0.98,
        "Reads or references environment variables.",
        1.5,
    ),
    PowerShellPattern(
        "virtualization_checks",
        "evasion",
        r"(?im)(?:VMware|VirtualBox|Hyper-V|QEMU|KVM|VIRTUAL|VBox|VMTools|vboxservice)",
        "medium",
        0.93,
        "Contains virtualization or sandbox-related identifiers.",
        6.0,
    ),
    PowerShellPattern(
        "debugger_checks",
        "evasion",
        r"(?im)(?:IsDebuggerPresent|CheckRemoteDebuggerPresent|Debugger\.IsAttached)",
        "high",
        0.97,
        "References debugger-detection primitives.",
        12.0,
    ),
    # Archives / payload handling
    PowerShellPattern(
        "archive_cmdlets",
        "archive",
        r"(?im)\b(?:Expand-Archive|Compress-Archive)\b",
        "low",
        0.98,
        "Uses PowerShell archive functionality.",
        2.0,
    ),
    PowerShellPattern(
        "zip_api",
        "archive",
        r"(?im)(?:ZipArchive|System\.IO\.Compression|GZipStream|DeflateStream)",
        "low",
        0.93,
        "References .NET compression APIs.",
        3.0,
    ),
    PowerShellPattern(
        "invoke_member",
        "dynamic_execution",
        r"(?im)\b(?:Invoke-Member|InvokeMember)\b",
        "medium",
        0.92,
        "Uses dynamic member invocation.",
        7.0,
    ),
)


# ---------------------------------------------------------------------------
# Additional lexical patterns
# ---------------------------------------------------------------------------

URL_RE = re.compile(r"(?i)\b(?:https?|ftp)://[^\s<>'\"`]+")

IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}" r"(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
)

WINDOWS_PATH_RE = re.compile(r"""(?ix)
    (?:
        [A-Za-z]:\\[^\r\n"'`<>|]+
        |
        \\\\[A-Za-z0-9_.-]+\\[^\r\n"'`<>|]+
    )
    """)

UNC_PATH_RE = re.compile(r"""(?i)\\\\[A-Za-z0-9_.-]+\\[^\r\n"'`<>|]+""")

REGISTRY_PATH_RE = re.compile(r"""(?ix)
    (?:
        HKLM|HKCU|HKCR|HKU|HKCC|HKEY_LOCAL_MACHINE|
        HKEY_CURRENT_USER|HKEY_CLASSES_ROOT|HKEY_USERS|
        HKEY_CURRENT_CONFIG
    )
    [\\/:][^\r\n"'`<>]+
    """)

VARIABLE_RE = re.compile(
    r"(?<![\w])\$[A-Za-z_][A-Za-z0-9_]*(?::[A-Za-z_][A-Za-z0-9_]*)?"
)

COMMAND_RE = re.compile(
    r"(?im)(?<![\w-])"
    r"(?:"
    r"Invoke-[A-Za-z][\w-]*|"
    r"Get-[A-Za-z][\w-]*|"
    r"Set-[A-Za-z][\w-]*|"
    r"New-[A-Za-z][\w-]*|"
    r"Remove-[A-Za-z][\w-]*|"
    r"Start-[A-Za-z][\w-]*|"
    r"Stop-[A-Za-z][\w-]*|"
    r"Add-[A-Za-z][\w-]*|"
    r"ConvertTo-[A-Za-z][\w-]*|"
    r"ConvertFrom-[A-Za-z][\w-]*|"
    r"Register-[A-Za-z][\w-]*|"
    r"Unregister-[A-Za-z][\w-]*|"
    r"Test-[A-Za-z][\w-]*|"
    r"Write-[A-Za-z][\w-]*|"
    r"Read-[A-Za-z][\w-]*"
    r")\b"
)

FUNCTION_RE = re.compile(r"(?im)^\s*(?:function|filter)\s+([A-Za-z_][A-Za-z0-9_.-]*)")

ALIAS_RE = re.compile(
    r"(?im)(?:Set-Alias|New-Alias)\s+(?:-[^\s]+\s+)*"
    r"(?:(?:-Name|-N)\s+)?['\"]?([A-Za-z_][\w-]*)['\"]?"
)

PARAMETER_RE = re.compile(r"(?im)(?<![\w-])-[A-Za-z][A-Za-z0-9-]*")

STRING_RE = re.compile(r"""(?xs)
    '(?:''|[^'])*'
    |
    "(?:""|`.|[^"`])*"
    """)

BASE64_TOKEN_RE = re.compile(
    r"(?<![A-Za-z0-9+/=])" r"[A-Za-z0-9+/]{40,}={0,2}" r"(?![A-Za-z0-9+/=])"
)

HEX_TOKEN_RE = re.compile(r"(?i)(?<![0-9a-f])" r"(?:[0-9a-f]{2}){16,}" r"(?![0-9a-f])")

CONCAT_RE = re.compile(r"""(?x)
    (?:
        ['"][^'"]{1,200}['"]\s*\+\s*
        ['"][^'"]{1,200}['"]
    )
    |
    (?:
        ['"][^'"]{1,200}['"]\s*\+\s*\$
    )
    """)

CHAR_CONSTRUCTION_RE = re.compile(
    r"(?im)(?:\[\s*char\s*\]\s*|\b(?:char|charw)\s*\()\s*[0-9A-Fx]",
)

FORMAT_CONSTRUCTION_RE = re.compile(
    r"(?im)(?:-f\s+['\"]|['\"].*?\{[0-9]+\}.*?['\"]\s*-f)"
)

REFLECTION_TYPE_RE = re.compile(r"(?im)\[\s*(?:type|gettype)\s*\]\s*\(\s*['\"]")

DOTNET_TYPE_RE = re.compile(r"(?im)\[[A-Za-z_][A-Za-z0-9_.]*(?:`[0-9]+)?\]")


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


@dataclass
class PowerShellString:
    """A statically extracted PowerShell string literal."""

    value: str
    line_number: int
    quote: str
    length: int
    entropy: float
    is_base64_like: bool = False
    is_hex_like: bool = False


@dataclass
class PowerShellEvidence:
    """One piece of PowerShell-specific static evidence."""

    indicator: str
    category: str
    evidence: str
    severity: str
    confidence: float
    line_number: Optional[int] = None
    description: str = ""
    source: str = "powershell"
    weight: float = 0.0


@dataclass
class PowerShellCombination:
    """A derived combination of lower-level indicators."""

    name: str
    present: bool
    required_indicators: List[str] = field(default_factory=list)
    explanation: str = ""
    severity: str = "medium"


@dataclass
class PowerShellAnalysis:
    """Complete static PowerShell analysis result."""

    family: str
    source_hash: str
    source_size: int
    line_count: int

    commands: List[str] = field(default_factory=list)
    functions: List[str] = field(default_factory=list)
    aliases: List[str] = field(default_factory=list)
    parameters: List[str] = field(default_factory=list)
    variables: List[str] = field(default_factory=list)
    urls: List[str] = field(default_factory=list)
    ipv4_addresses: List[str] = field(default_factory=list)
    windows_paths: List[str] = field(default_factory=list)
    registry_paths: List[str] = field(default_factory=list)

    strings: List[PowerShellString] = field(default_factory=list)
    evidence: List[PowerShellEvidence] = field(default_factory=list)
    indicators: List[str] = field(default_factory=list)
    categories: List[str] = field(default_factory=list)
    combinations: List[PowerShellCombination] = field(default_factory=list)

    feature_vector: Dict[str, float] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Source handling
# ---------------------------------------------------------------------------


def _decode_bytes(data: bytes) -> str:
    """Decode PowerShell source without executing it."""

    if data.startswith(b"\xff\xfe"):
        return data[2:].decode("utf-16-le", errors="replace")

    if data.startswith(b"\xfe\xff"):
        return data[2:].decode("utf-16-be", errors="replace")

    if data.startswith(b"\xef\xbb\xbf"):
        return data[3:].decode("utf-8", errors="replace")

    # UTF-16LE PowerShell files sometimes have no BOM. Only use the heuristic
    # when a substantial fraction of NUL bytes is present.
    if len(data) >= 64:
        nul_ratio = data.count(b"\x00") / max(len(data), 1)
        if nul_ratio > 0.20:
            try:
                return data.decode("utf-16-le", errors="replace")
            except UnicodeDecodeError:
                pass

    return data.decode("utf-8", errors="replace")


def _read_source(
    source: Union[str, bytes, bytearray, memoryview, Path],
    *,
    max_size: int = MAX_SOURCE_SIZE,
) -> Tuple[str, Optional[str]]:
    """
    Read source as text.

    Returns:
        (text, optional_source_name)
    """

    if isinstance(source, Path):
        size = source.stat().st_size
        if size > max_size:
            raise ValueError(
                f"PowerShell source exceeds maximum supported size "
                f"({size} > {max_size} bytes)"
            )
        return _decode_bytes(source.read_bytes()), str(source)

    if isinstance(source, (bytes, bytearray, memoryview)):
        data = bytes(source)
        if len(data) > max_size:
            raise ValueError(
                f"PowerShell source exceeds maximum supported size "
                f"({len(data)} > {max_size} bytes)"
            )
        return _decode_bytes(data), None

    if isinstance(source, str):
        # Treat existing paths as paths only when they are unambiguously
        # filesystem references. Long script text must never be passed to Path.
        if "\n" not in source and "\r" not in source:
            try:
                candidate = Path(source)
                if candidate.exists() and candidate.is_file():
                    size = candidate.stat().st_size
                    if size > max_size:
                        raise ValueError(
                            f"PowerShell source exceeds maximum supported size "
                            f"({size} > {max_size} bytes)"
                        )
                    return _decode_bytes(candidate.read_bytes()), str(candidate)
            except (OSError, ValueError):
                pass

        encoded = source.encode("utf-8", errors="replace")
        if len(encoded) > max_size:
            raise ValueError(
                f"PowerShell source exceeds maximum supported size "
                f"({len(encoded)} > {max_size} bytes)"
            )
        return source, None

    raise TypeError("source must be str, bytes, bytearray, memoryview, or pathlib.Path")


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


# ---------------------------------------------------------------------------
# Generic lexical helpers
# ---------------------------------------------------------------------------


def _line_number(source: str, offset: int) -> int:
    return source.count("\n", 0, offset) + 1


def _dedupe_preserve(values: Iterable[str], limit: int) -> List[str]:
    result: List[str] = []
    seen = set()

    for value in values:
        normalized = value.strip()
        if not normalized:
            continue
        key = normalized.casefold()
        if key in seen:
            continue
        seen.add(key)
        result.append(normalized)
        if len(result) >= limit:
            break

    return result


def _normalize_command(command: str) -> str:
    return command.strip().casefold()


def _extract_matches(
    pattern: re.Pattern[str],
    source: str,
    *,
    group: int = 0,
    limit: int = 10_000,
) -> List[Tuple[str, int]]:
    result: List[Tuple[str, int]] = []

    for match in pattern.finditer(source):
        value = match.group(group).strip()
        if value:
            result.append((value, _line_number(source, match.start(group))))
        if len(result) >= limit:
            break

    return result


# ---------------------------------------------------------------------------
# Comment handling
# ---------------------------------------------------------------------------


def _strip_comments(source: str) -> str:
    """
    Remove common PowerShell comments while preserving line structure.

    This is intentionally lexical rather than a complete PowerShell grammar.
    Strings are protected so '#' inside quoted strings is not treated as a
    comment delimiter.
    """

    result: List[str] = []
    i = 0
    n = len(source)
    in_single = False
    in_double = False
    in_block_comment = False

    while i < n:
        ch = source[i]
        nxt = source[i + 1] if i + 1 < n else ""

        if in_block_comment:
            if ch == "#" and nxt == ">":
                result.extend((" ", " "))
                i += 2
                in_block_comment = False
            else:
                result.append("\n" if ch == "\n" else " ")
                i += 1
            continue

        if not in_single and not in_double and ch == "<" and nxt == "#":
            result.extend((" ", " "))
            i += 2
            in_block_comment = True
            continue

        if in_single:
            result.append(ch)
            if ch == "'":
                if nxt == "'":
                    result.append(nxt)
                    i += 2
                    continue
                in_single = False
            i += 1
            continue

        if in_double:
            result.append(ch)
            if ch == "`" and nxt:
                result.append(nxt)
                i += 2
                continue
            if ch == '"':
                if nxt == '"':
                    result.append(nxt)
                    i += 2
                    continue
                in_double = False
            i += 1
            continue

        if ch == "'":
            in_single = True
            result.append(ch)
            i += 1
            continue

        if ch == '"':
            in_double = True
            result.append(ch)
            i += 1
            continue

        if ch == "#":
            while i < n and source[i] != "\n":
                result.append(" ")
                i += 1
            continue

        result.append(ch)
        i += 1

    return "".join(result)


# ---------------------------------------------------------------------------
# Strings
# ---------------------------------------------------------------------------


def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0

    counts = Counter(data)
    length = len(data)

    return -sum(
        (count / length) * math.log2(count / length)
        for count in counts.values()
        if count
    )


def _is_base64_like(value: str) -> bool:
    compact = re.sub(r"\s+", "", value)

    if len(compact) < 24:
        return False

    if not re.fullmatch(r"[A-Za-z0-9+/]*={0,2}", compact):
        return False

    if len(compact) % 4 not in (0, 2, 3):
        return False

    alpha = sum(c.isalpha() for c in compact)
    digits = sum(c.isdigit() for c in compact)

    return (alpha + digits) / max(len(compact), 1) >= 0.90


def _is_hex_like(value: str) -> bool:
    compact = re.sub(r"\s+", "", value)

    return (
        len(compact) >= 32
        and len(compact) % 2 == 0
        and re.fullmatch(r"[0-9A-Fa-f]+", compact) is not None
    )


def _decode_base64_safely(value: str) -> Optional[bytes]:
    compact = re.sub(r"\s+", "", value)

    if not _is_base64_like(compact):
        return None

    if len(compact) > (MAX_BASE64_DECODE_BYTES * 4 // 3 + 16):
        return None

    try:
        padding = "=" * ((4 - len(compact) % 4) % 4)
        return base64.b64decode(
            compact + padding,
            validate=True,
        )
    except (ValueError, binascii.Error):
        return None


def extract_strings(
    source: str,
    *,
    limit: int = MAX_STRINGS,
) -> List[PowerShellString]:
    """Extract quoted PowerShell strings without evaluating expansions."""

    result: List[PowerShellString] = []

    for match in STRING_RE.finditer(source):
        raw = match.group(0)
        if len(raw) < 2:
            continue

        quote = raw[0]
        value = raw[1:-1]

        # PowerShell doubles quote characters inside matching string types.
        if quote == "'":
            value = value.replace("''", "'")
        elif quote == '"':
            value = value.replace('""', '"')

        encoded = value.encode("utf-8", errors="replace")
        entropy_data = encoded[:MAX_ENTROPY_BYTES]

        result.append(
            PowerShellString(
                value=value,
                line_number=_line_number(source, match.start()),
                quote=quote,
                length=len(value),
                entropy=_shannon_entropy(entropy_data),
                is_base64_like=_is_base64_like(value),
                is_hex_like=_is_hex_like(value),
            )
        )

        if len(result) >= limit:
            break

    return result


# ---------------------------------------------------------------------------
# Pattern evidence
# ---------------------------------------------------------------------------


def _compile_patterns() -> List[Tuple[PowerShellPattern, re.Pattern[str]]]:
    compiled: List[Tuple[PowerShellPattern, re.Pattern[str]]] = []

    for definition in PATTERNS:
        try:
            compiled.append(
                (
                    definition,
                    re.compile(definition.regex),
                )
            )
        except re.error:
            # Pattern definitions are internal constants. This branch prevents
            # a single malformed rule from making the entire scanner unusable.
            continue

    return compiled


_COMPILED_PATTERNS = _compile_patterns()


def _make_pattern_evidence(
    source: str,
    *,
    include_low_confidence: bool = True,
) -> List[PowerShellEvidence]:
    evidence: List[PowerShellEvidence] = []
    seen: set[Tuple[str, int, str]] = set()

    for definition, pattern in _COMPILED_PATTERNS:
        if not include_low_confidence and definition.confidence < 0.80:
            continue

        for match in pattern.finditer(source):
            raw = match.group(0).strip()

            if not raw:
                continue

            # Prevent enormous evidence records from pathological source.
            snippet = raw[:500]

            key = (
                definition.name,
                _line_number(source, match.start()),
                snippet.casefold(),
            )

            if key in seen:
                continue

            seen.add(key)

            evidence.append(
                PowerShellEvidence(
                    indicator=definition.name,
                    category=definition.category,
                    evidence=snippet,
                    severity=definition.severity,
                    confidence=definition.confidence,
                    line_number=_line_number(source, match.start()),
                    description=definition.description,
                    weight=definition.weight,
                )
            )

            if len(evidence) >= MAX_EVIDENCE_ITEMS:
                return evidence

    return evidence


# ---------------------------------------------------------------------------
# Derived lexical evidence
# ---------------------------------------------------------------------------


def _append_derived_evidence(
    source: str,
    evidence: List[PowerShellEvidence],
) -> None:
    """Add evidence not naturally represented by the main pattern table."""

    existing = {(item.indicator, item.line_number) for item in evidence}

    def add(
        indicator: str,
        category: str,
        match: re.Match[str],
        severity: str,
        confidence: float,
        description: str,
        weight: float,
    ) -> None:
        key = (
            indicator,
            _line_number(source, match.start()),
        )
        if key in existing or len(evidence) >= MAX_EVIDENCE_ITEMS:
            return

        existing.add(key)

        evidence.append(
            PowerShellEvidence(
                indicator=indicator,
                category=category,
                evidence=match.group(0)[:500].strip(),
                severity=severity,
                confidence=confidence,
                line_number=_line_number(source, match.start()),
                description=description,
                weight=weight,
            )
        )

    # Base64-like strings are useful even when no explicit decoder is present.
    for match in BASE64_TOKEN_RE.finditer(source):
        add(
            "base64_like_payload",
            "encoding",
            match,
            "medium",
            0.72,
            "Contains a long Base64-like token.",
            5.0,
        )

    # Hexadecimal payload-like strings.
    for match in HEX_TOKEN_RE.finditer(source):
        add(
            "hex_like_payload",
            "obfuscation",
            match,
            "medium",
            0.76,
            "Contains a long hexadecimal token.",
            4.0,
        )

    # Character construction is common in benign scripts, so it is only
    # medium severity and gains importance when combined with execution.
    for match in CHAR_CONSTRUCTION_RE.finditer(source):
        add(
            "character_construction",
            "obfuscation",
            match,
            "medium",
            0.88,
            "Constructs characters dynamically.",
            4.0,
        )

    for match in FORMAT_CONSTRUCTION_RE.finditer(source):
        add(
            "format_string_construction",
            "obfuscation",
            match,
            "low",
            0.83,
            "Uses format-string construction that can obscure command content.",
            2.0,
        )

    for match in CONCAT_RE.finditer(source):
        add(
            "string_concatenation",
            "obfuscation",
            match,
            "low",
            0.82,
            "Concatenates string fragments.",
            1.5,
        )

    for match in REFLECTION_TYPE_RE.finditer(source):
        add(
            "dynamic_type_resolution",
            "reflection",
            match,
            "medium",
            0.91,
            "Resolves a .NET type dynamically.",
            6.0,
        )


# ---------------------------------------------------------------------------
# Lexical extraction
# ---------------------------------------------------------------------------


def extract_commands(
    source: str,
    *,
    limit: int = MAX_TOKENS,
) -> List[str]:
    matches = _extract_matches(COMMAND_RE, source, limit=limit)
    return _dedupe_preserve((value for value, _ in matches), limit)


def extract_functions(
    source: str,
    *,
    limit: int = 10_000,
) -> List[str]:
    result: List[str] = []

    for match in FUNCTION_RE.finditer(source):
        result.append(match.group(1))
        if len(result) >= limit:
            break

    return _dedupe_preserve(result, limit)


def extract_aliases(
    source: str,
    *,
    limit: int = 10_000,
) -> List[str]:
    result: List[str] = []

    for match in ALIAS_RE.finditer(source):
        result.append(match.group(1))
        if len(result) >= limit:
            break

    return _dedupe_preserve(result, limit)


def extract_parameters(
    source: str,
    *,
    limit: int = MAX_TOKENS,
) -> List[str]:
    result: List[str] = []

    for match in PARAMETER_RE.finditer(source):
        value = match.group(0).casefold()
        if value not in result:
            result.append(value)

        if len(result) >= limit:
            break

    return result


def extract_variables(
    source: str,
    *,
    limit: int = MAX_IDENTIFIERS,
) -> List[str]:
    result: List[str] = []

    for match in VARIABLE_RE.finditer(source):
        value = match.group(0)
        if value.casefold() not in {v.casefold() for v in result}:
            result.append(value)

        if len(result) >= limit:
            break

    return result


def extract_urls(
    source: str,
    *,
    limit: int = MAX_URLS,
) -> List[str]:
    matches = _extract_matches(URL_RE, source, limit=limit)
    return _dedupe_preserve((value.rstrip(".,;)]}") for value, _ in matches), limit)


def extract_ipv4_addresses(
    source: str,
    *,
    limit: int = MAX_URLS,
) -> List[str]:
    return _dedupe_preserve(
        (match.group(0) for match in IPV4_RE.finditer(source)),
        limit,
    )


def extract_windows_paths(
    source: str,
    *,
    limit: int = MAX_URLS,
) -> List[str]:
    values = list(match.group(0).strip() for match in WINDOWS_PATH_RE.finditer(source))
    values.extend(match.group(0).strip() for match in UNC_PATH_RE.finditer(source))

    return _dedupe_preserve(values, limit)


def extract_registry_paths(
    source: str,
    *,
    limit: int = MAX_URLS,
) -> List[str]:
    return _dedupe_preserve(
        (match.group(0).strip() for match in REGISTRY_PATH_RE.finditer(source)),
        limit,
    )


# ---------------------------------------------------------------------------
# Indicator utilities
# ---------------------------------------------------------------------------


def _indicator_set(evidence: Sequence[PowerShellEvidence]) -> set[str]:
    return {item.indicator.casefold() for item in evidence}


def _category_set(evidence: Sequence[PowerShellEvidence]) -> set[str]:
    return {item.category.casefold() for item in evidence}


def _indicator_counts(
    evidence: Sequence[PowerShellEvidence],
) -> Counter[str]:
    return Counter(item.indicator.casefold() for item in evidence)


def _category_counts(
    evidence: Sequence[PowerShellEvidence],
) -> Counter[str]:
    return Counter(item.category.casefold() for item in evidence)


# ---------------------------------------------------------------------------
# Derived combinations
# ---------------------------------------------------------------------------


COMBINATION_DEFINITIONS: Tuple[Tuple[str, Tuple[str, ...], str, str], ...] = (
    (
        "download_then_execute",
        (
            "download_string",
            "invoke_web_request",
            "invoke_rest_method",
            "web_client",
        ),
        "Combines network content acquisition with execution-oriented PowerShell.",
        "high",
    ),
    (
        "encoded_dynamic_execution",
        (
            "encoded_command",
            "invoke_expression",
            "from_base64_string",
            "scriptblock_create",
        ),
        "Combines encoded/decoded content with dynamic PowerShell execution.",
        "critical",
    ),
    (
        "obfuscated_execution",
        (
            "character_construction",
            "string_concatenation",
            "invoke_expression",
        ),
        "Combines string-obfuscation techniques with dynamic execution.",
        "high",
    ),
    (
        "download_dynamic_execution",
        (
            "download_string",
            "invoke_expression",
        ),
        "Downloads content and executes it dynamically.",
        "critical",
    ),
    (
        "download_scriptblock_execution",
        (
            "download_string",
            "scriptblock_create",
        ),
        "Downloads content and turns it into an executable script block.",
        "critical",
    ),
    (
        "reflection_payload_execution",
        (
            "reflection_load",
            "reflection_invoke",
        ),
        "Loads and invokes .NET code using reflection.",
        "critical",
    ),
    (
        "memory_injection",
        (
            "virtual_alloc",
            "write_process_memory",
            "create_remote_thread",
        ),
        "Contains a process-memory injection API chain.",
        "critical",
    ),
    (
        "persistence_execution",
        (
            "run_key",
            "start_process",
        ),
        "Combines startup persistence with explicit process execution.",
        "high",
    ),
    (
        "scheduled_task_execution",
        (
            "scheduled_task",
            "start_process",
        ),
        "Combines scheduled-task functionality with process execution.",
        "high",
    ),
    (
        "service_execution",
        (
            "service_creation",
            "start_process",
        ),
        "Combines service manipulation with process execution.",
        "high",
    ),
    (
        "credential_dumping",
        (
            "lsass",
            "write_process_memory",
        ),
        "Combines LSASS/process-memory access indicators.",
        "critical",
    ),
    (
        "amsi_evasion",
        (
            "amsi_reference",
            "amsi_bypass_field",
        ),
        "Contains multiple AMSI-bypass-oriented indicators.",
        "critical",
    ),
    (
        "policy_bypass_encoded",
        (
            "execution_policy_bypass",
            "encoded_command",
        ),
        "Combines execution-policy bypass with encoded PowerShell.",
        "critical",
    ),
    (
        "lolbin_chain",
        (
            "certutil_execution",
            "rundll32_execution",
            "regsvr32_execution",
            "mshta_execution",
        ),
        "References one or more Windows signed-binary execution primitives.",
        "high",
    ),
    (
        "network_com_automation",
        (
            "network",
            "com_object_reference",
        ),
        "Combines network activity with COM automation.",
        "high",
    ),
)


def _derive_combinations(
    evidence: Sequence[PowerShellEvidence],
) -> List[PowerShellCombination]:
    indicators = _indicator_set(evidence)
    categories = _category_set(evidence)

    combinations: List[PowerShellCombination] = []

    for name, requirements, explanation, severity in COMBINATION_DEFINITIONS:
        if name == "download_then_execute":
            has_download = bool(
                indicators
                & {
                    "download_string",
                    "invoke_web_request",
                    "invoke_rest_method",
                    "web_client",
                }
            )
            has_execution = bool(
                categories
                & {
                    "execution",
                    "dynamic_execution",
                    "reflection",
                    "process",
                }
            )
            present = has_download and has_execution

        elif name == "encoded_dynamic_execution":
            has_encoding = bool(
                indicators
                & {
                    "encoded_command",
                    "from_base64_string",
                    "base64_decode_transform",
                    "base64_like_payload",
                }
            )
            has_dynamic = bool(
                categories
                & {
                    "dynamic_execution",
                    "reflection",
                }
            )
            present = has_encoding and has_dynamic

        elif name == "obfuscated_execution":
            has_obfuscation = bool(
                categories
                & {
                    "obfuscation",
                    "encoding",
                    "decoding",
                }
            )
            has_execution = bool(
                categories
                & {
                    "execution",
                    "dynamic_execution",
                }
            )
            present = has_obfuscation and has_execution

        elif name == "download_dynamic_execution":
            present = (
                "download_string" in indicators and "invoke_expression" in indicators
            )

        elif name == "download_scriptblock_execution":
            present = (
                "download_string" in indicators and "scriptblock_create" in indicators
            )

        elif name == "reflection_payload_execution":
            present = (
                "reflection_load" in indicators and "reflection_invoke" in indicators
            )

        elif name == "memory_injection":
            present = all(item in indicators for item in requirements)

        elif name == "persistence_execution":
            present = "run_key" in indicators and "start_process" in indicators

        elif name == "scheduled_task_execution":
            present = "scheduled_task" in indicators and "start_process" in indicators

        elif name == "service_execution":
            present = "service_creation" in indicators and "start_process" in indicators

        elif name == "credential_dumping":
            present = "lsass" in indicators and "write_process_memory" in indicators

        elif name == "amsi_evasion":
            present = (
                "amsi_reference" in indicators and "amsi_bypass_field" in indicators
            )

        elif name == "policy_bypass_encoded":
            present = (
                "execution_policy_bypass" in indicators
                and "encoded_command" in indicators
            )

        elif name == "lolbin_chain":
            present = bool(
                indicators
                & {
                    "certutil_execution",
                    "rundll32_execution",
                    "regsvr32_execution",
                    "mshta_execution",
                }
            )

        elif name == "network_com_automation":
            present = bool(categories & {"network", "download", "web_client"}) and bool(
                categories & {"com_automation"}
            )

        else:
            present = all(requirement in indicators for requirement in requirements)

        combinations.append(
            PowerShellCombination(
                name=name,
                present=present,
                required_indicators=list(requirements),
                explanation=explanation,
                severity=severity,
            )
        )

    return combinations


# ---------------------------------------------------------------------------
# Score
# ---------------------------------------------------------------------------


def _calculate_signal_score(
    evidence: Sequence[PowerShellEvidence],
    combinations: Sequence[PowerShellCombination],
    *,
    source_size: int,
) -> float:
    """
    Calculate a bounded static signal score.

    This is a heuristic signal, not a malware probability.
    """

    score = 0.0

    for item in evidence:
        severity_multiplier = {
            "low": 0.55,
            "medium": 0.85,
            "high": 1.15,
            "critical": 1.45,
        }.get(item.severity, 1.0)

        score += item.weight * item.confidence * severity_multiplier

    for combo in combinations:
        if combo.present:
            score += {
                "low": 3.0,
                "medium": 6.0,
                "high": 12.0,
                "critical": 20.0,
            }.get(combo.severity, 6.0)

    # Avoid letting enormous scripts gain a high score simply because they
    # contain many benign commands.
    if source_size > 1_000_000:
        score *= 0.90

    return round(min(100.0, max(0.0, score)), 4)


# ---------------------------------------------------------------------------
# Feature schema
# ---------------------------------------------------------------------------


def powershell_feature_names() -> List[str]:
    """Return the stable feature names emitted by this module."""

    names = [
        "powershell_source_size",
        "powershell_line_count",
        "powershell_command_count",
        "powershell_function_count",
        "powershell_alias_count",
        "powershell_parameter_count",
        "powershell_variable_count",
        "powershell_url_count",
        "powershell_ipv4_count",
        "powershell_windows_path_count",
        "powershell_registry_path_count",
        "powershell_string_count",
        "powershell_string_total_length",
        "powershell_string_max_length",
        "powershell_string_mean_entropy",
        "powershell_base64_string_count",
        "powershell_hex_string_count",
        "powershell_base64_token_count",
        "powershell_hex_token_count",
        "powershell_dotnet_type_count",
        "powershell_score",
        "powershell_evidence_count",
        "powershell_high_severity_count",
        "powershell_critical_severity_count",
        "powershell_category_count",
        "powershell_indicator_count",
        "powershell_combination_count",
        "powershell_present_combination_count",
    ]

    for category in INDICATOR_CATEGORIES:
        names.append(f"powershell_category_{category}")
        names.append(f"powershell_category_{category}_count")

    indicator_names = _dedupe_preserve(
        (definition.name for definition in PATTERNS),
        limit=10_000,
    )

    for indicator in indicator_names:
        names.append(f"powershell_indicator_{indicator}")
        names.append(f"powershell_indicator_{indicator}_count")

    for name, _, _, _ in COMBINATION_DEFINITIONS:
        names.append(f"powershell_combination_{name}")

    return names


def build_feature_schema() -> Dict[str, Any]:
    """Return an ML-oriented schema describing this module's features."""

    numeric_features = powershell_feature_names()

    return {
        "name": "powershell_static_features",
        "version": "1.0.0",
        "description": (
            "Stable scalar features generated from static PowerShell analysis. "
            "No feature requires PowerShell execution."
        ),
        "feature_names": numeric_features,
        "feature_count": len(numeric_features),
        "target_type": "numeric",
        "score_semantics": (
            "powershell_score is a bounded heuristic signal from 0 to 100; "
            "it is not a calibrated malware probability."
        ),
        "categories": list(INDICATOR_CATEGORIES),
        "indicators": [definition.name for definition in PATTERNS],
        "combinations": [definition[0] for definition in COMBINATION_DEFINITIONS],
    }


# ---------------------------------------------------------------------------
# Feature extraction
# ---------------------------------------------------------------------------


def _build_feature_vector(
    analysis: PowerShellAnalysis,
) -> Dict[str, float]:
    evidence = analysis.evidence
    indicators = _indicator_counts(evidence)
    categories = _category_counts(evidence)

    strings = analysis.strings

    total_string_length = sum(item.length for item in strings)
    max_string_length = max(
        (item.length for item in strings),
        default=0,
    )

    mean_entropy = (
        sum(item.entropy for item in strings) / len(strings) if strings else 0.0
    )

    base64_string_count = sum(1 for item in strings if item.is_base64_like)
    hex_string_count = sum(1 for item in strings if item.is_hex_like)

    vector: Dict[str, float] = {
        "powershell_source_size": float(analysis.source_size),
        "powershell_line_count": float(analysis.line_count),
        "powershell_command_count": float(len(analysis.commands)),
        "powershell_function_count": float(len(analysis.functions)),
        "powershell_alias_count": float(len(analysis.aliases)),
        "powershell_parameter_count": float(len(analysis.parameters)),
        "powershell_variable_count": float(len(analysis.variables)),
        "powershell_url_count": float(len(analysis.urls)),
        "powershell_ipv4_count": float(len(analysis.ipv4_addresses)),
        "powershell_windows_path_count": float(len(analysis.windows_paths)),
        "powershell_registry_path_count": float(len(analysis.registry_paths)),
        "powershell_string_count": float(len(strings)),
        "powershell_string_total_length": float(total_string_length),
        "powershell_string_max_length": float(max_string_length),
        "powershell_string_mean_entropy": round(mean_entropy, 6),
        "powershell_base64_string_count": float(base64_string_count),
        "powershell_hex_string_count": float(hex_string_count),
        "powershell_base64_token_count": float(
            indicators.get("base64_like_payload", 0)
        ),
        "powershell_hex_token_count": float(indicators.get("hex_like_payload", 0)),
        "powershell_dotnet_type_count": float(
            len(DOTNET_TYPE_RE.findall(analysis.metadata.get("source", "")))
        ),
        "powershell_score": float(analysis.metadata.get("signal_score", 0.0)),
        "powershell_evidence_count": float(len(evidence)),
        "powershell_high_severity_count": float(
            sum(1 for item in evidence if SEVERITY_RANK.get(item.severity, 0) >= 3)
        ),
        "powershell_critical_severity_count": float(
            sum(1 for item in evidence if item.severity == "critical")
        ),
        "powershell_category_count": float(len(categories)),
        "powershell_indicator_count": float(len(indicators)),
        "powershell_combination_count": float(len(analysis.combinations)),
        "powershell_present_combination_count": float(
            sum(1 for item in analysis.combinations if item.present)
        ),
    }

    for category in INDICATOR_CATEGORIES:
        count = categories.get(category, 0)
        vector[f"powershell_category_{category}"] = float(1 if count else 0)
        vector[f"powershell_category_{category}_count"] = float(count)

    indicator_names = _dedupe_preserve(
        (definition.name for definition in PATTERNS),
        limit=10_000,
    )

    for indicator in indicator_names:
        count = indicators.get(indicator.casefold(), 0)
        vector[f"powershell_indicator_{indicator}"] = float(1 if count else 0)
        vector[f"powershell_indicator_{indicator}_count"] = float(count)

    for combination in analysis.combinations:
        vector[f"powershell_combination_{combination.name}"] = float(
            1 if combination.present else 0
        )

    # Guarantee schema completeness and deterministic order.
    schema_names = powershell_feature_names()

    return {name: float(vector.get(name, 0.0)) for name in schema_names}


# ---------------------------------------------------------------------------
# Main analyzer
# ---------------------------------------------------------------------------


def analyze_powershell(
    source: Union[str, bytes, bytearray, memoryview, Path],
    *,
    max_source_size: int = MAX_SOURCE_SIZE,
    include_low_confidence: bool = True,
) -> PowerShellAnalysis:
    """
    Analyze PowerShell source statically.

    No PowerShell interpreter is invoked.
    """

    text, source_name = _read_source(
        source,
        max_size=max_source_size,
    )

    # Protect the parser against pathological line counts.
    lines = text.splitlines()

    if len(lines) > MAX_LINES:
        lines = lines[:MAX_LINES]
        text = "\n".join(lines)

    source_hash = _sha256_text(text)

    lexical_source = _strip_comments(text)

    strings = extract_strings(
        text,
        limit=MAX_STRINGS,
    )

    evidence = _make_pattern_evidence(
        lexical_source,
        include_low_confidence=include_low_confidence,
    )

    _append_derived_evidence(
        lexical_source,
        evidence,
    )

    commands = extract_commands(
        lexical_source,
    )
    functions = extract_functions(
        lexical_source,
    )
    aliases = extract_aliases(
        lexical_source,
    )
    parameters = extract_parameters(
        lexical_source,
    )
    variables = extract_variables(
        lexical_source,
    )
    urls = extract_urls(
        text,
    )
    ipv4_addresses = extract_ipv4_addresses(
        text,
    )
    windows_paths = extract_windows_paths(
        text,
    )
    registry_paths = extract_registry_paths(
        text,
    )

    combinations = _derive_combinations(evidence)

    indicators = _dedupe_preserve(
        (item.indicator for item in evidence),
        limit=MAX_EVIDENCE_ITEMS,
    )

    categories = _dedupe_preserve(
        (item.category for item in evidence),
        limit=len(INDICATOR_CATEGORIES),
    )

    # Store only bounded metadata. The complete source is intentionally not
    # retained in the result object.
    signal_score = _calculate_signal_score(
        evidence,
        combinations,
        source_size=len(text.encode("utf-8", errors="replace")),
    )

    high_risk_count = sum(
        1 for item in evidence if item.severity in {"high", "critical"}
    )

    critical_count = sum(1 for item in evidence if item.severity == "critical")

    metadata: Dict[str, Any] = {
        "source_name": source_name,
        "source": lexical_source,
        "sha256": source_hash,
        "signal_score": signal_score,
        "high_risk_evidence_count": high_risk_count,
        "critical_evidence_count": critical_count,
        "has_network_indicators": any(
            item.category in {"network", "download", "web_client"} for item in evidence
        ),
        "has_dynamic_execution": any(
            item.category == "dynamic_execution" for item in evidence
        ),
        "has_obfuscation": any(
            item.category in {"obfuscation", "encoding", "decoding"}
            for item in evidence
        ),
        "has_persistence": any(
            item.category
            in {
                "persistence",
                "scheduled_task",
                "service",
            }
            for item in evidence
        ),
        "has_credential_access": any(
            item.category == "credential_access" for item in evidence
        ),
        "has_process_injection": any(
            item.category == "process_injection" for item in evidence
        ),
        "parser": "pharos-cdr.static-powershell",
        "parser_version": "1.0.0",
        "execution_performed": False,
        "network_access_performed": False,
        "filesystem_payload_extraction_performed": False,
    }

    analysis = PowerShellAnalysis(
        family="powershell",
        source_hash=source_hash,
        source_size=len(text.encode("utf-8", errors="replace")),
        line_count=len(lines),
        commands=commands,
        functions=functions,
        aliases=aliases,
        parameters=parameters,
        variables=variables,
        urls=urls,
        ipv4_addresses=ipv4_addresses,
        windows_paths=windows_paths,
        registry_paths=registry_paths,
        strings=strings,
        evidence=evidence,
        indicators=indicators,
        categories=categories,
        combinations=combinations,
        metadata=metadata,
    )

    analysis.feature_vector = _build_feature_vector(analysis)

    return analysis


def parse_powershell(
    source: Union[str, bytes, bytearray, memoryview, Path],
    **kwargs: Any,
) -> PowerShellAnalysis:
    """Alias for :func:`analyze_powershell`."""

    return analyze_powershell(source, **kwargs)


def extract_powershell_features(
    source: Union[str, bytes, bytearray, memoryview, Path],
    **kwargs: Any,
) -> PowerShellAnalysis:
    """Return the complete PowerShell feature analysis."""

    return analyze_powershell(source, **kwargs)


def extract_feature_vector(
    source: Union[str, bytes, bytearray, memoryview, Path],
    **kwargs: Any,
) -> Dict[str, float]:
    """Analyze PowerShell source and return its scalar feature vector."""

    return analyze_powershell(source, **kwargs).feature_vector


def extract_powershell_feature_vector(
    source: Union[str, bytes, bytearray, memoryview, Path],
    **kwargs: Any,
) -> Dict[str, float]:
    """Explicit alias for :func:`extract_feature_vector`."""

    return extract_feature_vector(source, **kwargs)


def vectorize_features(
    analysis: Union[
        PowerShellAnalysis,
        Mapping[str, Any],
    ],
) -> Dict[str, float]:
    """
    Convert an analysis or compatible mapping into the stable feature schema.
    """

    if isinstance(analysis, PowerShellAnalysis):
        return {
            name: float(analysis.feature_vector.get(name, 0.0))
            for name in powershell_feature_names()
        }

    feature_vector = analysis.get("feature_vector", analysis)

    if not isinstance(feature_vector, Mapping):
        raise TypeError(
            "analysis must be PowerShellAnalysis or a mapping containing "
            "feature_vector"
        )

    return {
        name: float(feature_vector.get(name, 0.0))
        for name in powershell_feature_names()
    }


# ---------------------------------------------------------------------------
# Query helpers
# ---------------------------------------------------------------------------


def has_indicator(
    analysis: PowerShellAnalysis,
    indicator: str,
) -> bool:
    """Return whether a named indicator was found."""

    target = indicator.casefold()

    return any(item.indicator.casefold() == target for item in analysis.evidence)


def has_category(
    analysis: PowerShellAnalysis,
    category: str,
) -> bool:
    """Return whether a named evidence category was found."""

    target = category.casefold()

    return any(item.category.casefold() == target for item in analysis.evidence)


def evidence_by_category(
    analysis: PowerShellAnalysis,
    category: str,
) -> List[PowerShellEvidence]:
    target = category.casefold()

    return [item for item in analysis.evidence if item.category.casefold() == target]


def evidence_by_indicator(
    analysis: PowerShellAnalysis,
    indicator: str,
) -> List[PowerShellEvidence]:
    target = indicator.casefold()

    return [item for item in analysis.evidence if item.indicator.casefold() == target]


def high_risk_evidence(
    analysis: PowerShellAnalysis,
) -> List[PowerShellEvidence]:
    """Return high/critical evidence sorted by severity and confidence."""

    return sorted(
        (item for item in analysis.evidence if item.severity in {"high", "critical"}),
        key=lambda item: (
            -SEVERITY_RANK.get(item.severity, 0),
            -item.confidence,
            -(item.weight or 0.0),
            item.line_number or 0,
        ),
    )


def present_combinations(
    analysis: PowerShellAnalysis,
) -> List[PowerShellCombination]:
    return [combination for combination in analysis.combinations if combination.present]


def indicator_count(
    analysis: PowerShellAnalysis,
    indicator: str,
) -> int:
    target = indicator.casefold()

    return sum(1 for item in analysis.evidence if item.indicator.casefold() == target)


def category_count(
    analysis: PowerShellAnalysis,
    category: str,
) -> int:
    target = category.casefold()

    return sum(1 for item in analysis.evidence if item.category.casefold() == target)


def highest_severity(
    analysis: PowerShellAnalysis,
) -> str:
    if not analysis.evidence:
        return "low"

    return max(
        (item.severity for item in analysis.evidence),
        key=lambda value: SEVERITY_RANK.get(value, 0),
    )


# ---------------------------------------------------------------------------
# Serialization / reporting
# ---------------------------------------------------------------------------


def _string_to_dict(item: PowerShellString) -> Dict[str, Any]:
    return asdict(item)


def _evidence_to_dict(item: PowerShellEvidence) -> Dict[str, Any]:
    return asdict(item)


def _combination_to_dict(
    item: PowerShellCombination,
) -> Dict[str, Any]:
    return asdict(item)


def analysis_to_dict(
    analysis: PowerShellAnalysis,
) -> Dict[str, Any]:
    """Convert an analysis to JSON-compatible primitive structures."""

    result = {
        "family": analysis.family,
        "source_hash": analysis.source_hash,
        "source_size": analysis.source_size,
        "line_count": analysis.line_count,
        "commands": list(analysis.commands),
        "functions": list(analysis.functions),
        "aliases": list(analysis.aliases),
        "parameters": list(analysis.parameters),
        "variables": list(analysis.variables),
        "urls": list(analysis.urls),
        "ipv4_addresses": list(analysis.ipv4_addresses),
        "windows_paths": list(analysis.windows_paths),
        "registry_paths": list(analysis.registry_paths),
        "strings": [_string_to_dict(item) for item in analysis.strings],
        "evidence": [_evidence_to_dict(item) for item in analysis.evidence],
        "indicators": list(analysis.indicators),
        "categories": list(analysis.categories),
        "combinations": [_combination_to_dict(item) for item in analysis.combinations],
        "feature_vector": dict(analysis.feature_vector),
        "metadata": dict(analysis.metadata),
    }

    # Never expose retained lexical source through metadata.
    result["metadata"].pop("source", None)

    return result


def summarize_powershell(
    analysis: PowerShellAnalysis,
) -> Dict[str, Any]:
    """Return a compact analyst-oriented summary."""

    high_risk = high_risk_evidence(analysis)
    combinations = present_combinations(analysis)

    return {
        "family": analysis.family,
        "sha256": analysis.source_hash,
        "source_size": analysis.source_size,
        "line_count": analysis.line_count,
        "signal_score": analysis.metadata.get("signal_score", 0.0),
        "highest_severity": highest_severity(analysis),
        "command_count": len(analysis.commands),
        "function_count": len(analysis.functions),
        "url_count": len(analysis.urls),
        "evidence_count": len(analysis.evidence),
        "high_risk_evidence_count": len(high_risk),
        "indicator_count": len(analysis.indicators),
        "category_count": len(analysis.categories),
        "present_combination_count": len(combinations),
        "indicators": list(analysis.indicators),
        "categories": list(analysis.categories),
        "high_risk_indicators": _dedupe_preserve(
            (item.indicator for item in high_risk),
            limit=100,
        ),
        "present_combinations": [item.name for item in combinations],
        "urls": list(analysis.urls),
        "ipv4_addresses": list(analysis.ipv4_addresses),
        "persistence_indicators": _dedupe_preserve(
            (
                item.indicator
                for item in analysis.evidence
                if item.category
                in {
                    "persistence",
                    "scheduled_task",
                    "service",
                }
            ),
            limit=100,
        ),
        "execution_indicators": _dedupe_preserve(
            (
                item.indicator
                for item in analysis.evidence
                if item.category
                in {
                    "execution",
                    "dynamic_execution",
                    "process",
                    "reflection",
                }
            ),
            limit=100,
        ),
    }


# ---------------------------------------------------------------------------
# Iterators
# ---------------------------------------------------------------------------


def iter_evidence(
    analysis: PowerShellAnalysis,
) -> Iterator[PowerShellEvidence]:
    yield from analysis.evidence


def iter_high_risk_evidence(
    analysis: PowerShellAnalysis,
) -> Iterator[PowerShellEvidence]:
    yield from high_risk_evidence(analysis)


def iter_strings(
    analysis: PowerShellAnalysis,
) -> Iterator[PowerShellString]:
    yield from analysis.strings


def iter_urls(
    analysis: PowerShellAnalysis,
) -> Iterator[str]:
    yield from analysis.urls


def iter_combinations(
    analysis: PowerShellAnalysis,
) -> Iterator[PowerShellCombination]:
    yield from analysis.combinations


def iter_analyses(
    sources: Iterable[Union[str, bytes, bytearray, memoryview, Path]],
    **kwargs: Any,
) -> Iterator[PowerShellAnalysis]:
    """Analyze multiple sources lazily."""

    for source in sources:
        yield analyze_powershell(source, **kwargs)


# ---------------------------------------------------------------------------
# Compatibility aliases
# ---------------------------------------------------------------------------

analyze = analyze_powershell
parse = parse_powershell
extract = extract_powershell_features


__all__ = [
    "MAX_SOURCE_SIZE",
    "MAX_LINES",
    "MAX_EVIDENCE_ITEMS",
    "MAX_STRINGS",
    "MAX_URLS",
    "MAX_IDENTIFIERS",
    "MAX_TOKENS",
    "INDICATOR_CATEGORIES",
    "PowerShellPattern",
    "PowerShellString",
    "PowerShellEvidence",
    "PowerShellCombination",
    "PowerShellAnalysis",
    "PATTERNS",
    "extract_strings",
    "extract_commands",
    "extract_functions",
    "extract_aliases",
    "extract_parameters",
    "extract_variables",
    "extract_urls",
    "extract_ipv4_addresses",
    "extract_windows_paths",
    "extract_registry_paths",
    "analyze_powershell",
    "parse_powershell",
    "extract_powershell_features",
    "extract_feature_vector",
    "extract_powershell_feature_vector",
    "powershell_feature_names",
    "build_feature_schema",
    "vectorize_features",
    "has_indicator",
    "has_category",
    "evidence_by_category",
    "evidence_by_indicator",
    "high_risk_evidence",
    "present_combinations",
    "indicator_count",
    "category_count",
    "highest_severity",
    "analysis_to_dict",
    "summarize_powershell",
    "iter_evidence",
    "iter_high_risk_evidence",
    "iter_strings",
    "iter_urls",
    "iter_combinations",
    "iter_analyses",
    "analyze",
    "parse",
    "extract",
]
