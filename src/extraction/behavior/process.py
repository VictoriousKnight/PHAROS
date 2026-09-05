"""
Static process-behavior extraction for pharos-cdr.

This module analyzes already-extracted evidence from documents, VBA, scripts,
and related static analyzers for process-creation, process-manipulation, and
process-injection behavior.

Security properties
-------------------
* Never starts a process.
* Never opens process handles.
* Never loads DLLs.
* Never invokes Windows APIs.
* Never executes extracted scripts or macros.
* Never performs dynamic analysis.
* Operates only on supplied text, mappings, or structured evidence.

The analyzer is deliberately source-agnostic. It accepts:
    * raw source text
    * bytes
    * filesystem paths
    * nested mappings/lists containing previously extracted evidence
    * arbitrary objects whose useful public attributes can be inspected

This makes it suitable for combining evidence from:
    VBA -> capabilities.py / api_features.py
    PowerShell -> powershell.py
    VBScript / JavaScript -> parser-specific modules
    strings -> strings.py
    Office/XLM -> xlm.py
    pipeline -> behavior/process.py

The output contains both human-readable evidence and stable scalar features
for the ML pipeline.
"""

from __future__ import annotations

import hashlib
import math
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
    Tuple,
    Union,
)

# ---------------------------------------------------------------------------
# Resource limits
# ---------------------------------------------------------------------------

MAX_SOURCE_SIZE = 25 * 1024 * 1024
MAX_TEXT_CHARS = 25 * 1024 * 1024
MAX_EVIDENCE_ITEMS = 20_000
MAX_MATCHES_PER_RULE = 5_000
MAX_TOKENS = 250_000
MAX_NESTING_DEPTH = 12
MAX_FIELD_TEXT = 100_000
MAX_PROCESSES = 10_000
MAX_PATHS = 10_000
MAX_COMMAND_LINES = 20_000


# ---------------------------------------------------------------------------
# Taxonomy
# ---------------------------------------------------------------------------

PROCESS_CATEGORIES: Tuple[str, ...] = (
    "process_creation",
    "process_execution",
    "shell_execution",
    "script_host",
    "command_interpreter",
    "process_discovery",
    "process_termination",
    "process_enumeration",
    "process_handle_access",
    "process_memory",
    "process_injection",
    "remote_thread",
    "token_manipulation",
    "parent_process",
    "process_hollowing",
    "living_off_the_land",
    "signed_binary_proxy",
    "execution_chain",
    "privilege",
    "evasion",
    "environment",
)

SEVERITIES = ("low", "medium", "high", "critical")

SEVERITY_RANK = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ProcessPattern:
    """Static process-behavior detection rule."""

    name: str
    category: str
    regex: str
    severity: str
    confidence: float
    description: str
    weight: float
    process_name: Optional[str] = None


@dataclass
class ProcessEvidence:
    """One static process-behavior observation."""

    indicator: str
    category: str
    evidence: str
    severity: str
    confidence: float
    line_number: Optional[int] = None
    process_name: Optional[str] = None
    source_type: str = "text"
    description: str = ""
    weight: float = 0.0


@dataclass
class ProcessRecord:
    """A process-like artifact referenced by static evidence."""

    name: str
    normalized_name: str
    source: str
    line_number: Optional[int] = None
    arguments: Optional[str] = None
    is_shell: bool = False
    is_script_host: bool = False
    is_signed_binary_proxy: bool = False
    is_likely_lolbin: bool = False


@dataclass
class ProcessCombination:
    """Derived multi-signal process behavior."""

    name: str
    present: bool
    required_indicators: List[str] = field(default_factory=list)
    explanation: str = ""
    severity: str = "medium"


@dataclass
class ProcessAnalysis:
    """Complete static process-behavior analysis."""

    source_hash: str
    source_size: int

    processes: List[ProcessRecord] = field(default_factory=list)
    evidence: List[ProcessEvidence] = field(default_factory=list)
    indicators: List[str] = field(default_factory=list)
    categories: List[str] = field(default_factory=list)
    combinations: List[ProcessCombination] = field(default_factory=list)

    shell_processes: List[str] = field(default_factory=list)
    script_hosts: List[str] = field(default_factory=list)
    lolbins: List[str] = field(default_factory=list)
    process_names: List[str] = field(default_factory=list)

    feature_vector: Dict[str, float] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Process / shell / LOLBin vocabulary
# ---------------------------------------------------------------------------

SHELL_PROCESSES: Dict[str, str] = {
    "cmd.exe": "Windows Command Prompt",
    "cmd": "Windows Command Prompt",
    "command.com": "DOS command interpreter",
    "powershell.exe": "Windows PowerShell",
    "powershell": "Windows PowerShell",
    "pwsh.exe": "PowerShell Core",
    "pwsh": "PowerShell Core",
    "wscript.exe": "Windows Script Host",
    "wscript": "Windows Script Host",
    "cscript.exe": "Windows Script Host",
    "cscript": "Windows Script Host",
    "mshta.exe": "HTML Application Host",
    "mshta": "HTML Application Host",
    "rundll32.exe": "Rundll32",
    "rundll32": "Rundll32",
    "regsvr32.exe": "Regsvr32",
    "regsvr32": "Regsvr32",
    "installutil.exe": "InstallUtil",
    "installutil": "InstallUtil",
    "regasm.exe": "RegAsm",
    "regasm": "RegAsm",
    "regsvcs.exe": "RegSvcs",
    "regsvcs": "RegSvcs",
    "msbuild.exe": "MSBuild",
    "msbuild": "MSBuild",
    "csc.exe": "C# compiler",
    "csc": "C# compiler",
    "vbc.exe": "VB compiler",
    "vbc": "VB compiler",
    "wmic.exe": "WMIC",
    "wmic": "WMIC",
    "certutil.exe": "CertUtil",
    "certutil": "CertUtil",
    "bitsadmin.exe": "BITSAdmin",
    "bitsadmin": "BITSAdmin",
    "forfiles.exe": "ForFiles",
    "forfiles": "ForFiles",
    "cmstp.exe": "CMSTP",
    "cmstp": "CMSTP",
    "msiexec.exe": "Windows Installer",
    "msiexec": "Windows Installer",
    "control.exe": "Control Panel launcher",
    "control": "Control Panel launcher",
    "hh.exe": "HTML Help",
    "hh": "HTML Help",
    "installutil": "InstallUtil",
    "esentutl.exe": "ESENT utility",
    "esentutl": "ESENT utility",
    "ftp.exe": "FTP client",
    "ftp": "FTP client",
}

SCRIPT_HOSTS = {
    "powershell.exe",
    "powershell",
    "pwsh.exe",
    "pwsh",
    "wscript.exe",
    "wscript",
    "cscript.exe",
    "cscript",
    "mshta.exe",
    "mshta",
    "msbuild.exe",
    "msbuild",
}

LIKELY_LOLBINS = {
    "certutil.exe",
    "certutil",
    "bitsadmin.exe",
    "bitsadmin",
    "rundll32.exe",
    "rundll32",
    "regsvr32.exe",
    "regsvr32",
    "mshta.exe",
    "mshta",
    "wmic.exe",
    "wmic",
    "cmstp.exe",
    "cmstp",
    "installutil.exe",
    "installutil",
    "regasm.exe",
    "regasm",
    "regsvcs.exe",
    "regsvcs",
    "msbuild.exe",
    "msbuild",
    "csc.exe",
    "csc",
    "vbc.exe",
    "vbc",
    "forfiles.exe",
    "forfiles",
    "hh.exe",
    "hh",
    "esentutl.exe",
    "esentutl",
}

COMMON_SYSTEM_PROCESSES = {
    "explorer.exe",
    "svchost.exe",
    "services.exe",
    "wininit.exe",
    "winlogon.exe",
    "lsass.exe",
    "smss.exe",
    "csrss.exe",
    "conhost.exe",
    "taskhostw.exe",
    "runtimebroker.exe",
    "dllhost.exe",
    "spoolsv.exe",
    "searchindexer.exe",
    "dwm.exe",
    "rundll32.exe",
}


# ---------------------------------------------------------------------------
# Detection rules
# ---------------------------------------------------------------------------

PATTERNS: Tuple[ProcessPattern, ...] = (
    ProcessPattern(
        "create_process_api",
        "process_creation",
        r"(?i)\b(?:CreateProcess(?:A|W)?|CreateProcessAsUser(?:A|W)?|CreateProcessWithTokenW|CreateProcessWithLogonW)\b",
        "high",
        0.99,
        "References a Windows process-creation API.",
        12.0,
    ),
    ProcessPattern(
        "shell_execute_api",
        "process_execution",
        r"(?i)\b(?:ShellExecute(?:A|W)?|ShellExecuteEx(?:A|W)?)\b",
        "high",
        0.98,
        "References ShellExecute process launching.",
        10.0,
    ),
    ProcessPattern(
        "winexec_api",
        "process_execution",
        r"(?i)\bWinExec\b",
        "high",
        0.99,
        "References the legacy WinExec process-launching API.",
        10.0,
    ),
    ProcessPattern(
        "system_api",
        "command_interpreter",
        r"(?i)\b(?:system|_wsystem|WinExec)\s*\(",
        "medium",
        0.90,
        "References a native command/process execution primitive.",
        7.0,
    ),
    ProcessPattern(
        "wmi_process_create",
        "process_creation",
        r"(?i)\b(?:Win32_Process|Create\s*\(\s*[^)]*(?:CommandLine|cmd|powershell)|Invoke-CimMethod)\b",
        "high",
        0.95,
        "References WMI/CIM process creation.",
        12.0,
    ),
    ProcessPattern(
        "powershell_start_process",
        "process_creation",
        r"(?i)\b(?:Start-Process|StartProcess|System\.Diagnostics\.Process::Start)\b",
        "high",
        0.98,
        "References PowerShell or .NET process creation.",
        10.0,
    ),
    ProcessPattern(
        "process_class_start",
        "process_creation",
        r"(?i)\[(?:System\.)?Diagnostics\.Process\]\s*::\s*(?:Start|StartWithShellExecute)",
        "high",
        0.99,
        "Uses .NET Process.Start.",
        11.0,
    ),
    ProcessPattern(
        "wscript_shell_run",
        "shell_execution",
        r"(?i)\b(?:WScript\.Shell|Shell\.Run|Shell\.Exec)\b",
        "high",
        0.98,
        "Uses Windows Script Host shell process execution.",
        11.0,
    ),
    ProcessPattern(
        "shell_object_run",
        "shell_execution",
        r"(?i)\b(?:\.Run|\.Exec)\s*\(\s*(?:['\"]|&|\$[A-Za-z_])",
        "medium",
        0.80,
        "Calls a method that may launch an external command.",
        5.0,
    ),
    ProcessPattern(
        "cmd_interpreter",
        "command_interpreter",
        r"(?i)(?:^|[\s\"'`])cmd(?:\.exe)?(?:\s|['\"`]|$)",
        "medium",
        0.97,
        "References the Windows command interpreter.",
        8.0,
        process_name="cmd.exe",
    ),
    ProcessPattern(
        "powershell_host",
        "script_host",
        r"(?i)(?:^|[\s\"'`])(?:powershell|pwsh)(?:\.exe)?(?:\s|[-/]|['\"`]|$)",
        "medium",
        0.98,
        "References a PowerShell host.",
        8.0,
        process_name="powershell.exe",
    ),
    ProcessPattern(
        "wscript_host",
        "script_host",
        r"(?i)(?:^|[\s\"'`])(?:wscript|cscript)(?:\.exe)?(?:\s|[-/]|['\"`]|$)",
        "medium",
        0.98,
        "References Windows Script Host.",
        7.0,
        process_name="wscript.exe",
    ),
    ProcessPattern(
        "mshta_host",
        "signed_binary_proxy",
        r"(?i)(?:^|[\s\"'`])mshta(?:\.exe)?(?:\s|[-/]|['\"`]|$)",
        "high",
        0.99,
        "References mshta, a signed Windows execution proxy.",
        12.0,
        process_name="mshta.exe",
    ),
    ProcessPattern(
        "rundll32_host",
        "signed_binary_proxy",
        r"(?i)(?:^|[\s\"'`])rundll32(?:\.exe)?(?:\s|[-/]|['\"`]|$)",
        "high",
        0.99,
        "References rundll32 execution.",
        12.0,
        process_name="rundll32.exe",
    ),
    ProcessPattern(
        "regsvr32_host",
        "signed_binary_proxy",
        r"(?i)(?:^|[\s\"'`])regsvr32(?:\.exe)?(?:\s|[-/]|['\"`]|$)",
        "high",
        0.99,
        "References regsvr32 execution.",
        12.0,
        process_name="regsvr32.exe",
    ),
    ProcessPattern(
        "certutil_host",
        "living_off_the_land",
        r"(?i)(?:^|[\s\"'`])certutil(?:\.exe)?(?:\s|[-/]|['\"`]|$)",
        "high",
        0.99,
        "References CertUtil.",
        10.0,
        process_name="certutil.exe",
    ),
    ProcessPattern(
        "bitsadmin_host",
        "living_off_the_land",
        r"(?i)(?:^|[\s\"'`])bitsadmin(?:\.exe)?(?:\s|[-/]|['\"`]|$)",
        "high",
        0.98,
        "References BITSAdmin.",
        10.0,
        process_name="bitsadmin.exe",
    ),
    ProcessPattern(
        "wmic_host",
        "living_off_the_land",
        r"(?i)(?:^|[\s\"'`])wmic(?:\.exe)?(?:\s|[-/]|['\"`]|$)",
        "medium",
        0.97,
        "References WMIC.",
        8.0,
        process_name="wmic.exe",
    ),
    ProcessPattern(
        "msbuild_host",
        "living_off_the_land",
        r"(?i)(?:^|[\s\"'`])msbuild(?:\.exe)?(?:\s|[-/]|['\"`]|$)",
        "high",
        0.98,
        "References MSBuild.",
        11.0,
        process_name="msbuild.exe",
    ),
    ProcessPattern(
        "installutil_host",
        "living_off_the_land",
        r"(?i)(?:^|[\s\"'`])installutil(?:\.exe)?(?:\s|[-/]|['\"`]|$)",
        "high",
        0.98,
        "References InstallUtil.",
        11.0,
        process_name="installutil.exe",
    ),
    ProcessPattern(
        "regasm_host",
        "living_off_the_land",
        r"(?i)(?:^|[\s\"'`])regasm(?:\.exe)?(?:\s|[-/]|['\"`]|$)",
        "high",
        0.98,
        "References RegAsm.",
        10.0,
        process_name="regasm.exe",
    ),
    ProcessPattern(
        "regsvcs_host",
        "living_off_the_land",
        r"(?i)(?:^|[\s\"'`])regsvcs(?:\.exe)?(?:\s|[-/]|['\"`]|$)",
        "high",
        0.98,
        "References RegSvcs.",
        10.0,
        process_name="regsvcs.exe",
    ),
    ProcessPattern(
        "forfiles_host",
        "living_off_the_land",
        r"(?i)(?:^|[\s\"'`])forfiles(?:\.exe)?(?:\s|[-/]|['\"`]|$)",
        "medium",
        0.96,
        "References ForFiles.",
        7.0,
        process_name="forfiles.exe",
    ),
    ProcessPattern(
        "process_enumeration",
        "process_enumeration",
        r"(?i)\b(?:Get-Process|tasklist(?:\.exe)?|Process32First|Process32Next|CreateToolhelp32Snapshot|EnumProcesses|NtQuerySystemInformation|Win32_Process)\b",
        "medium",
        0.97,
        "References process enumeration functionality.",
        7.0,
    ),
    ProcessPattern(
        "open_process",
        "process_handle_access",
        r"(?i)\b(?:OpenProcess|NtOpenProcess|ZwOpenProcess)\b",
        "high",
        0.99,
        "References process-handle acquisition.",
        10.0,
    ),
    ProcessPattern(
        "terminate_process",
        "process_termination",
        r"(?i)\b(?:TerminateProcess|Stop-Process|taskkill(?:\.exe)?)\b",
        "medium",
        0.98,
        "References process termination.",
        6.0,
    ),
    ProcessPattern(
        "virtual_alloc",
        "process_memory",
        r"(?i)\b(?:VirtualAlloc|VirtualAllocEx|VirtualProtect|VirtualProtectEx|NtAllocateVirtualMemory|ZwAllocateVirtualMemory)\b",
        "high",
        0.99,
        "References virtual memory allocation/protection APIs.",
        12.0,
    ),
    ProcessPattern(
        "write_process_memory",
        "process_memory",
        r"(?i)\b(?:WriteProcessMemory|NtWriteVirtualMemory|ZwWriteVirtualMemory)\b",
        "critical",
        0.99,
        "References writing memory into a process.",
        18.0,
    ),
    ProcessPattern(
        "read_process_memory",
        "process_memory",
        r"(?i)\b(?:ReadProcessMemory|NtReadVirtualMemory|ZwReadVirtualMemory)\b",
        "high",
        0.99,
        "References reading memory from a process.",
        12.0,
    ),
    ProcessPattern(
        "remote_thread",
        "remote_thread",
        r"(?i)\b(?:CreateRemoteThread|CreateRemoteThreadEx|NtCreateThreadEx|RtlCreateUserThread)\b",
        "critical",
        0.99,
        "References remote-thread creation.",
        20.0,
    ),
    ProcessPattern(
        "queue_user_apc",
        "process_injection",
        r"(?i)\b(?:QueueUserAPC|NtQueueApcThread|ZwQueueApcThread)\b",
        "critical",
        0.98,
        "References APC-based process injection.",
        18.0,
    ),
    ProcessPattern(
        "thread_context",
        "process_injection",
        r"(?i)\b(?:GetThreadContext|SetThreadContext|Wow64GetThreadContext|Wow64SetThreadContext)\b",
        "high",
        0.98,
        "References thread-context manipulation.",
        14.0,
    ),
    ProcessPattern(
        "process_hollowing_terms",
        "process_hollowing",
        r"(?i)(?:PROCESS_HOLLOWING|process hollowing|NtUnmapViewOfSection|ZwUnmapViewOfSection|unmap.*section.*process)",
        "critical",
        0.94,
        "Contains process-hollowing-related static indicators.",
        18.0,
    ),
    ProcessPattern(
        "duplicate_process_handle",
        "process_handle_access",
        r"(?i)\b(?:DuplicateHandle|NtDuplicateObject|ZwDuplicateObject)\b",
        "high",
        0.98,
        "References duplication of process or object handles.",
        11.0,
    ),
    ProcessPattern(
        "token_open",
        "token_manipulation",
        r"(?i)\b(?:OpenProcessToken|OpenThreadToken|DuplicateToken|DuplicateTokenEx)\b",
        "high",
        0.98,
        "References access or duplication of security tokens.",
        10.0,
    ),
    ProcessPattern(
        "token_privilege",
        "privilege",
        r"(?i)\b(?:AdjustTokenPrivileges|SeDebugPrivilege|SeImpersonatePrivilege|SeAssignPrimaryTokenPrivilege)\b",
        "high",
        0.98,
        "References security-token privilege manipulation.",
        13.0,
    ),
    ProcessPattern(
        "parent_process_attribute",
        "parent_process",
        r"(?i)(?:PROC_THREAD_ATTRIBUTE_PARENT_PROCESS|UpdateProcThreadAttribute|ParentProcess)",
        "high",
        0.96,
        "References explicit parent-process manipulation.",
        13.0,
    ),
    ProcessPattern(
        "debug_privilege",
        "privilege",
        r"(?i)\bSeDebugPrivilege\b",
        "high",
        0.99,
        "References SeDebugPrivilege.",
        12.0,
    ),
    ProcessPattern(
        "environment_process_launch",
        "environment",
        r"(?i)(?:ProcessStartInfo|UseShellExecute|CreateNoWindow|WindowStyle\s*=\s*['\"]Hidden['\"])",
        "medium",
        0.92,
        "References process-launch configuration.",
        6.0,
    ),
    ProcessPattern(
        "hidden_process_window",
        "evasion",
        r"(?i)(?:-WindowStyle\s+Hidden|CreateNoWindow\s*=\s*\$?true|SW_HIDE|STARTF_USESHOWWINDOW)",
        "medium",
        0.95,
        "Configures hidden process execution.",
        8.0,
    ),
    ProcessPattern(
        "parent_pid",
        "parent_process",
        r"(?i)(?:ParentProcessId|PPID|InheritedFromUniqueProcessId)",
        "medium",
        0.93,
        "References process parentage information.",
        5.0,
    ),
)


_COMPILED_PATTERNS: Tuple[Tuple[ProcessPattern, re.Pattern[str]], ...] = tuple(
    (definition, re.compile(definition.regex)) for definition in PATTERNS
)


# ---------------------------------------------------------------------------
# Combination rules
# ---------------------------------------------------------------------------

COMBINATION_DEFINITIONS: Tuple[Tuple[str, Tuple[str, ...], str, str], ...] = (
    (
        "remote_process_injection",
        (
            "open_process",
            "write_process_memory",
            "remote_thread",
        ),
        "Combines process-handle access, remote memory writing, and remote-thread creation.",
        "critical",
    ),
    (
        "memory_injection_chain",
        (
            "virtual_alloc",
            "write_process_memory",
            "remote_thread",
        ),
        "Contains a classic remote-memory injection chain.",
        "critical",
    ),
    (
        "apc_injection",
        (
            "open_process",
            "queue_user_apc",
        ),
        "Combines process access with APC-based execution.",
        "critical",
    ),
    (
        "process_hollowing_chain",
        (
            "create_process_api",
            "process_hollowing_terms",
        ),
        "Contains process creation plus hollowing-related behavior.",
        "critical",
    ),
    (
        "token_process_manipulation",
        (
            "open_process",
            "token_open",
        ),
        "Combines process access with security-token manipulation.",
        "high",
    ),
    (
        "privileged_process_access",
        (
            "open_process",
            "debug_privilege",
        ),
        "Combines process access with SeDebugPrivilege.",
        "high",
    ),
    (
        "hidden_process_execution",
        (
            "process_creation",
            "hidden_process_window",
        ),
        "Combines process creation with hidden-window execution.",
        "high",
    ),
    (
        "script_host_execution",
        (
            "powershell_host",
            "create_process_api",
        ),
        "Combines script-host execution with an explicit process-creation primitive.",
        "high",
    ),
    (
        "lolbin_execution",
        (
            "signed_binary_proxy",
            "living_off_the_land",
        ),
        "Contains multiple signed-binary or LOLBin execution indicators.",
        "high",
    ),
    (
        "process_discovery_then_execution",
        (
            "process_enumeration",
            "process_creation",
        ),
        "Combines process discovery with process creation.",
        "medium",
    ),
    (
        "parent_process_manipulation",
        (
            "create_process_api",
            "parent_process_attribute",
        ),
        "Combines process creation with explicit parent-process manipulation.",
        "critical",
    ),
)


# ---------------------------------------------------------------------------
# Input normalization
# ---------------------------------------------------------------------------


def _decode_bytes(data: bytes) -> str:
    if data.startswith(b"\xff\xfe"):
        return data[2:].decode("utf-16-le", errors="replace")

    if data.startswith(b"\xfe\xff"):
        return data[2:].decode("utf-16-be", errors="replace")

    if data.startswith(b"\xef\xbb\xbf"):
        return data[3:].decode("utf-8", errors="replace")

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
    if isinstance(source, Path):
        size = source.stat().st_size
        if size > max_size:
            raise ValueError(
                f"source exceeds maximum supported size " f"({size} > {max_size})"
            )
        return _decode_bytes(source.read_bytes()), str(source)

    if isinstance(source, (bytes, bytearray, memoryview)):
        data = bytes(source)
        if len(data) > max_size:
            raise ValueError(
                f"source exceeds maximum supported size " f"({len(data)} > {max_size})"
            )
        return _decode_bytes(data), None

    if isinstance(source, str):
        if "\n" not in source and "\r" not in source:
            try:
                path = Path(source)
                if path.exists() and path.is_file():
                    size = path.stat().st_size
                    if size > max_size:
                        raise ValueError(
                            f"source exceeds maximum supported size "
                            f"({size} > {max_size})"
                        )
                    return _decode_bytes(path.read_bytes()), str(path)
            except (OSError, ValueError):
                pass

        encoded_size = len(source.encode("utf-8", errors="replace"))
        if encoded_size > max_size:
            raise ValueError(
                f"source exceeds maximum supported size "
                f"({encoded_size} > {max_size})"
            )

        return source, None

    raise TypeError("source must be str, bytes, bytearray, memoryview, or pathlib.Path")


def _normalize_scalar(value: Any) -> Optional[str]:
    if value is None:
        return None

    if isinstance(value, str):
        return value[:MAX_FIELD_TEXT]

    if isinstance(value, (bytes, bytearray, memoryview)):
        return _decode_bytes(bytes(value))[:MAX_FIELD_TEXT]

    if isinstance(value, (int, float, bool)):
        return str(value)

    return None


def _mapping_to_text(
    value: Any,
    *,
    depth: int = 0,
    visited: Optional[set[int]] = None,
) -> str:
    """
    Flatten structured extraction results into bounded searchable text.

    This intentionally extracts only values useful for static correlation.
    It never interprets or executes values.
    """

    if depth > MAX_NESTING_DEPTH:
        return ""

    if visited is None:
        visited = set()

    object_id = id(value)

    if object_id in visited:
        return ""

    visited.add(object_id)

    scalar = _normalize_scalar(value)
    if scalar is not None:
        return scalar

    if isinstance(value, Mapping):
        chunks: List[str] = []

        for key, item in list(value.items())[:MAX_TOKENS]:
            key_text = _normalize_scalar(key) or ""
            item_text = _mapping_to_text(
                item,
                depth=depth + 1,
                visited=visited,
            )

            if key_text:
                chunks.append(key_text)

            if item_text:
                chunks.append(item_text)

        return "\n".join(chunks)[:MAX_TEXT_CHARS]

    if isinstance(value, (list, tuple, set, frozenset)):
        chunks = []

        for item in list(value)[:MAX_TOKENS]:
            text = _mapping_to_text(
                item,
                depth=depth + 1,
                visited=visited,
            )
            if text:
                chunks.append(text)

        return "\n".join(chunks)[:MAX_TEXT_CHARS]

    # Support dataclasses and ordinary analysis objects without importing
    # project-specific modules.
    if hasattr(value, "__dataclass_fields__"):
        try:
            return _mapping_to_text(
                asdict(value),
                depth=depth + 1,
                visited=visited,
            )
        except Exception:
            pass

    if hasattr(value, "__dict__"):
        try:
            public = {
                key: item
                for key, item in vars(value).items()
                if not key.startswith("_")
            }
            return _mapping_to_text(
                public,
                depth=depth + 1,
                visited=visited,
            )
        except Exception:
            pass

    return ""


# ---------------------------------------------------------------------------
# Text utilities
# ---------------------------------------------------------------------------


def _line_number(source: str, offset: int) -> int:
    return source.count("\n", 0, offset) + 1


def _dedupe(values: Iterable[str], limit: int = 10_000) -> List[str]:
    result: List[str] = []
    seen: set[str] = set()

    for value in values:
        value = value.strip()

        if not value:
            continue

        key = value.casefold()

        if key in seen:
            continue

        seen.add(key)
        result.append(value)

        if len(result) >= limit:
            break

    return result


def _normalize_process_name(name: str) -> str:
    value = name.strip().strip("\"'`")
    value = value.replace("/", "\\")
    value = value.rsplit("\\", 1)[-1]
    return value.casefold()


def _canonical_process_name(name: str) -> str:
    normalized = _normalize_process_name(name)

    aliases = {
        "cmd": "cmd.exe",
        "command.com": "command.com",
        "powershell": "powershell.exe",
        "pwsh": "pwsh.exe",
        "wscript": "wscript.exe",
        "cscript": "cscript.exe",
        "mshta": "mshta.exe",
        "rundll32": "rundll32.exe",
        "regsvr32": "regsvr32.exe",
        "certutil": "certutil.exe",
        "bitsadmin": "bitsadmin.exe",
        "wmic": "wmic.exe",
        "msbuild": "msbuild.exe",
        "installutil": "installutil.exe",
        "regasm": "regasm.exe",
        "regsvcs": "regsvcs.exe",
        "forfiles": "forfiles.exe",
        "csc": "csc.exe",
        "vbc": "vbc.exe",
        "cmstp": "cmstp.exe",
        "hh": "hh.exe",
        "esentutl": "esentutl.exe",
    }

    return aliases.get(normalized, normalized)


# ---------------------------------------------------------------------------
# Process-name extraction
# ---------------------------------------------------------------------------


PROCESS_TOKEN_RE = re.compile(r"""(?ix)
    (?:
        (?P<path>
            [A-Za-z]:\\[^"'`\r\n<>|]+?\.(?:exe|com|bat|cmd|ps1|psm1|vbs|vbe|js|jse|hta)
        )
        |
        (?P<bare>
            \b[A-Za-z0-9_.-]+?\.(?:exe|com|bat|cmd|ps1|psm1|vbs|vbe|js|jse|hta)\b
        )
    )
    """)

PROCESS_ASSIGNMENT_RE = re.compile(r"""(?ix)
    \b(?:FileName|Executable|ExecutablePath|Command|CommandLine|ApplicationName|
    ProcessName|ImagePath|Program|TargetPath)\b
    \s*(?:=|:)\s*
    ['"`]?([^'\r\n"`]{1,500})
    """)


def extract_process_records(
    source: str,
    *,
    limit: int = MAX_PROCESSES,
) -> List[ProcessRecord]:
    records: List[ProcessRecord] = []
    seen: set[Tuple[str, int]] = set()

    for match in PROCESS_TOKEN_RE.finditer(source):
        raw = match.group("path") or match.group("bare") or ""
        raw = raw.strip()

        normalized = _normalize_process_name(raw)
        canonical = _canonical_process_name(normalized)

        if not normalized:
            continue

        line_number = _line_number(source, match.start())

        key = (canonical, line_number)

        if key in seen:
            continue

        seen.add(key)

        records.append(
            ProcessRecord(
                name=raw,
                normalized_name=canonical,
                source="process_token",
                line_number=line_number,
                is_shell=canonical in SHELL_PROCESSES,
                is_script_host=canonical in SCRIPT_HOSTS,
                is_signed_binary_proxy=canonical
                in {
                    "mshta.exe",
                    "rundll32.exe",
                    "regsvr32.exe",
                },
                is_likely_lolbin=canonical in LIKELY_LOLBINS,
            )
        )

        if len(records) >= limit:
            break

    for match in PROCESS_ASSIGNMENT_RE.finditer(source):
        raw = match.group(1).strip()

        token_match = PROCESS_TOKEN_RE.search(raw)

        if token_match:
            process_text = token_match.group("path") or token_match.group("bare") or ""
        else:
            # Only use a bounded first token for fields such as
            # "powershell.exe -enc ...".
            process_text = raw.split(None, 1)[0]

        if not process_text:
            continue

        normalized = _normalize_process_name(process_text)
        canonical = _canonical_process_name(normalized)

        line_number = _line_number(source, match.start())

        key = (canonical, line_number)

        if key in seen:
            continue

        seen.add(key)

        arguments = None
        if len(raw) > len(process_text):
            arguments = raw[len(process_text) :].strip()[:1000]

        records.append(
            ProcessRecord(
                name=process_text,
                normalized_name=canonical,
                source="process_field",
                line_number=line_number,
                arguments=arguments,
                is_shell=canonical in SHELL_PROCESSES,
                is_script_host=canonical in SCRIPT_HOSTS,
                is_signed_binary_proxy=canonical
                in {
                    "mshta.exe",
                    "rundll32.exe",
                    "regsvr32.exe",
                },
                is_likely_lolbin=canonical in LIKELY_LOLBINS,
            )
        )

        if len(records) >= limit:
            break

    return records


# ---------------------------------------------------------------------------
# Pattern matching
# ---------------------------------------------------------------------------


def _pattern_evidence(
    source: str,
    *,
    include_low_confidence: bool = True,
) -> List[ProcessEvidence]:
    evidence: List[ProcessEvidence] = []
    seen: set[Tuple[str, int, str]] = set()

    for definition, pattern in _COMPILED_PATTERNS:
        if not include_low_confidence and definition.confidence < 0.80:
            continue

        match_count = 0

        for match in pattern.finditer(source):
            raw = match.group(0).strip()

            if not raw:
                continue

            line = _line_number(source, match.start())
            snippet = raw[:500]

            key = (
                definition.name,
                line,
                snippet.casefold(),
            )

            if key in seen:
                continue

            seen.add(key)

            evidence.append(
                ProcessEvidence(
                    indicator=definition.name,
                    category=definition.category,
                    evidence=snippet,
                    severity=definition.severity,
                    confidence=definition.confidence,
                    line_number=line,
                    process_name=definition.process_name,
                    source_type="pattern",
                    description=definition.description,
                    weight=definition.weight,
                )
            )

            match_count += 1

            if (
                match_count >= MAX_MATCHES_PER_RULE
                or len(evidence) >= MAX_EVIDENCE_ITEMS
            ):
                break

        if len(evidence) >= MAX_EVIDENCE_ITEMS:
            break

    return evidence


def _process_record_evidence(
    records: Sequence[ProcessRecord],
) -> List[ProcessEvidence]:
    evidence: List[ProcessEvidence] = []

    for record in records:
        if len(evidence) >= MAX_EVIDENCE_ITEMS:
            break

        if record.is_shell:
            evidence.append(
                ProcessEvidence(
                    indicator="known_shell_process",
                    category="shell_execution",
                    evidence=record.name,
                    severity="medium",
                    confidence=0.97,
                    line_number=record.line_number,
                    process_name=record.normalized_name,
                    source_type=record.source,
                    description="References a command or scripting shell.",
                    weight=6.0,
                )
            )

        if record.is_script_host:
            evidence.append(
                ProcessEvidence(
                    indicator="known_script_host",
                    category="script_host",
                    evidence=record.name,
                    severity="medium",
                    confidence=0.97,
                    line_number=record.line_number,
                    process_name=record.normalized_name,
                    source_type=record.source,
                    description="References a Windows scripting or PowerShell host.",
                    weight=6.0,
                )
            )

        if record.is_signed_binary_proxy:
            evidence.append(
                ProcessEvidence(
                    indicator="signed_binary_proxy_process",
                    category="signed_binary_proxy",
                    evidence=record.name,
                    severity="high",
                    confidence=0.98,
                    line_number=record.line_number,
                    process_name=record.normalized_name,
                    source_type=record.source,
                    description="References a signed Windows binary capable of proxy execution.",
                    weight=10.0,
                )
            )

        if record.is_likely_lolbin:
            evidence.append(
                ProcessEvidence(
                    indicator="lolbin_process",
                    category="living_off_the_land",
                    evidence=record.name,
                    severity="high",
                    confidence=0.97,
                    line_number=record.line_number,
                    process_name=record.normalized_name,
                    source_type=record.source,
                    description="References a commonly abused Windows utility.",
                    weight=8.0,
                )
            )

    return evidence[:MAX_EVIDENCE_ITEMS]


# ---------------------------------------------------------------------------
# Command-line relationship extraction
# ---------------------------------------------------------------------------


def _extract_command_contexts(
    source: str,
    *,
    limit: int = MAX_COMMAND_LINES,
) -> List[str]:
    contexts: List[str] = []

    for line in source.splitlines():
        stripped = line.strip()

        if not stripped:
            continue

        lowered = stripped.casefold()

        if any(
            token in lowered
            for token in (
                "createprocess",
                "shellexecute",
                "start-process",
                "process.start",
                "wscript.shell",
                "cmd.exe",
                "powershell",
                "pwsh",
                "mshta",
                "rundll32",
                "regsvr32",
                "certutil",
                "bitsadmin",
                "wmic",
                "msbuild",
                "installutil",
                "regasm",
                "regsvcs",
            )
        ):
            contexts.append(stripped[:2000])

        if len(contexts) >= limit:
            break

    return contexts


def _derive_command_chain_evidence(
    source: str,
) -> List[ProcessEvidence]:
    evidence: List[ProcessEvidence] = []

    contexts = _extract_command_contexts(source)

    for context in contexts:
        lowered = context.casefold()

        shell = any(
            item in lowered
            for item in (
                "cmd.exe",
                "powershell",
                "pwsh",
                "wscript",
                "cscript",
                "mshta",
            )
        )

        downloader = any(
            item in lowered
            for item in (
                "invoke-webrequest",
                "invoke-restmethod",
                "downloadstring",
                "downloadfile",
                "bitsadmin",
                "certutil",
                "curl ",
                "wget ",
            )
        )

        execution = any(
            item in lowered
            for item in (
                "start-process",
                "process.start",
                "createprocess",
                "shellexecute",
                "cmd.exe",
                "powershell",
                "mshta",
                "rundll32",
                "regsvr32",
            )
        )

        if shell and execution:
            evidence.append(
                ProcessEvidence(
                    indicator="shell_execution_chain",
                    category="execution_chain",
                    evidence=context,
                    severity="high",
                    confidence=0.90,
                    source_type="command_context",
                    description="A command context contains shell/process execution.",
                    weight=8.0,
                )
            )

        if downloader and execution:
            evidence.append(
                ProcessEvidence(
                    indicator="download_execute_chain",
                    category="execution_chain",
                    evidence=context,
                    severity="high",
                    confidence=0.89,
                    source_type="command_context",
                    description="A command context combines acquisition and process execution.",
                    weight=11.0,
                )
            )

    return evidence[:MAX_EVIDENCE_ITEMS]


# ---------------------------------------------------------------------------
# Combination derivation
# ---------------------------------------------------------------------------


def _indicator_set(
    evidence: Sequence[ProcessEvidence],
) -> set[str]:
    return {item.indicator.casefold() for item in evidence}


def _category_set(
    evidence: Sequence[ProcessEvidence],
) -> set[str]:
    return {item.category.casefold() for item in evidence}


def _derive_combinations(
    evidence: Sequence[ProcessEvidence],
) -> List[ProcessCombination]:
    indicators = _indicator_set(evidence)
    categories = _category_set(evidence)

    combinations: List[ProcessCombination] = []

    for name, requirements, explanation, severity in COMBINATION_DEFINITIONS:
        if name == "remote_process_injection":
            present = all(item in indicators for item in requirements)

        elif name == "memory_injection_chain":
            present = all(item in indicators for item in requirements)

        elif name == "apc_injection":
            present = "open_process" in indicators and "queue_user_apc" in indicators

        elif name == "process_hollowing_chain":
            present = (
                "create_process_api" in indicators
                and "process_hollowing_terms" in indicators
            )

        elif name == "token_process_manipulation":
            present = "open_process" in indicators and "token_open" in indicators

        elif name == "privileged_process_access":
            present = "open_process" in indicators and "debug_privilege" in indicators

        elif name == "hidden_process_execution":
            present = (
                "process_creation" in categories
                and "hidden_process_window" in indicators
            )

        elif name == "script_host_execution":
            present = (
                "powershell_host" in indicators and "create_process_api" in indicators
            )

        elif name == "lolbin_execution":
            present = (
                "signed_binary_proxy" in categories
                and "living_off_the_land" in categories
            )

        elif name == "process_discovery_then_execution":
            present = (
                "process_enumeration" in indicators and "process_creation" in categories
            )

        elif name == "parent_process_manipulation":
            present = (
                "create_process_api" in indicators
                and "parent_process_attribute" in indicators
            )

        else:
            present = all(item in indicators for item in requirements)

        combinations.append(
            ProcessCombination(
                name=name,
                present=present,
                required_indicators=list(requirements),
                explanation=explanation,
                severity=severity,
            )
        )

    return combinations


# ---------------------------------------------------------------------------
# Signal score
# ---------------------------------------------------------------------------


def _calculate_signal_score(
    evidence: Sequence[ProcessEvidence],
    combinations: Sequence[ProcessCombination],
) -> float:
    score = 0.0

    severity_multiplier = {
        "low": 0.55,
        "medium": 0.85,
        "high": 1.15,
        "critical": 1.45,
    }

    for item in evidence:
        score += (
            item.weight * item.confidence * severity_multiplier.get(item.severity, 1.0)
        )

    combination_bonus = {
        "low": 2.0,
        "medium": 5.0,
        "high": 11.0,
        "critical": 20.0,
    }

    for combination in combinations:
        if combination.present:
            score += combination_bonus.get(
                combination.severity,
                5.0,
            )

    return round(
        min(100.0, max(0.0, score)),
        4,
    )


# ---------------------------------------------------------------------------
# Feature schema
# ---------------------------------------------------------------------------


def process_feature_names() -> List[str]:
    names = [
        "process_source_size",
        "process_record_count",
        "process_unique_name_count",
        "process_evidence_count",
        "process_indicator_count",
        "process_category_count",
        "process_combination_count",
        "process_present_combination_count",
        "process_shell_process_count",
        "process_script_host_count",
        "process_lolbin_count",
        "process_signed_binary_proxy_count",
        "process_high_severity_count",
        "process_critical_severity_count",
        "process_signal_score",
    ]

    for category in PROCESS_CATEGORIES:
        names.append(f"process_category_{category}")
        names.append(f"process_category_{category}_count")

    indicator_names = _dedupe(
        (definition.name for definition in PATTERNS),
        limit=10_000,
    )

    for indicator in indicator_names:
        names.append(f"process_indicator_{indicator}")
        names.append(f"process_indicator_{indicator}_count")

    for name, _, _, _ in COMBINATION_DEFINITIONS:
        names.append(f"process_combination_{name}")

    return names


def build_feature_schema() -> Dict[str, Any]:
    return {
        "name": "process_behavior_static_features",
        "version": "1.0.0",
        "description": (
            "Stable scalar process-behavior features derived entirely from "
            "static evidence."
        ),
        "feature_names": process_feature_names(),
        "feature_count": len(process_feature_names()),
        "target_type": "numeric",
        "score_semantics": (
            "process_signal_score is a bounded heuristic signal from 0 to 100 "
            "and is not a calibrated malware probability."
        ),
        "categories": list(PROCESS_CATEGORIES),
        "indicators": [definition.name for definition in PATTERNS],
        "combinations": [definition[0] for definition in COMBINATION_DEFINITIONS],
    }


# ---------------------------------------------------------------------------
# Feature-vector construction
# ---------------------------------------------------------------------------


def _build_feature_vector(
    analysis: ProcessAnalysis,
) -> Dict[str, float]:
    evidence = analysis.evidence

    category_counts = Counter(item.category.casefold() for item in evidence)

    indicator_counts = Counter(item.indicator.casefold() for item in evidence)

    high_count = sum(1 for item in evidence if SEVERITY_RANK.get(item.severity, 0) >= 3)

    critical_count = sum(1 for item in evidence if item.severity == "critical")

    vector: Dict[str, float] = {
        "process_source_size": float(analysis.source_size),
        "process_record_count": float(len(analysis.processes)),
        "process_unique_name_count": float(
            len({item.normalized_name for item in analysis.processes})
        ),
        "process_evidence_count": float(len(evidence)),
        "process_indicator_count": float(len(indicator_counts)),
        "process_category_count": float(len(category_counts)),
        "process_combination_count": float(len(analysis.combinations)),
        "process_present_combination_count": float(
            sum(1 for item in analysis.combinations if item.present)
        ),
        "process_shell_process_count": float(len(analysis.shell_processes)),
        "process_script_host_count": float(len(analysis.script_hosts)),
        "process_lolbin_count": float(len(analysis.lolbins)),
        "process_signed_binary_proxy_count": float(
            sum(1 for item in analysis.processes if item.is_signed_binary_proxy)
        ),
        "process_high_severity_count": float(high_count),
        "process_critical_severity_count": float(critical_count),
        "process_signal_score": float(analysis.metadata.get("signal_score", 0.0)),
    }

    for category in PROCESS_CATEGORIES:
        count = category_counts.get(category, 0)

        vector[f"process_category_{category}"] = float(1 if count else 0)
        vector[f"process_category_{category}_count"] = float(count)

    for definition in PATTERNS:
        indicator = definition.name.casefold()
        count = indicator_counts.get(indicator, 0)

        vector[f"process_indicator_{definition.name}"] = float(1 if count else 0)
        vector[f"process_indicator_{definition.name}_count"] = float(count)

    for combination in analysis.combinations:
        vector[f"process_combination_{combination.name}"] = float(
            1 if combination.present else 0
        )

    return {name: float(vector.get(name, 0.0)) for name in process_feature_names()}


# ---------------------------------------------------------------------------
# Main analyzer
# ---------------------------------------------------------------------------


def analyze_process_behavior(
    source: Union[
        str,
        bytes,
        bytearray,
        memoryview,
        Path,
        Mapping[str, Any],
        Sequence[Any],
        Any,
    ],
    *,
    max_source_size: int = MAX_SOURCE_SIZE,
    include_low_confidence: bool = True,
) -> ProcessAnalysis:
    """
    Perform static process-behavior analysis.

    ``source`` may be raw text or structured output from another pharos-cdr
    extractor.
    """

    source_name: Optional[str] = None

    if isinstance(
        source,
        (str, bytes, bytearray, memoryview, Path),
    ):
        text, source_name = _read_source(
            source,
            max_size=max_source_size,
        )
    else:
        text = _mapping_to_text(source)

        encoded_size = len(
            text.encode(
                "utf-8",
                errors="replace",
            )
        )

        if encoded_size > max_source_size:
            text = text[:max_source_size]

    source_size = len(
        text.encode(
            "utf-8",
            errors="replace",
        )
    )

    source_hash = hashlib.sha256(
        text.encode(
            "utf-8",
            errors="replace",
        )
    ).hexdigest()

    pattern_evidence = _pattern_evidence(
        text,
        include_low_confidence=include_low_confidence,
    )

    records = extract_process_records(
        text,
        limit=MAX_PROCESSES,
    )

    record_evidence = _process_record_evidence(
        records,
    )

    chain_evidence = _derive_command_chain_evidence(
        text,
    )

    evidence: List[ProcessEvidence] = []
    seen: set[Tuple[str, Optional[int], str]] = set()

    for item in pattern_evidence + record_evidence + chain_evidence:
        key = (
            item.indicator.casefold(),
            item.line_number,
            item.evidence.casefold(),
        )

        if key in seen:
            continue

        seen.add(key)
        evidence.append(item)

        if len(evidence) >= MAX_EVIDENCE_ITEMS:
            break

    indicators = _dedupe(item.indicator for item in evidence)

    categories = _dedupe(item.category for item in evidence)

    combinations = _derive_combinations(
        evidence,
    )

    shell_processes = _dedupe(item.normalized_name for item in records if item.is_shell)

    script_hosts = _dedupe(
        item.normalized_name for item in records if item.is_script_host
    )

    lolbins = _dedupe(item.normalized_name for item in records if item.is_likely_lolbin)

    process_names = _dedupe(item.normalized_name for item in records)

    signal_score = _calculate_signal_score(
        evidence,
        combinations,
    )

    metadata: Dict[str, Any] = {
        "source_name": source_name,
        "sha256": source_hash,
        "signal_score": signal_score,
        "highest_severity": (
            max(
                (item.severity for item in evidence),
                key=lambda value: SEVERITY_RANK.get(
                    value,
                    0,
                ),
            )
            if evidence
            else "low"
        ),
        "high_risk_evidence_count": sum(
            1 for item in evidence if item.severity in {"high", "critical"}
        ),
        "critical_evidence_count": sum(
            1 for item in evidence if item.severity == "critical"
        ),
        "has_process_creation": any(
            item.category == "process_creation" for item in evidence
        ),
        "has_process_injection": any(
            item.category
            in {
                "process_injection",
                "process_memory",
                "remote_thread",
                "process_hollowing",
            }
            for item in evidence
        ),
        "has_shell_execution": any(
            item.category
            in {
                "shell_execution",
                "command_interpreter",
                "script_host",
            }
            for item in evidence
        ),
        "has_lolbin": bool(lolbins),
        "execution_performed": False,
        "dynamic_analysis_performed": False,
        "processes_started": False,
        "process_handles_opened": False,
        "network_access_performed": False,
        "parser": "pharos-cdr.static-process-behavior",
        "parser_version": "1.0.0",
    }

    analysis = ProcessAnalysis(
        source_hash=source_hash,
        source_size=source_size,
        processes=records,
        evidence=evidence,
        indicators=indicators,
        categories=categories,
        combinations=combinations,
        shell_processes=shell_processes,
        script_hosts=script_hosts,
        lolbins=lolbins,
        process_names=process_names,
        metadata=metadata,
    )

    analysis.feature_vector = _build_feature_vector(
        analysis,
    )

    return analysis


# ---------------------------------------------------------------------------
# Aliases / public feature APIs
# ---------------------------------------------------------------------------


def analyze(
    source: Any,
    **kwargs: Any,
) -> ProcessAnalysis:
    """Short alias for :func:`analyze_process_behavior`."""

    return analyze_process_behavior(
        source,
        **kwargs,
    )


def parse_process_behavior(
    source: Any,
    **kwargs: Any,
) -> ProcessAnalysis:
    """Parser-style alias for the process analyzer."""

    return analyze_process_behavior(
        source,
        **kwargs,
    )


def extract_process_features(
    source: Any,
    **kwargs: Any,
) -> ProcessAnalysis:
    """Return complete process-behavior features."""

    return analyze_process_behavior(
        source,
        **kwargs,
    )


def extract_feature_vector(
    source: Any,
    **kwargs: Any,
) -> Dict[str, float]:
    """Analyze input and return the stable process feature vector."""

    return analyze_process_behavior(
        source,
        **kwargs,
    ).feature_vector


def extract_process_feature_vector(
    source: Any,
    **kwargs: Any,
) -> Dict[str, float]:
    """Explicit process-feature-vector alias."""

    return extract_feature_vector(
        source,
        **kwargs,
    )


def vectorize_features(
    analysis: Union[
        ProcessAnalysis,
        Mapping[str, Any],
    ],
) -> Dict[str, float]:
    """Normalize a process analysis/mapping to the stable feature schema."""

    if isinstance(analysis, ProcessAnalysis):
        values = analysis.feature_vector
    elif isinstance(analysis, Mapping):
        values = analysis.get(
            "feature_vector",
            analysis,
        )
    else:
        raise TypeError("analysis must be ProcessAnalysis or a mapping")

    if not isinstance(values, Mapping):
        raise TypeError("feature_vector must be a mapping")

    return {name: float(values.get(name, 0.0)) for name in process_feature_names()}


# ---------------------------------------------------------------------------
# Query helpers
# ---------------------------------------------------------------------------


def has_indicator(
    analysis: ProcessAnalysis,
    indicator: str,
) -> bool:
    target = indicator.casefold()

    return any(item.indicator.casefold() == target for item in analysis.evidence)


def has_category(
    analysis: ProcessAnalysis,
    category: str,
) -> bool:
    target = category.casefold()

    return any(item.category.casefold() == target for item in analysis.evidence)


def indicator_count(
    analysis: ProcessAnalysis,
    indicator: str,
) -> int:
    target = indicator.casefold()

    return sum(1 for item in analysis.evidence if item.indicator.casefold() == target)


def category_count(
    analysis: ProcessAnalysis,
    category: str,
) -> int:
    target = category.casefold()

    return sum(1 for item in analysis.evidence if item.category.casefold() == target)


def evidence_by_category(
    analysis: ProcessAnalysis,
    category: str,
) -> List[ProcessEvidence]:
    target = category.casefold()

    return [item for item in analysis.evidence if item.category.casefold() == target]


def evidence_by_indicator(
    analysis: ProcessAnalysis,
    indicator: str,
) -> List[ProcessEvidence]:
    target = indicator.casefold()

    return [item for item in analysis.evidence if item.indicator.casefold() == target]


def high_risk_evidence(
    analysis: ProcessAnalysis,
) -> List[ProcessEvidence]:
    return sorted(
        (item for item in analysis.evidence if item.severity in {"high", "critical"}),
        key=lambda item: (
            -SEVERITY_RANK.get(
                item.severity,
                0,
            ),
            -item.confidence,
            -(item.weight or 0.0),
            item.line_number or 0,
        ),
    )


def present_combinations(
    analysis: ProcessAnalysis,
) -> List[ProcessCombination]:
    return [item for item in analysis.combinations if item.present]


def highest_severity(
    analysis: ProcessAnalysis,
) -> str:
    if not analysis.evidence:
        return "low"

    return max(
        (item.severity for item in analysis.evidence),
        key=lambda value: SEVERITY_RANK.get(
            value,
            0,
        ),
    )


# ---------------------------------------------------------------------------
# Serialization
# ---------------------------------------------------------------------------


def analysis_to_dict(
    analysis: ProcessAnalysis,
) -> Dict[str, Any]:
    """Return a JSON-compatible representation."""

    return {
        "source_hash": analysis.source_hash,
        "source_size": analysis.source_size,
        "processes": [asdict(item) for item in analysis.processes],
        "evidence": [asdict(item) for item in analysis.evidence],
        "indicators": list(analysis.indicators),
        "categories": list(analysis.categories),
        "combinations": [asdict(item) for item in analysis.combinations],
        "shell_processes": list(analysis.shell_processes),
        "script_hosts": list(analysis.script_hosts),
        "lolbins": list(analysis.lolbins),
        "process_names": list(analysis.process_names),
        "feature_vector": dict(analysis.feature_vector),
        "metadata": dict(analysis.metadata),
    }


def summarize_process_behavior(
    analysis: ProcessAnalysis,
) -> Dict[str, Any]:
    """Return a compact analyst-facing summary."""

    high_risk = high_risk_evidence(analysis)

    present = present_combinations(analysis)

    return {
        "sha256": analysis.source_hash,
        "source_size": analysis.source_size,
        "signal_score": analysis.metadata.get(
            "signal_score",
            0.0,
        ),
        "highest_severity": highest_severity(analysis),
        "process_count": len(analysis.processes),
        "unique_process_count": len(analysis.process_names),
        "evidence_count": len(analysis.evidence),
        "high_risk_evidence_count": len(high_risk),
        "shell_processes": list(analysis.shell_processes),
        "script_hosts": list(analysis.script_hosts),
        "lolbins": list(analysis.lolbins),
        "indicators": list(analysis.indicators),
        "categories": list(analysis.categories),
        "high_risk_indicators": _dedupe(item.indicator for item in high_risk),
        "present_combinations": [item.name for item in present],
        "process_names": list(analysis.process_names),
    }


# ---------------------------------------------------------------------------
# Iterators
# ---------------------------------------------------------------------------


def iter_evidence(
    analysis: ProcessAnalysis,
) -> Iterator[ProcessEvidence]:
    yield from analysis.evidence


def iter_high_risk_evidence(
    analysis: ProcessAnalysis,
) -> Iterator[ProcessEvidence]:
    yield from high_risk_evidence(analysis)


def iter_processes(
    analysis: ProcessAnalysis,
) -> Iterator[ProcessRecord]:
    yield from analysis.processes


def iter_combinations(
    analysis: ProcessAnalysis,
) -> Iterator[ProcessCombination]:
    yield from analysis.combinations


def iter_analyses(
    sources: Iterable[Any],
    **kwargs: Any,
) -> Iterator[ProcessAnalysis]:
    """Lazily analyze multiple evidence sources."""

    for source in sources:
        yield analyze_process_behavior(
            source,
            **kwargs,
        )


# ---------------------------------------------------------------------------
# Public constants / compatibility aliases
# ---------------------------------------------------------------------------

PROCESS_PATTERNS = PATTERNS

parse = parse_process_behavior
extract = extract_process_features


__all__ = [
    "MAX_SOURCE_SIZE",
    "MAX_EVIDENCE_ITEMS",
    "PROCESS_CATEGORIES",
    "SEVERITIES",
    "ProcessPattern",
    "ProcessEvidence",
    "ProcessRecord",
    "ProcessCombination",
    "ProcessAnalysis",
    "PATTERNS",
    "PROCESS_PATTERNS",
    "SHELL_PROCESSES",
    "SCRIPT_HOSTS",
    "LIKELY_LOLBINS",
    "COMMON_SYSTEM_PROCESSES",
    "analyze_process_behavior",
    "parse_process_behavior",
    "extract_process_features",
    "extract_feature_vector",
    "extract_process_feature_vector",
    "process_feature_names",
    "build_feature_schema",
    "vectorize_features",
    "extract_process_records",
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
    "summarize_process_behavior",
    "iter_evidence",
    "iter_high_risk_evidence",
    "iter_processes",
    "iter_combinations",
    "iter_analyses",
    "analyze",
    "parse",
    "extract",
]
