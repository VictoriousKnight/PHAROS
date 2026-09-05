"""
Static dynamic-execution capability extraction.

This module detects indicators of runtime/dynamic code execution in source
text, documents, extracted strings, macro source, scripts, configuration
data, logs, and other analysis artifacts.

The module is intentionally STATIC ONLY.

It does not:
    - execute code
    - evaluate expressions
    - invoke COM
    - invoke VBA
    - launch processes
    - load DLLs/shared libraries
    - perform network access
    - resolve URLs
    - decode and execute payloads
    - write extracted payloads to disk
    - modify the host system

The goal is to identify evidence that a sample contains mechanisms capable of
performing dynamic execution, such as:

    VBA Execute / Eval / Application.Run
    PowerShell Invoke-Expression / iex
    PowerShell dynamic invocation
    PowerShell reflection and assembly loading
    JavaScript eval / Function constructors
    VBScript Execute / ExecuteGlobal / Eval
    WScript.Shell execution
    Shell / command interpreter invocation
    COM-based execution
    .NET reflection
    dynamic method invocation
    script-host execution
    macro execution
    embedded script execution
    expression evaluation
    runtime code generation
    memory-based execution indicators
    shellcode/payload execution indicators
    encoded-content followed by execution
    dynamically constructed commands

This module does NOT claim that every dynamic-execution indicator is
malicious. Dynamic execution is a capability. Context, combinations, and
other extraction modules should be used to determine risk.

Evidence flow:

    source text
        |
        v
    static indicators
        |
        v
    capability evidence
        |
        v
    capability combinations
        |
        v
    stable feature vector
        |
        +--> feature_pipeline.py
        +--> ML dataset / prediction
        +--> CDR policy
        +--> reporting
"""

from __future__ import annotations

import hashlib
import math
import os
import re
from collections import Counter
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable, Iterator, Mapping, Optional, Sequence


# =============================================================================
# RESOURCE LIMITS
# =============================================================================

MAX_SOURCE_SIZE = 25 * 1024 * 1024
MAX_TEXT_CHARS = 25 * 1024 * 1024
MAX_FIELD_TEXT = 100_000
MAX_NESTING_DEPTH = 12

MAX_EVIDENCE_ITEMS = 20_000
MAX_RECORDS = 10_000
MAX_INDICATORS = 10_000
MAX_MATCHES_PER_RULE = 5_000
MAX_LINES = 500_000

MAX_INDICATOR_LENGTH = 256
MAX_EVIDENCE_LENGTH = 4_096
MAX_SOURCE_NAME_LENGTH = 512

MAX_ENTROPY_TEXT = 32_768
MAX_DYNAMIC_EXPRESSION_LENGTH = 8_192


# =============================================================================
# TAXONOMY
# =============================================================================

DYNAMIC_EXECUTION_CATEGORIES = (
    "dynamic_evaluation",
    "dynamic_invocation",
    "expression_evaluation",
    "runtime_code_generation",
    "runtime_script_execution",
    "macro_execution",
    "script_host_execution",
    "command_execution",
    "shell_execution",
    "com_execution",
    "reflection",
    "assembly_loading",
    "module_loading",
    "delegate_execution",
    "method_invocation",
    "function_construction",
    "string_to_code",
    "encoded_execution",
    "decoded_execution",
    "memory_execution",
    "shellcode_execution",
    "payload_execution",
    "download_execute",
    "temporary_execution",
    "scheduled_execution",
    "embedded_execution",
    "obfuscated_execution",
    "indirect_execution",
    "execution_chain",
)

SEVERITIES = (
    "low",
    "medium",
    "high",
    "critical",
)


# =============================================================================
# DATACLASSES
# =============================================================================


@dataclass(frozen=True)
class DynamicExecutionPattern:
    """
    Static detection rule for a dynamic-execution capability.
    """

    name: str
    category: str
    pattern: str
    severity: str = "medium"
    confidence: float = 0.80
    operation: str = "execute"
    description: str = ""
    families: tuple[str, ...] = ()


@dataclass(frozen=True)
class DynamicExecutionEvidence:
    """
    One piece of static evidence supporting a dynamic-execution capability.
    """

    category: str
    indicator: str
    evidence: str
    source: str = "source"
    line_number: Optional[int] = None
    field: Optional[str] = None
    procedure: Optional[str] = None
    operation: str = "execute"
    target: Optional[str] = None
    platform: Optional[str] = None
    language: Optional[str] = None
    confidence: float = 1.0
    severity: str = "medium"


@dataclass(frozen=True)
class DynamicExecutionRecord:
    """
    Normalized dynamic-execution capability record.
    """

    indicator: str
    category: str
    operation: str
    target: Optional[str]
    language: Optional[str]
    platform: Optional[str]
    severity: str
    confidence: float
    evidence: str
    line_number: Optional[int] = None
    procedure: Optional[str] = None


@dataclass(frozen=True)
class DynamicExecutionCombination:
    """
    Higher-level relationship between dynamic-execution indicators.
    """

    name: str
    present: bool
    required_categories: tuple[str, ...]
    explanation: str


@dataclass
class DynamicExecutionAnalysis:
    """
    Complete static dynamic-execution capability analysis.
    """

    source_hash: str
    source_size: int

    records: list[DynamicExecutionRecord] = field(default_factory=list)
    evidence: list[DynamicExecutionEvidence] = field(default_factory=list)

    indicators: list[str] = field(default_factory=list)
    categories: list[str] = field(default_factory=list)
    combinations: list[DynamicExecutionCombination] = field(default_factory=list)

    languages: list[str] = field(default_factory=list)
    platforms: list[str] = field(default_factory=list)
    operations: list[str] = field(default_factory=list)

    feature_vector: dict[str, float] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)


# =============================================================================
# INTERNAL CONSTANTS
# =============================================================================

_LANGUAGE_ALIASES = {
    "vba": "vba",
    "visualbasic": "vb",
    "visual basic": "vb",
    "vbscript": "vbscript",
    "vbs": "vbscript",
    "javascript": "javascript",
    "jscript": "javascript",
    "javascriptcore": "javascript",
    "js": "javascript",
    "powershell": "powershell",
    "pwsh": "powershell",
    "ps1": "powershell",
    "batch": "batch",
    "cmd": "batch",
    "command": "batch",
    "shell": "shell",
    "bash": "shell",
    "sh": "shell",
    "zsh": "shell",
    "python": "python",
    "py": "python",
    "generic": "generic",
    "unknown": "generic",
}

_WINDOWS_INDICATORS = (
    "wscript.shell",
    "shell.application",
    "scripting.filesystemobject",
    "powershell",
    "cmd.exe",
    "rundll32",
    "regsvr32",
    "mshta",
    "wscript",
    "cscript",
    "winexec",
    "shellexecute",
    "createprocess",
    "loadlibrary",
    "loadpackagedlibrary",
    "amsi",
    "ntdll",
    "kernel32",
    "advapi32",
)

_CROSS_PLATFORM_INDICATORS = (
    "eval(",
    "exec(",
    "compile(",
    "system(",
    "popen(",
    "subprocess",
    "child_process",
    "runtime.exec",
)

_EXECUTION_TERMS = frozenset(
    {
        "execute",
        "execution",
        "invoke",
        "eval",
        "run",
        "shell",
        "command",
        "script",
        "macro",
        "load",
        "reflect",
        "reflection",
        "assembly",
        "delegate",
        "dynamic",
        "payload",
        "shellcode",
    }
)


# =============================================================================
# REGEX HELPERS
# =============================================================================

# The patterns are deliberately context-sensitive where practical.
# Generic words such as "run" are not sufficient on their own.

_PATTERNS: tuple[DynamicExecutionPattern, ...] = (
    # -------------------------------------------------------------------------
    # VBA / VB
    # -------------------------------------------------------------------------
    DynamicExecutionPattern(
        "vba_execute",
        "dynamic_evaluation",
        r"(?i)\b(?:Application\.)?(?:Execute|ExecuteExcel4Macro)\s*\(",
        "high",
        0.96,
        "execute",
        "VBA dynamically executes a command or macro expression.",
        ("vba", "vb"),
    ),
    DynamicExecutionPattern(
        "vba_eval",
        "expression_evaluation",
        r"(?i)\b(?:VBA\.)?Eval\s*\(",
        "high",
        0.94,
        "execute",
        "VBA evaluates a runtime expression.",
        ("vba", "vb"),
    ),
    DynamicExecutionPattern(
        "vba_application_run",
        "dynamic_invocation",
        r"(?i)\bApplication\s*\.\s*Run\s*\(",
        "high",
        0.95,
        "invoke",
        "VBA invokes a macro/function dynamically.",
        ("vba", "vb"),
    ),
    DynamicExecutionPattern(
        "vba_run_method",
        "dynamic_invocation",
        r"(?i)\b(?:Application|Excel|Word|Access|PowerPoint)\s*\.\s*Run\s*\(",
        "high",
        0.93,
        "invoke",
        "Office automation dynamically invokes a procedure.",
        ("vba", "vb"),
    ),
    DynamicExecutionPattern(
        "vba_callbyname",
        "dynamic_invocation",
        r"(?i)\bCallByName\s*\(",
        "high",
        0.95,
        "invoke",
        "VBA resolves and invokes a method/property dynamically.",
        ("vba", "vb"),
    ),
    DynamicExecutionPattern(
        "vba_execute_global",
        "runtime_script_execution",
        r"(?i)\bExecuteGlobal\s+",
        "high",
        0.97,
        "execute",
        "VB-family code executes dynamically constructed global code.",
        ("vba", "vb", "vbscript"),
    ),
    DynamicExecutionPattern(
        "vba_execute_statement",
        "runtime_script_execution",
        r"(?i)(?<![A-Za-z])Execute\s+(?:Global\s+)?[A-Za-z_][A-Za-z0-9_]*",
        "high",
        0.90,
        "execute",
        "VB-family Execute statement dynamically evaluates code.",
        ("vba", "vb", "vbscript"),
    ),
    DynamicExecutionPattern(
        "vba_shell",
        "shell_execution",
        r"(?i)\b(?:VBA\.)?Shell\s*\(",
        "high",
        0.96,
        "execute",
        "VBA invokes a shell/process through the Shell function.",
        ("vba", "vb"),
    ),
    DynamicExecutionPattern(
        "vba_wscript_shell",
        "script_host_execution",
        r"(?i)\bCreateObject\s*\(\s*['\"]WScript\.Shell['\"]\s*\)",
        "high",
        0.97,
        "execute",
        "VBA/VBScript creates WScript.Shell for command execution.",
        ("vba", "vb", "vbscript"),
    ),
    DynamicExecutionPattern(
        "vba_shell_run",
        "shell_execution",
        r"(?i)\bWScript\.Shell\b[\s\S]{0,300}\.(?:Run|Exec)\s+",
        "high",
        0.96,
        "execute",
        "WScript.Shell is used to execute a command.",
        ("vba", "vb", "vbscript"),
    ),
    DynamicExecutionPattern(
        "vba_getobject_com",
        "com_execution",
        r"(?i)\b(?:CreateObject|GetObject)\s*\(",
        "medium",
        0.78,
        "invoke",
        "COM automation object resolution may enable dynamic execution.",
        ("vba", "vb", "vbscript"),
    ),
    DynamicExecutionPattern(
        "vba_ole_object",
        "com_execution",
        r"(?i)\b(?:OLEObject|OLEObjects|Object\s*\.)",
        "medium",
        0.72,
        "invoke",
        "Office OLE automation can provide indirect execution capabilities.",
        ("vba", "vb"),
    ),
    # -------------------------------------------------------------------------
    # PowerShell
    # -------------------------------------------------------------------------
    DynamicExecutionPattern(
        "powershell_iex",
        "dynamic_evaluation",
        r"(?i)(?:\bIEX\b|\bInvoke-Expression\b)",
        "critical",
        0.99,
        "execute",
        "PowerShell dynamically evaluates supplied content as code.",
        ("powershell",),
    ),
    DynamicExecutionPattern(
        "powershell_invoke_command",
        "dynamic_invocation",
        r"(?i)\b(?:Invoke-Command|Invoke-Item)\b",
        "high",
        0.89,
        "invoke",
        "PowerShell invokes a command or item dynamically.",
        ("powershell",),
    ),
    DynamicExecutionPattern(
        "powershell_scriptblock",
        "runtime_code_generation",
        r"(?i)\[scriptblock\]\s*::\s*Create\s*\(",
        "high",
        0.97,
        "execute",
        "PowerShell creates a ScriptBlock dynamically.",
        ("powershell",),
    ),
    DynamicExecutionPattern(
        "powershell_add_type",
        "runtime_code_generation",
        r"(?i)\bAdd-Type\b",
        "high",
        0.90,
        "compile",
        "PowerShell dynamically compiles or loads .NET type definitions.",
        ("powershell",),
    ),
    DynamicExecutionPattern(
        "powershell_reflection",
        "reflection",
        r"(?i)\.(?:GetType|GetMethod|GetField|GetProperty|Invoke|InvokeMember)\s*\(",
        "high",
        0.88,
        "reflect",
        "PowerShell/.NET reflection can dynamically resolve and invoke members.",
        ("powershell",),
    ),
    DynamicExecutionPattern(
        "powershell_reflection_assembly",
        "assembly_loading",
        r"(?i)\[(?:Reflection\.)?Assembly\]\s*::\s*(?:Load|LoadFrom|LoadFile|LoadWithPartialName)\s*\(",
        "high",
        0.98,
        "load",
        "PowerShell loads a .NET assembly dynamically.",
        ("powershell",),
    ),
    DynamicExecutionPattern(
        "powershell_type_gettype",
        "reflection",
        r"(?i)\[type\]\s*::\s*GetType\s*\(",
        "medium",
        0.85,
        "reflect",
        "PowerShell resolves a type dynamically.",
        ("powershell",),
    ),
    DynamicExecutionPattern(
        "powershell_method_invoke",
        "method_invocation",
        r"(?i)\.(?:Invoke|InvokeMember)\s*\(",
        "high",
        0.91,
        "invoke",
        "A dynamically resolved method is invoked.",
        ("powershell",),
    ),
    DynamicExecutionPattern(
        "powershell_encoded_command",
        "encoded_execution",
        r"(?i)(?:^|[\s/-])-(?:e|en|enc|enco|encod|encodedcommand)\b",
        "high",
        0.96,
        "execute",
        "PowerShell encoded-command execution is referenced.",
        ("powershell",),
    ),
    DynamicExecutionPattern(
        "powershell_command_variable",
        "indirect_execution",
        r"(?i)&\s*\(\s*\$[A-Za-z_][A-Za-z0-9_]*\s*\)",
        "high",
        0.90,
        "execute",
        "PowerShell invokes a command stored in a variable/expression.",
        ("powershell",),
    ),
    DynamicExecutionPattern(
        "powershell_call_operator",
        "dynamic_invocation",
        r"(?i)(?<!\w)&\s*(?:['\"]|\$[A-Za-z_])",
        "medium",
        0.82,
        "invoke",
        "PowerShell call operator invokes a dynamically selected command.",
        ("powershell",),
    ),
    DynamicExecutionPattern(
        "powershell_start_process",
        "command_execution",
        r"(?i)\bStart-Process\b",
        "medium",
        0.90,
        "execute",
        "PowerShell starts another process.",
        ("powershell",),
    ),
    DynamicExecutionPattern(
        "powershell_process_start",
        "command_execution",
        r"(?i)\[(?:System\.)?Diagnostics\.Process\]\s*::\s*Start\s*\(",
        "high",
        0.96,
        "execute",
        ".NET Process.Start is referenced from PowerShell.",
        ("powershell",),
    ),
    # -------------------------------------------------------------------------
    # JavaScript / JScript
    # -------------------------------------------------------------------------
    DynamicExecutionPattern(
        "javascript_eval",
        "dynamic_evaluation",
        r"(?i)(?<![\w.])eval\s*\(",
        "high",
        0.96,
        "execute",
        "JavaScript dynamically evaluates a string as code.",
        ("javascript",),
    ),
    DynamicExecutionPattern(
        "javascript_function_constructor",
        "function_construction",
        r"(?i)\bnew\s+Function\s*\(",
        "high",
        0.96,
        "execute",
        "JavaScript constructs a function dynamically.",
        ("javascript",),
    ),
    DynamicExecutionPattern(
        "javascript_function_call",
        "function_construction",
        r"(?i)\bFunction\s*\(\s*['\"]",
        "high",
        0.91,
        "execute",
        "JavaScript dynamically constructs executable code.",
        ("javascript",),
    ),
    DynamicExecutionPattern(
        "javascript_settimeout_string",
        "dynamic_evaluation",
        r"(?i)\bsetTimeout\s*\(\s*['\"]",
        "high",
        0.92,
        "execute",
        "JavaScript schedules dynamically evaluated code.",
        ("javascript",),
    ),
    DynamicExecutionPattern(
        "javascript_setinterval_string",
        "dynamic_evaluation",
        r"(?i)\bsetInterval\s*\(\s*['\"]",
        "high",
        0.92,
        "execute",
        "JavaScript schedules dynamically evaluated code.",
        ("javascript",),
    ),
    DynamicExecutionPattern(
        "javascript_active_x",
        "com_execution",
        r"(?i)\bnew\s+ActiveXObject\s*\(",
        "high",
        0.96,
        "invoke",
        "JScript creates an ActiveX/COM object.",
        ("javascript",),
    ),
    DynamicExecutionPattern(
        "javascript_wscript_shell",
        "script_host_execution",
        r"(?i)\b(?:WScript\.CreateObject|new\s+ActiveXObject)\s*\(\s*['\"]WScript\.Shell",
        "critical",
        0.98,
        "execute",
        "JScript creates WScript.Shell for command execution.",
        ("javascript",),
    ),
    DynamicExecutionPattern(
        "javascript_wsh_run",
        "shell_execution",
        r"(?i)\b(?:\.Run|\.Exec)\s*\(",
        "medium",
        0.76,
        "execute",
        "A script-host object may be invoking a command.",
        ("javascript",),
    ),
    # -------------------------------------------------------------------------
    # Python / generic scripting
    # -------------------------------------------------------------------------
    DynamicExecutionPattern(
        "python_eval",
        "dynamic_evaluation",
        r"(?i)(?<![\w.])eval\s*\(",
        "high",
        0.94,
        "execute",
        "Python dynamically evaluates an expression.",
        ("python",),
    ),
    DynamicExecutionPattern(
        "python_exec",
        "runtime_script_execution",
        r"(?i)(?<![\w.])exec\s*\(",
        "high",
        0.97,
        "execute",
        "Python dynamically executes code.",
        ("python",),
    ),
    DynamicExecutionPattern(
        "python_compile",
        "runtime_code_generation",
        r"(?i)(?<![\w.])compile\s*\(",
        "medium",
        0.88,
        "compile",
        "Python compiles source into an executable code object.",
        ("python",),
    ),
    DynamicExecutionPattern(
        "python_importlib",
        "module_loading",
        r"(?i)\bimportlib\.(?:import_module|util\.spec_from_file_location)\s*\(",
        "medium",
        0.88,
        "load",
        "Python dynamically resolves or loads a module.",
        ("python",),
    ),
    DynamicExecutionPattern(
        "python_subprocess",
        "command_execution",
        r"(?i)\bsubprocess\.(?:Popen|run|call|check_call|check_output)\s*\(",
        "high",
        0.96,
        "execute",
        "Python invokes an operating-system process.",
        ("python",),
    ),
    DynamicExecutionPattern(
        "python_os_system",
        "shell_execution",
        r"(?i)\bos\.system\s*\(",
        "high",
        0.96,
        "execute",
        "Python invokes a shell command.",
        ("python",),
    ),
    DynamicExecutionPattern(
        "python_os_popen",
        "shell_execution",
        r"(?i)\bos\.popen\s*\(",
        "high",
        0.94,
        "execute",
        "Python opens a shell command pipeline.",
        ("python",),
    ),
    # -------------------------------------------------------------------------
    # Generic shell / command execution
    # -------------------------------------------------------------------------
    DynamicExecutionPattern(
        "generic_cmd",
        "command_execution",
        r"(?i)\b(?:cmd|cmd\.exe)\s+(?:/c|/k)\b",
        "high",
        0.96,
        "execute",
        "Windows command interpreter execution is referenced.",
        ("batch", "powershell", "vba", "vbscript", "javascript", "generic"),
    ),
    DynamicExecutionPattern(
        "generic_powershell",
        "command_execution",
        r"(?i)\b(?:powershell|pwsh)(?:\.exe)?\b(?:\s+-(?:noexit|command|c|encodedcommand|enc|e)\b)?",
        "medium",
        0.86,
        "execute",
        "PowerShell command execution is referenced.",
        ("batch", "vba", "vbscript", "javascript", "generic"),
    ),
    DynamicExecutionPattern(
        "generic_wscript",
        "script_host_execution",
        r"(?i)\b(?:wscript|cscript)(?:\.exe)?\b",
        "high",
        0.92,
        "execute",
        "Windows Script Host execution is referenced.",
        ("batch", "generic"),
    ),
    DynamicExecutionPattern(
        "generic_mshta",
        "script_host_execution",
        r"(?i)\bmshta(?:\.exe)?\b",
        "high",
        0.96,
        "execute",
        "MSHTA script-host execution is referenced.",
        ("batch", "generic"),
    ),
    DynamicExecutionPattern(
        "generic_rundll32",
        "module_loading",
        r"(?i)\brundll32(?:\.exe)?\b",
        "high",
        0.96,
        "execute",
        "Rundll32 is used as a signed executable proxy for DLL execution.",
        ("batch", "generic"),
    ),
    DynamicExecutionPattern(
        "generic_regsvr32",
        "module_loading",
        r"(?i)\bregsvr32(?:\.exe)?\b",
        "high",
        0.96,
        "execute",
        "Regsvr32 is referenced for DLL/COM registration execution.",
        ("batch", "generic"),
    ),
    DynamicExecutionPattern(
        "generic_shell_execute",
        "shell_execution",
        r"(?i)\b(?:ShellExecute|ShellExecuteEx|WinExec|CreateProcess|CreateProcessW|CreateProcessA)\s*\(",
        "high",
        0.96,
        "execute",
        "A native process/shell execution API is referenced.",
        ("vba", "vb", "generic"),
    ),
    # -------------------------------------------------------------------------
    # .NET / reflection
    # -------------------------------------------------------------------------
    DynamicExecutionPattern(
        "dotnet_reflection_invoke",
        "reflection",
        r"(?i)\b(?:GetMethod|GetField|GetProperty|Invoke|InvokeMember|CreateDelegate)\s*\(",
        "medium",
        0.86,
        "reflect",
        ".NET reflection can resolve and invoke runtime members.",
        ("powershell", "generic"),
    ),
    DynamicExecutionPattern(
        "dotnet_assembly_load",
        "assembly_loading",
        r"(?i)\b(?:Assembly\.)?Load(?:From|File|WithPartialName)?\s*\(",
        "high",
        0.92,
        "load",
        ".NET assembly loading is referenced.",
        ("powershell", "generic"),
    ),
    DynamicExecutionPattern(
        "dotnet_activator",
        "dynamic_invocation",
        r"(?i)\bActivator\s*\.\s*(?:CreateInstance|CreateComInstanceFrom)\s*\(",
        "high",
        0.93,
        "invoke",
        ".NET dynamically creates an object or COM instance.",
        ("powershell", "generic"),
    ),
    DynamicExecutionPattern(
        "dotnet_delegate",
        "delegate_execution",
        r"(?i)\b(?:Delegate|DynamicMethod|CreateDelegate)\b",
        "medium",
        0.82,
        "invoke",
        "Runtime delegate/dynamic method mechanisms are referenced.",
        ("powershell", "generic"),
    ),
    # -------------------------------------------------------------------------
    # COM / automation
    # -------------------------------------------------------------------------
    DynamicExecutionPattern(
        "com_createobject",
        "com_execution",
        r"(?i)\b(?:CreateObject|GetObject)\s*\(\s*['\"][A-Za-z0-9_.-]+['\"]",
        "medium",
        0.86,
        "invoke",
        "COM automation object creation is referenced.",
        ("vba", "vb", "vbscript", "generic"),
    ),
    DynamicExecutionPattern(
        "com_automation_shell",
        "com_execution",
        r"(?i)\b(?:WScript\.Shell|Shell\.Application|Scripting\.FileSystemObject)\b",
        "medium",
        0.86,
        "invoke",
        "Windows scripting/automation COM objects are referenced.",
        ("vba", "vb", "vbscript", "javascript", "generic"),
    ),
    DynamicExecutionPattern(
        "com_application_dispatch",
        "dynamic_invocation",
        r"(?i)\b(?:Dispatch|DispatchEx|GetObject|CreateObject)\s*\(",
        "medium",
        0.84,
        "invoke",
        "Automation dispatch may dynamically resolve executable objects.",
        ("generic",),
    ),
    # -------------------------------------------------------------------------
    # Memory execution / payload execution
    # -------------------------------------------------------------------------
    DynamicExecutionPattern(
        "virtualalloc",
        "memory_execution",
        r"(?i)\b(?:VirtualAlloc|VirtualAllocEx|NtAllocateVirtualMemory)\b",
        "high",
        0.94,
        "allocate",
        "Executable-capable memory allocation API is referenced.",
        ("vba", "generic"),
    ),
    DynamicExecutionPattern(
        "virtualprotect",
        "memory_execution",
        r"(?i)\b(?:VirtualProtect|VirtualProtectEx|NtProtectVirtualMemory)\b",
        "high",
        0.94,
        "modify",
        "Memory protection modification is referenced.",
        ("vba", "generic"),
    ),
    DynamicExecutionPattern(
        "write_process_memory",
        "memory_execution",
        r"(?i)\b(?:WriteProcessMemory|NtWriteVirtualMemory)\b",
        "high",
        0.97,
        "write",
        "Memory writing into a process is referenced.",
        ("vba", "generic"),
    ),
    DynamicExecutionPattern(
        "create_remote_thread",
        "memory_execution",
        r"(?i)\b(?:CreateRemoteThread|CreateRemoteThreadEx|NtCreateThreadEx)\b",
        "critical",
        0.98,
        "execute",
        "Remote thread creation is referenced.",
        ("vba", "generic"),
    ),
    DynamicExecutionPattern(
        "shellcode_reference",
        "shellcode_execution",
        r"(?i)\b(?:shellcode|shell[\s_-]?code|opcode|opcodes|raw\s+bytes)\b",
        "medium",
        0.82,
        "execute",
        "Text references shellcode or raw executable bytes.",
        ("generic",),
    ),
    DynamicExecutionPattern(
        "memory_to_thread_chain",
        "payload_execution",
        r"(?is)\b(?:VirtualAlloc|VirtualProtect|WriteProcessMemory)[\s\S]{0,1200}\b(?:CreateThread|CreateRemoteThread|NtCreateThreadEx)\b",
        "critical",
        0.98,
        "execute",
        "Memory allocation/protection/writing is followed by thread creation.",
        ("vba", "generic"),
    ),
    # -------------------------------------------------------------------------
    # Encoded / decoded execution
    # -------------------------------------------------------------------------
    DynamicExecutionPattern(
        "powershell_from_base64",
        "encoded_execution",
        r"(?i)\b(?:FromBase64String|Convert\.FromBase64String)\s*\(",
        "high",
        0.93,
        "decode",
        "Base64 content is decoded through a runtime API.",
        ("powershell", "generic"),
    ),
    DynamicExecutionPattern(
        "generic_base64_decode",
        "decoded_execution",
        r"(?i)\b(?:base64|frombase64string|b64decode|decode64)\b",
        "low",
        0.72,
        "decode",
        "Base64 decoding capability is referenced.",
        ("generic",),
    ),
    DynamicExecutionPattern(
        "encoded_then_eval",
        "encoded_execution",
        r"(?is)\b(?:FromBase64String|b64decode|base64)[\s\S]{0,1200}\b(?:eval|exec|IEX|Invoke-Expression|Execute)\b",
        "critical",
        0.98,
        "execute",
        "Encoded content is associated with dynamic evaluation/execution.",
        ("powershell", "python", "vba", "vbscript", "javascript", "generic"),
    ),
    DynamicExecutionPattern(
        "decode_then_shell",
        "encoded_execution",
        r"(?is)\b(?:FromBase64String|b64decode|base64)[\s\S]{0,1200}\b(?:Shell|cmd\.exe|powershell|wscript|cscript|mshta)\b",
        "high",
        0.96,
        "execute",
        "Decoded content is associated with shell/script execution.",
        ("powershell", "python", "vba", "vbscript", "generic"),
    ),
    # -------------------------------------------------------------------------
    # Indirect/dynamically constructed commands
    # -------------------------------------------------------------------------
    DynamicExecutionPattern(
        "string_concat_execution",
        "string_to_code",
        r"(?is)(?:Execute|Eval|IEX|Invoke-Expression|exec|eval)\s*\(\s*(?:[A-Za-z_][A-Za-z0-9_]*\s*\+\s*)+",
        "high",
        0.91,
        "execute",
        "Dynamic execution receives a concatenated expression.",
        ("vba", "vbscript", "powershell", "javascript", "python", "generic"),
    ),
    DynamicExecutionPattern(
        "character_code_execution",
        "obfuscated_execution",
        r"(?i)\b(?:Chr|ChrW|Char|FromCharCode|fromCharCode)\s*\(",
        "medium",
        0.82,
        "construct",
        "Character-code conversion may construct executable strings.",
        ("vba", "vb", "vbscript", "javascript", "generic"),
    ),
    DynamicExecutionPattern(
        "replace_construct_execution",
        "obfuscated_execution",
        r"(?i)\b(?:Replace|replace|Substitute)\s*\(",
        "low",
        0.68,
        "construct",
        "String replacement may participate in dynamic code construction.",
        ("vba", "vb", "vbscript", "powershell", "javascript", "generic"),
    ),
    DynamicExecutionPattern(
        "reverse_construct_execution",
        "obfuscated_execution",
        r"(?i)\b(?:Reverse|StrReverse|Array\.Reverse|reverse)\s*\(",
        "medium",
        0.76,
        "construct",
        "String/array reversal may be used to reconstruct executable content.",
        ("vba", "vb", "vbscript", "powershell", "javascript", "generic"),
    ),
)


# =============================================================================
# GENERAL HELPERS
# =============================================================================


def _clamp(value: float, low: float = 0.0, high: float = 1.0) -> float:
    return max(low, min(high, float(value)))


def _severity_rank(value: str) -> int:
    try:
        return SEVERITIES.index(value.lower())
    except ValueError:
        return 0


def _max_severity(values: Iterable[str]) -> str:
    best = "low"
    rank = -1

    for value in values:
        current = _severity_rank(value)
        if current > rank:
            rank = current
            best = value

    return best


def _safe_text(
    value: Any,
    max_length: int = MAX_FIELD_TEXT,
) -> str:
    if value is None:
        return ""

    if isinstance(value, bytes):
        return value[:max_length].decode(
            "utf-8",
            errors="replace",
        )

    if isinstance(value, bytearray):
        return bytes(value[:max_length]).decode(
            "utf-8",
            errors="replace",
        )

    if isinstance(value, str):
        return value[:max_length]

    try:
        return str(value)[:max_length]
    except Exception:
        return ""


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _entropy(text: str) -> float:
    if not text:
        return 0.0

    counts = Counter(text)
    length = len(text)

    result = 0.0

    for count in counts.values():
        probability = count / length
        result -= probability * math.log2(probability)

    return result


def _normalize_language(value: Any) -> str:
    text = _safe_text(value, 128).strip().lower()

    if not text:
        return "generic"

    return _LANGUAGE_ALIASES.get(text, text)


def _infer_language(
    text: str,
    source_type: Optional[str] = None,
) -> str:
    if source_type:
        normalized = _normalize_language(source_type)

        if normalized != "generic":
            return normalized

    lower = text[:MAX_TEXT_CHARS].lower()

    if any(
        token in lower
        for token in (
            "sub auto_open()",
            "sub document_open()",
            "sub workbook_open()",
            "declare ptrsafe",
            "createobject(",
            "application.run",
            "executeexcel4macro",
        )
    ):
        return "vba"

    if any(
        token in lower
        for token in (
            "wscript.shell",
            "executeglobal",
            "on error resume next",
            "dim ",
        )
    ):
        return "vbscript"

    if any(
        token in lower
        for token in (
            "invoke-expression",
            "powershell",
            "get-member",
            "[reflection.assembly]",
            "start-process",
            "$env:",
        )
    ):
        return "powershell"

    if any(
        token in lower
        for token in (
            "activexobject",
            "function(",
            "=>",
            "document.createelement",
            "eval(",
        )
    ):
        return "javascript"

    if any(
        token in lower
        for token in (
            "subprocess.",
            "os.system(",
            "import subprocess",
            "import os",
        )
    ):
        return "python"

    if re.search(
        r"(?im)^\s*(?:@echo\s+off|set\s+\w+=|if\s+exist|"
        r"for\s+%%|cmd(?:\.exe)?\s+/[ck])",
        text,
    ):
        return "batch"

    if re.search(
        r"(?im)^\s*(?:#!/bin/(?:ba)?sh|curl\s+|wget\s+|"
        r"chmod\s+|bash\s+-c\b|sh\s+-c\b)",
        text,
    ):
        return "shell"

    return "generic"


def _infer_platform(
    text: str,
    language: str,
) -> str:
    lower = text[:MAX_TEXT_CHARS].lower()

    if any(indicator in lower for indicator in _WINDOWS_INDICATORS):
        return "windows"

    if language in {
        "vba",
        "vb",
        "vbscript",
    }:
        return "windows"

    if any(
        token in lower
        for token in (
            "/bin/sh",
            "/bin/bash",
            "linux",
            "ubuntu",
            "debian",
            "systemd",
        )
    ):
        return "linux"

    if any(
        token in lower
        for token in (
            "darwin",
            "macos",
            "osascript",
        )
    ):
        return "macos"

    if language == "powershell":
        return "windows"

    return "cross_platform"


def _operation_for_indicator(
    category: str,
    indicator: str,
) -> str:
    indicator_lower = indicator.lower()

    if category in {
        "dynamic_evaluation",
        "expression_evaluation",
        "runtime_script_execution",
        "runtime_code_generation",
        "string_to_code",
        "encoded_execution",
        "decoded_execution",
        "payload_execution",
        "shellcode_execution",
    }:
        return "execute"

    if category in {
        "dynamic_invocation",
        "method_invocation",
        "delegate_execution",
        "com_execution",
    }:
        return "invoke"

    if category in {
        "assembly_loading",
        "module_loading",
    }:
        return "load"

    if category == "reflection":
        return "reflect"

    if category == "command_execution":
        return "execute"

    if category == "shell_execution":
        return "execute"

    if category == "obfuscated_execution":
        return "construct"

    if "decode" in indicator_lower:
        return "decode"

    return "execute"


def _extract_target(
    evidence: str,
    category: str,
) -> Optional[str]:
    """
    Extract a bounded human-readable target from evidence.

    This intentionally does not resolve or inspect the target.
    """
    text = evidence[:MAX_EVIDENCE_LENGTH]

    if category in {
        "assembly_loading",
        "module_loading",
    }:
        match = re.search(
            r"(?i)(?:loadfrom|loadfile|load)\s*\(\s*['\"]([^'\"]+)",
            text,
        )

        if match:
            return match.group(1)[:512]

    if category in {
        "shell_execution",
        "command_execution",
    }:
        match = re.search(
            r"(?i)(?:cmd(?:\.exe)?|powershell(?:\.exe)?|"
            r"wscript(?:\.exe)?|cscript(?:\.exe)?|mshta(?:\.exe)?)"
            r"(?:\s+[^;\r\n]{0,300})?",
            text,
        )

        if match:
            return match.group(0)[:512]

    return None


def _source_line(
    text: str,
    start_offset: int,
) -> int:
    return text.count("\n", 0, start_offset) + 1


# =============================================================================
# SOURCE NORMALIZATION
# =============================================================================


def _read_source(
    source: Any,
) -> tuple[str, int, str]:
    """
    Convert supported input into bounded text.

    Supported inputs include:
        str
        bytes
        bytearray
        pathlib.Path
        os.PathLike
        mappings
        sequences
        arbitrary objects with __dict__
    """
    if source is None:
        empty = ""
        return empty, 0, _sha256_text(empty)

    if isinstance(source, Path):
        try:
            size = source.stat().st_size

            if size > MAX_SOURCE_SIZE:
                raise ValueError("Source exceeds MAX_SOURCE_SIZE")

            data = source.read_bytes()

            return (
                data.decode("utf-8", errors="replace"),
                len(data),
                _sha256_bytes(data),
            )
        except OSError:
            return "", 0, _sha256_text("")

    if isinstance(source, os.PathLike):
        return _read_source(Path(source))

    if isinstance(source, bytes):
        data = source[:MAX_SOURCE_SIZE]

        return (
            data.decode("utf-8", errors="replace"),
            len(data),
            _sha256_bytes(data),
        )

    if isinstance(source, bytearray):
        data = bytes(source[:MAX_SOURCE_SIZE])

        return (
            data.decode("utf-8", errors="replace"),
            len(data),
            _sha256_bytes(data),
        )

    if isinstance(source, str):
        text = source[:MAX_TEXT_CHARS]

        return (
            text,
            len(source.encode("utf-8", errors="replace")),
            _sha256_text(text),
        )

    return _flatten_source(source)


def _flatten_source(
    source: Any,
) -> tuple[str, int, str]:
    """
    Safely flatten nested mappings/sequences/objects.
    """
    pieces: list[str] = []
    total_size = 0
    seen: set[int] = set()

    def visit(
        value: Any,
        depth: int,
        field_name: str = "",
    ) -> None:
        nonlocal total_size

        if depth > MAX_NESTING_DEPTH:
            return

        if len(pieces) >= MAX_EVIDENCE_ITEMS:
            return

        if value is None:
            return

        if isinstance(
            value,
            (str, bytes, bytearray, Path, os.PathLike),
        ):
            text = _safe_text(value)

            if field_name:
                pieces.append(f"{field_name}: {text}")
            else:
                pieces.append(text)

            total_size += len(
                text.encode(
                    "utf-8",
                    errors="replace",
                )
            )

            return

        object_id = id(value)

        if object_id in seen:
            return

        if isinstance(value, Mapping):
            seen.add(object_id)

            for key, item in value.items():
                visit(
                    item,
                    depth + 1,
                    _safe_text(key, 512),
                )

            return

        if isinstance(value, Sequence) and not isinstance(
            value,
            (str, bytes, bytearray),
        ):
            seen.add(object_id)

            for index, item in enumerate(value):
                visit(
                    item,
                    depth + 1,
                    str(index),
                )

            return

        if hasattr(value, "__dict__"):
            seen.add(object_id)

            try:
                attributes = vars(value)
            except Exception:
                attributes = {}

            if isinstance(attributes, Mapping):
                for key, item in attributes.items():
                    visit(
                        item,
                        depth + 1,
                        _safe_text(key, 512),
                    )

            return

        text = _safe_text(value)

        if text:
            pieces.append(text)

            total_size += len(
                text.encode(
                    "utf-8",
                    errors="replace",
                )
            )

    visit(source, 0)

    text = "\n".join(pieces)

    if len(text) > MAX_TEXT_CHARS:
        text = text[:MAX_TEXT_CHARS]

    return (
        text,
        min(total_size, MAX_SOURCE_SIZE),
        _sha256_text(text),
    )


# =============================================================================
# PATTERN MATCHING
# =============================================================================


def _pattern_applies(
    pattern: DynamicExecutionPattern,
    language: str,
) -> bool:
    if not pattern.families:
        return True

    if "generic" in pattern.families:
        return True

    return language in pattern.families


def _deduplicate_matches(
    matches: Iterable[re.Match[str]],
) -> list[re.Match[str]]:
    results: list[re.Match[str]] = []
    seen: set[tuple[int, int]] = set()

    for match in matches:
        key = (match.start(), match.end())

        if key in seen:
            continue

        seen.add(key)
        results.append(match)

        if len(results) >= MAX_MATCHES_PER_RULE:
            break

    return results


def _compile_pattern(
    expression: str,
) -> Optional[re.Pattern[str]]:
    try:
        return re.compile(expression)
    except re.error:
        return None


# =============================================================================
# PUBLIC INDICATOR EXTRACTION
# =============================================================================


def extract_dynamic_execution_indicators(
    source: Any,
    *,
    source_type: Optional[str] = None,
    max_indicators: int = MAX_INDICATORS,
) -> list[str]:
    """
    Extract unique dynamic-execution indicator names.

    This function performs no execution or dynamic resolution.
    """
    text, _, _ = _read_source(source)

    if not text:
        return []

    language = _infer_language(
        text,
        source_type,
    )

    indicators: list[str] = []
    seen: set[str] = set()

    for pattern in _PATTERNS:
        if len(indicators) >= max_indicators:
            break

        if not _pattern_applies(pattern, language):
            continue

        compiled = _compile_pattern(pattern.pattern)

        if compiled is None:
            continue

        if compiled.search(text) is None:
            continue

        if pattern.name in seen:
            continue

        seen.add(pattern.name)
        indicators.append(pattern.name)

    return indicators


def extract_dynamic_execution_evidence(
    source: Any,
    *,
    source_type: Optional[str] = None,
    source_name: Optional[str] = None,
    max_evidence: int = MAX_EVIDENCE_ITEMS,
) -> list[DynamicExecutionEvidence]:
    """
    Extract detailed static evidence for dynamic execution.
    """
    text, _, _ = _read_source(source)

    if not text:
        return []

    language = _infer_language(
        text,
        source_type,
    )

    platform = _infer_platform(
        text,
        language,
    )

    evidence: list[DynamicExecutionEvidence] = []
    seen: set[tuple[str, int, str]] = set()

    for pattern in _PATTERNS:
        if len(evidence) >= max_evidence:
            break

        if not _pattern_applies(pattern, language):
            continue

        compiled = _compile_pattern(pattern.pattern)

        if compiled is None:
            continue

        matches = _deduplicate_matches(compiled.finditer(text))

        for match in matches:
            if len(evidence) >= max_evidence:
                break

            start = match.start()
            line_number = _source_line(
                text,
                start,
            )

            snippet_start = max(
                0,
                start - 160,
            )

            snippet_end = min(
                len(text),
                match.end() + 320,
            )

            snippet = text[snippet_start:snippet_end]

            snippet = snippet.replace(
                "\x00",
                " ",
            )

            snippet = snippet[:MAX_EVIDENCE_LENGTH]

            key = (
                pattern.name,
                line_number,
                snippet[:256],
            )

            if key in seen:
                continue

            seen.add(key)

            confidence = _clamp(pattern.confidence)

            severity = pattern.severity

            target = _extract_target(
                snippet,
                pattern.category,
            )

            evidence.append(
                DynamicExecutionEvidence(
                    category=pattern.category,
                    indicator=pattern.name,
                    evidence=snippet,
                    source=(
                        source_name[:MAX_SOURCE_NAME_LENGTH]
                        if source_name
                        else "source"
                    ),
                    line_number=line_number,
                    field=None,
                    procedure=None,
                    operation=pattern.operation,
                    target=target,
                    platform=platform,
                    language=language,
                    confidence=confidence,
                    severity=severity,
                )
            )

    return evidence


# =============================================================================
# RECORD CONSTRUCTION
# =============================================================================


def _build_records(
    evidence: Sequence[DynamicExecutionEvidence],
) -> list[DynamicExecutionRecord]:
    records: list[DynamicExecutionRecord] = []

    seen: set[
        tuple[
            str,
            str,
            Optional[int],
            Optional[str],
        ]
    ] = set()

    for item in evidence:
        if len(records) >= MAX_RECORDS:
            break

        key = (
            item.indicator,
            item.category,
            item.line_number,
            item.evidence[:256],
        )

        if key in seen:
            continue

        seen.add(key)

        records.append(
            DynamicExecutionRecord(
                indicator=item.indicator,
                category=item.category,
                operation=item.operation,
                target=item.target,
                language=item.language,
                platform=item.platform,
                severity=item.severity,
                confidence=item.confidence,
                evidence=item.evidence,
                line_number=item.line_number,
                procedure=item.procedure,
            )
        )

    return records


# =============================================================================
# COMBINATION DERIVATION
# =============================================================================


def _derive_combinations(
    records: Sequence[DynamicExecutionRecord],
) -> list[DynamicExecutionCombination]:
    categories = {record.category for record in records}

    indicators = {record.indicator for record in records}

    combinations: list[DynamicExecutionCombination] = []

    def add(
        name: str,
        required_categories: tuple[str, ...],
        explanation: str,
        present: bool,
    ) -> None:
        combinations.append(
            DynamicExecutionCombination(
                name=name,
                present=present,
                required_categories=required_categories,
                explanation=explanation,
            )
        )

    add(
        "dynamic_evaluation",
        ("dynamic_evaluation",),
        "The sample contains an explicit runtime expression/code evaluation mechanism.",
        "dynamic_evaluation" in categories,
    )

    add(
        "dynamic_invocation_chain",
        (
            "dynamic_invocation",
            "method_invocation",
        ),
        "Dynamic resolution and method invocation occur together.",
        ("dynamic_invocation" in categories and "method_invocation" in categories),
    )

    add(
        "script_host_execution",
        (
            "script_host_execution",
            "shell_execution",
        ),
        "A script host is combined with shell execution capability.",
        ("script_host_execution" in categories and "shell_execution" in categories),
    )

    add(
        "com_to_execution",
        (
            "com_execution",
            "command_execution",
        ),
        "COM automation is combined with command execution.",
        ("com_execution" in categories and "command_execution" in categories),
    )

    add(
        "reflection_to_execution",
        (
            "reflection",
            "method_invocation",
        ),
        "Reflection is combined with runtime method invocation.",
        ("reflection" in categories and "method_invocation" in categories),
    )

    add(
        "assembly_reflection_chain",
        (
            "assembly_loading",
            "reflection",
        ),
        "Runtime assembly loading is combined with reflection.",
        ("assembly_loading" in categories and "reflection" in categories),
    )

    add(
        "encoded_dynamic_execution",
        (
            "encoded_execution",
            "dynamic_evaluation",
        ),
        "Encoded or decoded content is associated with dynamic code evaluation.",
        ("encoded_execution" in categories and "dynamic_evaluation" in categories),
    )

    add(
        "decoded_shell_execution",
        (
            "decoded_execution",
            "shell_execution",
        ),
        "Decoded content is associated with shell execution.",
        ("decoded_execution" in categories and "shell_execution" in categories),
    )

    add(
        "memory_execution_chain",
        (
            "memory_execution",
            "payload_execution",
        ),
        "Memory manipulation is associated with execution of an in-memory payload.",
        ("memory_execution" in categories and "payload_execution" in categories),
    )

    add(
        "shellcode_execution_chain",
        (
            "shellcode_execution",
            "memory_execution",
        ),
        "Shellcode indicators occur together with memory-execution primitives.",
        ("shellcode_execution" in categories and "memory_execution" in categories),
    )

    add(
        "obfuscated_dynamic_execution",
        (
            "obfuscated_execution",
            "dynamic_evaluation",
        ),
        "Obfuscation/string construction is combined with dynamic evaluation.",
        ("obfuscated_execution" in categories and "dynamic_evaluation" in categories),
    )

    add(
        "download_execute",
        (
            "download_execute",
            "command_execution",
        ),
        "The source indicates remote/download behavior combined with command execution.",
        ("download_execute" in categories and "command_execution" in categories),
    )

    add(
        "indirect_execution",
        (
            "indirect_execution",
            "dynamic_invocation",
        ),
        "Execution is mediated through dynamically selected commands or members.",
        ("indirect_execution" in categories and "dynamic_invocation" in categories),
    )

    high_signal_categories = {
        "dynamic_evaluation",
        "runtime_code_generation",
        "encoded_execution",
        "memory_execution",
        "shellcode_execution",
        "payload_execution",
        "obfuscated_execution",
        "assembly_loading",
        "reflection",
    }

    add(
        "multi_layer_dynamic_execution",
        tuple(sorted(high_signal_categories)),
        "Multiple independent dynamic-execution capability layers are present.",
        sum(category in categories for category in high_signal_categories) >= 3,
    )

    # The set is intentionally computed so callers can use this function as
    # an extension point without changing the public result contract.
    _ = indicators

    return combinations


# =============================================================================
# FEATURE VECTOR
# =============================================================================


_BASE_FEATURE_NAMES = [
    "source_size",
    "record_count",
    "evidence_count",
    "indicator_count",
    "category_count",
    "combination_count",
    "high_count",
    "critical_count",
    "execute_count",
    "invoke_count",
    "load_count",
    "reflect_count",
    "decode_count",
    "construct_count",
    "compile_count",
    "allocate_count",
    "modify_count",
    "write_count",
    "vba_count",
    "vb_count",
    "vbscript_count",
    "powershell_count",
    "javascript_count",
    "python_count",
    "batch_count",
    "shell_count",
    "generic_count",
    "windows_count",
    "linux_count",
    "macos_count",
    "cross_platform_count",
    "unique_target_count",
    "average_confidence",
    "maximum_confidence",
    "evidence_entropy",
    "long_evidence_count",
    "very_long_evidence_count",
    "signal_score",
]


def _indicator_names() -> list[str]:
    return [pattern.name for pattern in _PATTERNS]


def _combination_names() -> list[str]:
    return [
        "dynamic_evaluation",
        "dynamic_invocation_chain",
        "script_host_execution",
        "com_to_execution",
        "reflection_to_execution",
        "assembly_reflection_chain",
        "encoded_dynamic_execution",
        "decoded_shell_execution",
        "memory_execution_chain",
        "shellcode_execution_chain",
        "obfuscated_dynamic_execution",
        "download_execute",
        "indirect_execution",
        "multi_layer_dynamic_execution",
    ]


def dynamic_execution_feature_names() -> list[str]:
    """
    Return the complete deterministic feature-vector schema.
    """
    names = list(_BASE_FEATURE_NAMES)

    names.extend(
        f"category_present__{category}" for category in DYNAMIC_EXECUTION_CATEGORIES
    )

    names.extend(
        f"category_count__{category}" for category in DYNAMIC_EXECUTION_CATEGORIES
    )

    indicators = list(dict.fromkeys(_indicator_names()))

    names.extend(f"indicator_present__{indicator}" for indicator in indicators)

    names.extend(f"indicator_count__{indicator}" for indicator in indicators)

    names.extend(f"combination_present__{name}" for name in _combination_names())

    return names


def _build_feature_vector(
    analysis: DynamicExecutionAnalysis,
) -> dict[str, float]:
    names = dynamic_execution_feature_names()

    features = {name: 0.0 for name in names}

    def set_value(
        name: str,
        value: float,
    ) -> None:
        if name in features:
            features[name] = float(value)

    records = analysis.records

    set_value(
        "source_size",
        analysis.source_size,
    )
    set_value(
        "record_count",
        len(records),
    )
    set_value(
        "evidence_count",
        len(analysis.evidence),
    )
    set_value(
        "indicator_count",
        len(analysis.indicators),
    )
    set_value(
        "category_count",
        len(analysis.categories),
    )
    set_value(
        "combination_count",
        len(analysis.combinations),
    )

    severity_counter = Counter(record.severity for record in records)

    set_value(
        "high_count",
        severity_counter["high"],
    )
    set_value(
        "critical_count",
        severity_counter["critical"],
    )

    operation_counter = Counter(record.operation for record in records)

    for operation in (
        "execute",
        "invoke",
        "load",
        "reflect",
        "decode",
        "construct",
        "compile",
        "allocate",
        "modify",
        "write",
    ):
        set_value(
            f"{operation}_count",
            operation_counter[operation],
        )

    language_counter = Counter(record.language or "generic" for record in records)

    for language in (
        "vba",
        "vb",
        "vbscript",
        "powershell",
        "javascript",
        "python",
        "batch",
        "shell",
        "generic",
    ):
        set_value(
            f"{language}_count",
            language_counter[language],
        )

    platform_counter = Counter(
        record.platform or "cross_platform" for record in records
    )

    for platform in (
        "windows",
        "linux",
        "macos",
        "cross_platform",
    ):
        set_value(
            f"{platform}_count",
            platform_counter[platform],
        )

    targets = {record.target for record in records if record.target}

    set_value(
        "unique_target_count",
        len(targets),
    )

    confidences = [record.confidence for record in records]

    if confidences:
        set_value(
            "average_confidence",
            sum(confidences) / len(confidences),
        )

        set_value(
            "maximum_confidence",
            max(confidences),
        )

    evidence_lengths = [len(item.evidence) for item in analysis.evidence]

    if evidence_lengths:
        bounded_evidence = "".join(
            item.evidence[:MAX_ENTROPY_TEXT] for item in analysis.evidence[:128]
        )

        set_value(
            "evidence_entropy",
            _entropy(bounded_evidence[:MAX_ENTROPY_TEXT]),
        )

        set_value(
            "long_evidence_count",
            sum(length >= 512 for length in evidence_lengths),
        )

        set_value(
            "very_long_evidence_count",
            sum(length >= 2048 for length in evidence_lengths),
        )

    category_counter = Counter(record.category for record in records)

    for category in DYNAMIC_EXECUTION_CATEGORIES:
        count = category_counter[category]

        set_value(
            f"category_present__{category}",
            int(count > 0),
        )

        set_value(
            f"category_count__{category}",
            count,
        )

    indicator_counter = Counter(record.indicator for record in records)

    for indicator in _indicator_names():
        count = indicator_counter[indicator]

        set_value(
            f"indicator_present__{indicator}",
            int(count > 0),
        )

        set_value(
            f"indicator_count__{indicator}",
            count,
        )

    for combination in analysis.combinations:
        set_value(
            f"combination_present__{combination.name}",
            int(combination.present),
        )

    # -------------------------------------------------------------------------
    # Capability signal score
    # -------------------------------------------------------------------------

    category_weights = {
        "dynamic_evaluation": 4.0,
        "dynamic_invocation": 2.5,
        "expression_evaluation": 3.5,
        "runtime_code_generation": 3.5,
        "runtime_script_execution": 4.0,
        "macro_execution": 3.5,
        "script_host_execution": 3.0,
        "command_execution": 3.0,
        "shell_execution": 3.0,
        "com_execution": 2.0,
        "reflection": 2.5,
        "assembly_loading": 3.0,
        "module_loading": 2.5,
        "delegate_execution": 2.5,
        "method_invocation": 2.0,
        "function_construction": 3.0,
        "string_to_code": 3.0,
        "encoded_execution": 4.0,
        "decoded_execution": 4.0,
        "memory_execution": 5.0,
        "shellcode_execution": 5.0,
        "payload_execution": 5.0,
        "download_execute": 5.0,
        "temporary_execution": 1.5,
        "scheduled_execution": 1.5,
        "embedded_execution": 2.5,
        "obfuscated_execution": 3.0,
        "indirect_execution": 2.5,
        "execution_chain": 4.0,
    }

    raw_score = 0.0

    for category, count in category_counter.items():
        weight = category_weights.get(
            category,
            0.0,
        )

        raw_score += weight * min(
            count,
            10,
        )

    for combination in analysis.combinations:
        if combination.present:
            raw_score += 3.0

    if severity_counter["critical"]:
        raw_score += 8.0

    elif severity_counter["high"]:
        raw_score += 3.0

    score = min(
        100.0,
        raw_score * 3.0,
    )

    set_value(
        "signal_score",
        round(score, 4),
    )

    return features


def vectorize_features(
    features: Mapping[str, object],
) -> list[float]:
    """
    Convert a feature mapping into the stable ordered feature vector.
    """
    return [
        float(
            features.get(
                name,
                0.0,
            )
            or 0.0
        )
        for name in dynamic_execution_feature_names()
    ]


def build_feature_schema() -> dict[str, Any]:
    """
    Return ML-oriented metadata for the dynamic-execution feature vector.
    """
    names = dynamic_execution_feature_names()

    return {
        "name": "dynamic_execution",
        "version": "1.0",
        "feature_count": len(names),
        "feature_names": names,
        "dtype": "float64",
        "ordering": "deterministic",
        "source": ("src/extraction/capabilities/" "dynamic_execution.py"),
        "static_only": True,
        "execution": False,
        "network_access": False,
        "notes": (
            "Features represent static capability evidence. "
            "Dynamic-execution capability does not by itself imply "
            "malicious intent."
        ),
    }


# =============================================================================
# MAIN ANALYSIS
# =============================================================================


def analyze_dynamic_execution(
    source: Any,
    *,
    source_type: Optional[str] = None,
    source_name: Optional[str] = None,
    max_evidence: int = MAX_EVIDENCE_ITEMS,
) -> DynamicExecutionAnalysis:
    """
    Perform bounded static dynamic-execution analysis.
    """
    text, source_size, source_hash = _read_source(source)

    if not text:
        analysis = DynamicExecutionAnalysis(
            source_hash=source_hash,
            source_size=source_size,
            metadata={
                "source_type": source_type,
                "source_name": source_name,
                "static_only": True,
                "execution": False,
                "network_access": False,
                "language": "generic",
                "platform": "cross_platform",
            },
        )

        analysis.feature_vector = _build_feature_vector(analysis)

        return analysis

    language = _infer_language(
        text,
        source_type,
    )

    platform = _infer_platform(
        text,
        language,
    )

    evidence = extract_dynamic_execution_evidence(
        text,
        source_type=language,
        source_name=source_name,
        max_evidence=max_evidence,
    )

    records = _build_records(evidence)

    indicators = sorted({record.indicator for record in records})

    categories = sorted({record.category for record in records})

    languages = sorted({record.language or "generic" for record in records})

    platforms = sorted({record.platform or platform for record in records})

    operations = sorted({record.operation for record in records})

    combinations = _derive_combinations(records)

    analysis = DynamicExecutionAnalysis(
        source_hash=source_hash,
        source_size=source_size,
        records=records,
        evidence=list(evidence),
        indicators=indicators,
        categories=categories,
        combinations=combinations,
        languages=languages,
        platforms=platforms,
        operations=operations,
        metadata={
            "source_type": source_type,
            "source_name": source_name,
            "inferred_language": language,
            "inferred_platform": platform,
            "static_only": True,
            "execution": False,
            "network_access": False,
            "max_evidence": max_evidence,
            "pattern_count": len(_PATTERNS),
        },
    )

    analysis.feature_vector = _build_feature_vector(analysis)

    return analysis


def analyze_dynamic_execution_capability(
    source: Any,
    **kwargs: Any,
) -> DynamicExecutionAnalysis:
    """
    Explicit capability-oriented alias.
    """
    return analyze_dynamic_execution(
        source,
        **kwargs,
    )


def analyze(
    source: Any,
    **kwargs: Any,
) -> DynamicExecutionAnalysis:
    """
    Generic analysis entry point.
    """
    return analyze_dynamic_execution(
        source,
        **kwargs,
    )


def parse_dynamic_execution(
    source: Any,
    **kwargs: Any,
) -> DynamicExecutionAnalysis:
    """
    Parse/analyze dynamic-execution indicators statically.
    """
    return analyze_dynamic_execution(
        source,
        **kwargs,
    )


def extract_dynamic_execution_features(
    source: Any,
    **kwargs: Any,
) -> dict[str, float]:
    """
    Extract the stable dynamic-execution feature mapping.
    """
    analysis = analyze_dynamic_execution(
        source,
        **kwargs,
    )

    return dict(analysis.feature_vector)


def extract_feature_vector(
    source: Any,
    **kwargs: Any,
) -> list[float]:
    """
    Extract the stable ordered dynamic-execution feature vector.
    """
    analysis = analyze_dynamic_execution(
        source,
        **kwargs,
    )

    return vectorize_features(analysis.feature_vector)


def extract_dynamic_execution_feature_vector(
    source: Any,
    **kwargs: Any,
) -> list[float]:
    """
    Explicit dynamic-execution feature-vector entry point.
    """
    return extract_feature_vector(
        source,
        **kwargs,
    )


# =============================================================================
# INSPECTION HELPERS
# =============================================================================


def has_indicator(
    analysis: DynamicExecutionAnalysis,
    indicator: str,
) -> bool:
    """
    Return whether an indicator is present.
    """
    return indicator in set(analysis.indicators)


def indicator_count(
    analysis: DynamicExecutionAnalysis,
    indicator: str,
) -> int:
    """
    Return the number of records containing an indicator.
    """
    return sum(record.indicator == indicator for record in analysis.records)


def has_category(
    analysis: DynamicExecutionAnalysis,
    category: str,
) -> bool:
    """
    Return whether a capability category is present.
    """
    return category in set(analysis.categories)


def category_count(
    analysis: DynamicExecutionAnalysis,
    category: str,
) -> int:
    """
    Return the number of records belonging to a category.
    """
    return sum(record.category == category for record in analysis.records)


def evidence_by_indicator(
    analysis: DynamicExecutionAnalysis,
    indicator: str,
) -> list[DynamicExecutionEvidence]:
    """
    Return evidence associated with an indicator.
    """
    return [item for item in analysis.evidence if item.indicator == indicator]


def evidence_by_category(
    analysis: DynamicExecutionAnalysis,
    category: str,
) -> list[DynamicExecutionEvidence]:
    """
    Return evidence associated with a capability category.
    """
    return [item for item in analysis.evidence if item.category == category]


def high_risk_evidence(
    analysis: DynamicExecutionAnalysis,
) -> list[DynamicExecutionEvidence]:
    """
    Return high and critical evidence.
    """
    return [
        item
        for item in analysis.evidence
        if _severity_rank(item.severity) >= _severity_rank("high")
    ]


def highest_severity(
    analysis: DynamicExecutionAnalysis,
) -> str:
    """
    Return the highest severity observed.
    """
    severities = [record.severity for record in analysis.records]

    severities.extend(item.severity for item in analysis.evidence)

    return _max_severity(severities)


def present_combinations(
    analysis: DynamicExecutionAnalysis,
) -> list[DynamicExecutionCombination]:
    """
    Return only combinations currently present.
    """
    return [combination for combination in analysis.combinations if combination.present]


# =============================================================================
# SERIALIZATION / REPORTING
# =============================================================================


def analysis_to_dict(
    analysis: DynamicExecutionAnalysis,
) -> dict[str, Any]:
    """
    Convert analysis to JSON-compatible primitives.
    """
    return {
        "source_hash": analysis.source_hash,
        "source_size": analysis.source_size,
        "records": [asdict(record) for record in analysis.records],
        "evidence": [asdict(item) for item in analysis.evidence],
        "indicators": list(analysis.indicators),
        "categories": list(analysis.categories),
        "combinations": [asdict(item) for item in analysis.combinations],
        "languages": list(analysis.languages),
        "platforms": list(analysis.platforms),
        "operations": list(analysis.operations),
        "feature_vector": dict(analysis.feature_vector),
        "metadata": dict(analysis.metadata),
    }


def summarize_dynamic_execution(
    analysis: DynamicExecutionAnalysis,
) -> dict[str, Any]:
    """
    Produce a compact operational summary.
    """
    category_counts = Counter(record.category for record in analysis.records)

    indicator_counts = Counter(record.indicator for record in analysis.records)

    operation_counts = Counter(record.operation for record in analysis.records)

    return {
        "source_hash": analysis.source_hash,
        "source_size": analysis.source_size,
        "record_count": len(analysis.records),
        "evidence_count": len(analysis.evidence),
        "indicator_count": len(analysis.indicators),
        "category_count": len(analysis.categories),
        "combination_count": len(analysis.combinations),
        "categories": list(analysis.categories),
        "category_counts": dict(sorted(category_counts.items())),
        "indicator_counts": dict(sorted(indicator_counts.items())),
        "operation_counts": dict(sorted(operation_counts.items())),
        "languages": list(analysis.languages),
        "platforms": list(analysis.platforms),
        "high_risk_count": len(high_risk_evidence(analysis)),
        "highest_severity": highest_severity(analysis),
        "present_combinations": [
            combination.name for combination in present_combinations(analysis)
        ],
        "signal_score": float(
            analysis.feature_vector.get(
                "signal_score",
                0.0,
            )
        ),
        "static_only": True,
        "execution": False,
        "network_access": False,
    }


# =============================================================================
# ITERATORS
# =============================================================================


def iter_evidence(
    analysis: DynamicExecutionAnalysis,
) -> Iterator[DynamicExecutionEvidence]:
    """
    Iterate over all dynamic-execution evidence.
    """
    yield from analysis.evidence


def iter_high_risk_evidence(
    analysis: DynamicExecutionAnalysis,
) -> Iterator[DynamicExecutionEvidence]:
    """
    Iterate over high/critical evidence.
    """
    yield from high_risk_evidence(analysis)


def iter_records(
    analysis: DynamicExecutionAnalysis,
) -> Iterator[DynamicExecutionRecord]:
    """
    Iterate over normalized capability records.
    """
    yield from analysis.records


def iter_combinations(
    analysis: DynamicExecutionAnalysis,
) -> Iterator[DynamicExecutionCombination]:
    """
    Iterate over capability combinations.
    """
    yield from analysis.combinations


def iter_analyses(
    analyses: Iterable[DynamicExecutionAnalysis],
) -> Iterator[DynamicExecutionAnalysis]:
    """
    Iterate over analyses.
    """
    yield from analyses


# =============================================================================
# COMPATIBILITY ALIASES
# =============================================================================


parse = parse_dynamic_execution
extract = extract_dynamic_execution_features


# =============================================================================
# PUBLIC API
# =============================================================================

__all__ = [
    "analyze_dynamic_execution",
    "analyze_dynamic_execution_capability",
    "analyze",
    "parse_dynamic_execution",
    "extract_dynamic_execution_features",
    "extract_dynamic_execution_indicators",
    "extract_dynamic_execution_evidence",
    "extract_feature_vector",
    "extract_dynamic_execution_feature_vector",
    "dynamic_execution_feature_names",
    "build_feature_schema",
    "vectorize_features",
    "has_indicator",
    "indicator_count",
    "has_category",
    "category_count",
    "evidence_by_indicator",
    "evidence_by_category",
    "high_risk_evidence",
    "highest_severity",
    "present_combinations",
    "analysis_to_dict",
    "summarize_dynamic_execution",
    "iter_evidence",
    "iter_high_risk_evidence",
    "iter_records",
    "iter_combinations",
    "iter_analyses",
    "DynamicExecutionPattern",
    "DynamicExecutionEvidence",
    "DynamicExecutionRecord",
    "DynamicExecutionCombination",
    "DynamicExecutionAnalysis",
    "DYNAMIC_EXECUTION_CATEGORIES",
    "SEVERITIES",
    "parse",
    "extract",
]
