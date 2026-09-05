"""
pharos-cdr/src/extraction/script/javascript.py

Static JavaScript/JScript feature extraction for the Pharos CDR pipeline.

This module performs defensive, non-executing analysis of JavaScript and
Windows JScript source. It is intentionally dependency-free and is designed
to complement script/parser.py.

Security properties
-------------------
- Never executes JavaScript/JScript.
- Never evaluates expressions.
- Never instantiates COM/ActiveX objects.
- Never launches processes.
- Never performs network requests.
- Never reads files referenced by analyzed source.
- Never resolves or follows URLs.
- Never writes extracted payloads to disk.
- Applies bounded input/evidence limits.

Primary analysis flow
---------------------
    source
      |
      v
    script.parser.parse_script()
      |
      v
    JavaScript/JScript-specific indicators
      |
      +--> execution / COM / network / filesystem / persistence
      +--> obfuscation / encoding / string construction
      +--> document/browser/script-loading behavior
      +--> suspicious capability combinations
      |
      v
    stable feature vector
      |
      v
    feature_pipeline.py / ML / CDR policy

The output is intended to be deterministic and ML-friendly.
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

try:
    from .parser import (
        ScriptAnalysis,
        analyze_script,
        parse_script,
    )
except ImportError:  # pragma: no cover - supports direct/module execution
    from parser import (
        ScriptAnalysis,
        analyze_script,
        parse_script,
    )


# ---------------------------------------------------------------------------
# Limits
# ---------------------------------------------------------------------------

MAX_SOURCE_SIZE = 25 * 1024 * 1024
MAX_EVIDENCE_ITEMS = 10_000
MAX_STRINGS = 10_000
MAX_URLS = 2_000
MAX_IDENTIFIERS = 20_000
MAX_FUNCTIONS = 5_000
MAX_FEATURE_TEXT = 2 * 1024 * 1024
MAX_SAMPLE_ITEMS = 100


# ---------------------------------------------------------------------------
# JavaScript-specific indicator taxonomy
# ---------------------------------------------------------------------------

JS_CATEGORIES: Tuple[str, ...] = (
    "execution",
    "dynamic_execution",
    "com_automation",
    "activex",
    "process",
    "filesystem",
    "network",
    "download",
    "script_loading",
    "browser",
    "document",
    "persistence",
    "registry",
    "credential_access",
    "discovery",
    "security_software",
    "obfuscation",
    "encoding",
    "reflection",
    "environment",
    "collection",
    "evasion",
    "command",
    "payload",
    "suspicious_protocol",
)

# Stable indicator names. These names are part of the ML feature schema and
# should therefore not be renamed casually after models have been trained.
JS_INDICATORS: Tuple[str, ...] = (
    "eval",
    "function_constructor",
    "settimeout_string",
    "setinterval_string",
    "execscript",
    "wscript_shell",
    "wscript_network",
    "activex_object",
    "activex_shell",
    "activex_fso",
    "activex_xmlhttp",
    "activex_winhttp",
    "activex_adodb",
    "activex_recordset",
    "activex_registry",
    "activex_process",
    "activex_wmi",
    "activex_scripting",
    "activex_other",
    "wsh_run",
    "wsh_exec",
    "shell_application",
    "filesystem_object",
    "text_stream",
    "file_copy_move_delete",
    "file_write",
    "file_read",
    "registry_access",
    "registry_run_key",
    "registry_startup",
    "xmlhttp",
    "winhttp",
    "http_request",
    "http_url",
    "download_to_file",
    "adodb_stream",
    "response_body",
    "response_text",
    "script_createelement",
    "script_src",
    "iframe_src",
    "document_write",
    "location_navigation",
    "window_open",
    "powershell",
    "cmd_shell",
    "wscript",
    "cscript",
    "mshta",
    "rundll32",
    "regsvr32",
    "certutil",
    "bitsadmin",
    "javascript_protocol",
    "data_protocol",
    "vbscript_protocol",
    "base64_decode",
    "base64_encode",
    "charcode_construction",
    "fromcharcode",
    "unescape",
    "decodeuricomponent",
    "string_fromcharcode",
    "hex_escape",
    "unicode_escape",
    "percent_encoding",
    "large_concatenation",
    "large_string",
    "high_entropy_string",
    "array_join_obfuscation",
    "reverse_string",
    "replace_chain",
    "split_join",
    "parseint_obfuscation",
    "parsefloat_obfuscation",
    "environment_variables",
    "hostname",
    "username",
    "userdomain",
    "temp_path",
    "appdata_path",
    "programdata_path",
    "systemroot_path",
    "process_enumeration",
    "security_software",
    "antivirus_terms",
    "sandbox_terms",
    "virtual_machine_terms",
    "debugger_terms",
    "credential_terms",
    "clipboard_access",
    "cookie_access",
    "localstorage_access",
    "webstorage_access",
    "startup_folder",
    "scheduled_task",
    "service_creation",
    "wmi",
    "powershell_encoded",
    "powershell_download",
    "powershell_reflection",
    "suspicious_long_line",
    "comment_density",
    "identifier_density",
    "token_density",
)


# ---------------------------------------------------------------------------
# Indicator definitions
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class JSIndicatorDefinition:
    """Definition of a JavaScript-specific static indicator."""

    name: str
    category: str
    severity: str
    confidence: float
    patterns: Tuple[re.Pattern[str], ...]
    description: str


def _compile_many(
    *patterns: str, flags: int = re.IGNORECASE
) -> Tuple[re.Pattern[str], ...]:
    return tuple(re.compile(pattern, flags) for pattern in patterns)


def _indicator(
    name: str,
    category: str,
    severity: str,
    confidence: float,
    *patterns: str,
    description: str,
) -> JSIndicatorDefinition:
    return JSIndicatorDefinition(
        name=name,
        category=category,
        severity=severity,
        confidence=confidence,
        patterns=_compile_many(*patterns),
        description=description,
    )


INDICATOR_DEFINITIONS: Tuple[JSIndicatorDefinition, ...] = (
    _indicator(
        "eval",
        "dynamic_execution",
        "high",
        0.98,
        r"\beval\s*\(",
        description="JavaScript eval() can execute dynamically constructed source.",
    ),
    _indicator(
        "function_constructor",
        "dynamic_execution",
        "high",
        0.98,
        r"\bnew\s+Function\s*\(",
        r"\bFunction\s*\(",
        description="Function constructor can create executable code dynamically.",
    ),
    _indicator(
        "settimeout_string",
        "dynamic_execution",
        "medium",
        0.92,
        r"\bsetTimeout\s*\(\s*['\"]",
        description="setTimeout called with source text may trigger dynamic evaluation.",
    ),
    _indicator(
        "setinterval_string",
        "dynamic_execution",
        "medium",
        0.92,
        r"\bsetInterval\s*\(\s*['\"]",
        description="setInterval called with source text may trigger dynamic evaluation.",
    ),
    _indicator(
        "execscript",
        "dynamic_execution",
        "high",
        0.98,
        r"\b(?:window\.)?execScript\s*\(",
        description="Legacy script execution API.",
    ),
    _indicator(
        "wscript_shell",
        "com_automation",
        "high",
        0.99,
        r"\bnew\s+ActiveXObject\s*\(\s*['\"](?:WScript\.)?Shell",
        r"\bCreateObject\s*\(\s*['\"](?:WScript\.)?Shell",
        description="Creation of Windows Script Host shell automation.",
    ),
    _indicator(
        "wscript_network",
        "network",
        "medium",
        0.96,
        r"['\"]WScript\.Network['\"]",
        r"['\"]WScript\.Network\.1['\"]",
        description="Windows Script Host network automation object.",
    ),
    _indicator(
        "activex_object",
        "activex",
        "high",
        0.99,
        r"\b(?:new\s+)?ActiveXObject\s*\(",
        r"\bGetObject\s*\(\s*['\"][^'\"]*ActiveX",
        description="ActiveX/COM object creation in JScript.",
    ),
    _indicator(
        "activex_shell",
        "process",
        "high",
        0.99,
        r"ActiveXObject\s*\(\s*['\"](?:WScript\.)?Shell",
        r"CreateObject\s*\(\s*['\"](?:WScript\.)?Shell",
        description="ActiveX/COM shell automation.",
    ),
    _indicator(
        "activex_fso",
        "filesystem",
        "high",
        0.99,
        r"ActiveXObject\s*\(\s*['\"]Scripting\.FileSystemObject",
        r"CreateObject\s*\(\s*['\"]Scripting\.FileSystemObject",
        description="Scripting.FileSystemObject provides filesystem access.",
    ),
    _indicator(
        "activex_xmlhttp",
        "network",
        "high",
        0.98,
        r"ActiveXObject\s*\(\s*['\"](?:MSXML2\.)?(?:XMLHTTP|ServerXMLHTTP)",
        r"CreateObject\s*\(\s*['\"](?:MSXML2\.)?(?:XMLHTTP|ServerXMLHTTP)",
        description="XMLHTTP/ServerXMLHTTP COM network client.",
    ),
    _indicator(
        "activex_winhttp",
        "network",
        "high",
        0.98,
        r"ActiveXObject\s*\(\s*['\"]WinHttp\.WinHttpRequest",
        r"CreateObject\s*\(\s*['\"]WinHttp\.WinHttpRequest",
        description="WinHTTP COM network client.",
    ),
    _indicator(
        "activex_adodb",
        "payload",
        "high",
        0.98,
        r"ActiveXObject\s*\(\s*['\"]ADODB\.(?:Stream|Recordset|Connection)",
        r"CreateObject\s*\(\s*['\"]ADODB\.(?:Stream|Recordset|Connection)",
        description="ADO COM objects commonly used for content transfer/storage.",
    ),
    _indicator(
        "activex_recordset",
        "collection",
        "medium",
        0.90,
        r"ActiveXObject\s*\(\s*['\"]ADODB\.Recordset",
        r"CreateObject\s*\(\s*['\"]ADODB\.Recordset",
        description="ADO Recordset object.",
    ),
    _indicator(
        "activex_registry",
        "registry",
        "high",
        0.99,
        r"ActiveXObject\s*\(\s*['\"]WScript\.Shell",
        r"\.(?:RegRead|RegWrite|RegDelete)\s*\(",
        description="Windows registry access through WSH shell automation.",
    ),
    _indicator(
        "activex_process",
        "process",
        "high",
        0.96,
        r"\b(?:WScript\.Shell|Shell\.Run|Shell\.Exec)\b",
        r"\.(?:Run|Exec)\s*\(\s*['\"](?:cmd|powershell|cscript|wscript)",
        description="Script-controlled process execution.",
    ),
    _indicator(
        "activex_wmi",
        "discovery",
        "high",
        0.98,
        r"ActiveXObject\s*\(\s*['\"]WbemScripting\.SWbemLocator",
        r"CreateObject\s*\(\s*['\"]WbemScripting\.SWbemLocator",
        r"\bSWbemLocator\b",
        description="WMI automation object.",
    ),
    _indicator(
        "activex_scripting",
        "com_automation",
        "medium",
        0.92,
        r"ActiveXObject\s*\(\s*['\"]Scripting\.",
        r"CreateObject\s*\(\s*['\"]Scripting\.",
        description="Windows Scripting runtime COM automation.",
    ),
    _indicator(
        "activex_other",
        "com_automation",
        "medium",
        0.85,
        r"ActiveXObject\s*\(\s*['\"][A-Za-z0-9_.-]+['\"]\s*\)",
        description="Generic ActiveX/COM object creation.",
    ),
    _indicator(
        "wsh_run",
        "process",
        "high",
        0.99,
        r"\.\s*Run\s*\(",
        r"\bShell\.Run\s*\(",
        description="Windows Script Host shell Run method.",
    ),
    _indicator(
        "wsh_exec",
        "process",
        "high",
        0.99,
        r"\.\s*Exec\s*\(",
        r"\bShell\.Exec\s*\(",
        description="Windows Script Host shell Exec method.",
    ),
    _indicator(
        "shell_application",
        "process",
        "high",
        0.97,
        r"Shell\.Application",
        r"new\s+ActiveXObject\s*\(\s*['\"]Shell\.Application['\"]",
        description="Shell.Application COM automation.",
    ),
    _indicator(
        "filesystem_object",
        "filesystem",
        "high",
        0.98,
        r"\bFileSystemObject\b",
        r"\bScripting\.FileSystemObject\b",
        description="Scripting filesystem automation.",
    ),
    _indicator(
        "text_stream",
        "filesystem",
        "medium",
        0.95,
        r"\b(?:OpenTextFile|CreateTextFile|GetFile|GetFolder)\s*\(",
        description="FileSystemObject text/file access.",
    ),
    _indicator(
        "file_copy_move_delete",
        "filesystem",
        "medium",
        0.96,
        r"\.(?:CopyFile|MoveFile|DeleteFile|CopyFolder|MoveFolder|DeleteFolder)\s*\(",
        description="Filesystem modification methods.",
    ),
    _indicator(
        "file_write",
        "filesystem",
        "medium",
        0.96,
        r"\.(?:Write|WriteLine|SaveToFile)\s*\(",
        description="Writing content to a file or stream.",
    ),
    _indicator(
        "file_read",
        "filesystem",
        "medium",
        0.95,
        r"\.(?:Read|ReadLine|ReadAll)\s*\(",
        description="Reading file or stream content.",
    ),
    _indicator(
        "registry_access",
        "registry",
        "high",
        0.98,
        r"\.(?:RegRead|RegWrite|RegDelete)\s*\(",
        description="Windows registry access.",
    ),
    _indicator(
        "registry_run_key",
        "persistence",
        "high",
        0.99,
        r"(?:CurrentVersion\\Run|CurrentVersion\\RunOnce|\\RunServices)",
        description="Registry autorun location.",
    ),
    _indicator(
        "registry_startup",
        "persistence",
        "high",
        0.97,
        r"(?:StartupApproved|Userinit|Winlogon\\Shell|Explorer\\User Shell Folders)",
        description="Registry locations associated with startup/persistence.",
    ),
    _indicator(
        "xmlhttp",
        "network",
        "high",
        0.97,
        r"\b(?:XMLHTTP|ServerXMLHTTP)\b",
        r"\bMSXML2\.",
        description="XMLHTTP network functionality.",
    ),
    _indicator(
        "winhttp",
        "network",
        "high",
        0.97,
        r"\bWinHttpRequest\b",
        r"\bWinHttp\.WinHttpRequest\b",
        description="WinHTTP network functionality.",
    ),
    _indicator(
        "http_request",
        "network",
        "medium",
        0.90,
        r"\.(?:open|send)\s*\(",
        r"\bXMLHttpRequest\b",
        description="HTTP request construction or transmission.",
    ),
    _indicator(
        "http_url",
        "network",
        "low",
        0.99,
        r"https?://",
        description="HTTP(S) URL present in source.",
    ),
    _indicator(
        "download_to_file",
        "download",
        "high",
        0.98,
        r"\.(?:SaveToFile|WriteFile|DownloadFile)\s*\(",
        r"\b(?:download|downloadfile|savetofile)\b",
        description="Potential transfer of remote content into a local file.",
    ),
    _indicator(
        "adodb_stream",
        "payload",
        "high",
        0.98,
        r"\bADODB\.Stream\b",
        r"\bAdodb\.Stream\b",
        description="ADODB.Stream frequently appears in binary content transfer chains.",
    ),
    _indicator(
        "response_body",
        "payload",
        "high",
        0.97,
        r"\.responseBody\b",
        description="Binary HTTP response access.",
    ),
    _indicator(
        "response_text",
        "payload",
        "medium",
        0.93,
        r"\.responseText\b",
        description="Text HTTP response access.",
    ),
    _indicator(
        "script_createelement",
        "script_loading",
        "medium",
        0.86,
        r"document\.createElement\s*\(\s*['\"]script['\"]",
        description="Dynamic creation of script elements.",
    ),
    _indicator(
        "script_src",
        "script_loading",
        "medium",
        0.94,
        r"\.src\s*=\s*['\"](?:https?:)?//",
        r"<script[^>]+src\s*=",
        description="Loading script content from a source URL.",
    ),
    _indicator(
        "iframe_src",
        "script_loading",
        "medium",
        0.90,
        r"<iframe[^>]+src\s*=",
        r"createElement\s*\(\s*['\"]iframe['\"]",
        description="Dynamic iframe/script content loading.",
    ),
    _indicator(
        "document_write",
        "document",
        "medium",
        0.88,
        r"\bdocument\.write(?:ln)?\s*\(",
        description="Dynamic document content injection.",
    ),
    _indicator(
        "location_navigation",
        "browser",
        "low",
        0.91,
        r"\b(?:window\.)?location(?:\.href)?\s*=",
        r"\blocation\.(?:assign|replace)\s*\(",
        description="Browser navigation or redirection.",
    ),
    _indicator(
        "window_open",
        "browser",
        "low",
        0.90,
        r"\bwindow\.open\s*\(",
        description="Opening a browser window or resource.",
    ),
    _indicator(
        "powershell",
        "command",
        "high",
        0.99,
        r"\b(?:powershell|pwsh)(?:\.exe)?\b",
        description="PowerShell invocation reference.",
    ),
    _indicator(
        "cmd_shell",
        "command",
        "high",
        0.99,
        r"\b(?:cmd|cmd\.exe)\b",
        r"(?:/c|/k)\s+",
        description="Windows command interpreter reference.",
    ),
    _indicator(
        "wscript",
        "command",
        "high",
        0.99,
        r"\b(?:wscript|cscript)(?:\.exe)?\b",
        description="Windows Script Host interpreter reference.",
    ),
    _indicator(
        "mshta",
        "command",
        "high",
        0.99,
        r"\bmshta(?:\.exe)?\b",
        description="MSHTA execution reference.",
    ),
    _indicator(
        "rundll32",
        "command",
        "high",
        0.99,
        r"\brundll32(?:\.exe)?\b",
        description="Rundll32 execution reference.",
    ),
    _indicator(
        "regsvr32",
        "command",
        "high",
        0.99,
        r"\bregsvr32(?:\.exe)?\b",
        description="Regsvr32 execution reference.",
    ),
    _indicator(
        "certutil",
        "command",
        "high",
        0.98,
        r"\bcertutil(?:\.exe)?\b",
        description="Certutil utility reference.",
    ),
    _indicator(
        "bitsadmin",
        "command",
        "high",
        0.98,
        r"\bbitsadmin(?:\.exe)?\b",
        description="BITSAdmin utility reference.",
    ),
    _indicator(
        "javascript_protocol",
        "suspicious_protocol",
        "medium",
        0.94,
        r"\bjavascript\s*:",
        description="JavaScript URL protocol.",
    ),
    _indicator(
        "data_protocol",
        "suspicious_protocol",
        "medium",
        0.92,
        r"\bdata\s*:",
        description="Data URL protocol.",
    ),
    _indicator(
        "vbscript_protocol",
        "suspicious_protocol",
        "medium",
        0.94,
        r"\bvbscript\s*:",
        description="VBScript URL protocol.",
    ),
    _indicator(
        "base64_decode",
        "encoding",
        "medium",
        0.90,
        r"\b(?:atob|decode64|frombase64string)\s*\(",
        r"\bbase64(?:decode|decoding)\b",
        description="Base64 decoding reference.",
    ),
    _indicator(
        "base64_encode",
        "encoding",
        "low",
        0.90,
        r"\b(?:btoa|encode64|tobase64string)\s*\(",
        description="Base64 encoding reference.",
    ),
    _indicator(
        "charcode_construction",
        "obfuscation",
        "medium",
        0.93,
        r"\bString\.fromCharCode\s*\(",
        r"\bfromCharCode\s*\(",
        description="Character-code construction of strings.",
    ),
    _indicator(
        "fromcharcode",
        "obfuscation",
        "medium",
        0.93,
        r"\bfromCharCode\s*\(",
        description="String.fromCharCode use.",
    ),
    _indicator(
        "unescape",
        "obfuscation",
        "medium",
        0.94,
        r"\bunescape\s*\(",
        description="Legacy URI/string decoding primitive.",
    ),
    _indicator(
        "decodeuricomponent",
        "encoding",
        "low",
        0.88,
        r"\bdecodeURIComponent\s*\(",
        description="URI decoding primitive.",
    ),
    _indicator(
        "string_fromcharcode",
        "obfuscation",
        "medium",
        0.95,
        r"\bString\.fromCharCode\s*\(",
        description="Character-code string construction.",
    ),
    _indicator(
        "hex_escape",
        "obfuscation",
        "medium",
        0.88,
        r"(?:\\x[0-9a-f]{2}){3,}",
        description="Repeated hexadecimal string escapes.",
    ),
    _indicator(
        "unicode_escape",
        "obfuscation",
        "medium",
        0.88,
        r"(?:\\u[0-9a-f]{4}){2,}",
        description="Repeated Unicode string escapes.",
    ),
    _indicator(
        "percent_encoding",
        "obfuscation",
        "low",
        0.86,
        r"(?:%[0-9a-f]{2}){4,}",
        description="Repeated percent-encoded characters.",
    ),
    _indicator(
        "large_concatenation",
        "obfuscation",
        "medium",
        0.87,
        r"(?:['\"][^'\"]{1,80}['\"]\s*\+\s*){5,}",
        description="Long chains of string concatenation.",
    ),
    _indicator(
        "large_string",
        "obfuscation",
        "low",
        0.84,
        r"['\"][^'\"]{512,}['\"]",
        description="Very large string literal.",
    ),
    _indicator(
        "array_join_obfuscation",
        "obfuscation",
        "medium",
        0.88,
        r"\[[^\]]{20,}\]\s*\.\s*join\s*\(",
        description="Array construction followed by join may assemble hidden strings.",
    ),
    _indicator(
        "reverse_string",
        "obfuscation",
        "medium",
        0.86,
        r"\.(?:reverse)\s*\(\s*\)\s*\.\s*(?:join)\s*\(",
        description="String reversal construction.",
    ),
    _indicator(
        "replace_chain",
        "obfuscation",
        "low",
        0.80,
        r"(?:\.(?:replace)\s*\([^;]{0,200}\)){3,}",
        description="Multiple replacement operations may indicate string transformation.",
    ),
    _indicator(
        "split_join",
        "obfuscation",
        "low",
        0.82,
        r"\.split\s*\([^)]*\)\s*\.\s*reverse\s*\(\s*\)\s*\.\s*join\s*\(",
        description="Split/reverse/join string transformation.",
    ),
    _indicator(
        "parseint_obfuscation",
        "obfuscation",
        "low",
        0.78,
        r"\bparseInt\s*\([^)]*,\s*(?:16|8|2)\s*\)",
        description="Numeric parsing sometimes used in encoded string reconstruction.",
    ),
    _indicator(
        "parsefloat_obfuscation",
        "obfuscation",
        "low",
        0.72,
        r"\bparseFloat\s*\(",
        description="Numeric parsing primitive.",
    ),
    _indicator(
        "environment_variables",
        "environment",
        "medium",
        0.94,
        r"\b(?:ExpandEnvironmentStrings|Environment)\b",
        r"%[A-Za-z_][A-Za-z0-9_]+%",
        description="Environment-variable access or expansion.",
    ),
    _indicator(
        "hostname",
        "discovery",
        "medium",
        0.91,
        r"\b(?:ComputerName|HostName|hostname)\b",
        description="Host identification reference.",
    ),
    _indicator(
        "username",
        "discovery",
        "medium",
        0.91,
        r"\b(?:UserName|USERNAME|USERPROFILE)\b",
        description="User identity reference.",
    ),
    _indicator(
        "userdomain",
        "discovery",
        "medium",
        0.91,
        r"\b(?:UserDomain|USERDOMAIN)\b",
        description="Windows domain identity reference.",
    ),
    _indicator(
        "temp_path",
        "environment",
        "medium",
        0.90,
        r"(?:%TEMP%|%TMP%|\\Temp\\|\\Temporary Internet Files\\)",
        description="Temporary-directory reference.",
    ),
    _indicator(
        "appdata_path",
        "environment",
        "medium",
        0.90,
        r"(?:%APPDATA%|%LOCALAPPDATA%|\\AppData\\)",
        description="AppData directory reference.",
    ),
    _indicator(
        "programdata_path",
        "environment",
        "medium",
        0.89,
        r"(?:%PROGRAMDATA%|\\ProgramData\\)",
        description="ProgramData directory reference.",
    ),
    _indicator(
        "systemroot_path",
        "environment",
        "medium",
        0.90,
        r"(?:%SystemRoot%|%WINDIR%|\\Windows\\System32\\)",
        description="Windows system directory reference.",
    ),
    _indicator(
        "process_enumeration",
        "discovery",
        "high",
        0.94,
        r"\b(?:Win32_Process|ExecQuery\s*\(\s*['\"]SELECT\s+.*FROM\s+Win32_Process)",
        r"\bProcesses\b",
        description="Process enumeration through WMI or related automation.",
    ),
    _indicator(
        "security_software",
        "security_software",
        "high",
        0.93,
        r"\b(?:Win32_Product|AntiVirusProduct|SecurityCenter2|SecurityCenter)\b",
        r"\b(?:Get-MpComputerStatus|MSFT_MpComputerStatus)\b",
        description="Security software discovery.",
    ),
    _indicator(
        "antivirus_terms",
        "security_software",
        "medium",
        0.80,
        r"\b(?:antivirus|anti-virus|defender|endpoint protection|security center)\b",
        description="Antivirus/security product terminology.",
    ),
    _indicator(
        "sandbox_terms",
        "evasion",
        "medium",
        0.78,
        r"\b(?:sandbox|analysis environment|malware analysis)\b",
        description="Sandbox/analysis environment terminology.",
    ),
    _indicator(
        "virtual_machine_terms",
        "evasion",
        "medium",
        0.78,
        r"\b(?:virtualbox|vmware|hyper-v|virtual machine|vboxservice)\b",
        description="Virtual-machine detection terminology.",
    ),
    _indicator(
        "debugger_terms",
        "evasion",
        "medium",
        0.80,
        r"\b(?:debugger|isdebuggerpresent|debugport|ollydbg|windbg|x64dbg)\b",
        description="Debugger/analysis detection terminology.",
    ),
    _indicator(
        "credential_terms",
        "credential_access",
        "medium",
        0.76,
        r"\b(?:password|credential|logon|token|secret|cookie|credential manager)\b",
        description="Credential-related terminology.",
    ),
    _indicator(
        "clipboard_access",
        "collection",
        "medium",
        0.88,
        r"\b(?:clipboardData|navigator\.clipboard|GetClipboardData)\b",
        description="Clipboard access.",
    ),
    _indicator(
        "cookie_access",
        "collection",
        "medium",
        0.90,
        r"\bdocument\.cookie\b",
        description="Browser cookie access.",
    ),
    _indicator(
        "localstorage_access",
        "collection",
        "low",
        0.86,
        r"\blocalStorage\b",
        description="Browser localStorage access.",
    ),
    _indicator(
        "webstorage_access",
        "collection",
        "low",
        0.86,
        r"\bsessionStorage\b",
        description="Browser sessionStorage access.",
    ),
    _indicator(
        "startup_folder",
        "persistence",
        "high",
        0.97,
        r"(?:\\Start Menu\\Programs\\Startup|\\Startup\\)",
        description="Windows Startup-folder reference.",
    ),
    _indicator(
        "scheduled_task",
        "persistence",
        "high",
        0.98,
        r"\bschtasks(?:\.exe)?\b",
        r"\bSchedule\.Service\b",
        description="Scheduled-task persistence reference.",
    ),
    _indicator(
        "service_creation",
        "persistence",
        "high",
        0.96,
        r"\b(?:CreateService|OpenSCManager|New-Service|Win32_Service)\b",
        description="Windows service creation/control reference.",
    ),
    _indicator(
        "wmi",
        "discovery",
        "high",
        0.97,
        r"\b(?:WbemScripting\.SWbemLocator|SWbemServices|Win32_[A-Za-z0-9_]+)\b",
        description="Windows Management Instrumentation reference.",
    ),
    _indicator(
        "powershell_encoded",
        "obfuscation",
        "high",
        0.99,
        r"(?:powershell|pwsh)[^;\r\n]{0,300}(?:-enc|-encodedcommand)\b",
        description="PowerShell encoded-command argument.",
    ),
    _indicator(
        "powershell_download",
        "download",
        "high",
        0.99,
        r"(?:powershell|pwsh)[^;\r\n]{0,400}(?:Invoke-WebRequest|iwr|curl|wget|WebClient|DownloadString|DownloadFile)",
        description="PowerShell download behavior reference.",
    ),
    _indicator(
        "powershell_reflection",
        "reflection",
        "high",
        0.98,
        r"(?:powershell|pwsh)[^;\r\n]{0,500}(?:Reflection\.Assembly|LoadWithPartialName|Assembly\.Load)",
        description="PowerShell reflection/assembly loading reference.",
    ),
)


INDICATOR_BY_NAME: Dict[str, JSIndicatorDefinition] = {
    definition.name: definition for definition in INDICATOR_DEFINITIONS
}


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class JavaScriptEvidence:
    """A single static JavaScript finding."""

    indicator: str
    category: str
    severity: str
    confidence: float
    evidence: str
    line_number: Optional[int] = None
    source: str = "javascript"
    description: str = ""


@dataclass(frozen=True)
class JavaScriptFunction:
    """Lightweight statically extracted JavaScript function metadata."""

    name: str
    line_number: Optional[int]
    parameters: Tuple[str, ...] = ()
    kind: str = "function"
    evidence: str = ""


@dataclass(frozen=True)
class JavaScriptObject:
    """A statically identified ActiveX/COM object name."""

    object_name: str
    line_number: Optional[int]
    constructor: str = "ActiveXObject"
    risk: str = "medium"


@dataclass(frozen=True)
class JavaScriptCombination:
    """A higher-level combination of static indicators."""

    name: str
    present: bool
    required_indicators: Tuple[str, ...]
    explanation: str
    severity: str = "medium"


@dataclass
class JavaScriptAnalysis:
    """Complete JavaScript/JScript static analysis result."""

    source_sha256: str
    source_size: int
    line_count: int
    family: str

    indicators: Dict[str, int] = field(default_factory=dict)
    categories: Dict[str, int] = field(default_factory=dict)

    evidence: List[JavaScriptEvidence] = field(default_factory=list)
    functions: List[JavaScriptFunction] = field(default_factory=list)
    activex_objects: List[JavaScriptObject] = field(default_factory=list)
    combinations: List[JavaScriptCombination] = field(default_factory=list)

    urls: List[str] = field(default_factory=list)
    identifiers: List[str] = field(default_factory=list)
    strings: List[str] = field(default_factory=list)

    feature_vector: Dict[str, Union[int, float, bool]] = field(default_factory=dict)

    severity: str = "low"
    confidence: float = 0.0

    metadata: Dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

_SOURCE_TYPES = (str, bytes, bytearray, memoryview)


def _read_source(source: Union[str, bytes, bytearray, memoryview, Path]) -> str:
    """
    Convert source input into bounded text.

    Path input is supported for convenience, but the module does not follow
    paths referenced by JavaScript itself.
    """
    if isinstance(source, Path):
        data = source.read_bytes()
        if len(data) > MAX_SOURCE_SIZE:
            raise ValueError(
                f"JavaScript source exceeds MAX_SOURCE_SIZE ({MAX_SOURCE_SIZE} bytes)"
            )
        return data.decode("utf-8", errors="replace")

    if isinstance(source, str):
        if len(source.encode("utf-8", errors="replace")) > MAX_SOURCE_SIZE:
            raise ValueError(
                f"JavaScript source exceeds MAX_SOURCE_SIZE ({MAX_SOURCE_SIZE} bytes)"
            )
        return source

    if isinstance(source, (bytes, bytearray, memoryview)):
        data = bytes(source)
        if len(data) > MAX_SOURCE_SIZE:
            raise ValueError(
                f"JavaScript source exceeds MAX_SOURCE_SIZE ({MAX_SOURCE_SIZE} bytes)"
            )
        return data.decode("utf-8", errors="replace")

    raise TypeError("source must be str, bytes, bytearray, memoryview, or pathlib.Path")


def _source_sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def _line_number(text: str, offset: int) -> int:
    if offset <= 0:
        return 1
    return text.count("\n", 0, offset) + 1


def _clip(value: str, maximum: int = 500) -> str:
    value = value.strip()
    if len(value) <= maximum:
        return value
    return value[: maximum - 3] + "..."


def _severity_rank(value: str) -> int:
    return {
        "low": 1,
        "medium": 2,
        "high": 3,
        "critical": 4,
    }.get(value.lower(), 0)


def _max_severity(values: Iterable[str]) -> str:
    best = "low"
    best_rank = 0
    for value in values:
        rank = _severity_rank(value)
        if rank > best_rank:
            best = value
            best_rank = rank
    return best


def _bounded_append(items: List[Any], value: Any, limit: int) -> bool:
    if len(items) >= limit:
        return False
    items.append(value)
    return True


# ---------------------------------------------------------------------------
# JavaScript lexical helpers
# ---------------------------------------------------------------------------

# Strings are deliberately kept lightweight. This is not a JavaScript parser.
_JS_STRING_RE = re.compile(
    r"""
    (?P<quote>['"`])
    (?P<body>
        (?:
            \\.
            |
            (?! (?P=quote) ) .
        )*
    )
    (?P=quote)
    """,
    re.VERBOSE | re.DOTALL,
)

_JS_IDENTIFIER_RE = re.compile(r"\b[A-Za-z_$][A-Za-z0-9_$]*\b")

_JS_FUNCTION_RE = re.compile(
    r"""
    \bfunction
    (?:\s*\*)?
    \s*
    (?P<name>[A-Za-z_$][A-Za-z0-9_$]*)?
    \s*
    \(
        (?P<params>[^)]{0,2000})
    \)
    """,
    re.IGNORECASE | re.VERBOSE,
)

_JS_ARROW_RE = re.compile(
    r"""
    (?:
        \(\s*(?P<params1>[^)]{0,1000})\s*\)
        |
        (?P<params2>[A-Za-z_$][A-Za-z0-9_$]*)
    )
    \s*=> 
    """,
    re.VERBOSE,
)

_ACTIVEX_RE = re.compile(
    r"""
    (?P<constructor>
        ActiveXObject
        |
        CreateObject
        |
        GetObject
    )
    \s*\(
    \s*
    (?P<quote>['"])
    (?P<object>[^'"]{1,500})
    (?P=quote)
    """,
    re.IGNORECASE | re.VERBOSE,
)

_URL_RE = re.compile(r"""(?i)\b(?:https?|ftp)://[^\s"'<>]+""")

_PROTOCOL_RE = re.compile(r"""(?i)\b(?:javascript|vbscript|data):""")


def _extract_js_strings(text: str) -> List[str]:
    result: List[str] = []

    for match in _JS_STRING_RE.finditer(text):
        if len(result) >= MAX_STRINGS:
            break

        body = match.group("body")
        if body is None:
            continue

        result.append(body)

    return result


def _extract_identifiers(text: str) -> List[str]:
    result: List[str] = []
    seen: set[str] = set()

    for match in _JS_IDENTIFIER_RE.finditer(text):
        if len(result) >= MAX_IDENTIFIERS:
            break

        value = match.group(0)
        key = value.lower()

        if key in seen:
            continue

        seen.add(key)
        result.append(value)

    return result


def _extract_functions(text: str) -> List[JavaScriptFunction]:
    functions: List[JavaScriptFunction] = []

    for match in _JS_FUNCTION_RE.finditer(text):
        if len(functions) >= MAX_FUNCTIONS:
            break

        name = match.group("name") or "<anonymous>"
        raw_params = match.group("params") or ""

        params = tuple(item.strip() for item in raw_params.split(",") if item.strip())

        functions.append(
            JavaScriptFunction(
                name=name,
                line_number=_line_number(text, match.start()),
                parameters=params,
                kind="function",
                evidence=_clip(match.group(0), 400),
            )
        )

    for match in _JS_ARROW_RE.finditer(text):
        if len(functions) >= MAX_FUNCTIONS:
            break

        raw_params = match.group("params1")
        if raw_params is None:
            raw_params = match.group("params2") or ""

        params = tuple(item.strip() for item in raw_params.split(",") if item.strip())

        functions.append(
            JavaScriptFunction(
                name="<arrow>",
                line_number=_line_number(text, match.start()),
                parameters=params,
                kind="arrow",
                evidence=_clip(match.group(0), 400),
            )
        )

    return functions


def _extract_activex_objects(text: str) -> List[JavaScriptObject]:
    objects: List[JavaScriptObject] = []
    seen: set[Tuple[str, int]] = set()

    for match in _ACTIVEX_RE.finditer(text):
        if len(objects) >= MAX_FUNCTIONS:
            break

        object_name = match.group("object").strip()
        line = _line_number(text, match.start())

        key = (object_name.lower(), line)
        if key in seen:
            continue
        seen.add(key)

        lowered = object_name.lower()

        if "shell" in lowered:
            risk = "high"
        elif any(
            marker in lowered
            for marker in (
                "xmlhttp",
                "winhttp",
                "adodb",
                "filesystem",
                "wmi",
                "scripting.",
            )
        ):
            risk = "high"
        else:
            risk = "medium"

        objects.append(
            JavaScriptObject(
                object_name=object_name,
                line_number=line,
                constructor=match.group("constructor"),
                risk=risk,
            )
        )

    return objects


# ---------------------------------------------------------------------------
# Comment/string-aware normalization
# ---------------------------------------------------------------------------


def _mask_strings_and_comments(text: str) -> str:
    """
    Replace comments and string bodies with spaces while retaining newlines.

    This is deliberately not a complete JavaScript lexer. It is a defensive
    normalization helper used to reduce false positives caused by ordinary
    prose/comments while preserving source offsets approximately.
    """
    chars = list(text)
    n = len(chars)
    i = 0

    state = "normal"

    while i < n:
        ch = chars[i]
        nxt = chars[i + 1] if i + 1 < n else ""

        if state == "normal":
            if ch == "/" and nxt == "/":
                chars[i] = " "
                chars[i + 1] = " "
                i += 2
                state = "line_comment"
                continue

            if ch == "/" and nxt == "*":
                chars[i] = " "
                chars[i + 1] = " "
                i += 2
                state = "block_comment"
                continue

            if ch in ("'", '"', "`"):
                quote = ch
                chars[i] = " "
                i += 1
                state = ("string", quote)
                continue

            i += 1
            continue

        if state == "line_comment":
            if ch == "\n":
                state = "normal"
            else:
                chars[i] = " "
            i += 1
            continue

        if state == "block_comment":
            if ch == "*" and nxt == "/":
                chars[i] = " "
                chars[i + 1] = " "
                i += 2
                state = "normal"
            else:
                if ch != "\n":
                    chars[i] = " "
                i += 1
            continue

        if isinstance(state, tuple) and state[0] == "string":
            quote = state[1]

            if ch == "\\":
                chars[i] = " "
                if i + 1 < n:
                    if chars[i + 1] != "\n":
                        chars[i + 1] = " "
                    i += 2
                else:
                    i += 1
                continue

            if ch == quote:
                chars[i] = " "
                i += 1
                state = "normal"
                continue

            if ch != "\n":
                chars[i] = " "

            i += 1
            continue

        i += 1

    return "".join(chars)


# ---------------------------------------------------------------------------
# Indicator matching
# ---------------------------------------------------------------------------


def _match_indicators(
    text: str,
) -> Tuple[Dict[str, int], List[JavaScriptEvidence]]:
    indicators: Dict[str, int] = Counter()
    evidence: List[JavaScriptEvidence] = []

    normalized = _mask_strings_and_comments(text)

    # Some indicators intentionally need literal strings, such as ActiveX
    # object names and URL-bearing strings. Run those against original text.
    sources: Tuple[Tuple[str, str], ...] = (
        ("normalized", normalized),
        ("source", text),
    )

    seen_evidence: set[Tuple[str, int, str]] = set()

    for definition in INDICATOR_DEFINITIONS:
        matched_offsets: List[Tuple[int, re.Match[str], str]] = []

        for source_name, candidate in sources:
            for pattern in definition.patterns:
                for match in pattern.finditer(candidate):
                    matched_offsets.append((match.start(), match, source_name))

                    if len(matched_offsets) >= MAX_EVIDENCE_ITEMS:
                        break

                if len(matched_offsets) >= MAX_EVIDENCE_ITEMS:
                    break

            if len(matched_offsets) >= MAX_EVIDENCE_ITEMS:
                break

        # Deduplicate by approximate source location/evidence.
        unique_matches: List[Tuple[int, re.Match[str], str]] = []

        for offset, match, source_name in sorted(
            matched_offsets,
            key=lambda item: item[0],
        ):
            line = _line_number(text, offset)
            snippet = _clip(match.group(0), 300)

            key = (definition.name, line, snippet.lower())

            if key in seen_evidence:
                continue

            seen_evidence.add(key)
            unique_matches.append((offset, match, source_name))

        if not unique_matches:
            continue

        indicators[definition.name] = len(unique_matches)

        for offset, match, _source_name in unique_matches:
            if len(evidence) >= MAX_EVIDENCE_ITEMS:
                break

            evidence.append(
                JavaScriptEvidence(
                    indicator=definition.name,
                    category=definition.category,
                    severity=definition.severity,
                    confidence=definition.confidence,
                    evidence=_clip(match.group(0), 500),
                    line_number=_line_number(text, offset),
                    source="javascript",
                    description=definition.description,
                )
            )

    return dict(indicators), evidence


# ---------------------------------------------------------------------------
# Derived/static statistics
# ---------------------------------------------------------------------------


def _string_statistics(strings: Sequence[str]) -> Dict[str, Union[int, float]]:
    if not strings:
        return {
            "string_count": 0,
            "string_total_length": 0,
            "string_max_length": 0,
            "string_mean_length": 0.0,
            "long_string_count": 0,
            "base64_like_string_count": 0,
            "hex_like_string_count": 0,
            "percent_encoded_string_count": 0,
            "high_entropy_string_count": 0,
        }

    total = sum(len(value) for value in strings)
    maximum = max(len(value) for value in strings)

    base64_re = re.compile(r"^[A-Za-z0-9+/]{16,}={0,2}$")
    hex_re = re.compile(r"^(?:[0-9A-Fa-f]{2}){8,}$")
    percent_re = re.compile(r"(?:%[0-9A-Fa-f]{2}){3,}")

    long_count = 0
    base64_count = 0
    hex_count = 0
    percent_count = 0
    entropy_count = 0

    for value in strings:
        if len(value) >= 256:
            long_count += 1

        compact = re.sub(r"\s+", "", value)

        if base64_re.fullmatch(compact):
            base64_count += 1

        if hex_re.fullmatch(compact):
            hex_count += 1

        if percent_re.search(value):
            percent_count += 1

        if len(value) >= 32 and _shannon_entropy(value) >= 4.5:
            entropy_count += 1

    return {
        "string_count": len(strings),
        "string_total_length": total,
        "string_max_length": maximum,
        "string_mean_length": total / len(strings),
        "long_string_count": long_count,
        "base64_like_string_count": base64_count,
        "hex_like_string_count": hex_count,
        "percent_encoded_string_count": percent_count,
        "high_entropy_string_count": entropy_count,
    }


def _shannon_entropy(value: str) -> float:
    if not value:
        return 0.0

    counts = Counter(value)
    length = len(value)

    entropy = 0.0

    for count in counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return entropy


def _source_statistics(text: str) -> Dict[str, Union[int, float]]:
    lines = text.splitlines() or [""]

    nonempty_lines = [line for line in lines if line.strip()]

    comment_lines = 0

    for line in lines:
        stripped = line.strip()
        if (
            stripped.startswith("//")
            or stripped.startswith("/*")
            or stripped.startswith("*")
        ):
            comment_lines += 1

    long_lines = sum(1 for line in lines if len(line) >= 1_000)
    very_long_lines = sum(1 for line in lines if len(line) >= 10_000)

    concatenation_count = len(
        re.findall(
            r"""['"][^'"]{0,500}['"]\s*\+\s*['"]""",
            text,
        )
    )

    semicolon_count = text.count(";")
    brace_count = text.count("{") + text.count("}")

    return {
        "line_count": len(lines),
        "nonempty_line_count": len(nonempty_lines),
        "comment_line_count": comment_lines,
        "comment_ratio": (comment_lines / len(lines) if lines else 0.0),
        "long_line_count": long_lines,
        "very_long_line_count": very_long_lines,
        "concatenation_count": concatenation_count,
        "semicolon_count": semicolon_count,
        "brace_count": brace_count,
        "average_line_length": (
            sum(len(line) for line in lines) / len(lines) if lines else 0.0
        ),
        "max_line_length": max(
            (len(line) for line in lines),
            default=0,
        ),
    }


# ---------------------------------------------------------------------------
# Category derivation
# ---------------------------------------------------------------------------


def _derive_categories(
    indicators: Mapping[str, int],
) -> Dict[str, int]:
    categories: Counter[str] = Counter()

    for name, count in indicators.items():
        if count <= 0:
            continue

        definition = INDICATOR_BY_NAME.get(name)
        if definition is None:
            continue

        categories[definition.category] += count

    return dict(categories)


def _derive_combinations(
    indicators: Mapping[str, int],
) -> List[JavaScriptCombination]:
    present = set(name for name, count in indicators.items() if count > 0)

    combinations: List[JavaScriptCombination] = []

    def add(
        name: str,
        required: Sequence[str],
        explanation: str,
        severity: str,
    ) -> None:
        required_tuple = tuple(required)
        is_present = all(item in present for item in required_tuple)

        combinations.append(
            JavaScriptCombination(
                name=name,
                present=is_present,
                required_indicators=required_tuple,
                explanation=explanation,
                severity=severity,
            )
        )

    add(
        "activex_process_execution",
        ("activex_object", "activex_process"),
        "ActiveX/COM automation is combined with script-controlled process execution.",
        "high",
    )

    add(
        "network_to_file",
        ("network", "download_to_file"),
        "Network functionality is combined with local file-writing behavior.",
        "high",
    )

    add(
        "network_binary_payload",
        ("network", "response_body", "adodb_stream"),
        "Network response bytes are combined with stream-based payload handling.",
        "high",
    )

    add(
        "download_then_execute",
        ("download_to_file", "activex_process"),
        "Transferred content is combined with process execution.",
        "critical",
    )

    add(
        "dynamic_execution_with_obfuscation",
        ("eval", "charcode_construction"),
        "Dynamic JavaScript execution is combined with character-code string construction.",
        "high",
    )

    add(
        "dynamic_execution_with_encoding",
        ("eval", "base64_decode"),
        "Dynamic execution is combined with encoded-content decoding.",
        "high",
    )

    add(
        "activex_network_execution",
        ("activex_object", "network", "activex_process"),
        "COM automation, network access, and process execution occur together.",
        "critical",
    )

    add(
        "filesystem_persistence",
        ("filesystem_object", "startup_folder"),
        "Filesystem automation references a Windows startup location.",
        "high",
    )

    add(
        "registry_persistence",
        ("registry_access", "registry_run_key"),
        "Registry modification/access is combined with an autorun location.",
        "critical",
    )

    add(
        "wmi_discovery_execution",
        ("wmi", "activex_process"),
        "WMI automation appears together with process execution behavior.",
        "high",
    )

    add(
        "powershell_encoded_execution",
        ("powershell", "powershell_encoded"),
        "PowerShell execution is combined with an encoded-command argument.",
        "critical",
    )

    add(
        "powershell_download_execution",
        ("powershell", "powershell_download"),
        "PowerShell is associated with remote content retrieval.",
        "high",
    )

    add(
        "browser_script_injection",
        ("script_loading", "script_src"),
        "The source dynamically or declaratively loads script content.",
        "medium",
    )

    add(
        "credential_collection",
        ("credential_terms", "cookie_access"),
        "Credential-related terminology occurs with browser cookie access.",
        "high",
    )

    add(
        "anti_analysis",
        ("security_software", "virtual_machine_terms"),
        "Security-software and virtual-machine detection signals occur together.",
        "high",
    )

    return combinations


# ---------------------------------------------------------------------------
# Feature vector
# ---------------------------------------------------------------------------


def _build_feature_vector(
    text: str,
    indicators: Mapping[str, int],
    categories: Mapping[str, int],
    combinations: Sequence[JavaScriptCombination],
    functions: Sequence[JavaScriptFunction],
    activex_objects: Sequence[JavaScriptObject],
    urls: Sequence[str],
    identifiers: Sequence[str],
    strings: Sequence[str],
) -> Dict[str, Union[int, float, bool]]:
    features: Dict[str, Union[int, float, bool]] = {}

    source_stats = _source_statistics(text)
    string_stats = _string_statistics(strings)

    # Family/schema version
    features["javascript_schema_version"] = 1

    # Structural features
    for key, value in source_stats.items():
        features[f"javascript_{key}"] = value

    # String features
    for key, value in string_stats.items():
        features[f"javascript_{key}"] = value

    features["javascript_function_count"] = len(functions)
    features["javascript_activex_object_count"] = len(activex_objects)
    features["javascript_url_count"] = len(urls)
    features["javascript_identifier_count"] = len(identifiers)

    # Stable indicator presence/count features.
    for name in JS_INDICATORS:
        count = int(indicators.get(name, 0))
        features[f"javascript_indicator_{name}"] = int(count > 0)
        features[f"javascript_indicator_{name}_count"] = count

    # Stable category presence/count features.
    for category in JS_CATEGORIES:
        count = int(categories.get(category, 0))
        features[f"javascript_category_{category}"] = int(count > 0)
        features[f"javascript_category_{category}_count"] = count

    # Combination features.
    for combination in combinations:
        key = f"javascript_combination_{combination.name}"
        features[key] = int(combination.present)

    # Aggregate capability signals.
    high_risk_count = 0
    medium_or_higher_count = 0
    total_evidence = 0

    for name, count in indicators.items():
        if count <= 0:
            continue

        definition = INDICATOR_BY_NAME.get(name)
        if definition is None:
            continue

        total_evidence += count

        if _severity_rank(definition.severity) >= _severity_rank("high"):
            high_risk_count += count

        if _severity_rank(definition.severity) >= _severity_rank("medium"):
            medium_or_higher_count += count

    features["javascript_indicator_total"] = sum(indicators.values())
    features["javascript_high_risk_indicator_count"] = high_risk_count
    features["javascript_medium_or_higher_indicator_count"] = medium_or_higher_count
    features["javascript_evidence_count"] = total_evidence

    # Distinct category count.
    features["javascript_present_category_count"] = sum(
        1 for category in JS_CATEGORIES if categories.get(category, 0) > 0
    )

    features["javascript_present_indicator_count"] = sum(
        1 for name in JS_INDICATORS if indicators.get(name, 0) > 0
    )

    features["javascript_present_combination_count"] = sum(
        1 for combination in combinations if combination.present
    )

    # A bounded deterministic signal score.
    score = 0.0

    severity_weights = {
        "low": 0.5,
        "medium": 1.5,
        "high": 3.0,
        "critical": 5.0,
    }

    for name, count in indicators.items():
        definition = INDICATOR_BY_NAME.get(name)
        if definition is None:
            continue

        score += (
            min(count, 10)
            * severity_weights.get(
                definition.severity,
                1.0,
            )
            * definition.confidence
        )

    for combination in combinations:
        if combination.present:
            score += {
                "low": 1.0,
                "medium": 3.0,
                "high": 6.0,
                "critical": 10.0,
            }.get(combination.severity, 2.0)

    if string_stats["high_entropy_string_count"] > 0:
        score += (
            min(
                int(string_stats["high_entropy_string_count"]),
                20,
            )
            * 0.75
        )

    if string_stats["long_string_count"] > 0:
        score += (
            min(
                int(string_stats["long_string_count"]),
                20,
            )
            * 0.5
        )

    if source_stats["very_long_line_count"] > 0:
        score += (
            min(
                int(source_stats["very_long_line_count"]),
                20,
            )
            * 0.5
        )

    features["javascript_signal_score"] = round(
        min(score, 1000.0),
        4,
    )

    # Binary summary flags useful for CDR policy.
    features["javascript_has_dynamic_execution"] = int(
        categories.get("dynamic_execution", 0) > 0
    )
    features["javascript_has_activex"] = int(categories.get("activex", 0) > 0)
    features["javascript_has_network"] = int(categories.get("network", 0) > 0)
    features["javascript_has_download"] = int(categories.get("download", 0) > 0)
    features["javascript_has_filesystem"] = int(categories.get("filesystem", 0) > 0)
    features["javascript_has_process_execution"] = int(
        categories.get("process", 0) > 0 or categories.get("command", 0) > 0
    )
    features["javascript_has_persistence"] = int(categories.get("persistence", 0) > 0)
    features["javascript_has_obfuscation"] = int(
        categories.get("obfuscation", 0) > 0 or categories.get("encoding", 0) > 0
    )

    return features


# ---------------------------------------------------------------------------
# Public analysis API
# ---------------------------------------------------------------------------


def analyze_javascript(
    source: Union[str, bytes, bytearray, memoryview, Path],
    *,
    filename: Optional[str] = None,
    parser_analysis: Optional[ScriptAnalysis] = None,
) -> JavaScriptAnalysis:
    """
    Analyze JavaScript/JScript source statically.

    Parameters
    ----------
    source:
        JavaScript source text, bytes, or a local source Path.

    filename:
        Optional filename used for parser-family inference.

    parser_analysis:
        Optional result from script.parser.parse_script(). Supplying it avoids
        repeating the generic parser work when the caller already has it.

    Returns
    -------
    JavaScriptAnalysis
        Structured evidence and ML-ready feature vector.

    Raises
    ------
    ValueError
        If the source exceeds the configured safety limit.
    TypeError
        If source has an unsupported type.
    """
    text = _read_source(source)

    if len(text.encode("utf-8", errors="replace")) > MAX_FEATURE_TEXT:
        feature_text = text[:MAX_FEATURE_TEXT]
        truncated_for_features = True
    else:
        feature_text = text
        truncated_for_features = False

    if parser_analysis is None:
        parser_analysis = parse_script(
            text,
            filename=filename,
            family="javascript",
        )

    indicators, evidence = _match_indicators(feature_text)

    categories = _derive_categories(indicators)

    strings = _extract_js_strings(feature_text)
    identifiers = _extract_identifiers(feature_text)
    functions = _extract_functions(feature_text)
    activex_objects = _extract_activex_objects(feature_text)

    urls: List[str] = []
    seen_urls: set[str] = set()

    for match in _URL_RE.finditer(feature_text):
        if len(urls) >= MAX_URLS:
            break

        value = match.group(0).rstrip(".,;)]}")
        key = value.lower()

        if key in seen_urls:
            continue

        seen_urls.add(key)
        urls.append(value)

    # Protocol references are not necessarily URLs in the normal sense.
    # Count them through indicators, but retain only actual URLs here.

    combinations = _derive_combinations(indicators)

    feature_vector = _build_feature_vector(
        feature_text,
        indicators,
        categories,
        combinations,
        functions,
        activex_objects,
        urls,
        identifiers,
        strings,
    )

    # Merge selected generic parser information without making the generic
    # parser a hard dependency for the JavaScript-specific schema.
    generic_features = getattr(parser_analysis, "feature_vector", {}) or {}

    for key in (
        "script_line_count",
        "script_token_count",
        "script_string_count",
        "script_url_count",
        "script_identifier_count",
        "script_procedure_count",
        "script_signal_score",
    ):
        if key in generic_features:
            feature_vector[f"generic_{key}"] = generic_features[key]

    severity_candidates: List[str] = [
        definition.severity
        for name, count in indicators.items()
        if count > 0
        for definition in [INDICATOR_BY_NAME.get(name)]
        if definition is not None
    ]

    severity_candidates.extend(
        combination.severity for combination in combinations if combination.present
    )

    severity = _max_severity(severity_candidates)

    # Confidence is deliberately based on actual high-confidence static
    # matches, not on a claim of malware classification.
    confidence_values = [
        definition.confidence
        for name, count in indicators.items()
        if count > 0
        for definition in [INDICATOR_BY_NAME.get(name)]
        if definition is not None
    ]

    if confidence_values:
        confidence = round(
            sum(confidence_values) / len(confidence_values),
            4,
        )
    else:
        confidence = 0.0

    source_bytes = text.encode("utf-8", errors="replace")

    metadata = {
        "module": "pharos_cdr.extraction.script.javascript",
        "analyzer": "static_javascript",
        "schema_version": 1,
        "filename": filename,
        "input_encoding": "utf-8-replacement",
        "source_size_bytes": len(source_bytes),
        "feature_text_truncated": truncated_for_features,
        "generic_parser_family": getattr(
            parser_analysis,
            "family",
            None,
        ),
        "generic_parser_available": parser_analysis is not None,
        "execution_performed": False,
        "network_access_performed": False,
        "com_instantiation_performed": False,
        "filesystem_payload_extraction_performed": False,
    }

    return JavaScriptAnalysis(
        source_sha256=_source_sha256(text),
        source_size=len(source_bytes),
        line_count=len(text.splitlines()) or 1,
        family="javascript",
        indicators=dict(sorted(indicators.items())),
        categories=dict(sorted(categories.items())),
        evidence=evidence[:MAX_EVIDENCE_ITEMS],
        functions=functions,
        activex_objects=activex_objects,
        combinations=combinations,
        urls=urls,
        identifiers=identifiers,
        strings=strings,
        feature_vector=dict(sorted(feature_vector.items())),
        severity=severity,
        confidence=confidence,
        metadata=metadata,
    )


def analyze_javascript_file(
    path: Union[str, Path],
) -> JavaScriptAnalysis:
    """
    Analyze a local JavaScript/JScript file without executing it.
    """
    source_path = Path(path)

    return analyze_javascript(
        source_path,
        filename=source_path.name,
    )


def parse_javascript(
    source: Union[str, bytes, bytearray, memoryview, Path],
    *,
    filename: Optional[str] = None,
) -> JavaScriptAnalysis:
    """Alias for analyze_javascript()."""
    return analyze_javascript(
        source,
        filename=filename,
    )


def extract_javascript_features(
    source: Union[str, bytes, bytearray, memoryview, Path],
    *,
    filename: Optional[str] = None,
) -> Dict[str, Union[int, float, bool]]:
    """
    Return only the stable JavaScript feature vector.
    """
    return analyze_javascript(
        source,
        filename=filename,
    ).feature_vector


def extract_feature_vector(
    source: Union[str, bytes, bytearray, memoryview, Path],
    *,
    filename: Optional[str] = None,
) -> Dict[str, Union[int, float, bool]]:
    """Compatibility alias for feature-pipeline callers."""
    return extract_javascript_features(
        source,
        filename=filename,
    )


def extract_javascript_feature_vector(
    source: Union[str, bytes, bytearray, memoryview, Path],
    *,
    filename: Optional[str] = None,
) -> Dict[str, Union[int, float, bool]]:
    """Explicit feature-vector alias."""
    return extract_javascript_features(
        source,
        filename=filename,
    )


# ---------------------------------------------------------------------------
# Feature schema
# ---------------------------------------------------------------------------


def javascript_feature_names() -> List[str]:
    """
    Return the deterministic names of JavaScript-specific features.

    Structural/string aggregate features are included using their fixed
    schema names. Indicator/category/combinations are generated from the
    stable taxonomies above.
    """
    names: List[str] = [
        "javascript_schema_version",
        "javascript_line_count",
        "javascript_nonempty_line_count",
        "javascript_comment_line_count",
        "javascript_comment_ratio",
        "javascript_long_line_count",
        "javascript_very_long_line_count",
        "javascript_concatenation_count",
        "javascript_semicolon_count",
        "javascript_brace_count",
        "javascript_average_line_length",
        "javascript_max_line_length",
        "javascript_string_count",
        "javascript_string_total_length",
        "javascript_string_max_length",
        "javascript_string_mean_length",
        "javascript_long_string_count",
        "javascript_base64_like_string_count",
        "javascript_hex_like_string_count",
        "javascript_percent_encoded_string_count",
        "javascript_high_entropy_string_count",
        "javascript_function_count",
        "javascript_activex_object_count",
        "javascript_url_count",
        "javascript_identifier_count",
    ]

    for name in JS_INDICATORS:
        names.append(f"javascript_indicator_{name}")
        names.append(f"javascript_indicator_{name}_count")

    for category in JS_CATEGORIES:
        names.append(f"javascript_category_{category}")
        names.append(f"javascript_category_{category}_count")

    for combination in _derive_combinations({}):
        names.append(f"javascript_combination_{combination.name}")

    names.extend(
        [
            "javascript_indicator_total",
            "javascript_high_risk_indicator_count",
            "javascript_medium_or_higher_indicator_count",
            "javascript_evidence_count",
            "javascript_present_category_count",
            "javascript_present_indicator_count",
            "javascript_present_combination_count",
            "javascript_signal_score",
            "javascript_has_dynamic_execution",
            "javascript_has_activex",
            "javascript_has_network",
            "javascript_has_download",
            "javascript_has_filesystem",
            "javascript_has_process_execution",
            "javascript_has_persistence",
            "javascript_has_obfuscation",
        ]
    )

    return names


def build_feature_schema() -> Dict[str, Any]:
    """
    Build a JSON-serializable feature schema for dataset/model metadata.
    """
    names = javascript_feature_names()

    feature_types: Dict[str, str] = {}

    for name in names:
        if name.endswith("_ratio") or name.endswith("_score"):
            feature_types[name] = "float"
        elif name.endswith("_mean_length") or name.endswith("_average_line_length"):
            feature_types[name] = "float"
        else:
            feature_types[name] = "integer"

    return {
        "module": "pharos_cdr.extraction.script.javascript",
        "schema_version": 1,
        "feature_count": len(names),
        "features": names,
        "types": feature_types,
        "description": (
            "Stable static JavaScript/JScript feature vector. "
            "No JavaScript execution is performed."
        ),
    }


def vectorize_features(
    analysis: JavaScriptAnalysis,
    feature_names: Optional[Sequence[str]] = None,
) -> List[float]:
    """
    Convert an analysis into an ordered numeric vector.

    Missing features are represented as zero. This makes model inference
    resilient to older/newer analysis objects while preserving a caller-
    supplied schema order.
    """
    names = list(
        feature_names if feature_names is not None else javascript_feature_names()
    )

    return [float(analysis.feature_vector.get(name, 0.0)) for name in names]


# ---------------------------------------------------------------------------
# Query helpers
# ---------------------------------------------------------------------------


def has_indicator(
    analysis: JavaScriptAnalysis,
    indicator: str,
) -> bool:
    """Return whether an indicator was observed."""
    return analysis.indicators.get(indicator, 0) > 0


def indicator_count(
    analysis: JavaScriptAnalysis,
    indicator: str,
) -> int:
    """Return the occurrence count of an indicator."""
    return int(analysis.indicators.get(indicator, 0))


def has_category(
    analysis: JavaScriptAnalysis,
    category: str,
) -> bool:
    """Return whether a category has any evidence."""
    return analysis.categories.get(category, 0) > 0


def category_count(
    analysis: JavaScriptAnalysis,
    category: str,
) -> int:
    """Return the total indicator matches in a category."""
    return int(analysis.categories.get(category, 0))


def high_risk_indicators(
    analysis: JavaScriptAnalysis,
) -> List[str]:
    """Return observed high/critical-severity indicator names."""
    result: List[str] = []

    for name, count in analysis.indicators.items():
        if count <= 0:
            continue

        definition = INDICATOR_BY_NAME.get(name)
        if definition is None:
            continue

        if _severity_rank(definition.severity) >= _severity_rank("high"):
            result.append(name)

    return result


def present_combinations(
    analysis: JavaScriptAnalysis,
) -> List[JavaScriptCombination]:
    """Return only combinations whose required indicators are present."""
    return [combination for combination in analysis.combinations if combination.present]


def evidence_by_category(
    analysis: JavaScriptAnalysis,
    category: str,
) -> List[JavaScriptEvidence]:
    """Filter evidence by category."""
    normalized = category.strip().lower()

    return [item for item in analysis.evidence if item.category.lower() == normalized]


def evidence_by_indicator(
    analysis: JavaScriptAnalysis,
    indicator: str,
) -> List[JavaScriptEvidence]:
    """Filter evidence by indicator name."""
    normalized = indicator.strip().lower()

    return [item for item in analysis.evidence if item.indicator.lower() == normalized]


# ---------------------------------------------------------------------------
# Serialization / reporting helpers
# ---------------------------------------------------------------------------


def analysis_to_dict(
    analysis: JavaScriptAnalysis,
) -> Dict[str, Any]:
    """
    Convert JavaScriptAnalysis to a JSON-serializable dictionary.
    """
    return asdict(analysis)


def summarize_javascript(
    analysis: JavaScriptAnalysis,
) -> Dict[str, Any]:
    """
    Produce a compact summary suitable for pipeline reports.
    """
    present_indicator_names = [
        name for name, count in analysis.indicators.items() if count > 0
    ]

    present_category_names = [
        name for name, count in analysis.categories.items() if count > 0
    ]

    present_combination_names = [
        combination.name for combination in analysis.combinations if combination.present
    ]

    return {
        "family": analysis.family,
        "source_sha256": analysis.source_sha256,
        "source_size": analysis.source_size,
        "line_count": analysis.line_count,
        "severity": analysis.severity,
        "confidence": analysis.confidence,
        "indicator_count": len(present_indicator_names),
        "indicators": present_indicator_names,
        "categories": present_category_names,
        "combinations": present_combination_names,
        "activex_object_count": len(analysis.activex_objects),
        "function_count": len(analysis.functions),
        "url_count": len(analysis.urls),
        "string_count": len(analysis.strings),
        "high_risk_indicators": high_risk_indicators(analysis),
        "signal_score": analysis.feature_vector.get(
            "javascript_signal_score",
            0.0,
        ),
    }


def iter_evidence(
    analysis: JavaScriptAnalysis,
) -> Iterator[JavaScriptEvidence]:
    """Iterate static JavaScript evidence records."""
    yield from analysis.evidence


def iter_functions(
    analysis: JavaScriptAnalysis,
) -> Iterator[JavaScriptFunction]:
    """Iterate extracted JavaScript functions."""
    yield from analysis.functions


def iter_activex_objects(
    analysis: JavaScriptAnalysis,
) -> Iterator[JavaScriptObject]:
    """Iterate statically identified ActiveX/COM objects."""
    yield from analysis.activex_objects


def iter_combinations(
    analysis: JavaScriptAnalysis,
) -> Iterator[JavaScriptCombination]:
    """Iterate all derived capability combinations."""
    yield from analysis.combinations


# ---------------------------------------------------------------------------
# Focused extraction helpers
# ---------------------------------------------------------------------------


def find_activex_objects(
    source: Union[str, bytes, bytearray, memoryview, Path],
) -> List[JavaScriptObject]:
    """Extract ActiveX/COM object names without returning a full analysis."""
    text = _read_source(source)
    return _extract_activex_objects(text)


def find_javascript_functions(
    source: Union[str, bytes, bytearray, memoryview, Path],
) -> List[JavaScriptFunction]:
    """Extract lightweight JavaScript function metadata."""
    text = _read_source(source)
    return _extract_functions(text)


def find_javascript_urls(
    source: Union[str, bytes, bytearray, memoryview, Path],
) -> List[str]:
    """Extract literal HTTP/HTTPS/FTP URLs from source."""
    text = _read_source(source)

    urls: List[str] = []
    seen: set[str] = set()

    for match in _URL_RE.finditer(text):
        if len(urls) >= MAX_URLS:
            break

        value = match.group(0).rstrip(".,;)]}")
        key = value.lower()

        if key in seen:
            continue

        seen.add(key)
        urls.append(value)

    return urls


def find_protocols(
    source: Union[str, bytes, bytearray, memoryview, Path],
) -> List[str]:
    """Return JavaScript/VBScript/data protocol occurrences."""
    text = _read_source(source)

    result: List[str] = []
    seen: set[str] = set()

    for match in _PROTOCOL_RE.finditer(text):
        value = match.group(0).lower()

        if value in seen:
            continue

        seen.add(value)
        result.append(value)

    return result


# ---------------------------------------------------------------------------
# Pipeline compatibility aliases
# ---------------------------------------------------------------------------

parse = parse_javascript
analyze = analyze_javascript
extract = extract_javascript_features
extract_features = extract_javascript_features
feature_names = javascript_feature_names


__all__ = [
    "MAX_SOURCE_SIZE",
    "MAX_EVIDENCE_ITEMS",
    "MAX_STRINGS",
    "MAX_URLS",
    "MAX_IDENTIFIERS",
    "MAX_FUNCTIONS",
    "MAX_FEATURE_TEXT",
    "JS_CATEGORIES",
    "JS_INDICATORS",
    "JSIndicatorDefinition",
    "JavaScriptEvidence",
    "JavaScriptFunction",
    "JavaScriptObject",
    "JavaScriptCombination",
    "JavaScriptAnalysis",
    "analyze_javascript",
    "analyze_javascript_file",
    "parse_javascript",
    "extract_javascript_features",
    "extract_feature_vector",
    "extract_javascript_feature_vector",
    "javascript_feature_names",
    "build_feature_schema",
    "vectorize_features",
    "has_indicator",
    "indicator_count",
    "has_category",
    "category_count",
    "high_risk_indicators",
    "present_combinations",
    "evidence_by_category",
    "evidence_by_indicator",
    "analysis_to_dict",
    "summarize_javascript",
    "iter_evidence",
    "iter_functions",
    "iter_activex_objects",
    "iter_combinations",
    "find_activex_objects",
    "find_javascript_functions",
    "find_javascript_urls",
    "find_protocols",
    "parse",
    "analyze",
    "extract",
    "extract_features",
    "feature_names",
]
