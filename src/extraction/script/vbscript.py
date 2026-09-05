"""
pharos-cdr/src/extraction/script/vbscript.py

Static VBScript/JScript-hosted VBScript feature extraction for Pharos CDR.

This module performs defensive, non-executing analysis of VBScript source.
It is intended for .vbs/.vbe/.wsf/.hta and other script-bearing content where
VBScript syntax may be embedded.

Security properties
-------------------
- Never executes VBScript.
- Never invokes WScript, COM, ActiveX, or WMI.
- Never launches processes.
- Never performs network requests.
- Never resolves or follows URLs.
- Never evaluates VBScript expressions.
- Never writes extracted payloads to disk.
- Applies bounded source/evidence limits.

Analysis flow
-------------
    source
      |
      v
    script/parser.py
      |
      v
    VBScript-specific static indicators
      |
      +--> execution / COM / filesystem / registry
      +--> network / download / payload handling
      +--> persistence / discovery / credentials
      +--> obfuscation / encoding / string construction
      +--> suspicious capability combinations
      |
      v
    stable feature vector
      |
      v
    feature_pipeline.py / ML / CDR policy
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
        parse_script,
    )
except ImportError:  # pragma: no cover
    from parser import (
        ScriptAnalysis,
        parse_script,
    )


# ---------------------------------------------------------------------------
# Safety limits
# ---------------------------------------------------------------------------

MAX_SOURCE_SIZE = 25 * 1024 * 1024
MAX_FEATURE_TEXT = 2 * 1024 * 1024
MAX_EVIDENCE_ITEMS = 10_000
MAX_STRINGS = 10_000
MAX_URLS = 2_000
MAX_IDENTIFIERS = 20_000
MAX_PROCEDURES = 5_000
MAX_OBJECTS = 5_000


# ---------------------------------------------------------------------------
# Taxonomy
# ---------------------------------------------------------------------------

VBSCRIPT_CATEGORIES: Tuple[str, ...] = (
    "execution",
    "dynamic_execution",
    "com_automation",
    "wscript",
    "activex",
    "process",
    "filesystem",
    "registry",
    "network",
    "download",
    "payload",
    "persistence",
    "discovery",
    "credential_access",
    "collection",
    "environment",
    "security_software",
    "evasion",
    "obfuscation",
    "encoding",
    "reflection",
    "document",
    "browser",
    "command",
    "configuration",
)

# Stable names intended for feature schema/model compatibility.
VBSCRIPT_INDICATORS: Tuple[str, ...] = (
    "execute",
    "executeglobal",
    "eval",
    "getref",
    "callbyname",
    "run_method",
    "exec_method",
    "wscript_shell",
    "wscript_network",
    "wscript_createobject",
    "wscript_arguments",
    "wscript_environment",
    "wscript_scriptfullname",
    "wscript_working_directory",
    "filesystem_object",
    "open_text_file",
    "create_text_file",
    "file_read",
    "file_write",
    "file_copy",
    "file_move",
    "file_delete",
    "folder_access",
    "drive_access",
    "registry_read",
    "registry_write",
    "registry_delete",
    "registry_run_key",
    "registry_runonce_key",
    "registry_startup",
    "xmlhttp",
    "serverxmlhttp",
    "winhttp",
    "http_open",
    "http_send",
    "http_response_body",
    "http_response_text",
    "download",
    "download_to_file",
    "adodb_stream",
    "adodb_recordset",
    "scriptlet",
    "xml_dom",
    "xml_data_island",
    "powershell",
    "cmd",
    "cscript",
    "wscript",
    "mshta",
    "rundll32",
    "regsvr32",
    "certutil",
    "bitsadmin",
    "schtasks",
    "javascript_protocol",
    "vbscript_protocol",
    "data_protocol",
    "base64",
    "base64_decode",
    "base64_encode",
    "fromcharcode",
    "chr_construction",
    "chrw_construction",
    "asc_transformation",
    "hex_transformation",
    "replace_chain",
    "split_join",
    "reverse_string",
    "string_concatenation",
    "large_string",
    "high_entropy_string",
    "hex_escape",
    "unicode_escape",
    "environment_variables",
    "environment_variable_expansion",
    "computer_name",
    "username",
    "user_domain",
    "temp_path",
    "appdata_path",
    "programdata_path",
    "systemroot_path",
    "process_enumeration",
    "wmi",
    "security_software",
    "antivirus_terms",
    "sandbox_terms",
    "virtual_machine_terms",
    "debugger_terms",
    "credential_terms",
    "clipboard_terms",
    "cookie_terms",
    "startup_folder",
    "scheduled_task",
    "service_creation",
    "self_reference",
    "embedded_script",
    "urlmon",
    "xmlhttp_object",
    "persistence_command",
    "powershell_encoded",
    "powershell_download",
    "powershell_reflection",
    "comment_density",
    "long_line",
    "very_long_line",
    "identifier_density",
    "token_density",
)


# ---------------------------------------------------------------------------
# Indicator definitions
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class VBScriptIndicatorDefinition:
    """Definition of one static VBScript indicator."""

    name: str
    category: str
    severity: str
    confidence: float
    patterns: Tuple[re.Pattern[str], ...]
    description: str


def _compile_many(
    *patterns: str,
    flags: int = re.IGNORECASE,
) -> Tuple[re.Pattern[str], ...]:
    return tuple(re.compile(pattern, flags) for pattern in patterns)


def _indicator(
    name: str,
    category: str,
    severity: str,
    confidence: float,
    *patterns: str,
    description: str,
) -> VBScriptIndicatorDefinition:
    return VBScriptIndicatorDefinition(
        name=name,
        category=category,
        severity=severity,
        confidence=confidence,
        patterns=_compile_many(*patterns),
        description=description,
    )


INDICATOR_DEFINITIONS: Tuple[VBScriptIndicatorDefinition, ...] = (
    _indicator(
        "execute",
        "dynamic_execution",
        "high",
        0.99,
        r"\bExecute\s+",
        r"\bExecute\s*\(",
        description="VBScript Execute dynamically interprets generated source.",
    ),
    _indicator(
        "executeglobal",
        "dynamic_execution",
        "critical",
        0.99,
        r"\bExecuteGlobal\s+",
        r"\bExecuteGlobal\s*\(",
        description="VBScript ExecuteGlobal dynamically executes generated global source.",
    ),
    _indicator(
        "eval",
        "dynamic_execution",
        "high",
        0.96,
        r"\bEval\s*\(",
        description="VBScript Eval evaluates an expression dynamically.",
    ),
    _indicator(
        "getref",
        "reflection",
        "high",
        0.96,
        r"\bGetRef\s*\(",
        description="GetRef resolves a procedure reference dynamically.",
    ),
    _indicator(
        "callbyname",
        "reflection",
        "high",
        0.96,
        r"\bCallByName\s*\(",
        description="CallByName dynamically invokes an object member.",
    ),
    _indicator(
        "run_method",
        "execution",
        "high",
        0.97,
        r"\.\s*Run\s+",
        r"\.\s*Run\s*\(",
        description="Object Run method may invoke a command depending on the object.",
    ),
    _indicator(
        "exec_method",
        "execution",
        "high",
        0.97,
        r"\.\s*Exec\s+",
        r"\.\s*Exec\s*\(",
        description="Object Exec method may launch a command or process.",
    ),
    _indicator(
        "wscript_shell",
        "wscript",
        "high",
        0.99,
        r"\bWScript\.Shell\b",
        r"\bCreateObject\s*\(\s*['\"]WScript\.Shell['\"]",
        description="Windows Script Host shell automation.",
    ),
    _indicator(
        "wscript_network",
        "wscript",
        "medium",
        0.96,
        r"\bWScript\.Network\b",
        r"\bCreateObject\s*\(\s*['\"]WScript\.Network(?:\.1)?['\"]",
        description="Windows Script Host network automation.",
    ),
    _indicator(
        "wscript_createobject",
        "com_automation",
        "medium",
        0.96,
        r"\bWScript\.CreateObject\s*\(",
        description="WScript COM object creation.",
    ),
    _indicator(
        "wscript_arguments",
        "wscript",
        "low",
        0.94,
        r"\bWScript\.Arguments\b",
        description="WScript command-line argument access.",
    ),
    _indicator(
        "wscript_environment",
        "environment",
        "medium",
        0.94,
        r"\bWScript\.Shell\b[^;\r\n]{0,500}\.Environment\b",
        r"\.Environment\s*\(",
        description="Windows environment-variable access.",
    ),
    _indicator(
        "wscript_scriptfullname",
        "environment",
        "low",
        0.90,
        r"\bWScript\.ScriptFullName\b",
        r"\bWScript\.ScriptName\b",
        description="Script path/name introspection.",
    ),
    _indicator(
        "wscript_working_directory",
        "environment",
        "low",
        0.88,
        r"\bWScript\.Shell\b[^;\r\n]{0,500}\.CurrentDirectory\b",
        r"\.CurrentDirectory\b",
        description="Current working-directory access.",
    ),
    _indicator(
        "filesystem_object",
        "filesystem",
        "high",
        0.99,
        r"\bScripting\.FileSystemObject\b",
        r"\bFileSystemObject\b",
        r"\bCreateObject\s*\(\s*['\"]Scripting\.FileSystemObject['\"]",
        description="Scripting.FileSystemObject provides broad filesystem access.",
    ),
    _indicator(
        "open_text_file",
        "filesystem",
        "medium",
        0.98,
        r"\bOpenTextFile\s*\(",
        description="Opening a text file through FileSystemObject.",
    ),
    _indicator(
        "create_text_file",
        "filesystem",
        "medium",
        0.98,
        r"\bCreateTextFile\s*\(",
        description="Creating a text file through FileSystemObject.",
    ),
    _indicator(
        "file_read",
        "filesystem",
        "medium",
        0.96,
        r"\.(?:Read|ReadLine|ReadAll)\b",
        description="Reading content from a file/stream.",
    ),
    _indicator(
        "file_write",
        "filesystem",
        "medium",
        0.96,
        r"\.(?:Write|WriteLine|WriteBlankLines)\b",
        description="Writing content to a file/stream.",
    ),
    _indicator(
        "file_copy",
        "filesystem",
        "medium",
        0.97,
        r"\bCopyFile\b",
        r"\bCopyFolder\b",
        description="Copying filesystem objects.",
    ),
    _indicator(
        "file_move",
        "filesystem",
        "medium",
        0.97,
        r"\bMoveFile\b",
        r"\bMoveFolder\b",
        description="Moving filesystem objects.",
    ),
    _indicator(
        "file_delete",
        "filesystem",
        "high",
        0.97,
        r"\bDeleteFile\b",
        r"\bDeleteFolder\b",
        description="Deleting filesystem objects.",
    ),
    _indicator(
        "folder_access",
        "filesystem",
        "medium",
        0.95,
        r"\b(?:GetFolder|SubFolders|Files)\b",
        description="Folder/file enumeration.",
    ),
    _indicator(
        "drive_access",
        "filesystem",
        "medium",
        0.94,
        r"\b(?:Drives|GetDrive|DriveExists)\b",
        description="Drive enumeration or access.",
    ),
    _indicator(
        "registry_read",
        "registry",
        "high",
        0.99,
        r"\.(?:RegRead)\s*\(",
        r"\bRegRead\s*\(",
        description="Windows registry read operation.",
    ),
    _indicator(
        "registry_write",
        "registry",
        "high",
        0.99,
        r"\.(?:RegWrite)\s*\(",
        r"\bRegWrite\s*\(",
        description="Windows registry write operation.",
    ),
    _indicator(
        "registry_delete",
        "registry",
        "high",
        0.99,
        r"\.(?:RegDelete)\s*\(",
        r"\bRegDelete\s*\(",
        description="Windows registry delete operation.",
    ),
    _indicator(
        "registry_run_key",
        "persistence",
        "critical",
        0.99,
        r"CurrentVersion\\Run(?:['\"\\]|$)",
        r"CurrentVersion\\Run\\",
        description="Windows Run autorun registry location.",
    ),
    _indicator(
        "registry_runonce_key",
        "persistence",
        "critical",
        0.99,
        r"CurrentVersion\\RunOnce",
        description="Windows RunOnce autorun registry location.",
    ),
    _indicator(
        "registry_startup",
        "persistence",
        "high",
        0.98,
        r"(?:Winlogon\\Shell|Winlogon\\Userinit|Explorer\\User Shell Folders|StartupApproved)",
        description="Registry locations associated with startup/persistence.",
    ),
    _indicator(
        "xmlhttp",
        "network",
        "high",
        0.98,
        r"\bMSXML2\.(?:XMLHTTP|ServerXMLHTTP)",
        r"\bMicrosoft\.XMLHTTP\b",
        r"\bXMLHTTP\b",
        description="MSXML HTTP client.",
    ),
    _indicator(
        "serverxmlhttp",
        "network",
        "high",
        0.98,
        r"\bServerXMLHTTP\b",
        r"\bMSXML2\.ServerXMLHTTP",
        description="MSXML ServerXMLHTTP network client.",
    ),
    _indicator(
        "winhttp",
        "network",
        "high",
        0.98,
        r"\bWinHttp\.WinHttpRequest\b",
        r"\bWinHttpRequest\b",
        description="WinHTTP request object.",
    ),
    _indicator(
        "http_open",
        "network",
        "medium",
        0.96,
        r"\.\s*Open\s+['\"]?(?:GET|POST|PUT|HEAD|OPTIONS|DELETE)\b",
        r"\.\s*Open\s*\(\s*['\"](?:GET|POST|PUT|HEAD|OPTIONS|DELETE)['\"]",
        description="HTTP request method initialization.",
    ),
    _indicator(
        "http_send",
        "network",
        "medium",
        0.96,
        r"\.\s*Send\s+",
        r"\.\s*Send\s*\(",
        description="HTTP request transmission.",
    ),
    _indicator(
        "http_response_body",
        "payload",
        "high",
        0.98,
        r"\.ResponseBody\b",
        description="Binary HTTP response access.",
    ),
    _indicator(
        "http_response_text",
        "payload",
        "medium",
        0.94,
        r"\.ResponseText\b",
        description="Text HTTP response access.",
    ),
    _indicator(
        "download",
        "download",
        "high",
        0.96,
        r"\b(?:Download|DownloadFile|DownloadString)\b",
        r"\b(?:URLDownloadToFile|URLDownloadToCacheFile)\b",
        description="Remote content retrieval reference.",
    ),
    _indicator(
        "download_to_file",
        "download",
        "critical",
        0.99,
        r"\bURLDownloadToFile\b",
        r"\b(?:SaveToFile|DownloadFile)\s*\(",
        description="Potential remote-content transfer into a local file.",
    ),
    _indicator(
        "adodb_stream",
        "payload",
        "high",
        0.99,
        r"\bADODB\.Stream\b",
        r"\bCreateObject\s*\(\s*['\"]ADODB\.Stream['\"]",
        description="ADODB.Stream content/binary data handling.",
    ),
    _indicator(
        "adodb_recordset",
        "payload",
        "medium",
        0.94,
        r"\bADODB\.Recordset\b",
        r"\bCreateObject\s*\(\s*['\"]ADODB\.Recordset['\"]",
        description="ADODB Recordset object.",
    ),
    _indicator(
        "scriptlet",
        "execution",
        "high",
        0.98,
        r"\bScriptlet\.TypeLib\b",
        r"\bScriptlet\.TypeLib\b",
        description="Scriptlet.TypeLib COM automation reference.",
    ),
    _indicator(
        "xml_dom",
        "document",
        "low",
        0.86,
        r"\bMSXML2\.DOMDocument\b",
        r"\bDOMDocument\b",
        description="MSXML DOM document object.",
    ),
    _indicator(
        "xml_data_island",
        "document",
        "medium",
        0.84,
        r"\bXMLHTTP\b[^;\r\n]{0,500}\bresponseXML\b",
        r"\bresponseXML\b",
        description="XML response processing.",
    ),
    _indicator(
        "powershell",
        "command",
        "high",
        0.99,
        r"\b(?:powershell|pwsh)(?:\.exe)?\b",
        description="PowerShell command reference.",
    ),
    _indicator(
        "cmd",
        "command",
        "high",
        0.99,
        r"\bcmd(?:\.exe)?\b",
        r"(?:/c|/k)\s+",
        description="Windows command interpreter reference.",
    ),
    _indicator(
        "cscript",
        "command",
        "high",
        0.99,
        r"\bcscript(?:\.exe)?\b",
        description="Cscript interpreter reference.",
    ),
    _indicator(
        "wscript",
        "command",
        "high",
        0.99,
        r"\bwscript(?:\.exe)?\b",
        description="Wscript interpreter reference.",
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
        "schtasks",
        "persistence",
        "high",
        0.99,
        r"\bschtasks(?:\.exe)?\b",
        description="Scheduled-task persistence reference.",
    ),
    _indicator(
        "javascript_protocol",
        "browser",
        "medium",
        0.95,
        r"\bjavascript\s*:",
        description="JavaScript protocol reference.",
    ),
    _indicator(
        "vbscript_protocol",
        "browser",
        "medium",
        0.97,
        r"\bvbscript\s*:",
        description="VBScript protocol reference.",
    ),
    _indicator(
        "data_protocol",
        "browser",
        "medium",
        0.90,
        r"\bdata\s*:",
        description="Data URL protocol reference.",
    ),
    _indicator(
        "base64",
        "encoding",
        "medium",
        0.89,
        r"\bbase64\b",
        r"\b(?:MIME|ADODB\.Stream)\b[^;\r\n]{0,500}\bbase64\b",
        description="Base64 encoding terminology or processing.",
    ),
    _indicator(
        "base64_decode",
        "encoding",
        "medium",
        0.94,
        r"\b(?:FromBase64String|DecodeBase64|Base64Decode)\b",
        r"\bbase64[^;\r\n]{0,100}(?:decode|decoding)\b",
        description="Base64 decoding reference.",
    ),
    _indicator(
        "base64_encode",
        "encoding",
        "low",
        0.88,
        r"\b(?:ToBase64String|EncodeBase64|Base64Encode)\b",
        r"\bbase64[^;\r\n]{0,100}(?:encode|encoding)\b",
        description="Base64 encoding reference.",
    ),
    _indicator(
        "fromcharcode",
        "obfuscation",
        "medium",
        0.94,
        r"\bString\.fromCharCode\b",
        description="JavaScript-style character-code construction embedded in script.",
    ),
    _indicator(
        "chr_construction",
        "obfuscation",
        "medium",
        0.94,
        r"\bChr\$?\s*\(",
        description="VBScript Chr-based string construction.",
    ),
    _indicator(
        "chrw_construction",
        "obfuscation",
        "medium",
        0.94,
        r"\bChrW\$?\s*\(",
        description="VBScript Unicode character construction.",
    ),
    _indicator(
        "asc_transformation",
        "obfuscation",
        "low",
        0.82,
        r"\bAscW?\s*\(",
        description="Character-code transformation.",
    ),
    _indicator(
        "hex_transformation",
        "obfuscation",
        "medium",
        0.88,
        r"\b(?:Hex|CInt|CLng)\s*\(",
        description="Numeric/string transformation primitives.",
    ),
    _indicator(
        "replace_chain",
        "obfuscation",
        "medium",
        0.88,
        r"(?:\bReplace\s*\([^;\r\n]{0,300}\)){3,}",
        description="Repeated Replace calls can indicate string deobfuscation.",
    ),
    _indicator(
        "split_join",
        "obfuscation",
        "medium",
        0.84,
        r"\b(?:Split|Join)\s*\(",
        description="String splitting/joining transformation.",
    ),
    _indicator(
        "reverse_string",
        "obfuscation",
        "medium",
        0.86,
        r"\bStrReverse\s*\(",
        description="VBScript string reversal.",
    ),
    _indicator(
        "string_concatenation",
        "obfuscation",
        "low",
        0.78,
        r"""(?:"[^"\r\n]{1,100}"|'[^'\r\n]{1,100}')\s*&\s*(?:"|'|[A-Za-z_])""",
        description="String concatenation that may contribute to generated source.",
    ),
    _indicator(
        "large_string",
        "obfuscation",
        "low",
        0.82,
        r"""["'][^"'\r\n]{512,}["']""",
        description="Very large string literal.",
    ),
    _indicator(
        "high_entropy_string",
        "obfuscation",
        "medium",
        0.86,
        r"""["'][A-Za-z0-9+/=_-]{128,}["']""",
        description="Long high-entropy-looking string literal.",
    ),
    _indicator(
        "hex_escape",
        "obfuscation",
        "medium",
        0.87,
        r"(?:\\x[0-9A-Fa-f]{2}){3,}",
        description="Repeated hexadecimal escape sequence.",
    ),
    _indicator(
        "unicode_escape",
        "obfuscation",
        "medium",
        0.87,
        r"(?:\\u[0-9A-Fa-f]{4}){2,}",
        description="Repeated Unicode escape sequence.",
    ),
    _indicator(
        "environment_variables",
        "environment",
        "medium",
        0.92,
        r"\bExpandEnvironmentStrings\s*\(",
        r"\bEnvironment\s*\(",
        description="Windows environment-variable expansion/access.",
    ),
    _indicator(
        "environment_variable_expansion",
        "environment",
        "low",
        0.86,
        r"%[A-Za-z_][A-Za-z0-9_]+%",
        description="Windows environment-variable syntax.",
    ),
    _indicator(
        "computer_name",
        "discovery",
        "medium",
        0.91,
        r"\b(?:ComputerName|COMPUTERNAME|HostName|hostname)\b",
        description="Host identity discovery reference.",
    ),
    _indicator(
        "username",
        "discovery",
        "medium",
        0.91,
        r"\b(?:UserName|USERNAME|USERPROFILE)\b",
        description="User identity discovery reference.",
    ),
    _indicator(
        "user_domain",
        "discovery",
        "medium",
        0.91,
        r"\b(?:UserDomain|USERDOMAIN)\b",
        description="Windows domain identity discovery reference.",
    ),
    _indicator(
        "temp_path",
        "environment",
        "medium",
        0.90,
        r"(?:%TEMP%|%TMP%|\\Temp\\|\\Temporary Internet Files\\)",
        description="Temporary directory reference.",
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
        description="Windows system-directory reference.",
    ),
    _indicator(
        "process_enumeration",
        "discovery",
        "high",
        0.97,
        r"\bWin32_Process\b",
        r"\bSELECT\s+.*\s+FROM\s+Win32_Process\b",
        description="Process enumeration through WMI.",
    ),
    _indicator(
        "wmi",
        "discovery",
        "high",
        0.98,
        r"\bWbemScripting\.SWbemLocator\b",
        r"\bSWbemLocator\b",
        r"\bSWbemServices\b",
        r"\bWin32_[A-Za-z0-9_]+\b",
        description="Windows Management Instrumentation reference.",
    ),
    _indicator(
        "security_software",
        "security_software",
        "high",
        0.94,
        r"\b(?:AntiVirusProduct|SecurityCenter2|SecurityCenter|Win32_QuickFixEngineering)\b",
        r"\b(?:Defender|Windows Defender|Endpoint Protection)\b",
        description="Security-software discovery reference.",
    ),
    _indicator(
        "antivirus_terms",
        "security_software",
        "medium",
        0.79,
        r"\b(?:antivirus|anti-virus|defender|security software|endpoint protection)\b",
        description="Antivirus/security terminology.",
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
        0.79,
        r"\b(?:virtualbox|vmware|hyper-v|virtual machine|vboxservice)\b",
        description="Virtual-machine detection terminology.",
    ),
    _indicator(
        "debugger_terms",
        "evasion",
        "medium",
        0.80,
        r"\b(?:debugger|isdebuggerpresent|ollydbg|windbg|x64dbg)\b",
        description="Debugger/analysis detection terminology.",
    ),
    _indicator(
        "credential_terms",
        "credential_access",
        "medium",
        0.77,
        r"\b(?:password|credential|logon|token|secret|credential manager)\b",
        description="Credential-related terminology.",
    ),
    _indicator(
        "clipboard_terms",
        "collection",
        "medium",
        0.86,
        r"\b(?:clipboard|htmlfile).*?(?:ParentWindow|DataObject|GetData)\b",
        r"\b(?:ClipboardData|GetClipboardData)\b",
        description="Clipboard access terminology/API reference.",
    ),
    _indicator(
        "cookie_terms",
        "collection",
        "medium",
        0.86,
        r"\bdocument\.cookie\b",
        r"\bcookie\b",
        description="Browser cookie access/reference.",
    ),
    _indicator(
        "startup_folder",
        "persistence",
        "high",
        0.98,
        r"(?:\\Start Menu\\Programs\\Startup|\\Startup\\)",
        description="Windows Startup-folder reference.",
    ),
    _indicator(
        "scheduled_task",
        "persistence",
        "high",
        0.99,
        r"\bschtasks(?:\.exe)?\b",
        r"\bSchedule\.Service\b",
        description="Scheduled-task persistence reference.",
    ),
    _indicator(
        "service_creation",
        "persistence",
        "high",
        0.97,
        r"\b(?:CreateService|OpenSCManager|Win32_Service|New-Service)\b",
        description="Windows service creation/control reference.",
    ),
    _indicator(
        "self_reference",
        "document",
        "low",
        0.86,
        r"\bWScript\.ScriptFullName\b",
        r"\bGetParentFolderName\s*\(\s*WScript\.ScriptFullName",
        description="Self-referential script path access.",
    ),
    _indicator(
        "embedded_script",
        "document",
        "medium",
        0.88,
        r"<script\b",
        r"<%[^%]*%>",
        r"\bVBScript\b",
        description="VBScript embedded in an HTML/hosted script context.",
    ),
    _indicator(
        "urlmon",
        "download",
        "high",
        0.98,
        r"\bURLMon\b",
        r"\bURLDownloadToFile\b",
        description="URLMon-based remote content retrieval.",
    ),
    _indicator(
        "xmlhttp_object",
        "network",
        "high",
        0.97,
        r"\bCreateObject\s*\(\s*['\"](?:MSXML2\.)?(?:XMLHTTP|ServerXMLHTTP)",
        description="Creation of an XMLHTTP network object.",
    ),
    _indicator(
        "persistence_command",
        "persistence",
        "high",
        0.98,
        r"\b(?:schtasks|sc\.exe|reg\.exe)\b[^;\r\n]{0,500}(?:create|add|run|startup)",
        description="Command-line persistence utility reference.",
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
        description="PowerShell remote-content retrieval reference.",
    ),
    _indicator(
        "powershell_reflection",
        "reflection",
        "high",
        0.98,
        r"(?:powershell|pwsh)[^;\r\n]{0,500}(?:Reflection\.Assembly|Assembly\.Load|LoadWithPartialName)",
        description="PowerShell reflection/assembly loading reference.",
    ),
    _indicator(
        "comment_density",
        "configuration",
        "low",
        0.70,
        r"(?m)^\s*'",
        r"(?m)^\s*REM\b",
        description="Comment-heavy source structure.",
    ),
    _indicator(
        "long_line",
        "configuration",
        "low",
        0.72,
        r"(?m)^.{1000,}$",
        description="Very long source line.",
    ),
    _indicator(
        "very_long_line",
        "configuration",
        "medium",
        0.78,
        r"(?m)^.{10000,}$",
        description="Extremely long source line.",
    ),
    _indicator(
        "identifier_density",
        "configuration",
        "low",
        0.70,
        r"\b(?:Dim|Private|Public|Function|Sub|Property)\b",
        description="VBScript declaration structure.",
    ),
    _indicator(
        "token_density",
        "configuration",
        "low",
        0.65,
        r"(?m)^.{0,2000}$",
        description="General source-structure indicator.",
    ),
)


INDICATOR_BY_NAME: Dict[str, VBScriptIndicatorDefinition] = {
    item.name: item for item in INDICATOR_DEFINITIONS
}


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class VBScriptEvidence:
    """One static VBScript finding."""

    indicator: str
    category: str
    severity: str
    confidence: float
    evidence: str
    line_number: Optional[int] = None
    source: str = "vbscript"
    description: str = ""


@dataclass(frozen=True)
class VBScriptProcedure:
    """Lightweight VBScript Sub/Function metadata."""

    name: str
    kind: str
    line_number: Optional[int]
    parameters: Tuple[str, ...] = ()
    evidence: str = ""


@dataclass(frozen=True)
class VBScriptObject:
    """A statically identified CreateObject/GetObject target."""

    object_name: str
    constructor: str
    line_number: Optional[int]
    risk: str = "medium"


@dataclass(frozen=True)
class VBScriptCombination:
    """A derived multi-indicator capability combination."""

    name: str
    present: bool
    required_indicators: Tuple[str, ...]
    explanation: str
    severity: str = "medium"


@dataclass
class VBScriptAnalysis:
    """Complete VBScript static-analysis result."""

    source_sha256: str
    source_size: int
    line_count: int
    family: str

    indicators: Dict[str, int] = field(default_factory=dict)
    categories: Dict[str, int] = field(default_factory=dict)

    evidence: List[VBScriptEvidence] = field(default_factory=list)
    procedures: List[VBScriptProcedure] = field(default_factory=list)
    objects: List[VBScriptObject] = field(default_factory=list)

    urls: List[str] = field(default_factory=list)
    identifiers: List[str] = field(default_factory=list)
    strings: List[str] = field(default_factory=list)

    combinations: List[VBScriptCombination] = field(default_factory=list)

    feature_vector: Dict[str, Union[int, float, bool]] = field(default_factory=dict)

    severity: str = "low"
    confidence: float = 0.0

    metadata: Dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Generic helpers
# ---------------------------------------------------------------------------


def _read_source(
    source: Union[str, bytes, bytearray, memoryview, Path],
) -> str:
    """Read bounded VBScript source without interpreting it."""
    if isinstance(source, Path):
        data = source.read_bytes()
        if len(data) > MAX_SOURCE_SIZE:
            raise ValueError(
                f"VBScript source exceeds MAX_SOURCE_SIZE ({MAX_SOURCE_SIZE} bytes)"
            )
        return data.decode("utf-8", errors="replace")

    if isinstance(source, str):
        if len(source.encode("utf-8", errors="replace")) > MAX_SOURCE_SIZE:
            raise ValueError(
                f"VBScript source exceeds MAX_SOURCE_SIZE ({MAX_SOURCE_SIZE} bytes)"
            )
        return source

    if isinstance(source, (bytes, bytearray, memoryview)):
        data = bytes(source)
        if len(data) > MAX_SOURCE_SIZE:
            raise ValueError(
                f"VBScript source exceeds MAX_SOURCE_SIZE ({MAX_SOURCE_SIZE} bytes)"
            )
        return data.decode("utf-8", errors="replace")

    raise TypeError("source must be str, bytes, bytearray, memoryview, or pathlib.Path")


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def _line_number(text: str, offset: int) -> int:
    return text.count("\n", 0, max(offset, 0)) + 1


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
    rank = 0

    for value in values:
        current = _severity_rank(value)

        if current > rank:
            best = value
            rank = current

    return best


# ---------------------------------------------------------------------------
# VBScript lexical helpers
# ---------------------------------------------------------------------------

# VBScript uses single-quoted comments. Double quotes delimit strings.
_VBS_STRING_RE = re.compile(
    r'"(?:[^"]|"")*"',
    re.DOTALL,
)

_VBS_IDENTIFIER_RE = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*\b")

_VBS_PROCEDURE_RE = re.compile(
    r"""
    ^\s*
    (?P<visibility>Public|Private|Friend)?
    \s*
    (?P<kind>Function|Sub|Property\s+(?:Get|Let|Set))
    \s+
    (?P<name>[A-Za-z_][A-Za-z0-9_]*)
    \s*
    (?:\((?P<params>[^)]{0,4000})\))?
    """,
    re.IGNORECASE | re.MULTILINE | re.VERBOSE,
)

_CREATE_OBJECT_RE = re.compile(
    r"""
    (?P<constructor>
        CreateObject
        |
        GetObject
        |
        WScript\.CreateObject
        |
        WScript\.GetObject
    )
    \s*
    \(
    \s*
    (?P<quote>['"])
    (?P<object>[^'"]{1,500})
    (?P=quote)
    """,
    re.IGNORECASE | re.VERBOSE,
)

_URL_RE = re.compile(r"""(?i)\b(?:https?|ftp)://[^\s"'<>]+""")


def _extract_strings(text: str) -> List[str]:
    result: List[str] = []

    for match in _VBS_STRING_RE.finditer(text):
        if len(result) >= MAX_STRINGS:
            break

        value = match.group(0)

        if len(value) >= 2:
            # Preserve escaped double quotes in their static representation.
            result.append(value[1:-1])

    return result


def _extract_identifiers(text: str) -> List[str]:
    result: List[str] = []
    seen: set[str] = set()

    for match in _VBS_IDENTIFIER_RE.finditer(text):
        if len(result) >= MAX_IDENTIFIERS:
            break

        value = match.group(0)
        key = value.lower()

        if key in seen:
            continue

        seen.add(key)
        result.append(value)

    return result


def _extract_procedures(text: str) -> List[VBScriptProcedure]:
    result: List[VBScriptProcedure] = []

    for match in _VBS_PROCEDURE_RE.finditer(text):
        if len(result) >= MAX_PROCEDURES:
            break

        kind = re.sub(
            r"\s+",
            " ",
            match.group("kind") or "Function",
        ).strip()

        raw_params = match.group("params") or ""

        params = tuple(item.strip() for item in raw_params.split(",") if item.strip())

        result.append(
            VBScriptProcedure(
                name=match.group("name"),
                kind=kind,
                line_number=_line_number(text, match.start()),
                parameters=params,
                evidence=_clip(match.group(0), 500),
            )
        )

    return result


def _extract_objects(text: str) -> List[VBScriptObject]:
    result: List[VBScriptObject] = []
    seen: set[Tuple[str, int]] = set()

    for match in _CREATE_OBJECT_RE.finditer(text):
        if len(result) >= MAX_OBJECTS:
            break

        object_name = match.group("object").strip()
        line = _line_number(text, match.start())

        key = (object_name.lower(), line)

        if key in seen:
            continue

        seen.add(key)

        lowered = object_name.lower()

        high_risk_markers = (
            "wscript.shell",
            "filesystemobject",
            "xmlhttp",
            "serverxmlhttp",
            "winhttp",
            "adodb.",
            "wbemscripting",
            "scriptlet.typelib",
        )

        risk = (
            "high"
            if any(marker in lowered for marker in high_risk_markers)
            else "medium"
        )

        result.append(
            VBScriptObject(
                object_name=object_name,
                constructor=match.group("constructor"),
                line_number=line,
                risk=risk,
            )
        )

    return result


# ---------------------------------------------------------------------------
# Comment-aware normalization
# ---------------------------------------------------------------------------


def _mask_comments_and_strings(text: str) -> str:
    """
    Mask VBScript comments and string bodies while retaining line structure.

    This is not a full VBScript lexer. It is intentionally conservative and
    exists to prevent ordinary comments/string contents from dominating
    executable-syntax indicators.
    """
    chars = list(text)
    n = len(chars)

    in_string = False
    in_comment = False

    i = 0

    while i < n:
        ch = chars[i]

        if in_comment:
            if ch == "\n":
                in_comment = False
            else:
                chars[i] = " "

            i += 1
            continue

        if in_string:
            if ch == '"':
                # VBScript escapes quotes as "".
                if i + 1 < n and chars[i + 1] == '"':
                    chars[i] = " "
                    chars[i + 1] = " "
                    i += 2
                    continue

                chars[i] = " "
                in_string = False
                i += 1
                continue

            if ch != "\n":
                chars[i] = " "

            i += 1
            continue

        # Start of VBScript string.
        if ch == '"':
            chars[i] = " "
            in_string = True
            i += 1
            continue

        # Single quote starts a comment unless it is inside a string.
        if ch == "'":
            chars[i] = " "
            in_comment = True
            i += 1
            continue

        # REM comments at line start / after whitespace.
        if (
            ch in "Rr"
            and text[i : i + 3].lower() == "rem"
            and (i == 0 or text[i - 1].isspace())
            and (i + 3 >= n or text[i + 3].isspace())
        ):
            for j in range(i, min(i + 3, n)):
                chars[j] = " "

            in_comment = True
            i += 3
            continue

        i += 1

    return "".join(chars)


# ---------------------------------------------------------------------------
# Indicator extraction
# ---------------------------------------------------------------------------


def _match_indicators(
    text: str,
) -> Tuple[Dict[str, int], List[VBScriptEvidence]]:
    indicators: Dict[str, int] = Counter()
    evidence: List[VBScriptEvidence] = []

    normalized = _mask_comments_and_strings(text)

    # Some indicators require literal object names or string content and are
    # therefore matched against both normalized and original source.
    sources = (
        ("normalized", normalized),
        ("source", text),
    )

    seen: set[Tuple[str, int, str]] = set()

    for definition in INDICATOR_DEFINITIONS:
        matches: List[Tuple[int, re.Match[str]]] = []

        for source_name, candidate in sources:
            del source_name  # source label is not needed in final evidence.

            for pattern in definition.patterns:
                for match in pattern.finditer(candidate):
                    matches.append((match.start(), match))

                    if len(matches) >= MAX_EVIDENCE_ITEMS:
                        break

                if len(matches) >= MAX_EVIDENCE_ITEMS:
                    break

            if len(matches) >= MAX_EVIDENCE_ITEMS:
                break

        if not matches:
            continue

        unique: List[Tuple[int, re.Match[str]]] = []

        for offset, match in sorted(
            matches,
            key=lambda item: item[0],
        ):
            line = _line_number(text, offset)
            snippet = _clip(match.group(0), 300)

            key = (
                definition.name,
                line,
                snippet.lower(),
            )

            if key in seen:
                continue

            seen.add(key)
            unique.append((offset, match))

        if not unique:
            continue

        indicators[definition.name] = len(unique)

        for offset, match in unique:
            if len(evidence) >= MAX_EVIDENCE_ITEMS:
                break

            evidence.append(
                VBScriptEvidence(
                    indicator=definition.name,
                    category=definition.category,
                    severity=definition.severity,
                    confidence=definition.confidence,
                    evidence=_clip(match.group(0), 500),
                    line_number=_line_number(text, offset),
                    source="vbscript",
                    description=definition.description,
                )
            )

    return dict(indicators), evidence


# ---------------------------------------------------------------------------
# Statistics
# ---------------------------------------------------------------------------


def _shannon_entropy(value: str) -> float:
    if not value:
        return 0.0

    counts = Counter(value)
    length = len(value)

    result = 0.0

    for count in counts.values():
        probability = count / length
        result -= probability * math.log2(probability)

    return result


def _string_statistics(
    strings: Sequence[str],
) -> Dict[str, Union[int, float]]:
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

    total = sum(len(item) for item in strings)
    maximum = max(len(item) for item in strings)

    base64_re = re.compile(r"^[A-Za-z0-9+/]{16,}={0,2}$")
    hex_re = re.compile(r"^(?:[0-9A-Fa-f]{2}){8,}$")
    percent_re = re.compile(r"(?:%[0-9A-Fa-f]{2}){3,}")

    long_count = 0
    base64_count = 0
    hex_count = 0
    percent_count = 0
    entropy_count = 0

    for item in strings:
        if len(item) >= 256:
            long_count += 1

        compact = re.sub(r"\s+", "", item)

        if base64_re.fullmatch(compact):
            base64_count += 1

        if hex_re.fullmatch(compact):
            hex_count += 1

        if percent_re.search(item):
            percent_count += 1

        if len(item) >= 32 and _shannon_entropy(item) >= 4.5:
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


def _source_statistics(
    text: str,
) -> Dict[str, Union[int, float]]:
    lines = text.splitlines() or [""]

    nonempty = [line for line in lines if line.strip()]

    comment_lines = 0

    for line in lines:
        stripped = line.lstrip()

        if (
            stripped.startswith("'")
            or stripped.lower().startswith("rem ")
            or stripped.lower() == "rem"
        ):
            comment_lines += 1

    long_lines = sum(1 for line in lines if len(line) >= 1_000)

    very_long_lines = sum(1 for line in lines if len(line) >= 10_000)

    ampersand_count = len(re.findall(r"&", text))

    procedure_count = len(_VBS_PROCEDURE_RE.findall(text))

    return {
        "line_count": len(lines),
        "nonempty_line_count": len(nonempty),
        "comment_line_count": comment_lines,
        "comment_ratio": (comment_lines / len(lines) if lines else 0.0),
        "long_line_count": long_lines,
        "very_long_line_count": very_long_lines,
        "ampersand_count": ampersand_count,
        "procedure_count": procedure_count,
        "average_line_length": (
            sum(len(line) for line in lines) / len(lines) if lines else 0.0
        ),
        "max_line_length": max(
            (len(line) for line in lines),
            default=0,
        ),
    }


# ---------------------------------------------------------------------------
# Categories and combinations
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
) -> List[VBScriptCombination]:
    present = {name for name, count in indicators.items() if count > 0}

    combinations: List[VBScriptCombination] = []

    def add(
        name: str,
        required: Sequence[str],
        explanation: str,
        severity: str,
    ) -> None:
        required_tuple = tuple(required)

        combinations.append(
            VBScriptCombination(
                name=name,
                present=all(item in present for item in required_tuple),
                required_indicators=required_tuple,
                explanation=explanation,
                severity=severity,
            )
        )

    add(
        "dynamic_execution_with_obfuscation",
        ("execute", "chr_construction"),
        "Dynamic VBScript execution is combined with character-code string construction.",
        "critical",
    )

    add(
        "dynamic_execution_with_encoding",
        ("execute", "base64_decode"),
        "Dynamic execution is combined with encoded-content decoding.",
        "critical",
    )

    add(
        "network_to_file",
        ("network", "download_to_file"),
        "Network activity is combined with writing transferred content to disk.",
        "high",
    )

    add(
        "network_binary_payload",
        ("network", "http_response_body", "adodb_stream"),
        "Binary HTTP response handling is combined with ADODB.Stream.",
        "critical",
    )

    add(
        "download_then_execute",
        ("download_to_file", "wscript_shell"),
        "Remote content retrieval is combined with shell automation.",
        "critical",
    )

    add(
        "download_then_dynamic_execution",
        ("download", "execute"),
        "Remote retrieval is combined with dynamic VBScript execution.",
        "critical",
    )

    add(
        "com_network_execution",
        ("wscript_createobject", "network", "wscript_shell"),
        "COM automation, network access, and shell execution occur together.",
        "critical",
    )

    add(
        "filesystem_persistence",
        ("filesystem_object", "startup_folder"),
        "Filesystem automation references the Windows Startup folder.",
        "high",
    )

    add(
        "registry_persistence",
        ("registry_write", "registry_run_key"),
        "Registry writes target an autorun location.",
        "critical",
    )

    add(
        "registry_runonce_persistence",
        ("registry_write", "registry_runonce_key"),
        "Registry writes target a RunOnce autorun location.",
        "critical",
    )

    add(
        "wmi_process_discovery",
        ("wmi", "process_enumeration"),
        "WMI is used in combination with process enumeration.",
        "high",
    )

    add(
        "powershell_encoded_execution",
        ("powershell", "powershell_encoded"),
        "PowerShell execution is combined with an encoded command.",
        "critical",
    )

    add(
        "powershell_download_execution",
        ("powershell", "powershell_download"),
        "PowerShell is associated with remote content retrieval.",
        "high",
    )

    add(
        "persistence_command_execution",
        ("persistence_command", "wscript_shell"),
        "Persistence-oriented command utilities occur with shell automation.",
        "critical",
    )

    add(
        "anti_analysis",
        ("security_software", "virtual_machine_terms"),
        "Security-software and VM-detection signals occur together.",
        "high",
    )

    add(
        "credential_collection",
        ("credential_terms", "cookie_terms"),
        "Credential terminology occurs with browser cookie access.",
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
    combinations: Sequence[VBScriptCombination],
    procedures: Sequence[VBScriptProcedure],
    objects: Sequence[VBScriptObject],
    urls: Sequence[str],
    identifiers: Sequence[str],
    strings: Sequence[str],
) -> Dict[str, Union[int, float, bool]]:
    features: Dict[str, Union[int, float, bool]] = {}

    source_stats = _source_statistics(text)
    string_stats = _string_statistics(strings)

    features["vbscript_schema_version"] = 1

    for key, value in source_stats.items():
        features[f"vbscript_{key}"] = value

    for key, value in string_stats.items():
        features[f"vbscript_{key}"] = value

    features["vbscript_procedure_count"] = len(procedures)
    features["vbscript_object_count"] = len(objects)
    features["vbscript_url_count"] = len(urls)
    features["vbscript_identifier_count"] = len(identifiers)

    for name in VBSCRIPT_INDICATORS:
        count = int(indicators.get(name, 0))

        features[f"vbscript_indicator_{name}"] = int(count > 0)
        features[f"vbscript_indicator_{name}_count"] = count

    for category in VBSCRIPT_CATEGORIES:
        count = int(categories.get(category, 0))

        features[f"vbscript_category_{category}"] = int(count > 0)
        features[f"vbscript_category_{category}_count"] = count

    for combination in combinations:
        features[f"vbscript_combination_{combination.name}"] = int(combination.present)

    high_risk_count = 0
    medium_or_higher_count = 0

    for name, count in indicators.items():
        if count <= 0:
            continue

        definition = INDICATOR_BY_NAME.get(name)

        if definition is None:
            continue

        if _severity_rank(definition.severity) >= _severity_rank("high"):
            high_risk_count += count

        if _severity_rank(definition.severity) >= _severity_rank("medium"):
            medium_or_higher_count += count

    features["vbscript_indicator_total"] = sum(indicators.values())

    features["vbscript_high_risk_indicator_count"] = high_risk_count

    features["vbscript_medium_or_higher_indicator_count"] = medium_or_higher_count

    features["vbscript_evidence_count"] = sum(indicators.values())

    features["vbscript_present_category_count"] = sum(
        1 for category in VBSCRIPT_CATEGORIES if categories.get(category, 0) > 0
    )

    features["vbscript_present_indicator_count"] = sum(
        1 for name in VBSCRIPT_INDICATORS if indicators.get(name, 0) > 0
    )

    features["vbscript_present_combination_count"] = sum(
        1 for item in combinations if item.present
    )

    # Stable bounded risk signal. This is not itself a malware verdict.
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

    combination_weights = {
        "low": 1.0,
        "medium": 3.0,
        "high": 6.0,
        "critical": 10.0,
    }

    for combination in combinations:
        if combination.present:
            score += combination_weights.get(
                combination.severity,
                2.0,
            )

    score += (
        min(
            int(string_stats["high_entropy_string_count"]),
            20,
        )
        * 0.75
    )

    score += (
        min(
            int(string_stats["long_string_count"]),
            20,
        )
        * 0.5
    )

    features["vbscript_signal_score"] = round(
        min(score, 1000.0),
        4,
    )

    # High-level policy-friendly flags.
    features["vbscript_has_dynamic_execution"] = int(
        categories.get("dynamic_execution", 0) > 0
    )

    features["vbscript_has_com"] = int(
        categories.get("com_automation", 0) > 0
        or categories.get("activex", 0) > 0
        or categories.get("wscript", 0) > 0
    )

    features["vbscript_has_network"] = int(categories.get("network", 0) > 0)

    features["vbscript_has_download"] = int(categories.get("download", 0) > 0)

    features["vbscript_has_filesystem"] = int(categories.get("filesystem", 0) > 0)

    features["vbscript_has_process_execution"] = int(
        categories.get("process", 0) > 0
        or categories.get("command", 0) > 0
        or indicators.get("wscript_shell", 0) > 0
    )

    features["vbscript_has_registry"] = int(categories.get("registry", 0) > 0)

    features["vbscript_has_persistence"] = int(categories.get("persistence", 0) > 0)

    features["vbscript_has_obfuscation"] = int(
        categories.get("obfuscation", 0) > 0 or categories.get("encoding", 0) > 0
    )

    features["vbscript_has_wmi"] = int(indicators.get("wmi", 0) > 0)

    return features


# ---------------------------------------------------------------------------
# Public analysis API
# ---------------------------------------------------------------------------


def analyze_vbscript(
    source: Union[str, bytes, bytearray, memoryview, Path],
    *,
    filename: Optional[str] = None,
    parser_analysis: Optional[ScriptAnalysis] = None,
) -> VBScriptAnalysis:
    """
    Analyze VBScript statically.

    No VBScript code is executed or evaluated.

    Parameters
    ----------
    source:
        Source text, bytes, or local Path.

    filename:
        Optional filename for integration with script/parser.py.

    parser_analysis:
        Optional generic parser result. Supplying it avoids repeating generic
        script parsing when the caller already performed it.
    """
    text = _read_source(source)

    encoded_size = len(
        text.encode(
            "utf-8",
            errors="replace",
        )
    )

    if encoded_size > MAX_FEATURE_TEXT:
        feature_text = text[:MAX_FEATURE_TEXT]
        truncated_for_features = True
    else:
        feature_text = text
        truncated_for_features = False

    if parser_analysis is None:
        parser_analysis = parse_script(
            text,
            filename=filename,
            family="vbscript",
        )

    indicators, evidence = _match_indicators(feature_text)

    categories = _derive_categories(indicators)

    strings = _extract_strings(feature_text)

    identifiers = _extract_identifiers(feature_text)

    procedures = _extract_procedures(feature_text)

    objects = _extract_objects(feature_text)

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

    combinations = _derive_combinations(indicators)

    feature_vector = _build_feature_vector(
        feature_text,
        indicators,
        categories,
        combinations,
        procedures,
        objects,
        urls,
        identifiers,
        strings,
    )

    # Preserve selected generic parser features under a namespaced prefix.
    generic_features = (
        getattr(
            parser_analysis,
            "feature_vector",
            {},
        )
        or {}
    )

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

    severity_values = [
        definition.severity
        for name, count in indicators.items()
        if count > 0
        for definition in [INDICATOR_BY_NAME.get(name)]
        if definition is not None
    ]

    severity_values.extend(
        combination.severity for combination in combinations if combination.present
    )

    severity = _max_severity(severity_values)

    confidence_values = [
        definition.confidence
        for name, count in indicators.items()
        if count > 0
        for definition in [INDICATOR_BY_NAME.get(name)]
        if definition is not None
    ]

    confidence = (
        round(
            sum(confidence_values) / len(confidence_values),
            4,
        )
        if confidence_values
        else 0.0
    )

    metadata = {
        "module": "pharos_cdr.extraction.script.vbscript",
        "analyzer": "static_vbscript",
        "schema_version": 1,
        "filename": filename,
        "input_encoding": "utf-8-replacement",
        "source_size_bytes": encoded_size,
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
        "wmi_access_performed": False,
        "filesystem_payload_extraction_performed": False,
    }

    return VBScriptAnalysis(
        source_sha256=_sha256(text),
        source_size=encoded_size,
        line_count=len(text.splitlines()) or 1,
        family="vbscript",
        indicators=dict(sorted(indicators.items())),
        categories=dict(sorted(categories.items())),
        evidence=evidence[:MAX_EVIDENCE_ITEMS],
        procedures=procedures,
        objects=objects,
        urls=urls,
        identifiers=identifiers,
        strings=strings,
        combinations=combinations,
        feature_vector=dict(sorted(feature_vector.items())),
        severity=severity,
        confidence=confidence,
        metadata=metadata,
    )


def analyze_vbscript_file(
    path: Union[str, Path],
) -> VBScriptAnalysis:
    """Analyze a local VBScript file without executing it."""
    source_path = Path(path)

    return analyze_vbscript(
        source_path,
        filename=source_path.name,
    )


def parse_vbscript(
    source: Union[str, bytes, bytearray, memoryview, Path],
    *,
    filename: Optional[str] = None,
) -> VBScriptAnalysis:
    """Alias for analyze_vbscript()."""
    return analyze_vbscript(
        source,
        filename=filename,
    )


def extract_vbscript_features(
    source: Union[str, bytes, bytearray, memoryview, Path],
    *,
    filename: Optional[str] = None,
) -> Dict[str, Union[int, float, bool]]:
    """Return the stable VBScript feature vector."""
    return analyze_vbscript(
        source,
        filename=filename,
    ).feature_vector


def extract_feature_vector(
    source: Union[str, bytes, bytearray, memoryview, Path],
    *,
    filename: Optional[str] = None,
) -> Dict[str, Union[int, float, bool]]:
    """Feature-pipeline compatibility alias."""
    return extract_vbscript_features(
        source,
        filename=filename,
    )


def extract_vbscript_feature_vector(
    source: Union[str, bytes, bytearray, memoryview, Path],
    *,
    filename: Optional[str] = None,
) -> Dict[str, Union[int, float, bool]]:
    """Explicit feature-vector alias."""
    return extract_vbscript_features(
        source,
        filename=filename,
    )


# ---------------------------------------------------------------------------
# Feature schema
# ---------------------------------------------------------------------------


def vbscript_feature_names() -> List[str]:
    """
    Return the deterministic VBScript feature schema.
    """
    names: List[str] = [
        "vbscript_schema_version",
        "vbscript_line_count",
        "vbscript_nonempty_line_count",
        "vbscript_comment_line_count",
        "vbscript_comment_ratio",
        "vbscript_long_line_count",
        "vbscript_very_long_line_count",
        "vbscript_ampersand_count",
        "vbscript_procedure_count",
        "vbscript_average_line_length",
        "vbscript_max_line_length",
        "vbscript_string_count",
        "vbscript_string_total_length",
        "vbscript_string_max_length",
        "vbscript_string_mean_length",
        "vbscript_long_string_count",
        "vbscript_base64_like_string_count",
        "vbscript_hex_like_string_count",
        "vbscript_percent_encoded_string_count",
        "vbscript_high_entropy_string_count",
        "vbscript_object_count",
        "vbscript_url_count",
        "vbscript_identifier_count",
    ]

    for name in VBSCRIPT_INDICATORS:
        names.append(f"vbscript_indicator_{name}")
        names.append(f"vbscript_indicator_{name}_count")

    for category in VBSCRIPT_CATEGORIES:
        names.append(f"vbscript_category_{category}")
        names.append(f"vbscript_category_{category}_count")

    for combination in _derive_combinations({}):
        names.append(f"vbscript_combination_{combination.name}")

    names.extend(
        [
            "vbscript_indicator_total",
            "vbscript_high_risk_indicator_count",
            "vbscript_medium_or_higher_indicator_count",
            "vbscript_evidence_count",
            "vbscript_present_category_count",
            "vbscript_present_indicator_count",
            "vbscript_present_combination_count",
            "vbscript_signal_score",
            "vbscript_has_dynamic_execution",
            "vbscript_has_com",
            "vbscript_has_network",
            "vbscript_has_download",
            "vbscript_has_filesystem",
            "vbscript_has_process_execution",
            "vbscript_has_registry",
            "vbscript_has_persistence",
            "vbscript_has_obfuscation",
            "vbscript_has_wmi",
        ]
    )

    return names


def build_feature_schema() -> Dict[str, Any]:
    """Return a JSON-serializable VBScript feature schema."""
    names = vbscript_feature_names()

    types: Dict[str, str] = {}

    for name in names:
        if (
            name.endswith("_ratio")
            or name.endswith("_score")
            or name.endswith("_mean_length")
            or name.endswith("_average_line_length")
        ):
            types[name] = "float"
        else:
            types[name] = "integer"

    return {
        "module": "pharos_cdr.extraction.script.vbscript",
        "schema_version": 1,
        "feature_count": len(names),
        "features": names,
        "types": types,
        "description": (
            "Stable static VBScript/JScript-hosted VBScript feature vector. "
            "No VBScript execution is performed."
        ),
    }


def vectorize_features(
    analysis: VBScriptAnalysis,
    feature_names: Optional[Sequence[str]] = None,
) -> List[float]:
    """
    Convert analysis to an ordered numeric vector.

    Missing schema features are represented by zero.
    """
    names = list(
        feature_names if feature_names is not None else vbscript_feature_names()
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
# Query helpers
# ---------------------------------------------------------------------------


def has_indicator(
    analysis: VBScriptAnalysis,
    indicator: str,
) -> bool:
    """Return whether a specific indicator was observed."""
    return (
        analysis.indicators.get(
            indicator,
            0,
        )
        > 0
    )


def indicator_count(
    analysis: VBScriptAnalysis,
    indicator: str,
) -> int:
    """Return an indicator occurrence count."""
    return int(
        analysis.indicators.get(
            indicator,
            0,
        )
    )


def has_category(
    analysis: VBScriptAnalysis,
    category: str,
) -> bool:
    """Return whether a category has evidence."""
    return (
        analysis.categories.get(
            category,
            0,
        )
        > 0
    )


def category_count(
    analysis: VBScriptAnalysis,
    category: str,
) -> int:
    """Return total matches in a category."""
    return int(
        analysis.categories.get(
            category,
            0,
        )
    )


def high_risk_indicators(
    analysis: VBScriptAnalysis,
) -> List[str]:
    """Return observed high/critical indicator names."""
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
    analysis: VBScriptAnalysis,
) -> List[VBScriptCombination]:
    """Return only satisfied combinations."""
    return [item for item in analysis.combinations if item.present]


def evidence_by_category(
    analysis: VBScriptAnalysis,
    category: str,
) -> List[VBScriptEvidence]:
    """Filter evidence by category."""
    target = category.strip().lower()

    return [item for item in analysis.evidence if item.category.lower() == target]


def evidence_by_indicator(
    analysis: VBScriptAnalysis,
    indicator: str,
) -> List[VBScriptEvidence]:
    """Filter evidence by indicator."""
    target = indicator.strip().lower()

    return [item for item in analysis.evidence if item.indicator.lower() == target]


# ---------------------------------------------------------------------------
# Focused extraction helpers
# ---------------------------------------------------------------------------


def find_vbscript_objects(
    source: Union[str, bytes, bytearray, memoryview, Path],
) -> List[VBScriptObject]:
    """Extract CreateObject/GetObject targets statically."""
    return _extract_objects(_read_source(source))


def find_vbscript_procedures(
    source: Union[str, bytes, bytearray, memoryview, Path],
) -> List[VBScriptProcedure]:
    """Extract lightweight Sub/Function metadata."""
    return _extract_procedures(_read_source(source))


def find_vbscript_urls(
    source: Union[str, bytes, bytearray, memoryview, Path],
) -> List[str]:
    """Extract literal HTTP/HTTPS/FTP URLs."""
    text = _read_source(source)

    result: List[str] = []
    seen: set[str] = set()

    for match in _URL_RE.finditer(text):
        if len(result) >= MAX_URLS:
            break

        value = match.group(0).rstrip(".,;)]}")

        key = value.lower()

        if key in seen:
            continue

        seen.add(key)
        result.append(value)

    return result


def find_protocols(
    source: Union[str, bytes, bytearray, memoryview, Path],
) -> List[str]:
    """Extract script/data protocol references."""
    text = _read_source(source)

    pattern = re.compile(r"(?i)\b(?:javascript|vbscript|data):")

    result: List[str] = []
    seen: set[str] = set()

    for match in pattern.finditer(text):
        value = match.group(0).lower()

        if value in seen:
            continue

        seen.add(value)
        result.append(value)

    return result


# ---------------------------------------------------------------------------
# Serialization / reporting
# ---------------------------------------------------------------------------


def analysis_to_dict(
    analysis: VBScriptAnalysis,
) -> Dict[str, Any]:
    """Convert the complete analysis to a JSON-serializable dictionary."""
    return asdict(analysis)


def summarize_vbscript(
    analysis: VBScriptAnalysis,
) -> Dict[str, Any]:
    """Produce a compact pipeline/report summary."""
    indicators = [name for name, count in analysis.indicators.items() if count > 0]

    categories = [name for name, count in analysis.categories.items() if count > 0]

    combinations = [item.name for item in analysis.combinations if item.present]

    return {
        "family": analysis.family,
        "source_sha256": analysis.source_sha256,
        "source_size": analysis.source_size,
        "line_count": analysis.line_count,
        "severity": analysis.severity,
        "confidence": analysis.confidence,
        "indicator_count": len(indicators),
        "indicators": indicators,
        "categories": categories,
        "combinations": combinations,
        "procedure_count": len(analysis.procedures),
        "object_count": len(analysis.objects),
        "url_count": len(analysis.urls),
        "string_count": len(analysis.strings),
        "high_risk_indicators": high_risk_indicators(analysis),
        "signal_score": analysis.feature_vector.get(
            "vbscript_signal_score",
            0.0,
        ),
    }


def iter_evidence(
    analysis: VBScriptAnalysis,
) -> Iterator[VBScriptEvidence]:
    """Iterate static evidence."""
    yield from analysis.evidence


def iter_procedures(
    analysis: VBScriptAnalysis,
) -> Iterator[VBScriptProcedure]:
    """Iterate statically extracted procedures."""
    yield from analysis.procedures


def iter_objects(
    analysis: VBScriptAnalysis,
) -> Iterator[VBScriptObject]:
    """Iterate statically identified COM objects."""
    yield from analysis.objects


def iter_combinations(
    analysis: VBScriptAnalysis,
) -> Iterator[VBScriptCombination]:
    """Iterate all derived combinations."""
    yield from analysis.combinations


# ---------------------------------------------------------------------------
# Compatibility aliases
# ---------------------------------------------------------------------------

parse = parse_vbscript
analyze = analyze_vbscript
extract = extract_vbscript_features
extract_features = extract_vbscript_features
feature_names = vbscript_feature_names


__all__ = [
    "MAX_SOURCE_SIZE",
    "MAX_FEATURE_TEXT",
    "MAX_EVIDENCE_ITEMS",
    "MAX_STRINGS",
    "MAX_URLS",
    "MAX_IDENTIFIERS",
    "MAX_PROCEDURES",
    "MAX_OBJECTS",
    "VBSCRIPT_CATEGORIES",
    "VBSCRIPT_INDICATORS",
    "VBScriptIndicatorDefinition",
    "VBScriptEvidence",
    "VBScriptProcedure",
    "VBScriptObject",
    "VBScriptCombination",
    "VBScriptAnalysis",
    "analyze_vbscript",
    "analyze_vbscript_file",
    "parse_vbscript",
    "extract_vbscript_features",
    "extract_feature_vector",
    "extract_vbscript_feature_vector",
    "vbscript_feature_names",
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
    "find_vbscript_objects",
    "find_vbscript_procedures",
    "find_vbscript_urls",
    "find_protocols",
    "analysis_to_dict",
    "summarize_vbscript",
    "iter_evidence",
    "iter_procedures",
    "iter_objects",
    "iter_combinations",
    "parse",
    "analyze",
    "extract",
    "extract_features",
    "feature_names",
]
