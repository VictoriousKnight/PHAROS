"""
pharos-cdr/src/extraction/capabilities/payload.py

Static payload / payload-delivery capability extraction for Pharos CDR.

This module identifies evidence that a document, script, macro, or other
analyzed artifact contains, constructs, decodes, stages, embeds, drops,
downloads, or launches a payload.

Security model
--------------
This module is STATIC ONLY.

It never:
    - executes extracted commands or scripts
    - decodes payloads for execution
    - launches processes
    - loads DLLs/shared libraries
    - invokes COM
    - performs network requests
    - writes extracted payloads to the host filesystem
    - executes VBA, JavaScript, PowerShell, shell, or XLM content

The extractor operates on text, bytes, paths, mappings, sequences, and nested
analysis objects. It is intended to consume output from other Pharos
extractors such as:

    extraction.common.strings
    extraction.office.embedded_objects
    extraction.office.ole
    extraction.office.xlm
    extraction.vba.capabilities
    extraction.vba.api_features
    extraction.script.parser
    extraction.behavior.process
    extraction.behavior.filesystem
    extraction.urls.url_features

The resulting feature vector is intentionally composed of stable scalar
features suitable for ML pipelines.

Evidence chain
--------------
    source text / analysis object
        -> payload indicator
        -> payload mechanism
        -> payload category
        -> capability combination
        -> feature vector
        -> ML / policy / CDR decision

The module is deliberately conservative. A Base64 string, URL, embedded
object, or executable filename alone does not automatically imply a malicious
payload. Stronger confidence is assigned when multiple independent signals
form a delivery or execution chain.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import math
import os
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
    Set,
    Tuple,
)

# ============================================================================
# Limits
# ============================================================================

MAX_SOURCE_SIZE = 25 * 1024 * 1024
MAX_TEXT_CHARS = 25 * 1024 * 1024
MAX_FIELD_TEXT = 100_000

MAX_NESTING_DEPTH = 12
MAX_EVIDENCE_ITEMS = 20_000
MAX_MATCHES_PER_RULE = 5_000
MAX_RECORDS = 10_000
MAX_INDICATORS = 10_000
MAX_TARGETS = 10_000
MAX_PAYLOAD_CANDIDATES = 5_000
MAX_DECODE_SAMPLE = 1_000_000
MAX_FEATURE_VALUE = 1_000_000

DEFAULT_CONFIDENCE = 0.80


# ============================================================================
# Taxonomy
# ============================================================================

PAYLOAD_CATEGORIES: Tuple[str, ...] = (
    "payload_presence",
    "payload_reference",
    "payload_construction",
    "payload_decoding",
    "payload_decompression",
    "payload_decryption",
    "payload_encoding",
    "payload_staging",
    "payload_drop",
    "payload_write",
    "payload_download",
    "payload_transfer",
    "payload_embedding",
    "payload_extraction",
    "payload_execution",
    "script_payload",
    "command_payload",
    "powershell_payload",
    "javascript_payload",
    "vbscript_payload",
    "macro_payload",
    "shell_payload",
    "executable_payload",
    "dll_payload",
    "assembly_payload",
    "shellcode",
    "reflective_payload",
    "memory_payload",
    "archive_payload",
    "document_payload",
    "template_payload",
    "activex_payload",
    "ole_payload",
    "container_payload",
    "url_payload",
    "network_payload",
    "temporary_payload",
    "payload_cleanup",
    "payload_obfuscation",
    "payload_fragmentation",
    "payload_reassembly",
    "payload_handoff",
    "living_off_the_land_payload",
)


OPERATIONS: Tuple[str, ...] = (
    "reference",
    "identify",
    "construct",
    "decode",
    "decompress",
    "decrypt",
    "encode",
    "stage",
    "drop",
    "write",
    "download",
    "transfer",
    "embed",
    "extract",
    "execute",
    "load",
    "inject",
    "reassemble",
    "cleanup",
    "obfuscate",
    "handoff",
    "unknown",
)


SEVERITIES: Tuple[str, ...] = (
    "low",
    "medium",
    "high",
    "critical",
)


PLATFORMS: Tuple[str, ...] = (
    "windows",
    "linux",
    "macos",
    "cross_platform",
    "unknown",
)


# ============================================================================
# Dataclasses
# ============================================================================


@dataclass(frozen=True)
class PayloadPattern:
    """
    Static payload-detection rule.

    Attributes:
        name:
            Stable rule identifier.
        category:
            Payload capability category.
        regex:
            Regular expression used for static matching.
        severity:
            Base severity assigned to matching evidence.
        confidence:
            Base confidence for the rule.
        operation:
            Operation implied by the pattern.
        description:
            Human-readable explanation.
        platform:
            Optional platform association.
    """

    name: str
    category: str
    regex: str
    severity: str = "medium"
    confidence: float = DEFAULT_CONFIDENCE
    operation: str = "unknown"
    description: str = ""
    platform: str = "unknown"


@dataclass
class PayloadEvidence:
    """
    A single piece of static evidence indicating payload behavior.
    """

    category: str
    indicator: str
    evidence: str
    source: str
    line_number: Optional[int] = None
    operation: str = "unknown"
    target: Optional[str] = None
    platform: str = "unknown"
    confidence: float = DEFAULT_CONFIDENCE
    severity: str = "medium"
    rule: Optional[str] = None


@dataclass
class PayloadRecord:
    """
    Normalized payload capability record.
    """

    mechanism: str
    category: str
    target: Optional[str]
    operation: str
    platform: str
    indicator: str
    evidence: str
    severity: str
    confidence: float


@dataclass(frozen=True)
class PayloadCombination:
    """
    Derived multi-signal payload chain.
    """

    name: str
    present: bool
    required_categories: Tuple[str, ...]
    explanation: str


@dataclass
class PayloadCandidate:
    """
    Bounded metadata about a possible encoded/embedded payload.

    The actual payload is intentionally never persisted or executed.
    """

    kind: str
    length: int
    confidence: float
    entropy: float
    decoded_size: Optional[int] = None
    printable_ratio: Optional[float] = None
    indicator: Optional[str] = None


@dataclass
class PayloadAnalysis:
    """
    Complete payload analysis result.
    """

    source_hash: str
    source_size: int
    records: List[PayloadRecord] = field(default_factory=list)
    evidence: List[PayloadEvidence] = field(default_factory=list)
    indicators: Dict[str, int] = field(default_factory=dict)
    categories: Dict[str, int] = field(default_factory=dict)
    combinations: List[PayloadCombination] = field(default_factory=list)
    targets: List[str] = field(default_factory=list)
    platforms: List[str] = field(default_factory=list)
    candidates: List[PayloadCandidate] = field(default_factory=list)
    feature_vector: Dict[str, float] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)


# ============================================================================
# Pattern vocabulary
# ============================================================================

# Strong payload construction / execution primitives.
PAYLOAD_EXECUTION_TERMS: Tuple[str, ...] = (
    "CreateProcess",
    "ShellExecute",
    "ShellExecuteEx",
    "WinExec",
    "system(",
    "popen(",
    "execve(",
    "execvp(",
    "Process.Start",
    "Start-Process",
    "WScript.Shell",
    'CreateObject("WScript.Shell")',
    "CreateObject('WScript.Shell')",
    "cmd.exe",
    "powershell.exe",
    "pwsh.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "msbuild.exe",
    "installutil.exe",
    "regasm.exe",
    "regsvcs.exe",
)


PAYLOAD_SCRIPT_HOSTS: Tuple[str, ...] = (
    "powershell",
    "pwsh",
    "wscript",
    "cscript",
    "mshta",
    "cmd.exe",
    "cmd /c",
    "cmd /k",
    "bash",
    "sh",
    "zsh",
    "python",
    "python.exe",
    "perl",
    "ruby",
    "node",
    "node.exe",
    "java",
    "java.exe",
)


PAYLOAD_EXECUTABLE_EXTENSIONS: Tuple[str, ...] = (
    ".exe",
    ".dll",
    ".scr",
    ".com",
    ".sys",
    ".ocx",
    ".cpl",
    ".msi",
    ".jar",
    ".elf",
    ".bin",
    ".so",
    ".dylib",
)


PAYLOAD_ARCHIVE_EXTENSIONS: Tuple[str, ...] = (
    ".zip",
    ".7z",
    ".rar",
    ".cab",
    ".gz",
    ".gzip",
    ".bz2",
    ".xz",
    ".tar",
)


PAYLOAD_DOCUMENT_EXTENSIONS: Tuple[str, ...] = (
    ".doc",
    ".docm",
    ".docx",
    ".dot",
    ".dotm",
    ".xls",
    ".xlsm",
    ".xlt",
    ".xltm",
    ".ppt",
    ".pptm",
    ".pps",
    ".ppsm",
    ".rtf",
    ".pdf",
)


PAYLOAD_INDICATOR_ALIASES: Dict[str, str] = {
    "frombase64string": "base64_decode",
    "convert.frombase64string": "base64_decode",
    "certutil -decode": "base64_decode",
    "certutil.exe -decode": "base64_decode",
    "-encodedcommand": "powershell_encoded_command",
    "-enc ": "powershell_encoded_command",
    "invoke-expression": "dynamic_script_execution",
    "iex(": "dynamic_script_execution",
    "eval(": "dynamic_script_execution",
    "new function(": "dynamic_script_execution",
    "exec(": "dynamic_script_execution",
    "execute(": "dynamic_script_execution",
    "executeglobal(": "dynamic_script_execution",
    "load(": "dynamic_script_execution",
    "assembly.load": "assembly_load",
    "reflection.assembly": "assembly_load",
    "virtualalloc": "memory_payload",
    "virtualallocex": "remote_memory_payload",
    "writeprocessmemory": "memory_payload_write",
    "createremotethread": "remote_payload_execution",
    "queueuserapc": "apc_payload_execution",
    "reflectiveloader": "reflective_loader",
    "reflective dll": "reflective_loader",
    "shellcode": "shellcode",
    "payload": "payload_reference",
    "stage": "payload_staging",
    "stager": "payload_stager",
    "dropper": "payload_dropper",
    "loader": "payload_loader",
    "implant": "payload_implant",
}


# ============================================================================
# Regular-expression rules
# ============================================================================

PATTERN_DEFINITIONS: Tuple[PayloadPattern, ...] = (
    PayloadPattern(
        name="explicit_payload_reference",
        category="payload_reference",
        regex=r"\b(?:payload|shellcode|stager|dropper|loader|implant|stage(?:d|r)?)\b",
        severity="medium",
        confidence=0.70,
        operation="reference",
        description="Explicit payload, loader, stager, dropper, or shellcode terminology.",
    ),
    PayloadPattern(
        name="base64_decode",
        category="payload_decoding",
        regex=r"(?i)\b(?:frombase64string|convert\.frombase64string|certutil(?:\.exe)?\s+(?:-decode|-decodehex))\b",
        severity="high",
        confidence=0.92,
        operation="decode",
        description="Static reference to Base64 or encoded-content decoding.",
        platform="windows",
    ),
    PayloadPattern(
        name="powershell_encoded_command",
        category="powershell_payload",
        regex=r"(?i)(?:powershell(?:\.exe)?\s+.*(?:-enc(?:odedcommand)?)(?:\s+|$)|(?:^|\s)-enc(?:odedcommand)?(?:\s+))",
        severity="high",
        confidence=0.95,
        operation="decode",
        description="PowerShell encoded-command invocation.",
        platform="windows",
    ),
    PayloadPattern(
        name="powershell_download_cradle",
        category="payload_download",
        regex=r"(?i)\b(?:invoke-webrequest|iwr|invoke-restmethod|irm|webclient|downloadstring|downloadfile|start-bitstransfer|bitsadmin)\b",
        severity="high",
        confidence=0.88,
        operation="download",
        description="Static reference to common script payload download mechanisms.",
        platform="windows",
    ),
    PayloadPattern(
        name="curl_wget_download",
        category="payload_download",
        regex=r"(?i)\b(?:curl|wget)\b(?:\s+|.*\s)(?:https?|ftp)://",
        severity="high",
        confidence=0.88,
        operation="download",
        description="Command-line retrieval of remote content.",
    ),
    PayloadPattern(
        name="javascript_dynamic_payload",
        category="javascript_payload",
        regex=r"(?i)\b(?:eval|function|new\s+Function|unescape|decodeURIComponent)\s*\(",
        severity="medium",
        confidence=0.84,
        operation="construct",
        description="JavaScript dynamic construction or evaluation of content.",
    ),
    PayloadPattern(
        name="vbscript_dynamic_payload",
        category="vbscript_payload",
        regex=r"(?i)\b(?:Execute|ExecuteGlobal|Eval)\s*\(",
        severity="medium",
        confidence=0.84,
        operation="execute",
        description="VBScript dynamic execution primitives.",
        platform="windows",
    ),
    PayloadPattern(
        name="powershell_dynamic_payload",
        category="powershell_payload",
        regex=r"(?i)\b(?:Invoke-Expression|IEX|Add-Type|Reflection\.Assembly|Assembly\.Load)\b",
        severity="high",
        confidence=0.90,
        operation="execute",
        description="PowerShell dynamic payload construction or assembly loading.",
        platform="windows",
    ),
    PayloadPattern(
        name="assembly_load",
        category="assembly_payload",
        regex=r"(?i)\b(?:Assembly\.Load|LoadWithPartialName|Reflection\.Assembly|System\.Reflection\.Assembly)\b",
        severity="high",
        confidence=0.91,
        operation="load",
        description="Static .NET assembly loading capability.",
        platform="windows",
    ),
    PayloadPattern(
        name="memory_payload",
        category="memory_payload",
        regex=r"(?i)\b(?:VirtualAlloc|VirtualAllocEx|WriteProcessMemory|NtWriteVirtualMemory|RtlMoveMemory)\b",
        severity="high",
        confidence=0.93,
        operation="write",
        description="Memory allocation or payload-writing APIs.",
        platform="windows",
    ),
    PayloadPattern(
        name="remote_payload_execution",
        category="reflective_payload",
        regex=r"(?i)\b(?:CreateRemoteThread|NtCreateThreadEx|RtlCreateUserThread|QueueUserAPC)\b",
        severity="critical",
        confidence=0.96,
        operation="inject",
        description="Static reference to remote payload execution primitives.",
        platform="windows",
    ),
    PayloadPattern(
        name="shellcode_reference",
        category="shellcode",
        regex=r"(?i)\b(?:shellcode|shell-code|raw\s+shell\s*code|position[- ]independent\s+code)\b",
        severity="high",
        confidence=0.94,
        operation="reference",
        description="Explicit shellcode terminology.",
    ),
    PayloadPattern(
        name="reflective_loader",
        category="reflective_payload",
        regex=r"(?i)\b(?:reflective(?:dll)?loader|reflective\s+loading|manual\s+map(?:ping)?|manual[- ]mapped\s+dll)\b",
        severity="critical",
        confidence=0.96,
        operation="load",
        description="Reflective or manual-mapped payload loading terminology.",
        platform="windows",
    ),
    PayloadPattern(
        name="dll_proxy_execution",
        category="dll_payload",
        regex=r"(?i)\b(?:rundll32(?:\.exe)?|regsvr32(?:\.exe)?|regasm(?:\.exe)?|regsvcs(?:\.exe)?)\b",
        severity="high",
        confidence=0.90,
        operation="execute",
        description="Signed Windows utility used as a DLL/script execution proxy.",
        platform="windows",
    ),
    PayloadPattern(
        name="mshta_payload",
        category="script_payload",
        regex=r"(?i)\bmshta(?:\.exe)?\b",
        severity="high",
        confidence=0.91,
        operation="execute",
        description="MSHTA script execution host.",
        platform="windows",
    ),
    PayloadPattern(
        name="msbuild_payload",
        category="living_off_the_land_payload",
        regex=r"(?i)\bmsbuild(?:\.exe)?\b",
        severity="high",
        confidence=0.88,
        operation="execute",
        description="MSBuild execution proxy frequently associated with script payload delivery.",
        platform="windows",
    ),
    PayloadPattern(
        name="certutil_payload",
        category="living_off_the_land_payload",
        regex=r"(?i)\bcertutil(?:\.exe)?\b.*(?:-decode|-urlcache|-split|-encode)",
        severity="high",
        confidence=0.90,
        operation="transfer",
        description="Certutil used for transfer or encoding/decoding.",
        platform="windows",
    ),
    PayloadPattern(
        name="embedded_ole_payload",
        category="ole_payload",
        regex=r"(?i)(?:oleobject|oleobject|olepackage|packageobject|embedded\s+ole|ole\s+package)",
        severity="medium",
        confidence=0.86,
        operation="embed",
        description="OLE or package object references.",
        platform="windows",
    ),
    PayloadPattern(
        name="activex_payload",
        category="activex_payload",
        regex=r"(?i)\b(?:ActiveXObject|ShockwaveFlash|Forms\.[A-Za-z0-9_]+|MSForms|ActiveX)\b",
        severity="medium",
        confidence=0.82,
        operation="embed",
        description="ActiveX or embedded control references.",
        platform="windows",
    ),
    PayloadPattern(
        name="template_payload",
        category="template_payload",
        regex=r"(?i)\b(?:attachedtemplate|normal\.dotm?|templateurl|remotetemplate|attached\s+template)\b",
        severity="high",
        confidence=0.88,
        operation="reference",
        description="Remote or attached document template references.",
        platform="windows",
    ),
    PayloadPattern(
        name="macro_payload",
        category="macro_payload",
        regex=r"(?i)\b(?:autoopen|autoclose|document_open|workbook_open|workbook_activate|auto_open|auto_close|documentopen)\b",
        severity="medium",
        confidence=0.79,
        operation="execute",
        description="Common automatic macro entry points.",
        platform="windows",
    ),
    PayloadPattern(
        name="file_drop",
        category="payload_drop",
        regex=r"(?i)\b(?:drop(?:s|ped|ping)?|write(?:file|alltext|bytes)|save(?:as)?|creat(?:e|ing)\s+(?:a\s+)?file|output\s+file)\b",
        severity="medium",
        confidence=0.77,
        operation="drop",
        description="Static indication of payload/file creation or dropping.",
    ),
    PayloadPattern(
        name="filesystem_payload_write",
        category="payload_write",
        regex=r"(?i)\b(?:WriteFile|CreateFile|File\.WriteAllBytes|File\.WriteAllText|OpenBinary|ADODB\.Stream|SaveToFile)\b",
        severity="high",
        confidence=0.88,
        operation="write",
        description="File-writing primitives that can stage a payload.",
    ),
    PayloadPattern(
        name="temporary_payload_path",
        category="temporary_payload",
        regex=r"(?i)(?:%temp%|%tmp%|\\temp\\|/tmp/|/var/tmp/|GetTempPath|GetTempFileName)",
        severity="medium",
        confidence=0.80,
        operation="stage",
        description="Temporary directory usage associated with payload staging.",
    ),
    PayloadPattern(
        name="archive_payload",
        category="archive_payload",
        regex=r"(?i)\b(?:expand-archive|tar|unzip|7z|7za|rar|cabextract|gzip|gunzip|decompress)\b",
        severity="medium",
        confidence=0.80,
        operation="decompress",
        description="Archive extraction or decompression.",
    ),
    PayloadPattern(
        name="payload_encryption",
        category="payload_decryption",
        regex=r"(?i)\b(?:decrypt|decryptstring|decryptdata|aes|rijndael|rc4|xor\s+(?:decrypt|decode)|crypto(?:graphy)?\b.*(?:decrypt|decryptor))",
        severity="medium",
        confidence=0.78,
        operation="decrypt",
        description="Static references to payload decryption.",
    ),
    PayloadPattern(
        name="payload_compression",
        category="payload_decompression",
        regex=r"(?i)\b(?:gzipstream|deflatestream|memorystream|decompress(?:ed|ion)?|inflate|gunzip)\b",
        severity="medium",
        confidence=0.78,
        operation="decompress",
        description="Compression/decompression primitives often used for staged payloads.",
    ),
    PayloadPattern(
        name="payload_fragmentation",
        category="payload_fragmentation",
        regex=r"(?i)\b(?:fragment(?:ed|ation)?|chunk(?:ed|ing)?|split(?:ting)?|piece(?:s)?|part(?:1|2|3)?\b.*payload)",
        severity="medium",
        confidence=0.74,
        operation="construct",
        description="Payload fragmentation or chunking terminology.",
    ),
    PayloadPattern(
        name="payload_reassembly",
        category="payload_reassembly",
        regex=r"(?i)\b(?:reassembl(?:e|y)|combine\s+(?:chunks|parts)|join\s+(?:chunks|parts)|concat(?:enate|enation)?)\b",
        severity="medium",
        confidence=0.76,
        operation="reassemble",
        description="Static indication of reconstructing fragmented content.",
    ),
    PayloadPattern(
        name="payload_cleanup",
        category="payload_cleanup",
        regex=r"(?i)\b(?:delete|erase|remove-item|unlink|shred|cleanup|clean\s+up)\b.*(?:payload|drop(?:ped)?\s+file|temp(?:orary)?\s+file|stage(?:d)?\s+file)",
        severity="high",
        confidence=0.88,
        operation="cleanup",
        description="Cleanup of staged or dropped payload artifacts.",
    ),
    PayloadPattern(
        name="download_to_file",
        category="payload_staging",
        regex=r"(?i)(?:download(?:file|string)?|bitsadmin|curl|wget|invoke-webrequest|webclient).*?(?:save|output|outfile|destination|temp|\.exe|\.dll|\.zip)",
        severity="high",
        confidence=0.90,
        operation="stage",
        description="Remote content retrieved and staged as a local payload.",
    ),
    PayloadPattern(
        name="url_payload_reference",
        category="url_payload",
        regex=r"(?i)\b(?:https?|ftp)://[^\s\"'<>]+(?:\.(?:exe|dll|zip|7z|cab|ps1|js|vbs|hta|jar|msi|bin))(?:[?#][^\s\"'<>]*)?",
        severity="high",
        confidence=0.90,
        operation="download",
        description="URL directly referencing a likely payload file.",
    ),
    PayloadPattern(
        name="powershell_payload_file",
        category="powershell_payload",
        regex=r"(?i)\b(?:\.ps1|powershell(?:\.exe)?|pwsh(?:\.exe)?)\b",
        severity="medium",
        confidence=0.78,
        operation="reference",
        description="PowerShell payload reference.",
        platform="windows",
    ),
    PayloadPattern(
        name="javascript_payload_file",
        category="javascript_payload",
        regex=r"(?i)\b(?:\.js|\.jse|\.mjs)\b",
        severity="medium",
        confidence=0.73,
        operation="reference",
        description="JavaScript/JScript payload reference.",
    ),
    PayloadPattern(
        name="vbscript_payload_file",
        category="vbscript_payload",
        regex=r"(?i)\b(?:\.vbs|\.vbe|\.wsf)\b",
        severity="medium",
        confidence=0.73,
        operation="reference",
        description="VBScript/WSF payload reference.",
        platform="windows",
    ),
    PayloadPattern(
        name="executable_payload_reference",
        category="executable_payload",
        regex=r"(?i)(?:[A-Za-z0-9_./\\%$:-]+)\.(?:exe|scr|com|msi|cpl|sys|ocx|dll|jar|bin)\b",
        severity="medium",
        confidence=0.76,
        operation="reference",
        description="Reference to an executable or loadable payload.",
    ),
    PayloadPattern(
        name="network_payload_transfer",
        category="network_payload",
        regex=r"(?i)\b(?:ftp|tftp|smb|webclient|httpclient|winhttp|wininet|bitsadmin|certutil|curl|wget)\b",
        severity="medium",
        confidence=0.75,
        operation="transfer",
        description="Network transfer primitives potentially used for payload delivery.",
    ),
)


# ============================================================================
# Regexes for semantic extraction
# ============================================================================

URL_RE = re.compile(r"(?i)\b(?:https?|ftp)://[^\s\"'<>]+")

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?\b")

WINDOWS_PATH_RE = re.compile(r"""(?ix)
    (?:
        [A-Za-z]:[\\/][^\r\n"'<>]{1,500}
        |
        \\\\[A-Za-z0-9_.-]+\\[^\r\n"'<>]{1,500}
        |
        %(?:TEMP|TMP|APPDATA|LOCALAPPDATA|PROGRAMDATA|WINDIR|SYSTEMROOT)%[\\/][^\r\n"'<>]{1,500}
    )
    """)

UNIX_PATH_RE = re.compile(r"""(?x)
    (?:
        /(?:tmp|var/tmp|dev/shm|home|opt|usr|etc|var)/[^\s"'<>]{1,500}
    )
    """)

EXECUTABLE_RE = re.compile(
    r"(?i)\b[^\s\"'<>]{1,300}\.(?:exe|dll|scr|com|msi|cpl|sys|ocx|jar|bin|so|dylib)\b"
)

SCRIPT_FILE_RE = re.compile(
    r"(?i)\b[^\s\"'<>]{1,300}\.(?:ps1|psm1|psd1|js|jse|vbs|vbe|wsf|hta|bat|cmd|sh|bash|py|pl|rb)\b"
)

BASE64_RE = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{40,}={0,2}(?![A-Za-z0-9+/=])")

HEX_BLOB_RE = re.compile(r"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{2}){32,}(?![0-9A-Fa-f])")

STRING_LITERAL_RE = re.compile(r"""(?xs)
    (?:
        "(?:\\.|[^"\\]){8,}"
        |
        '(?:\\.|[^'\\]){8,}'
    )
    """)

LINE_RE = re.compile(r"\r\n|\r|\n")

WHITESPACE_RE = re.compile(r"\s+")


# ============================================================================
# General helpers
# ============================================================================


def _clamp(value: float, minimum: float = 0.0, maximum: float = 1.0) -> float:
    return max(minimum, min(maximum, value))


def _bounded_int(value: Any, default: int = 0) -> int:
    try:
        result = int(value)
    except (TypeError, ValueError, OverflowError):
        return default
    return max(0, min(result, MAX_FEATURE_VALUE))


def _normalize_text(value: Any) -> str:
    """
    Convert arbitrary supported input into bounded text.

    No object methods are invoked except safe built-in representations.
    """
    if value is None:
        return ""

    if isinstance(value, str):
        return value[:MAX_FIELD_TEXT]

    if isinstance(value, bytes):
        return value[:MAX_FIELD_TEXT].decode("utf-8", errors="replace")

    if isinstance(value, bytearray):
        return bytes(value[:MAX_FIELD_TEXT]).decode("utf-8", errors="replace")

    if isinstance(value, memoryview):
        return bytes(value[:MAX_FIELD_TEXT]).decode("utf-8", errors="replace")

    if isinstance(value, os.PathLike):
        try:
            return os.fspath(value)[:MAX_FIELD_TEXT]
        except TypeError:
            return ""

    if isinstance(value, (int, float, bool)):
        return str(value)

    try:
        return str(value)[:MAX_FIELD_TEXT]
    except Exception:
        return ""


def _read_source(source: Any) -> Tuple[str, int, str]:
    """
    Read source without executing or resolving external resources.

    Returns:
        text, byte_size, source_kind
    """
    if source is None:
        return "", 0, "empty"

    if isinstance(source, bytes):
        data = source[:MAX_SOURCE_SIZE]
        return data.decode("utf-8", errors="replace"), len(data), "bytes"

    if isinstance(source, bytearray):
        data = bytes(source[:MAX_SOURCE_SIZE])
        return data.decode("utf-8", errors="replace"), len(data), "bytes"

    if isinstance(source, memoryview):
        data = bytes(source[:MAX_SOURCE_SIZE])
        return data.decode("utf-8", errors="replace"), len(data), "bytes"

    if isinstance(source, str):
        encoded = source[:MAX_TEXT_CHARS].encode("utf-8", errors="replace")
        return source[:MAX_TEXT_CHARS], min(len(encoded), MAX_SOURCE_SIZE), "text"

    if isinstance(source, os.PathLike):
        try:
            path = Path(source)
            with path.open("rb") as handle:
                data = handle.read(MAX_SOURCE_SIZE + 1)
        except (OSError, ValueError):
            text = _normalize_text(source)
            return text, len(text.encode("utf-8", errors="replace")), "path"

        truncated = data[:MAX_SOURCE_SIZE]
        return (
            truncated.decode("utf-8", errors="replace"),
            len(truncated),
            "file",
        )

    if isinstance(source, Mapping) or isinstance(source, Sequence):
        text = _flatten_input(source)
        encoded = text.encode("utf-8", errors="replace")
        return text[:MAX_TEXT_CHARS], min(len(encoded), MAX_SOURCE_SIZE), "structured"

    text = _normalize_text(source)
    encoded = text.encode("utf-8", errors="replace")
    return text, min(len(encoded), MAX_SOURCE_SIZE), "object"


def _flatten_input(
    value: Any,
    depth: int = 0,
    seen: Optional[Set[int]] = None,
) -> str:
    """
    Safely flatten nested mappings/sequences into searchable text.
    """
    if seen is None:
        seen = set()

    if depth > MAX_NESTING_DEPTH:
        return ""

    if value is None:
        return ""

    primitive_types = (str, bytes, bytearray, memoryview, int, float, bool)

    if isinstance(value, primitive_types):
        return _normalize_text(value)

    object_id = id(value)
    if object_id in seen:
        return ""

    seen.add(object_id)

    chunks: List[str] = []

    if isinstance(value, Mapping):
        count = 0
        for key, item in value.items():
            if count >= MAX_INDICATORS:
                break

            key_text = _normalize_text(key)
            item_text = _flatten_input(item, depth + 1, seen)

            if key_text:
                chunks.append(key_text)
            if item_text:
                chunks.append(item_text)

            count += 1

        return "\n".join(chunks)[:MAX_TEXT_CHARS]

    if isinstance(value, Sequence) and not isinstance(
        value,
        (str, bytes, bytearray, memoryview),
    ):
        count = 0
        for item in value:
            if count >= MAX_INDICATORS:
                break

            item_text = _flatten_input(item, depth + 1, seen)
            if item_text:
                chunks.append(item_text)

            count += 1

        return "\n".join(chunks)[:MAX_TEXT_CHARS]

    # Dataclass-like objects and analysis objects.
    if hasattr(value, "__dict__"):
        try:
            return _flatten_input(vars(value), depth + 1, seen)
        except Exception:
            pass

    return _normalize_text(value)


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def _normalize_line(line: str) -> str:
    return WHITESPACE_RE.sub(" ", line.strip())


def _line_number(text: str, position: int) -> int:
    return text.count("\n", 0, position) + 1


def _bounded_matches(
    pattern: re.Pattern[str],
    text: str,
    limit: int = MAX_MATCHES_PER_RULE,
) -> Iterator[re.Match[str]]:
    count = 0
    try:
        for match in pattern.finditer(text):
            yield match
            count += 1
            if count >= limit:
                break
    except (MemoryError, re.error):
        return


def _compile(pattern: str) -> Optional[re.Pattern[str]]:
    try:
        return re.compile(pattern, re.IGNORECASE | re.MULTILINE)
    except re.error:
        return None


def _safe_evidence_text(text: str, start: int, end: int) -> str:
    """
    Produce a bounded contextual excerpt around a match.
    """
    context_start = max(0, start - 180)
    context_end = min(len(text), end + 220)

    excerpt = text[context_start:context_end]
    excerpt = excerpt.replace("\x00", " ")

    if len(excerpt) > 500:
        excerpt = excerpt[:500]

    return _normalize_line(excerpt)


def _infer_platform(indicator: str, evidence: str) -> str:
    combined = f"{indicator} {evidence}".lower()

    windows_terms = (
        "powershell",
        "wscript",
        "cscript",
        "mshta",
        "rundll32",
        "regsvr32",
        "msbuild",
        "wininet",
        "winhttp",
        "kernel32",
        "advapi32",
        "hkey_",
        "registry",
        "wscript.shell",
        "cmd.exe",
        "\\windows\\",
        "appdata",
        "win32",
        "ole",
        "activex",
        "vba",
        "amsi",
    )

    linux_terms = (
        "/bin/sh",
        "/bin/bash",
        "bash",
        "systemd",
        "ld.so",
        "/etc/",
        "/usr/bin/",
        "/var/tmp/",
        "proc/self",
    )

    macos_terms = (
        "launchagent",
        "launchdaemon",
        "/library/",
        "osascript",
        "applescript",
        "xpc",
        "dyld",
    )

    windows = any(term in combined for term in windows_terms)
    linux = any(term in combined for term in linux_terms)
    macos = any(term in combined for term in macos_terms)

    count = sum((windows, linux, macos))

    if count > 1:
        return "cross_platform"
    if windows:
        return "windows"
    if linux:
        return "linux"
    if macos:
        return "macos"

    return "unknown"


def _infer_operation(indicator: str, evidence: str, default: str) -> str:
    combined = f"{indicator} {evidence}".lower()

    operation_terms = (
        ("cleanup", "cleanup"),
        ("delete", "cleanup"),
        ("erase", "cleanup"),
        ("remove-item", "cleanup"),
        ("download", "download"),
        ("downloadstring", "download"),
        ("downloadfile", "download"),
        ("invoke-webrequest", "download"),
        ("invoke-restmethod", "download"),
        ("curl", "download"),
        ("wget", "download"),
        ("decode", "decode"),
        ("frombase64string", "decode"),
        ("-encodedcommand", "decode"),
        ("decrypt", "decrypt"),
        ("decompress", "decompress"),
        ("expand-archive", "decompress"),
        ("writefile", "write"),
        ("writeallbytes", "write"),
        ("savetofile", "write"),
        ("createfile", "write"),
        ("virtualalloc", "write"),
        ("writeprocessmemory", "write"),
        ("createremotethread", "inject"),
        ("queueuserapc", "inject"),
        ("reflective", "load"),
        ("assembly.load", "load"),
        ("execute", "execute"),
        ("invoke-expression", "execute"),
        ("iex", "execute"),
        ("eval", "execute"),
        ("drop", "drop"),
        ("stage", "stage"),
        ("stager", "stage"),
        ("fragment", "construct"),
        ("chunk", "construct"),
        ("reassembl", "reassemble"),
        ("obfuscat", "obfuscate"),
        ("encrypt", "encrypt"),
    )

    for term, operation in operation_terms:
        if term in combined:
            return operation

    return default if default in OPERATIONS else "unknown"


def _infer_target(indicator: str, evidence: str) -> Optional[str]:
    combined = f"{indicator} {evidence}"

    patterns = (
        EXECUTABLE_RE,
        SCRIPT_FILE_RE,
        URL_RE,
        WINDOWS_PATH_RE,
        UNIX_PATH_RE,
        IP_RE,
    )

    for pattern in patterns:
        match = pattern.search(combined)
        if match:
            target = match.group(0).strip()
            if target:
                return target[:500]

    lowered = combined.lower()

    target_terms = (
        "shellcode",
        "dll",
        "exe",
        "powershell",
        "javascript",
        "vbscript",
        "macro",
        "assembly",
        "payload",
        "archive",
        "template",
        "activex",
        "ole",
    )

    for term in target_terms:
        if term in lowered:
            return term

    return None


def _severity_rank(severity: str) -> int:
    return {
        "low": 1,
        "medium": 2,
        "high": 3,
        "critical": 4,
    }.get(severity.lower(), 0)


def _upgrade_severity(
    severity: str,
    *,
    operation: str,
    category: str,
    has_execution_context: bool,
) -> str:
    """
    Increase confidence/severity when payload evidence is part of an
    execution chain.
    """
    rank = _severity_rank(severity)

    if has_execution_context and category in {
        "payload_decoding",
        "payload_download",
        "payload_decompression",
        "payload_decryption",
        "payload_write",
        "payload_staging",
        "payload_construction",
        "payload_obfuscation",
        "powershell_payload",
        "javascript_payload",
        "vbscript_payload",
    }:
        rank = min(4, rank + 1)

    if operation in {"inject", "load"} and category in {
        "memory_payload",
        "reflective_payload",
        "shellcode",
        "assembly_payload",
    }:
        rank = max(rank, 3)

    return {
        1: "low",
        2: "medium",
        3: "high",
        4: "critical",
    }.get(rank, "medium")


# ============================================================================
# Encoded-content analysis
# ============================================================================


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0

    counts = Counter(data)
    length = len(data)

    entropy = 0.0
    for count in counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return entropy


def _printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0

    printable = sum(1 for byte in data if byte in (9, 10, 13) or 32 <= byte <= 126)

    return printable / len(data)


def _looks_like_base64(candidate: str) -> bool:
    candidate = re.sub(r"\s+", "", candidate)

    if len(candidate) < 40:
        return False

    if len(candidate) % 4 not in (0, 2, 3):
        return False

    if not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", candidate):
        return False

    return True


def _analyze_base64_candidate(candidate: str) -> Optional[PayloadCandidate]:
    compact = re.sub(r"\s+", "", candidate)

    if len(compact) > MAX_DECODE_SAMPLE:
        compact = compact[:MAX_DECODE_SAMPLE]

    if not _looks_like_base64(compact):
        return None

    padded = compact + ("=" * ((4 - len(compact) % 4) % 4))

    try:
        decoded = base64.b64decode(
            padded,
            validate=True,
        )
    except (ValueError, binascii.Error if "binascii" in globals() else ValueError):
        # The fallback expression above intentionally avoids importing another
        # module just for an exception class; base64 may raise ValueError.
        return None

    if not decoded:
        return None

    printable = _printable_ratio(decoded)
    entropy = _entropy(decoded)

    confidence = 0.60

    if len(decoded) >= 64:
        confidence += 0.08

    if printable > 0.65:
        confidence += 0.10

    if decoded.startswith(b"MZ"):
        confidence += 0.20
    elif decoded.startswith(b"PK\x03\x04"):
        confidence += 0.16
    elif decoded.startswith(b"\x7fELF"):
        confidence += 0.20

    confidence = _clamp(confidence)

    return PayloadCandidate(
        kind="base64",
        length=len(compact),
        confidence=confidence,
        entropy=entropy,
        decoded_size=min(len(decoded), MAX_DECODE_SAMPLE),
        printable_ratio=printable,
        indicator="base64_blob",
    )


def _extract_base64_candidates(text: str) -> List[PayloadCandidate]:
    candidates: List[PayloadCandidate] = []

    for match in _bounded_matches(BASE64_RE, text, MAX_PAYLOAD_CANDIDATES):
        candidate = _analyze_base64_candidate(match.group(0))

        if candidate is None:
            continue

        candidates.append(candidate)

        if len(candidates) >= MAX_PAYLOAD_CANDIDATES:
            break

    return candidates


def _extract_hex_candidates(text: str) -> List[PayloadCandidate]:
    candidates: List[PayloadCandidate] = []

    for match in _bounded_matches(
        HEX_BLOB_RE,
        text,
        MAX_PAYLOAD_CANDIDATES,
    ):
        value = match.group(0)

        try:
            decoded = bytes.fromhex(value[:MAX_DECODE_SAMPLE])
        except ValueError:
            continue

        if not decoded:
            continue

        printable = _printable_ratio(decoded)
        entropy = _entropy(decoded)

        confidence = 0.50

        if decoded.startswith(b"MZ"):
            confidence += 0.25
        elif decoded.startswith(b"PK\x03\x04"):
            confidence += 0.20
        elif decoded.startswith(b"\x7fELF"):
            confidence += 0.25

        candidates.append(
            PayloadCandidate(
                kind="hex",
                length=len(value),
                confidence=_clamp(confidence),
                entropy=entropy,
                decoded_size=min(len(decoded), MAX_DECODE_SAMPLE),
                printable_ratio=printable,
                indicator="hex_blob",
            )
        )

        if len(candidates) >= MAX_PAYLOAD_CANDIDATES:
            break

    return candidates


# ============================================================================
# Static payload-pattern analysis
# ============================================================================


def _build_patterns() -> Tuple[Tuple[PayloadPattern, re.Pattern[str]], ...]:
    compiled: List[Tuple[PayloadPattern, re.Pattern[str]]] = []

    for pattern in PATTERN_DEFINITIONS:
        regex = _compile(pattern.regex)
        if regex is not None:
            compiled.append((pattern, regex))

    return tuple(compiled)


COMPILED_PATTERNS = _build_patterns()


def _has_execution_context(text: str) -> bool:
    lowered = text.lower()

    execution_terms = (
        "createprocess",
        "shellexecute",
        "winexec",
        "process.start",
        "start-process",
        "invoke-expression",
        "iex",
        "eval(",
        "execute(",
        "executeGlobal",
        "cmd.exe",
        "powershell.exe",
        "wscript.exe",
        "cscript.exe",
        "mshta.exe",
        "rundll32.exe",
        "regsvr32.exe",
        "createremotethread",
        "writeprocessmemory",
        "virtualalloc",
        "assembly.load",
        "shellcode",
    )

    return any(term.lower() in lowered for term in execution_terms)


def _add_evidence(
    evidence: List[PayloadEvidence],
    *,
    category: str,
    indicator: str,
    excerpt: str,
    source: str,
    line_number: Optional[int],
    operation: str,
    target: Optional[str],
    platform: str,
    confidence: float,
    severity: str,
    rule: Optional[str],
) -> None:
    if len(evidence) >= MAX_EVIDENCE_ITEMS:
        return

    evidence.append(
        PayloadEvidence(
            category=category,
            indicator=indicator,
            evidence=excerpt[:500],
            source=source,
            line_number=line_number,
            operation=operation,
            target=target,
            platform=platform,
            confidence=_clamp(confidence),
            severity=severity,
            rule=rule,
        )
    )


def _match_patterns(
    text: str,
    source_kind: str,
) -> List[PayloadEvidence]:
    evidence: List[PayloadEvidence] = []
    execution_context = _has_execution_context(text)

    for pattern, compiled in COMPILED_PATTERNS:
        for match in _bounded_matches(
            compiled,
            text,
            MAX_MATCHES_PER_RULE,
        ):
            indicator = match.group(0).strip()

            if not indicator:
                continue

            excerpt = _safe_evidence_text(
                text,
                match.start(),
                match.end(),
            )

            line_number = _line_number(text, match.start())

            operation = _infer_operation(
                indicator,
                excerpt,
                pattern.operation,
            )

            target = _infer_target(
                indicator,
                excerpt,
            )

            platform = (
                pattern.platform
                if pattern.platform != "unknown"
                else _infer_platform(indicator, excerpt)
            )

            confidence = pattern.confidence

            if execution_context:
                confidence = min(
                    1.0,
                    confidence + 0.05,
                )

            severity = _upgrade_severity(
                pattern.severity,
                operation=operation,
                category=pattern.category,
                has_execution_context=execution_context,
            )

            _add_evidence(
                evidence,
                category=pattern.category,
                indicator=pattern.name,
                excerpt=excerpt,
                source=source_kind,
                line_number=line_number,
                operation=operation,
                target=target,
                platform=platform,
                confidence=confidence,
                severity=severity,
                rule=pattern.name,
            )

            if len(evidence) >= MAX_EVIDENCE_ITEMS:
                return evidence

    return evidence


def _match_structural_payload_signals(
    text: str,
    source_kind: str,
) -> List[PayloadEvidence]:
    evidence: List[PayloadEvidence] = []

    # URLs can be payload delivery mechanisms, but URL presence by itself is
    # intentionally treated as medium/low-confidence reference evidence.
    for match in _bounded_matches(URL_RE, text, MAX_MATCHES_PER_RULE):
        url = match.group(0)

        lowered = url.lower()

        likely_payload = any(
            extension in lowered
            for extension in (
                ".exe",
                ".dll",
                ".zip",
                ".7z",
                ".cab",
                ".ps1",
                ".js",
                ".jse",
                ".vbs",
                ".vbe",
                ".hta",
                ".jar",
                ".msi",
                ".bin",
            )
        )

        if not likely_payload:
            continue

        excerpt = _safe_evidence_text(
            text,
            match.start(),
            match.end(),
        )

        _add_evidence(
            evidence,
            category="url_payload",
            indicator="payload_url",
            excerpt=excerpt,
            source=source_kind,
            line_number=_line_number(text, match.start()),
            operation="download",
            target=url[:500],
            platform=_infer_platform(url, excerpt),
            confidence=0.90,
            severity="high",
            rule="url_payload_reference",
        )

        if len(evidence) >= MAX_EVIDENCE_ITEMS:
            break

    # Executable file references.
    for match in _bounded_matches(
        EXECUTABLE_RE,
        text,
        MAX_MATCHES_PER_RULE,
    ):
        target = match.group(0)

        excerpt = _safe_evidence_text(
            text,
            match.start(),
            match.end(),
        )

        _add_evidence(
            evidence,
            category="executable_payload",
            indicator="executable_reference",
            excerpt=excerpt,
            source=source_kind,
            line_number=_line_number(text, match.start()),
            operation="reference",
            target=target[:500],
            platform=_infer_platform(target, excerpt),
            confidence=0.72,
            severity="medium",
            rule="executable_payload_reference",
        )

        if len(evidence) >= MAX_EVIDENCE_ITEMS:
            break

    # Script references.
    for match in _bounded_matches(
        SCRIPT_FILE_RE,
        text,
        MAX_MATCHES_PER_RULE,
    ):
        target = match.group(0)

        excerpt = _safe_evidence_text(
            text,
            match.start(),
            match.end(),
        )

        _add_evidence(
            evidence,
            category="script_payload",
            indicator="script_reference",
            excerpt=excerpt,
            source=source_kind,
            line_number=_line_number(text, match.start()),
            operation="reference",
            target=target[:500],
            platform=_infer_platform(target, excerpt),
            confidence=0.70,
            severity="medium",
            rule="script_payload_reference",
        )

        if len(evidence) >= MAX_EVIDENCE_ITEMS:
            break

    return evidence


# ============================================================================
# Semantic evidence normalization
# ============================================================================


def _deduplicate_evidence(
    evidence: Iterable[PayloadEvidence],
) -> List[PayloadEvidence]:
    result: List[PayloadEvidence] = []
    seen: Set[Tuple[Any, ...]] = set()

    for item in evidence:
        key = (
            item.category,
            item.indicator,
            item.line_number,
            item.operation,
            item.target,
            item.evidence[:240],
        )

        if key in seen:
            continue

        seen.add(key)
        result.append(item)

        if len(result) >= MAX_EVIDENCE_ITEMS:
            break

    return result


def _evidence_to_records(
    evidence: Iterable[PayloadEvidence],
) -> List[PayloadRecord]:
    records: List[PayloadRecord] = []
    seen: Set[Tuple[Any, ...]] = set()

    for item in evidence:
        key = (
            item.category,
            item.indicator,
            item.target,
            item.operation,
        )

        if key in seen:
            continue

        seen.add(key)

        mechanism = item.indicator.replace("_", " ")

        records.append(
            PayloadRecord(
                mechanism=mechanism,
                category=item.category,
                target=item.target,
                operation=item.operation,
                platform=item.platform,
                indicator=item.indicator,
                evidence=item.evidence,
                severity=item.severity,
                confidence=item.confidence,
            )
        )

        if len(records) >= MAX_RECORDS:
            break

    return records


def _count_indicators(
    evidence: Iterable[PayloadEvidence],
) -> Dict[str, int]:
    counts: Counter[str] = Counter()

    for item in evidence:
        counts[item.indicator] += 1

    return dict(sorted(counts.items()))


def _count_categories(
    evidence: Iterable[PayloadEvidence],
) -> Dict[str, int]:
    counts: Counter[str] = Counter()

    for item in evidence:
        counts[item.category] += 1

    return dict(sorted(counts.items()))


def _collect_targets(
    evidence: Iterable[PayloadEvidence],
) -> List[str]:
    targets: Set[str] = set()

    for item in evidence:
        if item.target:
            targets.add(item.target[:500])

        if len(targets) >= MAX_TARGETS:
            break

    return sorted(targets)


def _collect_platforms(
    evidence: Iterable[PayloadEvidence],
) -> List[str]:
    platforms: Set[str] = set()

    for item in evidence:
        if item.platform in PLATFORMS:
            if item.platform != "unknown":
                platforms.add(item.platform)

    return sorted(platforms)


# ============================================================================
# Combination analysis
# ============================================================================


def _category_present(
    category_counts: Mapping[str, int],
    category: str,
) -> bool:
    return int(category_counts.get(category, 0)) > 0


def _has_execution_indicator(
    indicator_counts: Mapping[str, int],
) -> bool:
    execution_indicators = {
        "powershell_encoded_command",
        "powershell_dynamic_payload",
        "javascript_dynamic_payload",
        "vbscript_dynamic_payload",
        "assembly_load",
        "remote_payload_execution",
        "memory_payload",
        "dll_proxy_execution",
        "mshta_payload",
        "msbuild_payload",
        "macro_payload",
    }

    return any(
        indicator_counts.get(indicator, 0) > 0 for indicator in execution_indicators
    )


def _derive_combinations(
    category_counts: Mapping[str, int],
    indicator_counts: Mapping[str, int],
) -> List[PayloadCombination]:
    combinations: List[PayloadCombination] = []

    def present(*categories: str) -> bool:
        return all(
            _category_present(category_counts, category) for category in categories
        )

    definitions = (
        (
            "download_stage_execute",
            (
                "payload_download",
                "payload_staging",
                "payload_execution",
            ),
            "Remote content is retrieved, staged, and associated with execution.",
        ),
        (
            "download_write_execute",
            (
                "payload_download",
                "payload_write",
                "payload_execution",
            ),
            "Remote content is downloaded, written locally, and associated with execution.",
        ),
        (
            "decode_execute",
            (
                "payload_decoding",
                "payload_execution",
            ),
            "Encoded content is decoded in an execution context.",
        ),
        (
            "decompress_execute",
            (
                "payload_decompression",
                "payload_execution",
            ),
            "Compressed content is decompressed in an execution context.",
        ),
        (
            "decrypt_execute",
            (
                "payload_decryption",
                "payload_execution",
            ),
            "Encrypted content is decrypted in an execution context.",
        ),
        (
            "memory_payload_chain",
            (
                "memory_payload",
                "payload_execution",
            ),
            "Payload-related memory manipulation is combined with execution.",
        ),
        (
            "reflective_payload_chain",
            (
                "reflective_payload",
                "memory_payload",
            ),
            "Reflective/manual payload loading is combined with memory manipulation.",
        ),
        (
            "shellcode_memory_chain",
            (
                "shellcode",
                "memory_payload",
            ),
            "Explicit shellcode evidence is combined with memory payload primitives.",
        ),
        (
            "script_payload_execution",
            (
                "script_payload",
                "payload_execution",
            ),
            "A script payload reference is combined with execution capability.",
        ),
        (
            "powershell_payload_chain",
            (
                "powershell_payload",
                "payload_download",
            ),
            "PowerShell payload capability is combined with remote retrieval.",
        ),
        (
            "payload_cleanup_chain",
            (
                "payload_drop",
                "payload_cleanup",
            ),
            "A dropped payload is followed by cleanup/removal evidence.",
        ),
        (
            "payload_obfuscation_chain",
            (
                "payload_obfuscation",
                "payload_decoding",
            ),
            "Obfuscation and decoding are combined in the payload path.",
        ),
        (
            "fragment_reassembly_chain",
            (
                "payload_fragmentation",
                "payload_reassembly",
            ),
            "Fragmented payload content is reconstructed.",
        ),
        (
            "living_off_the_land_delivery",
            (
                "living_off_the_land_payload",
                "payload_download",
            ),
            "A signed/native utility is associated with remote payload delivery.",
        ),
        (
            "document_embedded_payload",
            (
                "document_payload",
                "payload_embedding",
            ),
            "A document artifact contains or references embedded payload content.",
        ),
    )

    for name, required, explanation in definitions:
        combinations.append(
            PayloadCombination(
                name=name,
                present=present(*required),
                required_categories=tuple(required),
                explanation=explanation,
            )
        )

    # Dynamic execution may not be represented as a dedicated category in
    # this module. Derive it from stable execution indicators.
    combinations.append(
        PayloadCombination(
            name="dynamic_decode_execution",
            present=(
                _category_present(category_counts, "payload_decoding")
                and _has_execution_indicator(indicator_counts)
            ),
            required_categories=(
                "payload_decoding",
                "payload_execution",
            ),
            explanation=(
                "Encoded content is present together with a payload execution "
                "indicator."
            ),
        )
    )

    # Broad multi-stage payload chain.
    stage_categories = (
        "payload_download",
        "payload_decoding",
        "payload_decompression",
        "payload_decryption",
        "payload_write",
        "payload_staging",
        "payload_execution",
    )

    stage_count = sum(
        1
        for category in stage_categories
        if _category_present(category_counts, category)
    )

    combinations.append(
        PayloadCombination(
            name="multi_stage_payload",
            present=stage_count >= 3,
            required_categories=tuple(stage_categories),
            explanation=(
                "At least three distinct payload delivery, transformation, "
                "staging, or execution stages are present."
            ),
        )
    )

    return combinations


# ============================================================================
# Feature vector
# ============================================================================


def _safe_feature_name(value: str) -> str:
    return re.sub(
        r"[^a-zA-Z0-9_]+",
        "_",
        value.strip().lower(),
    ).strip("_")


def _calculate_signal_score(
    evidence: Sequence[PayloadEvidence],
    combinations: Sequence[PayloadCombination],
    candidates: Sequence[PayloadCandidate],
) -> float:
    score = 0.0

    severity_weights = {
        "low": 0.50,
        "medium": 1.00,
        "high": 2.00,
        "critical": 3.50,
    }

    for item in evidence:
        score += severity_weights.get(item.severity, 1.0) * _clamp(item.confidence)

    for combination in combinations:
        if combination.present:
            score += 2.5

    for candidate in candidates:
        if candidate.confidence >= 0.85:
            score += 1.25
        elif candidate.confidence >= 0.70:
            score += 0.75
        else:
            score += 0.25

    return min(score, 10_000.0)


def _build_feature_vector(
    source_size: int,
    evidence: Sequence[PayloadEvidence],
    records: Sequence[PayloadRecord],
    combinations: Sequence[PayloadCombination],
    candidates: Sequence[PayloadCandidate],
) -> Dict[str, float]:
    indicator_counts = _count_indicators(evidence)
    category_counts = _count_categories(evidence)

    high_count = sum(1 for item in evidence if item.severity == "high")

    critical_count = sum(1 for item in evidence if item.severity == "critical")

    operation_counts = Counter(item.operation for item in evidence)

    platform_counts = Counter(item.platform for item in evidence)

    vector: Dict[str, float] = {
        "source_size": float(_bounded_int(source_size)),
        "record_count": float(len(records)),
        "evidence_count": float(len(evidence)),
        "target_count": float(len(_collect_targets(evidence))),
        "platform_count": float(len(_collect_platforms(evidence))),
        "indicator_count": float(len(indicator_counts)),
        "category_count": float(len(category_counts)),
        "combination_count": float(len(combinations)),
        "candidate_count": float(len(candidates)),
        "high_count": float(high_count),
        "critical_count": float(critical_count),
        "reference_count": float(operation_counts.get("reference", 0)),
        "identify_count": float(operation_counts.get("identify", 0)),
        "construct_count": float(operation_counts.get("construct", 0)),
        "decode_count": float(operation_counts.get("decode", 0)),
        "decompress_count": float(operation_counts.get("decompress", 0)),
        "decrypt_count": float(operation_counts.get("decrypt", 0)),
        "encode_count": float(operation_counts.get("encode", 0)),
        "stage_count": float(operation_counts.get("stage", 0)),
        "drop_count": float(operation_counts.get("drop", 0)),
        "write_count": float(operation_counts.get("write", 0)),
        "download_count": float(operation_counts.get("download", 0)),
        "transfer_count": float(operation_counts.get("transfer", 0)),
        "embed_count": float(operation_counts.get("embed", 0)),
        "extract_count": float(operation_counts.get("extract", 0)),
        "execute_count": float(operation_counts.get("execute", 0)),
        "load_count": float(operation_counts.get("load", 0)),
        "inject_count": float(operation_counts.get("inject", 0)),
        "reassemble_count": float(operation_counts.get("reassemble", 0)),
        "cleanup_count": float(operation_counts.get("cleanup", 0)),
        "obfuscate_count": float(operation_counts.get("obfuscate", 0)),
        "handoff_count": float(operation_counts.get("handoff", 0)),
        "windows_count": float(platform_counts.get("windows", 0)),
        "linux_count": float(platform_counts.get("linux", 0)),
        "macos_count": float(platform_counts.get("macos", 0)),
        "cross_platform_count": float(platform_counts.get("cross_platform", 0)),
        "base64_candidate_count": float(
            sum(1 for candidate in candidates if candidate.kind == "base64")
        ),
        "hex_candidate_count": float(
            sum(1 for candidate in candidates if candidate.kind == "hex")
        ),
        "high_confidence_candidate_count": float(
            sum(1 for candidate in candidates if candidate.confidence >= 0.85)
        ),
        "signal_score": _calculate_signal_score(
            evidence,
            combinations,
            candidates,
        ),
    }

    # Stable category features.
    for category in PAYLOAD_CATEGORIES:
        key = _safe_feature_name(category)

        vector[f"category_{key}_present"] = float(category_counts.get(category, 0) > 0)

        vector[f"category_{key}_count"] = float(category_counts.get(category, 0))

    # Stable indicator features.
    indicator_names = sorted(
        set(PAYLOAD_INDICATOR_ALIASES.values())
        | {pattern.name for pattern in PATTERN_DEFINITIONS}
        | {
            "base64_blob",
            "hex_blob",
            "payload_url",
            "executable_reference",
            "script_reference",
        }
    )

    for indicator in indicator_names:
        key = _safe_feature_name(indicator)

        vector[f"indicator_{key}_present"] = float(
            indicator_counts.get(indicator, 0) > 0
        )

        vector[f"indicator_{key}_count"] = float(indicator_counts.get(indicator, 0))

    for combination in combinations:
        key = _safe_feature_name(combination.name)

        vector[f"combination_{key}_present"] = float(combination.present)

    return vector


# ============================================================================
# Public analysis functions
# ============================================================================


def analyze_payload(
    source: Any,
    *,
    source_name: Optional[str] = None,
    include_candidates: bool = True,
) -> PayloadAnalysis:
    """
    Analyze an artifact for static payload capabilities.

    Args:
        source:
            Text, bytes, path, mapping, sequence, or analysis object.
        source_name:
            Optional logical source name stored in evidence.
        include_candidates:
            Whether bounded encoded-content candidate analysis is performed.

    Returns:
        PayloadAnalysis
    """
    text, source_size, source_kind = _read_source(source)

    if len(text) > MAX_TEXT_CHARS:
        text = text[:MAX_TEXT_CHARS]

    source_label = source_name[:500] if source_name else source_kind

    evidence = _match_patterns(
        text,
        source_label,
    )

    structural_evidence = _match_structural_payload_signals(
        text,
        source_label,
    )

    evidence.extend(structural_evidence)

    candidates: List[PayloadCandidate] = []

    if include_candidates:
        candidates.extend(_extract_base64_candidates(text))
        candidates.extend(_extract_hex_candidates(text))

    # Base64 candidates are evidence only when they have sufficient size and
    # confidence. This avoids treating every random high-entropy string as a
    # payload.
    for candidate in candidates:
        if len(evidence) >= MAX_EVIDENCE_ITEMS:
            break

        if candidate.confidence < 0.65:
            continue

        severity = "medium"

        if candidate.confidence >= 0.90:
            severity = "high"

        evidence.append(
            PayloadEvidence(
                category="payload_encoding",
                indicator=candidate.indicator or f"{candidate.kind}_blob",
                evidence=(
                    f"Static {candidate.kind} candidate; "
                    f"encoded_length={candidate.length}; "
                    f"decoded_size={candidate.decoded_size}; "
                    f"entropy={candidate.entropy:.3f}; "
                    f"printable_ratio="
                    f"{candidate.printable_ratio:.3f}"
                    if candidate.printable_ratio is not None
                    else (
                        f"Static {candidate.kind} candidate; "
                        f"encoded_length={candidate.length}; "
                        f"decoded_size={candidate.decoded_size}; "
                        f"entropy={candidate.entropy:.3f}"
                    )
                ),
                source=source_label,
                line_number=None,
                operation="decode",
                target=None,
                platform="unknown",
                confidence=candidate.confidence,
                severity=severity,
                rule=f"{candidate.kind}_candidate",
            )
        )

    evidence = _deduplicate_evidence(evidence)

    category_counts = _count_categories(evidence)
    indicator_counts = _count_indicators(evidence)

    # Add explicit payload execution category when an execution indicator
    # exists. This is derived rather than pattern-matched so downstream
    # consumers get a stable capability category.
    if _has_execution_indicator(indicator_counts):
        derived_execution = PayloadEvidence(
            category="payload_execution",
            indicator="derived_payload_execution",
            evidence=(
                "Payload execution capability inferred from static execution "
                "or loader indicators."
            ),
            source=source_label,
            line_number=None,
            operation="execute",
            target=_infer_target(
                "payload execution",
                text[:1000],
            ),
            platform=_infer_platform(
                "payload execution",
                text[:2000],
            ),
            confidence=0.82,
            severity="high",
            rule="derived_payload_execution",
        )

        evidence.append(derived_execution)
        evidence = _deduplicate_evidence(evidence)

    # Derive additional categories from strong mechanisms.
    indicator_counts = _count_indicators(evidence)
    category_counts = _count_categories(evidence)

    derived_categories: List[Tuple[str, str, str, str, float, str]] = []

    if category_counts.get("payload_obfuscation", 0) == 0 and (
        indicator_counts.get("powershell_encoded_command", 0) > 0
        or indicator_counts.get("base64_blob", 0) > 0
    ):
        derived_categories.append(
            (
                "payload_obfuscation",
                "derived_payload_obfuscation",
                "Encoded payload content may provide obfuscation.",
                "obfuscate",
                0.76,
                "medium",
            )
        )

    if category_counts.get("payload_embedding", 0) == 0 and (
        category_counts.get("ole_payload", 0) > 0
        or category_counts.get("activex_payload", 0) > 0
        or category_counts.get("embedded_objects", 0) > 0
    ):
        derived_categories.append(
            (
                "payload_embedding",
                "derived_payload_embedding",
                "Payload embedding inferred from document object indicators.",
                "embed",
                0.82,
                "medium",
            )
        )

    for (
        category,
        indicator,
        message,
        operation,
        confidence,
        severity,
    ) in derived_categories:
        evidence.append(
            PayloadEvidence(
                category=category,
                indicator=indicator,
                evidence=message,
                source=source_label,
                operation=operation,
                confidence=confidence,
                severity=severity,
                rule=indicator,
            )
        )

    evidence = _deduplicate_evidence(evidence)

    records = _evidence_to_records(evidence)

    indicator_counts = _count_indicators(evidence)
    category_counts = _count_categories(evidence)

    combinations = _derive_combinations(
        category_counts,
        indicator_counts,
    )

    targets = _collect_targets(evidence)
    platforms = _collect_platforms(evidence)

    feature_vector = _build_feature_vector(
        source_size,
        evidence,
        records,
        combinations,
        candidates,
    )

    metadata: Dict[str, Any] = {
        "source_kind": source_kind,
        "source_name": source_name,
        "static_only": True,
        "executed_code": False,
        "network_access": False,
        "filesystem_payload_extraction": False,
        "candidate_analysis_enabled": include_candidates,
        "pattern_count": len(PATTERN_DEFINITIONS),
        "max_source_size": MAX_SOURCE_SIZE,
        "max_evidence_items": MAX_EVIDENCE_ITEMS,
        "max_payload_candidates": MAX_PAYLOAD_CANDIDATES,
        "severity": highest_severity(
            PayloadAnalysis(
                source_hash=_sha256_text(text),
                source_size=source_size,
                records=records,
                evidence=evidence,
                indicators=indicator_counts,
                categories=category_counts,
                combinations=combinations,
                targets=targets,
                platforms=platforms,
                candidates=candidates,
                feature_vector=feature_vector,
                metadata={},
            )
        ),
    }

    return PayloadAnalysis(
        source_hash=_sha256_text(text),
        source_size=source_size,
        records=records,
        evidence=evidence,
        indicators=indicator_counts,
        categories=category_counts,
        combinations=combinations,
        targets=targets,
        platforms=platforms,
        candidates=candidates,
        feature_vector=feature_vector,
        metadata=metadata,
    )


def analyze_payload_capabilities(
    source: Any,
    *,
    source_name: Optional[str] = None,
    include_candidates: bool = True,
) -> PayloadAnalysis:
    """
    Compatibility alias for analyze_payload().
    """
    return analyze_payload(
        source,
        source_name=source_name,
        include_candidates=include_candidates,
    )


def analyze(
    source: Any,
    *,
    source_name: Optional[str] = None,
    include_candidates: bool = True,
) -> PayloadAnalysis:
    """
    Short alias for analyze_payload().
    """
    return analyze_payload(
        source,
        source_name=source_name,
        include_candidates=include_candidates,
    )


def parse_payload(
    source: Any,
    *,
    source_name: Optional[str] = None,
    include_candidates: bool = True,
) -> PayloadAnalysis:
    """
    Parse/analyze payload indicators without executing content.
    """
    return analyze_payload(
        source,
        source_name=source_name,
        include_candidates=include_candidates,
    )


def extract_payload_features(
    source: Any,
    *,
    source_name: Optional[str] = None,
    include_candidates: bool = True,
) -> Dict[str, float]:
    """
    Extract the stable payload feature vector.
    """
    return analyze_payload(
        source,
        source_name=source_name,
        include_candidates=include_candidates,
    ).feature_vector


def extract_feature_vector(
    source: Any,
    *,
    source_name: Optional[str] = None,
    include_candidates: bool = True,
) -> Dict[str, float]:
    """
    Generic feature-vector alias.
    """
    return extract_payload_features(
        source,
        source_name=source_name,
        include_candidates=include_candidates,
    )


def extract_payload_feature_vector(
    source: Any,
    *,
    source_name: Optional[str] = None,
    include_candidates: bool = True,
) -> Dict[str, float]:
    """
    Explicit payload feature-vector API.
    """
    return extract_payload_features(
        source,
        source_name=source_name,
        include_candidates=include_candidates,
    )


def extract_payload_records(
    source: Any,
    *,
    source_name: Optional[str] = None,
    include_candidates: bool = True,
) -> List[PayloadRecord]:
    """
    Return normalized payload capability records.
    """
    return analyze_payload(
        source,
        source_name=source_name,
        include_candidates=include_candidates,
    ).records


# ============================================================================
# Query helpers
# ============================================================================


def has_indicator(
    analysis: PayloadAnalysis,
    indicator: str,
) -> bool:
    """
    Return True when an indicator is present.
    """
    return analysis.indicators.get(indicator, 0) > 0


def indicator_count(
    analysis: PayloadAnalysis,
    indicator: str,
) -> int:
    """
    Return the count for an indicator.
    """
    return int(analysis.indicators.get(indicator, 0))


def has_category(
    analysis: PayloadAnalysis,
    category: str,
) -> bool:
    """
    Return True when a payload category is present.
    """
    return analysis.categories.get(category, 0) > 0


def category_count(
    analysis: PayloadAnalysis,
    category: str,
) -> int:
    """
    Return the count for a payload category.
    """
    return int(analysis.categories.get(category, 0))


def evidence_by_category(
    analysis: PayloadAnalysis,
    category: str,
) -> List[PayloadEvidence]:
    """
    Return evidence belonging to a category.
    """
    return [item for item in analysis.evidence if item.category == category]


def evidence_by_indicator(
    analysis: PayloadAnalysis,
    indicator: str,
) -> List[PayloadEvidence]:
    """
    Return evidence belonging to an indicator.
    """
    return [item for item in analysis.evidence if item.indicator == indicator]


def high_risk_evidence(
    analysis: PayloadAnalysis,
) -> List[PayloadEvidence]:
    """
    Return high/critical payload evidence.
    """
    return [item for item in analysis.evidence if item.severity in {"high", "critical"}]


def present_combinations(
    analysis: PayloadAnalysis,
) -> List[PayloadCombination]:
    """
    Return only derived payload chains that are present.
    """
    return [item for item in analysis.combinations if item.present]


def highest_severity(
    analysis: PayloadAnalysis,
) -> str:
    """
    Return the highest observed evidence severity.
    """
    highest = "low"

    for item in analysis.evidence:
        if _severity_rank(item.severity) > _severity_rank(highest):
            highest = item.severity

    return highest


# ============================================================================
# Feature schema
# ============================================================================


def payload_feature_names() -> List[str]:
    """
    Return stable feature names.

    The list is deterministic and can be used to construct ML matrices.
    """
    dummy_evidence: List[PayloadEvidence] = []

    dummy_combinations = _derive_combinations(
        {},
        {},
    )

    dummy_vector = _build_feature_vector(
        0,
        dummy_evidence,
        [],
        dummy_combinations,
        [],
    )

    return list(dummy_vector.keys())


def evasion_safe_feature_names() -> List[str]:
    """
    Backward-compatible helper name for callers that historically used a
    generic capability feature-name function.
    """
    return payload_feature_names()


def build_feature_schema() -> Dict[str, Any]:
    """
    Build a machine-readable feature schema.
    """
    names = payload_feature_names()

    return {
        "schema_version": "1.0",
        "module": "pharos_cdr.extraction.capabilities.payload",
        "static_only": True,
        "feature_count": len(names),
        "features": [
            {
                "name": name,
                "type": "float",
            }
            for name in names
        ],
    }


def vectorize_features(
    features: Mapping[str, Any],
    feature_names: Optional[Sequence[str]] = None,
) -> List[float]:
    """
    Convert a feature mapping into a stable ordered numeric vector.
    """
    names = (
        list(feature_names) if feature_names is not None else payload_feature_names()
    )

    vector: List[float] = []

    for name in names:
        value = features.get(name, 0.0)

        try:
            numeric = float(value)
        except (TypeError, ValueError, OverflowError):
            numeric = 0.0

        if not math.isfinite(numeric):
            numeric = 0.0

        vector.append(
            max(
                0.0,
                min(
                    numeric,
                    float(MAX_FEATURE_VALUE),
                ),
            )
        )

    return vector


# ============================================================================
# Serialization and summaries
# ============================================================================


def analysis_to_dict(
    analysis: PayloadAnalysis,
) -> Dict[str, Any]:
    """
    Convert PayloadAnalysis into JSON-compatible structures.
    """
    result = asdict(analysis)

    # Explicitly normalize tuples into lists for JSON serialization.
    result["combinations"] = [
        {
            "name": item.name,
            "present": item.present,
            "required_categories": list(item.required_categories),
            "explanation": item.explanation,
        }
        for item in analysis.combinations
    ]

    return result


def summarize_payload(
    analysis: PayloadAnalysis,
) -> Dict[str, Any]:
    """
    Return a compact summary suitable for reports and pipeline decisions.
    """
    present = present_combinations(analysis)

    return {
        "source_hash": analysis.source_hash,
        "source_size": analysis.source_size,
        "highest_severity": highest_severity(analysis),
        "record_count": len(analysis.records),
        "evidence_count": len(analysis.evidence),
        "indicator_count": len(analysis.indicators),
        "category_count": len(analysis.categories),
        "target_count": len(analysis.targets),
        "candidate_count": len(analysis.candidates),
        "platforms": list(analysis.platforms),
        "high_risk_evidence_count": len(high_risk_evidence(analysis)),
        "present_combinations": [item.name for item in present],
        "signal_score": analysis.feature_vector.get(
            "signal_score",
            0.0,
        ),
        "static_only": True,
    }


def summarize_payload_capabilities(
    analysis: PayloadAnalysis,
) -> Dict[str, Any]:
    """
    Compatibility alias for summarize_payload().
    """
    return summarize_payload(analysis)


# ============================================================================
# Iterators
# ============================================================================


def iter_evidence(
    analysis: PayloadAnalysis,
) -> Iterator[PayloadEvidence]:
    """
    Iterate over payload evidence.
    """
    yield from analysis.evidence


def iter_high_risk_evidence(
    analysis: PayloadAnalysis,
) -> Iterator[PayloadEvidence]:
    """
    Iterate over high/critical payload evidence.
    """
    for item in analysis.evidence:
        if item.severity in {"high", "critical"}:
            yield item


def iter_records(
    analysis: PayloadAnalysis,
) -> Iterator[PayloadRecord]:
    """
    Iterate over normalized payload records.
    """
    yield from analysis.records


def iter_combinations(
    analysis: PayloadAnalysis,
) -> Iterator[PayloadCombination]:
    """
    Iterate over derived payload combinations.
    """
    yield from analysis.combinations


def iter_analyses(
    sources: Iterable[Any],
    *,
    include_candidates: bool = True,
) -> Iterator[PayloadAnalysis]:
    """
    Analyze an iterable of sources lazily.
    """
    for source in sources:
        yield analyze_payload(
            source,
            include_candidates=include_candidates,
        )


# ============================================================================
# Convenience predicates
# ============================================================================


def has_payload_capability(
    analysis: PayloadAnalysis,
) -> bool:
    """
    Return True when meaningful payload capability evidence exists.

    Weak references alone are not enough; either a stronger category,
    high/critical evidence, or a present multi-stage combination is required.
    """
    strong_categories = {
        "payload_download",
        "payload_decoding",
        "payload_decompression",
        "payload_decryption",
        "payload_write",
        "payload_staging",
        "payload_execution",
        "memory_payload",
        "shellcode",
        "reflective_payload",
        "payload_drop",
        "powershell_payload",
        "javascript_payload",
        "vbscript_payload",
        "executable_payload",
    }

    if any(has_category(analysis, category) for category in strong_categories):
        return True

    if high_risk_evidence(analysis):
        return True

    if present_combinations(analysis):
        return True

    return False


def payload_signal_score(
    analysis: PayloadAnalysis,
) -> float:
    """
    Return the bounded aggregate payload signal score.
    """
    return float(
        analysis.feature_vector.get(
            "signal_score",
            0.0,
        )
    )


# ============================================================================
# Compatibility aliases
# ============================================================================

parse = parse_payload
extract = extract_payload_features
analyze_capabilities = analyze_payload_capabilities


# ============================================================================
# Public APIs
# ============================================================================

__all__ = [
    "MAX_SOURCE_SIZE",
    "MAX_TEXT_CHARS",
    "MAX_EVIDENCE_ITEMS",
    "MAX_RECORDS",
    "MAX_INDICATORS",
    "MAX_TARGETS",
    "MAX_PAYLOAD_CANDIDATES",
    "PAYLOAD_CATEGORIES",
    "OPERATIONS",
    "SEVERITIES",
    "PLATFORMS",
    "PATTERN_DEFINITIONS",
    "PayloadPattern",
    "PayloadEvidence",
    "PayloadRecord",
    "PayloadCombination",
    "PayloadCandidate",
    "PayloadAnalysis",
    "analyze_payload",
    "analyze_payload_capabilities",
    "analyze",
    "parse_payload",
    "parse",
    "extract_payload_features",
    "extract_feature_vector",
    "extract_payload_feature_vector",
    "extract_payload_records",
    "extract",
    "has_indicator",
    "indicator_count",
    "has_category",
    "category_count",
    "evidence_by_category",
    "evidence_by_indicator",
    "high_risk_evidence",
    "present_combinations",
    "highest_severity",
    "has_payload_capability",
    "payload_signal_score",
    "payload_feature_names",
    "evasion_safe_feature_names",
    "build_feature_schema",
    "vectorize_features",
    "analysis_to_dict",
    "summarize_payload",
    "summarize_payload_capabilities",
    "iter_evidence",
    "iter_high_risk_evidence",
    "iter_records",
    "iter_combinations",
    "iter_analyses",
    "analyze_capabilities",
]
