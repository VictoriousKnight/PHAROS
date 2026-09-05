"""
Static VBA API feature extraction.

This module analyzes VBA source/token evidence and extracts ML-friendly
features describing Windows API usage and related capabilities.

Design goals:
    - Static analysis only.
    - No VBA execution.
    - No DLL loading.
    - No API invocation.
    - No network access.
    - Stable numeric feature names for ML.
    - Preserve semantic evidence separately from numeric features.

Expected upstream input:
    - VBA source text
    - parser output
    - tokenized/declaration records
    - or a mixture of these represented as mappings/objects

The extractor recognizes:
    - Declare statements
    - Declare Function / Declare Sub
    - VBA7 PtrSafe declarations
    - kernel32 APIs
    - user32 APIs
    - advapi32 APIs
    - oleaut32 APIs
    - wininet / winhttp APIs
    - shell/process APIs
    - memory manipulation APIs
    - registry APIs
    - file-system APIs
    - COM/automation APIs
    - cryptographic APIs
    - service/persistence-related APIs
    - anti-analysis/time/environment APIs

Important:
    API presence is evidence of capability, not proof of maliciousness.
    The strongest interpretation normally comes from combinations of API
    capabilities with VBA execution flow, obfuscation, URLs, embedded
    payloads, persistence, and other independent evidence.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import asdict, dataclass, field
from typing import (
    Any,
    BinaryIO,
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
# Limits
# ---------------------------------------------------------------------------

MAX_SOURCE_SIZE = 25 * 1024 * 1024
MAX_API_RECORDS = 100_000
MAX_EVIDENCE_ITEMS = 10_000


# ---------------------------------------------------------------------------
# API capability taxonomy
# ---------------------------------------------------------------------------

API_CAPABILITIES: Dict[str, Tuple[str, ...]] = {
    "process_execution": (
        "CreateProcess",
        "CreateProcessA",
        "CreateProcessW",
        "WinExec",
        "ShellExecute",
        "ShellExecuteA",
        "ShellExecuteW",
        "ShellExecuteEx",
        "ShellExecuteExA",
        "ShellExecuteExW",
        "OpenProcess",
        "TerminateProcess",
        "CreateThread",
        "CreateRemoteThread",
        "CreateRemoteThreadEx",
        "QueueUserAPC",
    ),
    "process_enumeration": (
        "CreateToolhelp32Snapshot",
        "Process32First",
        "Process32FirstW",
        "Process32Next",
        "Process32NextW",
        "EnumProcesses",
        "EnumProcessModules",
        "GetCurrentProcess",
        "OpenProcess",
    ),
    "memory_execution": (
        "VirtualAlloc",
        "VirtualAllocEx",
        "VirtualProtect",
        "VirtualProtectEx",
        "WriteProcessMemory",
        "ReadProcessMemory",
        "VirtualQuery",
        "VirtualQueryEx",
        "MapViewOfFile",
        "UnmapViewOfFile",
        "CreateRemoteThread",
        "CreateRemoteThreadEx",
        "RtlMoveMemory",
        "RtlCopyMemory",
        "CopyMemory",
    ),
    "dynamic_library_loading": (
        "LoadLibrary",
        "LoadLibraryA",
        "LoadLibraryW",
        "LoadLibraryEx",
        "LoadLibraryExA",
        "LoadLibraryExW",
        "GetModuleHandle",
        "GetModuleHandleA",
        "GetModuleHandleW",
        "GetProcAddress",
        "FreeLibrary",
    ),
    "file_system": (
        "CreateFile",
        "CreateFileA",
        "CreateFileW",
        "ReadFile",
        "WriteFile",
        "DeleteFile",
        "DeleteFileA",
        "DeleteFileW",
        "MoveFile",
        "MoveFileA",
        "MoveFileW",
        "CopyFile",
        "CopyFileA",
        "CopyFileW",
        "GetTempPath",
        "GetTempFileName",
        "SetFileAttributes",
        "GetFileAttributes",
        "FindFirstFile",
        "FindFirstFileA",
        "FindFirstFileW",
        "FindNextFile",
        "FindNextFileA",
        "FindNextFileW",
    ),
    "registry": (
        "RegOpenKey",
        "RegOpenKeyA",
        "RegOpenKeyW",
        "RegOpenKeyEx",
        "RegOpenKeyExA",
        "RegOpenKeyExW",
        "RegCreateKey",
        "RegCreateKeyA",
        "RegCreateKeyW",
        "RegCreateKeyEx",
        "RegCreateKeyExA",
        "RegCreateKeyExW",
        "RegSetValue",
        "RegSetValueA",
        "RegSetValueW",
        "RegSetValueEx",
        "RegSetValueExA",
        "RegSetValueExW",
        "RegQueryValue",
        "RegQueryValueA",
        "RegQueryValueW",
        "RegQueryValueEx",
        "RegQueryValueExA",
        "RegQueryValueExW",
        "RegDeleteValue",
        "RegDeleteValueA",
        "RegDeleteValueW",
        "RegCloseKey",
    ),
    "network": (
        "InternetOpen",
        "InternetOpenA",
        "InternetOpenW",
        "InternetConnect",
        "InternetConnectA",
        "InternetConnectW",
        "InternetOpenUrl",
        "InternetOpenUrlA",
        "InternetOpenUrlW",
        "InternetReadFile",
        "InternetReadFileEx",
        "InternetQueryInfo",
        "InternetCrackUrl",
        "HttpOpenRequest",
        "HttpOpenRequestA",
        "HttpOpenRequestW",
        "HttpSendRequest",
        "HttpSendRequestA",
        "HttpSendRequestW",
        "HttpQueryInfo",
        "URLDownloadToFile",
        "URLDownloadToFileA",
        "URLDownloadToFileW",
        "URLOpenBlockingStream",
        "WinHttpOpen",
        "WinHttpConnect",
        "WinHttpOpenRequest",
        "WinHttpSendRequest",
        "WinHttpReceiveResponse",
        "WinHttpReadData",
        "WinHttpQueryHeaders",
        "WSAStartup",
        "socket",
        "connect",
        "send",
        "recv",
        "InternetSetOption",
    ),
    "download": (
        "URLDownloadToFile",
        "URLDownloadToFileA",
        "URLDownloadToFileW",
        "URLOpenBlockingStream",
        "URLOpenPullStream",
        "InternetOpenUrl",
        "InternetReadFile",
        "WinHttpSendRequest",
        "WinHttpReceiveResponse",
        "WinHttpReadData",
    ),
    "shell": (
        "ShellExecute",
        "ShellExecuteA",
        "ShellExecuteW",
        "ShellExecuteEx",
        "ShellExecuteExA",
        "ShellExecuteExW",
        "WinExec",
        "CreateProcess",
        "CreateProcessA",
        "CreateProcessW",
    ),
    "com_automation": (
        "CoCreateInstance",
        "CoCreateInstanceEx",
        "CoGetClassObject",
        "CoInitialize",
        "CoInitializeEx",
        "CoUninitialize",
        "CoCreateGuid",
        "CLSIDFromProgID",
        "CLSIDFromString",
        "StringFromGUID2",
    ),
    "service_management": (
        "OpenSCManager",
        "OpenSCManagerA",
        "OpenSCManagerW",
        "OpenService",
        "OpenServiceA",
        "OpenServiceW",
        "CreateService",
        "CreateServiceA",
        "CreateServiceW",
        "StartService",
        "StartServiceA",
        "StartServiceW",
        "ControlService",
        "DeleteService",
        "CloseServiceHandle",
    ),
    "security_token": (
        "OpenProcessToken",
        "OpenThreadToken",
        "GetTokenInformation",
        "DuplicateToken",
        "DuplicateTokenEx",
        "AdjustTokenPrivileges",
        "LookupPrivilegeValue",
        "ImpersonateLoggedOnUser",
        "RevertToSelf",
    ),
    "credential_access": (
        "CredEnumerate",
        "CredEnumerateA",
        "CredEnumerateW",
        "CredRead",
        "CredReadA",
        "CredReadW",
        "CredWrite",
        "CredDelete",
    ),
    "cryptography": (
        "CryptAcquireContext",
        "CryptAcquireContextA",
        "CryptAcquireContextW",
        "CryptCreateHash",
        "CryptHashData",
        "CryptDeriveKey",
        "CryptEncrypt",
        "CryptDecrypt",
        "CryptDestroyHash",
        "CryptDestroyKey",
        "CryptGenRandom",
    ),
    "environment": (
        "GetEnvironmentVariable",
        "GetEnvironmentVariableA",
        "GetEnvironmentVariableW",
        "ExpandEnvironmentStrings",
        "ExpandEnvironmentStringsA",
        "ExpandEnvironmentStringsW",
        "GetComputerName",
        "GetComputerNameA",
        "GetComputerNameW",
        "GetUserName",
        "GetUserNameA",
        "GetUserNameW",
        "GetSystemDirectory",
        "GetSystemDirectoryA",
        "GetSystemDirectoryW",
        "GetWindowsDirectory",
        "GetWindowsDirectoryA",
        "GetWindowsDirectoryW",
        "GetVersionEx",
        "GetVersionExA",
        "GetVersionExW",
        "GetNativeSystemInfo",
    ),
    "process_environment": (
        "GetCommandLine",
        "GetCommandLineA",
        "GetCommandLineW",
        "GetEnvironmentVariable",
        "GetEnvironmentVariableA",
        "GetEnvironmentVariableW",
        "GetUserName",
        "GetUserNameA",
        "GetUserNameW",
        "GetComputerName",
        "GetComputerNameA",
        "GetComputerNameW",
    ),
    "time_environment": (
        "GetTickCount",
        "GetTickCount64",
        "QueryPerformanceCounter",
        "GetSystemTime",
        "GetLocalTime",
        "GetSystemTimeAsFileTime",
        "Sleep",
        "GetLastInputInfo",
    ),
    "window_interaction": (
        "FindWindow",
        "FindWindowA",
        "FindWindowW",
        "FindWindowEx",
        "FindWindowExA",
        "FindWindowExW",
        "EnumWindows",
        "EnumChildWindows",
        "GetWindowText",
        "GetWindowTextA",
        "GetWindowTextW",
        "SendMessage",
        "SendMessageA",
        "SendMessageW",
        "PostMessage",
        "PostMessageA",
        "PostMessageW",
        "ShowWindow",
        "SetForegroundWindow",
    ),
    "clipboard": (
        "OpenClipboard",
        "CloseClipboard",
        "GetClipboardData",
        "SetClipboardData",
        "EmptyClipboard",
        "IsClipboardFormatAvailable",
    ),
    "synchronization": (
        "CreateMutex",
        "CreateMutexA",
        "CreateMutexW",
        "OpenMutex",
        "OpenMutexA",
        "OpenMutexW",
        "CreateEvent",
        "CreateEventA",
        "CreateEventW",
        "OpenEvent",
        "WaitForSingleObject",
        "WaitForMultipleObjects",
    ),
    "anti_analysis": (
        "IsDebuggerPresent",
        "CheckRemoteDebuggerPresent",
        "OutputDebugString",
        "OutputDebugStringA",
        "OutputDebugStringW",
        "NtQueryInformationProcess",
        "GetTickCount",
        "GetTickCount64",
        "QueryPerformanceCounter",
        "GetSystemTime",
        "GetLocalTime",
    ),
    "process_injection": (
        "OpenProcess",
        "VirtualAllocEx",
        "VirtualProtectEx",
        "WriteProcessMemory",
        "ReadProcessMemory",
        "CreateRemoteThread",
        "CreateRemoteThreadEx",
        "QueueUserAPC",
        "NtWriteVirtualMemory",
        "NtAllocateVirtualMemory",
        "NtProtectVirtualMemory",
    ),
}


# ---------------------------------------------------------------------------
# API family mapping
# ---------------------------------------------------------------------------

DLL_FAMILIES: Dict[str, str] = {
    "kernel32": "kernel32",
    "kernelbase": "kernel32",
    "user32": "user32",
    "advapi32": "advapi32",
    "ole32": "ole32",
    "oleaut32": "oleaut32",
    "urlmon": "urlmon",
    "wininet": "wininet",
    "winhttp": "winhttp",
    "ws2_32": "ws2_32",
    "wsock32": "ws2_32",
    "shell32": "shell32",
    "shlwapi": "shlwapi",
    "crypt32": "crypt32",
    "advpack": "advpack",
    "ntdll": "ntdll",
    "rpcrt4": "rpcrt4",
    "secur32": "secur32",
    "netapi32": "netapi32",
    "samlib": "samlib",
    "version": "version",
    "gdi32": "gdi32",
}


# ---------------------------------------------------------------------------
# API aliases / normalization
# ---------------------------------------------------------------------------

COMMON_API_ALIASES: Dict[str, str] = {
    "urldownloadtofile": "URLDownloadToFile",
    "urldownloadtofilea": "URLDownloadToFileA",
    "urldownloadtofilew": "URLDownloadToFileW",
    "internetopenurl": "InternetOpenUrl",
    "internetopenurla": "InternetOpenUrlA",
    "internetopenurlw": "InternetOpenUrlW",
    "winexec": "WinExec",
    "shellexecute": "ShellExecute",
    "shellexecutea": "ShellExecuteA",
    "shellexecutew": "ShellExecuteW",
    "createprocess": "CreateProcess",
    "createprocessa": "CreateProcessA",
    "createprocessw": "CreateProcessW",
    "virtualalloc": "VirtualAlloc",
    "virtualallocex": "VirtualAllocEx",
    "virtualprotect": "VirtualProtect",
    "virtualprotectex": "VirtualProtectEx",
    "writeprocessmemory": "WriteProcessMemory",
    "readprocessmemory": "ReadProcessMemory",
    "createremotethread": "CreateRemoteThread",
    "loadlibrary": "LoadLibrary",
    "loadlibrarya": "LoadLibraryA",
    "loadlibraryw": "LoadLibraryW",
    "getprocaddress": "GetProcAddress",
    "regopenkey": "RegOpenKey",
    "regopenkeyex": "RegOpenKeyEx",
    "regcreatekey": "RegCreateKey",
    "regcreatekeyex": "RegCreateKeyEx",
    "regsetvalue": "RegSetValue",
    "regsetvalueex": "RegSetValueEx",
    "regqueryvalue": "RegQueryValue",
    "regqueryvalueex": "RegQueryValueEx",
    "internetopen": "InternetOpen",
    "internetconnect": "InternetConnect",
    "internetreadfile": "InternetReadFile",
    "winhttpopen": "WinHttpOpen",
    "winhttpconnect": "WinHttpConnect",
    "winhttprequest": "WinHttpOpenRequest",
    "winhttpsendrequest": "WinHttpSendRequest",
    "winhttpreceivedresponse": "WinHttpReceiveResponse",
    "winhttpreaddata": "WinHttpReadData",
    "cocreateinstance": "CoCreateInstance",
    "coinitialize": "CoInitialize",
    "coinitializeex": "CoInitializeEx",
    "openprocess": "OpenProcess",
    "createtoolhelp32snapshot": "CreateToolhelp32Snapshot",
    "process32first": "Process32First",
    "process32next": "Process32Next",
    "enumprocesses": "EnumProcesses",
    "enumprocessmodules": "EnumProcessModules",
    "getenvironmentvariable": "GetEnvironmentVariable",
    "expandenvironmentstrings": "ExpandEnvironmentStrings",
    "getusername": "GetUserName",
    "getcomputername": "GetComputerName",
    "gettickcount": "GetTickCount",
    "gettickcount64": "GetTickCount64",
    "queryperformancecounter": "QueryPerformanceCounter",
    "isdebuggerpresent": "IsDebuggerPresent",
    "checkremotedebuggerpresent": "CheckRemoteDebuggerPresent",
}


# ---------------------------------------------------------------------------
# Regexes
# ---------------------------------------------------------------------------

DECLARE_RE = re.compile(
    r"""(?imx)
    ^\s*
    (?:Public\s+|Private\s+|Friend\s+)?
    Declare
    \s+
    (?:PtrSafe\s+)?
    (?P<kind>Function|Sub)
    \s+
    (?P<name>[A-Za-z_][A-Za-z0-9_]*)
    (?:\s+Lib\s+["'](?P<library>[^"']+)["'])?
    (?:\s+Alias\s+["'](?P<alias>[^"']+)["'])?
    """,
)

DECLARE_LIB_RE = re.compile(
    r"""(?imx)
    ^\s*
    (?:Public\s+|Private\s+|Friend\s+)?
    Declare
    \s+
    (?:PtrSafe\s+)?
    (?:Function|Sub)
    \s+
    [A-Za-z_][A-Za-z0-9_]*
    .*?
    \s+Lib\s+
    ["'](?P<library>[^"']+)["']
    """,
)

API_CALL_RE = re.compile(
    r"""(?ix)
    \b
    (?P<api>
        URLDownloadToFile(?:A|W)?
        |InternetOpenUrl(?:A|W)?
        |InternetOpen(?:A|W)?
        |InternetConnect(?:A|W)?
        |InternetReadFile(?:Ex)?
        |HttpOpenRequest(?:A|W)?
        |HttpSendRequest(?:A|W)?
        |WinHttpOpen
        |WinHttpConnect
        |WinHttpOpenRequest
        |WinHttpSendRequest
        |WinHttpReceiveResponse
        |WinHttpReadData
        |ShellExecute(?:Ex)?(?:A|W)?
        |WinExec
        |CreateProcess(?:A|W)?
        |OpenProcess
        |VirtualAlloc(?:Ex)?
        |VirtualProtect(?:Ex)?
        |WriteProcessMemory
        |ReadProcessMemory
        |CreateRemoteThread(?:Ex)?
        |QueueUserAPC
        |LoadLibrary(?:Ex)?(?:A|W)?
        |GetModuleHandle(?:A|W)?
        |GetProcAddress
        |RegOpenKey(?:Ex)?(?:A|W)?
        |RegCreateKey(?:Ex)?(?:A|W)?
        |RegSetValue(?:Ex)?(?:A|W)?
        |RegQueryValue(?:Ex)?(?:A|W)?
        |RegDeleteValue(?:A|W)?
        |CoCreateInstance(?:Ex)?
        |CoInitialize(?:Ex)?
        |IsDebuggerPresent
        |CheckRemoteDebuggerPresent
        |CreateMutex(?:A|W)?
        |GetEnvironmentVariable(?:A|W)?
        |GetUserName(?:A|W)?
        |GetComputerName(?:A|W)?
    )
    \s*\(
    """,
)

LIB_REFERENCE_RE = re.compile(
    r"""(?im)
    \b
    (?:Lib|library|dll)
    \s*
    ["']?
    (?P<library>
        [A-Za-z0-9_.-]+
        \.(?:dll|ocx)
    )
    ["']?
    """,
)

API_STRING_RE = re.compile(
    r"""(?i)
    \b
    (?P<api>
        [A-Za-z_][A-Za-z0-9_]{2,80}
    )
    \s*
    \(
    """,
)

COMMENT_RE = re.compile(
    r"""(?m)
    ^\s*(?:'|Rem\b).*$
    """,
)


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class VBAAPIDeclaration:
    """A statically detected VBA Declare statement."""

    name: str
    library: Optional[str]
    alias: Optional[str]
    kind: str
    ptrsafe: bool
    line_number: int
    raw: str

    @property
    def normalized_name(self) -> str:
        return normalize_api_name(self.alias or self.name)


@dataclass(frozen=True)
class VBAAPICall:
    """A statically detected API call."""

    name: str
    normalized_name: str
    line_number: int
    source: str
    capability_categories: Tuple[str, ...]
    library: Optional[str] = None


@dataclass
class VBAAPIFeatures:
    """
    Complete API feature extraction result.
    """

    declarations: Tuple[VBAAPIDeclaration, ...] = field(default_factory=tuple)

    calls: Tuple[VBAAPICall, ...] = field(default_factory=tuple)

    libraries: Tuple[str, ...] = field(default_factory=tuple)

    capabilities: Tuple[str, ...] = field(default_factory=tuple)

    indicators: Tuple[str, ...] = field(default_factory=tuple)

    feature_vector: Dict[str, float] = field(default_factory=dict)

    metadata: Dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Normalization
# ---------------------------------------------------------------------------


def normalize_api_name(name: Any) -> str:
    """
    Normalize an API name for matching.

    VBA API names are case-insensitive for practical matching purposes.
    """

    value = str(name or "").strip()

    if not value:
        return ""

    value = value.split(".")[-1]
    value = value.strip("`'\" ")

    lower = value.lower()

    if lower in COMMON_API_ALIASES:
        return COMMON_API_ALIASES[lower]

    # Strip VBA alias decorations while preserving A/W suffixes.
    return value


def normalize_library_name(library: Any) -> str:
    """
    Normalize a DLL/library name.
    """

    value = str(library or "").strip().strip("\"'")

    if not value:
        return ""

    value = value.rsplit("\\", 1)[-1]
    value = value.rsplit("/", 1)[-1]

    lower = value.lower()

    if lower.endswith(".dll"):
        lower = lower[:-4]
    elif lower.endswith(".ocx"):
        lower = lower[:-4]

    return DLL_FAMILIES.get(
        lower,
        lower,
    )


def _casefold(value: str) -> str:
    return value.strip().casefold()


# ---------------------------------------------------------------------------
# Capability indexing
# ---------------------------------------------------------------------------


def _build_api_index() -> Dict[str, Tuple[str, ...]]:
    index: Dict[str, List[str]] = {}

    for capability, names in API_CAPABILITIES.items():
        for name in names:
            normalized = normalize_api_name(name)

            if not normalized:
                continue

            key = _casefold(normalized)

            index.setdefault(
                key,
                [],
            ).append(capability)

    return {key: tuple(sorted(set(values))) for key, values in index.items()}


API_INDEX = _build_api_index()


def api_capabilities(api_name: str) -> Tuple[str, ...]:
    """
    Return capability categories associated with an API name.
    """

    normalized = normalize_api_name(api_name)

    if not normalized:
        return tuple()

    return API_INDEX.get(
        _casefold(normalized),
        tuple(),
    )


# ---------------------------------------------------------------------------
# Source handling
# ---------------------------------------------------------------------------


def _read_source(
    source: Union[
        str,
        bytes,
        bytearray,
        memoryview,
        BinaryIO,
    ],
) -> str:
    """
    Convert supported source types into text.
    """

    if isinstance(source, str):
        if len(source.encode("utf-8", errors="ignore")) > MAX_SOURCE_SIZE:
            raise ValueError("VBA source exceeds maximum size")

        return source

    if isinstance(source, bytes):
        if len(source) > MAX_SOURCE_SIZE:
            raise ValueError("VBA source exceeds maximum size")

        return source.decode(
            "utf-8",
            errors="replace",
        )

    if isinstance(source, bytearray):
        return _read_source(bytes(source))

    if isinstance(source, memoryview):
        return _read_source(source.tobytes())

    if hasattr(source, "read"):
        data = source.read()

        if isinstance(data, str):
            return _read_source(data)

        return _read_source(data)

    raise TypeError("source must be text, bytes-like data, or a binary/text stream")


# ---------------------------------------------------------------------------
# Comment handling
# ---------------------------------------------------------------------------


def strip_vba_comments(source: str) -> str:
    """
    Remove full-line VBA comments and inline apostrophe comments.

    This is intentionally conservative. String literals are protected
    so apostrophes inside strings are not interpreted as comments.
    """

    output: List[str] = []

    for line in source.splitlines():
        stripped = line.lstrip()

        if stripped.startswith("'"):
            output.append("")
            continue

        if re.match(
            r"(?i)^Rem(?:\s|$)",
            stripped,
        ):
            output.append("")
            continue

        result: List[str] = []
        in_string = False
        escaped = False

        for char in line:
            if char == '"' and not escaped:
                in_string = not in_string
                result.append(char)
                continue

            if char == "'" and not in_string:
                break

            result.append(char)

            escaped = char == "\\" and not escaped

            if char != "\\":
                escaped = False

        output.append("".join(result))

    return "\n".join(output)


# ---------------------------------------------------------------------------
# Declaration parsing
# ---------------------------------------------------------------------------


def parse_api_declarations(
    source: str,
) -> Tuple[VBAAPIDeclaration, ...]:
    """
    Parse VBA Declare statements.
    """

    declarations: List[VBAAPIDeclaration] = []

    for match in DECLARE_RE.finditer(source):
        line_number = (
            source.count(
                "\n",
                0,
                match.start(),
            )
            + 1
        )

        raw = match.group(0).strip()

        # Determine PtrSafe from the declaration text.
        ptrsafe = bool(
            re.search(
                r"(?i)\bPtrSafe\b",
                raw,
            )
        )

        declaration = VBAAPIDeclaration(
            name=match.group("name"),
            library=(match.group("library") or None),
            alias=(match.group("alias") or None),
            kind=match.group("kind"),
            ptrsafe=ptrsafe,
            line_number=line_number,
            raw=raw,
        )

        declarations.append(declaration)

        if len(declarations) >= MAX_API_RECORDS:
            break

    return tuple(declarations)


# ---------------------------------------------------------------------------
# Library parsing
# ---------------------------------------------------------------------------


def extract_declared_libraries(
    source: str,
) -> Tuple[str, ...]:
    """
    Extract DLL/library names from Declare statements.
    """

    libraries: List[str] = []

    for match in DECLARE_LIB_RE.finditer(source):
        library = normalize_library_name(match.group("library"))

        if library:
            libraries.append(library)

    return tuple(sorted(set(libraries)))


def extract_library_references(
    source: str,
) -> Tuple[str, ...]:
    """
    Extract generic static DLL references.
    """

    libraries: List[str] = []

    for match in LIB_REFERENCE_RE.finditer(source):
        library = normalize_library_name(match.group("library"))

        if library:
            libraries.append(library)

    return tuple(sorted(set(libraries)))


# ---------------------------------------------------------------------------
# API-call parsing
# ---------------------------------------------------------------------------


def _api_known(name: str) -> bool:
    return bool(api_capabilities(name))


def parse_api_calls(
    source: str,
    declarations: Sequence[VBAAPIDeclaration] = (),
) -> Tuple[VBAAPICall, ...]:
    """
    Extract statically recognizable API calls.

    Detection is intentionally based on known Windows API names rather
    than attempting to interpret or execute VBA.
    """

    calls: List[VBAAPICall] = []
    seen: set[Tuple[int, str]] = set()

    declaration_libraries: Dict[str, Optional[str]] = {}

    for declaration in declarations:
        declaration_libraries[_casefold(declaration.normalized_name)] = (
            declaration.library
        )

    for match in API_CALL_RE.finditer(source):
        raw_name = match.group("api")
        normalized = normalize_api_name(raw_name)

        if not _api_known(normalized):
            continue

        line_number = (
            source.count(
                "\n",
                0,
                match.start(),
            )
            + 1
        )

        key = (
            line_number,
            _casefold(normalized),
        )

        if key in seen:
            continue

        seen.add(key)

        categories = api_capabilities(normalized)

        calls.append(
            VBAAPICall(
                name=raw_name,
                normalized_name=normalized,
                line_number=line_number,
                source=source[
                    max(0, match.start() - 80) : min(len(source), match.end() + 120)
                ].strip(),
                capability_categories=categories,
                library=declaration_libraries.get(_casefold(normalized)),
            )
        )

        if len(calls) >= MAX_API_RECORDS:
            break

    # Add declared APIs which may not appear in call syntax.
    declared_keys = {
        (
            declaration.line_number,
            _casefold(declaration.normalized_name),
        )
        for declaration in declarations
    }

    for declaration in declarations:
        normalized = declaration.normalized_name

        if not normalized:
            continue

        categories = api_capabilities(normalized)

        if not categories:
            continue

        key = (
            declaration.line_number,
            _casefold(normalized),
        )

        if key in declared_keys:
            # Declaration itself is valuable evidence, but if an actual
            # call was already represented on another line we do not
            # manufacture a duplicate call record.
            if any(
                _casefold(call.normalized_name) == _casefold(normalized)
                for call in calls
            ):
                continue

        calls.append(
            VBAAPICall(
                name=declaration.name,
                normalized_name=normalized,
                line_number=declaration.line_number,
                source=declaration.raw,
                capability_categories=categories,
                library=declaration.library,
            )
        )

        if len(calls) >= MAX_API_RECORDS:
            break

    return tuple(calls)


# ---------------------------------------------------------------------------
# Generic API extraction from structured input
# ---------------------------------------------------------------------------


def _value_from_record(
    record: Any,
    *names: str,
) -> Any:
    for name in names:
        if isinstance(record, Mapping):
            if name in record:
                return record[name]

        if hasattr(record, name):
            try:
                return getattr(record, name)
            except Exception:
                pass

    return None


def normalize_structured_api_records(
    records: Iterable[Any],
) -> Tuple[VBAAPICall, ...]:
    """
    Convert upstream parser records into VBAAPICall objects.

    Accepted field aliases include:
        name / api / api_name / function
        line / line_number
        source / context / raw
        library / dll
    """

    result: List[VBAAPICall] = []

    for record in records:
        name = _value_from_record(
            record,
            "name",
            "api",
            "api_name",
            "function",
            "function_name",
        )

        if not name:
            continue

        normalized = normalize_api_name(name)

        categories = api_capabilities(normalized)

        library_value = _value_from_record(
            record,
            "library",
            "dll",
            "module",
        )

        library = normalize_library_name(library_value) if library_value else None

        line_value = _value_from_record(
            record,
            "line",
            "line_number",
            "lineno",
        )

        try:
            line_number = int(line_value)
        except (
            TypeError,
            ValueError,
        ):
            line_number = 0

        source = _value_from_record(
            record,
            "source",
            "context",
            "raw",
            "text",
        )

        result.append(
            VBAAPICall(
                name=str(name),
                normalized_name=normalized,
                line_number=line_number,
                source=str(source or ""),
                capability_categories=categories,
                library=library,
            )
        )

        if len(result) >= MAX_API_RECORDS:
            break

    return tuple(result)


# ---------------------------------------------------------------------------
# Capability derivation
# ---------------------------------------------------------------------------


def derive_capabilities(
    calls: Sequence[VBAAPICall],
    declarations: Sequence[VBAAPIDeclaration] = (),
) -> Tuple[str, ...]:
    """
    Derive capability categories from API evidence.
    """

    capabilities: set[str] = set()

    for call in calls:
        capabilities.update(call.capability_categories)

    for declaration in declarations:
        capabilities.update(api_capabilities(declaration.normalized_name))

    return tuple(sorted(capabilities))


# ---------------------------------------------------------------------------
# Indicators
# ---------------------------------------------------------------------------


def derive_api_indicators(
    calls: Sequence[VBAAPICall],
    declarations: Sequence[VBAAPIDeclaration],
    libraries: Sequence[str],
) -> Tuple[str, ...]:
    """
    Generate semantic API indicators.

    These are evidence labels, not malware verdicts.
    """

    indicators: set[str] = set()

    call_names = {_casefold(call.normalized_name) for call in calls}

    categories = set(
        derive_capabilities(
            calls,
            declarations,
        )
    )

    libraries_normalized = {normalize_library_name(library) for library in libraries}

    if declarations:
        indicators.add("vba_api_declaration_present")

    if any(declaration.ptrsafe for declaration in declarations):
        indicators.add("vba7_ptrsafe_declaration")

    if "process_execution" in categories:
        indicators.add("api_process_execution")

    if "process_injection" in categories:
        indicators.add("api_process_injection")

    if "memory_execution" in categories:
        indicators.add("api_memory_manipulation")

    if "dynamic_library_loading" in categories:
        indicators.add("api_dynamic_library_loading")

    if "file_system" in categories:
        indicators.add("api_file_system_access")

    if "registry" in categories:
        indicators.add("api_registry_access")

    if "network" in categories:
        indicators.add("api_network_access")

    if "download" in categories:
        indicators.add("api_download_capability")

    if "shell" in categories:
        indicators.add("api_shell_execution")

    if "service_management" in categories:
        indicators.add("api_service_management")

    if "credential_access" in categories:
        indicators.add("api_credential_access")

    if "security_token" in categories:
        indicators.add("api_token_manipulation")

    if "cryptography" in categories:
        indicators.add("api_cryptography")

    if "environment" in categories:
        indicators.add("api_environment_discovery")

    if "process_environment" in categories:
        indicators.add("api_process_environment_discovery")

    if "time_environment" in categories:
        indicators.add("api_time_environment")

    if "window_interaction" in categories:
        indicators.add("api_window_interaction")

    if "clipboard" in categories:
        indicators.add("api_clipboard_access")

    if "synchronization" in categories:
        indicators.add("api_synchronization")

    if "anti_analysis" in categories:
        indicators.add("api_anti_analysis")

    if "user32" in libraries_normalized:
        indicators.add("user32_library_reference")

    if "kernel32" in libraries_normalized:
        indicators.add("kernel32_library_reference")

    if "advapi32" in libraries_normalized:
        indicators.add("advapi32_library_reference")

    if "wininet" in libraries_normalized:
        indicators.add("wininet_library_reference")

    if "winhttp" in libraries_normalized:
        indicators.add("winhttp_library_reference")

    if "urlmon" in libraries_normalized:
        indicators.add("urlmon_library_reference")

    if "ws2_32" in libraries_normalized:
        indicators.add("ws2_32_library_reference")

    if {
        "virtualallocex",
        "writeprocessmemory",
        "createremotethread",
    } <= call_names:
        indicators.add("remote_process_memory_execution_chain")

    if "dynamic_library_loading" in categories and "process_execution" in categories:
        indicators.add("dynamic_library_execution_combination")

    if "network" in categories and "file_system" in categories:
        indicators.add("network_file_combination")

    if "download" in categories and "process_execution" in categories:
        indicators.add("download_execution_combination")

    if "registry" in categories and "service_management" in categories:
        indicators.add("registry_service_combination")

    if "anti_analysis" in categories and "process_enumeration" in categories:
        indicators.add("anti_analysis_discovery_combination")

    return tuple(sorted(indicators))


# ---------------------------------------------------------------------------
# Feature vector
# ---------------------------------------------------------------------------


def _count_capability_calls(
    calls: Sequence[VBAAPICall],
    capability: str,
) -> int:
    return sum(capability in call.capability_categories for call in calls)


def _unique_capability_count(
    calls: Sequence[VBAAPICall],
    capability: str,
) -> int:
    return len(
        {
            _casefold(call.normalized_name)
            for call in calls
            if capability in call.capability_categories
        }
    )


def _build_feature_vector(
    *,
    declarations: Sequence[VBAAPIDeclaration],
    calls: Sequence[VBAAPICall],
    libraries: Sequence[str],
    source: str,
) -> Dict[str, float]:
    """
    Build a deterministic numeric feature vector.
    """

    vector: Dict[str, float] = {}

    # ---------------------------------------------------------------
    # General API statistics.
    # ---------------------------------------------------------------

    unique_api_names = {
        _casefold(call.normalized_name) for call in calls if call.normalized_name
    }

    declared_api_names = {
        _casefold(declaration.normalized_name)
        for declaration in declarations
        if declaration.normalized_name
    }

    vector["vba_api_declaration_count"] = float(len(declarations))

    vector["vba_api_call_count"] = float(len(calls))

    vector["vba_api_unique_count"] = float(len(unique_api_names))

    vector["vba_api_declared_unique_count"] = float(len(declared_api_names))

    vector["vba_api_library_count"] = float(len(set(libraries)))

    vector["vba_api_source_size"] = float(len(source.encode("utf-8", errors="ignore")))

    # ---------------------------------------------------------------
    # Capability counts.
    # ---------------------------------------------------------------

    for capability in sorted(API_CAPABILITIES):
        vector[f"vba_api_{capability}_count"] = float(
            _count_capability_calls(
                calls,
                capability,
            )
        )

        vector[f"vba_api_{capability}_unique_count"] = float(
            _unique_capability_count(
                calls,
                capability,
            )
        )

        vector[f"vba_api_has_{capability}"] = float(
            any(capability in call.capability_categories for call in calls)
            or any(
                capability in api_capabilities(declaration.normalized_name)
                for declaration in declarations
            )
        )

    # ---------------------------------------------------------------
    # Library families.
    # ---------------------------------------------------------------

    library_set = {normalize_library_name(library) for library in libraries}

    for library in sorted(set(DLL_FAMILIES.values())):
        vector[f"vba_api_library_{library}"] = float(library in library_set)

    # ---------------------------------------------------------------
    # API-specific high-value features.
    # ---------------------------------------------------------------

    normalized_names = {_casefold(call.normalized_name) for call in calls}

    for api_name in (
        "CreateProcess",
        "WinExec",
        "ShellExecute",
        "ShellExecuteEx",
        "URLDownloadToFile",
        "InternetOpenUrl",
        "InternetReadFile",
        "WinHttpSendRequest",
        "WinHttpReceiveResponse",
        "WinHttpReadData",
        "VirtualAlloc",
        "VirtualAllocEx",
        "VirtualProtect",
        "VirtualProtectEx",
        "WriteProcessMemory",
        "ReadProcessMemory",
        "CreateRemoteThread",
        "LoadLibrary",
        "LoadLibraryEx",
        "GetProcAddress",
        "RegOpenKey",
        "RegOpenKeyEx",
        "RegCreateKey",
        "RegCreateKeyEx",
        "RegSetValue",
        "RegSetValueEx",
        "RegQueryValue",
        "RegQueryValueEx",
        "CoCreateInstance",
        "OpenProcess",
        "CreateToolhelp32Snapshot",
        "Process32First",
        "Process32Next",
        "IsDebuggerPresent",
        "CheckRemoteDebuggerPresent",
        "CreateMutex",
        "OpenProcessToken",
        "GetTokenInformation",
        "AdjustTokenPrivileges",
    ):
        vector["vba_api_call_" + api_name.lower()] = float(
            _casefold(api_name) in normalized_names
        )

    # ---------------------------------------------------------------
    # API chain combinations.
    # ---------------------------------------------------------------

    has_virtual_alloc_ex = any(
        name in normalized_names
        for name in (
            "virtualallocex",
            "virtualalloc",
        )
    )

    has_write_memory = "writeprocessmemory" in normalized_names

    has_remote_thread = any(
        name in normalized_names
        for name in (
            "createremotethread",
            "createremotethreadex",
            "queueuserapc",
        )
    )

    vector["vba_api_remote_memory_execution_chain"] = float(
        has_virtual_alloc_ex and has_write_memory and has_remote_thread
    )

    vector["vba_api_dynamic_resolution_chain"] = float(
        "loadlibrary" in normalized_names
        or "loadlibrarya" in normalized_names
        or "loadlibraryw" in normalized_names
    ) * float("getprocaddress" in normalized_names)

    vector["vba_api_download_execution_chain"] = float(
        any(
            name in normalized_names
            for name in (
                "urldownloadtofile",
                "urldownloadtofilea",
                "urldownloadtofilew",
                "internetreadfile",
                "winhttpreaddata",
            )
        )
        and any(
            name in normalized_names
            for name in (
                "winexec",
                "createprocess",
                "createprocessa",
                "createprocessw",
                "shellexecute",
                "shellexecutea",
                "shellexecutew",
            )
        )
    )

    vector["vba_api_registry_persistence_signal"] = float(
        "registry"
        in {capability for call in calls for capability in call.capability_categories}
        and (
            "process_execution"
            in {
                capability
                for call in calls
                for capability in call.capability_categories
            }
            or "service_management"
            in {
                capability
                for call in calls
                for capability in call.capability_categories
            }
        )
    )

    vector["vba_api_anti_analysis_signal"] = float(
        "anti_analysis"
        in {capability for call in calls for capability in call.capability_categories}
    )

    # ---------------------------------------------------------------
    # Declaration characteristics.
    # ---------------------------------------------------------------

    vector["vba_api_ptrsafe_declaration_count"] = float(
        sum(declaration.ptrsafe for declaration in declarations)
    )

    vector["vba_api_alias_declaration_count"] = float(
        sum(bool(declaration.alias) for declaration in declarations)
    )

    vector["vba_api_external_library_declaration_count"] = float(
        sum(bool(declaration.library) for declaration in declarations)
    )

    # ---------------------------------------------------------------
    # Density features.
    # ---------------------------------------------------------------

    source_lines = max(
        1,
        len(source.splitlines()),
    )

    vector["vba_api_calls_per_source_line"] = float(len(calls)) / float(source_lines)

    vector["vba_api_unique_ratio"] = (
        float(len(unique_api_names)) / float(len(calls)) if calls else 0.0
    )

    vector["vba_api_declaration_ratio"] = (
        float(len(declarations)) / float(len(calls)) if calls else 0.0
    )

    # ---------------------------------------------------------------
    # String/API interaction indicators.
    # ---------------------------------------------------------------

    source_lower = source.lower()

    vector["vba_api_source_has_http"] = float(
        "http://" in source_lower or "https://" in source_lower
    )

    vector["vba_api_source_has_windows_path"] = float(
        bool(
            re.search(
                r"(?i)(?:[a-z]:\\|\\\\)",
                source,
            )
        )
    )

    vector["vba_api_source_has_cmd"] = float(
        bool(
            re.search(
                r"(?i)\b(?:cmd(?:\.exe)?|powershell(?:\.exe)?)\b",
                source,
            )
        )
    )

    vector["vba_api_source_has_base64"] = float(
        bool(
            re.search(
                r"(?i)\bbase64\b|frombase64string|decodebase64",
                source,
            )
        )
    )

    # ---------------------------------------------------------------
    # Ensure finite values.
    # ---------------------------------------------------------------

    for key, value in list(vector.items()):
        if not math.isfinite(value):
            vector[key] = 0.0

    return vector


# ---------------------------------------------------------------------------
# Main analyzer
# ---------------------------------------------------------------------------


def extract_api_features(
    source: Union[
        str,
        bytes,
        bytearray,
        memoryview,
        BinaryIO,
    ],
    *,
    structured_records: Optional[Iterable[Any]] = None,
) -> VBAAPIFeatures:
    """
    Analyze VBA API evidence.

    Args:
        source:
            VBA source text or bytes.

        structured_records:
            Optional records emitted by an upstream VBA parser.

    Returns:
        VBAAPIFeatures
    """

    text = _read_source(source)

    analysis_source = strip_vba_comments(text)

    declarations = parse_api_declarations(analysis_source)

    parsed_calls = parse_api_calls(
        analysis_source,
        declarations,
    )

    structured_calls: Tuple[VBAAPICall, ...] = tuple()

    if structured_records is not None:
        structured_calls = normalize_structured_api_records(structured_records)

    # Merge parser records and regex-derived records.
    calls_by_key: Dict[
        Tuple[int, str],
        VBAAPICall,
    ] = {}

    for call in parsed_calls + structured_calls:
        key = (
            call.line_number,
            _casefold(call.normalized_name),
        )

        if key not in calls_by_key:
            calls_by_key[key] = call
            continue

        # Prefer the record carrying a library or richer source context.
        existing = calls_by_key[key]

        if len(call.source) > len(existing.source) or (
            call.library and not existing.library
        ):
            calls_by_key[key] = call

    calls = tuple(
        sorted(
            calls_by_key.values(),
            key=lambda item: (
                item.line_number,
                item.normalized_name.lower(),
            ),
        )
    )

    declared_libraries = extract_declared_libraries(analysis_source)

    referenced_libraries = extract_library_references(analysis_source)

    libraries = tuple(
        sorted(
            set(
                declared_libraries
                + referenced_libraries
                + tuple(call.library for call in calls if call.library)
            )
        )
    )

    capabilities = derive_capabilities(
        calls,
        declarations,
    )

    indicators = derive_api_indicators(
        calls,
        declarations,
        libraries,
    )

    feature_vector = _build_feature_vector(
        declarations=declarations,
        calls=calls,
        libraries=libraries,
        source=analysis_source,
    )

    metadata: Dict[str, Any] = {
        "source_length": len(analysis_source),
        "source_line_count": len(analysis_source.splitlines()),
        "declaration_count": len(declarations),
        "call_count": len(calls),
        "library_count": len(libraries),
        "capability_count": len(capabilities),
        "indicator_count": len(indicators),
    }

    return VBAAPIFeatures(
        declarations=declarations,
        calls=calls,
        libraries=libraries,
        capabilities=capabilities,
        indicators=indicators,
        feature_vector=feature_vector,
        metadata=metadata,
    )


def analyze_vba_api(
    source: Union[
        str,
        bytes,
        bytearray,
        memoryview,
        BinaryIO,
    ],
    **kwargs: Any,
) -> VBAAPIFeatures:
    """
    Alias for extract_api_features().
    """

    return extract_api_features(
        source,
        **kwargs,
    )


# ---------------------------------------------------------------------------
# Feature-only APIs
# ---------------------------------------------------------------------------


def extract_feature_vector(
    source: Union[
        str,
        bytes,
        bytearray,
        memoryview,
        BinaryIO,
    ],
    **kwargs: Any,
) -> Dict[str, float]:
    """
    Return only numeric features.
    """

    return dict(
        extract_api_features(
            source,
            **kwargs,
        ).feature_vector
    )


def extract_api_feature_vector(
    source: Union[
        str,
        bytes,
        bytearray,
        memoryview,
        BinaryIO,
    ],
    **kwargs: Any,
) -> Dict[str, float]:
    """
    Explicit alias for extract_feature_vector().
    """

    return extract_feature_vector(
        source,
        **kwargs,
    )


# ---------------------------------------------------------------------------
# Stable schema
# ---------------------------------------------------------------------------


def api_feature_names() -> Tuple[str, ...]:
    """
    Return the canonical numeric feature names.
    """

    empty_vector = _build_feature_vector(
        declarations=tuple(),
        calls=tuple(),
        libraries=tuple(),
        source="",
    )

    return tuple(sorted(empty_vector.keys()))


def build_feature_schema() -> Dict[str, Any]:
    """
    Build a machine-readable API feature schema.
    """

    names = api_feature_names()

    return {
        "schema_version": "1.0.0",
        "extractor": "vba.api_features",
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
    Convert a feature mapping into deterministic vector order.
    """

    names = tuple(feature_names) if feature_names is not None else api_feature_names()

    result: List[float] = []

    for name in names:
        value = features.get(
            name,
            0.0,
        )

        try:
            numeric = float(value)

            if not math.isfinite(numeric):
                numeric = 0.0

        except (
            TypeError,
            ValueError,
        ):
            numeric = 0.0

        result.append(numeric)

    return result


# ---------------------------------------------------------------------------
# Query helpers
# ---------------------------------------------------------------------------


def find_api_calls(
    analysis: VBAAPIFeatures,
    api_name: str,
) -> Tuple[VBAAPICall, ...]:
    """
    Find calls to a specific API.
    """

    target = _casefold(normalize_api_name(api_name))

    return tuple(
        call for call in analysis.calls if _casefold(call.normalized_name) == target
    )


def find_calls_by_capability(
    analysis: VBAAPIFeatures,
    capability: str,
) -> Tuple[VBAAPICall, ...]:
    """
    Return API calls associated with a capability.
    """

    target = capability.strip().lower()

    return tuple(
        call
        for call in analysis.calls
        if target in {item.lower() for item in call.capability_categories}
    )


def has_capability(
    analysis: VBAAPIFeatures,
    capability: str,
) -> bool:
    """
    Test whether static API evidence supports a capability.
    """

    return capability in analysis.capabilities


def capability_count(
    analysis: VBAAPIFeatures,
    capability: str,
) -> int:
    """
    Count API calls belonging to a capability.
    """

    return len(
        find_calls_by_capability(
            analysis,
            capability,
        )
    )


def has_api(
    analysis: VBAAPIFeatures,
    api_name: str,
) -> bool:
    """
    Test whether an API appears in the analysis.
    """

    return bool(
        find_api_calls(
            analysis,
            api_name,
        )
    )


# ---------------------------------------------------------------------------
# Serialization
# ---------------------------------------------------------------------------


def analysis_to_dict(
    analysis: VBAAPIFeatures,
    *,
    include_source_context: bool = True,
) -> Dict[str, Any]:
    """
    Convert the analysis result to a JSON-serializable dictionary.
    """

    calls: List[Dict[str, Any]] = []

    for call in analysis.calls:
        record = asdict(call)

        if not include_source_context:
            record.pop(
                "source",
                None,
            )

        calls.append(record)

    return {
        "declarations": [asdict(declaration) for declaration in analysis.declarations],
        "calls": calls,
        "libraries": list(analysis.libraries),
        "capabilities": list(analysis.capabilities),
        "indicators": list(analysis.indicators),
        "feature_vector": dict(analysis.feature_vector),
        "metadata": dict(analysis.metadata),
    }


# ---------------------------------------------------------------------------
# Evidence summaries
# ---------------------------------------------------------------------------


def summarize_api_capabilities(
    analysis: VBAAPIFeatures,
) -> Dict[str, int]:
    """
    Return capability -> number of API call records.
    """

    counts: Counter[str] = Counter()

    for call in analysis.calls:
        for capability in call.capability_categories:
            counts[capability] += 1

    return dict(sorted(counts.items()))


def suspicious_capability_count(
    analysis: VBAAPIFeatures,
) -> int:
    """
    Count high-impact capability categories.

    This is an evidence metric, not a malware score.
    """

    high_impact = {
        "process_execution",
        "process_injection",
        "memory_execution",
        "dynamic_library_loading",
        "download",
        "registry",
        "service_management",
        "credential_access",
        "security_token",
        "anti_analysis",
    }

    return sum(capability in high_impact for capability in analysis.capabilities)


# ---------------------------------------------------------------------------
# Batch processing
# ---------------------------------------------------------------------------


def iter_api_features(
    sources: Iterable[
        Union[
            str,
            bytes,
            bytearray,
            memoryview,
            BinaryIO,
        ]
    ],
    *,
    continue_on_error: bool = True,
    **kwargs: Any,
) -> Iterator[
    Tuple[
        Any,
        Optional[VBAAPIFeatures],
        Optional[Exception],
    ]
]:
    """
    Analyze multiple VBA sources.

    Yields:
        (source, analysis, error)
    """

    for source in sources:
        try:
            analysis = extract_api_features(
                source,
                **kwargs,
            )

            yield (
                source,
                analysis,
                None,
            )

        except Exception as exc:
            if not continue_on_error:
                raise

            yield (
                source,
                None,
                exc,
            )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

__all__ = [
    "API_CAPABILITIES",
    "DLL_FAMILIES",
    "VBAAPIDeclaration",
    "VBAAPICall",
    "VBAAPIFeatures",
    "normalize_api_name",
    "normalize_library_name",
    "api_capabilities",
    "strip_vba_comments",
    "parse_api_declarations",
    "parse_api_calls",
    "extract_declared_libraries",
    "extract_library_references",
    "normalize_structured_api_records",
    "derive_capabilities",
    "derive_api_indicators",
    "extract_api_features",
    "analyze_vba_api",
    "extract_feature_vector",
    "extract_api_feature_vector",
    "api_feature_names",
    "build_feature_schema",
    "vectorize_features",
    "find_api_calls",
    "find_calls_by_capability",
    "has_capability",
    "capability_count",
    "has_api",
    "analysis_to_dict",
    "summarize_api_capabilities",
    "suspicious_capability_count",
    "iter_api_features",
]
