"""
Static VBA capability analysis for Pharos CDR.

This module translates parsed VBA/API evidence into normalized capabilities.

Security model
--------------
This module NEVER:
- executes VBA;
- evaluates VBA expressions;
- invokes Windows APIs;
- launches processes;
- accesses the network;
- modifies the registry/filesystem;
- loads DLLs;
- resolves COM objects.

It only interprets already-extracted static evidence.

Pipeline
--------
    VBA source
        |
        v
    parser.py
        |
        +--> calls
        +--> strings
        +--> declarations
        +--> statements
        +--> indicators
        |
        v
    api_features.py
        |
        +--> API capabilities
        |
        v
    capabilities.py
        |
        +--> normalized capabilities
        +--> evidence
        +--> combinations
        +--> feature vector
        |
        +--> execution.py
        +--> obfuscation.py
        +--> feature_pipeline.py
        +--> policy.py
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from typing import Any, Iterable, Iterator, Mapping, Optional, Sequence

from .parser import VBAAnalysis as _ParserVBAAnalysis


class VBAAnalysis(_ParserVBAAnalysis):
    """Concrete analysis container used by capability extraction.

    The parser model is abstract in some integrations; this implementation
    provides safe, in-memory collections for all evidence types consumed by
    this module.
    """

    __abstractmethods__ = frozenset()

    def __init__(self, source: str = "", **kwargs: Any) -> None:
        self.source = source
        self.api_declarations: list[Any] = list(
            kwargs.pop("api_declarations", ()) or ()
        )
        self.calls: list[Any] = list(kwargs.pop("calls", ()) or ())
        self.statements: list[Any] = list(kwargs.pop("statements", ()) or ())
        self.indicators: list[Any] = list(kwargs.pop("indicators", ()) or ())
        self.strings: list[Any] = list(kwargs.pop("strings", ()) or ())
        for name, value in kwargs.items():
            setattr(self, name, value)

    def add_api_declaration(self, declaration: Any) -> Any:
        self.api_declarations.append(declaration)
        return declaration

    def add_call(self, call: Any) -> Any:
        self.calls.append(call)
        return call

    def add_statement(self, statement: Any) -> Any:
        self.statements.append(statement)
        return statement

    def add_indicator(self, indicator: Any) -> Any:
        self.indicators.append(indicator)
        return indicator

    def add_string(self, string: Any) -> Any:
        self.strings.append(string)
        return string

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "api_declarations": list(self.api_declarations),
            "calls": list(self.calls),
            "statements": list(self.statements),
            "indicators": list(self.indicators),
            "strings": list(self.strings),
        }

# ---------------------------------------------------------------------------
# Safety limits
# ---------------------------------------------------------------------------

MAX_SOURCE_SIZE = 25 * 1024 * 1024
MAX_EVIDENCE = 100_000
MAX_CAPABILITIES = 10_000
MAX_TEXT_LENGTH = 4_096


# ---------------------------------------------------------------------------
# Capability taxonomy
# ---------------------------------------------------------------------------

CAPABILITY_CATEGORIES = (
    "execution",
    "process",
    "memory",
    "injection",
    "filesystem",
    "registry",
    "network",
    "download",
    "communication",
    "com_automation",
    "macro",
    "persistence",
    "credential_access",
    "discovery",
    "collection",
    "clipboard",
    "security_software",
    "evasion",
    "environment",
    "crypto",
    "encoding",
    "obfuscation",
    "reflection",
    "dynamic_resolution",
    "service",
    "token",
    "synchronization",
    "user_interface",
    "document_manipulation",
    "configuration",
)


# ---------------------------------------------------------------------------
# API capability map
# ---------------------------------------------------------------------------

API_CAPABILITIES: dict[str, tuple[str, ...]] = {
    # Process creation / execution
    "createprocess": ("process", "execution"),
    "createprocessa": ("process", "execution"),
    "createprocessw": ("process", "execution"),
    "createprocessasuser": ("process", "execution"),
    "createprocessasusera": ("process", "execution"),
    "createprocessasuserw": ("process", "execution"),
    "winexec": ("process", "execution"),
    "shellexecute": ("process", "execution"),
    "shellexecutea": ("process", "execution"),
    "shellexecutew": ("process", "execution"),
    "shellexecuteex": ("process", "execution"),
    "shellexecuteexa": ("process", "execution"),
    "shellexecuteexw": ("process", "execution"),
    "exitprocess": ("process", "execution"),
    "terminateprocess": ("process", "execution"),
    # Process inspection / access
    "openprocess": ("process", "discovery"),
    "getcurrentprocess": ("process", "discovery"),
    "getcurrentprocessid": ("process", "discovery"),
    "getprocessid": ("process", "discovery"),
    "getexitcodeprocess": ("process", "discovery"),
    "getprocessimagefilename": ("process", "discovery"),
    "getprocessimagefilenamea": ("process", "discovery"),
    "getprocessimagefilenamew": ("process", "discovery"),
    "enumprocesses": ("process", "discovery"),
    "process32first": ("process", "discovery"),
    "process32firstw": ("process", "discovery"),
    "process32next": ("process", "discovery"),
    "process32nextw": ("process", "discovery"),
    "createtoolhelp32snapshot": ("process", "discovery"),
    # Memory
    "virtualalloc": ("memory",),
    "virtualalloca": ("memory",),
    "virtualallocex": ("memory", "injection"),
    "virtualfree": ("memory",),
    "virtualfreeex": ("memory", "injection"),
    "virtualprotect": ("memory",),
    "virtualprotectex": ("memory", "injection"),
    "writeprocessmemory": ("memory", "injection"),
    "readprocessmemory": ("memory",),
    "flushinstructioncache": ("memory", "execution"),
    "mapviewoffile": ("memory",),
    "unmapviewoffile": ("memory",),
    "createremotethread": ("injection", "execution"),
    "createremotethreada": ("injection", "execution"),
    "createremotethreadw": ("injection", "execution"),
    "queueuserworkitem": ("execution",),
    "rtlmovememory": ("memory",),
    "rtlcopymemory": ("memory",),
    "copymemory": ("memory",),
    # Dynamic API/library resolution
    "getprocaddress": ("dynamic_resolution",),
    "getmodulehandle": ("dynamic_resolution",),
    "getmodulehandlea": ("dynamic_resolution",),
    "getmodulehandlew": ("dynamic_resolution",),
    "loadlibrary": ("dynamic_resolution",),
    "loadlibrarya": ("dynamic_resolution",),
    "loadlibraryw": ("dynamic_resolution",),
    "loadlibraryex": ("dynamic_resolution",),
    "loadlibraryexa": ("dynamic_resolution",),
    "loadlibraryexw": ("dynamic_resolution",),
    # Filesystem
    "createfile": ("filesystem",),
    "createfilea": ("filesystem",),
    "createfilew": ("filesystem",),
    "readfile": ("filesystem",),
    "writefile": ("filesystem",),
    "deletefile": ("filesystem",),
    "deletefilea": ("filesystem",),
    "deletefilew": ("filesystem",),
    "copyfile": ("filesystem",),
    "copyfilea": ("filesystem",),
    "copyfilew": ("filesystem",),
    "movefile": ("filesystem",),
    "movefilea": ("filesystem",),
    "movefilew": ("filesystem",),
    "getfileattributes": ("filesystem",),
    "getfileattributesa": ("filesystem",),
    "getfileattributesw": ("filesystem",),
    "gettempfilename": ("filesystem",),
    "gettemppath": ("filesystem",),
    "gettemppatha": ("filesystem",),
    "gettemppathw": ("filesystem",),
    # Registry
    "regopenkey": ("registry", "configuration"),
    "regopenkeya": ("registry", "configuration"),
    "regopenkeyw": ("registry", "configuration"),
    "regopenkeyex": ("registry", "configuration"),
    "regopenkeyexa": ("registry", "configuration"),
    "regopenkeyexw": ("registry", "configuration"),
    "regcreatekey": ("registry",),
    "regcreatekeya": ("registry",),
    "regcreatekeyw": ("registry",),
    "regcreatekeyex": ("registry",),
    "regcreatekeyexa": ("registry",),
    "regcreatekeyexw": ("registry",),
    "regsetvalue": ("registry", "persistence"),
    "regsetvaluea": ("registry", "persistence"),
    "regsetvaluew": ("registry", "persistence"),
    "regsetvalueex": ("registry", "persistence"),
    "regsetvalueexa": ("registry", "persistence"),
    "regsetvalueexw": ("registry", "persistence"),
    "regqueryvalue": ("registry",),
    "regqueryvaluea": ("registry",),
    "regqueryvaluew": ("registry",),
    "regqueryvalueex": ("registry",),
    "regqueryvalueexa": ("registry",),
    "regqueryvalueexw": ("registry",),
    "regdeletekey": ("registry",),
    "regdeletekeya": ("registry",),
    "regdeletekeyw": ("registry",),
    "regdeletevalue": ("registry",),
    "regdeletevaluea": ("registry",),
    "regdeletevaluew": ("registry",),
    # Networking
    "internetopen": ("network", "communication"),
    "internetopena": ("network", "communication"),
    "internetopenw": ("network", "communication"),
    "internetopenurl": ("network", "communication"),
    "internetopenurla": ("network", "communication"),
    "internetopenurlw": ("network", "communication"),
    "internetconnect": ("network", "communication"),
    "internetconnecta": ("network", "communication"),
    "internetconnectw": ("network", "communication"),
    "httpopenrequest": ("network", "communication"),
    "httpopenrequesta": ("network", "communication"),
    "httpopenrequestw": ("network", "communication"),
    "httpsendrequest": ("network", "communication"),
    "httpsendrequesta": ("network", "communication"),
    "httpsendrequestw": ("network", "communication"),
    "internetreadfile": ("network", "communication", "download"),
    "internetreadfileex": ("network", "communication", "download"),
    "winhttpopen": ("network", "communication"),
    "winhttpconnect": ("network", "communication"),
    "winhttpopenrequest": ("network", "communication"),
    "winhttpsendrequest": ("network", "communication"),
    "winhttpreceiveresponse": ("network", "communication"),
    "winhttpreaddata": ("network", "communication", "download"),
    # Download
    "urldownloadtofile": ("network", "download", "filesystem"),
    "urldownloadtofilea": ("network", "download", "filesystem"),
    "urldownloadtofilew": ("network", "download", "filesystem"),
    # COM / automation
    "cocreateinstance": ("com_automation",),
    "cocreateinstanceex": ("com_automation",),
    "cogetclassobject": ("com_automation",),
    "getobject": ("com_automation",),
    "createobject": ("com_automation",),
    # Credential/token access
    "openprocesstoken": ("token", "credential_access"),
    "openthreadtoken": ("token", "credential_access"),
    "gettokeninformation": ("token", "credential_access"),
    "duplicatetoken": ("token", "credential_access"),
    "duplicatetokenex": ("token", "credential_access"),
    "adjusttokenprivileges": ("token", "credential_access"),
    "lookupprivilegevalue": ("token",),
    "lookupaccountname": ("credential_access", "discovery"),
    "lookupaccountsid": ("credential_access", "discovery"),
    # Environment / discovery
    "getcomputername": ("environment", "discovery"),
    "getcomputernamea": ("environment", "discovery"),
    "getcomputernamew": ("environment", "discovery"),
    "getusername": ("environment", "discovery"),
    "getusernamea": ("environment", "discovery"),
    "getusernamew": ("environment", "discovery"),
    "getsystemdirectory": ("environment", "discovery"),
    "getwindowsdirectory": ("environment", "discovery"),
    "getversionex": ("environment", "discovery"),
    "getversionexa": ("environment", "discovery"),
    "getversionexw": ("environment", "discovery"),
    "getlogicaldrives": ("environment", "discovery"),
    "getdiskfreespace": ("environment", "discovery"),
    "getsysteminfo": ("environment", "discovery"),
    # Services / persistence
    "openscmanager": ("service", "persistence"),
    "openscmanagera": ("service", "persistence"),
    "openscmanagerw": ("service", "persistence"),
    "createservice": ("service", "persistence"),
    "createservicea": ("service", "persistence"),
    "createservicew": ("service", "persistence"),
    "openservice": ("service", "persistence"),
    "startservice": ("service", "persistence"),
    "controlservice": ("service", "persistence"),
    "deleteservice": ("service", "persistence"),
    # Synchronization
    "createsemaphore": ("synchronization",),
    "createmutex": ("synchronization",),
    "openmutex": ("synchronization",),
    "releaseMutex": ("synchronization",),
    # Clipboard / UI
    "openclipboard": ("clipboard",),
    "getclipboarddata": ("clipboard", "collection"),
    "setclipboarddata": ("clipboard", "collection"),
    "closeclipboard": ("clipboard",),
    "findwindow": ("user_interface", "discovery"),
    "findwindowa": ("user_interface", "discovery"),
    "findwindoww": ("user_interface", "discovery"),
    "getforegroundwindow": ("user_interface", "discovery"),
    "getwindowtext": ("user_interface", "discovery"),
    "getwindowtexta": ("user_interface", "discovery"),
    "getwindowtextw": ("user_interface", "discovery"),
    # Crypto
    "cryptacquirecontext": ("crypto",),
    "cryptacquirecontexta": ("crypto",),
    "cryptacquirecontextw": ("crypto",),
    "cryptcreatehash": ("crypto",),
    "crypthashdata": ("crypto",),
    "cryptderivekey": ("crypto",),
    "cryptdecrypt": ("crypto",),
    "cryptencrypt": ("crypto",),
    "cryptdestroykey": ("crypto",),
    # Security-product discovery
    "opensecuritycenter": ("security_software", "discovery"),
    "wscgetsecurityproductlist": ("security_software", "discovery"),
}


# ---------------------------------------------------------------------------
# Library-family mapping
# ---------------------------------------------------------------------------

LIBRARY_CAPABILITIES: dict[str, tuple[str, ...]] = {
    "kernel32": (
        "process",
        "filesystem",
        "memory",
        "environment",
    ),
    "kernelbase": (
        "process",
        "filesystem",
        "memory",
        "environment",
    ),
    "user32": (
        "user_interface",
        "discovery",
    ),
    "advapi32": (
        "registry",
        "service",
        "token",
        "credential_access",
    ),
    "ole32": ("com_automation",),
    "oleaut32": ("com_automation",),
    "oleacc": ("user_interface",),
    "wininet": (
        "network",
        "communication",
        "download",
    ),
    "winhttp": (
        "network",
        "communication",
        "download",
    ),
    "urlmon": (
        "network",
        "download",
    ),
    "shell32": (
        "execution",
        "filesystem",
    ),
    "crypt32": ("crypto",),
    "bcrypt": ("crypto",),
}


# ---------------------------------------------------------------------------
# Source-level capability patterns
# ---------------------------------------------------------------------------

SOURCE_CAPABILITY_PATTERNS: dict[str, tuple[str, ...]] = {
    "execution": (
        r"\bShell\s*\(",
        r"\bWScript\.Shell\b",
        r"\bShellExecute(?:Ex)?\b",
        r"\bApplication\.Run\b",
        r"\bCallByName\b",
        r"\bExecute(?:Global)?\b",
        r"\bMacScript\b",
    ),
    "dynamic_resolution": (
        r"\bGetProcAddress\b",
        r"\bLoadLibrary(?:Ex)?\b",
        r"\bCallByName\b",
        r"\bApplication\.Run\b",
    ),
    "com_automation": (
        r"\bCreateObject\s*\(",
        r"\bGetObject\s*\(",
        r"\bWScript\.Shell\b",
        r"\bADODB\.Stream\b",
        r"\bMSXML\d*\.",
        r"\bWinHttp\.WinHttpRequest\b",
    ),
    "network": (
        r"\bXMLHTTP\b",
        r"\bWinHttpRequest\b",
        r"\bServerXMLHTTP\b",
        r"\bInternetOpen(?:Url)?\b",
        r"\bWinHttp\b",
        r"\bURLDownloadToFile\b",
    ),
    "download": (
        r"\bURLDownloadToFile\b",
        r"\bADODB\.Stream\b",
        r"\bXMLHTTP\b",
        r"\bWinHttpRequest\b",
        r"\bInternetOpenUrl\b",
    ),
    "filesystem": (
        r"\bOpen\s+[^,\r\n]+For\s+(?:Binary|Output|Input|Append)\b",
        r"\b(?:Kill|FileCopy|Name|MkDir|RmDir|ChDir|ChDrive)\b",
        r"\bADODB\.Stream\b",
        r"\bScripting\.FileSystemObject\b",
    ),
    "registry": (
        r"\b(?:RegOpenKey|RegCreateKey|RegSetValue|RegQueryValue|"
        r"RegDeleteKey|RegDeleteValue)\b",
        r"\b(?:SaveSetting|GetSetting|DeleteSetting)\b",
    ),
    "persistence": (
        r"\b(?:SaveSetting|RegSetValue|RegCreateKey|CreateService)\b",
        r"\b(?:CurrentUser|CurrentVersion\\Run|RunOnce)\b",
        r"\bStartup\b",
    ),
    "credential_access": (
        r"\b(?:OpenProcessToken|GetTokenInformation|"
        r"CredRead|CredEnumerate|WNetGetUser)\b",
        r"\b(?:Password|Credential|Credentials|Token)\b",
    ),
    "collection": (
        r"\b(?:Clipboard|GetClipboardData|OpenClipboard)\b",
        r"\b(?:FileSystemObject|Dir|FileLen|LOF)\b",
    ),
    "discovery": (
        r"\b(?:Environ|GetUserName|GetComputerName|"
        r"GetVersionEx|GetSystemInfo|GetLogicalDrives)\b",
    ),
    "environment": (
        r"\b(?:Environ|Application\.OperatingSystem|"
        r"Application\.Version|Command)\b",
    ),
    "obfuscation": (
        r"\b(?:Chr|ChrW|ChrB|Asc|AscW|StrReverse|"
        r"Replace|Mid|Left|Right|Split|Join)\b",
    ),
    "encoding": (
        r"\b(?:Base64|FromBase64String|ToBase64String|"
        r"ADODB\.Stream|MSXML\d*\.DOMDocument)\b",
    ),
    "evasion": (
        r"\bOn\s+Error\s+Resume\s+Next\b",
        r"\b(?:Environ|GetVersionEx|GetSystemInfo)\b",
    ),
    "macro": (
        r"\b(?:AutoOpen|AutoClose|AutoExec|AutoExit|"
        r"Document_Open|Document_Close|Workbook_Open|"
        r"Workbook_BeforeClose)\b",
        r"\bApplication\.Run\b",
    ),
    "document_manipulation": (
        r"\b(?:ActiveDocument|ThisDocument|ActiveWorkbook|"
        r"ThisWorkbook|Worksheets|VBProject|VBComponents)\b",
    ),
    "reflection": (
        r"\b(?:VBProject|VBComponents|CodeModule|"
        r"InsertLines|AddFromString|DeleteLines)\b",
    ),
    "user_interface": (r"\b(?:MsgBox|InputBox|UserForm|CommandBars|Dialogs)\b",),
}


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass
class CapabilityEvidence:
    """Evidence supporting one normalized capability."""

    capability: str
    source_type: str
    indicator: str
    evidence: str
    line_number: Optional[int] = None
    procedure: Optional[str] = None
    confidence: float = 1.0
    severity: str = "medium"


@dataclass
class CapabilityRecord:
    """Normalized capability with evidence and derived metadata."""

    name: str
    present: bool = True
    count: int = 0
    unique_indicators: list[str] = field(default_factory=list)
    evidence: list[CapabilityEvidence] = field(default_factory=list)
    confidence: float = 1.0
    severity: str = "low"


@dataclass
class CapabilityCombination:
    """Higher-level capability combination."""

    name: str
    present: bool
    required_capabilities: list[str]
    explanation: str


@dataclass
class VBACapabilityAnalysis:
    """Complete normalized VBA capability analysis."""

    capabilities: dict[str, CapabilityRecord] = field(default_factory=dict)
    combinations: list[CapabilityCombination] = field(default_factory=list)
    evidence: list[CapabilityEvidence] = field(default_factory=list)
    feature_vector: dict[str, int | float] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Normalization
# ---------------------------------------------------------------------------


def normalize_api_name(name: str) -> str:
    """Normalize API/procedure names for capability lookup."""

    value = str(name).strip()

    if "!" in value:
        value = value.rsplit("!", 1)[-1]

    if "." in value:
        value = value.rsplit(".", 1)[-1]

    return value.casefold()


def normalize_library_name(name: Optional[str]) -> str:
    """Normalize a library/DLL reference."""

    if not name:
        return ""

    value = name.strip().strip('"').casefold()

    if value.endswith(".dll"):
        value = value[:-4]

    if value.endswith(".ocx"):
        value = value[:-4]

    return value


# ---------------------------------------------------------------------------
# API capability lookup
# ---------------------------------------------------------------------------


def api_capabilities(api_name: str) -> tuple[str, ...]:
    """Return normalized capabilities associated with an API."""

    normalized = normalize_api_name(api_name)

    direct = API_CAPABILITIES.get(normalized)

    if direct:
        return direct

    # Handle common A/W/Ex suffix variants.
    base = normalized

    for suffix in ("exw", "exa", "w", "a"):
        if base.endswith(suffix) and len(base) > len(suffix):
            base = base[: -len(suffix)]
            direct = API_CAPABILITIES.get(base)

            if direct:
                return direct

    return ()


def library_capabilities(library: Optional[str]) -> tuple[str, ...]:
    """Return broad capability families associated with a DLL."""

    normalized = normalize_library_name(library)

    if not normalized:
        return ()

    if normalized in LIBRARY_CAPABILITIES:
        return LIBRARY_CAPABILITIES[normalized]

    for family, capabilities in LIBRARY_CAPABILITIES.items():
        if normalized.startswith(family):
            return capabilities

    return ()


# ---------------------------------------------------------------------------
# Evidence helpers
# ---------------------------------------------------------------------------


def _clip(value: Any, maximum: int = MAX_TEXT_LENGTH) -> str:
    text = str(value)

    if len(text) <= maximum:
        return text

    return text[:maximum] + "..."


def _add_evidence(
    result: VBACapabilityAnalysis,
    evidence: CapabilityEvidence,
) -> None:
    if len(result.evidence) >= MAX_EVIDENCE:
        return

    result.evidence.append(evidence)

    record = result.capabilities.get(evidence.capability)

    if record is None:
        record = CapabilityRecord(
            name=evidence.capability,
        )
        result.capabilities[evidence.capability] = record

    record.count += 1

    if evidence.indicator not in record.unique_indicators:
        record.unique_indicators.append(evidence.indicator)

    if len(record.evidence) < MAX_EVIDENCE:
        record.evidence.append(evidence)

    record.confidence = max(
        record.confidence,
        evidence.confidence,
    )

    if evidence.severity == "high":
        record.severity = "high"
    elif evidence.severity == "medium" and record.severity != "high":
        record.severity = "medium"


# ---------------------------------------------------------------------------
# Parser-object integration
# ---------------------------------------------------------------------------


def _get_attr(obj: Any, name: str, default: Any = None) -> Any:
    if isinstance(obj, Mapping):
        return obj.get(name, default)

    return getattr(obj, name, default)


def _iter_api_declarations(
    analysis: Any,
) -> Iterable[Any]:
    return _get_attr(analysis, "api_declarations", ()) or ()


def _iter_calls(
    analysis: Any,
) -> Iterable[Any]:
    return _get_attr(analysis, "calls", ()) or ()


def _iter_statements(
    analysis: Any,
) -> Iterable[Any]:
    return _get_attr(analysis, "statements", ()) or ()


def _iter_indicators(
    analysis: Any,
) -> Iterable[Any]:
    return _get_attr(analysis, "indicators", ()) or ()


def _iter_strings(
    analysis: Any,
) -> Iterable[Any]:
    return _get_attr(analysis, "strings", ()) or ()


# ---------------------------------------------------------------------------
# API-derived capabilities
# ---------------------------------------------------------------------------


def derive_api_capabilities(
    analysis: Any,
    result: Optional[VBAAnalysis] = None,
) -> VBACapabilityAnalysis:
    """
    Derive capabilities from parsed VBA API declarations/calls.
    """

    if result is None:
        result = VBACapabilityAnalysis()

    # External Declare statements.
    for declaration in _iter_api_declarations(analysis):
        name = _get_attr(declaration, "name", "")
        alias = _get_attr(declaration, "alias", None)
        library = _get_attr(declaration, "library", None)
        line_number = _get_attr(declaration, "line_number", None)

        api_name = alias or name
        capabilities = api_capabilities(api_name)

        for capability in capabilities:
            severity = (
                "high"
                if capability
                in {
                    "injection",
                    "execution",
                    "persistence",
                }
                else "medium"
            )

            _add_evidence(
                result,
                CapabilityEvidence(
                    capability=capability,
                    source_type="api_declaration",
                    indicator=normalize_api_name(api_name),
                    evidence=_clip(_get_attr(declaration, "raw", api_name)),
                    line_number=line_number,
                    confidence=0.98,
                    severity=severity,
                ),
            )

        # Library family evidence is deliberately lower-confidence than
        # individual API evidence.
        for capability in library_capabilities(library):
            _add_evidence(
                result,
                CapabilityEvidence(
                    capability=capability,
                    source_type="api_library",
                    indicator=normalize_library_name(library),
                    evidence=_clip(_get_attr(declaration, "raw", library or "")),
                    line_number=line_number,
                    confidence=0.65,
                    severity="low",
                ),
            )

    # Calls can exist without explicit Declare statements, e.g. VBA runtime,
    # object methods, or functions exposed by referenced libraries.
    for call in _iter_calls(analysis):
        name = _get_attr(call, "name", "")
        line_number = _get_attr(call, "line_number", None)
        procedure = _get_attr(call, "procedure", None)
        source = _get_attr(call, "source", name)

        for capability in api_capabilities(name):
            severity = (
                "high"
                if capability
                in {
                    "execution",
                    "injection",
                    "persistence",
                }
                else "medium"
            )

            _add_evidence(
                result,
                CapabilityEvidence(
                    capability=capability,
                    source_type="api_call",
                    indicator=normalize_api_name(name),
                    evidence=_clip(source),
                    line_number=line_number,
                    procedure=procedure,
                    confidence=0.92,
                    severity=severity,
                ),
            )

    return result


# ---------------------------------------------------------------------------
# Source-derived capabilities
# ---------------------------------------------------------------------------


def derive_source_capabilities(
    analysis: Any,
    result: Optional[VBACapabilityAnalysis] = None,
) -> VBACapabilityAnalysis:
    """Derive capabilities from source-level indicators and statements."""

    if result is None:
        result = VBACapabilityAnalysis()

    for statement in _iter_statements(analysis):
        text = _get_attr(statement, "text", "")
        line_number = _get_attr(statement, "line_number", None)
        procedure = _get_attr(statement, "procedure", None)

        if not text:
            continue

        for capability, patterns in SOURCE_CAPABILITY_PATTERNS.items():
            for pattern in patterns:
                match = re.search(
                    pattern,
                    text,
                    flags=re.IGNORECASE,
                )

                if not match:
                    continue

                indicator = match.group(0).strip()

                severity = "low"

                if capability in {
                    "execution",
                    "download",
                    "persistence",
                    "dynamic_resolution",
                    "reflection",
                }:
                    severity = "medium"

                if capability in {
                    "execution",
                    "download",
                } and re.search(
                    r"(?i)\b(?:Shell|Execute|ExecuteGlobal|"
                    r"Application\.Run|URLDownloadToFile)\b",
                    text,
                ):
                    severity = "high"

                _add_evidence(
                    result,
                    CapabilityEvidence(
                        capability=capability,
                        source_type="source_pattern",
                        indicator=indicator,
                        evidence=_clip(text),
                        line_number=line_number,
                        procedure=procedure,
                        confidence=0.84,
                        severity=severity,
                    ),
                )

                # One evidence item per capability/statement/pattern family
                # is sufficient.
                break

    # Existing parser indicators are valuable evidence and may capture
    # constructs not represented in the source pattern table.
    for indicator in _iter_indicators(analysis):
        category = _get_attr(indicator, "category", "")
        name = _get_attr(indicator, "indicator", "")
        evidence = _get_attr(indicator, "evidence", "")
        line_number = _get_attr(indicator, "line_number", None)
        procedure = _get_attr(indicator, "procedure", None)
        severity = _get_attr(indicator, "severity", "medium")

        capability_map = {
            "execution": "execution",
            "automation": "com_automation",
            "network": "network",
            "filesystem": "filesystem",
            "registry": "registry",
            "macro": "macro",
            "obfuscation": "obfuscation",
            "environment": "environment",
            "evasion": "evasion",
        }

        capability = capability_map.get(str(category).casefold())

        if capability:
            _add_evidence(
                result,
                CapabilityEvidence(
                    capability=capability,
                    source_type="parser_indicator",
                    indicator=str(name),
                    evidence=_clip(evidence),
                    line_number=line_number,
                    procedure=procedure,
                    confidence=0.90,
                    severity=severity,
                ),
            )

    return result


# ---------------------------------------------------------------------------
# String-derived capabilities
# ---------------------------------------------------------------------------


def derive_string_capabilities(
    analysis: Any,
    result: Optional[VBACapabilityAnalysis] = None,
) -> VBACapabilityAnalysis:
    """Derive weak-to-moderate capabilities from extracted string evidence."""

    if result is None:
        result = VBACapabilityAnalysis()

    for string in _iter_strings(analysis):
        value = _get_attr(string, "value", "")
        line_number = _get_attr(string, "line_number", None)
        procedure = _get_attr(string, "procedure", None)

        if not value:
            continue

        urls = _get_attr(string, "urls", ()) or ()
        paths = _get_attr(string, "paths", ()) or ()
        ips = _get_attr(string, "ipv4_addresses", ()) or ()
        base64_like = bool(_get_attr(string, "base64_like", False))

        for url in urls:
            _add_evidence(
                result,
                CapabilityEvidence(
                    capability="network",
                    source_type="string",
                    indicator="url",
                    evidence=_clip(url),
                    line_number=line_number,
                    procedure=procedure,
                    confidence=0.88,
                    severity="medium",
                ),
            )

        for path in paths:
            _add_evidence(
                result,
                CapabilityEvidence(
                    capability="filesystem",
                    source_type="string",
                    indicator="path",
                    evidence=_clip(path),
                    line_number=line_number,
                    procedure=procedure,
                    confidence=0.75,
                    severity="low",
                ),
            )

        for ip in ips:
            _add_evidence(
                result,
                CapabilityEvidence(
                    capability="network",
                    source_type="string",
                    indicator="ipv4",
                    evidence=_clip(ip),
                    line_number=line_number,
                    procedure=procedure,
                    confidence=0.80,
                    severity="medium",
                ),
            )

        if base64_like:
            _add_evidence(
                result,
                CapabilityEvidence(
                    capability="encoding",
                    source_type="string",
                    indicator="base64_like",
                    evidence=_clip(value),
                    line_number=line_number,
                    procedure=procedure,
                    confidence=0.72,
                    severity="low",
                ),
            )

            _add_evidence(
                result,
                CapabilityEvidence(
                    capability="obfuscation",
                    source_type="string",
                    indicator="base64_like",
                    evidence=_clip(value),
                    line_number=line_number,
                    procedure=procedure,
                    confidence=0.62,
                    severity="low",
                ),
            )

    return result


# ---------------------------------------------------------------------------
# Combination analysis
# ---------------------------------------------------------------------------


def _has_capability(
    analysis: VBACapabilityAnalysis,
    capability: str,
) -> bool:
    record = analysis.capabilities.get(capability)
    return bool(record and record.present and record.count > 0)


def _add_combination(
    result: VBACapabilityAnalysis,
    name: str,
    required: Sequence[str],
    explanation: str,
) -> None:
    result.combinations.append(
        CapabilityCombination(
            name=name,
            present=all(_has_capability(result, capability) for capability in required),
            required_capabilities=list(required),
            explanation=explanation,
        )
    )


def derive_capability_combinations(
    result: VBACapabilityAnalysis,
) -> list[CapabilityCombination]:
    """
    Derive higher-level capability chains.

    These combinations are intentionally descriptive rather than verdicts.
    """

    result.combinations = []

    _add_combination(
        result,
        "download_then_execute",
        ("download", "execution"),
        "The VBA contains both network/download capability and execution capability.",
    )

    _add_combination(
        result,
        "networked_com_automation",
        ("network", "com_automation"),
        "The VBA combines network access with COM/automation facilities.",
    )

    _add_combination(
        result,
        "filesystem_execution",
        ("filesystem", "execution"),
        "The VBA combines filesystem operations with execution capability.",
    )

    _add_combination(
        result,
        "registry_persistence",
        ("registry", "persistence"),
        "The VBA references registry functionality together with persistence indicators.",
    )

    _add_combination(
        result,
        "process_memory_injection",
        ("process", "memory", "injection"),
        "The VBA contains process access, memory manipulation, and injection-related capabilities.",
    )

    _add_combination(
        result,
        "dynamic_execution",
        ("dynamic_resolution", "execution"),
        "The VBA combines dynamic API/code resolution with execution capability.",
    )

    _add_combination(
        result,
        "obfuscated_execution",
        ("obfuscation", "execution"),
        "The VBA combines obfuscation/string transformation with execution capability.",
    )

    _add_combination(
        result,
        "environment_aware_execution",
        ("environment", "execution"),
        "The VBA combines environment discovery with execution capability.",
    )

    _add_combination(
        result,
        "macro_network_execution",
        ("macro", "network", "execution"),
        "The VBA contains macro-triggering behavior together with network and execution capability.",
    )

    _add_combination(
        result,
        "credential_collection",
        ("credential_access", "collection"),
        "The VBA contains credential-access and collection-related capability signals.",
    )

    _add_combination(
        result,
        "service_persistence",
        ("service", "persistence"),
        "The VBA references service management together with persistence capability.",
    )

    return result.combinations


# ---------------------------------------------------------------------------
# Risk-oriented feature vector
# ---------------------------------------------------------------------------


def build_feature_vector(
    result: VBACapabilityAnalysis,
) -> dict[str, int | float]:
    """Create ML-ready scalar capability features."""

    vector: dict[str, int | float] = {}

    # Stable category presence/count features.
    for category in CAPABILITY_CATEGORIES:
        record = result.capabilities.get(category)

        count = record.count if record else 0
        present = int(count > 0)

        vector[f"vba_cap_{category}"] = present
        vector[f"vba_cap_{category}_count"] = count

        if record:
            vector[f"vba_cap_{category}_high_confidence"] = int(
                record.confidence >= 0.85
            )
            vector[f"vba_cap_{category}_high_severity"] = int(record.severity == "high")
        else:
            vector[f"vba_cap_{category}_high_confidence"] = 0
            vector[f"vba_cap_{category}_high_severity"] = 0

    # Combination features.
    for combination in result.combinations:
        key = "vba_cap_combo_" + combination.name.casefold()
        vector[key] = int(combination.present)

    # Global counts.
    vector["vba_capability_count"] = sum(
        1 for record in result.capabilities.values() if record.present
    )

    vector["vba_capability_evidence_count"] = len(result.evidence)

    vector["vba_capability_high_severity_count"] = sum(
        1 for record in result.capabilities.values() if record.severity == "high"
    )

    vector["vba_capability_medium_severity_count"] = sum(
        1 for record in result.capabilities.values() if record.severity == "medium"
    )

    vector["vba_capability_high_confidence_count"] = sum(
        1 for record in result.capabilities.values() if record.confidence >= 0.85
    )

    # Stronger aggregate signals.
    execution = _has_capability(result, "execution")
    download = _has_capability(result, "download")
    network = _has_capability(result, "network")
    persistence = _has_capability(result, "persistence")
    obfuscation = _has_capability(result, "obfuscation")
    injection = _has_capability(result, "injection")
    dynamic = _has_capability(result, "dynamic_resolution")
    environment = _has_capability(result, "environment")
    macro = _has_capability(result, "macro")

    vector["vba_cap_active_payload_chain"] = int(download and execution)

    vector["vba_cap_persistence_chain"] = int(
        persistence
        and (_has_capability(result, "registry") or _has_capability(result, "service"))
    )

    vector["vba_cap_injection_chain"] = int(
        injection
        and _has_capability(result, "memory")
        and _has_capability(result, "process")
    )

    vector["vba_cap_dynamic_execution_chain"] = int(dynamic and execution)

    vector["vba_cap_obfuscated_execution_chain"] = int(obfuscation and execution)

    vector["vba_cap_macro_network_execution_chain"] = int(
        macro and network and execution
    )

    vector["vba_cap_environment_aware_execution_chain"] = int(environment and execution)

    # A bounded normalized score useful for ranking, not as a verdict.
    high_weight = sum(
        record.count
        for record in result.capabilities.values()
        if record.severity == "high"
    )

    medium_weight = sum(
        record.count
        for record in result.capabilities.values()
        if record.severity == "medium"
    )

    capability_score = (
        min(high_weight, 20) * 3
        + min(medium_weight, 30) * 1.5
        + min(
            sum(1 for combo in result.combinations if combo.present),
            10,
        )
        * 2
    )

    vector["vba_capability_signal_score"] = min(
        capability_score,
        100.0,
    )

    return vector


# ---------------------------------------------------------------------------
# Main public API
# ---------------------------------------------------------------------------


def analyze_capabilities(
    analysis: Any,
) -> VBACapabilityAnalysis:
    """
    Analyze an already parsed VBA object.

    `analysis` is normally the VBAAnalysis returned by parser.parse_vba().
    """

    result = VBACapabilityAnalysis()

    derive_api_capabilities(
        analysis,
        result=result,
    )

    derive_source_capabilities(
        analysis,
        result=result,
    )

    derive_string_capabilities(
        analysis,
        result=result,
    )

    derive_capability_combinations(result)

    result.feature_vector = build_feature_vector(result)

    result.metadata = {
        "analyzer": "pharos-cdr-vba-capabilities",
        "version": "1.0",
        "static_only": True,
        "capability_categories": list(CAPABILITY_CATEGORIES),
        "evidence_count": len(result.evidence),
        "capability_count": len(result.capabilities),
        "combination_count": len(result.combinations),
    }

    return result


def extract_capabilities(
    analysis: Any,
) -> dict[str, CapabilityRecord]:
    """Return only the normalized capability records."""

    return analyze_capabilities(analysis).capabilities


def derive_capabilities(
    analysis: Any,
) -> dict[str, CapabilityRecord]:
    """Compatibility-oriented alias for extract_capabilities()."""

    return extract_capabilities(analysis)


def extract_capability_features(
    analysis: Any,
) -> dict[str, int | float]:
    """Return the ML-ready capability feature vector."""

    return analyze_capabilities(analysis).feature_vector


def extract_feature_vector(
    analysis: Any,
) -> dict[str, int | float]:
    """Compatibility alias for capability feature extraction."""

    return extract_capability_features(analysis)


# ---------------------------------------------------------------------------
# Query helpers
# ---------------------------------------------------------------------------


def has_capability(
    analysis: VBACapabilityAnalysis,
    capability: str,
) -> bool:
    """Return whether a capability is present."""

    return _has_capability(
        analysis,
        capability.casefold(),
    )


def capability_count(
    analysis: VBACapabilityAnalysis,
    capability: str,
) -> int:
    """Return evidence count for a capability."""

    record = analysis.capabilities.get(capability.casefold())

    return record.count if record else 0


def capability_names(
    analysis: VBACapabilityAnalysis,
) -> list[str]:
    """Return present capability names."""

    return sorted(
        (name for name, record in analysis.capabilities.items() if record.present),
        key=str.casefold,
    )


def capabilities_by_severity(
    analysis: VBACapabilityAnalysis,
    severity: str,
) -> list[CapabilityRecord]:
    """Return capabilities matching a severity level."""

    target = severity.casefold()

    return [
        record
        for record in analysis.capabilities.values()
        if record.severity.casefold() == target
    ]


def high_risk_capabilities(
    analysis: VBACapabilityAnalysis,
) -> list[CapabilityRecord]:
    """Return capabilities classified with high static severity."""

    return capabilities_by_severity(
        analysis,
        "high",
    )


def present_combinations(
    analysis: VBACapabilityAnalysis,
) -> list[CapabilityCombination]:
    """Return only capability combinations that are present."""

    return [combination for combination in analysis.combinations if combination.present]


def get_evidence(
    analysis: VBACapabilityAnalysis,
    capability: Optional[str] = None,
) -> list[CapabilityEvidence]:
    """Return evidence, optionally filtered by capability."""

    if capability is None:
        return list(analysis.evidence)

    target = capability.casefold()

    return [
        evidence
        for evidence in analysis.evidence
        if evidence.capability.casefold() == target
    ]


# ---------------------------------------------------------------------------
# Schema / serialization
# ---------------------------------------------------------------------------


def capability_feature_names() -> list[str]:
    """
    Return the stable capability feature schema.

    Combination names are derived from the static combination taxonomy.
    """

    names: list[str] = []

    for category in CAPABILITY_CATEGORIES:
        names.extend(
            (
                f"vba_cap_{category}",
                f"vba_cap_{category}_count",
                f"vba_cap_{category}_high_confidence",
                f"vba_cap_{category}_high_severity",
            )
        )

    combinations = (
        "download_then_execute",
        "networked_com_automation",
        "filesystem_execution",
        "registry_persistence",
        "process_memory_injection",
        "dynamic_execution",
        "obfuscated_execution",
        "environment_aware_execution",
        "macro_network_execution",
        "credential_collection",
        "service_persistence",
    )

    names.extend(f"vba_cap_combo_{name}" for name in combinations)

    names.extend(
        (
            "vba_capability_count",
            "vba_capability_evidence_count",
            "vba_capability_high_severity_count",
            "vba_capability_medium_severity_count",
            "vba_capability_high_confidence_count",
            "vba_cap_active_payload_chain",
            "vba_cap_persistence_chain",
            "vba_cap_injection_chain",
            "vba_cap_dynamic_execution_chain",
            "vba_cap_obfuscated_execution_chain",
            "vba_cap_macro_network_execution_chain",
            "vba_cap_environment_aware_execution_chain",
            "vba_capability_signal_score",
        )
    )

    return names


def build_feature_schema() -> dict[str, str]:
    """Return feature names and primitive types."""

    schema: dict[str, str] = {}

    for name in capability_feature_names():
        schema[name] = "float" if name == "vba_capability_signal_score" else "int"

    return schema


def analysis_to_dict(
    analysis: VBACapabilityAnalysis,
    *,
    include_evidence: bool = True,
) -> dict[str, Any]:
    """Convert capability analysis to JSON-compatible primitives."""

    capabilities: dict[str, Any] = {}

    for name, record in analysis.capabilities.items():
        item = asdict(record)

        if not include_evidence:
            item["evidence"] = []

        capabilities[name] = item

    result = {
        "capabilities": capabilities,
        "combinations": [asdict(item) for item in analysis.combinations],
        "feature_vector": dict(analysis.feature_vector),
        "metadata": dict(analysis.metadata),
    }

    if include_evidence:
        result["evidence"] = [asdict(item) for item in analysis.evidence]

    return result


def summarize_capabilities(
    analysis: VBACapabilityAnalysis,
) -> dict[str, Any]:
    """Return a compact capability summary for reports."""

    return {
        "capabilities": capability_names(analysis),
        "high_severity": [record.name for record in high_risk_capabilities(analysis)],
        "present_combinations": [
            combination.name for combination in present_combinations(analysis)
        ],
        "capability_count": len(capability_names(analysis)),
        "evidence_count": len(analysis.evidence),
        "signal_score": analysis.feature_vector.get(
            "vba_capability_signal_score",
            0.0,
        ),
    }


# ---------------------------------------------------------------------------
# Batch helpers
# ---------------------------------------------------------------------------


def iter_capability_analyses(
    analyses: Iterable[Any],
) -> Iterator[VBACapabilityAnalysis]:
    """Analyze multiple parsed VBA objects."""

    for analysis in analyses:
        yield analyze_capabilities(analysis)


# ---------------------------------------------------------------------------
# Public exports
# ---------------------------------------------------------------------------

__all__ = [
    "MAX_SOURCE_SIZE",
    "MAX_EVIDENCE",
    "MAX_CAPABILITIES",
    "CAPABILITY_CATEGORIES",
    "API_CAPABILITIES",
    "LIBRARY_CAPABILITIES",
    "SOURCE_CAPABILITY_PATTERNS",
    "CapabilityEvidence",
    "CapabilityRecord",
    "CapabilityCombination",
    "VBACapabilityAnalysis",
    "normalize_api_name",
    "normalize_library_name",
    "api_capabilities",
    "library_capabilities",
    "derive_api_capabilities",
    "derive_source_capabilities",
    "derive_string_capabilities",
    "derive_capability_combinations",
    "build_feature_vector",
    "analyze_capabilities",
    "extract_capabilities",
    "derive_capabilities",
    "extract_capability_features",
    "extract_feature_vector",
    "has_capability",
    "capability_count",
    "capability_names",
    "capabilities_by_severity",
    "high_risk_capabilities",
    "present_combinations",
    "get_evidence",
    "capability_feature_names",
    "build_feature_schema",
    "analysis_to_dict",
    "summarize_capabilities",
    "iter_capability_analyses",
]
