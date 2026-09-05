"""
Static VBA parser for Pharos CDR.

This module parses VBA source code into structured, analysis-friendly records.
It performs lexical and syntactic inspection only.

Security properties
-------------------
- Never executes VBA.
- Never invokes Windows APIs.
- Never evaluates VBA expressions.
- Never launches processes.
- Never resolves or downloads external resources.
- Applies bounded input sizes and record limits.
- Preserves source evidence where useful for downstream analysis.

The parser intentionally does not attempt to be a complete VBA compiler.
Its goal is defensive malware/document analysis: identify modules,
procedures, declarations, statements, literals, calls, control-flow constructs,
and suspicious language constructs while retaining enough context for
downstream feature extraction.

Typical flow
------------
    Office/OLE extraction
          |
          v
    VBA source
          |
          v
    parse_vba()
          |
          +--> modules / procedures
          +--> declarations
          +--> statements
          +--> calls
          +--> strings
          +--> identifiers
          +--> control-flow evidence
          +--> suspicious language indicators
          |
          +--> api_features.py
          +--> capabilities.py
          +--> execution.py
          +--> obfuscation.py
          +--> feature_pipeline.py
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import asdict, dataclass, field
from typing import Any, Iterable, Iterator, Mapping, Optional, Sequence

# ---------------------------------------------------------------------------
# Safety limits
# ---------------------------------------------------------------------------

MAX_SOURCE_SIZE = 25 * 1024 * 1024
MAX_LINES = 500_000
MAX_MODULES = 10_000
MAX_PROCEDURES = 100_000
MAX_STATEMENTS = 500_000
MAX_CALLS = 250_000
MAX_STRINGS = 100_000
MAX_IDENTIFIERS = 250_000
MAX_EVIDENCE = 100_000

MAX_STRING_LENGTH = 1_000_000
MAX_IDENTIFIER_LENGTH = 512


# ---------------------------------------------------------------------------
# Regular expressions
# ---------------------------------------------------------------------------

ATTRIBUTE_RE = re.compile(
    r"^\s*Attribute\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)" r"\s+(?P<value>.+?)\s*$",
    re.IGNORECASE,
)

OPTION_RE = re.compile(
    r"^\s*Option\s+(?P<option>[A-Za-z_][A-Za-z0-9_]*)(?:\s+(?P<value>.*))?$",
    re.IGNORECASE,
)

MODULE_HEADER_RE = re.compile(
    r"^\s*(?:Attribute\s+VB_)?(?:Name|VB_Name)\s*=\s*(?P<name>.+?)\s*$",
    re.IGNORECASE,
)

PROCEDURE_RE = re.compile(
    r"^\s*"
    r"(?:(?:Public|Private|Friend|Static|Global|Protected)\s+)*"
    r"(?P<kind>Sub|Function|Property\s+(?:Get|Let|Set))"
    r"\s+"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_\.]*)"
    r"(?P<args>\s*\([^)]*\))?"
    r"(?:\s+As\s+(?P<return_type>[A-Za-z_][A-Za-z0-9_\.]*(?:\([^)]*\))?))?"
    r"\s*$",
    re.IGNORECASE,
)

END_PROCEDURE_RE = re.compile(
    r"^\s*End\s+(?:Sub|Function|Property)\b",
    re.IGNORECASE,
)

DECLARE_RE = re.compile(
    r"^\s*"
    r"(?:(?:Public|Private|Friend|Global|Static)\s+)*"
    r"Declare\s+"
    r"(?P<kind>PtrSafe\s+)?"
    r"(?P<procedure>Function|Sub)\s+"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)"
    r"(?:\s+Lib\s+"
    r"(?P<library>\"[^\"]*\"|[A-Za-z_][A-Za-z0-9_\.]*))?"
    r"(?:\s+Alias\s+"
    r"(?P<alias>\"[^\"]*\"|[A-Za-z_][A-Za-z0-9_]*))?"
    r"(?P<args>\s*\([^)]*\))?"
    r"(?:\s+As\s+(?P<return_type>.+?))?"
    r"\s*$",
    re.IGNORECASE,
)

CONST_RE = re.compile(
    r"^\s*(?:(?:Public|Private|Friend|Global)\s+)?"
    r"Const\s+"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)"
    r"(?:\s+As\s+(?P<type>[A-Za-z_][A-Za-z0-9_\.]*))?"
    r"\s*=\s*(?P<value>.+?)\s*$",
    re.IGNORECASE,
)

DIM_RE = re.compile(
    r"^\s*(?:(?:Public|Private|Friend|Global|Static)\s+)?"
    r"(?:Dim|ReDim)\s+(?P<body>.+?)\s*$",
    re.IGNORECASE,
)

SET_RE = re.compile(
    r"^\s*Set\s+(?P<target>[A-Za-z_][A-Za-z0-9_\.]*)" r"\s*=\s*(?P<expression>.+?)\s*$",
    re.IGNORECASE,
)

ASSIGNMENT_RE = re.compile(
    r"^\s*(?P<target>[A-Za-z_][A-Za-z0-9_\.\(\)]*)" r"\s*=\s*(?P<expression>.+?)\s*$"
)

LABEL_RE = re.compile(r"^\s*(?P<label>[A-Za-z_][A-Za-z0-9_]*|\d+)\s*:\s*$")

GOTO_RE = re.compile(
    r"\b(?:GoTo|GoSub|Resume\s+Next|Resume)\b"
    r"(?:\s+(?P<target>[A-Za-z_][A-Za-z0-9_]*|\d+))?",
    re.IGNORECASE,
)

ON_ERROR_RE = re.compile(
    r"\bOn\s+Error\s+"
    r"(?P<mode>GoTo\s+0|GoTo\s+-1|GoTo\s+Resume\s+Next|GoTo\s+[A-Za-z_][A-Za-z0-9_]*|Resume\s+Next)"
    r"\b",
    re.IGNORECASE,
)

CALL_RE = re.compile(
    r"(?<![A-Za-z0-9_])"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_\.]*)"
    r"\s*(?P<args>\([^()\r\n]*\))?",
    re.IGNORECASE,
)

STRING_RE = re.compile(
    r'"(?:[^"]|"")*"',
    re.DOTALL,
)

HEX_LITERAL_RE = re.compile(
    r"(?<![A-Za-z0-9_])&H[0-9A-Fa-f]+[&%!#@]?",
)

OCTAL_LITERAL_RE = re.compile(
    r"(?<![A-Za-z0-9_])&O[0-7]+[&%!#@]?",
)

NUMBER_RE = re.compile(
    r"(?<![A-Za-z0-9_])"
    r"(?:"
    r"\d+(?:\.\d+)?(?:[Ee][+-]?\d+)?"
    r"|&H[0-9A-Fa-f]+"
    r"|&O[0-7]+"
    r")"
    r"[&%#!@]?"
    r"(?![A-Za-z0-9_])"
)

IDENTIFIER_RE = re.compile(
    r"(?<![A-Za-z0-9_])" r"[A-Za-z_][A-Za-z0-9_]*" r"(?![A-Za-z0-9_])"
)

URL_RE = re.compile(
    r"\b(?:https?|ftp)://[^\s\"'<>]+",
    re.IGNORECASE,
)

WINDOWS_PATH_RE = re.compile(
    r"(?:[A-Za-z]:\\|\\\\)[^\"'\r\n]+",
)

UNC_PATH_RE = re.compile(
    r"\\\\[A-Za-z0-9_.-]+\\[^\"'\r\n]+",
)

IPV4_RE = re.compile(r"(?<![\d.])" r"(?:\d{1,3}\.){3}\d{1,3}" r"(?![\d.])")

BASE64_LIKE_RE = re.compile(
    r"(?<![A-Za-z0-9+/=])" r"[A-Za-z0-9+/]{40,}={0,2}" r"(?![A-Za-z0-9+/=])"
)

EXECUTION_KEYWORD_RE = re.compile(
    r"\b(?:Shell|CreateObject|GetObject|CallByName|Application\.Run|"
    r"Execute|ExecuteGlobal|Eval|WScript\.Shell|MacScript|FollowHyperlink)\b",
    re.IGNORECASE,
)

DYNAMIC_CODE_RE = re.compile(
    r"\b(?:Execute|ExecuteGlobal|Eval|CallByName|Application\.Run)\b",
    re.IGNORECASE,
)

COM_RE = re.compile(
    r"\b(?:CreateObject|GetObject)\s*\(",
    re.IGNORECASE,
)

SHELL_RE = re.compile(
    r"\b(?:Shell|WScript\.Shell)\b",
    re.IGNORECASE,
)

FILE_IO_RE = re.compile(
    r"\b(?:Open|Close|Print|Write|Put|Get|Kill|Name|FileCopy|"
    r"Dir|MkDir|RmDir|ChDir|ChDrive|FileLen|LOF|EOF)\b",
    re.IGNORECASE,
)

REGISTRY_RE = re.compile(
    r"\b(?:RegOpenKey|RegCreateKey|RegSetValue|RegQueryValue|"
    r"RegDeleteKey|RegDeleteValue|SaveSetting|GetSetting|"
    r"DeleteSetting)\b",
    re.IGNORECASE,
)

NETWORK_RE = re.compile(
    r"\b(?:WinHttp|XMLHTTP|MSXML|InternetOpen|InternetOpenUrl|"
    r"URLDownloadToFile|WinInet|ADODB\.Stream|ServerXMLHTTP)\b",
    re.IGNORECASE,
)

MACRO_RE = re.compile(
    r"\b(?:Application\.Run|RunAutoMacros|AutoOpen|AutoClose|"
    r"AutoExec|AutoExit|Document_Open|Document_Close|Workbook_Open|"
    r"Workbook_BeforeClose)\b",
    re.IGNORECASE,
)

OBFUSCATION_RE = re.compile(
    r"\b(?:Chr|ChrW|ChrB|Asc|AscW|StrReverse|Replace|"
    r"Mid|Left|Right|Split|Join|Hex|Oct|Val)\b",
    re.IGNORECASE,
)

ENVIRONMENT_RE = re.compile(
    r"\b(?:Environ|Application\.OperatingSystem|Application\.Version|" r"Command)\b",
    re.IGNORECASE,
)

ERROR_SUPPRESSION_RE = re.compile(
    r"\bOn\s+Error\s+Resume\s+Next\b",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# VBA keyword sets
# ---------------------------------------------------------------------------

VBA_KEYWORDS = frozenset(
    {
        "addressof",
        "alias",
        "and",
        "array",
        "as",
        "attribute",
        "base",
        "boolean",
        "byref",
        "byte",
        "byval",
        "call",
        "case",
        "cdbl",
        "cbool",
        "cbyte",
        "ccur",
        "cdate",
        "cdec",
        "cint",
        "clng",
        "close",
        "const",
        "csng",
        "cstr",
        "currency",
        "date",
        "debug",
        "decimal",
        "declare",
        "defbool",
        "defbyte",
        "defcur",
        "defdate",
        "defdec",
        "defint",
        "deflng",
        "defobj",
        "defsng",
        "defstr",
        "defvar",
        "dim",
        "do",
        "double",
        "each",
        "else",
        "elseif",
        "empty",
        "end",
        "enum",
        "eqv",
        "erase",
        "error",
        "event",
        "exit",
        "explicit",
        "false",
        "for",
        "friend",
        "function",
        "get",
        "global",
        "gosub",
        "goto",
        "if",
        "imp",
        "implements",
        "in",
        "input",
        "integer",
        "is",
        "let",
        "lib",
        "like",
        "line",
        "load",
        "lock",
        "long",
        "loop",
        "lset",
        "me",
        "mod",
        "module",
        "new",
        "next",
        "not",
        "nothing",
        "null",
        "object",
        "on",
        "open",
        "option",
        "or",
        "paramarray",
        "preserve",
        "private",
        "property",
        "public",
        "put",
        "raiseevent",
        "randomize",
        "redim",
        "rem",
        "reset",
        "resume",
        "rset",
        "select",
        "set",
        "single",
        "static",
        "step",
        "stop",
        "string",
        "sub",
        "then",
        "to",
        "true",
        "type",
        "typeof",
        "variant",
        "wend",
        "while",
        "with",
        "xor",
    }
)


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class VBASource:
    """Normalized VBA source container."""

    text: str
    encoding: str = "utf-8"
    source_name: Optional[str] = None
    sha256: str = ""


@dataclass
class VBAAttribute:
    """Module-level VBA attribute."""

    name: str
    value: str
    line_number: int
    raw: str


@dataclass
class VBAOption:
    """VBA Option statement."""

    name: str
    value: Optional[str]
    line_number: int
    raw: str


@dataclass
class VBADeclaration:
    """Variable, constant, or API declaration."""

    name: str
    declaration_type: str
    data_type: Optional[str]
    value: Optional[str]
    line_number: int
    raw: str
    scope: Optional[str] = None


@dataclass
class VBAAPIDeclaration:
    """External Windows/API declaration."""

    name: str
    library: Optional[str]
    alias: Optional[str]
    kind: str
    ptrsafe: bool
    line_number: int
    raw: str
    arguments: Optional[str] = None
    return_type: Optional[str] = None

    @property
    def normalized_name(self) -> str:
        return self.alias or self.name


@dataclass
class VBAProcedure:
    """VBA procedure definition."""

    name: str
    kind: str
    line_number: int
    end_line_number: Optional[int]
    arguments: list[str] = field(default_factory=list)
    return_type: Optional[str] = None
    visibility: Optional[str] = None
    is_static: bool = False
    source: str = ""


@dataclass
class VBAStatement:
    """Single normalized VBA statement."""

    line_number: int
    text: str
    statement_type: str
    procedure: Optional[str] = None
    indentation: int = 0
    continuation: bool = False


@dataclass
class VBACall:
    """Potential procedure/function call."""

    name: str
    line_number: int
    procedure: Optional[str]
    arguments: Optional[str]
    source: str
    qualified: bool = False


@dataclass
class VBAStringLiteral:
    """String literal extracted from VBA."""

    value: str
    line_number: int
    procedure: Optional[str]
    raw: str
    length: int
    is_long: bool
    urls: list[str] = field(default_factory=list)
    paths: list[str] = field(default_factory=list)
    ipv4_addresses: list[str] = field(default_factory=list)
    base64_like: bool = False


@dataclass
class VBAControlFlow:
    """Control-flow construct."""

    kind: str
    line_number: int
    procedure: Optional[str]
    target: Optional[str]
    raw: str


@dataclass
class VBAIndicator:
    """Static suspicious-language indicator."""

    category: str
    indicator: str
    line_number: int
    procedure: Optional[str]
    evidence: str
    severity: str = "medium"


@dataclass
class VBAParseStatistics:
    """Aggregate parser statistics."""

    source_size: int = 0
    line_count: int = 0
    module_count: int = 0
    procedure_count: int = 0
    declaration_count: int = 0
    api_declaration_count: int = 0
    statement_count: int = 0
    call_count: int = 0
    string_count: int = 0
    identifier_count: int = 0
    attribute_count: int = 0
    option_count: int = 0
    control_flow_count: int = 0
    indicator_count: int = 0
    comment_line_count: int = 0
    blank_line_count: int = 0
    continuation_line_count: int = 0
    long_string_count: int = 0
    url_count: int = 0
    path_count: int = 0
    ipv4_count: int = 0


@dataclass
class VBAAnalysis:
    """Complete static VBA parsing result."""

    source: VBASource
    modules: list[str] = field(default_factory=list)
    attributes: list[VBAAttribute] = field(default_factory=list)
    options: list[VBAOption] = field(default_factory=list)
    declarations: list[VBADeclaration] = field(default_factory=list)
    api_declarations: list[VBAAPIDeclaration] = field(default_factory=list)
    procedures: list[VBAProcedure] = field(default_factory=list)
    statements: list[VBAStatement] = field(default_factory=list)
    calls: list[VBACall] = field(default_factory=list)
    strings: list[VBAStringLiteral] = field(default_factory=list)
    identifiers: list[str] = field(default_factory=list)
    control_flow: list[VBAControlFlow] = field(default_factory=list)
    indicators: list[VBAIndicator] = field(default_factory=list)
    statistics: VBAParseStatistics = field(default_factory=VBAParseStatistics)
    feature_vector: dict[str, int | float] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Source normalization
# ---------------------------------------------------------------------------


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def normalize_vba_source(source: str | bytes) -> VBASource:
    """
    Normalize VBA source into a bounded UTF-8 string.

    Bytes are decoded conservatively. No external codec or execution is used.
    """

    if isinstance(source, bytes):
        if len(source) > MAX_SOURCE_SIZE:
            raise ValueError(
                f"VBA source exceeds maximum size of {MAX_SOURCE_SIZE} bytes"
            )

        encoding = "utf-8"

        if source.startswith(b"\xff\xfe"):
            encoding = "utf-16-le"
        elif source.startswith(b"\xfe\xff"):
            encoding = "utf-16-be"

        try:
            text = source.decode(encoding, errors="replace")
        except LookupError:
            text = source.decode("utf-8", errors="replace")
            encoding = "utf-8"
    elif isinstance(source, str):
        if len(source.encode("utf-8", errors="replace")) > MAX_SOURCE_SIZE:
            raise ValueError(
                f"VBA source exceeds maximum size of {MAX_SOURCE_SIZE} bytes"
            )
        text = source
        encoding = "utf-8"
    else:
        raise TypeError("source must be str or bytes")

    # Normalize common VBA line endings.
    text = text.replace("\r\n", "\n").replace("\r", "\n")

    return VBASource(
        text=text,
        encoding=encoding,
        sha256=_sha256_text(text),
    )


def split_vba_lines(source: str) -> list[str]:
    """Split source into bounded lines."""

    lines = source.split("\n")

    if len(lines) > MAX_LINES:
        raise ValueError(f"VBA source contains more than {MAX_LINES} lines")

    return lines


# ---------------------------------------------------------------------------
# Comments
# ---------------------------------------------------------------------------


def strip_vba_comment(line: str) -> tuple[str, Optional[str]]:
    """
    Remove a VBA comment while preserving apostrophes inside string literals.

    VBA also permits Rem comments when Rem is the first statement token.
    """

    in_string = False
    index = 0

    while index < len(line):
        char = line[index]

        if char == '"':
            if in_string and index + 1 < len(line) and line[index + 1] == '"':
                index += 2
                continue

            in_string = not in_string
            index += 1
            continue

        if char == "'" and not in_string:
            return line[:index].rstrip(), line[index + 1 :].strip()

        index += 1

    # Handle "Rem ..." outside strings.
    stripped = line.lstrip()
    if not in_string and re.match(r"(?i)^Rem(?:\s|$)", stripped):
        match = re.match(r"(?i)^Rem(?:\s|$)(.*)$", stripped)
        comment = match.group(1).strip() if match else ""
        return "", comment

    return line.rstrip(), None


def strip_vba_comments(source: str) -> str:
    """Return source with VBA comments removed."""

    return "\n".join(strip_vba_comment(line)[0] for line in source.splitlines())


# ---------------------------------------------------------------------------
# Statement splitting
# ---------------------------------------------------------------------------


def split_vba_statements(lines: Sequence[str]) -> Iterator[tuple[int, str, bool]]:
    """
    Yield logical VBA statements.

    VBA line continuation uses an underscore outside a string literal.
    """

    buffer = ""
    first_line = 1
    continued = False

    for line_number, raw_line in enumerate(lines, start=1):
        code, _comment = strip_vba_comment(raw_line)

        if not code.strip():
            if buffer:
                yield first_line, buffer.strip(), continued
                buffer = ""
                continued = False
            continue

        stripped = code.rstrip()

        # Detect continuation underscore outside a string.
        continuation = _has_trailing_continuation(stripped)

        if not buffer:
            first_line = line_number
            buffer = _remove_trailing_continuation(stripped)
        else:
            fragment = _remove_trailing_continuation(stripped).strip()
            buffer = f"{buffer} {fragment}".strip()

        if continuation:
            continued = True
            continue

        yield first_line, buffer.strip(), continued
        buffer = ""
        continued = False

    if buffer:
        yield first_line, buffer.strip(), continued


def _has_trailing_continuation(line: str) -> bool:
    in_string = False
    last_non_space = -1

    for index, char in enumerate(line):
        if char == '"':
            if in_string and index + 1 < len(line) and line[index + 1] == '"':
                continue
            in_string = not in_string

        if not char.isspace():
            last_non_space = index

    return not in_string and last_non_space >= 0 and line[last_non_space] == "_"


def _remove_trailing_continuation(line: str) -> str:
    stripped = line.rstrip()
    if stripped.endswith("_"):
        return stripped[:-1].rstrip()
    return stripped


# ---------------------------------------------------------------------------
# Procedure parsing
# ---------------------------------------------------------------------------


def _parse_argument_names(argument_text: Optional[str]) -> list[str]:
    if not argument_text:
        return []

    body = argument_text.strip()
    if body.startswith("(") and body.endswith(")"):
        body = body[1:-1]

    if not body.strip():
        return []

    result: list[str] = []

    for item in _split_top_level_commas(body):
        token = item.strip()

        token = re.sub(
            r"^(?:Optional|ByVal|ByRef|ParamArray)\s+",
            "",
            token,
            flags=re.IGNORECASE,
        )

        match = re.match(
            r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)(?:\s*\(\))?",
            token,
            flags=re.IGNORECASE,
        )

        if match:
            result.append(match.group("name"))

    return result


def _split_top_level_commas(text: str) -> list[str]:
    result: list[str] = []
    start = 0
    depth = 0
    in_string = False

    for index, char in enumerate(text):
        if char == '"':
            in_string = not in_string
            continue

        if in_string:
            continue

        if char == "(":
            depth += 1
        elif char == ")":
            depth = max(0, depth - 1)
        elif char == "," and depth == 0:
            result.append(text[start:index])
            start = index + 1

    result.append(text[start:])
    return result


def parse_procedure_header(statement: str) -> Optional[dict[str, Any]]:
    """Parse a Sub/Function/Property declaration."""

    match = PROCEDURE_RE.match(statement)
    if not match:
        return None

    prefix = statement[: match.start("kind")]

    visibility = None
    for candidate in ("Public", "Private", "Friend"):
        if re.search(rf"\b{candidate}\b", prefix, re.IGNORECASE):
            visibility = candidate.lower()
            break

    return {
        "name": match.group("name"),
        "kind": re.sub(r"\s+", " ", match.group("kind")).lower(),
        "arguments": _parse_argument_names(match.group("args")),
        "return_type": match.group("return_type"),
        "visibility": visibility,
        "is_static": bool(re.search(r"\bStatic\b", prefix, re.IGNORECASE)),
    }


# ---------------------------------------------------------------------------
# Module / attribute / option parsing
# ---------------------------------------------------------------------------


def parse_module_name(attributes: Sequence[VBAAttribute]) -> Optional[str]:
    """Extract the canonical VB_Name attribute."""

    for attribute in attributes:
        if attribute.name.casefold() == "vb_name":
            value = attribute.value.strip()

            if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
                return value[1:-1].replace('""', '"')

            return value

    return None


def parse_attributes(lines: Sequence[str]) -> list[VBAAttribute]:
    result: list[VBAAttribute] = []

    for line_number, line in enumerate(lines, start=1):
        if len(result) >= MAX_EVIDENCE:
            break

        match = ATTRIBUTE_RE.match(line)
        if not match:
            continue

        result.append(
            VBAAttribute(
                name=match.group("name"),
                value=match.group("value").strip(),
                line_number=line_number,
                raw=line,
            )
        )

    return result


def parse_options(lines: Sequence[str]) -> list[VBAOption]:
    result: list[VBAOption] = []

    for line_number, line in enumerate(lines, start=1):
        if len(result) >= MAX_EVIDENCE:
            break

        match = OPTION_RE.match(line)
        if not match:
            continue

        result.append(
            VBAOption(
                name=match.group("option"),
                value=match.group("value").strip() if match.group("value") else None,
                line_number=line_number,
                raw=line,
            )
        )

    return result


# ---------------------------------------------------------------------------
# Declarations
# ---------------------------------------------------------------------------


def parse_api_declarations(
    source: str | bytes,
) -> list[VBAAPIDeclaration]:
    """Parse Declare Function/Sub statements."""

    normalized = normalize_vba_source(source)
    result: list[VBAAPIDeclaration] = []

    for line_number, statement, _continued in split_vba_statements(
        split_vba_lines(normalized.text)
    ):
        if len(result) >= MAX_PROCEDURES:
            break

        match = DECLARE_RE.match(statement)
        if not match:
            continue

        library = _unquote(match.group("library"))
        alias = _unquote(match.group("alias"))

        result.append(
            VBAAPIDeclaration(
                name=match.group("name"),
                library=library,
                alias=alias,
                kind=match.group("procedure").lower(),
                ptrsafe=bool(match.group("kind")),
                line_number=line_number,
                raw=statement,
                arguments=match.group("args"),
                return_type=match.group("return_type"),
            )
        )

    return result


def parse_declarations(
    source: str | bytes,
) -> list[VBADeclaration]:
    """Parse Const and Dim/ReDim declarations."""

    normalized = normalize_vba_source(source)
    result: list[VBADeclaration] = []

    current_scope: Optional[str] = None

    for line_number, statement, _continued in split_vba_statements(
        split_vba_lines(normalized.text)
    ):
        procedure = parse_procedure_header(statement)

        if procedure:
            current_scope = procedure["name"]
            continue

        if END_PROCEDURE_RE.match(statement):
            current_scope = None
            continue

        const_match = CONST_RE.match(statement)

        if const_match:
            result.append(
                VBADeclaration(
                    name=const_match.group("name"),
                    declaration_type="const",
                    data_type=const_match.group("type"),
                    value=const_match.group("value"),
                    line_number=line_number,
                    raw=statement,
                    scope=current_scope,
                )
            )
            continue

        dim_match = DIM_RE.match(statement)

        if dim_match:
            body = dim_match.group("body")

            for declaration in _parse_dim_body(
                body,
                line_number=line_number,
                raw=statement,
                scope=current_scope,
            ):
                result.append(declaration)

                if len(result) >= MAX_EVIDENCE:
                    return result

    return result


def _parse_dim_body(
    body: str,
    *,
    line_number: int,
    raw: str,
    scope: Optional[str],
) -> list[VBADeclaration]:
    result: list[VBADeclaration] = []

    for item in _split_top_level_commas(body):
        item = item.strip()

        match = re.match(
            r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)(?:\s*\([^)]*\))?"
            r"(?:\s+As\s+(?P<type>.+?))?$",
            item,
            re.IGNORECASE,
        )

        if not match:
            continue

        result.append(
            VBADeclaration(
                name=match.group("name"),
                declaration_type="dim",
                data_type=match.group("type"),
                value=None,
                line_number=line_number,
                raw=raw,
                scope=scope,
            )
        )

    return result


# ---------------------------------------------------------------------------
# Calls
# ---------------------------------------------------------------------------


def _is_likely_call(
    name: str,
    statement: str,
    declarations: set[str],
) -> bool:
    lower = name.casefold()

    if lower in VBA_KEYWORDS:
        return False

    if lower in {
        "if",
        "then",
        "else",
        "elseif",
        "for",
        "each",
        "next",
        "while",
        "wend",
        "do",
        "loop",
        "select",
        "case",
        "with",
        "end",
        "property",
        "function",
        "sub",
        "const",
        "dim",
        "redim",
        "set",
        "let",
        "on",
        "error",
        "resume",
        "goto",
        "gosub",
        "call",
        "exit",
    }:
        return False

    # A qualified identifier is frequently an object/module method.
    if "." in name:
        return True

    # Explicit Call statement.
    if re.search(
        rf"(?i)\bCall\s+{re.escape(name)}\b",
        statement,
    ):
        return True

    # Declared functions and APIs are useful even without parentheses.
    if lower in declarations:
        return True

    # A function invocation normally has an opening parenthesis.
    pattern = rf"(?i)\b{re.escape(name)}\s*\("
    return bool(re.search(pattern, statement))


def parse_calls(
    source: str | bytes,
    api_declarations: Optional[Sequence[VBAAPIDeclaration]] = None,
) -> list[VBACall]:
    """
    Extract likely procedure/function calls.

    This is deliberately heuristic. It does not attempt semantic execution.
    """

    normalized = normalize_vba_source(source)

    declared = {item.normalized_name.casefold() for item in (api_declarations or [])}

    result: list[VBACall] = []
    current_procedure: Optional[str] = None

    for line_number, statement, _continued in split_vba_statements(
        split_vba_lines(normalized.text)
    ):
        if len(result) >= MAX_CALLS:
            break

        procedure = parse_procedure_header(statement)

        if procedure:
            current_procedure = procedure["name"]
            continue

        if END_PROCEDURE_RE.match(statement):
            current_procedure = None
            continue

        # Skip Declare statements themselves.
        if DECLARE_RE.match(statement):
            continue

        for match in CALL_RE.finditer(statement):
            name = match.group("name")

            if not _is_likely_call(name, statement, declared):
                continue

            result.append(
                VBACall(
                    name=name,
                    line_number=line_number,
                    procedure=current_procedure,
                    arguments=match.group("args"),
                    source=statement,
                    qualified="." in name,
                )
            )

            if len(result) >= MAX_CALLS:
                break

    return result


# ---------------------------------------------------------------------------
# String extraction
# ---------------------------------------------------------------------------


def _decode_vba_string(raw: str) -> str:
    if len(raw) < 2:
        return raw

    body = raw[1:-1]

    # VBA escapes embedded quotes by doubling them.
    return body.replace('""', '"')


def extract_string_literals(
    source: str | bytes,
) -> list[VBAStringLiteral]:
    """Extract VBA string literals without evaluating concatenations."""

    normalized = normalize_vba_source(source)
    result: list[VBAStringLiteral] = []

    current_procedure: Optional[str] = None

    for line_number, statement, _continued in split_vba_statements(
        split_vba_lines(normalized.text)
    ):
        procedure = parse_procedure_header(statement)

        if procedure:
            current_procedure = procedure["name"]
            continue

        if END_PROCEDURE_RE.match(statement):
            current_procedure = None
            continue

        for match in STRING_RE.finditer(statement):
            if len(result) >= MAX_STRINGS:
                return result

            raw = match.group(0)

            if len(raw) > MAX_STRING_LENGTH:
                continue

            value = _decode_vba_string(raw)

            urls = URL_RE.findall(value)
            paths = WINDOWS_PATH_RE.findall(value)
            paths.extend(UNC_PATH_RE.findall(value))
            ips = IPV4_RE.findall(value)

            result.append(
                VBAStringLiteral(
                    value=value,
                    line_number=line_number,
                    procedure=current_procedure,
                    raw=raw,
                    length=len(value),
                    is_long=len(value) >= 256,
                    urls=sorted(set(urls)),
                    paths=sorted(set(paths)),
                    ipv4_addresses=sorted(set(ips)),
                    base64_like=bool(BASE64_LIKE_RE.fullmatch(value.strip())),
                )
            )

    return result


# ---------------------------------------------------------------------------
# Identifier extraction
# ---------------------------------------------------------------------------


def extract_identifiers(
    source: str | bytes,
    *,
    exclude_keywords: bool = True,
) -> list[str]:
    """Extract unique identifiers while preserving first-seen order."""

    normalized = normalize_vba_source(source)
    result: list[str] = []
    seen: set[str] = set()

    code = strip_vba_comments(normalized.text)

    for match in IDENTIFIER_RE.finditer(code):
        identifier = match.group(0)

        if len(identifier) > MAX_IDENTIFIER_LENGTH:
            continue

        key = identifier.casefold()

        if exclude_keywords and key in VBA_KEYWORDS:
            continue

        if key in seen:
            continue

        seen.add(key)
        result.append(identifier)

        if len(result) >= MAX_IDENTIFIERS:
            break

    return result


# ---------------------------------------------------------------------------
# Control flow
# ---------------------------------------------------------------------------


def parse_control_flow(
    source: str | bytes,
) -> list[VBAControlFlow]:
    """Extract static control-flow constructs."""

    normalized = normalize_vba_source(source)
    result: list[VBAControlFlow] = []
    current_procedure: Optional[str] = None

    for line_number, statement, _continued in split_vba_statements(
        split_vba_lines(normalized.text)
    ):
        procedure = parse_procedure_header(statement)

        if procedure:
            current_procedure = procedure["name"]
            continue

        if END_PROCEDURE_RE.match(statement):
            current_procedure = None
            continue

        lower = statement.casefold()

        if re.search(r"\bif\b", lower):
            result.append(
                VBAControlFlow(
                    kind="if",
                    line_number=line_number,
                    procedure=current_procedure,
                    target=None,
                    raw=statement,
                )
            )

        if re.search(r"\bfor\b", lower):
            result.append(
                VBAControlFlow(
                    kind="for",
                    line_number=line_number,
                    procedure=current_procedure,
                    target=None,
                    raw=statement,
                )
            )

        if re.search(r"\bdo\b", lower):
            result.append(
                VBAControlFlow(
                    kind="do",
                    line_number=line_number,
                    procedure=current_procedure,
                    target=None,
                    raw=statement,
                )
            )

        if re.search(r"\bwhile\b", lower):
            result.append(
                VBAControlFlow(
                    kind="while",
                    line_number=line_number,
                    procedure=current_procedure,
                    target=None,
                    raw=statement,
                )
            )

        if re.search(r"\bselect\s+case\b", lower):
            result.append(
                VBAControlFlow(
                    kind="select_case",
                    line_number=line_number,
                    procedure=current_procedure,
                    target=None,
                    raw=statement,
                )
            )

        goto_match = GOTO_RE.search(statement)

        if goto_match:
            result.append(
                VBAControlFlow(
                    kind="goto",
                    line_number=line_number,
                    procedure=current_procedure,
                    target=goto_match.group("target"),
                    raw=statement,
                )
            )

        error_match = ON_ERROR_RE.search(statement)

        if error_match:
            result.append(
                VBAControlFlow(
                    kind="error_handler",
                    line_number=line_number,
                    procedure=current_procedure,
                    target=error_match.group("mode"),
                    raw=statement,
                )
            )

        label_match = LABEL_RE.match(statement)

        if label_match:
            result.append(
                VBAControlFlow(
                    kind="label",
                    line_number=line_number,
                    procedure=current_procedure,
                    target=label_match.group("label"),
                    raw=statement,
                )
            )

        if len(result) >= MAX_EVIDENCE:
            break

    return result


# ---------------------------------------------------------------------------
# Statement classification
# ---------------------------------------------------------------------------


def classify_statement(statement: str) -> str:
    """Classify a VBA statement into a coarse static category."""

    stripped = statement.strip()

    if not stripped:
        return "empty"

    if ATTRIBUTE_RE.match(stripped):
        return "attribute"

    if OPTION_RE.match(stripped):
        return "option"

    if DECLARE_RE.match(stripped):
        return "api_declaration"

    if PROCEDURE_RE.match(stripped):
        return "procedure"

    if END_PROCEDURE_RE.match(stripped):
        return "procedure_end"

    if CONST_RE.match(stripped):
        return "constant_declaration"

    if DIM_RE.match(stripped):
        return "variable_declaration"

    if SET_RE.match(stripped):
        return "object_assignment"

    if GOTO_RE.search(stripped):
        return "control_flow"

    if ON_ERROR_RE.search(stripped):
        return "error_handling"

    if re.match(r"(?i)^\s*(If|ElseIf|Else)\b", stripped):
        return "conditional"

    if re.match(r"(?i)^\s*(For|For Each|Next)\b", stripped):
        return "loop"

    if re.match(r"(?i)^\s*(Do|Loop|While|Wend)\b", stripped):
        return "loop"

    if re.match(r"(?i)^\s*(Select Case|Case)\b", stripped):
        return "selection"

    if re.match(r"(?i)^\s*(With|End With)\b", stripped):
        return "object_scope"

    if re.match(r"(?i)^\s*(Call)\b", stripped):
        return "call"

    if re.match(r"(?i)^\s*(Exit|Stop|End)\b", stripped):
        return "termination"

    if ASSIGNMENT_RE.match(stripped):
        return "assignment"

    if EXECUTION_KEYWORD_RE.search(stripped):
        return "execution"

    if NETWORK_RE.search(stripped):
        return "network"

    if REGISTRY_RE.search(stripped):
        return "registry"

    if FILE_IO_RE.search(stripped):
        return "filesystem"

    return "expression"


def parse_statements(
    source: str | bytes,
) -> list[VBAStatement]:
    """Parse source into logical statements."""

    normalized = normalize_vba_source(source)
    lines = split_vba_lines(normalized.text)

    result: list[VBAStatement] = []
    current_procedure: Optional[str] = None

    for line_number, statement, continuation in split_vba_statements(lines):
        if len(result) >= MAX_STATEMENTS:
            break

        procedure = parse_procedure_header(statement)

        if procedure:
            current_procedure = procedure["name"]

        statement_type = classify_statement(statement)

        result.append(
            VBAStatement(
                line_number=line_number,
                text=statement,
                statement_type=statement_type,
                procedure=current_procedure,
                indentation=len(statement) - len(statement.lstrip()),
                continuation=continuation,
            )
        )

        if END_PROCEDURE_RE.match(statement):
            current_procedure = None

    return result


# ---------------------------------------------------------------------------
# Indicator extraction
# ---------------------------------------------------------------------------


def _indicator(
    result: list[VBAIndicator],
    *,
    category: str,
    indicator: str,
    line_number: int,
    procedure: Optional[str],
    evidence: str,
    severity: str = "medium",
) -> None:
    if len(result) >= MAX_EVIDENCE:
        return

    result.append(
        VBAIndicator(
            category=category,
            indicator=indicator,
            line_number=line_number,
            procedure=procedure,
            evidence=evidence[:2048],
            severity=severity,
        )
    )


def derive_indicators(
    source: str | bytes,
) -> list[VBAIndicator]:
    """
    Derive static semantic indicators.

    Indicators describe language constructs and references; they do not
    assert that a document is malicious by themselves.
    """

    normalized = normalize_vba_source(source)
    result: list[VBAIndicator] = []

    current_procedure: Optional[str] = None

    for line_number, statement, _continued in split_vba_statements(
        split_vba_lines(normalized.text)
    ):
        procedure = parse_procedure_header(statement)

        if procedure:
            current_procedure = procedure["name"]
            continue

        if END_PROCEDURE_RE.match(statement):
            current_procedure = None
            continue

        checks = (
            (
                "execution",
                "shell",
                SHELL_RE,
                "high",
            ),
            (
                "execution",
                "dynamic_code",
                DYNAMIC_CODE_RE,
                "high",
            ),
            (
                "automation",
                "com_object_creation",
                COM_RE,
                "high",
            ),
            (
                "network",
                "network_reference",
                NETWORK_RE,
                "medium",
            ),
            (
                "filesystem",
                "file_io",
                FILE_IO_RE,
                "low",
            ),
            (
                "registry",
                "registry_access",
                REGISTRY_RE,
                "medium",
            ),
            (
                "macro",
                "macro_execution",
                MACRO_RE,
                "high",
            ),
            (
                "obfuscation",
                "string_manipulation",
                OBFUSCATION_RE,
                "low",
            ),
            (
                "environment",
                "environment_discovery",
                ENVIRONMENT_RE,
                "low",
            ),
            (
                "evasion",
                "error_suppression",
                ERROR_SUPPRESSION_RE,
                "medium",
            ),
        )

        for category, name, regex, severity in checks:
            if regex.search(statement):
                _indicator(
                    result,
                    category=category,
                    indicator=name,
                    line_number=line_number,
                    procedure=current_procedure,
                    evidence=statement,
                    severity=severity,
                )

    return result


# ---------------------------------------------------------------------------
# Feature extraction
# ---------------------------------------------------------------------------


def _count_matching_indicators(
    indicators: Sequence[VBAIndicator],
    category: str,
) -> int:
    return sum(
        1 for item in indicators if item.category.casefold() == category.casefold()
    )


def build_feature_vector(
    analysis: VBAAnalysis,
) -> dict[str, int | float]:
    """Build stable scalar features from a parsed VBA analysis."""

    stats = analysis.statistics
    indicators = analysis.indicators

    unique_calls = {call.name.casefold() for call in analysis.calls}

    unique_identifiers = {identifier.casefold() for identifier in analysis.identifiers}

    api_names = {
        declaration.normalized_name.casefold()
        for declaration in analysis.api_declarations
    }

    libraries = {
        declaration.library.casefold()
        for declaration in analysis.api_declarations
        if declaration.library
    }

    option_names = {option.name.casefold() for option in analysis.options}

    control_flow_kinds = {item.kind.casefold() for item in analysis.control_flow}

    feature_vector: dict[str, int | float] = {
        "vba_source_size": stats.source_size,
        "vba_line_count": stats.line_count,
        "vba_module_count": stats.module_count,
        "vba_procedure_count": stats.procedure_count,
        "vba_declaration_count": stats.declaration_count,
        "vba_api_declaration_count": stats.api_declaration_count,
        "vba_statement_count": stats.statement_count,
        "vba_call_count": stats.call_count,
        "vba_unique_call_count": len(unique_calls),
        "vba_string_count": stats.string_count,
        "vba_identifier_count": stats.identifier_count,
        "vba_unique_identifier_count": len(unique_identifiers),
        "vba_control_flow_count": stats.control_flow_count,
        "vba_indicator_count": stats.indicator_count,
        "vba_comment_line_count": stats.comment_line_count,
        "vba_blank_line_count": stats.blank_line_count,
        "vba_continuation_line_count": stats.continuation_line_count,
        "vba_long_string_count": stats.long_string_count,
        "vba_url_count": stats.url_count,
        "vba_path_count": stats.path_count,
        "vba_ipv4_count": stats.ipv4_count,
        "vba_api_unique_count": len(api_names),
        "vba_api_library_count": len(libraries),
        "vba_has_option_explicit": int("explicit" in option_names),
        "vba_has_option_base": int("base" in option_names),
        "vba_has_goto": int("goto" in control_flow_kinds),
        "vba_has_error_handler": int("error_handler" in control_flow_kinds),
        "vba_has_dynamic_code": int(
            _count_matching_indicators(indicators, "execution") > 0
        ),
        "vba_has_network_reference": int(
            _count_matching_indicators(indicators, "network") > 0
        ),
        "vba_has_registry_reference": int(
            _count_matching_indicators(indicators, "registry") > 0
        ),
        "vba_has_com_creation": int(
            any(item.indicator == "com_object_creation" for item in indicators)
        ),
        "vba_has_shell_reference": int(
            any(item.indicator == "shell" for item in indicators)
        ),
        "vba_has_macro_execution": int(
            any(item.indicator == "macro_execution" for item in indicators)
        ),
        "vba_has_error_suppression": int(
            any(item.indicator == "error_suppression" for item in indicators)
        ),
        "vba_ptrsafe_api_count": sum(
            1 for item in analysis.api_declarations if item.ptrsafe
        ),
        "vba_api_alias_count": sum(
            1 for item in analysis.api_declarations if item.alias
        ),
    }

    # Library-family indicators.
    library_families = {
        "kernel32": (
            "kernel32",
            "kernelbase",
        ),
        "user32": ("user32",),
        "advapi32": ("advapi32",),
        "ole32": ("ole32",),
        "oleaut32": ("oleaut32",),
        "wininet": ("wininet",),
        "winhttp": ("winhttp",),
        "shell32": ("shell32",),
        "urlmon": ("urlmon",),
        "crypt32": ("crypt32",),
    }

    for family, names in library_families.items():
        feature_vector[f"vba_api_library_{family}"] = int(
            any(any(name in library for name in names) for library in libraries)
        )

    # High-value API indicators.
    high_value_apis = {
        "createprocess": "process_creation",
        "createprocessa": "process_creation",
        "createprocessw": "process_creation",
        "winexec": "process_creation",
        "shellexecute": "shell_execution",
        "shellexecutea": "shell_execution",
        "shellexecutew": "shell_execution",
        "virtualalloc": "memory_allocation",
        "virtualallocex": "remote_memory_allocation",
        "virtualprotect": "memory_protection",
        "virtualprotectex": "remote_memory_protection",
        "writeprocessmemory": "remote_memory_write",
        "createremotethread": "remote_thread",
        "openprocess": "process_access",
        "getprocaddress": "dynamic_api_resolution",
        "loadlibrary": "dynamic_library_loading",
        "loadlibrarya": "dynamic_library_loading",
        "loadlibraryw": "dynamic_library_loading",
        "regopenkey": "registry_access",
        "regcreatekey": "registry_modification",
        "regsetvalue": "registry_modification",
        "urldownloadtofile": "download",
        "internetopenurl": "network_download",
        "winhttpopen": "network",
        "winhttpconnect": "network",
        "winhttpsendrequest": "network",
        "openclipboard": "clipboard",
        "getclipboarddata": "clipboard",
        "openprocessToken": "token_access",
        "openprocesstoken": "token_access",
        "adjusttokenprivileges": "token_privilege",
    }

    normalized_api_names = {name.casefold() for name in api_names}

    for api_name, feature_name in high_value_apis.items():
        feature_vector[f"vba_api_{feature_name}"] = int(
            api_name.casefold() in normalized_api_names
        )

    # Derived combinations.
    feature_vector["vba_remote_memory_execution_chain"] = int(
        bool(
            feature_vector.get("vba_api_remote_memory_allocation", 0)
            and feature_vector.get("vba_api_remote_memory_write", 0)
            and feature_vector.get("vba_api_remote_thread", 0)
        )
    )

    feature_vector["vba_dynamic_api_loading_chain"] = int(
        bool(
            feature_vector.get("vba_api_dynamic_api_resolution", 0)
            and feature_vector.get("vba_api_dynamic_library_loading", 0)
        )
    )

    feature_vector["vba_download_execution_signal"] = int(
        bool(
            feature_vector.get("vba_api_download", 0)
            and (
                feature_vector.get("vba_api_process_creation", 0)
                or feature_vector.get("vba_api_shell_execution", 0)
                or feature_vector.get("vba_has_shell_reference", 0)
            )
        )
    )

    feature_vector["vba_registry_persistence_signal"] = int(
        bool(
            feature_vector.get("vba_api_registry_modification", 0)
            and (
                feature_vector.get("vba_has_macro_execution", 0)
                or feature_vector.get("vba_procedure_count", 0) > 0
            )
        )
    )

    feature_vector["vba_suspicious_indicator_count"] = sum(
        1 for item in indicators if item.severity in {"high", "medium"}
    )

    # Density measures.
    lines = max(stats.line_count, 1)
    source_bytes = max(stats.source_size, 1)

    feature_vector["vba_calls_per_line"] = stats.call_count / lines

    feature_vector["vba_strings_per_line"] = stats.string_count / lines

    feature_vector["vba_indicators_per_kb"] = stats.indicator_count / (
        source_bytes / 1024.0
    )

    return feature_vector


# ---------------------------------------------------------------------------
# Statistics
# ---------------------------------------------------------------------------


def calculate_statistics(
    analysis: VBAAnalysis,
) -> VBAParseStatistics:
    """Calculate aggregate statistics from analysis records."""

    stats = VBAParseStatistics()

    stats.source_size = len(analysis.source.text.encode("utf-8", errors="replace"))

    stats.line_count = len(analysis.source.text.splitlines())
    stats.module_count = len(analysis.modules)
    stats.procedure_count = len(analysis.procedures)
    stats.declaration_count = len(analysis.declarations)
    stats.api_declaration_count = len(analysis.api_declarations)
    stats.statement_count = len(analysis.statements)
    stats.call_count = len(analysis.calls)
    stats.string_count = len(analysis.strings)
    stats.identifier_count = len(analysis.identifiers)
    stats.attribute_count = len(analysis.attributes)
    stats.option_count = len(analysis.options)
    stats.control_flow_count = len(analysis.control_flow)
    stats.indicator_count = len(analysis.indicators)

    for line in analysis.source.text.splitlines():
        if not line.strip():
            stats.blank_line_count += 1
        elif strip_vba_comment(line)[0].strip() == "":
            stats.comment_line_count += 1

        if _has_trailing_continuation(line):
            stats.continuation_line_count += 1

    stats.long_string_count = sum(1 for item in analysis.strings if item.is_long)

    stats.url_count = sum(len(item.urls) for item in analysis.strings)

    stats.path_count = sum(len(item.paths) for item in analysis.strings)

    stats.ipv4_count = sum(len(item.ipv4_addresses) for item in analysis.strings)

    return stats


# ---------------------------------------------------------------------------
# Main parser
# ---------------------------------------------------------------------------


def parse_vba(
    source: str | bytes,
    *,
    source_name: Optional[str] = None,
) -> VBAAnalysis:
    """
    Parse VBA source into a complete static analysis object.
    """

    normalized = normalize_vba_source(source)

    if source_name:
        normalized = VBASource(
            text=normalized.text,
            encoding=normalized.encoding,
            source_name=source_name,
            sha256=normalized.sha256,
        )

    lines = split_vba_lines(normalized.text)

    attributes = parse_attributes(lines)
    options = parse_options(lines)

    module_name = parse_module_name(attributes)

    modules = [module_name] if module_name else []

    api_declarations = parse_api_declarations(normalized.text)
    declarations = parse_declarations(normalized.text)

    statements = parse_statements(normalized.text)

    procedures: list[VBAProcedure] = []
    current_procedure: Optional[VBAProcedure] = None

    for statement in statements:
        procedure_info = parse_procedure_header(statement.text)

        if procedure_info:
            if current_procedure is not None:
                # Recover from malformed/incomplete VBA.
                current_procedure.end_line_number = statement.line_number - 1
                procedures.append(current_procedure)

            current_procedure = VBAProcedure(
                name=procedure_info["name"],
                kind=procedure_info["kind"],
                line_number=statement.line_number,
                end_line_number=None,
                arguments=procedure_info["arguments"],
                return_type=procedure_info["return_type"],
                visibility=procedure_info["visibility"],
                is_static=procedure_info["is_static"],
            )
            continue

        if END_PROCEDURE_RE.match(statement.text):
            if current_procedure is not None:
                current_procedure.end_line_number = statement.line_number
                procedures.append(current_procedure)
                current_procedure = None

    if current_procedure is not None:
        current_procedure.end_line_number = len(lines)
        procedures.append(current_procedure)

    # Attach procedure source.
    for procedure in procedures:
        start = max(procedure.line_number - 1, 0)
        end = min(
            procedure.end_line_number or len(lines),
            len(lines),
        )
        procedure.source = "\n".join(lines[start:end])

    calls = parse_calls(
        normalized.text,
        api_declarations=api_declarations,
    )

    strings = extract_string_literals(normalized.text)
    identifiers = extract_identifiers(normalized.text)
    control_flow = parse_control_flow(normalized.text)
    indicators = derive_indicators(normalized.text)

    analysis = VBAAnalysis(
        source=normalized,
        modules=modules,
        attributes=attributes,
        options=options,
        declarations=declarations,
        api_declarations=api_declarations,
        procedures=procedures,
        statements=statements,
        calls=calls,
        strings=strings,
        identifiers=identifiers,
        control_flow=control_flow,
        indicators=indicators,
    )

    analysis.statistics = calculate_statistics(analysis)
    analysis.feature_vector = build_feature_vector(analysis)

    analysis.metadata = {
        "parser": "pharos-cdr-vba-parser",
        "parser_version": "1.0",
        "static_only": True,
        "source_name": source_name,
        "source_sha256": normalized.sha256,
        "encoding": normalized.encoding,
        "limits": {
            "max_source_size": MAX_SOURCE_SIZE,
            "max_lines": MAX_LINES,
            "max_modules": MAX_MODULES,
            "max_procedures": MAX_PROCEDURES,
            "max_statements": MAX_STATEMENTS,
            "max_calls": MAX_CALLS,
            "max_strings": MAX_STRINGS,
            "max_identifiers": MAX_IDENTIFIERS,
        },
    }

    return analysis


def analyze_vba(
    source: str | bytes,
    *,
    source_name: Optional[str] = None,
) -> VBAAnalysis:
    """Compatibility alias for parse_vba()."""

    return parse_vba(
        source,
        source_name=source_name,
    )


# ---------------------------------------------------------------------------
# API-compatible helper functions
# ---------------------------------------------------------------------------


def extract_vba_calls(
    source: str | bytes,
) -> list[VBACall]:
    """Convenience API for extracting only calls."""

    analysis = parse_vba(source)
    return analysis.calls


def extract_vba_strings(
    source: str | bytes,
) -> list[VBAStringLiteral]:
    """Convenience API for extracting only string literals."""

    analysis = parse_vba(source)
    return analysis.strings


def extract_vba_procedures(
    source: str | bytes,
) -> list[VBAProcedure]:
    """Convenience API for extracting procedures."""

    analysis = parse_vba(source)
    return analysis.procedures


def extract_vba_api_declarations(
    source: str | bytes,
) -> list[VBAAPIDeclaration]:
    """Convenience API for extracting Declare statements."""

    return parse_api_declarations(source)


def extract_vba_identifiers(
    source: str | bytes,
) -> list[str]:
    """Convenience API for extracting identifiers."""

    return extract_identifiers(source)


def extract_vba_features(
    source: str | bytes,
) -> dict[str, int | float]:
    """Return the parser-level feature vector."""

    return parse_vba(source).feature_vector


def vba_feature_names() -> list[str]:
    """Return stable parser feature names."""

    # Use a tiny empty analysis instead of hard-coding a second schema.
    analysis = parse_vba("")
    return sorted(analysis.feature_vector.keys())


def extract_feature_vector(
    source: str | bytes,
) -> dict[str, int | float]:
    """Compatibility alias for feature extraction."""

    return extract_vba_features(source)


def build_feature_schema() -> dict[str, str]:
    """Return feature names and primitive types."""

    analysis = parse_vba("")
    return {
        name: _feature_type(value) for name, value in analysis.feature_vector.items()
    }


def _feature_type(value: Any) -> str:
    if isinstance(value, bool):
        return "bool"

    if isinstance(value, int):
        return "int"

    if isinstance(value, float):
        return "float"

    return type(value).__name__


# ---------------------------------------------------------------------------
# Queries
# ---------------------------------------------------------------------------


def find_procedure(
    analysis: VBAAnalysis,
    name: str,
) -> Optional[VBAProcedure]:
    """Find a procedure by case-insensitive name."""

    target = name.casefold()

    for procedure in analysis.procedures:
        if procedure.name.casefold() == target:
            return procedure

    return None


def find_calls(
    analysis: VBAAnalysis,
    name: str,
) -> list[VBACall]:
    """Find calls by case-insensitive name."""

    target = name.casefold()

    return [call for call in analysis.calls if call.name.casefold() == target]


def find_indicators(
    analysis: VBAAnalysis,
    category: Optional[str] = None,
) -> list[VBAIndicator]:
    """Return indicators optionally filtered by category."""

    if category is None:
        return list(analysis.indicators)

    target = category.casefold()

    return [
        indicator
        for indicator in analysis.indicators
        if indicator.category.casefold() == target
    ]


def has_indicator(
    analysis: VBAAnalysis,
    indicator_name: str,
) -> bool:
    """Check whether a named static indicator exists."""

    target = indicator_name.casefold()

    return any(item.indicator.casefold() == target for item in analysis.indicators)


def has_api_declaration(
    analysis: VBAAnalysis,
    api_name: str,
) -> bool:
    """Check whether a VBA Declare statement references an API."""

    target = api_name.casefold()

    return any(
        item.normalized_name.casefold() == target for item in analysis.api_declarations
    )


def has_external_api(
    analysis: VBAAnalysis,
) -> bool:
    """Return True when one or more external API declarations exist."""

    return bool(analysis.api_declarations)


# ---------------------------------------------------------------------------
# Serialization
# ---------------------------------------------------------------------------


def analysis_to_dict(
    analysis: VBAAnalysis,
    *,
    include_source: bool = False,
    include_statement_source: bool = True,
) -> dict[str, Any]:
    """
    Convert the analysis to JSON-compatible primitives.

    Source text is omitted by default to keep reports manageable.
    """

    result: dict[str, Any] = {
        "source": {
            "encoding": analysis.source.encoding,
            "source_name": analysis.source.source_name,
            "sha256": analysis.source.sha256,
            "size": len(
                analysis.source.text.encode(
                    "utf-8",
                    errors="replace",
                )
            ),
        },
        "modules": analysis.modules,
        "attributes": [asdict(item) for item in analysis.attributes],
        "options": [asdict(item) for item in analysis.options],
        "declarations": [asdict(item) for item in analysis.declarations],
        "api_declarations": [asdict(item) for item in analysis.api_declarations],
        "procedures": [asdict(item) for item in analysis.procedures],
        "statements": [],
        "calls": [asdict(item) for item in analysis.calls],
        "strings": [asdict(item) for item in analysis.strings],
        "identifiers": analysis.identifiers,
        "control_flow": [asdict(item) for item in analysis.control_flow],
        "indicators": [asdict(item) for item in analysis.indicators],
        "statistics": asdict(analysis.statistics),
        "feature_vector": analysis.feature_vector,
        "metadata": analysis.metadata,
    }

    for statement in analysis.statements:
        item = asdict(statement)

        if not include_statement_source:
            item.pop("text", None)

        result["statements"].append(item)

    if include_source:
        result["source"]["text"] = analysis.source.text

    return result


def summarize_analysis(
    analysis: VBAAnalysis,
) -> dict[str, Any]:
    """Return a compact report-oriented summary."""

    indicator_counts: dict[str, int] = {}

    for indicator in analysis.indicators:
        key = indicator.indicator
        indicator_counts[key] = indicator_counts.get(key, 0) + 1

    procedure_names = [procedure.name for procedure in analysis.procedures]

    api_names = sorted(
        {declaration.normalized_name for declaration in analysis.api_declarations},
        key=str.casefold,
    )

    return {
        "sha256": analysis.source.sha256,
        "module_names": analysis.modules,
        "procedure_names": procedure_names,
        "api_names": api_names,
        "indicator_counts": indicator_counts,
        "statistics": asdict(analysis.statistics),
        "feature_vector": dict(analysis.feature_vector),
    }


# ---------------------------------------------------------------------------
# Batch parsing
# ---------------------------------------------------------------------------


def iter_vba_analyses(
    sources: Iterable[str | bytes | tuple[str, str | bytes]],
) -> Iterator[VBAAnalysis]:
    """
    Parse multiple VBA sources.

    Items may be:
        source
    or:
        (source_name, source)
    """

    for item in sources:
        if isinstance(item, tuple) and len(item) == 2:
            source_name, source = item
            yield parse_vba(
                source,
                source_name=str(source_name),
            )
        else:
            yield parse_vba(item)


# ---------------------------------------------------------------------------
# Safe source predicates
# ---------------------------------------------------------------------------


def looks_like_vba(source: str | bytes) -> bool:
    """
    Return whether source contains plausible VBA syntax.

    This is a heuristic, not a file-type detector.
    """

    normalized = normalize_vba_source(source)
    text = normalized.text

    markers = (
        r"\bAttribute\s+VB_Name\b",
        r"\bOption\s+(?:Explicit|Base|Compare)\b",
        r"\b(?:Public|Private)?\s*(?:Sub|Function)\s+\w+",
        r"\bDeclare\s+(?:PtrSafe\s+)?(?:Function|Sub)\b",
        r"\bDim\s+\w+",
        r"\bEnd\s+(?:Sub|Function|Property)\b",
    )

    return any(re.search(pattern, text, re.IGNORECASE) for pattern in markers)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _unquote(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None

    value = value.strip()

    if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        return value[1:-1].replace('""', '"')

    return value


__all__ = [
    "MAX_SOURCE_SIZE",
    "MAX_LINES",
    "MAX_MODULES",
    "MAX_PROCEDURES",
    "MAX_STATEMENTS",
    "MAX_CALLS",
    "MAX_STRINGS",
    "MAX_IDENTIFIERS",
    "VBASource",
    "VBAAttribute",
    "VBAOption",
    "VBADeclaration",
    "VBAAPIDeclaration",
    "VBAProcedure",
    "VBAStatement",
    "VBACall",
    "VBAStringLiteral",
    "VBAControlFlow",
    "VBAIndicator",
    "VBAParseStatistics",
    "VBAAnalysis",
    "normalize_vba_source",
    "split_vba_lines",
    "strip_vba_comment",
    "strip_vba_comments",
    "split_vba_statements",
    "parse_module_name",
    "parse_attributes",
    "parse_options",
    "parse_procedure_header",
    "parse_api_declarations",
    "parse_declarations",
    "parse_calls",
    "extract_string_literals",
    "extract_identifiers",
    "parse_control_flow",
    "classify_statement",
    "parse_statements",
    "derive_indicators",
    "calculate_statistics",
    "build_feature_vector",
    "parse_vba",
    "analyze_vba",
    "extract_vba_calls",
    "extract_vba_strings",
    "extract_vba_procedures",
    "extract_vba_api_declarations",
    "extract_vba_identifiers",
    "extract_vba_features",
    "vba_feature_names",
    "extract_feature_vector",
    "build_feature_schema",
    "find_procedure",
    "find_calls",
    "find_indicators",
    "has_indicator",
    "has_api_declaration",
    "has_external_api",
    "analysis_to_dict",
    "summarize_analysis",
    "iter_vba_analyses",
    "looks_like_vba",
]
