"""
Static script parsing and evidence extraction.

This module provides a common parser/normalizer for script content used by
the Pharos CDR and malware-analysis pipeline.

Supported script families:
    - JavaScript / JScript
    - VBScript
    - PowerShell
    - generic command/shell-like script text

The parser is intentionally syntax-light and dependency-free. It does not
attempt to build a complete language AST. Instead, it produces deterministic
static evidence suitable for downstream modules:

    parser.py
        -> javascript.py
        -> vbscript.py
        -> powershell.py
        -> feature_pipeline.py
        -> ML / CDR policy

Security properties:
    - never executes script;
    - never evaluates expressions;
    - never invokes COM/ActiveX;
    - never launches subprocesses;
    - never resolves or downloads URLs;
    - never imports/loads executable modules;
    - never writes extracted content to the host filesystem.

The parser is designed to preserve evidence rather than aggressively rewrite
or "clean" suspicious source.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
import hashlib
import re
from collections import Counter
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
# Limits
# ---------------------------------------------------------------------------

MAX_SOURCE_SIZE = 25 * 1024 * 1024
MAX_LINES = 500_000
MAX_EVIDENCE_ITEMS = 20_000
MAX_TOKENS = 200_000
MAX_STRINGS = 50_000
MAX_URLS = 20_000
MAX_IDENTIFIERS = 100_000
MAX_PROCEDURES = 50_000


# ---------------------------------------------------------------------------
# Script families
# ---------------------------------------------------------------------------

SCRIPT_FAMILIES: Tuple[str, ...] = (
    "javascript",
    "vbscript",
    "powershell",
    "batch",
    "shell",
    "generic",
)


EXTENSION_TO_FAMILY: Dict[str, str] = {
    ".js": "javascript",
    ".jse": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".wsf": "javascript",
    ".hta": "javascript",
    ".vbs": "vbscript",
    ".vbe": "vbscript",
    ".wsf": "vbscript",
    ".ps1": "powershell",
    ".psm1": "powershell",
    ".psd1": "powershell",
    ".ps1xml": "powershell",
    ".bat": "batch",
    ".cmd": "batch",
    ".sh": "shell",
    ".bash": "shell",
    ".zsh": "shell",
    ".ksh": "shell",
}


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ScriptString:
    """Static string literal."""

    value: str
    quote: str
    line_number: int
    column: int
    length: int
    truncated: bool = False


@dataclass(frozen=True)
class ScriptToken:
    """Lightweight lexical token."""

    value: str
    normalized: str
    token_type: str
    line_number: int
    column: int
    length: int


@dataclass(frozen=True)
class ScriptURL:
    """URL-like static evidence."""

    value: str
    line_number: int
    column: int
    scheme: str
    host: Optional[str] = None


@dataclass(frozen=True)
class ScriptProcedure:
    """Statically identified function/sub/procedure-like declaration."""

    name: str
    normalized_name: str
    kind: str
    line_number: int
    end_line_number: Optional[int] = None


@dataclass(frozen=True)
class ScriptEvidence:
    """Generic parser evidence."""

    category: str
    indicator: str
    evidence: str
    line_number: Optional[int] = None
    column: Optional[int] = None
    confidence: float = 1.0
    severity: str = "low"
    family: str = "generic"


@dataclass
class ScriptAnalysis:
    """Complete static parsing result."""

    family: str
    source_hash: str
    source_size_bytes: int
    line_count: int

    strings: List[ScriptString] = field(default_factory=list)
    tokens: List[ScriptToken] = field(default_factory=list)
    urls: List[ScriptURL] = field(default_factory=list)
    procedures: List[ScriptProcedure] = field(default_factory=list)
    evidence: List[ScriptEvidence] = field(default_factory=list)

    identifiers: List[str] = field(default_factory=list)
    comments: List[str] = field(default_factory=list)

    feature_vector: Dict[str, Union[int, float, bool]] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Source helpers
# ---------------------------------------------------------------------------


def _read_source(
    source: Union[str, bytes, bytearray],
) -> str:
    if isinstance(source, str):
        size = len(source.encode("utf-8", errors="ignore"))
        if size > MAX_SOURCE_SIZE:
            raise ValueError(f"script source exceeds MAX_SOURCE_SIZE={MAX_SOURCE_SIZE}")
        return source

    if isinstance(source, (bytes, bytearray)):
        if len(source) > MAX_SOURCE_SIZE:
            raise ValueError(f"script source exceeds MAX_SOURCE_SIZE={MAX_SOURCE_SIZE}")
        return bytes(source).decode("utf-8", errors="replace")

    raise TypeError("source must be str, bytes, or bytearray")


def _normalize_family(
    family: Optional[str],
) -> str:
    if not family:
        return "generic"

    normalized = family.strip().lower()

    aliases = {
        "js": "javascript",
        "jscript": "javascript",
        "javascript": "javascript",
        "vbs": "vbscript",
        "vbscript": "vbscript",
        "powershell": "powershell",
        "pwsh": "powershell",
        "ps": "powershell",
        "cmd": "batch",
        "bat": "batch",
        "batch": "batch",
        "sh": "shell",
        "bash": "shell",
        "shell": "shell",
        "generic": "generic",
    }

    return aliases.get(normalized, "generic")


def infer_script_family(
    source: Optional[Union[str, bytes, bytearray]] = None,
    filename: Optional[str] = None,
    content_type: Optional[str] = None,
) -> str:
    """
    Infer a script family from filename/content-type/source heuristics.

    Explicit filename extension takes precedence over weak source heuristics.
    """
    if filename:
        lowered = filename.lower()

        for extension, family in EXTENSION_TO_FAMILY.items():
            if lowered.endswith(extension):
                return family

    if content_type:
        lowered_type = content_type.lower()

        if "powershell" in lowered_type:
            return "powershell"

        if "javascript" in lowered_type or "ecmascript" in lowered_type:
            return "javascript"

        if "vbscript" in lowered_type:
            return "vbscript"

    if source is None:
        return "generic"

    text = _read_source(source)

    family_scores: Dict[str, int] = {family: 0 for family in SCRIPT_FAMILIES}

    # PowerShell-specific syntax.
    family_scores["powershell"] += len(
        re.findall(
            r"(?im)^\s*(?:param|function|filter|workflow)\b",
            text,
        )
    )
    family_scores["powershell"] += len(
        re.findall(
            r"(?i)(?:\$\w+|Get-[A-Za-z]+|Set-[A-Za-z]+|"
            r"New-[A-Za-z]+|Invoke-[A-Za-z]+|Write-[A-Za-z]+)",
            text,
        )
    )

    # VBScript syntax.
    family_scores["vbscript"] += len(
        re.findall(
            r"(?im)^\s*(?:Option\s+Explicit|Dim|Function|Sub|Class)\b",
            text,
        )
    )
    family_scores["vbscript"] += len(
        re.findall(
            r"(?i)\b(?:CreateObject|WScript|VBScript|On\s+Error\s+Resume)\b",
            text,
        )
    )

    # JavaScript/JScript syntax.
    family_scores["javascript"] += len(
        re.findall(
            r"(?im)^\s*(?:function|var|let|const|class|import|export)\b",
            text,
        )
    )
    family_scores["javascript"] += len(
        re.findall(
            r"(?i)\b(?:eval|ActiveXObject|WScript\.CreateObject)\b",
            text,
        )
    )

    # Batch.
    family_scores["batch"] += len(
        re.findall(
            r"(?im)^\s*@?(?:echo|set|if|for|goto|call|start)\b",
            text,
        )
    )

    # Shell.
    family_scores["shell"] += len(
        re.findall(
            r"(?m)^\s*#!\s*/?(?:usr/bin/)?(?:env\s+)?(?:ba)?sh\b",
            text,
        )
    )
    family_scores["shell"] += len(
        re.findall(
            r"(?m)^\s*(?:export|source|alias)\s+\w+",
            text,
        )
    )

    best_family = max(
        family_scores,
        key=family_scores.get,
    )

    if family_scores[best_family] <= 0:
        return "generic"

    return best_family


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


# ---------------------------------------------------------------------------
# Comment handling
# ---------------------------------------------------------------------------


def _extract_comments(
    source: str,
    family: str,
) -> List[str]:
    """
    Extract comments without attempting to interpret code inside them.
    """
    comments: List[str] = []

    lines = source.splitlines()

    for line in lines:
        stripped = line.strip()

        if family in {"javascript", "generic"}:
            if stripped.startswith("//"):
                comments.append(stripped[2:].strip())
                continue

            if stripped.startswith("/*") and stripped.endswith("*/"):
                comments.append(stripped[2:-2].strip())
                continue

        if family == "powershell":
            if stripped.startswith("#"):
                comments.append(stripped[1:].strip())
                continue

        if family == "vbscript":
            if stripped.startswith("'"):
                comments.append(stripped[1:].strip())
                continue

            if re.match(r"(?i)^Rem(?:\s|$)", stripped):
                comments.append(
                    re.sub(
                        r"(?i)^Rem(?:\s|$)",
                        "",
                        stripped,
                    ).strip()
                )
                continue

        if family == "batch":
            if re.match(r"(?i)^(?:rem(?:\s|$)|::)", stripped):
                comments.append(
                    re.sub(
                        r"(?i)^(?:rem(?:\s|$)|::)",
                        "",
                        stripped,
                    ).strip()
                )
                continue

        if family == "shell":
            if stripped.startswith("#"):
                comments.append(stripped[1:].strip())

    return comments[:MAX_EVIDENCE_ITEMS]


def strip_comments(
    source: Union[str, bytes, bytearray],
    family: str = "generic",
) -> str:
    """
    Produce a conservative comment-stripped view.

    This function preserves strings and does not attempt full language
    parsing. It is intended for evidence matching rather than compilation.
    """
    text = _read_source(source)
    family = _normalize_family(family)

    output: List[str] = []

    in_block_comment = False

    for raw_line in text.splitlines():
        line = raw_line

        if family in {"javascript", "generic"}:
            if in_block_comment:
                end = line.find("*/")

                if end < 0:
                    output.append("")
                    continue

                line = line[end + 2 :]
                in_block_comment = False

            if "/*" in line:
                start = line.find("/*")
                end = line.find("*/", start + 2)

                if end < 0:
                    line = line[:start]
                    in_block_comment = True
                else:
                    line = line[:start] + line[end + 2 :]

            line = _strip_inline_comment(
                line,
                "//",
            )

        elif family == "powershell":
            line = _strip_inline_comment(
                line,
                "#",
            )

        elif family == "vbscript":
            line = _strip_inline_comment(
                line,
                "'",
            )

            if re.match(
                r"(?i)^\s*Rem(?:\s|$)",
                line,
            ):
                line = ""

        elif family == "batch":
            line = _strip_inline_comment(
                line,
                "REM",
            )

            if re.match(
                r"(?i)^\s*::",
                line,
            ):
                line = ""

        elif family == "shell":
            line = _strip_inline_comment(
                line,
                "#",
            )

        output.append(line)

    return "\n".join(output)


def _strip_inline_comment(
    line: str,
    marker: str,
) -> str:
    """
    Strip a comment marker only when outside simple quoted strings.
    """
    if not marker:
        return line

    in_single = False
    in_double = False
    i = 0

    marker_lower = marker.lower()

    while i < len(line):
        char = line[i]

        if char == "'" and not in_double:
            in_single = not in_single
            i += 1
            continue

        if char == '"' and not in_single:
            # Basic doubled-quote handling.
            if in_double and i + 1 < len(line) and line[i + 1] == '"':
                i += 2
                continue

            in_double = not in_double
            i += 1
            continue

        if not in_single and not in_double:
            remaining = line[i:]

            if marker == "REM" and re.match(
                r"(?i)^REM(?:\s|$)",
                remaining,
            ):
                return line[:i]

            if marker != "REM" and remaining.startswith(marker):
                return line[:i]

            if marker == "#" and char == "#":
                return line[:i]

        i += 1

    return line


# ---------------------------------------------------------------------------
# String lexer
# ---------------------------------------------------------------------------


def extract_strings(
    source: Union[str, bytes, bytearray],
    family: str = "generic",
) -> List[ScriptString]:
    """
    Extract quoted string literals using a bounded lightweight lexer.
    """
    text = _read_source(source)
    family = _normalize_family(family)

    strings: List[ScriptString] = []

    for line_number, line in enumerate(
        text.splitlines(),
        start=1,
    ):
        i = 0

        while i < len(line):
            quote: Optional[str] = None

            if line[i] == '"':
                quote = '"'
            elif line[i] == "'" and family in {"javascript", "generic", "powershell"}:
                quote = "'"

            if quote is None:
                i += 1
                continue

            start = i
            i += 1
            value_chars: List[str] = []

            while i < len(line):
                char = line[i]

                if char == quote:
                    # JavaScript/PowerShell backslash escaping.
                    if (
                        i > 0
                        and line[i - 1] == "\\"
                        and family
                        in {
                            "javascript",
                            "generic",
                            "powershell",
                        }
                    ):
                        value_chars.append(char)
                        i += 1
                        continue

                    # VBA/VBScript-style doubled quote.
                    if i + 1 < len(line) and line[i + 1] == quote:
                        value_chars.append(quote)
                        i += 2
                        continue

                    break

                value_chars.append(char)
                i += 1

            if i >= len(line):
                value = "".join(value_chars)
                truncated = True
            else:
                value = "".join(value_chars)
                truncated = False
                i += 1

            if len(strings) >= MAX_STRINGS:
                return strings

            bounded = value[:8_192]

            strings.append(
                ScriptString(
                    value=bounded,
                    quote=quote,
                    line_number=line_number,
                    column=start + 1,
                    length=len(value),
                    truncated=truncated or len(value) > 8_192,
                )
            )

    return strings


# ---------------------------------------------------------------------------
# Tokenization
# ---------------------------------------------------------------------------


_IDENTIFIER_RE = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*")

_NUMBER_RE = re.compile(r"""(?ix)
    (?:
        0x[0-9a-f]+
        |
        0b[01]+
        |
        0o[0-7]+
        |
        \d+(?:\.\d+)?
    )
    """)

_OPERATOR_RE = re.compile(r"""(?x)
    (?:
        ===|!==|>>>|<<=|>>=|&&|\|\||=>|==|!=|<=|>=|
        \+\+|--|\+=|-=|\*=|/=|%=|<<|>>|&=|\|=|\^=|
        [+\-*/%=<>!&|^~?:]
    )
    """)

_PUNCTUATION = set("()[]{}.,;:")


def tokenize(
    source: Union[str, bytes, bytearray],
    family: str = "generic",
) -> List[ScriptToken]:
    """
    Produce lightweight lexical tokens.

    Tokens are intended for feature extraction and pattern matching, not
    language compilation.
    """
    text = strip_comments(
        source,
        family=family,
    )

    tokens: List[ScriptToken] = []

    for line_number, line in enumerate(
        text.splitlines(),
        start=1,
    ):
        i = 0

        while i < len(line):
            char = line[i]

            if char.isspace():
                i += 1
                continue

            start = i

            if char in {'"', "'"}:
                quote = char
                i += 1

                while i < len(line):
                    if line[i] == quote:
                        if i + 1 < len(line) and line[i + 1] == quote:
                            i += 2
                            continue

                        i += 1
                        break

                    if line[i] == "\\" and i + 1 < len(line):
                        i += 2
                    else:
                        i += 1

                value = line[start:i]
                token_type = "string"

            else:
                match = _IDENTIFIER_RE.match(
                    line,
                    i,
                )

                if match:
                    value = match.group(0)
                    i = match.end()
                    token_type = "identifier"

                else:
                    match = _NUMBER_RE.match(
                        line,
                        i,
                    )

                    if match:
                        value = match.group(0)
                        i = match.end()
                        token_type = "number"

                    else:
                        match = _OPERATOR_RE.match(
                            line,
                            i,
                        )

                        if match:
                            value = match.group(0)
                            i = match.end()
                            token_type = "operator"

                        elif char in _PUNCTUATION:
                            value = char
                            i += 1
                            token_type = "punctuation"

                        else:
                            value = char
                            i += 1
                            token_type = "other"

            if len(tokens) >= MAX_TOKENS:
                return tokens

            tokens.append(
                ScriptToken(
                    value=value,
                    normalized=value.lower(),
                    token_type=token_type,
                    line_number=line_number,
                    column=start + 1,
                    length=len(value),
                )
            )

    return tokens


# ---------------------------------------------------------------------------
# URL extraction
# ---------------------------------------------------------------------------


_URL_RE = re.compile(r"""(?ix)
    \b
    (?P<scheme>
        https?|ftp|file
    )
    ://
    (?P<rest>
        [^\s<>"'`]+
    )
    """)


def extract_urls(
    source: Union[str, bytes, bytearray],
) -> List[ScriptURL]:
    """
    Extract URL-like strings without resolving them.
    """
    text = _read_source(source)
    results: List[ScriptURL] = []

    for line_number, line in enumerate(
        text.splitlines(),
        start=1,
    ):
        for match in _URL_RE.finditer(line):
            if len(results) >= MAX_URLS:
                return results

            scheme = match.group("scheme").lower()
            rest = match.group("rest").rstrip(".,;)]}")

            value = f"{scheme}://{rest}"

            host_match = re.match(
                r"(?i)([^/:?#]+)",
                rest,
            )

            host = host_match.group(1) if host_match else None

            results.append(
                ScriptURL(
                    value=value[:8_192],
                    line_number=line_number,
                    column=match.start() + 1,
                    scheme=scheme,
                    host=host,
                )
            )

    return results


# ---------------------------------------------------------------------------
# Procedure extraction
# ---------------------------------------------------------------------------


def extract_procedures(
    source: Union[str, bytes, bytearray],
    family: str = "generic",
) -> List[ScriptProcedure]:
    """
    Extract function/sub/procedure declarations using family-aware regexes.
    """
    text = _read_source(source)
    family = _normalize_family(family)

    procedures: List[ScriptProcedure] = []

    patterns: List[Tuple[str, re.Pattern[str]]] = []

    if family == "javascript":
        patterns.append(
            (
                "function",
                re.compile(r"(?i)\bfunction\s+" r"([A-Za-z_$][A-Za-z0-9_$]*)\s*\("),
            )
        )

    elif family == "vbscript":
        patterns.extend(
            [
                (
                    "function",
                    re.compile(
                        r"(?i)^\s*(?:Public\s+|Private\s+)?"
                        r"Function\s+"
                        r"([A-Za-z_][A-Za-z0-9_]*)"
                    ),
                ),
                (
                    "sub",
                    re.compile(
                        r"(?i)^\s*(?:Public\s+|Private\s+)?"
                        r"Sub\s+"
                        r"([A-Za-z_][A-Za-z0-9_]*)"
                    ),
                ),
                (
                    "property",
                    re.compile(
                        r"(?i)^\s*(?:Public\s+|Private\s+)?"
                        r"Property\s+"
                        r"(?:Get|Let|Set)\s+"
                        r"([A-Za-z_][A-Za-z0-9_]*)"
                    ),
                ),
            ]
        )

    elif family == "powershell":
        patterns.append(
            (
                "function",
                re.compile(r"(?i)^\s*function\s+" r"([A-Za-z_][A-Za-z0-9_-]*)"),
            )
        )

        patterns.append(
            (
                "filter",
                re.compile(r"(?i)^\s*filter\s+" r"([A-Za-z_][A-Za-z0-9_-]*)"),
            )
        )

    else:
        patterns.extend(
            [
                (
                    "function",
                    re.compile(r"(?i)\bfunction\s+" r"([A-Za-z_$][A-Za-z0-9_$-]*)"),
                ),
                (
                    "sub",
                    re.compile(r"(?i)\bsub\s+" r"([A-Za-z_][A-Za-z0-9_]*)"),
                ),
            ]
        )

    active: Optional[ScriptProcedure] = None

    for line_number, line in enumerate(
        text.splitlines(),
        start=1,
    ):
        for kind, pattern in patterns:
            match = pattern.search(line)

            if not match:
                continue

            if len(procedures) >= MAX_PROCEDURES:
                return procedures

            procedure = ScriptProcedure(
                name=match.group(1),
                normalized_name=match.group(1).lower(),
                kind=kind,
                line_number=line_number,
            )

            procedures.append(procedure)
            active = procedure
            break

        # VBScript end markers.
        if family == "vbscript" and re.search(
            r"(?i)^\s*End\s+(?:Function|Sub|Property)\b",
            line,
        ):
            if active is not None:
                # Dataclasses are frozen, so replace the last record.
                last = procedures[-1]

                procedures[-1] = ScriptProcedure(
                    name=last.name,
                    normalized_name=last.normalized_name,
                    kind=last.kind,
                    line_number=last.line_number,
                    end_line_number=line_number,
                )

            active = None

    return procedures


# ---------------------------------------------------------------------------
# Identifier extraction
# ---------------------------------------------------------------------------


def extract_identifiers(
    tokens: Sequence[ScriptToken],
) -> List[str]:
    """
    Extract unique identifiers in first-seen order.
    """
    identifiers: List[str] = []
    seen: set[str] = set()

    for token in tokens:
        if token.token_type != "identifier":
            continue

        normalized = token.normalized

        if normalized in seen:
            continue

        seen.add(normalized)
        identifiers.append(token.value)

        if len(identifiers) >= MAX_IDENTIFIERS:
            break

    return identifiers


# ---------------------------------------------------------------------------
# Generic static indicators
# ---------------------------------------------------------------------------


GENERIC_INDICATORS: Tuple[Tuple[str, str, str, float, str], ...] = (
    (
        "dynamic_execution",
        "eval",
        r"(?i)\beval\s*\(",
        0.95,
        "high",
    ),
    (
        "dynamic_execution",
        "execute",
        r"(?i)\bexecute(?:global)?\s*\(",
        0.95,
        "high",
    ),
    (
        "dynamic_execution",
        "invoke",
        r"(?i)\b(?:invoke|invoke-command)\b",
        0.75,
        "medium",
    ),
    (
        "com_automation",
        "activexobject",
        r"(?i)\bActiveXObject\s*\(",
        0.98,
        "high",
    ),
    (
        "com_automation",
        "createobject",
        r"(?i)\bCreateObject\s*\(",
        0.90,
        "high",
    ),
    (
        "process_execution",
        "wscript_shell",
        r"(?i)\bWScript\s*\.\s*Shell\b",
        0.96,
        "high",
    ),
    (
        "process_execution",
        "shell",
        r"(?i)\b(?:Shell|Start-Process)\b",
        0.85,
        "medium",
    ),
    (
        "network",
        "web_request",
        r"(?i)\b(?:WebClient|Invoke-WebRequest|Invoke-RestMethod|"
        r"XMLHTTP|WinHttpRequest|MSXML2\.)\b",
        0.92,
        "high",
    ),
    (
        "download",
        "download",
        r"(?i)\b(?:DownloadString|DownloadFile|" r"Start-BitsTransfer|curl|wget)\b",
        0.95,
        "high",
    ),
    (
        "filesystem",
        "filesystem_access",
        r"(?i)\b(?:FileSystemObject|OpenTextFile|"
        r"ReadAllText|WriteAllText|Out-File|Set-Content|"
        r"Add-Content)\b",
        0.80,
        "medium",
    ),
    (
        "registry",
        "registry_access",
        r"(?i)\b(?:RegRead|RegWrite|RegDelete|"
        r"HKLM|HKCU|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER)\b",
        0.85,
        "medium",
    ),
    (
        "persistence",
        "startup_location",
        r"(?i)\b(?:CurrentVersion\\Run|Startup|"
        r"Logon\s+Scripts|ScheduledTask|schtasks)\b",
        0.96,
        "high",
    ),
    (
        "credential_access",
        "credential_terms",
        r"(?i)\b(?:password|credential|token|" r"secret|logon|credentialmanager)\b",
        0.45,
        "low",
    ),
    (
        "obfuscation",
        "character_construction",
        r"(?i)\b(?:Chr|ChrW|String\.fromCharCode)\s*\(",
        0.88,
        "medium",
    ),
    (
        "obfuscation",
        "base64_operation",
        r"(?i)\b(?:FromBase64String|ToBase64String|" r"base64|certutil\s+-decode)\b",
        0.90,
        "high",
    ),
    (
        "obfuscation",
        "string_reversal",
        r"(?i)\b(?:StrReverse|reverse)\s*\(",
        0.82,
        "medium",
    ),
    (
        "environment",
        "environment_variable",
        r"(?i)(?:\$env:|Environ\s*\(|" r"WScript\.Shell.*Environment)",
        0.80,
        "low",
    ),
    (
        "discovery",
        "system_information",
        r"(?i)\b(?:Win32_OperatingSystem|"
        r"Win32_ComputerSystem|hostname|"
        r"Get-CimInstance|Get-WmiObject)\b",
        0.70,
        "medium",
    ),
    (
        "evasion",
        "security_software",
        r"(?i)\b(?:Defender|antivirus|"
        r"security\s+center|EDR|CrowdStrike|SentinelOne)\b",
        0.70,
        "medium",
    ),
)


def detect_generic_indicators(
    source: str,
    family: str,
) -> List[ScriptEvidence]:
    """
    Detect common script capabilities with conservative confidence levels.
    """
    evidence: List[ScriptEvidence] = []

    for line_number, line in enumerate(
        source.splitlines(),
        start=1,
    ):
        for (
            category,
            indicator,
            pattern,
            confidence,
            severity,
        ) in GENERIC_INDICATORS:
            if not re.search(pattern, line):
                continue

            if len(evidence) >= MAX_EVIDENCE_ITEMS:
                return evidence

            evidence.append(
                ScriptEvidence(
                    category=category,
                    indicator=indicator,
                    evidence=line.strip()[:2_000],
                    line_number=line_number,
                    confidence=confidence,
                    severity=severity,
                    family=family,
                )
            )

    return evidence


# ---------------------------------------------------------------------------
# Obfuscation/statistical indicators
# ---------------------------------------------------------------------------


def _entropy(value: str) -> float:
    if not value:
        return 0.0

    counts = Counter(value)
    length = len(value)

    import math

    return -sum(
        (count / length) * math.log2(count / length) for count in counts.values()
    )


def _looks_base64(value: str) -> bool:
    compact = re.sub(r"\s+", "", value)

    if len(compact) < 16:
        return False

    if not re.fullmatch(
        r"[A-Za-z0-9+/]+={0,2}",
        compact,
    ):
        return False

    return True


def _looks_hex(value: str) -> bool:
    compact = re.sub(r"[\s,\\xX]+", "", value)

    return len(compact) >= 16 and bool(
        re.fullmatch(
            r"[0-9A-Fa-f]+",
            compact,
        )
    )


def detect_string_indicators(
    strings: Sequence[ScriptString],
    family: str,
) -> List[ScriptEvidence]:
    evidence: List[ScriptEvidence] = []

    for item in strings:
        value = item.value

        if _looks_base64(value):
            evidence.append(
                ScriptEvidence(
                    category="obfuscation",
                    indicator="base64_like_string",
                    evidence=value[:2_000],
                    line_number=item.line_number,
                    column=item.column,
                    confidence=0.72,
                    severity=("high" if item.length >= 128 else "medium"),
                    family=family,
                )
            )

        if _looks_hex(value):
            evidence.append(
                ScriptEvidence(
                    category="obfuscation",
                    indicator="hex_like_string",
                    evidence=value[:2_000],
                    line_number=item.line_number,
                    column=item.column,
                    confidence=0.78,
                    severity=("high" if item.length >= 128 else "medium"),
                    family=family,
                )
            )

        if item.length >= 64:
            entropy = _entropy(value)

            if entropy >= 4.5:
                evidence.append(
                    ScriptEvidence(
                        category="obfuscation",
                        indicator="high_entropy_string",
                        evidence=value[:2_000],
                        line_number=item.line_number,
                        column=item.column,
                        confidence=0.65,
                        severity=("high" if entropy >= 5.4 else "medium"),
                        family=family,
                    )
                )

    return evidence[:MAX_EVIDENCE_ITEMS]


# ---------------------------------------------------------------------------
# Family-specific evidence
# ---------------------------------------------------------------------------


def detect_family_indicators(
    source: str,
    family: str,
) -> List[ScriptEvidence]:
    """
    Detect syntax/features characteristic of each script family.
    """
    evidence: List[ScriptEvidence] = []

    patterns: Dict[
        str,
        Tuple[
            Tuple[str, str, float, str],
            ...,
        ],
    ] = {
        "powershell": (
            (
                "powershell",
                "encoded_command",
                r"(?i)(?:-enc(?:odedcommand)?|-e)\s+[A-Za-z0-9+/=]{8,}",
                0.98,
                "high",
            ),
            (
                "powershell",
                "iex",
                r"(?i)(?:\bIEX\b|Invoke-Expression)",
                0.98,
                "high",
            ),
            (
                "powershell",
                "download_cradle",
                r"(?i)\b(?:Net\.WebClient|WebClient|"
                r"Invoke-WebRequest|Invoke-RestMethod)\b",
                0.92,
                "high",
            ),
            (
                "powershell",
                "reflection",
                r"(?i)\[(?:Reflection|Type)\]::",
                0.85,
                "medium",
            ),
            (
                "powershell",
                "assembly_loading",
                r"(?i)\b(?:Add-Type|Load|LoadFrom|" r"Assembly\.Load)\b",
                0.90,
                "high",
            ),
            (
                "powershell",
                "amsi_reference",
                r"(?i)\b(?:amsi|AmsiUtils|" r"amsiInitFailed)\b",
                0.92,
                "high",
            ),
        ),
        "javascript": (
            (
                "javascript",
                "eval",
                r"(?i)\beval\s*\(",
                0.98,
                "high",
            ),
            (
                "javascript",
                "function_constructor",
                r"(?i)\bFunction\s*\(",
                0.90,
                "high",
            ),
            (
                "javascript",
                "activexobject",
                r"(?i)\bActiveXObject\s*\(",
                0.99,
                "high",
            ),
            (
                "javascript",
                "document_write",
                r"(?i)\bdocument\s*\.\s*write(?:ln)?\s*\(",
                0.60,
                "low",
            ),
            (
                "javascript",
                "char_code_construction",
                r"(?i)\bString\s*\.\s*fromCharCode\s*\(",
                0.92,
                "medium",
            ),
        ),
        "vbscript": (
            (
                "vbscript",
                "createobject",
                r"(?i)\bCreateObject\s*\(",
                0.94,
                "high",
            ),
            (
                "vbscript",
                "wscript_shell",
                r"(?i)\bWScript\s*\.\s*Shell\b",
                0.98,
                "high",
            ),
            (
                "vbscript",
                "execute",
                r"(?i)\bExecute(?:Global)?\s*\(",
                0.98,
                "high",
            ),
            (
                "vbscript",
                "getobject",
                r"(?i)\bGetObject\s*\(",
                0.82,
                "medium",
            ),
            (
                "vbscript",
                "chr_construction",
                r"(?i)\bChrW?\$?\s*\(",
                0.88,
                "medium",
            ),
        ),
        "batch": (
            (
                "batch",
                "powershell_invocation",
                r"(?i)\b(?:powershell|pwsh)(?:\.exe)?\b",
                0.96,
                "high",
            ),
            (
                "batch",
                "certutil",
                r"(?i)\bcertutil(?:\.exe)?\b",
                0.92,
                "high",
            ),
            (
                "batch",
                "bitsadmin",
                r"(?i)\bbitsadmin(?:\.exe)?\b",
                0.94,
                "high",
            ),
            (
                "batch",
                "rundll32",
                r"(?i)\brundll32(?:\.exe)?\b",
                0.94,
                "high",
            ),
            (
                "batch",
                "regsvr32",
                r"(?i)\bregsvr32(?:\.exe)?\b",
                0.94,
                "high",
            ),
        ),
        "shell": (
            (
                "shell",
                "curl",
                r"(?i)\bcurl\b",
                0.75,
                "medium",
            ),
            (
                "shell",
                "wget",
                r"(?i)\bwget\b",
                0.75,
                "medium",
            ),
            (
                "shell",
                "eval",
                r"(?i)\beval\s+",
                0.88,
                "high",
            ),
            (
                "shell",
                "command_substitution",
                r"\$\([^)]{1,1000}\)",
                0.60,
                "low",
            ),
            (
                "shell",
                "base64_decode",
                r"(?i)\bbase64\s+(?:-d|--decode)\b",
                0.94,
                "high",
            ),
        ),
    }

    for (
        category,
        indicator,
        pattern,
        confidence,
        severity,
    ) in patterns.get(family, ()):
        for line_number, line in enumerate(
            source.splitlines(),
            start=1,
        ):
            if not re.search(pattern, line):
                continue

            if len(evidence) >= MAX_EVIDENCE_ITEMS:
                return evidence

            evidence.append(
                ScriptEvidence(
                    category=category,
                    indicator=indicator,
                    evidence=line.strip()[:2_000],
                    line_number=line_number,
                    confidence=confidence,
                    severity=severity,
                    family=family,
                )
            )

    return evidence


# ---------------------------------------------------------------------------
# Structural indicators
# ---------------------------------------------------------------------------


def detect_structural_indicators(
    source: str,
    family: str,
    strings: Sequence[ScriptString],
    tokens: Sequence[ScriptToken],
    comments: Sequence[str],
) -> List[ScriptEvidence]:
    evidence: List[ScriptEvidence] = []

    lines = source.splitlines()

    # Excessive line continuation / concatenation.
    continuation_count = 0
    concatenation_count = 0

    for line_number, line in enumerate(
        lines,
        start=1,
    ):
        if re.search(r"_\s*$", line):
            continuation_count += 1

        # JavaScript/VBScript/generic string concatenation.
        if re.search(r"""(?x)(?:["'].*["'])\s*(?:\+|&)\s*(?:["']|[A-Za-z_$])""", line):
            concatenation_count += 1

    if continuation_count >= 10:
        evidence.append(
            ScriptEvidence(
                category="obfuscation",
                indicator="excessive_line_continuation",
                evidence=f"continuation_count={continuation_count}",
                confidence=0.78,
                severity="medium",
                family=family,
            )
        )

    if concatenation_count >= 10:
        evidence.append(
            ScriptEvidence(
                category="obfuscation",
                indicator="heavy_string_concatenation",
                evidence=f"concatenation_count={concatenation_count}",
                confidence=0.72,
                severity="medium",
                family=family,
            )
        )

    # Comment ratio is intentionally weak evidence.
    nonempty_lines = sum(1 for line in lines if line.strip())

    if nonempty_lines:
        comment_ratio = len(comments) / nonempty_lines

        if len(comments) >= 25 and comment_ratio >= 0.50:
            evidence.append(
                ScriptEvidence(
                    category="source_structure",
                    indicator="comment_heavy_source",
                    evidence=(
                        f"comments={len(comments)};"
                        f"nonempty_lines={nonempty_lines};"
                        f"ratio={comment_ratio:.3f}"
                    ),
                    confidence=0.45,
                    severity="low",
                    family=family,
                )
            )

    # Very long lines can indicate generated/packed source.
    long_lines = [
        (index, len(line))
        for index, line in enumerate(
            lines,
            start=1,
        )
        if len(line) >= 1_000
    ]

    if long_lines:
        evidence.append(
            ScriptEvidence(
                category="obfuscation",
                indicator="very_long_source_line",
                evidence=(
                    f"count={len(long_lines)};"
                    f"max_length={max(length for _, length in long_lines)}"
                ),
                line_number=long_lines[0][0],
                confidence=0.68,
                severity="medium",
                family=family,
            )
        )

    # Identifier density / token density.
    identifier_tokens = sum(1 for token in tokens if token.token_type == "identifier")

    if len(tokens) >= 100_000:
        evidence.append(
            ScriptEvidence(
                category="source_structure",
                indicator="large_token_volume",
                evidence=f"token_count={len(tokens)}",
                confidence=0.70,
                severity="medium",
                family=family,
            )
        )

    if identifier_tokens >= 10_000:
        evidence.append(
            ScriptEvidence(
                category="source_structure",
                indicator="high_identifier_volume",
                evidence=f"identifier_tokens={identifier_tokens}",
                confidence=0.55,
                severity="low",
                family=family,
            )
        )

    return evidence


# ---------------------------------------------------------------------------
# Capability combinations
# ---------------------------------------------------------------------------


def derive_combinations(
    evidence: Sequence[ScriptEvidence],
) -> Dict[str, Dict[str, Any]]:
    """
    Correlate independent static signals into higher-level evidence chains.
    """
    categories = {item.category for item in evidence}

    indicators = {item.indicator for item in evidence}

    return {
        "download_then_execute": {
            "present": (
                "download" in categories
                and (
                    "process_execution" in categories
                    or "dynamic_execution" in categories
                )
            ),
            "explanation": (
                "The script contains both content acquisition and "
                "execution-related indicators."
            ),
        },
        "dynamic_execution_with_obfuscation": {
            "present": (
                "dynamic_execution" in categories and "obfuscation" in categories
            ),
            "explanation": ("Dynamic execution occurs alongside obfuscation evidence."),
        },
        "network_with_com_automation": {
            "present": ("network" in categories and "com_automation" in categories),
            "explanation": (
                "Network behavior is combined with COM/ActiveX automation."
            ),
        },
        "persistence_with_execution": {
            "present": (
                "persistence" in categories and "process_execution" in categories
            ),
            "explanation": (
                "Persistence indicators occur alongside process execution."
            ),
        },
        "encoded_content_with_dynamic_execution": {
            "present": (
                "obfuscation" in categories
                and "dynamic_execution" in categories
                and (
                    "base64_operation" in indicators
                    or "base64_like_string" in indicators
                    or "character_construction" in indicators
                )
            ),
            "explanation": (
                "Encoded/constructed content is combined with dynamic " "execution."
            ),
        },
    }


# ---------------------------------------------------------------------------
# Feature vector
# ---------------------------------------------------------------------------


STABLE_INDICATORS: Tuple[str, ...] = (
    "dynamic_execution",
    "eval",
    "execute",
    "invoke",
    "activexobject",
    "createobject",
    "wscript_shell",
    "shell",
    "web_request",
    "download",
    "filesystem_access",
    "registry_access",
    "startup_location",
    "credential_terms",
    "character_construction",
    "base64_operation",
    "string_reversal",
    "environment_variable",
    "system_information",
    "security_software",
    "encoded_command",
    "iex",
    "download_cradle",
    "reflection",
    "assembly_loading",
    "amsi_reference",
    "function_constructor",
    "document_write",
    "char_code_construction",
    "getobject",
    "chr_construction",
    "powershell_invocation",
    "certutil",
    "bitsadmin",
    "rundll32",
    "regsvr32",
    "curl",
    "wget",
    "command_substitution",
    "base64_decode",
    "excessive_line_continuation",
    "heavy_string_concatenation",
    "comment_heavy_source",
    "very_long_source_line",
    "large_token_volume",
    "high_identifier_volume",
)


def _safe_name(value: str) -> str:
    return re.sub(
        r"[^a-z0-9_]+",
        "_",
        value.lower(),
    ).strip("_")


def build_feature_vector(
    analysis: ScriptAnalysis,
) -> Dict[str, Union[int, float, bool]]:
    """
    Build deterministic scalar features for ML pipelines.
    """
    evidence = analysis.evidence
    vector: Dict[str, Union[int, float, bool]] = {}

    vector["script_line_count"] = analysis.line_count
    vector["script_source_size_bytes"] = analysis.source_size_bytes
    vector["script_string_count"] = len(analysis.strings)
    vector["script_token_count"] = len(analysis.tokens)
    vector["script_url_count"] = len(analysis.urls)
    vector["script_procedure_count"] = len(analysis.procedures)
    vector["script_identifier_count"] = len(analysis.identifiers)
    vector["script_comment_count"] = len(analysis.comments)
    vector["script_evidence_count"] = len(evidence)

    for family in SCRIPT_FAMILIES:
        vector[f"script_family_{family}"] = int(analysis.family == family)

    categories = sorted({item.category for item in evidence})

    for category in categories:
        safe = _safe_name(category)

        count = sum(1 for item in evidence if item.category == category)

        vector[f"script_category_{safe}"] = int(count > 0)
        vector[f"script_category_{safe}_count"] = count

    for indicator in STABLE_INDICATORS:
        safe = _safe_name(indicator)

        count = sum(1 for item in evidence if item.indicator == indicator)

        vector[f"script_indicator_{safe}"] = int(count > 0)
        vector[f"script_indicator_{safe}_count"] = count

    # String statistics.
    lengths = [item.length for item in analysis.strings]

    vector["script_max_string_length"] = max(lengths) if lengths else 0

    vector["script_total_string_characters"] = sum(lengths)

    vector["script_mean_string_length"] = (
        sum(lengths) / len(lengths) if lengths else 0.0
    )

    vector["script_base64_like_string_count"] = sum(
        1 for item in analysis.strings if _looks_base64(item.value)
    )

    vector["script_hex_like_string_count"] = sum(
        1 for item in analysis.strings if _looks_hex(item.value)
    )

    vector["script_high_entropy_string_count"] = sum(
        1
        for item in analysis.strings
        if item.length >= 64 and _entropy(item.value) >= 4.5
    )

    # Severity.
    vector["script_high_severity_evidence_count"] = sum(
        1 for item in evidence if item.severity in {"high", "critical"}
    )

    vector["script_medium_severity_evidence_count"] = sum(
        1 for item in evidence if item.severity == "medium"
    )

    # Confidence.
    if evidence:
        vector["script_mean_evidence_confidence"] = sum(
            item.confidence for item in evidence
        ) / len(evidence)

        vector["script_max_evidence_confidence"] = max(
            item.confidence for item in evidence
        )
    else:
        vector["script_mean_evidence_confidence"] = 0.0
        vector["script_max_evidence_confidence"] = 0.0

    # Higher-level chains.
    combinations = derive_combinations(evidence)

    for name, combination in combinations.items():
        vector[f"script_chain_{_safe_name(name)}"] = int(bool(combination["present"]))

    # Conservative weighted signal.
    weights = {
        "dynamic_execution": 5.0,
        "process_execution": 5.0,
        "download": 5.0,
        "network": 3.0,
        "persistence": 5.0,
        "credential_access": 3.0,
        "com_automation": 3.0,
        "obfuscation": 3.0,
        "registry": 2.0,
        "evasion": 2.0,
        "filesystem": 1.5,
        "discovery": 1.5,
        "environment": 0.5,
    }

    score = 0.0

    for category, weight in weights.items():
        count = sum(1 for item in evidence if item.category == category)

        score += min(count, 20) * weight

    for name, combination in combinations.items():
        if combination["present"]:
            score += 5.0

    vector["script_signal_score"] = min(
        round(score, 6),
        100.0,
    )

    return vector


# ---------------------------------------------------------------------------
# Main parser
# ---------------------------------------------------------------------------


def parse_script(
    source: Union[str, bytes, bytearray],
    family: Optional[str] = None,
    filename: Optional[str] = None,
    content_type: Optional[str] = None,
) -> ScriptAnalysis:
    """
    Parse script source into static evidence.
    """
    text = _read_source(source)

    normalized_family = (
        _normalize_family(family)
        if family
        else infer_script_family(
            source=text,
            filename=filename,
            content_type=content_type,
        )
    )

    line_count = len(text.splitlines())

    if line_count > MAX_LINES:
        raise ValueError(f"script exceeds MAX_LINES={MAX_LINES}")

    source_hash = _sha256_text(text)

    strings = extract_strings(
        text,
        family=normalized_family,
    )

    tokens = tokenize(
        text,
        family=normalized_family,
    )

    urls = extract_urls(text)

    procedures = extract_procedures(
        text,
        family=normalized_family,
    )

    identifiers = extract_identifiers(tokens)

    comments = _extract_comments(
        text,
        family=normalized_family,
    )

    clean = strip_comments(
        text,
        family=normalized_family,
    )

    evidence: List[ScriptEvidence] = []

    evidence.extend(
        detect_generic_indicators(
            clean,
            normalized_family,
        )
    )

    evidence.extend(
        detect_family_indicators(
            clean,
            normalized_family,
        )
    )

    evidence.extend(
        detect_string_indicators(
            strings,
            normalized_family,
        )
    )

    evidence.extend(
        detect_structural_indicators(
            text,
            normalized_family,
            strings,
            tokens,
            comments,
        )
    )

    evidence = evidence[:MAX_EVIDENCE_ITEMS]

    combinations = derive_combinations(evidence)

    metadata: Dict[str, Any] = {
        "module": "src.extraction.script.parser",
        "static_only": True,
        "filename": filename,
        "content_type": content_type,
        "family_inferred": family is None,
        "string_count": len(strings),
        "token_count": len(tokens),
        "url_count": len(urls),
        "procedure_count": len(procedures),
        "identifier_count": len(identifiers),
        "comment_count": len(comments),
        "evidence_count": len(evidence),
        "categories": sorted({item.category for item in evidence}),
        "indicators": sorted({item.indicator for item in evidence}),
        "combinations": combinations,
    }

    analysis = ScriptAnalysis(
        family=normalized_family,
        source_hash=source_hash,
        source_size_bytes=len(
            text.encode(
                "utf-8",
                errors="replace",
            )
        ),
        line_count=line_count,
        strings=strings,
        tokens=tokens,
        urls=urls,
        procedures=procedures,
        evidence=evidence,
        identifiers=identifiers,
        comments=comments,
        metadata=metadata,
    )

    analysis.feature_vector = build_feature_vector(analysis)

    return analysis


# ---------------------------------------------------------------------------
# Compatibility/convenience APIs
# ---------------------------------------------------------------------------


def analyze_script(
    source: Union[str, bytes, bytearray],
    family: Optional[str] = None,
    filename: Optional[str] = None,
    content_type: Optional[str] = None,
) -> ScriptAnalysis:
    """Alias for parse_script()."""
    return parse_script(
        source=source,
        family=family,
        filename=filename,
        content_type=content_type,
    )


def extract_script_features(
    source: Union[str, bytes, bytearray],
    family: Optional[str] = None,
    filename: Optional[str] = None,
    content_type: Optional[str] = None,
) -> ScriptAnalysis:
    """Feature-extraction alias."""
    return parse_script(
        source=source,
        family=family,
        filename=filename,
        content_type=content_type,
    )


def extract_feature_vector(
    source: Union[str, bytes, bytearray],
    family: Optional[str] = None,
    filename: Optional[str] = None,
    content_type: Optional[str] = None,
) -> Dict[str, Union[int, float, bool]]:
    """Return the scalar feature vector."""
    return parse_script(
        source=source,
        family=family,
        filename=filename,
        content_type=content_type,
    ).feature_vector


def extract_script_feature_vector(
    source: Union[str, bytes, bytearray],
    family: Optional[str] = None,
    filename: Optional[str] = None,
    content_type: Optional[str] = None,
) -> Dict[str, Union[int, float, bool]]:
    """Explicit feature-vector alias."""
    return extract_feature_vector(
        source,
        family=family,
        filename=filename,
        content_type=content_type,
    )


def script_feature_names() -> List[str]:
    """
    Return deterministic feature names.

    The parser uses an empty analysis so dynamically present categories do
    not affect schema generation.
    """
    empty = ScriptAnalysis(
        family="generic",
        source_hash="",
        source_size_bytes=0,
        line_count=0,
    )

    empty.feature_vector = build_feature_vector(empty)

    return sorted(empty.feature_vector.keys())


def build_feature_schema() -> Dict[str, Any]:
    """Return a machine-readable parser feature schema."""
    names = script_feature_names()

    features: List[Dict[str, str]] = []

    for name in names:
        if "mean_" in name or name.endswith("_score") or "confidence" in name:
            feature_type = "float"
        else:
            feature_type = "integer"

        features.append(
            {
                "name": name,
                "type": feature_type,
            }
        )

    return {
        "name": "script_parser_features",
        "version": "1.0",
        "static_only": True,
        "feature_count": len(features),
        "features": features,
    }


def vectorize_features(
    analysis_or_source: Union[
        ScriptAnalysis,
        str,
        bytes,
        bytearray,
    ],
    feature_names: Optional[Sequence[str]] = None,
) -> List[Union[int, float, bool]]:
    """
    Convert a script analysis to a deterministic ordered vector.
    """
    if isinstance(
        analysis_or_source,
        ScriptAnalysis,
    ):
        analysis = analysis_or_source
    else:
        analysis = parse_script(analysis_or_source)

    names = list(feature_names) if feature_names is not None else script_feature_names()

    return [
        analysis.feature_vector.get(
            name,
            0,
        )
        for name in names
    ]


# ---------------------------------------------------------------------------
# Query helpers
# ---------------------------------------------------------------------------


def has_indicator(
    analysis_or_source: Union[
        ScriptAnalysis,
        str,
        bytes,
        bytearray,
    ],
    indicator: str,
) -> bool:
    """Return whether a named static indicator is present."""
    analysis = (
        analysis_or_source
        if isinstance(
            analysis_or_source,
            ScriptAnalysis,
        )
        else parse_script(analysis_or_source)
    )

    normalized = indicator.lower()

    return any(item.indicator.lower() == normalized for item in analysis.evidence)


def has_category(
    analysis_or_source: Union[
        ScriptAnalysis,
        str,
        bytes,
        bytearray,
    ],
    category: str,
) -> bool:
    """Return whether a category is present."""
    analysis = (
        analysis_or_source
        if isinstance(
            analysis_or_source,
            ScriptAnalysis,
        )
        else parse_script(analysis_or_source)
    )

    normalized = category.lower()

    return any(item.category.lower() == normalized for item in analysis.evidence)


def evidence_by_category(
    analysis_or_source: Union[
        ScriptAnalysis,
        str,
        bytes,
        bytearray,
    ],
    category: str,
) -> List[ScriptEvidence]:
    """Return evidence matching a category."""
    analysis = (
        analysis_or_source
        if isinstance(
            analysis_or_source,
            ScriptAnalysis,
        )
        else parse_script(analysis_or_source)
    )

    normalized = category.lower()

    return [item for item in analysis.evidence if item.category.lower() == normalized]


def evidence_by_indicator(
    analysis_or_source: Union[
        ScriptAnalysis,
        str,
        bytes,
        bytearray,
    ],
    indicator: str,
) -> List[ScriptEvidence]:
    """Return evidence matching an indicator."""
    analysis = (
        analysis_or_source
        if isinstance(
            analysis_or_source,
            ScriptAnalysis,
        )
        else parse_script(analysis_or_source)
    )

    normalized = indicator.lower()

    return [item for item in analysis.evidence if item.indicator.lower() == normalized]


def high_risk_evidence(
    analysis_or_source: Union[
        ScriptAnalysis,
        str,
        bytes,
        bytearray,
    ],
) -> List[ScriptEvidence]:
    """Return high/critical severity static evidence."""
    analysis = (
        analysis_or_source
        if isinstance(
            analysis_or_source,
            ScriptAnalysis,
        )
        else parse_script(analysis_or_source)
    )

    return [
        item
        for item in analysis.evidence
        if item.severity
        in {
            "high",
            "critical",
        }
    ]


def present_combinations(
    analysis_or_source: Union[
        ScriptAnalysis,
        str,
        bytes,
        bytearray,
    ],
) -> List[str]:
    """Return present higher-level evidence chains."""
    analysis = (
        analysis_or_source
        if isinstance(
            analysis_or_source,
            ScriptAnalysis,
        )
        else parse_script(analysis_or_source)
    )

    combinations = analysis.metadata.get(
        "combinations",
        {},
    )

    return sorted(
        name
        for name, value in combinations.items()
        if isinstance(value, Mapping) and value.get("present")
    )


# ---------------------------------------------------------------------------
# Serialization and summaries
# ---------------------------------------------------------------------------


def analysis_to_dict(
    analysis: ScriptAnalysis,
) -> Dict[str, Any]:
    """Serialize an analysis to JSON-compatible data."""
    return asdict(analysis)


def summarize_script(
    analysis_or_source: Union[
        ScriptAnalysis,
        str,
        bytes,
        bytearray,
    ],
) -> Dict[str, Any]:
    """
    Return a compact triage summary.
    """
    analysis = (
        analysis_or_source
        if isinstance(
            analysis_or_source,
            ScriptAnalysis,
        )
        else parse_script(analysis_or_source)
    )

    high_risk = high_risk_evidence(analysis)

    return {
        "family": analysis.family,
        "source_sha256": analysis.source_hash,
        "source_size_bytes": analysis.source_size_bytes,
        "line_count": analysis.line_count,
        "string_count": len(analysis.strings),
        "token_count": len(analysis.tokens),
        "url_count": len(analysis.urls),
        "procedure_count": len(analysis.procedures),
        "identifier_count": len(analysis.identifiers),
        "comment_count": len(analysis.comments),
        "evidence_count": len(analysis.evidence),
        "high_risk_evidence_count": len(high_risk),
        "categories": sorted({item.category for item in analysis.evidence}),
        "indicators": sorted({item.indicator for item in analysis.evidence}),
        "present_combinations": present_combinations(analysis),
        "signal_score": analysis.feature_vector.get(
            "script_signal_score",
            0.0,
        ),
    }


# ---------------------------------------------------------------------------
# Iterators
# ---------------------------------------------------------------------------


def iter_evidence(
    source: Union[str, bytes, bytearray],
    family: Optional[str] = None,
    filename: Optional[str] = None,
) -> Iterator[ScriptEvidence]:
    """Yield static evidence lazily."""
    analysis = parse_script(
        source,
        family=family,
        filename=filename,
    )

    yield from analysis.evidence


def iter_strings(
    source: Union[str, bytes, bytearray],
    family: str = "generic",
) -> Iterator[ScriptString]:
    """Yield strings lazily."""
    yield from extract_strings(
        source,
        family=family,
    )


def iter_urls(
    source: Union[str, bytes, bytearray],
) -> Iterator[ScriptURL]:
    """Yield URLs lazily."""
    yield from extract_urls(source)


def iter_procedures(
    source: Union[str, bytes, bytearray],
    family: str = "generic",
) -> Iterator[ScriptProcedure]:
    """Yield procedures lazily."""
    yield from extract_procedures(
        source,
        family=family,
    )


def iter_script_analyses(
    sources: Iterable[Union[str, bytes, bytearray]],
    family: Optional[str] = None,
) -> Iterator[ScriptAnalysis]:
    """Analyze multiple scripts lazily."""
    for source in sources:
        yield parse_script(
            source,
            family=family,
        )


# ---------------------------------------------------------------------------
# Compatibility aliases
# ---------------------------------------------------------------------------


parse = parse_script
analyze = parse_script
extract = parse_script


__all__ = [
    "MAX_SOURCE_SIZE",
    "MAX_LINES",
    "MAX_EVIDENCE_ITEMS",
    "MAX_TOKENS",
    "MAX_STRINGS",
    "MAX_URLS",
    "MAX_IDENTIFIERS",
    "MAX_PROCEDURES",
    "SCRIPT_FAMILIES",
    "EXTENSION_TO_FAMILY",
    "ScriptString",
    "ScriptToken",
    "ScriptURL",
    "ScriptProcedure",
    "ScriptEvidence",
    "ScriptAnalysis",
    "infer_script_family",
    "strip_comments",
    "extract_strings",
    "tokenize",
    "extract_urls",
    "extract_procedures",
    "extract_identifiers",
    "detect_generic_indicators",
    "detect_family_indicators",
    "detect_string_indicators",
    "detect_structural_indicators",
    "derive_combinations",
    "build_feature_vector",
    "parse_script",
    "analyze_script",
    "extract_script_features",
    "extract_feature_vector",
    "extract_script_feature_vector",
    "script_feature_names",
    "build_feature_schema",
    "vectorize_features",
    "has_indicator",
    "has_category",
    "evidence_by_category",
    "evidence_by_indicator",
    "high_risk_evidence",
    "present_combinations",
    "analysis_to_dict",
    "summarize_script",
    "iter_evidence",
    "iter_strings",
    "iter_urls",
    "iter_procedures",
    "iter_script_analyses",
    "parse",
    "analyze",
    "extract",
]
