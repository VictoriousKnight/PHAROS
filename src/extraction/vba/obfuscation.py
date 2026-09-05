"""
Static VBA obfuscation analysis.

This module detects source-level obfuscation and concealment techniques in
VBA without executing, evaluating, or deobfuscating the macro.

The analyzer is designed for defensive malware analysis and CDR workflows.

It identifies:
    - excessive string concatenation;
    - Chr / ChrW / Chr$ construction;
    - Asc / AscW reconstruction;
    - hexadecimal / octal character construction;
    - Replace / Split / Join based string transformation;
    - Base64-like and hexadecimal encoded material;
    - string reversal;
    - case manipulation;
    - dynamic variable/name construction;
    - VBA line continuations;
    - excessive identifier irregularity;
    - unusual string fragmentation;
    - comments/whitespace used to obscure source structure;
    - suspicious use of VBA intrinsic functions associated with
      transformation or dynamic resolution;
    - combinations of obfuscation + execution indicators.

IMPORTANT:
    This module never:
      - executes VBA;
      - evaluates expressions;
      - invokes COM;
      - calls Windows APIs;
      - decodes an attacker payload;
      - downloads content;
      - launches processes;
      - writes reconstructed payloads to disk.

The goal is evidence extraction, not payload recovery.

Integration:
    VBA source
        -> parser.py
        -> obfuscation.py
        -> capabilities.py / execution.py / api_features.py
        -> feature_pipeline.py
        -> ML / CDR policy
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
import hashlib
import math
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
MAX_STRINGS = 50_000
MAX_IDENTIFIERS = 100_000
MAX_TRANSFORM_RECORDS = 50_000


# ---------------------------------------------------------------------------
# Taxonomy
# ---------------------------------------------------------------------------

OBFUSCATION_CATEGORIES: Tuple[str, ...] = (
    "string_encoding",
    "string_fragmentation",
    "string_transformation",
    "character_construction",
    "numeric_encoding",
    "identifier_obfuscation",
    "control_flow_obfuscation",
    "whitespace_obfuscation",
    "comment_obfuscation",
    "dynamic_name_construction",
    "encoded_blob",
    "environment_dependent",
    "execution_obfuscation",
)


CATEGORY_WEIGHTS: Dict[str, float] = {
    "string_encoding": 3.0,
    "string_fragmentation": 2.0,
    "string_transformation": 2.5,
    "character_construction": 3.0,
    "numeric_encoding": 2.5,
    "identifier_obfuscation": 1.5,
    "control_flow_obfuscation": 2.0,
    "whitespace_obfuscation": 0.5,
    "comment_obfuscation": 0.5,
    "dynamic_name_construction": 3.0,
    "encoded_blob": 3.5,
    "environment_dependent": 1.0,
    "execution_obfuscation": 4.0,
}


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class VBAObfuscationEvidence:
    """
    One static obfuscation observation.
    """

    category: str
    indicator: str
    evidence: str
    line_number: Optional[int] = None
    procedure: Optional[str] = None
    confidence: float = 1.0
    severity: str = "medium"

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "confidence",
            max(0.0, min(1.0, float(self.confidence))),
        )
        object.__setattr__(
            self,
            "severity",
            str(self.severity or "medium").lower(),
        )


@dataclass(frozen=True)
class VBAStringRecord:
    """
    A statically extracted VBA string literal.

    The actual literal value is retained only in bounded form.
    """

    value: str
    line_number: int
    length: int
    entropy: float
    is_base64_like: bool
    is_hex_like: bool
    is_url_like: bool
    is_path_like: bool
    is_command_like: bool
    is_fragment_like: bool


@dataclass(frozen=True)
class VBATransformationRecord:
    """
    A static transformation-function observation.
    """

    function_name: str
    normalized_name: str
    category: str
    line_number: int
    evidence: str
    confidence: float = 1.0


@dataclass
class VBAObfuscationAnalysis:
    """
    Complete static obfuscation analysis.
    """

    evidence: List[VBAObfuscationEvidence] = field(default_factory=list)
    strings: List[VBAStringRecord] = field(default_factory=list)
    transformations: List[VBATransformationRecord] = field(default_factory=list)
    categories: Dict[str, int] = field(default_factory=dict)
    indicators: List[str] = field(default_factory=list)
    feature_vector: Dict[str, Union[int, float, bool]] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Generic helpers
# ---------------------------------------------------------------------------


def _read_source(source: Union[str, bytes, bytearray]) -> str:
    if isinstance(source, str):
        encoded_size = len(source.encode("utf-8", errors="ignore"))
        if encoded_size > MAX_SOURCE_SIZE:
            raise ValueError(f"VBA source exceeds MAX_SOURCE_SIZE={MAX_SOURCE_SIZE}")
        return source

    if isinstance(source, (bytes, bytearray)):
        if len(source) > MAX_SOURCE_SIZE:
            raise ValueError(f"VBA source exceeds MAX_SOURCE_SIZE={MAX_SOURCE_SIZE}")
        return bytes(source).decode("utf-8", errors="replace")

    raise TypeError("source must be str, bytes, or bytearray")


def _normalize_name(value: str) -> str:
    return re.sub(r"\s+", "", str(value or "").strip().lower())


def _clamp(value: float, minimum: float = 0.0, maximum: float = 1.0) -> float:
    return max(minimum, min(maximum, float(value)))


def _entropy(value: str) -> float:
    """
    Shannon entropy of a string.
    """
    if not value:
        return 0.0

    counts = Counter(value)
    length = len(value)

    return -sum(
        (count / length) * math.log2(count / length) for count in counts.values()
    )


def _strip_vba_comments(source: str) -> str:
    """
    Remove ordinary VBA comments while preserving quoted strings.
    """
    output: List[str] = []

    for raw_line in source.splitlines():
        line = raw_line
        in_string = False
        comment_index: Optional[int] = None
        i = 0

        while i < len(line):
            char = line[i]

            if char == '"':
                if in_string and i + 1 < len(line) and line[i + 1] == '"':
                    i += 2
                    continue

                in_string = not in_string
                i += 1
                continue

            if not in_string and char == "'":
                comment_index = i
                break

            i += 1

        if comment_index is not None:
            line = line[:comment_index]

        stripped = line.lstrip()

        if re.match(r"(?i)^Rem(?:\s|$)", stripped):
            leading_length = len(line) - len(stripped)
            line = line[:leading_length]

        output.append(line)

    return "\n".join(output)


def _mask_strings(source: str) -> str:
    """
    Replace string contents with placeholders while retaining their spans.

    This is useful when detecting syntax-level obfuscation without allowing
    string contents to influence unrelated regexes.
    """
    output: List[str] = []

    for line in source.splitlines():
        result: List[str] = []
        in_string = False
        i = 0

        while i < len(line):
            char = line[i]

            if char == '"':
                if in_string:
                    if i + 1 < len(line) and line[i + 1] == '"':
                        result.append("SS")
                        i += 2
                        continue

                    result.append('"')
                    in_string = False
                    i += 1
                    continue

                result.append('"')
                in_string = True
                i += 1
                continue

            if in_string:
                result.append("S")
            else:
                result.append(char)

            i += 1

        output.append("".join(result))

    return "\n".join(output)


def _append_evidence(
    output: List[VBAObfuscationEvidence],
    *,
    category: str,
    indicator: str,
    evidence: str,
    line_number: Optional[int],
    procedure: Optional[str],
    confidence: float,
    severity: str,
) -> None:
    if len(output) >= MAX_EVIDENCE_ITEMS:
        return

    output.append(
        VBAObfuscationEvidence(
            category=category,
            indicator=indicator,
            evidence=evidence[:2_000],
            line_number=line_number,
            procedure=procedure,
            confidence=confidence,
            severity=severity,
        )
    )


# ---------------------------------------------------------------------------
# VBA string extraction
# ---------------------------------------------------------------------------

_STRING_RE = re.compile(
    r'"((?:""|[^"])*)"',
    re.DOTALL,
)


def _unescape_vba_string(value: str) -> str:
    return value.replace('""', '"')


def _is_base64_like(value: str) -> bool:
    compact = re.sub(r"\s+", "", value)

    if len(compact) < 16:
        return False

    if len(compact) % 4 not in {0, 2, 3}:
        return False

    return bool(
        re.fullmatch(
            r"[A-Za-z0-9+/]+={0,2}",
            compact,
        )
    )


def _is_hex_like(value: str) -> bool:
    compact = re.sub(r"[\s,\\xX]+", "", value)

    if len(compact) < 12:
        return False

    return bool(re.fullmatch(r"[0-9A-Fa-f]+", compact))


def _is_url_like(value: str) -> bool:
    return bool(
        re.search(
            r"(?i)\b(?:https?|ftp)://[^\s\"']+",
            value,
        )
    )


def _is_path_like(value: str) -> bool:
    return bool(
        re.search(
            r"""(?ix)
            (?:[A-Z]:\\)
            |
            (?:\\\\[^\\\s]+\\)
            |
            (?:/etc/|/tmp/|/var/|/usr/|/home/)
            """,
            value,
        )
    )


def _is_command_like(value: str) -> bool:
    return bool(
        re.search(
            r"""(?ix)\b(
                cmd(?:\.exe)?
                |powershell(?:\.exe)?
                |pwsh(?:\.exe)?
                |wscript(?:\.exe)?
                |cscript(?:\.exe)?
                |mshta(?:\.exe)?
                |rundll32(?:\.exe)?
                |regsvr32(?:\.exe)?
                |wmic(?:\.exe)?
                |bitsadmin(?:\.exe)?
            )\b""",
            value,
        )
    )


def extract_string_records(
    source: Union[str, bytes, bytearray],
) -> List[VBAStringRecord]:
    """
    Extract bounded VBA string literals.
    """
    text = _read_source(source)
    records: List[VBAStringRecord] = []

    for line_number, line in enumerate(text.splitlines(), start=1):
        for match in _STRING_RE.finditer(line):
            if len(records) >= MAX_STRINGS:
                return records

            value = _unescape_vba_string(match.group(1))

            # Keep pathological literals bounded.
            bounded_value = value[:8_192]

            fragment_like = len(bounded_value) <= 4 or (
                len(bounded_value) <= 12
                and not re.search(
                    r"(?i)\b(?:the|and|http|www|windows|document)\b",
                    bounded_value,
                )
            )

            records.append(
                VBAStringRecord(
                    value=bounded_value,
                    line_number=line_number,
                    length=len(value),
                    entropy=round(_entropy(bounded_value), 6),
                    is_base64_like=_is_base64_like(bounded_value),
                    is_hex_like=_is_hex_like(bounded_value),
                    is_url_like=_is_url_like(bounded_value),
                    is_path_like=_is_path_like(bounded_value),
                    is_command_like=_is_command_like(bounded_value),
                    is_fragment_like=fragment_like,
                )
            )

    return records


# ---------------------------------------------------------------------------
# Character construction
# ---------------------------------------------------------------------------

CHARACTER_FUNCTIONS: Dict[str, Dict[str, Any]] = {
    "chr": {
        "category": "character_construction",
        "confidence": 0.98,
        "severity": "medium",
    },
    "chr$": {
        "category": "character_construction",
        "confidence": 0.98,
        "severity": "medium",
    },
    "chrw": {
        "category": "character_construction",
        "confidence": 0.99,
        "severity": "medium",
    },
    "chrw$": {
        "category": "character_construction",
        "confidence": 0.99,
        "severity": "medium",
    },
    "asc": {
        "category": "numeric_encoding",
        "confidence": 0.90,
        "severity": "low",
    },
    "ascw": {
        "category": "numeric_encoding",
        "confidence": 0.90,
        "severity": "low",
    },
}


def detect_character_construction(
    source: str,
    procedures: Optional[Mapping[int, str]] = None,
) -> List[VBAObfuscationEvidence]:
    """
    Detect Chr/ChrW/Asc/AscW-style character manipulation.
    """
    evidence: List[VBAObfuscationEvidence] = []

    pattern = re.compile(r"(?i)\b(ChrW?\$?|AscW?)\s*\(")

    for line_number, line in enumerate(source.splitlines(), start=1):
        matches = list(pattern.finditer(line))

        if not matches:
            continue

        for match in matches:
            function_name = _normalize_name(match.group(1))
            info = CHARACTER_FUNCTIONS.get(
                function_name,
                {
                    "category": "character_construction",
                    "confidence": 0.90,
                    "severity": "medium",
                },
            )

            _append_evidence(
                evidence,
                category=info["category"],
                indicator=function_name,
                evidence=line.strip(),
                line_number=line_number,
                procedure=(procedures.get(line_number) if procedures else None),
                confidence=info["confidence"],
                severity=info["severity"],
            )

    return evidence


# ---------------------------------------------------------------------------
# Transformation functions
# ---------------------------------------------------------------------------

TRANSFORMATION_FUNCTIONS: Dict[str, Tuple[str, float, str]] = {
    "replace": ("string_transformation", 0.90, "medium"),
    "replace$": ("string_transformation", 0.92, "medium"),
    "split": ("string_transformation", 0.70, "low"),
    "join": ("string_transformation", 0.70, "low"),
    "strreverse": ("string_transformation", 0.96, "medium"),
    "lcase": ("string_transformation", 0.45, "low"),
    "ucase": ("string_transformation", 0.45, "low"),
    "strconv": ("string_transformation", 0.65, "low"),
    "format": ("string_transformation", 0.35, "low"),
    "mid": ("string_transformation", 0.45, "low"),
    "left": ("string_transformation", 0.35, "low"),
    "right": ("string_transformation", 0.35, "low"),
    "trim": ("string_transformation", 0.20, "low"),
    "trim$": ("string_transformation", 0.20, "low"),
}


def extract_transformation_records(
    source: Union[str, bytes, bytearray],
) -> List[VBATransformationRecord]:
    """
    Identify intrinsic VBA functions commonly involved in string
    transformation.
    """
    text = _strip_vba_comments(_read_source(source))
    records: List[VBATransformationRecord] = []

    function_names = sorted(
        TRANSFORMATION_FUNCTIONS,
        key=len,
        reverse=True,
    )

    pattern = re.compile(
        r"(?i)\b(" + "|".join(re.escape(name) for name in function_names) + r")\s*\("
    )

    for line_number, line in enumerate(text.splitlines(), start=1):
        for match in pattern.finditer(line):
            if len(records) >= MAX_TRANSFORM_RECORDS:
                return records

            name = _normalize_name(match.group(1))
            category, confidence, _severity = TRANSFORMATION_FUNCTIONS[name]

            records.append(
                VBATransformationRecord(
                    function_name=match.group(1),
                    normalized_name=name,
                    category=category,
                    line_number=line_number,
                    evidence=line.strip()[:2_000],
                    confidence=confidence,
                )
            )

    return records


# ---------------------------------------------------------------------------
# String fragmentation
# ---------------------------------------------------------------------------


def _string_literal_count(line: str) -> int:
    return len(_STRING_RE.findall(line))


def _plus_operator_count(line: str) -> int:
    """
    Count + concatenation operators outside string literals.
    """
    count = 0
    in_string = False
    i = 0

    while i < len(line):
        char = line[i]

        if char == '"':
            if in_string and i + 1 < len(line) and line[i + 1] == '"':
                i += 2
                continue

            in_string = not in_string
            i += 1
            continue

        if not in_string and char == "+":
            count += 1

        i += 1

    return count


def _ampersand_operator_count(line: str) -> int:
    """
    Count & concatenation operators outside string literals.
    """
    count = 0
    in_string = False
    i = 0

    while i < len(line):
        char = line[i]

        if char == '"':
            if in_string and i + 1 < len(line) and line[i + 1] == '"':
                i += 2
                continue

            in_string = not in_string
            i += 1
            continue

        if not in_string and char == "&":
            count += 1

        i += 1

    return count


def detect_string_fragmentation(
    source: str,
) -> List[VBAObfuscationEvidence]:
    """
    Detect unusually fragmented string construction.

    Normal VBA concatenation is common, so the detector becomes stronger
    when many short literals are combined on one line.
    """
    evidence: List[VBAObfuscationEvidence] = []

    for line_number, line in enumerate(source.splitlines(), start=1):
        literal_count = _string_literal_count(line)
        plus_count = _plus_operator_count(line)
        amp_count = _ampersand_operator_count(line)

        operators = plus_count + amp_count

        if literal_count < 3 or operators < 2:
            continue

        strings = [
            _unescape_vba_string(match.group(1)) for match in _STRING_RE.finditer(line)
        ]

        average_length = (
            sum(len(value) for value in strings) / len(strings) if strings else 0.0
        )

        if literal_count >= 8:
            severity = "high"
            confidence = 0.95
        elif literal_count >= 5:
            severity = "medium"
            confidence = 0.90
        elif average_length <= 3:
            severity = "medium"
            confidence = 0.88
        else:
            severity = "low"
            confidence = 0.75

        _append_evidence(
            evidence,
            category="string_fragmentation",
            indicator="fragmented_string_construction",
            evidence=line.strip(),
            line_number=line_number,
            procedure=None,
            confidence=confidence,
            severity=severity,
        )

    return evidence


# ---------------------------------------------------------------------------
# Encoded material
# ---------------------------------------------------------------------------


def detect_encoded_strings(
    records: Sequence[VBAStringRecord],
) -> List[VBAObfuscationEvidence]:
    """
    Identify strings that have Base64-like or hexadecimal characteristics.

    This does not decode the content.
    """
    evidence: List[VBAObfuscationEvidence] = []

    for record in records:
        if record.is_base64_like:
            severity = "medium"

            if record.length >= 64:
                severity = "high"

            _append_evidence(
                evidence,
                category="string_encoding",
                indicator="base64_like_string",
                evidence=record.value,
                line_number=record.line_number,
                procedure=None,
                confidence=0.75,
                severity=severity,
            )

        if record.is_hex_like:
            severity = "medium"

            if record.length >= 64:
                severity = "high"

            _append_evidence(
                evidence,
                category="encoded_blob",
                indicator="hex_like_string",
                evidence=record.value,
                line_number=record.line_number,
                procedure=None,
                confidence=0.82,
                severity=severity,
            )

    return evidence


# ---------------------------------------------------------------------------
# Numeric encoding
# ---------------------------------------------------------------------------


_NUMERIC_CHAR_RE = re.compile(r"(?i)\bChrW?\$?\s*\(\s*(?:&H[0-9A-F]+|\d+)\s*\)")

_NUMERIC_SEQUENCE_RE = re.compile(r"""(?ix)
    (?:
        \b(?:Chr|ChrW)\s*\(\s*(?:&H[0-9A-F]+|\d+)\s*\)
        \s*(?:&|$)
    ){3,}
    """)


def detect_numeric_encoding(
    source: str,
) -> List[VBAObfuscationEvidence]:
    """
    Detect numeric character construction and repeated numeric encoding.
    """
    evidence: List[VBAObfuscationEvidence] = []

    for line_number, line in enumerate(source.splitlines(), start=1):
        individual = list(_NUMERIC_CHAR_RE.finditer(line))

        if individual:
            severity = "medium"
            confidence = 0.90

            if len(individual) >= 6:
                severity = "high"
                confidence = 0.97

            _append_evidence(
                evidence,
                category="numeric_encoding",
                indicator="numeric_character_construction",
                evidence=line.strip(),
                line_number=line_number,
                procedure=None,
                confidence=confidence,
                severity=severity,
            )

        if _NUMERIC_SEQUENCE_RE.search(line):
            _append_evidence(
                evidence,
                category="numeric_encoding",
                indicator="repeated_numeric_character_sequence",
                evidence=line.strip(),
                line_number=line_number,
                procedure=None,
                confidence=0.98,
                severity="high",
            )

    return evidence


# ---------------------------------------------------------------------------
# Identifier analysis
# ---------------------------------------------------------------------------


_IDENTIFIER_RE = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*\b")


_VBA_KEYWORDS = {
    "sub",
    "function",
    "property",
    "get",
    "let",
    "set",
    "end",
    "if",
    "then",
    "else",
    "elseif",
    "for",
    "each",
    "next",
    "do",
    "loop",
    "while",
    "wend",
    "select",
    "case",
    "with",
    "goto",
    "gosub",
    "return",
    "call",
    "dim",
    "redim",
    "preserve",
    "as",
    "new",
    "set",
    "public",
    "private",
    "friend",
    "static",
    "const",
    "option",
    "explicit",
    "on",
    "error",
    "resume",
    "exit",
    "stop",
    "debug",
    "rem",
    "true",
    "false",
    "nothing",
    "empty",
    "null",
    "me",
    "application",
    "activeworkbook",
    "activedocument",
    "thisworkbook",
    "thisdocument",
}


def _identifier_complexity(identifier: str) -> float:
    """
    Estimate irregularity of an identifier.

    This is deliberately heuristic and should be treated as weak evidence.
    """
    if not identifier:
        return 0.0

    score = 0.0

    if len(identifier) >= 18:
        score += 0.25

    if re.search(r"[A-Z].*[A-Z]", identifier):
        score += 0.10

    if re.search(r"\d", identifier):
        score += 0.15

    if re.search(r"[_$]{2,}", identifier):
        score += 0.20

    if re.search(r"(?i)(?:lI|Il|O0|0O)", identifier):
        score += 0.25

    if len(set(identifier.lower())) <= 3 and len(identifier) >= 6:
        score += 0.25

    if not re.search(r"[aeiou]", identifier.lower()) and len(identifier) >= 7:
        score += 0.20

    return _clamp(score)


def analyze_identifiers(
    source: str,
) -> Tuple[List[VBAObfuscationEvidence], Dict[str, Any]]:
    """
    Analyze identifier irregularity without assuming that unusual names are
    malicious.
    """
    evidence: List[VBAObfuscationEvidence] = []
    identifiers: List[str] = []

    for line_number, line in enumerate(source.splitlines(), start=1):
        for match in _IDENTIFIER_RE.finditer(line):
            identifier = match.group(0)

            if len(identifiers) >= MAX_IDENTIFIERS:
                break

            normalized = identifier.lower()

            if normalized in _VBA_KEYWORDS:
                continue

            identifiers.append(identifier)

    if not identifiers:
        return evidence, {
            "identifier_count": 0,
            "mean_identifier_length": 0.0,
            "suspicious_identifier_count": 0,
        }

    suspicious = 0
    scores: List[float] = []

    for identifier in identifiers:
        score = _identifier_complexity(identifier)
        scores.append(score)

        if score >= 0.60:
            suspicious += 1

    ratio = suspicious / len(identifiers)

    if suspicious >= 5 and ratio >= 0.15:
        _append_evidence(
            evidence,
            category="identifier_obfuscation",
            indicator="irregular_identifier_set",
            evidence=(
                f"suspicious={suspicious}; "
                f"total={len(identifiers)}; "
                f"ratio={ratio:.3f}"
            ),
            line_number=None,
            procedure=None,
            confidence=_clamp(0.60 + ratio),
            severity="medium" if ratio < 0.35 else "high",
        )

    metadata = {
        "identifier_count": len(identifiers),
        "mean_identifier_length": round(
            sum(len(item) for item in identifiers) / len(identifiers),
            6,
        ),
        "suspicious_identifier_count": suspicious,
        "suspicious_identifier_ratio": round(ratio, 6),
        "max_identifier_complexity": round(
            max(scores) if scores else 0.0,
            6,
        ),
    }

    return evidence, metadata


# ---------------------------------------------------------------------------
# Whitespace and line continuation analysis
# ---------------------------------------------------------------------------


def detect_whitespace_and_continuations(
    source: str,
) -> List[VBAObfuscationEvidence]:
    """
    Detect excessive line continuations and unusual whitespace patterns.
    """
    evidence: List[VBAObfuscationEvidence] = []

    lines = source.splitlines()

    continuation_count = 0

    for line_number, line in enumerate(lines, start=1):
        stripped = line.rstrip()

        if re.search(r"_\s*$", stripped):
            continuation_count += 1

        # Extremely large whitespace runs can make manual inspection harder.
        if re.search(r"[ \t]{20,}", line):
            _append_evidence(
                evidence,
                category="whitespace_obfuscation",
                indicator="excessive_whitespace",
                evidence=line.strip()[:2_000],
                line_number=line_number,
                procedure=None,
                confidence=0.70,
                severity="low",
            )

    if continuation_count >= 10:
        severity = "medium" if continuation_count < 30 else "high"

        _append_evidence(
            evidence,
            category="string_fragmentation",
            indicator="excessive_line_continuations",
            evidence=f"line_continuations={continuation_count}",
            line_number=None,
            procedure=None,
            confidence=0.90,
            severity=severity,
        )

    return evidence


# ---------------------------------------------------------------------------
# Comment analysis
# ---------------------------------------------------------------------------


def detect_comment_obfuscation(
    source: str,
) -> List[VBAObfuscationEvidence]:
    """
    Detect unusually comment-heavy or comment-structured source.

    Comments alone are not suspicious. This is a weak static signal intended
    to identify source that deserves correlation with stronger indicators.
    """
    evidence: List[VBAObfuscationEvidence] = []

    lines = source.splitlines()

    comment_lines = 0
    total_nonempty = 0

    for line in lines:
        stripped = line.strip()

        if not stripped:
            continue

        total_nonempty += 1

        if stripped.startswith("'") or re.match(
            r"(?i)^Rem(?:\s|$)",
            stripped,
        ):
            comment_lines += 1

    if total_nonempty == 0:
        return evidence

    ratio = comment_lines / total_nonempty

    if comment_lines >= 25 and ratio >= 0.50:
        _append_evidence(
            evidence,
            category="comment_obfuscation",
            indicator="comment_heavy_source",
            evidence=(
                f"comment_lines={comment_lines}; "
                f"nonempty_lines={total_nonempty}; "
                f"ratio={ratio:.3f}"
            ),
            line_number=None,
            procedure=None,
            confidence=0.55,
            severity="low",
        )

    return evidence


# ---------------------------------------------------------------------------
# Dynamic-name construction
# ---------------------------------------------------------------------------


_DYNAMIC_NAME_PATTERNS: Tuple[Tuple[str, str, float, str], ...] = (
    (
        "getobject_with_constructed_name",
        r"(?i)\bGetObject\s*\([^)]*(?:&|\+|ChrW?\$?)",
        "dynamic_name_construction",
        0.90,
    ),
    (
        "createobject_with_constructed_name",
        r"(?i)\bCreateObject\s*\([^)]*(?:&|\+|ChrW?\$?)",
        "dynamic_name_construction",
        0.92,
    ),
    (
        "application_run_with_constructed_name",
        r"(?i)\bApplication\s*\.\s*Run\s+[^,\r\n]*(?:&|\+|ChrW?\$?)",
        "execution_obfuscation",
        0.96,
    ),
    (
        "callbyname_with_constructed_name",
        r"(?i)\bCallByName\s*\([^)]*(?:&|\+|ChrW?\$?)",
        "dynamic_name_construction",
        0.96,
    ),
)


def detect_dynamic_name_construction(
    source: str,
) -> List[VBAObfuscationEvidence]:
    evidence: List[VBAObfuscationEvidence] = []

    for line_number, line in enumerate(source.splitlines(), start=1):
        for indicator, pattern, category, confidence in _DYNAMIC_NAME_PATTERNS:
            if re.search(pattern, line):
                _append_evidence(
                    evidence,
                    category=category,
                    indicator=indicator,
                    evidence=line.strip(),
                    line_number=line_number,
                    procedure=None,
                    confidence=confidence,
                    severity=(
                        "high" if category == "execution_obfuscation" else "medium"
                    ),
                )

    return evidence


# ---------------------------------------------------------------------------
# Environment-dependent construction
# ---------------------------------------------------------------------------


_ENVIRONMENT_PATTERNS: Tuple[Tuple[str, str, float], ...] = (
    (
        "environ",
        r"(?i)\bEnviron\s*(?:\(|\$)",
        0.85,
    ),
    (
        "application_path",
        r"(?i)\bApplication\s*\.\s*(?:Path|UserName|OperatingSystem|Version)\b",
        0.55,
    ),
    (
        "environment_variable",
        r"(?i)\b(?:WScript\s*\.\s*)?Shell\s*\.\s*Environment\s*\(",
        0.80,
    ),
)


def detect_environment_dependent_logic(
    source: str,
) -> List[VBAObfuscationEvidence]:
    evidence: List[VBAObfuscationEvidence] = []

    for line_number, line in enumerate(source.splitlines(), start=1):
        for indicator, pattern, confidence in _ENVIRONMENT_PATTERNS:
            if re.search(pattern, line):
                _append_evidence(
                    evidence,
                    category="environment_dependent",
                    indicator=indicator,
                    evidence=line.strip(),
                    line_number=line_number,
                    procedure=None,
                    confidence=confidence,
                    severity="low",
                )

    return evidence


# ---------------------------------------------------------------------------
# Encoded / high entropy blobs
# ---------------------------------------------------------------------------


def detect_high_entropy_strings(
    records: Sequence[VBAStringRecord],
) -> List[VBAObfuscationEvidence]:
    """
    Detect long, high-entropy string literals.

    This is intentionally conservative. High entropy can occur in benign
    identifiers, serialized data, certificates, hashes, or generated content.
    """
    evidence: List[VBAObfuscationEvidence] = []

    for record in records:
        if record.length < 32:
            continue

        if record.entropy < 4.5:
            continue

        if record.is_url_like or record.is_path_like:
            continue

        confidence = 0.65

        if record.entropy >= 5.2:
            confidence = 0.78

        if record.length >= 128:
            confidence += 0.08

        severity = "medium"

        if record.entropy >= 5.5 and record.length >= 128:
            severity = "high"

        _append_evidence(
            evidence,
            category="encoded_blob",
            indicator="high_entropy_string",
            evidence=record.value,
            line_number=record.line_number,
            procedure=None,
            confidence=_clamp(confidence),
            severity=severity,
        )

    return evidence


# ---------------------------------------------------------------------------
# Suspicious string fragmentation statistics
# ---------------------------------------------------------------------------


def calculate_string_statistics(
    records: Sequence[VBAStringRecord],
) -> Dict[str, Any]:
    """
    Calculate bounded aggregate statistics over string literals.
    """
    if not records:
        return {
            "string_count": 0,
            "total_string_characters": 0,
            "mean_string_length": 0.0,
            "median_string_length": 0.0,
            "max_string_length": 0,
            "short_string_count": 0,
            "base64_like_count": 0,
            "hex_like_count": 0,
            "high_entropy_count": 0,
            "command_like_count": 0,
            "url_like_count": 0,
            "path_like_count": 0,
        }

    lengths = sorted(record.length for record in records)
    count = len(lengths)

    if count % 2:
        median = float(lengths[count // 2])
    else:
        median = (lengths[count // 2 - 1] + lengths[count // 2]) / 2.0

    return {
        "string_count": count,
        "total_string_characters": sum(lengths),
        "mean_string_length": round(
            sum(lengths) / count,
            6,
        ),
        "median_string_length": round(median, 6),
        "max_string_length": max(lengths),
        "short_string_count": sum(1 for length in lengths if length <= 4),
        "base64_like_count": sum(1 for record in records if record.is_base64_like),
        "hex_like_count": sum(1 for record in records if record.is_hex_like),
        "high_entropy_count": sum(1 for record in records if record.entropy >= 4.5),
        "command_like_count": sum(1 for record in records if record.is_command_like),
        "url_like_count": sum(1 for record in records if record.is_url_like),
        "path_like_count": sum(1 for record in records if record.is_path_like),
    }


# ---------------------------------------------------------------------------
# Higher-level combinations
# ---------------------------------------------------------------------------


def derive_obfuscation_combinations(
    evidence: Sequence[VBAObfuscationEvidence],
) -> Dict[str, Dict[str, Any]]:
    """
    Correlate multiple static obfuscation signals.

    The combinations are heuristic indicators, not maliciousness verdicts.
    """
    categories = {item.category for item in evidence}
    indicators = {item.indicator for item in evidence}

    combinations: Dict[str, Dict[str, Any]] = {}

    combinations["encoded_string_construction"] = {
        "present": (
            "string_encoding" in categories and "character_construction" in categories
        ),
        "required_categories": [
            "string_encoding",
            "character_construction",
        ],
        "explanation": (
            "Encoded-looking strings occur alongside character construction."
        ),
    }

    combinations["fragmented_dynamic_strings"] = {
        "present": (
            "string_fragmentation" in categories
            and (
                "dynamic_name_construction" in categories
                or "execution_obfuscation" in categories
            )
        ),
        "required_categories": [
            "string_fragmentation",
            "dynamic_name_construction_or_execution_obfuscation",
        ],
        "explanation": (
            "String fragmentation is combined with dynamically constructed "
            "names or execution-related dispatch."
        ),
    }

    combinations["numeric_execution_obfuscation"] = {
        "present": (
            "numeric_encoding" in categories and "execution_obfuscation" in categories
        ),
        "required_categories": [
            "numeric_encoding",
            "execution_obfuscation",
        ],
        "explanation": (
            "Numeric character construction is combined with an "
            "execution-related dynamic dispatch mechanism."
        ),
    }

    combinations["encoded_blob_with_transformations"] = {
        "present": (
            "encoded_blob" in categories and "string_transformation" in categories
        ),
        "required_categories": [
            "encoded_blob",
            "string_transformation",
        ],
        "explanation": (
            "A high-entropy/encoded-looking literal occurs alongside "
            "string transformation functions."
        ),
    }

    combinations["obfuscation_with_environment_logic"] = {
        "present": (
            bool(
                categories
                & {
                    "string_encoding",
                    "character_construction",
                    "string_fragmentation",
                    "encoded_blob",
                    "execution_obfuscation",
                }
            )
            and "environment_dependent" in categories
        ),
        "required_categories": [
            "obfuscation",
            "environment_dependent",
        ],
        "explanation": (
            "Obfuscation indicators are combined with environment-dependent "
            "source constructs."
        ),
    }

    combinations["heavy_identifier_obfuscation"] = {
        "present": "identifier_obfuscation" in categories,
        "required_categories": ["identifier_obfuscation"],
        "explanation": (
            "The source contains an elevated proportion of irregular " "identifiers."
        ),
    }

    combinations["flow_obfuscation"] = {
        "present": "control_flow_obfuscation" in categories,
        "required_categories": ["control_flow_obfuscation"],
        "explanation": (
            "Nonlinear or conditional source structure may complicate "
            "static interpretation."
        ),
    }

    combinations["_indicator_count"] = {
        "present": bool(indicators),
        "required_categories": [],
        "explanation": "Static indicator count is available.",
    }

    return combinations


# ---------------------------------------------------------------------------
# Control-flow obfuscation
# ---------------------------------------------------------------------------


def detect_control_flow_obfuscation(
    source: str,
) -> List[VBAObfuscationEvidence]:
    """
    Detect control-flow constructs that can make static interpretation harder.

    Ordinary loops/conditionals are weak evidence. Goto-heavy or unusual
    branching receives stronger treatment.
    """
    evidence: List[VBAObfuscationEvidence] = []

    lines = source.splitlines()

    goto_lines = []
    label_count = 0
    conditional_compilation_count = 0

    for line_number, line in enumerate(lines, start=1):
        stripped = line.strip()

        if not stripped:
            continue

        if re.match(
            r"(?i)^(?:[A-Za-z_][A-Za-z0-9_]*:|\d+\s*:?)\s*$",
            stripped,
        ):
            label_count += 1

        if re.search(
            r"(?i)^\s*(?:GoTo|GoSub)\s+\w+",
            line,
        ):
            goto_lines.append(line_number)

        if re.search(
            r"(?i)^\s*#(?:If|ElseIf|Else|End\s+If)\b",
            line,
        ):
            conditional_compilation_count += 1

    if len(goto_lines) >= 3:
        severity = "medium"

        if len(goto_lines) >= 10:
            severity = "high"

        _append_evidence(
            evidence,
            category="control_flow_obfuscation",
            indicator="goto_heavy_flow",
            evidence=f"goto_count={len(goto_lines)}",
            line_number=goto_lines[0],
            procedure=None,
            confidence=0.85,
            severity=severity,
        )

    if label_count >= 5:
        _append_evidence(
            evidence,
            category="control_flow_obfuscation",
            indicator="many_labels",
            evidence=f"label_count={label_count}",
            line_number=None,
            procedure=None,
            confidence=0.75,
            severity="medium",
        )

    if conditional_compilation_count >= 3:
        _append_evidence(
            evidence,
            category="control_flow_obfuscation",
            indicator="conditional_compilation",
            evidence=(
                f"conditional_compilation_count=" f"{conditional_compilation_count}"
            ),
            line_number=None,
            procedure=None,
            confidence=0.78,
            severity="medium",
        )

    return evidence


# ---------------------------------------------------------------------------
# Execution correlation
# ---------------------------------------------------------------------------


_EXECUTION_INDICATORS = {
    "shell",
    "execute",
    "executeglobal",
    "eval",
    "application.run",
    "callbyname",
    "createobject",
    "getobject",
    "ontime",
    "wscript.shell",
}


def correlate_execution_obfuscation(
    source: str,
    evidence: Sequence[VBAObfuscationEvidence],
) -> List[VBAObfuscationEvidence]:
    """
    Identify lines where obfuscation and execution mechanisms occur together.

    This does not execute or resolve the resulting value.
    """
    output: List[VBAObfuscationEvidence] = []

    lines = source.splitlines()

    obfuscated_lines = {
        item.line_number
        for item in evidence
        if item.line_number is not None
        and item.category
        in {
            "string_encoding",
            "string_fragmentation",
            "character_construction",
            "numeric_encoding",
            "string_transformation",
            "encoded_blob",
            "dynamic_name_construction",
        }
    }

    for line_number in sorted(obfuscated_lines):
        if line_number is None or line_number > len(lines):
            continue

        line = lines[line_number - 1]

        if not re.search(
            r"(?i)\b(?:Shell|Execute|ExecuteGlobal|Eval|Evaluate|"
            r"CallByName|CreateObject|GetObject|Application\s*\.\s*Run|"
            r"OnTime)\b",
            line,
        ):
            continue

        _append_evidence(
            output,
            category="execution_obfuscation",
            indicator="obfuscated_execution_expression",
            evidence=line.strip(),
            line_number=line_number,
            procedure=None,
            confidence=0.96,
            severity="high",
        )

    # Also detect multi-line proximity: obfuscation immediately followed by
    # execution is useful evidence even if the actual expression spans lines.
    obfuscated_numbers = sorted(
        number for number in obfuscated_lines if number is not None
    )

    for number in obfuscated_numbers:
        for nearby in range(number + 1, min(number + 4, len(lines) + 1)):
            nearby_line = lines[nearby - 1]

            if re.search(
                r"(?i)\b(?:Shell|Execute|ExecuteGlobal|Eval|Evaluate|"
                r"CallByName|Application\s*\.\s*Run)\b",
                nearby_line,
            ):
                _append_evidence(
                    output,
                    category="execution_obfuscation",
                    indicator="obfuscation_near_execution",
                    evidence=(
                        f"obfuscation_line={number}; "
                        f"execution_line={nearby}; "
                        f"source={nearby_line.strip()}"
                    ),
                    line_number=nearby,
                    procedure=None,
                    confidence=0.86,
                    severity="high",
                )
                break

    return output


# ---------------------------------------------------------------------------
# Feature vector
# ---------------------------------------------------------------------------


def _safe_feature_name(value: str) -> str:
    return re.sub(
        r"[^a-z0-9_]+",
        "_",
        value.lower(),
    ).strip("_")


def _category_count(
    evidence: Sequence[VBAObfuscationEvidence],
    category: str,
) -> int:
    return sum(1 for item in evidence if item.category == category)


def _indicator_count(
    evidence: Sequence[VBAObfuscationEvidence],
    indicator: str,
) -> int:
    return sum(1 for item in evidence if item.indicator == indicator)


def build_feature_vector(
    evidence: Sequence[VBAObfuscationEvidence],
    strings: Sequence[VBAStringRecord],
    transformations: Sequence[VBATransformationRecord],
    combinations: Optional[Mapping[str, Mapping[str, Any]]] = None,
    string_statistics: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Union[int, float, bool]]:
    """
    Build deterministic ML-ready scalar features.
    """
    if combinations is None:
        combinations = derive_obfuscation_combinations(evidence)

    if string_statistics is None:
        string_statistics = calculate_string_statistics(strings)

    vector: Dict[str, Union[int, float, bool]] = {}

    # Stable category features.
    for category in OBFUSCATION_CATEGORIES:
        count = _category_count(evidence, category)

        vector[f"vba_obfuscation_{category}"] = int(count > 0)
        vector[f"vba_obfuscation_{category}_count"] = count

    # Stable indicator features.
    stable_indicators = (
        "base64_like_string",
        "hex_like_string",
        "high_entropy_string",
        "fragmented_string_construction",
        "excessive_line_continuations",
        "numeric_character_construction",
        "repeated_numeric_character_sequence",
        "irregular_identifier_set",
        "goto_heavy_flow",
        "many_labels",
        "conditional_compilation",
        "obfuscated_execution_expression",
        "obfuscation_near_execution",
        "createobject_with_constructed_name",
        "getobject_with_constructed_name",
        "application_run_with_constructed_name",
        "callbyname_with_constructed_name",
    )

    for indicator in stable_indicators:
        safe = _safe_feature_name(indicator)

        vector[f"vba_obfuscation_indicator_{safe}"] = int(
            _indicator_count(evidence, indicator) > 0
        )
        vector[f"vba_obfuscation_indicator_{safe}_count"] = _indicator_count(
            evidence, indicator
        )

    # String statistics.
    vector["vba_obfuscation_string_count"] = int(
        string_statistics.get("string_count", 0)
    )
    vector["vba_obfuscation_total_string_characters"] = int(
        string_statistics.get("total_string_characters", 0)
    )
    vector["vba_obfuscation_mean_string_length"] = float(
        string_statistics.get("mean_string_length", 0.0)
    )
    vector["vba_obfuscation_median_string_length"] = float(
        string_statistics.get("median_string_length", 0.0)
    )
    vector["vba_obfuscation_max_string_length"] = int(
        string_statistics.get("max_string_length", 0)
    )
    vector["vba_obfuscation_short_string_count"] = int(
        string_statistics.get("short_string_count", 0)
    )
    vector["vba_obfuscation_base64_like_count"] = int(
        string_statistics.get("base64_like_count", 0)
    )
    vector["vba_obfuscation_hex_like_count"] = int(
        string_statistics.get("hex_like_count", 0)
    )
    vector["vba_obfuscation_high_entropy_count"] = int(
        string_statistics.get("high_entropy_count", 0)
    )
    vector["vba_obfuscation_command_like_count"] = int(
        string_statistics.get("command_like_count", 0)
    )
    vector["vba_obfuscation_url_like_count"] = int(
        string_statistics.get("url_like_count", 0)
    )
    vector["vba_obfuscation_path_like_count"] = int(
        string_statistics.get("path_like_count", 0)
    )

    # Transformation statistics.
    vector["vba_obfuscation_transformation_count"] = len(transformations)

    for function_name in TRANSFORMATION_FUNCTIONS:
        safe = _safe_feature_name(function_name)

        count = sum(
            1 for record in transformations if record.normalized_name == function_name
        )

        vector[f"vba_obfuscation_transform_{safe}"] = int(count > 0)
        vector[f"vba_obfuscation_transform_{safe}_count"] = count

    # Combination features.
    for name, combination in combinations.items():
        if name.startswith("_"):
            continue

        safe = _safe_feature_name(name)

        vector[f"vba_obfuscation_chain_{safe}"] = int(bool(combination.get("present")))

    # Confidence statistics.
    if evidence:
        vector["vba_obfuscation_mean_confidence"] = round(
            sum(item.confidence for item in evidence) / len(evidence),
            6,
        )
        vector["vba_obfuscation_max_confidence"] = round(
            max(item.confidence for item in evidence),
            6,
        )
    else:
        vector["vba_obfuscation_mean_confidence"] = 0.0
        vector["vba_obfuscation_max_confidence"] = 0.0

    vector["vba_obfuscation_high_severity_count"] = sum(
        1 for item in evidence if item.severity in {"high", "critical"}
    )

    vector["vba_obfuscation_medium_severity_count"] = sum(
        1 for item in evidence if item.severity == "medium"
    )

    # Weak-source indicators.
    vector["vba_obfuscation_has_strings"] = int(bool(strings))
    vector["vba_obfuscation_has_transformations"] = int(bool(transformations))

    # Conservative weighted signal score.
    score = 0.0

    for category, weight in CATEGORY_WEIGHTS.items():
        score += (
            min(
                _category_count(evidence, category),
                20,
            )
            * weight
        )

    # Strong combinations get an additional bounded contribution.
    for name, combination in combinations.items():
        if name.startswith("_"):
            continue

        if combination.get("present"):
            if name in {
                "encoded_string_construction",
                "fragmented_dynamic_strings",
                "numeric_execution_obfuscation",
                "encoded_blob_with_transformations",
            }:
                score += 5.0
            else:
                score += 2.0

    vector["vba_obfuscation_signal_score"] = round(
        min(score, 100.0),
        6,
    )

    return vector


# ---------------------------------------------------------------------------
# Main analysis
# ---------------------------------------------------------------------------


def analyze_obfuscation(
    source: Union[str, bytes, bytearray],
) -> VBAObfuscationAnalysis:
    """
    Perform complete static VBA obfuscation analysis.
    """
    text = _read_source(source)
    clean = _strip_vba_comments(text)

    strings = extract_string_records(text)

    evidence: List[VBAObfuscationEvidence] = []

    evidence.extend(detect_character_construction(clean))

    transformations = extract_transformation_records(clean)

    for transformation in transformations:
        category = transformation.category

        # Most transformation functions are weak by themselves.
        severity = "low"

        if transformation.normalized_name in {
            "replace",
            "replace$",
            "strreverse",
        }:
            severity = "medium"

        _append_evidence(
            evidence,
            category=category,
            indicator=transformation.normalized_name,
            evidence=transformation.evidence,
            line_number=transformation.line_number,
            procedure=None,
            confidence=transformation.confidence,
            severity=severity,
        )

    evidence.extend(detect_string_fragmentation(clean))

    evidence.extend(detect_encoded_strings(strings))

    evidence.extend(detect_high_entropy_strings(strings))

    evidence.extend(detect_numeric_encoding(clean))

    identifier_evidence, identifier_metadata = analyze_identifiers(clean)
    evidence.extend(identifier_evidence)

    evidence.extend(detect_whitespace_and_continuations(text))

    evidence.extend(detect_comment_obfuscation(text))

    evidence.extend(detect_dynamic_name_construction(clean))

    evidence.extend(detect_environment_dependent_logic(clean))

    evidence.extend(detect_control_flow_obfuscation(clean))

    # Execution correlation is intentionally last so it can use the complete
    # set of obfuscation observations.
    evidence.extend(
        correlate_execution_obfuscation(
            clean,
            evidence,
        )
    )

    categories = {
        category: _category_count(evidence, category)
        for category in OBFUSCATION_CATEGORIES
    }

    indicators = sorted({item.indicator for item in evidence if item.indicator})

    string_statistics = calculate_string_statistics(strings)

    combinations = derive_obfuscation_combinations(evidence)

    feature_vector = build_feature_vector(
        evidence=evidence,
        strings=strings,
        transformations=transformations,
        combinations=combinations,
        string_statistics=string_statistics,
    )

    source_hash = hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()

    highest_severity = "low"

    severity_order = {
        "low": 0,
        "medium": 1,
        "high": 2,
        "critical": 3,
    }

    for item in evidence:
        if severity_order.get(item.severity, 0) > severity_order.get(
            highest_severity,
            0,
        ):
            highest_severity = item.severity

    metadata: Dict[str, Any] = {
        "module": "src.extraction.vba.obfuscation",
        "static_only": True,
        "source_sha256": source_hash,
        "source_size_bytes": len(text.encode("utf-8", errors="replace")),
        "line_count": len(text.splitlines()),
        "evidence_count": len(evidence),
        "string_count": len(strings),
        "transformation_count": len(transformations),
        "highest_severity": highest_severity,
        "string_statistics": string_statistics,
        "identifier_statistics": identifier_metadata,
        "combinations": {
            name: {
                key: value
                for key, value in combination.items()
                if key != "required_categories"
            }
            for name, combination in combinations.items()
            if not name.startswith("_")
        },
    }

    return VBAObfuscationAnalysis(
        evidence=evidence,
        strings=strings,
        transformations=transformations,
        categories=categories,
        indicators=indicators,
        feature_vector=feature_vector,
        metadata=metadata,
    )


# ---------------------------------------------------------------------------
# Convenience APIs
# ---------------------------------------------------------------------------


def extract_obfuscation_features(
    source: Union[str, bytes, bytearray],
) -> VBAObfuscationAnalysis:
    """Alias for analyze_obfuscation()."""
    return analyze_obfuscation(source)


def analyze_vba_obfuscation(
    source: Union[str, bytes, bytearray],
) -> VBAObfuscationAnalysis:
    """Compatibility alias for VBA extraction pipelines."""
    return analyze_obfuscation(source)


def extract_feature_vector(
    source: Union[str, bytes, bytearray],
) -> Dict[str, Union[int, float, bool]]:
    """Return only the obfuscation feature dictionary."""
    return analyze_obfuscation(source).feature_vector


def extract_obfuscation_feature_vector(
    source: Union[str, bytes, bytearray],
) -> Dict[str, Union[int, float, bool]]:
    """Explicit feature-vector alias."""
    return extract_feature_vector(source)


def obfuscation_feature_names() -> List[str]:
    """
    Return deterministic feature names from an empty analysis.
    """
    empty = build_feature_vector(
        evidence=[],
        strings=[],
        transformations=[],
        combinations=derive_obfuscation_combinations([]),
        string_statistics=calculate_string_statistics([]),
    )

    return sorted(empty.keys())


def build_feature_schema() -> Dict[str, Any]:
    """
    Build a machine-readable feature schema.
    """
    names = obfuscation_feature_names()

    features: List[Dict[str, str]] = []

    for name in names:
        if (
            name.endswith("score")
            or name.endswith("confidence")
            or "mean_" in name
            or "median_" in name
        ):
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
        "name": "vba_obfuscation_features",
        "version": "1.0",
        "static_only": True,
        "feature_count": len(features),
        "features": features,
    }


def vectorize_features(
    analysis_or_source: Union[
        VBAObfuscationAnalysis,
        str,
        bytes,
        bytearray,
    ],
    feature_names: Optional[Sequence[str]] = None,
) -> List[Union[int, float, bool]]:
    """
    Convert an analysis into a deterministic ordered feature vector.
    """
    if isinstance(analysis_or_source, VBAObfuscationAnalysis):
        analysis = analysis_or_source
    else:
        analysis = analyze_obfuscation(analysis_or_source)

    names = (
        list(feature_names)
        if feature_names is not None
        else obfuscation_feature_names()
    )

    return [analysis.feature_vector.get(name, 0) for name in names]


# ---------------------------------------------------------------------------
# Query helpers
# ---------------------------------------------------------------------------


def has_obfuscation(
    analysis_or_source: Union[
        VBAObfuscationAnalysis,
        str,
        bytes,
        bytearray,
    ],
) -> bool:
    """
    Return whether any obfuscation evidence was found.

    This should not be interpreted as a malware verdict.
    """
    analysis = (
        analysis_or_source
        if isinstance(analysis_or_source, VBAObfuscationAnalysis)
        else analyze_obfuscation(analysis_or_source)
    )

    return bool(analysis.evidence)


def has_strong_obfuscation(
    analysis_or_source: Union[
        VBAObfuscationAnalysis,
        str,
        bytes,
        bytearray,
    ],
) -> bool:
    """
    Return whether stronger obfuscation evidence was found.
    """
    analysis = (
        analysis_or_source
        if isinstance(analysis_or_source, VBAObfuscationAnalysis)
        else analyze_obfuscation(analysis_or_source)
    )

    strong_categories = {
        "string_encoding",
        "character_construction",
        "encoded_blob",
        "dynamic_name_construction",
        "execution_obfuscation",
    }

    return any(
        item.category in strong_categories
        and item.severity in {"medium", "high", "critical"}
        for item in analysis.evidence
    )


def obfuscation_count(
    analysis_or_source: Union[
        VBAObfuscationAnalysis,
        str,
        bytes,
        bytearray,
    ],
    category: Optional[str] = None,
) -> int:
    """Count obfuscation evidence, optionally by category."""
    analysis = (
        analysis_or_source
        if isinstance(analysis_or_source, VBAObfuscationAnalysis)
        else analyze_obfuscation(analysis_or_source)
    )

    if category is None:
        return len(analysis.evidence)

    return analysis.categories.get(category, 0)


def find_obfuscation_evidence(
    analysis_or_source: Union[
        VBAObfuscationAnalysis,
        str,
        bytes,
        bytearray,
    ],
    category: Optional[str] = None,
    indicator: Optional[str] = None,
) -> List[VBAObfuscationEvidence]:
    """
    Return evidence matching optional filters.
    """
    analysis = (
        analysis_or_source
        if isinstance(analysis_or_source, VBAObfuscationAnalysis)
        else analyze_obfuscation(analysis_or_source)
    )

    results: List[VBAObfuscationEvidence] = []

    for item in analysis.evidence:
        if category is not None and item.category != category:
            continue

        if indicator is not None and item.indicator != indicator:
            continue

        results.append(item)

    return results


def find_encoded_strings(
    analysis_or_source: Union[
        VBAObfuscationAnalysis,
        str,
        bytes,
        bytearray,
    ],
) -> List[VBAStringRecord]:
    """Return strings classified as Base64-like or hexadecimal-like."""
    analysis = (
        analysis_or_source
        if isinstance(analysis_or_source, VBAObfuscationAnalysis)
        else analyze_obfuscation(analysis_or_source)
    )

    return [
        record
        for record in analysis.strings
        if record.is_base64_like or record.is_hex_like
    ]


def find_high_entropy_strings(
    analysis_or_source: Union[
        VBAObfuscationAnalysis,
        str,
        bytes,
        bytearray,
    ],
    minimum_entropy: float = 4.5,
    minimum_length: int = 32,
) -> List[VBAStringRecord]:
    """
    Return long/high-entropy string literals without decoding them.
    """
    analysis = (
        analysis_or_source
        if isinstance(analysis_or_source, VBAObfuscationAnalysis)
        else analyze_obfuscation(analysis_or_source)
    )

    return [
        record
        for record in analysis.strings
        if record.length >= minimum_length and record.entropy >= minimum_entropy
    ]


def find_transformations(
    analysis_or_source: Union[
        VBAObfuscationAnalysis,
        str,
        bytes,
        bytearray,
    ],
    function_name: Optional[str] = None,
) -> List[VBATransformationRecord]:
    """Return statically observed string transformation functions."""
    analysis = (
        analysis_or_source
        if isinstance(analysis_or_source, VBAObfuscationAnalysis)
        else analyze_obfuscation(analysis_or_source)
    )

    if function_name is None:
        return list(analysis.transformations)

    normalized = _normalize_name(function_name)

    return [
        record
        for record in analysis.transformations
        if record.normalized_name == normalized
    ]


def present_combinations(
    analysis_or_source: Union[
        VBAObfuscationAnalysis,
        str,
        bytes,
        bytearray,
    ],
) -> List[str]:
    """Return higher-level obfuscation combinations that are present."""
    analysis = (
        analysis_or_source
        if isinstance(analysis_or_source, VBAObfuscationAnalysis)
        else analyze_obfuscation(analysis_or_source)
    )

    combinations = analysis.metadata.get("combinations", {})

    return sorted(
        name
        for name, value in combinations.items()
        if isinstance(value, Mapping) and bool(value.get("present"))
    )


# ---------------------------------------------------------------------------
# Serialization / summaries
# ---------------------------------------------------------------------------


def analysis_to_dict(
    analysis: VBAObfuscationAnalysis,
) -> Dict[str, Any]:
    """Serialize the analysis into JSON-compatible primitives."""
    return asdict(analysis)


def summarize_obfuscation(
    analysis_or_source: Union[
        VBAObfuscationAnalysis,
        str,
        bytes,
        bytearray,
    ],
) -> Dict[str, Any]:
    """
    Return a compact triage-oriented summary.
    """
    analysis = (
        analysis_or_source
        if isinstance(analysis_or_source, VBAObfuscationAnalysis)
        else analyze_obfuscation(analysis_or_source)
    )

    high_risk = [
        item for item in analysis.evidence if item.severity in {"high", "critical"}
    ]

    return {
        "has_obfuscation": bool(analysis.evidence),
        "has_strong_obfuscation": has_strong_obfuscation(analysis),
        "evidence_count": len(analysis.evidence),
        "string_count": len(analysis.strings),
        "transformation_count": len(analysis.transformations),
        "high_risk_evidence_count": len(high_risk),
        "categories": dict(analysis.categories),
        "indicators": list(analysis.indicators),
        "encoded_string_count": len(find_encoded_strings(analysis)),
        "high_entropy_string_count": len(find_high_entropy_strings(analysis)),
        "present_combinations": present_combinations(analysis),
        "highest_severity": analysis.metadata.get(
            "highest_severity",
            "low",
        ),
        "signal_score": analysis.feature_vector.get(
            "vba_obfuscation_signal_score",
            0.0,
        ),
    }


def iter_obfuscation_evidence(
    source: Union[str, bytes, bytearray],
) -> Iterator[VBAObfuscationEvidence]:
    """Yield static obfuscation evidence lazily."""
    analysis = analyze_obfuscation(source)

    for item in analysis.evidence:
        yield item


def iter_obfuscation_strings(
    source: Union[str, bytes, bytearray],
) -> Iterator[VBAStringRecord]:
    """Yield extracted VBA strings lazily."""
    analysis = analyze_obfuscation(source)

    for item in analysis.strings:
        yield item


def iter_obfuscation_analyses(
    sources: Iterable[Union[str, bytes, bytearray]],
) -> Iterator[VBAObfuscationAnalysis]:
    """Analyze multiple VBA sources lazily."""
    for source in sources:
        yield analyze_obfuscation(source)


# ---------------------------------------------------------------------------
# Compatibility aliases
# ---------------------------------------------------------------------------

parse_obfuscation = analyze_obfuscation
extract_obfuscation = analyze_obfuscation
obfuscation_features = extract_obfuscation_features


__all__ = [
    "MAX_SOURCE_SIZE",
    "MAX_LINES",
    "MAX_EVIDENCE_ITEMS",
    "MAX_STRINGS",
    "MAX_IDENTIFIERS",
    "MAX_TRANSFORM_RECORDS",
    "OBFUSCATION_CATEGORIES",
    "CATEGORY_WEIGHTS",
    "VBAObfuscationEvidence",
    "VBAStringRecord",
    "VBATransformationRecord",
    "VBAObfuscationAnalysis",
    "extract_string_records",
    "detect_character_construction",
    "extract_transformation_records",
    "detect_string_fragmentation",
    "detect_encoded_strings",
    "detect_numeric_encoding",
    "analyze_identifiers",
    "detect_whitespace_and_continuations",
    "detect_comment_obfuscation",
    "detect_dynamic_name_construction",
    "detect_environment_dependent_logic",
    "detect_high_entropy_strings",
    "calculate_string_statistics",
    "derive_obfuscation_combinations",
    "detect_control_flow_obfuscation",
    "correlate_execution_obfuscation",
    "build_feature_vector",
    "analyze_obfuscation",
    "extract_obfuscation_features",
    "analyze_vba_obfuscation",
    "extract_feature_vector",
    "extract_obfuscation_feature_vector",
    "obfuscation_feature_names",
    "build_feature_schema",
    "vectorize_features",
    "has_obfuscation",
    "has_strong_obfuscation",
    "obfuscation_count",
    "find_obfuscation_evidence",
    "find_encoded_strings",
    "find_high_entropy_strings",
    "find_transformations",
    "present_combinations",
    "analysis_to_dict",
    "summarize_obfuscation",
    "iter_obfuscation_evidence",
    "iter_obfuscation_strings",
    "iter_obfuscation_analyses",
    "parse_obfuscation",
    "extract_obfuscation",
    "obfuscation_features",
]
