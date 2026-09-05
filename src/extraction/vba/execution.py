"""
Static VBA execution and control-flow analysis.

This module identifies VBA constructs that can cause code execution, invoke
other procedures, launch external processes, dynamically resolve code, or
alter execution flow.

IMPORTANT:
    This module is strictly static. It never:
      - executes VBA;
      - invokes Windows APIs;
      - launches processes;
      - evaluates VBA expressions;
      - resolves COM objects;
      - downloads content;
      - loads DLLs;
      - writes extracted payloads to disk.

The output is intended to feed:
    VBA source
        -> parser.py
        -> execution.py
        -> capabilities.py / obfuscation.py / api_features.py
        -> feature_pipeline.py
        -> ML + CDR policy

The analyzer deliberately distinguishes:
    1. execution mechanisms,
    2. auto-execution triggers,
    3. dynamic execution,
    4. external process execution,
    5. procedure/control-flow behavior,
    6. error-handling and flow-obfuscation indicators.

A single indicator should not be interpreted as malicious. For example,
"Call Foo" or an "If" statement is normal VBA. Higher-risk decisions should
come from combinations of evidence.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
import hashlib
import re
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
MAX_PROCEDURES = 100_000
MAX_EVIDENCE_ITEMS = 20_000
MAX_CALLS = 100_000
MAX_STRINGS = 50_000


# ---------------------------------------------------------------------------
# Severity / confidence helpers
# ---------------------------------------------------------------------------

SEVERITY_ORDER = {
    "low": 0,
    "medium": 1,
    "high": 2,
    "critical": 3,
}


def _max_severity(*values: str) -> str:
    """Return the highest severity from the supplied values."""
    best = "low"
    for value in values:
        normalized = str(value or "low").lower()
        if SEVERITY_ORDER.get(normalized, 0) > SEVERITY_ORDER[best]:
            best = normalized
    return best


def _clamp_confidence(value: float) -> float:
    return max(0.0, min(1.0, float(value)))


def _normalize_name(value: str) -> str:
    """
    Normalize a VBA identifier/call target for comparison.

    VBA identifiers are case-insensitive and may be qualified with an object
    name such as Application.Run or WScript.Shell.Run.
    """
    value = str(value or "").strip().lower()
    value = re.sub(r"\s+", "", value)
    return value


def _strip_vba_comments(source: str) -> str:
    """
    Remove ordinary VBA comments while preserving quoted strings.

    This is intentionally lightweight rather than a complete VBA lexer.
    It handles:
        ' comment
        Rem comment

    It does not attempt to interpret every VBA preprocessor construct.
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

        # VBA's Rem is a comment keyword when it begins a statement.
        stripped = line.lstrip()
        if re.match(r"(?i)^rem(?:\s|$)", stripped):
            line = line[: len(line) - len(stripped)]

        output.append(line)

    return "\n".join(output)


def _read_source(source: Union[str, bytes, bytearray]) -> str:
    if isinstance(source, str):
        if len(source.encode("utf-8", errors="ignore")) > MAX_SOURCE_SIZE:
            raise ValueError(f"VBA source exceeds MAX_SOURCE_SIZE={MAX_SOURCE_SIZE}")
        return source

    if isinstance(source, (bytes, bytearray)):
        if len(source) > MAX_SOURCE_SIZE:
            raise ValueError(f"VBA source exceeds MAX_SOURCE_SIZE={MAX_SOURCE_SIZE}")

        return bytes(source).decode("utf-8", errors="replace")

    raise TypeError("source must be str, bytes, or bytearray")


# ---------------------------------------------------------------------------
# Static execution taxonomy
# ---------------------------------------------------------------------------

EXECUTION_CATEGORIES: Tuple[str, ...] = (
    "auto_execution",
    "external_process",
    "shell_execution",
    "dynamic_execution",
    "macro_execution",
    "procedure_invocation",
    "com_execution",
    "document_event",
    "control_flow",
    "error_handling",
    "scheduled_execution",
    "delayed_execution",
    "indirect_execution",
    "execution_obfuscation",
)


# High-value execution indicators. These are normalized names where possible.
DIRECT_EXECUTION_FUNCTIONS = {
    "shell",
    "exec",
    "execute",
    "executeglobal",
    "eval",
    "application.run",
    "application.evaluate",
    "evaluate",
    "run",
    "callbyname",
}

SHELL_FUNCTIONS = {
    "shell",
}

DYNAMIC_EXECUTION_FUNCTIONS = {
    "execute",
    "executeglobal",
    "eval",
    "evaluate",
    "application.evaluate",
    "callbyname",
}

MACRO_EXECUTION_FUNCTIONS = {
    "application.run",
    "run",
    "callbyname",
}

COM_EXECUTION_METHODS = {
    "wscript.shell.run",
    "wscript.shell.exec",
    "shell.run",
    "shell.exec",
}

DELAYED_EXECUTION_FUNCTIONS = {
    "application.ontime",
    "ontime",
    "wscript.sleep",
    "sleep",
}

SCHEDULED_EXECUTION_FUNCTIONS = {
    "application.ontime",
    "ontime",
}


# ---------------------------------------------------------------------------
# Auto-execution entry points
# ---------------------------------------------------------------------------

AUTO_EXECUTION_ENTRY_POINTS: Dict[str, Dict[str, Any]] = {
    # Classic Excel / generic Office auto macros.
    "autoopen": {
        "host": "generic",
        "kind": "auto_macro",
        "severity": "high",
        "confidence": 0.98,
    },
    "auto_open": {
        "host": "generic",
        "kind": "auto_macro",
        "severity": "high",
        "confidence": 0.98,
    },
    "autoclose": {
        "host": "generic",
        "kind": "auto_macro",
        "severity": "high",
        "confidence": 0.98,
    },
    "auto_close": {
        "host": "generic",
        "kind": "auto_macro",
        "severity": "high",
        "confidence": 0.98,
    },
    "autonew": {
        "host": "generic",
        "kind": "auto_macro",
        "severity": "high",
        "confidence": 0.98,
    },
    "auto_new": {
        "host": "generic",
        "kind": "auto_macro",
        "severity": "high",
        "confidence": 0.98,
    },
    "autoexec": {
        "host": "generic",
        "kind": "auto_macro",
        "severity": "high",
        "confidence": 0.98,
    },
    "auto_exit": {
        "host": "generic",
        "kind": "auto_macro",
        "severity": "high",
        "confidence": 0.98,
    },
    "autoclose": {
        "host": "generic",
        "kind": "auto_macro",
        "severity": "high",
        "confidence": 0.98,
    },
    # Word.
    "document_open": {
        "host": "word",
        "kind": "document_event",
        "severity": "high",
        "confidence": 0.99,
    },
    "documentopen": {
        "host": "word",
        "kind": "document_event",
        "severity": "high",
        "confidence": 0.99,
    },
    "document_close": {
        "host": "word",
        "kind": "document_event",
        "severity": "high",
        "confidence": 0.99,
    },
    "documentbeforeclose": {
        "host": "word",
        "kind": "document_event",
        "severity": "high",
        "confidence": 0.98,
    },
    "document_new": {
        "host": "word",
        "kind": "document_event",
        "severity": "medium",
        "confidence": 0.95,
    },
    "documentchange": {
        "host": "word",
        "kind": "document_event",
        "severity": "medium",
        "confidence": 0.95,
    },
    # Excel.
    "workbook_open": {
        "host": "excel",
        "kind": "document_event",
        "severity": "high",
        "confidence": 0.99,
    },
    "workbookopen": {
        "host": "excel",
        "kind": "document_event",
        "severity": "high",
        "confidence": 0.99,
    },
    "workbook_beforeclose": {
        "host": "excel",
        "kind": "document_event",
        "severity": "high",
        "confidence": 0.98,
    },
    "workbookbeforeclose": {
        "host": "excel",
        "kind": "document_event",
        "severity": "high",
        "confidence": 0.98,
    },
    "workbook_activate": {
        "host": "excel",
        "kind": "document_event",
        "severity": "medium",
        "confidence": 0.95,
    },
    "workbookactivate": {
        "host": "excel",
        "kind": "document_event",
        "severity": "medium",
        "confidence": 0.95,
    },
    # PowerPoint.
    "presentation_open": {
        "host": "powerpoint",
        "kind": "document_event",
        "severity": "high",
        "confidence": 0.98,
    },
    "presentationopen": {
        "host": "powerpoint",
        "kind": "document_event",
        "severity": "high",
        "confidence": 0.98,
    },
    # Access.
    "autoexec": {
        "host": "access",
        "kind": "auto_macro",
        "severity": "high",
        "confidence": 0.98,
    },
    "autoexecmacro": {
        "host": "access",
        "kind": "auto_macro",
        "severity": "high",
        "confidence": 0.98,
    },
}


# ---------------------------------------------------------------------------
# Source patterns
# ---------------------------------------------------------------------------

# Patterns are deliberately line-oriented. They detect evidence but do not
# evaluate the VBA statement.

EXECUTION_PATTERNS: Tuple[Tuple[str, str, str, float], ...] = (
    (
        "shell_call",
        r"(?i)(?:^|[^\w])Shell\s*(?:\(|\s)",
        "shell_execution",
        0.99,
    ),
    (
        "execute_call",
        r"(?i)(?:^|[^\w])Execute\s*(?:\(|\s)",
        "dynamic_execution",
        0.99,
    ),
    (
        "execute_global_call",
        r"(?i)(?:^|[^\w])ExecuteGlobal\s*(?:\(|\s)",
        "dynamic_execution",
        0.99,
    ),
    (
        "eval_call",
        r"(?i)(?:^|[^\w])Eval(?:uate)?\s*(?:\(|\s)",
        "dynamic_execution",
        0.97,
    ),
    (
        "application_run",
        r"(?i)\bApplication\s*\.\s*Run\s*(?:\(|\s)",
        "macro_execution",
        0.99,
    ),
    (
        "application_evaluate",
        r"(?i)\bApplication\s*\.\s*(?:Evaluate|ExecuteExcel4Macro)\s*(?:\(|\s)",
        "dynamic_execution",
        0.99,
    ),
    (
        "callbyname",
        r"(?i)\bCallByName\s*(?:\(|\s)",
        "indirect_execution",
        0.98,
    ),
    (
        "wscript_shell_run",
        r"(?i)\b(?:WScript|CreateObject\s*\([^)]*WScript\.Shell[^)]*\))\s*\.\s*(?:Run|Exec)\s*(?:\(|\s)",
        "com_execution",
        0.97,
    ),
    (
        "ontime",
        r"(?i)\b(?:Application\s*\.\s*)?OnTime\s*(?:\(|\s)",
        "scheduled_execution",
        0.98,
    ),
    (
        "sleep",
        r"(?i)\b(?:WScript\s*\.\s*)?Sleep\s*(?:\(|\s)",
        "delayed_execution",
        0.90,
    ),
    (
        "createobject",
        r"(?i)\bCreateObject\s*\(",
        "com_execution",
        0.95,
    ),
    (
        "getobject",
        r"(?i)\bGetObject\s*\(",
        "com_execution",
        0.90,
    ),
    (
        "sendkeys",
        r"(?i)\bSendKeys\s*(?:\(|\s)",
        "indirect_execution",
        0.85,
    ),
    (
        "sendmessage",
        r"(?i)\b(?:SendMessage|PostMessage)\s*(?:\(|\s)",
        "indirect_execution",
        0.80,
    ),
    (
        "run_command_style",
        r"(?i)\b(?:cmd(?:\.exe)?|powershell(?:\.exe)?|wscript(?:\.exe)?|cscript(?:\.exe)?|mshta(?:\.exe)?|rundll32(?:\.exe)?|regsvr32(?:\.exe)?|wmic(?:\.exe)?)\b",
        "external_process",
        0.95,
    ),
)


CONTROL_FLOW_PATTERNS: Tuple[Tuple[str, str, float], ...] = (
    (
        "goto",
        r"(?i)^\s*(?:GoTo|GoSub)\s+\w+",
        0.70,
    ),
    (
        "on_error",
        r"(?i)^\s*On\s+Error\s+(?:Resume\s+Next|GoTo\s+\w+|GoTo\s+0)",
        0.65,
    ),
    (
        "error_resume_next",
        r"(?i)^\s*On\s+Error\s+Resume\s+Next",
        0.72,
    ),
    (
        "conditional_compilation",
        r"(?i)^\s*#(?:If|ElseIf|Else|End\s+If)\b",
        0.55,
    ),
    (
        "for_loop",
        r"(?i)^\s*For(?:\s+Each)?\b",
        0.25,
    ),
    (
        "do_loop",
        r"(?i)^\s*Do(?:\s+While|\s+Until)?\b",
        0.25,
    ),
    (
        "while_loop",
        r"(?i)^\s*While\b",
        0.25,
    ),
    (
        "if_branch",
        r"(?i)^\s*If\b.+\bThen\b",
        0.20,
    ),
    (
        "select_case",
        r"(?i)^\s*Select\s+Case\b",
        0.15,
    ),
)


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class VBAExecutionEvidence:
    """
    One static execution/control-flow observation.
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
            _clamp_confidence(self.confidence),
        )
        object.__setattr__(
            self,
            "severity",
            str(self.severity or "medium").lower(),
        )


@dataclass(frozen=True)
class VBAProcedureRecord:
    """
    Statically discovered VBA procedure.
    """

    name: str
    kind: str
    start_line: int
    end_line: int
    visibility: str = "unknown"
    attributes: Tuple[str, ...] = ()
    has_parameters: bool = False
    parameter_count: int = 0
    executable_statement_count: int = 0
    calls: Tuple[str, ...] = ()


@dataclass(frozen=True)
class VBAExecutionCall:
    """
    Statically detected invocation.

    The target is not resolved or executed.
    """

    target: str
    normalized_target: str
    kind: str
    line_number: int
    procedure: Optional[str] = None
    evidence: str = ""
    confidence: float = 1.0


@dataclass
class VBAExecutionAnalysis:
    """
    Complete static execution analysis.
    """

    evidence: List[VBAExecutionEvidence] = field(default_factory=list)
    procedures: List[VBAProcedureRecord] = field(default_factory=list)
    calls: List[VBAExecutionCall] = field(default_factory=list)
    auto_execution: List[str] = field(default_factory=list)
    categories: Dict[str, int] = field(default_factory=dict)
    indicators: List[str] = field(default_factory=list)
    feature_vector: Dict[str, Union[int, float, bool]] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Procedure parsing
# ---------------------------------------------------------------------------

_PROCEDURE_START_RE = re.compile(
    r"""
    ^\s*
    (?:(?:Public|Private|Friend|Static)\s+)*
    (?:(?:Default|Property)\s+)*
    (?P<kind>Sub|Function|Property\s+(?:Get|Let|Set))
    \s+
    (?P<name>[A-Za-z_][A-Za-z0-9_\.]*)
    \s*
    (?P<params>\([^)]*\))?
    """,
    re.IGNORECASE | re.VERBOSE,
)

_PROCEDURE_END_RE = re.compile(
    r"^\s*End\s+(?:Sub|Function|Property)\b",
    re.IGNORECASE,
)


def _procedure_visibility(line: str) -> str:
    match = re.match(
        r"^\s*(Public|Private|Friend|Static)\b",
        line,
        re.IGNORECASE,
    )
    return match.group(1).lower() if match else "unknown"


def _parameter_count(params: Optional[str]) -> int:
    if not params:
        return 0

    content = params.strip()[1:-1].strip()
    if not content:
        return 0

    # VBA parameters may contain commas inside some type/declaration syntax,
    # but simple comma counting is a safe static approximation here.
    return len([part for part in content.split(",") if part.strip()])


def parse_procedures(
    source: Union[str, bytes, bytearray],
) -> List[VBAProcedureRecord]:
    """
    Discover Sub, Function, and Property procedures without executing them.
    """
    text = _strip_vba_comments(_read_source(source))
    lines = text.splitlines()

    if len(lines) > MAX_LINES:
        raise ValueError(f"VBA source exceeds MAX_LINES={MAX_LINES}")

    procedures: List[VBAProcedureRecord] = []
    current: Optional[Dict[str, Any]] = None

    for line_number, line in enumerate(lines, start=1):
        match = _PROCEDURE_START_RE.match(line)

        if match:
            if current is not None:
                procedures.append(
                    _finalize_procedure(
                        current,
                        line_number - 1,
                        lines,
                    )
                )

                if len(procedures) >= MAX_PROCEDURES:
                    break

            kind = re.sub(r"\s+", " ", match.group("kind").strip().lower())
            name = match.group("name").strip()

            current = {
                "name": name,
                "kind": kind,
                "start_line": line_number,
                "visibility": _procedure_visibility(line),
                "params": match.group("params"),
                "attributes": [],
            }
            continue

        if current is not None and _PROCEDURE_END_RE.match(line):
            procedures.append(
                _finalize_procedure(
                    current,
                    line_number,
                    lines,
                )
            )
            current = None

    if current is not None and len(procedures) < MAX_PROCEDURES:
        procedures.append(
            _finalize_procedure(
                current,
                len(lines),
                lines,
            )
        )

    return procedures


def _finalize_procedure(
    current: Mapping[str, Any],
    end_line: int,
    lines: Sequence[str],
) -> VBAProcedureRecord:
    start_line = int(current["start_line"])
    safe_end = max(start_line, min(end_line, len(lines)))

    body = lines[start_line:safe_end]
    executable_count = 0

    for line in body:
        stripped = line.strip()
        if not stripped:
            continue

        if stripped.startswith("#"):
            continue

        if _PROCEDURE_END_RE.match(stripped):
            continue

        executable_count += 1

    return VBAProcedureRecord(
        name=str(current["name"]),
        kind=str(current["kind"]),
        start_line=start_line,
        end_line=safe_end,
        visibility=str(current.get("visibility", "unknown")),
        attributes=tuple(current.get("attributes", ())),
        has_parameters=bool(current.get("params")),
        parameter_count=_parameter_count(current.get("params")),
        executable_statement_count=executable_count,
        calls=(),
    )


# ---------------------------------------------------------------------------
# Auto-execution detection
# ---------------------------------------------------------------------------


def find_auto_execution_points(
    source: Union[str, bytes, bytearray],
    procedures: Optional[Sequence[VBAProcedureRecord]] = None,
) -> List[Dict[str, Any]]:
    """
    Identify known Office/VBA auto-execution entry points.

    This is intentionally conservative: the presence of a name is evidence,
    not proof that the host will invoke it in the current document context.
    """
    if procedures is None:
        procedures = parse_procedures(source)

    findings: List[Dict[str, Any]] = []

    for procedure in procedures:
        normalized = _normalize_name(procedure.name).split(".")[-1]

        info = AUTO_EXECUTION_ENTRY_POINTS.get(normalized)
        if info is None:
            continue

        findings.append(
            {
                "name": procedure.name,
                "normalized_name": normalized,
                "kind": info["kind"],
                "host": info["host"],
                "line_number": procedure.start_line,
                "severity": info["severity"],
                "confidence": info["confidence"],
            }
        )

    return findings


# ---------------------------------------------------------------------------
# Static call extraction
# ---------------------------------------------------------------------------

_CALL_TARGET_RE = re.compile(
    r"""
    (?:
        \b(?P<keyword>Call)\s+
    )?
    (?P<target>
        (?:[A-Za-z_][A-Za-z0-9_]*\s*\.\s*)*
        [A-Za-z_][A-Za-z0-9_]*
    )
    \s*
    (?=\(|\s|$)
    """,
    re.IGNORECASE | re.VERBOSE,
)

_QUALIFIED_CALL_RE = re.compile(
    r"\b[A-Za-z_][A-Za-z0-9_]*(?:\s*\.\s*[A-Za-z_][A-Za-z0-9_]*)+"
)


def _extract_explicit_calls(
    line: str,
    line_number: int,
    procedure: Optional[str],
) -> List[VBAExecutionCall]:
    calls: List[VBAExecutionCall] = []

    # Explicit "Call Foo(...)" statements.
    explicit = re.finditer(
        r"(?i)\bCall\s+([A-Za-z_][A-Za-z0-9_]*(?:\s*\.\s*[A-Za-z_][A-Za-z0-9_]*)*)",
        line,
    )

    for match in explicit:
        target = re.sub(r"\s+", "", match.group(1))
        calls.append(
            VBAExecutionCall(
                target=target,
                normalized_target=_normalize_name(target),
                kind="procedure_call",
                line_number=line_number,
                procedure=procedure,
                evidence=match.group(0).strip(),
                confidence=0.98,
            )
        )

    # Function-style calls of known execution primitives.
    for function_name in (
        "Shell",
        "Execute",
        "ExecuteGlobal",
        "Eval",
        "Evaluate",
        "CallByName",
        "CreateObject",
        "GetObject",
        "Run",
        "OnTime",
        "Sleep",
        "SendKeys",
        "ExecuteExcel4Macro",
    ):
        pattern = re.compile(rf"(?i)\b{re.escape(function_name)}\s*\(")

        for match in pattern.finditer(line):
            target = function_name
            normalized = _normalize_name(target)

            if normalized in SHELL_FUNCTIONS:
                kind = "shell_execution"
            elif normalized in DYNAMIC_EXECUTION_FUNCTIONS:
                kind = "dynamic_execution"
            elif normalized in MACRO_EXECUTION_FUNCTIONS:
                kind = "macro_execution"
            elif normalized in DELAYED_EXECUTION_FUNCTIONS:
                kind = "delayed_execution"
            elif normalized == "createobject":
                kind = "com_creation"
            elif normalized == "getobject":
                kind = "com_reference"
            else:
                kind = "indirect_execution"

            calls.append(
                VBAExecutionCall(
                    target=target,
                    normalized_target=normalized,
                    kind=kind,
                    line_number=line_number,
                    procedure=procedure,
                    evidence=match.group(0),
                    confidence=0.97,
                )
            )

    # Object-qualified execution calls.
    for match in _QUALIFIED_CALL_RE.finditer(line):
        target = re.sub(r"\s+", "", match.group(0))
        normalized = _normalize_name(target)

        if normalized.endswith(".run"):
            kind = "macro_or_shell_execution"
        elif normalized.endswith(".exec"):
            kind = "external_process"
        elif normalized.endswith(".evaluate"):
            kind = "dynamic_execution"
        elif normalized.endswith(".execute"):
            kind = "dynamic_execution"
        elif normalized.endswith(".executeexcel4macro"):
            kind = "macro_execution"
        else:
            continue

        calls.append(
            VBAExecutionCall(
                target=target,
                normalized_target=normalized,
                kind=kind,
                line_number=line_number,
                procedure=procedure,
                evidence=match.group(0),
                confidence=0.96,
            )
        )

    # De-duplicate same target/kind/line.
    unique: Dict[Tuple[str, str, int], VBAExecutionCall] = {}
    for call in calls:
        key = (
            call.normalized_target,
            call.kind,
            call.line_number,
        )
        unique[key] = call

    return list(unique.values())


def parse_execution_calls(
    source: Union[str, bytes, bytearray],
    procedures: Optional[Sequence[VBAProcedureRecord]] = None,
) -> List[VBAExecutionCall]:
    """
    Extract statically visible execution-related calls.

    This function never attempts to determine what a dynamic string contains.
    """
    text = _strip_vba_comments(_read_source(source))
    lines = text.splitlines()

    if len(lines) > MAX_LINES:
        raise ValueError(f"VBA source exceeds MAX_LINES={MAX_LINES}")

    procedure_ranges: List[Tuple[int, int, str]] = []

    if procedures:
        for procedure in procedures:
            procedure_ranges.append(
                (
                    procedure.start_line,
                    procedure.end_line,
                    procedure.name,
                )
            )

    def procedure_for_line(line_number: int) -> Optional[str]:
        for start, end, name in procedure_ranges:
            if start <= line_number <= end:
                return name
        return None

    calls: List[VBAExecutionCall] = []

    for line_number, line in enumerate(lines, start=1):
        if not line.strip():
            continue

        calls.extend(
            _extract_explicit_calls(
                line=line,
                line_number=line_number,
                procedure=procedure_for_line(line_number),
            )
        )

        if len(calls) >= MAX_CALLS:
            return calls[:MAX_CALLS]

    return calls[:MAX_CALLS]


# ---------------------------------------------------------------------------
# Execution evidence
# ---------------------------------------------------------------------------


def _find_line_procedure(
    line_number: int,
    procedures: Sequence[VBAProcedureRecord],
) -> Optional[str]:
    for procedure in procedures:
        if procedure.start_line <= line_number <= procedure.end_line:
            return procedure.name
    return None


def _append_evidence(
    output: List[VBAExecutionEvidence],
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
        VBAExecutionEvidence(
            category=category,
            indicator=indicator,
            evidence=evidence[:2_000],
            line_number=line_number,
            procedure=procedure,
            confidence=confidence,
            severity=severity,
        )
    )


def extract_execution_evidence(
    source: Union[str, bytes, bytearray],
    procedures: Optional[Sequence[VBAProcedureRecord]] = None,
) -> List[VBAExecutionEvidence]:
    """
    Extract static evidence related to execution and control flow.
    """
    text = _strip_vba_comments(_read_source(source))
    lines = text.splitlines()

    if len(lines) > MAX_LINES:
        raise ValueError(f"VBA source exceeds MAX_LINES={MAX_LINES}")

    if procedures is None:
        procedures = parse_procedures(text)

    evidence: List[VBAExecutionEvidence] = []

    # Auto-execution procedures.
    for finding in find_auto_execution_points(text, procedures):
        _append_evidence(
            evidence,
            category="auto_execution",
            indicator=finding["kind"],
            evidence=finding["name"],
            line_number=finding["line_number"],
            procedure=finding["name"],
            confidence=finding["confidence"],
            severity=finding["severity"],
        )

    # Direct execution patterns.
    for line_number, line in enumerate(lines, start=1):
        stripped = line.strip()

        if not stripped:
            continue

        procedure = _find_line_procedure(line_number, procedures)

        for indicator, pattern, category, confidence in EXECUTION_PATTERNS:
            if re.search(pattern, line):
                severity = "medium"

                if category in {
                    "dynamic_execution",
                    "shell_execution",
                    "external_process",
                    "macro_execution",
                }:
                    severity = "high"

                if indicator in {
                    "wscript_shell_run",
                    "run_command_style",
                    "execute_global_call",
                }:
                    severity = "high"

                _append_evidence(
                    evidence,
                    category=category,
                    indicator=indicator,
                    evidence=stripped,
                    line_number=line_number,
                    procedure=procedure,
                    confidence=confidence,
                    severity=severity,
                )

        for indicator, pattern, confidence in CONTROL_FLOW_PATTERNS:
            if re.search(pattern, line):
                severity = "low"

                if indicator in {"goto", "error_resume_next"}:
                    severity = "medium"

                if indicator == "conditional_compilation":
                    severity = "medium"

                _append_evidence(
                    evidence,
                    category=(
                        "control_flow"
                        if indicator not in {"on_error", "error_resume_next"}
                        else "error_handling"
                    ),
                    indicator=indicator,
                    evidence=stripped,
                    line_number=line_number,
                    procedure=procedure,
                    confidence=confidence,
                    severity=severity,
                )

    return evidence


# ---------------------------------------------------------------------------
# Execution chains
# ---------------------------------------------------------------------------


def _contains_category(
    evidence: Sequence[VBAExecutionEvidence],
    category: str,
) -> bool:
    return any(item.category == category for item in evidence)


def _contains_indicator(
    evidence: Sequence[VBAExecutionEvidence],
    indicator: str,
) -> bool:
    return any(item.indicator == indicator for item in evidence)


def derive_execution_chains(
    evidence: Sequence[VBAExecutionEvidence],
    calls: Sequence[VBAExecutionCall],
) -> Dict[str, Dict[str, Any]]:
    """
    Derive higher-level combinations from independent static indicators.

    These are correlations, not claims that the source will necessarily
    execute the observed chain.
    """
    indicators = {item.indicator for item in evidence}
    categories = {item.category for item in evidence}

    chains: Dict[str, Dict[str, Any]] = {}

    dynamic = bool(
        {
            "execute_call",
            "execute_global_call",
            "eval_call",
            "application_evaluate",
            "callbyname",
        }
        & indicators
    )

    shell = bool(
        {
            "shell_call",
            "wscript_shell_run",
            "run_command_style",
        }
        & indicators
    )

    auto = "auto_execution" in categories
    macro = "application_run" in indicators
    scheduled = "ontime" in indicators
    com = "createobject" in indicators or "getobject" in indicators

    chains["auto_to_execution"] = {
        "present": auto and (shell or dynamic or macro or com),
        "required": ["auto_execution", "execution_mechanism"],
        "explanation": (
            "An automatic/document event procedure is combined with a "
            "statically visible execution-related mechanism."
        ),
    }

    chains["dynamic_execution"] = {
        "present": dynamic,
        "required": ["dynamic_execution"],
        "explanation": (
            "The VBA source contains a construct capable of interpreting "
            "or dispatching code/expressions dynamically."
        ),
    }

    chains["shell_execution"] = {
        "present": shell,
        "required": ["shell_execution"],
        "explanation": (
            "The VBA source contains a statically visible shell/process "
            "launch mechanism."
        ),
    }

    chains["com_to_execution"] = {
        "present": com and shell,
        "required": ["com_creation_or_reference", "execution"],
        "explanation": (
            "COM/object access is combined with a visible process or shell "
            "execution primitive."
        ),
    }

    chains["scheduled_execution"] = {
        "present": scheduled,
        "required": ["scheduled_execution"],
        "explanation": ("The source contains a timer/scheduled callback mechanism."),
    }

    chains["macro_dispatch"] = {
        "present": macro,
        "required": ["macro_dispatch"],
        "explanation": ("The source contains Application.Run-style macro dispatch."),
    }

    chains["execution_with_error_suppression"] = {
        "present": (
            (shell or dynamic or macro)
            and _contains_indicator(evidence, "error_resume_next")
        ),
        "required": ["execution", "error_suppression"],
        "explanation": (
            "An execution mechanism appears alongside On Error Resume Next. "
            "This can be benign, but the combination is useful for triage."
        ),
    }

    chains["execution_with_control_flow_obfuscation"] = {
        "present": (
            (shell or dynamic or macro)
            and (
                _contains_indicator(evidence, "goto")
                or _contains_indicator(evidence, "conditional_compilation")
            )
        ),
        "required": ["execution", "nonlinear_or_conditional_flow"],
        "explanation": (
            "An execution mechanism appears alongside flow constructs that "
            "can complicate static interpretation."
        ),
    }

    # Keep calls referenced so callers can evolve the chain logic without
    # changing this function's API.
    chains["_call_count"] = {
        "present": bool(calls),
        "required": [],
        "explanation": "Number of execution-related calls was observed.",
    }

    return chains


# ---------------------------------------------------------------------------
# Feature vector
# ---------------------------------------------------------------------------


def _category_count(
    evidence: Sequence[VBAExecutionEvidence],
    category: str,
) -> int:
    return sum(1 for item in evidence if item.category == category)


def _indicator_count(
    evidence: Sequence[VBAExecutionEvidence],
    indicator: str,
) -> int:
    return sum(1 for item in evidence if item.indicator == indicator)


def build_feature_vector(
    evidence: Sequence[VBAExecutionEvidence],
    procedures: Sequence[VBAProcedureRecord],
    calls: Sequence[VBAExecutionCall],
    chains: Optional[Mapping[str, Mapping[str, Any]]] = None,
) -> Dict[str, Union[int, float, bool]]:
    """
    Build deterministic scalar features suitable for ML pipelines.

    Feature names are stable and intentionally descriptive.
    """
    if chains is None:
        chains = derive_execution_chains(evidence, calls)

    vector: Dict[str, Union[int, float, bool]] = {}

    # Category presence/counts.
    for category in EXECUTION_CATEGORIES:
        count = _category_count(evidence, category)
        vector[f"vba_execution_{category}"] = int(count > 0)
        vector[f"vba_execution_{category}_count"] = count

    # Important indicators.
    important_indicators = sorted(
        {item.indicator for item in evidence if item.indicator}
    )

    for indicator in important_indicators:
        safe_name = re.sub(r"[^a-z0-9_]+", "_", indicator.lower()).strip("_")
        if not safe_name:
            continue

        vector[f"vba_execution_indicator_{safe_name}"] = 1
        vector[f"vba_execution_indicator_{safe_name}_count"] = _indicator_count(
            evidence, indicator
        )

    # Core execution signals are always present in the schema.
    stable_indicators = (
        "shell_call",
        "execute_call",
        "execute_global_call",
        "eval_call",
        "application_run",
        "application_evaluate",
        "callbyname",
        "wscript_shell_run",
        "createobject",
        "getobject",
        "ontime",
        "sleep",
        "run_command_style",
        "goto",
        "error_resume_next",
        "conditional_compilation",
    )

    for indicator in stable_indicators:
        safe_name = indicator
        vector.setdefault(
            f"vba_execution_indicator_{safe_name}",
            0,
        )
        vector.setdefault(
            f"vba_execution_indicator_{safe_name}_count",
            0,
        )

    # Auto-execution.
    auto_count = _category_count(evidence, "auto_execution")
    document_event_count = _category_count(evidence, "document_event")

    vector["vba_auto_execution"] = int(auto_count > 0)
    vector["vba_auto_execution_count"] = auto_count
    vector["vba_document_event_execution"] = int(document_event_count > 0)
    vector["vba_document_event_execution_count"] = document_event_count

    # Procedure statistics.
    vector["vba_procedure_count"] = len(procedures)
    vector["vba_procedure_with_parameters_count"] = sum(
        1 for procedure in procedures if procedure.has_parameters
    )
    vector["vba_total_executable_statement_count"] = sum(
        procedure.executable_statement_count for procedure in procedures
    )

    # Call statistics.
    vector["vba_execution_call_count"] = len(calls)
    vector["vba_dynamic_call_count"] = sum(
        1 for call in calls if call.kind == "dynamic_execution"
    )
    vector["vba_shell_call_count"] = sum(
        1 for call in calls if call.kind == "shell_execution"
    )
    vector["vba_macro_dispatch_count"] = sum(
        1
        for call in calls
        if call.kind == "macro_execution" or call.kind == "macro_or_shell_execution"
    )

    # Chains.
    for chain_name, chain in chains.items():
        if chain_name.startswith("_"):
            continue

        safe_name = re.sub(
            r"[^a-z0-9_]+",
            "_",
            chain_name.lower(),
        ).strip("_")

        vector[f"vba_execution_chain_{safe_name}"] = int(bool(chain.get("present")))

    # Evidence quality.
    vector["vba_execution_high_severity_count"] = sum(
        1 for item in evidence if item.severity in {"high", "critical"}
    )
    vector["vba_execution_medium_severity_count"] = sum(
        1 for item in evidence if item.severity == "medium"
    )

    if evidence:
        vector["vba_execution_mean_confidence"] = round(
            sum(item.confidence for item in evidence) / len(evidence),
            6,
        )
        vector["vba_execution_max_confidence"] = round(
            max(item.confidence for item in evidence),
            6,
        )
    else:
        vector["vba_execution_mean_confidence"] = 0.0
        vector["vba_execution_max_confidence"] = 0.0

    # Conservative static signal score. This is a triage feature, not a
    # probability of maliciousness.
    weights = {
        "auto_execution": 2.0,
        "document_event": 2.0,
        "external_process": 4.0,
        "shell_execution": 4.0,
        "dynamic_execution": 4.0,
        "macro_execution": 3.0,
        "com_execution": 2.0,
        "scheduled_execution": 2.0,
        "delayed_execution": 1.0,
        "indirect_execution": 1.5,
        "execution_obfuscation": 2.0,
        "error_handling": 0.5,
        "control_flow": 0.25,
    }

    raw_score = 0.0
    for category, weight in weights.items():
        raw_score += (
            min(
                _category_count(evidence, category),
                20,
            )
            * weight
        )

    # Cap to keep the feature numerically stable.
    vector["vba_execution_signal_score"] = round(
        min(raw_score, 100.0),
        6,
    )

    return vector


# ---------------------------------------------------------------------------
# Main analyzer
# ---------------------------------------------------------------------------


def analyze_execution(
    source: Union[str, bytes, bytearray],
) -> VBAExecutionAnalysis:
    """
    Perform complete static VBA execution analysis.
    """
    text = _read_source(source)
    clean = _strip_vba_comments(text)

    procedures = parse_procedures(clean)
    calls = parse_execution_calls(clean, procedures)
    evidence = extract_execution_evidence(clean, procedures)
    chains = derive_execution_chains(evidence, calls)
    feature_vector = build_feature_vector(
        evidence=evidence,
        procedures=procedures,
        calls=calls,
        chains=chains,
    )

    categories = {
        category: _category_count(evidence, category)
        for category in EXECUTION_CATEGORIES
    }

    indicators = sorted({item.indicator for item in evidence if item.indicator})

    auto_execution = sorted(
        {
            item.procedure
            for item in evidence
            if item.category == "auto_execution" and item.procedure
        }
    )

    source_hash = hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()

    highest_severity = "low"
    if evidence:
        highest_severity = _max_severity(*(item.severity for item in evidence))

    metadata: Dict[str, Any] = {
        "module": "src.extraction.vba.execution",
        "static_only": True,
        "source_sha256": source_hash,
        "source_size_bytes": len(text.encode("utf-8", errors="replace")),
        "line_count": len(text.splitlines()),
        "procedure_count": len(procedures),
        "execution_call_count": len(calls),
        "evidence_count": len(evidence),
        "highest_severity": highest_severity,
        "auto_execution_count": len(auto_execution),
        "dynamic_execution_present": bool(
            feature_vector.get("vba_execution_dynamic_execution", 0)
        ),
        "external_process_present": bool(
            feature_vector.get("vba_execution_external_process", 0)
        ),
        "chains": {
            name: {key: value for key, value in chain.items() if key != "required"}
            for name, chain in chains.items()
            if not name.startswith("_")
        },
    }

    return VBAExecutionAnalysis(
        evidence=evidence,
        procedures=list(procedures),
        calls=list(calls),
        auto_execution=auto_execution,
        categories=categories,
        indicators=indicators,
        feature_vector=feature_vector,
        metadata=metadata,
    )


# ---------------------------------------------------------------------------
# Convenience APIs
# ---------------------------------------------------------------------------


def extract_execution_features(
    source: Union[str, bytes, bytearray],
) -> VBAExecutionAnalysis:
    """Alias for analyze_execution()."""
    return analyze_execution(source)


def analyze_vba_execution(
    source: Union[str, bytes, bytearray],
) -> VBAExecutionAnalysis:
    """Compatibility alias used by extraction pipelines."""
    return analyze_execution(source)


def extract_feature_vector(
    source: Union[str, bytes, bytearray],
) -> Dict[str, Union[int, float, bool]]:
    """Return only the deterministic execution feature vector."""
    return analyze_execution(source).feature_vector


def extract_execution_feature_vector(
    source: Union[str, bytes, bytearray],
) -> Dict[str, Union[int, float, bool]]:
    """Explicit feature-vector alias."""
    return extract_feature_vector(source)


def execution_feature_names() -> List[str]:
    """
    Return the stable feature names produced by an empty analysis.

    This gives the ML pipeline a schema without requiring a real sample.
    """
    return sorted(
        build_feature_vector(
            evidence=[],
            procedures=[],
            calls=[],
            chains=derive_execution_chains([], []),
        ).keys()
    )


def build_feature_schema() -> Dict[str, Any]:
    """
    Return a machine-readable schema for the execution feature vector.
    """
    names = execution_feature_names()

    return {
        "name": "vba_execution_features",
        "version": "1.0",
        "static_only": True,
        "feature_count": len(names),
        "features": [
            {
                "name": name,
                "type": (
                    "float"
                    if name.endswith("confidence") or name.endswith("score")
                    else "integer"
                ),
            }
            for name in names
        ],
    }


def vectorize_features(
    analysis_or_source: Union[
        VBAExecutionAnalysis,
        str,
        bytes,
        bytearray,
    ],
    feature_names: Optional[Sequence[str]] = None,
) -> List[Union[int, float, bool]]:
    """
    Convert an analysis to a deterministic ordered vector.

    If feature_names is omitted, the module's stable schema is used.
    Missing features are represented by zero.
    """
    if isinstance(analysis_or_source, VBAExecutionAnalysis):
        analysis = analysis_or_source
    else:
        analysis = analyze_execution(analysis_or_source)

    names = (
        list(feature_names) if feature_names is not None else execution_feature_names()
    )

    return [analysis.feature_vector.get(name, 0) for name in names]


# ---------------------------------------------------------------------------
# Query helpers
# ---------------------------------------------------------------------------


def has_execution_mechanism(
    analysis_or_source: Union[
        VBAExecutionAnalysis,
        str,
        bytes,
        bytearray,
    ],
) -> bool:
    """Return whether any execution-related mechanism was statically found."""
    analysis = (
        analysis_or_source
        if isinstance(analysis_or_source, VBAExecutionAnalysis)
        else analyze_execution(analysis_or_source)
    )

    execution_categories = {
        "external_process",
        "shell_execution",
        "dynamic_execution",
        "macro_execution",
        "com_execution",
        "scheduled_execution",
        "delayed_execution",
        "indirect_execution",
    }

    return any(item.category in execution_categories for item in analysis.evidence)


def has_auto_execution(
    analysis_or_source: Union[
        VBAExecutionAnalysis,
        str,
        bytes,
        bytearray,
    ],
) -> bool:
    """Return whether a known auto-execution/document event was found."""
    analysis = (
        analysis_or_source
        if isinstance(analysis_or_source, VBAExecutionAnalysis)
        else analyze_execution(analysis_or_source)
    )
    return bool(analysis.auto_execution)


def has_dynamic_execution(
    analysis_or_source: Union[
        VBAExecutionAnalysis,
        str,
        bytes,
        bytearray,
    ],
) -> bool:
    """Return whether dynamic execution constructs were statically found."""
    analysis = (
        analysis_or_source
        if isinstance(analysis_or_source, VBAExecutionAnalysis)
        else analyze_execution(analysis_or_source)
    )
    return any(item.category == "dynamic_execution" for item in analysis.evidence)


def execution_count(
    analysis_or_source: Union[
        VBAExecutionAnalysis,
        str,
        bytes,
        bytearray,
    ],
    category: Optional[str] = None,
) -> int:
    """Count execution evidence, optionally restricted to a category."""
    analysis = (
        analysis_or_source
        if isinstance(analysis_or_source, VBAExecutionAnalysis)
        else analyze_execution(analysis_or_source)
    )

    if category is None:
        return len(analysis.evidence)

    return analysis.categories.get(category, 0)


def find_execution_evidence(
    analysis_or_source: Union[
        VBAExecutionAnalysis,
        str,
        bytes,
        bytearray,
    ],
    category: Optional[str] = None,
    indicator: Optional[str] = None,
) -> List[VBAExecutionEvidence]:
    """
    Return evidence matching optional category and indicator filters.
    """
    analysis = (
        analysis_or_source
        if isinstance(analysis_or_source, VBAExecutionAnalysis)
        else analyze_execution(analysis_or_source)
    )

    results: List[VBAExecutionEvidence] = []

    for item in analysis.evidence:
        if category is not None and item.category != category:
            continue

        if indicator is not None and item.indicator != indicator:
            continue

        results.append(item)

    return results


def find_auto_macros(
    analysis_or_source: Union[
        VBAExecutionAnalysis,
        str,
        bytes,
        bytearray,
    ],
) -> List[str]:
    """Return discovered auto-execution procedure names."""
    analysis = (
        analysis_or_source
        if isinstance(analysis_or_source, VBAExecutionAnalysis)
        else analyze_execution(analysis_or_source)
    )
    return list(analysis.auto_execution)


def find_dynamic_calls(
    analysis_or_source: Union[
        VBAExecutionAnalysis,
        str,
        bytes,
        bytearray,
    ],
) -> List[VBAExecutionCall]:
    """Return calls classified as dynamic execution."""
    analysis = (
        analysis_or_source
        if isinstance(analysis_or_source, VBAExecutionAnalysis)
        else analyze_execution(analysis_or_source)
    )

    return [call for call in analysis.calls if call.kind == "dynamic_execution"]


def find_shell_calls(
    analysis_or_source: Union[
        VBAExecutionAnalysis,
        str,
        bytes,
        bytearray,
    ],
) -> List[VBAExecutionCall]:
    """Return shell/process-related calls."""
    analysis = (
        analysis_or_source
        if isinstance(analysis_or_source, VBAExecutionAnalysis)
        else analyze_execution(analysis_or_source)
    )

    return [
        call
        for call in analysis.calls
        if call.kind
        in {
            "shell_execution",
            "external_process",
            "macro_or_shell_execution",
        }
    ]


# ---------------------------------------------------------------------------
# Serialization / summaries
# ---------------------------------------------------------------------------


def analysis_to_dict(
    analysis: VBAExecutionAnalysis,
) -> Dict[str, Any]:
    """
    Serialize an analysis into JSON-compatible primitives.
    """
    return asdict(analysis)


def summarize_execution(
    analysis_or_source: Union[
        VBAExecutionAnalysis,
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
        if isinstance(analysis_or_source, VBAExecutionAnalysis)
        else analyze_execution(analysis_or_source)
    )

    high_risk = [
        item for item in analysis.evidence if item.severity in {"high", "critical"}
    ]

    return {
        "has_execution_mechanism": has_execution_mechanism(analysis),
        "has_auto_execution": has_auto_execution(analysis),
        "has_dynamic_execution": has_dynamic_execution(analysis),
        "auto_execution_points": list(analysis.auto_execution),
        "procedure_count": len(analysis.procedures),
        "execution_call_count": len(analysis.calls),
        "evidence_count": len(analysis.evidence),
        "high_risk_evidence_count": len(high_risk),
        "categories": dict(analysis.categories),
        "indicators": list(analysis.indicators),
        "highest_severity": analysis.metadata.get(
            "highest_severity",
            "low",
        ),
        "signal_score": analysis.feature_vector.get(
            "vba_execution_signal_score",
            0.0,
        ),
        "chains": analysis.metadata.get("chains", {}),
    }


def iter_execution_evidence(
    source: Union[str, bytes, bytearray],
) -> Iterator[VBAExecutionEvidence]:
    """Yield execution evidence lazily."""
    analysis = analyze_execution(source)

    for item in analysis.evidence:
        yield item


def iter_execution_calls(
    source: Union[str, bytes, bytearray],
) -> Iterator[VBAExecutionCall]:
    """Yield statically detected execution calls."""
    analysis = analyze_execution(source)

    for item in analysis.calls:
        yield item


def iter_execution_analyses(
    sources: Iterable[Union[str, bytes, bytearray]],
) -> Iterator[VBAExecutionAnalysis]:
    """Analyze multiple VBA sources without retaining them in this module."""
    for source in sources:
        yield analyze_execution(source)


# ---------------------------------------------------------------------------
# Module-level compatibility aliases
# ---------------------------------------------------------------------------

parse_execution = parse_execution_calls
extract_execution = analyze_execution
execution_features = extract_execution_features


__all__ = [
    "MAX_SOURCE_SIZE",
    "MAX_LINES",
    "MAX_PROCEDURES",
    "MAX_EVIDENCE_ITEMS",
    "MAX_CALLS",
    "EXECUTION_CATEGORIES",
    "AUTO_EXECUTION_ENTRY_POINTS",
    "VBAExecutionEvidence",
    "VBAProcedureRecord",
    "VBAExecutionCall",
    "VBAExecutionAnalysis",
    "parse_procedures",
    "find_auto_execution_points",
    "parse_execution_calls",
    "parse_execution",
    "extract_execution_evidence",
    "derive_execution_chains",
    "build_feature_vector",
    "analyze_execution",
    "extract_execution_features",
    "analyze_vba_execution",
    "extract_feature_vector",
    "extract_execution_feature_vector",
    "execution_feature_names",
    "build_feature_schema",
    "vectorize_features",
    "has_execution_mechanism",
    "has_auto_execution",
    "has_dynamic_execution",
    "execution_count",
    "find_execution_evidence",
    "find_auto_macros",
    "find_dynamic_calls",
    "find_shell_calls",
    "analysis_to_dict",
    "summarize_execution",
    "iter_execution_evidence",
    "iter_execution_calls",
    "iter_execution_analyses",
    "execution_features",
]
