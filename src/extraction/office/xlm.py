"""
Static analysis of Excel 4.0 / XLM macros in OOXML workbooks.

This module analyzes XLM (Excel 4.0) macro-related structures in
Office Open XML workbooks, including:

    .xlsx
    .xlsm
    .xltx
    .xltm

Primary responsibilities
------------------------
    - identify Excel macro sheets
    - identify hidden/veryHidden worksheets
    - inspect worksheet relationships
    - inspect defined names
    - identify XLM-style macro formulas
    - identify command/function indicators
    - identify suspicious external references
    - identify execution, download, persistence, and obfuscation indicators
    - produce structured records
    - produce ML-ready scalar features

Security model
--------------
This module is deliberately static-only.

It does NOT:
    - evaluate Excel formulas
    - execute XLM macros
    - resolve external links
    - download remote resources
    - invoke Excel
    - invoke COM
    - write extracted workbook content to disk
    - alter the input package

The intended architecture is:

    OOXML workbook
          |
          v
        xlm.py
          |
          +---- workbook/sheet metadata
          +---- macro-sheet detection
          +---- defined-name analysis
          +---- formula indicators
          +---- external-reference indicators
          |
          v
    office_features.py
          |
          v
    feature_pipeline.py
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple
import io
import math
import posixpath
import re
import zipfile
import xml.etree.ElementTree as ET

XLM_VERSION = 1

DEFAULT_MAX_XML_SIZE = 16 * 1024 * 1024
DEFAULT_MAX_WORKSHEETS = 2048
DEFAULT_MAX_FORMULAS_PER_SHEET = 100_000
DEFAULT_MAX_DEFINED_NAMES = 20_000
DEFAULT_MAX_FORMULA_LENGTH = 16_384


# ---------------------------------------------------------------------------
# OOXML namespaces
# ---------------------------------------------------------------------------

MAIN_NS = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"

MAIN_NS_STRICT = "http://purl.oclc.org/ooxml/spreadsheetml/main"

REL_NS = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"

REL_NS_STRICT = "http://purl.oclc.org/ooxml/officeDocument/relationships"

PACKAGE_REL_NS = "http://schemas.openxmlformats.org/package/2006/relationships"

PACKAGE_REL_NS_STRICT = "http://purl.oclc.org/ooxml/package/relationships"

RELATIONSHIP_NAMESPACES = {
    REL_NS,
    REL_NS_STRICT,
    PACKAGE_REL_NS,
    PACKAGE_REL_NS_STRICT,
}


# ---------------------------------------------------------------------------
# Worksheet relationship types
# ---------------------------------------------------------------------------

WORKSHEET_RELATIONSHIP_TERMS = {
    "worksheet",
    "macrosheet",
    "dialogsheet",
    "chartsheet",
}


MACROSHEET_RELATIONSHIP_TERMS = {
    "macrosheet",
}


DIALOGSHEET_RELATIONSHIP_TERMS = {
    "dialogsheet",
}


# ---------------------------------------------------------------------------
# XLM function indicators
# ---------------------------------------------------------------------------

# These are names commonly associated with Excel 4.0 macro commands/functions.
# Detection is textual; no function is executed or evaluated.

XLM_FUNCTIONS = {
    "ALERT",
    "ARGUMENT",
    "CALL",
    "CLOSE",
    "CONCATENATE",
    "DEFINE.NAME",
    "DELETE.NAME",
    "DEREF",
    "EXEC",
    "FILES",
    "FOPEN",
    "FORK",
    "FORMULA",
    "FORMULA.FILL",
    "GET.CELL",
    "GET.DOCUMENT",
    "GET.FORMULA",
    "GET.NAME",
    "GET.WORKBOOK",
    "GOTO",
    "HALT",
    "IF",
    "INPUT",
    "LINKS",
    "LIST",
    "LOOP",
    "MACRO",
    "NEXT",
    "NOTE",
    "ON.TIME",
    "OPEN",
    "PAUSE",
    "RUN",
    "SELECT",
    "SET.NAME",
    "SOUND",
    "START",
    "TEXT",
    "WHILE",
    "WORKBOOK.SELECT",
    "WRITE",
}


EXECUTION_FUNCTIONS = {
    "CALL",
    "EXEC",
    "GOTO",
    "HALT",
    "MACRO",
    "RUN",
    "START",
}


FILE_FUNCTIONS = {
    "CLOSE",
    "FILES",
    "FOPEN",
    "OPEN",
    "WRITE",
}


NETWORK_FUNCTIONS = {
    "CALL",
    "EXEC",
    "OPEN",
    "LINKS",
}


DYNAMIC_FUNCTIONS = {
    "CALL",
    "EXEC",
    "EVALUATE",
    "FORMULA",
    "FORMULA.FILL",
    "GET.CELL",
    "GET.DOCUMENT",
    "GET.FORMULA",
    "GET.NAME",
    "GET.WORKBOOK",
    "MACRO",
    "RUN",
}


# ---------------------------------------------------------------------------
# Textual indicators
# ---------------------------------------------------------------------------

URL_PATTERN = re.compile(r"(?i)\b(?:https?|ftp|file|smb)://[^\s<>'\"]+")

UNC_PATTERN = re.compile(r"(?i)(?:\\\\|//)[^\\/\s]+[\\/][^\\/\s]+")

WINDOWS_PATH_PATTERN = re.compile(r"(?i)\b[A-Z]:[\\/][^\r\n<>'\"]+")

IPV4_PATTERN = re.compile(
    r"\b(?:" r"(?:25[0-5]|2[0-4]\d|1?\d?\d)\." r"){3}" r"(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
)

ENVIRONMENT_VARIABLE_PATTERN = re.compile(r"%[A-Za-z_][A-Za-z0-9_]*%")

BASE64_LIKE_PATTERN = re.compile(
    r"(?i)(?<![A-Za-z0-9+/])" r"[A-Za-z0-9+/]{24,}={0,2}" r"(?![A-Za-z0-9+/])"
)

HEX_LIKE_PATTERN = re.compile(r"(?i)(?<![0-9a-f])[0-9a-f]{24,}(?![0-9a-f])")

POWER_SHELL_PATTERN = re.compile(
    r"(?i)(?:"
    r"powershell(?:\.exe)?|"
    r"pwsh(?:\.exe)?|"
    r"encodedcommand|"
    r"invoke-expression|"
    r"invoke-webrequest|"
    r"invoke-restmethod|"
    r"start-process"
    r")"
)

WINDOWS_EXECUTION_PATTERN = re.compile(
    r"(?i)(?:"
    r"cmd(?:\.exe)?|"
    r"wscript(?:\.exe)?|"
    r"cscript(?:\.exe)?|"
    r"mshta(?:\.exe)?|"
    r"rundll32(?:\.exe)?|"
    r"regsvr32(?:\.exe)?|"
    r"regsvcs(?:\.exe)?|"
    r"installutil(?:\.exe)?|"
    r"certutil(?:\.exe)?"
    r")"
)

DOWNLOAD_PATTERN = re.compile(
    r"(?i)(?:"
    r"download|"
    r"urldownload|"
    r"winhttp|"
    r"wininet|"
    r"xmlhttp|"
    r"webclient|"
    r"invoke-webrequest|"
    r"invoke-restmethod|"
    r"bitsadmin"
    r")"
)

PERSISTENCE_PATTERN = re.compile(
    r"(?i)(?:"
    r"currentversion\\run|"
    r"\\run\\|"
    r"runonce|"
    r"startup|"
    r"start menu|"
    r"scheduled task|"
    r"task scheduler"
    r")"
)

CREDENTIAL_PATTERN = re.compile(
    r"(?i)(?:"
    r"password|"
    r"passwd|"
    r"credential|"
    r"token|"
    r"secret|"
    r"login|"
    r"cookie"
    r")"
)

OBFUSCATION_PATTERN = re.compile(
    r"(?i)(?:"
    r"CHAR\s*\(|"
    r"CODE\s*\(|"
    r"UNICHAR\s*\(|"
    r"UNICHAR\s*\(|"
    r"DEC2HEX\s*\(|"
    r"HEX2DEC\s*\(|"
    r"SUBSTITUTE\s*\(|"
    r"REPLACE\s*\(|"
    r"CONCATENATE\s*\(|"
    r"CONCAT\s*\(|"
    r"BASE64|"
    r"ENCODE|"
    r"DECODE"
    r")"
)

INDIRECT_REFERENCE_PATTERN = re.compile(
    r"(?i)(?:"
    r"\bINDIRECT\s*\(|"
    r"\bEVALUATE\s*\(|"
    r"\bGET\.CELL\s*\(|"
    r"\bGET\.DOCUMENT\s*\(|"
    r"\bGET\.WORKBOOK\s*\("
    r")"
)

XLM_FORMULA_PATTERN = re.compile(
    r"(?i)(?:"
    r"^[=+]\s*(?:"
    r"(?:ALERT|CALL|CLOSE|EXEC|FILES|FOPEN|"
    r"FORMULA|FORMULA\.FILL|GET\.CELL|GET\.DOCUMENT|"
    r"GET\.FORMULA|GET\.NAME|GET\.WORKBOOK|GOTO|"
    r"HALT|MACRO|OPEN|RUN|SET\.NAME|START|"
    r"WORKBOOK\.SELECT)\b"
    r"|"
    r".*\b(?:EXEC|CALL|GET\.CELL|GET\.DOCUMENT|"
    r"GET\.WORKBOOK|RUN|GOTO|MACRO)\s*\("
    r")"
    r")"
)

EXTERNAL_REFERENCE_PATTERN = re.compile(
    r"(?i)(?:" r"\[[^\]]+\]|" r"\b(?:https?|ftp|file|smb)://|" r"\\\\" r")"
)

SUSPICIOUS_SHEET_NAME_PATTERN = re.compile(
    r"(?i)(?:"
    r"macro|"
    r"xlm|"
    r"excel\s*4|"
    r"command|"
    r"payload|"
    r"stage|"
    r"loader|"
    r"download|"
    r"startup"
    r")"
)


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass
class XLMFormulaRecord:
    """
    One formula/static expression discovered in a workbook.

    The formula is retained in bounded form for analysis/reporting.
    """

    sheet_name: str
    sheet_state: str
    cell_reference: str

    formula: str
    formula_length: int

    is_xlm_like: bool

    xlm_functions: List[str] = field(default_factory=list)

    contains_url: bool = False
    contains_unc_path: bool = False
    contains_windows_path: bool = False
    contains_ipv4: bool = False
    contains_external_reference: bool = False

    contains_execution_indicator: bool = False
    contains_download_indicator: bool = False
    contains_persistence_indicator: bool = False
    contains_credential_indicator: bool = False
    contains_obfuscation_indicator: bool = False
    contains_dynamic_reference: bool = False

    suspicious: bool = False

    def to_dict(self) -> Dict[str, object]:
        return {
            "sheet_name": self.sheet_name,
            "sheet_state": self.sheet_state,
            "cell_reference": self.cell_reference,
            "formula": self.formula,
            "formula_length": self.formula_length,
            "is_xlm_like": self.is_xlm_like,
            "xlm_functions": list(self.xlm_functions),
            "contains_url": self.contains_url,
            "contains_unc_path": self.contains_unc_path,
            "contains_windows_path": self.contains_windows_path,
            "contains_ipv4": self.contains_ipv4,
            "contains_external_reference": (self.contains_external_reference),
            "contains_execution_indicator": (self.contains_execution_indicator),
            "contains_download_indicator": (self.contains_download_indicator),
            "contains_persistence_indicator": (self.contains_persistence_indicator),
            "contains_credential_indicator": (self.contains_credential_indicator),
            "contains_obfuscation_indicator": (self.contains_obfuscation_indicator),
            "contains_dynamic_reference": (self.contains_dynamic_reference),
            "suspicious": self.suspicious,
        }


@dataclass
class XLMSheetRecord:
    """
    Static metadata for an Excel worksheet.
    """

    sheet_name: str
    state: str
    relationship_id: str
    target: str
    relationship_type: str

    is_macrosheet: bool
    is_dialogsheet: bool
    is_hidden: bool
    is_very_hidden: bool

    formula_count: int = 0
    xlm_formula_count: int = 0
    suspicious_formula_count: int = 0

    url_count: int = 0
    external_reference_count: int = 0
    execution_indicator_count: int = 0
    download_indicator_count: int = 0
    obfuscation_indicator_count: int = 0

    suspicious: bool = False

    def to_dict(self) -> Dict[str, object]:
        return {
            "sheet_name": self.sheet_name,
            "state": self.state,
            "relationship_id": self.relationship_id,
            "target": self.target,
            "relationship_type": self.relationship_type,
            "is_macrosheet": self.is_macrosheet,
            "is_dialogsheet": self.is_dialogsheet,
            "is_hidden": self.is_hidden,
            "is_very_hidden": self.is_very_hidden,
            "formula_count": self.formula_count,
            "xlm_formula_count": self.xlm_formula_count,
            "suspicious_formula_count": (self.suspicious_formula_count),
            "url_count": self.url_count,
            "external_reference_count": (self.external_reference_count),
            "execution_indicator_count": (self.execution_indicator_count),
            "download_indicator_count": (self.download_indicator_count),
            "obfuscation_indicator_count": (self.obfuscation_indicator_count),
            "suspicious": self.suspicious,
        }


@dataclass
class XLMDefinedNameRecord:
    """
    Static representation of an Excel defined name.

    Defined names are important because XLM macros can be represented
    through names rather than conventional cell formulas.
    """

    name: str
    local_sheet_id: Optional[int]
    hidden: bool
    value: str

    formula_length: int

    contains_xlm_function: bool
    xlm_functions: List[str] = field(default_factory=list)

    contains_url: bool = False
    contains_external_reference: bool = False
    contains_execution_indicator: bool = False
    contains_download_indicator: bool = False
    contains_obfuscation_indicator: bool = False
    contains_dynamic_reference: bool = False

    suspicious: bool = False

    def to_dict(self) -> Dict[str, object]:
        return {
            "name": self.name,
            "local_sheet_id": self.local_sheet_id,
            "hidden": self.hidden,
            "value": self.value,
            "formula_length": self.formula_length,
            "contains_xlm_function": (self.contains_xlm_function),
            "xlm_functions": list(self.xlm_functions),
            "contains_url": self.contains_url,
            "contains_external_reference": (self.contains_external_reference),
            "contains_execution_indicator": (self.contains_execution_indicator),
            "contains_download_indicator": (self.contains_download_indicator),
            "contains_obfuscation_indicator": (self.contains_obfuscation_indicator),
            "contains_dynamic_reference": (self.contains_dynamic_reference),
            "suspicious": self.suspicious,
        }


@dataclass
class XLMStatistics:
    """
    Aggregate XLM analysis statistics.
    """

    worksheet_count: int = 0
    hidden_sheet_count: int = 0
    very_hidden_sheet_count: int = 0

    macrosheet_count: int = 0
    dialogsheet_count: int = 0

    formula_count: int = 0
    xlm_formula_count: int = 0
    suspicious_formula_count: int = 0

    defined_name_count: int = 0
    xlm_defined_name_count: int = 0
    suspicious_defined_name_count: int = 0
    hidden_defined_name_count: int = 0

    url_count: int = 0
    external_reference_count: int = 0
    execution_indicator_count: int = 0
    download_indicator_count: int = 0
    persistence_indicator_count: int = 0
    credential_indicator_count: int = 0
    obfuscation_indicator_count: int = 0
    dynamic_reference_count: int = 0

    suspicious_sheet_count: int = 0

    function_counts: Dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, object]:
        return {
            "worksheet_count": self.worksheet_count,
            "hidden_sheet_count": self.hidden_sheet_count,
            "very_hidden_sheet_count": (self.very_hidden_sheet_count),
            "macrosheet_count": self.macrosheet_count,
            "dialogsheet_count": self.dialogsheet_count,
            "formula_count": self.formula_count,
            "xlm_formula_count": self.xlm_formula_count,
            "suspicious_formula_count": (self.suspicious_formula_count),
            "defined_name_count": self.defined_name_count,
            "xlm_defined_name_count": (self.xlm_defined_name_count),
            "suspicious_defined_name_count": (self.suspicious_defined_name_count),
            "hidden_defined_name_count": (self.hidden_defined_name_count),
            "url_count": self.url_count,
            "external_reference_count": (self.external_reference_count),
            "execution_indicator_count": (self.execution_indicator_count),
            "download_indicator_count": (self.download_indicator_count),
            "persistence_indicator_count": (self.persistence_indicator_count),
            "credential_indicator_count": (self.credential_indicator_count),
            "obfuscation_indicator_count": (self.obfuscation_indicator_count),
            "dynamic_reference_count": (self.dynamic_reference_count),
            "suspicious_sheet_count": (self.suspicious_sheet_count),
            "function_counts": dict(self.function_counts),
        }


@dataclass
class XLMAnalysis:
    """
    Complete static XLM analysis result.
    """

    version: int

    is_ooxml: bool
    is_spreadsheet_package: bool
    parse_error: bool

    package_path: Optional[str]

    sheets: List[XLMSheetRecord]
    formulas: List[XLMFormulaRecord]
    defined_names: List[XLMDefinedNameRecord]

    statistics: XLMStatistics

    has_xlm: bool
    has_macrosheets: bool
    has_suspicious_content: bool

    truncated: bool
    truncation_reasons: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, object]:
        return {
            "version": self.version,
            "is_ooxml": self.is_ooxml,
            "is_spreadsheet_package": (self.is_spreadsheet_package),
            "parse_error": self.parse_error,
            "package_path": self.package_path,
            "sheets": [item.to_dict() for item in self.sheets],
            "formulas": [item.to_dict() for item in self.formulas],
            "defined_names": [item.to_dict() for item in self.defined_names],
            "statistics": self.statistics.to_dict(),
            "has_xlm": self.has_xlm,
            "has_macrosheets": self.has_macrosheets,
            "has_suspicious_content": (self.has_suspicious_content),
            "truncated": self.truncated,
            "truncation_reasons": list(self.truncation_reasons),
        }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _normalize_member_name(name: str) -> str:
    value = str(name or "").replace("\\", "/")

    while value.startswith("./"):
        value = value[2:]

    value = posixpath.normpath(value)

    if value == ".":
        return ""

    return value


def _safe_text(value: object) -> str:
    if value is None:
        return ""

    return str(value).strip()


def _bounded_text(
    value: str,
    max_length: int,
) -> str:
    value = str(value or "")

    if len(value) <= max_length:
        return value

    return value[:max_length]


def _local_name(tag: str) -> str:
    return str(tag).rsplit("}", 1)[-1].lower()


def _relationship_terminal_name(
    relationship_type: str,
) -> str:
    value = str(relationship_type or "").rstrip("/")

    if not value:
        return ""

    return value.rsplit("/", 1)[-1].lower()


def _is_macrosheet_relationship(
    relationship_type: str,
) -> bool:
    return (
        _relationship_terminal_name(relationship_type) in MACROSHEET_RELATIONSHIP_TERMS
    )


def _is_dialogsheet_relationship(
    relationship_type: str,
) -> bool:
    return (
        _relationship_terminal_name(relationship_type) in DIALOGSHEET_RELATIONSHIP_TERMS
    )


def _is_hidden_state(state: str) -> bool:
    return str(state or "").lower() in {
        "hidden",
        "veryhidden",
    }


def _is_very_hidden_state(state: str) -> bool:
    return str(state or "").lower() == "veryhidden"


def _extract_xlm_functions(
    expression: str,
) -> List[str]:
    """
    Extract known XLM function names from an expression.

    Function names are bounded by word/function-like boundaries to reduce
    accidental matches inside unrelated text.
    """

    text = str(expression or "").upper()

    found: List[str] = []

    for function_name in XLM_FUNCTIONS:
        pattern = r"(?<![A-Z0-9_.])" + re.escape(function_name) + r"(?![A-Z0-9_.])"

        if re.search(pattern, text):
            found.append(function_name)

    return sorted(found)


def _contains_xlm_function(
    expression: str,
) -> bool:
    return bool(_extract_xlm_functions(expression))


def _analyze_expression(
    expression: str,
) -> Dict[str, object]:
    """
    Analyze one formula/defined-name expression.
    """

    value = str(expression or "")

    functions = _extract_xlm_functions(value)

    contains_url = bool(URL_PATTERN.search(value))

    contains_unc = bool(UNC_PATTERN.search(value))

    contains_windows_path = bool(WINDOWS_PATH_PATTERN.search(value))

    contains_ipv4 = bool(IPV4_PATTERN.search(value))

    contains_external = bool(EXTERNAL_REFERENCE_PATTERN.search(value))

    contains_execution = bool(
        WINDOWS_EXECUTION_PATTERN.search(value)
        or any(function_name in EXECUTION_FUNCTIONS for function_name in functions)
    )

    contains_download = bool(DOWNLOAD_PATTERN.search(value))

    contains_persistence = bool(PERSISTENCE_PATTERN.search(value))

    contains_credentials = bool(CREDENTIAL_PATTERN.search(value))

    contains_obfuscation = bool(
        OBFUSCATION_PATTERN.search(value)
        or BASE64_LIKE_PATTERN.search(value)
        or HEX_LIKE_PATTERN.search(value)
    )

    contains_dynamic = bool(
        INDIRECT_REFERENCE_PATTERN.search(value)
        or any(function_name in DYNAMIC_FUNCTIONS for function_name in functions)
    )

    is_xlm_like = bool(functions or XLM_FORMULA_PATTERN.search(value))

    suspicious = bool(
        contains_execution
        or contains_download
        or contains_persistence
        or contains_obfuscation
        or (contains_external and is_xlm_like)
        or (contains_dynamic and is_xlm_like)
    )

    return {
        "functions": functions,
        "contains_url": contains_url,
        "contains_unc": contains_unc,
        "contains_windows_path": contains_windows_path,
        "contains_ipv4": contains_ipv4,
        "contains_external": contains_external,
        "contains_execution": contains_execution,
        "contains_download": contains_download,
        "contains_persistence": contains_persistence,
        "contains_credentials": contains_credentials,
        "contains_obfuscation": contains_obfuscation,
        "contains_dynamic": contains_dynamic,
        "is_xlm_like": is_xlm_like,
        "suspicious": suspicious,
    }


def _increment(
    mapping: Dict[str, int],
    key: str,
) -> None:
    mapping[key] = mapping.get(key, 0) + 1


def _resolve_target(
    source: str,
    target: str,
) -> str:
    """
    Resolve an OOXML relationship target against its relationship-file
    directory without accessing the target.

    This is path normalization only.
    """

    target = str(target or "").replace(
        "\\",
        "/",
    )

    if target.startswith("/"):
        return _normalize_member_name(target.lstrip("/"))

    source = _normalize_member_name(source)

    source_dir = posixpath.dirname(source)

    return _normalize_member_name(
        posixpath.join(
            source_dir,
            target,
        )
    )


# ---------------------------------------------------------------------------
# XML readers
# ---------------------------------------------------------------------------


def _read_xml(
    archive: zipfile.ZipFile,
    member_name: str,
) -> Optional[bytes]:
    try:
        info = archive.getinfo(member_name)

        if info.file_size > DEFAULT_MAX_XML_SIZE:
            return None

        return archive.read(member_name)

    except (
        KeyError,
        RuntimeError,
        OSError,
        ValueError,
        zipfile.BadZipFile,
    ):
        return None


def _find_member_case_insensitive(
    names: Sequence[str],
    target: str,
) -> Optional[str]:
    normalized_target = _normalize_member_name(target).lower()

    for name in names:
        if _normalize_member_name(name).lower() == normalized_target:
            return name

    return None


def _find_workbook_member(
    names: Sequence[str],
) -> Optional[str]:
    candidates = [
        "xl/workbook.xml",
        "xl/workbook.xml",
    ]

    for candidate in candidates:
        found = _find_member_case_insensitive(
            names,
            candidate,
        )

        if found:
            return found

    return None


def _find_workbook_relationships(
    names: Sequence[str],
) -> Optional[str]:
    candidates = [
        "xl/_rels/workbook.xml.rels",
    ]

    for candidate in candidates:
        found = _find_member_case_insensitive(
            names,
            candidate,
        )

        if found:
            return found

    return None


# ---------------------------------------------------------------------------
# Relationship parsing
# ---------------------------------------------------------------------------


@dataclass
class _Relationship:
    relationship_id: str
    relationship_type: str
    target: str
    target_mode: str


def _parse_relationships(
    xml_data: bytes,
) -> List[_Relationship]:
    if not xml_data:
        return []

    try:
        root = ET.fromstring(xml_data)
    except (
        ET.ParseError,
        ValueError,
        TypeError,
    ):
        return []

    relationships: List[_Relationship] = []

    for element in root.iter():
        if _local_name(element.tag) != "relationship":
            continue

        relationship_id = _safe_text(element.attrib.get("Id"))

        relationship_type = _safe_text(element.attrib.get("Type"))

        target = _safe_text(element.attrib.get("Target"))

        target_mode = _safe_text(element.attrib.get("TargetMode"))

        relationships.append(
            _Relationship(
                relationship_id=relationship_id,
                relationship_type=relationship_type,
                target=target,
                target_mode=target_mode,
            )
        )

    return relationships


# ---------------------------------------------------------------------------
# Workbook sheet parsing
# ---------------------------------------------------------------------------


@dataclass
class _WorkbookSheet:
    name: str
    state: str
    relationship_id: str


def _parse_workbook_sheets(
    xml_data: bytes,
    *,
    max_sheets: int,
) -> Tuple[
    List[_WorkbookSheet],
    List[Tuple[str, Optional[int], bool, str]],
]:
    """
    Parse workbook sheet metadata and defined names.

    Returns:
        sheets,
        defined_names
    """

    if not xml_data:
        return [], []

    try:
        root = ET.fromstring(xml_data)
    except (
        ET.ParseError,
        ValueError,
        TypeError,
    ):
        return [], []

    sheets: List[_WorkbookSheet] = []

    defined_names: List[Tuple[str, Optional[int], bool, str]] = []

    for element in root.iter():
        local = _local_name(element.tag)

        if local == "sheet":
            if len(sheets) >= max_sheets:
                break

            name = _safe_text(element.attrib.get("name"))

            state = _safe_text(element.attrib.get("state")) or "visible"

            relationship_id = (
                _safe_text(element.attrib.get(f"{{{REL_NS}}}id"))
                or _safe_text(element.attrib.get(f"{{{REL_NS_STRICT}}}id"))
                or _safe_text(element.attrib.get("r:id"))
            )

            sheets.append(
                _WorkbookSheet(
                    name=name,
                    state=state,
                    relationship_id=relationship_id,
                )
            )

        elif local == "definedName":
            name = _safe_text(element.attrib.get("name"))

            local_sheet_id_raw = element.attrib.get("localSheetId")

            local_sheet_id: Optional[int]

            try:
                local_sheet_id = (
                    int(local_sheet_id_raw) if local_sheet_id_raw is not None else None
                )
            except (
                TypeError,
                ValueError,
            ):
                local_sheet_id = None

            hidden_raw = _safe_text(element.attrib.get("hidden")).lower()

            hidden = hidden_raw in {
                "1",
                "true",
            }

            value = _safe_text(element.text)

            defined_names.append(
                (
                    name,
                    local_sheet_id,
                    hidden,
                    value,
                )
            )

    return sheets, defined_names


# ---------------------------------------------------------------------------
# Worksheet formula parsing
# ---------------------------------------------------------------------------


def _parse_formulas(
    xml_data: bytes,
    *,
    sheet_name: str,
    sheet_state: str,
    max_formulas: int,
    max_formula_length: int,
) -> List[XLMFormulaRecord]:
    if not xml_data:
        return []

    try:
        root = ET.fromstring(xml_data)
    except (
        ET.ParseError,
        ValueError,
        TypeError,
    ):
        return []

    records: List[XLMFormulaRecord] = []

    formula_count = 0

    for cell in root.iter():
        if _local_name(cell.tag) != "c":
            continue

        reference = _safe_text(cell.attrib.get("r"))

        for child in cell:
            if _local_name(child.tag) != "f":
                continue

            if formula_count >= max_formulas:
                return records

            formula_count += 1

            formula = _bounded_text(
                _safe_text(child.text),
                max_formula_length,
            )

            # OOXML stores the formula body without the leading "=".
            expression = "=" + formula if formula else ""

            details = _analyze_expression(expression)

            record = XLMFormulaRecord(
                sheet_name=sheet_name,
                sheet_state=sheet_state,
                cell_reference=reference,
                formula=expression,
                formula_length=len(expression),
                is_xlm_like=bool(details["is_xlm_like"]),
                xlm_functions=list(details["functions"]),
                contains_url=bool(details["contains_url"]),
                contains_unc_path=bool(details["contains_unc"]),
                contains_windows_path=bool(details["contains_windows_path"]),
                contains_ipv4=bool(details["contains_ipv4"]),
                contains_external_reference=bool(details["contains_external"]),
                contains_execution_indicator=bool(details["contains_execution"]),
                contains_download_indicator=bool(details["contains_download"]),
                contains_persistence_indicator=bool(details["contains_persistence"]),
                contains_credential_indicator=bool(details["contains_credentials"]),
                contains_obfuscation_indicator=bool(details["contains_obfuscation"]),
                contains_dynamic_reference=bool(details["contains_dynamic"]),
                suspicious=bool(details["suspicious"]),
            )

            records.append(record)

    return records


# ---------------------------------------------------------------------------
# Defined-name analysis
# ---------------------------------------------------------------------------


def _analyze_defined_name(
    name: str,
    local_sheet_id: Optional[int],
    hidden: bool,
    value: str,
    *,
    max_formula_length: int,
) -> XLMDefinedNameRecord:
    expression = _bounded_text(
        value,
        max_formula_length,
    )

    details = _analyze_expression(expression)

    return XLMDefinedNameRecord(
        name=name,
        local_sheet_id=local_sheet_id,
        hidden=hidden,
        value=expression,
        formula_length=len(expression),
        contains_xlm_function=bool(details["is_xlm_like"]),
        xlm_functions=list(details["functions"]),
        contains_url=bool(details["contains_url"]),
        contains_external_reference=bool(details["contains_external"]),
        contains_execution_indicator=bool(details["contains_execution"]),
        contains_download_indicator=bool(details["contains_download"]),
        contains_obfuscation_indicator=bool(details["contains_obfuscation"]),
        contains_dynamic_reference=bool(details["contains_dynamic"]),
        suspicious=bool(details["suspicious"]),
    )


# ---------------------------------------------------------------------------
# Statistics
# ---------------------------------------------------------------------------


def calculate_statistics(
    sheets: Sequence[XLMSheetRecord],
    formulas: Sequence[XLMFormulaRecord],
    defined_names: Sequence[XLMDefinedNameRecord],
) -> XLMStatistics:
    """
    Calculate aggregate XLM statistics.
    """

    stats = XLMStatistics()

    stats.worksheet_count = len(sheets)

    for sheet in sheets:
        if sheet.is_hidden:
            stats.hidden_sheet_count += 1

        if sheet.is_very_hidden:
            stats.very_hidden_sheet_count += 1

        if sheet.is_macrosheet:
            stats.macrosheet_count += 1

        if sheet.is_dialogsheet:
            stats.dialogsheet_count += 1

        stats.formula_count += sheet.formula_count

        stats.xlm_formula_count += sheet.xlm_formula_count

        stats.suspicious_formula_count += sheet.suspicious_formula_count

        stats.url_count += sheet.url_count

        stats.external_reference_count += sheet.external_reference_count

        stats.execution_indicator_count += sheet.execution_indicator_count

        stats.download_indicator_count += sheet.download_indicator_count

        stats.obfuscation_indicator_count += sheet.obfuscation_indicator_count

        if sheet.suspicious:
            stats.suspicious_sheet_count += 1

    for formula in formulas:
        stats.formula_count += 0

        if formula.is_xlm_like:
            stats.xlm_formula_count += 0

        if formula.suspicious:
            stats.suspicious_formula_count += 0

        if formula.contains_url:
            stats.url_count += 0

        if formula.contains_external_reference:
            stats.external_reference_count += 0

        if formula.contains_execution_indicator:
            stats.execution_indicator_count += 0

        if formula.contains_download_indicator:
            stats.download_indicator_count += 0

        if formula.contains_persistence_indicator:
            stats.persistence_indicator_count += 1

        if formula.contains_credential_indicator:
            stats.credential_indicator_count += 1

        if formula.contains_obfuscation_indicator:
            stats.obfuscation_indicator_count += 0

        if formula.contains_dynamic_reference:
            stats.dynamic_reference_count += 0

        for function_name in formula.xlm_functions:
            _increment(
                stats.function_counts,
                function_name,
            )

    # The sheet records already contain aggregate counts for formula/url/
    # execution/etc. Formula-level records are used here for categories that
    # are intentionally not duplicated in sheet aggregation.
    for defined_name in defined_names:
        stats.defined_name_count += 1

        if defined_name.hidden:
            stats.hidden_defined_name_count += 1

        if defined_name.contains_xlm_function:
            stats.xlm_defined_name_count += 1

        if defined_name.suspicious:
            stats.suspicious_defined_name_count += 1

        if defined_name.contains_url:
            stats.url_count += 1

        if defined_name.contains_external_reference:
            stats.external_reference_count += 1

        if defined_name.contains_execution_indicator:
            stats.execution_indicator_count += 1

        if defined_name.contains_download_indicator:
            stats.download_indicator_count += 1

        if defined_name.contains_obfuscation_indicator:
            stats.obfuscation_indicator_count += 1

        if defined_name.contains_dynamic_reference:
            stats.dynamic_reference_count += 1

        for function_name in defined_name.xlm_functions:
            _increment(
                stats.function_counts,
                function_name,
            )

    return stats


# ---------------------------------------------------------------------------
# Main OOXML analyzer
# ---------------------------------------------------------------------------


def analyze_xlm(
    data: bytes,
    *,
    package_path: Optional[str] = None,
    max_worksheets: int = DEFAULT_MAX_WORKSHEETS,
    max_formulas_per_sheet: int = DEFAULT_MAX_FORMULAS_PER_SHEET,
    max_defined_names: int = DEFAULT_MAX_DEFINED_NAMES,
    max_formula_length: int = DEFAULT_MAX_FORMULA_LENGTH,
) -> XLMAnalysis:
    """
    Analyze an OOXML workbook for XLM/Excel 4.0 macro indicators.

    No formula is evaluated and no external target is accessed.
    """

    empty_statistics = XLMStatistics()

    if not isinstance(
        data,
        (bytes, bytearray, memoryview),
    ):
        return XLMAnalysis(
            version=XLM_VERSION,
            is_ooxml=False,
            is_spreadsheet_package=False,
            parse_error=True,
            package_path=package_path,
            sheets=[],
            formulas=[],
            defined_names=[],
            statistics=empty_statistics,
            has_xlm=False,
            has_macrosheets=False,
            has_suspicious_content=False,
            truncated=False,
            truncation_reasons=["input_is_not_bytes"],
        )

    raw = bytes(data)

    sheets_output: List[XLMSheetRecord] = []

    formulas_output: List[XLMFormulaRecord] = []

    defined_names_output: List[XLMDefinedNameRecord] = []

    truncation_reasons: List[str] = []

    is_ooxml = False
    is_spreadsheet_package = False
    parse_error = False

    try:
        with zipfile.ZipFile(
            io.BytesIO(raw),
            "r",
        ) as archive:
            names = archive.namelist()

            normalized = {_normalize_member_name(name).lower() for name in names}

            is_ooxml = "[content_types].xml" in normalized

            workbook_member = _find_workbook_member(names)

            if workbook_member is None:
                return XLMAnalysis(
                    version=XLM_VERSION,
                    is_ooxml=is_ooxml,
                    is_spreadsheet_package=False,
                    parse_error=False,
                    package_path=package_path,
                    sheets=[],
                    formulas=[],
                    defined_names=[],
                    statistics=empty_statistics,
                    has_xlm=False,
                    has_macrosheets=False,
                    has_suspicious_content=False,
                    truncated=False,
                    truncation_reasons=[],
                )

            is_spreadsheet_package = True

            workbook_xml = _read_xml(
                archive,
                workbook_member,
            )

            if workbook_xml is None:
                return XLMAnalysis(
                    version=XLM_VERSION,
                    is_ooxml=is_ooxml,
                    is_spreadsheet_package=True,
                    parse_error=True,
                    package_path=package_path,
                    sheets=[],
                    formulas=[],
                    defined_names=[],
                    statistics=empty_statistics,
                    has_xlm=False,
                    has_macrosheets=False,
                    has_suspicious_content=False,
                    truncated=False,
                    truncation_reasons=["workbook_xml_unavailable"],
                )

            workbook_sheets, workbook_names = _parse_workbook_sheets(
                workbook_xml,
                max_sheets=max_worksheets,
            )

            if len(workbook_sheets) >= max_worksheets:
                truncation_reasons.append("maximum_worksheets_reached")

            if len(workbook_names) > max_defined_names:
                workbook_names = workbook_names[:max_defined_names]

                truncation_reasons.append("maximum_defined_names_reached")

            for (
                name,
                local_sheet_id,
                hidden,
                value,
            ) in workbook_names:
                defined_names_output.append(
                    _analyze_defined_name(
                        name,
                        local_sheet_id,
                        hidden,
                        value,
                        max_formula_length=(max_formula_length),
                    )
                )

            relationship_member = _find_workbook_relationships(names)

            relationships: Dict[str, _Relationship] = {}

            if relationship_member:
                relationship_xml = _read_xml(
                    archive,
                    relationship_member,
                )

                if relationship_xml is not None:
                    for relationship in _parse_relationships(relationship_xml):
                        relationships[relationship.relationship_id] = relationship

            for sheet_index, sheet in enumerate(workbook_sheets):
                relationship = relationships.get(sheet.relationship_id)

                target = relationship.target if relationship else ""

                relationship_type = (
                    relationship.relationship_type if relationship else ""
                )

                target_mode = relationship.target_mode if relationship else ""

                is_macrosheet = _is_macrosheet_relationship(relationship_type)

                is_dialogsheet = _is_dialogsheet_relationship(relationship_type)

                state = sheet.state

                is_hidden = _is_hidden_state(state)

                is_very_hidden = _is_very_hidden_state(state)

                resolved_target = ""

                if relationship:
                    resolved_target = _resolve_target(
                        relationship_member or workbook_member,
                        target,
                    )

                worksheet_member = (
                    _find_member_case_insensitive(
                        names,
                        resolved_target,
                    )
                    if resolved_target
                    else None
                )

                sheet_formulas: List[XLMFormulaRecord] = []

                if worksheet_member:
                    worksheet_xml = _read_xml(
                        archive,
                        worksheet_member,
                    )

                    if worksheet_xml is None:
                        parse_error = True
                    else:
                        sheet_formulas = _parse_formulas(
                            worksheet_xml,
                            sheet_name=sheet.name,
                            sheet_state=state,
                            max_formulas=(max_formulas_per_sheet),
                            max_formula_length=(max_formula_length),
                        )

                        if len(sheet_formulas) >= (max_formulas_per_sheet):
                            truncation_reasons.append(
                                "maximum_formulas_per_sheet_reached:" + sheet.name
                            )

                formulas_output.extend(sheet_formulas)

                url_count = sum(1 for formula in sheet_formulas if formula.contains_url)

                external_count = sum(
                    1
                    for formula in sheet_formulas
                    if formula.contains_external_reference
                )

                execution_count = sum(
                    1
                    for formula in sheet_formulas
                    if formula.contains_execution_indicator
                )

                download_count = sum(
                    1
                    for formula in sheet_formulas
                    if formula.contains_download_indicator
                )

                obfuscation_count = sum(
                    1
                    for formula in sheet_formulas
                    if formula.contains_obfuscation_indicator
                )

                suspicious_formula_count = sum(
                    1 for formula in sheet_formulas if formula.suspicious
                )

                xlm_formula_count = sum(
                    1 for formula in sheet_formulas if formula.is_xlm_like
                )

                suspicious_sheet_name = bool(
                    SUSPICIOUS_SHEET_NAME_PATTERN.search(sheet.name)
                )

                suspicious = bool(
                    is_macrosheet
                    or is_dialogsheet
                    or suspicious_formula_count > 0
                    or (is_hidden and xlm_formula_count > 0)
                    or suspicious_sheet_name
                )

                sheets_output.append(
                    XLMSheetRecord(
                        sheet_name=sheet.name,
                        state=state,
                        relationship_id=(sheet.relationship_id),
                        target=target,
                        relationship_type=(relationship_type),
                        is_macrosheet=(is_macrosheet),
                        is_dialogsheet=(is_dialogsheet),
                        is_hidden=is_hidden,
                        is_very_hidden=(is_very_hidden),
                        formula_count=len(sheet_formulas),
                        xlm_formula_count=(xlm_formula_count),
                        suspicious_formula_count=(suspicious_formula_count),
                        url_count=url_count,
                        external_reference_count=(external_count),
                        execution_indicator_count=(execution_count),
                        download_indicator_count=(download_count),
                        obfuscation_indicator_count=(obfuscation_count),
                        suspicious=suspicious,
                    )
                )

    except (
        zipfile.BadZipFile,
        RuntimeError,
        OSError,
        ValueError,
    ):
        parse_error = True

    statistics = _calculate_statistics_without_double_counting(
        sheets_output,
        formulas_output,
        defined_names_output,
    )

    has_macrosheets = any(sheet.is_macrosheet for sheet in sheets_output)

    has_xlm = bool(
        has_macrosheets
        or statistics.xlm_formula_count > 0
        or statistics.xlm_defined_name_count > 0
    )

    has_suspicious_content = bool(
        statistics.suspicious_formula_count > 0
        or statistics.suspicious_defined_name_count > 0
        or statistics.execution_indicator_count > 0
        or statistics.download_indicator_count > 0
        or statistics.persistence_indicator_count > 0
        or statistics.obfuscation_indicator_count > 0
        or has_macrosheets
    )

    return XLMAnalysis(
        version=XLM_VERSION,
        is_ooxml=is_ooxml,
        is_spreadsheet_package=(is_spreadsheet_package),
        parse_error=parse_error,
        package_path=package_path,
        sheets=sheets_output,
        formulas=formulas_output,
        defined_names=defined_names_output,
        statistics=statistics,
        has_xlm=has_xlm,
        has_macrosheets=has_macrosheets,
        has_suspicious_content=(has_suspicious_content),
        truncated=bool(truncation_reasons),
        truncation_reasons=sorted(set(truncation_reasons)),
    )


def _calculate_statistics_without_double_counting(
    sheets: Sequence[XLMSheetRecord],
    formulas: Sequence[XLMFormulaRecord],
    defined_names: Sequence[XLMDefinedNameRecord],
) -> XLMStatistics:
    """
    Calculate statistics directly from records.

    This intentionally avoids counting formula indicators once at the
    sheet level and again at the formula level.
    """

    stats = XLMStatistics()

    stats.worksheet_count = len(sheets)

    for sheet in sheets:
        if sheet.is_hidden:
            stats.hidden_sheet_count += 1

        if sheet.is_very_hidden:
            stats.very_hidden_sheet_count += 1

        if sheet.is_macrosheet:
            stats.macrosheet_count += 1

        if sheet.is_dialogsheet:
            stats.dialogsheet_count += 1

        if sheet.suspicious:
            stats.suspicious_sheet_count += 1

    stats.formula_count = len(formulas)

    stats.xlm_formula_count = sum(1 for formula in formulas if formula.is_xlm_like)

    stats.suspicious_formula_count = sum(
        1 for formula in formulas if formula.suspicious
    )

    stats.defined_name_count = len(defined_names)

    stats.xlm_defined_name_count = sum(
        1 for name in defined_names if name.contains_xlm_function
    )

    stats.suspicious_defined_name_count = sum(
        1 for name in defined_names if name.suspicious
    )

    stats.hidden_defined_name_count = sum(1 for name in defined_names if name.hidden)

    for formula in formulas:
        if formula.contains_url:
            stats.url_count += 1

        if formula.contains_external_reference:
            stats.external_reference_count += 1

        if formula.contains_execution_indicator:
            stats.execution_indicator_count += 1

        if formula.contains_download_indicator:
            stats.download_indicator_count += 1

        if formula.contains_persistence_indicator:
            stats.persistence_indicator_count += 1

        if formula.contains_credential_indicator:
            stats.credential_indicator_count += 1

        if formula.contains_obfuscation_indicator:
            stats.obfuscation_indicator_count += 1

        if formula.contains_dynamic_reference:
            stats.dynamic_reference_count += 1

        for function_name in formula.xlm_functions:
            _increment(
                stats.function_counts,
                function_name,
            )

    for name in defined_names:
        if name.contains_url:
            stats.url_count += 1

        if name.contains_external_reference:
            stats.external_reference_count += 1

        if name.contains_execution_indicator:
            stats.execution_indicator_count += 1

        if name.contains_download_indicator:
            stats.download_indicator_count += 1

        if name.contains_obfuscation_indicator:
            stats.obfuscation_indicator_count += 1

        if name.contains_dynamic_reference:
            stats.dynamic_reference_count += 1

        for function_name in name.xlm_functions:
            _increment(
                stats.function_counts,
                function_name,
            )

    return stats


def analyze_xlm_file(
    file_path: str | Path,
    *,
    max_worksheets: int = DEFAULT_MAX_WORKSHEETS,
    max_formulas_per_sheet: int = DEFAULT_MAX_FORMULAS_PER_SHEET,
    max_defined_names: int = DEFAULT_MAX_DEFINED_NAMES,
    max_formula_length: int = DEFAULT_MAX_FORMULA_LENGTH,
) -> XLMAnalysis:
    """
    Analyze an OOXML workbook from disk.
    """

    path = Path(file_path)

    try:
        data = path.read_bytes()
    except (
        OSError,
        IOError,
    ):
        return XLMAnalysis(
            version=XLM_VERSION,
            is_ooxml=False,
            is_spreadsheet_package=False,
            parse_error=True,
            package_path=str(path),
            sheets=[],
            formulas=[],
            defined_names=[],
            statistics=XLMStatistics(),
            has_xlm=False,
            has_macrosheets=False,
            has_suspicious_content=False,
            truncated=False,
            truncation_reasons=["file_read_error"],
        )

    return analyze_xlm(
        data,
        package_path=str(path),
        max_worksheets=max_worksheets,
        max_formulas_per_sheet=(max_formulas_per_sheet),
        max_defined_names=max_defined_names,
        max_formula_length=max_formula_length,
    )


# ---------------------------------------------------------------------------
# XLM record helpers
# ---------------------------------------------------------------------------


def find_macrosheets(
    analysis: XLMAnalysis,
) -> List[XLMSheetRecord]:
    """
    Return worksheets identified as Excel 4.0 macro sheets.
    """

    return [sheet for sheet in analysis.sheets if sheet.is_macrosheet]


def find_suspicious_formulas(
    analysis: XLMAnalysis,
) -> List[XLMFormulaRecord]:
    """
    Return formulas that contain suspicious XLM/execution indicators.
    """

    return [formula for formula in analysis.formulas if formula.suspicious]


def find_suspicious_defined_names(
    analysis: XLMAnalysis,
) -> List[XLMDefinedNameRecord]:
    """
    Return suspicious defined names.
    """

    return [item for item in analysis.defined_names if item.suspicious]


def iter_xlm_functions(
    analysis: XLMAnalysis,
) -> Iterable[str]:
    """
    Yield unique XLM function names found in the workbook.
    """

    functions = set()

    for formula in analysis.formulas:
        functions.update(formula.xlm_functions)

    for name in analysis.defined_names:
        functions.update(name.xlm_functions)

    for function_name in sorted(functions):
        yield function_name


# ---------------------------------------------------------------------------
# ML features
# ---------------------------------------------------------------------------


def xlm_features(
    analysis: XLMAnalysis,
) -> Dict[str, object]:
    """
    Convert XLM analysis into ML-ready scalar features.

    Raw formulas, sheet names, targets, and defined-name values are
    deliberately excluded.
    """

    stats = analysis.statistics

    worksheet_count = max(
        stats.worksheet_count,
        1,
    )

    formula_count = max(
        stats.formula_count,
        1,
    )

    xlm_formula_ratio = stats.xlm_formula_count / formula_count

    hidden_sheet_ratio = stats.hidden_sheet_count / worksheet_count

    suspicious_formula_ratio = stats.suspicious_formula_count / formula_count

    return {
        "xlm_version": XLM_VERSION,
        "xlm_is_ooxml": int(analysis.is_ooxml),
        "xlm_is_spreadsheet_package": int(analysis.is_spreadsheet_package),
        "xlm_parse_error": int(analysis.parse_error),
        "xlm_worksheet_count": (stats.worksheet_count),
        "xlm_hidden_sheet_count": (stats.hidden_sheet_count),
        "xlm_very_hidden_sheet_count": (stats.very_hidden_sheet_count),
        "xlm_macrosheet_count": (stats.macrosheet_count),
        "xlm_dialogsheet_count": (stats.dialogsheet_count),
        "xlm_formula_count": (stats.formula_count),
        "xlm_formula_indicator_count": (stats.xlm_formula_count),
        "xlm_suspicious_formula_count": (stats.suspicious_formula_count),
        "xlm_defined_name_count": (stats.defined_name_count),
        "xlm_defined_name_indicator_count": (stats.xlm_defined_name_count),
        "xlm_suspicious_defined_name_count": (stats.suspicious_defined_name_count),
        "xlm_hidden_defined_name_count": (stats.hidden_defined_name_count),
        "xlm_url_count": stats.url_count,
        "xlm_external_reference_count": (stats.external_reference_count),
        "xlm_execution_indicator_count": (stats.execution_indicator_count),
        "xlm_download_indicator_count": (stats.download_indicator_count),
        "xlm_persistence_indicator_count": (stats.persistence_indicator_count),
        "xlm_credential_indicator_count": (stats.credential_indicator_count),
        "xlm_obfuscation_indicator_count": (stats.obfuscation_indicator_count),
        "xlm_dynamic_reference_count": (stats.dynamic_reference_count),
        "xlm_suspicious_sheet_count": (stats.suspicious_sheet_count),
        "xlm_has_xlm": int(analysis.has_xlm),
        "xlm_has_macrosheets": int(analysis.has_macrosheets),
        "xlm_has_suspicious_content": int(analysis.has_suspicious_content),
        "xlm_formula_ratio": (xlm_formula_ratio),
        "xlm_hidden_sheet_ratio": (hidden_sheet_ratio),
        "xlm_suspicious_formula_ratio": (suspicious_formula_ratio),
        "xlm_truncated": int(analysis.truncated),
        "xlm_truncation_count": len(analysis.truncation_reasons),
    }


def extract_xlm_features(
    data: bytes,
    *,
    max_worksheets: int = DEFAULT_MAX_WORKSHEETS,
    max_formulas_per_sheet: int = DEFAULT_MAX_FORMULAS_PER_SHEET,
    max_defined_names: int = DEFAULT_MAX_DEFINED_NAMES,
    max_formula_length: int = DEFAULT_MAX_FORMULA_LENGTH,
) -> Dict[str, object]:
    """
    Convenience API returning only ML-oriented XLM features.
    """

    analysis = analyze_xlm(
        data,
        max_worksheets=max_worksheets,
        max_formulas_per_sheet=(max_formulas_per_sheet),
        max_defined_names=max_defined_names,
        max_formula_length=max_formula_length,
    )

    return xlm_features(analysis)


# ---------------------------------------------------------------------------
# Serialization
# ---------------------------------------------------------------------------


def analysis_to_dict(
    analysis: XLMAnalysis,
) -> Dict[str, object]:
    """
    Return a JSON-serializable analysis dictionary.
    """

    return analysis.to_dict()


# ---------------------------------------------------------------------------
# Compatibility aliases
# ---------------------------------------------------------------------------


def analyze_xlm_workbook(
    data: bytes,
    **kwargs: object,
) -> XLMAnalysis:
    """
    Alias for workbook-oriented callers.
    """

    return analyze_xlm(
        data,
        **kwargs,
    )


def extract_xlm_feature_vector(
    data: bytes,
    **kwargs: object,
) -> Dict[str, object]:
    """
    Alias for ML feature extraction.
    """

    return extract_xlm_features(
        data,
        **kwargs,
    )


__all__ = [
    "XLM_VERSION",
    "XLMFormulaRecord",
    "XLMSheetRecord",
    "XLMDefinedNameRecord",
    "XLMStatistics",
    "XLMAnalysis",
    "analyze_xlm",
    "analyze_xlm_file",
    "analyze_xlm_workbook",
    "calculate_statistics",
    "find_macrosheets",
    "find_suspicious_formulas",
    "find_suspicious_defined_names",
    "iter_xlm_functions",
    "xlm_features",
    "extract_xlm_features",
    "extract_xlm_feature_vector",
    "analysis_to_dict",
]
