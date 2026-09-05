"""
OOXML template relationship analysis.

This module performs static analysis of Microsoft Office Open XML
(OOXML) packages such as:

    .docx
    .docm
    .dotx
    .dotm
    .xlsx
    .xlsm
    .xltx
    .xltm
    .pptx
    .pptm
    .potx
    .potm

The primary purpose is to identify template-related relationships and
template-like references that may be relevant to document malware
analysis.

Security model
--------------
This module is deliberately static-only.

It:
    - reads ZIP/XML package structures
    - inspects relationship files
    - identifies template-related relationship types
    - identifies external template targets
    - identifies remote/network template locations
    - records suspicious target characteristics
    - produces bounded, ML-friendly scalar features

It does NOT:
    - download remote templates
    - resolve network locations
    - execute macros
    - execute templates
    - extract files to the host filesystem
    - follow external relationships
    - modify the source document

The output is intended to feed the broader extraction pipeline:

    OOXML package
          |
          v
    templates.py
          |
          +---- template relationship evidence
          |
          +---- external/remote reference evidence
          |
          +---- suspicious target features
          |
          v
    feature_pipeline.py
          |
          v
    ML / policy / CDR decisions
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple
from urllib.parse import urlparse
import hashlib
import posixpath
import re
import zipfile
import xml.etree.ElementTree as ET

TEMPLATES_VERSION = 1

DEFAULT_MAX_RELATIONSHIP_FILES = 512
DEFAULT_MAX_RELATIONSHIPS_PER_FILE = 1024
DEFAULT_MAX_TARGET_LENGTH = 8192
DEFAULT_MAX_XML_SIZE = 8 * 1024 * 1024


# ---------------------------------------------------------------------------
# OOXML namespaces
# ---------------------------------------------------------------------------

RELATIONSHIP_NAMESPACE = "http://schemas.openxmlformats.org/package/2006/relationships"
RELATIONSHIP_NAMESPACE_STRICT = "http://purl.oclc.org/ooxml/package/relationships"

RELATIONSHIP_NAMESPACES = {
    RELATIONSHIP_NAMESPACE,
    RELATIONSHIP_NAMESPACE_STRICT,
}

XML_NAMESPACE = "http://www.w3.org/XML/1998/namespace"


# Relationship types commonly associated with attached templates.

TEMPLATE_RELATIONSHIP_TYPES = {
    "http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate",
    "http://schemas.openxmlformats.org/officeDocument/2006/relationships/template",
    "http://purl.oclc.org/ooxml/officeDocument/relationships/attachedTemplate",
    "http://purl.oclc.org/ooxml/officeDocument/relationships/template",
}


# Some packages expose template relationships through transitional/strict
# namespaces or with a relationship URI whose terminal component is
# template/attachedTemplate. The exact URI is therefore not the only signal.

TEMPLATE_RELATIONSHIP_TERMS = {
    "template",
    "attachedtemplate",
}


# Relationship targets and content locations that frequently appear around
# template functionality.

TEMPLATE_PATH_TERMS = (
    "template",
    "templates",
    "startup",
    "word",
    "xl",
    "ppt",
)


# ---------------------------------------------------------------------------
# Extensions and target classifications
# ---------------------------------------------------------------------------

TEMPLATE_EXTENSIONS = {
    ".dot",
    ".dotm",
    ".dotx",
    ".pot",
    ".potm",
    ".potx",
    ".xlt",
    ".xltm",
    ".xltx",
    ".doc",
    ".docm",
    ".docx",
    ".xls",
    ".xlsm",
    ".xlsx",
    ".ppt",
    ".pptm",
    ".pptx",
}


MACRO_ENABLED_EXTENSIONS = {
    ".dotm",
    ".potm",
    ".xltm",
    ".docm",
    ".xlsm",
    ".pptm",
}


OFFICE_EXTENSIONS = {
    ".doc",
    ".docm",
    ".docx",
    ".dot",
    ".dotm",
    ".dotx",
    ".xls",
    ".xlsm",
    ".xlsx",
    ".xlt",
    ".xltm",
    ".xltx",
    ".ppt",
    ".pptm",
    ".pptx",
    ".pot",
    ".potm",
    ".potx",
}


SCRIPT_EXTENSIONS = {
    ".bat",
    ".cmd",
    ".com",
    ".js",
    ".jse",
    ".ps1",
    ".psm1",
    ".psd1",
    ".vbe",
    ".vbs",
    ".wsf",
    ".wsh",
}


EXECUTABLE_EXTENSIONS = {
    ".app",
    ".com",
    ".dll",
    ".exe",
    ".msi",
    ".scr",
}


ARCHIVE_EXTENSIONS = {
    ".7z",
    ".cab",
    ".gz",
    ".iso",
    ".rar",
    ".tar",
    ".zip",
}


SUSPICIOUS_EXTENSIONS = SCRIPT_EXTENSIONS | EXECUTABLE_EXTENSIONS


NETWORK_SCHEMES = {
    "http",
    "https",
    "ftp",
    "ftps",
    "smb",
    "file",
    "dav",
    "davs",
}


REMOTE_SCHEMES = {
    "http",
    "https",
    "ftp",
    "ftps",
    "dav",
    "davs",
}


WINDOWS_PATH_PATTERN = re.compile(r"^(?:[A-Za-z]:[\\/]|\\\\|//)")

UNC_PATH_PATTERN = re.compile(r"^(?:\\\\|//)[^\\/]+[\\/][^\\/]+")

URL_PATTERN = re.compile(r"(?i)\b(?:https?|ftps?|davs?|smb|file)://[^\s<>'\"]+")

ENVIRONMENT_VARIABLE_PATTERN = re.compile(r"%[A-Za-z_][A-Za-z0-9_]*%")

MACRO_INDICATOR_PATTERN = re.compile(
    r"(?i)(?:macro|vba|visual\s+basic|autoopen|document_open|workbook_open)"
)

EXECUTION_INDICATOR_PATTERN = re.compile(
    r"(?i)(?:powershell|cmd(?:\.exe)?|wscript|cscript|mshta|rundll32|regsvr32|"
    r"shell|createprocess|winexec|start-process)"
)

DOWNLOAD_INDICATOR_PATTERN = re.compile(
    r"(?i)(?:download|invoke-webrequest|invoke-restmethod|bitsadmin|certutil|"
    r"urlmon|winhttp|internetopen|urldownload)"
)

OBFUSCATION_INDICATOR_PATTERN = re.compile(
    r"(?i)(?:base64|frombase64string|encodedcommand|^0x[0-9a-f]+$|"
    r"chr\s*\(|char\s*\(|replace\s*\(|split\s*\()"
)

SUSPICIOUS_PATH_PATTERN = re.compile(
    r"(?i)(?:\\\\|//|%[a-z0-9_]+%|"
    r"\\windows\\|/windows/|\\system32\\|/system32/|"
    r"\\appdata\\|/appdata/|\\temp\\|/temp/|"
    r"\\startup\\|/startup/)"
)


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TemplateRelationshipRecord:
    """
    One template-related OOXML relationship.

    The target is intentionally preserved as a reference string only.
    It is never dereferenced by this module.
    """

    source_relationship_file: str
    relationship_id: str
    relationship_type: str
    target: str
    target_mode: str

    is_template_relationship: bool
    is_external: bool
    is_remote: bool
    is_unc: bool
    is_absolute_path: bool

    target_extension: str
    target_kind: str

    contains_environment_variable: bool
    contains_macro_indicator: bool
    contains_execution_indicator: bool
    contains_download_indicator: bool
    contains_obfuscation_indicator: bool
    suspicious_target: bool

    normalized_target: str = ""

    def to_dict(self) -> Dict[str, object]:
        return {
            "source_relationship_file": self.source_relationship_file,
            "relationship_id": self.relationship_id,
            "relationship_type": self.relationship_type,
            "target": self.target,
            "target_mode": self.target_mode,
            "is_template_relationship": self.is_template_relationship,
            "is_external": self.is_external,
            "is_remote": self.is_remote,
            "is_unc": self.is_unc,
            "is_absolute_path": self.is_absolute_path,
            "target_extension": self.target_extension,
            "target_kind": self.target_kind,
            "contains_environment_variable": self.contains_environment_variable,
            "contains_macro_indicator": self.contains_macro_indicator,
            "contains_execution_indicator": self.contains_execution_indicator,
            "contains_download_indicator": self.contains_download_indicator,
            "contains_obfuscation_indicator": self.contains_obfuscation_indicator,
            "suspicious_target": self.suspicious_target,
            "normalized_target": self.normalized_target,
        }


@dataclass
class TemplateStatistics:
    """
    Aggregate statistics over template relationships.
    """

    relationship_files_examined: int = 0
    relationship_files_failed: int = 0

    total_relationships: int = 0
    template_relationships: int = 0

    external_template_relationships: int = 0
    remote_template_relationships: int = 0
    unc_template_relationships: int = 0
    absolute_path_template_relationships: int = 0

    office_template_targets: int = 0
    macro_enabled_template_targets: int = 0
    script_targets: int = 0
    executable_targets: int = 0

    suspicious_targets: int = 0
    environment_variable_targets: int = 0

    macro_indicator_targets: int = 0
    execution_indicator_targets: int = 0
    download_indicator_targets: int = 0
    obfuscation_indicator_targets: int = 0

    relationship_types: Dict[str, int] = field(default_factory=dict)
    target_kinds: Dict[str, int] = field(default_factory=dict)
    target_extensions: Dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, object]:
        return {
            "relationship_files_examined": self.relationship_files_examined,
            "relationship_files_failed": self.relationship_files_failed,
            "total_relationships": self.total_relationships,
            "template_relationships": self.template_relationships,
            "external_template_relationships": self.external_template_relationships,
            "remote_template_relationships": self.remote_template_relationships,
            "unc_template_relationships": self.unc_template_relationships,
            "absolute_path_template_relationships": self.absolute_path_template_relationships,
            "office_template_targets": self.office_template_targets,
            "macro_enabled_template_targets": self.macro_enabled_template_targets,
            "script_targets": self.script_targets,
            "executable_targets": self.executable_targets,
            "suspicious_targets": self.suspicious_targets,
            "environment_variable_targets": self.environment_variable_targets,
            "macro_indicator_targets": self.macro_indicator_targets,
            "execution_indicator_targets": self.execution_indicator_targets,
            "download_indicator_targets": self.download_indicator_targets,
            "obfuscation_indicator_targets": self.obfuscation_indicator_targets,
            "relationship_types": dict(self.relationship_types),
            "target_kinds": dict(self.target_kinds),
            "target_extensions": dict(self.target_extensions),
        }


@dataclass
class TemplateAnalysis:
    """
    Complete static template analysis result.
    """

    version: int
    package_path: Optional[str]

    records: List[TemplateRelationshipRecord]
    statistics: TemplateStatistics

    package_is_ooxml: bool
    zip_read_error: bool
    parse_errors: int

    truncated: bool
    truncation_reasons: List[str]

    def to_dict(self) -> Dict[str, object]:
        return {
            "version": self.version,
            "package_path": self.package_path,
            "records": [record.to_dict() for record in self.records],
            "statistics": self.statistics.to_dict(),
            "package_is_ooxml": self.package_is_ooxml,
            "zip_read_error": self.zip_read_error,
            "parse_errors": self.parse_errors,
            "truncated": self.truncated,
            "truncation_reasons": list(self.truncation_reasons),
        }


# ---------------------------------------------------------------------------
# General helpers
# ---------------------------------------------------------------------------


def _normalize_member_name(name: str) -> str:
    """
    Normalize a ZIP member path without resolving it outside the package.
    """

    value = str(name or "").replace("\\", "/")

    while value.startswith("./"):
        value = value[2:]

    value = posixpath.normpath(value)

    if value == ".":
        return ""

    return value


def _extension_from_target(target: str) -> str:
    """
    Extract a lower-case extension from a relationship target.

    Query strings and fragments are ignored.
    """

    clean = str(target or "").split("?", 1)[0].split("#", 1)[0]
    clean = clean.rstrip("/\\")

    name = clean.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]

    if "." not in name:
        return ""

    suffix = "." + name.rsplit(".", 1)[-1].lower()

    if len(suffix) > 16:
        return ""

    return suffix


def _safe_target(target: str, max_length: int) -> str:
    """
    Bound target strings before analysis/storage.
    """

    target = str(target or "")

    if len(target) <= max_length:
        return target

    return target[:max_length]


def _relationship_type_name(relationship_type: str) -> str:
    """
    Return the terminal component of an OOXML relationship URI.
    """

    value = str(relationship_type or "").rstrip("/")

    if not value:
        return ""

    return value.rsplit("/", 1)[-1].lower()


def _is_template_relationship_type(relationship_type: str) -> bool:
    """
    Determine whether a relationship URI is template-related.
    """

    value = str(relationship_type or "").strip().lower()

    if value in {item.lower() for item in TEMPLATE_RELATIONSHIP_TYPES}:
        return True

    terminal = _relationship_type_name(value)

    if terminal in TEMPLATE_RELATIONSHIP_TERMS:
        return True

    return (
        "relationship" in value
        and "template" in value
        and (
            "attachedtemplate" in value
            or value.endswith("/template")
            or terminal == "template"
        )
    )


def _is_external_relationship(target_mode: str) -> bool:
    return str(target_mode or "").strip().lower() == "external"


def _is_remote_target(target: str) -> bool:
    """
    Detect network/remote references without making a network request.
    """

    value = str(target or "").strip()

    if URL_PATTERN.search(value):
        return True

    parsed = urlparse(value)

    if parsed.scheme.lower() in REMOTE_SCHEMES:
        return True

    return False


def _is_unc_target(target: str) -> bool:
    return bool(UNC_PATH_PATTERN.match(str(target or "").strip()))


def _is_absolute_path(target: str) -> bool:
    value = str(target or "").strip()

    if WINDOWS_PATH_PATTERN.match(value):
        return True

    if value.startswith("/"):
        return True

    return False


def _contains_environment_variable(target: str) -> bool:
    return bool(ENVIRONMENT_VARIABLE_PATTERN.search(str(target or "")))


def _target_kind(extension: str, target: str) -> str:
    """
    Classify the target based primarily on its extension.

    A target without an extension remains "unknown" unless its textual
    characteristics provide a stronger classification.
    """

    extension = extension.lower()

    if extension in MACRO_ENABLED_EXTENSIONS:
        return "macro_enabled_office"

    if extension in TEMPLATE_EXTENSIONS:
        return "office_template_or_document"

    if extension in SCRIPT_EXTENSIONS:
        return "script"

    if extension in EXECUTABLE_EXTENSIONS:
        return "executable"

    if extension in ARCHIVE_EXTENSIONS:
        return "archive"

    if extension in OFFICE_EXTENSIONS:
        return "office_document"

    if _is_remote_target(target):
        return "remote_reference"

    if _is_unc_target(target):
        return "network_path"

    return "unknown"


def _is_suspicious_target(
    target: str,
    extension: str,
    *,
    is_remote: bool,
    is_unc: bool,
    is_absolute_path: bool,
    contains_environment_variable: bool,
    contains_macro_indicator: bool,
    contains_execution_indicator: bool,
    contains_download_indicator: bool,
    contains_obfuscation_indicator: bool,
) -> bool:
    """
    Determine whether a template target deserves elevated attention.

    This is intentionally heuristic. It is not a malware verdict.
    """

    if extension in SUSPICIOUS_EXTENSIONS:
        return True

    if is_remote or is_unc:
        return True

    if contains_environment_variable:
        return True

    if contains_execution_indicator:
        return True

    if contains_download_indicator:
        return True

    if contains_obfuscation_indicator:
        return True

    if contains_macro_indicator:
        return True

    if is_absolute_path and bool(SUSPICIOUS_PATH_PATTERN.search(str(target or ""))):
        return True

    return False


def _increment_counter(
    mapping: Dict[str, int],
    key: str,
) -> None:
    mapping[key] = mapping.get(key, 0) + 1


# ---------------------------------------------------------------------------
# XML parsing
# ---------------------------------------------------------------------------


def _parse_relationship_xml(
    xml_data: bytes,
    source_relationship_file: str,
    *,
    max_relationships: int,
    max_target_length: int,
) -> Tuple[List[Tuple[str, str, str, str]], int, bool]:
    """
    Parse an OOXML .rels file.

    Returns:
        relationships,
        parse_errors,
        truncated
    """

    if not xml_data:
        return [], 0, False

    if len(xml_data) > DEFAULT_MAX_XML_SIZE:
        return [], 1, True

    try:
        root = ET.fromstring(xml_data)
    except (ET.ParseError, ValueError, TypeError):
        return [], 1, False

    records: List[Tuple[str, str, str, str]] = []
    truncated = False

    count = 0

    for element in root.iter():
        local_name = element.tag.rsplit("}", 1)[-1].lower()

        if local_name != "relationship":
            continue

        if count >= max_relationships:
            truncated = True
            break

        relationship_id = str(element.attrib.get("Id", "")).strip()

        relationship_type = str(element.attrib.get("Type", "")).strip()

        target = _safe_target(
            str(element.attrib.get("Target", "")),
            max_target_length,
        )

        target_mode = str(element.attrib.get("TargetMode", "")).strip()

        records.append(
            (
                relationship_id,
                relationship_type,
                target,
                target_mode,
            )
        )

        count += 1

    return records, 0, truncated


# ---------------------------------------------------------------------------
# Record construction
# ---------------------------------------------------------------------------


def _build_record(
    *,
    source_relationship_file: str,
    relationship_id: str,
    relationship_type: str,
    target: str,
    target_mode: str,
) -> TemplateRelationshipRecord:
    """
    Build one normalized template relationship record.
    """

    target = str(target or "").strip()

    normalized_target = target.replace("\\", "/")

    extension = _extension_from_target(target)

    relationship_is_template = _is_template_relationship_type(relationship_type)

    is_external = _is_external_relationship(target_mode)
    is_remote = _is_remote_target(target)
    is_unc = _is_unc_target(target)
    is_absolute = _is_absolute_path(target)

    contains_environment_variable = _contains_environment_variable(target)

    contains_macro_indicator = bool(MACRO_INDICATOR_PATTERN.search(target))

    contains_execution_indicator = bool(EXECUTION_INDICATOR_PATTERN.search(target))

    contains_download_indicator = bool(DOWNLOAD_INDICATOR_PATTERN.search(target))

    contains_obfuscation_indicator = bool(OBFUSCATION_INDICATOR_PATTERN.search(target))

    suspicious = _is_suspicious_target(
        target,
        extension,
        is_remote=is_remote,
        is_unc=is_unc,
        is_absolute_path=is_absolute,
        contains_environment_variable=contains_environment_variable,
        contains_macro_indicator=contains_macro_indicator,
        contains_execution_indicator=contains_execution_indicator,
        contains_download_indicator=contains_download_indicator,
        contains_obfuscation_indicator=contains_obfuscation_indicator,
    )

    return TemplateRelationshipRecord(
        source_relationship_file=source_relationship_file,
        relationship_id=relationship_id,
        relationship_type=relationship_type,
        target=target,
        target_mode=target_mode,
        is_template_relationship=relationship_is_template,
        is_external=is_external,
        is_remote=is_remote,
        is_unc=is_unc,
        is_absolute_path=is_absolute,
        target_extension=extension,
        target_kind=_target_kind(extension, target),
        contains_environment_variable=contains_environment_variable,
        contains_macro_indicator=contains_macro_indicator,
        contains_execution_indicator=contains_execution_indicator,
        contains_download_indicator=contains_download_indicator,
        contains_obfuscation_indicator=contains_obfuscation_indicator,
        suspicious_target=suspicious,
        normalized_target=normalized_target,
    )


# ---------------------------------------------------------------------------
# Statistics
# ---------------------------------------------------------------------------


def calculate_statistics(
    records: Sequence[TemplateRelationshipRecord],
    *,
    relationship_files_examined: int = 0,
    relationship_files_failed: int = 0,
    parse_errors: int = 0,
) -> TemplateStatistics:
    """
    Calculate aggregate statistics from template relationship records.
    """

    stats = TemplateStatistics(
        relationship_files_examined=relationship_files_examined,
        relationship_files_failed=relationship_files_failed,
    )

    for record in records:
        stats.total_relationships += 1

        _increment_counter(
            stats.relationship_types,
            _relationship_type_name(record.relationship_type),
        )

        _increment_counter(
            stats.target_kinds,
            record.target_kind,
        )

        if record.target_extension:
            _increment_counter(
                stats.target_extensions,
                record.target_extension,
            )

        if record.is_template_relationship:
            stats.template_relationships += 1

        if not record.is_template_relationship:
            continue

        if record.is_external:
            stats.external_template_relationships += 1

        if record.is_remote:
            stats.remote_template_relationships += 1

        if record.is_unc:
            stats.unc_template_relationships += 1

        if record.is_absolute_path:
            stats.absolute_path_template_relationships += 1

        if record.target_kind == "office_template_or_document":
            stats.office_template_targets += 1

        if record.target_kind == "macro_enabled_office":
            stats.macro_enabled_template_targets += 1

        if record.target_kind == "script":
            stats.script_targets += 1

        if record.target_kind == "executable":
            stats.executable_targets += 1

        if record.suspicious_target:
            stats.suspicious_targets += 1

        if record.contains_environment_variable:
            stats.environment_variable_targets += 1

        if record.contains_macro_indicator:
            stats.macro_indicator_targets += 1

        if record.contains_execution_indicator:
            stats.execution_indicator_targets += 1

        if record.contains_download_indicator:
            stats.download_indicator_targets += 1

        if record.contains_obfuscation_indicator:
            stats.obfuscation_indicator_targets += 1

    return stats


# ---------------------------------------------------------------------------
# OOXML analysis
# ---------------------------------------------------------------------------


def analyze_ooxml_templates(
    data: bytes,
    *,
    package_path: Optional[str] = None,
    max_relationship_files: int = DEFAULT_MAX_RELATIONSHIP_FILES,
    max_relationships_per_file: int = DEFAULT_MAX_RELATIONSHIPS_PER_FILE,
    max_target_length: int = DEFAULT_MAX_TARGET_LENGTH,
) -> TemplateAnalysis:
    """
    Analyze template relationships inside an OOXML package.

    Parameters
    ----------
    data:
        Complete OOXML package bytes.

    package_path:
        Optional source path for reporting only.

    max_relationship_files:
        Maximum number of .rels files to inspect.

    max_relationships_per_file:
        Maximum Relationship elements parsed from each .rels file.

    max_target_length:
        Maximum relationship target length retained.

    Returns
    -------
    TemplateAnalysis
        Structured static-analysis result.

    Notes
    -----
    The input is treated as untrusted data.

    No external relationship target is opened, resolved, downloaded, or
    executed.
    """

    records: List[TemplateRelationshipRecord] = []

    truncation_reasons: List[str] = []

    package_is_ooxml = False
    zip_read_error = False
    parse_errors = 0

    relationship_files_examined = 0
    relationship_files_failed = 0

    truncated = False

    if not isinstance(data, (bytes, bytearray, memoryview)):
        return TemplateAnalysis(
            version=TEMPLATES_VERSION,
            package_path=package_path,
            records=[],
            statistics=TemplateStatistics(),
            package_is_ooxml=False,
            zip_read_error=True,
            parse_errors=1,
            truncated=False,
            truncation_reasons=["input_is_not_bytes"],
        )

    raw_data = bytes(data)

    try:
        with zipfile.ZipFile(
            __import__("io").BytesIO(raw_data),
            "r",
        ) as archive:
            names = archive.namelist()

            normalized_names = {_normalize_member_name(name): name for name in names}

            if (
                "[Content_Types].xml" in normalized_names
                or "_rels/.rels" in normalized_names
            ):
                package_is_ooxml = True

            relationship_names = [
                name
                for name in names
                if _normalize_member_name(name).lower().endswith(".rels")
            ]

            if len(relationship_names) > max_relationship_files:
                relationship_names = relationship_names[:max_relationship_files]
                truncated = True
                truncation_reasons.append("maximum_relationship_files_reached")

            for relationship_name in relationship_names:
                if relationship_files_examined >= max_relationship_files:
                    truncated = True
                    break

                relationship_files_examined += 1

                try:
                    info = archive.getinfo(relationship_name)

                    if info.file_size > DEFAULT_MAX_XML_SIZE:
                        relationship_files_failed += 1
                        parse_errors += 1
                        continue

                    xml_data = archive.read(relationship_name)

                except (
                    KeyError,
                    RuntimeError,
                    OSError,
                    ValueError,
                    zipfile.BadZipFile,
                ):
                    relationship_files_failed += 1
                    parse_errors += 1
                    continue

                parsed, errors, file_truncated = _parse_relationship_xml(
                    xml_data,
                    _normalize_member_name(relationship_name),
                    max_relationships=max_relationships_per_file,
                    max_target_length=max_target_length,
                )

                parse_errors += errors

                if file_truncated:
                    truncated = True
                    truncation_reasons.append(
                        f"maximum_relationships_reached:{_normalize_member_name(relationship_name)}"
                    )

                for (
                    relationship_id,
                    relationship_type,
                    target,
                    target_mode,
                ) in parsed:
                    record = _build_record(
                        source_relationship_file=_normalize_member_name(
                            relationship_name
                        ),
                        relationship_id=relationship_id,
                        relationship_type=relationship_type,
                        target=target,
                        target_mode=target_mode,
                    )

                    if record.is_template_relationship:
                        records.append(record)

    except (
        zipfile.BadZipFile,
        RuntimeError,
        OSError,
        ValueError,
    ):
        zip_read_error = True
        parse_errors += 1

    statistics = calculate_statistics(
        records,
        relationship_files_examined=relationship_files_examined,
        relationship_files_failed=relationship_files_failed,
        parse_errors=parse_errors,
    )

    return TemplateAnalysis(
        version=TEMPLATES_VERSION,
        package_path=package_path,
        records=records,
        statistics=statistics,
        package_is_ooxml=package_is_ooxml,
        zip_read_error=zip_read_error,
        parse_errors=parse_errors,
        truncated=truncated,
        truncation_reasons=sorted(set(truncation_reasons)),
    )


def analyze_ooxml_templates_file(
    file_path: str | Path,
    *,
    max_relationship_files: int = DEFAULT_MAX_RELATIONSHIP_FILES,
    max_relationships_per_file: int = DEFAULT_MAX_RELATIONSHIPS_PER_FILE,
    max_target_length: int = DEFAULT_MAX_TARGET_LENGTH,
) -> TemplateAnalysis:
    """
    Analyze an OOXML file from disk.

    The complete source file is read into memory and passed to the same
    static analyzer used by the byte-oriented API.
    """

    path = Path(file_path)

    try:
        data = path.read_bytes()
    except (OSError, IOError):
        return TemplateAnalysis(
            version=TEMPLATES_VERSION,
            package_path=str(path),
            records=[],
            statistics=TemplateStatistics(),
            package_is_ooxml=False,
            zip_read_error=True,
            parse_errors=1,
            truncated=False,
            truncation_reasons=["file_read_error"],
        )

    return analyze_ooxml_templates(
        data,
        package_path=str(path),
        max_relationship_files=max_relationship_files,
        max_relationships_per_file=max_relationships_per_file,
        max_target_length=max_target_length,
    )


# ---------------------------------------------------------------------------
# Feature extraction
# ---------------------------------------------------------------------------


def template_features(
    analysis: TemplateAnalysis,
) -> Dict[str, object]:
    """
    Convert template analysis into ML-ready scalar/categorical features.

    Raw targets, relationship IDs, paths, and hashes are deliberately not
    included here.

    The feature namespace is prefixed with ``template_`` to reduce collisions
    with features generated by other extraction modules.
    """

    stats = analysis.statistics

    template_count = stats.template_relationships

    external_ratio = (
        stats.external_template_relationships / template_count
        if template_count
        else 0.0
    )

    remote_ratio = (
        stats.remote_template_relationships / template_count if template_count else 0.0
    )

    suspicious_ratio = (
        stats.suspicious_targets / template_count if template_count else 0.0
    )

    macro_enabled_ratio = (
        stats.macro_enabled_template_targets / template_count if template_count else 0.0
    )

    return {
        "template_version": TEMPLATES_VERSION,
        "template_package_is_ooxml": int(analysis.package_is_ooxml),
        "template_zip_read_error": int(analysis.zip_read_error),
        "template_parse_errors": analysis.parse_errors,
        "template_truncated": int(analysis.truncated),
        "template_relationship_files_examined": (stats.relationship_files_examined),
        "template_relationship_files_failed": (stats.relationship_files_failed),
        "template_total_relationships": stats.total_relationships,
        "template_relationship_count": template_count,
        "template_external_count": (stats.external_template_relationships),
        "template_remote_count": (stats.remote_template_relationships),
        "template_unc_count": (stats.unc_template_relationships),
        "template_absolute_path_count": (stats.absolute_path_template_relationships),
        "template_office_target_count": (stats.office_template_targets),
        "template_macro_enabled_count": (stats.macro_enabled_template_targets),
        "template_script_target_count": stats.script_targets,
        "template_executable_target_count": (stats.executable_targets),
        "template_suspicious_count": stats.suspicious_targets,
        "template_environment_variable_count": (stats.environment_variable_targets),
        "template_macro_indicator_count": (stats.macro_indicator_targets),
        "template_execution_indicator_count": (stats.execution_indicator_targets),
        "template_download_indicator_count": (stats.download_indicator_targets),
        "template_obfuscation_indicator_count": (stats.obfuscation_indicator_targets),
        "template_external_ratio": external_ratio,
        "template_remote_ratio": remote_ratio,
        "template_suspicious_ratio": suspicious_ratio,
        "template_macro_enabled_ratio": macro_enabled_ratio,
    }


def extract_template_features(
    data: bytes,
    *,
    max_relationship_files: int = DEFAULT_MAX_RELATIONSHIP_FILES,
    max_relationships_per_file: int = DEFAULT_MAX_RELATIONSHIPS_PER_FILE,
    max_target_length: int = DEFAULT_MAX_TARGET_LENGTH,
) -> Dict[str, object]:
    """
    Convenience API returning only ML-oriented template features.
    """

    analysis = analyze_ooxml_templates(
        data,
        max_relationship_files=max_relationship_files,
        max_relationships_per_file=max_relationships_per_file,
        max_target_length=max_target_length,
    )

    return template_features(analysis)


# ---------------------------------------------------------------------------
# Convenience iterators
# ---------------------------------------------------------------------------


def iter_template_targets(
    analysis: TemplateAnalysis,
    *,
    suspicious_only: bool = False,
) -> Iterable[str]:
    """
    Yield template target references.

    This function exposes references only; it never opens or resolves them.
    """

    for record in analysis.records:
        if suspicious_only and not record.suspicious_target:
            continue

        yield record.target


def iter_template_records(
    analysis: TemplateAnalysis,
    *,
    suspicious_only: bool = False,
) -> Iterable[TemplateRelationshipRecord]:
    """
    Yield template relationship records.
    """

    for record in analysis.records:
        if suspicious_only and not record.suspicious_target:
            continue

        yield record


# ---------------------------------------------------------------------------
# Stable digest helpers
# ---------------------------------------------------------------------------


def template_target_digest(
    analysis: TemplateAnalysis,
) -> Optional[str]:
    """
    Return a stable SHA-256 digest over normalized template targets.

    This can be useful for deduplication/correlation while avoiding the
    need to persist the complete target list as an ML feature.
    """

    targets = sorted(
        record.normalized_target
        for record in analysis.records
        if record.normalized_target
    )

    if not targets:
        return None

    material = "\n".join(targets).encode(
        "utf-8",
        errors="replace",
    )

    return hashlib.sha256(material).hexdigest()


# ---------------------------------------------------------------------------
# Serialization helpers
# ---------------------------------------------------------------------------


def _round_floats(
    value: object,
    digits: int = 6,
) -> object:
    """
    Recursively round floating-point values for stable output.
    """

    if isinstance(value, float):
        return round(value, digits)

    if isinstance(value, dict):
        return {key: _round_floats(item, digits) for key, item in value.items()}

    if isinstance(value, list):
        return [_round_floats(item, digits) for item in value]

    if isinstance(value, tuple):
        return tuple(_round_floats(item, digits) for item in value)

    return value


def analysis_to_dict(
    analysis: TemplateAnalysis,
) -> Dict[str, object]:
    """
    Return a normalized dictionary suitable for JSON serialization.
    """

    result = analysis.to_dict()

    digest = template_target_digest(analysis)

    if digest:
        result["template_target_digest"] = digest

    return _round_floats(result)


__all__ = [
    "TEMPLATES_VERSION",
    "TemplateRelationshipRecord",
    "TemplateStatistics",
    "TemplateAnalysis",
    "analyze_ooxml_templates",
    "analyze_ooxml_templates_file",
    "calculate_statistics",
    "template_features",
    "extract_template_features",
    "iter_template_targets",
    "iter_template_records",
    "template_target_digest",
    "analysis_to_dict",
]
