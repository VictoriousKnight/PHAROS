"""
OOXML relationship analysis.

This module analyzes Open XML relationship files, primarily:

    _rels/.rels
    word/_rels/document.xml.rels
    word/_rels/header1.xml.rels
    word/_rels/footer1.xml.rels
    word/_rels/settings.xml.rels
    xl/_rels/workbook.xml.rels
    xl/worksheets/_rels/*.xml.rels
    ppt/_rels/presentation.xml.rels
    ppt/slides/_rels/*.xml.rels

Relationship files are XML documents containing Relationship elements such
as:

    <Relationship
        Id="rId1"
        Type="..."
        Target="..."
        TargetMode="External" />

This module intentionally performs structural analysis only.

It does NOT:
- fetch external URLs
- resolve network locations
- open embedded objects
- execute relationship targets
- parse the target document
- modify the source archive
- decide that a document is malicious

Those responsibilities belong to higher-level Office/CDR/pipeline modules.

Design goals
------------
1. Parse XML defensively.
2. Never perform network access.
3. Never dereference relationship targets.
4. Return JSON-serializable data.
5. Preserve useful relationship details for later analysis.
6. Provide deterministic scalar features for ML.
7. Detect potentially interesting relationship characteristics without
   treating them as definitive maliciousness.
8. Work both with raw .rels XML bytes and extracted relationship files.
"""

from __future__ import annotations

import posixpath
import re
from collections import Counter
from dataclasses import dataclass
from typing import Any, Iterable, Sequence
from urllib.parse import urlparse
from xml.etree import ElementTree as ET

RELATIONSHIP_NAMESPACE = "http://schemas.openxmlformats.org/package/2006/relationships"

RELATIONSHIP_NAMESPACE_STRICT = "http://purl.oclc.org/ooxml/package/relationships"

XML_NAMESPACE = "http://www.w3.org/XML/1998/namespace"

RELATIONSHIP_TAG = f"{{{RELATIONSHIP_NAMESPACE}}}Relationship"

RELATIONSHIP_TAG_STRICT = f"{{{RELATIONSHIP_NAMESPACE_STRICT}}}Relationship"

RELATIONSHIP_FILE_PATTERN = re.compile(r"(?i)(?:^|/)_rels/[^/]+\.rels$")

EXTERNAL_TARGET_MODES = frozenset(
    {
        "external",
    }
)

EXTERNAL_SCHEMES = frozenset(
    {
        "http",
        "https",
        "ftp",
        "file",
        "javascript",
        "data",
        "mailto",
        "ms-msdt",
        "ms-officecmd",
        "ms-excel",
        "ms-word",
        "ms-powerpoint",
    }
)

NETWORK_SCHEMES = frozenset(
    {
        "http",
        "https",
        "ftp",
        "ftps",
        "ws",
        "wss",
        "smb",
        "nfs",
    }
)

LOCAL_FILE_SCHEMES = frozenset(
    {
        "file",
    }
)

SCRIPT_SCHEMES = frozenset(
    {
        "javascript",
        "vbscript",
        "data",
    }
)

OFFICE_SCHEMES = frozenset(
    {
        "ms-officecmd",
        "ms-excel",
        "ms-word",
        "ms-powerpoint",
    }
)

EMBEDDED_RELATIONSHIP_MARKERS = (
    "oleObject",
    "oleObject",
    "package",
    "embedded",
    "control",
)

HYPERLINK_RELATIONSHIP_MARKERS = ("hyperlink",)

IMAGE_RELATIONSHIP_MARKERS = ("image",)

EXTERNAL_RESOURCE_MARKERS = ("external",)

DANGEROUS_TARGET_EXTENSIONS = frozenset(
    {
        ".bat",
        ".cmd",
        ".com",
        ".cpl",
        ".dll",
        ".exe",
        ".hta",
        ".jar",
        ".js",
        ".jse",
        ".lnk",
        ".msi",
        ".ocx",
        ".ps1",
        ".scr",
        ".sys",
        ".vbe",
        ".vbs",
        ".wsf",
        ".wsh",
    }
)

MACRO_TARGET_EXTENSIONS = frozenset(
    {
        ".bin",
        ".vba",
        ".bas",
        ".cls",
        ".frm",
    }
)

SUSPICIOUS_TARGET_PATTERN = re.compile(
    r"(?i)"
    r"(?:"
    r"javascript:"
    r"|vbscript:"
    r"|data:"
    r"|file:"
    r"|ms-msdt:"
    r"|ms-officecmd:"
    r"|powershell"
    r"|cmd(?:\.exe)?"
    r"|wscript(?:\.exe)?"
    r"|cscript(?:\.exe)?"
    r"|mshta(?:\.exe)?"
    r"|rundll32(?:\.exe)?"
    r"|regsvr32(?:\.exe)?"
    r")"
)

WINDOWS_PATH_PATTERN = re.compile(r"(?i)" r"(?:" r"^[a-z]:[\\/]" r"|^\\\\" r")")

URL_PATTERN = re.compile(r"(?i)" r"^[a-z][a-z0-9+.-]*://")

RELATIONSHIP_ID_PATTERN = re.compile(r"(?i)^rId[0-9]+$")

XML_ID_PATTERN = re.compile(r"(?i)" r"(?:" r"^rId" r"|^id" r")")


@dataclass(frozen=True)
class RelationshipRecord:
    """
    One OOXML Relationship element.

    All fields are textual and JSON serializable.
    """

    relationship_id: str
    relationship_type: str
    target: str
    target_mode: str

    source_part: str | None
    target_part: str | None

    is_external: bool
    is_internal: bool

    scheme: str
    host: str
    port: int | None

    is_network_target: bool
    is_local_file_target: bool
    is_script_target: bool
    is_office_protocol_target: bool

    is_hyperlink: bool
    is_image: bool
    is_embedded_object: bool
    is_external_resource: bool

    target_extension: str
    target_has_query: bool
    target_has_fragment: bool
    target_has_encoded_data: bool
    target_uses_windows_path: bool

    has_suspicious_target_pattern: bool
    has_dangerous_target_extension: bool
    has_macro_target_extension: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "relationship_id": self.relationship_id,
            "relationship_type": self.relationship_type,
            "target": self.target,
            "target_mode": self.target_mode,
            "source_part": self.source_part,
            "target_part": self.target_part,
            "is_external": self.is_external,
            "is_internal": self.is_internal,
            "scheme": self.scheme,
            "host": self.host,
            "port": self.port,
            "is_network_target": self.is_network_target,
            "is_local_file_target": self.is_local_file_target,
            "is_script_target": self.is_script_target,
            "is_office_protocol_target": (self.is_office_protocol_target),
            "is_hyperlink": self.is_hyperlink,
            "is_image": self.is_image,
            "is_embedded_object": self.is_embedded_object,
            "is_external_resource": self.is_external_resource,
            "target_extension": self.target_extension,
            "target_has_query": self.target_has_query,
            "target_has_fragment": self.target_has_fragment,
            "target_has_encoded_data": self.target_has_encoded_data,
            "target_uses_windows_path": (self.target_uses_windows_path),
            "has_suspicious_target_pattern": (self.has_suspicious_target_pattern),
            "has_dangerous_target_extension": (self.has_dangerous_target_extension),
            "has_macro_target_extension": (self.has_macro_target_extension),
        }


@dataclass(frozen=True)
class RelationshipStatistics:
    """
    Aggregate relationship statistics.
    """

    relationship_count: int
    unique_relationship_type_count: int

    external_count: int
    internal_count: int

    hyperlink_count: int
    image_count: int
    embedded_object_count: int
    external_resource_count: int

    network_target_count: int
    local_file_target_count: int
    script_target_count: int
    office_protocol_target_count: int

    suspicious_target_count: int
    dangerous_extension_count: int
    macro_extension_count: int

    target_query_count: int
    target_fragment_count: int
    encoded_target_count: int
    windows_path_target_count: int

    duplicate_relationship_id_count: int
    empty_target_count: int
    empty_type_count: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "relationship_count": self.relationship_count,
            "unique_relationship_type_count": (self.unique_relationship_type_count),
            "external_count": self.external_count,
            "internal_count": self.internal_count,
            "hyperlink_count": self.hyperlink_count,
            "image_count": self.image_count,
            "embedded_object_count": (self.embedded_object_count),
            "external_resource_count": (self.external_resource_count),
            "network_target_count": self.network_target_count,
            "local_file_target_count": (self.local_file_target_count),
            "script_target_count": self.script_target_count,
            "office_protocol_target_count": (self.office_protocol_target_count),
            "suspicious_target_count": (self.suspicious_target_count),
            "dangerous_extension_count": (self.dangerous_extension_count),
            "macro_extension_count": (self.macro_extension_count),
            "target_query_count": self.target_query_count,
            "target_fragment_count": self.target_fragment_count,
            "encoded_target_count": self.encoded_target_count,
            "windows_path_target_count": (self.windows_path_target_count),
            "duplicate_relationship_id_count": (self.duplicate_relationship_id_count),
            "empty_target_count": self.empty_target_count,
            "empty_type_count": self.empty_type_count,
        }


@dataclass(frozen=True)
class RelationshipAnalysis:
    """
    Complete analysis result for a single .rels file.
    """

    source_part: str | None
    relationship_file: str | None

    relationships: tuple[RelationshipRecord, ...]
    statistics: RelationshipStatistics

    parse_success: bool
    parse_error: str | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_part": self.source_part,
            "relationship_file": self.relationship_file,
            "relationships": [
                relationship.to_dict() for relationship in self.relationships
            ],
            "statistics": self.statistics.to_dict(),
            "parse_success": self.parse_success,
            "parse_error": self.parse_error,
        }


def _local_name(tag: str) -> str:
    """
    Return the local XML element name regardless of namespace.
    """

    if not tag:
        return ""

    if "}" in tag:
        return tag.rsplit("}", 1)[-1]

    if ":" in tag:
        return tag.rsplit(":", 1)[-1]

    return tag


def _safe_attribute(
    element: ET.Element,
    name: str,
) -> str:
    value = element.attrib.get(name)

    if value is None:
        return ""

    return str(value).strip()


def _normalize_target_mode(value: str) -> str:
    return value.strip().lower()


def _normalize_relationship_type(value: str) -> str:
    return value.strip()


def _relationship_type_local_name(
    relationship_type: str,
) -> str:
    """
    Extract the final component of a relationship type URI.

    Example:
        http://schemas.openxmlformats.org/officeDocument/2006/
        relationships/hyperlink

    -> hyperlink
    """

    value = relationship_type.strip()

    if not value:
        return ""

    value = value.rstrip("/#")

    if "/" in value:
        value = value.rsplit("/", 1)[-1]

    if "#" in value:
        value = value.rsplit("#", 1)[-1]

    return value


def _normalize_source_part(
    relationship_file: str | None,
) -> str | None:
    """
    Convert a .rels path into the part it describes.

    Examples:

        _rels/.rels
            -> ""

        word/_rels/document.xml.rels
            -> word/document.xml

        xl/worksheets/_rels/sheet1.xml.rels
            -> xl/worksheets/sheet1.xml
    """

    if not relationship_file:
        return None

    normalized = relationship_file.replace("\\", "/").lstrip("/")

    if not normalized.lower().endswith(".rels"):
        return normalized

    if normalized == "_rels/.rels":
        return ""

    marker = "/_rels/"

    if marker not in normalized:
        return normalized[:-5]

    directory, rel_filename = normalized.rsplit(
        marker,
        1,
    )

    if rel_filename.lower().endswith(".rels"):
        rel_filename = rel_filename[:-5]

    if not directory:
        return rel_filename

    return f"{directory}/{rel_filename}"


def _resolve_internal_target(
    target: str,
    source_part: str | None,
) -> str:
    """
    Resolve an OOXML internal relationship target lexically.

    This function never accesses the filesystem or ZIP archive.

    OOXML targets are URI-like paths. Resolution is performed with POSIX
    semantics because package paths use '/' regardless of host OS.
    """

    if not target:
        return ""

    target = target.replace("\\", "/")

    if target.startswith("/"):
        return posixpath.normpath(target.lstrip("/"))

    if source_part is None:
        return posixpath.normpath(target)

    source_directory = posixpath.dirname(source_part)

    return posixpath.normpath(
        posixpath.join(
            source_directory,
            target,
        )
    )


def _extract_target_extension(
    target: str,
) -> str:
    """
    Extract the final target extension without resolving or opening it.
    """

    if not target:
        return ""

    value = target

    for separator in ("?", "#"):
        if separator in value:
            value = value.split(separator, 1)[0]

    value = value.replace("\\", "/")

    basename = value.rsplit("/", 1)[-1]

    if "." not in basename:
        return ""

    extension = basename.rsplit(".", 1)[-1]

    if not extension:
        return ""

    return f".{extension.lower()}"


def _parse_target_url(
    target: str,
) -> tuple[str, str, int | None]:
    """
    Parse URI components without performing any resolution.
    """

    if not target:
        return "", "", None

    try:
        parsed = urlparse(target)
    except ValueError:
        return "", "", None

    scheme = parsed.scheme.lower()
    host = parsed.hostname or ""

    try:
        port = parsed.port
    except ValueError:
        port = None

    return scheme, host, port


def _relationship_has_marker(
    relationship_type: str,
    markers: Sequence[str],
) -> bool:
    local_name = _relationship_type_local_name(relationship_type).lower()

    full_type = relationship_type.lower()

    return any(
        marker.lower() in local_name or marker.lower() in full_type
        for marker in markers
    )


def _classify_relationship(
    *,
    relationship_id: str,
    relationship_type: str,
    target: str,
    target_mode: str,
    source_part: str | None,
) -> RelationshipRecord:
    normalized_mode = _normalize_target_mode(target_mode)

    is_external = normalized_mode in EXTERNAL_TARGET_MODES or bool(
        URL_PATTERN.match(target)
    )

    is_internal = not is_external

    scheme, host, port = _parse_target_url(target)

    is_network_target = scheme in NETWORK_SCHEMES or (is_external and bool(host))

    is_local_file_target = scheme in LOCAL_FILE_SCHEMES or bool(
        WINDOWS_PATH_PATTERN.match(target)
    )

    is_script_target = scheme in SCRIPT_SCHEMES or (
        _extract_target_extension(target)
        in {
            ".js",
            ".jse",
            ".ps1",
            ".vbe",
            ".vbs",
            ".wsf",
            ".wsh",
        }
    )

    is_office_protocol_target = scheme in OFFICE_SCHEMES

    is_hyperlink = _relationship_has_marker(
        relationship_type,
        HYPERLINK_RELATIONSHIP_MARKERS,
    )

    is_image = _relationship_has_marker(
        relationship_type,
        IMAGE_RELATIONSHIP_MARKERS,
    )

    is_embedded_object = _relationship_has_marker(
        relationship_type,
        EMBEDDED_RELATIONSHIP_MARKERS,
    )

    is_external_resource = is_external or _relationship_has_marker(
        relationship_type,
        EXTERNAL_RESOURCE_MARKERS,
    )

    target_extension = _extract_target_extension(target)

    target_has_query = "?" in target
    target_has_fragment = "#" in target

    target_has_encoded_data = "%" in target or (target_has_query and "=" in target)

    target_uses_windows_path = bool(WINDOWS_PATH_PATTERN.match(target))

    has_suspicious_target_pattern = bool(SUSPICIOUS_TARGET_PATTERN.search(target))

    has_dangerous_target_extension = target_extension in DANGEROUS_TARGET_EXTENSIONS

    has_macro_target_extension = target_extension in MACRO_TARGET_EXTENSIONS

    resolved_target = _resolve_internal_target(
        target,
        source_part,
    )

    target_part = resolved_target if is_internal else None

    return RelationshipRecord(
        relationship_id=relationship_id,
        relationship_type=relationship_type,
        target=target,
        target_mode=normalized_mode,
        source_part=source_part,
        target_part=target_part,
        is_external=is_external,
        is_internal=is_internal,
        scheme=scheme,
        host=host,
        port=port,
        is_network_target=is_network_target,
        is_local_file_target=is_local_file_target,
        is_script_target=is_script_target,
        is_office_protocol_target=(is_office_protocol_target),
        is_hyperlink=is_hyperlink,
        is_image=is_image,
        is_embedded_object=is_embedded_object,
        is_external_resource=is_external_resource,
        target_extension=target_extension,
        target_has_query=target_has_query,
        target_has_fragment=target_has_fragment,
        target_has_encoded_data=target_has_encoded_data,
        target_uses_windows_path=(target_uses_windows_path),
        has_suspicious_target_pattern=(has_suspicious_target_pattern),
        has_dangerous_target_extension=(has_dangerous_target_extension),
        has_macro_target_extension=(has_macro_target_extension),
    )


def _find_relationship_elements(
    root: ET.Element,
) -> list[ET.Element]:
    """
    Locate Relationship elements by local name.

    OOXML relationship files normally use the standard namespace, but local
    name matching makes the parser tolerant of namespace-prefix variations.
    """

    return [
        element
        for element in root.iter()
        if _local_name(element.tag).lower() == "relationship"
    ]


def _parse_xml(
    data: bytes,
) -> ET.Element:
    """
    Parse XML using ElementTree.

    The standard library parser does not perform network retrieval of
    external entities. XML input is still treated as untrusted data.
    """

    if not data:
        raise ValueError("Relationship XML is empty")

    return ET.fromstring(data)


def calculate_relationship_statistics(
    relationships: Sequence[RelationshipRecord],
) -> RelationshipStatistics:
    if not relationships:
        return RelationshipStatistics(
            relationship_count=0,
            unique_relationship_type_count=0,
            external_count=0,
            internal_count=0,
            hyperlink_count=0,
            image_count=0,
            embedded_object_count=0,
            external_resource_count=0,
            network_target_count=0,
            local_file_target_count=0,
            script_target_count=0,
            office_protocol_target_count=0,
            suspicious_target_count=0,
            dangerous_extension_count=0,
            macro_extension_count=0,
            target_query_count=0,
            target_fragment_count=0,
            encoded_target_count=0,
            windows_path_target_count=0,
            duplicate_relationship_id_count=0,
            empty_target_count=0,
            empty_type_count=0,
        )

    relationship_types = {
        relationship.relationship_type
        for relationship in relationships
        if relationship.relationship_type
    }

    relationship_ids = [
        relationship.relationship_id
        for relationship in relationships
        if relationship.relationship_id
    ]

    id_counts = Counter(relationship_ids)

    duplicate_id_count = sum(count - 1 for count in id_counts.values() if count > 1)

    return RelationshipStatistics(
        relationship_count=len(relationships),
        unique_relationship_type_count=len(relationship_types),
        external_count=sum(relationship.is_external for relationship in relationships),
        internal_count=sum(relationship.is_internal for relationship in relationships),
        hyperlink_count=sum(
            relationship.is_hyperlink for relationship in relationships
        ),
        image_count=sum(relationship.is_image for relationship in relationships),
        embedded_object_count=sum(
            relationship.is_embedded_object for relationship in relationships
        ),
        external_resource_count=sum(
            relationship.is_external_resource for relationship in relationships
        ),
        network_target_count=sum(
            relationship.is_network_target for relationship in relationships
        ),
        local_file_target_count=sum(
            relationship.is_local_file_target for relationship in relationships
        ),
        script_target_count=sum(
            relationship.is_script_target for relationship in relationships
        ),
        office_protocol_target_count=sum(
            relationship.is_office_protocol_target for relationship in relationships
        ),
        suspicious_target_count=sum(
            relationship.has_suspicious_target_pattern for relationship in relationships
        ),
        dangerous_extension_count=sum(
            relationship.has_dangerous_target_extension
            for relationship in relationships
        ),
        macro_extension_count=sum(
            relationship.has_macro_target_extension for relationship in relationships
        ),
        target_query_count=sum(
            relationship.target_has_query for relationship in relationships
        ),
        target_fragment_count=sum(
            relationship.target_has_fragment for relationship in relationships
        ),
        encoded_target_count=sum(
            relationship.target_has_encoded_data for relationship in relationships
        ),
        windows_path_target_count=sum(
            relationship.target_uses_windows_path for relationship in relationships
        ),
        duplicate_relationship_id_count=(duplicate_id_count),
        empty_target_count=sum(
            not relationship.target for relationship in relationships
        ),
        empty_type_count=sum(
            not relationship.relationship_type for relationship in relationships
        ),
    )


def analyze_relationship_xml(
    data: bytes,
    *,
    relationship_file: str | None = None,
    source_part: str | None = None,
    max_relationships: int = 10_000,
) -> RelationshipAnalysis:
    """
    Analyze one OOXML .rels XML document.

    Parameters
    ----------
    data:
        Raw XML bytes.

    relationship_file:
        Optional package path such as:
        "word/_rels/document.xml.rels".

    source_part:
        Optional package part described by the relationship file.

    max_relationships:
        Hard limit on relationship records returned.
    """

    if max_relationships <= 0:
        raise ValueError("max_relationships must be greater than zero")

    if source_part is None:
        source_part = _normalize_source_part(relationship_file)

    try:
        root = _parse_xml(data)
    except (
        ET.ParseError,
        ValueError,
        TypeError,
    ) as exc:
        return RelationshipAnalysis(
            source_part=source_part,
            relationship_file=relationship_file,
            relationships=(),
            statistics=calculate_relationship_statistics(()),
            parse_success=False,
            parse_error=(f"{type(exc).__name__}: {exc}"),
        )

    elements = _find_relationship_elements(root)

    relationships: list[RelationshipRecord] = []

    for element in elements[:max_relationships]:
        relationship_id = _safe_attribute(
            element,
            "Id",
        )

        relationship_type = _normalize_relationship_type(
            _safe_attribute(
                element,
                "Type",
            )
        )

        target = _safe_attribute(
            element,
            "Target",
        )

        target_mode = _normalize_target_mode(
            _safe_attribute(
                element,
                "TargetMode",
            )
        )

        relationship = _classify_relationship(
            relationship_id=relationship_id,
            relationship_type=relationship_type,
            target=target,
            target_mode=target_mode,
            source_part=source_part,
        )

        relationships.append(relationship)

    statistics = calculate_relationship_statistics(relationships)

    return RelationshipAnalysis(
        source_part=source_part,
        relationship_file=relationship_file,
        relationships=tuple(relationships),
        statistics=statistics,
        parse_success=True,
        parse_error=None,
    )


def analyze_relationship_file(
    file_path: str,
    *,
    relationship_file: str | None = None,
    source_part: str | None = None,
    max_relationships: int = 10_000,
) -> RelationshipAnalysis:
    """
    Analyze a .rels file from disk.

    The file is read as bytes and parsed as XML. No relationship target is
    accessed.
    """

    with open(file_path, "rb") as handle:
        data = handle.read()

    return analyze_relationship_xml(
        data,
        relationship_file=relationship_file,
        source_part=source_part,
        max_relationships=max_relationships,
    )


def is_relationship_file(
    package_path: str,
) -> bool:
    """
    Return True when a package path appears to be an OOXML relationship file.
    """

    normalized = package_path.replace(
        "\\",
        "/",
    ).lstrip("/")

    if not normalized.lower().endswith(".rels"):
        return False

    if normalized == "_rels/.rels":
        return True

    return "/_rels/" in normalized


def relationship_source_part(
    relationship_file: str,
) -> str | None:
    """
    Public wrapper for relationship-file -> source-part conversion.
    """

    return _normalize_source_part(relationship_file)


def relationship_type_name(
    relationship_type: str,
) -> str:
    """
    Return the final semantic component of a relationship type URI.
    """

    return _relationship_type_local_name(relationship_type)


def relationship_features(
    analysis: RelationshipAnalysis,
) -> dict[str, Any]:
    """
    Convert relationship analysis into ML-friendly scalar features.

    Raw targets and relationship records are deliberately excluded.
    """

    statistics = analysis.statistics

    features: dict[str, Any] = {
        "relationships_version": 1,
        "relationships_parse_success": (analysis.parse_success),
        "relationships_count": (statistics.relationship_count),
        "relationships_unique_type_count": (statistics.unique_relationship_type_count),
        "relationships_external_count": (statistics.external_count),
        "relationships_internal_count": (statistics.internal_count),
        "relationships_hyperlink_count": (statistics.hyperlink_count),
        "relationships_image_count": (statistics.image_count),
        "relationships_embedded_object_count": (statistics.embedded_object_count),
        "relationships_external_resource_count": (statistics.external_resource_count),
        "relationships_network_target_count": (statistics.network_target_count),
        "relationships_local_file_target_count": (statistics.local_file_target_count),
        "relationships_script_target_count": (statistics.script_target_count),
        "relationships_office_protocol_target_count": (
            statistics.office_protocol_target_count
        ),
        "relationships_suspicious_target_count": (statistics.suspicious_target_count),
        "relationships_dangerous_extension_count": (
            statistics.dangerous_extension_count
        ),
        "relationships_macro_extension_count": (statistics.macro_extension_count),
        "relationships_target_query_count": (statistics.target_query_count),
        "relationships_target_fragment_count": (statistics.target_fragment_count),
        "relationships_encoded_target_count": (statistics.encoded_target_count),
        "relationships_windows_path_target_count": (
            statistics.windows_path_target_count
        ),
        "relationships_duplicate_id_count": (
            statistics.duplicate_relationship_id_count
        ),
        "relationships_empty_target_count": (statistics.empty_target_count),
        "relationships_empty_type_count": (statistics.empty_type_count),
        "relationships_has_external": (statistics.external_count > 0),
        "relationships_has_network_target": (statistics.network_target_count > 0),
        "relationships_has_local_file_target": (statistics.local_file_target_count > 0),
        "relationships_has_script_target": (statistics.script_target_count > 0),
        "relationships_has_office_protocol_target": (
            statistics.office_protocol_target_count > 0
        ),
        "relationships_has_hyperlink": (statistics.hyperlink_count > 0),
        "relationships_has_embedded_object": (statistics.embedded_object_count > 0),
        "relationships_has_suspicious_target": (statistics.suspicious_target_count > 0),
        "relationships_has_dangerous_extension": (
            statistics.dangerous_extension_count > 0
        ),
        "relationships_has_macro_extension": (statistics.macro_extension_count > 0),
        "relationships_has_duplicate_ids": (
            statistics.duplicate_relationship_id_count > 0
        ),
        "relationships_has_empty_target": (statistics.empty_target_count > 0),
        "relationships_has_encoded_target": (statistics.encoded_target_count > 0),
    }

    return _round_floats(features)


def analyze_relationships(
    relationship_documents: Iterable[tuple[str | None, bytes]],
    *,
    max_relationships_per_file: int = 10_000,
) -> dict[str, Any]:
    """
    Analyze multiple relationship documents.

    Parameters
    ----------
    relationship_documents:
        Iterable of:
            (relationship_file_path, raw_xml_bytes)

        Example:
            (
                "word/_rels/document.xml.rels",
                b"...",
            )

    Returns
    -------
    dict
        Aggregate relationship analysis plus per-file details.
    """

    analyses: list[RelationshipAnalysis] = []

    for relationship_file, data in relationship_documents:
        analyses.append(
            analyze_relationship_xml(
                data,
                relationship_file=relationship_file,
                max_relationships=max_relationships_per_file,
            )
        )

    all_relationships: list[RelationshipRecord] = []

    parse_success_count = 0
    parse_failure_count = 0

    for analysis in analyses:
        if analysis.parse_success:
            parse_success_count += 1
        else:
            parse_failure_count += 1

        all_relationships.extend(analysis.relationships)

    aggregate_statistics = calculate_relationship_statistics(all_relationships)

    feature_result = relationship_features(
        RelationshipAnalysis(
            source_part=None,
            relationship_file=None,
            relationships=tuple(all_relationships),
            statistics=aggregate_statistics,
            parse_success=(parse_failure_count == 0),
            parse_error=None,
        )
    )

    return _round_floats(
        {
            "relationships_version": 1,
            "relationship_file_count": len(analyses),
            "relationship_files_parse_success": (parse_success_count),
            "relationship_files_parse_failure": (parse_failure_count),
            "relationship_files": [analysis.to_dict() for analysis in analyses],
            "statistics": (aggregate_statistics.to_dict()),
            "features": feature_result,
        }
    )


def extract_relationship_features(
    relationship_xml: bytes,
    *,
    relationship_file: str | None = None,
    source_part: str | None = None,
    max_relationships: int = 10_000,
) -> dict[str, Any]:
    """
    Convenience function for feature_pipeline.py.
    """

    analysis = analyze_relationship_xml(
        relationship_xml,
        relationship_file=relationship_file,
        source_part=source_part,
        max_relationships=max_relationships,
    )

    return relationship_features(analysis)


def _round_floats(
    value: Any,
    digits: int = 6,
) -> Any:
    if isinstance(value, float):
        return round(value, digits)

    if isinstance(value, list):
        return [_round_floats(item, digits) for item in value]

    if isinstance(value, tuple):
        return tuple(_round_floats(item, digits) for item in value)

    if isinstance(value, dict):
        return {
            key: _round_floats(
                item,
                digits,
            )
            for key, item in value.items()
        }

    return value


__all__ = [
    "RELATIONSHIP_NAMESPACE",
    "RELATIONSHIP_NAMESPACE_STRICT",
    "RelationshipRecord",
    "RelationshipStatistics",
    "RelationshipAnalysis",
    "is_relationship_file",
    "relationship_source_part",
    "relationship_type_name",
    "calculate_relationship_statistics",
    "analyze_relationship_xml",
    "analyze_relationship_file",
    "analyze_relationships",
    "relationship_features",
    "extract_relationship_features",
]
