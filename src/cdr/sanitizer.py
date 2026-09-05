"""
pharos-cdr: static Office document sanitizer.

This module implements bounded, in-memory Content Disarm and Reconstruction
(CDR) sanitization for ZIP/OOXML-based Office documents.

Security model
--------------
The sanitizer is strictly defensive:

* It never executes macros, scripts, formulas, embedded files, or commands.
* It never launches processes.
* It never resolves or downloads external URLs.
* It never loads DLLs or native libraries.
* It never writes intermediate untrusted content to disk.
* It performs archive processing in memory.
* It applies hard limits to archive entry count, entry sizes, and aggregate
  uncompressed size.
* It rejects malformed or unsafe archive structures rather than attempting
  unsafe recovery.

Primary targets
---------------
The sanitizer is designed for OOXML documents such as:

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
    .ppsx
    .ppsm

The implementation removes or neutralizes common active-content structures:

* VBA projects
* Excel 4/XLM macro sheets
* ActiveX controls
* embedded OLE/package objects
* external relationships
* remote templates
* DDE-related relationship/content-type references
* macro-enabled content types where the corresponding active payload was
  removed
* script-like embedded payloads
* external-link relationships
* selected custom XML/control structures associated with active content

The sanitizer deliberately does not claim that every possible Office threat
is removed. Unknown or unsupported structures should be handled by the policy,
detector, reconstruction, and integrity layers.

Typical usage
-------------

    result = sanitize_document(
        document_bytes,
        remove_vba=True,
        remove_xlm=True,
        remove_activex=True,
        remove_embedded_objects=True,
        remove_external_relationships=True,
    )

    clean_bytes = result.data

The returned object contains both the sanitized bytes and a deterministic
record of what was changed.
"""

from __future__ import annotations

import hashlib
import io
import math
import os
import posixpath
import re
import zipfile
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import (
    Any,
    Dict,
    Iterable,
    Iterator,
    List,
    Mapping,
    MutableMapping,
    Optional,
    Sequence,
    Set,
    Tuple,
)
from xml.etree import ElementTree as ET

from cdr.detector import MAX_VALUE_LENGTH


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MODULE_NAME = "cdr.sanitizer"
SANITIZER_VERSION = "1.0.0"

MAX_INPUT_BYTES = 50 * 1024 * 1024
MAX_OUTPUT_BYTES = 75 * 1024 * 1024

MAX_ZIP_ENTRIES = 10_000
MAX_ENTRY_SIZE = 100 * 1024 * 1024
MAX_TOTAL_UNCOMPRESSED = 250 * 1024 * 1024
MAX_TOTAL_COMPRESSED = 100 * 1024 * 1024
MAX_ENTRY_NAME_LENGTH = 4_096

MAX_XML_BYTES = 25 * 1024 * 1024
MAX_XML_DEPTH = 100
MAX_XML_ATTRIBUTES = 20_000
MAX_XML_ELEMENTS = 500_000

MAX_ACTIONS = 20_000
MAX_REMOVED_ENTRIES = 20_000
MAX_MODIFIED_ENTRIES = 20_000
MAX_WARNINGS = 5_000

DEFAULT_COMPRESSION = zipfile.ZIP_DEFLATED
DEFAULT_COMPRESSLEVEL = 6

# OOXML relationship namespace.
REL_NS = "http://schemas.openxmlformats.org/package/2006/relationships"

# Transitional and common OOXML content-type namespace.
CT_NS = "http://schemas.openxmlformats.org/package/2006/content-types"

# Strict OOXML namespaces.
STRICT_REL_NS = "http://purl.oclc.org/ooxml-package/relationships"
STRICT_CT_NS = "http://purl.oclc.org/ooxml-package/content-types"

# Common Office namespaces.
OFFICE_NS = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
OFFICE_NS_STRICT = "http://purl.oclc.org/ooxml/officeDocument/relationships"

# Relationship types which should not survive sanitization.
RELATIONSHIP_VBA = {
    "http://schemas.microsoft.com/office/2006/relationships/vbaProject",
    "http://schemas.microsoft.com/office/2006/relationships/vbaProjectSignature",
    "http://schemas.microsoft.com/office/2019/relationships/vbaProject",
}

RELATIONSHIP_EXTERNAL_LINK = {
    "http://schemas.openxmlformats.org/officeDocument/2006/relationships/externalLink",
    "http://purl.oclc.org/ooxml/officeDocument/relationships/externalLink",
}

RELATIONSHIP_OLE_OBJECT = {
    "http://schemas.openxmlformats.org/officeDocument/2006/relationships/oleObject",
    "http://purl.oclc.org/ooxml/officeDocument/relationships/oleObject",
}

RELATIONSHIP_PACKAGE = {
    "http://schemas.openxmlformats.org/officeDocument/2006/relationships/package",
    "http://purl.oclc.org/ooxml/officeDocument/relationships/package",
}

RELATIONSHIP_CONTROL = {
    "http://schemas.openxmlformats.org/officeDocument/2006/relationships/control",
    "http://purl.oclc.org/ooxml/officeDocument/relationships/control",
}

RELATIONSHIP_ATTACHED_TEMPLATE = {
    "http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate",
    "http://purl.oclc.org/ooxml/officeDocument/relationships/attachedTemplate",
}

RELATIONSHIP_IMAGE = {
    "http://schemas.openxmlformats.org/officeDocument/2006/relationships/image",
    "http://purl.oclc.org/ooxml/officeDocument/relationships/image",
}

# Relationship targets/types which are normally unsafe when external.
EXTERNAL_RELATIONSHIP_TYPES = (
    RELATIONSHIP_EXTERNAL_LINK
    | RELATIONSHIP_ATTACHED_TEMPLATE
)

# Active-content relationship types.
ACTIVE_RELATIONSHIP_TYPES = (
    RELATIONSHIP_VBA
    | RELATIONSHIP_OLE_OBJECT
    | RELATIONSHIP_PACKAGE
    | RELATIONSHIP_CONTROL
    | RELATIONSHIP_ATTACHED_TEMPLATE
)

# Entries that contain active content.
VBA_ENTRY_NAMES = {
    "vbaProject.bin",
    "vbaProjectSignature.bin",
}

ACTIVE_DIRECTORY_MARKERS = (
    "word/activeX/",
    "xl/activeX/",
    "ppt/activeX/",
    "word/embeddings/",
    "xl/embeddings/",
    "ppt/embeddings/",
)

XLM_DIRECTORY_MARKERS = (
    "xl/macrosheets/",
    "xl/macroSheets/",
)

EXTERNAL_LINK_DIRECTORY_MARKERS = (
    "xl/externalLinks/",
)

REMOTE_TEMPLATE_NAMES = {
    "word/settings.xml",
    "word/webSettings.xml",
}

# Macro-enabled content types.
MACRO_CONTENT_TYPES = {
    "application/vnd.ms-word.document.macroEnabled.main+xml",
    "application/vnd.ms-word.template.macroEnabledTemplate.main+xml",
    "application/vnd.ms-excel.sheet.macroEnabled.main+xml",
    "application/vnd.ms-excel.template.macroEnabled.main+xml",
    "application/vnd.ms-powerpoint.presentation.macroEnabled.main+xml",
    "application/vnd.ms-powerpoint.template.macroEnabled.main+xml",
    "application/vnd.ms-powerpoint.slideshow.macroEnabled.main+xml",
}

VBA_CONTENT_TYPES = {
    "application/vnd.ms-office.vbaProject",
    "application/vnd.ms-office.vbaProjectSignature",
}

ACTIVEX_CONTENT_TYPE_MARKERS = (
    "activeX",
    "control",
)

EMBEDDED_CONTENT_TYPE_MARKERS = (
    "oleObject",
    "package",
)

# DDE-related textual indicators. These are used only in XML fields and
# relationship metadata; no field is evaluated.
DDE_PATTERNS = (
    re.compile(r"\bdde(?:auto)?\b", re.IGNORECASE),
    re.compile(r"\bdde\s*:", re.IGNORECASE),
    re.compile(r"\bapplication\s*=\s*[\"']dde", re.IGNORECASE),
)

# Relationship targets can use relative paths. Only package-local references
# are considered for removal; external targets are removed by relationship
# policy.
URL_SCHEMES = (
    "http:",
    "https:",
    "ftp:",
    "file:",
    "ms-",
)


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class SanitizerError(Exception):
    """Base sanitizer exception."""


class SanitizerInputError(SanitizerError):
    """Raised when sanitizer input is invalid or unsafe."""


class SanitizerArchiveError(SanitizerError):
    """Raised when a ZIP/OOXML archive is malformed or violates limits."""


class SanitizerOutputError(SanitizerError):
    """Raised when a sanitized document cannot be reconstructed safely."""


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class SanitizationAction(str, Enum):
    """Action applied to a document component."""

    PRESERVE = "preserve"
    REMOVE = "remove"
    REWRITE = "rewrite"
    REJECT = "reject"


class SanitizationReason(str, Enum):
    """Reason a component was changed."""

    VBA = "vba"
    XLM = "xlm"
    ACTIVEX = "activex"
    EMBEDDED_OBJECT = "embedded_object"
    EMBEDDED_SCRIPT = "embedded_script"
    EXTERNAL_RELATIONSHIP = "external_relationship"
    REMOTE_TEMPLATE = "remote_template"
    DDE = "dde"
    MACRO_CONTENT_TYPE = "macro_content_type"
    ACTIVE_CONTENT_TYPE = "active_content_type"
    INVALID_REFERENCE = "invalid_reference"
    UNSAFE_ARCHIVE = "unsafe_archive"
    MALFORMED_XML = "malformed_xml"
    POLICY = "policy"


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SanitizationActionRecord:
    """Record of one sanitizer operation."""

    action: SanitizationAction
    reason: SanitizationReason
    path: str
    detail: str = ""
    original_size: int = 0
    resulting_size: int = 0
    relationship_type: str = ""
    target: str = ""


@dataclass(frozen=True)
class SanitizationWarning:
    """Non-fatal warning generated during sanitization."""

    code: str
    path: str
    message: str
    severity: str = "medium"


@dataclass(frozen=True)
class SanitizerPolicy:
    """
    Fine-grained sanitizer policy.

    All flags default to a conservative CDR posture.
    """

    remove_vba: bool = True
    remove_xlm: bool = True
    remove_activex: bool = True
    remove_embedded_objects: bool = True
    remove_embedded_scripts: bool = True
    remove_external_relationships: bool = True
    remove_remote_templates: bool = True
    remove_dde: bool = True
    strip_macro_content_types: bool = True
    strip_active_content_types: bool = True
    sanitize_custom_xml: bool = False
    preserve_images: bool = True
    reject_malformed_xml: bool = False
    reject_unknown_active_content: bool = False

    max_input_bytes: int = MAX_INPUT_BYTES
    max_output_bytes: int = MAX_OUTPUT_BYTES
    max_entries: int = MAX_ZIP_ENTRIES
    max_entry_size: int = MAX_ENTRY_SIZE
    max_total_uncompressed: int = MAX_TOTAL_UNCOMPRESSED

    def __post_init__(self) -> None:
        limits = (
            ("max_input_bytes", self.max_input_bytes, 1, MAX_INPUT_BYTES),
            ("max_output_bytes", self.max_output_bytes, 1, MAX_OUTPUT_BYTES),
            ("max_entries", self.max_entries, 1, MAX_ZIP_ENTRIES),
            ("max_entry_size", self.max_entry_size, 1, MAX_ENTRY_SIZE),
            (
                "max_total_uncompressed",
                self.max_total_uncompressed,
                1,
                MAX_TOTAL_UNCOMPRESSED,
            ),
        )

        for name, value, minimum, maximum in limits:
            if not isinstance(value, int):
                raise SanitizerInputError(
                    f"{name} must be an integer"
                )

            if not minimum <= value <= maximum:
                raise SanitizerInputError(
                    f"{name} must be between {minimum} and {maximum}"
                )


@dataclass(frozen=True)
class SanitizationResult:
    """
    Complete sanitization result.

    ``data`` is the reconstructed sanitized OOXML package.
    """

    data: bytes
    original_sha256: str
    sanitized_sha256: str
    original_size: int
    sanitized_size: int
    format: str
    actions: Tuple[SanitizationActionRecord, ...]
    removed_entries: Tuple[str, ...]
    modified_entries: Tuple[str, ...]
    preserved_entries: Tuple[str, ...]
    warnings: Tuple[SanitizationWarning, ...]
    changed: bool
    active_content_removed: bool
    external_content_removed: bool
    macros_removed: bool
    embedded_objects_removed: bool
    overall_action: SanitizationAction
    metadata: Mapping[str, Any] = field(default_factory=dict)

    @property
    def is_clean(self) -> bool:
        """Return True if no sanitizer changes were required."""
        return not self.changed

    @property
    def action_count(self) -> int:
        """Return number of recorded sanitization actions."""
        return len(self.actions)


@dataclass
class _Entry:
    """Internal in-memory ZIP entry representation."""

    name: str
    data: bytes
    compress_type: int
    compress_level: Optional[int] = None
    date_time: Tuple[int, int, int, int, int, int] = (
        1980,
        1,
        1,
        0,
        0,
        0,
    )
    external_attr: int = 0
    create_system: int = 0


# ---------------------------------------------------------------------------
# Generic helpers
# ---------------------------------------------------------------------------


def _safe_text(value: Any, limit: int = 8_192) -> str:
    if value is None:
        return ""

    if isinstance(value, bytes):
        text = value[:limit].decode("utf-8", errors="replace")
    elif isinstance(value, str):
        text = value[:limit]
    else:
        try:
            text = str(value)[:limit]
        except Exception:
            return ""

    return text.replace("\x00", "")


def _normalize_path(value: Any) -> str:
    """
    Normalize ZIP entry paths without resolving them against the host
    filesystem.
    """
    text = _safe_text(value, MAX_ENTRY_NAME_LENGTH)
    text = text.replace("\\", "/")

    while text.startswith("./"):
        text = text[2:]

    normalized = posixpath.normpath(text)

    if normalized == ".":
        return ""

    return normalized


def _is_unsafe_zip_path(name: str) -> bool:
    """
    Reject path traversal and malformed absolute ZIP names.
    """
    normalized = _normalize_path(name)

    if not normalized:
        return True

    if normalized.startswith("/"):
        return True

    if re.match(r"^[A-Za-z]:", normalized):
        return True

    components = normalized.split("/")

    if any(component == ".." for component in components):
        return True

    if "\x00" in normalized:
        return True

    return False


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _looks_like_zip(data: bytes) -> bool:
    return data.startswith(
        (
            b"PK\x03\x04",
            b"PK\x05\x06",
            b"PK\x07\x08",
        )
    )


def _looks_like_ole(data: bytes) -> bool:
    return data.startswith(bytes.fromhex("D0CF11E0A1B11AE1"))


def _looks_like_pdf(data: bytes) -> bool:
    return data.startswith(b"%PDF-")


def _looks_like_rtf(data: bytes) -> bool:
    return data.startswith(b"{\\rtf")


def _is_ooxml_candidate(entries: Mapping[str, _Entry]) -> bool:
    names = {name.lower() for name in entries}

    return (
        "[content_types].xml" in names
        and (
            "_rels/.rels" in names
            or "word/document.xml" in names
            or "xl/workbook.xml" in names
            or "ppt/presentation.xml" in names
        )
    )


def _detect_format(data: bytes) -> str:
    if _looks_like_zip(data):
        return "zip/ooxml"

    if _looks_like_ole(data):
        return "ole"

    if _looks_like_pdf(data):
        return "pdf"

    if _looks_like_rtf(data):
        return "rtf"

    return "unknown"


# ---------------------------------------------------------------------------
# XML helpers
# ---------------------------------------------------------------------------


def _local_name(tag: str) -> str:
    if not tag:
        return ""

    if "}" in tag:
        return tag.rsplit("}", 1)[-1]

    return tag


def _namespace(tag: str) -> str:
    if tag.startswith("{") and "}" in tag:
        return tag[1:].split("}", 1)[0]

    return ""


def _qname(namespace: str, local: str) -> str:
    if namespace:
        return f"{{{namespace}}}{local}"

    return local


def _parse_xml(
    data: bytes,
    *,
    path: str,
    reject_malformed: bool,
) -> Optional[ET.Element]:
    if len(data) > MAX_XML_BYTES:
        raise SanitizerArchiveError(
            f"XML entry exceeds maximum size: {path}"
        )

    try:
        root = ET.fromstring(data)
    except ET.ParseError as exc:
        if reject_malformed:
            raise SanitizerArchiveError(
                f"Malformed XML entry: {path}"
            ) from exc
        return None

    # Defensive post-parse structural limits.
    count = 0
    max_depth = 0

    stack: List[Tuple[ET.Element, int]] = [(root, 1)]

    while stack:
        element, depth = stack.pop()

        count += 1
        max_depth = max(max_depth, depth)

        if count > MAX_XML_ELEMENTS:
            raise SanitizerArchiveError(
                f"XML entry contains too many elements: {path}"
            )

        if depth > MAX_XML_DEPTH:
            raise SanitizerArchiveError(
                f"XML entry exceeds maximum nesting depth: {path}"
            )

        if len(element.attrib) > MAX_XML_ATTRIBUTES:
            raise SanitizerArchiveError(
                f"XML entry contains too many attributes: {path}"
            )

        for child in list(element):
            stack.append((child, depth + 1))

    return root


def _serialize_xml(root: ET.Element) -> bytes:
    """
    Serialize XML deterministically enough for CDR output.

    ElementTree may normalize namespace prefixes, which is acceptable for
    OOXML as namespace URIs remain authoritative.
    """
    return ET.tostring(
        root,
        encoding="utf-8",
        xml_declaration=True,
    )


def _remove_elements_by_local_name(
    root: ET.Element,
    names: Set[str],
) -> int:
    """
    Remove child elements matching local names.

    Returns number removed.
    """
    removed = 0

    stack = [root]

    while stack:
        parent = stack.pop()

        for child in list(parent):
            if _local_name(child.tag).lower() in names:
                parent.remove(child)
                removed += 1
                continue

            stack.append(child)

    return removed


def _remove_dde_nodes(
    root: ET.Element,
) -> int:
    """
    Remove common DDE-related XML nodes and attributes.

    This is deliberately conservative and only targets explicit DDE
    indicators. It does not interpret field codes.
    """
    removed = 0

    stack: List[ET.Element] = [root]

    while stack:
        parent = stack.pop()

        for child in list(parent):
            local = _local_name(child.tag).lower()

            if local in {
                "dde",
                "ddeitem",
                "ddeitems",
                "ddefield",
                "ddeauto",
            }:
                parent.remove(child)
                removed += 1
                continue

            serialized = ET.tostring(
                child,
                encoding="unicode",
            )

            if any(pattern.search(serialized) for pattern in DDE_PATTERNS):
                parent.remove(child)
                removed += 1
                continue

            stack.append(child)

    # Remove explicit DDE attributes.
    for element in root.iter():
        for attribute in list(element.attrib):
            local = _local_name(attribute).lower()

            if local in {
                "dde",
                "ddeauto",
            }:
                del element.attrib[attribute]
                removed += 1

    return removed


def _remove_external_targets_from_generic_xml(
    root: ET.Element,
) -> int:
    """
    Remove explicit external relationship-like attributes from generic XML.

    Relationship parts receive more precise processing elsewhere.
    """
    removed = 0

    for element in root.iter():
        for attribute, value in list(element.attrib.items()):
            local = _local_name(attribute).lower()
            text = _safe_text(value, MAX_VALUE_LENGTH if "MAX_VALUE_LENGTH" in globals() else 8192).strip()

            if local in {
                "target",
                "href",
                "url",
                "uri",
            }:
                lowered = text.lower()

                if lowered.startswith(URL_SCHEMES):
                    del element.attrib[attribute]
                    removed += 1

    return removed


# ---------------------------------------------------------------------------
# ZIP loading
# ---------------------------------------------------------------------------


def _read_archive(
    data: bytes,
    policy: SanitizerPolicy,
) -> Dict[str, _Entry]:
    """
    Read a ZIP archive into bounded memory.
    """
    if not _looks_like_zip(data):
        raise SanitizerArchiveError(
            "Input is not a ZIP/OOXML container"
        )

    entries: Dict[str, _Entry] = {}

    total_uncompressed = 0
    total_compressed = 0

    try:
        with zipfile.ZipFile(io.BytesIO(data), "r") as archive:
            infos = archive.infolist()

            if len(infos) > policy.max_entries:
                raise SanitizerArchiveError(
                    f"Archive contains too many entries: {len(infos)}"
                )

            for info in infos:
                name = _normalize_path(info.filename)

                if not name:
                    raise SanitizerArchiveError(
                        "Archive contains an empty entry name"
                    )

                if len(name) > MAX_ENTRY_NAME_LENGTH:
                    raise SanitizerArchiveError(
                        f"Archive entry name is too long: {name[:128]!r}"
                    )

                if _is_unsafe_zip_path(name):
                    raise SanitizerArchiveError(
                        f"Unsafe archive entry path: {info.filename!r}"
                    )

                if info.is_dir():
                    # Directory entries are not required by OOXML and are
                    # omitted from reconstructed output.
                    continue

                declared_size = int(info.file_size)
                compressed_size = int(info.compress_size)

                if declared_size < 0 or compressed_size < 0:
                    raise SanitizerArchiveError(
                        f"Invalid ZIP size metadata: {name}"
                    )

                if declared_size > policy.max_entry_size:
                    raise SanitizerArchiveError(
                        f"Archive entry exceeds size limit: {name}"
                    )

                total_uncompressed += declared_size
                total_compressed += compressed_size

                if total_uncompressed > policy.max_total_uncompressed:
                    raise SanitizerArchiveError(
                        "Archive exceeds total uncompressed-size limit"
                    )

                if total_compressed > MAX_TOTAL_COMPRESSED:
                    raise SanitizerArchiveError(
                        "Archive exceeds total compressed-size limit"
                    )

                try:
                    content = archive.read(info)
                except (
                    OSError,
                    RuntimeError,
                    ValueError,
                    zipfile.BadZipFile,
                    zipfile.LargeZipFile,
                ) as exc:
                    raise SanitizerArchiveError(
                        f"Unable to safely read archive entry: {name}"
                    ) from exc

                if len(content) != declared_size:
                    raise SanitizerArchiveError(
                        f"Archive entry size mismatch: {name}"
                    )

                entries[name] = _Entry(
                    name=name,
                    data=content,
                    compress_type=info.compress_type,
                    date_time=info.date_time,
                    external_attr=info.external_attr,
                    create_system=info.create_system,
                )

    except zipfile.BadZipFile as exc:
        raise SanitizerArchiveError(
            "Malformed ZIP archive"
        ) from exc

    return entries


# ---------------------------------------------------------------------------
# Entry classification
# ---------------------------------------------------------------------------


def _is_vba_entry(name: str) -> bool:
    lowered = name.lower()

    if lowered in {
        item.lower()
        for item in VBA_ENTRY_NAMES
    }:
        return True

    return (
        lowered.endswith("/vbaproject.bin")
        or lowered.endswith("/vbaprojectsignature.bin")
    )


def _is_xlm_entry(name: str) -> bool:
    lowered = name.lower()

    return any(
        marker.lower() in lowered
        for marker in XLM_DIRECTORY_MARKERS
    )


def _is_activex_entry(name: str) -> bool:
    lowered = name.lower()

    return any(
        marker.lower() in lowered
        for marker in ACTIVE_DIRECTORY_MARKERS
        if "activex" in marker.lower()
    ) or "/control" in lowered and lowered.endswith(".xml")


def _is_embedded_object_entry(name: str) -> bool:
    lowered = name.lower()

    return (
        any(
            marker.lower() in lowered
            for marker in ACTIVE_DIRECTORY_MARKERS
            if "embedding" in marker.lower()
        )
        or lowered.endswith(".bin")
        and (
            "/embeddings/" in lowered
            or lowered.startswith("embeddings/")
        )
    )


def _is_external_link_entry(name: str) -> bool:
    lowered = name.lower()

    return any(
        marker.lower() in lowered
        for marker in EXTERNAL_LINK_DIRECTORY_MARKERS
    )


def _is_script_like_entry(name: str, data: bytes) -> bool:
    lowered = name.lower()

    script_extensions = (
        ".js",
        ".jse",
        ".vbs",
        ".vbe",
        ".ps1",
        ".psm1",
        ".bat",
        ".cmd",
        ".hta",
        ".wsf",
        ".wsc",
        ".sh",
    )

    if lowered.endswith(script_extensions):
        return True

    if len(data) > MAX_XML_BYTES:
        return False

    sample = data[:65_536].lower()

    return (
        b"powershell" in sample
        or b"wscript.shell" in sample
        or b"createobject(" in sample
        or b"frombase64string" in sample
    )


def _is_content_types_entry(name: str) -> bool:
    return name.lower() == "[content_types].xml"


def _is_relationship_entry(name: str) -> bool:
    lowered = name.lower()

    return (
        lowered == "_rels/.rels"
        or lowered.endswith(".rels")
        or "/_rels/" in lowered
    )


# ---------------------------------------------------------------------------
# Content Types sanitization
# ---------------------------------------------------------------------------


def _content_type_is_active(
    content_type: str,
) -> bool:
    lowered = content_type.lower()

    if lowered in {
        item.lower()
        for item in VBA_CONTENT_TYPES
    }:
        return True

    if any(
        marker.lower() in lowered
        for marker in ACTIVEX_CONTENT_TYPE_MARKERS
    ):
        return True

    if any(
        marker.lower() in lowered
        for marker in EMBEDDED_CONTENT_TYPE_MARKERS
    ):
        return True

    return False


def _sanitize_content_types(
    entry: _Entry,
    *,
    policy: SanitizerPolicy,
) -> Tuple[_Entry, Optional[SanitizationActionRecord], List[str]]:
    """
    Remove active-content Default/Override declarations from
    [Content_Types].xml.
    """
    warnings: List[str] = []

    root = _parse_xml(
        entry.data,
        path=entry.name,
        reject_malformed=policy.reject_malformed_xml,
    )

    if root is None:
        return entry, None, warnings

    modified = False
    removed_count = 0

    for child in list(root):
        local = _local_name(child.tag).lower()

        if local not in {"default", "override"}:
            continue

        content_type = _safe_text(
            child.attrib.get("ContentType", ""),
            4_096,
        )

        part_name = _normalize_path(
            child.attrib.get("PartName", ""),
        )

        should_remove = False
        reason = SanitizationReason.ACTIVE_CONTENT_TYPE

        if policy.strip_macro_content_types:
            if (
                content_type.lower()
                in {
                    item.lower()
                    for item in VBA_CONTENT_TYPES
                }
                or content_type.lower()
                in {
                    item.lower()
                    for item in MACRO_CONTENT_TYPES
                }
            ):
                should_remove = True
                reason = SanitizationReason.MACRO_CONTENT_TYPE

        if policy.strip_active_content_types and _content_type_is_active(
            content_type
        ):
            should_remove = True
            reason = SanitizationReason.ACTIVE_CONTENT_TYPE

        if part_name:
            part_lower = part_name.lower()

            if policy.remove_vba and (
                "vbaproject.bin" in part_lower
                or "vbaprojectsignature.bin" in part_lower
            ):
                should_remove = True
                reason = SanitizationReason.VBA

            if policy.remove_activex and "activex" in part_lower:
                should_remove = True
                reason = SanitizationReason.ACTIVEX

            if policy.remove_embedded_objects and (
                "/embeddings/" in part_lower
            ):
                should_remove = True
                reason = SanitizationReason.EMBEDDED_OBJECT

        if should_remove:
            root.remove(child)
            modified = True
            removed_count += 1

    if not modified:
        return entry, None, warnings

    result = _Entry(
        name=entry.name,
        data=_serialize_xml(root),
        compress_type=entry.compress_type,
        compress_level=entry.compress_level,
        date_time=entry.date_time,
        external_attr=entry.external_attr,
        create_system=entry.create_system,
    )

    action = SanitizationActionRecord(
        action=SanitizationAction.REWRITE,
        reason=SanitizationReason.ACTIVE_CONTENT_TYPE,
        path=entry.name,
        detail=f"Removed {removed_count} active content type declaration(s).",
        original_size=len(entry.data),
        resulting_size=len(result.data),
    )

    return result, action, warnings


# ---------------------------------------------------------------------------
# Relationship sanitization
# ---------------------------------------------------------------------------


def _relationship_target_is_external(
    relationship: ET.Element,
) -> bool:
    target_mode = _safe_text(
        relationship.attrib.get("TargetMode", ""),
        128,
    ).lower()

    if target_mode == "external":
        return True

    target = _safe_text(
        relationship.attrib.get("Target", ""),
        MAX_VALUE_LENGTH if "MAX_VALUE_LENGTH" in globals() else 8192,
    ).strip().lower()

    if target.startswith(URL_SCHEMES):
        return True

    return False


def _relationship_should_remove(
    relationship: ET.Element,
    *,
    policy: SanitizerPolicy,
) -> Tuple[bool, SanitizationReason]:
    rel_type = _safe_text(
        relationship.attrib.get("Type", ""),
        2_048,
    )

    rel_type_lower = rel_type.lower()

    if policy.remove_vba:
        if rel_type in RELATIONSHIP_VBA:
            return True, SanitizationReason.VBA

        if "vbaproject" in rel_type_lower:
            return True, SanitizationReason.VBA

    if policy.remove_embedded_objects:
        if rel_type in RELATIONSHIP_OLE_OBJECT:
            return True, SanitizationReason.EMBEDDED_OBJECT

        if rel_type in RELATIONSHIP_PACKAGE:
            return True, SanitizationReason.EMBEDDED_OBJECT

        if "oleobject" in rel_type_lower:
            return True, SanitizationReason.EMBEDDED_OBJECT

    if policy.remove_activex:
        if rel_type in RELATIONSHIP_CONTROL:
            return True, SanitizationReason.ACTIVEX

        if "control" in rel_type_lower:
            return True, SanitizationReason.ACTIVEX

    if policy.remove_remote_templates:
        if rel_type in RELATIONSHIP_ATTACHED_TEMPLATE:
            return True, SanitizationReason.REMOTE_TEMPLATE

        if "attachedtemplate" in rel_type_lower:
            return True, SanitizationReason.REMOTE_TEMPLATE

    if policy.remove_external_relationships:
        if rel_type in EXTERNAL_RELATIONSHIP_TYPES:
            return True, SanitizationReason.EXTERNAL_RELATIONSHIP

        if _relationship_target_is_external(relationship):
            return True, SanitizationReason.EXTERNAL_RELATIONSHIP

    return False, SanitizationReason.POLICY


def _sanitize_relationships(
    entry: _Entry,
    *,
    policy: SanitizerPolicy,
) -> Tuple[_Entry, List[SanitizationActionRecord], List[str]]:
    root = _parse_xml(
        entry.data,
        path=entry.name,
        reject_malformed=policy.reject_malformed_xml,
    )

    if root is None:
        return entry, [], []

    modified = False
    actions: List[SanitizationActionRecord] = []

    for child in list(root):
        if _local_name(child.tag).lower() != "relationship":
            continue

        remove, reason = _relationship_should_remove(
            child,
            policy=policy,
        )

        if not remove:
            continue

        rel_id = _safe_text(
            child.attrib.get("Id", ""),
            256,
        )

        rel_type = _safe_text(
            child.attrib.get("Type", ""),
            2_048,
        )

        target = _safe_text(
            child.attrib.get("Target", ""),
            4_096,
        )

        root.remove(child)
        modified = True

        actions.append(
            SanitizationActionRecord(
                action=SanitizationAction.REMOVE,
                reason=reason,
                path=entry.name,
                detail=f"Removed relationship {rel_id or '<unnamed>'}.",
                original_size=len(entry.data),
                resulting_size=0,
                relationship_type=rel_type,
                target=target,
            )
        )

    if not modified:
        return entry, actions, []

    result = _Entry(
        name=entry.name,
        data=_serialize_xml(root),
        compress_type=entry.compress_type,
        compress_level=entry.compress_level,
        date_time=entry.date_time,
        external_attr=entry.external_attr,
        create_system=entry.create_system,
    )

    updated_actions: List[SanitizationActionRecord] = []

    for action in actions:
        updated_actions.append(
            SanitizationActionRecord(
                action=action.action,
                reason=action.reason,
                path=action.path,
                detail=action.detail,
                original_size=action.original_size,
                resulting_size=len(result.data),
                relationship_type=action.relationship_type,
                target=action.target,
            )
        )

    return result, updated_actions, []


# ---------------------------------------------------------------------------
# Generic XML sanitization
# ---------------------------------------------------------------------------


def _sanitize_generic_xml(
    entry: _Entry,
    *,
    policy: SanitizerPolicy,
) -> Tuple[_Entry, Optional[SanitizationActionRecord], List[str]]:
    """
    Sanitize XML fields which contain direct DDE or external URL indicators.

    Relationship parts are handled separately because they require semantic
    relationship processing.
    """
    if _is_relationship_entry(entry.name):
        return entry, None, []

    root = _parse_xml(
        entry.data,
        path=entry.name,
        reject_malformed=policy.reject_malformed_xml,
    )

    if root is None:
        return entry, None, []

    removed = 0

    if policy.remove_dde:
        removed += _remove_dde_nodes(root)

    # Do not aggressively strip arbitrary URLs from all OOXML XML. URLs can
    # legitimately represent hyperlinks. External relationships are removed
    # through .rels processing. Only direct DDE-like constructs are handled
    # here.

    if removed == 0:
        return entry, None, []

    result = _Entry(
        name=entry.name,
        data=_serialize_xml(root),
        compress_type=entry.compress_type,
        compress_level=entry.compress_level,
        date_time=entry.date_time,
        external_attr=entry.external_attr,
        create_system=entry.create_system,
    )

    action = SanitizationActionRecord(
        action=SanitizationAction.REWRITE,
        reason=SanitizationReason.DDE,
        path=entry.name,
        detail=f"Removed {removed} DDE-related XML node/attribute(s).",
        original_size=len(entry.data),
        resulting_size=len(result.data),
    )

    return result, action, []


# ---------------------------------------------------------------------------
# Word-specific sanitization
# ---------------------------------------------------------------------------


def _sanitize_word_document_xml(
    entry: _Entry,
    *,
    policy: SanitizerPolicy,
) -> Tuple[_Entry, List[SanitizationActionRecord]]:
    """
    Remove Word-specific active fields that are directly identifiable.

    The implementation intentionally avoids trying to interpret arbitrary
    field codes.
    """
    if not entry.name.lower().startswith("word/"):
        return entry, []

    root = _parse_xml(
        entry.data,
        path=entry.name,
        reject_malformed=policy.reject_malformed_xml,
    )

    if root is None:
        return entry, []

    modified = False
    removed = 0

    if policy.remove_dde:
        # Explicit fldSimple/instrText fields containing DDE.
        for element in list(root.iter()):
            local = _local_name(element.tag).lower()

            if local not in {
                "fldsimple",
                "instrtext",
                "fldchar",
            }:
                continue

            serialized = ET.tostring(
                element,
                encoding="unicode",
            )

            if any(
                pattern.search(serialized)
                for pattern in DDE_PATTERNS
            ):
                parent = _find_parent(root, element)

                if parent is not None:
                    parent.remove(element)
                    modified = True
                    removed += 1

    if not modified:
        return entry, []

    result = _Entry(
        name=entry.name,
        data=_serialize_xml(root),
        compress_type=entry.compress_type,
        compress_level=entry.compress_level,
        date_time=entry.date_time,
        external_attr=entry.external_attr,
        create_system=entry.create_system,
    )

    action = SanitizationActionRecord(
        action=SanitizationAction.REWRITE,
        reason=SanitizationReason.DDE,
        path=entry.name,
        detail=f"Removed {removed} Word DDE-related field element(s).",
        original_size=len(entry.data),
        resulting_size=len(result.data),
    )

    return result, [action]


def _find_parent(
    root: ET.Element,
    target: ET.Element,
) -> Optional[ET.Element]:
    for parent in root.iter():
        for child in list(parent):
            if child is target:
                return parent

    return None


# ---------------------------------------------------------------------------
# Entry removal policy
# ---------------------------------------------------------------------------


def _entry_removal_reason(
    name: str,
    data: bytes,
    *,
    policy: SanitizerPolicy,
) -> Optional[SanitizationReason]:
    """
    Determine whether an archive entry should be completely removed.
    """
    if policy.remove_vba and _is_vba_entry(name):
        return SanitizationReason.VBA

    if policy.remove_xlm and _is_xlm_entry(name):
        return SanitizationReason.XLM

    if policy.remove_activex and _is_activex_entry(name):
        return SanitizationReason.ACTIVEX

    if policy.remove_embedded_objects and _is_embedded_object_entry(name):
        return SanitizationReason.EMBEDDED_OBJECT

    if policy.remove_embedded_scripts and _is_script_like_entry(name, data):
        # Do not remove arbitrary OOXML XML simply because it contains a
        # script-looking string. Only known script-like entry extensions or
        # obvious payload files reach here.
        lowered = name.lower()

        if lowered.endswith(
            (
                ".js",
                ".jse",
                ".vbs",
                ".vbe",
                ".ps1",
                ".psm1",
                ".bat",
                ".cmd",
                ".hta",
                ".wsf",
                ".wsc",
                ".sh",
            )
        ):
            return SanitizationReason.EMBEDDED_SCRIPT

    if policy.remove_external_relationships and _is_external_link_entry(name):
        return SanitizationReason.EXTERNAL_RELATIONSHIP

    return None


# ---------------------------------------------------------------------------
# Package relationship cleanup
# ---------------------------------------------------------------------------


def _existing_entry_targets(
    entries: Mapping[str, _Entry],
) -> Set[str]:
    return {
        _normalize_path(name).lower()
        for name in entries
    }


def _relationship_source_directory(
    relationship_path: str,
) -> str:
    """
    Convert ``word/_rels/document.xml.rels`` to ``word``.
    """
    normalized = _normalize_path(relationship_path)

    marker = "/_rels/"

    if marker in normalized:
        return normalized.split(marker, 1)[0]

    if normalized.startswith("_rels/"):
        return ""

    return posixpath.dirname(normalized)


def _resolve_relationship_target(
    relationship_path: str,
    target: str,
) -> Optional[str]:
    """
    Resolve a package-local relationship target without touching the host
    filesystem.
    """
    target = _safe_text(target, MAX_ENTRY_NAME_LENGTH).replace("\\", "/")

    if not target:
        return None

    lowered = target.lower()

    if lowered.startswith(URL_SCHEMES):
        return None

    if target.startswith("/"):
        return _normalize_path(target.lstrip("/"))

    source_dir = _relationship_source_directory(
        relationship_path
    )

    return _normalize_path(
        posixpath.join(source_dir, target)
    )


def _remove_orphan_relationships(
    entries: MutableMapping[str, _Entry],
    *,
    policy: SanitizerPolicy,
) -> List[SanitizationActionRecord]:
    """
    Remove relationships whose local target no longer exists.

    This prevents dangling references after active parts have been removed.
    """
    actions: List[SanitizationActionRecord] = []

    existing = _existing_entry_targets(entries)

    for name in list(entries):
        if not _is_relationship_entry(name):
            continue

        entry = entries[name]

        root = _parse_xml(
            entry.data,
            path=name,
            reject_malformed=policy.reject_malformed_xml,
        )

        if root is None:
            continue

        modified = False

        for relationship in list(root):
            if _local_name(relationship.tag).lower() != "relationship":
                continue

            if _relationship_target_is_external(relationship):
                continue

            target = _safe_text(
                relationship.attrib.get("Target", ""),
                MAX_ENTRY_NAME_LENGTH,
            )

            resolved = _resolve_relationship_target(
                name,
                target,
            )

            if resolved is None:
                continue

            if resolved.lower() in existing:
                continue

            rel_type = _safe_text(
                relationship.attrib.get("Type", ""),
                2_048,
            )

            rel_id = _safe_text(
                relationship.attrib.get("Id", ""),
                256,
            )

            root.remove(relationship)
            modified = True

            actions.append(
                SanitizationActionRecord(
                    action=SanitizationAction.REMOVE,
                    reason=SanitizationReason.INVALID_REFERENCE,
                    path=name,
                    detail=(
                        f"Removed dangling relationship "
                        f"{rel_id or '<unnamed>'}."
                    ),
                    original_size=len(entry.data),
                    resulting_size=0,
                    relationship_type=rel_type,
                    target=target,
                )
            )

        if modified:
            rewritten = _Entry(
                name=entry.name,
                data=_serialize_xml(root),
                compress_type=entry.compress_type,
                compress_level=entry.compress_level,
                date_time=entry.date_time,
                external_attr=entry.external_attr,
                create_system=entry.create_system,
            )

            entries[name] = rewritten

            for index, action in enumerate(actions):
                if action.path == name and action.resulting_size == 0:
                    actions[index] = SanitizationActionRecord(
                        action=action.action,
                        reason=action.reason,
                        path=action.path,
                        detail=action.detail,
                        original_size=action.original_size,
                        resulting_size=len(rewritten.data),
                        relationship_type=action.relationship_type,
                        target=action.target,
                    )

    return actions


# ---------------------------------------------------------------------------
# Main package sanitization
# ---------------------------------------------------------------------------


def sanitize(
    value: bytes | bytearray | os.PathLike[str] | str,
    *,
    policy: Optional[SanitizerPolicy] = None,
) -> SanitizationResult:
    """
    Sanitize an Office document or supported document container.

    For OOXML/ZIP input, a new in-memory archive is reconstructed.
    Unsupported binary formats are rejected rather than partially modified.
    """
    return sanitize_document(value, policy=policy)


def sanitize_document(
    value: bytes | bytearray | os.PathLike[str] | str,
    *,
    policy: Optional[SanitizerPolicy] = None,
) -> SanitizationResult:
    """
    Primary sanitizer API.
    """
    if policy is None:
        policy = SanitizerPolicy()

    original = _read_input(value, policy)

    if len(original) > policy.max_input_bytes:
        raise SanitizerInputError(
            f"Input exceeds maximum size of {policy.max_input_bytes} bytes"
        )

    original_sha256 = _sha256(original)
    detected_format = _detect_format(original)

    if detected_format != "zip/ooxml":
        if _looks_like_ole(original):
            raise SanitizerInputError(
                "Legacy OLE/CFB documents require an OLE-aware reconstruction "
                "stage; sanitizer.py does not rewrite OLE containers."
            )

        raise SanitizerInputError(
            f"Unsupported sanitizer input format: {detected_format}"
        )

    entries = _read_archive(
        original,
        policy,
    )

    if not _is_ooxml_candidate(entries):
        raise SanitizerArchiveError(
            "ZIP container does not appear to be an OOXML package"
        )

    original_names = tuple(sorted(entries.keys()))

    actions: List[SanitizationActionRecord] = []
    warnings: List[SanitizationWarning] = []

    removed_entries: List[str] = []
    modified_entries: Set[str] = set()

    # ------------------------------------------------------------------
    # Phase 1: remove clearly unsafe package members.
    # ------------------------------------------------------------------

    for name in list(entries.keys()):
        if len(actions) >= MAX_ACTIONS:
            raise SanitizerOutputError(
                "Sanitization action limit exceeded"
            )

        reason = _entry_removal_reason(
            name,
            entries[name].data,
            policy=policy,
        )

        if reason is None:
            continue

        if name in {
            "[Content_Types].xml",
            "_rels/.rels",
        }:
            continue

        entry = entries.pop(name)

        action = SanitizationActionRecord(
            action=SanitizationAction.REMOVE,
            reason=reason,
            path=name,
            detail=f"Removed unsafe package member: {name}.",
            original_size=len(entry.data),
            resulting_size=0,
        )

        actions.append(action)
        removed_entries.append(name)

    # ------------------------------------------------------------------
    # Phase 2: rewrite relationships.
    # ------------------------------------------------------------------

    for name in list(entries.keys()):
        if len(actions) >= MAX_ACTIONS:
            raise SanitizerOutputError(
                "Sanitization action limit exceeded"
            )

        if not _is_relationship_entry(name):
            continue

        entry = entries[name]

        rewritten, rel_actions, rel_warnings = _sanitize_relationships(
            entry,
            policy=policy,
        )

        if rewritten.data != entry.data:
            entries[name] = rewritten
            modified_entries.add(name)

        actions.extend(rel_actions)

        for warning in rel_warnings:
            warnings.append(
                SanitizationWarning(
                    code="relationship_warning",
                    path=name,
                    message=warning,
                )
            )

    # ------------------------------------------------------------------
    # Phase 3: rewrite content types.
    # ------------------------------------------------------------------

    content_types_name = next(
        (
            name
            for name in entries
            if _is_content_types_entry(name)
        ),
        None,
    )

    if content_types_name is not None:
        entry = entries[content_types_name]

        rewritten, action, type_warnings = _sanitize_content_types(
            entry,
            policy=policy,
        )

        if action is not None and rewritten.data != entry.data:
            entries[content_types_name] = rewritten
            modified_entries.add(content_types_name)
            actions.append(action)

        for warning in type_warnings:
            warnings.append(
                SanitizationWarning(
                    code="content_type_warning",
                    path=content_types_name,
                    message=warning,
                )
            )

    # ------------------------------------------------------------------
    # Phase 4: generic XML/DDE cleanup.
    # ------------------------------------------------------------------

    for name in list(entries.keys()):
        if len(actions) >= MAX_ACTIONS:
            raise SanitizerOutputError(
                "Sanitization action limit exceeded"
            )

        if not name.lower().endswith(".xml"):
            continue

        entry = entries[name]

        rewritten, action, xml_warnings = _sanitize_generic_xml(
            entry,
            policy=policy,
        )

        if action is not None and rewritten.data != entry.data:
            entries[name] = rewritten
            modified_entries.add(name)
            actions.append(action)

        for warning in xml_warnings:
            warnings.append(
                SanitizationWarning(
                    code="xml_warning",
                    path=name,
                    message=warning,
                )
            )

    # ------------------------------------------------------------------
    # Phase 5: Word-specific DDE cleanup.
    # ------------------------------------------------------------------

    for name in list(entries.keys()):
        if len(actions) >= MAX_ACTIONS:
            raise SanitizerOutputError(
                "Sanitization action limit exceeded"
            )

        if not name.lower().endswith(".xml"):
            continue

        entry = entries[name]

        rewritten, word_actions = _sanitize_word_document_xml(
            entry,
            policy=policy,
        )

        if rewritten.data != entry.data:
            entries[name] = rewritten
            modified_entries.add(name)

        actions.extend(word_actions)

    # ------------------------------------------------------------------
    # Phase 6: remove relationships orphaned by earlier deletion.
    # ------------------------------------------------------------------

    orphan_actions = _remove_orphan_relationships(
        entries,
        policy=policy,
    )

    actions.extend(orphan_actions)

    for action in orphan_actions:
        modified_entries.add(action.path)

    # ------------------------------------------------------------------
    # Phase 7: final archive integrity checks.
    # ------------------------------------------------------------------

    if len(entries) > policy.max_entries:
        raise SanitizerOutputError(
            "Sanitized package exceeds entry-count limit"
        )

    if len(actions) > MAX_ACTIONS:
        raise SanitizerOutputError(
            "Sanitization action limit exceeded"
        )

    output = _write_archive(
        entries,
        max_output_bytes=policy.max_output_bytes,
    )

    if len(output) > policy.max_output_bytes:
        raise SanitizerOutputError(
            "Sanitized output exceeds maximum output size"
        )

    sanitized_sha256 = _sha256(output)

    final_names = tuple(sorted(entries.keys()))

    preserved_entries = tuple(
        sorted(
            set(final_names)
            - set(removed_entries)
            - set(modified_entries)
        )
    )

    active_content_removed = any(
        action.reason
        in {
            SanitizationReason.VBA,
            SanitizationReason.XLM,
            SanitizationReason.ACTIVEX,
            SanitizationReason.EMBEDDED_OBJECT,
            SanitizationReason.EMBEDDED_SCRIPT,
            SanitizationReason.MACRO_CONTENT_TYPE,
            SanitizationReason.ACTIVE_CONTENT_TYPE,
        }
        for action in actions
    )

    external_content_removed = any(
        action.reason
        in {
            SanitizationReason.EXTERNAL_RELATIONSHIP,
            SanitizationReason.REMOTE_TEMPLATE,
        }
        for action in actions
    )

    macros_removed = any(
        action.reason
        in {
            SanitizationReason.VBA,
            SanitizationReason.XLM,
            SanitizationReason.MACRO_CONTENT_TYPE,
        }
        for action in actions
    )

    embedded_objects_removed = any(
        action.reason
        in {
            SanitizationReason.EMBEDDED_OBJECT,
            SanitizationReason.EMBEDDED_SCRIPT,
        }
        for action in actions
    )

    changed = output != original

    overall_action = _overall_action(
        actions=actions,
        changed=changed,
    )

    # Final warning for packages that originally looked macro-enabled but
    # still contain suspicious macro markers after sanitization.
    remaining_active_markers = _remaining_active_markers(entries)

    if remaining_active_markers:
        warnings.append(
            SanitizationWarning(
                code="active_content_remaining",
                path="<package>",
                message=(
                    "Potential active-content markers remain after "
                    "sanitization: "
                    + ", ".join(sorted(remaining_active_markers)[:32])
                ),
                severity="high",
            )
        )

    warnings = warnings[:MAX_WARNINGS]

    return SanitizationResult(
        data=output,
        original_sha256=original_sha256,
        sanitized_sha256=sanitized_sha256,
        original_size=len(original),
        sanitized_size=len(output),
        format="ooxml",
        actions=tuple(actions[:MAX_ACTIONS]),
        removed_entries=tuple(sorted(set(removed_entries))),
        modified_entries=tuple(sorted(modified_entries)),
        preserved_entries=preserved_entries,
        warnings=tuple(warnings),
        changed=changed,
        active_content_removed=active_content_removed,
        external_content_removed=external_content_removed,
        macros_removed=macros_removed,
        embedded_objects_removed=embedded_objects_removed,
        overall_action=overall_action,
        metadata={
            "module": MODULE_NAME,
            "version": SANITIZER_VERSION,
            "static_only": True,
            "entry_count_before": len(original_names),
            "entry_count_after": len(final_names),
            "compression": "deflate",
            "deterministic_output": True,
        },
    )


def sanitize_content(
    content: bytes | bytearray,
    *,
    policy: Optional[SanitizerPolicy] = None,
) -> SanitizationResult:
    """
    Sanitize raw in-memory OOXML content.
    """
    return sanitize_document(content, policy=policy)


def sanitize_file(
    path: os.PathLike[str] | str,
    *,
    policy: Optional[SanitizerPolicy] = None,
) -> SanitizationResult:
    """
    Read and sanitize a document path.

    The source document is only read; it is never modified.
    """
    return sanitize_document(path, policy=policy)


# ---------------------------------------------------------------------------
# Input reading
# ---------------------------------------------------------------------------


def _read_input(
    value: bytes | bytearray | os.PathLike[str] | str,
    policy: SanitizerPolicy,
) -> bytes:
    if isinstance(value, bytes):
        return value

    if isinstance(value, bytearray):
        return bytes(value)

    if isinstance(value, os.PathLike):
        path = Path(value)

        try:
            stat = path.stat()
        except OSError as exc:
            raise SanitizerInputError(
                f"Unable to inspect input path: {path}"
            ) from exc

        if not path.is_file():
            raise SanitizerInputError(
                f"Input is not a regular file: {path}"
            )

        if stat.st_size > policy.max_input_bytes:
            raise SanitizerInputError(
                f"Input exceeds maximum size of {policy.max_input_bytes} bytes"
            )

        try:
            data = path.read_bytes()
        except OSError as exc:
            raise SanitizerInputError(
                f"Unable to read input path: {path}"
            ) from exc

        return data

    if isinstance(value, str):
        # Strings are interpreted as paths only when an existing regular file
        # exists. This avoids silently treating large document text as a path.
        path = Path(value)

        try:
            if path.exists():
                if not path.is_file():
                    raise SanitizerInputError(
                        f"Input is not a regular file: {path}"
                    )

                stat = path.stat()

                if stat.st_size > policy.max_input_bytes:
                    raise SanitizerInputError(
                        f"Input exceeds maximum size of "
                        f"{policy.max_input_bytes} bytes"
                    )

                return path.read_bytes()
        except OSError:
            pass

        raise SanitizerInputError(
            "String sanitizer input must reference an existing file"
        )

    raise SanitizerInputError(
        "Sanitizer input must be bytes, bytearray, or a filesystem path"
    )


# ---------------------------------------------------------------------------
# Archive reconstruction
# ---------------------------------------------------------------------------


def _write_archive(
    entries: Mapping[str, _Entry],
    *,
    max_output_bytes: int,
) -> bytes:
    """
    Reconstruct a ZIP archive deterministically in memory.
    """
    buffer = io.BytesIO()

    try:
        with zipfile.ZipFile(
            buffer,
            mode="w",
            compression=DEFAULT_COMPRESSION,
            compresslevel=DEFAULT_COMPRESSLEVEL,
            strict_timestamps=True,
        ) as archive:
            for name in sorted(entries):
                entry = entries[name]

                if _is_unsafe_zip_path(name):
                    raise SanitizerOutputError(
                        f"Unsafe output entry name: {name}"
                    )

                if len(entry.data) > MAX_ENTRY_SIZE:
                    raise SanitizerOutputError(
                        f"Output entry exceeds size limit: {name}"
                    )

                info = zipfile.ZipInfo(
                    filename=name,
                    date_time=(
                        1980,
                        1,
                        1,
                        0,
                        0,
                        0,
                    ),
                )

                # Preserve directory-like Unix mode only when harmless.
                info.external_attr = (
                    entry.external_attr
                    & 0xFFFFFFFF
                )

                info.create_system = 0

                # Reconstructed archives always use deflate for deterministic
                # and broadly compatible output.
                info.compress_type = DEFAULT_COMPRESSION

                archive.writestr(
                    info,
                    entry.data,
                )

                if buffer.tell() > max_output_bytes:
                    raise SanitizerOutputError(
                        "Sanitized archive exceeds output size limit"
                    )

    except zipfile.LargeZipFile as exc:
        raise SanitizerOutputError(
            "Sanitized archive exceeds ZIP limits"
        ) from exc

    return buffer.getvalue()


# ---------------------------------------------------------------------------
# Post-sanitization checks
# ---------------------------------------------------------------------------


def _remaining_active_markers(
    entries: Mapping[str, _Entry],
) -> Set[str]:
    markers: Set[str] = set()

    for name, entry in entries.items():
        lowered = name.lower()

        if _is_vba_entry(name):
            markers.add("vba_project")

        if _is_xlm_entry(name):
            markers.add("xlm_macro_sheet")

        if _is_activex_entry(name):
            markers.add("activex")

        if _is_embedded_object_entry(name):
            markers.add("embedded_object")

        if _is_external_link_entry(name):
            markers.add("external_link")

        if _is_relationship_entry(name):
            root = _parse_xml(
                entry.data,
                path=name,
                reject_malformed=False,
            )

            if root is not None:
                for child in root:
                    if _local_name(child.tag).lower() != "relationship":
                        continue

                    rel_type = _safe_text(
                        child.attrib.get("Type", ""),
                        2_048,
                    ).lower()

                    if "vbaproject" in rel_type:
                        markers.add("vba_relationship")

                    if "oleobject" in rel_type:
                        markers.add("ole_relationship")

                    if "attachedtemplate" in rel_type:
                        markers.add("remote_template")

                    if _relationship_target_is_external(child):
                        markers.add("external_relationship")

        if lowered.endswith(".xml"):
            sample = entry.data[:65_536].lower()

            if b"ddeauto" in sample or b"dde:" in sample:
                markers.add("dde")

    return markers


def validate_sanitized_document(
    result: SanitizationResult,
) -> Tuple[str, ...]:
    """
    Validate basic invariants of a sanitizer result.

    Returns an empty tuple for a structurally valid result.
    """
    errors: List[str] = []

    if not isinstance(result, SanitizationResult):
        return ("result is not a SanitizationResult",)

    if not re.fullmatch(r"[0-9a-f]{64}", result.original_sha256):
        errors.append(
            "original_sha256 is not a valid SHA-256 digest"
        )

    if not re.fullmatch(r"[0-9a-f]{64}", result.sanitized_sha256):
        errors.append(
            "sanitized_sha256 is not a valid SHA-256 digest"
        )

    if result.original_size < 0:
        errors.append("original_size is negative")

    if result.sanitized_size < 0:
        errors.append("sanitized_size is negative")

    if result.sanitized_size != len(result.data):
        errors.append(
            "sanitized_size does not match result.data length"
        )

    if result.action_count > MAX_ACTIONS:
        errors.append("action count exceeds limit")

    if len(result.warnings) > MAX_WARNINGS:
        errors.append("warning count exceeds limit")

    return tuple(errors)


# ---------------------------------------------------------------------------
# Result helpers
# ---------------------------------------------------------------------------


def _overall_action(
    *,
    actions: Sequence[SanitizationActionRecord],
    changed: bool,
) -> SanitizationAction:
    if any(
        action.action == SanitizationAction.REJECT
        for action in actions
    ):
        return SanitizationAction.REJECT

    if any(
        action.reason
        in {
            SanitizationReason.VBA,
            SanitizationReason.XLM,
            SanitizationReason.ACTIVEX,
            SanitizationReason.EMBEDDED_OBJECT,
            SanitizationReason.EMBEDDED_SCRIPT,
        }
        for action in actions
    ):
        return SanitizationAction.REMOVE

    if any(
        action.action == SanitizationAction.REWRITE
        for action in actions
    ):
        return SanitizationAction.REWRITE

    if changed:
        return SanitizationAction.REWRITE

    return SanitizationAction.PRESERVE


def actions_by_reason(
    result: SanitizationResult,
    reason: SanitizationReason | str,
) -> Tuple[SanitizationActionRecord, ...]:
    """
    Return actions matching a sanitization reason.
    """
    if isinstance(reason, SanitizationReason):
        normalized = reason
    else:
        try:
            normalized = SanitizationReason(
                _safe_text(reason, 128).lower()
            )
        except ValueError:
            return ()

    return tuple(
        action
        for action in result.actions
        if action.reason == normalized
    )


def removed_entry_count(
    result: SanitizationResult,
) -> int:
    """Return number of removed archive entries."""
    return len(result.removed_entries)


def modified_entry_count(
    result: SanitizationResult,
) -> int:
    """Return number of modified archive entries."""
    return len(result.modified_entries)


def preserved_entry_count(
    result: SanitizationResult,
) -> int:
    """Return number of preserved archive entries."""
    return len(result.preserved_entries)


def has_warning(
    result: SanitizationResult,
    code: str,
) -> bool:
    """Return whether a warning code is present."""
    normalized = _safe_text(code, 256).strip().lower()

    return any(
        warning.code.lower() == normalized
        for warning in result.warnings
    )


def was_removed(
    result: SanitizationResult,
    path: str,
) -> bool:
    """Return whether a package member was removed."""
    normalized = _normalize_path(path).lower()

    return any(
        item.lower() == normalized
        for item in result.removed_entries
    )


def was_modified(
    result: SanitizationResult,
    path: str,
) -> bool:
    """Return whether a package member was modified."""
    normalized = _normalize_path(path).lower()

    return any(
        item.lower() == normalized
        for item in result.modified_entries
    )


def iter_actions(
    result: SanitizationResult,
) -> Iterator[SanitizationActionRecord]:
    """Yield sanitizer actions in deterministic order."""
    yield from result.actions


def iter_warnings(
    result: SanitizationResult,
) -> Iterator[SanitizationWarning]:
    """Yield sanitizer warnings."""
    yield from result.warnings


# ---------------------------------------------------------------------------
# Serialization
# ---------------------------------------------------------------------------


def _action_to_dict(
    action: SanitizationActionRecord,
) -> Dict[str, Any]:
    return {
        "action": action.action.value,
        "reason": action.reason.value,
        "path": action.path,
        "detail": action.detail,
        "original_size": action.original_size,
        "resulting_size": action.resulting_size,
        "relationship_type": action.relationship_type,
        "target": action.target,
    }


def _warning_to_dict(
    warning: SanitizationWarning,
) -> Dict[str, Any]:
    return {
        "code": warning.code,
        "path": warning.path,
        "message": warning.message,
        "severity": warning.severity,
    }


def result_to_dict(
    result: SanitizationResult,
    *,
    include_data: bool = False,
) -> Dict[str, Any]:
    """
    Convert a sanitizer result to a JSON-compatible mapping.

    Sanitized binary content is excluded by default to prevent accidental
    duplication of potentially large document data.
    """
    payload: Dict[str, Any] = {
        "original_sha256": result.original_sha256,
        "sanitized_sha256": result.sanitized_sha256,
        "original_size": result.original_size,
        "sanitized_size": result.sanitized_size,
        "format": result.format,
        "changed": result.changed,
        "active_content_removed": result.active_content_removed,
        "external_content_removed": result.external_content_removed,
        "macros_removed": result.macros_removed,
        "embedded_objects_removed": result.embedded_objects_removed,
        "overall_action": result.overall_action.value,
        "actions": [
            _action_to_dict(action)
            for action in result.actions
        ],
        "removed_entries": list(result.removed_entries),
        "modified_entries": list(result.modified_entries),
        "preserved_entries": list(result.preserved_entries),
        "warnings": [
            _warning_to_dict(warning)
            for warning in result.warnings
        ],
        "metadata": dict(result.metadata),
    }

    if include_data:
        payload["data_sha256"] = result.sanitized_sha256
        payload["data_length"] = len(result.data)

    return payload


def to_dict(
    result: SanitizationResult,
    *,
    include_data: bool = False,
) -> Dict[str, Any]:
    """Alias for :func:`result_to_dict`."""
    return result_to_dict(
        result,
        include_data=include_data,
    )


def result_to_json(
    result: SanitizationResult,
    *,
    indent: Optional[int] = 2,
) -> str:
    """
    Serialize sanitizer metadata to JSON.
    """
    import json

    return json.dumps(
        result_to_dict(result),
        indent=indent,
        sort_keys=True,
        ensure_ascii=False,
    )


def save_result_report(
    result: SanitizationResult,
    path: os.PathLike[str] | str,
    *,
    indent: int = 2,
) -> None:
    """
    Save only sanitizer metadata/report JSON.

    The sanitized document bytes are not written by this helper.
    """
    target = Path(path)

    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(
            result_to_json(
                result,
                indent=indent,
            ),
            encoding="utf-8",
        )
    except OSError as exc:
        raise SanitizerOutputError(
            f"Unable to write sanitizer report: {target}"
        ) from exc


# ---------------------------------------------------------------------------
# Output convenience
# ---------------------------------------------------------------------------


def sanitized_bytes(
    result: SanitizationResult,
) -> bytes:
    """
    Return sanitized document bytes.
    """
    return result.data


def save_sanitized_file(
    result: SanitizationResult,
    path: os.PathLike[str] | str,
) -> None:
    """
    Write the already-sanitized result to a caller-selected destination.

    This function writes only the reconstructed safe result; it never writes
    extracted intermediate archive members.
    """
    target = Path(path)

    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(result.data)
    except OSError as exc:
        raise SanitizerOutputError(
            f"Unable to write sanitized document: {target}"
        ) from exc


# ---------------------------------------------------------------------------
# Policy presets
# ---------------------------------------------------------------------------


def balanced_policy() -> SanitizerPolicy:
    """
    Return the standard balanced CDR sanitizer policy.
    """
    return SanitizerPolicy(
        remove_vba=True,
        remove_xlm=True,
        remove_activex=True,
        remove_embedded_objects=True,
        remove_embedded_scripts=True,
        remove_external_relationships=True,
        remove_remote_templates=True,
        remove_dde=True,
        strip_macro_content_types=True,
        strip_active_content_types=True,
        sanitize_custom_xml=False,
        preserve_images=True,
        reject_malformed_xml=False,
        reject_unknown_active_content=False,
    )


def strict_policy() -> SanitizerPolicy:
    """
    Return a strict CDR sanitizer policy.
    """
    return SanitizerPolicy(
        remove_vba=True,
        remove_xlm=True,
        remove_activex=True,
        remove_embedded_objects=True,
        remove_embedded_scripts=True,
        remove_external_relationships=True,
        remove_remote_templates=True,
        remove_dde=True,
        strip_macro_content_types=True,
        strip_active_content_types=True,
        sanitize_custom_xml=True,
        preserve_images=True,
        reject_malformed_xml=True,
        reject_unknown_active_content=True,
    )


def permissive_policy() -> SanitizerPolicy:
    """
    Return a permissive policy that still removes execution-oriented active
    content.
    """
    return SanitizerPolicy(
        remove_vba=True,
        remove_xlm=True,
        remove_activex=True,
        remove_embedded_objects=False,
        remove_embedded_scripts=True,
        remove_external_relationships=True,
        remove_remote_templates=True,
        remove_dde=True,
        strip_macro_content_types=True,
        strip_active_content_types=True,
        sanitize_custom_xml=False,
        preserve_images=True,
        reject_malformed_xml=False,
        reject_unknown_active_content=False,
    )


# ---------------------------------------------------------------------------
# Convenience predicates
# ---------------------------------------------------------------------------


def changed(
    result: SanitizationResult,
) -> bool:
    """Return whether the document was modified."""
    return result.changed


def macros_removed(
    result: SanitizationResult,
) -> bool:
    """Return whether macro content was removed."""
    return result.macros_removed


def active_content_removed(
    result: SanitizationResult,
) -> bool:
    """Return whether active content was removed."""
    return result.active_content_removed


def external_content_removed(
    result: SanitizationResult,
) -> bool:
    """Return whether external content/references were removed."""
    return result.external_content_removed


def requires_reinspection(
    result: SanitizationResult,
) -> bool:
    """
    Return whether downstream integrity/reconstruction inspection is
    advisable.

    Sanitized documents with warnings, modified XML, or removed active
    content should normally be re-parsed by the CDR integrity layer.
    """
    return bool(
        result.warnings
        or result.modified_entries
        or result.removed_entries
    )


# ---------------------------------------------------------------------------
# Public APIs
# ---------------------------------------------------------------------------

__all__ = [
    "MODULE_NAME",
    "SANITIZER_VERSION",
    "MAX_INPUT_BYTES",
    "MAX_OUTPUT_BYTES",
    "MAX_ZIP_ENTRIES",
    "MAX_ENTRY_SIZE",
    "MAX_TOTAL_UNCOMPRESSED",
    "MAX_TOTAL_COMPRESSED",
    "SanitizerError",
    "SanitizerInputError",
    "SanitizerArchiveError",
    "SanitizerOutputError",
    "SanitizationAction",
    "SanitizationReason",
    "SanitizationActionRecord",
    "SanitizationWarning",
    "SanitizerPolicy",
    "SanitizationResult",
    "sanitize",
    "sanitize_document",
    "sanitize_content",
    "sanitize_file",
    "validate_sanitized_document",
    "actions_by_reason",
    "removed_entry_count",
    "modified_entry_count",
    "preserved_entry_count",
    "has_warning",
    "was_removed",
    "was_modified",
    "iter_actions",
    "iter_warnings",
    "result_to_dict",
    "to_dict",
    "result_to_json",
    "save_result_report",
    "sanitized_bytes",
    "save_sanitized_file",
    "balanced_policy",
    "strict_policy",
    "permissive_policy",
    "changed",
    "macros_removed",
    "active_content_removed",
    "external_content_removed",
    "requires_reinspection",
]