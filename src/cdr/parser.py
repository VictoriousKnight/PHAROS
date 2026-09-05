"""
Static document parser for the Pharos CDR pipeline.

The parser provides the structural input required by the CDR policy,
detector, sanitizer, reconstruction, and integrity layers.

Security model
--------------
This module is intentionally static-only:

- Never executes macros, scripts, formulas, ActiveX controls, or OLE objects.
- Never follows external relationships or downloads remote resources.
- Never invokes subprocesses or operating-system execution APIs.
- Never writes extracted embedded objects to disk.
- Never trusts document-provided paths as filesystem paths.
- Uses bounded ZIP/XML/OOXML inspection to reduce decompression and parser
  abuse risk.
- Keeps extracted content in memory and returns metadata/evidence rather than
  executable artifacts.

Supported structural families
-----------------------------
- OOXML: .docx, .docm, .dotx, .dotm, .xlsx, .xlsm, .xltx, .xltm,
  .pptx, .pptm, .potx, .potm, .ppsx, .ppsm
- OLE Compound File Binary Format
- PDF
- RTF
- ZIP/container-like documents
- Generic binary/unknown files

This module does not attempt to fully interpret every document format.
Its purpose is safe structural inspection for downstream CDR decisions.
"""

from __future__ import annotations

import hashlib
import io
import math
import os
import re
import struct
import zipfile
from dataclasses import asdict, dataclass, field, is_dataclass
from pathlib import Path
from typing import Any, Iterable, Iterator, Mapping, Optional, Sequence
from xml.etree import ElementTree as ET

# ---------------------------------------------------------------------------
# Limits
# ---------------------------------------------------------------------------

MAX_FILE_SIZE = 100 * 1024 * 1024
MAX_ZIP_ENTRIES = 20_000
MAX_ZIP_ENTRY_NAME = 4_096
MAX_ZIP_ENTRY_UNCOMPRESSED = 50 * 1024 * 1024
MAX_ZIP_TOTAL_UNCOMPRESSED = 250 * 1024 * 1024
MAX_XML_BYTES = 25 * 1024 * 1024
MAX_XML_ELEMENTS = 250_000
MAX_XML_TEXT = 10_000
MAX_EVIDENCE = 20_000
MAX_RELATIONSHIPS = 10_000
MAX_EMBEDDED_ITEMS = 10_000
MAX_CUSTOM_PROPERTIES = 5_000
MAX_DOCUMENT_PARTS = 20_000
MAX_TEXT_SAMPLE = 100_000
MAX_PATH_TEXT = 4_096
MAX_HASH_BYTES = 16 * 1024 * 1024

MAX_NESTING_DEPTH = 12

# ZIP signatures
ZIP_LOCAL = b"PK\x03\x04"
ZIP_EMPTY = b"PK\x05\x06"
ZIP_SPANNED = b"PK\x07\x08"

# OLE / CFB signature
OLE_MAGIC = bytes.fromhex("D0CF11E0A1B11AE1")

# PDF
PDF_MAGIC = b"%PDF-"

# RTF
RTF_MAGIC = b"{\\rtf"

# PE
PE_DOS_MAGIC = b"MZ"

# ELF
ELF_MAGIC = b"\x7fELF"


# ---------------------------------------------------------------------------
# OOXML namespaces
# ---------------------------------------------------------------------------

NS_REL = "http://schemas.openxmlformats.org/package/2006/relationships"
NS_REL_STRICT = "http://purl.oclc.org/ooxml/package/relationships"

REL_EXTERNAL = {
    "http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink",
    "http://schemas.openxmlformats.org/officeDocument/2006/relationships/oleObject",
    "http://schemas.openxmlformats.org/officeDocument/2006/relationships/package",
    "http://schemas.openxmlformats.org/officeDocument/2006/relationships/control",
    "http://schemas.openxmlformats.org/officeDocument/2006/relationships/image",
    "http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate",
    "http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument",
}

REL_TYPE_HINTS = {
    "oleObject": "ole_object",
    "package": "embedded_package",
    "control": "control",
    "attachedTemplate": "attached_template",
    "hyperlink": "hyperlink",
    "image": "image",
    "vbaProject": "vba_project",
    "externalLink": "external_link",
    "customXml": "custom_xml",
    "connections": "connections",
}


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class CDRParserError(RuntimeError):
    """Base exception for parser failures."""


class CDRInputError(CDRParserError):
    """Raised when parser input is invalid or exceeds configured limits."""


class CDRContainerError(CDRParserError):
    """Raised when a container cannot be safely inspected."""


class CDRXMLLimitError(CDRParserError):
    """Raised when XML inspection exceeds configured limits."""


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DocumentIdentity:
    """Basic identity and cryptographic metadata for a document."""

    filename: str
    extension: str
    size: int
    sha256: str
    format: str
    mime_type: str
    is_container: bool
    is_known_document: bool


@dataclass(frozen=True)
class PackagePart:
    """Metadata for one OOXML/container member."""

    name: str
    normalized_name: str
    extension: str
    size: int
    compressed_size: int
    compression_ratio: float
    crc32: Optional[int]
    is_directory: bool
    is_xml: bool
    is_binary: bool
    is_macro_related: bool
    is_embedded_object: bool
    is_external_link_related: bool
    content_type: str = ""


@dataclass(frozen=True)
class RelationshipRecord:
    """Static OOXML relationship metadata."""

    source_part: str
    relationship_id: str
    relationship_type: str
    target: str
    target_mode: str
    target_is_external: bool
    target_kind: str


@dataclass(frozen=True)
class EmbeddedObjectRecord:
    """Metadata for an embedded or linked object."""

    part_name: str
    object_kind: str
    extension: str
    size: int
    compressed_size: int
    sha256: str
    signature: str
    is_executable: bool
    is_script: bool
    is_document: bool
    is_archive: bool
    is_ole: bool
    is_external: bool
    source_relationship: str = ""


@dataclass(frozen=True)
class DocumentFeature:
    """A structural feature relevant to CDR policy decisions."""

    name: str
    value: Any
    severity: str = "info"
    source: str = ""
    evidence: str = ""


@dataclass(frozen=True)
class ParserEvidence:
    """Bounded evidence item produced by static parsing."""

    category: str
    indicator: str
    severity: str
    source: str
    detail: str


@dataclass(frozen=True)
class ParserStatistics:
    """Aggregate document/package statistics."""

    entry_count: int = 0
    xml_part_count: int = 0
    binary_part_count: int = 0
    macro_part_count: int = 0
    embedded_object_count: int = 0
    external_relationship_count: int = 0
    hyperlink_count: int = 0
    ole_object_count: int = 0
    attached_template_count: int = 0
    active_x_count: int = 0
    custom_xml_count: int = 0
    external_link_count: int = 0
    suspicious_extension_count: int = 0
    high_compression_ratio_count: int = 0
    total_uncompressed_size: int = 0
    total_compressed_size: int = 0
    xml_element_count: int = 0
    xml_text_bytes: int = 0


@dataclass(frozen=True)
class ParsedDocument:
    """Complete static parser output consumed by the CDR pipeline."""

    identity: DocumentIdentity
    parts: tuple[PackagePart, ...] = ()
    relationships: tuple[RelationshipRecord, ...] = ()
    embedded_objects: tuple[EmbeddedObjectRecord, ...] = ()
    features: tuple[DocumentFeature, ...] = ()
    evidence: tuple[ParserEvidence, ...] = ()
    statistics: ParserStatistics = field(default_factory=ParserStatistics)
    text_sample: str = ""
    metadata: Mapping[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Generic helpers
# ---------------------------------------------------------------------------


def _safe_text(value: Any, default: str = "") -> str:
    if value is None:
        return default

    try:
        return str(value)
    except Exception:
        return default


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError, OverflowError):
        return default


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        result = float(value)
    except (TypeError, ValueError, OverflowError):
        return default

    if not math.isfinite(result):
        return default

    return result


def _clamp(value: float, low: float, high: float) -> float:
    return max(low, min(high, value))


def _bounded_text(value: Any, limit: int = MAX_TEXT_SAMPLE) -> str:
    text = _safe_text(value)

    if len(text) <= limit:
        return text

    return text[:limit]


def _normalize_path(path: str) -> str:
    text = _safe_text(path).replace("\\", "/").strip()

    while "//" in text:
        text = text.replace("//", "/")

    # Package paths must be relative. Strip leading slashes defensively.
    text = text.lstrip("/")

    if len(text) > MAX_PATH_TEXT:
        text = text[:MAX_PATH_TEXT]

    return text


def _extension(path: str) -> str:
    name = _safe_text(path).lower().strip()

    if "." not in name:
        return ""

    return "." + name.rsplit(".", 1)[1]


def _sha256(data: bytes) -> str:
    if len(data) <= MAX_HASH_BYTES:
        return hashlib.sha256(data).hexdigest()

    digest = hashlib.sha256()

    digest.update(data[:MAX_HASH_BYTES])

    return digest.hexdigest()


def _read_input(
    source: bytes | bytearray | memoryview | str | os.PathLike[str],
) -> tuple[bytes, str]:
    """
    Read parser input safely.

    Returns:
        (content_bytes, logical_filename)
    """
    if isinstance(source, bytes):
        data = source
        filename = "input.bin"

    elif isinstance(source, bytearray):
        data = bytes(source)
        filename = "input.bin"

    elif isinstance(source, memoryview):
        data = source.tobytes()
        filename = "input.bin"

    elif isinstance(source, (str, os.PathLike)):
        path = Path(source)

        try:
            size = path.stat().st_size
        except OSError as exc:
            raise CDRInputError(f"Unable to stat input file: {path}") from exc

        if size > MAX_FILE_SIZE:
            raise CDRInputError(f"Input exceeds maximum allowed size: {size} bytes.")

        try:
            data = path.read_bytes()
        except OSError as exc:
            raise CDRInputError(f"Unable to read input file: {path}") from exc

        filename = path.name

    else:
        raise CDRInputError(f"Unsupported parser input type: {type(source).__name__}")

    if len(data) > MAX_FILE_SIZE:
        raise CDRInputError(f"Input exceeds maximum allowed size: {len(data)} bytes.")

    return data, filename


def _looks_like_zip(data: bytes) -> bool:
    return data.startswith(
        (
            ZIP_LOCAL,
            ZIP_EMPTY,
            ZIP_SPANNED,
        )
    )


def _looks_like_ole(data: bytes) -> bool:
    return data.startswith(OLE_MAGIC)


def _looks_like_pdf(data: bytes) -> bool:
    return data.startswith(PDF_MAGIC)


def _looks_like_rtf(data: bytes) -> bool:
    return data[:16].lower().startswith(RTF_MAGIC)


def _looks_like_pe(data: bytes) -> bool:
    if len(data) < 64 or not data.startswith(PE_DOS_MAGIC):
        return False

    pe_offset = struct.unpack_from(
        "<I",
        data,
        0x3C,
    )[0]

    if pe_offset < 64:
        return False

    if pe_offset + 4 > len(data):
        return False

    return data[pe_offset : pe_offset + 4] == b"PE\x00\x00"


def _looks_like_elf(data: bytes) -> bool:
    return data.startswith(ELF_MAGIC)


def _magic_name(data: bytes) -> str:
    if _looks_like_pe(data):
        return "PE"

    if _looks_like_elf(data):
        return "ELF"

    if _looks_like_ole(data):
        return "OLE"

    if _looks_like_pdf(data):
        return "PDF"

    if _looks_like_rtf(data):
        return "RTF"

    if _looks_like_zip(data):
        return "ZIP"

    if data.startswith(b"\x1f\x8b"):
        return "GZIP"

    if data.startswith(b"Rar!\x1a\x07"):
        return "RAR"

    if data.startswith(b"7z\xbc\xaf\x27\x1c"):
        return "7Z"

    if data.startswith(b"MSCF"):
        return "CAB"

    return "unknown"


def _format_from_extension(
    extension: str,
    data: bytes,
) -> tuple[str, str, bool]:
    ext = extension.lower()

    office_extensions = {
        ".docx": (
            "docx",
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        ),
        ".docm": ("docm", "application/vnd.ms-word.document.macroEnabled.12"),
        ".dotx": (
            "dotx",
            "application/vnd.openxmlformats-officedocument.wordprocessingml.template",
        ),
        ".dotm": ("dotm", "application/vnd.ms-word.template.macroEnabled.12"),
        ".xlsx": (
            "xlsx",
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        ),
        ".xlsm": ("xlsm", "application/vnd.ms-excel.sheet.macroEnabled.12"),
        ".xltx": (
            "xltx",
            "application/vnd.openxmlformats-officedocument.spreadsheetml.template",
        ),
        ".xltm": ("xltm", "application/vnd.ms-excel.template.macroEnabled.12"),
        ".pptx": (
            "pptx",
            "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        ),
        ".pptm": ("pptm", "application/vnd.ms-powerpoint.presentation.macroEnabled.12"),
        ".potx": (
            "potx",
            "application/vnd.openxmlformats-officedocument.presentationml.template",
        ),
        ".potm": ("potm", "application/vnd.ms-powerpoint.template.macroEnabled.12"),
        ".ppsx": (
            "ppsx",
            "application/vnd.openxmlformats-officedocument.presentationml.slideshow",
        ),
        ".ppsm": ("ppsm", "application/vnd.ms-powerpoint.slideshow.macroEnabled.12"),
    }

    if ext in office_extensions:
        fmt, mime = office_extensions[ext]
        return fmt, mime, True

    simple = {
        ".pdf": ("pdf", "application/pdf"),
        ".rtf": ("rtf", "application/rtf"),
        ".doc": ("ole_document", "application/msword"),
        ".xls": ("ole_workbook", "application/vnd.ms-excel"),
        ".ppt": ("ole_presentation", "application/vnd.ms-powerpoint"),
        ".zip": ("zip", "application/zip"),
    }

    if ext in simple:
        fmt, mime = simple[ext]
        return fmt, mime, ext not in {".zip"}

    magic = _magic_name(data)

    if magic == "OLE":
        return "ole_container", "application/x-ole-storage", True

    if magic == "PDF":
        return "pdf", "application/pdf", True

    if magic == "RTF":
        return "rtf", "application/rtf", True

    if magic == "ZIP":
        return "zip_container", "application/zip", True

    if magic == "PE":
        return "pe", "application/vnd.microsoft.portable-executable", False

    if magic == "ELF":
        return "elf", "application/x-elf", False

    return "unknown", "application/octet-stream", False


# ---------------------------------------------------------------------------
# Content classification
# ---------------------------------------------------------------------------


def _part_kind_from_name(name: str) -> str:
    normalized = _normalize_path(name).lower()

    if "vbaproject" in normalized:
        return "vba_project"

    if "/embeddings/" in normalized:
        return "embedded_object"

    if normalized.startswith("word/vba"):
        return "vba_project"

    if "/activex/" in normalized:
        return "activex"

    if "/ctrlprops/" in normalized:
        return "control_properties"

    if "external" in normalized and "link" in normalized:
        return "external_link"

    if normalized.endswith(".bin"):
        return "binary"

    if normalized.endswith(".xml") or normalized.endswith(".rels"):
        return "xml"

    if normalized.endswith(
        (
            ".js",
            ".jse",
            ".vbs",
            ".vbe",
            ".ps1",
            ".psm1",
            ".psd1",
            ".bat",
            ".cmd",
            ".hta",
        )
    ):
        return "script"

    if normalized.endswith(
        (
            ".exe",
            ".dll",
            ".scr",
            ".com",
            ".sys",
            ".ocx",
        )
    ):
        return "executable"

    return "other"


def _is_macro_related_name(name: str) -> bool:
    normalized = _normalize_path(name).lower()

    macro_markers = (
        "vbaproject",
        "/vba/",
        "vba",
        "macrosheet",
        "dialogsheet",
        "xlm",
        "macro",
    )

    return any(marker in normalized for marker in macro_markers)


def _is_embedded_name(name: str) -> bool:
    normalized = _normalize_path(name).lower()

    return (
        "/embeddings/" in normalized
        or "/activex/" in normalized
        or normalized.startswith("embeddings/")
        or "oleobject" in normalized
    )


def _is_external_name(name: str) -> bool:
    normalized = _normalize_path(name).lower()

    return (
        normalized.endswith(".rels")
        or "externallink" in normalized
        or "external" in normalized
        and "link" in normalized
    )


def _is_xml_name(name: str) -> bool:
    normalized = _normalize_path(name).lower()

    return normalized.endswith((".xml", ".rels"))


def _is_binary_name(name: str) -> bool:
    normalized = _normalize_path(name).lower()

    return normalized.endswith(
        (
            ".bin",
            ".dat",
            ".ole",
            ".exe",
            ".dll",
            ".ocx",
            ".cab",
        )
    )


def _content_type_for_part(
    content_types: Mapping[str, str],
    part_name: str,
) -> str:
    normalized = "/" + _normalize_path(part_name)

    direct = content_types.get(normalized)

    if direct:
        return direct

    extension = _extension(part_name)

    for key, value in content_types.items():
        if key.startswith("*"):
            suffix = key[1:]
            if extension == suffix:
                return value

    return ""


# ---------------------------------------------------------------------------
# ZIP safety inspection
# ---------------------------------------------------------------------------


def _safe_zip_entries(
    data: bytes,
) -> list[zipfile.ZipInfo]:
    if not _looks_like_zip(data):
        raise CDRContainerError("Input does not have a recognized ZIP signature.")

    try:
        archive = zipfile.ZipFile(
            io.BytesIO(data),
            mode="r",
        )
    except (OSError, zipfile.BadZipFile) as exc:
        raise CDRContainerError("Unable to inspect ZIP container safely.") from exc

    try:
        entries = archive.infolist()

        if len(entries) > MAX_ZIP_ENTRIES:
            raise CDRContainerError("ZIP container contains too many entries.")

        total_uncompressed = 0

        for info in entries:
            filename = _safe_text(info.filename)

            if len(filename) > MAX_ZIP_ENTRY_NAME:
                raise CDRContainerError("ZIP entry name exceeds configured limit.")

            normalized = _normalize_path(filename)

            # Reject absolute/traversal package paths.
            if (
                filename.startswith(("/", "\\"))
                or re.match(r"^[A-Za-z]:", filename)
                or any(component == ".." for component in normalized.split("/"))
            ):
                raise CDRContainerError("ZIP container contains an unsafe path.")

            uncompressed = _safe_int(
                info.file_size,
                0,
            )

            if uncompressed < 0:
                raise CDRContainerError("ZIP entry has invalid uncompressed size.")

            if uncompressed > MAX_ZIP_ENTRY_UNCOMPRESSED:
                raise CDRContainerError("ZIP entry exceeds per-entry size limit.")

            total_uncompressed += uncompressed

            if total_uncompressed > MAX_ZIP_TOTAL_UNCOMPRESSED:
                raise CDRContainerError(
                    "ZIP container exceeds total uncompressed size limit."
                )

        return entries

    finally:
        archive.close()


def _read_zip_member(
    data: bytes,
    info: zipfile.ZipInfo,
    *,
    limit: int,
) -> bytes:
    if info.is_dir():
        return b""

    expected = _safe_int(info.file_size, 0)

    if expected > limit:
        raise CDRContainerError(f"ZIP member exceeds read limit: {info.filename}")

    try:
        with zipfile.ZipFile(
            io.BytesIO(data),
            mode="r",
        ) as archive:
            with archive.open(info, mode="r") as handle:
                content = handle.read(limit + 1)
    except (OSError, EOFError, RuntimeError, zipfile.BadZipFile) as exc:
        raise CDRContainerError(
            f"Unable to read ZIP member safely: {info.filename}"
        ) from exc

    if len(content) > limit:
        raise CDRContainerError(
            f"ZIP member exceeded configured read limit: {info.filename}"
        )

    return content


# ---------------------------------------------------------------------------
# OOXML content types
# ---------------------------------------------------------------------------


def _parse_content_types(
    data: bytes,
    entries: Sequence[zipfile.ZipInfo],
) -> dict[str, str]:
    content_types_info = None

    for info in entries:
        if _normalize_path(info.filename).lower() == "[content_types].xml":
            content_types_info = info
            break

    if content_types_info is None:
        return {}

    raw = _read_zip_member(
        data,
        content_types_info,
        limit=MAX_XML_BYTES,
    )

    try:
        root = ET.fromstring(raw)
    except ET.ParseError:
        return {}

    result: dict[str, str] = {}

    for child in root:
        local = child.tag.rsplit("}", 1)[-1]

        if local == "Default":
            extension = _safe_text(child.attrib.get("Extension")).lower()

            content_type = _safe_text(child.attrib.get("ContentType"))

            if extension:
                result["*." + extension] = content_type

        elif local == "Override":
            part_name = _normalize_path(child.attrib.get("PartName", ""))

            content_type = _safe_text(child.attrib.get("ContentType"))

            if part_name:
                result["/" + part_name] = content_type

    return result


# ---------------------------------------------------------------------------
# Relationship parsing
# ---------------------------------------------------------------------------


def _relationship_kind(
    relationship_type: str,
) -> str:
    normalized = _safe_text(relationship_type).lower()

    for marker, kind in REL_TYPE_HINTS.items():
        if marker.lower() in normalized:
            return kind

    if "external" in normalized and "link" in normalized:
        return "external_link"

    return "other"


def _parse_relationships(
    data: bytes,
    entries: Sequence[zipfile.ZipInfo],
) -> tuple[list[RelationshipRecord], list[ParserEvidence]]:
    relationships: list[RelationshipRecord] = []
    evidence: list[ParserEvidence] = []

    for info in entries:
        if len(relationships) >= MAX_RELATIONSHIPS:
            break

        name = _normalize_path(info.filename)

        if not name.lower().endswith(".rels"):
            continue

        raw = _read_zip_member(
            data,
            info,
            limit=MAX_XML_BYTES,
        )

        try:
            root = ET.fromstring(raw)
        except ET.ParseError:
            evidence.append(
                ParserEvidence(
                    category="parser",
                    indicator="malformed_relationship_xml",
                    severity="medium",
                    source=name,
                    detail="Relationship XML could not be parsed.",
                )
            )
            continue

        source_part = _relationship_source_part(name)

        for child in root:
            if len(relationships) >= MAX_RELATIONSHIPS:
                break

            local_name = child.tag.rsplit("}", 1)[-1]

            if local_name != "Relationship":
                continue

            relationship_id = _safe_text(child.attrib.get("Id"))

            relationship_type = _safe_text(child.attrib.get("Type"))

            target = _safe_text(child.attrib.get("Target"))

            target_mode = _safe_text(child.attrib.get("TargetMode"))

            target_external = (
                target_mode.lower() == "external"
                or target.lower().startswith(
                    (
                        "http://",
                        "https://",
                        "ftp://",
                        "file://",
                        "mailto:",
                    )
                )
            )

            kind = _relationship_kind(relationship_type)

            record = RelationshipRecord(
                source_part=source_part,
                relationship_id=relationship_id,
                relationship_type=relationship_type,
                target=_bounded_text(
                    target,
                    MAX_PATH_TEXT,
                ),
                target_mode=target_mode,
                target_is_external=target_external,
                target_kind=kind,
            )

            relationships.append(record)

            if target_external:
                evidence.append(
                    ParserEvidence(
                        category="external_resource",
                        indicator="external_relationship",
                        severity="medium",
                        source=name,
                        detail=(f"{kind}: " f"{_bounded_text(target, 512)}"),
                    )
                )

            if kind == "attached_template":
                evidence.append(
                    ParserEvidence(
                        category="template",
                        indicator="attached_template",
                        severity="high",
                        source=name,
                        detail=_bounded_text(
                            target,
                            512,
                        ),
                    )
                )

            if kind == "ole_object":
                evidence.append(
                    ParserEvidence(
                        category="embedded_object",
                        indicator="ole_relationship",
                        severity="high",
                        source=name,
                        detail=_bounded_text(
                            target,
                            512,
                        ),
                    )
                )

    return relationships, evidence


def _relationship_source_part(
    rels_path: str,
) -> str:
    normalized = _normalize_path(rels_path)

    if normalized.lower() == "_rels/.rels":
        return ""

    marker = "/_rels/"

    if marker in normalized:
        base, rel_name = normalized.rsplit(
            marker,
            1,
        )

        if rel_name.lower().endswith(".rels"):
            rel_name = rel_name[:-5]

        if base:
            return f"{base}/{rel_name}"

        return rel_name

    if normalized.lower().startswith("_rels/"):
        rel_name = normalized[6:]

        if rel_name.lower().endswith(".rels"):
            rel_name = rel_name[:-5]

        return rel_name

    return normalized


# ---------------------------------------------------------------------------
# OOXML embedded-object inspection
# ---------------------------------------------------------------------------


def _signature_for_content(data: bytes) -> str:
    return _magic_name(data)


def _classify_embedded_content(
    data: bytes,
    extension: str,
) -> tuple[
    str,
    bool,
    bool,
    bool,
    bool,
    bool,
]:
    """
    Returns:
        kind,
        executable,
        script,
        document,
        archive,
        ole
    """
    signature = _magic_name(data)
    ext = extension.lower()

    executable = signature in {"PE", "ELF"} or ext in {
        ".exe",
        ".dll",
        ".scr",
        ".sys",
        ".ocx",
        ".com",
    }

    script = ext in {
        ".js",
        ".jse",
        ".vbs",
        ".vbe",
        ".ps1",
        ".psm1",
        ".bat",
        ".cmd",
        ".hta",
        ".sh",
    }

    document = signature in {
        "PDF",
        "RTF",
        "OLE",
        "ZIP",
    } or ext in {
        ".pdf",
        ".rtf",
        ".doc",
        ".xls",
        ".ppt",
        ".docx",
        ".docm",
        ".xlsx",
        ".xlsm",
        ".pptx",
        ".pptm",
    }

    archive = signature in {
        "ZIP",
        "GZIP",
        "RAR",
        "7Z",
        "CAB",
    } or ext in {
        ".zip",
        ".gz",
        ".gzip",
        ".rar",
        ".7z",
        ".cab",
    }

    ole = signature == "OLE"

    if executable:
        kind = "executable"
    elif script:
        kind = "script"
    elif ole:
        kind = "ole"
    elif archive:
        kind = "archive"
    elif document:
        kind = "document"
    else:
        kind = "binary"

    return (
        kind,
        executable,
        script,
        document,
        archive,
        ole,
    )


def _extract_embedded_objects(
    data: bytes,
    entries: Sequence[zipfile.ZipInfo],
    relationships: Sequence[RelationshipRecord],
) -> tuple[
    list[EmbeddedObjectRecord],
    list[ParserEvidence],
]:
    objects: list[EmbeddedObjectRecord] = []
    evidence: list[ParserEvidence] = []

    relationship_targets: dict[str, list[RelationshipRecord]] = {}

    for relationship in relationships:
        target = _normalize_path(relationship.target).lower()

        relationship_targets.setdefault(
            target,
            [],
        ).append(relationship)

    for info in entries:
        if len(objects) >= MAX_EMBEDDED_ITEMS:
            break

        name = _normalize_path(info.filename)

        if info.is_dir():
            continue

        is_embedded = _is_embedded_name(name)

        if not is_embedded:
            continue

        try:
            raw = _read_zip_member(
                data,
                info,
                limit=min(
                    MAX_ZIP_ENTRY_UNCOMPRESSED,
                    MAX_HASH_BYTES,
                ),
            )
        except CDRContainerError as exc:
            evidence.append(
                ParserEvidence(
                    category="embedded_object",
                    indicator="embedded_object_unreadable",
                    severity="high",
                    source=name,
                    detail=str(exc),
                )
            )
            continue

        extension = _extension(name)

        (
            kind,
            executable,
            script,
            document,
            archive,
            ole,
        ) = _classify_embedded_content(
            raw,
            extension,
        )

        linked_relationships = relationship_targets.get(
            name.lower(),
            [],
        )

        external = any(item.target_is_external for item in linked_relationships)

        source_relationship = ""

        if linked_relationships:
            source_relationship = linked_relationships[0].relationship_id

        record = EmbeddedObjectRecord(
            part_name=name,
            object_kind=kind,
            extension=extension,
            size=_safe_int(info.file_size),
            compressed_size=_safe_int(info.compress_size),
            sha256=_sha256(raw),
            signature=_signature_for_content(raw),
            is_executable=executable,
            is_script=script,
            is_document=document,
            is_archive=archive,
            is_ole=ole,
            is_external=external,
            source_relationship=source_relationship,
        )

        objects.append(record)

        if executable:
            evidence.append(
                ParserEvidence(
                    category="embedded_object",
                    indicator="embedded_executable",
                    severity="critical",
                    source=name,
                    detail=(
                        f"Embedded object has executable signature "
                        f"{record.signature}."
                    ),
                )
            )

        elif script:
            evidence.append(
                ParserEvidence(
                    category="embedded_object",
                    indicator="embedded_script",
                    severity="high",
                    source=name,
                    detail=(
                        f"Embedded object has script-like extension " f"{extension}."
                    ),
                )
            )

        elif ole:
            evidence.append(
                ParserEvidence(
                    category="embedded_object",
                    indicator="embedded_ole",
                    severity="high",
                    source=name,
                    detail="Embedded object has OLE/CFB signature.",
                )
            )

        if archive:
            evidence.append(
                ParserEvidence(
                    category="embedded_object",
                    indicator="embedded_archive",
                    severity="medium",
                    source=name,
                    detail="Embedded object has archive/container signature.",
                )
            )

    return objects, evidence


# ---------------------------------------------------------------------------
# XML inspection
# ---------------------------------------------------------------------------


def _xml_local_name(tag: str) -> str:
    if "}" in tag:
        return tag.rsplit("}", 1)[-1]

    return tag


def _xml_attribute_text(
    element: ET.Element,
) -> str:
    parts: list[str] = []

    for key, value in element.attrib.items():
        parts.append(f"{_xml_local_name(key)}={_safe_text(value)}")

    return " ".join(parts)


def _inspect_xml(
    data: bytes,
    part_name: str,
) -> tuple[
    int,
    int,
    str,
    list[ParserEvidence],
]:
    if len(data) > MAX_XML_BYTES:
        raise CDRXMLLimitError(f"XML part exceeds maximum size: {part_name}")

    try:
        root = ET.fromstring(data)
    except ET.ParseError as exc:
        return (
            0,
            0,
            "",
            [
                ParserEvidence(
                    category="parser",
                    indicator="malformed_xml",
                    severity="medium",
                    source=part_name,
                    detail=_bounded_text(
                        str(exc),
                        512,
                    ),
                )
            ],
        )

    element_count = 0
    text_bytes = 0
    text_fragments: list[str] = []
    evidence: list[ParserEvidence] = []

    suspicious_attributes = (
        "Target",
        "TargetMode",
        "External",
        "r:id",
        "href",
        "link",
    )

    suspicious_text_patterns = (
        (
            re.compile(
                r"(?:https?|ftp|file)://",
                re.IGNORECASE,
            ),
            "external_url",
            "medium",
        ),
        (
            re.compile(
                r"\\\\[^\\/\s]+\\",
                re.IGNORECASE,
            ),
            "unc_path",
            "medium",
        ),
        (
            re.compile(
                r"\b(?:powershell|cmd|wscript|cscript|mshta|rundll32|regsvr32)\b",
                re.IGNORECASE,
            ),
            "execution_string",
            "high",
        ),
    )

    for element in root.iter():
        element_count += 1

        if element_count > MAX_XML_ELEMENTS:
            raise CDRXMLLimitError(f"XML element count exceeds limit: {part_name}")

        attrs = _xml_attribute_text(element)

        for attribute_name in suspicious_attributes:
            if attribute_name in element.attrib:
                value = _bounded_text(
                    element.attrib.get(attribute_name, ""),
                    2_048,
                )

                if value:
                    evidence.append(
                        ParserEvidence(
                            category="xml",
                            indicator="suspicious_attribute",
                            severity="medium",
                            source=part_name,
                            detail=(
                                f"{_xml_local_name(element.tag)} "
                                f"{attribute_name}={value}"
                            ),
                        )
                    )

        if attrs:
            text_fragments.append(attrs)

        if element.text:
            text = _bounded_text(
                element.text,
                MAX_XML_TEXT,
            )

            text_bytes += len(
                text.encode(
                    "utf-8",
                    errors="ignore",
                )
            )

            if len("".join(text_fragments)) < MAX_TEXT_SAMPLE:
                text_fragments.append(text)

            for pattern, indicator, severity in suspicious_text_patterns:
                if pattern.search(text):
                    evidence.append(
                        ParserEvidence(
                            category="xml",
                            indicator=indicator,
                            severity=severity,
                            source=part_name,
                            detail=_bounded_text(
                                text.strip(),
                                512,
                            ),
                        )
                    )

        if len(evidence) >= MAX_EVIDENCE:
            break

        if text_bytes > MAX_XML_BYTES:
            break

    text_sample = _bounded_text(
        " ".join(fragment for fragment in text_fragments if fragment),
        MAX_TEXT_SAMPLE,
    )

    return (
        element_count,
        text_bytes,
        text_sample,
        evidence,
    )


# ---------------------------------------------------------------------------
# Document text extraction
# ---------------------------------------------------------------------------


def _extract_text_sample(
    data: bytes,
    entries: Sequence[zipfile.ZipInfo],
) -> str:
    fragments: list[str] = []

    interesting_names = (
        "word/document.xml",
        "word/header",
        "word/footer",
        "word/comments",
        "xl/sharedstrings.xml",
        "xl/worksheets/",
        "ppt/slides/",
        "ppt/notes",
        "docprops/",
    )

    for info in entries:
        if len(" ".join(fragments)) >= MAX_TEXT_SAMPLE:
            break

        name = _normalize_path(info.filename).lower()

        if not name.endswith(".xml"):
            continue

        if not any(marker in name for marker in interesting_names):
            continue

        try:
            raw = _read_zip_member(
                data,
                info,
                limit=MAX_XML_BYTES,
            )
        except CDRContainerError:
            continue

        try:
            root = ET.fromstring(raw)
        except ET.ParseError:
            continue

        for element in root.iter():
            if element.text:
                text = element.text.strip()

                if text:
                    fragments.append(text)

                    if len(" ".join(fragments)) >= MAX_TEXT_SAMPLE:
                        break

    return _bounded_text(
        " ".join(fragments),
        MAX_TEXT_SAMPLE,
    )


# ---------------------------------------------------------------------------
# OOXML package parser
# ---------------------------------------------------------------------------


def _parse_ooxml(
    data: bytes,
    filename: str,
    identity: DocumentIdentity,
) -> ParsedDocument:
    entries = _safe_zip_entries(data)

    content_types = _parse_content_types(
        data,
        entries,
    )

    relationships, relationship_evidence = _parse_relationships(
        data,
        entries,
    )

    parts: list[PackagePart] = []
    evidence: list[ParserEvidence] = list(relationship_evidence)
    features: list[DocumentFeature] = []

    xml_count = 0
    binary_count = 0
    macro_count = 0
    suspicious_extensions = 0
    high_ratio_count = 0
    total_uncompressed = 0
    total_compressed = 0
    xml_element_count = 0
    xml_text_bytes = 0

    macro_extensions = {
        ".bin",
    }

    suspicious_extension_names = {
        ".exe",
        ".dll",
        ".scr",
        ".com",
        ".cmd",
        ".bat",
        ".js",
        ".jse",
        ".vbs",
        ".vbe",
        ".ps1",
        ".hta",
    }

    for info in entries:
        if len(parts) >= MAX_DOCUMENT_PARTS:
            break

        name = _normalize_path(info.filename)

        if not name:
            continue

        size = _safe_int(
            info.file_size,
            0,
        )

        compressed_size = _safe_int(
            info.compress_size,
            0,
        )

        total_uncompressed += size
        total_compressed += compressed_size

        ratio = (
            size / compressed_size
            if compressed_size > 0
            else float("inf") if size > 0 else 1.0
        )

        if ratio > 100:
            high_ratio_count += 1

            evidence.append(
                ParserEvidence(
                    category="container",
                    indicator="high_compression_ratio",
                    severity="medium",
                    source=name,
                    detail=(f"Compression ratio approximately " f"{ratio:.2f}:1."),
                )
            )

        extension = _extension(name)

        is_xml = _is_xml_name(name)
        is_binary = _is_binary_name(name)
        is_macro = _is_macro_related_name(name)
        is_embedded = _is_embedded_name(name)
        is_external = _is_external_name(name)

        if is_xml:
            xml_count += 1

        if is_binary:
            binary_count += 1

        if is_macro:
            macro_count += 1

        if extension in suspicious_extension_names:
            suspicious_extensions += 1

            evidence.append(
                ParserEvidence(
                    category="embedded_content",
                    indicator="suspicious_file_extension",
                    severity="high",
                    source=name,
                    detail=(
                        f"Package member uses suspicious extension " f"{extension}."
                    ),
                )
            )

        content_type = _content_type_for_part(
            content_types,
            name,
        )

        part = PackagePart(
            name=name,
            normalized_name=name.lower(),
            extension=extension,
            size=size,
            compressed_size=compressed_size,
            compression_ratio=(float(ratio) if math.isfinite(ratio) else float("inf")),
            crc32=(_safe_int(info.CRC) if info.CRC is not None else None),
            is_directory=info.is_dir(),
            is_xml=is_xml,
            is_binary=is_binary,
            is_macro_related=is_macro,
            is_embedded_object=is_embedded,
            is_external_link_related=is_external,
            content_type=content_type,
        )

        parts.append(part)

        if is_macro:
            evidence.append(
                ParserEvidence(
                    category="macro",
                    indicator="macro_related_part",
                    severity="high",
                    source=name,
                    detail="Package member is associated with macro/XLM content.",
                )
            )

        if is_embedded:
            evidence.append(
                ParserEvidence(
                    category="embedded_object",
                    indicator="embedded_part",
                    severity="high",
                    source=name,
                    detail="Package member resides in an embedded/control area.",
                )
            )

        if is_external:
            evidence.append(
                ParserEvidence(
                    category="external_resource",
                    indicator="external_link_part",
                    severity="medium",
                    source=name,
                    detail="Package member is associated with external links.",
                )
            )

        if len(evidence) >= MAX_EVIDENCE and len(parts) >= MAX_DOCUMENT_PARTS:
            break

    embedded_objects, embedded_evidence = _extract_embedded_objects(
        data,
        entries,
        relationships,
    )

    evidence.extend(embedded_evidence)

    active_x_count = sum(
        1
        for part in parts
        if "/activex/" in part.normalized_name or "ctrlprops" in part.normalized_name
    )

    ole_count = sum(
        1 for relationship in relationships if relationship.target_kind == "ole_object"
    )

    hyperlink_count = sum(
        1 for relationship in relationships if relationship.target_kind == "hyperlink"
    )

    external_relationship_count = sum(
        1 for relationship in relationships if relationship.target_is_external
    )

    attached_template_count = sum(
        1
        for relationship in relationships
        if relationship.target_kind == "attached_template"
    )

    external_link_count = sum(
        1
        for relationship in relationships
        if relationship.target_kind == "external_link"
    )

    custom_xml_count = sum(1 for part in parts if "customxml" in part.normalized_name)

    # Inspect XML parts only after structural enumeration.
    for info in entries:
        if len(evidence) >= MAX_EVIDENCE:
            break

        name = _normalize_path(info.filename)

        if not _is_xml_name(name):
            continue

        try:
            raw = _read_zip_member(
                data,
                info,
                limit=MAX_XML_BYTES,
            )
        except CDRContainerError as exc:
            evidence.append(
                ParserEvidence(
                    category="parser",
                    indicator="xml_part_unreadable",
                    severity="medium",
                    source=name,
                    detail=str(exc),
                )
            )
            continue

        try:
            (
                element_count,
                text_bytes,
                _sample,
                xml_evidence,
            ) = _inspect_xml(
                raw,
                name,
            )
        except CDRXMLLimitError as exc:
            evidence.append(
                ParserEvidence(
                    category="parser",
                    indicator="xml_resource_limit",
                    severity="high",
                    source=name,
                    detail=str(exc),
                )
            )
            continue

        xml_element_count += element_count
        xml_text_bytes += text_bytes
        evidence.extend(xml_evidence)

    if macro_count:
        features.append(
            DocumentFeature(
                name="macro_related_parts",
                value=macro_count,
                severity="high",
                source="package",
                evidence="Macro/XLM-related package parts detected.",
            )
        )

    if embedded_objects:
        features.append(
            DocumentFeature(
                name="embedded_object_count",
                value=len(embedded_objects),
                severity="high",
                source="package",
                evidence="Embedded package/control/object parts detected.",
            )
        )

    if external_relationship_count:
        features.append(
            DocumentFeature(
                name="external_relationship_count",
                value=external_relationship_count,
                severity="medium",
                source="relationships",
                evidence="External relationships are present.",
            )
        )

    if attached_template_count:
        features.append(
            DocumentFeature(
                name="attached_template_count",
                value=attached_template_count,
                severity="high",
                source="relationships",
                evidence="Attached template relationship detected.",
            )
        )

    if active_x_count:
        features.append(
            DocumentFeature(
                name="active_x_count",
                value=active_x_count,
                severity="critical",
                source="package",
                evidence="ActiveX/control package content detected.",
            )
        )

    if high_ratio_count:
        features.append(
            DocumentFeature(
                name="high_compression_ratio_count",
                value=high_ratio_count,
                severity="medium",
                source="package",
                evidence="One or more entries have unusually high compression ratios.",
            )
        )

    if suspicious_extensions:
        features.append(
            DocumentFeature(
                name="suspicious_extension_count",
                value=suspicious_extensions,
                severity="high",
                source="package",
                evidence="Executable/script-like package members detected.",
            )
        )

    statistics = ParserStatistics(
        entry_count=len(parts),
        xml_part_count=xml_count,
        binary_part_count=binary_count,
        macro_part_count=macro_count,
        embedded_object_count=len(embedded_objects),
        external_relationship_count=external_relationship_count,
        hyperlink_count=hyperlink_count,
        ole_object_count=ole_count,
        attached_template_count=attached_template_count,
        active_x_count=active_x_count,
        custom_xml_count=custom_xml_count,
        external_link_count=external_link_count,
        suspicious_extension_count=suspicious_extensions,
        high_compression_ratio_count=high_ratio_count,
        total_uncompressed_size=total_uncompressed,
        total_compressed_size=total_compressed,
        xml_element_count=xml_element_count,
        xml_text_bytes=xml_text_bytes,
    )

    text_sample = _extract_text_sample(
        data,
        entries,
    )

    metadata = {
        "container": "zip",
        "ooxml": True,
        "content_types": len(content_types),
        "macro_enabled_extension": identity.extension.lower()
        in {
            ".docm",
            ".dotm",
            ".xlsm",
            ".xltm",
            ".pptm",
            ".potm",
            ".ppsm",
        },
    }

    evidence = _deduplicate_evidence(evidence)

    return ParsedDocument(
        identity=identity,
        parts=tuple(parts),
        relationships=tuple(relationships),
        embedded_objects=tuple(embedded_objects),
        features=tuple(features),
        evidence=tuple(evidence[:MAX_EVIDENCE]),
        statistics=statistics,
        text_sample=text_sample,
        metadata=metadata,
    )


# ---------------------------------------------------------------------------
# OLE parser
# ---------------------------------------------------------------------------


def _parse_ole(
    data: bytes,
    filename: str,
    identity: DocumentIdentity,
) -> ParsedDocument:
    evidence: list[ParserEvidence] = []
    features: list[DocumentFeature] = []

    evidence.append(
        ParserEvidence(
            category="container",
            indicator="ole_compound_file",
            severity="high",
            source=filename,
            detail="Input has an OLE Compound File Binary signature.",
        )
    )

    # CFB header contains useful structural information without parsing
    # arbitrary streams or invoking OLE handlers.
    sector_shift = None
    mini_sector_shift = None
    num_fat_sectors = None
    num_dir_sectors = None

    if len(data) >= 512:
        try:
            sector_shift = struct.unpack_from(
                "<H",
                data,
                30,
            )[0]

            mini_sector_shift = struct.unpack_from(
                "<H",
                data,
                32,
            )[0]

            num_fat_sectors = struct.unpack_from(
                "<I",
                data,
                44,
            )[0]

            num_dir_sectors = struct.unpack_from(
                "<I",
                data,
                40,
            )[0]
        except struct.error:
            pass

    if sector_shift not in {
        9,
        12,
    }:
        evidence.append(
            ParserEvidence(
                category="container",
                indicator="unusual_ole_sector_size",
                severity="medium",
                source=filename,
                detail=f"Sector shift: {sector_shift!r}.",
            )
        )

    if mini_sector_shift not in {
        None,
        6,
    }:
        evidence.append(
            ParserEvidence(
                category="container",
                indicator="unusual_ole_mini_sector_size",
                severity="low",
                source=filename,
                detail=f"Mini-sector shift: {mini_sector_shift!r}.",
            )
        )

    # Static string inspection of the bounded OLE header/body sample is
    # intentionally conservative. It does not invoke OLE parsers or VBA.
    sample = data[:MAX_TEXT_SAMPLE]

    decoded = sample.decode(
        "latin-1",
        errors="ignore",
    )

    ole_markers = (
        "VBA",
        "Macros",
        "ThisDocument",
        "Workbook",
        "AutoExec",
        "AutoOpen",
        "Document_Open",
        "Shell",
        "CreateObject",
        "WScript",
        "PowerShell",
    )

    marker_count = 0

    for marker in ole_markers:
        if marker.lower() in decoded.lower():
            marker_count += 1

            severity = (
                "high"
                if marker.lower()
                in {
                    "vba",
                    "macro",
                    "autoexec",
                    "autoopen",
                    "document_open",
                    "shell",
                    "createobject",
                    "powershell",
                }
                else "medium"
            )

            evidence.append(
                ParserEvidence(
                    category="macro",
                    indicator="ole_macro_marker",
                    severity=severity,
                    source=filename,
                    detail=f"Static marker detected: {marker}.",
                )
            )

    if marker_count:
        features.append(
            DocumentFeature(
                name="ole_macro_marker_count",
                value=marker_count,
                severity="high",
                source=filename,
                evidence="Potential macro/VBA markers were found statically.",
            )
        )

    metadata = {
        "container": "ole",
        "sector_shift": sector_shift,
        "mini_sector_shift": mini_sector_shift,
        "num_fat_sectors": num_fat_sectors,
        "num_directory_sectors": num_dir_sectors,
        "ole_stream_parsing": False,
        "macro_execution": False,
    }

    statistics = ParserStatistics(
        entry_count=1,
        binary_part_count=1,
        macro_part_count=marker_count,
        total_uncompressed_size=len(data),
        total_compressed_size=len(data),
    )

    return ParsedDocument(
        identity=identity,
        features=tuple(features),
        evidence=tuple(_deduplicate_evidence(evidence)),
        statistics=statistics,
        text_sample=_bounded_text(
            decoded,
            MAX_TEXT_SAMPLE,
        ),
        metadata=metadata,
    )


# ---------------------------------------------------------------------------
# PDF parser
# ---------------------------------------------------------------------------


def _parse_pdf(
    data: bytes,
    filename: str,
    identity: DocumentIdentity,
) -> ParsedDocument:
    evidence: list[ParserEvidence] = []
    features: list[DocumentFeature] = []

    sample = data[:MAX_TEXT_SAMPLE]

    # PDF syntax is inspected as bytes/Latin-1 text only. No PDF renderer or
    # JavaScript engine is invoked.
    text = sample.decode(
        "latin-1",
        errors="ignore",
    )

    patterns = (
        (
            re.compile(
                r"/JavaScript\b|/JS\b",
                re.IGNORECASE,
            ),
            "javascript",
            "critical",
        ),
        (
            re.compile(
                r"/OpenAction\b|/AA\b",
                re.IGNORECASE,
            ),
            "automatic_action",
            "high",
        ),
        (
            re.compile(
                r"/Launch\b",
                re.IGNORECASE,
            ),
            "launch_action",
            "critical",
        ),
        (
            re.compile(
                r"/EmbeddedFile\b|/Filespec\b",
                re.IGNORECASE,
            ),
            "embedded_file",
            "high",
        ),
        (
            re.compile(
                r"/RichMedia\b|/3D\b",
                re.IGNORECASE,
            ),
            "active_content",
            "high",
        ),
        (
            re.compile(
                r"/SubmitForm\b|/GoToR\b|/URI\b",
                re.IGNORECASE,
            ),
            "external_action",
            "medium",
        ),
    )

    counts: dict[str, int] = {}

    for pattern, indicator, severity in patterns:
        count = len(pattern.findall(text))

        if count:
            counts[indicator] = count

            evidence.append(
                ParserEvidence(
                    category="pdf_active_content",
                    indicator=indicator,
                    severity=severity,
                    source=filename,
                    detail=f"Detected {count} PDF marker occurrence(s).",
                )
            )

            features.append(
                DocumentFeature(
                    name=f"pdf_{indicator}_count",
                    value=count,
                    severity=severity,
                    source=filename,
                    evidence=f"PDF marker {indicator} detected.",
                )
            )

    statistics = ParserStatistics(
        entry_count=1,
        binary_part_count=1,
        total_uncompressed_size=len(data),
        total_compressed_size=len(data),
    )

    metadata = {
        "container": "pdf",
        "active_content_indicators": counts,
        "renderer_invocation": False,
        "javascript_execution": False,
    }

    return ParsedDocument(
        identity=identity,
        features=tuple(features),
        evidence=tuple(_deduplicate_evidence(evidence)),
        statistics=statistics,
        text_sample=_extract_pdf_text_sample(text),
        metadata=metadata,
    )


def _extract_pdf_text_sample(
    text: str,
) -> str:
    """
    Extract a conservative PDF text sample from literal strings.

    This is not a full PDF parser and deliberately does not decode streams,
    execute JavaScript, process forms, or resolve objects.
    """
    fragments: list[str] = []

    # Basic PDF literal-string pattern. Escapes are intentionally retained.
    for match in re.finditer(
        r"\((?:\\.|[^\\)]){1,2048}\)",
        text,
    ):
        value = match.group(0)[1:-1]

        if value:
            fragments.append(value)

        if len(" ".join(fragments)) >= MAX_TEXT_SAMPLE:
            break

    return _bounded_text(
        " ".join(fragments),
        MAX_TEXT_SAMPLE,
    )


# ---------------------------------------------------------------------------
# RTF parser
# ---------------------------------------------------------------------------


def _parse_rtf(
    data: bytes,
    filename: str,
    identity: DocumentIdentity,
) -> ParsedDocument:
    evidence: list[ParserEvidence] = []
    features: list[DocumentFeature] = []

    text = data[:MAX_TEXT_SAMPLE].decode(
        "latin-1",
        errors="ignore",
    )

    patterns = (
        (
            r"\\object\b",
            "embedded_object",
            "high",
        ),
        (
            r"\\objdata\b",
            "embedded_object_data",
            "critical",
        ),
        (
            r"\\objupdate\b",
            "object_update",
            "high",
        ),
        (
            r"\\template\b|\\*\s*\\atnref\b",
            "template_reference",
            "high",
        ),
        (
            r"\\field\b",
            "field",
            "low",
        ),
        (
            r"\\fldinst\b",
            "field_instruction",
            "medium",
        ),
        (
            r"INCLUDEPICTURE|INCLUDETEXT|DDEAUTO|DDE",
            "external_or_dynamic_field",
            "high",
        ),
    )

    for pattern, indicator, severity in patterns:
        count = len(
            re.findall(
                pattern,
                text,
                flags=re.IGNORECASE,
            )
        )

        if count:
            evidence.append(
                ParserEvidence(
                    category="rtf",
                    indicator=indicator,
                    severity=severity,
                    source=filename,
                    detail=f"Detected {count} RTF marker occurrence(s).",
                )
            )

            features.append(
                DocumentFeature(
                    name=f"rtf_{indicator}_count",
                    value=count,
                    severity=severity,
                    source=filename,
                    evidence=f"RTF marker {indicator} detected.",
                )
            )

    # Static object signatures in bounded RTF content.
    signatures = (
        (b"MZ", "embedded_pe", "critical"),
        (OLE_MAGIC, "embedded_ole", "critical"),
        (b"%PDF-", "embedded_pdf", "high"),
    )

    for signature, indicator, severity in signatures:
        count = data[:MAX_HASH_BYTES].count(signature)

        if count:
            evidence.append(
                ParserEvidence(
                    category="embedded_object",
                    indicator=indicator,
                    severity=severity,
                    source=filename,
                    detail=f"Embedded signature occurrence count: {count}.",
                )
            )

    statistics = ParserStatistics(
        entry_count=1,
        binary_part_count=1,
        embedded_object_count=len(
            re.findall(
                r"\\object\b",
                text,
                flags=re.IGNORECASE,
            )
        ),
        total_uncompressed_size=len(data),
        total_compressed_size=len(data),
    )

    metadata = {
        "container": "rtf",
        "object_execution": False,
        "external_resource_resolution": False,
    }

    return ParsedDocument(
        identity=identity,
        features=tuple(features),
        evidence=tuple(_deduplicate_evidence(evidence)),
        statistics=statistics,
        text_sample=_extract_rtf_text_sample(text),
        metadata=metadata,
    )


def _extract_rtf_text_sample(
    text: str,
) -> str:
    """
    Remove common RTF control words for a conservative text sample.
    """
    cleaned = re.sub(
        r"\\'[0-9a-fA-F]{2}",
        " ",
        text,
    )

    cleaned = re.sub(
        r"\\[a-zA-Z]+-?\d* ?",
        " ",
        cleaned,
    )

    cleaned = cleaned.replace(
        "{",
        " ",
    ).replace(
        "}",
        " ",
    )

    cleaned = re.sub(
        r"\s+",
        " ",
        cleaned,
    )

    return _bounded_text(
        cleaned.strip(),
        MAX_TEXT_SAMPLE,
    )


# ---------------------------------------------------------------------------
# Generic binary parser
# ---------------------------------------------------------------------------


def _parse_generic(
    data: bytes,
    filename: str,
    identity: DocumentIdentity,
) -> ParsedDocument:
    evidence: list[ParserEvidence] = []
    features: list[DocumentFeature] = []

    signature = _magic_name(data)

    if signature in {
        "PE",
        "ELF",
    }:
        evidence.append(
            ParserEvidence(
                category="executable",
                indicator="executable_signature",
                severity="critical",
                source=filename,
                detail=f"Executable signature detected: {signature}.",
            )
        )

        features.append(
            DocumentFeature(
                name="executable_signature",
                value=signature,
                severity="critical",
                source=filename,
                evidence="Input is executable content rather than a normal document.",
            )
        )

    printable = data[:MAX_TEXT_SAMPLE].decode(
        "latin-1",
        errors="ignore",
    )

    url_count = len(
        re.findall(
            r"\b(?:https?|ftp)://[^\s\"'<>]+",
            printable,
            flags=re.IGNORECASE,
        )
    )

    if url_count:
        evidence.append(
            ParserEvidence(
                category="external_resource",
                indicator="url_in_binary",
                severity="medium",
                source=filename,
                detail=f"Detected {url_count} URL-like string(s).",
            )
        )

    statistics = ParserStatistics(
        entry_count=1,
        binary_part_count=1,
        total_uncompressed_size=len(data),
        total_compressed_size=len(data),
    )

    return ParsedDocument(
        identity=identity,
        features=tuple(features),
        evidence=tuple(_deduplicate_evidence(evidence)),
        statistics=statistics,
        text_sample=_bounded_text(
            printable,
            MAX_TEXT_SAMPLE,
        ),
        metadata={
            "container": "generic",
            "signature": signature,
        },
    )


# ---------------------------------------------------------------------------
# Evidence normalization
# ---------------------------------------------------------------------------


_SEVERITY_ORDER = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def _deduplicate_evidence(
    evidence: Iterable[ParserEvidence],
) -> list[ParserEvidence]:
    seen: set[tuple[str, str, str, str]] = set()
    result: list[ParserEvidence] = []

    for item in evidence:
        key = (
            item.category,
            item.indicator,
            item.source,
            item.detail,
        )

        if key in seen:
            continue

        seen.add(key)
        result.append(item)

        if len(result) >= MAX_EVIDENCE:
            break

    result.sort(
        key=lambda item: (
            -_SEVERITY_ORDER.get(
                item.severity.lower(),
                0,
            ),
            item.category,
            item.indicator,
            item.source,
            item.detail,
        )
    )

    return result


# ---------------------------------------------------------------------------
# Feature vector
# ---------------------------------------------------------------------------


PARSER_FEATURE_NAMES = (
    "file_size",
    "is_container",
    "is_known_document",
    "entry_count",
    "xml_part_count",
    "binary_part_count",
    "macro_part_count",
    "embedded_object_count",
    "external_relationship_count",
    "hyperlink_count",
    "ole_object_count",
    "attached_template_count",
    "active_x_count",
    "custom_xml_count",
    "external_link_count",
    "suspicious_extension_count",
    "high_compression_ratio_count",
    "total_uncompressed_size",
    "total_compressed_size",
    "xml_element_count",
    "xml_text_bytes",
    "critical_evidence_count",
    "high_evidence_count",
    "medium_evidence_count",
    "low_evidence_count",
    "feature_count",
    "relationship_count",
    "part_count",
)


def extract_feature_vector(
    parsed: ParsedDocument,
) -> dict[str, float]:
    """Extract a stable scalar feature mapping from parser output."""
    statistics = parsed.statistics

    critical = sum(1 for item in parsed.evidence if item.severity.lower() == "critical")

    high = sum(1 for item in parsed.evidence if item.severity.lower() == "high")

    medium = sum(1 for item in parsed.evidence if item.severity.lower() == "medium")

    low = sum(1 for item in parsed.evidence if item.severity.lower() == "low")

    values = {
        "file_size": float(parsed.identity.size),
        "is_container": float(bool(parsed.identity.is_container)),
        "is_known_document": float(bool(parsed.identity.is_known_document)),
        "entry_count": float(statistics.entry_count),
        "xml_part_count": float(statistics.xml_part_count),
        "binary_part_count": float(statistics.binary_part_count),
        "macro_part_count": float(statistics.macro_part_count),
        "embedded_object_count": float(statistics.embedded_object_count),
        "external_relationship_count": float(statistics.external_relationship_count),
        "hyperlink_count": float(statistics.hyperlink_count),
        "ole_object_count": float(statistics.ole_object_count),
        "attached_template_count": float(statistics.attached_template_count),
        "active_x_count": float(statistics.active_x_count),
        "custom_xml_count": float(statistics.custom_xml_count),
        "external_link_count": float(statistics.external_link_count),
        "suspicious_extension_count": float(statistics.suspicious_extension_count),
        "high_compression_ratio_count": float(statistics.high_compression_ratio_count),
        "total_uncompressed_size": float(statistics.total_uncompressed_size),
        "total_compressed_size": float(statistics.total_compressed_size),
        "xml_element_count": float(statistics.xml_element_count),
        "xml_text_bytes": float(statistics.xml_text_bytes),
        "critical_evidence_count": float(critical),
        "high_evidence_count": float(high),
        "medium_evidence_count": float(medium),
        "low_evidence_count": float(low),
        "feature_count": float(len(parsed.features)),
        "relationship_count": float(len(parsed.relationships)),
        "part_count": float(len(parsed.parts)),
    }

    return {name: _safe_float(values.get(name, 0.0)) for name in PARSER_FEATURE_NAMES}


def extract_feature_vector_list(
    parsed: ParsedDocument,
) -> list[float]:
    """Return parser features in deterministic schema order."""
    mapping = extract_feature_vector(parsed)

    return [mapping[name] for name in PARSER_FEATURE_NAMES]


def feature_names() -> tuple[str, ...]:
    """Return the stable parser feature schema."""
    return PARSER_FEATURE_NAMES


# ---------------------------------------------------------------------------
# Query helpers
# ---------------------------------------------------------------------------


def has_indicator(
    parsed: ParsedDocument,
    indicator: str,
) -> bool:
    """Return whether a parser indicator is present."""
    target = _safe_text(indicator).strip().lower()

    return any(item.indicator.lower() == target for item in parsed.evidence)


def has_category(
    parsed: ParsedDocument,
    category: str,
) -> bool:
    """Return whether parser evidence contains a category."""
    target = _safe_text(category).strip().lower()

    return any(item.category.lower() == target for item in parsed.evidence)


def evidence_by_category(
    parsed: ParsedDocument,
    category: str,
) -> tuple[ParserEvidence, ...]:
    """Return evidence for one category."""
    target = _safe_text(category).strip().lower()

    return tuple(item for item in parsed.evidence if item.category.lower() == target)


def evidence_by_indicator(
    parsed: ParsedDocument,
    indicator: str,
) -> tuple[ParserEvidence, ...]:
    """Return evidence for one indicator."""
    target = _safe_text(indicator).strip().lower()

    return tuple(item for item in parsed.evidence if item.indicator.lower() == target)


def high_risk_evidence(
    parsed: ParsedDocument,
) -> tuple[ParserEvidence, ...]:
    """Return high and critical parser findings."""
    return tuple(
        item
        for item in parsed.evidence
        if item.severity.lower()
        in {
            "high",
            "critical",
        }
    )


def iter_parts(
    parsed: ParsedDocument,
) -> Iterator[PackagePart]:
    """Iterate over package parts."""
    yield from parsed.parts


def iter_relationships(
    parsed: ParsedDocument,
) -> Iterator[RelationshipRecord]:
    """Iterate over relationship records."""
    yield from parsed.relationships


def iter_embedded_objects(
    parsed: ParsedDocument,
) -> Iterator[EmbeddedObjectRecord]:
    """Iterate over embedded-object records."""
    yield from parsed.embedded_objects


def iter_evidence(
    parsed: ParsedDocument,
) -> Iterator[ParserEvidence]:
    """Iterate over parser evidence."""
    yield from parsed.evidence


# ---------------------------------------------------------------------------
# Serialization
# ---------------------------------------------------------------------------


def _json_safe(value: Any) -> Any:
    if value is None or isinstance(
        value,
        (str, int, bool),
    ):
        return value

    if isinstance(value, float):
        return value if math.isfinite(value) else None

    if isinstance(value, Path):
        return str(value)

    if is_dataclass(value):
        return _json_safe(asdict(value))

    if isinstance(value, Mapping):
        return {_safe_text(key): _json_safe(item) for key, item in value.items()}

    if isinstance(
        value,
        (list, tuple, set, frozenset),
    ):
        return [_json_safe(item) for item in value]

    return _safe_text(value)


def analysis_to_dict(
    parsed: ParsedDocument,
) -> dict[str, Any]:
    """Serialize parser output into a JSON-compatible dictionary."""
    return _json_safe(
        {
            "identity": parsed.identity,
            "parts": parsed.parts,
            "relationships": parsed.relationships,
            "embedded_objects": parsed.embedded_objects,
            "features": parsed.features,
            "evidence": parsed.evidence,
            "statistics": parsed.statistics,
            "text_sample": parsed.text_sample,
            "metadata": parsed.metadata,
            "feature_vector": extract_feature_vector(parsed),
        }
    )


def summarize(
    parsed: ParsedDocument,
) -> dict[str, Any]:
    """Return a compact operational parser summary."""
    statistics = parsed.statistics

    risk_levels = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
    }

    categories: dict[str, int] = {}

    for item in parsed.evidence:
        severity = item.severity.lower()

        if severity not in risk_levels:
            severity = "info"

        risk_levels[severity] += 1

        categories[item.category] = categories.get(item.category, 0) + 1

    return {
        "filename": parsed.identity.filename,
        "format": parsed.identity.format,
        "mime_type": parsed.identity.mime_type,
        "size": parsed.identity.size,
        "sha256": parsed.identity.sha256,
        "is_container": parsed.identity.is_container,
        "is_known_document": parsed.identity.is_known_document,
        "parts": len(parsed.parts),
        "relationships": len(parsed.relationships),
        "embedded_objects": len(parsed.embedded_objects),
        "evidence": len(parsed.evidence),
        "risk_levels": risk_levels,
        "evidence_categories": categories,
        "statistics": _json_safe(statistics),
    }


# ---------------------------------------------------------------------------
# Main parser
# ---------------------------------------------------------------------------


def parse_document(
    source: bytes | bytearray | memoryview | str | os.PathLike[str],
    *,
    filename: Optional[str] = None,
) -> ParsedDocument:
    """
    Parse a document or container statically.

    Args:
        source:
            Bytes, bytearray, memoryview, or filesystem path.
        filename:
            Optional logical filename used for format inference. When omitted
            for byte input, ``input.bin`` is used.

    Returns:
        ParsedDocument containing only static structural information.
    """
    data, detected_filename = _read_input(source)

    logical_filename = (
        _safe_text(filename).strip() if filename is not None else detected_filename
    )

    if not logical_filename:
        logical_filename = detected_filename or "input.bin"

    extension = _extension(logical_filename)

    fmt, mime_type, known_document = _format_from_extension(
        extension,
        data,
    )

    # Content signatures override obviously incorrect extensions for the
    # security-sensitive container families.
    if _looks_like_ole(data):
        fmt = (
            "ole_document"
            if extension
            in {
                ".doc",
                ".xls",
                ".ppt",
            }
            else "ole_container"
        )
        mime_type = "application/x-ole-storage"
        known_document = True

    elif _looks_like_pdf(data):
        fmt = "pdf"
        mime_type = "application/pdf"
        known_document = True

    elif _looks_like_rtf(data):
        fmt = "rtf"
        mime_type = "application/rtf"
        known_document = True

    elif _looks_like_zip(data):
        if extension in {
            ".docx",
            ".docm",
            ".dotx",
            ".dotm",
            ".xlsx",
            ".xlsm",
            ".xltx",
            ".xltm",
            ".pptx",
            ".pptm",
            ".potx",
            ".potm",
            ".ppsx",
            ".ppsm",
        }:
            known_document = True
        else:
            fmt = "zip_container"
            mime_type = "application/zip"

    identity = DocumentIdentity(
        filename=logical_filename,
        extension=extension,
        size=len(data),
        sha256=_sha256(data),
        format=fmt,
        mime_type=mime_type,
        is_container=(
            fmt
            in {
                "docx",
                "docm",
                "dotx",
                "dotm",
                "xlsx",
                "xlsm",
                "xltx",
                "xltm",
                "pptx",
                "pptm",
                "potx",
                "potm",
                "ppsx",
                "ppsm",
                "ole_document",
                "ole_container",
                "zip_container",
                "pdf",
                "rtf",
            }
        ),
        is_known_document=known_document,
    )

    if _looks_like_zip(data):
        return _parse_ooxml(
            data,
            logical_filename,
            identity,
        )

    if _looks_like_ole(data):
        return _parse_ole(
            data,
            logical_filename,
            identity,
        )

    if _looks_like_pdf(data):
        return _parse_pdf(
            data,
            logical_filename,
            identity,
        )

    if _looks_like_rtf(data):
        return _parse_rtf(
            data,
            logical_filename,
            identity,
        )

    return _parse_generic(
        data,
        logical_filename,
        identity,
    )


# ---------------------------------------------------------------------------
# Convenience aliases
# ---------------------------------------------------------------------------


def parse(
    source: bytes | bytearray | memoryview | str | os.PathLike[str],
    *,
    filename: Optional[str] = None,
) -> ParsedDocument:
    """Alias for :func:`parse_document`."""
    return parse_document(
        source,
        filename=filename,
    )


def analyze(
    source: bytes | bytearray | memoryview | str | os.PathLike[str],
    *,
    filename: Optional[str] = None,
) -> ParsedDocument:
    """Alias for :func:`parse_document` for pipeline compatibility."""
    return parse_document(
        source,
        filename=filename,
    )


def extract(
    source: bytes | bytearray | memoryview | str | os.PathLike[str],
    *,
    filename: Optional[str] = None,
) -> ParsedDocument:
    """Alias for :func:`parse_document`."""
    return parse_document(
        source,
        filename=filename,
    )


def parse_file(
    path: os.PathLike[str] | str,
) -> ParsedDocument:
    """Parse a filesystem document using its filename for format hints."""
    return parse_document(path)


# ---------------------------------------------------------------------------
# Public APIs
# ---------------------------------------------------------------------------

__all__ = [
    # Limits / schema
    "MAX_FILE_SIZE",
    "MAX_ZIP_ENTRIES",
    "MAX_ZIP_ENTRY_NAME",
    "MAX_ZIP_ENTRY_UNCOMPRESSED",
    "MAX_ZIP_TOTAL_UNCOMPRESSED",
    "MAX_XML_BYTES",
    "MAX_XML_ELEMENTS",
    "MAX_EVIDENCE",
    "PARSER_FEATURE_NAMES",
    # Exceptions
    "CDRParserError",
    "CDRInputError",
    "CDRContainerError",
    "CDRXMLLimitError",
    # Dataclasses
    "DocumentIdentity",
    "PackagePart",
    "RelationshipRecord",
    "EmbeddedObjectRecord",
    "DocumentFeature",
    "ParserEvidence",
    "ParserStatistics",
    "ParsedDocument",
    # Main parsing
    "parse_document",
    "parse_file",
    "parse",
    "analyze",
    "extract",
    # Features
    "extract_feature_vector",
    "extract_feature_vector_list",
    "feature_names",
    # Queries
    "has_indicator",
    "has_category",
    "evidence_by_category",
    "evidence_by_indicator",
    "high_risk_evidence",
    # Iterators
    "iter_parts",
    "iter_relationships",
    "iter_embedded_objects",
    "iter_evidence",
    # Serialization / reporting
    "analysis_to_dict",
    "summarize",
]


if __name__ == "__main__":
    import argparse
    import json

    parser = argparse.ArgumentParser(
        description=("Statically parse a document for the Pharos CDR pipeline.")
    )

    parser.add_argument(
        "path",
        help="Path to the document to inspect.",
    )

    parser.add_argument(
        "--summary",
        action="store_true",
        help="Print a compact summary instead of full parser output.",
    )

    args = parser.parse_args()

    try:
        result = parse_file(args.path)

        if args.summary:
            print(
                json.dumps(
                    summarize(result),
                    indent=2,
                    ensure_ascii=False,
                    sort_keys=True,
                )
            )
        else:
            print(
                json.dumps(
                    analysis_to_dict(result),
                    indent=2,
                    ensure_ascii=False,
                    sort_keys=True,
                )
            )

    except CDRParserError as exc:
        parser.error(str(exc))
