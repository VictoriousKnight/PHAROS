"""
pharos-cdr - OOXML reconstruction and package rebuilding.

This module provides the reconstruction stage of the Content Disarm and
Reconstruction (CDR) pipeline.

Security properties
-------------------
- Static analysis and reconstruction only.
- Never executes VBA, XLM, JavaScript, VBScript, PowerShell, DDE, or other
  embedded content.
- Never launches processes or loads native libraries.
- Never resolves or downloads external URLs.
- Never extracts untrusted archive members to the host filesystem.
- All archive and XML operations are bounded.
- Reconstruction is performed in memory unless the caller explicitly asks
  to save the final artifact.
- Duplicate ZIP member names are rejected.
- ZIP path traversal names are rejected.
- Encrypted ZIP entries are rejected.
- ZIP bombs are bounded by compressed/uncompressed and entry limits.
- XML references are checked against the reconstructed package.
- Output is deterministic: fixed ZIP timestamps, stable member ordering,
  and normalized ZIP metadata.

This module is intentionally focused on reconstruction. Policy decisions and
content removal belong to ``cdr.policy`` and ``cdr.sanitizer``.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import posixpath
import re
import zipfile
from dataclasses import dataclass, field, asdict
from datetime import datetime
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
    Tuple,
    Union,
)
from xml.etree import ElementTree as ET


MODULE_NAME = "pharos_cdr.reconstruction"
RECONSTRUCTION_VERSION = "1.0.0"

MAX_INPUT_BYTES = 75 * 1024 * 1024
MAX_OUTPUT_BYTES = 100 * 1024 * 1024
MAX_ZIP_ENTRIES = 10_000
MAX_ENTRY_COMPRESSED = 100 * 1024 * 1024
MAX_ENTRY_UNCOMPRESSED = 150 * 1024 * 1024
MAX_TOTAL_COMPRESSED = 100 * 1024 * 1024
MAX_TOTAL_UNCOMPRESSED = 300 * 1024 * 1024
MAX_XML_BYTES = 25 * 1024 * 1024
MAX_XML_ELEMENTS = 250_000
MAX_XML_ATTRIBUTES = 1_000_000
MAX_XML_DEPTH = 128
MAX_REFERENCES = 50_000
MAX_WARNINGS = 10_000
MAX_ACTIONS = 20_000
MAX_MEMBER_NAME = 1024
MAX_REPORT_BYTES = 20 * 1024 * 1024

OOXML_ROOT_RELS = "_rels/.rels"
OOXML_CONTENT_TYPES = "[Content_Types].xml"

PACKAGE_REL_NS = "http://schemas.openxmlformats.org/package/2006/relationships"
PACKAGE_REL_NS_STRICT = "http://purl.oclc.org/ooxml/package/relationships"
REL_ID = "Id"
REL_TYPE = "Type"
REL_TARGET = "Target"
REL_TARGET_MODE = "TargetMode"

CONTENT_TYPES_NS = "http://schemas.openxmlformats.org/package/2006/content-types"
CONTENT_TYPES_NS_STRICT = "http://purl.oclc.org/ooxml/content-types"

RELATIONSHIP_SUFFIX = ".rels"

XML_SUFFIXES = (".xml", ".rels")
XML_MEDIA_TYPES = {
    "application/xml",
    "text/xml",
    "application/vnd.openxmlformats-officedocument",
}

ACTIVE_MEMBER_MARKERS = (
    "vbaproject",
    "vbaData",
    "activeX",
    "activex",
    "embeddings/",
    "macrosheets/",
    "customui/",
    "customxml/",
    "people/",
    "webextensions/",
    "externalLinks/",
)

ACTIVE_EXTENSIONS = {
    ".vba",
    ".bin",
    ".xlam",
    ".xla",
    ".xlsb",
    ".js",
    ".jse",
    ".vbs",
    ".vbe",
    ".wsf",
    ".wsh",
    ".ps1",
    ".psm1",
    ".bat",
    ".cmd",
    ".hta",
}

DANGEROUS_RELATIONSHIP_TERMS = (
    "vbaProject",
    "oleObject",
    "package",
    "control",
    "attachedTemplate",
    "externalLink",
    "external",
    "dde",
)

RELATIONSHIP_TARGET_ESCAPE_RE = re.compile(r"(^|/)\.\.(?:/|$)")
INVALID_XML_CONTROL_RE = re.compile(
    r"[\x00-\x08\x0B\x0C\x0E-\x1F]"
)

DEFAULT_ZIP_DATE = (1980, 1, 1, 0, 0, 0)


class ReconstructionError(Exception):
    """Base exception for reconstruction failures."""


class ReconstructionInputError(ReconstructionError):
    """Raised when reconstruction input is invalid or unsafe."""


class ReconstructionArchiveError(ReconstructionError):
    """Raised when the input/output OOXML archive is malformed or unsafe."""


class ReconstructionValidationError(ReconstructionError):
    """Raised when the reconstructed package fails validation."""


class ReconstructionOutputError(ReconstructionError):
    """Raised when the reconstructed artifact cannot be produced safely."""


class ReconstructionSeverity(str, Enum):
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class ReconstructionStatus(str, Enum):
    RECONSTRUCTED = "reconstructed"
    VALIDATED = "validated"
    REJECTED = "rejected"
    FAILED = "failed"


class ReferenceKind(str, Enum):
    RELATIONSHIP = "relationship"
    XML_PART = "xml_part"
    CONTENT_TYPE = "content_type"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class ReconstructionWarning:
    code: str
    message: str
    severity: ReconstructionSeverity = ReconstructionSeverity.WARNING
    member: Optional[str] = None
    detail: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "code": self.code,
            "message": self.message,
            "severity": self.severity.value,
            "member": self.member,
            "detail": self.detail,
        }


@dataclass(frozen=True)
class ReconstructionAction:
    action: str
    member: str
    original_size: int
    resulting_size: int
    reason: str
    changed: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class PackageReference:
    source: str
    target: str
    resolved_target: Optional[str]
    relationship_id: Optional[str]
    relationship_type: Optional[str]
    target_mode: Optional[str]
    kind: ReferenceKind
    valid: bool
    external: bool = False
    reason: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        result["kind"] = self.kind.value
        return result


@dataclass(frozen=True)
class PackageStatistics:
    member_count: int
    xml_member_count: int
    relationship_count: int
    external_relationship_count: int
    total_compressed_size: int
    total_uncompressed_size: int
    reconstructed_size: int
    sha256: str
    active_markers: int
    orphan_relationship_parts: int
    dangling_relationships: int
    malformed_xml_parts: int

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ReconstructionPolicy:
    """
    Reconstruction-specific safety policy.

    This policy does not decide whether content should be sanitized. It
    controls how aggressively the reconstruction stage validates the package.
    """

    reject_duplicate_members: bool = True
    reject_path_traversal: bool = True
    reject_encrypted_entries: bool = True
    reject_malformed_xml: bool = True
    reject_dangling_relationships: bool = False
    reject_orphan_relationship_parts: bool = False
    reject_external_relationships: bool = False
    reject_active_markers: bool = True
    reject_invalid_xml_controls: bool = True
    normalize_xml: bool = False
    preserve_unknown_members: bool = True
    preserve_member_permissions: bool = False
    validate_content_types: bool = True
    validate_relationships: bool = True
    deterministic_zip: bool = True
    compression_level: int = 6

    def normalized(self) -> "ReconstructionPolicy":
        level = int(self.compression_level)
        if level < 0:
            level = 0
        if level > 9:
            level = 9

        return ReconstructionPolicy(
            reject_duplicate_members=bool(self.reject_duplicate_members),
            reject_path_traversal=bool(self.reject_path_traversal),
            reject_encrypted_entries=bool(self.reject_encrypted_entries),
            reject_malformed_xml=bool(self.reject_malformed_xml),
            reject_dangling_relationships=bool(self.reject_dangling_relationships),
            reject_orphan_relationship_parts=bool(
                self.reject_orphan_relationship_parts
            ),
            reject_external_relationships=bool(
                self.reject_external_relationships
            ),
            reject_active_markers=bool(self.reject_active_markers),
            reject_invalid_xml_controls=bool(
                self.reject_invalid_xml_controls
            ),
            normalize_xml=bool(self.normalize_xml),
            preserve_unknown_members=bool(self.preserve_unknown_members),
            preserve_member_permissions=bool(self.preserve_member_permissions),
            validate_content_types=bool(self.validate_content_types),
            validate_relationships=bool(self.validate_relationships),
            deterministic_zip=bool(self.deterministic_zip),
            compression_level=level,
        )


@dataclass
class ReconstructionResult:
    status: ReconstructionStatus
    success: bool
    input_size: int
    output_size: int
    input_sha256: str
    output_sha256: str
    changed: bool
    members_before: int
    members_after: int
    removed_members: List[str] = field(default_factory=list)
    rewritten_members: List[str] = field(default_factory=list)
    actions: List[ReconstructionAction] = field(default_factory=list)
    warnings: List[ReconstructionWarning] = field(default_factory=list)
    references: List[PackageReference] = field(default_factory=list)
    statistics: Optional[PackageStatistics] = None
    policy: Dict[str, Any] = field(default_factory=dict)
    validation: Dict[str, Any] = field(default_factory=dict)

    @property
    def rejected(self) -> bool:
        return self.status == ReconstructionStatus.REJECTED

    @property
    def validated(self) -> bool:
        return self.status == ReconstructionStatus.VALIDATED

    @property
    def warning_count(self) -> int:
        return len(self.warnings)

    @property
    def error_count(self) -> int:
        return sum(
            1
            for warning in self.warnings
            if warning.severity in {
                ReconstructionSeverity.ERROR,
                ReconstructionSeverity.CRITICAL,
            }
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "module": MODULE_NAME,
            "version": RECONSTRUCTION_VERSION,
            "status": self.status.value,
            "success": self.success,
            "input_size": self.input_size,
            "output_size": self.output_size,
            "input_sha256": self.input_sha256,
            "output_sha256": self.output_sha256,
            "changed": self.changed,
            "members_before": self.members_before,
            "members_after": self.members_after,
            "removed_members": list(self.removed_members),
            "rewritten_members": list(self.rewritten_members),
            "actions": [item.to_dict() for item in self.actions],
            "warnings": [item.to_dict() for item in self.warnings],
            "references": [item.to_dict() for item in self.references],
            "statistics": (
                self.statistics.to_dict() if self.statistics else None
            ),
            "policy": dict(self.policy),
            "validation": dict(self.validation),
        }

    def to_json(self, *, indent: Optional[int] = 2) -> str:
        return json.dumps(
            self.to_dict(),
            indent=indent,
            sort_keys=True,
            ensure_ascii=False,
        )


@dataclass
class _PackageMember:
    name: str
    data: bytes
    compress_type: int
    compress_size: int
    original_size: int
    is_xml: bool
    is_relationship: bool
    external_attr: int = 0
    flag_bits: int = 0


@dataclass
class _ValidationState:
    references: List[PackageReference] = field(default_factory=list)
    warnings: List[ReconstructionWarning] = field(default_factory=list)
    malformed_xml_parts: int = 0
    dangling_relationships: int = 0
    orphan_relationship_parts: int = 0
    external_relationships: int = 0
    active_markers: int = 0


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _safe_text(value: Any, limit: int = 8192) -> str:
    if value is None:
        return ""
    try:
        text = str(value)
    except Exception:
        return ""
    return text[:limit]


def _coerce_bytes(value: Any) -> bytes:
    if isinstance(value, bytes):
        return value

    if isinstance(value, bytearray):
        return bytes(value)

    if isinstance(value, memoryview):
        return value.tobytes()

    if isinstance(value, os.PathLike):
        path = Path(value)
        try:
            size = path.stat().st_size
        except OSError as exc:
            raise ReconstructionInputError(
                f"Unable to inspect input path: {exc}"
            ) from exc

        if size > MAX_INPUT_BYTES:
            raise ReconstructionInputError(
                f"Input exceeds MAX_INPUT_BYTES ({MAX_INPUT_BYTES})."
            )

        try:
            return path.read_bytes()
        except OSError as exc:
            raise ReconstructionInputError(
                f"Unable to read input path: {exc}"
            ) from exc

    if isinstance(value, str):
        path = Path(value)
        if path.exists() and path.is_file():
            return _coerce_bytes(path)

        raise ReconstructionInputError(
            "String input is not accepted as raw document content. "
            "Provide bytes or an existing file path."
        )

    raise ReconstructionInputError(
        f"Unsupported reconstruction input type: {type(value).__name__}"
    )


def _is_xml_member(name: str) -> bool:
    lowered = name.lower()
    return lowered.endswith(".xml") or lowered.endswith(".rels")


def _is_relationship_member(name: str) -> bool:
    return name.lower().endswith("/_rels/.rels") or name.lower() == "_rels/.rels"


def _normalize_member_name(name: str) -> str:
    value = _safe_text(name, MAX_MEMBER_NAME).replace("\\", "/")

    while value.startswith("./"):
        value = value[2:]

    value = value.lstrip("/")

    if not value:
        raise ReconstructionArchiveError("ZIP member has an empty name.")

    if "\x00" in value:
        raise ReconstructionArchiveError(
            "ZIP member name contains a NUL byte."
        )

    if len(value) > MAX_MEMBER_NAME:
        raise ReconstructionArchiveError(
            f"ZIP member name exceeds {MAX_MEMBER_NAME} characters."
        )

    parts = []
    for part in value.split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            raise ReconstructionArchiveError(
                f"ZIP member path traversal detected: {name!r}"
            )
        parts.append(part)

    normalized = "/".join(parts)

    if not normalized:
        raise ReconstructionArchiveError(
            f"ZIP member normalized to an empty path: {name!r}"
        )

    if RELATIONSHIP_SUFFIX in normalized:
        pass

    return normalized


def _contains_active_marker(name: str) -> bool:
    lowered = name.lower()

    if any(marker.lower() in lowered for marker in ACTIVE_MEMBER_MARKERS):
        return True

    suffix = Path(lowered).suffix
    return suffix in ACTIVE_EXTENSIONS


def _contains_invalid_xml_controls(data: bytes) -> bool:
    if not data:
        return False

    if b"\x00" in data:
        return True

    try:
        text = data.decode("utf-8", errors="ignore")
    except Exception:
        return False

    return INVALID_XML_CONTROL_RE.search(text) is not None


def _xml_namespace(tag: str) -> Tuple[str, str]:
    if not tag.startswith("{"):
        return "", tag

    closing = tag.find("}")
    if closing <= 0:
        return "", tag

    return tag[1:closing], tag[closing + 1 :]


def _count_xml_tree(
    root: ET.Element,
) -> Tuple[int, int, int]:
    elements = 0
    attributes = 0
    maximum_depth = 0

    stack: List[Tuple[ET.Element, int]] = [(root, 1)]

    while stack:
        element, depth = stack.pop()
        elements += 1
        attributes += len(element.attrib)
        maximum_depth = max(maximum_depth, depth)

        if elements > MAX_XML_ELEMENTS:
            raise ReconstructionArchiveError(
                f"XML element limit exceeded ({MAX_XML_ELEMENTS})."
            )

        if attributes > MAX_XML_ATTRIBUTES:
            raise ReconstructionArchiveError(
                f"XML attribute limit exceeded ({MAX_XML_ATTRIBUTES})."
            )

        if depth > MAX_XML_DEPTH:
            raise ReconstructionArchiveError(
                f"XML depth limit exceeded ({MAX_XML_DEPTH})."
            )

        children = list(element)
        for child in reversed(children):
            stack.append((child, depth + 1))

    return elements, attributes, maximum_depth


def _parse_xml(data: bytes, member: str) -> ET.Element:
    if len(data) > MAX_XML_BYTES:
        raise ReconstructionArchiveError(
            f"XML member exceeds MAX_XML_BYTES: {member}"
        )

    if _contains_invalid_xml_controls(data):
        raise ReconstructionArchiveError(
            f"XML member contains invalid XML control characters: {member}"
        )

    try:
        root = ET.fromstring(data)
    except ET.ParseError as exc:
        raise ReconstructionArchiveError(
            f"Malformed XML in {member}: {exc}"
        ) from exc

    _count_xml_tree(root)
    return root


def _serialize_xml(root: ET.Element) -> bytes:
    ET.register_namespace(
        "",
        "http://schemas.openxmlformats.org/package/2006/content-types",
    )

    buffer = io.BytesIO()
    tree = ET.ElementTree(root)

    try:
        tree.write(
            buffer,
            encoding="utf-8",
            xml_declaration=True,
            short_empty_elements=True,
        )
    except (TypeError, ValueError) as exc:
        raise ReconstructionOutputError(
            f"Unable to serialize XML: {exc}"
        ) from exc

    return buffer.getvalue()


def _is_external_relationship(
    target_mode: Optional[str],
    target: Optional[str],
) -> bool:
    if target_mode and target_mode.lower() == "external":
        return True

    if not target:
        return False

    lowered = target.lower()

    return (
        "://" in lowered
        or lowered.startswith(("mailto:", "file:", "ms-", "data:"))
    )


def _relationship_source_from_member(member: str) -> Optional[str]:
    """
    Convert a .rels member to the package part it describes.

    Examples:
      _rels/.rels
        -> /
      word/_rels/document.xml.rels
        -> word/document.xml
      xl/worksheets/_rels/sheet1.xml.rels
        -> xl/worksheets/sheet1.xml
    """
    normalized = _normalize_member_name(member)

    if normalized == "_rels/.rels":
        return "/"

    marker = "/_rels/"
    if marker not in normalized:
        return None

    base, rel_name = normalized.rsplit(marker, 1)

    if not rel_name.endswith(".rels"):
        return None

    source_name = rel_name[:-5]

    if base:
        return f"{base}/{source_name}"

    return source_name


def _resolve_relationship_target(
    source: str,
    target: str,
) -> Tuple[Optional[str], Optional[str]]:
    if not target:
        return None, "empty relationship target"

    target = target.replace("\\", "/")

    if target.startswith("/"):
        resolved = posixpath.normpath(target.lstrip("/"))
    else:
        if source == "/":
            base = ""
        else:
            base = posixpath.dirname(source)

        resolved = posixpath.normpath(
            posixpath.join(base, target)
        )

    if resolved == ".":
        return None, "relationship target resolves to package root"

    if resolved.startswith("../") or resolved == "..":
        return None, "relationship target escapes package root"

    if RELATIONSHIP_TARGET_ESCAPE_RE.search(resolved):
        return None, "relationship target contains traversal"

    return resolved, None


def _read_zip_members(data: bytes) -> Dict[str, _PackageMember]:
    if len(data) > MAX_INPUT_BYTES:
        raise ReconstructionInputError(
            f"Input exceeds MAX_INPUT_BYTES ({MAX_INPUT_BYTES})."
        )

    if not data.startswith(b"PK"):
        raise ReconstructionArchiveError(
            "Input is not a ZIP-based OOXML package."
        )

    members: Dict[str, _PackageMember] = {}
    total_compressed = 0
    total_uncompressed = 0

    try:
        archive = zipfile.ZipFile(io.BytesIO(data), "r")
    except (zipfile.BadZipFile, OSError) as exc:
        raise ReconstructionArchiveError(
            f"Unable to open OOXML ZIP package: {exc}"
        ) from exc

    try:
        infos = archive.infolist()

        if len(infos) > MAX_ZIP_ENTRIES:
            raise ReconstructionArchiveError(
                f"ZIP entry count exceeds MAX_ZIP_ENTRIES ({MAX_ZIP_ENTRIES})."
            )

        for info in infos:
            normalized = _normalize_member_name(info.filename)

            if normalized in members:
                raise ReconstructionArchiveError(
                    f"Duplicate ZIP member detected: {normalized}"
                )

            if info.is_dir():
                continue

            if info.file_size > MAX_ENTRY_UNCOMPRESSED:
                raise ReconstructionArchiveError(
                    f"ZIP member exceeds uncompressed size limit: "
                    f"{normalized}"
                )

            if info.compress_size > MAX_ENTRY_COMPRESSED:
                raise ReconstructionArchiveError(
                    f"ZIP member exceeds compressed size limit: "
                    f"{normalized}"
                )

            total_compressed += max(0, int(info.compress_size))
            total_uncompressed += max(0, int(info.file_size))

            if total_compressed > MAX_TOTAL_COMPRESSED:
                raise ReconstructionArchiveError(
                    "ZIP compressed-size aggregate limit exceeded."
                )

            if total_uncompressed > MAX_TOTAL_UNCOMPRESSED:
                raise ReconstructionArchiveError(
                    "ZIP uncompressed-size aggregate limit exceeded."
                )

            if info.flag_bits & 0x1:
                raise ReconstructionArchiveError(
                    f"Encrypted ZIP member is not accepted: {normalized}"
                )

            try:
                content = archive.read(info)
            except (RuntimeError, ValueError, zipfile.BadZipFile) as exc:
                raise ReconstructionArchiveError(
                    f"Unable to read ZIP member {normalized}: {exc}"
                ) from exc

            if len(content) != info.file_size:
                raise ReconstructionArchiveError(
                    f"ZIP member size mismatch: {normalized}"
                )

            members[normalized] = _PackageMember(
                name=normalized,
                data=content,
                compress_type=info.compress_type,
                compress_size=info.compress_size,
                original_size=info.file_size,
                is_xml=_is_xml_member(normalized),
                is_relationship=_is_relationship_member(normalized),
                external_attr=info.external_attr,
                flag_bits=info.flag_bits,
            )
    finally:
        archive.close()

    return members


def _remove_xml_children_by_local_name(
    root: ET.Element,
    local_names: Sequence[str],
) -> int:
    wanted = {item.lower() for item in local_names}
    removed = 0

    for parent in root.iter():
        children = list(parent)

        for child in children:
            _, local = _xml_namespace(child.tag)

            if local.lower() in wanted:
                parent.remove(child)
                removed += 1

    return removed


def _remove_dangling_relationships(
    members: MutableMapping[str, _PackageMember],
    state: _ValidationState,
    policy: ReconstructionPolicy,
) -> None:
    """
    Remove relationships whose targets no longer exist.

    This is intentionally conservative: only internal relationships are
    candidates for automatic removal. External relationships are handled
    according to policy.
    """
    rel_members = [
        name
        for name, member in members.items()
        if member.is_relationship
    ]

    for rel_member in sorted(rel_members):
        member = members.get(rel_member)
        if member is None:
            continue

        try:
            root = _parse_xml(member.data, rel_member)
        except ReconstructionArchiveError:
            continue

        source = _relationship_source_from_member(rel_member)
        if source is None:
            continue

        changed = False

        for relationship in list(root):
            _, local = _xml_namespace(relationship.tag)
            if local != "Relationship":
                continue

            target = relationship.attrib.get(REL_TARGET, "")
            target_mode = relationship.attrib.get(REL_TARGET_MODE)
            relationship_id = relationship.attrib.get(REL_ID)
            relationship_type = relationship.attrib.get(REL_TYPE)

            external = _is_external_relationship(
                target_mode,
                target,
            )

            if external:
                state.external_relationships += 1

                state.references.append(
                    PackageReference(
                        source=source,
                        target=target,
                        resolved_target=None,
                        relationship_id=relationship_id,
                        relationship_type=relationship_type,
                        target_mode=target_mode,
                        kind=ReferenceKind.RELATIONSHIP,
                        valid=not policy.reject_external_relationships,
                        external=True,
                        reason=(
                            "external relationship"
                            if policy.reject_external_relationships
                            else None
                        ),
                    )
                )

                if policy.reject_external_relationships:
                    raise ReconstructionValidationError(
                        f"External relationship remains in {rel_member}: "
                        f"{target}"
                    )

                continue

            resolved, reason = _resolve_relationship_target(
                source,
                target,
            )

            if resolved is None:
                state.dangling_relationships += 1

                state.references.append(
                    PackageReference(
                        source=source,
                        target=target,
                        resolved_target=None,
                        relationship_id=relationship_id,
                        relationship_type=relationship_type,
                        target_mode=target_mode,
                        kind=ReferenceKind.RELATIONSHIP,
                        valid=False,
                        external=False,
                        reason=reason,
                    )
                )

                if policy.reject_dangling_relationships:
                    raise ReconstructionValidationError(
                        f"Invalid relationship target in {rel_member}: "
                        f"{target!r} ({reason})"
                    )

                root.remove(relationship)
                changed = True
                continue

            valid = resolved in members

            state.references.append(
                PackageReference(
                    source=source,
                    target=target,
                    resolved_target=resolved,
                    relationship_id=relationship_id,
                    relationship_type=relationship_type,
                    target_mode=target_mode,
                    kind=ReferenceKind.RELATIONSHIP,
                    valid=valid,
                    external=False,
                    reason=None if valid else "target member missing",
                )
            )

            if not valid:
                state.dangling_relationships += 1

                if policy.reject_dangling_relationships:
                    raise ReconstructionValidationError(
                        f"Dangling relationship in {rel_member}: "
                        f"{target!r} -> {resolved!r}"
                    )

                root.remove(relationship)
                changed = True

        if changed:
            new_data = _serialize_xml(root)

            members[rel_member] = _PackageMember(
                name=member.name,
                data=new_data,
                compress_type=member.compress_type,
                compress_size=len(new_data),
                original_size=member.original_size,
                is_xml=True,
                is_relationship=True,
                external_attr=member.external_attr,
                flag_bits=member.flag_bits,
            )


def _find_orphan_relationship_parts(
    members: Mapping[str, _PackageMember],
) -> List[str]:
    orphans: List[str] = []

    for name, member in members.items():
        if not member.is_relationship:
            continue

        source = _relationship_source_from_member(name)

        if source is None:
            continue

        if source == "/":
            continue

        if source not in members:
            orphans.append(name)

    return sorted(orphans)


def _validate_content_types(
    members: Mapping[str, _PackageMember],
    state: _ValidationState,
    policy: ReconstructionPolicy,
) -> None:
    member = members.get(OOXML_CONTENT_TYPES)

    if member is None:
        state.warnings.append(
            ReconstructionWarning(
                code="missing_content_types",
                message="OOXML package is missing [Content_Types].xml.",
                severity=ReconstructionSeverity.ERROR,
                member=OOXML_CONTENT_TYPES,
            )
        )

        if policy.validate_content_types:
            raise ReconstructionValidationError(
                "OOXML package is missing [Content_Types].xml."
            )

        return

    try:
        root = _parse_xml(member.data, OOXML_CONTENT_TYPES)
    except ReconstructionArchiveError as exc:
        state.malformed_xml_parts += 1

        state.warnings.append(
            ReconstructionWarning(
                code="malformed_content_types",
                message=str(exc),
                severity=ReconstructionSeverity.ERROR,
                member=OOXML_CONTENT_TYPES,
            )
        )

        if policy.reject_malformed_xml:
            raise ReconstructionValidationError(str(exc)) from exc

        return

    overrides: Dict[str, str] = {}
    defaults: Dict[str, str] = {}

    for child in root:
        _, local = _xml_namespace(child.tag)

        if local == "Override":
            part_name = child.attrib.get("PartName", "")
            content_type = child.attrib.get("ContentType", "")
            if part_name:
                overrides[part_name.lstrip("/")] = content_type

        elif local == "Default":
            extension = child.attrib.get("Extension", "").lower()
            content_type = child.attrib.get("ContentType", "")
            if extension:
                defaults[extension] = content_type

    for member_name in members:
        if member_name == OOXML_CONTENT_TYPES:
            continue

        if member_name.startswith("_rels/"):
            continue

        part_name = member_name.lstrip("/")

        if part_name in overrides:
            continue

        suffix = Path(part_name).suffix.lower().lstrip(".")

        if suffix in defaults:
            continue

        # OOXML permits content types to be supplied through overrides.
        # A missing mapping is therefore suspicious but not universally
        # invalid because nonstandard packages may carry custom content.
        state.warnings.append(
            ReconstructionWarning(
                code="missing_content_type_mapping",
                message=(
                    "Package member has no explicit or default content-type "
                    f"mapping: {member_name}"
                ),
                severity=ReconstructionSeverity.WARNING,
                member=member_name,
            )
        )


def _validate_xml_members(
    members: Mapping[str, _PackageMember],
    state: _ValidationState,
    policy: ReconstructionPolicy,
) -> None:
    for name in sorted(members):
        member = members[name]

        if not member.is_xml:
            continue

        try:
            root = _parse_xml(member.data, name)
        except ReconstructionArchiveError as exc:
            state.malformed_xml_parts += 1

            severity = (
                ReconstructionSeverity.ERROR
                if policy.reject_malformed_xml
                else ReconstructionSeverity.WARNING
            )

            state.warnings.append(
                ReconstructionWarning(
                    code="malformed_xml",
                    message=str(exc),
                    severity=severity,
                    member=name,
                )
            )

            if policy.reject_malformed_xml:
                raise ReconstructionValidationError(str(exc)) from exc

            continue

        if policy.reject_invalid_xml_controls:
            if _contains_invalid_xml_controls(member.data):
                raise ReconstructionValidationError(
                    f"Invalid XML control characters remain in {name}."
                )

        # Parse and walk once to enforce resource bounds.
        _count_xml_tree(root)


def _validate_active_markers(
    members: Mapping[str, _PackageMember],
    state: _ValidationState,
    policy: ReconstructionPolicy,
) -> None:
    for name in sorted(members):
        if not _contains_active_marker(name):
            continue

        state.active_markers += 1

        state.warnings.append(
            ReconstructionWarning(
                code="active_content_marker",
                message=(
                    "Potentially active-content package member remains after "
                    f"reconstruction: {name}"
                ),
                severity=(
                    ReconstructionSeverity.ERROR
                    if policy.reject_active_markers
                    else ReconstructionSeverity.WARNING
                ),
                member=name,
            )
        )

        if policy.reject_active_markers:
            raise ReconstructionValidationError(
                f"Potentially active-content member remains: {name}"
            )


def _validate_relationships(
    members: MutableMapping[str, _PackageMember],
    state: _ValidationState,
    policy: ReconstructionPolicy,
) -> None:
    if not policy.validate_relationships:
        return

    root_relationships = members.get(OOXML_ROOT_RELS)

    if root_relationships is None:
        state.warnings.append(
            ReconstructionWarning(
                code="missing_root_relationships",
                message="OOXML package is missing root relationships.",
                severity=ReconstructionSeverity.WARNING,
                member=OOXML_ROOT_RELS,
            )
        )

    _remove_dangling_relationships(
        members,
        state,
        policy,
    )

    orphans = _find_orphan_relationship_parts(members)

    for orphan in orphans:
        state.orphan_relationship_parts += 1

        state.warnings.append(
            ReconstructionWarning(
                code="orphan_relationship_part",
                message=(
                    f"Relationship part has no corresponding source part: "
                    f"{orphan}"
                ),
                severity=(
                    ReconstructionSeverity.ERROR
                    if policy.reject_orphan_relationship_parts
                    else ReconstructionSeverity.WARNING
                ),
                member=orphan,
            )
        )

    if policy.reject_orphan_relationship_parts and orphans:
        raise ReconstructionValidationError(
            "Orphan relationship parts remain: "
            + ", ".join(orphans[:20])
        )


def _normalize_xml_members(
    members: MutableMapping[str, _PackageMember],
) -> List[str]:
    rewritten: List[str] = []

    for name in sorted(list(members)):
        member = members[name]

        if not member.is_xml:
            continue

        try:
            root = _parse_xml(member.data, name)
        except ReconstructionArchiveError:
            continue

        normalized = _serialize_xml(root)

        if normalized != member.data:
            members[name] = _PackageMember(
                name=member.name,
                data=normalized,
                compress_type=member.compress_type,
                compress_size=len(normalized),
                original_size=member.original_size,
                is_xml=True,
                is_relationship=member.is_relationship,
                external_attr=member.external_attr,
                flag_bits=member.flag_bits,
            )
            rewritten.append(name)

    return rewritten


def _zipinfo_for_member(
    member: _PackageMember,
    policy: ReconstructionPolicy,
) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(
        filename=member.name,
        date_time=DEFAULT_ZIP_DATE,
    )

    info.compress_type = (
        zipfile.ZIP_DEFLATED
        if policy.compression_level >= 0
        else zipfile.ZIP_STORED
    )

    info.flag_bits = 0

    if policy.preserve_member_permissions:
        info.external_attr = member.external_attr
    else:
        info.external_attr = 0

    info.create_system = 0
    info.create_version = 20
    info.extract_version = 20

    return info


def _build_zip(
    members: Mapping[str, _PackageMember],
    policy: ReconstructionPolicy,
) -> bytes:
    ordered_names = sorted(members)

    if len(ordered_names) > MAX_ZIP_ENTRIES:
        raise ReconstructionOutputError(
            f"Output member count exceeds MAX_ZIP_ENTRIES ({MAX_ZIP_ENTRIES})."
        )

    output = io.BytesIO()

    try:
        with zipfile.ZipFile(
            output,
            mode="w",
            compression=zipfile.ZIP_DEFLATED,
            compresslevel=policy.compression_level,
            allowZip64=True,
        ) as archive:
            for name in ordered_names:
                member = members[name]

                if len(member.data) > MAX_ENTRY_UNCOMPRESSED:
                    raise ReconstructionOutputError(
                        f"Output member exceeds size limit: {name}"
                    )

                info = _zipinfo_for_member(member, policy)

                archive.writestr(
                    info,
                    member.data,
                )
    except (OSError, ValueError, RuntimeError, zipfile.BadZipFile) as exc:
        raise ReconstructionOutputError(
            f"Unable to construct reconstructed OOXML package: {exc}"
        ) from exc

    result = output.getvalue()

    if len(result) > MAX_OUTPUT_BYTES:
        raise ReconstructionOutputError(
            f"Reconstructed output exceeds MAX_OUTPUT_BYTES "
            f"({MAX_OUTPUT_BYTES})."
        )

    return result


def _package_statistics(
    members: Mapping[str, _PackageMember],
    output: bytes,
    state: _ValidationState,
) -> PackageStatistics:
    compressed = sum(
        max(0, member.compress_size)
        for member in members.values()
    )

    uncompressed = sum(
        len(member.data)
        for member in members.values()
    )

    relationship_count = sum(
        1
        for member in members.values()
        if member.is_relationship
    )

    xml_count = sum(
        1
        for member in members.values()
        if member.is_xml
    )

    return PackageStatistics(
        member_count=len(members),
        xml_member_count=xml_count,
        relationship_count=relationship_count,
        external_relationship_count=state.external_relationships,
        total_compressed_size=compressed,
        total_uncompressed_size=uncompressed,
        reconstructed_size=len(output),
        sha256=_sha256(output),
        active_markers=state.active_markers,
        orphan_relationship_parts=state.orphan_relationship_parts,
        dangling_relationships=state.dangling_relationships,
        malformed_xml_parts=state.malformed_xml_parts,
    )


def _policy_to_dict(policy: ReconstructionPolicy) -> Dict[str, Any]:
    return {
        key: getattr(policy, key)
        for key in (
            "reject_duplicate_members",
            "reject_path_traversal",
            "reject_encrypted_entries",
            "reject_malformed_xml",
            "reject_dangling_relationships",
            "reject_orphan_relationship_parts",
            "reject_external_relationships",
            "reject_active_markers",
            "reject_invalid_xml_controls",
            "normalize_xml",
            "preserve_unknown_members",
            "preserve_member_permissions",
            "validate_content_types",
            "validate_relationships",
            "deterministic_zip",
            "compression_level",
        )
    }


def reconstruct_document(
    source: Union[bytes, bytearray, memoryview, os.PathLike, str],
    *,
    policy: Optional[ReconstructionPolicy] = None,
) -> Tuple[bytes, ReconstructionResult]:
    """
    Reconstruct an OOXML package entirely in memory.

    The input should normally be the output of ``cdr.sanitizer``. This
    function does not itself perform broad content sanitization; instead it
    validates the package, repairs safe internal references where possible,
    optionally normalizes XML, and deterministically rebuilds the ZIP.
    """
    effective_policy = (
        policy.normalized()
        if policy is not None
        else ReconstructionPolicy().normalized()
    )

    input_data = _coerce_bytes(source)

    if len(input_data) > MAX_INPUT_BYTES:
        raise ReconstructionInputError(
            f"Input exceeds MAX_INPUT_BYTES ({MAX_INPUT_BYTES})."
        )

    input_hash = _sha256(input_data)

    members = _read_zip_members(input_data)
    members_before = len(members)

    state = _ValidationState()

    if effective_policy.reject_active_markers:
        _validate_active_markers(
            members,
            state,
            effective_policy,
        )

    _validate_xml_members(
        members,
        state,
        effective_policy,
    )

    if effective_policy.validate_content_types:
        _validate_content_types(
            members,
            state,
            effective_policy,
        )

    _validate_relationships(
        members,
        state,
        effective_policy,
    )

    rewritten_members: List[str] = []

    if effective_policy.normalize_xml:
        rewritten_members = _normalize_xml_members(members)

    # Relationship cleanup can produce rewritten .rels members, so validate
    # the final relationship graph after all structural modifications.
    final_state = _ValidationState()
    _validate_relationships(
        members,
        final_state,
        effective_policy,
    )

    state.references.extend(final_state.references)
    state.warnings.extend(final_state.warnings)
    state.dangling_relationships = max(
        state.dangling_relationships,
        final_state.dangling_relationships,
    )
    state.orphan_relationship_parts = max(
        state.orphan_relationship_parts,
        final_state.orphan_relationship_parts,
    )
    state.external_relationships = max(
        state.external_relationships,
        final_state.external_relationships,
    )

    if len(state.warnings) > MAX_WARNINGS:
        state.warnings = state.warnings[:MAX_WARNINGS]

    if len(state.references) > MAX_REFERENCES:
        state.references = state.references[:MAX_REFERENCES]

    output = _build_zip(
        members,
        effective_policy,
    )

    output_hash = _sha256(output)

    changed = input_data != output

    actions: List[ReconstructionAction] = []

    for name in rewritten_members:
        member = members.get(name)
        if member is None:
            continue

        actions.append(
            ReconstructionAction(
                action="rewrite",
                member=name,
                original_size=member.original_size,
                resulting_size=len(member.data),
                reason="xml_normalization",
                changed=True,
            )
        )

    if len(actions) > MAX_ACTIONS:
        actions = actions[:MAX_ACTIONS]

    statistics = _package_statistics(
        members,
        output,
        state,
    )

    validation = {
        "valid_zip": True,
        "valid_xml": state.malformed_xml_parts == 0,
        "dangling_relationships": state.dangling_relationships,
        "orphan_relationship_parts": state.orphan_relationship_parts,
        "external_relationships": state.external_relationships,
        "active_markers": state.active_markers,
        "member_count": len(members),
        "sha256": output_hash,
    }

    result = ReconstructionResult(
        status=(
            ReconstructionStatus.RECONSTRUCTED
            if changed
            else ReconstructionStatus.VALIDATED
        ),
        success=True,
        input_size=len(input_data),
        output_size=len(output),
        input_sha256=input_hash,
        output_sha256=output_hash,
        changed=changed,
        members_before=members_before,
        members_after=len(members),
        removed_members=[],
        rewritten_members=rewritten_members,
        actions=actions,
        warnings=state.warnings,
        references=state.references,
        statistics=statistics,
        policy=_policy_to_dict(effective_policy),
        validation=validation,
    )

    return output, result


def reconstruct(
    source: Union[bytes, bytearray, memoryview, os.PathLike, str],
    *,
    policy: Optional[ReconstructionPolicy] = None,
) -> bytes:
    """
    Convenience API returning only the reconstructed document bytes.
    """
    output, _ = reconstruct_document(
        source,
        policy=policy,
    )
    return output


def reconstruct_content(
    source: Union[bytes, bytearray, memoryview],
    *,
    policy: Optional[ReconstructionPolicy] = None,
) -> bytes:
    """Reconstruct in-memory document content."""
    return reconstruct(
        source,
        policy=policy,
    )


def reconstruct_file(
    source_path: Union[str, os.PathLike],
    output_path: Union[str, os.PathLike],
    *,
    policy: Optional[ReconstructionPolicy] = None,
    overwrite: bool = False,
) -> ReconstructionResult:
    """
    Reconstruct an OOXML file and explicitly save the resulting artifact.

    File output occurs only because the caller explicitly requested it.
    """
    source = Path(source_path)
    destination = Path(output_path)

    if destination.exists() and not overwrite:
        raise ReconstructionOutputError(
            f"Output already exists: {destination}"
        )

    output, result = reconstruct_document(
        source,
        policy=policy,
    )

    if len(output) > MAX_OUTPUT_BYTES:
        raise ReconstructionOutputError(
            f"Output exceeds MAX_OUTPUT_BYTES ({MAX_OUTPUT_BYTES})."
        )

    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(output)
    except OSError as exc:
        raise ReconstructionOutputError(
            f"Unable to save reconstructed file: {exc}"
        ) from exc

    return result


def validate_reconstructed_document(
    source: Union[bytes, bytearray, memoryview, os.PathLike, str],
    *,
    policy: Optional[ReconstructionPolicy] = None,
) -> ReconstructionResult:
    """
    Validate a package by reconstructing it without XML normalization.

    The returned artifact is discarded. This is useful for checking whether
    an already-sanitized document is safe and structurally coherent.
    """
    effective_policy = (
        policy.normalized()
        if policy is not None
        else ReconstructionPolicy().normalized()
    )

    effective_policy = ReconstructionPolicy(
        **{
            **_policy_to_dict(effective_policy),
            "normalize_xml": False,
        }
    )

    _, result = reconstruct_document(
        source,
        policy=effective_policy,
    )

    if not result.success:
        result.status = ReconstructionStatus.REJECTED

    return result


def is_reconstructed_valid(
    source: Union[bytes, bytearray, memoryview, os.PathLike, str],
    *,
    policy: Optional[ReconstructionPolicy] = None,
) -> bool:
    """Return True when reconstruction/validation succeeds."""
    try:
        result = validate_reconstructed_document(
            source,
            policy=policy,
        )
    except ReconstructionError:
        return False

    return result.success and result.error_count == 0


def extract_package_members(
    source: Union[bytes, bytearray, memoryview, os.PathLike, str],
) -> List[str]:
    """
    Return normalized package member names without extracting them to disk.
    """
    data = _coerce_bytes(source)
    members = _read_zip_members(data)
    return sorted(members)


def read_package_member(
    source: Union[bytes, bytearray, memoryview, os.PathLike, str],
    member_name: str,
) -> bytes:
    """
    Read one package member into memory.

    This API never writes the member to the host filesystem.
    """
    data = _coerce_bytes(source)
    members = _read_zip_members(data)
    normalized = _normalize_member_name(member_name)

    member = members.get(normalized)

    if member is None:
        raise ReconstructionInputError(
            f"Package member not found: {normalized}"
        )

    return bytes(member.data)


def package_sha256(
    source: Union[bytes, bytearray, memoryview, os.PathLike, str],
) -> str:
    """Return SHA-256 of the supplied package bytes."""
    return _sha256(_coerce_bytes(source))


def reconstruction_fingerprint(
    result: ReconstructionResult,
) -> str:
    """
    Produce a stable fingerprint of reconstruction metadata.

    The fingerprint deliberately includes the output digest and policy, making
    it suitable for audit/report correlation.
    """
    payload = {
        "module": MODULE_NAME,
        "version": RECONSTRUCTION_VERSION,
        "output_sha256": result.output_sha256,
        "changed": result.changed,
        "members_after": result.members_after,
        "removed_members": sorted(result.removed_members),
        "rewritten_members": sorted(result.rewritten_members),
        "policy": result.policy,
    }

    serialized = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")

    return _sha256(serialized)


def reconstruction_to_dict(
    result: ReconstructionResult,
) -> Dict[str, Any]:
    """Serialize a reconstruction result to a dictionary."""
    return result.to_dict()


def reconstruction_to_json(
    result: ReconstructionResult,
    *,
    indent: Optional[int] = 2,
) -> str:
    """Serialize a reconstruction result to JSON."""
    return result.to_json(indent=indent)


def save_reconstruction_report(
    result: ReconstructionResult,
    output_path: Union[str, os.PathLike],
    *,
    indent: int = 2,
    overwrite: bool = False,
) -> Path:
    """Explicitly save a reconstruction report as JSON."""
    destination = Path(output_path)

    if destination.exists() and not overwrite:
        raise ReconstructionOutputError(
            f"Report already exists: {destination}"
        )

    content = reconstruction_to_json(
        result,
        indent=indent,
    ).encode("utf-8")

    if len(content) > MAX_REPORT_BYTES:
        raise ReconstructionOutputError(
            "Reconstruction report exceeds MAX_REPORT_BYTES."
        )

    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(content)
    except OSError as exc:
        raise ReconstructionOutputError(
            f"Unable to save reconstruction report: {exc}"
        ) from exc

    return destination


def save_reconstructed_content(
    content: bytes,
    output_path: Union[str, os.PathLike],
    *,
    overwrite: bool = False,
) -> Path:
    """
    Explicitly save already-reconstructed bytes.

    This function does not perform additional reconstruction or sanitization.
    """
    if not isinstance(content, bytes):
        raise ReconstructionOutputError(
            "Reconstructed content must be bytes."
        )

    if len(content) > MAX_OUTPUT_BYTES:
        raise ReconstructionOutputError(
            f"Content exceeds MAX_OUTPUT_BYTES ({MAX_OUTPUT_BYTES})."
        )

    destination = Path(output_path)

    if destination.exists() and not overwrite:
        raise ReconstructionOutputError(
            f"Output already exists: {destination}"
        )

    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(content)
    except OSError as exc:
        raise ReconstructionOutputError(
            f"Unable to save reconstructed content: {exc}"
        ) from exc

    return destination


def default_policy() -> ReconstructionPolicy:
    """Return the default balanced reconstruction policy."""
    return ReconstructionPolicy().normalized()


def strict_policy() -> ReconstructionPolicy:
    """Return a strict reconstruction policy."""
    return ReconstructionPolicy(
        reject_duplicate_members=True,
        reject_path_traversal=True,
        reject_encrypted_entries=True,
        reject_malformed_xml=True,
        reject_dangling_relationships=True,
        reject_orphan_relationship_parts=True,
        reject_external_relationships=True,
        reject_active_markers=True,
        reject_invalid_xml_controls=True,
        normalize_xml=True,
        preserve_unknown_members=True,
        preserve_member_permissions=False,
        validate_content_types=True,
        validate_relationships=True,
        deterministic_zip=True,
        compression_level=9,
    ).normalized()


def permissive_policy() -> ReconstructionPolicy:
    """Return a permissive policy for compatibility-oriented validation."""
    return ReconstructionPolicy(
        reject_duplicate_members=True,
        reject_path_traversal=True,
        reject_encrypted_entries=True,
        reject_malformed_xml=False,
        reject_dangling_relationships=False,
        reject_orphan_relationship_parts=False,
        reject_external_relationships=False,
        reject_active_markers=False,
        reject_invalid_xml_controls=True,
        normalize_xml=False,
        preserve_unknown_members=True,
        preserve_member_permissions=False,
        validate_content_types=False,
        validate_relationships=True,
        deterministic_zip=True,
        compression_level=6,
    ).normalized()


def summarize_reconstruction(
    result: ReconstructionResult,
) -> Dict[str, Any]:
    """Return a compact audit-oriented reconstruction summary."""
    statistics = result.statistics

    return {
        "status": result.status.value,
        "success": result.success,
        "changed": result.changed,
        "input_size": result.input_size,
        "output_size": result.output_size,
        "input_sha256": result.input_sha256,
        "output_sha256": result.output_sha256,
        "members_before": result.members_before,
        "members_after": result.members_after,
        "removed_count": len(result.removed_members),
        "rewritten_count": len(result.rewritten_members),
        "warning_count": result.warning_count,
        "error_count": result.error_count,
        "dangling_relationships": (
            statistics.dangling_relationships
            if statistics
            else 0
        ),
        "orphan_relationship_parts": (
            statistics.orphan_relationship_parts
            if statistics
            else 0
        ),
        "external_relationships": (
            statistics.external_relationship_count
            if statistics
            else 0
        ),
        "active_markers": (
            statistics.active_markers
            if statistics
            else 0
        ),
        "malformed_xml_parts": (
            statistics.malformed_xml_parts
            if statistics
            else 0
        ),
        "fingerprint": reconstruction_fingerprint(result),
    }


def iter_warnings(
    result: ReconstructionResult,
) -> Iterator[ReconstructionWarning]:
    """Iterate reconstruction warnings deterministically."""
    yield from result.warnings


def iter_errors(
    result: ReconstructionResult,
) -> Iterator[ReconstructionWarning]:
    """Iterate only error/critical reconstruction warnings."""
    for warning in result.warnings:
        if warning.severity in {
            ReconstructionSeverity.ERROR,
            ReconstructionSeverity.CRITICAL,
        }:
            yield warning


def iter_references(
    result: ReconstructionResult,
) -> Iterator[PackageReference]:
    """Iterate package references recorded during validation."""
    yield from result.references


def iter_actions(
    result: ReconstructionResult,
) -> Iterator[ReconstructionAction]:
    """Iterate reconstruction actions."""
    yield from result.actions


def count_external_references(
    result: ReconstructionResult,
) -> int:
    """Count external package references observed during validation."""
    return sum(
        1
        for reference in result.references
        if reference.external
    )


def count_dangling_references(
    result: ReconstructionResult,
) -> int:
    """Count invalid/dangling internal package references."""
    return sum(
        1
        for reference in result.references
        if not reference.valid and not reference.external
    )


def has_errors(
    result: ReconstructionResult,
) -> bool:
    """Return True when the reconstruction result contains errors."""
    return result.error_count > 0


def has_external_references(
    result: ReconstructionResult,
) -> bool:
    """Return True when external references were observed."""
    return count_external_references(result) > 0


def has_dangling_references(
    result: ReconstructionResult,
) -> bool:
    """Return True when dangling/invalid internal references were observed."""
    return count_dangling_references(result) > 0


def analyze_reconstruction(
    source: Union[bytes, bytearray, memoryview, os.PathLike, str],
    *,
    policy: Optional[ReconstructionPolicy] = None,
) -> ReconstructionResult:
    """
    Analyze and reconstruct an OOXML package, returning the complete result.
    """
    _, result = reconstruct_document(
        source,
        policy=policy,
    )
    return result


def rebuild(
    source: Union[bytes, bytearray, memoryview, os.PathLike, str],
    *,
    policy: Optional[ReconstructionPolicy] = None,
) -> bytes:
    """Alias for ``reconstruct``."""
    return reconstruct(
        source,
        policy=policy,
    )


def validate(
    source: Union[bytes, bytearray, memoryview, os.PathLike, str],
    *,
    policy: Optional[ReconstructionPolicy] = None,
) -> ReconstructionResult:
    """Alias for ``validate_reconstructed_document``."""
    return validate_reconstructed_document(
        source,
        policy=policy,
    )


# ---------------------------------------------------------------------------
# PUBLIC APIs
# ---------------------------------------------------------------------------

__all__ = [
    "MODULE_NAME",
    "RECONSTRUCTION_VERSION",
    "MAX_INPUT_BYTES",
    "MAX_OUTPUT_BYTES",
    "MAX_ZIP_ENTRIES",
    "MAX_ENTRY_COMPRESSED",
    "MAX_ENTRY_UNCOMPRESSED",
    "MAX_TOTAL_COMPRESSED",
    "MAX_TOTAL_UNCOMPRESSED",
    "MAX_XML_BYTES",
    "MAX_XML_ELEMENTS",
    "MAX_XML_ATTRIBUTES",
    "MAX_XML_DEPTH",
    "MAX_REFERENCES",
    "MAX_WARNINGS",
    "MAX_ACTIONS",
    "MAX_MEMBER_NAME",
    "MAX_REPORT_BYTES",
    "ReconstructionError",
    "ReconstructionInputError",
    "ReconstructionArchiveError",
    "ReconstructionValidationError",
    "ReconstructionOutputError",
    "ReconstructionSeverity",
    "ReconstructionStatus",
    "ReferenceKind",
    "ReconstructionWarning",
    "ReconstructionAction",
    "PackageReference",
    "PackageStatistics",
    "ReconstructionPolicy",
    "ReconstructionResult",
    "reconstruct_document",
    "reconstruct",
    "reconstruct_content",
    "reconstruct_file",
    "analyze_reconstruction",
    "rebuild",
    "validate_reconstructed_document",
    "is_reconstructed_valid",
    "validate",
    "extract_package_members",
    "read_package_member",
    "package_sha256",
    "reconstruction_to_dict",
    "reconstruction_to_json",
    "reconstruction_fingerprint",
    "save_reconstruction_report",
    "save_reconstructed_content",
    "default_policy",
    "strict_policy",
    "permissive_policy",
    "summarize_reconstruction",
    "iter_warnings",
    "iter_errors",
    "iter_references",
    "iter_actions",
    "count_external_references",
    "count_dangling_references",
    "has_errors",
    "has_external_references",
    "has_dangling_references",
]