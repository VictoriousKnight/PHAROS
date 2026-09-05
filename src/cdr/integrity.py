"""
pharos-cdr - OOXML package integrity verification.

This module provides the final integrity-verification stage of the CDR
pipeline. It is designed to run after sanitization and reconstruction.

Security model
--------------
- Static-only analysis.
- Never executes macros, scripts, embedded executables, or DDE.
- Never launches processes.
- Never loads DLLs/native libraries.
- Never resolves, contacts, or downloads URLs.
- Never extracts package members to the host filesystem.
- Reads ZIP members only into bounded memory.
- Rejects duplicate member names and path traversal.
- Rejects encrypted ZIP members.
- Enforces per-member and aggregate archive limits.
- Parses XML with bounded tree/attribute/depth limits.
- Verifies internal OOXML relationship targets without accessing the network.
- Produces deterministic hashes and audit-friendly findings.

The module intentionally does not decide whether a document is malicious.
It answers whether the resulting package is structurally coherent and whether
security-relevant active-content remnants remain.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import posixpath
import re
import zipfile
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import (
    Any,
    Dict,
    Iterator,
    List,
    Mapping,
    Optional,
    Sequence,
    Tuple,
    Union,
)
from xml.etree import ElementTree as ET


MODULE_NAME = "pharos_cdr.integrity"
INTEGRITY_VERSION = "1.0.0"

MAX_INPUT_BYTES = 100 * 1024 * 1024
MAX_ZIP_ENTRIES = 10_000
MAX_MEMBER_NAME = 1_024
MAX_ENTRY_COMPRESSED = 100 * 1024 * 1024
MAX_ENTRY_UNCOMPRESSED = 150 * 1024 * 1024
MAX_TOTAL_COMPRESSED = 100 * 1024 * 1024
MAX_TOTAL_UNCOMPRESSED = 300 * 1024 * 1024

MAX_XML_BYTES = 25 * 1024 * 1024
MAX_XML_ELEMENTS = 250_000
MAX_XML_ATTRIBUTES = 1_000_000
MAX_XML_DEPTH = 128

MAX_FINDINGS = 20_000
MAX_REFERENCES = 50_000
MAX_MEMBER_RECORDS = 20_000
MAX_REPORT_BYTES = 20 * 1024 * 1024

OOXML_CONTENT_TYPES = "[Content_Types].xml"
OOXML_ROOT_RELS = "_rels/.rels"

REL_ID = "Id"
REL_TYPE = "Type"
REL_TARGET = "Target"
REL_TARGET_MODE = "TargetMode"

RELATIONSHIP_SUFFIX = ".rels"

PACKAGE_REL_NAMESPACES = {
    "http://schemas.openxmlformats.org/package/2006/relationships",
    "http://purl.oclc.org/ooxml/package/relationships",
}

CONTENT_TYPE_NAMESPACES = {
    "http://schemas.openxmlformats.org/package/2006/content-types",
    "http://purl.oclc.org/ooxml/content-types",
}

ACTIVE_MEMBER_MARKERS = (
    "vbaproject",
    "vbadata",
    "activex/",
    "activex",
    "embeddings/",
    "macrosheets/",
    "customui/",
    "webextensions/",
    "externalLinks/",
    "customxml/",
)

ACTIVE_EXTENSIONS = {
    ".vba",
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
    ".xlam",
    ".xla",
    ".xlsb",
}

ACTIVE_CONTENT_TYPE_TERMS = (
    "macroenabled",
    "vba",
    "activex",
    "oleobject",
    "package",
)

DANGEROUS_RELATIONSHIP_TERMS = (
    "vbaproject",
    "oleobject",
    "package",
    "control",
    "attachedtemplate",
    "externallink",
    "external",
    "dde",
)

INVALID_XML_CONTROL_RE = re.compile(
    r"[\x00-\x08\x0B\x0C\x0E-\x1F]"
)

RELATIONSHIP_ESCAPE_RE = re.compile(
    r"(^|/)\.\.(?:/|$)"
)


class IntegrityError(Exception):
    """Base integrity-verification error."""


class IntegrityInputError(IntegrityError):
    """Raised when verification input is invalid."""


class IntegrityArchiveError(IntegrityError):
    """Raised when an archive violates structural safety constraints."""


class IntegrityXMLException(IntegrityError):
    """Raised when XML cannot be safely parsed."""


class IntegrityVerificationError(IntegrityError):
    """Raised when strict verification fails."""


class IntegritySeverity(str, Enum):
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class IntegrityStatus(str, Enum):
    VALID = "valid"
    VALID_WITH_WARNINGS = "valid_with_warnings"
    INVALID = "invalid"
    REJECTED = "rejected"


class IntegrityFindingCode(str, Enum):
    INPUT_TOO_LARGE = "input_too_large"
    NOT_ZIP = "not_zip"
    BAD_ZIP = "bad_zip"
    TOO_MANY_ENTRIES = "too_many_entries"
    DUPLICATE_MEMBER = "duplicate_member"
    PATH_TRAVERSAL = "path_traversal"
    INVALID_MEMBER_NAME = "invalid_member_name"
    ENCRYPTED_MEMBER = "encrypted_member"
    MEMBER_TOO_LARGE = "member_too_large"
    ARCHIVE_TOO_LARGE = "archive_too_large"
    MEMBER_READ_ERROR = "member_read_error"
    SIZE_MISMATCH = "size_mismatch"
    MISSING_CONTENT_TYPES = "missing_content_types"
    MALFORMED_XML = "malformed_xml"
    XML_LIMIT_EXCEEDED = "xml_limit_exceeded"
    INVALID_XML_CONTROL = "invalid_xml_control"
    MISSING_CONTENT_TYPE = "missing_content_type"
    CONTENT_TYPE_TARGET_MISSING = "content_type_target_missing"
    ORPHAN_OVERRIDE = "orphan_content_type_override"
    MISSING_ROOT_RELATIONSHIPS = "missing_root_relationships"
    MALFORMED_RELATIONSHIPS = "malformed_relationships"
    INVALID_RELATIONSHIP_TARGET = "invalid_relationship_target"
    DANGLING_RELATIONSHIP = "dangling_relationship"
    EXTERNAL_RELATIONSHIP = "external_relationship"
    DUPLICATE_RELATIONSHIP_ID = "duplicate_relationship_id"
    ACTIVE_MEMBER = "active_member"
    ACTIVE_CONTENT_TYPE = "active_content_type"
    DANGEROUS_RELATIONSHIP = "dangerous_relationship"
    ORPHAN_RELATIONSHIP_PART = "orphan_relationship_part"
    HASH_MISMATCH = "hash_mismatch"
    OUTPUT_TOO_LARGE = "output_too_large"


@dataclass(frozen=True)
class IntegrityFinding:
    code: IntegrityFindingCode
    severity: IntegritySeverity
    message: str
    member: Optional[str] = None
    detail: Optional[str] = None
    expected: Optional[str] = None
    observed: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        result["code"] = self.code.value
        result["severity"] = self.severity.value
        return result


@dataclass(frozen=True)
class IntegrityReference:
    source: str
    target: str
    resolved_target: Optional[str]
    relationship_id: Optional[str]
    relationship_type: Optional[str]
    target_mode: Optional[str]
    external: bool
    valid: bool
    dangerous: bool
    reason: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class IntegrityMember:
    name: str
    compressed_size: int
    uncompressed_size: int
    crc32: int
    compression_method: int
    is_xml: bool
    is_relationship: bool
    active_marker: bool
    sha256: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class IntegrityStatistics:
    member_count: int
    xml_member_count: int
    relationship_member_count: int
    active_member_count: int
    active_content_type_count: int
    dangerous_relationship_count: int
    external_relationship_count: int
    dangling_relationship_count: int
    orphan_relationship_part_count: int
    malformed_xml_count: int
    total_compressed_size: int
    total_uncompressed_size: int
    package_size: int
    sha256: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class IntegrityPolicy:
    """
    Verification policy.

    ``reject_*`` controls whether the corresponding condition causes the
    document to be considered invalid. Conditions can still be recorded as
    warnings when rejection is disabled.
    """

    reject_duplicate_members: bool = True
    reject_path_traversal: bool = True
    reject_encrypted_members: bool = True
    reject_oversized_members: bool = True
    reject_malformed_xml: bool = True
    reject_invalid_xml_controls: bool = True
    reject_missing_content_types: bool = True
    reject_missing_content_type_mapping: bool = False
    reject_dangling_relationships: bool = True
    reject_orphan_relationship_parts: bool = True
    reject_external_relationships: bool = True
    reject_dangerous_relationships: bool = True
    reject_active_members: bool = True
    reject_active_content_types: bool = True
    require_root_relationships: bool = False
    require_relationship_targets: bool = True
    verify_member_crc: bool = True
    verify_content_type_targets: bool = True
    verify_relationships: bool = True
    verify_xml: bool = True

    def normalized(self) -> "IntegrityPolicy":
        return IntegrityPolicy(
            reject_duplicate_members=bool(self.reject_duplicate_members),
            reject_path_traversal=bool(self.reject_path_traversal),
            reject_encrypted_members=bool(self.reject_encrypted_members),
            reject_oversized_members=bool(self.reject_oversized_members),
            reject_malformed_xml=bool(self.reject_malformed_xml),
            reject_invalid_xml_controls=bool(
                self.reject_invalid_xml_controls
            ),
            reject_missing_content_types=bool(
                self.reject_missing_content_types
            ),
            reject_missing_content_type_mapping=bool(
                self.reject_missing_content_type_mapping
            ),
            reject_dangling_relationships=bool(
                self.reject_dangling_relationships
            ),
            reject_orphan_relationship_parts=bool(
                self.reject_orphan_relationship_parts
            ),
            reject_external_relationships=bool(
                self.reject_external_relationships
            ),
            reject_dangerous_relationships=bool(
                self.reject_dangerous_relationships
            ),
            reject_active_members=bool(self.reject_active_members),
            reject_active_content_types=bool(
                self.reject_active_content_types
            ),
            require_root_relationships=bool(
                self.require_root_relationships
            ),
            require_relationship_targets=bool(
                self.require_relationship_targets
            ),
            verify_member_crc=bool(self.verify_member_crc),
            verify_content_type_targets=bool(
                self.verify_content_type_targets
            ),
            verify_relationships=bool(self.verify_relationships),
            verify_xml=bool(self.verify_xml),
        )


@dataclass
class IntegrityResult:
    status: IntegrityStatus
    valid: bool
    input_size: int
    sha256: str
    findings: List[IntegrityFinding] = field(default_factory=list)
    references: List[IntegrityReference] = field(default_factory=list)
    members: List[IntegrityMember] = field(default_factory=list)
    statistics: Optional[IntegrityStatistics] = None
    policy: Dict[str, Any] = field(default_factory=dict)
    expected_sha256: Optional[str] = None
    fingerprint: Optional[str] = None

    @property
    def warning_count(self) -> int:
        return sum(
            1
            for finding in self.findings
            if finding.severity == IntegritySeverity.WARNING
        )

    @property
    def error_count(self) -> int:
        return sum(
            1
            for finding in self.findings
            if finding.severity in {
                IntegritySeverity.ERROR,
                IntegritySeverity.CRITICAL,
            }
        )

    @property
    def critical_count(self) -> int:
        return sum(
            1
            for finding in self.findings
            if finding.severity == IntegritySeverity.CRITICAL
        )

    @property
    def active_content_count(self) -> int:
        return sum(
            1
            for member in self.members
            if member.active_marker
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "module": MODULE_NAME,
            "version": INTEGRITY_VERSION,
            "status": self.status.value,
            "valid": self.valid,
            "input_size": self.input_size,
            "sha256": self.sha256,
            "expected_sha256": self.expected_sha256,
            "findings": [
                finding.to_dict()
                for finding in self.findings
            ],
            "references": [
                reference.to_dict()
                for reference in self.references
            ],
            "members": [
                member.to_dict()
                for member in self.members
            ],
            "statistics": (
                self.statistics.to_dict()
                if self.statistics is not None
                else None
            ),
            "policy": dict(self.policy),
            "fingerprint": self.fingerprint,
        }

    def to_json(self, *, indent: Optional[int] = 2) -> str:
        return json.dumps(
            self.to_dict(),
            indent=indent,
            sort_keys=True,
            ensure_ascii=False,
        )


@dataclass
class _PackageEntry:
    name: str
    data: bytes
    compressed_size: int
    uncompressed_size: int
    crc32: int
    compression_method: int
    is_xml: bool
    is_relationship: bool
    active_marker: bool


@dataclass
class _IntegrityState:
    findings: List[IntegrityFinding] = field(default_factory=list)
    references: List[IntegrityReference] = field(default_factory=list)
    members: List[IntegrityMember] = field(default_factory=list)
    xml_roots: Dict[str, ET.Element] = field(default_factory=dict)
    content_types: Dict[str, str] = field(default_factory=dict)
    defaults: Dict[str, str] = field(default_factory=dict)


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


def _coerce_bytes(
    source: Union[
        bytes,
        bytearray,
        memoryview,
        os.PathLike,
        str,
    ],
) -> bytes:
    if isinstance(source, bytes):
        return source

    if isinstance(source, bytearray):
        return bytes(source)

    if isinstance(source, memoryview):
        return source.tobytes()

    if isinstance(source, os.PathLike):
        path = Path(source)

        try:
            size = path.stat().st_size
        except OSError as exc:
            raise IntegrityInputError(
                f"Unable to inspect input file: {exc}"
            ) from exc

        if size > MAX_INPUT_BYTES:
            raise IntegrityInputError(
                f"Input exceeds MAX_INPUT_BYTES ({MAX_INPUT_BYTES})."
            )

        try:
            return path.read_bytes()
        except OSError as exc:
            raise IntegrityInputError(
                f"Unable to read input file: {exc}"
            ) from exc

    if isinstance(source, str):
        path = Path(source)

        if not path.exists() or not path.is_file():
            raise IntegrityInputError(
                "String input must identify an existing regular file."
            )

        return _coerce_bytes(path)

    raise IntegrityInputError(
        f"Unsupported input type: {type(source).__name__}"
    )


def _normalize_member_name(name: str) -> str:
    value = _safe_text(name, MAX_MEMBER_NAME)
    value = value.replace("\\", "/")

    if not value:
        raise IntegrityArchiveError("ZIP member has an empty name.")

    if "\x00" in value:
        raise IntegrityArchiveError(
            "ZIP member contains a NUL byte."
        )

    if len(value) > MAX_MEMBER_NAME:
        raise IntegrityArchiveError(
            f"ZIP member name exceeds {MAX_MEMBER_NAME} characters."
        )

    if value.startswith("/"):
        raise IntegrityArchiveError(
            f"Absolute ZIP member path is not permitted: {name!r}"
        )

    normalized_parts: List[str] = []

    for part in value.split("/"):
        if part in ("", "."):
            continue

        if part == "..":
            raise IntegrityArchiveError(
                f"ZIP path traversal detected: {name!r}"
            )

        normalized_parts.append(part)

    normalized = "/".join(normalized_parts)

    if not normalized:
        raise IntegrityArchiveError(
            f"ZIP member normalizes to an empty path: {name!r}"
        )

    return normalized


def _is_xml_member(name: str) -> bool:
    lowered = name.lower()
    return lowered.endswith(".xml") or lowered.endswith(".rels")


def _is_relationship_member(name: str) -> bool:
    lowered = name.lower()

    return (
        lowered == "_rels/.rels"
        or lowered.endswith("/_rels/.rels")
    )


def _contains_active_marker(name: str) -> bool:
    lowered = name.lower()

    if any(
        marker.lower() in lowered
        for marker in ACTIVE_MEMBER_MARKERS
    ):
        return True

    return Path(lowered).suffix in ACTIVE_EXTENSIONS


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


def _xml_local_name(tag: str) -> str:
    if not tag:
        return ""

    if tag.startswith("{"):
        closing = tag.find("}")
        if closing >= 0:
            return tag[closing + 1 :]

    return tag


def _parse_xml(
    data: bytes,
    member: str,
) -> ET.Element:
    if len(data) > MAX_XML_BYTES:
        raise IntegrityXMLException(
            f"XML member exceeds MAX_XML_BYTES: {member}"
        )

    if _contains_invalid_xml_controls(data):
        raise IntegrityXMLException(
            f"XML member contains invalid control characters: {member}"
        )

    try:
        root = ET.fromstring(data)
    except ET.ParseError as exc:
        raise IntegrityXMLException(
            f"Malformed XML in {member}: {exc}"
        ) from exc

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
            raise IntegrityXMLException(
                f"XML element limit exceeded in {member}."
            )

        if attributes > MAX_XML_ATTRIBUTES:
            raise IntegrityXMLException(
                f"XML attribute limit exceeded in {member}."
            )

        if depth > MAX_XML_DEPTH:
            raise IntegrityXMLException(
                f"XML nesting depth exceeded in {member}."
            )

        children = list(element)

        for child in reversed(children):
            stack.append((child, depth + 1))

    return root


def _relationship_source(member: str) -> Optional[str]:
    normalized = _normalize_member_name(member)

    if normalized == "_rels/.rels":
        return "/"

    marker = "/_rels/"

    if marker not in normalized:
        return None

    base, rel_name = normalized.rsplit(marker, 1)

    if not rel_name.endswith(".rels"):
        return None

    source_part = rel_name[:-5]

    if base:
        return f"{base}/{source_part}"

    return source_part


def _is_external_target(
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
        or lowered.startswith(
            (
                "mailto:",
                "file:",
                "ms-",
                "data:",
                "javascript:",
            )
        )
    )


def _resolve_target(
    source: str,
    target: str,
) -> Tuple[Optional[str], Optional[str]]:
    if not target:
        return None, "empty target"

    target = target.replace("\\", "/")

    if target.startswith("/"):
        resolved = posixpath.normpath(
            target.lstrip("/")
        )
    else:
        base = "" if source == "/" else posixpath.dirname(source)
        resolved = posixpath.normpath(
            posixpath.join(base, target)
        )

    if resolved in ("", "."):
        return None, "target resolves to package root"

    if resolved == ".." or resolved.startswith("../"):
        return None, "target escapes package root"

    if RELATIONSHIP_ESCAPE_RE.search(resolved):
        return None, "target contains traversal"

    return resolved, None


def _relationship_is_dangerous(
    relationship_type: Optional[str],
) -> bool:
    if not relationship_type:
        return False

    lowered = relationship_type.lower()

    return any(
        term in lowered
        for term in DANGEROUS_RELATIONSHIP_TERMS
    )


def _add_finding(
    state: _IntegrityState,
    finding: IntegrityFinding,
) -> None:
    if len(state.findings) >= MAX_FINDINGS:
        return

    state.findings.append(finding)


def _read_package(
    data: bytes,
    policy: IntegrityPolicy,
    state: _IntegrityState,
) -> Dict[str, _PackageEntry]:
    if len(data) > MAX_INPUT_BYTES:
        _add_finding(
            state,
            IntegrityFinding(
                code=IntegrityFindingCode.INPUT_TOO_LARGE,
                severity=IntegritySeverity.CRITICAL,
                message="Input package exceeds the maximum allowed size.",
                expected=str(MAX_INPUT_BYTES),
                observed=str(len(data)),
            ),
        )
        raise IntegrityArchiveError(
            "Input exceeds MAX_INPUT_BYTES."
        )

    if not data.startswith(b"PK"):
        _add_finding(
            state,
            IntegrityFinding(
                code=IntegrityFindingCode.NOT_ZIP,
                severity=IntegritySeverity.CRITICAL,
                message="Input is not a ZIP-based OOXML package.",
            ),
        )
        raise IntegrityArchiveError(
            "Input is not a ZIP package."
        )

    entries: Dict[str, _PackageEntry] = {}

    try:
        archive = zipfile.ZipFile(
            io.BytesIO(data),
            mode="r",
        )
    except zipfile.BadZipFile as exc:
        _add_finding(
            state,
            IntegrityFinding(
                code=IntegrityFindingCode.BAD_ZIP,
                severity=IntegritySeverity.CRITICAL,
                message="Input is not a valid ZIP archive.",
                detail=str(exc),
            ),
        )
        raise IntegrityArchiveError(
            "Invalid ZIP archive."
        ) from exc

    try:
        infos = archive.infolist()

        if len(infos) > MAX_ZIP_ENTRIES:
            _add_finding(
                state,
                IntegrityFinding(
                    code=IntegrityFindingCode.TOO_MANY_ENTRIES,
                    severity=IntegritySeverity.CRITICAL,
                    message="ZIP entry count exceeds the allowed limit.",
                    expected=str(MAX_ZIP_ENTRIES),
                    observed=str(len(infos)),
                ),
            )
            raise IntegrityArchiveError(
                "Too many ZIP entries."
            )

        total_compressed = 0
        total_uncompressed = 0

        for info in infos:
            try:
                name = _normalize_member_name(info.filename)
            except IntegrityArchiveError as exc:
                _add_finding(
                    state,
                    IntegrityFinding(
                        code=IntegrityFindingCode.PATH_TRAVERSAL,
                        severity=IntegritySeverity.CRITICAL,
                        message=str(exc),
                        member=_safe_text(info.filename),
                    ),
                )

                if policy.reject_path_traversal:
                    raise

                continue

            if name in entries:
                _add_finding(
                    state,
                    IntegrityFinding(
                        code=IntegrityFindingCode.DUPLICATE_MEMBER,
                        severity=IntegritySeverity.CRITICAL,
                        message="Duplicate ZIP member name detected.",
                        member=name,
                    ),
                )

                if policy.reject_duplicate_members:
                    raise IntegrityArchiveError(
                        f"Duplicate ZIP member: {name}"
                    )

                continue

            if info.is_dir():
                continue

            if info.flag_bits & 0x1:
                _add_finding(
                    state,
                    IntegrityFinding(
                        code=IntegrityFindingCode.ENCRYPTED_MEMBER,
                        severity=IntegritySeverity.CRITICAL,
                        message="Encrypted ZIP members are not accepted.",
                        member=name,
                    ),
                )

                if policy.reject_encrypted_members:
                    raise IntegrityArchiveError(
                        f"Encrypted ZIP member: {name}"
                    )

            if (
                info.file_size > MAX_ENTRY_UNCOMPRESSED
                or info.compress_size > MAX_ENTRY_COMPRESSED
            ):
                _add_finding(
                    state,
                    IntegrityFinding(
                        code=IntegrityFindingCode.MEMBER_TOO_LARGE,
                        severity=IntegritySeverity.CRITICAL,
                        message="ZIP member exceeds the configured size limit.",
                        member=name,
                        expected=(
                            f"uncompressed<={MAX_ENTRY_UNCOMPRESSED},"
                            f"compressed<={MAX_ENTRY_COMPRESSED}"
                        ),
                        observed=(
                            f"uncompressed={info.file_size},"
                            f"compressed={info.compress_size}"
                        ),
                    ),
                )

                if policy.reject_oversized_members:
                    raise IntegrityArchiveError(
                        f"Oversized ZIP member: {name}"
                    )

            total_compressed += max(
                0,
                int(info.compress_size),
            )
            total_uncompressed += max(
                0,
                int(info.file_size),
            )

            if (
                total_compressed > MAX_TOTAL_COMPRESSED
                or total_uncompressed > MAX_TOTAL_UNCOMPRESSED
            ):
                _add_finding(
                    state,
                    IntegrityFinding(
                        code=IntegrityFindingCode.ARCHIVE_TOO_LARGE,
                        severity=IntegritySeverity.CRITICAL,
                        message="Aggregate ZIP size limits were exceeded.",
                        expected=(
                            f"compressed<={MAX_TOTAL_COMPRESSED},"
                            f"uncompressed<={MAX_TOTAL_UNCOMPRESSED}"
                        ),
                        observed=(
                            f"compressed={total_compressed},"
                            f"uncompressed={total_uncompressed}"
                        ),
                    ),
                )
                raise IntegrityArchiveError(
                    "Aggregate ZIP size limit exceeded."
                )

            try:
                content = archive.read(info)
            except Exception as exc:
                _add_finding(
                    state,
                    IntegrityFinding(
                        code=IntegrityFindingCode.MEMBER_READ_ERROR,
                        severity=IntegritySeverity.CRITICAL,
                        message="Unable to read ZIP member.",
                        member=name,
                        detail=str(exc),
                    ),
                )
                raise IntegrityArchiveError(
                    f"Unable to read member: {name}"
                ) from exc

            if len(content) != info.file_size:
                _add_finding(
                    state,
                    IntegrityFinding(
                        code=IntegrityFindingCode.SIZE_MISMATCH,
                        severity=IntegritySeverity.CRITICAL,
                        message="ZIP member size does not match its directory entry.",
                        member=name,
                        expected=str(info.file_size),
                        observed=str(len(content)),
                    ),
                )
                raise IntegrityArchiveError(
                    f"ZIP member size mismatch: {name}"
                )

            if policy.verify_member_crc:
                observed_crc = zipfile.crc32(content) & 0xFFFFFFFF

                if observed_crc != info.CRC:
                    _add_finding(
                        state,
                        IntegrityFinding(
                            code=IntegrityFindingCode.SIZE_MISMATCH,
                            severity=IntegritySeverity.CRITICAL,
                            message="ZIP member CRC mismatch.",
                            member=name,
                            expected=f"{info.CRC:08x}",
                            observed=f"{observed_crc:08x}",
                        ),
                    )
                    raise IntegrityArchiveError(
                        f"CRC mismatch: {name}"
                    )

            is_xml = _is_xml_member(name)
            is_relationship = _is_relationship_member(name)
            active_marker = _contains_active_marker(name)

            entry = _PackageEntry(
                name=name,
                data=content,
                compressed_size=int(info.compress_size),
                uncompressed_size=int(info.file_size),
                crc32=int(info.CRC),
                compression_method=int(info.compress_type),
                is_xml=is_xml,
                is_relationship=is_relationship,
                active_marker=active_marker,
            )

            entries[name] = entry

            if len(state.members) < MAX_MEMBER_RECORDS:
                state.members.append(
                    IntegrityMember(
                        name=name,
                        compressed_size=int(info.compress_size),
                        uncompressed_size=int(info.file_size),
                        crc32=int(info.CRC),
                        compression_method=int(info.compress_type),
                        is_xml=is_xml,
                        is_relationship=is_relationship,
                        active_marker=active_marker,
                        sha256=_sha256(content),
                    )
                )

            if active_marker:
                severity = (
                    IntegritySeverity.ERROR
                    if policy.reject_active_members
                    else IntegritySeverity.WARNING
                )

                _add_finding(
                    state,
                    IntegrityFinding(
                        code=IntegrityFindingCode.ACTIVE_MEMBER,
                        severity=severity,
                        message=(
                            "Potential active-content package member remains."
                        ),
                        member=name,
                    ),
                )

                if policy.reject_active_members:
                    raise IntegrityVerificationError(
                        f"Active-content member remains: {name}"
                    )
    finally:
        archive.close()

    return entries


def _parse_xml_members(
    entries: Mapping[str, _PackageEntry],
    policy: IntegrityPolicy,
    state: _IntegrityState,
) -> None:
    if not policy.verify_xml:
        return

    for name in sorted(entries):
        entry = entries[name]

        if not entry.is_xml:
            continue

        if policy.reject_invalid_xml_controls:
            if _contains_invalid_xml_controls(entry.data):
                _add_finding(
                    state,
                    IntegrityFinding(
                        code=IntegrityFindingCode.INVALID_XML_CONTROL,
                        severity=IntegritySeverity.ERROR,
                        message="XML member contains invalid control characters.",
                        member=name,
                    ),
                )

                if policy.reject_invalid_xml_controls:
                    raise IntegrityXMLException(
                        f"Invalid XML controls remain in {name}."
                    )

        try:
            root = _parse_xml(
                entry.data,
                name,
            )
        except IntegrityXMLException as exc:
            code = (
                IntegrityFindingCode.XML_LIMIT_EXCEEDED
                if any(
                    term in str(exc).lower()
                    for term in (
                        "limit",
                        "size",
                        "depth",
                        "nesting",
                        "attribute",
                        "element",
                    )
                )
                else IntegrityFindingCode.MALFORMED_XML
            )

            severity = (
                IntegritySeverity.ERROR
                if policy.reject_malformed_xml
                else IntegritySeverity.WARNING
            )

            _add_finding(
                state,
                IntegrityFinding(
                    code=code,
                    severity=severity,
                    message=str(exc),
                    member=name,
                ),
            )

            if policy.reject_malformed_xml:
                raise

            continue

        state.xml_roots[name] = root


def _parse_content_types(
    entries: Mapping[str, _PackageEntry],
    policy: IntegrityPolicy,
    state: _IntegrityState,
) -> None:
    member = entries.get(OOXML_CONTENT_TYPES)

    if member is None:
        severity = (
            IntegritySeverity.ERROR
            if policy.reject_missing_content_types
            else IntegritySeverity.WARNING
        )

        _add_finding(
            state,
            IntegrityFinding(
                code=IntegrityFindingCode.MISSING_CONTENT_TYPES,
                severity=severity,
                message="OOXML package is missing [Content_Types].xml.",
                member=OOXML_CONTENT_TYPES,
            ),
        )

        if policy.reject_missing_content_types:
            raise IntegrityVerificationError(
                "Missing [Content_Types].xml."
            )

        return

    root = state.xml_roots.get(OOXML_CONTENT_TYPES)

    if root is None:
        return

    for child in root:
        local = _xml_local_name(child.tag)

        if local == "Default":
            extension = child.attrib.get(
                "Extension",
                "",
            ).strip().lower()

            content_type = child.attrib.get(
                "ContentType",
                "",
            ).strip()

            if extension and content_type:
                state.defaults[extension] = content_type

        elif local == "Override":
            part_name = child.attrib.get(
                "PartName",
                "",
            ).strip()

            content_type = child.attrib.get(
                "ContentType",
                "",
            ).strip()

            if not part_name:
                continue

            normalized = part_name.lstrip("/")

            state.content_types[normalized] = content_type

            if (
                policy.reject_active_content_types
                and any(
                    term in content_type.lower()
                    for term in ACTIVE_CONTENT_TYPE_TERMS
                )
            ):
                _add_finding(
                    state,
                    IntegrityFinding(
                        code=IntegrityFindingCode.ACTIVE_CONTENT_TYPE,
                        severity=IntegritySeverity.ERROR,
                        message=(
                            "Potential active-content content type remains."
                        ),
                        member=normalized,
                        observed=content_type,
                    ),
                )

                raise IntegrityVerificationError(
                    f"Active content type remains for {normalized}."
                )

    if policy.verify_content_type_targets:
        for part_name in sorted(state.content_types):
            if part_name not in entries:
                _add_finding(
                    state,
                    IntegrityFinding(
                        code=IntegrityFindingCode.ORPHAN_OVERRIDE,
                        severity=IntegritySeverity.ERROR,
                        message=(
                            "Content-type override references a missing "
                            "package member."
                        ),
                        member=part_name,
                    ),
                )

                if policy.reject_missing_content_type_mapping:
                    raise IntegrityVerificationError(
                        f"Orphan content-type override: {part_name}"
                    )

        for name in sorted(entries):
            if name == OOXML_CONTENT_TYPES:
                continue

            if name.startswith("_rels/"):
                continue

            if name in state.content_types:
                continue

            extension = Path(name).suffix.lower().lstrip(".")

            if extension and extension in state.defaults:
                continue

            severity = (
                IntegritySeverity.ERROR
                if policy.reject_missing_content_type_mapping
                else IntegritySeverity.WARNING
            )

            _add_finding(
                state,
                IntegrityFinding(
                    code=IntegrityFindingCode.MISSING_CONTENT_TYPE,
                    severity=severity,
                    message=(
                        "Package member has no content-type override or "
                        "matching default."
                    ),
                    member=name,
                ),
            )

            if policy.reject_missing_content_type_mapping:
                raise IntegrityVerificationError(
                    f"Missing content type for {name}"
                )


def _verify_relationships(
    entries: Mapping[str, _PackageEntry],
    policy: IntegrityPolicy,
    state: _IntegrityState,
) -> None:
    if not policy.verify_relationships:
        return

    relationship_members = sorted(
        name
        for name, entry in entries.items()
        if entry.is_relationship
    )

    if (
        policy.require_root_relationships
        and OOXML_ROOT_RELS not in entries
    ):
        _add_finding(
            state,
            IntegrityFinding(
                code=IntegrityFindingCode.MISSING_ROOT_RELATIONSHIPS,
                severity=IntegritySeverity.ERROR,
                message="Root relationships part is missing.",
                member=OOXML_ROOT_RELS,
            ),
        )

        raise IntegrityVerificationError(
            "Missing root relationships part."
        )

    for rel_member in relationship_members:
        root = state.xml_roots.get(rel_member)

        if root is None:
            severity = (
                IntegritySeverity.ERROR
                if policy.reject_malformed_xml
                else IntegritySeverity.WARNING
            )

            _add_finding(
                state,
                IntegrityFinding(
                    code=IntegrityFindingCode.MALFORMED_RELATIONSHIPS,
                    severity=severity,
                    message="Relationship XML could not be validated.",
                    member=rel_member,
                ),
            )
            continue

        source = _relationship_source(rel_member)

        if source is None:
            _add_finding(
                state,
                IntegrityFinding(
                    code=IntegrityFindingCode.MALFORMED_RELATIONSHIPS,
                    severity=IntegritySeverity.ERROR,
                    message="Unable to determine relationship source part.",
                    member=rel_member,
                ),
            )

            if policy.require_relationship_targets:
                raise IntegrityVerificationError(
                    f"Invalid relationship part name: {rel_member}"
                )

            continue

        seen_ids: set[str] = set()

        for relationship in root:
            if _xml_local_name(relationship.tag) != "Relationship":
                continue

            relationship_id = relationship.attrib.get(REL_ID)
            relationship_type = relationship.attrib.get(REL_TYPE)
            target = relationship.attrib.get(REL_TARGET, "")
            target_mode = relationship.attrib.get(REL_TARGET_MODE)

            if relationship_id:
                if relationship_id in seen_ids:
                    _add_finding(
                        state,
                        IntegrityFinding(
                            code=IntegrityFindingCode.DUPLICATE_RELATIONSHIP_ID,
                            severity=IntegritySeverity.ERROR,
                            message="Duplicate relationship Id detected.",
                            member=rel_member,
                            observed=relationship_id,
                        ),
                    )

                    if policy.require_relationship_targets:
                        raise IntegrityVerificationError(
                            f"Duplicate relationship Id {relationship_id} "
                            f"in {rel_member}"
                        )

                seen_ids.add(relationship_id)

            external = _is_external_target(
                target_mode,
                target,
            )

            dangerous = _relationship_is_dangerous(
                relationship_type,
            )

            if dangerous:
                severity = (
                    IntegritySeverity.ERROR
                    if policy.reject_dangerous_relationships
                    else IntegritySeverity.WARNING
                )

                _add_finding(
                    state,
                    IntegrityFinding(
                        code=IntegrityFindingCode.DANGEROUS_RELATIONSHIP,
                        severity=severity,
                        message=(
                            "Potentially dangerous relationship type remains."
                        ),
                        member=rel_member,
                        detail=relationship_type,
                    ),
                )

                if policy.reject_dangerous_relationships:
                    raise IntegrityVerificationError(
                        f"Dangerous relationship remains in {rel_member}: "
                        f"{relationship_type}"
                    )

            if external:
                _add_finding(
                    state,
                    IntegrityFinding(
                        code=IntegrityFindingCode.EXTERNAL_RELATIONSHIP,
                        severity=(
                            IntegritySeverity.ERROR
                            if policy.reject_external_relationships
                            else IntegritySeverity.WARNING
                        ),
                        message="External relationship remains.",
                        member=rel_member,
                        detail=target,
                    ),
                )

                state.references.append(
                    IntegrityReference(
                        source=source,
                        target=target,
                        resolved_target=None,
                        relationship_id=relationship_id,
                        relationship_type=relationship_type,
                        target_mode=target_mode,
                        external=True,
                        valid=not policy.reject_external_relationships,
                        dangerous=dangerous,
                        reason=(
                            "external relationship"
                            if policy.reject_external_relationships
                            else None
                        ),
                    )
                )

                if policy.reject_external_relationships:
                    raise IntegrityVerificationError(
                        f"External relationship remains: {rel_member}"
                    )

                continue

            resolved, reason = _resolve_target(
                source,
                target,
            )

            if resolved is None:
                _add_finding(
                    state,
                    IntegrityFinding(
                        code=IntegrityFindingCode.INVALID_RELATIONSHIP_TARGET,
                        severity=IntegritySeverity.ERROR,
                        message="Relationship target is invalid.",
                        member=rel_member,
                        detail=reason,
                        observed=target,
                    ),
                )

                state.references.append(
                    IntegrityReference(
                        source=source,
                        target=target,
                        resolved_target=None,
                        relationship_id=relationship_id,
                        relationship_type=relationship_type,
                        target_mode=target_mode,
                        external=False,
                        valid=False,
                        dangerous=dangerous,
                        reason=reason,
                    )
                )

                if policy.require_relationship_targets:
                    raise IntegrityVerificationError(
                        f"Invalid relationship target in {rel_member}: "
                        f"{target}"
                    )

                continue

            valid = resolved in entries

            state.references.append(
                IntegrityReference(
                    source=source,
                    target=target,
                    resolved_target=resolved,
                    relationship_id=relationship_id,
                    relationship_type=relationship_type,
                    target_mode=target_mode,
                    external=False,
                    valid=valid,
                    dangerous=dangerous,
                    reason=None if valid else "target member missing",
                )
            )

            if not valid:
                _add_finding(
                    state,
                    IntegrityFinding(
                        code=IntegrityFindingCode.DANGLING_RELATIONSHIP,
                        severity=IntegritySeverity.ERROR,
                        message=(
                            "Relationship points to a package member that "
                            "does not exist."
                        ),
                        member=rel_member,
                        detail=target,
                        observed=resolved,
                    ),
                )

                if policy.reject_dangling_relationships:
                    raise IntegrityVerificationError(
                        f"Dangling relationship in {rel_member}: "
                        f"{resolved}"
                    )

    orphan_relationships = _find_orphan_relationship_parts(
        entries
    )

    for orphan in orphan_relationships:
        _add_finding(
            state,
            IntegrityFinding(
                code=IntegrityFindingCode.ORPHAN_RELATIONSHIP_PART,
                severity=(
                    IntegritySeverity.ERROR
                    if policy.reject_orphan_relationship_parts
                    else IntegritySeverity.WARNING
                ),
                message=(
                    "Relationship part has no corresponding source package "
                    "part."
                ),
                member=orphan,
            ),
        )

    if (
        orphan_relationships
        and policy.reject_orphan_relationship_parts
    ):
        raise IntegrityVerificationError(
            "Orphan relationship parts remain."
        )

    if len(state.references) > MAX_REFERENCES:
        del state.references[MAX_REFERENCES:]


def _find_orphan_relationship_parts(
    entries: Mapping[str, _PackageEntry],
) -> List[str]:
    result: List[str] = []

    for name, entry in entries.items():
        if not entry.is_relationship:
            continue

        source = _relationship_source(name)

        if source is None or source == "/":
            continue

        if source not in entries:
            result.append(name)

    return sorted(result)


def _verify_active_content(
    entries: Mapping[str, _PackageEntry],
    policy: IntegrityPolicy,
    state: _IntegrityState,
) -> None:
    for name in sorted(entries):
        entry = entries[name]

        if not entry.active_marker:
            continue

        severity = (
            IntegritySeverity.ERROR
            if policy.reject_active_members
            else IntegritySeverity.WARNING
        )

        _add_finding(
            state,
            IntegrityFinding(
                code=IntegrityFindingCode.ACTIVE_MEMBER,
                severity=severity,
                message="Potential active-content member remains.",
                member=name,
            ),
        )

        if policy.reject_active_members:
            raise IntegrityVerificationError(
                f"Active-content member remains: {name}"
            )

    for name, content_type in state.content_types.items():
        if not any(
            term in content_type.lower()
            for term in ACTIVE_CONTENT_TYPE_TERMS
        ):
            continue

        severity = (
            IntegritySeverity.ERROR
            if policy.reject_active_content_types
            else IntegritySeverity.WARNING
        )

        _add_finding(
            state,
            IntegrityFinding(
                code=IntegrityFindingCode.ACTIVE_CONTENT_TYPE,
                severity=severity,
                message="Potential active content type remains.",
                member=name,
                observed=content_type,
            ),
        )

        if policy.reject_active_content_types:
            raise IntegrityVerificationError(
                f"Active content type remains: {content_type}"
            )


def _statistics(
    data: bytes,
    entries: Mapping[str, _PackageEntry],
    state: _IntegrityState,
) -> IntegrityStatistics:
    return IntegrityStatistics(
        member_count=len(entries),
        xml_member_count=sum(
            1
            for entry in entries.values()
            if entry.is_xml
        ),
        relationship_member_count=sum(
            1
            for entry in entries.values()
            if entry.is_relationship
        ),
        active_member_count=sum(
            1
            for entry in entries.values()
            if entry.active_marker
        ),
        active_content_type_count=sum(
            1
            for content_type in state.content_types.values()
            if any(
                term in content_type.lower()
                for term in ACTIVE_CONTENT_TYPE_TERMS
            )
        ),
        dangerous_relationship_count=sum(
            1
            for reference in state.references
            if reference.dangerous
        ),
        external_relationship_count=sum(
            1
            for reference in state.references
            if reference.external
        ),
        dangling_relationship_count=sum(
            1
            for reference in state.references
            if not reference.external and not reference.valid
        ),
        orphan_relationship_part_count=sum(
            1
            for finding in state.findings
            if finding.code
            == IntegrityFindingCode.ORPHAN_RELATIONSHIP_PART
        ),
        malformed_xml_count=sum(
            1
            for finding in state.findings
            if finding.code in {
                IntegrityFindingCode.MALFORMED_XML,
                IntegrityFindingCode.XML_LIMIT_EXCEEDED,
            }
        ),
        total_compressed_size=sum(
            entry.compressed_size
            for entry in entries.values()
        ),
        total_uncompressed_size=sum(
            entry.uncompressed_size
            for entry in entries.values()
        ),
        package_size=len(data),
        sha256=_sha256(data),
    )


def _policy_dict(
    policy: IntegrityPolicy,
) -> Dict[str, Any]:
    return asdict(policy)


def _result_fingerprint(
    result: IntegrityResult,
) -> str:
    payload = {
        "module": MODULE_NAME,
        "version": INTEGRITY_VERSION,
        "status": result.status.value,
        "valid": result.valid,
        "sha256": result.sha256,
        "expected_sha256": result.expected_sha256,
        "statistics": (
            result.statistics.to_dict()
            if result.statistics is not None
            else None
        ),
        "finding_codes": sorted(
            finding.code.value
            for finding in result.findings
        ),
        "policy": result.policy,
    }

    serialized = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")

    return _sha256(serialized)


def verify_integrity(
    source: Union[
        bytes,
        bytearray,
        memoryview,
        os.PathLike,
        str,
    ],
    *,
    policy: Optional[IntegrityPolicy] = None,
    expected_sha256: Optional[str] = None,
) -> IntegrityResult:
    """
    Verify an OOXML package and return a complete integrity report.

    No modification is performed. The input package remains untouched.
    """
    effective_policy = (
        policy.normalized()
        if policy is not None
        else IntegrityPolicy().normalized()
    )

    data = _coerce_bytes(source)

    state = _IntegrityState()

    digest = _sha256(data)

    if expected_sha256 is not None:
        expected = _safe_text(
            expected_sha256,
            128,
        ).strip().lower()

        if (
            not re.fullmatch(
                r"[0-9a-f]{64}",
                expected,
            )
        ):
            raise IntegrityInputError(
                "expected_sha256 must be a 64-character hexadecimal digest."
            )

        if digest != expected:
            _add_finding(
                state,
                IntegrityFinding(
                    code=IntegrityFindingCode.HASH_MISMATCH,
                    severity=IntegritySeverity.ERROR,
                    message="Package SHA-256 does not match expected digest.",
                    expected=expected,
                    observed=digest,
                ),
            )

    try:
        entries = _read_package(
            data,
            effective_policy,
            state,
        )

        _parse_xml_members(
            entries,
            effective_policy,
            state,
        )

        _parse_content_types(
            entries,
            effective_policy,
            state,
        )

        _verify_relationships(
            entries,
            effective_policy,
            state,
        )

        _verify_active_content(
            entries,
            effective_policy,
            state,
        )

    except (
        IntegrityArchiveError,
        IntegrityXMLException,
        IntegrityVerificationError,
    ):
        status = IntegrityStatus.REJECTED
        valid = False
    else:
        critical = any(
            finding.severity == IntegritySeverity.CRITICAL
            for finding in state.findings
        )

        errors = any(
            finding.severity == IntegritySeverity.ERROR
            for finding in state.findings
        )

        warnings = any(
            finding.severity == IntegritySeverity.WARNING
            for finding in state.findings
        )

        if critical or errors:
            status = IntegrityStatus.INVALID
            valid = False
        elif warnings:
            status = IntegrityStatus.VALID_WITH_WARNINGS
            valid = True
        else:
            status = IntegrityStatus.VALID
            valid = True

    result = IntegrityResult(
        status=status,
        valid=valid,
        input_size=len(data),
        sha256=digest,
        findings=state.findings[:MAX_FINDINGS],
        references=state.references[:MAX_REFERENCES],
        members=state.members[:MAX_MEMBER_RECORDS],
        statistics=_statistics(
            data,
            entries if "entries" in locals() else {},
            state,
        ),
        policy=_policy_dict(effective_policy),
        expected_sha256=expected_sha256,
    )

    result.fingerprint = _result_fingerprint(result)

    return result


def check_integrity(
    source: Union[
        bytes,
        bytearray,
        memoryview,
        os.PathLike,
        str,
    ],
    *,
    policy: Optional[IntegrityPolicy] = None,
    expected_sha256: Optional[str] = None,
) -> bool:
    """Return True when integrity verification succeeds."""
    result = verify_integrity(
        source,
        policy=policy,
        expected_sha256=expected_sha256,
    )
    return result.valid


def validate_package(
    source: Union[
        bytes,
        bytearray,
        memoryview,
        os.PathLike,
        str,
    ],
    *,
    policy: Optional[IntegrityPolicy] = None,
) -> IntegrityResult:
    """Alias for ``verify_integrity``."""
    return verify_integrity(
        source,
        policy=policy,
    )


def verify_bytes(
    source: Union[bytes, bytearray, memoryview],
    *,
    policy: Optional[IntegrityPolicy] = None,
    expected_sha256: Optional[str] = None,
) -> IntegrityResult:
    """Verify an in-memory OOXML package."""
    return verify_integrity(
        source,
        policy=policy,
        expected_sha256=expected_sha256,
    )


def verify_file(
    source_path: Union[str, os.PathLike],
    *,
    policy: Optional[IntegrityPolicy] = None,
    expected_sha256: Optional[str] = None,
) -> IntegrityResult:
    """Verify an OOXML file without modifying it."""
    return verify_integrity(
        source_path,
        policy=policy,
        expected_sha256=expected_sha256,
    )


def package_sha256(
    source: Union[
        bytes,
        bytearray,
        memoryview,
        os.PathLike,
        str,
    ],
) -> str:
    """Return the SHA-256 digest of a package."""
    return _sha256(_coerce_bytes(source))


def package_member_names(
    source: Union[
        bytes,
        bytearray,
        memoryview,
        os.PathLike,
        str,
    ],
) -> List[str]:
    """Return normalized package member names."""
    data = _coerce_bytes(source)

    state = _IntegrityState()
    entries = _read_package(
        data,
        IntegrityPolicy(
            reject_duplicate_members=True,
            reject_path_traversal=True,
            reject_encrypted_members=True,
            reject_oversized_members=True,
            reject_malformed_xml=False,
            reject_invalid_xml_controls=False,
            reject_missing_content_types=False,
            reject_missing_content_type_mapping=False,
            reject_dangling_relationships=False,
            reject_orphan_relationship_parts=False,
            reject_external_relationships=False,
            reject_dangerous_relationships=False,
            reject_active_members=False,
            reject_active_content_types=False,
            require_root_relationships=False,
            require_relationship_targets=False,
            verify_member_crc=True,
            verify_content_type_targets=False,
            verify_relationships=False,
            verify_xml=False,
        ).normalized(),
        state,
    )

    return sorted(entries)


def read_package_member(
    source: Union[
        bytes,
        bytearray,
        memoryview,
        os.PathLike,
        str,
    ],
    member_name: str,
) -> bytes:
    """
    Read one ZIP member into memory.

    The member is never extracted to the filesystem.
    """
    data = _coerce_bytes(source)

    state = _IntegrityState()

    entries = _read_package(
        data,
        IntegrityPolicy(
            reject_duplicate_members=True,
            reject_path_traversal=True,
            reject_encrypted_members=True,
            reject_oversized_members=True,
            verify_member_crc=True,
            verify_xml=False,
            verify_relationships=False,
            reject_active_members=False,
            reject_active_content_types=False,
            reject_missing_content_types=False,
            reject_missing_content_type_mapping=False,
            reject_dangling_relationships=False,
            reject_orphan_relationship_parts=False,
            reject_external_relationships=False,
            reject_dangerous_relationships=False,
            require_root_relationships=False,
            require_relationship_targets=False,
            verify_content_type_targets=False,
        ).normalized(),
        state,
    )

    normalized = _normalize_member_name(member_name)

    entry = entries.get(normalized)

    if entry is None:
        raise IntegrityInputError(
            f"Package member not found: {normalized}"
        )

    return bytes(entry.data)


def result_to_dict(
    result: IntegrityResult,
) -> Dict[str, Any]:
    """Serialize an integrity result to a dictionary."""
    return result.to_dict()


def result_to_json(
    result: IntegrityResult,
    *,
    indent: Optional[int] = 2,
) -> str:
    """Serialize an integrity result to JSON."""
    return result.to_json(indent=indent)


def save_integrity_report(
    result: IntegrityResult,
    output_path: Union[str, os.PathLike],
    *,
    indent: int = 2,
    overwrite: bool = False,
) -> Path:
    """Explicitly save an integrity report as JSON."""
    destination = Path(output_path)

    if destination.exists() and not overwrite:
        raise IntegrityInputError(
            f"Report already exists: {destination}"
        )

    content = result_to_json(
        result,
        indent=indent,
    ).encode("utf-8")

    if len(content) > MAX_REPORT_BYTES:
        raise IntegrityInputError(
            "Integrity report exceeds MAX_REPORT_BYTES."
        )

    try:
        destination.parent.mkdir(
            parents=True,
            exist_ok=True,
        )
        destination.write_bytes(content)
    except OSError as exc:
        raise IntegrityInputError(
            f"Unable to save integrity report: {exc}"
        ) from exc

    return destination


def summarize_integrity(
    result: IntegrityResult,
) -> Dict[str, Any]:
    """Return a compact audit-oriented integrity summary."""
    statistics = result.statistics

    return {
        "status": result.status.value,
        "valid": result.valid,
        "input_size": result.input_size,
        "sha256": result.sha256,
        "expected_sha256": result.expected_sha256,
        "warning_count": result.warning_count,
        "error_count": result.error_count,
        "critical_count": result.critical_count,
        "member_count": (
            statistics.member_count
            if statistics
            else 0
        ),
        "xml_member_count": (
            statistics.xml_member_count
            if statistics
            else 0
        ),
        "relationship_member_count": (
            statistics.relationship_member_count
            if statistics
            else 0
        ),
        "active_member_count": (
            statistics.active_member_count
            if statistics
            else 0
        ),
        "active_content_type_count": (
            statistics.active_content_type_count
            if statistics
            else 0
        ),
        "dangerous_relationship_count": (
            statistics.dangerous_relationship_count
            if statistics
            else 0
        ),
        "external_relationship_count": (
            statistics.external_relationship_count
            if statistics
            else 0
        ),
        "dangling_relationship_count": (
            statistics.dangling_relationship_count
            if statistics
            else 0
        ),
        "orphan_relationship_part_count": (
            statistics.orphan_relationship_part_count
            if statistics
            else 0
        ),
        "malformed_xml_count": (
            statistics.malformed_xml_count
            if statistics
            else 0
        ),
        "fingerprint": result.fingerprint,
    }


def iter_findings(
    result: IntegrityResult,
) -> Iterator[IntegrityFinding]:
    """Iterate all integrity findings."""
    yield from result.findings


def iter_errors(
    result: IntegrityResult,
) -> Iterator[IntegrityFinding]:
    """Iterate error and critical findings."""
    for finding in result.findings:
        if finding.severity in {
            IntegritySeverity.ERROR,
            IntegritySeverity.CRITICAL,
        }:
            yield finding


def iter_warnings(
    result: IntegrityResult,
) -> Iterator[IntegrityFinding]:
    """Iterate warning findings."""
    for finding in result.findings:
        if finding.severity == IntegritySeverity.WARNING:
            yield finding


def iter_references(
    result: IntegrityResult,
) -> Iterator[IntegrityReference]:
    """Iterate relationship references."""
    yield from result.references


def iter_members(
    result: IntegrityResult,
) -> Iterator[IntegrityMember]:
    """Iterate package-member metadata."""
    yield from result.members


def findings_by_code(
    result: IntegrityResult,
    code: Union[
        IntegrityFindingCode,
        str,
    ],
) -> List[IntegrityFinding]:
    """Return findings matching a finding code."""
    wanted = (
        code.value
        if isinstance(code, IntegrityFindingCode)
        else _safe_text(code).strip().lower()
    )

    return [
        finding
        for finding in result.findings
        if finding.code.value == wanted
    ]


def findings_by_severity(
    result: IntegrityResult,
    severity: Union[
        IntegritySeverity,
        str,
    ],
) -> List[IntegrityFinding]:
    """Return findings matching a severity."""
    wanted = (
        severity.value
        if isinstance(severity, IntegritySeverity)
        else _safe_text(severity).strip().lower()
    )

    return [
        finding
        for finding in result.findings
        if finding.severity.value == wanted
    ]


def has_active_content(
    result: IntegrityResult,
) -> bool:
    """Return True when active-content remnants were detected."""
    return (
        result.active_content_count > 0
        or any(
            finding.code
            == IntegrityFindingCode.ACTIVE_CONTENT_TYPE
            for finding in result.findings
        )
    )


def has_external_relationships(
    result: IntegrityResult,
) -> bool:
    """Return True when external relationships remain."""
    return any(
        reference.external
        for reference in result.references
    )


def has_dangling_relationships(
    result: IntegrityResult,
) -> bool:
    """Return True when dangling relationships remain."""
    return any(
        not reference.external
        and not reference.valid
        for reference in result.references
    )


def has_dangerous_relationships(
    result: IntegrityResult,
) -> bool:
    """Return True when dangerous relationship types remain."""
    return any(
        reference.dangerous
        for reference in result.references
    )


def is_clean(
    result: IntegrityResult,
) -> bool:
    """
    Return True when verification succeeded without warnings/errors.
    """
    return (
        result.valid
        and result.warning_count == 0
        and result.error_count == 0
    )


def default_policy() -> IntegrityPolicy:
    """Return the balanced default integrity policy."""
    return IntegrityPolicy().normalized()


def strict_policy() -> IntegrityPolicy:
    """Return the strictest supported integrity policy."""
    return IntegrityPolicy(
        reject_duplicate_members=True,
        reject_path_traversal=True,
        reject_encrypted_members=True,
        reject_oversized_members=True,
        reject_malformed_xml=True,
        reject_invalid_xml_controls=True,
        reject_missing_content_types=True,
        reject_missing_content_type_mapping=True,
        reject_dangling_relationships=True,
        reject_orphan_relationship_parts=True,
        reject_external_relationships=True,
        reject_dangerous_relationships=True,
        reject_active_members=True,
        reject_active_content_types=True,
        require_root_relationships=False,
        require_relationship_targets=True,
        verify_member_crc=True,
        verify_content_type_targets=True,
        verify_relationships=True,
        verify_xml=True,
    ).normalized()


def permissive_policy() -> IntegrityPolicy:
    """
    Return a compatibility-oriented policy.

    Structural ZIP safety remains enforced, while semantic anomalies are
    generally reported as warnings rather than rejected.
    """
    return IntegrityPolicy(
        reject_duplicate_members=True,
        reject_path_traversal=True,
        reject_encrypted_members=True,
        reject_oversized_members=True,
        reject_malformed_xml=False,
        reject_invalid_xml_controls=True,
        reject_missing_content_types=False,
        reject_missing_content_type_mapping=False,
        reject_dangling_relationships=False,
        reject_orphan_relationship_parts=False,
        reject_external_relationships=False,
        reject_dangerous_relationships=False,
        reject_active_members=False,
        reject_active_content_types=False,
        require_root_relationships=False,
        require_relationship_targets=False,
        verify_member_crc=True,
        verify_content_type_targets=True,
        verify_relationships=True,
        verify_xml=True,
    ).normalized()


def integrity_fingerprint(
    result: IntegrityResult,
) -> str:
    """
    Return the stable audit fingerprint associated with an integrity result.
    """
    if result.fingerprint:
        return result.fingerprint

    return _result_fingerprint(result)


def compare_hashes(
    source: Union[
        bytes,
        bytearray,
        memoryview,
        os.PathLike,
        str,
    ],
    expected_sha256: str,
) -> bool:
    """Compare a package digest against an expected SHA-256."""
    observed = package_sha256(source)

    expected = _safe_text(
        expected_sha256,
        128,
    ).strip().lower()

    return (
        bool(
            re.fullmatch(
                r"[0-9a-f]{64}",
                expected,
            )
        )
        and observed == expected
    )


def verify_reconstructed_package(
    source: Union[
        bytes,
        bytearray,
        memoryview,
        os.PathLike,
        str,
    ],
    *,
    strict: bool = True,
    expected_sha256: Optional[str] = None,
) -> IntegrityResult:
    """
    High-level verification entry point intended for the final CDR stage.
    """
    policy = (
        strict_policy()
        if strict
        else default_policy()
    )

    return verify_integrity(
        source,
        policy=policy,
        expected_sha256=expected_sha256,
    )


# ---------------------------------------------------------------------------
# PUBLIC APIs
# ---------------------------------------------------------------------------

__all__ = [
    "MODULE_NAME",
    "INTEGRITY_VERSION",
    "MAX_INPUT_BYTES",
    "MAX_ZIP_ENTRIES",
    "MAX_MEMBER_NAME",
    "MAX_ENTRY_COMPRESSED",
    "MAX_ENTRY_UNCOMPRESSED",
    "MAX_TOTAL_COMPRESSED",
    "MAX_TOTAL_UNCOMPRESSED",
    "MAX_XML_BYTES",
    "MAX_XML_ELEMENTS",
    "MAX_XML_ATTRIBUTES",
    "MAX_XML_DEPTH",
    "MAX_FINDINGS",
    "MAX_REFERENCES",
    "MAX_MEMBER_RECORDS",
    "MAX_REPORT_BYTES",
    "IntegrityError",
    "IntegrityInputError",
    "IntegrityArchiveError",
    "IntegrityXMLException",
    "IntegrityVerificationError",
    "IntegritySeverity",
    "IntegrityStatus",
    "IntegrityFindingCode",
    "IntegrityFinding",
    "IntegrityReference",
    "IntegrityMember",
    "IntegrityStatistics",
    "IntegrityPolicy",
    "IntegrityResult",
    "verify_integrity",
    "check_integrity",
    "validate_package",
    "verify_bytes",
    "verify_file",
    "verify_reconstructed_package",
    "package_sha256",
    "package_member_names",
    "read_package_member",
    "compare_hashes",
    "result_to_dict",
    "result_to_json",
    "save_integrity_report",
    "integrity_fingerprint",
    "summarize_integrity",
    "iter_findings",
    "iter_errors",
    "iter_warnings",
    "iter_references",
    "iter_members",
    "findings_by_code",
    "findings_by_severity",
    "has_active_content",
    "has_external_relationships",
    "has_dangling_relationships",
    "has_dangerous_relationships",
    "is_clean",
    "default_policy",
    "strict_policy",
    "permissive_policy",
]