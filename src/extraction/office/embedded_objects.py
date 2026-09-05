"""
OOXML embedded-object analysis.

This module inspects ZIP-based Office/Open XML packages for embedded
objects and related payloads.

Typical package locations include:

    word/embeddings/
    xl/embeddings/
    ppt/embeddings/

and:

    word/activeX/
    xl/activeX/
    ppt/activeX/

The module identifies:
- embedded object parts
- OLE object payloads
- embedded package payloads
- ActiveX/control parts
- relationship references to embedded content
- suspicious embedded extensions
- nested archive/container indicators
- executable/script-like embedded payloads
- object sizes
- content hashes
- compression characteristics

The implementation is deliberately static.

It does NOT:
- execute embedded objects
- instantiate OLE/COM objects
- execute ActiveX
- invoke external applications
- extract embedded files to the host filesystem
- fetch relationship targets
- open embedded payloads with external applications

For deeper OLE analysis, use:
    src/extraction/office/ole.py

For relationship semantics, use:
    src/extraction/office/relationships.py

For broader Office package analysis, use:
    src/extraction/office/office_features.py

Design goals
------------
1. Treat the Office ZIP package as hostile input.
2. Keep all operations in memory.
3. Never trust ZIP member names.
4. Avoid filesystem extraction.
5. Bound object sizes and object counts.
6. Return JSON-serializable results.
7. Provide both detailed records and ML-ready scalar features.
8. Preserve enough evidence for downstream CDR decisions.
"""

from __future__ import annotations

import hashlib
import io
import math
import posixpath
import re
import zipfile
from collections import Counter
from dataclasses import dataclass
from typing import Any, Iterable, Sequence

EMBEDDED_OBJECTS_VERSION = 1

DEFAULT_MAX_OBJECTS = 1_000
DEFAULT_MAX_OBJECT_SIZE = 128 * 1024 * 1024
DEFAULT_MAX_TOTAL_EMBEDDED_SIZE = 512 * 1024 * 1024

OLE_SIGNATURE = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"

ZIP_SIGNATURES = (
    b"PK\x03\x04",
    b"PK\x05\x06",
    b"PK\x07\x08",
)

PE_SIGNATURES = (b"MZ",)

ELF_SIGNATURE = b"\x7fELF"

PDF_SIGNATURE = b"%PDF-"

RTF_SIGNATURE = b"{\\rtf"

CAB_SIGNATURE = b"MSCF"

GZIP_SIGNATURE = b"\x1f\x8b"

RAR_SIGNATURES = (
    b"Rar!\x1a\x07\x00",
    b"Rar!\x1a\x07\x01\x00",
)

SEVEN_Z_SIGNATURE = b"7z\xbc\xaf'\x1c"

SCRIPT_EXTENSIONS = frozenset(
    {
        ".bat",
        ".cmd",
        ".js",
        ".jse",
        ".ps1",
        ".psm1",
        ".py",
        ".pyw",
        ".sh",
        ".vbe",
        ".vbs",
        ".wsf",
        ".wsh",
    }
)

EXECUTABLE_EXTENSIONS = frozenset(
    {
        ".com",
        ".dll",
        ".exe",
        ".ocx",
        ".scr",
        ".sys",
    }
)

INSTALLER_EXTENSIONS = frozenset(
    {
        ".msi",
        ".msp",
        ".cab",
    }
)

ARCHIVE_EXTENSIONS = frozenset(
    {
        ".7z",
        ".bz2",
        ".cab",
        ".gz",
        ".iso",
        ".rar",
        ".tar",
        ".tgz",
        ".xz",
        ".zip",
    }
)

OFFICE_EXTENSIONS = frozenset(
    {
        ".doc",
        ".docm",
        ".docx",
        ".dot",
        ".dotm",
        ".dotx",
        ".xls",
        ".xlsb",
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
        ".pps",
        ".ppsm",
        ".ppsx",
    }
)

DOCUMENT_EXTENSIONS = frozenset(
    {
        ".pdf",
        ".rtf",
        ".txt",
        ".csv",
        ".xml",
        ".html",
        ".htm",
    }
)

SUSPICIOUS_EXTENSIONS = SCRIPT_EXTENSIONS | EXECUTABLE_EXTENSIONS | INSTALLER_EXTENSIONS

EMBEDDING_DIRECTORY_RE = re.compile(r"(?i)(?:^|/)(?:" r"embeddings|embedded" r")/")

ACTIVEX_DIRECTORY_RE = re.compile(r"(?i)(?:^|/)activex/")

CONTROL_DIRECTORY_RE = re.compile(r"(?i)(?:^|/)(?:controls|control)/")

OLE_OBJECT_NAME_RE = re.compile(
    r"(?i)" r"(?:" r"oleobject" r"|oleobject\d*" r"|object\d*" r")"
)

PACKAGE_CONTENT_TYPE_RE = re.compile(
    r"(?i)"
    r"(?:"
    r"oleObject"
    r"|embeddedPackage"
    r"|package"
    r"|activeX"
    r"|control"
    r")"
)

TARGET_EXTENSION_RE = re.compile(r"(?i)" r"\.([a-z0-9]{1,16})$")


@dataclass(frozen=True)
class EmbeddedObjectRecord:
    """
    Metadata describing one embedded package member.
    """

    member_name: str
    object_kind: str

    compressed_size: int
    uncompressed_size: int
    compression_ratio: float

    crc32: int

    sha256: str
    md5: str

    extension: str
    filename: str

    is_ole: bool
    is_package: bool
    is_activex: bool
    is_control: bool
    is_embedding_path: bool

    is_script: bool
    is_executable: bool
    is_installer: bool
    is_archive: bool
    is_office_document: bool
    is_document: bool
    is_suspicious_extension: bool

    detected_format: str

    has_pe_signature: bool
    has_elf_signature: bool
    has_pdf_signature: bool
    has_rtf_signature: bool
    has_zip_signature: bool
    has_ole_signature: bool
    has_cab_signature: bool
    has_gzip_signature: bool
    has_rar_signature: bool
    has_7z_signature: bool

    high_compression_ratio: bool
    empty_payload: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "member_name": self.member_name,
            "object_kind": self.object_kind,
            "compressed_size": self.compressed_size,
            "uncompressed_size": self.uncompressed_size,
            "compression_ratio": self.compression_ratio,
            "crc32": self.crc32,
            "sha256": self.sha256,
            "md5": self.md5,
            "extension": self.extension,
            "filename": self.filename,
            "is_ole": self.is_ole,
            "is_package": self.is_package,
            "is_activex": self.is_activex,
            "is_control": self.is_control,
            "is_embedding_path": self.is_embedding_path,
            "is_script": self.is_script,
            "is_executable": self.is_executable,
            "is_installer": self.is_installer,
            "is_archive": self.is_archive,
            "is_office_document": self.is_office_document,
            "is_document": self.is_document,
            "is_suspicious_extension": (self.is_suspicious_extension),
            "detected_format": self.detected_format,
            "has_pe_signature": self.has_pe_signature,
            "has_elf_signature": self.has_elf_signature,
            "has_pdf_signature": self.has_pdf_signature,
            "has_rtf_signature": self.has_rtf_signature,
            "has_zip_signature": self.has_zip_signature,
            "has_ole_signature": self.has_ole_signature,
            "has_cab_signature": self.has_cab_signature,
            "has_gzip_signature": self.has_gzip_signature,
            "has_rar_signature": self.has_rar_signature,
            "has_7z_signature": self.has_7z_signature,
            "high_compression_ratio": (self.high_compression_ratio),
            "empty_payload": self.empty_payload,
        }


@dataclass(frozen=True)
class EmbeddedObjectStatistics:
    """
    Aggregate statistics for embedded objects.
    """

    object_count: int
    total_compressed_size: int
    total_uncompressed_size: int
    maximum_object_size: int
    average_object_size: float

    ole_count: int
    package_count: int
    activex_count: int
    control_count: int

    script_count: int
    executable_count: int
    installer_count: int
    archive_count: int
    office_document_count: int
    document_count: int
    suspicious_extension_count: int

    pe_signature_count: int
    elf_signature_count: int
    pdf_signature_count: int
    rtf_signature_count: int
    zip_signature_count: int
    ole_signature_count: int
    cab_signature_count: int
    gzip_signature_count: int
    rar_signature_count: int
    seven_zip_signature_count: int

    high_compression_ratio_count: int
    empty_payload_count: int

    unique_sha256_count: int
    duplicate_sha256_count: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "object_count": self.object_count,
            "total_compressed_size": (self.total_compressed_size),
            "total_uncompressed_size": (self.total_uncompressed_size),
            "maximum_object_size": (self.maximum_object_size),
            "average_object_size": (self.average_object_size),
            "ole_count": self.ole_count,
            "package_count": self.package_count,
            "activex_count": self.activex_count,
            "control_count": self.control_count,
            "script_count": self.script_count,
            "executable_count": self.executable_count,
            "installer_count": self.installer_count,
            "archive_count": self.archive_count,
            "office_document_count": (self.office_document_count),
            "document_count": self.document_count,
            "suspicious_extension_count": (self.suspicious_extension_count),
            "pe_signature_count": (self.pe_signature_count),
            "elf_signature_count": (self.elf_signature_count),
            "pdf_signature_count": (self.pdf_signature_count),
            "rtf_signature_count": (self.rtf_signature_count),
            "zip_signature_count": (self.zip_signature_count),
            "ole_signature_count": (self.ole_signature_count),
            "cab_signature_count": (self.cab_signature_count),
            "gzip_signature_count": (self.gzip_signature_count),
            "rar_signature_count": (self.rar_signature_count),
            "seven_zip_signature_count": (self.seven_zip_signature_count),
            "high_compression_ratio_count": (self.high_compression_ratio_count),
            "empty_payload_count": (self.empty_payload_count),
            "unique_sha256_count": (self.unique_sha256_count),
            "duplicate_sha256_count": (self.duplicate_sha256_count),
        }


@dataclass(frozen=True)
class EmbeddedObjectAnalysis:
    """
    Complete analysis result for an Office package.
    """

    package_path: str | None
    package_is_zip: bool

    objects: tuple[EmbeddedObjectRecord, ...]
    statistics: EmbeddedObjectStatistics

    total_package_members: int
    candidate_member_count: int

    truncated_by_object_limit: bool
    truncated_by_total_size_limit: bool

    parse_success: bool
    parse_error: str | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "embedded_objects_version": (EMBEDDED_OBJECTS_VERSION),
            "package_path": self.package_path,
            "package_is_zip": self.package_is_zip,
            "objects": [obj.to_dict() for obj in self.objects],
            "statistics": self.statistics.to_dict(),
            "total_package_members": (self.total_package_members),
            "candidate_member_count": (self.candidate_member_count),
            "truncated_by_object_limit": (self.truncated_by_object_limit),
            "truncated_by_total_size_limit": (self.truncated_by_total_size_limit),
            "parse_success": self.parse_success,
            "parse_error": self.parse_error,
        }


def _normalize_member_name(name: str) -> str:
    return name.replace("\\", "/").lstrip("/")


def _extension_from_name(name: str) -> str:
    normalized = _normalize_member_name(name)

    basename = normalized.rsplit("/", 1)[-1]

    if "." not in basename:
        return ""

    extension = basename.rsplit(".", 1)[-1]

    if not extension:
        return ""

    if not TARGET_EXTENSION_RE.fullmatch(f".{extension}"):
        return ""

    return f".{extension.lower()}"


def _is_embedding_path(name: str) -> bool:
    return bool(EMBEDDING_DIRECTORY_RE.search(_normalize_member_name(name)))


def _is_activex_path(name: str) -> bool:
    return bool(ACTIVEX_DIRECTORY_RE.search(_normalize_member_name(name)))


def _is_control_path(name: str) -> bool:
    return bool(CONTROL_DIRECTORY_RE.search(_normalize_member_name(name)))


def _is_ole_filename(name: str) -> bool:
    basename = _normalize_member_name(name).rsplit("/", 1)[-1]

    return bool(OLE_OBJECT_NAME_RE.search(basename))


def _detect_object_kind(
    name: str,
    extension: str,
    *,
    is_activex: bool,
    is_control: bool,
    is_embedding: bool,
) -> str:
    if is_activex:
        return "activex"

    if is_control:
        return "control"

    if extension in {".bin", ".ole"}:
        return "ole_or_binary"

    if extension in OFFICE_EXTENSIONS:
        return "embedded_office_document"

    if extension in ARCHIVE_EXTENSIONS:
        return "embedded_archive"

    if extension in SCRIPT_EXTENSIONS:
        return "embedded_script"

    if extension in EXECUTABLE_EXTENSIONS:
        return "embedded_executable"

    if extension in INSTALLER_EXTENSIONS:
        return "embedded_installer"

    if is_embedding:
        return "embedded_payload"

    return "embedded_candidate"


def _detect_magic_format(
    data: bytes,
) -> str:
    if not data:
        return "empty"

    if data.startswith(OLE_SIGNATURE):
        return "ole"

    if any(data.startswith(signature) for signature in PE_SIGNATURES):
        return "pe"

    if data.startswith(ELF_SIGNATURE):
        return "elf"

    if data.startswith(PDF_SIGNATURE):
        return "pdf"

    if data.startswith(RTF_SIGNATURE):
        return "rtf"

    if any(data.startswith(signature) for signature in ZIP_SIGNATURES):
        return "zip"

    if data.startswith(CAB_SIGNATURE):
        return "cab"

    if data.startswith(GZIP_SIGNATURE):
        return "gzip"

    if any(data.startswith(signature) for signature in RAR_SIGNATURES):
        return "rar"

    if data.startswith(SEVEN_Z_SIGNATURE):
        return "7z"

    return "unknown"


def _calculate_hashes(
    data: bytes,
) -> tuple[str, str]:
    sha256 = hashlib.sha256(data).hexdigest()
    md5 = hashlib.md5(
        data,
        usedforsecurity=False,
    ).hexdigest()

    return sha256, md5


def _compression_ratio(
    compressed_size: int,
    uncompressed_size: int,
) -> float:
    if compressed_size <= 0:
        if uncompressed_size > 0:
            return float("inf")

        return 1.0

    return uncompressed_size / compressed_size


def _safe_ratio_for_output(
    value: float,
) -> float:
    if not math.isfinite(value):
        return 0.0

    return round(value, 6)


def _looks_like_candidate(
    info: zipfile.ZipInfo,
) -> bool:
    name = _normalize_member_name(info.filename)

    extension = _extension_from_name(name)

    return (
        _is_embedding_path(name)
        or _is_activex_path(name)
        or _is_control_path(name)
        or _is_ole_filename(name)
        or extension in SUSPICIOUS_EXTENSIONS
        or extension in ARCHIVE_EXTENSIONS
        or extension in OFFICE_EXTENSIONS
        or extension in DOCUMENT_EXTENSIONS
    )


def _read_zip_member_bounded(
    archive: zipfile.ZipFile,
    info: zipfile.ZipInfo,
    *,
    max_size: int,
) -> bytes:
    """
    Read a ZIP member into memory with an explicit uncompressed-size limit.

    ZipInfo.file_size is checked first, but the actual read is additionally
    bounded because malformed archives should not be trusted.
    """

    if max_size <= 0:
        raise ValueError("max_size must be greater than zero")

    if info.file_size > max_size:
        raise ValueError("embedded object exceeds configured size limit")

    with archive.open(
        info,
        "r",
    ) as handle:
        chunks: list[bytes] = []
        total = 0

        while True:
            chunk = handle.read(min(1024 * 1024, max_size - total))

            if not chunk:
                break

            total += len(chunk)

            if total > max_size:
                raise ValueError(
                    "embedded object exceeded configured " "size limit while reading"
                )

            chunks.append(chunk)

    return b"".join(chunks)


def _build_record(
    *,
    info: zipfile.ZipInfo,
    data: bytes,
) -> EmbeddedObjectRecord:
    member_name = _normalize_member_name(info.filename)

    extension = _extension_from_name(member_name)

    is_embedding = _is_embedding_path(member_name)

    is_activex = _is_activex_path(member_name)

    is_control = _is_control_path(member_name)

    magic = _detect_magic_format(data)

    sha256, md5 = _calculate_hashes(data)

    is_ole = (
        magic == "ole"
        or extension in {".ole"}
        or (extension == ".bin" and _is_ole_filename(member_name))
    )

    is_package = (
        magic
        in {
            "zip",
            "rar",
            "7z",
            "cab",
            "gzip",
        }
        or extension in ARCHIVE_EXTENSIONS
    )

    is_script = extension in SCRIPT_EXTENSIONS

    is_executable = extension in EXECUTABLE_EXTENSIONS or magic in {"pe", "elf"}

    is_installer = extension in INSTALLER_EXTENSIONS or magic == "cab"

    is_archive = extension in ARCHIVE_EXTENSIONS or magic in {
        "zip",
        "rar",
        "7z",
        "gzip",
    }

    is_office_document = extension in OFFICE_EXTENSIONS

    is_document = extension in DOCUMENT_EXTENSIONS or magic in {"pdf", "rtf"}

    is_suspicious_extension = extension in SUSPICIOUS_EXTENSIONS

    object_kind = _detect_object_kind(
        member_name,
        extension,
        is_activex=is_activex,
        is_control=is_control,
        is_embedding=is_embedding,
    )

    compressed_size = max(
        0,
        int(info.compress_size),
    )

    uncompressed_size = max(
        0,
        int(info.file_size),
    )

    ratio = _compression_ratio(
        compressed_size,
        uncompressed_size,
    )

    return EmbeddedObjectRecord(
        member_name=member_name,
        object_kind=object_kind,
        compressed_size=compressed_size,
        uncompressed_size=uncompressed_size,
        compression_ratio=(_safe_ratio_for_output(ratio)),
        crc32=int(info.CRC) & 0xFFFFFFFF,
        sha256=sha256,
        md5=md5,
        extension=extension,
        filename=member_name.rsplit(
            "/",
            1,
        )[-1],
        is_ole=is_ole,
        is_package=is_package,
        is_activex=is_activex,
        is_control=is_control,
        is_embedding_path=is_embedding,
        is_script=is_script,
        is_executable=is_executable,
        is_installer=is_installer,
        is_archive=is_archive,
        is_office_document=is_office_document,
        is_document=is_document,
        is_suspicious_extension=(is_suspicious_extension),
        detected_format=magic,
        has_pe_signature=(magic == "pe"),
        has_elf_signature=(magic == "elf"),
        has_pdf_signature=(magic == "pdf"),
        has_rtf_signature=(magic == "rtf"),
        has_zip_signature=(magic == "zip"),
        has_ole_signature=(magic == "ole"),
        has_cab_signature=(magic == "cab"),
        has_gzip_signature=(magic == "gzip"),
        has_rar_signature=(magic == "rar"),
        has_7z_signature=(magic == "7z"),
        high_compression_ratio=(ratio >= 100.0),
        empty_payload=(len(data) == 0),
    )


def calculate_statistics(
    objects: Sequence[EmbeddedObjectRecord],
) -> EmbeddedObjectStatistics:
    if not objects:
        return EmbeddedObjectStatistics(
            object_count=0,
            total_compressed_size=0,
            total_uncompressed_size=0,
            maximum_object_size=0,
            average_object_size=0.0,
            ole_count=0,
            package_count=0,
            activex_count=0,
            control_count=0,
            script_count=0,
            executable_count=0,
            installer_count=0,
            archive_count=0,
            office_document_count=0,
            document_count=0,
            suspicious_extension_count=0,
            pe_signature_count=0,
            elf_signature_count=0,
            pdf_signature_count=0,
            rtf_signature_count=0,
            zip_signature_count=0,
            ole_signature_count=0,
            cab_signature_count=0,
            gzip_signature_count=0,
            rar_signature_count=0,
            seven_zip_signature_count=0,
            high_compression_ratio_count=0,
            empty_payload_count=0,
            unique_sha256_count=0,
            duplicate_sha256_count=0,
        )

    sizes = [object_record.uncompressed_size for object_record in objects]

    hashes = [object_record.sha256 for object_record in objects]

    hash_counts = Counter(hashes)

    duplicate_hash_count = sum(count - 1 for count in hash_counts.values() if count > 1)

    return EmbeddedObjectStatistics(
        object_count=len(objects),
        total_compressed_size=sum(
            object_record.compressed_size for object_record in objects
        ),
        total_uncompressed_size=sum(sizes),
        maximum_object_size=max(sizes),
        average_object_size=(sum(sizes) / len(sizes)),
        ole_count=sum(object_record.is_ole for object_record in objects),
        package_count=sum(object_record.is_package for object_record in objects),
        activex_count=sum(object_record.is_activex for object_record in objects),
        control_count=sum(object_record.is_control for object_record in objects),
        script_count=sum(object_record.is_script for object_record in objects),
        executable_count=sum(object_record.is_executable for object_record in objects),
        installer_count=sum(object_record.is_installer for object_record in objects),
        archive_count=sum(object_record.is_archive for object_record in objects),
        office_document_count=sum(
            object_record.is_office_document for object_record in objects
        ),
        document_count=sum(object_record.is_document for object_record in objects),
        suspicious_extension_count=sum(
            object_record.is_suspicious_extension for object_record in objects
        ),
        pe_signature_count=sum(
            object_record.has_pe_signature for object_record in objects
        ),
        elf_signature_count=sum(
            object_record.has_elf_signature for object_record in objects
        ),
        pdf_signature_count=sum(
            object_record.has_pdf_signature for object_record in objects
        ),
        rtf_signature_count=sum(
            object_record.has_rtf_signature for object_record in objects
        ),
        zip_signature_count=sum(
            object_record.has_zip_signature for object_record in objects
        ),
        ole_signature_count=sum(
            object_record.has_ole_signature for object_record in objects
        ),
        cab_signature_count=sum(
            object_record.has_cab_signature for object_record in objects
        ),
        gzip_signature_count=sum(
            object_record.has_gzip_signature for object_record in objects
        ),
        rar_signature_count=sum(
            object_record.has_rar_signature for object_record in objects
        ),
        seven_zip_signature_count=sum(
            object_record.has_7z_signature for object_record in objects
        ),
        high_compression_ratio_count=sum(
            object_record.high_compression_ratio for object_record in objects
        ),
        empty_payload_count=sum(
            object_record.empty_payload for object_record in objects
        ),
        unique_sha256_count=len(hash_counts),
        duplicate_sha256_count=(duplicate_hash_count),
    )


def analyze_ooxml_embedded_objects(
    data: bytes,
    *,
    package_path: str | None = None,
    max_objects: int = DEFAULT_MAX_OBJECTS,
    max_object_size: int = DEFAULT_MAX_OBJECT_SIZE,
    max_total_embedded_size: int = (DEFAULT_MAX_TOTAL_EMBEDDED_SIZE),
) -> EmbeddedObjectAnalysis:
    """
    Analyze embedded payloads contained in an OOXML ZIP package.

    The ZIP is processed entirely in memory. Embedded members are never
    extracted to the host filesystem.

    Parameters
    ----------
    data:
        Raw OOXML ZIP bytes.

    package_path:
        Optional path of the source Office file.

    max_objects:
        Maximum number of embedded objects to inspect.

    max_object_size:
        Maximum uncompressed size of any single embedded object.

    max_total_embedded_size:
        Maximum aggregate uncompressed size of inspected embedded objects.
    """

    if max_objects <= 0:
        raise ValueError("max_objects must be greater than zero")

    if max_object_size <= 0:
        raise ValueError("max_object_size must be greater than zero")

    if max_total_embedded_size <= 0:
        raise ValueError("max_total_embedded_size must be greater than zero")

    if not data:
        return EmbeddedObjectAnalysis(
            package_path=package_path,
            package_is_zip=False,
            objects=(),
            statistics=calculate_statistics(()),
            total_package_members=0,
            candidate_member_count=0,
            truncated_by_object_limit=False,
            truncated_by_total_size_limit=False,
            parse_success=False,
            parse_error="Package data is empty",
        )

    if not zipfile.is_zipfile(io.BytesIO(data)):
        return EmbeddedObjectAnalysis(
            package_path=package_path,
            package_is_zip=False,
            objects=(),
            statistics=calculate_statistics(()),
            total_package_members=0,
            candidate_member_count=0,
            truncated_by_object_limit=False,
            truncated_by_total_size_limit=False,
            parse_success=False,
            parse_error=("Input is not a valid ZIP/OOXML package"),
        )

    objects: list[EmbeddedObjectRecord] = []

    truncated_by_object_limit = False
    truncated_by_total_size_limit = False

    try:
        with zipfile.ZipFile(
            io.BytesIO(data),
            "r",
        ) as archive:
            infos = archive.infolist()

            candidate_infos = [
                info
                for info in infos
                if not info.is_dir() and _looks_like_candidate(info)
            ]

            for index, info in enumerate(candidate_infos):
                if index >= max_objects:
                    truncated_by_object_limit = True
                    break

                if (
                    sum(object_record.uncompressed_size for object_record in objects)
                    + max(
                        0,
                        int(info.file_size),
                    )
                    > max_total_embedded_size
                ):
                    truncated_by_total_size_limit = True
                    break

                try:
                    payload = _read_zip_member_bounded(
                        archive,
                        info,
                        max_size=max_object_size,
                    )
                except (
                    OSError,
                    RuntimeError,
                    ValueError,
                    zipfile.BadZipFile,
                ):
                    # Keep scanning other candidates. One malformed member
                    # should not hide independent embedded objects.
                    continue

                record = _build_record(
                    info=info,
                    data=payload,
                )

                objects.append(record)

    except (
        OSError,
        RuntimeError,
        zipfile.BadZipFile,
    ) as exc:
        statistics = calculate_statistics(objects)

        return EmbeddedObjectAnalysis(
            package_path=package_path,
            package_is_zip=True,
            objects=tuple(objects),
            statistics=statistics,
            total_package_members=(len(infos) if "infos" in locals() else 0),
            candidate_member_count=(
                len(candidate_infos) if "candidate_infos" in locals() else 0
            ),
            truncated_by_object_limit=(truncated_by_object_limit),
            truncated_by_total_size_limit=(truncated_by_total_size_limit),
            parse_success=False,
            parse_error=(f"{type(exc).__name__}: {exc}"),
        )

    statistics = calculate_statistics(objects)

    return EmbeddedObjectAnalysis(
        package_path=package_path,
        package_is_zip=True,
        objects=tuple(objects),
        statistics=statistics,
        total_package_members=len(infos),
        candidate_member_count=len(candidate_infos),
        truncated_by_object_limit=(truncated_by_object_limit),
        truncated_by_total_size_limit=(truncated_by_total_size_limit),
        parse_success=True,
        parse_error=None,
    )


def analyze_ooxml_embedded_objects_file(
    file_path: str,
    *,
    max_objects: int = DEFAULT_MAX_OBJECTS,
    max_object_size: int = DEFAULT_MAX_OBJECT_SIZE,
    max_total_embedded_size: int = (DEFAULT_MAX_TOTAL_EMBEDDED_SIZE),
) -> EmbeddedObjectAnalysis:
    """
    Analyze an OOXML file from disk.

    The Office package itself is read into memory. Embedded members are never
    extracted to disk.
    """

    with open(
        file_path,
        "rb",
    ) as handle:
        data = handle.read()

    return analyze_ooxml_embedded_objects(
        data,
        package_path=file_path,
        max_objects=max_objects,
        max_object_size=max_object_size,
        max_total_embedded_size=(max_total_embedded_size),
    )


def embedded_object_features(
    analysis: EmbeddedObjectAnalysis,
) -> dict[str, Any]:
    """
    Convert embedded-object analysis into ML-ready scalar features.

    Hashes, filenames and raw payloads are intentionally excluded.
    """

    statistics = analysis.statistics

    features: dict[str, Any] = {
        "embedded_objects_version": (EMBEDDED_OBJECTS_VERSION),
        "embedded_objects_parse_success": (analysis.parse_success),
        "embedded_objects_package_is_zip": (analysis.package_is_zip),
        "embedded_objects_total_package_members": (analysis.total_package_members),
        "embedded_objects_candidate_member_count": (analysis.candidate_member_count),
        "embedded_objects_count": (statistics.object_count),
        "embedded_objects_total_compressed_size": (statistics.total_compressed_size),
        "embedded_objects_total_uncompressed_size": (
            statistics.total_uncompressed_size
        ),
        "embedded_objects_maximum_size": (statistics.maximum_object_size),
        "embedded_objects_average_size": (statistics.average_object_size),
        "embedded_objects_ole_count": (statistics.ole_count),
        "embedded_objects_package_count": (statistics.package_count),
        "embedded_objects_activex_count": (statistics.activex_count),
        "embedded_objects_control_count": (statistics.control_count),
        "embedded_objects_script_count": (statistics.script_count),
        "embedded_objects_executable_count": (statistics.executable_count),
        "embedded_objects_installer_count": (statistics.installer_count),
        "embedded_objects_archive_count": (statistics.archive_count),
        "embedded_objects_office_document_count": (statistics.office_document_count),
        "embedded_objects_document_count": (statistics.document_count),
        "embedded_objects_suspicious_extension_count": (
            statistics.suspicious_extension_count
        ),
        "embedded_objects_pe_signature_count": (statistics.pe_signature_count),
        "embedded_objects_elf_signature_count": (statistics.elf_signature_count),
        "embedded_objects_pdf_signature_count": (statistics.pdf_signature_count),
        "embedded_objects_rtf_signature_count": (statistics.rtf_signature_count),
        "embedded_objects_zip_signature_count": (statistics.zip_signature_count),
        "embedded_objects_ole_signature_count": (statistics.ole_signature_count),
        "embedded_objects_cab_signature_count": (statistics.cab_signature_count),
        "embedded_objects_gzip_signature_count": (statistics.gzip_signature_count),
        "embedded_objects_rar_signature_count": (statistics.rar_signature_count),
        "embedded_objects_7z_signature_count": (statistics.seven_zip_signature_count),
        "embedded_objects_high_compression_count": (
            statistics.high_compression_ratio_count
        ),
        "embedded_objects_empty_count": (statistics.empty_payload_count),
        "embedded_objects_unique_hash_count": (statistics.unique_sha256_count),
        "embedded_objects_duplicate_hash_count": (statistics.duplicate_sha256_count),
        "embedded_objects_truncated_object_limit": (analysis.truncated_by_object_limit),
        "embedded_objects_truncated_size_limit": (
            analysis.truncated_by_total_size_limit
        ),
        "embedded_objects_has_ole": (statistics.ole_count > 0),
        "embedded_objects_has_activex": (statistics.activex_count > 0),
        "embedded_objects_has_control": (statistics.control_count > 0),
        "embedded_objects_has_script": (statistics.script_count > 0),
        "embedded_objects_has_executable": (statistics.executable_count > 0),
        "embedded_objects_has_installer": (statistics.installer_count > 0),
        "embedded_objects_has_archive": (statistics.archive_count > 0),
        "embedded_objects_has_pe": (statistics.pe_signature_count > 0),
        "embedded_objects_has_elf": (statistics.elf_signature_count > 0),
        "embedded_objects_has_nested_zip": (statistics.zip_signature_count > 0),
        "embedded_objects_has_nested_ole": (statistics.ole_signature_count > 0),
        "embedded_objects_has_suspicious_extension": (
            statistics.suspicious_extension_count > 0
        ),
        "embedded_objects_has_high_compression": (
            statistics.high_compression_ratio_count > 0
        ),
        "embedded_objects_has_duplicates": (statistics.duplicate_sha256_count > 0),
    }

    return _round_floats(features)


def extract_embedded_object_features(
    data: bytes,
    *,
    package_path: str | None = None,
    max_objects: int = DEFAULT_MAX_OBJECTS,
    max_object_size: int = DEFAULT_MAX_OBJECT_SIZE,
    max_total_embedded_size: int = (DEFAULT_MAX_TOTAL_EMBEDDED_SIZE),
) -> dict[str, Any]:
    """
    Convenience wrapper for feature_pipeline.py.
    """

    analysis = analyze_ooxml_embedded_objects(
        data,
        package_path=package_path,
        max_objects=max_objects,
        max_object_size=max_object_size,
        max_total_embedded_size=(max_total_embedded_size),
    )

    return embedded_object_features(analysis)


def iter_embedded_objects(
    data: bytes,
    *,
    max_objects: int = DEFAULT_MAX_OBJECTS,
    max_object_size: int = DEFAULT_MAX_OBJECT_SIZE,
    max_total_embedded_size: int = (DEFAULT_MAX_TOTAL_EMBEDDED_SIZE),
) -> Iterable[tuple[EmbeddedObjectRecord, bytes]]:
    """
    Yield embedded-object metadata and payload bytes.

    This is intended for controlled downstream analysis, for example passing
    an OLE payload to ole.py.

    Payloads remain in memory and are never written to disk.
    """

    if not zipfile.is_zipfile(io.BytesIO(data)):
        return

    if max_objects <= 0:
        return

    if max_object_size <= 0:
        return

    if max_total_embedded_size <= 0:
        return

    total_size = 0
    yielded = 0

    with zipfile.ZipFile(
        io.BytesIO(data),
        "r",
    ) as archive:

        for info in archive.infolist():
            if yielded >= max_objects:
                break

            if info.is_dir():
                continue

            if not _looks_like_candidate(info):
                continue

            declared_size = max(
                0,
                int(info.file_size),
            )

            if declared_size > max_object_size:
                continue

            if total_size + declared_size > max_total_embedded_size:
                break

            try:
                payload = _read_zip_member_bounded(
                    archive,
                    info,
                    max_size=max_object_size,
                )
            except (
                OSError,
                RuntimeError,
                ValueError,
                zipfile.BadZipFile,
            ):
                continue

            record = _build_record(
                info=info,
                data=payload,
            )

            total_size += len(payload)
            yielded += 1

            yield record, payload


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
    "EMBEDDED_OBJECTS_VERSION",
    "EmbeddedObjectRecord",
    "EmbeddedObjectStatistics",
    "EmbeddedObjectAnalysis",
    "analyze_ooxml_embedded_objects",
    "analyze_ooxml_embedded_objects_file",
    "embedded_object_features",
    "extract_embedded_object_features",
    "iter_embedded_objects",
]
