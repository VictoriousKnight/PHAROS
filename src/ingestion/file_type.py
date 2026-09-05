"""
pharos-cdr.ingestion.file_type
==============================

Static file-type identification for the Pharos CDR ingestion layer.

This module identifies files primarily from their content (magic bytes and
lightweight structural signatures), with filename extensions used only as
supplementary metadata.

Security properties
-------------------
* Never executes or opens a document with an application.
* Never invokes external utilities such as `file`, `7z`, `unzip`, or Office.
* Never follows embedded references or URLs.
* Never decompresses archives.
* Never parses macros.
* Never loads OLE/COM objects.
* Never writes extracted content to disk.
* All inspection is bounded.

The output is intentionally generic so downstream modules can use it without
depending on a particular parser implementation.

Supported families include, among others:

* Microsoft Office OOXML
* legacy Microsoft OLE Compound File Binary Format
* PDF
* RTF
* ZIP
* GZIP
* BZIP2
* XZ
* 7-Zip
* RAR
* TAR
* PE
* ELF
* Mach-O
* Java class files
* WebAssembly
* SQLite
* common image/audio/video formats
* common text/script formats
* unknown binary data

The module does not claim that a file is safe merely because its type is
recognized. File-type identification is an ingestion primitive, not a malware
verdict.
"""

from __future__ import annotations

import dataclasses
import hashlib
import mimetypes
import os
import re
import struct
from dataclasses import dataclass, field
from pathlib import Path
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
)


# ---------------------------------------------------------------------------
# Limits
# ---------------------------------------------------------------------------

MAX_READ_SIZE = 64 * 1024
MAX_TEXT_SAMPLE = 32 * 1024
MAX_PATH_LENGTH = 4096
MAX_EXTENSION_LENGTH = 32


# ---------------------------------------------------------------------------
# Type families
# ---------------------------------------------------------------------------

FAMILY_DOCUMENT = "document"
FAMILY_ARCHIVE = "archive"
FAMILY_EXECUTABLE = "executable"
FAMILY_SCRIPT = "script"
FAMILY_IMAGE = "image"
FAMILY_AUDIO = "audio"
FAMILY_VIDEO = "video"
FAMILY_DATABASE = "database"
FAMILY_FONT = "font"
FAMILY_TEXT = "text"
FAMILY_BINARY = "binary"
FAMILY_UNKNOWN = "unknown"


# ---------------------------------------------------------------------------
# Public data structures
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FileSignature:
    """
    Static signature used to identify a file type.

    `offset` specifies where the signature is expected.
    `mask` optionally specifies a byte mask for signatures containing variable
    bytes.
    """

    name: str
    extension: str
    mime_type: str
    family: str
    magic: bytes
    offset: int = 0
    description: str = ""
    priority: int = 100
    mask: Optional[bytes] = None


@dataclass(frozen=True)
class FileTypeResult:
    """
    Result of static file-type identification.

    `confidence` describes confidence in the format identification itself,
    not confidence that the file is benign.
    """

    name: str
    extension: str
    mime_type: str
    family: str
    confidence: float
    method: str
    description: str = ""
    detected_extension: str = ""
    declared_extension: str = ""
    extension_mismatch: bool = False
    is_container: bool = False
    is_document: bool = False
    is_executable: bool = False
    is_script: bool = False
    is_text: bool = False
    is_unknown: bool = False
    size: int = 0
    sha256: str = ""
    sample_size: int = 0
    warnings: Tuple[str, ...] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)

    @property
    def recognized(self) -> bool:
        """Return True if a concrete file type was identified."""
        return not self.is_unknown


# ---------------------------------------------------------------------------
# Signature helpers
# ---------------------------------------------------------------------------


def _sig(
    name: str,
    extension: str,
    mime_type: str,
    family: str,
    magic: bytes,
    *,
    offset: int = 0,
    description: str = "",
    priority: int = 100,
    mask: Optional[bytes] = None,
) -> FileSignature:
    return FileSignature(
        name=name,
        extension=extension,
        mime_type=mime_type,
        family=family,
        magic=magic,
        offset=offset,
        description=description,
        priority=priority,
        mask=mask,
    )


# ---------------------------------------------------------------------------
# Static magic signatures
# ---------------------------------------------------------------------------

_SIGNATURES: Tuple[FileSignature, ...] = (
    # Microsoft / Office ----------------------------------------------------
    _sig(
        "ole_compound_file",
        ".ole",
        "application/x-ole-storage",
        FAMILY_DOCUMENT,
        b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",
        description="Microsoft Compound File Binary Format container.",
        priority=1000,
    ),
    _sig(
        "office_openxml",
        ".zip",
        "application/zip",
        FAMILY_DOCUMENT,
        b"PK\x03\x04",
        description="ZIP-based container potentially containing Office Open XML.",
        priority=850,
    ),
    # PDF / RTF -------------------------------------------------------------
    _sig(
        "pdf",
        ".pdf",
        "application/pdf",
        FAMILY_DOCUMENT,
        b"%PDF-",
        description="Portable Document Format.",
        priority=950,
    ),
    _sig(
        "rtf",
        ".rtf",
        "application/rtf",
        FAMILY_DOCUMENT,
        b"{\\rtf",
        description="Rich Text Format document.",
        priority=900,
    ),
    # Archives --------------------------------------------------------------
    _sig(
        "zip",
        ".zip",
        "application/zip",
        FAMILY_ARCHIVE,
        b"PK\x03\x04",
        description="ZIP archive.",
        priority=800,
    ),
    _sig(
        "zip_empty",
        ".zip",
        "application/zip",
        FAMILY_ARCHIVE,
        b"PK\x05\x06",
        description="Empty ZIP archive.",
        priority=800,
    ),
    _sig(
        "zip_spanned",
        ".zip",
        "application/zip",
        FAMILY_ARCHIVE,
        b"PK\x07\x08",
        description="Spanned ZIP archive.",
        priority=800,
    ),
    _sig(
        "gzip",
        ".gz",
        "application/gzip",
        FAMILY_ARCHIVE,
        b"\x1f\x8b",
        description="GZIP compressed data.",
        priority=800,
    ),
    _sig(
        "bzip2",
        ".bz2",
        "application/x-bzip2",
        FAMILY_ARCHIVE,
        b"BZh",
        description="BZIP2 compressed data.",
        priority=800,
    ),
    _sig(
        "xz",
        ".xz",
        "application/x-xz",
        FAMILY_ARCHIVE,
        b"\xfd7zXZ\x00",
        description="XZ compressed data.",
        priority=800,
    ),
    _sig(
        "seven_zip",
        ".7z",
        "application/x-7z-compressed",
        FAMILY_ARCHIVE,
        b"7z\xbc\xaf'\x1c",
        description="7-Zip archive.",
        priority=850,
    ),
    _sig(
        "rar",
        ".rar",
        "application/vnd.rar",
        FAMILY_ARCHIVE,
        b"Rar!\x1a\x07\x00",
        description="RAR archive.",
        priority=800,
    ),
    _sig(
        "rar5",
        ".rar",
        "application/vnd.rar",
        FAMILY_ARCHIVE,
        b"Rar!\x1a\x07\x01\x00",
        description="RAR 5 archive.",
        priority=800,
    ),
    _sig(
        "tar_ustar",
        ".tar",
        "application/x-tar",
        FAMILY_ARCHIVE,
        b"ustar",
        offset=257,
        description="POSIX tar archive.",
        priority=700,
    ),
    # Executables -----------------------------------------------------------
    _sig(
        "windows_pe",
        ".exe",
        "application/vnd.microsoft.portable-executable",
        FAMILY_EXECUTABLE,
        b"MZ",
        description="Windows PE-compatible executable header.",
        priority=950,
    ),
    _sig(
        "elf",
        ".elf",
        "application/x-elf",
        FAMILY_EXECUTABLE,
        b"\x7fELF",
        description="Executable and Linkable Format binary.",
        priority=950,
    ),
    _sig(
        "mach_o_32",
        ".mach-o",
        "application/x-mach-binary",
        FAMILY_EXECUTABLE,
        b"\xfe\xed\xfa\xce",
        description="32-bit Mach-O executable.",
        priority=950,
    ),
    _sig(
        "mach_o_64",
        ".mach-o",
        "application/x-mach-binary",
        FAMILY_EXECUTABLE,
        b"\xfe\xed\xfa\xcf",
        description="64-bit Mach-O executable.",
        priority=950,
    ),
    _sig(
        "mach_o_32_reverse",
        ".mach-o",
        "application/x-mach-binary",
        FAMILY_EXECUTABLE,
        b"\xce\xfa\xed\xfe",
        description="32-bit reverse-endian Mach-O executable.",
        priority=950,
    ),
    _sig(
        "mach_o_64_reverse",
        ".mach-o",
        "application/x-mach-binary",
        FAMILY_EXECUTABLE,
        b"\xcf\xfa\xed\xfe",
        description="64-bit reverse-endian Mach-O executable.",
        priority=950,
    ),
    _sig(
        "fat_mach_o",
        ".mach-o",
        "application/x-mach-binary",
        FAMILY_EXECUTABLE,
        b"\xca\xfe\xba\xbe",
        description="Mach-O universal/fat binary.",
        priority=940,
    ),
    _sig(
        "fat_mach_o_64",
        ".mach-o",
        "application/x-mach-binary",
        FAMILY_EXECUTABLE,
        b"\xca\xfe\xba\xbf",
        description="64-bit Mach-O universal/fat binary.",
        priority=940,
    ),
    # Bytecode / executable-like formats -----------------------------------
    _sig(
        "java_class",
        ".class",
        "application/java-vm",
        FAMILY_EXECUTABLE,
        b"\xca\xfe\xba\xbe",
        description="Java class file.",
        priority=900,
    ),
    _sig(
        "wasm",
        ".wasm",
        "application/wasm",
        FAMILY_EXECUTABLE,
        b"\x00asm",
        description="WebAssembly binary.",
        priority=900,
    ),
    # Databases -------------------------------------------------------------
    _sig(
        "sqlite3",
        ".sqlite",
        "application/vnd.sqlite3",
        FAMILY_DATABASE,
        b"SQLite format 3\x00",
        description="SQLite database.",
        priority=900,
    ),
    # Images ----------------------------------------------------------------
    _sig(
        "png",
        ".png",
        "image/png",
        FAMILY_IMAGE,
        b"\x89PNG\r\n\x1a\n",
        description="Portable Network Graphics image.",
        priority=900,
    ),
    _sig(
        "jpeg",
        ".jpg",
        "image/jpeg",
        FAMILY_IMAGE,
        b"\xff\xd8\xff",
        description="JPEG image.",
        priority=900,
    ),
    _sig(
        "gif",
        ".gif",
        "image/gif",
        FAMILY_IMAGE,
        b"GIF8",
        description="GIF image.",
        priority=900,
    ),
    _sig(
        "bmp",
        ".bmp",
        "image/bmp",
        FAMILY_IMAGE,
        b"BM",
        description="Bitmap image.",
        priority=700,
    ),
    _sig(
        "webp",
        ".webp",
        "image/webp",
        FAMILY_IMAGE,
        b"WEBP",
        offset=8,
        description="WebP image.",
        priority=850,
    ),
    _sig(
        "ico",
        ".ico",
        "image/x-icon",
        FAMILY_IMAGE,
        b"\x00\x00\x01\x00",
        description="Windows icon image.",
        priority=700,
    ),
    # Audio -----------------------------------------------------------------
    _sig(
        "wav",
        ".wav",
        "audio/wav",
        FAMILY_AUDIO,
        b"WAVE",
        offset=8,
        description="RIFF/WAVE audio.",
        priority=850,
    ),
    _sig(
        "flac",
        ".flac",
        "audio/flac",
        FAMILY_AUDIO,
        b"fLaC",
        description="FLAC audio.",
        priority=850,
    ),
    _sig(
        "ogg",
        ".ogg",
        "audio/ogg",
        FAMILY_AUDIO,
        b"OggS",
        description="Ogg container.",
        priority=800,
    ),
    _sig(
        "mp3",
        ".mp3",
        "audio/mpeg",
        FAMILY_AUDIO,
        b"ID3",
        description="MP3 audio with ID3 metadata.",
        priority=650,
    ),
    # Video -----------------------------------------------------------------
    _sig(
        "avi",
        ".avi",
        "video/x-msvideo",
        FAMILY_VIDEO,
        b"AVI ",
        offset=8,
        description="AVI video.",
        priority=850,
    ),
    _sig(
        "webm",
        ".webm",
        "video/webm",
        FAMILY_VIDEO,
        b"\x1a\x45\xdf\xa3",
        description="EBML/WebM-style container.",
        priority=700,
    ),
    _sig(
        "mp4",
        ".mp4",
        "video/mp4",
        FAMILY_VIDEO,
        b"ftyp",
        offset=4,
        description="ISO Base Media / MP4-family container.",
        priority=750,
    ),
    # Fonts -----------------------------------------------------------------
    _sig(
        "truetype",
        ".ttf",
        "font/ttf",
        FAMILY_FONT,
        b"\x00\x01\x00\x00",
        description="TrueType font.",
        priority=750,
    ),
    _sig(
        "opentype",
        ".otf",
        "font/otf",
        FAMILY_FONT,
        b"OTTO",
        description="OpenType font.",
        priority=750,
    ),
    _sig(
        "woff",
        ".woff",
        "font/woff",
        FAMILY_FONT,
        b"wOFF",
        description="Web Open Font Format.",
        priority=750,
    ),
    _sig(
        "woff2",
        ".woff2",
        "font/woff2",
        FAMILY_FONT,
        b"wOF2",
        description="Web Open Font Format 2.",
        priority=750,
    ),
)


# ---------------------------------------------------------------------------
# Extension mappings
# ---------------------------------------------------------------------------

_EXTENSION_MAP: Dict[str, Tuple[str, str, str]] = {
    ".doc": ("legacy_word", "application/msword", FAMILY_DOCUMENT),
    ".dot": ("legacy_word_template", "application/msword", FAMILY_DOCUMENT),
    ".xls": ("legacy_excel", "application/vnd.ms-excel", FAMILY_DOCUMENT),
    ".xlt": ("legacy_excel_template", "application/vnd.ms-excel", FAMILY_DOCUMENT),
    ".ppt": (
        "legacy_powerpoint",
        "application/vnd.ms-powerpoint",
        FAMILY_DOCUMENT,
    ),
    ".pot": (
        "legacy_powerpoint_template",
        "application/vnd.ms-powerpoint",
        FAMILY_DOCUMENT,
    ),
    ".docx": (
        "word_openxml",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        FAMILY_DOCUMENT,
    ),
    ".docm": (
        "word_openxml_macro_enabled",
        "application/vnd.ms-word.document.macroEnabled.12",
        FAMILY_DOCUMENT,
    ),
    ".dotx": (
        "word_openxml_template",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.template",
        FAMILY_DOCUMENT,
    ),
    ".dotm": (
        "word_openxml_macro_enabled_template",
        "application/vnd.ms-word.template.macroEnabled.12",
        FAMILY_DOCUMENT,
    ),
    ".xlsm": (
        "excel_openxml_macro_enabled",
        "application/vnd.ms-excel.sheet.macroEnabled.12",
        FAMILY_DOCUMENT,
    ),
    ".xlsx": (
        "excel_openxml",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        FAMILY_DOCUMENT,
    ),
    ".xltm": (
        "excel_openxml_macro_enabled_template",
        "application/vnd.ms-excel.template.macroEnabled.12",
        FAMILY_DOCUMENT,
    ),
    ".xltx": (
        "excel_openxml_template",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.template",
        FAMILY_DOCUMENT,
    ),
    ".pptx": (
        "powerpoint_openxml",
        "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        FAMILY_DOCUMENT,
    ),
    ".pptm": (
        "powerpoint_openxml_macro_enabled",
        "application/vnd.ms-powerpoint.presentation.macroEnabled.12",
        FAMILY_DOCUMENT,
    ),
    ".ppsx": (
        "powerpoint_openxml_slideshow",
        "application/vnd.openxmlformats-officedocument.presentationml.slideshow",
        FAMILY_DOCUMENT,
    ),
    ".ppsm": (
        "powerpoint_openxml_macro_enabled_slideshow",
        "application/vnd.ms-powerpoint.slideshow.macroEnabled.12",
        FAMILY_DOCUMENT,
    ),
    ".pdf": ("pdf", "application/pdf", FAMILY_DOCUMENT),
    ".rtf": ("rtf", "application/rtf", FAMILY_DOCUMENT),
    ".txt": ("plain_text", "text/plain", FAMILY_TEXT),
    ".csv": ("csv", "text/csv", FAMILY_TEXT),
    ".tsv": ("tsv", "text/tab-separated-values", FAMILY_TEXT),
    ".json": ("json", "application/json", FAMILY_TEXT),
    ".xml": ("xml", "application/xml", FAMILY_TEXT),
    ".html": ("html", "text/html", FAMILY_TEXT),
    ".htm": ("html", "text/html", FAMILY_TEXT),
    ".js": ("javascript", "text/javascript", FAMILY_SCRIPT),
    ".jse": ("javascript_encoded", "text/javascript", FAMILY_SCRIPT),
    ".vbs": ("vbscript", "text/vbscript", FAMILY_SCRIPT),
    ".vbe": ("vbscript_encoded", "text/vbscript", FAMILY_SCRIPT),
    ".ps1": (
        "powershell",
        "application/x-powershell",
        FAMILY_SCRIPT,
    ),
    ".psm1": (
        "powershell_module",
        "application/x-powershell",
        FAMILY_SCRIPT,
    ),
    ".psd1": (
        "powershell_data",
        "application/x-powershell",
        FAMILY_SCRIPT,
    ),
    ".bat": ("batch", "application/x-bat", FAMILY_SCRIPT),
    ".cmd": ("windows_command_script", "application/x-cmd", FAMILY_SCRIPT),
    ".sh": ("shell_script", "application/x-sh", FAMILY_SCRIPT),
    ".py": ("python", "text/x-python", FAMILY_SCRIPT),
    ".rb": ("ruby", "text/x-ruby", FAMILY_SCRIPT),
    ".pl": ("perl", "text/x-perl", FAMILY_SCRIPT),
    ".php": ("php", "application/x-httpd-php", FAMILY_SCRIPT),
    ".zip": ("zip", "application/zip", FAMILY_ARCHIVE),
    ".gz": ("gzip", "application/gzip", FAMILY_ARCHIVE),
    ".bz2": ("bzip2", "application/x-bzip2", FAMILY_ARCHIVE),
    ".xz": ("xz", "application/x-xz", FAMILY_ARCHIVE),
    ".7z": ("seven_zip", "application/x-7z-compressed", FAMILY_ARCHIVE),
    ".rar": ("rar", "application/vnd.rar", FAMILY_ARCHIVE),
    ".tar": ("tar", "application/x-tar", FAMILY_ARCHIVE),
    ".exe": (
        "windows_pe",
        "application/vnd.microsoft.portable-executable",
        FAMILY_EXECUTABLE,
    ),
    ".dll": (
        "windows_pe_dll",
        "application/vnd.microsoft.portable-executable",
        FAMILY_EXECUTABLE,
    ),
    ".sys": (
        "windows_pe_driver",
        "application/vnd.microsoft.portable-executable",
        FAMILY_EXECUTABLE,
    ),
    ".elf": ("elf", "application/x-elf", FAMILY_EXECUTABLE),
    ".so": ("elf_shared_object", "application/x-elf", FAMILY_EXECUTABLE),
    ".dylib": (
        "mach_o_shared_library",
        "application/x-mach-binary",
        FAMILY_EXECUTABLE,
    ),
    ".class": ("java_class", "application/java-vm", FAMILY_EXECUTABLE),
    ".wasm": ("wasm", "application/wasm", FAMILY_EXECUTABLE),
    ".sqlite": ("sqlite3", "application/vnd.sqlite3", FAMILY_DATABASE),
    ".db": ("database", "application/octet-stream", FAMILY_DATABASE),
}


# ---------------------------------------------------------------------------
# Extension helpers
# ---------------------------------------------------------------------------


def normalize_extension(value: Any) -> str:
    """
    Normalize a filename extension.

    Examples
    --------
    >>> normalize_extension("DOCM")
    '.docm'
    >>> normalize_extension("report.docx")
    '.docx'
    """
    if value is None:
        return ""

    text = str(value).strip().lower()

    if not text:
        return ""

    if "/" in text or "\\" in text:
        text = Path(text).suffix.lower()
    elif not text.startswith("."):
        text = "." + text

    if len(text) > MAX_EXTENSION_LENGTH:
        return ""

    if not re.fullmatch(r"\.[a-z0-9][a-z0-9._+-]*", text):
        return ""

    return text


def declared_extension(path_or_name: Any) -> str:
    """Return the normalized extension declared by a filename/path."""
    if path_or_name is None:
        return ""

    try:
        return normalize_extension(Path(str(path_or_name)).suffix)
    except Exception:
        return ""


def extension_metadata(
    extension: str,
) -> Dict[str, str]:
    """Return metadata associated with a known extension."""
    normalized = normalize_extension(extension)

    if normalized in _EXTENSION_MAP:
        name, mime_type, family = _EXTENSION_MAP[normalized]
        return {
            "name": name,
            "mime_type": mime_type,
            "family": family,
        }

    guessed_mime, _ = mimetypes.guess_type("file" + normalized)

    return {
        "name": "unknown",
        "mime_type": guessed_mime or "application/octet-stream",
        "family": FAMILY_UNKNOWN,
    }


# ---------------------------------------------------------------------------
# Byte handling
# ---------------------------------------------------------------------------


def _read_sample(
    source: Any,
    max_bytes: int = MAX_READ_SIZE,
) -> Tuple[bytes, int, str]:
    """
    Read a bounded sample from bytes or a filesystem path.

    Returns:
        (sample, total_size, warning)
    """
    if isinstance(source, bytes):
        sample = source[:max_bytes]
        return sample, len(source), ""

    if isinstance(source, bytearray):
        raw = bytes(source)
        return raw[:max_bytes], len(raw), ""

    if isinstance(source, memoryview):
        raw = source.tobytes()
        return raw[:max_bytes], len(raw), ""

    if isinstance(source, os.PathLike):
        path = Path(source)

        try:
            stat = path.stat()
        except OSError as exc:
            return b"", 0, f"unable_to_stat:{type(exc).__name__}"

        if not path.is_file():
            return b"", int(stat.st_size), "source_is_not_regular_file"

        try:
            with path.open("rb") as handle:
                sample = handle.read(max_bytes)
        except OSError as exc:
            return b"", int(stat.st_size), f"unable_to_read:{type(exc).__name__}"

        return sample, min(int(stat.st_size), MAX_SOURCE_SIZE), ""

    if isinstance(source, str):
        path = Path(source)

        if path.exists():
            return _read_sample(path, max_bytes)

        raw = source.encode("utf-8", errors="replace")
        return raw[:max_bytes], len(raw), ""

    return b"", 0, "unsupported_source_type"


def _matches_signature(
    sample: bytes,
    signature: FileSignature,
) -> bool:
    """Check a signature against bounded bytes."""
    start = signature.offset
    end = start + len(signature.magic)

    if start < 0 or end > len(sample):
        return False

    observed = sample[start:end]

    if signature.mask is None:
        return observed == signature.magic

    if len(signature.mask) != len(signature.magic):
        return False

    return all(
        (observed[index] & signature.mask[index])
        == (signature.magic[index] & signature.mask[index])
        for index in range(len(signature.magic))
    )


# ---------------------------------------------------------------------------
# Structural format checks
# ---------------------------------------------------------------------------


def _looks_like_ooxml(sample: bytes) -> bool:
    """
    Identify likely Office Open XML content without opening/extracting ZIP data.

    We only inspect a bounded byte sample for characteristic OOXML path names.
    """
    if not sample.startswith(b"PK"):
        return False

    markers = (
        b"[Content_Types].xml",
        b"word/",
        b"xl/",
        b"ppt/",
        b"_rels/",
    )

    return any(marker in sample for marker in markers)


def _looks_like_pdf(sample: bytes) -> bool:
    """Check for a PDF header within the initial bounded sample."""
    return sample.startswith(b"%PDF-")


def _looks_like_rtf(sample: bytes) -> bool:
    """Check for the RTF opening signature."""
    return sample.startswith(b"{\\rtf")


def _looks_like_pe(sample: bytes) -> bool:
    """
    Identify PE files conservatively.

    A DOS MZ header alone is insufficient to conclusively identify a PE.
    When enough bytes are available, inspect e_lfanew and verify PE\\0\\0.
    """
    if len(sample) < 2 or sample[:2] != b"MZ":
        return False

    if len(sample) < 0x40:
        return True

    try:
        pe_offset = struct.unpack_from("<I", sample, 0x3C)[0]
    except struct.error:
        return True

    if pe_offset < 0 or pe_offset + 4 > len(sample):
        return True

    return sample[pe_offset : pe_offset + 4] == b"PE\x00\x00"


def _looks_like_tar(sample: bytes) -> bool:
    """Check the standard tar ustar marker."""
    return len(sample) >= 262 and sample[257:262] == b"ustar"


def _looks_like_text(sample: bytes) -> bool:
    """
    Estimate whether a sample is text.

    This is deliberately conservative and only used as a fallback when no
    stronger binary signature is present.
    """
    if not sample:
        return False

    if b"\x00" in sample:
        return False

    printable = 0
    examined = min(len(sample), MAX_TEXT_SAMPLE)

    for byte in sample[:examined]:
        if byte in (9, 10, 13) or 32 <= byte <= 126:
            printable += 1

    return printable / max(1, examined) >= 0.85


def _detect_script_from_text(sample: bytes) -> Optional[Tuple[str, str]]:
    """Detect common script formats from bounded textual content."""
    if not sample:
        return None

    text = sample[:MAX_TEXT_SAMPLE].decode(
        "utf-8",
        errors="ignore",
    )

    if not text:
        return None

    lowered = text.lower()

    powershell_markers = (
        "powershell",
        "pwsh",
        "invoke-expression",
        "invoke-command",
        "frombase64string",
    )

    if any(marker in lowered for marker in powershell_markers):
        return (
            "powershell",
            "application/x-powershell",
        )

    javascript_markers = (
        "javascript:",
        "function(",
        "function ",
        "eval(",
        "wscript.createobject",
        "activexobject",
    )

    if any(marker in lowered for marker in javascript_markers):
        return (
            "javascript",
            "text/javascript",
        )

    vbscript_markers = (
        "createobject(",
        "wscript.shell",
        "on error resume next",
        "dim ",
        "set ",
    )

    if any(marker in lowered for marker in vbscript_markers):
        return (
            "vbscript",
            "text/vbscript",
        )

    shell_markers = (
        "#!/bin/sh",
        "#!/bin/bash",
        "#!/usr/bin/env bash",
        "#!/usr/bin/env sh",
    )

    if any(marker in lowered for marker in shell_markers):
        return (
            "shell_script",
            "application/x-sh",
        )

    batch_markers = (
        "@echo off",
        "cmd.exe",
        "setlocal",
        "%%~",
    )

    if any(marker in lowered for marker in batch_markers):
        return (
            "batch",
            "application/x-bat",
        )

    python_markers = (
        "#!/usr/bin/python",
        "#!/usr/bin/env python",
        "import os",
        "import sys",
        "def ",
    )

    if any(marker in lowered for marker in python_markers):
        return (
            "python",
            "text/x-python",
        )

    return None


def _detect_riff_subtype(sample: bytes) -> Optional[Tuple[str, str, str]]:
    """Identify common RIFF subtypes."""
    if len(sample) < 12 or sample[:4] != b"RIFF":
        return None

    subtype = sample[8:12]

    if subtype == b"WAVE":
        return "wav", "audio/wav", FAMILY_AUDIO

    if subtype == b"AVI ":
        return "avi", "video/x-msvideo", FAMILY_VIDEO

    if subtype == b"WEBP":
        return "webp", "image/webp", FAMILY_IMAGE

    return None


def _detect_mp4_family(sample: bytes) -> bool:
    """Detect an ISO Base Media container using its ftyp box."""
    return len(sample) >= 12 and sample[4:8] == b"ftyp"


# ---------------------------------------------------------------------------
# Content-based identification
# ---------------------------------------------------------------------------


def identify_from_bytes(
    data: bytes,
    *,
    declared_extension: str = "",
    include_hash: bool = True,
) -> FileTypeResult:
    """
    Identify a file from bounded content bytes.

    This function never executes the supplied bytes.
    """
    if not isinstance(data, bytes):
        data = bytes(data)

    bounded = data[:MAX_SOURCE_SIZE]
    sample = bounded[:MAX_READ_SIZE]

    declared = normalize_extension(declared_extension)
    warnings: List[str] = []

    detected_name = "unknown"
    detected_extension = ""
    mime_type = "application/octet-stream"
    family = FAMILY_UNKNOWN
    description = ""
    method = "unknown"
    confidence = 0.0

    # Strong structural checks first.
    if _looks_like_pe(sample):
        detected_name = "windows_pe"
        detected_extension = ".exe"
        mime_type = "application/vnd.microsoft.portable-executable"
        family = FAMILY_EXECUTABLE
        description = "Windows PE-compatible executable header."
        method = "magic+structure"
        confidence = 0.99

    elif _looks_like_ooxml(sample):
        detected_name = "office_openxml"
        detected_extension = ".zip"
        mime_type = "application/zip"
        family = FAMILY_DOCUMENT
        description = "ZIP-based Office Open XML container identified by OOXML markers."
        method = "magic+structure"
        confidence = 0.98

    elif _looks_like_pdf(sample):
        detected_name = "pdf"
        detected_extension = ".pdf"
        mime_type = "application/pdf"
        family = FAMILY_DOCUMENT
        description = "Portable Document Format."
        method = "magic"
        confidence = 0.99

    elif _looks_like_rtf(sample):
        detected_name = "rtf"
        detected_extension = ".rtf"
        mime_type = "application/rtf"
        family = FAMILY_DOCUMENT
        description = "Rich Text Format document."
        method = "magic"
        confidence = 0.99

    else:
        riff = _detect_riff_subtype(sample)

        if riff is not None:
            detected_name, mime_type, family = riff
            detected_extension = {
                "wav": ".wav",
                "avi": ".avi",
                "webp": ".webp",
            }[detected_name]
            description = f"{detected_name.upper()} RIFF container."
            method = "magic+structure"
            confidence = 0.98

        elif _detect_mp4_family(sample):
            detected_name = "mp4"
            detected_extension = ".mp4"
            mime_type = "video/mp4"
            family = FAMILY_VIDEO
            description = "ISO Base Media / MP4-family container."
            method = "magic+structure"
            confidence = 0.94

        elif _looks_like_tar(sample):
            detected_name = "tar"
            detected_extension = ".tar"
            mime_type = "application/x-tar"
            family = FAMILY_ARCHIVE
            description = "POSIX tar archive."
            method = "magic+structure"
            confidence = 0.97

        else:
            matches = [
                signature
                for signature in _SIGNATURES
                if _matches_signature(sample, signature)
            ]

            if matches:
                matches.sort(
                    key=lambda item: item.priority,
                    reverse=True,
                )

                match = matches[0]

                detected_name = match.name
                detected_extension = match.extension
                mime_type = match.mime_type
                family = match.family
                description = match.description
                method = "magic"
                confidence = 0.96

    # Text/script fallback.
    if family == FAMILY_UNKNOWN and _looks_like_text(sample):
        script = _detect_script_from_text(sample)

        if script is not None:
            detected_name, mime_type = script
            family = FAMILY_SCRIPT

            extension_by_name = {
                "powershell": ".ps1",
                "javascript": ".js",
                "vbscript": ".vbs",
                "shell_script": ".sh",
                "batch": ".bat",
                "python": ".py",
            }

            detected_extension = extension_by_name.get(
                detected_name,
                ".txt",
            )

            description = f"Textual {detected_name} source."
            method = "text-heuristic"
            confidence = 0.88

        else:
            detected_name = "plain_text"
            detected_extension = ".txt"
            mime_type = "text/plain"
            family = FAMILY_TEXT
            description = "Textual data without a stronger format signature."
            method = "text-heuristic"
            confidence = 0.78

    if family == FAMILY_UNKNOWN:
        warnings.append("file_type_not_recognized")

    if declared and detected_extension:
        # OOXML is represented by a generic ZIP magic signature internally,
        # but should still be compared against the document extension.
        if (
            declared
            in {
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
                ".ppsx",
                ".ppsm",
            }
            and detected_name == "office_openxml"
        ):
            extension_mismatch = False
        else:
            extension_mismatch = declared != detected_extension

        if extension_mismatch:
            warnings.append(f"extension_mismatch:{declared}->{detected_extension}")
    else:
        extension_mismatch = False

    if declared and declared in _EXTENSION_MAP:
        declared_name = _EXTENSION_MAP[declared][0]
    else:
        declared_name = ""

    sha256 = ""
    if include_hash:
        sha256 = hashlib.sha256(bounded).hexdigest()

    return FileTypeResult(
        name=detected_name,
        extension=detected_extension,
        mime_type=mime_type,
        family=family,
        confidence=max(0.0, min(1.0, confidence)),
        method=method,
        description=description,
        detected_extension=detected_extension,
        declared_extension=declared,
        extension_mismatch=extension_mismatch,
        is_container=family
        in {
            FAMILY_ARCHIVE,
            FAMILY_DOCUMENT,
        },
        is_document=family == FAMILY_DOCUMENT,
        is_executable=family == FAMILY_EXECUTABLE,
        is_script=family == FAMILY_SCRIPT,
        is_text=family == FAMILY_TEXT,
        is_unknown=family == FAMILY_UNKNOWN,
        size=len(data),
        sha256=sha256,
        sample_size=len(sample),
        warnings=tuple(warnings),
        metadata={
            "declared_type": declared_name,
            "method": method,
            "content_sample_bounded": len(data) > MAX_READ_SIZE,
            "source_bounded": len(data) > MAX_SOURCE_SIZE,
        },
    )


# ---------------------------------------------------------------------------
# Filesystem identification
# ---------------------------------------------------------------------------


def identify_file(
    path: os.PathLike[str] | str,
    *,
    include_hash: bool = True,
) -> FileTypeResult:
    """
    Identify a filesystem file without executing or dynamically opening it.

    Only a bounded prefix is read.
    """
    file_path = Path(path)

    declared = declared_extension(file_path)

    sample, total_size, warning = _read_sample(
        file_path,
        MAX_READ_SIZE,
    )

    result = identify_from_bytes(
        sample,
        declared_extension=declared,
        include_hash=False,
    )

    sha256 = ""

    if include_hash:
        digest = hashlib.sha256()

        try:
            with file_path.open("rb") as handle:
                remaining = MAX_SOURCE_SIZE

                while remaining > 0:
                    chunk = handle.read(min(1024 * 1024, remaining))
                    if not chunk:
                        break

                    digest.update(chunk)
                    remaining -= len(chunk)

            sha256 = digest.hexdigest()

        except OSError:
            sha256 = ""

    warnings = list(result.warnings)

    if warning:
        warnings.append(warning)

    return dataclasses.replace(
        result,
        size=total_size,
        sha256=sha256,
        warnings=tuple(dict.fromkeys(warnings)),
        metadata={
            **dict(result.metadata),
            "path_name": file_path.name[:MAX_PATH_LENGTH],
        },
    )


# ---------------------------------------------------------------------------
# Generic identification API
# ---------------------------------------------------------------------------


def identify(
    source: Any,
    *,
    declared_extension: str = "",
    include_hash: bool = True,
) -> FileTypeResult:
    """
    Identify bytes, bytearray, memoryview, path, or textual source.

    For strings that point to existing files, the file is inspected.
    Otherwise the string is treated as content.
    """
    if isinstance(source, (bytes, bytearray, memoryview)):
        return identify_from_bytes(
            bytes(source),
            declared_extension=declared_extension,
            include_hash=include_hash,
        )

    if isinstance(source, os.PathLike):
        return identify_file(
            source,
            include_hash=include_hash,
        )

    if isinstance(source, str):
        path = Path(source)

        try:
            if path.exists():
                return identify_file(
                    path,
                    include_hash=include_hash,
                )
        except OSError:
            pass

        return identify_from_bytes(
            source.encode("utf-8", errors="replace"),
            declared_extension=declared_extension,
            include_hash=include_hash,
        )

    raise TypeError("source must be bytes, bytearray, memoryview, str, or os.PathLike")


# ---------------------------------------------------------------------------
# Classification helpers
# ---------------------------------------------------------------------------


def is_office_document(result: FileTypeResult) -> bool:
    """Return True for recognized legacy or OOXML Office document types."""
    if result.family != FAMILY_DOCUMENT:
        return False

    office_names = {
        "ole_compound_file",
        "office_openxml",
        "legacy_word",
        "legacy_word_template",
        "legacy_excel",
        "legacy_excel_template",
        "legacy_powerpoint",
        "legacy_powerpoint_template",
        "word_openxml",
        "word_openxml_macro_enabled",
        "word_openxml_template",
        "word_openxml_macro_enabled_template",
        "excel_openxml",
        "excel_openxml_macro_enabled",
        "excel_openxml_template",
        "excel_openxml_macro_enabled_template",
        "powerpoint_openxml",
        "powerpoint_openxml_macro_enabled",
        "powerpoint_openxml_slideshow",
        "powerpoint_openxml_macro_enabled_slideshow",
    }

    return result.name in office_names


def is_macro_capable(result: FileTypeResult) -> bool:
    """Return True for formats commonly capable of carrying Office macros."""
    return result.name in {
        "ole_compound_file",
        "word_openxml_macro_enabled",
        "word_openxml_macro_enabled_template",
        "excel_openxml_macro_enabled",
        "excel_openxml_macro_enabled_template",
        "powerpoint_openxml_macro_enabled",
        "powerpoint_openxml_macro_enabled_slideshow",
    } or result.declared_extension in {
        ".docm",
        ".dotm",
        ".xlsm",
        ".xltm",
        ".pptm",
        ".ppsm",
        ".doc",
        ".dot",
        ".xls",
        ".xlt",
        ".ppt",
        ".pot",
    }


def is_archive(result: FileTypeResult) -> bool:
    """Return True for archive/compression formats."""
    return result.family == FAMILY_ARCHIVE


def is_executable(result: FileTypeResult) -> bool:
    """Return True for executable binary formats."""
    return result.family == FAMILY_EXECUTABLE


def is_script(result: FileTypeResult) -> bool:
    """Return True for script formats."""
    return result.family == FAMILY_SCRIPT


def is_document(result: FileTypeResult) -> bool:
    """Return True for document formats."""
    return result.family == FAMILY_DOCUMENT


def has_extension_mismatch(result: FileTypeResult) -> bool:
    """Return True if filename extension conflicts with detected content."""
    return result.extension_mismatch


# ---------------------------------------------------------------------------
# Signature inspection APIs
# ---------------------------------------------------------------------------


def iter_signatures() -> Iterator[FileSignature]:
    """Iterate through the built-in static signature database."""
    yield from sorted(
        _SIGNATURES,
        key=lambda item: (-item.priority, item.name),
    )


def known_extensions() -> Tuple[str, ...]:
    """Return all known normalized extensions."""
    return tuple(sorted(_EXTENSION_MAP))


def signatures_for_extension(
    extension: str,
) -> Tuple[FileSignature, ...]:
    """Return built-in signatures associated with an extension."""
    normalized = normalize_extension(extension)

    return tuple(
        signature
        for signature in iter_signatures()
        if signature.extension == normalized
    )


# ---------------------------------------------------------------------------
# Serialization
# ---------------------------------------------------------------------------


def result_to_dict(
    result: FileTypeResult,
) -> Dict[str, Any]:
    """Convert a FileTypeResult to JSON-compatible primitives."""
    return {
        "name": result.name,
        "extension": result.extension,
        "mime_type": result.mime_type,
        "family": result.family,
        "confidence": result.confidence,
        "method": result.method,
        "description": result.description,
        "detected_extension": result.detected_extension,
        "declared_extension": result.declared_extension,
        "extension_mismatch": result.extension_mismatch,
        "is_container": result.is_container,
        "is_document": result.is_document,
        "is_executable": result.is_executable,
        "is_script": result.is_script,
        "is_text": result.is_text,
        "is_unknown": result.is_unknown,
        "recognized": result.recognized,
        "size": result.size,
        "sha256": result.sha256,
        "sample_size": result.sample_size,
        "warnings": list(result.warnings),
        "metadata": dict(result.metadata),
    }


def summarize(result: FileTypeResult) -> Dict[str, Any]:
    """Return a compact ingestion-oriented summary."""
    return {
        "type": result.name,
        "family": result.family,
        "mime_type": result.mime_type,
        "confidence": result.confidence,
        "declared_extension": result.declared_extension,
        "detected_extension": result.detected_extension,
        "extension_mismatch": result.extension_mismatch,
        "is_office": is_office_document(result),
        "macro_capable": is_macro_capable(result),
        "is_archive": is_archive(result),
        "is_executable": is_executable(result),
        "is_script": is_script(result),
        "size": result.size,
        "sha256": result.sha256,
        "warnings": list(result.warnings),
    }


# ---------------------------------------------------------------------------
# Compatibility aliases
# ---------------------------------------------------------------------------


detect = identify
detect_file_type = identify
analyze_file_type = identify
file_type = identify
analyze = identify


# ---------------------------------------------------------------------------
# PUBLIC APIs
# ---------------------------------------------------------------------------
#
# Core types:
#   FileSignature
#   FileTypeResult
#
# Identification:
#   identify
#   identify_from_bytes
#   identify_file
#   detect
#   detect_file_type
#   analyze_file_type
#   file_type
#   analyze
#
# Extension handling:
#   normalize_extension
#   declared_extension
#   extension_metadata
#
# Classification:
#   is_office_document
#   is_macro_capable
#   is_archive
#   is_executable
#   is_script
#   is_document
#   has_extension_mismatch
#
# Signature database:
#   iter_signatures
#   known_extensions
#   signatures_for_extension
#
# Serialization/reporting:
#   result_to_dict
#   summarize
#
# Safety:
#   This module performs content-based static identification only. It does not
#   execute files, invoke interpreters, follow URLs, decompress archives,
#   instantiate Office/COM objects, parse macros, or modify the host system.
# ---------------------------------------------------------------------------

__all__ = [
    "FileSignature",
    "FileTypeResult",
    "identify",
    "identify_from_bytes",
    "identify_file",
    "detect",
    "detect_file_type",
    "analyze_file_type",
    "file_type",
    "analyze",
    "normalize_extension",
    "declared_extension",
    "extension_metadata",
    "is_office_document",
    "is_macro_capable",
    "is_archive",
    "is_executable",
    "is_script",
    "is_document",
    "has_extension_mismatch",
    "iter_signatures",
    "known_extensions",
    "signatures_for_extension",
    "result_to_dict",
    "summarize",
]
