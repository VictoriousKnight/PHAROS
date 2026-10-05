"""
Static file-type identification for Pharos CDR.

This module identifies files from bounded content signatures and lightweight
text/structure heuristics. It never executes files, decompresses archives,
parses macros, follows URLs, or invokes external utilities.
"""

from __future__ import annotations

import hashlib
import mimetypes
import os
import re
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator, Mapping

# ---------------------------------------------------------------------------
# Limits
# ---------------------------------------------------------------------------

MAX_READ_SIZE = 64 * 1024
MAX_EXTENSION_LENGTH = 32
MAX_TEXT_SAMPLE = 32 * 1024
MAX_SOURCE_SIZE = 64 * 1024 * 1024
HASH_CHUNK_SIZE = 1024 * 1024

# ---------------------------------------------------------------------------
# Families
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
# Public result types
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FileSignature:
    name: str
    extension: str
    mime_type: str
    family: str
    magic: bytes
    offset: int = 0
    description: str = ""
    priority: int = 100


@dataclass(frozen=True)
class FileTypeResult:
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

    warnings: tuple[str, ...] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)

    @property
    def recognized(self) -> bool:
        return not self.is_unknown


# ---------------------------------------------------------------------------
# Signature database
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
) -> FileSignature:
    return FileSignature(
        name,
        extension,
        mime_type,
        family,
        magic,
        offset,
        description,
        priority,
    )


_SIGNATURES = (
    # Office / documents
    _sig(
        "ole_compound_file",
        ".ole",
        "application/x-ole-storage",
        FAMILY_DOCUMENT,
        b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",
        priority=1000,
    ),
    _sig(
        "pdf",
        ".pdf",
        "application/pdf",
        FAMILY_DOCUMENT,
        b"%PDF-",
        priority=950,
    ),
    _sig(
        "rtf",
        ".rtf",
        "application/rtf",
        FAMILY_DOCUMENT,
        b"{\\rtf",
        priority=900,
    ),
    # Archives
    _sig("zip", ".zip", "application/zip", FAMILY_ARCHIVE, b"PK\x03\x04", priority=800),
    _sig(
        "zip_empty",
        ".zip",
        "application/zip",
        FAMILY_ARCHIVE,
        b"PK\x05\x06",
        priority=800,
    ),
    _sig(
        "zip_spanned",
        ".zip",
        "application/zip",
        FAMILY_ARCHIVE,
        b"PK\x07\x08",
        priority=800,
    ),
    _sig("gzip", ".gz", "application/gzip", FAMILY_ARCHIVE, b"\x1f\x8b", priority=800),
    _sig("bzip2", ".bz2", "application/x-bzip2", FAMILY_ARCHIVE, b"BZh", priority=800),
    _sig(
        "xz", ".xz", "application/x-xz", FAMILY_ARCHIVE, b"\xfd7zXZ\x00", priority=800
    ),
    _sig(
        "seven_zip",
        ".7z",
        "application/x-7z-compressed",
        FAMILY_ARCHIVE,
        b"7z\xbc\xaf'\x1c",
        priority=850,
    ),
    _sig(
        "rar",
        ".rar",
        "application/vnd.rar",
        FAMILY_ARCHIVE,
        b"Rar!\x1a\x07\x00",
        priority=800,
    ),
    _sig(
        "rar5",
        ".rar",
        "application/vnd.rar",
        FAMILY_ARCHIVE,
        b"Rar!\x1a\x07\x01\x00",
        priority=810,
    ),
    _sig(
        "tar",
        ".tar",
        "application/x-tar",
        FAMILY_ARCHIVE,
        b"ustar",
        offset=257,
        priority=700,
    ),
    # Executables
    _sig(
        "windows_pe",
        ".exe",
        "application/vnd.microsoft.portable-executable",
        FAMILY_EXECUTABLE,
        b"MZ",
        priority=950,
    ),
    _sig(
        "elf",
        ".elf",
        "application/x-elf",
        FAMILY_EXECUTABLE,
        b"\x7fELF",
        priority=950,
    ),
    _sig(
        "mach_o_32",
        ".mach-o",
        "application/x-mach-binary",
        FAMILY_EXECUTABLE,
        b"\xfe\xed\xfa\xce",
        priority=950,
    ),
    _sig(
        "mach_o_64",
        ".mach-o",
        "application/x-mach-binary",
        FAMILY_EXECUTABLE,
        b"\xfe\xed\xfa\xcf",
        priority=950,
    ),
    _sig(
        "mach_o_32_reverse",
        ".mach-o",
        "application/x-mach-binary",
        FAMILY_EXECUTABLE,
        b"\xce\xfa\xed\xfe",
        priority=950,
    ),
    _sig(
        "mach_o_64_reverse",
        ".mach-o",
        "application/x-mach-binary",
        FAMILY_EXECUTABLE,
        b"\xcf\xfa\xed\xfe",
        priority=950,
    ),
    _sig(
        "java_class",
        ".class",
        "application/java-vm",
        FAMILY_EXECUTABLE,
        b"\xca\xfe\xba\xbe",
        priority=900,
    ),
    _sig(
        "wasm",
        ".wasm",
        "application/wasm",
        FAMILY_EXECUTABLE,
        b"\x00asm",
        priority=900,
    ),
    # Database
    _sig(
        "sqlite3",
        ".sqlite",
        "application/vnd.sqlite3",
        FAMILY_DATABASE,
        b"SQLite format 3\x00",
        priority=900,
    ),
    # Images
    _sig("png", ".png", "image/png", FAMILY_IMAGE, b"\x89PNG\r\n\x1a\n", priority=900),
    _sig("jpeg", ".jpg", "image/jpeg", FAMILY_IMAGE, b"\xff\xd8\xff", priority=900),
    _sig("gif", ".gif", "image/gif", FAMILY_IMAGE, b"GIF8", priority=900),
    _sig("bmp", ".bmp", "image/bmp", FAMILY_IMAGE, b"BM", priority=700),
    _sig(
        "webp",
        ".webp",
        "image/webp",
        FAMILY_IMAGE,
        b"WEBP",
        offset=8,
        priority=850,
    ),
    _sig(
        "ico", ".ico", "image/x-icon", FAMILY_IMAGE, b"\x00\x00\x01\x00", priority=700
    ),
    # Audio
    _sig("flac", ".flac", "audio/flac", FAMILY_AUDIO, b"fLaC", priority=850),
    _sig("ogg", ".ogg", "audio/ogg", FAMILY_AUDIO, b"OggS", priority=800),
    _sig("mp3", ".mp3", "audio/mpeg", FAMILY_AUDIO, b"ID3", priority=650),
    # Video
    _sig(
        "webm",
        ".webm",
        "video/webm",
        FAMILY_VIDEO,
        b"\x1a\x45\xdf\xa3",
        priority=700,
    ),
    _sig(
        "mp4",
        ".mp4",
        "video/mp4",
        FAMILY_VIDEO,
        b"ftyp",
        offset=4,
        priority=750,
    ),
    # Fonts
    _sig(
        "truetype", ".ttf", "font/ttf", FAMILY_FONT, b"\x00\x01\x00\x00", priority=750
    ),
    _sig("opentype", ".otf", "font/otf", FAMILY_FONT, b"OTTO", priority=750),
    _sig("woff", ".woff", "font/woff", FAMILY_FONT, b"wOFF", priority=750),
    _sig("woff2", ".woff2", "font/woff2", FAMILY_FONT, b"wOF2", priority=750),
)

_SIGNATURES = tuple(sorted(_SIGNATURES, key=lambda item: (-item.priority, item.name)))

# ---------------------------------------------------------------------------
# Extension metadata
# ---------------------------------------------------------------------------

_EXTENSION_MAP: dict[str, tuple[str, str, str]] = {
    # Office
    ".doc": ("legacy_word", "application/msword", FAMILY_DOCUMENT),
    ".dot": ("legacy_word_template", "application/msword", FAMILY_DOCUMENT),
    ".xls": ("legacy_excel", "application/vnd.ms-excel", FAMILY_DOCUMENT),
    ".xlt": ("legacy_excel_template", "application/vnd.ms-excel", FAMILY_DOCUMENT),
    ".ppt": ("legacy_powerpoint", "application/vnd.ms-powerpoint", FAMILY_DOCUMENT),
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
    ".xlsx": (
        "excel_openxml",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        FAMILY_DOCUMENT,
    ),
    ".xlsm": (
        "excel_openxml_macro_enabled",
        "application/vnd.ms-excel.sheet.macroEnabled.12",
        FAMILY_DOCUMENT,
    ),
    ".xltx": (
        "excel_openxml_template",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.template",
        FAMILY_DOCUMENT,
    ),
    ".xltm": (
        "excel_openxml_macro_enabled_template",
        "application/vnd.ms-excel.template.macroEnabled.12",
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
    # Documents / text
    ".pdf": ("pdf", "application/pdf", FAMILY_DOCUMENT),
    ".rtf": ("rtf", "application/rtf", FAMILY_DOCUMENT),
    ".txt": ("plain_text", "text/plain", FAMILY_TEXT),
    ".csv": ("csv", "text/csv", FAMILY_TEXT),
    ".tsv": ("tsv", "text/tab-separated-values", FAMILY_TEXT),
    ".json": ("json", "application/json", FAMILY_TEXT),
    ".xml": ("xml", "application/xml", FAMILY_TEXT),
    ".html": ("html", "text/html", FAMILY_TEXT),
    ".htm": ("html", "text/html", FAMILY_TEXT),
    # Scripts
    ".js": ("javascript", "text/javascript", FAMILY_SCRIPT),
    ".jse": ("javascript_encoded", "text/javascript", FAMILY_SCRIPT),
    ".vbs": ("vbscript", "text/vbscript", FAMILY_SCRIPT),
    ".vbe": ("vbscript_encoded", "text/vbscript", FAMILY_SCRIPT),
    ".ps1": ("powershell", "application/x-powershell", FAMILY_SCRIPT),
    ".psm1": ("powershell_module", "application/x-powershell", FAMILY_SCRIPT),
    ".psd1": ("powershell_data", "application/x-powershell", FAMILY_SCRIPT),
    ".bat": ("batch", "application/x-bat", FAMILY_SCRIPT),
    ".cmd": ("windows_command_script", "application/x-cmd", FAMILY_SCRIPT),
    ".sh": ("shell_script", "application/x-sh", FAMILY_SCRIPT),
    ".py": ("python", "text/x-python", FAMILY_SCRIPT),
    ".rb": ("ruby", "text/x-ruby", FAMILY_SCRIPT),
    ".pl": ("perl", "text/x-perl", FAMILY_SCRIPT),
    ".php": ("php", "application/x-httpd-php", FAMILY_SCRIPT),
    # Archives
    ".zip": ("zip", "application/zip", FAMILY_ARCHIVE),
    ".gz": ("gzip", "application/gzip", FAMILY_ARCHIVE),
    ".bz2": ("bzip2", "application/x-bzip2", FAMILY_ARCHIVE),
    ".xz": ("xz", "application/x-xz", FAMILY_ARCHIVE),
    ".7z": ("seven_zip", "application/x-7z-compressed", FAMILY_ARCHIVE),
    ".rar": ("rar", "application/vnd.rar", FAMILY_ARCHIVE),
    ".tar": ("tar", "application/x-tar", FAMILY_ARCHIVE),
    # Executables
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
    # Databases
    ".sqlite": ("sqlite3", "application/vnd.sqlite3", FAMILY_DATABASE),
    ".db": ("database", "application/octet-stream", FAMILY_DATABASE),
}

_OFFICE_EXTENSIONS = {
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

_MACRO_EXTENSIONS = {
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

_OFFICE_NAMES = {
    name
    for extension, (name, _, _) in _EXTENSION_MAP.items()
    if extension in _OFFICE_EXTENSIONS
}
_OFFICE_NAMES.update(
    {
        "ole_compound_file",
        "office_openxml",
    }
)

_SCRIPT_EXTENSIONS = {
    extension
    for extension, (_, _, family) in _EXTENSION_MAP.items()
    if family == FAMILY_SCRIPT
}

# ---------------------------------------------------------------------------
# Extension helpers
# ---------------------------------------------------------------------------


def normalize_extension(value: Any) -> str:
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
    if path_or_name is None:
        return ""

    try:
        return normalize_extension(Path(str(path_or_name)).suffix)
    except (TypeError, ValueError, OSError):
        return ""


def extension_metadata(extension: str) -> dict[str, str]:
    extension = normalize_extension(extension)

    if extension in _EXTENSION_MAP:
        name, mime_type, family = _EXTENSION_MAP[extension]
        return {
            "name": name,
            "mime_type": mime_type,
            "family": family,
        }

    mime_type = mimetypes.guess_type("file" + extension)[0]
    return {
        "name": "unknown",
        "mime_type": mime_type or "application/octet-stream",
        "family": FAMILY_UNKNOWN,
    }


# ---------------------------------------------------------------------------
# Input handling
# ---------------------------------------------------------------------------


def _read_sample(
    source: Any,
    max_bytes: int = MAX_READ_SIZE,
) -> tuple[bytes, int, str]:
    if isinstance(source, bytes):
        return source[:max_bytes], len(source), ""

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
        except OSError:
            return b"", 0, "file_could_not_be_accessed"

        if not path.is_file():
            return b"", int(stat.st_size), "source_is_not_regular_file"

        try:
            with path.open("rb") as file:
                return file.read(max_bytes), int(stat.st_size), ""
        except OSError:
            return b"", int(stat.st_size), "file_could_not_be_read"

    if isinstance(source, str):
        path = Path(source)

        try:
            if path.exists():
                return _read_sample(path, max_bytes)
        except OSError:
            pass

        raw = source.encode("utf-8", errors="replace")
        return raw[:max_bytes], len(raw), ""

    return b"", 0, "unsupported_source_type"


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()

    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(HASH_CHUNK_SIZE), b""):
            digest.update(chunk)

    return digest.hexdigest()


# ---------------------------------------------------------------------------
# Signature matching
# ---------------------------------------------------------------------------


def _matches(sample: bytes, signature: FileSignature) -> bool:
    start = signature.offset
    end = start + len(signature.magic)

    return start >= 0 and end <= len(sample) and sample[start:end] == signature.magic


# ---------------------------------------------------------------------------
# Lightweight structural detection
# ---------------------------------------------------------------------------


def _looks_like_ooxml(sample: bytes) -> bool:
    if not sample.startswith(b"PK"):
        return False

    return any(
        marker in sample
        for marker in (
            b"[Content_Types].xml",
            b"word/",
            b"xl/",
            b"ppt/",
            b"_rels/",
        )
    )


def _looks_like_pe(sample: bytes) -> bool:
    if not sample.startswith(b"MZ"):
        return False

    if len(sample) < 0x40:
        return True

    try:
        offset = struct.unpack_from("<I", sample, 0x3C)[0]
    except struct.error:
        return True

    if offset + 4 > len(sample):
        return True

    return sample[offset : offset + 4] == b"PE\x00\x00"


def _looks_like_tar(sample: bytes) -> bool:
    return len(sample) >= 262 and sample[257:262] == b"ustar"


def _detect_riff(sample: bytes) -> tuple[str, str, str] | None:
    if len(sample) < 12 or sample[:4] != b"RIFF":
        return None

    subtype = sample[8:12]

    formats = {
        b"WAVE": ("wav", "audio/wav", FAMILY_AUDIO),
        b"AVI ": ("avi", "video/x-msvideo", FAMILY_VIDEO),
        b"WEBP": ("webp", "image/webp", FAMILY_IMAGE),
    }

    return formats.get(subtype)


def _looks_like_text(sample: bytes) -> bool:
    if not sample or b"\x00" in sample:
        return False

    examined = sample[:MAX_TEXT_SAMPLE]
    printable = sum(byte in (9, 10, 13) or 32 <= byte <= 126 for byte in examined)

    return printable / len(examined) >= 0.85


def _detect_script(sample: bytes) -> tuple[str, str, str] | None:
    if not sample:
        return None

    text = sample[:MAX_TEXT_SAMPLE].decode("utf-8", errors="ignore").lower()

    patterns = (
        (
            "powershell",
            "application/x-powershell",
            ".ps1",
            (
                "powershell",
                "pwsh",
                "invoke-expression",
                "invoke-command",
                "frombase64string",
            ),
        ),
        (
            "javascript",
            "text/javascript",
            ".js",
            (
                "javascript:",
                "function(",
                "function ",
                "eval(",
                "wscript.createobject",
                "activexobject",
            ),
        ),
        (
            "vbscript",
            "text/vbscript",
            ".vbs",
            ("createobject(", "wscript.shell", "on error resume next", "dim ", "set "),
        ),
        (
            "shell_script",
            "application/x-sh",
            ".sh",
            ("#!/bin/sh", "#!/bin/bash", "#!/usr/bin/env bash", "#!/usr/bin/env sh"),
        ),
        (
            "batch",
            "application/x-bat",
            ".bat",
            ("@echo off", "cmd.exe", "setlocal", "%%~"),
        ),
        (
            "python",
            "text/x-python",
            ".py",
            (
                "#!/usr/bin/python",
                "#!/usr/bin/env python",
                "import os",
                "import sys",
                "def ",
            ),
        ),
    )

    for name, mime_type, extension, markers in patterns:
        if any(marker in text for marker in markers):
            return name, mime_type, extension

    return None


# ---------------------------------------------------------------------------
# Core identification
# ---------------------------------------------------------------------------


def identify_from_bytes(
    data: bytes,
    *,
    declared_extension: str = "",
    include_hash: bool = True,
) -> FileTypeResult:
    if not isinstance(data, bytes):
        data = bytes(data)

    original_size = len(data)
    bounded = data[:MAX_SOURCE_SIZE]
    sample = bounded[:MAX_READ_SIZE]

    declared = normalize_extension(declared_extension)

    name = "unknown"
    extension = ""
    mime_type = "application/octet-stream"
    family = FAMILY_UNKNOWN
    description = ""
    method = "unknown"
    confidence = 0.0

    # Strong structural checks.
    if _looks_like_pe(sample):
        name = "windows_pe"
        extension = ".exe"
        mime_type = "application/vnd.microsoft.portable-executable"
        family = FAMILY_EXECUTABLE
        description = "Windows PE executable."
        method = "magic+structure"
        confidence = 0.99

    elif _looks_like_ooxml(sample):
        name = "office_openxml"
        extension = ".zip"
        mime_type = "application/zip"
        family = FAMILY_DOCUMENT
        description = "ZIP-based Office Open XML document."
        method = "magic+structure"
        confidence = 0.98

    elif sample.startswith(b"%PDF-"):
        name = "pdf"
        extension = ".pdf"
        mime_type = "application/pdf"
        family = FAMILY_DOCUMENT
        description = "Portable Document Format."
        method = "magic"
        confidence = 0.99

    elif sample.startswith(b"{\\rtf"):
        name = "rtf"
        extension = ".rtf"
        mime_type = "application/rtf"
        family = FAMILY_DOCUMENT
        description = "Rich Text Format document."
        method = "magic"
        confidence = 0.99

    else:
        riff = _detect_riff(sample)

        if riff:
            name, mime_type, family = riff
            extension = {
                "wav": ".wav",
                "avi": ".avi",
                "webp": ".webp",
            }[name]
            description = f"{name.upper()} RIFF container."
            method = "magic+structure"
            confidence = 0.98

        elif len(sample) >= 12 and sample[4:8] == b"ftyp":
            name = "mp4"
            extension = ".mp4"
            mime_type = "video/mp4"
            family = FAMILY_VIDEO
            description = "ISO Base Media / MP4-family container."
            method = "magic+structure"
            confidence = 0.94

        elif _looks_like_tar(sample):
            name = "tar"
            extension = ".tar"
            mime_type = "application/x-tar"
            family = FAMILY_ARCHIVE
            description = "POSIX tar archive."
            method = "magic+structure"
            confidence = 0.97

        else:
            for signature in _SIGNATURES:
                if _matches(sample, signature):
                    name = signature.name
                    extension = signature.extension
                    mime_type = signature.mime_type
                    family = signature.family
                    description = signature.description
                    method = "magic"
                    confidence = 0.96
                    break

    # Text/script fallback.
    if family == FAMILY_UNKNOWN and _looks_like_text(sample):
        script = _detect_script(sample)

        if script:
            name, mime_type, extension = script
            family = FAMILY_SCRIPT
            description = f"Textual {name} source."
            method = "text-heuristic"
            confidence = 0.88
        else:
            name = "plain_text"
            extension = ".txt"
            mime_type = "text/plain"
            family = FAMILY_TEXT
            description = "Plain textual data."
            method = "text-heuristic"
            confidence = 0.78

    warnings: list[str] = []

    if family == FAMILY_UNKNOWN:
        warnings.append("file_type_not_recognized")

    extension_mismatch = False

    if declared and extension:
        if name == "office_openxml" and declared in _OFFICE_EXTENSIONS:
            extension_mismatch = False
        else:
            extension_mismatch = declared != extension

        if extension_mismatch:
            warnings.append(f"extension_mismatch:{declared}->{extension}")

    declared_name = _EXTENSION_MAP[declared][0] if declared in _EXTENSION_MAP else ""

    return FileTypeResult(
        name=name,
        extension=extension,
        mime_type=mime_type,
        family=family,
        confidence=max(0.0, min(1.0, confidence)),
        method=method,
        description=description,
        detected_extension=extension,
        declared_extension=declared,
        extension_mismatch=extension_mismatch,
        is_container=family in {FAMILY_ARCHIVE, FAMILY_DOCUMENT},
        is_document=family == FAMILY_DOCUMENT,
        is_executable=family == FAMILY_EXECUTABLE,
        is_script=family == FAMILY_SCRIPT,
        is_text=family == FAMILY_TEXT,
        is_unknown=family == FAMILY_UNKNOWN,
        size=original_size,
        sha256=_sha256_bytes(bounded) if include_hash else "",
        sample_size=len(sample),
        warnings=tuple(warnings),
        metadata={
            "declared_type": declared_name,
            "content_sample_bounded": original_size > MAX_READ_SIZE,
            "source_bounded": original_size > MAX_SOURCE_SIZE,
        },
    )


def identify_file(
    path: os.PathLike[str] | str,
    *,
    include_hash: bool = True,
) -> FileTypeResult:
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
        try:
            sha256 = _sha256_file(file_path)
        except OSError:
            warning = warning or "file_could_not_be_read"

    warnings = list(result.warnings)

    if warning:
        warnings.append(warning)

    return FileTypeResult(
        **{
            **result.__dict__,
            "size": total_size,
            "sha256": sha256,
            "warnings": tuple(dict.fromkeys(warnings)),
            "metadata": {
                **dict(result.metadata),
                "path_name": file_path.name[:MAX_EXTENSION_LENGTH],
            },
        }
    )


def identify(
    source: Any,
    *,
    declared_extension: str = "",
    include_hash: bool = True,
) -> FileTypeResult:
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
    return result.family == FAMILY_DOCUMENT and result.name in _OFFICE_NAMES


def is_macro_capable(result: FileTypeResult) -> bool:
    return (
        result.name
        in {
            "ole_compound_file",
            "word_openxml_macro_enabled",
            "word_openxml_macro_enabled_template",
            "excel_openxml_macro_enabled",
            "excel_openxml_macro_enabled_template",
            "powerpoint_openxml_macro_enabled",
            "powerpoint_openxml_macro_enabled_slideshow",
        }
        or result.declared_extension in _MACRO_EXTENSIONS
    )


def is_archive(result: FileTypeResult) -> bool:
    return result.family == FAMILY_ARCHIVE


def is_executable(result: FileTypeResult) -> bool:
    return result.family == FAMILY_EXECUTABLE


def is_script(result: FileTypeResult) -> bool:
    return result.family == FAMILY_SCRIPT


def is_document(result: FileTypeResult) -> bool:
    return result.family == FAMILY_DOCUMENT


def has_extension_mismatch(result: FileTypeResult) -> bool:
    return result.extension_mismatch


# ---------------------------------------------------------------------------
# Signature inspection
# ---------------------------------------------------------------------------


def iter_signatures() -> Iterator[FileSignature]:
    yield from _SIGNATURES


def known_extensions() -> tuple[str, ...]:
    return tuple(sorted(_EXTENSION_MAP))


def signatures_for_extension(
    extension: str,
) -> tuple[FileSignature, ...]:
    normalized = normalize_extension(extension)
    return tuple(
        signature for signature in _SIGNATURES if signature.extension == normalized
    )


# ---------------------------------------------------------------------------
# Serialization
# ---------------------------------------------------------------------------


def result_to_dict(result: FileTypeResult) -> dict[str, Any]:
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


def summarize(result: FileTypeResult) -> dict[str, Any]:
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
