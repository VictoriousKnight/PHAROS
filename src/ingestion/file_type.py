"""
PHAROS Ingestion - File Type Identification
-------------------------------------------
Lightweight, accurate, and dependency-free file type identification.
Uses magic byte headers, zip inspection for OOXML, and declared extension matching.
"""

from __future__ import annotations

import hashlib
import io
import os
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator, Mapping, Optional, Sequence

# Canonical file families
FAMILY_DOCUMENT = "document"
FAMILY_ARCHIVE = "archive"
FAMILY_EXECUTABLE = "executable"
FAMILY_SCRIPT = "script"
FAMILY_TEXT = "text"
FAMILY_UNKNOWN = "unknown"

# OOXML standard MIME types
OOXML_MIMES = {
    "word": ("docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"),
    "word_macro": ("docm", "application/vnd.ms-word.document.macroEnabled.12"),
    "excel": ("xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"),
    "excel_macro": ("xlsm", "application/vnd.ms-excel.sheet.macroEnabled.12"),
    "powerpoint": ("pptx", "application/vnd.openxmlformats-officedocument.presentationml.presentation"),
    "powerpoint_macro": ("pptm", "application/vnd.ms-powerpoint.presentation.macroEnabled.12"),
}


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


# Well-known file signatures
_SIGNATURES: tuple[FileSignature, ...] = (
    FileSignature("ole_compound_file", ".ole", "application/x-ole-storage", FAMILY_DOCUMENT, b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", priority=1000),
    FileSignature("pdf", ".pdf", "application/pdf", FAMILY_DOCUMENT, b"%PDF-", priority=900),
    FileSignature("rtf", ".rtf", "application/rtf", FAMILY_DOCUMENT, b"{\\rtf", priority=800),
    FileSignature("zip", ".zip", "application/zip", FAMILY_ARCHIVE, b"PK\x03\x04", priority=500),
    FileSignature("pe_executable", ".exe", "application/vnd.microsoft.portable-executable", FAMILY_EXECUTABLE, b"MZ", priority=700),
    FileSignature("elf", ".elf", "application/x-executable", FAMILY_EXECUTABLE, b"\x7fELF", priority=700),
    FileSignature("rar", ".rar", "application/vnd.rar", FAMILY_ARCHIVE, b"Rar!\x1a\x07", priority=600),
    FileSignature("7z", ".7z", "application/x-7z-compressed", FAMILY_ARCHIVE, b"7z\xbc\xaf\x27\x1c", priority=600),
    FileSignature("tar_posix", ".tar", "application/x-tar", FAMILY_ARCHIVE, b"ustar", offset=257, priority=400),
)


def normalize_extension(value: Any) -> str:
    """Normalize file extension to lowercase with leading dot."""
    if not value or not isinstance(value, str):
        return ""
    ext = os.path.splitext(value)[1].lower() if "." in value else f".{value.lower()}"
    return ext if ext != "." else ""


def declared_extension(path_or_name: Any) -> str:
    """Extract normalized extension from filename or path."""
    if isinstance(path_or_name, Path):
        return path_or_name.suffix.lower()
    return normalize_extension(str(path_or_name or ""))


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _inspect_ooxml_zip(path_or_bytes: Path | bytes) -> tuple[str, str, str, bool]:
    """Inspect ZIP container to determine if it is OOXML (Word, Excel, PowerPoint) and macro-enabled."""
    try:
        zf = zipfile.ZipFile(path_or_bytes if isinstance(path_or_bytes, Path) else io.BytesIO(path_or_bytes))
        with zf:
            namelist = set(zf.namelist())
            has_macros = any("vbaProject.bin" in name for name in namelist)

            if any(n.startswith("word/") for n in namelist):
                ext, mime = OOXML_MIMES["word_macro"] if has_macros else OOXML_MIMES["word"]
                return f"ooxml_word_{'macro' if has_macros else 'standard'}", f".{ext}", mime, has_macros
            if any(n.startswith("xl/") for n in namelist):
                ext, mime = OOXML_MIMES["excel_macro"] if has_macros else OOXML_MIMES["excel"]
                return f"ooxml_excel_{'macro' if has_macros else 'standard'}", f".{ext}", mime, has_macros
            if any(n.startswith("ppt/") for n in namelist):
                ext, mime = OOXML_MIMES["powerpoint_macro"] if has_macros else OOXML_MIMES["powerpoint"]
                return f"ooxml_powerpoint_{'macro' if has_macros else 'standard'}", f".{ext}", mime, has_macros
            return "zip_archive", ".zip", "application/zip", False
    except Exception:
        return "zip_archive", ".zip", "application/zip", False


def identify_from_bytes(
    data: bytes,
    *,
    declared_filename: Optional[str] = None,
    include_hash: bool = True
) -> FileTypeResult:
    """Identify file type directly from memory bytes."""
    size = len(data)
    sample = data[:4096]
    decl_ext = declared_extension(declared_filename)
    sha256 = _sha256_bytes(data) if include_hash else ""
    warnings: list[str] = []

    # 1. Check Magic Signatures
    matched_sig: Optional[FileSignature] = None
    for sig in sorted(_SIGNATURES, key=lambda s: s.priority, reverse=True):
        end = sig.offset + len(sig.magic)
        if len(sample) >= end and sample[sig.offset:end] == sig.magic:
            matched_sig = sig
            break

    # 2. Refine ZIP / OOXML containers
    if matched_sig and matched_sig.name == "zip":
        import io
        name, ext, mime, has_vba = _inspect_ooxml_zip(data)
        is_doc = name.startswith("ooxml_")
        family = FAMILY_DOCUMENT if is_doc else FAMILY_ARCHIVE
        mismatch = bool(decl_ext and decl_ext != ext)
        return FileTypeResult(
            name=name,
            extension=ext,
            mime_type=mime,
            family=family,
            confidence=0.98 if is_doc else 0.90,
            method="ooxml_container_inspection" if is_doc else "magic_bytes",
            detected_extension=ext,
            declared_extension=decl_ext,
            extension_mismatch=mismatch,
            is_container=True,
            is_document=is_doc,
            size=size,
            sha256=sha256,
            sample_size=len(sample),
            warnings=tuple(warnings),
            metadata={"has_vba_project": has_vba}
        )

    # 3. Refine OLE Compound Files (Legacy Office)
    if matched_sig and matched_sig.name == "ole_compound_file":
        ext = decl_ext if decl_ext in [".doc", ".xls", ".ppt"] else ".ole"
        return FileTypeResult(
            name="ole_compound_file",
            extension=ext,
            mime_type="application/x-ole-storage",
            family=FAMILY_DOCUMENT,
            confidence=0.95,
            method="magic_bytes",
            detected_extension=ext,
            declared_extension=decl_ext,
            extension_mismatch=bool(decl_ext and decl_ext != ext and decl_ext not in [".doc", ".xls", ".ppt"]),
            is_container=True,
            is_document=True,
            size=size,
            sha256=sha256,
            sample_size=len(sample),
            warnings=tuple(warnings)
        )

    # 4. Standard Signature Matches (PDF, RTF, Executable, etc.)
    if matched_sig:
        mismatch = bool(decl_ext and decl_ext != matched_sig.extension)
        return FileTypeResult(
            name=matched_sig.name,
            extension=matched_sig.extension,
            mime_type=matched_sig.mime_type,
            family=matched_sig.family,
            confidence=0.95,
            method="magic_bytes",
            detected_extension=matched_sig.extension,
            declared_extension=decl_ext,
            extension_mismatch=mismatch,
            is_document=(matched_sig.family == FAMILY_DOCUMENT),
            is_executable=(matched_sig.family == FAMILY_EXECUTABLE),
            is_container=(matched_sig.family == FAMILY_ARCHIVE),
            size=size,
            sha256=sha256,
            sample_size=len(sample),
            warnings=tuple(warnings)
        )

    # 5. Check Plain Text / Scripts
    try:
        text_str = sample.decode("utf-8")
        is_script = decl_ext in [".js", ".vbs", ".ps1", ".bat", ".cmd", ".sh", ".py"]
        return FileTypeResult(
            name="script" if is_script else "plain_text",
            extension=decl_ext or ".txt",
            mime_type="text/plain",
            family=FAMILY_SCRIPT if is_script else FAMILY_TEXT,
            confidence=0.80,
            method="text_decoding",
            detected_extension=decl_ext or ".txt",
            declared_extension=decl_ext,
            extension_mismatch=False,
            is_script=is_script,
            is_text=True,
            size=size,
            sha256=sha256,
            sample_size=len(sample),
            warnings=tuple(warnings)
        )
    except UnicodeDecodeError:
        pass

    # 6. Fallback Unknown Binary
    return FileTypeResult(
        name="unknown",
        extension=decl_ext or ".bin",
        mime_type="application/octet-stream",
        family=FAMILY_UNKNOWN,
        confidence=0.10,
        method="fallback",
        detected_extension=decl_ext or ".bin",
        declared_extension=decl_ext,
        extension_mismatch=False,
        is_unknown=True,
        size=size,
        sha256=sha256,
        sample_size=len(sample),
        warnings=("file_type_not_recognized",)
    )


def identify_file(
    path: str | Path,
    *,
    declared_filename: Optional[str] = None,
    include_hash: bool = True
) -> FileTypeResult:
    """Identify file type directly from a disk path."""
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(f"File not found: {p}")
    
    with open(p, "rb") as f:
        data = f.read()

    filename = declared_filename or p.name
    return identify_from_bytes(data, declared_filename=filename, include_hash=include_hash)


# Aliases for backward compatibility across pipeline and scanner
identify = identify_file
detect_file_type = identify_file
analyze_file_type = identify_file
file_type = identify_file


def is_office_document(result: FileTypeResult) -> bool:
    return result.is_document or "ooxml" in result.name or "ole" in result.name


def is_macro_capable(result: FileTypeResult) -> bool:
    return result.extension in [".docm", ".xlsm", ".pptm", ".dotm", ".xltm", ".potm"] or result.metadata.get("has_vba_project", False)


def is_archive(result: FileTypeResult) -> bool:
    return result.family == FAMILY_ARCHIVE or result.is_container


def is_executable(result: FileTypeResult) -> bool:
    return result.family == FAMILY_EXECUTABLE or result.is_executable


def is_script(result: FileTypeResult) -> bool:
    return result.family == FAMILY_SCRIPT or result.is_script


def is_document(result: FileTypeResult) -> bool:
    return result.is_document


def has_extension_mismatch(result: FileTypeResult) -> bool:
    return result.extension_mismatch
