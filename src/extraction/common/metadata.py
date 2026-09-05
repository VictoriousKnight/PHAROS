"""
Format-independent file metadata extraction.

This module extracts metadata that can be obtained without parsing the
internal structure of a document or executing its contents.

Collected metadata
------------------
Filesystem metadata:
- file size
- extension
- filename
- basename / stem
- timestamps
- permissions
- ownership
- inode / device information where available
- hard-link count
- symlink information
- file type flags

Filename indicators:
- executable-looking extensions
- script-looking extensions
- archive/container extensions
- document extensions
- suspicious double extensions
- multiple extensions
- hidden-file indicators
- temporary-file indicators

Path characteristics:
- filename length
- path depth
- directory depth
- filename entropy
- extension characteristics
- unusual characters
- Unicode/non-ASCII filename indicators

The module deliberately does NOT:
- parse Office metadata
- parse OLE streams
- parse OOXML properties
- parse PDF metadata
- inspect macros
- inspect scripts
- execute files
- determine whether a file is malicious

Those responsibilities belong to specialized extraction layers.

Design goals
------------
1. Deterministic output.
2. JSON-serializable results.
3. Cross-platform behavior where practical.
4. Graceful handling of unavailable OS metadata.
5. No file execution.
6. No dependency on external parsing libraries.
7. Bounded string/path processing.
8. ML-friendly scalar features separated from descriptive metadata.
"""

from __future__ import annotations

import math
import os
import re
import stat
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence

METADATA_VERSION = 1

DEFAULT_MAX_FILENAME_LENGTH = 4_096
DEFAULT_MAX_PATH_LENGTH = 16_384
DEFAULT_MAX_EXTENSION_COUNT = 16


# ---------------------------------------------------------------------------
# Extension classifications
# ---------------------------------------------------------------------------

DOCUMENT_EXTENSIONS = frozenset(
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
        ".pdf",
        ".rtf",
        ".odt",
        ".ods",
        ".odp",
        ".txt",
        ".csv",
        ".xml",
        ".json",
        ".html",
        ".htm",
        ".xhtml",
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

MACRO_ENABLED_EXTENSIONS = frozenset(
    {
        ".docm",
        ".dotm",
        ".xlsm",
        ".xltm",
        ".pptm",
        ".potm",
        ".ppsm",
    }
)

SCRIPT_EXTENSIONS = frozenset(
    {
        ".bat",
        ".cmd",
        ".com",
        ".js",
        ".jse",
        ".ps1",
        ".psd1",
        ".psm1",
        ".py",
        ".pyw",
        ".rb",
        ".sh",
        ".vbe",
        ".vbs",
        ".wsf",
        ".wsh",
    }
)

EXECUTABLE_EXTENSIONS = frozenset(
    {
        ".apk",
        ".app",
        ".bin",
        ".com",
        ".dll",
        ".elf",
        ".exe",
        ".msi",
        ".scr",
        ".sys",
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

TEMPORARY_EXTENSIONS = frozenset(
    {
        ".bak",
        ".old",
        ".orig",
        ".part",
        ".swp",
        ".tmp",
        ".temp",
    }
)

LOCKFILE_EXTENSIONS = frozenset(
    {
        ".lock",
        ".lck",
    }
)

# Extensions commonly associated with content that may be directly executed
# or interpreted by a host application.
HIGH_EXECUTION_RISK_EXTENSIONS = frozenset(
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
        ".msp",
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


# ---------------------------------------------------------------------------
# Filename indicators
# ---------------------------------------------------------------------------

DOUBLE_EXTENSION_RE = re.compile(
    r"(?i)"
    r"\.(?:"
    r"doc|docx|docm|xls|xlsx|xlsm|ppt|pptx|pptm|"
    r"pdf|txt|rtf|jpg|jpeg|png|gif|zip|rar"
    r")"
    r"\.(?:"
    r"exe|scr|com|bat|cmd|js|jse|vbs|vbe|ps1|wsf|wsh|msi|dll"
    r")$"
)

MULTIPLE_EXTENSION_RE = re.compile(r"(?i)" r"(?:\.[a-z0-9_-]{1,32}){3,}$")

HIDDEN_UNIX_NAME_RE = re.compile(r"^\.[^.].*")

TEMPORARY_NAME_RE = re.compile(
    r"(?i)"
    r"(?:"
    r"~\$"
    r"|~"
    r"|\.tmp$"
    r"|\.temp$"
    r"|\.bak$"
    r"|\.swp$"
    r"|\.part$"
    r"|\.crdownload$"
    r"|\.download$"
    r")"
)

BACKUP_NAME_RE = re.compile(r"(?i)" r"(?:" r"\.bak$" r"|\.old$" r"|\.orig$" r"|~$" r")")

NON_ASCII_RE = re.compile(r"[^\x00-\x7f]")

CONTROL_CHARACTER_RE = re.compile(r"[\x00-\x1f\x7f]")

SUSPICIOUS_FILENAME_CHARACTER_RE = re.compile(r"""[<>:"/\\|?*\x00-\x1f]""")

REPEATED_SEPARATOR_RE = re.compile(r"[_\-.]{3,}")


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FileTimestamps:
    """
    Normalized filesystem timestamps.

    Values are represented as UTC ISO-8601 strings plus Unix timestamps.
    """

    created_epoch: float | None
    modified_epoch: float | None
    accessed_epoch: float | None
    changed_epoch: float | None

    created_utc: str | None
    modified_utc: str | None
    accessed_utc: str | None
    changed_utc: str | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "created_epoch": self.created_epoch,
            "modified_epoch": self.modified_epoch,
            "accessed_epoch": self.accessed_epoch,
            "changed_epoch": self.changed_epoch,
            "created_utc": self.created_utc,
            "modified_utc": self.modified_utc,
            "accessed_utc": self.accessed_utc,
            "changed_utc": self.changed_utc,
        }


@dataclass(frozen=True)
class PermissionMetadata:
    """
    Portable representation of POSIX-style permissions.

    Windows does not expose all of these semantics through os.stat(), so
    fields may be None on platforms where the information is unavailable.
    """

    mode: int | None
    mode_octal: str | None

    owner_read: bool | None
    owner_write: bool | None
    owner_execute: bool | None

    group_read: bool | None
    group_write: bool | None
    group_execute: bool | None

    other_read: bool | None
    other_write: bool | None
    other_execute: bool | None

    is_world_writable: bool | None
    is_executable: bool | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "mode": self.mode,
            "mode_octal": self.mode_octal,
            "owner_read": self.owner_read,
            "owner_write": self.owner_write,
            "owner_execute": self.owner_execute,
            "group_read": self.group_read,
            "group_write": self.group_write,
            "group_execute": self.group_execute,
            "other_read": self.other_read,
            "other_write": self.other_write,
            "other_execute": self.other_execute,
            "is_world_writable": self.is_world_writable,
            "is_executable": self.is_executable,
        }


@dataclass(frozen=True)
class ExtensionMetadata:
    """
    Characteristics derived from a filename's extensions.
    """

    extension: str
    extensions: tuple[str, ...]
    extension_count: int

    extension_known_document: bool
    extension_known_office: bool
    extension_macro_enabled: bool
    extension_known_script: bool
    extension_known_executable: bool
    extension_known_archive: bool
    extension_temporary: bool
    extension_lockfile: bool
    extension_high_execution_risk: bool

    has_multiple_extensions: bool
    has_double_extension_pattern: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "extension": self.extension,
            "extensions": list(self.extensions),
            "extension_count": self.extension_count,
            "extension_known_document": (self.extension_known_document),
            "extension_known_office": (self.extension_known_office),
            "extension_macro_enabled": (self.extension_macro_enabled),
            "extension_known_script": (self.extension_known_script),
            "extension_known_executable": (self.extension_known_executable),
            "extension_known_archive": (self.extension_known_archive),
            "extension_temporary": self.extension_temporary,
            "extension_lockfile": self.extension_lockfile,
            "extension_high_execution_risk": (self.extension_high_execution_risk),
            "has_multiple_extensions": (self.has_multiple_extensions),
            "has_double_extension_pattern": (self.has_double_extension_pattern),
        }


@dataclass(frozen=True)
class FilenameMetadata:
    """
    Characteristics derived solely from the filename.
    """

    name: str
    stem: str
    suffix: str

    name_length: int
    stem_length: int
    suffix_length: int

    name_entropy: float

    contains_non_ascii: bool
    contains_control_characters: bool
    contains_suspicious_characters: bool
    contains_repeated_separators: bool

    starts_with_dot: bool
    is_hidden_style_name: bool
    is_temporary_style_name: bool
    is_backup_style_name: bool

    has_double_extension_pattern: bool
    has_multiple_extensions: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "stem": self.stem,
            "suffix": self.suffix,
            "name_length": self.name_length,
            "stem_length": self.stem_length,
            "suffix_length": self.suffix_length,
            "name_entropy": self.name_entropy,
            "contains_non_ascii": self.contains_non_ascii,
            "contains_control_characters": (self.contains_control_characters),
            "contains_suspicious_characters": (self.contains_suspicious_characters),
            "contains_repeated_separators": (self.contains_repeated_separators),
            "starts_with_dot": self.starts_with_dot,
            "is_hidden_style_name": self.is_hidden_style_name,
            "is_temporary_style_name": (self.is_temporary_style_name),
            "is_backup_style_name": self.is_backup_style_name,
            "has_double_extension_pattern": (self.has_double_extension_pattern),
            "has_multiple_extensions": (self.has_multiple_extensions),
        }


# ---------------------------------------------------------------------------
# Generic helpers
# ---------------------------------------------------------------------------


def _safe_float(value: Any) -> float | None:
    try:
        result = float(value)
    except (TypeError, ValueError, OverflowError):
        return None

    if not math.isfinite(result):
        return None

    return result


def _utc_isoformat(timestamp: float | None) -> str | None:
    if timestamp is None:
        return None

    try:
        value = datetime.fromtimestamp(
            timestamp,
            tz=timezone.utc,
        )
    except (OverflowError, OSError, ValueError):
        return None

    return value.isoformat()


def _safe_entropy(value: str) -> float:
    """
    Calculate Shannon entropy of a Unicode string.

    This is a filename-oriented heuristic, not a file-byte entropy
    calculation. Byte-level entropy belongs in entropy.py.
    """

    if not value:
        return 0.0

    counts = Counter(value)
    length = len(value)

    entropy = 0.0

    for count in counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return max(0.0, min(16.0, entropy))


def _normalize_extension(extension: str) -> str:
    extension = extension.strip().lower()

    if not extension:
        return ""

    if not extension.startswith("."):
        extension = f".{extension}"

    return extension


def _extract_extensions(
    filename: str,
    *,
    max_extensions: int = DEFAULT_MAX_EXTENSION_COUNT,
) -> tuple[str, ...]:
    """
    Extract suffixes from a filename from left to right.

    Example:
        invoice.docx.exe -> (".docx", ".exe")

    pathlib.Path.suffixes is used where possible because it handles compound
    suffixes more consistently than a hand-written split.
    """

    if max_extensions <= 0:
        return ()

    try:
        suffixes = Path(filename).suffixes
    except (OSError, ValueError):
        suffixes = []

    normalized: list[str] = []

    for suffix in suffixes:
        value = _normalize_extension(suffix)

        if value and value not in normalized:
            normalized.append(value)

        if len(normalized) >= max_extensions:
            break

    return tuple(normalized)


def _safe_filename_parts(
    filename: str,
) -> tuple[str, str, str]:
    """
    Return basename, stem and final suffix without filesystem access.
    """

    try:
        path = Path(filename)
        name = path.name
        stem = path.stem
        suffix = path.suffix
    except (OSError, ValueError):
        name = os.path.basename(filename)
        suffix = ""

        if "." in name and not name.startswith("."):
            stem, suffix = name.rsplit(".", 1)
            suffix = f".{suffix}"
        else:
            stem = name

    return name, stem, _normalize_extension(suffix)


def _round_float(value: float | None, digits: int = 6) -> float | None:
    if value is None:
        return None

    return round(value, digits)


def _round_floats(value: Any, digits: int = 6) -> Any:
    if isinstance(value, float):
        return round(value, digits)

    if isinstance(value, list):
        return [_round_floats(item, digits) for item in value]

    if isinstance(value, tuple):
        return tuple(_round_floats(item, digits) for item in value)

    if isinstance(value, dict):
        return {key: _round_floats(item, digits) for key, item in value.items()}

    return value


# ---------------------------------------------------------------------------
# Timestamp extraction
# ---------------------------------------------------------------------------


def extract_timestamps(
    stat_result: os.stat_result,
) -> FileTimestamps:
    """
    Extract platform-independent timestamp information.

    st_ctime has different semantics across platforms:
    - POSIX: metadata/status change time
    - Windows: creation time

    It is therefore explicitly named changed_epoch/changed_utc here rather
    than pretending it universally represents creation time.
    """

    created = _safe_float(getattr(stat_result, "st_birthtime", None))

    modified = _safe_float(getattr(stat_result, "st_mtime", None))

    accessed = _safe_float(getattr(stat_result, "st_atime", None))

    changed = _safe_float(getattr(stat_result, "st_ctime", None))

    if created is None and os.name == "nt":
        created = changed

    return FileTimestamps(
        created_epoch=created,
        modified_epoch=modified,
        accessed_epoch=accessed,
        changed_epoch=changed,
        created_utc=_utc_isoformat(created),
        modified_utc=_utc_isoformat(modified),
        accessed_utc=_utc_isoformat(accessed),
        changed_utc=_utc_isoformat(changed),
    )


# ---------------------------------------------------------------------------
# Permission extraction
# ---------------------------------------------------------------------------


def extract_permissions(
    stat_result: os.stat_result,
) -> PermissionMetadata:
    """
    Extract POSIX-style permission bits where available.
    """

    mode = getattr(stat_result, "st_mode", None)

    if mode is None:
        return PermissionMetadata(
            mode=None,
            mode_octal=None,
            owner_read=None,
            owner_write=None,
            owner_execute=None,
            group_read=None,
            group_write=None,
            group_execute=None,
            other_read=None,
            other_write=None,
            other_execute=None,
            is_world_writable=None,
            is_executable=None,
        )

    try:
        numeric_mode = stat.S_IMODE(mode)
    except (TypeError, ValueError):
        numeric_mode = None

    if numeric_mode is None:
        return PermissionMetadata(
            mode=None,
            mode_octal=None,
            owner_read=None,
            owner_write=None,
            owner_execute=None,
            group_read=None,
            group_write=None,
            group_execute=None,
            other_read=None,
            other_write=None,
            other_execute=None,
            is_world_writable=None,
            is_executable=None,
        )

    return PermissionMetadata(
        mode=numeric_mode,
        mode_octal=oct(numeric_mode),
        owner_read=bool(mode & stat.S_IRUSR),
        owner_write=bool(mode & stat.S_IWUSR),
        owner_execute=bool(mode & stat.S_IXUSR),
        group_read=bool(mode & stat.S_IRGRP),
        group_write=bool(mode & stat.S_IWGRP),
        group_execute=bool(mode & stat.S_IXGRP),
        other_read=bool(mode & stat.S_IROTH),
        other_write=bool(mode & stat.S_IWOTH),
        other_execute=bool(mode & stat.S_IXOTH),
        is_world_writable=bool(mode & stat.S_IWOTH),
        is_executable=bool(mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)),
    )


# ---------------------------------------------------------------------------
# Extension analysis
# ---------------------------------------------------------------------------


def analyze_extensions(
    filename: str,
    *,
    max_extensions: int = DEFAULT_MAX_EXTENSION_COUNT,
) -> ExtensionMetadata:
    name, _, final_suffix = _safe_filename_parts(filename)

    extensions = _extract_extensions(
        name,
        max_extensions=max_extensions,
    )

    extension = final_suffix

    if not extension and extensions:
        extension = extensions[-1]

    return ExtensionMetadata(
        extension=extension,
        extensions=extensions,
        extension_count=len(extensions),
        extension_known_document=(extension in DOCUMENT_EXTENSIONS),
        extension_known_office=(extension in OFFICE_EXTENSIONS),
        extension_macro_enabled=(extension in MACRO_ENABLED_EXTENSIONS),
        extension_known_script=(extension in SCRIPT_EXTENSIONS),
        extension_known_executable=(extension in EXECUTABLE_EXTENSIONS),
        extension_known_archive=(extension in ARCHIVE_EXTENSIONS),
        extension_temporary=(extension in TEMPORARY_EXTENSIONS),
        extension_lockfile=(extension in LOCKFILE_EXTENSIONS),
        extension_high_execution_risk=(extension in HIGH_EXECUTION_RISK_EXTENSIONS),
        has_multiple_extensions=len(extensions) >= 2,
        has_double_extension_pattern=bool(DOUBLE_EXTENSION_RE.search(name)),
    )


# ---------------------------------------------------------------------------
# Filename analysis
# ---------------------------------------------------------------------------


def analyze_filename(
    filename: str,
    *,
    max_filename_length: int = DEFAULT_MAX_FILENAME_LENGTH,
    max_extensions: int = DEFAULT_MAX_EXTENSION_COUNT,
) -> FilenameMetadata:
    """
    Analyze a filename without opening or stat'ing the file.
    """

    if max_filename_length <= 0:
        raise ValueError("max_filename_length must be greater than zero")

    name, stem, suffix = _safe_filename_parts(filename)

    name = name[:max_filename_length]
    stem = stem[:max_filename_length]
    suffix = suffix[:max_filename_length]

    extension_metadata = analyze_extensions(
        name,
        max_extensions=max_extensions,
    )

    return FilenameMetadata(
        name=name,
        stem=stem,
        suffix=suffix,
        name_length=len(name),
        stem_length=len(stem),
        suffix_length=len(suffix),
        name_entropy=_round_float(_safe_entropy(name)) or 0.0,
        contains_non_ascii=bool(NON_ASCII_RE.search(name)),
        contains_control_characters=bool(CONTROL_CHARACTER_RE.search(name)),
        contains_suspicious_characters=bool(
            SUSPICIOUS_FILENAME_CHARACTER_RE.search(name)
        ),
        contains_repeated_separators=bool(REPEATED_SEPARATOR_RE.search(name)),
        starts_with_dot=name.startswith("."),
        is_hidden_style_name=bool(HIDDEN_UNIX_NAME_RE.match(name)),
        is_temporary_style_name=bool(TEMPORARY_NAME_RE.search(name)),
        is_backup_style_name=bool(BACKUP_NAME_RE.search(name)),
        has_double_extension_pattern=(extension_metadata.has_double_extension_pattern),
        has_multiple_extensions=(
            extension_metadata.extension_count >= 2
            or bool(MULTIPLE_EXTENSION_RE.search(name))
        ),
    )


# ---------------------------------------------------------------------------
# Ownership
# ---------------------------------------------------------------------------


def extract_ownership(
    stat_result: os.stat_result,
) -> dict[str, Any]:
    """
    Extract numeric ownership information.

    Username/group-name resolution is deliberately not performed here.

    Resolving account names can invoke system-specific services such as
    LDAP/NSS and can introduce latency, network access, or environment-
    dependent behavior. Numeric UID/GID values are deterministic and safer
    for a feature-extraction layer.
    """

    uid = getattr(stat_result, "st_uid", None)
    gid = getattr(stat_result, "st_gid", None)

    try:
        uid_value = int(uid) if uid is not None else None
    except (TypeError, ValueError):
        uid_value = None

    try:
        gid_value = int(gid) if gid is not None else None
    except (TypeError, ValueError):
        gid_value = None

    return {
        "uid": uid_value,
        "gid": gid_value,
        "ownership_available": (uid_value is not None or gid_value is not None),
    }


# ---------------------------------------------------------------------------
# Filesystem type analysis
# ---------------------------------------------------------------------------


def analyze_file_type(
    stat_result: os.stat_result,
) -> dict[str, Any]:
    mode = getattr(stat_result, "st_mode", 0)

    return {
        "is_regular_file": bool(stat.S_ISREG(mode)),
        "is_directory": bool(stat.S_ISDIR(mode)),
        "is_symlink": bool(stat.S_ISLNK(mode)),
        "is_socket": bool(stat.S_ISSOCK(mode)),
        "is_fifo": bool(stat.S_ISFIFO(mode)),
        "is_block_device": bool(stat.S_ISBLK(mode)),
        "is_character_device": bool(stat.S_ISCHR(mode)),
    }


# ---------------------------------------------------------------------------
# Path analysis
# ---------------------------------------------------------------------------


def analyze_path(
    file_path: str,
    *,
    max_path_length: int = DEFAULT_MAX_PATH_LENGTH,
) -> dict[str, Any]:
    """
    Analyze path structure without resolving symlinks or touching the file.
    """

    if max_path_length <= 0:
        raise ValueError("max_path_length must be greater than zero")

    original = str(file_path)
    truncated = original[:max_path_length]

    path = Path(truncated)

    try:
        parts = path.parts
    except (OSError, ValueError):
        parts = ()

    name = path.name

    directory = str(path.parent)

    try:
        depth = len(parts)
    except TypeError:
        depth = 0

    directory_depth = max(0, depth - 1)

    return {
        "path_length": len(truncated),
        "path_was_truncated": len(original) > len(truncated),
        "path_depth": depth,
        "directory_depth": directory_depth,
        "directory_length": len(directory),
        "basename_length": len(name),
        "path_contains_non_ascii": bool(NON_ASCII_RE.search(truncated)),
        "path_contains_control_characters": bool(
            CONTROL_CHARACTER_RE.search(truncated)
        ),
        "path_contains_repeated_separators": bool(
            REPEATED_SEPARATOR_RE.search(truncated)
        ),
        "path_is_absolute": path.is_absolute(),
        "path_name": name,
        "path_parent": directory,
    }


# ---------------------------------------------------------------------------
# Stat metadata
# ---------------------------------------------------------------------------


def analyze_stat(
    stat_result: os.stat_result,
) -> dict[str, Any]:
    """
    Convert os.stat_result into a JSON-friendly dictionary.
    """

    size = getattr(stat_result, "st_size", None)
    inode = getattr(stat_result, "st_ino", None)
    device = getattr(stat_result, "st_dev", None)
    links = getattr(stat_result, "st_nlink", None)
    block_size = getattr(stat_result, "st_blksize", None)
    blocks = getattr(stat_result, "st_blocks", None)

    def safe_int(value: Any) -> int | None:
        try:
            return int(value)
        except (TypeError, ValueError, OverflowError):
            return None

    size_value = safe_int(size)
    inode_value = safe_int(inode)
    device_value = safe_int(device)
    links_value = safe_int(links)
    block_size_value = safe_int(block_size)
    blocks_value = safe_int(blocks)

    return {
        "size_bytes": size_value,
        "inode": inode_value,
        "device": device_value,
        "hard_link_count": links_value,
        "block_size": block_size_value,
        "allocated_blocks": blocks_value,
    }


# ---------------------------------------------------------------------------
# Public metadata extraction
# ---------------------------------------------------------------------------


def extract_metadata(
    file_path: str | os.PathLike[str],
    *,
    follow_symlinks: bool = False,
    max_filename_length: int = DEFAULT_MAX_FILENAME_LENGTH,
    max_path_length: int = DEFAULT_MAX_PATH_LENGTH,
    max_extensions: int = DEFAULT_MAX_EXTENSION_COUNT,
) -> dict[str, Any]:
    """
    Extract filesystem and filename metadata.

    Parameters
    ----------
    file_path:
        Path to the file.

    follow_symlinks:
        If False, lstat() is used so that the metadata describes the link
        itself rather than its target.

    max_filename_length:
        Maximum number of filename characters retained in descriptive output.

    max_path_length:
        Maximum number of path characters analyzed.

    max_extensions:
        Maximum number of filename extensions retained.

    Returns
    -------
    dict
        JSON-serializable metadata dictionary.

    Raises
    ------
    FileNotFoundError
        If the path does not exist.

    PermissionError
        If the process cannot stat the path.

    OSError
        For other filesystem errors.
    """

    path = Path(file_path)

    if follow_symlinks:
        stat_result = path.stat()
    else:
        stat_result = path.lstat()

    filename_metadata = analyze_filename(
        path.name,
        max_filename_length=max_filename_length,
        max_extensions=max_extensions,
    )

    extension_metadata = analyze_extensions(
        path.name,
        max_extensions=max_extensions,
    )

    timestamps = extract_timestamps(stat_result)
    permissions = extract_permissions(stat_result)
    ownership = extract_ownership(stat_result)
    file_type = analyze_file_type(stat_result)
    stat_metadata = analyze_stat(stat_result)
    path_metadata = analyze_path(
        str(path),
        max_path_length=max_path_length,
    )

    is_symlink = file_type["is_symlink"]

    symlink_target: str | None = None

    if is_symlink and not follow_symlinks:
        try:
            symlink_target = os.readlink(path)
        except (OSError, ValueError):
            symlink_target = None

    result: dict[str, Any] = {
        "metadata_version": METADATA_VERSION,
        "file_path": str(path),
        "file_name": filename_metadata.name,
        "file_stem": filename_metadata.stem,
        "file_extension": filename_metadata.suffix,
        "filename": filename_metadata.to_dict(),
        "extensions": extension_metadata.to_dict(),
        "timestamps": timestamps.to_dict(),
        "permissions": permissions.to_dict(),
        "ownership": ownership,
        "file_type": file_type,
        "stat": stat_metadata,
        "path": path_metadata,
        "symlink": {
            "is_symlink": is_symlink,
            "follow_symlinks": follow_symlinks,
            "target": symlink_target,
            "target_available": symlink_target is not None,
        },
    }

    return _round_floats(result)


# ---------------------------------------------------------------------------
# ML-oriented feature extraction
# ---------------------------------------------------------------------------


def extract_metadata_features(
    file_path: str | os.PathLike[str],
    *,
    follow_symlinks: bool = False,
    max_filename_length: int = DEFAULT_MAX_FILENAME_LENGTH,
    max_path_length: int = DEFAULT_MAX_PATH_LENGTH,
    max_extensions: int = DEFAULT_MAX_EXTENSION_COUNT,
) -> dict[str, Any]:
    """
    Return scalar/bool metadata features suitable for feature_pipeline.py.

    Descriptive strings, paths and timestamps are intentionally excluded.

    The output contains no account names and does not resolve ownership
    through external identity services.
    """

    metadata = extract_metadata(
        file_path,
        follow_symlinks=follow_symlinks,
        max_filename_length=max_filename_length,
        max_path_length=max_path_length,
        max_extensions=max_extensions,
    )

    filename = metadata["filename"]
    extensions = metadata["extensions"]
    timestamps = metadata["timestamps"]
    permissions = metadata["permissions"]
    ownership = metadata["ownership"]
    file_type = metadata["file_type"]
    stat_metadata = metadata["stat"]
    path_metadata = metadata["path"]
    symlink = metadata["symlink"]

    size_bytes = stat_metadata.get("size_bytes")

    features: dict[str, Any] = {
        "metadata_version": METADATA_VERSION,
        # File size
        "metadata_size_bytes": (size_bytes if isinstance(size_bytes, int) else 0),
        "metadata_size_log2": (
            math.log2(size_bytes + 1)
            if isinstance(size_bytes, int) and size_bytes >= 0
            else 0.0
        ),
        # Filename
        "metadata_filename_length": (filename["name_length"]),
        "metadata_filename_stem_length": (filename["stem_length"]),
        "metadata_filename_extension_length": (filename["suffix_length"]),
        "metadata_filename_entropy": (filename["name_entropy"]),
        "metadata_filename_non_ascii": (filename["contains_non_ascii"]),
        "metadata_filename_control_characters": (
            filename["contains_control_characters"]
        ),
        "metadata_filename_suspicious_characters": (
            filename["contains_suspicious_characters"]
        ),
        "metadata_filename_repeated_separators": (
            filename["contains_repeated_separators"]
        ),
        "metadata_filename_starts_with_dot": (filename["starts_with_dot"]),
        "metadata_filename_hidden_style": (filename["is_hidden_style_name"]),
        "metadata_filename_temporary_style": (filename["is_temporary_style_name"]),
        "metadata_filename_backup_style": (filename["is_backup_style_name"]),
        "metadata_filename_multiple_extensions": (filename["has_multiple_extensions"]),
        "metadata_filename_double_extension": (
            filename["has_double_extension_pattern"]
        ),
        # Extension semantics
        "metadata_extension_count": (extensions["extension_count"]),
        "metadata_extension_known_document": (extensions["extension_known_document"]),
        "metadata_extension_known_office": (extensions["extension_known_office"]),
        "metadata_extension_macro_enabled": (extensions["extension_macro_enabled"]),
        "metadata_extension_known_script": (extensions["extension_known_script"]),
        "metadata_extension_known_executable": (
            extensions["extension_known_executable"]
        ),
        "metadata_extension_known_archive": (extensions["extension_known_archive"]),
        "metadata_extension_temporary": (extensions["extension_temporary"]),
        "metadata_extension_lockfile": (extensions["extension_lockfile"]),
        "metadata_extension_high_execution_risk": (
            extensions["extension_high_execution_risk"]
        ),
        # Path
        "metadata_path_length": (path_metadata["path_length"]),
        "metadata_path_depth": (path_metadata["path_depth"]),
        "metadata_directory_depth": (path_metadata["directory_depth"]),
        "metadata_directory_length": (path_metadata["directory_length"]),
        "metadata_path_non_ascii": (path_metadata["path_contains_non_ascii"]),
        "metadata_path_control_characters": (
            path_metadata["path_contains_control_characters"]
        ),
        "metadata_path_repeated_separators": (
            path_metadata["path_contains_repeated_separators"]
        ),
        "metadata_path_absolute": (path_metadata["path_is_absolute"]),
        "metadata_path_truncated": (path_metadata["path_was_truncated"]),
        # File type
        "metadata_is_regular_file": (file_type["is_regular_file"]),
        "metadata_is_directory": (file_type["is_directory"]),
        "metadata_is_symlink": (file_type["is_symlink"]),
        "metadata_is_socket": (file_type["is_socket"]),
        "metadata_is_fifo": (file_type["is_fifo"]),
        "metadata_is_block_device": (file_type["is_block_device"]),
        "metadata_is_character_device": (file_type["is_character_device"]),
        # Permissions
        "metadata_owner_read": (permissions["owner_read"]),
        "metadata_owner_write": (permissions["owner_write"]),
        "metadata_owner_execute": (permissions["owner_execute"]),
        "metadata_group_read": (permissions["group_read"]),
        "metadata_group_write": (permissions["group_write"]),
        "metadata_group_execute": (permissions["group_execute"]),
        "metadata_other_read": (permissions["other_read"]),
        "metadata_other_write": (permissions["other_write"]),
        "metadata_other_execute": (permissions["other_execute"]),
        "metadata_world_writable": (permissions["is_world_writable"]),
        "metadata_filesystem_executable": (permissions["is_executable"]),
        # Ownership
        "metadata_ownership_available": (ownership["ownership_available"]),
        "metadata_uid": (ownership["uid"] if ownership["uid"] is not None else -1),
        "metadata_gid": (ownership["gid"] if ownership["gid"] is not None else -1),
        # Hard links
        "metadata_hard_link_count": (
            stat_metadata["hard_link_count"]
            if stat_metadata["hard_link_count"] is not None
            else 0
        ),
        # Symlink
        "metadata_symlink": (symlink["is_symlink"]),
        "metadata_symlink_target_available": (symlink["target_available"]),
        # Timestamp availability
        "metadata_created_timestamp_available": (
            timestamps["created_epoch"] is not None
        ),
        "metadata_modified_timestamp_available": (
            timestamps["modified_epoch"] is not None
        ),
        "metadata_accessed_timestamp_available": (
            timestamps["accessed_epoch"] is not None
        ),
        "metadata_changed_timestamp_available": (
            timestamps["changed_epoch"] is not None
        ),
    }

    # Timestamp deltas are generally more useful than raw wall-clock
    # timestamps for ML. They are still descriptive metadata rather than
    # maliciousness decisions.
    modified = timestamps["modified_epoch"]
    accessed = timestamps["accessed_epoch"]
    created = timestamps["created_epoch"]

    features["metadata_modified_accessed_delta_seconds"] = (
        abs(modified - accessed)
        if modified is not None and accessed is not None
        else 0.0
    )

    features["metadata_created_modified_delta_seconds"] = (
        abs(modified - created) if modified is not None and created is not None else 0.0
    )

    return _round_floats(features)


# ---------------------------------------------------------------------------
# Batch helpers
# ---------------------------------------------------------------------------


def extract_metadata_many(
    file_paths: Sequence[str | os.PathLike[str]],
    *,
    follow_symlinks: bool = False,
    max_filename_length: int = DEFAULT_MAX_FILENAME_LENGTH,
    max_path_length: int = DEFAULT_MAX_PATH_LENGTH,
    max_extensions: int = DEFAULT_MAX_EXTENSION_COUNT,
    continue_on_error: bool = True,
) -> list[dict[str, Any]]:
    """
    Extract metadata for multiple files.

    Errors are represented in-band when continue_on_error=True.

    No file contents are read by this function.
    """

    results: list[dict[str, Any]] = []

    for file_path in file_paths:
        path_string = str(file_path)

        try:
            result = extract_metadata(
                file_path,
                follow_symlinks=follow_symlinks,
                max_filename_length=max_filename_length,
                max_path_length=max_path_length,
                max_extensions=max_extensions,
            )

            results.append(result)

        except OSError as exc:
            if not continue_on_error:
                raise

            results.append(
                {
                    "metadata_version": METADATA_VERSION,
                    "file_path": path_string,
                    "metadata_error": type(exc).__name__,
                    "metadata_error_message": str(exc),
                }
            )

    return results


# ---------------------------------------------------------------------------
# Dataset-friendly helper
# ---------------------------------------------------------------------------


def extract_metadata_feature_vector(
    file_path: str | os.PathLike[str],
    *,
    feature_names: Sequence[str],
    follow_symlinks: bool = False,
) -> dict[str, Any]:
    """
    Return a stable feature vector restricted to a requested schema.

    This is useful when feature_schema.json defines the exact columns expected
    by the trained model.
    """

    features = extract_metadata_features(
        file_path,
        follow_symlinks=follow_symlinks,
    )

    vector: dict[str, Any] = {}

    for name in feature_names:
        value = features.get(name)

        if value is None:
            value = 0

        vector[name] = value

    return vector


# ---------------------------------------------------------------------------
# Module exports
# ---------------------------------------------------------------------------

__all__ = [
    "METADATA_VERSION",
    "DOCUMENT_EXTENSIONS",
    "OFFICE_EXTENSIONS",
    "MACRO_ENABLED_EXTENSIONS",
    "SCRIPT_EXTENSIONS",
    "EXECUTABLE_EXTENSIONS",
    "ARCHIVE_EXTENSIONS",
    "TEMPORARY_EXTENSIONS",
    "LOCKFILE_EXTENSIONS",
    "HIGH_EXECUTION_RISK_EXTENSIONS",
    "FileTimestamps",
    "PermissionMetadata",
    "ExtensionMetadata",
    "FilenameMetadata",
    "extract_timestamps",
    "extract_permissions",
    "extract_ownership",
    "analyze_file_type",
    "analyze_stat",
    "analyze_extensions",
    "analyze_filename",
    "analyze_path",
    "extract_metadata",
    "extract_metadata_features",
    "extract_metadata_many",
    "extract_metadata_feature_vector",
]
