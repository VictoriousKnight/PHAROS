"""Filesystem and filename metadata extraction."""

from __future__ import annotations

import math
import os
import re
import stat
from pathlib import Path
from typing import Any, Iterable, Mapping

METADATA_VERSION = 2
MAX_FILENAME_LENGTH = 4096
MAX_PATH_LENGTH = 16384
MAX_EXTENSIONS = 16


def _exts(value: str) -> frozenset[str]:
    return frozenset(f".{x}" for x in value.split())


_OFFICE = _exts(
    "doc docm docx dot dotm dotx xls xlsb xlsm xlsx xlt xltm xltx "
    "ppt pptm pptx pot potm potx pps ppsm ppsx"
)
DOCUMENT_EXTENSIONS = _OFFICE | _exts(
    "pdf rtf odt ods odp txt csv xml json html htm xhtml"
)
OFFICE_EXTENSIONS = _OFFICE
MACRO_EXTENSIONS = _exts("docm dotm xlsm xltm pptm potm ppsm")
SCRIPT_EXTENSIONS = _exts(
    "bat cmd com js jse ps1 psd1 psm1 py pyw rb sh vbe vbs wsf wsh"
)
EXECUTABLE_EXTENSIONS = _exts("apk app bin com dll elf exe msi scr sys")
ARCHIVE_EXTENSIONS = _exts("7z bz2 cab gz iso rar tar tgz xz zip")
TEMPORARY_EXTENSIONS = _exts("bak old orig part swp tmp temp")
LOCKFILE_EXTENSIONS = _exts("lock lck")
HIGH_EXECUTION_RISK_EXTENSIONS = _exts(
    "bat cmd com cpl dll exe hta jar js jse lnk msi msp ocx "
    "ps1 scr sys vbe vbs wsf wsh"
)

DOUBLE_EXTENSION_RE = re.compile(
    r"\.(?:doc|docx|docm|xls|xlsx|xlsm|ppt|pptx|pptm|pdf|txt|rtf|jpg|jpeg|png|gif|zip|rar)"
    r"\.(?:exe|scr|com|bat|cmd|js|jse|vbs|vbe|ps1|wsf|wsh|msi|dll)$",
    re.I,
)
MULTIPLE_EXTENSION_RE = re.compile(r"(?:\.[a-z0-9_-]{1,32}){3,}$", re.I)
TEMPORARY_NAME_RE = re.compile(
    r"(?:~\$|~|\.tmp$|\.temp$|\.bak$|\.swp$|\.part$|\.crdownload$|\.download$)",
    re.I,
)
BACKUP_NAME_RE = re.compile(r"(?:\.bak$|\.old$|\.orig$|~$)", re.I)
HIDDEN_NAME_RE = re.compile(r"^\.[^.].*")
NON_ASCII_RE = re.compile(r"[^\x00-\x7f]")
CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
SUSPICIOUS_NAME_RE = re.compile(r"""[<>:"/\\|?*\x00-\x1f]""")
REPEATED_SEPARATOR_RE = re.compile(r"[_\-.]{3,}")

_PERMISSION_FLAGS = {
    "owner_read": stat.S_IRUSR,
    "owner_write": stat.S_IWUSR,
    "owner_execute": stat.S_IXUSR,
    "group_read": stat.S_IRGRP,
    "group_write": stat.S_IWGRP,
    "group_execute": stat.S_IXGRP,
    "other_read": stat.S_IROTH,
    "other_write": stat.S_IWOTH,
    "other_execute": stat.S_IXOTH,
}


def _safe_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError, OverflowError):
        return None


def _safe_float(value: Any) -> float | None:
    try:
        value = float(value)
        return value if math.isfinite(value) else None
    except (TypeError, ValueError, OverflowError):
        return None


def _utc(timestamp: Any) -> str | None:
    value = _safe_float(timestamp)
    if value is None:
        return None
    try:
        from datetime import datetime, timezone

        return datetime.fromtimestamp(value, timezone.utc).isoformat()
    except (OSError, OverflowError, ValueError):
        return None


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = {c: value.count(c) for c in set(value)}
    length = len(value)
    return min(
        16.0,
        -sum((n / length) * math.log2(n / length) for n in counts.values()),
    )


def _parts(filename: str) -> tuple[str, str, str]:
    name = Path(filename).name
    suffix = Path(name).suffix.lower()
    return name, Path(name).stem, suffix


def _extensions(filename: str, max_extensions: int = MAX_EXTENSIONS) -> list[str]:
    name = Path(filename).name
    found = re.findall(r"\.[^.]+", name)
    result = []
    for ext in found:
        ext = ext.lower()
        if ext not in result:
            result.append(ext)
        if len(result) >= max(0, max_extensions):
            break
    return result


def analyze_filename(
    filename: str,
    max_length: int = MAX_FILENAME_LENGTH,
    max_extensions: int = MAX_EXTENSIONS,
) -> dict[str, Any]:
    name = str(filename or "")[:max_length]
    name, stem, suffix = _parts(name)
    return {
        "name": name,
        "stem": stem,
        "suffix": suffix,
        "name_length": len(name),
        "stem_length": len(stem),
        "suffix_length": len(suffix),
        "name_entropy": _entropy(name),
        "contains_non_ascii": bool(NON_ASCII_RE.search(name)),
        "contains_control_characters": bool(CONTROL_RE.search(name)),
        "contains_suspicious_characters": bool(SUSPICIOUS_NAME_RE.search(name)),
        "contains_repeated_separators": bool(REPEATED_SEPARATOR_RE.search(name)),
        "starts_with_dot": bool(HIDDEN_NAME_RE.match(name)),
        "hidden_style": bool(HIDDEN_NAME_RE.match(name)),
        "temporary_style": bool(TEMPORARY_NAME_RE.search(name)),
        "backup_style": bool(BACKUP_NAME_RE.search(name)),
        "double_extension": bool(DOUBLE_EXTENSION_RE.search(name)),
        "multiple_extensions": bool(MULTIPLE_EXTENSION_RE.search(name)),
        "extensions": _extensions(name, max_extensions),
    }


def analyze_extensions(
    filename: str,
    max_extensions: int = MAX_EXTENSIONS,
) -> dict[str, Any]:
    extensions = _extensions(filename, max_extensions)
    extension = Path(str(filename)).suffix.lower()
    return {
        "extension": extension,
        "extensions": extensions,
        "extension_count": len(extensions),
        "known_document": extension in DOCUMENT_EXTENSIONS,
        "known_office": extension in OFFICE_EXTENSIONS,
        "macro_enabled": extension in MACRO_EXTENSIONS,
        "known_script": extension in SCRIPT_EXTENSIONS,
        "known_executable": extension in EXECUTABLE_EXTENSIONS,
        "known_archive": extension in ARCHIVE_EXTENSIONS,
        "temporary": extension in TEMPORARY_EXTENSIONS,
        "lockfile": extension in LOCKFILE_EXTENSIONS,
        "high_execution_risk": extension in HIGH_EXECUTION_RISK_EXTENSIONS,
    }


def extract_timestamps(stat_result: os.stat_result) -> dict[str, Any]:
    changed = getattr(stat_result, "st_ctime", None)
    created = getattr(stat_result, "st_birthtime", None)
    if created is None and os.name == "nt":
        created = changed

    values = {
        "created": created,
        "modified": getattr(stat_result, "st_mtime", None),
        "accessed": getattr(stat_result, "st_atime", None),
        "changed": changed,
    }
    return {
        **{f"{k}_epoch": v for k, v in values.items()},
        **{f"{k}_utc": _utc(v) for k, v in values.items()},
    }


def extract_permissions(stat_result: os.stat_result) -> dict[str, Any]:
    mode = getattr(stat_result, "st_mode", None)
    if mode is None:
        return {
            **{name: None for name in _PERMISSION_FLAGS},
            "mode": None,
            "mode_octal": None,
            "world_writable": None,
            "executable": None,
        }

    flags = {name: bool(mode & flag) for name, flag in _PERMISSION_FLAGS.items()}
    return {
        "mode": mode,
        "mode_octal": oct(mode & 0o7777),
        **flags,
        "world_writable": flags["other_write"],
        "executable": any(
            flags[f"{group}_execute"] for group in ("owner", "group", "other")
        ),
    }


def extract_ownership(stat_result: os.stat_result) -> dict[str, Any]:
    uid = _safe_int(getattr(stat_result, "st_uid", None))
    gid = _safe_int(getattr(stat_result, "st_gid", None))
    return {"uid": uid, "gid": gid, "available": uid is not None or gid is not None}


def analyze_file_type(stat_result: os.stat_result) -> dict[str, bool]:
    mode = getattr(stat_result, "st_mode", 0)
    return {
        "regular": stat.S_ISREG(mode),
        "directory": stat.S_ISDIR(mode),
        "symlink": stat.S_ISLNK(mode),
        "socket": stat.S_ISSOCK(mode),
        "fifo": stat.S_ISFIFO(mode),
        "block_device": stat.S_ISBLK(mode),
        "character_device": stat.S_ISCHR(mode),
    }


def analyze_stat(stat_result: os.stat_result) -> dict[str, Any]:
    fields = {
        "size_bytes": "st_size",
        "inode": "st_ino",
        "device": "st_dev",
        "hard_link_count": "st_nlink",
        "block_size": "st_blksize",
        "allocated_blocks": "st_blocks",
    }
    return {
        key: _safe_int(getattr(stat_result, attr, None)) for key, attr in fields.items()
    }


def analyze_path(
    file_path: str | os.PathLike[str],
    max_length: int = MAX_PATH_LENGTH,
) -> dict[str, Any]:
    path = str(file_path)
    limited = path[:max_length]
    parent, name = os.path.dirname(limited), os.path.basename(limited)
    parts = [p for p in limited.replace("\\", "/").split("/") if p]
    return {
        "length": len(limited),
        "truncated": len(path) > max_length,
        "depth": len(parts),
        "directory_depth": max(0, len(parts) - bool(name)),
        "directory_length": len(parent),
        "basename_length": len(name),
        "non_ascii": bool(NON_ASCII_RE.search(limited)),
        "control_characters": bool(CONTROL_RE.search(limited)),
        "repeated_separators": bool(REPEATED_SEPARATOR_RE.search(limited)),
        "absolute": os.path.isabs(path),
        "name": name,
        "parent": parent,
    }


def extract_metadata(
    file_path: str | os.PathLike[str],
    follow_symlinks: bool = False,
    max_filename_length: int = MAX_FILENAME_LENGTH,
    max_path_length: int = MAX_PATH_LENGTH,
    max_extensions: int = MAX_EXTENSIONS,
) -> dict[str, Any]:
    path = Path(file_path)
    info = path.stat() if follow_symlinks else path.lstat()
    name = analyze_filename(path.name, max_filename_length, max_extensions)

    result = {
        "metadata_version": METADATA_VERSION,
        "file_path": str(path)[:max_path_length],
        "filename": name,
        "extensions": analyze_extensions(path.name, max_extensions),
        "timestamps": extract_timestamps(info),
        "permissions": extract_permissions(info),
        "ownership": extract_ownership(info),
        "file_type": analyze_file_type(info),
        "stat": analyze_stat(info),
        "path": analyze_path(path, max_path_length),
        "symlink": path.is_symlink(),
    }

    if path.is_symlink() and not follow_symlinks:
        try:
            result["symlink_target"] = os.readlink(path)
            result["symlink_target_available"] = True
        except OSError:
            result["symlink_target"] = None
            result["symlink_target_available"] = False
    else:
        result["symlink_target"] = None
        result["symlink_target_available"] = False

    return result


def _prefixed(
    prefix: str,
    source: Mapping[str, Any],
    mapping: Mapping[str, str],
) -> dict[str, Any]:
    return {prefix + dst: source[src] for dst, src in mapping.items()}


def extract_metadata_features(
    file_path: str | os.PathLike[str],
    follow_symlinks: bool = False,
    max_filename_length: int = MAX_FILENAME_LENGTH,
    max_path_length: int = MAX_PATH_LENGTH,
    max_extensions: int = MAX_EXTENSIONS,
) -> dict[str, Any]:
    data = extract_metadata(
        file_path,
        follow_symlinks,
        max_filename_length,
        max_path_length,
        max_extensions,
    )
    name, ext = data["filename"], data["extensions"]
    path, typ = data["path"], data["file_type"]
    perm, owner = data["permissions"], data["ownership"]
    stat_data, times = data["stat"], data["timestamps"]

    size = stat_data.get("size_bytes") or 0
    created, modified = times.get("created_epoch"), times.get("modified_epoch")
    accessed = times.get("accessed_epoch")

    features = {
        "metadata_version": METADATA_VERSION,
        "metadata_size_bytes": size,
        "metadata_size_log2": math.log2(size + 1) if size >= 0 else 0.0,
        "metadata_symlink": bool(data["symlink"]),
        "metadata_symlink_target_available": bool(data["symlink_target_available"]),
        "metadata_ownership_available": bool(owner["available"]),
        "metadata_uid": owner["uid"] if owner["uid"] is not None else -1,
        "metadata_gid": owner["gid"] if owner["gid"] is not None else -1,
        "metadata_hard_link_count": stat_data["hard_link_count"] or 0,
        "metadata_created_timestamp_available": created is not None,
        "metadata_modified_timestamp_available": modified is not None,
        "metadata_accessed_timestamp_available": accessed is not None,
        "metadata_changed_timestamp_available": times.get("changed_epoch") is not None,
        "metadata_modified_accessed_delta": (
            modified - accessed
            if modified is not None and accessed is not None
            else 0.0
        ),
        "metadata_created_modified_delta": (
            modified - created if modified is not None and created is not None else 0.0
        ),
    }

    features.update(
        _prefixed(
            "metadata_filename_",
            name,
            {
                "length": "name_length",
                "stem_length": "stem_length",
                "extension_length": "suffix_length",
                "entropy": "name_entropy",
                "non_ascii": "contains_non_ascii",
                "control": "contains_control_characters",
                "suspicious": "contains_suspicious_characters",
                "repeated_separators": "contains_repeated_separators",
                "hidden": "starts_with_dot",
                "temporary": "temporary_style",
                "backup": "backup_style",
                "multiple_extensions": "multiple_extensions",
                "double_extension": "double_extension",
            },
        )
    )
    features.update(
        _prefixed(
            "metadata_extension_",
            ext,
            {
                "count": "extension_count",
                "document": "known_document",
                "office": "known_office",
                "macro": "macro_enabled",
                "script": "known_script",
                "executable": "known_executable",
                "archive": "known_archive",
                "temporary": "temporary",
                "lockfile": "lockfile",
                "execution_risk": "high_execution_risk",
            },
        )
    )
    features.update(
        _prefixed(
            "metadata_path_",
            path,
            {
                "length": "length",
                "depth": "depth",
                "directory_depth": "directory_depth",
                "directory_length": "directory_length",
                "non_ascii": "non_ascii",
                "control": "control_characters",
                "repeated_separators": "repeated_separators",
                "absolute": "absolute",
                "truncated": "truncated",
            },
        )
    )
    features.update(
        _prefixed(
            "metadata_is_",
            typ,
            {
                "regular_file": "regular",
                "directory": "directory",
                "symlink": "symlink",
                "socket": "socket",
                "fifo": "fifo",
                "block_device": "block_device",
                "character_device": "character_device",
            },
        )
    )
    features.update(
        _prefixed(
            "metadata_",
            perm,
            {
                "owner_read": "owner_read",
                "owner_write": "owner_write",
                "owner_execute": "owner_execute",
                "group_read": "group_read",
                "group_write": "group_write",
                "group_execute": "group_execute",
                "other_read": "other_read",
                "other_write": "other_write",
                "other_execute": "other_execute",
                "world_writable": "world_writable",
                "filesystem_executable": "executable",
            },
        )
    )

    return features


def extract_metadata_many(
    file_paths: Iterable[str | os.PathLike[str]],
    follow_symlinks: bool = False,
    continue_on_error: bool = True,
) -> list[dict[str, Any]]:
    result = []
    for file_path in file_paths:
        try:
            result.append(extract_metadata(file_path, follow_symlinks))
        except OSError as exc:
            if not continue_on_error:
                raise
            result.append(
                {
                    "metadata_version": METADATA_VERSION,
                    "file_path": str(file_path),
                    "metadata_error": type(exc).__name__,
                    "metadata_error_message": str(exc),
                }
            )
    return result


def extract_metadata_feature_vector(
    file_path: str | os.PathLike[str],
    feature_names: Iterable[str],
    follow_symlinks: bool = False,
) -> dict[str, Any]:
    features = extract_metadata_features(file_path, follow_symlinks)
    return {name: features.get(name, 0) for name in feature_names}


# Pipeline compatibility aliases.
extract_features = extract_metadata_features
analyze_features = extract_metadata_features
extract = extract_metadata
analyze = extract_metadata


__all__ = [
    "METADATA_VERSION",
    "MAX_FILENAME_LENGTH",
    "MAX_PATH_LENGTH",
    "MAX_EXTENSIONS",
    "DOCUMENT_EXTENSIONS",
    "OFFICE_EXTENSIONS",
    "MACRO_EXTENSIONS",
    "SCRIPT_EXTENSIONS",
    "EXECUTABLE_EXTENSIONS",
    "ARCHIVE_EXTENSIONS",
    "TEMPORARY_EXTENSIONS",
    "LOCKFILE_EXTENSIONS",
    "HIGH_EXECUTION_RISK_EXTENSIONS",
    "analyze_filename",
    "analyze_extensions",
    "extract_timestamps",
    "extract_permissions",
    "extract_ownership",
    "analyze_file_type",
    "analyze_stat",
    "analyze_path",
    "extract_metadata",
    "extract_metadata_features",
    "extract_metadata_many",
    "extract_metadata_feature_vector",
    "extract_features",
    "analyze_features",
    "extract",
    "analyze",
]
