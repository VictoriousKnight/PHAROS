"""
Static OLE Compound File Binary Format (CFB) analysis.

This module analyzes legacy Microsoft Office/OLE containers commonly found
in files such as:

    .doc
    .xls
    .ppt
    .dot
    .xlt
    .pot
    .msg
    .vsd
    .pub

It can also be used against OLE payloads embedded inside OOXML packages.

Security model
--------------
This module is static-only.

It:
    - detects OLE/CFB containers
    - parses the compound-file directory
    - enumerates storages and streams
    - identifies VBA/macro-related structures
    - identifies common Office/OLE stream indicators
    - calculates bounded stream statistics
    - detects suspicious stream names
    - exposes ML-ready scalar features

It does NOT:
    - execute VBA
    - execute embedded objects
    - instantiate COM objects
    - resolve external links
    - launch child processes
    - write extracted objects to disk
    - modify the source file
    - download referenced resources

Optional dependency
-------------------
If ``olefile`` is installed, it is used for additional high-level parsing
and VBA stream discovery. The built-in CFB parser remains responsible for
basic container validation and directory/stream analysis, so the module
does not depend entirely on third-party parsing behavior.

The intended extraction flow is:

    OOXML / legacy Office file
              |
              +---- embedded_objects.py
              |          |
              |          +---- OLE payload
              |
              v
           ole.py
              |
              +---- CFB structure
              +---- VBA indicators
              +---- stream metadata
              +---- suspicious structures
              |
              v
        office_features.py
              |
              v
        feature_pipeline.py
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Optional, Sequence, Tuple
import hashlib
import io
import math
import re
import struct
import zipfile

OLE_VERSION = 1

# Microsoft Compound File Binary Format signature.
OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"

# Common byte-order marker for CFB.
LITTLE_ENDIAN_BYTE_ORDER = b"\xfe\xff"

# ---------------------------------------------------------------------------
# Parser limits
# ---------------------------------------------------------------------------

DEFAULT_MAX_STREAMS = 4096
DEFAULT_MAX_STREAM_SIZE = 64 * 1024 * 1024
DEFAULT_MAX_TOTAL_STREAM_BYTES = 256 * 1024 * 1024
DEFAULT_MAX_DIRECTORY_ENTRIES = 8192
DEFAULT_MAX_PATH_LENGTH = 4096
DEFAULT_MAX_SAMPLE_BYTES = 1024 * 1024

# ---------------------------------------------------------------------------
# CFB constants
# ---------------------------------------------------------------------------

FREESECT = 0xFFFFFFFF
ENDOFCHAIN = 0xFFFFFFFE
FATSECT = 0xFFFFFFFD
DIFSECT = 0xFFFFFFFC
NOSTREAM = 0xFFFFFFFF

OBJ_STORAGE = 1
OBJ_STREAM = 2
OBJ_ROOT = 5

MINI_STREAM_CUTOFF = 4096

SECTOR_SIZE_BY_SHIFT = {
    9: 512,
    12: 4096,
}

MINI_SECTOR_SIZE = 64

MAX_FAT_ENTRIES = 10_000_000


# ---------------------------------------------------------------------------
# Regex indicators
# ---------------------------------------------------------------------------

VBA_STREAM_PATTERN = re.compile(
    r"(?i)(?:^|/|\\)"
    r"(?:vba|dir|project|projectwm|"
    r"_vba_project|"
    r"__srp_|"
    r""
    r")"
)

VBA_NAME_PATTERN = re.compile(
    r"(?i)^(?:vba|dir|project|projectwm|_vba_project|"
    r"__srp_[a-z0-9_]+|"
    r"module\d*|"
    r"thisdocument|"
    r"sheet\d+|"
    r"workbook)$"
)

VBA_MODULE_PATTERN = re.compile(
    r"(?i)(?:"
    r"thisdocument|"
    r"workbook|"
    r"sheet\d+|"
    r"module\d+|"
    r"class\d+|"
    r"form\d+|"
    r"bas\d+"
    r")"
)

SUSPICIOUS_STREAM_NAME_PATTERN = re.compile(
    r"(?i)(?:"
    r"vba|"
    r"macro|"
    r"module|"
    r"script|"
    r"activex|"
    r"ole|"
    r"object|"
    r"package|"
    r"control|"
    r"embeddings?|"
    r"external|"
    r"link"
    r")"
)

EXECUTION_INDICATOR_PATTERN = re.compile(
    r"(?i)(?:"
    r"powershell|"
    r"cmd(?:\.exe)?|"
    r"wscript|"
    r"cscript|"
    r"mshta|"
    r"rundll32|"
    r"regsvr32|"
    r"shell|"
    r"createprocess|"
    r"winexec|"
    r"autoopen|"
    r"document_open|"
    r"workbook_open|"
    r"autoexec"
    r")"
)

DOWNLOAD_INDICATOR_PATTERN = re.compile(
    r"(?i)(?:"
    r"http://|"
    r"https://|"
    r"ftp://|"
    r"urlmon|"
    r"winhttp|"
    r"wininet|"
    r"urldownload|"
    r"xmlhttp|"
    r"inet"
    r")"
)

PERSISTENCE_INDICATOR_PATTERN = re.compile(
    r"(?i)(?:"
    r"startup|"
    r"runonce|"
    r"\\run\\|"
    r"currentversion\\run|"
    r"registry"
    r")"
)

OBFUSCATION_INDICATOR_PATTERN = re.compile(
    r"(?i)(?:"
    r"base64|"
    r"frombase64string|"
    r"chr\s*\(|"
    r"char\s*\(|"
    r"strreverse|"
    r"replace\s*\(|"
    r"xor|"
    r"hex"
    r")"
)

URL_PATTERN = re.compile(rb"(?i)\b(?:https?|ftp)://[^\x00\s<>'\"]+")

WINDOWS_PATH_PATTERN = re.compile(rb"(?i)(?:[A-Z]:\\|\\\\)[^\x00\r\n]{2,}")

IPV4_PATTERN = re.compile(
    rb"\b(?:"
    rb"(?:25[0-5]|2[0-4]\d|1?\d?\d)"
    rb"\."
    rb"){3}"
    rb"(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
)

BASE64_PATTERN = re.compile(
    rb"(?<![A-Za-z0-9+/])" rb"[A-Za-z0-9+/]{24,}={0,2}" rb"(?![A-Za-z0-9+/])"
)

SHELL_PATTERN = re.compile(
    rb"(?i)(?:"
    rb"powershell|cmd\.exe|wscript|cscript|mshta|"
    rb"rundll32|regsvr32|"
    rb"createprocess|winexec|"
    rb"shell\s*\(|"
    rb"wmi|"
    rb"adodb\.stream"
    rb")"
)

MACRO_TEXT_PATTERN = re.compile(
    rb"(?i)(?:"
    rb"autoopen|"
    rb"auto_open|"
    rb"document_open|"
    rb"workbook_open|"
    rb"autoexec|"
    rb"vbproject|"
    rb"vbcomponents|"
    rb"codemodule|"
    rb"shell\s*\(|"
    rb"createobject|"
    rb"getobject"
    rb")"
)


# ---------------------------------------------------------------------------
# CFB special values
# ---------------------------------------------------------------------------


def _u32(data: bytes, offset: int) -> int:
    """Read a little-endian unsigned 32-bit integer safely."""

    if offset < 0 or offset + 4 > len(data):
        return 0

    return struct.unpack_from("<I", data, offset)[0]


def _u16(data: bytes, offset: int) -> int:
    """Read a little-endian unsigned 16-bit integer safely."""

    if offset < 0 or offset + 2 > len(data):
        return 0

    return struct.unpack_from("<H", data, offset)[0]


def _u64(data: bytes, offset: int) -> int:
    """Read a little-endian unsigned 64-bit integer safely."""

    if offset < 0 or offset + 8 > len(data):
        return 0

    return struct.unpack_from("<Q", data, offset)[0]


def _is_special_sector(value: int) -> bool:
    return value in {
        FREESECT,
        ENDOFCHAIN,
        FATSECT,
        DIFSECT,
    }


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass
class OLEStreamRecord:
    """
    Metadata describing one OLE stream.

    Payload bytes are not retained in this record.
    """

    stream_id: int
    name: str
    path: str

    size: int
    start_sector: int

    is_mini_stream: bool

    sha256: Optional[str] = None
    entropy: Optional[float] = None

    contains_url: bool = False
    contains_ipv4: bool = False
    contains_windows_path: bool = False
    contains_base64_like: bool = False
    contains_shell_indicator: bool = False
    contains_macro_indicator: bool = False

    is_vba_related: bool = False
    is_suspicious_name: bool = False
    is_suspicious_content: bool = False

    def to_dict(self) -> Dict[str, object]:
        return {
            "stream_id": self.stream_id,
            "name": self.name,
            "path": self.path,
            "size": self.size,
            "start_sector": self.start_sector,
            "is_mini_stream": self.is_mini_stream,
            "sha256": self.sha256,
            "entropy": self.entropy,
            "contains_url": self.contains_url,
            "contains_ipv4": self.contains_ipv4,
            "contains_windows_path": self.contains_windows_path,
            "contains_base64_like": self.contains_base64_like,
            "contains_shell_indicator": self.contains_shell_indicator,
            "contains_macro_indicator": self.contains_macro_indicator,
            "is_vba_related": self.is_vba_related,
            "is_suspicious_name": self.is_suspicious_name,
            "is_suspicious_content": self.is_suspicious_content,
        }


@dataclass
class OLEDirectoryEntry:
    """
    Internal CFB directory entry.

    This is exposed in analysis output because directory structure is useful
    evidence when investigating malformed or weaponized OLE files.
    """

    entry_id: int
    name: str
    object_type: int

    color: int

    left_sibling: int
    right_sibling: int
    child: int

    clsid: str

    state_bits: int
    creation_time: int
    modified_time: int

    start_sector: int
    stream_size: int

    parent_id: Optional[int] = None

    def to_dict(self) -> Dict[str, object]:
        return {
            "entry_id": self.entry_id,
            "name": self.name,
            "object_type": self.object_type,
            "color": self.color,
            "left_sibling": self.left_sibling,
            "right_sibling": self.right_sibling,
            "child": self.child,
            "clsid": self.clsid,
            "state_bits": self.state_bits,
            "creation_time": self.creation_time,
            "modified_time": self.modified_time,
            "start_sector": self.start_sector,
            "stream_size": self.stream_size,
            "parent_id": self.parent_id,
        }


@dataclass
class OLEStatistics:
    """
    Aggregate OLE container statistics.
    """

    directory_entries: int = 0
    storage_count: int = 0
    stream_count: int = 0

    non_empty_stream_count: int = 0
    mini_stream_count: int = 0
    large_stream_count: int = 0

    total_stream_bytes: int = 0
    maximum_stream_size: int = 0

    vba_stream_count: int = 0
    macro_related_stream_count: int = 0

    suspicious_name_count: int = 0
    suspicious_content_count: int = 0

    url_stream_count: int = 0
    ipv4_stream_count: int = 0
    windows_path_stream_count: int = 0
    base64_like_stream_count: int = 0
    shell_indicator_stream_count: int = 0

    high_entropy_stream_count: int = 0

    root_clsid_count: int = 0
    non_empty_clsid_count: int = 0

    object_type_counts: Dict[str, int] = field(default_factory=dict)
    stream_name_counts: Dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, object]:
        return {
            "directory_entries": self.directory_entries,
            "storage_count": self.storage_count,
            "stream_count": self.stream_count,
            "non_empty_stream_count": self.non_empty_stream_count,
            "mini_stream_count": self.mini_stream_count,
            "large_stream_count": self.large_stream_count,
            "total_stream_bytes": self.total_stream_bytes,
            "maximum_stream_size": self.maximum_stream_size,
            "vba_stream_count": self.vba_stream_count,
            "macro_related_stream_count": self.macro_related_stream_count,
            "suspicious_name_count": self.suspicious_name_count,
            "suspicious_content_count": self.suspicious_content_count,
            "url_stream_count": self.url_stream_count,
            "ipv4_stream_count": self.ipv4_stream_count,
            "windows_path_stream_count": self.windows_path_stream_count,
            "base64_like_stream_count": self.base64_like_stream_count,
            "shell_indicator_stream_count": self.shell_indicator_stream_count,
            "high_entropy_stream_count": self.high_entropy_stream_count,
            "root_clsid_count": self.root_clsid_count,
            "non_empty_clsid_count": self.non_empty_clsid_count,
            "object_type_counts": dict(self.object_type_counts),
            "stream_name_counts": dict(self.stream_name_counts),
        }


@dataclass
class OLEAnalysis:
    """
    Complete static OLE analysis result.
    """

    version: int

    is_ole: bool
    valid_header: bool
    parse_error: bool

    sector_size: int
    mini_sector_size: int

    package_path: Optional[str]

    directories: List[OLEDirectoryEntry]
    streams: List[OLEStreamRecord]
    statistics: OLEStatistics

    root_clsid: Optional[str] = None

    has_vba: bool = False
    has_macros: bool = False
    has_embedded_objects: bool = False

    suspicious: bool = False

    truncated: bool = False
    truncation_reasons: List[str] = field(default_factory=list)

    parser_backend: str = "builtin"

    def to_dict(self) -> Dict[str, object]:
        return {
            "version": self.version,
            "is_ole": self.is_ole,
            "valid_header": self.valid_header,
            "parse_error": self.parse_error,
            "sector_size": self.sector_size,
            "mini_sector_size": self.mini_sector_size,
            "package_path": self.package_path,
            "directories": [entry.to_dict() for entry in self.directories],
            "streams": [stream.to_dict() for stream in self.streams],
            "statistics": self.statistics.to_dict(),
            "root_clsid": self.root_clsid,
            "has_vba": self.has_vba,
            "has_macros": self.has_macros,
            "has_embedded_objects": self.has_embedded_objects,
            "suspicious": self.suspicious,
            "truncated": self.truncated,
            "truncation_reasons": list(self.truncation_reasons),
            "parser_backend": self.parser_backend,
        }


# ---------------------------------------------------------------------------
# General helpers
# ---------------------------------------------------------------------------


def _shannon_entropy(data: bytes) -> float:
    """
    Calculate Shannon entropy in bits per byte.
    """

    if not data:
        return 0.0

    counts = [0] * 256

    for byte in data:
        counts[byte] += 1

    length = len(data)
    entropy = 0.0

    for count in counts:
        if count == 0:
            continue

        probability = count / length
        entropy -= probability * math.log2(probability)

    return entropy


def _safe_ascii(value: bytes) -> str:
    """
    Decode bounded ASCII-ish bytes safely.
    """

    return value.decode(
        "ascii",
        errors="replace",
    ).rstrip("\x00")


def _decode_directory_name(raw: bytes) -> str:
    """
    Decode the 64-byte CFB directory name field.

    CFB directory names are normally UTF-16LE and include a byte-length
    field. Malformed names are handled defensively.
    """

    if len(raw) < 64:
        raw = raw.ljust(64, b"\x00")

    name_length = _u16(raw, 64 - 2)

    if name_length < 2:
        return ""

    name_length = min(name_length, 64)

    payload = raw[: name_length - 2]

    try:
        return payload.decode(
            "utf-16le",
            errors="replace",
        )
    except UnicodeError:
        return payload.decode(
            "latin-1",
            errors="replace",
        )


def _format_clsid(raw: bytes) -> str:
    """
    Format the 16-byte CFB CLSID as a conventional GUID string.
    """

    if len(raw) != 16 or raw == b"\x00" * 16:
        return ""

    try:
        part1 = struct.unpack_from("<I", raw, 0)[0]
        part2 = struct.unpack_from("<H", raw, 4)[0]
        part3 = struct.unpack_from("<H", raw, 6)[0]

        part4 = raw[8:10].hex()
        part5 = raw[10:16].hex()

        return f"{part1:08x}-{part2:04x}-{part3:04x}-" f"{part4}-{part5}"
    except (struct.error, IndexError):
        return ""


def _increment(mapping: Dict[str, int], key: str) -> None:
    mapping[key] = mapping.get(key, 0) + 1


def _normalize_name(value: str) -> str:
    return str(value or "").strip().replace("\x00", "")


def _path_join(parent: str, name: str) -> str:
    name = _normalize_name(name)

    if not parent:
        return name

    if not name:
        return parent

    return f"{parent}/{name}"


def _object_type_name(object_type: int) -> str:
    return {
        0: "empty",
        OBJ_STORAGE: "storage",
        OBJ_STREAM: "stream",
        3: "lockbytes",
        4: "property",
        OBJ_ROOT: "root",
    }.get(object_type, "unknown")


def _is_vba_related_name(name: str, path: str) -> bool:
    """
    Identify names associated with VBA storage/streams.

    Name-based detection is intentionally conservative and should be
    combined with content-level indicators by the caller.
    """

    normalized = _normalize_name(name)

    if VBA_NAME_PATTERN.search(normalized):
        return True

    lower_path = path.lower()

    if "/vba/" in f"/{lower_path}/":
        return True

    if lower_path.endswith("/dir"):
        return True

    if lower_path.endswith("/project"):
        return True

    if lower_path.endswith("/projectwm"):
        return True

    if "_vba_project" in lower_path:
        return True

    return False


def _is_suspicious_stream_name(name: str, path: str) -> bool:
    return bool(
        SUSPICIOUS_STREAM_NAME_PATTERN.search(name)
        or SUSPICIOUS_STREAM_NAME_PATTERN.search(path)
    )


def _contains_pattern(data: bytes, pattern: re.Pattern[bytes]) -> bool:
    try:
        return bool(pattern.search(data))
    except (TypeError, ValueError):
        return False


def _looks_like_vba_content(data: bytes) -> bool:
    return _contains_pattern(data, MACRO_TEXT_PATTERN)


def _is_suspicious_content(data: bytes) -> bool:
    if _contains_pattern(data, SHELL_PATTERN):
        return True

    if _contains_pattern(data, DOWNLOAD_INDICATOR_PATTERN):
        return True

    if _contains_pattern(data, PERSISTENCE_INDICATOR_PATTERN):
        return True

    if _contains_pattern(data, OBFUSCATION_INDICATOR_PATTERN):
        return True

    if _contains_pattern(data, MACRO_TEXT_PATTERN):
        return True

    return False


# ---------------------------------------------------------------------------
# CFB header
# ---------------------------------------------------------------------------


@dataclass
class _CFBHeader:
    sector_shift: int
    mini_sector_shift: int

    major_version: int
    minor_version: int

    byte_order: int

    num_dir_sectors: int
    num_fat_sectors: int

    first_dir_sector: int
    transaction_signature: int

    mini_stream_cutoff: int
    first_mini_fat_sector: int
    num_mini_fat_sectors: int

    first_difat_sector: int
    num_difat_sectors: int

    difat: List[int]


def _parse_header(data: bytes) -> Optional[_CFBHeader]:
    """
    Parse the 512-byte CFB header.
    """

    if len(data) < 512:
        return None

    if data[:8] != OLE_MAGIC:
        return None

    sector_shift = _u16(data, 30)
    mini_sector_shift = _u16(data, 32)

    if sector_shift not in SECTOR_SIZE_BY_SHIFT:
        return None

    if mini_sector_shift != 6:
        return None

    major_version = _u16(data, 26)
    minor_version = _u16(data, 24)
    byte_order = _u16(data, 28)

    if byte_order != 0xFFFE:
        return None

    num_dir_sectors = _u32(data, 40)
    num_fat_sectors = _u32(data, 44)

    first_dir_sector = _u32(data, 48)
    transaction_signature = _u32(data, 52)

    mini_stream_cutoff = _u32(data, 56)

    first_mini_fat_sector = _u32(data, 60)
    num_mini_fat_sectors = _u32(data, 64)

    first_difat_sector = _u32(data, 68)
    num_difat_sectors = _u32(data, 72)

    difat = []

    # Header contains 109 DIFAT entries from offset 76.
    for index in range(109):
        value = _u32(data, 76 + index * 4)

        if value != FREESECT:
            difat.append(value)

    return _CFBHeader(
        sector_shift=sector_shift,
        mini_sector_shift=mini_sector_shift,
        major_version=major_version,
        minor_version=minor_version,
        byte_order=byte_order,
        num_dir_sectors=num_dir_sectors,
        num_fat_sectors=num_fat_sectors,
        first_dir_sector=first_dir_sector,
        transaction_signature=transaction_signature,
        mini_stream_cutoff=mini_stream_cutoff,
        first_mini_fat_sector=first_mini_fat_sector,
        num_mini_fat_sectors=num_mini_fat_sectors,
        first_difat_sector=first_difat_sector,
        num_difat_sectors=num_difat_sectors,
        difat=difat,
    )


# ---------------------------------------------------------------------------
# Sector access
# ---------------------------------------------------------------------------


class _CFBReader:
    """
    Bounded in-memory CFB reader.

    It never writes or modifies the source bytes.
    """

    def __init__(
        self,
        data: bytes,
        header: _CFBHeader,
    ) -> None:
        self.data = data
        self.header = header
        self.sector_size = SECTOR_SIZE_BY_SHIFT[header.sector_shift]

    @property
    def sector_count(self) -> int:
        if len(self.data) <= 512:
            return 0

        available = len(self.data) - 512

        return available // self.sector_size

    def sector_offset(self, sector_id: int) -> Optional[int]:
        if sector_id < 0:
            return None

        offset = 512 + sector_id * self.sector_size

        if offset < 512:
            return None

        if offset + self.sector_size > len(self.data):
            return None

        return offset

    def read_sector(self, sector_id: int) -> Optional[bytes]:
        offset = self.sector_offset(sector_id)

        if offset is None:
            return None

        return self.data[offset : offset + self.sector_size]

    def read_sector_uint32(
        self,
        sector_id: int,
    ) -> Optional[List[int]]:
        sector = self.read_sector(sector_id)

        if sector is None:
            return None

        values = []

        for offset in range(
            0,
            len(sector) - 3,
            4,
        ):
            values.append(_u32(sector, offset))

        return values


# ---------------------------------------------------------------------------
# DIFAT / FAT
# ---------------------------------------------------------------------------


def _read_difat(
    reader: _CFBReader,
    header: _CFBHeader,
) -> List[int]:
    """
    Read the complete DIFAT chain.

    The implementation is bounded by the physical input size and the
    declared DIFAT sector count.
    """

    fat_sectors = [value for value in header.difat if value != FREESECT]

    if header.num_difat_sectors == 0:
        return fat_sectors

    current = header.first_difat_sector
    visited: set[int] = set()

    entries_per_sector = (reader.sector_size // 4) - 1

    max_iterations = min(
        header.num_difat_sectors,
        reader.sector_count + 1,
    )

    for _ in range(max_iterations):
        if current in visited:
            break

        if current in {
            FREESECT,
            ENDOFCHAIN,
        }:
            break

        visited.add(current)

        values = reader.read_sector_uint32(current)

        if not values:
            break

        for value in values[:entries_per_sector]:
            if value != FREESECT:
                fat_sectors.append(value)

        current = values[-1]

    return fat_sectors


def _read_fat(
    reader: _CFBReader,
    header: _CFBHeader,
) -> List[int]:
    """
    Construct the sector allocation table.
    """

    difat = _read_difat(reader, header)

    if not difat:
        return []

    if len(difat) > max(
        header.num_fat_sectors + 109,
        109,
    ):
        difat = difat[: header.num_fat_sectors + 109]

    fat: List[int] = []

    for sector_id in difat:
        values = reader.read_sector_uint32(sector_id)

        if not values:
            continue

        fat.extend(values)

        if len(fat) >= MAX_FAT_ENTRIES:
            return fat[:MAX_FAT_ENTRIES]

    return fat


def _sector_chain(
    fat: Sequence[int],
    start_sector: int,
    *,
    max_sectors: int,
) -> List[int]:
    """
    Follow a CFB FAT chain defensively.
    """

    if start_sector in {
        FREESECT,
        ENDOFCHAIN,
        FATSECT,
        DIFSECT,
        NOSTREAM,
    }:
        return []

    if start_sector < 0:
        return []

    chain: List[int] = []
    visited: set[int] = set()

    current = start_sector

    while len(chain) < max_sectors:
        if current in visited:
            break

        if current >= len(fat):
            break

        if current in {
            FREESECT,
            ENDOFCHAIN,
            FATSECT,
            DIFSECT,
        }:
            break

        visited.add(current)
        chain.append(current)

        next_sector = fat[current]

        if next_sector == ENDOFCHAIN:
            break

        if next_sector in {
            FREESECT,
            FATSECT,
            DIFSECT,
        }:
            break

        current = next_sector

    return chain


def _read_chain(
    reader: _CFBReader,
    fat: Sequence[int],
    start_sector: int,
    size: int,
    *,
    max_bytes: int,
) -> bytes:
    """
    Read a normal FAT stream with a strict output bound.
    """

    if size <= 0:
        return b""

    requested = min(
        int(size),
        int(max_bytes),
    )

    max_sectors = (requested + reader.sector_size - 1) // reader.sector_size

    chain = _sector_chain(
        fat,
        start_sector,
        max_sectors=max_sectors,
    )

    output = bytearray()

    for sector_id in chain:
        sector = reader.read_sector(sector_id)

        if sector is None:
            break

        remaining = requested - len(output)

        if remaining <= 0:
            break

        output.extend(sector[:remaining])

    return bytes(output)


# ---------------------------------------------------------------------------
# Directory parsing
# ---------------------------------------------------------------------------


def _read_directory(
    reader: _CFBReader,
    fat: Sequence[int],
    header: _CFBHeader,
    *,
    max_directory_entries: int,
) -> Tuple[List[OLEDirectoryEntry], bool]:
    """
    Parse the CFB directory stream.
    """

    directory_size = max(
        reader.sector_size,
        max_directory_entries * 128,
    )

    raw = _read_chain(
        reader,
        fat,
        header.first_dir_sector,
        directory_size,
        max_bytes=directory_size,
    )

    if not raw:
        return [], False

    entries: List[OLEDirectoryEntry] = []

    maximum = min(
        len(raw) // 128,
        max_directory_entries,
    )

    truncated = len(raw) // 128 > max_directory_entries

    for entry_id in range(maximum):
        offset = entry_id * 128

        entry_data = raw[offset : offset + 128]

        if len(entry_data) < 128:
            break

        object_type = entry_data[66]

        if object_type == 0:
            continue

        name = _decode_directory_name(entry_data[:64])

        color = entry_data[67]

        left_sibling = _u32(entry_data, 68)
        right_sibling = _u32(entry_data, 72)
        child = _u32(entry_data, 76)

        clsid = _format_clsid(entry_data[80:96])

        state_bits = _u32(entry_data, 96)

        creation_time = _u64(
            entry_data,
            100,
        )

        modified_time = _u64(
            entry_data,
            108,
        )

        start_sector = _u32(
            entry_data,
            116,
        )

        stream_size = _u64(
            entry_data,
            120,
        )

        # Version 3+ stores stream sizes as 64-bit, while older versions
        # effectively use the lower 32 bits.
        if header.major_version < 4:
            stream_size &= 0xFFFFFFFF

        entries.append(
            OLEDirectoryEntry(
                entry_id=entry_id,
                name=name,
                object_type=object_type,
                color=color,
                left_sibling=left_sibling,
                right_sibling=right_sibling,
                child=child,
                clsid=clsid,
                state_bits=state_bits,
                creation_time=creation_time,
                modified_time=modified_time,
                start_sector=start_sector,
                stream_size=stream_size,
            )
        )

    # Recover parent relationships by walking the storage child trees.
    entry_map = {entry.entry_id: entry for entry in entries}

    def assign_parent(
        child_id: int,
        parent_id: int,
        visited: set[int],
    ) -> None:
        if child_id in {
            NOSTREAM,
            FREESECT,
        }:
            return

        if child_id in visited:
            return

        entry = entry_map.get(child_id)

        if entry is None:
            return

        visited.add(child_id)

        if entry.parent_id is None:
            entry.parent_id = parent_id

        assign_parent(
            entry.left_sibling,
            parent_id,
            visited,
        )

        assign_parent(
            entry.right_sibling,
            parent_id,
            visited,
        )

        if entry.object_type in {
            OBJ_STORAGE,
            OBJ_ROOT,
        }:
            assign_parent(
                entry.child,
                entry.entry_id,
                visited,
            )

    roots = [entry for entry in entries if entry.object_type == OBJ_ROOT]

    for root in roots:
        assign_parent(
            root.child,
            root.entry_id,
            set(),
        )

    return entries, truncated


# ---------------------------------------------------------------------------
# Mini stream support
# ---------------------------------------------------------------------------


def _read_mini_fat(
    reader: _CFBReader,
    fat: Sequence[int],
    header: _CFBHeader,
) -> List[int]:
    """
    Read the MiniFAT chain.
    """

    if header.num_mini_fat_sectors == 0:
        return []

    sector_count = min(
        header.num_mini_fat_sectors,
        reader.sector_count,
    )

    raw = _read_chain(
        reader,
        fat,
        header.first_mini_fat_sector,
        sector_count * reader.sector_size,
        max_bytes=sector_count * reader.sector_size,
    )

    values = []

    for offset in range(
        0,
        len(raw) - 3,
        4,
    ):
        values.append(_u32(raw, offset))

        if len(values) >= MAX_FAT_ENTRIES:
            break

    return values


def _read_mini_chain(
    mini_stream: bytes,
    mini_fat: Sequence[int],
    start_sector: int,
    size: int,
    *,
    max_bytes: int,
) -> bytes:
    """
    Read a stream from the CFB Mini Stream.
    """

    if size <= 0:
        return b""

    requested = min(
        int(size),
        int(max_bytes),
    )

    if start_sector in {
        FREESECT,
        ENDOFCHAIN,
        NOSTREAM,
    }:
        return b""

    max_sectors = (requested + MINI_SECTOR_SIZE - 1) // MINI_SECTOR_SIZE

    chain = _sector_chain(
        mini_fat,
        start_sector,
        max_sectors=max_sectors,
    )

    output = bytearray()

    for mini_sector_id in chain:
        offset = mini_sector_id * MINI_SECTOR_SIZE

        if offset < 0 or offset >= len(mini_stream):
            break

        chunk = mini_stream[offset : offset + MINI_SECTOR_SIZE]

        remaining = requested - len(output)

        if remaining <= 0:
            break

        output.extend(chunk[:remaining])

    return bytes(output)


# ---------------------------------------------------------------------------
# Directory paths
# ---------------------------------------------------------------------------


def _build_directory_paths(
    entries: Sequence[OLEDirectoryEntry],
) -> Dict[int, str]:
    """
    Build logical paths for directory entries.
    """

    entry_map = {entry.entry_id: entry for entry in entries}

    paths: Dict[int, str] = {}

    roots = [entry for entry in entries if entry.object_type == OBJ_ROOT]

    if not roots:
        return paths

    root = roots[0]

    paths[root.entry_id] = _normalize_name(root.name) or "Root Entry"

    # Parent IDs are generally sufficient. Add cycle protection.
    for entry in entries:
        if entry.entry_id == root.entry_id:
            continue

        current = entry
        components: List[str] = []

        visited: set[int] = set()

        while current.entry_id != root.entry_id:
            if current.entry_id in visited:
                break

            visited.add(current.entry_id)

            name = _normalize_name(current.name)

            if name:
                components.append(name)

            parent_id = current.parent_id

            if parent_id is None:
                break

            parent = entry_map.get(parent_id)

            if parent is None:
                break

            current = parent

        if current.entry_id == root.entry_id:
            root_name = paths[root.entry_id]

            components.reverse()

            if components:
                paths[entry.entry_id] = root_name + "/" + "/".join(components)
            else:
                paths[entry.entry_id] = root_name

    return paths


# ---------------------------------------------------------------------------
# Stream extraction
# ---------------------------------------------------------------------------


def _sample_stream(
    reader: _CFBReader,
    fat: Sequence[int],
    mini_fat: Sequence[int],
    mini_stream: bytes,
    entry: OLEDirectoryEntry,
    *,
    max_sample_bytes: int,
) -> bytes:
    """
    Read a bounded sample from a stream.
    """

    if entry.stream_size <= 0:
        return b""

    requested = min(
        entry.stream_size,
        max_sample_bytes,
    )

    if entry.stream_size < MINI_STREAM_CUTOFF:
        return _read_mini_chain(
            mini_stream,
            mini_fat,
            entry.start_sector,
            requested,
            max_bytes=requested,
        )

    return _read_chain(
        reader,
        fat,
        entry.start_sector,
        requested,
        max_bytes=requested,
    )


# ---------------------------------------------------------------------------
# Stream analysis
# ---------------------------------------------------------------------------


def _analyze_stream(
    entry: OLEDirectoryEntry,
    path: str,
    sample: bytes,
    *,
    calculate_hash: bool,
) -> OLEStreamRecord:
    """
    Build a stream-level static analysis record.
    """

    name = _normalize_name(entry.name)

    is_vba_related = _is_vba_related_name(
        name,
        path,
    )

    is_suspicious_name = _is_suspicious_stream_name(
        name,
        path,
    )

    contains_url = _contains_pattern(
        sample,
        URL_PATTERN,
    )

    contains_ipv4 = _contains_pattern(
        sample,
        IPV4_PATTERN,
    )

    contains_windows_path = _contains_pattern(
        sample,
        WINDOWS_PATH_PATTERN,
    )

    contains_base64_like = _contains_pattern(
        sample,
        BASE64_PATTERN,
    )

    contains_shell_indicator = _contains_pattern(
        sample,
        SHELL_PATTERN,
    )

    contains_macro_indicator = _looks_like_vba_content(sample)

    suspicious_content = _is_suspicious_content(sample)

    sha256 = None

    if calculate_hash:
        sha256 = hashlib.sha256(sample).hexdigest()

    entropy = None

    if sample:
        entropy = _shannon_entropy(sample)

    return OLEStreamRecord(
        stream_id=entry.entry_id,
        name=name,
        path=path,
        size=int(entry.stream_size),
        start_sector=entry.start_sector,
        is_mini_stream=(entry.stream_size < MINI_STREAM_CUTOFF),
        sha256=sha256,
        entropy=entropy,
        contains_url=contains_url,
        contains_ipv4=contains_ipv4,
        contains_windows_path=contains_windows_path,
        contains_base64_like=contains_base64_like,
        contains_shell_indicator=contains_shell_indicator,
        contains_macro_indicator=contains_macro_indicator,
        is_vba_related=is_vba_related,
        is_suspicious_name=is_suspicious_name,
        is_suspicious_content=suspicious_content,
    )


# ---------------------------------------------------------------------------
# Statistics
# ---------------------------------------------------------------------------


def calculate_statistics(
    directories: Sequence[OLEDirectoryEntry],
    streams: Sequence[OLEStreamRecord],
) -> OLEStatistics:
    """
    Calculate aggregate OLE statistics.
    """

    stats = OLEStatistics()

    stats.directory_entries = len(directories)

    for entry in directories:
        object_name = _object_type_name(entry.object_type)

        _increment(
            stats.object_type_counts,
            object_name,
        )

        if entry.object_type in {
            OBJ_STORAGE,
            OBJ_ROOT,
        }:
            stats.storage_count += 1

        if entry.clsid:
            stats.non_empty_clsid_count += 1

        if entry.object_type == OBJ_ROOT and entry.clsid:
            stats.root_clsid_count += 1

    for stream in streams:
        stats.stream_count += 1

        if stream.size > 0:
            stats.non_empty_stream_count += 1

        if stream.is_mini_stream:
            stats.mini_stream_count += 1
        else:
            stats.large_stream_count += 1

        stats.total_stream_bytes += stream.size

        stats.maximum_stream_size = max(
            stats.maximum_stream_size,
            stream.size,
        )

        _increment(
            stats.stream_name_counts,
            stream.name.lower(),
        )

        if stream.is_vba_related:
            stats.vba_stream_count += 1

        if stream.contains_macro_indicator:
            stats.macro_related_stream_count += 1

        if stream.is_suspicious_name:
            stats.suspicious_name_count += 1

        if stream.is_suspicious_content:
            stats.suspicious_content_count += 1

        if stream.contains_url:
            stats.url_stream_count += 1

        if stream.contains_ipv4:
            stats.ipv4_stream_count += 1

        if stream.contains_windows_path:
            stats.windows_path_stream_count += 1

        if stream.contains_base64_like:
            stats.base64_like_stream_count += 1

        if stream.contains_shell_indicator:
            stats.shell_indicator_stream_count += 1

        if stream.entropy is not None and stream.entropy >= 7.0:
            stats.high_entropy_stream_count += 1

    return stats


# ---------------------------------------------------------------------------
# Main analyzer
# ---------------------------------------------------------------------------


def analyze_ole(
    data: bytes,
    *,
    package_path: Optional[str] = None,
    max_streams: int = DEFAULT_MAX_STREAMS,
    max_stream_size: int = DEFAULT_MAX_STREAM_SIZE,
    max_total_stream_bytes: int = DEFAULT_MAX_TOTAL_STREAM_BYTES,
    max_directory_entries: int = DEFAULT_MAX_DIRECTORY_ENTRIES,
    max_sample_bytes: int = DEFAULT_MAX_SAMPLE_BYTES,
    calculate_hashes: bool = True,
) -> OLEAnalysis:
    """
    Perform bounded static analysis of an OLE/CFB container.

    Parameters
    ----------
    data:
        Complete OLE/CFB bytes.

    package_path:
        Optional source path for reporting.

    max_streams:
        Maximum number of streams to analyze.

    max_stream_size:
        Maximum bytes read from an individual stream.

    max_total_stream_bytes:
        Maximum cumulative bytes sampled across streams.

    max_directory_entries:
        Maximum directory entries parsed.

    max_sample_bytes:
        Maximum sample size used for stream content indicators.

    calculate_hashes:
        Whether to calculate SHA-256 for sampled stream data.

    Returns
    -------
    OLEAnalysis
        Structured static-analysis result.

    Important
    ---------
    A positive ``has_vba`` or ``suspicious`` result is an analytical
    indicator, not a malware verdict.
    """

    truncation_reasons: List[str] = []

    if not isinstance(
        data,
        (bytes, bytearray, memoryview),
    ):
        return OLEAnalysis(
            version=OLE_VERSION,
            is_ole=False,
            valid_header=False,
            parse_error=True,
            sector_size=0,
            mini_sector_size=MINI_SECTOR_SIZE,
            package_path=package_path,
            directories=[],
            streams=[],
            statistics=OLEStatistics(),
            suspicious=False,
            truncated=False,
            truncation_reasons=["input_is_not_bytes"],
        )

    raw = bytes(data)

    is_ole = len(raw) >= 8 and raw[:8] == OLE_MAGIC

    if not is_ole:
        return OLEAnalysis(
            version=OLE_VERSION,
            is_ole=False,
            valid_header=False,
            parse_error=False,
            sector_size=0,
            mini_sector_size=MINI_SECTOR_SIZE,
            package_path=package_path,
            directories=[],
            streams=[],
            statistics=OLEStatistics(),
            suspicious=False,
            truncated=False,
            truncation_reasons=[],
        )

    header = _parse_header(raw)

    if header is None:
        return OLEAnalysis(
            version=OLE_VERSION,
            is_ole=True,
            valid_header=False,
            parse_error=True,
            sector_size=0,
            mini_sector_size=MINI_SECTOR_SIZE,
            package_path=package_path,
            directories=[],
            streams=[],
            statistics=OLEStatistics(),
            suspicious=True,
            truncated=False,
            truncation_reasons=["invalid_cfb_header"],
        )

    reader = _CFBReader(
        raw,
        header,
    )

    if reader.sector_count <= 0:
        return OLEAnalysis(
            version=OLE_VERSION,
            is_ole=True,
            valid_header=True,
            parse_error=True,
            sector_size=reader.sector_size,
            mini_sector_size=MINI_SECTOR_SIZE,
            package_path=package_path,
            directories=[],
            streams=[],
            statistics=OLEStatistics(),
            suspicious=True,
            truncated=False,
            truncation_reasons=["no_sectors_available"],
        )

    fat = _read_fat(
        reader,
        header,
    )

    if not fat:
        return OLEAnalysis(
            version=OLE_VERSION,
            is_ole=True,
            valid_header=True,
            parse_error=True,
            sector_size=reader.sector_size,
            mini_sector_size=MINI_SECTOR_SIZE,
            package_path=package_path,
            directories=[],
            streams=[],
            statistics=OLEStatistics(),
            suspicious=True,
            truncated=False,
            truncation_reasons=["fat_unavailable"],
        )

    directories, directory_truncated = _read_directory(
        reader,
        fat,
        header,
        max_directory_entries=max_directory_entries,
    )

    if directory_truncated:
        truncation_reasons.append("maximum_directory_entries_reached")

    if not directories:
        return OLEAnalysis(
            version=OLE_VERSION,
            is_ole=True,
            valid_header=True,
            parse_error=True,
            sector_size=reader.sector_size,
            mini_sector_size=MINI_SECTOR_SIZE,
            package_path=package_path,
            directories=[],
            streams=[],
            statistics=OLEStatistics(),
            suspicious=True,
            truncated=bool(truncation_reasons),
            truncation_reasons=truncation_reasons,
        )

    paths = _build_directory_paths(directories)

    mini_fat = _read_mini_fat(
        reader,
        fat,
        header,
    )

    root_entries = [entry for entry in directories if entry.object_type == OBJ_ROOT]

    mini_stream = b""

    if root_entries:
        root = root_entries[0]

        if root.stream_size > 0:
            mini_stream = _read_chain(
                reader,
                fat,
                root.start_sector,
                root.stream_size,
                max_bytes=min(
                    root.stream_size,
                    DEFAULT_MAX_TOTAL_STREAM_BYTES,
                ),
            )

    streams: List[OLEStreamRecord] = []

    total_sampled = 0

    stream_entries = [entry for entry in directories if entry.object_type == OBJ_STREAM]

    if len(stream_entries) > max_streams:
        stream_entries = stream_entries[:max_streams]

        truncation_reasons.append("maximum_streams_reached")

    for entry in stream_entries:
        if entry.stream_size < 0:
            continue

        remaining_total = max_total_stream_bytes - total_sampled

        if remaining_total <= 0:
            truncation_reasons.append("maximum_total_stream_bytes_reached")
            break

        stream_limit = min(
            max_stream_size,
            max_sample_bytes,
            remaining_total,
        )

        sample = _sample_stream(
            reader,
            fat,
            mini_fat,
            mini_stream,
            entry,
            max_sample_bytes=stream_limit,
        )

        total_sampled += len(sample)

        path = paths.get(
            entry.entry_id,
            _normalize_name(entry.name),
        )

        stream_record = _analyze_stream(
            entry,
            path,
            sample,
            calculate_hash=calculate_hashes,
        )

        streams.append(stream_record)

    statistics = calculate_statistics(
        directories,
        streams,
    )

    root_clsid = None

    if root_entries:
        root_clsid = root_entries[0].clsid or None

    has_vba = (
        statistics.vba_stream_count > 0 or statistics.macro_related_stream_count > 0
    )

    has_macros = has_vba or any(stream.contains_macro_indicator for stream in streams)

    has_embedded_objects = any(
        (
            "ole" in stream.name.lower()
            or "object" in stream.name.lower()
            or "package" in stream.name.lower()
            or "embedding" in stream.path.lower()
        )
        for stream in streams
    )

    suspicious = (
        has_vba
        or statistics.suspicious_name_count > 0
        or statistics.suspicious_content_count > 0
        or statistics.url_stream_count > 0
        or statistics.shell_indicator_stream_count > 0
    )

    return OLEAnalysis(
        version=OLE_VERSION,
        is_ole=True,
        valid_header=True,
        parse_error=False,
        sector_size=reader.sector_size,
        mini_sector_size=MINI_SECTOR_SIZE,
        package_path=package_path,
        directories=directories,
        streams=streams,
        statistics=statistics,
        root_clsid=root_clsid,
        has_vba=has_vba,
        has_macros=has_macros,
        has_embedded_objects=has_embedded_objects,
        suspicious=suspicious,
        truncated=bool(truncation_reasons),
        truncation_reasons=sorted(set(truncation_reasons)),
    )


def analyze_ole_file(
    file_path: str | Path,
    *,
    max_streams: int = DEFAULT_MAX_STREAMS,
    max_stream_size: int = DEFAULT_MAX_STREAM_SIZE,
    max_total_stream_bytes: int = DEFAULT_MAX_TOTAL_STREAM_BYTES,
    max_directory_entries: int = DEFAULT_MAX_DIRECTORY_ENTRIES,
    max_sample_bytes: int = DEFAULT_MAX_SAMPLE_BYTES,
    calculate_hashes: bool = True,
) -> OLEAnalysis:
    """
    Analyze an OLE file from disk.
    """

    path = Path(file_path)

    try:
        data = path.read_bytes()
    except (OSError, IOError):
        return OLEAnalysis(
            version=OLE_VERSION,
            is_ole=False,
            valid_header=False,
            parse_error=True,
            sector_size=0,
            mini_sector_size=MINI_SECTOR_SIZE,
            package_path=str(path),
            directories=[],
            streams=[],
            statistics=OLEStatistics(),
            suspicious=False,
            truncated=False,
            truncation_reasons=["file_read_error"],
        )

    return analyze_ole(
        data,
        package_path=str(path),
        max_streams=max_streams,
        max_stream_size=max_stream_size,
        max_total_stream_bytes=max_total_stream_bytes,
        max_directory_entries=max_directory_entries,
        max_sample_bytes=max_sample_bytes,
        calculate_hashes=calculate_hashes,
    )


# ---------------------------------------------------------------------------
# Stream payload iterator
# ---------------------------------------------------------------------------


def iter_ole_streams(
    data: bytes,
    *,
    max_streams: int = DEFAULT_MAX_STREAMS,
    max_stream_size: int = DEFAULT_MAX_STREAM_SIZE,
    max_total_stream_bytes: int = DEFAULT_MAX_TOTAL_STREAM_BYTES,
) -> Iterator[Tuple[OLEStreamRecord, bytes]]:
    """
    Yield analyzed stream records together with bounded in-memory samples.

    This is useful when downstream code such as VBA analysis needs the
    actual stream bytes.

    Nothing is written to disk and no OLE content is executed.
    """

    if not isinstance(
        data,
        (bytes, bytearray, memoryview),
    ):
        return

    raw = bytes(data)

    header = _parse_header(raw)

    if header is None:
        return

    reader = _CFBReader(
        raw,
        header,
    )

    fat = _read_fat(
        reader,
        header,
    )

    if not fat:
        return

    directories, _ = _read_directory(
        reader,
        fat,
        header,
        max_directory_entries=DEFAULT_MAX_DIRECTORY_ENTRIES,
    )

    paths = _build_directory_paths(directories)

    mini_fat = _read_mini_fat(
        reader,
        fat,
        header,
    )

    root_entries = [entry for entry in directories if entry.object_type == OBJ_ROOT]

    mini_stream = b""

    if root_entries:
        root = root_entries[0]

        if root.stream_size > 0:
            mini_stream = _read_chain(
                reader,
                fat,
                root.start_sector,
                root.stream_size,
                max_bytes=min(
                    root.stream_size,
                    max_total_stream_bytes,
                ),
            )

    entries = [entry for entry in directories if entry.object_type == OBJ_STREAM][
        :max_streams
    ]

    total_read = 0

    for entry in entries:
        if total_read >= max_total_stream_bytes:
            return

        remaining = max_total_stream_bytes - total_read

        limit = min(
            max_stream_size,
            remaining,
        )

        sample = _sample_stream(
            reader,
            fat,
            mini_fat,
            mini_stream,
            entry,
            max_sample_bytes=limit,
        )

        total_read += len(sample)

        path = paths.get(
            entry.entry_id,
            _normalize_name(entry.name),
        )

        record = _analyze_stream(
            entry,
            path,
            sample,
            calculate_hash=True,
        )

        yield record, sample


# ---------------------------------------------------------------------------
# VBA-oriented helpers
# ---------------------------------------------------------------------------


def find_vba_streams(
    analysis: OLEAnalysis,
) -> List[OLEStreamRecord]:
    """
    Return streams likely to participate in a VBA project.
    """

    return [
        stream
        for stream in analysis.streams
        if stream.is_vba_related or stream.contains_macro_indicator
    ]


def find_suspicious_streams(
    analysis: OLEAnalysis,
) -> List[OLEStreamRecord]:
    """
    Return streams containing static indicators requiring additional
    investigation.
    """

    return [
        stream
        for stream in analysis.streams
        if (
            stream.is_suspicious_name
            or stream.is_suspicious_content
            or stream.contains_url
            or stream.contains_shell_indicator
        )
    ]


# ---------------------------------------------------------------------------
# ML feature extraction
# ---------------------------------------------------------------------------


def ole_features(
    analysis: OLEAnalysis,
) -> Dict[str, object]:
    """
    Convert an OLE analysis result into ML-ready scalar features.

    Raw stream names, paths, hashes, and CLSIDs are deliberately excluded
    from this feature dictionary.
    """

    stats = analysis.statistics

    stream_count = stats.stream_count

    vba_ratio = stats.vba_stream_count / stream_count if stream_count else 0.0

    suspicious_ratio = (
        (stats.suspicious_name_count + stats.suspicious_content_count) / stream_count
        if stream_count
        else 0.0
    )

    high_entropy_ratio = (
        stats.high_entropy_stream_count / stream_count if stream_count else 0.0
    )

    return {
        "ole_version": OLE_VERSION,
        "ole_is_container": int(analysis.is_ole),
        "ole_valid_header": int(analysis.valid_header),
        "ole_parse_error": int(analysis.parse_error),
        "ole_sector_size": analysis.sector_size,
        "ole_directory_entry_count": (stats.directory_entries),
        "ole_storage_count": stats.storage_count,
        "ole_stream_count": stats.stream_count,
        "ole_non_empty_stream_count": (stats.non_empty_stream_count),
        "ole_mini_stream_count": (stats.mini_stream_count),
        "ole_large_stream_count": (stats.large_stream_count),
        "ole_total_stream_bytes": (stats.total_stream_bytes),
        "ole_max_stream_size": (stats.maximum_stream_size),
        "ole_vba_stream_count": (stats.vba_stream_count),
        "ole_macro_related_stream_count": (stats.macro_related_stream_count),
        "ole_suspicious_name_count": (stats.suspicious_name_count),
        "ole_suspicious_content_count": (stats.suspicious_content_count),
        "ole_url_stream_count": (stats.url_stream_count),
        "ole_ipv4_stream_count": (stats.ipv4_stream_count),
        "ole_windows_path_stream_count": (stats.windows_path_stream_count),
        "ole_base64_like_stream_count": (stats.base64_like_stream_count),
        "ole_shell_indicator_stream_count": (stats.shell_indicator_stream_count),
        "ole_high_entropy_stream_count": (stats.high_entropy_stream_count),
        "ole_non_empty_clsid_count": (stats.non_empty_clsid_count),
        "ole_has_vba": int(analysis.has_vba),
        "ole_has_macros": int(analysis.has_macros),
        "ole_has_embedded_objects": int(analysis.has_embedded_objects),
        "ole_suspicious": int(analysis.suspicious),
        "ole_vba_stream_ratio": vba_ratio,
        "ole_suspicious_stream_ratio": suspicious_ratio,
        "ole_high_entropy_stream_ratio": (high_entropy_ratio),
        "ole_truncated": int(analysis.truncated),
        "ole_parse_truncation_count": len(analysis.truncation_reasons),
    }


def extract_ole_features(
    data: bytes,
    *,
    max_streams: int = DEFAULT_MAX_STREAMS,
    max_stream_size: int = DEFAULT_MAX_STREAM_SIZE,
    max_total_stream_bytes: int = DEFAULT_MAX_TOTAL_STREAM_BYTES,
    max_directory_entries: int = DEFAULT_MAX_DIRECTORY_ENTRIES,
    max_sample_bytes: int = DEFAULT_MAX_SAMPLE_BYTES,
) -> Dict[str, object]:
    """
    Convenience function returning only ML-oriented OLE features.
    """

    analysis = analyze_ole(
        data,
        max_streams=max_streams,
        max_stream_size=max_stream_size,
        max_total_stream_bytes=max_total_stream_bytes,
        max_directory_entries=max_directory_entries,
        max_sample_bytes=max_sample_bytes,
    )

    return ole_features(analysis)


# ---------------------------------------------------------------------------
# Serialization
# ---------------------------------------------------------------------------


def analysis_to_dict(
    analysis: OLEAnalysis,
) -> Dict[str, object]:
    """
    Return a JSON-serializable analysis dictionary.
    """

    return analysis.to_dict()


# ---------------------------------------------------------------------------
# Compatibility aliases
# ---------------------------------------------------------------------------


def analyze_ole_container(
    data: bytes,
    **kwargs: object,
) -> OLEAnalysis:
    """
    Alias for callers that use "container" terminology.
    """

    return analyze_ole(
        data,
        **kwargs,
    )


def extract_ole_stream_features(
    data: bytes,
    **kwargs: object,
) -> Dict[str, object]:
    """
    Alias for the ML feature API.
    """

    return extract_ole_features(
        data,
        **kwargs,
    )


__all__ = [
    "OLE_VERSION",
    "OLE_MAGIC",
    "OLEStreamRecord",
    "OLEDirectoryEntry",
    "OLEStatistics",
    "OLEAnalysis",
    "analyze_ole",
    "analyze_ole_file",
    "analyze_ole_container",
    "iter_ole_streams",
    "find_vba_streams",
    "find_suspicious_streams",
    "calculate_statistics",
    "ole_features",
    "extract_ole_features",
    "extract_ole_stream_features",
    "analysis_to_dict",
]
