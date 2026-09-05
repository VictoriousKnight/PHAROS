"""
pharos-cdr/src/ingestion/safety.py

Static ingestion safety controls for the Pharos CDR pipeline.

This module provides a defensive safety gate around untrusted files and
in-memory content before deeper parsing, feature extraction, ML inference,
or CDR processing.

Security properties
-------------------
- Never executes submitted files.
- Never invokes subprocesses or external programs.
- Never loads DLLs/shared libraries.
- Never imports or executes submitted scripts/macros.
- Never extracts archives to the host filesystem.
- Never follows URLs or performs network requests.
- Never modifies the submitted file.
- Uses bounded reads and recursion limits.
- Detects path, size, type, symlink, and resource-risk conditions.
- Produces deterministic structured findings.
- Supports both filesystem paths and in-memory bytes.

Important
---------
A "safe" result means that the input passed this ingestion safety gate. It
does NOT mean that the file is benign. Malware detection is performed by the
later extraction, ML, behavior, decision, and CDR layers.
"""

from __future__ import annotations

import hashlib
import math
import os
import stat
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterator, List, Mapping, Optional, Sequence, Tuple

# ============================================================================
# Resource limits
# ============================================================================

DEFAULT_MAX_FILE_SIZE = 25 * 1024 * 1024
DEFAULT_MAX_SAMPLE_SIZE = 64 * 1024
DEFAULT_MAX_PATH_LENGTH = 4096
DEFAULT_MAX_FILENAME_LENGTH = 255
DEFAULT_MAX_FINDINGS = 256
DEFAULT_MAX_ARCHIVE_DEPTH = 8

# Defensive limits for pathological input names / byte content.
MAX_TEXT_SCAN = 100_000
MAX_ENTROPY_SAMPLE = 64 * 1024

# Common platform-independent dangerous path components.
WINDOWS_DEVICE_NAMES = {
    "con",
    "prn",
    "aux",
    "nul",
    "clock$",
    "com1",
    "com2",
    "com3",
    "com4",
    "com5",
    "com6",
    "com7",
    "com8",
    "com9",
    "lpt1",
    "lpt2",
    "lpt3",
    "lpt4",
    "lpt5",
    "lpt6",
    "lpt7",
    "lpt8",
    "lpt9",
}

EXECUTABLE_EXTENSIONS = {
    ".exe",
    ".dll",
    ".sys",
    ".scr",
    ".com",
    ".cpl",
    ".ocx",
    ".drv",
    ".efi",
    ".bin",
    ".elf",
    ".so",
    ".dylib",
    ".app",
}

SCRIPT_EXTENSIONS = {
    ".bat",
    ".cmd",
    ".com",
    ".ps1",
    ".psm1",
    ".psd1",
    ".vbs",
    ".vbe",
    ".js",
    ".jse",
    ".wsf",
    ".wsh",
    ".hta",
    ".sh",
    ".bash",
    ".zsh",
    ".fish",
    ".py",
    ".pl",
    ".rb",
    ".php",
}

MACRO_CAPABLE_EXTENSIONS = {
    ".docm",
    ".dotm",
    ".xlsm",
    ".xltm",
    ".xlam",
    ".pptm",
    ".potm",
    ".ppsm",
    ".ppam",
    ".vsdm",
    ".vsdx",
    ".xll",
    ".doc",
    ".xls",
    ".ppt",
}

ARCHIVE_EXTENSIONS = {
    ".zip",
    ".7z",
    ".rar",
    ".gz",
    ".gzip",
    ".bz2",
    ".xz",
    ".tar",
    ".tgz",
    ".tbz",
    ".txz",
    ".cab",
    ".iso",
}

DOCUMENT_EXTENSIONS = {
    ".pdf",
    ".rtf",
    ".doc",
    ".docx",
    ".docm",
    ".dot",
    ".dotx",
    ".dotm",
    ".xls",
    ".xlsx",
    ".xlsm",
    ".xlt",
    ".xltx",
    ".xltm",
    ".ppt",
    ".pptx",
    ".pptm",
    ".odt",
    ".ods",
    ".odp",
}

# Byte signatures used only for static classification.
MAGIC_SIGNATURES: Tuple[Tuple[str, bytes], ...] = (
    ("pdf", b"%PDF-"),
    ("ole", bytes.fromhex("D0CF11E0A1B11AE1")),
    ("zip", b"PK\x03\x04"),
    ("zip_empty", b"PK\x05\x06"),
    ("zip_spanned", b"PK\x07\x08"),
    ("gzip", b"\x1f\x8b"),
    ("bzip2", b"BZh"),
    ("xz", b"\xfd7zXZ\x00"),
    ("7zip", b"7z\xbc\xaf'\x1c"),
    ("rar4", b"Rar!\x1a\x07\x00"),
    ("rar5", b"Rar!\x1a\x07\x01\x00"),
    ("pe", b"MZ"),
    ("elf", b"\x7fELF"),
    ("mach_o_32", b"\xfe\xed\xfa\xce"),
    ("mach_o_64", b"\xfe\xed\xfa\xcf"),
    ("mach_o_32_reverse", b"\xce\xfa\xed\xfe"),
    ("mach_o_64_reverse", b"\xcf\xfa\xed\xfe"),
    ("wasm", b"\x00asm"),
    ("rtf", b"{\\rtf"),
    ("sqlite", b"SQLite format 3\x00"),
)


# ============================================================================
# Severity
# ============================================================================

SEVERITY_ORDER = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


# ============================================================================
# Data structures
# ============================================================================


@dataclass(frozen=True)
class SafetyFinding:
    """
    One ingestion safety finding.

    A finding describes an input property or ingestion concern. It is not
    itself a malware verdict.
    """

    code: str
    message: str
    severity: str = "info"
    category: str = "safety"
    evidence: Optional[str] = None
    blocking: bool = False
    recoverable: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class SafetyHashes:
    """Cryptographic identifiers calculated over the inspected content."""

    md5: str = ""
    sha1: str = ""
    sha256: str = ""
    size_hashed: int = 0
    complete: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class SafetyStatistics:
    """Bounded static content statistics."""

    size: int = 0
    sample_size: int = 0

    entropy: float = 0.0
    printable_ratio: float = 0.0
    ascii_ratio: float = 0.0
    zero_ratio: float = 0.0

    has_null_bytes: bool = False
    starts_with_mz: bool = False
    starts_with_ole: bool = False
    starts_with_zip: bool = False
    starts_with_pdf: bool = False
    starts_with_rtf: bool = False
    starts_with_elf: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class SafetyResult:
    """
    Complete result of the ingestion safety gate.

    ``safe`` means the file passed the safety gate.

    ``allowed_for_analysis`` indicates whether downstream static analysis may
    proceed under the selected policy.

    Neither field means "malware-free".
    """

    safe: bool
    allowed_for_analysis: bool

    source_kind: str = ""
    path: Optional[str] = None
    filename: str = ""
    extension: str = ""

    size: int = 0

    hashes: SafetyHashes = field(default_factory=SafetyHashes)
    statistics: SafetyStatistics = field(default_factory=SafetyStatistics)

    findings: List[SafetyFinding] = field(default_factory=list)

    blocking_findings: int = 0
    warning_findings: int = 0

    detected_signatures: List[str] = field(default_factory=list)
    risk_flags: List[str] = field(default_factory=list)

    feature_vector: Dict[str, float] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self._refresh()
        self.feature_vector = build_feature_vector(self)

    def _refresh(self) -> None:
        self.blocking_findings = sum(1 for finding in self.findings if finding.blocking)

        self.warning_findings = sum(
            1
            for finding in self.findings
            if SEVERITY_ORDER.get(finding.severity, 0) >= 2
        )

    @property
    def highest_severity(self) -> str:
        if not self.findings:
            return "info"

        finding = max(
            self.findings,
            key=lambda item: SEVERITY_ORDER.get(item.severity, 0),
        )
        return finding.severity

    @property
    def requires_review(self) -> bool:
        return self.warning_findings > 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "safe": self.safe,
            "allowed_for_analysis": self.allowed_for_analysis,
            "source_kind": self.source_kind,
            "path": self.path,
            "filename": self.filename,
            "extension": self.extension,
            "size": self.size,
            "hashes": self.hashes.to_dict(),
            "statistics": self.statistics.to_dict(),
            "findings": [finding.to_dict() for finding in self.findings],
            "blocking_findings": self.blocking_findings,
            "warning_findings": self.warning_findings,
            "highest_severity": self.highest_severity,
            "requires_review": self.requires_review,
            "detected_signatures": list(self.detected_signatures),
            "risk_flags": list(self.risk_flags),
            "feature_vector": dict(self.feature_vector),
        }


# ============================================================================
# Generic helpers
# ============================================================================


def _safe_text(value: Any, limit: int = MAX_TEXT_SCAN) -> str:
    if value is None:
        return ""

    try:
        text = str(value)
    except Exception:
        return ""

    if len(text) > limit:
        return text[:limit] + "..."

    return text


def _normalize_extension(extension: str) -> str:
    value = _safe_text(extension, 64).strip().lower()

    if not value:
        return ""

    if not value.startswith("."):
        value = "." + value

    return value


def _path_string(value: Any) -> Optional[str]:
    if value is None:
        return None

    try:
        return os.fspath(value)
    except TypeError:
        return _safe_text(value, DEFAULT_MAX_PATH_LENGTH)


def _filename(path: Optional[str]) -> str:
    if not path:
        return ""

    try:
        return Path(path).name
    except Exception:
        return os.path.basename(path)


def _extension(path_or_name: Optional[str]) -> str:
    if not path_or_name:
        return ""

    try:
        return _normalize_extension(Path(path_or_name).suffix)
    except Exception:
        return ""


def _feature_name(value: Any) -> str:
    text = _safe_text(value, 128).strip().lower()

    if not text:
        return ""

    chars: List[str] = []

    for char in text:
        if char.isalnum():
            chars.append(char)
        elif char in {"_", "-", ".", " "}:
            chars.append("_")

    result = "".join(chars)

    while "__" in result:
        result = result.replace("__", "_")

    return result.strip("_")


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0

    counts = [0] * 256

    for value in data:
        counts[value] += 1

    length = len(data)
    result = 0.0

    for count in counts:
        if count:
            probability = count / length
            result -= probability * math.log2(probability)

    return round(result, 6)


def _printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0

    count = sum(1 for value in data if value in (9, 10, 13) or 32 <= value <= 126)

    return round(count / len(data), 6)


def _ascii_ratio(data: bytes) -> float:
    if not data:
        return 0.0

    return round(sum(value < 128 for value in data) / len(data), 6)


def _zero_ratio(data: bytes) -> float:
    if not data:
        return 0.0

    return round(data.count(b"\x00") / len(data), 6)


# ============================================================================
# Hashing
# ============================================================================


def _hash_bytes(data: bytes) -> SafetyHashes:
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()

    md5.update(data)
    sha1.update(data)
    sha256.update(data)

    return SafetyHashes(
        md5=md5.hexdigest(),
        sha1=sha1.hexdigest(),
        sha256=sha256.hexdigest(),
        size_hashed=len(data),
        complete=True,
    )


def _hash_file(
    path: str,
    maximum: int,
) -> SafetyHashes:
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()

    total = 0
    complete = True

    try:
        with open(path, "rb") as handle:
            while total < maximum:
                wanted = min(1024 * 1024, maximum - total)
                chunk = handle.read(wanted)

                if not chunk:
                    break

                md5.update(chunk)
                sha1.update(chunk)
                sha256.update(chunk)
                total += len(chunk)

                if len(chunk) < wanted:
                    break
            else:
                # Exactly hit the configured boundary. Check whether bytes
                # remain without consuming them into memory.
                extra = handle.read(1)
                if extra:
                    complete = False

    except (OSError, ValueError):
        return SafetyHashes(
            size_hashed=total,
            complete=False,
        )

    return SafetyHashes(
        md5=md5.hexdigest(),
        sha1=sha1.hexdigest(),
        sha256=sha256.hexdigest(),
        size_hashed=total,
        complete=complete,
    )


# ============================================================================
# Reading
# ============================================================================


def _read_sample(
    path: str,
    maximum: int,
) -> Tuple[bytes, bool]:
    """
    Read at most ``maximum`` bytes.

    Returns:
        sample, reached_eof
    """

    maximum = max(0, int(maximum))

    if maximum == 0:
        return b"", True

    chunks: List[bytes] = []
    total = 0

    try:
        with open(path, "rb") as handle:
            while total < maximum:
                wanted = min(64 * 1024, maximum - total)
                chunk = handle.read(wanted)

                if not chunk:
                    return b"".join(chunks), True

                chunks.append(chunk)
                total += len(chunk)

                if len(chunk) < wanted:
                    return b"".join(chunks), True

    except (OSError, ValueError):
        return b"".join(chunks), False

    return b"".join(chunks), False


# ============================================================================
# Finding helpers
# ============================================================================


def _add_finding(
    findings: List[SafetyFinding],
    *,
    code: str,
    message: str,
    severity: str = "info",
    category: str = "safety",
    evidence: Optional[str] = None,
    blocking: bool = False,
    recoverable: bool = True,
) -> None:
    if len(findings) >= DEFAULT_MAX_FINDINGS:
        return

    normalized = _safe_text(severity, 32).lower()

    if normalized not in SEVERITY_ORDER:
        normalized = "info"

    findings.append(
        SafetyFinding(
            code=_safe_text(code, 128),
            message=_safe_text(message, 2048),
            severity=normalized,
            category=_safe_text(category, 128) or "safety",
            evidence=_safe_text(evidence, 4096) or None,
            blocking=bool(blocking),
            recoverable=bool(recoverable),
        )
    )


# ============================================================================
# Path safety
# ============================================================================


def _check_path_safety(
    path: str,
    findings: List[SafetyFinding],
    *,
    max_path_length: int,
) -> None:
    if len(path) > max_path_length:
        _add_finding(
            findings,
            code="path_too_long",
            message="The input path exceeds the configured path-length limit.",
            severity="high",
            category="path_safety",
            blocking=True,
            recoverable=False,
        )

    filename = _filename(path)

    if len(filename) > DEFAULT_MAX_FILENAME_LENGTH:
        _add_finding(
            findings,
            code="filename_too_long",
            message="The filename exceeds the conventional filesystem filename limit.",
            severity="medium",
            category="path_safety",
        )

    if "\x00" in path:
        _add_finding(
            findings,
            code="nul_in_path",
            message="The supplied path contains a NUL character.",
            severity="critical",
            category="path_safety",
            blocking=True,
            recoverable=False,
        )

    # Control characters can cause ambiguity in logs, filenames, or path
    # processing. They are reported rather than automatically rejected.
    controls = [
        char for char in path if ord(char) < 32 and char not in {"\t", "\n", "\r"}
    ]

    if controls:
        _add_finding(
            findings,
            code="control_character_in_path",
            message="The path contains control characters.",
            severity="medium",
            category="path_safety",
        )

    # Windows device names are dangerous in cross-platform ingestion because
    # they can refer to devices rather than ordinary files.
    stem = Path(filename).stem.lower()

    if stem in WINDOWS_DEVICE_NAMES:
        _add_finding(
            findings,
            code="windows_device_name",
            message="The filename matches a reserved Windows device name.",
            severity="high",
            category="path_safety",
            blocking=True,
            recoverable=False,
        )

    # Reject obvious path traversal components when a path is intended to
    # represent an uploaded filename or relative path.
    components = path.replace("\\", "/").split("/")

    if any(component == ".." for component in components):
        _add_finding(
            findings,
            code="path_traversal_component",
            message="The supplied path contains a parent-directory traversal component.",
            severity="high",
            category="path_safety",
        )


def _check_filename_safety(
    filename: str,
    findings: List[SafetyFinding],
) -> None:
    if not filename:
        return

    if "\x00" in filename:
        _add_finding(
            findings,
            code="nul_in_filename",
            message="The filename contains a NUL character.",
            severity="critical",
            category="path_safety",
            blocking=True,
            recoverable=False,
        )

    if filename in {".", ".."}:
        _add_finding(
            findings,
            code="invalid_filename",
            message="The supplied filename is a directory traversal marker.",
            severity="high",
            category="path_safety",
            blocking=True,
            recoverable=False,
        )

    if filename.rstrip(" .") != filename:
        _add_finding(
            findings,
            code="trailing_dot_or_space",
            message="The filename contains trailing dots or spaces.",
            severity="low",
            category="path_safety",
        )


# ============================================================================
# File-system safety
# ============================================================================


def _check_filesystem_object(
    path: str,
    findings: List[SafetyFinding],
    *,
    require_regular_file: bool,
    reject_symlinks: bool,
) -> Optional[os.stat_result]:
    try:
        link_metadata = os.lstat(path)
    except (OSError, ValueError):
        _add_finding(
            findings,
            code="lstat_failed",
            message="The filesystem object could not be inspected.",
            severity="high",
            category="filesystem",
            blocking=True,
            recoverable=False,
        )
        return None

    if stat.S_ISLNK(link_metadata.st_mode):
        if reject_symlinks:
            _add_finding(
                findings,
                code="symbolic_link",
                message="Symbolic links are not accepted by the ingestion safety policy.",
                severity="high",
                category="filesystem",
                blocking=True,
                recoverable=False,
            )
        else:
            _add_finding(
                findings,
                code="symbolic_link",
                message="The input is a symbolic link.",
                severity="medium",
                category="filesystem",
            )

    if require_regular_file and not stat.S_ISREG(link_metadata.st_mode):
        _add_finding(
            findings,
            code="not_regular_file",
            message="The input is not a regular filesystem file.",
            severity="high",
            category="filesystem",
            blocking=True,
            recoverable=False,
        )
        return link_metadata

    try:
        metadata = os.stat(path, follow_symlinks=False)
    except (OSError, ValueError):
        _add_finding(
            findings,
            code="stat_failed",
            message="The file metadata could not be read.",
            severity="high",
            category="filesystem",
            blocking=True,
            recoverable=False,
        )
        return link_metadata

    return metadata


def _check_permissions(
    metadata: os.stat_result,
    findings: List[SafetyFinding],
) -> None:
    mode = metadata.st_mode

    if not stat.S_ISREG(mode):
        return

    # World-writable files deserve a review signal because their content may
    # have been altered by another principal. This does not indicate malware.
    if mode & stat.S_IWOTH:
        _add_finding(
            findings,
            code="world_writable",
            message="The file is world-writable.",
            severity="low",
            category="filesystem",
        )

    if mode & stat.S_ISUID:
        _add_finding(
            findings,
            code="setuid_file",
            message="The file has the setuid permission bit.",
            severity="medium",
            category="filesystem",
        )

    if mode & stat.S_ISGID:
        _add_finding(
            findings,
            code="setgid_file",
            message="The file has the setgid permission bit.",
            severity="low",
            category="filesystem",
        )


# ============================================================================
# Content signatures
# ============================================================================


def detect_signatures(data: bytes) -> List[str]:
    """
    Return known static magic signatures present at the beginning of content.

    No parser or decompressor is invoked.
    """

    if not data:
        return []

    signatures: List[str] = []

    for name, magic in MAGIC_SIGNATURES:
        if data.startswith(magic):
            signatures.append(name)

    # OOXML/ZIP files share the ZIP signature. These markers are only checked
    # in the bounded sample and are not extracted.
    lowered = data[:MAX_TEXT_SCAN].lower()

    if b"[content_types].xml" in lowered:
        signatures.append("ooxml")

    if b"word/" in lowered:
        signatures.append("ooxml_word")

    if b"xl/" in lowered:
        signatures.append("ooxml_excel")

    if b"ppt/" in lowered:
        signatures.append("ooxml_powerpoint")

    return sorted(set(signatures))


def _check_signature_risks(
    signatures: Sequence[str],
    extension: str,
    findings: List[SafetyFinding],
    risk_flags: List[str],
) -> None:
    signature_set = set(signatures)

    if "pe" in signature_set:
        risk_flags.append("executable_content")

        _add_finding(
            findings,
            code="executable_signature",
            message="The content begins with a Windows executable signature.",
            severity="medium",
            category="content_type",
        )

    if "elf" in signature_set:
        risk_flags.append("elf_content")

        _add_finding(
            findings,
            code="elf_signature",
            message="The content begins with an ELF executable signature.",
            severity="medium",
            category="content_type",
        )

    if any(item.startswith("mach_o") for item in signature_set):
        risk_flags.append("macho_content")

        _add_finding(
            findings,
            code="macho_signature",
            message="The content begins with a Mach-O executable signature.",
            severity="medium",
            category="content_type",
        )

    if "ole" in signature_set:
        risk_flags.append("ole_container")

        if extension in MACRO_CAPABLE_EXTENSIONS:
            _add_finding(
                findings,
                code="ole_macro_capable",
                message="The content is an OLE container associated with macro-capable document formats.",
                severity="medium",
                category="content_type",
            )

    if "ooxml" in signature_set:
        risk_flags.append("ooxml_container")

    if "zip" in signature_set or "ooxml" in signature_set:
        risk_flags.append("container_content")

    if any(
        item in signature_set
        for item in {
            "gzip",
            "bzip2",
            "xz",
            "7zip",
            "rar4",
            "rar5",
        }
    ):
        risk_flags.append("compressed_or_archived_content")

        _add_finding(
            findings,
            code="compressed_container",
            message="The content begins with a known compressed/archive container signature.",
            severity="low",
            category="content_type",
        )


# ============================================================================
# Content statistics
# ============================================================================


def _statistics(
    data: bytes,
    size: int,
) -> SafetyStatistics:
    sample = data[:MAX_ENTROPY_SAMPLE]

    return SafetyStatistics(
        size=max(0, int(size)),
        sample_size=len(sample),
        entropy=_entropy(sample),
        printable_ratio=_printable_ratio(sample),
        ascii_ratio=_ascii_ratio(sample),
        zero_ratio=_zero_ratio(sample),
        has_null_bytes=b"\x00" in sample,
        starts_with_mz=sample.startswith(b"MZ"),
        starts_with_ole=sample.startswith(bytes.fromhex("D0CF11E0A1B11AE1")),
        starts_with_zip=sample.startswith(b"PK"),
        starts_with_pdf=sample.startswith(b"%PDF-"),
        starts_with_rtf=sample.startswith(b"{\\rtf"),
        starts_with_elf=sample.startswith(b"\x7fELF"),
    )


def _check_content_characteristics(
    stats: SafetyStatistics,
    family: Optional[str],
    findings: List[SafetyFinding],
    risk_flags: List[str],
) -> None:
    if stats.sample_size >= 4096 and stats.entropy >= 7.8:
        risk_flags.append("high_entropy_content")

        normalized_family = (family or "").lower()

        if normalized_family in {
            "archive",
            "executable",
            "image",
            "audio",
            "video",
            "binary",
        }:
            severity = "info"
        else:
            severity = "low"

        _add_finding(
            findings,
            code="high_entropy_content",
            message="The bounded sample has unusually high byte entropy.",
            severity=severity,
            category="content_characteristics",
            evidence=f"entropy={stats.entropy:.4f}",
        )

    if (
        stats.sample_size >= 4096
        and stats.printable_ratio > 0.995
        and stats.zero_ratio > 0.0
    ):
        _add_finding(
            findings,
            code="mixed_text_binary",
            message="The sample is predominantly printable text but contains NUL bytes.",
            severity="low",
            category="content_characteristics",
        )


# ============================================================================
# Extension/content consistency
# ============================================================================


def _extension_category(extension: str) -> Optional[str]:
    if extension in EXECUTABLE_EXTENSIONS:
        return "executable"

    if extension in SCRIPT_EXTENSIONS:
        return "script"

    if extension in MACRO_CAPABLE_EXTENSIONS:
        return "macro_document"

    if extension in ARCHIVE_EXTENSIONS:
        return "archive"

    if extension in DOCUMENT_EXTENSIONS:
        return "document"

    return None


def _signature_category(signatures: Sequence[str]) -> Optional[str]:
    signature_set = set(signatures)

    if signature_set & {
        "pe",
        "elf",
        "mach_o_32",
        "mach_o_64",
        "mach_o_32_reverse",
        "mach_o_64_reverse",
        "wasm",
    }:
        return "executable"

    if signature_set & {
        "zip",
        "zip_empty",
        "zip_spanned",
        "gzip",
        "bzip2",
        "xz",
        "7zip",
        "rar4",
        "rar5",
    }:
        return "archive"

    if signature_set & {
        "pdf",
        "rtf",
        "ole",
        "ooxml",
    }:
        return "document"

    return None


def _check_extension_consistency(
    extension: str,
    signatures: Sequence[str],
    findings: List[SafetyFinding],
) -> bool:
    if not extension or not signatures:
        return False

    expected = _extension_category(extension)
    actual = _signature_category(signatures)

    if expected is None or actual is None:
        return False

    compatible = False

    if expected == actual:
        compatible = True

    if expected == "macro_document" and actual == "document":
        compatible = True

    # OOXML documents are ZIP containers but are still legitimate document
    # content.
    if expected in {"document", "macro_document"} and "ooxml" in signatures:
        compatible = True

    if expected == "archive" and actual == "document" and "ooxml" not in signatures:
        compatible = False

    if compatible:
        return False

    _add_finding(
        findings,
        code="extension_content_mismatch",
        message=(
            f"The filename extension '{extension}' is inconsistent with "
            f"the detected static content category '{actual}'."
        ),
        severity="medium",
        category="content_type",
        evidence=",".join(signatures),
    )

    return True


# ============================================================================
# Executable/script/macro risk policy
# ============================================================================


def _check_active_content_policy(
    extension: str,
    signatures: Sequence[str],
    findings: List[SafetyFinding],
    risk_flags: List[str],
    *,
    block_executables: bool,
    block_scripts: bool,
    block_macro_documents: bool,
) -> None:
    signature_set = set(signatures)

    executable_content = bool(
        signature_set
        & {
            "pe",
            "elf",
            "mach_o_32",
            "mach_o_64",
            "mach_o_32_reverse",
            "mach_o_64_reverse",
            "wasm",
        }
    )

    script_content = extension in SCRIPT_EXTENSIONS

    macro_document = extension in MACRO_CAPABLE_EXTENSIONS or "ole" in signature_set

    if executable_content:
        risk_flags.append("executable_content")

        if block_executables:
            _add_finding(
                findings,
                code="executable_blocked",
                message="Executable content is blocked by the ingestion safety policy.",
                severity="high",
                category="active_content",
                blocking=True,
                recoverable=False,
            )

    if script_content:
        risk_flags.append("script_content")

        if block_scripts:
            _add_finding(
                findings,
                code="script_blocked",
                message="Script content is blocked by the ingestion safety policy.",
                severity="high",
                category="active_content",
                blocking=True,
                recoverable=False,
            )

    if macro_document:
        risk_flags.append("macro_capable_content")

        if block_macro_documents:
            _add_finding(
                findings,
                code="macro_capable_document_blocked",
                message="Macro-capable document content is blocked by the ingestion safety policy.",
                severity="high",
                category="active_content",
                blocking=True,
                recoverable=False,
            )


# ============================================================================
# Resource policy
# ============================================================================


def _check_resource_limits(
    size: int,
    findings: List[SafetyFinding],
    *,
    max_file_size: int,
) -> None:
    if size > max_file_size:
        _add_finding(
            findings,
            code="file_size_limit_exceeded",
            message=(
                f"The input size ({size} bytes) exceeds the configured "
                f"safety limit ({max_file_size} bytes)."
            ),
            severity="critical",
            category="resource_limit",
            blocking=True,
            recoverable=False,
        )


# ============================================================================
# Core path safety gate
# ============================================================================


def check_file_safety(
    path: os.PathLike[str] | str,
    *,
    max_file_size: int = DEFAULT_MAX_FILE_SIZE,
    max_sample_size: int = DEFAULT_MAX_SAMPLE_SIZE,
    max_hash_size: int = DEFAULT_MAX_FILE_SIZE,
    max_path_length: int = DEFAULT_MAX_PATH_LENGTH,
    require_regular_file: bool = True,
    reject_symlinks: bool = True,
    require_readable: bool = True,
    reject_empty: bool = True,
    require_known_content: bool = False,
    block_executables: bool = False,
    block_scripts: bool = False,
    block_macro_documents: bool = False,
) -> SafetyResult:
    """
    Run the static safety gate against a filesystem path.

    The function never executes the target and never performs active content
    processing.

    Parameters
    ----------
    path:
        Filesystem path to inspect.

    max_file_size:
        Maximum accepted file size.

    max_sample_size:
        Maximum bytes inspected for static content checks.

    max_hash_size:
        Maximum bytes used for cryptographic hashing.

    max_path_length:
        Maximum accepted path length.

    require_regular_file:
        Reject directories and special filesystem objects.

    reject_symlinks:
        Reject symbolic links before opening the target.

    require_readable:
        Require that a bounded sample can be read.

    reject_empty:
        Reject zero-byte inputs.

    require_known_content:
        Reject content that produces no recognized magic signature.

    block_executables:
        Reject executable content.

    block_scripts:
        Reject script filenames.

    block_macro_documents:
        Reject macro-capable document inputs.
    """

    findings: List[SafetyFinding] = []
    risk_flags: List[str] = []

    normalized_path = _path_string(path)

    if not normalized_path:
        _add_finding(
            findings,
            code="missing_path",
            message="No filesystem path was supplied.",
            severity="critical",
            category="input",
            blocking=True,
            recoverable=False,
        )

        return SafetyResult(
            safe=False,
            allowed_for_analysis=False,
            source_kind="path",
            findings=findings,
        )

    _check_path_safety(
        normalized_path,
        findings,
        max_path_length=max_path_length,
    )

    filename = _filename(normalized_path)
    extension = _extension(filename)

    _check_filename_safety(
        filename,
        findings,
    )

    if not os.path.exists(normalized_path):
        _add_finding(
            findings,
            code="file_not_found",
            message="The supplied file does not exist.",
            severity="critical",
            category="filesystem",
            blocking=True,
            recoverable=False,
        )

        return SafetyResult(
            safe=False,
            allowed_for_analysis=False,
            source_kind="path",
            path=normalized_path,
            filename=filename,
            extension=extension,
            findings=findings,
        )

    metadata = _check_filesystem_object(
        normalized_path,
        findings,
        require_regular_file=require_regular_file,
        reject_symlinks=reject_symlinks,
    )

    if metadata is None:
        return SafetyResult(
            safe=False,
            allowed_for_analysis=False,
            source_kind="path",
            path=normalized_path,
            filename=filename,
            extension=extension,
            findings=findings,
        )

    size = int(getattr(metadata, "st_size", 0) or 0)

    _check_resource_limits(
        size,
        findings,
        max_file_size=max_file_size,
    )

    if size == 0 and reject_empty:
        _add_finding(
            findings,
            code="empty_file",
            message="Zero-byte files are rejected by the ingestion safety policy.",
            severity="medium",
            category="content",
            blocking=True,
            recoverable=False,
        )

    _check_permissions(
        metadata,
        findings,
    )

    try:
        readable = os.access(normalized_path, os.R_OK)
    except OSError:
        readable = False

    if require_readable and not readable:
        _add_finding(
            findings,
            code="not_readable",
            message="The file is not readable by the current process.",
            severity="high",
            category="filesystem",
            blocking=True,
            recoverable=False,
        )

    sample = b""
    sample_complete = False

    if readable and size <= max_file_size:
        sample, sample_complete = _read_sample(
            normalized_path,
            min(max_sample_size, size),
        )

        if size > 0 and not sample:
            _add_finding(
                findings,
                code="read_failed",
                message="The bounded content sample could not be read.",
                severity="high",
                category="filesystem",
                blocking=True,
                recoverable=False,
            )

        if size > len(sample) and not sample_complete:
            _add_finding(
                findings,
                code="bounded_sample",
                message="Only a bounded prefix of the file was inspected.",
                severity="info",
                category="resource_limit",
            )

    statistics = _statistics(
        sample,
        size,
    )

    signatures = detect_signatures(sample)

    _check_signature_risks(
        signatures,
        extension,
        findings,
        risk_flags,
    )

    _check_content_characteristics(
        statistics,
        None,
        findings,
        risk_flags,
    )

    mismatch = _check_extension_consistency(
        extension,
        signatures,
        findings,
    )

    if mismatch:
        risk_flags.append("extension_content_mismatch")

    _check_active_content_policy(
        extension,
        signatures,
        findings,
        risk_flags,
        block_executables=block_executables,
        block_scripts=block_scripts,
        block_macro_documents=block_macro_documents,
    )

    if require_known_content and sample and not signatures:
        _add_finding(
            findings,
            code="unknown_content_type",
            message="The bounded content sample did not match a recognized static signature.",
            severity="medium",
            category="content_type",
            blocking=True,
            recoverable=False,
        )

    hashes = SafetyHashes()

    if readable and size <= max_file_size:
        hashes = _hash_file(
            normalized_path,
            min(max_hash_size, max_file_size),
        )

        if not hashes.sha256:
            _add_finding(
                findings,
                code="hash_failed",
                message="Cryptographic hashing could not be completed.",
                severity="medium",
                category="integrity",
            )

        elif not hashes.complete:
            _add_finding(
                findings,
                code="partial_hash",
                message="The cryptographic digest covers only a bounded prefix of the file.",
                severity="medium",
                category="integrity",
            )

    blocking = any(finding.blocking for finding in findings)

    safe = not blocking

    return SafetyResult(
        safe=safe,
        allowed_for_analysis=safe,
        source_kind="path",
        path=normalized_path,
        filename=filename,
        extension=extension,
        size=size,
        hashes=hashes,
        statistics=statistics,
        findings=findings,
        detected_signatures=sorted(set(signatures)),
        risk_flags=sorted(set(risk_flags)),
    )


# ============================================================================
# In-memory safety gate
# ============================================================================


def check_bytes_safety(
    data: bytes | bytearray | memoryview,
    *,
    filename: Optional[str] = None,
    max_file_size: int = DEFAULT_MAX_FILE_SIZE,
    max_sample_size: int = DEFAULT_MAX_SAMPLE_SIZE,
    require_known_content: bool = False,
    block_executables: bool = False,
    block_scripts: bool = False,
    block_macro_documents: bool = False,
) -> SafetyResult:
    """
    Run the static safety gate against in-memory content.

    The content is never written to disk.
    """

    findings: List[SafetyFinding] = []
    risk_flags: List[str] = []

    try:
        raw = bytes(data)
    except Exception:
        _add_finding(
            findings,
            code="invalid_bytes",
            message="The supplied object could not be converted to bytes.",
            severity="critical",
            category="input",
            blocking=True,
            recoverable=False,
        )

        return SafetyResult(
            safe=False,
            allowed_for_analysis=False,
            source_kind="bytes",
            filename=_safe_text(filename, DEFAULT_MAX_FILENAME_LENGTH),
            findings=findings,
        )

    filename_value = _safe_text(
        filename,
        DEFAULT_MAX_FILENAME_LENGTH,
    )

    extension = _extension(filename_value)
    size = len(raw)

    _check_filename_safety(
        filename_value,
        findings,
    )

    _check_resource_limits(
        size,
        findings,
        max_file_size=max_file_size,
    )

    if size == 0:
        _add_finding(
            findings,
            code="empty_file",
            message="Zero-byte content is rejected by the ingestion safety policy.",
            severity="medium",
            category="content",
            blocking=True,
            recoverable=False,
        )

    sample = raw[:max_sample_size]

    if size > len(sample):
        _add_finding(
            findings,
            code="bounded_sample",
            message="Only a bounded prefix of the supplied content was inspected.",
            severity="info",
            category="resource_limit",
        )

    statistics = _statistics(
        sample,
        size,
    )

    signatures = detect_signatures(sample)

    _check_signature_risks(
        signatures,
        extension,
        findings,
        risk_flags,
    )

    _check_content_characteristics(
        statistics,
        None,
        findings,
        risk_flags,
    )

    mismatch = _check_extension_consistency(
        extension,
        signatures,
        findings,
    )

    if mismatch:
        risk_flags.append("extension_content_mismatch")

    _check_active_content_policy(
        extension,
        signatures,
        findings,
        risk_flags,
        block_executables=block_executables,
        block_scripts=block_scripts,
        block_macro_documents=block_macro_documents,
    )

    if require_known_content and sample and not signatures:
        _add_finding(
            findings,
            code="unknown_content_type",
            message="The bounded content sample did not match a recognized static signature.",
            severity="medium",
            category="content_type",
            blocking=True,
            recoverable=False,
        )

    hashes = _hash_bytes(raw)

    return SafetyResult(
        safe=not any(finding.blocking for finding in findings),
        allowed_for_analysis=not any(finding.blocking for finding in findings),
        source_kind="bytes",
        path=None,
        filename=filename_value,
        extension=extension,
        size=size,
        hashes=hashes,
        statistics=statistics,
        findings=findings,
        detected_signatures=sorted(set(signatures)),
        risk_flags=sorted(set(risk_flags)),
    )


# ============================================================================
# Generic entry point
# ============================================================================


def check_safety(
    source: Any,
    *,
    filename: Optional[str] = None,
    max_file_size: int = DEFAULT_MAX_FILE_SIZE,
    max_sample_size: int = DEFAULT_MAX_SAMPLE_SIZE,
    max_hash_size: int = DEFAULT_MAX_FILE_SIZE,
    max_path_length: int = DEFAULT_MAX_PATH_LENGTH,
    require_regular_file: bool = True,
    reject_symlinks: bool = True,
    require_readable: bool = True,
    reject_empty: bool = True,
    require_known_content: bool = False,
    block_executables: bool = False,
    block_scripts: bool = False,
    block_macro_documents: bool = False,
) -> SafetyResult:
    """
    Generic safety-gate entry point.

    Supported input types:

    - filesystem paths;
    - bytes;
    - bytearray;
    - memoryview.

    Strings are interpreted as filesystem paths.
    """

    if isinstance(source, (bytes, bytearray, memoryview)):
        return check_bytes_safety(
            source,
            filename=filename,
            max_file_size=max_file_size,
            max_sample_size=max_sample_size,
            require_known_content=require_known_content,
            block_executables=block_executables,
            block_scripts=block_scripts,
            block_macro_documents=block_macro_documents,
        )

    if isinstance(source, (str, os.PathLike)):
        return check_file_safety(
            source,
            max_file_size=max_file_size,
            max_sample_size=max_sample_size,
            max_hash_size=max_hash_size,
            max_path_length=max_path_length,
            require_regular_file=require_regular_file,
            reject_symlinks=reject_symlinks,
            require_readable=require_readable,
            reject_empty=reject_empty,
            require_known_content=require_known_content,
            block_executables=block_executables,
            block_scripts=block_scripts,
            block_macro_documents=block_macro_documents,
        )

    finding = SafetyFinding(
        code="unsupported_input",
        message=(
            "Safety checking accepts filesystem paths or in-memory byte "
            "sequences only."
        ),
        severity="critical",
        category="input",
        blocking=True,
        recoverable=False,
    )

    return SafetyResult(
        safe=False,
        allowed_for_analysis=False,
        source_kind="unknown",
        filename=_safe_text(filename, DEFAULT_MAX_FILENAME_LENGTH),
        findings=[finding],
    )


# ============================================================================
# Predicates
# ============================================================================


def is_safe(result: SafetyResult) -> bool:
    """Return whether the input passed the safety gate."""

    return bool(result.safe)


def is_allowed(result: SafetyResult) -> bool:
    """Return whether downstream static analysis may proceed."""

    return bool(result.allowed_for_analysis)


def has_finding(
    result: SafetyResult,
    code: str,
) -> bool:
    """Check whether a specific safety finding exists."""

    target = _safe_text(code, 128).lower()

    return any(finding.code.lower() == target for finding in result.findings)


def has_category(
    result: SafetyResult,
    category: str,
) -> bool:
    """Check whether a safety finding category exists."""

    target = _safe_text(category, 128).lower()

    return any(finding.category.lower() == target for finding in result.findings)


def has_risk_flag(
    result: SafetyResult,
    flag: str,
) -> bool:
    """Check whether a normalized risk flag is present."""

    target = _feature_name(flag)

    return target in {_feature_name(item) for item in result.risk_flags}


def highest_severity(
    result: SafetyResult,
) -> str:
    """Return the highest finding severity."""

    return result.highest_severity


def findings_by_severity(
    result: SafetyResult,
    severity: str,
) -> List[SafetyFinding]:
    """Return findings with the specified severity."""

    target = _safe_text(severity, 32).lower()

    return [
        finding for finding in result.findings if finding.severity.lower() == target
    ]


def findings_by_category(
    result: SafetyResult,
    category: str,
) -> List[SafetyFinding]:
    """Return findings belonging to a category."""

    target = _safe_text(category, 128).lower()

    return [
        finding for finding in result.findings if finding.category.lower() == target
    ]


def blocking_findings(
    result: SafetyResult,
) -> List[SafetyFinding]:
    """Return findings that block downstream analysis."""

    return [finding for finding in result.findings if finding.blocking]


def requires_review(
    result: SafetyResult,
) -> bool:
    """
    Return whether the result contains medium-or-higher findings.

    This is not a malware verdict.
    """

    return result.requires_review


# ============================================================================
# Feature extraction
# ============================================================================


def build_feature_vector(
    result: SafetyResult,
) -> Dict[str, float]:
    """
    Build a deterministic scalar feature vector from a safety result.

    Dynamic finding/category/risk features are included using stable,
    normalized names.
    """

    vector: Dict[str, float] = {
        "safe": float(bool(result.safe)),
        "allowed_for_analysis": float(bool(result.allowed_for_analysis)),
        "source_is_path": float(result.source_kind == "path"),
        "source_is_bytes": float(result.source_kind == "bytes"),
        "size": float(result.size),
        "sample_size": float(result.statistics.sample_size),
        "entropy": float(result.statistics.entropy),
        "printable_ratio": float(result.statistics.printable_ratio),
        "ascii_ratio": float(result.statistics.ascii_ratio),
        "zero_ratio": float(result.statistics.zero_ratio),
        "has_null_bytes": float(result.statistics.has_null_bytes),
        "starts_with_mz": float(result.statistics.starts_with_mz),
        "starts_with_ole": float(result.statistics.starts_with_ole),
        "starts_with_zip": float(result.statistics.starts_with_zip),
        "starts_with_pdf": float(result.statistics.starts_with_pdf),
        "starts_with_rtf": float(result.statistics.starts_with_rtf),
        "starts_with_elf": float(result.statistics.starts_with_elf),
        "hash_available": float(bool(result.hashes.sha256)),
        "hash_complete": float(bool(result.hashes.complete)),
        "size_hashed": float(result.hashes.size_hashed),
        "signature_count": float(len(result.detected_signatures)),
        "risk_flag_count": float(len(result.risk_flags)),
        "finding_count": float(len(result.findings)),
        "blocking_finding_count": float(result.blocking_findings),
        "warning_finding_count": float(result.warning_findings),
        "highest_severity": float(SEVERITY_ORDER.get(result.highest_severity, 0)),
    }

    severity_counts = {severity: 0 for severity in SEVERITY_ORDER}

    finding_code_counts: Dict[str, int] = {}
    category_counts: Dict[str, int] = {}
    risk_counts: Dict[str, int] = {}
    signature_counts: Dict[str, int] = {}

    for finding in result.findings:
        severity = finding.severity.lower()

        if severity in severity_counts:
            severity_counts[severity] += 1

        code = _feature_name(finding.code)

        if code:
            finding_code_counts[code] = finding_code_counts.get(code, 0) + 1

        category = _feature_name(finding.category)

        if category:
            category_counts[category] = category_counts.get(category, 0) + 1

    for flag in result.risk_flags:
        normalized = _feature_name(flag)

        if normalized:
            risk_counts[normalized] = risk_counts.get(normalized, 0) + 1

    for signature in result.detected_signatures:
        normalized = _feature_name(signature)

        if normalized:
            signature_counts[normalized] = signature_counts.get(normalized, 0) + 1

    for severity, count in severity_counts.items():
        vector[f"severity_{severity}_count"] = float(count)

    for code, count in sorted(finding_code_counts.items()):
        vector[f"finding_{code}"] = float(count)

    for category, count in sorted(category_counts.items()):
        vector[f"category_{category}"] = float(count)

    for flag, count in sorted(risk_counts.items()):
        vector[f"risk_{flag}"] = float(count)

    for signature, count in sorted(signature_counts.items()):
        vector[f"signature_{signature}"] = float(count)

    return dict(sorted(vector.items()))


def extract_feature_vector(
    result: SafetyResult,
) -> Dict[str, float]:
    """Return the result's stable feature vector."""

    return dict(result.feature_vector)


def feature_names() -> List[str]:
    """
    Return the fixed core feature names.

    Dynamic signature/finding/risk features are deliberately excluded from
    this fixed list and can be incorporated by the dataset/schema layer.
    """

    return [
        "safe",
        "allowed_for_analysis",
        "source_is_path",
        "source_is_bytes",
        "size",
        "sample_size",
        "entropy",
        "printable_ratio",
        "ascii_ratio",
        "zero_ratio",
        "has_null_bytes",
        "starts_with_mz",
        "starts_with_ole",
        "starts_with_zip",
        "starts_with_pdf",
        "starts_with_rtf",
        "starts_with_elf",
        "hash_available",
        "hash_complete",
        "size_hashed",
        "signature_count",
        "risk_flag_count",
        "finding_count",
        "blocking_finding_count",
        "warning_finding_count",
        "highest_severity",
        "severity_info_count",
        "severity_low_count",
        "severity_medium_count",
        "severity_high_count",
        "severity_critical_count",
    ]


def build_feature_schema() -> Dict[str, Any]:
    """Return a serializable core feature schema."""

    return {
        "schema_version": "1.0",
        "module": "src.ingestion.safety",
        "feature_type": "scalar",
        "features": [
            {
                "name": name,
                "dtype": "float64",
            }
            for name in feature_names()
        ],
    }


def vectorize(
    result: SafetyResult,
    names: Optional[Sequence[str]] = None,
) -> List[float]:
    """Convert the safety result to an ordered numeric vector."""

    if names is None:
        names = feature_names()

    return [float(result.feature_vector.get(name, 0.0)) for name in names]


# ============================================================================
# Serialization / reporting
# ============================================================================


def result_to_dict(
    result: SafetyResult,
) -> Dict[str, Any]:
    """Serialize a safety result into JSON-compatible Python structures."""

    return result.to_dict()


def summarize(
    result: SafetyResult,
) -> Dict[str, Any]:
    """Return a compact safety summary for reports and pipeline decisions."""

    return {
        "safe": result.safe,
        "allowed_for_analysis": result.allowed_for_analysis,
        "source_kind": result.source_kind,
        "filename": result.filename,
        "extension": result.extension,
        "size": result.size,
        "sha256": result.hashes.sha256,
        "hash_complete": result.hashes.complete,
        "detected_signatures": list(result.detected_signatures),
        "risk_flags": list(result.risk_flags),
        "finding_count": len(result.findings),
        "blocking_findings": result.blocking_findings,
        "warning_findings": result.warning_findings,
        "highest_severity": result.highest_severity,
        "requires_review": result.requires_review,
    }


def iter_findings(
    result: SafetyResult,
) -> Iterator[SafetyFinding]:
    """Iterate over all findings."""

    yield from result.findings


def iter_blocking_findings(
    result: SafetyResult,
) -> Iterator[SafetyFinding]:
    """Iterate over blocking findings."""

    for finding in result.findings:
        if finding.blocking:
            yield finding


def iter_risk_flags(
    result: SafetyResult,
) -> Iterator[str]:
    """Iterate over normalized risk flags."""

    yield from result.risk_flags


# ============================================================================
# Policy helpers
# ============================================================================


def default_safety_policy() -> Dict[str, Any]:
    """
    Return the project's conservative default ingestion policy.

    Executables, scripts, and macro-capable documents are flagged but not
    automatically blocked here because Pharos is intended to analyze such
    content statically. Callers can enable the corresponding block options
    when operating an upload gateway with a stricter policy.
    """

    return {
        "max_file_size": DEFAULT_MAX_FILE_SIZE,
        "max_sample_size": DEFAULT_MAX_SAMPLE_SIZE,
        "max_hash_size": DEFAULT_MAX_FILE_SIZE,
        "max_path_length": DEFAULT_MAX_PATH_LENGTH,
        "require_regular_file": True,
        "reject_symlinks": True,
        "require_readable": True,
        "reject_empty": True,
        "require_known_content": False,
        "block_executables": False,
        "block_scripts": False,
        "block_macro_documents": False,
    }


def strict_safety_policy() -> Dict[str, Any]:
    """
    Return a stricter upload-gateway policy.

    This policy blocks executable, script, and macro-capable inputs.
    """

    policy = default_safety_policy()

    policy.update(
        {
            "block_executables": True,
            "block_scripts": True,
            "block_macro_documents": True,
            "require_known_content": True,
        }
    )

    return policy


def evaluate_policy(
    result: SafetyResult,
    *,
    block_on_warning: bool = False,
) -> bool:
    """
    Evaluate an already-generated result against a simple policy.

    Parameters
    ----------
    result:
        Existing safety result.

    block_on_warning:
        If true, medium-or-higher findings also prevent downstream analysis.
    """

    if result.blocking_findings > 0:
        return False

    if block_on_warning and result.warning_findings > 0:
        return False

    return bool(result.safe)


# ============================================================================
# Compatibility aliases
# ============================================================================


check = check_safety
analyze = check_safety
analyze_file = check_file_safety
analyze_bytes = check_bytes_safety
validate_safety = check_safety
validate_file_safety = check_file_safety
validate_bytes_safety = check_bytes_safety
extract_features = extract_feature_vector


# ============================================================================
# PUBLIC APIs
# ============================================================================


__all__ = [
    "SafetyFinding",
    "SafetyHashes",
    "SafetyStatistics",
    "SafetyResult",
    "check_safety",
    "check_file_safety",
    "check_bytes_safety",
    "detect_signatures",
    "is_safe",
    "is_allowed",
    "has_finding",
    "has_category",
    "has_risk_flag",
    "highest_severity",
    "findings_by_severity",
    "findings_by_category",
    "blocking_findings",
    "requires_review",
    "build_feature_vector",
    "extract_feature_vector",
    "extract_features",
    "feature_names",
    "build_feature_schema",
    "vectorize",
    "result_to_dict",
    "summarize",
    "iter_findings",
    "iter_blocking_findings",
    "iter_risk_flags",
    "default_safety_policy",
    "strict_safety_policy",
    "evaluate_policy",
    "check",
    "analyze",
    "analyze_file",
    "analyze_bytes",
    "validate_safety",
    "validate_file_safety",
    "validate_bytes_safety",
]
