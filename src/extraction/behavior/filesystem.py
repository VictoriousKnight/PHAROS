"""
Static filesystem-behavior extraction for the Pharos CDR pipeline.

This module analyzes text, bytes, paths, and structured static-analysis
results for filesystem-related behavior without executing anything.

Security properties
-------------------
- Never creates, deletes, modifies, or opens arbitrary files discovered in
  analyzed content.
- Never executes commands or scripts.
- Never resolves or follows external references.
- Never invokes OS filesystem APIs for behavioral interpretation.
- Input paths are treated as data, not instructions.
- Bounded parsing is used to prevent pathological input from consuming
  excessive resources.

The extractor is designed to sit between static content extraction and the
feature pipeline:

    raw/static evidence
        -> filesystem behavior
        -> capabilities / behavior chains
        -> ML feature vector
        -> CDR decision

The resulting feature names are deterministic and suitable for model-schema
generation.
"""

from __future__ import annotations

import hashlib
import math
import re
from dataclasses import asdict, dataclass, field
from pathlib import PurePath
from typing import Any, Dict, Iterable, Iterator, List, Mapping, Optional, Sequence, Tuple


# ---------------------------------------------------------------------------
# Limits
# ---------------------------------------------------------------------------

MAX_SOURCE_SIZE = 25 * 1024 * 1024
MAX_TEXT_CHARS = 25 * 1024 * 1024
MAX_EVIDENCE_ITEMS = 20_000
MAX_MATCHES_PER_RULE = 5_000
MAX_NESTING_DEPTH = 12
MAX_FIELD_TEXT = 100_000
MAX_PATHS = 20_000
MAX_COMMAND_LINES = 20_000
MAX_FILE_OPERATIONS = 20_000
MAX_UNIQUE_VALUES = 10_000


# ---------------------------------------------------------------------------
# Severity / confidence helpers
# ---------------------------------------------------------------------------

SEVERITIES = ("low", "medium", "high", "critical")

SEVERITY_WEIGHT = {
    "low": 1.0,
    "medium": 2.0,
    "high": 4.0,
    "critical": 7.0,
}


def _clamp(value: float, lower: float, upper: float) -> float:
    return max(lower, min(upper, value))


def _severity_rank(value: str) -> int:
    try:
        return SEVERITIES.index(value)
    except ValueError:
        return 0


def _max_severity(values: Iterable[str]) -> str:
    best = "low"
    for value in values:
        if _severity_rank(value) > _severity_rank(best):
            best = value
    return best


def _normalize_severity(value: Any, default: str = "medium") -> str:
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in SEVERITIES:
            return normalized
    return default


def _normalize_confidence(value: Any, default: float = 0.75) -> float:
    try:
        return _clamp(float(value), 0.0, 1.0)
    except (TypeError, ValueError):
        return default


# ---------------------------------------------------------------------------
# Filesystem taxonomy
# ---------------------------------------------------------------------------

FILESYSTEM_CATEGORIES: Tuple[str, ...] = (
    "file_create",
    "file_write",
    "file_append",
    "file_read",
    "file_copy",
    "file_move",
    "file_delete",
    "file_rename",
    "file_exists",
    "file_metadata",
    "directory_create",
    "directory_delete",
    "directory_enumeration",
    "directory_change",
    "temporary_file",
    "alternate_data_stream",
    "network_share",
    "unc_path",
    "mapped_drive",
    "system_directory",
    "user_directory",
    "startup_directory",
    "download_directory",
    "application_directory",
    "hidden_file",
    "file_attribute",
    "archive_operation",
    "executable_file",
    "script_file",
    "library_file",
    "document_file",
    "configuration_file",
    "credential_file",
    "log_file",
    "backup_file",
    "lock_file",
    "staging",
    "cleanup",
    "destructive_file_operation",
    "filesystem_execution",
    "path_discovery",
)


# Indicators are deliberately descriptive rather than proof of maliciousness.
# Many legitimate applications perform these operations.
INDICATOR_NAMES: Tuple[str, ...] = (
    "create_file",
    "write_file",
    "append_file",
    "read_file",
    "copy_file",
    "move_file",
    "delete_file",
    "rename_file",
    "file_exists_check",
    "file_metadata_query",
    "create_directory",
    "delete_directory",
    "enumerate_directory",
    "change_directory",
    "temporary_file",
    "alternate_data_stream",
    "unc_path",
    "network_share",
    "mapped_drive",
    "startup_location",
    "system_path",
    "user_profile_path",
    "download_path",
    "hidden_file",
    "hidden_attribute",
    "archive_creation",
    "archive_extraction",
    "executable_target",
    "script_target",
    "library_target",
    "document_target",
    "configuration_target",
    "credential_target",
    "log_target",
    "backup_target",
    "lock_target",
    "file_staging",
    "file_cleanup",
    "recursive_delete",
    "mass_file_operation",
    "path_traversal",
    "filesystem_execution",
)


# ---------------------------------------------------------------------------
# Known filesystem vocabularies
# ---------------------------------------------------------------------------

SYSTEM_PATH_MARKERS: Tuple[str, ...] = (
    r"\\windows\\",
    r"\\system32\\",
    r"\\syswow64\\",
    r"\\winsxs\\",
    r"\\program files\\",
    r"\\programdata\\",
    r"\\system volume information\\",
    "/etc/",
    "/usr/bin/",
    "/usr/sbin/",
    "/usr/lib/",
    "/var/lib/",
    "/var/log/",
    "/opt/",
)

USER_PATH_MARKERS: Tuple[str, ...] = (
    r"\\users\\",
    r"\\documents and settings\\",
    "/home/",
    "/users/",
)

STARTUP_PATH_MARKERS: Tuple[str, ...] = (
    r"\\start menu\\programs\\startup",
    r"\\appdata\\roaming\\microsoft\\windows\\start menu\\programs\\startup",
    r"\\programdata\\microsoft\\windows\\start menu\\programs\\startup",
    "/.config/autostart/",
)

DOWNLOAD_PATH_MARKERS: Tuple[str, ...] = (
    r"\\downloads\\",
    r"\\appdata\\local\\microsoft\\windows\\inetcache",
    r"\\appdata\\local\\temp\\",
    "/downloads/",
    "/tmp/",
    "/var/tmp/",
)

TEMP_PATH_MARKERS: Tuple[str, ...] = (
    r"\\temp\\",
    r"\\tmp\\",
    r"\\appdata\\local\\temp\\",
    "/tmp/",
    "/var/tmp/",
)

NETWORK_SHARE_MARKERS: Tuple[str, ...] = (
    r"\\netlogon\\",
    r"\\sysvol\\",
)

EXECUTABLE_EXTENSIONS = {
    ".exe",
    ".com",
    ".scr",
    ".msi",
    ".dll",
    ".sys",
    ".cpl",
    ".ocx",
    ".drv",
    ".efi",
    ".elf",
    ".bin",
}

SCRIPT_EXTENSIONS = {
    ".ps1",
    ".psm1",
    ".psd1",
    ".vbs",
    ".vbe",
    ".js",
    ".jse",
    ".wsf",
    ".wsc",
    ".hta",
    ".bat",
    ".cmd",
    ".sh",
    ".bash",
    ".zsh",
    ".fish",
    ".py",
    ".pl",
    ".rb",
}

LIBRARY_EXTENSIONS = {
    ".dll",
    ".ocx",
    ".so",
    ".dylib",
    ".sys",
    ".drv",
}

DOCUMENT_EXTENSIONS = {
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
    ".pps",
    ".ppsx",
    ".pdf",
    ".rtf",
    ".odt",
    ".ods",
    ".odp",
}

CONFIGURATION_EXTENSIONS = {
    ".ini",
    ".cfg",
    ".conf",
    ".config",
    ".json",
    ".yaml",
    ".yml",
    ".xml",
    ".toml",
    ".plist",
}

CREDENTIAL_FILENAMES = {
    "sam",
    "security",
    "ntds.dit",
    "credentials",
    "credentials.xml",
    "web.config",
    "unattend.xml",
    "sysprep.xml",
    ".netrc",
    ".npmrc",
    ".pypirc",
    "id_rsa",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    "known_hosts",
}

LOG_EXTENSIONS = {
    ".log",
    ".evtx",
    ".etl",
    ".trace",
}

BACKUP_EXTENSIONS = {
    ".bak",
    ".backup",
    ".old",
    ".orig",
    ".tmp",
    ".swp",
}

ARCHIVE_EXTENSIONS = {
    ".zip",
    ".rar",
    ".7z",
    ".cab",
    ".tar",
    ".gz",
    ".tgz",
    ".bz2",
    ".xz",
    ".iso",
}

LOCK_EXTENSIONS = {
    ".lock",
    ".lck",
}


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class FilesystemPattern:
    """A static filesystem-behavior detection rule."""

    name: str
    category: str
    pattern: str
    description: str
    severity: str = "medium"
    confidence: float = 0.80
    flags: int = re.IGNORECASE


@dataclass
class FilesystemEvidence:
    """One bounded piece of evidence supporting filesystem behavior."""

    category: str
    indicator: str
    evidence: str
    source: str = "static_text"
    line_number: Optional[int] = None
    path: Optional[str] = None
    operation: Optional[str] = None
    severity: str = "medium"
    confidence: float = 0.75
    context: Optional[str] = None

    def __post_init__(self) -> None:
        self.category = str(self.category)
        self.indicator = str(self.indicator)
        self.severity = _normalize_severity(self.severity)
        self.confidence = _normalize_confidence(self.confidence)
        if self.evidence:
            self.evidence = self.evidence[:MAX_FIELD_TEXT]
        if self.context:
            self.context = self.context[:MAX_FIELD_TEXT]
        if self.path:
            self.path = self.path[:MAX_FIELD_TEXT]


@dataclass
class FilesystemRecord:
    """A normalized filesystem operation discovered in static content."""

    operation: str
    path: Optional[str] = None
    source: str = "static_text"
    category: Optional[str] = None
    indicator: Optional[str] = None
    line_number: Optional[int] = None
    recursive: bool = False
    target_type: Optional[str] = None
    severity: str = "medium"
    confidence: float = 0.75
    evidence: Optional[str] = None

    def __post_init__(self) -> None:
        self.operation = str(self.operation).strip().lower()
        self.severity = _normalize_severity(self.severity)
        self.confidence = _normalize_confidence(self.confidence)
        if self.path:
            self.path = self.path[:MAX_FIELD_TEXT]
        if self.evidence:
            self.evidence = self.evidence[:MAX_FIELD_TEXT]


@dataclass(frozen=True)
class FilesystemCombination:
    """A higher-level filesystem behavior chain."""

    name: str
    present: bool
    required_indicators: Tuple[str, ...]
    explanation: str
    severity: str = "high"


@dataclass
class FilesystemAnalysis:
    """Complete static filesystem-behavior analysis."""

    source_hash: str
    source_size: int
    evidence: List[FilesystemEvidence] = field(default_factory=list)
    records: List[FilesystemRecord] = field(default_factory=list)
    indicators: List[str] = field(default_factory=list)
    categories: List[str] = field(default_factory=list)
    combinations: List[FilesystemCombination] = field(default_factory=list)
    paths: List[str] = field(default_factory=list)
    executable_paths: List[str] = field(default_factory=list)
    script_paths: List[str] = field(default_factory=list)
    network_paths: List[str] = field(default_factory=list)
    system_paths: List[str] = field(default_factory=list)
    user_paths: List[str] = field(default_factory=list)
    temporary_paths: List[str] = field(default_factory=list)
    suspicious_paths: List[str] = field(default_factory=list)
    feature_vector: Dict[str, float] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Regex rules
# ---------------------------------------------------------------------------

def _p(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern, re.IGNORECASE)


PATTERNS: Tuple[FilesystemPattern, ...] = (
    FilesystemPattern(
        "create_file_api",
        "file_create",
        r"\b(?:CreateFile(?:W|A)?|open|fopen|_wfopen|File\.Create|FileStream)\s*\(",
        "File creation/opening API or constructor.",
        "medium",
        0.90,
    ),
    FilesystemPattern(
        "write_file_api",
        "file_write",
        r"\b(?:WriteFile|WriteFileEx|fwrite|write|File\.WriteAll(?:Text|Bytes)|WriteAllText|WriteAllBytes|FileStream\.Write)\s*\(",
        "File write operation.",
        "medium",
        0.92,
    ),
    FilesystemPattern(
        "append_file_api",
        "file_append",
        r"\b(?:File\.Append(?:AllText|Text)?|StreamWriter|fputs|fprintf)\s*\(",
        "File append or writer operation.",
        "medium",
        0.86,
    ),
    FilesystemPattern(
        "read_file_api",
        "file_read",
        r"\b(?:ReadFile(?:Ex)?|fread|read|File\.ReadAll(?:Text|Bytes|Lines)|FileStream\.Read|StreamReader)\s*\(",
        "File read operation.",
        "low",
        0.90,
    ),
    FilesystemPattern(
        "copy_file_api",
        "file_copy",
        r"\b(?:CopyFile(?:Ex|W|A)?|File\.Copy|copy-item)\b",
        "File copy operation.",
        "medium",
        0.92,
    ),
    FilesystemPattern(
        "move_file_api",
        "file_move",
        r"\b(?:MoveFile(?:Ex|W|A)?|File\.Move|move-item|mv\s+|move\s+)\b",
        "File move operation.",
        "medium",
        0.88,
    ),
    FilesystemPattern(
        "delete_file_api",
        "file_delete",
        r"\b(?:DeleteFile(?:W|A)?|File\.Delete|Remove-Item|del\s+|erase\s+|rm\s+(?:-rf|-f|-r)?\s*)\b",
        "File deletion operation.",
        "high",
        0.93,
    ),
    FilesystemPattern(
        "rename_file_api",
        "file_rename",
        r"\b(?:rename|ren|RenameFile(?:W|A)?|File\.Move)\b",
        "File rename operation.",
        "medium",
        0.78,
    ),
    FilesystemPattern(
        "file_exists_api",
        "file_exists",
        r"\b(?:GetFileAttributes(?:W|A)?|Path\.Exists|File\.Exists|Test-Path|access\s*\(|stat\s*\(|lstat\s*\()\b",
        "Filesystem existence or accessibility check.",
        "low",
        0.90,
    ),
    FilesystemPattern(
        "file_metadata_api",
        "file_metadata",
        r"\b(?:GetFileAttributes(?:W|A)?|GetFileInformationByHandle|stat\s*\(|lstat\s*\(|FileInfo|DirectoryInfo)\b",
        "Filesystem metadata query.",
        "low",
        0.86,
    ),
    FilesystemPattern(
        "directory_create_api",
        "directory_create",
        r"\b(?:CreateDirectory(?:W|A)?|mkdir|md\s+|New-Item\s+-ItemType\s+Directory|Directory\.CreateDirectory)\b",
        "Directory creation operation.",
        "medium",
        0.90,
    ),
    FilesystemPattern(
        "directory_delete_api",
        "directory_delete",
        r"\b(?:RemoveDirectory(?:W|A)?|rmdir|rd\s+|Directory\.Delete|Remove-Item\s+.*(?:-Recurse|-Force))\b",
        "Directory deletion operation.",
        "high",
        0.90,
    ),
    FilesystemPattern(
        "directory_enumeration_api",
        "directory_enumeration",
        r"\b(?:FindFirstFile(?:W|A)?|FindNextFile(?:W|A)?|GetFileInformationByHandle|Directory\.GetFiles|Directory\.EnumerateFiles|Get-ChildItem|dir\s+|ls\s+|find\s+)\b",
        "Directory or file enumeration.",
        "low",
        0.90,
    ),
    FilesystemPattern(
        "change_directory",
        "directory_change",
        r"(?:\b(?:SetCurrentDirectory(?:W|A)?|chdir|Set-Location|SetLocation|cd)\b)",
        "Current-directory change.",
        "low",
        0.86,
    ),
    FilesystemPattern(
        "temporary_file",
        "temporary_file",
        r"\b(?:GetTempPath(?:W|A)?|GetTempFileName(?:W|A)?|mktemp|mkstemp|NamedTemporaryFile|TemporaryFile|%TEMP%|%TMP%|\$env:TEMP|\$env:TMP)\b",
        "Temporary-file or temporary-directory reference.",
        "medium",
        0.92,
    ),
    FilesystemPattern(
        "alternate_data_stream",
        "alternate_data_stream",
        r"(?i)(?:[A-Za-z]:)?[^ \t\r\n\"']+:[A-Za-z0-9_$.-]+",
        "Possible Windows NTFS alternate data stream.",
        "high",
        0.80,
    ),
    FilesystemPattern(
        "unc_path",
        "unc_path",
        r"\\\\[A-Za-z0-9$._-]+\\[^\r\n\"']+",
        "UNC/network path.",
        "medium",
        0.94,
    ),
    FilesystemPattern(
        "mapped_drive",
        "mapped_drive",
        r"\b(?:net\s+use|New-PSDrive|subst)\b",
        "Mapped/network drive operation.",
        "medium",
        0.90,
    ),
    FilesystemPattern(
        "startup_location",
        "startup_directory",
        r"(?i)(?:\\start menu\\programs\\startup|\\appdata\\roaming\\microsoft\\windows\\start menu\\programs\\startup|\\programdata\\microsoft\\windows\\start menu\\programs\\startup|/\.config/autostart/)",
        "Startup/autostart directory reference.",
        "high",
        0.96,
    ),
    FilesystemPattern(
        "hidden_file",
        "hidden_file",
        r"\b(?:attrib\s+.*\+h|SetFileAttributes(?:W|A)?|FILE_ATTRIBUTE_HIDDEN|\.hidden\b|Hidden\s*=\s*true)\b",
        "Hidden-file or hidden-attribute operation.",
        "high",
        0.91,
    ),
    FilesystemPattern(
        "archive_create",
        "archive_operation",
        r"\b(?:Compress-Archive|tar\s+(?:-c|-cz|-cf)|zip\s+(?:-r|-q)|7z\s+a|makecab)\b",
        "Archive creation.",
        "medium",
        0.90,
    ),
    FilesystemPattern(
        "archive_extract",
        "archive_operation",
        r"\b(?:Expand-Archive|tar\s+(?:-x|-xf|-xz)|unzip\b|7z\s+x|extract(?:ing|or)?\b)\b",
        "Archive extraction.",
        "medium",
        0.88,
    ),
    FilesystemPattern(
        "path_traversal",
        "path_discovery",
        r"(?:\.\.[\\/]){2,}|(?:\.\.[\\/])[^ \t\r\n\"']+",
        "Path traversal sequence.",
        "high",
        0.82,
    ),
    FilesystemPattern(
        "filesystem_execution",
        "filesystem_execution",
        r"\b(?:ShellExecute(?:Ex|W|A)?|CreateProcess(?:W|A)?|WinExec|Start-Process|Process\.Start|WScript\.Shell|exec\s*\(|system\s*\()\b",
        "Execution primitive associated with a filesystem-resident target.",
        "high",
        0.82,
    ),
    FilesystemPattern(
        "recursive_delete",
        "destructive_file_operation",
        r"(?:Remove-Item\b[^;\r\n]*-(?:Recurse|Force)|\brm\s+-[^\r\n]*(?:r|R|f|F)|\brmdir\s+/s\b|\bdel\s+/s\b)",
        "Recursive or forced deletion.",
        "critical",
        0.96,
    ),
)


COMPILED_PATTERNS: Tuple[Tuple[FilesystemPattern, re.Pattern[str]], ...] = tuple(
    (pattern, _p(pattern.pattern)) for pattern in PATTERNS
)


# ---------------------------------------------------------------------------
# Input normalization
# ---------------------------------------------------------------------------

def _read_source(source: Any) -> Tuple[str, int, str]:
    """
    Convert supported static-analysis input into bounded text.

    Returns:
        text, original byte/character size, source-kind label
    """
    if source is None:
        return "", 0, "empty"

    if isinstance(source, bytes):
        original_size = len(source)
        if original_size > MAX_SOURCE_SIZE:
            source = source[:MAX_SOURCE_SIZE]
        text = source.decode("utf-8", errors="replace")
        return text[:MAX_TEXT_CHARS], original_size, "bytes"

    if isinstance(source, str):
        original_size = len(source.encode("utf-8", errors="replace"))
        return source[:MAX_TEXT_CHARS], original_size, "text"

    if isinstance(source, Mapping):
        chunks: List[str] = []
        total = 0
        for key, value in _walk_mapping(source):
            fragment = f"{key}={value}"
            fragment = fragment[:MAX_FIELD_TEXT]
            chunks.append(fragment)
            total += len(fragment.encode("utf-8", errors="replace"))
            if total >= MAX_SOURCE_SIZE:
                break
        return "\n".join(chunks)[:MAX_TEXT_CHARS], total, "mapping"

    if isinstance(source, (list, tuple, set, frozenset)):
        chunks = []
        total = 0
        for item in source:
            fragment = _safe_value_to_text(item, 0)
            if fragment:
                chunks.append(fragment[:MAX_FIELD_TEXT])
                total += len(fragment.encode("utf-8", errors="replace"))
            if total >= MAX_SOURCE_SIZE:
                break
        return "\n".join(chunks)[:MAX_TEXT_CHARS], total, "sequence"

    # pathlib.Path and compatible objects are represented as data.
    if isinstance(source, PurePath):
        text = str(source)
        return text[:MAX_TEXT_CHARS], len(text.encode("utf-8")), "path"

    text = _safe_value_to_text(source, 0)
    return text[:MAX_TEXT_CHARS], len(text.encode("utf-8", errors="replace")), "object"


def _safe_value_to_text(value: Any, depth: int) -> str:
    if depth > MAX_NESTING_DEPTH:
        return "<max-depth>"

    if value is None:
        return ""

    if isinstance(value, bytes):
        return value[:MAX_FIELD_TEXT].decode("utf-8", errors="replace")

    if isinstance(value, str):
        return value[:MAX_FIELD_TEXT]

    if isinstance(value, Mapping):
        parts: List[str] = []
        for key, item in value.items():
            parts.append(
                f"{_safe_value_to_text(key, depth + 1)}="
                f"{_safe_value_to_text(item, depth + 1)}"
            )
            if len(parts) >= MAX_UNIQUE_VALUES:
                break
        return "\n".join(parts)[:MAX_FIELD_TEXT]

    if isinstance(value, (list, tuple, set, frozenset)):
        parts = [
            _safe_value_to_text(item, depth + 1)
            for item in list(value)[:MAX_UNIQUE_VALUES]
        ]
        return "\n".join(item for item in parts if item)[:MAX_FIELD_TEXT]

    try:
        return str(value)[:MAX_FIELD_TEXT]
    except Exception:
        return ""


def _walk_mapping(
    mapping: Mapping[Any, Any],
    prefix: str = "",
    depth: int = 0,
) -> Iterator[Tuple[str, Any]]:
    if depth > MAX_NESTING_DEPTH:
        return

    count = 0
    for key, value in mapping.items():
        key_text = str(key)
        full_key = f"{prefix}.{key_text}" if prefix else key_text

        if isinstance(value, Mapping) and depth < MAX_NESTING_DEPTH:
            yield from _walk_mapping(value, full_key, depth + 1)
        elif isinstance(value, (list, tuple, set, frozenset)):
            yield full_key, _safe_value_to_text(value, depth + 1)
        else:
            yield full_key, value

        count += 1
        if count >= MAX_UNIQUE_VALUES:
            break


def _sha256_text(text: str) -> str:
    return hashlib.sha256(
        text.encode("utf-8", errors="replace")
    ).hexdigest()


# ---------------------------------------------------------------------------
# Text/path extraction
# ---------------------------------------------------------------------------

WINDOWS_PATH_RE = re.compile(
    r"""(?:
        [A-Za-z]:[\\/]
        |
        \\\\
    )
    [^\x00\r\n"'<>\|]{1,2048}
    """,
    re.IGNORECASE | re.VERBOSE,
)

POSIX_PATH_RE = re.compile(
    r"""(?:
        /
        [A-Za-z0-9._~!$&'()+,@%\- ]+
        (?:/[A-Za-z0-9._~!$&'()+,@%\- ]+)*
    )
    """,
    re.IGNORECASE | re.VERBOSE,
)

RELATIVE_PATH_RE = re.compile(
    r"""(?:
        (?:\.\.?[\\/])
        [^\x00\r\n"'<>\|]{1,1024}
    )""",
    re.IGNORECASE,
)

PATHLIKE_FILENAME_RE = re.compile(
    r"""(?:
        [A-Za-z0-9_$%~.\- ]+
        [\\/]
        [A-Za-z0-9_$%~.\- ]
        (?:[\\/][A-Za-z0-9_$%~.\- ]+)*
    )""",
    re.IGNORECASE,
)

WINDOWS_ENV_PATH_RE = re.compile(
    r"""(?:
        %(?:TEMP|TMP|APPDATA|LOCALAPPDATA|PROGRAMDATA|PROGRAMFILES|
        PROGRAMFILES\(?:X86\)|SYSTEMROOT|WINDIR|USERPROFILE|PUBLIC|
        STARTUP|ALLUSERSPROFILE)%[\\/][^\r\n"']*
        |
        \$env:(?:TEMP|TMP|APPDATA|LOCALAPPDATA|PROGRAMDATA|PROGRAMFILES|
        SYSTEMROOT|WINDIR|USERPROFILE|PUBLIC)[\\/][^\r\n"']*
    )""",
    re.IGNORECASE | re.VERBOSE,
)

FILENAME_RE = re.compile(
    r"""(?<![A-Za-z0-9])
    [A-Za-z0-9_$%~.\-]{1,180}
    \.
    (?:exe|com|scr|dll|sys|ocx|cpl|msi|ps1|psm1|psd1|vbs|vbe|js|jse|
       wsf|wsc|hta|bat|cmd|sh|bash|py|pl|rb|doc|docx|docm|xls|xlsx|xlsm|
       ppt|pptx|pptm|pdf|rtf|zip|rar|7z|cab|tar|gz|ini|cfg|conf|json|xml|
       yaml|yml|log|evtx|dat|tmp|bak|old|lock)
    \b""",
    re.IGNORECASE | re.VERBOSE,
)


def _normalize_path(path: str) -> str:
    value = path.strip().strip("\"'`")
    value = re.sub(r"\s+", " ", value)
    value = value.replace("/", "\\") if re.match(r"^[A-Za-z]:", value) else value
    return value[:MAX_FIELD_TEXT]


def _looks_like_path(value: str) -> bool:
    value = value.strip()
    if not value:
        return False

    lowered = value.lower()

    if re.match(r"^[a-z]:[\\/]", value):
        return True
    if value.startswith("\\\\"):
        return True
    if value.startswith(("/", "./", "../", ".\\", "..\\")):
        return True
    if any(marker in lowered for marker in ("\\appdata\\", "\\users\\", "\\windows\\")):
        return True
    if "/" in value or "\\" in value:
        return True
    return bool(FILENAME_RE.search(value))


def extract_paths(
    text: str,
    max_paths: int = MAX_PATHS,
) -> List[str]:
    """Extract bounded Windows/POSIX/relative path-like values."""
    if not text:
        return []

    paths: List[str] = []
    seen = set()

    patterns = (
        WINDOWS_ENV_PATH_RE,
        WINDOWS_PATH_RE,
        POSIX_PATH_RE,
        RELATIVE_PATH_RE,
        PATHLIKE_FILENAME_RE,
        FILENAME_RE,
    )

    for regex in patterns:
        count = 0
        for match in regex.finditer(text):
            path = _normalize_path(match.group(0))
            if not _looks_like_path(path):
                continue

            key = path.casefold()
            if key in seen:
                continue

            seen.add(key)
            paths.append(path)

            count += 1
            if len(paths) >= max_paths or count >= MAX_MATCHES_PER_RULE:
                return paths

    return paths


def _line_number(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _context(text: str, start: int, end: int, radius: int = 180) -> str:
    left = max(0, start - radius)
    right = min(len(text), end + radius)
    return text[left:right].replace("\x00", " ")[:MAX_FIELD_TEXT]


# ---------------------------------------------------------------------------
# Path classification
# ---------------------------------------------------------------------------

def _lower_path(path: str) -> str:
    return path.replace("/", "\\").casefold()


def classify_path(path: str) -> Dict[str, Any]:
    """
    Classify a path into defensive, model-friendly filesystem properties.
    """
    normalized = _normalize_path(path)
    lowered = _lower_path(normalized)

    suffix = ""
    filename = lowered.rsplit("\\", 1)[-1]
    if "." in filename:
        suffix = "." + filename.rsplit(".", 1)[-1]

    is_unc = normalized.startswith("\\\\")
    is_mapped_drive = bool(re.match(r"^[A-Za-z]:\\", normalized))
    is_relative = not is_unc and not is_mapped_drive and not normalized.startswith("/")
    is_traversal = "..\\" in lowered or "../" in path or lowered.startswith("..")

    result: Dict[str, Any] = {
        "normalized": normalized,
        "is_unc": is_unc,
        "is_mapped_drive": is_mapped_drive,
        "is_relative": is_relative,
        "is_traversal": is_traversal,
        "is_system": any(marker in lowered for marker in SYSTEM_PATH_MARKERS),
        "is_user": any(marker in lowered for marker in USER_PATH_MARKERS),
        "is_startup": any(marker in lowered for marker in STARTUP_PATH_MARKERS),
        "is_download": any(marker in lowered for marker in DOWNLOAD_PATH_MARKERS),
        "is_temporary": any(marker in lowered for marker in TEMP_PATH_MARKERS),
        "is_executable": suffix in EXECUTABLE_EXTENSIONS,
        "is_script": suffix in SCRIPT_EXTENSIONS,
        "is_library": suffix in LIBRARY_EXTENSIONS,
        "is_document": suffix in DOCUMENT_EXTENSIONS,
        "is_configuration": suffix in CONFIGURATION_EXTENSIONS,
        "is_credential": filename in CREDENTIAL_FILENAMES,
        "is_log": suffix in LOG_EXTENSIONS,
        "is_backup": suffix in BACKUP_EXTENSIONS,
        "is_archive": suffix in ARCHIVE_EXTENSIONS,
        "is_lock": suffix in LOCK_EXTENSIONS,
        "extension": suffix,
        "filename": filename,
    }

    return result


def classify_paths(paths: Iterable[str]) -> Dict[str, List[str]]:
    """Return unique paths grouped by useful filesystem classifications."""
    groups: Dict[str, List[str]] = {
        "network": [],
        "system": [],
        "user": [],
        "startup": [],
        "download": [],
        "temporary": [],
        "executable": [],
        "script": [],
        "library": [],
        "document": [],
        "configuration": [],
        "credential": [],
        "log": [],
        "backup": [],
        "archive": [],
        "lock": [],
        "traversal": [],
        "suspicious": [],
    }

    seen: Dict[str, set] = {key: set() for key in groups}

    for path in paths:
        info = classify_path(path)
        normalized = info["normalized"]

        def add(group: str) -> None:
            key = normalized.casefold()
            if key not in seen[group] and len(groups[group]) < MAX_PATHS:
                seen[group].add(key)
                groups[group].append(normalized)

        if info["is_unc"] or info["is_system"] and "\\sysvol\\" in normalized.casefold():
            add("network")
        if info["is_system"]:
            add("system")
        if info["is_user"]:
            add("user")
        if info["is_startup"]:
            add("startup")
        if info["is_download"]:
            add("download")
        if info["is_temporary"]:
            add("temporary")
        if info["is_executable"]:
            add("executable")
        if info["is_script"]:
            add("script")
        if info["is_library"]:
            add("library")
        if info["is_document"]:
            add("document")
        if info["is_configuration"]:
            add("configuration")
        if info["is_credential"]:
            add("credential")
        if info["is_log"]:
            add("log")
        if info["is_backup"]:
            add("backup")
        if info["is_archive"]:
            add("archive")
        if info["is_lock"]:
            add("lock")
        if info["is_traversal"]:
            add("traversal")

        if (
            info["is_unc"]
            or info["is_startup"]
            or info["is_credential"]
            or info["is_traversal"]
            or info["is_executable"]
        ):
            add("suspicious")

    return groups


# ---------------------------------------------------------------------------
# Evidence creation
# ---------------------------------------------------------------------------

def _append_evidence(
    evidence: List[FilesystemEvidence],
    seen: set,
    item: FilesystemEvidence,
) -> None:
    if len(evidence) >= MAX_EVIDENCE_ITEMS:
        return

    key = (
        item.indicator,
        item.category,
        item.line_number,
        item.path,
        item.evidence[:256],
    )
    if key in seen:
        return

    seen.add(key)
    evidence.append(item)


def _append_record(
    records: List[FilesystemRecord],
    seen: set,
    record: FilesystemRecord,
) -> None:
    if len(records) >= MAX_FILE_OPERATIONS:
        return

    key = (
        record.operation,
        (record.path or "").casefold(),
        record.line_number,
        record.indicator,
    )
    if key in seen:
        return

    seen.add(key)
    records.append(record)


def _indicator_for_category(category: str) -> str:
    mapping = {
        "file_create": "create_file",
        "file_write": "write_file",
        "file_append": "append_file",
        "file_read": "read_file",
        "file_copy": "copy_file",
        "file_move": "move_file",
        "file_delete": "delete_file",
        "file_rename": "rename_file",
        "file_exists": "file_exists_check",
        "file_metadata": "file_metadata_query",
        "directory_create": "create_directory",
        "directory_delete": "delete_directory",
        "directory_enumeration": "enumerate_directory",
        "directory_change": "change_directory",
        "temporary_file": "temporary_file",
        "alternate_data_stream": "alternate_data_stream",
        "network_share": "network_share",
        "unc_path": "unc_path",
        "mapped_drive": "mapped_drive",
        "startup_directory": "startup_location",
        "system_directory": "system_path",
        "user_directory": "user_profile_path",
        "download_directory": "download_path",
        "hidden_file": "hidden_file",
        "file_attribute": "hidden_attribute",
        "archive_operation": "archive_operation",
        "executable_file": "executable_target",
        "script_file": "script_target",
        "library_file": "library_target",
        "document_file": "document_target",
        "configuration_file": "configuration_target",
        "credential_file": "credential_target",
        "log_file": "log_target",
        "backup_file": "backup_target",
        "lock_file": "lock_target",
        "staging": "file_staging",
        "cleanup": "file_cleanup",
        "destructive_file_operation": "recursive_delete",
        "filesystem_execution": "filesystem_execution",
        "path_discovery": "path_discovery",
    }
    return mapping.get(category, category)


def _category_for_indicator(indicator: str) -> str:
    mapping = {
        "create_file": "file_create",
        "write_file": "file_write",
        "append_file": "file_append",
        "read_file": "file_read",
        "copy_file": "file_copy",
        "move_file": "file_move",
        "delete_file": "file_delete",
        "rename_file": "file_rename",
        "file_exists_check": "file_exists",
        "file_metadata_query": "file_metadata",
        "create_directory": "directory_create",
        "delete_directory": "directory_delete",
        "enumerate_directory": "directory_enumeration",
        "change_directory": "directory_change",
        "temporary_file": "temporary_file",
        "alternate_data_stream": "alternate_data_stream",
        "unc_path": "unc_path",
        "network_share": "network_share",
        "mapped_drive": "mapped_drive",
        "startup_location": "startup_directory",
        "system_path": "system_directory",
        "user_profile_path": "user_directory",
        "download_path": "download_directory",
        "hidden_file": "hidden_file",
        "hidden_attribute": "file_attribute",
        "archive_creation": "archive_operation",
        "archive_extraction": "archive_operation",
        "executable_target": "executable_file",
        "script_target": "script_file",
        "library_target": "library_file",
        "document_target": "document_file",
        "configuration_target": "configuration_file",
        "credential_target": "credential_file",
        "log_target": "log_file",
        "backup_target": "backup_file",
        "lock_target": "lock_file",
        "file_staging": "staging",
        "file_cleanup": "cleanup",
        "recursive_delete": "destructive_file_operation",
        "filesystem_execution": "filesystem_execution",
        "path_traversal": "path_discovery",
    }
    return mapping.get(indicator, "path_discovery")


# ---------------------------------------------------------------------------
# API and command semantic interpretation
# ---------------------------------------------------------------------------

OPERATION_ALIASES: Dict[str, Tuple[str, str]] = {
    "create": ("file_create", "create_file"),
    "createfile": ("file_create", "create_file"),
    "write": ("file_write", "write_file"),
    "writefile": ("file_write", "write_file"),
    "append": ("file_append", "append_file"),
    "read": ("file_read", "read_file"),
    "readfile": ("file_read", "read_file"),
    "copy": ("file_copy", "copy_file"),
    "copyfile": ("file_copy", "copy_file"),
    "move": ("file_move", "move_file"),
    "movefile": ("file_move", "move_file"),
    "delete": ("file_delete", "delete_file"),
    "deletefile": ("file_delete", "delete_file"),
    "remove": ("file_delete", "delete_file"),
    "rename": ("file_rename", "rename_file"),
    "exists": ("file_exists", "file_exists_check"),
    "stat": ("file_metadata", "file_metadata_query"),
    "metadata": ("file_metadata", "file_metadata_query"),
    "mkdir": ("directory_create", "create_directory"),
    "createdirectory": ("directory_create", "create_directory"),
    "rmdir": ("directory_delete", "delete_directory"),
    "removedirectory": ("directory_delete", "delete_directory"),
    "list": ("directory_enumeration", "enumerate_directory"),
    "enumerate": ("directory_enumeration", "enumerate_directory"),
    "readdir": ("directory_enumeration", "enumerate_directory"),
    "chdir": ("directory_change", "change_directory"),
    "temp": ("temporary_file", "temporary_file"),
    "archive": ("archive_operation", "archive_creation"),
    "extract": ("archive_operation", "archive_extraction"),
}


def normalize_operation(operation: Any) -> Optional[Tuple[str, str]]:
    if operation is None:
        return None

    value = str(operation).strip().lower()
    value = re.sub(r"[^a-z0-9]+", "", value)

    if value in OPERATION_ALIASES:
        return OPERATION_ALIASES[value]

    return None


def extract_operation_records(
    source: Any,
    max_records: int = MAX_FILE_OPERATIONS,
) -> List[FilesystemRecord]:
    """
    Normalize filesystem records from structured static-analysis data.

    This function does not perform any operation represented by the records.
    """
    records: List[FilesystemRecord] = []
    seen = set()

    def consume(value: Any, depth: int = 0) -> None:
        if depth > MAX_NESTING_DEPTH or len(records) >= max_records:
            return

        if isinstance(value, FilesystemRecord):
            _append_record(records, seen, value)
            return

        if isinstance(value, Mapping):
            operation_value = (
                value.get("operation")
                or value.get("action")
                or value.get("op")
                or value.get("filesystem_operation")
                or value.get("behavior")
            )

            normalized = normalize_operation(operation_value)
            if normalized:
                category, indicator = normalized
                path = (
                    value.get("path")
                    or value.get("target")
                    or value.get("filename")
                    or value.get("file")
                    or value.get("source_path")
                    or value.get("destination_path")
                )

                record = FilesystemRecord(
                    operation=operation_value,
                    path=_normalize_path(str(path)) if path else None,
                    source=str(value.get("source", "structured")),
                    category=category,
                    indicator=indicator,
                    line_number=_coerce_int(
                        value.get("line_number") or value.get("line")
                    ),
                    recursive=bool(
                        value.get("recursive")
                        or value.get("recurse")
                    ),
                    target_type=(
                        str(value["target_type"])
                        if value.get("target_type") is not None
                        else None
                    ),
                    severity=_normalize_severity(
                        value.get("severity"),
                        "medium",
                    ),
                    confidence=_normalize_confidence(
                        value.get("confidence"),
                        0.85,
                    ),
                    evidence=(
                        str(value.get("evidence"))[:MAX_FIELD_TEXT]
                        if value.get("evidence") is not None
                        else None
                    ),
                )
                _append_record(records, seen, record)

            for key, nested in value.items():
                if key in {
                    "operation",
                    "action",
                    "op",
                    "filesystem_operation",
                    "behavior",
                    "path",
                    "target",
                    "filename",
                    "file",
                    "source_path",
                    "destination_path",
                }:
                    continue
                consume(nested, depth + 1)

            return

        if isinstance(value, (list, tuple, set, frozenset)):
            for item in value:
                consume(item, depth + 1)
                if len(records) >= max_records:
                    break

    consume(source)
    return records


def _coerce_int(value: Any) -> Optional[int]:
    if value is None:
        return None
    try:
        result = int(value)
        return result if result >= 1 else None
    except (TypeError, ValueError):
        return None


# ---------------------------------------------------------------------------
# Path-derived evidence
# ---------------------------------------------------------------------------

def _derive_path_evidence(
    text: str,
    paths: Sequence[str],
    evidence: List[FilesystemEvidence],
    evidence_seen: set,
    records: List[FilesystemRecord],
    record_seen: set,
) -> None:
    for path in paths:
        info = classify_path(path)

        # Locate a representative occurrence for useful line/context data.
        position = text.casefold().find(path.casefold())
        line_number = _line_number(text, position) if position >= 0 else None
        context = (
            _context(text, position, position + len(path))
            if position >= 0
            else path
        )

        path_properties = (
            ("unc_path", "unc_path", "network_share", "Network/UNC path reference."),
            ("is_startup", "startup_location", "startup_directory", "Startup/autostart directory reference."),
            ("is_system", "system_path", "system_directory", "System-directory reference."),
            ("is_user", "user_profile_path", "user_directory", "User-profile directory reference."),
            ("is_download", "download_path", "download_directory", "Download/staging directory reference."),
            ("is_temporary", "temporary_file", "temporary_file", "Temporary-directory/file reference."),
            ("is_executable", "executable_target", "executable_file", "Executable filesystem target."),
            ("is_script", "script_target", "script_file", "Script filesystem target."),
            ("is_library", "library_target", "library_file", "Library filesystem target."),
            ("is_document", "document_target", "document_file", "Document filesystem target."),
            ("is_configuration", "configuration_target", "configuration_file", "Configuration-file target."),
            ("is_credential", "credential_target", "credential_file", "Potential credential-related file target."),
            ("is_log", "log_target", "log_file", "Log-file target."),
            ("is_backup", "backup_target", "backup_file", "Backup/temporary file target."),
            ("is_lock", "lock_target", "lock_file", "Lock-file target."),
            ("is_traversal", "path_traversal", "path_discovery", "Path traversal sequence."),
        )

        for property_name, indicator, category, description in path_properties:
            if not info.get(property_name):
                continue

            severity = "medium"
            confidence = 0.86

            if indicator in {
                "startup_location",
                "credential_target",
                "path_traversal",
                "executable_target",
            }:
                severity = "high"

            if indicator == "path_traversal":
                confidence = 0.80

            item = FilesystemEvidence(
                category=category,
                indicator=indicator,
                evidence=description,
                source="path_classification",
                line_number=line_number,
                path=path,
                operation=None,
                severity=severity,
                confidence=confidence,
                context=context,
            )
            _append_evidence(evidence, evidence_seen, item)

        # Infer a target operation from nearby command/API context.
        if position >= 0:
            nearby_start = max(0, position - 300)
            nearby_end = min(len(text), position + len(path) + 300)
            nearby = text[nearby_start:nearby_end]

            inferred = _infer_operation_from_context(nearby)
            if inferred:
                category, indicator, operation, severity, confidence = inferred
                record = FilesystemRecord(
                    operation=operation,
                    path=path,
                    source="context_inference",
                    category=category,
                    indicator=indicator,
                    line_number=line_number,
                    recursive=bool(
                        re.search(
                            r"(?:-recurse|-recursive|/s\b|-rf\b|-r\b)",
                            nearby,
                            re.IGNORECASE,
                        )
                    ),
                    target_type=_target_type_from_path(info),
                    severity=severity,
                    confidence=confidence,
                    evidence=nearby[:MAX_FIELD_TEXT],
                )
                _append_record(records, record_seen, record)


def _target_type_from_path(info: Mapping[str, Any]) -> Optional[str]:
    if info.get("is_executable"):
        return "executable"
    if info.get("is_script"):
        return "script"
    if info.get("is_library"):
        return "library"
    if info.get("is_document"):
        return "document"
    if info.get("is_configuration"):
        return "configuration"
    if info.get("is_credential"):
        return "credential"
    if info.get("is_archive"):
        return "archive"
    return None


def _infer_operation_from_context(
    context: str,
) -> Optional[Tuple[str, str, str, str, float]]:
    lowered = context.casefold()

    checks = (
        (
            r"\b(?:deletefile|remove-item|del|erase|rm|unlink|remove)\b",
            "file_delete",
            "delete_file",
            "delete",
            "high",
            0.84,
        ),
        (
            r"\b(?:copyfile|copy-item|copy)\b",
            "file_copy",
            "copy_file",
            "medium",
            0.84,
        ),
        (
            r"\b(?:movefile|move-item|move|mv|rename|ren)\b",
            "file_move",
            "move_file",
            "medium",
            0.82,
        ),
        (
            r"\b(?:writefile|writealltext|writeallbytes|fwrite|fprintf|echo)\b",
            "file_write",
            "write_file",
            "medium",
            0.80,
        ),
        (
            r"\b(?:readfile|readalltext|readallbytes|fread|cat|type|more)\b",
            "file_read",
            "read_file",
            "low",
            0.80,
        ),
        (
            r"\b(?:mkdir|md|new-item)\b",
            "directory_create",
            "create_directory",
            "medium",
            0.82,
        ),
        (
            r"\b(?:rmdir|rd|remove-directory)\b",
            "directory_delete",
            "delete_directory",
            "high",
            0.84,
        ),
    )

    for expression, category, indicator, operation, severity, confidence in checks:
        if re.search(expression, lowered, re.IGNORECASE):
            return category, indicator, operation, severity, confidence

    return None


# ---------------------------------------------------------------------------
# Pattern extraction
# ---------------------------------------------------------------------------

def _extract_pattern_evidence(
    text: str,
    evidence: List[FilesystemEvidence],
    evidence_seen: set,
    records: List[FilesystemRecord],
    record_seen: set,
) -> None:
    for rule, regex in COMPILED_PATTERNS:
        matches = 0

        for match in regex.finditer(text):
            raw = match.group(0).strip()
            if not raw:
                continue

            line_number = _line_number(text, match.start())
            context = _context(text, match.start(), match.end())

            indicator = _indicator_for_category(rule.category)

            severity = rule.severity
            confidence = rule.confidence

            if rule.name == "alternate_data_stream":
                # Reduce false positives from ordinary colon-containing tokens.
                if re.match(r"^[A-Za-z]:[\\/]", raw):
                    continue

            item = FilesystemEvidence(
                category=rule.category,
                indicator=indicator,
                evidence=raw,
                source="pattern",
                line_number=line_number,
                operation=None,
                severity=severity,
                confidence=confidence,
                context=context,
            )
            _append_evidence(evidence, evidence_seen, item)

            operation = _operation_from_category(rule.category)
            if operation:
                path = _find_nearby_path(text, match.start(), match.end())
                record = FilesystemRecord(
                    operation=operation,
                    path=path,
                    source="pattern",
                    category=rule.category,
                    indicator=indicator,
                    line_number=line_number,
                    recursive=bool(
                        re.search(
                            r"(?:-recurse|-recursive|/s\b|-rf\b|-r\b)",
                            context,
                            re.IGNORECASE,
                        )
                    ),
                    target_type=(
                        _target_type_from_path(classify_path(path))
                        if path
                        else None
                    ),
                    severity=severity,
                    confidence=confidence,
                    evidence=raw,
                )
                _append_record(records, record_seen, record)

            matches += 1
            if matches >= MAX_MATCHES_PER_RULE:
                break


def _operation_from_category(category: str) -> Optional[str]:
    mapping = {
        "file_create": "create",
        "file_write": "write",
        "file_append": "append",
        "file_read": "read",
        "file_copy": "copy",
        "file_move": "move",
        "file_delete": "delete",
        "file_rename": "rename",
        "file_exists": "exists",
        "file_metadata": "metadata",
        "directory_create": "mkdir",
        "directory_delete": "rmdir",
        "directory_enumeration": "enumerate",
        "directory_change": "chdir",
        "temporary_file": "temp",
        "archive_operation": "archive",
        "destructive_file_operation": "delete",
    }
    return mapping.get(category)


def _find_nearby_path(
    text: str,
    start: int,
    end: int,
    radius: int = 500,
) -> Optional[str]:
    left = max(0, start - radius)
    right = min(len(text), end + radius)
    context = text[left:right]

    paths = extract_paths(context, max_paths=20)
    if not paths:
        return None

    # Prefer a path closest to the matched operation.
    relative_position = start - left
    best_path = None
    best_distance = math.inf

    for path in paths:
        local_position = context.casefold().find(path.casefold())
        if local_position < 0:
            continue
        distance = abs(local_position - relative_position)
        if distance < best_distance:
            best_distance = distance
            best_path = path

    return best_path


# ---------------------------------------------------------------------------
# Special semantic indicators
# ---------------------------------------------------------------------------

def _derive_special_indicators(
    text: str,
    paths: Sequence[str],
    evidence: List[FilesystemEvidence],
    evidence_seen: set,
) -> None:
    lowered = text.casefold()

    special_rules = (
        (
            "file_staging",
            "staging",
            r"(?:\bstage\b|\bstaging\b|\bdrop(?:per)?\b|\bpayload\b).{0,160}(?:write|copy|save|create|extract)",
            "Potential file staging before another action.",
            "high",
            0.70,
        ),
        (
            "file_cleanup",
            "cleanup",
            r"(?:\bcleanup\b|\bclean[- ]up\b|\bdelete\b|\bremove\b).{0,160}(?:temp|temporary|artifact|trace|log|file)",
            "Potential filesystem cleanup after an operation.",
            "high",
            0.72,
        ),
        (
            "mass_file_operation",
            "destructive_file_operation",
            r"(?:\b(?:delete|remove|wipe|erase|purge)\b).{0,100}(?:\b(?:all|recursive|recursively|many|files|directories)\b)",
            "Potential broad filesystem modification or deletion.",
            "high",
            0.72,
        ),
        (
            "filesystem_execution",
            "filesystem_execution",
            r"(?:\b(?:execute|run|launch|start|invoke)\b).{0,100}(?:[A-Za-z]:[\\/]|\\\\|/tmp/|/home/|\.exe\b|\.dll\b|\.ps1\b|\.vbs\b|\.js\b)",
            "Execution language associated with a filesystem-resident target.",
            "high",
            0.72,
        ),
    )

    for indicator, category, expression, description, severity, confidence in special_rules:
        match = re.search(expression, lowered, re.IGNORECASE | re.DOTALL)
        if not match:
            continue

        item = FilesystemEvidence(
            category=category,
            indicator=indicator,
            evidence=match.group(0)[:MAX_FIELD_TEXT],
            source="semantic_pattern",
            line_number=_line_number(text, match.start()),
            severity=severity,
            confidence=confidence,
            context=_context(text, match.start(), match.end()),
        )
        _append_evidence(evidence, evidence_seen, item)

    # File extension-specific targeting.
    for path in paths:
        info = classify_path(path)
        target_pairs = (
            ("executable_target", "executable_file", info["is_executable"]),
            ("script_target", "script_file", info["is_script"]),
            ("library_target", "library_file", info["is_library"]),
            ("credential_target", "credential_file", info["is_credential"]),
        )

        for indicator, category, present in target_pairs:
            if not present:
                continue

            position = lowered.find(path.casefold())
            item = FilesystemEvidence(
                category=category,
                indicator=indicator,
                evidence=path,
                source="path_semantics",
                line_number=(
                    _line_number(text, position) if position >= 0 else None
                ),
                path=path,
                severity="high" if indicator != "script_target" else "medium",
                confidence=0.90,
            )
            _append_evidence(evidence, evidence_seen, item)


# ---------------------------------------------------------------------------
# Combination logic
# ---------------------------------------------------------------------------

COMBINATION_DEFINITIONS: Tuple[
    Tuple[str, Tuple[str, ...], str, str],
    ...
] = (
    (
        "stage_then_execute",
        ("file_staging", "filesystem_execution"),
        "Filesystem staging followed by execution-related behavior.",
        "high",
    ),
    (
        "download_or_temp_then_execute",
        ("download_path", "filesystem_execution"),
        "A downloaded or temporary filesystem location is associated with execution.",
        "high",
    ),
    (
        "startup_file_placement",
        ("startup_location", "write_file"),
        "A startup/autostart location is associated with file writing.",
        "critical",
    ),
    (
        "credential_file_access",
        ("credential_target", "read_file"),
        "A credential-related file is associated with a read operation.",
        "high",
    ),
    (
        "executable_write_then_execute",
        ("executable_target", "write_file", "filesystem_execution"),
        "An executable target is written and associated with subsequent execution.",
        "critical",
    ),
    (
        "recursive_delete_cleanup",
        ("recursive_delete",),
        "Recursive or forced filesystem deletion was detected.",
        "critical",
    ),
    (
        "network_share_file_operation",
        ("network_share", "write_file"),
        "A network/UNC location is associated with file writing.",
        "high",
    ),
    (
        "hidden_file_write",
        ("hidden_file", "write_file"),
        "A hidden-file attribute or hidden target is associated with writing.",
        "high",
    ),
    (
        "archive_extract_to_temp",
        ("archive_extraction", "temporary_file"),
        "Archive extraction is associated with a temporary/staging location.",
        "medium",
    ),
    (
        "copy_executable",
        ("copy_file", "executable_target"),
        "An executable file is associated with a copy operation.",
        "high",
    ),
)


def _derive_combinations(
    indicators: set,
    evidence: Sequence[FilesystemEvidence],
    records: Sequence[FilesystemRecord],
) -> List[FilesystemCombination]:
    combinations: List[FilesystemCombination] = []

    for name, required, explanation, severity in COMBINATION_DEFINITIONS:
        present = all(item in indicators for item in required)
        combinations.append(
            FilesystemCombination(
                name=name,
                present=present,
                required_indicators=required,
                explanation=explanation,
                severity=severity,
            )
        )

    # Structured record-aware refinements.
    operations = {record.operation for record in records}
    executable_records = [
        record
        for record in records
        if record.target_type == "executable"
    ]

    if (
        "write" in operations
        and executable_records
        and "filesystem_execution" in indicators
    ):
        name = "write_executable_then_execute"
        if not any(item.name == name for item in combinations):
            combinations.append(
                FilesystemCombination(
                    name=name,
                    present=True,
                    required_indicators=(
                        "write_file",
                        "executable_target",
                        "filesystem_execution",
                    ),
                    explanation=(
                        "Structured evidence links an executable target to "
                        "file writing and execution behavior."
                    ),
                    severity="critical",
                )
            )

    return combinations


# ---------------------------------------------------------------------------
# Feature-vector construction
# ---------------------------------------------------------------------------

def filesystem_feature_names() -> List[str]:
    """Return deterministic feature names for model training/inference."""
    names = [
        "filesystem_source_size",
        "filesystem_path_count",
        "filesystem_record_count",
        "filesystem_evidence_count",
        "filesystem_indicator_count",
        "filesystem_category_count",
        "filesystem_combination_count",
        "filesystem_present_combination_count",
        "filesystem_executable_path_count",
        "filesystem_script_path_count",
        "filesystem_network_path_count",
        "filesystem_system_path_count",
        "filesystem_user_path_count",
        "filesystem_temporary_path_count",
        "filesystem_suspicious_path_count",
        "filesystem_high_severity_count",
        "filesystem_critical_severity_count",
        "filesystem_max_severity",
        "filesystem_signal_score",
        "filesystem_unique_extension_count",
        "filesystem_average_path_length",
        "filesystem_long_path_count",
        "filesystem_relative_path_count",
        "filesystem_traversal_path_count",
    ]

    for category in FILESYSTEM_CATEGORIES:
        names.append(f"filesystem_category_{category}_present")
        names.append(f"filesystem_category_{category}_count")

    for indicator in INDICATOR_NAMES:
        names.append(f"filesystem_indicator_{indicator}_present")
        names.append(f"filesystem_indicator_{indicator}_count")

    for name, _, _, _ in COMBINATION_DEFINITIONS:
        names.append(f"filesystem_combination_{name}")

    return names


def build_feature_schema() -> Dict[str, Any]:
    """Build a JSON-serializable feature schema."""
    return {
        "name": "pharos.filesystem_behavior",
        "version": "1.0",
        "description": (
            "Static filesystem-behavior features derived from document, "
            "script, VBA, and other analysis evidence."
        ),
        "static_only": True,
        "feature_names": filesystem_feature_names(),
        "feature_count": len(filesystem_feature_names()),
        "categories": list(FILESYSTEM_CATEGORIES),
        "indicators": list(INDICATOR_NAMES),
        "combinations": [item[0] for item in COMBINATION_DEFINITIONS],
    }


def _build_feature_vector(
    analysis: FilesystemAnalysis,
) -> Dict[str, float]:
    evidence = analysis.evidence
    records = analysis.records

    indicator_counts: Dict[str, int] = {
        name: 0 for name in INDICATOR_NAMES
    }
    category_counts: Dict[str, int] = {
        name: 0 for name in FILESYSTEM_CATEGORIES
    }

    for item in evidence:
        if item.indicator in indicator_counts:
            indicator_counts[item.indicator] += 1
        if item.category in category_counts:
            category_counts[item.category] += 1

    high_count = sum(
        1 for item in evidence
        if item.severity == "high"
    )
    critical_count = sum(
        1 for item in evidence
        if item.severity == "critical"
    )

    present_combinations = [
        item for item in analysis.combinations if item.present
    ]

    extensions = {
        classify_path(path)["extension"]
        for path in analysis.paths
        if classify_path(path)["extension"]
    }

    average_path_length = (
        sum(len(path) for path in analysis.paths) / len(analysis.paths)
        if analysis.paths
        else 0.0
    )

    relative_path_count = sum(
        1
        for path in analysis.paths
        if classify_path(path)["is_relative"]
    )

    traversal_count = sum(
        1
        for path in analysis.paths
        if classify_path(path)["is_traversal"]
    )

    score = 0.0
    for item in evidence:
        score += (
            SEVERITY_WEIGHT.get(item.severity, 1.0)
            * _normalize_confidence(item.confidence)
        )

    for combination in present_combinations:
        score += SEVERITY_WEIGHT.get(combination.severity, 1.0) * 2.0

    # Keep the score bounded so it remains stable as evidence volume grows.
    score = _clamp(score, 0.0, 100.0)

    feature_vector: Dict[str, float] = {
        "filesystem_source_size": float(analysis.source_size),
        "filesystem_path_count": float(len(analysis.paths)),
        "filesystem_record_count": float(len(records)),
        "filesystem_evidence_count": float(len(evidence)),
        "filesystem_indicator_count": float(len(analysis.indicators)),
        "filesystem_category_count": float(len(analysis.categories)),
        "filesystem_combination_count": float(len(analysis.combinations)),
        "filesystem_present_combination_count": float(
            len(present_combinations)
        ),
        "filesystem_executable_path_count": float(
            len(analysis.executable_paths)
        ),
        "filesystem_script_path_count": float(
            len(analysis.script_paths)
        ),
        "filesystem_network_path_count": float(
            len(analysis.network_paths)
        ),
        "filesystem_system_path_count": float(
            len(analysis.system_paths)
        ),
        "filesystem_user_path_count": float(
            len(analysis.user_paths)
        ),
        "filesystem_temporary_path_count": float(
            len(analysis.temporary_paths)
        ),
        "filesystem_suspicious_path_count": float(
            len(analysis.suspicious_paths)
        ),
        "filesystem_high_severity_count": float(high_count),
        "filesystem_critical_severity_count": float(critical_count),
        "filesystem_max_severity": float(
            _severity_rank(
                _max_severity(item.severity for item in evidence)
                if evidence
                else "low"
            )
        ),
        "filesystem_signal_score": float(score),
        "filesystem_unique_extension_count": float(len(extensions)),
        "filesystem_average_path_length": float(average_path_length),
        "filesystem_long_path_count": float(
            sum(1 for path in analysis.paths if len(path) > 260)
        ),
        "filesystem_relative_path_count": float(relative_path_count),
        "filesystem_traversal_path_count": float(traversal_count),
    }

    for category in FILESYSTEM_CATEGORIES:
        count = category_counts[category]
        feature_vector[f"filesystem_category_{category}_present"] = (
            1.0 if count else 0.0
        )
        feature_vector[f"filesystem_category_{category}_count"] = float(count)

    for indicator in INDICATOR_NAMES:
        count = indicator_counts[indicator]
        feature_vector[f"filesystem_indicator_{indicator}_present"] = (
            1.0 if count else 0.0
        )
        feature_vector[f"filesystem_indicator_{indicator}_count"] = float(count)

    for name, _, _, _ in COMBINATION_DEFINITIONS:
        feature_vector[f"filesystem_combination_{name}"] = float(
            any(
                combination.name == name and combination.present
                for combination in analysis.combinations
            )
        )

    return feature_vector


def vectorize_features(
    analysis: FilesystemAnalysis,
    feature_names: Optional[Sequence[str]] = None,
) -> List[float]:
    """
    Convert an analysis to an ordered numeric feature vector.

    Missing feature names are represented as zero, allowing callers to use a
    persisted training schema safely.
    """
    vector = analysis.feature_vector or _build_feature_vector(analysis)
    names = list(feature_names) if feature_names is not None else filesystem_feature_names()
    return [float(vector.get(name, 0.0)) for name in names]


# ---------------------------------------------------------------------------
# Main analysis
# ---------------------------------------------------------------------------

def analyze_filesystem_behavior(
    source: Any,
    *,
    include_paths: bool = True,
    include_records: bool = True,
    max_evidence: int = MAX_EVIDENCE_ITEMS,
    max_paths: int = MAX_PATHS,
) -> FilesystemAnalysis:
    """
    Analyze static filesystem behavior.

    Args:
        source:
            Raw text/bytes or structured static-analysis data.
        include_paths:
            Whether to retain extracted paths.
        include_records:
            Whether to infer normalized filesystem operation records.
        max_evidence:
            Upper bound on retained evidence.
        max_paths:
            Upper bound on retained paths.

    Returns:
        FilesystemAnalysis with evidence, records, classifications,
        combinations, and ML-ready features.
    """
    text, source_size, source_kind = _read_source(source)
    source_hash = _sha256_text(text)

    evidence: List[FilesystemEvidence] = []
    evidence_seen = set()

    records: List[FilesystemRecord] = []
    record_seen = set()

    # Structured operation records are useful when previous pipeline stages
    # already normalized behavior.
    if include_records:
        for record in extract_operation_records(source):
            _append_record(records, record_seen, record)

            if record.indicator:
                item = FilesystemEvidence(
                    category=record.category or _category_for_indicator(
                        record.indicator
                    ),
                    indicator=record.indicator,
                    evidence=record.evidence or record.operation,
                    source=record.source,
                    line_number=record.line_number,
                    path=record.path,
                    operation=record.operation,
                    severity=record.severity,
                    confidence=record.confidence,
                )
                _append_evidence(evidence, evidence_seen, item)

    _extract_pattern_evidence(
        text,
        evidence,
        evidence_seen,
        records,
        record_seen,
    )

    paths = extract_paths(text, max_paths=max_paths) if include_paths else []

    if include_paths:
        _derive_path_evidence(
            text,
            paths,
            evidence,
            evidence_seen,
            records,
            record_seen,
        )

    _derive_special_indicators(
        text,
        paths,
        evidence,
        evidence_seen,
    )

    # Enforce the caller's lower evidence bound after all extraction passes.
    if len(evidence) > max_evidence:
        evidence = evidence[:max_evidence]

    groups = classify_paths(paths)

    indicator_set = {
        item.indicator
        for item in evidence
        if item.indicator
    }
    category_set = {
        item.category
        for item in evidence
        if item.category
    }

    # Derive explicit semantic indicators from path classifications.
    if groups["network"]:
        indicator_set.update({"network_share", "unc_path"})
        category_set.update({"network_share", "unc_path"})

    if groups["startup"]:
        indicator_set.add("startup_location")
        category_set.add("startup_directory")

    if groups["temporary"]:
        indicator_set.add("temporary_file")
        category_set.add("temporary_file")

    if groups["executable"]:
        indicator_set.add("executable_target")
        category_set.add("executable_file")

    if groups["script"]:
        indicator_set.add("script_target")
        category_set.add("script_file")

    if groups["credential"]:
        indicator_set.add("credential_target")
        category_set.add("credential_file")

    combinations = _derive_combinations(
        indicator_set,
        evidence,
        records,
    )

    # Stable ordering.
    indicators = sorted(
        indicator_set,
        key=lambda item: (
            INDICATOR_NAMES.index(item)
            if item in INDICATOR_NAMES
            else len(INDICATOR_NAMES),
            item,
        ),
    )

    categories = sorted(
        category_set,
        key=lambda item: (
            FILESYSTEM_CATEGORIES.index(item)
            if item in FILESYSTEM_CATEGORIES
            else len(FILESYSTEM_CATEGORIES),
            item,
        ),
    )

    analysis = FilesystemAnalysis(
        source_hash=source_hash,
        source_size=source_size,
        evidence=evidence,
        records=records if include_records else [],
        indicators=indicators,
        categories=categories,
        combinations=combinations,
        paths=paths,
        executable_paths=groups["executable"],
        script_paths=groups["script"],
        network_paths=groups["network"],
        system_paths=groups["system"],
        user_paths=groups["user"],
        temporary_paths=groups["temporary"],
        suspicious_paths=groups["suspicious"],
        metadata={
            "module": "pharos.extraction.behavior.filesystem",
            "version": "1.0",
            "static_only": True,
            "source_kind": source_kind,
            "limits": {
                "max_source_size": MAX_SOURCE_SIZE,
                "max_text_chars": MAX_TEXT_CHARS,
                "max_evidence_items": max_evidence,
                "max_paths": max_paths,
            },
            "evidence_truncated": len(evidence) >= max_evidence,
            "paths_truncated": len(paths) >= max_paths,
        },
    )

    analysis.feature_vector = _build_feature_vector(analysis)
    return analysis


# ---------------------------------------------------------------------------
# Public aliases / convenience APIs
# ---------------------------------------------------------------------------

def analyze(source: Any, **kwargs: Any) -> FilesystemAnalysis:
    """Alias for :func:`analyze_filesystem_behavior`."""
    return analyze_filesystem_behavior(source, **kwargs)


def parse_filesystem_behavior(
    source: Any,
    **kwargs: Any,
) -> FilesystemAnalysis:
    """Compatibility alias for callers using parser-style terminology."""
    return analyze_filesystem_behavior(source, **kwargs)


def extract_filesystem_features(
    source: Any,
    **kwargs: Any,
) -> Dict[str, float]:
    """Return the complete filesystem feature mapping."""
    return analyze_filesystem_behavior(source, **kwargs).feature_vector


def extract_feature_vector(
    source: Any,
    feature_names: Optional[Sequence[str]] = None,
    **kwargs: Any,
) -> List[float]:
    """Return an ordered filesystem feature vector."""
    analysis = analyze_filesystem_behavior(source, **kwargs)
    return vectorize_features(analysis, feature_names)


def extract_filesystem_feature_vector(
    source: Any,
    feature_names: Optional[Sequence[str]] = None,
    **kwargs: Any,
) -> List[float]:
    """Explicit alias for ML integration."""
    return extract_feature_vector(
        source,
        feature_names=feature_names,
        **kwargs,
    )


# ---------------------------------------------------------------------------
# Query helpers
# ---------------------------------------------------------------------------

def has_indicator(
    analysis: FilesystemAnalysis,
    indicator: str,
) -> bool:
    """Return whether an indicator is present."""
    return indicator in set(analysis.indicators)


def has_category(
    analysis: FilesystemAnalysis,
    category: str,
) -> bool:
    """Return whether a filesystem category is present."""
    return category in set(analysis.categories)


def indicator_count(
    analysis: FilesystemAnalysis,
    indicator: str,
) -> int:
    """Return the evidence count for an indicator."""
    return sum(
        1 for item in analysis.evidence
        if item.indicator == indicator
    )


def category_count(
    analysis: FilesystemAnalysis,
    category: str,
) -> int:
    """Return the evidence count for a category."""
    return sum(
        1 for item in analysis.evidence
        if item.category == category
    )


def evidence_by_category(
    analysis: FilesystemAnalysis,
    category: str,
) -> List[FilesystemEvidence]:
    """Return evidence associated with one category."""
    return [
        item for item in analysis.evidence
        if item.category == category
    ]


def evidence_by_indicator(
    analysis: FilesystemAnalysis,
    indicator: str,
) -> List[FilesystemEvidence]:
    """Return evidence associated with one indicator."""
    return [
        item for item in analysis.evidence
        if item.indicator == indicator
    ]


def high_risk_evidence(
    analysis: FilesystemAnalysis,
) -> List[FilesystemEvidence]:
    """Return high/critical filesystem evidence."""
    return [
        item for item in analysis.evidence
        if item.severity in {"high", "critical"}
    ]


def present_combinations(
    analysis: FilesystemAnalysis,
) -> List[FilesystemCombination]:
    """Return only combinations whose conditions were satisfied."""
    return [
        item for item in analysis.combinations
        if item.present
    ]


def highest_severity(
    analysis: FilesystemAnalysis,
) -> str:
    """Return the highest evidence severity in an analysis."""
    return _max_severity(
        item.severity for item in analysis.evidence
    ) if analysis.evidence else "low"


def path_info(path: str) -> Dict[str, Any]:
    """Public convenience wrapper around path classification."""
    return classify_path(path)


def extract_filesystem_paths(
    source: Any,
    max_paths: int = MAX_PATHS,
) -> List[str]:
    """Extract filesystem paths without performing behavior analysis."""
    text, _, _ = _read_source(source)
    return extract_paths(text, max_paths=max_paths)


# ---------------------------------------------------------------------------
# Serialization / summaries
# ---------------------------------------------------------------------------

def analysis_to_dict(
    analysis: FilesystemAnalysis,
) -> Dict[str, Any]:
    """Convert an analysis to a JSON-compatible dictionary."""
    return {
        "source_hash": analysis.source_hash,
        "source_size": analysis.source_size,
        "evidence": [asdict(item) for item in analysis.evidence],
        "records": [asdict(item) for item in analysis.records],
        "indicators": list(analysis.indicators),
        "categories": list(analysis.categories),
        "combinations": [asdict(item) for item in analysis.combinations],
        "paths": list(analysis.paths),
        "executable_paths": list(analysis.executable_paths),
        "script_paths": list(analysis.script_paths),
        "network_paths": list(analysis.network_paths),
        "system_paths": list(analysis.system_paths),
        "user_paths": list(analysis.user_paths),
        "temporary_paths": list(analysis.temporary_paths),
        "suspicious_paths": list(analysis.suspicious_paths),
        "feature_vector": dict(analysis.feature_vector),
        "metadata": dict(analysis.metadata),
    }


def summarize_filesystem_behavior(
    analysis: FilesystemAnalysis,
) -> Dict[str, Any]:
    """Return a compact summary suitable for reports and API responses."""
    present = present_combinations(analysis)

    return {
        "source_hash": analysis.source_hash,
        "source_size": analysis.source_size,
        "evidence_count": len(analysis.evidence),
        "record_count": len(analysis.records),
        "path_count": len(analysis.paths),
        "indicator_count": len(analysis.indicators),
        "category_count": len(analysis.categories),
        "combination_count": len(present),
        "highest_severity": highest_severity(analysis),
        "signal_score": analysis.feature_vector.get(
            "filesystem_signal_score",
            0.0,
        ),
        "high_risk_evidence_count": len(high_risk_evidence(analysis)),
        "executable_path_count": len(analysis.executable_paths),
        "script_path_count": len(analysis.script_paths),
        "network_path_count": len(analysis.network_paths),
        "startup_path_count": sum(
            1
            for item in analysis.evidence
            if item.indicator == "startup_location"
        ),
        "credential_target_count": sum(
            1
            for item in analysis.evidence
            if item.indicator == "credential_target"
        ),
        "destructive_operation_count": sum(
            1
            for item in analysis.evidence
            if item.indicator == "recursive_delete"
            or item.category == "destructive_file_operation"
        ),
        "present_combinations": [
            item.name for item in present
        ],
    }


# ---------------------------------------------------------------------------
# Iterators
# ---------------------------------------------------------------------------

def iter_evidence(
    analysis: FilesystemAnalysis,
) -> Iterator[FilesystemEvidence]:
    """Yield filesystem evidence."""
    yield from analysis.evidence


def iter_high_risk_evidence(
    analysis: FilesystemAnalysis,
) -> Iterator[FilesystemEvidence]:
    """Yield only high/critical evidence."""
    for item in analysis.evidence:
        if item.severity in {"high", "critical"}:
            yield item


def iter_records(
    analysis: FilesystemAnalysis,
) -> Iterator[FilesystemRecord]:
    """Yield normalized filesystem records."""
    yield from analysis.records


def iter_paths(
    analysis: FilesystemAnalysis,
) -> Iterator[str]:
    """Yield extracted paths."""
    yield from analysis.paths


def iter_combinations(
    analysis: FilesystemAnalysis,
) -> Iterator[FilesystemCombination]:
    """Yield filesystem behavior combinations."""
    yield from analysis.combinations


def iter_analyses(
    sources: Iterable[Any],
    **kwargs: Any,
) -> Iterator[FilesystemAnalysis]:
    """Analyze an iterable of static sources lazily."""
    for source in sources:
        yield analyze_filesystem_behavior(source, **kwargs)


# ---------------------------------------------------------------------------
# Explicit exports
# ---------------------------------------------------------------------------

__all__ = [
    "MAX_SOURCE_SIZE",
    "MAX_TEXT_CHARS",
    "MAX_EVIDENCE_ITEMS",
    "MAX_PATHS",
    "MAX_FILE_OPERATIONS",
    "FILESYSTEM_CATEGORIES",
    "INDICATOR_NAMES",
    "FilesystemPattern",
    "FilesystemEvidence",
    "FilesystemRecord",
    "FilesystemCombination",
    "FilesystemAnalysis",
    "PATTERNS",
    "COMBINATION_DEFINITIONS",
    "extract_paths",
    "extract_filesystem_paths",
    "classify_path",
    "classify_paths",
    "normalize_operation",
    "extract_operation_records",
    "analyze_filesystem_behavior",
    "analyze",
    "parse_filesystem_behavior",
    "extract_filesystem_features",
    "extract_feature_vector",
    "extract_filesystem_feature_vector",
    "filesystem_feature_names",
    "build_feature_schema",
    "vectorize_features",
    "has_indicator",
    "has_category",
    "indicator_count",
    "category_count",
    "evidence_by_category",
    "evidence_by_indicator",
    "high_risk_evidence",
    "present_combinations",
    "highest_severity",
    "path_info",
    "analysis_to_dict",
    "summarize_filesystem_behavior",
    "iter_evidence",
    "iter_high_risk_evidence",
    "iter_records",
    "iter_paths",
    "iter_combinations",
    "iter_analyses",
]