"""
Static collection-behavior extraction for Pharos CDR.

This module performs defensive, static analysis of text, bytes, paths, and
nested analysis objects to identify indicators associated with data collection.

Security properties
-------------------
- Never executes commands, scripts, macros, or binaries.
- Never accesses the operating-system clipboard.
- Never captures screenshots, audio, keystrokes, or other live input.
- Never enumerates the live filesystem, removable drives, processes, or users.
- Never opens network connections.
- Never reads browser databases, mailboxes, archives, or credential stores.
- Never extracts embedded files to the host filesystem.
- Only analyzes material supplied by the caller.

The extractor is intentionally conservative around generic words such as
"collect", "data", and "file". Stronger contextual combinations receive higher
confidence and severity.

Evidence chain
--------------
static text/path/API reference
    -> collection indicator
    -> collection category
    -> collection behavior/combination
    -> feature vector
    -> ML/CDR policy
"""

from __future__ import annotations

import hashlib
import os
import re
from collections import Counter
from dataclasses import asdict, dataclass, field
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
    Set,
    Tuple,
    Union,
)


# ---------------------------------------------------------------------------
# Limits
# ---------------------------------------------------------------------------

MAX_SOURCE_SIZE = 25 * 1024 * 1024
MAX_TEXT_CHARS = 25 * 1024 * 1024
MAX_EVIDENCE_ITEMS = 20_000
MAX_MATCHES_PER_RULE = 5_000
MAX_NESTING_DEPTH = 12
MAX_FIELD_TEXT = 100_000
MAX_COLLECTION_RECORDS = 10_000
MAX_LOCATIONS = 10_000
MAX_TOKENS = 250_000


# ---------------------------------------------------------------------------
# Taxonomy
# ---------------------------------------------------------------------------

COLLECTION_CATEGORIES: Tuple[str, ...] = (
    "collection",
    "file_collection",
    "document_collection",
    "archive_collection",
    "filesystem_discovery",
    "directory_discovery",
    "removable_media",
    "network_share_collection",
    "browser_data",
    "browser_history",
    "browser_downloads",
    "browser_bookmarks",
    "browser_cache",
    "browser_cookies",
    "clipboard",
    "clipboard_collection",
    "screenshot",
    "screen_capture",
    "audio_capture",
    "video_capture",
    "input_capture",
    "keylogging",
    "email_collection",
    "mailbox_collection",
    "chat_collection",
    "database_collection",
    "cloud_storage",
    "cloud_collection",
    "source_code_collection",
    "configuration_collection",
    "credential_collection",
    "archive_creation",
    "data_staging",
    "compression",
    "encoding",
    "temporary_staging",
    "metadata_collection",
    "user_data_collection",
    "system_information",
    "process_information",
    "network_information",
    "security_information",
    "log_collection",
    "history_collection",
    "exfiltration_preparation",
    "collection_evasion",
)


SEVERITY_ORDER = {
    "low": 0,
    "medium": 1,
    "high": 2,
    "critical": 3,
}


SEVERITY_WEIGHTS = {
    "low": 1.0,
    "medium": 2.0,
    "high": 4.0,
    "critical": 7.0,
}


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CollectionPattern:
    """A static collection indicator rule."""

    name: str
    category: str
    regex: str
    severity: str = "medium"
    confidence: float = 0.8
    operation: str = "unknown"
    description: str = ""
    platform: str = "cross-platform"


@dataclass
class CollectionEvidence:
    """One bounded piece of static collection evidence."""

    category: str
    indicator: str
    evidence: str
    source: str = "static"
    line_number: Optional[int] = None
    operation: str = "unknown"
    location: Optional[str] = None
    platform: str = "cross-platform"
    confidence: float = 1.0
    severity: str = "medium"


@dataclass
class CollectionRecord:
    """Normalized collection behavior derived from evidence."""

    mechanism: str
    category: str
    location: Optional[str]
    operation: str
    platform: str
    indicator: str
    evidence: str
    severity: str
    confidence: float


@dataclass
class CollectionCombination:
    """Higher-level collection behavior derived from multiple indicators."""

    name: str
    present: bool
    required_categories: Tuple[str, ...]
    explanation: str


@dataclass
class CollectionAnalysis:
    """Complete static collection-behavior analysis."""

    source_hash: str
    source_size: int
    records: List[CollectionRecord] = field(default_factory=list)
    evidence: List[CollectionEvidence] = field(default_factory=list)
    indicators: List[str] = field(default_factory=list)
    categories: List[str] = field(default_factory=list)
    combinations: List[CollectionCombination] = field(default_factory=list)
    locations: List[str] = field(default_factory=list)
    platforms: List[str] = field(default_factory=list)
    feature_vector: Dict[str, float] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Input normalization
# ---------------------------------------------------------------------------


SourceLike = Union[
    str,
    bytes,
    bytearray,
    memoryview,
    os.PathLike,
    Mapping[str, Any],
    Sequence[Any],
    Any,
]


def _read_source(source: SourceLike) -> Tuple[str, int, str]:
    """
    Convert caller-provided material into bounded text.

    Returns:
        (text, source_size, source_kind)

    Files are read only because the caller explicitly supplied a path. The
    module never searches for files or enumerates directories.
    """
    if isinstance(source, bytes):
        raw = source[:MAX_SOURCE_SIZE]
        return raw.decode("utf-8", errors="replace")[:MAX_TEXT_CHARS], len(raw), "bytes"

    if isinstance(source, bytearray):
        raw = bytes(source[:MAX_SOURCE_SIZE])
        return raw.decode("utf-8", errors="replace")[:MAX_TEXT_CHARS], len(raw), "bytes"

    if isinstance(source, memoryview):
        raw = source.tobytes()[:MAX_SOURCE_SIZE]
        return raw.decode("utf-8", errors="replace")[:MAX_TEXT_CHARS], len(raw), "bytes"

    if isinstance(source, os.PathLike):
        path = Path(source)

        try:
            stat = path.stat()
            size = int(stat.st_size)
        except (OSError, ValueError):
            return str(path)[:MAX_TEXT_CHARS], len(str(path)), "path"

        if not path.is_file():
            return str(path)[:MAX_TEXT_CHARS], size, "path"

        if size > MAX_SOURCE_SIZE:
            with path.open("rb") as handle:
                raw = handle.read(MAX_SOURCE_SIZE)
        else:
            with path.open("rb") as handle:
                raw = handle.read()

        return (
            raw.decode("utf-8", errors="replace")[:MAX_TEXT_CHARS],
            size,
            "file",
        )

    if isinstance(source, str):
        return (
            source[:MAX_TEXT_CHARS],
            len(source.encode("utf-8", errors="replace")),
            "text",
        )

    return (
        _flatten_source(source)[:MAX_TEXT_CHARS],
        len(_flatten_source(source).encode("utf-8", errors="replace")),
        "object",
    )


def _safe_scalar_text(value: Any) -> str:
    """Safely stringify a scalar value within a strict size bound."""
    if value is None:
        return ""

    if isinstance(value, bytes):
        return value[:MAX_FIELD_TEXT].decode("utf-8", errors="replace")

    if isinstance(value, bytearray):
        return bytes(value[:MAX_FIELD_TEXT]).decode("utf-8", errors="replace")

    try:
        return str(value)[:MAX_FIELD_TEXT]
    except Exception:
        return ""


def _flatten_source(
    source: Any,
    *,
    depth: int = 0,
    seen: Optional[Set[int]] = None,
) -> str:
    """
    Recursively flatten nested analysis structures into searchable text.

    This intentionally avoids invoking arbitrary object methods other than a
    bounded string conversion.
    """
    if depth > MAX_NESTING_DEPTH:
        return ""

    if seen is None:
        seen = set()

    if source is None:
        return ""

    if isinstance(source, (str, bytes, bytearray, memoryview, os.PathLike)):
        return _safe_scalar_text(source)

    object_id = id(source)
    if object_id in seen:
        return ""

    seen.add(object_id)

    parts: List[str] = []

    if isinstance(source, Mapping):
        count = 0
        for key, value in source.items():
            if count >= MAX_TOKENS:
                break

            key_text = _safe_scalar_text(key)
            value_text = _flatten_source(
                value,
                depth=depth + 1,
                seen=seen,
            )

            if key_text:
                parts.append(key_text)
            if value_text:
                parts.append(value_text)

            count += 1

        return "\n".join(parts)[:MAX_TEXT_CHARS]

    if isinstance(source, Sequence) and not isinstance(
        source,
        (str, bytes, bytearray, memoryview),
    ):
        for index, value in enumerate(source):
            if index >= MAX_TOKENS:
                break

            value_text = _flatten_source(
                value,
                depth=depth + 1,
                seen=seen,
            )
            if value_text:
                parts.append(value_text)

        return "\n".join(parts)[:MAX_TEXT_CHARS]

    if hasattr(source, "__dict__"):
        try:
            return _flatten_source(
                vars(source),
                depth=depth + 1,
                seen=seen,
            )
        except Exception:
            pass

    return _safe_scalar_text(source)


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def _normalize_space(value: str) -> str:
    return re.sub(r"\s+", " ", value).strip()


def _safe_excerpt(text: str, start: int, end: int, radius: int = 100) -> str:
    left = max(0, start - radius)
    right = min(len(text), end + radius)
    excerpt = text[left:right]
    return _normalize_space(excerpt)[:MAX_FIELD_TEXT]


def _line_number(text: str, position: int) -> int:
    return text.count("\n", 0, position) + 1


# ---------------------------------------------------------------------------
# Pattern definitions
# ---------------------------------------------------------------------------


def _p(
    name: str,
    category: str,
    regex: str,
    *,
    severity: str = "medium",
    confidence: float = 0.8,
    operation: str = "unknown",
    description: str = "",
    platform: str = "cross-platform",
) -> CollectionPattern:
    return CollectionPattern(
        name=name,
        category=category,
        regex=regex,
        severity=severity,
        confidence=confidence,
        operation=operation,
        description=description,
        platform=platform,
    )


PATTERNS: Tuple[CollectionPattern, ...] = (
    # -----------------------------------------------------------------------
    # Generic file/document collection
    # -----------------------------------------------------------------------
    _p(
        "file_search_commands",
        "filesystem_discovery",
        r"(?i)\b(?:dir|tree|where|where\.exe|find|findstr|ls|find\s+/-|Get-ChildItem|gci|Get-Item|Get-ChildItem\s+-Recurse)\b",
        severity="low",
        confidence=0.55,
        operation="discover",
        description="Commands commonly used to enumerate files or directories.",
    ),
    _p(
        "recursive_file_enumeration",
        "filesystem_discovery",
        r"(?i)(?:-recurse\b|recursive(?:ly)?\b|walk(?:dir|ing)?\b|os\.walk\b|Directory\.EnumerateFiles\b|Directory\.GetFiles\b|glob\.(?:glob|iglob)\b)",
        severity="medium",
        confidence=0.78,
        operation="discover",
        description="Recursive filesystem enumeration.",
    ),
    _p(
        "document_extensions",
        "document_collection",
        r"(?i)(?:\*\.(?:doc|docx|docm|dot|dotx|dotm|xls|xlsx|xlsm|xltm|ppt|pptx|pptm|pdf|rtf|txt|csv)|\.(?:docx?|docm|xlsx?|xlsm|pptx?|pptm|pdf|rtf|csv|txt)\b)",
        severity="low",
        confidence=0.58,
        operation="read",
        description="References to common document file types.",
    ),
    _p(
        "sensitive_file_extensions",
        "file_collection",
        r"(?i)(?:\.(?:conf|config|ini|cfg|yaml|yml|json|xml|log|bak|backup|db|sqlite|sqlite3|sql|kdbx|pem|key|pfx|p12|cer|crt)\b)",
        severity="medium",
        confidence=0.70,
        operation="read",
        description="References to potentially sensitive configuration, database, or key files.",
    ),
    _p(
        "user_document_directories",
        "document_collection",
        r"(?i)(?:%USERPROFILE%|%HOMEPATH%|%APPDATA%|%LOCALAPPDATA%|~/Documents\b|~/Desktop\b|~/Downloads\b|/home/[^/\s]+/(?:Documents|Desktop|Downloads)\b|C:\\Users\\[^\\\s]+\\(?:Documents|Desktop|Downloads)\b)",
        severity="medium",
        confidence=0.78,
        operation="read",
        description="References to common user data directories.",
    ),
    _p(
        "bulk_copy_commands",
        "file_collection",
        r"(?i)\b(?:copy|xcopy|robocopy|cp|rsync)\b.{0,160}(?:/s|/e|-r|-a|--recursive|Documents|Desktop|Downloads|AppData|Users)",
        severity="medium",
        confidence=0.80,
        operation="collect",
        description="Recursive or targeted file-copy operations.",
    ),
    _p(
        "archive_collection",
        "archive_collection",
        r"(?i)\b(?:Compress-Archive|7z(?:\.exe)?|7za(?:\.exe)?|WinRAR|rar(?:\.exe)?|tar(?:\.exe)?|zip(?:\.exe)?|makecab(?:\.exe)?|cabarc)\b",
        severity="medium",
        confidence=0.78,
        operation="collect",
        description="Archive utilities that may be used to stage collected data.",
    ),
    _p(
        "archive_creation_flags",
        "archive_creation",
        r"(?i)(?:7z(?:\.exe)?\s+(?:a|u)\b|tar\s+(?:-c|-cz|-cf)\b|Compress-Archive\b|zip\s+-r\b|rar\s+a\b)",
        severity="medium",
        confidence=0.86,
        operation="stage",
        description="Explicit archive creation.",
    ),
    _p(
        "temporary_staging_paths",
        "temporary_staging",
        r"(?i)(?:%TEMP%|%TMP%|\\Temp\\|\\AppData\\Local\\Temp\\|/tmp/|/var/tmp/|/dev/shm/)",
        severity="low",
        confidence=0.55,
        operation="stage",
        description="Temporary locations frequently used for data staging.",
    ),
    # -----------------------------------------------------------------------
    # Clipboard / screen / input
    # -----------------------------------------------------------------------
    _p(
        "windows_clipboard_api",
        "clipboard_collection",
        r"(?i)\b(?:OpenClipboard|GetClipboardData|GetClipboardSequenceNumber|EnumClipboardFormats|GetClipboardFormatName|SetClipboardData)\b",
        severity="high",
        confidence=0.93,
        operation="collect",
        description="Windows clipboard API references.",
        platform="windows",
    ),
    _p(
        "powershell_clipboard",
        "clipboard_collection",
        r"(?i)\b(?:Get-Clipboard|Set-Clipboard|Clipboard\.GetText|Clipboard\.ContainsText)\b",
        severity="high",
        confidence=0.92,
        operation="collect",
        description="PowerShell/.NET clipboard access.",
        platform="windows",
    ),
    _p(
        "clipboard_automation",
        "clipboard",
        r"(?i)(?:clipboard(?:\.|\s+)(?:gettext|gettext|text|data)|DataObject\s*\.\s*GetText|MSForms\.DataObject)",
        severity="medium",
        confidence=0.82,
        operation="collect",
        description="Script-level clipboard access.",
        platform="windows",
    ),
    _p(
        "screenshot_apis",
        "screenshot",
        r"(?i)\b(?:BitBlt|PrintWindow|CreateCompatibleBitmap|CopyFromScreen|Graphics\.CopyFromScreen|ImageGrab\.grab|screenshot|capture_screen|screen_capture)\b",
        severity="high",
        confidence=0.90,
        operation="capture",
        description="Screen or screenshot capture references.",
    ),
    _p(
        "screenshot_commands",
        "screen_capture",
        r"(?i)\b(?:gnome-screenshot|scrot|import\s+-window\s+root|spectacle|screencapture)\b",
        severity="high",
        confidence=0.91,
        operation="capture",
        description="Known screen capture utilities.",
    ),
    _p(
        "audio_capture",
        "audio_capture",
        r"(?i)\b(?:waveInOpen|waveInStart|DirectSoundCapture|WasapiCapture|PyAudio|sounddevice|arecord|rec\.exe|ffmpeg)\b.{0,120}(?:audio|microphone|mic|record)",
        severity="high",
        confidence=0.86,
        operation="capture",
        description="Audio or microphone capture references.",
    ),
    _p(
        "keylogging_apis",
        "keylogging",
        r"(?i)\b(?:GetAsyncKeyState|GetKeyState|SetWindowsHookEx(?:A|W)?|WH_KEYBOARD_LL|GetKeyboardState|RegisterRawInputDevices)\b",
        severity="high",
        confidence=0.93,
        operation="capture",
        description="Keyboard/input capture API references.",
        platform="windows",
    ),
    _p(
        "keylogging_terms",
        "input_capture",
        r"(?i)\b(?:keylogger|key\s*logging|keyboard\s*hook|keystroke\s*logging|capture\s+keystrokes)\b",
        severity="high",
        confidence=0.94,
        operation="capture",
        description="Explicit keyboard capture terminology.",
    ),
    # -----------------------------------------------------------------------
    # Browser data
    # -----------------------------------------------------------------------
    _p(
        "chrome_user_data",
        "browser_data",
        r"(?i)(?:Chrome\\User Data|Chromium\\User Data|Google\\Chrome|chromium-browser|\.config/chromium)",
        severity="medium",
        confidence=0.82,
        operation="read",
        description="Chrome/Chromium profile references.",
    ),
    _p(
        "edge_user_data",
        "browser_data",
        r"(?i)(?:Microsoft\\Edge\\User Data|Edge\\User Data|msedge(?:\.exe)?)",
        severity="medium",
        confidence=0.82,
        operation="read",
        description="Microsoft Edge profile references.",
        platform="windows",
    ),
    _p(
        "firefox_profile",
        "browser_data",
        r"(?i)(?:Mozilla\\Firefox\\Profiles|\.mozilla/firefox|profiles\.ini|firefox-profile)",
        severity="medium",
        confidence=0.82,
        operation="read",
        description="Firefox profile references.",
    ),
    _p(
        "browser_history",
        "browser_history",
        r"(?i)\b(?:History|places\.sqlite|WebCache|browser_history|chrome_history|firefox_history)\b",
        severity="medium",
        confidence=0.82,
        operation="read",
        description="Browser history database or history references.",
    ),
    _p(
        "browser_downloads",
        "browser_downloads",
        r"(?i)\b(?:Downloads|download_history|download_url|downloads\.sqlite)\b",
        severity="low",
        confidence=0.62,
        operation="read",
        description="Browser download-history or download-directory references.",
    ),
    _p(
        "browser_bookmarks",
        "browser_bookmarks",
        r"(?i)\b(?:Bookmarks|bookmark_bar|places\.sqlite)\b",
        severity="low",
        confidence=0.62,
        operation="read",
        description="Browser bookmark references.",
    ),
    _p(
        "browser_cookies",
        "browser_cookies",
        r"(?i)\b(?:Cookies|cookies\.sqlite|cookieStore|document\.cookie|Network\\Cookies)\b",
        severity="high",
        confidence=0.91,
        operation="read",
        description="Browser cookie access references.",
    ),
    _p(
        "browser_login_data",
        "browser_data",
        r"(?i)(?:Login Data|logins\.json|key4\.db|Web Data|Login Data For Account|os_crypt)",
        severity="high",
        confidence=0.94,
        operation="read",
        description="Browser login/credential database references.",
    ),
    _p(
        "browser_cache",
        "browser_cache",
        r"(?i)(?:Cache\\|CacheStorage|Code Cache|GPUCache|cache2\\entries|browser_cache)",
        severity="medium",
        confidence=0.72,
        operation="read",
        description="Browser cache references.",
    ),
    # -----------------------------------------------------------------------
    # Email / chat / mailbox
    # -----------------------------------------------------------------------
    _p(
        "outlook_mailbox",
        "mailbox_collection",
        r"(?i)(?:Outlook\\|Microsoft\\Outlook|\.pst\b|\.ost\b|MAPI|Namespace\.GetDefaultFolder|GetDefaultFolder\s*\()",
        severity="high",
        confidence=0.89,
        operation="collect",
        description="Outlook/MAPI mailbox access references.",
        platform="windows",
    ),
    _p(
        "mail_file_collection",
        "email_collection",
        r"(?i)\.(?:pst|ost|mbox|eml|msg)\b",
        severity="medium",
        confidence=0.78,
        operation="read",
        description="Common mailbox/email file references.",
    ),
    _p(
        "mail_protocol_collection",
        "email_collection",
        r"(?i)\b(?:IMAP|POP3|SMTP)\b.{0,120}(?:mailbox|message|email|folder|inbox|download|fetch|retrieve)",
        severity="medium",
        confidence=0.82,
        operation="collect",
        description="Mail protocol references in a collection context.",
    ),
    _p(
        "chat_data",
        "chat_collection",
        r"(?i)(?:Discord|Slack|Teams|Telegram|WhatsApp).{0,120}(?:history|message|chat|database|cache|conversation)",
        severity="medium",
        confidence=0.78,
        operation="collect",
        description="Local chat/history collection references.",
    ),
    # -----------------------------------------------------------------------
    # Cloud / source code / configuration
    # -----------------------------------------------------------------------
    _p(
        "cloud_storage_paths",
        "cloud_storage",
        r"(?i)(?:OneDrive|Google Drive|Dropbox|iCloud Drive|DriveFS|CloudStorage).{0,120}(?:file|document|folder|sync|collect|copy)",
        severity="medium",
        confidence=0.76,
        operation="collect",
        description="Cloud-synchronized storage collection references.",
    ),
    _p(
        "cloud_configuration",
        "cloud_collection",
        r"(?i)(?:\.aws[\\/](?:credentials|config)|\.azure[\\/]|\.config/gcloud|application_default_credentials\.json|kubeconfig|\.kube[\\/](?:config|cache))",
        severity="high",
        confidence=0.92,
        operation="read",
        description="Cloud and orchestration configuration references.",
    ),
    _p(
        "source_code_directories",
        "source_code_collection",
        r"(?i)(?:\\(?:src|source|repos|repository|projects|workspace)\\|/(?:src|source|repos|repository|projects|workspace)/)",
        severity="medium",
        confidence=0.68,
        operation="read",
        description="Source-code or development workspace references.",
    ),
    _p(
        "git_metadata",
        "source_code_collection",
        r"(?i)(?:\.git[\\/](?:config|credentials|logs|refs)|git\s+(?:log|config|remote|show|branch))",
        severity="medium",
        confidence=0.80,
        operation="read",
        description="Git metadata references.",
    ),
    _p(
        "configuration_collection",
        "configuration_collection",
        r"(?i)(?:collect|copy|read|search|find|enumerate).{0,120}(?:config(?:uration)?|\.ini\b|\.conf\b|\.cfg\b|\.yaml\b|\.yml\b|\.json\b|\.xml\b)",
        severity="medium",
        confidence=0.74,
        operation="read",
        description="Configuration-file collection in an explicit access context.",
    ),
    # -----------------------------------------------------------------------
    # Databases and logs
    # -----------------------------------------------------------------------
    _p(
        "database_files",
        "database_collection",
        r"(?i)\.(?:db|sqlite|sqlite3|mdb|accdb|sql)\b",
        severity="medium",
        confidence=0.72,
        operation="read",
        description="Database file references.",
    ),
    _p(
        "database_dump_commands",
        "database_collection",
        r"(?i)\b(?:mysqldump|pg_dump|sqlcmd|bcp|expdp|mongo(?:export|dump)|mongodump|sqlite3)\b",
        severity="high",
        confidence=0.90,
        operation="collect",
        description="Database export/dump utilities.",
    ),
    _p(
        "log_collection",
        "log_collection",
        r"(?i)(?:collect|copy|archive|compress|read|search|grep|findstr).{0,120}(?:\.log\b|logs?[\\/]|event\s*log|journalctl)",
        severity="medium",
        confidence=0.75,
        operation="collect",
        description="Explicit log collection references.",
    ),
    # -----------------------------------------------------------------------
    # System/user/network information
    # -----------------------------------------------------------------------
    _p(
        "user_profile_information",
        "user_data_collection",
        r"(?i)(?:%USERPROFILE%|%HOMEPATH%|%APPDATA%|%LOCALAPPDATA%|/home/[^/\s]+).{0,120}(?:collect|copy|read|search|enumerate|profile|history)",
        severity="medium",
        confidence=0.76,
        operation="collect",
        description="Collection from user profile locations.",
    ),
    _p(
        "system_information_commands",
        "system_information",
        r"(?i)\b(?:systeminfo|hostname|whoami|uname|lsb_release|Get-ComputerInfo|Get-CimInstance\s+Win32_ComputerSystem|Get-WmiObject\s+Win32_ComputerSystem)\b",
        severity="low",
        confidence=0.66,
        operation="discover",
        description="System information discovery.",
    ),
    _p(
        "process_information_commands",
        "process_information",
        r"(?i)\b(?:tasklist|Get-Process|ps\s+-|ps\b|wmic\s+process|Process\.GetProcesses)\b",
        severity="low",
        confidence=0.68,
        operation="discover",
        description="Process information discovery.",
    ),
    _p(
        "network_information_commands",
        "network_information",
        r"(?i)\b(?:ipconfig|ifconfig|ip\s+addr|Get-NetIPAddress|netstat|ss\s+-|route\s+print|Get-NetTCPConnection|arp\s+-a)\b",
        severity="low",
        confidence=0.68,
        operation="discover",
        description="Network information discovery.",
    ),
    _p(
        "security_information",
        "security_information",
        r"(?i)\b(?:Get-MpComputerStatus|Get-CimInstance\s+.*(?:AntiVirus|Firewall)|netsh\s+advfirewall|SecurityCenter2|installed\s+antivirus|security\s+software)\b",
        severity="medium",
        confidence=0.75,
        operation="discover",
        description="Security-software or security-configuration discovery.",
    ),
    # -----------------------------------------------------------------------
    # Removable media / network shares
    # -----------------------------------------------------------------------
    _p(
        "removable_drive_enumeration",
        "removable_media",
        r"(?i)(?:DriveType\s*=\s*2|DRIVE_REMOVABLE|Get-Volume|Win32_LogicalDisk|USBSTOR|Removable\s+Drive|/media/|/mnt/)",
        severity="medium",
        confidence=0.82,
        operation="discover",
        description="Removable-media enumeration references.",
    ),
    _p(
        "network_share_paths",
        "network_share_collection",
        r"(?i)(?:\\\\[^\\\s]+\\[^\\\s]+|(?:net\s+use|Get-SmbShare|Get-PSDrive).{0,120}(?:share|drive|server))",
        severity="medium",
        confidence=0.82,
        operation="discover",
        description="Network-share or mapped-drive references.",
    ),
    _p(
        "network_share_collection",
        "network_share_collection",
        r"(?i)(?:copy|xcopy|robocopy|dir|Get-ChildItem|findstr|find).{0,180}\\\\[^\\\s]+\\[^\\\s]+",
        severity="high",
        confidence=0.86,
        operation="collect",
        description="File collection from a network share.",
    ),
    # -----------------------------------------------------------------------
    # Metadata/history
    # -----------------------------------------------------------------------
    _p(
        "recent_file_history",
        "history_collection",
        r"(?i)(?:Recent|RecentItems|AutomaticDestinations|CustomDestinations|ShellBags|UserAssist|JumpList|RecentDocs)",
        severity="medium",
        confidence=0.84,
        operation="collect",
        description="Windows recent-file or user activity artifacts.",
        platform="windows",
    ),
    _p(
        "shellbag_collection",
        "history_collection",
        r"(?i)\b(?:ShellBags|BagMRU|Bags)\b",
        severity="high",
        confidence=0.90,
        operation="collect",
        description="ShellBag/user-folder history references.",
        platform="windows",
    ),
    _p(
        "file_metadata_access",
        "metadata_collection",
        r"(?i)\b(?:stat|GetFileAttributes|FileInfo|DirectoryInfo|creationtime|lastwritetime|mtime|ctime|atime)\b",
        severity="low",
        confidence=0.60,
        operation="read",
        description="File metadata access.",
    ),
    # -----------------------------------------------------------------------
    # Encoding / staging / collection preparation
    # -----------------------------------------------------------------------
    _p(
        "base64_staging",
        "encoding",
        r"(?i)\b(?:ToBase64String|FromBase64String|base64(?:\s+|-)(?:encode|decode)|certutil\s+-encode|openssl\s+base64)\b",
        severity="medium",
        confidence=0.78,
        operation="stage",
        description="Base64 transformation potentially used during data staging.",
    ),
    _p(
        "hex_encoding",
        "encoding",
        r"(?i)\b(?:hex(?:lify|dump|encode)|ToHexString|xxd|Format-Hex)\b",
        severity="low",
        confidence=0.62,
        operation="stage",
        description="Hexadecimal transformation references.",
    ),
    _p(
        "data_staging_terms",
        "data_staging",
        r"(?i)\b(?:stage|staging|staged_data|collection_dir|loot|lootdir|harvest|harvested|bundle|package|aggregate)\b",
        severity="medium",
        confidence=0.74,
        operation="stage",
        description="Explicit data-staging terminology.",
    ),
    _p(
        "collection_archive_directory",
        "data_staging",
        r"(?i)(?:archive|zip|7z|rar|tar).{0,100}(?:collect|loot|staging|staged|harvest|documents|files)",
        severity="high",
        confidence=0.88,
        operation="stage",
        description="Archive creation associated with collected data.",
    ),
    # -----------------------------------------------------------------------
    # Explicit collection / exfiltration preparation
    # -----------------------------------------------------------------------
    _p(
        "explicit_file_collection",
        "file_collection",
        r"(?i)\b(?:collect|gather|harvest|grab|steal|scoop|acquire)\b.{0,100}\b(?:files?|documents?|directories|folders|data)\b",
        severity="high",
        confidence=0.88,
        operation="collect",
        description="Explicit file/data collection language.",
    ),
    _p(
        "bulk_data_collection",
        "collection",
        r"(?i)\b(?:collect|copy|archive|compress|stage|bundle)\b.{0,160}\b(?:all|every|entire|recursive|user|home|profile|documents|desktop|downloads)\b",
        severity="high",
        confidence=0.88,
        operation="collect",
        description="Broad or bulk data collection behavior.",
    ),
    _p(
        "exfiltration_staging",
        "exfiltration_preparation",
        r"(?i)\b(?:stage|package|archive|compress|encode|bundle)\b.{0,180}\b(?:exfil|upload|send|POST|HTTP|HTTPS|FTP|SFTP|webhook|C2|command.?and.?control)\b",
        severity="high",
        confidence=0.91,
        operation="stage",
        description="Collection staging linked to a transmission context.",
    ),
)


_COMPILED_PATTERNS: Tuple[Tuple[CollectionPattern, re.Pattern[str]], ...] = tuple(
    (pattern, re.compile(pattern.regex)) for pattern in PATTERNS
)


# ---------------------------------------------------------------------------
# Additional contextual rules
# ---------------------------------------------------------------------------


_LOCATION_PATTERNS: Tuple[Tuple[str, str], ...] = (
    (
        "windows_user_profile",
        r"(?i)(?:%USERPROFILE%|C:\\Users\\[^\\\s]+)",
    ),
    (
        "windows_documents",
        r"(?i)C:\\Users\\[^\\\s]+\\Documents(?:\\[^\\\s]+)*",
    ),
    (
        "windows_desktop",
        r"(?i)C:\\Users\\[^\\\s]+\\Desktop(?:\\[^\\\s]+)*",
    ),
    (
        "windows_downloads",
        r"(?i)C:\\Users\\[^\\\s]+\\Downloads(?:\\[^\\\s]+)*",
    ),
    (
        "windows_appdata",
        r"(?i)(?:%APPDATA%|%LOCALAPPDATA%|C:\\Users\\[^\\\s]+\\AppData\\)",
    ),
    (
        "windows_network_share",
        r"\\\\[^\\\s]+\\[^\\\s]+",
    ),
    (
        "unix_home",
        r"(?i)/home/[^/\s]+(?:/[^/\s]+)*",
    ),
    (
        "unix_tmp",
        r"(?i)/(?:tmp|var/tmp|dev/shm)(?:/[^/\s]+)*",
    ),
    (
        "browser_profile",
        r"(?i)(?:Chrome\\User Data|Microsoft\\Edge\\User Data|Mozilla\\Firefox\\Profiles|\.config/(?:google-chrome|chromium|mozilla))",
    ),
    (
        "mailbox",
        r"(?i)(?:[^\\/\s]+\.pst|[^\\/\s]+\.ost|[^\\/\s]+\.mbox|[^\\/\s]+\.eml)",
    ),
    (
        "cloud_config",
        r"(?i)(?:\.aws[\\/](?:credentials|config)|\.azure[\\/]|\.config/gcloud|\.kube[\\/]config)",
    ),
    (
        "git_metadata",
        r"(?i)\.git[\\/](?:config|credentials|logs|refs)",
    ),
)


_OPERATION_PATTERNS: Tuple[Tuple[str, re.Pattern[str]], ...] = (
    (
        "dump",
        re.compile(r"(?i)\b(?:dump|dumping|dumped|memory\s+dump|database\s+dump)\b"),
    ),
    (
        "extract",
        re.compile(r"(?i)\b(?:extract|extraction|extracting|retrieve|retrieval)\b"),
    ),
    (
        "enumerate",
        re.compile(
            r"(?i)\b(?:enumerate|enumeration|list|listing|discover|discovery|scan|search)\b"
        ),
    ),
    (
        "read",
        re.compile(r"(?i)\b(?:read|open|load|access|query|fetch|get|parse)\b"),
    ),
    (
        "collect",
        re.compile(r"(?i)\b(?:collect|collection|gather|harvest|grab|acquire|copy)\b"),
    ),
    (
        "capture",
        re.compile(
            r"(?i)\b(?:capture|capturing|record|recording|screenshot|keylog|keylogging)\b"
        ),
    ),
    (
        "stage",
        re.compile(r"(?i)\b(?:stage|staging|archive|compress|bundle|package)\b"),
    ),
    (
        "encode",
        re.compile(r"(?i)\b(?:encode|encoding|base64|hexlify|serialize)\b"),
    ),
    (
        "exfiltrate",
        re.compile(r"(?i)\b(?:exfil|exfiltrate|upload|send|POST|transmit|webhook)\b"),
    ),
)


_PLATFORM_PATTERNS: Tuple[Tuple[str, re.Pattern[str]], ...] = (
    (
        "windows",
        re.compile(
            r"(?i)(?:\bWindows\b|Win32|PowerShell|cmd\.exe|C:\\|%APPDATA%|%TEMP%|HKLM|HKCU)"
        ),
    ),
    (
        "linux",
        re.compile(r"(?i)(?:\bLinux\b|/home/|/etc/|/var/|/tmp/|bash\b|sh\b|systemd)"),
    ),
    (
        "macos",
        re.compile(r"(?i)(?:\bmacOS\b|/Users/|/Library/|~/Library/|osascript)"),
    ),
    (
        "cloud",
        re.compile(
            r"(?i)(?:AWS|Azure|GCP|Google Cloud|Kubernetes|\.aws[\\/]|\.azure[\\/]|\.kube[\\/])"
        ),
    ),
)


# ---------------------------------------------------------------------------
# Static helpers
# ---------------------------------------------------------------------------


def _infer_operation(text: str, default: str = "unknown") -> str:
    """Infer the strongest static operation represented in an excerpt."""
    for operation, pattern in _OPERATION_PATTERNS:
        if pattern.search(text):
            return operation
    return default


def _infer_platform(text: str, default: str = "cross-platform") -> str:
    """Infer a platform from static vocabulary."""
    matches: List[str] = []

    for platform, pattern in _PLATFORM_PATTERNS:
        if pattern.search(text):
            matches.append(platform)

    if not matches:
        return default

    if "cloud" in matches and len(matches) == 1:
        return "cloud"

    if len(matches) == 1:
        return matches[0]

    return "cross-platform"


def _find_location(text: str) -> Optional[str]:
    """Return the first bounded sensitive collection location."""
    for _, pattern in _LOCATION_PATTERNS:
        match = pattern.search(text)
        if match:
            return match.group(0)[:MAX_FIELD_TEXT]
    return None


def _is_weak_generic_indicator(pattern: CollectionPattern) -> bool:
    """
    Identify rules whose presence alone should not strongly imply collection.

    Generic file extensions and system discovery commands are deliberately
    treated as weak evidence.
    """
    return pattern.name in {
        "document_extensions",
        "sensitive_file_extensions",
        "file_search_commands",
        "temporary_staging_paths",
        "system_information_commands",
        "process_information_commands",
        "network_information_commands",
        "file_metadata_access",
        "browser_downloads",
        "browser_bookmarks",
        "browser_cache",
        "database_files",
        "hex_encoding",
        "system_information_commands",
    }


def _contextual_confidence(
    pattern: CollectionPattern,
    excerpt: str,
) -> float:
    """
    Adjust confidence using contextual terms.

    This is intentionally heuristic and bounded; it does not attempt to
    determine whether the referenced behavior actually occurred.
    """
    confidence = pattern.confidence

    strong_terms = (
        r"\bcollect\b",
        r"\bcollection\b",
        r"\bharvest\b",
        r"\bsteal\b",
        r"\bcopy\b",
        r"\bextract\b",
        r"\bdump\b",
        r"\bstage\b",
        r"\barchive\b",
        r"\bcompress\b",
        r"\bcapture\b",
        r"\bread\b",
        r"\baccess\b",
        r"\benumerate\b",
    )

    if any(re.search(term, excerpt, re.I) for term in strong_terms):
        confidence += 0.05

    if _is_weak_generic_indicator(pattern):
        confidence -= 0.08

    return max(0.05, min(1.0, confidence))


def _deduplicate_evidence(
    evidence: Iterable[CollectionEvidence],
) -> List[CollectionEvidence]:
    """Deduplicate evidence while preserving order."""
    result: List[CollectionEvidence] = []
    seen: Set[Tuple[Any, ...]] = set()

    for item in evidence:
        key = (
            item.category,
            item.indicator,
            item.evidence,
            item.line_number,
            item.location,
        )

        if key in seen:
            continue

        seen.add(key)
        result.append(item)

        if len(result) >= MAX_EVIDENCE_ITEMS:
            break

    return result


# ---------------------------------------------------------------------------
# Extraction
# ---------------------------------------------------------------------------


def _extract_pattern_evidence(
    text: str,
) -> List[CollectionEvidence]:
    """Apply all static rules to the supplied text."""
    evidence: List[CollectionEvidence] = []

    for pattern, compiled in _COMPILED_PATTERNS:
        matches = 0

        for match in compiled.finditer(text):
            if matches >= MAX_MATCHES_PER_RULE:
                break

            excerpt = _safe_excerpt(
                text,
                match.start(),
                match.end(),
            )

            operation = _infer_operation(
                excerpt,
                default=pattern.operation,
            )

            platform = _infer_platform(
                excerpt,
                default=pattern.platform,
            )

            location = _find_location(excerpt)

            confidence = _contextual_confidence(
                pattern,
                excerpt,
            )

            evidence.append(
                CollectionEvidence(
                    category=pattern.category,
                    indicator=pattern.name,
                    evidence=excerpt,
                    source="static_pattern",
                    line_number=_line_number(text, match.start()),
                    operation=operation,
                    location=location,
                    platform=platform,
                    confidence=confidence,
                    severity=pattern.severity,
                )
            )

            matches += 1

            if len(evidence) >= MAX_EVIDENCE_ITEMS:
                return evidence

    return evidence


def _derive_records(
    evidence: Sequence[CollectionEvidence],
) -> List[CollectionRecord]:
    """Convert evidence into normalized collection records."""
    records: List[CollectionRecord] = []
    seen: Set[Tuple[Any, ...]] = set()

    for item in evidence:
        key = (
            item.indicator,
            item.category,
            item.location,
            item.operation,
            item.platform,
        )

        if key in seen:
            continue

        seen.add(key)

        records.append(
            CollectionRecord(
                mechanism=item.indicator,
                category=item.category,
                location=item.location,
                operation=item.operation,
                platform=item.platform,
                indicator=item.indicator,
                evidence=item.evidence,
                severity=item.severity,
                confidence=item.confidence,
            )
        )

        if len(records) >= MAX_COLLECTION_RECORDS:
            break

    return records


def _derive_locations(
    evidence: Sequence[CollectionEvidence],
) -> List[str]:
    """Collect unique static locations."""
    locations: List[str] = []
    seen: Set[str] = set()

    for item in evidence:
        if not item.location:
            continue

        location = item.location[:MAX_FIELD_TEXT]

        if location in seen:
            continue

        seen.add(location)
        locations.append(location)

        if len(locations) >= MAX_LOCATIONS:
            break

    return locations


def _derive_combinations(
    categories: Set[str],
    evidence: Sequence[CollectionEvidence],
) -> List[CollectionCombination]:
    """Derive higher-level collection behavior chains."""
    combinations: List[CollectionCombination] = []

    def add(
        name: str,
        required: Tuple[str, ...],
        explanation: str,
        present: bool,
    ) -> None:
        combinations.append(
            CollectionCombination(
                name=name,
                present=present,
                required_categories=required,
                explanation=explanation,
            )
        )

    add(
        "bulk_file_collection",
        ("file_collection", "filesystem_discovery"),
        "File-system enumeration is combined with explicit file collection.",
        "file_collection" in categories and "filesystem_discovery" in categories,
    )

    add(
        "document_harvesting",
        ("document_collection",),
        "References indicate collection of user documents or document files.",
        "document_collection" in categories,
    )

    add(
        "browser_data_collection",
        ("browser_data",),
        "Browser profile or browser-resident data is referenced for collection.",
        "browser_data" in categories
        or "browser_history" in categories
        or "browser_cookies" in categories,
    )

    add(
        "browser_credential_adjacent_collection",
        ("browser_data", "browser_cookies"),
        "Browser profile data and cookies are jointly referenced.",
        "browser_data" in categories and "browser_cookies" in categories,
    )

    add(
        "clipboard_collection",
        ("clipboard_collection",),
        "Static references indicate clipboard acquisition.",
        "clipboard_collection" in categories,
    )

    add(
        "screen_and_input_collection",
        ("screen_capture", "input_capture"),
        "Screen capture and keyboard/input collection are both present.",
        "screen_capture" in categories and "input_capture" in categories,
    )

    add(
        "mailbox_collection",
        ("mailbox_collection",),
        "Mailbox or Outlook/MAPI collection indicators are present.",
        "mailbox_collection" in categories or "email_collection" in categories,
    )

    add(
        "database_collection",
        ("database_collection",),
        "Database export, dump, or database-file collection indicators are present.",
        "database_collection" in categories,
    )

    add(
        "cloud_data_collection",
        ("cloud_collection",),
        "Cloud configuration or cloud-storage collection indicators are present.",
        "cloud_collection" in categories or "cloud_storage" in categories,
    )

    add(
        "removable_media_collection",
        ("removable_media", "file_collection"),
        "Removable-media discovery is combined with file collection.",
        "removable_media" in categories and "file_collection" in categories,
    )

    add(
        "network_share_collection",
        ("network_share_collection",),
        "Network-share discovery or file collection is present.",
        "network_share_collection" in categories,
    )

    add(
        "archive_based_staging",
        ("archive_creation", "data_staging"),
        "Collected data appears to be prepared through archive creation and staging.",
        "archive_creation" in categories and "data_staging" in categories,
    )

    add(
        "collection_to_exfiltration_staging",
        ("collection", "exfiltration_preparation"),
        "Collection indicators are linked to staging for later transmission.",
        ("collection" in categories and "exfiltration_preparation" in categories),
    )

    add(
        "compression_after_collection",
        ("compression", "file_collection"),
        "Compression/archive behavior occurs alongside file collection.",
        "compression" in categories and "file_collection" in categories,
    )

    add(
        "source_code_harvesting",
        ("source_code_collection",),
        "Development/source-code locations are referenced for collection.",
        "source_code_collection" in categories,
    )

    add(
        "user_activity_collection",
        ("user_data_collection", "history_collection"),
        "User-profile data and historical activity artifacts are jointly referenced.",
        "user_data_collection" in categories and "history_collection" in categories,
    )

    add(
        "multi_source_collection",
        (
            "file_collection",
            "browser_data",
            "clipboard_collection",
        ),
        "Multiple independent user-data collection sources are represented.",
        sum(
            int(category in categories)
            for category in (
                "file_collection",
                "browser_data",
                "clipboard_collection",
                "mailbox_collection",
                "database_collection",
                "cloud_collection",
                "screen_capture",
            )
        )
        >= 2,
    )

    # Operation-driven combination.
    operations = {item.operation for item in evidence}

    add(
        "collect_then_stage",
        ("collection", "data_staging"),
        "Collection and subsequent staging operations are both represented.",
        (
            bool(operations & {"collect", "capture", "read", "extract", "dump"})
            and bool(operations & {"stage", "encode"})
        ),
    )

    return combinations


def _derive_signal_score(
    evidence: Sequence[CollectionEvidence],
    combinations: Sequence[CollectionCombination],
) -> float:
    """Calculate a bounded heuristic collection signal score."""
    score = 0.0

    for item in evidence:
        score += SEVERITY_WEIGHTS.get(item.severity, 1.0)
        score *= 0.9995

        if item.operation in {"dump", "extract", "capture", "collect"}:
            score += 0.75

        if item.operation == "stage":
            score += 0.35

        score += max(0.0, item.confidence - 0.5) * 0.8

    for combination in combinations:
        if combination.present:
            score += 4.0

    return round(min(100.0, max(0.0, score)), 4)


# ---------------------------------------------------------------------------
# Feature vectors
# ---------------------------------------------------------------------------


def _build_feature_vector(
    source_size: int,
    records: Sequence[CollectionRecord],
    evidence: Sequence[CollectionEvidence],
    indicators: Sequence[str],
    categories: Sequence[str],
    combinations: Sequence[CollectionCombination],
    locations: Sequence[str],
    platforms: Sequence[str],
) -> Dict[str, float]:
    """Build a stable ML-ready scalar feature vector."""
    vector: Dict[str, float] = {}

    vector["source_size"] = float(source_size)
    vector["record_count"] = float(len(records))
    vector["evidence_count"] = float(len(evidence))
    vector["location_count"] = float(len(locations))
    vector["platform_count"] = float(len(platforms))
    vector["indicator_count"] = float(len(indicators))
    vector["category_count"] = float(len(categories))
    vector["combination_count"] = float(sum(1 for item in combinations if item.present))

    severity_counts = Counter(item.severity for item in evidence)
    vector["low_count"] = float(severity_counts.get("low", 0))
    vector["medium_count"] = float(severity_counts.get("medium", 0))
    vector["high_count"] = float(severity_counts.get("high", 0))
    vector["critical_count"] = float(severity_counts.get("critical", 0))

    operation_counts = Counter(item.operation for item in records)

    operations = (
        "dump",
        "extract",
        "enumerate",
        "read",
        "collect",
        "capture",
        "stage",
        "encode",
        "exfiltrate",
        "unknown",
    )

    for operation in operations:
        vector[f"{operation}_count"] = float(operation_counts.get(operation, 0))

    platform_counts = Counter(item.platform for item in records)

    for platform in ("windows", "linux", "macos", "cloud", "cross-platform"):
        vector[f"{platform.replace('-', '_')}_count"] = float(
            platform_counts.get(platform, 0)
        )

    category_counts = Counter(item.category for item in evidence)

    for category in COLLECTION_CATEGORIES:
        vector[f"category_{category}_present"] = float(
            category_counts.get(category, 0) > 0
        )
        vector[f"category_{category}_count"] = float(category_counts.get(category, 0))

    indicator_counts = Counter(item.indicator for item in evidence)

    all_indicators = sorted(
        {pattern.name for pattern in PATTERNS} | set(indicator_counts)
    )

    for indicator in all_indicators:
        vector[f"indicator_{indicator}_present"] = float(
            indicator_counts.get(indicator, 0) > 0
        )
        vector[f"indicator_{indicator}_count"] = float(
            indicator_counts.get(indicator, 0)
        )

    combination_map = {item.name: item for item in combinations}

    for name in sorted(combination_map):
        vector[f"combination_{name}_present"] = float(combination_map[name].present)

    vector["collection_signal_score"] = _derive_signal_score(
        evidence,
        combinations,
    )

    return vector


def collection_feature_names() -> List[str]:
    """Return stable feature names used by the extractor."""
    empty_vector = _build_feature_vector(
        source_size=0,
        records=[],
        evidence=[],
        indicators=[],
        categories=[],
        combinations=_derive_combinations(set(), []),
        locations=[],
        platforms=[],
    )

    return list(empty_vector.keys())


def build_feature_schema() -> Dict[str, Any]:
    """Return a machine-readable feature schema."""
    return {
        "schema_version": "1.0",
        "feature_type": "static_collection_behavior",
        "features": [
            {
                "name": name,
                "type": "float",
                "description": ("Stable static collection-behavior feature."),
            }
            for name in collection_feature_names()
        ],
    }


def vectorize_features(
    analysis: CollectionAnalysis,
    feature_names: Optional[Sequence[str]] = None,
) -> List[float]:
    """
    Convert an analysis into an ordered numeric feature vector.

    Unknown requested features are represented as zero, allowing callers to
    align this extractor with an external feature schema.
    """
    names = (
        list(feature_names) if feature_names is not None else collection_feature_names()
    )

    return [float(analysis.feature_vector.get(name, 0.0)) for name in names]


# ---------------------------------------------------------------------------
# Public analysis API
# ---------------------------------------------------------------------------


def analyze_collection_behavior(
    source: SourceLike,
) -> CollectionAnalysis:
    """
    Perform static collection-behavior analysis.

    Args:
        source:
            Text, bytes, path supplied by the caller, mapping, sequence, or
            analysis object.

    Returns:
        CollectionAnalysis

    No collection operation represented by an indicator is actually performed.
    """
    text, source_size, source_kind = _read_source(source)

    if len(text) > MAX_TEXT_CHARS:
        text = text[:MAX_TEXT_CHARS]

    source_hash = _sha256_text(text)

    evidence = _extract_pattern_evidence(text)
    evidence = _deduplicate_evidence(evidence)

    records = _derive_records(evidence)

    indicators = sorted({item.indicator for item in evidence})

    categories = sorted({item.category for item in evidence})

    locations = _derive_locations(evidence)

    platforms = sorted({item.platform for item in evidence if item.platform})

    combinations = _derive_combinations(
        set(categories),
        evidence,
    )

    feature_vector = _build_feature_vector(
        source_size=source_size,
        records=records,
        evidence=evidence,
        indicators=indicators,
        categories=categories,
        combinations=combinations,
        locations=locations,
        platforms=platforms,
    )

    metadata = {
        "schema_version": "1.0",
        "analyzer": "pharos-cdr.static-collection",
        "static_only": True,
        "source_kind": source_kind,
        "text_length": len(text),
        "truncated": len(text) >= MAX_TEXT_CHARS,
        "pattern_count": len(PATTERNS),
        "evidence_truncated": len(evidence) >= MAX_EVIDENCE_ITEMS,
        "record_truncated": len(records) >= MAX_COLLECTION_RECORDS,
        "location_truncated": len(locations) >= MAX_LOCATIONS,
        "present_combination_count": sum(1 for item in combinations if item.present),
        "signal_score": feature_vector.get(
            "collection_signal_score",
            0.0,
        ),
    }

    return CollectionAnalysis(
        source_hash=source_hash,
        source_size=source_size,
        records=records,
        evidence=evidence,
        indicators=indicators,
        categories=categories,
        combinations=combinations,
        locations=locations,
        platforms=platforms,
        feature_vector=feature_vector,
        metadata=metadata,
    )


def analyze_collection(source: SourceLike) -> CollectionAnalysis:
    """Alias for analyze_collection_behavior."""
    return analyze_collection_behavior(source)


def analyze(source: SourceLike) -> CollectionAnalysis:
    """Short alias for analyze_collection_behavior."""
    return analyze_collection_behavior(source)


def parse_collection_behavior(source: SourceLike) -> CollectionAnalysis:
    """Compatibility alias for parser-oriented callers."""
    return analyze_collection_behavior(source)


def extract_collection_features(source: SourceLike) -> CollectionAnalysis:
    """Return a complete collection feature analysis."""
    return analyze_collection_behavior(source)


def extract_feature_vector(
    source: SourceLike,
) -> Dict[str, float]:
    """Return the ML-ready collection feature mapping."""
    return analyze_collection_behavior(source).feature_vector


def extract_collection_feature_vector(
    source: SourceLike,
) -> Dict[str, float]:
    """Explicit alias for collection feature-vector extraction."""
    return extract_feature_vector(source)


def extract_collection_records(
    source: SourceLike,
) -> List[CollectionRecord]:
    """Extract normalized collection records."""
    return analyze_collection_behavior(source).records


# ---------------------------------------------------------------------------
# Query helpers
# ---------------------------------------------------------------------------


def has_indicator(
    analysis: CollectionAnalysis,
    indicator: str,
) -> bool:
    """Return whether an indicator is present."""
    target = indicator.strip().lower()

    return any(value.lower() == target for value in analysis.indicators)


def has_category(
    analysis: CollectionAnalysis,
    category: str,
) -> bool:
    """Return whether a collection category is present."""
    target = category.strip().lower()

    return any(value.lower() == target for value in analysis.categories)


def indicator_count(
    analysis: CollectionAnalysis,
    indicator: str,
) -> int:
    """Count evidence items associated with an indicator."""
    target = indicator.strip().lower()

    return sum(1 for item in analysis.evidence if item.indicator.lower() == target)


def category_count(
    analysis: CollectionAnalysis,
    category: str,
) -> int:
    """Count evidence items associated with a category."""
    target = category.strip().lower()

    return sum(1 for item in analysis.evidence if item.category.lower() == target)


def evidence_by_category(
    analysis: CollectionAnalysis,
    category: str,
) -> List[CollectionEvidence]:
    """Return evidence belonging to a category."""
    target = category.strip().lower()

    return [item for item in analysis.evidence if item.category.lower() == target]


def evidence_by_indicator(
    analysis: CollectionAnalysis,
    indicator: str,
) -> List[CollectionEvidence]:
    """Return evidence belonging to an indicator."""
    target = indicator.strip().lower()

    return [item for item in analysis.evidence if item.indicator.lower() == target]


def high_risk_evidence(
    analysis: CollectionAnalysis,
) -> List[CollectionEvidence]:
    """Return high and critical collection evidence."""
    return [
        item for item in analysis.evidence if SEVERITY_ORDER.get(item.severity, 0) >= 2
    ]


def present_combinations(
    analysis: CollectionAnalysis,
) -> List[CollectionCombination]:
    """Return only combinations whose conditions are satisfied."""
    return [item for item in analysis.combinations if item.present]


def highest_severity(
    analysis: CollectionAnalysis,
) -> str:
    """Return the highest observed evidence severity."""
    if not analysis.evidence:
        return "low"

    return max(
        (item.severity for item in analysis.evidence),
        key=lambda value: SEVERITY_ORDER.get(value, 0),
    )


# ---------------------------------------------------------------------------
# Serialization
# ---------------------------------------------------------------------------


def analysis_to_dict(
    analysis: CollectionAnalysis,
) -> Dict[str, Any]:
    """Serialize a collection analysis into JSON-compatible structures."""
    return asdict(analysis)


def summarize_collection_behavior(
    analysis: CollectionAnalysis,
) -> Dict[str, Any]:
    """
    Return a compact operational summary suitable for pipeline reports.
    """
    severity_counts = Counter(item.severity for item in analysis.evidence)

    operation_counts = Counter(item.operation for item in analysis.records)

    return {
        "source_hash": analysis.source_hash,
        "source_size": analysis.source_size,
        "signal_score": analysis.feature_vector.get(
            "collection_signal_score",
            0.0,
        ),
        "highest_severity": highest_severity(analysis),
        "record_count": len(analysis.records),
        "evidence_count": len(analysis.evidence),
        "indicator_count": len(analysis.indicators),
        "category_count": len(analysis.categories),
        "location_count": len(analysis.locations),
        "platforms": list(analysis.platforms),
        "categories": list(analysis.categories),
        "indicators": list(analysis.indicators),
        "present_combinations": [item.name for item in present_combinations(analysis)],
        "severity_counts": dict(severity_counts),
        "operation_counts": dict(operation_counts),
        "high_risk_evidence_count": len(high_risk_evidence(analysis)),
    }


# ---------------------------------------------------------------------------
# Iterators
# ---------------------------------------------------------------------------


def iter_evidence(
    analysis: CollectionAnalysis,
) -> Iterator[CollectionEvidence]:
    """Iterate over all collection evidence."""
    yield from analysis.evidence


def iter_high_risk_evidence(
    analysis: CollectionAnalysis,
) -> Iterator[CollectionEvidence]:
    """Iterate over high/critical collection evidence."""
    yield from high_risk_evidence(analysis)


def iter_records(
    analysis: CollectionAnalysis,
) -> Iterator[CollectionRecord]:
    """Iterate over normalized collection records."""
    yield from analysis.records


def iter_combinations(
    analysis: CollectionAnalysis,
    *,
    present_only: bool = False,
) -> Iterator[CollectionCombination]:
    """Iterate over derived collection combinations."""
    for item in analysis.combinations:
        if present_only and not item.present:
            continue
        yield item


def iter_analyses(
    sources: Iterable[SourceLike],
) -> Iterator[CollectionAnalysis]:
    """Analyze an iterable of supplied sources lazily."""
    for source in sources:
        yield analyze_collection_behavior(source)


# ---------------------------------------------------------------------------
# Compatibility aliases
# ---------------------------------------------------------------------------


parse = parse_collection_behavior
extract = extract_collection_features


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


__all__ = [
    "CollectionPattern",
    "CollectionEvidence",
    "CollectionRecord",
    "CollectionCombination",
    "CollectionAnalysis",
    "analyze_collection_behavior",
    "analyze_collection",
    "analyze",
    "parse_collection_behavior",
    "extract_collection_features",
    "extract_feature_vector",
    "extract_collection_feature_vector",
    "collection_feature_names",
    "build_feature_schema",
    "vectorize_features",
    "extract_collection_records",
    "has_indicator",
    "has_category",
    "indicator_count",
    "category_count",
    "evidence_by_category",
    "evidence_by_indicator",
    "high_risk_evidence",
    "present_combinations",
    "highest_severity",
    "analysis_to_dict",
    "summarize_collection_behavior",
    "iter_evidence",
    "iter_high_risk_evidence",
    "iter_records",
    "iter_combinations",
    "iter_analyses",
    "parse",
    "extract",
]
