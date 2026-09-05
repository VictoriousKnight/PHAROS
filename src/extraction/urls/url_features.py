"""
Static URL and network-indicator feature extraction.

This module performs defensive, static analysis of URLs and URL-like strings
found in documents, scripts, logs, metadata, extracted strings, or arbitrary
nested analysis structures.

Security properties
-------------------
- Never performs DNS resolution.
- Never opens network connections.
- Never sends HTTP/HTTPS requests.
- Never follows redirects.
- Never downloads content.
- Never executes JavaScript or other active content.
- Never loads remote resources.
- Never modifies the filesystem.
- Uses bounded parsing and extraction to reduce resource-exhaustion risk.

The extractor focuses on structural and lexical characteristics that are
useful for:
    URL reputation features
    phishing/suspicious-link detection
    malware/document triage
    CDR policy decisions
    static behavioral correlation
    ML feature generation

The module intentionally does NOT decide whether a URL is malicious by itself.
It produces evidence and normalized features that can be combined with other
signals such as document structure, VBA, scripts, process behavior, network
behavior, and ML models.

Public API
----------
Primary analysis:
    analyze_url_features
    analyze_urls
    analyze
    parse_url_features
    extract_url_features

Feature vectors:
    extract_feature_vector
    extract_url_feature_vector
    url_feature_names
    build_feature_schema
    vectorize_features

Inspection:
    extract_url_records
    has_indicator
    has_category
    indicator_count
    category_count
    evidence_by_category
    evidence_by_indicator
    high_risk_evidence
    highest_severity
    present_combinations

Serialization/reporting:
    analysis_to_dict
    summarize_url_features

Iterators:
    iter_evidence
    iter_high_risk_evidence
    iter_records
    iter_combinations
    iter_analyses

Compatibility aliases:
    parse
    extract
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import ipaddress
import math
import os
import re
import urllib.parse
from collections import Counter
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable, Iterator, Mapping, Optional, Sequence

__all__ = [
    # Primary analysis entry points
    "analyze_url_features",
    "analyze_urls",
    "analyze",
    "parse_url_features",
    "extract_url_features",
    # Feature-vector API
    "extract_feature_vector",
    "extract_url_feature_vector",
    "url_feature_names",
    "build_feature_schema",
    "vectorize_features",
    # Record/evidence access
    "extract_url_records",
    "has_indicator",
    "has_category",
    "indicator_count",
    "category_count",
    "evidence_by_category",
    "evidence_by_indicator",
    "high_risk_evidence",
    "highest_severity",
    "present_combinations",
    # Serialization/reporting
    "analysis_to_dict",
    "summarize_url_features",
    # Iterators
    "iter_evidence",
    "iter_high_risk_evidence",
    "iter_records",
    "iter_combinations",
    "iter_analyses",
    # Public data structures
    "URLPattern",
    "URLEvidence",
    "URLRecord",
    "URLCombination",
    "URLAnalysis",
    # Compatibility aliases
    "parse",
    "extract",
]


# ---------------------------------------------------------------------------
# Resource limits
# ---------------------------------------------------------------------------

MAX_SOURCE_SIZE = 25 * 1024 * 1024
MAX_TEXT_CHARS = 25 * 1024 * 1024
MAX_FIELD_TEXT = 100_000
MAX_NESTING_DEPTH = 12

MAX_URLS = 20_000
MAX_EVIDENCE_ITEMS = 30_000
MAX_RECORDS = 20_000
MAX_MATCHES_PER_RULE = 5_000
MAX_QUERY_PARAMETERS = 5_000
MAX_PATH_COMPONENTS = 5_000
MAX_HOST_LABELS = 1_000

MAX_URL_LENGTH = 16_384
MAX_DOMAIN_LENGTH = 2_048
MAX_PATH_LENGTH = 8_192
MAX_QUERY_LENGTH = 16_384

MAX_DECODE_ATTEMPTS = 8
MAX_DECODED_TEXT = 32_768

# Entropy is useful as a weak signal but should never independently classify
# a URL as malicious.
HIGH_ENTROPY_THRESHOLD = 4.25
VERY_HIGH_ENTROPY_THRESHOLD = 5.25

# Long host/path/query thresholds.
LONG_URL_THRESHOLD = 512
VERY_LONG_URL_THRESHOLD = 2_048
LONG_HOST_THRESHOLD = 80
LONG_PATH_THRESHOLD = 180
LONG_QUERY_THRESHOLD = 250

# Numeric/domain thresholds.
MANY_SUBDOMAINS_THRESHOLD = 4
MANY_QUERY_PARAMETERS_THRESHOLD = 8
MANY_PATH_COMPONENTS_THRESHOLD = 8
HIGH_PORT_THRESHOLD = 1024


# ---------------------------------------------------------------------------
# Taxonomy
# ---------------------------------------------------------------------------

URL_CATEGORIES = (
    "scheme",
    "domain",
    "ip_address",
    "port",
    "path",
    "query",
    "fragment",
    "userinfo",
    "redirector",
    "shortener",
    "tracking",
    "encoding",
    "obfuscation",
    "suspicious_tld",
    "dynamic_host",
    "dynamic_path",
    "download",
    "execution",
    "remote_resource",
    "phishing",
    "credential_collection",
    "malware_delivery",
    "command_control",
    "cloud_storage",
    "public_file_hosting",
    "local_network",
    "external_reference",
    "javascript_scheme",
    "data_scheme",
    "file_scheme",
    "dangerous_scheme",
    "suspicious_port",
    "high_entropy",
    "excessive_length",
    "excessive_parameters",
    "nested_url",
    "encoded_url",
    "unicode_domain",
    "punycode",
    "homograph",
    "archive_or_payload",
    "suspicious_extension",
    "unknown",
)


SEVERITIES = ("low", "medium", "high", "critical")


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class URLPattern:
    """Static URL detection rule."""

    name: str
    category: str
    pattern: str
    severity: str = "medium"
    confidence: float = 0.8
    operation: str = "detect"
    description: str = ""


@dataclass(frozen=True)
class URLEvidence:
    """Evidence produced from one URL or URL-like indicator."""

    category: str
    indicator: str
    evidence: str
    source: str = "url"
    url: Optional[str] = None
    line_number: Optional[int] = None
    field: Optional[str] = None
    operation: str = "detect"
    target: Optional[str] = None
    platform: Optional[str] = None
    confidence: float = 1.0
    severity: str = "medium"


@dataclass(frozen=True)
class URLRecord:
    """Normalized representation of one discovered URL."""

    url: str
    normalized_url: str
    scheme: str
    host: str
    registrable_domain: str
    port: Optional[int]
    path: str
    query: str
    fragment: str
    username_present: bool
    password_present: bool
    is_ip_address: bool
    is_private_ip: bool
    is_loopback_ip: bool
    is_localhost: bool
    is_punycode: bool
    has_unicode: bool
    subdomain_count: int
    path_component_count: int
    query_parameter_count: int
    url_length: int
    host_length: int
    path_length: int
    query_length: int
    entropy: float
    categories: tuple[str, ...] = ()
    indicators: tuple[str, ...] = ()
    severity: str = "low"
    confidence: float = 1.0
    evidence: tuple[str, ...] = ()
    source: Optional[str] = None


@dataclass(frozen=True)
class URLCombination:
    """Higher-level relationship between URL characteristics."""

    name: str
    present: bool
    required_categories: tuple[str, ...]
    explanation: str


@dataclass
class URLAnalysis:
    """Complete static URL analysis result."""

    source_hash: str
    source_size: int

    records: list[URLRecord] = field(default_factory=list)
    evidence: list[URLEvidence] = field(default_factory=list)

    indicators: list[str] = field(default_factory=list)
    categories: list[str] = field(default_factory=list)
    combinations: list[URLCombination] = field(default_factory=list)

    domains: list[str] = field(default_factory=list)
    hosts: list[str] = field(default_factory=list)
    schemes: list[str] = field(default_factory=list)
    platforms: list[str] = field(default_factory=list)

    feature_vector: dict[str, float] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Regexes and vocabularies
# ---------------------------------------------------------------------------


_SCHEME_RE = re.compile(
    r"(?i)\b(?:https?|ftp|ftps|file|javascript|data|blob|ws|wss|"
    r"ms-msdt|ms-officecmd|ms-excel|ms-word|ms-powerpoint|"
    r"outlook|onenote|search|shell|vscode)://"
)

_URL_RE = re.compile(
    r"""(?ix)
    (?:
        (?P<scheme>
            https?://
            | ftp://
            | ftps://
            | file://
            | javascript:
            | data:
            | blob:
            | ws://
            | wss://
            | ms-[a-z0-9.+-]+:
            | outlook:
            | onenote:
            | search:
            | shell:
            | vscode:
        )
        [^\s<>"'`\]\[(){}]+
    )
    |
    (?:
        (?<![@\w.-])
        (?:
            (?:www\.)?
            (?:[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?)
            \.
            [a-z]{2,63}
        )
        (?::\d{1,5})?
        (?:/[^\s<>"'`\]\[(){}]*)?
    )
    |
    (?:
        https?%3a%2f%2f
        [^\s<>"'`\]\[(){}]+
    )
    """,
)

_IPV4_RE = re.compile(
    r"(?<![\w.])"
    r"(?:25[0-5]|2[0-4]\d|1?\d?\d)"
    r"(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}"
    r"(?![\w.])"
)

_IPV6_RE = re.compile(
    r"(?i)(?<![\w:])" r"\[?[0-9a-f]{0,4}(?::[0-9a-f]{1,4}){2,7}\]?" r"(?![\w:])"
)

_EMAIL_RE = re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,63}\b")

_DOMAIN_RE = re.compile(
    r"(?i)(?<![@\w.-])"
    r"(?:[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?)"
    r"\.[a-z]{2,63}"
    r"(?![\w.-])"
)

_PERCENT_ESCAPE_RE = re.compile(r"(?i)%[0-9a-f]{2}")
_HEX_ESCAPE_RE = re.compile(r"(?i)\\x[0-9a-f]{2}")
_UNICODE_ESCAPE_RE = re.compile(r"(?i)\\u[0-9a-f]{4}")

_BASE64_RE = re.compile(
    r"(?<![A-Za-z0-9+/=_-])" r"[A-Za-z0-9+/_-]{24,}={0,2}" r"(?![A-Za-z0-9+/=_-])"
)

_HEX_STRING_RE = re.compile(r"(?i)(?<![0-9a-f])(?:[0-9a-f]{2}){12,}(?![0-9a-f])")

_PORT_RE = re.compile(r":(\d{1,5})(?:/|$)")

_REDIRECT_PARAM_RE = re.compile(
    r"(?i)(?:^|[?&])"
    r"(?:url|uri|u|target|dest|destination|redirect|redirect_uri|"
    r"redirect_url|next|continue|return|returnurl|return_url|"
    r"link|linkurl|goto|go|r|to)="
)

_TRACKING_PARAM_RE = re.compile(
    r"(?i)(?:^|[?&])"
    r"(?:utm_[a-z0-9_]+|gclid|dclid|fbclid|msclkid|mc_cid|mc_eid|"
    r"ref|referrer|affiliate|aff_id|campaign|source|medium)="
)

_CREDENTIAL_PARAM_RE = re.compile(
    r"(?i)(?:^|[?&])"
    r"(?:user|username|login|email|e-mail|password|passwd|pass|"
    r"pwd|token|auth|authorization|session|sid|credential|credentials)="
)

_DOWNLOAD_PARAM_RE = re.compile(
    r"(?i)(?:^|[?&])"
    r"(?:download|download_url|file|filename|attachment|attach|"
    r"payload|package|installer|setup|update|document)="
)

_NESTED_URL_RE = re.compile(r"(?i)(?:https?%3a%2f%2f|https?://|ftp%3a%2f%2f|ftp://)")

_URL_ENCODED_SCHEME_RE = re.compile(r"(?i)(?:https?%3a%2f%2f|https?%253a%252f%252f)")

_USERNAME_PASSWORD_RE = re.compile(r"^[^/?#\s]+:[^/?#\s]+@")

_JAVASCRIPT_SCHEME_RE = re.compile(r"(?i)^javascript:")
_DATA_SCHEME_RE = re.compile(r"(?i)^data:")
_FILE_SCHEME_RE = re.compile(r"(?i)^file:")
_BLOB_SCHEME_RE = re.compile(r"(?i)^blob:")

_SUSPICIOUS_EXTENSION_RE = re.compile(
    r"(?i)\.(?:exe|scr|com|pif|bat|cmd|ps1|psm1|vbs|vbe|js|jse|"
    r"wsf|wsh|hta|dll|msi|msp|cpl|jar|lnk|iso|img|cab|zip|rar|7z|"
    r"docm|xlsm|pptm|xlam|dotm|xltm)(?:$|[?#])"
)

_ARCHIVE_EXTENSION_RE = re.compile(
    r"(?i)\.(?:zip|rar|7z|gz|gzip|tar|cab|iso|img|arj|ace)(?:$|[?#])"
)

_DOCUMENT_EXTENSION_RE = re.compile(
    r"(?i)\.(?:doc|docx|docm|dot|dotm|xls|xlsx|xlsm|xlt|xltm|ppt|pptx|"
    r"pptm|pdf|rtf|one|pub)(?:$|[?#])"
)

_EXECUTABLE_EXTENSION_RE = re.compile(
    r"(?i)\.(?:exe|scr|com|pif|bat|cmd|ps1|vbs|vbe|js|jse|wsf|wsh|"
    r"hta|dll|msi|msp|cpl|jar)(?:$|[?#])"
)

_WINDOWS_PATH_RE = re.compile(r"(?i)(?:[a-z]:\\|\\\\)[^\s<>\"']{2,}")

_LOCALHOST_RE = re.compile(r"(?i)^(?:localhost|localhost\.[a-z0-9.-]+)$")

_SUSPICIOUS_HOST_TOKEN_RE = re.compile(
    r"(?i)(?:login|signin|verify|verification|secure|security|"
    r"account|update|confirm|authentication|auth|wallet|payment|"
    r"invoice|document|share|onedrive|microsoft|office365|"
    r"outlook|appleid|icloud|paypal|docusign|dropbox|drive)"
)

_RANDOMIZED_SUBDOMAIN_RE = re.compile(r"(?i)^[a-z0-9]{12,}$")

_NUMERIC_HOST_LABEL_RE = re.compile(r"^\d{4,}$")

_HIGH_RISK_TLD_RE = re.compile(
    r"(?i)\.(?:zip|mov|click|download|top|xyz|tk|ml|ga|cf|gq|"
    r"work|party|loan|country|stream|win|review|support|"
    r"rest|fit|cam|live|buzz|icu|monster|cyou)$"
)

_SHORTENER_DOMAINS = frozenset(
    {
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "goo.gl",
        "ow.ly",
        "is.gd",
        "buff.ly",
        "rebrand.ly",
        "cutt.ly",
        "shorturl.at",
        "tiny.cc",
        "lnkd.in",
        "rb.gy",
        "s.id",
        "v.gd",
        "trib.al",
    }
)

_REDIRECTOR_DOMAINS = frozenset(
    {
        "google.com",
        "www.google.com",
        "googleusercontent.com",
        "bing.com",
        "www.bing.com",
        "facebook.com",
        "www.facebook.com",
        "linkedin.com",
        "www.linkedin.com",
        "youtube.com",
        "www.youtube.com",
        "doubleclick.net",
        "googleadservices.com",
    }
)

_CLOUD_HOSTS = frozenset(
    {
        "drive.google.com",
        "docs.google.com",
        "storage.googleapis.com",
        "onedrive.live.com",
        "1drv.ms",
        "sharepoint.com",
        "dropbox.com",
        "dropboxusercontent.com",
        "box.com",
        "boxusercontent.com",
        "mega.nz",
    }
)

_PUBLIC_FILE_HOSTS = frozenset(
    {
        "mediafire.com",
        "sendspace.com",
        "4shared.com",
        "mega.nz",
        "dropbox.com",
        "drive.google.com",
        "onedrive.live.com",
    }
)

_SUSPICIOUS_PORTS = frozenset(
    {
        21,
        22,
        23,
        25,
        53,
        110,
        111,
        135,
        139,
        143,
        389,
        443,
        445,
        465,
        587,
        993,
        995,
        1080,
        1433,
        1521,
        2049,
        2375,
        3306,
        3389,
        4444,
        5000,
        5432,
        5900,
        5985,
        5986,
        6379,
        8080,
        8443,
        9000,
        9200,
        27017,
    }
)

_EXECUTION_SCHEMES = frozenset(
    {
        "javascript",
        "data",
        "file",
        "ms-msdt",
        "ms-officecmd",
        "ms-excel",
        "ms-word",
        "ms-powerpoint",
        "outlook",
        "onenote",
        "search",
        "shell",
    }
)

_PLATFORM_SCHEMES = {
    "ms-msdt": "windows",
    "ms-officecmd": "windows",
    "ms-excel": "windows",
    "ms-word": "windows",
    "ms-powerpoint": "windows",
    "outlook": "windows",
    "onenote": "windows",
    "shell": "windows",
    "vscode": "cross_platform",
}

_WINDOWS_HOST_TERMS = (
    "windows",
    "win32",
    "win64",
    "microsoft",
    "office",
    "onedrive",
    "sharepoint",
)

_LINUX_HOST_TERMS = (
    "linux",
    "ubuntu",
    "debian",
    "centos",
    "redhat",
    "fedora",
    "alpine",
)

_MACOS_HOST_TERMS = (
    "macos",
    "darwin",
    "apple",
    "icloud",
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _clamp(value: float, low: float = 0.0, high: float = 1.0) -> float:
    return max(low, min(high, value))


def _severity_rank(value: str) -> int:
    try:
        return SEVERITIES.index(value.lower())
    except ValueError:
        return 0


def _max_severity(values: Iterable[str]) -> str:
    best = "low"
    best_rank = -1

    for value in values:
        rank = _severity_rank(value)
        if rank > best_rank:
            best = value
            best_rank = rank

    return best


def _safe_text(value: Any, max_length: int = MAX_FIELD_TEXT) -> str:
    if value is None:
        return ""

    if isinstance(value, bytes):
        return value[:max_length].decode("utf-8", errors="replace")

    if isinstance(value, bytearray):
        return bytes(value[:max_length]).decode("utf-8", errors="replace")

    if isinstance(value, str):
        return value[:max_length]

    try:
        return str(value)[:max_length]
    except Exception:
        return ""


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def _entropy(text: str) -> float:
    if not text:
        return 0.0

    counts = Counter(text)
    length = len(text)

    entropy = 0.0
    for count in counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return round(entropy, 4)


def _normalize_whitespace(value: str) -> str:
    return re.sub(r"\s+", " ", value).strip()


def _strip_trailing_url_punctuation(value: str) -> str:
    value = value.strip()

    while value and value[-1] in ".,;:!?)]}>\"'":
        if value.endswith(")") and value.count("(") >= value.count(")"):
            break
        if value.endswith("]") and value.count("[") >= value.count("]"):
            break
        if value.endswith("}") and value.count("{") >= value.count("}"):
            break
        value = value[:-1]

    return value


def _decode_percent_limited(value: str) -> str:
    current = value

    for _ in range(MAX_DECODE_ATTEMPTS):
        if len(current) > MAX_DECODED_TEXT:
            current = current[:MAX_DECODED_TEXT]

        if "%" not in current:
            break

        try:
            decoded = urllib.parse.unquote(current)
        except Exception:
            break

        if decoded == current:
            break

        current = decoded

    return current[:MAX_DECODED_TEXT]


def _decode_base64_limited(value: str) -> Optional[str]:
    candidate = value.strip()

    if len(candidate) < 24 or len(candidate) > MAX_DECODED_TEXT:
        return None

    candidate = candidate.replace("-", "+").replace("_", "/")

    if not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", candidate):
        return None

    padding = (-len(candidate)) % 4
    candidate += "=" * padding

    try:
        decoded = base64.b64decode(candidate, validate=True)
    except (ValueError, binascii.Error):
        return None

    if not decoded:
        return None

    text = decoded.decode("utf-8", errors="replace")
    printable = sum(1 for char in text if char.isprintable() or char in "\r\n\t")

    if printable / max(1, len(text)) < 0.65:
        return None

    return text[:MAX_DECODED_TEXT]


def _is_ip_address(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def _ip_properties(host: str) -> tuple[bool, bool, bool]:
    try:
        ip = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False, False, False

    return ip.is_private, ip.is_loopback, ip.is_unspecified


def _registrable_domain(host: str) -> str:
    """
    Lightweight registrable-domain approximation.

    This intentionally avoids a public-suffix database so that the extractor
    remains dependency-free and deterministic. It should not be treated as a
    perfect PSL implementation.
    """
    host = host.strip(".").lower()

    if not host:
        return ""

    if _is_ip_address(host):
        return host

    labels = [label for label in host.split(".") if label]

    if len(labels) <= 2:
        return ".".join(labels)

    common_two_level_suffixes = {
        "co.uk",
        "org.uk",
        "ac.uk",
        "gov.uk",
        "com.au",
        "net.au",
        "org.au",
        "co.jp",
        "co.in",
        "com.br",
        "com.cn",
        "com.sg",
        "co.nz",
        "co.za",
    }

    suffix = ".".join(labels[-2:])

    if suffix in common_two_level_suffixes and len(labels) >= 3:
        return ".".join(labels[-3:])

    return ".".join(labels[-2:])


def _host_subdomain_count(host: str) -> int:
    host = host.strip(".")
    if not host or _is_ip_address(host):
        return 0

    labels = [label for label in host.split(".") if label]

    if len(labels) <= 2:
        return 0

    return max(0, len(labels) - 2)


def _path_component_count(path: str) -> int:
    return len([part for part in path.split("/") if part])


def _query_parameter_count(query: str) -> int:
    if not query:
        return 0

    try:
        return len(
            [
                part
                for part in urllib.parse.parse_qsl(
                    query,
                    keep_blank_values=True,
                    strict_parsing=False,
                )
            ]
        )
    except Exception:
        return query.count("&") + 1


def _looks_unicode(value: str) -> bool:
    return any(ord(char) > 127 for char in value)


def _looks_punycode(host: str) -> bool:
    return any(label.lower().startswith("xn--") for label in host.split("."))


def _extract_port(netloc: str) -> Optional[int]:
    try:
        parsed = urllib.parse.urlsplit(
            "http://" + netloc if "://" not in netloc else netloc
        )
        return parsed.port
    except (ValueError, TypeError):
        match = _PORT_RE.search(netloc)
        if match:
            try:
                return int(match.group(1))
            except ValueError:
                return None

    return None


def _infer_platform(url: str, scheme: str, host: str) -> str:
    lower = f"{scheme}://{host}".lower()

    if scheme in _PLATFORM_SCHEMES:
        return _PLATFORM_SCHEMES[scheme]

    if scheme in {"file", "javascript"}:
        return "cross_platform"

    if any(term in lower for term in _WINDOWS_HOST_TERMS):
        return "windows"

    if any(term in lower for term in _LINUX_HOST_TERMS):
        return "linux"

    if any(term in lower for term in _MACOS_HOST_TERMS):
        return "macos"

    return "cross_platform"


def _normalize_scheme(scheme: str) -> str:
    return scheme.lower().rstrip(":")


def _ensure_scheme(value: str) -> str:
    if "://" in value:
        return value

    if re.match(r"(?i)^[a-z][a-z0-9+.-]*:", value):
        return value

    return "http://" + value


def _looks_like_url(value: str) -> bool:
    value = value.strip()

    if not value:
        return False

    if _SCHEME_RE.search(value):
        return True

    if _IPV4_RE.fullmatch(value):
        return True

    if _DOMAIN_RE.fullmatch(value):
        return True

    if _DOMAIN_RE.search(value):
        return True

    return False


# ---------------------------------------------------------------------------
# Source normalization
# ---------------------------------------------------------------------------


def _read_source(source: Any) -> tuple[str, int, str]:
    """
    Convert arbitrary input into bounded text.

    Returns:
        text, source_size, source_hash
    """
    if source is None:
        return "", 0, _sha256_text("")

    if isinstance(source, Path):
        try:
            size = source.stat().st_size
            if size > MAX_SOURCE_SIZE:
                raise ValueError(
                    f"Source exceeds MAX_SOURCE_SIZE ({MAX_SOURCE_SIZE} bytes)"
                )

            data = source.read_bytes()
            return (
                data[:MAX_SOURCE_SIZE].decode("utf-8", errors="replace"),
                len(data),
                _sha256_bytes(data),
            )
        except OSError:
            return "", 0, _sha256_text("")

    if isinstance(source, os.PathLike):
        return _read_source(Path(source))

    if isinstance(source, bytes):
        data = source[:MAX_SOURCE_SIZE]
        return (
            data.decode("utf-8", errors="replace"),
            len(data),
            _sha256_bytes(data),
        )

    if isinstance(source, bytearray):
        data = bytes(source[:MAX_SOURCE_SIZE])
        return (
            data.decode("utf-8", errors="replace"),
            len(data),
            _sha256_bytes(data),
        )

    if isinstance(source, str):
        text = source[:MAX_TEXT_CHARS]
        return text, len(source.encode("utf-8", errors="replace")), _sha256_text(text)

    return _flatten_source(source)


def _flatten_source(source: Any) -> tuple[str, int, str]:
    """
    Safely flatten nested mappings/sequences into searchable text.

    Values are bounded and recursion is capped.
    """
    pieces: list[str] = []
    total_size = 0
    seen: set[int] = set()

    def visit(value: Any, depth: int, field_name: str = "") -> None:
        nonlocal total_size

        if len(pieces) >= MAX_URLS:
            return

        if depth > MAX_NESTING_DEPTH:
            return

        if value is None:
            return

        if isinstance(value, (str, bytes, bytearray, Path, os.PathLike)):
            text = _safe_text(value, MAX_FIELD_TEXT)

            if field_name:
                pieces.append(f"{field_name}: {text}")
            else:
                pieces.append(text)

            total_size += len(text.encode("utf-8", errors="replace"))
            return

        object_id = id(value)

        if object_id in seen:
            return

        if isinstance(value, Mapping):
            seen.add(object_id)

            for key, item in value.items():
                key_text = _safe_text(key, 512)
                visit(item, depth + 1, key_text)

            return

        if isinstance(value, Sequence) and not isinstance(
            value,
            (str, bytes, bytearray),
        ):
            seen.add(object_id)

            for index, item in enumerate(value):
                visit(item, depth + 1, str(index))

            return

        if hasattr(value, "__dict__"):
            seen.add(object_id)

            try:
                attributes = vars(value)
            except Exception:
                attributes = {}

            if isinstance(attributes, Mapping):
                for key, item in attributes.items():
                    visit(item, depth + 1, _safe_text(key, 512))

            return

        text = _safe_text(value, MAX_FIELD_TEXT)
        if text:
            pieces.append(text)
            total_size += len(text.encode("utf-8", errors="replace"))

    visit(source, 0)

    text = "\n".join(pieces)

    if len(text) > MAX_TEXT_CHARS:
        text = text[:MAX_TEXT_CHARS]

    return text, min(total_size, MAX_SOURCE_SIZE), _sha256_text(text)


# ---------------------------------------------------------------------------
# URL extraction
# ---------------------------------------------------------------------------


def extract_urls(
    source: Any,
    *,
    max_urls: int = MAX_URLS,
) -> list[tuple[str, Optional[int], Optional[str]]]:
    """
    Extract URL-like strings.

    Returns tuples:
        (url, line_number, source_field)
    """
    text, _, _ = _read_source(source)

    if not text:
        return []

    results: list[tuple[str, Optional[int], Optional[str]]] = []
    seen: set[str] = set()

    lines = text.splitlines()

    for line_number, line in enumerate(lines, start=1):
        if len(results) >= max_urls:
            break

        for match in _URL_RE.finditer(line):
            if len(results) >= max_urls:
                break

            candidate = _strip_trailing_url_punctuation(match.group(0))

            if len(candidate) > MAX_URL_LENGTH:
                candidate = candidate[:MAX_URL_LENGTH]

            if not candidate:
                continue

            normalized_key = candidate.casefold()

            if normalized_key in seen:
                continue

            seen.add(normalized_key)

            field = None
            prefix = line[: match.start()]
            field_match = re.search(r"([A-Za-z_][A-Za-z0-9_.-]{0,128})\s*:", prefix)

            if field_match:
                field = field_match.group(1)

            results.append((candidate, line_number, field))

    return results


# ---------------------------------------------------------------------------
# URL parsing
# ---------------------------------------------------------------------------


def _parse_url(
    url: str,
    *,
    source: Optional[str] = None,
) -> URLRecord:
    original = _strip_trailing_url_punctuation(url)
    candidate = _ensure_scheme(original)

    decoded_candidate = _decode_percent_limited(candidate)

    try:
        parsed = urllib.parse.urlsplit(candidate)
    except ValueError:
        parsed = urllib.parse.urlsplit("http://" + candidate)

    scheme = _normalize_scheme(parsed.scheme)

    try:
        host = parsed.hostname or ""
    except ValueError:
        host = ""

    host = host.rstrip(".").lower()

    try:
        port = parsed.port
    except ValueError:
        port = _extract_port(parsed.netloc)

    path = parsed.path or ""
    query = parsed.query or ""
    fragment = parsed.fragment or ""

    username_present = parsed.username is not None
    password_present = parsed.password is not None

    is_ip = _is_ip_address(host)
    is_private_ip, is_loopback_ip, _ = _ip_properties(host)

    is_localhost = bool(_LOCALHOST_RE.fullmatch(host))

    is_punycode = _looks_punycode(host)
    has_unicode = _looks_unicode(original)

    subdomain_count = _host_subdomain_count(host)
    path_component_count = _path_component_count(path)
    query_parameter_count = _query_parameter_count(query)

    entropy = _entropy(
        "".join(
            [
                host,
                path,
                query,
            ]
        )[:MAX_DECODED_TEXT]
    )

    categories: set[str] = set()
    indicators: list[str] = []
    evidence: list[str] = []

    def add(
        category: str,
        indicator: str,
        evidence_text: str,
    ) -> None:
        categories.add(category)

        if indicator not in indicators:
            indicators.append(indicator)

        if evidence_text not in evidence:
            evidence.append(evidence_text)

    if scheme:
        categories.add("scheme")

    if host:
        categories.add("domain")

    if is_ip:
        add(
            "ip_address",
            "ip_literal",
            f"URL uses IP address host: {host}",
        )

    if port is not None:
        categories.add("port")

        if port in _SUSPICIOUS_PORTS or port >= HIGH_PORT_THRESHOLD:
            add(
                "suspicious_port",
                "non_standard_or_sensitive_port",
                f"URL uses port {port}",
            )

    if path:
        categories.add("path")

    if query:
        categories.add("query")

    if fragment:
        categories.add("fragment")

    if username_present or password_present:
        add(
            "userinfo",
            "url_userinfo",
            "URL contains userinfo before the host",
        )

    if is_private_ip or is_loopback_ip or is_localhost:
        add(
            "local_network",
            "private_or_loopback_target",
            f"URL targets local/private host: {host}",
        )

    if _JAVASCRIPT_SCHEME_RE.match(original):
        add(
            "javascript_scheme",
            "javascript_scheme",
            "URL uses the javascript: scheme",
        )

        add(
            "execution",
            "scriptable_url",
            "URL scheme can represent executable script content",
        )

    if _DATA_SCHEME_RE.match(original):
        add(
            "data_scheme",
            "data_scheme",
            "URL uses the data: scheme",
        )

        add(
            "execution",
            "embedded_content_scheme",
            "URL contains an embedded data payload",
        )

    if _FILE_SCHEME_RE.match(original):
        add(
            "file_scheme",
            "file_scheme",
            "URL uses the file: scheme",
        )

    if scheme in _EXECUTION_SCHEMES:
        add(
            "dangerous_scheme",
            "non_http_execution_scheme",
            f"URL uses potentially actionable scheme: {scheme}",
        )

    if _BLOB_SCHEME_RE.match(original):
        add(
            "remote_resource",
            "blob_scheme",
            "URL uses the blob: scheme",
        )

    if _URL_ENCODED_SCHEME_RE.search(original):
        add(
            "encoded_url",
            "encoded_scheme",
            "URL contains an encoded URL scheme",
        )

    percent_count = len(_PERCENT_ESCAPE_RE.findall(original))

    if percent_count >= 3:
        add(
            "encoding",
            "percent_encoding",
            f"URL contains {percent_count} percent-encoded sequences",
        )

    if _HEX_ESCAPE_RE.search(original) or _UNICODE_ESCAPE_RE.search(original):
        add(
            "encoding",
            "escape_encoding",
            "URL contains hexadecimal or Unicode escape sequences",
        )

    if _BASE64_RE.search(query) or _BASE64_RE.search(path):
        add(
            "encoding",
            "base64_like_content",
            "URL path or query contains base64-like content",
        )

    if _HEX_STRING_RE.search(query) or _HEX_STRING_RE.search(path):
        add(
            "encoding",
            "hex_encoded_content",
            "URL path or query contains long hexadecimal content",
        )

    if _NESTED_URL_RE.search(decoded_candidate):
        nested_matches = list(
            _NESTED_URL_RE.finditer(decoded_candidate[:MAX_QUERY_LENGTH])
        )

        if len(nested_matches) > 1 or (percent_count >= 2 and nested_matches):
            add(
                "nested_url",
                "nested_url",
                "URL contains another URL or encoded nested URL",
            )

    if _REDIRECT_PARAM_RE.search(query):
        add(
            "redirector",
            "redirect_parameter",
            "URL contains a redirect-style parameter",
        )

    if _TRACKING_PARAM_RE.search(query):
        add(
            "tracking",
            "tracking_parameter",
            "URL contains common tracking parameters",
        )

    if _CREDENTIAL_PARAM_RE.search(query):
        add(
            "credential_collection",
            "credential_parameter",
            "URL contains credential/authentication-related parameters",
        )

    if _DOWNLOAD_PARAM_RE.search(query):
        add(
            "download",
            "download_parameter",
            "URL contains a download or payload-style parameter",
        )

    if _SUSPICIOUS_EXTENSION_RE.search(path):
        add(
            "suspicious_extension",
            "executable_or_active_extension",
            f"URL path ends with an active or executable extension: {path}",
        )

        add(
            "malware_delivery",
            "active_content_extension",
            "URL references an executable or active-content file extension",
        )

    if _ARCHIVE_EXTENSION_RE.search(path):
        add(
            "archive_or_payload",
            "archive_extension",
            "URL references an archive or disk-image style extension",
        )

    if _DOCUMENT_EXTENSION_RE.search(path):
        add(
            "remote_resource",
            "document_resource",
            "URL references a document-like resource",
        )

    if _EXECUTABLE_EXTENSION_RE.search(path):
        add(
            "execution",
            "executable_resource",
            "URL references a directly executable resource",
        )

    if _HIGH_RISK_TLD_RE.search(host):
        add(
            "suspicious_tld",
            "high_risk_tld",
            f"Host uses a TLD commonly associated with higher-risk abuse: {host}",
        )

    if is_punycode:
        add(
            "punycode",
            "punycode_hostname",
            f"Hostname contains Punycode labels: {host}",
        )

    if has_unicode:
        add(
            "unicode_domain",
            "unicode_url",
            "URL contains non-ASCII Unicode characters",
        )

    if subdomain_count >= MANY_SUBDOMAINS_THRESHOLD:
        add(
            "domain",
            "many_subdomains",
            f"URL contains {subdomain_count} subdomain levels",
        )

    if any(
        _RANDOMIZED_SUBDOMAIN_RE.fullmatch(label or "") for label in host.split(".")
    ):
        add(
            "dynamic_host",
            "randomized_host_label",
            "Hostname contains a long alphanumeric label",
        )

    if any(_NUMERIC_HOST_LABEL_RE.fullmatch(label or "") for label in host.split(".")):
        add(
            "dynamic_host",
            "numeric_host_label",
            "Hostname contains a long numeric label",
        )

    if _SUSPICIOUS_HOST_TOKEN_RE.search(host):
        add(
            "phishing",
            "security_or_account_host_token",
            f"Hostname contains account/security-oriented terminology: {host}",
        )

    if host in _SHORTENER_DOMAINS:
        add(
            "shortener",
            "known_url_shortener",
            f"URL uses known shortening service: {host}",
        )

    registrable = _registrable_domain(host)

    if registrable in _REDIRECTOR_DOMAINS:
        if _REDIRECT_PARAM_RE.search(query):
            add(
                "redirector",
                "known_redirector",
                f"URL uses a known redirect-capable host: {registrable}",
            )

    if registrable in _CLOUD_HOSTS or host in _CLOUD_HOSTS:
        add(
            "cloud_storage",
            "cloud_storage_host",
            f"URL uses a cloud-storage provider: {host}",
        )

    if registrable in _PUBLIC_FILE_HOSTS or host in _PUBLIC_FILE_HOSTS:
        add(
            "public_file_hosting",
            "public_file_host",
            f"URL uses a public file-hosting service: {host}",
        )

    if len(original) >= LONG_URL_THRESHOLD:
        add(
            "excessive_length",
            "long_url",
            f"URL length is {len(original)} characters",
        )

    if len(original) >= VERY_LONG_URL_THRESHOLD:
        add(
            "excessive_length",
            "very_long_url",
            f"URL length is {len(original)} characters",
        )

    if len(host) >= LONG_HOST_THRESHOLD:
        add(
            "excessive_length",
            "long_host",
            f"Hostname length is {len(host)} characters",
        )

    if len(path) >= LONG_PATH_THRESHOLD:
        add(
            "dynamic_path",
            "long_path",
            f"URL path length is {len(path)} characters",
        )

    if len(query) >= LONG_QUERY_THRESHOLD:
        add(
            "dynamic_path",
            "long_query",
            f"URL query length is {len(query)} characters",
        )

    if query_parameter_count >= MANY_QUERY_PARAMETERS_THRESHOLD:
        add(
            "excessive_parameters",
            "many_query_parameters",
            f"URL contains {query_parameter_count} query parameters",
        )

    if entropy >= HIGH_ENTROPY_THRESHOLD:
        add(
            "high_entropy",
            "high_entropy_url",
            f"URL structural content has entropy {entropy:.3f}",
        )

    if entropy >= VERY_HIGH_ENTROPY_THRESHOLD:
        add(
            "high_entropy",
            "very_high_entropy_url",
            f"URL structural content has entropy {entropy:.3f}",
        )

    decoded_lower = decoded_candidate.lower()

    if any(
        token in decoded_lower
        for token in (
            "powershell",
            "cmd.exe",
            "wscript",
            "cscript",
            "mshta",
            "rundll32",
            "regsvr32",
            "msiexec",
        )
    ):
        add(
            "execution",
            "execution_tool_reference",
            "URL references a command/script execution utility",
        )

    if any(
        token in decoded_lower
        for token in (
            "download",
            "payload",
            "installer",
            "setup",
            "update.exe",
            "dropper",
        )
    ):
        add(
            "download",
            "download_or_payload_term",
            "URL contains download or payload terminology",
        )

    if any(
        token in decoded_lower
        for token in (
            "login",
            "signin",
            "verify",
            "verification",
            "password",
            "credential",
            "session",
            "authenticate",
        )
    ):
        add(
            "phishing",
            "credential_lure_term",
            "URL contains credential/authentication lure terminology",
        )

    if any(
        token in decoded_lower
        for token in (
            "webhook",
            "callback",
            "c2",
            "command",
            "beacon",
            "panel",
        )
    ):
        add(
            "command_control",
            "c2_or_callback_term",
            "URL contains command/control or callback terminology",
        )

    platform = _infer_platform(original, scheme, host)

    # Severity is deliberately conservative. A single structural anomaly
    # should generally remain low/medium.
    if any(
        category in categories
        for category in (
            "javascript_scheme",
            "data_scheme",
            "dangerous_scheme",
        )
    ):
        severity = "high"
    elif any(
        category in categories
        for category in (
            "execution",
            "malware_delivery",
            "credential_collection",
        )
    ) and any(
        category in categories
        for category in (
            "encoding",
            "obfuscation",
            "nested_url",
            "phishing",
        )
    ):
        severity = "high"
    elif any(
        category in categories
        for category in (
            "execution",
            "malware_delivery",
            "credential_collection",
            "command_control",
        )
    ):
        severity = "medium"
    elif len(categories) >= 4:
        severity = "medium"
    else:
        severity = "low"

    confidence = 0.70

    if is_ip:
        confidence += 0.05

    if scheme in {"http", "https"}:
        confidence += 0.05

    if categories.intersection(
        {
            "javascript_scheme",
            "data_scheme",
            "execution",
            "malware_delivery",
        }
    ):
        confidence += 0.10

    confidence = _clamp(confidence)

    normalized = candidate.lower()

    return URLRecord(
        url=original,
        normalized_url=normalized,
        scheme=scheme,
        host=host,
        registrable_domain=registrable,
        port=port,
        path=path,
        query=query,
        fragment=fragment,
        username_present=username_present,
        password_present=password_present,
        is_ip_address=is_ip,
        is_private_ip=is_private_ip,
        is_loopback_ip=is_loopback_ip,
        is_localhost=is_localhost,
        is_punycode=is_punycode,
        has_unicode=has_unicode,
        subdomain_count=subdomain_count,
        path_component_count=path_component_count,
        query_parameter_count=query_parameter_count,
        url_length=len(original),
        host_length=len(host),
        path_length=len(path),
        query_length=len(query),
        entropy=entropy,
        categories=tuple(sorted(categories)),
        indicators=tuple(indicators),
        severity=severity,
        confidence=confidence,
        evidence=tuple(evidence),
        source=source,
    )


# ---------------------------------------------------------------------------
# Evidence generation
# ---------------------------------------------------------------------------


def _operation_for_category(category: str, indicator: str) -> str:
    if category in {"redirector", "shortener"}:
        return "redirect"

    if category in {"encoding", "encoded_url", "obfuscation"}:
        return "obfuscate"

    if category in {"execution", "dangerous_scheme"}:
        return "execute"

    if category in {"download", "malware_delivery"}:
        return "download"

    if category == "credential_collection":
        return "collect"

    if category == "command_control":
        return "communicate"

    if category in {"phishing"}:
        return "lure"

    if category in {"tracking"}:
        return "track"

    if category in {"cloud_storage", "public_file_hosting"}:
        return "host"

    if category in {"local_network"}:
        return "access"

    if category == "high_entropy":
        return "obfuscate"

    if category == "nested_url":
        return "redirect"

    return "detect"


def _evidence_from_record(
    record: URLRecord,
    *,
    line_number: Optional[int],
    field: Optional[str],
) -> list[URLEvidence]:
    results: list[URLEvidence] = []

    for index, indicator in enumerate(record.indicators):
        category = (
            record.categories[index] if index < len(record.categories) else "unknown"
        )

        # The mapping above is not necessarily one-to-one because categories
        # and indicators are independent sets. Find a better category by
        # semantic indicator matching.
        indicator_lower = indicator.lower()

        if "javascript" in indicator_lower:
            category = "javascript_scheme"
        elif "data_scheme" in indicator_lower:
            category = "data_scheme"
        elif "executable" in indicator_lower or "execution" in indicator_lower:
            category = "execution"
        elif "credential" in indicator_lower:
            category = "credential_collection"
        elif "phishing" in indicator_lower or "lure" in indicator_lower:
            category = "phishing"
        elif "redirect" in indicator_lower or "nested_url" in indicator_lower:
            category = "redirector"
        elif "encoding" in indicator_lower or "base64" in indicator_lower:
            category = "encoding"
        elif "punycode" in indicator_lower:
            category = "punycode"
        elif "unicode" in indicator_lower:
            category = "unicode_domain"
        elif "shortener" in indicator_lower:
            category = "shortener"
        elif "download" in indicator_lower or "payload" in indicator_lower:
            category = "download"
        elif "command" in indicator_lower or "c2" in indicator_lower:
            category = "command_control"
        elif "private" in indicator_lower or "loopback" in indicator_lower:
            category = "local_network"
        elif "tracking" in indicator_lower:
            category = "tracking"
        elif "port" in indicator_lower:
            category = "suspicious_port"
        elif "entropy" in indicator_lower:
            category = "high_entropy"
        elif "subdomain" in indicator_lower:
            category = "domain"
        elif "extension" in indicator_lower:
            category = "suspicious_extension"

        severity = record.severity

        if indicator in {
            "javascript_scheme",
            "data_scheme",
            "embedded_content_scheme",
            "non_http_execution_scheme",
        }:
            severity = "high"

        if indicator in {
            "executable_resource",
            "active_content_extension",
            "credential_parameter",
        }:
            severity = "high"

        confidence = record.confidence

        results.append(
            URLEvidence(
                category=category,
                indicator=indicator,
                evidence=(
                    record.evidence[index]
                    if index < len(record.evidence)
                    else f"URL indicator: {indicator}"
                ),
                source="url",
                url=record.url,
                line_number=line_number,
                field=field,
                operation=_operation_for_category(category, indicator),
                target=record.host or None,
                platform=_infer_platform(
                    record.url,
                    record.scheme,
                    record.host,
                ),
                confidence=confidence,
                severity=severity,
            )
        )

    return results


# ---------------------------------------------------------------------------
# Combinations
# ---------------------------------------------------------------------------


def _derive_combinations(
    records: Sequence[URLRecord],
    evidence: Sequence[URLEvidence],
) -> list[URLCombination]:
    categories = {category for record in records for category in record.categories}

    indicators = {indicator for record in records for indicator in record.indicators}

    combinations: list[URLCombination] = []

    def add(
        name: str,
        required: Iterable[str],
        explanation: str,
        *,
        present: bool,
    ) -> None:
        combinations.append(
            URLCombination(
                name=name,
                present=present,
                required_categories=tuple(required),
                explanation=explanation,
            )
        )

    add(
        "encoded_redirect_chain",
        ("encoding", "redirector"),
        "Encoded content combined with redirect behavior can conceal the final destination.",
        present=("encoding" in categories and "redirector" in categories),
    )

    add(
        "shortened_redirect_chain",
        ("shortener", "redirector"),
        "A shortened URL combined with redirect parameters obscures the eventual destination.",
        present=("shortener" in categories and "redirector" in categories),
    )

    add(
        "phishing_redirect",
        ("phishing", "redirector"),
        "Credential-oriented terminology combined with redirection is a stronger phishing signal.",
        present=("phishing" in categories and "redirector" in categories),
    )

    add(
        "credential_download",
        ("credential_collection", "download"),
        "Credential-related parameters combined with download behavior may indicate a malicious lure or delivery flow.",
        present=("credential_collection" in categories and "download" in categories),
    )

    add(
        "encoded_execution",
        ("encoding", "execution"),
        "Encoded URL content combined with executable behavior can conceal an actionable payload or script.",
        present=("encoding" in categories and "execution" in categories),
    )

    add(
        "execution_delivery",
        ("download", "execution"),
        "A URL associated with both downloading and execution is a stronger delivery signal.",
        present=("download" in categories and "execution" in categories),
    )

    add(
        "nested_encoded_url",
        ("nested_url", "encoding"),
        "Nested URLs combined with encoding can obscure the final destination.",
        present=("nested_url" in categories and "encoding" in categories),
    )

    add(
        "active_content_delivery",
        ("malware_delivery", "suspicious_extension"),
        "An active-content extension combined with malware-delivery evidence indicates a potentially risky remote resource.",
        present=(
            "malware_delivery" in categories and "suspicious_extension" in categories
        ),
    )

    add(
        "ip_based_delivery",
        ("ip_address", "download"),
        "A direct IP address combined with download behavior can indicate infrastructure used for payload delivery.",
        present=("ip_address" in categories and "download" in categories),
    )

    add(
        "high_entropy_obfuscation",
        ("high_entropy", "encoding"),
        "High entropy combined with encoding is consistent with concealed URL content.",
        present=("high_entropy" in categories and "encoding" in categories),
    )

    add(
        "cloud_payload_delivery",
        ("cloud_storage", "download"),
        "Cloud storage combined with download behavior can be used for benign file sharing or payload delivery and therefore requires correlation.",
        present=("cloud_storage" in categories and "download" in categories),
    )

    add(
        "command_control_indicator",
        ("command_control", "remote_resource"),
        "Command/control terminology combined with a remote resource is a stronger network-behavior indicator.",
        present=("command_control" in categories and "remote_resource" in categories),
    )

    add(
        "multi_signal_url",
        (
            "encoding",
            "redirector",
            "phishing",
            "execution",
            "malware_delivery",
            "credential_collection",
        ),
        "Multiple independent URL-risk categories occur together.",
        present=sum(
            category in categories
            for category in (
                "encoding",
                "redirector",
                "phishing",
                "execution",
                "malware_delivery",
                "credential_collection",
            )
        )
        >= 3,
    )

    # Prevent an unused-variable warning in implementations that inspect
    # evidence programmatically.
    _ = indicators
    _ = evidence

    return combinations


# ---------------------------------------------------------------------------
# Feature vectors
# ---------------------------------------------------------------------------


def _feature_prefix_names() -> list[str]:
    names = [
        "source_size",
        "record_count",
        "evidence_count",
        "domain_count",
        "host_count",
        "scheme_count",
        "indicator_count",
        "category_count",
        "combination_count",
        "high_count",
        "critical_count",
        "ip_count",
        "private_ip_count",
        "loopback_count",
        "localhost_count",
        "punycode_count",
        "unicode_count",
        "userinfo_count",
        "username_count",
        "password_count",
        "shortener_count",
        "redirector_count",
        "tracking_count",
        "download_count",
        "execution_count",
        "credential_count",
        "phishing_count",
        "malware_delivery_count",
        "command_control_count",
        "cloud_storage_count",
        "public_file_host_count",
        "suspicious_port_count",
        "encoded_count",
        "nested_url_count",
        "high_entropy_count",
        "long_url_count",
        "very_long_url_count",
        "long_host_count",
        "long_path_count",
        "long_query_count",
        "many_parameter_count",
        "many_subdomain_count",
        "suspicious_extension_count",
        "archive_count",
        "document_count",
        "average_url_length",
        "maximum_url_length",
        "average_host_length",
        "maximum_host_length",
        "average_entropy",
        "maximum_entropy",
        "average_query_parameters",
        "maximum_query_parameters",
        "average_path_components",
        "maximum_path_components",
        "windows_count",
        "linux_count",
        "macos_count",
        "cross_platform_count",
        "detect_count",
        "redirect_count",
        "execute_count",
        "download_operation_count",
        "collect_count",
        "communicate_count",
        "lure_count",
        "obfuscate_count",
        "host_operation_count",
        "signal_score",
    ]

    return names


def url_feature_names() -> list[str]:
    """
    Return the complete stable feature-vector schema.

    The order is deterministic and suitable for ML pipelines.
    """
    names = list(_feature_prefix_names())

    names.extend(f"category_present__{category}" for category in URL_CATEGORIES)

    names.extend(f"category_count__{category}" for category in URL_CATEGORIES)

    indicator_names = [
        "ip_literal",
        "private_or_loopback_target",
        "url_userinfo",
        "non_standard_or_sensitive_port",
        "javascript_scheme",
        "data_scheme",
        "file_scheme",
        "non_http_execution_scheme",
        "blob_scheme",
        "encoded_scheme",
        "percent_encoding",
        "escape_encoding",
        "base64_like_content",
        "hex_encoded_content",
        "nested_url",
        "redirect_parameter",
        "tracking_parameter",
        "credential_parameter",
        "download_parameter",
        "executable_or_active_extension",
        "active_content_extension",
        "archive_extension",
        "document_resource",
        "executable_resource",
        "high_risk_tld",
        "punycode_hostname",
        "unicode_url",
        "many_subdomains",
        "randomized_host_label",
        "numeric_host_label",
        "security_or_account_host_token",
        "known_url_shortener",
        "known_redirector",
        "cloud_storage_host",
        "public_file_host",
        "long_url",
        "very_long_url",
        "long_host",
        "long_path",
        "long_query",
        "many_query_parameters",
        "high_entropy_url",
        "very_high_entropy_url",
        "execution_tool_reference",
        "download_or_payload_term",
        "credential_lure_term",
        "c2_or_callback_term",
        "document_resource",
    ]

    # Preserve order while removing accidental duplicates.
    indicator_names = list(dict.fromkeys(indicator_names))

    names.extend(f"indicator_present__{indicator}" for indicator in indicator_names)

    names.extend(f"indicator_count__{indicator}" for indicator in indicator_names)

    combination_names = [
        "encoded_redirect_chain",
        "shortened_redirect_chain",
        "phishing_redirect",
        "credential_download",
        "encoded_execution",
        "execution_delivery",
        "nested_encoded_url",
        "active_content_delivery",
        "ip_based_delivery",
        "high_entropy_obfuscation",
        "cloud_payload_delivery",
        "command_control_indicator",
        "multi_signal_url",
    ]

    names.extend(f"combination_present__{name}" for name in combination_names)

    return names


def _indicator_names() -> list[str]:
    prefix = "indicator_present__"
    return [
        name[len(prefix) :] for name in url_feature_names() if name.startswith(prefix)
    ]


def _combination_names() -> list[str]:
    prefix = "combination_present__"
    return [
        name[len(prefix) :] for name in url_feature_names() if name.startswith(prefix)
    ]


def _build_feature_vector(
    analysis: URLAnalysis,
) -> dict[str, float]:
    records = analysis.records

    features: dict[str, float] = {name: 0.0 for name in url_feature_names()}

    def set_value(name: str, value: float) -> None:
        if name in features:
            features[name] = float(value)

    set_value("source_size", analysis.source_size)
    set_value("record_count", len(records))
    set_value("evidence_count", len(analysis.evidence))
    set_value("domain_count", len(analysis.domains))
    set_value("host_count", len(analysis.hosts))
    set_value("scheme_count", len(analysis.schemes))
    set_value("indicator_count", len(analysis.indicators))
    set_value("category_count", len(analysis.categories))
    set_value("combination_count", len(analysis.combinations))

    set_value(
        "high_count",
        sum(
            _severity_rank(record.severity) >= _severity_rank("high")
            for record in records
        ),
    )

    set_value(
        "critical_count",
        sum(record.severity == "critical" for record in records),
    )

    set_value(
        "ip_count",
        sum(record.is_ip_address for record in records),
    )
    set_value(
        "private_ip_count",
        sum(record.is_private_ip for record in records),
    )
    set_value(
        "loopback_count",
        sum(record.is_loopback_ip for record in records),
    )
    set_value(
        "localhost_count",
        sum(record.is_localhost for record in records),
    )
    set_value(
        "punycode_count",
        sum(record.is_punycode for record in records),
    )
    set_value(
        "unicode_count",
        sum(record.has_unicode for record in records),
    )
    set_value(
        "userinfo_count",
        sum(record.username_present or record.password_present for record in records),
    )
    set_value(
        "username_count",
        sum(record.username_present for record in records),
    )
    set_value(
        "password_count",
        sum(record.password_present for record in records),
    )

    category_counter = Counter(
        category for record in records for category in record.categories
    )

    indicator_counter = Counter(
        indicator for record in records for indicator in record.indicators
    )

    operation_counter = Counter(evidence.operation for evidence in analysis.evidence)

    platform_counter = Counter(analysis.platforms)

    for category in URL_CATEGORIES:
        count = category_counter.get(category, 0)
        set_value(f"category_present__{category}", int(count > 0))
        set_value(f"category_count__{category}", count)

    for indicator in _indicator_names():
        count = indicator_counter.get(indicator, 0)
        set_value(f"indicator_present__{indicator}", int(count > 0))
        set_value(f"indicator_count__{indicator}", count)

    for combination in analysis.combinations:
        set_value(
            f"combination_present__{combination.name}",
            int(combination.present),
        )

    numeric_values = {
        "url_length": [record.url_length for record in records],
        "host_length": [record.host_length for record in records],
        "entropy": [record.entropy for record in records],
        "query_parameters": [record.query_parameter_count for record in records],
        "path_components": [record.path_component_count for record in records],
    }

    if records:
        set_value(
            "average_url_length",
            sum(numeric_values["url_length"]) / len(records),
        )
        set_value(
            "maximum_url_length",
            max(numeric_values["url_length"]),
        )

        set_value(
            "average_host_length",
            sum(numeric_values["host_length"]) / len(records),
        )
        set_value(
            "maximum_host_length",
            max(numeric_values["host_length"]),
        )

        set_value(
            "average_entropy",
            sum(numeric_values["entropy"]) / len(records),
        )
        set_value(
            "maximum_entropy",
            max(numeric_values["entropy"]),
        )

        set_value(
            "average_query_parameters",
            sum(numeric_values["query_parameters"]) / len(records),
        )
        set_value(
            "maximum_query_parameters",
            max(numeric_values["query_parameters"]),
        )

        set_value(
            "average_path_components",
            sum(numeric_values["path_components"]) / len(records),
        )
        set_value(
            "maximum_path_components",
            max(numeric_values["path_components"]),
        )

    set_value("shortener_count", category_counter["shortener"])
    set_value("redirector_count", category_counter["redirector"])
    set_value("tracking_count", category_counter["tracking"])
    set_value("download_count", category_counter["download"])
    set_value("execution_count", category_counter["execution"])
    set_value(
        "credential_count",
        category_counter["credential_collection"],
    )
    set_value("phishing_count", category_counter["phishing"])
    set_value(
        "malware_delivery_count",
        category_counter["malware_delivery"],
    )
    set_value(
        "command_control_count",
        category_counter["command_control"],
    )
    set_value(
        "cloud_storage_count",
        category_counter["cloud_storage"],
    )
    set_value(
        "public_file_host_count",
        category_counter["public_file_hosting"],
    )
    set_value(
        "suspicious_port_count",
        category_counter["suspicious_port"],
    )
    set_value(
        "encoded_count",
        category_counter["encoding"],
    )
    set_value(
        "nested_url_count",
        category_counter["nested_url"],
    )
    set_value(
        "high_entropy_count",
        category_counter["high_entropy"],
    )
    set_value(
        "long_url_count",
        indicator_counter["long_url"],
    )
    set_value(
        "very_long_url_count",
        indicator_counter["very_long_url"],
    )
    set_value(
        "long_host_count",
        indicator_counter["long_host"],
    )
    set_value(
        "long_path_count",
        indicator_counter["long_path"],
    )
    set_value(
        "long_query_count",
        indicator_counter["long_query"],
    )
    set_value(
        "many_parameter_count",
        indicator_counter["many_query_parameters"],
    )
    set_value(
        "many_subdomain_count",
        indicator_counter["many_subdomains"],
    )
    set_value(
        "suspicious_extension_count",
        category_counter["suspicious_extension"],
    )
    set_value(
        "archive_count",
        category_counter["archive_or_payload"],
    )
    set_value(
        "document_count",
        indicator_counter["document_resource"],
    )

    set_value(
        "windows_count",
        platform_counter["windows"],
    )
    set_value(
        "linux_count",
        platform_counter["linux"],
    )
    set_value(
        "macos_count",
        platform_counter["macos"],
    )
    set_value(
        "cross_platform_count",
        platform_counter["cross_platform"],
    )

    for operation in (
        "detect",
        "redirect",
        "execute",
        "download",
        "collect",
        "communicate",
        "lure",
        "obfuscate",
        "host",
    ):
        set_value(
            (
                f"{operation}_count"
                if operation != "download"
                else "download_operation_count"
            ),
            operation_counter[operation],
        )

    # Weighted signal score.
    category_weights = {
        "javascript_scheme": 3.0,
        "data_scheme": 3.0,
        "execution": 2.5,
        "malware_delivery": 2.5,
        "credential_collection": 2.5,
        "command_control": 2.5,
        "phishing": 2.0,
        "encoded_url": 1.5,
        "encoding": 1.0,
        "nested_url": 1.5,
        "redirector": 1.0,
        "shortener": 0.75,
        "suspicious_extension": 1.5,
        "suspicious_port": 1.0,
        "ip_address": 0.75,
        "punycode": 1.25,
        "unicode_domain": 1.25,
        "high_entropy": 0.75,
        "excessive_length": 0.5,
        "excessive_parameters": 0.5,
        "local_network": 0.5,
    }

    raw_score = 0.0

    for category, count in category_counter.items():
        raw_score += category_weights.get(category, 0.0) * min(count, 10)

    for combination in analysis.combinations:
        if combination.present:
            raw_score += 2.0

    # Normalize to approximately [0, 100].
    score = min(100.0, raw_score * 4.0)

    set_value("signal_score", round(score, 4))

    return features


def vectorize_features(
    features: Mapping[str, object],
) -> list[float]:
    """
    Convert a feature mapping to the stable URL feature-vector order.
    """
    return [float(features.get(name, 0.0) or 0.0) for name in url_feature_names()]


def build_feature_schema() -> dict[str, Any]:
    """
    Return ML-oriented metadata describing the stable feature vector.
    """
    names = url_feature_names()

    return {
        "name": "url_features",
        "version": "1.0",
        "feature_count": len(names),
        "feature_names": names,
        "dtype": "float64",
        "ordering": "deterministic",
        "source": "src/extraction/urls/url_features.py",
        "static_only": True,
        "network_access": False,
        "execution": False,
        "notes": (
            "URL features are structural/lexical indicators and must be "
            "combined with contextual and behavioral evidence."
        ),
    }


# ---------------------------------------------------------------------------
# Main analysis
# ---------------------------------------------------------------------------


def analyze_url_features(
    source: Any,
    *,
    source_name: Optional[str] = None,
    source_type: Optional[str] = None,
    max_urls: int = MAX_URLS,
) -> URLAnalysis:
    """
    Perform bounded static URL analysis.
    """
    text, source_size, source_hash = _read_source(source)

    extracted = extract_urls(
        text,
        max_urls=min(max_urls, MAX_URLS),
    )

    records: list[URLRecord] = []
    evidence: list[URLEvidence] = []

    seen_urls: set[str] = set()

    for url, line_number, field in extracted:
        if len(records) >= MAX_RECORDS:
            break

        normalized_key = url.casefold()

        if normalized_key in seen_urls:
            continue

        seen_urls.add(normalized_key)

        record = _parse_url(
            url,
            source=source_name,
        )

        records.append(record)

        record_evidence = _evidence_from_record(
            record,
            line_number=line_number,
            field=field,
        )

        for item in record_evidence:
            if len(evidence) >= MAX_EVIDENCE_ITEMS:
                break

            evidence.append(item)

    indicators = sorted(
        {indicator for record in records for indicator in record.indicators}
    )

    categories = sorted(
        {category for record in records for category in record.categories}
    )

    domains = sorted(
        {record.registrable_domain for record in records if record.registrable_domain}
    )

    hosts = sorted({record.host for record in records if record.host})

    schemes = sorted({record.scheme for record in records if record.scheme})

    platforms = sorted(
        {
            _infer_platform(
                record.url,
                record.scheme,
                record.host,
            )
            for record in records
        }
    )

    combinations = _derive_combinations(
        records,
        evidence,
    )

    analysis = URLAnalysis(
        source_hash=source_hash,
        source_size=source_size,
        records=records,
        evidence=evidence,
        indicators=indicators,
        categories=categories,
        combinations=combinations,
        domains=domains,
        hosts=hosts,
        schemes=schemes,
        platforms=platforms,
        metadata={
            "source_name": source_name,
            "source_type": source_type,
            "url_count": len(records),
            "unique_domain_count": len(domains),
            "unique_host_count": len(hosts),
            "unique_scheme_count": len(schemes),
            "static_only": True,
            "network_access": False,
            "execution": False,
            "dns_resolution": False,
            "content_download": False,
            "max_urls": max_urls,
        },
    )

    analysis.feature_vector = _build_feature_vector(analysis)

    return analysis


def analyze_urls(
    source: Any,
    **kwargs: Any,
) -> URLAnalysis:
    """Alias-style public entry point for URL analysis."""
    return analyze_url_features(source, **kwargs)


def parse_url_features(
    source: Any,
    **kwargs: Any,
) -> URLAnalysis:
    """Parse and analyze URL indicators without network interaction."""
    return analyze_url_features(source, **kwargs)


def analyze(
    source: Any,
    **kwargs: Any,
) -> URLAnalysis:
    """Generic analysis alias."""
    return analyze_url_features(source, **kwargs)


def extract_url_features(
    source: Any,
    **kwargs: Any,
) -> dict[str, float]:
    """
    Extract a stable URL feature mapping.
    """
    analysis = analyze_url_features(source, **kwargs)
    return dict(analysis.feature_vector)


def extract_feature_vector(
    source: Any,
    **kwargs: Any,
) -> list[float]:
    """
    Extract the stable ordered URL feature vector.
    """
    analysis = analyze_url_features(source, **kwargs)
    return vectorize_features(analysis.feature_vector)


def extract_url_feature_vector(
    source: Any,
    **kwargs: Any,
) -> list[float]:
    """Explicit URL feature-vector entry point."""
    return extract_feature_vector(source, **kwargs)


# ---------------------------------------------------------------------------
# Inspection helpers
# ---------------------------------------------------------------------------


def extract_url_records(
    source: Any,
    **kwargs: Any,
) -> list[URLRecord]:
    """Return normalized URL records."""
    return analyze_url_features(source, **kwargs).records


def has_indicator(
    analysis: URLAnalysis,
    indicator: str,
) -> bool:
    """Return whether an indicator is present."""
    return indicator in set(analysis.indicators)


def has_category(
    analysis: URLAnalysis,
    category: str,
) -> bool:
    """Return whether a category is present."""
    return category in set(analysis.categories)


def indicator_count(
    analysis: URLAnalysis,
    indicator: str,
) -> int:
    """Return the number of records containing an indicator."""
    return sum(indicator in record.indicators for record in analysis.records)


def category_count(
    analysis: URLAnalysis,
    category: str,
) -> int:
    """Return the number of records containing a category."""
    return sum(category in record.categories for record in analysis.records)


def evidence_by_category(
    analysis: URLAnalysis,
    category: str,
) -> list[URLEvidence]:
    """Return evidence belonging to a category."""
    return [item for item in analysis.evidence if item.category == category]


def evidence_by_indicator(
    analysis: URLAnalysis,
    indicator: str,
) -> list[URLEvidence]:
    """Return evidence belonging to an indicator."""
    return [item for item in analysis.evidence if item.indicator == indicator]


def high_risk_evidence(
    analysis: URLAnalysis,
) -> list[URLEvidence]:
    """Return high/critical evidence."""
    return [
        item
        for item in analysis.evidence
        if _severity_rank(item.severity) >= _severity_rank("high")
    ]


def highest_severity(
    analysis: URLAnalysis,
) -> str:
    """Return the highest observed severity."""
    severities = [record.severity for record in analysis.records]

    severities.extend(item.severity for item in analysis.evidence)

    return _max_severity(severities)


def present_combinations(
    analysis: URLAnalysis,
) -> list[URLCombination]:
    """Return only currently-present higher-level combinations."""
    return [combination for combination in analysis.combinations if combination.present]


# ---------------------------------------------------------------------------
# Serialization/reporting
# ---------------------------------------------------------------------------


def analysis_to_dict(
    analysis: URLAnalysis,
) -> dict[str, Any]:
    """
    Convert URL analysis to JSON-compatible primitives.
    """
    return {
        "source_hash": analysis.source_hash,
        "source_size": analysis.source_size,
        "records": [asdict(record) for record in analysis.records],
        "evidence": [asdict(item) for item in analysis.evidence],
        "indicators": list(analysis.indicators),
        "categories": list(analysis.categories),
        "combinations": [asdict(item) for item in analysis.combinations],
        "domains": list(analysis.domains),
        "hosts": list(analysis.hosts),
        "schemes": list(analysis.schemes),
        "platforms": list(analysis.platforms),
        "feature_vector": dict(analysis.feature_vector),
        "metadata": dict(analysis.metadata),
    }


def summarize_url_features(
    analysis: URLAnalysis,
) -> dict[str, Any]:
    """
    Produce a compact operational summary.
    """
    category_counts = Counter(
        category for record in analysis.records for category in record.categories
    )

    indicator_counts = Counter(
        indicator for record in analysis.records for indicator in record.indicators
    )

    return {
        "source_hash": analysis.source_hash,
        "source_size": analysis.source_size,
        "url_count": len(analysis.records),
        "unique_domains": len(analysis.domains),
        "unique_hosts": len(analysis.hosts),
        "schemes": list(analysis.schemes),
        "categories": list(analysis.categories),
        "category_counts": dict(sorted(category_counts.items())),
        "indicator_counts": dict(sorted(indicator_counts.items())),
        "high_risk_count": len(high_risk_evidence(analysis)),
        "highest_severity": highest_severity(analysis),
        "present_combinations": [
            combination.name for combination in present_combinations(analysis)
        ],
        "signal_score": float(analysis.feature_vector.get("signal_score", 0.0)),
        "domains": list(analysis.domains),
        "platforms": list(analysis.platforms),
        "static_only": True,
    }


# ---------------------------------------------------------------------------
# Iterators
# ---------------------------------------------------------------------------


def iter_evidence(
    analysis: URLAnalysis,
) -> Iterator[URLEvidence]:
    """Iterate over all URL evidence."""
    yield from analysis.evidence


def iter_high_risk_evidence(
    analysis: URLAnalysis,
) -> Iterator[URLEvidence]:
    """Iterate over high/critical URL evidence."""
    yield from high_risk_evidence(analysis)


def iter_records(
    analysis: URLAnalysis,
) -> Iterator[URLRecord]:
    """Iterate over normalized URL records."""
    yield from analysis.records


def iter_combinations(
    analysis: URLAnalysis,
) -> Iterator[URLCombination]:
    """Iterate over URL combinations."""
    yield from analysis.combinations


def iter_analyses(
    analyses: Iterable[URLAnalysis],
) -> Iterator[URLAnalysis]:
    """Iterate over URL analyses."""
    yield from analyses


# ---------------------------------------------------------------------------
# Compatibility aliases
# ---------------------------------------------------------------------------


parse = parse_url_features
extract = extract_url_features


# =============================================================================
# PUBLIC API
# =============================================================================

__all__ = [
    "analyze_url_features",
    "analyze_urls",
    "analyze",
    "parse_url_features",
    "extract_url_features",
    "extract_urls",
    "extract_feature_vector",
    "extract_url_feature_vector",
    "url_feature_names",
    "build_feature_schema",
    "vectorize_features",
    "extract_url_records",
    "has_indicator",
    "has_category",
    "indicator_count",
    "category_count",
    "evidence_by_category",
    "evidence_by_indicator",
    "high_risk_evidence",
    "highest_severity",
    "present_combinations",
    "analysis_to_dict",
    "summarize_url_features",
    "iter_evidence",
    "iter_high_risk_evidence",
    "iter_records",
    "iter_combinations",
    "iter_analyses",
    "URLPattern",
    "URLEvidence",
    "URLRecord",
    "URLCombination",
    "URLAnalysis",
    "URL_CATEGORIES",
    "SEVERITIES",
    "parse",
    "extract",
]
