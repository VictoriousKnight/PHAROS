"""
Generic string extraction and analysis.

This module extracts textual strings from arbitrary binary files and produces
features useful for malware/document analysis.

Supported string representations
---------------------------------
- ASCII / printable byte strings
- UTF-8 strings
- UTF-16LE strings
- UTF-16BE strings

The module also provides lightweight analysis for:

- URLs
- email addresses
- IP addresses
- Windows paths
- UNC paths
- command/scripting indicators
- PowerShell indicators
- shell/interpreter indicators
- encoded-looking strings
- Base64-like strings
- hexadecimal strings
- high-entropy strings
- suspicious command-line constructs
- string length/distribution statistics

Design principles
-----------------
1. Extraction is deterministic.
2. Results are JSON serializable.
3. The module does not execute extracted content.
4. Detection is heuristic and contextual; no individual string is considered
   proof of maliciousness.
5. Detailed strings and ML-ready scalar features are exposed separately.
6. Limits are enforced so hostile files cannot cause unbounded memory usage.

This module intentionally does not parse:
- VBA
- JavaScript
- VBScript
- PowerShell syntax
- Office XML
- OLE
- URLs as full semantic objects

Those responsibilities belong to the specialized extraction modules.
"""

from __future__ import annotations

import base64
import binascii
import ipaddress
import math
import re
from collections import Counter
from dataclasses import dataclass
from statistics import mean, pstdev
from typing import Any, Iterable, Iterator, Sequence
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_MIN_ASCII_LENGTH = 4
DEFAULT_MIN_UNICODE_LENGTH = 4

DEFAULT_MAX_STRINGS = 10_000
DEFAULT_MAX_STRING_LENGTH = 16_384

DEFAULT_HIGH_ENTROPY_THRESHOLD = 4.5
DEFAULT_VERY_HIGH_ENTROPY_THRESHOLD = 5.5

DEFAULT_MAX_ANALYSIS_SAMPLE = 4 * 1024 * 1024

# ASCII printable range.
ASCII_PRINTABLE_MIN = 0x20
ASCII_PRINTABLE_MAX = 0x7E

# Characters which are allowed in a normal textual string but terminate
# extraction.
STRING_TERMINATORS = {
    0x00,
    0x09,
    0x0A,
    0x0B,
    0x0C,
    0x0D,
}

# ---------------------------------------------------------------------------
# Regular expressions
# ---------------------------------------------------------------------------

URL_RE = re.compile(r"(?i)\b" r"(?:https?|ftp)://" r"[^\s<>'\"`\x00-\x1f]+")

EMAIL_RE = re.compile(
    r"(?i)\b" r"[a-z0-9.!#$%&'*+/=?^_`{|}~-]+" r"@" r"[a-z0-9-]+(?:\.[a-z0-9-]+)+" r"\b"
)

# IPv4 candidate. Validation is performed separately with ipaddress.
IPV4_RE = re.compile(r"(?<![\w.])" r"(?:\d{1,3}\.){3}\d{1,3}" r"(?![\w.])")

# IPv6 candidates are harder to identify reliably with regex. This catches
# common colon-containing candidates and validation happens separately.
IPV6_RE = re.compile(
    r"(?<![\w:])" r"(?:[0-9a-fA-F]{0,4}:){2,7}" r"[0-9a-fA-F]{0,4}" r"(?![\w:])"
)

WINDOWS_PATH_RE = re.compile(
    r"(?i)"
    r"(?:[a-z]:\\|[a-z]:/)"
    r"(?:[^\\/\x00-\x1f:*?\"<>|]+[\\/])*"
    r"[^\\/\x00-\x1f:*?\"<>|]+"
)

UNC_PATH_RE = re.compile(r"(?i)" r"\\\\" r"[^\\/\x00-\x1f]+" r"(?:\\[^\\/\x00-\x1f]+)+")

BASE64_RE = re.compile(
    r"(?<![A-Za-z0-9+/=])" r"(?:[A-Za-z0-9+/]{4}){3,}" r"={0,2}" r"(?![A-Za-z0-9+/=])"
)

HEX_RE = re.compile(r"(?i)" r"(?<![0-9a-f])" r"(?:[0-9a-f]{2}){8,}" r"(?![0-9a-f])")

POWERSHELL_RE = re.compile(
    r"(?i)\b("
    r"powershell(?:\.exe)?|"
    r"pwsh(?:\.exe)?|"
    r"invoke-expression|"
    r"iex|"
    r"invoke-webrequest|"
    r"iwr|"
    r"invoke-restmethod|"
    r"irm|"
    r"downloadstring|"
    r"downloadfile|"
    r"start-process|"
    r"new-object\s+net\.webclient|"
    r"set-executionpolicy|"
    r"encodedcommand|"
    r"executionpolicy"
    r")\b"
)

WINDOWS_COMMAND_RE = re.compile(
    r"(?i)\b("
    r"cmd(?:\.exe)?|"
    r"wscript(?:\.exe)?|"
    r"cscript(?:\.exe)?|"
    r"mshta(?:\.exe)?|"
    r"rundll32(?:\.exe)?|"
    r"regsvr32(?:\.exe)?|"
    r"regasm(?:\.exe)?|"
    r"regsvcs(?:\.exe)?|"
    r"certutil(?:\.exe)?|"
    r"bitsadmin(?:\.exe)?|"
    r"msiexec(?:\.exe)?|"
    r"installutil(?:\.exe)?|"
    r"wmic(?:\.exe)?|"
    r"csc(?:\.exe)?"
    r")\b"
)

SCRIPT_ENGINE_RE = re.compile(
    r"(?i)\b("
    r"javascript|"
    r"vbscript|"
    r"jscript|"
    r"powershell|"
    r"visual\s+basic|"
    r"macro|"
    r"autoexec|"
    r"wsh|"
    r"windows\s+script\s+host"
    r")\b"
)

COMMAND_ARGUMENT_RE = re.compile(
    r"(?i)(?:^|[\s\"'])("
    r"-enc(?:odedcommand)?|"
    r"/c|"
    r"/k|"
    r"-nop(?:rofile)?|"
    r"-w(?:indowstyle)?|"
    r"-hidden|"
    r"-executionpolicy|"
    r"-ep|"
    r"-command|"
    r"-file"
    r")(?:[\s=]|$)"
)

NETWORK_COMMAND_RE = re.compile(
    r"(?i)\b("
    r"curl|"
    r"wget|"
    r"bitsadmin|"
    r"certutil|"
    r"invoke-webrequest|"
    r"invoke-restmethod|"
    r"webclient|"
    r"winhttp|"
    r"urldownloadtofile"
    r")\b"
)

SUSPICIOUS_EXECUTION_RE = re.compile(
    r"(?i)\b("
    r"createprocess|"
    r"winexec|"
    r"shellexecute|"
    r"shellapplication|"
    r"wscript\.shell|"
    r"adodb\.stream|"
    r"xmlhttp|"
    r"winhttprequest|"
    r"scriptcontrol|"
    r"msxml2\.xmlhttp"
    r")\b"
)

CREDENTIAL_RE = re.compile(
    r"(?i)\b("
    r"password|"
    r"passwd|"
    r"credential|"
    r"credentials|"
    r"username|"
    r"login|"
    r"token|"
    r"cookie|"
    r"authorization|"
    r"secret"
    r")\b"
)

PERSISTENCE_RE = re.compile(
    r"(?i)\b("
    r"runonce|"
    r"currentversion\\run|"
    r"startup|"
    r"scheduled\s+task|"
    r"taskschd|"
    r"servicecontrolmanager|"
    r"create service|"
    r"sc\.exe"
    r")\b"
)

OBFUSCATION_RE = re.compile(
    r"(?i)\b("
    r"chr|"
    r"chrw|"
    r"frombase64string|"
    r"base64|"
    r"decode|"
    r"decrypt|"
    r"replace|"
    r"substring|"
    r"reverse|"
    r"join|"
    r"split"
    r")\b"
)

# Strings containing a large concentration of shell metacharacters.
SHELL_META_RE = re.compile(r"[;&|<>`$()\[\]{}]")

# Common Windows environment variables.
ENVIRONMENT_VARIABLE_RE = re.compile(r"(?i)%[a-z_][a-z0-9_]*%")

# Common Office / macro-related textual indicators.
OFFICE_INDICATOR_RE = re.compile(
    r"(?i)\b("
    r"vba|"
    r"vbaproject|"
    r"vba6|"
    r"vba7|"
    r"macro|"
    r"xlm|"
    r"excel4macro|"
    r"autoopen|"
    r"autoclose|"
    r"document_open|"
    r"workbook_open|"
    r"documentopen"
    r")\b"
)


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ExtractedString:
    """
    Representation of one extracted string.

    Attributes
    ----------
    value:
        Decoded textual value.

    encoding:
        One of:
            ascii
            utf8
            utf16le
            utf16be

    offset:
        Approximate byte offset in the analyzed data.

    byte_length:
        Length of the original byte representation.

    character_length:
        Number of decoded characters.
    """

    value: str
    encoding: str
    offset: int
    byte_length: int
    character_length: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "value": self.value,
            "encoding": self.encoding,
            "offset": self.offset,
            "byte_length": self.byte_length,
            "character_length": self.character_length,
        }


@dataclass(frozen=True)
class StringStatistics:
    """Aggregate statistics over extracted strings."""

    count: int
    total_characters: int
    minimum_length: int
    maximum_length: int
    mean_length: float
    median_length: float
    standard_deviation_length: float
    short_string_count: int
    medium_string_count: int
    long_string_count: int
    very_long_string_count: int
    ascii_count: int
    utf8_count: int
    utf16le_count: int
    utf16be_count: int
    high_entropy_string_count: int
    very_high_entropy_string_count: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "count": self.count,
            "total_characters": self.total_characters,
            "minimum_length": self.minimum_length,
            "maximum_length": self.maximum_length,
            "mean_length": self.mean_length,
            "median_length": self.median_length,
            "standard_deviation_length": self.standard_deviation_length,
            "short_string_count": self.short_string_count,
            "medium_string_count": self.medium_string_count,
            "long_string_count": self.long_string_count,
            "very_long_string_count": self.very_long_string_count,
            "ascii_count": self.ascii_count,
            "utf8_count": self.utf8_count,
            "utf16le_count": self.utf16le_count,
            "utf16be_count": self.utf16be_count,
            "high_entropy_string_count": self.high_entropy_string_count,
            "very_high_entropy_string_count": (self.very_high_entropy_string_count),
        }


# ---------------------------------------------------------------------------
# Generic helpers
# ---------------------------------------------------------------------------


def _shannon_entropy(text: str) -> float:
    """Calculate Shannon entropy over Unicode characters."""
    if not text:
        return 0.0

    counts = Counter(text)
    length = len(text)

    entropy = 0.0

    for count in counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return entropy


def _safe_decode(
    data: bytes,
    encoding: str,
) -> str:
    """Decode bytes while preventing malformed input from raising."""
    try:
        return data.decode(encoding, errors="replace")
    except (LookupError, UnicodeError):
        return ""


def _is_reasonable_text(text: str) -> bool:
    """
    Determine whether a decoded string contains enough usable text.

    This rejects strings dominated by replacement characters or control
    characters.
    """
    if not text:
        return False

    replacement_count = text.count("\ufffd")

    if replacement_count / len(text) > 0.25:
        return False

    useful = 0

    for char in text:
        codepoint = ord(char)

        if char in "\t\r\n" or 32 <= codepoint <= 126 or codepoint >= 160:
            useful += 1

    return useful / len(text) >= 0.65


def _normalize_string(text: str) -> str:
    """
    Normalize extracted text for analysis.

    The original textual value is preserved as much as possible. Only
    surrounding whitespace and NUL characters are removed.
    """
    return text.replace("\x00", "").strip()


def _median(values: Sequence[int]) -> float:
    if not values:
        return 0.0

    ordered = sorted(values)
    middle = len(ordered) // 2

    if len(ordered) % 2:
        return float(ordered[middle])

    return (ordered[middle - 1] + ordered[middle]) / 2.0


def _clamp_entropy(value: float) -> float:
    return max(0.0, min(8.0, value))


# ---------------------------------------------------------------------------
# ASCII extraction
# ---------------------------------------------------------------------------


def extract_ascii_strings(
    data: bytes,
    *,
    min_length: int = DEFAULT_MIN_ASCII_LENGTH,
    max_length: int = DEFAULT_MAX_STRING_LENGTH,
    max_strings: int = DEFAULT_MAX_STRINGS,
) -> list[ExtractedString]:
    """
    Extract printable ASCII strings.

    Strings are terminated by bytes outside the printable ASCII range.

    The returned offset points to the beginning of the string in the input
    byte sequence.
    """
    if min_length <= 0:
        raise ValueError("min_length must be greater than zero")

    if max_length < min_length:
        raise ValueError("max_length must be >= min_length")

    if max_strings <= 0:
        return []

    result: list[ExtractedString] = []

    start: int | None = None

    for index, byte in enumerate(data):
        is_printable = ASCII_PRINTABLE_MIN <= byte <= ASCII_PRINTABLE_MAX

        if is_printable:
            if start is None:
                start = index

        else:
            if start is not None:
                _append_ascii_string(
                    result,
                    data,
                    start,
                    index,
                    min_length,
                    max_length,
                )

                if len(result) >= max_strings:
                    return result

                start = None

    if start is not None:
        _append_ascii_string(
            result,
            data,
            start,
            len(data),
            min_length,
            max_length,
        )

    return result[:max_strings]


def _append_ascii_string(
    result: list[ExtractedString],
    data: bytes,
    start: int,
    end: int,
    min_length: int,
    max_length: int,
) -> None:
    length = end - start

    if length < min_length:
        return

    actual_end = min(
        end,
        start + max_length,
    )

    raw = data[start:actual_end]

    text = _safe_decode(raw, "ascii")

    if not text:
        return

    result.append(
        ExtractedString(
            value=text,
            encoding="ascii",
            offset=start,
            byte_length=len(raw),
            character_length=len(text),
        )
    )


# ---------------------------------------------------------------------------
# UTF-16 extraction
# ---------------------------------------------------------------------------


def extract_utf16_strings(
    data: bytes,
    *,
    encoding: str = "utf-16le",
    min_length: int = DEFAULT_MIN_UNICODE_LENGTH,
    max_length: int = DEFAULT_MAX_STRING_LENGTH,
    max_strings: int = DEFAULT_MAX_STRINGS,
) -> list[ExtractedString]:
    """
    Extract UTF-16LE or UTF-16BE strings from binary data.

    This implementation specifically targets the common malware/document
    pattern where ASCII text is stored as:

        P\x00o\x00w\x00e\x00r\x00...

    or the corresponding big-endian representation.

    Strings containing replacement characters or excessive controls are
    rejected.
    """
    if encoding not in {"utf-16le", "utf-16be"}:
        raise ValueError("encoding must be 'utf-16le' or 'utf-16be'")

    if min_length <= 0:
        raise ValueError("min_length must be greater than zero")

    if max_length < min_length:
        raise ValueError("max_length must be >= min_length")

    if max_strings <= 0:
        return []

    result: list[ExtractedString] = []

    # UTF-16 characters consume two bytes.
    for alignment in (0, 1):
        start: int | None = None

        index = alignment

        while index + 1 < len(data):
            pair = data[index : index + 2]

            try:
                char = pair.decode(encoding)
            except UnicodeDecodeError:
                char = ""

            codepoint = ord(char) if char else 0

            is_textual = (
                (ASCII_PRINTABLE_MIN <= codepoint <= ASCII_PRINTABLE_MAX)
                or codepoint in (0x09, 0x0A, 0x0D)
                or codepoint >= 0xA0
            )

            if is_textual:
                if start is None:
                    start = index

            else:
                if start is not None:
                    _append_utf16_string(
                        result,
                        data,
                        start,
                        index,
                        encoding,
                        min_length,
                        max_length,
                    )

                    if len(result) >= max_strings:
                        break

                    start = None

            index += 2

        if start is not None and len(result) < max_strings:
            _append_utf16_string(
                result,
                data,
                start,
                len(data) - ((len(data) - start) % 2),
                encoding,
                min_length,
                max_length,
            )

        if len(result) >= max_strings:
            break

    return _deduplicate_strings(result, max_strings)


def _append_utf16_string(
    result: list[ExtractedString],
    data: bytes,
    start: int,
    end: int,
    encoding: str,
    min_length: int,
    max_length: int,
) -> None:
    raw = data[start:end]

    if len(raw) < min_length * 2:
        return

    raw = raw[: max_length * 2]

    text = _safe_decode(raw, encoding)
    text = _normalize_string(text)

    if len(text) < min_length:
        return

    if not _is_reasonable_text(text):
        return

    result.append(
        ExtractedString(
            value=text,
            encoding=encoding,
            offset=start,
            byte_length=len(raw),
            character_length=len(text),
        )
    )


# ---------------------------------------------------------------------------
# UTF-8 / generic textual extraction
# ---------------------------------------------------------------------------


def extract_utf8_strings(
    data: bytes,
    *,
    min_length: int = DEFAULT_MIN_UNICODE_LENGTH,
    max_length: int = DEFAULT_MAX_STRING_LENGTH,
    max_strings: int = DEFAULT_MAX_STRINGS,
) -> list[ExtractedString]:
    """
    Extract contiguous UTF-8 text runs from arbitrary binary data.

    This intentionally uses a conservative strategy to avoid interpreting
    arbitrary binary data as text.
    """
    if min_length <= 0:
        raise ValueError("min_length must be greater than zero")

    if max_length < min_length:
        raise ValueError("max_length must be >= min_length")

    if max_strings <= 0:
        return []

    result: list[ExtractedString] = []

    # Decode small candidate runs separated by ASCII control bytes.
    start: int | None = None

    for index, byte in enumerate(data):
        is_candidate = byte >= 0x20 or byte in (0x09, 0x0A, 0x0D)

        if is_candidate:
            if start is None:
                start = index

        else:
            if start is not None:
                _append_utf8_candidate(
                    result,
                    data,
                    start,
                    index,
                    min_length,
                    max_length,
                )

                if len(result) >= max_strings:
                    return result

                start = None

    if start is not None:
        _append_utf8_candidate(
            result,
            data,
            start,
            len(data),
            min_length,
            max_length,
        )

    return result[:max_strings]


def _append_utf8_candidate(
    result: list[ExtractedString],
    data: bytes,
    start: int,
    end: int,
    min_length: int,
    max_length: int,
) -> None:
    raw = data[start : min(end, start + max_length * 4)]

    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return

    text = _normalize_string(text)

    if len(text) < min_length:
        return

    if not _is_reasonable_text(text):
        return

    result.append(
        ExtractedString(
            value=text,
            encoding="utf8",
            offset=start,
            byte_length=len(raw),
            character_length=len(text),
        )
    )


# ---------------------------------------------------------------------------
# Combined extraction
# ---------------------------------------------------------------------------


def extract_strings(
    data: bytes,
    *,
    min_ascii_length: int = DEFAULT_MIN_ASCII_LENGTH,
    min_unicode_length: int = DEFAULT_MIN_UNICODE_LENGTH,
    max_string_length: int = DEFAULT_MAX_STRING_LENGTH,
    max_strings: int = DEFAULT_MAX_STRINGS,
    include_ascii: bool = True,
    include_utf8: bool = True,
    include_utf16: bool = True,
) -> list[ExtractedString]:
    """
    Extract strings from multiple common encodings.

    Duplicate values at the same offset/encoding are removed.
    """
    if not data:
        return []

    results: list[ExtractedString] = []

    if include_ascii:
        results.extend(
            extract_ascii_strings(
                data,
                min_length=min_ascii_length,
                max_length=max_string_length,
                max_strings=max_strings,
            )
        )

    if include_utf8 and len(results) < max_strings:
        results.extend(
            extract_utf8_strings(
                data,
                min_length=min_unicode_length,
                max_length=max_string_length,
                max_strings=max_strings - len(results),
            )
        )

    if include_utf16 and len(results) < max_strings:
        for encoding in ("utf-16le", "utf-16be"):
            if len(results) >= max_strings:
                break

            results.extend(
                extract_utf16_strings(
                    data,
                    encoding=encoding,
                    min_length=min_unicode_length,
                    max_length=max_string_length,
                    max_strings=max_strings - len(results),
                )
            )

    return _deduplicate_strings(results, max_strings)


def _deduplicate_strings(
    strings: Iterable[ExtractedString],
    max_strings: int,
) -> list[ExtractedString]:
    """Deduplicate extracted strings while preserving discovery order."""
    seen: set[tuple[str, int, str]] = set()
    result: list[ExtractedString] = []

    for item in strings:
        key = (
            item.value,
            item.offset,
            item.encoding,
        )

        if key in seen:
            continue

        seen.add(key)
        result.append(item)

        if len(result) >= max_strings:
            break

    return result


# ---------------------------------------------------------------------------
# Individual string classification
# ---------------------------------------------------------------------------


def is_valid_ipv4(value: str) -> bool:
    """Return True if value is a valid IPv4 address."""
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False

    return address.version == 4


def is_valid_ipv6(value: str) -> bool:
    """Return True if value is a valid IPv6 address."""
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False

    return address.version == 6


def extract_urls(text: str) -> list[str]:
    """Extract HTTP/HTTPS/FTP URLs from text."""
    return _unique_preserve_order(
        match.group(0).rstrip(".,;:!?)]}") for match in URL_RE.finditer(text)
    )


def extract_emails(text: str) -> list[str]:
    """Extract email addresses from text."""
    return _unique_preserve_order(match.group(0) for match in EMAIL_RE.finditer(text))


def extract_ipv4_addresses(text: str) -> list[str]:
    """Extract valid IPv4 addresses from text."""
    result: list[str] = []

    for match in IPV4_RE.finditer(text):
        candidate = match.group(0)

        if is_valid_ipv4(candidate):
            result.append(candidate)

    return _unique_preserve_order(result)


def extract_ipv6_addresses(text: str) -> list[str]:
    """Extract valid IPv6 addresses from text."""
    result: list[str] = []

    for match in IPV6_RE.finditer(text):
        candidate = match.group(0)

        if is_valid_ipv6(candidate):
            result.append(candidate)

    return _unique_preserve_order(result)


def extract_windows_paths(text: str) -> list[str]:
    """Extract Windows drive-letter paths."""
    return _unique_preserve_order(
        match.group(0).rstrip(".,;:)]}") for match in WINDOWS_PATH_RE.finditer(text)
    )


def extract_unc_paths(text: str) -> list[str]:
    """Extract UNC paths such as \\\\server\\share\\file."""
    return _unique_preserve_order(
        match.group(0).rstrip(".,;:)]}") for match in UNC_PATH_RE.finditer(text)
    )


def _unique_preserve_order(values: Iterable[str]) -> list[str]:
    """Deduplicate strings without changing their first-seen order."""
    seen: set[str] = set()
    result: list[str] = []

    for value in values:
        if value not in seen:
            seen.add(value)
            result.append(value)

    return result


# ---------------------------------------------------------------------------
# Encoded-string analysis
# ---------------------------------------------------------------------------


def looks_like_base64(
    value: str,
    *,
    minimum_length: int = 16,
) -> bool:
    """
    Determine whether a string plausibly represents Base64.

    This is intentionally conservative and does not decode arbitrary content
    as executable data.
    """
    compact = re.sub(r"\s+", "", value)

    if len(compact) < minimum_length:
        return False

    if len(compact) % 4 != 0:
        return False

    if not BASE64_RE.fullmatch(compact):
        return False

    try:
        decoded = base64.b64decode(
            compact,
            validate=True,
        )
    except (ValueError, binascii.Error):
        return False

    if not decoded:
        return False

    # Reject strings that simply happen to match Base64 syntax but decode to
    # overwhelmingly printable text. Those are less informative as encoded
    # payload indicators.
    printable = sum(
        1
        for byte in decoded
        if byte in (9, 10, 13) or ASCII_PRINTABLE_MIN <= byte <= ASCII_PRINTABLE_MAX
    )

    printable_ratio_value = printable / len(decoded)

    return printable_ratio_value < 0.95


def looks_like_hex(
    value: str,
    *,
    minimum_length: int = 16,
) -> bool:
    """Determine whether a string plausibly contains hexadecimal encoding."""
    compact = re.sub(r"\s+", "", value)

    return (
        len(compact) >= minimum_length
        and len(compact) % 2 == 0
        and HEX_RE.fullmatch(compact) is not None
    )


def string_entropy(value: str) -> float:
    """Calculate character-level Shannon entropy."""
    return _clamp_entropy(_shannon_entropy(value))


def is_high_entropy_string(
    value: str,
    *,
    threshold: float = DEFAULT_HIGH_ENTROPY_THRESHOLD,
) -> bool:
    """
    Determine whether a string has unusually high character entropy.

    High entropy may indicate:
        - encoded data
        - encrypted material
        - compressed fragments
        - generated identifiers
        - hashes

    It is not inherently malicious.
    """
    return string_entropy(value) >= threshold


# ---------------------------------------------------------------------------
# Semantic indicators
# ---------------------------------------------------------------------------


def classify_string(value: str) -> dict[str, Any]:
    """
    Extract semantic indicators from one string.

    This function produces evidence, not a malware verdict.
    """
    normalized = value.strip()
    lowered = normalized.lower()

    urls = extract_urls(normalized)
    emails = extract_emails(normalized)
    ipv4 = extract_ipv4_addresses(normalized)
    ipv6 = extract_ipv6_addresses(normalized)
    windows_paths = extract_windows_paths(normalized)
    unc_paths = extract_unc_paths(normalized)

    powershell_matches = [
        match.group(0) for match in POWERSHELL_RE.finditer(normalized)
    ]

    windows_command_matches = [
        match.group(0) for match in WINDOWS_COMMAND_RE.finditer(normalized)
    ]

    script_engine_matches = [
        match.group(0) for match in SCRIPT_ENGINE_RE.finditer(normalized)
    ]

    command_argument_matches = [
        match.group(0) for match in COMMAND_ARGUMENT_RE.finditer(normalized)
    ]

    network_command_matches = [
        match.group(0) for match in NETWORK_COMMAND_RE.finditer(normalized)
    ]

    execution_matches = [
        match.group(0) for match in SUSPICIOUS_EXECUTION_RE.finditer(normalized)
    ]

    credential_matches = [
        match.group(0) for match in CREDENTIAL_RE.finditer(normalized)
    ]

    persistence_matches = [
        match.group(0) for match in PERSISTENCE_RE.finditer(normalized)
    ]

    obfuscation_matches = [
        match.group(0) for match in OBFUSCATION_RE.finditer(normalized)
    ]

    office_matches = [
        match.group(0) for match in OFFICE_INDICATOR_RE.finditer(normalized)
    ]

    environment_variables = ENVIRONMENT_VARIABLE_RE.findall(normalized)

    shell_meta_count = len(SHELL_META_RE.findall(normalized))

    entropy = string_entropy(normalized)

    base64_like = looks_like_base64(normalized)
    hex_like = looks_like_hex(normalized)

    # URL-specific characteristics.
    url_has_ip_host = False
    url_has_nonstandard_port = False
    url_has_long_path = False
    url_has_encoded_data = False

    for url in urls:
        try:
            parsed = urlparse(url)

            hostname = parsed.hostname

            if hostname:
                if is_valid_ipv4(hostname) or is_valid_ipv6(hostname):
                    url_has_ip_host = True

            if parsed.port is not None:
                default_port = 443 if parsed.scheme.lower() == "https" else 80

                if parsed.port != default_port:
                    url_has_nonstandard_port = True

            if len(parsed.path) >= 100:
                url_has_long_path = True

            if "%" in url or "=" in parsed.query:
                url_has_encoded_data = True

        except ValueError:
            # Malformed URLs are ignored rather than causing extraction to
            # fail for the whole file.
            continue

    return {
        "string_length": len(normalized),
        "string_entropy": entropy,
        "contains_url": bool(urls),
        "url_count": len(urls),
        "contains_email": bool(emails),
        "email_count": len(emails),
        "contains_ipv4": bool(ipv4),
        "ipv4_count": len(ipv4),
        "contains_ipv6": bool(ipv6),
        "ipv6_count": len(ipv6),
        "contains_windows_path": bool(windows_paths),
        "windows_path_count": len(windows_paths),
        "contains_unc_path": bool(unc_paths),
        "unc_path_count": len(unc_paths),
        "contains_powershell": bool(powershell_matches),
        "powershell_indicator_count": len(powershell_matches),
        "contains_windows_command": bool(windows_command_matches),
        "windows_command_indicator_count": len(windows_command_matches),
        "contains_script_engine": bool(script_engine_matches),
        "script_engine_indicator_count": len(script_engine_matches),
        "contains_command_argument": bool(command_argument_matches),
        "command_argument_indicator_count": len(command_argument_matches),
        "contains_network_command": bool(network_command_matches),
        "network_command_indicator_count": len(network_command_matches),
        "contains_execution_indicator": bool(execution_matches),
        "execution_indicator_count": len(execution_matches),
        "contains_credential_indicator": bool(credential_matches),
        "credential_indicator_count": len(credential_matches),
        "contains_persistence_indicator": bool(persistence_matches),
        "persistence_indicator_count": len(persistence_matches),
        "contains_obfuscation_indicator": bool(obfuscation_matches),
        "obfuscation_indicator_count": len(obfuscation_matches),
        "contains_office_indicator": bool(office_matches),
        "office_indicator_count": len(office_matches),
        "environment_variable_count": len(environment_variables),
        "shell_metacharacter_count": shell_meta_count,
        "looks_like_base64": base64_like,
        "looks_like_hex": hex_like,
        "is_high_entropy": is_high_entropy_string(normalized),
        "is_very_high_entropy": is_high_entropy_string(
            normalized,
            threshold=DEFAULT_VERY_HIGH_ENTROPY_THRESHOLD,
        ),
        "url_host_is_ip": url_has_ip_host,
        "url_has_nonstandard_port": url_has_nonstandard_port,
        "url_has_long_path": url_has_long_path,
        "url_has_encoded_data": url_has_encoded_data,
        # Preserve concrete observations for reports.
        "urls": urls,
        "emails": emails,
        "ipv4_addresses": ipv4,
        "ipv6_addresses": ipv6,
        "windows_paths": windows_paths,
        "unc_paths": unc_paths,
        "powershell_indicators": _unique_preserve_order(powershell_matches),
        "windows_command_indicators": _unique_preserve_order(windows_command_matches),
        "script_engine_indicators": _unique_preserve_order(script_engine_matches),
        "execution_indicators": _unique_preserve_order(execution_matches),
        "obfuscation_indicators": _unique_preserve_order(obfuscation_matches),
    }


# ---------------------------------------------------------------------------
# Aggregate statistics
# ---------------------------------------------------------------------------


def string_statistics(
    strings: Sequence[ExtractedString],
    *,
    high_entropy_threshold: float = DEFAULT_HIGH_ENTROPY_THRESHOLD,
    very_high_entropy_threshold: float = (DEFAULT_VERY_HIGH_ENTROPY_THRESHOLD),
) -> StringStatistics:
    """
    Calculate aggregate statistics over extracted strings.
    """
    if not strings:
        return StringStatistics(
            count=0,
            total_characters=0,
            minimum_length=0,
            maximum_length=0,
            mean_length=0.0,
            median_length=0.0,
            standard_deviation_length=0.0,
            short_string_count=0,
            medium_string_count=0,
            long_string_count=0,
            very_long_string_count=0,
            ascii_count=0,
            utf8_count=0,
            utf16le_count=0,
            utf16be_count=0,
            high_entropy_string_count=0,
            very_high_entropy_string_count=0,
        )

    lengths = [item.character_length for item in strings]

    return StringStatistics(
        count=len(strings),
        total_characters=sum(lengths),
        minimum_length=min(lengths),
        maximum_length=max(lengths),
        mean_length=mean(lengths),
        median_length=_median(lengths),
        standard_deviation_length=(pstdev(lengths) if len(lengths) > 1 else 0.0),
        short_string_count=sum(length < 8 for length in lengths),
        medium_string_count=sum(8 <= length < 32 for length in lengths),
        long_string_count=sum(32 <= length < 256 for length in lengths),
        very_long_string_count=sum(length >= 256 for length in lengths),
        ascii_count=sum(item.encoding == "ascii" for item in strings),
        utf8_count=sum(item.encoding == "utf8" for item in strings),
        utf16le_count=sum(item.encoding == "utf-16le" for item in strings),
        utf16be_count=sum(item.encoding == "utf-16be" for item in strings),
        high_entropy_string_count=sum(
            string_entropy(item.value) >= high_entropy_threshold for item in strings
        ),
        very_high_entropy_string_count=sum(
            string_entropy(item.value) >= very_high_entropy_threshold
            for item in strings
        ),
    )


# ---------------------------------------------------------------------------
# Composite analysis
# ---------------------------------------------------------------------------


def analyze_strings(
    data: bytes,
    *,
    min_ascii_length: int = DEFAULT_MIN_ASCII_LENGTH,
    min_unicode_length: int = DEFAULT_MIN_UNICODE_LENGTH,
    max_string_length: int = DEFAULT_MAX_STRING_LENGTH,
    max_strings: int = DEFAULT_MAX_STRINGS,
    include_string_values: bool = True,
) -> dict[str, Any]:
    """
    Perform complete string analysis on a byte sequence.

    Returns both ML-friendly scalar features and detailed observations.
    """
    strings = extract_strings(
        data,
        min_ascii_length=min_ascii_length,
        min_unicode_length=min_unicode_length,
        max_string_length=max_string_length,
        max_strings=max_strings,
    )

    statistics = string_statistics(strings)

    classifications = [classify_string(item.value) for item in strings]

    # Aggregate semantic indicators.
    url_values = _unique_preserve_order(
        url for classification in classifications for url in classification["urls"]
    )

    email_values = _unique_preserve_order(
        email
        for classification in classifications
        for email in classification["emails"]
    )

    ipv4_values = _unique_preserve_order(
        address
        for classification in classifications
        for address in classification["ipv4_addresses"]
    )

    ipv6_values = _unique_preserve_order(
        address
        for classification in classifications
        for address in classification["ipv6_addresses"]
    )

    windows_paths = _unique_preserve_order(
        path
        for classification in classifications
        for path in classification["windows_paths"]
    )

    unc_paths = _unique_preserve_order(
        path
        for classification in classifications
        for path in classification["unc_paths"]
    )

    powershell_count = sum(
        classification["powershell_indicator_count"]
        for classification in classifications
    )

    windows_command_count = sum(
        classification["windows_command_indicator_count"]
        for classification in classifications
    )

    script_engine_count = sum(
        classification["script_engine_indicator_count"]
        for classification in classifications
    )

    command_argument_count = sum(
        classification["command_argument_indicator_count"]
        for classification in classifications
    )

    network_command_count = sum(
        classification["network_command_indicator_count"]
        for classification in classifications
    )

    execution_indicator_count = sum(
        classification["execution_indicator_count"]
        for classification in classifications
    )

    credential_indicator_count = sum(
        classification["credential_indicator_count"]
        for classification in classifications
    )

    persistence_indicator_count = sum(
        classification["persistence_indicator_count"]
        for classification in classifications
    )

    obfuscation_indicator_count = sum(
        classification["obfuscation_indicator_count"]
        for classification in classifications
    )

    office_indicator_count = sum(
        classification["office_indicator_count"] for classification in classifications
    )

    base64_like_count = sum(
        classification["looks_like_base64"] for classification in classifications
    )

    hex_like_count = sum(
        classification["looks_like_hex"] for classification in classifications
    )

    high_entropy_count = sum(
        classification["is_high_entropy"] for classification in classifications
    )

    very_high_entropy_count = sum(
        classification["is_very_high_entropy"] for classification in classifications
    )

    shell_metacharacter_count = sum(
        classification["shell_metacharacter_count"]
        for classification in classifications
    )

    environment_variable_count = sum(
        classification["environment_variable_count"]
        for classification in classifications
    )

    url_ip_host_count = sum(
        classification["url_host_is_ip"] for classification in classifications
    )

    url_nonstandard_port_count = sum(
        classification["url_has_nonstandard_port"] for classification in classifications
    )

    url_long_path_count = sum(
        classification["url_has_long_path"] for classification in classifications
    )

    url_encoded_data_count = sum(
        classification["url_has_encoded_data"] for classification in classifications
    )

    features: dict[str, Any] = {
        "strings_version": 1,
        # Basic extraction statistics.
        "string_count": statistics.count,
        "string_total_characters": statistics.total_characters,
        "string_min_length": statistics.minimum_length,
        "string_max_length": statistics.maximum_length,
        "string_mean_length": statistics.mean_length,
        "string_median_length": statistics.median_length,
        "string_stddev_length": (statistics.standard_deviation_length),
        "string_short_count": statistics.short_string_count,
        "string_medium_count": statistics.medium_string_count,
        "string_long_count": statistics.long_string_count,
        "string_very_long_count": (statistics.very_long_string_count),
        "string_ascii_count": statistics.ascii_count,
        "string_utf8_count": statistics.utf8_count,
        "string_utf16le_count": statistics.utf16le_count,
        "string_utf16be_count": statistics.utf16be_count,
        "string_high_entropy_count": high_entropy_count,
        "string_very_high_entropy_count": (very_high_entropy_count),
        # Semantic indicators.
        "string_url_count": len(url_values),
        "string_email_count": len(email_values),
        "string_ipv4_count": len(ipv4_values),
        "string_ipv6_count": len(ipv6_values),
        "string_windows_path_count": len(windows_paths),
        "string_unc_path_count": len(unc_paths),
        "string_powershell_indicator_count": powershell_count,
        "string_windows_command_indicator_count": (windows_command_count),
        "string_script_engine_indicator_count": (script_engine_count),
        "string_command_argument_indicator_count": (command_argument_count),
        "string_network_command_indicator_count": (network_command_count),
        "string_execution_indicator_count": (execution_indicator_count),
        "string_credential_indicator_count": (credential_indicator_count),
        "string_persistence_indicator_count": (persistence_indicator_count),
        "string_obfuscation_indicator_count": (obfuscation_indicator_count),
        "string_office_indicator_count": (office_indicator_count),
        # Encoded data.
        "string_base64_like_count": base64_like_count,
        "string_hex_like_count": hex_like_count,
        # Shell / environment characteristics.
        "string_shell_metacharacter_count": (shell_metacharacter_count),
        "string_environment_variable_count": (environment_variable_count),
        # URL characteristics.
        "string_url_ip_host_count": url_ip_host_count,
        "string_url_nonstandard_port_count": (url_nonstandard_port_count),
        "string_url_long_path_count": (url_long_path_count),
        "string_url_encoded_data_count": (url_encoded_data_count),
        # High-level boolean indicators.
        "strings_contain_urls": bool(url_values),
        "strings_contain_emails": bool(email_values),
        "strings_contain_ipv4": bool(ipv4_values),
        "strings_contain_ipv6": bool(ipv6_values),
        "strings_contain_windows_paths": bool(windows_paths),
        "strings_contain_unc_paths": bool(unc_paths),
        "strings_contain_powershell": powershell_count > 0,
        "strings_contain_windows_commands": (windows_command_count > 0),
        "strings_contain_script_engines": (script_engine_count > 0),
        "strings_contain_execution_indicators": (execution_indicator_count > 0),
        "strings_contain_network_commands": (network_command_count > 0),
        "strings_contain_credential_indicators": (credential_indicator_count > 0),
        "strings_contain_persistence_indicators": (persistence_indicator_count > 0),
        "strings_contain_obfuscation_indicators": (obfuscation_indicator_count > 0),
        "strings_contain_office_indicators": (office_indicator_count > 0),
        "strings_contain_base64_like_data": (base64_like_count > 0),
        "strings_contain_hex_like_data": (hex_like_count > 0),
        "strings_contain_high_entropy_data": (high_entropy_count > 0),
    }

    if include_string_values:
        features["strings"] = [item.to_dict() for item in strings]

        features["string_classifications"] = [
            {
                "offset": item.offset,
                "encoding": item.encoding,
                "value": item.value,
                "classification": classification,
            }
            for item, classification in zip(
                strings,
                classifications,
            )
        ]

        features["string_urls"] = url_values
        features["string_emails"] = email_values
        features["string_ipv4_addresses"] = ipv4_values
        features["string_ipv6_addresses"] = ipv6_values
        features["string_windows_paths"] = windows_paths
        features["string_unc_paths"] = unc_paths

    return _round_floats(features)


# ---------------------------------------------------------------------------
# File analysis
# ---------------------------------------------------------------------------


def analyze_file(
    file_path: str,
    *,
    max_sample_size: int = DEFAULT_MAX_ANALYSIS_SAMPLE,
    min_ascii_length: int = DEFAULT_MIN_ASCII_LENGTH,
    min_unicode_length: int = DEFAULT_MIN_UNICODE_LENGTH,
    max_string_length: int = DEFAULT_MAX_STRING_LENGTH,
    max_strings: int = DEFAULT_MAX_STRINGS,
    include_string_values: bool = True,
) -> dict[str, Any]:
    """
    Analyze strings in a file.

    Large files are sampled from the beginning, middle, and end to keep memory
    consumption bounded.

    The sampling strategy intentionally mirrors the approach used by the
    entropy module so that the two modules analyze comparable regions.
    """
    if max_sample_size <= 0:
        raise ValueError("max_sample_size must be greater than zero")

    with open(file_path, "rb") as handle:
        handle.seek(0, 2)
        file_size = handle.tell()

        if file_size <= max_sample_size:
            handle.seek(0)
            data = handle.read()

            sampled = False

        else:
            beginning_size = max_sample_size // 3
            middle_size = max_sample_size // 3
            ending_size = max_sample_size - beginning_size - middle_size

            handle.seek(0)
            beginning = handle.read(beginning_size)

            middle_offset = max(
                0,
                (file_size // 2) - (middle_size // 2),
            )

            handle.seek(middle_offset)
            middle = handle.read(middle_size)

            ending_offset = max(
                0,
                file_size - ending_size,
            )

            handle.seek(ending_offset)
            ending = handle.read(ending_size)

            data = beginning + middle + ending
            sampled = True

    result = analyze_strings(
        data,
        min_ascii_length=min_ascii_length,
        min_unicode_length=min_unicode_length,
        max_string_length=max_string_length,
        max_strings=max_strings,
        include_string_values=include_string_values,
    )

    result.update(
        {
            "string_file_size_bytes": file_size,
            "string_sample_size_bytes": len(data),
            "string_sample_coverage_ratio": (
                len(data) / file_size if file_size > 0 else 0.0
            ),
            "string_sampling_used": sampled,
            "string_max_sample_size": max_sample_size,
        }
    )

    return _round_floats(result)


# ---------------------------------------------------------------------------
# ML feature API
# ---------------------------------------------------------------------------


def extract_string_features(
    file_path: str,
    *,
    max_sample_size: int = DEFAULT_MAX_ANALYSIS_SAMPLE,
    min_ascii_length: int = DEFAULT_MIN_ASCII_LENGTH,
    min_unicode_length: int = DEFAULT_MIN_UNICODE_LENGTH,
    max_string_length: int = DEFAULT_MAX_STRING_LENGTH,
    max_strings: int = DEFAULT_MAX_STRINGS,
) -> dict[str, Any]:
    """
    Return scalar string features suitable for the ML feature pipeline.

    Detailed strings, URLs, paths, and classification structures are excluded
    from the returned feature vector.
    """
    analysis = analyze_file(
        file_path,
        max_sample_size=max_sample_size,
        min_ascii_length=min_ascii_length,
        min_unicode_length=min_unicode_length,
        max_string_length=max_string_length,
        max_strings=max_strings,
        include_string_values=False,
    )

    return {
        key: value
        for key, value in analysis.items()
        if isinstance(value, (bool, int, float))
    }


# ---------------------------------------------------------------------------
# Serialization helpers
# ---------------------------------------------------------------------------


def _round_floats(
    value: Any,
    *,
    digits: int = 6,
) -> Any:
    """Recursively round floats for deterministic serialization."""
    if isinstance(value, float):
        return round(value, digits)

    if isinstance(value, list):
        return [_round_floats(item, digits=digits) for item in value]

    if isinstance(value, tuple):
        return tuple(_round_floats(item, digits=digits) for item in value)

    if isinstance(value, dict):
        return {key: _round_floats(item, digits=digits) for key, item in value.items()}

    return value


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

__all__ = [
    "ExtractedString",
    "StringStatistics",
    "extract_ascii_strings",
    "extract_utf8_strings",
    "extract_utf16_strings",
    "extract_strings",
    "extract_urls",
    "extract_emails",
    "extract_ipv4_addresses",
    "extract_ipv6_addresses",
    "extract_windows_paths",
    "extract_unc_paths",
    "is_valid_ipv4",
    "is_valid_ipv6",
    "looks_like_base64",
    "looks_like_hex",
    "string_entropy",
    "is_high_entropy_string",
    "classify_string",
    "string_statistics",
    "analyze_strings",
    "analyze_file",
    "extract_string_features",
]
