"""
Static network-behavior extraction for Pharos CDR.

This module analyzes network-related behavior represented in source text,
strings, logs, metadata, extracted script/VBA content, or nested analysis
objects. It deliberately performs no network activity.

The extractor is intended to sit in the static-analysis chain:

    document/script/binary
        -> network behavior extraction
        -> capability/feature pipeline
        -> ML / CDR policy / reporting

Security properties
-------------------
- Never opens sockets.
- Never performs DNS resolution.
- Never makes HTTP/HTTPS requests.
- Never contacts discovered IP addresses or domains.
- Never executes commands or scripts.
- Never loads external modules.
- Never downloads discovered URLs.
- Never writes extracted network artifacts to disk.
- Uses bounded parsing to avoid pathological input sizes.

The implementation recognizes:
- URLs and URI schemes
- IPv4 and IPv6 addresses
- domains and hostnames
- ports
- DNS operations
- HTTP/HTTPS
- WinINet / WinHTTP
- Winsock
- PowerShell networking
- curl/wget/bitsadmin/certutil-style transfer indicators
- COM/XMLHTTP/WinHttpRequest
- socket APIs
- reverse/bind-shell terminology
- proxy configuration
- firewall/network configuration
- network discovery
- SMB/UNC paths
- FTP/TFTP
- SMTP
- LDAP
- RDP
- WebDAV
- named network shares
- downloads/uploads
- command-and-control style indicators
- network + execution / persistence / obfuscation combinations

The module is heuristic. Presence of a network indicator does not imply
maliciousness; callers should combine these features with document,
script, execution, persistence, credential, and other behavioral signals.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import math
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

MAX_NETWORK_RECORDS = 10_000
MAX_HOSTS = 10_000
MAX_URLS = 10_000
MAX_IPS = 10_000
MAX_DOMAINS = 10_000
MAX_PORTS = 10_000

MAX_COMMAND_LINES = 20_000
MAX_TOKENS = 250_000


# ---------------------------------------------------------------------------
# Taxonomy
# ---------------------------------------------------------------------------

NETWORK_CATEGORIES: Tuple[str, ...] = (
    "network_access",
    "network_connection",
    "network_listener",
    "network_client",
    "network_server",
    "dns",
    "http",
    "https",
    "ftp",
    "tftp",
    "smtp",
    "ldap",
    "smb",
    "webdav",
    "rdp",
    "winsock",
    "wininet",
    "winhttp",
    "socket_api",
    "download",
    "upload",
    "network_transfer",
    "network_discovery",
    "host_discovery",
    "service_discovery",
    "share_discovery",
    "proxy",
    "firewall",
    "network_configuration",
    "network_credentials",
    "authentication",
    "encrypted_communication",
    "c2",
    "remote_access",
    "reverse_shell",
    "bind_shell",
    "callback",
    "external_resource",
    "unc_path",
    "url",
    "ip_address",
    "domain",
    "port",
    "network_obfuscation",
    "network_execution",
    "network_persistence",
    "network_evasion",
    "network_apis",
    "network_command",
)


SEVERITY_ORDER = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class NetworkPattern:
    """One static rule used to identify network behavior."""

    name: str
    category: str
    pattern: str
    severity: str = "medium"
    confidence: float = 0.8
    operation: Optional[str] = None
    description: str = ""


@dataclass
class NetworkEvidence:
    """One bounded piece of evidence supporting a network finding."""

    category: str
    indicator: str
    evidence: str
    source: str = "text"
    line_number: Optional[int] = None
    operation: Optional[str] = None
    host: Optional[str] = None
    domain: Optional[str] = None
    ip_address: Optional[str] = None
    port: Optional[int] = None
    protocol: Optional[str] = None
    confidence: float = 0.8
    severity: str = "medium"


@dataclass
class NetworkRecord:
    """Structured representation of a discovered network artifact."""

    kind: str
    value: str
    normalized: str
    source: str = "text"
    protocol: Optional[str] = None
    host: Optional[str] = None
    domain: Optional[str] = None
    ip_address: Optional[str] = None
    port: Optional[int] = None
    path: Optional[str] = None
    operation: Optional[str] = None
    line_number: Optional[int] = None
    indicators: List[str] = field(default_factory=list)
    categories: List[str] = field(default_factory=list)


@dataclass(frozen=True)
class NetworkCombination:
    """A higher-confidence behavioral combination."""

    name: str
    present: bool
    required_categories: Tuple[str, ...] = ()
    required_indicators: Tuple[str, ...] = ()
    explanation: str = ""


@dataclass
class NetworkAnalysis:
    """Complete static network-behavior analysis."""

    source_hash: str
    source_size: int

    records: List[NetworkRecord] = field(default_factory=list)
    evidence: List[NetworkEvidence] = field(default_factory=list)

    urls: List[str] = field(default_factory=list)
    hosts: List[str] = field(default_factory=list)
    domains: List[str] = field(default_factory=list)
    ip_addresses: List[str] = field(default_factory=list)
    ports: List[int] = field(default_factory=list)

    protocols: List[str] = field(default_factory=list)
    indicators: List[str] = field(default_factory=list)
    categories: List[str] = field(default_factory=list)
    combinations: List[NetworkCombination] = field(default_factory=list)

    feature_vector: Dict[str, Union[int, float]] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Protocol / vocabulary constants
# ---------------------------------------------------------------------------


KNOWN_PROTOCOLS: Tuple[str, ...] = (
    "http",
    "https",
    "ftp",
    "ftps",
    "tftp",
    "smtp",
    "smtps",
    "imap",
    "imaps",
    "pop3",
    "pop3s",
    "ldap",
    "ldaps",
    "smb",
    "smb2",
    "webdav",
    "ws",
    "wss",
    "tcp",
    "udp",
    "icmp",
    "rdp",
    "ssh",
    "telnet",
    "dns",
)


COMMON_PORTS: Dict[int, str] = {
    20: "ftp-data",
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    119: "nntp",
    123: "ntp",
    135: "rpc",
    137: "netbios-ns",
    138: "netbios-dgm",
    139: "netbios-ssn",
    143: "imap",
    161: "snmp",
    389: "ldap",
    443: "https",
    445: "smb",
    465: "smtps",
    587: "submission",
    636: "ldaps",
    993: "imaps",
    995: "pop3s",
    1433: "mssql",
    1521: "oracle",
    1723: "pptp",
    3306: "mysql",
    3389: "rdp",
    5432: "postgresql",
    5900: "vnc",
    5985: "winrm-http",
    5986: "winrm-https",
    8080: "http-alt",
    8443: "https-alt",
}


NETWORK_COMMANDS: Tuple[str, ...] = (
    "curl",
    "wget",
    "bitsadmin",
    "certutil",
    "ftp",
    "tftp",
    "invoke-webrequest",
    "invoke-restmethod",
    "start-bitstransfer",
    "net use",
    "net view",
    "net share",
    "net session",
    "netstat",
    "ipconfig",
    "route print",
    "arp -a",
    "nslookup",
    "ping",
    "tracert",
    "pathping",
    "nbtstat",
    "wevtutil",
    "winrm",
    "psexec",
)


NETWORK_API_NAMES: Tuple[str, ...] = (
    "socket",
    "connect",
    "bind",
    "listen",
    "accept",
    "send",
    "sendto",
    "recv",
    "recvfrom",
    "getaddrinfo",
    "gethostbyname",
    "gethostbyaddr",
    "getnameinfo",
    "inet_addr",
    "inet_ntoa",
    "wsastartup",
    "wsacleanup",
    "wsasocket",
    "wsaconnect",
    "wsasend",
    "wsarecv",
    "winhttpopen",
    "winhttpconnect",
    "winhttpsendrequest",
    "winhttpopenrequest",
    "winhttpreaddata",
    "wininet",
    "internetopen",
    "internetconnect",
    "internetopenurl",
    "httpopenrequest",
    "httpsendrequest",
    "internetreadfile",
    "urldownloadtofile",
    "urldownloadtofilea",
    "urldownloadtofilew",
    "urldownloadcacheentryfile",
    "urlmon",
    "winhttpreaddata",
    "winhttpwriteData",
    "internetwritefile",
    "dnsquery",
    "dnsextract",
    "getaddrinfo",
    "xmlhttp",
    "serverxmlhttp",
    "winhttprequest",
    "xmlhttp.request",
    "xmlhttp.open",
    "xmlhttp.send",
    "winhttprequest.open",
    "winhttprequest.send",
)


# ---------------------------------------------------------------------------
# Regexes
# ---------------------------------------------------------------------------


URL_RE = re.compile(r"""(?ix)
    \b
    (?:
        https?|ftp|ftps|tftp|ldap|ldaps|smb|ws|wss
    )
    ://
    [^\s<>"'`(){}\[\]]{1,4096}
    """)

# UNC paths such as:
# \\server\share
# \\10.0.0.1\share
UNC_RE = re.compile(r"""(?i)
    (?<![A-Za-z0-9_])
    \\\\
    (?:
        [A-Za-z0-9._$-]+
        |
        (?:\d{1,3}\.){3}\d{1,3}
        |
        \[[0-9A-Fa-f:]+\]
    )
    (?:\\[^\\\r\n"']{1,255})+
    """)

# IPv4 with optional :port.
IPV4_RE = re.compile(
    r"(?<![\d.])"
    r"(?P<ip>(?:\d{1,3}\.){3}\d{1,3})"
    r"(?::(?P<port>\d{1,5}))?"
    r"(?![\d.])"
)

# Bracketed IPv6, optionally followed by a port.
IPV6_BRACKET_RE = re.compile(
    r"(?<![A-Za-z0-9])"
    r"\[(?P<ip>[0-9A-Fa-f:.]{2,45})\]"
    r"(?::(?P<port>\d{1,5}))?"
    r"(?![A-Za-z0-9])"
)

# Bare IPv6. This is intentionally conservative to avoid treating ordinary
# colon-separated text as an IP address.
IPV6_RE = re.compile(
    r"(?<![A-Za-z0-9:])"
    r"(?P<ip>"
    r"(?:[0-9A-Fa-f]{1,4}:){2,7}"
    r"[0-9A-Fa-f]{0,4}"
    r")"
    r"(?![A-Za-z0-9:])"
)

DOMAIN_RE = re.compile(r"""(?ix)
    (?<![@A-Za-z0-9_-])
    (?P<domain>
        (?:[A-Za-z0-9](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9])?\.)+
        [A-Za-z]{2,63}
    )
    (?::(?P<port>\d{1,5}))?
    (?![A-Za-z0-9_.-])
    """)

HOSTNAME_RE = re.compile(r"""(?ix)
    (?<![A-Za-z0-9_-])
    (?P<host>
        [A-Za-z0-9](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9])?
        (?:\.[A-Za-z0-9](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9])?)+
    )
    (?![A-Za-z0-9_.-])
    """)

PORT_RE = re.compile(r"""(?ix)
    (?:
        \bport\s*[:=]\s*(?P<port1>\d{1,5})
        |
        \b(?:tcp|udp)\s*[/:\-]\s*(?P<port2>\d{1,5})
        |
        :(?P<port3>\d{1,5})(?!\d)
    )
    """)


# ---------------------------------------------------------------------------
# Network API rules
# ---------------------------------------------------------------------------


API_RULES: Tuple[NetworkPattern, ...] = (
    NetworkPattern(
        "socket_api",
        "socket_api",
        r"\b(?:socket|WSASocket|WSAStartup|WSACleanup)\s*\(",
        "medium",
        0.96,
        "socket",
        "Winsock socket initialization or creation.",
    ),
    NetworkPattern(
        "connect_api",
        "network_connection",
        r"\b(?:connect|WSAConnect)\s*\(",
        "medium",
        0.96,
        "connect",
        "Network connection API.",
    ),
    NetworkPattern(
        "listener_api",
        "network_listener",
        r"\b(?:bind|listen|accept)\s*\(",
        "medium",
        0.96,
        "listen",
        "Socket listener/server API.",
    ),
    NetworkPattern(
        "socket_send_api",
        "network_transfer",
        r"\b(?:send|sendto|WSASend|InternetWriteFile|WinHttpWriteData)\s*\(",
        "medium",
        0.95,
        "send",
        "Network data transmission API.",
    ),
    NetworkPattern(
        "socket_receive_api",
        "network_transfer",
        r"\b(?:recv|recvfrom|WSARecv|InternetReadFile|WinHttpReadData)\s*\(",
        "medium",
        0.95,
        "receive",
        "Network data reception API.",
    ),
    NetworkPattern(
        "dns_resolution_api",
        "dns",
        r"\b(?:getaddrinfo|gethostbyname|gethostbyaddr|getnameinfo|DnsQuery(?:_A|_W)?)\s*\(",
        "low",
        0.95,
        "resolve",
        "DNS/hostname resolution API.",
    ),
    NetworkPattern(
        "wininet_api",
        "wininet",
        r"\b(?:InternetOpen|InternetConnect|InternetOpenUrl|HttpOpenRequest|HttpSendRequest|InternetReadFile)\s*\(",
        "medium",
        0.96,
        "http",
        "WinINet network API usage.",
    ),
    NetworkPattern(
        "winhttp_api",
        "winhttp",
        r"\b(?:WinHttpOpen|WinHttpConnect|WinHttpOpenRequest|WinHttpSendRequest|WinHttpReadData)\s*\(",
        "medium",
        0.96,
        "http",
        "WinHTTP network API usage.",
    ),
    NetworkPattern(
        "urlmon_download",
        "download",
        r"\b(?:URLDownloadToFile(?:A|W)?|CoInternetGetSession)\s*\(",
        "high",
        0.98,
        "download",
        "URLMon/file download functionality.",
    ),
    NetworkPattern(
        "xmlhttp",
        "http",
        r"\b(?:MSXML2\.)?(?:XMLHTTP|ServerXMLHTTP|WinHttpRequest)\b",
        "medium",
        0.94,
        "http",
        "COM HTTP client object.",
    ),
    NetworkPattern(
        "http_request",
        "http",
        r"\b(?:XMLHTTP|ServerXMLHTTP|WinHttpRequest)\s*\.\s*(?:open|send)\s*\(",
        "medium",
        0.97,
        "http",
        "COM HTTP request operation.",
    ),
    NetworkPattern(
        "network_library_reference",
        "network_apis",
        r"(?i)\b(?:wininet|winhttp|ws2_32|wsock32|urlmon|dnsapi)\b",
        "low",
        0.88,
        "library",
        "Reference to a network-related Windows library.",
    ),
)


# ---------------------------------------------------------------------------
# Network command rules
# ---------------------------------------------------------------------------


COMMAND_RULES: Tuple[NetworkPattern, ...] = (
    NetworkPattern(
        "curl",
        "download",
        r"(?i)(?:^|[;&|`\s])curl(?:\.exe)?(?:\s|$)",
        "medium",
        0.95,
        "download",
        "curl network client.",
    ),
    NetworkPattern(
        "wget",
        "download",
        r"(?i)(?:^|[;&|`\s])wget(?:\.exe)?(?:\s|$)",
        "medium",
        0.95,
        "download",
        "wget network client.",
    ),
    NetworkPattern(
        "bitsadmin",
        "download",
        r"(?i)\bbitsadmin(?:\.exe)?\b",
        "high",
        0.98,
        "download",
        "BITS transfer utility.",
    ),
    NetworkPattern(
        "certutil_urlcache",
        "download",
        r"(?i)\bcertutil(?:\.exe)?\b[^\r\n]{0,500}\b-urlcache\b",
        "high",
        0.97,
        "download",
        "certutil URL-cache transfer syntax.",
    ),
    NetworkPattern(
        "powershell_web_request",
        "download",
        r"(?i)\b(?:Invoke-WebRequest|Invoke-RestMethod|Start-BitsTransfer)\b",
        "medium",
        0.96,
        "download",
        "PowerShell web/transfer cmdlet.",
    ),
    NetworkPattern(
        "powershell_webclient",
        "download",
        r"(?i)\b(?:Net\.WebClient|System\.Net\.WebClient|DownloadString|DownloadFile|OpenRead)\b",
        "high",
        0.97,
        "download",
        "PowerShell/.NET network transfer API.",
    ),
    NetworkPattern(
        "ftp_command",
        "ftp",
        r"(?i)(?:^|[;&|`\s])ftp(?:\.exe)?(?:\s|$)",
        "medium",
        0.94,
        "ftp",
        "FTP client usage.",
    ),
    NetworkPattern(
        "tftp_command",
        "tftp",
        r"(?i)(?:^|[;&|`\s])tftp(?:\.exe)?(?:\s|$)",
        "medium",
        0.94,
        "tftp",
        "TFTP client usage.",
    ),
    NetworkPattern(
        "net_use",
        "smb",
        r"(?i)\bnet(?:\.exe)?\s+use\b",
        "medium",
        0.95,
        "connect",
        "SMB/network share mapping.",
    ),
    NetworkPattern(
        "net_view",
        "share_discovery",
        r"(?i)\bnet(?:\.exe)?\s+view\b",
        "low",
        0.95,
        "discover",
        "Network/share discovery command.",
    ),
    NetworkPattern(
        "net_share",
        "share_discovery",
        r"(?i)\bnet(?:\.exe)?\s+share\b",
        "medium",
        0.94,
        "discover",
        "Local share enumeration/configuration.",
    ),
    NetworkPattern(
        "net_session",
        "network_discovery",
        r"(?i)\bnet(?:\.exe)?\s+session\b",
        "medium",
        0.94,
        "discover",
        "Network session enumeration.",
    ),
    NetworkPattern(
        "netstat",
        "network_discovery",
        r"(?i)\bnetstat(?:\.exe)?\b",
        "low",
        0.96,
        "discover",
        "Network connection/listener enumeration.",
    ),
    NetworkPattern(
        "ipconfig",
        "host_discovery",
        r"(?i)\bipconfig(?:\.exe)?\b",
        "low",
        0.96,
        "discover",
        "Local network configuration discovery.",
    ),
    NetworkPattern(
        "arp",
        "network_discovery",
        r"(?i)\barp(?:\.exe)?\s+-a\b",
        "low",
        0.95,
        "discover",
        "ARP/network neighbor discovery.",
    ),
    NetworkPattern(
        "nslookup",
        "dns",
        r"(?i)\bnslookup(?:\.exe)?\b",
        "low",
        0.96,
        "resolve",
        "DNS query utility.",
    ),
    NetworkPattern(
        "ping",
        "network_discovery",
        r"(?i)\bping(?:\.exe)?\b",
        "low",
        0.90,
        "discover",
        "ICMP/network reachability check.",
    ),
    NetworkPattern(
        "tracert",
        "network_discovery",
        r"(?i)\b(?:tracert|traceroute|pathping)(?:\.exe)?\b",
        "low",
        0.95,
        "discover",
        "Network path discovery.",
    ),
    NetworkPattern(
        "nbtstat",
        "network_discovery",
        r"(?i)\bnbtstat(?:\.exe)?\b",
        "low",
        0.95,
        "discover",
        "NetBIOS/network discovery utility.",
    ),
)


# ---------------------------------------------------------------------------
# Higher-level static rules
# ---------------------------------------------------------------------------


BEHAVIOR_RULES: Tuple[NetworkPattern, ...] = (
    NetworkPattern(
        "reverse_shell",
        "reverse_shell",
        r"(?i)\b(?:reverse\s+shell|reverse\s+tcp|connect[-\s]?back|callback\s+shell)\b",
        "critical",
        0.97,
        "callback",
        "Explicit reverse-shell/callback terminology.",
    ),
    NetworkPattern(
        "bind_shell",
        "bind_shell",
        r"(?i)\b(?:bind\s+shell|listen(?:ing)?\s+shell)\b",
        "high",
        0.96,
        "listen",
        "Explicit bind-shell terminology.",
    ),
    NetworkPattern(
        "network_execution",
        "network_execution",
        r"(?i)\b(?:download(?:ed|s)?|retriev(?:e|ed|es)|fetch(?:ed|es)?)\b[^\r\n]{0,200}\b(?:execute|run|start|invoke|launch)\b",
        "high",
        0.90,
        "download_execute",
        "Textual download followed by execution behavior.",
    ),
    NetworkPattern(
        "remote_execution",
        "network_execution",
        r"(?i)\b(?:psexec|wmic|winrm|remote\s+service|remote\s+execution)\b",
        "high",
        0.96,
        "remote_execute",
        "Remote execution mechanism.",
    ),
    NetworkPattern(
        "proxy_configuration",
        "proxy",
        r"(?i)\b(?:proxy(?:server|url)?|winhttp\s+set\s+proxy|netsh\s+winhttp\s+set\s+proxy)\b",
        "medium",
        0.93,
        "configure",
        "Proxy configuration or reference.",
    ),
    NetworkPattern(
        "firewall_configuration",
        "firewall",
        r"(?i)\b(?:netsh\s+advfirewall|windows\s+firewall|firewall\s+rule|New-NetFirewallRule|Set-NetFirewallRule|Remove-NetFirewallRule)\b",
        "high",
        0.96,
        "configure",
        "Firewall configuration or modification.",
    ),
    NetworkPattern(
        "credential_network_access",
        "network_credentials",
        r"(?i)\b(?:net\s+use\s+\\\\|cmdkey|credential\s+manager|saved\s+credentials|network\s+credential)\b",
        "medium",
        0.92,
        "credential",
        "Network credential access or use.",
    ),
    NetworkPattern(
        "smb_remote_share",
        "smb",
        r"(?i)\\\\[A-Za-z0-9._$-]+\\[^\s\\/:*?\"<>|]+",
        "medium",
        0.96,
        "share",
        "SMB/UNC network share reference.",
    ),
    NetworkPattern(
        "ldap_access",
        "ldap",
        r"(?i)\b(?:LDAP|LDAPS|ldap://|ldaps://|DirectoryEntry|DirectorySearcher)\b",
        "medium",
        0.94,
        "query",
        "LDAP/directory-service access.",
    ),
    NetworkPattern(
        "rdp_access",
        "rdp",
        r"(?i)\b(?:mstsc(?:\.exe)?|remote\s+desktop|rdp://|3389/tcp)\b",
        "medium",
        0.94,
        "remote_access",
        "Remote Desktop/RDP reference.",
    ),
    NetworkPattern(
        "webdav_access",
        "webdav",
        r"(?i)\b(?:webdav|webclient|\\\\[^\\\s]+@SSL\\DavWWWRoot)\b",
        "medium",
        0.90,
        "remote_access",
        "WebDAV/network WebClient reference.",
    ),
    NetworkPattern(
        "encrypted_transport",
        "encrypted_communication",
        r"(?i)\b(?:https|wss|tls|ssl|schannel|secure\s+socket|SslStream|HttpsURLConnection)\b",
        "low",
        0.88,
        "encrypted",
        "Encrypted network transport indicator.",
    ),
    NetworkPattern(
        "network_obfuscation",
        "network_obfuscation",
        r"(?i)\b(?:base64|frombase64string|urldecode|urlencode|hex(?:adecimal)?|xor)\b[^\r\n]{0,250}\b(?:url|uri|host|domain|http|https|socket|connect)\b",
        "high",
        0.87,
        "obfuscate",
        "Possible obfuscation of network material.",
    ),
)


# ---------------------------------------------------------------------------
# Utility functions
# ---------------------------------------------------------------------------


def _safe_text(value: Any, limit: int = MAX_FIELD_TEXT) -> str:
    """Convert an arbitrary object into bounded text without executing it."""
    if value is None:
        return ""

    if isinstance(value, bytes):
        return value[:limit].decode("utf-8", errors="replace")

    if isinstance(value, str):
        return value[:limit]

    if isinstance(value, Path):
        try:
            return str(value)[:limit]
        except Exception:
            return ""

    if isinstance(value, (int, float, bool)):
        return str(value)[:limit]

    if isinstance(value, Mapping):
        try:
            return json.dumps(value, ensure_ascii=False, default=str)[:limit]
        except Exception:
            return str(value)[:limit]

    if isinstance(value, (list, tuple, set, frozenset)):
        try:
            return repr(value)[:limit]
        except Exception:
            return ""

    try:
        return str(value)[:limit]
    except Exception:
        return ""


def _read_source(source: Any) -> Tuple[str, int, str]:
    """
    Return (text, source_size, source_hash).

    A path is read only as input data. No discovered network resource is
    accessed.
    """
    if isinstance(source, (bytes, bytearray, memoryview)):
        raw = bytes(source)
        bounded = raw[:MAX_SOURCE_SIZE]
        return (
            bounded.decode("utf-8", errors="replace"),
            len(raw),
            hashlib.sha256(raw[:MAX_SOURCE_SIZE]).hexdigest(),
        )

    if isinstance(source, Path):
        path = source
        try:
            size = path.stat().st_size
            with path.open("rb") as handle:
                raw = handle.read(MAX_SOURCE_SIZE)
            return (
                raw.decode("utf-8", errors="replace"),
                int(size),
                hashlib.sha256(raw).hexdigest(),
            )
        except (OSError, ValueError):
            text = str(path)
            return text[:MAX_TEXT_CHARS], len(text), _sha256_text(text)

    if isinstance(source, str):
        # Only treat an existing local filesystem path as a path. The module
        # never interprets URLs as paths to fetch.
        if len(source) <= 4096:
            try:
                possible_path = Path(source)
                if possible_path.exists() and possible_path.is_file():
                    size = possible_path.stat().st_size
                    with possible_path.open("rb") as handle:
                        raw = handle.read(MAX_SOURCE_SIZE)
                    return (
                        raw.decode("utf-8", errors="replace"),
                        int(size),
                        hashlib.sha256(raw).hexdigest(),
                    )
            except (OSError, ValueError, PermissionError):
                pass

        text = source[:MAX_TEXT_CHARS]
        return text, len(source), _sha256_text(text)

    if isinstance(source, Mapping):
        parts: List[str] = []
        total = 0

        def append(value: Any) -> None:
            nonlocal total
            if total >= MAX_TEXT_CHARS:
                return
            text = _safe_text(value)
            if not text:
                return
            remaining = MAX_TEXT_CHARS - total
            text = text[:remaining]
            parts.append(text)
            total += len(text) + 1

        _flatten_mapping(source, append)
        text = "\n".join(parts)[:MAX_TEXT_CHARS]
        return text, len(text), _sha256_text(text)

    if isinstance(source, (list, tuple, set, frozenset)):
        parts = []
        total = 0

        for item in source:
            if total >= MAX_TEXT_CHARS:
                break
            text = _safe_text(item)
            if not text:
                continue
            remaining = MAX_TEXT_CHARS - total
            text = text[:remaining]
            parts.append(text)
            total += len(text) + 1

        text = "\n".join(parts)[:MAX_TEXT_CHARS]
        return text, len(text), _sha256_text(text)

    text = _safe_text(source, MAX_TEXT_CHARS)
    return text, len(text), _sha256_text(text)


def _flatten_mapping(
    value: Any,
    append: Any,
    depth: int = 0,
) -> None:
    """Flatten nested structures without traversing unbounded object graphs."""
    if depth > MAX_NESTING_DEPTH:
        return

    if isinstance(value, Mapping):
        for key, item in value.items():
            append(key)
            if depth < MAX_NESTING_DEPTH:
                _flatten_mapping(item, append, depth + 1)
        return

    if isinstance(value, (list, tuple, set, frozenset)):
        for item in value:
            if depth < MAX_NESTING_DEPTH:
                _flatten_mapping(item, append, depth + 1)
            else:
                append(item)
        return

    append(value)


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def _normalize_whitespace(value: str) -> str:
    return re.sub(r"\s+", " ", value).strip()


def _clip(value: str, limit: int = MAX_FIELD_TEXT) -> str:
    value = value or ""
    if len(value) <= limit:
        return value
    return value[:limit] + "…"


def _safe_confidence(value: float) -> float:
    try:
        return max(0.0, min(1.0, float(value)))
    except (TypeError, ValueError):
        return 0.0


def _valid_port(value: Any) -> Optional[int]:
    try:
        port = int(value)
    except (TypeError, ValueError):
        return None

    if 1 <= port <= 65535:
        return port

    return None


def _normalize_ip(value: str) -> Optional[str]:
    value = value.strip().strip("[]")

    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


def _is_public_ip(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
        return not (
            address.is_private
            or address.is_loopback
            or address.is_link_local
            or address.is_multicast
            or address.is_unspecified
            or address.is_reserved
        )
    except ValueError:
        return False


def _looks_like_domain(value: str) -> bool:
    value = value.rstrip(".").lower()

    if len(value) > 253:
        return False

    if "." not in value:
        return False

    try:
        return bool(DOMAIN_RE.fullmatch(value))
    except Exception:
        return False


def _normalize_domain(value: str) -> str:
    value = value.strip().rstrip(".").lower()
    return value


def _normalize_host(value: str) -> str:
    value = value.strip().strip("[]").rstrip(".").lower()
    return value


def _normalize_url(value: str) -> str:
    value = value.strip().rstrip(".,;")
    return value


def _protocol_from_url(url: str) -> Optional[str]:
    match = re.match(r"(?i)^([a-z][a-z0-9+.-]{1,15})://", url)
    if not match:
        return None
    return match.group(1).lower()


def _url_host_port_path(
    url: str,
) -> Tuple[Optional[str], Optional[int], Optional[str]]:
    """
    Parse a URL authority conservatively without performing any resolution.

    Returns (host, port, path).
    """
    match = re.match(
        r"(?is)^[a-z][a-z0-9+.-]{1,15}://([^/?#]{1,2048})([^?#]*)",
        url,
    )
    if not match:
        return None, None, None

    authority = match.group(1)
    path = match.group(2) or None

    # Remove userinfo. This is parsing only; credentials are not used.
    if "@" in authority:
        authority = authority.rsplit("@", 1)[1]

    host: Optional[str] = None
    port: Optional[int] = None

    if authority.startswith("["):
        end = authority.find("]")
        if end > 0:
            host = authority[1:end]
            remainder = authority[end + 1 :]
            if remainder.startswith(":"):
                port = _valid_port(remainder[1:])
    else:
        if ":" in authority:
            candidate_host, candidate_port = authority.rsplit(":", 1)
            parsed_port = _valid_port(candidate_port)
            if parsed_port is not None:
                host = candidate_host
                port = parsed_port
            else:
                host = authority
        else:
            host = authority

    if host:
        host = _normalize_host(host)

    return host or None, port, path


def _line_number(text: str, position: int) -> int:
    if position <= 0:
        return 1
    return text.count("\n", 0, position) + 1


def _append_unique(
    values: List[Any],
    value: Any,
    limit: int,
) -> None:
    if len(values) >= limit:
        return

    if value not in values:
        values.append(value)


def _iter_lines_bounded(text: str) -> Iterator[Tuple[int, str]]:
    for number, line in enumerate(text.splitlines(), start=1):
        if number > MAX_COMMAND_LINES:
            break
        yield number, line[:MAX_FIELD_TEXT]


# ---------------------------------------------------------------------------
# Pattern application
# ---------------------------------------------------------------------------


def _apply_patterns(
    text: str,
    patterns: Sequence[NetworkPattern],
    evidence: List[NetworkEvidence],
    seen: Set[Tuple[str, int, str]],
) -> None:
    """Apply bounded regex rules to source text."""
    if not text or len(evidence) >= MAX_EVIDENCE_ITEMS:
        return

    for rule in patterns:
        if len(evidence) >= MAX_EVIDENCE_ITEMS:
            break

        try:
            matches = re.finditer(
                rule.pattern,
                text,
                flags=re.IGNORECASE | re.MULTILINE,
            )
        except (re.error, TypeError):
            continue

        count = 0

        for match in matches:
            if count >= MAX_MATCHES_PER_RULE:
                break
            if len(evidence) >= MAX_EVIDENCE_ITEMS:
                break

            position = match.start()
            line = _line_number(text, position)

            raw = _clip(_normalize_whitespace(match.group(0)))
            if not raw:
                continue

            dedupe_key = (rule.name, line, raw[:512])
            if dedupe_key in seen:
                continue

            seen.add(dedupe_key)

            evidence.append(
                NetworkEvidence(
                    category=rule.category,
                    indicator=rule.name,
                    evidence=raw,
                    source="pattern",
                    line_number=line,
                    operation=rule.operation,
                    confidence=_safe_confidence(rule.confidence),
                    severity=rule.severity,
                )
            )

            count += 1


# ---------------------------------------------------------------------------
# URL extraction
# ---------------------------------------------------------------------------


def extract_urls(
    text: str,
    evidence: Optional[List[NetworkEvidence]] = None,
) -> List[NetworkRecord]:
    """
    Extract URLs and derive protocol/host/port information.

    No URL is resolved, fetched, or contacted.
    """
    records: List[NetworkRecord] = []
    seen: Set[str] = set()

    if not text:
        return records

    for match in URL_RE.finditer(text):
        if len(records) >= MAX_URLS:
            break

        url = _normalize_url(match.group(0))
        if not url or url.lower() in seen:
            continue

        seen.add(url.lower())

        protocol = _protocol_from_url(url)
        host, port, path = _url_host_port_path(url)

        ip_value = _normalize_ip(host) if host else None
        domain = None

        if host and not ip_value and _looks_like_domain(host):
            domain = _normalize_domain(host)

        categories: List[str] = ["url", "external_resource"]

        if protocol == "http":
            categories.append("http")
        elif protocol == "https":
            categories.extend(("http", "https"))
        elif protocol in {"ftp", "ftps"}:
            categories.append("ftp")
        elif protocol == "tftp":
            categories.append("tftp")
        elif protocol in {"ldap", "ldaps"}:
            categories.append("ldap")
        elif protocol in {"ws", "wss"}:
            categories.append("http")

        if ip_value:
            categories.append("ip_address")
        elif domain:
            categories.append("domain")

        if port is not None:
            categories.append("port")

        record = NetworkRecord(
            kind="url",
            value=url,
            normalized=url.lower(),
            source="url",
            protocol=protocol,
            host=host,
            domain=domain,
            ip_address=ip_value,
            port=port,
            path=path,
            categories=sorted(set(categories)),
        )

        records.append(record)

        if evidence is not None and len(evidence) < MAX_EVIDENCE_ITEMS:
            severity = "medium"

            if protocol in {"http", "https"}:
                severity = "medium"
            elif protocol in {"ftp", "tftp"}:
                severity = "medium"

            evidence.append(
                NetworkEvidence(
                    category="url",
                    indicator="url_reference",
                    evidence=_clip(url),
                    source="url",
                    line_number=_line_number(text, match.start()),
                    operation="reference",
                    host=host,
                    domain=domain,
                    ip_address=ip_value,
                    port=port,
                    protocol=protocol,
                    confidence=0.99,
                    severity=severity,
                )
            )

    return records


# ---------------------------------------------------------------------------
# IP extraction
# ---------------------------------------------------------------------------


def extract_ip_addresses(
    text: str,
    evidence: Optional[List[NetworkEvidence]] = None,
) -> List[NetworkRecord]:
    records: List[NetworkRecord] = []
    seen: Set[str] = set()

    if not text:
        return records

    occupied: List[Tuple[int, int]] = []

    for match in IPV4_RE.finditer(text):
        if len(records) >= MAX_IPS:
            break

        ip_value = _normalize_ip(match.group("ip"))
        if not ip_value:
            continue

        # Avoid duplicating IPs that occur as part of a URL already represented
        # by URL records.
        key = ip_value
        if key in seen:
            continue

        seen.add(key)

        port = _valid_port(match.group("port"))

        record = NetworkRecord(
            kind="ip_address",
            value=ip_value,
            normalized=ip_value,
            source="ipv4",
            ip_address=ip_value,
            port=port,
            categories=["ip_address"] + (["port"] if port else []),
        )

        records.append(record)
        occupied.append((match.start(), match.end()))

        if evidence is not None and len(evidence) < MAX_EVIDENCE_ITEMS:
            severity = "medium" if _is_public_ip(ip_value) else "low"

            evidence.append(
                NetworkEvidence(
                    category="ip_address",
                    indicator="ipv4_address",
                    evidence=match.group(0),
                    source="ipv4",
                    line_number=_line_number(text, match.start()),
                    operation="reference",
                    ip_address=ip_value,
                    port=port,
                    confidence=0.99,
                    severity=severity,
                )
            )

    for pattern in (IPV6_BRACKET_RE, IPV6_RE):
        if len(records) >= MAX_IPS:
            break

        for match in pattern.finditer(text):
            if len(records) >= MAX_IPS:
                break

            ip_value = _normalize_ip(match.group("ip"))
            if not ip_value or ip_value in seen:
                continue

            seen.add(ip_value)
            port = _valid_port(match.groupdict().get("port"))

            record = NetworkRecord(
                kind="ip_address",
                value=ip_value,
                normalized=ip_value,
                source="ipv6",
                ip_address=ip_value,
                port=port,
                categories=["ip_address"] + (["port"] if port else []),
            )

            records.append(record)

            if evidence is not None and len(evidence) < MAX_EVIDENCE_ITEMS:
                evidence.append(
                    NetworkEvidence(
                        category="ip_address",
                        indicator="ipv6_address",
                        evidence=_clip(match.group(0)),
                        source="ipv6",
                        line_number=_line_number(text, match.start()),
                        operation="reference",
                        ip_address=ip_value,
                        port=port,
                        confidence=0.99,
                        severity="medium",
                    )
                )

    return records


# ---------------------------------------------------------------------------
# Domain / host extraction
# ---------------------------------------------------------------------------


def extract_domains(
    text: str,
    evidence: Optional[List[NetworkEvidence]] = None,
) -> List[NetworkRecord]:
    records: List[NetworkRecord] = []
    seen: Set[str] = set()

    if not text:
        return records

    for match in DOMAIN_RE.finditer(text):
        if len(records) >= MAX_DOMAINS:
            break

        domain = _normalize_domain(match.group("domain"))
        if not domain or domain in seen:
            continue

        # Skip values that are clearly local file extensions or obvious
        # programming-language constructs.
        if domain.endswith(
            (
                ".local",
                ".internal",
                ".lan",
                ".test",
                ".example",
                ".invalid",
            )
        ):
            continue

        seen.add(domain)

        port = _valid_port(match.group("port"))

        record = NetworkRecord(
            kind="domain",
            value=domain,
            normalized=domain,
            source="domain",
            host=domain,
            domain=domain,
            port=port,
            categories=["domain"] + (["port"] if port else []),
        )

        records.append(record)

        if evidence is not None and len(evidence) < MAX_EVIDENCE_ITEMS:
            evidence.append(
                NetworkEvidence(
                    category="domain",
                    indicator="domain_name",
                    evidence=match.group(0),
                    source="domain",
                    line_number=_line_number(text, match.start()),
                    operation="reference",
                    host=domain,
                    domain=domain,
                    port=port,
                    confidence=0.90,
                    severity="low",
                )
            )

    return records


# ---------------------------------------------------------------------------
# UNC extraction
# ---------------------------------------------------------------------------


def extract_unc_paths(
    text: str,
    evidence: Optional[List[NetworkEvidence]] = None,
) -> List[NetworkRecord]:
    records: List[NetworkRecord] = []
    seen: Set[str] = set()

    if not text:
        return records

    for match in UNC_RE.finditer(text):
        if len(records) >= MAX_NETWORK_RECORDS:
            break

        value = match.group(0).rstrip(".,;")
        normalized = value.lower()

        if normalized in seen:
            continue

        seen.add(normalized)

        host_match = re.match(r"^\\\\([^\\]+)", value)
        host = host_match.group(1) if host_match else None

        ip_value = _normalize_ip(host) if host else None
        domain = None

        if host and not ip_value and _looks_like_domain(host):
            domain = _normalize_domain(host)

        record = NetworkRecord(
            kind="unc_path",
            value=value,
            normalized=normalized,
            source="unc",
            host=host,
            domain=domain,
            ip_address=ip_value,
            path=value,
            categories=["unc_path", "smb", "external_resource"],
        )

        records.append(record)

        if evidence is not None and len(evidence) < MAX_EVIDENCE_ITEMS:
            evidence.append(
                NetworkEvidence(
                    category="unc_path",
                    indicator="unc_network_path",
                    evidence=_clip(value),
                    source="unc",
                    line_number=_line_number(text, match.start()),
                    operation="share",
                    host=host,
                    domain=domain,
                    ip_address=ip_value,
                    protocol="smb",
                    confidence=0.99,
                    severity="medium",
                )
            )

    return records


# ---------------------------------------------------------------------------
# Port extraction
# ---------------------------------------------------------------------------


def extract_ports(
    text: str,
    evidence: Optional[List[NetworkEvidence]] = None,
) -> List[int]:
    ports: List[int] = []
    seen: Set[int] = set()

    if not text:
        return ports

    for match in PORT_RE.finditer(text):
        if len(ports) >= MAX_PORTS:
            break

        raw_port = match.group("port1") or match.group("port2") or match.group("port3")

        port = _valid_port(raw_port)
        if port is None or port in seen:
            continue

        seen.add(port)
        ports.append(port)

        if evidence is not None and len(evidence) < MAX_EVIDENCE_ITEMS:
            severity = "low"

            if port in {445, 3389, 5985, 5986}:
                severity = "medium"

            evidence.append(
                NetworkEvidence(
                    category="port",
                    indicator="port_reference",
                    evidence=match.group(0),
                    source="port",
                    line_number=_line_number(text, match.start()),
                    operation="reference",
                    port=port,
                    protocol=COMMON_PORTS.get(port),
                    confidence=0.91,
                    severity=severity,
                )
            )

    return ports


# ---------------------------------------------------------------------------
# Library / API helpers
# ---------------------------------------------------------------------------


def normalize_api_name(name: str) -> str:
    """Normalize a network API name for stable comparisons."""
    value = _safe_text(name).strip().lower()

    if "!" in value:
        value = value.rsplit("!", 1)[-1]

    if "::" in value:
        value = value.rsplit("::", 1)[-1]

    if "." in value and value not in {
        "xmlhttp.open",
        "xmlhttp.send",
        "winhttprequest.open",
        "winhttprequest.send",
    }:
        value = value.rsplit(".", 1)[-1]

    return re.sub(r"[^a-z0-9_]+", "", value)


def network_api_category(api_name: str) -> Optional[str]:
    normalized = normalize_api_name(api_name)

    if normalized in {
        "socket",
        "wsasocket",
        "wsastartup",
        "wsacleanup",
    }:
        return "socket_api"

    if normalized in {"connect", "wsaconnect"}:
        return "network_connection"

    if normalized in {"bind", "listen", "accept"}:
        return "network_listener"

    if normalized in {
        "send",
        "sendto",
        "wsasend",
        "recv",
        "recvfrom",
        "wsarecv",
    }:
        return "network_transfer"

    if normalized in {
        "getaddrinfo",
        "gethostbyname",
        "gethostbyaddr",
        "getnameinfo",
        "dnsquerya",
        "dnsqueryw",
    }:
        return "dns"

    if normalized in {
        "internetopen",
        "internetconnect",
        "internetopenurl",
        "httpopenrequest",
        "httpsendrequest",
        "internetreadfile",
        "internetwritefile",
    }:
        return "wininet"

    if normalized in {
        "winhttpopen",
        "winhttpconnect",
        "winhttpopenrequest",
        "winhttpsendrequest",
        "winhttpreaddata",
        "winhttpwritedata",
    }:
        return "winhttp"

    if normalized.startswith("urldownloadtofile"):
        return "download"

    if normalized in {
        "xmlhttp",
        "serverxmlhttp",
        "winhttprequest",
        "xmlhttpopen",
        "xmlhttpsend",
        "winhttprequestopen",
        "winhttprequestsend",
    }:
        return "http"

    return None


def extract_network_api_names(text: str) -> List[str]:
    """Extract recognizable network API names without invoking them."""
    if not text:
        return []

    names: List[str] = []
    seen: Set[str] = set()

    for api in NETWORK_API_NAMES:
        escaped = re.escape(api)

        pattern = re.compile(rf"(?i)(?<![A-Za-z0-9_]){escaped}(?![A-Za-z0-9_])")

        if pattern.search(text):
            normalized = normalize_api_name(api)

            if normalized not in seen:
                seen.add(normalized)
                names.append(normalized)

        if len(names) >= 256:
            break

    return names


# ---------------------------------------------------------------------------
# Protocol inference
# ---------------------------------------------------------------------------


def infer_protocols(
    text: str,
    records: Sequence[NetworkRecord],
) -> List[str]:
    protocols: List[str] = []
    seen: Set[str] = set()

    def add(protocol: Optional[str]) -> None:
        if not protocol:
            return

        value = protocol.lower()

        if value in seen:
            return

        if value not in KNOWN_PROTOCOLS:
            return

        seen.add(value)
        protocols.append(value)

    for record in records:
        add(record.protocol)

    lowered = text.lower()

    protocol_patterns = (
        ("https", r"\bhttps://"),
        ("http", r"\bhttp://"),
        ("ftp", r"\bftps?://|\bftp(?:\.exe)?\b"),
        ("tftp", r"\btftp(?:\.exe)?\b"),
        ("ldap", r"\bldaps?://|\bldap\b"),
        ("smb", r"\\\\[^\\\s]+\\|\bsmb://|\bnet\s+use\b"),
        ("rdp", r"\brdp://|\bmstsc(?:\.exe)?\b|\b3389(?:/tcp)?\b"),
        ("dns", r"\b(?:nslookup|DnsQuery|getaddrinfo|gethostbyname)\b"),
        ("smtp", r"\bsmtps?://|\bsmtp\b"),
        ("webdav", r"\bwebdav\b|\bDavWWWRoot\b"),
        ("tcp", r"\btcp\b"),
        ("udp", r"\budp\b"),
    )

    for protocol, pattern in protocol_patterns:
        try:
            if re.search(pattern, lowered, re.IGNORECASE):
                add(protocol)
        except re.error:
            continue

    return protocols


# ---------------------------------------------------------------------------
# Operation inference
# ---------------------------------------------------------------------------


def infer_operations(text: str) -> List[str]:
    operations: List[str] = []
    seen: Set[str] = set()

    patterns = (
        ("connect", r"(?i)\b(?:connect|connection|connectback|internetconnect)\b"),
        ("listen", r"(?i)\b(?:bind|listen|accept|listener)\b"),
        ("resolve", r"(?i)\b(?:dns|resolve|lookup|getaddrinfo|nslookup)\b"),
        (
            "download",
            r"(?i)\b(?:download|downloadstring|downloadfile|bitsadmin|wget|curl)\b",
        ),
        ("upload", r"(?i)\b(?:upload|put|post|uploadfile|uploadstring)\b"),
        ("send", r"(?i)\b(?:send|sendto|post|write)\b"),
        ("receive", r"(?i)\b(?:recv|receive|read|get|download)\b"),
        (
            "discover",
            r"(?i)\b(?:netstat|net\s+view|ipconfig|arp|tracert|nbtstat|discover)\b",
        ),
        ("remote_execute", r"(?i)\b(?:psexec|winrm|remote\s+execution)\b"),
        ("configure", r"(?i)\b(?:proxy|firewall|netsh)\b"),
    )

    for operation, pattern in patterns:
        try:
            if re.search(pattern, text):
                if operation not in seen:
                    seen.add(operation)
                    operations.append(operation)
        except re.error:
            continue

    return operations


# ---------------------------------------------------------------------------
# Indicator derivation
# ---------------------------------------------------------------------------


def derive_indicator_names(
    evidence: Sequence[NetworkEvidence],
) -> List[str]:
    names: List[str] = []
    seen: Set[str] = set()

    for item in evidence:
        if not item.indicator:
            continue

        if item.indicator not in seen:
            seen.add(item.indicator)
            names.append(item.indicator)

    return names


def derive_category_names(
    evidence: Sequence[NetworkEvidence],
    records: Sequence[NetworkRecord],
) -> List[str]:
    categories: Set[str] = set()

    for item in evidence:
        if item.category:
            categories.add(item.category)

    for record in records:
        categories.update(record.categories)

    return sorted(category for category in categories if category in NETWORK_CATEGORIES)


# ---------------------------------------------------------------------------
# Combination derivation
# ---------------------------------------------------------------------------


def _has_category(
    categories: Set[str],
    *names: str,
) -> bool:
    return any(name in categories for name in names)


def _has_indicator(
    indicators: Set[str],
    *names: str,
) -> bool:
    return any(name in indicators for name in names)


def derive_combinations(
    categories: Iterable[str],
    indicators: Iterable[str],
    evidence: Sequence[NetworkEvidence],
    text: str,
) -> List[NetworkCombination]:
    category_set = set(categories)
    indicator_set = set(indicators)

    combinations: List[NetworkCombination] = []

    def add(
        name: str,
        present: bool,
        required_categories: Sequence[str] = (),
        required_indicators: Sequence[str] = (),
        explanation: str = "",
    ) -> None:
        combinations.append(
            NetworkCombination(
                name=name,
                present=bool(present),
                required_categories=tuple(required_categories),
                required_indicators=tuple(required_indicators),
                explanation=explanation,
            )
        )

    has_transfer = _has_category(
        category_set,
        "download",
        "upload",
        "network_transfer",
    )

    has_execution = bool(
        re.search(
            r"(?i)\b(?:execute|execution|invoke|launch|start|run|powershell|cmd|wscript|mshta|rundll32)\b",
            text,
        )
    )

    add(
        "network_download",
        _has_category(category_set, "download"),
        ("download",),
        explanation="Network retrieval/download behavior is present.",
    )

    add(
        "network_upload",
        _has_category(category_set, "upload"),
        ("upload",),
        explanation="Network upload behavior is present.",
    )

    add(
        "download_then_execute",
        has_transfer and "download" in category_set and has_execution,
        ("download", "network_execution"),
        explanation="Network transfer evidence co-occurs with execution-related evidence.",
    )

    add(
        "network_client_communication",
        _has_category(
            category_set,
            "network_connection",
            "http",
            "https",
            "wininet",
            "winhttp",
            "socket_api",
        ),
        (
            "network_connection",
            "http",
            "https",
            "wininet",
            "winhttp",
            "socket_api",
        ),
        explanation="Static evidence indicates outbound/client-style network communication.",
    )

    add(
        "network_listener",
        _has_category(category_set, "network_listener", "network_server"),
        ("network_listener",),
        explanation="Static evidence indicates socket/server listener behavior.",
    )

    add(
        "network_discovery",
        _has_category(
            category_set,
            "network_discovery",
            "host_discovery",
            "service_discovery",
            "share_discovery",
        ),
        (
            "network_discovery",
            "host_discovery",
            "service_discovery",
            "share_discovery",
        ),
        explanation="Network or host discovery behavior is present.",
    )

    add(
        "smb_share_access",
        _has_category(category_set, "smb", "unc_path"),
        ("smb", "unc_path"),
        explanation="SMB/UNC share access is represented in static evidence.",
    )

    add(
        "network_credentials",
        _has_category(
            category_set,
            "network_credentials",
            "authentication",
        ),
        ("network_credentials", "authentication"),
        explanation="Network credential/authentication activity is indicated.",
    )

    add(
        "remote_access",
        _has_category(
            category_set,
            "remote_access",
            "rdp",
            "smb",
            "webdav",
        ),
        ("remote_access", "rdp", "smb", "webdav"),
        explanation="Remote-access or remote-resource behavior is present.",
    )

    add(
        "reverse_shell_behavior",
        _has_category(category_set, "reverse_shell", "callback"),
        ("reverse_shell", "callback"),
        explanation="Explicit callback/reverse-shell evidence is present.",
    )

    add(
        "bind_shell_behavior",
        _has_category(category_set, "bind_shell", "network_listener"),
        ("bind_shell", "network_listener"),
        explanation="Bind-shell/listener evidence is present.",
    )

    add(
        "network_obfuscated_communication",
        _has_category(
            category_set,
            "network_obfuscation",
        )
        and bool(
            re.search(
                r"(?i)\b(?:base64|frombase64string|xor|hex|urldecod|urlencod)\b",
                text,
            )
        ),
        ("network_obfuscation",),
        explanation="Network material appears to be combined with encoding/obfuscation indicators.",
    )

    add(
        "encrypted_network_communication",
        _has_category(category_set, "encrypted_communication")
        and _has_category(
            category_set,
            "http",
            "https",
            "network_connection",
        ),
        ("encrypted_communication",),
        explanation="Encrypted transport indicators co-occur with network communication.",
    )

    add(
        "proxy_or_firewall_modification",
        _has_category(category_set, "proxy", "firewall")
        and bool(
            re.search(
                r"(?i)\b(?:set|add|remove|configure|change|modify)\b",
                text,
            )
        ),
        ("proxy", "firewall"),
        explanation="Proxy or firewall configuration evidence co-occurs with modification terminology.",
    )

    add(
        "network_api_communication",
        _has_category(
            category_set,
            "network_apis",
            "socket_api",
            "wininet",
            "winhttp",
        ),
        ("network_apis",),
        explanation="Network API/library evidence indicates programmatic network capability.",
    )

    add(
        "dns_resolution_and_connection",
        "dns" in category_set
        and _has_category(
            category_set,
            "network_connection",
            "http",
            "https",
            "socket_api",
        ),
        ("dns", "network_connection"),
        explanation="DNS resolution indicators co-occur with connection/client indicators.",
    )

    return combinations


# ---------------------------------------------------------------------------
# Feature vector
# ---------------------------------------------------------------------------


def _signal_score(
    analysis: NetworkAnalysis,
) -> float:
    score = 0.0

    severity_weights = {
        "low": 0.15,
        "medium": 0.50,
        "high": 1.25,
        "critical": 2.25,
    }

    for item in analysis.evidence:
        score += severity_weights.get(item.severity, 0.25)
        score *= 1.0

        score += 0.20 * _safe_confidence(item.confidence)

    for combination in analysis.combinations:
        if combination.present:
            if combination.name in {
                "reverse_shell_behavior",
                "bind_shell_behavior",
                "download_then_execute",
                "network_obfuscated_communication",
            }:
                score += 2.0
            else:
                score += 0.75

    if _has_public_network_endpoint(analysis):
        score += 0.75

    return round(min(score, 100.0), 4)


def _has_public_network_endpoint(
    analysis: NetworkAnalysis,
) -> bool:
    return any(_is_public_ip(value) for value in analysis.ip_addresses)


def _build_feature_vector(
    analysis: NetworkAnalysis,
) -> Dict[str, Union[int, float]]:
    vector: Dict[str, Union[int, float]] = {}

    category_counts = Counter(
        item.category for item in analysis.evidence if item.category
    )

    indicator_counts = Counter(
        item.indicator for item in analysis.evidence if item.indicator
    )

    combination_presence = {
        item.name: int(item.present) for item in analysis.combinations
    }

    operation_counts = Counter(
        item.operation for item in analysis.evidence if item.operation
    )

    vector["network_source_size"] = min(
        analysis.source_size,
        MAX_SOURCE_SIZE,
    )
    vector["network_record_count"] = len(analysis.records)
    vector["network_evidence_count"] = len(analysis.evidence)
    vector["network_url_count"] = len(analysis.urls)
    vector["network_host_count"] = len(analysis.hosts)
    vector["network_domain_count"] = len(analysis.domains)
    vector["network_ip_count"] = len(analysis.ip_addresses)
    vector["network_port_count"] = len(analysis.ports)
    vector["network_protocol_count"] = len(analysis.protocols)
    vector["network_indicator_count"] = len(analysis.indicators)
    vector["network_category_count"] = len(analysis.categories)
    vector["network_combination_count"] = len(
        [item for item in analysis.combinations if item.present]
    )

    for operation in (
        "connect",
        "listen",
        "resolve",
        "download",
        "upload",
        "send",
        "receive",
        "discover",
        "remote_execute",
        "configure",
    ):
        vector[f"network_operation_{operation}_count"] = operation_counts.get(
            operation,
            0,
        )
        vector[f"network_operation_{operation}_present"] = int(
            operation_counts.get(operation, 0) > 0
        )

    for category in NETWORK_CATEGORIES:
        count = category_counts.get(category, 0)
        vector[f"network_category_{category}_count"] = count
        vector[f"network_category_{category}_present"] = int(count > 0)

    known_indicators = sorted(
        {
            pattern.name
            for pattern in (
                *API_RULES,
                *COMMAND_RULES,
                *BEHAVIOR_RULES,
            )
        }
        | {
            "url_reference",
            "ipv4_address",
            "ipv6_address",
            "domain_name",
            "unc_network_path",
            "port_reference",
        }
    )

    for indicator in known_indicators:
        count = indicator_counts.get(indicator, 0)
        vector[f"network_indicator_{indicator}_count"] = count
        vector[f"network_indicator_{indicator}_present"] = int(count > 0)

    for combination_name in (
        "network_download",
        "network_upload",
        "download_then_execute",
        "network_client_communication",
        "network_listener",
        "network_discovery",
        "smb_share_access",
        "network_credentials",
        "remote_access",
        "reverse_shell_behavior",
        "bind_shell_behavior",
        "network_obfuscated_communication",
        "encrypted_network_communication",
        "proxy_or_firewall_modification",
        "network_api_communication",
        "dns_resolution_and_connection",
    ):
        vector[f"network_combination_{combination_name}_present"] = (
            combination_presence.get(combination_name, 0)
        )

    high_count = sum(1 for item in analysis.evidence if item.severity == "high")
    critical_count = sum(1 for item in analysis.evidence if item.severity == "critical")

    vector["network_high_severity_count"] = high_count
    vector["network_critical_severity_count"] = critical_count
    vector["network_public_ip_count"] = sum(
        1 for value in analysis.ip_addresses if _is_public_ip(value)
    )

    vector["network_signal_score"] = _signal_score(analysis)

    return vector


def registry_style_vectorize_placeholder_not_used() -> None:
    """
    Intentionally empty compatibility guard.

    This function is never part of the public API and is retained only to
    make accidental references to a registry extractor obvious during
    development.
    """
    return None


# ---------------------------------------------------------------------------
# Main analysis
# ---------------------------------------------------------------------------


def analyze_network_behavior(
    source: Any,
    *,
    source_name: Optional[str] = None,
) -> NetworkAnalysis:
    """
    Perform static network-behavior analysis.

    Parameters
    ----------
    source:
        Raw text, bytes, local file path, mapping, sequence, or analysis object.
    source_name:
        Optional logical name for metadata/reporting.

    Returns
    -------
    NetworkAnalysis
        Structured, bounded static network findings.

    No network operations are performed.
    """
    text, source_size, source_hash = _read_source(source)

    evidence: List[NetworkEvidence] = []
    seen_evidence: Set[Tuple[str, int, str]] = set()

    # High-value structured network artifacts.
    url_records = extract_urls(text, evidence)
    ip_records = extract_ip_addresses(text, evidence)
    domain_records = extract_domains(text, evidence)
    unc_records = extract_unc_paths(text, evidence)

    # Pattern-based semantic evidence.
    _apply_patterns(
        text,
        API_RULES,
        evidence,
        seen_evidence,
    )

    _apply_patterns(
        text,
        COMMAND_RULES,
        evidence,
        seen_evidence,
    )

    _apply_patterns(
        text,
        BEHAVIOR_RULES,
        evidence,
        seen_evidence,
    )

    # Explicit API names.
    api_names = extract_network_api_names(text)

    for api_name in api_names:
        if len(evidence) >= MAX_EVIDENCE_ITEMS:
            break

        category = network_api_category(api_name) or "network_apis"

        evidence.append(
            NetworkEvidence(
                category=category,
                indicator=f"api_{api_name}",
                evidence=api_name,
                source="api",
                operation="api",
                confidence=0.95,
                severity="medium",
            )
        )

    # Registry-like operation inference is deliberately not performed here;
    # this module owns network semantics only.
    operations = infer_operations(text)

    # Port evidence can overlap with URL/IP extraction. That is intentional:
    # it creates stable port-specific ML features.
    ports = extract_ports(text, evidence)

    records: List[NetworkRecord] = []

    def extend_records(items: Sequence[NetworkRecord]) -> None:
        if len(records) >= MAX_NETWORK_RECORDS:
            return

        for item in items:
            if len(records) >= MAX_NETWORK_RECORDS:
                break
            records.append(item)

    extend_records(url_records)
    extend_records(ip_records)
    extend_records(domain_records)
    extend_records(unc_records)

    # Annotate API/command evidence with nearby endpoint context where
    # possible. This remains purely static.
    _enrich_evidence_from_records(evidence, records, text)

    indicators = derive_indicator_names(evidence)
    categories = derive_category_names(evidence, records)

    protocols = infer_protocols(text, records)

    hosts: List[str] = []
    domains: List[str] = []
    ip_addresses: List[str] = []

    for record in records:
        if record.host:
            _append_unique(hosts, record.host, MAX_HOSTS)

        if record.domain:
            _append_unique(domains, record.domain, MAX_DOMAINS)

        if record.ip_address:
            _append_unique(
                ip_addresses,
                record.ip_address,
                MAX_IPS,
            )

    # Include domain candidates from structured domain records even if a URL
    # parser supplied them first.
    for record in domain_records:
        if record.domain:
            _append_unique(domains, record.domain, MAX_DOMAINS)

    combinations = derive_combinations(
        categories,
        indicators,
        evidence,
        text,
    )

    metadata: Dict[str, Any] = {
        "analyzer": "pharos-cdr.network",
        "version": "1.0",
        "static_only": True,
        "network_activity_performed": False,
        "dns_queries_performed": False,
        "http_requests_performed": False,
        "socket_operations_performed": False,
        "source_truncated": source_size > MAX_SOURCE_SIZE,
        "text_length": len(text),
        "api_names": api_names,
        "operations": operations,
        "protocols": protocols,
        "common_ports": {
            str(port): COMMON_PORTS[port] for port in ports if port in COMMON_PORTS
        },
        "public_ip_count": sum(1 for value in ip_addresses if _is_public_ip(value)),
    }

    if source_name:
        metadata["source_name"] = _clip(str(source_name), 4096)

    analysis = NetworkAnalysis(
        source_hash=source_hash,
        source_size=source_size,
        records=records,
        evidence=evidence[:MAX_EVIDENCE_ITEMS],
        urls=[record.value for record in url_records[:MAX_URLS]],
        hosts=hosts[:MAX_HOSTS],
        domains=domains[:MAX_DOMAINS],
        ip_addresses=ip_addresses[:MAX_IPS],
        ports=sorted(set(ports))[:MAX_PORTS],
        protocols=protocols,
        indicators=indicators,
        categories=categories,
        combinations=combinations,
        metadata=metadata,
    )

    analysis.feature_vector = _build_feature_vector(analysis)

    return analysis


def _enrich_evidence_from_records(
    evidence: List[NetworkEvidence],
    records: Sequence[NetworkRecord],
    text: str,
) -> None:
    """
    Add endpoint context to nearby generic evidence.

    This is deliberately conservative and only uses textual proximity.
    """
    if not evidence or not records:
        return

    endpoint_values: List[
        Tuple[str, Optional[str], Optional[str], Optional[str], Optional[int]]
    ] = []

    for record in records:
        endpoint_values.append(
            (
                record.value,
                record.host,
                record.domain,
                record.ip_address,
                record.port,
            )
        )

    for item in evidence:
        if item.host or item.domain or item.ip_address:
            continue

        evidence_text = item.evidence.lower()

        for value, host, domain, ip_value, port in endpoint_values[:256]:
            if not value:
                continue

            if value.lower() not in evidence_text:
                continue

            item.host = host
            item.domain = domain
            item.ip_address = ip_value
            item.port = port
            break


# ---------------------------------------------------------------------------
# Parsing / extraction aliases
# ---------------------------------------------------------------------------


def parse_network_behavior(
    source: Any,
    *,
    source_name: Optional[str] = None,
) -> NetworkAnalysis:
    return analyze_network_behavior(
        source,
        source_name=source_name,
    )


def extract_network_features(
    source: Any,
    *,
    source_name: Optional[str] = None,
) -> Dict[str, Union[int, float]]:
    analysis = analyze_network_behavior(
        source,
        source_name=source_name,
    )
    return dict(analysis.feature_vector)


def extract_feature_vector(
    source: Any,
    *,
    source_name: Optional[str] = None,
) -> Dict[str, Union[int, float]]:
    return extract_network_features(
        source,
        source_name=source_name,
    )


def extract_network_feature_vector(
    source: Any,
    *,
    source_name: Optional[str] = None,
) -> Dict[str, Union[int, float]]:
    return extract_network_features(
        source,
        source_name=source_name,
    )


# ---------------------------------------------------------------------------
# Feature schema / vectorization
# ---------------------------------------------------------------------------


def network_feature_names() -> List[str]:
    """
    Return the deterministic feature-name schema.

    The schema is generated from the same vocabulary used by the feature
    vector builder so training and inference can share feature ordering.
    """
    names: List[str] = [
        "network_source_size",
        "network_record_count",
        "network_evidence_count",
        "network_url_count",
        "network_host_count",
        "network_domain_count",
        "network_ip_count",
        "network_port_count",
        "network_protocol_count",
        "network_indicator_count",
        "network_category_count",
        "network_combination_count",
    ]

    operations = (
        "connect",
        "listen",
        "resolve",
        "download",
        "upload",
        "send",
        "receive",
        "discover",
        "remote_execute",
        "configure",
    )

    for operation in operations:
        names.extend(
            (
                f"network_operation_{operation}_count",
                f"network_operation_{operation}_present",
            )
        )

    for category in NETWORK_CATEGORIES:
        names.extend(
            (
                f"network_category_{category}_count",
                f"network_category_{category}_present",
            )
        )

    known_indicators = sorted(
        {
            pattern.name
            for pattern in (
                *API_RULES,
                *COMMAND_RULES,
                *BEHAVIOR_RULES,
            )
        }
        | {
            "url_reference",
            "ipv4_address",
            "ipv6_address",
            "domain_name",
            "unc_network_path",
            "port_reference",
        }
    )

    for indicator in known_indicators:
        names.extend(
            (
                f"network_indicator_{indicator}_count",
                f"network_indicator_{indicator}_present",
            )
        )

    for combination_name in (
        "network_download",
        "network_upload",
        "download_then_execute",
        "network_client_communication",
        "network_listener",
        "network_discovery",
        "smb_share_access",
        "network_credentials",
        "remote_access",
        "reverse_shell_behavior",
        "bind_shell_behavior",
        "network_obfuscated_communication",
        "encrypted_network_communication",
        "proxy_or_firewall_modification",
        "network_api_communication",
        "dns_resolution_and_connection",
    ):
        names.append(f"network_combination_{combination_name}_present")

    names.extend(
        (
            "network_high_severity_count",
            "network_critical_severity_count",
            "network_public_ip_count",
            "network_signal_score",
        )
    )

    return names


def build_feature_schema() -> Dict[str, Any]:
    names = network_feature_names()

    return {
        "schema_version": "1.0",
        "feature_family": "network_behavior",
        "static_only": True,
        "dtype": "float64",
        "feature_count": len(names),
        "features": [
            {
                "name": name,
                "type": "numeric",
            }
            for name in names
        ],
    }


def vectorize_features(
    features: Mapping[str, Any],
    feature_names: Optional[Sequence[str]] = None,
) -> List[float]:
    """
    Convert a feature mapping into a deterministic numeric vector.

    Missing features become 0.0; invalid numeric values also become 0.0.
    """
    names = (
        list(feature_names) if feature_names is not None else network_feature_names()
    )

    vector: List[float] = []

    for name in names:
        value = features.get(name, 0.0)

        try:
            numeric = float(value)
        except (TypeError, ValueError):
            numeric = 0.0

        if not math.isfinite(numeric):
            numeric = 0.0

        vector.append(numeric)

    return vector


# ---------------------------------------------------------------------------
# Query helpers
# ---------------------------------------------------------------------------


def has_indicator(
    analysis: NetworkAnalysis,
    indicator: str,
) -> bool:
    return indicator in set(analysis.indicators)


def has_category(
    analysis: NetworkAnalysis,
    category: str,
) -> bool:
    return category in set(analysis.categories)


def indicator_count(
    analysis: NetworkAnalysis,
    indicator: str,
) -> int:
    return sum(1 for item in analysis.evidence if item.indicator == indicator)


def category_count(
    analysis: NetworkAnalysis,
    category: str,
) -> int:
    return sum(1 for item in analysis.evidence if item.category == category)


def evidence_by_category(
    analysis: NetworkAnalysis,
    category: str,
) -> List[NetworkEvidence]:
    return [item for item in analysis.evidence if item.category == category]


def evidence_by_indicator(
    analysis: NetworkAnalysis,
    indicator: str,
) -> List[NetworkEvidence]:
    return [item for item in analysis.evidence if item.indicator == indicator]


def high_risk_evidence(
    analysis: NetworkAnalysis,
    minimum_severity: str = "high",
) -> List[NetworkEvidence]:
    threshold = SEVERITY_ORDER.get(
        minimum_severity.lower(),
        SEVERITY_ORDER["high"],
    )

    return [
        item
        for item in analysis.evidence
        if SEVERITY_ORDER.get(item.severity, 0) >= threshold
    ]


def present_combinations(
    analysis: NetworkAnalysis,
) -> List[NetworkCombination]:
    return [item for item in analysis.combinations if item.present]


def highest_severity(
    analysis: NetworkAnalysis,
) -> str:
    if not analysis.evidence:
        return "low"

    return max(
        (item.severity for item in analysis.evidence),
        key=lambda value: SEVERITY_ORDER.get(value, 0),
    )


# ---------------------------------------------------------------------------
# Structured record helpers
# ---------------------------------------------------------------------------


def extract_network_records(
    source: Any,
    *,
    source_name: Optional[str] = None,
) -> List[NetworkRecord]:
    analysis = analyze_network_behavior(
        source,
        source_name=source_name,
    )
    return list(analysis.records)


def extract_endpoints(
    source: Any,
    *,
    source_name: Optional[str] = None,
) -> Dict[str, List[Any]]:
    """
    Return deduplicated endpoint artifacts.

    This is useful for downstream report generation while preserving the
    static-only guarantee.
    """
    analysis = analyze_network_behavior(
        source,
        source_name=source_name,
    )

    return {
        "urls": list(analysis.urls),
        "hosts": list(analysis.hosts),
        "domains": list(analysis.domains),
        "ip_addresses": list(analysis.ip_addresses),
        "ports": list(analysis.ports),
        "protocols": list(analysis.protocols),
    }


# ---------------------------------------------------------------------------
# Serialization / summaries
# ---------------------------------------------------------------------------


def analysis_to_dict(
    analysis: NetworkAnalysis,
) -> Dict[str, Any]:
    return asdict(analysis)


def summarize_network_behavior(
    analysis: NetworkAnalysis,
) -> Dict[str, Any]:
    """
    Return a compact report-oriented summary.
    """
    present = present_combinations(analysis)

    severity_counts = Counter(item.severity for item in analysis.evidence)

    operation_counts = Counter(
        item.operation for item in analysis.evidence if item.operation
    )

    return {
        "source_hash": analysis.source_hash,
        "source_size": analysis.source_size,
        "url_count": len(analysis.urls),
        "host_count": len(analysis.hosts),
        "domain_count": len(analysis.domains),
        "ip_count": len(analysis.ip_addresses),
        "port_count": len(analysis.ports),
        "protocols": list(analysis.protocols),
        "record_count": len(analysis.records),
        "evidence_count": len(analysis.evidence),
        "indicator_count": len(analysis.indicators),
        "category_count": len(analysis.categories),
        "highest_severity": highest_severity(analysis),
        "severity_counts": dict(severity_counts),
        "operation_counts": dict(operation_counts),
        "categories": list(analysis.categories),
        "indicators": list(analysis.indicators),
        "present_combinations": [item.name for item in present],
        "public_ip_count": sum(
            1 for value in analysis.ip_addresses if _is_public_ip(value)
        ),
        "signal_score": analysis.feature_vector.get(
            "network_signal_score",
            0.0,
        ),
        "static_only": True,
        "network_activity_performed": False,
    }


# ---------------------------------------------------------------------------
# Iterators
# ---------------------------------------------------------------------------


def iter_evidence(
    analysis: NetworkAnalysis,
) -> Iterator[NetworkEvidence]:
    yield from analysis.evidence


def iter_high_risk_evidence(
    analysis: NetworkAnalysis,
    minimum_severity: str = "high",
) -> Iterator[NetworkEvidence]:
    yield from high_risk_evidence(
        analysis,
        minimum_severity=minimum_severity,
    )


def iter_records(
    analysis: NetworkAnalysis,
) -> Iterator[NetworkRecord]:
    yield from analysis.records


def iter_urls(
    analysis: NetworkAnalysis,
) -> Iterator[str]:
    yield from analysis.urls


def iter_hosts(
    analysis: NetworkAnalysis,
) -> Iterator[str]:
    yield from analysis.hosts


def iter_domains(
    analysis: NetworkAnalysis,
) -> Iterator[str]:
    yield from analysis.domains


def iter_ip_addresses(
    analysis: NetworkAnalysis,
) -> Iterator[str]:
    yield from analysis.ip_addresses


def iter_combinations(
    analysis: NetworkAnalysis,
) -> Iterator[NetworkCombination]:
    yield from analysis.combinations


def iter_analyses(
    sources: Iterable[Any],
) -> Iterator[NetworkAnalysis]:
    for source in sources:
        yield analyze_network_behavior(source)


# ---------------------------------------------------------------------------
# Compatibility aliases
# ---------------------------------------------------------------------------


analyze = analyze_network_behavior
parse = parse_network_behavior
extract = extract_network_features


__all__ = [
    "NETWORK_CATEGORIES",
    "NetworkPattern",
    "NetworkEvidence",
    "NetworkRecord",
    "NetworkCombination",
    "NetworkAnalysis",
    "analyze_network_behavior",
    "analyze",
    "parse_network_behavior",
    "parse",
    "extract_network_features",
    "extract_feature_vector",
    "extract_network_feature_vector",
    "extract_network_records",
    "extract_endpoints",
    "extract_urls",
    "extract_ip_addresses",
    "extract_domains",
    "extract_unc_paths",
    "extract_ports",
    "extract_network_api_names",
    "network_api_category",
    "normalize_api_name",
    "infer_protocols",
    "infer_operations",
    "derive_indicator_names",
    "derive_category_names",
    "derive_combinations",
    "network_feature_names",
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
    "analysis_to_dict",
    "summarize_network_behavior",
    "iter_evidence",
    "iter_high_risk_evidence",
    "iter_records",
    "iter_urls",
    "iter_hosts",
    "iter_domains",
    "iter_ip_addresses",
    "iter_combinations",
    "iter_analyses",
]
