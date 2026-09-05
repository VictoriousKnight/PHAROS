"""
Static communication capability extraction.

This module analyzes source text, binary content, paths, mappings, sequences, and
other structured inputs for indicators of communication capabilities without
executing code, resolving hosts, opening sockets, making network requests, or
interacting with the live operating system.

The analyzer focuses on evidence such as:

- HTTP/HTTPS, FTP, SMTP, DNS, SMB, LDAP, WinINet, WinHTTP, sockets
- URL construction and network API usage
- downloads, uploads, callbacks, beaconing, polling, C2-like communication
- proxy configuration and proxy-aware communication
- DNS tunneling / encoded DNS indicators
- raw socket and Winsock usage
- named pipes and IPC-style communication
- email communication
- cloud/storage API communication
- PowerShell, JavaScript, VBScript, shell, and batch network primitives
- suspicious communication combinations and staged payload retrieval
- stable ML-ready scalar feature vectors

This module performs static inspection only.

It does NOT:

- connect to hosts
- resolve DNS
- perform HTTP requests
- download or upload content
- open sockets
- execute scripts or macros
- invoke operating-system networking APIs
- authenticate to services
- extract or write payloads to disk

All parsing is bounded to reduce resource consumption on hostile input.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterator, Optional


# =============================================================================
# Limits
# =============================================================================

MAX_SOURCE_SIZE = 25 * 1024 * 1024
MAX_TEXT_SIZE = 25 * 1024 * 1024
MAX_FIELD_TEXT = 100_000
MAX_EVIDENCE_ITEMS = 20_000
MAX_RECORDS = 10_000
MAX_MATCHES_PER_PATTERN = 5_000
MAX_NESTING_DEPTH = 12
MAX_TOKENS = 250_000
MAX_INDICATORS = 10_000
MAX_TARGETS = 10_000
MAX_URLS = 10_000
MAX_LINES = 500_000
MAX_BINARY_SCAN = 4 * 1024 * 1024


# =============================================================================
# Categories
# =============================================================================

COMMUNICATION_CATEGORIES = (
    "network",
    "web",
    "http",
    "https",
    "ftp",
    "smtp",
    "dns",
    "ldap",
    "smb",
    "websocket",
    "socket",
    "winsock",
    "wininet",
    "winhttp",
    "email",
    "cloud",
    "proxy",
    "ipc",
    "named_pipe",
    "download",
    "upload",
    "callback",
    "beacon",
    "polling",
    "c2",
    "tunneling",
    "dns_tunneling",
    "encoded_communication",
    "network_discovery",
    "remote_resource",
    "staged_communication",
    "communication_encryption",
    "communication_obfuscation",
    "credentialed_communication",
    "exfiltration_channel",
    "command_channel",
    "telemetry",
)


SEVERITY_ORDER = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


# =============================================================================
# Pattern definitions
# =============================================================================


@dataclass(frozen=True)
class CommunicationPattern:
    """Static rule describing one communication capability indicator."""

    name: str
    category: str
    regex: str
    severity: str = "medium"
    confidence: float = 0.80
    operation: str = "detect"
    platform: str = "cross-platform"
    description: str = ""


@dataclass(frozen=True)
class CommunicationEvidence:
    """Evidence item produced by static communication analysis."""

    category: str
    indicator: str
    evidence: str
    source: str
    line_number: Optional[int] = None
    target: Optional[str] = None
    protocol: Optional[str] = None
    operation: str = "detect"
    platform: str = "cross-platform"
    confidence: float = 1.0
    severity: str = "medium"


@dataclass(frozen=True)
class CommunicationRecord:
    """Normalized communication capability record."""

    category: str
    protocol: str
    operation: str
    target: Optional[str]
    indicator: str
    evidence: str
    platform: str
    severity: str
    confidence: float
    source_offset: Optional[int] = None


@dataclass(frozen=True)
class CommunicationCombination:
    """Derived multi-indicator communication capability."""

    name: str
    present: bool
    required_categories: tuple[str, ...]
    explanation: str
    severity: str = "medium"
    confidence: float = 0.80


@dataclass
class CommunicationAnalysis:
    """Complete static communication analysis result."""

    source_hash: str
    source_size: int
    evidence: list[CommunicationEvidence] = field(default_factory=list)
    records: list[CommunicationRecord] = field(default_factory=list)
    indicators: list[str] = field(default_factory=list)
    categories: list[str] = field(default_factory=list)
    protocols: list[str] = field(default_factory=list)
    targets: list[str] = field(default_factory=list)
    operations: list[str] = field(default_factory=list)
    platforms: list[str] = field(default_factory=list)
    combinations: list[CommunicationCombination] = field(default_factory=list)
    feature_vector: dict[str, float] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)


# =============================================================================
# Communication pattern table
# =============================================================================

PATTERNS: tuple[CommunicationPattern, ...] = (
    # -------------------------------------------------------------------------
    # URLs / web
    # -------------------------------------------------------------------------
    CommunicationPattern(
        "http_url",
        "http",
        r"\bhttps?://[^\s\"'<>]+",
        "medium",
        0.97,
        "connect",
        "cross-platform",
        "HTTP or HTTPS URL reference.",
    ),
    CommunicationPattern(
        "ftp_url",
        "ftp",
        r"\bftps?://[^\s\"'<>]+",
        "medium",
        0.96,
        "connect",
        "cross-platform",
        "FTP or FTPS URL reference.",
    ),
    CommunicationPattern(
        "web_request",
        "web",
        r"\b(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(?:https?://|/)",
        "medium",
        0.90,
        "request",
        "cross-platform",
        "HTTP-style request indicator.",
    ),
    CommunicationPattern(
        "http_client",
        "http",
        r"\b(?:requests\.(?:get|post|put|patch|delete|request)|urllib\.request|urlopen|http\.client|aiohttp|curl|wget)\b",
        "medium",
        0.92,
        "request",
        "cross-platform",
        "Common HTTP client API or command.",
    ),
    CommunicationPattern(
        "powershell_web_client",
        "web",
        r"\b(?:Invoke-WebRequest|Invoke-RestMethod|WebClient|HttpClient|HttpWebRequest|DownloadString|DownloadFile|UploadString|UploadFile)\b",
        "high",
        0.96,
        "request",
        "Windows",
        "PowerShell/.NET web communication primitive.",
    ),
    CommunicationPattern(
        "powershell_web_cmdlet",
        "web",
        r"\b(?:iwr|irm)\b",
        "medium",
        0.88,
        "request",
        "Windows",
        "PowerShell web request aliases.",
    ),
    CommunicationPattern(
        "javascript_fetch",
        "web",
        r"\b(?:fetch|XMLHttpRequest|ActiveXObject\s*\(\s*[\"'](?:MSXML2\.)?XMLHTTP|WinHttpRequest)\b",
        "medium",
        0.91,
        "request",
        "cross-platform",
        "JavaScript or COM web request primitive.",
    ),
    CommunicationPattern(
        "vbscript_http",
        "web",
        r"\b(?:MSXML2\.(?:XMLHTTP|ServerXMLHTTP)|WinHttp\.WinHttpRequest|Microsoft\.XMLHTTP)\b",
        "high",
        0.96,
        "request",
        "Windows",
        "VBScript/COM HTTP request object.",
    ),
    CommunicationPattern(
        "shell_curl",
        "http",
        r"(?:^|[\s;&|])curl(?:\.exe)?(?:\s|$)",
        "medium",
        0.93,
        "request",
        "cross-platform",
        "curl command invocation.",
    ),
    CommunicationPattern(
        "shell_wget",
        "http",
        r"(?:^|[\s;&|])wget(?:\.exe)?(?:\s|$)",
        "medium",
        0.93,
        "request",
        "cross-platform",
        "wget command invocation.",
    ),

    # -------------------------------------------------------------------------
    # Windows WinINet / WinHTTP
    # -------------------------------------------------------------------------
    CommunicationPattern(
        "wininet_open",
        "wininet",
        r"\bInternetOpen(?:A|W)?\b",
        "medium",
        0.94,
        "connect",
        "Windows",
        "WinINet session initialization.",
    ),
    CommunicationPattern(
        "wininet_url",
        "wininet",
        r"\bInternetOpenUrl(?:A|W)?\b",
        "medium",
        0.96,
        "request",
        "Windows",
        "WinINet URL access.",
    ),
    CommunicationPattern(
        "wininet_connect",
        "wininet",
        r"\bInternetConnect(?:A|W)?\b",
        "medium",
        0.96,
        "connect",
        "Windows",
        "WinINet server connection.",
    ),
    CommunicationPattern(
        "wininet_download",
        "download",
        r"\b(?:URLDownloadToFile(?:A|W)?|InternetReadFile|InternetQueryInfo(?:A|W)?)\b",
        "high",
        0.97,
        "download",
        "Windows",
        "WinINet download/read operation.",
    ),
    CommunicationPattern(
        "wininet_upload",
        "upload",
        r"\bInternetWriteFile\b",
        "high",
        0.95,
        "upload",
        "Windows",
        "WinINet data upload/write operation.",
    ),
    CommunicationPattern(
        "winhttp_open",
        "winhttp",
        r"\bWinHttpOpen\b",
        "medium",
        0.95,
        "connect",
        "Windows",
        "WinHTTP session initialization.",
    ),
    CommunicationPattern(
        "winhttp_connect",
        "winhttp",
        r"\bWinHttpConnect\b",
        "medium",
        0.97,
        "connect",
        "Windows",
        "WinHTTP server connection.",
    ),
    CommunicationPattern(
        "winhttp_request",
        "winhttp",
        r"\bWinHttpOpenRequest\b",
        "medium",
        0.97,
        "request",
        "Windows",
        "WinHTTP request creation.",
    ),
    CommunicationPattern(
        "winhttp_send",
        "winhttp",
        r"\bWinHttpSendRequest\b",
        "high",
        0.98,
        "request",
        "Windows",
        "WinHTTP request transmission.",
    ),
    CommunicationPattern(
        "winhttp_receive",
        "winhttp",
        r"\bWinHttpReceiveResponse\b",
        "medium",
        0.97,
        "receive",
        "Windows",
        "WinHTTP response retrieval.",
    ),

    # -------------------------------------------------------------------------
    # Sockets / Winsock
    # -------------------------------------------------------------------------
    CommunicationPattern(
        "socket_create",
        "socket",
        r"\b(?:socket|WSASocket(?:A|W)?|Socket)\s*\(",
        "medium",
        0.93,
        "create",
        "cross-platform",
        "Raw socket creation.",
    ),
    CommunicationPattern(
        "socket_connect",
        "socket",
        r"\b(?:connect|WSAConnect|WSAConnectByName(?:A|W)?)\s*\(",
        "high",
        0.95,
        "connect",
        "cross-platform",
        "Socket connection primitive.",
    ),
    CommunicationPattern(
        "socket_send",
        "socket",
        r"\b(?:send|sendto|WSASend|WSASendTo)\s*\(",
        "medium",
        0.92,
        "send",
        "cross-platform",
        "Socket send primitive.",
    ),
    CommunicationPattern(
        "socket_receive",
        "socket",
        r"\b(?:recv|recvfrom|WSARecv|WSARecvFrom)\s*\(",
        "medium",
        0.92,
        "receive",
        "cross-platform",
        "Socket receive primitive.",
    ),
    CommunicationPattern(
        "winsock_library",
        "winsock",
        r"\b(?:ws2_32\.dll|winsock\.dll|WINSOCK2)\b",
        "medium",
        0.96,
        "load",
        "Windows",
        "Winsock library reference.",
    ),
    CommunicationPattern(
        "socket_endpoint",
        "socket",
        r"\b(?:AF_INET|AF_INET6|SOCK_STREAM|SOCK_DGRAM|IPPROTO_TCP|IPPROTO_UDP)\b",
        "medium",
        0.94,
        "configure",
        "cross-platform",
        "Socket endpoint configuration constant.",
    ),

    # -------------------------------------------------------------------------
    # DNS
    # -------------------------------------------------------------------------
    CommunicationPattern(
        "dns_resolution",
        "dns",
        r"\b(?:getaddrinfo|gethostbyname|gethostbyaddr|getnameinfo|DnsQuery(?:_A|_W)?|Resolve-DnsName|nslookup|dig|host)\b",
        "medium",
        0.92,
        "resolve",
        "cross-platform",
        "DNS or hostname resolution primitive.",
    ),
    CommunicationPattern(
        "dns_api",
        "dns",
        r"\b(?:DnsQuery|DnsRecordListFree|DnsQueryEx)\b",
        "medium",
        0.96,
        "query",
        "Windows",
        "Windows DNS API reference.",
    ),
    CommunicationPattern(
        "dns_tunnel_indicator",
        "dns_tunneling",
        r"\b(?:dns\s*tunnel|iodine|dnscat(?:2)?|dns2tcp|dns\s*exfil(?:tration)?)\b",
        "high",
        0.96,
        "tunnel",
        "cross-platform",
        "Explicit DNS tunneling or DNS exfiltration terminology.",
    ),
    CommunicationPattern(
        "dns_long_label",
        "dns_tunneling",
        r"\b[a-z0-9]{35,}(?:\.[a-z0-9-]{1,63}){1,5}\b",
        "low",
        0.70,
        "encode",
        "cross-platform",
        "Long DNS-like label that may represent encoded data.",
    ),

    # -------------------------------------------------------------------------
    # SMB / LDAP / remote resources
    # -------------------------------------------------------------------------
    CommunicationPattern(
        "smb_unc",
        "smb",
        r"\\\\[A-Za-z0-9_.-]+\\[^\s\"']+",
        "medium",
        0.94,
        "access",
        "Windows",
        "Windows UNC/SMB resource reference.",
    ),
    CommunicationPattern(
        "smb_api",
        "smb",
        r"\b(?:WNetAddConnection2|WNetUseConnection|NetShareEnum|NetShareGetInfo)\b",
        "high",
        0.95,
        "access",
        "Windows",
        "Windows network share API.",
    ),
    CommunicationPattern(
        "ldap",
        "ldap",
        r"\b(?:ldap://|ldaps://|LDAPConnection|DirectorySearcher|System\.DirectoryServices)\b",
        "medium",
        0.93,
        "query",
        "cross-platform",
        "LDAP or directory-service communication.",
    ),
    CommunicationPattern(
        "remote_resource",
        "remote_resource",
        r"\b(?:WebDAV|\\\\[^\\\r\n]+\\[^\\\r\n]+|remote\s+(?:share|resource|server)|network\s+share)\b",
        "medium",
        0.88,
        "access",
        "cross-platform",
        "Remote resource reference.",
    ),

    # -------------------------------------------------------------------------
    # Email
    # -------------------------------------------------------------------------
    CommunicationPattern(
        "smtp",
        "smtp",
        r"\b(?:smtp://|smtps://|SMTPClient|SmtpClient|MailMessage|sendmail|EHLO|HELO)\b",
        "medium",
        0.92,
        "send",
        "cross-platform",
        "SMTP/email communication primitive.",
    ),
    CommunicationPattern(
        "email_address",
        "email",
        r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b",
        "low",
        0.94,
        "reference",
        "cross-platform",
        "Email address reference.",
    ),
    CommunicationPattern(
        "imap_pop",
        "email",
        r"\b(?:imap://|imaps://|pop3://|pop3s://|IMAP|POP3)\b",
        "medium",
        0.92,
        "connect",
        "cross-platform",
        "Mail retrieval protocol reference.",
    ),

    # -------------------------------------------------------------------------
    # WebSocket / persistent channels
    # -------------------------------------------------------------------------
    CommunicationPattern(
        "websocket",
        "websocket",
        r"\b(?:ws://|wss://|WebSocket|ClientWebSocket|websocket-client)\b",
        "medium",
        0.95,
        "connect",
        "cross-platform",
        "WebSocket communication reference.",
    ),
    CommunicationPattern(
        "persistent_connection",
        "callback",
        r"\b(?:keepalive|keep-alive|persistent\s+(?:connection|socket|session)|long[- ]polling)\b",
        "medium",
        0.86,
        "maintain",
        "cross-platform",
        "Persistent communication indicator.",
    ),

    # -------------------------------------------------------------------------
    # Download / upload / retrieval
    # -------------------------------------------------------------------------
    CommunicationPattern(
        "download",
        "download",
        r"\b(?:download(?:ing)?|downloaded|retrieve(?:d)?|fetch(?:ing|ed)?|pull(?:ing|ed)?|stage(?:d|ing)?)\b",
        "low",
        0.72,
        "retrieve",
        "cross-platform",
        "Generic retrieval/download terminology.",
    ),
    CommunicationPattern(
        "upload",
        "upload",
        r"\b(?:upload(?:ing|ed)?|post(?:ing|ed)?|send(?:ing|ed)?)\b",
        "low",
        0.70,
        "send",
        "cross-platform",
        "Generic upload/transmission terminology.",
    ),
    CommunicationPattern(
        "download_file_api",
        "download",
        r"\b(?:DownloadFile|DownloadData|DownloadString|URLDownloadToFile|Start-BitsTransfer)\b",
        "high",
        0.96,
        "download",
        "Windows",
        "Explicit file/data retrieval API.",
    ),
    CommunicationPattern(
        "bits_transfer",
        "download",
        r"\b(?:Start-BitsTransfer|bitsadmin(?:\.exe)?)\b",
        "high",
        0.95,
        "download",
        "Windows",
        "BITS transfer utility or PowerShell cmdlet.",
    ),
    CommunicationPattern(
        "upload_file_api",
        "upload",
        r"\b(?:UploadFile|UploadData|UploadString|Invoke-RestMethod)\b",
        "medium",
        0.90,
        "upload",
        "cross-platform",
        "Explicit data upload primitive.",
    ),

    # -------------------------------------------------------------------------
    # C2 / beaconing / callback
    # -------------------------------------------------------------------------
    CommunicationPattern(
        "c2",
        "c2",
        r"\b(?:command[- ]and[- ]control|c2|C&C|command\s+channel|control\s+server)\b",
        "high",
        0.94,
        "communicate",
        "cross-platform",
        "Command-and-control terminology.",
    ),
    CommunicationPattern(
        "callback",
        "callback",
        r"\b(?:callback|call[- ]back|reverse\s+(?:shell|connection|channel))\b",
        "high",
        0.93,
        "callback",
        "cross-platform",
        "Callback or reverse-channel indicator.",
    ),
    CommunicationPattern(
        "beacon",
        "beacon",
        r"\b(?:beacon(?:ing)?|beacon\s+interval|heartbeat|check[- ]in|phone[- ]home)\b",
        "high",
        0.91,
        "beacon",
        "cross-platform",
        "Periodic callback/beacon terminology.",
    ),
    CommunicationPattern(
        "polling",
        "polling",
        r"\b(?:poll(?:ing)?|poll\s+interval|periodically\s+(?:check|request|query)|timer.*(?:request|connect|callback))\b",
        "medium",
        0.84,
        "poll",
        "cross-platform",
        "Periodic network polling indicator.",
    ),

    # -------------------------------------------------------------------------
    # Proxy
    # -------------------------------------------------------------------------
    CommunicationPattern(
        "proxy_environment",
        "proxy",
        r"\b(?:HTTP_PROXY|HTTPS_PROXY|ALL_PROXY|NO_PROXY|http_proxy|https_proxy|proxy)\b",
        "low",
        0.88,
        "configure",
        "cross-platform",
        "Proxy environment/configuration reference.",
    ),
    CommunicationPattern(
        "proxy_api",
        "proxy",
        r"\b(?:InternetQueryOption|WinHttpSetOption|WinHttpGetProxyForUrl|Proxy|WebProxy)\b",
        "medium",
        0.92,
        "configure",
        "Windows",
        "Proxy-aware networking API or object.",
    ),
    CommunicationPattern(
        "proxy_avoidance",
        "proxy",
        r"\b(?:bypass(?:ing)?\s+(?:proxy|proxy\s+server)|direct\s+(?:connection|socket)|ignoreProxy|no_proxy)\b",
        "high",
        0.88,
        "bypass",
        "cross-platform",
        "Proxy bypass/avoidance indicator.",
    ),

    # -------------------------------------------------------------------------
    # IPC / named pipes
    # -------------------------------------------------------------------------
    CommunicationPattern(
        "named_pipe",
        "named_pipe",
        r"\\\\\.\\pipe\\[A-Za-z0-9_.-]+",
        "medium",
        0.97,
        "access",
        "Windows",
        "Windows named pipe path.",
    ),
    CommunicationPattern(
        "named_pipe_api",
        "named_pipe",
        r"\b(?:CreateNamedPipe(?:A|W)?|ConnectNamedPipe|CallNamedPipe(?:A|W)?|WaitNamedPipe(?:A|W)?)\b",
        "medium",
        0.96,
        "communicate",
        "Windows",
        "Named-pipe communication API.",
    ),
    CommunicationPattern(
        "ipc_generic",
        "ipc",
        r"\b(?:inter[- ]process\s+communication|IPC|named\s+pipe|Unix\s+socket|domain\s+socket)\b",
        "low",
        0.85,
        "communicate",
        "cross-platform",
        "Generic IPC communication indicator.",
    ),

    # -------------------------------------------------------------------------
    # Cloud / APIs
    # -------------------------------------------------------------------------
    CommunicationPattern(
        "cloud_storage",
        "cloud",
        r"\b(?:S3|Amazon\s+S3|Azure\s+Blob|Azure\s+Storage|Google\s+Cloud\s+Storage|Dropbox\s+API|OneDrive\s+API)\b",
        "medium",
        0.91,
        "communicate",
        "cross-platform",
        "Cloud storage communication reference.",
    ),
    CommunicationPattern(
        "cloud_api",
        "cloud",
        r"\b(?:boto3|azure\.storage|google\.cloud|Microsoft\.Graph|GraphServiceClient)\b",
        "medium",
        0.93,
        "request",
        "cross-platform",
        "Cloud API/client reference.",
    ),
    CommunicationPattern(
        "rest_api",
        "web",
        r"\b(?:REST\s*API|RESTful|API\s+endpoint|endpoint\s*[:=]|api_url|base_url|baseUri)\b",
        "low",
        0.83,
        "request",
        "cross-platform",
        "REST/API endpoint indicator.",
    ),

    # -------------------------------------------------------------------------
    # Encryption / encoding in communication
    # -------------------------------------------------------------------------
    CommunicationPattern(
        "tls",
        "communication_encryption",
        r"\b(?:TLS|SSL|HTTPS|SslStream|Schannel|CERT_CONTEXT|SSLContext)\b",
        "low",
        0.91,
        "encrypt",
        "cross-platform",
        "Encrypted transport reference.",
    ),
    CommunicationPattern(
        "encrypted_channel",
        "communication_encryption",
        r"\b(?:encrypted\s+(?:channel|connection|socket|traffic)|secure\s+(?:channel|transport)|AES.*(?:socket|network|http))\b",
        "medium",
        0.84,
        "encrypt",
        "cross-platform",
        "Explicit encrypted communication indicator.",
    ),
    CommunicationPattern(
        "encoded_transport",
        "encoded_communication",
        r"\b(?:base64|base64url|hex(?:adecimal)?|url[- ]encode|percent[- ]encode|encode(?:d)?\s+(?:request|payload|traffic|data))\b",
        "low",
        0.82,
        "encode",
        "cross-platform",
        "Encoded communication/data indicator.",
    ),
    CommunicationPattern(
        "custom_protocol",
        "communication_obfuscation",
        r"\b(?:custom\s+protocol|binary\s+protocol|proprietary\s+protocol|packet\s+encoding|packet\s+obfuscation)\b",
        "medium",
        0.82,
        "communicate",
        "cross-platform",
        "Custom or obfuscated protocol indicator.",
    ),

    # -------------------------------------------------------------------------
    # Credentials / authenticated network access
    # -------------------------------------------------------------------------
    CommunicationPattern(
        "network_credentials",
        "credentialed_communication",
        r"\b(?:Authorization:\s*Bearer|Basic\s+[A-Za-z0-9+/=]+|Credential|NetworkCredential|CredentialCache|username.*password.*(?:http|ftp|smtp))\b",
        "medium",
        0.84,
        "authenticate",
        "cross-platform",
        "Credentialed communication indicator.",
    ),
    CommunicationPattern(
        "windows_auth_network",
        "credentialed_communication",
        r"\b(?:WNetUseConnection|CredUIPromptForCredentials|InternetSetOption.*USERNAME|InternetSetOption.*PASSWORD)\b",
        "high",
        0.90,
        "authenticate",
        "Windows",
        "Windows network authentication primitive.",
    ),

    # -------------------------------------------------------------------------
    # Network discovery
    # -------------------------------------------------------------------------
    CommunicationPattern(
        "network_discovery",
        "network_discovery",
        r"\b(?:ipconfig|ifconfig|ip\s+addr|Get-NetIPAddress|Get-NetIPConfiguration|arp\s+-a|route\s+print|netstat|Get-NetTCPConnection|nslookup|Resolve-DnsName)\b",
        "medium",
        0.91,
        "discover",
        "cross-platform",
        "Network configuration or connection discovery command.",
    ),
    CommunicationPattern(
        "host_discovery",
        "network_discovery",
        r"\b(?:ping|tracert|traceroute|hostname|GetHostName|InetAddress\.getLocalHost)\b",
        "low",
        0.86,
        "discover",
        "cross-platform",
        "Host/network discovery primitive.",
    ),

    # -------------------------------------------------------------------------
    # Exfiltration / staged communication
    # -------------------------------------------------------------------------
    CommunicationPattern(
        "exfiltration",
        "exfiltration_channel",
        r"\b(?:exfiltrat(?:e|ion|ing)|data\s+exfil(?:tration)?|steal(?:ing)?\s+(?:data|files)|send\s+(?:files|documents|credentials|logs)\s+(?:to|over))\b",
        "high",
        0.94,
        "exfiltrate",
        "cross-platform",
        "Explicit data exfiltration terminology.",
    ),
    CommunicationPattern(
        "file_exfiltration",
        "exfiltration_channel",
        r"\b(?:upload|POST|PUT|multipart/form-data).{0,160}\b(?:file|document|archive|credential|password|cookie|token|log)\b",
        "high",
        0.84,
        "exfiltrate",
        "cross-platform",
        "File or sensitive-data transmission pattern.",
    ),
    CommunicationPattern(
        "staged_download",
        "staged_communication",
        r"\b(?:stage(?:d|ing)?|second[- ]stage|stage\s+payload|payload\s+from\s+(?:server|url|endpoint)|download.*(?:payload|module|dll|exe|script))\b",
        "high",
        0.92,
        "stage",
        "cross-platform",
        "Staged payload retrieval indicator.",
    ),
    CommunicationPattern(
        "remote_command",
        "command_channel",
        r"\b(?:remote\s+command|command\s+channel|execute\s+command.*(?:server|socket|http|https)|receive.*command.*(?:http|socket|server))\b",
        "high",
        0.90,
        "command",
        "cross-platform",
        "Remote command-channel indicator.",
    ),

    # -------------------------------------------------------------------------
    # Common command-line networking tools
    # -------------------------------------------------------------------------
    CommunicationPattern(
        "powershell_network_tool",
        "network",
        r"\b(?:Test-NetConnection|Invoke-WebRequest|Invoke-RestMethod|Start-BitsTransfer|WebClient)\b",
        "medium",
        0.93,
        "communicate",
        "Windows",
        "PowerShell network utility.",
    ),
    CommunicationPattern(
        "windows_network_tool",
        "network",
        r"\b(?:certutil(?:\.exe)?\s+.*-urlcache|bitsadmin(?:\.exe)?\s+/transfer|ftp(?:\.exe)?\s+|telnet(?:\.exe)?\s+|tftp(?:\.exe)?\s+)\b",
        "high",
        0.91,
        "communicate",
        "Windows",
        "Windows command-line network utility.",
    ),
    CommunicationPattern(
        "unix_network_tool",
        "network",
        r"\b(?:nc|ncat|socat|telnet|ftp|tftp|ssh|scp|sftp)(?:\s|$)",
        "medium",
        0.88,
        "communicate",
        "cross-platform",
        "Unix-style networking utility.",
    ),
)


# =============================================================================
# Combination definitions
# =============================================================================


COMBINATION_DEFINITIONS = (
    (
        "http_download",
        ("http", "download"),
        "HTTP communication combined with a retrieval/download capability.",
        "high",
        0.91,
    ),
    (
        "https_download",
        ("https", "download"),
        "HTTPS communication combined with a retrieval/download capability.",
        "high",
        0.93,
    ),
    (
        "networked_upload",
        ("network", "upload"),
        "Network communication combined with an upload capability.",
        "medium",
        0.84,
    ),
    (
        "network_exfiltration",
        ("network", "exfiltration_channel"),
        "Network communication combined with explicit exfiltration behavior.",
        "critical",
        0.94,
    ),
    (
        "web_exfiltration",
        ("web", "exfiltration_channel"),
        "Web/API communication combined with exfiltration indicators.",
        "critical",
        0.93,
    ),
    (
        "c2_callback",
        ("c2", "callback"),
        "Command-and-control terminology combined with callback behavior.",
        "critical",
        0.96,
    ),
    (
        "c2_beacon",
        ("c2", "beacon"),
        "Command-and-control terminology combined with periodic beaconing.",
        "critical",
        0.96,
    ),
    (
        "beacon_polling",
        ("beacon", "polling"),
        "Beaconing combined with periodic polling behavior.",
        "high",
        0.91,
    ),
    (
        "dns_tunnel",
        ("dns", "dns_tunneling"),
        "DNS communication combined with explicit DNS tunneling indicators.",
        "critical",
        0.96,
    ),
    (
        "encoded_network_traffic",
        ("network", "encoded_communication"),
        "Network communication combined with encoded transport indicators.",
        "medium",
        0.84,
    ),
    (
        "encrypted_c2",
        ("c2", "communication_encryption"),
        "C2 communication combined with encrypted transport.",
        "high",
        0.91,
    ),
    (
        "credentialed_remote_access",
        ("network", "credentialed_communication"),
        "Network communication combined with explicit credential use.",
        "high",
        0.89,
    ),
    (
        "staged_network_payload",
        ("staged_communication", "download"),
        "Staged communication combined with payload retrieval.",
        "critical",
        0.95,
    ),
    (
        "remote_command_channel",
        ("network", "command_channel"),
        "Network capability combined with a remote command channel.",
        "critical",
        0.94,
    ),
    (
        "network_discovery_channel",
        ("network_discovery", "network"),
        "Network discovery capability combined with network communication.",
        "medium",
        0.82,
    ),
    (
        "websocket_callback",
        ("websocket", "callback"),
        "WebSocket communication combined with callback behavior.",
        "high",
        0.91,
    ),
    (
        "proxy_avoidance",
        ("network", "proxy"),
        "Network communication accompanied by proxy configuration or bypass indicators.",
        "medium",
        0.80,
    ),
    (
        "ipc_network_bridge",
        ("ipc", "network"),
        "IPC capability combined with network communication.",
        "medium",
        0.80,
    ),
)


# =============================================================================
# Internal helpers
# =============================================================================


def _clamp_confidence(value: float) -> float:
    return max(0.0, min(1.0, float(value)))


def _severity_max(left: str, right: str) -> str:
    if SEVERITY_ORDER.get(right, 0) > SEVERITY_ORDER.get(left, 0):
        return right
    return left


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _decode_text(data: bytes) -> str:
    """Decode bytes without failing on hostile or malformed input."""
    if not data:
        return ""

    for encoding in ("utf-8", "utf-16-le", "utf-16-be", "latin-1"):
        try:
            text = data.decode(encoding, errors="strict")
            if text:
                return text
        except UnicodeDecodeError:
            continue

    return data.decode("utf-8", errors="replace")


def _bounded_text(value: Any) -> str:
    if isinstance(value, str):
        return value[:MAX_FIELD_TEXT]

    if isinstance(value, bytes):
        return _decode_text(value[:MAX_FIELD_TEXT])

    try:
        text = str(value)
    except Exception:
        return ""

    return text[:MAX_FIELD_TEXT]


def _read_input(source: Any) -> tuple[bytes, str, dict[str, Any]]:
    """
    Normalize a supported source into bounded bytes/text.

    Paths are read only as input. No extracted content is written to disk.
    """

    metadata: dict[str, Any] = {}

    if source is None:
        return b"", "", metadata

    if isinstance(source, bytes):
        data = source[:MAX_SOURCE_SIZE]
        return data, _decode_text(data), metadata

    if isinstance(source, bytearray):
        data = bytes(source[:MAX_SOURCE_SIZE])
        return data, _decode_text(data), metadata

    if isinstance(source, memoryview):
        data = source.tobytes()[:MAX_SOURCE_SIZE]
        return data, _decode_text(data), metadata

    if isinstance(source, os.PathLike):
        try:
            path = Path(source)
            metadata["source_name"] = path.name
            data = path.read_bytes()[:MAX_SOURCE_SIZE]
            return data, _decode_text(data), metadata
        except (OSError, ValueError):
            return b"", "", metadata

    if isinstance(source, str):
        possible_path = Path(source)

        if len(source) <= 4096:
            try:
                if possible_path.is_file():
                    metadata["source_name"] = possible_path.name
                    data = possible_path.read_bytes()[:MAX_SOURCE_SIZE]
                    return data, _decode_text(data), metadata
            except (OSError, ValueError):
                pass

        data = source.encode("utf-8", errors="replace")[:MAX_SOURCE_SIZE]
        return data, source[:MAX_SOURCE_SIZE], metadata

    return b"", _bounded_text(source), metadata


def _flatten_source(
    source: Any,
    *,
    max_depth: int = MAX_NESTING_DEPTH,
) -> tuple[list[tuple[str, str]], bytes, dict[str, Any]]:
    """
    Flatten nested structures into bounded textual fields.

    The first returned item contains ``(field_name, text)`` tuples.
    The second contains any directly supplied binary source.
    """

    fields: list[tuple[str, str]] = []
    binary_source = b""
    metadata: dict[str, Any] = {}
    seen: set[int] = set()

    def visit(value: Any, name: str, depth: int) -> None:
        nonlocal binary_source

        if len(fields) >= MAX_TOKENS:
            return

        if depth > max_depth:
            return

        if value is None:
            return

        if isinstance(value, bytes):
            if not binary_source:
                binary_source = value[:MAX_SOURCE_SIZE]

            text = _decode_text(value[:MAX_FIELD_TEXT])
            if text:
                fields.append((name, text))
            return

        if isinstance(value, bytearray):
            visit(bytes(value), name, depth)
            return

        if isinstance(value, memoryview):
            visit(value.tobytes(), name, depth)
            return

        if isinstance(value, str):
            text = value[:MAX_FIELD_TEXT]
            if text:
                fields.append((name, text))
            return

        if isinstance(value, os.PathLike):
            data, text, path_meta = _read_input(value)
            metadata.update(path_meta)

            if data and not binary_source:
                binary_source = data

            if text:
                fields.append((name, text))
            return

        object_id = id(value)

        if isinstance(value, Mapping):
            if object_id in seen:
                return

            seen.add(object_id)

            for key, child in value.items():
                if len(fields) >= MAX_TOKENS:
                    break

                child_name = f"{name}.{str(key)[:128]}" if name else str(key)[:128]
                visit(child, child_name, depth + 1)

            return

        if isinstance(value, Sequence) and not isinstance(
            value, (str, bytes, bytearray, memoryview)
        ):
            if object_id in seen:
                return

            seen.add(object_id)

            for index, child in enumerate(value):
                if len(fields) >= MAX_TOKENS:
                    break

                visit(child, f"{name}[{index}]", depth + 1)

            return

        text = _bounded_text(value)
        if text:
            fields.append((name, text))

    visit(source, "source", 0)

    return fields, binary_source, metadata


def _line_number(text: str, offset: int) -> int:
    return text.count("\n", 0, max(0, offset)) + 1


def _clean_evidence(value: str) -> str:
    value = value.replace("\x00", " ")
    value = re.sub(r"\s+", " ", value).strip()
    return value[:1000]


def _extract_target(text: str) -> Optional[str]:
    url_match = re.search(
        r"\b(?:https?|ftp|ftps|ws|wss|ldap|ldaps)://[^\s\"'<>]+",
        text,
        flags=re.IGNORECASE,
    )
    if url_match:
        return url_match.group(0)[:512]

    unc_match = re.search(r"\\\\[A-Za-z0-9_.-]+\\[^\s\"']+", text)
    if unc_match:
        return unc_match.group(0)[:512]

    pipe_match = re.search(r"\\\\\.\\pipe\\[A-Za-z0-9_.-]+", text, flags=re.I)
    if pipe_match:
        return pipe_match.group(0)[:512]

    host_match = re.search(
        r"\b(?:host|hostname|server|endpoint|domain|target|url|uri)\s*[:=]\s*"
        r"[\"']?([A-Za-z0-9._:-]{2,255})",
        text,
        flags=re.IGNORECASE,
    )
    if host_match:
        return host_match.group(1)[:255]

    return None


def _infer_protocol(category: str, evidence: str) -> str:
    lowered = evidence.lower()

    if "https://" in lowered or category == "https":
        return "https"
    if "http://" in lowered or category == "http":
        return "http"
    if "ftps://" in lowered:
        return "ftps"
    if "ftp://" in lowered or category == "ftp":
        return "ftp"
    if "wss://" in lowered:
        return "wss"
    if "ws://" in lowered or category == "websocket":
        return "websocket"
    if "ldap://" in lowered:
        return "ldap"
    if "ldaps://" in lowered:
        return "ldaps"
    if category in {"smtp", "email"}:
        return "smtp"
    if category in {"dns", "dns_tunneling"}:
        return "dns"
    if category in {"smb", "named_pipe"}:
        return "smb"
    if category in {"socket", "winsock"}:
        return "socket"
    if category in {"wininet"}:
        return "wininet"
    if category in {"winhttp"}:
        return "winhttp"
    if category in {"cloud"}:
        return "cloud"
    if category in {"ipc", "named_pipe"}:
        return "ipc"

    return category


def _infer_operation(pattern: CommunicationPattern, evidence: str) -> str:
    if pattern.operation != "detect":
        return pattern.operation

    lowered = evidence.lower()

    if re.search(r"\b(?:download|retrieve|fetch|pull|receive)\b", lowered):
        return "receive"

    if re.search(r"\b(?:upload|send|post|put|exfiltrat)", lowered):
        return "send"

    if re.search(r"\b(?:resolve|lookup|query|dns)\b", lowered):
        return "resolve"

    if re.search(r"\b(?:discover|enumerate|netstat|ipconfig|ifconfig)\b", lowered):
        return "discover"

    if re.search(r"\b(?:proxy|bypass)\b", lowered):
        return "configure"

    if re.search(r"\b(?:connect|connection|socket)\b", lowered):
        return "connect"

    return "detect"


def _dedupe_strings(values: Iterable[str], limit: int) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()

    for value in values:
        value = str(value)
        if not value or value in seen:
            continue

        seen.add(value)
        result.append(value)

        if len(result) >= limit:
            break

    return result


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0

    counts = Counter(data)
    length = len(data)

    return -sum(
        (count / length) * math.log2(count / length)
        for count in counts.values()
        if count
    )


def _extract_urls(text: str) -> list[str]:
    pattern = re.compile(
        r"\b(?:https?|ftps?|wss?|ldaps?)://[^\s\"'<>]+",
        re.IGNORECASE,
    )
    return _dedupe_strings(
        (match.group(0).rstrip(".,;)]}") for match in pattern.finditer(text)),
        MAX_URLS,
    )


def _platform_for_pattern(pattern: CommunicationPattern) -> str:
    return pattern.platform


def _add_evidence(
    analysis: CommunicationAnalysis,
    evidence: CommunicationEvidence,
) -> None:
    if len(analysis.evidence) >= MAX_EVIDENCE_ITEMS:
        return

    analysis.evidence.append(evidence)


def _add_record(
    analysis: CommunicationAnalysis,
    record: CommunicationRecord,
) -> None:
    if len(analysis.records) >= MAX_RECORDS:
        return

    analysis.records.append(record)


def _scan_patterns(
    text: str,
    analysis: CommunicationAnalysis,
    *,
    source_name: str,
) -> None:
    if not text:
        return

    for pattern in PATTERNS:
        try:
            compiled = re.compile(pattern.regex, re.IGNORECASE | re.MULTILINE)
        except re.error:
            continue

        match_count = 0

        for match in compiled.finditer(text):
            if match_count >= MAX_MATCHES_PER_PATTERN:
                break

            raw = match.group(0)
            if not raw:
                continue

            evidence_text = _clean_evidence(raw)
            line = _line_number(text, match.start())

            target = _extract_target(raw)
            protocol = _infer_protocol(pattern.category, raw)
            operation = _infer_operation(pattern, raw)
            platform = _platform_for_pattern(pattern)

            evidence = CommunicationEvidence(
                category=pattern.category,
                indicator=pattern.name,
                evidence=evidence_text,
                source=source_name,
                line_number=line,
                target=target,
                protocol=protocol,
                operation=operation,
                platform=platform,
                confidence=_clamp_confidence(pattern.confidence),
                severity=pattern.severity,
            )

            _add_evidence(analysis, evidence)

            _add_record(
                analysis,
                CommunicationRecord(
                    category=pattern.category,
                    protocol=protocol,
                    operation=operation,
                    target=target,
                    indicator=pattern.name,
                    evidence=evidence_text,
                    platform=platform,
                    severity=pattern.severity,
                    confidence=_clamp_confidence(pattern.confidence),
                    source_offset=match.start(),
                ),
            )

            match_count += 1


def _scan_ip_addresses(
    text: str,
    analysis: CommunicationAnalysis,
    *,
    source_name: str,
) -> None:
    """
    Extract IPv4 literals as communication targets.

    This is intentionally informational; an IP literal does not by itself imply
    malicious network behavior.
    """

    pattern = re.compile(
        r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}"
        r"(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
    )

    seen: set[str] = set()

    for match in pattern.finditer(text):
        ip = match.group(0)

        if ip in seen:
            continue

        seen.add(ip)

        evidence = CommunicationEvidence(
            category="network",
            indicator="ipv4_literal",
            evidence=ip,
            source=source_name,
            line_number=_line_number(text, match.start()),
            target=ip,
            protocol="network",
            operation="reference",
            platform="cross-platform",
            confidence=0.94,
            severity="low",
        )

        _add_evidence(analysis, evidence)

        _add_record(
            analysis,
            CommunicationRecord(
                category="network",
                protocol="network",
                operation="reference",
                target=ip,
                indicator="ipv4_literal",
                evidence=ip,
                platform="cross-platform",
                severity="low",
                confidence=0.94,
                source_offset=match.start(),
            ),
        )


def _scan_port_references(
    text: str,
    analysis: CommunicationAnalysis,
    *,
    source_name: str,
) -> None:
    patterns = (
        (
            "port_reference",
            re.compile(
                r"\b(?:port|dstport|destport|remoteport|localport)"
                r"\s*[:=]\s*(\d{1,5})\b",
                re.IGNORECASE,
            ),
        ),
        (
            "host_port",
            re.compile(
                r"\b(?:https?|ftp|ws|wss)://[^/\s:]+:(\d{1,5})\b",
                re.IGNORECASE,
            ),
        ),
    )

    seen: set[str] = set()

    for indicator, pattern in patterns:
        for match in pattern.finditer(text):
            port = match.group(1)

            try:
                number = int(port)
            except ValueError:
                continue

            if not 1 <= number <= 65535:
                continue

            key = f"{indicator}:{number}"
            if key in seen:
                continue

            seen.add(key)

            evidence = CommunicationEvidence(
                category="network",
                indicator=indicator,
                evidence=_clean_evidence(match.group(0)),
                source=source_name,
                line_number=_line_number(text, match.start()),
                target=f"port:{number}",
                protocol="network",
                operation="configure",
                platform="cross-platform",
                confidence=0.90,
                severity="low",
            )

            _add_evidence(analysis, evidence)

            _add_record(
                analysis,
                CommunicationRecord(
                    category="network",
                    protocol="network",
                    operation="configure",
                    target=f"port:{number}",
                    indicator=indicator,
                    evidence=_clean_evidence(match.group(0)),
                    platform="cross-platform",
                    severity="low",
                    confidence=0.90,
                    source_offset=match.start(),
                ),
            )


def _scan_binary_indicators(
    data: bytes,
    analysis: CommunicationAnalysis,
) -> None:
    """
    Inspect binary content for embedded textual communication indicators.

    Binary scanning is bounded and never attempts to execute or load content.
    """

    if not data:
        return

    bounded = data[:MAX_BINARY_SCAN]

    # Extract printable ASCII regions.
    printable = bytearray()

    for byte in bounded:
        if 32 <= byte <= 126 or byte in (9, 10, 13):
            printable.append(byte)
        else:
            printable.append(32)

    text = printable.decode("ascii", errors="ignore")

    if text:
        _scan_patterns(
            text,
            analysis,
            source_name="binary-strings",
        )

        _scan_ip_addresses(
            text,
            analysis,
            source_name="binary-strings",
        )

        _scan_port_references(
            text,
            analysis,
            source_name="binary-strings",
        )


def _derive_categories(analysis: CommunicationAnalysis) -> None:
    analysis.indicators = _dedupe_strings(
        (record.indicator for record in analysis.records), MAX_INDICATORS
    )

    analysis.categories = _dedupe_strings(
        (record.category for record in analysis.records),
        len(COMMUNICATION_CATEGORIES),
    )

    analysis.protocols = _dedupe_strings(
        (record.protocol for record in analysis.records),
        len(COMMUNICATION_CATEGORIES) + 20,
    )

    analysis.targets = _dedupe_strings(
        (record.target for record in analysis.records if record.target),
        MAX_TARGETS,
    )

    analysis.operations = _dedupe_strings(
        (record.operation for record in analysis.records),
        64,
    )

    analysis.platforms = _dedupe_strings(
        (record.platform for record in analysis.records),
        16,
    )


def _derive_combinations(
    analysis: CommunicationAnalysis,
) -> list[CommunicationCombination]:
    categories = set(analysis.categories)

    combinations: list[CommunicationCombination] = []

    for name, required, explanation, severity, confidence in COMBINATION_DEFINITIONS:
        present = all(category in categories for category in required)

        combinations.append(
            CommunicationCombination(
                name=name,
                present=present,
                required_categories=tuple(required),
                explanation=explanation,
                severity=severity,
                confidence=confidence,
            )
        )

    # Strong contextual combination: explicit URL + download/retrieval.
    has_url = bool(_extract_urls(
        "\n".join(item.evidence for item in analysis.evidence)
    ))

    if has_url and "download" in categories:
        combinations.append(
            CommunicationCombination(
                name="url_retrieval_chain",
                present=True,
                required_categories=("download",),
                explanation="A concrete URL reference is associated with retrieval behavior.",
                severity="high",
                confidence=0.90,
            )
        )
    else:
        combinations.append(
            CommunicationCombination(
                name="url_retrieval_chain",
                present=False,
                required_categories=("download",),
                explanation="A concrete URL reference is associated with retrieval behavior.",
                severity="high",
                confidence=0.90,
            )
        )

    return combinations


def _signal_score(analysis: CommunicationAnalysis) -> float:
    score = 0.0

    for record in analysis.records:
        severity_weight = {
            "info": 0.1,
            "low": 0.5,
            "medium": 1.0,
            "high": 2.0,
            "critical": 3.5,
        }.get(record.severity, 1.0)

        score += severity_weight * max(0.25, record.confidence)

    for combination in analysis.combinations:
        if combination.present:
            score += (
                {
                    "info": 0.2,
                    "low": 0.5,
                    "medium": 1.0,
                    "high": 2.0,
                    "critical": 3.5,
                }.get(combination.severity, 1.0)
                * combination.confidence
            )

    return round(score, 6)


def _build_feature_vector(
    analysis: CommunicationAnalysis,
) -> dict[str, float]:
    records = analysis.records

    vector: dict[str, float] = {
        "source_size": float(analysis.source_size),
        "record_count": float(len(records)),
        "evidence_count": float(len(analysis.evidence)),
        "indicator_count": float(len(analysis.indicators)),
        "category_count": float(len(analysis.categories)),
        "protocol_count": float(len(analysis.protocols)),
        "target_count": float(len(analysis.targets)),
        "operation_count": float(len(analysis.operations)),
        "platform_count": float(len(analysis.platforms)),
        "combination_count": float(
            sum(1 for item in analysis.combinations if item.present)
        ),
        "high_count": float(
            sum(1 for item in records if item.severity == "high")
        ),
        "critical_count": float(
            sum(1 for item in records if item.severity == "critical")
        ),
        "network_count": float(
            sum(1 for item in records if item.category == "network")
        ),
        "web_count": float(
            sum(1 for item in records if item.category == "web")
        ),
        "http_count": float(
            sum(1 for item in records if item.category == "http")
        ),
        "https_count": float(
            sum(1 for item in records if item.category == "https")
        ),
        "ftp_count": float(
            sum(1 for item in records if item.category == "ftp")
        ),
        "dns_count": float(
            sum(1 for item in records if item.category == "dns")
        ),
        "dns_tunneling_count": float(
            sum(1 for item in records if item.category == "dns_tunneling")
        ),
        "ldap_count": float(
            sum(1 for item in records if item.category == "ldap")
        ),
        "smb_count": float(
            sum(1 for item in records if item.category == "smb")
        ),
        "socket_count": float(
            sum(1 for item in records if item.category == "socket")
        ),
        "winsock_count": float(
            sum(1 for item in records if item.category == "winsock")
        ),
        "wininet_count": float(
            sum(1 for item in records if item.category == "wininet")
        ),
        "winhttp_count": float(
            sum(1 for item in records if item.category == "winhttp")
        ),
        "email_count": float(
            sum(1 for item in records if item.category == "email")
        ),
        "smtp_count": float(
            sum(1 for item in records if item.category == "smtp")
        ),
        "websocket_count": float(
            sum(1 for item in records if item.category == "websocket")
        ),
        "cloud_count": float(
            sum(1 for item in records if item.category == "cloud")
        ),
        "proxy_count": float(
            sum(1 for item in records if item.category == "proxy")
        ),
        "ipc_count": float(
            sum(1 for item in records if item.category == "ipc")
        ),
        "named_pipe_count": float(
            sum(1 for item in records if item.category == "named_pipe")
        ),
        "download_count": float(
            sum(1 for item in records if item.category == "download")
        ),
        "upload_count": float(
            sum(1 for item in records if item.category == "upload")
        ),
        "callback_count": float(
            sum(1 for item in records if item.category == "callback")
        ),
        "beacon_count": float(
            sum(1 for item in records if item.category == "beacon")
        ),
        "polling_count": float(
            sum(1 for item in records if item.category == "polling")
        ),
        "c2_count": float(
            sum(1 for item in records if item.category == "c2")
        ),
        "command_channel_count": float(
            sum(1 for item in records if item.category == "command_channel")
        ),
        "staged_communication_count": float(
            sum(1 for item in records if item.category == "staged_communication")
        ),
        "encoded_communication_count": float(
            sum(1 for item in records if item.category == "encoded_communication")
        ),
        "communication_encryption_count": float(
            sum(1 for item in records if item.category == "communication_encryption")
        ),
        "communication_obfuscation_count": float(
            sum(1 for item in records if item.category == "communication_obfuscation")
        ),
        "credentialed_communication_count": float(
            sum(1 for item in records if item.category == "credentialed_communication")
        ),
        "network_discovery_count": float(
            sum(1 for item in records if item.category == "network_discovery")
        ),
        "remote_resource_count": float(
            sum(1 for item in records if item.category == "remote_resource")
        ),
        "exfiltration_channel_count": float(
            sum(1 for item in records if item.category == "exfiltration_channel")
        ),
        "ipv4_literal_count": float(
            sum(1 for item in records if item.indicator == "ipv4_literal")
        ),
        "port_reference_count": float(
            sum(1 for item in records if item.indicator in {
                "port_reference",
                "host_port",
            })
        ),
        "windows_count": float(
            sum(1 for item in records if item.platform == "Windows")
        ),
        "cross_platform_count": float(
            sum(1 for item in records if item.platform == "cross-platform")
        ),
        "signal_score": 0.0,
    }

    for category in COMMUNICATION_CATEGORIES:
        vector[f"category_{category}"] = float(
            sum(1 for item in records if item.category == category)
        )

    for indicator in sorted(analysis.indicators):
        vector[f"indicator_{indicator}"] = float(
            sum(1 for item in records if item.indicator == indicator)
        )

    for combination in analysis.combinations:
        vector[f"combination_{combination.name}"] = float(
            combination.present
        )

    vector["signal_score"] = _signal_score(analysis)

    return dict(sorted(vector.items()))


# =============================================================================
# Main analysis API
# =============================================================================


def analyze_communication(
    source: Any,
    *,
    source_name: str = "source",
) -> CommunicationAnalysis:
    """
    Analyze communication capabilities in arbitrary static input.

    Parameters
    ----------
    source:
        Text, bytes, path, mapping, sequence, or bounded structured object.
    source_name:
        Human-readable name used in evidence records.

    Returns
    -------
    CommunicationAnalysis
        Complete static communication analysis.

    Notes
    -----
    No network activity is performed.
    """

    direct_data, direct_text, direct_metadata = _read_input(source)

    fields, binary_source, nested_metadata = _flatten_source(source)

    metadata = {
        **direct_metadata,
        **nested_metadata,
        "static_only": True,
        "network_activity_performed": False,
        "source_type": type(source).__name__,
    }

    if direct_data and not binary_source:
        binary_source = direct_data

    combined_text_parts: list[str] = []

    if direct_text:
        combined_text_parts.append(direct_text)

    combined_text_parts.extend(text for _, text in fields)

    combined_text = "\n".join(combined_text_parts)

    if len(combined_text) > MAX_TEXT_SIZE:
        combined_text = combined_text[:MAX_TEXT_SIZE]

    source_bytes = direct_data or binary_source

    if not source_bytes and combined_text:
        source_bytes = combined_text.encode(
            "utf-8",
            errors="replace",
        )[:MAX_SOURCE_SIZE]

    source_bytes = source_bytes[:MAX_SOURCE_SIZE]

    analysis = CommunicationAnalysis(
        source_hash=_sha256(source_bytes),
        source_size=len(source_bytes),
        metadata=metadata,
    )

    if fields:
        for field_name, field_text in fields:
            _scan_patterns(
                field_text,
                analysis,
                source_name=field_name or source_name,
            )

            _scan_ip_addresses(
                field_text,
                analysis,
                source_name=field_name or source_name,
            )

            _scan_port_references(
                field_text,
                analysis,
                source_name=field_name or source_name,
            )
    else:
        _scan_patterns(
            combined_text,
            analysis,
            source_name=source_name,
        )

        _scan_ip_addresses(
            combined_text,
            analysis,
            source_name=source_name,
        )

        _scan_port_references(
            combined_text,
            analysis,
            source_name=source_name,
        )

    if source_bytes:
        _scan_binary_indicators(source_bytes, analysis)

    # Remove exact duplicate records that may have been found both in the
    # structured fields and binary-string scan.
    unique_records: list[CommunicationRecord] = []
    seen_records: set[tuple[Any, ...]] = set()

    for record in analysis.records:
        key = (
            record.category,
            record.protocol,
            record.operation,
            record.target,
            record.indicator,
            record.evidence,
        )

        if key in seen_records:
            continue

        seen_records.add(key)
        unique_records.append(record)

        if len(unique_records) >= MAX_RECORDS:
            break

    analysis.records = unique_records

    unique_evidence: list[CommunicationEvidence] = []
    seen_evidence: set[tuple[Any, ...]] = set()

    for evidence in analysis.evidence:
        key = (
            evidence.category,
            evidence.indicator,
            evidence.evidence,
            evidence.source,
            evidence.line_number,
            evidence.target,
        )

        if key in seen_evidence:
            continue

        seen_evidence.add(key)
        unique_evidence.append(evidence)

        if len(unique_evidence) >= MAX_EVIDENCE_ITEMS:
            break

    analysis.evidence = unique_evidence

    _derive_categories(analysis)

    analysis.combinations = _derive_combinations(analysis)

    analysis.feature_vector = _build_feature_vector(analysis)

    analysis.metadata.update(
        {
            "url_count": len(_extract_urls(combined_text)),
            "text_field_count": len(fields),
            "record_limit": MAX_RECORDS,
            "evidence_limit": MAX_EVIDENCE_ITEMS,
            "pattern_count": len(PATTERNS),
        }
    )

    return analysis


def analyze_communication_content(
    content: Any,
    *,
    source_name: str = "content",
) -> CommunicationAnalysis:
    """Analyze in-memory communication-related content."""

    return analyze_communication(
        content,
        source_name=source_name,
    )


def parse_communication(
    source: Any,
    *,
    source_name: str = "source",
) -> CommunicationAnalysis:
    """Compatibility alias for :func:`analyze_communication`."""

    return analyze_communication(
        source,
        source_name=source_name,
    )


def extract_communication_features(
    source: Any,
    *,
    source_name: str = "source",
) -> dict[str, float]:
    """Return the stable communication feature vector."""

    return analyze_communication(
        source,
        source_name=source_name,
    ).feature_vector


def extract_feature_vector(
    source: Any,
    *,
    source_name: str = "source",
) -> dict[str, float]:
    """Return communication features as a scalar mapping."""

    return extract_communication_features(
        source,
        source_name=source_name,
    )


def extract_communication_feature_vector(
    source: Any,
    *,
    source_name: str = "source",
) -> dict[str, float]:
    """Explicit alias for communication feature-vector extraction."""

    return extract_communication_features(
        source,
        source_name=source_name,
    )


# =============================================================================
# Feature schema helpers
# =============================================================================


def communication_feature_names() -> list[str]:
    """
    Return deterministic base feature names.

    Dynamic indicator and combination features are included from the current
    rule table.
    """

    names = {
        "source_size",
        "record_count",
        "evidence_count",
        "indicator_count",
        "category_count",
        "protocol_count",
        "target_count",
        "operation_count",
        "platform_count",
        "combination_count",
        "high_count",
        "critical_count",
        "network_count",
        "web_count",
        "http_count",
        "https_count",
        "ftp_count",
        "dns_count",
        "dns_tunneling_count",
        "ldap_count",
        "smb_count",
        "socket_count",
        "winsock_count",
        "wininet_count",
        "winhttp_count",
        "email_count",
        "smtp_count",
        "websocket_count",
        "cloud_count",
        "proxy_count",
        "ipc_count",
        "named_pipe_count",
        "download_count",
        "upload_count",
        "callback_count",
        "beacon_count",
        "polling_count",
        "c2_count",
        "command_channel_count",
        "staged_communication_count",
        "encoded_communication_count",
        "communication_encryption_count",
        "communication_obfuscation_count",
        "credentialed_communication_count",
        "network_discovery_count",
        "remote_resource_count",
        "exfiltration_channel_count",
        "ipv4_literal_count",
        "port_reference_count",
        "windows_count",
        "cross_platform_count",
        "signal_score",
    }

    names.update(
        f"category_{category}"
        for category in COMMUNICATION_CATEGORIES
    )

    names.update(
        f"indicator_{pattern.name}"
        for pattern in PATTERNS
    )

    names.update(
        f"combination_{definition[0]}"
        for definition in COMBINATION_DEFINITIONS
    )

    names.add("combination_url_retrieval_chain")

    return sorted(names)


def build_feature_schema() -> dict[str, Any]:
    """Build a serializable feature schema for ML pipelines."""

    names = communication_feature_names()

    return {
        "schema_version": "1.0",
        "module": "src.extraction.capabilities.communication",
        "feature_type": "static_communication_capability",
        "features": [
            {
                "name": name,
                "type": "float",
            }
            for name in names
        ],
        "count": len(names),
        "static_only": True,
    }


def vectorize_features(
    features: Mapping[str, Any],
    *,
    feature_names: Optional[Sequence[str]] = None,
) -> list[float]:
    """
    Convert a feature mapping to a deterministic numeric vector.

    Missing features are represented by zero.
    """

    names = list(feature_names or communication_feature_names())

    vector: list[float] = []

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


# =============================================================================
# Query helpers
# =============================================================================


def extract_communication_records(
    source: Any,
    *,
    source_name: str = "source",
) -> list[CommunicationRecord]:
    """Return normalized communication records."""

    return analyze_communication(
        source,
        source_name=source_name,
    ).records


def has_indicator(
    analysis: CommunicationAnalysis,
    indicator: str,
) -> bool:
    """Return whether an indicator is present."""

    return indicator in set(analysis.indicators)


def has_category(
    analysis: CommunicationAnalysis,
    category: str,
) -> bool:
    """Return whether a communication category is present."""

    return category in set(analysis.categories)


def indicator_count(
    analysis: CommunicationAnalysis,
    indicator: str,
) -> int:
    """Count records carrying a specific indicator."""

    return sum(
        1
        for record in analysis.records
        if record.indicator == indicator
    )


def category_count(
    analysis: CommunicationAnalysis,
    category: str,
) -> int:
    """Count records belonging to a specific category."""

    return sum(
        1
        for record in analysis.records
        if record.category == category
    )


def evidence_by_category(
    analysis: CommunicationAnalysis,
    category: str,
) -> list[CommunicationEvidence]:
    """Return evidence belonging to a category."""

    return [
        item
        for item in analysis.evidence
        if item.category == category
    ]


def evidence_by_indicator(
    analysis: CommunicationAnalysis,
    indicator: str,
) -> list[CommunicationEvidence]:
    """Return evidence belonging to an indicator."""

    return [
        item
        for item in analysis.evidence
        if item.indicator == indicator
    ]


def high_risk_evidence(
    analysis: CommunicationAnalysis,
) -> list[CommunicationEvidence]:
    """Return high and critical severity communication evidence."""

    return [
        item
        for item in analysis.evidence
        if SEVERITY_ORDER.get(item.severity, 0) >= SEVERITY_ORDER["high"]
    ]


def present_combinations(
    analysis: CommunicationAnalysis,
) -> list[CommunicationCombination]:
    """Return only combinations that are present."""

    return [
        item
        for item in analysis.combinations
        if item.present
    ]


def highest_severity(
    analysis: CommunicationAnalysis,
) -> str:
    """Return the highest severity observed in the analysis."""

    severity = "info"

    for evidence in analysis.evidence:
        severity = _severity_max(severity, evidence.severity)

    for combination in analysis.combinations:
        if combination.present:
            severity = _severity_max(severity, combination.severity)

    return severity


# =============================================================================
# Serialization and reporting
# =============================================================================


def analysis_to_dict(
    analysis: CommunicationAnalysis,
) -> dict[str, Any]:
    """Convert an analysis into a JSON-compatible dictionary."""

    result = asdict(analysis)

    result["summary"] = {
        "highest_severity": highest_severity(analysis),
        "signal_score": analysis.feature_vector.get("signal_score", 0.0),
        "record_count": len(analysis.records),
        "evidence_count": len(analysis.evidence),
        "present_combinations": [
            item.name
            for item in analysis.combinations
            if item.present
        ],
    }

    return result


def summarize_communication(
    analysis: CommunicationAnalysis,
) -> dict[str, Any]:
    """Return a compact communication summary suitable for reports."""

    category_counts = Counter(
        record.category
        for record in analysis.records
    )

    protocol_counts = Counter(
        record.protocol
        for record in analysis.records
    )

    operation_counts = Counter(
        record.operation
        for record in analysis.records
    )

    return {
        "source_hash": analysis.source_hash,
        "source_size": analysis.source_size,
        "highest_severity": highest_severity(analysis),
        "signal_score": analysis.feature_vector.get(
            "signal_score",
            0.0,
        ),
        "indicators": list(analysis.indicators),
        "categories": list(analysis.categories),
        "protocols": list(analysis.protocols),
        "targets": list(analysis.targets),
        "operations": list(analysis.operations),
        "category_counts": dict(sorted(category_counts.items())),
        "protocol_counts": dict(sorted(protocol_counts.items())),
        "operation_counts": dict(sorted(operation_counts.items())),
        "present_combinations": [
            item.name
            for item in analysis.combinations
            if item.present
        ],
        "high_risk_evidence_count": len(
            high_risk_evidence(analysis)
        ),
    }


def iter_evidence(
    analysis: CommunicationAnalysis,
) -> Iterator[CommunicationEvidence]:
    """Iterate over communication evidence."""

    yield from analysis.evidence


def iter_high_risk_evidence(
    analysis: CommunicationAnalysis,
) -> Iterator[CommunicationEvidence]:
    """Iterate over high and critical evidence."""

    yield from high_risk_evidence(analysis)


def iter_records(
    analysis: CommunicationAnalysis,
) -> Iterator[CommunicationRecord]:
    """Iterate over normalized communication records."""

    yield from analysis.records


def iter_combinations(
    analysis: CommunicationAnalysis,
    *,
    present_only: bool = False,
) -> Iterator[CommunicationCombination]:
    """Iterate over derived combinations."""

    for combination in analysis.combinations:
        if present_only and not combination.present:
            continue

        yield combination


def iter_analyses(
    sources: Iterable[Any],
    *,
    source_name: str = "source",
) -> Iterator[CommunicationAnalysis]:
    """Analyze multiple sources lazily."""

    for index, source in enumerate(sources):
        yield analyze_communication(
            source,
            source_name=f"{source_name}[{index}]",
        )


# =============================================================================
# Convenience aliases
# =============================================================================


analyze = analyze_communication
extract = extract_communication_features


# =============================================================================
# PUBLIC APIs
# =============================================================================

__all__ = [
    "MAX_SOURCE_SIZE",
    "MAX_TEXT_SIZE",
    "MAX_FIELD_TEXT",
    "MAX_EVIDENCE_ITEMS",
    "MAX_RECORDS",
    "MAX_MATCHES_PER_PATTERN",
    "MAX_NESTING_DEPTH",
    "MAX_TOKENS",
    "MAX_INDICATORS",
    "MAX_TARGETS",
    "MAX_URLS",
    "MAX_LINES",
    "MAX_BINARY_SCAN",
    "COMMUNICATION_CATEGORIES",
    "PATTERNS",
    "COMBINATION_DEFINITIONS",
    "CommunicationPattern",
    "CommunicationEvidence",
    "CommunicationRecord",
    "CommunicationCombination",
    "CommunicationAnalysis",
    "analyze_communication",
    "analyze_communication_content",
    "parse_communication",
    "extract_communication_features",
    "extract_feature_vector",
    "extract_communication_feature_vector",
    "extract_communication_records",
    "communication_feature_names",
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
    "summarize_communication",
    "iter_evidence",
    "iter_high_risk_evidence",
    "iter_records",
    "iter_combinations",
    "iter_analyses",
    "analyze",
    "extract",
]