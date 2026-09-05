"""
Static credential-behavior extraction.

This module identifies credential-access, credential-discovery, authentication
artifact, secret-handling, and credential-collection indicators from untrusted
source material.

The extractor is intentionally passive. It never:
    - accesses the host credential store
    - reads browser credential databases
    - queries LSASS
    - invokes Windows APIs
    - accesses the registry
    - decrypts secrets
    - launches commands or processes
    - performs network authentication
    - writes files or modifies system state

Inputs may be:
    - text
    - bytes
    - filesystem paths
    - mappings
    - nested sequences
    - dataclass/object instances

Output is designed for:

    credentials.py
        -> feature_pipeline.py
        -> ML / CDR / policy / reporting

Evidence chain:

    static indicator
        -> credential behavior
        -> credential-access category
        -> higher-level combination
        -> stable feature vector
        -> downstream decision
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections import Counter
from dataclasses import asdict, dataclass, field, is_dataclass
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
)

# ---------------------------------------------------------------------------
# Resource limits
# ---------------------------------------------------------------------------

MAX_SOURCE_SIZE = 25 * 1024 * 1024
MAX_TEXT_CHARS = 25 * 1024 * 1024
MAX_FIELD_TEXT = 100_000

MAX_EVIDENCE_ITEMS = 20_000
MAX_MATCHES_PER_RULE = 5_000
MAX_NESTING_DEPTH = 12
MAX_CREDENTIAL_RECORDS = 10_000
MAX_LOCATIONS = 10_000
MAX_TOKENS = 250_000
MAX_INDICATORS = 20_000
MAX_COMMAND_LINES = 20_000

MAX_SNIPPET_LENGTH = 500


# ---------------------------------------------------------------------------
# Credential taxonomy
# ---------------------------------------------------------------------------

CREDENTIAL_CATEGORIES: Tuple[str, ...] = (
    "credential_access",
    "credential_discovery",
    "credential_collection",
    "credential_storage",
    "credential_query",
    "credential_dumping",
    "password_access",
    "password_collection",
    "username_discovery",
    "account_discovery",
    "account_manipulation",
    "authentication",
    "authentication_material",
    "browser_credentials",
    "browser_passwords",
    "browser_cookies",
    "web_credentials",
    "password_managers",
    "email_credentials",
    "cloud_credentials",
    "api_keys",
    "access_tokens",
    "refresh_tokens",
    "session_tokens",
    "oauth_tokens",
    "jwt_tokens",
    "kerberos",
    "ntlm",
    "lsass",
    "sam_database",
    "security_accounts_manager",
    "lsa_secrets",
    "credential_manager",
    "windows_vault",
    "dpapi",
    "cached_credentials",
    "credential_files",
    "ssh_credentials",
    "ssh_keys",
    "private_keys",
    "certificate_credentials",
    "gpg_credentials",
    "aws_credentials",
    "azure_credentials",
    "gcp_credentials",
    "kubernetes_credentials",
    "docker_credentials",
    "git_credentials",
    "database_credentials",
    "rdp_credentials",
    "vpn_credentials",
    "wifi_credentials",
    "office_credentials",
    "cloud_identity",
    "environment_secrets",
    "config_secrets",
    "secret_files",
    "clipboard_credentials",
    "input_capture",
    "keylogging",
    "credential_phishing",
    "credential_exfiltration",
    "credential_decryption",
    "credential_encoding",
    "credential_obfuscation",
    "credential_validation",
    "privilege_related_credentials",
    "authentication_bypass",
)


# ---------------------------------------------------------------------------
# Severity ordering
# ---------------------------------------------------------------------------

SEVERITY_ORDER: Dict[str, int] = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CredentialPattern:
    """Static rule describing credential-related behavior."""

    name: str
    category: str
    regex: str
    severity: str = "medium"
    confidence: float = 0.90
    operation: str = "access"
    platform: str = "generic"
    description: str = ""


@dataclass
class CredentialEvidence:
    """One bounded static piece of credential-related evidence."""

    category: str
    indicator: str
    evidence: str
    source: str = "text"
    line_number: Optional[int] = None
    operation: str = "access"
    platform: str = "generic"
    location: Optional[str] = None
    confidence: float = 1.0
    severity: str = "medium"
    pattern: Optional[str] = None


@dataclass
class CredentialRecord:
    """Normalized credential behavior."""

    behavior: str
    category: str
    operation: str
    platform: str
    indicator: str
    evidence: str
    severity: str = "medium"
    confidence: float = 1.0
    location: Optional[str] = None
    line_number: Optional[int] = None


@dataclass
class CredentialCombination:
    """Higher-level credential-access behavior."""

    name: str
    present: bool
    required_categories: Tuple[str, ...] = field(default_factory=tuple)
    explanation: str = ""


@dataclass
class CredentialAnalysis:
    """Complete static credential-behavior analysis."""

    source_hash: str
    source_size: int

    records: List[CredentialRecord] = field(default_factory=list)
    evidence: List[CredentialEvidence] = field(default_factory=list)

    indicators: List[str] = field(default_factory=list)
    categories: List[str] = field(default_factory=list)
    locations: List[str] = field(default_factory=list)
    platforms: List[str] = field(default_factory=list)

    combinations: List[CredentialCombination] = field(default_factory=list)

    feature_vector: Dict[str, float] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Static credential patterns
# ---------------------------------------------------------------------------

CREDENTIAL_PATTERNS: Tuple[CredentialPattern, ...] = (
    # Generic credential vocabulary.
    CredentialPattern(
        "credential_keyword",
        "credential_access",
        r"\b(?:credential|credentials|credential[s]? store|secret|secrets|"
        r"password|passwd|passphrase|authentication material)\b",
        severity="low",
        confidence=0.70,
        platform="generic",
        description="References credential or secret material.",
    ),
    CredentialPattern(
        "password_variable",
        "password_access",
        r"\b(?:password|passwd|passphrase|pwd|userpass|loginpass|"
        r"adminpass|credential|secret)(?:[_\-]?(?:value|data|text|input|"
        r"string|field|blob))?\b",
        severity="low",
        confidence=0.80,
        platform="generic",
        description="References variables or fields commonly used for passwords.",
    ),
    CredentialPattern(
        "username_reference",
        "username_discovery",
        r"\b(?:username|user_name|user|login|account|useraccount|"
        r"currentuser|current_user|domainuser|logonuser)\b",
        severity="low",
        confidence=0.72,
        platform="generic",
        description="References user/account identity values.",
    ),
    # Windows credential stores.
    CredentialPattern(
        "cmdkey_credentials",
        "credential_manager",
        r"\b(?:cmdkey(?:\.exe)?)(?:\s+/(?:list|generic|add|delete|smartcard))?\b",
        severity="high",
        confidence=0.96,
        platform="windows",
        description="References Windows Credential Manager through cmdkey.",
    ),
    CredentialPattern(
        "credential_manager_api",
        "credential_manager",
        r"\b(?:CredRead(?:A|W)?|CredEnumerate(?:A|W)?|CredWrite(?:A|W)?|"
        r"CredDelete(?:A|W)?|CredUIPromptForCredentials(?:A|W)?|"
        r"CredPackAuthenticationBuffer(?:A|W)?)\b",
        severity="high",
        confidence=0.98,
        platform="windows",
        description="References Windows Credential Manager APIs.",
    ),
    CredentialPattern(
        "windows_vault",
        "windows_vault",
        r"\b(?:VaultCli|VaultEnumerateItems|VaultOpenVault|"
        r"Windows Credential Vault|Web Credentials|Credential Locker)\b",
        severity="high",
        confidence=0.96,
        platform="windows",
        description="References Windows credential-vault functionality.",
    ),
    CredentialPattern(
        "sam_database",
        "sam_database",
        r"\b(?:SAM|Security Account Manager|"
        r"\\Windows\\System32\\config\\SAM|"
        r"HKLM\\SAM|HKEY_LOCAL_MACHINE\\SAM)\b",
        severity="high",
        confidence=0.94,
        platform="windows",
        description="References the Windows SAM database.",
    ),
    CredentialPattern(
        "security_hive",
        "security_accounts_manager",
        r"\b(?:\\Windows\\System32\\config\\SECURITY|"
        r"HKLM\\SECURITY|HKEY_LOCAL_MACHINE\\SECURITY)\b",
        severity="high",
        confidence=0.94,
        platform="windows",
        description="References the Windows SECURITY registry hive.",
    ),
    CredentialPattern(
        "lsa_secrets",
        "lsa_secrets",
        r"\b(?:LSA Secrets?|LsaOpenPolicy|LsaRetrievePrivateData|"
        r"PolicyPrivateInformation|NL\$1|NL\$2|NL\$3|NL\$4|NL\$5|"
        r"NL\$6|NL\$7|NL\$8|NL\$9|NL\$10)\b",
        severity="critical",
        confidence=0.97,
        platform="windows",
        description="References Windows LSA secrets or cached logon material.",
    ),
    CredentialPattern(
        "cached_domain_credentials",
        "cached_credentials",
        r"\b(?:MSCache|MSCache2|DCC2|DCC|" r"CachedInteractiveLogons|NL\$Control)\b",
        severity="high",
        confidence=0.95,
        platform="windows",
        description="References cached domain credential material.",
    ),
    # LSASS and process memory.
    CredentialPattern(
        "lsass_process",
        "lsass",
        r"\b(?:lsass(?:\.exe)?|Local Security Authority Subsystem Service|"
        r"LSA process)\b",
        severity="high",
        confidence=0.96,
        platform="windows",
        description="References LSASS or the local security authority process.",
    ),
    CredentialPattern(
        "lsass_memory_access",
        "credential_dumping",
        r"\b(?:OpenProcess|ReadProcessMemory|MiniDumpWriteDump|"
        r"MiniDumpWithFullMemory|DbgHelp|comsvcs\.dll|"
        r"rundll32(?:\.exe)?\s+[^\\\n]{0,150}\bMiniDump|"
        r"procdump(?:\.exe)?\b).{0,300}\b(?:lsass|LSASS)\b",
        severity="critical",
        confidence=0.99,
        platform="windows",
        description="Combines process-memory access with LSASS credential targeting.",
    ),
    CredentialPattern(
        "credential_dump_tools",
        "credential_dumping",
        r"\b(?:mimikatz|sekurlsa|logonpasswords|wdigest|lsadump|"
        r"samdump|secretsdump|nanodump|pypykatz|rubeus)\b",
        severity="critical",
        confidence=0.99,
        platform="windows",
        description="References well-known credential-dumping functionality or tools.",
    ),
    # Windows authentication protocols.
    CredentialPattern(
        "ntlm_material",
        "ntlm",
        r"\b(?:NTLM|NTLMv1|NTLMv2|NetNTLM|Net-NTLM|MSV1_0|"
        r"MSV1_0_SUBAUTH_LOGON|NTOWFv1|NTOWFv2)\b",
        severity="high",
        confidence=0.94,
        platform="windows",
        description="References NTLM authentication material.",
    ),
    CredentialPattern(
        "kerberos_material",
        "kerberos",
        r"\b(?:Kerberos|krbtgt|TGT|TGS|ticket-granting ticket|"
        r"service ticket|Kirbi|KRB-CRED|AS-REQ|AS-REP|TGS-REQ|TGS-REP)\b",
        severity="high",
        confidence=0.91,
        platform="windows",
        description="References Kerberos authentication material.",
    ),
    CredentialPattern(
        "kerberos_ticket_tools",
        "kerberos",
        r"\b(?:klist|Rubeus|kerberoast|AS-REP roast|"
        r"GetUserSPNs|RequestTGT|ptt|pass[- ]the[- ]ticket)\b",
        severity="high",
        confidence=0.96,
        platform="windows",
        description="References Kerberos ticket discovery or manipulation.",
    ),
    # DPAPI.
    CredentialPattern(
        "dpapi",
        "dpapi",
        r"\b(?:DPAPI|CryptProtectData|CryptUnprotectData|"
        r"CryptProtectMemory|CryptUnprotectMemory|"
        r"MasterKey|MasterKeyFile|PreferredMasterKey)\b",
        severity="high",
        confidence=0.95,
        platform="windows",
        description="References Windows DPAPI-protected data.",
    ),
    CredentialPattern(
        "dpapi_browser_context",
        "credential_decryption",
        r"\b(?:CryptUnprotectData|DPAPI|MasterKey)\b.{0,500}\b(?:Chrome|"
        r"Chromium|Edge|Firefox|Cookies|Login Data|Local State)\b",
        severity="critical",
        confidence=0.98,
        platform="windows",
        description="Correlates DPAPI functionality with browser credential artifacts.",
    ),
    # Browser credentials.
    CredentialPattern(
        "chrome_login_data",
        "browser_passwords",
        r"\b(?:Chrome|Chromium|Google Chrome)\b.{0,300}\b(?:Login Data|"
        r"Login Data For Account|Web Data|Local State)\b",
        severity="high",
        confidence=0.96,
        platform="generic",
        description="References Chromium password-storage artifacts.",
    ),
    CredentialPattern(
        "edge_login_data",
        "browser_passwords",
        r"\b(?:Microsoft Edge|msedge)\b.{0,300}\b(?:Login Data|Local State)\b",
        severity="high",
        confidence=0.96,
        platform="windows",
        description="References Microsoft Edge credential artifacts.",
    ),
    CredentialPattern(
        "firefox_credentials",
        "browser_passwords",
        r"\b(?:Firefox|Mozilla)\b.{0,300}\b(?:logins\.json|key4\.db|"
        r"key3\.db|signons\.sqlite|cert9\.db)\b",
        severity="high",
        confidence=0.97,
        platform="generic",
        description="References Firefox credential databases.",
    ),
    CredentialPattern(
        "browser_cookies",
        "browser_cookies",
        r"\b(?:Chrome|Chromium|Edge|Firefox|Opera|Brave)\b.{0,350}\b"
        r"(?:Cookies|cookies\.sqlite|Network\\Cookies|"
        r"Login Data|session cookie|browser cookie)\b",
        severity="high",
        confidence=0.91,
        platform="generic",
        description="References browser cookie/session artifacts.",
    ),
    CredentialPattern(
        "browser_password_generic",
        "browser_credentials",
        r"\b(?:browser|Chrome|Chromium|Edge|Firefox|Opera|Brave)\b.{0,300}\b"
        r"(?:password|credential|login|secret)\b",
        severity="medium",
        confidence=0.82,
        platform="generic",
        description="Combines browser context with credential terminology.",
    ),
    # Password managers.
    CredentialPattern(
        "password_manager",
        "password_managers",
        r"\b(?:KeePass|KeePassXC|1Password|Bitwarden|LastPass|"
        r"Dashlane|RoboForm|Password Safe|credential manager)\b",
        severity="medium",
        confidence=0.84,
        platform="generic",
        description="References password-management applications or stores.",
    ),
    CredentialPattern(
        "password_database",
        "password_managers",
        r"\b(?:\.kdbx|\.agilekeychain|\.1pif|Bitwarden vault|"
        r"LastPass vault|password vault)\b",
        severity="high",
        confidence=0.93,
        platform="generic",
        description="References password-manager database artifacts.",
    ),
    # SSH and private keys.
    CredentialPattern(
        "ssh_private_key",
        "ssh_keys",
        r"\b(?:-----BEGIN (?:RSA|DSA|EC|OPENSSH|ED25519) PRIVATE KEY-----|"
        r"~/.ssh/(?:id_rsa|id_dsa|id_ecdsa|id_ed25519)|"
        r"\.ssh/(?:id_rsa|id_dsa|id_ecdsa|id_ed25519))\b",
        severity="high",
        confidence=0.99,
        platform="generic",
        description="References SSH private-key material.",
    ),
    CredentialPattern(
        "ssh_config_credentials",
        "ssh_credentials",
        r"\b(?:\.ssh/config|known_hosts|authorized_keys|"
        r"IdentityFile|ssh-agent|SSH_AUTH_SOCK)\b",
        severity="medium",
        confidence=0.90,
        platform="generic",
        description="References SSH authentication configuration or agents.",
    ),
    CredentialPattern(
        "private_key_generic",
        "private_keys",
        r"\b(?:private key|private_key|secret key|key material|"
        r"BEGIN .* PRIVATE KEY)\b",
        severity="high",
        confidence=0.91,
        platform="generic",
        description="References private cryptographic key material.",
    ),
    # Cloud credentials.
    CredentialPattern(
        "aws_credentials",
        "aws_credentials",
        r"\b(?:AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN|"
        r"\.aws/credentials|\.aws/config|aws_access_key_id|"
        r"aws_secret_access_key|AKIA[0-9A-Z]{16})\b",
        severity="high",
        confidence=0.98,
        platform="generic",
        description="References AWS credential material.",
    ),
    CredentialPattern(
        "azure_credentials",
        "azure_credentials",
        r"\b(?:AZURE_CLIENT_ID|AZURE_CLIENT_SECRET|AZURE_TENANT_ID|"
        r"Azure CLI token cache|\.azure/|Azure access token|"
        r"az account get-access-token)\b",
        severity="high",
        confidence=0.95,
        platform="generic",
        description="References Azure authentication material.",
    ),
    CredentialPattern(
        "gcp_credentials",
        "gcp_credentials",
        r"\b(?:GOOGLE_APPLICATION_CREDENTIALS|"
        r"application_default_credentials\.json|"
        r"\.config/gcloud|gcloud auth|GCP service account|"
        r"private_key_id|client_email)\b",
        severity="high",
        confidence=0.95,
        platform="generic",
        description="References Google Cloud credential material.",
    ),
    CredentialPattern(
        "cloud_access_token",
        "access_tokens",
        r"\b(?:access[_ -]?token|bearer[_ -]?token|authorization token|"
        r"OAuth access token|OAuth2 token|id_token|refresh_token)\b",
        severity="high",
        confidence=0.89,
        platform="generic",
        description="References cloud/web access-token material.",
    ),
    CredentialPattern(
        "jwt_token",
        "jwt_tokens",
        r"\b(?:JWT|JSON Web Token|eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\."
        r"[A-Za-z0-9_-]{5,})\b",
        severity="high",
        confidence=0.96,
        platform="generic",
        description="References JWT authentication material.",
    ),
    # Kubernetes / Docker.
    CredentialPattern(
        "kubernetes_credentials",
        "kubernetes_credentials",
        r"\b(?:KUBECONFIG|\.kube/config|kubeconfig|service-account token|"
        r"/var/run/secrets/kubernetes\.io/serviceaccount|"
        r"client-certificate-data|client-key-data)\b",
        severity="high",
        confidence=0.97,
        platform="generic",
        description="References Kubernetes authentication artifacts.",
    ),
    CredentialPattern(
        "docker_credentials",
        "docker_credentials",
        r"\b(?:\.docker/config\.json|docker login|docker credential helper|"
        r"DOCKER_CONFIG)\b",
        severity="high",
        confidence=0.94,
        platform="generic",
        description="References Docker authentication artifacts.",
    ),
    # Git credentials.
    CredentialPattern(
        "git_credentials",
        "git_credentials",
        r"\b(?:\.git-credentials|credential\.helper|git credential|"
        r"GIT_ASKPASS|GIT_CONFIG_GLOBAL|github token|gitlab token)\b",
        severity="high",
        confidence=0.92,
        platform="generic",
        description="References Git authentication material.",
    ),
    # Database credentials.
    CredentialPattern(
        "database_credentials",
        "database_credentials",
        r"\b(?:connection string|connectionstring|"
        r"(?:mysql|postgres(?:ql)?|mssql|sqlserver|oracle|mongodb)"
        r"[^\\\n]{0,150}(?:password|pwd|user|uid))\b",
        severity="high",
        confidence=0.88,
        platform="generic",
        description="References database connection credentials.",
    ),
    CredentialPattern(
        "database_password_fields",
        "database_credentials",
        r"\b(?:DB_PASSWORD|DATABASE_PASSWORD|MYSQL_PWD|PGPASSWORD|"
        r"SQL_PASSWORD|MONGO_INITDB_ROOT_PASSWORD|DB_USER|DATABASE_USER)\b",
        severity="high",
        confidence=0.97,
        platform="generic",
        description="References database credential variables.",
    ),
    # RDP / VPN / Wi-Fi.
    CredentialPattern(
        "rdp_credentials",
        "rdp_credentials",
        r"\b(?:RDP|Remote Desktop|mstsc|Terminal Services)\b.{0,350}\b"
        r"(?:password|credential|username|NLA|CredSSP)\b",
        severity="medium",
        confidence=0.88,
        platform="windows",
        description="Combines RDP context with credential material.",
    ),
    CredentialPattern(
        "vpn_credentials",
        "vpn_credentials",
        r"\b(?:VPN|OpenVPN|WireGuard|AnyConnect|GlobalProtect|"
        r"FortiClient|Pulse Secure)\b.{0,350}\b"
        r"(?:password|credential|secret|token|private key)\b",
        severity="medium",
        confidence=0.86,
        platform="generic",
        description="Combines VPN context with authentication material.",
    ),
    CredentialPattern(
        "wifi_credentials",
        "wifi_credentials",
        r"\b(?:WLAN|Wi-Fi|Wireless|netsh\s+wlan)\b.{0,350}\b"
        r"(?:profile|key|password|credential|clear)\b",
        severity="high",
        confidence=0.90,
        platform="windows",
        description="References wireless credential/profile material.",
    ),
    # Clipboard / input capture.
    CredentialPattern(
        "clipboard_access",
        "clipboard_credentials",
        r"\b(?:GetClipboardData|OpenClipboard|Clipboard\.GetText|"
        r"ClipboardData|clipboard|navigator\.clipboard)\b",
        severity="medium",
        confidence=0.80,
        platform="generic",
        description="References clipboard contents.",
    ),
    CredentialPattern(
        "clipboard_password_context",
        "clipboard_credentials",
        r"\b(?:clipboard|GetClipboardData|Clipboard\.GetText)\b.{0,300}\b"
        r"(?:password|credential|token|secret|key|OTP|2FA|code)\b",
        severity="high",
        confidence=0.94,
        platform="generic",
        description="Combines clipboard access with credential terminology.",
    ),
    CredentialPattern(
        "keylogging",
        "keylogging",
        r"\b(?:GetAsyncKeyState|GetKeyState|SetWindowsHookEx(?:A|W)?|"
        r"WH_KEYBOARD_LL|WH_KEYBOARD|keyboard hook|keylogger|"
        r"Raw Input|RegisterRawInputDevices)\b",
        severity="high",
        confidence=0.97,
        platform="generic",
        description="References keyboard-input capture behavior.",
    ),
    CredentialPattern(
        "input_password_context",
        "input_capture",
        r"\b(?:keyboard|keypress|keylog|input capture|hook)\b.{0,350}\b"
        r"(?:password|credential|login|secret|token|PIN|OTP)\b",
        severity="high",
        confidence=0.93,
        platform="generic",
        description="Combines input capture with credential terminology.",
    ),
    # Environment/configuration secrets.
    CredentialPattern(
        "secret_environment_variable",
        "environment_secrets",
        r"\b(?:PASSWORD|PASSWD|SECRET|TOKEN|API_KEY|APIKEY|"
        r"CLIENT_SECRET|PRIVATE_KEY|ACCESS_KEY|AUTH_TOKEN|"
        r"BEARER_TOKEN|SESSION_TOKEN)\b",
        severity="medium",
        confidence=0.88,
        platform="generic",
        description="References secrets held in environment variables.",
    ),
    CredentialPattern(
        "config_secret_file",
        "config_secrets",
        r"\b(?:\.env|credentials\.json|secrets\.json|secrets\.yml|"
        r"secrets\.yaml|config\.json|application\.properties|"
        r"appsettings\.json|web\.config|settings\.xml)\b.{0,300}\b"
        r"(?:password|secret|token|key|credential)\b",
        severity="high",
        confidence=0.90,
        platform="generic",
        description="References configuration files containing secret fields.",
    ),
    CredentialPattern(
        "secret_file_extensions",
        "secret_files",
        r"\b(?:\.pem|\.key|\.pfx|\.p12|\.kdbx|\.ovpn|"
        r"credentials|credential|secrets?)\b",
        severity="medium",
        confidence=0.76,
        platform="generic",
        description="References files commonly associated with secret material.",
    ),
    # API keys and tokens.
    CredentialPattern(
        "api_key",
        "api_keys",
        r"\b(?:API[_ -]?KEY|APIKEY|ACCESS[_ -]?KEY|SECRET[_ -]?KEY|"
        r"CLIENT[_ -]?SECRET|DEVELOPER[_ -]?KEY)\b",
        severity="medium",
        confidence=0.88,
        platform="generic",
        description="References API-key style authentication material.",
    ),
    CredentialPattern(
        "github_token",
        "api_keys",
        r"\b(?:GITHUB_TOKEN|ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b",
        severity="high",
        confidence=0.98,
        platform="generic",
        description="References GitHub authentication tokens.",
    ),
    CredentialPattern(
        "slack_token",
        "api_keys",
        r"\b(?:xox[baprs]-[A-Za-z0-9-]{10,})\b",
        severity="high",
        confidence=0.98,
        platform="generic",
        description="References Slack-style authentication tokens.",
    ),
    # Credential collection / validation.
    CredentialPattern(
        "credential_prompt",
        "credential_collection",
        r"\b(?:prompt|input|readline|ask|request|collect|capture|"
        r"enter password|enter your password|login form|credential form)\b"
        r".{0,250}\b(?:password|credential|username|login|secret)\b",
        severity="medium",
        confidence=0.89,
        platform="generic",
        description="Collects or prompts for credential material.",
    ),
    CredentialPattern(
        "credential_validation",
        "credential_validation",
        r"\b(?:validate|verify|authenticate|login|logon|sign in|signin|"
        r"credential check|password check)\b.{0,300}\b"
        r"(?:password|credential|username|token|secret)\b",
        severity="medium",
        confidence=0.82,
        platform="generic",
        description="References credential validation or authentication.",
    ),
    CredentialPattern(
        "authentication_bypass",
        "authentication_bypass",
        r"\b(?:bypass authentication|disable authentication|"
        r"skip authentication|password bypass|authentication bypass|"
        r"bypass login|disable login|single sign[- ]on bypass)\b",
        severity="high",
        confidence=0.95,
        platform="generic",
        description="References authentication bypass behavior.",
    ),
    # Encoding / obfuscation in credential context.
    CredentialPattern(
        "credential_base64",
        "credential_encoding",
        r"\b(?:password|credential|secret|token|key)\b.{0,250}\b"
        r"(?:base64|b64encode|b64decode|Convert::FromBase64String|"
        r"FromBase64String|ToBase64String)\b",
        severity="medium",
        confidence=0.89,
        platform="generic",
        description="Combines credential terminology with Base64 processing.",
    ),
    CredentialPattern(
        "credential_encryption",
        "credential_decryption",
        r"\b(?:password|credential|secret|token|key)\b.{0,350}\b"
        r"(?:decrypt|decryptdata|unprotect|decryptstring|"
        r"CryptUnprotectData|DPAPI|AES|DES|RC4|RSA)\b",
        severity="high",
        confidence=0.91,
        platform="generic",
        description="Combines credential material with decryption functionality.",
    ),
    # PowerShell credential APIs.
    CredentialPattern(
        "powershell_credential_object",
        "authentication_material",
        r"\b(?:Get-Credential|PSCredential|System\.Management\.Automation\."
        r"PSCredential|NetworkCredential|CredentialCache)\b",
        severity="medium",
        confidence=0.95,
        platform="windows",
        description="References PowerShell/.NET credential objects.",
    ),
    CredentialPattern(
        "powershell_credential_property",
        "credential_access",
        r"\b(?:PSCredential|NetworkCredential)\b.{0,300}\b"
        r"(?:GetNetworkCredential|Password|UserName|SecurePassword)\b",
        severity="high",
        confidence=0.96,
        platform="windows",
        description="Accesses properties of PowerShell/.NET credential objects.",
    ),
    # Office/VBA credential context.
    CredentialPattern(
        "office_credential_access",
        "office_credentials",
        r"\b(?:Application\.UserName|Environ\([\"'](?:USERNAME|USER|"
        r"USERDOMAIN)[\"']\)|WScript\.Network\.(?:UserName|UserDomain))\b",
        severity="low",
        confidence=0.82,
        platform="windows",
        description="References user identity from an Office/script environment.",
    ),
    CredentialPattern(
        "office_password_terms",
        "office_credentials",
        r"\b(?:VBA|Visual Basic|Office|Excel|Word|Outlook)\b.{0,350}\b"
        r"(?:password|credential|secret|token)\b",
        severity="medium",
        confidence=0.76,
        platform="windows",
        description="Combines Office/VBA context with credential terminology.",
    ),
    # Credential exfiltration context.
    CredentialPattern(
        "credential_network_transfer",
        "credential_exfiltration",
        r"\b(?:password|credential|secret|token|api[_ -]?key|private key)\b"
        r".{0,500}\b(?:POST|PUT|upload|send|request|HTTP|HTTPS|"
        r"WinHttp|WinInet|curl|wget|Invoke-WebRequest|Invoke-RestMethod|"
        r"WebClient|XMLHTTP|fetch)\b",
        severity="high",
        confidence=0.90,
        platform="generic",
        description="Combines credential material with network-transfer behavior.",
    ),
    CredentialPattern(
        "credential_archive",
        "credential_collection",
        r"\b(?:password|credential|secret|token|key|\.kdbx|"
        r"credentials\.json)\b.{0,350}\b(?:zip|7z|rar|tar|gzip|compress|"
        r"archive|Compress-Archive)\b",
        severity="high",
        confidence=0.87,
        platform="generic",
        description="Combines credential artifacts with archiving behavior.",
    ),
    # Process discovery + credential targeting.
    CredentialPattern(
        "credential_process_targeting",
        "credential_dumping",
        r"\b(?:tasklist|Get-Process|wmic\s+process|ps(?:\.exe)?\s+-)\b"
        r".{0,300}\b(?:lsass|winlogon|vault|credential|browser|chrome|"
        r"firefox|edge)\b",
        severity="high",
        confidence=0.94,
        platform="generic",
        description="Combines process discovery with credential-related targeting.",
    ),
)


# ---------------------------------------------------------------------------
# Stable indicator names
# ---------------------------------------------------------------------------

STABLE_INDICATORS: Tuple[str, ...] = tuple(
    sorted({pattern.name for pattern in CREDENTIAL_PATTERNS})
)


# ---------------------------------------------------------------------------
# Input helpers
# ---------------------------------------------------------------------------


def _safe_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _bounded_text(
    value: Any,
    limit: int = MAX_FIELD_TEXT,
) -> str:
    if value is None:
        return ""

    if isinstance(value, bytes):
        return value[:limit].decode("utf-8", errors="replace")

    if isinstance(value, bytearray):
        return bytes(value[:limit]).decode(
            "utf-8",
            errors="replace",
        )

    if isinstance(value, memoryview):
        return value.tobytes()[:limit].decode(
            "utf-8",
            errors="replace",
        )

    if isinstance(value, str):
        return value[:limit]

    if isinstance(value, Path):
        return str(value)[:limit]

    if is_dataclass(value):
        try:
            return json.dumps(
                asdict(value),
                ensure_ascii=False,
                sort_keys=True,
                default=str,
            )[:limit]
        except Exception:
            pass

    if isinstance(value, Mapping):
        try:
            return json.dumps(
                value,
                ensure_ascii=False,
                sort_keys=True,
                default=str,
            )[:limit]
        except Exception:
            pass

    if isinstance(value, (list, tuple, set)):
        try:
            return json.dumps(
                list(value),
                ensure_ascii=False,
                sort_keys=False,
                default=str,
            )[:limit]
        except Exception:
            pass

    try:
        return str(value)[:limit]
    except Exception:
        return ""


def _read_path(path: Path) -> bytes:
    try:
        if not path.is_file():
            return b""

        size = path.stat().st_size

        if size < 0 or size > MAX_SOURCE_SIZE:
            return b""

        with path.open("rb") as handle:
            return handle.read(MAX_SOURCE_SIZE + 1)
    except (OSError, ValueError):
        return b""


def _input_to_bytes(source: Any) -> bytes:
    if isinstance(source, bytes):
        return source[: MAX_SOURCE_SIZE + 1]

    if isinstance(source, bytearray):
        return bytes(source[: MAX_SOURCE_SIZE + 1])

    if isinstance(source, memoryview):
        return source.tobytes()[: MAX_SOURCE_SIZE + 1]

    if isinstance(source, Path):
        return _read_path(source)

    if isinstance(source, str):
        try:
            candidate = Path(source)

            # Avoid interpreting arbitrary long attacker-controlled strings
            # as filesystem paths.
            if len(source) <= 4096 and candidate.is_file():
                return _read_path(candidate)
        except (OSError, ValueError):
            pass

        return source.encode(
            "utf-8",
            errors="replace",
        )[: MAX_SOURCE_SIZE + 1]

    return _bounded_text(
        source,
        MAX_SOURCE_SIZE + 1,
    ).encode(
        "utf-8",
        errors="replace",
    )


def _flatten_input(
    value: Any,
    *,
    prefix: str = "root",
    depth: int = 0,
    seen: Optional[Set[int]] = None,
) -> List[Tuple[str, str]]:
    """
    Flatten nested data into deterministic text fields.

    This prevents recursive or pathological structured objects from consuming
    unbounded resources.
    """
    if seen is None:
        seen = set()

    if depth > MAX_NESTING_DEPTH:
        return []

    if len(seen) > MAX_CREDENTIAL_RECORDS:
        return []

    if value is None:
        return []

    if isinstance(value, (str, bytes, bytearray, memoryview, Path)):
        text = _bounded_text(value)
        return [(prefix, text)] if text else []

    if isinstance(value, Mapping):
        object_id = id(value)

        if object_id in seen:
            return []

        seen.add(object_id)

        result: List[Tuple[str, str]] = []

        for index, (key, item) in enumerate(value.items()):
            if index >= MAX_CREDENTIAL_RECORDS:
                break

            key_text = re.sub(
                r"[^A-Za-z0-9_.-]+",
                "_",
                _bounded_text(key, 200),
            ).strip("_")

            child_prefix = f"{prefix}.{key_text}" if key_text else f"{prefix}.{index}"

            result.extend(
                _flatten_input(
                    item,
                    prefix=child_prefix,
                    depth=depth + 1,
                    seen=seen,
                )
            )

            if len(result) >= MAX_CREDENTIAL_RECORDS:
                break

        return result[:MAX_CREDENTIAL_RECORDS]

    if isinstance(value, (list, tuple, set)):
        object_id = id(value)

        if object_id in seen:
            return []

        seen.add(object_id)

        result = []

        for index, item in enumerate(value):
            if index >= MAX_CREDENTIAL_RECORDS:
                break

            result.extend(
                _flatten_input(
                    item,
                    prefix=f"{prefix}[{index}]",
                    depth=depth + 1,
                    seen=seen,
                )
            )

            if len(result) >= MAX_CREDENTIAL_RECORDS:
                break

        return result[:MAX_CREDENTIAL_RECORDS]

    object_id = id(value)

    if object_id in seen:
        return []

    seen.add(object_id)

    try:
        attributes = vars(value)
    except (TypeError, ValueError):
        attributes = None

    if isinstance(attributes, Mapping):
        return _flatten_input(
            attributes,
            prefix=prefix,
            depth=depth + 1,
            seen=seen,
        )

    text = _bounded_text(value)

    return [(prefix, text)] if text else []


def _normalize_source(
    source: Any,
) -> Tuple[str, int, str]:
    if isinstance(
        source,
        (str, bytes, bytearray, memoryview, Path),
    ):
        raw = _input_to_bytes(source)

        source_kind = "bytes"

        if isinstance(source, str):
            source_kind = "text_or_path"
        elif isinstance(source, Path):
            source_kind = "path"

        truncated = len(raw) > MAX_SOURCE_SIZE

        raw = raw[:MAX_SOURCE_SIZE]

        text = raw.decode(
            "utf-8",
            errors="replace",
        )

        if truncated:
            text = text[:MAX_TEXT_CHARS]

        return text, len(raw), source_kind

    fields = _flatten_input(source)

    if not fields:
        return "", 0, "structured"

    pieces: List[str] = []
    total = 0

    for name, value in fields:
        if not value:
            continue

        bounded = value[:MAX_FIELD_TEXT]

        piece = f"{name}: {bounded}"

        remaining = MAX_TEXT_CHARS - total

        if remaining <= 0:
            break

        piece = piece[:remaining]

        pieces.append(piece)
        total += len(piece) + 1

    text = "\n".join(pieces)

    raw = text.encode(
        "utf-8",
        errors="replace",
    )

    return (
        text[:MAX_TEXT_CHARS],
        min(len(raw), MAX_SOURCE_SIZE),
        "structured",
    )


# ---------------------------------------------------------------------------
# Text/context helpers
# ---------------------------------------------------------------------------


def _line_number(
    text: str,
    position: int,
) -> int:
    if position <= 0:
        return 1

    return (
        text.count(
            "\n",
            0,
            position,
        )
        + 1
    )


def _line_text(
    text: str,
    line_number: int,
) -> str:
    if line_number <= 0:
        return ""

    lines = text.splitlines()

    if line_number > len(lines):
        return ""

    return lines[line_number - 1][:MAX_SNIPPET_LENGTH]


def _normalize_indicator(value: str) -> str:
    return re.sub(
        r"\s+",
        " ",
        value.strip().lower(),
    )


def _normalize_platform(
    platform: str,
) -> str:
    value = platform.strip().lower()

    if value in {
        "win",
        "windows",
        "win32",
        "win64",
    }:
        return "windows"

    if value in {
        "linux",
        "unix",
        "gnu/linux",
    }:
        return "linux"

    if value in {
        "mac",
        "macos",
        "osx",
        "darwin",
    }:
        return "macos"

    return platform.strip().lower() or "generic"


def _infer_platform(
    text: str,
) -> str:
    lower = text.lower()

    scores = {
        "windows": 0,
        "linux": 0,
        "macos": 0,
    }

    windows_terms = (
        r"\bwindows\b",
        r"\\system32\\",
        r"\bhklm\b",
        r"\bhkcu\b",
        r"\blsass\b",
        r"\bwmic\b",
        r"\bpowershell\b",
        r"\bwscript\b",
        r"\bwin32_",
        r"\bntlm\b",
        r"\bkerberos\b",
        r"\bsam\b",
        r"\bdpapi\b",
    )

    linux_terms = (
        r"/proc/",
        r"/etc/",
        r"\blinux\b",
        r"\bssh\b",
        r"\bkubeconfig\b",
        r"\.ssh/",
        r"\.aws/",
    )

    macos_terms = (
        r"\bmacos\b",
        r"\bos x\b",
        r"\bdarwin\b",
        r"/users/",
        r"\bkeychain\b",
    )

    for pattern in windows_terms:
        if re.search(pattern, lower):
            scores["windows"] += 1

    for pattern in linux_terms:
        if re.search(pattern, lower):
            scores["linux"] += 1

    for pattern in macos_terms:
        if re.search(pattern, lower):
            scores["macos"] += 1

    platform, score = max(
        scores.items(),
        key=lambda item: item[1],
    )

    return platform if score else "generic"


def _infer_operation(
    text: str,
    match_start: int,
    default: str,
) -> str:
    start = max(
        0,
        match_start - 400,
    )

    end = min(
        len(text),
        match_start + 450,
    )

    context = text[start:end].lower()

    if re.search(
        r"\b(?:dump|dumping|extract|retrieve|"
        r"steal|harvest|collect|capture|read|"
        r"enumerate|query|list|export|copy)\b",
        context,
    ):
        return "collect"

    if re.search(
        r"\b(?:decrypt|decrypts|decrypting|" r"unprotect|unpack|decode)\b",
        context,
    ):
        return "decrypt"

    if re.search(
        r"\b(?:send|upload|post|put|exfiltrate|" r"transmit|forward|submit)\b",
        context,
    ):
        return "exfiltrate"

    if re.search(
        r"\b(?:validate|verify|authenticate|login|" r"logon|signin|sign-in)\b",
        context,
    ):
        return "validate"

    if re.search(
        r"\b(?:prompt|input|request|ask|enter|capture)\b",
        context,
    ):
        return "collect"

    return default


def _extract_location(
    text: str,
    match_start: int,
    match_end: int,
) -> Optional[str]:
    """
    Extract a nearby credential-artifact location.

    Locations are metadata only. They are never opened or resolved.
    """
    start = max(
        0,
        match_start - 350,
    )

    end = min(
        len(text),
        match_end + 600,
    )

    context = text[start:end]

    patterns = (
        # Windows hives.
        r"(?i)\b(?:HKLM|HKCU|HKCR|HKU|"
        r"HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT|"
        r"HKEY_USERS)\\[A-Za-z0-9_.\\/\- %]{1,300}",
        # Windows files.
        r"(?i)[A-Z]:\\[A-Za-z0-9_. %+\-\\]{1,300}",
        # Unix home/config locations.
        r"(?i)(?:~|/home/[A-Za-z0-9_.@+\-]+|/Users/[A-Za-z0-9_.@+\-]+)"
        r"(?:/[A-Za-z0-9_.@+\-=/]{1,300})?",
        # Common credential directories.
        r"(?i)/(?:etc|var|opt|root|tmp|run)/" r"[A-Za-z0-9_.@+\-=/]{1,300}",
        # Known credential artifacts.
        r"(?i)(?:\.aws/credentials|\.aws/config|\.ssh/"
        r"(?:id_rsa|id_dsa|id_ecdsa|id_ed25519|config|known_hosts)|"
        r"\.kube/config|\.docker/config\.json|\.git-credentials|"
        r"logins\.json|key4\.db|Login Data|Cookies|"
        r"credentials\.json|secrets\.json|\.env)",
    )

    for pattern in patterns:
        found = re.search(
            pattern,
            context,
        )

        if found:
            value = re.sub(
                r"\s+",
                " ",
                found.group(0).strip(),
            )

            return value[:300]

    return None


# ---------------------------------------------------------------------------
# Compile rules
# ---------------------------------------------------------------------------

_COMPILED_PATTERNS: Tuple[Tuple[CredentialPattern, re.Pattern[str]], ...] = tuple(
    (
        pattern,
        re.compile(
            pattern.regex,
            re.IGNORECASE | re.MULTILINE,
        ),
    )
    for pattern in CREDENTIAL_PATTERNS
)


# ---------------------------------------------------------------------------
# Evidence extraction
# ---------------------------------------------------------------------------


def extract_credential_evidence(
    text: str,
    *,
    source_name: str = "text",
    max_items: int = MAX_EVIDENCE_ITEMS,
) -> List[CredentialEvidence]:
    """Extract bounded static credential evidence."""
    if not text:
        return []

    bounded_text = text[:MAX_TEXT_CHARS]

    result: List[CredentialEvidence] = []

    for pattern, compiled in _COMPILED_PATTERNS:
        if len(result) >= max_items:
            break

        match_count = 0

        try:
            matches = compiled.finditer(bounded_text)
        except (re.error, ValueError):
            continue

        for match in matches:
            if match_count >= MAX_MATCHES_PER_RULE:
                break

            if len(result) >= max_items:
                break

            match_count += 1

            start = match.start()
            end = match.end()

            line_number = _line_number(
                bounded_text,
                start,
            )

            line = _line_text(
                bounded_text,
                line_number,
            )

            matched_text = re.sub(
                r"\s+",
                " ",
                match.group(0).strip(),
            )[:250]

            if not matched_text:
                matched_text = pattern.name

            context_start = max(
                0,
                start - 500,
            )

            context_end = min(
                len(bounded_text),
                end + 500,
            )

            local_context = bounded_text[context_start:context_end]

            platform = _normalize_platform(pattern.platform)

            if platform == "generic":
                platform = _infer_platform(local_context)

            operation = _infer_operation(
                bounded_text,
                start,
                pattern.operation,
            )

            location = _extract_location(
                bounded_text,
                start,
                end,
            )

            snippet = line or matched_text

            result.append(
                CredentialEvidence(
                    category=pattern.category,
                    indicator=pattern.name,
                    evidence=snippet[:MAX_SNIPPET_LENGTH],
                    source=source_name,
                    line_number=line_number,
                    operation=operation,
                    platform=platform,
                    location=location,
                    confidence=max(
                        0.0,
                        min(1.0, pattern.confidence),
                    ),
                    severity=pattern.severity,
                    pattern=pattern.name,
                )
            )

    return result[:max_items]


def _deduplicate_evidence(
    evidence: Sequence[CredentialEvidence],
) -> List[CredentialEvidence]:
    seen: Set[Tuple[Any, ...]] = set()
    result: List[CredentialEvidence] = []

    for item in evidence:
        key = (
            item.category,
            item.indicator,
            item.evidence,
            item.line_number,
            item.operation,
            item.platform,
            item.location,
        )

        if key in seen:
            continue

        seen.add(key)
        result.append(item)

        if len(result) >= MAX_EVIDENCE_ITEMS:
            break

    return result


def _records_from_evidence(
    evidence: Sequence[CredentialEvidence],
) -> List[CredentialRecord]:
    records: List[CredentialRecord] = []
    seen: Set[Tuple[Any, ...]] = set()

    for item in evidence:
        key = (
            item.category,
            item.indicator,
            item.operation,
            item.platform,
            item.location,
            item.line_number,
        )

        if key in seen:
            continue

        seen.add(key)

        records.append(
            CredentialRecord(
                behavior=item.indicator.replace(
                    "_",
                    " ",
                ),
                category=item.category,
                operation=item.operation,
                platform=item.platform,
                indicator=item.indicator,
                evidence=item.evidence,
                severity=item.severity,
                confidence=item.confidence,
                location=item.location,
                line_number=item.line_number,
            )
        )

        if len(records) >= MAX_CREDENTIAL_RECORDS:
            break

    return records


# ---------------------------------------------------------------------------
# Higher-level combinations
# ---------------------------------------------------------------------------

COMBINATION_DEFINITIONS: Tuple[Tuple[str, Tuple[str, ...], str], ...] = (
    (
        "windows_credential_access",
        (
            "credential_access",
            "credential_discovery",
        ),
        "The source contains Windows-oriented credential-access/discovery behavior.",
    ),
    (
        "credential_dumping",
        (
            "credential_dumping",
            "lsass",
        ),
        "The source combines credential-dumping behavior with LSASS targeting.",
    ),
    (
        "browser_credential_collection",
        (
            "browser_credentials",
            "browser_passwords",
        ),
        "The source references browser credential artifacts.",
    ),
    (
        "browser_session_collection",
        (
            "browser_cookies",
            "browser_credentials",
        ),
        "The source combines browser authentication/session artifacts.",
    ),
    (
        "credential_decryption",
        (
            "credential_decryption",
            "dpapi",
        ),
        "Credential material is associated with decryption or DPAPI behavior.",
    ),
    (
        "cloud_credential_access",
        (
            "cloud_credentials",
            "access_tokens",
        ),
        "The source combines cloud credential and token-related behavior.",
    ),
    (
        "private_key_access",
        (
            "private_keys",
            "ssh_keys",
        ),
        "The source references private/SSH authentication keys.",
    ),
    (
        "credential_collection",
        (
            "credential_collection",
            "password_collection",
        ),
        "The source contains behavior consistent with collecting password material.",
    ),
    (
        "credential_exfiltration",
        (
            "credential_exfiltration",
            "credential_access",
        ),
        "Credential-related material is combined with transfer/exfiltration behavior.",
    ),
    (
        "credential_archive_collection",
        (
            "credential_collection",
            "credential_storage",
        ),
        "Credential artifacts are associated with storage/archive handling.",
    ),
    (
        "authentication_material_access",
        (
            "authentication_material",
            "access_tokens",
        ),
        "The source accesses reusable authentication material.",
    ),
    (
        "privileged_credential_access",
        (
            "privilege_related_credentials",
            "credential_access",
        ),
        "Credential behavior occurs in a privilege-related context.",
    ),
)


def derive_combinations(
    records: Sequence[CredentialRecord],
    evidence: Sequence[CredentialEvidence],
    *,
    source_text: str = "",
) -> List[CredentialCombination]:
    categories = {record.category for record in records}

    combinations: List[CredentialCombination] = []

    for name, required, explanation in COMBINATION_DEFINITIONS:
        present = False

        if name == "windows_credential_access":
            present = (
                "lsass" in categories
                or "sam_database" in categories
                or "lsa_secrets" in categories
                or "credential_manager" in categories
                or "windows_vault" in categories
                or (
                    "credential_access" in categories
                    and any(record.platform == "windows" for record in records)
                )
            )

        elif name == "credential_dumping":
            present = "credential_dumping" in categories and (
                "lsass" in categories
                or "sam_database" in categories
                or "lsa_secrets" in categories
                or "security_accounts_manager" in categories
            )

        elif name == "browser_credential_collection":
            present = "browser_passwords" in categories or (
                "browser_credentials" in categories
                and (
                    "credential_access" in categories or "password_access" in categories
                )
            )

        elif name == "browser_session_collection":
            present = "browser_cookies" in categories and (
                "browser_credentials" in categories or "browser_passwords" in categories
            )

        elif name == "credential_decryption":
            present = "credential_decryption" in categories and (
                "dpapi" in categories
                or "browser_passwords" in categories
                or "credential_access" in categories
            )

        elif name == "cloud_credential_access":
            present = bool(
                categories.intersection(
                    {
                        "aws_credentials",
                        "azure_credentials",
                        "gcp_credentials",
                        "kubernetes_credentials",
                        "docker_credentials",
                    }
                )
            ) and bool(
                categories.intersection(
                    {
                        "access_tokens",
                        "refresh_tokens",
                        "oauth_tokens",
                        "cloud_identity",
                        "authentication_material",
                    }
                )
            )

        elif name == "private_key_access":
            present = (
                "private_keys" in categories
                or "ssh_keys" in categories
                or "certificate_credentials" in categories
            )

        elif name == "credential_collection":
            present = (
                "credential_collection" in categories
                or "password_collection" in categories
                or "input_capture" in categories
                or "keylogging" in categories
            )

        elif name == "credential_exfiltration":
            present = "credential_exfiltration" in categories and bool(
                categories.intersection(
                    {
                        "credential_access",
                        "credential_collection",
                        "browser_credentials",
                        "password_access",
                        "api_keys",
                        "access_tokens",
                        "private_keys",
                    }
                )
            )

        elif name == "credential_archive_collection":
            present = "credential_collection" in categories and bool(
                re.search(
                    r"\b(?:zip|7z|rar|tar|gzip|archive|" r"Compress-Archive)\b",
                    source_text,
                    re.IGNORECASE,
                )
            )

        elif name == "authentication_material_access":
            present = "authentication_material" in categories and bool(
                categories.intersection(
                    {
                        "access_tokens",
                        "refresh_tokens",
                        "session_tokens",
                        "oauth_tokens",
                        "jwt_tokens",
                        "kerberos",
                        "ntlm",
                    }
                )
            )

        elif name == "privileged_credential_access":
            present = "privilege_related_credentials" in categories and (
                "credential_access" in categories or "credential_dumping" in categories
            )

        else:
            present = all(category in categories for category in required)

        combinations.append(
            CredentialCombination(
                name=name,
                present=present,
                required_categories=required,
                explanation=explanation,
            )
        )

    # Strong cross-category signal: a source containing several independent
    # credential-access mechanisms.
    access_categories = {
        "lsass",
        "sam_database",
        "lsa_secrets",
        "credential_manager",
        "browser_passwords",
        "browser_cookies",
        "password_managers",
        "ssh_keys",
        "aws_credentials",
        "azure_credentials",
        "gcp_credentials",
        "kubernetes_credentials",
        "docker_credentials",
        "git_credentials",
        "database_credentials",
        "api_keys",
        "access_tokens",
    }

    matched_access = categories.intersection(access_categories)

    if len(matched_access) >= 3:
        combinations.append(
            CredentialCombination(
                name="multi_source_credential_collection",
                present=True,
                required_categories=tuple(sorted(matched_access)),
                explanation=(
                    "Multiple independent credential stores or authentication "
                    "material sources are referenced."
                ),
            )
        )

    return combinations


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------

_CATEGORY_WEIGHTS: Dict[str, float] = {
    "credential_access": 1.0,
    "credential_discovery": 1.0,
    "credential_collection": 1.5,
    "credential_storage": 0.5,
    "credential_query": 0.8,
    "credential_dumping": 2.8,
    "password_access": 1.2,
    "password_collection": 2.0,
    "username_discovery": 0.3,
    "account_discovery": 0.4,
    "account_manipulation": 1.0,
    "authentication": 0.4,
    "authentication_material": 1.4,
    "authentication_bypass": 2.5,
    "browser_credentials": 1.3,
    "browser_passwords": 2.0,
    "browser_cookies": 1.7,
    "web_credentials": 1.3,
    "password_managers": 1.3,
    "email_credentials": 1.2,
    "cloud_credentials": 1.7,
    "api_keys": 1.5,
    "access_tokens": 1.8,
    "refresh_tokens": 1.8,
    "session_tokens": 1.7,
    "oauth_tokens": 1.7,
    "jwt_tokens": 1.7,
    "kerberos": 1.8,
    "ntlm": 1.8,
    "lsass": 2.7,
    "sam_database": 2.5,
    "security_accounts_manager": 2.5,
    "lsa_secrets": 2.8,
    "credential_manager": 1.8,
    "windows_vault": 2.0,
    "dpapi": 1.9,
    "cached_credentials": 2.0,
    "credential_files": 1.0,
    "ssh_credentials": 1.0,
    "ssh_keys": 1.8,
    "private_keys": 2.0,
    "certificate_credentials": 1.7,
    "gpg_credentials": 1.3,
    "aws_credentials": 2.0,
    "azure_credentials": 2.0,
    "gcp_credentials": 2.0,
    "kubernetes_credentials": 2.0,
    "docker_credentials": 1.8,
    "git_credentials": 1.7,
    "database_credentials": 1.7,
    "rdp_credentials": 1.2,
    "vpn_credentials": 1.1,
    "wifi_credentials": 1.5,
    "office_credentials": 0.6,
    "cloud_identity": 0.8,
    "environment_secrets": 1.0,
    "config_secrets": 1.4,
    "secret_files": 1.0,
    "clipboard_credentials": 1.4,
    "input_capture": 1.7,
    "keylogging": 2.2,
    "credential_phishing": 2.0,
    "credential_exfiltration": 2.6,
    "credential_decryption": 2.4,
    "credential_encoding": 0.8,
    "credential_obfuscation": 1.2,
    "credential_validation": 0.5,
    "privilege_related_credentials": 1.8,
}


def _signal_score(
    records: Sequence[CredentialRecord],
    combinations: Sequence[CredentialCombination],
) -> float:
    score = 0.0

    for record in records:
        weight = _CATEGORY_WEIGHTS.get(
            record.category,
            0.5,
        )

        severity_multiplier = {
            "info": 0.25,
            "low": 0.50,
            "medium": 1.00,
            "high": 1.50,
            "critical": 2.00,
        }.get(
            record.severity,
            1.0,
        )

        confidence = max(
            0.0,
            min(1.0, record.confidence),
        )

        score += weight * severity_multiplier * confidence

    for combination in combinations:
        if not combination.present:
            continue

        if combination.name in {
            "credential_dumping",
            "credential_exfiltration",
            "multi_source_credential_collection",
            "credential_decryption",
        }:
            score += 2.5
        else:
            score += 1.0

    return round(
        min(score, 100.0),
        6,
    )


# ---------------------------------------------------------------------------
# Feature vectors
# ---------------------------------------------------------------------------


def _count_by(
    records: Sequence[CredentialRecord],
    attribute: str,
) -> Counter:
    return Counter(
        getattr(record, attribute)
        for record in records
        if getattr(record, attribute, None)
    )


def build_feature_vector(
    records: Sequence[CredentialRecord],
    evidence: Sequence[CredentialEvidence],
    combinations: Sequence[CredentialCombination],
    *,
    source_size: int = 0,
) -> Dict[str, float]:
    """Build stable scalar credential-behavior features."""
    vector: Dict[str, float] = {}

    category_counts = _count_by(
        records,
        "category",
    )

    indicator_counts = _count_by(
        records,
        "indicator",
    )

    platform_counts = _count_by(
        records,
        "platform",
    )

    operation_counts = _count_by(
        records,
        "operation",
    )

    severity_counts = _count_by(
        records,
        "severity",
    )

    locations = {record.location for record in records if record.location}

    present_combinations = {item.name for item in combinations if item.present}

    # Global counts.
    vector["source_size"] = float(max(0, source_size))

    vector["record_count"] = float(len(records))

    vector["evidence_count"] = float(len(evidence))

    vector["indicator_count"] = float(len(indicator_counts))

    vector["category_count"] = float(len(category_counts))

    vector["location_count"] = float(len(locations))

    vector["platform_count"] = float(len(platform_counts))

    vector["combination_count"] = float(len(present_combinations))

    # Severity.
    vector["info_count"] = float(severity_counts.get("info", 0))

    vector["low_count"] = float(severity_counts.get("low", 0))

    vector["medium_count"] = float(severity_counts.get("medium", 0))

    vector["high_count"] = float(severity_counts.get("high", 0))

    vector["critical_count"] = float(severity_counts.get("critical", 0))

    # Operations.
    vector["access_count"] = float(operation_counts.get("access", 0))

    vector["collect_count"] = float(operation_counts.get("collect", 0))

    vector["decrypt_count"] = float(operation_counts.get("decrypt", 0))

    vector["exfiltrate_count"] = float(operation_counts.get("exfiltrate", 0))

    vector["validate_count"] = float(operation_counts.get("validate", 0))

    # Platform.
    vector["windows_count"] = float(platform_counts.get("windows", 0))

    vector["linux_count"] = float(platform_counts.get("linux", 0))

    vector["macos_count"] = float(platform_counts.get("macos", 0))

    vector["generic_platform_count"] = float(platform_counts.get("generic", 0))

    # High-value credential categories.
    dump_categories = {
        "credential_dumping",
        "lsass",
        "sam_database",
        "lsa_secrets",
        "cached_credentials",
        "security_accounts_manager",
    }

    browser_categories = {
        "browser_credentials",
        "browser_passwords",
        "browser_cookies",
    }

    cloud_categories = {
        "aws_credentials",
        "azure_credentials",
        "gcp_credentials",
        "kubernetes_credentials",
        "docker_credentials",
        "cloud_credentials",
    }

    token_categories = {
        "access_tokens",
        "refresh_tokens",
        "session_tokens",
        "oauth_tokens",
        "jwt_tokens",
        "authentication_material",
    }

    key_categories = {
        "ssh_keys",
        "private_keys",
        "certificate_credentials",
        "gpg_credentials",
    }

    vector["credential_dump_signal_count"] = float(
        sum(
            count
            for category, count in category_counts.items()
            if category in dump_categories
        )
    )

    vector["browser_credential_signal_count"] = float(
        sum(
            count
            for category, count in category_counts.items()
            if category in browser_categories
        )
    )

    vector["cloud_credential_signal_count"] = float(
        sum(
            count
            for category, count in category_counts.items()
            if category in cloud_categories
        )
    )

    vector["token_signal_count"] = float(
        sum(
            count
            for category, count in category_counts.items()
            if category in token_categories
        )
    )

    vector["key_material_signal_count"] = float(
        sum(
            count
            for category, count in category_counts.items()
            if category in key_categories
        )
    )

    vector["collection_signal_count"] = float(
        sum(
            count
            for category, count in category_counts.items()
            if category
            in {
                "credential_collection",
                "password_collection",
                "credential_exfiltration",
                "input_capture",
                "keylogging",
            }
        )
    )

    # Stable category features.
    for category in CREDENTIAL_CATEGORIES:
        count = category_counts.get(
            category,
            0,
        )

        vector[f"category_{category}_present"] = 1.0 if count else 0.0

        vector[f"category_{category}_count"] = float(count)

    # Stable indicator features.
    for indicator in STABLE_INDICATORS:
        count = indicator_counts.get(
            indicator,
            0,
        )

        vector[f"indicator_{indicator}_present"] = 1.0 if count else 0.0

        vector[f"indicator_{indicator}_count"] = float(count)

    # Stable combination features.
    combination_names = {name for name, _, _ in COMBINATION_DEFINITIONS}

    combination_names.add("multi_source_credential_collection")

    for name in sorted(combination_names):
        vector[f"combination_{name}_present"] = (
            1.0 if name in present_combinations else 0.0
        )

    vector["credential_signal_score"] = _signal_score(
        records,
        combinations,
    )

    return vector


def feature_names() -> List[str]:
    """Return deterministic feature names."""
    names = {
        "source_size",
        "record_count",
        "evidence_count",
        "indicator_count",
        "category_count",
        "location_count",
        "platform_count",
        "combination_count",
        "info_count",
        "low_count",
        "medium_count",
        "high_count",
        "critical_count",
        "access_count",
        "collect_count",
        "decrypt_count",
        "exfiltrate_count",
        "validate_count",
        "windows_count",
        "linux_count",
        "macos_count",
        "generic_platform_count",
        "credential_dump_signal_count",
        "browser_credential_signal_count",
        "cloud_credential_signal_count",
        "token_signal_count",
        "key_material_signal_count",
        "collection_signal_count",
        "credential_signal_score",
    }

    for category in CREDENTIAL_CATEGORIES:
        names.add(f"category_{category}_present")
        names.add(f"category_{category}_count")

    for indicator in STABLE_INDICATORS:
        names.add(f"indicator_{indicator}_present")
        names.add(f"indicator_{indicator}_count")

    for name, _, _ in COMBINATION_DEFINITIONS:
        names.add(f"combination_{name}_present")

    names.add("combination_multi_source_credential_collection_present")

    return sorted(names)


def credentials_feature_names() -> List[str]:
    return feature_names()


def build_feature_schema() -> Dict[str, Any]:
    names = feature_names()

    return {
        "version": 1,
        "module": "extraction.behavior.credentials",
        "feature_count": len(names),
        "features": [
            {
                "name": name,
                "type": "float",
            }
            for name in names
        ],
    }


def vectorize_features(
    feature_vector: Mapping[str, Any],
    names: Optional[Sequence[str]] = None,
) -> List[float]:
    selected = list(names) if names is not None else feature_names()

    result: List[float] = []

    for name in selected:
        value = feature_vector.get(
            name,
            0.0,
        )

        if isinstance(value, bool):
            result.append(1.0 if value else 0.0)
            continue

        try:
            number = float(value)
        except (TypeError, ValueError):
            number = 0.0

        if not math.isfinite(number):
            number = 0.0

        result.append(number)

    return result


def extract_feature_vector(
    analysis: CredentialAnalysis,
    names: Optional[Sequence[str]] = None,
) -> List[float]:
    return vectorize_features(
        analysis.feature_vector,
        names=names,
    )


def extract_credentials_feature_vector(
    analysis: CredentialAnalysis,
    names: Optional[Sequence[str]] = None,
) -> List[float]:
    return extract_feature_vector(
        analysis,
        names=names,
    )


# ---------------------------------------------------------------------------
# Main analysis
# ---------------------------------------------------------------------------


def analyze_credentials(
    source: Any,
    *,
    source_name: str = "text",
    max_evidence: int = MAX_EVIDENCE_ITEMS,
) -> CredentialAnalysis:
    """
    Analyze source material for credential-related behavior.

    No credential store, operating-system service, browser database, or
    authentication subsystem is accessed.
    """
    text, source_size, source_kind = _normalize_source(source)

    if len(text) > MAX_TEXT_CHARS:
        text = text[:MAX_TEXT_CHARS]

    source_hash = _safe_sha256(
        text.encode(
            "utf-8",
            errors="replace",
        )
    )

    evidence = extract_credential_evidence(
        text,
        source_name=source_name,
        max_items=max_evidence,
    )

    evidence = _deduplicate_evidence(evidence)

    records = _records_from_evidence(evidence)

    indicators = sorted({record.indicator for record in records if record.indicator})[
        :MAX_INDICATORS
    ]

    categories = sorted({record.category for record in records if record.category})

    locations = sorted({record.location for record in records if record.location})[
        :MAX_LOCATIONS
    ]

    platforms = sorted({record.platform for record in records if record.platform})

    combinations = derive_combinations(
        records,
        evidence,
        source_text=text,
    )

    feature_vector = build_feature_vector(
        records,
        evidence,
        combinations,
        source_size=source_size,
    )

    high_count = sum(
        1
        for record in records
        if SEVERITY_ORDER.get(
            record.severity,
            0,
        )
        >= 3
    )

    critical_count = sum(
        1
        for record in records
        if SEVERITY_ORDER.get(
            record.severity,
            0,
        )
        >= 4
    )

    dump_count = sum(
        1
        for record in records
        if record.category
        in {
            "credential_dumping",
            "lsass",
            "sam_database",
            "lsa_secrets",
            "cached_credentials",
            "security_accounts_manager",
        }
    )

    exfiltration_count = sum(
        1 for record in records if record.category == "credential_exfiltration"
    )

    metadata: Dict[str, Any] = {
        "module": "extraction.behavior.credentials",
        "version": 1,
        "static_only": True,
        "source_kind": source_kind,
        "source_name": source_name,
        "truncated": (source_size >= MAX_SOURCE_SIZE or len(text) >= MAX_TEXT_CHARS),
        "pattern_count": len(CREDENTIAL_PATTERNS),
        "feature_count": len(feature_names()),
        "high_severity_count": high_count,
        "critical_severity_count": critical_count,
        "credential_dump_count": dump_count,
        "credential_exfiltration_count": exfiltration_count,
        "signal_score": feature_vector.get(
            "credential_signal_score",
            0.0,
        ),
    }

    return CredentialAnalysis(
        source_hash=source_hash,
        source_size=source_size,
        records=records,
        evidence=evidence,
        indicators=indicators,
        categories=categories,
        locations=locations,
        platforms=platforms,
        combinations=combinations,
        feature_vector=feature_vector,
        metadata=metadata,
    )


def analyze(
    source: Any,
    *,
    source_name: str = "text",
    max_evidence: int = MAX_EVIDENCE_ITEMS,
) -> CredentialAnalysis:
    return analyze_credentials(
        source,
        source_name=source_name,
        max_evidence=max_evidence,
    )


def parse_credentials(
    source: Any,
    *,
    source_name: str = "text",
    max_evidence: int = MAX_EVIDENCE_ITEMS,
) -> CredentialAnalysis:
    return analyze_credentials(
        source,
        source_name=source_name,
        max_evidence=max_evidence,
    )


def parse_credential_behavior(
    source: Any,
    *,
    source_name: str = "text",
    max_evidence: int = MAX_EVIDENCE_ITEMS,
) -> CredentialAnalysis:
    return analyze_credentials(
        source,
        source_name=source_name,
        max_evidence=max_evidence,
    )


def extract_credentials_features(
    source: Any,
    *,
    source_name: str = "text",
    max_evidence: int = MAX_EVIDENCE_ITEMS,
) -> Dict[str, Any]:
    return analysis_to_dict(
        analyze_credentials(
            source,
            source_name=source_name,
            max_evidence=max_evidence,
        )
    )


def extract_credential_records(
    source: Any,
    *,
    source_name: str = "text",
    max_evidence: int = MAX_EVIDENCE_ITEMS,
) -> List[CredentialRecord]:
    return analyze_credentials(
        source,
        source_name=source_name,
        max_evidence=max_evidence,
    ).records


# ---------------------------------------------------------------------------
# Query helpers
# ---------------------------------------------------------------------------


def has_indicator(
    analysis: CredentialAnalysis,
    indicator: str,
) -> bool:
    target = _normalize_indicator(indicator)

    return any(_normalize_indicator(item) == target for item in analysis.indicators)


def indicator_count(
    analysis: CredentialAnalysis,
    indicator: str,
) -> int:
    target = _normalize_indicator(indicator)

    return sum(
        1
        for record in analysis.records
        if _normalize_indicator(record.indicator) == target
    )


def has_category(
    analysis: CredentialAnalysis,
    category: str,
) -> bool:
    target = _normalize_indicator(category)

    return any(_normalize_indicator(item) == target for item in analysis.categories)


def category_count(
    analysis: CredentialAnalysis,
    category: str,
) -> int:
    target = _normalize_indicator(category)

    return sum(
        1
        for record in analysis.records
        if _normalize_indicator(record.category) == target
    )


def evidence_by_category(
    analysis: CredentialAnalysis,
    category: str,
) -> List[CredentialEvidence]:
    target = _normalize_indicator(category)

    return [
        item
        for item in analysis.evidence
        if _normalize_indicator(item.category) == target
    ]


def evidence_by_indicator(
    analysis: CredentialAnalysis,
    indicator: str,
) -> List[CredentialEvidence]:
    target = _normalize_indicator(indicator)

    return [
        item
        for item in analysis.evidence
        if _normalize_indicator(item.indicator) == target
    ]


def high_risk_evidence(
    analysis: CredentialAnalysis,
) -> List[CredentialEvidence]:
    return [
        item
        for item in analysis.evidence
        if SEVERITY_ORDER.get(
            item.severity,
            0,
        )
        >= 3
    ]


def present_combinations(
    analysis: CredentialAnalysis,
) -> List[CredentialCombination]:
    return [combination for combination in analysis.combinations if combination.present]


def highest_severity(
    analysis: CredentialAnalysis,
) -> str:
    if not analysis.records:
        return "info"

    return max(
        (record.severity for record in analysis.records),
        key=lambda value: SEVERITY_ORDER.get(
            value,
            0,
        ),
    )


def has_credential_dumping(
    analysis: CredentialAnalysis,
) -> bool:
    return bool(
        analysis.feature_vector.get(
            "credential_dump_signal_count",
            0.0,
        )
    )


def has_browser_credential_access(
    analysis: CredentialAnalysis,
) -> bool:
    return bool(
        analysis.feature_vector.get(
            "browser_credential_signal_count",
            0.0,
        )
    )


def has_cloud_credential_access(
    analysis: CredentialAnalysis,
) -> bool:
    return bool(
        analysis.feature_vector.get(
            "cloud_credential_signal_count",
            0.0,
        )
    )


# ---------------------------------------------------------------------------
# Summary / serialization
# ---------------------------------------------------------------------------


def summarize_credentials(
    analysis: CredentialAnalysis,
) -> Dict[str, Any]:
    category_counts = Counter(record.category for record in analysis.records)

    indicator_counts = Counter(record.indicator for record in analysis.records)

    operation_counts = Counter(record.operation for record in analysis.records)

    platform_counts = Counter(record.platform for record in analysis.records)

    severity_counts = Counter(record.severity for record in analysis.records)

    return {
        "source_hash": analysis.source_hash,
        "source_size": analysis.source_size,
        "record_count": len(analysis.records),
        "evidence_count": len(analysis.evidence),
        "category_count": len(analysis.categories),
        "indicator_count": len(analysis.indicators),
        "location_count": len(analysis.locations),
        "platform_count": len(analysis.platforms),
        "highest_severity": highest_severity(analysis),
        "signal_score": analysis.feature_vector.get(
            "credential_signal_score",
            0.0,
        ),
        "credential_dumping": has_credential_dumping(analysis),
        "browser_credential_access": has_browser_credential_access(analysis),
        "cloud_credential_access": has_cloud_credential_access(analysis),
        "categories": dict(sorted(category_counts.items())),
        "indicators": dict(sorted(indicator_counts.items())),
        "operations": dict(sorted(operation_counts.items())),
        "platforms": dict(sorted(platform_counts.items())),
        "severities": dict(sorted(severity_counts.items())),
        "present_combinations": [
            combination.name for combination in present_combinations(analysis)
        ],
    }


def _json_safe(
    value: Any,
) -> Any:
    if is_dataclass(value):
        return {key: _json_safe(item) for key, item in asdict(value).items()}

    if isinstance(value, Mapping):
        return {str(key): _json_safe(item) for key, item in value.items()}

    if isinstance(value, (list, tuple, set)):
        return [_json_safe(item) for item in value]

    if isinstance(value, Path):
        return str(value)

    if isinstance(value, float):
        if not math.isfinite(value):
            return 0.0

    return value


def analysis_to_dict(
    analysis: CredentialAnalysis,
) -> Dict[str, Any]:
    """Convert analysis to a JSON-compatible dictionary."""
    return {
        "source_hash": analysis.source_hash,
        "source_size": analysis.source_size,
        "records": [_json_safe(record) for record in analysis.records],
        "evidence": [_json_safe(item) for item in analysis.evidence],
        "indicators": list(analysis.indicators),
        "categories": list(analysis.categories),
        "locations": list(analysis.locations),
        "platforms": list(analysis.platforms),
        "combinations": [_json_safe(item) for item in analysis.combinations],
        "feature_vector": {
            key: float(value) for key, value in analysis.feature_vector.items()
        },
        "metadata": _json_safe(analysis.metadata),
        "summary": summarize_credentials(analysis),
    }


# ---------------------------------------------------------------------------
# Iterators
# ---------------------------------------------------------------------------


def iter_evidence(
    analysis: CredentialAnalysis,
) -> Iterator[CredentialEvidence]:
    yield from analysis.evidence


def iter_high_risk_evidence(
    analysis: CredentialAnalysis,
) -> Iterator[CredentialEvidence]:
    for item in analysis.evidence:
        if (
            SEVERITY_ORDER.get(
                item.severity,
                0,
            )
            >= 3
        ):
            yield item


def iter_credential_records(
    analysis: CredentialAnalysis,
) -> Iterator[CredentialRecord]:
    yield from analysis.records


def iter_records(
    analysis: CredentialAnalysis,
) -> Iterator[CredentialRecord]:
    yield from analysis.records


def iter_combinations(
    analysis: CredentialAnalysis,
) -> Iterator[CredentialCombination]:
    yield from analysis.combinations


def iter_analyses(
    sources: Iterable[Any],
    *,
    source_name: str = "text",
) -> Iterator[CredentialAnalysis]:
    for source in sources:
        yield analyze_credentials(
            source,
            source_name=source_name,
        )


# ---------------------------------------------------------------------------
# Compatibility aliases
# ---------------------------------------------------------------------------

parse = parse_credentials
extract = extract_credentials_features
credentials_feature_schema = build_feature_schema


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

__all__ = [
    "MAX_SOURCE_SIZE",
    "MAX_TEXT_CHARS",
    "MAX_FIELD_TEXT",
    "MAX_EVIDENCE_ITEMS",
    "MAX_MATCHES_PER_RULE",
    "MAX_NESTING_DEPTH",
    "MAX_CREDENTIAL_RECORDS",
    "MAX_LOCATIONS",
    "CREDENTIAL_CATEGORIES",
    "SEVERITY_ORDER",
    "CredentialPattern",
    "CredentialEvidence",
    "CredentialRecord",
    "CredentialCombination",
    "CredentialAnalysis",
    "CREDENTIAL_PATTERNS",
    "STABLE_INDICATORS",
    "COMBINATION_DEFINITIONS",
    "extract_credential_evidence",
    "derive_combinations",
    "build_feature_vector",
    "feature_names",
    "credentials_feature_names",
    "build_feature_schema",
    "vectorize_features",
    "extract_feature_vector",
    "extract_credentials_feature_vector",
    "analyze_credentials",
    "analyze",
    "parse_credentials",
    "parse_credential_behavior",
    "extract_credentials_features",
    "extract_credential_records",
    "has_indicator",
    "indicator_count",
    "has_category",
    "category_count",
    "evidence_by_category",
    "evidence_by_indicator",
    "high_risk_evidence",
    "present_combinations",
    "highest_severity",
    "has_credential_dumping",
    "has_browser_credential_access",
    "has_cloud_credential_access",
    "summarize_credentials",
    "analysis_to_dict",
    "iter_evidence",
    "iter_high_risk_evidence",
    "iter_credential_records",
    "iter_records",
    "iter_combinations",
    "iter_analyses",
    "parse",
    "extract",
    "credentials_feature_schema",
]
