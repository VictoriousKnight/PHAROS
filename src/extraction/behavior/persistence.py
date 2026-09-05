"""
Static persistence-behavior extraction for Pharos CDR.

This module identifies persistence mechanisms represented in documents,
scripts, VBA, command lines, logs, extracted strings, and nested analysis
objects. It never creates, modifies, deletes, registers, schedules, or
executes persistence mechanisms on the host.

The module recognizes common Windows persistence mechanisms including:

- Registry Run / RunOnce keys
- Startup folders
- Winlogon / Userinit / Shell persistence
- IFEO debugger persistence
- AppInit_DLLs
- Active Setup
- COM hijacking
- Shell extensions and file associations
- Services
- Scheduled tasks
- WMI permanent event subscriptions
- Windows startup/task folders
- Office add-ins and trusted locations
- Browser/helper integrations
- DLL search/order hijacking indicators
- DLL side-loading indicators
- Login scripts / Group Policy scripts
- PowerShell profiles
- Windows services and service configuration
- Boot/logon helper mechanisms
- Cron / systemd / init persistence on Unix-like systems
- SSH authorized_keys
- Shell startup files
- macOS LaunchAgents / LaunchDaemons
- macOS Login Items
- Configuration/profile persistence

The extractor is heuristic. A persistence indicator is not inherently
malicious: legitimate installers, enterprise management software, security
products, and system configuration tools routinely create persistence.

Intended flow:

    source
      -> static persistence extraction
      -> behavior/capability features
      -> ML / policy / CDR decision
      -> report

Security properties
-------------------
- No registry access.
- No service creation/modification.
- No task scheduling.
- No WMI access.
- No filesystem modification.
- No command execution.
- No process creation.
- No shell invocation.
- No persistence mechanism is installed or tested dynamically.
"""

from __future__ import annotations

import hashlib
import json
import math
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

MAX_PERSISTENCE_RECORDS = 10_000
MAX_PATHS = 10_000
MAX_REGISTRY_KEYS = 10_000
MAX_COMMAND_LINES = 20_000


# ---------------------------------------------------------------------------
# Taxonomy
# ---------------------------------------------------------------------------

PERSISTENCE_CATEGORIES: Tuple[str, ...] = (
    "persistence",
    "registry_persistence",
    "run_key",
    "run_once",
    "startup_folder",
    "winlogon",
    "userinit",
    "shell_persistence",
    "active_setup",
    "appinit",
    "ifeo",
    "com_hijacking",
    "shell_extension",
    "file_association",
    "office_persistence",
    "office_addin",
    "office_startup",
    "trusted_location",
    "service_persistence",
    "scheduled_task",
    "scheduled_job",
    "wmi_persistence",
    "wmi_event_subscription",
    "startup_script",
    "logon_script",
    "group_policy",
    "powershell_profile",
    "dll_hijacking",
    "dll_search_order",
    "dll_side_loading",
    "image_hijacking",
    "browser_persistence",
    "helper_object",
    "credential_persistence",
    "ssh_persistence",
    "shell_startup",
    "cron_persistence",
    "systemd_persistence",
    "init_persistence",
    "macos_launch_agent",
    "macos_launch_daemon",
    "macos_login_item",
    "login_item",
    "boot_persistence",
    "configuration_persistence",
    "persistence_command",
    "persistence_api",
    "persistence_script",
    "persistence_evasion",
    "persistence_execution",
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
class PersistencePattern:
    """One static persistence-detection rule."""

    name: str
    category: str
    pattern: str
    severity: str = "medium"
    confidence: float = 0.8
    mechanism: Optional[str] = None
    operation: Optional[str] = None
    description: str = ""


@dataclass
class PersistenceEvidence:
    """One bounded piece of evidence supporting a persistence finding."""

    category: str
    indicator: str
    evidence: str
    source: str = "text"
    line_number: Optional[int] = None
    mechanism: Optional[str] = None
    operation: Optional[str] = None
    path: Optional[str] = None
    registry_key: Optional[str] = None
    value_name: Optional[str] = None
    command: Optional[str] = None
    confidence: float = 0.8
    severity: str = "medium"


@dataclass
class PersistenceRecord:
    """Structured persistence artifact."""

    kind: str
    value: str
    normalized: str
    mechanism: Optional[str] = None
    category: Optional[str] = None
    source: str = "text"
    operation: Optional[str] = None
    path: Optional[str] = None
    registry_key: Optional[str] = None
    value_name: Optional[str] = None
    command: Optional[str] = None
    indicators: List[str] = field(default_factory=list)
    categories: List[str] = field(default_factory=list)


@dataclass(frozen=True)
class PersistenceCombination:
    """A higher-confidence combination of persistence signals."""

    name: str
    present: bool
    required_categories: Tuple[str, ...] = ()
    required_indicators: Tuple[str, ...] = ()
    explanation: str = ""


@dataclass
class PersistenceAnalysis:
    """Complete static persistence analysis."""

    source_hash: str
    source_size: int

    records: List[PersistenceRecord] = field(default_factory=list)
    evidence: List[PersistenceEvidence] = field(default_factory=list)

    paths: List[str] = field(default_factory=list)
    registry_keys: List[str] = field(default_factory=list)
    mechanisms: List[str] = field(default_factory=list)

    indicators: List[str] = field(default_factory=list)
    categories: List[str] = field(default_factory=list)
    combinations: List[PersistenceCombination] = field(default_factory=list)

    feature_vector: Dict[str, Union[int, float]] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Vocabulary
# ---------------------------------------------------------------------------

REGISTRY_HIVES: Tuple[str, ...] = (
    "HKLM",
    "HKCU",
    "HKCR",
    "HKU",
    "HKCC",
    "HKEY_LOCAL_MACHINE",
    "HKEY_CURRENT_USER",
    "HKEY_CLASSES_ROOT",
    "HKEY_USERS",
    "HKEY_CURRENT_CONFIG",
)


RUN_KEY_TERMS: Tuple[str, ...] = (
    r"\software\microsoft\windows\currentversion\run",
    r"\software\microsoft\windows\currentversion\runonce",
    r"\software\microsoft\windows\currentversion\runservices",
    r"\software\microsoft\windows\currentversion\runservicesonce",
    r"\software\microsoft\windows\currentversion\explorer\startupapproved",
)


WINLOGON_TERMS: Tuple[str, ...] = (
    r"\software\microsoft\windows nt\currentversion\winlogon",
    r"\software\microsoft\windows nt\currentversion\winlogon\shell",
    r"\software\microsoft\windows nt\currentversion\winlogon\userinit",
)


IFEO_TERMS: Tuple[str, ...] = (
    r"\software\microsoft\windows nt\currentversion\image file execution options",
    r"\software\wow6432node\microsoft\windows nt\currentversion\image file execution options",
)


APPINIT_TERMS: Tuple[str, ...] = (
    r"\software\microsoft\windows nt\currentversion\windows\appinit_dlls",
    r"\software\wow6432node\microsoft\windows nt\currentversion\windows\appinit_dlls",
)


ACTIVE_SETUP_TERMS: Tuple[str, ...] = (
    r"\software\microsoft\active setup\installed components",
    r"\software\wow6432node\microsoft\active setup\installed components",
)


SERVICE_TERMS: Tuple[str, ...] = (
    r"\system\currentcontrolset\services",
    r"\system\controlset001\services",
    r"\system\controlset002\services",
)


COM_HIJACK_TERMS: Tuple[str, ...] = (
    r"\software\classes\clsid",
    r"\software\classes\wow6432node\clsid",
    r"\software\classes\inprocserver32",
    r"\software\classes\localserver32",
    r"\software\classes\inprochandler32",
    r"\software\classes\shell\open\command",
)


OFFICE_TERMS: Tuple[str, ...] = (
    r"\software\microsoft\office",
    r"\software\microsoft\office\*\addins",
    r"\software\microsoft\office\*\common\security\trusted locations",
    r"\software\microsoft\office\*\common\officefilecache",
)


POWERSHELL_PROFILE_PATHS: Tuple[str, ...] = (
    r"\documents\windowspowershell\profile.ps1",
    r"\documents\powershell\profile.ps1",
    r"\system32\windowspowershell\v1.0\profile.ps1",
)


UNIX_STARTUP_FILES: Tuple[str, ...] = (
    ".bashrc",
    ".bash_profile",
    ".profile",
    ".zshrc",
    ".zprofile",
    ".kshrc",
    ".cshrc",
    "/etc/profile",
    "/etc/bash.bashrc",
    "/etc/rc.local",
    "/etc/init.d/",
)


MACOS_LAUNCH_PATHS: Tuple[str, ...] = (
    "/library/launchagents/",
    "/library/launchdaemons/",
    "/system/library/launchagents/",
    "/system/library/launchdaemons/",
    "/users/",
)


# ---------------------------------------------------------------------------
# Regex helpers
# ---------------------------------------------------------------------------

REGISTRY_KEY_RE = re.compile(r"""(?ix)
    (?:
        \b(?:HKLM|HKCU|HKCR|HKU|HKCC)\b
        |
        \bHKEY_(?:LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS|CURRENT_CONFIG)\b
    )
    [\\/:][^\r\n"']{1,2048}
    """)

WINDOWS_PATH_RE = re.compile(r"""(?ix)
    (?:
        [A-Z]:\\
        |
        %SystemRoot%\\
        |
        %WinDir%\\
        |
        %AppData%\\
        |
        %LocalAppData%\\
        |
        %ProgramData%\\
        |
        %ProgramFiles%\\
        |
        %Temp%\\
        |
        %UserProfile%\\
    )
    [^\r\n"'<>|]{1,2048}
    """)

UNIX_PATH_RE = re.compile(r"""(?x)
    (?:
        /etc/[A-Za-z0-9._+@%=-]+(?:/[A-Za-z0-9._+@%=-]+)*
        |
        /var/[A-Za-z0-9._+@%=-]+(?:/[A-Za-z0-9._+@%=-]+)*
        |
        /usr/[A-Za-z0-9._+@%=-]+(?:/[A-Za-z0-9._+@%=-]+)*
        |
        /opt/[A-Za-z0-9._+@%=-]+(?:/[A-Za-z0-9._+@%=-]+)*
        |
        /home/[A-Za-z0-9._+@%=-]+(?:/[A-Za-z0-9._+@%=-]+)*
        |
        /Users/[A-Za-z0-9._+@%=-]+(?:/[A-Za-z0-9._+@%=-]+)*
        |
        /Library/[A-Za-z0-9._+@%=-]+(?:/[A-Za-z0-9._+@%=-]+)*
    )
    """)

REG_VALUE_ASSIGNMENT_RE = re.compile(r"""(?ix)
    (?:
        /v\s+(?P<reg_value1>"[^"]{1,512}"|'[^']{1,512}'|\S{1,512})
        |
        /ve\s+
        |
        -name\s+(?P<reg_value2>"[^"]{1,512}"|'[^']{1,512}'|\S{1,512})
        |
        -propertytype\s+
    )
    """)

TASK_NAME_RE = re.compile(r"""(?ix)
    (?:
        /tn\s+(?P<name1>"[^"]{1,512}"|'[^']{1,512}'|\S{1,512})
        |
        -taskname\s+(?P<name2>"[^"]{1,512}"|'[^']{1,512}'|\S{1,512})
    )
    """)

SERVICE_NAME_RE = re.compile(r"""(?ix)
    \b(?:sc(?:\.exe)?|New-Service|Set-Service|Get-Service)
    \s+(?:(?:create|config|start|stop|delete)\s+)?
    (?P<name>[A-Za-z0-9_.@$:-]{1,256})
    """)

WMI_NAMESPACE_RE = re.compile(r"""(?ix)
    (?:
        root\\subscription
        |
        root\\cimv2
        |
        __EventFilter
        |
        __EventConsumer
        |
        __FilterToConsumerBinding
    )
    """)


# ---------------------------------------------------------------------------
# Static persistence rules
# ---------------------------------------------------------------------------

PERSISTENCE_RULES: Tuple[PersistencePattern, ...] = (
    # Registry
    PersistencePattern(
        "run_key",
        "run_key",
        r"(?i)\b(?:HK(?:LM|CU)|HKEY_(?:LOCAL_MACHINE|CURRENT_USER))"
        r"[\\/:][^\r\n]{0,1024}\\(?:Run|RunOnce|RunServices|RunServicesOnce)\b",
        "high",
        0.99,
        "registry_run_key",
        "write",
        "Windows Registry Run/RunOnce persistence location.",
    ),
    PersistencePattern(
        "startup_approved",
        "run_key",
        r"(?i)\\(?:StartupApproved)\\",
        "high",
        0.94,
        "registry_run_key",
        "write",
        "StartupApproved registry persistence-related location.",
    ),
    PersistencePattern(
        "winlogon",
        "winlogon",
        r"(?i)\\(?:Winlogon)\\(?:Shell|Userinit|Notify|GPExtensions)\b",
        "high",
        0.98,
        "winlogon",
        "write",
        "Winlogon persistence location.",
    ),
    PersistencePattern(
        "userinit",
        "userinit",
        r"(?i)\b(?:Userinit|UserInitMprLogonScript)\b",
        "high",
        0.96,
        "userinit",
        "write",
        "Userinit/logon-script persistence indicator.",
    ),
    PersistencePattern(
        "shell_persistence",
        "shell_persistence",
        r"(?i)\\Winlogon\\[^\\\r\n]{0,256}\\Shell\b|\bWinlogon\b[^\r\n]{0,300}\bShell\b",
        "high",
        0.95,
        "winlogon_shell",
        "write",
        "Windows shell replacement or modification.",
    ),
    PersistencePattern(
        "ifeo",
        "ifeo",
        r"(?i)\\Image\s+File\s+Execution\s+Options\\[^\r\n\\]{1,256}\\(?:Debugger|GlobalFlag|SilentProcessExit)\b",
        "high",
        0.98,
        "ifeo",
        "write",
        "Image File Execution Options persistence/hijacking.",
    ),
    PersistencePattern(
        "appinit_dlls",
        "appinit",
        r"(?i)\bAppInit_DLLs\b|\bLoadAppInit_DLLs\b",
        "high",
        0.98,
        "appinit",
        "write",
        "AppInit DLL loading persistence.",
    ),
    PersistencePattern(
        "active_setup",
        "active_setup",
        r"(?i)\b(?:Active\s+Setup|Installed\s+Components)\b[^\r\n]{0,500}\b(?:StubPath|Version)\b",
        "high",
        0.96,
        "active_setup",
        "write",
        "Active Setup per-user initialization persistence.",
    ),
    PersistencePattern(
        "services_registry",
        "service_persistence",
        r"(?i)\\System\\(?:CurrentControlSet|ControlSet\d{3})\\Services\\[^\r\n\\]{1,256}",
        "high",
        0.97,
        "service",
        "write",
        "Windows service configuration registry location.",
    ),
    PersistencePattern(
        "com_hijacking",
        "com_hijacking",
        r"(?i)\\(?:InprocServer32|InprocHandler32|LocalServer32|TreatAs|ProgID)\b",
        "high",
        0.94,
        "com_hijacking",
        "write",
        "COM registration/hijacking location.",
    ),
    PersistencePattern(
        "clsid_hijacking",
        "com_hijacking",
        r"(?i)\\(?:CLSID|Interface|TypeLib)\\\{[0-9A-Fa-f-]{8,64}\}",
        "high",
        0.95,
        "com_hijacking",
        "write",
        "COM class/interface registration location.",
    ),
    PersistencePattern(
        "shell_open_command",
        "file_association",
        r"(?i)\\(?:shell)\\(?:open|openas|command)\b",
        "medium",
        0.92,
        "file_association",
        "write",
        "File association or shell command registration.",
    ),
    PersistencePattern(
        "url_protocol",
        "file_association",
        r"(?i)\\(?:URL\s+Protocol)\b",
        "medium",
        0.91,
        "url_protocol",
        "write",
        "Custom URL protocol registration.",
    ),
    PersistencePattern(
        "office_addin",
        "office_addin",
        r"(?i)\b(?:Office|Word|Excel|PowerPoint|Outlook|Access)\b"
        r"[^\r\n]{0,500}\\(?:Addins?|Add-ins?)\\",
        "high",
        0.92,
        "office_addin",
        "write",
        "Office add-in persistence location.",
    ),
    PersistencePattern(
        "office_startup",
        "office_startup",
        r"(?i)\b(?:XLSTART|STARTUP|Word\\Startup|Excel\\XLSTART)\b",
        "high",
        0.92,
        "office_startup",
        "write",
        "Office startup-directory persistence.",
    ),
    PersistencePattern(
        "trusted_location",
        "trusted_location",
        r"(?i)\b(?:Trusted\s+Locations?|TrustedLocation)\b",
        "medium",
        0.90,
        "trusted_location",
        "write",
        "Office trusted-location configuration.",
    ),
    # Windows task/service mechanisms
    PersistencePattern(
        "schtasks_create",
        "scheduled_task",
        r"(?i)\bschtasks(?:\.exe)?\s+/create\b",
        "high",
        0.99,
        "scheduled_task",
        "create",
        "Scheduled task creation.",
    ),
    PersistencePattern(
        "schtasks_change",
        "scheduled_task",
        r"(?i)\bschtasks(?:\.exe)?\s+/(?:change|run)\b",
        "medium",
        0.95,
        "scheduled_task",
        "modify",
        "Scheduled task modification/execution.",
    ),
    PersistencePattern(
        "powershell_scheduled_task",
        "scheduled_task",
        r"(?i)\b(?:Register-ScheduledTask|New-ScheduledTask|Set-ScheduledTask)\b",
        "high",
        0.98,
        "scheduled_task",
        "create",
        "PowerShell scheduled-task management.",
    ),
    PersistencePattern(
        "at_command",
        "scheduled_job",
        r"(?i)(?:^|[;&|`\s])at(?:\.exe)?\s+\d{1,2}:\d{2}\b",
        "high",
        0.93,
        "scheduled_job",
        "create",
        "Legacy Windows AT scheduled job.",
    ),
    PersistencePattern(
        "service_create",
        "service_persistence",
        r"(?i)\bsc(?:\.exe)?\s+(?:create|config)\b",
        "high",
        0.99,
        "service",
        "create",
        "Windows service creation/configuration.",
    ),
    PersistencePattern(
        "powershell_service",
        "service_persistence",
        r"(?i)\b(?:New-Service|Set-Service)\b",
        "high",
        0.98,
        "service",
        "create",
        "PowerShell service creation/configuration.",
    ),
    PersistencePattern(
        "wmic_service_create",
        "service_persistence",
        r"(?i)\bwmic(?:\.exe)?\b[^\r\n]{0,500}\b(?:create|call\s+create)\b[^\r\n]{0,500}\bservice\b",
        "high",
        0.96,
        "service",
        "create",
        "WMI-based service creation.",
    ),
    # WMI persistence
    PersistencePattern(
        "wmi_event_filter",
        "wmi_event_subscription",
        r"(?i)\b__EventFilter\b|\bEventFilter\b",
        "high",
        0.96,
        "wmi_event_subscription",
        "create",
        "WMI event filter.",
    ),
    PersistencePattern(
        "wmi_event_consumer",
        "wmi_event_subscription",
        r"(?i)\b(?:__EventConsumer|CommandLineEventConsumer|ActiveScriptEventConsumer|NTEventLogEventConsumer)\b",
        "high",
        0.98,
        "wmi_event_subscription",
        "create",
        "WMI permanent event consumer.",
    ),
    PersistencePattern(
        "wmi_filter_binding",
        "wmi_event_subscription",
        r"(?i)\b__FilterToConsumerBinding\b",
        "critical",
        0.99,
        "wmi_event_subscription",
        "create",
        "WMI permanent event subscription binding.",
    ),
    PersistencePattern(
        "wmi_subscription_namespace",
        "wmi_persistence",
        WMI_NAMESPACE_RE.pattern,
        "high",
        0.94,
        "wmi_event_subscription",
        "create",
        "WMI subscription namespace/object.",
    ),
    # Startup/logon
    PersistencePattern(
        "startup_folder",
        "startup_folder",
        r"(?i)\b(?:Startup|Start\s+Menu\\Programs\\Startup)\b",
        "high",
        0.95,
        "startup_folder",
        "write",
        "Windows Startup folder reference.",
    ),
    PersistencePattern(
        "startup_folder_path",
        "startup_folder",
        r"(?i)(?:%APPDATA%|%USERPROFILE%|%PROGRAMDATA%)[^\r\n]{0,500}\\(?:Microsoft\\)?Windows\\Start\s+Menu\\Programs\\Startup\b",
        "high",
        0.99,
        "startup_folder",
        "write",
        "Windows Startup folder path.",
    ),
    PersistencePattern(
        "startup_script",
        "startup_script",
        r"(?i)\b(?:startup\s+script|startup\.cmd|startup\.bat|startup\.ps1)\b",
        "medium",
        0.92,
        "startup_script",
        "write",
        "Startup script reference.",
    ),
    PersistencePattern(
        "logon_script",
        "logon_script",
        r"(?i)\b(?:logon\s+script|logon\s+scriptpath|UserInitMprLogonScript|login\s+script)\b",
        "high",
        0.96,
        "logon_script",
        "write",
        "Logon/login script persistence.",
    ),
    PersistencePattern(
        "group_policy_script",
        "group_policy",
        r"(?i)\b(?:Group\s+Policy|GPO|UserInitMprLogonScript|Scripts\\Logon|Scripts\\Startup)\b",
        "medium",
        0.91,
        "group_policy",
        "write",
        "Group Policy script persistence.",
    ),
    # PowerShell
    PersistencePattern(
        "powershell_profile",
        "powershell_profile",
        r"(?i)\b(?:\$PROFILE|Microsoft\.PowerShell_profile\.ps1|profile\.ps1)\b",
        "high",
        0.97,
        "powershell_profile",
        "write",
        "PowerShell profile persistence.",
    ),
    PersistencePattern(
        "powershell_profile_path",
        "powershell_profile",
        r"(?i)(?:WindowsPowerShell|PowerShell)\\(?:Microsoft\.PowerShell_profile|profile)\.ps1\b",
        "high",
        0.98,
        "powershell_profile",
        "write",
        "PowerShell profile path.",
    ),
    # DLL / image hijacking
    PersistencePattern(
        "dll_search_order",
        "dll_search_order",
        r"(?i)\b(?:DLL\s+search\s+order|search\s+order\s+hijacking|SafeDllSearchMode)\b",
        "high",
        0.93,
        "dll_search_order",
        "hijack",
        "DLL search-order hijacking indicator.",
    ),
    PersistencePattern(
        "dll_side_loading",
        "dll_side_loading",
        r"(?i)\b(?:DLL\s+side[-\s]?loading|side[-\s]?load(?:ed|ing)?\s+DLL)\b",
        "high",
        0.94,
        "dll_side_loading",
        "hijack",
        "DLL side-loading indicator.",
    ),
    PersistencePattern(
        "dll_hijacking",
        "dll_hijacking",
        r"(?i)\b(?:DLL\s+hijack(?:ing)?|DLL\s+preloading|phantom\s+DLL)\b",
        "high",
        0.95,
        "dll_hijacking",
        "hijack",
        "DLL hijacking/preloading indicator.",
    ),
    PersistencePattern(
        "image_hijacking",
        "image_hijacking",
        r"(?i)\b(?:Image\s+File\s+Execution\s+Options|IFEO|SilentProcessExit)\b",
        "high",
        0.97,
        "image_hijacking",
        "hijack",
        "Executable image hijacking configuration.",
    ),
    # Unix-like persistence
    PersistencePattern(
        "cron_persistence",
        "cron_persistence",
        r"(?i)\b(?:crontab|cron\.d|cron\.daily|cron\.hourly|cron\.weekly|cron\.monthly)\b",
        "high",
        0.97,
        "cron",
        "write",
        "Cron-based persistence.",
    ),
    PersistencePattern(
        "systemd_persistence",
        "systemd_persistence",
        r"(?i)\b(?:systemctl\s+(?:enable|start|preset)|\.service\b|/etc/systemd/system/)\b",
        "high",
        0.97,
        "systemd",
        "write",
        "systemd service persistence.",
    ),
    PersistencePattern(
        "init_persistence",
        "init_persistence",
        r"(?i)\b(?:/etc/init\.d/|update-rc\.d|rc\.local|chkconfig)\b",
        "high",
        0.96,
        "init",
        "write",
        "Unix init-script persistence.",
    ),
    PersistencePattern(
        "shell_startup",
        "shell_startup",
        r"(?i)(?:^|[\s\"'])~/(?:\.bashrc|\.bash_profile|\.profile|\.zshrc|\.zprofile|\.kshrc)\b|"
        r"(?:/home/[^/\s]+|/root)/\.(?:bashrc|bash_profile|profile|zshrc|zprofile)\b",
        "medium",
        0.95,
        "shell_startup",
        "write",
        "Unix shell startup-file persistence.",
    ),
    PersistencePattern(
        "authorized_keys",
        "ssh_persistence",
        r"(?i)(?:\.ssh[\\/])?authorized_keys\b",
        "high",
        0.97,
        "ssh_authorized_keys",
        "write",
        "SSH authorized_keys persistence/access.",
    ),
    # macOS
    PersistencePattern(
        "launch_agent",
        "macos_launch_agent",
        r"(?i)\b(?:LaunchAgents|~/Library/LaunchAgents|/Library/LaunchAgents)\b",
        "high",
        0.98,
        "launch_agent",
        "write",
        "macOS LaunchAgent persistence.",
    ),
    PersistencePattern(
        "launch_daemon",
        "macos_launch_daemon",
        r"(?i)\b(?:LaunchDaemons|/Library/LaunchDaemons|/System/Library/LaunchDaemons)\b",
        "high",
        0.98,
        "launch_daemon",
        "write",
        "macOS LaunchDaemon persistence.",
    ),
    PersistencePattern(
        "macos_login_item",
        "macos_login_item",
        r"(?i)\b(?:login\s+item|LoginItems|SMLoginItem|osascript.*login item)\b",
        "high",
        0.95,
        "login_item",
        "write",
        "macOS login-item persistence.",
    ),
    # Generic persistence APIs/commands
    PersistencePattern(
        "registry_persistence_api",
        "persistence_api",
        r"(?i)\b(?:RegSetValueEx|RegCreateKeyEx|RegOpenKeyEx|SHSetValue|Set-ItemProperty|New-ItemProperty)\b",
        "medium",
        0.95,
        "registry",
        "write",
        "Registry persistence-related API/cmdlet.",
    ),
    PersistencePattern(
        "service_api",
        "persistence_api",
        r"(?i)\b(?:CreateService(?:A|W)?|OpenSCManager(?:A|W)?|ChangeServiceConfig(?:A|W)?)\b",
        "high",
        0.98,
        "service",
        "create",
        "Windows Service Control Manager API.",
    ),
    PersistencePattern(
        "task_scheduler_api",
        "persistence_api",
        r"(?i)\b(?:ITaskService|ITaskDefinition|TaskScheduler|Schedule\.Service|RegisterTaskDefinition)\b",
        "high",
        0.96,
        "scheduled_task",
        "create",
        "Task Scheduler API/interface.",
    ),
    PersistencePattern(
        "wmi_persistence_api",
        "persistence_api",
        r"(?i)\b(?:SWbemObject|SWbemServices|ManagementObject|ManagementClass)\b[^\r\n]{0,300}\b(?:__EventFilter|__EventConsumer|__FilterToConsumerBinding)\b",
        "high",
        0.95,
        "wmi_event_subscription",
        "create",
        "WMI permanent-event persistence API usage.",
    ),
)


# ---------------------------------------------------------------------------
# Generic persistence terms
# ---------------------------------------------------------------------------

GENERIC_PERSISTENCE_TERMS: Tuple[PersistencePattern, ...] = (
    PersistencePattern(
        "persistence_term",
        "persistence",
        r"(?i)\b(?:persistence|persist(?:ed|ence)?|startup|autorun|autostart|logon|login)\b",
        "low",
        0.72,
        "generic",
        "reference",
        "Generic persistence terminology.",
    ),
    PersistencePattern(
        "boot_persistence",
        "boot_persistence",
        r"(?i)\b(?:boot\s+execute|boot\s+start|boot\s+driver|early\s+launch|ELAM)\b",
        "high",
        0.92,
        "boot",
        "write",
        "Boot-time persistence indicator.",
    ),
    PersistencePattern(
        "helper_object",
        "helper_object",
        r"(?i)\b(?:Browser\s+Helper\s+Object|BHO|Helper\s+Object)\b",
        "high",
        0.93,
        "browser_helper",
        "write",
        "Browser helper-object persistence.",
    ),
)


# ---------------------------------------------------------------------------
# Utility functions
# ---------------------------------------------------------------------------


def _safe_text(value: Any, limit: int = MAX_FIELD_TEXT) -> str:
    if value is None:
        return ""

    if isinstance(value, bytes):
        return value[:limit].decode("utf-8", errors="replace")

    if isinstance(value, str):
        return value[:limit]

    if isinstance(value, Path):
        return str(value)[:limit]

    if isinstance(value, (int, float, bool)):
        return str(value)[:limit]

    if isinstance(value, Mapping):
        try:
            return json.dumps(
                value,
                ensure_ascii=False,
                default=str,
            )[:limit]
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


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def _clip(value: str, limit: int = MAX_FIELD_TEXT) -> str:
    value = value or ""
    if len(value) <= limit:
        return value
    return value[:limit] + "…"


def _normalize_whitespace(value: str) -> str:
    return re.sub(r"\s+", " ", value).strip()


def _safe_confidence(value: Any) -> float:
    try:
        return max(0.0, min(1.0, float(value)))
    except (TypeError, ValueError):
        return 0.0


def _append_unique(
    values: List[Any],
    value: Any,
    limit: int,
) -> None:
    if len(values) >= limit:
        return

    if value not in values:
        values.append(value)


def _line_number(text: str, position: int) -> int:
    return text.count("\n", 0, max(position, 0)) + 1


def _iter_lines_bounded(text: str) -> Iterator[Tuple[int, str]]:
    for number, line in enumerate(
        text.splitlines(),
        start=1,
    ):
        if number > MAX_COMMAND_LINES:
            break
        yield number, line[:MAX_FIELD_TEXT]


def _read_source(source: Any) -> Tuple[str, int, str]:
    """
    Read static input only.

    A string that names an existing local file is read as a local analysis
    input. URLs are never fetched.
    """
    if isinstance(source, (bytes, bytearray, memoryview)):
        raw = bytes(source)
        bounded = raw[:MAX_SOURCE_SIZE]

        return (
            bounded.decode("utf-8", errors="replace"),
            len(raw),
            hashlib.sha256(bounded).hexdigest(),
        )

    if isinstance(source, Path):
        try:
            size = source.stat().st_size

            with source.open("rb") as handle:
                raw = handle.read(MAX_SOURCE_SIZE)

            return (
                raw.decode("utf-8", errors="replace"),
                int(size),
                hashlib.sha256(raw).hexdigest(),
            )
        except (OSError, ValueError):
            text = str(source)
            return text, len(text), _sha256_text(text)

    if isinstance(source, str):
        if len(source) <= 4096:
            try:
                path = Path(source)

                if path.exists() and path.is_file():
                    size = path.stat().st_size

                    with path.open("rb") as handle:
                        raw = handle.read(MAX_SOURCE_SIZE)

                    return (
                        raw.decode("utf-8", errors="replace"),
                        int(size),
                        hashlib.sha256(raw).hexdigest(),
                    )
            except (OSError, ValueError, PermissionError):
                pass

        text = source[:MAX_TEXT_CHARS]

        return (
            text,
            len(source),
            _sha256_text(text),
        )

    if isinstance(source, Mapping):
        parts: List[str] = []
        total = 0

        def append(value: Any) -> None:
            nonlocal total

            if total >= MAX_TEXT_CHARS:
                return

            item = _safe_text(value)

            if not item:
                return

            remaining = MAX_TEXT_CHARS - total
            item = item[:remaining]

            parts.append(item)
            total += len(item) + 1

        _flatten_mapping(source, append)

        text = "\n".join(parts)[:MAX_TEXT_CHARS]

        return (
            text,
            len(text),
            _sha256_text(text),
        )

    if isinstance(source, (list, tuple, set, frozenset)):
        parts: List[str] = []
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

        return (
            text,
            len(text),
            _sha256_text(text),
        )

    text = _safe_text(source, MAX_TEXT_CHARS)

    return (
        text,
        len(text),
        _sha256_text(text),
    )


def _flatten_mapping(
    value: Any,
    append: Any,
    depth: int = 0,
) -> None:
    if depth > MAX_NESTING_DEPTH:
        return

    if isinstance(value, Mapping):
        for key, item in value.items():
            append(key)

            if depth < MAX_NESTING_DEPTH:
                _flatten_mapping(
                    item,
                    append,
                    depth + 1,
                )

        return

    if isinstance(value, (list, tuple, set, frozenset)):
        for item in value:
            if depth < MAX_NESTING_DEPTH:
                _flatten_mapping(
                    item,
                    append,
                    depth + 1,
                )
            else:
                append(item)

        return

    append(value)


def _dedupe_case_insensitive(
    values: Iterable[str],
    limit: int,
) -> List[str]:
    result: List[str] = []
    seen: Set[str] = set()

    for value in values:
        normalized = value.strip().lower()

        if not normalized or normalized in seen:
            continue

        seen.add(normalized)
        result.append(value.strip())

        if len(result) >= limit:
            break

    return result


# ---------------------------------------------------------------------------
# Registry/path normalization
# ---------------------------------------------------------------------------


def normalize_registry_key(value: str) -> str:
    """
    Normalize a registry path without querying the registry.
    """
    result = _safe_text(value).strip()

    result = re.sub(
        r"(?i)^computer\\",
        "",
        result,
    )

    result = re.sub(
        r"(?i)^registry::",
        "",
        result,
    )

    result = re.sub(
        r"(?i)^microsoft\.powershell\.core\\registry::",
        "",
        result,
    )

    result = result.replace("/", "\\")

    result = re.sub(
        r"\\+",
        "\\",
        result,
    )

    result = result.strip(" \t\r\n\"'")

    aliases = {
        "hkey_local_machine": "HKLM",
        "hkey_current_user": "HKCU",
        "hkey_classes_root": "HKCR",
        "hkey_users": "HKU",
        "hkey_current_config": "HKCC",
    }

    lowered = result.lower()

    for full_name, alias in aliases.items():
        if lowered == full_name:
            return alias

        prefix = full_name + "\\"

        if lowered.startswith(prefix):
            suffix = result[len(full_name) + 1 :]
            return alias + "\\" + suffix

    return result


def is_registry_key(value: str) -> bool:
    normalized = normalize_registry_key(value)

    return bool(
        re.match(
            r"(?i)^(?:HKLM|HKCU|HKCR|HKU|HKCC)\\",
            normalized,
        )
    )


def registry_hive(value: str) -> Optional[str]:
    normalized = normalize_registry_key(value)

    match = re.match(
        r"(?i)^(HKLM|HKCU|HKCR|HKU|HKCC)(?:\\|$)",
        normalized,
    )

    if not match:
        return None

    return match.group(1).upper()


def _registry_mechanism(key: str) -> Optional[str]:
    lowered = normalize_registry_key(key).lower()

    if "\\runonce" in lowered:
        return "registry_run_once"

    if "\\run" in lowered and (lowered.endswith("\\run") or "\\run\\" in lowered):
        return "registry_run_key"

    if "\\startupapproved" in lowered:
        return "startup_approved"

    if "\\winlogon" in lowered:
        return "winlogon"

    if "image file execution options" in lowered:
        return "ifeo"

    if "appinit_dlls" in lowered:
        return "appinit"

    if "active setup" in lowered:
        return "active_setup"

    if "\\services\\" in lowered:
        return "service"

    if any(
        term in lowered
        for term in (
            "\\inprocserver32",
            "\\inprochandler32",
            "\\localserver32",
            "\\clsid\\",
        )
    ):
        return "com_hijacking"

    if "\\shell\\open\\command" in lowered:
        return "file_association"

    if "office" in lowered and (
        "\\addins" in lowered or "trusted locations" in lowered
    ):
        return "office"

    return None


# ---------------------------------------------------------------------------
# Registry artifact extraction
# ---------------------------------------------------------------------------


def extract_registry_keys(
    text: str,
    evidence: Optional[List[PersistenceEvidence]] = None,
) -> List[PersistenceRecord]:
    records: List[PersistenceRecord] = []
    seen: Set[str] = set()

    for match in REGISTRY_KEY_RE.finditer(text):
        if len(records) >= MAX_REGISTRY_KEYS:
            break

        raw = match.group(0)
        normalized = normalize_registry_key(raw)

        if not normalized:
            continue

        dedupe_key = normalized.lower()

        if dedupe_key in seen:
            continue

        seen.add(dedupe_key)

        mechanism = _registry_mechanism(normalized)

        categories = ["persistence"] if mechanism else []

        if mechanism == "registry_run_key":
            categories.append("run_key")
        elif mechanism == "registry_run_once":
            categories.append("run_once")
        elif mechanism == "winlogon":
            categories.append("winlogon")
        elif mechanism == "ifeo":
            categories.append("ifeo")
        elif mechanism == "appinit":
            categories.append("appinit")
        elif mechanism == "active_setup":
            categories.append("active_setup")
        elif mechanism == "service":
            categories.append("service_persistence")
        elif mechanism == "com_hijacking":
            categories.append("com_hijacking")
        elif mechanism == "file_association":
            categories.append("file_association")
        elif mechanism == "office":
            categories.append("office_persistence")

        record = PersistenceRecord(
            kind="registry_key",
            value=raw,
            normalized=normalized,
            mechanism=mechanism,
            category=categories[1] if len(categories) > 1 else "persistence",
            source="registry",
            registry_key=normalized,
            categories=sorted(set(categories)),
        )

        records.append(record)

        if evidence is not None and len(evidence) < MAX_EVIDENCE_ITEMS:
            severity = "low"

            if mechanism in {
                "registry_run_key",
                "registry_run_once",
                "winlogon",
                "ifeo",
                "appinit",
                "active_setup",
                "service",
                "com_hijacking",
            }:
                severity = "high"

            evidence.append(
                PersistenceEvidence(
                    category=record.category or "persistence",
                    indicator=(mechanism if mechanism else "registry_key_reference"),
                    evidence=_clip(raw),
                    source="registry",
                    line_number=_line_number(text, match.start()),
                    mechanism=mechanism,
                    operation="reference",
                    registry_key=normalized,
                    confidence=0.96 if mechanism else 0.88,
                    severity=severity,
                )
            )

    return records


def extract_paths(
    text: str,
    evidence: Optional[List[PersistenceEvidence]] = None,
) -> List[PersistenceRecord]:
    records: List[PersistenceRecord] = []
    seen: Set[str] = set()

    patterns = (
        WINDOWS_PATH_RE,
        UNIX_PATH_RE,
    )

    for pattern in patterns:
        for match in pattern.finditer(text):
            if len(records) >= MAX_PATHS:
                return records

            raw = match.group(0).rstrip(".,;")
            normalized = raw.lower()

            if not raw or normalized in seen:
                continue

            seen.add(normalized)

            mechanism: Optional[str] = None
            category = "persistence"
            categories: List[str] = []

            lowered = normalized.replace("\\", "/")

            if "start menu/programs/startup" in lowered or lowered.endswith("/startup"):
                mechanism = "startup_folder"
                category = "startup_folder"
                categories.append("startup_folder")

            elif any(
                term.lower().replace("\\", "/") in lowered
                for term in UNIX_STARTUP_FILES
            ):
                mechanism = "shell_startup"
                category = "shell_startup"
                categories.append("shell_startup")

            elif "/etc/systemd/system/" in lowered:
                mechanism = "systemd"
                category = "systemd_persistence"
                categories.append("systemd_persistence")

            elif "/etc/init.d/" in lowered:
                mechanism = "init"
                category = "init_persistence"
                categories.append("init_persistence")

            elif "/etc/cron" in lowered or "/var/spool/cron" in lowered:
                mechanism = "cron"
                category = "cron_persistence"
                categories.append("cron_persistence")

            elif "/library/launchagents/" in lowered or "/launchagents/" in lowered:
                mechanism = "launch_agent"
                category = "macos_launch_agent"
                categories.append("macos_launch_agent")

            elif "/library/launchdaemons/" in lowered or "/launchdaemons/" in lowered:
                mechanism = "launch_daemon"
                category = "macos_launch_daemon"
                categories.append("macos_launch_daemon")

            elif ".ssh/authorized_keys" in lowered:
                mechanism = "ssh_authorized_keys"
                category = "ssh_persistence"
                categories.append("ssh_persistence")

            elif "windowspowershell" in lowered and "profile.ps1" in lowered:
                mechanism = "powershell_profile"
                category = "powershell_profile"
                categories.append("powershell_profile")

            elif "powershell" in lowered and "profile.ps1" in lowered:
                mechanism = "powershell_profile"
                category = "powershell_profile"
                categories.append("powershell_profile")

            else:
                continue

            categories.append("persistence")

            record = PersistenceRecord(
                kind="path",
                value=raw,
                normalized=normalized,
                mechanism=mechanism,
                category=category,
                source="path",
                path=raw,
                categories=sorted(set(categories)),
            )

            records.append(record)

            if evidence is not None and len(evidence) < MAX_EVIDENCE_ITEMS:
                evidence.append(
                    PersistenceEvidence(
                        category=category,
                        indicator=mechanism,
                        evidence=_clip(raw),
                        source="path",
                        line_number=_line_number(text, match.start()),
                        mechanism=mechanism,
                        operation="reference",
                        path=raw,
                        confidence=0.95,
                        severity="high",
                    )
                )

    return records


# ---------------------------------------------------------------------------
# Command extraction
# ---------------------------------------------------------------------------


def extract_persistence_commands(
    text: str,
    evidence: Optional[List[PersistenceEvidence]] = None,
) -> List[PersistenceRecord]:
    records: List[PersistenceRecord] = []
    seen: Set[Tuple[str, str]] = set()

    command_patterns: Tuple[Tuple[str, str, str, str, float, str], ...] = (
        (
            "schtasks_create",
            "scheduled_task",
            r"(?i)\bschtasks(?:\.exe)?\s+/create\b[^\r\n]*",
            "create",
            0.99,
            "Scheduled task creation command.",
        ),
        (
            "sc_create",
            "service_persistence",
            r"(?i)\bsc(?:\.exe)?\s+(?:create|config)\b[^\r\n]*",
            "create",
            0.99,
            "Windows service creation/configuration command.",
        ),
        (
            "reg_add",
            "registry_persistence",
            r"(?i)\breg(?:\.exe)?\s+add\b[^\r\n]*",
            "write",
            0.99,
            "Registry write command.",
        ),
        (
            "reg_import",
            "registry_persistence",
            r"(?i)\breg(?:\.exe)?\s+import\b[^\r\n]*",
            "write",
            0.98,
            "Registry import command.",
        ),
        (
            "powershell_register_task",
            "scheduled_task",
            r"(?i)\b(?:Register-ScheduledTask|New-ScheduledTask)\b[^\r\n]*",
            "create",
            0.98,
            "PowerShell scheduled-task creation.",
        ),
        (
            "powershell_new_service",
            "service_persistence",
            r"(?i)\bNew-Service\b[^\r\n]*",
            "create",
            0.98,
            "PowerShell service creation.",
        ),
        (
            "systemctl_enable",
            "systemd_persistence",
            r"(?i)\bsystemctl\s+(?:enable|preset)\b[^\r\n]*",
            "enable",
            0.98,
            "systemd service enablement.",
        ),
        (
            "crontab_install",
            "cron_persistence",
            r"(?i)\bcrontab\b[^\r\n]*",
            "write",
            0.95,
            "Crontab command.",
        ),
        (
            "update_rc_d",
            "init_persistence",
            r"(?i)\bupdate-rc\.d\b[^\r\n]*",
            "enable",
            0.97,
            "SysV init service enablement.",
        ),
        (
            "launchctl",
            "macos_launch_agent",
            r"(?i)\blaunchctl\s+(?:load|bootstrap|enable)\b[^\r\n]*",
            "enable",
            0.98,
            "macOS launch service enablement.",
        ),
    )

    for (
        name,
        category,
        pattern,
        operation,
        confidence,
        description,
    ) in command_patterns:
        try:
            matches = re.finditer(
                pattern,
                text,
                flags=re.IGNORECASE | re.MULTILINE,
            )
        except re.error:
            continue

        count = 0

        for match in matches:
            if len(records) >= MAX_PERSISTENCE_RECORDS:
                return records

            if count >= MAX_MATCHES_PER_RULE:
                break

            command = _normalize_whitespace(match.group(0))

            key = (name, command.lower())

            if key in seen:
                continue

            seen.add(key)

            record = PersistenceRecord(
                kind="command",
                value=command,
                normalized=command.lower(),
                mechanism=category,
                category=category,
                source="command",
                operation=operation,
                command=command,
                indicators=[name],
                categories=[
                    "persistence",
                    category,
                    "persistence_command",
                ],
            )

            records.append(record)

            if evidence is not None and len(evidence) < MAX_EVIDENCE_ITEMS:
                evidence.append(
                    PersistenceEvidence(
                        category=category,
                        indicator=name,
                        evidence=_clip(command),
                        source="command",
                        line_number=_line_number(
                            text,
                            match.start(),
                        ),
                        mechanism=category,
                        operation=operation,
                        command=command,
                        confidence=confidence,
                        severity="high",
                    )
                )

            count += 1

    return records


# ---------------------------------------------------------------------------
# Script/API persistence extraction
# ---------------------------------------------------------------------------


def extract_persistence_apis(
    text: str,
    evidence: Optional[List[PersistenceEvidence]] = None,
) -> List[PersistenceRecord]:
    records: List[PersistenceRecord] = []

    api_patterns: Tuple[Tuple[str, str, str, str, float], ...] = (
        (
            "RegSetValueEx",
            "registry_persistence",
            "registry",
            "write",
            0.99,
        ),
        (
            "RegCreateKeyEx",
            "registry_persistence",
            "registry",
            "create",
            0.98,
        ),
        (
            "SHSetValue",
            "registry_persistence",
            "registry",
            "write",
            0.98,
        ),
        (
            "WScript.Shell.RegWrite",
            "registry_persistence",
            "registry",
            "write",
            0.99,
        ),
        (
            "WScript.Shell.RegDelete",
            "registry_persistence",
            "registry",
            "delete",
            0.90,
        ),
        (
            "CreateService",
            "service_persistence",
            "service",
            "create",
            0.99,
        ),
        (
            "ChangeServiceConfig",
            "service_persistence",
            "service",
            "modify",
            0.99,
        ),
        (
            "RegisterTaskDefinition",
            "scheduled_task",
            "scheduled_task",
            "create",
            0.98,
        ),
        (
            "ITaskService",
            "scheduled_task",
            "scheduled_task",
            "create",
            0.95,
        ),
        (
            "ManagementObject",
            "wmi_persistence",
            "wmi_event_subscription",
            "create",
            0.90,
        ),
    )

    seen: Set[str] = set()

    for (
        api,
        category,
        mechanism,
        operation,
        confidence,
    ) in api_patterns:
        pattern = re.compile(
            re.escape(api),
            re.IGNORECASE,
        )

        for match in pattern.finditer(text):
            if len(records) >= MAX_PERSISTENCE_RECORDS:
                return records

            normalized = api.lower()

            if normalized in seen:
                continue

            seen.add(normalized)

            record = PersistenceRecord(
                kind="api",
                value=api,
                normalized=normalized,
                mechanism=mechanism,
                category=category,
                source="api",
                operation=operation,
                indicators=[api],
                categories=[
                    "persistence",
                    category,
                    "persistence_api",
                ],
            )

            records.append(record)

            if evidence is not None and len(evidence) < MAX_EVIDENCE_ITEMS:
                evidence.append(
                    PersistenceEvidence(
                        category=category,
                        indicator=f"api_{normalized}",
                        evidence=api,
                        source="api",
                        line_number=_line_number(
                            text,
                            match.start(),
                        ),
                        mechanism=mechanism,
                        operation=operation,
                        confidence=confidence,
                        severity=(
                            "high" if category != "registry_persistence" else "medium"
                        ),
                    )
                )

    return records


# ---------------------------------------------------------------------------
# Pattern engine
# ---------------------------------------------------------------------------


def _apply_patterns(
    text: str,
    patterns: Sequence[PersistencePattern],
    evidence: List[PersistenceEvidence],
    seen: Set[Tuple[str, int, str]],
) -> None:
    if not text:
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

            raw = _normalize_whitespace(match.group(0))

            if not raw:
                continue

            line_number = _line_number(
                text,
                match.start(),
            )

            key = (
                rule.name,
                line_number,
                raw[:512].lower(),
            )

            if key in seen:
                continue

            seen.add(key)

            evidence.append(
                PersistenceEvidence(
                    category=rule.category,
                    indicator=rule.name,
                    evidence=_clip(raw),
                    source="pattern",
                    line_number=line_number,
                    mechanism=rule.mechanism,
                    operation=rule.operation,
                    confidence=_safe_confidence(rule.confidence),
                    severity=rule.severity,
                )
            )

            count += 1


# ---------------------------------------------------------------------------
# Command enrichment
# ---------------------------------------------------------------------------


def _extract_registry_value_name(
    command: str,
) -> Optional[str]:
    match = REG_VALUE_ASSIGNMENT_RE.search(command)

    if not match:
        return None

    value = match.group("reg_value1") or match.group("reg_value2")

    if not value:
        return None

    return value.strip("\"'")


def _extract_task_name(
    command: str,
) -> Optional[str]:
    match = TASK_NAME_RE.search(command)

    if not match:
        return None

    value = match.group("name1") or match.group("name2")

    if not value:
        return None

    return value.strip("\"'")


def _extract_service_name(
    command: str,
) -> Optional[str]:
    match = SERVICE_NAME_RE.search(command)

    if not match:
        return None

    return match.group("name")


def _enrich_records(
    records: List[PersistenceRecord],
    evidence: List[PersistenceEvidence],
) -> None:
    for record in records:
        if record.kind != "command" or not record.command:
            continue

        command = record.command

        if record.category == "registry_persistence":
            key_match = REGISTRY_KEY_RE.search(command)

            if key_match:
                key = normalize_registry_key(key_match.group(0))
                record.registry_key = key

                mechanism = _registry_mechanism(key)

                if mechanism:
                    record.mechanism = mechanism

                    if mechanism not in record.indicators:
                        record.indicators.append(mechanism)

                    if mechanism == "registry_run_key":
                        record.categories.append("run_key")
                    elif mechanism == "registry_run_once":
                        record.categories.append("run_once")

            value_name = _extract_registry_value_name(command)

            if value_name:
                record.value_name = value_name

        elif record.category == "scheduled_task":
            task_name = _extract_task_name(command)

            if task_name:
                record.value_name = task_name

        elif record.category == "service_persistence":
            service_name = _extract_service_name(command)

            if service_name:
                record.value_name = service_name

        record.categories = sorted(set(record.categories))

    # Add parsed registry/value/task/service context to corresponding
    # evidence records using exact command text.
    for item in evidence:
        if not item.command:
            continue

        key_match = REGISTRY_KEY_RE.search(item.command)

        if key_match:
            item.registry_key = normalize_registry_key(key_match.group(0))

            item.value_name = _extract_registry_value_name(item.command)

        if item.mechanism == "scheduled_task":
            item.value_name = _extract_task_name(item.command)

        if item.mechanism == "service":
            item.value_name = _extract_service_name(item.command)


# ---------------------------------------------------------------------------
# Mechanism/category derivation
# ---------------------------------------------------------------------------


def derive_indicator_names(
    evidence: Sequence[PersistenceEvidence],
) -> List[str]:
    result: List[str] = []
    seen: Set[str] = set()

    for item in evidence:
        if not item.indicator:
            continue

        if item.indicator in seen:
            continue

        seen.add(item.indicator)
        result.append(item.indicator)

    return result


def derive_category_names(
    evidence: Sequence[PersistenceEvidence],
    records: Sequence[PersistenceRecord],
) -> List[str]:
    categories: Set[str] = set()

    for item in evidence:
        if item.category:
            categories.add(item.category)

    for record in records:
        categories.update(record.categories)

    return sorted(
        category for category in categories if category in PERSISTENCE_CATEGORIES
    )


def derive_mechanisms(
    evidence: Sequence[PersistenceEvidence],
    records: Sequence[PersistenceRecord],
) -> List[str]:
    mechanisms: List[str] = []
    seen: Set[str] = set()

    for item in evidence:
        if item.mechanism and item.mechanism not in seen:
            seen.add(item.mechanism)
            mechanisms.append(item.mechanism)

    for record in records:
        if record.mechanism and record.mechanism not in seen:
            seen.add(record.mechanism)
            mechanisms.append(record.mechanism)

    return mechanisms


# ---------------------------------------------------------------------------
# Combination detection
# ---------------------------------------------------------------------------


def derive_combinations(
    categories: Iterable[str],
    indicators: Iterable[str],
    evidence: Sequence[PersistenceEvidence],
    text: str,
) -> List[PersistenceCombination]:
    category_set = set(categories)
    indicator_set = set(indicators)

    combinations: List[PersistenceCombination] = []

    def add(
        name: str,
        present: bool,
        required_categories: Sequence[str] = (),
        required_indicators: Sequence[str] = (),
        explanation: str = "",
    ) -> None:
        combinations.append(
            PersistenceCombination(
                name=name,
                present=bool(present),
                required_categories=tuple(required_categories),
                required_indicators=tuple(required_indicators),
                explanation=explanation,
            )
        )

    has_registry_write = any(
        item.category
        in {
            "registry_persistence",
            "run_key",
            "run_once",
            "winlogon",
            "ifeo",
            "appinit",
            "active_setup",
            "com_hijacking",
            "file_association",
            "office_addin",
            "trusted_location",
        }
        and item.operation
        in {
            "write",
            "create",
            "modify",
        }
        for item in evidence
    )

    has_scheduled_task = "scheduled_task" in category_set and any(
        item.operation
        in {
            "create",
            "write",
            "enable",
        }
        for item in evidence
        if item.category == "scheduled_task"
    )

    has_service = "service_persistence" in category_set and any(
        item.operation
        in {
            "create",
            "write",
            "modify",
        }
        for item in evidence
        if item.category == "service_persistence"
    )

    execution_terms = bool(
        re.search(
            r"(?i)\b(?:cmd(?:\.exe)?|powershell(?:\.exe)?|"
            r"wscript(?:\.exe)?|cscript(?:\.exe)?|mshta(?:\.exe)?|"
            r"rundll32(?:\.exe)?|regsvr32(?:\.exe)?|"
            r"python(?:\.exe)?|wsl(?:\.exe)?|bash|sh)\b",
            text,
        )
    )

    add(
        "registry_persistence",
        has_registry_write,
        (
            "registry_persistence",
            "run_key",
            "run_once",
            "winlogon",
            "ifeo",
            "appinit",
            "active_setup",
            "com_hijacking",
        ),
        explanation=(
            "A registry location associated with persistence is "
            "combined with a write/create/modify operation."
        ),
    )

    add(
        "run_key_persistence",
        "run_key" in category_set or "run_once" in category_set,
        (
            "run_key",
            "run_once",
        ),
        explanation=("Run or RunOnce persistence indicators are present."),
    )

    add(
        "run_key_with_execution",
        (("run_key" in category_set or "run_once" in category_set) and execution_terms),
        (
            "run_key",
            "run_once",
        ),
        explanation=(
            "Run/RunOnce persistence co-occurs with executable "
            "or script-host content."
        ),
    )

    add(
        "service_persistence",
        has_service,
        ("service_persistence",),
        explanation=(
            "A Windows service creation/configuration mechanism " "is represented."
        ),
    )

    add(
        "scheduled_task_persistence",
        has_scheduled_task,
        ("scheduled_task",),
        explanation=("Scheduled-task creation or enablement is represented."),
    )

    add(
        "wmi_persistence",
        ("wmi_persistence" in category_set or "wmi_event_subscription" in category_set),
        (
            "wmi_persistence",
            "wmi_event_subscription",
        ),
        explanation=("WMI permanent-event persistence indicators are present."),
    )

    add(
        "com_hijacking_persistence",
        "com_hijacking" in category_set,
        ("com_hijacking",),
        explanation=("COM registration/hijacking persistence indicators are present."),
    )

    add(
        "ifeo_persistence",
        "ifeo" in category_set or "image_hijacking" in category_set,
        ("ifeo", "image_hijacking"),
        explanation=(
            "Image File Execution Options or executable-image hijacking "
            "indicators are present."
        ),
    )

    add(
        "startup_persistence",
        _has_any(
            category_set,
            (
                "startup_folder",
                "startup_script",
                "startup_script",
                "shell_startup",
                "powershell_profile",
                "macos_launch_agent",
                "macos_launch_daemon",
                "macos_login_item",
            ),
        ),
        (
            "startup_folder",
            "startup_script",
            "shell_startup",
            "powershell_profile",
            "macos_launch_agent",
            "macos_launch_daemon",
            "macos_login_item",
        ),
        explanation=(
            "A startup, login, shell-profile, or launch-item persistence "
            "mechanism is represented."
        ),
    )

    add(
        "unix_persistence",
        _has_any(
            category_set,
            (
                "cron_persistence",
                "systemd_persistence",
                "init_persistence",
                "shell_startup",
                "ssh_persistence",
            ),
        ),
        (
            "cron_persistence",
            "systemd_persistence",
            "init_persistence",
            "shell_startup",
            "ssh_persistence",
        ),
        explanation=("A Unix-like persistence mechanism is represented."),
    )

    add(
        "macos_persistence",
        _has_any(
            category_set,
            (
                "macos_launch_agent",
                "macos_launch_daemon",
                "macos_login_item",
            ),
        ),
        (
            "macos_launch_agent",
            "macos_launch_daemon",
            "macos_login_item",
        ),
        explanation=("A macOS launch or login persistence mechanism is represented."),
    )

    add(
        "office_persistence",
        _has_any(
            category_set,
            (
                "office_persistence",
                "office_addin",
                "office_startup",
                "trusted_location",
            ),
        ),
        (
            "office_persistence",
            "office_addin",
            "office_startup",
            "trusted_location",
        ),
        explanation=(
            "Office-specific persistence or trusted execution configuration "
            "is represented."
        ),
    )

    add(
        "persistence_with_execution",
        bool(category_set) and "persistence" in category_set and execution_terms,
        ("persistence", "persistence_execution"),
        explanation=(
            "Persistence evidence co-occurs with executable/script-host " "content."
        ),
    )

    add(
        "persistence_command_execution",
        ("persistence_command" in category_set and execution_terms),
        (
            "persistence_command",
            "persistence_execution",
        ),
        explanation=(
            "Persistence-management commands contain executable/script " "references."
        ),
    )

    add(
        "high_risk_multi_mechanism_persistence",
        len({item.mechanism for item in evidence if item.mechanism}) >= 2,
        explanation=(
            "Multiple distinct persistence mechanisms are represented "
            "in the same source."
        ),
    )

    add(
        "persistence_api_chain",
        "persistence_api" in category_set
        and (
            "service_persistence" in category_set
            or "scheduled_task" in category_set
            or "registry_persistence" in category_set
            or "wmi_persistence" in category_set
        ),
        ("persistence_api",),
        explanation=(
            "Persistence API references co-occur with a concrete "
            "persistence mechanism."
        ),
    )

    return combinations


def _has_any(
    values: Set[str],
    candidates: Sequence[str],
) -> bool:
    return any(candidate in values for candidate in candidates)


# ---------------------------------------------------------------------------
# Feature vector
# ---------------------------------------------------------------------------


def _signal_score(
    analysis: PersistenceAnalysis,
) -> float:
    weights = {
        "low": 0.15,
        "medium": 0.55,
        "high": 1.35,
        "critical": 2.5,
    }

    score = 0.0

    for item in analysis.evidence:
        score += weights.get(
            item.severity,
            0.25,
        )
        score += 0.20 * _safe_confidence(item.confidence)

    high_value_combinations = {
        "run_key_with_execution": 1.5,
        "service_persistence": 1.5,
        "scheduled_task_persistence": 1.5,
        "wmi_persistence": 2.0,
        "com_hijacking_persistence": 1.75,
        "ifeo_persistence": 1.75,
        "persistence_with_execution": 1.75,
        "high_risk_multi_mechanism_persistence": 1.5,
    }

    for combination in analysis.combinations:
        if combination.present:
            score += high_value_combinations.get(
                combination.name,
                0.60,
            )

    return round(
        min(score, 100.0),
        4,
    )


def _build_feature_vector(
    analysis: PersistenceAnalysis,
) -> Dict[str, Union[int, float]]:
    vector: Dict[str, Union[int, float]] = {}

    category_counts = Counter(
        item.category for item in analysis.evidence if item.category
    )

    indicator_counts = Counter(
        item.indicator for item in analysis.evidence if item.indicator
    )

    mechanism_counts = Counter(
        item.mechanism for item in analysis.evidence if item.mechanism
    )

    operation_counts = Counter(
        item.operation for item in analysis.evidence if item.operation
    )

    vector["persistence_source_size"] = min(
        analysis.source_size,
        MAX_SOURCE_SIZE,
    )
    vector["persistence_record_count"] = len(analysis.records)
    vector["persistence_evidence_count"] = len(analysis.evidence)
    vector["persistence_path_count"] = len(analysis.paths)
    vector["persistence_registry_key_count"] = len(analysis.registry_keys)
    vector["persistence_mechanism_count"] = len(analysis.mechanisms)
    vector["persistence_indicator_count"] = len(analysis.indicators)
    vector["persistence_category_count"] = len(analysis.categories)
    vector["persistence_combination_count"] = sum(
        int(item.present) for item in analysis.combinations
    )

    for operation in (
        "reference",
        "write",
        "create",
        "modify",
        "delete",
        "enable",
        "hijack",
    ):
        count = operation_counts.get(
            operation,
            0,
        )

        vector[f"persistence_operation_{operation}_count"] = count

        vector[f"persistence_operation_{operation}_present"] = int(count > 0)

    for category in PERSISTENCE_CATEGORIES:
        count = category_counts.get(
            category,
            0,
        )

        vector[f"persistence_category_{category}_count"] = count

        vector[f"persistence_category_{category}_present"] = int(count > 0)

    known_indicators = sorted(
        {
            rule.name
            for rule in (
                *PERSISTENCE_RULES,
                *GENERIC_PERSISTENCE_TERMS,
            )
        }
        | {
            "registry_key_reference",
        }
    )

    for indicator in known_indicators:
        count = indicator_counts.get(
            indicator,
            0,
        )

        vector[f"persistence_indicator_{indicator}_count"] = count

        vector[f"persistence_indicator_{indicator}_present"] = int(count > 0)

    known_mechanisms = sorted(
        set(analysis.mechanisms)
        | {
            "registry_run_key",
            "registry_run_once",
            "startup_folder",
            "winlogon",
            "userinit",
            "ifeo",
            "appinit",
            "active_setup",
            "service",
            "scheduled_task",
            "wmi_event_subscription",
            "com_hijacking",
            "office_addin",
            "office_startup",
            "trusted_location",
            "powershell_profile",
            "dll_search_order",
            "dll_side_loading",
            "dll_hijacking",
            "cron",
            "systemd",
            "init",
            "shell_startup",
            "ssh_authorized_keys",
            "launch_agent",
            "launch_daemon",
            "login_item",
        }
    )

    for mechanism in known_mechanisms:
        count = mechanism_counts.get(
            mechanism,
            0,
        )

        vector[f"persistence_mechanism_{mechanism}_count"] = count

        vector[f"persistence_mechanism_{mechanism}_present"] = int(count > 0)

    combination_names = (
        "registry_persistence",
        "run_key_persistence",
        "run_key_with_execution",
        "service_persistence",
        "scheduled_task_persistence",
        "wmi_persistence",
        "com_hijacking_persistence",
        "ifeo_persistence",
        "startup_persistence",
        "unix_persistence",
        "macos_persistence",
        "office_persistence",
        "persistence_with_execution",
        "persistence_command_execution",
        "high_risk_multi_mechanism_persistence",
        "persistence_api_chain",
    )

    combination_map = {item.name: int(item.present) for item in analysis.combinations}

    for name in combination_names:
        vector[f"persistence_combination_{name}_present"] = combination_map.get(
            name,
            0,
        )

    high_count = sum(1 for item in analysis.evidence if item.severity == "high")

    critical_count = sum(1 for item in analysis.evidence if item.severity == "critical")

    vector["persistence_high_severity_count"] = high_count

    vector["persistence_critical_severity_count"] = critical_count

    vector["persistence_distinct_mechanism_count"] = len(
        {item.mechanism for item in analysis.evidence if item.mechanism}
    )

    vector["persistence_signal_score"] = _signal_score(analysis)

    return vector


# ---------------------------------------------------------------------------
# Main analysis
# ---------------------------------------------------------------------------


def analyze_persistence_behavior(
    source: Any,
    *,
    source_name: Optional[str] = None,
) -> PersistenceAnalysis:
    """
    Analyze persistence-related behavior statically.

    No persistence mechanism is created, modified, tested, or installed.
    """
    text, source_size, source_hash = _read_source(source)

    evidence: List[PersistenceEvidence] = []

    # Structured artifact extraction.
    registry_records = extract_registry_keys(
        text,
        evidence,
    )

    path_records = extract_paths(
        text,
        evidence,
    )

    command_records = extract_persistence_commands(
        text,
        evidence,
    )

    api_records = extract_persistence_apis(
        text,
        evidence,
    )

    # Pattern rules.
    seen: Set[Tuple[str, int, str]] = set()

    _apply_patterns(
        text,
        PERSISTENCE_RULES,
        evidence,
        seen,
    )

    _apply_patterns(
        text,
        GENERIC_PERSISTENCE_TERMS,
        evidence,
        seen,
    )

    records: List[PersistenceRecord] = []

    for collection in (
        registry_records,
        path_records,
        command_records,
        api_records,
    ):
        for record in collection:
            if len(records) >= MAX_PERSISTENCE_RECORDS:
                break

            records.append(record)

        if len(records) >= MAX_PERSISTENCE_RECORDS:
            break

    _enrich_records(
        records,
        evidence,
    )

    indicators = derive_indicator_names(evidence)

    categories = derive_category_names(
        evidence,
        records,
    )

    mechanisms = derive_mechanisms(
        evidence,
        records,
    )

    paths: List[str] = []
    registry_keys: List[str] = []

    for record in records:
        if record.path:
            _append_unique(
                paths,
                record.path,
                MAX_PATHS,
            )

        if record.registry_key:
            _append_unique(
                registry_keys,
                record.registry_key,
                MAX_REGISTRY_KEYS,
            )

    combinations = derive_combinations(
        categories,
        indicators,
        evidence,
        text,
    )

    metadata: Dict[str, Any] = {
        "analyzer": "pharos-cdr.persistance",
        "version": "1.0",
        "static_only": True,
        "persistence_mechanisms_modified": False,
        "registry_access_performed": False,
        "services_modified": False,
        "scheduled_tasks_modified": False,
        "wmi_access_performed": False,
        "filesystem_modified": False,
        "source_truncated": source_size > MAX_SOURCE_SIZE,
        "text_length": len(text),
        "registry_hives": sorted(
            {hive for key in registry_keys if (hive := registry_hive(key))}
        ),
    }

    if source_name:
        metadata["source_name"] = _clip(
            str(source_name),
            4096,
        )

    analysis = PersistenceAnalysis(
        source_hash=source_hash,
        source_size=source_size,
        records=records,
        evidence=evidence[:MAX_EVIDENCE_ITEMS],
        paths=paths[:MAX_PATHS],
        registry_keys=registry_keys[:MAX_REGISTRY_KEYS],
        mechanisms=mechanisms,
        indicators=indicators,
        categories=categories,
        combinations=combinations,
        metadata=metadata,
    )

    analysis.feature_vector = _build_feature_vector(analysis)

    return analysis


# ---------------------------------------------------------------------------
# Parsing / extraction aliases
# ---------------------------------------------------------------------------


def parse_persistence_behavior(
    source: Any,
    *,
    source_name: Optional[str] = None,
) -> PersistenceAnalysis:
    return analyze_persistence_behavior(
        source,
        source_name=source_name,
    )


def extract_persistence_features(
    source: Any,
    *,
    source_name: Optional[str] = None,
) -> Dict[str, Union[int, float]]:
    analysis = analyze_persistence_behavior(
        source,
        source_name=source_name,
    )

    return dict(analysis.feature_vector)


def extract_feature_vector(
    source: Any,
    *,
    source_name: Optional[str] = None,
) -> Dict[str, Union[int, float]]:
    return extract_persistence_features(
        source,
        source_name=source_name,
    )


def extract_persistence_feature_vector(
    source: Any,
    *,
    source_name: Optional[str] = None,
) -> Dict[str, Union[int, float]]:
    return extract_persistence_features(
        source,
        source_name=source_name,
    )


# ---------------------------------------------------------------------------
# Feature schema / vectorization
# ---------------------------------------------------------------------------


def persistence_feature_names() -> List[str]:
    names: List[str] = [
        "persistence_source_size",
        "persistence_record_count",
        "persistence_evidence_count",
        "persistence_path_count",
        "persistence_registry_key_count",
        "persistence_mechanism_count",
        "persistence_indicator_count",
        "persistence_category_count",
        "persistence_combination_count",
    ]

    for operation in (
        "reference",
        "write",
        "create",
        "modify",
        "delete",
        "enable",
        "hijack",
    ):
        names.extend(
            (
                f"persistence_operation_{operation}_count",
                f"persistence_operation_{operation}_present",
            )
        )

    for category in PERSISTENCE_CATEGORIES:
        names.extend(
            (
                f"persistence_category_{category}_count",
                f"persistence_category_{category}_present",
            )
        )

    known_indicators = sorted(
        {
            rule.name
            for rule in (
                *PERSISTENCE_RULES,
                *GENERIC_PERSISTENCE_TERMS,
            )
        }
        | {
            "registry_key_reference",
        }
    )

    for indicator in known_indicators:
        names.extend(
            (
                f"persistence_indicator_{indicator}_count",
                f"persistence_indicator_{indicator}_present",
            )
        )

    known_mechanisms = sorted(
        {
            "registry_run_key",
            "registry_run_once",
            "startup_folder",
            "winlogon",
            "userinit",
            "ifeo",
            "appinit",
            "active_setup",
            "service",
            "scheduled_task",
            "wmi_event_subscription",
            "com_hijacking",
            "office_addin",
            "office_startup",
            "trusted_location",
            "powershell_profile",
            "dll_search_order",
            "dll_side_loading",
            "dll_hijacking",
            "cron",
            "systemd",
            "init",
            "shell_startup",
            "ssh_authorized_keys",
            "launch_agent",
            "launch_daemon",
            "login_item",
        }
        | {record.mechanism for record in [] if record.mechanism}
    )

    for mechanism in sorted(known_mechanisms):
        names.extend(
            (
                f"persistence_mechanism_{mechanism}_count",
                f"persistence_mechanism_{mechanism}_present",
            )
        )

    for combination in (
        "registry_persistence",
        "run_key_persistence",
        "run_key_with_execution",
        "service_persistence",
        "scheduled_task_persistence",
        "wmi_persistence",
        "com_hijacking_persistence",
        "ifeo_persistence",
        "startup_persistence",
        "unix_persistence",
        "macos_persistence",
        "office_persistence",
        "persistence_with_execution",
        "persistence_command_execution",
        "high_risk_multi_mechanism_persistence",
        "persistence_api_chain",
    ):
        names.append(f"persistence_combination_{combination}_present")

    names.extend(
        (
            "persistence_high_severity_count",
            "persistence_critical_severity_count",
            "persistence_distinct_mechanism_count",
            "persistence_signal_score",
        )
    )

    return names


def build_feature_schema() -> Dict[str, Any]:
    names = persistence_feature_names()

    return {
        "schema_version": "1.0",
        "feature_family": "persistence_behavior",
        "module_name": "persistance",
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
    names = (
        list(feature_names)
        if feature_names is not None
        else persistence_feature_names()
    )

    vector: List[float] = []

    for name in names:
        value = features.get(
            name,
            0.0,
        )

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
    analysis: PersistenceAnalysis,
    indicator: str,
) -> bool:
    return indicator in set(analysis.indicators)


def has_category(
    analysis: PersistenceAnalysis,
    category: str,
) -> bool:
    return category in set(analysis.categories)


def indicator_count(
    analysis: PersistenceAnalysis,
    indicator: str,
) -> int:
    return sum(1 for item in analysis.evidence if item.indicator == indicator)


def category_count(
    analysis: PersistenceAnalysis,
    category: str,
) -> int:
    return sum(1 for item in analysis.evidence if item.category == category)


def mechanism_count(
    analysis: PersistenceAnalysis,
    mechanism: str,
) -> int:
    return sum(1 for item in analysis.evidence if item.mechanism == mechanism)


def evidence_by_category(
    analysis: PersistenceAnalysis,
    category: str,
) -> List[PersistenceEvidence]:
    return [item for item in analysis.evidence if item.category == category]


def evidence_by_indicator(
    analysis: PersistenceAnalysis,
    indicator: str,
) -> List[PersistenceEvidence]:
    return [item for item in analysis.evidence if item.indicator == indicator]


def evidence_by_mechanism(
    analysis: PersistenceAnalysis,
    mechanism: str,
) -> List[PersistenceEvidence]:
    return [item for item in analysis.evidence if item.mechanism == mechanism]


def high_risk_evidence(
    analysis: PersistenceAnalysis,
    minimum_severity: str = "high",
) -> List[PersistenceEvidence]:
    threshold = SEVERITY_ORDER.get(
        minimum_severity.lower(),
        SEVERITY_ORDER["high"],
    )

    return [
        item
        for item in analysis.evidence
        if SEVERITY_ORDER.get(
            item.severity,
            0,
        )
        >= threshold
    ]


def present_combinations(
    analysis: PersistenceAnalysis,
) -> List[PersistenceCombination]:
    return [item for item in analysis.combinations if item.present]


def highest_severity(
    analysis: PersistenceAnalysis,
) -> str:
    if not analysis.evidence:
        return "low"

    return max(
        (item.severity for item in analysis.evidence),
        key=lambda value: SEVERITY_ORDER.get(
            value,
            0,
        ),
    )


# ---------------------------------------------------------------------------
# Structured extraction helpers
# ---------------------------------------------------------------------------


def extract_persistence_records(
    source: Any,
    *,
    source_name: Optional[str] = None,
) -> List[PersistenceRecord]:
    analysis = analyze_persistence_behavior(
        source,
        source_name=source_name,
    )

    return list(analysis.records)


def extract_persistence_mechanisms(
    source: Any,
    *,
    source_name: Optional[str] = None,
) -> List[str]:
    analysis = analyze_persistence_behavior(
        source,
        source_name=source_name,
    )

    return list(analysis.mechanisms)


def extract_persistence_paths(
    source: Any,
    *,
    source_name: Optional[str] = None,
) -> List[str]:
    analysis = analyze_persistence_behavior(
        source,
        source_name=source_name,
    )

    return list(analysis.paths)


def extract_persistence_registry_keys(
    source: Any,
    *,
    source_name: Optional[str] = None,
) -> List[str]:
    analysis = analyze_persistence_behavior(
        source,
        source_name=source_name,
    )

    return list(analysis.registry_keys)


# ---------------------------------------------------------------------------
# Serialization / summaries
# ---------------------------------------------------------------------------


def analysis_to_dict(
    analysis: PersistenceAnalysis,
) -> Dict[str, Any]:
    return asdict(analysis)


def summarize_persistence_behavior(
    analysis: PersistenceAnalysis,
) -> Dict[str, Any]:
    severity_counts = Counter(item.severity for item in analysis.evidence)

    operation_counts = Counter(
        item.operation for item in analysis.evidence if item.operation
    )

    mechanism_counts = Counter(
        item.mechanism for item in analysis.evidence if item.mechanism
    )

    return {
        "source_hash": analysis.source_hash,
        "source_size": analysis.source_size,
        "record_count": len(analysis.records),
        "evidence_count": len(analysis.evidence),
        "path_count": len(analysis.paths),
        "registry_key_count": len(analysis.registry_keys),
        "mechanism_count": len(analysis.mechanisms),
        "indicator_count": len(analysis.indicators),
        "category_count": len(analysis.categories),
        "highest_severity": highest_severity(analysis),
        "severity_counts": dict(severity_counts),
        "operation_counts": dict(operation_counts),
        "mechanism_counts": dict(mechanism_counts),
        "mechanisms": list(analysis.mechanisms),
        "categories": list(analysis.categories),
        "indicators": list(analysis.indicators),
        "present_combinations": [item.name for item in present_combinations(analysis)],
        "signal_score": analysis.feature_vector.get(
            "persistence_signal_score",
            0.0,
        ),
        "static_only": True,
        "persistence_mechanisms_modified": False,
    }


# ---------------------------------------------------------------------------
# Iterators
# ---------------------------------------------------------------------------


def iter_evidence(
    analysis: PersistenceAnalysis,
) -> Iterator[PersistenceEvidence]:
    yield from analysis.evidence


def iter_high_risk_evidence(
    analysis: PersistenceAnalysis,
    minimum_severity: str = "high",
) -> Iterator[PersistenceEvidence]:
    yield from high_risk_evidence(
        analysis,
        minimum_severity=minimum_severity,
    )


def iter_records(
    analysis: PersistenceAnalysis,
) -> Iterator[PersistenceRecord]:
    yield from analysis.records


def iter_mechanisms(
    analysis: PersistenceAnalysis,
) -> Iterator[str]:
    yield from analysis.mechanisms


def iter_paths(
    analysis: PersistenceAnalysis,
) -> Iterator[str]:
    yield from analysis.paths


def iter_registry_keys(
    analysis: PersistenceAnalysis,
) -> Iterator[str]:
    yield from analysis.registry_keys


def iter_combinations(
    analysis: PersistenceAnalysis,
) -> Iterator[PersistenceCombination]:
    yield from analysis.combinations


def iter_analyses(
    sources: Iterable[Any],
) -> Iterator[PersistenceAnalysis]:
    for source in sources:
        yield analyze_persistence_behavior(source)


# ---------------------------------------------------------------------------
# Compatibility aliases
# ---------------------------------------------------------------------------

analyze = analyze_persistence_behavior
parse = parse_persistence_behavior
extract = extract_persistence_features


__all__ = [
    "PERSISTENCE_CATEGORIES",
    "PersistencePattern",
    "PersistenceEvidence",
    "PersistenceRecord",
    "PersistenceCombination",
    "PersistenceAnalysis",
    "analyze_persistence_behavior",
    "analyze",
    "parse_persistence_behavior",
    "parse",
    "extract_persistence_features",
    "extract_feature_vector",
    "extract_persistence_feature_vector",
    "extract_persistence_records",
    "extract_persistence_mechanisms",
    "extract_persistence_paths",
    "extract_persistence_registry_keys",
    "extract_registry_keys",
    "extract_paths",
    "extract_persistence_commands",
    "extract_persistence_apis",
    "normalize_registry_key",
    "is_registry_key",
    "registry_hive",
    "derive_indicator_names",
    "derive_category_names",
    "derive_mechanisms",
    "derive_combinations",
    "persistence_feature_names",
    "build_feature_schema",
    "vectorize_features",
    "has_indicator",
    "has_category",
    "indicator_count",
    "category_count",
    "mechanism_count",
    "evidence_by_category",
    "evidence_by_indicator",
    "evidence_by_mechanism",
    "high_risk_evidence",
    "present_combinations",
    "highest_severity",
    "analysis_to_dict",
    "summarize_persistence_behavior",
    "iter_evidence",
    "iter_high_risk_evidence",
    "iter_records",
    "iter_mechanisms",
    "iter_paths",
    "iter_registry_keys",
    "iter_combinations",
    "iter_analyses",
]
