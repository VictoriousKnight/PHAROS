"""
Derived capability analysis.

This module derives higher-level capabilities from already-extracted static
signals produced by the Pharos CDR extraction modules.

The purpose of this module is to provide a common defensive interpretation
layer between low-level indicators and downstream ML/CDR/pipeline components.

It can consume:

- mappings and dictionaries containing extracted features
- capability analysis objects
- communication analysis objects
- payload analysis objects
- dynamic-execution analysis objects
- process/script/behavior evidence
- raw text and bytes as a fallback
- nested sequences and structured extraction results

The analyzer derives contextual capabilities such as:

- download and execute
- networked payload retrieval
- command-and-control
- staged execution
- encoded/obfuscated execution
- in-memory payload execution
- process injection
- persistence
- credential access
- collection and exfiltration
- dynamic execution
- macro-based execution
- filesystem execution
- registry persistence
- security-tool impairment
- defense evasion
- multi-stage execution chains

This module is STATIC ONLY.

It does NOT:

- execute macros or scripts
- launch processes
- invoke operating-system APIs
- connect to networks
- resolve DNS
- download payloads
- decrypt or execute payloads
- inspect the live process tree
- modify files, registry, services, or system configuration

Derived capabilities represent analytical conclusions from static evidence.
They should be treated as evidence-weighted indicators rather than proof that
the corresponding behavior occurred at runtime.
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
MAX_INDICATORS = 10_000
MAX_CATEGORIES = 512
MAX_TARGETS = 10_000
MAX_DEPTH = 12
MAX_FIELDS = 100_000
MAX_FEATURES = 100_000


# =============================================================================
# Severity
# =============================================================================

SEVERITY_ORDER = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def _severity_value(value: str) -> int:
    return SEVERITY_ORDER.get(str(value).lower(), 0)


def _max_severity(left: str, right: str) -> str:
    return right if _severity_value(right) > _severity_value(left) else left


# =============================================================================
# Capability categories
# =============================================================================

DERIVED_CAPABILITIES = (
    "execution",
    "dynamic_execution",
    "script_execution",
    "macro_execution",
    "command_execution",
    "process_creation",
    "process_injection",
    "process_hollowing",
    "memory_execution",
    "in_memory_execution",
    "reflective_loading",
    "filesystem_execution",
    "file_write",
    "file_delete",
    "registry_persistence",
    "service_persistence",
    "scheduled_task_persistence",
    "startup_persistence",
    "persistence",
    "network_communication",
    "web_communication",
    "download",
    "upload",
    "staged_download",
    "command_and_control",
    "callback",
    "beaconing",
    "polling",
    "remote_command",
    "network_discovery",
    "credential_access",
    "credential_collection",
    "collection",
    "archive_collection",
    "clipboard_collection",
    "browser_data_collection",
    "screen_capture",
    "keylogging",
    "exfiltration",
    "exfiltration_channel",
    "encoded_payload",
    "decoded_payload",
    "compressed_payload",
    "embedded_payload",
    "nested_payload",
    "payload_staging",
    "payload_loader",
    "obfuscated_execution",
    "encrypted_communication",
    "communication_obfuscation",
    "dns_tunneling",
    "proxy_avoidance",
    "defense_evasion",
    "security_software_discovery",
    "security_software_impairment",
    "anti_analysis",
    "anti_debugging",
    "anti_vm",
    "anti_sandbox",
    "artifact_cleanup",
    "environment_aware_execution",
    "living_off_the_land",
    "signed_binary_proxy",
    "com_automation",
    "office_automation",
    "document_manipulation",
    "remote_resource_access",
    "ipc_communication",
    "credentialed_network_access",
    "multi_stage_execution",
    "download_execute",
    "decode_execute",
    "network_execute",
    "memory_execute",
    "persistence_execute",
    "collect_exfiltrate",
    "discover_communicate",
    "evasion_execute",
)


# =============================================================================
# Evidence and result models
# =============================================================================


@dataclass(frozen=True)
class DerivedEvidence:
    """Evidence supporting a derived capability."""

    capability: str
    indicator: str
    evidence: str
    source: str
    supporting_categories: tuple[str, ...] = ()
    supporting_indicators: tuple[str, ...] = ()
    confidence: float = 0.80
    severity: str = "medium"


@dataclass(frozen=True)
class DerivedCapability:
    """A higher-level capability derived from lower-level evidence."""

    name: str
    present: bool
    confidence: float
    severity: str
    evidence_count: int
    supporting_categories: tuple[str, ...]
    supporting_indicators: tuple[str, ...]
    explanation: str


@dataclass(frozen=True)
class DerivedCombination:
    """Higher-order capability chain."""

    name: str
    present: bool
    required_capabilities: tuple[str, ...]
    explanation: str
    severity: str
    confidence: float


@dataclass
class DerivedAnalysis:
    """Complete derived capability analysis."""

    source_hash: str
    source_size: int
    capabilities: list[DerivedCapability] = field(default_factory=list)
    evidence: list[DerivedEvidence] = field(default_factory=list)
    combinations: list[DerivedCombination] = field(default_factory=list)
    indicators: list[str] = field(default_factory=list)
    categories: list[str] = field(default_factory=list)
    feature_vector: dict[str, float] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)


# =============================================================================
# Capability rule definitions
# =============================================================================


@dataclass(frozen=True)
class CapabilityRule:
    """Rule describing how a higher-level capability is derived."""

    name: str
    required_any: tuple[str, ...] = ()
    required_all: tuple[str, ...] = ()
    explanation: str = ""
    severity: str = "medium"
    confidence: float = 0.80


RULES: tuple[CapabilityRule, ...] = (
    CapabilityRule(
        "execution",
        required_any=(
            "execution",
            "dynamic_execution",
            "script_execution",
            "command_execution",
            "process_creation",
        ),
        explanation="Static evidence indicates an execution capability.",
        severity="high",
        confidence=0.88,
    ),
    CapabilityRule(
        "dynamic_execution",
        required_any=(
            "dynamic_execution",
            "reflection",
            "dynamic_resolution",
            "eval",
            "invoke",
            "runtime_compilation",
        ),
        explanation="Static evidence indicates runtime or dynamically resolved execution.",
        severity="high",
        confidence=0.91,
    ),
    CapabilityRule(
        "script_execution",
        required_any=(
            "script_execution",
            "script_host",
            "powershell",
            "javascript",
            "vbscript",
            "shell_execution",
        ),
        explanation="Static evidence indicates script-host or script execution capability.",
        severity="high",
        confidence=0.90,
    ),
    CapabilityRule(
        "macro_execution",
        required_any=(
            "macro",
            "vba",
            "xlm",
            "macro_execution",
        ),
        explanation="Static evidence indicates macro/XLM/VBA execution capability.",
        severity="high",
        confidence=0.92,
    ),
    CapabilityRule(
        "command_execution",
        required_any=(
            "command_execution",
            "shell_execution",
            "command_interpreter",
            "process_execution",
        ),
        explanation="Static evidence indicates command interpreter or process execution.",
        severity="high",
        confidence=0.90,
    ),
    CapabilityRule(
        "process_creation",
        required_any=(
            "process_creation",
            "process_execution",
            "create_process",
        ),
        explanation="Static evidence indicates process creation or launch capability.",
        severity="high",
        confidence=0.91,
    ),
    CapabilityRule(
        "process_injection",
        required_any=(
            "process_injection",
            "injection",
            "remote_thread",
            "write_process_memory",
            "memory_injection",
        ),
        explanation="Static evidence indicates process-memory injection capability.",
        severity="critical",
        confidence=0.95,
    ),
    CapabilityRule(
        "process_hollowing",
        required_any=(
            "process_hollowing",
            "hollowing",
        ),
        explanation="Static evidence indicates process hollowing behavior.",
        severity="critical",
        confidence=0.96,
    ),
    CapabilityRule(
        "memory_execution",
        required_any=(
            "memory_execution",
            "in_memory_execution",
            "virtualalloc",
            "virtualallocex",
            "createthread",
            "rtlmovememory",
        ),
        explanation="Static evidence indicates execution from allocated or manipulated memory.",
        severity="critical",
        confidence=0.94,
    ),
    CapabilityRule(
        "in_memory_execution",
        required_all=(
            "memory_execution",
            "execution",
        ),
        explanation="Memory manipulation is combined with an execution capability.",
        severity="critical",
        confidence=0.96,
    ),
    CapabilityRule(
        "reflective_loading",
        required_any=(
            "reflective_loading",
            "reflection",
            "assembly_load",
            "loadlibrary",
            "manual_mapping",
        ),
        explanation="Static evidence indicates reflective, manual, or dynamic module loading.",
        severity="high",
        confidence=0.90,
    ),
    CapabilityRule(
        "filesystem_execution",
        required_all=(
            "filesystem",
            "execution",
        ),
        explanation="Filesystem operations are combined with execution capability.",
        severity="high",
        confidence=0.88,
    ),
    CapabilityRule(
        "file_write",
        required_any=(
            "file_write",
            "filesystem_write",
            "create_file",
            "write_file",
            "drop_file",
        ),
        explanation="Static evidence indicates file creation or modification.",
        severity="medium",
        confidence=0.86,
    ),
    CapabilityRule(
        "file_delete",
        required_any=(
            "file_delete",
            "delete_file",
            "artifact_removal",
        ),
        explanation="Static evidence indicates file deletion or artifact removal.",
        severity="medium",
        confidence=0.87,
    ),
    CapabilityRule(
        "registry_persistence",
        required_all=(
            "registry",
            "persistence",
        ),
        explanation="Registry access is combined with persistence indicators.",
        severity="high",
        confidence=0.92,
    ),
    CapabilityRule(
        "service_persistence",
        required_all=(
            "service",
            "persistence",
        ),
        explanation="Service management is combined with persistence indicators.",
        severity="high",
        confidence=0.92,
    ),
    CapabilityRule(
        "scheduled_task_persistence",
        required_any=(
            "scheduled_task",
            "task_scheduler",
            "schtasks",
        ),
        explanation="Static evidence indicates scheduled-task persistence capability.",
        severity="high",
        confidence=0.93,
    ),
    CapabilityRule(
        "startup_persistence",
        required_any=(
            "startup",
            "run_key",
            "startup_folder",
            "logon_script",
        ),
        explanation="Static evidence indicates startup/logon persistence.",
        severity="high",
        confidence=0.91,
    ),
    CapabilityRule(
        "persistence",
        required_any=(
            "persistence",
            "registry_persistence",
            "service_persistence",
            "scheduled_task",
            "startup",
            "startup_persistence",
        ),
        explanation="Static evidence indicates persistence capability.",
        severity="high",
        confidence=0.90,
    ),
    CapabilityRule(
        "network_communication",
        required_any=(
            "network",
            "web",
            "http",
            "https",
            "ftp",
            "dns",
            "socket",
            "winsock",
            "wininet",
            "winhttp",
            "communication",
        ),
        explanation="Static evidence indicates network communication capability.",
        severity="medium",
        confidence=0.91,
    ),
    CapabilityRule(
        "web_communication",
        required_any=(
            "web",
            "http",
            "https",
            "wininet",
            "winhttp",
            "websocket",
            "rest_api",
        ),
        explanation="Static evidence indicates web/API communication capability.",
        severity="medium",
        confidence=0.93,
    ),
    CapabilityRule(
        "download",
        required_any=(
            "download",
            "retrieve",
            "remote_resource",
            "staged_download",
        ),
        explanation="Static evidence indicates remote content retrieval.",
        severity="high",
        confidence=0.90,
    ),
    CapabilityRule(
        "upload",
        required_any=(
            "upload",
            "exfiltration",
            "exfiltration_channel",
        ),
        explanation="Static evidence indicates outbound data transmission.",
        severity="medium",
        confidence=0.88,
    ),
    CapabilityRule(
        "staged_download",
        required_any=(
            "staged_download",
            "staged_communication",
            "second_stage",
            "stage_payload",
        ),
        explanation="Static evidence indicates staged content retrieval.",
        severity="high",
        confidence=0.93,
    ),
    CapabilityRule(
        "command_and_control",
        required_any=(
            "c2",
            "command_channel",
            "control_server",
            "command_and_control",
        ),
        explanation="Static evidence indicates command-and-control communication.",
        severity="critical",
        confidence=0.94,
    ),
    CapabilityRule(
        "callback",
        required_any=(
            "callback",
            "reverse_connection",
            "reverse_shell",
        ),
        explanation="Static evidence indicates callback or reverse-channel communication.",
        severity="high",
        confidence=0.92,
    ),
    CapabilityRule(
        "beaconing",
        required_any=(
            "beacon",
            "beaconing",
            "heartbeat",
            "phone_home",
        ),
        explanation="Static evidence indicates periodic callback/beaconing.",
        severity="high",
        confidence=0.91,
    ),
    CapabilityRule(
        "polling",
        required_any=(
            "polling",
            "periodic_poll",
            "check_interval",
        ),
        explanation="Static evidence indicates periodic communication polling.",
        severity="medium",
        confidence=0.86,
    ),
    CapabilityRule(
        "remote_command",
        required_any=(
            "remote_command",
            "command_channel",
            "c2",
        ),
        explanation="Static evidence indicates a remote command capability.",
        severity="critical",
        confidence=0.90,
    ),
    CapabilityRule(
        "network_discovery",
        required_any=(
            "network_discovery",
            "host_discovery",
            "network_configuration",
        ),
        explanation="Static evidence indicates network or host discovery.",
        severity="medium",
        confidence=0.89,
    ),
    CapabilityRule(
        "credential_access",
        required_any=(
            "credential_access",
            "credential",
            "token",
            "password",
            "browser_credentials",
        ),
        explanation="Static evidence indicates access to credential-related data or APIs.",
        severity="high",
        confidence=0.88,
    ),
    CapabilityRule(
        "credential_collection",
        required_any=(
            "credential_collection",
            "credential_access",
            "browser_credentials",
            "password",
            "token",
        ),
        explanation="Static evidence indicates collection of credentials or authentication material.",
        severity="high",
        confidence=0.90,
    ),
    CapabilityRule(
        "collection",
        required_any=(
            "collection",
            "clipboard",
            "screen_capture",
            "keylogging",
            "browser_data_collection",
            "credential_collection",
        ),
        explanation="Static evidence indicates collection of local or user data.",
        severity="high",
        confidence=0.88,
    ),
    CapabilityRule(
        "archive_collection",
        required_any=(
            "archive",
            "archive_collection",
            "compression",
            "compress",
        ),
        explanation="Static evidence indicates archive/compression-based collection or staging.",
        severity="medium",
        confidence=0.83,
    ),
    CapabilityRule(
        "clipboard_collection",
        required_any=(
            "clipboard",
            "clipboard_collection",
        ),
        explanation="Static evidence indicates clipboard access.",
        severity="medium",
        confidence=0.91,
    ),
    CapabilityRule(
        "browser_data_collection",
        required_any=(
            "browser_credentials",
            "browser_data_collection",
            "cookies",
            "browser_history",
        ),
        explanation="Static evidence indicates browser data access.",
        severity="high",
        confidence=0.90,
    ),
    CapabilityRule(
        "screen_capture",
        required_any=(
            "screen_capture",
            "screenshot",
            "desktop_capture",
        ),
        explanation="Static evidence indicates screen capture capability.",
        severity="high",
        confidence=0.94,
    ),
    CapabilityRule(
        "keylogging",
        required_any=(
            "keylogging",
            "keyboard_hook",
            "key_hook",
        ),
        explanation="Static evidence indicates keyboard monitoring capability.",
        severity="critical",
        confidence=0.95,
    ),
    CapabilityRule(
        "exfiltration",
        required_any=(
            "exfiltration",
            "exfiltration_channel",
        ),
        explanation="Static evidence indicates data exfiltration capability.",
        severity="critical",
        confidence=0.94,
    ),
    CapabilityRule(
        "exfiltration_channel",
        required_all=(
            "collection",
            "network_communication",
        ),
        explanation="Data collection is combined with a network communication channel.",
        severity="critical",
        confidence=0.91,
    ),
    CapabilityRule(
        "encoded_payload",
        required_any=(
            "encoded_payload",
            "base64_payload",
            "hex_payload",
            "encoding",
        ),
        explanation="Static evidence indicates encoded content that may represent a payload.",
        severity="medium",
        confidence=0.85,
    ),
    CapabilityRule(
        "decoded_payload",
        required_any=(
            "decoded_payload",
            "payload_decoder",
            "base64_decode",
            "hex_decode",
        ),
        explanation="Static evidence indicates decoding of encoded content.",
        severity="high",
        confidence=0.90,
    ),
    CapabilityRule(
        "compressed_payload",
        required_any=(
            "compressed_payload",
            "compression",
            "archive_payload",
        ),
        explanation="Static evidence indicates compressed or archived content.",
        severity="medium",
        confidence=0.84,
    ),
    CapabilityRule(
        "embedded_payload",
        required_any=(
            "embedded_payload",
            "embedded_object",
            "embedded_file",
        ),
        explanation="Static evidence indicates embedded content or payloads.",
        severity="medium",
        confidence=0.89,
    ),
    CapabilityRule(
        "nested_payload",
        required_any=(
            "nested_payload",
            "nested_archive",
            "payload_nesting",
        ),
        explanation="Static evidence indicates nested payload/container structure.",
        severity="high",
        confidence=0.91,
    ),
    CapabilityRule(
        "payload_staging",
        required_any=(
            "staged_download",
            "staged_communication",
            "payload_staging",
            "second_stage",
        ),
        explanation="Static evidence indicates payload staging.",
        severity="high",
        confidence=0.91,
    ),
    CapabilityRule(
        "payload_loader",
        required_any=(
            "payload_loader",
            "reflective_loading",
            "in_memory_payload",
            "dynamic_loader",
        ),
        explanation="Static evidence indicates a payload-loading mechanism.",
        severity="high",
        confidence=0.91,
    ),
    CapabilityRule(
        "obfuscated_execution",
        required_all=(
            "obfuscation",
            "execution",
        ),
        explanation="Obfuscation indicators are combined with execution capability.",
        severity="high",
        confidence=0.92,
    ),
    CapabilityRule(
        "encrypted_communication",
        required_any=(
            "communication_encryption",
            "tls",
            "ssl",
            "https",
            "encrypted_channel",
        ),
        explanation="Static evidence indicates encrypted communication.",
        severity="low",
        confidence=0.91,
    ),
    CapabilityRule(
        "communication_obfuscation",
        required_any=(
            "communication_obfuscation",
            "encoded_communication",
            "custom_protocol",
        ),
        explanation="Static evidence indicates obfuscated or encoded communications.",
        severity="medium",
        confidence=0.84,
    ),
    CapabilityRule(
        "dns_tunneling",
        required_any=(
            "dns_tunneling",
            "dns_tunnel",
        ),
        explanation="Static evidence indicates DNS tunneling.",
        severity="critical",
        confidence=0.95,
    ),
    CapabilityRule(
        "proxy_avoidance",
        required_any=(
            "proxy_avoidance",
            "proxy_bypass",
        ),
        explanation="Static evidence indicates proxy avoidance or bypass.",
        severity="high",
        confidence=0.88,
    ),
    CapabilityRule(
        "defense_evasion",
        required_any=(
            "evasion",
            "defense_evasion",
            "artifact_cleanup",
            "security_software_impairment",
            "anti_analysis",
            "obfuscation",
        ),
        explanation="Static evidence indicates one or more defense-evasion techniques.",
        severity="high",
        confidence=0.88,
    ),
    CapabilityRule(
        "security_software_discovery",
        required_any=(
            "security_software_discovery",
            "security_software",
            "antivirus_discovery",
        ),
        explanation="Static evidence indicates security-software discovery.",
        severity="medium",
        confidence=0.90,
    ),
    CapabilityRule(
        "security_software_impairment",
        required_any=(
            "security_software_impairment",
            "av_impairment",
            "security_disable",
            "amsi_bypass",
            "etw_bypass",
        ),
        explanation="Static evidence indicates security-control impairment or bypass.",
        severity="critical",
        confidence=0.95,
    ),
    CapabilityRule(
        "anti_analysis",
        required_any=(
            "anti_analysis",
            "anti_debugging",
            "anti_vm",
            "anti_sandbox",
        ),
        explanation="Static evidence indicates anti-analysis behavior.",
        severity="high",
        confidence=0.91,
    ),
    CapabilityRule(
        "anti_debugging",
        required_any=(
            "anti_debugging",
            "debugger_artifacts",
            "debugger_detection",
        ),
        explanation="Static evidence indicates debugger-detection or anti-debugging capability.",
        severity="high",
        confidence=0.93,
    ),
    CapabilityRule(
        "anti_vm",
        required_any=(
            "anti_vm",
            "virtualization_artifacts",
            "vm_detection",
        ),
        explanation="Static evidence indicates virtual-machine detection.",
        severity="high",
        confidence=0.92,
    ),
    CapabilityRule(
        "anti_sandbox",
        required_any=(
            "anti_sandbox",
            "sandbox_artifacts",
            "sandbox_detection",
        ),
        explanation="Static evidence indicates sandbox detection.",
        severity="high",
        confidence=0.92,
    ),
    CapabilityRule(
        "artifact_cleanup",
        required_any=(
            "artifact_cleanup",
            "artifact_removal",
            "file_delete",
            "log_clearing",
            "history_clearing",
        ),
        explanation="Static evidence indicates cleanup or removal of artifacts.",
        severity="high",
        confidence=0.90,
    ),
    CapabilityRule(
        "environment_aware_execution",
        required_all=(
            "environment_checks",
            "execution",
        ),
        explanation="Environment checks are combined with execution capability.",
        severity="high",
        confidence=0.91,
    ),
    CapabilityRule(
        "living_off_the_land",
        required_any=(
            "living_off_the_land",
            "signed_binary_proxy",
            "lolbin",
        ),
        explanation="Static evidence indicates use of trusted system utilities as execution proxies.",
        severity="high",
        confidence=0.90,
    ),
    CapabilityRule(
        "signed_binary_proxy",
        required_any=(
            "signed_binary_proxy",
            "lolbin",
            "proxy_execution",
        ),
        explanation="Static evidence indicates a signed system binary may proxy execution.",
        severity="high",
        confidence=0.92,
    ),
    CapabilityRule(
        "com_automation",
        required_any=(
            "com_automation",
            "com",
            "automation",
        ),
        explanation="Static evidence indicates COM/automation capability.",
        severity="medium",
        confidence=0.89,
    ),
    CapabilityRule(
        "office_automation",
        required_any=(
            "office_automation",
            "excel_automation",
            "word_automation",
            "powerpoint_automation",
        ),
        explanation="Static evidence indicates Office application automation.",
        severity="medium",
        confidence=0.90,
    ),
    CapabilityRule(
        "document_manipulation",
        required_any=(
            "document_manipulation",
            "office",
            "document",
            "workbook",
        ),
        explanation="Static evidence indicates document manipulation capability.",
        severity="low",
        confidence=0.85,
    ),
    CapabilityRule(
        "remote_resource_access",
        required_any=(
            "remote_resource",
            "smb",
            "network_share",
            "remote_resource_access",
        ),
        explanation="Static evidence indicates access to remote resources.",
        severity="medium",
        confidence=0.90,
    ),
    CapabilityRule(
        "ipc_communication",
        required_any=(
            "ipc",
            "named_pipe",
            "pipe",
        ),
        explanation="Static evidence indicates inter-process communication capability.",
        severity="medium",
        confidence=0.88,
    ),
    CapabilityRule(
        "credentialed_network_access",
        required_all=(
            "credentialed_communication",
            "network_communication",
        ),
        explanation="Network communication is combined with explicit credential use.",
        severity="high",
        confidence=0.90,
    ),
)


# =============================================================================
# Combination definitions
# =============================================================================


COMBINATION_DEFINITIONS = (
    (
        "download_execute",
        ("download", "execution"),
        "Remote content retrieval is combined with execution capability.",
        "critical",
        0.96,
    ),
    (
        "decode_execute",
        ("decoded_payload", "execution"),
        "Decoded content is combined with execution capability.",
        "critical",
        0.95,
    ),
    (
        "network_execute",
        ("network_communication", "execution"),
        "Network communication is combined with execution capability.",
        "high",
        0.91,
    ),
    (
        "memory_execute",
        ("memory_execution", "execution"),
        "Memory manipulation is combined with execution capability.",
        "critical",
        0.97,
    ),
    (
        "persistence_execute",
        ("persistence", "execution"),
        "Persistence capability is combined with execution.",
        "critical",
        0.94,
    ),
    (
        "collect_exfiltrate",
        ("collection", "exfiltration_channel"),
        "Collection capability is combined with an outbound communication channel.",
        "critical",
        0.95,
    ),
    (
        "discover_communicate",
        ("network_discovery", "network_communication"),
        "Network discovery is combined with communication capability.",
        "high",
        0.88,
    ),
    (
        "evasion_execute",
        ("defense_evasion", "execution"),
        "Defense-evasion indicators are combined with execution capability.",
        "critical",
        0.95,
    ),
    (
        "encoded_execute",
        ("encoded_payload", "execution"),
        "Encoded payload indicators are combined with execution.",
        "high",
        0.93,
    ),
    (
        "staged_execute",
        ("payload_staging", "execution"),
        "Staged payload behavior is combined with execution.",
        "critical",
        0.95,
    ),
    (
        "payload_loader_execute",
        ("payload_loader", "execution"),
        "Payload-loading capability is combined with execution.",
        "critical",
        0.95,
    ),
    (
        "c2_remote_command",
        ("command_and_control", "remote_command"),
        "Command-and-control communication is combined with remote command capability.",
        "critical",
        0.97,
    ),
    (
        "c2_beacon",
        ("command_and_control", "beaconing"),
        "Command-and-control capability is combined with beaconing.",
        "critical",
        0.97,
    ),
    (
        "callback_execute",
        ("callback", "execution"),
        "Callback communication is combined with execution capability.",
        "critical",
        0.93,
    ),
    (
        "anti_analysis_execute",
        ("anti_analysis", "execution"),
        "Anti-analysis behavior is combined with execution capability.",
        "critical",
        0.95,
    ),
    (
        "security_impairment_execute",
        ("security_software_impairment", "execution"),
        "Security-control impairment is combined with execution.",
        "critical",
        0.98,
    ),
    (
        "living_off_land_execute",
        ("living_off_the_land", "execution"),
        "Trusted-system utility use is combined with execution.",
        "high",
        0.93,
    ),
    (
        "remote_resource_execute",
        ("remote_resource_access", "execution"),
        "Remote-resource access is combined with execution.",
        "high",
        0.91,
    ),
    (
        "credential_collect_exfiltrate",
        ("credential_collection", "exfiltration_channel"),
        "Credential collection is combined with an outbound communication channel.",
        "critical",
        0.97,
    ),
    (
        "multi_stage_execution",
        ("payload_staging", "payload_loader", "execution"),
        "Staging and payload loading are combined with execution capability.",
        "critical",
        0.98,
    ),
)


# =============================================================================
# Input normalization
# =============================================================================


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _decode_bytes(data: bytes) -> str:
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
        return _decode_bytes(value[:MAX_FIELD_TEXT])

    try:
        return str(value)[:MAX_FIELD_TEXT]
    except Exception:
        return ""


def _normalize_key(value: Any) -> str:
    text = str(value).strip().lower()

    text = re.sub(r"[^a-z0-9_./ -]+", "", text)
    text = text.replace("/", "_")
    text = text.replace("-", "_")
    text = re.sub(r"\s+", "_", text)
    text = re.sub(r"_+", "_", text)

    return text.strip("_")


def _normalize_token(value: Any) -> str:
    token = _normalize_key(value)

    aliases = {
        "vba": "macro",
        "xlm": "macro",
        "vba_macro": "macro",
        "macro_execution": "macro",
        "process_injection": "process_injection",
        "memory_injection": "process_injection",
        "remote_thread": "remote_thread",
        "create_process": "process_creation",
        "process_creation": "process_creation",
        "process_execution": "execution",
        "shell_execution": "command_execution",
        "command_interpreter": "command_execution",
        "script_host": "script_execution",
        "powershell": "script_execution",
        "javascript": "script_execution",
        "vbscript": "script_execution",
        "network_communication": "network",
        "web_communication": "web",
        "http_request": "http",
        "https_request": "https",
        "network_download": "download",
        "staged_communication": "staged_download",
        "stage_payload": "payload_staging",
        "second_stage": "payload_staging",
        "c2": "c2",
        "command_and_control": "c2",
        "command_channel": "command_channel",
        "callback": "callback",
        "beacon": "beacon",
        "beaconing": "beacon",
        "credential": "credential_access",
        "credential_access": "credential_access",
        "credential_collection": "credential_collection",
        "browser_credentials": "browser_credentials",
        "browser_data": "browser_data_collection",
        "exfil": "exfiltration",
        "exfiltration": "exfiltration",
        "collection": "collection",
        "clipboard": "clipboard",
        "screenshot": "screen_capture",
        "screen_capture": "screen_capture",
        "keylog": "keylogging",
        "keylogging": "keylogging",
        "encoding": "encoding",
        "encoded_payload": "encoded_payload",
        "base64_payload": "encoded_payload",
        "hex_payload": "encoded_payload",
        "base64_decode": "decoded_payload",
        "hex_decode": "decoded_payload",
        "payload_decoder": "decoded_payload",
        "compression": "compressed_payload",
        "compressed_payload": "compressed_payload",
        "archive_payload": "compressed_payload",
        "embedded_object": "embedded_payload",
        "embedded_payload": "embedded_payload",
        "nested_archive": "nested_payload",
        "nested_payload": "nested_payload",
        "reflective_loading": "reflective_loading",
        "manual_mapping": "reflective_loading",
        "dynamic_loader": "payload_loader",
        "payload_loader": "payload_loader",
        "in_memory_payload": "in_memory_execution",
        "in_memory_execution": "in_memory_execution",
        "memory_execution": "memory_execution",
        "execution": "execution",
        "dynamic_execution": "dynamic_execution",
        "reflection": "dynamic_execution",
        "dynamic_resolution": "dynamic_execution",
        "eval": "dynamic_execution",
        "invoke": "dynamic_execution",
        "runtime_compilation": "dynamic_execution",
        "filesystem_write": "file_write",
        "create_file": "file_write",
        "write_file": "file_write",
        "drop_file": "file_write",
        "file_delete": "file_delete",
        "artifact_removal": "artifact_cleanup",
        "registry_persistence": "registry_persistence",
        "service_persistence": "service_persistence",
        "scheduled_task": "scheduled_task",
        "task_scheduler": "scheduled_task",
        "startup_persistence": "startup_persistence",
        "run_key": "startup_persistence",
        "startup_folder": "startup_persistence",
        "persistence": "persistence",
        "network_discovery": "network_discovery",
        "host_discovery": "network_discovery",
        "network_configuration": "network_discovery",
        "security_software_discovery": "security_software_discovery",
        "security_software_impairment": "security_software_impairment",
        "av_impairment": "security_software_impairment",
        "amsi_bypass": "security_software_impairment",
        "etw_bypass": "security_software_impairment",
        "anti_analysis": "anti_analysis",
        "anti_debugging": "anti_debugging",
        "anti_vm": "anti_vm",
        "anti_sandbox": "anti_sandbox",
        "environment_checks": "environment_checks",
        "evasion": "evasion",
        "defense_evasion": "defense_evasion",
        "obfuscation": "obfuscation",
        "living_off_the_land": "living_off_the_land",
        "lolbin": "living_off_the_land",
        "signed_binary_proxy": "signed_binary_proxy",
        "proxy_execution": "signed_binary_proxy",
        "com": "com_automation",
        "automation": "com_automation",
        "com_automation": "com_automation",
        "office_automation": "office_automation",
        "document_manipulation": "document_manipulation",
        "remote_resource": "remote_resource",
        "network_share": "remote_resource",
        "smb": "smb",
        "ipc": "ipc",
        "named_pipe": "named_pipe",
        "pipe": "named_pipe",
        "credentialed_communication": "credentialed_communication",
        "communication_encryption": "communication_encryption",
        "tls": "communication_encryption",
        "ssl": "communication_encryption",
        "https": "https",
        "encoded_communication": "encoded_communication",
        "communication_obfuscation": "communication_obfuscation",
        "dns_tunneling": "dns_tunneling",
        "dns_tunnel": "dns_tunneling",
        "proxy_avoidance": "proxy_avoidance",
        "proxy_bypass": "proxy_avoidance",
    }

    return aliases.get(token, token)


def _collect_tokens_from_mapping(
    source: Mapping[Any, Any],
    *,
    depth: int = 0,
    prefix: str = "",
) -> tuple[set[str], list[tuple[str, str, str]]]:
    """
    Collect normalized categorical tokens from nested mappings.

    Returns:
        (tokens, evidence tuples)
    """

    tokens: set[str] = set()
    evidence: list[tuple[str, str, str]] = []

    if depth > MAX_DEPTH:
        return tokens, evidence

    for key, value in source.items():
        if len(evidence) >= MAX_EVIDENCE_ITEMS:
            break

        key_name = _normalize_key(key)
        field_name = f"{prefix}.{key_name}" if prefix else key_name

        if isinstance(value, Mapping):
            child_tokens, child_evidence = _collect_tokens_from_mapping(
                value,
                depth=depth + 1,
                prefix=field_name,
            )
            tokens.update(child_tokens)
            evidence.extend(child_evidence)
            continue

        if isinstance(value, Sequence) and not isinstance(
            value,
            (str, bytes, bytearray, memoryview),
        ):
            for item in value[:MAX_FIELDS]:
                if isinstance(item, Mapping):
                    child_tokens, child_evidence = _collect_tokens_from_mapping(
                        item,
                        depth=depth + 1,
                        prefix=field_name,
                    )
                    tokens.update(child_tokens)
                    evidence.extend(child_evidence)
                else:
                    text = _bounded_text(item)
                    token = _normalize_token(text)

                    if token:
                        tokens.add(token)
                        evidence.append(
                            (
                                token,
                                field_name,
                                text[:500],
                            )
                        )
            continue

        if isinstance(value, bool):
            if value:
                token = _normalize_token(key_name)
                if token:
                    tokens.add(token)
                    evidence.append(
                        (
                            token,
                            field_name,
                            "true",
                        )
                    )
            continue

        if isinstance(value, (int, float)):
            if value:
                token = _normalize_token(key_name)
                if token:
                    tokens.add(token)
                    evidence.append(
                        (
                            token,
                            field_name,
                            str(value),
                        )
                    )
            continue

        text = _bounded_text(value)

        key_token = _normalize_token(key_name)
        value_token = _normalize_token(text)

        if key_token:
            tokens.add(key_token)
            evidence.append(
                (
                    key_token,
                    field_name,
                    text[:500],
                )
            )

        if value_token:
            tokens.add(value_token)
            evidence.append(
                (
                    value_token,
                    field_name,
                    text[:500],
                )
            )

    return tokens, evidence


def _flatten_text(
    source: Any,
    *,
    depth: int = 0,
    prefix: str = "source",
    seen: Optional[set[int]] = None,
) -> list[tuple[str, str]]:
    """Flatten arbitrary structured input into bounded text fields."""

    if seen is None:
        seen = set()

    if depth > MAX_DEPTH:
        return []

    if source is None:
        return []

    if isinstance(source, str):
        return [(prefix, source[:MAX_FIELD_TEXT])]

    if isinstance(source, bytes):
        return [
            (
                prefix,
                _decode_bytes(source[:MAX_FIELD_TEXT]),
            )
        ]

    if isinstance(source, bytearray):
        return _flatten_text(
            bytes(source),
            depth=depth,
            prefix=prefix,
            seen=seen,
        )

    if isinstance(source, memoryview):
        return _flatten_text(
            source.tobytes(),
            depth=depth,
            prefix=prefix,
            seen=seen,
        )

    if isinstance(source, os.PathLike):
        try:
            path = Path(source)
            data = path.read_bytes()[:MAX_SOURCE_SIZE]
            return [
                (
                    prefix,
                    _decode_bytes(data),
                )
            ]
        except (OSError, ValueError):
            return []

    object_id = id(source)

    if object_id in seen:
        return []

    if isinstance(source, (Mapping, Sequence)):
        seen.add(object_id)

    result: list[tuple[str, str]] = []

    if isinstance(source, Mapping):
        for key, value in source.items():
            if len(result) >= MAX_FIELDS:
                break

            child_prefix = f"{prefix}.{str(key)[:128]}"
            result.extend(
                _flatten_text(
                    value,
                    depth=depth + 1,
                    prefix=child_prefix,
                    seen=seen,
                )
            )

        return result

    if isinstance(source, Sequence) and not isinstance(
        source,
        (str, bytes, bytearray, memoryview),
    ):
        for index, value in enumerate(source):
            if len(result) >= MAX_FIELDS:
                break

            result.extend(
                _flatten_text(
                    value,
                    depth=depth + 1,
                    prefix=f"{prefix}[{index}]",
                    seen=seen,
                )
            )

        return result

    text = _bounded_text(source)

    if text:
        result.append((prefix, text))

    return result


# =============================================================================
# Object adaptation
# =============================================================================


def _analysis_like_tokens(
    source: Any,
) -> tuple[set[str], list[DerivedEvidence], dict[str, Any]]:
    """
    Adapt common analyzer result objects into normalized capability tokens.
    """

    tokens: set[str] = set()
    evidence: list[DerivedEvidence] = []
    metadata: dict[str, Any] = {}

    if isinstance(source, DerivedAnalysis):
        for capability in source.capabilities:
            if capability.present:
                token = _normalize_token(capability.name)
                if token:
                    tokens.add(token)

        for item in source.evidence:
            token = _normalize_token(item.capability)
            if token:
                tokens.add(token)

        metadata["source_analysis_type"] = "DerivedAnalysis"
        return tokens, evidence, metadata

    if hasattr(source, "capabilities"):
        try:
            capabilities = getattr(source, "capabilities")

            if isinstance(capabilities, Mapping):
                for name, value in capabilities.items():
                    if bool(value):
                        token = _normalize_token(name)
                        if token:
                            tokens.add(token)

            elif isinstance(capabilities, Sequence):
                for item in capabilities:
                    if hasattr(item, "name"):
                        name = getattr(item, "name", "")
                        present = getattr(item, "present", True)

                        if present:
                            token = _normalize_token(name)
                            if token:
                                tokens.add(token)
                    else:
                        token = _normalize_token(item)
                        if token:
                            tokens.add(token)

        except Exception:
            pass

    if hasattr(source, "categories"):
        try:
            categories = getattr(source, "categories")

            if isinstance(categories, Mapping):
                categories = categories.keys()

            for category in categories:
                token = _normalize_token(category)
                if token:
                    tokens.add(token)

        except Exception:
            pass

    if hasattr(source, "indicators"):
        try:
            indicators = getattr(source, "indicators")

            if isinstance(indicators, Mapping):
                indicators = indicators.keys()

            for indicator in indicators:
                token = _normalize_token(indicator)
                if token:
                    tokens.add(token)

        except Exception:
            pass

    if hasattr(source, "feature_vector"):
        try:
            features = getattr(source, "feature_vector")

            if isinstance(features, Mapping):
                for key, value in features.items():
                    try:
                        numeric = float(value)
                    except (TypeError, ValueError):
                        continue

                    if numeric > 0:
                        token = _normalize_token(key)
                        if token:
                            tokens.add(token)

        except Exception:
            pass

    if hasattr(source, "evidence"):
        try:
            raw_evidence = getattr(source, "evidence")

            if isinstance(raw_evidence, Sequence):
                for item in raw_evidence[:MAX_EVIDENCE_ITEMS]:
                    capability = getattr(
                        item,
                        "category",
                        getattr(item, "capability", ""),
                    )
                    indicator = getattr(
                        item,
                        "indicator",
                        "",
                    )
                    text = getattr(
                        item,
                        "evidence",
                        "",
                    )

                    capability_token = _normalize_token(capability)
                    indicator_token = _normalize_token(indicator)

                    if capability_token:
                        tokens.add(capability_token)

                    if indicator_token:
                        tokens.add(indicator_token)

                    if capability_token:
                        evidence.append(
                            DerivedEvidence(
                                capability=capability_token,
                                indicator=indicator_token or "source_evidence",
                                evidence=_bounded_text(text)[:1000],
                                source=type(source).__name__,
                                supporting_categories=(capability_token,),
                                supporting_indicators=(
                                    (indicator_token,) if indicator_token else ()
                                ),
                                confidence=float(
                                    getattr(
                                        item,
                                        "confidence",
                                        0.80,
                                    )
                                ),
                                severity=str(
                                    getattr(
                                        item,
                                        "severity",
                                        "medium",
                                    )
                                ),
                            )
                        )

        except Exception:
            pass

    return tokens, evidence, metadata


# =============================================================================
# Raw-text fallback indicators
# =============================================================================


RAW_INDICATOR_RULES: tuple[tuple[str, str, str, str, float], ...] = (
    (
        "download",
        "download",
        r"\b(?:download|downloaded|downloading|retrieve|retrieved|fetch|fetched|pull|stage|staged)\b",
        "Static text indicates remote content retrieval.",
        0.72,
    ),
    (
        "execution",
        "execution",
        r"\b(?:execute|executed|execution|run|launch|spawn|invoke)\b",
        "Static text indicates execution terminology.",
        0.68,
    ),
    (
        "network",
        "network",
        r"\b(?:http|https|socket|network|internet|wininet|winhttp|winsock)\b",
        "Static text indicates network communication.",
        0.74,
    ),
    (
        "c2",
        "c2",
        r"\b(?:command[- ]and[- ]control|c2|c&c|control\s+server)\b",
        "Static text indicates command-and-control terminology.",
        0.88,
    ),
    (
        "callback",
        "callback",
        r"\b(?:callback|reverse\s+(?:shell|connection|channel)|phone[- ]home)\b",
        "Static text indicates callback behavior.",
        0.88,
    ),
    (
        "beacon",
        "beacon",
        r"\b(?:beacon(?:ing)?|heartbeat|check[- ]in)\b",
        "Static text indicates beaconing.",
        0.84,
    ),
    (
        "persistence",
        "persistence",
        r"\b(?:persistence|autorun|startup|run\s+key|scheduled\s+task|service)\b",
        "Static text indicates persistence mechanisms.",
        0.82,
    ),
    (
        "registry",
        "registry",
        r"\b(?:registry|regedit|reg\.exe|RegOpenKey|RegSetValue)\b",
        "Static text indicates registry access.",
        0.82,
    ),
    (
        "credential_access",
        "credential_access",
        r"\b(?:credential|password|passwd|token|cookie|browser\s+(?:password|credential))\b",
        "Static text indicates credential-related access.",
        0.75,
    ),
    (
        "collection",
        "collection",
        r"\b(?:collect|collection|clipboard|screenshot|keylog|browser\s+data)\b",
        "Static text indicates data collection.",
        0.78,
    ),
    (
        "exfiltration",
        "exfiltration",
        r"\b(?:exfiltrat(?:e|ion|ing)|steal(?:ing)?\s+(?:data|files))\b",
        "Static text indicates data exfiltration.",
        0.90,
    ),
    (
        "encoding",
        "encoding",
        r"\b(?:base64|base64url|hex(?:adecimal)?|encode|encoded|decode|decoded)\b",
        "Static text indicates encoding/decoding.",
        0.73,
    ),
    (
        "obfuscation",
        "obfuscation",
        r"\b(?:obfuscat(?:e|ed|ion)|encoded\s+command|invoke-expression|iex)\b",
        "Static text indicates obfuscation.",
        0.84,
    ),
    (
        "dynamic_execution",
        "dynamic_execution",
        r"\b(?:eval|invoke|reflection|dynamic\s+(?:code|execution|resolution)|assembly\.load|loadlibrary)\b",
        "Static text indicates dynamic execution.",
        0.84,
    ),
    (
        "process_injection",
        "process_injection",
        r"\b(?:process\s+injection|inject(?:ion)?|WriteProcessMemory|CreateRemoteThread|VirtualAllocEx|NtMapViewOfSection)\b",
        "Static text indicates process-memory injection.",
        0.92,
    ),
    (
        "memory_execution",
        "memory_execution",
        r"\b(?:VirtualAlloc|VirtualProtect|CreateThread|shellcode|in[- ]memory)\b",
        "Static text indicates executable memory manipulation.",
        0.88,
    ),
    (
        "anti_analysis",
        "anti_analysis",
        r"\b(?:anti[- ]debug|anti[- ]vm|anti[- ]sandbox|debugger\s+check|virtual\s+machine\s+check)\b",
        "Static text indicates anti-analysis behavior.",
        0.86,
    ),
    (
        "evasion",
        "evasion",
        r"\b(?:defense\s+evasion|security\s+software|disable\s+(?:av|amsi|etw)|bypass)\b",
        "Static text indicates defense evasion.",
        0.80,
    ),
    (
        "environment_checks",
        "environment_checks",
        r"\b(?:environment\s+check|sandbox\s+artifact|hostname|username|locale|domain\s+check)\b",
        "Static text indicates environment-aware checks.",
        0.72,
    ),
    (
        "living_off_the_land",
        "living_off_the_land",
        r"\b(?:living[- ]off[- ]the[- ]land|lolbin|rundll32|regsvr32|mshta|wmic|certutil|bitsadmin)\b",
        "Static text indicates trusted-system utility usage.",
        0.86,
    ),
    (
        "com_automation",
        "com_automation",
        r"\b(?:COM|ActiveXObject|CreateObject|GetObject|AutomationObject)\b",
        "Static text indicates COM/automation usage.",
        0.78,
    ),
)


def _scan_raw_text(
    text: str,
    *,
    source_name: str,
) -> tuple[set[str], list[DerivedEvidence]]:
    tokens: set[str] = set()
    evidence: list[DerivedEvidence] = []

    if not text:
        return tokens, evidence

    for name, category, expression, explanation, confidence in RAW_INDICATOR_RULES:
        try:
            pattern = re.compile(
                expression,
                re.IGNORECASE | re.MULTILINE,
            )
        except re.error:
            continue

        count = 0

        for match in pattern.finditer(text):
            if count >= 1000:
                break

            raw = match.group(0).strip()

            if not raw:
                continue

            token = _normalize_token(category)

            if token:
                tokens.add(token)

            evidence.append(
                DerivedEvidence(
                    capability=token or category,
                    indicator=name,
                    evidence=raw[:1000],
                    source=source_name,
                    supporting_categories=(token,) if token else (),
                    supporting_indicators=(name,),
                    confidence=confidence,
                    severity=("high" if confidence >= 0.90 else "medium"),
                )
            )

            count += 1

            if len(evidence) >= MAX_EVIDENCE_ITEMS:
                return tokens, evidence

    return tokens, evidence


# =============================================================================
# Rule evaluation
# =============================================================================


def _rule_matches(
    rule: CapabilityRule,
    tokens: set[str],
) -> bool:
    if rule.required_all:
        if not all(token in tokens for token in rule.required_all):
            return False

    if rule.required_any:
        if not any(token in tokens for token in rule.required_any):
            return False

    return bool(rule.required_any or rule.required_all)


def _supporting_tokens(
    rule: CapabilityRule,
    tokens: set[str],
) -> tuple[str, ...]:
    result: list[str] = []

    candidates = list(rule.required_any) + list(rule.required_all)

    for candidate in candidates:
        if candidate in tokens and candidate not in result:
            result.append(candidate)

    return tuple(result)


def _derive_capabilities(
    tokens: set[str],
    evidence: list[DerivedEvidence],
) -> list[DerivedCapability]:
    capabilities: list[DerivedCapability] = []

    evidence_by_token: dict[str, list[DerivedEvidence]] = {}

    for item in evidence:
        evidence_by_token.setdefault(
            _normalize_token(item.capability),
            [],
        ).append(item)

    for rule in RULES:
        present = _rule_matches(rule, tokens)

        if not present:
            capabilities.append(
                DerivedCapability(
                    name=rule.name,
                    present=False,
                    confidence=0.0,
                    severity=rule.severity,
                    evidence_count=0,
                    supporting_categories=(),
                    supporting_indicators=(),
                    explanation=rule.explanation,
                )
            )
            continue

        supporting = _supporting_tokens(rule, tokens)

        supporting_evidence: list[DerivedEvidence] = []

        for token in supporting:
            supporting_evidence.extend(evidence_by_token.get(token, []))

        if supporting_evidence:
            confidence = max(
                rule.confidence,
                min(
                    0.99,
                    sum(item.confidence for item in supporting_evidence)
                    / len(supporting_evidence),
                ),
            )

            severity = rule.severity

            for item in supporting_evidence:
                severity = _max_severity(
                    severity,
                    item.severity,
                )

            indicator_names = tuple(
                dict.fromkeys(
                    item.indicator for item in supporting_evidence if item.indicator
                )
            )
        else:
            confidence = rule.confidence
            severity = rule.severity
            indicator_names = supporting

        capabilities.append(
            DerivedCapability(
                name=rule.name,
                present=True,
                confidence=round(
                    min(0.99, confidence),
                    6,
                ),
                severity=severity,
                evidence_count=len(supporting_evidence),
                supporting_categories=supporting,
                supporting_indicators=indicator_names,
                explanation=rule.explanation,
            )
        )

    return capabilities


def _derive_combinations(
    capabilities: list[DerivedCapability],
) -> list[DerivedCombination]:
    present = {capability.name for capability in capabilities if capability.present}

    combinations: list[DerivedCombination] = []

    for name, required, explanation, severity, confidence in COMBINATION_DEFINITIONS:
        is_present = all(capability in present for capability in required)

        combinations.append(
            DerivedCombination(
                name=name,
                present=is_present,
                required_capabilities=tuple(required),
                explanation=explanation,
                severity=severity,
                confidence=confidence,
            )
        )

    return combinations


# =============================================================================
# Feature extraction
# =============================================================================


def _build_feature_vector(
    analysis: DerivedAnalysis,
) -> dict[str, float]:
    present_capabilities = [item for item in analysis.capabilities if item.present]

    vector: dict[str, float] = {
        "source_size": float(analysis.source_size),
        "capability_count": float(len(present_capabilities)),
        "evidence_count": float(len(analysis.evidence)),
        "indicator_count": float(len(analysis.indicators)),
        "category_count": float(len(analysis.categories)),
        "combination_count": float(
            sum(1 for item in analysis.combinations if item.present)
        ),
        "high_count": float(
            sum(1 for item in present_capabilities if item.severity == "high")
        ),
        "critical_count": float(
            sum(1 for item in present_capabilities if item.severity == "critical")
        ),
        "signal_score": 0.0,
    }

    for capability in DERIVED_CAPABILITIES:
        item = next(
            (
                candidate
                for candidate in analysis.capabilities
                if candidate.name == capability
            ),
            None,
        )

        vector[f"capability_{capability}"] = float(bool(item and item.present))

        vector[f"capability_{capability}_confidence"] = float(
            item.confidence if item and item.present else 0.0
        )

    for combination in analysis.combinations:
        vector[f"combination_{combination.name}"] = float(combination.present)

    severity_weights = {
        "info": 0.1,
        "low": 0.4,
        "medium": 1.0,
        "high": 2.0,
        "critical": 3.5,
    }

    score = 0.0

    for item in present_capabilities:
        score += severity_weights.get(item.severity, 1.0) * item.confidence

    for combination in analysis.combinations:
        if combination.present:
            score += (
                severity_weights.get(
                    combination.severity,
                    1.0,
                )
                * combination.confidence
            )

    vector["signal_score"] = round(score, 6)

    return dict(sorted(vector.items()))


# =============================================================================
# Main public analysis
# =============================================================================


def analyze_derived(
    source: Any,
    *,
    source_name: str = "source",
) -> DerivedAnalysis:
    """
    Derive higher-level capabilities from static extraction results.

    ``source`` may be a previously generated analysis object, feature mapping,
    nested extraction result, text, bytes, path, or sequence.
    """

    raw_data = b""
    source_size = 0
    metadata: dict[str, Any] = {
        "static_only": True,
        "runtime_behavior_observed": False,
        "network_activity_performed": False,
        "execution_performed": False,
        "source_type": type(source).__name__,
    }

    if isinstance(source, bytes):
        raw_data = source[:MAX_SOURCE_SIZE]
        source_size = len(raw_data)

    elif isinstance(source, bytearray):
        raw_data = bytes(source[:MAX_SOURCE_SIZE])
        source_size = len(raw_data)

    elif isinstance(source, memoryview):
        raw_data = source.tobytes()[:MAX_SOURCE_SIZE]
        source_size = len(raw_data)

    elif isinstance(source, os.PathLike):
        try:
            raw_data = Path(source).read_bytes()[:MAX_SOURCE_SIZE]
            source_size = len(raw_data)
        except (OSError, ValueError):
            raw_data = b""
            source_size = 0

    elif isinstance(source, str):
        raw_data = source.encode(
            "utf-8",
            errors="replace",
        )[:MAX_SOURCE_SIZE]
        source_size = len(raw_data)

    else:
        try:
            encoded = json.dumps(
                source,
                default=str,
                ensure_ascii=False,
            ).encode(
                "utf-8",
                errors="replace",
            )
            raw_data = encoded[:MAX_SOURCE_SIZE]
            source_size = len(raw_data)
        except Exception:
            text = _bounded_text(source)
            raw_data = text.encode(
                "utf-8",
                errors="replace",
            )[:MAX_SOURCE_SIZE]
            source_size = len(raw_data)

    analysis = DerivedAnalysis(
        source_hash=_sha256(raw_data),
        source_size=source_size,
        metadata=metadata,
    )

    tokens: set[str] = set()
    evidence: list[DerivedEvidence] = []

    object_tokens, object_evidence, object_metadata = _analysis_like_tokens(source)

    tokens.update(object_tokens)
    evidence.extend(object_evidence)
    metadata.update(object_metadata)

    if isinstance(source, Mapping):
        mapping_tokens, mapping_evidence = _collect_tokens_from_mapping(source)

        tokens.update(mapping_tokens)

        for token, field_name, value in mapping_evidence[:MAX_EVIDENCE_ITEMS]:
            evidence.append(
                DerivedEvidence(
                    capability=token,
                    indicator=field_name,
                    evidence=value,
                    source=source_name,
                    supporting_categories=(token,),
                    supporting_indicators=(field_name,),
                    confidence=0.78,
                    severity="medium",
                )
            )

    text_fields = _flatten_text(source)

    total_text = "\n".join(text for _, text in text_fields if text)

    if len(total_text) > MAX_TEXT_SIZE:
        total_text = total_text[:MAX_TEXT_SIZE]

    if total_text:
        text_tokens, text_evidence = _scan_raw_text(
            total_text,
            source_name=source_name,
        )

        tokens.update(text_tokens)
        evidence.extend(text_evidence)

    # Preserve only bounded unique evidence.
    unique_evidence: list[DerivedEvidence] = []
    seen: set[tuple[Any, ...]] = set()

    for item in evidence:
        key = (
            item.capability,
            item.indicator,
            item.evidence,
            item.source,
        )

        if key in seen:
            continue

        seen.add(key)
        unique_evidence.append(item)

        if len(unique_evidence) >= MAX_EVIDENCE_ITEMS:
            break

    analysis.evidence = unique_evidence

    # Normalize raw tokens and discard empty values.
    normalized_tokens: set[str] = set()

    for token in tokens:
        normalized = _normalize_token(token)

        if normalized:
            normalized_tokens.add(normalized)

    tokens = normalized_tokens

    analysis.indicators = sorted(
        {item.indicator for item in analysis.evidence if item.indicator}
    )[:MAX_INDICATORS]

    analysis.categories = sorted(tokens)[:MAX_CATEGORIES]

    analysis.capabilities = _derive_capabilities(
        tokens,
        analysis.evidence,
    )

    analysis.combinations = _derive_combinations(
        analysis.capabilities,
    )

    analysis.feature_vector = _build_feature_vector(
        analysis,
    )

    analysis.metadata.update(
        {
            "normalized_token_count": len(tokens),
            "text_field_count": len(text_fields),
            "rule_count": len(RULES),
            "combination_rule_count": len(COMBINATION_DEFINITIONS),
        }
    )

    return analysis


def analyze_derived_content(
    content: Any,
    *,
    source_name: str = "content",
) -> DerivedAnalysis:
    """Analyze in-memory content for derived capabilities."""

    return analyze_derived(
        content,
        source_name=source_name,
    )


def parse_derived(
    source: Any,
    *,
    source_name: str = "source",
) -> DerivedAnalysis:
    """Compatibility alias for :func:`analyze_derived`."""

    return analyze_derived(
        source,
        source_name=source_name,
    )


def extract_derived_features(
    source: Any,
    *,
    source_name: str = "source",
) -> dict[str, float]:
    """Extract the ML-ready derived capability feature vector."""

    return analyze_derived(
        source,
        source_name=source_name,
    ).feature_vector


def extract_feature_vector(
    source: Any,
    *,
    source_name: str = "source",
) -> dict[str, float]:
    """Return the derived feature vector."""

    return extract_derived_features(
        source,
        source_name=source_name,
    )


def extract_derived_feature_vector(
    source: Any,
    *,
    source_name: str = "source",
) -> dict[str, float]:
    """Explicit alias for derived capability feature-vector extraction."""

    return extract_derived_features(
        source,
        source_name=source_name,
    )


# =============================================================================
# Schema and vectorization
# =============================================================================


def derived_feature_names() -> list[str]:
    """Return deterministic names for all derived features."""

    names = {
        "source_size",
        "capability_count",
        "evidence_count",
        "indicator_count",
        "category_count",
        "combination_count",
        "high_count",
        "critical_count",
        "signal_score",
    }

    for capability in DERIVED_CAPABILITIES:
        names.add(f"capability_{capability}")
        names.add(f"capability_{capability}_confidence")

    for name, *_ in COMBINATION_DEFINITIONS:
        names.add(f"combination_{name}")

    return sorted(names)


def build_feature_schema() -> dict[str, Any]:
    """Build a serializable feature schema."""

    names = derived_feature_names()

    return {
        "schema_version": "1.0",
        "module": "src.extraction.capabilities.derived",
        "feature_type": "derived_capability",
        "static_only": True,
        "features": [
            {
                "name": name,
                "type": "float",
            }
            for name in names
        ],
        "count": len(names),
    }


def vectorize_features(
    features: Mapping[str, Any],
    *,
    feature_names: Optional[Sequence[str]] = None,
) -> list[float]:
    """Convert a feature mapping into a deterministic numeric vector."""

    names = list(feature_names or derived_feature_names())

    result: list[float] = []

    for name in names:
        value = features.get(name, 0.0)

        try:
            numeric = float(value)
        except (TypeError, ValueError):
            numeric = 0.0

        if not math.isfinite(numeric):
            numeric = 0.0

        result.append(numeric)

    return result


# =============================================================================
# Capability query helpers
# =============================================================================


def has_capability(
    analysis: DerivedAnalysis,
    capability: str,
) -> bool:
    """Return whether a derived capability is present."""

    target = _normalize_token(capability)

    return any(item.present and item.name == target for item in analysis.capabilities)


def capability_count(
    analysis: DerivedAnalysis,
    capability: str,
) -> int:
    """Return 1 when a capability is present, otherwise 0."""

    return int(
        has_capability(
            analysis,
            capability,
        )
    )


def capability_names(
    analysis: DerivedAnalysis,
    *,
    present_only: bool = True,
) -> list[str]:
    """Return capability names in deterministic order."""

    if present_only:
        return [item.name for item in analysis.capabilities if item.present]

    return [item.name for item in analysis.capabilities]


def capabilities_by_severity(
    analysis: DerivedAnalysis,
    severity: str,
) -> list[DerivedCapability]:
    """Return present capabilities at a specific severity."""

    normalized = str(severity).lower()

    return [
        item
        for item in analysis.capabilities
        if item.present and item.severity.lower() == normalized
    ]


def high_risk_capabilities(
    analysis: DerivedAnalysis,
) -> list[DerivedCapability]:
    """Return high and critical capabilities."""

    return [
        item
        for item in analysis.capabilities
        if item.present and _severity_value(item.severity) >= 3
    ]


def get_capability(
    analysis: DerivedAnalysis,
    capability: str,
) -> Optional[DerivedCapability]:
    """Return one capability record by name."""

    target = _normalize_token(capability)

    for item in analysis.capabilities:
        if item.name == target:
            return item

    return None


def evidence_by_capability(
    analysis: DerivedAnalysis,
    capability: str,
) -> list[DerivedEvidence]:
    """Return evidence supporting a capability."""

    target = _normalize_token(capability)

    return [
        item
        for item in analysis.evidence
        if item.capability == target or target in item.supporting_categories
    ]


def present_combinations(
    analysis: DerivedAnalysis,
) -> list[DerivedCombination]:
    """Return only present capability combinations."""

    return [item for item in analysis.combinations if item.present]


def highest_severity(
    analysis: DerivedAnalysis,
) -> str:
    """Return the highest severity present in the analysis."""

    severity = "info"

    for item in analysis.capabilities:
        if item.present:
            severity = _max_severity(
                severity,
                item.severity,
            )

    for item in analysis.combinations:
        if item.present:
            severity = _max_severity(
                severity,
                item.severity,
            )

    return severity


# =============================================================================
# Serialization / reporting
# =============================================================================


def analysis_to_dict(
    analysis: DerivedAnalysis,
) -> dict[str, Any]:
    """Convert a derived analysis into a JSON-compatible dictionary."""

    result = asdict(analysis)

    result["summary"] = summarize_derived(
        analysis,
    )

    return result


def analysis_to_json(
    analysis: DerivedAnalysis,
    *,
    indent: int = 2,
) -> str:
    """Serialize a derived analysis as JSON."""

    return json.dumps(
        analysis_to_dict(analysis),
        indent=indent,
        sort_keys=True,
        ensure_ascii=False,
    )


def summarize_derived(
    analysis: DerivedAnalysis,
) -> dict[str, Any]:
    """Return a compact report-friendly summary."""

    present = [item for item in analysis.capabilities if item.present]

    severity_counts = Counter(item.severity for item in present)

    return {
        "source_hash": analysis.source_hash,
        "source_size": analysis.source_size,
        "highest_severity": highest_severity(
            analysis,
        ),
        "signal_score": analysis.feature_vector.get(
            "signal_score",
            0.0,
        ),
        "capability_count": len(present),
        "capabilities": [item.name for item in present],
        "high_risk_capabilities": [
            item.name
            for item in high_risk_capabilities(
                analysis,
            )
        ],
        "severity_counts": dict(sorted(severity_counts.items())),
        "present_combinations": [
            item.name
            for item in present_combinations(
                analysis,
            )
        ],
        "evidence_count": len(analysis.evidence),
    }


# =============================================================================
# Iterators
# =============================================================================


def iter_capabilities(
    analysis: DerivedAnalysis,
    *,
    present_only: bool = False,
) -> Iterator[DerivedCapability]:
    """Iterate through derived capability records."""

    for item in analysis.capabilities:
        if present_only and not item.present:
            continue

        yield item


def iter_evidence(
    analysis: DerivedAnalysis,
) -> Iterator[DerivedEvidence]:
    """Iterate through supporting evidence."""

    yield from analysis.evidence


def iter_high_risk_evidence(
    analysis: DerivedAnalysis,
) -> Iterator[DerivedEvidence]:
    """Iterate over evidence associated with high-risk capabilities."""

    high_risk = {
        item.name
        for item in high_risk_capabilities(
            analysis,
        )
    }

    for item in analysis.evidence:
        if item.capability in high_risk:
            yield item


def iter_combinations(
    analysis: DerivedAnalysis,
    *,
    present_only: bool = False,
) -> Iterator[DerivedCombination]:
    """Iterate over derived capability combinations."""

    for item in analysis.combinations:
        if present_only and not item.present:
            continue

        yield item


def iter_analyses(
    sources: Iterable[Any],
    *,
    source_name: str = "source",
) -> Iterator[DerivedAnalysis]:
    """Analyze multiple sources lazily."""

    for index, source in enumerate(sources):
        yield analyze_derived(
            source,
            source_name=f"{source_name}[{index}]",
        )


# =============================================================================
# Convenience aliases
# =============================================================================


analyze = analyze_derived
extract = extract_derived_features


# =============================================================================
# PUBLIC APIs
# =============================================================================

__all__ = [
    "MAX_SOURCE_SIZE",
    "MAX_TEXT_SIZE",
    "MAX_FIELD_TEXT",
    "MAX_EVIDENCE_ITEMS",
    "MAX_RECORDS",
    "MAX_INDICATORS",
    "MAX_CATEGORIES",
    "MAX_TARGETS",
    "MAX_DEPTH",
    "MAX_FIELDS",
    "MAX_FEATURES",
    "SEVERITY_ORDER",
    "DERIVED_CAPABILITIES",
    "RULES",
    "COMBINATION_DEFINITIONS",
    "DerivedEvidence",
    "DerivedCapability",
    "DerivedCombination",
    "DerivedAnalysis",
    "CapabilityRule",
    "analyze_derived",
    "analyze_derived_content",
    "parse_derived",
    "extract_derived_features",
    "extract_feature_vector",
    "extract_derived_feature_vector",
    "derived_feature_names",
    "build_feature_schema",
    "vectorize_features",
    "has_capability",
    "capability_count",
    "capability_names",
    "capabilities_by_severity",
    "high_risk_capabilities",
    "get_capability",
    "evidence_by_capability",
    "present_combinations",
    "highest_severity",
    "analysis_to_dict",
    "analysis_to_json",
    "summarize_derived",
    "iter_capabilities",
    "iter_evidence",
    "iter_high_risk_evidence",
    "iter_combinations",
    "iter_analyses",
    "analyze",
    "extract",
]
