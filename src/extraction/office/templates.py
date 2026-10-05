"""
Lightweight OOXML templates extraction for Pharos CDR.

Extracts scalar ML features concerning attached templates from OOXML .rels files.
"""

from __future__ import annotations

import io
import re
import zipfile
from typing import Any
from xml.etree import ElementTree as ET

MAX_XML_BYTES = 16 * 1024 * 1024

NETWORK_RE = re.compile(r"(?i)^(?:https?|ftp)://")
UNC_RE = re.compile(r"(?i)^\\\\[a-z0-9_-]")
ABS_PATH_RE = re.compile(r"(?i)^[a-z]:\\")
OFFICE_EXT_RE = re.compile(r"(?i)\.(?:docx?|dotx?|xlsx?|xltx?|pptx?|potx?)(?:$|[?#])")
MACRO_EXT_RE = re.compile(r"(?i)\.(?:docm|dotm|xlsm|xltm|pptm|potm|ppsm)(?:$|[?#])")
SCRIPT_RE = re.compile(r"(?i)\.(?:js|vbs|wsf|bat|cmd|ps1|hta)(?:$|[?#])|javascript:|vbscript:")
EXE_RE = re.compile(r"(?i)\.(?:exe|dll|scr|pif|cpl)(?:$|[?#])")
ENV_RE = re.compile(r"(?i)%(?:appdata|temp|tmp|userprofile|comspec)%")
MACRO_IND_RE = re.compile(r"(?i)auto(?:open|close|exec)|document_open|workbook_open")
EXEC_IND_RE = re.compile(r"(?i)cmd(?:\\.exe)?|powershell|wscript|cscript|mshta|rundll32|regsvr32")
DL_IND_RE = re.compile(r"(?i)download|invoke-webrequest|webclient")
OBFUSCATION_RE = re.compile(r"(?i)chr\(|base64|strreverse|xor")

def extract_template_features(
    data: bytes,
    *,
    package_path: str | None = None,
    max_rels_files: int = 100,
) -> dict[str, Any]:
    f = {
        "template_version": 1.0,
        "template_package_is_ooxml": 0.0,
        "template_zip_read_error": 0.0,
        "template_parse_errors": 0.0,
        "template_truncated": 0.0,
        "template_relationship_files_examined": 0.0,
        "template_relationship_files_failed": 0.0,
        "template_total_relationships": 0.0,
        "template_relationship_count": 0.0,
        "template_external_count": 0.0,
        "template_remote_count": 0.0,
        "template_unc_count": 0.0,
        "template_absolute_path_count": 0.0,
        "template_office_target_count": 0.0,
        "template_macro_enabled_count": 0.0,
        "template_script_target_count": 0.0,
        "template_executable_target_count": 0.0,
        "template_suspicious_count": 0.0,
        "template_environment_variable_count": 0.0,
        "template_macro_indicator_count": 0.0,
        "template_execution_indicator_count": 0.0,
        "template_download_indicator_count": 0.0,
        "template_obfuscation_indicator_count": 0.0,
        "template_external_ratio": 0.0,
        "template_remote_ratio": 0.0,
        "template_suspicious_ratio": 0.0,
        "template_macro_enabled_ratio": 0.0,
    }

    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
        f["template_package_is_ooxml"] = 1.0
    except Exception:
        f["template_zip_read_error"] = 1.0
        return f

    try:
        entries = archive.infolist()
        examined_count = 0

        for info in entries:
            if examined_count >= max_rels_files:
                f["template_truncated"] = 1.0
                break
                
            if not info.filename.lower().endswith(".rels"):
                continue
                
            examined_count += 1
            f["template_relationship_files_examined"] += 1.0

            if info.file_size > MAX_XML_BYTES:
                f["template_relationship_files_failed"] += 1.0
                f["template_parse_errors"] += 1.0
                continue

            try:
                content = archive.read(info)
                root = ET.fromstring(content)
            except Exception:
                f["template_relationship_files_failed"] += 1.0
                f["template_parse_errors"] += 1.0
                continue

            for elem in root.iter():
                tag = elem.tag.rsplit("}", 1)[-1].lower()
                if tag != "relationship":
                    continue

                f["template_total_relationships"] += 1.0
                
                rel_type = elem.get("Type", "")
                if "attachedTemplate" not in rel_type:
                    continue

                f["template_relationship_count"] += 1.0
                target = elem.get("Target", "")
                target_mode = elem.get("TargetMode", "")

                is_suspicious = False

                if target_mode == "External":
                    f["template_external_count"] += 1.0
                
                if NETWORK_RE.match(target):
                    f["template_remote_count"] += 1.0
                if UNC_RE.match(target):
                    f["template_unc_count"] += 1.0
                if ABS_PATH_RE.match(target):
                    f["template_absolute_path_count"] += 1.0
                    
                if OFFICE_EXT_RE.search(target):
                    f["template_office_target_count"] += 1.0
                if MACRO_EXT_RE.search(target):
                    f["template_macro_enabled_count"] += 1.0
                if SCRIPT_RE.search(target):
                    f["template_script_target_count"] += 1.0
                    is_suspicious = True
                if EXE_RE.search(target):
                    f["template_executable_target_count"] += 1.0
                    is_suspicious = True
                
                if ENV_RE.search(target):
                    f["template_environment_variable_count"] += 1.0
                    is_suspicious = True
                if MACRO_IND_RE.search(target):
                    f["template_macro_indicator_count"] += 1.0
                    is_suspicious = True
                if EXEC_IND_RE.search(target):
                    f["template_execution_indicator_count"] += 1.0
                    is_suspicious = True
                if DL_IND_RE.search(target):
                    f["template_download_indicator_count"] += 1.0
                    is_suspicious = True
                if OBFUSCATION_RE.search(target):
                    f["template_obfuscation_indicator_count"] += 1.0
                    is_suspicious = True

                if is_suspicious:
                    f["template_suspicious_count"] += 1.0

        if f["template_relationship_count"] > 0:
            count = f["template_relationship_count"]
            f["template_external_ratio"] = f["template_external_count"] / count
            f["template_remote_ratio"] = f["template_remote_count"] / count
            f["template_suspicious_ratio"] = f["template_suspicious_count"] / count
            f["template_macro_enabled_ratio"] = f["template_macro_enabled_count"] / count

    finally:
        archive.close()

    return f

__all__ = ["extract_template_features"]
