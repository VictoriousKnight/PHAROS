"""
Lightweight OOXML relationships feature extraction for Pharos CDR.

Extracts scalar ML features directly from `.rels` XML files.
"""

from __future__ import annotations

import re
from typing import Any
from xml.etree import ElementTree as ET

MAX_XML_BYTES = 16 * 1024 * 1024

SUSPICIOUS_TARGET_RE = re.compile(
    r"(?:javascript:|vbscript:|data:|file:|ms-msdt:|ms-officecmd:|"
    r"powershell|cmd(?:\.exe)?|wscript(?:\.exe)?|cscript(?:\.exe)?|"
    r"mshta(?:\.exe)?|rundll32(?:\.exe)?|regsvr32(?:\.exe)?)",
    re.I,
)
NETWORK_RE = re.compile(r"(?i)^(?:https?|ftp)://")
SCRIPT_TARGET_RE = re.compile(r"(?i)^(?:javascript|vbscript):")
OFFICE_PROTOCOL_RE = re.compile(r"(?i)^ms-[a-z]+:")
DANGEROUS_EXT_RE = re.compile(r"(?i)\.(?:exe|dll|bat|cmd|vbs|js|ps1|hta)(?:$|[?#])")
MACRO_EXT_RE = re.compile(r"(?i)\.(?:docm|dotm|xlsm|xltm|pptm|potm|ppsm)(?:$|[?#])")


def extract_relationship_features(
    relationship_xml: bytes,
    *,
    relationship_file: str | None = None,
    source_part: str | None = None,
    max_relationships: int = 10_000,
) -> dict[str, Any]:
    """Extract numeric features from an OOXML .rels file."""
    if len(relationship_xml) > MAX_XML_BYTES:
        return {"relationships_parse_success": 0.0}

    f = {
        "relationships_version": 1.0,
        "relationships_parse_success": 0.0,
        "relationships_count": 0.0,
        "relationships_unique_type_count": 0.0,
        "relationships_external_count": 0.0,
        "relationships_internal_count": 0.0,
        "relationships_hyperlink_count": 0.0,
        "relationships_image_count": 0.0,
        "relationships_embedded_object_count": 0.0,
        "relationships_external_resource_count": 0.0,
        "relationships_network_target_count": 0.0,
        "relationships_local_file_target_count": 0.0,
        "relationships_script_target_count": 0.0,
        "relationships_office_protocol_target_count": 0.0,
        "relationships_suspicious_target_count": 0.0,
        "relationships_dangerous_extension_count": 0.0,
        "relationships_macro_extension_count": 0.0,
        "relationships_target_query_count": 0.0,
        "relationships_target_fragment_count": 0.0,
        "relationships_encoded_target_count": 0.0,
        "relationships_windows_path_target_count": 0.0,
        "relationships_duplicate_id_count": 0.0,
        "relationships_empty_target_count": 0.0,
        "relationships_empty_type_count": 0.0,
    }

    try:
        root = ET.fromstring(relationship_xml)
        f["relationships_parse_success"] = 1.0
    except ET.ParseError:
        return f

    seen_ids = set()
    seen_types = set()
    count = 0

    for elem in root.iter():
        tag = elem.tag.rsplit("}", 1)[-1].lower()
        if tag != "relationship":
            continue

        count += 1
        if count > max_relationships:
            break

        f["relationships_count"] += 1.0

        rel_id = elem.get("Id", "")
        if rel_id in seen_ids:
            f["relationships_duplicate_id_count"] += 1.0
        seen_ids.add(rel_id)

        rel_type = elem.get("Type", "")
        if not rel_type:
            f["relationships_empty_type_count"] += 1.0
        seen_types.add(rel_type)

        target = elem.get("Target", "")
        if not target:
            f["relationships_empty_target_count"] += 1.0
        
        if "?" in target:
            f["relationships_target_query_count"] += 1.0
        if "#" in target:
            f["relationships_target_fragment_count"] += 1.0
        if "%" in target:
            f["relationships_encoded_target_count"] += 1.0
        if "\\" in target or re.match(r"(?i)^[a-z]:\\", target):
            f["relationships_windows_path_target_count"] += 1.0

        target_mode = elem.get("TargetMode", "")
        if target_mode == "External":
            f["relationships_external_count"] += 1.0
            if not NETWORK_RE.match(target):
                f["relationships_external_resource_count"] += 1.0
        else:
            f["relationships_internal_count"] += 1.0

        rel_type_lower = rel_type.lower()
        if "hyperlink" in rel_type_lower:
            f["relationships_hyperlink_count"] += 1.0
        if "image" in rel_type_lower:
            f["relationships_image_count"] += 1.0
        if "oleobject" in rel_type_lower:
            f["relationships_embedded_object_count"] += 1.0

        if NETWORK_RE.match(target):
            f["relationships_network_target_count"] += 1.0
        elif target.lower().startswith("file://"):
            f["relationships_local_file_target_count"] += 1.0

        if SCRIPT_TARGET_RE.match(target):
            f["relationships_script_target_count"] += 1.0
        
        if OFFICE_PROTOCOL_RE.match(target):
            f["relationships_office_protocol_target_count"] += 1.0

        if SUSPICIOUS_TARGET_RE.search(target):
            f["relationships_suspicious_target_count"] += 1.0

        if DANGEROUS_EXT_RE.search(target):
            f["relationships_dangerous_extension_count"] += 1.0

        if MACRO_EXT_RE.search(target):
            f["relationships_macro_extension_count"] += 1.0

    f["relationships_unique_type_count"] = float(len(seen_types))

    f["relationships_has_external"] = float(f["relationships_external_count"] > 0)
    f["relationships_has_network_target"] = float(f["relationships_network_target_count"] > 0)
    f["relationships_has_local_file_target"] = float(f["relationships_local_file_target_count"] > 0)
    f["relationships_has_script_target"] = float(f["relationships_script_target_count"] > 0)
    f["relationships_has_office_protocol_target"] = float(f["relationships_office_protocol_target_count"] > 0)
    f["relationships_has_hyperlink"] = float(f["relationships_hyperlink_count"] > 0)
    f["relationships_has_embedded_object"] = float(f["relationships_embedded_object_count"] > 0)
    f["relationships_has_suspicious_target"] = float(f["relationships_suspicious_target_count"] > 0)
    f["relationships_has_dangerous_extension"] = float(f["relationships_dangerous_extension_count"] > 0)

    return f

__all__ = ["extract_relationship_features"]
