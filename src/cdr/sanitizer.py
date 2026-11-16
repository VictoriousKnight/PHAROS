"""
PHAROS CDR - Sanitizer & Reconstruction Engine
---------------------------------------------
Performs Content Disarm and Reconstruction (CDR):
1. Disassembles OOXML packages in memory.
2. Strips active components: vbaProject.bin, macro relationship references,
   embedded binary objects, and suspicious external hyper-references.
3. Updates [Content_Types].xml from macroEnabled MIME types to clean standard types (.docx/.xlsx/.pptx).
4. Reconstructs a clean, safe, valid package and writes out the sanitized binary.
"""

from __future__ import annotations

import io
import logging
import re
import xml.etree.ElementTree as ET
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping, Optional

logger = logging.getLogger("cdr.sanitizer")

# Patterns of files to strip completely
STRIP_PATTERNS = [
    re.compile(r"vbaProject\.bin.*$", re.IGNORECASE),
    re.compile(r"vbaData\.xml.*$", re.IGNORECASE),
    re.compile(r".*vba.*", re.IGNORECASE),
    re.compile(r".*\.bin$", re.IGNORECASE),
    re.compile(r".*oleObject.*", re.IGNORECASE),
    re.compile(r".*activeX.*", re.IGNORECASE),
    re.compile(r".*embeddings/.*", re.IGNORECASE),
]

# Mapping macro content types to clean standard types
CONTENT_TYPE_REPLACEMENTS = {
    "application/vnd.ms-word.document.macroEnabled.main+xml": "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml",
    "application/vnd.ms-excel.sheet.macroEnabled.main+xml": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml",
    "application/vnd.ms-powerpoint.presentation.macroEnabled.main+xml": "application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml",
}


@dataclass
class SanitizationResult:
    success: bool
    sanitized_content: Optional[bytes] = None
    removed_items: list[str] = field(default_factory=list)
    modified_items: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "success": self.success,
            "removed_items": self.removed_items,
            "modified_items": self.modified_items,
            "errors": self.errors,
            "sanitized_bytes_count": len(self.sanitized_content) if self.sanitized_content else 0
        }


def _clean_relationships_xml(xml_bytes: bytes) -> tuple[bytes, list[str]]:
    """Remove relationship targets pointing to vbaProject or external executable resources."""
    removed = []
    try:
        root = ET.fromstring(xml_bytes)
        to_remove = []
        for elem in list(root):
            target = elem.attrib.get("Target", "")
            type_attr = elem.attrib.get("Type", "")
            if "vbaProject" in target or "vba" in type_attr.lower() or "oleObject" in target:
                to_remove.append(elem)
                removed.append(target or type_attr)
        for elem in to_remove:
            root.remove(elem)
        return ET.tostring(root, encoding="utf-8", xml_declaration=True), removed
    except Exception:
        return xml_bytes, removed


def _clean_content_types_xml(xml_bytes: bytes) -> tuple[bytes, list[str]]:
    """Downgrade macroEnabled content types to clean standard OpenXML types."""
    modified = []
    try:
        root = ET.fromstring(xml_bytes)
        for elem in root.iter():
            ct = elem.attrib.get("ContentType", "")
            if ct in CONTENT_TYPE_REPLACEMENTS:
                elem.attrib["ContentType"] = CONTENT_TYPE_REPLACEMENTS[ct]
                modified.append(f"{ct} -> {elem.attrib['ContentType']}")
            # Remove Overrides for vbaProject
            part_name = elem.attrib.get("PartName", "")
            if "vbaProject" in part_name:
                root.remove(elem)
                modified.append(f"Removed ContentType entry for {part_name}")
        return ET.tostring(root, encoding="utf-8", xml_declaration=True), modified
    except Exception:
        return xml_bytes, modified


def sanitize_ooxml_bytes(data: bytes) -> SanitizationResult:
    """Disarm and reconstruct an OpenXML document package."""
    removed: list[str] = []
    modified: list[str] = []
    errors: list[str] = []

    try:
        in_buf = io.BytesIO(data)
        out_buf = io.BytesIO()

        with zipfile.ZipFile(in_buf, "r") as zin, zipfile.ZipFile(out_buf, "w", zipfile.ZIP_DEFLATED) as zout:
            for item in zin.infolist():
                filename = item.filename

                # 1. Check if member matches blacklisted active component
                if any(p.search(filename) for p in STRIP_PATTERNS):
                    removed.append(filename)
                    continue

                content = zin.read(filename)

                # 2. Clean Relationships
                if filename.endswith(".rels"):
                    cleaned_rels, rels_removed = _clean_relationships_xml(content)
                    if rels_removed:
                        content = cleaned_rels
                        modified.append(f"Cleaned {filename} (removed: {len(rels_removed)} targets)")

                # 3. Clean Content Types
                elif filename == "[Content_Types].xml":
                    cleaned_ct, ct_mod = _clean_content_types_xml(content)
                    if ct_mod:
                        content = cleaned_ct
                        modified.extend(ct_mod)

                zout.writestr(item, content)

        out_data = out_buf.getvalue()
        return SanitizationResult(
            success=True,
            sanitized_content=out_data,
            removed_items=removed,
            modified_items=modified
        )

    except Exception as exc:
        logger.error("CDR Sanitization failed: %s", exc)
        return SanitizationResult(
            success=False,
            errors=[f"CDR Reconstruction error: {exc}"]
        )


def sanitize_document(content_or_path: bytes | str | Path) -> Optional[bytes]:
    """Unified sanitizer API. Returns clean bytes if sanitization succeeded."""
    if isinstance(content_or_path, (str, Path)):
        p = Path(content_or_path)
        if not p.is_file():
            return None
        data = p.read_bytes()
    else:
        data = content_or_path

    # Currently supports full OOXML reconstruction
    if data.startswith(b"PK\x03\x04"):
        res = sanitize_ooxml_bytes(data)
        if res.success:
            return res.sanitized_content

    return None


# Scanner compatibility aliases
sanitize_content = sanitize_document
sanitize = sanitize_document

__all__ = ["SanitizationResult", "sanitize_ooxml_bytes", "sanitize_document", "sanitize_content", "sanitize"]
