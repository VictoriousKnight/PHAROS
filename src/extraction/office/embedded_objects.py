"""
Lightweight OOXML embedded objects extraction for Pharos CDR.

Extracts scalar ML features from OOXML embedded objects without full parsing.
"""

from __future__ import annotations

import io
import re
import zipfile
from typing import Any

MAX_ZIP_ENTRIES = 10_000
MAX_OBJECT_SIZE = 16 * 1024 * 1024

SUSPICIOUS_EXT_RE = re.compile(
    r"(?i)\.(?:exe|dll|bat|cmd|vbs|js|ps1|hta|scr|pif|cpl|jar|wsf|sh|msi)$"
)

def extract_embedded_object_features(
    data: bytes,
    *,
    package_path: str | None = None,
    max_objects: int = 10_000,
    max_object_size: int = MAX_OBJECT_SIZE,
    max_total_embedded_size: int = 64 * 1024 * 1024,
) -> dict[str, Any]:
    f = {
        "embedded_objects_version": 1.0,
        "embedded_objects_parse_success": 0.0,
        "embedded_objects_package_is_zip": 0.0,
        "embedded_objects_total_package_members": 0.0,
        "embedded_objects_candidate_member_count": 0.0,
        "embedded_objects_count": 0.0,
        "embedded_objects_total_compressed_size": 0.0,
        "embedded_objects_total_uncompressed_size": 0.0,
        "embedded_objects_maximum_size": 0.0,
        "embedded_objects_average_size": 0.0,
        "embedded_objects_ole_count": 0.0,
        "embedded_objects_package_count": 0.0,
        "embedded_objects_activex_count": 0.0,
        "embedded_objects_control_count": 0.0,
        "embedded_objects_script_count": 0.0,
        "embedded_objects_executable_count": 0.0,
        "embedded_objects_installer_count": 0.0,
        "embedded_objects_archive_count": 0.0,
        "embedded_objects_office_document_count": 0.0,
        "embedded_objects_document_count": 0.0,
        "embedded_objects_suspicious_extension_count": 0.0,
        "embedded_objects_pe_signature_count": 0.0,
        "embedded_objects_elf_signature_count": 0.0,
        "embedded_objects_pdf_signature_count": 0.0,
        "embedded_objects_rtf_signature_count": 0.0,
        "embedded_objects_zip_signature_count": 0.0,
        "embedded_objects_ole_signature_count": 0.0,
        "embedded_objects_cab_signature_count": 0.0,
        "embedded_objects_gzip_signature_count": 0.0,
        "embedded_objects_rar_signature_count": 0.0,
        "embedded_objects_has_pe_signature": 0.0,
        "embedded_objects_has_ole_signature": 0.0,
        "embedded_objects_has_suspicious_extension": 0.0,
    }

    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
        f["embedded_objects_package_is_zip"] = 1.0
        f["embedded_objects_parse_success"] = 1.0
    except Exception:
        return f

    try:
        entries = archive.infolist()
        f["embedded_objects_total_package_members"] = float(len(entries))

        candidate_count = 0
        total_compressed = 0
        total_uncompressed = 0
        max_size = 0

        for info in entries:
            if candidate_count >= max_objects:
                break
                
            lower = info.filename.lower()
            
            # Identify embedded object candidates
            if not ("embeddings/" in lower or "oleobject" in lower or "activex" in lower or "vba" in lower):
                continue
                
            candidate_count += 1
            f["embedded_objects_count"] += 1.0
            total_compressed += info.compress_size
            total_uncompressed += info.file_size
            if info.file_size > max_size:
                max_size = info.file_size

            if info.file_size > max_object_size:
                continue

            if "oleobject" in lower or lower.endswith(".bin"):
                f["embedded_objects_ole_count"] += 1.0
            if "activex" in lower:
                f["embedded_objects_activex_count"] += 1.0
            if "package" in lower:
                f["embedded_objects_package_count"] += 1.0
            if "control" in lower:
                f["embedded_objects_control_count"] += 1.0
            
            if SUSPICIOUS_EXT_RE.search(lower):
                f["embedded_objects_suspicious_extension_count"] += 1.0
            if lower.endswith((".js", ".vbs", ".ps1", ".bat", ".cmd")):
                f["embedded_objects_script_count"] += 1.0
            if lower.endswith((".exe", ".dll", ".scr")):
                f["embedded_objects_executable_count"] += 1.0
            if lower.endswith((".msi", ".cab")):
                f["embedded_objects_installer_count"] += 1.0
            if lower.endswith((".zip", ".rar", ".7z", ".gz")):
                f["embedded_objects_archive_count"] += 1.0
            if lower.endswith((".docx", ".docm", ".xlsx", ".xlsm", ".pptx")):
                f["embedded_objects_office_document_count"] += 1.0
            if lower.endswith((".pdf", ".rtf", ".txt")):
                f["embedded_objects_document_count"] += 1.0

            try:
                # Read just enough for signatures
                with archive.open(info) as f_obj:
                    prefix = f_obj.read(16)
                    
                if prefix.startswith(b"MZ"):
                    f["embedded_objects_pe_signature_count"] += 1.0
                if prefix.startswith(b"\x7fELF"):
                    f["embedded_objects_elf_signature_count"] += 1.0
                if prefix.startswith(b"%PDF-"):
                    f["embedded_objects_pdf_signature_count"] += 1.0
                if prefix.startswith(b"{\\rtf"):
                    f["embedded_objects_rtf_signature_count"] += 1.0
                if prefix.startswith(b"PK\x03\x04"):
                    f["embedded_objects_zip_signature_count"] += 1.0
                if prefix.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
                    f["embedded_objects_ole_signature_count"] += 1.0
                if prefix.startswith(b"MSCF"):
                    f["embedded_objects_cab_signature_count"] += 1.0
                if prefix.startswith(b"\x1f\x8b"):
                    f["embedded_objects_gzip_signature_count"] += 1.0
                if prefix.startswith(b"Rar!\x1a\x07\x00"):
                    f["embedded_objects_rar_signature_count"] += 1.0

            except Exception:
                pass

        f["embedded_objects_candidate_member_count"] = float(candidate_count)
        f["embedded_objects_total_compressed_size"] = float(total_compressed)
        f["embedded_objects_total_uncompressed_size"] = float(total_uncompressed)
        f["embedded_objects_maximum_size"] = float(max_size)
        
        if candidate_count > 0:
            f["embedded_objects_average_size"] = float(total_uncompressed) / candidate_count
            
        f["embedded_objects_has_pe_signature"] = float(f["embedded_objects_pe_signature_count"] > 0)
        f["embedded_objects_has_ole_signature"] = float(f["embedded_objects_ole_signature_count"] > 0)
        f["embedded_objects_has_suspicious_extension"] = float(f["embedded_objects_suspicious_extension_count"] > 0)

    finally:
        archive.close()

    return f

__all__ = ["extract_embedded_object_features"]
