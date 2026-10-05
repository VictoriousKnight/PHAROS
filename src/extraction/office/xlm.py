"""
Lightweight XLM (Excel 4.0) macro extraction for Pharos CDR.

Extracts scalar ML features from OOXML spreadsheet files without deep parsing.
"""

from __future__ import annotations

import io
import re
import zipfile
from typing import Any
from xml.etree import ElementTree as ET

MAX_XML_BYTES = 16 * 1024 * 1024

XLM_FUNCTIONS = {
    "ALERT", "ARGUMENT", "CALL", "CLOSE", "CONCATENATE", "DEFINE.NAME",
    "DELETE.NAME", "DEREF", "EXEC", "FILES", "FOPEN", "FORK", "FORMULA",
    "FORMULA.FILL", "GET.CELL", "GET.DOCUMENT", "GET.FORMULA", "GET.NAME",
    "GET.WORKBOOK", "GOTO", "HALT", "INPUT", "LINKS", "LIST", "LOOP",
    "MACRO", "NEXT", "NOTE", "ON.TIME", "OPEN", "PAUSE", "RUN", "SELECT",
    "SET.NAME", "SOUND", "START", "TEXT", "WHILE", "WORKBOOK.SELECT", "WRITE",
}

EXEC_RE = re.compile(r"(?i)\b(?:shell|exec|cmd|powershell|rundll32|regsvr32)\b")
DL_RE = re.compile(r"(?i)\b(?:urlmon|winhttp|download|webclient)\b")
OBF_RE = re.compile(r"(?i)\b(?:char|chr|code|concat)\b")

def extract_xlm_features(
    data: bytes,
    *,
    package_path: str | None = None,
) -> dict[str, Any]:
    f = {
        "xlm_version": 1.0,
        "xlm_is_ooxml": 1.0,
        "xlm_is_spreadsheet_package": 0.0,
        "xlm_parse_error": 0.0,
        "xlm_worksheet_count": 0.0,
        "xlm_hidden_sheet_count": 0.0,
        "xlm_very_hidden_sheet_count": 0.0,
        "xlm_macrosheet_count": 0.0,
        "xlm_dialogsheet_count": 0.0,
        "xlm_formula_count": 0.0,
        "xlm_formula_indicator_count": 0.0,
        "xlm_suspicious_formula_count": 0.0,
        "xlm_defined_name_count": 0.0,
        "xlm_defined_name_indicator_count": 0.0,
        "xlm_suspicious_defined_name_count": 0.0,
        "xlm_hidden_defined_name_count": 0.0,
        "xlm_url_count": 0.0,
        "xlm_external_reference_count": 0.0,
        "xlm_execution_indicator_count": 0.0,
        "xlm_download_indicator_count": 0.0,
        "xlm_persistence_indicator_count": 0.0,
        "xlm_credential_indicator_count": 0.0,
        "xlm_obfuscation_indicator_count": 0.0,
        "xlm_dynamic_reference_count": 0.0,
        "xlm_suspicious_sheet_count": 0.0,
        "xlm_has_xlm": 0.0,
        "xlm_has_macrosheets": 0.0,
    }

    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except Exception:
        f["xlm_is_ooxml"] = 0.0
        return f

    try:
        entries = archive.infolist()
        is_spreadsheet = any("xl/workbook.xml" in info.filename.lower() for info in entries)
        if not is_spreadsheet:
            return f
            
        f["xlm_is_spreadsheet_package"] = 1.0

        for info in entries:
            lower = info.filename.lower()
            if not lower.endswith(".xml"):
                continue
                
            if info.file_size > MAX_XML_BYTES:
                f["xlm_parse_error"] = 1.0
                continue
                
            try:
                content = archive.read(info)
                root = ET.fromstring(content)
            except Exception:
                f["xlm_parse_error"] = 1.0
                continue
                
            # Parse workbook for sheets and defined names
            if "workbook.xml" in lower:
                for elem in root.iter():
                    tag = elem.tag.rsplit("}", 1)[-1].lower()
                    if tag == "sheet":
                        f["xlm_worksheet_count"] += 1.0
                        state = (elem.get("state") or "").lower()
                        if state == "hidden":
                            f["xlm_hidden_sheet_count"] += 1.0
                        elif state == "veryhidden":
                            f["xlm_very_hidden_sheet_count"] += 1.0
                    
                    elif tag == "definedname":
                        f["xlm_defined_name_count"] += 1.0
                        hidden = (elem.get("hidden") or "0")
                        if hidden in ("1", "true"):
                            f["xlm_hidden_defined_name_count"] += 1.0
                        
                        text = (elem.text or "").upper()
                        if any(fn in text for fn in XLM_FUNCTIONS):
                            f["xlm_defined_name_indicator_count"] += 1.0
                            if EXEC_RE.search(text) or DL_RE.search(text):
                                f["xlm_suspicious_defined_name_count"] += 1.0

            # Parse rels for macrosheets
            if "workbook.xml.rels" in lower:
                for elem in root.iter():
                    tag = elem.tag.rsplit("}", 1)[-1].lower()
                    if tag == "relationship":
                        rel_type = (elem.get("Type") or "").lower()
                        if "macrosheet" in rel_type:
                            f["xlm_macrosheet_count"] += 1.0
                            
            # Parse worksheet formulas
            if "worksheets/" in lower or "macrosheets/" in lower:
                for elem in root.iter():
                    tag = elem.tag.rsplit("}", 1)[-1].lower()
                    if tag == "f":
                        f["xlm_formula_count"] += 1.0
                        text = (elem.text or "").upper()
                        
                        has_xlm = any(fn + "(" in text for fn in XLM_FUNCTIONS)
                        if has_xlm:
                            f["xlm_formula_indicator_count"] += 1.0
                            
                        is_suspicious = False
                        if EXEC_RE.search(text):
                            f["xlm_execution_indicator_count"] += 1.0
                            is_suspicious = True
                        if DL_RE.search(text):
                            f["xlm_download_indicator_count"] += 1.0
                            is_suspicious = True
                        if OBF_RE.search(text):
                            f["xlm_obfuscation_indicator_count"] += 1.0
                            
                        if is_suspicious:
                            f["xlm_suspicious_formula_count"] += 1.0
                            
        f["xlm_has_xlm"] = float(f["xlm_formula_indicator_count"] > 0 or f["xlm_defined_name_indicator_count"] > 0)
        f["xlm_has_macrosheets"] = float(f["xlm_macrosheet_count"] > 0)

    finally:
        archive.close()

    return f

__all__ = ["extract_xlm_features"]
