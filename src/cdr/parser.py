"""
PHAROS CDR - Document Structure Parser
--------------------------------------
Parses OOXML (Word, Excel, PowerPoint) zip packages and legacy OLE compound files.
Extracts internal member streams, XML relationship graphs, and metadata without
executing any active content.
"""

from __future__ import annotations

import io
import logging
import xml.etree.ElementTree as ET
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping, Optional

logger = logging.getLogger("cdr.parser")


@dataclass
class ParsedDocument:
    is_valid: bool
    format_type: str  # 'ooxml' or 'ole' or 'unknown'
    members: list[str] = field(default_factory=list)
    has_macros: bool = False
    has_embedded_objects: bool = False
    external_targets: list[str] = field(default_factory=list)
    raw_parts: dict[str, bytes] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)


def parse_ooxml(data: bytes) -> ParsedDocument:
    """Parse an OpenXML ZIP package and inspect its structural hierarchy."""
    doc = ParsedDocument(is_valid=False, format_type="ooxml")
    try:
        with zipfile.ZipFile(io.BytesIO(data), "r") as zf:
            doc.members = zf.namelist()
            doc.is_valid = True

            for name in doc.members:
                # Detect active macro containers
                if "vbaProject.bin" in name or name.endswith(".bin"):
                    doc.has_macros = True

                # Detect embedded object binaries
                if any(x in name for x in ["oleObject", "embeddings/", "activeX"]):
                    doc.has_embedded_objects = True

                # Parse relationship targets for external links / dynamic DDE
                if name.endswith(".rels"):
                    try:
                        rels_bytes = zf.read(name)
                        root = ET.fromstring(rels_bytes)
                        for elem in root.iter():
                            target = elem.attrib.get("Target", "")
                            mode = elem.attrib.get("TargetMode", "")
                            if mode == "External" or target.startswith(("http://", "https://", "ftp://")):
                                doc.external_targets.append(target)
                    except Exception:
                        pass

                # Store essential XML and structure parts
                try:
                    doc.raw_parts[name] = zf.read(name)
                except Exception:
                    pass

    except Exception as exc:
        doc.errors.append(f"OOXML ZIP parse failure: {exc}")
        doc.is_valid = False

    return doc


def parse_document(content_or_path: bytes | str | Path) -> ParsedDocument:
    """Unified entry point to parse any document structure."""
    if isinstance(content_or_path, (str, Path)):
        p = Path(content_or_path)
        if not p.is_file():
            return ParsedDocument(is_valid=False, format_type="unknown", errors=["File not found"])
        data = p.read_bytes()
    else:
        data = content_or_path

    # Check for OOXML (PK\x03\x04)
    if data.startswith(b"PK\x03\x04"):
        return parse_ooxml(data)

    # Check for Legacy OLE (\xd0\xcf\x11\xe0)
    if data.startswith(b"\xd0\xcf\x11\xe0"):
        return ParsedDocument(
            is_valid=True,
            format_type="ole",
            has_macros=b"Attribut" in data or b"Sub " in data,
            metadata={"bytes_size": len(data)}
        )

    return ParsedDocument(
        is_valid=False,
        format_type="unknown",
        errors=["Unrecognized file signature for CDR parsing"]
    )


# Short aliases
parse = parse_document

__all__ = ["ParsedDocument", "parse_document", "parse", "parse_ooxml"]
