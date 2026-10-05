"""
Top-level Office feature extractor for Pharos CDR.

Consolidates ML feature vectors from specialized Office extraction modules.
"""

from __future__ import annotations

import zipfile
import io
from pathlib import Path
from typing import Any, BinaryIO, Union

from src.extraction.office.relationships import extract_relationship_features
from src.extraction.office.embedded_objects import extract_embedded_object_features
from src.extraction.office.templates import extract_template_features
from src.extraction.office.ole import extract_ole_features
from src.extraction.office.xlm import extract_xlm_features

def extract_office_features(
    source: Union[str, Path, bytes, bytearray, memoryview, BinaryIO],
    *,
    include_metadata: bool = False,
    **kwargs: Any,
) -> dict[str, Any]:
    """Extract all Office features."""
    
    data = _read_source(source)
    
    # Initialize feature vector with container identity
    features: dict[str, float] = {
        "office_is_ooxml": 0.0,
        "office_is_macro_enabled_extension": 0.0,
        "office_is_legacy_ole": 0.0,
        "office_family_word": 0.0,
        "office_family_excel": 0.0,
        "office_family_powerpoint": 0.0,
        "office_family_ole": 0.0,
        "office_family_unknown": 0.0,
        "office_has_vba_project": 0.0,
        "office_has_xlm": 0.0,
        "office_has_embedded_objects": 0.0,
        "office_has_activex": 0.0,
        "office_has_external_relationships": 0.0,
        "office_has_external_targets": 0.0,
        "office_has_hyperlinks": 0.0,
        "office_part_count": 0.0,
        "office_xml_part_count": 0.0,
        "office_relationship_part_count": 0.0,
        "office_macro_related_part_count": 0.0,
    }

    # Add features from sub-modules
    ole_feats = extract_ole_features(data)
    features.update(ole_feats)
    
    xlm_feats = extract_xlm_features(data)
    features.update(xlm_feats)
    
    embed_feats = extract_embedded_object_features(data)
    features.update(embed_feats)
    
    tmpl_feats = extract_template_features(data)
    features.update(tmpl_feats)

    # Process relationships and basic OOXML container
    if data.startswith(b"PK\x03\x04"):
        features["office_is_ooxml"] = 1.0
        try:
            archive = zipfile.ZipFile(io.BytesIO(data))
            entries = archive.infolist()
            features["office_part_count"] = float(len(entries))
            
            rels_data = b""
            for info in entries:
                lower = info.filename.lower()
                if lower.endswith(".xml"):
                    features["office_xml_part_count"] += 1.0
                if lower.endswith(".rels"):
                    features["office_relationship_part_count"] += 1.0
                    # Just grab the main .rels for relationship features
                    if info.file_size < 16 * 1024 * 1024 and not rels_data:
                        rels_data = archive.read(info)
                if "vba" in lower:
                    features["office_has_vba_project"] = 1.0
                    features["office_macro_related_part_count"] += 1.0
                if "word/" in lower:
                    features["office_family_word"] = 1.0
                if "xl/" in lower:
                    features["office_family_excel"] = 1.0
                if "ppt/" in lower:
                    features["office_family_powerpoint"] = 1.0
                    
            if rels_data:
                rel_feats = extract_relationship_features(rels_data)
                features.update(rel_feats)
                if rel_feats.get("relationships_external_count", 0) > 0:
                    features["office_has_external_relationships"] = 1.0
                if rel_feats.get("relationships_network_target_count", 0) > 0:
                    features["office_has_external_targets"] = 1.0
                if rel_feats.get("relationships_hyperlink_count", 0) > 0:
                    features["office_has_hyperlinks"] = 1.0
                    
        except Exception:
            pass

    if features.get("ole_is_container") == 1.0:
        features["office_is_legacy_ole"] = 1.0
        features["office_family_ole"] = 1.0
        
    if features.get("xlm_has_xlm") == 1.0:
        features["office_has_xlm"] = 1.0
        
    if features.get("embedded_objects_count", 0) > 0:
        features["office_has_embedded_objects"] = 1.0
        
    if features.get("embedded_objects_activex_count", 0) > 0:
        features["office_has_activex"] = 1.0

    if not any(features[k] > 0 for k in ("office_family_word", "office_family_excel", "office_family_powerpoint", "office_family_ole")):
        features["office_family_unknown"] = 1.0

    if include_metadata:
        features["office_extension"] = "unknown"
        features["office_document_family"] = "unknown"
        features["office_indicators"] = []
        features["office_file_name"] = "unknown"

    return features

def extract_office_feature_vector(
    source: Union[str, Path, bytes, bytearray, memoryview, BinaryIO],
    **kwargs: Any,
) -> dict[str, float]:
    return extract_office_features(source, include_metadata=False, **kwargs)

def _read_source(source: Union[str, Path, bytes, bytearray, memoryview, BinaryIO]) -> bytes:
    if isinstance(source, (bytes, bytearray, memoryview)):
        return bytes(source)
    if isinstance(source, (str, Path)):
        with open(source, "rb") as f:
            return f.read()
    return source.read()

__all__ = ["extract_office_features", "extract_office_feature_vector"]
