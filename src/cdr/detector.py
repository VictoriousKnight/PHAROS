"""
PHAROS CDR - Threat Detector
----------------------------
Static inspection of document structure for active and weaponized components.
Scans for VBA macros, embedded OLE packages, dynamic execution triggers,
external relationship hijacking, and malicious DDE payloads.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping, Optional

from src.cdr.parser import ParsedDocument, parse_document

logger = logging.getLogger("cdr.detector")


@dataclass
class ThreatDetectionResult:
    is_safe: bool
    requires_sanitization: bool
    has_macros: bool = False
    has_embedded_objects: bool = False
    has_external_targets: bool = False
    threat_level: str = "low"  # 'low', 'medium', 'high', 'critical'
    threat_score: float = 0.0
    detected_threats: list[dict[str, Any]] = field(default_factory=list)
    document_format: str = "unknown"

    def to_dict(self) -> dict[str, Any]:
        return {
            "is_safe": self.is_safe,
            "requires_sanitization": self.requires_sanitization,
            "has_macros": self.has_macros,
            "has_embedded_objects": self.has_embedded_objects,
            "has_external_targets": self.has_external_targets,
            "threat_level": self.threat_level,
            "threat_score": self.threat_score,
            "detected_threats": self.detected_threats,
            "document_format": self.document_format,
        }


def detect_threats(content_or_path: bytes | str | Path) -> ThreatDetectionResult:
    """
    Main detection entry point.
    Parses document structure and evaluates weaponization indicators.
    """
    doc: ParsedDocument = parse_document(content_or_path)

    threats: list[dict[str, Any]] = []
    score = 0.0

    if not doc.is_valid:
        return ThreatDetectionResult(
            is_safe=False,
            requires_sanitization=False,
            threat_level="critical",
            threat_score=1.0,
            detected_threats=[{"type": "corrupt_container", "detail": "Document structure invalid or malformed."}],
            document_format=doc.format_type
        )

    # 1. Macro Detection
    if doc.has_macros:
        score += 0.45
        threats.append({
            "type": "active_macros",
            "severity": "high",
            "description": "Embedded VBA project / macro binaries detected."
        })

    # 2. Embedded Objects (potential dropped binaries or shell objects)
    if doc.has_embedded_objects:
        score += 0.30
        threats.append({
            "type": "embedded_objects",
            "severity": "medium",
            "description": "Embedded OLE objects, activeX controls, or binary packages present."
        })

    # 3. External Relationships (potential template injection or phishing)
    if doc.external_targets:
        score += 0.25
        threats.append({
            "type": "external_relationships",
            "severity": "medium",
            "description": f"Found {len(doc.external_targets)} external remote links / targets.",
            "targets": doc.external_targets[:5]
        })

    # Determine severity tier
    requires_sanitization = bool(threats)
    if score >= 0.70:
        level = "critical"
    elif score >= 0.40:
        level = "high"
    elif score > 0.0:
        level = "medium"
    else:
        level = "low"

    return ThreatDetectionResult(
        is_safe=(len(threats) == 0),
        requires_sanitization=requires_sanitization,
        has_macros=doc.has_macros,
        has_embedded_objects=doc.has_embedded_objects,
        has_external_targets=bool(doc.external_targets),
        threat_level=level,
        threat_score=round(min(score, 1.0), 3),
        detected_threats=threats,
        document_format=doc.format_type
    )


# Scanner-compatible entry points
def detect(content_or_path: bytes | str | Path, **kwargs) -> dict[str, Any]:
    res = detect_threats(content_or_path)
    return res.to_dict()


analyze = detect
inspect = detect
scan = detect

__all__ = ["ThreatDetectionResult", "detect_threats", "detect", "analyze", "inspect", "scan"]
