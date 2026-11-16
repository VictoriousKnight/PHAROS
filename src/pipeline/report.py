"""
PHAROS Pipeline - Scan Reporting Engine
---------------------------------------
Formats scanner and decision results into standardized, human-readable
and machine-parsable reports: JSON, Dictionary, and self-contained HTML.
"""

from __future__ import annotations

import html
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Optional


@dataclass
class ScanReport:
    scan_id: str
    file_name: str
    sha256: str
    verdict: str
    disposition: str
    confidence: str
    risk_score: float
    model_probability: Optional[float]
    sanitized: bool
    sanitized_sha256: Optional[str]
    reasons: list[str] = field(default_factory=list)
    threat_findings: list[dict[str, Any]] = field(default_factory=list)
    llm_explanation: Optional[dict[str, Any]] = None
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "file_name": self.file_name,
            "sha256": self.sha256,
            "verdict": self.verdict,
            "disposition": self.disposition,
            "confidence": self.confidence,
            "risk_score": round(self.risk_score, 4),
            "model_probability": round(self.model_probability, 4) if self.model_probability is not None else None,
            "sanitized": self.sanitized,
            "sanitized_sha256": self.sanitized_sha256,
            "reasons": self.reasons,
            "threat_findings": self.threat_findings,
            "llm_explanation": self.llm_explanation,
            "created_at": self.created_at,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    def to_html(self) -> str:
        verdict_color = "#10b981" if self.verdict == "clean" else ("#f59e0b" if self.verdict == "sanitize" else "#ef4444")
        reasons_list = "".join(f"<li>{html.escape(r)}</li>" for r in self.reasons) or "<li>Clean - no anomalies detected</li>"

        return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>PHAROS Scan Report - {html.escape(self.file_name)}</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background: #0f172a; color: #f8fafc; padding: 2rem; margin: 0; }}
    .container {{ max-width: 800px; margin: 0 auto; background: #1e293b; border-radius: 12px; padding: 2rem; box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.3); border: 1px solid #334155; }}
    .header {{ display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #334155; padding-bottom: 1rem; margin-bottom: 1.5rem; }}
    .badge {{ background: {verdict_color}; color: #ffffff; padding: 0.35rem 0.85rem; border-radius: 9999px; font-weight: 700; text-transform: uppercase; font-size: 0.875rem; }}
    .field {{ margin-bottom: 0.75rem; font-size: 0.95rem; }}
    .label {{ color: #94a3b8; font-weight: 600; width: 140px; display: inline-block; }}
    .value {{ font-family: ui-monospace, monospace; color: #e2e8f0; }}
    .section-title {{ font-size: 1.15rem; font-weight: 700; margin-top: 1.5rem; margin-bottom: 0.75rem; color: #38bdf8; }}
    ul {{ padding-left: 1.25rem; color: #cbd5e1; line-height: 1.6; }}
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h2 style="margin: 0; color: #f1f5f9;">PHAROS CDR Threat Report</h2>
      <span class="badge">{html.escape(self.disposition)}</span>
    </div>
    <div class="field"><span class="label">File Name:</span> <span class="value">{html.escape(self.file_name)}</span></div>
    <div class="field"><span class="label">SHA-256:</span> <span class="value">{html.escape(self.sha256)}</span></div>
    <div class="field"><span class="label">Risk Score:</span> <span class="value">{self.risk_score*100:.1f}%</span></div>
    <div class="field"><span class="label">ML Probability:</span> <span class="value">{f"{self.model_probability*100:.1f}%" if self.model_probability is not None else "N/A"}</span></div>
    <div class="field"><span class="label">Sanitized:</span> <span class="value">{'Yes (Clean Package Generated)' if self.sanitized else 'No'}</span></div>
    {f'<div class="field"><span class="label">Clean SHA-256:</span> <span class="value">{html.escape(self.sanitized_sha256)}</span></div>' if self.sanitized_sha256 else ''}

    <div class="section-title">Security Findings & Reasons</div>
    <ul>{reasons_list}</ul>
  </div>
</body>
</html>"""


def build_report(scan_result: Any) -> ScanReport:
    """Generate a ScanReport instance from a scan result."""
    data = scan_result.to_dict() if hasattr(scan_result, "to_dict") else dict(scan_result)

    inp = data.get("input", {})
    file_name = inp.get("source_name") or inp.get("file_name") or "unknown_file"
    sha256 = inp.get("sha256") or data.get("sha256", "unknown_hash")

    decision = data.get("decision", {})
    disposition = decision.get("disposition") or data.get("verdict", "unknown")
    verdict = "clean" if disposition == "pass" else disposition

    findings = []
    cdr_det = data.get("cdr_detection", {})
    if isinstance(cdr_det, Mapping):
        findings = cdr_det.get("detected_threats", [])

    return ScanReport(
        scan_id=data.get("scan_id", "scan_default"),
        file_name=file_name,
        sha256=sha256,
        verdict=verdict,
        disposition=disposition,
        confidence=decision.get("confidence", "high"),
        risk_score=decision.get("score", 0.0),
        model_probability=decision.get("model_probability"),
        sanitized=bool(data.get("sanitized_content") or data.get("sanitized_sha256")),
        sanitized_sha256=data.get("sanitized_sha256"),
        reasons=decision.get("reasons", []),
        threat_findings=findings,
        llm_explanation=data.get("llm_explanation"),
    )


def report_to_html(scan_result: Any) -> str:
    return build_report(scan_result).to_html()


def report_to_dict(scan_result: Any) -> dict[str, Any]:
    return build_report(scan_result).to_dict()


def report_to_json(scan_result: Any) -> str:
    return build_report(scan_result).to_json()


__all__ = [
    "ScanReport",
    "build_report",
    "report_to_html",
    "report_to_dict",
    "report_to_json",
]
