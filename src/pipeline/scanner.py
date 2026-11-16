"""
PHAROS Pipeline - Unified Document Scanner
------------------------------------------
The primary orchestrator for PHAROS:
1. Ingestion & File Type Verification (src.ingestion.file_type)
2. Static Feature Extraction (src.extraction.feature_pipeline)
3. ML Threat Inference (src.ml.predict)
4. CDR Threat Detection & Policy (src.cdr.detector, src.cdr.policy)
5. CDR Disarm & Reconstruction (src.cdr.sanitizer, src.cdr.integrity)
6. Unified Decision Synthesis (src.pipeline.decision)
"""

from __future__ import annotations

import hashlib
import logging
import tempfile
import uuid
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Mapping, Optional

from src.cdr.detector import detect_threats
from src.cdr.integrity import verify_reconstructed_package
from src.cdr.policy import evaluate_policy
from src.cdr.sanitizer import sanitize_document
from src.extraction.feature_pipeline import FeaturePipeline
from src.ingestion.file_type import identify_from_bytes
from src.ml.explain import explain_prediction
from src.ml.predict import predict
from src.pipeline.decision import DecisionResult, make_decision
from src.sandbox import validate_archive_safety

logger = logging.getLogger("pipeline.scanner")


class ScanError(Exception):
    """Base scanner exception."""


class ScanInputError(ScanError):
    """Raised for malformed or missing input."""


class ScanLimitError(ScanError):
    """Raised when file limits are exceeded."""


class ScanStageError(ScanError):
    """Raised when a specific scan stage fails."""


class ScanVerdict(str, Enum):
    PASS = "pass"
    SANITIZE = "sanitize"
    REVIEW = "review"
    REJECT = "reject"


@dataclass
class ScanInput:
    content: bytes
    source_name: str
    sha256: str
    size: int


@dataclass
class ScanConfig:
    run_ml: bool = True
    run_cdr_detection: bool = True
    run_policy: bool = True
    sanitize: bool = True
    verify_sanitized: bool = True
    include_llm_context: bool = True
    model_threshold: float = 0.50


@dataclass
class ScanResult:
    scan_id: str
    input: ScanInput
    verdict: ScanVerdict
    decision: DecisionResult
    features: dict[str, Any] = field(default_factory=dict)
    prediction: Optional[dict[str, Any]] = None
    cdr_detection: Optional[dict[str, Any]] = None
    policy: Optional[dict[str, Any]] = None
    sanitized_content: Optional[bytes] = None
    sanitized_sha256: Optional[str] = None
    integrity: Optional[dict[str, Any]] = None
    llm_explanation: Optional[dict[str, Any]] = None

    def to_dict(self, *, include_content: bool = False) -> dict[str, Any]:
        res = {
            "scan_id": self.scan_id,
            "verdict": self.verdict.value,
            "input": {
                "source_name": self.input.source_name,
                "sha256": self.input.sha256,
                "size": self.input.size,
            },
            "decision": self.decision.to_dict(),
            "prediction": self.prediction,
            "cdr_detection": self.cdr_detection,
            "policy": self.policy,
            "sanitized": self.sanitized_content is not None,
            "sanitized_sha256": self.sanitized_sha256,
            "integrity": self.integrity,
            "llm_explanation": self.llm_explanation,
        }
        if include_content and self.sanitized_content:
            res["sanitized_content"] = self.sanitized_content
        return res


def scan_bytes(
    data: bytes,
    *,
    file_name: str = "document.bin",
    config: Optional[ScanConfig] = None,
) -> ScanResult:
    """
    Execute the full end-to-end scanning pipeline on raw document bytes.
    """
    cfg = config or ScanConfig()

    if not data:
        raise ScanInputError("No data provided for scanning.")

    sha256 = hashlib.sha256(data).hexdigest()
    scan_id = f"scan_{uuid.uuid4().hex[:12]}"
    logger.info("Starting scan", extra={"scan_id": scan_id})
    inp = ScanInput(content=data, source_name=file_name, sha256=sha256, size=len(data))

    # Pre-analysis sandbox safety check (guard against zip bombs and zip-slip path traversal)
    validate_archive_safety(data)

    # Stage 1: Feature Extraction
    extracted_features: dict[str, Any] = {}
    try:
        pipeline = FeaturePipeline()
        # Create a temporary file with the original extension so OOXML, VBA,
        # OLE, and specialized extractors can fully inspect the container.
        ext = Path(file_name).suffix or ".bin"
        with tempfile.NamedTemporaryFile(suffix=ext, delete=False) as tf:
            tf.write(data)
            temp_path = Path(tf.name)
        try:
            feat_res = pipeline.analyze_file(temp_path)
            extracted_features = feat_res.feature_vector
        finally:
            temp_path.unlink(missing_ok=True)
    except Exception as exc:
        logger.warning("Feature extraction failed: %s", exc)

    # Stage 2: Machine Learning Threat Prediction
    pred_res = None
    llm_context = None
    if cfg.run_ml and extracted_features:
        try:
            pred_res = predict(extracted_features, threshold=cfg.model_threshold)
            if cfg.include_llm_context:
                exp = explain_prediction(extracted_features, threshold=cfg.model_threshold)
                llm_context = exp.to_dict()
        except Exception as exc:
            logger.warning("ML prediction failed: %s", exc)

    # Stage 3: CDR Threat Detection
    cdr_det = None
    if cfg.run_cdr_detection:
        try:
            det_res = detect_threats(data)
            cdr_det = det_res.to_dict()
        except Exception as exc:
            logger.warning("CDR detection failed: %s", exc)

    # Stage 4: Policy Evaluation
    cdr_pol = None
    if cfg.run_policy and cdr_det:
        try:
            cdr_pol = evaluate_policy(cdr_det)
        except Exception as exc:
            logger.warning("CDR policy evaluation failed: %s", exc)

    # Stage 5: Final Decision Synthesis
    decision = make_decision(
        features=extracted_features,
        ml_prediction=pred_res,
        cdr_detection=cdr_det,
        cdr_policy=cdr_pol,
    )

    # Stage 6: Content Disarm and Reconstruction (if required or configured)
    sanitized_bytes = None
    sanitized_hash = None
    integrity_report = None

    should_sanitize = cfg.sanitize and (
        decision.requires_sanitization or (cdr_pol and cdr_pol.get("action") == "sanitize")
    )

    if should_sanitize:
        try:
            sanitized_bytes = sanitize_document(data)
            if sanitized_bytes:
                sanitized_hash = hashlib.sha256(sanitized_bytes).hexdigest()
                if cfg.verify_sanitized:
                    integrity_report = verify_reconstructed_package(sanitized_bytes, strict=True)
        except Exception as exc:
            logger.error("Sanitization stage failed: %s", exc)

    verdict_map = {
        "pass": ScanVerdict.PASS,
        "sanitize": ScanVerdict.SANITIZE,
        "review": ScanVerdict.REVIEW,
        "reject": ScanVerdict.REJECT,
    }
    final_verdict = verdict_map.get(decision.disposition.value, ScanVerdict.REVIEW)

    return ScanResult(
        scan_id=scan_id,
        input=inp,
        verdict=final_verdict,
        decision=decision,
        features=extracted_features,
        prediction=pred_res,
        cdr_detection=cdr_det,
        policy=cdr_pol,
        sanitized_content=sanitized_bytes,
        sanitized_sha256=sanitized_hash,
        integrity=integrity_report,
        llm_explanation=llm_context,
    )


def scan_file(
    file_path: str | Path,
    *,
    config: Optional[ScanConfig] = None,
) -> ScanResult:
    """Execute scanning pipeline on a file from disk."""
    p = Path(file_path)
    if not p.is_file():
        raise ScanInputError(f"Target file not found: {p}")
    return scan_bytes(p.read_bytes(), file_name=p.name, config=config)


# Scanner aliases
scan = scan_bytes

__all__ = [
    "ScanError",
    "ScanInputError",
    "ScanLimitError",
    "ScanStageError",
    "ScanVerdict",
    "ScanInput",
    "ScanConfig",
    "ScanResult",
    "scan_bytes",
    "scan_file",
    "scan",
]
