"""
PHAROS Web - Concurrent Document Scanning Service
-------------------------------------------------
Asynchronous worker service orchestrating multi-client requests.
Runs ingestion, ML inference, CDR disarm & reconstruction, and saves
sanitized deliverables in a safe storage repository.
"""

from __future__ import annotations

import concurrent.futures
import json
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Optional

from src.pipeline.scanner import ScanConfig, scan_bytes
from src.sandbox import run_sandboxed_scan, SandboxSecurityViolation
from src.ml.utils import flatten_prediction
from src.ml.llm import generate_brief
from web.db import record_scan

logger = logging.getLogger("web.scan_service")

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SANITIZED_STORAGE = PROJECT_ROOT / "outputs" / "sanitized"
SANITIZED_STORAGE.mkdir(parents=True, exist_ok=True)

# Thread pool executor for multi-client processing
_EXECUTOR = concurrent.futures.ThreadPoolExecutor(max_workers=8, thread_name_prefix="pharos-scan")

# In-memory status tracking for active jobs
_JOB_STATUS: dict[str, dict[str, Any]] = {}


@dataclass
class JobState:
    scan_id: str
    status: str  # 'queued', 'processing', 'completed', 'failed'
    stage: str
    percent: int
    result: Optional[dict[str, Any]] = None
    error: Optional[str] = None
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


def _process_scan_task(
    scan_id: str,
    file_bytes: bytes,
    file_name: str,
    user_id: Optional[int],
) -> None:
    """Worker task executed concurrently."""
    try:
        _JOB_STATUS[scan_id] = {
            "status": "processing",
            "stage": "Parsing container architecture and validating format...",
            "percent": 20,
        }

        # Configure scanner
        cfg = ScanConfig(
            run_ml=True,
            run_cdr_detection=True,
            run_policy=True,
            sanitize=True,
            verify_sanitized=True,
            include_llm_context=True,
        )

        _JOB_STATUS[scan_id]["stage"] = "Executing static analysis within isolated security sandbox..."
        _JOB_STATUS[scan_id]["percent"] = 50

        # Execute inside defensive sandbox (process boundary, decompression bomb guard, timeout limit)
        raw_dict, sanitized_content, verdict_str, risk_score, sanitized_sha256, orig_sha256 = run_sandboxed_scan(
            file_bytes=file_bytes,
            file_name=file_name,
            scanner_config={
                "run_ml": True,
                "run_cdr_detection": True,
                "run_policy": True,
                "sanitize": True,
                "verify_sanitized": True,
                "include_llm_context": True,
            }
        )

        _JOB_STATUS[scan_id]["stage"] = "Neutralizing active elements & reconstructing package..."
        _JOB_STATUS[scan_id]["percent"] = 80

        # Save sanitized file to storage if generated
        sanitized_path_str = None
        if sanitized_content:
            # Normalize extension to .docx for sanitized clean deliverables
            base_stem = Path(file_name).stem
            clean_filename = f"{base_stem}_clean_{scan_id[:8]}.docx"
            target_path = SANITIZED_STORAGE / clean_filename
            target_path.write_bytes(sanitized_content)
            sanitized_path_str = str(target_path)

        # -----------------------------------------------------------------
        # 1️⃣ Gather raw scanner output and flatten ML prediction
        # -----------------------------------------------------------------
        prediction_data = raw_dict.get("prediction")
        ml_flat = flatten_prediction(prediction_data) if prediction_data else {}

        # -----------------------------------------------------------------
        # 2️⃣ Ask the LLM for a human‑readable executive brief (optional)
        # -----------------------------------------------------------------
        try:
            llm_brief = generate_brief(raw_dict)
        except Exception as exc:  # noqa: BLE001 – ensure the job never crashes
            logger.warning("LLM brief generation failed: %s", exc)
            llm_brief = {
                "summary_rationale": "LLM integration unavailable.",
                "top_contributions": [],
            }

        # Merge everything into a single dict that will be persisted / returned
        res_dict = {
            **raw_dict,
            **ml_flat,
            "llm_explanation": llm_brief,
        }

        # Save to user_database
        record_scan(
            scan_id=scan_id,
            user_id=user_id,
            file_name=file_name,
            original_sha256=orig_sha256,
            clean_sha256=sanitized_sha256,
            verdict=verdict_str,
            risk_score=risk_score,
            sanitized_file_path=sanitized_path_str,
            summary_json=json.dumps(res_dict),
        )

        _JOB_STATUS[scan_id] = {
            "status": "completed",
            "stage": "Document processing & reconstruction complete",
            "percent": 100,
            "result": res_dict,
            "sanitized_file_path": sanitized_path_str,
        }

    except Exception as exc:
        logger.error("Scan job %s failed: %s", scan_id, exc, exc_info=True)
        _JOB_STATUS[scan_id] = {
            "status": "failed",
            "stage": "Error during processing",
            "percent": 100,
            "error": str(exc),
        }


def submit_scan(
    file_bytes: bytes,
    file_name: str,
    user_id: Optional[int] = None,
) -> str:
    """Enqueue a new scan job for asynchronous processing."""
    scan_id = f"pharos_{uuid.uuid4().hex[:12]}"
    _JOB_STATUS[scan_id] = {
        "status": "queued",
        "stage": "Queued for analysis...",
        "percent": 5,
    }
    _EXECUTOR.submit(_process_scan_task, scan_id, file_bytes, file_name, user_id)
    return scan_id


def get_job_status(scan_id: str) -> dict[str, Any]:
    """Retrieve the live progress or final result of a scan job."""
    if scan_id in _JOB_STATUS:
        status = _JOB_STATUS[scan_id]
        if status.get('status') == 'completed':
            # Remove in‑memory entry to avoid stale data on future requests.
            _JOB_STATUS.pop(scan_id, None)
        return status

    # Check persistence DB if job has aged out of memory
    from web.db import get_scan_by_id
    rec = get_scan_by_id(scan_id)
    if rec:
        res_data = json.loads(rec["summary_json"]) if rec["summary_json"] else {}
        return {
            "status": "completed",
            "stage": "Document processing & reconstruction complete",
            "percent": 100,
            "result": res_data,
            "sanitized_file_path": rec["sanitized_file_path"],
        }

    return {"status": "not_found", "error": "Scan ID not found."}
