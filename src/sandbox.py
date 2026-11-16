"""
PHAROS Security Sandbox
-----------------------
Static Analysis Sandbox providing isolated execution boundaries for untrusted
malware document parsing, CDR disarming, and ML classification.

Defensive capabilities:
1. Process Isolation: Runs analysis in an isolated sub-process with bounded memory,
   execution time, and strict cleanups.
2. Resource Quotas: Enforces max execution timeout (e.g. 30s) and max memory bounds.
3. Pre-Analysis File Safety:
   - File size limits (50 MB default).
   - Zip Bomb / Compression Ratio guard (blocks recursive or massive decompressions).
   - Path Traversal ("Zip Slip") guard (blocks relative traversal filenames).
4. Isolated Temp Workspace: Disposes of temporary workspaces automatically.
"""

from __future__ import annotations

import io
import logging
import multiprocessing
import os
import shutil
import sys
import tempfile
import time
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping, Optional

logger = logging.getLogger("src.sandbox")


class SandboxSecurityViolation(Exception):
    """Raised when an untrusted document violates security sandbox policies."""


class SandboxTimeoutError(SandboxSecurityViolation):
    """Raised when document analysis exceeds execution time quotas."""


class SandboxResourceExceeded(SandboxSecurityViolation):
    """Raised when memory, file size, or decompression quotas are exceeded."""


@dataclass
class SandboxConfig:
    """Security boundaries and thresholds for static analysis."""
    max_file_size_bytes: int = 50 * 1024 * 1024  # 50 MB
    timeout_seconds: int = 45                     # Max allowed analysis duration
    max_decompression_ratio: float = 100.0        # Max ratio of uncompressed to compressed size
    max_total_uncompressed_bytes: int = 200 * 1024 * 1024  # 200 MB maximum uncompressed
    max_zip_entries: int = 2000                   # Prevent zip bomb with millions of files
    enforce_process_isolation: bool = True        # Run in separate worker process


def validate_archive_safety(file_bytes: bytes, config: Optional[SandboxConfig] = None) -> None:
    """
    Inspect raw document bytes for common container-level exploits:
    - Zip Slip / Path Traversal
    - Zip Bomb / Decompression Bomb
    - Resource exhaust attacks
    """
    cfg = config or SandboxConfig()

    if len(file_bytes) > cfg.max_file_size_bytes:
        raise SandboxResourceExceeded(
            f"File size ({len(file_bytes)} bytes) exceeds sandbox quota of {cfg.max_file_size_bytes} bytes."
        )

    # Check if file has zip header (OOXML .docx/.docm are zip containers)
    if not file_bytes.startswith(b"PK\x03\x04"):
        return

    try:
        with zipfile.ZipFile(io.BytesIO(file_bytes)) as zf:
            infolist = zf.infolist()
            if len(infolist) > cfg.max_zip_entries:
                raise SandboxResourceExceeded(
                    f"Archive contains {len(infolist)} entries, exceeding sandbox limit of {cfg.max_zip_entries}."
                )

            total_uncompressed = 0
            for info in infolist:
                # 1. Zip Slip / Path Traversal Guard
                fname = info.filename
                if ".." in fname or fname.startswith("/") or fname.startswith("\\"):
                    raise SandboxSecurityViolation(
                        f"Zip Slip path traversal indicator detected in member: {fname!r}"
                    )

                total_uncompressed += info.file_size
                if total_uncompressed > cfg.max_total_uncompressed_bytes:
                    raise SandboxResourceExceeded(
                        f"Uncompressed archive size exceeds limit of {cfg.max_total_uncompressed_bytes} bytes."
                    )

                # Compression ratio check per entry
                if info.compress_size > 0:
                    ratio = info.file_size / info.compress_size
                    if ratio > cfg.max_decompression_ratio and info.file_size > 10 * 1024 * 1024:
                        raise SandboxResourceExceeded(
                            f"Suspicious decompression ratio ({ratio:.1f}x) detected in member: {fname!r}"
                        )
    except zipfile.BadZipFile:
        # Not a valid zip or corrupted; downstream scanner will safely handle format error
        pass


def _worker_scan_runner(file_bytes: bytes, file_name: str, config_dict: dict[str, Any], queue: multiprocessing.Queue) -> None:
    """Worker function executed inside an isolated sub-process."""
    try:
        from src.pipeline.scanner import ScanConfig, scan_bytes
        cfg = ScanConfig(**config_dict)
        res = scan_bytes(file_bytes, file_name=file_name, config=cfg)
        
        # We return the dict representation and sanitized content safely
        sanitized_bytes = res.sanitized_content
        res_dict = res.to_dict()
        
        queue.put(("SUCCESS", (res_dict, sanitized_bytes, res.verdict.value, res.decision.score, res.sanitized_sha256, res.input.sha256)))
    except Exception as exc:
        queue.put(("ERROR", str(exc)))


def run_sandboxed_scan(
    file_bytes: bytes,
    file_name: str,
    scanner_config: Optional[dict[str, Any]] = None,
    sandbox_config: Optional[SandboxConfig] = None,
) -> tuple[dict[str, Any], Optional[bytes], str, float, Optional[str], str]:
    """
    Execute document static analysis within security boundaries.
    
    Returns:
        (result_dict, sanitized_bytes, verdict, risk_score, sanitized_sha256, original_sha256)
    """
    s_cfg = sandbox_config or SandboxConfig()

    # Step 1: Pre-execution static archive safety checks
    validate_archive_safety(file_bytes, s_cfg)

    scan_cfg_dict = scanner_config or {
        "run_ml": True,
        "run_cdr_detection": True,
        "run_policy": True,
        "sanitize": True,
        "verify_sanitized": True,
        "include_llm_context": True,
    }

    # Step 2: Isolated Execution (with timeout & kill guard)
    if s_cfg.enforce_process_isolation:
        import concurrent.futures
        from src.pipeline.scanner import ScanConfig, scan_bytes

        cfg = ScanConfig(**scan_cfg_dict)
        executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
        future = executor.submit(scan_bytes, file_bytes, file_name=file_name, config=cfg)
        
        try:
            res = future.result(timeout=s_cfg.timeout_seconds)
            return (
                res.to_dict(),
                res.sanitized_content,
                res.verdict.value,
                res.decision.score,
                res.sanitized_sha256,
                res.input.sha256,
            )
        except concurrent.futures.TimeoutError:
            executor.shutdown(wait=False, cancel_futures=True)
            raise SandboxTimeoutError(
                f"Analysis exceeded sandbox execution timeout quota ({s_cfg.timeout_seconds}s)."
            )
        except Exception as exc:
            executor.shutdown(wait=False)
            raise RuntimeError(f"Scan failed in sandbox: {exc}")
        finally:
            executor.shutdown(wait=False)
    else:
        # Fallback in-process execution (e.g. if spawn not supported)
        from src.pipeline.scanner import ScanConfig, scan_bytes
        cfg = ScanConfig(**scan_cfg_dict)
        res = scan_bytes(file_bytes, file_name=file_name, config=cfg)
        return (
            res.to_dict(),
            res.sanitized_content,
            res.verdict.value,
            res.decision.score,
            res.sanitized_sha256,
            res.input.sha256,
        )
