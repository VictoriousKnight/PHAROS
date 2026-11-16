# -*- coding: utf-8 -*-
"""Diagnostic utility for PHAROS.

Run via:
    python -m src.ml.diagnostics

The script performs a series of non‑destructive health checks:
- Environment configuration (required env vars)
- ML model file availability and basic compatibility
- Gemini API key presence and model ID validation
- Ollama server reachability
- Database connectivity (read‑only)
- Feature extraction sanity on a safe dummy payload

It prints a concise, human‑readable summary and exits with status 0 on success,
or a non‑zero code if any check fails. No production data is modified.
"""

import os
import sys
import json
import hashlib
import logging
import traceback
from typing import Any

# Import project modules – these imports are expected to succeed within the
# repository's virtual environment.
from src.config import settings
from src.ml.predict import Predictor
from src.ml.llm import _validate_gemini_model, ConfigurationError
from src.extraction.feature_pipeline import FeaturePipeline

# Database check – the web package creates a SQLAlchemy engine on import.
# Importing ``web.db`` is safe because it does not perform destructive actions.
from web import db as web_db

logger = logging.getLogger(__name__)


def _print_status(name: str, ok: bool, details: str = "") -> None:
    """Utility to print a uniform status line.

    Args:
        name: The check name.
        ok:   Whether the check succeeded.
        details: Optional additional information displayed when ``ok`` is
                 ``False``.
    """
    status = "OK" if ok else "FAIL"
    line = f"[{status}] {name}"
    if not ok and details:
        line += f": {details}"
    print(line)


def _check_env() -> bool:
    """Validate required environment variables.

    Returns ``True`` if all required variables are present, otherwise prints
    failures and returns ``False``.
    """
    required = ["GEMINI_API_KEY", "GEMINI_MODEL", "OLLAMA_HOST"]
    all_ok = True
    for var in required:
        if not os.getenv(var):
            _print_status(f"Env var {var}", False, "not set")
            all_ok = False
        else:
            _print_status(f"Env var {var}", True)
    return all_ok


def _check_model() -> bool:
    """Attempt to load the trained ML model and perform a dummy prediction.
    """
    try:
        predictor = Predictor()
        # ``is_available`` is a property we added earlier – if missing we fallback.
        if not getattr(predictor, "is_available", True):
            _print_status("ML model availability", False, "model not available")
            return False
        # Create a minimal feature vector with a single zero feature.
        dummy_features = {"dummy_feature": 0.0}
        pred = predictor.predict(dummy_features)
        # ``predict`` may return a dict or tuple; we only care that it does not raise.
        _print_status("ML model load & predict", True)
        return True
    except Exception as exc:  # pragma: no cover – defensive
        _print_status("ML model load & predict", False, str(exc))
        logger.debug("Exception during model check", exc_info=True)
        return False


def _check_gemini() -> bool:
    """Validate Gemini configuration and make a cheap test request.
    """
    model_id = os.getenv("GEMINI_MODEL", "")
    try:
        _validate_gemini_model(model_id)
        _print_status("Gemini model ID validation", True)
    except ConfigurationError as err:
        _print_status("Gemini model ID validation", False, str(err))
        return False
    # If an API key is present we can issue a very small request.
    api_key = os.getenv("GEMINI_API_KEY", "")
    if not api_key:
        _print_status("Gemini API key presence", False, "not set")
        return False
    _print_status("Gemini API key presence", True)
    # Perform a lightweight request using a minimal dummy scan dictionary.
    from src.ml.llm import _generate_gemini_brief
    try:
        dummy_scan = {
            "threat_score": 0.0,
            "verdict": "CLEAN",
            "findings": [],
            "features": {},
        }
        response = _generate_gemini_brief(dummy_scan, api_key=api_key)
        _print_status("Gemini connectivity test", True)
        return True
    except Exception as exc:
        _print_status("Gemini connectivity test", False, str(exc))
        logger.debug("Gemini request failed", exc_info=True)
        return False


def _check_ollama() -> bool:
    """Check that the Ollama host is reachable via its API tags endpoint."""
    import requests
    host = os.getenv("OLLAMA_HOST", "http://localhost:11434").strip()
    if not host.startswith("http://") and not host.startswith("https://"):
        host = f"http://{host}"
    endpoint = f"{host.rstrip('/')}/api/tags"
    try:
        resp = requests.get(endpoint, timeout=5)
        if resp.status_code == 200:
            _print_status("Ollama connectivity test", True)
            return True
        _print_status("Ollama connectivity test", False, f"HTTP status {resp.status_code}")
        return False
    except Exception as exc:
        _print_status("Ollama connectivity test", False, str(exc))
        logger.debug("Ollama request failed", exc_info=True)
        return False


def _check_database() -> bool:
    """Run a lightweight read‑only query against the configured DB.

    Uses the same Turso HTTP API or local SQLite helpers that the rest of
    web/db.py uses – no SQLAlchemy dependency required.
    """
    try:
        if web_db.is_turso_enabled():
            # Turso: execute a cheap read via the HTTP pipeline
            web_db._turso_execute("SELECT 1")
        else:
            # Local SQLite: open a connection and run a trivial query
            conn = web_db._get_local_connection()
            try:
                conn.execute("SELECT 1")
            finally:
                conn.close()
        _print_status("Database connectivity", True)
        return True
    except Exception as exc:
        _print_status("Database connectivity", False, str(exc))
        logger.debug("Database check failed", exc_info=True)
        return False


def _check_feature_extraction() -> bool:
    """Run the FeaturePipeline on a safe dummy payload.
    """
    try:
        pipeline = FeaturePipeline()
        dummy_data = b"dummy"
        analysis = pipeline.analyze(dummy_data)
        # Verify that we obtained a feature vector with at least one entry.
        if not analysis.feature_vector:
            _print_status("Feature extraction", False, "empty feature vector")
            return False
        _print_status("Feature extraction", True)
        return True
    except Exception as exc:
        _print_status("Feature extraction", False, str(exc))
        logger.debug("Feature extraction failed", exc_info=True)
        return False


def main() -> None:
    """Entry point for the ``python -m src.ml.diagnostics`` command.
    """
    # Configure a minimal console logger – avoid interfering with the project's
    # rotating file logger configuration.
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    checks = [
        _check_env,
        _check_model,
        _check_gemini,
        _check_ollama,
        _check_database,
        _check_feature_extraction,
    ]

    all_ok = True
    for fn in checks:
        try:
            ok = fn()
        except Exception:  # pragma: no cover – unexpected guard
            ok = False
            logger.error("Unexpected error in %s", fn.__name__, exc_info=True)
        all_ok = all_ok and ok

    if all_ok:
        print("\nAll diagnostics passed.")
        sys.exit(0)
    else:
        print("\nOne or more diagnostics failed. See above messages.")
        sys.exit(1)


if __name__ == "__main__":
    main()
