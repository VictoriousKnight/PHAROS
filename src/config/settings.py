"""
Application configuration for Pharos CDR.

Only settings that affect application behavior belong here.
Secrets and environment-specific values are read from environment variables.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _env(name: str, default: str) -> str:
    return os.getenv(name, default)


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, default))
    except (TypeError, ValueError):
        return default


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, default))
    except (TypeError, ValueError):
        return default


def _env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)

    if value is None:
        return default

    return value.strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


@dataclass(frozen=True)
class Settings:
    """Runtime configuration."""

    # Paths
    project_root: Path = PROJECT_ROOT
    raw_dir: Path = PROJECT_ROOT / "data" / "raw"
    processed_dir: Path = PROJECT_ROOT / "data" / "processed"
    samples_dir: Path = PROJECT_ROOT / "data" / "samples"
    manifests_dir: Path = PROJECT_ROOT / "data" / "manifests"
    models_dir: Path = PROJECT_ROOT / "models"

    # File/resource limits
    max_file_size: int = 64 * 1024 * 1024
    max_read_bytes: int = 64 * 1024 * 1024
    max_zip_entries: int = 10_000
    max_xml_bytes: int = 16 * 1024 * 1024
    max_text_bytes: int = 16 * 1024 * 1024

    # ML
    model_path: Path = PROJECT_ROOT / "models" / "trained" / "random_forest.joblib"
    feature_schema_path: Path = (
        PROJECT_ROOT / "models" / "metadata" / "feature_schema.json"
    )
    model_metadata_path: Path = (
        PROJECT_ROOT / "models" / "metadata" / "model_metadata.json"
    )
    thresholds_path: Path = PROJECT_ROOT / "models" / "metadata" / "thresholds.json"

    # Detection
    detection_threshold: float = 0.5

    # API
    api_host: str = "127.0.0.1"
    api_port: int = 8000
    api_debug: bool = False

    # CDR
    cdr_enabled: bool = True

    # Logging
    log_level: str = "INFO"


def load_settings() -> Settings:
    """Load settings from environment variables."""
    return Settings(
        max_file_size=_env_int(
            "PHAROS_MAX_FILE_SIZE",
            64 * 1024 * 1024,
        ),
        max_read_bytes=_env_int(
            "PHAROS_MAX_READ_BYTES",
            64 * 1024 * 1024,
        ),
        max_zip_entries=_env_int(
            "PHAROS_MAX_ZIP_ENTRIES",
            10_000,
        ),
        max_xml_bytes=_env_int(
            "PHAROS_MAX_XML_BYTES",
            16 * 1024 * 1024,
        ),
        max_text_bytes=_env_int(
            "PHAROS_MAX_TEXT_BYTES",
            16 * 1024 * 1024,
        ),
        detection_threshold=_env_float(
            "PHAROS_DETECTION_THRESHOLD",
            0.5,
        ),
        api_host=_env(
            "PHAROS_API_HOST",
            "127.0.0.1",
        ),
        api_port=_env_int(
            "PHAROS_API_PORT",
            8000,
        ),
        api_debug=_env_bool(
            "PHAROS_API_DEBUG",
            False,
        ),
        cdr_enabled=_env_bool(
            "PHAROS_CDR_ENABLED",
            True,
        ),
        log_level=_env(
            "PHAROS_LOG_LEVEL",
            "INFO",
        ).upper(),
    )


settings = load_settings()


__all__ = [
    "Settings",
    "settings",
    "load_settings",
    "PROJECT_ROOT",
]
