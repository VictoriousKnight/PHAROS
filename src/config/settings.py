"""
pharos-cdr/src/config/settings.py
=================================

Central configuration for the Pharos CDR project.

Design goals
------------

- Environment-driven configuration.
- Safe, deterministic defaults.
- Explicit filesystem locations.
- No secrets embedded in source code.
- Bounded upload, archive, parsing, extraction, and API resources.
- Configuration suitable for static malware/document analysis.
- No execution of submitted documents, macros, scripts, or payloads.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping, Optional

# ---------------------------------------------------------------------------
# Project paths
# ---------------------------------------------------------------------------

MODULE_NAME = "pharos_cdr.src.config.settings"
SETTINGS_VERSION = "1.0.0"

PROJECT_ROOT = Path(
    os.getenv(
        "PHAROS_CDR_PROJECT_ROOT",
        Path(__file__).resolve().parents[2],
    )
).resolve()

SRC_ROOT = PROJECT_ROOT / "src"
DATA_ROOT = PROJECT_ROOT / "data"
RAW_DATA_ROOT = DATA_ROOT / "raw"
PROCESSED_DATA_ROOT = DATA_ROOT / "processed"
SAMPLES_ROOT = DATA_ROOT / "samples"
MANIFESTS_ROOT = DATA_ROOT / "manifests"

MODELS_ROOT = PROJECT_ROOT / "models"
TRAINED_MODELS_ROOT = MODELS_ROOT / "trained"
MODEL_METADATA_ROOT = MODELS_ROOT / "metadata"

OUTPUTS_ROOT = PROJECT_ROOT / "outputs"
SANITIZED_OUTPUT_ROOT = OUTPUTS_ROOT / "sanitized"
REPORT_OUTPUT_ROOT = OUTPUTS_ROOT / "reports"
PLOT_OUTPUT_ROOT = OUTPUTS_ROOT / "plots"

WEB_ROOT = PROJECT_ROOT / "web"
WEB_TEMPLATE_ROOT = WEB_ROOT / "templates"
WEB_STATIC_ROOT = WEB_ROOT / "static"

DEFAULT_MODEL_PATH = TRAINED_MODELS_ROOT / "random_forest.joblib"

DEFAULT_FEATURE_SCHEMA_PATH = MODEL_METADATA_ROOT / "feature_schema.json"

DEFAULT_MODEL_METADATA_PATH = MODEL_METADATA_ROOT / "model_metadata.json"

DEFAULT_THRESHOLDS_PATH = MODEL_METADATA_ROOT / "thresholds.json"


# ---------------------------------------------------------------------------
# Environment helpers
# ---------------------------------------------------------------------------


_TRUE_VALUES = {
    "1",
    "true",
    "yes",
    "y",
    "on",
    "enabled",
}

_FALSE_VALUES = {
    "0",
    "false",
    "no",
    "n",
    "off",
    "disabled",
}


def _env(
    name: str,
    default: Optional[str] = None,
) -> Optional[str]:
    value = os.getenv(name)

    if value is None:
        return default

    value = value.strip()

    return value if value else default


def _env_bool(
    name: str,
    default: bool,
) -> bool:
    value = _env(name)

    if value is None:
        return default

    normalized = value.lower()

    if normalized in _TRUE_VALUES:
        return True

    if normalized in _FALSE_VALUES:
        return False

    return default


def _env_int(
    name: str,
    default: int,
    *,
    minimum: Optional[int] = None,
    maximum: Optional[int] = None,
) -> int:
    value = _env(name)

    if value is None:
        result = default
    else:
        try:
            result = int(value)
        except ValueError:
            result = default

    if minimum is not None:
        result = max(
            minimum,
            result,
        )

    if maximum is not None:
        result = min(
            maximum,
            result,
        )

    return result


def _env_float(
    name: str,
    default: float,
    *,
    minimum: Optional[float] = None,
    maximum: Optional[float] = None,
) -> float:
    value = _env(name)

    if value is None:
        result = default
    else:
        try:
            result = float(value)
        except ValueError:
            result = default

    if minimum is not None:
        result = max(
            minimum,
            result,
        )

    if maximum is not None:
        result = min(
            maximum,
            result,
        )

    return result


def _env_path(
    name: str,
    default: Path,
) -> Path:
    value = _env(name)

    if value is None:
        return default

    path = Path(value)

    if not path.is_absolute():
        path = PROJECT_ROOT / path

    return path.resolve()


def _env_csv(
    name: str,
    default: tuple[str, ...],
) -> tuple[str, ...]:
    value = _env(name)

    if value is None:
        return default

    values = [item.strip() for item in value.split(",") if item.strip()]

    return tuple(values) or default


# ---------------------------------------------------------------------------
# Security-sensitive defaults
# ---------------------------------------------------------------------------


DEFAULT_MAX_UPLOAD_BYTES = 100 * 1024 * 1024
DEFAULT_MAX_ANALYSIS_BYTES = 25 * 1024 * 1024

DEFAULT_MAX_ZIP_ENTRIES = 10_000
DEFAULT_MAX_ZIP_ENTRY_BYTES = 100 * 1024 * 1024
DEFAULT_MAX_ZIP_TOTAL_UNCOMPRESSED_BYTES = 250 * 1024 * 1024
DEFAULT_MAX_ZIP_TOTAL_COMPRESSED_BYTES = 100 * 1024 * 1024

DEFAULT_MAX_SOURCE_BYTES = 25 * 1024 * 1024
DEFAULT_MAX_STRING_COUNT = 100_000
DEFAULT_MAX_EVIDENCE_COUNT = 20_000
DEFAULT_MAX_FEATURE_COUNT = 100_000
DEFAULT_MAX_RECURSION_DEPTH = 12

DEFAULT_MAX_REPORT_BYTES = 25 * 1024 * 1024
DEFAULT_MAX_FINDINGS = 20_000

DEFAULT_MODEL_THRESHOLD = 0.50
DEFAULT_HIGH_RISK_THRESHOLD = 0.80
DEFAULT_REVIEW_THRESHOLD = 0.50


# ---------------------------------------------------------------------------
# Allowed file types
# ---------------------------------------------------------------------------

DEFAULT_ALLOWED_EXTENSIONS = (
    ".doc",
    ".docm",
    ".docx",
    ".dot",
    ".dotm",
    ".dotx",
    ".xls",
    ".xlsb",
    ".xlsm",
    ".xlsx",
    ".xlt",
    ".xltm",
    ".xltx",
    ".ppt",
    ".pptm",
    ".pptx",
    ".pot",
    ".potm",
    ".potx",
    ".pps",
    ".ppsm",
    ".ppsx",
    ".rtf",
    ".pdf",
    ".txt",
    ".csv",
    ".js",
    ".jse",
    ".vbs",
    ".vbe",
    ".ps1",
    ".psm1",
    ".bat",
    ".cmd",
    ".sh",
)

DEFAULT_ALLOWED_MIME_TYPES = (
    "application/octet-stream",
    "application/pdf",
    "application/rtf",
    "application/msword",
    "application/vnd.ms-excel",
    "application/vnd.ms-powerpoint",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.template",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.template",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    "application/vnd.openxmlformats-officedocument.presentationml.template",
    "application/vnd.openxmlformats-officedocument.presentationml.slideshow",
    "application/vnd.ms-word.document.macroenabled.12",
    "application/vnd.ms-word.template.macroenabled.12",
    "application/vnd.ms-excel.sheet.macroenabled.12",
    "application/vnd.ms-excel.template.macroenabled.12",
    "application/vnd.ms-powerpoint.presentation.macroenabled.12",
    "application/vnd.ms-powerpoint.template.macroenabled.12",
    "application/vnd.ms-powerpoint.slideshow.macroenabled.12",
    "text/plain",
    "text/csv",
    "text/javascript",
    "application/javascript",
    "application/x-javascript",
    "text/vbscript",
    "application/x-sh",
)


# ---------------------------------------------------------------------------
# Configuration dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PathSettings:
    """Project filesystem locations."""

    project_root: Path = PROJECT_ROOT
    src_root: Path = SRC_ROOT

    data_root: Path = DATA_ROOT
    raw_data_root: Path = RAW_DATA_ROOT
    processed_data_root: Path = PROCESSED_DATA_ROOT
    samples_root: Path = SAMPLES_ROOT
    manifests_root: Path = MANIFESTS_ROOT

    models_root: Path = MODELS_ROOT
    trained_models_root: Path = TRAINED_MODELS_ROOT
    model_metadata_root: Path = MODEL_METADATA_ROOT

    outputs_root: Path = OUTPUTS_ROOT
    sanitized_output_root: Path = SANITIZED_OUTPUT_ROOT
    report_output_root: Path = REPORT_OUTPUT_ROOT
    plot_output_root: Path = PLOT_OUTPUT_ROOT

    web_root: Path = WEB_ROOT
    web_template_root: Path = WEB_TEMPLATE_ROOT
    web_static_root: Path = WEB_STATIC_ROOT

    model_path: Path = DEFAULT_MODEL_PATH
    feature_schema_path: Path = DEFAULT_FEATURE_SCHEMA_PATH
    model_metadata_path: Path = DEFAULT_MODEL_METADATA_PATH
    thresholds_path: Path = DEFAULT_THRESHOLDS_PATH


@dataclass(frozen=True)
class ResourceSettings:
    """Global bounded-resource configuration."""

    max_upload_bytes: int = DEFAULT_MAX_UPLOAD_BYTES
    max_analysis_bytes: int = DEFAULT_MAX_ANALYSIS_BYTES

    max_source_bytes: int = DEFAULT_MAX_SOURCE_BYTES

    max_zip_entries: int = DEFAULT_MAX_ZIP_ENTRIES
    max_zip_entry_bytes: int = DEFAULT_MAX_ZIP_ENTRY_BYTES
    max_zip_total_uncompressed_bytes: int = DEFAULT_MAX_ZIP_TOTAL_UNCOMPRESSED_BYTES
    max_zip_total_compressed_bytes: int = DEFAULT_MAX_ZIP_TOTAL_COMPRESSED_BYTES

    max_strings: int = DEFAULT_MAX_STRING_COUNT
    max_evidence: int = DEFAULT_MAX_EVIDENCE_COUNT
    max_features: int = DEFAULT_MAX_FEATURE_COUNT

    max_recursion_depth: int = DEFAULT_MAX_RECURSION_DEPTH

    max_report_bytes: int = DEFAULT_MAX_REPORT_BYTES
    max_findings: int = DEFAULT_MAX_FINDINGS


@dataclass(frozen=True)
class ModelSettings:
    """Machine-learning inference configuration."""

    model_path: Path = DEFAULT_MODEL_PATH
    schema_path: Path = DEFAULT_FEATURE_SCHEMA_PATH
    metadata_path: Path = DEFAULT_MODEL_METADATA_PATH
    thresholds_path: Path = DEFAULT_THRESHOLDS_PATH

    threshold: float = DEFAULT_MODEL_THRESHOLD
    high_risk_threshold: float = DEFAULT_HIGH_RISK_THRESHOLD
    review_threshold: float = DEFAULT_REVIEW_THRESHOLD

    require_model: bool = False
    fail_closed: bool = True


@dataclass(frozen=True)
class CDRSettings:
    """Content Disarm and Reconstruction policy configuration."""

    enabled: bool = True

    mode: str = "balanced"

    remove_vba: bool = True
    remove_xlm: bool = True
    remove_activex: bool = True
    remove_embedded_objects: bool = True
    remove_embedded_scripts: bool = True

    sanitize_external_relationships: bool = True
    sanitize_remote_templates: bool = True
    sanitize_dde: bool = True

    sanitize_obfuscation: bool = True
    remove_persistence: bool = True
    remove_evasion_content: bool = True

    reject_executable_payloads: bool = True
    reject_critical_content: bool = True

    preserve_images: bool = True
    preserve_document_text: bool = True
    preserve_styles: bool = True

    require_integrity_verification: bool = True


@dataclass(frozen=True)
class APISettings:
    """Web/API configuration."""

    host: str = "127.0.0.1"
    port: int = 5000

    debug: bool = False
    testing: bool = False

    secret_key: str = ""

    max_request_bytes: int = DEFAULT_MAX_UPLOAD_BYTES
    max_filename_length: int = 255

    allowed_extensions: tuple[str, ...] = DEFAULT_ALLOWED_EXTENSIONS

    allowed_mime_types: tuple[str, ...] = DEFAULT_ALLOWED_MIME_TYPES

    enable_html_ui: bool = True
    enable_json_api: bool = True

    expose_diagnostics: bool = False
    expose_model_metadata: bool = True

    store_scan_results: bool = True
    scan_store_max_items: int = 1_000

    cors_enabled: bool = False
    cors_origins: tuple[str, ...] = ()

    request_timeout_seconds: int = 300


@dataclass(frozen=True)
class LoggingSettings:
    """Application logging configuration."""

    level: str = "INFO"

    log_file: Optional[Path] = None

    json_logs: bool = False

    include_tracebacks: bool = False


@dataclass(frozen=True)
class SecuritySettings:
    """Application security controls."""

    allow_symlinks: bool = False

    reject_duplicate_zip_entries: bool = True
    reject_encrypted_archives: bool = True

    reject_path_traversal: bool = True
    reject_absolute_archive_paths: bool = True

    sanitize_filenames: bool = True

    disable_network_access: bool = True
    disable_dynamic_execution: bool = True

    require_trusted_model_artifacts: bool = True

    enable_security_headers: bool = True

    content_security_policy: str = (
        "default-src 'self'; "
        "base-uri 'none'; "
        "form-action 'self'; "
        "frame-ancestors 'none'; "
        "object-src 'none'; "
        "script-src 'self'; "
        "style-src 'self'"
    )


@dataclass(frozen=True)
class Settings:
    """Complete Pharos CDR application configuration."""

    environment: str = "development"

    paths: PathSettings = field(default_factory=PathSettings)

    resources: ResourceSettings = field(default_factory=ResourceSettings)

    model: ModelSettings = field(default_factory=ModelSettings)

    cdr: CDRSettings = field(default_factory=CDRSettings)

    api: APISettings = field(default_factory=APISettings)

    logging: LoggingSettings = field(default_factory=LoggingSettings)

    security: SecuritySettings = field(default_factory=SecuritySettings)


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


_VALID_CDR_MODES = {
    "permissive",
    "balanced",
    "strict",
}


_VALID_LOG_LEVELS = {
    "CRITICAL",
    "ERROR",
    "WARNING",
    "INFO",
    "DEBUG",
}


def _validate_probability(
    value: float,
    name: str,
) -> None:
    if not 0.0 <= value <= 1.0:
        raise ValueError(f"{name} must be between 0 and 1.")


def _validate_paths(
    paths: PathSettings,
) -> None:
    if not paths.project_root.is_absolute():
        raise ValueError("project_root must be absolute.")

    for name in (
        "data_root",
        "models_root",
        "outputs_root",
        "web_root",
    ):
        path = getattr(
            paths,
            name,
        )

        if not path.is_absolute():
            raise ValueError(f"{name} must be absolute.")


def _validate_resources(
    resources: ResourceSettings,
) -> None:
    positive_fields = (
        "max_upload_bytes",
        "max_analysis_bytes",
        "max_source_bytes",
        "max_zip_entries",
        "max_zip_entry_bytes",
        "max_zip_total_uncompressed_bytes",
        "max_zip_total_compressed_bytes",
        "max_strings",
        "max_evidence",
        "max_features",
        "max_recursion_depth",
        "max_report_bytes",
        "max_findings",
    )

    for name in positive_fields:
        value = getattr(
            resources,
            name,
        )

        if value <= 0:
            raise ValueError(f"{name} must be positive.")

    if resources.max_zip_total_uncompressed_bytes < resources.max_zip_entry_bytes:
        raise ValueError(
            "max_zip_total_uncompressed_bytes must be "
            "greater than or equal to max_zip_entry_bytes."
        )


def _validate_model(
    model: ModelSettings,
) -> None:
    _validate_probability(
        model.threshold,
        "model.threshold",
    )

    _validate_probability(
        model.high_risk_threshold,
        "model.high_risk_threshold",
    )

    _validate_probability(
        model.review_threshold,
        "model.review_threshold",
    )

    if model.review_threshold > model.high_risk_threshold:
        raise ValueError(
            "model.review_threshold must not exceed " "model.high_risk_threshold."
        )


def _validate_cdr(
    cdr: CDRSettings,
) -> None:
    if cdr.mode not in _VALID_CDR_MODES:
        raise ValueError(
            "cdr.mode must be one of: " + ", ".join(sorted(_VALID_CDR_MODES))
        )


def _validate_api(
    api: APISettings,
) -> None:
    if not 1 <= api.port <= 65535:
        raise ValueError("api.port must be between 1 and 65535.")

    if api.max_request_bytes <= 0:
        raise ValueError("api.max_request_bytes must be positive.")

    if api.max_filename_length <= 0:
        raise ValueError("api.max_filename_length must be positive.")

    if api.scan_store_max_items <= 0:
        raise ValueError("api.scan_store_max_items must be positive.")

    if api.request_timeout_seconds <= 0:
        raise ValueError("api.request_timeout_seconds must be positive.")


def _validate_logging(
    logging_settings: LoggingSettings,
) -> None:
    if logging_settings.level.upper() not in _VALID_LOG_LEVELS:
        raise ValueError("logging.level is invalid.")


def validate_settings(
    settings: Settings,
) -> Settings:
    """
    Validate and return application settings.

    Raises:
        ValueError: If a configuration constraint is violated.
    """

    _validate_paths(settings.paths)

    _validate_resources(settings.resources)

    _validate_model(settings.model)

    _validate_cdr(settings.cdr)

    _validate_api(settings.api)

    _validate_logging(settings.logging)

    if not settings.environment.strip():
        raise ValueError("environment cannot be empty.")

    return settings


# ---------------------------------------------------------------------------
# Settings construction
# ---------------------------------------------------------------------------


def load_settings() -> Settings:
    """
    Build settings from environment variables.

    Environment variables are intentionally explicit so deployments can
    configure the service without modifying source code.
    """

    environment = (
        _env(
            "PHAROS_CDR_ENV",
            "development",
        )
        or "development"
    )

    # Paths
    paths = PathSettings(
        project_root=_env_path(
            "PHAROS_CDR_PROJECT_ROOT",
            PROJECT_ROOT,
        ),
        src_root=_env_path(
            "PHAROS_CDR_SRC_ROOT",
            SRC_ROOT,
        ),
        data_root=_env_path(
            "PHAROS_CDR_DATA_ROOT",
            DATA_ROOT,
        ),
        raw_data_root=_env_path(
            "PHAROS_CDR_RAW_DATA_ROOT",
            RAW_DATA_ROOT,
        ),
        processed_data_root=_env_path(
            "PHAROS_CDR_PROCESSED_DATA_ROOT",
            PROCESSED_DATA_ROOT,
        ),
        samples_root=_env_path(
            "PHAROS_CDR_SAMPLES_ROOT",
            SAMPLES_ROOT,
        ),
        manifests_root=_env_path(
            "PHAROS_CDR_MANIFESTS_ROOT",
            MANIFESTS_ROOT,
        ),
        models_root=_env_path(
            "PHAROS_CDR_MODELS_ROOT",
            MODELS_ROOT,
        ),
        trained_models_root=_env_path(
            "PHAROS_CDR_TRAINED_MODELS_ROOT",
            TRAINED_MODELS_ROOT,
        ),
        model_metadata_root=_env_path(
            "PHAROS_CDR_MODEL_METADATA_ROOT",
            MODEL_METADATA_ROOT,
        ),
        outputs_root=_env_path(
            "PHAROS_CDR_OUTPUTS_ROOT",
            OUTPUTS_ROOT,
        ),
        sanitized_output_root=_env_path(
            "PHAROS_CDR_SANITIZED_OUTPUT_ROOT",
            SANITIZED_OUTPUT_ROOT,
        ),
        report_output_root=_env_path(
            "PHAROS_CDR_REPORT_OUTPUT_ROOT",
            REPORT_OUTPUT_ROOT,
        ),
        plot_output_root=_env_path(
            "PHAROS_CDR_PLOT_OUTPUT_ROOT",
            PLOT_OUTPUT_ROOT,
        ),
        web_root=_env_path(
            "PHAROS_CDR_WEB_ROOT",
            WEB_ROOT,
        ),
        web_template_root=_env_path(
            "PHAROS_CDR_WEB_TEMPLATE_ROOT",
            WEB_TEMPLATE_ROOT,
        ),
        web_static_root=_env_path(
            "PHAROS_CDR_WEB_STATIC_ROOT",
            WEB_STATIC_ROOT,
        ),
        model_path=_env_path(
            "PHAROS_CDR_MODEL_PATH",
            DEFAULT_MODEL_PATH,
        ),
        feature_schema_path=_env_path(
            "PHAROS_CDR_FEATURE_SCHEMA_PATH",
            DEFAULT_FEATURE_SCHEMA_PATH,
        ),
        model_metadata_path=_env_path(
            "PHAROS_CDR_MODEL_METADATA_PATH",
            DEFAULT_MODEL_METADATA_PATH,
        ),
        thresholds_path=_env_path(
            "PHAROS_CDR_THRESHOLDS_PATH",
            DEFAULT_THRESHOLDS_PATH,
        ),
    )

    # Resources
    resources = ResourceSettings(
        max_upload_bytes=_env_int(
            "PHAROS_CDR_MAX_UPLOAD_BYTES",
            DEFAULT_MAX_UPLOAD_BYTES,
            minimum=1,
            maximum=2 * 1024 * 1024 * 1024,
        ),
        max_analysis_bytes=_env_int(
            "PHAROS_CDR_MAX_ANALYSIS_BYTES",
            DEFAULT_MAX_ANALYSIS_BYTES,
            minimum=1,
            maximum=512 * 1024 * 1024,
        ),
        max_source_bytes=_env_int(
            "PHAROS_CDR_MAX_SOURCE_BYTES",
            DEFAULT_MAX_SOURCE_BYTES,
            minimum=1,
            maximum=512 * 1024 * 1024,
        ),
        max_zip_entries=_env_int(
            "PHAROS_CDR_MAX_ZIP_ENTRIES",
            DEFAULT_MAX_ZIP_ENTRIES,
            minimum=1,
            maximum=1_000_000,
        ),
        max_zip_entry_bytes=_env_int(
            "PHAROS_CDR_MAX_ZIP_ENTRY_BYTES",
            DEFAULT_MAX_ZIP_ENTRY_BYTES,
            minimum=1,
            maximum=2 * 1024 * 1024 * 1024,
        ),
        max_zip_total_uncompressed_bytes=_env_int(
            "PHAROS_CDR_MAX_ZIP_TOTAL_UNCOMPRESSED_BYTES",
            DEFAULT_MAX_ZIP_TOTAL_UNCOMPRESSED_BYTES,
            minimum=1,
            maximum=4 * 1024 * 1024 * 1024,
        ),
        max_zip_total_compressed_bytes=_env_int(
            "PHAROS_CDR_MAX_ZIP_TOTAL_COMPRESSED_BYTES",
            DEFAULT_MAX_ZIP_TOTAL_COMPRESSED_BYTES,
            minimum=1,
            maximum=2 * 1024 * 1024 * 1024,
        ),
        max_strings=_env_int(
            "PHAROS_CDR_MAX_STRINGS",
            DEFAULT_MAX_STRING_COUNT,
            minimum=1,
            maximum=1_000_000,
        ),
        max_evidence=_env_int(
            "PHAROS_CDR_MAX_EVIDENCE",
            DEFAULT_MAX_EVIDENCE_COUNT,
            minimum=1,
            maximum=1_000_000,
        ),
        max_features=_env_int(
            "PHAROS_CDR_MAX_FEATURES",
            DEFAULT_MAX_FEATURE_COUNT,
            minimum=1,
            maximum=1_000_000,
        ),
        max_recursion_depth=_env_int(
            "PHAROS_CDR_MAX_RECURSION_DEPTH",
            DEFAULT_MAX_RECURSION_DEPTH,
            minimum=1,
            maximum=100,
        ),
        max_report_bytes=_env_int(
            "PHAROS_CDR_MAX_REPORT_BYTES",
            DEFAULT_MAX_REPORT_BYTES,
            minimum=1,
            maximum=512 * 1024 * 1024,
        ),
        max_findings=_env_int(
            "PHAROS_CDR_MAX_FINDINGS",
            DEFAULT_MAX_FINDINGS,
            minimum=1,
            maximum=1_000_000,
        ),
    )

    # Model
    model = ModelSettings(
        model_path=paths.model_path,
        schema_path=paths.feature_schema_path,
        metadata_path=paths.model_metadata_path,
        thresholds_path=paths.thresholds_path,
        threshold=_env_float(
            "PHAROS_CDR_MODEL_THRESHOLD",
            DEFAULT_MODEL_THRESHOLD,
            minimum=0.0,
            maximum=1.0,
        ),
        high_risk_threshold=_env_float(
            "PHAROS_CDR_HIGH_RISK_THRESHOLD",
            DEFAULT_HIGH_RISK_THRESHOLD,
            minimum=0.0,
            maximum=1.0,
        ),
        review_threshold=_env_float(
            "PHAROS_CDR_REVIEW_THRESHOLD",
            DEFAULT_REVIEW_THRESHOLD,
            minimum=0.0,
            maximum=1.0,
        ),
        require_model=_env_bool(
            "PHAROS_CDR_REQUIRE_MODEL",
            False,
        ),
        fail_closed=_env_bool(
            "PHAROS_CDR_FAIL_CLOSED",
            True,
        ),
    )

    # CDR
    cdr = CDRSettings(
        enabled=_env_bool(
            "PHAROS_CDR_CDR_ENABLED",
            True,
        ),
        mode=(
            _env(
                "PHAROS_CDR_CDR_MODE",
                "balanced",
            )
            or "balanced"
        ).lower(),
        remove_vba=_env_bool(
            "PHAROS_CDR_REMOVE_VBA",
            True,
        ),
        remove_xlm=_env_bool(
            "PHAROS_CDR_REMOVE_XLM",
            True,
        ),
        remove_activex=_env_bool(
            "PHAROS_CDR_REMOVE_ACTIVEX",
            True,
        ),
        remove_embedded_objects=_env_bool(
            "PHAROS_CDR_REMOVE_EMBEDDED_OBJECTS",
            True,
        ),
        remove_embedded_scripts=_env_bool(
            "PHAROS_CDR_REMOVE_EMBEDDED_SCRIPTS",
            True,
        ),
        sanitize_external_relationships=_env_bool(
            "PHAROS_CDR_SANITIZE_EXTERNAL_RELATIONSHIPS",
            True,
        ),
        sanitize_remote_templates=_env_bool(
            "PHAROS_CDR_SANITIZE_REMOTE_TEMPLATES",
            True,
        ),
        sanitize_dde=_env_bool(
            "PHAROS_CDR_SANITIZE_DDE",
            True,
        ),
        sanitize_obfuscation=_env_bool(
            "PHAROS_CDR_SANITIZE_OBFUSCATION",
            True,
        ),
        remove_persistence=_env_bool(
            "PHAROS_CDR_REMOVE_PERSISTENCE",
            True,
        ),
        remove_evasion_content=_env_bool(
            "PHAROS_CDR_REMOVE_EVASION_CONTENT",
            True,
        ),
        reject_executable_payloads=_env_bool(
            "PHAROS_CDR_REJECT_EXECUTABLE_PAYLOADS",
            True,
        ),
        reject_critical_content=_env_bool(
            "PHAROS_CDR_REJECT_CRITICAL_CONTENT",
            True,
        ),
        preserve_images=_env_bool(
            "PHAROS_CDR_PRESERVE_IMAGES",
            True,
        ),
        preserve_document_text=_env_bool(
            "PHAROS_CDR_PRESERVE_DOCUMENT_TEXT",
            True,
        ),
        preserve_styles=_env_bool(
            "PHAROS_CDR_PRESERVE_STYLES",
            True,
        ),
        require_integrity_verification=_env_bool(
            "PHAROS_CDR_REQUIRE_INTEGRITY",
            True,
        ),
    )

    # API
    api = APISettings(
        host=(
            _env(
                "PHAROS_CDR_API_HOST",
                "127.0.0.1",
            )
            or "127.0.0.1"
        ),
        port=_env_int(
            "PHAROS_CDR_API_PORT",
            5000,
            minimum=1,
            maximum=65535,
        ),
        debug=_env_bool(
            "PHAROS_CDR_API_DEBUG",
            False,
        ),
        testing=_env_bool(
            "PHAROS_CDR_API_TESTING",
            False,
        ),
        secret_key=(
            _env(
                "PHAROS_CDR_SECRET_KEY",
                "",
            )
            or ""
        ),
        max_request_bytes=_env_int(
            "PHAROS_CDR_MAX_REQUEST_BYTES",
            DEFAULT_MAX_UPLOAD_BYTES,
            minimum=1,
            maximum=2 * 1024 * 1024 * 1024,
        ),
        max_filename_length=_env_int(
            "PHAROS_CDR_MAX_FILENAME_LENGTH",
            255,
            minimum=1,
            maximum=4096,
        ),
        allowed_extensions=_env_csv(
            "PHAROS_CDR_ALLOWED_EXTENSIONS",
            DEFAULT_ALLOWED_EXTENSIONS,
        ),
        allowed_mime_types=_env_csv(
            "PHAROS_CDR_ALLOWED_MIME_TYPES",
            DEFAULT_ALLOWED_MIME_TYPES,
        ),
        enable_html_ui=_env_bool(
            "PHAROS_CDR_ENABLE_HTML_UI",
            True,
        ),
        enable_json_api=_env_bool(
            "PHAROS_CDR_ENABLE_JSON_API",
            True,
        ),
        expose_diagnostics=_env_bool(
            "PHAROS_CDR_EXPOSE_DIAGNOSTICS",
            False,
        ),
        expose_model_metadata=_env_bool(
            "PHAROS_CDR_EXPOSE_MODEL_METADATA",
            True,
        ),
        store_scan_results=_env_bool(
            "PHAROS_CDR_STORE_SCAN_RESULTS",
            True,
        ),
        scan_store_max_items=_env_int(
            "PHAROS_CDR_SCAN_STORE_MAX_ITEMS",
            1_000,
            minimum=1,
            maximum=1_000_000,
        ),
        cors_enabled=_env_bool(
            "PHAROS_CDR_CORS_ENABLED",
            False,
        ),
        cors_origins=_env_csv(
            "PHAROS_CDR_CORS_ORIGINS",
            (),
        ),
        request_timeout_seconds=_env_int(
            "PHAROS_CDR_REQUEST_TIMEOUT_SECONDS",
            300,
            minimum=1,
            maximum=3600,
        ),
    )

    # Logging
    log_file_value = _env("PHAROS_CDR_LOG_FILE")

    logging_settings = LoggingSettings(
        level=(
            _env(
                "PHAROS_CDR_LOG_LEVEL",
                "INFO",
            )
            or "INFO"
        ).upper(),
        log_file=(Path(log_file_value).resolve() if log_file_value else None),
        json_logs=_env_bool(
            "PHAROS_CDR_JSON_LOGS",
            False,
        ),
        include_tracebacks=_env_bool(
            "PHAROS_CDR_INCLUDE_TRACEBACKS",
            False,
        ),
    )

    # Security
    security = SecuritySettings(
        allow_symlinks=_env_bool(
            "PHAROS_CDR_ALLOW_SYMLINKS",
            False,
        ),
        reject_duplicate_zip_entries=_env_bool(
            "PHAROS_CDR_REJECT_DUPLICATE_ZIP_ENTRIES",
            True,
        ),
        reject_encrypted_archives=_env_bool(
            "PHAROS_CDR_REJECT_ENCRYPTED_ARCHIVES",
            True,
        ),
        reject_path_traversal=_env_bool(
            "PHAROS_CDR_REJECT_PATH_TRAVERSAL",
            True,
        ),
        reject_absolute_archive_paths=_env_bool(
            "PHAROS_CDR_REJECT_ABSOLUTE_ARCHIVE_PATHS",
            True,
        ),
        sanitize_filenames=_env_bool(
            "PHAROS_CDR_SANITIZE_FILENAMES",
            True,
        ),
        disable_network_access=_env_bool(
            "PHAROS_CDR_DISABLE_NETWORK_ACCESS",
            True,
        ),
        disable_dynamic_execution=_env_bool(
            "PHAROS_CDR_DISABLE_DYNAMIC_EXECUTION",
            True,
        ),
        require_trusted_model_artifacts=_env_bool(
            "PHAROS_CDR_REQUIRE_TRUSTED_MODEL_ARTIFACTS",
            True,
        ),
        enable_security_headers=_env_bool(
            "PHAROS_CDR_ENABLE_SECURITY_HEADERS",
            True,
        ),
        content_security_policy=(
            _env(
                "PHAROS_CDR_CONTENT_SECURITY_POLICY",
                SecuritySettings.content_security_policy,
            )
            or SecuritySettings.content_security_policy
        ),
    )

    settings = Settings(
        environment=environment,
        paths=paths,
        resources=resources,
        model=model,
        cdr=cdr,
        api=api,
        logging=logging_settings,
        security=security,
    )

    return validate_settings(settings)


# ---------------------------------------------------------------------------
# Global settings instance
# ---------------------------------------------------------------------------

settings = load_settings()


# ---------------------------------------------------------------------------
# Compatibility / convenience functions
# ---------------------------------------------------------------------------


def get_settings() -> Settings:
    """Return the process-wide settings object."""

    return settings


def reload_settings() -> Settings:
    """
    Re-read configuration from environment variables.

    Useful for tests and controlled application startup.
    """

    global settings

    settings = load_settings()

    return settings


def ensure_directories(
    value: Optional[Settings] = None,
) -> None:
    """
    Create configured application directories.

    This function only creates project-owned directories. It never creates
    directories based on untrusted document content.
    """

    current = value if value is not None else settings

    directories = (
        current.paths.raw_data_root,
        current.paths.processed_data_root,
        current.paths.samples_root,
        current.paths.manifests_root,
        current.paths.trained_models_root,
        current.paths.model_metadata_root,
        current.paths.sanitized_output_root,
        current.paths.report_output_root,
        current.paths.plot_output_root,
    )

    for directory in directories:
        directory.mkdir(
            parents=True,
            exist_ok=True,
        )


def settings_to_dict(
    value: Optional[Settings] = None,
    *,
    include_secret: bool = False,
) -> dict[str, Any]:
    """
    Serialize settings into a JSON-compatible mapping.

    Secrets are excluded by default.
    """

    current = value if value is not None else settings

    def convert(
        item: Any,
    ) -> Any:
        if isinstance(
            item,
            Path,
        ):
            return str(item)

        if isinstance(
            item,
            tuple,
        ):
            return [convert(child) for child in item]

        if hasattr(
            item,
            "__dataclass_fields__",
        ):
            result: dict[str, Any] = {}

            for field_name in item.__dataclass_fields__:
                if field_name == "secret_key" and not include_secret:
                    continue

                result[field_name] = convert(
                    getattr(
                        item,
                        field_name,
                    )
                )

            return result

        if isinstance(
            item,
            Mapping,
        ):
            return {str(key): convert(child) for key, child in item.items()}

        return item

    return convert(current)


def settings_json(
    value: Optional[Settings] = None,
    *,
    include_secret: bool = False,
) -> str:
    """Return settings as deterministic JSON."""

    return json.dumps(
        settings_to_dict(
            value,
            include_secret=include_secret,
        ),
        indent=2,
        sort_keys=True,
        ensure_ascii=False,
    )


def is_production(
    value: Optional[Settings] = None,
) -> bool:
    """Return whether configuration targets a production environment."""

    current = value if value is not None else settings

    return current.environment.lower() in {
        "production",
        "prod",
    }


def is_testing(
    value: Optional[Settings] = None,
) -> bool:
    """Return whether test mode is enabled."""

    current = value if value is not None else settings

    return bool(current.api.testing)


def model_artifacts_available(
    value: Optional[Settings] = None,
) -> bool:
    """Return whether all configured ML artifacts currently exist."""

    current = value if value is not None else settings

    paths = (
        current.model.model_path,
        current.model.schema_path,
        current.model.metadata_path,
        current.model.thresholds_path,
    )

    return all(path.is_file() for path in paths)


def allowed_extension(
    filename: str,
    value: Optional[Settings] = None,
) -> bool:
    """Check whether a filename has an allowed analysis extension."""

    current = value if value is not None else settings

    suffix = Path(filename).suffix.lower()

    return suffix in {item.lower() for item in current.api.allowed_extensions}


def allowed_mime_type(
    mime_type: str,
    value: Optional[Settings] = None,
) -> bool:
    """Check whether a MIME type is explicitly allowed."""

    current = value if value is not None else settings

    normalized = (mime_type or "").strip().lower()

    return normalized in {item.lower() for item in current.api.allowed_mime_types}


def normalize_extension(
    value: str,
) -> str:
    """Normalize a file extension to lowercase dotted form."""

    text = (value or "").strip().lower()

    if not text:
        return ""

    if not text.startswith("."):
        text = "." + text

    return text


_FILENAME_RE = re.compile(r"[^A-Za-z0-9._()\- ]+")


def safe_filename(
    filename: str,
    *,
    max_length: Optional[int] = None,
) -> str:
    """
    Produce a safe display/storage filename.

    This function does not guarantee that the resulting filename is unique.
    """

    limit = max_length if max_length is not None else settings.api.max_filename_length

    name = Path(filename or "document").name

    name = name.replace(
        "\x00",
        "",
    )

    name = _FILENAME_RE.sub(
        "_",
        name,
    )

    name = name.strip(" .")

    if not name:
        name = "document"

    return name[:limit]


# ---------------------------------------------------------------------------
# Configuration profiles
# ---------------------------------------------------------------------------


def permissive_cdr_settings() -> CDRSettings:
    """Return a conservative/permissive CDR profile."""

    return CDRSettings(
        enabled=True,
        mode="permissive",
        remove_vba=False,
        remove_xlm=False,
        remove_activex=True,
        remove_embedded_objects=False,
        remove_embedded_scripts=True,
        sanitize_external_relationships=True,
        sanitize_remote_templates=True,
        sanitize_dde=True,
        sanitize_obfuscation=False,
        remove_persistence=True,
        remove_evasion_content=False,
        reject_executable_payloads=True,
        reject_critical_content=True,
        preserve_images=True,
        preserve_document_text=True,
        preserve_styles=True,
        require_integrity_verification=True,
    )


def balanced_cdr_settings() -> CDRSettings:
    """Return the default balanced CDR profile."""

    return CDRSettings()


def strict_cdr_settings() -> CDRSettings:
    """Return a strict CDR profile."""

    return CDRSettings(
        enabled=True,
        mode="strict",
        remove_vba=True,
        remove_xlm=True,
        remove_activex=True,
        remove_embedded_objects=True,
        remove_embedded_scripts=True,
        sanitize_external_relationships=True,
        sanitize_remote_templates=True,
        sanitize_dde=True,
        sanitize_obfuscation=True,
        remove_persistence=True,
        remove_evasion_content=True,
        reject_executable_payloads=True,
        reject_critical_content=True,
        preserve_images=True,
        preserve_document_text=True,
        preserve_styles=True,
        require_integrity_verification=True,
    )


def development_settings() -> Settings:
    """Return a development-oriented configuration."""

    return Settings(
        environment="development",
        paths=settings.paths,
        resources=settings.resources,
        model=ModelSettings(
            model_path=settings.model.model_path,
            schema_path=settings.model.schema_path,
            metadata_path=settings.model.metadata_path,
            thresholds_path=settings.model.thresholds_path,
            threshold=settings.model.threshold,
            high_risk_threshold=settings.model.high_risk_threshold,
            review_threshold=settings.model.review_threshold,
            require_model=False,
            fail_closed=True,
        ),
        cdr=balanced_cdr_settings(),
        api=APISettings(
            host="127.0.0.1",
            port=settings.api.port,
            debug=True,
            testing=False,
            secret_key=settings.api.secret_key,
            max_request_bytes=settings.api.max_request_bytes,
            max_filename_length=settings.api.max_filename_length,
            allowed_extensions=settings.api.allowed_extensions,
            allowed_mime_types=settings.api.allowed_mime_types,
            enable_html_ui=True,
            enable_json_api=True,
            expose_diagnostics=True,
            expose_model_metadata=True,
            store_scan_results=True,
            scan_store_max_items=settings.api.scan_store_max_items,
            cors_enabled=False,
            cors_origins=(),
            request_timeout_seconds=settings.api.request_timeout_seconds,
        ),
        logging=LoggingSettings(
            level="DEBUG",
            log_file=settings.logging.log_file,
            json_logs=False,
            include_tracebacks=True,
        ),
        security=settings.security,
    )


def production_settings() -> Settings:
    """Return a hardened production-oriented configuration."""

    return Settings(
        environment="production",
        paths=settings.paths,
        resources=settings.resources,
        model=ModelSettings(
            model_path=settings.model.model_path,
            schema_path=settings.model.schema_path,
            metadata_path=settings.model.metadata_path,
            thresholds_path=settings.model.thresholds_path,
            threshold=settings.model.threshold,
            high_risk_threshold=settings.model.high_risk_threshold,
            review_threshold=settings.model.review_threshold,
            require_model=True,
            fail_closed=True,
        ),
        cdr=strict_cdr_settings(),
        api=APISettings(
            host=(
                _env(
                    "PHAROS_CDR_API_HOST",
                    "127.0.0.1",
                )
                or "127.0.0.1"
            ),
            port=settings.api.port,
            debug=False,
            testing=False,
            secret_key=settings.api.secret_key,
            max_request_bytes=settings.api.max_request_bytes,
            max_filename_length=settings.api.max_filename_length,
            allowed_extensions=settings.api.allowed_extensions,
            allowed_mime_types=settings.api.allowed_mime_types,
            enable_html_ui=True,
            enable_json_api=True,
            expose_diagnostics=False,
            expose_model_metadata=False,
            store_scan_results=settings.api.store_scan_results,
            scan_store_max_items=settings.api.scan_store_max_items,
            cors_enabled=settings.api.cors_enabled,
            cors_origins=settings.api.cors_origins,
            request_timeout_seconds=settings.api.request_timeout_seconds,
        ),
        logging=LoggingSettings(
            level="INFO",
            log_file=settings.logging.log_file,
            json_logs=True,
            include_tracebacks=False,
        ),
        security=SecuritySettings(
            allow_symlinks=False,
            reject_duplicate_zip_entries=True,
            reject_encrypted_archives=True,
            reject_path_traversal=True,
            reject_absolute_archive_paths=True,
            sanitize_filenames=True,
            disable_network_access=True,
            disable_dynamic_execution=True,
            require_trusted_model_artifacts=True,
            enable_security_headers=True,
            content_security_policy=(settings.security.content_security_policy),
        ),
    )


# ---------------------------------------------------------------------------
# Public APIs
# ---------------------------------------------------------------------------

__all__ = [
    "MODULE_NAME",
    "SETTINGS_VERSION",
    "PROJECT_ROOT",
    "SRC_ROOT",
    "DATA_ROOT",
    "RAW_DATA_ROOT",
    "PROCESSED_DATA_ROOT",
    "SAMPLES_ROOT",
    "MANIFESTS_ROOT",
    "MODELS_ROOT",
    "TRAINED_MODELS_ROOT",
    "MODEL_METADATA_ROOT",
    "OUTPUTS_ROOT",
    "SANITIZED_OUTPUT_ROOT",
    "REPORT_OUTPUT_ROOT",
    "PLOT_OUTPUT_ROOT",
    "WEB_ROOT",
    "WEB_TEMPLATE_ROOT",
    "WEB_STATIC_ROOT",
    "DEFAULT_MODEL_PATH",
    "DEFAULT_FEATURE_SCHEMA_PATH",
    "DEFAULT_MODEL_METADATA_PATH",
    "DEFAULT_THRESHOLDS_PATH",
    "DEFAULT_MAX_UPLOAD_BYTES",
    "DEFAULT_MAX_ANALYSIS_BYTES",
    "DEFAULT_MAX_ZIP_ENTRIES",
    "DEFAULT_MAX_ZIP_ENTRY_BYTES",
    "DEFAULT_MAX_ZIP_TOTAL_UNCOMPRESSED_BYTES",
    "DEFAULT_MAX_ZIP_TOTAL_COMPRESSED_BYTES",
    "DEFAULT_MAX_SOURCE_BYTES",
    "DEFAULT_MAX_STRING_COUNT",
    "DEFAULT_MAX_EVIDENCE_COUNT",
    "DEFAULT_MAX_FEATURE_COUNT",
    "DEFAULT_MAX_RECURSION_DEPTH",
    "DEFAULT_MAX_REPORT_BYTES",
    "DEFAULT_MAX_FINDINGS",
    "DEFAULT_MODEL_THRESHOLD",
    "DEFAULT_HIGH_RISK_THRESHOLD",
    "DEFAULT_REVIEW_THRESHOLD",
    "DEFAULT_ALLOWED_EXTENSIONS",
    "DEFAULT_ALLOWED_MIME_TYPES",
    "PathSettings",
    "ResourceSettings",
    "ModelSettings",
    "CDRSettings",
    "APISettings",
    "LoggingSettings",
    "SecuritySettings",
    "Settings",
    "load_settings",
    "settings",
    "get_settings",
    "reload_settings",
    "validate_settings",
    "ensure_directories",
    "settings_to_dict",
    "settings_json",
    "is_production",
    "is_testing",
    "model_artifacts_available",
    "allowed_extension",
    "allowed_mime_type",
    "normalize_extension",
    "safe_filename",
    "permissive_cdr_settings",
    "balanced_cdr_settings",
    "strict_cdr_settings",
    "development_settings",
    "production_settings",
]
