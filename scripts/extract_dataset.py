#!/usr/bin/env python3
"""
pharos-cdr/scripts/extract_dataset.py

Build a machine-learning dataset from the Pharos CDR raw sample tree,
or extract features from one individual document.

Expected dataset layout
-----------------------

    data/
      raw/
        benign/
          sample1.docx
          sample2.xlsm
        malicious/
          sample3.doc
          sample4.xls

Single-file usage
-----------------

    python scripts/extract_dataset.py \
        --input data/raw/benign/sample1.docx \
        --output data/processed/sample1_features.csv

Dataset usage
-------------

    python scripts/extract_dataset.py

    python scripts/extract_dataset.py \
        --input-root data/raw \
        --output data/processed/dataset.jsonl \
        --schema models/metadata/feature_schema.json \
        --manifest data/manifests/dataset_manifest.json

    python scripts/extract_dataset.py \
        --classes benign malicious \
        --deduplicate

Security model
--------------

This script is strictly static-analysis oriented.

It does NOT:

- execute Office macros;
- execute JavaScript, VBScript, PowerShell, shell, or batch files;
- launch extracted executables;
- invoke embedded payloads;
- resolve or contact URLs;
- download network resources;
- load untrusted DLLs;
- write extracted document contents to disk;
- execute OLE objects;
- open documents through Office applications.

Feature extraction is delegated to the project's static feature pipeline.

Dataset artifacts contain feature values and metadata rather than original
document contents.
"""

from __future__ import annotations

import argparse
import hashlib
import inspect
import json
import logging
import math
import os
import sys
import time
import traceback
from dataclasses import asdict, dataclass, field, is_dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Optional, Sequence

# ---------------------------------------------------------------------------
# Bootstrap project import path
# ---------------------------------------------------------------------------

SCRIPT_PATH = Path(__file__).resolve()
PROJECT_ROOT = SCRIPT_PATH.parent.parent

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


# ---------------------------------------------------------------------------
# Project imports
# ---------------------------------------------------------------------------

from src.ml.dataset import (  # noqa: E402
    Dataset,
    DatasetRecord,
    build_schema,
    create_dataset,
    dataset_fingerprint,
    dataset_statistics,
    save_csv,
    save_dataset,
    save_jsonl,
    save_schema,
    validate_dataset,
)

try:
    from src.ml.dataset import (  # noqa: E402
        schema_fingerprint as calculate_schema_fingerprint,
    )
except ImportError:
    calculate_schema_fingerprint = None


try:
    from src.extraction.feature_pipeline import (  # type: ignore # noqa: E402
        analyze_file,
        extract_features,
    )
except ImportError:
    try:
        from src.extraction.feature_pipeline import (  # type: ignore # noqa: E402
            analyze,
            extract_features,
        )

        analyze_file = analyze
    except ImportError:
        try:
            from src.extraction.feature_pipeline import (  # type: ignore # noqa: E402
                extract_features,
            )

            analyze_file = None
        except ImportError:
            analyze_file = None
            extract_features = None


# ---------------------------------------------------------------------------
# Metadata
# ---------------------------------------------------------------------------

MODULE_NAME = "pharos_cdr.scripts.extract_dataset"
SCRIPT_VERSION = "1.2.0"

DEFAULT_INPUT_ROOT = PROJECT_ROOT / "data" / "raw"
DEFAULT_OUTPUT_PATH = PROJECT_ROOT / "data" / "processed" / "dataset.csv"
DEFAULT_SCHEMA_PATH = PROJECT_ROOT / "models" / "metadata" / "feature_schema.json"
DEFAULT_MANIFEST_PATH = PROJECT_ROOT / "data" / "manifests" / "dataset_manifest.json"

DEFAULT_CLASSES = (
    "benign",
    "malicious",
)

DEFAULT_MAX_FILE_SIZE = 100 * 1024 * 1024
DEFAULT_MAX_FILES = 100_000
DEFAULT_MAX_ERRORS = 1_000
DEFAULT_LOG_EVERY = 100
DEFAULT_MAX_FEATURES = 100_000

SUPPORTED_EXTENSIONS = frozenset(
    {
        # Microsoft Office / OOXML
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
        # Documents
        ".pdf",
        ".rtf",
        # Scripts
        ".js",
        ".jse",
        ".vbs",
        ".vbe",
        ".wsf",
        ".wsc",
        ".ps1",
        ".psm1",
        ".psd1",
        ".bat",
        ".cmd",
        ".sh",
        # Text/configuration-like inputs
        ".txt",
        ".xml",
        ".json",
        ".html",
        ".htm",
    }
)

IGNORED_DIRECTORIES = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        "__pycache__",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
        "node_modules",
        "venv",
        ".venv",
    }
)

IDENTITY_KEYS = frozenset(
    {
        "sample_id",
        "id",
        "path",
        "file",
        "file_path",
        "filename",
        "name",
        "source",
        "split",
        "sha256",
        "md5",
        "sha1",
        "label",
        "class",
        "target",
        "timestamp",
        "created_at",
        "updated_at",
        "metadata",
        "identity",
        "error",
        "errors",
        "warnings",
        "evidence",
        "records",
        "findings",
        "analysis",
        "summary",
    }
)

LOGGER = logging.getLogger(MODULE_NAME)


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class DatasetExtractionError(RuntimeError):
    """Base exception for dataset extraction failures."""


class ConfigurationError(DatasetExtractionError):
    """Invalid extraction configuration."""


class SampleLimitError(DatasetExtractionError):
    """Configured sample limits were exceeded."""


class FeatureExtractionError(DatasetExtractionError):
    """Static feature extraction failed."""


class DatasetBuildError(DatasetExtractionError):
    """Dataset construction or persistence failed."""


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ExtractionConfig:
    """Configuration for one dataset extraction run."""

    input_root: Path = DEFAULT_INPUT_ROOT
    output_path: Path = DEFAULT_OUTPUT_PATH
    schema_path: Path = DEFAULT_SCHEMA_PATH
    manifest_path: Path = DEFAULT_MANIFEST_PATH
    classes: tuple[str, ...] = DEFAULT_CLASSES

    recursive: bool = True
    deduplicate: bool = True
    fail_fast: bool = False
    include_unsupported: bool = False
    allow_empty_classes: bool = False

    max_file_size: int = DEFAULT_MAX_FILE_SIZE
    max_files: int = DEFAULT_MAX_FILES
    max_errors: int = DEFAULT_MAX_ERRORS
    log_every: int = DEFAULT_LOG_EVERY

    include_paths_in_records: bool = False
    preserve_sample_metadata: bool = True

    # Dataset split is intentionally optional. The extraction script must not
    # silently invent a train/validation/test assignment.
    split: str = ""

    seed: int = 42


@dataclass
class SampleCandidate:
    """A discovered raw sample before feature extraction."""

    path: Path
    label: str
    relative_path: str
    extension: str
    size_bytes: int
    sha256: str = ""


@dataclass
class ExtractionFailure:
    """One sample that could not be converted into a feature record."""

    path: str
    label: str
    error_type: str
    message: str
    stage: str
    timestamp: str
    traceback: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "label": self.label,
            "error_type": self.error_type,
            "message": self.message,
            "stage": self.stage,
            "timestamp": self.timestamp,
            "traceback": self.traceback,
        }


@dataclass
class ExtractionStats:
    """Counters accumulated during extraction."""

    discovered: int = 0
    selected: int = 0
    processed: int = 0
    successful: int = 0
    failed: int = 0
    skipped: int = 0

    duplicate_hashes: int = 0
    duplicate_sample_ids: int = 0

    benign: int = 0
    malicious: int = 0
    other_labels: int = 0

    total_bytes: int = 0
    successful_bytes: int = 0

    started_at: str = ""
    finished_at: str = ""
    elapsed_seconds: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ExtractionResult:
    """Complete result of a dataset extraction run."""

    config: ExtractionConfig
    dataset: Optional[Dataset]
    schema: Any
    stats: ExtractionStats
    failures: list[ExtractionFailure] = field(default_factory=list)
    dataset_fingerprint: str = ""
    schema_fingerprint: str = ""

    def to_dict(self) -> dict[str, Any]:
        schema_value = self.schema

        if is_dataclass(schema_value):
            schema_value = asdict(schema_value)

        return {
            "module": MODULE_NAME,
            "version": SCRIPT_VERSION,
            "config": {
                key: (
                    str(value)
                    if isinstance(value, Path)
                    else list(value) if isinstance(value, tuple) else value
                )
                for key, value in asdict(self.config).items()
            },
            "stats": self.stats.to_dict(),
            "dataset_fingerprint": self.dataset_fingerprint,
            "schema_fingerprint": self.schema_fingerprint,
            "failure_count": len(self.failures),
            "failures": [failure.to_dict() for failure in self.failures],
            "schema": schema_value,
        }


# ---------------------------------------------------------------------------
# Generic helpers
# ---------------------------------------------------------------------------


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def safe_text(
    value: Any,
    maximum: int = 4_096,
) -> str:
    if value is None:
        return ""

    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")

    return str(value)[:maximum]


def normalize_label(value: Any) -> str:
    return safe_text(value, 128).strip().lower().replace(" ", "_").replace("-", "_")


def normalize_split(value: Any) -> str:
    return safe_text(value, 128).strip().lower().replace(" ", "_")


def sha256_file(
    path: Path,
    *,
    chunk_size: int = 1024 * 1024,
) -> str:
    """Calculate SHA-256 without loading the entire sample into memory."""

    digest = hashlib.sha256()

    with path.open("rb") as handle:
        while True:
            chunk = handle.read(chunk_size)

            if not chunk:
                break

            digest.update(chunk)

    return digest.hexdigest()


def ensure_directory(path: Path) -> None:
    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )


def json_safe(
    value: Any,
    *,
    depth: int = 0,
    max_depth: int = 12,
) -> Any:
    """Convert arbitrary values into bounded JSON-compatible values."""

    if depth > max_depth:
        return "<max-depth>"

    if value is None:
        return None

    if isinstance(value, (str, int, float, bool)):
        if isinstance(value, float) and not math.isfinite(value):
            return None

        return value

    if isinstance(value, Path):
        return str(value)

    if is_dataclass(value):
        return json_safe(
            asdict(value),
            depth=depth + 1,
            max_depth=max_depth,
        )

    if isinstance(value, Mapping):
        result: dict[str, Any] = {}

        for key, item in list(value.items())[:10_000]:
            result[safe_text(key, 512)] = json_safe(
                item,
                depth=depth + 1,
                max_depth=max_depth,
            )

        return result

    if isinstance(value, (list, tuple, set, frozenset)):
        return [
            json_safe(
                item,
                depth=depth + 1,
                max_depth=max_depth,
            )
            for item in list(value)[:10_000]
        ]

    return safe_text(value, 4_096)


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


def validate_config(config: ExtractionConfig) -> None:
    if not config.classes:
        raise ConfigurationError("At least one dataset class is required.")

    if len(set(config.classes)) != len(config.classes):
        raise ConfigurationError("Dataset class names must be unique.")

    for label in config.classes:
        if not normalize_label(label):
            raise ConfigurationError("Dataset class names cannot be empty.")

    if config.max_file_size <= 0:
        raise ConfigurationError("max_file_size must be greater than zero.")

    if config.max_files <= 0:
        raise ConfigurationError("max_files must be greater than zero.")

    if config.max_errors < 0:
        raise ConfigurationError("max_errors cannot be negative.")

    if config.log_every <= 0:
        raise ConfigurationError("log_every must be greater than zero.")

    if config.seed < 0:
        raise ConfigurationError("seed cannot be negative.")


def make_config(
    *,
    input_root: Path = DEFAULT_INPUT_ROOT,
    output_path: Path = DEFAULT_OUTPUT_PATH,
    schema_path: Path = DEFAULT_SCHEMA_PATH,
    manifest_path: Path = DEFAULT_MANIFEST_PATH,
    classes: Sequence[str] = DEFAULT_CLASSES,
    recursive: bool = True,
    deduplicate: bool = True,
    fail_fast: bool = False,
    include_unsupported: bool = False,
    allow_empty_classes: bool = False,
    max_file_size: int = DEFAULT_MAX_FILE_SIZE,
    max_files: int = DEFAULT_MAX_FILES,
    max_errors: int = DEFAULT_MAX_ERRORS,
    log_every: int = DEFAULT_LOG_EVERY,
    include_paths_in_records: bool = False,
    preserve_sample_metadata: bool = True,
    split: str = "",
    seed: int = 42,
) -> ExtractionConfig:
    normalized_classes = tuple(normalize_label(label) for label in classes)

    config = ExtractionConfig(
        input_root=Path(input_root),
        output_path=Path(output_path),
        schema_path=Path(schema_path),
        manifest_path=Path(manifest_path),
        classes=normalized_classes,
        recursive=recursive,
        deduplicate=deduplicate,
        fail_fast=fail_fast,
        include_unsupported=include_unsupported,
        allow_empty_classes=allow_empty_classes,
        max_file_size=max_file_size,
        max_files=max_files,
        max_errors=max_errors,
        log_every=log_every,
        include_paths_in_records=include_paths_in_records,
        preserve_sample_metadata=preserve_sample_metadata,
        split=normalize_split(split),
        seed=seed,
    )

    validate_config(config)
    return config


# ---------------------------------------------------------------------------
# File discovery
# ---------------------------------------------------------------------------


def is_ignored_directory(path: Path) -> bool:
    return any(part in IGNORED_DIRECTORIES for part in path.parts)


def is_supported_extension(path: Path) -> bool:
    return path.suffix.lower() in SUPPORTED_EXTENSIONS


def discover_class_files(
    root: Path,
    label: str,
    *,
    recursive: bool,
    include_unsupported: bool,
) -> list[Path]:
    """Discover files belonging to one class directory."""

    class_root = root / label

    if not class_root.exists():
        return []

    if not class_root.is_dir():
        raise ConfigurationError(f"Dataset class path is not a directory: {class_root}")

    pattern = "**/*" if recursive else "*"

    discovered: list[Path] = []

    for path in class_root.glob(pattern):
        if not path.is_file():
            continue

        try:
            relative_to_root = path.relative_to(root)
        except ValueError:
            continue

        if is_ignored_directory(relative_to_root):
            continue

        if not include_unsupported and not is_supported_extension(path):
            continue

        discovered.append(path)

    discovered.sort(
        key=lambda item: (str(item.relative_to(root)).replace(os.sep, "/").lower())
    )

    return discovered


def discover_samples(
    config: ExtractionConfig,
) -> list[SampleCandidate]:
    """Discover all candidate files in deterministic order."""

    root = config.input_root.resolve()

    if not root.exists():
        raise ConfigurationError(f"Input root does not exist: {root}")

    if not root.is_dir():
        raise ConfigurationError(f"Input root is not a directory: {root}")

    candidates: list[SampleCandidate] = []

    for label in config.classes:
        paths = discover_class_files(
            root,
            label,
            recursive=config.recursive,
            include_unsupported=config.include_unsupported,
        )

        for path in paths:
            try:
                size = path.stat().st_size
            except OSError as exc:
                LOGGER.warning(
                    "Unable to stat %s: %s",
                    path,
                    exc,
                )
                continue

            relative = str(path.relative_to(root)).replace(os.sep, "/")

            candidates.append(
                SampleCandidate(
                    path=path,
                    label=label,
                    relative_path=relative,
                    extension=path.suffix.lower(),
                    size_bytes=size,
                )
            )

    candidates.sort(
        key=lambda item: (
            item.label,
            item.relative_path.lower(),
        )
    )

    if len(candidates) > config.max_files:
        raise SampleLimitError(
            f"Discovered {len(candidates):,} files, "
            f"exceeding max_files={config.max_files:,}."
        )

    return candidates


def validate_candidates(
    candidates: Sequence[SampleCandidate],
    config: ExtractionConfig,
) -> list[SampleCandidate]:
    """Apply file-size and class-level constraints."""

    selected: list[SampleCandidate] = []
    class_counts = {label: 0 for label in config.classes}

    for candidate in candidates:
        if candidate.size_bytes <= 0:
            LOGGER.warning(
                "Skipping empty file: %s",
                candidate.path,
            )
            continue

        if candidate.size_bytes > config.max_file_size:
            LOGGER.warning(
                "Skipping oversized file: %s " "(%d bytes > %d)",
                candidate.path,
                candidate.size_bytes,
                config.max_file_size,
            )
            continue

        class_counts[candidate.label] = class_counts.get(candidate.label, 0) + 1

        selected.append(candidate)

    if not config.allow_empty_classes:
        missing = [label for label in config.classes if class_counts.get(label, 0) == 0]

        if missing:
            raise ConfigurationError(
                "No usable samples found for class(es): " + ", ".join(missing)
            )

    return selected


# ---------------------------------------------------------------------------
# Single-file discovery
# ---------------------------------------------------------------------------


def infer_single_file_label(
    path: Path,
    *,
    input_root: Optional[Path] = None,
    classes: Sequence[str] = DEFAULT_CLASSES,
) -> str:
    """
    Infer a single-file label from its parent directory when possible.

    If the path is under:

        data/raw/benign/
        data/raw/malicious/

    the corresponding directory name is used.

    Otherwise "unknown" is returned.
    """

    normalized_classes = {normalize_label(label) for label in classes}

    resolved_path = path.resolve()

    if input_root is not None:
        try:
            relative = resolved_path.relative_to(Path(input_root).resolve())

            if relative.parts:
                candidate = normalize_label(relative.parts[0])

                if candidate in normalized_classes:
                    return candidate

        except ValueError:
            pass

    parent_name = normalize_label(resolved_path.parent.name)

    if parent_name in normalized_classes:
        return parent_name

    return "unknown"


def make_single_file_candidate(
    path: Path,
    *,
    label: Optional[str] = None,
    input_root: Optional[Path] = None,
    classes: Sequence[str] = DEFAULT_CLASSES,
    max_file_size: int = DEFAULT_MAX_FILE_SIZE,
    include_unsupported: bool = False,
) -> SampleCandidate:
    """Create a candidate record for one input file."""

    path = Path(path).expanduser().resolve()

    if not path.exists():
        raise ConfigurationError(f"Input file does not exist: {path}")

    if not path.is_file():
        raise ConfigurationError(f"Input path is not a file: {path}")

    size = path.stat().st_size

    if size <= 0:
        raise ConfigurationError(f"Input file is empty: {path}")

    if size > max_file_size:
        raise ConfigurationError(
            f"Input file exceeds max_file_size=" f"{max_file_size:,}: {path}"
        )

    extension = path.suffix.lower()

    if not include_unsupported and extension not in SUPPORTED_EXTENSIONS:
        raise ConfigurationError(
            f"Unsupported file extension: "
            f"{extension or '<none>'}. "
            "Use --include-unsupported to override."
        )

    if label is None:
        label = infer_single_file_label(
            path,
            input_root=input_root,
            classes=classes,
        )
    else:
        label = normalize_label(label)

    try:
        if input_root is not None:
            relative_path = str(path.relative_to(Path(input_root).resolve())).replace(
                os.sep, "/"
            )
        else:
            relative_path = path.name

    except ValueError:
        relative_path = path.name

    return SampleCandidate(
        path=path,
        label=label,
        relative_path=relative_path,
        extension=extension,
        size_bytes=size,
    )


# ---------------------------------------------------------------------------
# Feature pipeline adapter
# ---------------------------------------------------------------------------


def _call_pipeline(path: Path) -> Any:
    """
    Invoke the project's static feature pipeline.

    The current Pharos pipeline exposes analyze_file(path), but compatible
    public entry points are retained for forward/backward compatibility.
    """

    if analyze_file is not None:
        attempts = (
            lambda: analyze_file(path),
            lambda: analyze_file(path=path),
            lambda: analyze_file(file_path=path),
            lambda: analyze_file(str(path)),
            lambda: analyze_file(path=str(path)),
            lambda: analyze_file(file_path=str(path)),
        )

        last_type_error: Optional[TypeError] = None

        for attempt in attempts:
            try:
                return attempt()
            except TypeError as exc:
                last_type_error = exc

        if last_type_error is not None:
            raise FeatureExtractionError(
                "The available analyze_file/analyze entry point "
                "does not accept a supported input signature."
            ) from last_type_error

    if extract_features is not None:
        attempts = (
            lambda: extract_features(path),
            lambda: extract_features(path=path),
            lambda: extract_features(file_path=path),
            lambda: extract_features(str(path)),
            lambda: extract_features(path=str(path)),
            lambda: extract_features(file_path=str(path)),
        )

        last_type_error = None

        for attempt in attempts:
            try:
                return attempt()
            except TypeError as exc:
                last_type_error = exc

        if last_type_error is not None:
            raise FeatureExtractionError(
                "The available extract_features entry point "
                "does not accept a supported input signature."
            ) from last_type_error

    raise FeatureExtractionError(
        "No compatible static feature-pipeline entry point " "is available."
    )


def _extract_from_analysis(
    analysis: Any,
) -> dict[str, float]:
    """
    Convert a feature-pipeline result into a flat numeric feature mapping.
    """

    if analysis is None:
        raise FeatureExtractionError("Feature pipeline returned no analysis.")

    if isinstance(analysis, Mapping):
        mapping = analysis

    elif is_dataclass(analysis):
        mapping = asdict(analysis)

    elif hasattr(analysis, "to_dict"):
        mapping = analysis.to_dict()

    else:
        mapping = {}

        for attribute in (
            "feature_vector",
            "features",
            "feature_values",
            "vector",
        ):
            if hasattr(analysis, attribute):
                value = getattr(
                    analysis,
                    attribute,
                )

                if isinstance(value, Mapping):
                    mapping = value
                    break

        if not mapping:
            raise FeatureExtractionError(
                "Feature pipeline returned an unsupported " "analysis object."
            )

    for key in (
        "feature_vector",
        "features",
        "feature_values",
        "vector",
    ):
        value = mapping.get(key)

        if isinstance(value, Mapping):
            return _flatten_numeric_mapping(value)

    return _flatten_numeric_mapping(mapping)


def _flatten_numeric_mapping(
    value: Any,
    *,
    prefix: str = "",
    output: Optional[dict[str, float]] = None,
    depth: int = 0,
    max_depth: int = 12,
) -> dict[str, float]:
    """
    Flatten numeric feature mappings deterministically.

    Boolean values become 0/1.
    Descriptive identity fields are ignored.
    """

    if output is None:
        output = {}

    if depth > max_depth:
        return output

    if isinstance(value, Mapping):
        for key in sorted(
            value.keys(),
            key=lambda item: str(item),
        ):
            key_text = safe_text(
                key,
                512,
            ).strip()

            if not key_text:
                continue

            normalized_key = key_text.lower().replace(" ", "_").replace("-", "_")

            if not prefix and normalized_key in IDENTITY_KEYS:
                continue

            child_prefix = f"{prefix}.{key_text}" if prefix else key_text

            _flatten_numeric_mapping(
                value[key],
                prefix=child_prefix,
                output=output,
                depth=depth + 1,
                max_depth=max_depth,
            )

        return output

    if isinstance(value, (list, tuple)):
        for index, child in enumerate(value[:10_000]):
            child_prefix = f"{prefix}.{index}" if prefix else str(index)

            _flatten_numeric_mapping(
                child,
                prefix=child_prefix,
                output=output,
                depth=depth + 1,
                max_depth=max_depth,
            )

        return output

    if not prefix:
        return output

    if isinstance(value, bool):
        output[prefix] = 1.0 if value else 0.0
        return output

    if isinstance(value, (int, float)):
        number = float(value)

        if not math.isfinite(number):
            number = 0.0

        output[prefix] = number

    return output


# ---------------------------------------------------------------------------
# DatasetRecord compatibility / identity handling
# ---------------------------------------------------------------------------


def _dataset_record_supported_fields() -> Optional[set[str]]:
    """
    Return DatasetRecord constructor fields when introspection is available.

    None means the constructor could not be inspected and the compatibility
    fallback should be used.
    """

    try:
        signature = inspect.signature(DatasetRecord)
    except (TypeError, ValueError):
        return None

    supported: set[str] = set()

    for name, parameter in signature.parameters.items():
        if name == "self":
            continue

        if parameter.kind in (
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
            inspect.Parameter.KEYWORD_ONLY,
        ):
            supported.add(name)

    return supported


def _build_dataset_record(
    *,
    sample_id: str,
    features: Mapping[str, float],
    label: str,
    metadata: Mapping[str, Any],
    sha256: str,
    filename: str,
    source: str,
    split: str,
) -> DatasetRecord:
    """
    Construct DatasetRecord while adapting to the project's actual schema.

    The canonical identity values are supplied whenever DatasetRecord exposes
    corresponding fields:

        sample_id
        sha256
        filename
        source
        split
        label
        features
        metadata

    This avoids silently losing identity information during CSV serialization
    when the DatasetRecord implementation provides these columns.
    """

    common_values: dict[str, Any] = {
        "sample_id": sample_id,
        "features": dict(features),
        "label": label,
        "metadata": dict(metadata),
        # Explicit dataset identity fields.
        "sha256": sha256,
        "filename": filename,
        "source": source,
        "split": split,
    }

    supported = _dataset_record_supported_fields()

    if supported is not None:
        kwargs = {
            key: value for key, value in common_values.items() if key in supported
        }

        try:
            return DatasetRecord(**kwargs)
        except TypeError as exc:
            raise DatasetBuildError(
                "Unable to construct DatasetRecord using the "
                f"supported fields {sorted(supported)}: {exc}"
            ) from exc

    # If the constructor cannot be introspected, try the canonical original
    # constructor first.
    try:
        return DatasetRecord(
            sample_id=sample_id,
            features=dict(features),
            label=label,
            metadata=dict(metadata),
        )
    except TypeError as exc:
        raise DatasetBuildError(
            "Unable to construct DatasetRecord: " f"{safe_text(exc, 2_000)}"
        ) from exc


# ---------------------------------------------------------------------------
# Record creation
# ---------------------------------------------------------------------------


def make_sample_id(
    candidate: SampleCandidate,
) -> str:
    """
    Produce the canonical deterministic sample identifier.

    IMPORTANT:
        sample_id is exactly the SHA-256 of the source file bytes.

    This gives the project a direct identity chain:

        file bytes -> SHA-256 -> sample_id -> feature vector -> dataset row

    It also means duplicate content produces the same sample_id regardless
    of filename, directory, or dataset label.
    """

    if not candidate.sha256:
        candidate.sha256 = sha256_file(candidate.path)

    return candidate.sha256.lower()


def build_record(
    candidate: SampleCandidate,
    analysis: Any,
    *,
    include_path: bool,
    preserve_metadata: bool,
    split: str = "",
) -> DatasetRecord:
    """Convert one static analysis result into a DatasetRecord."""

    features = _extract_from_analysis(analysis)

    if not features:
        raise FeatureExtractionError("No numeric features were produced.")

    if len(features) > DEFAULT_MAX_FEATURES:
        raise FeatureExtractionError(
            f"Feature count {len(features):,} exceeds "
            f"maximum supported feature count "
            f"{DEFAULT_MAX_FEATURES:,}."
        )

    if not candidate.sha256:
        try:
            candidate.sha256 = sha256_file(candidate.path)
        except OSError as exc:
            raise FeatureExtractionError(
                f"Unable to calculate source SHA-256: {exc}"
            ) from exc

    candidate.sha256 = candidate.sha256.lower()

    if len(candidate.sha256) != 64:
        raise FeatureExtractionError("Invalid source SHA-256 was produced.")

    sample_id = make_sample_id(candidate)

    filename = candidate.path.name
    source = candidate.relative_path
    normalized_split = normalize_split(split)

    # These fields are deliberately retained even when
    # preserve_sample_metadata is disabled. They are core dataset identity
    # fields, not optional diagnostic metadata.
    metadata: dict[str, Any] = {
        "label_source": "directory_or_cli",
        "source_class": candidate.label,
        "extension": candidate.extension,
        "size_bytes": candidate.size_bytes,
        "sha256": candidate.sha256,
        "filename": filename,
        "relative_path": candidate.relative_path,
        "source": source,
        "split": normalized_split,
    }

    if include_path:
        metadata["path"] = str(candidate.path)

    if not preserve_metadata:
        # Keep only the fields necessary to maintain a portable identity
        # chain. Absolute paths remain excluded unless explicitly requested.
        metadata = {
            "sha256": candidate.sha256,
            "filename": filename,
            "source": source,
            "split": normalized_split,
            "label": candidate.label,
            "extension": candidate.extension,
            "size_bytes": candidate.size_bytes,
        }

        if include_path:
            metadata["path"] = str(candidate.path)

    return _build_dataset_record(
        sample_id=sample_id,
        features=features,
        label=candidate.label,
        metadata=metadata,
        sha256=candidate.sha256,
        filename=filename,
        source=source,
        split=normalized_split,
    )


def extract_candidate(
    candidate: SampleCandidate,
    config: ExtractionConfig,
) -> DatasetRecord:
    """Extract one sample using the static feature pipeline."""

    try:
        candidate.sha256 = sha256_file(candidate.path)
    except OSError as exc:
        raise FeatureExtractionError(f"Unable to hash sample: {exc}") from exc

    try:
        analysis = _call_pipeline(candidate.path)

    except DatasetExtractionError:
        raise

    except Exception as exc:
        raise FeatureExtractionError(
            "Static feature extraction failed: " f"{safe_text(exc)}"
        ) from exc

    return build_record(
        candidate,
        analysis,
        include_path=config.include_paths_in_records,
        preserve_metadata=config.preserve_sample_metadata,
        split=config.split,
    )


# ---------------------------------------------------------------------------
# Extraction engine
# ---------------------------------------------------------------------------


def extract_records(
    candidates: Sequence[SampleCandidate],
    config: ExtractionConfig,
) -> tuple[
    list[DatasetRecord],
    ExtractionStats,
    list[ExtractionFailure],
]:
    """
    Extract feature records in deterministic single-process order.
    """

    stats = ExtractionStats(started_at=utc_now())

    stats.discovered = len(candidates)

    records: list[DatasetRecord] = []
    failures: list[ExtractionFailure] = []

    for index, candidate in enumerate(
        candidates,
        start=1,
    ):
        stats.selected += 1
        stats.total_bytes += candidate.size_bytes

        try:
            record = extract_candidate(
                candidate,
                config,
            )

            records.append(record)

            stats.successful += 1
            stats.successful_bytes += candidate.size_bytes

            if candidate.label == "benign":
                stats.benign += 1

            elif candidate.label == "malicious":
                stats.malicious += 1

            else:
                stats.other_labels += 1

        except Exception as exc:
            stats.failed += 1

            failure = ExtractionFailure(
                path=candidate.relative_path,
                label=candidate.label,
                error_type=type(exc).__name__,
                message=safe_text(
                    exc,
                    2_000,
                ),
                stage="feature_extraction",
                timestamp=utc_now(),
                traceback=(
                    traceback.format_exc()
                    if LOGGER.isEnabledFor(logging.DEBUG)
                    else None
                ),
            )

            failures.append(failure)

            LOGGER.error(
                "Failed sample %d/%d: %s — %s",
                index,
                len(candidates),
                candidate.path,
                exc,
            )

            if len(failures) > config.max_errors:
                raise SampleLimitError(
                    "Maximum extraction error count " f"exceeded: {config.max_errors}"
                )

            if config.fail_fast:
                raise

        stats.processed += 1

        if index % config.log_every == 0 or index == len(candidates):
            LOGGER.info(
                "Processed %d/%d samples; " "successful=%d failed=%d",
                index,
                len(candidates),
                stats.successful,
                stats.failed,
            )

    stats.finished_at = utc_now()

    try:
        started = datetime.fromisoformat(stats.started_at)
        finished = datetime.fromisoformat(stats.finished_at)

        stats.elapsed_seconds = max(
            0.0,
            (finished - started).total_seconds(),
        )

    except Exception:
        stats.elapsed_seconds = 0.0

    return (
        records,
        stats,
        failures,
    )


# ---------------------------------------------------------------------------
# Duplicate handling
# ---------------------------------------------------------------------------


def _record_identity(
    record: DatasetRecord,
) -> tuple[str, str]:
    """
    Extract canonical sample ID and SHA-256 from a DatasetRecord.

    SHA-256 is checked both as a first-class field and inside metadata.
    """

    sample_id = (
        safe_text(
            getattr(
                record,
                "sample_id",
                "",
            ),
            512,
        )
        .strip()
        .lower()
    )

    digest = (
        safe_text(
            getattr(
                record,
                "sha256",
                "",
            ),
            128,
        )
        .strip()
        .lower()
    )

    metadata = getattr(
        record,
        "metadata",
        {},
    )

    if isinstance(metadata, Mapping):
        if not digest:
            digest = (
                safe_text(
                    metadata.get("sha256", ""),
                    128,
                )
                .strip()
                .lower()
            )

        if not sample_id:
            sample_id = (
                safe_text(
                    metadata.get("sample_id", ""),
                    512,
                )
                .strip()
                .lower()
            )

    return sample_id, digest


def deduplicate_dataset_records(
    records: Sequence[DatasetRecord],
) -> tuple[
    list[DatasetRecord],
    int,
    int,
]:
    """
    Remove duplicate sample IDs and duplicate content hashes.

    First deterministic occurrence is retained.
    """

    seen_ids: set[str] = set()
    seen_hashes: set[str] = set()

    unique: list[DatasetRecord] = []

    duplicate_ids = 0
    duplicate_hashes = 0

    for record in records:
        sample_id, digest = _record_identity(record)

        if sample_id and sample_id in seen_ids:
            duplicate_ids += 1
            continue

        if digest and digest in seen_hashes:
            duplicate_hashes += 1
            continue

        if sample_id:
            seen_ids.add(sample_id)

        if digest:
            seen_hashes.add(digest)

        unique.append(record)

    return (
        unique,
        duplicate_ids,
        duplicate_hashes,
    )


# ---------------------------------------------------------------------------
# Dataset creation
# ---------------------------------------------------------------------------


def build_dataset(
    records: Sequence[DatasetRecord],
) -> Dataset:
    """Build the project's canonical Dataset object."""

    if not records:
        raise DatasetBuildError("No successful feature records were produced.")

    try:
        return create_dataset(records)

    except TypeError:
        try:
            return create_dataset(records=list(records))

        except Exception as exc:
            raise DatasetBuildError(f"Unable to create dataset: {exc}") from exc

    except Exception as exc:
        raise DatasetBuildError(f"Unable to create dataset: {exc}") from exc


# ---------------------------------------------------------------------------
# Manifest generation
# ---------------------------------------------------------------------------


def build_manifest(
    result: ExtractionResult,
) -> dict[str, Any]:
    """Build a machine-readable dataset manifest."""

    dataset = result.dataset

    statistics: Any = {}

    if dataset is not None:
        try:
            statistics = dataset_statistics(dataset)

            if is_dataclass(statistics):
                statistics = asdict(statistics)

            elif hasattr(statistics, "to_dict"):
                statistics = statistics.to_dict()

        except Exception as exc:
            LOGGER.warning(
                "Unable to compute dataset statistics: %s",
                exc,
            )

    manifest = {
        "manifest_version": "1.1",
        "module": MODULE_NAME,
        "script_version": SCRIPT_VERSION,
        "generated_at": utc_now(),
        "identity": {
            "sample_id_definition": ("SHA-256 digest of source file bytes"),
            "content_hash_algorithm": "sha256",
            "path_independent": True,
        },
        "dataset": {
            "fingerprint": result.dataset_fingerprint,
            "schema_fingerprint": result.schema_fingerprint,
            "statistics": json_safe(statistics),
        },
        "extraction": result.stats.to_dict(),
        "configuration": {
            key: (
                str(value)
                if isinstance(value, Path)
                else list(value) if isinstance(value, tuple) else value
            )
            for key, value in asdict(result.config).items()
        },
        "classes": list(result.config.classes),
        "supported_extensions": sorted(SUPPORTED_EXTENSIONS),
        "failures": [failure.to_dict() for failure in result.failures],
    }

    return json_safe(manifest)


def save_manifest(
    manifest: Mapping[str, Any],
    path: Path,
) -> None:
    """Write a deterministic JSON manifest."""

    ensure_directory(path)

    with path.open(
        "w",
        encoding="utf-8",
        newline="\n",
    ) as handle:
        json.dump(
            manifest,
            handle,
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
        )

        handle.write("\n")


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------


def save_dataset_artifacts(
    dataset: Dataset,
    schema: Any,
    config: ExtractionConfig,
) -> None:
    """Persist dataset and feature schema."""

    ensure_directory(config.output_path)
    ensure_directory(config.schema_path)

    suffix = config.output_path.suffix.lower()

    if suffix in {
        ".jsonl",
        ".ndjson",
    }:
        save_jsonl(
            dataset,
            config.output_path,
        )

    elif suffix == ".csv":
        save_csv(
            dataset,
            config.output_path,
        )

    else:
        save_dataset(
            dataset,
            config.output_path,
        )

    save_schema(
        schema,
        config.schema_path,
    )


# ---------------------------------------------------------------------------
# Main dataset extraction
# ---------------------------------------------------------------------------


def extract_dataset(
    config: ExtractionConfig,
) -> ExtractionResult:
    """Execute one complete dataset extraction run."""

    validate_config(config)

    started = time.monotonic()

    LOGGER.info("Starting dataset extraction.")

    LOGGER.info(
        "Input root: %s",
        config.input_root,
    )

    candidates = discover_samples(config)

    candidates = validate_candidates(
        candidates,
        config,
    )

    if not candidates:
        raise DatasetBuildError("No usable samples were discovered.")

    records, stats, failures = extract_records(
        candidates,
        config,
    )

    if config.deduplicate:
        (
            records,
            duplicate_ids,
            duplicate_hashes,
        ) = deduplicate_dataset_records(records)

        stats.duplicate_sample_ids = duplicate_ids
        stats.duplicate_hashes = duplicate_hashes

    if not records:
        raise DatasetBuildError(
            "No valid dataset records remain " "after extraction and deduplication."
        )

    records.sort(
        key=lambda record: (
            safe_text(
                getattr(
                    record,
                    "label",
                    "",
                ),
                128,
            ),
            safe_text(
                getattr(
                    record,
                    "sample_id",
                    "",
                ),
                512,
            ),
        )
    )

    dataset = build_dataset(records)

    try:
        schema = build_schema(records)

    except TypeError:
        try:
            schema = build_schema(dataset)

        except Exception as exc:
            raise DatasetBuildError(f"Schema construction failed: {exc}") from exc

    except Exception as exc:
        raise DatasetBuildError(f"Schema construction failed: {exc}") from exc

    try:
        validation = validate_dataset(dataset)

        if validation is False:
            raise DatasetBuildError("Dataset validation returned false.")

    except TypeError:
        try:
            validation = validate_dataset(
                dataset,
                schema=schema,
            )

            if validation is False:
                raise DatasetBuildError("Dataset validation returned false.")

        except Exception as exc:
            raise DatasetBuildError(f"Dataset validation failed: {exc}") from exc

    except Exception as exc:
        raise DatasetBuildError(f"Dataset validation failed: {exc}") from exc

    try:
        fingerprint = dataset_fingerprint(dataset)

    except Exception as exc:
        LOGGER.warning(
            "Unable to calculate dataset fingerprint: %s",
            exc,
        )

        fingerprint = ""

    schema_fp = ""

    if calculate_schema_fingerprint is not None:
        try:
            schema_fp = calculate_schema_fingerprint(schema)

        except Exception as exc:
            LOGGER.warning(
                "Unable to calculate schema fingerprint: %s",
                exc,
            )

    result = ExtractionResult(
        config=config,
        dataset=dataset,
        schema=schema,
        stats=stats,
        failures=failures,
        dataset_fingerprint=fingerprint,
        schema_fingerprint=schema_fp,
    )

    save_dataset_artifacts(
        dataset,
        schema,
        config,
    )

    save_manifest(
        build_manifest(result),
        config.manifest_path,
    )

    elapsed = time.monotonic() - started

    LOGGER.info(
        "Dataset extraction complete: " "%d records, %d failures, %.2fs.",
        len(records),
        len(failures),
        elapsed,
    )

    return result


# ---------------------------------------------------------------------------
# Single-file extraction
# ---------------------------------------------------------------------------


def extract_single_file(
    *,
    input_path: Path,
    output_path: Path,
    schema_path: Optional[Path] = None,
    manifest_path: Optional[Path] = None,
    label: Optional[str] = None,
    input_root: Optional[Path] = None,
    include_path: bool = False,
    preserve_metadata: bool = True,
    max_file_size: int = DEFAULT_MAX_FILE_SIZE,
    include_unsupported: bool = False,
    split: str = "",
    seed: int = 42,
) -> ExtractionResult:
    """
    Extract static features from exactly one file.

    The output is a one-record Dataset serialized using the extension of
    output_path. CSV is recommended for interactive inspection.
    """

    input_path = Path(input_path).expanduser().resolve()

    output_path = Path(output_path).expanduser().resolve()

    if not input_path.exists():
        raise ConfigurationError(f"Input file does not exist: {input_path}")

    if not input_path.is_file():
        raise ConfigurationError(f"Input path is not a file: {input_path}")

    extension = input_path.suffix.lower()

    if not include_unsupported and extension not in SUPPORTED_EXTENSIONS:
        raise ConfigurationError(
            f"Unsupported file extension: "
            f"{extension or '<none>'}. "
            "Use --include-unsupported to override."
        )

    inferred_label = (
        normalize_label(label)
        if label
        else infer_single_file_label(
            input_path,
            input_root=input_root,
        )
    )

    candidate = make_single_file_candidate(
        input_path,
        label=inferred_label,
        input_root=input_root,
        max_file_size=max_file_size,
        include_unsupported=include_unsupported,
    )

    config = make_config(
        input_root=(input_root if input_root is not None else input_path.parent),
        output_path=output_path,
        schema_path=(
            schema_path
            if schema_path is not None
            else output_path.with_suffix(".schema.json")
        ),
        manifest_path=(
            manifest_path
            if manifest_path is not None
            else output_path.with_suffix(".manifest.json")
        ),
        classes=(inferred_label,),
        recursive=False,
        deduplicate=False,
        fail_fast=True,
        include_unsupported=include_unsupported,
        allow_empty_classes=True,
        max_file_size=max_file_size,
        max_files=1,
        max_errors=0,
        log_every=1,
        include_paths_in_records=include_path,
        preserve_sample_metadata=preserve_metadata,
        split=split,
        seed=seed,
    )

    records, stats, failures = extract_records(
        [candidate],
        config,
    )

    if not records:
        message = failures[0].message if failures else "No features were produced."

        raise FeatureExtractionError(message)

    dataset = build_dataset(records)

    try:
        schema = build_schema(records)

    except TypeError:
        schema = build_schema(dataset)

    try:
        validation = validate_dataset(dataset)

    except TypeError:
        validation = validate_dataset(
            dataset,
            schema=schema,
        )

    if validation is False:
        raise DatasetBuildError("Single-file dataset validation returned false.")

    try:
        fingerprint = dataset_fingerprint(dataset)

    except Exception:
        fingerprint = ""

    schema_fp = ""

    if calculate_schema_fingerprint is not None:
        try:
            schema_fp = calculate_schema_fingerprint(schema)

        except Exception:
            schema_fp = ""

    result = ExtractionResult(
        config=config,
        dataset=dataset,
        schema=schema,
        stats=stats,
        failures=failures,
        dataset_fingerprint=fingerprint,
        schema_fingerprint=schema_fp,
    )

    save_dataset_artifacts(
        dataset,
        schema,
        config,
    )

    save_manifest(
        build_manifest(result),
        config.manifest_path,
    )

    return result


# ---------------------------------------------------------------------------
# Summary helpers
# ---------------------------------------------------------------------------


def summarize_result(
    result: ExtractionResult,
) -> dict[str, Any]:
    return {
        "module": MODULE_NAME,
        "version": SCRIPT_VERSION,
        "records": result.stats.successful,
        "failed": result.stats.failed,
        "duplicates": (
            result.stats.duplicate_hashes + result.stats.duplicate_sample_ids
        ),
        "benign": result.stats.benign,
        "malicious": result.stats.malicious,
        "other_labels": result.stats.other_labels,
        "bytes": result.stats.successful_bytes,
        "elapsed_seconds": result.stats.elapsed_seconds,
        "dataset_fingerprint": result.dataset_fingerprint,
        "schema_fingerprint": result.schema_fingerprint,
        "output": str(result.config.output_path),
        "schema": str(result.config.schema_path),
        "manifest": str(result.config.manifest_path),
    }


def print_summary(
    result: ExtractionResult,
) -> None:
    summary = summarize_result(result)

    print()
    print("Pharos CDR dataset extraction")
    print("================================")
    print(f"Records:             {summary['records']:,}")
    print(f"Failed:              {summary['failed']:,}")
    print(f"Duplicates removed:  {summary['duplicates']:,}")
    print(f"Benign:              {summary['benign']:,}")
    print(f"Malicious:           {summary['malicious']:,}")
    print(f"Other labels:        {summary['other_labels']:,}")
    print(f"Bytes:               {summary['bytes']:,}")
    print(f"Elapsed:             {summary['elapsed_seconds']:.2f}s")

    print()
    print(f"Dataset:   {summary['output']}")
    print(f"Schema:    {summary['schema']}")
    print(f"Manifest:  {summary['manifest']}")

    if summary["dataset_fingerprint"]:
        print(f"Dataset SHA:  {summary['dataset_fingerprint']}")

    if summary["schema_fingerprint"]:
        print(f"Schema SHA:   {summary['schema_fingerprint']}")

    print()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="extract_dataset.py",
        description=(
            "Extract static Pharos CDR features and build "
            "a labeled ML dataset, or extract one file "
            "directly to CSV."
        ),
        formatter_class=(argparse.ArgumentDefaultsHelpFormatter),
    )

    # ------------------------------------------------------------------
    # Input selection
    # ------------------------------------------------------------------

    input_group = parser.add_mutually_exclusive_group()

    input_group.add_argument(
        "--input",
        type=Path,
        default=None,
        help=(
            "Extract exactly one file. This is the recommended "
            "mode for inspecting a first DOCX."
        ),
    )

    input_group.add_argument(
        "--input-root",
        type=Path,
        default=DEFAULT_INPUT_ROOT,
        help=("Dataset root containing one subdirectory per class."),
    )

    parser.add_argument(
        "--label",
        type=str,
        default=None,
        help=(
            "Label for --input mode. If omitted, the parent "
            "directory is checked for benign/malicious."
        ),
    )

    # ------------------------------------------------------------------
    # Outputs
    # ------------------------------------------------------------------

    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help=(
            "Output dataset path. Supported formats include "
            ".csv, .jsonl, and .ndjson. In single-file mode "
            "the default is data/processed/<input>_features.csv."
        ),
    )

    parser.add_argument(
        "--schema",
        type=Path,
        default=None,
        help=(
            "Feature schema output path. In single-file mode "
            "a .schema.json file is generated beside the CSV "
            "when this is omitted."
        ),
    )

    parser.add_argument(
        "--manifest",
        type=Path,
        default=None,
        help=(
            "Extraction manifest output path. In single-file mode "
            "a .manifest.json file is generated beside the CSV "
            "when this is omitted."
        ),
    )

    # ------------------------------------------------------------------
    # Dataset options
    # ------------------------------------------------------------------

    parser.add_argument(
        "--classes",
        nargs="+",
        default=list(DEFAULT_CLASSES),
        help=("Class directory names under --input-root."),
    )

    parser.add_argument(
        "--no-recursive",
        action="store_true",
        help=("Only process files directly inside each class directory."),
    )

    parser.add_argument(
        "--deduplicate",
        action="store_true",
        default=True,
        help=("Remove duplicate sample IDs/content hashes."),
    )

    parser.add_argument(
        "--no-deduplicate",
        action="store_true",
        help=("Keep duplicate sample IDs/content hashes."),
    )

    parser.add_argument(
        "--fail-fast",
        action="store_true",
        help=("Stop immediately when one sample fails."),
    )

    parser.add_argument(
        "--include-unsupported",
        action="store_true",
        help=("Pass unsupported extensions to the static " "feature pipeline."),
    )

    parser.add_argument(
        "--allow-empty-classes",
        action="store_true",
        help=("Allow class directories to contain no usable samples."),
    )

    parser.add_argument(
        "--split",
        type=str,
        default="",
        help=(
            "Optional dataset split label such as train, validation, "
            "or test. No split is invented when omitted."
        ),
    )

    # ------------------------------------------------------------------
    # Resource limits
    # ------------------------------------------------------------------

    parser.add_argument(
        "--max-file-size",
        type=int,
        default=DEFAULT_MAX_FILE_SIZE,
        help=("Maximum source file size in bytes."),
    )

    parser.add_argument(
        "--max-files",
        type=int,
        default=DEFAULT_MAX_FILES,
        help=("Maximum number of discovered files."),
    )

    parser.add_argument(
        "--max-errors",
        type=int,
        default=DEFAULT_MAX_ERRORS,
        help=("Maximum extraction failures before aborting."),
    )

    parser.add_argument(
        "--log-every",
        type=int,
        default=DEFAULT_LOG_EVERY,
        help=("Log extraction progress every N samples."),
    )

    # ------------------------------------------------------------------
    # Metadata
    # ------------------------------------------------------------------

    parser.add_argument(
        "--include-paths",
        action="store_true",
        help=(
            "Store absolute source paths in record metadata. "
            "Disabled by default for dataset portability."
        ),
    )

    parser.add_argument(
        "--no-sample-metadata",
        action="store_true",
        help=(
            "Reduce optional sample metadata while retaining "
            "canonical identity fields such as SHA-256."
        ),
    )

    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help=("Reproducibility seed stored in the manifest."),
    )

    # ------------------------------------------------------------------
    # Logging
    # ------------------------------------------------------------------

    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable informational logging.",
    )

    parser.add_argument(
        "--debug",
        action="store_true",
        help=("Enable debug logging and failure tracebacks."),
    )

    return parser


def _default_single_file_output(
    input_path: Path,
) -> Path:
    """
    Produce:

        data/processed/<stem>_features.csv
    """

    return PROJECT_ROOT / "data" / "processed" / f"{input_path.stem}_features.csv"


def _default_single_file_schema(
    output_path: Path,
) -> Path:
    return output_path.with_suffix(".schema.json")


def _default_single_file_manifest(
    output_path: Path,
) -> Path:
    return output_path.with_suffix(".manifest.json")


def config_from_namespace(
    args: argparse.Namespace,
) -> ExtractionConfig:
    """Convert dataset-mode CLI arguments into ExtractionConfig."""

    output = Path(args.output) if args.output is not None else DEFAULT_OUTPUT_PATH

    schema = Path(args.schema) if args.schema is not None else DEFAULT_SCHEMA_PATH

    manifest = (
        Path(args.manifest) if args.manifest is not None else DEFAULT_MANIFEST_PATH
    )

    return make_config(
        input_root=Path(args.input_root),
        output_path=output,
        schema_path=schema,
        manifest_path=manifest,
        classes=tuple(args.classes),
        recursive=not bool(args.no_recursive),
        deduplicate=not bool(args.no_deduplicate),
        fail_fast=bool(args.fail_fast),
        include_unsupported=bool(args.include_unsupported),
        allow_empty_classes=bool(args.allow_empty_classes),
        max_file_size=int(args.max_file_size),
        max_files=int(args.max_files),
        max_errors=int(args.max_errors),
        log_every=int(args.log_every),
        include_paths_in_records=bool(args.include_paths),
        preserve_sample_metadata=not bool(args.no_sample_metadata),
        split=args.split,
        seed=int(args.seed),
    )


# Backward-compatible alias.
config_from_args = config_from_namespace


def configure_logging(
    *,
    verbose: bool = False,
    debug: bool = False,
) -> None:
    if debug:
        level = logging.DEBUG

    elif verbose:
        level = logging.INFO

    else:
        level = logging.WARNING

    logging.basicConfig(
        level=level,
        format=("%(asctime)s | " "%(levelname)s | " "%(name)s | " "%(message)s"),
    )


def run_single_file(
    args: argparse.Namespace,
) -> ExtractionResult:
    """Run CLI single-file extraction."""

    input_path = Path(args.input).expanduser().resolve()

    output_path = (
        Path(args.output)
        if args.output is not None
        else _default_single_file_output(input_path)
    )

    schema_path = (
        Path(args.schema)
        if args.schema is not None
        else _default_single_file_schema(output_path)
    )

    manifest_path = (
        Path(args.manifest)
        if args.manifest is not None
        else _default_single_file_manifest(output_path)
    )

    return extract_single_file(
        input_path=input_path,
        output_path=output_path,
        schema_path=schema_path,
        manifest_path=manifest_path,
        label=args.label,
        input_root=(Path(args.input_root) if args.input_root is not None else None),
        include_path=bool(args.include_paths),
        preserve_metadata=not bool(args.no_sample_metadata),
        max_file_size=int(args.max_file_size),
        include_unsupported=bool(args.include_unsupported),
        split=args.split,
        seed=int(args.seed),
    )


def main(
    argv: Optional[Sequence[str]] = None,
) -> int:
    parser = build_argument_parser()

    args = parser.parse_args(argv)

    configure_logging(
        verbose=args.verbose,
        debug=args.debug,
    )

    try:
        if args.input is not None:
            result = run_single_file(args)

        else:
            config = config_from_namespace(args)
            result = extract_dataset(config)

        print_summary(result)

        return 0

    except KeyboardInterrupt:
        LOGGER.error("Dataset extraction interrupted.")

        return 130

    except DatasetExtractionError as exc:
        LOGGER.error(
            "Dataset extraction failed: %s",
            exc,
        )

        if args.debug:
            traceback.print_exc()

        return 2

    except Exception as exc:
        LOGGER.exception("Unexpected dataset extraction failure.")

        if args.debug:
            print(
                traceback.format_exc(),
                file=sys.stderr,
            )

        return 1


# ---------------------------------------------------------------------------
# Public APIs
# ---------------------------------------------------------------------------

__all__ = [
    "MODULE_NAME",
    "SCRIPT_VERSION",
    "SUPPORTED_EXTENSIONS",
    "DatasetExtractionError",
    "ConfigurationError",
    "SampleLimitError",
    "FeatureExtractionError",
    "DatasetBuildError",
    "ExtractionConfig",
    "SampleCandidate",
    "ExtractionFailure",
    "ExtractionStats",
    "ExtractionResult",
    "make_config",
    "validate_config",
    "is_ignored_directory",
    "is_supported_extension",
    "discover_class_files",
    "discover_samples",
    "validate_candidates",
    "infer_single_file_label",
    "make_single_file_candidate",
    "make_sample_id",
    "build_record",
    "extract_candidate",
    "extract_records",
    "deduplicate_dataset_records",
    "build_dataset",
    "extract_dataset",
    "extract_single_file",
    "build_manifest",
    "save_manifest",
    "save_dataset_artifacts",
    "summarize_result",
    "print_summary",
    "build_argument_parser",
    "config_from_namespace",
    "config_from_args",
    "configure_logging",
    "run_single_file",
    "main",
]


if __name__ == "__main__":
    raise SystemExit(main())
