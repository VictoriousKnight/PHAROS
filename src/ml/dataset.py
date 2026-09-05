"""
pharos-cdr/src/ml/dataset.py

Dataset construction and persistence for the Pharos CDR ML pipeline.

Responsibilities
----------------
- Convert static-analysis results into ML-ready feature records.
- Flatten nested feature dictionaries deterministically.
- Preserve sample identifiers and labels.
- Build stable feature schemas.
- Align records to a common feature space.
- Persist datasets as CSV or JSONL.
- Load datasets back into Python structures.
- Generate deterministic train/test splits.
- Produce dataset statistics and summaries.

This module does NOT:
- execute submitted files;
- execute macros or scripts;
- perform dynamic analysis;
- train models;
- make malware decisions;
- sanitize documents.

The expected architecture is:

    ingestion
        ↓
    extraction / analysis
        ↓
    dataset.py
        ↓
    train.py / predict.py / evaluation.py
        ↓
    pipeline decision / CDR

The dataset layer deliberately accepts already-extracted features rather than
performing extraction itself. This keeps feature extraction and ML concerns
loosely coupled and makes generated datasets reproducible.
"""

from __future__ import annotations

import csv
import hashlib
import json
import math
import os
import random
import statistics
from dataclasses import asdict, dataclass, field, is_dataclass
from pathlib import Path
from typing import (
    Any,
    Dict,
    Iterable,
    Iterator,
    List,
    Mapping,
    MutableMapping,
    Optional,
    Sequence,
    Tuple,
)

# ============================================================================
# Constants and limits
# ============================================================================

SCHEMA_VERSION = "1.0"
DATASET_VERSION = "1.0"

DEFAULT_MAX_RECORDS = 1_000_000
DEFAULT_MAX_FEATURES = 100_000
DEFAULT_MAX_FIELD_LENGTH = 100_000
DEFAULT_MAX_JSON_SIZE = 50 * 1024 * 1024

DEFAULT_TEST_RATIO = 0.20
DEFAULT_RANDOM_SEED = 42

LABEL_BENIGN = 0
LABEL_MALICIOUS = 1

KNOWN_LABELS = {
    0,
    1,
    "0",
    "1",
    "benign",
    "malicious",
    "clean",
    "unsafe",
    "safe",
    "suspicious",
    "malware",
    "malicious_document",
    "benign_document",
}

# Fields that are metadata rather than model features.
RESERVED_FIELDS = {
    "id",
    "sample_id",
    "sha256",
    "md5",
    "sha1",
    "path",
    "filepath",
    "file_path",
    "filename",
    "name",
    "label",
    "target",
    "class",
    "split",
    "source",
    "source_path",
    "dataset",
    "dataset_id",
    "timestamp",
    "created_at",
    "updated_at",
}

# Keys commonly produced by the extraction modules in this project.
FEATURE_CONTAINER_KEYS = (
    "feature_vector",
    "features",
    "feature_values",
    "vector",
    "ml_features",
)

IDENTITY_KEYS = (
    "sample_id",
    "id",
    "sha256",
    "filename",
    "name",
    "path",
    "filepath",
    "file_path",
)

LABEL_KEYS = (
    "label",
    "target",
    "class",
    "classification",
    "ground_truth",
)

# Feature names containing these terms can be highly informative of the
# source file identity rather than its behavioral properties. They are not
# automatically removed; the caller can explicitly request metadata exclusion.
IDENTITY_FEATURE_HINTS = (
    "sha256",
    "sha1",
    "md5",
    "filename",
    "filepath",
    "source_path",
)


# ============================================================================
# Exceptions
# ============================================================================


class DatasetError(Exception):
    """Base exception for dataset operations."""


class DatasetSchemaError(DatasetError):
    """Raised when feature schemas cannot be reconciled."""


class DatasetFormatError(DatasetError):
    """Raised when dataset serialization is malformed."""


class DatasetLimitError(DatasetError):
    """Raised when an input exceeds a configured dataset limit."""


# ============================================================================
# Dataclasses
# ============================================================================


@dataclass(frozen=True)
class FeatureDefinition:
    """Definition of one ML feature."""

    name: str
    dtype: str = "float64"
    default: float = 0.0
    description: str = ""
    source: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class FeatureSchema:
    """
    Stable feature schema used to align records.

    Feature order is deterministic and must be preserved when constructing
    matrices for model training or inference.
    """

    version: str = SCHEMA_VERSION
    features: List[FeatureDefinition] = field(default_factory=list)

    label_name: str = "label"
    id_fields: List[str] = field(default_factory=lambda: ["sample_id"])

    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.features = _deduplicate_feature_definitions(self.features)

    @property
    def feature_names(self) -> List[str]:
        return [feature.name for feature in self.features]

    @property
    def n_features(self) -> int:
        return len(self.features)

    def contains(self, name: str) -> bool:
        return name in set(self.feature_names)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": self.version,
            "features": [feature.to_dict() for feature in self.features],
            "label_name": self.label_name,
            "id_fields": list(self.id_fields),
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(
        cls,
        data: Mapping[str, Any],
    ) -> "FeatureSchema":
        raw_features = data.get("features", [])

        definitions: List[FeatureDefinition] = []

        if isinstance(raw_features, Sequence) and not isinstance(
            raw_features,
            (str, bytes, bytearray),
        ):
            for item in raw_features:
                if isinstance(item, Mapping):
                    definitions.append(
                        FeatureDefinition(
                            name=_normalize_feature_name(item.get("name", "")),
                            dtype=_safe_text(
                                item.get("dtype", "float64"),
                                32,
                            )
                            or "float64",
                            default=_safe_float(item.get("default", 0.0)),
                            description=_safe_text(
                                item.get("description", ""),
                                DEFAULT_MAX_FIELD_LENGTH,
                            ),
                            source=_safe_text(
                                item.get("source", ""),
                                1024,
                            ),
                        )
                    )

        return cls(
            version=_safe_text(
                data.get("schema_version", SCHEMA_VERSION),
                64,
            )
            or SCHEMA_VERSION,
            features=definitions,
            label_name=_normalize_feature_name(data.get("label_name", "label"))
            or "label",
            id_fields=[
                _normalize_feature_name(item)
                for item in data.get("id_fields", ["sample_id"])
                if _normalize_feature_name(item)
            ],
            metadata=dict(data.get("metadata", {})),
        )


@dataclass
class DatasetRecord:
    """
    One ML dataset sample.

    ``features`` contains only model features. Identity and label metadata are
    kept separately to avoid accidentally training on filenames or hashes.
    """

    sample_id: str
    features: Dict[str, float] = field(default_factory=dict)

    label: Optional[int] = None

    sha256: str = ""
    filename: str = ""
    source: str = ""

    split: str = ""

    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(
        self,
        *,
        include_metadata: bool = True,
    ) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "sample_id": self.sample_id,
            "label": self.label,
            "sha256": self.sha256,
            "filename": self.filename,
            "source": self.source,
            "split": self.split,
            "features": dict(self.features),
        }

        if include_metadata:
            result["metadata"] = dict(self.metadata)

        return result


@dataclass
class Dataset:
    """Collection of dataset records and their feature schema."""

    records: List[DatasetRecord] = field(default_factory=list)

    schema: FeatureSchema = field(default_factory=FeatureSchema)

    name: str = "pharos_cdr_dataset"
    version: str = DATASET_VERSION

    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.schema.features and self.records:
            self.schema = build_schema(self.records)

        self.records = [
            record for record in self.records if isinstance(record, DatasetRecord)
        ]

    @property
    def size(self) -> int:
        return len(self.records)

    @property
    def n_features(self) -> int:
        return self.schema.n_features

    @property
    def feature_names(self) -> List[str]:
        return self.schema.feature_names

    def labels(self) -> List[int]:
        return [
            int(record.label) for record in self.records if record.label is not None
        ]

    def labeled_records(self) -> List[DatasetRecord]:
        return [record for record in self.records if record.label is not None]

    def unlabeled_records(self) -> List[DatasetRecord]:
        return [record for record in self.records if record.label is None]

    def to_dict(
        self,
        *,
        include_metadata: bool = True,
    ) -> Dict[str, Any]:
        return {
            "dataset_version": self.version,
            "name": self.name,
            "schema": self.schema.to_dict(),
            "metadata": dict(self.metadata),
            "records": [
                record.to_dict(include_metadata=include_metadata)
                for record in self.records
            ],
        }


@dataclass(frozen=True)
class DatasetSplit:
    """Train/test dataset split."""

    train: Dataset
    test: Dataset
    seed: int
    test_ratio: float

    def to_dict(self) -> Dict[str, Any]:
        return {
            "seed": self.seed,
            "test_ratio": self.test_ratio,
            "train_size": self.train.size,
            "test_size": self.test.size,
        }


@dataclass
class DatasetStatistics:
    """Statistical summary of a dataset."""

    record_count: int = 0
    feature_count: int = 0

    labeled_count: int = 0
    unlabeled_count: int = 0

    benign_count: int = 0
    malicious_count: int = 0

    positive_rate: float = 0.0

    missing_feature_values: int = 0
    nonzero_feature_values: int = 0

    duplicate_sample_ids: int = 0
    duplicate_sha256: int = 0

    feature_statistics: Dict[str, Dict[str, float]] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ============================================================================
# Generic helpers
# ============================================================================


def _safe_text(
    value: Any,
    limit: int = DEFAULT_MAX_FIELD_LENGTH,
) -> str:
    if value is None:
        return ""

    try:
        text = str(value)
    except Exception:
        return ""

    if len(text) > limit:
        return text[:limit] + "..."

    return text


def _safe_float(value: Any) -> float:
    if value is None:
        return 0.0

    if isinstance(value, bool):
        return float(value)

    try:
        result = float(value)
    except (TypeError, ValueError, OverflowError):
        return 0.0

    if not math.isfinite(result):
        return 0.0

    return result


def _safe_int(
    value: Any,
) -> Optional[int]:
    if value is None:
        return None

    if isinstance(value, bool):
        return int(value)

    if isinstance(value, int):
        return int(value)

    text = _safe_text(value, 128).strip().lower()

    if text in {
        "benign",
        "clean",
        "safe",
        "negative",
        "normal",
    }:
        return LABEL_BENIGN

    if text in {
        "malicious",
        "malware",
        "unsafe",
        "suspicious",
        "positive",
        "malicious_document",
    }:
        return LABEL_MALICIOUS

    try:
        numeric = int(float(text))
    except (TypeError, ValueError):
        return None

    if numeric in (0, 1):
        return numeric

    return None


def _normalize_feature_name(
    value: Any,
) -> str:
    """
    Normalize a feature name into a deterministic identifier.

    Dots, spaces, slashes, and hyphens become underscores.
    """

    text = _safe_text(value, 512).strip().lower()

    if not text:
        return ""

    chars: List[str] = []

    for char in text:
        if char.isalnum():
            chars.append(char)
        elif char in {"_", "-", ".", "/", "\\", " "}:
            chars.append("_")

    result = "".join(chars)

    while "__" in result:
        result = result.replace("__", "_")

    return result.strip("_")


def _is_scalar(value: Any) -> bool:
    return (
        isinstance(
            value,
            (
                str,
                bytes,
                bytearray,
                int,
                float,
                bool,
            ),
        )
        or value is None
    )


def _is_sequence(value: Any) -> bool:
    return isinstance(value, Sequence) and not isinstance(
        value,
        (str, bytes, bytearray),
    )


def _dataclass_to_dict(value: Any) -> Any:
    if is_dataclass(value):
        try:
            return asdict(value)
        except Exception:
            return value

    return value


def _mapping_copy(
    value: Mapping[str, Any],
) -> Dict[str, Any]:
    result: Dict[str, Any] = {}

    for key, item in value.items():
        normalized_key = _safe_text(key, 512)

        if not normalized_key:
            continue

        result[normalized_key] = item

    return result


# ============================================================================
# Label handling
# ============================================================================


def normalize_label(
    label: Any,
) -> Optional[int]:
    """
    Normalize common benign/malicious labels to 0/1.

    Unknown labels return ``None`` rather than being silently converted.
    """

    return _safe_int(label)


def infer_label(
    value: Any,
    *,
    default: Optional[int] = None,
) -> Optional[int]:
    """
    Infer a label from a record or path-like source.

    Explicit label fields always take precedence.

    Directory-name inference is intentionally conservative and only recognizes
    common dataset conventions such as ``benign`` and ``malicious``.
    """

    if isinstance(value, Mapping):
        for key in LABEL_KEYS:
            if key in value:
                normalized = normalize_label(value[key])

                if normalized is not None:
                    return normalized

    if isinstance(value, (str, os.PathLike)):
        text = _safe_text(value, 4096).replace("\\", "/").lower()
        components = [component for component in text.split("/") if component]

        for component in reversed(components):
            if component in {
                "benign",
                "clean",
                "safe",
            }:
                return LABEL_BENIGN

            if component in {
                "malicious",
                "malware",
                "suspicious",
            }:
                return LABEL_MALICIOUS

    return default


# ============================================================================
# Feature extraction from arbitrary analysis results
# ============================================================================


def _find_feature_container(
    analysis: Mapping[str, Any],
) -> Optional[Mapping[str, Any]]:
    """
    Locate an explicit feature container.

    This avoids flattening every metadata field into a model feature.
    """

    for key in FEATURE_CONTAINER_KEYS:
        value = analysis.get(key)

        if isinstance(value, Mapping):
            return value

    return None


def _flatten_feature_mapping(
    value: Mapping[str, Any],
    *,
    prefix: str = "",
    max_features: int = DEFAULT_MAX_FEATURES,
    depth: int = 0,
    max_depth: int = 12,
) -> Dict[str, float]:
    """
    Recursively flatten nested numeric feature mappings.

    Lists and arbitrary objects are not treated as model features.
    """

    if depth > max_depth:
        return {}

    result: Dict[str, float] = {}

    for raw_key, raw_value in value.items():
        if len(result) >= max_features:
            break

        key = _normalize_feature_name(raw_key)

        if not key:
            continue

        full_key = f"{prefix}_{key}" if prefix else key

        if isinstance(raw_value, Mapping):
            nested = _flatten_feature_mapping(
                raw_value,
                prefix=full_key,
                max_features=max_features - len(result),
                depth=depth + 1,
                max_depth=max_depth,
            )
            result.update(nested)
            continue

        if _is_sequence(raw_value):
            # Numeric vectors are preserved as indexed scalar features.
            sequence = list(raw_value)

            for index, item in enumerate(sequence):
                if len(result) >= max_features:
                    break

                if isinstance(item, Mapping):
                    continue

                if isinstance(item, (int, float, bool)):
                    result[f"{full_key}_{index}"] = _safe_float(item)

            continue

        if isinstance(raw_value, (int, float, bool)):
            result[full_key] = _safe_float(raw_value)

    return result


def extract_features(
    analysis: Any,
    *,
    max_features: int = DEFAULT_MAX_FEATURES,
    max_depth: int = 12,
    exclude_metadata: bool = True,
) -> Dict[str, float]:
    """
    Extract numeric ML features from an analysis result.

    Preferred input shape:

        {
            "feature_vector": {
                "feature_a": 1,
                "feature_b": 0
            }
        }

    If no explicit feature container exists, the function looks for common
    scalar fields while avoiding obvious identity/metadata fields.
    """

    analysis = _dataclass_to_dict(analysis)

    if not isinstance(analysis, Mapping):
        return {}

    explicit = _find_feature_container(analysis)

    if explicit is not None:
        features = _flatten_feature_mapping(
            explicit,
            max_features=max_features,
            max_depth=max_depth,
        )
    else:
        source: Dict[str, Any] = {}

        for key, value in analysis.items():
            normalized = _normalize_feature_name(key)

            if not normalized:
                continue

            if exclude_metadata and normalized in {
                _normalize_feature_name(item) for item in RESERVED_FIELDS
            }:
                continue

            if isinstance(value, Mapping):
                nested = _flatten_feature_mapping(
                    value,
                    prefix=normalized,
                    max_features=max_features - len(source),
                    max_depth=max_depth,
                )
                source.update(nested)

            elif isinstance(value, (int, float, bool)):
                source[normalized] = _safe_float(value)

        features = source

    if exclude_metadata:
        reserved = {_normalize_feature_name(item) for item in RESERVED_FIELDS}

        features = {
            key: value
            for key, value in features.items()
            if key not in reserved
            and not any(
                key == hint or key.startswith(hint + "_")
                for hint in IDENTITY_FEATURE_HINTS
            )
        }

    return dict(sorted(features.items()))


def extract_identity(
    analysis: Any,
    *,
    fallback_id: Optional[str] = None,
) -> Dict[str, str]:
    """Extract sample identity metadata from an analysis result."""

    analysis = _dataclass_to_dict(analysis)

    if not isinstance(analysis, Mapping):
        return {
            "sample_id": fallback_id or "",
            "sha256": "",
            "filename": "",
            "source": "",
        }

    values: Dict[str, str] = {}

    def first_value(keys: Sequence[str]) -> str:
        for key in keys:
            value = analysis.get(key)

            if value not in (None, ""):
                return _safe_text(value, DEFAULT_MAX_FIELD_LENGTH)

        return ""

    values["sample_id"] = first_value(("sample_id", "id"))
    values["sha256"] = first_value(("sha256",))
    values["filename"] = first_value(("filename", "name"))
    values["source"] = first_value(
        ("source", "source_path", "path", "filepath", "file_path")
    )

    if not values["sample_id"]:
        values["sample_id"] = (
            values["sha256"] or values["filename"] or fallback_id or ""
        )

    return values


def extract_label(
    analysis: Any,
    *,
    default: Optional[int] = None,
) -> Optional[int]:
    """Extract and normalize an explicit label from an analysis result."""

    analysis = _dataclass_to_dict(analysis)

    if isinstance(analysis, Mapping):
        for key in LABEL_KEYS:
            if key in analysis:
                normalized = normalize_label(analysis[key])

                if normalized is not None:
                    return normalized

    return infer_label(
        analysis,
        default=default,
    )


# ============================================================================
# Record construction
# ============================================================================


def make_sample_id(
    *,
    sha256: str = "",
    filename: str = "",
    source: str = "",
    fallback_index: Optional[int] = None,
) -> str:
    """
    Generate a deterministic sample identifier.

    SHA-256 is preferred. If unavailable, a normalized filename/source token
    is hashed rather than using a mutable filesystem path directly.
    """

    if sha256:
        return _safe_text(sha256, 128).lower()

    basis = "|".join(
        [
            _safe_text(filename, 4096),
            _safe_text(source, 4096),
        ]
    )

    if not basis and fallback_index is not None:
        basis = f"sample:{fallback_index}"

    if not basis:
        basis = "unknown"

    return hashlib.sha256(basis.encode("utf-8", errors="replace")).hexdigest()


def record_from_analysis(
    analysis: Any,
    *,
    label: Optional[Any] = None,
    sample_id: Optional[str] = None,
    source: Optional[str] = None,
    max_features: int = DEFAULT_MAX_FEATURES,
    exclude_metadata: bool = True,
) -> DatasetRecord:
    """
    Convert an analysis object into one ``DatasetRecord``.

    The function accepts dataclasses, dictionaries, and ordinary objects
    exposing compatible attributes.
    """

    analysis = _dataclass_to_dict(analysis)

    if not isinstance(analysis, Mapping):
        try:
            analysis = vars(analysis)
        except Exception:
            analysis = {}

    identity = extract_identity(analysis)

    explicit_source = (
        _safe_text(source, DEFAULT_MAX_FIELD_LENGTH)
        if source is not None
        else identity["source"]
    )

    normalized_label = (
        normalize_label(label) if label is not None else extract_label(analysis)
    )

    normalized_id = _safe_text(sample_id, 512) if sample_id else identity["sample_id"]

    if not normalized_id:
        normalized_id = make_sample_id(
            sha256=identity["sha256"],
            filename=identity["filename"],
            source=explicit_source,
        )

    features = extract_features(
        analysis,
        max_features=max_features,
        exclude_metadata=exclude_metadata,
    )

    metadata: Dict[str, Any] = {}

    for key in (
        "metadata",
        "analysis_metadata",
        "file_metadata",
    ):
        value = analysis.get(key)

        if isinstance(value, Mapping):
            metadata.update({_safe_text(k, 512): v for k, v in value.items()})

    return DatasetRecord(
        sample_id=normalized_id,
        features=features,
        label=normalized_label,
        sha256=identity["sha256"],
        filename=identity["filename"],
        source=explicit_source,
        metadata=metadata,
    )


def records_from_analyses(
    analyses: Iterable[Any],
    *,
    labels: Optional[Sequence[Any]] = None,
    max_records: int = DEFAULT_MAX_RECORDS,
    max_features: int = DEFAULT_MAX_FEATURES,
    exclude_metadata: bool = True,
) -> List[DatasetRecord]:
    """Convert an iterable of analysis results into dataset records."""

    records: List[DatasetRecord] = []

    label_values = list(labels) if labels is not None else []

    for index, analysis in enumerate(analyses):
        if index >= max_records:
            raise DatasetLimitError(f"Maximum record count exceeded: {max_records}")

        explicit_label = label_values[index] if index < len(label_values) else None

        record = record_from_analysis(
            analysis,
            label=explicit_label,
            max_features=max_features,
            exclude_metadata=exclude_metadata,
        )

        if not record.sample_id:
            record.sample_id = make_sample_id(
                filename=record.filename,
                source=record.source,
                fallback_index=index,
            )

        records.append(record)

    return records


# ============================================================================
# Schema construction
# ============================================================================


def _deduplicate_feature_definitions(
    features: Sequence[FeatureDefinition],
) -> List[FeatureDefinition]:
    seen = set()
    result: List[FeatureDefinition] = []

    for feature in sorted(
        features,
        key=lambda item: item.name,
    ):
        normalized = _normalize_feature_name(feature.name)

        if not normalized or normalized in seen:
            continue

        seen.add(normalized)

        result.append(
            FeatureDefinition(
                name=normalized,
                dtype=feature.dtype or "float64",
                default=_safe_float(feature.default),
                description=feature.description,
                source=feature.source,
            )
        )

    return result


def build_schema(
    records: Sequence[DatasetRecord],
    *,
    metadata: Optional[Mapping[str, Any]] = None,
) -> FeatureSchema:
    """
    Build a deterministic schema from the union of record feature names.
    """

    names = set()

    for record in records:
        names.update(_normalize_feature_name(name) for name in record.features)

        if len(names) > DEFAULT_MAX_FEATURES:
            raise DatasetLimitError(f"Feature count exceeds {DEFAULT_MAX_FEATURES}")

    definitions = [
        FeatureDefinition(
            name=name,
            dtype="float64",
            default=0.0,
        )
        for name in sorted(name for name in names if name)
    ]

    return FeatureSchema(
        version=SCHEMA_VERSION,
        features=definitions,
        metadata=dict(metadata or {}),
    )


def merge_schemas(
    schemas: Sequence[FeatureSchema],
) -> FeatureSchema:
    """Create the deterministic union of multiple feature schemas."""

    definitions: Dict[str, FeatureDefinition] = {}

    for schema in schemas:
        for feature in schema.features:
            name = _normalize_feature_name(feature.name)

            if not name:
                continue

            if name not in definitions:
                definitions[name] = FeatureDefinition(
                    name=name,
                    dtype=feature.dtype,
                    default=feature.default,
                    description=feature.description,
                    source=feature.source,
                )

    return FeatureSchema(
        version=SCHEMA_VERSION,
        features=[definitions[name] for name in sorted(definitions)],
    )


def align_record(
    record: DatasetRecord,
    schema: FeatureSchema,
) -> DatasetRecord:
    """Align a record to a schema, filling absent features with defaults."""

    aligned: Dict[str, float] = {}

    for definition in schema.features:
        value = record.features.get(
            definition.name,
            definition.default,
        )

        aligned[definition.name] = _safe_float(value)

    return DatasetRecord(
        sample_id=record.sample_id,
        features=aligned,
        label=record.label,
        sha256=record.sha256,
        filename=record.filename,
        source=record.source,
        split=record.split,
        metadata=dict(record.metadata),
    )


def align_dataset(
    dataset: Dataset,
    schema: FeatureSchema,
) -> Dataset:
    """Return a dataset whose records conform exactly to ``schema``."""

    return Dataset(
        records=[align_record(record, schema) for record in dataset.records],
        schema=schema,
        name=dataset.name,
        version=dataset.version,
        metadata=dict(dataset.metadata),
    )


# ============================================================================
# Dataset creation
# ============================================================================


def create_dataset(
    analyses: Optional[Iterable[Any]] = None,
    *,
    records: Optional[Sequence[DatasetRecord]] = None,
    labels: Optional[Sequence[Any]] = None,
    name: str = "pharos_cdr_dataset",
    metadata: Optional[Mapping[str, Any]] = None,
    max_records: int = DEFAULT_MAX_RECORDS,
    max_features: int = DEFAULT_MAX_FEATURES,
    exclude_metadata: bool = True,
) -> Dataset:
    """
    Create a dataset from analysis objects or pre-built records.

    Exactly one of ``analyses`` and ``records`` may be supplied.
    """

    if analyses is not None and records is not None:
        raise DatasetError("Provide either analyses or records, not both.")

    if records is not None:
        dataset_records = list(records)

        if len(dataset_records) > max_records:
            raise DatasetLimitError(f"Maximum record count exceeded: {max_records}")

    elif analyses is not None:
        dataset_records = records_from_analyses(
            analyses,
            labels=labels,
            max_records=max_records,
            max_features=max_features,
            exclude_metadata=exclude_metadata,
        )
    else:
        dataset_records = []

    schema = build_schema(
        dataset_records,
        metadata=metadata,
    )

    dataset = Dataset(
        records=dataset_records,
        schema=schema,
        name=_safe_text(name, 512) or "pharos_cdr_dataset",
        version=DATASET_VERSION,
        metadata=dict(metadata or {}),
    )

    return align_dataset(
        dataset,
        schema,
    )


# ============================================================================
# Matrix / vector conversion
# ============================================================================


def feature_matrix(
    dataset: Dataset,
    *,
    schema: Optional[FeatureSchema] = None,
) -> List[List[float]]:
    """
    Convert a dataset into a row-major numeric matrix.

    No external numerical dependency is required.
    """

    active_schema = schema or dataset.schema

    return [
        [
            _safe_float(
                record.features.get(
                    feature.name,
                    feature.default,
                )
            )
            for feature in active_schema.features
        ]
        for record in dataset.records
    ]


def target_vector(
    dataset: Dataset,
    *,
    require_labels: bool = True,
) -> List[int]:
    """
    Return labels in dataset order.
    """

    result: List[int] = []

    for record in dataset.records:
        if record.label is None:
            if require_labels:
                raise DatasetError(f"Record '{record.sample_id}' has no label.")
            continue

        result.append(int(record.label))

    return result


def sample_ids(
    dataset: Dataset,
) -> List[str]:
    """Return sample IDs in dataset order."""

    return [record.sample_id for record in dataset.records]


def feature_dicts(
    dataset: Dataset,
) -> List[Dict[str, float]]:
    """Return aligned feature dictionaries."""

    return [dict(record.features) for record in dataset.records]


# ============================================================================
# Deduplication / integrity
# ============================================================================


def duplicate_sample_ids(
    records: Sequence[DatasetRecord],
) -> Dict[str, int]:
    """Return sample IDs occurring more than once."""

    counts: Dict[str, int] = {}

    for record in records:
        counts[record.sample_id] = counts.get(record.sample_id, 0) + 1

    return {key: count for key, count in counts.items() if count > 1}


def duplicate_hashes(
    records: Sequence[DatasetRecord],
) -> Dict[str, int]:
    """Return SHA-256 values occurring more than once."""

    counts: Dict[str, int] = {}

    for record in records:
        if not record.sha256:
            continue

        normalized = record.sha256.lower()

        counts[normalized] = counts.get(normalized, 0) + 1

    return {key: count for key, count in counts.items() if count > 1}


def deduplicate_records(
    records: Sequence[DatasetRecord],
    *,
    key: str = "sample_id",
    keep: str = "first",
) -> List[DatasetRecord]:
    """
    Remove duplicate records.

    ``key`` may be ``sample_id`` or ``sha256``.
    """

    if key not in {"sample_id", "sha256"}:
        raise DatasetError("Deduplication key must be 'sample_id' or 'sha256'.")

    if keep not in {"first", "last"}:
        raise DatasetError("keep must be 'first' or 'last'.")

    selected: Dict[str, DatasetRecord] = {}

    sequence = records if keep == "first" else list(reversed(records))

    for record in sequence:
        value = getattr(record, key, "")

        if not value:
            # Records without the selected identity are retained.
            selected[f"__missing__:{id(record)}"] = record
            continue

        normalized = _safe_text(value, 512).lower()

        if normalized not in selected:
            selected[normalized] = record

    result = list(selected.values())

    if keep == "last":
        result.reverse()

    return result


# ============================================================================
# Dataset statistics
# ============================================================================


def dataset_statistics(
    dataset: Dataset,
    *,
    include_feature_statistics: bool = True,
    max_feature_statistics: int = DEFAULT_MAX_FEATURES,
) -> DatasetStatistics:
    """Calculate dataset-level and optional per-feature statistics."""

    records = dataset.records

    labels = [record.label for record in records if record.label is not None]

    benign = sum(1 for label in labels if label == LABEL_BENIGN)

    malicious = sum(1 for label in labels if label == LABEL_MALICIOUS)

    total_values = len(records) * dataset.n_features

    missing_values = 0
    nonzero_values = 0

    for record in records:
        for feature in dataset.schema.features:
            value = record.features.get(feature.name)

            if value is None:
                missing_values += 1
            elif _safe_float(value) != 0.0:
                nonzero_values += 1

    duplicate_ids = duplicate_sample_ids(records)
    duplicate_sha = duplicate_hashes(records)

    statistics_result = DatasetStatistics(
        record_count=len(records),
        feature_count=dataset.n_features,
        labeled_count=len(labels),
        unlabeled_count=len(records) - len(labels),
        benign_count=benign,
        malicious_count=malicious,
        positive_rate=(malicious / len(labels) if labels else 0.0),
        missing_feature_values=missing_values,
        nonzero_feature_values=nonzero_values,
        duplicate_sample_ids=sum(count - 1 for count in duplicate_ids.values()),
        duplicate_sha256=sum(count - 1 for count in duplicate_sha.values()),
    )

    if include_feature_statistics:
        if dataset.n_features > max_feature_statistics:
            raise DatasetLimitError(
                "Feature statistics requested for more features than allowed."
            )

        for feature in dataset.schema.features:
            values = [
                _safe_float(
                    record.features.get(
                        feature.name,
                        feature.default,
                    )
                )
                for record in records
            ]

            if not values:
                continue

            mean = statistics.fmean(values)

            try:
                stdev = statistics.pstdev(values)
            except statistics.StatisticsError:
                stdev = 0.0

            statistics_result.feature_statistics[feature.name] = {
                "min": float(min(values)),
                "max": float(max(values)),
                "mean": float(mean),
                "std": float(stdev),
                "nonzero": float(sum(value != 0.0 for value in values)),
                "missing": float(
                    sum(feature.name not in record.features for record in records)
                ),
            }

    return statistics_result


def class_distribution(
    dataset: Dataset,
) -> Dict[int, int]:
    """Return counts for each known numeric class."""

    result = {
        LABEL_BENIGN: 0,
        LABEL_MALICIOUS: 0,
    }

    for record in dataset.records:
        if record.label in result:
            result[record.label] += 1

    return result


# ============================================================================
# Deterministic train/test splitting
# ============================================================================


def _stratified_indices(
    records: Sequence[DatasetRecord],
    *,
    test_ratio: float,
    seed: int,
) -> Tuple[List[int], List[int]]:
    """
    Generate a deterministic stratified split where possible.

    Unlabeled records are assigned to the training set.
    """

    groups: Dict[int, List[int]] = {}

    unlabeled: List[int] = []

    for index, record in enumerate(records):
        if record.label is None:
            unlabeled.append(index)
        else:
            groups.setdefault(
                int(record.label),
                [],
            ).append(index)

    rng = random.Random(seed)

    train_indices: List[int] = []
    test_indices: List[int] = []

    for label in sorted(groups):
        indices = list(groups[label])
        rng.shuffle(indices)

        if len(indices) <= 1:
            test_count = 0
        else:
            test_count = int(round(len(indices) * test_ratio))

            test_count = max(
                1,
                min(
                    len(indices) - 1,
                    test_count,
                ),
            )

        test_indices.extend(indices[:test_count])

        train_indices.extend(indices[test_count:])

    # Unlabeled records remain in train because they cannot participate in
    # supervised evaluation.
    train_indices.extend(unlabeled)

    rng.shuffle(train_indices)
    rng.shuffle(test_indices)

    return train_indices, test_indices


def split_dataset(
    dataset: Dataset,
    *,
    test_ratio: float = DEFAULT_TEST_RATIO,
    seed: int = DEFAULT_RANDOM_SEED,
    stratify: bool = True,
) -> DatasetSplit:
    """
    Deterministically split a dataset into train and test sets.

    When stratification is enabled, each known class is split independently.
    """

    if not 0.0 < test_ratio < 1.0:
        raise DatasetError("test_ratio must be between 0 and 1.")

    records = list(dataset.records)

    if stratify:
        train_indices, test_indices = _stratified_indices(
            records,
            test_ratio=test_ratio,
            seed=seed,
        )
    else:
        indices = list(range(len(records)))
        rng = random.Random(seed)
        rng.shuffle(indices)

        test_count = int(round(len(indices) * test_ratio))

        test_indices = indices[:test_count]
        train_indices = indices[test_count:]

    train_records: List[DatasetRecord] = []
    test_records: List[DatasetRecord] = []

    for index in train_indices:
        record = records[index]

        train_records.append(
            DatasetRecord(
                sample_id=record.sample_id,
                features=dict(record.features),
                label=record.label,
                sha256=record.sha256,
                filename=record.filename,
                source=record.source,
                split="train",
                metadata=dict(record.metadata),
            )
        )

    for index in test_indices:
        record = records[index]

        test_records.append(
            DatasetRecord(
                sample_id=record.sample_id,
                features=dict(record.features),
                label=record.label,
                sha256=record.sha256,
                filename=record.filename,
                source=record.source,
                split="test",
                metadata=dict(record.metadata),
            )
        )

    train = Dataset(
        records=train_records,
        schema=dataset.schema,
        name=dataset.name,
        version=dataset.version,
        metadata={
            **dataset.metadata,
            "split": "train",
            "seed": seed,
            "test_ratio": test_ratio,
        },
    )

    test = Dataset(
        records=test_records,
        schema=dataset.schema,
        name=dataset.name,
        version=dataset.version,
        metadata={
            **dataset.metadata,
            "split": "test",
            "seed": seed,
            "test_ratio": test_ratio,
        },
    )

    return DatasetSplit(
        train=train,
        test=test,
        seed=seed,
        test_ratio=test_ratio,
    )


# ============================================================================
# CSV serialization
# ============================================================================


def _csv_header(
    dataset: Dataset,
    *,
    include_metadata: bool,
) -> List[str]:
    header = [
        "sample_id",
        "label",
        "sha256",
        "filename",
        "source",
        "split",
    ]

    header.extend(dataset.schema.feature_names)

    if include_metadata:
        header.append("metadata_json")

    return header


def _record_to_csv_row(
    record: DatasetRecord,
    schema: FeatureSchema,
    *,
    include_metadata: bool,
) -> Dict[str, Any]:
    row: Dict[str, Any] = {
        "sample_id": record.sample_id,
        "label": ("" if record.label is None else int(record.label)),
        "sha256": record.sha256,
        "filename": record.filename,
        "source": record.source,
        "split": record.split,
    }

    for feature in schema.features:
        row[feature.name] = _safe_float(
            record.features.get(
                feature.name,
                feature.default,
            )
        )

    if include_metadata:
        row["metadata_json"] = json.dumps(
            record.metadata,
            sort_keys=True,
            ensure_ascii=False,
            separators=(",", ":"),
            default=str,
        )

    return row


def save_csv(
    dataset: Dataset,
    path: os.PathLike[str] | str,
    *,
    include_metadata: bool = True,
    newline: str = "",
) -> str:
    """
    Save a dataset as a deterministic CSV file.

    Feature columns follow the dataset schema order.
    """

    output_path = Path(path)

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    header = _csv_header(
        dataset,
        include_metadata=include_metadata,
    )

    with output_path.open(
        "w",
        encoding="utf-8",
        newline=newline,
    ) as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=header,
            extrasaction="ignore",
        )

        writer.writeheader()

        for record in dataset.records:
            writer.writerow(
                _record_to_csv_row(
                    record,
                    dataset.schema,
                    include_metadata=include_metadata,
                )
            )

    return str(output_path)


def _parse_csv_value(
    value: str,
) -> Any:
    text = value.strip()

    if text == "":
        return None

    try:
        numeric = float(text)

        if math.isfinite(numeric):
            return numeric

    except (TypeError, ValueError):
        pass

    return value


def load_csv(
    path: os.PathLike[str] | str,
    *,
    name: Optional[str] = None,
    schema: Optional[FeatureSchema] = None,
    max_records: int = DEFAULT_MAX_RECORDS,
    max_features: int = DEFAULT_MAX_FEATURES,
) -> Dataset:
    """Load a dataset from a CSV file."""

    input_path = Path(path)

    if not input_path.exists():
        raise DatasetFormatError(f"Dataset file does not exist: {input_path}")

    records: List[DatasetRecord] = []

    with input_path.open(
        "r",
        encoding="utf-8",
        newline="",
    ) as handle:
        reader = csv.DictReader(handle)

        if not reader.fieldnames:
            raise DatasetFormatError("CSV dataset has no header.")

        fieldnames = [
            _normalize_feature_name(field) for field in reader.fieldnames if field
        ]

        if len(fieldnames) > max_features + len(RESERVED_FIELDS) + 10:
            raise DatasetLimitError("CSV contains too many columns.")

        for index, raw_row in enumerate(reader):
            if index >= max_records:
                raise DatasetLimitError(f"Maximum record count exceeded: {max_records}")

            row = {
                _normalize_feature_name(key): value
                for key, value in raw_row.items()
                if key
            }

            features: Dict[str, float] = {}

            for key, value in row.items():
                if key in {
                    "sample_id",
                    "label",
                    "sha256",
                    "filename",
                    "source",
                    "split",
                    "metadata_json",
                }:
                    continue

                parsed = _parse_csv_value(_safe_text(value, DEFAULT_MAX_FIELD_LENGTH))

                if isinstance(
                    parsed,
                    (int, float),
                ):
                    features[key] = _safe_float(parsed)

            metadata: Dict[str, Any] = {}

            metadata_text = row.get(
                "metadata_json",
                "",
            )

            if metadata_text:
                try:
                    parsed_metadata = json.loads(metadata_text)

                    if isinstance(
                        parsed_metadata,
                        Mapping,
                    ):
                        metadata = dict(parsed_metadata)

                except json.JSONDecodeError:
                    metadata = {"metadata_parse_error": True}

            label = normalize_label(row.get("label"))

            record = DatasetRecord(
                sample_id=_safe_text(
                    row.get("sample_id", ""),
                    512,
                ),
                features=features,
                label=label,
                sha256=_safe_text(
                    row.get("sha256", ""),
                    128,
                ),
                filename=_safe_text(
                    row.get("filename", ""),
                    DEFAULT_MAX_FIELD_LENGTH,
                ),
                source=_safe_text(
                    row.get("source", ""),
                    DEFAULT_MAX_FIELD_LENGTH,
                ),
                split=_safe_text(
                    row.get("split", ""),
                    64,
                ),
                metadata=metadata,
            )

            records.append(record)

    inferred_schema = schema or build_schema(records)

    dataset = Dataset(
        records=records,
        schema=inferred_schema,
        name=(_safe_text(name, 512) if name else input_path.stem),
        metadata={
            "format": "csv",
            "source_path": str(input_path),
        },
    )

    return align_dataset(
        dataset,
        inferred_schema,
    )


# ============================================================================
# JSONL serialization
# ============================================================================


def save_jsonl(
    dataset: Dataset,
    path: os.PathLike[str] | str,
    *,
    include_metadata: bool = True,
) -> str:
    """
    Save a dataset as JSON Lines.

    The first line contains the dataset/schema metadata. Each following line
    contains one record.
    """

    output_path = Path(path)

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with output_path.open(
        "w",
        encoding="utf-8",
        newline="\n",
    ) as handle:
        header = {
            "_type": "dataset_header",
            "dataset_version": dataset.version,
            "name": dataset.name,
            "schema": dataset.schema.to_dict(),
            "metadata": dataset.metadata,
        }

        handle.write(
            json.dumps(
                header,
                sort_keys=True,
                ensure_ascii=False,
                separators=(",", ":"),
                default=str,
            )
            + "\n"
        )

        for record in dataset.records:
            payload = {
                "_type": "record",
                **record.to_dict(include_metadata=include_metadata),
            }

            handle.write(
                json.dumps(
                    payload,
                    sort_keys=True,
                    ensure_ascii=False,
                    separators=(",", ":"),
                    default=str,
                )
                + "\n"
            )

    return str(output_path)


def load_jsonl(
    path: os.PathLike[str] | str,
    *,
    max_records: int = DEFAULT_MAX_RECORDS,
    max_features: int = DEFAULT_MAX_FEATURES,
) -> Dataset:
    """Load a dataset saved by ``save_jsonl``."""

    input_path = Path(path)

    if not input_path.exists():
        raise DatasetFormatError(f"Dataset file does not exist: {input_path}")

    schema: Optional[FeatureSchema] = None
    records: List[DatasetRecord] = []
    dataset_name = input_path.stem
    dataset_version = DATASET_VERSION
    dataset_metadata: Dict[str, Any] = {}

    with input_path.open(
        "r",
        encoding="utf-8",
    ) as handle:
        for line_number, line in enumerate(handle, start=1):
            if len(line) > DEFAULT_MAX_JSON_SIZE:
                raise DatasetLimitError(f"JSONL line {line_number} is too large.")

            line = line.strip()

            if not line:
                continue

            try:
                payload = json.loads(line)
            except json.JSONDecodeError as exc:
                raise DatasetFormatError(
                    f"Invalid JSON on line {line_number}."
                ) from exc

            if not isinstance(payload, Mapping):
                raise DatasetFormatError(f"JSONL line {line_number} is not an object.")

            record_type = payload.get("_type")

            if record_type == "dataset_header":
                raw_schema = payload.get("schema")

                if not isinstance(
                    raw_schema,
                    Mapping,
                ):
                    raise DatasetFormatError(
                        "Dataset header does not contain a valid schema."
                    )

                schema = FeatureSchema.from_dict(raw_schema)

                if schema.n_features > max_features:
                    raise DatasetLimitError(
                        "Dataset schema contains too many features."
                    )

                dataset_name = _safe_text(
                    payload.get(
                        "name",
                        dataset_name,
                    ),
                    512,
                )

                dataset_version = _safe_text(
                    payload.get(
                        "dataset_version",
                        DATASET_VERSION,
                    ),
                    64,
                )

                raw_metadata = payload.get(
                    "metadata",
                    {},
                )

                if isinstance(
                    raw_metadata,
                    Mapping,
                ):
                    dataset_metadata = dict(raw_metadata)

                continue

            if record_type not in {None, "record"}:
                continue

            if len(records) >= max_records:
                raise DatasetLimitError(f"Maximum record count exceeded: {max_records}")

            raw_features = payload.get(
                "features",
                {},
            )

            if not isinstance(
                raw_features,
                Mapping,
            ):
                raise DatasetFormatError(
                    f"Invalid feature mapping on line {line_number}."
                )

            features = {
                _normalize_feature_name(key): _safe_float(value)
                for key, value in raw_features.items()
                if _normalize_feature_name(key)
            }

            if len(features) > max_features:
                raise DatasetLimitError("Record contains too many features.")

            label = normalize_label(payload.get("label"))

            raw_metadata = payload.get(
                "metadata",
                {},
            )

            metadata = (
                dict(raw_metadata)
                if isinstance(
                    raw_metadata,
                    Mapping,
                )
                else {}
            )

            records.append(
                DatasetRecord(
                    sample_id=_safe_text(
                        payload.get(
                            "sample_id",
                            "",
                        ),
                        512,
                    ),
                    features=features,
                    label=label,
                    sha256=_safe_text(
                        payload.get(
                            "sha256",
                            "",
                        ),
                        128,
                    ),
                    filename=_safe_text(
                        payload.get(
                            "filename",
                            "",
                        ),
                        DEFAULT_MAX_FIELD_LENGTH,
                    ),
                    source=_safe_text(
                        payload.get(
                            "source",
                            "",
                        ),
                        DEFAULT_MAX_FIELD_LENGTH,
                    ),
                    split=_safe_text(
                        payload.get(
                            "split",
                            "",
                        ),
                        64,
                    ),
                    metadata=metadata,
                )
            )

    if schema is None:
        schema = build_schema(records)

    if schema.n_features > max_features:
        raise DatasetLimitError("Dataset schema contains too many features.")

    dataset = Dataset(
        records=records,
        schema=schema,
        name=dataset_name,
        version=dataset_version,
        metadata=dataset_metadata,
    )

    return align_dataset(
        dataset,
        schema,
    )


# ============================================================================
# Generic persistence
# ============================================================================


def save_dataset(
    dataset: Dataset,
    path: os.PathLike[str] | str,
    *,
    format: Optional[str] = None,
    include_metadata: bool = True,
) -> str:
    """
    Save a dataset based on the requested or inferred format.

    Supported formats:
        csv
        jsonl
    """

    output_path = Path(path)

    selected = (
        _safe_text(format, 32).lower()
        if format
        else output_path.suffix.lower().lstrip(".")
    )

    if selected == "csv":
        return save_csv(
            dataset,
            output_path,
            include_metadata=include_metadata,
        )

    if selected in {"jsonl", "ndjson"}:
        return save_jsonl(
            dataset,
            output_path,
            include_metadata=include_metadata,
        )

    raise DatasetFormatError("Unsupported dataset format. Use csv or jsonl.")


def load_dataset(
    path: os.PathLike[str] | str,
    *,
    format: Optional[str] = None,
    schema: Optional[FeatureSchema] = None,
    max_records: int = DEFAULT_MAX_RECORDS,
    max_features: int = DEFAULT_MAX_FEATURES,
) -> Dataset:
    """Load a dataset based on the requested or inferred format."""

    input_path = Path(path)

    selected = (
        _safe_text(format, 32).lower()
        if format
        else input_path.suffix.lower().lstrip(".")
    )

    if selected == "csv":
        return load_csv(
            input_path,
            schema=schema,
            max_records=max_records,
            max_features=max_features,
        )

    if selected in {"jsonl", "ndjson"}:
        return load_jsonl(
            input_path,
            max_records=max_records,
            max_features=max_features,
        )

    raise DatasetFormatError("Unsupported dataset format. Use csv or jsonl.")


# ============================================================================
# Schema persistence
# ============================================================================


def save_schema(
    schema: FeatureSchema,
    path: os.PathLike[str] | str,
) -> str:
    """Persist a feature schema as JSON."""

    output_path = Path(path)

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with output_path.open(
        "w",
        encoding="utf-8",
    ) as handle:
        json.dump(
            schema.to_dict(),
            handle,
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
        )

        handle.write("\n")

    return str(output_path)


def load_schema(
    path: os.PathLike[str] | str,
) -> FeatureSchema:
    """Load a feature schema from JSON."""

    input_path = Path(path)

    if not input_path.exists():
        raise DatasetSchemaError(f"Schema file does not exist: {input_path}")

    try:
        with input_path.open(
            "r",
            encoding="utf-8",
        ) as handle:
            payload = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        raise DatasetSchemaError(
            f"Could not load feature schema: {input_path}"
        ) from exc

    if not isinstance(payload, Mapping):
        raise DatasetSchemaError("Feature schema JSON must contain an object.")

    return FeatureSchema.from_dict(payload)


# ============================================================================
# Dataset fingerprints / reproducibility
# ============================================================================


def dataset_fingerprint(
    dataset: Dataset,
) -> str:
    """
    Calculate a deterministic SHA-256 fingerprint of dataset content.

    The fingerprint includes:
    - schema;
    - sample IDs;
    - labels;
    - hashes;
    - ordered feature values.

    File paths and arbitrary metadata are excluded so that moving a dataset
    between machines does not change its identity.
    """

    digest = hashlib.sha256()

    schema_payload = json.dumps(
        dataset.schema.to_dict(),
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
    )

    digest.update(
        schema_payload.encode(
            "utf-8",
            errors="replace",
        )
    )

    for record in dataset.records:
        payload = {
            "sample_id": record.sample_id,
            "label": record.label,
            "sha256": record.sha256,
            "features": [
                [
                    feature.name,
                    _safe_float(
                        record.features.get(
                            feature.name,
                            feature.default,
                        )
                    ),
                ]
                for feature in dataset.schema.features
            ],
        }

        digest.update(
            json.dumps(
                payload,
                sort_keys=True,
                ensure_ascii=False,
                separators=(",", ":"),
            ).encode(
                "utf-8",
                errors="replace",
            )
        )

    return digest.hexdigest()


def schema_fingerprint(
    schema: FeatureSchema,
) -> str:
    """Calculate a deterministic fingerprint for a feature schema."""

    payload = json.dumps(
        schema.to_dict(),
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
    )

    return hashlib.sha256(
        payload.encode(
            "utf-8",
            errors="replace",
        )
    ).hexdigest()


# ============================================================================
# Validation
# ============================================================================


def validate_schema(
    schema: FeatureSchema,
) -> List[str]:
    """Return schema validation errors."""

    errors: List[str] = []

    names = [feature.name for feature in schema.features]

    if len(names) != len(set(names)):
        errors.append("Schema contains duplicate feature names.")

    for feature in schema.features:
        if not feature.name:
            errors.append("Schema contains an empty feature name.")

        if feature.dtype not in {
            "float64",
            "float32",
            "int64",
            "int32",
            "bool",
        }:
            errors.append(
                f"Unsupported dtype for feature '{feature.name}': " f"{feature.dtype}"
            )

    return errors


def validate_record(
    record: DatasetRecord,
    schema: Optional[FeatureSchema] = None,
) -> List[str]:
    """Return validation errors for one dataset record."""

    errors: List[str] = []

    if not record.sample_id:
        errors.append("Record has no sample_id.")

    for name, value in record.features.items():
        if not _normalize_feature_name(name):
            errors.append("Record contains an empty feature name.")

        try:
            numeric = float(value)

            if not math.isfinite(numeric):
                errors.append(f"Feature '{name}' is not finite.")

        except (TypeError, ValueError):
            errors.append(f"Feature '{name}' is not numeric.")

    if record.label not in {
        None,
        LABEL_BENIGN,
        LABEL_MALICIOUS,
    }:
        errors.append(f"Unsupported label: {record.label}")

    if schema is not None:
        unknown = set(record.features) - set(schema.feature_names)

        if unknown:
            errors.append(
                "Record contains features outside the supplied schema: "
                + ", ".join(sorted(unknown)[:20])
            )

    return errors


def validate_dataset(
    dataset: Dataset,
    *,
    require_labels: bool = False,
) -> List[str]:
    """Validate the complete dataset and return all detected errors."""

    errors = validate_schema(dataset.schema)

    duplicate_ids = duplicate_sample_ids(dataset.records)

    if duplicate_ids:
        errors.append("Dataset contains duplicate sample IDs.")

    for index, record in enumerate(dataset.records):
        record_errors = validate_record(
            record,
            dataset.schema,
        )

        if require_labels and record.label is None:
            record_errors.append("Record is unlabeled.")

        for error in record_errors:
            errors.append(f"record[{index}]: {error}")

    return errors


# ============================================================================
# Dataset summaries
# ============================================================================


def summarize_dataset(
    dataset: Dataset,
) -> Dict[str, Any]:
    """Return a compact, report-friendly dataset summary."""

    statistics_result = dataset_statistics(
        dataset,
        include_feature_statistics=False,
    )

    return {
        "name": dataset.name,
        "version": dataset.version,
        "records": dataset.size,
        "features": dataset.n_features,
        "labeled": statistics_result.labeled_count,
        "unlabeled": statistics_result.unlabeled_count,
        "benign": statistics_result.benign_count,
        "malicious": statistics_result.malicious_count,
        "positive_rate": statistics_result.positive_rate,
        "duplicate_sample_ids": statistics_result.duplicate_sample_ids,
        "duplicate_sha256": statistics_result.duplicate_sha256,
        "schema_fingerprint": schema_fingerprint(dataset.schema),
        "dataset_fingerprint": dataset_fingerprint(dataset),
    }


def iter_records(
    dataset: Dataset,
) -> Iterator[DatasetRecord]:
    """Iterate through dataset records."""

    yield from dataset.records


def iter_labeled_records(
    dataset: Dataset,
) -> Iterator[DatasetRecord]:
    """Iterate only through labeled records."""

    for record in dataset.records:
        if record.label is not None:
            yield record


def iter_unlabeled_records(
    dataset: Dataset,
) -> Iterator[DatasetRecord]:
    """Iterate only through unlabeled records."""

    for record in dataset.records:
        if record.label is None:
            yield record


# ============================================================================
# Feature selection
# ============================================================================


def select_features(
    dataset: Dataset,
    feature_names: Sequence[str],
) -> Dataset:
    """
    Produce a dataset containing only the requested features.
    """

    normalized_names = [
        _normalize_feature_name(name)
        for name in feature_names
        if _normalize_feature_name(name)
    ]

    requested = set(normalized_names)

    definitions = [
        feature for feature in dataset.schema.features if feature.name in requested
    ]

    selected_schema = FeatureSchema(
        version=dataset.schema.version,
        features=definitions,
        label_name=dataset.schema.label_name,
        id_fields=list(dataset.schema.id_fields),
        metadata={
            **dataset.schema.metadata,
            "selected_features": True,
        },
    )

    records = []

    for record in dataset.records:
        records.append(
            DatasetRecord(
                sample_id=record.sample_id,
                features={
                    name: record.features.get(
                        name,
                        0.0,
                    )
                    for name in selected_schema.feature_names
                },
                label=record.label,
                sha256=record.sha256,
                filename=record.filename,
                source=record.source,
                split=record.split,
                metadata=dict(record.metadata),
            )
        )

    return Dataset(
        records=records,
        schema=selected_schema,
        name=dataset.name,
        version=dataset.version,
        metadata={
            **dataset.metadata,
            "feature_selection": True,
        },
    )


def remove_features(
    dataset: Dataset,
    feature_names: Sequence[str],
) -> Dataset:
    """Remove the specified features from a dataset."""

    remove = {_normalize_feature_name(name) for name in feature_names}

    keep = [
        feature.name
        for feature in dataset.schema.features
        if feature.name not in remove
    ]

    return select_features(
        dataset,
        keep,
    )


def remove_identity_features(
    dataset: Dataset,
) -> Dataset:
    """
    Remove feature columns that look like direct sample identity fields.
    """

    selected = []

    for feature in dataset.schema.features:
        name = feature.name

        if any(
            name == hint or name.startswith(hint + "_")
            for hint in IDENTITY_FEATURE_HINTS
        ):
            continue

        selected.append(name)

    return select_features(
        dataset,
        selected,
    )


# ============================================================================
# Compatibility helpers for ML modules
# ============================================================================


def build_ml_inputs(
    dataset: Dataset,
    *,
    require_labels: bool = True,
) -> Tuple[List[List[float]], List[int], List[str]]:
    """
    Return ``X``, ``y``, and sample IDs in aligned order.

    This is intentionally dependency-free so ``train.py`` can decide whether
    to use scikit-learn or another estimator implementation.
    """

    records = dataset.records

    if require_labels:
        records = [record for record in records if record.label is not None]

    active_dataset = Dataset(
        records=records,
        schema=dataset.schema,
        name=dataset.name,
        version=dataset.version,
        metadata=dict(dataset.metadata),
    )

    x = feature_matrix(active_dataset)

    y = target_vector(
        active_dataset,
        require_labels=require_labels,
    )

    ids = sample_ids(active_dataset)

    return x, y, ids


def save_ml_dataset(
    dataset: Dataset,
    csv_path: os.PathLike[str] | str,
    *,
    schema_path: Optional[os.PathLike[str] | str] = None,
    jsonl_path: Optional[os.PathLike[str] | str] = None,
) -> Dict[str, str]:
    """
    Convenience persistence function for the training pipeline.

    CSV is the primary tabular artifact. JSONL and schema are optional.
    """

    outputs: Dict[str, str] = {}

    outputs["csv"] = save_csv(
        dataset,
        csv_path,
    )

    if schema_path is not None:
        outputs["schema"] = save_schema(
            dataset.schema,
            schema_path,
        )

    if jsonl_path is not None:
        outputs["jsonl"] = save_jsonl(
            dataset,
            jsonl_path,
        )

    return outputs


# ============================================================================
# Compatibility aliases
# ============================================================================


create = create_dataset
from_analysis = record_from_analysis
from_analyses = records_from_analyses
build_feature_schema = build_schema
save = save_dataset
load = load_dataset
stats = dataset_statistics
split = split_dataset
to_matrix = feature_matrix
to_targets = target_vector
fingerprint = dataset_fingerprint


# ============================================================================
# PUBLIC APIs
# ============================================================================


__all__ = [
    "FeatureDefinition",
    "FeatureSchema",
    "DatasetRecord",
    "Dataset",
    "DatasetSplit",
    "DatasetStatistics",
    "DatasetError",
    "DatasetSchemaError",
    "DatasetFormatError",
    "DatasetLimitError",
    "normalize_label",
    "infer_label",
    "extract_features",
    "extract_identity",
    "extract_label",
    "make_sample_id",
    "record_from_analysis",
    "records_from_analyses",
    "build_schema",
    "build_feature_schema",
    "merge_schemas",
    "align_record",
    "align_dataset",
    "create_dataset",
    "create",
    "feature_matrix",
    "target_vector",
    "sample_ids",
    "feature_dicts",
    "build_ml_inputs",
    "duplicate_sample_ids",
    "duplicate_hashes",
    "deduplicate_records",
    "dataset_fingerprint",
    "schema_fingerprint",
    "dataset_statistics",
    "stats",
    "class_distribution",
    "validate_schema",
    "validate_record",
    "validate_dataset",
    "summarize_dataset",
    "split_dataset",
    "split",
    "save_csv",
    "load_csv",
    "save_jsonl",
    "load_jsonl",
    "save_dataset",
    "load_dataset",
    "save_schema",
    "load_schema",
    "save_ml_dataset",
    "save",
    "load",
    "select_features",
    "remove_features",
    "remove_identity_features",
    "iter_records",
    "iter_labeled_records",
    "iter_unlabeled_records",
    "from_analysis",
    "from_analyses",
    "to_matrix",
    "to_targets",
    "fingerprint",
]
