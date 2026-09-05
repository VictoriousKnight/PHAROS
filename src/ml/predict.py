"""
pharos-cdr.src.ml.predict
=========================

Inference utilities for the Pharos CDR malware/document classifier.

This module loads the trusted Random Forest model produced by
``src.ml.train`` and applies it to already-extracted feature data.

Security model
--------------
* Input documents are NOT executed.
* Macros/scripts are NOT executed.
* URLs are NOT contacted.
* No subprocesses are launched.
* No network access is performed.
* Prediction operates only on numeric feature vectors / previously extracted
  analysis records.
* Model artifacts must be trusted because joblib deserialization can reconstruct
  Python objects.

Supported inputs
----------------
1. A DatasetRecord-like object.
2. A mapping containing ``features`` or ``feature_vector``.
3. A numeric feature mapping.
4. A numeric feature sequence paired with a feature schema.
5. A Dataset for batch prediction.

The persisted artifacts expected by default are:

models/
    trained/
        random_forest.joblib
    metadata/
        feature_schema.json
        model_metadata.json
        thresholds.json
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import os
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

try:
    from .dataset import (
        Dataset,
        DatasetRecord,
        extract_features,
        load_dataset,
        load_schema,
    )
    from .train import (
        DEFAULT_MODEL_PATH,
        DEFAULT_SCHEMA_PATH,
        DEFAULT_METADATA_PATH,
        DEFAULT_THRESHOLDS_PATH,
        load_trained_model,
    )
except ImportError:  # pragma: no cover - direct execution support
    from dataset import (  # type: ignore
        Dataset,
        DatasetRecord,
        extract_features,
        load_dataset,
        load_schema,
    )
    from train import (  # type: ignore
        DEFAULT_MODEL_PATH,
        DEFAULT_SCHEMA_PATH,
        DEFAULT_METADATA_PATH,
        DEFAULT_THRESHOLDS_PATH,
        load_trained_model,
    )


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_THRESHOLD = 0.50
MAX_FEATURES = 100_000
MAX_BATCH_SIZE = 2_000_000
MAX_JSON_SIZE = 100 * 1024 * 1024

POSITIVE_LABEL = 1
NEGATIVE_LABEL = 0

POSITIVE_LABEL_NAME = "malicious"
NEGATIVE_LABEL_NAME = "benign"

DEFAULT_OUTPUT_FORMAT = "jsonl"

IDENTITY_FEATURE_HINTS = (
    "sample_id",
    "sha256",
    "sha1",
    "md5",
    "hash",
    "filename",
    "file_name",
    "path",
    "filepath",
    "file_path",
)

RESERVED_MAPPING_KEYS = {
    "sample_id",
    "id",
    "label",
    "target",
    "y",
    "features",
    "feature_vector",
    "feature_values",
    "metadata",
    "analysis",
    "result",
    "prediction",
    "predictions",
}


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class PredictionError(RuntimeError):
    """Base exception for prediction failures."""


class PredictionDependencyError(PredictionError):
    """Raised when a required prediction dependency is unavailable."""


class FeatureSchemaError(PredictionError):
    """Raised when prediction features do not match the trained schema."""


class ArtifactError(PredictionError):
    """Raised when model or metadata artifacts are missing or invalid."""


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PredictionConfig:
    """Configuration controlling prediction behavior."""

    threshold: Optional[float] = None
    include_probability: bool = True
    include_feature_summary: bool = False
    reject_unknown_features: bool = True
    allow_missing_features: bool = True
    missing_feature_value: float = 0.0

    def validate(self) -> None:
        if self.threshold is not None:
            if not 0.0 <= self.threshold <= 1.0:
                raise ValueError("threshold must be between 0 and 1.")

        if not math.isfinite(self.missing_feature_value):
            raise ValueError("missing_feature_value must be finite.")


@dataclass(frozen=True)
class ModelArtifacts:
    """Paths and loaded metadata associated with a trained model."""

    model_path: str
    schema_path: str
    metadata_path: Optional[str]
    thresholds_path: Optional[str]

    model: Any
    schema: Any

    threshold: float
    model_version: str = "unknown"
    model_type: str = "unknown"

    dataset_fingerprint: Optional[str] = None
    schema_fingerprint: Optional[str] = None

    metadata: Dict[str, Any] = field(default_factory=dict)
    threshold_metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PredictionResult:
    """Prediction result for one analyzed sample."""

    sample_id: Optional[str]

    label: int
    label_name: str

    probability_malicious: float
    probability_benign: float

    threshold: float

    decision: str
    confidence: float

    model_type: str
    model_version: str

    feature_count: int
    nonzero_feature_count: int

    missing_feature_count: int
    unknown_feature_count: int

    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class BatchPredictionResult:
    """Prediction results for a collection of samples."""

    predictions: List[PredictionResult]

    total: int
    benign: int
    malicious: int

    threshold: float

    model_type: str
    model_version: str

    source: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total": self.total,
            "benign": self.benign,
            "malicious": self.malicious,
            "threshold": self.threshold,
            "model_type": self.model_type,
            "model_version": self.model_version,
            "source": self.source,
            "predictions": [prediction.to_dict() for prediction in self.predictions],
        }


# ---------------------------------------------------------------------------
# General helpers
# ---------------------------------------------------------------------------


def _safe_float(
    value: Any,
    default: float = 0.0,
) -> float:
    """Convert a value to a finite float."""
    try:
        result = float(value)
    except (TypeError, ValueError):
        return default

    if not math.isfinite(result):
        return default

    return result


def _normalize_feature_name(value: Any) -> str:
    """Normalize a feature name without changing semantic separators."""
    text = str(value).strip()

    if not text:
        return ""

    return text


def _validate_feature_names(
    feature_names: Sequence[Any],
) -> List[str]:
    """Validate an ordered feature-name sequence."""
    if not feature_names:
        raise FeatureSchemaError("The feature schema contains no feature names.")

    if len(feature_names) > MAX_FEATURES:
        raise FeatureSchemaError(
            f"The feature schema contains {len(feature_names)} features; "
            f"maximum supported is {MAX_FEATURES}."
        )

    result: List[str] = []
    seen = set()

    for value in feature_names:
        name = _normalize_feature_name(value)

        if not name:
            raise FeatureSchemaError("Feature schema contains an empty feature name.")

        if name in seen:
            raise FeatureSchemaError(f"Duplicate feature name in schema: {name!r}")

        seen.add(name)
        result.append(name)

    return result


def _read_json(
    path: os.PathLike[str] | str,
) -> Dict[str, Any]:
    """Read a bounded JSON object from disk."""
    target = Path(path)

    if not target.is_file():
        raise ArtifactError(f"Artifact does not exist: {target}")

    try:
        if target.stat().st_size > MAX_JSON_SIZE:
            raise ArtifactError(f"Artifact is too large: {target}")
    except OSError as exc:
        raise ArtifactError(f"Unable to inspect artifact: {target}") from exc

    try:
        with target.open("r", encoding="utf-8") as handle:
            payload = json.load(handle)
    except Exception as exc:
        raise ArtifactError(f"Unable to parse JSON artifact: {target}") from exc

    if not isinstance(payload, dict):
        raise ArtifactError(f"JSON artifact must contain an object: {target}")

    return payload


def _first_nonempty(
    mapping: Mapping[str, Any],
    *keys: str,
) -> Any:
    """Return the first non-empty mapping value."""
    for key in keys:
        value = mapping.get(key)

        if value is not None and value != "":
            return value

    return None


# ---------------------------------------------------------------------------
# Schema handling
# ---------------------------------------------------------------------------


def _schema_feature_names(schema: Any) -> List[str]:
    """Extract ordered feature names from a loaded schema object."""
    if schema is None:
        raise FeatureSchemaError("Feature schema is missing.")

    candidate = getattr(schema, "feature_names", None)

    if candidate:
        return _validate_feature_names(candidate)

    if isinstance(schema, Mapping):
        direct = schema.get("feature_names")

        if direct:
            return _validate_feature_names(direct)

        features = schema.get("features")

        if isinstance(features, Sequence) and not isinstance(
            features,
            (str, bytes, bytearray),
        ):
            names: List[str] = []

            for feature in features:
                if isinstance(feature, str):
                    names.append(feature)
                elif isinstance(feature, Mapping):
                    name = feature.get("name")

                    if name is not None:
                        names.append(str(name))
                elif hasattr(feature, "name"):
                    names.append(str(feature.name))

            if names:
                return _validate_feature_names(names)

    if hasattr(schema, "to_dict"):
        try:
            payload = schema.to_dict()

            if isinstance(payload, Mapping):
                return _schema_feature_names(payload)
        except Exception:
            pass

    raise FeatureSchemaError("Unable to determine ordered feature names from schema.")


def get_feature_names(
    schema: Any,
) -> List[str]:
    """Public helper returning the ordered trained feature schema."""
    return _schema_feature_names(schema)


def _schema_fingerprint(schema: Any) -> Optional[str]:
    """Extract a schema fingerprint when one is available."""
    for attribute in (
        "fingerprint",
        "schema_fingerprint",
    ):
        value = getattr(schema, attribute, None)

        if callable(value):
            try:
                value = value()
            except Exception:
                value = None

        if value:
            return str(value)

    if isinstance(schema, Mapping):
        value = _first_nonempty(
            schema,
            "fingerprint",
            "schema_fingerprint",
        )

        if value:
            return str(value)

    return None


# ---------------------------------------------------------------------------
# Artifact loading
# ---------------------------------------------------------------------------


def load_prediction_artifacts(
    *,
    model_path: os.PathLike[str] | str = DEFAULT_MODEL_PATH,
    schema_path: os.PathLike[str] | str = DEFAULT_SCHEMA_PATH,
    metadata_path: Optional[os.PathLike[str] | str] = DEFAULT_METADATA_PATH,
    thresholds_path: Optional[os.PathLike[str] | str] = DEFAULT_THRESHOLDS_PATH,
) -> ModelArtifacts:
    """
    Load the trusted model, feature schema, metadata, and threshold artifacts.

    Model loading uses joblib and therefore must only be performed against
    trusted model files.
    """
    model_target = Path(model_path)
    schema_target = Path(schema_path)

    if not model_target.is_file():
        raise ArtifactError(f"Model artifact does not exist: {model_target}")

    if not schema_target.is_file():
        raise ArtifactError(f"Feature schema does not exist: {schema_target}")

    try:
        model = load_trained_model(model_target)
    except Exception as exc:
        raise ArtifactError(f"Unable to load trained model: {model_target}") from exc

    try:
        schema = load_schema(schema_target)
    except Exception as exc:
        raise ArtifactError(f"Unable to load feature schema: {schema_target}") from exc

    # Validate the schema immediately rather than discovering incompatibility
    # only after processing a sample.
    feature_names = _schema_feature_names(schema)

    if not feature_names:
        raise FeatureSchemaError("Loaded schema has no features.")

    metadata: Dict[str, Any] = {}

    if metadata_path is not None:
        metadata_target = Path(metadata_path)

        if metadata_target.is_file():
            metadata = _read_json(metadata_target)

    threshold_metadata: Dict[str, Any] = {}

    if thresholds_path is not None:
        threshold_target = Path(thresholds_path)

        if threshold_target.is_file():
            threshold_metadata = _read_json(threshold_target)

    threshold = _extract_threshold(
        threshold_metadata,
        metadata,
        default=DEFAULT_THRESHOLD,
    )

    model_type = _extract_model_type(
        metadata,
        model,
    )

    model_version = _extract_model_version(
        metadata,
    )

    dataset_fingerprint = _extract_dataset_fingerprint(
        metadata,
        threshold_metadata,
    )

    schema_fingerprint = _extract_schema_fingerprint(
        metadata,
        threshold_metadata,
        schema,
    )

    # Check the model's learned feature count where available.
    model_feature_count = getattr(
        model,
        "n_features_in_",
        None,
    )

    if model_feature_count is not None:
        if int(model_feature_count) != len(feature_names):
            raise FeatureSchemaError(
                "Model/schema feature-count mismatch: "
                f"model={model_feature_count}, "
                f"schema={len(feature_names)}."
            )

    return ModelArtifacts(
        model_path=str(model_target),
        schema_path=str(schema_target),
        metadata_path=(str(metadata_path) if metadata_path is not None else None),
        thresholds_path=(str(thresholds_path) if thresholds_path is not None else None),
        model=model,
        schema=schema,
        threshold=threshold,
        model_version=model_version,
        model_type=model_type,
        dataset_fingerprint=dataset_fingerprint,
        schema_fingerprint=schema_fingerprint,
        metadata=metadata,
        threshold_metadata=threshold_metadata,
    )


def _extract_threshold(
    threshold_metadata: Mapping[str, Any],
    model_metadata: Mapping[str, Any],
    *,
    default: float,
) -> float:
    """Extract the persisted operational threshold."""
    candidates: List[Any] = [
        (
            threshold_metadata.get("classification", {}).get("selected_threshold")
            if isinstance(
                threshold_metadata.get("classification"),
                Mapping,
            )
            else None
        ),
        threshold_metadata.get("selected_threshold"),
        (
            model_metadata.get("threshold", {}).get("selected_threshold")
            if isinstance(
                model_metadata.get("threshold"),
                Mapping,
            )
            else None
        ),
        model_metadata.get("selected_threshold"),
        default,
    ]

    for candidate in candidates:
        if candidate is None:
            continue

        value = _safe_float(
            candidate,
            default=float("nan"),
        )

        if math.isfinite(value) and 0.0 <= value <= 1.0:
            return value

    raise ArtifactError(
        "No valid classification threshold was found in model artifacts."
    )


def _extract_model_type(
    metadata: Mapping[str, Any],
    model: Any,
) -> str:
    """Extract model type from metadata or the model object."""
    artifact = metadata.get("artifact")

    if isinstance(artifact, Mapping):
        value = artifact.get("model_type")

        if value:
            return str(value)

    value = metadata.get("model_type")

    if value:
        return str(value)

    return type(model).__name__


def _extract_model_version(
    metadata: Mapping[str, Any],
) -> str:
    """Extract model version from metadata."""
    artifact = metadata.get("artifact")

    if isinstance(artifact, Mapping):
        value = artifact.get("model_version")

        if value:
            return str(value)

    value = metadata.get("model_version")

    if value:
        return str(value)

    return "unknown"


def _extract_dataset_fingerprint(
    metadata: Mapping[str, Any],
    threshold_metadata: Mapping[str, Any],
) -> Optional[str]:
    """Extract the training dataset fingerprint."""
    dataset = metadata.get("dataset")

    if isinstance(dataset, Mapping):
        value = dataset.get("fingerprint")

        if value:
            return str(value)

    for source in (
        metadata,
        threshold_metadata,
    ):
        value = source.get("dataset_fingerprint")

        if value:
            return str(value)

    return None


def _extract_schema_fingerprint(
    metadata: Mapping[str, Any],
    threshold_metadata: Mapping[str, Any],
    schema: Any,
) -> Optional[str]:
    """Extract the trained schema fingerprint."""
    features = metadata.get("features")

    if isinstance(features, Mapping):
        value = features.get("schema_fingerprint")

        if value:
            return str(value)

    for source in (
        metadata,
        threshold_metadata,
    ):
        value = source.get("schema_fingerprint")

        if value:
            return str(value)

    return _schema_fingerprint(schema)


# ---------------------------------------------------------------------------
# Feature extraction and alignment
# ---------------------------------------------------------------------------


def _is_numeric_scalar(value: Any) -> bool:
    """Return whether a value is a finite numeric scalar."""
    if isinstance(value, bool):
        return True

    if isinstance(value, (int, float)):
        return math.isfinite(float(value))

    return False


def _flatten_numeric_mapping(
    value: Any,
    *,
    prefix: str = "",
    output: Optional[Dict[str, float]] = None,
    depth: int = 0,
    max_depth: int = 12,
) -> Dict[str, float]:
    """
    Flatten a nested feature mapping into numeric feature values.

    Non-feature metadata is ignored.
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
            key_text = str(key).strip()

            if not key_text:
                continue

            if key_text in RESERVED_MAPPING_KEYS:
                continue

            child_prefix = f"{prefix}.{key_text}" if prefix else key_text

            child = value[key]

            if _is_numeric_scalar(child):
                output[child_prefix] = _safe_float(child)
                continue

            if isinstance(child, Mapping):
                _flatten_numeric_mapping(
                    child,
                    prefix=child_prefix,
                    output=output,
                    depth=depth + 1,
                    max_depth=max_depth,
                )

    return output


def _extract_record_features(
    record: Any,
) -> Tuple[Dict[str, float], Optional[str]]:
    """
    Extract numeric feature values and sample ID from one input record.
    """
    sample_id: Optional[str] = None

    if isinstance(record, DatasetRecord):
        sample_id_value = getattr(record, "sample_id", None)

        if sample_id_value:
            sample_id = str(sample_id_value)

        features = getattr(record, "features", {}) or {}

        if isinstance(features, Mapping):
            return (
                _flatten_numeric_mapping(features),
                sample_id,
            )

    if isinstance(record, Mapping):
        sample_id_value = _first_nonempty(
            record,
            "sample_id",
            "id",
        )

        if sample_id_value is not None:
            sample_id = str(sample_id_value)

        feature_container = record.get("features")

        if feature_container is None:
            feature_container = record.get("feature_vector")

        if feature_container is None:
            feature_container = record.get("feature_values")

        if isinstance(feature_container, Mapping):
            return (
                _flatten_numeric_mapping(feature_container),
                sample_id,
            )

        # A flat numeric mapping is also accepted.
        flat = _flatten_numeric_mapping(record)

        if flat:
            return flat, sample_id

    # Support dataclass-like analysis/record objects.
    features = getattr(record, "features", None)

    if isinstance(features, Mapping):
        sample_id_value = getattr(record, "sample_id", None)

        if sample_id_value:
            sample_id = str(sample_id_value)

        return (
            _flatten_numeric_mapping(features),
            sample_id,
        )

    # Finally use the dataset helper when available.
    try:
        extracted = extract_features(record)

        if isinstance(extracted, Mapping):
            sample_id_value = getattr(record, "sample_id", None)

            if sample_id_value:
                sample_id = str(sample_id_value)

            return (
                _flatten_numeric_mapping(extracted),
                sample_id,
            )
    except Exception:
        pass

    raise FeatureSchemaError("Unable to extract numeric features from input record.")


def _looks_like_identity_feature(
    name: str,
) -> bool:
    """Identify metadata fields that should never become model inputs."""
    normalized = name.strip().lower()

    return any(
        hint == normalized
        or normalized.startswith(f"{hint}.")
        or normalized.endswith(f".{hint}")
        for hint in IDENTITY_FEATURE_HINTS
    )


def align_features(
    features: Mapping[str, Any],
    feature_names: Sequence[str],
    *,
    reject_unknown_features: bool = True,
    allow_missing_features: bool = True,
    missing_feature_value: float = 0.0,
) -> Tuple[List[float], int, int, List[str]]:
    """
    Align an arbitrary numeric feature mapping to the trained schema.

    Returns
    -------
    vector:
        Ordered model input vector.
    missing_count:
        Number of schema features absent from the input.
    unknown_count:
        Number of supplied features absent from the schema.
    unknown_names:
        Unknown feature names.
    """
    names = _validate_feature_names(feature_names)

    if not math.isfinite(missing_feature_value):
        raise ValueError("missing_feature_value must be finite.")

    normalized_features: Dict[str, float] = {}

    for key, value in features.items():
        name = _normalize_feature_name(key)

        if not name:
            continue

        if not _is_numeric_scalar(value):
            # Numeric strings are accepted for compatibility with CSV-loaded
            # records.
            try:
                converted = float(value)
            except (TypeError, ValueError):
                continue

            if not math.isfinite(converted):
                continue

            normalized_features[name] = converted
        else:
            normalized_features[name] = _safe_float(value)

    schema_set = set(names)

    unknown_names = sorted(
        name for name in normalized_features if name not in schema_set
    )

    if reject_unknown_features and unknown_names:
        raise FeatureSchemaError(
            "Input contains features not present in the trained schema: "
            + ", ".join(unknown_names[:20])
            + (f" ... ({len(unknown_names)} total)" if len(unknown_names) > 20 else "")
        )

    vector: List[float] = []
    missing_count = 0

    for name in names:
        if name in normalized_features:
            value = normalized_features[name]

            if not math.isfinite(value):
                raise FeatureSchemaError(
                    f"Feature {name!r} contains a non-finite value."
                )

            vector.append(float(value))
        else:
            if not allow_missing_features:
                raise FeatureSchemaError(f"Required feature is missing: {name!r}")

            vector.append(float(missing_feature_value))
            missing_count += 1

    return (
        vector,
        missing_count,
        len(unknown_names),
        unknown_names,
    )


def vectorize_record(
    record: Any,
    schema: Any,
    *,
    reject_unknown_features: bool = True,
    allow_missing_features: bool = True,
    missing_feature_value: float = 0.0,
) -> Tuple[
    List[float],
    Optional[str],
    int,
    int,
    List[str],
]:
    """Convert one record into the exact feature order expected by the model."""
    feature_names = _schema_feature_names(schema)

    features, sample_id = _extract_record_features(record)

    (
        vector,
        missing_count,
        unknown_count,
        unknown_names,
    ) = align_features(
        features,
        feature_names,
        reject_unknown_features=reject_unknown_features,
        allow_missing_features=allow_missing_features,
        missing_feature_value=missing_feature_value,
    )

    return (
        vector,
        sample_id,
        missing_count,
        unknown_count,
        unknown_names,
    )


# ---------------------------------------------------------------------------
# Model prediction
# ---------------------------------------------------------------------------


def _positive_class_index(
    model: Any,
) -> int:
    """Locate class 1 in the trained classifier."""
    classes = list(getattr(model, "classes_", []))

    if not classes:
        raise PredictionError("Loaded model does not expose classes_.")

    for index, value in enumerate(classes):
        try:
            numeric = int(value)

            if numeric == POSITIVE_LABEL:
                return index
        except (TypeError, ValueError):
            pass

        if str(value).strip().lower() in {
            "1",
            "true",
            "malicious",
            "malware",
            "positive",
        }:
            return index

    raise PredictionError(
        f"Unable to identify malicious class in model classes: {classes!r}"
    )


def _validate_vector(
    vector: Sequence[Any],
    expected_count: int,
) -> List[float]:
    """Validate a model input vector."""
    if len(vector) != expected_count:
        raise FeatureSchemaError(
            f"Feature vector has {len(vector)} values; "
            f"model expects {expected_count}."
        )

    result: List[float] = []

    for index, value in enumerate(vector):
        converted = _safe_float(
            value,
            default=float("nan"),
        )

        if not math.isfinite(converted):
            raise FeatureSchemaError(
                f"Feature vector contains a non-finite value at index "
                f"{index}: {value!r}"
            )

        result.append(converted)

    return result


def predict_probability(
    model: Any,
    vector: Sequence[Any],
) -> float:
    """Return the model's probability for the malicious class."""
    if not hasattr(model, "predict_proba"):
        raise PredictionError("Loaded model does not expose predict_proba().")

    expected_count = getattr(
        model,
        "n_features_in_",
        len(vector),
    )

    validated = _validate_vector(
        vector,
        int(expected_count),
    )

    try:
        probabilities = model.predict_proba([validated])
    except Exception as exc:
        raise PredictionError(f"Model probability prediction failed: {exc}") from exc

    if not probabilities or not probabilities[0]:
        raise PredictionError("Model returned an empty probability vector.")

    positive_index = _positive_class_index(model)

    if positive_index >= len(probabilities[0]):
        raise PredictionError("Model returned malformed class probabilities.")

    probability = _safe_float(
        probabilities[0][positive_index],
        default=float("nan"),
    )

    if not math.isfinite(probability):
        raise PredictionError("Model returned a non-finite malicious probability.")

    if not 0.0 <= probability <= 1.0:
        raise PredictionError(f"Model returned an invalid probability: {probability}")

    return probability


def predict_vector(
    model: Any,
    vector: Sequence[Any],
    *,
    threshold: float = DEFAULT_THRESHOLD,
) -> Tuple[int, float, float]:
    """
    Predict one already-aligned feature vector.

    Returns
    -------
    label:
        0 for benign, 1 for malicious.
    probability_malicious:
        Probability assigned to class 1.
    probability_benign:
        Probability assigned to class 0.
    """
    if not 0.0 <= threshold <= 1.0:
        raise ValueError("threshold must be between 0 and 1.")

    probability_malicious = predict_probability(
        model,
        vector,
    )

    probability_benign = 1.0 - probability_malicious

    label = int(probability_malicious >= threshold)

    return (
        label,
        probability_malicious,
        probability_benign,
    )


def predict_record(
    record: Any,
    artifacts: ModelArtifacts,
    *,
    config: PredictionConfig = PredictionConfig(),
) -> PredictionResult:
    """Predict the malware risk of one feature-analysis record."""
    config.validate()

    (
        vector,
        sample_id,
        missing_count,
        unknown_count,
        unknown_names,
    ) = vectorize_record(
        record,
        artifacts.schema,
        reject_unknown_features=config.reject_unknown_features,
        allow_missing_features=config.allow_missing_features,
        missing_feature_value=config.missing_feature_value,
    )

    threshold = (
        artifacts.threshold if config.threshold is None else float(config.threshold)
    )

    (
        label,
        probability_malicious,
        probability_benign,
    ) = predict_vector(
        artifacts.model,
        vector,
        threshold=threshold,
    )

    confidence = max(
        probability_malicious,
        probability_benign,
    )

    metadata: Dict[str, Any] = {
        "dataset_fingerprint": artifacts.dataset_fingerprint,
        "schema_fingerprint": artifacts.schema_fingerprint,
    }

    if config.include_feature_summary:
        metadata["feature_summary"] = {
            "feature_count": len(vector),
            "nonzero_feature_count": sum(1 for value in vector if value != 0.0),
            "missing_feature_count": missing_count,
            "unknown_feature_count": unknown_count,
            "unknown_features": unknown_names,
        }

    return PredictionResult(
        sample_id=sample_id,
        label=label,
        label_name=(
            POSITIVE_LABEL_NAME if label == POSITIVE_LABEL else NEGATIVE_LABEL_NAME
        ),
        probability_malicious=probability_malicious,
        probability_benign=probability_benign,
        threshold=threshold,
        decision=(
            POSITIVE_LABEL_NAME if label == POSITIVE_LABEL else NEGATIVE_LABEL_NAME
        ),
        confidence=confidence,
        model_type=artifacts.model_type,
        model_version=artifacts.model_version,
        feature_count=len(vector),
        nonzero_feature_count=sum(1 for value in vector if value != 0.0),
        missing_feature_count=missing_count,
        unknown_feature_count=unknown_count,
        metadata=metadata,
    )


# ---------------------------------------------------------------------------
# Batch prediction
# ---------------------------------------------------------------------------


def predict_records(
    records: Iterable[Any],
    artifacts: ModelArtifacts,
    *,
    config: PredictionConfig = PredictionConfig(),
    source: Optional[str] = None,
) -> BatchPredictionResult:
    """Predict a bounded iterable of records."""
    config.validate()

    predictions: List[PredictionResult] = []

    for index, record in enumerate(records):
        if index >= MAX_BATCH_SIZE:
            raise PredictionError(
                f"Batch exceeds maximum supported size of " f"{MAX_BATCH_SIZE}."
            )

        prediction = predict_record(
            record,
            artifacts,
            config=config,
        )

        predictions.append(prediction)

    malicious = sum(
        1 for prediction in predictions if prediction.label == POSITIVE_LABEL
    )

    benign = len(predictions) - malicious

    return BatchPredictionResult(
        predictions=predictions,
        total=len(predictions),
        benign=benign,
        malicious=malicious,
        threshold=(
            artifacts.threshold if config.threshold is None else float(config.threshold)
        ),
        model_type=artifacts.model_type,
        model_version=artifacts.model_version,
        source=source,
    )


def predict_dataset(
    dataset: Dataset,
    artifacts: ModelArtifacts,
    *,
    config: PredictionConfig = PredictionConfig(),
    source: Optional[str] = None,
) -> BatchPredictionResult:
    """Predict every record in a Dataset."""
    records = list(getattr(dataset, "records", []) or [])

    if len(records) > MAX_BATCH_SIZE:
        raise PredictionError(
            f"Dataset contains {len(records)} records; "
            f"maximum prediction batch is {MAX_BATCH_SIZE}."
        )

    return predict_records(
        records,
        artifacts,
        config=config,
        source=source,
    )


def predict_dataset_path(
    dataset_path: os.PathLike[str] | str,
    artifacts: ModelArtifacts,
    *,
    config: PredictionConfig = PredictionConfig(),
) -> BatchPredictionResult:
    """Load a CSV/JSONL dataset and predict every record."""
    source = Path(dataset_path)

    if not source.is_file():
        raise PredictionError(f"Dataset does not exist: {source}")

    try:
        dataset = load_dataset(source)
    except Exception as exc:
        raise PredictionError(
            f"Unable to load prediction dataset {source}: {exc}"
        ) from exc

    return predict_dataset(
        dataset,
        artifacts,
        config=config,
        source=str(source),
    )


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------


def prediction_to_dict(
    prediction: PredictionResult,
) -> Dict[str, Any]:
    """Serialize one prediction to a dictionary."""
    return prediction.to_dict()


def predictions_to_json(
    result: BatchPredictionResult,
    *,
    indent: int = 2,
) -> str:
    """Serialize a batch result as JSON."""
    return json.dumps(
        result.to_dict(),
        indent=indent,
        sort_keys=True,
        ensure_ascii=False,
        allow_nan=False,
    )


def predictions_to_jsonl(
    result: BatchPredictionResult,
) -> str:
    """Serialize individual predictions as JSON Lines."""
    lines = [
        json.dumps(
            prediction.to_dict(),
            sort_keys=True,
            ensure_ascii=False,
            allow_nan=False,
        )
        for prediction in result.predictions
    ]

    return "\n".join(lines) + ("\n" if lines else "")


def save_predictions_json(
    result: BatchPredictionResult,
    path: os.PathLike[str] | str,
) -> Path:
    """Atomically save batch predictions as JSON."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)

    temporary = target.with_name(f".{target.name}.{os.getpid()}.tmp")

    try:
        with temporary.open(
            "w",
            encoding="utf-8",
            newline="\n",
        ) as handle:
            json.dump(
                result.to_dict(),
                handle,
                indent=2,
                sort_keys=True,
                ensure_ascii=False,
                allow_nan=False,
            )
            handle.write("\n")

        os.replace(
            temporary,
            target,
        )
    except Exception as exc:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass

        raise PredictionError(f"Unable to save prediction output: {target}") from exc

    return target


def save_predictions_jsonl(
    result: BatchPredictionResult,
    path: os.PathLike[str] | str,
) -> Path:
    """Atomically save individual predictions as JSON Lines."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)

    temporary = target.with_name(f".{target.name}.{os.getpid()}.tmp")

    try:
        with temporary.open(
            "w",
            encoding="utf-8",
            newline="\n",
        ) as handle:
            for prediction in result.predictions:
                json.dump(
                    prediction.to_dict(),
                    handle,
                    sort_keys=True,
                    ensure_ascii=False,
                    allow_nan=False,
                )
                handle.write("\n")

        os.replace(
            temporary,
            target,
        )
    except Exception as exc:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass

        raise PredictionError(
            f"Unable to save JSONL prediction output: {target}"
        ) from exc

    return target


def save_predictions_csv(
    result: BatchPredictionResult,
    path: os.PathLike[str] | str,
) -> Path:
    """Save predictions in a flat CSV representation."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)

    fieldnames = [
        "sample_id",
        "label",
        "label_name",
        "probability_malicious",
        "probability_benign",
        "threshold",
        "decision",
        "confidence",
        "model_type",
        "model_version",
        "feature_count",
        "nonzero_feature_count",
        "missing_feature_count",
        "unknown_feature_count",
    ]

    temporary = target.with_name(f".{target.name}.{os.getpid()}.tmp")

    try:
        with temporary.open(
            "w",
            encoding="utf-8",
            newline="",
        ) as handle:
            writer = csv.DictWriter(
                handle,
                fieldnames=fieldnames,
            )

            writer.writeheader()

            for prediction in result.predictions:
                row = prediction.to_dict()

                writer.writerow({field: row.get(field) for field in fieldnames})

        os.replace(
            temporary,
            target,
        )
    except Exception as exc:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass

        raise PredictionError(
            f"Unable to save CSV prediction output: {target}"
        ) from exc

    return target


# ---------------------------------------------------------------------------
# Threshold and model information
# ---------------------------------------------------------------------------


def get_prediction_threshold(
    artifacts: ModelArtifacts,
) -> float:
    """Return the persisted operational prediction threshold."""
    return float(artifacts.threshold)


def model_summary(
    artifacts: ModelArtifacts,
) -> Dict[str, Any]:
    """Return a compact summary of loaded model artifacts."""
    feature_names = _schema_feature_names(artifacts.schema)

    return {
        "model_type": artifacts.model_type,
        "model_version": artifacts.model_version,
        "model_path": artifacts.model_path,
        "schema_path": artifacts.schema_path,
        "metadata_path": artifacts.metadata_path,
        "thresholds_path": artifacts.thresholds_path,
        "threshold": artifacts.threshold,
        "feature_count": len(feature_names),
        "dataset_fingerprint": artifacts.dataset_fingerprint,
        "schema_fingerprint": artifacts.schema_fingerprint,
        "model_feature_count": getattr(
            artifacts.model,
            "n_features_in_",
            None,
        ),
        "classes": [
            str(value)
            for value in getattr(
                artifacts.model,
                "classes_",
                [],
            )
        ],
    }


# ---------------------------------------------------------------------------
# Convenience API
# ---------------------------------------------------------------------------


def predict(
    record: Any,
    *,
    model_path: os.PathLike[str] | str = DEFAULT_MODEL_PATH,
    schema_path: os.PathLike[str] | str = DEFAULT_SCHEMA_PATH,
    metadata_path: Optional[os.PathLike[str] | str] = DEFAULT_METADATA_PATH,
    thresholds_path: Optional[os.PathLike[str] | str] = DEFAULT_THRESHOLDS_PATH,
    threshold: Optional[float] = None,
) -> PredictionResult:
    """
    Load model artifacts and predict one record.

    This is the primary high-level API for pipeline integration.
    """
    artifacts = load_prediction_artifacts(
        model_path=model_path,
        schema_path=schema_path,
        metadata_path=metadata_path,
        thresholds_path=thresholds_path,
    )

    config = PredictionConfig(
        threshold=threshold,
    )

    return predict_record(
        record,
        artifacts,
        config=config,
    )


def predict_file(
    dataset_path: os.PathLike[str] | str,
    *,
    model_path: os.PathLike[str] | str = DEFAULT_MODEL_PATH,
    schema_path: os.PathLike[str] | str = DEFAULT_SCHEMA_PATH,
    metadata_path: Optional[os.PathLike[str] | str] = DEFAULT_METADATA_PATH,
    thresholds_path: Optional[os.PathLike[str] | str] = DEFAULT_THRESHOLDS_PATH,
    threshold: Optional[float] = None,
) -> BatchPredictionResult:
    """Load model artifacts and predict an entire dataset file."""
    artifacts = load_prediction_artifacts(
        model_path=model_path,
        schema_path=schema_path,
        metadata_path=metadata_path,
        thresholds_path=thresholds_path,
    )

    config = PredictionConfig(
        threshold=threshold,
    )

    return predict_dataset_path(
        dataset_path,
        artifacts,
        config=config,
    )


# ---------------------------------------------------------------------------
# Command-line interface
# ---------------------------------------------------------------------------


def build_argument_parser() -> argparse.ArgumentParser:
    """Build the prediction command-line parser."""
    parser = argparse.ArgumentParser(
        description=(
            "Run static ML inference using the Pharos CDR " "Random Forest classifier."
        )
    )

    parser.add_argument(
        "input",
        type=Path,
        help="CSV or JSONL feature dataset to classify.",
    )

    parser.add_argument(
        "--model",
        type=Path,
        default=DEFAULT_MODEL_PATH,
        help=f"Model artifact (default: {DEFAULT_MODEL_PATH}).",
    )

    parser.add_argument(
        "--schema",
        type=Path,
        default=DEFAULT_SCHEMA_PATH,
        help=f"Feature schema (default: {DEFAULT_SCHEMA_PATH}).",
    )

    parser.add_argument(
        "--metadata",
        type=Path,
        default=DEFAULT_METADATA_PATH,
        help=f"Model metadata (default: {DEFAULT_METADATA_PATH}).",
    )

    parser.add_argument(
        "--thresholds",
        type=Path,
        default=DEFAULT_THRESHOLDS_PATH,
        help=("Threshold metadata " f"(default: {DEFAULT_THRESHOLDS_PATH})."),
    )

    parser.add_argument(
        "--threshold",
        type=float,
        default=None,
        help=(
            "Override persisted classification threshold. "
            "Use only when intentionally changing the operational policy."
        ),
    )

    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Optional output file.",
    )

    parser.add_argument(
        "--format",
        choices=("json", "jsonl", "csv"),
        default=DEFAULT_OUTPUT_FORMAT,
        help="Output format (default: jsonl).",
    )

    parser.add_argument(
        "--reject-unknown-features",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Reject features absent from the trained schema.",
    )

    parser.add_argument(
        "--allow-missing-features",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Fill absent schema features with zero.",
    )

    parser.add_argument(
        "--include-feature-summary",
        action="store_true",
        help="Include feature-vector statistics in each result.",
    )

    return parser


def _write_cli_output(
    result: BatchPredictionResult,
    output: Optional[Path],
    output_format: str,
) -> None:
    """Write or print prediction results according to CLI options."""
    if output is not None:
        if output_format == "json":
            save_predictions_json(
                result,
                output,
            )
        elif output_format == "csv":
            save_predictions_csv(
                result,
                output,
            )
        else:
            save_predictions_jsonl(
                result,
                output,
            )

        return

    if output_format == "json":
        print(predictions_to_json(result))
    elif output_format == "csv":
        fieldnames = [
            "sample_id",
            "label",
            "label_name",
            "probability_malicious",
            "probability_benign",
            "threshold",
            "decision",
            "confidence",
            "model_type",
            "model_version",
            "feature_count",
            "nonzero_feature_count",
            "missing_feature_count",
            "unknown_feature_count",
        ]

        writer = csv.DictWriter(
            sys.stdout,
            fieldnames=fieldnames,
        )

        writer.writeheader()

        for prediction in result.predictions:
            row = prediction.to_dict()

            writer.writerow({field: row.get(field) for field in fieldnames})
    else:
        sys.stdout.write(predictions_to_jsonl(result))


def main(
    argv: Optional[Sequence[str]] = None,
) -> int:
    """CLI entry point."""
    parser = build_argument_parser()
    args = parser.parse_args(argv)

    if args.threshold is not None:
        if not 0.0 <= args.threshold <= 1.0:
            parser.error("--threshold must be between 0 and 1.")

    config = PredictionConfig(
        threshold=args.threshold,
        include_feature_summary=args.include_feature_summary,
        reject_unknown_features=args.reject_unknown_features,
        allow_missing_features=args.allow_missing_features,
    )

    try:
        artifacts = load_prediction_artifacts(
            model_path=args.model,
            schema_path=args.schema,
            metadata_path=args.metadata,
            thresholds_path=args.thresholds,
        )

        result = predict_dataset_path(
            args.input,
            artifacts,
            config=config,
        )

        _write_cli_output(
            result,
            args.output,
            args.format,
        )

    except (
        PredictionError,
        ValueError,
    ) as exc:
        print(
            f"Prediction failed: {exc}",
            file=sys.stderr,
        )
        return 2

    return 0


if __name__ == "__main__":
    raise SystemExit(main())


# ---------------------------------------------------------------------------
# PUBLIC APIs
# ---------------------------------------------------------------------------

__all__ = [
    "PredictionError",
    "PredictionDependencyError",
    "FeatureSchemaError",
    "ArtifactError",
    "PredictionConfig",
    "ModelArtifacts",
    "PredictionResult",
    "BatchPredictionResult",
    "load_prediction_artifacts",
    "get_prediction_threshold",
    "model_summary",
    "get_feature_names",
    "align_features",
    "vectorize_record",
    "predict_probability",
    "predict_vector",
    "predict_record",
    "predict_records",
    "predict_dataset",
    "predict_dataset_path",
    "predict",
    "predict_file",
    "prediction_to_dict",
    "predictions_to_json",
    "predictions_to_jsonl",
    "save_predictions_json",
    "save_predictions_jsonl",
    "save_predictions_csv",
    "build_argument_parser",
    "main",
]
