"""
pharos-cdr.src.ml.train
=======================

Deterministic, defensive model-training utilities for Pharos CDR.

This module trains a supervised malware/document-risk classifier from the
dataset representation implemented in ``src.ml.dataset``.

Design goals
------------
* Static/offline training only.
* Never execute, import, or otherwise activate analyzed documents/macros/scripts.
* Deterministic Random Forest training by default.
* Stable feature ordering and schema persistence.
* Class-imbalance-aware training.
* Reproducible train/validation/test splitting.
* Threshold selection based on validation probabilities.
* Model, schema, metadata, and threshold persistence.
* Defensive validation of datasets before training.
* No network access.
* No arbitrary code loading from samples.

Expected project locations
--------------------------
models/
    trained/
        random_forest.joblib
    metadata/
        feature_schema.json
        model_metadata.json
        thresholds.json

Typical usage
-------------
Programmatically::

    from src.ml.dataset import load_dataset
    from src.ml.train import train_model

    dataset = load_dataset("data/processed/features.csv")
    result = train_model(dataset)

Command line::

    python -m src.ml.train data/processed/features.csv

The module deliberately keeps training artifacts separate from input data.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import platform
import sys
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

try:
    from .dataset import (
        Dataset,
        DatasetRecord,
        DatasetSplit,
        build_ml_inputs,
        dataset_fingerprint,
        dataset_statistics,
        load_dataset,
        save_schema,
        split_dataset,
        validate_dataset,
    )
except ImportError:  # pragma: no cover - supports direct execution
    from dataset import (  # type: ignore
        Dataset,
        DatasetRecord,
        DatasetSplit,
        build_ml_inputs,
        dataset_fingerprint,
        dataset_statistics,
        load_dataset,
        save_schema,
        split_dataset,
        validate_dataset,
    )


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_MODEL_PATH = Path("models/trained/random_forest.joblib")
DEFAULT_SCHEMA_PATH = Path("models/metadata/feature_schema.json")
DEFAULT_METADATA_PATH = Path("models/metadata/model_metadata.json")
DEFAULT_THRESHOLDS_PATH = Path("models/metadata/thresholds.json")

DEFAULT_RANDOM_STATE = 42
DEFAULT_N_ESTIMATORS = 400
DEFAULT_MAX_DEPTH: Optional[int] = None
DEFAULT_MIN_SAMPLES_SPLIT = 2
DEFAULT_MIN_SAMPLES_LEAF = 1
DEFAULT_MAX_FEATURES = "sqrt"
DEFAULT_CLASS_WEIGHT = "balanced_subsample"
DEFAULT_N_JOBS = -1

DEFAULT_TEST_SIZE = 0.20
DEFAULT_VALIDATION_SIZE = 0.20

DEFAULT_THRESHOLD = 0.50
DEFAULT_THRESHOLD_MIN = 0.05
DEFAULT_THRESHOLD_MAX = 0.95
DEFAULT_THRESHOLD_STEP = 0.01

DEFAULT_MAX_TRAINING_RECORDS = 2_000_000
MAX_FEATURES = 100_000

MODEL_TYPE = "RandomForestClassifier"
MODEL_FORMAT = "joblib"
MODEL_VERSION = "1.0"

POSITIVE_LABELS = {
    "1",
    "true",
    "yes",
    "malicious",
    "malware",
    "suspicious",
    "unsafe",
    "bad",
    "positive",
    "threat",
}

NEGATIVE_LABELS = {
    "0",
    "false",
    "no",
    "benign",
    "safe",
    "clean",
    "normal",
    "negative",
}

IDENTITY_FEATURE_HINTS = (
    "sha256",
    "sha1",
    "md5",
    "hash",
    "sample_id",
    "filename",
    "file_name",
    "path",
    "filepath",
    "file_path",
)

DEFAULT_THRESHOLD_OBJECTIVES = (
    "f1",
    "balanced_accuracy",
    "youden_j",
    "mcc",
)


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class TrainingError(RuntimeError):
    """Base exception for model-training failures."""


class DependencyError(TrainingError):
    """Raised when a required ML dependency is unavailable."""


class DatasetTrainingError(TrainingError):
    """Raised when the supplied dataset cannot safely be used for training."""


class ModelPersistenceError(TrainingError):
    """Raised when a model artifact cannot be persisted safely."""


# ---------------------------------------------------------------------------
# Optional ML dependencies
# ---------------------------------------------------------------------------


def _require_sklearn() -> Dict[str, Any]:
    """
    Import scikit-learn lazily.

    Lazy imports keep dataset utilities usable in environments that only need
    feature extraction or dataset manipulation.
    """
    try:
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.metrics import (
            accuracy_score,
            balanced_accuracy_score,
            classification_report,
            confusion_matrix,
            f1_score,
            matthews_corrcoef,
            precision_score,
            recall_score,
            roc_auc_score,
        )
    except ImportError as exc:
        raise DependencyError(
            "scikit-learn is required for model training. "
            "Install the project's ML dependencies before training."
        ) from exc

    return {
        "RandomForestClassifier": RandomForestClassifier,
        "accuracy_score": accuracy_score,
        "balanced_accuracy_score": balanced_accuracy_score,
        "classification_report": classification_report,
        "confusion_matrix": confusion_matrix,
        "f1_score": f1_score,
        "matthews_corrcoef": matthews_corrcoef,
        "precision_score": precision_score,
        "recall_score": recall_score,
        "roc_auc_score": roc_auc_score,
    }


def _require_joblib() -> Any:
    """Import joblib lazily for model persistence."""
    try:
        import joblib
    except ImportError as exc:
        raise DependencyError(
            "joblib is required to persist the trained model."
        ) from exc
    return joblib


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RandomForestConfig:
    """Configuration for deterministic Random Forest training."""

    n_estimators: int = DEFAULT_N_ESTIMATORS
    max_depth: Optional[int] = DEFAULT_MAX_DEPTH
    min_samples_split: int = DEFAULT_MIN_SAMPLES_SPLIT
    min_samples_leaf: int = DEFAULT_MIN_SAMPLES_LEAF
    max_features: Any = DEFAULT_MAX_FEATURES
    class_weight: Any = DEFAULT_CLASS_WEIGHT
    random_state: int = DEFAULT_RANDOM_STATE
    n_jobs: int = DEFAULT_N_JOBS
    bootstrap: bool = True
    criterion: str = "gini"
    max_leaf_nodes: Optional[int] = None
    max_samples: Optional[float] = None
    ccp_alpha: float = 0.0

    def validate(self) -> None:
        if self.n_estimators < 10:
            raise ValueError("n_estimators must be >= 10.")

        if self.max_depth is not None and self.max_depth < 1:
            raise ValueError("max_depth must be >= 1 or None.")

        if self.min_samples_split < 2:
            raise ValueError("min_samples_split must be >= 2.")

        if self.min_samples_leaf < 1:
            raise ValueError("min_samples_leaf must be >= 1.")

        if self.max_leaf_nodes is not None and self.max_leaf_nodes < 2:
            raise ValueError("max_leaf_nodes must be >= 2 or None.")

        if self.max_samples is not None:
            if not self.bootstrap:
                raise ValueError("max_samples requires bootstrap=True.")
            if not 0.0 < self.max_samples <= 1.0:
                raise ValueError("max_samples must be in (0, 1].")

        if self.ccp_alpha < 0:
            raise ValueError("ccp_alpha must be >= 0.")


@dataclass(frozen=True)
class SplitConfig:
    """Configuration for train/validation/test splitting."""

    test_size: float = DEFAULT_TEST_SIZE
    validation_size: float = DEFAULT_VALIDATION_SIZE
    random_state: int = DEFAULT_RANDOM_STATE

    def validate(self) -> None:
        if not 0.0 < self.test_size < 1.0:
            raise ValueError("test_size must be between 0 and 1.")

        if not 0.0 < self.validation_size < 1.0:
            raise ValueError("validation_size must be between 0 and 1.")

        if self.test_size + self.validation_size >= 1.0:
            raise ValueError("test_size + validation_size must be less than 1.")


@dataclass(frozen=True)
class ThresholdResult:
    """Result of validation-set threshold optimization."""

    default_threshold: float
    selected_threshold: float
    objective: str
    objective_score: float
    precision: float
    recall: float
    f1: float
    balanced_accuracy: float
    youden_j: float
    matthews_corrcoef: float
    positive_predictions: int
    negative_predictions: int


@dataclass
class EvaluationResult:
    """Serializable classifier evaluation result."""

    sample_count: int = 0
    positive_count: int = 0
    negative_count: int = 0
    threshold: float = DEFAULT_THRESHOLD

    accuracy: float = 0.0
    balanced_accuracy: float = 0.0
    precision: float = 0.0
    recall: float = 0.0
    f1: float = 0.0
    matthews_corrcoef: float = 0.0
    roc_auc: Optional[float] = None

    true_negative: int = 0
    false_positive: int = 0
    false_negative: int = 0
    true_positive: int = 0

    classification_report: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class FeatureImportance:
    """One model feature-importance record."""

    feature: str
    importance: float
    rank: int

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class TrainingResult:
    """Complete in-memory result of a model-training operation."""

    model: Any
    model_path: Optional[str]

    feature_names: List[str]
    feature_count: int

    dataset_fingerprint: str
    schema_fingerprint: str

    train_count: int
    validation_count: int
    test_count: int

    train_class_distribution: Dict[str, int]
    validation_class_distribution: Dict[str, int]
    test_class_distribution: Dict[str, int]

    validation: EvaluationResult
    test: EvaluationResult

    threshold: ThresholdResult

    feature_importance: List[FeatureImportance]

    config: RandomForestConfig
    split_config: SplitConfig

    trained_at: str
    duration_seconds: float

    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self, include_model: bool = False) -> Dict[str, Any]:
        result = {
            "model_path": self.model_path,
            "feature_names": list(self.feature_names),
            "feature_count": self.feature_count,
            "dataset_fingerprint": self.dataset_fingerprint,
            "schema_fingerprint": self.schema_fingerprint,
            "train_count": self.train_count,
            "validation_count": self.validation_count,
            "test_count": self.test_count,
            "train_class_distribution": dict(self.train_class_distribution),
            "validation_class_distribution": dict(self.validation_class_distribution),
            "test_class_distribution": dict(self.test_class_distribution),
            "validation": self.validation.to_dict(),
            "test": self.test.to_dict(),
            "threshold": asdict(self.threshold),
            "feature_importance": [item.to_dict() for item in self.feature_importance],
            "config": asdict(self.config),
            "split_config": asdict(self.split_config),
            "trained_at": self.trained_at,
            "duration_seconds": self.duration_seconds,
            "metadata": dict(self.metadata),
        }

        if include_model:
            result["model"] = self.model

        return result


# ---------------------------------------------------------------------------
# General helpers
# ---------------------------------------------------------------------------


def _utc_now() -> str:
    """Return a stable UTC ISO-8601 timestamp."""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _safe_float(value: Any, default: float = 0.0) -> float:
    """Convert a value to a finite float."""
    try:
        result = float(value)
    except (TypeError, ValueError):
        return default

    if not math.isfinite(result):
        return default

    return result


def _safe_int(value: Any, default: int = 0) -> int:
    """Convert a value to an integer."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _normalize_label_value(value: Any) -> Optional[int]:
    """
    Normalize a dataset label into binary 0/1.

    Unknown labels return None instead of being guessed.
    """
    if isinstance(value, bool):
        return int(value)

    if isinstance(value, int) and value in (0, 1):
        return int(value)

    if isinstance(value, float) and value in (0.0, 1.0):
        return int(value)

    text = str(value).strip().lower()

    if text in POSITIVE_LABELS:
        return 1

    if text in NEGATIVE_LABELS:
        return 0

    try:
        numeric = float(text)
    except ValueError:
        return None

    if numeric == 1.0:
        return 1

    if numeric == 0.0:
        return 0

    return None


def _class_distribution(labels: Sequence[int]) -> Dict[str, int]:
    """Return a stable binary class distribution."""
    positives = sum(1 for label in labels if int(label) == 1)
    negatives = sum(1 for label in labels if int(label) == 0)

    return {
        "0": negatives,
        "1": positives,
    }


def _ensure_binary_labels(labels: Sequence[Any], context: str) -> List[int]:
    """Validate and normalize labels."""
    normalized: List[int] = []

    for index, value in enumerate(labels):
        label = _normalize_label_value(value)

        if label is None:
            raise DatasetTrainingError(
                f"{context}: record {index} has an unsupported label: " f"{value!r}"
            )

        normalized.append(label)

    if not normalized:
        raise DatasetTrainingError(f"{context}: no labels were supplied.")

    classes = set(normalized)

    if classes != {0, 1}:
        raise DatasetTrainingError(
            f"{context}: binary training requires both classes 0 and 1; "
            f"observed classes={sorted(classes)}"
        )

    return normalized


def _validate_feature_names(feature_names: Sequence[str]) -> List[str]:
    """
    Validate and normalize feature names.

    Feature names must be unique and deterministic.
    """
    if not feature_names:
        raise DatasetTrainingError("Dataset contains no features.")

    if len(feature_names) > MAX_FEATURES:
        raise DatasetTrainingError(
            f"Dataset contains {len(feature_names)} features; "
            f"maximum supported is {MAX_FEATURES}."
        )

    result: List[str] = []
    seen = set()

    for name in feature_names:
        text = str(name).strip()

        if not text:
            raise DatasetTrainingError("Feature names cannot be empty.")

        if text in seen:
            raise DatasetTrainingError(f"Duplicate feature name detected: {text!r}")

        seen.add(text)
        result.append(text)

    return result


def _validate_matrix(
    matrix: Sequence[Sequence[Any]],
    feature_count: int,
    context: str,
) -> List[List[float]]:
    """Validate and convert a feature matrix into finite floats."""
    result: List[List[float]] = []

    for row_index, row in enumerate(matrix):
        if len(row) != feature_count:
            raise DatasetTrainingError(
                f"{context}: row {row_index} has {len(row)} features; "
                f"expected {feature_count}."
            )

        converted: List[float] = []

        for column_index, value in enumerate(row):
            number = _safe_float(value, default=float("nan"))

            if not math.isfinite(number):
                raise DatasetTrainingError(
                    f"{context}: non-finite feature value at "
                    f"row={row_index}, column={column_index}: {value!r}"
                )

            converted.append(number)

        result.append(converted)

    return result


def _safe_json_dump(
    path: Path,
    payload: Mapping[str, Any],
) -> None:
    """Atomically write a JSON object."""
    path.parent.mkdir(parents=True, exist_ok=True)

    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")

    try:
        with temporary.open("w", encoding="utf-8", newline="\n") as handle:
            json.dump(
                payload,
                handle,
                indent=2,
                sort_keys=True,
                ensure_ascii=False,
                allow_nan=False,
            )
            handle.write("\n")

        os.replace(temporary, path)
    except Exception as exc:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass

        raise ModelPersistenceError(f"Unable to write metadata file: {path}") from exc


def _sha256_json(payload: Any) -> str:
    """Hash canonical JSON for deterministic metadata fingerprints."""
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    ).encode("utf-8")

    return hashlib.sha256(encoded).hexdigest()


def _dataset_schema_fingerprint(dataset: Dataset) -> str:
    """
    Obtain the schema fingerprint from the dataset.

    Falls back to hashing the ordered feature names when the dataset object
    does not expose a dedicated schema fingerprint helper.
    """
    schema = getattr(dataset, "schema", None)

    if schema is not None:
        for attribute in ("fingerprint", "schema_fingerprint"):
            value = getattr(schema, attribute, None)

            if callable(value):
                try:
                    fingerprint = value()
                    if fingerprint:
                        return str(fingerprint)
                except Exception:
                    pass

            elif value:
                return str(value)

        try:
            if hasattr(schema, "to_dict"):
                return _sha256_json(schema.to_dict())
            if hasattr(schema, "__dict__"):
                return _sha256_json(schema.__dict__)
        except Exception:
            pass

    feature_names = list(getattr(schema, "feature_names", []) or [])

    if not feature_names:
        records = getattr(dataset, "records", [])
        inferred = set()

        for record in records:
            features = getattr(record, "features", {}) or {}
            inferred.update(str(key) for key in features.keys())

        feature_names = sorted(inferred)

    return _sha256_json(feature_names)


# ---------------------------------------------------------------------------
# Dataset preparation
# ---------------------------------------------------------------------------


def prepare_training_data(
    dataset: Dataset,
) -> Tuple[List[List[float]], List[int], List[str], List[str]]:
    """
    Validate a dataset and convert it to ML-ready matrices.

    Returns
    -------
    X:
        Feature matrix.
    y:
        Binary labels.
    sample_ids:
        Dataset sample identifiers.
    feature_names:
        Ordered feature names.
    """
    if dataset is None:
        raise DatasetTrainingError("dataset must not be None.")

    records = list(getattr(dataset, "records", []) or [])

    if not records:
        raise DatasetTrainingError("Dataset contains no records.")

    if len(records) > DEFAULT_MAX_TRAINING_RECORDS:
        raise DatasetTrainingError(
            f"Dataset contains {len(records)} records; "
            f"maximum supported training size is "
            f"{DEFAULT_MAX_TRAINING_RECORDS}."
        )

    try:
        validation = validate_dataset(dataset)
    except Exception as exc:
        raise DatasetTrainingError(f"Dataset validation failed: {exc}") from exc

    if validation is False:
        raise DatasetTrainingError("Dataset validation returned false.")

    try:
        X, y, sample_ids = build_ml_inputs(
            dataset,
            require_labels=True,
        )
    except Exception as exc:
        raise DatasetTrainingError(f"Unable to build ML inputs: {exc}") from exc

    feature_names: List[str] = []

    schema = getattr(dataset, "schema", None)

    if schema is not None:
        candidate = getattr(schema, "feature_names", None)

        if candidate:
            feature_names = [str(item) for item in candidate]

        elif hasattr(schema, "features"):
            schema_features = getattr(schema, "features", None)

            if isinstance(schema_features, Sequence):
                for feature in schema_features:
                    if isinstance(feature, str):
                        feature_names.append(feature)
                    elif hasattr(feature, "name"):
                        feature_names.append(str(feature.name))

    if not feature_names and records:
        feature_container = getattr(records[0], "features", {}) or {}
        feature_names = sorted(str(name) for name in feature_container.keys())

    feature_names = _validate_feature_names(feature_names)

    if not X:
        raise DatasetTrainingError("Dataset produced an empty feature matrix.")

    if len(X) != len(y):
        raise DatasetTrainingError(
            f"Feature/label count mismatch: X={len(X)}, y={len(y)}."
        )

    if len(sample_ids) != len(y):
        raise DatasetTrainingError("Sample-ID/label count mismatch.")

    X_validated = _validate_matrix(
        X,
        feature_count=len(feature_names),
        context="training dataset",
    )

    y_validated = _ensure_binary_labels(
        y,
        context="training dataset",
    )

    return (
        X_validated,
        y_validated,
        [str(item) for item in sample_ids],
        feature_names,
    )


# ---------------------------------------------------------------------------
# Splitting
# ---------------------------------------------------------------------------


def split_training_data(
    dataset: Dataset,
    split_config: SplitConfig = SplitConfig(),
) -> DatasetSplit:
    """
    Create deterministic train/validation/test splits.

    The project's dataset splitter is used so the same splitting semantics
    remain available to downstream evaluation and experimentation.
    """
    split_config.validate()

    try:
        split = split_dataset(
            dataset,
            test_size=split_config.test_size,
            validation_size=split_config.validation_size,
            random_state=split_config.random_state,
            stratify=True,
        )
    except TypeError:
        # Compatibility with alternate dataset.py signatures.
        try:
            split = split_dataset(
                dataset,
                test_size=split_config.test_size,
                validation_size=split_config.validation_size,
                random_state=split_config.random_state,
            )
        except Exception as exc:
            raise DatasetTrainingError(f"Unable to split dataset: {exc}") from exc
    except Exception as exc:
        raise DatasetTrainingError(f"Unable to split dataset: {exc}") from exc

    if split is None:
        raise DatasetTrainingError("Dataset splitter returned no result.")

    return split


def _extract_split_dataset(
    split: DatasetSplit,
    name: str,
) -> Dataset:
    """Retrieve a named dataset from a DatasetSplit defensively."""
    value = getattr(split, name, None)

    if value is None and isinstance(split, Mapping):
        value = split.get(name)

    if value is None:
        raise DatasetTrainingError(f"DatasetSplit does not contain a {name!r} dataset.")

    return value


# ---------------------------------------------------------------------------
# Model construction
# ---------------------------------------------------------------------------


def build_random_forest(
    config: RandomForestConfig = RandomForestConfig(),
) -> Any:
    """Construct an untrained deterministic Random Forest classifier."""
    config.validate()

    ml = _require_sklearn()
    RandomForestClassifier = ml["RandomForestClassifier"]

    return RandomForestClassifier(
        n_estimators=config.n_estimators,
        max_depth=config.max_depth,
        min_samples_split=config.min_samples_split,
        min_samples_leaf=config.min_samples_leaf,
        max_features=config.max_features,
        class_weight=config.class_weight,
        random_state=config.random_state,
        n_jobs=config.n_jobs,
        bootstrap=config.bootstrap,
        criterion=config.criterion,
        max_leaf_nodes=config.max_leaf_nodes,
        max_samples=config.max_samples,
        ccp_alpha=config.ccp_alpha,
    )


def fit_random_forest(
    model: Any,
    X_train: Sequence[Sequence[float]],
    y_train: Sequence[int],
) -> Any:
    """Fit a supplied classifier after validating the training matrices."""
    y = _ensure_binary_labels(y_train, "training split")

    if len(X_train) != len(y):
        raise DatasetTrainingError(
            f"Training feature/label mismatch: X={len(X_train)}, y={len(y)}."
        )

    if not X_train:
        raise DatasetTrainingError("Training split is empty.")

    feature_count = len(X_train[0])

    X = _validate_matrix(
        X_train,
        feature_count=feature_count,
        context="training split",
    )

    try:
        model.fit(X, y)
    except Exception as exc:
        raise TrainingError(f"Random Forest fitting failed: {exc}") from exc

    return model


# ---------------------------------------------------------------------------
# Prediction
# ---------------------------------------------------------------------------


def predict_labels(
    model: Any,
    X: Sequence[Sequence[float]],
    threshold: float = DEFAULT_THRESHOLD,
) -> List[int]:
    """Predict binary labels using a probability threshold."""
    if not 0.0 <= threshold <= 1.0:
        raise ValueError("threshold must be between 0 and 1.")

    rows = [list(row) for row in X]

    if not rows:
        return []

    feature_count = len(rows[0])

    validated = _validate_matrix(
        rows,
        feature_count=feature_count,
        context="prediction matrix",
    )

    if not hasattr(model, "predict_proba"):
        raise TrainingError("The supplied model does not expose predict_proba().")

    try:
        probabilities = model.predict_proba(validated)
    except Exception as exc:
        raise TrainingError(f"Model probability prediction failed: {exc}") from exc

    classes = list(getattr(model, "classes_", []))

    if not classes:
        raise TrainingError("Model does not expose classes_.")

    positive_index: Optional[int] = None

    for index, value in enumerate(classes):
        normalized = _normalize_label_value(value)

        if normalized == 1:
            positive_index = index
            break

    if positive_index is None:
        raise TrainingError(
            f"Unable to identify positive class in model classes: {classes!r}"
        )

    predictions: List[int] = []

    for row in probabilities:
        if positive_index >= len(row):
            raise TrainingError("Model returned malformed probability output.")

        probability = _safe_float(row[positive_index], default=float("nan"))

        if not math.isfinite(probability):
            raise TrainingError("Model returned a non-finite probability.")

        predictions.append(int(probability >= threshold))

    return predictions


def predict_probabilities(
    model: Any,
    X: Sequence[Sequence[float]],
) -> List[float]:
    """Return positive-class probabilities from a trained classifier."""
    rows = [list(row) for row in X]

    if not rows:
        return []

    feature_count = len(rows[0])

    validated = _validate_matrix(
        rows,
        feature_count=feature_count,
        context="probability prediction matrix",
    )

    if not hasattr(model, "predict_proba"):
        raise TrainingError("The supplied model does not expose predict_proba().")

    try:
        probabilities = model.predict_proba(validated)
    except Exception as exc:
        raise TrainingError(f"Model probability prediction failed: {exc}") from exc

    classes = list(getattr(model, "classes_", []))

    positive_index: Optional[int] = None

    for index, value in enumerate(classes):
        if _normalize_label_value(value) == 1:
            positive_index = index
            break

    if positive_index is None:
        raise TrainingError(f"Positive class not found in model classes: {classes!r}")

    result: List[float] = []

    for row in probabilities:
        probability = _safe_float(
            row[positive_index],
            default=float("nan"),
        )

        if not math.isfinite(probability):
            raise TrainingError("Model returned a non-finite probability.")

        result.append(probability)

    return result


# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------


def evaluate_model(
    model: Any,
    X: Sequence[Sequence[float]],
    y: Sequence[int],
    threshold: float = DEFAULT_THRESHOLD,
) -> EvaluationResult:
    """
    Evaluate a classifier using both thresholded predictions and ROC-AUC.

    ROC-AUC is probability-based and therefore independent of the selected
    operational threshold.
    """
    if not 0.0 <= threshold <= 1.0:
        raise ValueError("threshold must be between 0 and 1.")

    labels = _ensure_binary_labels(y, "evaluation split")

    if len(X) != len(labels):
        raise DatasetTrainingError(
            f"Evaluation feature/label mismatch: X={len(X)}, y={len(labels)}."
        )

    if not labels:
        raise DatasetTrainingError("Evaluation split is empty.")

    predictions = predict_labels(
        model,
        X,
        threshold=threshold,
    )

    probabilities = predict_probabilities(model, X)

    ml = _require_sklearn()

    accuracy = float(ml["accuracy_score"](labels, predictions))

    balanced_accuracy = float(ml["balanced_accuracy_score"](labels, predictions))

    precision = float(
        ml["precision_score"](
            labels,
            predictions,
            zero_division=0,
        )
    )

    recall = float(
        ml["recall_score"](
            labels,
            predictions,
            zero_division=0,
        )
    )

    f1 = float(
        ml["f1_score"](
            labels,
            predictions,
            zero_division=0,
        )
    )

    mcc = float(
        ml["matthews_corrcoef"](
            labels,
            predictions,
        )
    )

    try:
        roc_auc = float(
            ml["roc_auc_score"](
                labels,
                probabilities,
            )
        )
    except ValueError:
        roc_auc = None

    matrix = ml["confusion_matrix"](
        labels,
        predictions,
        labels=[0, 1],
    )

    true_negative = int(matrix[0][0])
    false_positive = int(matrix[0][1])
    false_negative = int(matrix[1][0])
    true_positive = int(matrix[1][1])

    report = ml["classification_report"](
        labels,
        predictions,
        labels=[0, 1],
        target_names=["benign", "malicious"],
        output_dict=True,
        zero_division=0,
    )

    return EvaluationResult(
        sample_count=len(labels),
        positive_count=sum(1 for label in labels if label == 1),
        negative_count=sum(1 for label in labels if label == 0),
        threshold=float(threshold),
        accuracy=accuracy,
        balanced_accuracy=balanced_accuracy,
        precision=precision,
        recall=recall,
        f1=f1,
        matthews_corrcoef=mcc,
        roc_auc=roc_auc,
        true_negative=true_negative,
        false_positive=false_positive,
        false_negative=false_negative,
        true_positive=true_positive,
        classification_report=report,
    )


# ---------------------------------------------------------------------------
# Threshold selection
# ---------------------------------------------------------------------------


def _threshold_objective_score(
    objective: str,
    *,
    precision: float,
    recall: float,
    f1: float,
    balanced_accuracy: float,
    youden_j: float,
    matthews_corrcoef: float,
) -> float:
    """Calculate a threshold-selection objective."""
    normalized = objective.strip().lower()

    if normalized == "f1":
        return f1

    if normalized == "balanced_accuracy":
        return balanced_accuracy

    if normalized == "youden_j":
        return youden_j

    if normalized in {"mcc", "matthews_corrcoef"}:
        return matthews_corrcoef

    if normalized == "recall":
        return recall

    if normalized == "precision":
        return precision

    raise ValueError(f"Unsupported threshold objective: {objective!r}")


def optimize_threshold(
    y_true: Sequence[int],
    probabilities: Sequence[float],
    objective: str = "f1",
    minimum_recall: Optional[float] = None,
    minimum_precision: Optional[float] = None,
    minimum_threshold: float = DEFAULT_THRESHOLD_MIN,
    maximum_threshold: float = DEFAULT_THRESHOLD_MAX,
    threshold_step: float = DEFAULT_THRESHOLD_STEP,
) -> ThresholdResult:
    """
    Select an operational probability threshold using validation data.

    By default F1 is optimized. Optional minimum precision/recall constraints
    can prevent selection of a threshold that is numerically optimal but
    operationally unsuitable.
    """
    labels = _ensure_binary_labels(y_true, "threshold optimization")

    if len(labels) != len(probabilities):
        raise DatasetTrainingError("Threshold optimization feature/label mismatch.")

    if not 0.0 <= minimum_threshold <= 1.0:
        raise ValueError("minimum_threshold must be between 0 and 1.")

    if not 0.0 <= maximum_threshold <= 1.0:
        raise ValueError("maximum_threshold must be between 0 and 1.")

    if minimum_threshold > maximum_threshold:
        raise ValueError("minimum_threshold cannot exceed maximum_threshold.")

    if threshold_step <= 0:
        raise ValueError("threshold_step must be positive.")

    if minimum_recall is not None and not 0.0 <= minimum_recall <= 1.0:
        raise ValueError("minimum_recall must be between 0 and 1.")

    if minimum_precision is not None and not 0.0 <= minimum_precision <= 1.0:
        raise ValueError("minimum_precision must be between 0 and 1.")

    probs: List[float] = []

    for value in probabilities:
        probability = _safe_float(value, default=float("nan"))

        if not math.isfinite(probability):
            raise DatasetTrainingError(
                "Threshold optimization received a non-finite probability."
            )

        if not 0.0 <= probability <= 1.0:
            raise DatasetTrainingError(f"Probability outside [0, 1]: {probability}")

        probs.append(probability)

    ml = _require_sklearn()

    best: Optional[Tuple[float, float, Dict[str, Any]]] = None

    threshold_count = int(
        math.floor((maximum_threshold - minimum_threshold) / threshold_step)
    )

    thresholds = [
        minimum_threshold + index * threshold_step
        for index in range(threshold_count + 1)
    ]

    if not thresholds or thresholds[-1] < maximum_threshold - 1e-12:
        thresholds.append(maximum_threshold)

    for threshold in thresholds:
        predictions = [int(probability >= threshold) for probability in probs]

        precision = float(
            ml["precision_score"](
                labels,
                predictions,
                zero_division=0,
            )
        )

        recall = float(
            ml["recall_score"](
                labels,
                predictions,
                zero_division=0,
            )
        )

        f1 = float(
            ml["f1_score"](
                labels,
                predictions,
                zero_division=0,
            )
        )

        balanced_accuracy = float(
            ml["balanced_accuracy_score"](
                labels,
                predictions,
            )
        )

        mcc = float(
            ml["matthews_corrcoef"](
                labels,
                predictions,
            )
        )

        matrix = ml["confusion_matrix"](
            labels,
            predictions,
            labels=[0, 1],
        )

        tn = int(matrix[0][0])
        fp = int(matrix[0][1])
        fn = int(matrix[1][0])
        tp = int(matrix[1][1])

        sensitivity = tp / (tp + fn) if tp + fn else 0.0

        specificity = tn / (tn + fp) if tn + fp else 0.0

        youden_j = sensitivity + specificity - 1.0

        if minimum_recall is not None and recall < minimum_recall:
            continue

        if minimum_precision is not None and precision < minimum_precision:
            continue

        score = _threshold_objective_score(
            objective,
            precision=precision,
            recall=recall,
            f1=f1,
            balanced_accuracy=balanced_accuracy,
            youden_j=youden_j,
            matthews_corrcoef=mcc,
        )

        # Deterministic tie-breaking:
        # 1. highest objective
        # 2. higher recall
        # 3. higher precision
        # 4. threshold closest to 0.50
        ranking = (
            score,
            recall,
            precision,
            -abs(threshold - DEFAULT_THRESHOLD),
        )

        if best is None or ranking > best[0]:
            best = (
                ranking,
                threshold,
                {
                    "precision": precision,
                    "recall": recall,
                    "f1": f1,
                    "balanced_accuracy": balanced_accuracy,
                    "youden_j": youden_j,
                    "matthews_corrcoef": mcc,
                    "positive_predictions": sum(predictions),
                    "negative_predictions": len(predictions) - sum(predictions),
                },
            )

    if best is None:
        # If constraints eliminated every threshold, fall back to the default
        # threshold rather than silently producing an unusable model.
        fallback = evaluate_threshold(
            labels,
            probs,
            threshold=DEFAULT_THRESHOLD,
        )

        return ThresholdResult(
            default_threshold=DEFAULT_THRESHOLD,
            selected_threshold=DEFAULT_THRESHOLD,
            objective=objective,
            objective_score=float(fallback[_objective_result_key(objective)]),
            precision=float(fallback["precision"]),
            recall=float(fallback["recall"]),
            f1=float(fallback["f1"]),
            balanced_accuracy=float(fallback["balanced_accuracy"]),
            youden_j=float(fallback["youden_j"]),
            matthews_corrcoef=float(fallback["matthews_corrcoef"]),
            positive_predictions=int(fallback["positive_predictions"]),
            negative_predictions=int(fallback["negative_predictions"]),
        )

    _, selected_threshold, values = best

    return ThresholdResult(
        default_threshold=DEFAULT_THRESHOLD,
        selected_threshold=float(selected_threshold),
        objective=objective,
        objective_score=float(
            _threshold_objective_score(
                objective,
                precision=values["precision"],
                recall=values["recall"],
                f1=values["f1"],
                balanced_accuracy=values["balanced_accuracy"],
                youden_j=values["youden_j"],
                matthews_corrcoef=values["matthews_corrcoef"],
            )
        ),
        precision=float(values["precision"]),
        recall=float(values["recall"]),
        f1=float(values["f1"]),
        balanced_accuracy=float(values["balanced_accuracy"]),
        youden_j=float(values["youden_j"]),
        matthews_corrcoef=float(values["matthews_corrcoef"]),
        positive_predictions=int(values["positive_predictions"]),
        negative_predictions=int(values["negative_predictions"]),
    )


def _objective_result_key(objective: str) -> str:
    """Map objective names to evaluate_threshold dictionary keys."""
    normalized = objective.strip().lower()

    mapping = {
        "f1": "f1",
        "balanced_accuracy": "balanced_accuracy",
        "youden_j": "youden_j",
        "mcc": "matthews_corrcoef",
        "matthews_corrcoef": "matthews_corrcoef",
        "recall": "recall",
        "precision": "precision",
    }

    try:
        return mapping[normalized]
    except KeyError as exc:
        raise ValueError(f"Unsupported threshold objective: {objective!r}") from exc


def evaluate_threshold(
    y_true: Sequence[int],
    probabilities: Sequence[float],
    threshold: float = DEFAULT_THRESHOLD,
) -> Dict[str, Any]:
    """Evaluate a threshold directly against known probabilities."""
    labels = _ensure_binary_labels(y_true, "threshold evaluation")

    if len(labels) != len(probabilities):
        raise DatasetTrainingError("Threshold evaluation feature/label mismatch.")

    if not 0.0 <= threshold <= 1.0:
        raise ValueError("threshold must be between 0 and 1.")

    probs = [_safe_float(value, default=float("nan")) for value in probabilities]

    if any(not math.isfinite(value) for value in probs):
        raise DatasetTrainingError(
            "Threshold evaluation received non-finite probabilities."
        )

    predictions = [int(probability >= threshold) for probability in probs]

    ml = _require_sklearn()

    precision = float(
        ml["precision_score"](
            labels,
            predictions,
            zero_division=0,
        )
    )

    recall = float(
        ml["recall_score"](
            labels,
            predictions,
            zero_division=0,
        )
    )

    f1 = float(
        ml["f1_score"](
            labels,
            predictions,
            zero_division=0,
        )
    )

    balanced_accuracy = float(
        ml["balanced_accuracy_score"](
            labels,
            predictions,
        )
    )

    mcc = float(
        ml["matthews_corrcoef"](
            labels,
            predictions,
        )
    )

    matrix = ml["confusion_matrix"](
        labels,
        predictions,
        labels=[0, 1],
    )

    tn = int(matrix[0][0])
    fp = int(matrix[0][1])
    fn = int(matrix[1][0])
    tp = int(matrix[1][1])

    sensitivity = tp / (tp + fn) if tp + fn else 0.0

    specificity = tn / (tn + fp) if tn + fp else 0.0

    youden_j = sensitivity + specificity - 1.0

    try:
        roc_auc = float(
            ml["roc_auc_score"](
                labels,
                probs,
            )
        )
    except ValueError:
        roc_auc = None

    return {
        "threshold": float(threshold),
        "accuracy": float(
            ml["accuracy_score"](
                labels,
                predictions,
            )
        ),
        "balanced_accuracy": balanced_accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "matthews_corrcoef": mcc,
        "youden_j": float(youden_j),
        "roc_auc": roc_auc,
        "true_negative": tn,
        "false_positive": fp,
        "false_negative": fn,
        "true_positive": tp,
        "positive_predictions": sum(predictions),
        "negative_predictions": len(predictions) - sum(predictions),
    }


# ---------------------------------------------------------------------------
# Feature importance
# ---------------------------------------------------------------------------


def extract_feature_importance(
    model: Any,
    feature_names: Sequence[str],
    top_n: Optional[int] = None,
) -> List[FeatureImportance]:
    """Extract deterministic Random Forest feature importances."""
    names = _validate_feature_names(feature_names)

    importances = getattr(model, "feature_importances_", None)

    if importances is None:
        raise TrainingError("Trained model does not expose feature_importances_.")

    if len(importances) != len(names):
        raise TrainingError(
            "Feature importance count does not match feature-name count."
        )

    records = [
        FeatureImportance(
            feature=name,
            importance=_safe_float(value),
            rank=0,
        )
        for name, value in zip(names, importances)
    ]

    records.sort(
        key=lambda item: (
            -item.importance,
            item.feature,
        )
    )

    for rank, record in enumerate(records, start=1):
        record.rank = rank

    if top_n is not None:
        if top_n < 1:
            raise ValueError("top_n must be >= 1 or None.")
        records = records[:top_n]

    return records


# ---------------------------------------------------------------------------
# Model metadata
# ---------------------------------------------------------------------------


def _dataset_record_count(dataset: Dataset) -> int:
    """Return the number of records in a dataset."""
    return len(list(getattr(dataset, "records", []) or []))


def _safe_dataset_statistics(dataset: Dataset) -> Dict[str, Any]:
    """Serialize dataset statistics without allowing statistics failure to abort training."""
    try:
        statistics = dataset_statistics(dataset)

        if hasattr(statistics, "to_dict"):
            value = statistics.to_dict()
        elif hasattr(statistics, "__dict__"):
            value = dict(statistics.__dict__)
        elif isinstance(statistics, Mapping):
            value = dict(statistics)
        else:
            value = {"value": str(statistics)}

        return value
    except Exception as exc:
        return {
            "error": str(exc),
            "record_count": _dataset_record_count(dataset),
        }


def build_model_metadata(
    *,
    dataset: Dataset,
    result: TrainingResult,
    input_path: Optional[str] = None,
) -> Dict[str, Any]:
    """Build a JSON-serializable model metadata document."""
    model = result.model

    model_parameters: Dict[str, Any] = {}

    if hasattr(model, "get_params"):
        try:
            model_parameters = dict(model.get_params())
        except Exception:
            model_parameters = {}

    metadata: Dict[str, Any] = {
        "artifact": {
            "model_type": MODEL_TYPE,
            "model_format": MODEL_FORMAT,
            "model_version": MODEL_VERSION,
            "created_at": result.trained_at,
            "model_path": result.model_path,
        },
        "project": {
            "name": "pharos-cdr",
            "purpose": "defensive static document malware classification",
            "execution_of_samples": False,
            "network_access": False,
        },
        "dataset": {
            "fingerprint": result.dataset_fingerprint,
            "schema_fingerprint": result.schema_fingerprint,
            "record_count": _dataset_record_count(dataset),
            "input_path": input_path,
            "statistics": _safe_dataset_statistics(dataset),
        },
        "features": {
            "count": result.feature_count,
            "names": list(result.feature_names),
        },
        "training": {
            "config": asdict(result.config),
            "split_config": asdict(result.split_config),
            "duration_seconds": result.duration_seconds,
            "train_count": result.train_count,
            "validation_count": result.validation_count,
            "test_count": result.test_count,
            "class_distribution": {
                "train": result.train_class_distribution,
                "validation": result.validation_class_distribution,
                "test": result.test_class_distribution,
            },
            "model_parameters": model_parameters,
        },
        "validation": result.validation.to_dict(),
        "test": result.test.to_dict(),
        "threshold": asdict(result.threshold),
        "feature_importance": [item.to_dict() for item in result.feature_importance],
        "runtime": {
            "python": platform.python_version(),
            "platform": platform.platform(),
            "implementation": platform.python_implementation(),
        },
    }

    metadata["metadata_fingerprint"] = _sha256_json(metadata)

    return metadata


def build_threshold_metadata(
    threshold: ThresholdResult,
    *,
    dataset_fingerprint_value: str,
    schema_fingerprint_value: str,
) -> Dict[str, Any]:
    """Build the persisted operational-threshold document."""
    payload = {
        "version": "1.0",
        "created_at": _utc_now(),
        "dataset_fingerprint": dataset_fingerprint_value,
        "schema_fingerprint": schema_fingerprint_value,
        "classification": {
            "positive_class": 1,
            "negative_class": 0,
            "default_threshold": threshold.default_threshold,
            "selected_threshold": threshold.selected_threshold,
        },
        "optimization": {
            "objective": threshold.objective,
            "objective_score": threshold.objective_score,
            "precision": threshold.precision,
            "recall": threshold.recall,
            "f1": threshold.f1,
            "balanced_accuracy": threshold.balanced_accuracy,
            "youden_j": threshold.youden_j,
            "matthews_corrcoef": threshold.matthews_corrcoef,
            "positive_predictions": threshold.positive_predictions,
            "negative_predictions": threshold.negative_predictions,
        },
        "usage": {
            "interpretation": (
                "Probability at or above selected_threshold is classified "
                "as malicious/suspicious."
            ),
            "static_only": True,
            "samples_executed": False,
        },
    }

    payload["thresholds_fingerprint"] = _sha256_json(payload)

    return payload


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------


def save_model(
    model: Any,
    path: os.PathLike[str] | str = DEFAULT_MODEL_PATH,
) -> Path:
    """
    Persist a trained model using joblib.

    Only the trusted in-memory classifier object produced by this training
    module should be supplied. This function does not load arbitrary objects.
    """
    target = Path(path)

    target.parent.mkdir(parents=True, exist_ok=True)

    temporary = target.with_name(f".{target.name}.{os.getpid()}.tmp")

    joblib = _require_joblib()

    try:
        joblib.dump(
            model,
            temporary,
            compress=3,
        )
        os.replace(temporary, target)
    except Exception as exc:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass

        raise ModelPersistenceError(
            f"Unable to persist trained model to {target}"
        ) from exc

    return target


def save_training_artifacts(
    result: TrainingResult,
    dataset: Dataset,
    *,
    model_path: os.PathLike[str] | str = DEFAULT_MODEL_PATH,
    schema_path: os.PathLike[str] | str = DEFAULT_SCHEMA_PATH,
    metadata_path: os.PathLike[str] | str = DEFAULT_METADATA_PATH,
    thresholds_path: os.PathLike[str] | str = DEFAULT_THRESHOLDS_PATH,
    input_path: Optional[str] = None,
) -> Dict[str, Path]:
    """
    Persist the model, feature schema, metadata, and threshold configuration.
    """
    model_target = save_model(
        result.model,
        model_path,
    )

    result.model_path = str(model_target)

    schema_target = Path(schema_path)
    metadata_target = Path(metadata_path)
    thresholds_target = Path(thresholds_path)

    schema = getattr(dataset, "schema", None)

    if schema is None:
        raise ModelPersistenceError("Dataset does not expose a feature schema.")

    try:
        save_schema(schema, schema_target)
    except Exception as exc:
        raise ModelPersistenceError(
            f"Unable to persist feature schema to {schema_target}"
        ) from exc

    metadata = build_model_metadata(
        dataset=dataset,
        result=result,
        input_path=input_path,
    )

    threshold_metadata = build_threshold_metadata(
        result.threshold,
        dataset_fingerprint_value=result.dataset_fingerprint,
        schema_fingerprint_value=result.schema_fingerprint,
    )

    _safe_json_dump(
        metadata_target,
        metadata,
    )

    _safe_json_dump(
        thresholds_target,
        threshold_metadata,
    )

    return {
        "model": model_target,
        "schema": schema_target,
        "metadata": metadata_target,
        "thresholds": thresholds_target,
    }


def load_trained_model(
    path: os.PathLike[str] | str = DEFAULT_MODEL_PATH,
) -> Any:
    """
    Load a previously trained model.

    This operation should only be used with trusted model artifacts generated
    by this project because joblib deserialization can execute Python-level
    object reconstruction.
    """
    target = Path(path)

    if not target.is_file():
        raise ModelPersistenceError(f"Model artifact does not exist: {target}")

    joblib = _require_joblib()

    try:
        model = joblib.load(target)
    except Exception as exc:
        raise ModelPersistenceError(f"Unable to load model artifact: {target}") from exc

    if not hasattr(model, "predict_proba"):
        raise ModelPersistenceError(
            "Loaded artifact is not a probability-capable classifier."
        )

    return model


# ---------------------------------------------------------------------------
# Full training pipeline
# ---------------------------------------------------------------------------


def train_model(
    dataset: Dataset,
    *,
    model_config: RandomForestConfig = RandomForestConfig(),
    split_config: SplitConfig = SplitConfig(),
    threshold_objective: str = "f1",
    minimum_recall: Optional[float] = None,
    minimum_precision: Optional[float] = None,
    model_path: Optional[os.PathLike[str] | str] = DEFAULT_MODEL_PATH,
    schema_path: Optional[os.PathLike[str] | str] = DEFAULT_SCHEMA_PATH,
    metadata_path: Optional[os.PathLike[str] | str] = DEFAULT_METADATA_PATH,
    thresholds_path: Optional[os.PathLike[str] | str] = DEFAULT_THRESHOLDS_PATH,
    input_path: Optional[str] = None,
    persist: bool = True,
) -> TrainingResult:
    """
    Execute the complete deterministic Random Forest training pipeline.

    Pipeline
    --------
    1. Validate the complete dataset.
    2. Build a stable feature matrix.
    3. Split into train/validation/test partitions.
    4. Fit Random Forest on the training partition.
    5. Optimize the classification threshold on validation data.
    6. Evaluate validation and test partitions.
    7. Extract feature importances.
    8. Optionally persist model/schema/metadata/thresholds.

    The test set is never used for threshold optimization.
    """
    started = time.monotonic()

    model_config.validate()
    split_config.validate()

    X, y, sample_ids, feature_names = prepare_training_data(dataset)

    # Validate sample IDs are present and unique.
    if len(set(sample_ids)) != len(sample_ids):
        raise DatasetTrainingError("Duplicate sample IDs detected before training.")

    # Use the project's splitter at the dataset level so all metadata and
    # records remain attached to their corresponding partitions.
    split = split_training_data(
        dataset,
        split_config=split_config,
    )

    train_dataset = _extract_split_dataset(split, "train")
    validation_dataset = _extract_split_dataset(split, "validation")
    test_dataset = _extract_split_dataset(split, "test")

    X_train, y_train, _, train_features = prepare_training_data(train_dataset)
    X_validation, y_validation, _, validation_features = prepare_training_data(
        validation_dataset
    )
    X_test, y_test, _, test_features = prepare_training_data(test_dataset)

    # Every split must use exactly the same feature schema.
    if train_features != feature_names:
        raise DatasetTrainingError(
            "Training split feature schema differs from the full dataset."
        )

    if validation_features != feature_names:
        raise DatasetTrainingError(
            "Validation split feature schema differs from the full dataset."
        )

    if test_features != feature_names:
        raise DatasetTrainingError(
            "Test split feature schema differs from the full dataset."
        )

    model = build_random_forest(model_config)

    fit_random_forest(
        model,
        X_train,
        y_train,
    )

    validation_probabilities = predict_probabilities(
        model,
        X_validation,
    )

    threshold = optimize_threshold(
        y_validation,
        validation_probabilities,
        objective=threshold_objective,
        minimum_recall=minimum_recall,
        minimum_precision=minimum_precision,
    )

    validation_result = evaluate_model(
        model,
        X_validation,
        y_validation,
        threshold=threshold.selected_threshold,
    )

    test_result = evaluate_model(
        model,
        X_test,
        y_test,
        threshold=threshold.selected_threshold,
    )

    feature_importance = extract_feature_importance(
        model,
        feature_names,
    )

    elapsed = time.monotonic() - started
    trained_at = _utc_now()

    try:
        data_fingerprint = dataset_fingerprint(dataset)
    except Exception:
        data_fingerprint = _sha256_json(
            {
                "sample_ids": sample_ids,
                "feature_names": feature_names,
                "labels": y,
            }
        )

    schema_fingerprint = _dataset_schema_fingerprint(dataset)

    result = TrainingResult(
        model=model,
        model_path=str(model_path) if model_path is not None else None,
        feature_names=feature_names,
        feature_count=len(feature_names),
        dataset_fingerprint=str(data_fingerprint),
        schema_fingerprint=str(schema_fingerprint),
        train_count=len(y_train),
        validation_count=len(y_validation),
        test_count=len(y_test),
        train_class_distribution=_class_distribution(y_train),
        validation_class_distribution=_class_distribution(y_validation),
        test_class_distribution=_class_distribution(y_test),
        validation=validation_result,
        test=test_result,
        threshold=threshold,
        feature_importance=feature_importance,
        config=model_config,
        split_config=split_config,
        trained_at=trained_at,
        duration_seconds=float(elapsed),
    )

    result.metadata = {
        "sample_ids_used_for_training": len(y_train),
        "positive_training_samples": sum(1 for label in y_train if label == 1),
        "negative_training_samples": sum(1 for label in y_train if label == 0),
        "validation_threshold_objective": threshold_objective,
        "minimum_recall": minimum_recall,
        "minimum_precision": minimum_precision,
    }

    if persist:
        if (
            model_path is None
            or schema_path is None
            or metadata_path is None
            or thresholds_path is None
        ):
            raise ModelPersistenceError(
                "All artifact paths must be supplied when persist=True."
            )

        save_training_artifacts(
            result,
            dataset,
            model_path=model_path,
            schema_path=schema_path,
            metadata_path=metadata_path,
            thresholds_path=thresholds_path,
            input_path=input_path,
        )

    return result


# ---------------------------------------------------------------------------
# Dataset-file convenience API
# ---------------------------------------------------------------------------


def train_from_dataset_path(
    dataset_path: os.PathLike[str] | str,
    *,
    model_config: RandomForestConfig = RandomForestConfig(),
    split_config: SplitConfig = SplitConfig(),
    threshold_objective: str = "f1",
    minimum_recall: Optional[float] = None,
    minimum_precision: Optional[float] = None,
    model_path: os.PathLike[str] | str = DEFAULT_MODEL_PATH,
    schema_path: os.PathLike[str] | str = DEFAULT_SCHEMA_PATH,
    metadata_path: os.PathLike[str] | str = DEFAULT_METADATA_PATH,
    thresholds_path: os.PathLike[str] | str = DEFAULT_THRESHOLDS_PATH,
) -> TrainingResult:
    """Load a dataset from disk and train the classifier."""
    source = Path(dataset_path)

    if not source.is_file():
        raise DatasetTrainingError(f"Dataset file does not exist: {source}")

    try:
        dataset = load_dataset(source)
    except Exception as exc:
        raise DatasetTrainingError(
            f"Unable to load dataset from {source}: {exc}"
        ) from exc

    return train_model(
        dataset,
        model_config=model_config,
        split_config=split_config,
        threshold_objective=threshold_objective,
        minimum_recall=minimum_recall,
        minimum_precision=minimum_precision,
        model_path=model_path,
        schema_path=schema_path,
        metadata_path=metadata_path,
        thresholds_path=thresholds_path,
        input_path=str(source),
        persist=True,
    )


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------


def summarize_training(result: TrainingResult) -> Dict[str, Any]:
    """Return a compact JSON-serializable training summary."""
    return {
        "model_type": MODEL_TYPE,
        "model_path": result.model_path,
        "feature_count": result.feature_count,
        "dataset_fingerprint": result.dataset_fingerprint,
        "schema_fingerprint": result.schema_fingerprint,
        "samples": {
            "train": result.train_count,
            "validation": result.validation_count,
            "test": result.test_count,
        },
        "classes": {
            "train": result.train_class_distribution,
            "validation": result.validation_class_distribution,
            "test": result.test_class_distribution,
        },
        "threshold": {
            "selected": result.threshold.selected_threshold,
            "objective": result.threshold.objective,
            "objective_score": result.threshold.objective_score,
        },
        "validation": {
            "accuracy": result.validation.accuracy,
            "balanced_accuracy": result.validation.balanced_accuracy,
            "precision": result.validation.precision,
            "recall": result.validation.recall,
            "f1": result.validation.f1,
            "mcc": result.validation.matthews_corrcoef,
            "roc_auc": result.validation.roc_auc,
        },
        "test": {
            "accuracy": result.test.accuracy,
            "balanced_accuracy": result.test.balanced_accuracy,
            "precision": result.test.precision,
            "recall": result.test.recall,
            "f1": result.test.f1,
            "mcc": result.test.matthews_corrcoef,
            "roc_auc": result.test.roc_auc,
        },
        "duration_seconds": result.duration_seconds,
    }


def top_features(
    result: TrainingResult,
    n: int = 20,
) -> List[FeatureImportance]:
    """Return the top N features by Random Forest importance."""
    if n < 1:
        raise ValueError("n must be >= 1.")

    return list(result.feature_importance[:n])


# ---------------------------------------------------------------------------
# Command-line interface
# ---------------------------------------------------------------------------


def build_argument_parser() -> argparse.ArgumentParser:
    """Construct the command-line interface parser."""
    parser = argparse.ArgumentParser(
        description=(
            "Train the Pharos CDR Random Forest classifier from a " "feature dataset."
        )
    )

    parser.add_argument(
        "dataset",
        type=Path,
        help="Path to the input CSV or JSONL dataset.",
    )

    parser.add_argument(
        "--model",
        type=Path,
        default=DEFAULT_MODEL_PATH,
        help=f"Output model path (default: {DEFAULT_MODEL_PATH}).",
    )

    parser.add_argument(
        "--schema",
        type=Path,
        default=DEFAULT_SCHEMA_PATH,
        help=f"Output schema path (default: {DEFAULT_SCHEMA_PATH}).",
    )

    parser.add_argument(
        "--metadata",
        type=Path,
        default=DEFAULT_METADATA_PATH,
        help=f"Output metadata path (default: {DEFAULT_METADATA_PATH}).",
    )

    parser.add_argument(
        "--thresholds",
        type=Path,
        default=DEFAULT_THRESHOLDS_PATH,
        help=(
            "Output threshold configuration path "
            f"(default: {DEFAULT_THRESHOLDS_PATH})."
        ),
    )

    parser.add_argument(
        "--estimators",
        type=int,
        default=DEFAULT_N_ESTIMATORS,
        help=f"Number of trees (default: {DEFAULT_N_ESTIMATORS}).",
    )

    parser.add_argument(
        "--max-depth",
        type=int,
        default=None,
        help="Maximum tree depth (default: unlimited).",
    )

    parser.add_argument(
        "--min-samples-split",
        type=int,
        default=DEFAULT_MIN_SAMPLES_SPLIT,
        help=(
            "Minimum samples required to split a node "
            f"(default: {DEFAULT_MIN_SAMPLES_SPLIT})."
        ),
    )

    parser.add_argument(
        "--min-samples-leaf",
        type=int,
        default=DEFAULT_MIN_SAMPLES_LEAF,
        help=(
            "Minimum samples required at a leaf "
            f"(default: {DEFAULT_MIN_SAMPLES_LEAF})."
        ),
    )

    parser.add_argument(
        "--max-features",
        default=DEFAULT_MAX_FEATURES,
        help=(
            "Number/fraction of features considered at each split. "
            "Use 'sqrt', 'log2', 'none', or a numeric value."
        ),
    )

    parser.add_argument(
        "--random-state",
        type=int,
        default=DEFAULT_RANDOM_STATE,
        help=f"Random seed (default: {DEFAULT_RANDOM_STATE}).",
    )

    parser.add_argument(
        "--n-jobs",
        type=int,
        default=DEFAULT_N_JOBS,
        help=(
            "Parallel worker count. -1 uses all CPUs " f"(default: {DEFAULT_N_JOBS})."
        ),
    )

    parser.add_argument(
        "--test-size",
        type=float,
        default=DEFAULT_TEST_SIZE,
        help=f"Test fraction (default: {DEFAULT_TEST_SIZE}).",
    )

    parser.add_argument(
        "--validation-size",
        type=float,
        default=DEFAULT_VALIDATION_SIZE,
        help=("Validation fraction (default: " f"{DEFAULT_VALIDATION_SIZE})."),
    )

    parser.add_argument(
        "--threshold-objective",
        choices=(
            "f1",
            "balanced_accuracy",
            "youden_j",
            "mcc",
            "recall",
            "precision",
        ),
        default="f1",
        help="Validation threshold optimization objective.",
    )

    parser.add_argument(
        "--minimum-recall",
        type=float,
        default=None,
        help="Optional minimum validation recall constraint.",
    )

    parser.add_argument(
        "--minimum-precision",
        type=float,
        default=None,
        help="Optional minimum validation precision constraint.",
    )

    parser.add_argument(
        "--top-features",
        type=int,
        default=20,
        help="Number of top feature importances to display.",
    )

    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    """CLI entry point."""
    parser = build_argument_parser()
    args = parser.parse_args(argv)

    max_features: Any = args.max_features

    if isinstance(max_features, str):
        normalized = max_features.strip().lower()

        if normalized == "none":
            max_features = 1.0
        elif normalized in {"sqrt", "log2"}:
            max_features = normalized
        else:
            try:
                numeric = float(normalized)

                if numeric <= 0:
                    raise ValueError

                if numeric.is_integer():
                    max_features = int(numeric)
                else:
                    max_features = numeric
            except ValueError:
                parser.error(
                    "--max-features must be sqrt, log2, none, "
                    "or a positive numeric value."
                )

    model_config = RandomForestConfig(
        n_estimators=args.estimators,
        max_depth=args.max_depth,
        min_samples_split=args.min_samples_split,
        min_samples_leaf=args.min_samples_leaf,
        max_features=max_features,
        random_state=args.random_state,
        n_jobs=args.n_jobs,
    )

    split_config = SplitConfig(
        test_size=args.test_size,
        validation_size=args.validation_size,
        random_state=args.random_state,
    )

    try:
        result = train_from_dataset_path(
            args.dataset,
            model_config=model_config,
            split_config=split_config,
            threshold_objective=args.threshold_objective,
            minimum_recall=args.minimum_recall,
            minimum_precision=args.minimum_precision,
            model_path=args.model,
            schema_path=args.schema,
            metadata_path=args.metadata,
            thresholds_path=args.thresholds,
        )
    except (TrainingError, ValueError) as exc:
        print(
            f"Training failed: {exc}",
            file=sys.stderr,
        )
        return 2

    summary = summarize_training(result)

    print(
        json.dumps(
            summary,
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
        )
    )

    if args.top_features > 0:
        print("\nTop features:")

        for feature in top_features(
            result,
            args.top_features,
        ):
            print(
                f"{feature.rank:4d}  "
                f"{feature.importance:.8f}  "
                f"{feature.feature}"
            )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())


# ---------------------------------------------------------------------------
# PUBLIC APIs
# ---------------------------------------------------------------------------

__all__ = [
    "TrainingError",
    "DependencyError",
    "DatasetTrainingError",
    "ModelPersistenceError",
    "RandomForestConfig",
    "SplitConfig",
    "ThresholdResult",
    "EvaluationResult",
    "FeatureImportance",
    "TrainingResult",
    "prepare_training_data",
    "split_training_data",
    "build_random_forest",
    "fit_random_forest",
    "train_model",
    "train_from_dataset_path",
    "predict_labels",
    "predict_probabilities",
    "load_trained_model",
    "evaluate_model",
    "evaluate_threshold",
    "optimize_threshold",
    "extract_feature_importance",
    "top_features",
    "save_model",
    "save_training_artifacts",
    "build_model_metadata",
    "build_threshold_metadata",
    "summarize_training",
    "build_argument_parser",
    "main",
]
