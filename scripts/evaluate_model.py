#!/usr/bin/env python3
"""
pharos-cdr/scripts/evaluate_model.py
====================================

Evaluate a trained Pharos CDR malware-classification model.

This script is the command-line entry point for:

    src.ml.evaluation

It supports:

    - loading a prepared dataset
    - loading the trusted trained model artifacts
    - deterministic evaluation
    - threshold analysis
    - classification metrics
    - ROC-AUC / average precision
    - confusion matrix
    - error analysis
    - deterministic stratified cross-validation
    - JSON / CSV result persistence
    - compatibility with src.ml.predict artifacts

The script performs static dataset/model evaluation only. It never:

    - executes documents
    - executes VBA/XLM macros
    - executes scripts
    - launches processes
    - contacts URLs
    - downloads payloads
    - executes payloads
    - performs dynamic malware analysis

Security note
-------------

The model artifact is loaded through joblib/pickle-compatible
deserialization. Only load model artifacts produced by a trusted
training environment.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import logging
import math
import os
import sys
import tempfile
import time
from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Optional, Sequence

# ---------------------------------------------------------------------------
# Project bootstrap
# ---------------------------------------------------------------------------

SCRIPT_PATH = Path(__file__).resolve()
PROJECT_ROOT = SCRIPT_PATH.parent.parent

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


# ---------------------------------------------------------------------------
# Project imports
# ---------------------------------------------------------------------------

from scripts.train_model import LOGGER
from scripts.train_model import LOGGER
from src.ml.dataset import (  # noqa: E402
    Dataset,
    dataset_fingerprint,
    load_dataset,
    load_schema,
    validate_dataset,
)

from src.ml import evaluation as evaluation_module  # noqa: E402
from src.ml import predict as predict_module  # noqa: E402

# ---------------------------------------------------------------------------
# Optional dependencies
# ---------------------------------------------------------------------------

try:
    import joblib  # type: ignore
except ImportError:
    joblib = None

try:
    import numpy as np  # type: ignore
except ImportError:
    np = None


# ---------------------------------------------------------------------------
# Metadata
# ---------------------------------------------------------------------------

MODULE_NAME = "pharos_cdr.scripts.evaluate_model"
EVALUATOR_VERSION = "1.0.0"

DEFAULT_DATASET_PATH = PROJECT_ROOT / "data" / "processed" / "dataset.jsonl"

DEFAULT_MODEL_PATH = PROJECT_ROOT / "models" / "trained" / "random_forest.joblib"

DEFAULT_SCHEMA_PATH = PROJECT_ROOT / "models" / "metadata" / "feature_schema.json"

DEFAULT_METADATA_PATH = PROJECT_ROOT / "models" / "metadata" / "model_metadata.json"

DEFAULT_THRESHOLDS_PATH = PROJECT_ROOT / "models" / "metadata" / "thresholds.json"

DEFAULT_OUTPUT_PATH = PROJECT_ROOT / "outputs" / "reports" / "model_evaluation.json"

DEFAULT_CSV_OUTPUT_PATH = PROJECT_ROOT / "outputs" / "reports" / "model_evaluation.csv"

DEFAULT_THRESHOLD = 0.50
DEFAULT_RANDOM_STATE = 42

DEFAULT_CV_FOLDS = 5
DEFAULT_MAX_CV_FOLDS = 10

MAX_EVALUATION_SAMPLES = 5_000_000
MAX_FEATURES = 100_000
MAX_THRESHOLDS = 201

POSITIVE_LABEL = 1
NEGATIVE_LABEL = 0


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class EvaluationScriptError(RuntimeError):
    """Base evaluation-script exception."""


class EvaluationDependencyError(EvaluationScriptError):
    """Required dependency is unavailable."""


class EvaluationDataError(EvaluationScriptError):
    """Dataset/model evaluation data is invalid."""


class EvaluationArtifactError(EvaluationScriptError):
    """Model/schema/metadata artifact is unavailable or invalid."""


class EvaluationConfigurationError(EvaluationScriptError):
    """Evaluation configuration is invalid."""


# ---------------------------------------------------------------------------
# Utility functions
# ---------------------------------------------------------------------------


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def safe_float(
    value: Any,
    default: float = 0.0,
) -> float:
    try:
        number = float(value)
    except (
        TypeError,
        ValueError,
    ):
        return default

    if not math.isfinite(number):
        return default

    return number


def safe_int(
    value: Any,
    default: int = 0,
) -> int:
    try:
        return int(value)
    except (
        TypeError,
        ValueError,
    ):
        return default


def json_safe(
    value: Any,
    *,
    depth: int = 0,
    max_depth: int = 12,
) -> Any:
    if depth > max_depth:
        return "<max-depth>"

    if value is None:
        return None

    if isinstance(
        value,
        (
            str,
            int,
            bool,
        ),
    ):
        return value

    if isinstance(
        value,
        float,
    ):
        return value if math.isfinite(value) else None

    if isinstance(
        value,
        Path,
    ):
        return str(value)

    if is_dataclass(value):
        return json_safe(
            asdict(value),
            depth=depth + 1,
            max_depth=max_depth,
        )

    if isinstance(
        value,
        Mapping,
    ):
        return {
            str(key): json_safe(
                item,
                depth=depth + 1,
                max_depth=max_depth,
            )
            for key, item in list(value.items())[:10_000]
        }

    if isinstance(
        value,
        (
            list,
            tuple,
            set,
            frozenset,
        ),
    ):
        return [
            json_safe(
                item,
                depth=depth + 1,
                max_depth=max_depth,
            )
            for item in list(value)[:10_000]
        ]

    return str(value)


def sha256_bytes(
    value: bytes,
) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_json(
    value: Any,
) -> str:
    payload = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    ).encode("utf-8")

    return sha256_bytes(payload)


def ensure_parent(
    path: Path,
) -> None:
    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )


def atomic_write_bytes(
    path: Path,
    data: bytes,
) -> None:
    ensure_parent(path)

    fd, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=str(path.parent),
    )

    temporary_path = Path(temporary_name)

    try:
        with os.fdopen(
            fd,
            "wb",
        ) as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())

        os.replace(
            temporary_path,
            path,
        )

    except Exception:
        try:
            temporary_path.unlink(missing_ok=True)
        except OSError:
            pass

        raise


def atomic_write_json(
    path: Path,
    value: Any,
) -> None:
    payload = json.dumps(
        value,
        indent=2,
        sort_keys=True,
        ensure_ascii=False,
        default=str,
    ).encode("utf-8")

    atomic_write_bytes(
        path,
        payload + b"\n",
    )


# ---------------------------------------------------------------------------
# Dependency validation
# ---------------------------------------------------------------------------


def validate_dependencies() -> None:
    missing: list[str] = []

    if np is None:
        missing.append("numpy")

    if joblib is None:
        missing.append("joblib")

    if missing:
        raise EvaluationDependencyError(
            "Missing required evaluation dependencies: " + ", ".join(missing)
        )


# ---------------------------------------------------------------------------
# Artifact loading
# ---------------------------------------------------------------------------


def load_json_file(
    path: Path,
) -> dict[str, Any]:
    if not path.exists():
        raise EvaluationArtifactError(f"Metadata file does not exist: {path}")

    if not path.is_file():
        raise EvaluationArtifactError(f"Metadata path is not a file: {path}")

    try:
        with path.open(
            "r",
            encoding="utf-8",
        ) as handle:
            value = json.load(handle)
    except Exception as exc:
        raise EvaluationArtifactError(
            f"Unable to read metadata file {path}: {exc}"
        ) from exc

    if not isinstance(
        value,
        Mapping,
    ):
        raise EvaluationArtifactError(
            f"Metadata file {path} does not contain a JSON object."
        )

    return dict(value)


def load_model(
    path: Path,
) -> Any:
    if not path.exists():
        raise EvaluationArtifactError(f"Model file does not exist: {path}")

    if not path.is_file():
        raise EvaluationArtifactError(f"Model path is not a file: {path}")

    try:
        model = predict_module.load_prediction_artifacts(model_path=path).model

        return model

    except Exception:
        # Fall back to the explicit trusted loader supplied by train.py.
        try:
            from src.ml.train import (
                load_trained_model,
            )

            return load_trained_model(path)

        except Exception as exc:
            raise EvaluationArtifactError(
                f"Unable to load trained model {path}: {exc}"
            ) from exc


def load_evaluation_artifacts(
    *,
    model_path: Path,
    schema_path: Path,
    metadata_path: Path,
    thresholds_path: Path,
) -> dict[str, Any]:
    model = load_model(model_path)

    try:
        schema = load_schema(schema_path)
    except Exception as exc:
        raise EvaluationArtifactError(
            f"Unable to load feature schema {schema_path}: {exc}"
        ) from exc

    metadata = load_json_file(metadata_path)

    thresholds = load_json_file(thresholds_path)

    model_feature_count = safe_int(
        getattr(
            model,
            "n_features_in_",
            0,
        )
    )

    schema_feature_count = extract_schema_feature_count(schema)

    if (
        model_feature_count
        and schema_feature_count
        and model_feature_count != schema_feature_count
    ):
        raise EvaluationArtifactError(
            "Model/schema feature-count mismatch: "
            f"model={model_feature_count}, "
            f"schema={schema_feature_count}"
        )

    threshold = extract_threshold(
        thresholds,
        metadata,
    )

    return {
        "model": model,
        "schema": schema,
        "metadata": metadata,
        "thresholds": thresholds,
        "threshold": threshold,
        "model_path": str(model_path),
        "schema_path": str(schema_path),
        "metadata_path": str(metadata_path),
        "thresholds_path": str(thresholds_path),
    }


def extract_schema_feature_count(
    schema: Any,
) -> int:
    if isinstance(
        schema,
        Mapping,
    ):
        for key in (
            "feature_count",
            "n_features",
        ):
            value = schema.get(key)

            count = safe_int(value)

            if count > 0:
                return count

        for key in (
            "feature_names",
            "features",
            "definitions",
        ):
            value = schema.get(key)

            if isinstance(
                value,
                Mapping,
            ):
                return len(value)

            if isinstance(
                value,
                Sequence,
            ) and not isinstance(
                value,
                (
                    str,
                    bytes,
                ),
            ):
                return len(value)

    for attribute in (
        "feature_count",
        "n_features",
    ):
        value = getattr(
            schema,
            attribute,
            None,
        )

        count = safe_int(value)

        if count > 0:
            return count

    for attribute in (
        "feature_names",
        "features",
        "definitions",
    ):
        value = getattr(
            schema,
            attribute,
            None,
        )

        if isinstance(
            value,
            Mapping,
        ):
            return len(value)

        if isinstance(
            value,
            Sequence,
        ) and not isinstance(
            value,
            (
                str,
                bytes,
            ),
        ):
            return len(value)

    return 0


def extract_threshold(
    thresholds: Mapping[str, Any],
    metadata: Mapping[str, Any],
) -> float:
    candidates = [
        thresholds.get("selected"),
        thresholds.get("malicious"),
        thresholds.get("positive"),
        thresholds.get("default"),
    ]

    decision = thresholds.get("decision")

    if isinstance(
        decision,
        Mapping,
    ):
        candidates.extend(
            [
                decision.get("malicious_if_probability_gte"),
                decision.get("threshold"),
            ]
        )

    threshold_metadata = metadata.get("threshold")

    if isinstance(
        threshold_metadata,
        Mapping,
    ):
        candidates.extend(
            [
                threshold_metadata.get("selected"),
                threshold_metadata.get("default"),
            ]
        )

    for candidate in candidates:
        value = safe_float(
            candidate,
            default=-1.0,
        )

        if 0.0 <= value <= 1.0:
            return value

    return DEFAULT_THRESHOLD


# ---------------------------------------------------------------------------
# Dataset loading
# ---------------------------------------------------------------------------


def load_evaluation_dataset(
    path: Path,
) -> Dataset:
    if not path.exists():
        raise EvaluationDataError(f"Dataset does not exist: {path}")

    try:
        dataset = load_dataset(path)
    except Exception as exc:
        raise EvaluationDataError(f"Unable to load evaluation dataset: {exc}") from exc

    try:
        valid = validate_dataset(dataset)

        if valid is False:
            raise EvaluationDataError("Dataset validation failed.")

    except TypeError:
        try:
            valid = validate_dataset(
                dataset,
                require_labels=True,
            )

            if valid is False:
                raise EvaluationDataError("Dataset validation failed.")
        except Exception as exc:
            raise EvaluationDataError(f"Dataset validation failed: {exc}") from exc

    except Exception as exc:
        raise EvaluationDataError(f"Dataset validation failed: {exc}") from exc

    records = getattr(
        dataset,
        "records",
        None,
    )

    if records is None:
        try:
            records = list(dataset)
        except TypeError:
            records = []

    if not records:
        raise EvaluationDataError("Evaluation dataset contains no records.")

    if len(records) > MAX_EVALUATION_SAMPLES:
        raise EvaluationDataError(
            f"Dataset contains {len(records):,} samples; "
            f"maximum is {MAX_EVALUATION_SAMPLES:,}."
        )

    return dataset


# ---------------------------------------------------------------------------
# Direct evaluation helpers
# ---------------------------------------------------------------------------


def vectorize_dataset(
    dataset: Dataset,
    artifacts: Mapping[str, Any],
) -> tuple[
    Any,
    Any,
    list[str],
    int,
    int,
    list[str],
]:
    """
    Convert dataset records using the exact feature alignment logic used by
    prediction.py.

    Returns:

        X
        y
        sample_ids
        missing_feature_count
        unknown_feature_count
        unknown_feature_names
    """

    records = getattr(
        dataset,
        "records",
        None,
    )

    if records is None:
        records = list(dataset)

    records = list(records)

    vectors: list[Any] = []
    targets: list[int] = []
    sample_ids: list[str] = []

    total_missing = 0
    total_unknown = 0
    unknown_names: set[str] = set()

    schema = artifacts["schema"]

    model = artifacts["model"]

    for index, record in enumerate(records):
        try:
            vector_result = predict_module.vectorize_record(
                record,
                schema,
            )
        except TypeError:
            try:
                vector_result = predict_module.vectorize_record(
                    record,
                    schema=schema,
                )
            except Exception as exc:
                raise EvaluationDataError(
                    f"Unable to vectorize record {index}: {exc}"
                ) from exc
        except Exception as exc:
            raise EvaluationDataError(
                f"Unable to vectorize record {index}: {exc}"
            ) from exc

        vector, sample_id, missing, unknown, names = normalize_vectorize_result(
            vector_result,
            index,
        )

        vectors.append(vector)

        label = getattr(
            record,
            "label",
            None,
        )

        if label is None and isinstance(
            record,
            Mapping,
        ):
            label = record.get("label")

        targets.append(
            normalize_label(
                label,
                index,
            )
        )

        sample_ids.append(str(sample_id if sample_id is not None else index))

        total_missing += int(missing)

        total_unknown += int(unknown)

        for name in names:
            unknown_names.add(str(name))

    try:
        x = np.asarray(
            vectors,
            dtype=np.float64,
        )
    except Exception as exc:
        raise EvaluationDataError(
            f"Unable to construct evaluation feature matrix: {exc}"
        ) from exc

    y = np.asarray(
        targets,
        dtype=np.int64,
    )

    if x.ndim != 2:
        raise EvaluationDataError(f"Evaluation matrix must be 2D; got {x.shape}.")

    model_feature_count = safe_int(
        getattr(
            model,
            "n_features_in_",
            0,
        )
    )

    if model_feature_count and x.shape[1] != model_feature_count:
        raise EvaluationDataError(
            "Evaluation feature count does not match model: "
            f"matrix={x.shape[1]}, "
            f"model={model_feature_count}"
        )

    x = np.nan_to_num(
        x,
        nan=0.0,
        posinf=0.0,
        neginf=0.0,
    )

    return (
        x,
        y,
        sample_ids,
        total_missing,
        total_unknown,
        sorted(unknown_names),
    )


def normalize_vectorize_result(
    value: Any,
    index: int,
) -> tuple[
    Any,
    Any,
    int,
    int,
    list[str],
]:
    if not isinstance(
        value,
        tuple,
    ):
        raise EvaluationDataError(
            f"vectorize_record returned an unsupported value " f"for record {index}."
        )

    if len(value) < 2:
        raise EvaluationDataError(
            f"vectorize_record returned too few values " f"for record {index}."
        )

    vector = value[0]
    sample_id = value[1]

    missing = safe_int(value[2]) if len(value) >= 3 else 0

    unknown = safe_int(value[3]) if len(value) >= 4 else 0

    names: list[str] = []

    if len(value) >= 5:
        raw_names = value[4]

        if isinstance(
            raw_names,
            Sequence,
        ) and not isinstance(
            raw_names,
            (
                str,
                bytes,
            ),
        ):
            names = [str(name) for name in raw_names]

    return (
        vector,
        sample_id,
        missing,
        unknown,
        names,
    )


def normalize_label(
    value: Any,
    index: int,
) -> int:
    if isinstance(
        value,
        bool,
    ):
        return int(value)

    if isinstance(
        value,
        (int, float),
    ):
        number = safe_float(
            value,
            default=-1.0,
        )

        if number in (
            0.0,
            1.0,
        ):
            return int(number)

    text = str(value if value is not None else "").strip().lower()

    normalized = text.replace(" ", "_").replace("-", "_")

    if normalized in {
        "0",
        "false",
        "benign",
        "clean",
        "safe",
        "good",
        "negative",
    }:
        return 0

    if normalized in {
        "1",
        "true",
        "malicious",
        "malware",
        "suspicious",
        "bad",
        "positive",
    }:
        return 1

    raise EvaluationDataError(
        f"Unsupported label {value!r} " f"at dataset record {index}."
    )


# ---------------------------------------------------------------------------
# Probability prediction
# ---------------------------------------------------------------------------


def predict_positive_probability(
    model: Any,
    x: Any,
) -> Any:
    if not hasattr(
        model,
        "predict_proba",
    ):
        raise EvaluationArtifactError("Model does not expose predict_proba().")

    try:
        probabilities = model.predict_proba(x)
    except Exception as exc:
        raise EvaluationDataError(
            f"Model probability prediction failed: {exc}"
        ) from exc

    probabilities = np.asarray(
        probabilities,
        dtype=np.float64,
    )

    if probabilities.ndim != 2:
        raise EvaluationDataError("Model probability output must be two-dimensional.")

    classes = list(
        getattr(
            model,
            "classes_",
            [],
        )
    )

    if 1 in classes:
        index = classes.index(1)
    elif "malicious" in classes:
        index = classes.index("malicious")
    elif probabilities.shape[1] == 2:
        index = 1
    else:
        raise EvaluationArtifactError(
            "Unable to identify the malicious/positive model class."
        )

    return np.clip(
        probabilities[
            :,
            index,
        ],
        0.0,
        1.0,
    )


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------


def confusion_counts(
    y_true: Any,
    probabilities: Any,
    threshold: float,
) -> tuple[
    int,
    int,
    int,
    int,
]:
    predictions = (np.asarray(probabilities) >= threshold).astype(np.int64)

    y_true = np.asarray(
        y_true,
        dtype=np.int64,
    )

    tn = int(np.sum((y_true == 0) & (predictions == 0)))

    fp = int(np.sum((y_true == 0) & (predictions == 1)))

    fn = int(np.sum((y_true == 1) & (predictions == 0)))

    tp = int(np.sum((y_true == 1) & (predictions == 1)))

    return (
        tn,
        fp,
        fn,
        tp,
    )


def metric_from_module(
    name: str,
    y_true: Any,
    probabilities: Any,
    threshold: float,
) -> Any:
    function = getattr(
        evaluation_module,
        name,
        None,
    )

    if function is None:
        return None

    attempts = [
        (
            y_true,
            probabilities,
            threshold,
        ),
        (
            y_true,
            probabilities,
        ),
    ]

    for args in attempts:
        try:
            return function(*args)
        except TypeError:
            continue
        except Exception:
            return None

    return None


def calculate_metrics(
    y_true: Any,
    probabilities: Any,
    threshold: float,
) -> dict[str, Any]:
    tn, fp, fn, tp = confusion_counts(
        y_true,
        probabilities,
        threshold,
    )

    total = tn + fp + fn + tp

    accuracy = (tn + tp) / total if total else 0.0

    recall = tp / (tp + fn) if (tp + fn) else 0.0

    precision = tp / (tp + fp) if (tp + fp) else 0.0

    specificity = tn / (tn + fp) if (tn + fp) else 0.0

    f1_denominator = precision + recall

    f1 = 2.0 * precision * recall / f1_denominator if f1_denominator else 0.0

    balanced_accuracy = (recall + specificity) / 2.0

    result = {
        "threshold": float(threshold),
        "samples": total,
        "accuracy": accuracy,
        "balanced_accuracy": balanced_accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "specificity": specificity,
        "false_positive_rate": (fp / (fp + tn) if (fp + tn) else 0.0),
        "false_negative_rate": (fn / (fn + tp) if (fn + tp) else 0.0),
        "true_negatives": tn,
        "false_positives": fp,
        "false_negatives": fn,
        "true_positives": tp,
    }

    if len(np.unique(y_true)) == 2:
        roc_auc = metric_from_module(
            "roc_auc",
            y_true,
            probabilities,
            threshold,
        )

        average_precision = metric_from_module(
            "average_precision",
            y_true,
            probabilities,
            threshold,
        )

        if roc_auc is not None:
            result["roc_auc"] = safe_float(roc_auc)

        if average_precision is not None:
            result["average_precision"] = safe_float(average_precision)

    return result


# ---------------------------------------------------------------------------
# Threshold analysis
# ---------------------------------------------------------------------------


def generate_thresholds(
    *,
    minimum: float = 0.01,
    maximum: float = 0.99,
    count: int = 99,
) -> list[float]:
    if count <= 1:
        return [
            round(
                minimum,
                4,
            )
        ]

    count = min(
        count,
        MAX_THRESHOLDS,
    )

    values = np.linspace(
        minimum,
        maximum,
        count,
    )

    return [
        round(
            float(value),
            4,
        )
        for value in values
    ]


def evaluate_thresholds(
    y_true: Any,
    probabilities: Any,
    *,
    thresholds: Sequence[float],
) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []

    for threshold in thresholds:
        value = safe_float(
            threshold,
            default=-1.0,
        )

        if not 0.0 <= value <= 1.0:
            continue

        results.append(
            calculate_metrics(
                y_true,
                probabilities,
                value,
            )
        )

    return results


def select_best_threshold(
    threshold_metrics: Sequence[Mapping[str, Any]],
    *,
    default: float,
) -> float:
    if not threshold_metrics:
        return float(default)

    best = max(
        threshold_metrics,
        key=lambda item: (
            safe_float(item.get("f1")),
            safe_float(item.get("balanced_accuracy")),
            -abs(safe_float(item.get("threshold")) - default),
        ),
    )

    return safe_float(
        best.get("threshold"),
        default,
    )


# ---------------------------------------------------------------------------
# Error analysis
# ---------------------------------------------------------------------------


def build_error_analysis(
    dataset: Dataset,
    sample_ids: Sequence[str],
    y_true: Any,
    probabilities: Any,
    *,
    threshold: float,
    max_examples: int = 1000,
) -> dict[str, Any]:
    records = getattr(
        dataset,
        "records",
        None,
    )

    if records is None:
        records = list(dataset)

    false_positives: list[dict[str, Any]] = []
    false_negatives: list[dict[str, Any]] = []

    predictions = (np.asarray(probabilities) >= threshold).astype(np.int64)

    for index, (
        record,
        sample_id,
        actual,
        probability,
        prediction,
    ) in enumerate(
        zip(
            records,
            sample_ids,
            y_true,
            probabilities,
            predictions,
        )
    ):
        if actual == 0 and prediction == 1:
            false_positives.append(
                {
                    "sample_id": str(sample_id),
                    "actual": "benign",
                    "predicted": "malicious",
                    "probability": float(probability),
                    "record_index": index,
                }
            )

        elif actual == 1 and prediction == 0:
            false_negatives.append(
                {
                    "sample_id": str(sample_id),
                    "actual": "malicious",
                    "predicted": "benign",
                    "probability": float(probability),
                    "record_index": index,
                }
            )

    return {
        "false_positive_count": len(false_positives),
        "false_negative_count": len(false_negatives),
        "false_positives": false_positives[:max_examples],
        "false_negatives": false_negatives[:max_examples],
    }


# ---------------------------------------------------------------------------
# Cross-validation
# ---------------------------------------------------------------------------


def stratified_folds(
    y: Any,
    *,
    folds: int,
    random_state: int,
) -> list[
    tuple[
        list[int],
        list[int],
    ]
]:
    """
    Deterministic stratified K-fold index generation.
    """

    if folds < 2:
        raise EvaluationConfigurationError(
            "Cross-validation requires at least two folds."
        )

    labels = [int(value) for value in y.tolist()]

    class_indices: dict[
        int,
        list[int],
    ] = {}

    for index, label in enumerate(labels):
        class_indices.setdefault(
            label,
            [],
        ).append(index)

    if len(class_indices) < 2:
        raise EvaluationDataError("Cross-validation requires both classes.")

    minimum_class_size = min(len(indices) for indices in class_indices.values())

    folds = min(
        folds,
        minimum_class_size,
    )

    if folds < 2:
        raise EvaluationDataError(
            "Not enough samples in each class for "
            "the requested cross-validation folds."
        )

    import random

    rng = random.Random(random_state)

    fold_buckets: list[list[int]] = [[] for _ in range(folds)]

    for label in sorted(class_indices):
        indices = list(class_indices[label])

        rng.shuffle(indices)

        for position, index in enumerate(indices):
            fold_buckets[position % folds].append(index)

    result = []

    all_indices = set(range(len(labels)))

    for bucket in fold_buckets:
        validation = sorted(bucket)

        validation_set = set(validation)

        training = sorted(all_indices - validation_set)

        result.append(
            (
                training,
                validation,
            )
        )

    return result


def clone_model_for_cv(
    model: Any,
) -> Any:
    try:
        from sklearn.base import clone  # type: ignore

        return clone(model)
    except Exception:
        if hasattr(
            model,
            "get_params",
        ):
            from sklearn.ensemble import (
                RandomForestClassifier,
            )

            params = model.get_params(deep=False)

            return RandomForestClassifier(**params)

        raise EvaluationArtifactError("Unable to clone model for cross-validation.")


def run_cross_validation(
    model: Any,
    x: Any,
    y: Any,
    *,
    folds: int,
    random_state: int,
    threshold: float,
) -> dict[str, Any]:
    fold_indices = stratified_folds(
        y,
        folds=folds,
        random_state=random_state,
    )

    fold_results: list[dict[str, Any]] = []

    for fold_number, (
        train_indices,
        validation_indices,
    ) in enumerate(
        fold_indices,
        start=1,
    ):
        fold_model = clone_model_for_cv(model)

        fold_model.fit(
            x[train_indices],
            y[train_indices],
        )

        probabilities = predict_positive_probability(
            fold_model,
            x[validation_indices],
        )

        metrics = calculate_metrics(
            y[validation_indices],
            probabilities,
            threshold,
        )

        fold_results.append(
            {
                "fold": fold_number,
                "train_samples": len(train_indices),
                "validation_samples": len(validation_indices),
                "metrics": metrics,
            }
        )

    metric_names = [
        "accuracy",
        "balanced_accuracy",
        "precision",
        "recall",
        "f1",
        "specificity",
        "false_positive_rate",
        "false_negative_rate",
    ]

    aggregate: dict[str, float] = {}

    for name in metric_names:
        values = [safe_float(fold["metrics"].get(name)) for fold in fold_results]

        aggregate[name] = float(np.mean(values)) if values else 0.0

    return {
        "folds": len(fold_results),
        "random_state": random_state,
        "threshold": threshold,
        "aggregate": aggregate,
        "fold_results": fold_results,
    }


# ---------------------------------------------------------------------------
# Evaluation result construction
# ---------------------------------------------------------------------------


def evaluate_model(
    *,
    dataset: Dataset,
    artifacts: Mapping[str, Any],
    threshold: Optional[float] = None,
    threshold_count: int = 99,
    cross_validation_folds: int = 0,
    random_state: int = DEFAULT_RANDOM_STATE,
) -> dict[str, Any]:
    started = time.monotonic()

    x, y, sample_ids, missing, unknown, unknown_names = vectorize_dataset(
        dataset,
        artifacts,
    )

    if x.shape[0] < 2:
        raise EvaluationDataError("At least two samples are required.")

    unique_labels = np.unique(y)

    if len(unique_labels) < 2:
        raise EvaluationDataError(
            "Evaluation requires both benign and malicious samples."
        )

    model = artifacts["model"]

    probabilities = predict_positive_probability(
        model,
        x,
    )

    default_threshold = artifacts.get("threshold") if threshold is None else threshold

    default_threshold = safe_float(
        default_threshold,
        DEFAULT_THRESHOLD,
    )

    threshold_values = generate_thresholds(count=threshold_count)

    threshold_results = evaluate_thresholds(
        y,
        probabilities,
        thresholds=threshold_values,
    )

    selected_threshold = select_best_threshold(
        threshold_results,
        default=default_threshold,
    )

    metrics = calculate_metrics(
        y,
        probabilities,
        selected_threshold,
    )

    default_metrics = calculate_metrics(
        y,
        probabilities,
        default_threshold,
    )

    error_analysis = build_error_analysis(
        dataset,
        sample_ids,
        y,
        probabilities,
        threshold=selected_threshold,
    )

    cross_validation = None

    if cross_validation_folds:
        cross_validation = run_cross_validation(
            model,
            x,
            y,
            folds=cross_validation_folds,
            random_state=random_state,
            threshold=selected_threshold,
        )

    try:
        data_fp = str(dataset_fingerprint(dataset))
    except Exception:
        data_fp = ""

    elapsed = time.monotonic() - started

    predictions = [
        {
            "sample_id": str(sample_id),
            "actual": ("malicious" if int(actual) == 1 else "benign"),
            "probability": float(probability),
            "prediction": (
                "malicious" if float(probability) >= selected_threshold else "benign"
            ),
        }
        for sample_id, actual, probability in zip(
            sample_ids,
            y,
            probabilities,
        )
    ]

    return {
        "evaluation_version": "1.0",
        "module": MODULE_NAME,
        "evaluator_version": EVALUATOR_VERSION,
        "created_at": utc_now(),
        "dataset": {
            "path": str(
                getattr(
                    dataset,
                    "path",
                    "",
                )
            ),
            "samples": int(x.shape[0]),
            "features": int(x.shape[1]),
            "dataset_fingerprint": data_fp,
            "benign_samples": int(np.sum(y == 0)),
            "malicious_samples": int(np.sum(y == 1)),
        },
        "model": {
            "type": type(model).__name__,
            "path": artifacts["model_path"],
            "schema_path": artifacts["schema_path"],
            "metadata_path": artifacts["metadata_path"],
            "thresholds_path": artifacts["thresholds_path"],
            "metadata": json_safe(
                artifacts.get(
                    "metadata",
                    {},
                )
            ),
        },
        "features": {
            "count": int(x.shape[1]),
            "missing_values": int(missing),
            "unknown_feature_values": int(unknown),
            "unknown_feature_names": unknown_names[:1000],
        },
        "threshold": {
            "artifact": float(default_threshold),
            "selected": float(selected_threshold),
            "optimization_metric": "f1",
            "candidate_count": len(threshold_results),
        },
        "metrics": {
            "selected_threshold": metrics,
            "artifact_threshold": default_metrics,
        },
        "threshold_analysis": threshold_results,
        "error_analysis": error_analysis,
        "cross_validation": cross_validation,
        "predictions": predictions,
        "runtime": {
            "seconds": elapsed,
        },
        "security": {
            "documents_executed": False,
            "macros_executed": False,
            "scripts_executed": False,
            "payloads_executed": False,
            "urls_contacted": False,
            "network_access": False,
            "dynamic_analysis": False,
        },
    }


# ---------------------------------------------------------------------------
# Output persistence
# ---------------------------------------------------------------------------


def save_json_result(
    result: Mapping[str, Any],
    path: Path,
) -> None:
    atomic_write_json(
        path,
        result,
    )


def save_csv_result(
    result: Mapping[str, Any],
    path: Path,
) -> None:
    metrics = result.get("metrics", {})

    selected = (
        metrics.get("selected_threshold", {})
        if isinstance(
            metrics,
            Mapping,
        )
        else {}
    )

    threshold_analysis = result.get(
        "threshold_analysis",
        [],
    )

    rows: list[dict[str, Any]] = []

    if isinstance(
        threshold_analysis,
        Sequence,
    ):
        for item in threshold_analysis:
            if isinstance(
                item,
                Mapping,
            ):
                rows.append(
                    {
                        "threshold": item.get("threshold"),
                        "accuracy": item.get("accuracy"),
                        "balanced_accuracy": item.get("balanced_accuracy"),
                        "precision": item.get("precision"),
                        "recall": item.get("recall"),
                        "f1": item.get("f1"),
                        "specificity": item.get("specificity"),
                        "false_positive_rate": item.get("false_positive_rate"),
                        "false_negative_rate": item.get("false_negative_rate"),
                        "true_negatives": item.get("true_negatives"),
                        "false_positives": item.get("false_positives"),
                        "false_negatives": item.get("false_negatives"),
                        "true_positives": item.get("true_positives"),
                    }
                )

    if not rows:
        rows.append(
            {
                "threshold": selected.get("threshold"),
                "accuracy": selected.get("accuracy"),
                "balanced_accuracy": selected.get("balanced_accuracy"),
                "precision": selected.get("precision"),
                "recall": selected.get("recall"),
                "f1": selected.get("f1"),
                "specificity": selected.get("specificity"),
                "false_positive_rate": selected.get("false_positive_rate"),
                "false_negative_rate": selected.get("false_negative_rate"),
                "true_negatives": selected.get("true_negatives"),
                "false_positives": selected.get("false_positives"),
                "false_negatives": selected.get("false_negatives"),
                "true_positives": selected.get("true_positives"),
            }
        )

    fieldnames = [
        "threshold",
        "accuracy",
        "balanced_accuracy",
        "precision",
        "recall",
        "f1",
        "specificity",
        "false_positive_rate",
        "false_negative_rate",
        "true_negatives",
        "false_positives",
        "false_negatives",
        "true_positives",
    ]

    ensure_parent(path)

    output_lines: list[str] = []

    from io import StringIO

    buffer = StringIO()

    writer = csv.DictWriter(
        buffer,
        fieldnames=fieldnames,
        extrasaction="ignore",
    )

    writer.writeheader()

    for row in rows:
        writer.writerow(row)

    atomic_write_bytes(
        path,
        buffer.getvalue().encode("utf-8"),
    )


# ---------------------------------------------------------------------------
# Human-readable output
# ---------------------------------------------------------------------------


def print_summary(
    result: Mapping[str, Any],
) -> None:
    dataset = result.get("dataset", {})

    metrics_container = result.get("metrics", {})

    metrics = (
        metrics_container.get("selected_threshold", {})
        if isinstance(
            metrics_container,
            Mapping,
        )
        else {}
    )

    threshold = result.get("threshold", {})

    error_analysis = result.get("error_analysis", {})

    print()
    print("Pharos CDR model evaluation")
    print("===========================")

    print(f"Samples:              " f"{safe_int(dataset.get('samples')):,}")

    print(f"Features:             " f"{safe_int(dataset.get('features')):,}")

    print(f"Benign:               " f"{safe_int(dataset.get('benign_samples')):,}")

    print(f"Malicious:            " f"{safe_int(dataset.get('malicious_samples')):,}")

    print()

    print(f"Threshold:            " f"{safe_float(threshold.get('selected')):.4f}")

    print(f"Accuracy:             " f"{safe_float(metrics.get('accuracy')):.4f}")

    print(
        f"Balanced accuracy:    " f"{safe_float(metrics.get('balanced_accuracy')):.4f}"
    )

    print(f"Precision:            " f"{safe_float(metrics.get('precision')):.4f}")

    print(f"Recall:               " f"{safe_float(metrics.get('recall')):.4f}")

    print(f"F1:                   " f"{safe_float(metrics.get('f1')):.4f}")

    roc_auc = metrics.get("roc_auc")

    if roc_auc is not None:
        print(f"ROC-AUC:              " f"{safe_float(roc_auc):.4f}")

    average_precision = metrics.get("average_precision")

    if average_precision is not None:
        print(f"Average precision:    " f"{safe_float(average_precision):.4f}")

    print()

    print(
        f"TN / FP / FN / TP:    "
        f"{safe_int(metrics.get('true_negatives'))} / "
        f"{safe_int(metrics.get('false_positives'))} / "
        f"{safe_int(metrics.get('false_negatives'))} / "
        f"{safe_int(metrics.get('true_positives'))}"
    )

    print(
        f"False positives:      "
        f"{safe_int(error_analysis.get('false_positive_count'))}"
    )

    print(
        f"False negatives:      "
        f"{safe_int(error_analysis.get('false_negative_count'))}"
    )

    cross_validation = result.get("cross_validation")

    if isinstance(
        cross_validation,
        Mapping,
    ):
        aggregate = cross_validation.get("aggregate", {})

        print()
        print(
            f"Cross-validation:     " f"{safe_int(cross_validation.get('folds'))} folds"
        )

        print(f"CV mean F1:           " f"{safe_float(aggregate.get('f1')):.4f}")

        print(
            f"CV balanced accuracy: "
            f"{safe_float(aggregate.get('balanced_accuracy')):.4f}"
        )

    print()

    runtime = result.get("runtime", {})

    print(f"Evaluation time:      " f"{safe_float(runtime.get('seconds')):.2f}s")

    print()


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="evaluate_model.py",
        description=("Evaluate the Pharos CDR Random Forest " "malware classifier."),
        formatter_class=(argparse.ArgumentDefaultsHelpFormatter),
    )

    parser.add_argument(
        "--dataset",
        type=Path,
        default=DEFAULT_DATASET_PATH,
        help="Evaluation dataset path.",
    )

    parser.add_argument(
        "--model",
        type=Path,
        default=DEFAULT_MODEL_PATH,
        help="Trained model path.",
    )

    parser.add_argument(
        "--schema",
        type=Path,
        default=DEFAULT_SCHEMA_PATH,
        help="Feature schema path.",
    )

    parser.add_argument(
        "--metadata",
        type=Path,
        default=DEFAULT_METADATA_PATH,
        help="Model metadata path.",
    )

    parser.add_argument(
        "--thresholds",
        type=Path,
        default=DEFAULT_THRESHOLDS_PATH,
        help="Threshold metadata path.",
    )

    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT_PATH,
        help="JSON evaluation report output path.",
    )

    parser.add_argument(
        "--csv-output",
        type=Path,
        default=None,
        help=("Optional CSV threshold-analysis output path."),
    )

    parser.add_argument(
        "--threshold",
        type=float,
        default=None,
        help=("Override the threshold stored in thresholds.json."),
    )

    parser.add_argument(
        "--threshold-count",
        type=int,
        default=99,
        help=("Number of thresholds evaluated between 0.01 and 0.99."),
    )

    parser.add_argument(
        "--cv-folds",
        type=int,
        default=0,
        help=("Run deterministic stratified cross-validation. " "Use 0 to disable."),
    )

    parser.add_argument(
        "--random-state",
        type=int,
        default=DEFAULT_RANDOM_STATE,
        help="Cross-validation random seed.",
    )

    parser.add_argument(
        "--no-threshold-optimization",
        action="store_true",
        help=(
            "Evaluate using the artifact/explicit threshold only "
            "instead of selecting the best F1 threshold."
        ),
    )

    parser.add_argument(
        "--no-overwrite",
        action="store_true",
        help="Refuse to overwrite an existing JSON report.",
    )

    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable informational logging.",
    )

    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging.",
    )

    return parser


def validate_arguments(
    args: argparse.Namespace,
) -> None:
    if not args.dataset.exists():
        raise EvaluationConfigurationError(f"Dataset does not exist: {args.dataset}")

    if not args.model.exists():
        raise EvaluationConfigurationError(f"Model does not exist: {args.model}")

    if not args.schema.exists():
        raise EvaluationConfigurationError(f"Schema does not exist: {args.schema}")

    if not args.metadata.exists():
        raise EvaluationConfigurationError(f"Metadata does not exist: {args.metadata}")

    if not args.thresholds.exists():
        raise EvaluationConfigurationError(
            f"Thresholds file does not exist: {args.thresholds}"
        )

    if args.threshold is not None:
        if not 0.0 <= args.threshold <= 1.0:
            raise EvaluationConfigurationError("--threshold must be between 0 and 1.")

    if not 1 <= args.threshold_count <= MAX_THRESHOLDS:
        raise EvaluationConfigurationError(
            f"--threshold-count must be between 1 and " f"{MAX_THRESHOLDS}."
        )

    if args.cv_folds < 0:
        raise EvaluationConfigurationError("--cv-folds cannot be negative.")

    if args.cv_folds > DEFAULT_MAX_CV_FOLDS:
        raise EvaluationConfigurationError(
            f"--cv-folds cannot exceed " f"{DEFAULT_MAX_CV_FOLDS}."
        )

    if args.no_overwrite and args.output.exists():
        raise EvaluationConfigurationError(
            f"Output already exists and --no-overwrite was selected: " f"{args.output}"
        )


def configure_logging(
    *,
    verbose: bool,
    debug: bool,
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


# ---------------------------------------------------------------------------
# Main evaluation workflow
# ---------------------------------------------------------------------------


def run_evaluation(
    *,
    dataset_path: Path = DEFAULT_DATASET_PATH,
    model_path: Path = DEFAULT_MODEL_PATH,
    schema_path: Path = DEFAULT_SCHEMA_PATH,
    metadata_path: Path = DEFAULT_METADATA_PATH,
    thresholds_path: Path = DEFAULT_THRESHOLDS_PATH,
    threshold: Optional[float] = None,
    threshold_count: int = 99,
    cross_validation_folds: int = 0,
    random_state: int = DEFAULT_RANDOM_STATE,
    optimize_threshold: bool = True,
) -> dict[str, Any]:
    validate_dependencies()

    if not 1 <= threshold_count <= MAX_THRESHOLDS:
        raise EvaluationConfigurationError(
            f"threshold_count must be between 1 and " f"{MAX_THRESHOLDS}."
        )

    if cross_validation_folds < 0:
        raise EvaluationConfigurationError("cross_validation_folds cannot be negative.")

    dataset = load_evaluation_dataset(Path(dataset_path))

    artifacts = load_evaluation_artifacts(
        model_path=Path(model_path),
        schema_path=Path(schema_path),
        metadata_path=Path(metadata_path),
        thresholds_path=Path(thresholds_path),
    )

    artifact_threshold = safe_float(
        artifacts.get("threshold"),
        DEFAULT_THRESHOLD,
    )

    effective_threshold = (
        artifact_threshold
        if threshold is None
        else safe_float(
            threshold,
            artifact_threshold,
        )
    )

    result = evaluate_model(
        dataset=dataset,
        artifacts=artifacts,
        threshold=effective_threshold,
        threshold_count=threshold_count,
        cross_validation_folds=cross_validation_folds,
        random_state=random_state,
    )

    if not optimize_threshold:
        metrics = calculate_metrics(
            *vectorize_for_fixed_evaluation(
                dataset,
                artifacts,
            ),
            threshold=effective_threshold,
        )

        result["threshold"]["selected"] = effective_threshold

        result["threshold"]["optimization_metric"] = None

        result["metrics"]["selected_threshold"] = metrics

    return result


def vectorize_for_fixed_evaluation(
    dataset: Dataset,
    artifacts: Mapping[str, Any],
) -> tuple[
    Any,
    Any,
]:
    x, y, _, _, _, _ = vectorize_dataset(
        dataset,
        artifacts,
    )

    probabilities = predict_positive_probability(
        artifacts["model"],
        x,
    )

    return (
        y,
        probabilities,
    )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


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
        validate_arguments(args)

        LOGGER.info("Loading evaluation dataset.")

        result = run_evaluation(
            dataset_path=args.dataset,
            model_path=args.model,
            schema_path=args.schema,
            metadata_path=args.metadata,
            thresholds_path=args.thresholds,
            threshold=args.threshold,
            threshold_count=args.threshold_count,
            cross_validation_folds=args.cv_folds,
            random_state=args.random_state,
            optimize_threshold=not args.no_threshold_optimization,
        )

        save_json_result(
            result,
            args.output,
        )

        if args.csv_output is not None:
            save_csv_result(
                result,
                args.csv_output,
            )

        print_summary(result)

        print(f"JSON report:          {args.output}")

        if args.csv_output is not None:
            print(f"CSV report:           {args.csv_output}")

        return 0

    except KeyboardInterrupt:
        LOGGER.error("Evaluation interrupted.")
        return 130

    except (EvaluationScriptError,) as exc:
        LOGGER.error(
            "Evaluation failed: %s",
            exc,
        )
        return 2

    except Exception:
        LOGGER.exception("Unexpected evaluation failure.")
        return 1


# ---------------------------------------------------------------------------
# Public APIs
# ---------------------------------------------------------------------------

__all__ = [
    "MODULE_NAME",
    "EVALUATOR_VERSION",
    "DEFAULT_DATASET_PATH",
    "DEFAULT_MODEL_PATH",
    "DEFAULT_SCHEMA_PATH",
    "DEFAULT_METADATA_PATH",
    "DEFAULT_THRESHOLDS_PATH",
    "DEFAULT_OUTPUT_PATH",
    "DEFAULT_CSV_OUTPUT_PATH",
    "EvaluationScriptError",
    "EvaluationDependencyError",
    "EvaluationDataError",
    "EvaluationArtifactError",
    "EvaluationConfigurationError",
    "load_json_file",
    "load_model",
    "load_evaluation_artifacts",
    "load_evaluation_dataset",
    "extract_threshold",
    "extract_schema_feature_count",
    "vectorize_dataset",
    "normalize_vectorize_result",
    "normalize_label",
    "predict_positive_probability",
    "confusion_counts",
    "calculate_metrics",
    "generate_thresholds",
    "evaluate_thresholds",
    "select_best_threshold",
    "build_error_analysis",
    "stratified_folds",
    "clone_model_for_cv",
    "run_cross_validation",
    "evaluate_model",
    "run_evaluation",
    "save_json_result",
    "save_csv_result",
    "build_argument_parser",
    "validate_arguments",
    "configure_logging",
    "print_summary",
    "main",
]


if __name__ == "__main__":
    raise SystemExit(main())
