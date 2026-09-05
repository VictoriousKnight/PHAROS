"""
Model explanation utilities for pharos-cdr.

This module provides static, deterministic explanations for trained
scikit-learn-style classifiers used by the Pharos CDR pipeline.

Security properties
-------------------
- Never executes samples, macros, scripts, or embedded content.
- Never contacts URLs or performs network activity.
- Never launches subprocesses.
- Never modifies analyzed input files.
- Only consumes already-extracted numeric feature vectors and trusted model
  artifacts.
- Model deserialization must only be performed on trusted model files.

Supported explanation methods
-----------------------------
1. Tree / Random Forest feature importance:
   Uses ``feature_importances_`` when available.

2. Permutation importance:
   Measures the effect of shuffling individual features on a supplied
   labeled dataset. This is bounded, deterministic, and uses the estimator
   directly without executing the underlying samples.

3. Sample-level heuristic contribution:
   Produces a ranked explanation by combining feature importance with the
   magnitude of a sample's feature value relative to a baseline. This is
   intentionally described as a heuristic rather than an exact SHAP-style
   attribution.

The module is intentionally dependency-light. scikit-learn and joblib are
only required when loading/evaluating a trained model artifact.
"""

from __future__ import annotations

import csv
import json
import math
import os
import statistics
import tempfile
from dataclasses import asdict, dataclass, field, is_dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, MutableMapping, Optional, Sequence

try:
    from .dataset import (
        Dataset,
        DatasetRecord,
        extract_features,
        feature_matrix,
        load_dataset,
        load_schema,
        target_vector,
    )
except ImportError:  # pragma: no cover - supports direct module execution
    from dataset import (  # type: ignore
        Dataset,
        DatasetRecord,
        extract_features,
        feature_matrix,
        load_dataset,
        load_schema,
        target_vector,
    )

try:
    from .predict import (
        ModelArtifacts,
        PredictionResult,
        load_prediction_artifacts,
        predict_probability,
        vectorize_record,
    )
except ImportError:  # pragma: no cover
    from predict import (  # type: ignore
        ModelArtifacts,
        PredictionResult,
        load_prediction_artifacts,
        predict_probability,
        vectorize_record,
    )


# ---------------------------------------------------------------------------
# Defaults and limits
# ---------------------------------------------------------------------------

DEFAULT_MODEL_PATH = Path("models/trained/random_forest.joblib")
DEFAULT_SCHEMA_PATH = Path("models/metadata/feature_schema.json")
DEFAULT_METADATA_PATH = Path("models/metadata/model_metadata.json")
DEFAULT_THRESHOLDS_PATH = Path("models/metadata/thresholds.json")

DEFAULT_OUTPUT_PATH = Path("outputs/reports/model_explanation.json")

DEFAULT_TOP_N = 25
DEFAULT_PERMUTATION_REPEATS = 5

MAX_FEATURES = 100_000
MAX_SAMPLES = 250_000
MAX_TOP_N = 1_000
MAX_PERMUTATION_REPEATS = 50
MAX_OUTPUT_ITEMS = 100_000
MAX_JSON_SIZE = 100 * 1024 * 1024

EPSILON = 1e-12


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class ExplanationError(RuntimeError):
    """Base exception for explanation failures."""


class ExplanationModelError(ExplanationError):
    """Raised when a model cannot provide the requested explanation."""


class ExplanationDataError(ExplanationError):
    """Raised when explanation input data is invalid."""


class ExplanationDependencyError(ExplanationError):
    """Raised when an optional runtime dependency is unavailable."""


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FeatureImportance:
    """Global importance information for one model feature."""

    feature: str
    importance: float
    normalized_importance: float
    rank: int
    source: str = "model"


@dataclass(frozen=True)
class PermutationImportance:
    """Permutation-importance statistics for one feature."""

    feature: str
    mean_decrease: float
    std_decrease: float
    min_decrease: float
    max_decrease: float
    repeats: int
    rank: int


@dataclass(frozen=True)
class SampleFeatureContribution:
    """
    Heuristic contribution information for one sample feature.

    ``signed_score`` is not a mathematically exact model attribution. It is
    an interpretable ranking signal formed from normalized feature magnitude,
    model importance, and the direction of the feature relative to a
    reference baseline.
    """

    feature: str
    value: float
    baseline: float
    delta: float
    normalized_delta: float
    model_importance: float
    signed_score: float
    absolute_score: float
    rank: int


@dataclass(frozen=True)
class SampleExplanation:
    """Explanation for a single analyzed sample."""

    sample_id: str
    probability: float
    prediction: int
    threshold: float
    risk_label: str
    top_features: tuple[SampleFeatureContribution, ...]
    missing_features: int = 0
    unknown_features: int = 0


@dataclass(frozen=True)
class FeatureGroupImportance:
    """Aggregated importance for a logical feature-name group."""

    group: str
    importance: float
    feature_count: int
    top_features: tuple[str, ...]


@dataclass(frozen=True)
class ExplanationResult:
    """Complete model explanation result."""

    model_path: str
    schema_path: str
    model_type: str
    model_version: str
    threshold: float
    feature_count: int
    global_importance: tuple[FeatureImportance, ...]
    feature_groups: tuple[FeatureGroupImportance, ...] = ()
    permutation_importance: tuple[PermutationImportance, ...] = ()
    sample_explanations: tuple[SampleExplanation, ...] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Safe conversion helpers
# ---------------------------------------------------------------------------


def _safe_text(value: Any, default: str = "") -> str:
    if value is None:
        return default
    try:
        return str(value)
    except Exception:
        return default


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        result = float(value)
    except (TypeError, ValueError, OverflowError):
        return default

    if not math.isfinite(result):
        return default

    return result


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError, OverflowError):
        return default


def _clamp(value: float, lower: float, upper: float) -> float:
    return max(lower, min(upper, value))


def _normalize_importances(values: Sequence[float]) -> list[float]:
    cleaned = [max(0.0, _safe_float(value)) for value in values]
    total = sum(cleaned)

    if total <= EPSILON:
        return [0.0 for _ in cleaned]

    return [value / total for value in cleaned]


def _json_safe(value: Any) -> Any:
    """Convert arbitrary metadata into bounded JSON-compatible values."""
    if value is None or isinstance(value, (str, bool, int)):
        return value

    if isinstance(value, float):
        return value if math.isfinite(value) else None

    if isinstance(value, Path):
        return str(value)

    if is_dataclass(value):
        return _json_safe(asdict(value))

    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for key, item in value.items():
            result[_safe_text(key)] = _json_safe(item)
        return result

    if isinstance(value, (list, tuple, set, frozenset)):
        return [_json_safe(item) for item in value]

    try:
        return _safe_text(value)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Feature-name handling
# ---------------------------------------------------------------------------


def _normalize_feature_names(
    feature_names: Sequence[Any],
    expected_count: Optional[int] = None,
) -> list[str]:
    names: list[str] = []

    for index, name in enumerate(feature_names):
        text = _safe_text(name).strip()

        if not text:
            text = f"feature_{index}"

        names.append(text)

        if len(names) >= MAX_FEATURES:
            break

    if expected_count is not None:
        expected_count = min(max(0, expected_count), MAX_FEATURES)

        if len(names) < expected_count:
            names.extend(
                f"feature_{index}"
                for index in range(len(names), expected_count)
            )
        elif len(names) > expected_count:
            names = names[:expected_count]

    return names


def _feature_names_from_schema(schema: Any) -> list[str]:
    if schema is None:
        return []

    if isinstance(schema, Mapping):
        raw = (
            schema.get("features")
            or schema.get("feature_names")
            or schema.get("definitions")
            or schema.get("schema")
        )

        if isinstance(raw, Mapping):
            names = list(raw.keys())
            return _normalize_feature_names(names)

        if isinstance(raw, Sequence) and not isinstance(raw, (str, bytes)):
            result: list[str] = []

            for item in raw:
                if isinstance(item, Mapping):
                    name = (
                        item.get("name")
                        or item.get("feature")
                        or item.get("key")
                    )
                else:
                    name = item

                if name is not None:
                    result.append(_safe_text(name))

            return _normalize_feature_names(result)

    try:
        raw_features = getattr(schema, "features", None)

        if raw_features:
            result = []

            for item in raw_features:
                if isinstance(item, Mapping):
                    result.append(
                        _safe_text(
                            item.get("name")
                            or item.get("feature")
                            or item.get("key")
                        )
                    )
                else:
                    result.append(
                        _safe_text(
                            getattr(item, "name", item)
                        )
                    )

            return _normalize_feature_names(result)
    except Exception:
        pass

    return []


def _model_feature_names(model: Any) -> list[str]:
    names = getattr(model, "feature_names_in_", None)

    if names is not None:
        try:
            return _normalize_feature_names(
                list(names),
                expected_count=len(names),
            )
        except Exception:
            pass

    count = getattr(model, "n_features_in_", None)

    if count is not None:
        count = _safe_int(count, 0)
        if 0 < count <= MAX_FEATURES:
            return [f"feature_{i}" for i in range(count)]

    return []


def _resolve_feature_names(
    model: Any,
    schema: Any = None,
    feature_names: Optional[Sequence[Any]] = None,
) -> list[str]:
    if feature_names is not None:
        names = _normalize_feature_names(feature_names)
        if names:
            return names

    schema_names = _feature_names_from_schema(schema)

    model_count = _safe_int(
        getattr(model, "n_features_in_", 0),
        0,
    )

    if schema_names:
        if model_count:
            return _normalize_feature_names(
                schema_names,
                expected_count=model_count,
            )
        return schema_names

    model_names = _model_feature_names(model)

    if model_names:
        return model_names

    raise ExplanationModelError(
        "Unable to determine model feature names."
    )


# ---------------------------------------------------------------------------
# Model loading
# ---------------------------------------------------------------------------


def load_explanation_artifacts(
    model_path: os.PathLike[str] | str = DEFAULT_MODEL_PATH,
    schema_path: os.PathLike[str] | str = DEFAULT_SCHEMA_PATH,
    metadata_path: os.PathLike[str] | str = DEFAULT_METADATA_PATH,
    thresholds_path: os.PathLike[str] | str = DEFAULT_THRESHOLDS_PATH,
) -> ModelArtifacts:
    """
    Load the model artifacts required for explanation.

    The implementation delegates model deserialization and artifact
    validation to the prediction layer.
    """
    try:
        return load_prediction_artifacts(
            model_path=model_path,
            schema_path=schema_path,
            metadata_path=metadata_path,
            thresholds_path=thresholds_path,
        )
    except Exception as exc:
        if isinstance(exc, ExplanationError):
            raise

        raise ExplanationModelError(
            f"Unable to load explanation artifacts: {exc}"
        ) from exc


# ---------------------------------------------------------------------------
# Global feature importance
# ---------------------------------------------------------------------------


def extract_model_importances(
    model: Any,
    feature_names: Sequence[Any],
) -> list[FeatureImportance]:
    """
    Extract and rank native model feature importances.

    Currently supports estimators exposing ``feature_importances_``,
    including RandomForestClassifier.
    """
    raw = getattr(model, "feature_importances_", None)

    if raw is None:
        raise ExplanationModelError(
            "The supplied model does not expose feature_importances_."
        )

    try:
        values = list(raw)
    except Exception as exc:
        raise ExplanationModelError(
            "Unable to read feature_importances_."
        ) from exc

    names = _normalize_feature_names(
        feature_names,
        expected_count=len(values),
    )

    normalized = _normalize_importances(values)

    indexed = list(
        zip(
            names,
            normalized,
            strict=False,
        )
    )

    indexed.sort(
        key=lambda item: (
            -item[1],
            item[0],
        )
    )

    result: list[FeatureImportance] = []

    for rank, (name, importance) in enumerate(indexed, start=1):
        result.append(
            FeatureImportance(
                feature=name,
                importance=float(importance),
                normalized_importance=float(importance),
                rank=rank,
                source="model",
            )
        )

    return result


def top_feature_importances(
    model: Any,
    feature_names: Sequence[Any],
    top_n: int = DEFAULT_TOP_N,
) -> list[FeatureImportance]:
    """Return the top native model feature importances."""
    top_n = _clamp(
        _safe_float(top_n, DEFAULT_TOP_N),
        1,
        MAX_TOP_N,
    )
    top_n = int(top_n)

    return extract_model_importances(
        model,
        feature_names,
    )[:top_n]


# ---------------------------------------------------------------------------
# Feature grouping
# ---------------------------------------------------------------------------


def _feature_group(feature_name: str) -> str:
    """
    Infer a stable logical group from a feature name.

    Examples:
        ``vba_execution_count`` -> ``vba``
        ``behavior_process_execution`` -> ``behavior``
        ``url_count`` -> ``url``
        ``entropy_mean`` -> ``common``
    """
    normalized = feature_name.strip().lower()

    if not normalized:
        return "unknown"

    prefixes = (
        "vba",
        "office",
        "xlm",
        "ole",
        "embedded",
        "script",
        "behavior",
        "process",
        "filesystem",
        "registry",
        "network",
        "persistence",
        "environment",
        "credential",
        "collection",
        "evasion",
        "url",
        "payload",
        "communication",
        "dynamic",
        "capability",
        "derived",
        "common",
        "file",
        "metadata",
    )

    for prefix in prefixes:
        if normalized == prefix or normalized.startswith(prefix + "_"):
            return prefix

    if "_" in normalized:
        first = normalized.split("_", 1)[0]

        if first in {
            "api",
            "macro",
            "document",
            "archive",
            "entropy",
            "string",
            "feature",
        }:
            return first

    return "other"


def aggregate_feature_groups(
    importances: Sequence[FeatureImportance],
) -> list[FeatureGroupImportance]:
    """Aggregate model feature importance into logical feature groups."""
    grouped: dict[str, list[FeatureImportance]] = {}

    for item in importances:
        group = _feature_group(item.feature)
        grouped.setdefault(group, []).append(item)

    result: list[FeatureGroupImportance] = []

    for group, items in grouped.items():
        ordered = sorted(
            items,
            key=lambda item: (
                -item.importance,
                item.feature,
            ),
        )

        result.append(
            FeatureGroupImportance(
                group=group,
                importance=float(
                    sum(item.importance for item in ordered)
                ),
                feature_count=len(ordered),
                top_features=tuple(
                    item.feature
                    for item in ordered[:10]
                ),
            )
        )

    result.sort(
        key=lambda item: (
            -item.importance,
            item.group,
        )
    )

    return result


# ---------------------------------------------------------------------------
# Dataset coercion
# ---------------------------------------------------------------------------


def _coerce_records(
    records: Iterable[Any],
    max_samples: int = MAX_SAMPLES,
) -> list[Any]:
    result: list[Any] = []

    for record in records:
        if len(result) >= max_samples:
            break
        result.append(record)

    return result


def _coerce_matrix(
    matrix: Any,
    expected_features: Optional[int] = None,
) -> list[list[float]]:
    if matrix is None:
        raise ExplanationDataError("Feature matrix is empty.")

    try:
        rows = list(matrix)
    except Exception as exc:
        raise ExplanationDataError(
            "Unable to iterate over feature matrix."
        ) from exc

    if len(rows) > MAX_SAMPLES:
        rows = rows[:MAX_SAMPLES]

    result: list[list[float]] = []

    width = expected_features

    for row in rows:
        try:
            values = list(row)
        except Exception as exc:
            raise ExplanationDataError(
                "Feature matrix contains a non-iterable row."
            ) from exc

        if width is None:
            width = len(values)

        if len(values) != width:
            raise ExplanationDataError(
                "Feature matrix rows have inconsistent feature counts."
            )

        cleaned = [
            _safe_float(value, 0.0)
            for value in values
        ]

        result.append(cleaned)

    if width is not None and width > MAX_FEATURES:
        raise ExplanationDataError(
            f"Feature matrix contains too many features: {width}."
        )

    return result


def _coerce_targets(
    values: Sequence[Any],
    expected_count: int,
) -> list[int]:
    if len(values) != expected_count:
        raise ExplanationDataError(
            "Target vector length does not match feature matrix."
        )

    result: list[int] = []

    for value in values:
        if isinstance(value, bool):
            result.append(int(value))
            continue

        numeric = _safe_float(value, math.nan)

        if math.isfinite(numeric):
            result.append(1 if numeric > 0 else 0)
            continue

        text = _safe_text(value).strip().lower()

        if text in {
            "1",
            "true",
            "yes",
            "positive",
            "malicious",
            "suspicious",
            "unsafe",
        }:
            result.append(1)
        elif text in {
            "0",
            "false",
            "no",
            "negative",
            "benign",
            "safe",
            "clean",
        }:
            result.append(0)
        else:
            raise ExplanationDataError(
                f"Unable to normalize target label: {value!r}"
            )

    return result


# ---------------------------------------------------------------------------
# Prediction helpers
# ---------------------------------------------------------------------------


def _positive_probability(model: Any, row: Sequence[float]) -> float:
    values = list(row)

    try:
        if hasattr(model, "predict_proba"):
            probability = model.predict_proba([values])

            if probability is not None:
                probabilities = list(probability[0])

                classes = getattr(
                    model,
                    "classes_",
                    list(range(len(probabilities))),
                )

                for index, class_value in enumerate(classes):
                    if _safe_float(class_value, 0.0) == 1.0:
                        return _clamp(
                            _safe_float(
                                probabilities[index],
                                0.0,
                            ),
                            0.0,
                            1.0,
                        )

                if len(probabilities) == 2:
                    return _clamp(
                        _safe_float(
                            probabilities[-1],
                            0.0,
                        ),
                        0.0,
                        1.0,
                    )

                if probabilities:
                    return _clamp(
                        _safe_float(
                            probabilities[0],
                            0.0,
                        ),
                        0.0,
                        1.0,
                    )
    except Exception:
        pass

    try:
        prediction = model.predict([values])[0]
        return 1.0 if _safe_float(prediction, 0.0) > 0 else 0.0
    except Exception as exc:
        raise ExplanationModelError(
            f"Unable to obtain model prediction: {exc}"
        ) from exc


# ---------------------------------------------------------------------------
# Baseline calculation
# ---------------------------------------------------------------------------


def feature_baselines(
    matrix: Sequence[Sequence[float]],
) -> list[float]:
    """
    Calculate a robust feature baseline using the median.

    The median is preferable to the mean for sparse malware-analysis
    feature vectors because many indicators are zero for most documents.
    """
    rows = _coerce_matrix(matrix)

    if not rows:
        raise ExplanationDataError("Cannot calculate baselines from no data.")

    width = len(rows[0])
    columns: list[list[float]] = [[] for _ in range(width)]

    for row in rows:
        for index, value in enumerate(row):
            columns[index].append(value)

    return [
        float(statistics.median(column))
        if column
        else 0.0
        for column in columns
    ]


def feature_scales(
    matrix: Sequence[Sequence[float]],
) -> list[float]:
    """
    Calculate robust feature scales using median absolute deviation.

    A minimum scale of 1.0 prevents divide-by-zero for binary/sparse
    indicators and keeps the heuristic contribution numerically stable.
    """
    rows = _coerce_matrix(matrix)

    if not rows:
        raise ExplanationDataError("Cannot calculate scales from no data.")

    baselines = feature_baselines(rows)
    width = len(rows[0])
    columns: list[list[float]] = [[] for _ in range(width)]

    for row in rows:
        for index, value in enumerate(row):
            columns[index].append(value)

    scales: list[float] = []

    for index, column in enumerate(columns):
        baseline = baselines[index]

        deviations = [
            abs(value - baseline)
            for value in column
        ]

        mad = (
            statistics.median(deviations)
            if deviations
            else 0.0
        )

        if mad <= EPSILON:
            spread = (
                max(column) - min(column)
                if column
                else 0.0
            )
            mad = spread

        scales.append(
            max(1.0, _safe_float(mad, 1.0))
        )

    return scales


# ---------------------------------------------------------------------------
# Sample-level heuristic explanation
# ---------------------------------------------------------------------------


def explain_sample_vector(
    model: Any,
    feature_names: Sequence[Any],
    vector: Sequence[Any],
    *,
    baseline: Optional[Sequence[Any]] = None,
    scales: Optional[Sequence[Any]] = None,
    threshold: float = 0.50,
    sample_id: str = "",
    top_n: int = DEFAULT_TOP_N,
) -> SampleExplanation:
    """
    Explain one numeric feature vector using model importance.

    This is a heuristic feature-ranking method, not an exact additive
    attribution method such as SHAP.
    """
    names = _normalize_feature_names(
        feature_names,
        expected_count=len(vector),
    )

    values = [
        _safe_float(value, 0.0)
        for value in vector
    ]

    if baseline is None:
        base = [0.0] * len(values)
    else:
        base = [
            _safe_float(value, 0.0)
            for value in baseline
        ]

    if len(base) != len(values):
        raise ExplanationDataError(
            "Baseline feature count does not match sample feature count."
        )

    if scales is None:
        scale_values = [1.0] * len(values)
    else:
        scale_values = [
            max(EPSILON, _safe_float(value, 1.0))
            for value in scales
        ]

    if len(scale_values) != len(values):
        raise ExplanationDataError(
            "Feature scale count does not match sample feature count."
        )

    raw_importance = getattr(model, "feature_importances_", None)

    if raw_importance is None:
        raise ExplanationModelError(
            "The supplied model does not expose feature_importances_."
        )

    importance = _normalize_importances(
        [
            _safe_float(value, 0.0)
            for value in list(raw_importance)
        ]
    )

    if len(importance) != len(values):
        raise ExplanationDataError(
            "Model feature importance count does not match feature vector."
        )

    threshold = _clamp(
        _safe_float(threshold, 0.50),
        0.0,
        1.0,
    )

    probability = _positive_probability(
        model,
        values,
    )

    prediction = int(probability >= threshold)

    contributions: list[SampleFeatureContribution] = []

    for index, value in enumerate(values):
        delta = value - base[index]
        normalized_delta = delta / scale_values[index]

        signed_score = (
            normalized_delta * importance[index]
        )

        contributions.append(
            SampleFeatureContribution(
                feature=names[index],
                value=float(value),
                baseline=float(base[index]),
                delta=float(delta),
                normalized_delta=float(normalized_delta),
                model_importance=float(importance[index]),
                signed_score=float(signed_score),
                absolute_score=float(abs(signed_score)),
                rank=0,
            )
        )

    contributions.sort(
        key=lambda item: (
            -item.absolute_score,
            -item.model_importance,
            item.feature,
        )
    )

    top_n = int(
        _clamp(
            _safe_float(top_n, DEFAULT_TOP_N),
            1,
            MAX_TOP_N,
        )
    )

    ranked: list[SampleFeatureContribution] = []

    for rank, item in enumerate(
        contributions[:top_n],
        start=1,
    ):
        ranked.append(
            SampleFeatureContribution(
                feature=item.feature,
                value=item.value,
                baseline=item.baseline,
                delta=item.delta,
                normalized_delta=item.normalized_delta,
                model_importance=item.model_importance,
                signed_score=item.signed_score,
                absolute_score=item.absolute_score,
                rank=rank,
            )
        )

    return SampleExplanation(
        sample_id=_safe_text(sample_id),
        probability=float(probability),
        prediction=prediction,
        threshold=threshold,
        risk_label=(
            "malicious_or_suspicious"
            if prediction
            else "benign_or_low_risk"
        ),
        top_features=tuple(ranked),
    )


def explain_record(
    artifacts: ModelArtifacts,
    record: Any,
    *,
    baseline: Optional[Sequence[Any]] = None,
    scales: Optional[Sequence[Any]] = None,
    baseline_matrix: Optional[Sequence[Sequence[Any]]] = None,
    threshold: Optional[float] = None,
    top_n: int = DEFAULT_TOP_N,
) -> SampleExplanation:
    """Explain one dataset/analysis record."""
    model = artifacts.model

    try:
        vector, sample_id, missing, unknown, _unknown_names = (
            vectorize_record(
                artifacts,
                record,
            )
        )
    except Exception as exc:
        raise ExplanationDataError(
            f"Unable to vectorize record for explanation: {exc}"
        ) from exc

    if baseline is None and baseline_matrix is not None:
        baseline = feature_baselines(
            baseline_matrix,
        )

    if scales is None and baseline_matrix is not None:
        scales = feature_scales(
            baseline_matrix,
        )

    selected_threshold = (
        _safe_float(
            threshold,
            getattr(artifacts, "threshold", 0.50),
        )
    )

    explanation = explain_sample_vector(
        model,
        artifacts.feature_names,
        vector,
        baseline=baseline,
        scales=scales,
        threshold=selected_threshold,
        sample_id=sample_id,
        top_n=top_n,
    )

    return SampleExplanation(
        sample_id=explanation.sample_id,
        probability=explanation.probability,
        prediction=explanation.prediction,
        threshold=explanation.threshold,
        risk_label=explanation.risk_label,
        top_features=explanation.top_features,
        missing_features=_safe_int(missing, 0),
        unknown_features=_safe_int(unknown, 0),
    )


# ---------------------------------------------------------------------------
# Permutation importance
# ---------------------------------------------------------------------------


def _deterministic_permutation(
    values: Sequence[Any],
    seed: int,
) -> list[Any]:
    """
    Deterministically permute a sequence using a local linear-congruential
    generator.

    This avoids dependence on global random state.
    """
    result = list(values)

    if len(result) <= 1:
        return result

    state = seed & 0xFFFFFFFF

    for index in range(len(result) - 1, 0, -1):
        state = (
            1664525 * state + 1013904223
        ) & 0xFFFFFFFF

        swap_index = state % (index + 1)

        result[index], result[swap_index] = (
            result[swap_index],
            result[index],
        )

    return result


def _binary_accuracy(
    model: Any,
    matrix: Sequence[Sequence[float]],
    targets: Sequence[int],
) -> float:
    if len(matrix) != len(targets):
        raise ExplanationDataError(
            "Matrix and target lengths differ."
        )

    if not matrix:
        return 0.0

    correct = 0

    try:
        predictions = model.predict(matrix)
        predictions = list(predictions)
    except Exception as exc:
        raise ExplanationModelError(
            f"Unable to obtain predictions for permutation importance: {exc}"
        ) from exc

    for prediction, target in zip(
        predictions,
        targets,
        strict=False,
    ):
        predicted = (
            1
            if _safe_float(prediction, 0.0) > 0
            else 0
        )

        if predicted == int(target):
            correct += 1

    return correct / len(matrix)


def permutation_importance(
    model: Any,
    matrix: Sequence[Sequence[Any]],
    targets: Sequence[Any],
    feature_names: Sequence[Any],
    *,
    repeats: int = DEFAULT_PERMUTATION_REPEATS,
    top_n: Optional[int] = DEFAULT_TOP_N,
    seed: int = 1337,
) -> list[PermutationImportance]:
    """
    Calculate deterministic permutation importance.

    The score is the decrease in classification accuracy after shuffling
    one feature. Positive values indicate that the feature contributes to
    predictive accuracy under this evaluation set.
    """
    rows = _coerce_matrix(matrix)

    if not rows:
        raise ExplanationDataError(
            "Cannot calculate permutation importance on an empty dataset."
        )

    targets_normalized = _coerce_targets(
        list(targets),
        len(rows),
    )

    width = len(rows[0])

    names = _normalize_feature_names(
        feature_names,
        expected_count=width,
    )

    repeats = int(
        _clamp(
            _safe_float(
                repeats,
                DEFAULT_PERMUTATION_REPEATS,
            ),
            1,
            MAX_PERMUTATION_REPEATS,
        )
    )

    baseline_accuracy = _binary_accuracy(
        model,
        rows,
        targets_normalized,
    )

    results: list[PermutationImportance] = []

    for feature_index in range(width):
        original_column = [
            row[feature_index]
            for row in rows
        ]

        decreases: list[float] = []

        for repeat_index in range(repeats):
            shuffled = _deterministic_permutation(
                original_column,
                seed=(
                    int(seed)
                    + feature_index * 1_000_003
                    + repeat_index * 97_003
                ),
            )

            modified = [
                list(row)
                for row in rows
            ]

            for row_index, value in enumerate(shuffled):
                modified[row_index][feature_index] = value

            accuracy = _binary_accuracy(
                model,
                modified,
                targets_normalized,
            )

            decreases.append(
                baseline_accuracy - accuracy
            )

        mean_value = (
            statistics.mean(decreases)
            if decreases
            else 0.0
        )

        std_value = (
            statistics.pstdev(decreases)
            if len(decreases) > 1
            else 0.0
        )

        results.append(
            PermutationImportance(
                feature=names[feature_index],
                mean_decrease=float(mean_value),
                std_decrease=float(std_value),
                min_decrease=float(min(decreases)),
                max_decrease=float(max(decreases)),
                repeats=repeats,
                rank=0,
            )
        )

    results.sort(
        key=lambda item: (
            -item.mean_decrease,
            -abs(item.mean_decrease),
            item.feature,
        )
    )

    ranked = [
        PermutationImportance(
            feature=item.feature,
            mean_decrease=item.mean_decrease,
            std_decrease=item.std_decrease,
            min_decrease=item.min_decrease,
            max_decrease=item.max_decrease,
            repeats=item.repeats,
            rank=index,
        )
        for index, item in enumerate(
            results,
            start=1,
        )
    ]

    if top_n is not None:
        top_n = int(
            _clamp(
                _safe_float(top_n, DEFAULT_TOP_N),
                1,
                MAX_TOP_N,
            )
        )
        ranked = ranked[:top_n]

    return ranked


# ---------------------------------------------------------------------------
# Complete explanation
# ---------------------------------------------------------------------------


def explain_model(
    artifacts: ModelArtifacts,
    *,
    feature_names: Optional[Sequence[Any]] = None,
    top_n: int = DEFAULT_TOP_N,
    matrix: Optional[Sequence[Sequence[Any]]] = None,
    targets: Optional[Sequence[Any]] = None,
    permutation_repeats: int = DEFAULT_PERMUTATION_REPEATS,
    permutation_seed: int = 1337,
    records: Optional[Iterable[Any]] = None,
    sample_limit: int = 25,
    baseline_matrix: Optional[Sequence[Sequence[Any]]] = None,
) -> ExplanationResult:
    """
    Produce a complete model explanation.

    Native model importance is always generated. Permutation importance is
    generated when both ``matrix`` and ``targets`` are supplied. Sample-level
    explanations are generated when ``records`` are supplied.
    """
    model = artifacts.model

    resolved_names = _resolve_feature_names(
        model,
        getattr(artifacts, "schema", None),
        feature_names or getattr(
            artifacts,
            "feature_names",
            None,
        ),
    )

    native_importance = extract_model_importances(
        model,
        resolved_names,
    )

    top_n = int(
        _clamp(
            _safe_float(top_n, DEFAULT_TOP_N),
            1,
            MAX_TOP_N,
        )
    )

    groups = aggregate_feature_groups(
        native_importance,
    )

    selected_matrix = matrix

    if selected_matrix is not None:
        selected_matrix = _coerce_matrix(
            selected_matrix,
            expected_features=len(resolved_names),
        )

    permutation: list[PermutationImportance] = []

    if selected_matrix is not None and targets is not None:
        permutation = permutation_importance(
            model,
            selected_matrix,
            targets,
            resolved_names,
            repeats=permutation_repeats,
            top_n=top_n,
            seed=permutation_seed,
        )

    sample_explanations: list[SampleExplanation] = []

    if records is not None:
        selected_records = _coerce_records(
            records,
            max_samples=int(
                _clamp(
                    _safe_float(sample_limit, 25),
                    1,
                    MAX_SAMPLES,
                )
            ),
        )

        reference_matrix = baseline_matrix

        if reference_matrix is None:
            reference_matrix = selected_matrix

        baseline = None
        scales = None

        if reference_matrix:
            baseline = feature_baselines(
                reference_matrix,
            )
            scales = feature_scales(
                reference_matrix,
            )

        for record in selected_records:
            sample_explanations.append(
                explain_record(
                    artifacts,
                    record,
                    baseline=baseline,
                    scales=scales,
                    top_n=top_n,
                )
            )

    metadata = {
        "explanation_method": (
            "native_model_importance"
            " + optional_permutation_importance"
            " + heuristic_sample_ranking"
        ),
        "sample_attribution_note": (
            "Sample-level signed scores are heuristic rankings and are not "
            "exact additive model attributions."
        ),
        "permutation_repeats": int(permutation_repeats),
        "permutation_seed": int(permutation_seed),
        "feature_groups": len(groups),
        "samples_explained": len(sample_explanations),
    }

    return ExplanationResult(
        model_path=_safe_text(
            getattr(artifacts, "model_path", DEFAULT_MODEL_PATH)
        ),
        schema_path=_safe_text(
            getattr(artifacts, "schema_path", DEFAULT_SCHEMA_PATH)
        ),
        model_type=_safe_text(
            getattr(artifacts, "model_type", type(model).__name__),
            type(model).__name__,
        ),
        model_version=_safe_text(
            getattr(artifacts, "model_version", ""),
        ),
        threshold=_safe_float(
            getattr(artifacts, "threshold", 0.50),
            0.50,
        ),
        feature_count=len(resolved_names),
        global_importance=tuple(
            native_importance[:top_n]
        ),
        feature_groups=tuple(groups),
        permutation_importance=tuple(permutation),
        sample_explanations=tuple(sample_explanations),
        metadata=metadata,
    )


def explain_dataset(
    artifacts: ModelArtifacts,
    dataset: Dataset,
    *,
    top_n: int = DEFAULT_TOP_N,
    permutation_repeats: int = DEFAULT_PERMUTATION_REPEATS,
    permutation_seed: int = 1337,
    sample_limit: int = 25,
) -> ExplanationResult:
    """Explain a Pharos dataset."""
    try:
        matrix = feature_matrix(dataset)
    except Exception as exc:
        raise ExplanationDataError(
            f"Unable to construct dataset feature matrix: {exc}"
        ) from exc

    try:
        targets = target_vector(dataset)
    except Exception as exc:
        raise ExplanationDataError(
            f"Unable to construct dataset target vector: {exc}"
        ) from exc

    return explain_model(
        artifacts,
        top_n=top_n,
        matrix=matrix,
        targets=targets,
        permutation_repeats=permutation_repeats,
        permutation_seed=permutation_seed,
        records=dataset.records,
        sample_limit=sample_limit,
        baseline_matrix=matrix,
    )


def explain_dataset_path(
    dataset_path: os.PathLike[str] | str,
    *,
    model_path: os.PathLike[str] | str = DEFAULT_MODEL_PATH,
    schema_path: os.PathLike[str] | str = DEFAULT_SCHEMA_PATH,
    metadata_path: os.PathLike[str] | str = DEFAULT_METADATA_PATH,
    thresholds_path: os.PathLike[str] | str = DEFAULT_THRESHOLDS_PATH,
    top_n: int = DEFAULT_TOP_N,
    permutation_repeats: int = DEFAULT_PERMUTATION_REPEATS,
    permutation_seed: int = 1337,
    sample_limit: int = 25,
) -> ExplanationResult:
    """Load a dataset and produce a complete model explanation."""
    try:
        dataset = load_dataset(dataset_path)
    except Exception as exc:
        raise ExplanationDataError(
            f"Unable to load dataset: {exc}"
        ) from exc

    artifacts = load_explanation_artifacts(
        model_path=model_path,
        schema_path=schema_path,
        metadata_path=metadata_path,
        thresholds_path=thresholds_path,
    )

    return explain_dataset(
        artifacts,
        dataset,
        top_n=top_n,
        permutation_repeats=permutation_repeats,
        permutation_seed=permutation_seed,
        sample_limit=sample_limit,
    )


# ---------------------------------------------------------------------------
# Serialization
# ---------------------------------------------------------------------------


def _feature_importance_to_dict(
    item: FeatureImportance,
) -> dict[str, Any]:
    return {
        "feature": item.feature,
        "importance": item.importance,
        "normalized_importance": item.normalized_importance,
        "rank": item.rank,
        "source": item.source,
    }


def _permutation_to_dict(
    item: PermutationImportance,
) -> dict[str, Any]:
    return {
        "feature": item.feature,
        "mean_decrease": item.mean_decrease,
        "std_decrease": item.std_decrease,
        "min_decrease": item.min_decrease,
        "max_decrease": item.max_decrease,
        "repeats": item.repeats,
        "rank": item.rank,
    }


def _sample_feature_to_dict(
    item: SampleFeatureContribution,
) -> dict[str, Any]:
    return {
        "feature": item.feature,
        "value": item.value,
        "baseline": item.baseline,
        "delta": item.delta,
        "normalized_delta": item.normalized_delta,
        "model_importance": item.model_importance,
        "signed_score": item.signed_score,
        "absolute_score": item.absolute_score,
        "rank": item.rank,
    }


def _sample_explanation_to_dict(
    item: SampleExplanation,
) -> dict[str, Any]:
    return {
        "sample_id": item.sample_id,
        "probability": item.probability,
        "prediction": item.prediction,
        "threshold": item.threshold,
        "risk_label": item.risk_label,
        "missing_features": item.missing_features,
        "unknown_features": item.unknown_features,
        "top_features": [
            _sample_feature_to_dict(feature)
            for feature in item.top_features
        ],
    }


def explanation_to_dict(
    result: ExplanationResult,
) -> dict[str, Any]:
    """Convert an explanation result to a JSON-compatible dictionary."""
    return {
        "model_path": result.model_path,
        "schema_path": result.schema_path,
        "model_type": result.model_type,
        "model_version": result.model_version,
        "threshold": result.threshold,
        "feature_count": result.feature_count,
        "global_importance": [
            _feature_importance_to_dict(item)
            for item in result.global_importance
        ],
        "feature_groups": [
            {
                "group": item.group,
                "importance": item.importance,
                "feature_count": item.feature_count,
                "top_features": list(item.top_features),
            }
            for item in result.feature_groups
        ],
        "permutation_importance": [
            _permutation_to_dict(item)
            for item in result.permutation_importance
        ],
        "sample_explanations": [
            _sample_explanation_to_dict(item)
            for item in result.sample_explanations
        ],
        "metadata": _json_safe(result.metadata),
    }


def explanation_to_json(
    result: ExplanationResult,
    *,
    indent: int = 2,
) -> str:
    """Serialize an explanation result to JSON."""
    return json.dumps(
        explanation_to_dict(result),
        indent=indent,
        sort_keys=True,
        ensure_ascii=False,
        allow_nan=False,
    )


def save_explanation_json(
    result: ExplanationResult,
    path: os.PathLike[str] | str = DEFAULT_OUTPUT_PATH,
    *,
    indent: int = 2,
) -> Path:
    """Atomically save an explanation result as JSON."""
    destination = Path(path)
    destination.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    payload = explanation_to_json(
        result,
        indent=indent,
    )

    if len(payload.encode("utf-8")) > MAX_JSON_SIZE:
        raise ExplanationDataError(
            "Explanation JSON exceeds configured size limit."
        )

    fd, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.",
        suffix=".tmp",
        dir=str(destination.parent),
        text=True,
    )

    try:
        with os.fdopen(
            fd,
            "w",
            encoding="utf-8",
            newline="\n",
        ) as handle:
            handle.write(payload)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())

        os.replace(
            temporary_name,
            destination,
        )
    except Exception:
        try:
            os.unlink(temporary_name)
        except OSError:
            pass
        raise

    return destination


def save_feature_importance_csv(
    importances: Sequence[FeatureImportance],
    path: os.PathLike[str] | str,
) -> Path:
    """Save native model feature importance to CSV."""
    destination = Path(path)
    destination.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    fd, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.",
        suffix=".tmp",
        dir=str(destination.parent),
        text=True,
    )

    try:
        with os.fdopen(
            fd,
            "w",
            encoding="utf-8",
            newline="",
        ) as handle:
            writer = csv.DictWriter(
                handle,
                fieldnames=[
                    "rank",
                    "feature",
                    "importance",
                    "normalized_importance",
                    "source",
                ],
            )

            writer.writeheader()

            for item in importances:
                writer.writerow(
                    {
                        "rank": item.rank,
                        "feature": item.feature,
                        "importance": item.importance,
                        "normalized_importance": (
                            item.normalized_importance
                        ),
                        "source": item.source,
                    }
                )

            handle.flush()
            os.fsync(handle.fileno())

        os.replace(
            temporary_name,
            destination,
        )
    except Exception:
        try:
            os.unlink(temporary_name)
        except OSError:
            pass
        raise

    return destination


def save_permutation_importance_csv(
    importances: Sequence[PermutationImportance],
    path: os.PathLike[str] | str,
) -> Path:
    """Save permutation importance to CSV."""
    destination = Path(path)
    destination.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    fd, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.",
        suffix=".tmp",
        dir=str(destination.parent),
        text=True,
    )

    try:
        with os.fdopen(
            fd,
            "w",
            encoding="utf-8",
            newline="",
        ) as handle:
            writer = csv.DictWriter(
                handle,
                fieldnames=[
                    "rank",
                    "feature",
                    "mean_decrease",
                    "std_decrease",
                    "min_decrease",
                    "max_decrease",
                    "repeats",
                ],
            )

            writer.writeheader()

            for item in importances:
                writer.writerow(
                    {
                        "rank": item.rank,
                        "feature": item.feature,
                        "mean_decrease": item.mean_decrease,
                        "std_decrease": item.std_decrease,
                        "min_decrease": item.min_decrease,
                        "max_decrease": item.max_decrease,
                        "repeats": item.repeats,
                    }
                )

            handle.flush()
            os.fsync(handle.fileno())

        os.replace(
            temporary_name,
            destination,
        )
    except Exception:
        try:
            os.unlink(temporary_name)
        except OSError:
            pass
        raise

    return destination


# ---------------------------------------------------------------------------
# Summaries and iterators
# ---------------------------------------------------------------------------


def summarize_explanation(
    result: ExplanationResult,
) -> dict[str, Any]:
    """Return a compact operational summary."""
    top_global = list(result.global_importance[:10])

    top_groups = list(result.feature_groups[:10])

    top_permutation = list(
        result.permutation_importance[:10]
    )

    sample_risk_count = sum(
        item.prediction
        for item in result.sample_explanations
    )

    return {
        "model_type": result.model_type,
        "model_version": result.model_version,
        "threshold": result.threshold,
        "feature_count": result.feature_count,
        "top_features": [
            {
                "feature": item.feature,
                "importance": item.importance,
                "rank": item.rank,
            }
            for item in top_global
        ],
        "top_feature_groups": [
            {
                "group": item.group,
                "importance": item.importance,
                "feature_count": item.feature_count,
            }
            for item in top_groups
        ],
        "top_permutation_features": [
            {
                "feature": item.feature,
                "mean_decrease": item.mean_decrease,
                "rank": item.rank,
            }
            for item in top_permutation
        ],
        "samples_explained": len(
            result.sample_explanations
        ),
        "samples_predicted_positive": sample_risk_count,
    }


def iter_feature_importances(
    result: ExplanationResult,
) -> Iterable[FeatureImportance]:
    """Iterate over global feature importance records."""
    yield from result.global_importance


def iter_feature_groups(
    result: ExplanationResult,
) -> Iterable[FeatureGroupImportance]:
    """Iterate over feature-group importance records."""
    yield from result.feature_groups


def iter_permutation_importances(
    result: ExplanationResult,
) -> Iterable[PermutationImportance]:
    """Iterate over permutation-importance records."""
    yield from result.permutation_importance


def iter_sample_explanations(
    result: ExplanationResult,
) -> Iterable[SampleExplanation]:
    """Iterate over sample explanations."""
    yield from result.sample_explanations


# ---------------------------------------------------------------------------
# Convenience APIs
# ---------------------------------------------------------------------------


def explain(
    model_path: os.PathLike[str] | str = DEFAULT_MODEL_PATH,
    *,
    dataset_path: Optional[os.PathLike[str] | str] = None,
    schema_path: os.PathLike[str] | str = DEFAULT_SCHEMA_PATH,
    metadata_path: os.PathLike[str] | str = DEFAULT_METADATA_PATH,
    thresholds_path: os.PathLike[str] | str = DEFAULT_THRESHOLDS_PATH,
    top_n: int = DEFAULT_TOP_N,
    permutation_repeats: int = DEFAULT_PERMUTATION_REPEATS,
    permutation_seed: int = 1337,
    sample_limit: int = 25,
) -> ExplanationResult:
    """
    High-level explanation entry point.

    If ``dataset_path`` is supplied, global, permutation, and sample-level
    explanations are generated. Otherwise only native model explanations
    are generated.
    """
    artifacts = load_explanation_artifacts(
        model_path=model_path,
        schema_path=schema_path,
        metadata_path=metadata_path,
        thresholds_path=thresholds_path,
    )

    if dataset_path is None:
        return explain_model(
            artifacts,
            top_n=top_n,
            permutation_repeats=permutation_repeats,
            permutation_seed=permutation_seed,
            sample_limit=sample_limit,
        )

    return explain_dataset_path(
        dataset_path,
        model_path=model_path,
        schema_path=schema_path,
        metadata_path=metadata_path,
        thresholds_path=thresholds_path,
        top_n=top_n,
        permutation_repeats=permutation_repeats,
        permutation_seed=permutation_seed,
        sample_limit=sample_limit,
    )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_argument_parser() -> Any:
    """Build the command-line argument parser."""
    import argparse

    parser = argparse.ArgumentParser(
        description=(
            "Generate static explanations for a Pharos CDR ML model."
        )
    )

    parser.add_argument(
        "--model",
        default=str(DEFAULT_MODEL_PATH),
        help="Path to the trained model artifact.",
    )

    parser.add_argument(
        "--schema",
        default=str(DEFAULT_SCHEMA_PATH),
        help="Path to the feature schema.",
    )

    parser.add_argument(
        "--metadata",
        default=str(DEFAULT_METADATA_PATH),
        help="Path to model metadata JSON.",
    )

    parser.add_argument(
        "--thresholds",
        default=str(DEFAULT_THRESHOLDS_PATH),
        help="Path to thresholds JSON.",
    )

    parser.add_argument(
        "--dataset",
        default=None,
        help="Optional dataset path for permutation/sample explanations.",
    )

    parser.add_argument(
        "--output",
        default=str(DEFAULT_OUTPUT_PATH),
        help="Output JSON path.",
    )

    parser.add_argument(
        "--top",
        type=int,
        default=DEFAULT_TOP_N,
        help=f"Number of top features to retain, maximum {MAX_TOP_N}.",
    )

    parser.add_argument(
        "--permutation-repeats",
        type=int,
        default=DEFAULT_PERMUTATION_REPEATS,
        help=(
            "Number of deterministic permutation repeats. "
            f"Maximum {MAX_PERMUTATION_REPEATS}."
        ),
    )

    parser.add_argument(
        "--permutation-seed",
        type=int,
        default=1337,
        help="Deterministic permutation seed.",
    )

    parser.add_argument(
        "--sample-limit",
        type=int,
        default=25,
        help="Maximum number of dataset records to explain.",
    )

    parser.add_argument(
        "--summary",
        action="store_true",
        help="Print a compact explanation summary instead of full JSON.",
    )

    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    """CLI entry point."""
    parser = build_argument_parser()
    args = parser.parse_args(argv)

    try:
        result = explain(
            model_path=args.model,
            dataset_path=args.dataset,
            schema_path=args.schema,
            metadata_path=args.metadata,
            thresholds_path=args.thresholds,
            top_n=args.top,
            permutation_repeats=args.permutation_repeats,
            permutation_seed=args.permutation_seed,
            sample_limit=args.sample_limit,
        )

        if args.summary:
            print(
                json.dumps(
                    summarize_explanation(result),
                    indent=2,
                    sort_keys=True,
                    ensure_ascii=False,
                )
            )
        else:
            output_path = save_explanation_json(
                result,
                args.output,
            )
            print(
                json.dumps(
                    {
                        "output": str(output_path),
                        "summary": summarize_explanation(result),
                    },
                    indent=2,
                    sort_keys=True,
                    ensure_ascii=False,
                )
            )

        return 0

    except ExplanationError as exc:
        parser.error(str(exc))
        return 2
    except KeyboardInterrupt:
        return 130


# ---------------------------------------------------------------------------
# Public APIs
# ---------------------------------------------------------------------------

__all__ = [
    "ExplanationError",
    "ExplanationModelError",
    "ExplanationDataError",
    "ExplanationDependencyError",
    "FeatureImportance",
    "PermutationImportance",
    "SampleFeatureContribution",
    "SampleExplanation",
    "FeatureGroupImportance",
    "ExplanationResult",
    "load_explanation_artifacts",
    "extract_model_importances",
    "top_feature_importances",
    "aggregate_feature_groups",
    "feature_baselines",
    "feature_scales",
    "explain_sample_vector",
    "explain_record",
    "permutation_importance",
    "explain_model",
    "explain_dataset",
    "explain_dataset_path",
    "explanation_to_dict",
    "explanation_to_json",
    "save_explanation_json",
    "save_feature_importance_csv",
    "save_permutation_importance_csv",
    "summarize_explanation",
    "iter_feature_importances",
    "iter_feature_groups",
    "iter_permutation_importances",
    "iter_sample_explanations",
    "explain",
    "build_argument_parser",
    "main",
]


if __name__ == "__main__":
    raise SystemExit(main())