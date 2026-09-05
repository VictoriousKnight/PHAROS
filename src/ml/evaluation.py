"""
pharos-cdr.src.ml.evaluation
============================

Model evaluation utilities for the Pharos CDR malware/document classifier.

This module evaluates already-extracted feature datasets against a trained
classifier. It does not execute samples, macros, scripts, URLs, or documents.

The evaluator supports:

* Accuracy, balanced accuracy, precision, recall, F1.
* Specificity and false-positive rate.
* Confusion matrices.
* ROC-AUC and PR-AUC when probabilities are available.
* Threshold sweeps.
* Per-class metrics.
* Prediction-level records.
* Dataset-level evaluation.
* Cross-validation evaluation for compatible estimators.
* JSON and CSV persistence.
* Deterministic summaries suitable for reports and CI checks.

Expected model artifacts:

models/
    trained/
        random_forest.joblib

models/metadata/
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
import statistics
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import (
    Any,
    Dict,
    Iterable,
    List,
    Mapping,
    Optional,
    Sequence,
    Tuple,
)

try:
    from .dataset import (
        Dataset,
        DatasetRecord,
        load_dataset,
    )
    from .predict import (
        ModelArtifacts,
        PredictionConfig,
        load_prediction_artifacts,
        vectorize_record,
        predict_probability,
    )
except ImportError:  # pragma: no cover
    from dataset import (  # type: ignore
        Dataset,
        DatasetRecord,
        load_dataset,
    )
    from predict import (  # type: ignore
        ModelArtifacts,
        PredictionConfig,
        load_prediction_artifacts,
        vectorize_record,
        predict_probability,
    )


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_MODEL_PATH = Path(
    "models/trained/random_forest.joblib"
)

DEFAULT_SCHEMA_PATH = Path(
    "models/metadata/feature_schema.json"
)

DEFAULT_METADATA_PATH = Path(
    "models/metadata/model_metadata.json"
)

DEFAULT_THRESHOLDS_PATH = Path(
    "models/metadata/thresholds.json"
)

DEFAULT_OUTPUT_PATH = Path(
    "outputs/reports/model_evaluation.json"
)

DEFAULT_THRESHOLD = 0.50

MAX_EVALUATION_SAMPLES = 2_000_000
MAX_THRESHOLDS = 10_001

POSITIVE_LABEL = 1
NEGATIVE_LABEL = 0

POSITIVE_LABEL_NAME = "malicious"
NEGATIVE_LABEL_NAME = "benign"

EPSILON = 1e-12


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class EvaluationError(RuntimeError):
    """Base exception for model evaluation errors."""


class EvaluationDataError(EvaluationError):
    """Raised when evaluation data is invalid."""


class EvaluationMetricError(EvaluationError):
    """Raised when a metric cannot be computed."""


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ConfusionMatrix:
    """Binary confusion matrix."""

    true_negative: int
    false_positive: int
    false_negative: int
    true_positive: int

    @property
    def total(self) -> int:
        return (
            self.true_negative
            + self.false_positive
            + self.false_negative
            + self.true_positive
        )

    def to_dict(self) -> Dict[str, int]:
        return {
            "true_negative": self.true_negative,
            "false_positive": self.false_positive,
            "false_negative": self.false_negative,
            "true_positive": self.true_positive,
            "total": self.total,
        }


@dataclass(frozen=True)
class ClassificationMetrics:
    """Binary classification metrics."""

    accuracy: float
    balanced_accuracy: float

    precision: float
    recall: float
    f1: float

    specificity: float
    false_positive_rate: float
    false_negative_rate: float

    positive_predictive_value: float
    negative_predictive_value: float

    sensitivity: float
    prevalence: float

    matthews_correlation: float
    diagnostic_odds_ratio: Optional[float]

    support: int
    positive_support: int
    negative_support: int

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class RankingMetrics:
    """Threshold-independent ranking metrics."""

    roc_auc: Optional[float]
    average_precision: Optional[float]
    pr_auc: Optional[float]

    score_count: int
    positive_count: int
    negative_count: int

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ThresholdMetrics:
    """Metrics calculated at one classification threshold."""

    threshold: float
    confusion_matrix: ConfusionMatrix
    metrics: ClassificationMetrics

    def to_dict(self) -> Dict[str, Any]:
        return {
            "threshold": self.threshold,
            "confusion_matrix": self.confusion_matrix.to_dict(),
            "metrics": self.metrics.to_dict(),
        }


@dataclass(frozen=True)
class ThresholdSelection:
    """Result of selecting an operational threshold."""

    selected_threshold: float
    criterion: str
    objective_value: float

    candidates_evaluated: int

    metrics: ThresholdMetrics

    def to_dict(self) -> Dict[str, Any]:
        return {
            "selected_threshold": self.selected_threshold,
            "criterion": self.criterion,
            "objective_value": self.objective_value,
            "candidates_evaluated": self.candidates_evaluated,
            "metrics": self.metrics.to_dict(),
        }


@dataclass
class EvaluationPrediction:
    """Prediction information retained for one evaluation sample."""

    sample_id: Optional[str]

    actual_label: int
    actual_label_name: str

    predicted_label: int
    predicted_label_name: str

    probability_malicious: float
    probability_benign: float

    threshold: float
    correct: bool

    missing_feature_count: int
    unknown_feature_count: int

    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class EvaluationResult:
    """Complete model evaluation result."""

    model_type: str
    model_version: str

    model_path: str
    schema_path: str

    threshold: float

    sample_count: int
    labeled_sample_count: int

    confusion_matrix: ConfusionMatrix
    metrics: ClassificationMetrics
    ranking: RankingMetrics

    threshold_selection: Optional[ThresholdSelection]

    class_distribution: Dict[str, int]

    predictions: List[EvaluationPrediction] = field(
        default_factory=list
    )

    metadata: Dict[str, Any] = field(
        default_factory=dict
    )

    def to_dict(
        self,
        *,
        include_predictions: bool = True,
    ) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "model": {
                "type": self.model_type,
                "version": self.model_version,
                "path": self.model_path,
                "schema_path": self.schema_path,
            },
            "threshold": self.threshold,
            "sample_count": self.sample_count,
            "labeled_sample_count": self.labeled_sample_count,
            "confusion_matrix": self.confusion_matrix.to_dict(),
            "metrics": self.metrics.to_dict(),
            "ranking": self.ranking.to_dict(),
            "threshold_selection": (
                self.threshold_selection.to_dict()
                if self.threshold_selection is not None
                else None
            ),
            "class_distribution": self.class_distribution,
            "metadata": self.metadata,
        }

        if include_predictions:
            payload["predictions"] = [
                prediction.to_dict()
                for prediction in self.predictions
            ]

        return payload


@dataclass(frozen=True)
class CrossValidationFold:
    """Metrics for one cross-validation fold."""

    fold: int
    sample_count: int
    confusion_matrix: ConfusionMatrix
    metrics: ClassificationMetrics
    ranking: RankingMetrics

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class CrossValidationResult:
    """Cross-validation summary."""

    folds: List[CrossValidationFold]

    mean_accuracy: float
    mean_balanced_accuracy: float
    mean_precision: float
    mean_recall: float
    mean_f1: float

    std_accuracy: float
    std_balanced_accuracy: float
    std_precision: float
    std_recall: float
    std_f1: float

    def to_dict(self) -> Dict[str, Any]:
        return {
            "folds": [
                fold.to_dict()
                for fold in self.folds
            ],
            "mean": {
                "accuracy": self.mean_accuracy,
                "balanced_accuracy": self.mean_balanced_accuracy,
                "precision": self.mean_precision,
                "recall": self.mean_recall,
                "f1": self.mean_f1,
            },
            "std": {
                "accuracy": self.std_accuracy,
                "balanced_accuracy": self.std_balanced_accuracy,
                "precision": self.std_precision,
                "recall": self.std_recall,
                "f1": self.std_f1,
            },
        }


# ---------------------------------------------------------------------------
# Generic helpers
# ---------------------------------------------------------------------------


def _safe_float(
    value: Any,
    default: float = 0.0,
) -> float:
    try:
        result = float(value)
    except (TypeError, ValueError):
        return default

    if not math.isfinite(result):
        return default

    return result


def _safe_int(
    value: Any,
    default: int = 0,
) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _clamp_probability(
    value: Any,
) -> float:
    result = _safe_float(
        value,
        default=float("nan"),
    )

    if not math.isfinite(result):
        raise EvaluationMetricError(
            f"Invalid probability: {value!r}"
        )

    if result < 0.0 or result > 1.0:
        raise EvaluationMetricError(
            f"Probability outside [0, 1]: {result}"
        )

    return result


def _validate_binary_labels(
    labels: Sequence[Any],
) -> List[int]:
    """Normalize evaluation labels to 0/1."""
    normalized: List[int] = []

    for index, value in enumerate(labels):
        if isinstance(value, bool):
            normalized.append(
                POSITIVE_LABEL
                if value
                else NEGATIVE_LABEL
            )
            continue

        if isinstance(value, str):
            lowered = value.strip().lower()

            if lowered in {
                "1",
                "true",
                "malicious",
                "malware",
                "positive",
                "suspicious",
                "bad",
            }:
                normalized.append(POSITIVE_LABEL)
                continue

            if lowered in {
                "0",
                "false",
                "benign",
                "clean",
                "negative",
                "safe",
                "good",
            }:
                normalized.append(NEGATIVE_LABEL)
                continue

        try:
            numeric = int(value)
        except (TypeError, ValueError) as exc:
            raise EvaluationDataError(
                f"Invalid binary label at index {index}: {value!r}"
            ) from exc

        if numeric not in {
            NEGATIVE_LABEL,
            POSITIVE_LABEL,
        }:
            raise EvaluationDataError(
                f"Label at index {index} is not binary: {value!r}"
            )

        normalized.append(numeric)

    return normalized


def _validate_same_length(
    *sequences: Sequence[Any],
) -> None:
    if not sequences:
        return

    expected = len(sequences[0])

    for sequence in sequences[1:]:
        if len(sequence) != expected:
            raise EvaluationDataError(
                "Evaluation inputs have inconsistent lengths."
            )


def _mean(
    values: Sequence[float],
) -> float:
    if not values:
        return 0.0

    return float(
        statistics.fmean(values)
    )


def _std(
    values: Sequence[float],
) -> float:
    if len(values) <= 1:
        return 0.0

    return float(
        statistics.stdev(values)
    )


# ---------------------------------------------------------------------------
# Confusion matrix and classification metrics
# ---------------------------------------------------------------------------


def confusion_matrix(
    actual: Sequence[Any],
    predicted: Sequence[Any],
) -> ConfusionMatrix:
    """Calculate a binary confusion matrix."""
    _validate_same_length(
        actual,
        predicted,
    )

    y_true = _validate_binary_labels(actual)
    y_pred = _validate_binary_labels(predicted)

    tn = fp = fn = tp = 0

    for truth, prediction in zip(
        y_true,
        y_pred,
    ):
        if truth == 0 and prediction == 0:
            tn += 1
        elif truth == 0 and prediction == 1:
            fp += 1
        elif truth == 1 and prediction == 0:
            fn += 1
        elif truth == 1 and prediction == 1:
            tp += 1

    return ConfusionMatrix(
        true_negative=tn,
        false_positive=fp,
        false_negative=fn,
        true_positive=tp,
    )


def _safe_ratio(
    numerator: float,
    denominator: float,
) -> float:
    if denominator == 0:
        return 0.0

    return numerator / denominator


def matthews_correlation(
    matrix: ConfusionMatrix,
) -> float:
    """Calculate the Matthews correlation coefficient."""
    numerator = (
        matrix.true_positive * matrix.true_negative
        - matrix.false_positive * matrix.false_negative
    )

    denominator = math.sqrt(
        (
            matrix.true_positive
            + matrix.false_positive
        )
        * (
            matrix.true_positive
            + matrix.false_negative
        )
        * (
            matrix.true_negative
            + matrix.false_positive
        )
        * (
            matrix.true_negative
            + matrix.false_negative
        )
    )

    if denominator == 0:
        return 0.0

    return numerator / denominator


def diagnostic_odds_ratio(
    matrix: ConfusionMatrix,
) -> Optional[float]:
    """
    Calculate the diagnostic odds ratio.

    Returns None when the denominator is zero.
    """
    numerator = (
        matrix.true_positive
        * matrix.true_negative
    )

    denominator = (
        matrix.false_positive
        * matrix.false_negative
    )

    if denominator == 0:
        if numerator > 0:
            return float("inf")

        return None

    return numerator / denominator


def calculate_metrics(
    matrix: ConfusionMatrix,
) -> ClassificationMetrics:
    """Calculate standard binary classification metrics."""
    total = matrix.total

    positive_support = (
        matrix.true_positive
        + matrix.false_negative
    )

    negative_support = (
        matrix.true_negative
        + matrix.false_positive
    )

    accuracy = _safe_ratio(
        matrix.true_positive
        + matrix.true_negative,
        total,
    )

    sensitivity = _safe_ratio(
        matrix.true_positive,
        positive_support,
    )

    specificity = _safe_ratio(
        matrix.true_negative,
        negative_support,
    )

    precision = _safe_ratio(
        matrix.true_positive,
        matrix.true_positive
        + matrix.false_positive,
    )

    negative_predictive_value = _safe_ratio(
        matrix.true_negative,
        matrix.true_negative
        + matrix.false_negative,
    )

    f1 = _safe_ratio(
        2.0 * precision * sensitivity,
        precision + sensitivity,
    )

    balanced_accuracy = (
        sensitivity + specificity
    ) / 2.0

    false_positive_rate = _safe_ratio(
        matrix.false_positive,
        negative_support,
    )

    false_negative_rate = _safe_ratio(
        matrix.false_negative,
        positive_support,
    )

    prevalence = _safe_ratio(
        positive_support,
        total,
    )

    return ClassificationMetrics(
        accuracy=accuracy,
        balanced_accuracy=balanced_accuracy,
        precision=precision,
        recall=sensitivity,
        f1=f1,
        specificity=specificity,
        false_positive_rate=false_positive_rate,
        false_negative_rate=false_negative_rate,
        positive_predictive_value=precision,
        negative_predictive_value=negative_predictive_value,
        sensitivity=sensitivity,
        prevalence=prevalence,
        matthews_correlation=matthews_correlation(matrix),
        diagnostic_odds_ratio=diagnostic_odds_ratio(matrix),
        support=total,
        positive_support=positive_support,
        negative_support=negative_support,
    )


def evaluate_threshold(
    actual: Sequence[Any],
    probabilities: Sequence[Any],
    threshold: float,
) -> ThresholdMetrics:
    """Calculate metrics for one probability threshold."""
    if not 0.0 <= threshold <= 1.0:
        raise ValueError(
            "threshold must be between 0 and 1."
        )

    _validate_same_length(
        actual,
        probabilities,
    )

    y_true = _validate_binary_labels(actual)

    scores = [
        _clamp_probability(value)
        for value in probabilities
    ]

    predicted = [
        POSITIVE_LABEL
        if score >= threshold
        else NEGATIVE_LABEL
        for score in scores
    ]

    matrix = confusion_matrix(
        y_true,
        predicted,
    )

    return ThresholdMetrics(
        threshold=float(threshold),
        confusion_matrix=matrix,
        metrics=calculate_metrics(matrix),
    )


# ---------------------------------------------------------------------------
# Ranking metrics
# ---------------------------------------------------------------------------


def _rankdata(
    values: Sequence[float],
) -> List[float]:
    """
    Return average ranks for tied values.

    Ranks are one-based.
    """
    indexed = sorted(
        enumerate(values),
        key=lambda item: item[1],
    )

    ranks = [0.0] * len(values)

    position = 0

    while position < len(indexed):
        end = position + 1
        value = indexed[position][1]

        while (
            end < len(indexed)
            and indexed[end][1] == value
        ):
            end += 1

        average_rank = (
            position + 1 + end
        ) / 2.0

        for index in range(position, end):
            original_index = indexed[index][0]
            ranks[original_index] = average_rank

        position = end

    return ranks


def roc_auc_score_binary(
    actual: Sequence[Any],
    probabilities: Sequence[Any],
) -> Optional[float]:
    """
    Calculate binary ROC-AUC without requiring scikit-learn.

    Returns None when only one class is present.
    """
    _validate_same_length(
        actual,
        probabilities,
    )

    y_true = _validate_binary_labels(actual)

    scores = [
        _clamp_probability(value)
        for value in probabilities
    ]

    positive_count = sum(
        1
        for value in y_true
        if value == 1
    )

    negative_count = len(y_true) - positive_count

    if positive_count == 0 or negative_count == 0:
        return None

    ranks = _rankdata(scores)

    positive_rank_sum = sum(
        rank
        for rank, label in zip(
            ranks,
            y_true,
        )
        if label == 1
    )

    auc = (
        positive_rank_sum
        - positive_count
        * (positive_count + 1)
        / 2.0
    ) / (
        positive_count
        * negative_count
    )

    return max(
        0.0,
        min(1.0, auc),
    )


def _precision_recall_curve(
    actual: Sequence[int],
    probabilities: Sequence[float],
) -> Tuple[List[float], List[float], List[float]]:
    """
    Build a precision-recall curve.

    Returns precision, recall, thresholds.
    """
    order = sorted(
        range(len(probabilities)),
        key=lambda index: (
            probabilities[index],
            index,
        ),
        reverse=True,
    )

    positive_total = sum(actual)

    if positive_total == 0:
        return (
            [1.0],
            [0.0],
            [],
        )

    precision: List[float] = [1.0]
    recall: List[float] = [0.0]
    thresholds: List[float] = []

    true_positive = 0
    false_positive = 0

    position = 0

    while position < len(order):
        score = probabilities[order[position]]
        end = position + 1

        while (
            end < len(order)
            and probabilities[order[end]] == score
        ):
            end += 1

        for index in order[position:end]:
            if actual[index] == 1:
                true_positive += 1
            else:
                false_positive += 1

        total_predicted_positive = (
            true_positive
            + false_positive
        )

        current_precision = _safe_ratio(
            true_positive,
            total_predicted_positive,
        )

        current_recall = _safe_ratio(
            true_positive,
            positive_total,
        )

        precision.append(current_precision)
        recall.append(current_recall)
        thresholds.append(score)

        position = end

    return precision, recall, thresholds


def average_precision_score_binary(
    actual: Sequence[Any],
    probabilities: Sequence[Any],
) -> Optional[float]:
    """Calculate average precision for a binary classifier."""
    _validate_same_length(
        actual,
        probabilities,
    )

    y_true = _validate_binary_labels(actual)

    scores = [
        _clamp_probability(value)
        for value in probabilities
    ]

    positive_total = sum(y_true)

    if positive_total == 0:
        return None

    order = sorted(
        range(len(scores)),
        key=lambda index: (
            scores[index],
            index,
        ),
        reverse=True,
    )

    true_positive = 0
    false_positive = 0

    previous_recall = 0.0
    average_precision = 0.0

    position = 0

    while position < len(order):
        score = scores[order[position]]
        end = position + 1

        while (
            end < len(order)
            and scores[order[end]] == score
        ):
            end += 1

        for index in order[position:end]:
            if y_true[index] == 1:
                true_positive += 1
            else:
                false_positive += 1

        precision = _safe_ratio(
            true_positive,
            true_positive + false_positive,
        )

        recall = _safe_ratio(
            true_positive,
            positive_total,
        )

        average_precision += (
            recall - previous_recall
        ) * precision

        previous_recall = recall
        position = end

    return max(
        0.0,
        min(1.0, average_precision),
    )


def pr_auc_score_binary(
    actual: Sequence[Any],
    probabilities: Sequence[Any],
) -> Optional[float]:
    """Calculate trapezoidal area under the precision-recall curve."""
    _validate_same_length(
        actual,
        probabilities,
    )

    y_true = _validate_binary_labels(actual)

    scores = [
        _clamp_probability(value)
        for value in probabilities
    ]

    if sum(y_true) == 0:
        return None

    precision, recall, _ = _precision_recall_curve(
        y_true,
        scores,
    )

    area = 0.0

    for index in range(1, len(recall)):
        delta_recall = (
            recall[index]
            - recall[index - 1]
        )

        area += (
            delta_recall
            * (
                precision[index]
                + precision[index - 1]
            )
            / 2.0
        )

    return max(
        0.0,
        min(1.0, area),
    )


def calculate_ranking_metrics(
    actual: Sequence[Any],
    probabilities: Sequence[Any],
) -> RankingMetrics:
    """Calculate ROC-AUC and precision-recall ranking metrics."""
    _validate_same_length(
        actual,
        probabilities,
    )

    labels = _validate_binary_labels(actual)

    scores = [
        _clamp_probability(value)
        for value in probabilities
    ]

    positive_count = sum(labels)
    negative_count = len(labels) - positive_count

    return RankingMetrics(
        roc_auc=roc_auc_score_binary(
            labels,
            scores,
        ),
        average_precision=average_precision_score_binary(
            labels,
            scores,
        ),
        pr_auc=pr_auc_score_binary(
            labels,
            scores,
        ),
        score_count=len(scores),
        positive_count=positive_count,
        negative_count=negative_count,
    )


# ---------------------------------------------------------------------------
# Threshold generation and selection
# ---------------------------------------------------------------------------


def generate_thresholds(
    probabilities: Sequence[Any],
    *,
    step: Optional[float] = None,
    include_boundaries: bool = True,
) -> List[float]:
    """
    Generate deterministic thresholds.

    If ``step`` is supplied, a regular grid is generated.

    Otherwise, thresholds are derived from observed probabilities and include
    0 and 1 when requested.
    """
    if step is not None:
        if step <= 0.0 or step > 1.0:
            raise ValueError(
                "threshold step must be > 0 and <= 1."
            )

        count = int(
            math.ceil(
                1.0 / step
            )
        ) + 2

        if count > MAX_THRESHOLDS:
            raise EvaluationDataError(
                "Requested threshold grid is too large."
            )

        values = {
            round(
                index * step,
                12,
            )
            for index in range(
                count
            )
        }

        values.add(1.0)

        if include_boundaries:
            values.add(0.0)

        return sorted(
            value
            for value in values
            if 0.0 <= value <= 1.0
        )

    scores = sorted(
        {
            round(
                _clamp_probability(value),
                12,
            )
            for value in probabilities
        }
    )

    thresholds = set(scores)

    if include_boundaries:
        thresholds.add(0.0)
        thresholds.add(1.0)

    # Include midpoints so a threshold can distinguish adjacent observed
    # scores when desired.
    if len(scores) >= 2:
        for left, right in zip(
            scores,
            scores[1:],
        ):
            midpoint = (
                left + right
            ) / 2.0

            if 0.0 <= midpoint <= 1.0:
                thresholds.add(
                    round(midpoint, 12)
                )

    result = sorted(thresholds)

    if len(result) > MAX_THRESHOLDS:
        # Deterministic reduction for very large probability sets.
        stride = max(
            1,
            math.ceil(
                len(result)
                / MAX_THRESHOLDS
            ),
        )

        result = result[::stride]

        if result[-1] != 1.0:
            result.append(1.0)

        if include_boundaries and result[0] != 0.0:
            result.insert(0, 0.0)

    return result


def select_threshold(
    actual: Sequence[Any],
    probabilities: Sequence[Any],
    *,
    criterion: str = "f1",
    thresholds: Optional[Sequence[float]] = None,
    step: Optional[float] = None,
) -> ThresholdSelection:
    """
    Select an operational threshold.

    Supported criteria:

    * ``f1``
    * ``balanced_accuracy``
    * ``accuracy``
    * ``recall``
    * ``precision``
    * ``specificity``
    * ``mcc``
    * ``youden_j``

    Ties are resolved by selecting the higher threshold, which generally
    reduces false positives.
    """
    _validate_same_length(
        actual,
        probabilities,
    )

    criterion_name = criterion.strip().lower()

    supported = {
        "f1",
        "balanced_accuracy",
        "accuracy",
        "recall",
        "precision",
        "specificity",
        "mcc",
        "youden_j",
    }

    if criterion_name not in supported:
        raise ValueError(
            f"Unsupported threshold criterion: {criterion!r}. "
            f"Supported: {sorted(supported)}"
        )

    scores = [
        _clamp_probability(value)
        for value in probabilities
    ]

    candidate_thresholds = (
        list(thresholds)
        if thresholds is not None
        else generate_thresholds(
            scores,
            step=step,
        )
    )

    if not candidate_thresholds:
        raise EvaluationDataError(
            "No threshold candidates were supplied."
        )

    evaluated: List[ThresholdMetrics] = []

    for threshold in candidate_thresholds:
        value = _safe_float(
            threshold,
            default=float("nan"),
        )

        if not math.isfinite(value):
            continue

        if not 0.0 <= value <= 1.0:
            continue

        evaluated.append(
            evaluate_threshold(
                actual,
                scores,
                value,
            )
        )

    if not evaluated:
        raise EvaluationDataError(
            "No valid threshold candidates were available."
        )

    def objective(
        result: ThresholdMetrics,
    ) -> float:
        metrics = result.metrics

        if criterion_name == "f1":
            return metrics.f1

        if criterion_name == "balanced_accuracy":
            return metrics.balanced_accuracy

        if criterion_name == "accuracy":
            return metrics.accuracy

        if criterion_name == "recall":
            return metrics.recall

        if criterion_name == "precision":
            return metrics.precision

        if criterion_name == "specificity":
            return metrics.specificity

        if criterion_name == "mcc":
            return metrics.matthews_correlation

        return (
            metrics.sensitivity
            + metrics.specificity
            - 1.0
        )

    best = max(
        evaluated,
        key=lambda result: (
            objective(result),
            result.threshold,
        ),
    )

    return ThresholdSelection(
        selected_threshold=best.threshold,
        criterion=criterion_name,
        objective_value=objective(best),
        candidates_evaluated=len(evaluated),
        metrics=best,
    )


# ---------------------------------------------------------------------------
# Dataset extraction
# ---------------------------------------------------------------------------


def _record_label(
    record: Any,
) -> Optional[int]:
    """Extract a binary label from a DatasetRecord-like object."""
    value: Any = None

    if isinstance(record, DatasetRecord):
        value = getattr(
            record,
            "label",
            None,
        )

    if value is None and isinstance(record, Mapping):
        for key in (
            "label",
            "target",
            "y",
        ):
            if key in record:
                value = record[key]
                break

    if value is None:
        value = getattr(
            record,
            "label",
            None,
        )

    if value is None:
        return None

    try:
        return _validate_binary_labels([value])[0]
    except EvaluationDataError:
        return None


def _record_id(
    record: Any,
) -> Optional[str]:
    if isinstance(record, DatasetRecord):
        value = getattr(
            record,
            "sample_id",
            None,
        )

        return (
            str(value)
            if value
            else None
        )

    if isinstance(record, Mapping):
        for key in (
            "sample_id",
            "id",
        ):
            value = record.get(key)

            if value:
                return str(value)

    value = getattr(
        record,
        "sample_id",
        None,
    )

    return (
        str(value)
        if value
        else None
    )


def _prepare_evaluation_records(
    dataset: Dataset,
) -> List[Any]:
    records = list(
        getattr(
            dataset,
            "records",
            [],
        )
        or []
    )

    if len(records) > MAX_EVALUATION_SAMPLES:
        raise EvaluationDataError(
            f"Dataset contains {len(records)} records; "
            f"maximum supported is {MAX_EVALUATION_SAMPLES}."
        )

    return records


# ---------------------------------------------------------------------------
# Model evaluation
# ---------------------------------------------------------------------------


def evaluate_records(
    records: Iterable[Any],
    artifacts: ModelArtifacts,
    *,
    threshold: Optional[float] = None,
    include_predictions: bool = True,
    reject_unknown_features: bool = True,
    allow_missing_features: bool = True,
    missing_feature_value: float = 0.0,
    select_operational_threshold: bool = False,
    threshold_criterion: str = "f1",
    threshold_step: Optional[float] = None,
) -> EvaluationResult:
    """
    Evaluate a trained model against labeled feature records.
    """
    record_list = list(records)

    if len(record_list) > MAX_EVALUATION_SAMPLES:
        raise EvaluationDataError(
            f"Evaluation contains {len(record_list)} records; "
            f"maximum supported is {MAX_EVALUATION_SAMPLES}."
        )

    actual: List[int] = []
    probabilities: List[float] = []
    predictions: List[EvaluationPrediction] = []

    missing_feature_total = 0
    unknown_feature_total = 0

    for record in record_list:
        label = _record_label(record)

        if label is None:
            continue

        (
            vector,
            sample_id,
            missing_count,
            unknown_count,
            unknown_names,
        ) = vectorize_record(
            record,
            artifacts.schema,
            reject_unknown_features=reject_unknown_features,
            allow_missing_features=allow_missing_features,
            missing_feature_value=missing_feature_value,
        )

        probability = predict_probability(
            artifacts.model,
            vector,
        )

        actual.append(label)
        probabilities.append(probability)

        missing_feature_total += missing_count
        unknown_feature_total += unknown_count

        if include_predictions:
            predictions.append(
                EvaluationPrediction(
                    sample_id=(
                        sample_id
                        if sample_id is not None
                        else _record_id(record)
                    ),
                    actual_label=label,
                    actual_label_name=(
                        POSITIVE_LABEL_NAME
                        if label == 1
                        else NEGATIVE_LABEL_NAME
                    ),
                    predicted_label=0,
                    predicted_label_name=NEGATIVE_LABEL_NAME,
                    probability_malicious=probability,
                    probability_benign=1.0 - probability,
                    threshold=(
                        artifacts.threshold
                        if threshold is None
                        else threshold
                    ),
                    correct=False,
                    missing_feature_count=missing_count,
                    unknown_feature_count=unknown_count,
                    metadata={
                        "unknown_features": unknown_names,
                    },
                )
            )

    if not actual:
        raise EvaluationDataError(
            "No labeled records were available for evaluation."
        )

    operational_threshold = (
        artifacts.threshold
        if threshold is None
        else float(threshold)
    )

    if not 0.0 <= operational_threshold <= 1.0:
        raise ValueError(
            "threshold must be between 0 and 1."
        )

    threshold_selection: Optional[
        ThresholdSelection
    ] = None

    if select_operational_threshold:
        threshold_selection = select_threshold(
            actual,
            probabilities,
            criterion=threshold_criterion,
            step=threshold_step,
        )

        operational_threshold = (
            threshold_selection.selected_threshold
        )

    threshold_result = evaluate_threshold(
        actual,
        probabilities,
        operational_threshold,
    )

    ranking = calculate_ranking_metrics(
        actual,
        probabilities,
    )

    if include_predictions:
        for prediction, label, probability in zip(
            predictions,
            actual,
            probabilities,
        ):
            predicted = int(
                probability >= operational_threshold
            )

            prediction.predicted_label = predicted
            prediction.predicted_label_name = (
                POSITIVE_LABEL_NAME
                if predicted == 1
                else NEGATIVE_LABEL_NAME
            )
            prediction.threshold = operational_threshold
            prediction.correct = (
                predicted == label
            )

    class_distribution = {
        NEGATIVE_LABEL_NAME: sum(
            1
            for label in actual
            if label == 0
        ),
        POSITIVE_LABEL_NAME: sum(
            1
            for label in actual
            if label == 1
        ),
    }

    return EvaluationResult(
        model_type=artifacts.model_type,
        model_version=artifacts.model_version,
        model_path=artifacts.model_path,
        schema_path=artifacts.schema_path,
        threshold=operational_threshold,
        sample_count=len(record_list),
        labeled_sample_count=len(actual),
        confusion_matrix=threshold_result.confusion_matrix,
        metrics=threshold_result.metrics,
        ranking=ranking,
        threshold_selection=threshold_selection,
        class_distribution=class_distribution,
        predictions=predictions,
        metadata={
            "missing_feature_total": missing_feature_total,
            "unknown_feature_total": unknown_feature_total,
            "dataset_fingerprint": artifacts.dataset_fingerprint,
            "schema_fingerprint": artifacts.schema_fingerprint,
        },
    )


def evaluate_dataset(
    dataset: Dataset,
    artifacts: ModelArtifacts,
    *,
    threshold: Optional[float] = None,
    include_predictions: bool = True,
    reject_unknown_features: bool = True,
    allow_missing_features: bool = True,
    missing_feature_value: float = 0.0,
    select_operational_threshold: bool = False,
    threshold_criterion: str = "f1",
    threshold_step: Optional[float] = None,
) -> EvaluationResult:
    """Evaluate a Dataset object."""
    return evaluate_records(
        _prepare_evaluation_records(dataset),
        artifacts,
        threshold=threshold,
        include_predictions=include_predictions,
        reject_unknown_features=reject_unknown_features,
        allow_missing_features=allow_missing_features,
        missing_feature_value=missing_feature_value,
        select_operational_threshold=select_operational_threshold,
        threshold_criterion=threshold_criterion,
        threshold_step=threshold_step,
    )


def evaluate_dataset_path(
    dataset_path: os.PathLike[str] | str,
    artifacts: ModelArtifacts,
    *,
    threshold: Optional[float] = None,
    include_predictions: bool = True,
    reject_unknown_features: bool = True,
    allow_missing_features: bool = True,
    missing_feature_value: float = 0.0,
    select_operational_threshold: bool = False,
    threshold_criterion: str = "f1",
    threshold_step: Optional[float] = None,
) -> EvaluationResult:
    """Load and evaluate a CSV/JSONL dataset."""
    source = Path(dataset_path)

    if not source.is_file():
        raise EvaluationDataError(
            f"Evaluation dataset does not exist: {source}"
        )

    try:
        dataset = load_dataset(source)
    except Exception as exc:
        raise EvaluationDataError(
            f"Unable to load evaluation dataset {source}: {exc}"
        ) from exc

    result = evaluate_dataset(
        dataset,
        artifacts,
        threshold=threshold,
        include_predictions=include_predictions,
        reject_unknown_features=reject_unknown_features,
        allow_missing_features=allow_missing_features,
        missing_feature_value=missing_feature_value,
        select_operational_threshold=select_operational_threshold,
        threshold_criterion=threshold_criterion,
        threshold_step=threshold_step,
    )

    result.metadata["evaluation_dataset"] = str(source)

    return result


# ---------------------------------------------------------------------------
# Error analysis
# ---------------------------------------------------------------------------


def false_positives(
    result: EvaluationResult,
) -> List[EvaluationPrediction]:
    """Return benign samples incorrectly classified as malicious."""
    return [
        prediction
        for prediction in result.predictions
        if (
            prediction.actual_label == 0
            and prediction.predicted_label == 1
        )
    ]


def false_negatives(
    result: EvaluationResult,
) -> List[EvaluationPrediction]:
    """Return malicious samples incorrectly classified as benign."""
    return [
        prediction
        for prediction in result.predictions
        if (
            prediction.actual_label == 1
            and prediction.predicted_label == 0
        )
    ]


def correct_predictions(
    result: EvaluationResult,
) -> List[EvaluationPrediction]:
    """Return correctly classified samples."""
    return [
        prediction
        for prediction in result.predictions
        if prediction.correct
    ]


def highest_risk_misclassifications(
    result: EvaluationResult,
    *,
    limit: int = 50,
) -> List[EvaluationPrediction]:
    """
    Return the most concerning misclassifications.

    False negatives are ordered first by malicious probability descending,
    followed by false positives.
    """
    if limit < 1:
        return []

    misclassified = [
        prediction
        for prediction in result.predictions
        if not prediction.correct
    ]

    return sorted(
        misclassified,
        key=lambda prediction: (
            prediction.actual_label == 1,
            prediction.probability_malicious,
        ),
        reverse=True,
    )[:limit]


def error_summary(
    result: EvaluationResult,
) -> Dict[str, Any]:
    """Create a compact error-analysis summary."""
    fps = false_positives(result)
    fns = false_negatives(result)

    return {
        "false_positive_count": len(fps),
        "false_negative_count": len(fns),
        "false_positive_rate": result.metrics.false_positive_rate,
        "false_negative_rate": result.metrics.false_negative_rate,
        "false_positives": [
            prediction.to_dict()
            for prediction in fps
        ],
        "false_negatives": [
            prediction.to_dict()
            for prediction in fns
        ],
    }


# ---------------------------------------------------------------------------
# Cross-validation
# ---------------------------------------------------------------------------


def _stratified_folds(
    labels: Sequence[int],
    n_splits: int,
    seed: int,
) -> List[Tuple[List[int], List[int]]]:
    """
    Build deterministic stratified folds without external dependencies.
    """
    if n_splits < 2:
        raise ValueError(
            "n_splits must be at least 2."
        )

    if len(labels) < n_splits:
        raise EvaluationDataError(
            "Number of samples must be at least n_splits."
        )

    import random

    positive = [
        index
        for index, label in enumerate(labels)
        if label == 1
    ]

    negative = [
        index
        for index, label in enumerate(labels)
        if label == 0
    ]

    if len(positive) < n_splits or len(negative) < n_splits:
        raise EvaluationDataError(
            "Each class must contain at least n_splits samples "
            "for stratified cross-validation."
        )

    rng = random.Random(seed)

    rng.shuffle(positive)
    rng.shuffle(negative)

    folds: List[List[int]] = [
        []
        for _ in range(n_splits)
    ]

    for position, index in enumerate(positive):
        folds[position % n_splits].append(index)

    for position, index in enumerate(negative):
        folds[position % n_splits].append(index)

    result: List[Tuple[List[int], List[int]]] = []

    all_indices = set(
        range(len(labels))
    )

    for fold in folds:
        validation = sorted(fold)
        training = sorted(
            all_indices - set(validation)
        )

        result.append(
            (
                training,
                validation,
            )
        )

    return result


def cross_validate_model(
    model_factory: Any,
    vectors: Sequence[Sequence[float]],
    labels: Sequence[Any],
    *,
    n_splits: int = 5,
    seed: int = 42,
) -> CrossValidationResult:
    """
    Perform deterministic stratified cross-validation.

    ``model_factory`` must be a callable returning a fresh unfitted estimator.
    """
    if not callable(model_factory):
        raise ValueError(
            "model_factory must be callable."
        )

    if not vectors:
        raise EvaluationDataError(
            "No feature vectors supplied."
        )

    _validate_same_length(
        vectors,
        labels,
    )

    y = _validate_binary_labels(labels)

    if len(vectors) > MAX_EVALUATION_SAMPLES:
        raise EvaluationDataError(
            "Cross-validation dataset is too large."
        )

    folds = _stratified_folds(
        y,
        n_splits,
        seed,
    )

    fold_results: List[
        CrossValidationFold
    ] = []

    for fold_number, (
        training_indices,
        validation_indices,
    ) in enumerate(
        folds,
        start=1,
    ):
        model = model_factory()

        x_train = [
            list(vectors[index])
            for index in training_indices
        ]

        y_train = [
            y[index]
            for index in training_indices
        ]

        x_validation = [
            list(vectors[index])
            for index in validation_indices
        ]

        y_validation = [
            y[index]
            for index in validation_indices
        ]

        try:
            model.fit(
                x_train,
                y_train,
            )
        except Exception as exc:
            raise EvaluationError(
                f"Model training failed during fold {fold_number}: "
                f"{exc}"
            ) from exc

        if not hasattr(
            model,
            "predict_proba",
        ):
            raise EvaluationError(
                "Cross-validation model must expose predict_proba()."
            )

        probabilities: List[float] = []

        for vector in x_validation:
            probabilities.append(
                predict_probability(
                    model,
                    vector,
                )
            )

        fold_threshold = evaluate_threshold(
            y_validation,
            probabilities,
            DEFAULT_THRESHOLD,
        )

        ranking = calculate_ranking_metrics(
            y_validation,
            probabilities,
        )

        fold_results.append(
            CrossValidationFold(
                fold=fold_number,
                sample_count=len(
                    validation_indices
                ),
                confusion_matrix=(
                    fold_threshold.confusion_matrix
                ),
                metrics=fold_threshold.metrics,
                ranking=ranking,
            )
        )

    accuracies = [
        fold.metrics.accuracy
        for fold in fold_results
    ]

    balanced_accuracies = [
        fold.metrics.balanced_accuracy
        for fold in fold_results
    ]

    precisions = [
        fold.metrics.precision
        for fold in fold_results
    ]

    recalls = [
        fold.metrics.recall
        for fold in fold_results
    ]

    f1_scores = [
        fold.metrics.f1
        for fold in fold_results
    ]

    return CrossValidationResult(
        folds=fold_results,
        mean_accuracy=_mean(accuracies),
        mean_balanced_accuracy=_mean(
            balanced_accuracies
        ),
        mean_precision=_mean(precisions),
        mean_recall=_mean(recalls),
        mean_f1=_mean(f1_scores),
        std_accuracy=_std(accuracies),
        std_balanced_accuracy=_std(
            balanced_accuracies
        ),
        std_precision=_std(precisions),
        std_recall=_std(recalls),
        std_f1=_std(f1_scores),
    )


# ---------------------------------------------------------------------------
# Serialization
# ---------------------------------------------------------------------------


def evaluation_to_dict(
    result: EvaluationResult,
    *,
    include_predictions: bool = True,
) -> Dict[str, Any]:
    """Serialize an EvaluationResult."""
    return result.to_dict(
        include_predictions=include_predictions,
    )


def evaluation_to_json(
    result: EvaluationResult,
    *,
    include_predictions: bool = True,
    indent: int = 2,
) -> str:
    """Serialize evaluation results as JSON."""
    return json.dumps(
        evaluation_to_dict(
            result,
            include_predictions=include_predictions,
        ),
        indent=indent,
        sort_keys=True,
        ensure_ascii=False,
        allow_nan=False,
    )


def save_evaluation_json(
    result: EvaluationResult,
    path: os.PathLike[str] | str,
    *,
    include_predictions: bool = True,
) -> Path:
    """Atomically save evaluation results as JSON."""
    target = Path(path)
    target.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    temporary = target.with_name(
        f".{target.name}.{os.getpid()}.tmp"
    )

    try:
        with temporary.open(
            "w",
            encoding="utf-8",
            newline="\n",
        ) as handle:
            json.dump(
                evaluation_to_dict(
                    result,
                    include_predictions=include_predictions,
                ),
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
            temporary.unlink(
                missing_ok=True
            )
        except OSError:
            pass

        raise EvaluationError(
            f"Unable to save evaluation report: {target}"
        ) from exc

    return target


def save_evaluation_predictions_csv(
    result: EvaluationResult,
    path: os.PathLike[str] | str,
) -> Path:
    """Save per-sample evaluation predictions as CSV."""
    target = Path(path)
    target.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    fieldnames = [
        "sample_id",
        "actual_label",
        "actual_label_name",
        "predicted_label",
        "predicted_label_name",
        "probability_malicious",
        "probability_benign",
        "threshold",
        "correct",
        "missing_feature_count",
        "unknown_feature_count",
    ]

    temporary = target.with_name(
        f".{target.name}.{os.getpid()}.tmp"
    )

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

                writer.writerow({
                    field: row.get(field)
                    for field in fieldnames
                })

        os.replace(
            temporary,
            target,
        )

    except Exception as exc:
        try:
            temporary.unlink(
                missing_ok=True
            )
        except OSError:
            pass

        raise EvaluationError(
            f"Unable to save prediction CSV: {target}"
        ) from exc

    return target


# ---------------------------------------------------------------------------
# Report summary
# ---------------------------------------------------------------------------


def summarize_evaluation(
    result: EvaluationResult,
) -> Dict[str, Any]:
    """Return a concise evaluation summary suitable for reports."""
    return {
        "model": {
            "type": result.model_type,
            "version": result.model_version,
        },
        "samples": {
            "total": result.sample_count,
            "labeled": result.labeled_sample_count,
            "benign": result.class_distribution.get(
                NEGATIVE_LABEL_NAME,
                0,
            ),
            "malicious": result.class_distribution.get(
                POSITIVE_LABEL_NAME,
                0,
            ),
        },
        "threshold": result.threshold,
        "metrics": {
            "accuracy": result.metrics.accuracy,
            "balanced_accuracy": (
                result.metrics.balanced_accuracy
            ),
            "precision": result.metrics.precision,
            "recall": result.metrics.recall,
            "f1": result.metrics.f1,
            "specificity": result.metrics.specificity,
            "false_positive_rate": (
                result.metrics.false_positive_rate
            ),
            "false_negative_rate": (
                result.metrics.false_negative_rate
            ),
            "matthews_correlation": (
                result.metrics.matthews_correlation
            ),
        },
        "ranking": {
            "roc_auc": result.ranking.roc_auc,
            "average_precision": (
                result.ranking.average_precision
            ),
            "pr_auc": result.ranking.pr_auc,
        },
        "confusion_matrix": (
            result.confusion_matrix.to_dict()
        ),
        "errors": {
            "false_positive_count": (
                result.confusion_matrix.false_positive
            ),
            "false_negative_count": (
                result.confusion_matrix.false_negative
            ),
        },
    }


# ---------------------------------------------------------------------------
# High-level API
# ---------------------------------------------------------------------------


def evaluate(
    dataset_path: os.PathLike[str] | str,
    *,
    model_path: os.PathLike[str] | str = DEFAULT_MODEL_PATH,
    schema_path: os.PathLike[str] | str = DEFAULT_SCHEMA_PATH,
    metadata_path: os.PathLike[str] | str = DEFAULT_METADATA_PATH,
    thresholds_path: os.PathLike[str] | str = DEFAULT_THRESHOLDS_PATH,
    threshold: Optional[float] = None,
    include_predictions: bool = True,
    select_operational_threshold: bool = False,
    threshold_criterion: str = "f1",
    threshold_step: Optional[float] = None,
) -> EvaluationResult:
    """High-level evaluation entry point."""
    artifacts = load_prediction_artifacts(
        model_path=model_path,
        schema_path=schema_path,
        metadata_path=metadata_path,
        thresholds_path=thresholds_path,
    )

    return evaluate_dataset_path(
        dataset_path,
        artifacts,
        threshold=threshold,
        include_predictions=include_predictions,
        select_operational_threshold=(
            select_operational_threshold
        ),
        threshold_criterion=threshold_criterion,
        threshold_step=threshold_step,
    )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_argument_parser() -> argparse.ArgumentParser:
    """Build the evaluation CLI parser."""
    parser = argparse.ArgumentParser(
        description=(
            "Evaluate the Pharos CDR malware/document "
            "classification model."
        )
    )

    parser.add_argument(
        "input",
        type=Path,
        help="CSV or JSONL labeled feature dataset.",
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
        help=(
            "Threshold metadata "
            f"(default: {DEFAULT_THRESHOLDS_PATH})."
        ),
    )

    parser.add_argument(
        "--threshold",
        type=float,
        default=None,
        help=(
            "Classification threshold override. "
            "If omitted, the persisted model threshold is used."
        ),
    )

    parser.add_argument(
        "--select-threshold",
        action="store_true",
        help=(
            "Select an operational threshold from the evaluation "
            "dataset using the requested criterion."
        ),
    )

    parser.add_argument(
        "--threshold-criterion",
        choices=(
            "f1",
            "balanced_accuracy",
            "accuracy",
            "recall",
            "precision",
            "specificity",
            "mcc",
            "youden_j",
        ),
        default="f1",
        help="Threshold-selection criterion.",
    )

    parser.add_argument(
        "--threshold-step",
        type=float,
        default=None,
        help=(
            "Regular threshold-grid step, e.g. 0.01. "
            "If omitted, observed scores and midpoints are used."
        ),
    )

    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT_PATH,
        help=f"JSON report path (default: {DEFAULT_OUTPUT_PATH}).",
    )

    parser.add_argument(
        "--predictions-output",
        type=Path,
        default=None,
        help="Optional per-sample prediction CSV.",
    )

    parser.add_argument(
        "--no-predictions",
        action="store_true",
        help="Do not retain per-sample predictions in the JSON report.",
    )

    parser.add_argument(
        "--summary-only",
        action="store_true",
        help="Print only the compact summary to stdout.",
    )

    return parser


def main(
    argv: Optional[Sequence[str]] = None,
) -> int:
    """Command-line entry point."""
    parser = build_argument_parser()
    args = parser.parse_args(argv)

    try:
        result = evaluate(
            args.input,
            model_path=args.model,
            schema_path=args.schema,
            metadata_path=args.metadata,
            thresholds_path=args.thresholds,
            threshold=args.threshold,
            include_predictions=not args.no_predictions,
            select_operational_threshold=args.select_threshold,
            threshold_criterion=args.threshold_criterion,
            threshold_step=args.threshold_step,
        )

        save_evaluation_json(
            result,
            args.output,
            include_predictions=not args.no_predictions,
        )

        if args.predictions_output is not None:
            save_evaluation_predictions_csv(
                result,
                args.predictions_output,
            )

        if args.summary_only:
            print(
                json.dumps(
                    summarize_evaluation(result),
                    indent=2,
                    sort_keys=True,
                    ensure_ascii=False,
                    allow_nan=False,
                )
            )
        else:
            print(
                json.dumps(
                    evaluation_to_dict(
                        result,
                        include_predictions=False,
                    ),
                    indent=2,
                    sort_keys=True,
                    ensure_ascii=False,
                    allow_nan=False,
                )
            )

    except (
        EvaluationError,
        ValueError,
    ) as exc:
        print(
            f"Evaluation failed: {exc}",
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
    "EvaluationError",
    "EvaluationDataError",
    "EvaluationMetricError",
    "ConfusionMatrix",
    "ClassificationMetrics",
    "RankingMetrics",
    "ThresholdMetrics",
    "ThresholdSelection",
    "EvaluationPrediction",
    "EvaluationResult",
    "CrossValidationFold",
    "CrossValidationResult",
    "confusion_matrix",
    "calculate_metrics",
    "matthews_correlation",
    "diagnostic_odds_ratio",
    "evaluate_threshold",
    "roc_auc_score_binary",
    "average_precision_score_binary",
    "pr_auc_score_binary",
    "calculate_ranking_metrics",
    "generate_thresholds",
    "select_threshold",
    "evaluate_records",
    "evaluate_dataset",
    "evaluate_dataset_path",
    "evaluate",
    "false_positives",
    "false_negatives",
    "correct_predictions",
    "highest_risk_misclassifications",
    "error_summary",
    "cross_validate_model",
    "evaluation_to_dict",
    "evaluation_to_json",
    "save_evaluation_json",
    "save_evaluation_predictions_csv",
    "summarize_evaluation",
    "build_argument_parser",
    "main",
]